//! Desktop native API: discovery, observable state and validated control writes.
//! Resources and action capabilities describe the operations this engine serves.

use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config;
use crate::connections;
use crate::control;
use crate::dns;
use crate::events;
use crate::flows;
use crate::http;
use crate::json;
use crate::logs::{self, Level};
use crate::outbounds;
use crate::probes;
use crate::providers;
use crate::share;
use crate::state;
use crate::state::Sample;

const CACHE_HEADERS: &str = "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";

/// Serves one request whose path starts with `/api`. `cors` is the allow-origin
/// header block for the desktop WebView, empty for every other caller.
pub fn handle(
    mut client: TcpStream,
    method: &str,
    target: &str,
    headers: &str,
    cors: &str,
) -> io::Result<()> {
    let path = http::path_of(target);
    let query = target.split_once('?').map_or("", |(_, query)| query);

    // Read the body once, before routing. A route that answers without
    // consuming the body would otherwise close the socket with unread bytes,
    // which Windows reports to the client as a connection reset — WebView
    // fetch surfaces that as "Failed to fetch" (operation starts send `{}`).
    let body = match read_body(&mut client, headers) {
        Ok(body) => body,
        Err(message) => return error(&mut client, 400, "invalid_request", &message, cors),
    };

    match (method, path) {
        ("POST", "/api/v1/dns/query") => {
            return match dns::query_json(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/probes") => {
            return match probes::start(&body) {
                Ok(accepted) => http::respond_with(
                    &mut client,
                    202,
                    &accepted.body,
                    &format!(
                        "{CACHE_HEADERS}{cors}Location: {}\r\nRetry-After: 1\r\n",
                        accepted.location
                    ),
                ),
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/config/validate") => {
            let request = match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(request) => request,
                Err(error) => {
                    return self::error(
                        &mut client,
                        400,
                        "invalid_request",
                        &error.to_string(),
                        cors,
                    )
                }
            };
            let mode = request
                .get("mode")
                .and_then(|value| value.as_str())
                .unwrap_or("syntax");
            if !matches!(mode, "syntax" | "full") {
                return error(&mut client, 422, "unsupported_value", "未知校验模式", cors);
            }
            let candidates = request
                .get("sources")
                .and_then(|value| value.as_array())
                .cloned()
                .or_else(|| {
                    request
                        .get("content")
                        .is_some()
                        .then(|| vec![request.clone()])
                });
            let Some(candidates) =
                candidates.filter(|sources| !sources.is_empty() && sources.len() <= 4)
            else {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "sources 必须包含 1 到 4 个候选源",
                    cors,
                );
            };
            let mut ids = std::collections::HashSet::new();
            let mut sources = Vec::new();
            for (index, source) in candidates.into_iter().enumerate() {
                let Some(content) = source.get("content").and_then(|value| value.as_str()) else {
                    return error(
                        &mut client,
                        400,
                        "invalid_request",
                        "候选源缺少 content",
                        cors,
                    );
                };
                if content.len() > config::MAX_BYTES {
                    return error(
                        &mut client,
                        413,
                        "request_too_large",
                        "候选源超过 max_bytes",
                        cors,
                    );
                }
                let id = source
                    .get("id")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("source-{}", index + 1));
                if id.is_empty()
                    || id.len() > 128
                    || !id.bytes().all(|value| {
                        value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-')
                    })
                    || !ids.insert(id.clone())
                {
                    return error(
                        &mut client,
                        400,
                        "invalid_request",
                        "候选源 ID 无效或重复",
                        cors,
                    );
                }
                let path = source
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        if index == 0 {
                            config::SOURCE_PATH.to_owned()
                        } else {
                            format!("source-{}.dae", index + 1)
                        }
                    });
                if !config::source_name_valid(&path) {
                    return error(&mut client, 400, "invalid_request", "候选源路径无效", cors);
                }
                sources.push((id, path, content.to_owned()));
            }
            let (valid, diagnostics) = config::validate_sources(&sources, mode);
            let diagnostics: serde_json::Value =
                serde_json::from_str(&diagnostics).unwrap_or_else(|_| serde_json::json!([]));
            let result = serde_json::json!({"valid":valid,"generation_id":config::generation(),"validated_at":state::iso8601(SystemTime::now()),"diagnostics":diagnostics});
            return http::respond_with(
                &mut client,
                200,
                &result.to_string(),
                &format!("{CACHE_HEADERS}{cors}"),
            );
        }
        ("PUT", path) if path.starts_with("/api/v1/config/sources/") => {
            let id = share::percent_decode(&path["/api/v1/config/sources/".len()..]);
            let Some(source) = config::config_source_json(&id)
                .and_then(|source| serde_json::from_str::<serde_json::Value>(&source).ok())
            else {
                return error(
                    &mut client,
                    404,
                    "resource_not_found",
                    "没有这个配置源",
                    cors,
                );
            };
            let Some(content) = json::field(&body, "content") else {
                return error(&mut client, 400, "invalid_request", "content 缺失", cors);
            };
            let Some(matched) = http::header_value(headers, "If-Match") else {
                return error(
                    &mut client,
                    428,
                    "precondition_required",
                    "缺少 If-Match",
                    cors,
                );
            };
            let revision = source["content_sha256"].as_str().unwrap_or_default();
            if !etag_matches(matched, revision) {
                return error(
                    &mut client,
                    412,
                    "stale_revision",
                    "配置已被其他写入更新",
                    cors,
                );
            }
            return match config::replace_source(&id, &content, Some(revision)) {
                Ok(()) => {
                    let accepted = probes::reload_accepted(config::reload_result_json());
                    http::respond_with(
                        &mut client,
                        202,
                        &accepted.body,
                        &format!(
                            "{CACHE_HEADERS}{cors}Location: {}\r\nRetry-After: 1\r\n",
                            accepted.location
                        ),
                    )
                }
                Err(failure) => error(
                    &mut client,
                    failure.status,
                    failure.code,
                    &failure.message,
                    cors,
                ),
            };
        }
        ("POST", "/api/v1/providers") => {
            return match providers::create(&body) {
                Ok((body, location)) => http::respond_with(
                    &mut client,
                    201,
                    &body,
                    &format!("{CACHE_HEADERS}{cors}Location: {location}\r\n"),
                ),
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", path) if path.starts_with("/api/v1/providers/") && path.ends_with("/refresh") => {
            let id = &path["/api/v1/providers/".len()..path.len() - "/refresh".len()];
            let id = share::percent_decode(id);
            return match providers::refresh(&id) {
                Ok((body, location)) => http::respond_with(
                    &mut client,
                    202,
                    &body,
                    &format!("{CACHE_HEADERS}{cors}Location: {location}\r\nRetry-After: 1\r\n"),
                ),
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/tun/set") => {
            return match tun_set(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("PATCH", path) if path.starts_with("/api/v1/providers/") => {
            let id = share::percent_decode(&path["/api/v1/providers/".len()..]);
            return match providers::update(&id, &body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("DELETE", path) if path.starts_with("/api/v1/providers/") => {
            let id = share::percent_decode(&path["/api/v1/providers/".len()..]);
            return match providers::delete(&id) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err(message) => error(&mut client, 500, "internal_error", &message, cors),
            };
        }
        ("POST", "/api/v1/nodes") => {
            return match providers::add_node(&body) {
                Ok((body, location)) => http::respond_with(
                    &mut client,
                    201,
                    &body,
                    &format!("{CACHE_HEADERS}{cors}Location: {location}\r\n"),
                ),
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/rules/reset") | ("PUT", "/api/v1/rules/order") => {
            return match config::manage_rules(&body, method == "POST") {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err(failure) => error(
                    &mut client,
                    failure.status,
                    failure.code,
                    &failure.message,
                    cors,
                ),
            };
        }
        ("PUT", "/api/v1/nodes/groups") => {
            return match config::update_nodes_groups(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err(failure) => error(
                    &mut client,
                    failure.status,
                    failure.code,
                    &failure.message,
                    cors,
                ),
            };
        }
        ("PUT", path) if path.starts_with("/api/v1/nodes/") && path.ends_with("/groups") => {
            let id =
                share::percent_decode(&path["/api/v1/nodes/".len()..path.len() - "/groups".len()]);
            return match config::update_node_groups(&id, &body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err(failure) => error(
                    &mut client,
                    failure.status,
                    failure.code,
                    &failure.message,
                    cors,
                ),
            };
        }
        ("DELETE", path) if path.starts_with("/api/v1/nodes/") => {
            let id = share::percent_decode(&path["/api/v1/nodes/".len()..]);
            return match providers::delete_node(&id) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/dns/cache/flush") => {
            return http::respond_with(
                &mut client,
                200,
                &dns::flush(),
                &format!("{CACHE_HEADERS}{cors}"),
            )
        }
        ("DELETE", path) if path.starts_with("/api/v1/dns/cache/") => {
            let id = &path["/api/v1/dns/cache/".len()..];
            return http::respond_with(
                &mut client,
                200,
                &dns::delete_entry(id),
                &format!("{CACHE_HEADERS}{cors}"),
            );
        }
        ("DELETE", "/api/v1/dns/cache") => {
            return match dns::delete_name(query) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            }
        }
        ("POST", "/api/v1/groups/delete") => {
            return match config::remove_group(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err(failure) => error(
                    &mut client,
                    failure.status,
                    failure.code,
                    &failure.message,
                    cors,
                ),
            };
        }
        ("POST", "/api/v1/operations/reload") => {
            return control::start_reload(&mut client, cors);
        }
        ("POST", "/api/v1/operations/suspend") => {
            return control::start_suspend(&mut client, cors);
        }
        ("POST", "/api/v1/operations/resume") => {
            return control::start_resume(&mut client, cors);
        }
        ("POST", "/api/v1/routing/trace") => {
            return control::trace(&mut client, cors, &body);
        }
        ("POST", "/api/v1/config/sources") => {
            return control::create_source(&mut client, cors, &body);
        }
        ("PATCH", "/api/v1/runtime/settings") => {
            return control::patch_settings(&mut client, cors, &body);
        }
        ("PATCH", "/api/v1/geodata/settings") => {
            return control::patch_geodata(&mut client, cors, &body);
        }
        ("POST", "/api/v1/geodata/update") => {
            return control::start_geodata_update(&mut client, cors);
        }
        ("PATCH", path) if path.starts_with("/api/v1/groups/") && path.ends_with("/config") => {
            let id =
                share::percent_decode(&path["/api/v1/groups/".len()..path.len() - "/config".len()]);
            let if_match = http::header_value(headers, "If-Match");
            return control::patch_group(&mut client, cors, &id, &body, if_match);
        }
        ("PUT", path) if path.starts_with("/api/v1/groups/") && path.ends_with("/selection") => {
            let id = share::percent_decode(
                &path["/api/v1/groups/".len()..path.len() - "/selection".len()],
            );
            return control::select(&mut client, cors, &id, &body);
        }
        ("DELETE", path) if path.starts_with("/api/v1/groups/") && path.ends_with("/selection") => {
            let id = share::percent_decode(
                &path["/api/v1/groups/".len()..path.len() - "/selection".len()],
            );
            return control::clear_selection(
                &mut client,
                cors,
                &id,
                param(query, "network").unwrap_or("both"),
            );
        }
        ("DELETE", "/api/v1/connections") => {
            return match close_connections_body(query) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, message)) => error(
                    &mut client,
                    status,
                    if status == 413 {
                        "request_too_large"
                    } else {
                        "invalid_request"
                    },
                    message,
                    cors,
                ),
            };
        }
        ("DELETE", path) if path.starts_with("/api/v1/connections/") => {
            let id = &path["/api/v1/connections/".len()..];
            return control::close_connection(&mut client, cors, id);
        }
        _ => {}
    }

    if method != "GET" {
        return error(
            &mut client,
            405,
            "method_not_allowed",
            "this engine serves a read-only API",
            cors,
        );
    }

    let body = match path {
        "/api" => DISCOVERY.to_string(),
        "/api/v1/version" => version(),
        "/api/v1/capabilities" => capabilities(),
        "/api/v1/runtime" => runtime(),
        "/api/v1/datapath" => datapath(),
        "/api/v1/tun" => tun_status_body(),
        "/api/v1/desktop/status" => desktop_status(client.local_addr().ok()),
        "/api/v1/runtime/traffic/history" => match history(query) {
            Ok(body) => body,
            Err(message) => return error(&mut client, 400, "invalid_request", message, cors),
        },
        "/api/v1/runtime/memory" => runtime_memory(),
        "/api/v1/runtime/memory/history" => match memory_history(query) {
            Ok(body) => body,
            Err(message) => return error(&mut client, 400, "invalid_request", message, cors),
        },
        "/api/v1/runtime/outbounds" => outbounds::snapshot(&config::outbound_seed()),
        "/api/v1/connections" => match connections_body(query) {
            Ok(body) => body,
            Err(message) => return error(&mut client, 400, "invalid_request", message, cors),
        },
        "/api/v1/config" => config::effective_json(),
        "/api/v1/rules" => config::rules_json(),
        "/api/v1/rules/defaults" => config::rule_defaults_json(),
        "/api/v1/nodes" => {
            let group = param(query, "group_id").map(share::query_decode);
            config::nodes_json(group.as_deref())
        }
        "/api/v1/providers" => {
            let limit = param(query, "limit").and_then(|value| value.parse::<u64>().ok());
            match providers::list(limit, param(query, "cursor")) {
                Ok(body) => body,
                Err((status, code, message)) => {
                    return error(&mut client, status, code, &message, cors)
                }
            }
        }
        path if path.starts_with("/api/v1/providers/") && path.ends_with("/settings") => {
            let id = share::percent_decode(
                &path["/api/v1/providers/".len()..path.len() - "/settings".len()],
            );
            match providers::settings(&id) {
                Some(body) => body,
                None => return error(&mut client, 404, "resource_not_found", "订阅不存在", cors),
            }
        }
        path if path.starts_with("/api/v1/providers/") => {
            let id = share::percent_decode(&path["/api/v1/providers/".len()..]);
            match providers::one(&id) {
                Some(body) => body,
                None => return error(&mut client, 404, "resource_not_found", "没有这个订阅", cors),
            }
        }
        "/api/v1/groups" => config::groups_json(),
        "/api/v1/dns/log" => match dns::log_json(query) {
            Ok(body) => body,
            Err((status, code, message)) => {
                return error(&mut client, status, code, &message, cors)
            }
        },
        "/api/v1/dns/cache" => match dns::cache_json(query) {
            Ok(body) => body,
            Err((status, code, message)) => {
                return error(&mut client, status, code, &message, cors)
            }
        },
        "/api/v1/flows" => match flows_body(query) {
            Ok(body) => body,
            Err((status, message)) => {
                let code = if status == 410 {
                    "cursor_expired"
                } else if status == 422 {
                    "unsupported_value"
                } else {
                    "invalid_request"
                };
                return error(&mut client, status, code, message, cors);
            }
        },
        "/api/v1/events" => return stream_events(client, query, headers, cors),
        "/api/v1/logs" => return stream_logs(client, query, headers, cors),
        path if path.starts_with("/api/v1/operations/") => {
            let id = &path["/api/v1/operations/".len()..];
            match probes::operation_json(id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such operation",
                        cors,
                    )
                }
            }
        }
        path if path.starts_with("/api/v1/config/sources/") => {
            let id = share::percent_decode(&path["/api/v1/config/sources/".len()..]);
            match config::config_source_json(&id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such source",
                        cors,
                    )
                }
            }
        }
        path if path.starts_with("/api/v1/nodes/") => {
            let id = share::percent_decode(&path["/api/v1/nodes/".len()..]);
            match config::node_json(&id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such node",
                        cors,
                    )
                }
            }
        }
        "/api/v1/runtime/settings" => control::settings_json(),
        "/api/v1/dns/rules" => control::dns_rules_json(),
        "/api/v1/geodata" => control::geodata_json(),
        "/api/v1/geodata/settings" => control::geodata_settings_json(),
        path if path.starts_with("/api/v1/groups/") && path.ends_with("/config") => {
            let id =
                share::percent_decode(&path["/api/v1/groups/".len()..path.len() - "/config".len()]);
            match control::group_config_json(&id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such group",
                        cors,
                    )
                }
            }
        }
        path if path.starts_with("/api/v1/groups/") => {
            let id = share::percent_decode(&path["/api/v1/groups/".len()..]);
            match config::group_json(&id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such group",
                        cors,
                    )
                }
            }
        }
        path if path.starts_with("/api/v1/flows/") => {
            let id = &path["/api/v1/flows/".len()..];
            match flows::detail(id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "this engine has no such flow",
                        cors,
                    )
                }
            }
        }
        _ => {
            return error(
                &mut client,
                404,
                "resource_not_found",
                "this engine does not serve that endpoint",
                cors,
            )
        }
    };
    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
}

/// The full discovery view: the listener is loopback-only and has no secret, so
/// a loopback peer is admitted without a credential.
const DISCOVERY: &str = r#"{"name":"daeuniverse/native","status":"draft","api_major":1,"base_path":"/api/v1","links":{"version":"/api/v1/version","capabilities":"/api/v1/capabilities","config":"/api/v1/config","config_validate":"/api/v1/config/validate","runtime":"/api/v1/runtime","runtime_outbounds":"/api/v1/runtime/outbounds","traffic_history":"/api/v1/runtime/traffic/history","memory_history":"/api/v1/runtime/memory/history","logs":"/api/v1/logs","providers":"/api/v1/providers","rules":"/api/v1/rules","operations":"/api/v1/operations/{operation_id}","geodata":"/api/v1/geodata","auth_setup":null,"auth_login":null},"auth":{"mode":"token","setup_required":false,"anonymous_loopback":true}}"#;

fn version() -> String {
    format!(
        r#"{{"api":{{"name":"daeuniverse/native","major":1,"status":"draft"}},"engine":{{"name":"lemonvpn","version":"{}"}}}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

fn capabilities() -> String {
    format!(
        r#"{{"observed_at":"{observed}","profiles":["base"],"limits":{{"max_request_target_bytes":8192,"max_header_bytes":16384,"max_json_body_bytes":1048576}},"resources":{{"runtime":{{"available":true}},"traffic_history":{{"available":true,"max_window_seconds":{window},"max_points":{points}}},"desktop":{{"available":true}},"datapath":{{"available":true,"kinds":["userspace"],"details":[]}},"connections":{{"available":true,"can_close":true,"max_bulk_close":1000}},"config":{{"available":true,"writable":true,"create":true,"max_bytes":{max_bytes},"max_sources":4}},"config_validate":{{"available":true,"modes":["syntax","full"],"max_bytes":{max_bytes},"max_sources":4}},"runtime_memory":{{"available":true,"metrics":["process.rss_bytes"]}},"runtime_outbounds":{{"available":true}},"memory_history":{{"available":true,"max_window_seconds":{window},"max_points":{points}}},"rules":{{"available":true,"max_rules":{max_bytes}}},"flows":{{"available":true,"recording":"{flow_recording}","scopes":["userspace_tcp","userspace_udp"],"max_flows":{max_flows},"max_steps_per_flow":1,"retention_seconds":{retention},"snapshot_ttl_seconds":30,"max_page_size":1000}},"nodes":{{"available":true,"can_manage":true}},"x-rule-management":{{"available":true,"reset":true,"reorder":true}},"x-hot-apply":{hot_apply},"x-proxy-chain":{{"available":true,"max_hops":8,"front_groups":true,"exit_groups":true,"traffic_activity":true,"preview":true,"network_preview":false}},"x-node-management":{{"subscription_delete":true,"persistent_delete":true}},"x-group-management":{{"delete":true,"replace_references":true,"atomic":true}},"x-node-membership":{{"available":true,"atomic":true,"batch":true,"max_batch_nodes":256}},{tun},{providers},"groups":{{"available":true,"config_patch":true,"selection":true,"max_patch_operations":16}},{dns},{probes},"routing_trace":{{"available":true,"resolve_modes":["none","live"]}},"runtime_settings":{{"available":true,"fields":["record_flows","record_logs","record_dns_log","log.level","dns_log.max_records","flows.max_flows","flows.retention_seconds"]}},"geodata":{{"available":true,"assets":["geoip","geosite"],"can_update":true,"configurable_sources":true,"max_urls":4}},"dns_rules":{{"available":true,"max_rules":64}},"reload":{{"available":true}},"suspend":{{"available":true}},"resume":{{"available":true}},"events":{events},"logs":{logs}}}}}"#,
        hot_apply = crate::compat::hot_apply_json(),
        observed = state::iso8601(SystemTime::now()),
        window = state::WINDOW_SECONDS,
        points = state::MAX_POINTS,
        max_bytes = config::MAX_BYTES,
        max_flows = 4096,
        retention = 86400,
        flow_recording = control::recording_mode("record_flows"),
        providers = providers::capabilities_json(),
        tun = tun_capability(),
        dns = dns::capabilities_json(),
        probes = probes::capabilities_json(),
        events = events_capability(),
        logs = logs_capability(),
    )
}

/// Capabilities describe the installed host backend, including embedded hosts.
fn tun_status_body() -> String {
    crate::tun::status_json()
}

fn tun_capability() -> String {
    if !crate::tun::supported() {
        return r#""tun":{"available":false}"#.to_owned();
    }
    format!(
        r#""tun":{{"available":true,"enabled":{},"udp":"{}","ipv6":{}}}"#,
        crate::tun::active(),
        if crate::compat::available() {
            "full"
        } else {
            "dns_only"
        },
        crate::compat::available()
    )
}

/// 应一次 TUN 开关请求,返回响应体或 (status, code, message)。
fn tun_set(body: &str) -> Result<String, (u16, &'static str, String)> {
    if !crate::tun::supported() {
        return Err((
            501,
            "unsupported_operation",
            "当前平台尚未提供 TUN 适配器".to_owned(),
        ));
    }
    let enabled = match json::bool_field(body, "enabled") {
        Ok(Some(value)) => value,
        Ok(None) => return Err((400, "invalid_request", "缺少 enabled 布尔字段".to_owned())),
        Err(message) => return Err((400, "invalid_request", message)),
    };
    let result = if enabled {
        crate::tun::enable()
    } else if crate::tun::active() {
        crate::tun::disable()
    } else {
        Ok(())
    };
    match result {
        Ok(()) => Ok(crate::tun::status_json()),
        Err(err) => Err(tun_failure(err.to_string())),
    }
}

/// A refused adapter creation is the one TUN failure the desktop shell can fix
/// by relaunching elevated; a missing DLL or a route failure is not.
fn tun_failure(message: String) -> (u16, &'static str, String) {
    if message.contains("管理员") {
        (403, "admin_required", message)
    } else {
        (500, "internal_error", message)
    }
}

fn read_body(client: &mut TcpStream, headers: &str) -> Result<String, String> {
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.trim().eq_ignore_ascii_case("content-length") {
                return None;
            }
            value.trim().parse::<usize>().ok()
        })
        .unwrap_or(0);
    if length > 1024 * 1024 {
        return Err("请求体超过 1 MiB".to_owned());
    }
    if length == 0 {
        return Ok(String::new());
    }
    let mut body = vec![0u8; length];
    crate::proxy::read_handshake(client, &mut body).map_err(|_| "请求体被截断".to_owned())?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Only the kinds this engine actually produces are declared; a client that
/// asks for a flow event gets the contract's 422 instead of silence.
fn events_capability() -> String {
    let kinds = events::KINDS
        .iter()
        .map(|kind| format!("\"{kind}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"available":true,"kinds":[{kinds}],"retention_seconds":{},"max_buffered_events":{},"max_clients":{},"heartbeat_seconds":{}}}"#,
        events::RETENTION_SECONDS,
        events::MAX_EVENTS,
        events::MAX_CLIENTS,
        events::HEARTBEAT_SECONDS,
    )
}

/// The contract requires these four fields whenever `available` is true, and
/// only filters this engine actually applies are declared.
fn logs_capability() -> String {
    let levels = logs::LEVELS
        .iter()
        .map(|level| format!("\"{}\"", level.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"available":true,"levels":[{levels}],"filters":["level"],"retention_seconds":{},"max_buffered_records":{}}}"#,
        logs::RETENTION_SECONDS,
        logs::MAX_RECORDS
    )
}

fn runtime() -> String {
    let now = SystemTime::now();
    let started = state::started();
    let uptime = now.duration_since(started).unwrap_or_default().as_secs();
    let (generation, revision, activated_at) = config::with_current(|config| {
        (
            config.generation.clone(),
            config.revision.clone(),
            config.loaded_at,
        )
    });
    let path_state = if control::suspended() {
        "disabled"
    } else {
        "active"
    };
    let active = state::active();
    let udp = connections::snapshot()
        .iter()
        .filter(|entry| entry.network == "udp")
        .count() as u64;
    let tcp = active.saturating_sub(udp);
    let (sampled_at, rates) = match state::latest_rates() {
        Some((at, seconds, upload, download)) => (
            format!("\"{}\"", state::iso8601(at)),
            format!(
                r#"{{"window_seconds":{seconds:.3},"upload_bytes_per_second":"{upload}","download_bytes_per_second":"{download}"}}"#
            ),
        ),
        None => ("null".to_string(), "null".to_string()),
    };
    format!(
        concat!(
            r#"{{"observed_at":"{observed}","instance_id":"{instance}","#,
            r#""lifecycle":{{"state":"{lifecycle}","started_at":"{started}","uptime_seconds":"{uptime}"}},"#,
            r#""generation":{{"active_id":"{generation}","config_revision":"{revision}","state":"active","activated_at":"{activated_at}"}},"#,
            r#""datapath":{{"kind":"userspace","state":"{path_state}","visibility":"partial","ebpf":null}},"#,
            r#""traffic":{{"scope":"visible","observed_by":"userspace","counter_since":"{started}","sampled_at":{sampled_at},"#,
            r#""connections":{{"tcp":{tcp},"udp":{udp},"total":{active}}},"#,
            r#""bytes":{{"upload":"{upload}","download":"{download}"}},"#,
            r#""rates":{rates}}},"#,
            r#""process":{{"pid":{pid},"cpu_percent":null}},"#,
            r#""last_reload":null}}"#
        ),
        observed = state::iso8601(now),
        instance = state::instance_id(),
        lifecycle = control::runtime_state(),
        path_state = path_state,
        generation = generation,
        revision = revision,
        activated_at = state::iso8601(activated_at),
        started = state::iso8601(started),
        uptime = uptime,
        active = active,
        tcp = tcp,
        udp = udp,
        sampled_at = sampled_at,
        upload = state::upload(),
        download = state::download(),
        rates = rates,
        pid = std::process::id(),
    )
}

/// Desktop-only facts stay outside the upstream contract's Linux memory and
/// eBPF fields. Every metric is a real platform sample or an explicit null.
fn desktop_status(address: Option<std::net::SocketAddr>) -> String {
    let memory = crate::platform::current().memory_snapshot();
    let bytes =
        |value: Option<u64>| value.map_or_else(|| "null".to_owned(), |value| quoted(Some(value)));
    format!(
        r#"{{"observed_at":"{observed}","mixed":{{"address":{address},"protocols":["HTTP","SOCKS5"]}},"tun":{tun},"memory":{{"process":{{"rss_bytes":{rss},"peak_rss_bytes":{peak},"private_bytes":{private}}},"system":{{"total_bytes":{total},"available_bytes":{available},"used_percent":{used}}}}}}}"#,
        observed = state::iso8601(SystemTime::now()),
        address = address.map_or_else(
            || "null".to_owned(),
            |address| json::quoted(&address.to_string())
        ),
        tun = tun_status_body(),
        rss = bytes(memory.resident_bytes),
        peak = bytes(memory.peak_resident_bytes),
        private = bytes(memory.private_bytes),
        total = bytes(memory.system_total_bytes),
        available = bytes(memory.system_available_bytes),
        used = memory
            .system_used_percent
            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
    )
}

fn datapath() -> String {
    format!(
        r#"{{"observed_at":"{}","kind":"userspace","state":"{}","visibility":"partial","ebpf":null,"errors":[]}}"#,
        state::iso8601(SystemTime::now()),
        if control::suspended() {
            "disabled"
        } else {
            "active"
        }
    )
}

/// `GET /api/v1/connections`: the tunnels this engine has open right now.
/// Routing labels the datapath cannot see stay null/unknown, never guessed.
fn connections_body(query: &str) -> Result<String, &'static str> {
    control::record_demand("record_flows");
    let network = match param(query, "type") {
        None | Some("all") => "all",
        Some("tcp") => "tcp",
        Some("udp") => "udp",
        Some(_) => return Err("type is not tcp, udp or all"),
    };
    if let Some(detail) = param(query, "detail") {
        if detail != "summary" && detail != "full" {
            return Err("detail is not summary or full");
        }
    }
    let source = param(query, "src").map(share::query_decode);
    let limit = match number(query, "limit")? {
        Some(value) if (1..=1000).contains(&value) => value as usize,
        Some(_) => return Err("limit is outside 1..1000"),
        None => 1000,
    };

    let (chain, mut entries) = if let Some(id) = param(query, "x-group") {
        config::chain_activity_snapshot(&share::query_decode(id))
            .ok_or("chain group does not exist")?
    } else {
        (serde_json::Value::Null, connections::snapshot())
    };
    entries.retain(|entry| network == "all" || entry.network == network);
    if let Some(source) = source {
        entries.retain(|entry| entry.src_ip == source);
    }
    let total = entries.len();
    let truncated = total > limit;
    let total_tcp = entries
        .iter()
        .filter(|entry| entry.network == "tcp")
        .count();
    let total_udp = entries
        .iter()
        .filter(|entry| entry.network == "udp")
        .count();
    let serialize = |network| {
        entries
        .iter()
        .take(limit)
        .filter(|entry|entry.network==network)
        .map(|entry| {
            let route = entry.route.as_ref();
            serde_json::json!({
                "id":entry.id,"flow_id":route.and_then(|route|route.flow_id.as_deref()),"pname":route.and_then(|route|route.process.as_ref()).and_then(|process|process.name.as_deref()),"state":"active",
                "src":entry.src,"dst":entry.dst,"domain":entry.domain,
                "outbound":route.map(|route|route.outbound.as_str()),"chain":route.map(|route|route.chain.as_slice()).unwrap_or_default(),
                "chain_source":if route.is_some(){"evaluation"}else{"unknown"},
                "x-lemonvpn-front-hops":route.and_then(|route|route.chain_front_hops),"x-lemonvpn-generation":route.map(|route|route.generation.as_str()),
                "rule_id":route.map(|route|route.rule_id.as_str()),"rule_expression":route.map(|route|route.expression.as_str()),
                "rule_source":if route.is_some(){"userspace"}else{"unknown"},"ingress":null,
                "domain_source":route.and_then(|route|route.domain_source),"started_at":state::iso8601_millis(entry.started_at),"observed_by":"userspace",
                "upload_bytes":entry.upload.to_string(),"download_bytes":entry.download.to_string(),
                "upload_bytes_per_second":null,"download_bytes_per_second":null
            }).to_string()
        })
        .collect::<Vec<_>>()
        .join(",")
    };
    let tcp = serialize("tcp");
    let udp = serialize("udp");

    Ok(format!(
        r#"{{"observed_at":"{observed}","instance_id":"{instance}","visibility":"partial","truncated":{truncated},"tcp":[{tcp}],"udp":[{udp}],"total_tcp":{total_tcp},"total_udp":{total_udp},"x-lemonvpn-chain":{chain}}}"#,
        observed = state::iso8601_millis(SystemTime::now()),
        instance = state::instance_id(),
        truncated = truncated,
    ))
}

fn close_connections_body(query: &str) -> Result<String, (u16, &'static str)> {
    if param(query, "all") != Some("true") {
        return Err((400, "批量关闭需要 all=true"));
    }
    let network = param(query, "type").unwrap_or("all");
    if !matches!(network, "all" | "tcp" | "udp") {
        return Err((400, "type 只接受 all/tcp/udp"));
    }
    let source = param(query, "src").map(share::query_decode);
    let entries: Vec<_> = connections::snapshot()
        .into_iter()
        .filter(|entry| {
            (network == "all" || entry.network == network)
                && source.as_ref().is_none_or(|source| &entry.src_ip == source)
        })
        .collect();
    if entries.len() > 1000 {
        return Err((413, "批量关闭最多 1000 条，请缩小范围"));
    }
    let closed = entries
        .iter()
        .filter(|entry| connections::close(&entry.id))
        .count();
    Ok(serde_json::json!({"closed":closed,"skipped":entries.len()-closed}).to_string())
}

/// `GET /api/v1/flows`: only filters the flow store applies are accepted, so a
/// client never receives a silently ignored parameter.
fn flows_body(query: &str) -> Result<String, (u16, &'static str)> {
    if let Some(detail) = param(query, "detail") {
        if detail != "summary" && detail != "full" {
            return Err((400, "detail is not summary or full"));
        }
    }
    let limit = match number(query, "limit") {
        Ok(Some(value)) if (1..=1000).contains(&value) => value as usize,
        Ok(Some(_)) => return Err((400, "limit is outside 1..1000")),
        Ok(None) => 1000,
        Err(message) => return Err((400, message)),
    };
    let network = param(query, "network").unwrap_or("all");
    let state = param(query, "state").unwrap_or("all");
    let connection_id = param(query, "connection_id").map(share::query_decode);
    flows::list_page(
        network,
        state,
        connection_id.as_deref(),
        limit,
        param(query, "cursor"),
    )
    .map_err(|message| {
        (
            if message == "cursor_expired" {
                410
            } else {
                400
            },
            message,
        )
    })
}

fn history(query: &str) -> Result<String, &'static str> {
    let window = match number(query, "window_seconds")? {
        Some(value) => value,
        None => state::WINDOW_SECONDS,
    };
    let max_points = match number(query, "max_points")? {
        Some(value) => value,
        None => state::MAX_POINTS,
    };
    if window == 0 || window > state::WINDOW_SECONDS {
        return Err("window_seconds is outside the advertised range");
    }
    if max_points == 0 || max_points > state::MAX_POINTS {
        return Err("max_points is outside the advertised range");
    }

    let now = SystemTime::now();
    let cutoff = now
        .checked_sub(Duration::from_secs(window))
        .unwrap_or(UNIX_EPOCH);
    let samples = state::samples();
    let rows = rows(&samples);
    let visible: Vec<&Row> = rows.iter().filter(|row| row.at > cutoff).collect();
    let step = visible.len().div_ceil(max_points as usize).max(1);
    // Thin backwards from the newest sample, so the most recent point survives.
    let mut kept: Vec<&Row> = visible.iter().rev().step_by(step).copied().collect();
    kept.reverse();
    let samples = kept
        .iter()
        .map(|row| {
            format!(
                r#"{{"sampled_at":"{at}","upload_bytes_per_second":{upload},"download_bytes_per_second":{download},"connections":{connections}}}"#,
                at = state::iso8601(row.at),
                upload = quoted(row.upload),
                download = quoted(row.download),
                connections = row.connections,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    Ok(format!(
        r#"{{"observed_at":"{observed}","window_seconds":{window},"sampled_every_seconds":{step},"samples":[{samples}]}}"#,
        observed = state::iso8601(now),
        step = step as f64,
    ))
}

/// The latest memory sample as the contract's RuntimeMemory snapshot. This
/// engine reads no cgroup and loads no eBPF, so those sections stay null.
fn runtime_memory() -> String {
    let rss = state::memory_samples().pop().and_then(|(_, rss)| rss);
    format!(
        r#"{{"observed_at":"{observed}","process":{{"rss_bytes":{rss}}},"cgroup":null,"kernel":null}}"#,
        observed = state::iso8601(SystemTime::now()),
        rss = rss.map_or_else(|| "null".to_owned(), |value| quoted(Some(value))),
    )
}

fn memory_history(query: &str) -> Result<String, &'static str> {
    let window = match number(query, "window_seconds")? {
        Some(value) => value,
        None => state::WINDOW_SECONDS,
    };
    let max_points = match number(query, "max_points")? {
        Some(value) => value,
        None => state::MAX_POINTS,
    };
    if window == 0 || window > state::WINDOW_SECONDS {
        return Err("window_seconds is outside the advertised range");
    }
    if max_points == 0 || max_points > state::MAX_POINTS {
        return Err("max_points is outside the advertised range");
    }

    let now = SystemTime::now();
    let cutoff = now
        .checked_sub(Duration::from_secs(window))
        .unwrap_or(UNIX_EPOCH);
    let visible: Vec<(SystemTime, Option<u64>)> = state::memory_samples()
        .into_iter()
        .filter(|(at, _)| *at > cutoff)
        .collect();
    let step = visible.len().div_ceil(max_points as usize).max(1);
    let mut kept: Vec<(SystemTime, Option<u64>)> =
        visible.iter().rev().step_by(step).copied().collect();
    kept.reverse();
    let samples = kept
        .iter()
        .map(|(at, rss)| {
            format!(
                r#"{{"sampled_at":"{}","rss_bytes":{},"cgroup_current_bytes":null}}"#,
                state::iso8601(*at),
                rss.map_or_else(|| "null".to_owned(), |value| quoted(Some(value))),
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    Ok(format!(
        r#"{{"observed_at":"{observed}","window_seconds":{window},"sampled_every_seconds":{step},"samples":[{samples}]}}"#,
        observed = state::iso8601(now),
        step = step as f64,
    ))
}

/// `If-Match` carries the source's SHA-256, quoted by the client.
fn etag_matches(header: &str, sha: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim().trim_start_matches("W/").trim_matches('"');
        candidate == sha
            || candidate
                .strip_prefix("sha256:")
                .is_some_and(|value| value == sha)
            || candidate
                .strip_prefix("sha256-")
                .is_some_and(|value| value == sha)
    })
}

struct Row {
    at: SystemTime,
    upload: Option<u64>,
    download: Option<u64>,
    connections: u64,
}

/// One row per recorded sample; its rates span the interval before it, and the
/// oldest sample in the ring has none.
fn rows(samples: &[Sample]) -> Vec<Row> {
    samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let rates = index
                .checked_sub(1)
                .and_then(|before| samples.get(before))
                .and_then(|previous| {
                    let seconds = sample.at.duration_since(previous.at).ok()?.as_secs_f64();
                    if seconds <= 0.0 {
                        return None;
                    }
                    Some((
                        ((sample.upload.saturating_sub(previous.upload)) as f64 / seconds).round()
                            as u64,
                        ((sample.download.saturating_sub(previous.download)) as f64 / seconds)
                            .round() as u64,
                    ))
                });
            Row {
                at: sample.at,
                upload: rates.map(|(upload, _)| upload),
                download: rates.map(|(_, download)| download),
                connections: sample.active,
            }
        })
        .collect()
}

/// `UInt64` travels as a decimal string, never a JSON number.
fn quoted(value: Option<u64>) -> String {
    match value {
        Some(value) => format!("\"{value}\""),
        None => "null".to_string(),
    }
}

fn number(query: &str, key: &str) -> Result<Option<u64>, &'static str> {
    match param(query, key) {
        Some(value) => value
            .parse()
            .map(Some)
            .map_err(|_| "a query parameter is not a non-negative integer"),
        None => Ok(None),
    }
}

fn param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

/// The request text starts with the request line, so header lookup starts at
/// the second line and stops at the blank line that ends the block.
/// `GET /api/v1/logs`: a bounded, resumable SSE stream whose first frame is
/// always `stream.ready`. Cursor and level errors are decided before any
/// stream headers are written.
fn stream_logs(mut client: TcpStream, query: &str, headers: &str, cors: &str) -> io::Result<()> {
    let level = match param(query, "level") {
        Some(value) => match Level::parse(value) {
            Some(level) if level.advertised() => Some(level),
            Some(_) => {
                return error(
                    &mut client,
                    422,
                    "unsupported_value",
                    "level is not an advertised log level",
                    cors,
                )
            }
            None => {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "level is not a log level",
                    cors,
                )
            }
        },
        None => None,
    };
    if param(query, "target").is_some() {
        return error(
            &mut client,
            422,
            "unsupported_value",
            "target is not an advertised log filter",
            cors,
        );
    }

    let cursor = http::header_value(headers, "Last-Event-ID");
    let minimum = level.unwrap_or(Level::Trace);
    let filter = level.map_or("all", Level::as_str);
    let subscription = match logs::store().subscribe(minimum, filter, cursor) {
        Ok(subscription) => subscription,
        Err(logs::CursorError::Expired) => {
            return error(
                &mut client,
                409,
                "event_cursor_expired",
                "event cursor is older than the retained window; reconnect without it",
                cors,
            )
        }
    };

    // No Content-Length: the stream ends when this connection closes.
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{cors}Connection: close\r\n\r\n"
    );
    client.write_all(head.as_bytes())?;
    client.flush()?;

    let ready = logs::ready_frame(
        &subscription.ready_id,
        &subscription.instance,
        &state::iso8601(SystemTime::now()),
    );
    client.write_all(ready.as_bytes())?;
    client.flush()?;

    for record in &subscription.replay {
        let id = logs::cursor_id(&subscription.instance, filter, record.seq);
        client.write_all(logs::record_frame(&id, record).as_bytes())?;
    }
    client.flush()?;

    // A real engine event, emitted after subscribing so it arrives as the
    // first live record instead of falling into the replay snapshot.
    logs::info(
        "engine::logs",
        "Log stream opened.",
        Some(logs::fields(&[("level", filter)])),
    );

    let mut last_frame = Instant::now();
    loop {
        control::record_demand("record_logs");
        if crate::runtime::stopping() {
            return Ok(());
        }
        match subscription
            .receiver
            .recv_timeout(Duration::from_millis(250))
        {
            Ok(record) => {
                let id = logs::cursor_id(&subscription.instance, filter, record.seq);
                client.write_all(logs::record_frame(&id, &record).as_bytes())?;
                client.flush()?;
                last_frame = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {
                if last_frame.elapsed() >= logs::HEARTBEAT_INTERVAL {
                    client.write_all(logs::HEARTBEAT.as_bytes())?;
                    client.flush()?;
                    last_frame = Instant::now();
                }
            }
            // The engine dropped this client's sender: its bounded queue filled
            // or the stream ended. Either way this connection is done.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// `GET /api/v1/events`: a bounded, resumable invalidation stream. The first
/// frame is always `stream.ready`; kind and cursor errors are decided before
/// any stream headers are written.
fn stream_events(mut client: TcpStream, query: &str, headers: &str, cors: &str) -> io::Result<()> {
    let mut kinds = Vec::new();
    if let Some(value) = param(query, "kinds") {
        for part in value.split(',') {
            let Some(kind) = events::known(part) else {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "kinds contains an unknown event kind",
                    cors,
                );
            };
            if kinds.contains(&kind) {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "kinds repeats an event kind",
                    cors,
                );
            }
            if !events::produced(kind) {
                return error(
                    &mut client,
                    422,
                    "unsupported_value",
                    "kinds contains an event kind this engine does not produce",
                    cors,
                );
            }
            kinds.push(kind);
        }
    }
    if param(query, "flow_id").is_some() {
        return error(
            &mut client,
            422,
            "unsupported_value",
            "flow_id is not an advertised event filter",
            cors,
        );
    }

    let cursor = http::header_value(headers, "Last-Event-ID");
    let mut subscription = match events::subscribe(cursor, kinds) {
        Ok(subscription) => subscription,
        Err(events::SubscribeError::Expired) => {
            return error(
                &mut client,
                409,
                "event_cursor_expired",
                "event cursor is older than the retained window; reconnect without it",
                cors,
            )
        }
        Err(events::SubscribeError::TooMany) => {
            return unavailable(
                &mut client,
                "the event stream has its maximum clients",
                cors,
            )
        }
    };

    // No Content-Length: the stream ends when this connection closes.
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{cors}Connection: close\r\n\r\n"
    );
    client.write_all(head.as_bytes())?;
    client.flush()?;

    let ready = format!(
        "id: {}\nevent: stream.ready\ndata: {}\n\n",
        subscription.ready_id,
        events::ready_data(),
    );
    client.write_all(ready.as_bytes())?;
    client.flush()?;

    let mut last_frame = Instant::now();
    loop {
        if crate::runtime::stopping() {
            return Ok(());
        }
        match subscription.next(Duration::from_millis(250)) {
            Some(event) => {
                let frame = format!(
                    "id: {}\nevent: {}\ndata: {}\n\n",
                    events::event_id(event.seq),
                    event.kind,
                    event.data,
                );
                client.write_all(frame.as_bytes())?;
                client.flush()?;
                last_frame = Instant::now();
            }
            None => {
                if last_frame.elapsed() >= Duration::from_secs(events::HEARTBEAT_SECONDS) {
                    client.write_all(logs::HEARTBEAT.as_bytes())?;
                    client.flush()?;
                    last_frame = Instant::now();
                }
            }
        }
    }
}

/// A 503 needs `Retry-After`, which `respond_with`'s fixed header block lacks.
fn unavailable(client: &mut TcpStream, message: &str, cors: &str) -> io::Result<()> {
    let body = format!(
        r#"{{"error":{{"code":"temporarily_unavailable","message":"{message}"}},"request_id":null}}"#
    );
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n{CACHE_HEADERS}{cors}Retry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes())?;
    client.flush()
}

fn error(
    client: &mut TcpStream,
    status: u16,
    code: &str,
    message: &str,
    cors: &str,
) -> io::Result<()> {
    let body =
        format!(r#"{{"error":{{"code":"{code}","message":"{message}"}},"request_id":null}}"#);
    http::respond_with(client, status, &body, &format!("{CACHE_HEADERS}{cors}"))
}

#[cfg(test)]
mod tests {
    use super::{number, param, quoted};
    use crate::http;

    #[test]
    fn marks_an_administrator_refusal() {
        let (status, code, _) =
            super::tun_failure("创建 TUN 适配器失败（需要管理员权限）".to_owned());
        assert_eq!((status, code), (403, "admin_required"));
        let (status, code, _) = super::tun_failure("加载 wintun.dll 失败".to_owned());
        assert_eq!((status, code), (500, "internal_error"));
    }

    #[test]
    fn reads_numeric_query_parameters() {
        assert_eq!(
            number("window_seconds=60&max_points=3", "window_seconds"),
            Ok(Some(60))
        );
        assert_eq!(
            number("window_seconds=60&max_points=3", "max_points"),
            Ok(Some(3))
        );
        assert_eq!(number("", "max_points"), Ok(None));
        assert_eq!(
            number("max_points=nope", "max_points"),
            Err("a query parameter is not a non-negative integer")
        );
        assert_eq!(
            number("max_points=-1", "max_points"),
            Err("a query parameter is not a non-negative integer")
        );
    }

    #[test]
    fn reads_query_parameters_by_name() {
        assert_eq!(param("level=info&target=honk", "level"), Some("info"));
        assert_eq!(param("level=info&target=honk", "target"), Some("honk"));
        assert_eq!(param("level=info", "target"), None);
        assert_eq!(param("level", "level"), None);
    }

    #[test]
    fn reads_last_event_id_case_insensitively() {
        let headers = "GET /api/v1/logs HTTP/1.1\r\nHost: localhost\r\nLast-Event-ID: lemonvpn-1:logs:all:4\r\n\r\n";
        assert_eq!(
            http::header_value(headers, "Last-Event-ID"),
            Some("lemonvpn-1:logs:all:4")
        );
        assert_eq!(
            http::header_value(headers, "last-event-id"),
            Some("lemonvpn-1:logs:all:4")
        );
        assert_eq!(http::header_value(headers, "If-None-Match"), None);
        assert_eq!(
            http::header_value("GET / HTTP/1.1\r\n\r\n", "Last-Event-ID"),
            None
        );
    }

    #[test]
    fn writes_uint64_as_strings() {
        assert_eq!(quoted(Some(0)), "\"0\"");
        assert_eq!(
            quoted(Some(18446744073709551615)),
            "\"18446744073709551615\""
        );
        assert_eq!(quoted(None), "null");
    }

    #[test]
    fn serves_the_runtime_memory_snapshot() {
        let body = super::runtime_memory();
        assert!(body.contains("\"observed_at\":\""));
        assert!(body.contains("\"cgroup\":null"));
        assert!(body.contains("\"kernel\":null"));
        let rss = body
            .split("\"rss_bytes\":")
            .nth(1)
            .expect("process.rss_bytes is present")
            .split(',')
            .next()
            .unwrap()
            .trim_end_matches('}')
            .to_owned();
        let value = rss.trim_matches('"');
        assert!(
            rss == "null" || (value.parse::<u64>().is_ok() && rss.starts_with('"')),
            "rss_bytes must be a decimal string or null, got {rss}"
        );
    }
}
