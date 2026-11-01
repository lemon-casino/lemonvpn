//! The read-only slice of the native API doona's pages read.
//!
//! Discovery, version identity, capabilities, the runtime snapshot, the traffic
//! ring, the datapath, the live connection snapshot, the invalidation event
//! stream and the resumable log stream are served. Everything else the contract
//! lists is absent from `capabilities`, so the client does not ask for it and
//! gets a contract 404 if it does.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config;
use crate::connections;
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

    match (method, path) {
        ("POST", "/api/v1/dns/query") => {
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => {
                    return error(&mut client, 400, "invalid_request", &message, cors)
                }
            };
            return match dns::query_json(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/probes") => {
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => {
                    return error(&mut client, 400, "invalid_request", &message, cors)
                }
            };
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
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => {
                    return error(&mut client, 400, "invalid_request", &message, cors)
                }
            };
            let Some(content) = json::field(&body, "content") else {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "content 缺失",
                    cors,
                );
            };
            if content.len() > config::MAX_BYTES {
                return error(
                    &mut client,
                    413,
                    "request_too_large",
                    "配置超过 max_bytes",
                    cors,
                );
            }
            let (valid, diagnostics) = config::validate(&content);
            let body = format!(
                r#"{{"valid":{valid},"generation_id":"{}","validated_at":"{}","diagnostics":{diagnostics}}}"#,
                json::escape(&config::generation()),
                state::iso8601(SystemTime::now()),
            );
            return http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"));
        }
        ("PUT", path) if path.starts_with("/api/v1/config/sources/") => {
            let id = &path["/api/v1/config/sources/".len()..];
            if id != config::SOURCE_ID {
                return error(
                    &mut client,
                    404,
                    "resource_not_found",
                    "this engine has one source",
                    cors,
                );
            }
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => {
                    return error(&mut client, 400, "invalid_request", &message, cors)
                }
            };
            let Some(content) = json::field(&body, "content") else {
                return error(
                    &mut client,
                    400,
                    "invalid_request",
                    "content 缺失",
                    cors,
                );
            };
            if content.len() > config::MAX_BYTES {
                return error(
                    &mut client,
                    413,
                    "request_too_large",
                    "配置超过 max_bytes",
                    cors,
                );
            }
            let Some(matched) = http::header_value(headers, "If-Match") else {
                return error(
                    &mut client,
                    428,
                    "precondition_required",
                    "缺少 If-Match",
                    cors,
                );
            };
            if !etag_matches(matched, &config::current_sha256()) {
                return error(
                    &mut client,
                    412,
                    "stale_revision",
                    "配置已被其他写入更新",
                    cors,
                );
            }
            return match config::replace(&content) {
                Ok(()) => {
                    let generation = json::escape(&config::generation());
                    let accepted = probes::reload_accepted(format!(
                        r#"{{"active_generation_id":"{generation}","datapath_generation_id":"{generation}"}}"#
                    ));
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
                Err(message) => error(&mut client, 500, "internal_error", &message, cors),
            };
        }
        ("POST", "/api/v1/providers") => {
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => return error(&mut client, 400, "invalid_request", &message, cors),
            };
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
                    &format!(
                        "{CACHE_HEADERS}{cors}Location: {location}\r\nRetry-After: 1\r\n"),
                ),
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("POST", "/api/v1/tun/set") => {
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => return error(&mut client, 400, "invalid_request", &message, cors),
            };
            return match tun_set(&body) {
                Ok(body) => {
                    http::respond_with(&mut client, 200, &body, &format!("{CACHE_HEADERS}{cors}"))
                }
                Err((status, code, message)) => error(&mut client, status, code, &message, cors),
            };
        }
        ("DELETE", path) if path.starts_with("/api/v1/providers/") => {
            let id = share::percent_decode(&path["/api/v1/providers/".len()..]);
            return http::respond_with(
                &mut client,
                200,
                &providers::delete(&id),
                &format!("{CACHE_HEADERS}{cors}"),
            );
        }
        ("POST", "/api/v1/nodes") => {
            let body = match read_body(&mut client, headers) {
                Ok(body) => body,
                Err(message) => return error(&mut client, 400, "invalid_request", &message, cors),
            };
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
        ("DELETE", path) if path.starts_with("/api/v1/nodes/") => {
            let id = &path["/api/v1/nodes/".len()..];
            return match providers::delete_node(id) {
                Ok(body) => http::respond_with(
                    &mut client,
                    200,
                    &body,
                    &format!("{CACHE_HEADERS}{cors}"),
                ),
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
        "/api/v1/runtime/traffic/history" => match history(query) {
            Ok(body) => body,
            Err(message) => return error(&mut client, 400, "invalid_request", message, cors),
        },
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
        "/api/v1/nodes" => config::nodes_json(param(query, "group_id")),
        "/api/v1/providers" => {
            let limit = param(query, "limit").and_then(|value| value.parse::<u64>().ok());
            match providers::list(limit, param(query, "cursor")) {
                Ok(body) => body,
                Err((status, code, message)) => {
                    return error(&mut client, status, code, &message, cors)
                }
            }
        }
        path if path.starts_with("/api/v1/providers/") => {
            let id = share::percent_decode(&path["/api/v1/providers/".len()..]);
            match providers::one(&id) {
                Some(body) => body,
                None => {
                    return error(
                        &mut client,
                        404,
                        "resource_not_found",
                        "没有这个订阅",
                        cors,
                    )
                }
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
                let code = if status == 422 {
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
            let id = &path["/api/v1/config/sources/".len()..];
            match config::config_source_json(id) {
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
            let id = &path["/api/v1/nodes/".len()..];
            match config::node_json(id) {
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
        path if path.starts_with("/api/v1/groups/") => {
            let id = &path["/api/v1/groups/".len()..];
            match config::group_json(id) {
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
        r#"{{"observed_at":"{observed}","profiles":["base"],"limits":{{"max_request_target_bytes":8192,"max_header_bytes":16384,"max_json_body_bytes":1048576}},"resources":{{"runtime":{{"available":true}},"traffic_history":{{"available":true,"max_window_seconds":{window},"max_points":{points}}},"datapath":{{"available":true,"kinds":["userspace"],"details":[]}},"connections":{{"available":true,"can_close":false}},"config":{{"available":true,"writable":true,"create":false,"max_bytes":{max_bytes},"max_sources":1}},"config_validate":{{"available":true,"modes":["syntax"],"max_bytes":{max_bytes},"max_sources":1}},"runtime_memory":{{"available":true,"metrics":["process.rss_bytes"]}},"runtime_outbounds":{{"available":true}},"memory_history":{{"available":true,"max_window_seconds":{window},"max_points":{points}}},"rules":{{"available":true,"max_rules":{max_bytes}}},"flows":{{"available":true,"recording":"on","scopes":["userspace_tcp"],"max_flows":{max_flows},"max_steps_per_flow":1,"retention_seconds":{retention},"snapshot_ttl_seconds":30,"max_page_size":1000}},"nodes":{{"available":true,"can_manage":true}},{tun},{providers},"groups":{{"available":true,"config_patch":false,"selection":false,"max_patch_operations":0}},{dns},{probes},"events":{events},"logs":{logs}}}}}"#,
        observed = state::iso8601(SystemTime::now()),
        window = state::WINDOW_SECONDS,
        points = state::MAX_POINTS,
        max_bytes = config::MAX_BYTES,
        max_flows = flows::MAX_FLOWS,
        retention = flows::RETENTION.as_secs(),
        providers = providers::capabilities_json(),
        tun = tun_capability(),
        dns = dns::capabilities_json(),
        probes = probes::capabilities_json(),
        events = events_capability(),
        logs = logs_capability(),
    )
}

/// TUN 模式仅存在于 Windows;状态与能力都如实上报。
#[cfg(windows)]
fn tun_status_body() -> String {
    crate::tun::status_json()
}

#[cfg(not(windows))]
fn tun_status_body() -> String {
    r#"{"enabled":false,"supported":false}"#.to_owned()
}

#[cfg(windows)]
fn tun_capability() -> String {
    format!(
        r#""tun":{{"available":true,"enabled":{},"udp":"dns_only"}}"#,
        crate::tun::active()
    )
}

#[cfg(not(windows))]
fn tun_capability() -> String {
    r#""tun":{"available":false}"#.to_owned()
}

/// 应一次 TUN 开关请求,返回响应体或 (status, code, message)。
#[cfg(windows)]
fn tun_set(body: &str) -> Result<String, (u16, &'static str, String)> {
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
        Err(err) => Err((500, "internal_error", err.to_string())),
    }
}

#[cfg(not(windows))]
fn tun_set(_body: &str) -> Result<String, (u16, &'static str, String)> {
    Err((
        501,
        "unsupported_operation",
        "TUN 模式仅支持 Windows".to_owned(),
    ))
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
    client
        .read_exact(&mut body)
        .map_err(|_| "请求体被截断".to_owned())?;
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
    let active = state::active();
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
            r#""lifecycle":{{"state":"running","started_at":"{started}","uptime_seconds":"{uptime}"}},"#,
            r#""generation":{{"active_id":"{generation}","config_revision":"{revision}","state":"active","activated_at":"{started}"}},"#,
            r#""datapath":{{"kind":"userspace","state":"active","visibility":"partial","ebpf":null}},"#,
            r#""traffic":{{"scope":"visible","observed_by":"userspace","counter_since":"{started}","sampled_at":{sampled_at},"#,
            r#""connections":{{"tcp":{active},"udp":0,"total":{active}}},"#,
            r#""bytes":{{"upload":"{upload}","download":"{download}"}},"#,
            r#""rates":{rates}}},"#,
            r#""process":{{"pid":{pid},"cpu_percent":null}},"#,
            r#""last_reload":null}}"#
        ),
        observed = state::iso8601(now),
        instance = format!("lemonvpn-{}", std::process::id()),
        generation = config::generation(),
        revision = config::revision(),
        started = state::iso8601(started),
        uptime = uptime,
        active = active,
        sampled_at = sampled_at,
        upload = state::upload(),
        download = state::download(),
        rates = rates,
        pid = std::process::id(),
    )
}

fn datapath() -> String {
    format!(
        r#"{{"observed_at":"{}","kind":"userspace","state":"active","visibility":"partial","ebpf":null,"errors":[]}}"#,
        state::iso8601(SystemTime::now())
    )
}

/// `GET /api/v1/connections`: the tunnels this engine has open right now.
/// Routing labels the datapath cannot see stay null/unknown, never guessed.
fn connections_body(query: &str) -> Result<String, &'static str> {
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
    let source = param(query, "src");
    let limit = match number(query, "limit")? {
        Some(value) if (1..=1000).contains(&value) => value as usize,
        Some(_) => return Err("limit is outside 1..1000"),
        None => 1000,
    };

    let mut entries = if network == "udp" {
        Vec::new()
    } else {
        connections::snapshot()
    };
    if let Some(source) = source {
        entries.retain(|entry| entry.src_ip == source);
    }
    let total = entries.len();
    let truncated = total > limit;
    let tcp = entries
        .iter()
        .take(limit)
        .map(|entry| {
            format!(
                concat!(
                    r#"{{"id":"{id}","flow_id":null,"pname":null,"state":"active","#,
                    r#""src":"{src}","dst":"{dst}","domain":null,"outbound":"direct","chain":[],"#,
                    r#""chain_source":"unknown","rule_id":null,"rule_expression":null,"rule_source":"unknown","#,
                    r#""ingress":null,"domain_source":null,"started_at":"{started}","observed_by":"userspace","#,
                    r#""upload_bytes":"{upload}","download_bytes":"{download}","#,
                    r#""upload_bytes_per_second":null,"download_bytes_per_second":null}}"#
                ),
                id = entry.id,
                src = entry.src,
                dst = entry.dst,
                started = state::iso8601(entry.started_at),
                upload = entry.upload,
                download = entry.download,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    Ok(format!(
        r#"{{"observed_at":"{observed}","instance_id":"{instance}","visibility":"partial","truncated":{truncated},"tcp":[{tcp}],"udp":[],"total_tcp":{total},"total_udp":0}}"#,
        observed = state::iso8601(SystemTime::now()),
        instance = state::instance_id(),
        truncated = truncated,
        total = total,
    ))
}

/// `GET /api/v1/flows`: only filters the flow store applies are accepted, so a
/// client never receives a silently ignored parameter.
fn flows_body(query: &str) -> Result<String, (u16, &'static str)> {
    if param(query, "cursor").is_some() {
        return Err((422, "cursor is not supported by this engine"));
    }
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
    flows::list(network, state, param(query, "connection_id"), limit)
        .map_err(|message| (400, message))
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

    loop {
        match subscription
            .receiver
            .recv_timeout(logs::HEARTBEAT_INTERVAL)
        {
            Ok(record) => {
                let id = logs::cursor_id(&subscription.instance, filter, record.seq);
                client.write_all(logs::record_frame(&id, &record).as_bytes())?;
                client.flush()?;
            }
            Err(RecvTimeoutError::Timeout) => {
                client.write_all(logs::HEARTBEAT.as_bytes())?;
                client.flush()?;
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
            return unavailable(&mut client, "the event stream has its maximum clients", cors)
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

    loop {
        match subscription.next(Duration::from_secs(events::HEARTBEAT_SECONDS)) {
            Some(event) => {
                let frame = format!(
                    "id: {}\nevent: {}\ndata: {}\n\n",
                    events::event_id(event.seq),
                    event.kind,
                    event.data,
                );
                client.write_all(frame.as_bytes())?;
                client.flush()?;
            }
            None => {
                client.write_all(logs::HEARTBEAT.as_bytes())?;
                client.flush()?;
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
    let body = format!(r#"{{"error":{{"code":"{code}","message":"{message}"}},"request_id":null}}"#);
    http::respond_with(client, status, &body, &format!("{CACHE_HEADERS}{cors}"))
}

#[cfg(test)]
mod tests {
    use super::{number, param, quoted};
    use crate::http;

    #[test]
    fn reads_numeric_query_parameters() {
        assert_eq!(number("window_seconds=60&max_points=3", "window_seconds"), Ok(Some(60)));
        assert_eq!(number("window_seconds=60&max_points=3", "max_points"), Ok(Some(3)));
        assert_eq!(number("", "max_points"), Ok(None));
        assert_eq!(number("max_points=nope", "max_points"), Err("a query parameter is not a non-negative integer"));
        assert_eq!(number("max_points=-1", "max_points"), Err("a query parameter is not a non-negative integer"));
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
        assert_eq!(http::header_value(headers, "Last-Event-ID"), Some("lemonvpn-1:logs:all:4"));
        assert_eq!(http::header_value(headers, "last-event-id"), Some("lemonvpn-1:logs:all:4"));
        assert_eq!(http::header_value(headers, "If-None-Match"), None);
        assert_eq!(http::header_value("GET / HTTP/1.1\r\n\r\n", "Last-Event-ID"), None);
    }

    #[test]
    fn writes_uint64_as_strings() {
        assert_eq!(quoted(Some(0)), "\"0\"");
        assert_eq!(quoted(Some(18446744073709551615)), "\"18446744073709551615\"");
        assert_eq!(quoted(None), "null");
    }
}
