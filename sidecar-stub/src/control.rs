//! Control-plane writes the dashboard drives: asynchronous operations
//! (reload, suspend, resume), runtime setting overrides, group selection and
//! config patches, routing trace simulation, DNS request rules and geodata
//! assets. Every write the UI offers lands here, and the state it keeps is
//! process-local: a restart returns to what the configuration file says.

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::SystemTime;

use crate::config;
use crate::connections;
use crate::fetch;
use crate::http;
use crate::json;
use crate::probes;
use crate::sha256;
use crate::state;

const HEADERS: &str = "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
const GEO_MAX_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_GEOIP: &str = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat";
const DEFAULT_GEOSITE: &str =
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat";

fn ok(client: &mut TcpStream, cors: &str, status: u16, body: &str) -> io::Result<()> {
    http::respond_with(client, status, body, &format!("{HEADERS}{cors}"))
}

fn no_content(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    http::respond_with(client, 204, "", &format!("{HEADERS}{cors}"))
}

fn fail(
    client: &mut TcpStream,
    cors: &str,
    status: u16,
    code: &str,
    message: &str,
) -> io::Result<()> {
    let body = format!(r#"{{"error":{{"code":"{code}","message":"{message}"}},"request_id":null}}"#);
    http::respond_with(client, status, &body, &format!("{HEADERS}{cors}"))
}

fn accepted_reply(
    client: &mut TcpStream,
    cors: &str,
    accepted: probes::Accepted,
) -> io::Result<()> {
    http::respond_with(
        client,
        202,
        &accepted.body,
        &format!(
            "{HEADERS}{cors}Location: {}\r\nRetry-After: 1\r\n",
            accepted.location
        ),
    )
}

fn quoted(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(|value| format!("\"{}\"", json::escape(value)))
        .unwrap_or_else(|| "null".to_owned())
}

fn quoted_at(value: Option<SystemTime>) -> String {
    value.map_or_else(|| "null".to_owned(), |at| {
        format!("\"{}\"", state::iso8601(at))
    })
}

// ---------- suspend / resume ----------

static SUSPENDED: AtomicBool = AtomicBool::new(false);

/// Whether the datapath refuses new inbound connections right now.
pub fn suspended() -> bool {
    SUSPENDED.load(Ordering::Relaxed)
}

pub fn runtime_state() -> &'static str {
    if suspended() {
        "suspended"
    } else {
        "running"
    }
}

pub fn start_reload(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    let generation = config::force_reload();
    let result = format!(
        r#"{{"active_generation_id":"{g}","datapath_generation_id":"{g}"}}"#,
        g = json::escape(&generation)
    );
    accepted_reply(client, cors, probes::reload_accepted(result))
}

pub fn start_suspend(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    SUSPENDED.store(true, Ordering::Relaxed);
    crate::logs::info(
        "engine::runtime",
        "Datapath suspended: new inbound connections are refused.",
        None,
    );
    let id = probes::create_operation("suspend");
    probes::finish_operation(&id, r#"{"runtime_state":"suspended"}"#.to_owned());
    accepted_reply(client, cors, probes::accepted(id, "suspend"))
}

pub fn start_resume(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    SUSPENDED.store(false, Ordering::Relaxed);
    crate::logs::info("engine::runtime", "Datapath resumed.", None);
    let id = probes::create_operation("resume");
    probes::finish_operation(&id, r#"{"runtime_state":"running"}"#.to_owned());
    accepted_reply(client, cors, probes::accepted(id, "resume"))
}

// ---------- runtime setting overrides ----------

static SETTINGS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn settings() -> MutexGuard<'static, HashMap<String, String>> {
    SETTINGS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A recorder mode the datapath honours; "on" unless a PATCH overrode it.
pub fn recording_mode(key: &str) -> String {
    settings()
        .get(key)
        .cloned()
        .unwrap_or_else(|| "on".to_owned())
}

pub fn settings_json() -> String {
    let overrides = settings();
    let source = if overrides.is_empty() {
        "config"
    } else {
        "runtime"
    };
    let mode = |key: &str| {
        overrides
            .get(key)
            .cloned()
            .unwrap_or_else(|| "on".to_owned())
    };
    let number = |key: &str, default: u64| {
        overrides
            .get(key)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let flows_mode = mode("record_flows");
    let logs_mode = mode("record_logs");
    let dns_mode = mode("record_dns_log");
    format!(
        r#"{{"observed_at":"{observed}","source":"{source}","recording":{{"flows":{{"allowed":true,"mode":"{flows_mode}","active":{flows_active}}},"logs":{{"allowed":true,"mode":"{logs_mode}","active":true}},"dns_log":{{"allowed":true,"mode":"{dns_mode}","active":true}},"events":{{"active":true}}}},"log":{{"level":"{level}","buffered_records":500}},"dns_log":{{"max_records":{dns_max}}},"flows":{{"max_flows":{flows_max},"retention_seconds":{retention}}}}}"#,
        observed = state::iso8601(SystemTime::now()),
        flows_active = flows_mode != "off",
        level = overrides
            .get("log.level")
            .cloned()
            .unwrap_or_else(|| "info".to_owned()),
        dns_max = number("dns_log.max_records", 2048),
        flows_max = number("flows.max_flows", crate::flows::MAX_FLOWS as u64),
        retention = number("flows.retention_seconds", crate::flows::RETENTION.as_secs()),
    )
}

fn json_number(body: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\":");
    let start = body.find(&pattern)? + pattern.len();
    let tail = body[start..].trim_start();
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    tail[..end].parse().ok()
}

pub fn patch_settings(
    client: &mut TcpStream,
    cors: &str,
    body: &str,
) -> io::Result<()> {
    {
        let mut map = settings();
        let modes: [(&str, [&str; 3]); 3] = [
            ("record_flows", ["on", "off", "auto"]),
            ("record_logs", ["on", "off", "on"]),
            ("record_dns_log", ["on", "off", "on"]),
        ];
        for (key, values) in modes {
            if let Some(value) = json::field(body, key) {
                if !values.contains(&value.as_str()) {
                    return fail(client, cors, 422, "unsupported_value", &format!("{key} 只接受 on/off/auto"));
                }
                map.insert(key.to_owned(), value);
            }
        }
        if let Some(level) = json::field(body, "level") {
            if !["trace", "debug", "info", "warn", "error"].contains(&level.as_str()) {
                return fail(client, cors, 422, "unsupported_value", "log.level 不是合法级别");
            }
            map.insert("log.level".to_owned(), level);
        }
        for (key, max) in [("dns_log.max_records", 65536), ("flows.max_flows", 4096)] {
            let value = json_number(body, key)
                .or_else(|| json_number(body, key.rsplit('.').next().unwrap_or(key)));
            if let Some(value) = value {
                if value == 0 || value > max {
                    return fail(client, cors, 422, "unsupported_value", &format!("{key} 超出范围"));
                }
                map.insert(key.to_owned(), value.to_string());
            }
        }
        if let Some(value) = json_number(body, "retention_seconds") {
            if value == 0 || value > 86400 {
                return fail(client, cors, 422, "unsupported_value", "retention_seconds 超出范围");
            }
            map.insert("flows.retention_seconds".to_owned(), value.to_string());
        }
    }
    ok(client, cors, 200, &settings_json())
}

// ---------- group selection ----------

static SELECTIONS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

/// The member a pinned selection or manual choice resolves to, by group name.
pub fn selection_override(group: &str) -> Option<String> {
    SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group)
        .cloned()
}

fn group_name_of(id: &str) -> Option<String> {
    id.strip_prefix("group-").map(str::to_owned)
}

pub fn select(
    client: &mut TcpStream,
    cors: &str,
    id: &str,
    body: &str,
) -> io::Result<()> {
    let Some(name) = group_name_of(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    let Some(member) = json::field(body, "member_id") else {
        return fail(client, cors, 400, "invalid_request", "member_id 缺失");
    };
    let member_name = member.strip_prefix("node-").unwrap_or(&member).to_owned();
    let network = json::field(body, "network").unwrap_or_else(|| "both".to_owned());
    if !["tcp", "udp", "both"].contains(&network.as_str()) {
        return fail(client, cors, 400, "invalid_request", "network 只接受 tcp/udp/both");
    }
    let manual = config::with_current(|config| {
        config
            .groups
            .iter()
            .find(|group| group.name == name)
            .map(|group| {
                (
                    group.members.contains(&member_name),
                    matches!(group.policy, config::Policy::Selector),
                )
            })
    });
    let Some((in_group, selector)) = manual else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    if !in_group {
        return fail(client, cors, 422, "unsupported_value", "成员不在该组内");
    }
    SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(name, member_name);
    let source = if selector { "runtime" } else { "override" };
    ok(
        client,
        cors,
        200,
        &format!(
            r#"{{"group_id":"{id}","member_id":{},"resolved_leaf_node_id":null,"network":"{network}","source":"{source}"}}"#,
            quoted(&Some(member)),
        ),
    )
}

pub fn clear_selection(client: &mut TcpStream, cors: &str, id: &str) -> io::Result<()> {
    let Some(name) = group_name_of(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&name);
    no_content(client, cors)
}

// ---------- group configuration patch ----------

pub fn group_config_json(id: &str) -> Option<String> {
    let name = group_name_of(id)?;
    config::with_current(|config| {
        let group = config.groups.iter().find(|group| group.name == name)?;
        Some(format!(
            r#"{{"policy":{{"kind":"{kind}","native":"{native}"}},"config":{{"default_member_id":{default},"final_outbound":{final},"check_url":null,"check_interval":null,"tolerance":null,"idle_timeout":null,"interrupt_connections":null}}}}"#,
            kind = group.policy.kind(),
            native = json::escape(&group.policy.native()),
            default = quoted(&group.default),
            final = quoted(&group.final_outbound),
        ))
    })
}

struct PatchOp {
    op: String,
    path: String,
    value: Option<String>,
}

/// Reads one quoted JSON string starting at its opening quote.
fn scan_string(text: &str) -> Option<String> {
    let rest = text.trim_start().strip_prefix('"')?;
    let mut value = String::new();
    let mut escaped = false;
    for character in rest.chars() {
        if escaped {
            value.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(value);
        } else {
            value.push(character);
        }
    }
    None
}

/// Reads the RFC 6902 operations a client submitted. Value objects (the
/// policy) are reduced to their `native` text; null and string values carry
/// through as-is.
fn parse_ops(body: &str) -> Vec<PatchOp> {
    let mut ops = Vec::new();
    let mut cursor = 0;
    while let Some(at) = body[cursor..].find("\"path\":") {
        let path_start = cursor + at + "\"path\":".len();
        let Some(path) = scan_string(&body[path_start..]) else { break };
        let op = body[..path_start]
            .rfind("\"op\":")
            .and_then(|pos| scan_string(&body[pos + "\"op\":".len()..]))
            .unwrap_or_else(|| "replace".to_owned());
        let after_path = path_start + path.len() + 2;
        let value = {
            let rest = body[after_path..].trim_start();
            if rest.starts_with(',') {
                let rest = rest[1..].trim_start();
                if rest.starts_with("\"value\":") {
                    let rest = rest["\"value\":".len()..].trim_start();
                    if rest.starts_with("null") {
                        None
                    } else if rest.starts_with('{') {
                        json::field(rest, "native")
                    } else {
                        scan_string(rest)
                    }
                } else {
                    None
                }
            } else {
                // A remove op carries no value.
                None
            }
        };
        ops.push(PatchOp { op, path, value });
        cursor = after_path;
        if cursor >= body.len() {
            break;
        }
    }
    ops
}

pub fn patch_group(
    client: &mut TcpStream,
    cors: &str,
    id: &str,
    body: &str,
    if_match: Option<&str>,
) -> io::Result<()> {
    let Some(name) = group_name_of(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    let Some(matched) = if_match else {
        return fail(client, cors, 428, "precondition_required", "缺少 If-Match");
    };
    if !etag_matches(matched, &config::current_sha256()) {
        return fail(client, cors, 412, "stale_revision", "配置已被其他写入更新");
    }
    let current = config::with_current(|config| {
        config.groups.iter().find(|group| group.name == name).map(|group| {
            (
                group.policy.native(),
                group.default.clone(),
                group.final_outbound.clone(),
            )
        })
    });
    let Some((_policy_now, default_now, final_now)) = current else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    let mut policy_new: Option<String> = None;
    let mut default_new: Option<Option<String>> = None;
    let mut final_new: Option<Option<String>> = None;
    for op in parse_ops(body) {
        let applies = match op.op.as_str() {
            "replace" | "add" | "remove" => true,
            "test" => true,
            _ => false,
        };
        if !applies {
            return fail(client, cors, 422, "unsupported_value", "不支持的 patch 操作");
        }
        let value = op.value.clone();
        match op.path.as_str() {
            "/policy" => {
                let Some(native) = value else {
                    return fail(client, cors, 422, "unsupported_value", "policy 不能为空");
                };
                let supported = native == "selector"
                    || native == "random"
                    || (native.starts_with("fixed(") && native.ends_with(')'));
                if !supported {
                    return fail(
                        client,
                        cors,
                        422,
                        "unsupported_value",
                        "此引擎只支持 selector、random 与 fixed(n) 策略",
                    );
                }
                policy_new = Some(native);
            }
            "/config/default_member_id" => {
                if op.op == "test" {
                    if value != default_now {
                        return fail(client, cors, 422, "unsupported_value", "test 失败");
                    }
                } else {
                    default_new = Some(value);
                }
            }
            "/config/final_outbound" => {
                if op.op == "test" {
                    if value != final_now {
                        return fail(client, cors, 422, "unsupported_value", "test 失败");
                    }
                } else {
                    final_new = Some(value);
                }
            }
            other => {
                return fail(
                    client,
                    cors,
                    422,
                    "unsupported_value",
                    &format!("字段 {other} 不可由此引擎修改"),
                );
            }
        }
    }
    let content = config::source_content();
    let rewritten = config::rewrite_group(
        &content,
        &name,
        policy_new.as_deref(),
        default_new
            .as_ref()
            .map(|value| value.as_deref()),
        final_new.as_ref().map(|value| value.as_deref()),
    );
    let Ok(rewritten) = rewritten else {
        return fail(client, cors, 422, "unsupported_value", "组在源文件中定位失败");
    };
    if let Err(message) = config::replace(&rewritten) {
        return fail(client, cors, 422, "unsupported_value", &message);
    }
    let id_owned = id.to_owned();
    let revision = config::current_sha256();
    let op_id = probes::create_operation("group_update");
    probes::finish_operation(
        &op_id,
        format!(
            r#"{{"group_id":{},"config_revision":"{}"}}"#,
            quoted(&Some(id_owned)),
            json::escape(&revision)
        ),
    );
    accepted_reply(client, cors, probes::accepted(op_id, "group_update"))
}

/// The shared `If-Match` comparison: raw, weak or sha256-prefixed forms.
fn etag_matches(header: &str, sha: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim().trim_start_matches("W/").trim_matches('"');
        candidate == sha
            || candidate.strip_prefix("sha256:").is_some_and(|value| value == sha)
            || candidate.strip_prefix("sha256-").is_some_and(|value| value == sha)
    })
}

// ---------- routing trace ----------

pub fn trace(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let domain = json::field(body, "domain");
    let dst_ip = json::field(body, "dst_ip");
    let Some(host) = domain.clone().or_else(|| dst_ip.clone()) else {
        return fail(client, cors, 400, "invalid_request", "input 需要 domain 或 dst_ip");
    };
    let live = json::field(body, "resolve").as_deref() == Some("live");
    let resolved = dst_ip.or_else(|| {
        if live && domain.is_some() {
            crate::dns::resolve(&host)
                .ok()
                .and_then(|addresses| addresses.first().map(|address| address.to_string()))
        } else {
            None
        }
    });
    let decision = config::decide(&host);
    let evaluation = format!(
        r#"{{"rule_id":"{rule}","expression":{expression},"result":"matched","missing_inputs":[],"conditions":[]}}"#,
        rule = json::escape(&decision.rule_id),
        expression = quoted(&Some(decision.expression.clone())),
    );
    let body = format!(
        r#"{{"mode":"simulation","instance_id":"lemonvpn-{pid}","generation_id":"{generation}","observed_at":"{observed}","evaluations":[{{"dst_ip":{dst_ip},"decision":"determinate","outbound":{outbound},"missing_inputs":[],"rules":[{evaluation}]}}],"dns":[]}}"#,
        pid = std::process::id(),
        generation = json::escape(&decision.generation),
        observed = state::iso8601(SystemTime::now()),
        dst_ip = quoted(&resolved),
        outbound = quoted(&Some(decision.outbound)),
    );
    ok(client, cors, 200, &body)
}

// ---------- DNS request rules ----------

pub fn dns_rules_json() -> String {
    let (generation, rules, fallback_upstream) = config::with_current(|config| {
        (
            config.generation.clone(),
            config
                .dns_rules
                .iter()
                .map(|rule| (rule.expression.clone(), rule.upstream.clone(), rule.line))
                .collect::<Vec<_>>(),
            config.upstreams.first().map(|upstream| upstream.name.clone()),
        )
    });
    let request = rules
        .iter()
        .enumerate()
        .map(|(index, (expression, upstream, line))| {
            format!(
                r#"{{"rule_id":"dns-req-{index}","index":{index},"expression":{expression_json},"action":"upstream","upstream":{upstream_json},"source":{{"file":"config.dae","source_id":"source-main","line":{line},"column":null}},"kind":"rule"}}"#,
                expression_json = quoted(&Some(expression.clone())),
                upstream_json = quoted(&Some(upstream.clone())),
                line = line,
            )
        })
        .collect::<Vec<_>>();
    let fallback_index = request.len();
    let mut request = request;
    request.push(format!(
        r#"{{"rule_id":"dns-req-fallback","index":{fallback_index},"expression":"fallback: {fallback}","action":"upstream","upstream":{upstream_json},"source":null,"kind":"fallback"}}"#,
        fallback = fallback_upstream.clone().unwrap_or_else(|| "default".to_owned()),
        upstream_json = quoted(&fallback_upstream),
    ));
    format!(
        r#"{{"generation_id":"{generation}","request":[{request}],"response":[{{"rule_id":"dns-resp-fallback","index":0,"expression":"","action":"accept","upstream":null,"source":null,"kind":"fallback"}}]}}"#,
        generation = json::escape(&generation),
        request = request.join(","),
    )
}

// ---------- geodata ----------

struct GeoState {
    geosite_urls: Vec<String>,
    geoip_urls: Vec<String>,
    auto_enabled: bool,
    interval_hours: u32,
    overridden: bool,
    last_checked: Option<SystemTime>,
    last_updated: Option<SystemTime>,
    last_error: Option<(String, String)>,
}

static GEO: OnceLock<Mutex<GeoState>> = OnceLock::new();

fn geo() -> MutexGuard<'static, GeoState> {
    GEO.get_or_init(|| {
        Mutex::new(GeoState {
            geosite_urls: vec![DEFAULT_GEOSITE.to_owned()],
            geoip_urls: vec![DEFAULT_GEOIP.to_owned()],
            auto_enabled: true,
            interval_hours: 24,
            overridden: false,
            last_checked: None,
            last_updated: None,
            last_error: None,
        })
    })
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn asset(kind: &str, file: &str) -> Option<String> {
    let path = config::data_dir().join(file);
    let metadata = std::fs::metadata(&path).ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let modified = metadata
        .modified()
        .ok()
        .map(|at| format!("\"{}\"", state::iso8601(at)))
        .unwrap_or_else(|| "null".to_owned());
    Some(format!(
        r#"{{"kind":"{kind}","sha256":"{sha}","size_bytes":"{size}","modified_at":{modified},"source_redacted":null}}"#,
        sha = sha256::hex(&bytes),
        size = metadata.len(),
    ))
}

pub fn geodata_json() -> String {
    let state = geo();
    let assets = [asset("geoip", "geoip.dat"), asset("geosite", "geosite.dat")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(",");
    let error = state.last_error.as_ref().map(|(code, message)| {
        format!(r#"{{"code":"{code}","message":"{}"}}"#, json::escape(message))
    });
    format!(
        r#"{{"observed_at":"{observed}","assets":[{assets}],"last_checked_at":{checked},"last_updated_at":{updated},"last_error":{error}}}"#,
        observed = state::iso8601(SystemTime::now()),
        checked = quoted_at(state.last_checked),
        updated = quoted_at(state.last_updated),
        error = error.unwrap_or_else(|| "null".to_owned()),
    )
}

pub fn geodata_settings_json() -> String {
    let state = geo();
    let urls = |list: &[String]| {
        list.iter()
            .map(|url| format!("\"{}\"", json::escape(url)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let source = if state.overridden { "override" } else { "default" };
    format!(
        r#"{{"source":"{source}","geosite":{{"urls":[{geosite}]}},"geoip":{{"urls":[{geoip}]}},"auto_update":{{"enabled":{auto},"interval_hours":{interval}}},"download":{{"route":"direct","group_id":null}}}}"#,
        geosite = urls(&state.geosite_urls),
        geoip = urls(&state.geoip_urls),
        auto = state.auto_enabled,
        interval = state.interval_hours,
    )
}

pub fn patch_geodata(
    client: &mut TcpStream,
    cors: &str,
    body: &str,
) -> io::Result<()> {
    let mut state = geo();
    for (key, slot) in [("geosite", 0usize), ("geoip", 1usize)] {
        let Some(section) = section_of(body, key) else { continue };
        let Some(urls_json) = section_of(&section, "urls") else { continue };
        let mut urls = Vec::new();
        let mut rest = urls_json.as_str();
        while let Some(start) = rest.find('"') {
            let Some(end) = rest[start + 1..].find('"') else { break };
            urls.push(rest[start + 1..start + 1 + end].to_owned());
            rest = &rest[start + 1 + end + 1..];
        }
        if urls.is_empty() || urls.len() > 4 {
            return fail(client, cors, 400, "invalid_request", "每个资产最多 4 个下载地址");
        }
        for url in &urls {
            if !url.starts_with("https://") && !url.starts_with("http://") {
                return fail(client, cors, 400, "invalid_request", "下载地址必须是 HTTP(S) URL");
            }
        }
        if slot == 0 {
            state.geosite_urls = urls;
        } else {
            state.geoip_urls = urls;
        }
        state.overridden = true;
    }
    if body.contains("\"auto_update\"") {
        if let Some(enabled) = json::field(body, "enabled") {
            state.auto_enabled = enabled == "true" || enabled == "on";
        }
        if let Some(hours) = json_number(body, "interval_hours") {
            if !(1..=168).contains(&hours) {
                return fail(client, cors, 400, "invalid_request", "interval_hours 在 1..168 之外");
            }
            state.interval_hours = hours as u32;
        }
    }
    drop(state);
    ok(client, cors, 200, &geodata_settings_json())
}

/// Extracts a nested JSON object's text for one top-level key.
fn section_of(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":{{");
    let start = body.find(&pattern)? + pattern.len() - 1;
    let mut depth = 0usize;
    for (offset, ch) in body[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(body[start..=start + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

pub fn start_geodata_update(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    let id = probes::create_operation("geodata_update");
    let worker_id = id.clone();
    thread::spawn(move || {
        let targets: [(&str, &str, Vec<String>); 2] = {
            let state = geo();
            [
                ("geoip", "geoip.dat", state.geoip_urls.clone()),
                ("geosite", "geosite.dat", state.geosite_urls.clone()),
            ]
        };
        let mut failures: Vec<String> = Vec::new();
        for (kind, file, urls) in targets {
            let path: PathBuf = config::data_dir().join(file);
            let mut stored = false;
            for url in &urls {
                match fetch::get(url, "lemonvpn-geodata", GEO_MAX_BYTES) {
                    Ok(response) if response.status == 200 && !response.body.is_empty() => {
                        let tmp = path.with_extension("dat.tmp");
                        if std::fs::write(&tmp, &response.body).is_ok()
                            && std::fs::rename(&tmp, &path).is_ok()
                        {
                            stored = true;
                            break;
                        }
                        failures.push(format!("{kind}: 写入数据目录失败"));
                    }
                    Ok(response) => failures.push(format!("{kind}: HTTP {}", response.status)),
                    Err(message) => failures.push(format!("{kind}: {message}")),
                }
            }
            let mut state = geo();
            state.last_checked = Some(SystemTime::now());
            if !stored {
                let message = failures.join("; ");
                state.last_error = Some(("geodata_update_failed".to_owned(), message.clone()));
                drop(state);
                probes::fail_operation(&worker_id, "geodata_update_failed", &message);
                return;
            }
            state.last_updated = Some(SystemTime::now());
            state.last_error = None;
        }
        probes::finish_operation(&worker_id, geodata_json());
    });
    accepted_reply(client, cors, probes::accepted(id, "geodata_update"))
}

// ---------- configuration source creation ----------

pub fn create_source(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let Some(path) = json::field(body, "path") else {
        return fail(client, cors, 400, "invalid_request", "path 缺失");
    };
    let Some(content) = json::field(body, "content") else {
        return fail(client, cors, 400, "invalid_request", "content 缺失");
    };
    if !path.ends_with(".dae")
        || path.len() > 1024
        || path.chars().any(|c| c.is_control())
        || path.contains('\\')
        || path.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return fail(client, cors, 400, "invalid_request", "path 不是合法的源文件名");
    }
    if content.len() > config::MAX_BYTES {
        return fail(client, cors, 413, "request_too_large", "配置超过 max_bytes");
    }
    let target = config::data_dir().join(&path);
    if target.exists() {
        return fail(client, cors, 409, "state_conflict", "同名源文件已存在");
    }
    let sources = std::fs::read_dir(config::data_dir())
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "dae"))
                .count()
        })
        .unwrap_or(0);
    if sources >= 4 {
        return fail(client, cors, 403, "quota_exceeded", "最多 4 个配置源");
    }
    if std::fs::write(&target, &content).is_err() {
        return fail(client, cors, 500, "internal_error", "源文件写入失败");
    }
    config::force_reload();
    let (valid, diagnostics) = config::validate_full_now();
    if !valid {
        let _ = std::fs::remove_file(&target);
        config::force_reload();
        return fail(client, cors, 422, "unsupported_value", &format!("校验未通过: {diagnostics}"));
    }
    accepted_reply(client, cors, probes::reload_accepted(config::reload_result_json()))
}

// ---------- connection closing ----------

pub fn close_connection(
    client: &mut TcpStream,
    cors: &str,
    id: &str,
) -> io::Result<()> {
    if connections::close(id) {
        no_content(client, cors)
    } else {
        fail(client, cors, 404, "resource_not_found", "没有这个连接")
    }
}

#[cfg(test)]
mod tests {
    use super::{etag_matches, parse_ops};
    use std::net::{TcpListener, TcpStream};

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn parse_ops_reads_the_rfc6902_operations() {
        let ops = parse_ops(
            r#"[{"op":"replace","path":"/policy","value":{"kind":"selector","native":"selector"}},{"op":"replace","path":"/config/default_member_id","value":"node-edge"},{"op":"replace","path":"/config/default_member_id","value":null},{"op":"remove","path":"/config/final_outbound"}]"#,
        );
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].op, "replace");
        assert_eq!(ops[0].path, "/policy");
        assert_eq!(ops[0].value.as_deref(), Some("selector"));
        assert_eq!(ops[1].path, "/config/default_member_id");
        assert_eq!(ops[1].value.as_deref(), Some("node-edge"));
        assert_eq!(ops[2].value, None);
        assert_eq!(ops[3].op, "remove");
        assert_eq!(ops[3].path, "/config/final_outbound");
        assert_eq!(ops[3].value, None);
    }

    #[test]
    fn etag_matches_accepts_the_advertised_forms() {
        assert!(etag_matches("abc", "abc"));
        assert!(etag_matches("\"abc\"", "abc"));
        assert!(etag_matches("W/\"abc\"", "abc"));
        assert!(etag_matches("sha256:abc", "abc"));
        assert!(etag_matches("sha256-abc", "abc"));
        assert!(etag_matches("\"def\", \"abc\"", "abc"));
        assert!(!etag_matches("def", "abc"));
    }

    #[test]
    fn patch_settings_round_trips_into_the_snapshot() {
        let (mut client, server) = socket_pair();
        drop(server);
        super::patch_settings(
            &mut client,
            "",
            r#"{"record_flows":"off","level":"debug","retention_seconds":120,"flows.max_flows":64}"#,
        )
        .unwrap();
        assert_eq!(super::recording_mode("record_flows"), "off");
        let snapshot = super::settings_json();
        assert!(snapshot.contains("\"source\":\"runtime\""));
        assert!(snapshot.contains("\"level\":\"debug\""));
        assert!(snapshot.contains("\"retention_seconds\":120"));
        assert!(snapshot.contains("\"max_flows\":64"));

        let (mut client, server) = socket_pair();
        drop(server);
        super::patch_settings(&mut client, "", r#"{"record_flows":"maybe"}"#).unwrap();
        assert_eq!(super::recording_mode("record_flows"), "off");

        let (mut client, server) = socket_pair();
        drop(server);
        super::patch_settings(&mut client, "", r#"{"flows.max_flows":0}"#).unwrap();
        assert_eq!(super::recording_mode("record_flows"), "off");

        super::settings().clear();
        assert_eq!(super::recording_mode("record_flows"), "on");
    }
}
