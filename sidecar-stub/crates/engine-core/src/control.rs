//! Control-plane writes the dashboard drives: asynchronous operations
//! (reload, suspend, resume), runtime setting overrides, group selection and
//! config patches, routing trace simulation, DNS request rules and geodata
//! assets. Recorder overrides are process-local; Geo asset settings persist.

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

use crate::config;
use crate::connections;
use crate::http;
use crate::json;
use crate::probes;
use crate::state;

const HEADERS: &str = "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";

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
    let body =
        serde_json::json!({"error":{"code":code,"message":message},"request_id":null}).to_string();
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
    let generation = match config::force_reload_checked() {
        Ok(generation) => generation,
        Err(message) => return fail(client, cors, 422, "invalid_config", &message),
    };
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
    let flows_active = recording_active("record_flows");
    let logs_active = recording_active("record_logs");
    let dns_active = recording_active("record_dns_log");
    let buffered = crate::logs::store().buffered_count();
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
    let text = format!(
        r#"{{"observed_at":"{observed}","source":"{source}","recording":{{"flows":{{"allowed":true,"mode":"{flows_mode}","active":{flows_active}}},"logs":{{"allowed":true,"mode":"{logs_mode}","active":{logs_active}}},"dns_log":{{"allowed":true,"mode":"{dns_mode}","active":{dns_active}}},"events":{{"active":true}}}},"log":{{"level":"{level}","buffered_records":{buffered}}},"dns_log":{{"max_records":{dns_max}}},"flows":{{"max_flows":{flows_max},"retention_seconds":{retention}}}}}"#,
        observed = state::iso8601(SystemTime::now()),
        flows_active = flows_active,
        logs_active = logs_active,
        dns_active = dns_active,
        buffered = buffered,
        level = overrides
            .get("log.level")
            .cloned()
            .unwrap_or_else(|| "info".to_owned()),
        dns_max = number("dns_log.max_records", 2048),
        flows_max = number("flows.max_flows", crate::flows::MAX_FLOWS as u64),
        retention = number("flows.retention_seconds", crate::flows::RETENTION.as_secs()),
    );
    drop(overrides);
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("runtime settings JSON");
    value["geodata"] = crate::geodata_updates::settings_json();
    value.to_string()
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

pub fn patch_settings(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let request = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(value)) => value,
        _ => return fail(client, cors, 400, "invalid_request", "设置必须为 JSON 对象"),
    };
    let mut next = HashMap::new();
    for (key, value) in &request {
        if matches!(
            key.as_str(),
            "record_flows" | "record_logs" | "record_dns_log"
        ) {
            let Some(value) = value
                .as_str()
                .filter(|value| matches!(*value, "on" | "off" | "auto"))
            else {
                return fail(
                    client,
                    cors,
                    422,
                    "unsupported_value",
                    "录制模式只接受 on/off/auto",
                );
            };
            next.insert(key.clone(), value.to_owned());
        } else if !matches!(
            key.as_str(),
            "log"
                | "dns_log"
                | "flows"
                | "level"
                | "retention_seconds"
                | "dns_log.max_records"
                | "flows.max_flows"
                | "geodata"
        ) {
            return fail(
                client,
                cors,
                422,
                "unsupported_value",
                &format!("不支持的设置 {key}"),
            );
        }
    }
    for (section, supported) in [
        ("log", &["level"][..]),
        ("dns_log", &["max_records"][..]),
        ("flows", &["max_flows", "retention_seconds"][..]),
    ] {
        if let Some(value) = request.get(section) {
            let Some(object) = value.as_object() else {
                return fail(client, cors, 422, "unsupported_value", "设置分组必须为对象");
            };
            if object.keys().any(|key| !supported.contains(&key.as_str())) {
                return fail(
                    client,
                    cors,
                    422,
                    "unsupported_value",
                    "设置分组包含未支持的字段",
                );
            }
        }
    }
    let field = |section: &str, key: &str| {
        request
            .get(&format!("{section}.{key}"))
            .or_else(|| request.get(section).and_then(|value| value.get(key)))
            .or_else(|| request.get(key))
    };
    if let Some(level) = field("log", "level") {
        let Some(level) = level
            .as_str()
            .filter(|value| crate::logs::Level::parse(value).is_some())
        else {
            return fail(client, cors, 422, "unsupported_value", "日志级别无效");
        };
        next.insert("log.level".to_owned(), level.to_owned());
    }
    for (section, key, minimum, maximum) in [
        ("dns_log", "max_records", 64, 65536),
        ("flows", "max_flows", 1, 4096),
        ("flows", "retention_seconds", 1, 86400),
    ] {
        if let Some(value) = field(section, key) {
            let Some(value) = value
                .as_u64()
                .filter(|value| (minimum..=maximum).contains(value))
            else {
                return fail(
                    client,
                    cors,
                    422,
                    "unsupported_value",
                    &format!("{section}.{key} 必须在 {minimum}..={maximum}"),
                );
            };
            next.insert(format!("{section}.{key}"), value.to_string());
        }
    }
    if let Some(value) = request.get("geodata") {
        if let Err(message) = crate::geodata_updates::patch(value) {
            return fail(client, cors, 422, "invalid_geodata_settings", &message);
        }
    }
    settings().extend(next);
    crate::dns::apply_runtime_limits();
    crate::flows::apply_runtime_limits();
    crate::events::runtime_changed();
    ok(client, cors, 200, &settings_json())
}

static FLOW_DEMAND: AtomicU64 = AtomicU64::new(0);
static LOG_DEMAND: AtomicU64 = AtomicU64::new(0);
static DNS_DEMAND: AtomicU64 = AtomicU64::new(0);
fn demand(key: &str) -> &'static AtomicU64 {
    match key {
        "record_flows" => &FLOW_DEMAND,
        "record_logs" => &LOG_DEMAND,
        _ => &DNS_DEMAND,
    }
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn record_demand(key: &str) {
    demand(key).store(now_seconds().saturating_add(30), Ordering::Relaxed);
}
pub(crate) fn recording_active(key: &str) -> bool {
    match recording_mode(key).as_str() {
        "off" => false,
        "auto" => now_seconds() < demand(key).load(Ordering::Relaxed),
        _ => true,
    }
}
pub(crate) fn runtime_limit(key: &str, default: usize) -> usize {
    settings()
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
pub(crate) fn settings_log_level() -> crate::logs::Level {
    settings()
        .get("log.level")
        .and_then(|value| crate::logs::Level::parse(value))
        .unwrap_or(crate::logs::Level::Info)
}

// ---------- group selection ----------

static SELECTIONS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

pub(crate) fn forget_member(groups: &[String], member: &str) {
    let mut selections = SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for group in groups {
        for network in ["tcp", "udp"] {
            let key = format!("{network}:{group}");
            if selections.get(&key).is_some_and(|value| value == member) {
                selections.remove(&key);
            }
        }
    }
}

pub(crate) fn forget_group(group: &str) {
    let mut selections = SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for network in ["tcp", "udp"] {
        selections.remove(&format!("{network}:{group}"));
    }
}

/// The member a pinned selection or manual choice resolves to, by group name.
pub fn selection_override(group: &str) -> Option<String> {
    selection_override_for(group, "tcp")
}

pub fn selection_override_for(group: &str, network: &str) -> Option<String> {
    SELECTIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&format!("{network}:{group}"))
        .cloned()
}

fn group_name_of(id: &str) -> Option<String> {
    id.strip_prefix("group-").map(str::to_owned)
}

pub fn select(client: &mut TcpStream, cors: &str, id: &str, body: &str) -> io::Result<()> {
    let Some(name) = group_name_of(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    let Some(member) = json::field(body, "member_id") else {
        return fail(client, cors, 400, "invalid_request", "member_id 缺失");
    };
    let member_name = member.strip_prefix("node-").unwrap_or(&member).to_owned();
    let network = json::field(body, "network").unwrap_or_else(|| "both".to_owned());
    if !["tcp", "udp", "both"].contains(&network.as_str()) {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "network 只接受 tcp/udp/both",
        );
    }
    // Serialize selection changes with route decisions/config publication. The
    // epoch also rejects an outbound dial that began before this selection.
    let manual = config::with_current(|config| {
        let group = config.groups.iter().find(|group| group.name == name)?;
        let selector = matches!(group.policy, config::Policy::Selector);
        if !group.members.contains(&member_name) {
            return Some((false, selector, 0));
        }
        let mut selections = SELECTIONS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        for kind in ["tcp", "udp"] {
            if network == "both" || network == kind {
                let previous = selections.insert(format!("{kind}:{name}"), member_name.clone());
                changed |= previous.as_ref() != Some(&member_name);
            }
        }
        drop(selections);
        let interrupted = if changed {
            connections::selection_changed(&name, &network)
        } else {
            0
        };
        Some((true, selector, interrupted))
    });
    let Some((in_group, selector, interrupted)) = manual else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    if !in_group {
        return fail(client, cors, 422, "unsupported_value", "成员不在该组内");
    }
    crate::dns::flush();
    crate::compat::queue_hot_apply();
    let source = if selector { "runtime" } else { "override" };
    crate::events::runtime_changed();
    crate::logs::info(
        "engine::groups",
        "Group selection hot-applied.",
        Some(crate::logs::fields(&[
            ("group", &name),
            ("network", &network),
            ("connections_closed", &interrupted.to_string()),
        ])),
    );
    let revision = config::group_selection_snapshot(id)
        .map(|(revision, _)| revision)
        .unwrap_or_default();
    ok(
        client,
        cors,
        200,
        &serde_json::json!({"group_id":id,"member_id":member,"resolved_leaf_node_id":format!("node-{member_name}"),"network":network,"source":source,"selection_revision":revision,"connections_interrupted":interrupted>0,"connections_closed":interrupted}).to_string(),
    )
}

pub fn clear_selection(
    client: &mut TcpStream,
    cors: &str,
    id: &str,
    network: &str,
) -> io::Result<()> {
    let Some(name) = group_name_of(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    if !matches!(network, "tcp" | "udp" | "both") {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "network 只接受 tcp/udp/both",
        );
    }
    let interrupted = config::with_current(|config| {
        config.groups.iter().find(|group| group.name == name)?;
        let mut selections = SELECTIONS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        for kind in ["tcp", "udp"] {
            if network == "both" || network == kind {
                changed |= selections.remove(&format!("{kind}:{name}")).is_some();
            }
        }
        drop(selections);
        Some(if changed {
            connections::selection_changed(&name, network)
        } else {
            0
        })
    });
    let Some(interrupted) = interrupted else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    crate::dns::flush();
    crate::compat::queue_hot_apply();
    crate::events::runtime_changed();
    crate::logs::info(
        "engine::groups",
        "Group selection override released and hot-applied.",
        Some(crate::logs::fields(&[
            ("group", &name),
            ("network", network),
            ("connections_closed", &interrupted.to_string()),
        ])),
    );
    let Some((revision, selection)) = config::group_selection_snapshot(id) else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    ok(client, cors, 200, &serde_json::json!({"group_id":id,"network":network,"selection_revision":revision,"connections_interrupted":interrupted>0,"connections_closed":interrupted,"selection":selection}).to_string())
}

// ---------- group configuration patch ----------

pub fn group_config_json(id: &str) -> Option<String> {
    let name = group_name_of(id)?;
    config::with_current(|config| {
        let group = config.groups.iter().find(|group| group.name == name)?;
        Some(format!(
            r#"{{"policy":{{"kind":"{kind}","native":"{native}"}},"config":{{"default_member_id":{default},"final_outbound":{final},"check_url":null,"check_interval":null,"tolerance":null,"idle_timeout":null,"interrupt_connections":true}}}}"#,
            kind = group.policy.kind(),
            native = json::escape(&group.policy.native()),
            default = quoted(&group.default.as_ref().map(|name|format!("node-{name}"))),
            final = quoted(&group.final_outbound),
        ))
    })
}

struct PatchOp {
    op: String,
    path: String,
    value: Option<String>,
}

/// Decode complete RFC 6902 operations without depending on JSON field order.
fn parse_ops(body: &str) -> Result<Vec<PatchOp>, String> {
    let values: Vec<serde_json::Value> =
        serde_json::from_str(body).map_err(|error| error.to_string())?;
    if values.len() > 16 {
        return Err("一次最多提交 16 个 patch 操作".to_owned());
    }
    values
        .into_iter()
        .map(|value| {
            let op = value
                .get("op")
                .and_then(|value| value.as_str())
                .ok_or("patch 缺少 op")?
                .to_owned();
            let path = value
                .get("path")
                .and_then(|value| value.as_str())
                .ok_or("patch 缺少 path")?
                .to_owned();
            let field = value.get("value");
            if op != "remove" && field.is_none() {
                return Err("patch 缺少 value".to_owned());
            }
            let value = match field {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(value)) => Some(value.clone()),
                Some(value) if path == "/policy" => Some(
                    value
                        .get("native")
                        .and_then(|value| value.as_str())
                        .ok_or("policy 缺少 native")?
                        .to_owned(),
                ),
                _ => return Err("不支持的 patch 值类型".to_owned()),
            };
            Ok(PatchOp { op, path, value })
        })
        .collect()
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
    let expected_revision = config::current_sha256();
    if !etag_matches(matched, &expected_revision) {
        return fail(client, cors, 412, "stale_revision", "配置已被其他写入更新");
    }
    let current = config::with_current(|config| {
        config
            .groups
            .iter()
            .find(|group| group.name == name)
            .map(|group| {
                (
                    group.policy.native(),
                    group.default.clone(),
                    group.final_outbound.clone(),
                )
            })
    });
    let Some((policy_now, default_now, final_now)) = current else {
        return fail(client, cors, 404, "resource_not_found", "没有这个组");
    };
    let ops = match parse_ops(body) {
        Ok(ops) => ops,
        Err(message) => return fail(client, cors, 400, "invalid_request", &message),
    };
    let mut policy_value = policy_now;
    let mut default_value = default_now;
    let mut final_value = final_now;
    let mut changed = false;
    for op in ops {
        if !matches!(op.op.as_str(), "replace" | "add" | "remove" | "test") {
            return fail(
                client,
                cors,
                422,
                "unsupported_value",
                "不支持的 patch 操作",
            );
        }
        let value = if op.op == "remove" { None } else { op.value };
        match op.path.as_str() {
            "/policy" => {
                let Some(policy) = value.as_deref().and_then(config::parse_policy) else {
                    return fail(
                        client,
                        cors,
                        422,
                        "unsupported_value",
                        "不支持的策略或 policy 为空",
                    );
                };
                if op.op == "test" {
                    if config::parse_policy(&policy_value) != Some(policy) {
                        return fail(client, cors, 409, "state_conflict", "policy test 失败");
                    }
                } else {
                    policy_value = policy.native();
                    changed = true;
                }
            }
            "/config/default_member_id" => {
                let value =
                    value.map(|value| value.strip_prefix("node-").unwrap_or(&value).to_owned());
                if op.op == "test" {
                    if value != default_value {
                        return fail(
                            client,
                            cors,
                            409,
                            "state_conflict",
                            "default_member_id test 失败",
                        );
                    }
                } else {
                    if value.as_ref().is_some_and(|member| {
                        !config::with_current(|config| {
                            config
                                .groups
                                .iter()
                                .find(|group| group.name == name)
                                .is_some_and(|group| group.members.contains(member))
                        })
                    }) {
                        return fail(client, cors, 422, "unsupported_value", "默认成员不在组内");
                    }
                    default_value = value;
                    changed = true;
                }
            }
            "/config/final_outbound" => {
                if op.op == "test" {
                    if value != final_value {
                        return fail(
                            client,
                            cors,
                            409,
                            "state_conflict",
                            "final_outbound test 失败",
                        );
                    }
                } else {
                    final_value = value;
                    changed = true;
                }
            }
            _ => return fail(client, cors, 422, "unsupported_value", "此字段不可修改"),
        }
    }
    if !changed {
        return ok(
            client,
            cors,
            200,
            &group_config_json(id).unwrap_or_default(),
        );
    }
    let policy_new = Some(policy_value);
    let default_new = Some(default_value);
    let final_new = Some(final_value);
    let content = config::source_content();
    let rewritten = config::rewrite_group(
        &content,
        &name,
        policy_new.as_deref(),
        default_new.as_ref().map(|value| value.as_deref()),
        final_new.as_ref().map(|value| value.as_deref()),
    );
    let Ok(rewritten) = rewritten else {
        return fail(
            client,
            cors,
            422,
            "unsupported_value",
            "组在源文件中定位失败",
        );
    };
    if let Err(failure) =
        config::replace_source(config::SOURCE_ID, &rewritten, Some(&expected_revision))
    {
        return fail(client, cors, failure.status, failure.code, &failure.message);
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
            || candidate
                .strip_prefix("sha256:")
                .is_some_and(|value| value == sha)
            || candidate
                .strip_prefix("sha256-")
                .is_some_and(|value| value == sha)
    })
}

// ---------- routing trace ----------

pub fn trace(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let Ok(request) = serde_json::from_str::<serde_json::Value>(body) else {
        return fail(client, cors, 400, "invalid_request", "请求不是有效的 JSON");
    };
    let fields = request.get("input").unwrap_or(&request);
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    let domain = text("domain");
    let dst_ip = text("dst_ip");
    let Some(host) = domain.clone().or_else(|| dst_ip.clone()) else {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "input 需要 domain 或 dst_ip",
        );
    };
    let live = request.get("resolve").and_then(|value| value.as_str()) == Some("live");
    let resolved = dst_ip.or_else(|| {
        if live && domain.is_some() {
            crate::dns::resolve(&host)
                .ok()
                .and_then(|addresses| addresses.first().map(|address| address.to_string()))
        } else {
            None
        }
    });
    let network = text("network").unwrap_or_else(|| "tcp".to_owned());
    if !matches!(network.as_str(), "tcp" | "udp") {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "network 只接受 tcp/udp",
        );
    }
    let process = json::field(body, "pname")
        .map(|name| crate::platform::process::ProcessInfo::selector(&name));
    let mut input = config::RoutingInput::new(&host, &network);
    input.process = process.as_ref();
    input.destination_ip = resolved.as_deref().and_then(|address| address.parse().ok());
    input.source_ip = text("src_ip").and_then(|address| address.parse().ok());
    let port = |key: &str| -> Result<Option<u16>, ()> {
        match fields.get(key).filter(|value| !value.is_null()) {
            None => Ok(None),
            Some(value) => value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
                .map(Some)
                .ok_or(()),
        }
    };
    let (Ok(source_port), Ok(destination_port)) = (port("src_port"), port("dst_port")) else {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "端口必须为 1 到 65535 的整数",
        );
    };
    input.source_port = source_port;
    input.destination_port = destination_port;
    let traced = config::trace_input(input);
    let body = serde_json::json!({"mode":"simulation","instance_id":state::instance_id(),
        "generation_id":traced["generation_id"],"observed_at":state::iso8601(SystemTime::now()),
        "evaluations":[traced["evaluation"]],"dns":[]})
    .to_string();
    ok(client, cors, 200, &body)
}

// ---------- DNS request rules ----------

pub fn dns_rules_json() -> String {
    config::with_current(|config| {
        let list = |rules: &[config::DnsRule], response: bool| {
            let mut rows = rules.iter().enumerate().map(|(index,rule)| {
                let action = match rule.upstream.as_str() { "accept"=>"accept", value if crate::dns::reply_code(value).is_some()=>"reject", _ if response=>"requery", _=>"upstream" };
                serde_json::json!({"rule_id":format!("dns-{}-{index}",if response {"resp"}else{"req"}),"index":index,"expression":rule.expression,"action":action,
                    "x-lemonvpn-action":if action=="reject" && rule.upstream!="reject"{Some(&rule.upstream)}else{None},
                    "upstream":if action=="upstream" || action=="requery"{Some(&rule.upstream)}else{None},"source":serde_json::from_str::<serde_json::Value>(&config::source_json(rule.line,rule.source_id.as_deref())).unwrap_or_default(),"kind":"rule"})
            }).collect::<Vec<_>>();
            let fallback = if response {
                Some(config.dns_response_fallback.as_str())
            } else {
                config.dns_request_fallback.as_deref().or_else(|| {
                    config
                        .upstreams
                        .first()
                        .map(|upstream| upstream.name.as_str())
                })
            };
            let action = match fallback {
                Some("accept") => "accept",
                Some(value) if crate::dns::reply_code(value).is_some() => "reject",
                _ if response => "requery",
                _ => "upstream",
            };
            let origin = if response {
                &config.dns_response_fallback_source
            } else {
                &config.dns_request_fallback_source
            };
            let fallback_source = origin
                .as_ref()
                .map(|(line, path)| {
                    serde_json::from_str::<serde_json::Value>(&config::source_json(
                        *line,
                        path.as_deref(),
                    ))
                    .unwrap_or_default()
                })
                .unwrap_or(serde_json::Value::Null);
            rows.push(serde_json::json!({"rule_id":format!("dns-{}-fallback",if response {"resp"}else{"req"}),"index":rows.len(),"expression":format!("fallback: {}",fallback.unwrap_or("default")),"action":action,
                "x-lemonvpn-action":if action=="reject" && fallback!=Some("reject"){fallback}else{None},
                "upstream":if action=="upstream" || action=="requery"{fallback}else{None},"source":fallback_source,"kind":"fallback"}));
            rows
        };
        serde_json::json!({"generation_id":config.generation,"request":list(&config.dns_rules,false),"response":list(&config.dns_response_rules,true)}).to_string()
    })
}

// ---------- geodata ----------

pub fn geodata_json() -> String {
    crate::geodata_updates::status().to_string()
}
pub fn geodata_settings_json() -> String {
    crate::geodata_updates::settings_json().to_string()
}
pub fn patch_geodata(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return fail(client, cors, 400, "invalid_request", "设置必须为有效 JSON"),
    };
    match crate::geodata_updates::patch(&value) {
        Ok(()) => ok(client, cors, 200, &geodata_settings_json()),
        Err(message) => fail(client, cors, 422, "invalid_geodata_settings", &message),
    }
}
pub fn start_geodata_update(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    match crate::geodata_updates::begin() {
        Ok(accepted) => accepted_reply(client, cors, accepted),
        Err(message) => fail(client, cors, 409, "geodata_update_unavailable", &message),
    }
}

// ---------- configuration source creation ----------

pub fn create_source(client: &mut TcpStream, cors: &str, body: &str) -> io::Result<()> {
    let Some(path) = json::field(body, "path") else {
        return fail(client, cors, 400, "invalid_request", "path 缺失");
    };
    let Some(content) = json::field(body, "content") else {
        return fail(client, cors, 400, "invalid_request", "content 缺失");
    };
    if !config::source_name_valid(&path) {
        return fail(
            client,
            cors,
            400,
            "invalid_request",
            "path 不是合法的源文件名",
        );
    }
    let (valid, diagnostics) = config::validate_sources(
        &[("source-new".to_owned(), path.clone(), content.clone())],
        "full",
    );
    if !valid {
        return fail(
            client,
            cors,
            422,
            "invalid_config",
            &format!("校验未通过：{diagnostics}"),
        );
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
    if let Err(error) = crate::storage::create_atomic(&target, content.as_bytes()) {
        return fail(
            client,
            cors,
            if error.kind() == io::ErrorKind::AlreadyExists {
                409
            } else {
                500
            },
            "source_write_failed",
            &format!("源文件写入失败：{error}"),
        );
    }
    config::force_reload();
    let (valid, diagnostics) = config::validate_full_now();
    if !valid {
        let _ = std::fs::remove_file(&target);
        config::force_reload();
        return fail(
            client,
            cors,
            422,
            "unsupported_value",
            &format!("校验未通过: {diagnostics}"),
        );
    }
    accepted_reply(
        client,
        cors,
        probes::reload_accepted(config::reload_result_json()),
    )
}

// ---------- connection closing ----------

pub fn close_connection(client: &mut TcpStream, cors: &str, id: &str) -> io::Result<()> {
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
        ).expect("valid patch");
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
