//! Node and group health probes.
//!
//! `tcp_connect` measures a direct TCP connect to the node's own address.
//! `http` and `dns` measure a real request carried through the node: an HTTP
//! GET to a connectivity-check endpoint and a DNS query to the first configured
//! upstream. A node job finishes before the 202 is written; a group job runs its
//! members on a background thread and finishes the operation when the last
//! member has answered.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::config;
use crate::json;
use crate::outbound;
use crate::state;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_RETENTION: Duration = Duration::from_secs(300);
const MAX_OPERATIONS: usize = 64;
const MAX_SAMPLES: usize = 10;
const MAX_MEMBERS_PER_JOB: usize = 16;
const MAX_RESULTS_PER_JOB: usize = 64;
/// A stable, cache-friendly endpoint for the HTTP probe. The first response
/// byte is all the probe needs, so any reachable site proves the node path.
const HTTP_HOST: &str = "www.baidu.com";
const HTTP_PORT: u16 = 80;
const HTTP_PATH: &str = "/";
const DNS_NAME: &str = "example.com";

pub struct Accepted {
    pub body: String,
    pub location: String,
}

struct Health {
    node_id: String,
    ip_version: &'static str,
    json: String,
    samples: Vec<u32>,
}

struct Operation {
    id: String,
    kind: &'static str,
    created_at: SystemTime,
    status: &'static str,
    result: Option<String>,
    finished_at: Option<SystemTime>,
}

struct Store {
    health: Vec<Health>,
    operations: Vec<Operation>,
    next: u64,
}

static STORE: OnceLock<Mutex<Store>> = OnceLock::new();

fn store() -> MutexGuard<'static, Store> {
    STORE
        .get_or_init(|| {
            Mutex::new(Store {
                health: Vec::new(),
                operations: Vec::new(),
                next: 0,
            })
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn capabilities_json() -> String {
    format!(
        concat!(
            r#""probes":{{"available":true,"targets":["node","group"],"kinds":["tcp_connect","http","dns"],"#,
            r#""transports":["tcp"],"ip_versions":["ipv4","ipv6"],"limits":{{"#,
            r#""max_members_per_job":{},"max_results_per_job":{},"max_active_jobs":4,"#,
            r#""max_queued_jobs":16,"max_concurrent_per_target":1,"job_timeout_ms":15000,"#,
            r#""per_principal_requests_per_minute":60,"global_requests_per_minute":240}}}},"#,
            r#""operations":{{"available":true,"retention_seconds":{}}}"#
        ),
        MAX_MEMBERS_PER_JOB,
        MAX_RESULTS_PER_JOB,
        OPERATION_RETENTION.as_secs()
    )
}

/// Latest health samples for one node, as the `health` array of a Node.
pub fn health_json(node_id: &str) -> String {
    let store = store();
    let rows: Vec<&str> = store
        .health
        .iter()
        .filter(|health| health.node_id == node_id)
        .map(|health| health.json.as_str())
        .collect();
    format!("[{}]", rows.join(","))
}

pub fn operation_json(id: &str) -> Option<String> {
    let mut store = store();
    prune(&mut store);
    let operation = store.operations.iter().find(|operation| operation.id == id)?;
    let at = state::iso8601(operation.created_at);
    let finished = operation
        .finished_at
        .map_or_else(|| "null".to_owned(), |at| format!("\"{}\"", state::iso8601(at)));
    let result = operation.result.as_deref().unwrap_or("null");
    Some(format!(
        r#"{{"operation_id":"{}","kind":"{}","status":"{}","created_at":"{at}","started_at":"{at}","finished_at":{finished},"result":{result},"error":null}}"#,
        json::escape(&operation.id),
        operation.kind,
        operation.status,
    ))
}

pub fn start(body: &str) -> Result<Accepted, (u16, &'static str, String)> {
    let target = object(body, "target")
        .ok_or_else(|| (400, "invalid_request", "target 缺失或不是对象".to_owned()))?;
    let target_type = field(&target, "type")
        .ok_or_else(|| (400, "invalid_request", "target.type 缺失".to_owned()))?;
    let kind = field(body, "kind")
        .ok_or_else(|| (400, "invalid_request", "kind 缺失".to_owned()))?;
    if !matches!(kind.as_str(), "tcp_connect" | "http" | "dns") {
        return Err((422, "unsupported_value", format!("不支持探测类型 {kind}")));
    }
    let transport = array(body, "transport");
    if transport != ["tcp"] {
        return Err((
            422,
            "unsupported_value",
            format!("{kind} 只支持 tcp"),
        ));
    }
    let ip_version = field(body, "ip_version")
        .ok_or_else(|| (400, "invalid_request", "ip_version 缺失".to_owned()))?;
    let version: &'static str = match ip_version.as_str() {
        "ipv4" => "ipv4",
        "ipv6" => "ipv6",
        "any" => "any",
        _ => {
            return Err((
                422,
                "unsupported_value",
                format!("不支持 ip_version {ip_version}"),
            ))
        }
    };
    let warmth = field(body, "warmth")
        .ok_or_else(|| (400, "invalid_request", "warmth 缺失".to_owned()))?;
    let warmth: &'static str = match warmth.as_str() {
        "warm" => "warm",
        "cold" => "cold",
        _ => {
            return Err((
                422,
                "unsupported_value",
                format!("不支持 warmth {warmth}"),
            ))
        }
    };

    match target_type.as_str() {
        "node" => start_node(body, &target, &kind, version, warmth),
        "group" => start_group(body, &target, &kind, version, warmth),
        other => Err((
            422,
            "unsupported_value",
            format!("不支持探测目标 {other}"),
        )),
    }
}

fn start_node(
    body: &str,
    target: &str,
    kind: &str,
    version: &'static str,
    warmth: &'static str,
) -> Result<Accepted, (u16, &'static str, String)> {
    if has_key(body, "members") {
        return Err((
            422,
            "unsupported_value",
            "node 探测不接受 members".to_owned(),
        ));
    }
    let node_id = field(target, "node_id")
        .ok_or_else(|| (400, "invalid_request", "target.node_id 缺失".to_owned()))?;
    let node = config::node(&node_id)
        .ok_or_else(|| (404, "resource_not_found", "this engine has no such node".to_owned()))?;

    let id = create_operation("probe");
    let outcome = probe(&node, kind, version);
    let observed_at = state::iso8601(SystemTime::now());
    record_health(
        &node_id,
        kind,
        outcome.ip_version,
        warmth,
        outcome.state,
        outcome.latency,
        &outcome.error,
    );
    let row = row_json(
        &node_id,
        &node_id,
        kind,
        outcome.purpose,
        warmth,
        &outcome,
        &observed_at,
    );
    let result = format!(
        concat!(
            r#"{{"target":{{"type":"node","node_id":"{}"}},"#,
            r#""selection_changed":{{"tcp":false,"udp":false}},"#,
            r#""selection_before":{{"tcp":null,"udp":null}},"#,
            r#""selection_after":{{"tcp":null,"udp":null}},"#,
            r#""results":[{}]}}"#
        ),
        json::escape(&node_id),
        row
    );
    finish_operation(&id, result);
    Ok(accepted(id, "probe"))
}

fn start_group(
    body: &str,
    target: &str,
    kind: &str,
    version: &'static str,
    warmth: &'static str,
) -> Result<Accepted, (u16, &'static str, String)> {
    let group_id = field(target, "group_id")
        .ok_or_else(|| (400, "invalid_request", "target.group_id 缺失".to_owned()))?;
    let members = members_spec(body)?;
    let snapshot = config::group_snapshot(&group_id).ok_or_else(|| {
        (
            404,
            "resource_not_found",
            "this engine has no such group".to_owned(),
        )
    })?;
    let selected: Vec<String> = match members {
        Members::Direct | Members::Leaves => snapshot.members.clone(),
        Members::Ids(ids) => ids
            .iter()
            .filter_map(|id| {
                let name = id.strip_prefix("node-").unwrap_or(id);
                snapshot.members.iter().find(|member| *member == name).cloned()
            })
            .collect(),
    };
    if selected.is_empty() {
        return Err((
            422,
            "unsupported_value",
            "分组没有可探测的成员".to_owned(),
        ));
    }
    if selected.len() > MAX_RESULTS_PER_JOB {
        return Err((
            422,
            "unsupported_value",
            format!("分组超过 {MAX_RESULTS_PER_JOB} 个成员，请分批探测"),
        ));
    }

    let selection = format!(
        r#"{{"tcp":{},"udp":null}}"#,
        optional_string(snapshot.selected.as_deref().map(|name| format!("node-{name}")).as_deref())
    );
    let id = create_operation("probe");
    let operation_id = id.clone();
    let target = json::escape(&group_id);
    let kind = kind.to_owned();
    thread::spawn(move || {
        let mut rows = Vec::with_capacity(selected.len());
        for member in selected {
            let member_id = format!("node-{member}");
            let Some(node) = config::node(&member_id) else {
                continue;
            };
            let outcome = probe(&node, kind.as_str(), version);
            let observed_at = state::iso8601(SystemTime::now());
            record_health(
                &member_id,
                &kind,
                outcome.ip_version,
                warmth,
                outcome.state,
                outcome.latency,
                &outcome.error,
            );
            rows.push(row_json(
                &member_id,
                &member_id,
                &kind,
                outcome.purpose,
                warmth,
                &outcome,
                &observed_at,
            ));
        }
        let result = format!(
            concat!(
                r#"{{"target":{{"type":"group","group_id":"{}"}},"#,
                r#""selection_changed":{{"tcp":false,"udp":false}},"#,
                r#""selection_before":{},"selection_after":{},"#,
                r#""results":[{}]}}"#
            ),
            target,
            selection,
            selection,
            rows.join(",")
        );
        finish_operation(&operation_id, result);
    });
    Ok(accepted(id, "probe"))
}

enum Members {
    Direct,
    Leaves,
    Ids(Vec<String>),
}

fn members_spec(
    body: &str,
) -> Result<Members, (u16, &'static str, String)> {
    if !has_key(body, "members") {
        return Ok(Members::Direct);
    }
    if let Some(value) = field(body, "members") {
        return match value.as_str() {
            "direct" => Ok(Members::Direct),
            "leaves" => Ok(Members::Leaves),
            other => Err((
                422,
                "unsupported_value",
                format!("不支持 members {other}"),
            )),
        };
    }
    let ids = array(body, "members");
    if ids.is_empty() {
        return Err((422, "unsupported_value", "members 数组为空".to_owned()));
    }
    Ok(Members::Ids(ids))
}

struct Outcome {
    state: &'static str,
    latency: Option<u32>,
    ip_version: &'static str,
    error: Option<String>,
    purpose: &'static str,
}

fn probe(node: &config::Node, kind: &str, version: &'static str) -> Outcome {
    match kind {
        "http" => probe_http(node, version),
        "dns" => probe_dns(node, version),
        _ => probe_tcp(node, version),
    }
}

fn probe_tcp(node: &config::Node, version: &'static str) -> Outcome {
    let addresses = match addresses(&node.host, version) {
        Ok(addresses) => addresses,
        Err(error) => return unresolved(version, "data", error),
    };

    let mut last = None;
    for ip in addresses {
        let address = SocketAddr::new(ip, node.port);
        let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let started = Instant::now();
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Outcome {
                    state: "healthy",
                    latency: Some(started.elapsed().as_millis() as u32),
                    ip_version: family,
                    error: None,
                    purpose: "data",
                };
            }
            Err(error) => {
                last = Some(Outcome {
                    state: "unavailable",
                    latency: None,
                    ip_version: family,
                    error: Some(format!("连接 {address} 失败：{error}")),
                    purpose: "data",
                })
            }
        }
    }

    last.unwrap_or_else(|| unresolved(version, "data", "节点没有可用地址".to_owned()))
}

fn probe_http(node: &config::Node, version: &'static str) -> Outcome {
    let addresses = match addresses(&node.host, version) {
        Ok(addresses) => addresses,
        Err(error) => return unresolved(version, "data", error),
    };

    let mut last = None;
    for ip in addresses {
        let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let started = Instant::now();
        let attempt = outbound::socks5(
            &node.name,
            &ip.to_string(),
            node.port,
            node.username.as_deref(),
            node.password.as_deref(),
            HTTP_HOST,
            HTTP_PORT,
        )
        .and_then(|mut stream| {
            stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
            stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
            let request = format!(
                "GET {HTTP_PATH} HTTP/1.1\r\nHost: {HTTP_HOST}\r\nUser-Agent: lemonvpn-probe\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes())?;
            stream.flush()?;
            let mut first = [0u8; 1];
            stream.read_exact(&mut first)?;
            Ok(())
        });
        match attempt {
            Ok(()) => {
                return Outcome {
                    state: "healthy",
                    latency: Some(started.elapsed().as_millis() as u32),
                    ip_version: family,
                    error: None,
                    purpose: "data",
                }
            }
            Err(error) => {
                last = Some(Outcome {
                    state: "unavailable",
                    latency: None,
                    ip_version: family,
                    error: Some(format!("HTTP 探测经节点失败：{error}")),
                    purpose: "data",
                })
            }
        }
    }

    last.unwrap_or_else(|| unresolved(version, "data", "节点没有可用地址".to_owned()))
}

fn probe_dns(node: &config::Node, version: &'static str) -> Outcome {
    let Some(upstream) = config::upstreams().into_iter().next() else {
        return unresolved(version, "dns", "没有配置 DNS 上游".to_owned());
    };
    let addresses = match addresses(&node.host, version) {
        Ok(addresses) => addresses,
        Err(error) => return unresolved(version, "dns", error),
    };

    let mut last = None;
    for ip in addresses {
        let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let started = Instant::now();
        let attempt = outbound::socks5(
            &node.name,
            &ip.to_string(),
            node.port,
            node.username.as_deref(),
            node.password.as_deref(),
            &upstream.host,
            upstream.port,
        )
        .and_then(|mut stream| {
            stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
            stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
            let query = dns_query(DNS_NAME);
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            stream.write_all(&framed)?;
            stream.flush()?;
            let mut length = [0u8; 2];
            stream.read_exact(&mut length)?;
            let length = u16::from_be_bytes(length) as usize;
            if !(12..=4096).contains(&length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS 响应长度不合理",
                ));
            }
            let mut response = vec![0u8; length];
            stream.read_exact(&mut response)?;
            if response[3] & 0x0f != 0 {
                return Err(io::Error::other(format!(
                    "DNS 响应码 {}",
                    response[3] & 0x0f
                )));
            }
            Ok(())
        });
        match attempt {
            Ok(()) => {
                return Outcome {
                    state: "healthy",
                    latency: Some(started.elapsed().as_millis() as u32),
                    ip_version: family,
                    error: None,
                    purpose: "dns",
                }
            }
            Err(error) => {
                last = Some(Outcome {
                    state: "unavailable",
                    latency: None,
                    ip_version: family,
                    error: Some(format!("DNS 探测经节点失败：{error}")),
                    purpose: "dns",
                })
            }
        }
    }

    last.unwrap_or_else(|| unresolved(version, "dns", "节点没有可用地址".to_owned()))
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut query = Vec::with_capacity(32);
    query.extend_from_slice(&0x4c56u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn addresses(host: &str, version: &'static str) -> Result<Vec<IpAddr>, String> {
    let all = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => crate::dns::resolve(host).map_err(|error| format!("解析节点地址失败：{error}"))?,
    };
    let filtered: Vec<IpAddr> = all
        .into_iter()
        .filter(|ip| match version {
            "ipv4" => ip.is_ipv4(),
            "ipv6" => ip.is_ipv6(),
            _ => true,
        })
        .collect();
    if filtered.is_empty() {
        return Err(format!("节点没有 {version} 地址"));
    }
    Ok(filtered)
}

fn unresolved(version: &'static str, purpose: &'static str, error: String) -> Outcome {
    Outcome {
        state: "unavailable",
        latency: None,
        ip_version: if version == "ipv6" { "ipv6" } else { "ipv4" },
        error: Some(error),
        purpose,
    }
}

fn row_json(
    member_id: &str,
    leaf_id: &str,
    kind: &str,
    purpose: &str,
    warmth: &str,
    outcome: &Outcome,
    observed_at: &str,
) -> String {
    format!(
        concat!(
            r#"{{"member_id":"{}","resolved_leaf_node_id":"{}","kind":"{}","purpose":"{}","transport":"tcp","#,
            r#""ip_version":"{}","warmth":"{}","state":"{}","latency_ms":{},"health_updated":true,"#,
            r#""error":{},"observed_at":"{}"}}"#
        ),
        json::escape(member_id),
        json::escape(leaf_id),
        kind,
        purpose,
        outcome.ip_version,
        warmth,
        outcome.state,
        optional_number(outcome.latency),
        optional_string(outcome.error.as_deref()),
        observed_at,
    )
}

fn record_health(
    node_id: &str,
    kind: &str,
    ip_version: &'static str,
    warmth: &str,
    status: &'static str,
    latency: Option<u32>,
    error: &Option<String>,
) {
    let observed_at = state::iso8601(SystemTime::now());
    let mut store = store();
    let existing = store
        .health
        .iter()
        .position(|health| health.node_id == node_id && health.ip_version == ip_version);
    let mut samples = existing
        .map(|index| store.health[index].samples.clone())
        .unwrap_or_default();
    if let Some(latency) = latency {
        samples.push(latency);
        if samples.len() > MAX_SAMPLES {
            samples.remove(0);
        }
    }
    let average = (!samples.is_empty())
        .then(|| samples.iter().sum::<u32>() / samples.len() as u32);
    let purpose = if kind == "dns" { "dns" } else { "data" };
    let json = format!(
        concat!(
            r#"{{"transport":"tcp","purpose":"{}","ip_version":"{}","warmth":"{}","#,
            r#""measurement":"{}","sample_source":"probe","state":"{}","#,
            r#""latency_ms":{},"moving_avg_ms":{},"avg10_ms":{},"observed_at":"{}","#,
            r#""error":{}}}"#
        ),
        purpose,
        ip_version,
        warmth,
        kind,
        status,
        optional_number(latency),
        optional_number(average),
        optional_number(average),
        observed_at,
        optional_string(error.as_deref()),
    );
    let health = Health {
        node_id: node_id.to_owned(),
        ip_version,
        json: json.clone(),
        samples,
    };
    match existing {
        Some(index) => store.health[index] = health,
        None => store.health.push(health),
    }
}

fn create_operation(kind: &'static str) -> String {
    let mut store = store();
    prune(&mut store);
    store.next += 1;
    let id = format!("op-{}", store.next);
    store.operations.push(Operation {
        id: id.clone(),
        kind,
        created_at: SystemTime::now(),
        status: "running",
        result: None,
        finished_at: None,
    });
    id
}

/// A reload that has already happened: writing the source and parsing it is
/// fast, so the operation is terminal before the 202 is written.
pub fn reload_accepted(result: String) -> Accepted {
    let id = create_operation("reload");
    finish_operation(&id, result);
    accepted(id, "reload")
}

fn finish_operation(id: &str, result: String) {
    let mut store = store();
    if let Some(operation) = store.operations.iter_mut().find(|operation| operation.id == id) {
        operation.status = "succeeded";
        operation.result = Some(result);
        operation.finished_at = Some(SystemTime::now());
    }
}

fn accepted(id: String, kind: &str) -> Accepted {
    let href = format!("/api/v1/operations/{id}");
    Accepted {
        body: format!(
            r#"{{"operation_id":"{}","kind":"{}","status":"queued","href":"{}"}}"#,
            json::escape(&id),
            kind,
            href
        ),
        location: href,
    }
}

fn prune(store: &mut Store) {
    let now = SystemTime::now();
    store.operations.retain(|operation| {
        now.duration_since(operation.created_at)
            .map(|age| age < OPERATION_RETENTION)
            .unwrap_or(true)
    });
    if store.operations.len() > MAX_OPERATIONS {
        let excess = store.operations.len() - MAX_OPERATIONS;
        store.operations.drain(..excess);
    }
}

fn optional_number(value: Option<u32>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", json::escape(value)))
}

fn has_key(body: &str, key: &str) -> bool {
    let marker = format!("\"{key}\"");
    body.find(&marker)
        .is_some_and(|start| body[start + marker.len()..].trim_start().starts_with(':'))
}

fn field(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
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

fn array(body: &str, key: &str) -> Vec<String> {
    let marker = format!("\"{key}\"");
    let Some(start) = body.find(&marker) else {
        return Vec::new();
    };
    let rest = &body[start + marker.len()..];
    let Some(rest) = rest.split_once('[').map(|(_, rest)| rest) else {
        return Vec::new();
    };
    let Some(rest) = rest.split_once(']').map(|(rest, _)| rest) else {
        return Vec::new();
    };
    rest.split(',')
        .filter_map(|item| {
            let item = item.trim().trim_matches('"');
            (!item.is_empty()).then(|| item.to_owned())
        })
        .collect()
}

fn object(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('{')?;
    let mut depth = 1usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in rest.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..index].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{array, dns_query, field, has_key, members_spec, object, Members};

    #[test]
    fn reads_the_node_target_object() {
        let body = r#"{"target":{"type":"node","node_id":"node-lan"},"kind":"tcp_connect","transport":["tcp"],"ip_version":"any","warmth":"warm"}"#;
        let target = object(body, "target").unwrap();
        assert_eq!(field(&target, "type").as_deref(), Some("node"));
        assert_eq!(field(&target, "node_id").as_deref(), Some("node-lan"));
        assert_eq!(field(body, "kind").as_deref(), Some("tcp_connect"));
        assert_eq!(array(body, "transport"), ["tcp"]);
        assert!(has_key(body, "target"));
        assert!(!has_key(body, "members"));
    }

    #[test]
    fn finds_a_nested_target_without_matching_outer_braces() {
        let body = r#"{"extra":{"a":1},"target":{"type":"node","node_id":"node-a"}}"#;
        let target = object(body, "target").unwrap();
        assert_eq!(target, r#""type":"node","node_id":"node-a""#);
    }

    #[test]
    fn reads_group_member_specs() {
        assert!(matches!(
            members_spec(r#"{"target":{"type":"group","group_id":"proxy"}}"#).unwrap(),
            Members::Direct
        ));
        assert!(matches!(
            members_spec(r#"{"members":"leaves"}"#).unwrap(),
            Members::Leaves
        ));
        match members_spec(r#"{"members":["node-a","node-b"]}"#).unwrap() {
            Members::Ids(ids) => assert_eq!(ids, ["node-a", "node-b"]),
            _ => panic!("expected ids"),
        }
    }

    #[test]
    fn builds_a_dns_query_for_a_name() {
        let query = dns_query("example.com");
        assert_eq!(&query[..2], &0x4c56u16.to_be_bytes());
        assert_eq!(query[12], 7);
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3);
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query.last(), Some(&1));
    }
}
