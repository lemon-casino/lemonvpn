//! Bounded flow history behind `GET /api/v1/flows`.
//!
//! A flow is recorded when the inbound has made a routing decision, before the
//! upstream dial, and is closed when the tunnel ends. The routing labels are the
//! ones the datapath actually used; fields the userspace datapath cannot see
//! (process name, kernel verdict, trace steps) stay null or disabled.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use crate::config::Decision;
use crate::json;
use crate::state;

pub const MAX_FLOWS: usize = 256;
pub const RETENTION: Duration = Duration::from_secs(300);

const STATES: [&str; 8] = [
    "observed", "routing", "dialing", "active", "closed", "blocked", "failed", "unknown",
];

pub struct Flow {
    pub process: Option<crate::platform::process::ProcessInfo>,
    pub id: String,
    pub revision: u64,
    pub network: &'static str,
    pub state: &'static str,
    pub outbound: String,
    pub chain: Vec<String>,
    pub rule_id: String,
    pub rule_generation: String,
    pub rule_expression: String,
    pub domain_source: Option<&'static str>,
    pub started_at: SystemTime,
    pub ended_at: Option<SystemTime>,
    pub src: String,
    pub dst: String,
    pub domain: Option<String>,
    pub connection_id: Option<String>,
}

static NEXT: AtomicU64 = AtomicU64::new(1);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static FLOWS: OnceLock<Mutex<VecDeque<Flow>>> = OnceLock::new();

fn store() -> MutexGuard<'static, VecDeque<Flow>> {
    FLOWS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn new_flow(
    src: SocketAddr,
    host: &str,
    port: u16,
    domain: Option<&str>,
    domain_source: Option<&'static str>,
    decision: &Decision,
) -> Flow {
    Flow {
        process: decision.process.clone(),
        id: format!(
            "flow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ),
        revision: 1,
        network: "tcp",
        state: "dialing",
        outbound: decision.outbound.clone(),
        chain: decision.selection_path(),
        rule_id: decision.rule_id.clone(),
        rule_generation: decision.generation.clone(),
        rule_expression: decision.expression.clone(),
        domain_source,
        started_at: SystemTime::now(),
        ended_at: None,
        src: src.to_string(),
        dst: crate::connections::target_address(host, port),
        domain: domain.map(str::to_owned),
        connection_id: None,
    }
}

fn prune_records(flows: &mut VecDeque<Flow>, reserve: usize) {
    let maximum = crate::control::runtime_limit("flows.max_flows", MAX_FLOWS);
    let retention = Duration::from_secs(crate::control::runtime_limit(
        "flows.retention_seconds",
        RETENTION.as_secs() as usize,
    ) as u64);
    let cutoff = SystemTime::now()
        .checked_sub(retention)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    flows.retain(|flow| flow.ended_at.is_none_or(|ended| ended >= cutoff));
    while flows.len().saturating_add(reserve) > maximum {
        flows.pop_front();
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn apply_runtime_limits() {
    prune_records(&mut store(), 0);
}
fn push(flow: Flow) {
    let mut flows = store();
    prune_records(&mut flows, 1);
    flows.push_back(flow);
}

/// Records an active flow; dropping the guard marks it closed.
pub fn begin(
    src: SocketAddr,
    host: &str,
    port: u16,
    domain: Option<&str>,
    domain_source: Option<&'static str>,
    decision: &Decision,
) -> Guard {
    if !crate::control::recording_active("record_flows") {
        return Guard {
            id: String::new(),
            finished: true,
        };
    }
    let flow = new_flow(src, host, port, domain, domain_source, decision);
    let id = flow.id.clone();
    push(flow);
    Guard {
        id,
        finished: false,
    }
}

/// Records a terminal flow for a connection the routing rules refused.
pub fn blocked(
    src: SocketAddr,
    host: &str,
    port: u16,
    domain: Option<&str>,
    domain_source: Option<&'static str>,
    decision: &Decision,
) {
    if !crate::control::recording_active("record_flows") {
        return;
    }
    let mut flow = new_flow(src, host, port, domain, domain_source, decision);
    flow.state = "blocked";
    flow.ended_at = Some(SystemTime::now());
    flow.revision = 2;
    push(flow);
}

pub struct Guard {
    id: String,
    finished: bool,
}

pub(crate) fn begin_udp(src: SocketAddr, host: &str, port: u16, decision: &Decision) -> Guard {
    let domain = (host.parse::<std::net::IpAddr>().is_err()).then_some(host);
    let guard = begin(
        src,
        host,
        port,
        domain,
        domain.map(|_| "explicit"),
        decision,
    );
    if let Some(flow) = store().iter_mut().find(|f| f.id == guard.id) {
        flow.network = "udp";
    }
    guard
}
pub(crate) fn blocked_udp(src: SocketAddr, host: &str, port: u16, decision: &Decision) {
    if !crate::control::recording_active("record_flows") {
        return;
    }
    let domain = (host.parse::<std::net::IpAddr>().is_err()).then_some(host);
    let mut flow = new_flow(
        src,
        host,
        port,
        domain,
        domain.map(|_| "explicit"),
        decision,
    );
    flow.network = "udp";
    flow.state = "blocked";
    flow.ended_at = Some(SystemTime::now());
    flow.revision = 2;
    push(flow);
}

impl Guard {
    pub(crate) fn link_connection(&self, id: &str) -> Option<(String, Option<&'static str>)> {
        let mut flows = store();
        let flow = flows
            .iter_mut()
            .find(|flow| !self.finished && flow.id == self.id)?;
        flow.connection_id = Some(id.to_owned());
        flow.state = "active";
        flow.revision += 1;
        Some((flow.id.clone(), flow.domain_source))
    }

    pub fn finish(mut self, state: &'static str) {
        self.close(state);
    }

    fn close(&mut self, state: &'static str) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut flows = store();
        if let Some(flow) = flows.iter_mut().find(|flow| flow.id == self.id) {
            flow.state = state;
            flow.ended_at = Some(SystemTime::now());
            flow.revision += 1;
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.close("closed");
    }
}

struct ListSnapshot {
    id: u64,
    at: Instant,
    observed: String,
    query: String,
    rows: Vec<String>,
    dropped: u64,
}
static SNAPSHOTS: OnceLock<Mutex<VecDeque<ListSnapshot>>> = OnceLock::new();
static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
pub fn list(
    network: &str,
    state_filter: &str,
    connection_id: Option<&str>,
    limit: usize,
) -> Result<String, &'static str> {
    list_page(network, state_filter, connection_id, limit, None)
}

pub(crate) fn list_page(
    network: &str,
    state_filter: &str,
    connection_id: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<String, &'static str> {
    crate::control::record_demand("record_flows");
    if !matches!(network, "tcp" | "udp" | "all") {
        return Err("network must be tcp, udp or all");
    }
    if state_filter != "all" && !STATES.contains(&state_filter) {
        return Err("state is not a connection state");
    }
    if limit == 0 {
        return Err("limit must be positive");
    }
    let query = format!(
        "{network}|{state_filter}|{}",
        connection_id.unwrap_or_default()
    );
    let mut snapshots = SNAPSHOTS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    snapshots.retain(|snapshot| snapshot.at.elapsed() < Duration::from_secs(30));
    let (snapshot, offset) = if let Some(cursor) = cursor {
        let (id, offset) = cursor
            .strip_prefix("fp-")
            .and_then(|value| value.split_once('-'))
            .ok_or("cursor_expired")?;
        let id: u64 = id.parse().map_err(|_| "cursor_expired")?;
        let offset: usize = offset.parse().map_err(|_| "cursor_expired")?;
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.id == id && snapshot.query == query)
            .ok_or("cursor_expired")?;
        if offset >= snapshot.rows.len() {
            return Err("cursor_expired");
        }
        (snapshot, offset)
    } else {
        let mut flows = store();
        prune_records(&mut flows, 0);
        let rows = flows
            .iter()
            .rev()
            .filter(|flow| {
                (network == "all" || flow.network == network)
                    && (state_filter == "all" || flow.state == state_filter)
                    && connection_id.is_none_or(|id| flow.connection_id.as_deref() == Some(id))
            })
            .map(|flow| format!("{{{},{}}}", fields(flow), input(flow)))
            .collect();
        drop(flows);
        while snapshots.len() >= 8 {
            snapshots.pop_front();
        }
        snapshots.push_back(ListSnapshot {
            id: NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
            at: Instant::now(),
            observed: state::iso8601(SystemTime::now()),
            query,
            rows,
            dropped: DROPPED.load(Ordering::Relaxed),
        });
        (snapshots.back().unwrap(), 0)
    };
    let end = offset.saturating_add(limit).min(snapshot.rows.len());
    let next = (end < snapshot.rows.len()).then(|| format!("fp-{}-{end}", snapshot.id));
    Ok(format!(
        r#"{{"instance_id":"{}","observed_at":"{}","coverage":{{"userspace_tcp":"full","userspace_udp":"full","kernel_direct":"none","kernel_block":"none","dns_intercept":"none","kernel_bypass":"none"}},"dropped_records":"{}","flows":[{}],"next_cursor":{}}}"#,
        state::instance_id(),
        snapshot.observed,
        snapshot.dropped,
        snapshot.rows[offset..end].join(","),
        next.as_deref()
            .map(json::quoted)
            .unwrap_or_else(|| "null".to_owned())
    ))
}

pub fn detail(id: &str) -> Option<String> {
    crate::control::record_demand("record_flows");
    let mut flows = store();
    prune_records(&mut flows, 0);
    let flow = flows.iter().find(|flow| flow.id == id)?;
    Some(format!(
        r#"{{{},{},"trace":{{"status":"disabled","missing":["not_instrumented"],"steps":[]}}}}"#,
        fields(flow),
        input(flow)
    ))
}

fn input(flow: &Flow) -> String {
    format!(
        "\"input\":{}",
        serde_json::json!({"src":flow.src,"dst":flow.dst,"domain":flow.domain,"domain_source":flow.domain_source,
        "pid":flow.process.as_ref().and_then(|process|process.pid),"process_path":flow.process.as_ref().and_then(|process|process.path.as_deref()),
        "src_mac":null,"ingress":null,"domain_rule_ids":[],"dscp":null,"mark":null})
    )
}

fn fields(flow: &Flow) -> String {
    let body = serde_json::json!({
        "id":flow.id,"instance_id":state::instance_id(),"revision":flow.revision,"network":flow.network,"state":flow.state,
        "pname":flow.process.as_ref().and_then(|process|process.name.as_deref()),"connection_id":flow.connection_id,"outbound":flow.outbound,"chain":flow.chain,"chain_source":"evaluation",
        "rule_id":flow.rule_id,"rule_generation_id":flow.rule_generation,"rule_expression":flow.rule_expression,"rule_source":"userspace",
        "ingress":null,"domain_source":flow.domain_source,"observed_by":"userspace","started_at":state::iso8601(flow.started_at),
        "ended_at":flow.ended_at.map(state::iso8601),"trace_status":"disabled"
    }).to_string();
    body[1..body.len() - 1].to_owned()
}

fn nullable(value: Option<&str>) -> String {
    value
        .map(json::quoted)
        .unwrap_or_else(|| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::{begin, blocked, detail, list, Guard};
    use crate::config::Decision;
    use std::net::{Ipv4Addr, SocketAddr};

    fn decision(outbound: &'static str) -> Decision {
        Decision {
            epoch: crate::connections::route_epoch(outbound, "tcp"),
            process: None,
            outbound: outbound.to_owned(),
            chain: Vec::new(),
            dependencies: Vec::new(),
            target: crate::config::Target::Direct,
            rule_id: "traffic:0".into(),
            generation: "generation-test".into(),
            expression: "domain(full: example.com) -> direct".into(),
        }
    }

    fn src() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40000))
    }

    #[test]
    fn closes_a_flow_when_its_guard_drops() {
        let guard: Guard = begin(
            src(),
            "example.com",
            443,
            Some("example.com"),
            Some("http_host"),
            &decision("direct"),
        );
        let active = list("tcp", "active", None, 100).unwrap();
        assert!(active.contains(r#""state":"active""#), "{active}");
        assert!(
            active.contains(r#""domain_source":"http_host""#),
            "{active}"
        );
        drop(guard);
        let closed = list("tcp", "closed", None, 100).unwrap();
        assert!(closed.contains(r#""state":"closed""#), "{closed}");
    }

    #[test]
    fn records_blocked_flows_and_their_detail() {
        blocked(
            src(),
            "blocked.example",
            443,
            Some("blocked.example"),
            Some("http_host"),
            &decision("block"),
        );
        let body = list("tcp", "blocked", None, 100).unwrap();
        assert!(body.contains(r#""outbound":"block""#), "{body}");
        let id = body
            .split(r#""id":""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("flow id");
        let detail = detail(id).expect("flow detail");
        assert!(detail.contains(r#""input""#), "{detail}");
        assert!(
            detail.contains(r#""trace":{"status":"disabled""#),
            "{detail}"
        );
    }

    #[test]
    fn rejects_unknown_filters() {
        assert!(list("sctp", "all", None, 10).is_err());
        assert!(list("tcp", "bogus", None, 10).is_err());
    }
}
