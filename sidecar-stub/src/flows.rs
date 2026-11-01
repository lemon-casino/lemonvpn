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
use std::time::{Duration, SystemTime};

use crate::config::Decision;
use crate::json;
use crate::state;

pub const MAX_FLOWS: usize = 256;
pub const RETENTION: Duration = Duration::from_secs(300);

const STATES: [&str; 8] = [
    "observed", "routing", "dialing", "active", "closed", "blocked", "failed", "unknown",
];

pub struct Flow {
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
        id: format!("flow-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)),
        revision: 1,
        network: "tcp",
        state: "active",
        outbound: decision.outbound.clone(),
        chain: decision.chain.clone(),
        rule_id: decision.rule_id.clone(),
        rule_generation: decision.generation.clone(),
        rule_expression: decision.expression.clone(),
        domain_source,
        started_at: SystemTime::now(),
        ended_at: None,
        src: src.to_string(),
        dst: format!("{host}:{port}"),
        domain: domain.map(str::to_owned),
    }
}

fn push(flow: Flow) {
    let mut flows = store();
    let cutoff = SystemTime::now()
        .checked_sub(RETENTION)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    while flows
        .front()
        .is_some_and(|flow| flow.ended_at.is_some_and(|ended| ended < cutoff))
    {
        flows.pop_front();
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    while flows.len() >= MAX_FLOWS {
        flows.pop_front();
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
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
    if crate::control::recording_mode("record_flows") == "off" {
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

impl Guard {
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

pub fn list(
    network: &str,
    state_filter: &str,
    connection_id: Option<&str>,
    limit: usize,
) -> Result<String, &'static str> {
    if !matches!(network, "tcp" | "udp" | "all") {
        return Err("network must be tcp, udp or all");
    }
    if state_filter != "all" && !STATES.contains(&state_filter) {
        return Err("state is not a connection state");
    }
    let flows = store();
    let mut rows = Vec::new();
    for flow in flows.iter().rev() {
        if network != "all" && flow.network != network {
            continue;
        }
        if state_filter != "all" && flow.state != state_filter {
            continue;
        }
        if let Some(id) = connection_id {
            if flow.id != id {
                continue;
            }
        }
        rows.push(format!("{{{}}}", fields(flow)));
        if rows.len() >= limit {
            break;
        }
    }
    Ok(format!(
        r#"{{"instance_id":"{}","observed_at":"{}","coverage":{{"userspace_tcp":"full","userspace_udp":"none","kernel_direct":"none","kernel_block":"none","dns_intercept":"none","kernel_bypass":"none"}},"dropped_records":"{}","flows":[{}],"next_cursor":null}}"#,
        state::instance_id(),
        state::iso8601(SystemTime::now()),
        DROPPED.load(Ordering::Relaxed),
        rows.join(",")
    ))
}

pub fn detail(id: &str) -> Option<String> {
    let flows = store();
    let flow = flows.iter().find(|flow| flow.id == id)?;
    Some(format!(
        r#"{{{},{},"trace":{{"status":"disabled","missing":["not_instrumented"],"steps":[]}}}}"#,
        fields(flow),
        input(flow)
    ))
}

fn input(flow: &Flow) -> String {
    format!(
        r#""input":{{"src":"{}","dst":"{}","domain":{},"domain_source":{},"pid":null,"process_path":null,"src_mac":null,"ingress":null,"domain_rule_ids":[],"dscp":null,"mark":null}}"#,
        json::escape(&flow.src),
        json::escape(&flow.dst),
        nullable(flow.domain.as_deref()),
        nullable(flow.domain_source)
    )
}

fn fields(flow: &Flow) -> String {
    let chain = flow
        .chain
        .iter()
        .map(|member| format!("\"{}\"", json::escape(member)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#""id":"{}","instance_id":"{}","revision":{},"network":"{}","state":"{}","pname":null,"connection_id":null,"outbound":"{}","chain":[{}],"chain_source":"evaluation","rule_id":"{}","rule_generation_id":"{}","rule_expression":{},"rule_source":"userspace","ingress":null,"domain_source":{},"observed_by":"userspace","started_at":"{}","ended_at":{},"trace_status":"disabled""#,
        flow.id,
        state::instance_id(),
        flow.revision,
        flow.network,
        flow.state,
        json::escape(&flow.outbound),
        chain,
        json::escape(&flow.rule_id),
        json::escape(&flow.rule_generation),
        json::quoted(&flow.rule_expression),
        nullable(flow.domain_source),
        state::iso8601(flow.started_at),
        flow.ended_at
            .map(|ended| format!("\"{}\"", state::iso8601(ended)))
            .unwrap_or_else(|| "null".to_string())
    )
}

fn nullable(value: Option<&str>) -> String {
    value.map(json::quoted).unwrap_or_else(|| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::{begin, blocked, detail, list, Guard};
    use crate::config::Decision;
    use std::net::{Ipv4Addr, SocketAddr};

    fn decision(outbound: &'static str) -> Decision {
        Decision {
            outbound: outbound.to_owned(),
            chain: Vec::new(),
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
        assert!(active.contains(r#""domain_source":"http_host""#), "{active}");
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
        assert!(detail.contains(r#""trace":{"status":"disabled""#), "{detail}");
    }

    #[test]
    fn rejects_unknown_filters() {
        assert!(list("sctp", "all", None, 10).is_err());
        assert!(list("tcp", "bogus", None, 10).is_err());
    }
}
