//! DNS requests carried through the node's actual UDP relay. No TCP fallback.
use std::io;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::{
    config, state, Accepted, Members, Outcome, CONNECT_TIMEOUT, DNS_NAME, MAX_MEMBERS_PER_JOB,
    MAX_RESULTS_PER_JOB,
};

pub(super) fn probe(node: &config::Node, version: &'static str) -> Outcome {
    let Some(upstream) = config::upstreams().into_iter().next() else {
        return super::unresolved(version, "dns", "没有配置 DNS 上游".to_owned());
    };
    let addresses = match super::addresses(&node.host, version) {
        Ok(addresses) => addresses,
        Err(error) => return super::unresolved(version, "dns", error),
    };
    let query = super::dns_query(DNS_NAME);
    let mut last = None;
    for address in addresses {
        if crate::runtime::stopping() {
            break;
        }
        let family = if address.is_ipv4() { "ipv4" } else { "ipv6" };
        let started = Instant::now();
        let attempt = (|| -> io::Result<()> {
            let relay = crate::compat::Datagram::open_probe(
                node,
                &address.to_string(),
                &upstream.host,
                upstream.port,
            )?;
            relay.send(&query)?;
            let deadline = Instant::now() + CONNECT_TIMEOUT;
            let mut response = [0u8; 4096];
            loop {
                if crate::runtime::stopping() {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "引擎正在退出"));
                }
                match relay.recv(&mut response) {
                    Ok((length, _, port)) => {
                        if port == upstream.port
                            && length >= 12
                            && response[..2] == query[..2]
                            && response[2] & 0x80 != 0
                        {
                            let code = response[3] & 0x0f;
                            return if code == 0 {
                                Ok(())
                            } else {
                                Err(io::Error::other(format!("DNS 响应码 {code}")))
                            };
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "UDP DNS 响应超时"));
                }
                thread::sleep(Duration::from_millis(10));
            }
        })();
        let outcome = Outcome {
            state: if attempt.is_ok() {
                "healthy"
            } else {
                "unavailable"
            },
            latency: attempt
                .as_ref()
                .ok()
                .map(|_| started.elapsed().as_millis().min(u32::MAX as u128) as u32),
            ip_version: family,
            error: attempt
                .err()
                .map(|error| format!("UDP DNS 探测经节点失败：{error}")),
            purpose: "dns",
        };
        if outcome.state == "healthy" {
            crate::group_policy::probe_result(node, "udp", true, outcome.latency);
            return outcome;
        }
        last = Some(outcome);
    }
    let outcome =
        last.unwrap_or_else(|| super::unresolved(version, "dns", "节点没有可用地址".to_owned()));
    if version == "any" {
        crate::group_policy::probe_result(node, "udp", false, None);
    }
    outcome
}

pub(super) fn selection(group: &str) -> serde_json::Value {
    let snapshot = config::group_snapshot(group);
    serde_json::json!({
        "tcp": snapshot.as_ref().and_then(|snapshot| snapshot.selected.as_ref()).map(|node| format!("node-{node}")),
        "udp": snapshot.as_ref().and_then(|snapshot| snapshot.selected_udp.as_ref()).map(|node| format!("node-{node}"))
    })
}

pub(super) fn start(
    body: &str,
    target: &str,
    target_type: &str,
    transports: &[String],
    version: &'static str,
    warmth: &'static str,
) -> Result<Accepted, (u16, &'static str, String)> {
    let (target_id, nodes, group) = match target_type {
        "node" => {
            if super::has_key(body, "members") {
                return Err((
                    422,
                    "unsupported_value",
                    "node 探测不接受 members".to_owned(),
                ));
            }
            let id = super::field(target, "node_id")
                .ok_or_else(|| (400, "invalid_request", "缺少 node_id".to_owned()))?;
            let node = config::node(&id)
                .ok_or_else(|| (404, "resource_not_found", "没有这个节点".to_owned()))?;
            (id, vec![node], false)
        }
        "group" => {
            let id = super::field(target, "group_id")
                .ok_or_else(|| (400, "invalid_request", "缺少 group_id".to_owned()))?;
            let snapshot = config::group_snapshot(&id)
                .ok_or_else(|| (404, "resource_not_found", "没有这个组".to_owned()))?;
            let names = match super::members_spec(body)? {
                Members::Direct | Members::Leaves => snapshot.members,
                Members::Ids(ids) => {
                    let names: Vec<String> = ids
                        .into_iter()
                        .map(|id| id.strip_prefix("node-").unwrap_or(&id).to_owned())
                        .collect();
                    if names.iter().any(|name| !snapshot.members.contains(name)) {
                        return Err((422, "unsupported_value", "探测成员不在该组内".to_owned()));
                    }
                    names
                }
            };
            let nodes = names
                .iter()
                .filter_map(|name| config::node(&format!("node-{name}")))
                .collect();
            (id, nodes, true)
        }
        _ => return Err((422, "unsupported_value", "探测只支持 node/group".to_owned())),
    };
    if nodes.is_empty()
        || nodes.len() > MAX_MEMBERS_PER_JOB
        || nodes.len() * transports.len() > MAX_RESULTS_PER_JOB
    {
        return Err((
            422,
            "unsupported_value",
            "探测成员或结果数量超限，请分批探测".to_owned(),
        ));
    }
    let before = if group {
        selection(&target_id)
    } else {
        serde_json::json!({"tcp":null,"udp":null})
    };
    let target = if group {
        serde_json::json!({"type":"group","group_id":target_id})
    } else {
        serde_json::json!({"type":"node","node_id":target_id})
    };
    let transports: Vec<&'static str> = ["tcp", "udp"]
        .into_iter()
        .filter(|value| transports.iter().any(|chosen| chosen == value))
        .collect();
    let id = super::create_operation("probe");
    let operation = id.clone();
    thread::spawn(move || {
        let mut rows = Vec::new();
        for node in nodes {
            for transport in &transports {
                if crate::runtime::stopping() {
                    super::fail_operation(&operation, "cancelled", "引擎正在退出");
                    return;
                }
                let outcome = if *transport == "udp" {
                    probe(&node, version)
                } else {
                    super::probe(&node, "dns", version)
                };
                let node_id = format!("node-{}", node.name);
                let observed = state::iso8601(SystemTime::now());
                super::record_network_health(
                    &node_id,
                    transport,
                    "dns",
                    outcome.ip_version,
                    warmth,
                    outcome.state,
                    outcome.latency,
                    &outcome.error,
                );
                rows.push(super::row_network_json(
                    &node_id, &node_id, transport, "dns", "dns", warmth, &outcome, &observed,
                ));
            }
        }
        let after = if group {
            selection(&target_id)
        } else {
            before.clone()
        };
        let result = format!(
            r#"{{"target":{target},"selection_changed":{{"tcp":{},"udp":{}}},"selection_before":{before},"selection_after":{after},"results":[{}]}}"#,
            before["tcp"] != after["tcp"],
            before["udp"] != after["udp"],
            rows.join(",")
        );
        super::finish_operation(&operation, result);
    });
    Ok(super::accepted(id, "probe"))
}
