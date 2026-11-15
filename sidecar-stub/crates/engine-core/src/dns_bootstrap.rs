//! Independent bootstrap DNS: per-domain single flight and bounded failure backoff.
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use super::{canonical, encode_query, parse_response, QUERY_ID};
use crate::{config, dns_transport, dns_wire_cache, rules_runtime};

const MAX_FAILURES: usize = 256;
const MAX_PENDING: usize = 128;
const LOOKUP_BUDGET: Duration = Duration::from_secs(12);
type ResultCell = Arc<(Mutex<Option<Result<Vec<IpAddr>, String>>>, Condvar)>;
#[derive(Clone)]
struct Failure {
    domain: String,
    message: String,
    attempts: u32,
    at: Instant,
    observed: SystemTime,
    retry: Instant,
}
#[derive(Default)]
struct Store {
    scope: String,
    failures: HashMap<String, Failure>,
    pending: HashMap<String, ResultCell>,
    suppressed: u64,
}
static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
fn store() -> std::sync::MutexGuard<'static, Store> {
    STORE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
fn changed() -> String {
    "引导查询已取消或配置已更新，请重试".into()
}
struct Pending {
    domain: String,
    cell: ResultCell,
}
impl Drop for Pending {
    fn drop(&mut self) {
        let mut state = store();
        if state
            .pending
            .get(&self.domain)
            .is_some_and(|p| Arc::ptr_eq(p, &self.cell))
        {
            state.pending.remove(&self.domain);
            cancel(&self.cell);
        }
    }
}
fn cancel(cell: &ResultCell) {
    let (lock, wake) = &**cell;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(Err(changed()));
    wake.notify_all();
}
pub(super) fn flush() {
    let mut state = store();
    state.scope.clear();
    state.failures.clear();
    for (_, cell) in state.pending.drain() {
        cancel(&cell);
    }
}
pub(super) fn clear(domain: Option<&str>) -> io::Result<usize> {
    let name = domain.map(canonical).transpose()?;
    let name = name.as_deref().map(|s| s.trim_end_matches('.'));
    let mut state = store();
    let before = state.failures.len();
    state
        .failures
        .retain(|key, _| name.is_some_and(|name| name != key));
    let keys: Vec<_> = state
        .pending
        .keys()
        .filter(|key| name.is_none_or(|name| name == key.as_str()))
        .cloned()
        .collect();
    for key in keys {
        if let Some(cell) = state.pending.remove(&key) {
            cancel(&cell);
        }
    }
    Ok(before - state.failures.len())
}
pub(super) fn statistics() -> serde_json::Value {
    let (mut failures, suppressed) = {
        let state = store();
        (
            state
                .failures
                .values()
                .filter(|f| f.at.elapsed() < Duration::from_secs(600))
                .cloned()
                .collect::<Vec<_>>(),
            state.suppressed,
        )
    };
    failures.sort_by(|a, b| a.domain.cmp(&b.domain));
    serde_json::json!({"suppressed":suppressed,"failures":failures.iter().map(|f|serde_json::json!({
        "domain":f.domain,"message":f.message,"attempts":f.attempts,
        "retry_after_seconds":f.retry.saturating_duration_since(Instant::now()).as_secs_f64().ceil() as u64,
        "last_failure_at":crate::state::iso8601(f.observed),"nodes":config::node_names_for_host(&f.domain)
    })).collect::<Vec<_>>()})
}
pub(super) fn resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    let domain = canonical(host)?.trim_end_matches('.').to_owned();
    let roots = rules_runtime::current().document.bootstrap.clone();
    let generation = config::generation();
    let ipv6 = crate::dns_settings::current()?.ipv6_enabled;
    let epoch = dns_transport::epoch();
    let scope = format!("{generation}|{epoch}|{ipv6}|{roots:?}");
    let cell;
    let owner;
    {
        let mut state = store();
        if state.scope != scope {
            state.failures.clear();
            for (_, cell) in state.pending.drain() {
                cancel(&cell);
            }
            state.scope = scope.clone();
        }
        state
            .failures
            .retain(|_, f| f.at.elapsed() < Duration::from_secs(600));
        if let Some(failure) = state
            .failures
            .get(&domain)
            .filter(|f| f.retry > Instant::now())
            .cloned()
        {
            state.suppressed += 1;
            let left = failure
                .retry
                .saturating_duration_since(Instant::now())
                .as_secs_f64()
                .ceil() as u64;
            return Err(io::Error::other(format!(
                "{}；{left} 秒后自动重试",
                failure.message
            )));
        }
        if let Some(pending) = state.pending.get(&domain) {
            cell = pending.clone();
            owner = false;
        } else {
            if state.pending.len() >= MAX_PENDING {
                return Err(io::Error::other("引导 DNS 在途查询已达上限"));
            }
            cell = Arc::new((Mutex::new(None), Condvar::new()));
            state.pending.insert(domain.clone(), cell.clone());
            owner = true;
        }
    }
    if !owner {
        let (lock, wake) = &*cell;
        let reply = wake
            .wait_timeout_while(
                lock.lock().unwrap_or_else(|e| e.into_inner()),
                LOOKUP_BUDGET + Duration::from_secs(3),
                |r| r.is_none(),
            )
            .unwrap_or_else(|e| e.into_inner())
            .0;
        return reply
            .clone()
            .unwrap_or_else(|| Err("合并引导 DNS 查询超时".into()))
            .map_err(io::Error::other);
    }
    let _pending = Pending {
        domain: domain.clone(),
        cell: cell.clone(),
    };
    let result = lookup(&domain, &roots, &generation, ipv6)
        .map_err(|error| format!("域名“{domain}”引导解析失败：{error}"));
    let active = config::generation() == generation
        && dns_transport::epoch() == epoch
        && rules_runtime::current().document.bootstrap == roots
        && crate::dns_settings::current().is_ok_and(|s| s.ipv6_enabled == ipv6);
    let result = {
        let mut state = store();
        if !active
            || state.scope != scope
            || !state
                .pending
                .get(&domain)
                .is_some_and(|p| Arc::ptr_eq(p, &cell))
        {
            Err(changed())
        } else {
            state.pending.remove(&domain);
            match &result {
                Ok(_) => {
                    state.failures.remove(&domain);
                }
                Err(message) => {
                    let attempts = state
                        .failures
                        .get(&domain)
                        .map_or(1, |f| f.attempts.saturating_add(1));
                    if state.failures.len() >= MAX_FAILURES && !state.failures.contains_key(&domain)
                    {
                        if let Some(oldest) = state
                            .failures
                            .iter()
                            .min_by_key(|(_, f)| f.at)
                            .map(|(key, _)| key.clone())
                        {
                            state.failures.remove(&oldest);
                        }
                    }
                    let delay =
                        Duration::from_secs((15u64 << attempts.saturating_sub(1).min(5)).min(300));
                    state.failures.insert(
                        domain.clone(),
                        Failure {
                            domain,
                            message: message.clone(),
                            attempts,
                            at: Instant::now(),
                            observed: SystemTime::now(),
                            retry: Instant::now() + delay,
                        },
                    );
                }
            }
            result
        }
    };
    let (lock, wake) = &*cell;
    let mut reply = lock.lock().unwrap_or_else(|e| e.into_inner());
    if reply.is_none() {
        *reply = Some(result.clone());
    }
    wake.notify_all();
    result.map_err(io::Error::other)
}
fn lookup(host: &str, roots: &[String], generation: &str, ipv6: bool) -> io::Result<Vec<IpAddr>> {
    let started = Instant::now();
    let mut result = Vec::new();
    let mut last = "没有可用引导 DNS".to_owned();
    for (kind, code) in [("A", 1), ("AAAA", 28)] {
        if kind == "AAAA" && !ipv6 {
            continue;
        }
        let query = encode_query(
            QUERY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            host,
            code,
        )?;
        for (i, url) in roots.iter().enumerate() {
            let left = LOOKUP_BUDGET.saturating_sub(started.elapsed()).as_millis() as u64;
            if left < 250 {
                break;
            }
            let resolver = rules_runtime::model::Resolver {
                id: format!("bootstrap-{i}"),
                name: "引导解析".into(),
                url: url.clone(),
                timeout_ms: left.min(2000),
                ..Default::default()
            };
            let cache_key = format!("__bootstrap_{i}_{}", crate::sha256::hex(url.as_bytes()));
            match dns_wire_cache::query(&query, &cache_key, generation, true, || {
                dns_transport::exchange(&resolver, &query).map(|wire| dns_wire_cache::Packet {
                    wire,
                    upstream: Some(resolver.id.clone()),
                })
            }) {
                Ok(reply) => {
                    match parse_response(&reply.wire) {
                        Ok((status, answers)) => {
                            let addresses: Vec<IpAddr> = answers
                                .into_iter()
                                .filter(|a| a.kind == kind)
                                .filter_map(|a| a.data.parse().ok())
                                .collect();
                            if addresses.is_empty() {
                                last = format!("{kind} {status}，未返回地址");
                            }
                            result.extend(addresses);
                            // NXDOMAIN and NODATA are valid answers, not upstream outages.
                            break;
                        }
                        Err(e) => last = e.to_string(),
                    }
                }
                Err(e) => last = e.to_string(),
            }
        }
    }
    if result.is_empty() {
        Err(io::Error::other(last))
    } else {
        Ok(result)
    }
}
