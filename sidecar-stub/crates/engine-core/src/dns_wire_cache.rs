//! Shared wire-response cache. Transaction IDs/case are per caller; TTL fields
//! are aged, OPT is not a resource TTL, and unsupported EDNS stays uncached.
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
struct Entry {
    origin: Option<String>,
    wire: Vec<u8>,
    at: Instant,
    ttl: u32,
    fields: Vec<(usize, u32)>,
    name: String,
    pool: String,
    negative: bool,
    hits: u64,
    touched: u64,
    prefetch: bool,
}
#[derive(Clone)]
pub struct Packet {
    pub wire: Vec<u8>,
    pub upstream: Option<String>,
}
type ResultCell = Arc<(Mutex<Option<Result<Packet, String>>>, Condvar)>;
#[derive(Default)]
struct Store {
    entries: HashMap<String, Entry>,
    pending: HashMap<String, ResultCell>,
    bytes: usize,
    clock: u64,
}
static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
static EPOCH: AtomicU64 = AtomicU64::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static MERGED: AtomicU64 = AtomicU64::new(0);
static STALE: AtomicU64 = AtomicU64::new(0);
pub struct Reply {
    pub upstream: Option<String>,
    pub wire: Vec<u8>,
    pub source: &'static str,
    pub prefetch: bool,
}
fn store() -> std::sync::MutexGuard<'static, Store> {
    STORE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
fn u16at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
fn u32at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn question(query: &[u8]) -> Option<(String, usize)> {
    if query.len() < 12
        || query[2] & 0xf8 != 0
        || u16at(query, 4)? != 1
        || u16at(query, 6)? != 0
        || u16at(query, 8)? != 0
    {
        return None;
    }
    let mut label = 12;
    loop {
        let size = *query.get(label)? as usize;
        if size & 0xc0 != 0 || size > 63 {
            return None;
        }
        label = label.checked_add(1 + size)?;
        if size == 0 {
            break;
        }
    }
    let (name, end) = crate::dns::read_name(query, 12).ok()?;
    let end = end + 4;
    if end > query.len() {
        return None;
    }
    let records = u16at(query, 10)?;
    if records > 1 {
        return None;
    }
    if records == 1 {
        let (_, name_end) = crate::dns::read_name(query, end).ok()?;
        if u16at(query, name_end)? != 41 {
            return None;
        }
        let n = u16at(query, name_end + 8)? as usize;
        let mut at = name_end + 10;
        let stop = at.checked_add(n)?;
        if stop != query.len() {
            return None;
        }
        while at < stop {
            let kind = u16at(query, at)?;
            let len = u16at(query, at + 2)? as usize;
            at = at.checked_add(4 + len)?;
            if kind != 12 || at > stop {
                return None;
            }
        }
    } else if query.len() != end {
        return None;
    }
    let mut normalized = query[2..].to_vec();
    for byte in normalized.get_mut(10..end - 6)? {
        *byte = byte.to_ascii_lowercase();
    }
    Some((format!("{}:{}", name, crate::sha256::hex(&normalized)), end))
}
fn inspect(wire: &[u8]) -> Option<(u32, Vec<(usize, u32)>, bool)> {
    let (_, end) = crate::dns::read_name(wire, 12).ok()?;
    let mut at = end + 4;
    let an = u16at(wire, 6)? as usize;
    let ns = u16at(wire, 8)? as usize;
    let ar = u16at(wire, 10)? as usize;
    let negative = wire.get(3)? & 15 == 3 || wire[3] & 15 == 0 && an == 0;
    if wire[3] & 15 != 0 && wire[3] & 15 != 3 || wire[2] & 2 != 0 {
        return None;
    }
    let mut fields = Vec::new();
    let mut ttl = u32::MAX;
    let mut negative_ttl = None;
    for _ in 0..an + ns + ar {
        let (_, after) = crate::dns::read_name(wire, at).ok()?;
        let kind = u16at(wire, after)?;
        let value = u32at(wire, after + 4)?;
        let len = u16at(wire, after + 8)? as usize;
        let data = after + 10;
        let stop = data.checked_add(len)?;
        if stop > wire.len() {
            return None;
        }
        if kind == 250 {
            return None;
        }
        if kind == 41 {
            // Cookies and ECS must not be replayed from a shared cache.
            let mut opt = data;
            while opt < stop {
                if u16at(wire, opt)? != 12 {
                    return None;
                }
                let n = u16at(wire, opt + 2)? as usize;
                opt = opt.checked_add(n + 4)?;
                if opt > stop {
                    return None;
                }
            }
        } else {
            fields.push((after + 4, value));
            ttl = ttl.min(value);
            if kind == 6 {
                let (_, first) = crate::dns::read_name(wire, data).ok()?;
                let (_, second) = crate::dns::read_name(wire, first).ok()?;
                if second + 20 > stop {
                    return None;
                }
                negative_ttl = Some(value.min(u32at(wire, second + 16)?));
            }
        }
        at = stop;
    }
    if at != wire.len() {
        return None;
    }
    if negative {
        ttl = negative_ttl?;
    }
    if ttl == 0 || ttl == u32::MAX {
        return None;
    }
    Some((ttl.min(86400), fields, negative))
}
fn reissue(entry: &Entry, query: &[u8], stale: bool) -> Option<Vec<u8>> {
    let (_, end) = question(query)?;
    let (_, reply_end) = crate::dns::read_name(&entry.wire, 12).ok()?;
    if end != reply_end + 4 {
        return None;
    }
    let mut wire = entry.wire.clone();
    wire[..2].copy_from_slice(&query[..2]);
    wire[12..end].copy_from_slice(&query[12..end]);
    let elapsed = entry.at.elapsed().as_secs().min(u32::MAX as u64) as u32;
    for (at, ttl) in &entry.fields {
        wire[*at..*at + 4].copy_from_slice(
            &(if stale {
                1
            } else {
                ttl.saturating_sub(elapsed)
            })
            .to_be_bytes(),
        );
    }
    if stale {
        wire[3] &= !0x20;
    }
    Some(wire)
}
pub fn flush() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    let mut state = store();
    state.entries.clear();
    state.bytes = 0;
    for pending in state.pending.values() {
        let (lock, wake) = &**pending;
        *lock.lock().unwrap() = Some(Err("DNS 策略已更新，请重试".into()));
        wake.notify_all();
    }
    state.pending.clear();
}
pub fn query(
    query: &[u8],
    pool: &str,
    generation: &str,
    use_cache: bool,
    network: impl FnOnce() -> io::Result<Packet>,
) -> io::Result<Reply> {
    query_inner(query, pool, generation, use_cache, false, network)
}
fn query_inner(
    query: &[u8],
    pool: &str,
    generation: &str,
    use_cache: bool,
    force: bool,
    network: impl FnOnce() -> io::Result<Packet>,
) -> io::Result<Reply> {
    let options = crate::rules_runtime::current().document.cache.clone();
    let Some((qkey, _)) = question(query).filter(|_| use_cache) else {
        return network().map(|packet| Reply {
            wire: packet.wire,
            upstream: packet.upstream,
            source: "bypass",
            prefetch: false,
        });
    };
    let key = format!(
        "{}|{}|{}|{}|{}",
        generation,
        crate::dns_transport::epoch(),
        crate::dns_transport::route_key(pool),
        pool,
        qkey
    );
    let epoch = EPOCH.load(Ordering::Acquire);
    let pending;
    let owner;
    {
        let mut state = store();
        state.clock += 1;
        let clock = state.clock;
        if let Some(entry) = state.entries.get_mut(&key) {
            if !force && entry.at.elapsed().as_secs() < u64::from(entry.ttl) {
                if let Some(wire) = reissue(entry, query, false) {
                    entry.hits += 1;
                    entry.touched = clock;
                    HITS.fetch_add(1, Ordering::Relaxed);
                    let prefetch = options.prefetch
                        && !entry.prefetch
                        && entry.hits >= 3
                        && entry.ttl > 10
                        && entry.at.elapsed().as_secs() >= u64::from(entry.ttl) * 9 / 10;
                    if prefetch {
                        entry.prefetch = true;
                    }
                    return Ok(Reply {
                        wire,
                        upstream: entry.origin.clone(),
                        source: "cache",
                        prefetch,
                    });
                }
            }
        }
        if let Some(cell) = state.pending.get(&key) {
            pending = cell.clone();
            owner = false;
            MERGED.fetch_add(1, Ordering::Relaxed);
        } else {
            if state.pending.len() >= 256 {
                return Err(io::Error::other("DNS 在途查询已达上限"));
            }
            pending = Arc::new((Mutex::new(None), Condvar::new()));
            state.pending.insert(key.clone(), pending.clone());
            owner = true;
            MISSES.fetch_add(1, Ordering::Relaxed);
        }
    }
    if !owner {
        let (lock, wake) = &*pending;
        let result = wake
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(30), |r| {
                r.is_none()
            })
            .unwrap()
            .0;
        let packet = result
            .as_ref()
            .ok_or_else(|| io::Error::other("合并 DNS 查询超时"))?
            .clone()
            .map_err(io::Error::other)?;
        let mut wire = packet.wire;
        let (_, end) = question(query).unwrap();
        if let Ok((_, after)) = crate::dns::read_name(&wire, 12) {
            if end == after + 4 {
                wire[12..end].copy_from_slice(&query[12..end]);
            }
        }
        wire[..2].copy_from_slice(&query[..2]);
        return Ok(Reply {
            wire,
            upstream: packet.upstream,
            source: "coalesced",
            prefetch: false,
        });
    }
    let mut result = network();
    let mut source = "upstream";
    if result.is_err() && options.stale_seconds > 0 {
        let state = store();
        if let Some(entry) = state.entries.get(&key).filter(|e| {
            !e.negative && e.at.elapsed().as_secs() <= u64::from(e.ttl) + options.stale_seconds
        }) {
            if let Some(reply) = reissue(entry, query, true) {
                result = Ok(Packet {
                    wire: reply,
                    upstream: entry.origin.clone(),
                });
                source = "stale";
                STALE.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    if let Ok(packet) = &result {
        let wire = &packet.wire;
        if source == "upstream" && epoch == EPOCH.load(Ordering::Acquire) {
            if let Some((ttl, fields, negative)) =
                inspect(wire).filter(|(_, _, n)| !*n || options.negative)
            {
                crate::config::with_current(|active| {
                    if active.generation != generation {
                        return;
                    }
                    let mut state = store();
                    if epoch != EPOCH.load(Ordering::Acquire) {
                        return;
                    }
                    if let Some(old) = state.entries.remove(&key) {
                        state.bytes = state.bytes.saturating_sub(old.wire.len());
                    }
                    state.clock += 1;
                    let touched = state.clock;
                    let name = crate::dns::read_name(query, 12)
                        .map(|v| v.0)
                        .unwrap_or_default();
                    state.bytes += wire.len();
                    state.entries.insert(
                        key.clone(),
                        Entry {
                            origin: packet.upstream.clone(),
                            wire: wire.clone(),
                            at: Instant::now(),
                            ttl,
                            fields,
                            name,
                            pool: pool.into(),
                            negative,
                            hits: 0,
                            touched,
                            prefetch: false,
                        },
                    );
                    while state.entries.len() > options.capacity || state.bytes > options.max_bytes
                    {
                        let oldest = state
                            .entries
                            .iter()
                            .min_by_key(|(_, e)| e.touched)
                            .map(|(k, _)| k.clone());
                        let Some(oldest) = oldest else { break };
                        if let Some(old) = state.entries.remove(&oldest) {
                            state.bytes = state.bytes.saturating_sub(old.wire.len());
                        }
                    }
                });
            }
        }
    }
    {
        let mut state = store();
        if state
            .pending
            .get(&key)
            .is_some_and(|p| Arc::ptr_eq(p, &pending))
        {
            state.pending.remove(&key);
        }
    }
    let (lock, wake) = &*pending;
    let mut cell = lock.lock().unwrap();
    if cell.is_none() {
        *cell = Some(
            result
                .as_ref()
                .map(Clone::clone)
                .map_err(ToString::to_string),
        );
    }
    wake.notify_all();
    drop(cell);
    result.map(|packet| Reply {
        wire: packet.wire,
        upstream: packet.upstream,
        source,
        prefetch: false,
    })
}
pub fn statistics() -> Value {
    let state = store();
    json!({"scope":"Rust shared wire cache","entries":state.entries.len(),"bytes":state.bytes,"pending":state.pending.len(),"hits":HITS.load(Ordering::Relaxed),"misses":MISSES.load(Ordering::Relaxed),"coalesced":MERGED.load(Ordering::Relaxed),"stale":STALE.load(Ordering::Relaxed)})
}
pub fn entries(query: &str) -> Value {
    let state = store();
    json!({"entries":state.entries.values().filter(|e|e.name.contains(query)).take(100).map(|e|json!({"domain":e.name,"pool":e.pool,"negative":e.negative,"ttl_seconds":e.ttl.saturating_sub(e.at.elapsed().as_secs().min(u32::MAX as u64) as u32),"hits":e.hits,"bytes":e.wire.len()})).collect::<Vec<_>>()})
}

static PREFETCH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PREFETCH_RATE: Mutex<Option<(Instant, u8)>> = Mutex::new(None);
pub fn prefetch(
    query: Vec<u8>,
    pool: String,
    generation: String,
    network: impl FnOnce() -> io::Result<Packet> + Send + 'static,
) {
    {
        let mut rate = PREFETCH_RATE.lock().unwrap();
        let (now, count) = rate.get_or_insert((Instant::now(), 0));
        if now.elapsed() > Duration::from_secs(1) {
            *now = Instant::now();
            *count = 0;
        }
        if *count >= 2 {
            return;
        }
        *count += 1;
    }
    if PREFETCH.fetch_add(1, Ordering::AcqRel) >= 2 {
        PREFETCH.fetch_sub(1, Ordering::AcqRel);
        return;
    }
    std::thread::spawn(move || {
        struct Permit;
        impl Drop for Permit {
            fn drop(&mut self) {
                PREFETCH.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _permit = Permit;
        let _ = query_inner(&query, &pool, &generation, true, true, network);
    });
}

pub fn remove_name(name: &str) -> usize {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut state = store();
    let keys = state
        .entries
        .iter()
        .filter(|(_, e)| e.name.trim_end_matches('.').eq_ignore_ascii_case(&name))
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
        if let Some(row) = state.entries.remove(&key) {
            state.bytes = state.bytes.saturating_sub(row.wire.len());
        }
    }
    count
}
