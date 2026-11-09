//! Resolver behind direct dials and the `/api/v1/dns/*` endpoints.
//!
//! Upstreams come from the `dns { upstream { ... } }` block of the accepted
//! configuration. Queries the resolver makes for its own dials are recorded in a
//! bounded log; diagnostic `/dns/query` calls are not, as the contract requires.
//! Only positive answers are cached (`coverage.negative` is false).

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use crate::config;
use crate::json;
use crate::state;

const MAX_CACHE: usize = 1024;
const MAX_LOG: usize = 2048;
const MAX_PAGE: usize = 500;
const MAX_TYPES: usize = 8;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub const RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "NS", "PTR", "MX", "TXT", "SRV", "SOA", "CAA",
];

#[derive(Clone, Debug)]
struct Answer {
    name: String,
    kind: &'static str,
    ttl: u32,
    data: String,
}

#[derive(Clone, Debug)]
struct Entry {
    id: String,
    domain: String,
    kind: &'static str,
    status: String,
    answers: Vec<Answer>,
    expires: SystemTime,
    upstream: Option<String>,
    generation: String,
}

#[derive(Clone, Debug)]
struct Record {
    seq: u64,
    at: SystemTime,
    src: Option<SocketAddr>,
    domain: String,
    kind: &'static str,
    status: String,
    cached: bool,
    upstream: Option<String>,
    route: serde_json::Value,
    elapsed_ms: u64,
    answers: Vec<Answer>,
}

struct Resolver {
    cache: Vec<Entry>,
    log: Vec<Record>,
    next_entry: u64,
    next_record: u64,
}

static RESOLVER: OnceLock<Mutex<Resolver>> = OnceLock::new();
static QUERY_ID: AtomicU16 = AtomicU16::new(1);

fn store() -> MutexGuard<'static, Resolver> {
    RESOLVER
        .get_or_init(|| {
            Mutex::new(Resolver {
                cache: Vec::new(),
                log: Vec::new(),
                next_entry: 0,
                next_record: 0,
            })
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn available() -> bool {
    !config::upstreams().is_empty()
}

/// Wire-preserving loopback DNS for the TUN core. Keep the configured DNS
/// rules authoritative, including TXT/SRV/EDNS and TCP truncation fallback.
pub(crate) fn start_forwarder(
    shutdown: crate::runtime::Shutdown,
) -> io::Result<(u16, std::thread::JoinHandle<()>)> {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = tcp.local_addr()?.port();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))?;
    tcp.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;
    let thread = std::thread::spawn(move || {
        let mut jobs: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut buffer = vec![0; 65535];
        while !shutdown.wait(Duration::from_millis(5)) {
            let mut pending = Vec::new();
            for job in jobs.drain(..) {
                if job.is_finished() {
                    let _ = job.join();
                } else {
                    pending.push(job);
                }
            }
            jobs = pending;
            if jobs.len() >= 32 {
                continue;
            }
            if let Ok((length, peer)) = udp.recv_from(&mut buffer) {
                let query = buffer[..length].to_vec();
                if let Ok(socket) = udp.try_clone() {
                    jobs.push(std::thread::spawn(move || {
                        if let Ok(reply) = forward_wire(&query) {
                            let _ = socket.send_to(&reply, peer);
                        }
                    }));
                }
            }
            if jobs.len() < 32 {
                if let Ok((mut socket, _)) = tcp.accept() {
                    jobs.push(std::thread::spawn(move || {
                        let _ = socket.set_nonblocking(false);
                        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
                        let mut len = [0; 2];
                        if socket.read_exact(&mut len).is_err() {
                            return;
                        }
                        let mut query = vec![0; u16::from_be_bytes(len) as usize];
                        if socket.read_exact(&mut query).is_err() {
                            return;
                        }
                        if let Ok(reply) = forward_wire(&query) {
                            let _ = socket.write_all(&(reply.len() as u16).to_be_bytes());
                            let _ = socket.write_all(&reply);
                        }
                    }));
                }
            }
        }
        for job in jobs {
            let _ = job.join();
        }
    });
    Ok((port, thread))
}

fn forward_wire(query: &[u8]) -> io::Result<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 || query[4..6] != [0, 1] {
        return Err(invalid("DNS 查询无效"));
    }
    let (name, end) = read_name(query, 12)?;
    if query.len() < end + 4 {
        return Err(invalid("DNS 查询截断"));
    }
    let kind = type_name(u16::from_be_bytes([query[end], query[end + 1]]));
    let generation = config::generation();
    let routed = config::dns_route_for(&name, kind);
    let forced = routed.as_ref().map(|(upstream, _)| upstream.as_str());
    let started = Instant::now();
    let (response, upstream) = routed_exchange(query, &name, kind, forced, &generation)?;
    if let Some(kind) = kind {
        if let Ok((status, answers)) = parse_response(&response) {
            record(
                None,
                &name,
                kind,
                &status,
                false,
                upstream.as_deref(),
                started.elapsed().as_millis() as u64,
                &answers,
                request_route(false, routed.as_ref()),
            );
            let _ = cache_put_at(
                &name,
                kind,
                &status,
                &answers,
                upstream.as_deref(),
                &generation,
            );
        }
    }
    Ok(response)
}

/// Preserve the original wire reply (including unknown RRs/EDNS). A response
/// may visit at most three distinct upstreams; loops fail closed with SERVFAIL.
fn routed_exchange(
    query: &[u8],
    name: &str,
    kind: Option<&str>,
    initial: Option<&str>,
    generation: &str,
) -> io::Result<(Vec<u8>, Option<String>)> {
    let upstreams = config::upstreams();
    let mut action = initial
        .map(str::to_owned)
        .or_else(|| upstreams.first().map(|u| u.name.clone()))
        .ok_or_else(|| invalid("没有配置 DNS 上游"))?;
    let mut visited = std::collections::HashSet::new();
    loop {
        if let Some(rcode) = reply_code(&action) {
            return Ok((empty_reply(query, rcode)?, None));
        }
        if visited.len() >= 3 || !visited.insert(action.clone()) {
            return Ok((empty_reply(query, 2)?, None));
        }
        let upstream = upstreams
            .iter()
            .find(|upstream| upstream.name == action)
            .ok_or_else(|| invalid(format!("DNS 上游 `{action}` 不存在")))?;
        let reply = exchange_wire(upstream, query)?;
        if config::generation() != generation {
            return Err(invalid("DNS 查询期间配置已更新，请重试"));
        }
        let (_, answers) = parse_response(&reply)?;
        let addresses = answers
            .iter()
            .filter(|answer| answer.kind == "A" || answer.kind == "AAAA")
            .filter_map(|answer| answer.data.parse().ok())
            .collect::<Vec<IpAddr>>();
        let next = config::dns_response_action(name, kind, &action, &addresses);
        if next == "accept" {
            return Ok((reply, Some(action)));
        }
        if let Some(rcode) = reply_code(&next) {
            return Ok((empty_reply(query, rcode)?, Some(action)));
        }
        action = next;
    }
}
pub(crate) fn reply_code(action: &str) -> Option<u8> {
    match action {
        "reject" => Some(0),
        "servfail" => Some(2),
        "nxdomain" => Some(3),
        "refused" => Some(5),
        _ => None,
    }
}
fn empty_reply(query: &[u8], rcode: u8) -> io::Result<Vec<u8>> {
    let (_, end) = read_name(query, 12)?;
    if query.len() < end + 4 {
        return Err(invalid("DNS 问题截断"));
    }
    let mut reply = query[..end + 4].to_vec();
    reply[2] = (query[2] & 1) | 0x80;
    reply[3] = 0x80 | (rcode & 15); // QR, RD, RA; no invented answers or AD.
    reply[6..12].fill(0);
    Ok(reply)
}
fn exchange_wire(upstream: &config::Upstream, query: &[u8]) -> io::Result<Vec<u8>> {
    if crate::platform::managed::egress_families()==Some([false,true])
        && upstream.name=="default" && upstream.protocol=="udp" && upstream.port==53
        && matches!(upstream.host.as_str(),"223.5.5.5"|"223.6.6.6") {
        let mut last=invalid("默认 IPv6 DNS 暂不可用");
        for host in ["2400:3200::1","2400:3200:baba::1"] {
            let mut selected=upstream.clone();selected.host=host.to_owned();
            match exchange_wire_native(&selected,query){Ok(reply)=>return Ok(reply),Err(e)=>last=e}
        }
        return Err(last);
    }
    exchange_wire_native(upstream,query)
}
fn exchange_wire_native(upstream: &config::Upstream, query: &[u8]) -> io::Result<Vec<u8>> {
    let reply = if upstream.protocol == "tcp" {
        tcp_exchange(upstream, query)?
    } else {
        let udp = udp_exchange(upstream, query)?;
        if udp.len() >= 4 && udp[2] & 2 != 0 {
            tcp_exchange(upstream, query)?
        } else {
            udp
        }
    };
    if reply.len() < 12 || reply[..2] != query[..2] || reply[2] & 0x80 == 0 || reply[4..6] != [0, 1]
    {
        return Err(invalid("DNS 响应事务不匹配"));
    }
    let (question, end) = read_name(query, 12)?;
    let (returned, after) = read_name(&reply, 12)?;
    if question != returned || query.get(end..end + 4) != reply.get(after..after + 4) {
        return Err(invalid("DNS 响应问题不匹配"));
    }
    Ok(reply)
}

/// Resolves a name for a direct dial. A and then AAAA are queried; the first
/// family with addresses wins, matching how a dual-stack dialer would try them.
pub fn resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }
    if !available() {
        return (host, 0)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect());
    }
    let name = canonical(host)?;
    let mut last = None;
    let families = crate::platform::managed::egress_families();
    let mut collected = Vec::new();
    for kind in ["A", "AAAA"] {
        if families.is_some_and(|f|!f[usize::from(kind=="AAAA")]) { continue; }
        match lookup(&name, kind, None, true) {
            Ok(result) => {
                record(
                    None,
                    &name,
                    kind,
                    &result.status,
                    result.cached,
                    result.upstream.as_deref(),
                    result.elapsed_ms,
                    &result.answers,
                    result.route.clone(),
                );
                let addresses: Vec<IpAddr> = result
                    .answers
                    .iter()
                    .filter_map(|answer| answer.data.parse().ok())
                    .collect();
                if !addresses.is_empty() {
                    if families.is_none() { return Ok(addresses); }
                    collected.extend(addresses);
                }
            }
            Err(error) => {
                record(
                    None,
                    &name,
                    kind,
                    "ERROR",
                    false,
                    None,
                    0,
                    &[],
                    request_route(false, None),
                );
                last = Some(error);
            }
        }
    }
    if !collected.is_empty() { return Ok(collected); }
    Err(last
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{host} 没有解析结果"))))
}

struct Lookup {
    status: String,
    answers: Vec<Answer>,
    cached: bool,
    entry_id: Option<String>,
    upstream: Option<String>,
    route: serde_json::Value,
    elapsed_ms: u64,
}

fn request_route(forced: bool, routed: Option<&(String, String)>) -> serde_json::Value {
    serde_json::json!({
        "source":if forced {"forced"} else if routed.is_some() {"dns.routing"} else {"default"},
        "rule":if forced {None} else {routed.map(|(_, expression)|expression)}
    })
}

fn lookup(
    domain: &str,
    kind: &'static str,
    forced_upstream: Option<&str>,
    use_cache: bool,
) -> io::Result<Lookup> {
    let name = canonical(domain)?;
    let routed = config::dns_route_for(&name, Some(kind));
    let route = request_route(forced_upstream.is_some(), routed.as_ref());
    let upstreams = config::upstreams();
    let chosen = forced_upstream.or_else(|| routed.as_ref().map(|(upstream, _)| upstream.as_str()));
    let generation = config::generation();
    let selected = chosen
        .map(str::to_owned)
        .or_else(|| upstreams.first().map(|upstream| upstream.name.clone()))
        .ok_or_else(|| invalid("没有配置 DNS 上游"))?;
    if use_cache {
        if let Some(hit) = cache_get_for(&name, kind, Some(&selected)) {
            return Ok(Lookup {
                status: hit.status,
                answers: hit.answers,
                cached: true,
                entry_id: Some(hit.id),
                upstream: hit.upstream,
                route,
                elapsed_ms: 0,
            });
        }
    }

    let started = Instant::now();
    let code = type_code(kind).ok_or_else(|| invalid("未知 DNS 类型"))?;
    let query = encode_query(QUERY_ID.fetch_add(1, Ordering::Relaxed), &name, code)?;
    let (response, final_upstream) =
        routed_exchange(&query, &name, Some(kind), Some(&selected), &generation)?;
    let (status, answers) = parse_response(&response)?;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let entry_id = if use_cache && status == "NOERROR" && !answers.is_empty() {
        cache_put_at(
            &name,
            kind,
            &status,
            &answers,
            final_upstream.as_deref(),
            &generation,
        )
    } else {
        None
    };

    Ok(Lookup {
        status,
        answers,
        cached: false,
        entry_id,
        upstream: final_upstream,
        route,
        elapsed_ms,
    })
}

#[cfg(test)]
fn exchange(
    upstream: &config::Upstream,
    name: &str,
    kind: &'static str,
) -> io::Result<(String, Vec<Answer>)> {
    let code = type_code(kind).ok_or_else(|| invalid(format!("不支持的记录类型 {kind}")))?;
    let id = QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = encode_query(id, name, code)?;
    let response = if upstream.protocol == "tcp" {
        tcp_exchange(upstream, &query)?
    } else {
        let udp = udp_exchange(upstream, &query)?;
        if udp.len() >= 4 && udp[2] & 0x02 != 0 {
            tcp_exchange(upstream, &query)?
        } else {
            udp
        }
    };
    parse_response(&response)
}

/// Resolver sockets must leave through the captured physical interface while
/// TUN is on; the shadow routes would otherwise send them back into the tunnel.
fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    crate::platform::current().bind_udp(local)
}

fn connect_tcp(address: SocketAddr) -> io::Result<TcpStream> {
    crate::platform::current().connect_tcp(address, QUERY_TIMEOUT)
}

fn udp_exchange(upstream: &config::Upstream, query: &[u8]) -> io::Result<Vec<u8>> {
    let address = (upstream.host.as_str(), upstream.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| invalid("DNS 上游没有可用地址"))?;
    let local = if address.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = bind_udp(local)?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    socket.connect(address)?;
    socket.send(query)?;
    let mut buffer = vec![0u8; 65535];
    let length = socket.recv(&mut buffer)?;
    buffer.truncate(length);
    Ok(buffer)
}

fn tcp_exchange(upstream: &config::Upstream, query: &[u8]) -> io::Result<Vec<u8>> {
    let address = (upstream.host.as_str(), upstream.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| invalid("DNS 上游没有可用地址"))?;
    let mut stream = connect_tcp(address)?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT))?;
    stream.write_all(&(query.len() as u16).to_be_bytes())?;
    stream.write_all(query)?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let mut buffer = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
fn cache_get(name: &str, kind: &'static str) -> Option<Entry> {
    cache_get_for(name, kind, None)
}

fn cache_get_for(name: &str, kind: &'static str, upstream: Option<&str>) -> Option<Entry> {
    let generation = config::generation();
    let now = SystemTime::now();
    let mut resolver = store();
    resolver.cache.retain(|entry| entry.expires > now);
    resolver
        .cache
        .iter()
        .find(|entry| {
            entry.domain == name
                && entry.kind == kind
                && entry.upstream.as_deref() == upstream
                && entry.generation == generation
        })
        .cloned()
}

#[cfg(test)]
fn cache_put(name: &str, kind: &'static str, status: &str, answers: &[Answer]) -> Option<String> {
    cache_put_for(name, kind, status, answers, None)
}

#[cfg(test)]
fn cache_put_for(
    name: &str,
    kind: &'static str,
    status: &str,
    answers: &[Answer],
    upstream: Option<&str>,
) -> Option<String> {
    cache_put_at(name, kind, status, answers, upstream, &config::generation())
}
fn cache_put_at(
    name: &str,
    kind: &'static str,
    status: &str,
    answers: &[Answer],
    upstream: Option<&str>,
    generation: &str,
) -> Option<String> {
    if status != "NOERROR" || answers.is_empty() {
        return None;
    }
    let ttl = answers
        .iter()
        .map(|answer| answer.ttl)
        .min()
        .unwrap_or(0)
        .min(3600);
    if ttl == 0 {
        return None;
    }
    // Serialize the generation check and insertion with publication/flush. A
    // reply that finishes after a hot change cannot repopulate the old cache.
    config::with_current(|config| {
        if config.generation != generation {
            return None;
        }
        let mut resolver = store();
        resolver.cache.retain(|entry| {
            !(entry.domain == name && entry.kind == kind && entry.upstream.as_deref() == upstream)
        });
        resolver.next_entry += 1;
        let id = format!("dns-entry-{}", resolver.next_entry);
        resolver.cache.insert(
            0,
            Entry {
                id: id.clone(),
                domain: name.to_owned(),
                kind,
                status: status.to_owned(),
                answers: answers.to_vec(),
                expires: SystemTime::now() + Duration::from_secs(u64::from(ttl)),
                upstream: upstream.map(str::to_owned),
                generation: generation.to_owned(),
            },
        );
        resolver.cache.truncate(MAX_CACHE);
        Some(id)
    })
}

fn record(
    src: Option<SocketAddr>,
    domain: &str,
    kind: &'static str,
    status: &str,
    cached: bool,
    upstream: Option<&str>,
    elapsed_ms: u64,
    answers: &[Answer],
    route: serde_json::Value,
) {
    if !crate::control::recording_active("record_dns_log") {
        return;
    }
    let maximum = crate::control::runtime_limit("dns_log.max_records", MAX_LOG);
    let mut resolver = store();
    resolver.next_record += 1;
    let seq = resolver.next_record;
    resolver.log.insert(
        0,
        Record {
            seq,
            at: SystemTime::now(),
            src,
            domain: domain.to_owned(),
            kind,
            status: status.to_owned(),
            cached,
            upstream: upstream.map(str::to_owned),
            route,
            elapsed_ms,
            answers: answers.to_vec(),
        },
    );
    resolver.log.truncate(maximum);
}

/// POST /api/v1/dns/query. `body` is the raw JSON request.
pub fn query_json(body: &str) -> Result<String, (u16, &'static str, String)> {
    crate::control::record_demand("record_dns_log");
    if !available() {
        return Err((
            404,
            "capability_not_supported",
            "未配置 DNS 上游".to_owned(),
        ));
    }
    let domain = field(body, "domain")
        .ok_or_else(|| (400, "invalid_request", "domain 不能为空".to_owned()))?;
    let domain = domain.trim().trim_end_matches('.').to_owned();
    if domain.is_empty() {
        return Err((400, "invalid_request", "domain 不能为空".to_owned()));
    }
    canonical(&domain).map_err(|error| (400, "invalid_request", error.to_string()))?;

    let request: serde_json::Value =
        serde_json::from_str(body).map_err(|error| (400, "invalid_request", error.to_string()))?;
    let type_field = request.get("type").or_else(|| request.get("types"));
    if type_field.is_some_and(|value| {
        !value.is_array()
            || value
                .as_array()
                .unwrap()
                .iter()
                .any(|value| !value.is_string())
    }) {
        return Err((400, "invalid_request", "type 必须为记录类型数组".to_owned()));
    }
    let mut types: Vec<String> = type_field
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    if types.is_empty() {
        types.push("A".to_owned());
    }
    let mut unique: Vec<&'static str> = Vec::new();
    for kind in types {
        let Some(kind) = RECORD_TYPES.iter().find(|known| **known == kind).copied() else {
            return Err((422, "unsupported_value", format!("不支持的记录类型 {kind}")));
        };
        if !unique.contains(&kind) {
            unique.push(kind);
        }
    }
    if unique.is_empty() || unique.len() > MAX_TYPES {
        return Err((
            422,
            "unsupported_value",
            format!("一次最多查询 {MAX_TYPES} 种记录类型"),
        ));
    }

    let upstream = field(body, "upstream");
    if let Some(name) = &upstream {
        if !config::upstreams().iter().any(|item| &item.name == name) {
            return Err((
                422,
                "unsupported_value",
                format!("DNS 上游 `{name}` 不在配置里"),
            ));
        }
    }
    let cache_mode = field(body, "cache_mode").unwrap_or_else(|| "normal".to_owned());
    if cache_mode != "normal" && cache_mode != "bypass" {
        return Err((
            422,
            "unsupported_value",
            "cache_mode 只能是 normal 或 bypass".to_owned(),
        ));
    }

    let mut results = Vec::new();
    for kind in unique {
        let result = lookup(&domain, kind, upstream.as_deref(), cache_mode == "normal");
        match result {
            Ok(lookup) => {
                record(None, &format!("{domain}."), kind, &lookup.status, lookup.cached, lookup.upstream.as_deref(), lookup.elapsed_ms, &lookup.answers, lookup.route.clone());
                results.push(result_json(&domain, kind, &lookup));
            },
            Err(error) => results.push(format!(
                r#"{{"type":"{kind}","cached":false,"cache_entry_id":null,"upstream":null,"route":{{"source":"default","rule":null}},"status":"{}","elapsed_ms":0,"question":{{"name":"{}","type":"{kind}"}},"answers":[]}}"#,
                json::escape(&outcome(&error)),
                json::escape(&format!("{domain}."))
            )),
        }
    }

    Ok(format!(
        r#"{{"domain":"{}","cache_mode":"{}","query_time":"{}","results":[{}]}}"#,
        json::escape(&domain),
        cache_mode,
        state::iso8601(SystemTime::now()),
        results.join(",")
    ))
}

fn result_json(domain: &str, kind: &str, lookup: &Lookup) -> String {
    format!(
        r#"{{"type":"{kind}","cached":{},"cache_entry_id":{},"upstream":{},"route":{route},"status":"{}","elapsed_ms":{},"question":{{"name":"{}","type":"{kind}"}},"answers":[{}]}}"#,
        lookup.cached,
        lookup
            .entry_id
            .as_ref()
            .map(|id| json::quoted(id))
            .unwrap_or_else(|| "null".to_string()),
        lookup
            .upstream
            .as_ref()
            .map(|name| json::quoted(name))
            .unwrap_or_else(|| "null".to_string()),
        json::escape(&lookup.status),
        lookup.elapsed_ms,
        json::escape(&format!("{domain}.")),
        answers_json(&lookup.answers),
        route = lookup.route,
    )
}

fn answers_json(answers: &[Answer]) -> String {
    answers
        .iter()
        .map(|answer| {
            format!(
                r#"{{"name":"{}","type":"{}","class":"IN","ttl":{},"data":"{}"}}"#,
                json::escape(&answer.name),
                answer.kind,
                answer.ttl,
                json::escape(&answer.data)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn log_json(query: &str) -> Result<String, (u16, &'static str, String)> {
    crate::control::record_demand("record_dns_log");
    let limit = limit_param(query, 100, MAX_PAGE)?;
    let name =
        param(query, "name").map(|value| crate::share::query_decode(value).to_ascii_lowercase());
    let kind = param(query, "type");
    let src = param(query, "src").map(crate::share::query_decode);
    let cursor = match param(query, "cursor") {
        Some(cursor) => Some(
            cursor
                .trim_start_matches("dl-")
                .parse::<u64>()
                .map_err(|_| (400, "invalid_request", "cursor 无效".to_owned()))?,
        ),
        None => None,
    };
    let resolver = store();
    let total = resolver.log.len();
    let mut matched: Vec<&Record> = resolver
        .log
        .iter()
        .filter(|record| {
            name.as_ref()
                .is_none_or(|name| record.domain.to_ascii_lowercase().contains(name))
                && kind.is_none_or(|kind| record.kind == kind)
                && src.as_ref().is_none_or(|src| {
                    record
                        .src
                        .is_some_and(|address| address.ip().to_string() == *src)
                })
                && cursor.is_none_or(|cursor| record.seq < cursor)
        })
        .collect();
    let more = matched.len() > limit;
    matched.truncate(limit);
    let next = more
        .then(|| matched.last().map(|record| format!("dl-{:06}", record.seq)))
        .flatten();
    let records = matched
        .iter()
        .map(|record| record_json(record))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        r#"{{"observed_at":"{}","total":{},"next_cursor":{},"records":[{}]}}"#,
        state::iso8601(SystemTime::now()),
        total,
        next.map(|cursor| json::quoted(&cursor))
            .unwrap_or_else(|| "null".to_string()),
        records
    ))
}

fn record_json(record: &Record) -> String {
    format!(
        r#"{{"id":"dl-{:06}","observed_at":"{}","src":{},"question":{{"name":"{}","type":"{}"}},"status":"{}","cached":{},"upstream":{},"route":{route},"elapsed_ms":{},"answers":[{}]}}"#,
        record.seq,
        state::iso8601(record.at),
        record
            .src
            .map(|address| json::quoted(&address.to_string()))
            .unwrap_or_else(|| "null".to_string()),
        json::escape(&record.domain),
        record.kind,
        json::escape(&record.status),
        record.cached,
        record
            .upstream
            .as_ref()
            .map(|name| json::quoted(name))
            .unwrap_or_else(|| "null".to_string()),
        record.elapsed_ms,
        answers_json(&record.answers),
        route = record.route,
    )
}

pub fn cache_json(query: &str) -> Result<String, (u16, &'static str, String)> {
    let limit = limit_param(query, 100, 1000)?;
    let name =
        param(query, "name").map(|value| crate::share::query_decode(value).to_ascii_lowercase());
    let domain = param(query, "domain").map(|value| {
        crate::share::percent_decode(value)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    });
    let types: Vec<String> = query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == "type").then(|| value.to_owned())
        })
        .collect();
    let include_expired = param(query, "include_expired") == Some("true");
    let offset = match param(query, "cursor") {
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| (400, "invalid_request", "cursor 无效".to_owned()))?,
        None => 0,
    };
    let now = SystemTime::now();
    let mut resolver = store();
    if !include_expired {
        resolver.cache.retain(|entry| entry.expires > now);
    }
    let total = resolver.cache.len();
    let usage = total;
    let mut matched: Vec<&Entry> = resolver
        .cache
        .iter()
        .filter(|entry| {
            name.as_ref()
                .is_none_or(|name| entry.domain.to_ascii_lowercase().contains(name))
                && domain
                    .as_ref()
                    .is_none_or(|domain| entry.domain.trim_end_matches('.') == domain)
                && (types.is_empty() || types.iter().any(|kind| entry.kind == kind))
                && (include_expired || entry.expires > now)
        })
        .collect();
    matched.sort_by(|left, right| right.expires.cmp(&left.expires));
    let page = matched.iter().skip(offset).take(limit).collect::<Vec<_>>();
    let next = (offset + page.len() < matched.len()).then(|| (offset + page.len()).to_string());
    let entries = page
        .iter()
        .map(|entry| cache_entry_json(entry))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        r#"{{"observed_at":"{}","coverage":{{"positive":true,"negative":false,"persistent":false}},"entries":[{}],"total":{},"next_cursor":{},"usage":{{"entries":"{}","entry_capacity":"{}"}}}}"#,
        state::iso8601(now),
        entries,
        total,
        next.map(|cursor| json::quoted(&cursor))
            .unwrap_or_else(|| "null".to_string()),
        usage,
        MAX_CACHE
    ))
}

fn cache_entry_json(entry: &Entry) -> String {
    format!(
        r#"{{"entry_id":"{}","domain":"{}","type":"{}","class":"IN","status":"{}","answers":[{}],"expires_at":"{}","stale_until":null}}"#,
        json::escape(&entry.id),
        json::escape(&entry.domain),
        entry.kind,
        json::escape(&entry.status),
        answers_json(&entry.answers),
        state::iso8601(entry.expires)
    )
}

pub fn delete_entry(id: &str) -> String {
    let mut resolver = store();
    let before = resolver.cache.len();
    resolver.cache.retain(|entry| entry.id != id);
    let deleted = before - resolver.cache.len();
    format!(r#"{{"deleted":{deleted}}}"#)
}

pub fn delete_name(query: &str) -> Result<String, (u16, &'static str, String)> {
    let name =
        param(query, "name").ok_or_else(|| (400, "invalid_request", "name 不能为空".to_owned()))?;
    let canonical = canonical(&crate::share::query_decode(name))
        .map_err(|error| (400, "invalid_request", error.to_string()))?;
    let types: Vec<String> = query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == "type").then(|| value.to_owned())
        })
        .collect();
    let mut resolver = store();
    let before = resolver.cache.len();
    resolver.cache.retain(|entry| {
        let matches = entry.domain == canonical
            && (types.is_empty() || types.iter().any(|kind| entry.kind == kind));
        !matches
    });
    let deleted = before - resolver.cache.len();
    Ok(format!(r#"{{"matched":{deleted},"deleted":{deleted}}}"#))
}

pub fn flush() -> String {
    let mut resolver = store();
    let deleted = resolver.cache.len();
    resolver.cache.clear();
    format!(r#"{{"matched":{deleted},"deleted":{deleted}}}"#)
}

pub(crate) fn apply_runtime_limits() {
    let maximum = crate::control::runtime_limit("dns_log.max_records", MAX_LOG);
    store().log.truncate(maximum);
}

pub fn capabilities_json() -> String {
    if !available() {
        return r#""dns_query":{"available":false},"dns_cache":{"available":false},"dns_log":{"available":false}"#.to_string();
    }
    let types = RECORD_TYPES
        .iter()
        .map(|kind| format!("\"{kind}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#""dns_query":{{"available":true,"record_types":[{types}],"limits":{{"max_types_per_request":{MAX_TYPES},"query_timeout_ms":5000,"max_response_bytes":65536,"per_principal_requests_per_minute":120,"global_requests_per_minute":480}}}},"dns_cache":{{"available":true,"read":true,"delete_entry":true,"delete_name":true,"flush":true,"entry_kinds":["positive"]}},"dns_log":{{"available":true,"min_records":64,"max_records":65536,"max_page_size":{MAX_PAGE}}}"#
    )
}

fn param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn limit_param(
    query: &str,
    default: usize,
    maximum: usize,
) -> Result<usize, (u16, &'static str, String)> {
    match param(query, "limit") {
        None => Ok(default),
        Some(value) => match value.parse::<usize>() {
            Ok(limit) if limit >= 1 && limit <= maximum => Ok(limit),
            Ok(_) => Err((
                400,
                "invalid_request",
                format!("limit 必须在 1..={maximum} 之间"),
            )),
            Err(_) => Err((400, "invalid_request", "limit 不是数字".to_owned())),
        },
    }
}

fn field(body: &str, key: &str) -> Option<String> {
    json::field(body, key)
}

#[cfg(test)]
fn array(body: &str, key: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get(key).and_then(|value| value.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn canonical(domain: &str) -> io::Result<String> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(invalid("域名不能为空"));
    }
    if trimmed.len() > 253 {
        return Err(invalid("域名超过 253 字节"));
    }
    let mut labels = Vec::new();
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid("域名标签必须在 1..=63 字节之间"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(invalid("域名包含不支持的字符"));
        }
        labels.push(label.to_ascii_lowercase());
    }
    Ok(format!("{}.", labels.join(".")))
}

fn type_code(kind: &str) -> Option<u16> {
    Some(match kind {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "CAA" => 257,
        _ => return None,
    })
}

fn type_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        257 => "CAA",
        _ => return None,
    })
}

fn encode_query(id: u16, domain: &str, kind: u16) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(32 + domain.len());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x00]);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid("域名标签必须在 1..=63 字节之间"));
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    Ok(bytes)
}

fn parse_response(bytes: &[u8]) -> io::Result<(String, Vec<Answer>)> {
    if bytes.len() < 12 {
        return Err(invalid("DNS 响应太短"));
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let status = match flags & 0x000f {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE",
    }
    .to_owned();
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(bytes, offset)?;
        offset += 4;
        if offset > bytes.len() {
            return Err(invalid("DNS 响应问题段被截断"));
        }
    }
    let mut parsed = Vec::new();
    for _ in 0..answers {
        let (name, next) = read_name(bytes, offset)?;
        offset = next;
        if offset + 10 > bytes.len() {
            return Err(invalid("DNS 响应答案段被截断"));
        }
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let ttl = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        let length = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
        offset += 10;
        if offset + length > bytes.len() {
            return Err(invalid("DNS 响应记录被截断"));
        }
        if let (Some(kind_name), Some(data)) = (type_name(kind), rdata(bytes, offset, length, kind))
        {
            parsed.push(Answer {
                name,
                kind: kind_name,
                ttl,
                data,
            });
        }
        offset += length;
    }
    Ok((status, parsed))
}

fn skip_name(bytes: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        let length = *bytes.get(offset).ok_or_else(|| invalid("DNS 名称被截断"))?;
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err(invalid("DNS 名称标签非法"));
        }
        offset += 1 + length as usize;
        if offset > bytes.len() {
            return Err(invalid("DNS 名称被截断"));
        }
    }
}

fn read_name(bytes: &[u8], offset: usize) -> io::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut position = offset;
    let mut next = None;
    let mut hops = 0;
    loop {
        let length = *bytes
            .get(position)
            .ok_or_else(|| invalid("DNS 名称被截断"))?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes
                .get(position + 1)
                .ok_or_else(|| invalid("DNS 指针被截断"))?;
            if next.is_none() {
                next = Some(position + 2);
            }
            position = ((usize::from(length & 0x3f)) << 8) | usize::from(low);
            hops += 1;
            if hops > 16 {
                return Err(invalid("DNS 名称指针循环"));
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(invalid("DNS 名称标签非法"));
        }
        if length == 0 {
            position += 1;
            break;
        }
        let start = position + 1;
        let end = start + usize::from(length);
        if end > bytes.len() {
            return Err(invalid("DNS 名称被截断"));
        }
        labels.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        position = end;
    }
    let name = if labels.is_empty() {
        ".".to_owned()
    } else {
        format!("{}.", labels.join("."))
    };
    Ok((name, next.unwrap_or(position)))
}

fn rdata(bytes: &[u8], offset: usize, length: usize, kind: u16) -> Option<String> {
    let end = offset + length;
    match kind {
        1 if length == 4 => Some(
            Ipv4Addr::new(
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            )
            .to_string(),
        ),
        28 if length == 16 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[offset..end]);
            Some(Ipv6Addr::from(raw).to_string())
        }
        2 | 5 | 12 => read_name(bytes, offset).ok().map(|(name, _)| name),
        15 if length > 2 => {
            let preference = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            read_name(bytes, offset + 2)
                .ok()
                .map(|(name, _)| format!("{preference} {name}"))
        }
        16 => {
            let mut position = offset;
            let mut parts = Vec::new();
            while position < end {
                let size = usize::from(bytes[position]);
                position += 1;
                if position + size > end {
                    break;
                }
                parts.push(String::from_utf8_lossy(&bytes[position..position + size]).into_owned());
                position += size;
            }
            Some(parts.join(" "))
        }
        33 if length > 6 => {
            let priority = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let weight = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let port = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
            read_name(bytes, offset + 6)
                .ok()
                .map(|(name, _)| format!("{priority} {weight} {port} {name}"))
        }
        6 => {
            let (mname, after) = read_name(bytes, offset).ok()?;
            let (rname, after) = read_name(bytes, after).ok()?;
            if after + 20 > end {
                return None;
            }
            let numbers = [
                u32::from_be_bytes([
                    bytes[after],
                    bytes[after + 1],
                    bytes[after + 2],
                    bytes[after + 3],
                ]),
                u32::from_be_bytes([
                    bytes[after + 4],
                    bytes[after + 5],
                    bytes[after + 6],
                    bytes[after + 7],
                ]),
                u32::from_be_bytes([
                    bytes[after + 8],
                    bytes[after + 9],
                    bytes[after + 10],
                    bytes[after + 11],
                ]),
                u32::from_be_bytes([
                    bytes[after + 12],
                    bytes[after + 13],
                    bytes[after + 14],
                    bytes[after + 15],
                ]),
                u32::from_be_bytes([
                    bytes[after + 16],
                    bytes[after + 17],
                    bytes[after + 18],
                    bytes[after + 19],
                ]),
            ];
            Some(format!(
                "{mname} {rname} {} {} {} {} {}",
                numbers[0], numbers[1], numbers[2], numbers[3], numbers[4]
            ))
        }
        257 if length > 2 => {
            let flags = bytes[offset];
            let tag_length = usize::from(bytes[offset + 1]);
            if offset + 2 + tag_length > end {
                return None;
            }
            let tag = String::from_utf8_lossy(&bytes[offset + 2..offset + 2 + tag_length]);
            let value = String::from_utf8_lossy(&bytes[offset + 2 + tag_length..end]);
            Some(format!("{flags} {tag} \"{value}\""))
        }
        _ => None,
    }
}

fn outcome(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "TIMEOUT".to_owned(),
        io::ErrorKind::NotFound => "NXDOMAIN".to_owned(),
        _ => "ERROR".to_owned(),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_query_with_labels_and_the_trailing_root() {
        let bytes = encode_query(0x1234, "example.com.", 1).unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x34]);
        assert_eq!(bytes[4..6], [0, 1]);
        assert_eq!(bytes[12], 7);
        assert_eq!(&bytes[13..20], b"example");
        assert_eq!(bytes[20], 3);
        assert_eq!(&bytes[21..24], b"com");
        assert_eq!(bytes[24], 0);
        assert_eq!(&bytes[25..27], &[0, 1]);
        assert_eq!(&bytes[27..29], &[0, 1]);
    }

    #[test]
    fn parses_an_a_answer_with_compression() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        response.push(7);
        response.extend_from_slice(b"example");
        response.push(3);
        response.extend_from_slice(b"com");
        response.push(0);
        response.extend_from_slice(&[0, 1, 0, 1]);
        response.extend_from_slice(&[0xc0, 12]);
        response.extend_from_slice(&[0, 1, 0, 1]);
        response.extend_from_slice(&300u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[93, 184, 216, 34]);

        let (status, answers) = parse_response(&response).unwrap();
        assert_eq!(status, "NOERROR");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com.");
        assert_eq!(answers[0].kind, "A");
        assert_eq!(answers[0].data, "93.184.216.34");
        assert_eq!(answers[0].ttl, 300);
    }

    #[test]
    fn parses_nxdomain_without_answers() {
        let response = [0x12, 0x34, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
        let (status, answers) = parse_response(&response).unwrap();
        assert_eq!(status, "NXDOMAIN");
        assert!(answers.is_empty());
    }

    #[test]
    fn rejects_names_that_do_not_fit_the_wire_format() {
        assert!(canonical("").is_err());
        assert!(canonical("a..b").is_err());
        assert!(canonical(&"a".repeat(64)).is_err());
        assert_eq!(canonical("Example.COM.").unwrap(), "example.com.");
    }

    #[test]
    fn reads_the_query_body_fields() {
        let body = r#"{"domain":"example.org","types":["A","AAAA"],"cache_mode":"bypass","upstream":"alidns"}"#;
        assert_eq!(field(body, "domain").as_deref(), Some("example.org"));
        assert_eq!(array(body, "types"), vec!["A", "AAAA"]);
        assert_eq!(field(body, "cache_mode").as_deref(), Some("bypass"));
        assert_eq!(field(body, "upstream").as_deref(), Some("alidns"));
        assert_eq!(field(body, "missing"), None);
    }
}
