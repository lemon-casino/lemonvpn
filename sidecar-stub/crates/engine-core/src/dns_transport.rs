//! DNS-only transports. All dials retain the engine's protected egress and
//! explicit outbound choice; TLS verification is never disabled.
use crate::rules_runtime::model::Resolver;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
trait Wire: Read + Write + Send {}
impl<T: Read + Write + Send> Wire for T {}
struct Idle {
    wire: Box<dyn Wire>,
    socket: TcpStream,
    at: Instant,
}
#[derive(Default)]
struct Stat {
    queries: u64,
    failures: u64,
    samples: Vec<u64>,
    error: Option<String>,
}
static POOL: OnceLock<Mutex<BTreeMap<String, Vec<Idle>>>> = OnceLock::new();
static LIVE: OnceLock<Mutex<BTreeMap<u64, TcpStream>>> = OnceLock::new();
static STATS: OnceLock<Mutex<BTreeMap<String, Stat>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
static EPOCH: AtomicU64 = AtomicU64::new(0);
thread_local! {static BOOTSTRAP:Cell<bool>=const{Cell::new(false)};static ENDPOINT:std::cell::RefCell<Option<String>>=const{std::cell::RefCell::new(None)};}
pub fn last_endpoint() -> Option<String> {
    ENDPOINT.with(|v| v.borrow().clone())
}
pub fn bootstrapping() -> bool {
    BOOTSTRAP.with(Cell::get)
}
pub fn with_bootstrap<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            BOOTSTRAP.with(|b| b.set(self.0));
        }
    }
    let old = BOOTSTRAP.with(|b| b.replace(true));
    let _r = Reset(old);
    f()
}
fn invalid(e: impl ToString) -> io::Error {
    io::Error::other(e.to_string())
}
fn endpoint(resolver: &Resolver) -> Result<(url::Url, String, u16), String> {
    let url = url::Url::parse(&resolver.url).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "udp" | "tcp" | "tls" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("DNS 上游须为 udp/tcp/tls/https URL，不接受账号或片段".into());
    }
    let host = url.host_str().unwrap().trim_matches(['[', ']']).to_owned();
    let port = url.port().unwrap_or(match url.scheme() {
        "https" => 443,
        "tls" => 853,
        _ => 53,
    });
    if port == 0 {
        return Err("DNS 端口不能为 0".into());
    }
    Ok((url, host, port))
}
pub fn validate(resolver: &Resolver) -> Result<(), String> {
    endpoint(resolver)?;
    if !(250..=15000).contains(&resolver.timeout_ms)
        || resolver.bootstrap.len() > 8
        || resolver
            .bootstrap
            .iter()
            .any(|ip| ip.parse::<IpAddr>().is_err())
        || resolver.outbound.is_empty()
    {
        return Err(format!("{}：超时、引导地址或出站设置无效", resolver.name));
    }
    if !resolver.tls_name.is_empty() {
        ServerName::try_from(resolver.tls_name.clone()).map_err(|_| "TLS 校验名无效")?;
    }
    Ok(())
}
fn tls(doh: bool) -> Arc<ClientConfig> {
    static TLS: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let config = TLS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone();
    if doh {
        config
    } else {
        let mut dot = (*config).clone();
        dot.alpn_protocols.clear();
        Arc::new(dot)
    }
}
pub fn flush() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    if let Some(p) = POOL.get() {
        p.lock().unwrap().clear();
    }
    if let Some(live) = LIVE.get() {
        for socket in live.lock().unwrap().values() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}
pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}
pub fn route_key(pool: &str) -> String {
    let snapshot = crate::rules_runtime::current();
    let Some(pool) = snapshot.document.pools.iter().find(|p| p.id == pool) else {
        return "legacy".into();
    };
    let targets = pool
        .members
        .iter()
        .filter_map(|id| snapshot.document.resolvers.iter().find(|r| &r.id == id))
        .map(|resolver| {
            if resolver.outbound == "direct" {
                return "direct".to_string();
            }
            crate::config::infrastructure_decision(
                &resolver.outbound,
                if resolver.url.starts_with("udp:") {
                    "udp"
                } else {
                    "tcp"
                },
            )
            .map(|d| format!("{:?}", d.target))
            .unwrap_or_else(|_| "unavailable".into())
        })
        .collect::<Vec<_>>();
    crate::sha256::hex(targets.join("|").as_bytes())
}
pub fn refresh_network() {
    static LAST: Mutex<Option<(std::time::SystemTime, String)>> = Mutex::new(None);
    let now = std::time::SystemTime::now();
    let mut last = LAST.lock().unwrap();
    if last.as_ref().is_some_and(|(at, _)| {
        now.duration_since(*at)
            .is_ok_and(|d| d < Duration::from_secs(5))
    }) {
        return;
    }
    let value = crate::platform::lan::addresses()
        .ok()
        .and_then(|addresses| serde_json::to_string(&addresses).ok())
        .unwrap_or_default();
    let changed = last.as_ref().is_some_and(|(at, old)| {
        *old != value
            || now
                .duration_since(*at)
                .map_or(true, |d| d > Duration::from_secs(12))
    });
    *last = Some((now, value));
    drop(last);
    if changed {
        crate::dns::flush();
        crate::compat::queue_hot_apply();
    }
}
pub fn statistics() -> Value {
    let stats = STATS.get_or_init(Default::default).lock().unwrap();
    json!({"scope":"Rust upstream exchanges","endpoints":stats.iter().map(|(id,s)|{
        let mut samples=s.samples.clone();samples.sort_unstable();let quantile=|p:usize|samples.get(samples.len().saturating_sub(1)*p/100).copied();
        json!({"id":id,"queries":s.queries,"failures":s.failures,"p50_ms":quantile(50),"p95_ms":quantile(95),"last_error":s.error})
    }).collect::<Vec<_>>()})
}
pub fn exchange_pool(id: &str, query: &[u8]) -> io::Result<Vec<u8>> {
    let snapshot = crate::rules_runtime::current();
    let pool = snapshot
        .document
        .pools
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| invalid("解析池不存在"))?;
    let members = pool
        .members
        .iter()
        .filter_map(|id| {
            snapshot
                .document
                .resolvers
                .iter()
                .find(|r| &r.id == id)
                .cloned()
        })
        .collect::<Vec<_>>();
    let mut last = invalid("没有可用 DNS 上游");
    if pool.strategy == "race" {
        let (tx, rx) = std::sync::mpsc::channel();
        let count = members.len().min(2);
        for resolver in members.iter().take(2) {
            let tx = tx.clone();
            let query = query.to_vec();
            let mut resolver = resolver.clone();
            resolver.timeout_ms = resolver.timeout_ms.min(10000);
            std::thread::spawn(move || {
                let result = exchange(&resolver, &query).map(|wire| (resolver.id, wire));
                let _ = tx.send(result);
            });
        }
        drop(tx);
        for result in rx.iter().take(count) {
            match result {
                Ok((id, reply)) => {
                    ENDPOINT.with(|v| *v.borrow_mut() = Some(id));
                    return Ok(reply);
                }
                Err(e) => last = e,
            }
        }
    } else {
        let budget = Instant::now();
        for mut resolver in members {
            let left = 10000u64.saturating_sub(budget.elapsed().as_millis() as u64);
            if left < 250 {
                break;
            }
            resolver.timeout_ms = resolver.timeout_ms.min(left);
            match exchange(&resolver, query) {
                Ok(reply) => {
                    ENDPOINT.with(|v| *v.borrow_mut() = Some(resolver.id));
                    return Ok(reply);
                }
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}
pub fn exchange(resolver: &Resolver, query: &[u8]) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let result = with_bootstrap(|| once(resolver, query));
    let mut all = STATS.get_or_init(Default::default).lock().unwrap();
    if all.len() >= 256 && !all.contains_key(&resolver.id) {
        all.pop_first();
    }
    let stats = all.entry(resolver.id.clone()).or_default();
    stats.queries += 1;
    if let Err(e) = &result {
        stats.failures += 1;
        stats.error = Some(e.to_string());
    } else {
        stats.error = None;
        stats.samples.push(started.elapsed().as_millis() as u64);
        if stats.samples.len() > 256 {
            stats.samples.remove(0);
        }
    }
    result
}
fn addresses(resolver: &Resolver, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let ips = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else if !resolver.bootstrap.is_empty() {
        resolver
            .bootstrap
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    } else {
        crate::dns::bootstrap_resolve(host)?
    };
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}
fn connect(resolver: &Resolver, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = invalid("DNS 服务器无可用地址");
    let timeout = Duration::from_millis(resolver.timeout_ms);
    for address in addresses(resolver, host, port)? {
        let result = if resolver.outbound == "direct" {
            crate::platform::current().connect_tcp(address, timeout)
        } else {
            crate::config::connect_outbound(&resolver.outbound, &address.ip().to_string(), port)
        };
        match result {
            Ok(socket) => {
                socket.set_read_timeout(Some(timeout))?;
                socket.set_write_timeout(Some(timeout))?;
                socket.set_nodelay(true)?;
                return Ok(socket);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}
fn once(resolver: &Resolver, query: &[u8]) -> io::Result<Vec<u8>> {
    once_retry(resolver, query, true)
}
fn once_retry(resolver: &Resolver, query: &[u8], retry: bool) -> io::Result<Vec<u8>> {
    if query.len() < 12 || query.len() > 65535 {
        return Err(invalid("DNS 查询大小无效"));
    }
    let (url, host, port) = endpoint(resolver).map_err(invalid)?;
    if url.scheme() == "udp" {
        let mut last = invalid("UDP DNS 无可用地址");
        for address in addresses(resolver, &host, port)? {
            if resolver.outbound != "direct" {
                let decision = crate::config::infrastructure_decision(&resolver.outbound, "udp")?;
                let relay =
                    crate::compat::Datagram::open(&decision, &address.ip().to_string(), port)?;
                relay.send(query)?;
                let mut reply = vec![0; 65535];
                let wait = Instant::now();
                let (n, _, _) = loop {
                    match relay.recv(&mut reply) {
                        Ok(value) => break value,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if wait.elapsed() >= Duration::from_millis(resolver.timeout_ms) {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "代理 UDP DNS 查询超时",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => return Err(e),
                    }
                };
                reply.truncate(n);
                crate::dns::validate_wire(query, &reply)?;
                if reply[2] & 2 != 0 {
                    let mut tcp = resolver.clone();
                    tcp.url = tcp.url.replacen("udp://", "tcp://", 1);
                    return once(&tcp, query);
                }
                return Ok(reply);
            }
            let socket = crate::platform::current().bind_udp(
                if address.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                }
                .parse()
                .unwrap(),
            )?;
            socket.set_read_timeout(Some(Duration::from_millis(resolver.timeout_ms)))?;
            socket.connect(address)?;
            socket.send(query)?;
            let mut reply = vec![0; 65535];
            match socket.recv(&mut reply) {
                Ok(n) => {
                    reply.truncate(n);
                    crate::dns::validate_wire(query, &reply)?;
                    if reply[2] & 2 != 0 {
                        let mut tcp = resolver.clone();
                        tcp.url = tcp.url.replacen("udp://", "tcp://", 1);
                        return once(&tcp, query);
                    }
                    return Ok(reply);
                }
                Err(e) => last = e,
            }
        }
        return Err(last);
    }
    let generation = crate::config::generation();
    let epoch = epoch();
    let egress = if resolver.outbound == "direct" {
        "direct".into()
    } else {
        crate::config::infrastructure_decision(&resolver.outbound, "tcp")
            .map(|d| crate::sha256::hex(format!("{:?}", d.target).as_bytes()))?
    };
    let key = format!(
        "{}|{}|{epoch}|{egress}",
        serde_json::to_string(resolver).map_err(invalid)?,
        generation
    );
    let cached = POOL
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get_mut(&key)
        .and_then(|list| {
            list.retain(|v| v.at.elapsed() < Duration::from_secs(30));
            list.pop()
        });
    let reused = cached.is_some();
    let (mut wire, socket) = if let Some(idle) = cached {
        (idle.wire, idle.socket)
    } else {
        let socket = connect(resolver, &host, port)?;
        let monitor = socket.try_clone()?;
        let wire = if matches!(url.scheme(), "https" | "tls") {
            let name = if resolver.tls_name.is_empty() {
                host.clone()
            } else {
                resolver.tls_name.clone()
            };
            let connection = ClientConnection::new(
                tls(url.scheme() == "https"),
                ServerName::try_from(name).map_err(invalid)?,
            )
            .map_err(invalid)?;
            Box::new(StreamOwned::new(connection, socket)) as Box<dyn Wire>
        } else {
            Box::new(socket) as Box<dyn Wire>
        };
        (wire, monitor)
    };
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    LIVE.get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(id, socket.try_clone()?);
    struct Active(u64);
    impl Drop for Active {
        fn drop(&mut self) {
            LIVE.get().unwrap().lock().unwrap().remove(&self.0);
        }
    }
    let _active = Active(id);
    let exchanged = (|| {
        let (reply, reusable) = if url.scheme() == "https" {
            let mut path = url.path().to_owned();
            if path.is_empty() {
                path.push('/')
            }
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            let host_header = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            write!(wire,"POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",query.len())?;
            wire.write_all(query)?;
            wire.flush()?;
            read_http(wire.as_mut())?
        } else {
            wire.write_all(&(query.len() as u16).to_be_bytes())?;
            wire.write_all(query)?;
            wire.flush()?;
            let mut size = [0; 2];
            wire.read_exact(&mut size)?;
            let n = u16::from_be_bytes(size) as usize;
            if n < 12 {
                return Err(invalid("DNS 回应过短"));
            }
            let mut reply = vec![0; n];
            wire.read_exact(&mut reply)?;
            (reply, true)
        };
        crate::dns::validate_wire(query, &reply)?;
        Ok::<_, io::Error>((reply, reusable))
    })();
    let (reply, reusable) = match exchanged {
        Ok(value) => value,
        Err(_e) if reused && retry => {
            let _ = socket.shutdown(Shutdown::Both);
            drop(wire);
            drop(socket);
            drop(_active);
            return once_retry(resolver, query, false);
        }
        Err(e) => return Err(e),
    };
    if reusable && epoch == self::epoch() && generation == crate::config::generation() {
        let mut pool = POOL.get().unwrap().lock().unwrap();
        if pool.len() > 128 {
            pool.clear();
        }
        let list = pool.entry(key).or_default();
        if list.len() < 4 {
            list.push(Idle {
                wire,
                socket,
                at: Instant::now(),
            });
        }
    }
    Ok(reply)
}
fn line(reader: &mut dyn Wire, limit: usize) -> io::Result<String> {
    let mut text = Vec::new();
    let mut b = [0];
    while text.len() < limit {
        reader.read_exact(&mut b)?;
        text.push(b[0]);
        if text.ends_with(b"\r\n") {
            return String::from_utf8(text).map_err(invalid);
        }
    }
    Err(invalid("DoH 响应头过长"))
}
fn read_http(reader: &mut dyn Wire) -> io::Result<(Vec<u8>, bool)> {
    let status = line(reader, 1024)?;
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(invalid(format!("DoH HTTP 状态：{}", status.trim())));
    }
    let mut size = None;
    let mut chunked = false;
    let mut reusable = status.starts_with("HTTP/1.1 ");
    let mut bytes = 0;
    let mut content_type = false;
    loop {
        let header = line(reader, 16 * 1024)?;
        bytes += header.len();
        if bytes > 16 * 1024 {
            return Err(invalid("DoH 头超限"));
        }
        if header == "\r\n" {
            break;
        }
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| invalid("DoH 响应头无效"))?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let n = value.parse::<usize>().map_err(invalid)?;
                if size.replace(n).is_some() || n > 65535 {
                    return Err(invalid("DoH 长度无效"));
                }
            }
            "content-type" => {
                content_type = value
                    .split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/dns-message"))
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(invalid("DoH 编码不受支持"));
                }
                chunked = true
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(invalid("DoH 压缩编码未请求"))
            }
            "connection" if value.eq_ignore_ascii_case("close") => reusable = false,
            _ => {}
        }
    }
    if !content_type || chunked && size.is_some() {
        return Err(invalid("DoH 响应类型或长度冲突"));
    }
    let mut reply = Vec::new();
    if chunked {
        loop {
            let header = line(reader, 128)?;
            let size = usize::from_str_radix(header.trim().split(';').next().unwrap_or(""), 16)
                .map_err(invalid)?;
            if size == 0 {
                let mut trailers = 0;
                loop {
                    let trailer = line(reader, 4096)?;
                    trailers += trailer.len();
                    if trailers > 4096 {
                        return Err(invalid("DoH trailer 超限"));
                    }
                    if trailer == "\r\n" {
                        break;
                    }
                }
                break;
            }
            if reply.len() + size > 65535 {
                return Err(invalid("DoH 数据超限"));
            }
            let start = reply.len();
            reply.resize(start + size, 0);
            reader.read_exact(&mut reply[start..])?;
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(invalid("DoH chunk 无效"));
            }
        }
    } else {
        let size = size.ok_or_else(|| invalid("DoH 缺少长度，不能安全复用连接"))?;
        reply.resize(size, 0);
        reader.read_exact(&mut reply)?;
    }
    Ok((reply, reusable))
}
