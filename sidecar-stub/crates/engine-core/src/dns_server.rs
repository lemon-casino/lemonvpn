//! Opt-in LAN DNS gateway. Fake-IP uses the active TUN core's own mapping pool;
//! real queries continue through the Rust policy/cache/transport pipeline.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    enabled: bool,
    bind_address: IpAddr,
    port: u16,
    allowed_networks: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0".parse().unwrap(),
            port: 1053,
            allowed_networks: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
        }
    }
}
fn network(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = text.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    (bits <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, bits))
}
fn contains(network: (IpAddr, u8), ip: IpAddr) -> bool {
    match (network, ip) {
        ((IpAddr::V4(a), n), IpAddr::V4(b)) => {
            n == 0 || (u32::from(a) >> (32 - n)) == (u32::from(b) >> (32 - n))
        }
        ((IpAddr::V6(a), n), IpAddr::V6(b)) => {
            n == 0 || (u128::from(a) >> (128 - n)) == (u128::from(b) >> (128 - n))
        }
        _ => false,
    }
}
fn local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback(),
        IpAddr::V6(v) => v.is_unique_local() || v.is_unicast_link_local() || v.is_loopback(),
    }
}
impl Settings {
    fn validate(&self) -> io::Result<()> {
        if self.port == 0
            || (!self.bind_address.is_unspecified() && !local(self.bind_address))
            || self.allowed_networks.is_empty()
            || self.allowed_networks.len() > 32
        {
            return Err(io::Error::other(
                "DNS 监听须为本地地址、有效端口和 1～32 个允许网段",
            ));
        }
        for text in &self.allowed_networks {
            let (ip, n) =
                network(text).ok_or_else(|| io::Error::other("DNS 允许网段须为 IPv4/IPv6 CIDR"))?;
            let allowed = match ip {
                IpAddr::V4(_) => [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                ]
                .iter()
                .any(|v| {
                    let p = network(v).unwrap();
                    n >= p.1 && contains(p, ip)
                }),
                IpAddr::V6(_) => ["fc00::/7", "fe80::/10", "::1/128"].iter().any(|v| {
                    let p = network(v).unwrap();
                    n >= p.1 && contains(p, ip)
                }),
            };
            if !allowed {
                return Err(io::Error::other("DNS 服务仅允许私网、链路本地和回环网段"));
            }
        }
        Ok(())
    }
    fn accepts(&self, ip: IpAddr) -> bool {
        ip.is_loopback()
            || (local(ip)
                && self
                    .allowed_networks
                    .iter()
                    .filter_map(|v| network(v))
                    .any(|n| contains(n, ip)))
    }
}
#[derive(Default)]
struct Metrics {
    queries: AtomicU64,
    errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}
impl Metrics {
    fn error(&self, error: impl ToString) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(error.to_string());
    }
}
/// Retain each query's destination IP, including wildcard listeners on hosts
/// with LAN, VPN and Docker interfaces. Never let routing choose a reply source.
struct UdpReplies {
    socket: crate::platform::udp_reply::Socket,
}
impl UdpReplies {
    fn bind(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: crate::platform::udp_reply::Socket::bind(address)?,
        })
    }
    fn reply(
        &self,
        bytes: &[u8],
        received: &crate::platform::udp_reply::Received,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            match self.socket.send_reply(bytes, received) {
                Ok(()) => return Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => return Err(e),
            }
        }
    }
}

struct Listener {
    tcp: TcpListener,
    udp: Arc<UdpReplies>,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
    metrics: Arc<Metrics>,
}
impl Listener {
    fn prepare(settings: Settings, previous: Option<&Self>) -> io::Result<Self> {
        let address = SocketAddr::new(settings.bind_address, settings.port);
        let same = previous.filter(|p| p.tcp.local_addr().ok() == Some(address));
        let tcp = match same {
            Some(p) => p.tcp.try_clone()?,
            None => TcpListener::bind(address)?,
        };
        let udp = match same {
            Some(p) => p.udp.clone(),
            None => Arc::new(UdpReplies::bind(address)?),
        };
        tcp.set_nonblocking(true)?;
        let accept = tcp.try_clone()?;
        let receive = udp.clone();
        let ready = Arc::new(AtomicBool::new(false));
        let active = ready.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let metrics = Arc::new(Metrics::default());
        let counters = metrics.clone();
        let task = thread::Builder::new()
            .name("lan-dns".into())
            .spawn(move || {
                let mut jobs: Vec<JoinHandle<()>> = Vec::new();
                let mut bytes = [0; 65535];
                while !stopped.load(Ordering::Acquire) && !crate::runtime::stopping() {
                    if !active.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    jobs.retain(|j| !j.is_finished());
                    if jobs.len() < 64 {
                        match receive.socket.recv(&mut bytes) {
                            Ok(packet)
                                if packet.len >= 12 && settings.accepts(packet.peer.ip()) =>
                            {
                                let query = bytes[..packet.len].to_vec();
                                let m = counters.clone();
                                let socket = receive.clone();
                                jobs.push(thread::spawn(move || {
                                    if let Some(mut reply) = answer(&query, &m) {
                                        if reply.len() > 512 {
                                            if let Ok(mut truncated) =
                                                crate::dns::empty_reply(&query, 0)
                                            {
                                                truncated[2] |= 2;
                                                reply = truncated;
                                            } else {
                                                return;
                                            }
                                        }
                                        if let Err(e) = socket.reply(&reply, &packet) {
                                            m.error(format!("DNS UDP 回包失败：{e}"));
                                        }
                                    }
                                }));
                            }
                            Ok(_) => {}
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                                ) => {}
                            Err(e) => counters.error(format!("DNS UDP 接收失败：{e}")),
                        }
                    }
                    if jobs.len() < 64 {
                        if let Ok((mut socket, peer)) = accept.accept() {
                            if settings.accepts(peer.ip()) {
                                let m = counters.clone();
                                jobs.push(thread::spawn(move || {
                                    let _ = socket.set_nonblocking(false);
                                    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
                                    let _ = socket.set_write_timeout(Some(Duration::from_secs(3)));
                                    let mut length = [0; 2];
                                    // Bound pipelined TCP requests and idle time per connection.
                                    for _ in 0..32 {
                                        if socket.read_exact(&mut length).is_err() {
                                            break;
                                        }
                                        let n = u16::from_be_bytes(length) as usize;
                                        if n < 12 {
                                            break;
                                        }
                                        let mut query = vec![0; n];
                                        if socket.read_exact(&mut query).is_err() {
                                            break;
                                        }
                                        let Some(reply) = answer(&query, &m) else {
                                            break;
                                        };
                                        if socket
                                            .write_all(&(reply.len() as u16).to_be_bytes())
                                            .and_then(|_| socket.write_all(&reply))
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }));
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                // Worker IO has bounded deadlines; don't delay a settings swap.
            })?;
        Ok(Self {
            tcp,
            udp,
            ready,
            stop,
            task: Some(task),
            metrics,
        })
    }
    fn activate(&self) {
        self.ready.store(true, Ordering::Release);
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.task.take() {
            let _ = t.join();
        }
    }
}
fn answer(query: &[u8], metrics: &Metrics) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0xf8 != 0 || query[4..6] != [0, 1] {
        return None;
    }
    metrics.queries.fetch_add(1, Ordering::Relaxed);
    let result = (|| {
        if !crate::compat::tun_active() {
            return crate::dns::forward_wire(query);
        }
        let endpoint = crate::compat::dns_endpoint()?;
        let mut socket = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.write_all(&(query.len() as u16).to_be_bytes())?;
        socket.write_all(query)?;
        let mut length = [0; 2];
        socket.read_exact(&mut length)?;
        let mut reply = vec![0; u16::from_be_bytes(length) as usize];
        socket.read_exact(&mut reply)?;
        if reply.len() < 12 || reply[..2] != query[..2] {
            return Err(io::Error::other("内核 DNS 响应无效"));
        }
        Ok(reply)
    })();
    match result {
        Ok(reply) => Some(reply),
        Err(e) => {
            metrics.error(e);
            crate::dns::empty_reply(query, 2).ok()
        }
    }
}
struct State {
    settings: Option<Settings>,
    listener: Option<Listener>,
    error: Option<String>,
}
static STATE: Mutex<State> = Mutex::new(State {
    settings: None,
    listener: None,
    error: None,
});
fn read(state: &mut State) -> io::Result<Settings> {
    if let Some(s) = &state.settings {
        return Ok(s.clone());
    }
    let value = match fs::read(crate::config::data_dir().join("dns-listener.json")) {
        Ok(bytes) if bytes.len() <= 8192 => {
            serde_json::from_slice(&bytes).map_err(io::Error::other)?
        }
        Ok(_) => return Err(io::Error::other("DNS 监听配置过大")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Settings::default(),
        Err(e) => return Err(e),
    };
    value.validate()?;
    state.settings = Some(value.clone());
    Ok(value)
}
fn revision(s: &Settings) -> String {
    crate::sha256::hex(&serde_json::to_vec(s).unwrap())
}
fn status(state: &mut State) -> io::Result<String> {
    let settings = read(state)?;
    let m = state.listener.as_ref().map(|l| &l.metrics);
    Ok(json!({"settings":settings,"revision":revision(&settings),"active":state.listener.is_some(),"error":state.error,"tun_enabled":crate::compat::tun_active(),"queries":m.map(|m|m.queries.load(Ordering::Relaxed)).unwrap_or(0),"failures":m.map(|m|m.errors.load(Ordering::Relaxed)).unwrap_or(0),"last_error":m.and_then(|m|m.last_error.lock().unwrap().clone())}).to_string())
}
pub(crate) fn status_json() -> io::Result<String> {
    status(&mut STATE.lock().unwrap())
}
pub(crate) fn start() {
    let mut state = STATE.lock().unwrap();
    let result = (|| {
        let settings = read(&mut state)?;
        if settings.enabled {
            state.listener = Some(Listener::prepare(settings, None)?);
            state.listener.as_ref().unwrap().activate();
        }
        Ok::<_, io::Error>(())
    })();
    if let Err(e) = result {
        state.error = Some(e.to_string());
    }
}
pub(crate) fn shutdown() {
    STATE.lock().unwrap().listener = None;
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    revision: String,
    settings: Settings,
}
pub(crate) fn update(body: &str) -> Result<String, (u16, &'static str, String)> {
    if body.len() > 8192 {
        return Err((413, "request_too_large", "DNS 监听配置过大".into()));
    }
    let update: Update =
        serde_json::from_str(body).map_err(|e| (422, "invalid_dns_listener", e.to_string()))?;
    update
        .settings
        .validate()
        .map_err(|e| (422, "invalid_dns_listener", e.to_string()))?;
    let mut state = STATE.lock().unwrap();
    let old = read(&mut state).map_err(|e| (500, "dns_listener_read_failed", e.to_string()))?;
    if revision(&old) != update.revision {
        return Err((409, "conflict", "DNS 监听配置已更新，请重新加载".into()));
    }
    let next = update.settings;
    if next != old || (next.enabled && state.listener.is_none()) {
        let listener = if next.enabled {
            Some(
                Listener::prepare(next.clone(), state.listener.as_ref()).map_err(|e| {
                    (
                        409,
                        "dns_listener_bind_failed",
                        format!("TCP/UDP DNS 端口无法监听，原设置未变更：{e}"),
                    )
                })?,
            )
        } else {
            None
        };
        crate::storage::write_atomic(
            &crate::config::data_dir().join("dns-listener.json"),
            &serde_json::to_vec_pretty(&next).unwrap(),
        )
        .map_err(|e| (500, "dns_listener_write_failed", e.to_string()))?;
        state.listener = listener;
        if let Some(l) = &state.listener {
            l.activate();
        }
        state.settings = Some(next);
        state.error = None;
        crate::events::emit(
            "runtime.updated",
            json!({"reason":"dns_listener"}).to_string(),
        );
    }
    status(&mut state).map_err(|e| (500, "dns_listener_read_failed", e.to_string()))
}
