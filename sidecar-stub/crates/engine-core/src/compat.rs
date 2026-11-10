//! Pinned mihomo protocol backend. Routing and observation remain in this engine.
//! Fixed per-outbound SOCKS listeners keep a decision immutable across selection changes.
use crate::{
    config,
    platform::{
        managed::{self, CoreProcess},
        tun_bridge::TunBridge,
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

static ROUTER: AtomicU16 = AtomicU16::new(0);
static DNS_PORT: AtomicU16 = AtomicU16::new(0);
static BACKEND: Mutex<Option<Backend>> = Mutex::new(None);
static BACKEND_V6: Mutex<Option<Backend>> = Mutex::new(None);
fn backend_slot(ipv6: bool) -> &'static Mutex<Option<Backend>> {
    if ipv6 && managed::egress_families().is_some() { &BACKEND_V6 } else { &BACKEND }
}

static TUN: Mutex<Option<TunBridge>> = Mutex::new(None);
static ROUTER_PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static HOT_PENDING: AtomicBool = AtomicBool::new(false);
static HOT_ERROR: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn queue_hot_apply() {
    HOT_PENDING.store(true, Ordering::Release);
}
pub(crate) fn hot_apply_json() -> String {
    json!({"available":true,"configuration":true,"group_selection":true,
        "existing_connections":"reconnect","dns_cache":"invalidate",
        "kernel_sync_pending":HOT_PENDING.load(Ordering::Acquire),
        "kernel_sync_error":*HOT_ERROR.lock().unwrap()})
    .to_string()
}

struct Backend {
    process: CoreProcess,
    entries: BTreeMap<String, (Value, u16)>,
    direct_port: u16,
    uplink: Option<String>,
    ipv6: bool,
    checked: Instant,
}

pub(crate) fn random_secret() -> io::Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("无法生成内核凭证"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub(crate) fn set_router_port(port: u16) {
    ROUTER.store(port, Ordering::Relaxed);
}
pub(crate) fn set_dns_port(port: u16) {
    DNS_PORT.store(port, Ordering::Relaxed);
}
pub(crate) fn router_password() -> &'static str {
    ROUTER_PASSWORD.get().map(String::as_str).unwrap_or("")
}
pub(crate) fn available() -> bool {
    managed::core_path().is_some()
}
pub(crate) fn tun_active() -> bool {
    TUN.lock().unwrap().as_mut().is_some_and(TunBridge::alive)
}
pub(crate) fn tun_recovery() -> Option<String> {
    TUN.lock().unwrap().as_ref().and_then(|bridge|bridge.recovery().map(str::to_owned))
}

pub(crate) fn apply_dns_settings(settings: &crate::platform::dns_settings::DnsSettings) -> io::Result<()> {
    if let Some(bridge) = TUN.lock().unwrap().as_mut() {
        bridge.update_dns(settings.clone())?;
    }
    Ok(())
}
pub(crate) fn flush_tun_dns()->io::Result<()>{for slot in [&BACKEND,&BACKEND_V6]{if let Some(backend)=slot.lock().unwrap().as_ref(){backend.process.request("POST","/cache/dns/flush",None)?;}}if let Some(bridge)=TUN.lock().unwrap().as_ref(){bridge.flush_dns()?;}Ok(())}

fn base_config(
    entries: &BTreeMap<String, (Value, u16)>,
    direct_port: u16,
    uplink: &Option<String>,
    ipv6: bool,
) -> Value {
    let mut listeners = vec![
        json!({"name":"lemonvpn-direct","type":"socks","listen":"127.0.0.1","port":direct_port,"udp":true,"proxy":"DIRECT"}),
    ];
    let mut proxies = Vec::new();
    if managed::egress_families().is_some() {
        proxies.push(json!({"name":"LemonVPN-Direct","type":"direct","ip-version":if ipv6 {"ipv6"}else{"ipv4"}}));
        listeners[0]["proxy"] = "LemonVPN-Direct".into();
    }
    for (key, (node, port)) in entries {
        let name = format!("node-{key}");
        if let Some(hops) = node.as_array() {
            for (index, hop) in hops.iter().enumerate() {
                let mut hop = hop.clone();
                hop["name"] = if index + 1 == hops.len() {
                    name.clone()
                } else {
                    format!("hop-{key}-{index}")
                }
                .into();
                if index > 0 {
                    hop["dialer-proxy"] = format!("hop-{key}-{}", index - 1).into();
                }
                proxies.push(hop);
            }
        } else {
            let mut node = node.clone();
            node["name"] = name.clone().into();
            proxies.push(node);
        }
        listeners.push(json!({"name":name,"type":"socks","listen":"127.0.0.1","port":port,"udp":true,"proxy":format!("node-{key}")}));
    }
    let mut config = json!({"ipv6":true,"allow-lan":false,"mode":"rule","log-level":"warning","find-process-mode":"off","listeners":listeners,"proxies":proxies,"rules":["MATCH,REJECT"],"tun":{"enable":false},"profile":{"store-selected":false,"store-fake-ip":false},"dns":{"enable":true,"ipv6":true,"enhanced-mode":"redir-host","default-nameserver":["223.5.5.5","1.1.1.1"],"nameserver":["223.5.5.5","1.1.1.1"]}});
    if let Some(name) = uplink {
        config["interface-name"] = name.clone().into();
    }
    if DNS_PORT.load(Ordering::Relaxed) != 0 {
        config["dns"]["nameserver"] = json!([format!(
            "udp://127.0.0.1:{}",
            DNS_PORT.load(Ordering::Relaxed)
        )]);
    }
    config
}

fn listener(node: Option<&config::Node>, address: Option<&str>) -> io::Result<u16> {
    if crate::runtime::stopping() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "引擎正在停止"));
    }
    // Render outside the backend lock; parsing config/providers must never invert locks.
    let selected = match node {
        Some(node) => Some(endpoint_addresses(address.unwrap_or(&node.host))?.into_iter().next().ok_or_else(||io::Error::other("节点没有可用地址"))?),
        _ => address.map(str::to_owned),
    };
    let rendered = node.map(|node| render_node(node, selected.as_deref())).transpose()?;
    listener_rendered(rendered)
}

fn listener_rendered(rendered: Option<Value>) -> io::Result<u16> {
    if crate::runtime::stopping() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "引擎正在停止"));
    }
    let key = rendered
        .as_ref()
        .map(|n| crate::sha256::hex(n.to_string().as_bytes()));
    let ipv6 = if managed::egress_families().is_some() {
        let first = rendered.as_ref().and_then(|v|v.as_array().and_then(|a|a.first()).or(Some(v)));
        first.and_then(|v|v.get("server")).and_then(Value::as_str)
            .and_then(|v|v.parse::<std::net::IpAddr>().ok()).map(|ip|ip.is_ipv6())
            .unwrap_or_else(||managed::egress_families()==Some([false,true]))
    } else { false };
    let uplink = if managed::egress_families().is_some() { managed::uplink_for(ipv6)? } else { managed::uplink_name() };
    let mut guard = backend_slot(ipv6).lock().unwrap();
    if guard.as_mut().is_some_and(|b|b.uplink!=uplink) { guard.take(); }
    if guard.as_mut().is_some_and(|b| !b.process.alive()) {
        *guard = None;
    }
    if guard.is_none() {
        let direct_port = managed::free_port()?;
        let entries = BTreeMap::new();
        let directory = config::data_dir()
            .join("compat")
            .join(format!("protocols-{}-{}", std::process::id(), if ipv6 {6}else{4}));
        let process = CoreProcess::start(
            &managed::core_path()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "缺少协议兼容内核"))?,
            directory,
            base_config(&entries, direct_port, &uplink, ipv6),
            random_secret()?,
        )?;
        *guard = Some(Backend {
            process,
            entries,
            direct_port,
            uplink,
            ipv6,
            checked: Instant::now(),
        });
    }
    let backend = guard.as_mut().unwrap();
    if managed::egress_families().is_none() && backend.checked.elapsed() >= Duration::from_secs(1) {
        if let Some(name) = managed::uplink_name() {
            if backend.uplink.as_ref() != Some(&name) {
                backend.process.request(
                    "PATCH",
                    "/configs",
                    Some(&json!({"interface-name":name})),
                )?;
                backend.uplink = Some(name);
            }
        }
        backend.checked = Instant::now();
    }
    let Some(key) = key else {
        return Ok(backend.direct_port);
    };
    if let Some((_, port)) = backend.entries.get(&key) {
        return Ok(*port);
    }
    if backend.entries.len() >= 1024 {
        return Err(io::Error::other(
            "活动协议配置超过 1024 项，请重启引擎释放旧配置",
        ));
    }
    let port = managed::free_port()?;
    backend
        .entries
        .insert(key.clone(), (rendered.unwrap(), port));
    let payload = base_config(&backend.entries, backend.direct_port, &backend.uplink, backend.ipv6);
    if let Err(error) = backend.process.configure(payload) {
        backend.entries.remove(&key);
        return Err(error);
    }
    Ok(port)
}

fn control(
    port: u16,
    command: u8,
    host: &str,
    target_port: u16,
) -> io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(3),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(12)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    stream.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err(io::Error::other("协议内核拒绝 SOCKS 握手"));
    }
    let mut request = vec![5, command, 0];
    write_address(&mut request, host, target_port)?;
    stream.write_all(&request)?;
    let mut head = [0; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 5 || head[1] != 0 {
        return Err(io::Error::other(format!(
            "协议内核连接失败（SOCKS {}）",
            head[1]
        )));
    }
    let address = read_address(&mut stream, head[3])?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok((stream, address))
}

fn endpoint_addresses(host: &str) -> io::Result<Vec<String>> {
    let addresses = if let Ok(ip)=host.parse(){vec![ip]}else{crate::dns::bootstrap_resolve(host)?};
    let families = managed::egress_families();
    let result: Vec<_> = addresses.into_iter().filter(|ip|ip.is_loopback() || families.map_or(true,|f|f[usize::from(ip.is_ipv6())]))
        .map(|ip|ip.to_string()).collect();
    if result.is_empty() { return Err(io::Error::new(io::ErrorKind::NotConnected,"没有对应地址族的可用出口")); }
    Ok(result)
}

pub(crate) fn connect(
    node: Option<&config::Node>,
    address: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    if managed::egress_families().is_some() {
        if let Some(node) = node {
            let mut last = io::Error::other("节点没有可用地址");
            for endpoint in endpoint_addresses(address.unwrap_or(&node.host))? {
                let result = listener(Some(node),Some(&endpoint)).and_then(|p|control(p,1,host,port));
                match result { Ok((stream,_))=>return Ok(stream),Err(e)=>last=e }
            }
            return Err(last);
        }
        // Native direct sockets select their family and avoid a global core bind.
        return crate::proxy::dial(host,port);
    }
    control(listener(node, address)?, 1, host, port).map(|(stream, _)| stream)
}

fn chain_listener(nodes: &[config::Node], network: &str) -> io::Result<u16> {
    chain_listener_at(nodes,network,None)
}
fn chain_listener_at(nodes: &[config::Node], network: &str, endpoint:Option<&str>) -> io::Result<u16> {
    if let Some(error) = chain_error(nodes, network) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, error));
    }
    let mut proxies: Vec<_> = nodes.iter().map(|node|render_node(node,None)).collect::<io::Result<_>>()?;
    for(proxy,node)in proxies.iter_mut().zip(nodes){proxy["server"]=endpoint_addresses(&node.host)?[0].clone().into();}
    if managed::egress_families().is_some() {
        proxies[0]["server"] = endpoint.map(str::to_owned).map(Ok).unwrap_or_else(||endpoint_addresses(&nodes[0].host).map(|a|a[0].clone()))?.into();
    }
    listener_rendered(Some(Value::Array(proxies)))
}

pub(crate) fn connect_chain(
    nodes: &[config::Node],
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    if managed::egress_families().is_some() && !nodes.is_empty() {
        let mut last=io::Error::other("前置节点没有可用地址");
        for endpoint in endpoint_addresses(&nodes[0].host)? {
            match chain_listener_at(nodes,"tcp",Some(&endpoint)).and_then(|p|control(p,1,host,port)) {
                Ok((stream,_))=>return Ok(stream),Err(e)=>last=e,
            }
        }
        return Err(last);
    }
    control(chain_listener(nodes, "tcp")?, 1, host, port).map(|(stream, _)| stream)
}

/// Static transport checks only. This never dials or resolves an endpoint.
pub(crate) fn chain_error(nodes: &[config::Node], network: &str) -> Option<String> {
    if !(2..=8).contains(&nodes.len()) {
        return Some("代理链需要 2 至 8 个节点".into());
    }
    let mut udp = network == "udp";
    for node in nodes.iter().rev() {
        let value = match render_node(node, None) {
            Ok(value) => value,
            Err(error) => return Some(error.to_string()),
        };
        let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
        let supports_udp = match kind {
            "http" | "ssh" => false,
            "snell" => {
                value.get("version").and_then(Value::as_u64).unwrap_or(1) >= 3
                    && value.get("udp").and_then(Value::as_bool) == Some(true)
            }
            "hysteria" | "hysteria2" | "tuic" | "wireguard" => true,
            _ => value.get("udp").and_then(Value::as_bool) == Some(true),
        };
        if udp && !supports_udp {
            return Some(format!(
                "节点“{}”未支持或未开启 UDP，无法承载此段链路",
                node.name
            ));
        }
        udp = matches!(kind, "hysteria" | "hysteria2" | "tuic" | "wireguard")
            || value.get("network").and_then(Value::as_str) == Some("quic")
            || (udp
                && matches!(kind, "ss" | "ssr" | "socks5")
                && value.get("udp-over-tcp").and_then(Value::as_bool) != Some(true));
    }
    None
}

pub(crate) struct Datagram {
    control: TcpStream,
    socket: UdpSocket,
    host: String,
    port: u16,
    policy_node: Option<config::Node>,
    first_reply: AtomicBool,
    opened_at: Instant,
}
impl Datagram {
    pub(crate) fn open(decision: &config::Decision, host: &str, port: u16) -> io::Result<Self> {
        let started = Instant::now();
        let result = Self::open_inner(decision, host, port);
        if result.is_err() {
            if let config::Target::Node(node) = &decision.target {
                crate::group_policy::dial_result(node, "udp", false, started.elapsed());
            }
        }
        result
    }

    fn open_inner(decision: &config::Decision, host: &str, port: u16) -> io::Result<Self> {
        let node = match &decision.target {
            config::Target::Block => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UDP 被规则阻止",
                ))
            }
            config::Target::Direct => None,
            config::Target::Node(node) => Some(node.as_ref()),
            config::Target::Chain { nodes, .. } => {
                return Self::open_port(chain_listener(nodes, "udp")?, None, host, port)
            }
        };
        Self::open_target(node, None, host, port)
    }

    pub(crate) fn open_probe(
        node: &config::Node,
        address: &str,
        host: &str,
        port: u16,
    ) -> io::Result<Self> {
        let mut relay = Self::open_target(Some(node), Some(address), host, port)?;
        // A health check is recorded as a probe, independently of real connection quality.
        relay.policy_node = None;
        Ok(relay)
    }

    fn open_target(
        node: Option<&config::Node>,
        address: Option<&str>,
        host: &str,
        port: u16,
    ) -> io::Result<Self> {
        if node.is_none() && managed::egress_families().is_some() {
            let endpoint=endpoint_addresses(host)?[0].clone();
            let proxy=json!({"type":"direct","server":endpoint,"udp":true});
            return Self::open_port(listener_rendered(Some(proxy))?,node,&endpoint,port);
        }
        Self::open_port(listener(node, address)?, node, host, port)
    }

    fn open_port(
        listener: u16,
        node: Option<&config::Node>,
        host: &str,
        port: u16,
    ) -> io::Result<Self> {
        let (control, mut relay) = control(listener, 3, "0.0.0.0", 0)?;
        if relay.ip().is_unspecified() {
            relay.set_ip("127.0.0.1".parse().unwrap());
        }
        if !relay.ip().is_loopback() || relay.port() == 0 {
            return Err(io::Error::other("内核返回了无效 UDP 中继地址"));
        }
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(relay)?;
        socket.set_nonblocking(true)?;
        control.set_nonblocking(true)?;
        Ok(Self {
            control,
            socket,
            host: host.to_owned(),
            port,
            policy_node: node.cloned(),
            first_reply: AtomicBool::new(false),
            opened_at: Instant::now(),
        })
    }
    pub(crate) fn send(&self, payload: &[u8]) -> io::Result<()> {
        let mut byte = [0];
        match self.control.peek(&mut byte) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "UDP 中继已关闭",
                ))
            }
        }
        let mut packet = vec![0, 0, 0];
        write_address(&mut packet, &self.host, self.port)?;
        packet.extend_from_slice(payload);
        self.socket.send(&packet).map(|_| ())
    }
    pub(crate) fn recv(&self, buffer: &mut [u8]) -> io::Result<(usize, String, u16)> {
        let size = self.socket.recv(buffer)?;
        let (host, port, offset) = parse_datagram(&buffer[..size])?;
        if !self.first_reply.swap(true, Ordering::Relaxed) {
            if let Some(node) = &self.policy_node {
                crate::group_policy::dial_result(node, "udp", true, self.opened_at.elapsed());
            }
        }
        buffer.copy_within(offset..size, 0);
        Ok((size - offset, host, port))
    }
}

pub(crate) fn write_address(bytes: &mut Vec<u8>, host: &str, port: u16) -> io::Result<()> {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        Err(_) if !host.is_empty() && host.len() <= 255 => {
            bytes.extend_from_slice(&[3, host.len() as u8]);
            bytes.extend_from_slice(host.as_bytes());
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS 目标地址无效",
            ))
        }
    }
    bytes.extend_from_slice(&port.to_be_bytes());
    Ok(())
}
fn read_address(reader: &mut impl Read, atyp: u8) -> io::Result<SocketAddr> {
    let ip = match atyp {
        1 => {
            let mut b = [0; 4];
            reader.read_exact(&mut b)?;
            std::net::IpAddr::from(b)
        }
        4 => {
            let mut b = [0; 16];
            reader.read_exact(&mut b)?;
            std::net::IpAddr::from(b)
        }
        3 => {
            let mut len = [0];
            reader.read_exact(&mut len)?;
            let mut b = vec![0; len[0] as usize];
            reader.read_exact(&mut b)?;
            "127.0.0.1".parse().unwrap()
        }
        _ => return Err(io::Error::other("无效 SOCKS 地址类型")),
    };
    let mut port = [0; 2];
    reader.read_exact(&mut port)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}
pub(crate) fn parse_datagram(packet: &[u8]) -> io::Result<(String, u16, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(io::Error::other("不支持分片或无效 SOCKS UDP 报文"));
    }
    let (host, end) = match packet[3] {
        1 if packet.len() >= 10 => (
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&packet[4..8]).unwrap()).to_string(),
            8,
        ),
        4 if packet.len() >= 22 => (
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[4..20]).unwrap()).to_string(),
            20,
        ),
        3 if packet.len() >= 7 && packet.len() >= 7 + packet[4] as usize => {
            let end = 5 + packet[4] as usize;
            (
                String::from_utf8(packet[5..end].to_vec())
                    .map_err(|_| io::Error::other("UDP 域名编码无效"))?,
                end,
            )
        }
        _ => return Err(io::Error::other("UDP 地址截断")),
    };
    Ok((
        host,
        u16::from_be_bytes([packet[end], packet[end + 1]]),
        end + 2,
    ))
}

static PROCESS_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());
fn remember_process_names() -> Vec<String> {
    let names = config::process_names();
    let mut previous = PROCESS_NAMES.lock().unwrap();
    if previous.len() + names.len() > 1024 {
        previous.clear();
    }
    for name in &names {
        if !previous.contains(name) {
            previous.push(name.clone());
        }
    }
    names
}
pub(crate) fn bridge_process(
    username: &[u8],
) -> Option<Option<crate::platform::process::ProcessInfo>> {
    if username == b"lemonvpn-tun" {
        return Some(None);
    }
    PROCESS_NAMES
        .lock()
        .unwrap()
        .iter()
        .find(|name| crate::platform::tun_bridge::process_token(name).as_bytes() == username)
        .map(|name| Some(crate::platform::process::ProcessInfo::selector(name)))
}
pub(crate) fn refresh_tun_processes() {
    // Query accepted configuration before acquiring the bridge lock (fixed lock order).
    let names = remember_process_names();
    if !HOT_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let result = (|| {
        for slot in [&BACKEND,&BACKEND_V6] {
            if let Some(backend) = slot.lock().unwrap().as_ref() {
                backend.process.request("POST", "/cache/dns/flush", None)?;
            }
        }
        if let Some(bridge) = TUN.lock().unwrap().as_mut() {
            bridge.update_processes(names)?;
            bridge.flush_dns()?;
        }
        Ok::<(), io::Error>(())
    })();
    let mut last = HOT_ERROR.lock().unwrap();
    if let Err(error) = result {
        HOT_PENDING.store(true, Ordering::Release);
        let message = error.to_string();
        if last.as_deref() != Some(&message) {
            crate::logs::warn(
                "engine::config",
                "内核热更新同步未完成，将重试。",
                Some(crate::logs::fields(&[("error", &message)])),
            );
        }
        *last = Some(message);
    } else {
        *last = None;
    }
}

pub(crate) fn refresh_network() {
    use std::sync::atomic::AtomicU64;
    static REVISION: AtomicU64 = AtomicU64::new(0);
    let Some(revision)=managed::network_revision() else {return};
    if let Some(bridge)=TUN.lock().unwrap().as_mut() { bridge.alive(); }
    let previous=REVISION.swap(revision,Ordering::AcqRel);
    if previous==0 || previous==revision {return}
    // Only POSIX hosts report revisions. Do not alter Windows recovery paths.
    crate::connections::close_all();
    crate::dns::flush();
    BACKEND.lock().unwrap().take();
    BACKEND_V6.lock().unwrap().take();
    HOT_PENDING.store(true,Ordering::Release);
    crate::logs::info("engine::network","Network changed or resumed; stale connections and resolver state released.",None);
}

pub(crate) fn enable_tun() -> io::Result<()> {
    // Read preferences before the bridge mutex: settings writes take settings -> TUN.
    let dns_settings = crate::dns_settings::effective().map_err(io::Error::other)?;
    if !crate::platform::current().tun_supported() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "当前平台尚未提供可用的 TUN 适配器",
        ));
    }
    let mut tun = TUN.lock().unwrap();
    if tun.as_mut().is_some_and(TunBridge::alive) {
        return Err(io::Error::other("TUN 模式已开启"));
    }
    // Drop the old broker owner before starting a replacement; its stop request
    // must never be delivered to the newly created session.
    tun.take();
    // Start the non-privileged protocol backend before installing capture routes.
    listener(None, None)?;
    if ROUTER_PASSWORD.get().is_none() {
        let _ = ROUTER_PASSWORD.set(random_secret()?);
    }
    let password = ROUTER_PASSWORD.get().unwrap();
    crate::platform::current().external_tun(true)?;
    let bridge = match TunBridge::start(
        ROUTER.load(Ordering::Relaxed),
        DNS_PORT.load(Ordering::Relaxed),
        password,
        config::data_dir().join("compat"),
        remember_process_names(),
        dns_settings,
    ) {
        Ok(bridge) => bridge,
        Err(error) => {
            let _ = crate::platform::current().external_tun(false);
            return Err(error);
        }
    };
    *tun = Some(bridge);
    Ok(())
}
pub(crate) fn disable_tun() -> io::Result<()> {
    let mut guard = TUN.lock().unwrap();
    if let Some(bridge) = guard.as_mut() {
        bridge.shutdown()?;
        guard.take();
        crate::platform::current().external_tun(false)?;
    }
    Ok(())
}
pub(crate) fn shutdown() {
    let _ = disable_tun();
    BACKEND.lock().unwrap().take();
    BACKEND_V6.lock().unwrap().take();
}

pub(crate) fn stream_transport(node: &config::Node) -> String {
    render_node(node, None)
        .ok()
        .and_then(|proxy| proxy.get("network").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "tcp".to_owned())
}

fn render_node(node: &config::Node, address: Option<&str>) -> io::Result<Value> {
    let mut result = if let Some(data) = node
        .link
        .as_deref()
        .and_then(|v| v.strip_prefix("mihomo://"))
    {
        let bytes = crate::base64::decode(data).ok_or_else(|| io::Error::other("节点编码无效"))?;
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("节点参数无效"))?
    } else if node.protocol == "socks5" {
        let mut value = json!({"type":"socks5","server":node.host,"port":node.port,"udp":true});
        if let Some(user) = &node.username {
            value["username"] = user.clone().into();
        }
        if let Some(pass) = &node.password {
            value["password"] = pass.clone().into();
        }
        value
    } else {
        let link = node
            .link
            .as_deref()
            .ok_or_else(|| io::Error::other("节点缺少协议参数"))?;
        if let Some(data) = link.strip_prefix("mihomo://") {
            let bytes =
                crate::base64::decode(data).ok_or_else(|| io::Error::other("节点编码无效"))?;
            serde_json::from_slice(&bytes).map_err(|_| io::Error::other("节点参数无效"))?
        } else {
            render_share(link)?
        }
    };
    // Never accept listener/command settings from subscriptions. Only proxy entries reach the core.
    if !result.is_object() {
        return Err(io::Error::other("节点必须为对象"));
    }
    result.as_object_mut().unwrap().remove("dialer-proxy");
    result.as_object_mut().unwrap().remove("interface-name");
    result.as_object_mut().unwrap().remove("routing-mark");
    if result.get("tls").and_then(Value::as_bool) == Some(true)
        || matches!(node.protocol.as_str(), "trojan" | "hysteria2" | "tuic")
    {
        let sni_key = if matches!(node.protocol.as_str(), "hysteria2" | "tuic") {
            "sni"
        } else {
            "servername"
        };
        if result
            .get(sni_key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            result[sni_key] = node.host.clone().into();
        }
    }
    if let Some(address) = address {
        result["server"] = address.into();
    }
    result["name"] = node.name.clone().into();
    result["port"] = node.port.into();
    Ok(result)
}

fn render_share(link: &str) -> io::Result<Value> {
    let share = crate::share::parse(link).map_err(io::Error::other)?;
    let query = link
        .split_once('?')
        .map(|(_, v)| v.split('#').next().unwrap_or(""))
        .unwrap_or("");
    let params = crate::share::query_params(query);
    let get = |key: &str| params.get(key).map(String::as_str).unwrap_or("");
    let mut n = json!({"type":share.protocol,"server":share.host,"port":share.port,"udp":true});
    match share.protocol.as_str() {
        "vless" => {
            n["uuid"] = share.secret.into();
            if !get("flow").is_empty() {
                n["flow"] = get("flow").into();
            }
            if !get("encryption").is_empty() {
                n["encryption"] = get("encryption").into();
            }
            n["packet-encoding"] = get("packetEncoding").into();
        }
        "vmess" => {
            let data = link
                .strip_prefix("vmess://")
                .unwrap()
                .split('#')
                .next()
                .unwrap();
            let bytes =
                crate::base64::decode(data).ok_or_else(|| io::Error::other("VMess 编码无效"))?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| io::Error::other("VMess 参数无效"))?;
            let text = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or("");
            n["uuid"] = share.secret.clone().into();
            n["alterId"] = value
                .get("aid")
                .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
                .unwrap_or(0)
                .into();
            n["cipher"] = if text("scy").is_empty() {
                "auto"
            } else {
                text("scy")
            }
            .into();
            transport(
                &mut n,
                if text("net") == "tcp" && text("type") == "http" {
                    "http"
                } else {
                    text("net")
                },
                text("path"),
                text("host"),
                text("path"),
            )?;
            if !text("fp").is_empty() {
                n["client-fingerprint"] = text("fp").into();
            }
        }
        "trojan" | "hysteria2" => {
            n["password"] = share.secret.clone().into();
        }
        "ss" => {
            let (method, password) = share
                .secret
                .split_once(':')
                .ok_or_else(|| io::Error::other("SS 参数无效"))?;
            n["cipher"] = method.into();
            n["password"] = password.into();
            if !get("plugin").is_empty() {
                let mut fields = get("plugin").split(';');
                let plugin = fields.next().unwrap_or("");
                let plugin = match plugin {
                    "obfs-local" | "simple-obfs" => "obfs",
                    "v2ray-plugin" => "v2ray-plugin",
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "SS 插件不在兼容内核支持范围内",
                        ))
                    }
                };
                n["plugin"] = plugin.into();
                let mut opts = json!({});
                for field in fields {
                    let (key, value) = field.split_once('=').unwrap_or((field, "true"));
                    let key = if key == "obfs" {
                        "mode"
                    } else {
                        key.strip_prefix("obfs-").unwrap_or(key)
                    };
                    opts[key] = match value {
                        "true" => true.into(),
                        "false" => false.into(),
                        _ => value.into(),
                    };
                }
                if plugin == "v2ray-plugin" && opts.get("mode").is_none() {
                    opts["mode"] = "websocket".into();
                }
                n["plugin-opts"] = opts;
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "分享协议不在支持范围内",
            ))
        }
    }
    if share.protocol != "vmess" && share.protocol != "ss" && share.protocol != "hysteria2" {
        transport(
            &mut n,
            get("type"),
            get("path"),
            get("host"),
            get("serviceName"),
        )?;
    }
    if share.tls && share.protocol != "ss" {
        n["tls"] = true.into();
    }
    if let Some(sni) = share.sni {
        n[if share.protocol == "hysteria2" {
            "sni"
        } else {
            "servername"
        }] = sni.into();
    }
    if !get("alpn").is_empty() {
        n["alpn"] = get("alpn")
            .split(',')
            .map(|v| Value::from(v.trim()))
            .collect();
    }
    n["skip-cert-verify"] = (matches!(get("allowInsecure"), "1" | "true")
        || matches!(get("insecure"), "1" | "true"))
    .into();
    if !get("fp").is_empty() {
        n["client-fingerprint"] = get("fp").into();
    }
    if share.reality {
        if get("pbk").is_empty() {
            return Err(io::Error::other("REALITY 节点缺少 public key"));
        }
        n["reality-opts"] = json!({"public-key":get("pbk"),"short-id":get("sid")});
        if get("fp").is_empty() {
            n["client-fingerprint"] = "chrome".into();
        }
    }
    if share.protocol == "hysteria2" {
        for (key, target) in [
            ("obfs", "obfs"),
            ("obfs-password", "obfs-password"),
            ("mport", "ports"),
            ("upmbps", "up"),
            ("downmbps", "down"),
        ] {
            if !get(key).is_empty() {
                n[target] = get(key).into();
            }
        }
    }
    Ok(n)
}

fn transport(
    node: &mut Value,
    network: &str,
    path: &str,
    host: &str,
    service: &str,
) -> io::Result<()> {
    let network = if network.is_empty() { "tcp" } else { network };
    if !matches!(
        network,
        "tcp" | "ws" | "grpc" | "h2" | "http" | "httpupgrade" | "mkcp" | "mekya"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("不支持的传输方式：{network}"),
        ));
    }
    node["network"] = network.into();
    match network {
        "ws" | "httpupgrade" => {
            node["ws-opts"] = json!({"path":if path.is_empty(){"/"}else{path}});
            if !host.is_empty() {
                node["ws-opts"]["headers"] = json!({"Host":host});
            }
            if network == "httpupgrade" {
                node["network"] = "ws".into();
                node["ws-opts"]["v2ray-http-upgrade"] = true.into();
            }
        }
        "grpc" => node["grpc-opts"] = json!({"grpc-service-name":service}),
        "h2" => {
            node["h2-opts"] = json!({"path":path,"host":host.split(',').filter(|s|!s.is_empty()).collect::<Vec<_>>()})
        }
        "http" => node["http-opts"] = json!({"path":[path],"headers":{"Host":[host]}}),
        _ => {}
    }
    Ok(())
}

pub(crate) fn flush_fake_ip()->io::Result<()>{let tun=TUN.lock().unwrap();let bridge=tun.as_ref().ok_or_else(||io::Error::other("TUN 未启用，未清理映射"))?;bridge.flush_fake_ip()}

pub(crate) fn apply_process_names(names:Vec<String>)->io::Result<()>{
    {let mut previous=PROCESS_NAMES.lock().unwrap();if previous.len()+names.len()>1024{previous.clear()}for name in &names{if !previous.contains(name){previous.push(name.clone());}}}
    if let Some(bridge)=TUN.lock().unwrap().as_mut(){bridge.update_processes(names)?;}Ok(())
}
