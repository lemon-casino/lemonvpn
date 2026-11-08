//! Platform-independent IPv4 TCP / DNS packet stack and TUN lifecycle.
use crate::platform::{self, TunConfig, TunSession};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const POLL_IDLE: Duration = Duration::from_millis(1);
const TCP_WINDOW: usize = 64 * 1024;
const UDP_BUFFER: usize = 4 * 1024;
const MAX_FLOWS: usize = 1024;
const MAX_LISTENERS: usize = 256;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// In-memory packet transport between the pump (or a test harness) and
/// smoltcp: `receive` pops packets the pump queued, tokens push egress
/// packets back out through the channel.
struct TunDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Sender<Vec<u8>>,
}

fn device_capabilities() -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ip;
    caps.max_transmission_unit = 65_535;
    // Virtual adapters may deliver host packets without checksums: the host's TCP/UDP segments arrive without
    // a computed checksum (Windows leaves it to NIC offload, and there is no
    // real NIC). Tell smoltcp to compute checksums on the way out (so the host
    // accepts our packets) but not to verify them on the way in (so we accept
    // the host's unchecksummed segments). `Tx` is exactly that split.
    caps.checksum.ipv4 = Checksum::Tx;
    caps.checksum.udp = Checksum::Tx;
    caps.checksum.tcp = Checksum::Tx;
    caps
}

/// Capabilities-only device for interface construction; the real device is
/// only borrowed inside each poll.
struct NullDevice;

impl Device for NullDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        None
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        None
    }

    fn capabilities(&self) -> DeviceCapabilities {
        device_capabilities()
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((
            TunRxToken { buf },
            TunTxToken {
                tx: self.tx.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            tx: self.tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        device_capabilities()
    }
}

struct TunRxToken {
    buf: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

struct TunTxToken {
    tx: Sender<Vec<u8>>,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        let _ = self.tx.send(buf);
        out
    }
}

/// Dials the original destination of one accepted flow. Production wires this
/// to the rule engine; tests wire it to a local echo server.
type Dial = Arc<dyn Fn(&str, u16, &crate::config::Decision) -> io::Result<TcpStream> + Send + Sync>;
/// Answers hijacked DNS queries. Production wires this to `dns::resolve`.
type Resolve = Arc<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

struct StackCore {
    iface: Interface,
    sockets: SocketSet<'static>,
    /// One listener per destination port seen so far; smoltcp listens on
    /// exact ports only, so the pump creates one per SYN target.
    listeners: HashMap<u16, SocketHandle>,
    /// Finished flows whose socket must stay in the set until the stack has
    /// emitted its FIN/RST, then be reaped by the pump.
    reaps: Vec<SocketHandle>,
    dns: SocketHandle,
    flows: usize,
    stopped: bool,
    upstreams: HashMap<SocketHandle, TcpStream>,
}

/// A running user-space stack: the pump thread plus the shared core the flow
/// relays lock onto. `stop` ends the pump; relays end with their flows.
struct Stack {
    /// Test-only access to flow bookkeeping.
    #[cfg_attr(not(test), allow(dead_code))]
    core: Arc<Mutex<StackCore>>,
    stop: Arc<AtomicBool>,
    pump: JoinHandle<()>,
}

impl Stack {
    fn start(
        inbound: Receiver<Vec<u8>>,
        outbound: Sender<Vec<u8>>,
        dial: Dial,
        resolve: Resolve,
        config: &TunConfig,
    ) -> Stack {
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut NullDevice,
            SmolInstant::from_millis(0),
        );
        // Flows are terminated for addresses that are not ours to own.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::from(config.stack_address)),
                config.prefix_len,
            ));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(config.stack_address));

        let mut sockets = SocketSet::new(vec![]);
        let dns = sockets.add(new_udp_socket());
        let _ = sockets.get_mut::<udp::Socket>(dns).bind(IpListenEndpoint {
            addr: None,
            port: 53,
        });
        let core = Arc::new(Mutex::new(StackCore {
            iface,
            sockets,
            listeners: HashMap::new(),
            reaps: Vec::new(),
            dns,
            flows: 0,
            stopped: false,
            upstreams: HashMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let pump_core = Arc::clone(&core);
        let pump_stop = Arc::clone(&stop);
        let pump = thread::spawn(move || {
            pump_loop(
                TunDevice {
                    rx: VecDeque::new(),
                    tx: outbound,
                },
                inbound,
                pump_core,
                pump_stop,
                dial,
                resolve,
                started,
            );
        });
        Stack { core, stop, pump }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        {
            let mut core = self.core.lock().unwrap();
            core.stopped = true;
            for (_, stream) in core.upstreams.drain() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            for (_, socket) in core.sockets.iter_mut() {
                if let smoltcp::socket::Socket::Tcp(socket) = socket {
                    socket.abort();
                }
            }
        }
        let _ = self.pump.join();
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
        tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
    )
}

/// A fresh wildcard listener; accepted flows get a new one to replace it.
/// Destination port of an IPv4 TCP segment whose flags are a bare SYN (the
/// first packet of a connection); None for anything else.
fn syn_dst_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 24 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet[9] != 6 || packet.len() < ihl + 14 {
        return None;
    }
    let flags = packet[ihl + 13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
}

/// Makes sure a listening socket exists for the SYN's destination port;
/// smoltcp matches listeners by exact port, so one is created per port seen.
fn ensure_listener(core: &Arc<Mutex<StackCore>>, port: u16) {
    if port == 0 {
        return;
    }
    let mut guard = core.lock().unwrap();
    if guard.listeners.contains_key(&port) || guard.listeners.len() >= MAX_LISTENERS {
        return;
    }
    let mut socket = new_tcp_socket();
    if socket.listen(IpListenEndpoint { addr: None, port }).is_ok() {
        let handle = guard.sockets.add(socket);
        guard.listeners.insert(port, handle);
    }
}

fn new_udp_socket() -> udp::Socket<'static> {
    // Packet buffers need a metadata slot per queued datagram; without any,
    // every send/recv fails.
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; UDP_BUFFER]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; UDP_BUFFER]),
    )
}

fn socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(v4) => SocketAddr::from((std::net::Ipv4Addr::from(v4), endpoint.port)),
    }
}

/// The pump: drains adapter packets through smoltcp, promotes accepted
/// listeners into relays, answers hijacked DNS, and paces re-polls.
fn pump_loop(
    mut device: TunDevice,
    inbound: Receiver<Vec<u8>>,
    core: Arc<Mutex<StackCore>>,
    stop: Arc<AtomicBool>,
    dial: Dial,
    resolve: Resolve,
    started: Instant,
) {
    while !stop.load(Ordering::Relaxed) {
        while let Ok(packet) = inbound.try_recv() {
            if let Some(port) = syn_dst_port(&packet) {
                ensure_listener(&core, port);
            }
            device.rx.push_back(packet);
        }
        let now = SmolInstant::from_millis(started.elapsed().as_millis() as i64);
        {
            let mut core = core.lock().unwrap();
            let StackCore {
                iface,
                sockets,
                reaps,
                ..
            } = &mut *core;
            iface.poll(now, &mut device, sockets);
            // Reap only once the socket reached Closed: removing earlier
            // would drop a FIN or RST still waiting to be emitted.
            reaps.retain(|handle| sockets.get_mut::<tcp::Socket>(*handle).is_open());
        }
        accept_flows(&core, &dial);
        serve_dns(&core, &resolve);
        let delay = {
            let mut core = core.lock().unwrap();
            let StackCore { iface, sockets, .. } = &mut *core;
            iface
                .poll_delay(now, sockets)
                .map(|d| Duration::from_millis(d.total_millis().max(0) as u64))
                .unwrap_or(POLL_IDLE)
                .min(Duration::from_millis(20))
                .max(POLL_IDLE)
        };
        thread::sleep(delay);
    }
}

/// Promotes any listener whose socket left the Listen state: the old socket
/// becomes the flow's, and the port slot frees so a later SYN re-creates a
/// listener.
fn accept_flows(core: &Arc<Mutex<StackCore>>, dial: &Dial) {
    let mut guard = core.lock().unwrap();
    let pending: Vec<(u16, SocketHandle)> = guard
        .listeners
        .iter()
        .map(|(port, handle)| (*port, *handle))
        .collect();
    for (port, handle) in pending {
        let listening = guard.sockets.get_mut::<tcp::Socket>(handle).is_listening();
        if listening {
            continue;
        }
        guard.listeners.remove(&port);

        if guard.flows >= MAX_FLOWS {
            guard.sockets.get_mut::<tcp::Socket>(handle).abort();
            continue;
        }
        let (src, target) = {
            let sock = guard.sockets.get_mut::<tcp::Socket>(handle);
            (
                sock.remote_endpoint().map(socket_addr),
                sock.local_endpoint().map(socket_addr),
            )
        };
        if let (Some(src), Some(target)) = (src, target) {
            guard.flows += 1;
            let shared = Arc::clone(core);
            let dial = Arc::clone(dial);
            thread::spawn(move || relay_flow(shared, handle, src, target, dial));
        } else {
            guard.sockets.get_mut::<tcp::Socket>(handle).abort();
        }
    }
}

/// One relayed flow: rule-engine dial, metered byte pumps in both
/// directions, flow record + live connection entry.
fn relay_flow(
    core: Arc<Mutex<StackCore>>,
    handle: SocketHandle,
    src: SocketAddr,
    target: SocketAddr,
    dial: Dial,
) {
    let target_str = target.ip().to_string();
    let decision = crate::config::decide_connection(&target_str, target.port(), Some(src), "tcp");
    let outbound = match dial(&target_str, target.port(), &decision) {
        Ok(stream) => stream,
        Err(_) => {
            crate::flows::blocked(src, &target_str, target.port(), None, None, &decision);
            finish_flow(&core, handle);
            return;
        }
    };
    let _ = outbound.set_nodelay(true);
    {
        let mut guard = core.lock().unwrap();
        if guard.stopped {
            drop(guard);
            let _ = outbound.shutdown(std::net::Shutdown::Both);
            finish_flow(&core, handle);
            return;
        }
        if let Ok(socket) = outbound.try_clone() {
            guard.upstreams.insert(handle, socket);
        }
    }

    let _flow = crate::flows::begin(src, &target_str, target.port(), None, None, &decision);
    let meter = crate::outbounds::Meter::open(&decision);
    let bytes = meter.handle();
    let _open = OpenCount::new();
    let live = crate::connections::Live::open(src, target, outbound.try_clone().ok());
    live.set_route(&decision, Some(&_flow));
    if live.closed() {
        abort_socket(&core, handle);
        finish_flow(&core, handle);
        return;
    }
    let retired = live.cancellation();
    let counters = Arc::clone(&live.counters);
    let _ = live; // keeps the connection listed until the relays end

    let read_half = match outbound.try_clone() {
        Ok(dup) => dup,
        Err(_) => {
            abort_socket(&core, handle);
            finish_flow(&core, handle);
            return;
        }
    };
    let up = thread::spawn({
        let core = Arc::clone(&core);
        let bytes = bytes.clone();
        let counters = Arc::clone(&counters);
        let retired = Arc::clone(&retired);
        move || relay_up(core, handle, outbound, bytes, counters, retired)
    });
    relay_down(&core, handle, read_half, &bytes, &counters, &retired);
    let _ = up.join();
    finish_flow(&core, handle);
}

/// Marks a finished flow: the flow count drops now, the socket stays in the
/// set until the pump has emitted its FIN and reaps it once Closed.
fn finish_flow(core: &Arc<Mutex<StackCore>>, handle: SocketHandle) {
    let mut guard = core.lock().unwrap();
    guard.flows = guard.flows.saturating_sub(1);
    guard.upstreams.remove(&handle);
    guard.reaps.push(handle);
}

enum Action {
    Data(usize),
    Eof,
    Wait,
}

/// Client → outbound: smoltcp recv to blocking writes; on the client's FIN
/// the outbound write half shuts down.
fn relay_up(
    core: Arc<Mutex<StackCore>>,
    handle: SocketHandle,
    mut outbound: TcpStream,
    bytes: crate::outbounds::Handle,
    counters: Arc<crate::connections::Counters>,
    retired: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf = vec![0u8; 8192];
    loop {
        if retired.load(Ordering::Acquire) {
            abort_socket(&core, handle);
            break;
        }
        let action = {
            let mut core = core.lock().unwrap();
            let sock = core.sockets.get_mut::<tcp::Socket>(handle);
            match sock.recv_slice(&mut buf) {
                Ok(n) if n > 0 => Action::Data(n),
                Err(tcp::RecvError::Finished) => Action::Eof,
                _ => {
                    // InvalidState covers both the unfinished handshake
                    // (keep waiting) and a dead socket (end the pump).
                    if sock.is_open() {
                        Action::Wait
                    } else {
                        Action::Eof
                    }
                }
            }
        };
        match action {
            Action::Data(n) => {
                if outbound.write_all(&buf[..n]).is_err() {
                    abort_socket(&core, handle);
                    break;
                }
                crate::state::add_upload(n as u64);
                bytes.upload(n as u64);
                counters.upload.fetch_add(n as u64, Ordering::Relaxed);
            }
            Action::Eof => {
                let _ = outbound.shutdown(std::net::Shutdown::Write);
                break;
            }
            Action::Wait => thread::sleep(POLL_IDLE),
        }
    }
}

/// Outbound → client: blocking reads into smoltcp sends; on the outbound's
/// EOF the socket sends its FIN, on an error it is aborted.
fn relay_down(
    core: &Arc<Mutex<StackCore>>,
    handle: SocketHandle,
    mut outbound: TcpStream,
    bytes: &crate::outbounds::Handle,
    counters: &Arc<crate::connections::Counters>,
    retired: &Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf = vec![0u8; 8192];
    loop {
        if retired.load(Ordering::Acquire) {
            abort_socket(core, handle);
            break;
        }
        match outbound.read(&mut buf) {
            Ok(0) => {
                close_socket(core, handle);
                break;
            }
            Ok(n) => {
                if !push_down(core, handle, &buf[..n], bytes, counters, retired) {
                    break;
                }
            }
            Err(_) => {
                abort_socket(&core, handle);
                break;
            }
        }
    }
}

/// Pushes one outbound chunk through the socket, looping on the partial
/// sends of a full transmit buffer. False means the socket went away.
fn push_down(
    core: &Arc<Mutex<StackCore>>,
    handle: SocketHandle,
    chunk: &[u8],
    bytes: &crate::outbounds::Handle,
    counters: &Arc<crate::connections::Counters>,
    retired: &Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    let mut sent_total = 0;
    while sent_total < chunk.len() {
        if retired.load(Ordering::Acquire) {
            abort_socket(core, handle);
            return false;
        }
        let sent = {
            let mut core = core.lock().unwrap();
            let sock = core.sockets.get_mut::<tcp::Socket>(handle);
            if !sock.may_send() {
                return false;
            }
            match sock.send_slice(&chunk[sent_total..]) {
                Ok(sent) => sent,
                Err(_) => return false,
            }
        };
        if sent == 0 {
            thread::sleep(POLL_IDLE);
            continue;
        }
        crate::state::add_download(sent as u64);
        bytes.download(sent as u64);
        counters.download.fetch_add(sent as u64, Ordering::Relaxed);
        sent_total += sent;
    }
    true
}

fn abort_socket(core: &Arc<Mutex<StackCore>>, handle: SocketHandle) {
    let mut core = core.lock().unwrap();
    core.sockets.get_mut::<tcp::Socket>(handle).abort();
}

fn close_socket(core: &Arc<Mutex<StackCore>>, handle: SocketHandle) {
    let mut core = core.lock().unwrap();
    core.sockets.get_mut::<tcp::Socket>(handle).close();
}

/// Counts one open flow for as long as it exists, however it ends.
struct OpenCount;

impl OpenCount {
    fn new() -> OpenCount {
        crate::state::connection_opened();
        OpenCount
    }
}

struct TunState {
    stack: Stack,
    session: Box<dyn TunSession>,
    config: TunConfig,
}

static TUN: Mutex<Option<TunState>> = Mutex::new(None);

pub(crate) fn active() -> bool {
    crate::compat::tun_active() || TUN.lock().unwrap().is_some()
}

pub(crate) fn supported() -> bool {
    // Kernel TUN exists only where capture can be privileged: Windows uses its
    // own wintun adapter, macOS delegates to the installed TUN service.
    platform::current().tun_supported()
}

pub(crate) fn enable() -> io::Result<()> {
    if crate::compat::available() {
        return crate::compat::enable_tun();
    }
    enable_with_config(TunConfig::default())
}

pub(crate) fn enable_with_config(config: TunConfig) -> io::Result<()> {
    config.validate()?;
    if !supported() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "当前平台尚未提供 TUN 适配器",
        ));
    }
    let mut guard = TUN.lock().unwrap();
    if guard.is_some() {
        return Err(invalid("TUN 模式已开启"));
    }
    let opened = platform::current().open_tun(&config)?;
    let stack = Stack::start(
        opened.incoming,
        opened.outgoing,
        Arc::new(|host, port, decision| crate::proxy::connect(decision, host, port)),
        Arc::new(crate::dns::resolve),
        &config,
    );
    *guard = Some(TunState {
        stack,
        session: opened.session,
        config,
    });
    crate::logs::info("engine::tun", "TUN packet capture started.", None);
    Ok(())
}

pub(crate) fn disable() -> io::Result<()> {
    crate::compat::disable_tun()?;
    // Serialize disable with enable until routes and the physical binding are
    // gone. Otherwise an old session could tear down a newly enabled one.
    let mut guard = TUN.lock().unwrap();
    let Some(mut state) = guard.take() else {
        return Ok(());
    };
    state.stack.stop();
    let result = state.session.shutdown();
    crate::logs::info("engine::tun", "TUN packet capture stopped.", None);
    result
}

pub(crate) fn status_json() -> String {
    if crate::compat::available() {
        return format!(
            r#"{{"enabled":{},"supported":true,"adapter":"LemonVPN","address":"198.18.0.1 / fdfe:dcba:9876::1","udp":"full","ipv6":true,"backend":"mihomo"}}"#,
            crate::compat::tun_active()
        );
    }
    if !supported() {
        return r#"{"enabled":false,"supported":false}"#.to_owned();
    }
    let guard = TUN.lock().unwrap();
    let defaults = TunConfig::default();
    let config = guard
        .as_ref()
        .map(|state| &state.config)
        .unwrap_or(&defaults);
    format!(
        r#"{{"enabled":{},"adapter":"{}","address":"{}","host_address":"{}","udp":"dns_only"}}"#,
        guard.is_some(),
        crate::json::escape(&config.name),
        config.stack_address,
        config.host_address
    )
}

impl Drop for OpenCount {
    fn drop(&mut self) {
        crate::state::connection_closed();
    }
}

// ---------------------------------------------------------------------------
// DNS hijack
// ---------------------------------------------------------------------------

/// Answers one hijacked datagram: parse the query, resolve through the
/// engine, build the reply. Malformed queries are ignored, not answered.
fn serve_dns(core: &Arc<Mutex<StackCore>>, resolve: &Resolve) {
    let request = {
        let mut core = core.lock().unwrap();
        let handle = core.dns;
        let sock = core.sockets.get_mut::<udp::Socket>(handle);
        if !sock.can_recv() {
            return;
        }
        sock.recv().ok().map(|(data, meta)| (data.to_vec(), meta))
    };
    let Some((payload, meta)) = request else {
        return;
    };
    let Some(query) = parse_dns_query(&payload) else {
        return;
    };
    let addrs = resolve(&query.name).unwrap_or_default();
    let reply = build_dns_response(&query, &addrs);
    let mut core = core.lock().unwrap();
    let handle = core.dns;
    let sock = core.sockets.get_mut::<udp::Socket>(handle);
    let _ = sock.send_slice(&reply, meta);
}

struct DnsQuery {
    id: u16,
    name: String,
    qtype: u16,
}

/// Parses the one-question, no-compression queries clients actually send.
fn parse_dns_query(payload: &[u8]) -> Option<DnsQuery> {
    if payload.len() < 12 || payload[2] & 0x80 != 0 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if questions != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = payload.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
        if labels.iter().map(|label| label.len() + 1).sum::<usize>() > 255 {
            return None;
        }
    }
    if pos + 4 > payload.len() || payload[pos + 2] != 0 || payload[pos + 3] != 1 {
        return None;
    }
    Some(DnsQuery {
        id,
        name: labels.join("."),
        qtype: u16::from_be_bytes([payload[pos], payload[pos + 1]]),
    })
}

/// Builds a minimal A/AAAA reply: header, echoed question, one record per
/// resolved address of the asked family, TTL 300. No answers means success
/// with an empty record section.
fn build_dns_response(query: &DnsQuery, addrs: &[IpAddr]) -> Vec<u8> {
    let answers: Vec<&IpAddr> = addrs
        .iter()
        .filter(|addr| match query.qtype {
            1 => addr.is_ipv4(),
            28 => addr.is_ipv6(),
            _ => false,
        })
        .collect();

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in query.name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for addr in answers {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&query.qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        match addr {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn sample_query() -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    #[test]
    fn dns_answer_is_well_formed() {
        let query = parse_dns_query(&sample_query()).expect("query parses");
        assert_eq!(query.name, "www.example.com");
        assert_eq!(query.id, 0x1234);

        let reply = build_dns_response(&query, &[IpAddr::from([1, 2, 3, 4])]);
        assert_eq!(reply[2] & 0x80, 0x80, "response bit set");
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 1, "one question");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer");
        assert!(reply.ends_with(&[0, 4, 1, 2, 3, 4]), "A record payload");

        let empty = build_dns_response(&query, &[]);
        assert_eq!(u16::from_be_bytes([empty[6], empty[7]]), 0, "no answers");
        assert_eq!(empty[2] & 0x80, 0x80, "still a response");
    }

    /// A client-side smoltcp interface wired to the stack over the same
    /// channels a real adapter would use: TCP through the relay to a local
    /// echo server, then a DNS query through the hijack.
    fn run_client(to_stack: Sender<Vec<u8>>, from_stack: Receiver<Vec<u8>>) -> io::Result<()> {
        let started = Instant::now();
        let now = || SmolInstant::from_millis(started.elapsed().as_millis() as i64);
        let deadline = || started.elapsed() < Duration::from_secs(15);

        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut NullDevice,
            now(),
        );
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(10, 111, 0, 2)),
                30,
            ));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 111, 0, 1));
        let mut device = TunDevice {
            rx: VecDeque::new(),
            tx: to_stack,
        };
        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(new_tcp_socket());
        let udp_handle = sockets.add(new_udp_socket());
        sockets
            .get_mut::<udp::Socket>(udp_handle)
            .bind(IpListenEndpoint {
                addr: None,
                port: 51000,
            })
            .map_err(|err| io::Error::other(format!("udp bind: {err:?}")))?;

        let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)), 80);
        sockets
            .get_mut::<tcp::Socket>(tcp_handle)
            .connect(
                iface.context(),
                remote,
                IpListenEndpoint {
                    addr: None,
                    port: 40000,
                },
            )
            .map_err(|err| io::Error::other(format!("connect: {err:?}")))?;

        loop {
            if !deadline() {
                return Err(io::Error::other("TCP 握手超时"));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            let open = {
                let sock = sockets.get_mut::<tcp::Socket>(tcp_handle);
                sock.may_send() && sock.may_recv()
            };
            if open {
                break;
            }
            thread::sleep(POLL_IDLE);
        }

        loop {
            if !deadline() {
                return Err(io::Error::other("发送超时"));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            let sent = sockets
                .get_mut::<tcp::Socket>(tcp_handle)
                .send_slice(b"hello")
                .map_err(|err| io::Error::other(format!("send: {err:?}")))?;
            if sent == 5 {
                break;
            }
            thread::sleep(POLL_IDLE);
        }

        let mut echoed = Vec::new();
        loop {
            if !deadline() {
                return Err(io::Error::other(format!("回声超时：{echoed:?}")));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            let mut buf = [0u8; 16];
            let result = sockets
                .get_mut::<tcp::Socket>(tcp_handle)
                .recv_slice(&mut buf);
            match result {
                Ok(n) => echoed.extend_from_slice(&buf[..n]),
                Err(tcp::RecvError::Finished) => break,
                Err(_) => {}
            }
            if echoed == b"hello" {
                break;
            }
            thread::sleep(POLL_IDLE);
        }
        assert_eq!(echoed, b"hello", "echoed payload");

        sockets.get_mut::<tcp::Socket>(tcp_handle).close();
        loop {
            if !deadline() {
                return Err(io::Error::other("关闭超时"));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            // Both directions drained means the server's FIN has been seen.
            let drained = {
                let sock = sockets.get_mut::<tcp::Socket>(tcp_handle);
                !sock.may_send() && !sock.may_recv()
            };
            if drained {
                break;
            }
            thread::sleep(POLL_IDLE);
        }

        // DNS through the hijack: query (8.8.8.8, 53), expect the stub
        // resolver's answer for it.
        let query = sample_query();
        loop {
            if !deadline() {
                return Err(io::Error::other("DNS 发送超时"));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            let sent = sockets
                .get_mut::<udp::Socket>(udp_handle)
                .send_slice(
                    &query,
                    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)), 53),
                )
                .map_err(|err| io::Error::other(format!("dns send: {err:?}")));
            if sent.is_ok() {
                break;
            }
            thread::sleep(POLL_IDLE);
        }
        let reply = loop {
            if !deadline() {
                return Err(io::Error::other("DNS 回复超时"));
            }
            pump_client(&mut iface, &mut device, &from_stack, &mut sockets, now());
            let received = {
                let sock = sockets.get_mut::<udp::Socket>(udp_handle);
                if sock.can_recv() {
                    sock.recv().ok().map(|(data, _)| data.to_vec())
                } else {
                    None
                }
            };
            if let Some(reply) = received {
                break reply;
            }
            thread::sleep(POLL_IDLE);
        };
        assert_eq!(reply[2] & 0x80, 0x80, "DNS response bit");
        assert_eq!(&reply[..2], &[0x12, 0x34], "query id echoed");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer");
        assert!(
            reply.ends_with(&[0, 4, 203, 0, 113, 7]),
            "stub resolver's address"
        );
        Ok(())
    }

    /// One client-side pump step: pull inbound packets off the channel,
    /// then drive smoltcp once.
    fn pump_client(
        iface: &mut Interface,
        device: &mut TunDevice,
        inbound: &Receiver<Vec<u8>>,
        sockets: &mut SocketSet<'static>,
        now: SmolInstant,
    ) {
        while let Ok(packet) = inbound.try_recv() {
            device.rx.push_back(packet);
        }
        iface.poll(now, device, sockets);
    }

    #[test]
    fn syn_destination_ports_are_parsed() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&[10, 111, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 2, 3, 4]);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());
        packet[20 + 13] = 0x02; // bare SYN
        assert_eq!(syn_dst_port(&packet), Some(80));

        packet[20 + 13] = 0x12; // SYN+ACK
        assert_eq!(syn_dst_port(&packet), None);
        packet[20 + 13] = 0x10; // pure ACK
        assert_eq!(syn_dst_port(&packet), None);
        packet[9] = 17; // UDP
        packet[20 + 13] = 0x02;
        assert_eq!(syn_dst_port(&packet), None);
        packet[0] = 0x65; // IHL 6 with no bytes to back it
        packet[9] = 6;
        assert_eq!(syn_dst_port(&packet), None);
    }

    #[test]
    fn stack_relays_tcp_and_answers_dns() {
        // Local echo server the test dial points every flow at.
        let listener = TcpListener::bind("127.0.0.1:0").expect("echo listener");
        let echo_addr = listener.local_addr().expect("echo addr");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                thread::spawn(move || {
                    let Ok(mut dup) = stream.try_clone() else {
                        return;
                    };
                    let _ = io::copy(&mut stream, &mut dup);
                });
            }
        });

        let (to_stack, stack_in) = mpsc::channel::<Vec<u8>>();
        let (stack_out, from_stack) = mpsc::channel::<Vec<u8>>();
        let dial: Dial = Arc::new(move |_: &str, _: u16, _: &crate::config::Decision| {
            TcpStream::connect(echo_addr)
        });
        let resolve: Resolve = Arc::new(|_: &str| Ok(vec![IpAddr::from([203, 0, 113, 7])]));
        let stack = Stack::start(stack_in, stack_out, dial, resolve, &TunConfig::default());

        let client = thread::spawn(move || run_client(to_stack, from_stack));
        let outcome = client.join().expect("client harness panicked");
        let flows = stack.core.lock().unwrap().flows;
        stack.stop();
        outcome.expect("client flow");
        assert_eq!(flows, 0, "flow bookkeeping balanced");
    }
}
