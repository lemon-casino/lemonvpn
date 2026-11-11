//! Windows adapter, routing and physical-network socket backend.
use crate::{OpenedTun, TunConfig, TunSession};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetUnicastIpAddressEntry, GAA_FLAG_INCLUDE_GATEWAYS,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_TUNNEL,
    IP_ADAPTER_ADDRESSES_LH, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{IpDadStateDuplicate, IpDadStatePreferred, AF_INET};

const ADAPTER_NAME: &str = "LemonVPN";
const RING_CAPACITY: u32 = 0x400_000;
const HIDE_WINDOW: u32 = 0x0800_0000;
const POLL_IDLE: Duration = Duration::from_millis(1);

#[link(name = "ws2_32")]
extern "system" {
    fn setsockopt(
        socket: usize,
        level: i32,
        option_name: i32,
        option_value: *const u8,
        option_len: i32,
    ) -> i32;
}

const IPPROTO_IP: i32 = 0;
/// Binds a socket's unicast traffic to one interface; per MSDN the index is
/// passed in network byte order.
const IP_UNICAST_IF: i32 = 31;

/// The interface the engine's own traffic must use while TUN mode is on:
/// resolved before the TUN routes exist, cleared again on disable.
static PHYSICAL: AtomicU32 = AtomicU32::new(0);
static LAST_PHYSICAL_CHECK: Mutex<Option<Instant>> = Mutex::new(None);

pub(crate) fn external_tun(enabled:bool) -> io::Result<()> {
    let index=if enabled {probe_physical_index()?} else {0};
    PHYSICAL.store(index,Ordering::Relaxed);
    *LAST_PHYSICAL_CHECK.lock().unwrap()=None;
    Ok(())
}

/// Re-evaluate the uplink for new connections after network changes/resume.
/// If the network disappears, fail explicitly instead of dialing unbound into
/// our own capture routes. Existing sockets reconnect through their protocol.
fn physical_index() -> io::Result<u32> {
    if PHYSICAL.load(Ordering::Relaxed) == 0 {
        return Ok(0);
    }
    let mut last = LAST_PHYSICAL_CHECK.lock().unwrap();
    let current = PHYSICAL.load(Ordering::Relaxed);
    if current == 0 {
        return Ok(0);
    }
    if last.is_some_and(|time| time.elapsed() < Duration::from_secs(1)) {
        return Ok(current);
    }
    let index = probe_physical_index().map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!("物理网络不可用：{error}"),
        )
    })?;
    // Teardown may have completed while adapters were being enumerated.
    if PHYSICAL.load(Ordering::Relaxed) == 0 {
        return Ok(0);
    }
    PHYSICAL.store(index, Ordering::Relaxed);
    *last = Some(Instant::now());
    Ok(index)
}

/// Picks the real NIC to leave through. `GetBestInterface` is not enough: a
/// leftover VPN adapter can own the default route, and binding the engine's
/// sockets to it would loop every outbound connection back into a tunnel.
/// Tunnels (including other wintun adapters) are therefore never candidates.
fn probe_physical_index() -> io::Result<u32> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    // u64 words keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buffer = vec![0u64; size as usize / 8];
    for _ in 0..3 {
        let rc = unsafe {
            GetAdaptersAddresses(
                0,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buffer.resize(size as usize / 8 + 1, 0);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut best: Option<(u32, u32)> = None;
        let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let description = wide_string(adapter.Description);
            let friendly = wide_string(adapter.FriendlyName);
            let tunnel = adapter.IfType == IF_TYPE_TUNNEL
                || description.to_ascii_lowercase().contains("wintun")
                || friendly.eq_ignore_ascii_case(ADAPTER_NAME);
            let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let index = if index==0 {adapter.Ipv6IfIndex} else {index};
            if adapter.OperStatus == IfOperStatusUp
                && !tunnel
                // Wintun adapters carry no MAC; this keeps other VPNs' TUNs
                // out even when their description does not name the driver.
                && adapter.PhysicalAddressLength > 0
                && !adapter.FirstGatewayAddress.is_null()
                && index != 0
                && best.map_or(true, |(metric, _)| adapter.Ipv4Metric < metric)
            {
                best = Some((adapter.Ipv4Metric, index));
            }
            current = adapter.Next;
        }
        return best
            .map(|(_, index)| index)
            .ok_or_else(|| io::Error::other("没有可用的物理网卡"));
    }
    Err(io::Error::other("枚举网卡失败：缓冲区不足"))
}

fn wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut length = 0;
    while unsafe { *ptr.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, length) })
}

pub(crate) fn uplink_name() -> io::Result<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias};
    let index = probe_physical_index()?;
    let mut luid = unsafe { std::mem::zeroed() };
    let mut alias = [0u16; 257];
    let rc = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    if rc != 0 { return Err(io::Error::from_raw_os_error(rc as i32)); }
    let rc = unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) };
    if rc != 0 { return Err(io::Error::from_raw_os_error(rc as i32)); }
    Ok(wide_string(alias.as_ptr()))
}

fn set_unicast_if(socket: &socket2::Socket, index: u32, ipv6:bool) -> io::Result<()> {
    let iface = if ipv6 {index} else {index.to_be()};
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            if ipv6 {41} else {IPPROTO_IP},
            IP_UNICAST_IF,
            (&iface as *const u32).cast(),
            4,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens `addr` with an `IP_UNICAST_IF` binding while TUN mode is on, so the
/// engine's outbound traffic uses the physical interface. Plain connect when
/// TUN is off.
pub(crate) fn connect_tcp(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    if addr.ip().is_loopback() {
        return TcpStream::connect_timeout(&addr, timeout);
    }
    let index = physical_index()?;
    if index == 0 {
        return TcpStream::connect_timeout(&addr, timeout);
    }
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    set_unicast_if(&socket, index,addr.is_ipv6())?;
    let local:SocketAddr=if addr.is_ipv6(){"[::]:0".parse().unwrap()}else{"0.0.0.0:0".parse().unwrap()};
    socket.bind(&local.into())?;
    // `connect_timeout` performs the async connect and waits for writability
    // via poll, so the returned socket is genuinely connected (a hand-rolled
    // non-blocking connect that breaks on `SO_ERROR == 0` exits early and
    // leaves the socket mid-handshake, yielding WSAENOTCONN on recv).
    socket.connect_timeout(&addr.into(), timeout)?;
    Ok(TcpStream::from(socket))
}

/// Binds a UDP socket on the physical interface while TUN mode is on.
/// IPv6 is left alone: the TUN routes are IPv4-only.
pub(crate) fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    if local.ip().is_loopback() {
        return UdpSocket::bind(local);
    }
    let index = physical_index()?;
    if index == 0 {
        return UdpSocket::bind(local);
    }
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    set_unicast_if(&socket, index,local.is_ipv6())?;
    socket.bind(&local.into())?;
    Ok(UdpSocket::from(socket))
}

/// RAII owns only routes successfully installed by this adapter. A failure on
/// the second route also rolls back the first, instead of leaving half a VPN.
struct Routes {
    gateway: Ipv4Addr,
    index: u32,
    installed: Vec<(String, String)>,
}

impl Routes {
    fn install(&mut self, routes: &[crate::Ipv4Route]) -> io::Result<()> {
        for route in routes {
            let network = route.network.to_string();
            let mask = Ipv4Addr::from(
                u32::MAX
                    .checked_shl(32 - u32::from(route.prefix_len))
                    .unwrap_or(0),
            )
            .to_string();
            let out = run_route(&[
                "add",
                &network,
                "mask",
                &mask,
                &self.gateway.to_string(),
                "metric",
                "1",
                "if",
                &self.index.to_string(),
            ])?;
            if !out.status.success() {
                let detail = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                return Err(io::Error::other(format!(
                    "route add {network} 失败：{}",
                    detail.trim()
                )));
            }
            self.installed.push((network, mask));
        }
        Ok(())
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        for (network, mask) in self.installed.drain(..).rev() {
            let _ = run_route(&[
                "delete",
                &network,
                "mask",
                &mask,
                &self.gateway.to_string(),
                "if",
                &self.index.to_string(),
            ]);
        }
    }
}

/// A core killed inside the service's job object never runs its own teardown.
/// Remove the shadow default routes and interface DNS that belong to the stale
/// adapter, otherwise traffic stays trapped while TUN reports off. The adapter
/// is left in place: the next core reuses it, and the driver has no delete API.
pub(crate) fn cleanup_stale() {
    let Ok(wintun) = (unsafe { wintun::load() }) else {
        return;
    };
    let Ok(adapter) = wintun::Adapter::open(&wintun, ADAPTER_NAME) else {
        return;
    };
    let Ok(index) = adapter.get_adapter_index() else {
        return;
    };
    for (network, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let _ = Command::new("route")
            .args(["delete", network, "mask", mask, "if", &index.to_string()])
            .creation_flags(HIDE_WINDOW)
            .output();
    }
    for family in ["ipv4", "ipv6"] {
        let _ = Command::new("netsh")
            .args([
                "interface",
                family,
                "set",
                "dnsservers",
                &format!("name={ADAPTER_NAME}"),
                "source=dhcp",
            ])
            .creation_flags(HIDE_WINDOW)
            .output();
    }
}

struct WindowsTunSession {
    stop: Arc<AtomicBool>,
    session: Option<Arc<wintun::Session>>,
    adapter: Option<Arc<wintun::Adapter>>,
    routes: Option<Routes>,
    threads: Vec<JoinHandle<()>>,
}

impl TunSession for WindowsTunSession {
    fn shutdown(&mut self) -> io::Result<()> {
        if self.adapter.is_none() {
            return Ok(());
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(session) = &self.session {
            let _ = session.shutdown();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        // Restore routing while the adapter still exists, then release the
        // physical-interface binding and driver handles.
        drop(self.routes.take());
        {
            let mut last = LAST_PHYSICAL_CHECK.lock().unwrap();
            PHYSICAL.store(0, Ordering::Relaxed);
            *last = None;
        }
        drop(self.session.take());
        drop(self.adapter.take());
        Ok(())
    }
}

impl Drop for WindowsTunSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

pub(crate) fn open_tun(config: &TunConfig) -> io::Result<OpenedTun> {
    config.validate()?;
    if PHYSICAL.load(Ordering::Relaxed) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "TUN 模式已开启",
        ));
    }
    let physical = probe_physical_index()
        .map_err(|err| io::Error::other(format!("探测物理网卡失败：{err}")))?;
    let wintun = unsafe { wintun::load() }
        .map_err(|err| io::Error::other(format!("加载 wintun.dll 失败（需随引擎分发）：{err}")))?;
    let adapter = wintun::Adapter::create(&wintun, &config.name, &config.name, None)
        .map_err(|err| io::Error::other(format!("创建 TUN 适配器失败（需要管理员权限）：{err}")))?;
    let mask = Ipv4Addr::from(u32::MAX << (32 - config.prefix_len));
    adapter
        .set_network_addresses_tuple(
            IpAddr::from(config.host_address),
            IpAddr::from(mask),
            // Only explicitly requested capture routes belong to this session;
            // configuring a gateway here would also create a default route.
            None,
        )
        .map_err(|err| io::Error::other(format!("配置 TUN 地址失败：{err}")))?;
    let index = adapter
        .get_adapter_index()
        .map_err(|err| io::Error::other(format!("读取 TUN 接口索引失败：{err}")))?;
    let session = Arc::new(
        adapter
            .start_session(RING_CAPACITY)
            .map_err(|err| io::Error::other(format!("打开 TUN 会话失败：{err}")))?,
    );
    wait_for_address(index, config.host_address)?;
    let stop = Arc::new(AtomicBool::new(false));
    let mut owner = WindowsTunSession {
        stop: Arc::clone(&stop),
        session: Some(Arc::clone(&session)),
        adapter: Some(adapter),
        routes: Some(Routes {
            gateway: config.stack_address,
            index,
            installed: Vec::new(),
        }),
        threads: Vec::new(),
    };
    {
        let mut last = LAST_PHYSICAL_CHECK.lock().unwrap();
        PHYSICAL.store(physical, Ordering::Relaxed);
        *last = Some(Instant::now());
    }
    // A failure here drops owner, rolling back routes and all driver state.
    owner.routes.as_mut().unwrap().install(&config.routes)?;
    let (to_stack, incoming) = mpsc::channel();
    let (outgoing, from_stack) = mpsc::channel::<Vec<u8>>();
    owner.threads.push(thread::spawn({
        let session = Arc::clone(&session);
        let stop = Arc::clone(&stop);
        move || {
            while !stop.load(Ordering::Relaxed) {
                match session.try_receive() {
                    Ok(Some(packet)) => {
                        if to_stack.send(packet.bytes().to_vec()).is_err() {
                            break;
                        }
                    }
                    Ok(None) => thread::sleep(POLL_IDLE),
                    Err(_) => break,
                }
            }
        }
    }));
    owner.threads.push(thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match from_stack.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => {
                    if let Ok(length) = u16::try_from(packet.len()) {
                        if let Ok(mut out) = session.allocate_send_packet(length) {
                            out.bytes_mut().copy_from_slice(&packet);
                            session.send_packet(out);
                        }
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }));
    Ok(OpenedTun {
        incoming,
        outgoing,
        session: Box::new(owner),
    })
}

fn run_route(args: &[&str]) -> io::Result<std::process::Output> {
    Command::new("route")
        .args(args)
        .creation_flags(HIDE_WINDOW)
        .output()
}

/// netsh returns before IPv4 duplicate-address detection completes. Publishing
/// capture routes too early makes Windows choose another adapter's source IP;
/// the SYN-ACK then arrives on the wrong interface and the handshake stalls.
fn wait_for_address(index: u32, address: Ipv4Addr) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = index;
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        let result = unsafe { GetUnicastIpAddressEntry(&mut row) };
        if result == 0 && row.DadState == IpDadStatePreferred && row.SkipAsSource == 0 {
            return Ok(());
        }
        if result == 0 && row.DadState == IpDadStateDuplicate {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "TUN 地址发生冲突"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "等待 TUN 地址就绪超时",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}
