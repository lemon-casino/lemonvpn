//! macOS egress protection: while the privileged TUN service owns the capture
//! routes, the engine's own sockets are pinned to the physical uplink with
//! IP_BOUND_IF, the same contract as the Windows IP_UNICAST_IF path.
use socket2::Socket;
use std::{
    ffi::CString,
    io,
    net::{SocketAddr, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    process::Command,
    sync::{
        atomic::{AtomicU32, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

const IPPROTO_IP: i32 = 0;
const IP_BOUND_IF: i32 = 25;
const IPPROTO_IPV6: i32 = 41;
const IPV6_BOUND_IF: i32 = 125;

extern "C" {
    fn setsockopt(
        socket: i32,
        level: i32,
        option_name: i32,
        option_value: *const core::ffi::c_void,
        option_len: u32,
    ) -> i32;
    fn if_nametoindex(name: *const core::ffi::c_char) -> u32;
}

/// The interface the engine's own traffic must use while TUN mode is on:
/// resolved before the TUN routes exist, cleared again on disable.
static PHYSICAL: AtomicU32 = AtomicU32::new(0);
static LAST_PHYSICAL_CHECK: Mutex<Option<Instant>> = Mutex::new(None);

pub(crate) fn external_tun(enabled: bool) -> io::Result<()> {
    let index = if enabled { probe_physical_index()? } else { 0 };
    PHYSICAL.store(index, Ordering::Relaxed);
    *LAST_PHYSICAL_CHECK.lock().unwrap() = None;
    Ok(())
}

/// Re-evaluate the uplink for new connections after network changes. If the
/// network disappears, fail explicitly instead of dialing unbound into our own
/// capture routes. Existing sockets reconnect through their protocol.
fn physical_index() -> io::Result<u32> {
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
    PHYSICAL.store(index, Ordering::Relaxed);
    *last = Some(Instant::now());
    Ok(index)
}

/// The kernel's own default-route interface; the service's split routes never
/// replace the default entry, so this stays valid while TUN is active.
/// The kernel's own default-route interface; the service's split routes never
/// replace the default entry, so this stays valid while TUN is active.
fn default_route_interface() -> io::Result<String> {
    let output = Command::new("/sbin/route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("没有默认路由"));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.trim_start().starts_with("interface:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, name)| name.trim().to_owned())
        .ok_or_else(|| io::Error::other("无法解析默认网卡"))
}

fn probe_physical_index() -> io::Result<u32> {
    let interface = default_route_interface()?;
    let name = CString::new(interface).map_err(|_| io::Error::other("网卡名称无效"))?;
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::other("默认网卡不存在"));
    }
    Ok(index)
}

/// Interface name for auxiliary cores that bind their own outbound sockets.
pub(crate) fn uplink_name() -> Option<String> {
    default_route_interface().ok()
}

fn set_bound_if(socket: &Socket, index: u32, ipv6: bool) -> io::Result<()> {
    let rc = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP },
            if ipv6 { IPV6_BOUND_IF } else { IP_BOUND_IF },
            (&index as *const u32).cast(),
            4,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens `addr` with an `IP_BOUND_IF` pin while TUN mode is on, so the
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
    let socket = Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    set_bound_if(&socket, index, addr.is_ipv6())?;
    let local: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    socket.bind(&local.into())?;
    socket.connect_timeout(&addr.into(), timeout)?;
    Ok(TcpStream::from(socket))
}

/// Binds a UDP socket on the physical interface while TUN mode is on. IPv6
/// matters here: the macOS service routes capture both families.
pub(crate) fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    if local.ip().is_loopback() {
        return UdpSocket::bind(local);
    }
    let index = physical_index()?;
    if index == 0 {
        return UdpSocket::bind(local);
    }
    let socket = Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    set_bound_if(&socket, index, local.is_ipv6())?;
    socket.bind(&local.into())?;
    Ok(UdpSocket::from(socket))
}
