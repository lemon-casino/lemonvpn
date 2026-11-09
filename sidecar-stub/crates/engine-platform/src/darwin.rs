//! macOS egress protection: while the privileged TUN service owns the capture
//! routes, the engine's own sockets are pinned to the physical uplink with
//! IP_BOUND_IF, the same contract as the Windows IP_UNICAST_IF path.
use socket2::Socket;
use std::{
    ffi::CString,
    io,
    net::{SocketAddr, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    sync::atomic::Ordering,
    time::Duration,
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

static CAPTURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn external_tun(enabled: bool) -> io::Result<()> {
    if enabled && !crate::network::snapshot(true)?.routes.any() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "没有可用物理出口",
        ));
    }
    CAPTURE.store(enabled, Ordering::Release);
    Ok(())
}
fn physical_index(ipv6: bool) -> io::Result<u32> {
    if !CAPTURE.load(Ordering::Acquire) {
        return Ok(0);
    }
    let name = CString::new(crate::network::interface(ipv6)?)?;
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "出口网卡暂不可用",
        ));
    }
    Ok(index)
}
pub(crate) fn uplink_name() -> Option<String> {
    crate::network::interface(false)
        .or_else(|_| crate::network::interface(true))
        .ok()
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
    let index = physical_index(addr.is_ipv6())?;
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
    let index = physical_index(local.is_ipv6())?;
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
