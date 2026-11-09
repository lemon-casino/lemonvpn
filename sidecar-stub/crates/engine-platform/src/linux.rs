//! Bind only our own newly-created sockets. Linux >=5.7 permits initial
//! SO_BINDTODEVICE on an unbound socket without granting capabilities to the app.
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
static CAPTURE: AtomicBool = AtomicBool::new(false);

pub(crate) fn supported() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut parts = release.split('.').filter_map(|p| p.parse::<u32>().ok());
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    (major > 5 || (major == 5 && minor >= 7)) && crate::network::ip_tool().is_ok()
}
pub(crate) fn external_tun(enabled: bool) -> io::Result<()> {
    if enabled {
        if !supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN 需要 Linux 5.7+ 与 iproute2",
            ));
        }
        let state = crate::network::snapshot(true)?;
        if !state.routes.any() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "没有可用物理出口",
            ));
        }
        for route in state.routes.iter() {
            let socket = Socket::new(
                if route.ipv6 {
                    Domain::IPV6
                } else {
                    Domain::IPV4
                },
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            socket.bind_device(Some(route.interface.as_bytes()))?;
        }
    }
    CAPTURE.store(enabled, Ordering::Release);
    Ok(())
}
fn protect(socket: &Socket, ipv6: bool) -> io::Result<()> {
    if CAPTURE.load(Ordering::Acquire) {
        let interface = crate::network::interface(ipv6)?;
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    Ok(())
}
pub(crate) fn connect_tcp(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    if address.ip().is_loopback() {
        return TcpStream::connect_timeout(&address, timeout);
    }
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    protect(&socket, address.is_ipv6())?;
    socket.connect_timeout(&address.into(), timeout)?;
    Ok(socket.into())
}
pub(crate) fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    if !local.ip().is_loopback() {
        protect(&socket, local.is_ipv6())?;
    }
    socket.bind(&local.into())?;
    Ok(socket.into())
}
