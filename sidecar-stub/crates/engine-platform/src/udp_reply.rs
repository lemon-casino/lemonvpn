//! Per-datagram destination metadata and reply source selection for LAN servers.
//! No connected socket, interface binding or socket-wide source mutation: workers
//! may reply concurrently to queries addressed to different local interfaces.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

#[derive(Clone, Copy)]
pub struct Received {
    pub len: usize,
    pub peer: SocketAddr,
    destination: IpAddr,
    interface: u32,
}

pub struct Socket {
    socket: UdpSocket,
    #[cfg(windows)]
    receive: windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG,
}

// Control headers and data require native alignment on both 64-bit architectures.
#[repr(C, align(8))]
struct Control([u8; 128]);

fn missing_destination() -> io::Error {
    io::Error::other("UDP 查询缺少目标地址，无法确定回包源地址")
}

impl Socket {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        // Keep IPv4 and IPv6 listeners explicit; an IPv6 wildcard must not
        // silently accept mapped IPv4 peers that bypass the caller's IPv4 ACL.
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.bind(&address.into())?;
        let socket: UdpSocket = socket.into();
        socket.set_nonblocking(true)?;
        Self::configure(socket, address.is_ipv6())
    }
    fn received(
        &self,
        len: usize,
        peer: SocketAddr,
        info: Option<(IpAddr, u32)>,
    ) -> io::Result<Received> {
        // A specifically bound socket has an unambiguous source even if the OS
        // omits ancillary data. Wildcard listeners must never guess.
        let (destination, mut interface) = match info {
            Some(info) => info,
            None => {
                let bound = self.socket.local_addr()?.ip();
                if bound.is_unspecified() {
                    return Err(missing_destination());
                }
                (bound, 0)
            }
        };
        if destination.is_unspecified()
            || destination.is_multicast()
            || matches!(destination, IpAddr::V4(v) if v.is_broadcast())
        {
            return Err(missing_destination());
        }
        // Only link-local IPv6 requires an interface scope. Pinning the ingress
        // interface for global/ULA addresses can reject valid cross-interface
        // requests (e.g. a Docker bridge querying the host's LAN address).
        if matches!(destination, IpAddr::V6(ip) if ip.is_unicast_link_local()) {
            if interface == 0 {
                interface = match peer {
                    SocketAddr::V6(peer) => peer.scope_id(),
                    _ => 0,
                };
            }
            if interface == 0 {
                return Err(missing_destination());
            }
        } else {
            interface = 0;
        }
        Ok(Received {
            len,
            peer,
            destination,
            interface,
        })
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::{mem, os::fd::AsRawFd, ptr};

    impl Socket {
        pub(super) fn configure(socket: UdpSocket, ipv6: bool) -> io::Result<Self> {
            let (level, option) = if ipv6 {
                (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
            } else {
                (libc::IPPROTO_IP, libc::IP_PKTINFO)
            };
            let enabled: libc::c_int = 1;
            // SAFETY: the value points to a live native integer of the stated size.
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    level,
                    option,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as _,
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { socket })
        }

        pub fn recv(&self, bytes: &mut [u8]) -> io::Result<Received> {
            let mut control = Control([0; 128]);
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let ((len, info), peer) = unsafe {
                // SAFETY: SockAddr owns the address buffer; all other pointers
                // reference live buffers for the duration of this synchronous call.
                socket2::SockAddr::try_init(|address, address_len| {
                    let mut message: libc::msghdr = mem::zeroed();
                    message.msg_name = address.cast();
                    message.msg_namelen = *address_len as _;
                    message.msg_iov = &mut iov;
                    message.msg_iovlen = 1;
                    message.msg_control = control.0.as_mut_ptr().cast();
                    message.msg_controllen = control.0.len() as _;
                    let len = libc::recvmsg(self.socket.as_raw_fd(), &mut message, 0);
                    if len < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                        || len as usize > bytes.len()
                        || message.msg_controllen as usize > control.0.len()
                    {
                        return Err(io::Error::other("UDP 数据报或目标地址信息不完整"));
                    }
                    *address_len = message.msg_namelen as _;
                    let mut info = None;
                    let mut header = libc::CMSG_FIRSTHDR(&message);
                    while !header.is_null() {
                        let size = (*header).cmsg_len as usize;
                        if size < libc::CMSG_LEN(0) as usize
                            || (header as usize - message.msg_control as usize) + size
                                > message.msg_controllen as usize
                        {
                            return Err(missing_destination());
                        }
                        match ((*header).cmsg_level, (*header).cmsg_type) {
                            (libc::IPPROTO_IP, libc::IP_PKTINFO)
                                if size
                                    >= libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _)
                                        as usize =>
                            {
                                let value = ptr::read_unaligned(
                                    libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(),
                                );
                                info = Some((
                                    IpAddr::V4(Ipv4Addr::from(value.ipi_addr.s_addr.to_ne_bytes())),
                                    value.ipi_ifindex as u32,
                                ));
                            }
                            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                                if size
                                    >= libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as _)
                                        as usize =>
                            {
                                let value = ptr::read_unaligned(
                                    libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>(),
                                );
                                info = Some((
                                    IpAddr::V6(Ipv6Addr::from(value.ipi6_addr.s6_addr)),
                                    value.ipi6_ifindex,
                                ));
                            }
                            _ => {}
                        }
                        header = libc::CMSG_NXTHDR(&message, header);
                    }
                    Ok((len as usize, info))
                })?
            };
            self.received(len, peer.as_socket().ok_or_else(missing_destination)?, info)
        }

        pub fn send_reply(&self, bytes: &[u8], received: &Received) -> io::Result<()> {
            let peer = socket2::SockAddr::from(received.peer);
            let mut control = Control([0; 128]);
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr() as *mut _,
                iov_len: bytes.len(),
            };
            // SAFETY: all pointers are live/aligned for the synchronous sendmsg;
            // CMSG_* computes the platform-specific header padding and lengths.
            unsafe {
                let mut message: libc::msghdr = mem::zeroed();
                message.msg_name = peer.as_ptr() as *mut _;
                message.msg_namelen = peer.len();
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.0.as_mut_ptr().cast();
                message.msg_controllen = control.0.len() as _;
                let header = libc::CMSG_FIRSTHDR(&message);
                match received.destination {
                    IpAddr::V4(ip) => {
                        let mut value: libc::in_pktinfo = mem::zeroed();
                        // Do not set the IPv4 interface index: macOS gives it
                        // precedence over the exact source, losing address aliases.
                        value.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                        (*header).cmsg_level = libc::IPPROTO_IP;
                        (*header).cmsg_type = libc::IP_PKTINFO;
                        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(&value) as _) as _;
                        ptr::write_unaligned(libc::CMSG_DATA(header).cast(), value);
                        message.msg_controllen =
                            libc::CMSG_SPACE(mem::size_of_val(&value) as _) as _;
                    }
                    IpAddr::V6(ip) => {
                        let value = libc::in6_pktinfo {
                            ipi6_addr: libc::in6_addr {
                                s6_addr: ip.octets(),
                            },
                            ipi6_ifindex: received.interface,
                        };
                        (*header).cmsg_level = libc::IPPROTO_IPV6;
                        (*header).cmsg_type = libc::IPV6_PKTINFO;
                        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(&value) as _) as _;
                        ptr::write_unaligned(libc::CMSG_DATA(header).cast(), value);
                        message.msg_controllen =
                            libc::CMSG_SPACE(mem::size_of_val(&value) as _) as _;
                    }
                }
                let sent = libc::sendmsg(self.socket.as_raw_fd(), &message, 0);
                if sent < 0 {
                    return Err(io::Error::last_os_error());
                }
                if sent as usize != bytes.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{mem, os::windows::io::AsRawSocket, ptr};
    use windows_sys::Win32::Networking::WinSock as w;

    fn error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { w::WSAGetLastError() })
    }
    fn aligned(size: usize) -> usize {
        (size + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1)
    }

    impl Socket {
        pub(super) fn configure(socket: UdpSocket, ipv6: bool) -> io::Result<Self> {
            let (level, option) = if ipv6 {
                (w::IPPROTO_IPV6, w::IPV6_PKTINFO)
            } else {
                (w::IPPROTO_IP, w::IP_PKTINFO)
            };
            let enabled: u32 = 1;
            let mut receive: w::LPFN_WSARECVMSG = None;
            let mut returned = 0;
            unsafe {
                // SAFETY: native values have the exact Winsock sizes; resolve
                // the extension on this socket's provider, never a temporary one.
                if w::setsockopt(
                    socket.as_raw_socket() as _,
                    level,
                    option,
                    (&enabled as *const u32).cast(),
                    mem::size_of_val(&enabled) as _,
                ) != 0
                {
                    return Err(error());
                }
                if w::WSAIoctl(
                    socket.as_raw_socket() as _,
                    w::SIO_GET_EXTENSION_FUNCTION_POINTER,
                    (&w::WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(),
                    mem::size_of_val(&w::WSAID_WSARECVMSG) as _,
                    (&mut receive as *mut w::LPFN_WSARECVMSG).cast(),
                    mem::size_of_val(&receive) as _,
                    &mut returned,
                    ptr::null_mut(),
                    None,
                ) != 0
                {
                    return Err(error());
                }
            }
            if receive.is_none() || returned as usize != mem::size_of_val(&receive) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "网络栈不支持 UDP 目标地址信息",
                ));
            }
            Ok(Self { socket, receive })
        }

        pub fn recv(&self, bytes: &mut [u8]) -> io::Result<Received> {
            let mut control = Control([0; 128]);
            let mut buffer = w::WSABUF {
                len: bytes.len() as _,
                buf: bytes.as_mut_ptr(),
            };
            let ((len, info), peer) = unsafe {
                // SAFETY: address/control/payload buffers live through WSARecvMsg;
                // extension pointer was resolved during successful initialization.
                socket2::SockAddr::try_init(|address, address_len| {
                    let mut message: w::WSAMSG = mem::zeroed();
                    message.name = address.cast();
                    message.namelen = *address_len as _;
                    message.lpBuffers = &mut buffer;
                    message.dwBufferCount = 1;
                    message.Control = w::WSABUF {
                        len: control.0.len() as _,
                        buf: control.0.as_mut_ptr(),
                    };
                    let mut len = 0;
                    if self.receive.unwrap()(
                        self.socket.as_raw_socket() as _,
                        &mut message,
                        &mut len,
                        ptr::null_mut(),
                        None,
                    ) != 0
                    {
                        return Err(error());
                    }
                    if message.dwFlags & (w::MSG_TRUNC | w::MSG_CTRUNC) != 0
                        || len as usize > bytes.len()
                        || message.Control.len as usize > control.0.len()
                    {
                        return Err(io::Error::other("UDP 数据报或目标地址信息不完整"));
                    }
                    *address_len = message.namelen as _;
                    let mut offset = 0;
                    let mut info = None;
                    let header_size = aligned(mem::size_of::<w::CMSGHDR>());
                    while offset + header_size <= message.Control.len as usize {
                        let header = ptr::read_unaligned(
                            control.0.as_ptr().add(offset).cast::<w::CMSGHDR>(),
                        );
                        if header.cmsg_len < header_size
                            || offset + header.cmsg_len > message.Control.len as usize
                        {
                            return Err(missing_destination());
                        }
                        let data = control.0.as_ptr().add(offset + header_size);
                        match (header.cmsg_level, header.cmsg_type) {
                            (w::IPPROTO_IP, w::IP_PKTINFO)
                                if header.cmsg_len
                                    >= header_size + mem::size_of::<w::IN_PKTINFO>() =>
                            {
                                let value = ptr::read_unaligned(data.cast::<w::IN_PKTINFO>());
                                info = Some((
                                    IpAddr::V4(Ipv4Addr::from(
                                        value.ipi_addr.S_un.S_addr.to_ne_bytes(),
                                    )),
                                    value.ipi_ifindex,
                                ));
                            }
                            (w::IPPROTO_IPV6, w::IPV6_PKTINFO)
                                if header.cmsg_len
                                    >= header_size + mem::size_of::<w::IN6_PKTINFO>() =>
                            {
                                let value = ptr::read_unaligned(data.cast::<w::IN6_PKTINFO>());
                                info = Some((
                                    IpAddr::V6(Ipv6Addr::from(value.ipi6_addr.u.Byte)),
                                    value.ipi6_ifindex,
                                ));
                            }
                            _ => {}
                        }
                        offset += aligned(header.cmsg_len);
                    }
                    Ok((len as usize, info))
                })?
            };
            self.received(len, peer.as_socket().ok_or_else(missing_destination)?, info)
        }

        pub fn send_reply(&self, bytes: &[u8], received: &Received) -> io::Result<()> {
            let peer = socket2::SockAddr::from(received.peer);
            let mut control = Control([0; 128]);
            let mut buffer = w::WSABUF {
                len: bytes.len() as _,
                buf: bytes.as_ptr() as *mut _,
            };
            let header_size = aligned(mem::size_of::<w::CMSGHDR>());
            unsafe {
                // SAFETY: source metadata is copied from our own receive result;
                // both buffers remain valid until synchronous WSASendMsg returns.
                let (level, option, size) = match received.destination {
                    IpAddr::V4(ip) => {
                        let value = w::IN_PKTINFO {
                            ipi_addr: w::IN_ADDR {
                                S_un: w::IN_ADDR_0 {
                                    S_addr: u32::from_ne_bytes(ip.octets()),
                                },
                            },
                            ipi_ifindex: 0,
                        };
                        ptr::write_unaligned(control.0.as_mut_ptr().add(header_size).cast(), value);
                        (w::IPPROTO_IP, w::IP_PKTINFO, mem::size_of_val(&value))
                    }
                    IpAddr::V6(ip) => {
                        let value = w::IN6_PKTINFO {
                            ipi6_addr: w::IN6_ADDR {
                                u: w::IN6_ADDR_0 { Byte: ip.octets() },
                            },
                            ipi6_ifindex: received.interface,
                        };
                        ptr::write_unaligned(control.0.as_mut_ptr().add(header_size).cast(), value);
                        (w::IPPROTO_IPV6, w::IPV6_PKTINFO, mem::size_of_val(&value))
                    }
                };
                ptr::write_unaligned(
                    control.0.as_mut_ptr().cast(),
                    w::CMSGHDR {
                        cmsg_len: header_size + size,
                        cmsg_level: level,
                        cmsg_type: option,
                    },
                );
                let mut message: w::WSAMSG = mem::zeroed();
                message.name = peer.as_ptr() as *mut _;
                message.namelen = peer.len();
                message.lpBuffers = &mut buffer;
                message.dwBufferCount = 1;
                message.Control = w::WSABUF {
                    len: (header_size + aligned(size)) as _,
                    buf: control.0.as_mut_ptr(),
                };
                let mut sent = 0;
                if w::WSASendMsg(
                    self.socket.as_raw_socket() as _,
                    &message,
                    0,
                    &mut sent,
                    ptr::null_mut(),
                    None,
                ) != 0
                {
                    return Err(error());
                }
                if sent as usize != bytes.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
            }
            Ok(())
        }
    }
}
