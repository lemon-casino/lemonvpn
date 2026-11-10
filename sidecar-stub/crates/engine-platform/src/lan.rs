//! Local interface enumeration only; never opens a connection or changes routes.
use serde::Serialize;
use std::{io, net::Ipv4Addr};

#[derive(Clone, Serialize)]
pub struct Address {
    pub interface: String,
    pub address: Ipv4Addr,
}

pub fn addresses() -> io::Result<Vec<Address>> {
    let mut addresses = enumerate()?;
    addresses.retain(|entry| entry.address.is_private());
    addresses.sort_by_key(|entry| (entry.address, entry.interface.clone()));
    addresses.dedup_by_key(|entry| entry.address);
    Ok(addresses)
}

#[cfg(windows)]
fn enumerate() -> io::Result<Vec<Address>> {
    use windows_sys::Win32::{
        Foundation::ERROR_BUFFER_OVERFLOW,
        NetworkManagement::{
            IpHelper::{
                GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
                GAA_FLAG_SKIP_MULTICAST, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, SOCKADDR_IN},
    };
    let mut size = 16384u32;
    let mut buffer = vec![0u64; size as usize / 8];
    for _ in 0..3 {
        let result = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            buffer.resize(size as usize / 8 + 1, 0);
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let mut output = Vec::new();
        let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let name = wide(adapter.FriendlyName);
            let tunnel = adapter.IfType == IF_TYPE_TUNNEL
                || name.eq_ignore_ascii_case("LemonVPN")
                || wide(adapter.Description)
                    .to_ascii_lowercase()
                    .contains("wintun");
            if adapter.OperStatus == IfOperStatusUp && !tunnel {
                let mut unicast = adapter.FirstUnicastAddress;
                while !unicast.is_null() {
                    let entry = unsafe { &*unicast };
                    let socket = entry.Address;
                    if !socket.lpSockaddr.is_null()
                        && socket.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>()
                        && unsafe { (*socket.lpSockaddr).sa_family } == AF_INET
                    {
                        let address = unsafe { &*socket.lpSockaddr.cast::<SOCKADDR_IN>() };
                        let ip =
                            Ipv4Addr::from(unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes());
                        output.push(Address {
                            interface: name.clone(),
                            address: ip,
                        });
                    }
                    unicast = entry.Next;
                }
            }
            current = adapter.Next;
        }
        return Ok(output);
    }
    Err(io::Error::other("无法读取局域网网卡地址"))
}

#[cfg(windows)]
fn wide(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *pointer.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, len) })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn enumerate() -> io::Result<Vec<Address>> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let _list = List(head);
    let mut output = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let entry = unsafe { &*current };
        let skip = (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) as u32;
        if entry.ifa_flags & libc::IFF_UP as u32 != 0
            && entry.ifa_flags & skip == 0
            && !entry.ifa_addr.is_null()
            && !entry.ifa_name.is_null()
            && unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if !name.to_ascii_lowercase().starts_with("tun")
                && !name.eq_ignore_ascii_case("LemonVPN")
            {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                output.push(Address {
                    interface: name,
                    address: Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                });
            }
        }
        current = entry.ifa_next;
    }
    Ok(output)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn enumerate() -> io::Result<Vec<Address>> {
    Ok(Vec::new())
}
