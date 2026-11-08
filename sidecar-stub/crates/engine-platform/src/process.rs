//! Owner metadata for local proxy clients. Ambiguous UDP owners remain unknown.
use std::net::SocketAddr;

#[derive(Clone, Debug, Default)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub path: Option<String>,
}
impl ProcessInfo {
    pub fn selector(value: &str) -> Self {
        let path = value.contains(['/', '\\']).then(|| value.to_owned());
        let name = value.rsplit(['/', '\\']).next().map(str::to_owned);
        Self {
            pid: None,
            name,
            path,
        }
    }
    pub fn matches(&self, value: &str) -> bool {
        let observed = if value.contains(['/', '\\']) {
            self.path.as_deref()
        } else {
            self.name.as_deref()
        };
        observed.is_some_and(|observed| {
            if cfg!(windows) {
                observed
                    .replace('/', "\\")
                    .eq_ignore_ascii_case(&value.replace('/', "\\"))
            } else {
                observed == value
            }
        })
    }
}
pub fn owner(source: SocketAddr, network: &str) -> Option<ProcessInfo> {
    #[cfg(windows)]
    {
        native::owner(source, network)
    }
    #[cfg(not(windows))]
    {
        let _ = (source, network);
        None
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };
    use windows_sys::Win32::{
        Foundation::CloseHandle, NetworkManagement::IpHelper::*, System::Threading::*,
    };
    pub(super) fn owner(source: SocketAddr, network: &str) -> Option<ProcessInfo> {
        let family = if source.is_ipv4() { 2 } else { 23 };
        let mut size = 0u32;
        let tcp = network == "tcp";
        unsafe {
            if tcp {
                GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
            } else {
                GetExtendedUdpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                );
            }
            if size < 4 || size > 16 * 1024 * 1024 {
                return None;
            }
            let mut bytes = vec![0u64; (size as usize).div_ceil(8)];
            let result = if tcp {
                GetExtendedTcpTable(
                    bytes.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    bytes.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };
            if result != 0 {
                return None;
            }
            let count = *(bytes.as_ptr().cast::<u32>()) as usize;
            let data = bytes.as_ptr().cast::<u8>().add(4);
            let mut owners = HashSet::new();
            macro_rules! rows {
                ($ty:ty, $addr:ident, $convert:expr) => {{
                    let stride = std::mem::size_of::<$ty>();
                    if count > (size as usize - 4) / stride {
                        return None;
                    }
                    for index in 0..count {
                        let row = std::ptr::read_unaligned(data.add(index * stride).cast::<$ty>());
                        let ip: IpAddr = ($convert)(row.$addr);
                        if u16::from_be(row.dwLocalPort as u16) == source.port()
                            && (ip == source.ip() || (!tcp && ip.is_unspecified()))
                        {
                            owners.insert(row.dwOwningPid);
                        }
                    }
                }};
            }
            match (tcp, source.is_ipv4()) {
                (true, true) => rows!(MIB_TCPROW_OWNER_PID, dwLocalAddr, |v: u32| Ipv4Addr::from(
                    v.to_ne_bytes()
                )
                .into()),
                (true, false) => rows!(MIB_TCP6ROW_OWNER_PID, ucLocalAddr, |v: [u8; 16]| {
                    Ipv6Addr::from(v).into()
                }),
                (false, true) => rows!(MIB_UDPROW_OWNER_PID, dwLocalAddr, |v: u32| Ipv4Addr::from(
                    v.to_ne_bytes()
                )
                .into()),
                (false, false) => rows!(MIB_UDP6ROW_OWNER_PID, ucLocalAddr, |v: [u8; 16]| {
                    Ipv6Addr::from(v).into()
                }),
            }
            if owners.len() != 1 {
                return None;
            }
            let pid = *owners.iter().next()?;
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == 0 {
                return None;
            }
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            let result = QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length);
            CloseHandle(handle);
            if result == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&path[..length as usize]);
            let mut info = ProcessInfo::selector(&path);
            // An untagged bridge connection belongs to the kernel, not the original app.
            if info
                .name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("lemonvpn-kernel.exe"))
            {
                return None;
            }
            info.pid = Some(pid);
            Some(info)
        }
    }
}
