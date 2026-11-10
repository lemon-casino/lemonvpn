//! Host integration for the shared engine. This crate never depends on engine
//! protocols, configuration, logging or the desktop shell.
//!
//! Desktop hosts use the native backend. A future mobile VPN service can install
//! its own backend before starting the engine, supply packet channels, and
//! protect outbound sockets using the operating system's VPN APIs.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

mod memory;
pub mod lan;
pub mod dns_artifact;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod egress;

/// Packet addressing agreed between the host adapter and the user-space stack.
#[derive(Clone, Debug)]
pub struct TunConfig {
    pub name: String,
    pub stack_address: Ipv4Addr,
    pub host_address: Ipv4Addr,
    pub prefix_len: u8,
    /// Destinations captured by the host. Desktop defaults shadow the IPv4
    /// default route; an embedded host or smoke test can select narrower routes.
    pub routes: Vec<Ipv4Route>,
}

#[derive(Clone, Debug)]
pub struct Ipv4Route {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "LemonVPN".to_owned(),
            stack_address: Ipv4Addr::new(10, 111, 0, 1),
            host_address: Ipv4Addr::new(10, 111, 0, 2),
            prefix_len: 30,
            routes: vec![
                Ipv4Route {
                    network: Ipv4Addr::new(0, 0, 0, 0),
                    prefix_len: 1,
                },
                Ipv4Route {
                    network: Ipv4Addr::new(128, 0, 0, 0),
                    prefix_len: 1,
                },
            ],
        }
    }
}

impl TunConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.prefix_len == 0
            || self.prefix_len > 30
            || self.stack_address == self.host_address
            || self.routes.iter().any(|route| route.prefix_len > 32)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN 地址和前缀无效",
            ));
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        if u32::from(self.stack_address) & mask != u32::from(self.host_address) & mask {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN 主机和协议栈必须位于同一子网",
            ));
        }
        Ok(())
    }
}

/// Owns the adapter and any routing changes. Implementations must also clean up
/// on Drop, including failures after only part of the setup has succeeded.
pub trait TunSession: Send {
    fn shutdown(&mut self) -> io::Result<()>;
}

/// Packet I/O is independent of handles, file descriptors and Apple packetFlow.
pub struct OpenedTun {
    pub incoming: Receiver<Vec<u8>>,
    pub outgoing: Sender<Vec<u8>>,
    pub session: Box<dyn TunSession>,
}

#[derive(Clone, Debug, Default)]
pub struct MemorySnapshot {
    pub resident_bytes: Option<u64>,
    pub peak_resident_bytes: Option<u64>,
    /// Private committed bytes, distinct from resident working-set memory.
    pub private_bytes: Option<u64>,
    pub system_total_bytes: Option<u64>,
    pub system_available_bytes: Option<u64>,
    pub system_used_percent: Option<u32>,
}

pub trait Platform: Send + Sync {
    /// Protect DNS/QUIC sockets while an auxiliary core owns capture routes.
    fn external_tun(&self, _enabled: bool) -> io::Result<()> { Ok(()) }
    /// Called for all external TCP sockets, including DNS and node probes.
    fn connect_tcp(&self, address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&address, timeout)
    }

    /// Called for external UDP sockets, including DNS and QUIC transports.
    fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        UdpSocket::bind(local)
    }

    fn tun_supported(&self) -> bool {
        false
    }

    fn open_tun(&self, _config: &TunConfig) -> io::Result<OpenedTun> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "当前平台尚未提供 TUN 适配器",
        ))
    }

    fn resident_memory_bytes(&self) -> Option<u64> {
        None
    }

    fn memory_snapshot(&self) -> MemorySnapshot {
        MemorySnapshot { resident_bytes: self.resident_memory_bytes(), ..MemorySnapshot::default() }
    }

    fn default_data_dir(&self) -> PathBuf {
        default_data_dir()
    }
}

/// TCP/UDP support without a system TUN adapter. Also useful to embedded hosts
/// that implement just the platform methods they need.
pub struct PortablePlatform;
impl Platform for PortablePlatform {}

struct NativePlatform;

impl Platform for NativePlatform {
    fn external_tun(&self, enabled: bool) -> io::Result<()> {
        #[cfg(windows)] { windows::external_tun(enabled) }
        #[cfg(target_os = "macos")] { darwin::external_tun(enabled) }
        #[cfg(target_os = "linux")] { linux::external_tun(enabled) }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))] { let _=enabled; Ok(()) }
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn connect_tcp(&self, address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        #[cfg(windows)] { windows::connect_tcp(address, timeout) }
        #[cfg(target_os = "macos")] { darwin::connect_tcp(address, timeout) }
        #[cfg(target_os = "linux")] { linux::connect_tcp(address, timeout) }
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        #[cfg(windows)] { windows::bind_udp(local) }
        #[cfg(target_os = "macos")] { darwin::bind_udp(local) }
        #[cfg(target_os = "linux")] { linux::bind_udp(local) }
    }

    fn tun_supported(&self) -> bool {
        #[cfg(target_os = "linux")]
        { return linux::supported(); }
        #[cfg(not(target_os = "linux"))]
        { cfg!(any(windows, target_os = "macos")) }
    }

    #[cfg(windows)]
    fn open_tun(&self, config: &TunConfig) -> io::Result<OpenedTun> {
        windows::open_tun(config)
    }

    fn resident_memory_bytes(&self) -> Option<u64> {
        memory::resident_bytes()
    }

    fn memory_snapshot(&self) -> MemorySnapshot {
        memory::snapshot()
    }
}

static PLATFORM: OnceLock<Arc<dyn Platform>> = OnceLock::new();

/// Install once, before any engine API or socket is used. The backend stays
/// alive for the process; there is one engine configuration per process.
pub fn install(platform: Arc<dyn Platform>) -> io::Result<()> {
    PLATFORM
        .set(platform)
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "平台后端已初始化"))
}

pub fn current() -> &'static dyn Platform {
    PLATFORM.get_or_init(|| Arc::new(NativePlatform)).as_ref()
}

pub(crate) fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("LemonVPN");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/LemonVPN");
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config).join("lemonvpn");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config/lemonvpn");
    }
    PathBuf::from(".")
}
pub mod system_proxy;
pub mod managed;
pub mod tun_bridge;
pub mod dns_settings;
#[cfg(windows)]
pub mod kernel_windows;
pub mod process;
#[cfg(unix)]
pub mod desktop_activation;
#[cfg(windows)]
pub mod service;
#[cfg(target_os = "macos")]
pub mod service_macos;
#[cfg(target_os = "linux")]
pub mod service_linux;
#[cfg(target_os="linux")]
mod linux_service_manager;
#[cfg(target_os="linux")]
pub mod privilege_linux;
#[cfg(target_os="linux")]
mod session_proxy_linux;
#[cfg(target_os = "linux")]
pub mod autostart_linux;
#[cfg(windows)]
pub mod parent;
