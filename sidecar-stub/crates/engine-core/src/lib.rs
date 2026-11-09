//! Shared LemonVPN engine: protocols, configuration, API and user-space IP stack.
//!
//! The desktop sidecar is a thin host for this library. Platform-specific device,
//! routing and socket operations belong to `platform`. Embedded hosts can install
//! a backend before startup; no desktop shell or process exit is required here.
//! There is currently one configuration and platform backend per process.

mod api;
mod compat;
mod base64;
mod config;
mod connections;
mod control;
mod crypto;
mod dns;
mod dns_settings;
mod events;
mod fetch;
mod flows;
mod geodata;
mod group_policy;
mod group_filter;
mod http;
mod hysteria2;
mod json;
mod logs;
mod outbound;
mod outbounds;
mod probes;
mod providers;
mod proxy;
mod runtime;
mod sha256;
mod shadowsocks;
mod share;
mod socks5;
mod state;
mod storage;
mod tls;
mod trojan;
mod tun;
mod tunnel;
mod vless;
mod vmess;

pub use lemonvpn_engine_platform as platform;
pub use runtime::{Engine, EngineOptions};
