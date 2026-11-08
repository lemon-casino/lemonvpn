//! Desktop serialization wrapper for platform-owned system proxy settings.
use lemonvpn_engine_platform::system_proxy;
pub use system_proxy::{disable_for, enable, recover_stale};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub server: Option<String>,
    pub error: Option<String>,
}

pub fn status() -> ProxyStatus {
    let status = system_proxy::status();
    ProxyStatus {
        enabled: status.enabled,
        server: status.server,
        error: status.error,
    }
}
