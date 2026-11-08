//! System proxy switch.
//!
//! The data plane of the system-proxy milestone is the engine's mixed inbound;
//! this module points Windows' per-user WinINet settings at it. The values that
//! were there before the first takeover are saved under `HKCU\Software\LemonVPN`
//! so switching the proxy off restores them instead of leaving the user with a
//! loopback proxy that no longer has an engine behind it.
//!
//! macOS delegates to `networksetup` with the same semantics; Linux
//! (`gsettings`/`kwriteconfig`) is not implemented yet and reports itself as
//! unavailable.

/// What the UI needs to render the switch.
#[derive(Clone, Debug)]
pub struct ProxyStatus {
    /// Whether the system proxy points at this shell's engine.
    pub enabled: bool,
    /// The `host:port` the system proxy currently uses, if readable.
    pub server: Option<String>,
    /// Why the switch cannot be used, or `None` when it can.
    pub error: Option<String>,
}

#[cfg(windows)]
mod imp {
    use super::ProxyStatus;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_support::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_support::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_support::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    };

    const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const OWN_KEY: &str = r"Software\LemonVPN";
    const PROXY_ENABLE: &str = "ProxyEnable";
    const PROXY_SERVER: &str = "ProxyServer";
    const PROXY_OVERRIDE: &str = "ProxyOverride";
    /// `1` once the pre-takeover values below are meaningful.
    const SAVED: &str = "SavedProxy";
    const SAVED_ENABLE: &str = "SavedProxyEnable";
    const SAVED_SERVER: &str = "SavedProxyServer";
    const SAVED_OVERRIDE: &str = "SavedProxyOverride";
    /// The `host:port` this shell last installed; tells our settings from a
    /// user's own.
    const OUR_SERVER: &str = "OurServer";
    const OUR_OWNER: &str = "OurOwnerPid";

    /// Points the system proxy at `server` (`host:port`), remembering whatever
    /// was configured before the first time this runs.
    pub fn enable(server: &str) -> Result<(), String> {
        let settings = RegKey::open(INTERNET_SETTINGS, false)?;
        let own = RegKey::open(OWN_KEY, true)?;
        enable_in(&settings, &own, server)?;
        notify();
        Ok(())
    }

    fn enable_in(settings: &RegKey, own: &RegKey, server: &str) -> Result<(), String> {
        if own.get_dword(SAVED)?.unwrap_or(0) == 0 {
            own.set_dword(SAVED_ENABLE, settings.get_dword(PROXY_ENABLE)?.unwrap_or(0))?;
            save_optional(&own, SAVED_SERVER, settings.get_string(PROXY_SERVER)?)?;
            save_optional(&own, SAVED_OVERRIDE, settings.get_string(PROXY_OVERRIDE)?)?;
            own.set_dword(SAVED, 1)?;
        }

        own.set_string(OUR_SERVER, server)?;
        own.set_dword(OUR_OWNER, std::process::id())?;
        settings.set_string(PROXY_SERVER, server)?;
        // Loopback hosts never go through the proxy; everything else does.
        settings.set_string(PROXY_OVERRIDE, "<local>")?;
        settings.set_dword(PROXY_ENABLE, 1)?;
        Ok(())
    }

    /// Restores the settings saved by [`enable`]. Leaves them alone when the
    /// current proxy server is no longer the one this shell installed — the
    /// user changed it themselves, and their choice wins.
    pub fn disable_for(server: &str) -> Result<(), String> {
        disable_owned(server, std::process::id())
    }

    /// Used by the sidecar watchdog after its desktop parent has exited.
    pub fn disable_owned(server: &str, owner: u32) -> Result<(), String> {
        disable_impl(server, Some(owner))
    }

    fn disable_impl(server: &str, owner: Option<u32>) -> Result<(), String> {
        let Ok(own) = RegKey::open(OWN_KEY, false) else {
            return Ok(());
        };
        if own.get_dword(SAVED)?.unwrap_or(0) == 0 {
            return Ok(());
        }
        let settings = RegKey::open(INTERNET_SETTINGS, false)?;
        if disable_in_owned(&settings, &own, server, owner)? {
            notify();
        }
        Ok(())
    }

    #[cfg(test)]
    fn disable_in(settings: &RegKey, own: &RegKey, server: &str) -> Result<bool, String> {
        disable_in_owned(settings, own, server, Some(std::process::id()))
    }

    fn disable_in_owned(
        settings: &RegKey,
        own: &RegKey,
        server: &str,
        owner: Option<u32>,
    ) -> Result<bool, String> {
        let ours = own.get_string(OUR_SERVER)?.unwrap_or_default();
        if ours != server
            || own.get_dword(SAVED)?.unwrap_or(0) == 0
            || owner.is_some_and(|pid| own.get_dword(OUR_OWNER).ok().flatten() != Some(pid))
        {
            return Ok(false);
        }
        let current = settings.get_string(PROXY_SERVER)?.unwrap_or_default();
        let changed = !ours.is_empty() && current == ours;
        if changed {
            settings.set_dword(PROXY_ENABLE, own.get_dword(SAVED_ENABLE)?.unwrap_or(0))?;
            restore(&settings, PROXY_SERVER, own.get_string(SAVED_SERVER)?)?;
            restore(&settings, PROXY_OVERRIDE, own.get_string(SAVED_OVERRIDE)?)?;
        }

        own.delete(SAVED)?;
        own.delete(SAVED_ENABLE)?;
        own.delete(SAVED_SERVER)?;
        own.delete(SAVED_OVERRIDE)?;
        own.delete(OUR_SERVER)?;
        own.delete(OUR_OWNER)?;
        Ok(changed)
    }

    /// Recover a previous crash only when its recorded loopback server has no
    /// listener. A live instance, unrelated proxy, or unreadable key is left alone.
    pub fn recover_stale() -> Result<(), String> {
        let Ok(own) = RegKey::open(OWN_KEY, false) else {
            return Ok(());
        };
        let Some(server) = own.get_string(OUR_SERVER)? else {
            return Ok(());
        };
        if let Some(owner) = own.get_dword(OUR_OWNER)? {
            if crate::parent::is_running(owner).unwrap_or(true) {
                return Ok(());
            }
        }
        let Ok(address) = server.parse::<std::net::SocketAddr>() else {
            return Ok(());
        };
        if !address.ip().is_loopback()
            || std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(200))
                .is_ok()
        {
            return Ok(());
        }
        disable_impl(&server, None)
    }

    pub fn status() -> ProxyStatus {
        match read_status() {
            Ok((enabled, server)) => ProxyStatus {
                enabled,
                server,
                error: None,
            },
            Err(err) => ProxyStatus {
                enabled: false,
                server: None,
                error: Some(err),
            },
        }
    }

    fn read_status() -> Result<(bool, Option<String>), String> {
        let settings = RegKey::open(INTERNET_SETTINGS, false)?;
        let on = settings.get_dword(PROXY_ENABLE)?.unwrap_or(0) != 0;
        let server = settings.get_string(PROXY_SERVER)?;
        let ours = match RegKey::open(OWN_KEY, false) {
            Ok(own) => own.get_string(OUR_SERVER)?,
            Err(_) => None,
        };
        let enabled = on && server.is_some() && server == ours;
        Ok((enabled, server))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn restore_is_scoped_to_owner_and_preserves_user_changes() {
            // Exercise real registry IO under isolated test keys. Never open
            // Internet Settings or notify WinINet in this test.
            let root = format!(
                r"Software\LemonVPN\StabilityTests\{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let settings = RegKey::open(&format!(r"{root}\settings"), true).unwrap();
            let own = RegKey::open(&format!(r"{root}\owner"), true).unwrap();
            settings.set_dword(PROXY_ENABLE, 0).unwrap();
            settings
                .set_string(PROXY_SERVER, "previous.example:8080")
                .unwrap();
            settings
                .set_string(PROXY_OVERRIDE, "localhost;*.internal")
                .unwrap();
            enable_in(&settings, &own, "127.0.0.1:18080").unwrap();
            enable_in(&settings, &own, "127.0.0.1:18080").unwrap();
            // An unrelated or failed instance may not restore or discard backup.
            assert!(!disable_in(&settings, &own, "127.0.0.1:19090").unwrap());
            // The same port reused by a new process still has another owner.
            assert!(!disable_in_owned(
                &settings,
                &own,
                "127.0.0.1:18080",
                Some(std::process::id() + 1)
            )
            .unwrap());
            assert_eq!(settings.get_dword(PROXY_ENABLE).unwrap(), Some(1));
            assert_eq!(own.get_dword(SAVED).unwrap(), Some(1));
            assert_eq!(
                own.get_string(SAVED_SERVER).unwrap().as_deref(),
                Some("previous.example:8080")
            );
            assert!(disable_in(&settings, &own, "127.0.0.1:18080").unwrap());
            assert_eq!(settings.get_dword(PROXY_ENABLE).unwrap(), Some(0));
            assert_eq!(
                settings.get_string(PROXY_SERVER).unwrap().as_deref(),
                Some("previous.example:8080")
            );
            assert_eq!(
                settings.get_string(PROXY_OVERRIDE).unwrap().as_deref(),
                Some("localhost;*.internal")
            );
            assert_eq!(own.get_dword(SAVED).unwrap(), None);
            assert!(!disable_in(&settings, &own, "127.0.0.1:18080").unwrap());
            // A later manual choice wins even when our original host exits.
            enable_in(&settings, &own, "127.0.0.1:18080").unwrap();
            settings
                .set_string(PROXY_SERVER, "user-choice.example:8888")
                .unwrap();
            assert!(!disable_in(&settings, &own, "127.0.0.1:18080").unwrap());
            assert_eq!(
                settings.get_string(PROXY_SERVER).unwrap().as_deref(),
                Some("user-choice.example:8888")
            );
            assert_eq!(own.get_dword(SAVED).unwrap(), None);
            drop(settings);
            drop(own);
            let root_w = wide(&root);
            assert_eq!(
                unsafe {
                    windows_support::Win32::System::Registry::RegDeleteTreeW(
                        HKEY_CURRENT_USER,
                        root_w.as_ptr(),
                    )
                },
                ERROR_SUCCESS
            );
        }
    }

    fn save_optional(own: &RegKey, name: &str, previous: Option<String>) -> Result<(), String> {
        match previous {
            Some(previous) => own.set_string(name, &previous),
            None => own.delete(name),
        }
    }

    fn restore(settings: &RegKey, name: &str, previous: Option<String>) -> Result<(), String> {
        match previous {
            Some(previous) => settings.set_string(name, &previous),
            None => settings.delete(name),
        }
    }

    /// Tells running programs to re-read the settings they cached.
    fn notify() {
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text).encode_wide().chain(Some(0)).collect()
    }

    /// One open registry key, closed on drop.
    struct RegKey(HKEY);

    impl Drop for RegKey {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    impl RegKey {
        fn open(subkey: &str, create: bool) -> Result<Self, String> {
            let path = wide(subkey);
            let mut key: HKEY = std::ptr::null_mut();
            let status = unsafe {
                if create {
                    RegCreateKeyW(HKEY_CURRENT_USER, path.as_ptr(), &mut key)
                } else {
                    RegOpenKeyExW(
                        HKEY_CURRENT_USER,
                        path.as_ptr(),
                        0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE,
                        &mut key,
                    )
                }
            };
            if status != ERROR_SUCCESS {
                return Err(format!("打开注册表 HKCU\\{subkey} 失败(错误码 {status})"));
            }
            Ok(RegKey(key))
        }

        fn get_string(&self, name: &str) -> Result<Option<String>, String> {
            let name_w = wide(name);
            let mut kind = 0u32;
            let mut size = 0u32;
            let mut status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                return Err(format!("读取注册表值 {name} 失败(错误码 {status})"));
            }
            if size > 64 * 1024 {
                return Err(format!("注册表值 {name} 异常大({size} 字节)"));
            }

            // One extra unit so a missing terminator cannot truncate the text.
            let mut buffer = vec![0u8; size as usize + 2];
            let mut size = buffer.len() as u32;
            status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    buffer.as_mut_ptr(),
                    &mut size,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("读取注册表值 {name} 失败(错误码 {status})"));
            }

            let units: Vec<u16> = buffer[..size as usize]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            Ok(Some(
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string(),
            ))
        }

        fn get_dword(&self, name: &str) -> Result<Option<u32>, String> {
            let name_w = wide(name);
            let mut kind = 0u32;
            let mut value = 0u32;
            let mut size = 4u32;
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    &mut value as *mut u32 as *mut u8,
                    &mut size,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                return Err(format!("读取注册表值 {name} 失败(错误码 {status})"));
            }
            if kind != REG_DWORD {
                return Ok(None);
            }
            Ok(Some(value))
        }

        fn set_string(&self, name: &str, value: &str) -> Result<(), String> {
            let name_w = wide(name);
            let value_w = wide(value);
            let bytes = unsafe {
                std::slice::from_raw_parts(value_w.as_ptr() as *const u8, value_w.len() * 2)
            };
            let status = unsafe {
                RegSetValueExW(
                    self.0,
                    name_w.as_ptr(),
                    0,
                    REG_SZ,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("写入注册表值 {name} 失败(错误码 {status})"));
            }
            Ok(())
        }

        fn set_dword(&self, name: &str, value: u32) -> Result<(), String> {
            let name_w = wide(name);
            let status = unsafe {
                RegSetValueExW(
                    self.0,
                    name_w.as_ptr(),
                    0,
                    REG_DWORD,
                    &value as *const u32 as *const u8,
                    4,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("写入注册表值 {name} 失败(错误码 {status})"));
            }
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            let name_w = wide(name);
            let status = unsafe { RegDeleteValueW(self.0, name_w.as_ptr()) };
            if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
                return Err(format!("删除注册表值 {name} 失败(错误码 {status})"));
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::ProxyStatus;
    use serde::{Deserialize, Serialize};
    use std::net::{SocketAddr, TcpStream};
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    /// One protocol's settings for one network service, as `networksetup`
    /// reports and accepts them.
    #[derive(Clone, Default, Deserialize, Serialize)]
    struct ProxyConfig {
        enabled: bool,
        host: Option<String>,
        port: Option<u16>,
    }

    /// Everything taken over for one network service, restored on disable.
    #[derive(Clone, Default, Deserialize, Serialize)]
    struct ServiceSnapshot {
        web: ProxyConfig,
        secure: ProxyConfig,
        socks: ProxyConfig,
        bypass: Option<Vec<String>>,
    }

    /// The macOS counterpart of the Windows `HKCU\Software\LemonVPN` values.
    #[derive(Deserialize, Serialize)]
    struct ProxyState {
        server: String,
        owner_pid: u32,
        services: Vec<(String, ServiceSnapshot)>,
    }

    const STATE_FILE: &str = "system-proxy.json";

    fn state_path() -> PathBuf {
        crate::default_data_dir().join(STATE_FILE)
    }

    fn load_state() -> Option<ProxyState> {
        let bytes = std::fs::read(state_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Written before any system setting changes, so a partial application is
    /// always recoverable by [`recover_stale`] even if this process dies.
    fn write_state(state: &ProxyState) -> Result<(), String> {
        let path = state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| format!("创建数据目录失败:{err}"))?;
        }
        let bytes = serde_json::to_vec(state).map_err(|err| err.to_string())?;
        std::fs::write(&path, bytes).map_err(|err| format!("写入代理状态失败:{err}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn clear_state() -> Result<(), String> {
        match std::fs::remove_file(state_path()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("清理代理状态失败:{err}")),
        }
    }

    fn networksetup(args: &[&str]) -> Result<String, String> {
        let output = Command::new("networksetup")
            .args(args)
            .output()
            .map_err(|err| format!("无法运行 networksetup:{err}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                format!(
                    "networksetup {} 失败(退出码 {:?})",
                    args.join(" "),
                    output.status.code()
                )
            } else {
                format!("networksetup {} 失败:{stderr}", args.join(" "))
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn parse_services(output: &str) -> Vec<String> {
        // The first line is the asterisk legend; a leading '*' marks a disabled
        // service whose settings cannot be switched.
        output
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('*'))
            .map(str::to_owned)
            .collect()
    }

    fn network_services() -> Result<Vec<String>, String> {
        let output = networksetup(&["-listallnetworkservices"])?;
        Ok(parse_services(&output))
    }

    fn get_flag(protocol: &str) -> &'static str {
        match protocol {
            "web" => "-getwebproxy",
            "secure" => "-getsecurewebproxy",
            _ => "-getsocksfirewallproxy",
        }
    }

    fn set_flag(protocol: &str) -> &'static str {
        match protocol {
            "web" => "-setwebproxy",
            "secure" => "-setsecurewebproxy",
            _ => "-setsocksfirewallproxy",
        }
    }

    fn state_flag(protocol: &str) -> &'static str {
        match protocol {
            "web" => "-setwebproxystate",
            "secure" => "-setsecurewebproxystate",
            _ => "-setsocksfirewallproxystate",
        }
    }

    fn read_config(protocol: &str, service: &str) -> Result<ProxyConfig, String> {
        let output = networksetup(&[get_flag(protocol), service])?;
        Ok(parse_config(&output))
    }

    fn parse_config(output: &str) -> ProxyConfig {
        let mut config = ProxyConfig::default();
        for line in output.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match name.trim() {
                "Enabled" => config.enabled = value.eq_ignore_ascii_case("yes"),
                "Server" if !value.is_empty() => config.host = Some(value.to_owned()),
                "Port" => config.port = value.parse().ok(),
                _ => {}
            }
        }
        config
    }

    fn read_bypass(service: &str) -> Result<Option<Vec<String>>, String> {
        let output = networksetup(&["-getproxybypassdomains", service])?;
        let domains: Vec<String> = output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("There are"))
            .map(str::to_owned)
            .collect();
        Ok((!domains.is_empty()).then_some(domains))
    }

    /// `networksetup` clears the list when the only extra argument is a blank.
    fn set_bypass(service: &str, domains: &[&str]) -> Result<(), String> {
        let mut args = vec!["-setproxybypassdomains", service];
        if domains.is_empty() {
            args.push(" ");
        } else {
            args.extend_from_slice(domains);
        }
        networksetup(&args).map(|_| ())
    }

    fn split_server(server: &str) -> Result<(&str, u16), String> {
        let (host, port) = server
            .rsplit_once(':')
            .ok_or_else(|| format!("代理地址缺少端口:{server}"))?;
        let port = port.parse().map_err(|_| format!("代理端口无效:{server}"))?;
        Ok((host, port))
    }

    fn snapshot_services(services: &[String]) -> Result<Vec<(String, ServiceSnapshot)>, String> {
        let mut snapshot = Vec::new();
        for name in services {
            snapshot.push((
                name.clone(),
                ServiceSnapshot {
                    web: read_config("web", name)?,
                    secure: read_config("secure", name)?,
                    socks: read_config("socks", name)?,
                    bypass: read_bypass(name)?,
                },
            ));
        }
        Ok(snapshot)
    }

    fn apply_service(service: &str, host: &str, port: u16) -> Result<(), String> {
        // `networksetup -set*proxy` enables the protocol while pointing it at
        // the server; no separate state call is needed for the takeover.
        for protocol in ["web", "secure", "socks"] {
            networksetup(&[set_flag(protocol), service, host, &port.to_string()])?;
        }
        set_bypass(service, &["127.0.0.1", "localhost"])
    }

    /// Restores one service's recorded settings verbatim.
    fn restore_service(service: &str, saved: &ServiceSnapshot) -> Result<(), String> {
        for (protocol, config) in
            [("web", &saved.web), ("secure", &saved.secure), ("socks", &saved.socks)]
        {
            if let (Some(host), Some(port)) = (config.host.as_deref(), config.port) {
                networksetup(&[set_flag(protocol), service, host, &port.to_string()])?;
            }
            networksetup(&[
                state_flag(protocol),
                service,
                if config.enabled { "on" } else { "off" },
            ])?;
        }
        match &saved.bypass {
            Some(domains) if !domains.is_empty() => {
                let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
                set_bypass(service, &refs)
            }
            _ => set_bypass(service, &[]),
        }
    }

    /// Whether any protocol on this service still points at our server.
    fn current_is_ours(service: &str, host: &str, port: u16) -> bool {
        for protocol in ["web", "secure", "socks"] {
            if let Ok(config) = read_config(protocol, service) {
                if config.enabled
                    && config.host.as_deref() == Some(host)
                    && config.port == Some(port)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Points the system proxy at `server`, remembering the pre-takeover
    /// settings of every network service the first time this runs.
    pub fn enable(server: &str) -> Result<(), String> {
        let services = network_services()?;
        let state = match load_state() {
            // A snapshot only exists for the original user settings; keep it
            // across restarts and ports, like the Windows SAVED values.
            Some(mut state) => {
                state.server = server.to_owned();
                state.owner_pid = std::process::id();
                state
            }
            None => ProxyState {
                server: server.to_owned(),
                owner_pid: std::process::id(),
                services: snapshot_services(&services)?,
            },
        };

        let (host, port) = split_server(server)?;
        write_state(&state)?;
        let mut applied = 0usize;
        let mut first_error = None;
        for (name, _) in &state.services {
            match apply_service(name, host, port) {
                Ok(()) => applied += 1,
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
        if applied == 0 {
            // Nothing took effect; undo the recorded takeover so the state
            // file does not claim settings that were never installed.
            let snapshot = state.services.clone();
            for (name, saved) in &snapshot {
                let _ = restore_service(name, saved);
            }
            clear_state()?;
            return Err(first_error.unwrap_or_else(|| "没有可用的网络服务".to_string()));
        }
        Ok(())
    }

    /// Restores the settings saved by [`enable`]. Leaves them alone when the
    /// recorded server no longer matches — the user changed it themselves, and
    /// their choice wins.
    pub fn disable_for(server: &str) -> Result<(), String> {
        disable_owned(server, std::process::id())
    }

    /// Used by the sidecar watchdog after its desktop parent has exited.
    pub fn disable_owned(server: &str, owner: u32) -> Result<(), String> {
        disable_impl(server, Some(owner)).map(|_| ())
    }

    fn disable_impl(server: &str, owner: Option<u32>) -> Result<bool, String> {
        let Some(state) = load_state() else {
            return Ok(false);
        };
        if state.server != server {
            return Ok(false);
        }
        if owner.is_some_and(|pid| state.owner_pid != pid) {
            return Ok(false);
        }
        let (host, port) = split_server(server)?;
        let mut changed = false;
        let mut first_error = None;
        for (name, saved) in &state.services {
            // A service the user reconfigured themselves keeps their choice;
            // an unreadable service is treated the same way.
            if current_is_ours(name, host, port) {
                match restore_service(name, saved) {
                    Ok(()) => changed = true,
                    Err(err) => {
                        first_error.get_or_insert(err);
                    }
                }
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        clear_state()?;
        Ok(changed)
    }

    /// A dead process may still own a live pid through EPERM; both count as
    /// alive, mirroring the Windows handle check.
    fn is_running(pid: u32) -> bool {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        if unsafe { kill(pid as i32, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(1)
    }

    /// Recover a previous crash only when its recorded loopback server has no
    /// listener. A live instance, unrelated proxy, or unreadable state is left
    /// alone.
    pub fn recover_stale() -> Result<(), String> {
        let Some(state) = load_state() else {
            return Ok(());
        };
        if is_running(state.owner_pid) {
            return Ok(());
        }
        let Ok(address) = state.server.parse::<SocketAddr>() else {
            return Ok(());
        };
        if !address.ip().is_loopback()
            || TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        disable_impl(&state.server, None).map(|_| ())
    }

    pub fn status() -> ProxyStatus {
        let Some(state) = load_state() else {
            return ProxyStatus {
                enabled: false,
                server: None,
                error: None,
            };
        };
        let Ok((host, port)) = split_server(&state.server) else {
            return ProxyStatus {
                enabled: false,
                server: None,
                error: Some(format!("代理地址无效:{}", state.server)),
            };
        };
        ProxyStatus {
            enabled: state
                .services
                .iter()
                .any(|(name, _)| current_is_ours(name, host, port)),
            server: Some(state.server),
            error: None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_services_and_skips_disabled() {
            let output = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nEthernet\n\n";
            assert_eq!(parse_services(output), vec!["Wi-Fi", "Ethernet"]);
            assert_eq!(parse_services("legend\n"), Vec::<String>::new());
        }

        #[test]
        fn parses_proxy_config_lines() {
            let output = "Enabled: Yes\nServer: 127.0.0.1\nPort: 18080\nAuthenticated Proxy Enabled: 0\n";
            let config = parse_config(output);
            assert!(config.enabled);
            assert_eq!(config.host.as_deref(), Some("127.0.0.1"));
            assert_eq!(config.port, Some(18080));

            let disabled = parse_config("Enabled: No\nServer: \nPort: 0\n");
            assert!(!disabled.enabled);
            assert_eq!(disabled.host, None);
            assert_eq!(disabled.port, Some(0));
        }

        #[test]
        fn splits_loopback_servers() {
            assert_eq!(split_server("127.0.0.1:18080"), Ok(("127.0.0.1", 18080)));
            assert!(split_server("no-port").is_err());
            assert!(split_server("127.0.0.1:oops").is_err());
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::ProxyStatus;

    const UNSUPPORTED: &str = "系统代理开关目前支持 Windows 与 macOS";

    pub fn status() -> ProxyStatus {
        ProxyStatus {
            enabled: false,
            server: None,
            error: Some(UNSUPPORTED.to_string()),
        }
    }

    pub fn enable(_server: &str) -> Result<(), String> {
        Err(UNSUPPORTED.to_string())
    }

    pub fn disable_for(_server: &str) -> Result<(), String> {
        Ok(())
    }

    pub fn disable_owned(_server: &str, _owner: u32) -> Result<(), String> {
        Ok(())
    }

    pub fn recover_stale() -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{disable_for, disable_owned, enable, recover_stale, status};
