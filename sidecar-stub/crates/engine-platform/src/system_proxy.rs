//! System proxy switch.
//!
//! The data plane of the system-proxy milestone is the engine's mixed inbound;
//! this module points Windows' per-user WinINet settings at it. The values that
//! were there before the first takeover are saved under `HKCU\Software\LemonVPN`
//! so switching the proxy off restores them instead of leaving the user with a
//! loopback proxy that no longer has an engine behind it.
//!
//! macOS (`networksetup`) and Linux (`gsettings`/`kwriteconfig`) are not
//! implemented yet; there the switch reports itself as unavailable.

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

#[cfg(not(windows))]
mod imp {
    use super::ProxyStatus;

    const UNSUPPORTED: &str = "系统代理开关目前只支持 Windows";

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
