//! User opt-in Windows integration. Building never invokes these operations.
use std::{path::Path, time::Duration};
#[derive(serde::Serialize)]
pub struct Status {
    pub autostart: bool,
    pub service_installed: bool,
    pub service_update_required: bool,
}

pub fn status() -> Status {
    #[cfg(windows)]
    {
        Status {
            autostart: autostart_value()
                .is_some_and(|v| v == startup_command().unwrap_or_default()),
            service_installed: lemonvpn_engine_platform::service::installed(),
            service_update_required: lemonvpn_engine_platform::service::update_required(),
        }
    }
    #[cfg(not(windows))]
    {
        Status {
            autostart: false,
            service_installed: false,
            service_update_required: false,
        }
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
#[cfg(windows)]
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
fn startup_command() -> Result<String, String> {
    Ok(format!(
        "\"{}\" --autostart",
        std::env::current_exe()
            .map_err(|e| e.to_string())?
            .display()
    ))
}
#[cfg(windows)]
fn autostart_value() -> Option<String> {
    unsafe {
        use windows_sys::Win32::System::Registry::*;
        let mut key = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN).as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        ) != 0
        {
            return None;
        }
        let mut bytes = vec![0u16; 32768];
        let mut length = (bytes.len() * 2) as u32;
        let mut kind = 0;
        let rc = RegQueryValueExW(
            key,
            wide("LemonVPN").as_ptr(),
            std::ptr::null(),
            &mut kind,
            bytes.as_mut_ptr().cast(),
            &mut length,
        );
        RegCloseKey(key);
        if rc != 0 || kind != REG_SZ {
            return None;
        }
        let size = (length as usize / 2).min(bytes.len());
        Some(
            String::from_utf16_lossy(&bytes[..size])
                .trim_end_matches('\0')
                .to_owned(),
        )
    }
}

pub fn set_autostart(enabled: bool) -> Result<Status, String> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Registry::*;
        let mut key = std::ptr::null_mut();
        let rc = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN).as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        );
        if rc != 0 {
            return Err(format!("打开启动设置失败：{rc}"));
        }
        let rc = if enabled {
            let value = wide(&startup_command()?);
            RegSetValueExW(
                key,
                wide("LemonVPN").as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        } else {
            RegDeleteValueW(key, wide("LemonVPN").as_ptr())
        };
        RegCloseKey(key);
        if rc != 0 && !(rc == 2 && !enabled) {
            return Err(format!("保存启动设置失败：{rc}"));
        }
        Ok(status())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("当前平台尚未提供开机自启".into())
    }
}

pub fn service_action(resources: &Path, install: bool) -> Result<Status, String> {
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{GetExitCodeProcess, WaitForSingleObject},
            UI::{
                Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
                WindowsAndMessaging::SW_HIDE,
            },
        };
        let executable = resources.join("lemonvpn-service.exe");
        if !executable.is_file() {
            return Err("安装包缺少 TUN 服务程序".into());
        }
        let params = if install {
            format!(
                "--install --owner-sid {}",
                lemonvpn_engine_platform::service::current_sid().map_err(|e| e.to_string())?
            )
        } else {
            "--uninstall".into()
        };
        let verb = wide("runas");
        let file: Vec<_> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let parameters = wide(&params);
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of_val(&info) as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(format!(
                "未能完成管理员授权：{}",
                std::io::Error::last_os_error()
            ));
        }
        // The helper owns installation; closing a UAC prompt does not restart the UI.
        let waited =
            WaitForSingleObject(info.hProcess, Duration::from_secs(120).as_millis() as u32);
        let mut exit = 1;
        GetExitCodeProcess(info.hProcess, &mut exit);
        CloseHandle(info.hProcess);
        if waited != 0 || exit != 0 {
            return Err(format!(
                "TUN 服务操作失败（退出码 {exit}），请查看安装目录与系统服务权限"
            ));
        }
        Ok(status())
    }
    #[cfg(not(windows))]
    {
        let _ = (resources, install);
        Err("当前平台不使用 Windows 服务".into())
    }
}
