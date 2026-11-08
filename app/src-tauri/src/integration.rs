//! User opt-in desktop integration. Building never invokes these operations.
//! Windows registers a Run-key autostart and owns the TUN service; macOS uses
//! a per-user LaunchAgent for autostart and installs the TUN service as a
//! root LaunchDaemon. Both service flows elevate only through an explicit
//! user action in the UI.
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
    #[cfg(target_os = "macos")]
    {
        Status {
            autostart: autostart_value().is_some(),
            service_installed: lemonvpn_engine_platform::service_macos::installed(),
            service_update_required: lemonvpn_engine_platform::service_macos::update_required(),
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
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
    #[cfg(target_os = "macos")]
    {
        let path = launch_agent_path()?;
        if enabled {
            let exe = std::env::current_exe().map_err(|err| err.to_string())?;
            let parent = path
                .parent()
                .ok_or_else(|| "LaunchAgents 路径异常".to_string())?;
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("创建 LaunchAgents 目录失败:{err}"))?;
            std::fs::write(&path, plist_content(&exe))
                .map_err(|err| format!("写入 LaunchAgent 失败:{err}"))?;
        } else {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("移除 LaunchAgent 失败:{err}")),
            }
        }
        Ok(status())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = enabled;
        Err("当前平台尚未提供开机自启".into())
    }
}

/// Per-user autostart for macOS: a LaunchAgent that runs at login, written
/// under `~/Library/LaunchAgents`, which the user owns without elevation.
#[cfg(target_os = "macos")]
const LAUNCH_AGENT_LABEL: &str = "org.lemonvpn.desktop";

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Result<std::path::PathBuf, String> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| "缺少 HOME 环境变量".to_string())?;
    Ok(std::path::PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_os = "macos")]
fn plist_content(exe: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>--autostart</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn autostart_value() -> Option<String> {
    let text = std::fs::read_to_string(launch_agent_path().ok()?).ok()?;
    let args = text.split("<array>").nth(1)?;
    let first = args.split("<string>").nth(1)?;
    let installed = first.split("</string>").next()?.trim().to_owned();
    let exe = std::env::current_exe().ok()?;
    (installed == xml_escape(&exe.display().to_string())).then_some(installed)
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
    #[cfg(target_os = "macos")]
    {
        use std::io::Read as _;
        use std::time::Instant;
        let executable = resources.join("lemonvpn-service");
        if !executable.is_file() {
            return Err("安装包缺少 TUN 服务程序".into());
        }
        let params = if install {
            format!(
                "--install --owner-uid {}",
                lemonvpn_engine_platform::service_macos::current_uid().map_err(|e| e.to_string())?
            )
        } else {
            "--uninstall".into()
        };
        // One elevated shell run: osascript shows the admin prompt and the
        // helper owns installation; cancelling the prompt must not restart the UI.
        let command = format!("{} {}", shell_quote(&executable.display().to_string()), params);
        let script = format!(
            "do shell script {} with administrator privileges",
            apple_quote(&command)
        );
        let mut child = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| format!("无法调用管理员授权：{err}"))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let outcome = loop {
            match child.try_wait() {
                Ok(Some(outcome)) => break outcome,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("管理员授权超时，请重试并在弹窗内确认".into());
                }
                Err(err) => return Err(format!("管理员授权失败：{err}")),
            }
        };
        if !outcome.success() {
            let mut reason = String::new();
            if let Some(stderr) = child.stderr.as_mut() {
                let _ = stderr.read_to_string(&mut reason);
            }
            let reason = reason.trim();
            return Err(format!(
                "TUN 服务操作失败（{}）",
                if reason.is_empty() {
                    format!("退出码 {}", outcome.code().unwrap_or(-1))
                } else {
                    reason.to_owned()
                }
            ));
        }
        Ok(status())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (resources, install);
        Err("当前平台不使用 Windows 服务".into())
    }
}

/// Single shell word: an argv value passed through `do shell script`, which
/// the helper runs with `/bin/sh`.
#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// AppleScript string literal inside `osascript -e`; argv carries it verbatim.
#[cfg(target_os = "macos")]
fn apple_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
