//! systemd, OpenRC, runit and an on-demand supervised-by-client fallback.
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const DIR: &str = "/var/lib/lemonvpn/Service";
const NAME: &str = "org.lemonvpn.tun.service";
const UNIT: &str = "/etc/systemd/system/org.lemonvpn.tun.service";
const RC: &str = "/etc/init.d/lemonvpn-tun";
const RUNIT: &str = "/etc/sv/lemonvpn-tun";
#[derive(Clone, Serialize, Deserialize)]
enum Manager {
    Systemd,
    Openrc,
    Runit { link: PathBuf },
    Standalone,
}
#[derive(Serialize, Deserialize)]
struct Registration {
    manager: Manager,
    owner: u32,
}
fn binary() -> PathBuf {
    Path::new(DIR).join("lemonvpn-service")
}
fn state() -> PathBuf {
    Path::new(DIR).join("service.json")
}
fn registered() -> io::Result<Option<Registration>> {
    match fs::read(state()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::from),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
pub fn installed() -> bool {
    binary().is_file() && (state().is_file() || Path::new(UNIT).is_file())
}
fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .into_iter()
        .map(|p| Path::new(p).join(name))
        .find(|p| p.is_file())
}
fn call(name: &str, args: &[&str]) -> bool {
    tool(name).is_some_and(|p| {
        Command::new(p)
            .args(args)
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}
fn write(path: impl AsRef<Path>, text: impl AsRef<[u8]>, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(&path, text)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
fn brokers() -> Vec<u32> {
    // A host-network container runs the same path in another mount namespace;
    // only processes that share our mounts are this service instance.
    crate::egress::own_brokers()
}
pub fn running() -> bool {
    if !crate::service_linux::is_elevated() {
        return crate::service_linux::reachable();
    }
    if let Some(pid) = fs::read_to_string(Path::new(DIR).join("broker.ready"))
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        if fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|p| p == binary()) {
            return true;
        }
    }
    !brokers().is_empty()
}
fn ready() -> bool {
    use std::os::unix::fs::FileTypeExt;
    let pid = fs::read_to_string(Path::new(DIR).join("broker.ready"))
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    pid.is_some_and(|pid| brokers().contains(&pid))
        && fs::symlink_metadata("/run/lemonvpn-tun.sock").is_ok_and(|m| m.file_type().is_socket())
}
pub struct Ready;
pub fn mark_ready() -> io::Result<Ready> {
    write(
        Path::new(DIR).join("broker.ready"),
        std::process::id().to_string(),
        0o600,
    )?;
    Ok(Ready)
}
impl Drop for Ready {
    fn drop(&mut self) {
        let _ = fs::remove_file(Path::new(DIR).join("broker.ready"));
    }
}
pub fn stop() -> io::Result<()> {
    let manager = registered()?.map(|r| r.manager).unwrap_or(Manager::Systemd);
    match &manager {
        Manager::Systemd => {
            call("systemctl", &["disable", "--now", NAME]);
        }
        Manager::Openrc => {
            call("rc-service", &["lemonvpn-tun", "stop"]);
            call("rc-update", &["del", "lemonvpn-tun", "default"]);
        }
        Manager::Runit { link } => {
            call("sv", &["down", &link.to_string_lossy()]);
            if fs::read_link(link).ok().as_deref() == Some(Path::new(RUNIT)) {
                fs::remove_file(link)?;
            }
        }
        Manager::Standalone => {}
    }
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    for pid in brokers() {
        unsafe { kill(pid as i32, 15) };
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while running() {
        if Instant::now() >= deadline {
            return Err(io::Error::other("TUN 服务未能停止，保留现有文件"));
        }
        thread::sleep(Duration::from_millis(100));
    }
    // `running()` is false both after a graceful exit and when a broker was
    // hard-killed. In the latter case its journal may still exist, or the
    // directory may already be gone; clean both before install/uninstall
    // removes the files that are the only record of those rules.
    crate::egress::cleanup_stale()?;
    Ok(())
}
pub fn install(owner: u32) -> io::Result<()> {
    let manager = if Path::new("/run/systemd/system").is_dir() && tool("systemctl").is_some() {
        Manager::Systemd
    } else if tool("rc-service").is_some() && tool("rc-update").is_some() {
        Manager::Openrc
    } else if tool("sv").is_some() {
        ["/var/service", "/service", "/etc/service"]
            .into_iter()
            .find(|p| Path::new(p).is_dir())
            .map(|p| Manager::Runit {
                link: Path::new(p).join("lemonvpn-tun"),
            })
            .unwrap_or(Manager::Standalone)
    } else {
        Manager::Standalone
    };
    let registration = Registration {
        manager: manager.clone(),
        owner,
    };
    write(state(), serde_json::to_vec(&registration)?, 0o600)?;
    let executable = binary();
    let ok = match manager {
        Manager::Systemd => {
            write(UNIT,format!("[Unit]\nDescription=LemonVPN TUN broker\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart={} --run --owner-uid {owner}\nKillMode=mixed\nLimitNOFILE=10240\nRestart=on-failure\nRestartSec=2\n[Install]\nWantedBy=multi-user.target\n",executable.display()),0o644)?;
            call("systemctl", &["daemon-reload"]) && call("systemctl", &["enable", "--now", NAME])
        }
        Manager::Openrc => {
            write(RC,format!("#!/sbin/openrc-run\nname=\"LemonVPN TUN broker\"\ncommand=\"{}\"\ncommand_args=\"--run --owner-uid {owner}\"\ncommand_background=true\npidfile=\"/run/lemonvpn-tun.pid\"\ndepend() {{ need net; }}\n",executable.display()),0o755)?;
            call("rc-update", &["add", "lemonvpn-tun", "default"])
                && call("rc-service", &["lemonvpn-tun", "start"])
        }
        Manager::Runit { link } => {
            fs::create_dir_all(RUNIT)?;
            write(
                Path::new(RUNIT).join("run"),
                format!(
                    "#!/bin/sh\nexec {} --run --owner-uid {owner}\n",
                    executable.display()
                ),
                0o755,
            )?;
            if !link.exists() {
                std::os::unix::fs::symlink(RUNIT, &link)?;
            }
            if fs::read_link(&link).ok().as_deref() != Some(Path::new(RUNIT)) {
                return Err(io::Error::other("runit 服务路径已被其他内容占用"));
            }
            call("sv", &["up", &link.to_string_lossy()])
        }
        Manager::Standalone => {
            use std::os::unix::process::CommandExt;
            extern "C" {
                fn setsid() -> i32;
            }
            let mut command = Command::new(executable);
            command
                .args(["--run", "--owner-uid", &owner.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if setsid() < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            command.spawn()?;
            true
        }
    };
    if !ok {
        return Err(io::Error::other("无法启动平台 TUN 服务"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        if Instant::now() >= deadline {
            return Err(io::Error::other("TUN 服务启动超时，请检查授权与服务日志"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
pub fn unregister() -> io::Result<()> {
    stop()?;
    let manager = registered()?.map(|r| r.manager).unwrap_or(Manager::Systemd);
    match manager {
        Manager::Systemd => {
            let _ = fs::remove_file(UNIT);
            call("systemctl", &["daemon-reload"]);
        }
        Manager::Openrc => {
            let _ = fs::remove_file(RC);
        }
        Manager::Runit { .. } => {
            let _ = fs::remove_file(Path::new(RUNIT).join("run"));
            let _ = fs::remove_dir(RUNIT);
        }
        Manager::Standalone => {}
    }
    Ok(())
}
