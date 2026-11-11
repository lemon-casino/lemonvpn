//! Privileged route ownership, shared by the macOS/Linux TUN brokers.
use crate::network::{self, Route, Routes};
use serde::{Deserialize, Serialize};
use std::{io, process::Command};

#[cfg(target_os = "macos")]
const SERVICE_DIR: &str = "/Library/Application Support/LemonVPN/Service";
#[cfg(target_os = "linux")]
const SERVICE_DIR: &str = "/var/lib/lemonvpn/Service";
static JOURNAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    route: Route,
    #[cfg(target_os = "linux")]
    priority: u32,
}
fn records() -> io::Result<Vec<Record>> {
    match std::fs::read(std::path::Path::new(SERVICE_DIR).join("egress-routes.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::from),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}
fn journal(guard: &Guard, add: bool) -> io::Result<()> {
    let _lock = JOURNAL.lock().unwrap();
    let mut records = records()?;
    records.retain(|r| {
        !same(&r.route, &guard.route) || {
            #[cfg(target_os = "linux")]
            {
                r.priority != guard.priority
            }
            #[cfg(target_os = "macos")]
            {
                false
            }
        }
    });
    if add {
        records.push(Record {
            route: guard.route.clone(),
            #[cfg(target_os = "linux")]
            priority: guard.priority,
        });
    }
    let path = std::path::Path::new(SERVICE_DIR).join("egress-routes.json");
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec(&records)?)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(temporary, path)
}

/// Prevent two root brokers from racing over the socket, journal and routes.
pub(crate) fn lock_broker() -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(std::path::Path::new(SERVICE_DIR).join("broker.lock"))?;
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err(io::Error::other("TUN 服务已在运行"));
    }
    Ok(file)
}

pub(crate) struct Egress {
    guards: Vec<Guard>,
    revision: u64,
    pub routes: Routes,
    checked: std::time::Instant,
}
fn same(a: &Route, b: &Route) -> bool {
    a.ipv6 == b.ipv6 && a.interface == b.interface && a.gateway == b.gateway
}
impl Egress {
    pub fn new() -> io::Result<Self> {
        let mut state = Self {
            guards: Vec::new(),
            revision: 0,
            routes: Routes::default(),
            checked: std::time::Instant::now() - std::time::Duration::from_secs(10),
        };
        state.refresh()?;
        if !state.routes.any() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "没有可用物理出口",
            ));
        }
        Ok(state)
    }
    pub fn refresh(&mut self) -> io::Result<bool> {
        let snapshot = network::snapshot(false)?;
        if snapshot.revision == self.revision
            && self.checked.elapsed() < std::time::Duration::from_secs(2)
        {
            return Ok(false);
        }
        // Routes/rules can be lost during suspend even when addresses match.
        let mut missing = Vec::new();
        for (index, guard) in self.guards.iter_mut().enumerate() {
            if !guard.present()? {
                if guard.owned {
                    journal(guard, false)?;
                }
                guard.owned = false;
                missing.push(index);
            }
        }
        for index in missing.into_iter().rev() {
            self.guards.remove(index);
        }
        let mut added = Vec::new();
        for route in snapshot.routes.iter() {
            #[cfg(target_os = "macos")]
            if let Some(old) = self.guards.iter_mut().find(|g| {
                g.route.ipv6 == route.ipv6
                    && g.route.interface == route.interface
                    && g.route.gateway != route.gateway
            }) {
                old.replace(route.clone())?;
            }
            if !self.guards.iter().any(|g| same(&g.route, route)) {
                added.push(Guard::acquire(route.clone())?);
            }
        }
        let repaired = !added.is_empty();
        // Only discard the previous route after every replacement was acquired.
        self.guards
            .retain(|g| snapshot.routes.iter().any(|r| same(&g.route, r)));
        self.guards.extend(added);
        let changed = repaired || self.revision != snapshot.revision;
        self.revision = snapshot.revision;
        self.routes = snapshot.routes;
        self.checked = std::time::Instant::now();
        Ok(changed)
    }
}

struct Guard {
    route: Route,
    owned: bool,
    #[cfg(target_os = "linux")]
    priority: u32,
}

#[cfg(target_os = "macos")]
impl Guard {
    fn query(&self) -> io::Result<bool> {
        let output = Command::new("/sbin/route")
            .args([
                "-n",
                "get",
                if self.route.ipv6 { "-inet6" } else { "-inet" },
                "-net",
                "-ifscope",
                &self.route.interface,
                "default",
            ])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let field = |key: &str| {
            text.lines().find_map(|line| {
                let (name, value) = line.trim().split_once(':')?;
                (name.trim() == key).then_some(value.trim())
            })
        };
        Ok(field("interface") == Some(self.route.interface.as_str())
            && field("gateway") == Some(self.route.gateway.as_str())
            && field("flags").is_some_and(|f| f.contains("IFSCOPE"))
            && (!self.owned || field("flags").is_some_and(|f| f.contains("PROTO2")))
            && matches!(field("destination"), Some("default" | "0.0.0.0" | "::")))
    }
    fn present(&self) -> io::Result<bool> {
        self.query()
    }
    fn acquire(route: Route) -> io::Result<Self> {
        let mut result = Self {
            route,
            owned: false,
        };
        if result.query()? {
            return Ok(result);
        }
        journal(&result, true)?;
        let output = Command::new("/sbin/route")
            .args([
                "-n",
                "add",
                if result.route.ipv6 { "-inet6" } else { "-inet" },
                "-net",
                "-proto2",
                "-ifscope",
                &result.route.interface,
                "default",
                &result.route.gateway,
            ])
            .output()?;
        if !output.status.success() {
            journal(&result, false)?;
            if result.query()? {
                return Ok(result);
            }
            return Err(io::Error::other(format!(
                "无法设置物理出口路由：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        result.owned = true;
        Ok(result)
    }
    fn replace(&mut self, route: Route) -> io::Result<()> {
        if !self.owned || !self.present()? {
            return Err(io::Error::other(
                "物理网卡已有其他 scoped 路由，保留用户设置",
            ));
        }
        let mut next = Self {
            route,
            owned: false,
        };
        journal(&next, true)?;
        let output = Command::new("/sbin/route")
            .args([
                "-n",
                "change",
                if next.route.ipv6 { "-inet6" } else { "-inet" },
                "-net",
                "-proto2",
                "-ifscope",
                &next.route.interface,
                "default",
                &next.route.gateway,
            ])
            .output()?;
        if !output.status.success() {
            journal(&next, false)?;
            return Err(io::Error::other("无法更新物理网关"));
        }
        next.owned = true;
        let old = std::mem::replace(self, next);
        // The old gateway no longer matches, so Drop cannot remove the replacement.
        journal(&old, false)?;
        Ok(())
    }
    fn remove(&self) {
        let _ = Command::new("/sbin/route")
            .args([
                "-n",
                "delete",
                if self.route.ipv6 { "-inet6" } else { "-inet" },
                "-net",
                "-ifscope",
                &self.route.interface,
                "default",
                &self.route.gateway,
            ])
            .output();
    }
}

#[cfg(target_os = "linux")]
const PROTOCOL: &str = "242";
#[cfg(target_os = "linux")]
fn rules(ipv6: bool) -> io::Result<Vec<serde_json::Value>> {
    let output = Command::new(network::ip_tool()?)
        .args(["-j", if ipv6 { "-6" } else { "-4" }, "rule", "show"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("无法读取策略路由"));
    }
    serde_json::from_slice(&output.stdout).map_err(io::Error::from)
}
#[cfg(target_os = "linux")]
fn ours(value: &serde_json::Value) -> bool {
    let protocol = &value["protocol"];
    (protocol.as_u64() == Some(242) || protocol.as_str() == Some(PROTOCOL))
        && value["priority"]
            .as_u64()
            .is_some_and(|p| (8750..8800).contains(&p))
        && value["oif"].is_string()
        && (value["table"] == "main" || value["table"].as_u64() == Some(254))
}

#[cfg(target_os = "linux")]
fn namespace_matches(pid: u32, kind: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata(format!("/proc/{}/ns/{kind}", std::process::id()));
    let other = std::fs::metadata(format!("/proc/{pid}/ns/{kind}"));
    matches!((current, other), (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(target_os = "linux")]
fn executable(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(
        path.to_string_lossy()
            .trim_end_matches(" (deleted)")
            .to_owned(),
    )
}

#[cfg(target_os = "linux")]
struct Processes {
    own_cores: Vec<u32>,
    own_brokers: Vec<u32>,
    foreign: Vec<u32>,
}

/// Split this project's processes into our own and another instance's.
///
/// Only processes in our network namespace can affect our rules. Within that
/// namespace the mount namespace separates us from a host-network container:
/// the container has the same executable path but its own mounts.
#[cfg(target_os = "linux")]
fn processes() -> Processes {
    let service = std::path::Path::new(SERVICE_DIR)
        .join("lemonvpn-service")
        .to_string_lossy()
        .into_owned();
    let core = std::path::Path::new(SERVICE_DIR)
        .join(crate::managed::CORE_BINARY_NAME)
        .to_string_lossy()
        .into_owned();
    let mut result = Processes {
        own_cores: Vec::new(),
        own_brokers: Vec::new(),
        foreign: Vec::new(),
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return result;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() || !namespace_matches(pid, "net") {
            continue;
        }
        let Some(executable) = executable(pid) else {
            continue;
        };
        let is_core = executable == core;
        if !is_core && executable != service {
            continue;
        }
        if !namespace_matches(pid, "mnt") {
            result.foreign.push(pid);
        } else if is_core {
            result.own_cores.push(pid);
        } else {
            result.own_brokers.push(pid);
        }
    }
    result
}

/// A live TUN owned by another LemonVPN instance in this network namespace.
/// Docker host-network is the common case; never kill it or sweep its rules.
#[cfg(target_os = "linux")]
pub(crate) fn foreign_tun() -> io::Result<Option<String>> {
    let found = processes();
    if !found.foreign.is_empty() {
        let pids = found
            .foreign
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(Some(format!(
            "另一个 LemonVPN TUN 实例正在使用当前网络命名空间（PID {pids}），请先停止它再启用 TUN"
        )));
    }
    if std::path::Path::new("/sys/class/net/LemonVPN").exists() && found.own_cores.is_empty() {
        return Ok(Some(
            "另一个 LemonVPN TUN 正在使用当前网络命名空间，请先停止它再启用 TUN".to_owned(),
        ));
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
pub(crate) fn own_brokers() -> Vec<u32> {
    processes().own_brokers
}

#[cfg(target_os = "linux")]
pub(crate) fn kill_own_cores() {
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    for pid in processes().own_cores {
        unsafe {
            kill(pid as i32, 15);
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn wait_for_device_gone(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::path::Path::new("/sys/class/net/LemonVPN").exists() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    true
}

#[cfg(target_os = "linux")]
impl Guard {
    fn present(&self) -> io::Result<bool> {
        Ok(rules(self.route.ipv6)?.iter().any(|v| {
            ours(v)
                && v["priority"].as_u64() == Some(self.priority.into())
                && v["oif"].as_str() == Some(self.route.interface.as_str())
        }))
    }
    fn acquire(route: Route) -> io::Result<Self> {
        let entries = rules(route.ipv6)?;
        // Bind-to-device is per socket: ordinary browser sockets have no oif
        // and continue into the kernel's capture rules at priority 9000+.
        let priority = (8750..8800)
            .find(|p| {
                !entries
                    .iter()
                    .any(|v| v["priority"].as_u64() == Some(*p as u64))
            })
            .ok_or_else(|| io::Error::other("物理出口策略路由优先级已用尽"))?;
        let mut result = Self {
            route,
            owned: false,
            priority,
        };
        journal(&result, true)?;
        let output = Command::new(network::ip_tool()?)
            .args([
                if result.route.ipv6 { "-6" } else { "-4" },
                "rule",
                "add",
                "pref",
                &priority.to_string(),
                "oif",
                &result.route.interface,
                "lookup",
                "main",
                "protocol",
                PROTOCOL,
            ])
            .output()?;
        if !output.status.success() {
            journal(&result, false)?;
            return Err(io::Error::other(format!(
                "无法设置引擎 socket 绕行：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        result.owned = true;
        Ok(result)
    }
    fn remove(&self) {
        if let Ok(tool) = network::ip_tool() {
            let _ = Command::new(tool)
                .args([
                    if self.route.ipv6 { "-6" } else { "-4" },
                    "rule",
                    "del",
                    "pref",
                    &self.priority.to_string(),
                    "oif",
                    &self.route.interface,
                    "lookup",
                    "main",
                    "protocol",
                    PROTOCOL,
                ])
                .output();
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.owned {
            if self.present().unwrap_or(false) {
                self.remove();
            }
            if matches!(self.present(), Ok(false)) {
                let _ = journal(self, false);
            }
        }
    }
}

/// The journal only covers rules written by a run that could persist it. A
/// broker killed during install/uninstall, a removed service directory or a
/// shared namespace can leave protocol-242 rules with no journal at all. Every
/// rule this project owns carries protocol 242 and a priority in 8750..8800,
/// so the sweep is unambiguous; callers must already own the service lock.
#[cfg(target_os = "linux")]
fn sweep_orphans() -> io::Result<()> {
    let tool = network::ip_tool()?;
    for ipv6 in [false, true] {
        for value in rules(ipv6)?.iter().filter(|value| ours(value)) {
            let Some(priority) = value["priority"].as_u64() else {
                continue;
            };
            let Some(oif) = value["oif"].as_str() else {
                continue;
            };
            let _ = Command::new(&tool)
                .args([
                    if ipv6 { "-6" } else { "-4" },
                    "rule",
                    "del",
                    "pref",
                    &priority.to_string(),
                    "oif",
                    oif,
                    "lookup",
                    "main",
                    "protocol",
                    PROTOCOL,
                ])
                .output();
        }
        if rules(ipv6)?.iter().any(ours) {
            return Err(io::Error::other("无法清理残留的物理出口策略路由"));
        }
    }
    Ok(())
}

pub(crate) fn cleanup_stale() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if foreign_tun()?.is_some() {
        // Our journal may point at priorities another live instance has since
        // reused; leave that instance and its rules untouched.
        return Ok(());
    }
    for record in records()? {
        let guard = Guard {
            route: record.route,
            owned: true,
            #[cfg(target_os = "linux")]
            priority: record.priority,
        };
        if guard.present()? {
            guard.remove();
        }
        if guard.present()? {
            return Err(io::Error::other("无法清理上次会话的物理出口路由"));
        }
        journal(&guard, false)?;
    }
    #[cfg(target_os = "linux")]
    sweep_orphans()?;
    Ok(())
}
