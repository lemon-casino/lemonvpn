//! Local routing metadata only: no DNS queries or connectivity probes.
//! IPv4 and IPv6 may use different devices. Wall-clock gaps include suspend on
//! macOS, unlike Instant; a wake invalidates even an unchanged route snapshot.
use serde::{Deserialize, Serialize};
use std::{
    io,
    process::Command,
    sync::Mutex,
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub ipv6: bool,
    pub interface: String,
    pub gateway: String,
    pub addresses: Vec<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routes {
    pub ipv4: Option<Route>,
    pub ipv6: Option<Route>,
}
impl Routes {
    pub fn get(&self, ipv6: bool) -> Option<&Route> {
        if ipv6 {
            self.ipv6.as_ref()
        } else {
            self.ipv4.as_ref()
        }
    }
    pub fn any(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.ipv4.iter().chain(self.ipv6.iter())
    }
}
#[derive(Clone, Default)]
pub struct Snapshot {
    pub routes: Routes,
    pub revision: u64,
    suspend_ns: Option<u64>,
}
static CACHE: Mutex<Option<(SystemTime, Snapshot)>> = Mutex::new(None);

pub fn snapshot(force: bool) -> io::Result<Snapshot> {
    let mut cache = CACHE.lock().unwrap();
    let now = SystemTime::now();
    if !force {
        if let Some((time, snapshot)) = &*cache {
            if now
                .duration_since(*time)
                .is_ok_and(|gap| gap < Duration::from_millis(1500))
            {
                return Ok(snapshot.clone());
            }
        }
    }
    // A missing family is normal on single-stack networks. Command failures
    // remain errors rather than silently allowing unbound egress into TUN.
    let routes = Routes {
        ipv4: probe(false)?,
        ipv6: probe(true)?,
    };
    let suspend_ns = suspend_time();
    let revision = match &*cache {
        Some((time, previous)) => previous.revision.wrapping_add(u64::from(
            previous.routes != routes
                || previous
                    .suspend_ns
                    .zip(suspend_ns)
                    .is_some_and(|(a, b)| a.abs_diff(b) > 250_000_000)
                || now
                    .duration_since(*time)
                    .map_or(true, |gap| gap > Duration::from_secs(6)),
        )),
        None => 1,
    };
    let result = Snapshot {
        routes,
        revision,
        suspend_ns,
    };
    *cache = Some((now, result.clone()));
    Ok(result)
}

#[cfg(target_os = "macos")]
fn suspend_time() -> Option<u64> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    let mut info = Timebase { numer: 0, denom: 0 };
    if unsafe { mach_timebase_info(&mut info) } != 0 || info.denom == 0 {
        return None;
    }
    let ticks = unsafe { mach_continuous_time().saturating_sub(mach_absolute_time()) };
    u64::try_from(u128::from(ticks) * u128::from(info.numer) / u128::from(info.denom)).ok()
}
#[cfg(target_os = "linux")]
fn suspend_time() -> Option<u64> {
    #[repr(C)]
    struct Timespec {
        seconds: std::ffi::c_long,
        nanoseconds: std::ffi::c_long,
    }
    extern "C" {
        fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
    }
    let read = |clock| {
        let mut value = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        if unsafe { clock_gettime(clock, &mut value) } != 0 {
            return None;
        }
        u64::try_from(value.seconds)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(value.nanoseconds).ok()?)
    };
    Some(read(7)?.saturating_sub(read(1)?))
}

pub fn interface(ipv6: bool) -> io::Result<String> {
    snapshot(false)?
        .routes
        .get(ipv6)
        .map(|r| r.interface.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                if ipv6 {
                    "IPv6 出口暂不可用"
                } else {
                    "IPv4 出口暂不可用"
                },
            )
        })
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "lo"
        && name != "lo0"
        && !name.to_ascii_lowercase().starts_with("lemonvpn")
        && !name.starts_with("utun")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}

#[cfg(target_os = "linux")]
pub(crate) fn ip_tool() -> io::Result<&'static str> {
    ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "缺少 iproute2（ip 命令）"))
}

#[cfg(target_os = "linux")]
fn probe(ipv6: bool) -> io::Result<Option<Route>> {
    let output = Command::new(ip_tool()?)
        .args([
            "-j",
            if ipv6 { "-6" } else { "-4" },
            "route",
            "show",
            "table",
            "main",
            "default",
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("无法读取默认路由"));
    }
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let selected = entries
        .iter()
        .filter(|r| {
            r.get("dev")
                .and_then(|v| v.as_str())
                .is_some_and(valid_interface)
                && r.get("type")
                    .and_then(|v| v.as_str())
                    .map_or(true, |v| v == "unicast")
                && !r
                    .get("flags")
                    .and_then(|v| v.as_array())
                    .is_some_and(|flags| flags.iter().any(|v| v == "linkdown"))
        })
        .min_by_key(|r| r.get("metric").and_then(|v| v.as_u64()).unwrap_or(0));
    let Some(entry) = selected else {
        return Ok(None);
    };
    let interface = entry["dev"].as_str().unwrap().to_owned();
    let output = Command::new(ip_tool()?)
        .args(["-j", "address", "show", "dev", &interface])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let links: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let mut addresses = Vec::new();
    for link in links {
        if matches!(link["operstate"].as_str(), Some("DOWN" | "LOWERLAYERDOWN")) {
            return Ok(None);
        }
        if let Some(info) = link["addr_info"].as_array() {
            for address in info {
                if address["family"].as_str() == Some(if ipv6 { "inet6" } else { "inet" }) {
                    if let Some(local) = address["local"].as_str() {
                        addresses.push(format!("{local}/{}", address["prefixlen"]));
                    }
                }
            }
        }
    }
    addresses.sort();
    Ok(Some(Route {
        ipv6,
        interface,
        gateway: entry["gateway"].as_str().unwrap_or("").to_owned(),
        addresses,
    }))
}

#[cfg(target_os = "macos")]
fn probe(ipv6: bool) -> io::Result<Option<Route>> {
    let output = Command::new("/sbin/route")
        .args([
            "-n",
            "get",
            if ipv6 { "-inet6" } else { "-inet" },
            "default",
        ])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |key: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.trim().split_once(':')?;
            (name.trim() == key).then_some(value.trim())
        })
    };
    let Some(interface) = field("interface").filter(|v| valid_interface(v)) else {
        return Ok(None);
    };
    let Some(gateway) = field("gateway") else {
        return Ok(None);
    };
    let output = Command::new("/sbin/ifconfig").arg(interface).output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.lines().any(|line| line.trim() == "status: inactive") {
        return Ok(None);
    }
    let addresses = text
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with(if ipv6 { "inet6 " } else { "inet " }) || line.starts_with("status:")
        })
        .map(str::to_owned)
        .collect();
    Ok(Some(Route {
        ipv6,
        interface: interface.to_owned(),
        gateway: gateway.to_owned(),
        addresses,
    }))
}
