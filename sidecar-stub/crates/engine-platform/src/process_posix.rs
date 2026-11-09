//! Best-effort local ownership; ambiguous endpoints are never attributed.
use super::ProcessInfo;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::{collections::HashSet, net::SocketAddr};

fn info(pid: u32) -> Option<ProcessInfo> {
    if pid == std::process::id() {
        return None;
    }
    #[cfg(target_os = "linux")]
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .to_str()?
        .trim_end_matches(" (deleted)")
        .to_owned();
    #[cfg(target_os = "macos")]
    let path = {
        #[link(name = "proc")]
        extern "C" {
            fn proc_pidpath(pid: i32, buffer: *mut core::ffi::c_void, size: u32) -> i32;
        }
        let mut bytes = vec![0u8; 4096];
        if unsafe { proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) } <= 0 {
            return None;
        }
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).ok()?
    };
    let mut value = ProcessInfo::selector(&path);
    if value.name.as_deref() == Some("lemonvpn-kernel") {
        return None;
    }
    value.pid = Some(pid);
    Some(value)
}

#[cfg(target_os = "linux")]
fn address(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::from(u32::from_str_radix(ip, 16).ok()?.to_ne_bytes()),
        32 => {
            let mut bytes = [0; 16];
            for (index, part) in ip.as_bytes().chunks_exact(8).enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(
                    &u32::from_str_radix(std::str::from_utf8(part).ok()?, 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            IpAddr::from(bytes)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(target_os = "linux")]
pub(super) fn owner(source: SocketAddr, network: &str) -> Option<ProcessInfo> {
    use std::{fs, os::unix::fs::MetadataExt};
    if !matches!(network, "tcp" | "udp") {
        return None;
    }
    let table = fs::read_to_string(format!(
        "/proc/self/net/{network}{}",
        if source.is_ipv6() { "6" } else { "" }
    ))
    .ok()?;
    let mut inodes = HashSet::new();
    for row in table.lines().skip(1) {
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some(local) = address(fields[1]) else {
            continue;
        };
        if local.port() == source.port()
            && (local.ip() == source.ip() || (network == "udp" && local.ip().is_unspecified()))
        {
            if let Ok(inode) = fields[9].parse::<u64>() {
                if inode != 0 {
                    inodes.insert(inode);
                }
            }
        }
    }
    if inodes.is_empty() {
        return None;
    }
    let uid = fs::metadata("/proc/self").ok()?.uid();
    let mut owners = HashSet::new();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        if entry.metadata().ok().is_none_or(|m| m.uid() != uid) {
            continue;
        }
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = link
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if inodes.contains(&inode) {
                owners.insert(pid);
                break;
            }
        }
        if owners.len() > 1 {
            return None;
        }
    }
    let pid = *owners.iter().next()?;
    // Re-read the socket table after walking procfs, avoiding a vanished or
    // reused inode becoming a stale process condition.
    let current = fs::read_to_string(format!(
        "/proc/self/net/{network}{}",
        if source.is_ipv6() { "6" } else { "" }
    ))
    .ok()?;
    if !current.lines().skip(1).any(|r| {
        let f: Vec<_> = r.split_whitespace().collect();
        f.len() > 9
            && f[9]
                .parse::<u64>()
                .ok()
                .is_some_and(|i| inodes.contains(&i))
            && address(f[1]).is_some_and(|local| {
                local.port() == source.port()
                    && (local.ip() == source.ip()
                        || (network == "udp" && local.ip().is_unspecified()))
            })
    }) {
        return None;
    }
    info(pid)
}

#[cfg(target_os = "macos")]
pub(super) fn owner(source: SocketAddr, network: &str) -> Option<ProcessInfo> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if !matches!(network, "tcp" | "udp") {
        return None;
    }
    let selection = format!("{}:{}", network.to_uppercase(), source.port());
    let mut child = Command::new("/usr/sbin/lsof")
        .args(["-w", "-n", "-P", "-a", "-i", &selection, "-F0pfn"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(256 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_millis(1200);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    }
    let bytes = reader.join().ok()?;
    if bytes.len() == 256 * 1024 {
        return None;
    }
    let mut pid = None;
    let mut owners = HashSet::new();
    for field in bytes.split(|b| *b == 0) {
        let text = std::str::from_utf8(field).ok()?.trim_start_matches('\n');
        if let Some(value) = text.strip_prefix('p') {
            pid = value.parse::<u32>().ok();
        }
        if let Some(value) = text.strip_prefix('n') {
            let local = value.split("->").next()?.trim();
            let parsed = local.parse::<SocketAddr>().ok().or_else(|| {
                let (host, port) = local.rsplit_once(':')?;
                if host == "*" && network == "udp" {
                    Some(SocketAddr::new(
                        if source.is_ipv6() {
                            "::".parse().ok()?
                        } else {
                            "0.0.0.0".parse().ok()?
                        },
                        port.parse().ok()?,
                    ))
                } else {
                    None
                }
            });
            if parsed.is_some_and(|s| {
                s.port() == source.port()
                    && (s.ip() == source.ip() || (network == "udp" && s.ip().is_unspecified()))
            }) {
                if let Some(pid) = pid {
                    owners.insert(pid);
                }
            }
        }
    }
    if owners.len() != 1 {
        return None;
    }
    info(*owners.iter().next()?)
}
