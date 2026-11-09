//! Portable session fallback for desktops without a writable proxy API.
//! Existing applications use TUN. Shells read
//! a boot/PID-guarded script, so a dead client does not export a dead proxy.
use std::{
    collections::HashMap,
    fs, io,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
const ENV_KEYS: [&str; 8] = [
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];
type Environment = HashMap<String, String>;
static MANAGER_CACHE: Mutex<Option<(Instant, Environment)>> = Mutex::new(None);

// systemctl prints bare values or dollar-single-quoted C strings. Decode data;
// never evaluate the user's environment as shell code.
fn environment_value(text: &str) -> io::Result<String> {
    let Some(quoted) = text.strip_prefix("$'") else {
        return Ok(text.to_owned());
    };
    let inner = quoted
        .strip_suffix('\'')
        .ok_or_else(|| io::Error::other("无效会话环境值"))?;
    let bytes = inner.as_bytes();
    let mut output = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        at += 1;
        if byte != b'\\' {
            output.push(byte);
            continue;
        }
        let escaped = *bytes
            .get(at)
            .ok_or_else(|| io::Error::other("无效会话环境转义"))?;
        at += 1;
        let value = match escaped {
            b'\\' | b'\'' | b'"' => escaped,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'b' => 8,
            b'f' => 12,
            b'v' => 11,
            b'a' => 7,
            b'e' => 27,
            b'x' => {
                let part = bytes
                    .get(at..at + 2)
                    .ok_or_else(|| io::Error::other("无效会话环境转义"))?;
                let digits = std::str::from_utf8(part).map_err(io::Error::other)?;
                let value = u8::from_str_radix(digits, 16).map_err(io::Error::other)?;
                at += 2;
                value
            }
            b'0'..=b'7' => {
                let mut value = (escaped - b'0') as u16;
                let mut count = 1;
                while count < 3 && bytes.get(at).is_some_and(|c| matches!(*c, b'0'..=b'7')) {
                    value = value * 8 + (bytes[at] - b'0') as u16;
                    at += 1;
                    count += 1;
                }
                u8::try_from(value).map_err(io::Error::other)?
            }
            _ => return Err(io::Error::other("不支持的会话环境转义")),
        };
        output.push(value);
    }
    let value = String::from_utf8(output).map_err(io::Error::other)?;
    if value.contains('\0') {
        return Err(io::Error::other("无效会话环境值"));
    }
    Ok(value)
}
fn manager_values() -> io::Result<Environment> {
    let mut cache = MANAGER_CACHE
        .lock()
        .map_err(|_| io::Error::other("会话环境锁不可用"))?;
    if let Some((time, values)) = cache.as_ref() {
        if time.elapsed() < Duration::from_millis(300) {
            return Ok(values.clone());
        }
    }
    let text = crate::system_proxy::session_command("systemctl", &["--user", "show-environment"])
        .map_err(io::Error::other)?;
    let mut values = Environment::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if ENV_KEYS.contains(&key) {
            values.insert(key.to_owned(), environment_value(value)?);
        }
    }
    *cache = Some((Instant::now(), values.clone()));
    Ok(values)
}
pub fn get_setting(schema: &str, key: &str) -> io::Result<Option<String>> {
    match schema {
        "session" => get(key),
        "manager" if ENV_KEYS.contains(&key) => Ok(manager_values()?.get(key).cloned()),
        _ => Err(io::Error::other("未知会话代理项目")),
    }
}
pub fn set_setting(schema: &str, key: &str, value: Option<&str>) -> io::Result<()> {
    match schema {
        "session" => set(key, value),
        "manager" if ENV_KEYS.contains(&key) => {
            let outcome = if let Some(value) = value {
                crate::system_proxy::session_command(
                    "systemctl",
                    &["--user", "set-environment", &format!("{key}={value}")],
                )
            } else {
                crate::system_proxy::session_command(
                    "systemctl",
                    &["--user", "unset-environment", key],
                )
            };
            *MANAGER_CACHE
                .lock()
                .map_err(|_| io::Error::other("会话环境锁不可用"))? = None;
            outcome.map(|_| ()).map_err(io::Error::other)
        }
        _ => Err(io::Error::other("未知会话代理项目")),
    }
}
const START: &str = "# >>> LemonVPN session proxy >>>";
const END: &str = "# <<< LemonVPN session proxy <<<";
fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("缺少 HOME"))
}
fn config() -> io::Result<PathBuf> {
    Ok(std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or(home()?.join(".config")))
}
fn path(key: &str) -> io::Result<PathBuf> {
    Ok(match key {
        "exports" => config()?.join("lemonvpn/session-proxy.sh"),
        "fish" => config()?.join("fish/conf.d/lemonvpn-proxy.fish"),
        ".profile" | ".bashrc" | ".bash_profile" | ".bash_login" | ".zshenv" | ".zprofile" => {
            home()?.join(key)
        }
        _ => return Err(io::Error::other("未知会话代理项目")),
    })
}
fn hook(key: &str) -> bool {
    key.starts_with('.')
}
fn read(path: &std::path::Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn block(text: &str) -> Option<&str> {
    let start = text.find(START)?;
    let end = text[start..].find(END)? + start + END.len();
    Some(&text[start..end])
}
pub fn get(key: &str) -> io::Result<Option<String>> {
    let content = read(&path(key)?)?;
    Ok(if hook(key) {
        content.as_deref().and_then(block).map(str::to_owned)
    } else {
        content
    })
}
pub fn set(key: &str, value: Option<&str>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let requested = path(key)?;
    // Preserve dotfile symlinks managed by the user.
    let path = match fs::symlink_metadata(&requested) {
        Ok(metadata) if metadata.file_type().is_symlink() => requested.canonicalize()?,
        Ok(_) => requested,
        Err(e) if e.kind() == io::ErrorKind::NotFound => requested,
        Err(e) => return Err(e),
    };
    let current = read(&path)?;
    let next = if hook(key) {
        let mut text = current.clone().unwrap_or_default();
        if let Some(owned) = block(&text) {
            let at = text.find(owned).unwrap();
            text.replace_range(at..at + owned.len(), "");
        }
        if let Some(value) = value {
            if !text.ends_with('\n') && !text.is_empty() {
                text.push('\n');
            }
            text.push_str(value);
            text.push('\n');
        }
        if value.is_none() && text.trim().is_empty() {
            None
        } else {
            Some(text)
        }
    } else {
        value.map(str::to_owned)
    };
    if let Some(next) = next {
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("无效会话目录"))?;
        fs::create_dir_all(directory)?;
        let mode = if hook(key) {
            fs::metadata(&path)
                .map(|m| m.permissions().mode())
                .unwrap_or(0o600)
        } else {
            0o700
        };
        let temporary = path.with_extension(format!("lemonvpn-{}.tmp", std::process::id()));
        fs::write(&temporary, next)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        if read(&path)? != current {
            let _ = fs::remove_file(temporary);
            return Err(io::Error::other("会话文件已被修改，请重试"));
        }
        fs::rename(temporary, path)
    } else {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn settings(host: &str, port: u16) -> io::Result<Vec<(String, String, String)>> {
    let endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let vars = [
        ("http_proxy", format!("http://{endpoint}")),
        ("https_proxy", format!("http://{endpoint}")),
        ("all_proxy", format!("socks5://{endpoint}")),
        ("HTTP_PROXY", format!("http://{endpoint}")),
        ("HTTPS_PROXY", format!("http://{endpoint}")),
        ("ALL_PROXY", format!("socks5://{endpoint}")),
        ("no_proxy", "localhost,127.0.0.1,::1".into()),
        ("NO_PROXY", "localhost,127.0.0.1,::1".into()),
    ];
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let stat = fs::read_to_string("/proc/self/stat")?;
    let start = stat
        .rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .ok_or_else(|| io::Error::other("无法记录会话进程身份"))?;
    let observed = format!(
        "sed 's/^.*) //' /proc/{}/stat 2>/dev/null | cut -d ' ' -f20",
        std::process::id()
    );
    let condition=format!("[ \"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\" = {} ] && [ \"$({observed})\" = {} ]",quote(boot.trim()),quote(start));
    let mut exports = format!("# LemonVPN session proxy\nif {condition}; then\n");
    for (key, value) in &vars {
        exports.push_str(&format!("  export {key}={}\n", quote(value)));
    }
    exports.push_str("else\n");
    for (key, value) in &vars {
        exports.push_str(&format!(
            "  [ \"${{{key}-}}\" != {} ] || unset {key}\n",
            quote(value)
        ));
    }
    exports.push_str("fi\n");
    let mut fish=format!("set -l lemonvpn_proxy_boot (cat /proc/sys/kernel/random/boot_id 2>/dev/null)\nset -l lemonvpn_proxy_start ({observed})\nif test \"$lemonvpn_proxy_boot\" = {}; and test \"$lemonvpn_proxy_start\" = {}\n",quote(boot.trim()),quote(start));
    for (key, value) in &vars {
        fish.push_str(&format!("set -gx {key} {}\n", quote(value)));
    }
    fish.push_str("else\n");
    for (key, value) in &vars {
        fish.push_str(&format!(
            "if set -q {key}; and test \"${key}\" = {}; set -e {key}; end\n",
            quote(value)
        ));
    }
    fish.push_str("end\n");
    fish.push_str("set -e lemonvpn_proxy_boot lemonvpn_proxy_start\n");
    let script = path("exports")?.to_string_lossy().into_owned();
    let hook_text = format!(
        "{START}\nif [ -r {} ]; then . {}; fi\n{END}",
        quote(&script),
        quote(&script)
    );
    let mut rows = vec![
        ("session".into(), "exports".into(), exports),
        ("session".into(), "fish".into(), fish),
    ];
    let login = if home()?.join(".bash_profile").exists() {
        ".bash_profile"
    } else if home()?.join(".bash_login").exists() {
        ".bash_login"
    } else {
        ".profile"
    };
    for key in [login, ".bashrc", ".zshenv"] {
        rows.push(("session".into(), key.into(), hook_text.clone()));
    }
    if manager_values().is_ok() {
        for (key, value) in vars {
            rows.push(("manager".into(), key.into(), value));
        }
    }
    Ok(rows)
}
