//! User-session proxy settings: GSettings, KDE KConfig and guarded shell fallback.
//! Save before mutation; restore each value only while it still equals ours.
use super::ProxyStatus;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
static LOCK: Mutex<()> = Mutex::new(());
#[derive(Clone, Serialize, Deserialize)]
enum Backend {
    Gnome,
    Kde(u8),
    Schema(String),
    Environment,
}
#[derive(Clone, Serialize, Deserialize)]
struct Setting {
    schema: String,
    key: String,
    before: Option<String>,
    applied: String,
    #[serde(default)]
    previous: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct State {
    backend: Backend,
    owner_pid: u32,
    server: String,
    settings: Vec<Setting>,
}
const ABSENT: &str = "__LEMONVPN_ABSENT_8f502__";

fn directory() -> PathBuf {
    std::env::var_os("LEMONVPN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(crate::default_data_dir)
}
fn path() -> PathBuf {
    directory().join("system-proxy.json")
}
fn load() -> Result<Option<State>, String> {
    match fs::read(path()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("代理快照损坏：{e}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn save(state: &State) -> Result<(), String> {
    crate::managed::private_dir(&directory()).map_err(|e| e.to_string())?;
    let temporary = path().with_extension(format!("{}.tmp", std::process::id()));
    fs::write(
        &temporary,
        serde_json::to_vec(state).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(temporary, path()).map_err(|e| e.to_string())
}
fn tool(name: &str) -> Result<PathBuf, String> {
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .into_iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| format!("缺少桌面集成工具：{name}"))
}
pub(crate) fn run(name: &str, args: &[&str]) -> Result<String, String> {
    use std::io::Read;
    let mut child = Command::new(tool(name)?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let read = |mut stream: Box<dyn Read + Send>| {
        let mut bytes = Vec::new();
        stream
            .by_ref()
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 128 * 1024 {
            return Err("桌面设置命令输出过大".to_owned());
        }
        String::from_utf8(bytes).map_err(|e| e.to_string())
    };
    let out = std::thread::spawn(move || read(Box::new(stdout)));
    let err = std::thread::spawn(move || read(Box::new(stderr)));
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("桌面设置命令超时或失败".to_owned());
            }
        }
    };
    let output = out.join().map_err(|_| "桌面设置读取失败")??;
    let error = err.join().map_err(|_| "桌面设置读取失败")??;
    if status?.success() {
        Ok(output.trim().to_owned())
    } else {
        Err(format!("{name}：{}", error.trim()))
    }
}
fn detect() -> Result<Backend, String> {
    static CHOICE: std::sync::OnceLock<Result<Backend, String>> = std::sync::OnceLock::new();
    CHOICE.get_or_init(detect_inner).clone()
}
fn detect_inner() -> Result<Backend, String> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();
    if desktop.contains("KDE") {
        for v in [6, 5] {
            if tool(&format!("kreadconfig{v}")).is_ok() && tool(&format!("kwriteconfig{v}")).is_ok()
            {
                return Ok(Backend::Kde(v));
            }
        }
        return Ok(Backend::Environment);
    }
    if tool("gsettings").is_ok()
        && ["GNOME", "UNITY", "CINNAMON", "MATE", "BUDGIE", "PANTHEON"]
            .iter()
            .any(|name| desktop.contains(name))
    {
        let schemas = run("gsettings", &["list-schemas"]).unwrap_or_default();
        let preferred = if desktop.contains("MATE") {
            "org.mate.system.proxy"
        } else if desktop.contains("CINNAMON") {
            "org.cinnamon.system.proxy"
        } else {
            "org.gnome.system.proxy"
        };
        if schemas.lines().any(|s| s == preferred) {
            return Ok(Backend::Schema(preferred.to_owned()));
        }
        if !desktop.contains("MATE") && schemas.lines().any(|s| s == "org.gnome.system.proxy") {
            return Ok(Backend::Gnome);
        }
    }
    Ok(Backend::Environment)
}
pub fn supported() -> bool {
    detect().is_ok()
}
pub fn scope() -> String {
    if matches!(detect(), Ok(Backend::Environment)) {
        "session".into()
    } else {
        "desktop".into()
    }
}

impl Backend {
    fn get(&self, schema: &str, key: &str) -> Result<Option<String>, String> {
        match self {
            Self::Gnome | Self::Schema(_) => run("gsettings", &["get", schema, key]).map(Some),
            Self::Environment => {
                crate::session_proxy_linux::get_setting(schema, key).map_err(|e| e.to_string())
            }
            Self::Kde(v) => run(
                &format!("kreadconfig{v}"),
                &[
                    "--file",
                    "kioslaverc",
                    "--group",
                    schema,
                    "--key",
                    key,
                    "--default",
                    ABSENT,
                ],
            )
            .map(|v| if v == ABSENT { None } else { Some(v) }),
        }
    }
    fn set(&self, schema: &str, key: &str, value: Option<&str>) -> Result<(), String> {
        match self {
            Self::Gnome | Self::Schema(_) => {
                if run("gsettings", &["writable", schema, key])? != "true" {
                    return Err(format!("桌面策略禁止修改 {schema}.{key}"));
                }
                run(
                    "gsettings",
                    &["set", schema, key, value.ok_or("缺少代理设置")?],
                )?;
            }
            Self::Kde(v) => {
                let name = format!("kwriteconfig{v}");
                let mut args = vec!["--file", "kioslaverc", "--group", schema, "--key", key];
                if let Some(value) = value {
                    args.push(value)
                } else {
                    args.push("--delete")
                }
                run(&name, &args)?;
            }
            Self::Environment => crate::session_proxy_linux::set_setting(schema, key, value)
                .map_err(|e| e.to_string())?,
        }
        Ok(())
    }
    fn notify(&self) {
        if matches!(self, Self::Kde(_)) {
            let _ = run(
                "dbus-send",
                &[
                    "--session",
                    "--type=signal",
                    "/KIO/Scheduler",
                    "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                ],
            );
        }
    }
}
fn settings(
    backend: &Backend,
    host: &str,
    port: u16,
) -> Result<Vec<(String, String, String)>, String> {
    let mut rows = Vec::new();
    let mut push = |schema: &str, key: &str, value: String| {
        rows.push((schema.to_owned(), key.to_owned(), value))
    };
    match backend {
        Backend::Environment => {
            return crate::session_proxy_linux::settings(host, port).map_err(|e| e.to_string())
        }
        Backend::Gnome | Backend::Schema(_) => {
            let prefix = match backend {
                Backend::Schema(prefix) => prefix.as_str(),
                _ => "org.gnome.system.proxy",
            };
            for part in ["http", "https", "socks"] {
                let schema = format!("{prefix}.{part}");
                push(&schema, "host", format!("'{host}'"));
                push(&schema, "port", port.to_string());
            }
            push(
                &format!("{prefix}.http"),
                "use-authentication",
                "false".into(),
            );
            push(prefix, "use-same-proxy", "false".into());
            push(
                prefix,
                "ignore-hosts",
                "['localhost', '127.0.0.0/8', '::1']".into(),
            );
            push(prefix, "mode", "'manual'".into());
        }
        Backend::Kde(_) => {
            for (key, scheme) in [
                ("httpProxy", "http"),
                ("httpsProxy", "http"),
                ("socksProxy", "socks"),
            ] {
                push("Proxy Settings", key, format!("{scheme}://{host} {port}"));
            }
            push(
                "Proxy Settings",
                "NoProxyFor",
                "localhost,127.0.0.1,::1".into(),
            );
            push("Proxy Settings", "ReversedException", "false".into());
            push("Proxy Settings", "ProxyType", "1".into());
        }
    }
    Ok(rows)
}
fn server_parts(server: &str) -> Result<(String, u16), String> {
    let address: SocketAddr = server.parse().map_err(|_| "无效代理地址")?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("系统代理必须指向本机端口".into());
    }
    Ok((address.ip().to_string(), address.port()))
}
pub fn enable(server: &str) -> Result<(), String> {
    let _lock = LOCK.lock().unwrap();
    let (host, port) = server_parts(server)?;
    let mut state = match load()? {
        Some(state) => state,
        None => {
            let backend = detect()?;
            let mut values = Vec::new();
            for (schema, key, value) in settings(&backend, &host, port)? {
                let before = backend.get(&schema, &key)?;
                values.push(Setting {
                    schema,
                    key,
                    before,
                    applied: value,
                    previous: Vec::new(),
                });
            }
            State {
                backend,
                settings: values,
                owner_pid: std::process::id(),
                server: server.to_owned(),
            }
        }
    };
    state.owner_pid = std::process::id();
    state.server = server.to_owned();
    // Preserve each original value across a restart/port change.
    for (schema, key, value) in settings(&state.backend, &host, port)? {
        if let Some(entry) = state
            .settings
            .iter_mut()
            .find(|s| s.schema == schema && s.key == key)
        {
            if entry.applied != value && !entry.previous.contains(&entry.applied) {
                entry.previous.push(entry.applied.clone());
            }
            entry.applied = value;
        } else {
            // The user manager may become available after the first enable.
            let before = state.backend.get(&schema, &key)?;
            state.settings.push(Setting {
                schema,
                key,
                before,
                applied: value,
                previous: Vec::new(),
            });
        }
    }
    save(&state)?;
    let outcome = (|| {
        for value in &state.settings {
            if state.backend.get(&value.schema, &value.key)?.as_deref() == Some(&value.applied) {
                continue;
            }
            state
                .backend
                .set(&value.schema, &value.key, Some(&value.applied))?;
            if state.backend.get(&value.schema, &value.key)?.as_deref() != Some(&value.applied) {
                return Err(format!("桌面未接受 {}.{}", value.schema, value.key));
            }
        }
        Ok(())
    })();
    state.backend.notify();
    if let Err(error) = outcome {
        restore(&state)?;
        return Err(error);
    }
    Ok(())
}
fn restore(state: &State) -> Result<(), String> {
    let mut first = None;
    // A user may have changed one endpoint while leaving 'manual' unchanged.
    // Keep that user's mode rather than disabling their newly selected proxy.
    let mut user_changed_endpoint = false;
    for value in &state.settings {
        if value.key == "mode" || value.key == "ProxyType" {
            continue;
        }
        let current = state.backend.get(&value.schema, &value.key)?;
        if current != value.before
            && current.as_deref() != Some(&value.applied)
            && !current.as_ref().is_some_and(|v| value.previous.contains(v))
        {
            user_changed_endpoint = true;
        }
    }
    for value in state.settings.iter().rev() {
        if user_changed_endpoint && (value.key == "mode" || value.key == "ProxyType") {
            continue;
        }
        let result = (|| {
            let current = state.backend.get(&value.schema, &value.key)?;
            if current == value.before {
                return Ok(());
            }
            if current.as_deref() == Some(&value.applied)
                || current.as_ref().is_some_and(|v| value.previous.contains(v))
            {
                state
                    .backend
                    .set(&value.schema, &value.key, value.before.as_deref())?;
            }
            Ok::<(), String>(())
        })();
        if let Err(e) = result {
            first.get_or_insert(e);
        }
    }
    state.backend.notify();
    if let Some(e) = first {
        return Err(e);
    }
    fs::remove_file(path()).map_err(|e| e.to_string())
}
pub fn disable_for(server: &str) -> Result<(), String> {
    disable_owned(server, std::process::id())
}
pub fn disable_owned(server: &str, owner: u32) -> Result<(), String> {
    let _lock = LOCK.lock().unwrap();
    if let Some(state) = load()? {
        if state.server == server && state.owner_pid == owner {
            restore(&state)?;
        }
    }
    Ok(())
}
pub fn recover_stale() -> Result<(), String> {
    let _lock = LOCK.lock().unwrap();
    if let Some(state) = load()? {
        let alive = Path::new(&format!("/proc/{}", state.owner_pid)).exists();
        let address: SocketAddr = state.server.parse().map_err(|_| "无效代理快照")?;
        if !alive
            && address.ip().is_loopback()
            && TcpStream::connect_timeout(&address, Duration::from_millis(150)).is_err()
        {
            restore(&state)?;
        }
    }
    Ok(())
}
pub fn status() -> ProxyStatus {
    let _lock = LOCK.lock().unwrap();
    let result = (|| {
        let Some(state) = load()? else {
            return Ok((false, None));
        };
        let mut all = true;
        for value in &state.settings {
            all &= state.backend.get(&value.schema, &value.key)?.as_deref() == Some(&value.applied);
        }
        Ok::<_, String>((all, Some(state.server)))
    })();
    match result {
        Ok((enabled, server)) => ProxyStatus {
            enabled,
            server,
            error: None,
        },
        Err(error) => ProxyStatus {
            enabled: false,
            server: None,
            error: Some(error),
        },
    }
}
