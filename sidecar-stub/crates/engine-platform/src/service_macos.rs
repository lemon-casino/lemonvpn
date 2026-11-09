//! macOS TUN broker: root LaunchDaemon, a root-owned Unix domain socket,
//! peer-euid validation, fixed config and an owned process group that ends
//! when the engine exits. The wire protocol matches the Windows pipe broker.
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use std::os::unix::net::UnixStream;

const NAME: &str = "org.lemonvpn.tun";
const PLIST: &str = "/Library/LaunchDaemons/org.lemonvpn.tun.plist";
const SOCKET: &str = "/var/run/lemonvpn-tun.sock";
const PRODUCT: &str = "/Library/Application Support/LemonVPN";
const SERVICE_DIR: &str = "/Library/Application Support/LemonVPN/Service";
const SOL_LOCAL: i32 = 0;
const LOCAL_PEERPID: i32 = 0x0002;

static STOP: AtomicBool = AtomicBool::new(false);
static SESSION: Mutex<Option<Session>> = Mutex::new(None);
struct Session {
    pid: u32,
    process: crate::managed::CoreProcess,
    config: Value,
    // Drop capture before its egress routes.
    egress: crate::egress::Egress,
    recovering: Option<String>,
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

extern "C" {
    fn geteuid() -> u32;
    fn getpeereid(socket: i32, uid: *mut u32, gid: *mut u32) -> i32;
    fn getsockopt(
        socket: i32,
        level: i32,
        name: i32,
        value: *mut core::ffi::c_void,
        length: *mut u32,
    ) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
    fn chown(path: *const core::ffi::c_char, owner: u32, group: u32) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
}

/// launchd terminates the daemon with SIGTERM on bootout/uninstall/reinstall.
/// The default disposition would skip the process teardown and orphan the
/// owned core, so every caught signal only flips the stop flag.
extern "C" fn stop_requested(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn is_elevated() -> bool {
    unsafe { geteuid() == 0 }
}
pub fn current_uid() -> io::Result<u32> {
    let uid = unsafe { geteuid() };
    (uid != 0)
        .then_some(uid)
        .ok_or_else(|| err("当前进程不应以 root 运行"))
}

/// The service binary shipped next to the engine: `Contents/MacOS/lemonvpn-*`
/// resolves to `Contents/Resources/lemonvpn-service` inside a .app bundle.
fn bundled_service_path() -> Option<PathBuf> {
    crate::managed::resource_path("lemonvpn-service")
}

pub fn installed() -> bool {
    Path::new(PLIST).is_file() && Path::new(SERVICE_DIR).join("lemonvpn-service").is_file()
}

/// Compare files only: detecting an obsolete service must not start it or
/// contact its old IPC implementation while the user is using the client.
pub fn update_required() -> bool {
    use sha2::{Digest, Sha256};
    use std::time::SystemTime;
    static EXPECTED: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    static CACHED: Mutex<Option<(SystemTime, u64, bool)>> = Mutex::new(None);
    if !installed() {
        return false;
    }
    let expected = EXPECTED.get_or_init(|| {
        bundled_service_path().and_then(|file| fs::read(file).ok()).map(|bytes| Sha256::digest(bytes).into())
    });
    let Some(expected) = expected else {
        return true;
    };
    let path = Path::new(SERVICE_DIR).join("lemonvpn-service");
    let Ok(metadata) = fs::metadata(&path) else {
        return true;
    };
    let Ok(modified) = metadata.modified() else {
        return true;
    };
    let mut cached = CACHED.lock().unwrap();
    if let Some((time, size, required)) = *cached {
        if time == modified && size == metadata.len() {
            return required;
        }
    }
    let required = fs::read(&path)
        .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)) != *expected)
        .unwrap_or(true);
    *cached = Some((modified, metadata.len(), required));
    required
}

/// Bounded reads/writes on the socket: timeouts only gate each chunk, the
/// deadline decides when the whole transfer has failed.
fn transfer(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TUN 服务通信超时"));
        }
        let step = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(500));
        stream.set_read_timeout(Some(step))?;
        stream.set_write_timeout(Some(step))?;
        let result = if write {
            stream.write(&bytes[offset..])
        } else {
            stream.read(&mut bytes[offset..])
        };
        match result {
            Ok(0) => {
                return Err(io::Error::new(
                    if write {
                        io::ErrorKind::WriteZero
                    } else {
                        io::ErrorKind::UnexpectedEof
                    },
                    if write {
                        "TUN 服务写入未完成"
                    } else {
                        "TUN 服务响应提前结束"
                    },
                ))
            }
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn send(stream: &mut UnixStream, value: &Value, deadline: Instant) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 128 * 1024 {
        return Err(err("服务消息过大"));
    }
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    transfer(stream, &mut frame, true, deadline)
}
fn receive(stream: &mut UnixStream, deadline: Instant) -> io::Result<Value> {
    let mut len = [0; 4];
    transfer(stream, &mut len, false, deadline)?;
    let length = u32::from_le_bytes(len) as usize;
    if length > 128 * 1024 {
        return Err(err("服务消息过大"));
    }
    let mut bytes = vec![0; length];
    transfer(stream, &mut bytes, false, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| err("服务消息无效"))
}

pub fn request(value: &Value) -> io::Result<Value> {
    if update_required() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "TUN 服务需要更新，请在 TUN 模式内点击修复服务并完成管理员授权",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(18);
    let mut stream = loop {
        match UnixStream::connect(SOCKET) {
            Ok(stream) => break stream,
            Err(e)
                if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused)
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(30))
            }
            Err(e) => return Err(e),
        }
    };
    send(&mut stream, value, deadline)?;
    let response = receive(&mut stream, deadline)?;
    let mut ack = [1];
    let _ = transfer(&mut stream, &mut ack, true, deadline);
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("TUN 服务请求失败")));
    }
    Ok(response)
}

fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut pid: i32 = 0;
    let mut length = std::mem::size_of::<i32>() as u32;
    let ok = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&mut pid as *mut i32).cast(),
            &mut length,
        )
    };
    if ok != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid as u32)
}
fn process_alive(pid: u32) -> bool {
    // Signal 0 only probes permission and existence; a dead pid reports ESRCH.
    unsafe { kill(pid as i32, 0) == 0 }
}

fn handle(stream: &mut UnixStream, owner: u32) -> io::Result<Value> {
    use std::os::unix::io::AsRawFd;
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if uid != owner {
        return Err(err("当前用户无权使用此服务"));
    }
    let pid = peer_pid(stream)?;
    let value = receive(stream, Instant::now() + Duration::from_secs(3));
    let result = (|| {
        let value = value?;
        let mut session = SESSION.lock().unwrap();
        if session.as_ref().is_some_and(|s| s.pid != pid) {
            return Err(err("TUN 已由其他引擎使用"));
        }
        match value.get("action").and_then(Value::as_str).unwrap_or("") {
            "start" => {
                if session.is_some() {
                    return Ok(json!({"ok":true,"enabled":true}));
                }
                let port = value
                    .get("router_port")
                    .and_then(Value::as_u64)
                    .filter(|p| *p >= 1024 && *p <= 65535)
                    .ok_or_else(|| err("无效引擎端口"))? as u16;
                let password = value
                    .get("password")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("缺少桥接凭证"))?;
                let dns_port = value
                    .get("dns_port")
                    .and_then(Value::as_u64)
                    .filter(|p| *p >= 1024 && *p <= 65535)
                    .ok_or_else(|| err("无效 DNS 端口"))? as u16;
                let mut config = crate::tun_bridge::configuration(port, dns_port, password)?;
                crate::dns_settings::DnsSettings::from_request(&value)?.apply(&mut config);
                crate::tun_bridge::apply_processes(
                    &mut config,
                    &crate::tun_bridge::process_list(&value)?,
                )?;
                // RAII also rolls back when secret generation/core startup fails.
                let egress = crate::egress::Egress::new()?;
                let binary = std::env::current_exe()?
                    .parent()
                    .ok_or_else(|| err("无效服务目录"))?
                    .join(crate::managed::CORE_BINARY_NAME);
                let directory = binary
                    .parent()
                    .ok_or_else(|| err("无效服务目录"))?
                    .join("runtime");
                let process =
                    crate::managed::CoreProcess::start(&binary, directory, config.clone(), crate::managed::random_secret()?)?;
                *session = Some(Session {
                    pid,
                    process,
                    config,
                    egress,
                    recovering: None,
                });
                Ok(json!({"ok":true,"enabled":true}))
            }
            "dns_settings" => {
                let settings = crate::dns_settings::DnsSettings::from_request(&value)?;
                let session = session.as_mut().ok_or_else(||err("TUN 未运行"))?;
                let mut next = session.config.clone();
                settings.apply(&mut next);
                crate::dns_settings::hot_apply(&session.process,&session.config,&next)?;
                session.config = next;
                Ok(json!({"ok":true,"enabled":true}))
            }
            "process_rules" => {
                let names = crate::tun_bridge::process_list(&value)?;
                let session = session.as_mut().ok_or_else(|| err("TUN 未运行"))?;
                let mut next = session.config.clone();
                crate::tun_bridge::apply_processes(&mut next, &names)?;
                session.process.configure(next.clone())?;
                session.config = next;
                Ok(json!({"ok":true,"enabled":true}))
            }
            "flush_dns" => {
                let session = session.as_ref().ok_or_else(|| err("TUN 未运行"))?;
                session.process.request("POST", "/cache/dns/flush", None)?;
                Ok(json!({"ok":true,"enabled":true}))
            }
            "stop" => {
                session.take();
                Ok(json!({"ok":true,"enabled":false}))
            }
            "status" => {
                if session.as_ref().is_some_and(|s|!process_alive(s.pid)) {session.take();}
                let enabled=session.is_some();
                let recovering=session.as_mut().and_then(|s| {
                    if !s.process.alive() {Some("协议内核恢复中".to_owned())}else{s.recovering.clone()}
                });
                Ok(json!({"ok":true,"enabled":enabled,"recovering":recovering,"dns_settings_version":1}))
            }
            _ => Err(err("未知服务操作")),
        }
    })();
    result
}

fn run(owner: u32) -> io::Result<()> {
    let _instance=crate::egress::lock_broker()?;
    // A previous daemon may have been hard-killed with a session still up;
    // only this service ever spawns the core from the protected directory.
    let _ = Command::new("/usr/bin/pkill")
        .arg("-f")
        .arg(format!("{SERVICE_DIR}/{}", crate::managed::CORE_BINARY_NAME))
        .status();
    for signum in [1, 2, 15] {
        unsafe { signal(signum, stop_requested as extern "C" fn(i32) as usize) };
    }
    crate::egress::cleanup_stale()?;
    let _ = fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))?;
    let watcher = thread::spawn(|| {
        while !STOP.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(250));
            let mut session = SESSION.lock().unwrap();
            if session.as_ref().is_some_and(|s| !process_alive(s.pid)) {
                session.take();
            } else if let Some(session) = session.as_mut() {
                let result = (|| {
                    let mut changed=session.egress.refresh()?;
                    if !session.process.alive() && session.egress.routes.any() {
                        let executable=std::env::current_exe()?;
                        let directory=executable.parent().ok_or_else(||err("无效服务目录"))?;
                        let next=crate::managed::CoreProcess::start(
                            &directory.join(crate::managed::CORE_BINARY_NAME),
                            directory.join("runtime"),
                            session.config.clone(),crate::managed::random_secret()?,
                        )?;
                        session.process=next;
                        changed=true;
                    }
                    if changed { session.process.request("DELETE", "/connections", None)?; }
                    if session.egress.routes.any() && (changed || session.recovering.is_some()) {
                        session.process.configure(session.config.clone())?;
                        session.process.request("POST", "/cache/dns/flush", None)?;
                    }
                    if !session.egress.routes.any() {
                        return Err(io::Error::new(io::ErrorKind::NotConnected,"等待网络恢复"));
                    }
                    Ok::<(),io::Error>(())
                })();
                session.recovering = result.err().map(|e| e.to_string());
            }
        }
        SESSION.lock().unwrap().take();
    });
    listener.set_nonblocking(true)?;
    while !STOP.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut stream = stream;
                let _ = stream.set_nonblocking(false);
                let response = match handle(&mut stream, owner) {
                    Ok(v) => v,
                    Err(e) => json!({"ok":false,"error":e.to_string()}),
                };
                if send(&mut stream, &response, Instant::now() + Duration::from_secs(2)).is_ok() {
                    let mut ack = [0];
                    let _ = transfer(
                        &mut stream,
                        &mut ack,
                        false,
                        Instant::now() + Duration::from_secs(2),
                    );
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200))
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    let _ = watcher.join();
    let _ = fs::remove_file(SOCKET);
    Ok(())
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(err("服务目录不允许使用符号链接"));
    }
    Ok(())
}

/// `fs::copy` inherits the source's owner through fcopyfile, which would leave
/// the root-executed binaries writable by the installing user. Force root:wheel.
fn root_own(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let text = CString::new(path.as_os_str().as_bytes())?;
    if unsafe { chown(text.as_ptr(), 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn plist_content(executable: &str, owner: u32) -> String {
    let executable = xml_escape(executable);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{executable}</string>
    <string>--run</string>
    <string>--owner-uid</string>
    <string>{owner}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#
    )
}

fn launchctl(args: &[&str]) -> io::Result<bool> {
    Command::new("/bin/launchctl").args(args).status().map(|s| s.success())
}

fn install(owner: u32) -> io::Result<()> {
    if !is_elevated() {
        return Err(err("安装 TUN 服务需要管理员权限"));
    }
    let source = std::env::current_exe()?
        .parent()
        .ok_or_else(|| err("无效安装目录"))?
        .to_path_buf();
    use sha2::{Digest, Sha256};
    let core_bytes = fs::read(source.join(crate::managed::CORE_BINARY_NAME))?;
    let digest = Sha256::digest(&core_bytes);
    let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if actual != include_str!("../assets/mihomo-darwin.sha256").trim() {
        return Err(err("协议内核校验失败，拒绝安装提权服务"));
    }
    let names = [
        "lemonvpn-service",
        crate::managed::CORE_BINARY_NAME,
        "mihomo.LICENSE.txt",
    ];
    let product = Path::new(PRODUCT);
    if product.exists() {
        reject_symlink(product)?;
    }
    let directory = Path::new(SERVICE_DIR);
    if directory.exists() {
        reject_symlink(directory)?;
    }
    // The old daemon must release the binaries before they are replaced.
    let _ = launchctl(&["bootout", &format!("system/{NAME}")]);
    thread::sleep(Duration::from_millis(300));
    fs::create_dir_all(product)?;
    fs::set_permissions(product, fs::Permissions::from_mode(0o755))?;
    root_own(product)?;
    // World-readable but root-writable, like the Windows service directory:
    // the unprivileged client must stat and hash the installed binaries.
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    root_own(directory)?;
    let executable = directory.join("lemonvpn-service");
    for name in names {
        let file = source.join(name);
        if !file.is_file() {
            return Err(err(format!("安装包缺少 {name}")));
        }
        let target = directory.join(name);
        if target.exists() {
            reject_symlink(&target)?;
        }
        fs::copy(&file, &target)?;
        // Binaries stay executable by everyone yet writable by root only.
        let mode = if name.ends_with(".txt") { 0o644 } else { 0o755 };
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        root_own(&target)?;
    }
    if !executable.is_file() {
        return Err(err("服务程序安装失败"));
    }
    fs::write(PLIST, plist_content(&executable.display().to_string(), owner))?;
    fs::set_permissions(PLIST, fs::Permissions::from_mode(0o644))?;
    root_own(Path::new(PLIST))?;
    let bootstrapped = launchctl(&["bootstrap", "system", PLIST])?;
    if !bootstrapped {
        let _ = fs::remove_file(PLIST);
        return Err(err("无法注册 TUN 服务（launchctl bootstrap）"));
    }
    Ok(())
}

fn uninstall() -> io::Result<()> {
    if !is_elevated() {
        return Err(err("卸载 TUN 服务需要管理员权限"));
    }
    if !installed() {
        return Err(err("TUN 服务尚未安装"));
    }
    let _ = launchctl(&["bootout", &format!("system/{NAME}")]);
    fs::remove_file(PLIST)?;
    fs::remove_dir_all(SERVICE_DIR)?;
    Ok(())
}

pub fn entry() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let owner = |args: &[String]| -> io::Result<u32> {
        args.windows(2)
            .find(|w| w[0] == "--owner-uid")
            .and_then(|w| w[1].parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .ok_or_else(|| err("缺少用户标识"))
    };
    if args.iter().any(|a| a == "--install") {
        return install(owner(&args)?);
    }
    if args.iter().any(|a| a == "--uninstall") {
        return uninstall();
    }
    run(owner(&args)?)
}
