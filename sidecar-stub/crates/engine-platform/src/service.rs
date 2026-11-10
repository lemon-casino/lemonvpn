//! Windows TUN broker: owner-SID pipe ACL, peer PID validation, fixed config,
//! bounded IPC and an owned process/job that ends when the engine exits.
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_support::Win32::{
    Foundation::*,
    Security::Authorization::*,
    Security::*,
    System::{Pipes::*, Threading::*},
};

const NAME: &str = "LemonVPN.Tun";
const PIPE: &str = r"\\.\pipe\LemonVPN.Tun.v2";
#[cfg(target_arch = "aarch64")]
const DRIVER_SHA256: &str = include_str!("../assets/wintun-arm64.sha256");
#[cfg(not(target_arch = "aarch64"))]
const DRIVER_SHA256: &str = include_str!("../assets/wintun.sha256");
#[cfg(target_arch = "aarch64")]
const KERNEL_SHA256: &str = include_str!("../assets/mihomo-arm64.sha256");
#[cfg(not(target_arch = "aarch64"))]
const KERNEL_SHA256: &str = include_str!("../assets/mihomo.sha256");
#[path = "pipe_io.rs"]
mod pipe_io;
static OWNER: OnceLock<String> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
static SESSION: Mutex<Option<Session>> = Mutex::new(None);
struct Session {
    pid: u32,
    parent: usize,
    process: crate::managed::CoreProcess,
    config: Value,
}
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.parent as HANDLE);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn sid_for_process(process: HANDLE) -> io::Result<String> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
        let mut bytes = vec![0u64; length as usize / 8 + 1];
        if GetTokenInformation(
            token,
            TokenUser,
            bytes.as_mut_ptr().cast(),
            length,
            &mut length,
        ) == 0
        {
            CloseHandle(token);
            return Err(io::Error::last_os_error());
        }
        let user = &*bytes.as_ptr().cast::<TOKEN_USER>();
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            CloseHandle(token);
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        CloseHandle(token);
        Ok(sid)
    }
}
pub fn current_sid() -> io::Result<String> {
    sid_for_process(unsafe { GetCurrentProcess() })
}
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut length = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut length,
        ) != 0
            && elevation.TokenIsElevated != 0;
        CloseHandle(token);
        ok
    }
}
pub fn installed() -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .ok()
        .and_then(|m| m.open_service(NAME, ServiceAccess::QUERY_STATUS).ok())
        .is_some()
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
        let file = std::env::current_exe()
            .ok()?
            .parent()?
            .join("lemonvpn-service.exe");
        Some(Sha256::digest(fs::read(file).ok()?).into())
    });
    let Some(expected) = expected else {
        return true;
    };
    let Some(path) = program_files_dir()
        .ok()
        .map(|p| p.join("LemonVPN/Service/lemonvpn-service.exe"))
    else {
        return true;
    };
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

fn transfer(file: &mut File, bytes: &mut [u8], write: bool, deadline: Instant) -> io::Result<()> {
    pipe_io::transfer(file, bytes, write, deadline, &STOP)
}
fn send(file: &mut File, value: &Value, deadline: Instant) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 128 * 1024 {
        return Err(err("服务消息过大"));
    }
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    transfer(file, &mut frame, true, deadline)
}
fn receive(file: &mut File, deadline: Instant) -> io::Result<Value> {
    let mut len = [0; 4];
    transfer(file, &mut len, false, deadline)?;
    let length = u32::from_le_bytes(len) as usize;
    if length > 128 * 1024 {
        return Err(err("服务消息过大"));
    }
    let mut bytes = vec![0; length];
    transfer(file, &mut bytes, false, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| err("服务消息无效"))
}

pub fn request(value: &Value) -> io::Result<Value> {
    if update_required() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "TUN 服务需要更新，请在 TUN 模式内点击修复服务并完成管理员授权",
        ));
    }
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(err)?;
    let service = manager
        .open_service(NAME, ServiceAccess::QUERY_STATUS)
        .map_err(err)?;
    if service.query_status().map_err(err)?.current_state == ServiceState::Stopped {
        if value.get("action").and_then(Value::as_str) == Some("start") {
            manager
                .open_service(NAME, ServiceAccess::START)
                .map_err(err)?
                .start::<&str>(&[])
                .map_err(err)?;
        } else {
            return Ok(json!({"ok":true,"enabled":false,"dns_settings_version":2}));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(18);
    let mut file = loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(windows_support::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED)
            .open(PIPE)
        {
            Ok(f) => break f,
            Err(e) if matches!(e.raw_os_error(), Some(2 | 231)) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(30))
            }
            Err(e) => return Err(e),
        }
    };
    // Only accept the registered service as the server (prevents pipe squatting).
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(file.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(err)?;
    let status = manager
        .open_service(NAME, ServiceAccess::QUERY_STATUS)
        .map_err(err)?
        .query_status()
        .map_err(err)?;
    if status.process_id != Some(pid) {
        return Err(err("TUN 服务身份不匹配"));
    }
    send(&mut file, value, deadline)?;
    let response = receive(&mut file, deadline)?;
    let mut ack = [1];
    let _ = transfer(&mut file, &mut ack, true, deadline);
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("TUN 服务请求失败")));
    }
    Ok(response)
}

fn handle(file: &mut File, owner: &str) -> io::Result<Value> {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(file.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, pid) };
    if parent.is_null() {
        return Err(io::Error::last_os_error());
    }
    let sid = sid_for_process(parent);
    if !matches!(sid.as_deref(),Ok(value) if value==owner) {
        unsafe {
            CloseHandle(parent);
        }
        return Err(err("当前用户无权使用此服务"));
    }
    let value = receive(file, Instant::now() + Duration::from_secs(3));
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
                let binary = std::env::current_exe()?
                    .parent()
                    .ok_or_else(|| err("无效服务目录"))?
                    .join(crate::managed::CORE_BINARY_NAME);
                let directory = binary
                    .parent()
                    .ok_or_else(|| err("无效服务目录"))?
                    .join("runtime");
                let mut random = [0u8; 32];
                if unsafe {
                    windows_support::Win32::Security::Cryptography::BCryptGenRandom(
                        std::ptr::null_mut(),
                        random.as_mut_ptr(),
                        32,
                        2,
                    )
                } < 0
                {
                    return Err(err("无法生成服务凭证"));
                }
                let secret = random.iter().map(|b| format!("{b:02x}")).collect();
                let process =
                    crate::managed::CoreProcess::start(&binary, directory, config.clone(), secret)?;
                let owned = unsafe { OpenProcess(0x00100000, 0, pid) };
                if owned.is_null() {
                    return Err(io::Error::last_os_error());
                }
                *session = Some(Session {
                    pid,
                    parent: owned as usize,
                    process,
                    config,
                });
                Ok(json!({"ok":true,"enabled":true}))
            }
            "dns_artifact_begin" | "dns_artifact_part" | "dns_artifact_commit" => crate::dns_artifact::handle(&value).unwrap(),
            "dns_settings" => {
                let settings = crate::dns_settings::DnsSettings::from_request(&value)?;
                let session = session.as_mut().ok_or_else(||err("TUN 未运行"))?;
                let mut next = session.config.clone();
                settings.apply(&mut next);
                crate::dns_settings::hot_apply(&session.process,&session.config,&next)?;
                session.config = next;
                Ok(json!({"ok":true,"enabled":true,"dns_settings_version":2,"dns_settings_sha256":crate::dns_artifact::settings_digest(&settings)?}))
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
            "flush_fakeip" => {
                let session = session.as_ref().ok_or_else(|| err("TUN 未运行"))?;
                session.process.request("POST", "/cache/fakeip/flush", None)?;
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
                let enabled = session.as_mut().is_some_and(|s| s.process.alive());
                if !enabled {
                    session.take();
                }
                Ok(json!({"ok":true,"enabled":enabled,"dns_settings_version":2}))
            }
            _ => Err(err("未知服务操作")),
        }
    })();
    unsafe {
        CloseHandle(parent);
    }
    result
}

windows_service::define_windows_service!(service_entry, service_main);
fn service_main(_: Vec<OsString>) {
    let _ = run();
}
fn run() -> io::Result<()> {
    let status = service_control_handler::register(NAME, |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(err)?;
    let state = |current_state| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    status
        .set_service_status(state(ServiceState::Running))
        .map_err(err)?;
    let watcher = thread::spawn(|| {
        while !STOP.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(250));
            let mut session = SESSION.lock().unwrap();
            if session.as_ref().is_some_and(
                |s| unsafe { WaitForSingleObject(s.parent as HANDLE, 0) } != WAIT_TIMEOUT,
            ) {
                session.take();
            }
        }
        SESSION.lock().unwrap().take();
    });
    let owner = OWNER.get().ok_or_else(|| err("服务缺少用户标识"))?;
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner})"));
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let pipe = unsafe {
        CreateNamedPipeW(
            wide(PIPE).as_ptr(),
            3 | 0x00080000 | windows_support::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            8192,
            8192,
            1000,
            &mut attributes,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        STOP.store(true, Ordering::Relaxed);
        unsafe {
            LocalFree(descriptor);
        }
        let _ = watcher.join();
        let _ = status.set_service_status(state(ServiceState::Stopped));
        return Err(error);
    }
    let mut file = unsafe { File::from_raw_handle(pipe) };
    // Reuse the first secured instance. Recreating it with FIRST_PIPE_INSTANCE
    // can fail while the previous client is still closing its own handle.
    while !STOP.load(Ordering::Relaxed) {
        let connected = pipe_io::connect(&file, &STOP).is_ok();
        if connected {
            let response = match handle(&mut file, owner) {
                Ok(v) => v,
                Err(e) => json!({"ok":false,"error":e.to_string()}),
            };
            if send(
                &mut file,
                &response,
                Instant::now() + Duration::from_secs(2),
            )
            .is_ok()
            {
                let mut ack = [0];
                let _ = transfer(
                    &mut file,
                    &mut ack,
                    false,
                    Instant::now() + Duration::from_secs(2),
                );
            }
        }
        unsafe {
            DisconnectNamedPipe(pipe);
        }
    }
    drop(file);
    unsafe {
        LocalFree(descriptor);
    }
    STOP.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    status
        .set_service_status(state(ServiceState::Stopped))
        .map_err(err)?;
    Ok(())
}

pub fn entry() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|a| a == "--install") {
        let owner = args
            .windows(2)
            .find(|w| w[0] == "--owner-sid")
            .map(|w| w[1].clone())
            .ok_or_else(|| err("缺少用户标识"))?;
        if !owner.starts_with("S-1-")
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
        {
            return Err(err("无效用户标识"));
        }
        return install(&owner);
    }
    if args.iter().any(|a| a == "--uninstall") {
        return uninstall();
    }
    let owner = args
        .windows(2)
        .find(|w| w[0] == "--owner-sid")
        .map(|w| w[1].clone())
        .ok_or_else(|| err("缺少用户标识"))?;
    let _ = OWNER.set(owner);
    service_dispatcher::start(NAME, service_entry).map_err(err)
}

fn reject_reparse(path: &std::path::Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    if fs::symlink_metadata(path)?.file_attributes() & 0x400 != 0 {
        return Err(err("服务目录不允许使用重解析点"));
    }
    Ok(())
}
fn protect_program(path: &std::path::Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let text = wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)");
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let ok = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let error = io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor);
    }
    if ok == 0 {
        return Err(error);
    }
    Ok(())
}

fn program_files_dir() -> io::Result<PathBuf> {
    use windows_support::Win32::System::Registry::*;
    let mut path = vec![0u16; 32768];
    let mut length = (path.len() * 2) as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion").as_ptr(),
            wide("ProgramFilesDir").as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            std::ptr::null_mut(),
            path.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let length = (length as usize / 2).saturating_sub(1).min(path.len());
    let result = PathBuf::from(String::from_utf16_lossy(&path[..length]));
    if !result.is_absolute() {
        return Err(err("系统程序目录无效"));
    }
    Ok(result)
}

fn install(owner: &str) -> io::Result<()> {
    if !is_elevated() {
        return Err(err("安装 TUN 服务需要管理员权限"));
    }
    let source = std::env::current_exe()?
        .parent()
        .ok_or_else(|| err("无效安装目录"))?
        .to_path_buf();
    use sha2::{Digest, Sha256};
    let core_bytes = fs::read(source.join(crate::managed::CORE_BINARY_NAME))?;
    let driver_bytes = fs::read(source.join("wintun.dll"))?;
    let driver_hash: String = Sha256::digest(&driver_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if driver_hash != DRIVER_SHA256.trim() {
        return Err(err("Wintun 校验失败，拒绝安装提权服务"));
    }
    let digest = Sha256::digest(&core_bytes);
    let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if actual != KERNEL_SHA256.trim() {
        return Err(err("协议内核校验失败，拒绝安装提权服务"));
    }
    let program_files = program_files_dir()?;
    reject_reparse(&program_files)?;
    let product = program_files.join("LemonVPN");
    if product.exists() {
        reject_reparse(&product)?;
    } else {
        fs::create_dir(&product)?;
    }
    protect_program(&product)?;
    let directory = product.join("Service");
    if directory.exists() {
        reject_reparse(&directory)?;
    } else {
        fs::create_dir(&directory)?;
    }
    // The owner must also be protected: a filtered administrator token must
    // not retain file-owner WRITE_DAC through the original per-user SID.
    protect_program(&directory)?;
    use std::os::windows::process::CommandExt;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(err)?;
    if let Ok(service) = manager.open_service(
        NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        let _ = service.stop();
        for _ in 0..100 {
            if service.query_status().map_err(err)?.current_state == ServiceState::Stopped {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        service.delete().map_err(err)?;
        drop(service);
        thread::sleep(Duration::from_millis(200));
    }
    for name in [
        "lemonvpn-service.exe",
        crate::managed::CORE_BINARY_NAME,
        "wintun.dll",
        "mihomo.LICENSE.txt",
        "wintun.LICENSE.txt",
    ] {
        let file = source.join(name);
        if !file.is_file() {
            return Err(err(format!("安装包缺少 {name}")));
        }
        let target = directory.join(name);
        if target.exists() {
            reject_reparse(&target)?;
            protect_program(&target)?;
        }
        match name {
            crate::managed::CORE_BINARY_NAME => fs::write(&target, &core_bytes)?,
            "wintun.dll" => fs::write(&target, &driver_bytes)?,
            _ => {
                fs::copy(file, &target)?;
            }
        }
        protect_program(&target)?;
    }
    let service = manager
        .create_service(
            &ServiceInfo {
                name: NAME.into(),
                display_name: "LemonVPN TUN 服务".into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::OnDemand,
                error_control: ServiceErrorControl::Normal,
                executable_path: directory.join("lemonvpn-service.exe"),
                launch_arguments: vec!["--run".into(), "--owner-sid".into(), owner.into()],
                dependencies: vec![],
                account_name: None,
                account_password: None,
            },
            ServiceAccess::START | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        )
        .map_err(err)?;
    let dacl=format!("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;{owner})");
    let output = std::process::Command::new(crate::managed::system_tool("sc.exe")?)
        .args(["sdset", NAME, &dacl])
        .creation_flags(0x0800_0000)
        .output()?;
    if !output.status.success() {
        let _ = service.delete();
        return Err(err("无法设置 TUN 服务启动权限"));
    }
    service.start::<&str>(&[]).map_err(err)?;
    Ok(())
}
fn uninstall() -> io::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(err)?;
    let service = manager
        .open_service(
            NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(err)?;
    let _ = service.stop();
    for _ in 0..100 {
        if service.query_status().map_err(err)?.current_state == ServiceState::Stopped {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    service.delete().map_err(err)?;
    Ok(())
}
