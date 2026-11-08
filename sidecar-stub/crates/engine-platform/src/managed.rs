//! Owned auxiliary cores. Dropping the owner terminates only its own process.
use serde_json::Value;
use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn random_secret() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(windows)]
pub fn system_tool(name: &str) -> io::Result<PathBuf> {
    let mut path = vec![0u16; 32768];
    let size = unsafe {
        windows_support::Win32::System::SystemInformation::GetSystemDirectoryW(
            path.as_mut_ptr(),
            path.len() as u32,
        )
    } as usize;
    if size == 0 || size >= path.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&path[..size])).join(name))
}

pub const CORE_BINARY_NAME: &str = if cfg!(windows) {
    "lemonvpn-kernel.exe"
} else {
    "lemonvpn-kernel"
};

pub fn core_path() -> Option<PathBuf> {
    let name = CORE_BINARY_NAME;
    let directory = std::env::current_exe().ok()?.parent()?.to_path_buf();
    // `../Resources` matches the macOS .app layout next to Contents/MacOS.
    [
        directory.join(name),
        directory.join("resources").join(name),
        directory.join("../Resources").join(name),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

pub fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_support::Win32::{
            Foundation::LocalFree, Security::Authorization::*, Security::*,
        };
        let sid = crate::service::current_sid()?;
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
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
        let result = unsafe {
            SetFileSecurityW(
                name.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        let error = io::Error::last_os_error();
        unsafe {
            LocalFree(descriptor);
        }
        if result == 0 {
            return Err(error);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub struct CoreProcess {
    child: Child,
    #[cfg(windows)]
    job: windows_support::Win32::Foundation::HANDLE,
    pub api_port: u16,
    secret: String,
    directory: PathBuf,
}
unsafe impl Send for CoreProcess {}

impl CoreProcess {
    pub fn start(
        binary: &Path,
        directory: PathBuf,
        mut config: Value,
        secret: String,
    ) -> io::Result<Self> {
        private_dir(&directory)?;
        let api_port = free_port()?;
        config["external-controller"] = format!("127.0.0.1:{api_port}").into();
        config["secret"] = secret.clone().into();
        let file = directory.join("runtime.json");
        fs::write(&file, serde_json::to_vec(&config)?)?;
        let mut command = Command::new(binary);
        command
            .arg("-d")
            .arg(&directory)
            .arg("-f")
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // A dedicated process group lets Drop reach helper children too.
            command.process_group(0);
        }
        #[cfg(windows)]
        let mut child = command.spawn()?;
        #[cfg(not(windows))]
        let child = command.spawn()?;
        #[cfg(windows)]
        let job = unsafe {
            use std::os::windows::io::AsRawHandle;
            use windows_support::Win32::{Foundation::CloseHandle, System::JobObjects::*};
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if job.is_null()
                || SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                ) == 0
                || AssignProcessToJobObject(job, child.as_raw_handle()) == 0
            {
                let error = io::Error::last_os_error();
                let _ = child.kill();
                let _ = child.wait();
                if !job.is_null() {
                    CloseHandle(job);
                }
                return Err(error);
            }
            job
        };
        let mut process = Self {
            child,
            #[cfg(windows)]
            job,
            api_port,
            secret,
            directory,
        };
        let deadline = Instant::now() + Duration::from_secs(12);
        while Instant::now() < deadline {
            if process.child.try_wait()?.is_some() {
                return Err(io::Error::other(
                    "兼容内核启动失败；TUN 需要安装管理员服务，或检查配置与端口",
                ));
            }
            if process.request("GET", "/version", None).is_ok() {
                return Ok(process);
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "兼容内核启动超时"))
    }
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> io::Result<String> {
        api(self.api_port, &self.secret, method, path, body)
    }
    /// Reloads must retain the private controller and its authentication.
    pub fn configure(&self, mut config: Value) -> io::Result<()> {
        config["external-controller"] = format!("127.0.0.1:{}", self.api_port).into();
        config["secret"] = self.secret.clone().into();
        self.request(
            "PUT",
            "/configs?force=true",
            Some(&serde_json::json!({"payload":config.to_string()})),
        )
        .map(|_| ())
    }
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        // Request graceful adapter/DNS/route cleanup before the owned process exits.
        let _ = self.request(
            "PATCH",
            "/configs",
            Some(&serde_json::json!({"tun":{"enable":false}})),
        );
        let _ = self.child.kill();
        #[cfg(unix)]
        unsafe {
            extern "C" {
                fn killpg(pgrp: i32, sig: i32) -> i32;
            }
            // SIGKILL the group started by `process_group(0)` so helpers the
            // kernel spawned cannot outlive the owner either.
            let _ = killpg(self.child.id() as i32, 9);
        }
        let _ = self.child.wait();
        #[cfg(windows)]
        unsafe {
            windows_support::Win32::Foundation::CloseHandle(self.job);
        }
        let _ = fs::remove_file(self.directory.join("runtime.json"));
    }
}

pub fn api(
    port: u16,
    secret: &str,
    method: &str,
    path: &str,
    value: Option<&Value>,
) -> io::Result<String> {
    let mut socket = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(350),
    )?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let body = value.map(Value::to_string).unwrap_or_default();
    write!(socket, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    let mut bytes = Vec::new();
    socket.take(2 * 1024 * 1024).read_to_end(&mut bytes)?;
    let response = String::from_utf8_lossy(&bytes);
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::other("内核 API 响应无效"))?;
    let code = head.split_whitespace().nth(1).unwrap_or("");
    if !code.starts_with('2') {
        return Err(io::Error::other(format!("内核 API 返回 HTTP {code}")));
    }
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut result = String::new();
        let mut data = body;
        while let Some((size, rest)) = data.split_once("\r\n") {
            let length = usize::from_str_radix(size.split(';').next().unwrap_or(""), 16)
                .map_err(|_| io::Error::other("无效分块"))?;
            if length == 0 {
                break;
            }
            result.push_str(
                rest.get(..length)
                    .ok_or_else(|| io::Error::other("截断分块"))?,
            );
            data = rest
                .get(length + 2..)
                .ok_or_else(|| io::Error::other("截断分块"))?;
        }
        return Ok(result);
    }
    Ok(body.to_owned())
}

pub fn uplink_name() -> Option<String> {
    #[cfg(windows)]
    {
        crate::windows::uplink_name().ok()
    }
    #[cfg(target_os = "macos")]
    {
        crate::darwin::uplink_name()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}
