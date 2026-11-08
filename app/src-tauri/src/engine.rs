//! Engine sidecar supervision for the LemonVPN desktop shell.
//!
//! The shell never proxies traffic itself: it starts the engine as a separate
//! process, waits for its loopback health endpoint, and kills it on exit. The
//! sidecar hosts the shared engine library; its legacy filename is retained
//! for compatibility with existing installations.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Port the engine listens on unless `LEMONVPN_ENGINE_PORT` overrides it.
pub const DEFAULT_PORT: u16 = 18080;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const RETRY_INTERVAL: Duration = Duration::from_millis(150);

/// Exit code the engine uses when it cannot bind its port; see
/// `sidecar-stub/src/main.rs`.
const ENGINE_EXIT_PORT_IN_USE: i32 = 3;

/// Lines kept for the log window; the oldest are dropped first.
const LOG_CAPACITY: usize = 500;

/// Restart attempts before the supervisor gives up and turns the proxy off.
const MAX_RESTARTS: u32 = 5;

/// An engine that stays up this long earns a fresh restart budget.
const STABLE_PERIOD: Duration = Duration::from_secs(60);

/// What the shell reports to the UI.
#[derive(Clone, serde::Serialize)]
pub struct EngineStatus {
    /// One of `running`, `restarting`, `port_in_use`, `unhealthy`, `failed`,
    /// `missing`, `stopped`.
    pub state: String,
    /// Human-readable detail: which binary, which port, or what failed.
    pub detail: String,
}

pub struct Engine {
    /// Serializes spawn/health/restart against shutdown.
    lifecycle: Mutex<()>,
    wake: (Mutex<()>, Condvar),
    child: Mutex<Option<Child>>,
    status: Mutex<EngineStatus>,
    port: u16,
    /// Engine stderr plus the shell's supervision lines, shared with the
    /// reader thread and the log window.
    logs: Arc<Mutex<VecDeque<String>>>,
    started: Instant,
    /// Set by `shutdown` so the supervisor does not fight an intentional stop.
    stopping: AtomicBool,
    restarts: Mutex<u32>,
    last_start: Mutex<Option<Instant>>,
    path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    owned_datapath: AtomicBool,
}

impl Engine {
    /// Builds the supervisor and performs the first start.
    pub fn start() -> Self {
        Self::start_at(port_from_env(), resolve_engine_path(), None)
    }

    fn start_at(port: u16, path: Option<PathBuf>, data_dir: Option<PathBuf>) -> Self {
        let engine = Engine {
            lifecycle: Mutex::new(()),
            wake: (Mutex::new(()), Condvar::new()),
            child: Mutex::new(None),
            port,
            logs: Arc::new(Mutex::new(VecDeque::new())),
            started: Instant::now(),
            stopping: AtomicBool::new(false),
            restarts: Mutex::new(0),
            last_start: Mutex::new(None),
            path,
            data_dir,
            owned_datapath: AtomicBool::new(false),
            status: Mutex::new(EngineStatus {
                state: "stopped".to_string(),
                detail: String::new(),
            }),
        };
        engine.spawn_once();
        engine
    }

    /// Spawns the engine and waits for health. Used for the first start and
    /// for every restart.
    fn spawn_once(&self) {
        let port = self.port;
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Some(path) = self.path.as_ref() else {
            let detail =
                "未找到引擎二进制:设置 LEMONVPN_ENGINE,或把 lemonvpn-engine-stub 放到应用同目录"
                    .to_string();
            self.log(&detail);
            *self.status.lock().unwrap() = EngineStatus {
                state: "missing".to_string(),
                detail,
            };
            return;
        };

        self.log(format!("启动引擎 {} (端口 {port})", path.display()));

        let mut command = Command::new(&path);
        command.env("LEMONVPN_ENGINE_PORT", port.to_string());
        command.env("LEMONVPN_PARENT_PID", std::process::id().to_string());
        if let Some(directory) = &self.data_dir {
            command.env("LEMONVPN_DATA_DIR", directory);
        }
        // Piped so the log window can show what the engine says; in a GUI
        // build inherited stdio goes nowhere.
        command.stderr(Stdio::piped());
        suppress_console_window(&mut command);

        match command.spawn() {
            Ok(mut child) => {
                if let Some(stderr) = child.stderr.take() {
                    let logs = Arc::clone(&self.logs);
                    let started = self.started;
                    std::thread::spawn(move || {
                        for line in BufReader::new(stderr).lines() {
                            let Ok(line) = line else { break };
                            push_line(&logs, started, line);
                        }
                    });
                }

                let status = match wait_for_health(port, &mut child, HEALTH_TIMEOUT, &self.stopping)
                {
                    Ok(()) => EngineStatus {
                        state: "running".to_string(),
                        detail: format!("{} 已在 127.0.0.1:{port} 就绪", path.display()),
                    },
                    Err(HealthFailure::PortInUse) => EngineStatus {
                        state: "port_in_use".to_string(),
                        detail: format!(
                            "127.0.0.1:{port} 已被其他进程占用,本次启动的 {} 无法绑定该端口",
                            path.display()
                        ),
                    },
                    Err(HealthFailure::ChildExited(code)) => EngineStatus {
                        state: "unhealthy".to_string(),
                        detail: match code {
                            Some(code) => {
                                format!("{} 启动后立即退出(退出码 {code})", path.display())
                            }
                            None => format!("{} 启动后立即退出", path.display()),
                        },
                    },
                    Err(HealthFailure::TimedOut) => EngineStatus {
                        state: "unhealthy".to_string(),
                        detail: format!("{} 已启动,但 /health 未在 10 秒内响应", path.display()),
                    },
                    Err(HealthFailure::Cancelled) => EngineStatus {
                        state: "stopped".to_string(),
                        detail: "引擎启动已取消".to_string(),
                    },
                };
                self.log(&status.detail);
                if status.state == "running" {
                    *self.last_start.lock().unwrap() = Some(Instant::now());
                    self.owned_datapath.store(true, Ordering::SeqCst);
                    *self.child.lock().unwrap() = Some(child);
                } else {
                    // A failed health check must not leave a live child holding
                    // the port while the supervisor starts another process.
                    let _ = child.kill();
                    let _ = child.wait();
                }
                *self.status.lock().unwrap() = status;
            }
            Err(err) => {
                let detail = format!("启动 {} 失败:{err}", path.display());
                self.log(&detail);
                *self.status.lock().unwrap() = EngineStatus {
                    state: "unhealthy".to_string(),
                    detail,
                };
            }
        }
    }

    /// One supervision step: restarts a dead engine with exponential backoff.
    /// Returns true when the engine gave up, in which case the caller must
    /// turn the system proxy off so it does not point at a dead port.
    pub fn tick(&self, on_exit: impl FnOnce()) -> bool {
        let _lifecycle = self.lifecycle.lock().unwrap();
        if self.stopping.load(Ordering::SeqCst) {
            return false;
        }

        match self.child_state() {
            ChildState::Running => {
                if let Some(started) = *self.last_start.lock().unwrap() {
                    if started.elapsed() >= STABLE_PERIOD {
                        *self.restarts.lock().unwrap() = 0;
                    }
                }
                return false;
            }
            ChildState::Exited(code) => {
                self.log(match code {
                    Some(code) => format!("引擎进程已退出(退出码 {code})"),
                    None => "引擎进程已退出".to_string(),
                });
                // Restore capture routes before attempting another process,
                // rather than leaving traffic trapped throughout retry backoff.
                on_exit();
            }
            ChildState::Absent => {}
        }

        let state = self.status().state;
        if matches!(
            state.as_str(),
            "missing" | "failed" | "stopped" | "port_in_use"
        ) {
            return false;
        }

        let attempt = {
            let mut restarts = self.restarts.lock().unwrap();
            *restarts += 1;
            *restarts
        };

        if attempt > MAX_RESTARTS {
            let detail = format!("引擎连续 {MAX_RESTARTS} 次重启失败,已停止自动重启");
            self.log(&detail);
            eprintln!("lemonvpn: {detail}");
            *self.status.lock().unwrap() = EngineStatus {
                state: "failed".to_string(),
                detail,
            };
            return true;
        }

        let backoff = backoff_for(attempt);
        self.log(format!(
            "第 {attempt} 次重启将在 {:.0} 秒后开始",
            backoff.as_secs_f32()
        ));
        eprintln!(
            "lemonvpn: 引擎退出,第 {attempt} 次重启将在 {:.0} 秒后开始",
            backoff.as_secs_f32()
        );
        *self.status.lock().unwrap() = EngineStatus {
            state: "restarting".to_string(),
            detail: format!(
                "引擎已退出,{:.0} 秒后第 {attempt} 次重启",
                backoff.as_secs_f32()
            ),
        };

        let _wait = self
            .wake
            .1
            .wait_timeout_while(self.wake.0.lock().unwrap(), backoff, |_| {
                !self.stopping.load(Ordering::SeqCst)
            })
            .unwrap();
        drop(_wait);
        if self.stopping.load(Ordering::SeqCst) {
            return false;
        }
        self.spawn_once();
        false
    }

    fn child_state(&self) -> ChildState {
        let mut child = self.child.lock().unwrap();
        let Some(running) = child.as_mut() else {
            return ChildState::Absent;
        };
        match running.try_wait() {
            Ok(Some(exit)) => {
                *child = None;
                ChildState::Exited(exit.code())
            }
            Ok(None) | Err(_) => ChildState::Running,
        }
    }

    pub fn status(&self) -> EngineStatus {
        self.status.lock().unwrap().clone()
    }

    /// The loopback port this engine was started on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// A failed or foreign listener never grants permission to clean up TUN.
    pub fn owned_datapath(&self) -> bool {
        self.owned_datapath.load(Ordering::SeqCst)
    }

    /// The recent engine output, oldest first.
    pub fn logs(&self) -> String {
        let logs = self.logs.lock().unwrap();
        logs.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn log(&self, line: impl AsRef<str>) {
        push_line(&self.logs, self.started, line);
    }

    /// Kills the engine process and stops the supervisor from restarting it.
    /// Safe to call more than once.
    pub fn shutdown(&self) {
        {
            let _wake = self.wake.0.lock().unwrap();
            self.stopping.store(true, Ordering::SeqCst);
            self.wake.1.notify_all();
        }
        let _lifecycle = self.lifecycle.lock().unwrap();
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *self.status.lock().unwrap() = EngineStatus {
            state: "stopped".to_string(),
            detail: "引擎已停止".to_string(),
        };
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Prefixes the line with elapsed seconds so the log window can show ordering
/// without depending on the engine's own timestamps.
fn push_line(logs: &Mutex<VecDeque<String>>, started: Instant, line: impl AsRef<str>) {
    let mut logs = logs.lock().unwrap();
    if logs.len() >= LOG_CAPACITY {
        logs.pop_front();
    }
    logs.push_back(format!(
        "[{:>7.2}s] {}",
        started.elapsed().as_secs_f32(),
        line.as_ref()
    ));
}

/// The port the next engine start will use, read before the engine exists.
pub fn configured_port() -> u16 {
    port_from_env()
}

fn port_from_env() -> u16 {
    std::env::var("LEMONVPN_ENGINE_PORT")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Order: `LEMONVPN_ENGINE` → the bundled
/// stub (`lemonvpn-engine-stub`, what `bundle.externalBin` installs) beside the
/// shell binary → in debug builds, the stub built from this workspace.
fn resolve_engine_path() -> Option<PathBuf> {
    if let Ok(value) = std::env::var("LEMONVPN_ENGINE") {
        let path = PathBuf::from(&value);
        if path.is_file() {
            return Some(path);
        }
    }

    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    // Tauri strips the target triple from externalBin, so the sidecar lands next
    // to the shell as a plain `lemonvpn-engine-stub.exe`.
    let stub = exe_dir.join(exe_name("lemonvpn-engine-stub"));
    if stub.is_file() {
        return Some(stub);
    }

    if cfg!(debug_assertions) {
        // app/src-tauri/target/debug → four levels up is the repository root.
        let stub = exe_dir
            .join("../../../../sidecar-stub/target/debug")
            .join(exe_name("lemonvpn-engine-stub"));
        if stub.is_file() {
            return Some(stub);
        }
    }

    None
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// What the supervisor sees when it looks at the child.
enum ChildState {
    Running,
    Exited(Option<i32>),
    Absent,
}

/// 1s, 2s, 4s, 8s, then 16s for every further attempt.
fn backoff_for(attempt: u32) -> Duration {
    Duration::from_secs(1 << attempt.saturating_sub(1).min(4))
}

/// Why the engine never became reachable.
enum HealthFailure {
    /// Another process holds the port, so the engine we spawned cannot bind it.
    PortInUse,
    /// The engine process exited before answering.
    ChildExited(Option<i32>),
    /// Nothing usable answered before the deadline.
    TimedOut,
    Cancelled,
}

/// One probe of the loopback health endpoint.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// Our child answered under its own identity.
    Ready,
    /// Something answered, but it is not the process we spawned.
    Foreign,
    /// Nothing answered this time.
    Silent,
}

fn wait_for_health(
    port: u16,
    child: &mut Child,
    timeout: Duration,
    stopping: &AtomicBool,
) -> Result<(), HealthFailure> {
    let pid = child.id();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if stopping.load(Ordering::SeqCst) {
            return Err(HealthFailure::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(exit)) if exit.code() == Some(ENGINE_EXIT_PORT_IN_USE) => {
                return Err(HealthFailure::PortInUse)
            }
            Ok(Some(exit)) => return Err(HealthFailure::ChildExited(exit.code())),
            Ok(None) => {}
            Err(_) => return Err(HealthFailure::ChildExited(None)),
        }

        match probe(port, pid) {
            Probe::Ready => return Ok(()),
            Probe::Foreign => return Err(HealthFailure::PortInUse),
            Probe::Silent => {}
        }

        std::thread::sleep(RETRY_INTERVAL);
    }

    Err(HealthFailure::TimedOut)
}

/// Only a listener that names itself as `lemonvpn-{pid}` for the child we just
/// spawned is adopted: a bare `200` could come from any process that won the
/// port first, which is exactly the silent failure this check exists to catch.
fn probe(port: u16, pid: u32) -> Probe {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
        return Probe::Silent;
    };
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));

    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return Probe::Silent;
    }

    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    while response.len() < 4096 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if response.is_empty() {
        return Probe::Silent;
    }

    let identity = format!(r#""instance":"lemonvpn-{pid}""#);
    if response.starts_with(b"HTTP/1.1 200") && contains(&response, identity.as_bytes()) {
        Probe::Ready
    } else {
        Probe::Foreign
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(windows)]
fn suppress_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn suppress_console_window(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[cfg(windows)]
    fn sidecar() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join("lemonvpn-engine-stub-x86_64-pc-windows-msvc.exe")
    }

    #[test]
    #[cfg(windows)]
    fn supervisor_recovers_child_exit_cancels_restart_and_does_not_adopt_foreign_port() {
        let directory =
            std::env::temp_dir().join(format!("lemonvpn-supervisor-{}", std::process::id()));
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let engine = Arc::new(Engine::start_at(port, Some(sidecar()), Some(directory)));
        assert_eq!(engine.status().state, "running");
        let first_pid = engine.child.lock().unwrap().as_ref().unwrap().id();
        engine
            .child
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .kill()
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let crash_notified = AtomicBool::new(false);
        assert!(!engine.tick(|| crash_notified.store(true, Ordering::SeqCst)));
        assert!(crash_notified.load(Ordering::SeqCst));
        assert_eq!(engine.status().state, "running");
        let second_pid = engine.child.lock().unwrap().as_ref().unwrap().id();
        assert_ne!(first_pid, second_pid);
        // Health must belong to the replacement process, not a stale listener.
        assert_eq!(probe(port, second_pid), Probe::Ready);
        engine
            .child
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .kill()
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let ticking = Arc::clone(&engine);
        let tick = std::thread::spawn(move || ticking.tick(|| {}));
        let deadline = Instant::now() + Duration::from_secs(2);
        while engine.status().state != "restarting" {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let stopped = Instant::now();
        engine.shutdown();
        tick.join().unwrap();
        assert!(
            stopped.elapsed() < Duration::from_secs(1),
            "shutdown must cancel restart backoff"
        );
        assert!(engine.child.lock().unwrap().is_none());
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("shutdown released the port");
        drop(engine);
        drop(listener);

        let foreign = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = foreign.local_addr().unwrap().port();
        let foreign_server = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = foreign.accept() {
                let _ = socket.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });
        let engine = Engine::start_at(port, Some(sidecar()), None);
        assert_eq!(engine.status().state, "port_in_use");
        assert!(!engine.owned_datapath());
        assert!(engine.child.lock().unwrap().is_none());
        assert!(!engine.tick(|| {}));
        assert_eq!(engine.status().state, "port_in_use");
        foreign_server.join().unwrap();
    }

    /// Serves one canned HTTP response, then closes.
    fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("绑定测试端口");
        let port = listener.local_addr().expect("读取端口").port();
        std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut request = [0u8; 256];
                let _ = socket.read(&mut request);
                let _ = socket.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn probe_accepts_its_own_identity() {
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 53\r\nConnection: close\r\n\r\n\
             {\"status\":\"ok\",\"instance\":\"lemonvpn-4242\",\"pid\":4242}",
        );
        assert_eq!(probe(port, 4242), Probe::Ready);
    }

    #[test]
    fn probe_rejects_another_engine() {
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 53\r\nConnection: close\r\n\r\n\
             {\"status\":\"ok\",\"instance\":\"lemonvpn-1111\",\"pid\":1111}",
        );
        assert_eq!(probe(port, 4242), Probe::Foreign);
    }

    #[test]
    fn probe_rejects_a_bare_200() {
        let port =
            serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        assert_eq!(probe(port, 4242), Probe::Foreign);
    }

    #[test]
    fn restart_backoff_doubles_then_caps() {
        let seconds: Vec<u64> = (1..=6)
            .map(|attempt| backoff_for(attempt).as_secs())
            .collect();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16, 16]);
    }

    #[test]
    fn log_buffer_drops_the_oldest_line() {
        let logs = Mutex::new(VecDeque::new());
        let started = Instant::now();
        for index in 0..LOG_CAPACITY + 5 {
            push_line(&logs, started, format!("line {index}"));
        }

        let logs = logs.into_inner().unwrap();
        assert_eq!(logs.len(), LOG_CAPACITY);
        assert!(logs.front().unwrap().ends_with("line 5"));
        assert!(logs
            .back()
            .unwrap()
            .ends_with(&format!("line {}", LOG_CAPACITY + 4)));
    }

    #[test]
    fn probe_reports_silence_when_nothing_listens() {
        let port = TcpListener::bind(("127.0.0.1", 0))
            .expect("取一个空闲端口")
            .local_addr()
            .expect("读取端口")
            .port();
        assert_eq!(probe(port, 4242), Probe::Silent);
    }
}
