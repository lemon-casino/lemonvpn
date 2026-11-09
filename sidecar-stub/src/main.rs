//! Desktop executable host for the shared engine library.
use lemonvpn_engine_core::{Engine, EngineOptions};
use std::{env, io, process, thread};

const DEFAULT_PORT: u16 = 18080;

fn main() {
    let port = match env::var("LEMONVPN_ENGINE_PORT") {
        Ok(value) => value.trim().parse::<u16>().unwrap_or_else(|_| {
            eprintln!("lemonvpn-engine-stub: invalid LEMONVPN_ENGINE_PORT={value:?}, using {DEFAULT_PORT}");
            DEFAULT_PORT
        }),
        Err(_) => DEFAULT_PORT,
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // Full-system TUN traffic fans out into one socket per flow; the
        // default 256 soft file-descriptor limit exhausts within seconds.
        unsafe {
            extern "C" {
                fn getrlimit(resource: i32, limit: *mut Rlimit) -> i32;
                fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
            }
            #[repr(C)]
            struct Rlimit {
                current: u64,
                maximum: u64,
            }
            #[cfg(target_os = "macos")]
            const RLIMIT_NOFILE: i32 = 8;
            #[cfg(target_os = "linux")]
            const RLIMIT_NOFILE: i32 = 7;
            const OPEN_MAX: u64 = 10240;
            let mut limit = Rlimit {
                current: 0,
                maximum: 0,
            };
            if getrlimit(RLIMIT_NOFILE, &mut limit) == 0 {
                let ceiling = limit.maximum.min(OPEN_MAX);
                limit.current = limit.current.max(ceiling);
                setrlimit(RLIMIT_NOFILE, &limit);
            }
        }
    }
    #[cfg(windows)]
    let parent = env::var("LEMONVPN_PARENT_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        .map(|pid| {
            (
                pid,
                lemonvpn_engine_core::platform::parent::ParentProcess::open(pid),
            )
        });
    #[cfg(windows)]
    if let Some((pid, Err(error))) = &parent {
        eprintln!("lemonvpn-engine-stub: parent {pid} is unavailable: {error}");
        let _ = lemonvpn_engine_core::platform::system_proxy::disable_owned(
            &format!("127.0.0.1:{port}"),
            *pid,
        );
        return;
    }
    #[cfg(not(windows))]
    extern "C" {
        fn getppid() -> i32;
    }
    #[cfg(not(windows))]
    let parent_pid = env::var("LEMONVPN_PARENT_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok());
    #[cfg(not(windows))]
    if let Some(pid) = parent_pid {
        if unsafe { getppid() } != pid as i32 {
            eprintln!("lemonvpn-engine-stub: parent {pid} is unavailable");
            let _ = lemonvpn_engine_core::platform::system_proxy::disable_owned(
                &format!("127.0.0.1:{port}"),
                pid,
            );
            return;
        }
    }
    let mut engine = Engine::start(EngineOptions {
        port,
        data_dir: None,
    })
    .unwrap_or_else(|err| {
        eprintln!("lemonvpn-engine-stub: failed to start on 127.0.0.1:{port}: {err}");
        // Preserve the shell's special port-ownership failure code.
        process::exit(if err.kind() == io::ErrorKind::AddrInUse {
            3
        } else {
            1
        });
    });
    eprintln!(
        "lemonvpn-engine-stub listening on http://{}",
        engine.local_addr()
    );
    #[cfg(windows)]
    if let Some((pid, Ok(parent))) = parent {
        if let Err(error) = parent.wait() {
            eprintln!("lemonvpn-engine-stub: parent watch failed: {error}");
        } else {
            // Release the proxy first, even if an in-flight remote dial takes
            // longer to cancel while the engine drains its own connections.
            let _ = lemonvpn_engine_core::platform::system_proxy::disable_owned(
                &format!("127.0.0.1:{}", engine.local_addr().port()),
                pid,
            );
            let _ = engine.shutdown();
            // The desktop owned stderr's read end and may have crashed. Never
            // panic on a broken log pipe before restoring the user's network.
            use std::io::Write;
            let _ = writeln!(
                io::stderr(),
                "lemonvpn-engine-stub: parent exited; owned state restored"
            );
            return;
        }
    }
    #[cfg(not(windows))]
    if let Some(pid) = parent_pid {
        thread::spawn(move || {
            let mut engine = engine;
            // The portable stand-in for the Windows process handle: once the
            // shell dies, the kernel re-parents this process and the engine
            // must restore the network before exiting.
            loop {
                thread::sleep(std::time::Duration::from_secs(2));
                if unsafe { getppid() } != pid as i32 {
                    let _ = lemonvpn_engine_core::platform::system_proxy::disable_owned(
                        &format!("127.0.0.1:{}", engine.local_addr().port()),
                        pid,
                    );
                    let _ = engine.shutdown();
                    eprintln!("lemonvpn-engine-stub: parent exited; owned state restored");
                    process::exit(0);
                }
            }
        });
    }
    loop {
        thread::park();
    }
}
