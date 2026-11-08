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
    loop {
        thread::park();
    }
}
