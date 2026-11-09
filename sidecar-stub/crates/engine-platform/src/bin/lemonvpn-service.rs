#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref()==Some("--kernel-stop") {
        let result = std::env::args().nth(2).and_then(|s|s.parse::<u32>().ok())
            .ok_or_else(||std::io::Error::other("无效内核 PID"))
            .and_then(lemonvpn_engine_platform::kernel_windows::signal);
        std::process::exit(if result.is_ok() {0} else {1});
    }
    #[cfg(windows)]
    if let Err(error) = lemonvpn_engine_platform::service::entry() {
        eprintln!("LemonVPN TUN service: {error}");
        std::process::exit(1);
    }
    #[cfg(target_os = "macos")]
    if let Err(error) = lemonvpn_engine_platform::service_macos::entry() {
        eprintln!("LemonVPN TUN service: {error}");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    if let Err(error) = lemonvpn_engine_platform::service_linux::entry() {
        eprintln!("LemonVPN TUN service: {error}");
        std::process::exit(1);
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        eprintln!("TUN service is only available on Windows, macOS and Linux");
        std::process::exit(1);
    }
}
