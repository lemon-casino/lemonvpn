#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
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
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        eprintln!("TUN service is only available on Windows and macOS");
        std::process::exit(1);
    }
}
