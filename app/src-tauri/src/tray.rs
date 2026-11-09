//! One persistent menu, background state reads and serialized user actions.
use crate::{engine::Engine, proxy_for_port, show_main};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{
    image::Image,
    menu::{CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    Manager,
};
pub const TUN_ID: &str = "tray_tun";
pub struct TrayUi {
    proxy: CheckMenuItem<tauri::Wry>,
    tun: CheckMenuItem<tauri::Wry>,
    stop: AtomicBool,
    busy: AtomicBool,
    refreshing: AtomicBool,
    can_hide: bool,
    last: Mutex<Option<(bool, bool, bool, bool)>>,
}
impl TrayUi {
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}
pub fn can_hide(app: &tauri::AppHandle) -> bool {
    app.try_state::<TrayUi>().is_some_and(|s| s.can_hide)
}
pub fn stop(app: &tauri::AppHandle) {
    if let Some(s) = app.try_state::<TrayUi>() {
        s.stop.store(true, Ordering::Release);
    }
}

pub fn install(app: &tauri::AppHandle) -> tauri::Result<()> {
    if app.try_state::<TrayUi>().is_some() {
        refresh(app);
        return Ok(());
    }
    let proxy = CheckMenuItemBuilder::with_id(crate::TRAY_SYSTEM_PROXY_ID, "系统代理")
        .enabled(false)
        .build(app)?;
    let tun = CheckMenuItemBuilder::with_id(TUN_ID, "TUN 模式")
        .enabled(false)
        .build(app)?;
    let show = MenuItem::with_id(app, crate::SHOW_WINDOW_ID, "显示窗口", true, None::<&str>)?;
    let logs = MenuItem::with_id(app, crate::OPEN_LOGS_ID, "引擎日志", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, crate::QUIT_ID, "退出", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = MenuBuilder::new(app)
        .item(&show)
        .item(&proxy)
        .item(&tun)
        .item(&logs)
        .item(&separator)
        .item(&quit)
        .build()?;
    let icon = TrayIconBuilder::with_id(crate::TRAY_ID)
        .icon(Image::from_bytes(include_bytes!("../icons/32x32.png"))?)
        .tooltip("LemonVPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
            refresh(tray.app_handle());
        })
        .build(app);
    let available = match icon {
        Ok(_) => true,
        Err(e) => {
            eprintln!("lemonvpn: 托盘不可用，窗口保留任务栏入口：{e}");
            false
        }
    };
    #[cfg(target_os = "linux")]
    let available = available && status_notifier_watcher();
    app.manage(TrayUi {
        proxy,
        tun,
        stop: AtomicBool::new(false),
        busy: AtomicBool::new(false),
        refreshing: AtomicBool::new(false),
        can_hide: available,
        last: Mutex::new(None),
    });
    refresh(app);
    let handle = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        if handle.try_state::<TrayUi>().is_none_or(|s| s.stopped()) {
            break;
        }
        refresh(&handle);
    });
    Ok(())
}

fn tun_status(port: u16) -> Result<serde_json::Value, String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_millis(700)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(700)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!(
                "GET /api/v1/tun HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    loop {
        if Instant::now() > deadline {
            return Err("TUN 状态读取超时".into());
        }
        let count = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > 64 * 1024 {
            return Err("TUN 状态过大".into());
        }
        if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]);
            let length = head.lines().find_map(|line| {
                let (k, v) = line.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            });
            if length.is_some_and(|n| bytes.len() >= end + 4 + n) {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("无效 TUN 状态")?;
    if head
        .lines()
        .next()
        .and_then(|s| s.split_whitespace().nth(1))
        != Some("200")
    {
        return Err("引擎暂未提供 TUN 状态".into());
    }
    serde_json::from_str(body).map_err(|e| e.to_string())
}

pub fn refresh(app: &tauri::AppHandle) {
    let Some(state) = app.try_state::<TrayUi>() else {
        return;
    };
    if state.stopped() || state.refreshing.swap(true, Ordering::AcqRel) {
        return;
    }
    let handle = app.clone();
    std::thread::spawn(move || {
        let Some(ui) = handle.try_state::<TrayUi>() else {
            return;
        };
        let engine = handle.state::<Engine>();
        let running = engine.status().state == "running";
        let proxy = proxy_for_port(engine.port());
        let tun = if running {
            tun_status(engine.port()).ok()
        } else {
            None
        };
        let busy = ui.busy.load(Ordering::Acquire);
        let previous = *ui.last.lock().unwrap();
        let values = (
            running && proxy.enabled,
            running && proxy.supported && !busy,
            running
                && tun
                    .as_ref()
                    .map(|v| v["enabled"].as_bool() == Some(true))
                    .unwrap_or(previous.is_some_and(|v| v.2)),
            running
                && tun
                    .as_ref()
                    .is_some_and(|v| v["supported"].as_bool() == Some(true))
                && !busy,
        );
        if !ui.stopped() {
            let mut last = ui.last.lock().unwrap();
            if last.as_ref() != Some(&values) {
                let _ = ui.proxy.set_checked(values.0);
                let _ = ui.proxy.set_enabled(values.1);
                let _ = ui.tun.set_checked(values.2);
                let _ = ui.tun.set_enabled(values.3);
                *last = Some(values);
            }
        }
        ui.refreshing.store(false, Ordering::Release);
    });
}

pub fn toggle(app: &tauri::AppHandle, tun: bool) {
    let Some(ui) = app.try_state::<TrayUi>() else {
        return;
    };
    if ui.stopped() || ui.busy.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Some(previous) = *ui.last.lock().unwrap() {
        // Native check items toggle on click. Keep the confirmed state while
        // authorization and the engine operation are still in progress.
        let _ = ui.proxy.set_checked(previous.0);
        let _ = ui.tun.set_checked(previous.2);
    }
    let _ = ui.proxy.set_enabled(false);
    let _ = ui.tun.set_enabled(false);
    let handle = app.clone();
    std::thread::spawn(move || {
        let Some(ui) = handle.try_state::<TrayUi>() else {
            return;
        };
        let result = (|| {
            let engine = handle.state::<Engine>();
            if engine.status().state != "running" {
                return Err("引擎未就绪".to_owned());
            }
            if tun {
                let current = tun_status(engine.port())?;
                if current["supported"].as_bool() != Some(true) {
                    return Err("当前环境不支持 TUN 模式".into());
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if current["enabled"].as_bool() != Some(true) {
                    let service = crate::integration::status();
                    #[cfg(target_os = "linux")]
                    let dormant = lemonvpn_engine_platform::service_linux::needs_start();
                    #[cfg(target_os = "macos")]
                    let dormant = false;
                    if !service.service_installed || service.service_update_required || dormant {
                        let resources = handle.path().resource_dir().map_err(|e| e.to_string())?;
                        crate::integration::service_action(&resources, true)?;
                    }
                }
                crate::set_tun(engine.port(), current["enabled"].as_bool() != Some(true))
            } else {
                crate::set_system_proxy(&engine, !proxy_for_port(engine.port()).enabled)
            }
        })();
        ui.busy.store(false, Ordering::Release);
        *ui.last.lock().unwrap() = None;
        if let Err(error) = result {
            if !ui.stopped() {
                eprintln!("lemonvpn: 托盘操作失败：{error}");
                show_main(&handle);
                if let Some(window) = handle.get_webview_window("main") {
                    let detail = serde_json::json!({"message":error});
                    let route = if tun {
                        "location.hash='#/settings?card=tun';"
                    } else {
                        ""
                    };
                    let _=window.eval(format!("{route}window.dispatchEvent(new CustomEvent('lemonvpn:desktop-error',{{detail:{detail}}}));"));
                }
            }
        }
        refresh(&handle);
    });
}

#[cfg(target_os = "linux")]
fn status_notifier_watcher() -> bool {
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.NameHasOwner",
            "org.kde.StatusNotifierWatcher",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(600);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if let Some(out) = child.stdout.take() {
                    let _ = out.take(4096).read_to_string(&mut text);
                }
                return status.success() && text.contains("true");
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}
