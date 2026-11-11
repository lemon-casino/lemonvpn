#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod integration;
#[cfg(any(windows, unix))]
mod instance;
mod proxy;
mod window;
mod tray;

use engine::{Engine, EngineStatus};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_OK, SW_SHOWNORMAL,
};

/// The native actions live in the tray; the main window uses the web UI.
const TRAY_SYSTEM_PROXY_ID: &str = "tray_system_proxy";
const SHOW_WINDOW_ID: &str = "show_window";
const OPEN_LOGS_ID: &str = "open_engine_logs";
const QUIT_ID: &str = "quit";
const TRAY_ID: &str = "lemonvpn";
const LOGS_WINDOW: &str = "logs";
/// The elevated relaunch passes this so the new instance turns TUN on once its
/// engine is healthy; the UI only has to request the restart.
const ENABLE_TUN_ARG: &str = "--enable-tun";

#[tauri::command]
fn windows_integration_status()->integration::Status {integration::status()}
#[tauri::command]
fn autostart_set(enabled:bool)->Result<integration::Status,String>{integration::set_autostart(enabled)}
#[tauri::command]
async fn windows_service_install(app:tauri::AppHandle)->Result<integration::Status,String>{
    let directory=app.path().resource_dir().map_err(|e|e.to_string())?;
    tauri::async_runtime::spawn_blocking(move||integration::service_action(&directory,true)).await.map_err(|e|e.to_string())?
}
#[tauri::command]
async fn windows_service_remove(app:tauri::AppHandle)->Result<integration::Status,String>{
    if let Some(engine)=app.try_state::<Engine>() {set_tun(engine.port(),false)?;}
    let directory=app.path().resource_dir().map_err(|e|e.to_string())?;
    tauri::async_runtime::spawn_blocking(move||integration::service_action(&directory,false)).await.map_err(|e|e.to_string())?
}

#[tauri::command]
fn engine_status(engine: tauri::State<'_, Engine>) -> EngineStatus {
    engine.status()
}

#[tauri::command]
fn engine_logs(engine: tauri::State<'_, Engine>) -> String {
    engine.logs()
}

#[cfg(not(any(target_os="linux",target_os="macos")))]
#[tauri::command]
fn proxy_status(engine: tauri::State<'_, Engine>) -> proxy::ProxyStatus {
    proxy_for_port(engine.port())
}

#[cfg(any(target_os="linux",target_os="macos"))]
#[tauri::command]
async fn proxy_status(engine: tauri::State<'_, Engine>) -> Result<proxy::ProxyStatus,String> {
    let port=engine.port();
    tauri::async_runtime::spawn_blocking(move||proxy_for_port(port)).await.map_err(|e|e.to_string())
}

fn proxy_for_port(port: u16) -> proxy::ProxyStatus {
    let mut status = proxy::status();
    status.enabled &= status.server.as_deref() == Some(&format!("127.0.0.1:{port}"));
    status
}

/// Proof from the log page that the custom protocol, the page script and IPC
/// all work; `LEMONVPN_OPEN_LOGS=1` makes it reachable without clicking.
#[tauri::command]
fn log_page_ready() {
    eprintln!("lemonvpn: 日志页已加载");
}

/// Turns the system proxy on (pointing at this engine) or restores whatever
/// was configured before it.
#[cfg(not(any(target_os="linux",target_os="macos")))]
#[tauri::command]
fn proxy_set(
    enabled: bool,
    engine: tauri::State<'_, Engine>,
    app:tauri::AppHandle,
) -> Result<proxy::ProxyStatus, String> {
    set_system_proxy(&engine, enabled)?;
    tray::refresh(&app);
    Ok(proxy_for_port(engine.port()))
}

#[cfg(any(target_os="linux",target_os="macos"))]
#[tauri::command]
async fn proxy_set(enabled:bool,app:tauri::AppHandle)->Result<proxy::ProxyStatus,String> {
    tauri::async_runtime::spawn_blocking(move|| {
        let engine=app.state::<Engine>();
        set_system_proxy(&engine,enabled)?;
        tray::refresh(&app);
        Ok(proxy_for_port(engine.port()))
    }).await.map_err(|e|e.to_string())?
}

fn set_system_proxy(engine: &Engine, enabled: bool) -> Result<(), String> {
    if !enabled {
        return proxy::disable_for(&format!("127.0.0.1:{}", engine.port()));
    }
    if engine.status().state != "running" {
        return Err("引擎未就绪,无法启用系统代理".to_string());
    }
    proxy::enable(&format!("127.0.0.1:{}", engine.port()))
}

/// Asks the engine to turn TUN on or off. The UI normally makes this call
/// itself; the shell uses it for the elevated relaunch and for shutdown, where
/// no window is involved.
fn set_tun(port: u16, enabled: bool) -> Result<(), String> {
    let body = format!(r#"{{"enabled":{enabled}}}"#);
    let request = format!(
        "POST /api/v1/tun/set HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|err| format!("连接引擎失败：{err}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("发送 TUN 请求失败：{err}"))?;
    let mut response = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|err| format!("读取 TUN 响应失败：{err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > 64 * 1024 {
            return Err("TUN 响应超过大小上限".to_string());
        }
        // The engine sends Content-Length. A complete response does not need
        // a TCP EOF: Windows may reset on close, or keep the connection open.
        if let Some(end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&response[..end]);
            let length = head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            });
            if length.is_some_and(|length| length <= response.len() - end - 4) {
                break;
            }
        }
    }
    parse_tun_response(&String::from_utf8_lossy(&response))
}

fn parse_tun_response(response: &str) -> Result<(), String> {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let status = head.lines().next().unwrap_or("");
    if status.contains(" 200 ") {
        return Ok(());
    }
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(|message| message.as_str())
                .map(str::to_owned)
        });
    Err(message.unwrap_or_else(|| status.trim().to_string()))
}

/// The elevated instance starts while the old one is still shutting down; wait
/// for its engine to release the port instead of reporting a false collision.
fn wait_for_port_release(port: u16, timeout: Duration) {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Removes the two shadow routes TUN installs, in case the engine died before
/// it could take them down itself. The stale adapter's DNS is reset as well so
/// name resolution cannot keep pointing at the dead TUN address.
#[cfg(windows)]
fn cleanup_tun_routes() {
    use std::os::windows::process::CommandExt;
    for (network, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let _ = std::process::Command::new("route")
            .args(["delete", network, "mask", mask, "10.111.0.1"])
            .creation_flags(0x0800_0000)
            .output();
    }
    for family in ["ipv4", "ipv6"] {
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                family,
                "set",
                "dnsservers",
                "name=LemonVPN",
                "source=dhcp",
            ])
            .creation_flags(0x0800_0000)
            .output();
    }
}

#[cfg(not(windows))]
fn cleanup_tun_routes() {}

#[cfg(windows)]
fn show_error(title: &str, text: &str) {
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_ICONERROR | MB_OK,
        );
    }
}

#[cfg(not(windows))]
fn show_error(_title: &str, text: &str) {
    eprintln!("lemonvpn: {text}");
}

/// Restarts the shell elevated. The current process exits so its engine lets go
/// of the port; the new one waits for the port and turns TUN on.
#[tauri::command]
fn tun_relaunch_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|err| format!("读取程序路径失败：{err}"))?;
        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let file: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let params: Vec<u16> = format!("{ENABLE_TUN_ARG}\0").encode_utf16().collect();
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = result as isize;
        if code <= 32 {
            return Err(format!("无法以管理员身份启动（ShellExecuteW 返回 {code}）"));
        }
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("请在 TUN 模式中安装或修复平台服务，无需以管理员身份重启应用".to_string())
    }
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        if !window.is_focused().unwrap_or(false) {
            let _=window.request_user_attention(Some(tauri::UserAttentionType::Informational));
        }
    }
}

fn build_menus(app: &tauri::AppHandle) -> tauri::Result<()> { tray::install(app) }

fn toggle_system_proxy(app: &tauri::AppHandle) { tray::toggle(app,false); }

#[tauri::command]
fn tray_refresh(app:tauri::AppHandle) {tray::refresh(&app);}

/// Restarts the engine when it dies, and turns the proxy off once it cannot be
/// recovered so the system is never left pointing at a dead port.
fn spawn_supervisor(handle: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let gave_up = match handle.try_state::<Engine>() {
            Some(engine) => engine.tick(|| {
                if engine.owned_datapath() && !isolated_ui_smoke() {
                    cleanup_tun_routes();
                }
            }),
            None => false,
        };
        if !gave_up {
            continue;
        }
        eprintln!("lemonvpn: 引擎无法恢复,关闭系统代理");
        cleanup_tun_routes();
        let port = handle.state::<Engine>().port();
        if let Err(err) = proxy::disable_for(&format!("127.0.0.1:{port}")) {
            eprintln!("lemonvpn: 关闭系统代理失败: {err}");
        }
        if let Err(err) = build_menus(&handle) {
            eprintln!("lemonvpn: 刷新菜单失败: {err}");
        }
    });
}

fn isolated_ui_smoke() -> bool {
    std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1")
        && std::env::var("LEMONVPN_SMOKE_DEBUG_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .is_some()
}

/// One listener serves both menus: Tauri routes tray menu events through the
/// same global handler as the window menu bar.
fn install_events(handle: &tauri::AppHandle) {
    handle.on_menu_event(|app, event| match event.id().as_ref() {
        TRAY_SYSTEM_PROXY_ID => toggle_system_proxy(app),
        tray::TUN_ID => tray::toggle(app,true),
        SHOW_WINDOW_ID => show_main(app),
        OPEN_LOGS_ID => open_logs(app),
        QUIT_ID => app.exit(0),
        _ => {}
    });
}

/// The log page is served by the shell itself over a custom protocol, so the
/// window does not depend on doona having a desktop log route (D6).
fn open_logs(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(LOGS_WINDOW) {
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }

    let url = tauri::Url::parse("lemonvpn://localhost/logs").expect("日志页 URL");
    let result = WebviewWindowBuilder::new(app, LOGS_WINDOW, WebviewUrl::CustomProtocol(url))
        .title("LemonVPN 引擎日志")
        .inner_size(760.0, 460.0)
        .build();
    if let Err(err) = result {
        eprintln!("lemonvpn: 打开引擎日志窗口失败: {err}");
    }
}

/// Identifies the desktop host, seeds a local profile on first run, and migrates
/// obsolete PWA caches without changing saved frontend preferences.
fn seed_profile_script(port: u16) -> String {
    let desktop = serde_json::json!({
        "name": "LemonVPN",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "engineUrl": format!("http://127.0.0.1:{port}"),
    });
    let port = port.to_string();
    let seed = [
        "(function(){try{",
        "if(localStorage.getItem('doona-profiles')!==null||localStorage.getItem('doona-api')!==null)return;",
        "var api='http://127.0.0.1:",
        port.as_str(),
        "';",
        "localStorage.setItem('doona-profiles',JSON.stringify([{id:'lemonvpn',name:'本机引擎',api:api,token:''}]));",
        "localStorage.setItem('doona-profile','lemonvpn');",
        "}catch(e){}})();",
    ]
    .concat();
    // Run in the host so migration also works when an older frontend is being
    // served by a previously installed PWA worker. Keep localStorage (profiles,
    // appearance, etc.) and every cache outside doona's shell namespace.
    let migration = include_str!("desktop-bootstrap.js");
    format!("window.__LEMONVPN_DESKTOP__={desktop};{seed}{migration}")
}

const LOG_PAGE: &str = r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>LemonVPN 引擎日志</title>
<style>
  :root { color-scheme: dark; }
  html, body { margin: 0; height: 100%; background: #101010; color: #ddd; }
  body { display: flex; flex-direction: column; font: 12px/1.55 ui-monospace, Consolas, monospace; }
  header { display: flex; align-items: center; gap: 12px; padding: 6px 12px; background: #191919; border-bottom: 1px solid #2a2a2a; }
  header b { font-weight: 600; }
  #state { color: #8a8a8a; }
  #copy { margin-left: auto; padding: 2px 12px; color: #ddd; background: #262626; border: 1px solid #3a3a3a; border-radius: 4px; cursor: pointer; }
  #copy:hover { background: #333; }
  pre { flex: 1; margin: 0; padding: 8px 12px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
<header><b>引擎日志</b><span id="state">连接中…</span><button id="copy">复制</button></header>
<pre id="log"></pre>
<script>
const invoke = window.__TAURI__?.core?.invoke ?? window.__TAURI_INTERNALS__?.invoke;
const log = document.getElementById('log');
const state = document.getElementById('state');
let latest = '';
let reported = false;
async function tick() {
  if (!invoke) { state.textContent = 'IPC 不可用'; return; }
  try {
    const text = await invoke('engine_logs');
    if (text !== latest) {
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
      latest = text;
      log.textContent = text || '(暂无输出)';
      if (atBottom) log.scrollTop = log.scrollHeight;
    }
    if (!reported) { reported = true; invoke('log_page_ready').catch(() => {}); }
    state.textContent = '每 0.5 秒刷新';
  } catch (err) {
    state.textContent = '读取失败:' + err;
  }
}
document.getElementById('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(latest); state.textContent = '已复制'; }
  catch { state.textContent = '复制失败'; }
});
tick();
setInterval(tick, 500);
</script>
</body>
</html>"##;

fn main() {
    #[cfg(any(windows, unix))]
    let _instance = {
        let directory = instance::data_dir();
        let handover = std::env::args().any(|arg| arg == ENABLE_TUN_ARG);
        let wait = if handover {
            Duration::from_secs(12)
        } else {
            Duration::ZERO
        };
        match instance::InstanceGuard::acquire(&directory, wait) {
            Ok(Some(guard)) => guard,
            Ok(None) => {
                instance::activate_existing(&directory);
                eprintln!("lemonvpn: 已有实例运行，显示现有窗口");
                return;
            }
            Err(error) => {
                eprintln!("lemonvpn: 无法取得实例锁：{error}");
                show_error("LemonVPN", &format!("无法打开应用数据目录：{error}"));
                return;
            }
        }
    };
    #[cfg(unix)]
    let activation_listener=_instance.activation_listener().ok();
    // A crashed host releases its instance lock before its sidecar watchdog
    // finishes cleanup. Let that owned listener disappear before replacing it.
    #[cfg(any(windows, unix))]
    if _instance.previous_owner {
        wait_for_port_release(engine::configured_port(), Duration::from_secs(3));
    }
    if std::env::var("LEMONVPN_SMOKE").as_deref() != Ok("1") {
        if let Err(error) = proxy::recover_stale() {
            eprintln!("lemonvpn: 恢复上次异常退出的代理失败：{error}");
        }
    }
    // The smoke deadline counts from process start: the window and WebView2 take
    // about a second before `setup` runs, and the engine handshake runs inside it,
    // so either would eat into the five seconds the smoke run is allowed.
    let started = std::time::Instant::now();
    tauri::Builder::default()
        .register_uri_scheme_protocol("lemonvpn", |_context, request| {
            let mut builder = tauri::http::Response::builder();
            if request.uri().path() == "/logs" {
                builder = builder.header("Content-Type", "text/html; charset=utf-8");
                builder
                    .body(LOG_PAGE.as_bytes().to_vec())
                    .expect("日志页响应")
            } else {
                builder
                    .status(404)
                    .body(Vec::new())
                    .expect("日志页 404 响应")
            }
        })
        .setup(move |app| {
            let smoke_ms = std::env::var("LEMONVPN_SMOKE_TIMEOUT_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5000)
                .clamp(1000, 7_200_000);
            let smoke_deadline = started + std::time::Duration::from_millis(smoke_ms);
            let wants_tun = std::env::args().any(|arg| arg == ENABLE_TUN_ARG);
            if wants_tun {
                wait_for_port_release(engine::configured_port(), Duration::from_secs(10));
            }
            let engine = Engine::start(app.path().resource_dir()?);
            let tun_error = if wants_tun {
                if engine.status().state == "running" {
                    set_tun(engine.port(), true).err()
                } else {
                    Some(format!(
                        "引擎未就绪（{}），无法开启 TUN",
                        engine.status().state
                    ))
                }
            } else {
                None
            };

            if std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1") {
                let status = engine.status();
                eprintln!("engine state={} detail={}", status.state, status.detail);
            }

            // Headless check of the proxy switch: `LEMONVPN_PROXY=on|off`.
            if let Ok(action) = std::env::var("LEMONVPN_PROXY") {
                let mut result = match action.as_str() {
                    "on" => set_system_proxy(&engine, true),
                    "off" => set_system_proxy(&engine, false),
                    other => Err(format!("未知的 LEMONVPN_PROXY 动作: {other}")),
                };
                match &result {
                    Ok(()) => eprintln!("proxy {action} ok: {:?}", proxy::status()),
                    Err(err) => eprintln!("proxy {action} failed: {err}"),
                }
                engine.shutdown();
                // This is a self-check, not a persistent background engine.
                // Never leave its test proxy pointing at the stopped child.
                if let Err(error) = proxy::disable_for(&format!("127.0.0.1:{}", engine.port())) {
                    eprintln!("lemonvpn: 代理自检后恢复失败：{error}");
                    result = Err(error);
                }
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            }

            app.manage(engine);
            install_events(app.handle());
            build_menus(app.handle())?;

            // Built in code rather than in tauri.conf.json so the page gets the
            // profile script before doona's bundle reads localStorage.
            let port = app.state::<Engine>().port();
            // Bypass an old HTTP-cache entry before removing its PWA worker.
            let entry = format!("index.html?desktop={}", env!("CARGO_PKG_VERSION"));
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App(entry.into()))
                // WebView2's host drop handler consumes HTML5 drag events. Rule
                // and dashboard ordering use the frontend's accessible DnD.
                .disable_drag_drop_handler()
                .title(
                    if std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1") && smoke_ms > 30_000 {
                        "LemonVPN · 稳定性测试"
                    } else {
                        "LemonVPN"
                    },
                )
                .inner_size(1100.0, 720.0)
                .visible(!std::env::args().any(|arg|arg=="--autostart") || !tray::can_hide(app.handle()))
                .initialization_script(seed_profile_script(port))
                .on_web_resource_request(|_, response| {
                    response.headers_mut().insert(
                        tauri::http::header::CACHE_CONTROL,
                        tauri::http::HeaderValue::from_static("no-store"),
                    );
                });
            // Only an explicit smoke run can expose a loopback inspector. The
            // test harness uses the actual packaged WebView and an isolated profile.
            #[cfg(windows)]
            let window = if std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1") {
                match std::env::var("LEMONVPN_SMOKE_DEBUG_PORT")
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                {
                    Some(port) => window.additional_browser_args(&format!(
                        "--remote-debugging-address=127.0.0.1 --remote-debugging-port={port}"
                    )),
                    None => window,
                }
            } else {
                window
            };
            #[cfg(windows)]
            let window = window.decorations(false);
            window.build()?;
            #[cfg(unix)]
            if let Some(socket)=activation_listener {instance::start_activation(socket,app.handle().clone());}

            if let Some(err) = tun_error {
                eprintln!("lemonvpn: TUN 开启失败: {err}");
                let text = format!("TUN 模式未能开启：\n{err}");
                std::thread::spawn(move || show_error("LemonVPN", &text));
            }

            if std::env::var("LEMONVPN_OPEN_LOGS").as_deref() == Ok("1") {
                open_logs(app.handle());
            }

            spawn_supervisor(app.handle().clone());

            if std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1") {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(
                        smoke_deadline.saturating_duration_since(std::time::Instant::now()),
                    );
                    handle.exit(0);
                });
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Closing the window keeps the engine and the system proxy up;
                // the tray's 退出 item is the way out.
                api.prevent_close();
                if tray::can_hide(window.app_handle()) {let _=window.hide();}
                else {let _=window.show();let _=window.minimize();}
            }
        })
        .invoke_handler(tauri::generate_handler![
            window::window_action,
            tray_refresh,
            engine_status,
            engine_logs,
            log_page_ready,
            proxy_status,
            proxy_set,
            tun_relaunch_as_admin
            ,windows_integration_status,autostart_set,windows_service_install,windows_service_remove
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the LemonVPN shell")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                show_main(app);
            }
            if let tauri::RunEvent::Exit = event {
                tray::stop(app);
                let mut owned_datapath = false;
                let mut port = None;
                if let Some(engine) = app.try_state::<Engine>() {
                    owned_datapath = engine.owned_datapath();
                    port = Some(engine.port());
                    if engine.status().state == "running" {
                        if let Err(err) = set_tun(engine.port(), false) {
                            eprintln!("lemonvpn: 退出时关闭 TUN 失败: {err}");
                        }
                    }
                    engine.shutdown();
                }
                // An isolated UI smoke run has never taken over the system
                // proxy/routes. Another installed instance may still own them.
                if !isolated_ui_smoke() {
                    if owned_datapath {
                        cleanup_tun_routes();
                    }
                    // Never leave the user's system proxy pointing at a dead port.
                    if let Some(port) = port {
                        if let Err(err) = proxy::disable_for(&format!("127.0.0.1:{port}")) {
                            eprintln!("lemonvpn: 退出时恢复系统代理失败: {err}");
                        }
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::{parse_tun_response, seed_profile_script, set_tun};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn seeds_the_local_engine_only() {
        let script = seed_profile_script(18080);
        assert!(script.contains("'http://127.0.0.1:18080'"));
        assert!(script.contains("'doona-profiles'"));
        assert!(script.contains("'doona-profile'"));
        assert!(script.contains("id:'lemonvpn'"));
        // A saved profile wins: only a first run may write.
        assert!(script.contains("!==null)return"));
    }

    #[test]
    fn posts_tun_enable_to_the_engine() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("监听测试端口");
        let port = listener.local_addr().expect("读取测试端口").port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("接受请求");
            let mut reader = BufReader::new(stream.try_clone().expect("复制 socket"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("读取请求行");
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("读取请求头");
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    content_length = value.trim().parse().expect("Content-Length");
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("读取请求体");
            assert_eq!(request_line.trim(), "POST /api/v1/tun/set HTTP/1.1");
            assert_eq!(
                String::from_utf8(body).expect("请求体 UTF-8"),
                r#"{"enabled":true}"#
            );
            (&stream)
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .expect("写响应");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            // Keep the server side open until the client finishes: completion
            // must follow Content-Length, not depend on receiving TCP EOF.
            assert_eq!((&stream).read(&mut [0]).unwrap(), 0);
        });
        assert_eq!(set_tun(port, true), Ok(()));
        server.join().expect("测试服务器线程");
    }

    #[test]
    fn parses_a_successful_tun_response() {
        assert_eq!(
            parse_tun_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"),
            Ok(())
        );
    }

    #[test]
    fn reports_the_engine_tun_error() {
        let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 96\r\n\r\n\
            {\"error\":{\"code\":\"internal_error\",\"message\":\"创建 TUN 适配器失败（需要管理员权限）\"}}";
        assert_eq!(
            parse_tun_response(response),
            Err("创建 TUN 适配器失败（需要管理员权限）".to_string())
        );
    }
}
