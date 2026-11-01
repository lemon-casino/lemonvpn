#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod proxy;

use engine::{Engine, EngineStatus};
use tauri::image::Image;
use tauri::menu::{CheckMenuItemBuilder, MenuBuilder, MenuItem, PredefinedMenuItem, SubmenuBuilder};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

/// Menu id of the window menu's system-proxy check item.
const SYSTEM_PROXY_ID: &str = "system_proxy";
/// The tray menu is a separate menu from the window menu bar, so its check
/// item needs its own id even though it drives the same switch.
const TRAY_SYSTEM_PROXY_ID: &str = "tray_system_proxy";
const SHOW_WINDOW_ID: &str = "show_window";
const OPEN_LOGS_ID: &str = "open_engine_logs";
const QUIT_ID: &str = "quit";
const TRAY_ID: &str = "lemonvpn";
const LOGS_WINDOW: &str = "logs";

#[tauri::command]
fn engine_status(engine: tauri::State<'_, Engine>) -> EngineStatus {
    engine.status()
}

#[tauri::command]
fn engine_logs(engine: tauri::State<'_, Engine>) -> String {
    engine.logs()
}

#[tauri::command]
fn proxy_status() -> proxy::ProxyStatus {
    proxy::status()
}

/// Proof from the log page that the custom protocol, the page script and IPC
/// all work; `LEMONVPN_OPEN_LOGS=1` makes it reachable without clicking.
#[tauri::command]
fn log_page_ready() {
    eprintln!("lemonvpn: 日志页已加载");
}

/// Turns the system proxy on (pointing at this engine) or restores whatever
/// was configured before it.
#[tauri::command]
fn proxy_set(enabled: bool, engine: tauri::State<'_, Engine>) -> Result<proxy::ProxyStatus, String> {
    set_system_proxy(&engine, enabled)?;
    Ok(proxy::status())
}

fn set_system_proxy(engine: &Engine, enabled: bool) -> Result<(), String> {
    if !enabled {
        return proxy::disable();
    }
    if engine.status().state != "running" {
        return Err("引擎未就绪,无法启用系统代理".to_string());
    }
    proxy::enable(&format!("127.0.0.1:{}", engine.port()))
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Rebuilds both menus from the live proxy state. Menu lookups do not recurse
/// into submenus, so rebuilding is simpler than tracking item handles.
fn build_menus(app: &tauri::AppHandle) -> tauri::Result<()> {
    let enabled = proxy::status().enabled;

    let app_proxy = CheckMenuItemBuilder::with_id(SYSTEM_PROXY_ID, "系统代理")
        .checked(enabled)
        .build(app)?;
    let app_logs = MenuItem::with_id(app, OPEN_LOGS_ID, "引擎日志", true, None::<&str>)?;
    let app_quit = MenuItem::with_id(app, QUIT_ID, "退出", true, None::<&str>)?;
    let submenu = SubmenuBuilder::new(app, "LemonVPN")
        .item(&app_proxy)
        .item(&app_logs)
        .item(&app_quit)
        .build()?;
    app.set_menu(MenuBuilder::new(app).item(&submenu).build()?)?;

    let tray_show = MenuItem::with_id(app, SHOW_WINDOW_ID, "显示窗口", true, None::<&str>)?;
    let tray_proxy = CheckMenuItemBuilder::with_id(TRAY_SYSTEM_PROXY_ID, "系统代理")
        .checked(enabled)
        .build(app)?;
    let tray_logs = MenuItem::with_id(app, OPEN_LOGS_ID, "引擎日志", true, None::<&str>)?;
    let tray_quit = MenuItem::with_id(app, QUIT_ID, "退出", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let tray_menu = MenuBuilder::new(app)
        .item(&tray_show)
        .item(&tray_proxy)
        .item(&tray_logs)
        .item(&separator)
        .item(&tray_quit)
        .build()?;

    match app.tray_by_id(TRAY_ID) {
        Some(tray) => tray.set_menu(Some(tray_menu))?,
        None => {
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(Image::from_bytes(include_bytes!("../icons/32x32.png"))?)
                .tooltip("LemonVPN")
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
        }
    }

    Ok(())
}

fn toggle_system_proxy(app: &tauri::AppHandle) {
    let Some(engine) = app.try_state::<Engine>() else {
        return;
    };
    let wanted = !proxy::status().enabled;
    if let Err(err) = set_system_proxy(&engine, wanted) {
        eprintln!("lemonvpn: 系统代理切换失败: {err}");
    }
    // Rebuild so both check items show the state that actually took effect.
    if let Err(err) = build_menus(app) {
        eprintln!("lemonvpn: 刷新菜单失败: {err}");
    }
}

/// Restarts the engine when it dies, and turns the proxy off once it cannot be
/// recovered so the system is never left pointing at a dead port.
fn spawn_supervisor(handle: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let gave_up = match handle.try_state::<Engine>() {
            Some(engine) => engine.tick(),
            None => false,
        };
        if !gave_up {
            continue;
        }
        eprintln!("lemonvpn: 引擎无法恢复,关闭系统代理");
        if let Err(err) = proxy::disable() {
            eprintln!("lemonvpn: 关闭系统代理失败: {err}");
        }
        if let Err(err) = build_menus(&handle) {
            eprintln!("lemonvpn: 刷新菜单失败: {err}");
        }
    });
}

/// One listener serves both menus: Tauri routes tray menu events through the
/// same global handler as the window menu bar.
fn install_events(handle: &tauri::AppHandle) {
    handle.on_menu_event(|app, event| match event.id().as_ref() {
        SYSTEM_PROXY_ID | TRAY_SYSTEM_PROXY_ID => toggle_system_proxy(app),
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

/// Seeds doona's backend profile so the embedded UI talks to this engine
/// instead of its built-in demo backend. It runs before any page script and
/// never touches profiles that already exist, so a backend the person picked
/// survives upgrades.
fn seed_profile_script(port: u16) -> String {
    let port = port.to_string();
    [
        "(function(){try{",
        "if(localStorage.getItem('doona-profiles')!==null||localStorage.getItem('doona-api')!==null)return;",
        "var api='http://127.0.0.1:",
        port.as_str(),
        "';",
        "localStorage.setItem('doona-profiles',JSON.stringify([{id:'lemonvpn',name:'本机引擎',api:api,token:''}]));",
        "localStorage.setItem('doona-profile','lemonvpn');",
        "}catch(e){}})();",
    ]
    .concat()
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
            let smoke_deadline = started + std::time::Duration::from_secs(5);
            let engine = Engine::start();

            if std::env::var("LEMONVPN_SMOKE").as_deref() == Ok("1") {
                let status = engine.status();
                eprintln!("engine state={} detail={}", status.state, status.detail);
            }

            // Headless check of the proxy switch: `LEMONVPN_PROXY=on|off`.
            if let Ok(action) = std::env::var("LEMONVPN_PROXY") {
                let result = match action.as_str() {
                    "on" => set_system_proxy(&engine, true),
                    "off" => set_system_proxy(&engine, false),
                    other => Err(format!("未知的 LEMONVPN_PROXY 动作: {other}")),
                };
                match &result {
                    Ok(()) => eprintln!("proxy {action} ok: {:?}", proxy::status()),
                    Err(err) => eprintln!("proxy {action} failed: {err}"),
                }
                engine.shutdown();
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            }

            app.manage(engine);
            install_events(app.handle());
            build_menus(app.handle())?;

            // Built in code rather than in tauri.conf.json so the page gets the
            // profile script before doona's bundle reads localStorage.
            let port = app.state::<Engine>().port();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("LemonVPN")
                .inner_size(1100.0, 720.0)
                .initialization_script(seed_profile_script(port))
                .build()?;

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
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            engine_status,
            engine_logs,
            log_page_ready,
            proxy_status,
            proxy_set
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the LemonVPN shell")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(engine) = app.try_state::<Engine>() {
                    engine.shutdown();
                }
                // Never leave the user's system proxy pointing at a dead port.
                if let Err(err) = proxy::disable() {
                    eprintln!("lemonvpn: 退出时恢复系统代理失败: {err}");
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::seed_profile_script;

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
}
