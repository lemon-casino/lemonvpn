//! Window chrome actions are scoped to the invoking main webview.
use tauri::Manager;
#[tauri::command]
pub fn window_action(window: tauri::WebviewWindow, action: String) -> Result<bool, String> {
    if window.label() != "main" {
        return Err("窗口操作只用于主窗口".to_owned());
    }
    let result = match action.as_str() {
        "quit" => {
            window.app_handle().exit(0);
            return Ok(false);
        }
        "minimize" => window.minimize(),
        "toggle_maximize" => {
            if window.is_maximized().map_err(|error| error.to_string())? {
                window.unmaximize()
            } else {
                window.maximize()
            }
        }
        "close" => window.close(),
        "start_dragging" => window.start_dragging(),
        "state" => Ok(()),
        _ => return Err("未知窗口操作".to_owned()),
    };
    result.map_err(|error| error.to_string())?;
    window.is_maximized().map_err(|error| error.to_string())
}
