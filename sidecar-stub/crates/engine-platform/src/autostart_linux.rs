//! XDG user autostart; no system unit, root or global environment changes.
use std::{fs, io, path::PathBuf};
fn entry() -> io::Result<PathBuf> {
    let directory = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .ok_or_else(|| io::Error::other("缺少用户配置目录"))?;
    Ok(directory.join("autostart/org.lemonvpn.desktop.desktop"))
}
fn executable() -> io::Result<PathBuf> {
    // An AppImage's mounted /tmp/.mount_... path is not stable across logins.
    if let Some(path) = std::env::var_os("APPIMAGE").map(PathBuf::from) {
        if path.is_absolute() && path.is_file() {
            return Ok(path);
        }
        return Err(io::Error::other(
            "无法定位 AppImage 原文件，请先保存到固定位置",
        ));
    }
    std::env::current_exe()
}
fn contents() -> io::Result<String> {
    let executable = executable()?;
    let path = executable
        .to_str()
        .ok_or_else(|| io::Error::other("程序路径不是 UTF-8"))?;
    if path.chars().any(char::is_control) {
        return Err(io::Error::other("程序路径包含控制字符"));
    }
    let mut argument = String::from("\"");
    for c in path.chars() {
        if c == '%' {
            argument.push_str("%%");
            continue;
        }
        if ['\\', '\"', '$', '`'].contains(&c) {
            argument.push('\\');
        }
        argument.push(c);
    }
    argument.push('"');
    // Desktop string escaping precedes Exec argument unquoting.
    let exec = argument.replace('\\', "\\\\");
    Ok(format!("[Desktop Entry]\nType=Application\nVersion=1.0\nName=LemonVPN\nExec={exec} --autostart\nIcon=lemonvpn\nTerminal=false\nHidden=false\nX-GNOME-Autostart-enabled=true\nX-LemonVPN-Autostart=true\n"))
}
pub fn enabled() -> bool {
    entry()
        .and_then(fs::read_to_string)
        .ok()
        .zip(contents().ok())
        .is_some_and(|(actual, expected)| actual == expected)
}
pub fn set(enabled: bool) -> io::Result<()> {
    let path = entry()?;
    if enabled {
        let text = contents()?;
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("无效自启路径"))?;
        fs::create_dir_all(directory)?;
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        fs::write(&temporary, text)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(temporary, path)
    } else {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
