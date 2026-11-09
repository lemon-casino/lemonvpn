//! User-triggered elevation; passwords stay in the OS authentication UI/TTY.
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .into_iter()
        .map(|p| Path::new(p).join(name))
        .find(|p| p.is_file())
}
pub fn authorize(executable: &Path, args: &[String]) -> io::Result<()> {
    let mut command = if let Some(pkexec) = tool("pkexec") {
        let mut command = Command::new(pkexec);
        command.arg(executable).args(args);
        command
    } else {
        let sudo = tool("sudo")
            .ok_or_else(|| io::Error::other("缺少 pkexec 或 sudo，无法申请管理员授权"))?;
        if std::env::var_os("SUDO_ASKPASS").is_some() {
            let mut command = Command::new(&sudo);
            command.args(["-A", "--"]).arg(executable).args(args);
            command
        } else {
            let choices: [(&str, &[&str]); 7] = [
                ("gnome-terminal", &["--wait", "--"]),
                ("konsole", &["--nofork", "-e"]),
                ("xfce4-terminal", &["--disable-server", "-x"]),
                ("mate-terminal", &["--disable-factory", "-x"]),
                ("xterm", &["-e"]),
                ("alacritty", &["-e"]),
                ("kitty", &["-e"]),
            ];
            let (path, flags) = choices
                .into_iter()
                .find_map(|(name, flags)| tool(name).map(|p| (p, flags)))
                .ok_or_else(|| {
                    io::Error::other("缺少图形授权器，请安装 polkit 或提供 sudo 的终端/askpass")
                })?;
            let mut command = Command::new(path);
            command
                .args(flags)
                .arg(sudo)
                .arg("--")
                .arg(executable)
                .args(args);
            command
        }
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    use std::io::Read;
    let stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.take(64 * 1024).read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "管理员授权超时或失败",
                ));
            }
        }
    };
    let reason = reader.join().unwrap_or_default();
    if outcome?.success() {
        Ok(())
    } else {
        Err(io::Error::other(if reason.trim().is_empty() {
            "管理员授权已取消或服务操作失败".to_owned()
        } else {
            reason.trim().to_owned()
        }))
    }
}
