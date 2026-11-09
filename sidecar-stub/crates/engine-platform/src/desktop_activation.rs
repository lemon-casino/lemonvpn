//! Same-user show-window datagrams; the application keeps its instance lock
//! until close_path has removed the socket. Requests queue during GUI startup.
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn notify(directory: &Path) {
    let Ok(path) = activation_path(directory) else {
        return;
    };
    let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    for _ in 0..20 {
        if socket.send_to(b"show", &path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn activation_path(directory: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    extern "C" {
        fn geteuid() -> u32;
    }
    let uid = unsafe { geteuid() };
    let root = PathBuf::from(format!("/tmp/lemonvpn-{uid}"));
    match std::fs::create_dir(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(&root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "窗口通信目录归属异常",
        ));
    }
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    // A fixed short pathname also works for deeply nested macOS data folders.
    use std::os::unix::ffi::OsStrExt;
    let mut digest = 0xcbf29ce484222325u64;
    for byte in directory.canonicalize()?.as_os_str().as_bytes() {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x100000001b3);
    }
    Ok(root.join(format!("activate-{digest:016x}.sock")))
}

pub struct Activation {
    socket: std::os::unix::net::UnixDatagram,
    path: Option<PathBuf>,
}
impl Activation {
    pub fn bind(directory: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let path = activation_path(directory)?;
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "窗口通信路径被占用",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let socket = std::os::unix::net::UnixDatagram::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self {
            socket,
            path: Some(path),
        })
    }
}
impl Activation {
    pub fn listener(&self) -> io::Result<std::os::unix::net::UnixDatagram> {
        self.socket.try_clone()
    }
    pub fn close_path(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}
impl Drop for Activation {
    fn drop(&mut self) {
        self.close_path();
    }
}
