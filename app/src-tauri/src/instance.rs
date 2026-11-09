//! One shell instance per data directory. Windows keeps a file handle open
//! with exclusive sharing and POSIX hosts keep an `flock` on the same lock
//! file; both release even if the process crashes, so a stale PID text alone
//! never prevents a later start.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const LOCK_FILE: &str = "desktop.lock";

pub struct InstanceGuard {
    _file: File,
    pub previous_owner: bool,
    #[cfg(unix)]
    activation: lemonvpn_engine_platform::desktop_activation::Activation,
}

pub fn data_dir() -> PathBuf {
    std::env::var_os("LEMONVPN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir)
}

#[cfg(windows)]
fn default_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("LemonVPN")
}

#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support/LemonVPN"))
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_data_dir() -> PathBuf {
    // Lock the same directory the engine uses, including XDG_CONFIG_HOME.
    lemonvpn_engine_platform::current().default_data_dir()
}

impl InstanceGuard {
    /// Elevated handover waits for the previous host to finish cleaning up.
    /// Ordinary duplicate launches return immediately without starting an engine.
    pub fn acquire(directory: &Path, wait: Duration) -> io::Result<Option<Self>> {
        std::fs::create_dir_all(directory)?;
        #[cfg(windows)]
        return Self::acquire_shared(directory, wait);
        #[cfg(unix)]
        return Self::acquire_flock(directory, wait);
    }

    #[cfg(windows)]
    fn acquire_shared(directory: &Path, wait: Duration) -> io::Result<Option<Self>> {
        const FILE_SHARE_READ: u32 = 1;
        let deadline = Instant::now() + wait;
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(FILE_SHARE_READ)
                .open(directory.join(LOCK_FILE))
            {
                Ok(mut file) => {
                    let mut previous = String::new();
                    (&mut file).take(64).read_to_string(&mut previous)?;
                    file.seek(SeekFrom::Start(0))?;
                    file.set_len(0)?;
                    write!(file, "{}", std::process::id())?;
                    file.flush()?;
                    return Ok(Some(Self {
                        _file: file,
                        previous_owner: previous.trim().parse::<u32>().is_ok(),
                    }));
                }
                Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(unix)]
    fn acquire_flock(directory: &Path, wait: Duration) -> io::Result<Option<Self>> {
        use std::os::unix::io::AsRawFd;
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        let deadline = Instant::now() + wait;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(LOCK_FILE))?;
        loop {
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
                let mut previous = String::new();
                (&mut file).take(64).read_to_string(&mut previous)?;
                file.seek(SeekFrom::Start(0))?;
                file.set_len(0)?;
                write!(file, "{}", std::process::id())?;
                file.flush()?;
                return Ok(Some(Self {
                    _file: file,
                    previous_owner: previous.trim().parse::<u32>().is_ok(),
                    activation: lemonvpn_engine_platform::desktop_activation::Activation::bind(directory)?,
                }));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(windows)]
pub fn activate_existing(directory: &Path) {
    use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
    let Some(pid) = std::fs::read_to_string(directory.join(LOCK_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
    else {
        return;
    };
    unsafe { EnumWindows(Some(show_owned_window), pid as isize) };
}

#[cfg(unix)]
pub fn activate_existing(directory:&Path){lemonvpn_engine_platform::desktop_activation::notify(directory);}

#[cfg(unix)]
impl InstanceGuard {
    pub fn activation_listener(&self)->io::Result<std::os::unix::net::UnixDatagram>{self.activation.listener()}
}
#[cfg(unix)]
impl Drop for InstanceGuard {fn drop(&mut self){self.activation.close_path();}}

#[cfg(unix)]
pub fn start_activation(socket:std::os::unix::net::UnixDatagram,app:tauri::AppHandle) {
    use tauri::Manager;
    std::thread::spawn(move|| {
        let mut bytes=[0;16];
        loop {
            if app.try_state::<crate::tray::TrayUi>().is_some_and(|state|state.stopped()){break}
            match socket.recv(&mut bytes) {
                Ok(4) if &bytes[..4]==b"show"=>{
                    let target=app.clone();
                    let _=app.run_on_main_thread(move||crate::show_main(&target));
                },
                Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut|io::ErrorKind::Interrupted)=>{},
                Err(_)=>break,_=>{},
            }
        }
    });
}

#[cfg(windows)]
unsafe extern "system" fn show_owned_window(
    window: windows_sys::Win32::Foundation::HWND,
    expected_pid: isize,
) -> i32 {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AllowSetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, SetForegroundWindow,
        ShowWindow, SW_RESTORE,
    };
    let mut pid = 0;
    GetWindowThreadProcessId(window, &mut pid);
    if pid != expected_pid as u32 {
        return 1;
    }
    let mut title = [0; 64];
    let length = GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32);
    if String::from_utf16_lossy(&title[..length.max(0) as usize]) != "LemonVPN" {
        return 1;
    }
    AllowSetForegroundWindow(pid);
    ShowWindow(window, SW_RESTORE);
    SetForegroundWindow(window);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_rejects_duplicates_and_recovers_after_owner_exits() {
        let directory =
            std::env::temp_dir().join(format!("lemonvpn-instance-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // A leftover file from an old PID does not count as a running owner.
        std::fs::write(directory.join(LOCK_FILE), "99999999").unwrap();
        let owner = InstanceGuard::acquire(&directory, Duration::ZERO)
            .unwrap()
            .unwrap();
        assert!(InstanceGuard::acquire(&directory, Duration::ZERO)
            .unwrap()
            .is_none());
        assert_eq!(
            std::fs::read_to_string(directory.join(LOCK_FILE)).unwrap(),
            std::process::id().to_string()
        );
        let waiting_directory = directory.clone();
        let waiter = std::thread::spawn(move || {
            InstanceGuard::acquire(&waiting_directory, Duration::from_secs(2)).unwrap()
        });
        std::thread::sleep(Duration::from_millis(100));
        drop(owner);
        let successor = waiter
            .join()
            .unwrap()
            .expect("handover must acquire the released lock");
        assert!(InstanceGuard::acquire(&directory, Duration::ZERO)
            .unwrap()
            .is_none());
        drop(successor);
        std::fs::remove_file(directory.join(LOCK_FILE)).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
