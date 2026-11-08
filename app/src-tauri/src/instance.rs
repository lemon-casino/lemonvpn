//! A Windows file handle owns the instance lock. Windows releases it even if
//! the process crashes; a stale PID file alone never prevents a later start.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const LOCK_FILE: &str = "desktop.lock";
const FILE_SHARE_READ: u32 = 1;

pub struct InstanceGuard {
    _file: File,
    pub previous_owner: bool,
}

pub fn data_dir() -> PathBuf {
    std::env::var_os("LEMONVPN_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join("LemonVPN")
        })
}

impl InstanceGuard {
    /// Elevated handover waits for the previous host to finish cleaning up.
    /// Ordinary duplicate launches return immediately without starting an engine.
    pub fn acquire(directory: &Path, wait: Duration) -> io::Result<Option<Self>> {
        std::fs::create_dir_all(directory)?;
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
                    use std::io::{Seek, SeekFrom};
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
}

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
