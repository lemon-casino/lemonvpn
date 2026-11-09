//! An owned hidden console lets Go receive CTRL_BREAK and save Fake-IP state.
//! Signalling is isolated in a helper, so the host's own console is untouched.
use std::{
    io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, RawHandle},
    },
    path::Path,
};
use windows_support::Win32::{
    Foundation::*,
    System::{Console::*, Threading::*},
};

pub struct KernelChild {
    handle: HANDLE,
    pid: u32,
}
unsafe impl Send for KernelChild {}
impl KernelChild {
    pub fn spawn(binary: &Path, directory: &Path, file: &Path, tun: bool) -> io::Result<Self> {
        let wide = |path: &Path| path.as_os_str().encode_wide().collect::<Vec<_>>();
        let application = binary
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut command = vec![b'"' as u16];
        command.extend(wide(binary));
        command.extend("\" -d \"".encode_utf16());
        command.extend(wide(directory));
        command.extend("\" -f \"".encode_utf16());
        command.extend(wide(file));
        command.extend([b'"' as u16, 0]);
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = 0; // SW_HIDE: the dedicated console is never visible.
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                if tun {
                    CREATE_NEW_CONSOLE
                } else {
                    CREATE_NO_WINDOW
                },
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut process,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            CloseHandle(process.hThread);
        }
        Ok(Self {
            handle: process.hProcess,
            pid: process.dwProcessId,
        })
    }
    pub fn id(&self) -> u32 {
        self.pid
    }
    pub fn try_wait(&mut self) -> io::Result<Option<()>> {
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.handle, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((code != 259).then_some(()))
    }
    pub fn kill(&mut self) -> io::Result<()> {
        if unsafe { TerminateProcess(self.handle, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn wait(&mut self) -> io::Result<()> {
        if unsafe { WaitForSingleObject(self.handle, INFINITE) } == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl AsRawHandle for KernelChild {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle
    }
}
impl Drop for KernelChild {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Only the service executable dispatches this helper role. It owns no routes.
pub fn signal(pid: u32) -> io::Result<()> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut path = vec![0u16; 32768];
        let mut size = path.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut size);
        CloseHandle(process);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..size as usize]));
        if path.file_name().is_none_or(|name| {
            !name
                .to_string_lossy()
                .eq_ignore_ascii_case("lemonvpn-kernel.exe")
        }) {
            return Err(io::Error::other("目标不是 LemonVPN 内核"));
        }
        if AttachConsole(pid) == 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe extern "system" fn ignore_console_event(_: u32) -> i32 {
            1
        }
        SetConsoleCtrlHandler(Some(ignore_console_event), 1);
        // This new, hidden console contains only the owned kernel and this helper.
        let ok = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
        let error = io::Error::last_os_error();
        FreeConsole();
        if ok == 0 {
            return Err(error);
        }
    }
    Ok(())
}
