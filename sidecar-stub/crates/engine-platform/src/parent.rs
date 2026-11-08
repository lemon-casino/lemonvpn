//! Hold a process handle so PID reuse cannot change which parent we watch.
use std::io;
use windows_support::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_support::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
};

pub struct ParentProcess(HANDLE);

impl ParentProcess {
    pub fn open(pid: u32) -> io::Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    pub fn wait(&self) -> io::Result<()> {
        if unsafe { WaitForSingleObject(self.0, INFINITE) } == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_TIMEOUT }
    }
}

impl Drop for ParentProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn is_running(pid: u32) -> io::Result<bool> {
    match ParentProcess::open(pid) {
        Ok(process) => Ok(process.running()),
        Err(error) if error.raw_os_error() == Some(87) => Ok(false),
        Err(error) => Err(error),
    }
}
