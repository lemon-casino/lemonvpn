//! Byte-mode named pipes with real overlapped completion and bounded waits.
//! A pending operation is cancelled and joined before its buffer/event is freed.
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_support::Win32::{
    Foundation::*,
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Pipes::ConnectNamedPipe,
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

struct Operation {
    state: OVERLAPPED,
    _event: OwnedHandle,
}
impl Operation {
    fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut state: OVERLAPPED = unsafe { std::mem::zeroed() };
        state.hEvent = event.as_raw_handle();
        Ok(Self {
            state,
            _event: event,
        })
    }
    fn cancel(&mut self, file: &File) {
        unsafe {
            CancelIoEx(file.as_raw_handle(), &self.state);
            let mut count = 0;
            GetOverlappedResult(file.as_raw_handle(), &self.state, &mut count, 1);
        }
    }
    fn wait(
        &mut self,
        file: &File,
        deadline: Option<Instant>,
        stop: &AtomicBool,
    ) -> io::Result<u32> {
        loop {
            if stop.load(Ordering::Relaxed) || deadline.is_some_and(|at| Instant::now() >= at) {
                self.cancel(file);
                return Err(io::Error::new(
                    if stop.load(Ordering::Relaxed) {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::TimedOut
                    },
                    "TUN 服务通信已取消或超时",
                ));
            }
            let wait = deadline
                .map(|at| {
                    at.saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(100))
                })
                .unwrap_or(Duration::from_millis(100));
            match unsafe { WaitForSingleObject(self.state.hEvent, wait.as_millis().max(1) as u32) }
            {
                WAIT_OBJECT_0 => {
                    let mut count = 0;
                    let ok = unsafe {
                        GetOverlappedResult(file.as_raw_handle(), &self.state, &mut count, 0)
                    };
                    if ok == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return Ok(count);
                }
                WAIT_TIMEOUT => {}
                _ => {
                    let error = io::Error::last_os_error();
                    self.cancel(file);
                    return Err(error);
                }
            }
        }
    }
}

pub(super) fn connect(file: &File, stop: &AtomicBool) -> io::Result<()> {
    let mut operation = Operation::new()?;
    if unsafe { ConnectNamedPipe(file.as_raw_handle(), &mut operation.state) } != 0 {
        return Ok(());
    }
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => operation.wait(file, None, stop).map(|_| ()),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

pub(super) fn transfer(
    file: &File,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TUN 服务通信超时"));
        }
        let mut operation = Operation::new()?;
        let mut count = 0;
        let ok = unsafe {
            if write {
                WriteFile(
                    file.as_raw_handle(),
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as u32,
                    std::ptr::null_mut(),
                    &mut operation.state,
                )
            } else {
                ReadFile(
                    file.as_raw_handle(),
                    bytes[offset..].as_mut_ptr(),
                    (bytes.len() - offset) as u32,
                    std::ptr::null_mut(),
                    &mut operation.state,
                )
            }
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            count = operation.wait(file, Some(deadline), stop)?;
        } else if unsafe {
            GetOverlappedResult(file.as_raw_handle(), &operation.state, &mut count, 0)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Err(io::Error::new(
                if write {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::UnexpectedEof
                },
                if write {
                    "TUN 服务写入未完成"
                } else {
                    "TUN 服务响应提前结束"
                },
            ));
        }
        offset += count as usize;
    }
    Ok(())
}
