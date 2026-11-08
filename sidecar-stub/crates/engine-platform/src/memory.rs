//! Platform memory snapshots. Unavailable metrics stay None.
#[cfg(windows)]
pub(crate) fn snapshot() -> crate::MemorySnapshot {
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut snapshot = crate::MemorySnapshot::default();
    let mut counters: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of_val(&counters) as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast(), counters.cb) };
    if ok != 0 {
        snapshot.resident_bytes = Some(counters.WorkingSetSize as u64);
        snapshot.peak_resident_bytes = Some(counters.PeakWorkingSetSize as u64);
        snapshot.private_bytes = Some(counters.PrivateUsage as u64);
    }
    let mut system: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    system.dwLength = std::mem::size_of_val(&system) as u32;
    if unsafe { GlobalMemoryStatusEx(&mut system) } != 0 {
        snapshot.system_total_bytes = Some(system.ullTotalPhys);
        snapshot.system_available_bytes = Some(system.ullAvailPhys);
        snapshot.system_used_percent = Some(system.dwMemoryLoad);
    }
    snapshot
}

#[cfg(windows)]
pub(crate) fn resident_bytes() -> Option<u64> {
    snapshot().resident_bytes
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn snapshot() -> crate::MemorySnapshot {
    crate::MemorySnapshot { resident_bytes: resident_bytes(), ..crate::MemorySnapshot::default() }
}

#[cfg(target_os = "macos")]
pub(crate) fn snapshot() -> crate::MemorySnapshot {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    // mach/task_info.h MACH_TASK_BASIC_INFO (flavor 20). The count the kernel
    // expects is the struct size in natural_t units; a mismatched flavor only
    // returns an error, which keeps every metric None.
    #[repr(C)]
    struct TimeValue {
        seconds: c_int,
        microseconds: c_int,
    }
    #[repr(C)]
    struct MachTaskBasicInfo {
        suspend_count: c_uint,
        virtual_size: u64,
        resident_size: u64,
        user_time: TimeValue,
        system_time: TimeValue,
        policy: c_uint,
    }
    extern "C" {
        // mach_task_self_ is exported as a data symbol (mach_port_t); calling
        // it like a function jumps into read-only data and faults (SIGBUS).
        static mach_task_self_: c_uint;
        fn task_info(target: c_uint, flavor: c_uint, info: *mut c_void, count: *mut c_uint) -> c_int;
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }

    let mut snapshot = crate::MemorySnapshot::default();
    let mut info: MachTaskBasicInfo = unsafe { std::mem::zeroed() };
    let mut count = (std::mem::size_of::<MachTaskBasicInfo>() / std::mem::size_of::<c_uint>())
        as c_uint;
    let result = unsafe {
        task_info(
            mach_task_self_,
            20,
            &mut info as *mut MachTaskBasicInfo as *mut c_void,
            &mut count,
        )
    };
    if result == 0 {
        snapshot.resident_bytes = Some(info.resident_size);
    }
    let name = b"hw.memsize\0";
    let mut total: u64 = 0;
    let mut length = std::mem::size_of::<u64>();
    if unsafe {
        sysctlbyname(
            name.as_ptr() as *const c_char,
            (&mut total as *mut u64).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } == 0
    {
        snapshot.system_total_bytes = Some(total);
    }
    snapshot
}

#[cfg(target_os = "macos")]
pub(crate) fn resident_bytes() -> Option<u64> {
    snapshot().resident_bytes
}

#[cfg(target_os = "linux")]
pub(crate) fn resident_bytes() -> Option<u64> {
    // VmRSS is expressed in KiB, independent of 4/16/64 KiB host page size.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?;
    rss.split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn resident_bytes() -> Option<u64> {
    None
}
