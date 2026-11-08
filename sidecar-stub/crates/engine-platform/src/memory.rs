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

#[cfg(not(windows))]
pub(crate) fn snapshot() -> crate::MemorySnapshot {
    crate::MemorySnapshot { resident_bytes: resident_bytes(), ..crate::MemorySnapshot::default() }
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

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) fn resident_bytes() -> Option<u64> {
    None
}
