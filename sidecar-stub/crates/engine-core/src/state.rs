//! Counters and the traffic ring the native API reports.
//!
//! The engine counts what it can see: bytes through the mixed inbound's tunnels
//! and the tunnels open right now. A recorder thread keeps one sample a second
//! for the ten minutes `capabilities` advertises.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The largest look-back `capabilities` advertises, at one sample a second.
pub const WINDOW_SECONDS: u64 = 600;
pub const MAX_POINTS: u64 = 600;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// The ring keeps a little more than the advertised window, so a sample just
/// outside it still has the predecessor its rate needs.
const MAX_SAMPLES: usize = WINDOW_SECONDS as usize + 8;

static ACTIVE: AtomicU64 = AtomicU64::new(0);
static UPLOAD: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD: AtomicU64 = AtomicU64::new(0);
static STARTED: OnceLock<SystemTime> = OnceLock::new();
static SAMPLES: OnceLock<Mutex<VecDeque<Sample>>> = OnceLock::new();

#[derive(Clone, Copy)]
pub struct Sample {
    pub at: SystemTime,
    /// Cumulative bytes the client sent, and the upstream answered.
    pub upload: u64,
    pub download: u64,
    pub active: u64,
    /// Process resident set at the sample, when the platform can report it.
    pub memory: Option<u64>,
}

/// Process start, fixed by the first call; `main` makes it before serving.
pub fn started() -> SystemTime {
    *STARTED.get_or_init(SystemTime::now)
}

/// The engine instance identity the contract scopes snapshots and cursors to.
pub fn instance_id() -> String {
    format!(
        "lemonvpn-{}-{}",
        std::process::id(),
        started()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

pub fn connection_opened() {
    ACTIVE.fetch_add(1, Ordering::Relaxed);
}

pub fn connection_closed() {
    ACTIVE.fetch_sub(1, Ordering::Relaxed);
}

pub fn add_upload(bytes: u64) {
    UPLOAD.fetch_add(bytes, Ordering::Relaxed);
}

pub fn add_download(bytes: u64) {
    DOWNLOAD.fetch_add(bytes, Ordering::Relaxed);
}

pub fn active() -> u64 {
    ACTIVE.load(Ordering::Relaxed)
}

pub fn upload() -> u64 {
    UPLOAD.load(Ordering::Relaxed)
}

pub fn download() -> u64 {
    DOWNLOAD.load(Ordering::Relaxed)
}

pub fn samples() -> Vec<Sample> {
    ring().iter().copied().collect()
}

pub fn memory_samples() -> Vec<(SystemTime, Option<u64>)> {
    ring()
        .iter()
        .map(|sample| (sample.at, sample.memory))
        .collect()
}

/// The rate over the recorder's latest interval, with the sample it ends at.
pub fn latest_rates() -> Option<(SystemTime, f64, u64, u64)> {
    let samples = ring();
    let last = samples.back()?;
    let previous = samples.iter().rev().nth(1)?;
    let seconds = last.at.duration_since(previous.at).ok()?.as_secs_f64();
    if seconds <= 0.0 {
        return None;
    }
    Some((
        last.at,
        seconds,
        rate(last.upload, previous.upload, seconds),
        rate(last.download, previous.download, seconds),
    ))
}

/// Starts the recorder. Called once, after the listener is bound.
pub fn start_recorder(shutdown: crate::runtime::Shutdown) -> std::thread::JoinHandle<()> {
    SAMPLES.get_or_init(|| Mutex::new(VecDeque::new()));
    std::thread::spawn(move || {
        while !shutdown.wait(SAMPLE_INTERVAL) {
            record();
        }
    })
}

fn record() {
    let at = SystemTime::now();
    let sample = Sample {
        at,
        upload: upload(),
        download: download(),
        active: active(),
        memory: crate::platform::current().resident_memory_bytes(),
    };
    let mut samples = ring();
    samples.push_back(sample);
    while samples.len() > MAX_SAMPLES {
        samples.pop_front();
    }
    let cutoff = at
        .checked_sub(Duration::from_secs(WINDOW_SECONDS + 2))
        .unwrap_or(UNIX_EPOCH);
    while samples.front().is_some_and(|sample| sample.at < cutoff) {
        samples.pop_front();
    }
}

fn rate(now: u64, before: u64, seconds: f64) -> u64 {
    ((now.saturating_sub(before)) as f64 / seconds).round() as u64
}

fn ring() -> MutexGuard<'static, VecDeque<Sample>> {
    SAMPLES
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An RFC 3339 UTC timestamp, seconds precision, as the contract's examples show.
pub fn iso8601(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0) as i64;
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

/// Millisecond samples distinguish rapid reads and new connection counters.
pub fn iso8601_millis(time: SystemTime) -> String {
    let seconds = iso8601(time);
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_millis())
        .unwrap_or(0);
    format!("{}.{millis:03}Z", seconds.trim_end_matches('Z'))
}

/// Howard Hinnant's days-to-civil conversion, for dates the system clock reports.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, iso8601};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso8601(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2024-02-29: the leap day the civil conversion has to keep.
        assert_eq!(
            iso8601(UNIX_EPOCH + Duration::from_secs(19_782 * 86_400)),
            "2024-02-29T00:00:00Z"
        );
        assert_eq!(
            iso8601(UNIX_EPOCH + Duration::from_secs(20_758 * 86_400 + 3_661)),
            "2026-11-01T01:01:01Z"
        );
    }

    #[test]
    fn converts_epoch_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_758), (2026, 11, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
