//! The engine's own log ring and the SSE framing doona's log page reads.
//!
//! Records are sanitized at the source: messages are fixed strings and fields
//! carry only engine facts (a bound address, a protocol, an error kind), never
//! credentials, configuration, stack traces or local paths. The ring is a
//! bounded, in-memory replay window, not durable storage.

use std::collections::VecDeque;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};

use crate::state;

/// The contract's replay window; older records are dropped even with room.
pub const RETENTION_SECONDS: u64 = 300;
/// The contract's replay-ring capacity.
pub const MAX_RECORDS: usize = 256;
/// Advertised levels, weakest first. `trace` is a `LogLevel` member but this
/// engine never emits it, so it is deliberately not advertised.
pub const LEVELS: [Level; 4] = [Level::Debug, Level::Info, Level::Warn, Level::Error];
/// Idle streams get a comment at this interval; the contract caps it at 15s.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const HEARTBEAT: &str = ": heartbeat\n\n";

/// A bounded queue per client. A writer that falls this far behind is closed
/// instead of making the engine wait.
const QUEUE_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(value: &str) -> Option<Level> {
        match value {
            "trace" => Some(Level::Trace),
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }

    /// `self` is the requested minimum severity.
    pub fn accepts(self, actual: Level) -> bool {
        actual >= self
    }

    pub fn advertised(self) -> bool {
        LEVELS.contains(&self)
    }
}

#[derive(Clone, Debug)]
pub struct Record {
    pub seq: u64,
    pub at: SystemTime,
    pub level: Level,
    pub target: &'static str,
    pub message: &'static str,
    /// A pre-rendered JSON object, or `null` for records with no fields.
    pub fields: Option<String>,
}

pub struct Subscription {
    /// Retained matching records strictly after the supplied cursor, oldest
    /// first. Empty for a connection without a cursor.
    pub replay: Vec<Record>,
    pub receiver: Receiver<Record>,
    /// Echoes a valid supplied cursor, so the ready frame cannot skip pending
    /// replay; otherwise it is the newest retained sequence.
    pub ready_id: String,
    pub instance: String,
}

#[derive(Debug)]
pub enum CursorError {
    /// Unknown, expired, previous-instance or changed-filter cursor.
    Expired,
}

pub struct LogStore {
    instance: String,
    capacity: usize,
    retention: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    ring: VecDeque<Record>,
    subscribers: Vec<Subscriber>,
    next_seq: u64,
    /// Highest sequence dropped from the ring. A cursor at this sequence is
    /// still complete: every record after it is retained.
    expired_before: u64,
}

struct Subscriber {
    level: Level,
    sender: SyncSender<Record>,
}

impl LogStore {
    pub fn new(instance: String, capacity: usize, retention: Duration) -> LogStore {
        LogStore {
            instance,
            capacity,
            retention,
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(capacity),
                subscribers: Vec::new(),
                next_seq: 1,
                expired_before: 0,
            }),
        }
    }

    /// Appends a record and fans it out without ever blocking an engine writer.
    pub fn emit(
        &self,
        level: Level,
        target: &'static str,
        message: &'static str,
        fields: Option<String>,
    ) {
        let mut inner = self.lock();
        let record = Record {
            seq: inner.next_seq,
            at: SystemTime::now(),
            level,
            target,
            message,
            fields,
        };
        inner.next_seq += 1;
        inner.ring.push_back(record.clone());
        inner.prune(self.capacity, self.retention, record.at);

        let mut alive = Vec::with_capacity(inner.subscribers.len());
        for subscriber in inner.subscribers.drain(..) {
            if !subscriber.level.accepts(level) {
                alive.push(subscriber);
                continue;
            }
            match subscriber.sender.try_send(record.clone()) {
                Ok(()) => alive.push(subscriber),
                // Full: the client is too slow, so close its stream. The
                // receiver drains what is queued and then sees the disconnect.
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
        }
        inner.subscribers = alive;
    }

    /// Registers a live subscriber and snapshots its replay window under the
    /// same lock, so no record can fall between replay and live delivery.
    pub fn subscribe(
        &self,
        minimum: Level,
        filter: &str,
        after: Option<&str>,
    ) -> Result<Subscription, CursorError> {
        let mut inner = self.lock();
        inner.prune(self.capacity, self.retention, SystemTime::now());
        let latest = inner.next_seq - 1;
        let (replay, ready_id) = match after {
            Some(cursor) => {
                let seq =
                    parse_cursor(cursor, &self.instance, filter).ok_or(CursorError::Expired)?;
                if seq > latest || seq < inner.expired_before {
                    return Err(CursorError::Expired);
                }
                let replay = inner
                    .ring
                    .iter()
                    .filter(|record| record.seq > seq && minimum.accepts(record.level))
                    .cloned()
                    .collect();
                (replay, cursor.to_string())
            }
            None => {
                // A new connection starts at the oldest retained record: the
                // ring exists so a page opened after startup still sees the
                // engine's recent history. The ready cursor sits just before
                // that record, so a resume mid-replay loses nothing.
                let baseline = inner
                    .ring
                    .front()
                    .map(|record| record.seq.saturating_sub(1))
                    .unwrap_or(latest);
                let replay = inner
                    .ring
                    .iter()
                    .filter(|record| minimum.accepts(record.level))
                    .cloned()
                    .collect();
                (replay, cursor_id(&self.instance, filter, baseline))
            }
        };

        let (sender, receiver) = sync_channel(QUEUE_DEPTH);
        inner.subscribers.push(Subscriber {
            level: minimum,
            sender,
        });
        Ok(Subscription {
            replay,
            receiver,
            ready_id,
            instance: self.instance.clone(),
        })
    }

    pub(crate) fn buffered_count(&self) -> usize {
        let mut inner = self.lock();
        inner.prune(self.capacity, self.retention, SystemTime::now());
        inner.ring.len()
    }

    #[cfg(test)]
    fn retained(&self) -> Vec<Record> {
        self.lock().ring.iter().cloned().collect()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Inner {
    fn prune(&mut self, capacity: usize, retention: Duration, now: SystemTime) {
        while self.ring.len() > capacity {
            if let Some(dropped) = self.ring.pop_front() {
                self.expired_before = self.expired_before.max(dropped.seq);
            }
        }
        let cutoff = now.checked_sub(retention).unwrap_or(SystemTime::UNIX_EPOCH);
        while self.ring.front().is_some_and(|record| record.at < cutoff) {
            if let Some(dropped) = self.ring.pop_front() {
                self.expired_before = self.expired_before.max(dropped.seq);
            }
        }
    }
}

static STORE: OnceLock<LogStore> = OnceLock::new();

pub fn store() -> &'static LogStore {
    STORE.get_or_init(|| {
        LogStore::new(
            state::instance_id(),
            MAX_RECORDS,
            Duration::from_secs(RETENTION_SECONDS),
        )
    })
}

pub fn emit(level: Level, target: &'static str, message: &'static str, fields: Option<String>) {
    if !crate::control::recording_active("record_logs") {
        return;
    }
    if crate::control::settings_log_level().accepts(level) {
        store().emit(level, target, message, fields);
    }
}

pub fn debug(target: &'static str, message: &'static str, fields: Option<String>) {
    emit(Level::Debug, target, message, fields);
}

pub fn info(target: &'static str, message: &'static str, fields: Option<String>) {
    emit(Level::Info, target, message, fields);
}

pub fn warn(target: &'static str, message: &'static str, fields: Option<String>) {
    emit(Level::Warn, target, message, fields);
}

pub fn error(target: &'static str, message: &'static str, fields: Option<String>) {
    emit(Level::Error, target, message, fields);
}

/// The opaque id of a log frame; the level filter is part of the cursor so a
/// reconnect with a changed filter is rejected instead of silently rebased.
pub fn cursor_id(instance: &str, filter: &str, seq: u64) -> String {
    format!("{instance}:logs:{filter}:{seq}")
}

fn parse_cursor(cursor: &str, instance: &str, filter: &str) -> Option<u64> {
    let mut parts = cursor.split(':');
    if parts.next()? != instance || parts.next()? != "logs" || parts.next()? != filter {
        return None;
    }
    let seq = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some(seq)
}

pub fn ready_frame(id: &str, instance: &str, observed_at: &str) -> String {
    format!(
        "id: {id}\nevent: stream.ready\ndata: {{\"instance_id\":\"{}\",\"observed_at\":\"{}\"}}\n\n",
        escape(instance),
        escape(observed_at)
    )
}

pub fn record_frame(id: &str, record: &Record) -> String {
    format!(
        "id: {id}\nevent: log\ndata: {{\"ts\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"message\":\"{}\",\"fields\":{}}}\n\n",
        escape(&state::iso8601(record.at)),
        record.level.as_str(),
        escape(record.target),
        escape(record.message),
        record.fields.as_deref().unwrap_or("null")
    )
}

/// Builds a JSON object of string fields, escaping values that came from a
/// client (a protocol name, an error kind) before they reach the ring.
pub fn fields(pairs: &[(&str, &str)]) -> String {
    let body = pairs
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", escape(key), escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        cursor_id, escape, fields, parse_cursor, ready_frame, record_frame, Level, LogStore,
        Record, MAX_RECORDS, RETENTION_SECONDS,
    };
    use std::time::{Duration, UNIX_EPOCH};

    fn store() -> LogStore {
        LogStore::new(
            "lemonvpn-9".to_string(),
            MAX_RECORDS,
            Duration::from_secs(RETENTION_SECONDS),
        )
    }

    fn record() -> Record {
        Record {
            seq: 7,
            at: UNIX_EPOCH + Duration::from_secs(20_758 * 86_400),
            level: Level::Info,
            target: "engine::tunnel",
            message: "Tunnel established.",
            fields: Some(fields(&[("via", "socks5")])),
        }
    }

    #[test]
    fn writes_well_formed_sse_frames() {
        assert_eq!(
            ready_frame("lemonvpn-9:logs:all:3", "lemonvpn-9", "2026-11-01T00:00:00Z"),
            "id: lemonvpn-9:logs:all:3\nevent: stream.ready\ndata: {\"instance_id\":\"lemonvpn-9\",\"observed_at\":\"2026-11-01T00:00:00Z\"}\n\n"
        );
        assert_eq!(
            record_frame("lemonvpn-9:logs:info:7", &record()),
            "id: lemonvpn-9:logs:info:7\nevent: log\ndata: {\"ts\":\"2026-11-01T00:00:00Z\",\"level\":\"info\",\"target\":\"engine::tunnel\",\"message\":\"Tunnel established.\",\"fields\":{\"via\":\"socks5\"}}\n\n"
        );
    }

    #[test]
    fn escapes_json_strings() {
        assert_eq!(escape("a\"b\\c\n\t"), "a\\\"b\\\\c\\n\\t");
        assert_eq!(fields(&[("k", "a\nb")]), "{\"k\":\"a\\nb\"}");
    }

    #[test]
    fn parses_levels_and_orders_them() {
        assert_eq!(Level::parse("trace"), Some(Level::Trace));
        assert_eq!(Level::parse("info"), Some(Level::Info));
        assert_eq!(Level::parse("error"), Some(Level::Error));
        assert_eq!(Level::parse("INFO"), None);
        assert_eq!(Level::parse("all"), None);
        assert!(!Level::Trace.advertised());
        assert!(Level::Error.advertised());
        assert!(Level::Info.accepts(Level::Warn));
        assert!(Level::Info.accepts(Level::Info));
        assert!(!Level::Info.accepts(Level::Debug));
        assert!(!Level::Warn.accepts(Level::Info));
    }

    #[test]
    fn parses_only_cursors_for_this_instance_and_filter() {
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:all:7", "lemonvpn-9", "all"),
            Some(7)
        );
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:info:0", "lemonvpn-9", "info"),
            Some(0)
        );
        assert_eq!(
            parse_cursor("lemonvpn-8:logs:all:7", "lemonvpn-9", "all"),
            None
        );
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:info:7", "lemonvpn-9", "all"),
            None
        );
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:all:x", "lemonvpn-9", "all"),
            None
        );
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:all", "lemonvpn-9", "all"),
            None
        );
        assert_eq!(
            parse_cursor("lemonvpn-9:logs:all:7:8", "lemonvpn-9", "all"),
            None
        );
        assert_eq!(parse_cursor("", "lemonvpn-9", "all"), None);
    }

    #[test]
    fn filters_live_records_by_minimum_level() {
        let store = store();
        let subscription = store.subscribe(Level::Info, "info", None).unwrap();
        store.emit(Level::Debug, "engine::test", "debug", None);
        store.emit(Level::Info, "engine::test", "info", None);
        store.emit(Level::Error, "engine::test", "error", None);

        assert_eq!(subscription.receiver.try_recv().unwrap().message, "info");
        assert_eq!(subscription.receiver.try_recv().unwrap().message, "error");
        assert!(subscription.receiver.try_recv().is_err());
    }

    #[test]
    fn replays_only_matching_records_after_the_cursor() {
        let store = store();
        store.emit(Level::Debug, "engine::test", "one", None);
        store.emit(Level::Info, "engine::test", "two", None);
        store.emit(Level::Error, "engine::test", "three", None);

        let subscription = store
            .subscribe(Level::Info, "all", Some("lemonvpn-9:logs:all:0"))
            .unwrap();
        let seqs: Vec<u64> = subscription
            .replay
            .iter()
            .map(|record| record.seq)
            .collect();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(subscription.ready_id, "lemonvpn-9:logs:all:0");

        let fresh = store.subscribe(Level::Info, "all", None).unwrap();
        let seqs: Vec<u64> = fresh.replay.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![2, 3], "新连接应从保留窗口的开头回放");
        assert_eq!(fresh.ready_id, "lemonvpn-9:logs:all:0");
    }

    #[test]
    fn rejects_unknown_and_expired_cursors() {
        let store = store();
        for _ in 0..4 {
            store.emit(Level::Info, "engine::test", "record", None);
        }
        assert!(store
            .subscribe(Level::Trace, "all", Some("lemonvpn-9:logs:all:99"))
            .is_err());
        assert!(store
            .subscribe(Level::Trace, "all", Some("lemonvpn-8:logs:all:1"))
            .is_err());
        assert!(store
            .subscribe(Level::Trace, "all", Some("lemonvpn-9:logs:info:1"))
            .is_err());
        assert!(store
            .subscribe(Level::Trace, "all", Some("nonsense"))
            .is_err());
    }

    #[test]
    fn bounds_the_ring_and_expires_the_oldest_cursor() {
        let store = LogStore::new("lemonvpn-9".to_string(), 2, Duration::from_secs(300));
        for _ in 0..4 {
            store.emit(Level::Info, "engine::test", "record", None);
        }
        let seqs: Vec<u64> = store.retained().iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![3, 4]);

        // Sequence 2 was dropped, so replaying after it would lose record 3.
        assert!(store
            .subscribe(Level::Trace, "all", Some("lemonvpn-9:logs:all:1"))
            .is_err());
        // Sequence 2 is the last dropped one; everything after it is retained.
        let subscription = store
            .subscribe(Level::Trace, "all", Some("lemonvpn-9:logs:all:2"))
            .unwrap();
        let seqs: Vec<u64> = subscription
            .replay
            .iter()
            .map(|record| record.seq)
            .collect();
        assert_eq!(seqs, vec![3, 4]);
    }

    #[test]
    fn heartbeats_stay_within_the_contract_interval() {
        assert_eq!(super::HEARTBEAT, ": heartbeat\n\n");
        assert!(super::HEARTBEAT_INTERVAL <= Duration::from_secs(15));
    }

    #[test]
    fn cursor_ids_round_trip() {
        let id = cursor_id("lemonvpn-9", "warn", 12);
        assert_eq!(id, "lemonvpn-9:logs:warn:12");
        assert_eq!(parse_cursor(&id, "lemonvpn-9", "warn"), Some(12));
    }
}
