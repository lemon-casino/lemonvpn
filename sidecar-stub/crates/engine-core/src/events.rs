//! Bounded, resumable invalidation events for `GET /api/v1/events`.
//!
//! Streams include coalesced runtime invalidations, terminal operation updates
//! and accepted generation changes. Per-flow trace events are not advertised.

use std::collections::VecDeque;
#[cfg(test)]
use std::sync::MutexGuard;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::state;

/// The contract's replay window; older events are dropped even with room.
pub const RETENTION_SECONDS: u64 = 60;
/// The replay ring's capacity, also advertised as `max_buffered_events`.
pub const MAX_EVENTS: usize = 1024;
/// Concurrent streams, also advertised as `max_clients`.
pub const MAX_CLIENTS: usize = 16;
/// Idle streams get a comment at this interval; the contract caps it at 15s.
pub const HEARTBEAT_SECONDS: u64 = 15;
/// Kinds this engine produces and advertises.
pub const KINDS: [&str; 4] = [
    "stream.ready",
    "runtime.updated",
    "operation.updated",
    "generation.changed",
];
/// Contract `EventKind` members this engine never produces.
const UNPRODUCED: [&str; 2] = ["flow.updated", "flow.gap"];

/// A coalesced invalidation is enough; the runtime snapshot is polled anyway.
const EMIT_INTERVAL: Duration = Duration::from_secs(5);

pub struct Event {
    pub seq: u64,
    pub kind: &'static str,
    pub data: String,
    pub at: SystemTime,
}

struct Bus {
    next: u64,
    events: VecDeque<Event>,
    clients: usize,
}

static BUS: OnceLock<(Mutex<Bus>, Condvar)> = OnceLock::new();

fn bus() -> &'static (Mutex<Bus>, Condvar) {
    BUS.get_or_init(|| {
        (
            Mutex::new(Bus {
                next: 1,
                events: VecDeque::new(),
                clients: 0,
            }),
            Condvar::new(),
        )
    })
}

#[cfg(test)]
fn lock() -> MutexGuard<'static, Bus> {
    bus()
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Starts the coalesced `runtime.updated` producer. Called once by `main`.
pub fn start(shutdown: crate::runtime::Shutdown) -> std::thread::JoinHandle<()> {
    let _ = bus();
    std::thread::spawn(move || {
        while !shutdown.wait(EMIT_INTERVAL) {
            runtime_changed();
        }
    })
}

/// Mutations notify clients at commit time, without waiting for the periodic
/// counters event to refresh their selections/settings/connections.
pub(crate) fn runtime_changed() {
    emit(
        "runtime.updated",
        serde_json::json!({
            "instance_id": state::instance_id(),
            "observed_at": state::iso8601(SystemTime::now()),
            "href": "/api/v1/runtime"
        })
        .to_string(),
    );
}

/// Appends an event and wakes every stream waiting for one.
pub fn emit(kind: &'static str, data: String) {
    let (lock, cvar) = bus();
    let mut bus = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let seq = bus.next;
    bus.next += 1;
    let now = SystemTime::now();
    bus.events.push_back(Event {
        seq,
        kind,
        data,
        at: now,
    });
    while bus.events.len() > MAX_EVENTS {
        bus.events.pop_front();
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(RETENTION_SECONDS))
        .unwrap_or(UNIX_EPOCH);
    while bus.events.front().is_some_and(|event| event.at < cutoff) {
        bus.events.pop_front();
    }
    cvar.notify_all();
}

pub(crate) fn operation_updated(id: &str, status: &str) {
    emit("operation.updated", serde_json::json!({"instance_id":state::instance_id(),"observed_at":state::iso8601(SystemTime::now()),"resource_id":id,"status":status,"href":format!("/api/v1/operations/{id}")}).to_string());
}

pub(crate) fn generation_changed(previous: &str, generation: &str) {
    // All callers have released the configuration lock. Kernel controllers may
    // call back into the DNS bridge while synchronizing, so do not do this in publish.
    crate::compat::refresh_tun_processes();
    if previous == generation {
        return;
    }
    emit("generation.changed", serde_json::json!({"instance_id":state::instance_id(),"observed_at":state::iso8601(SystemTime::now()),"previous_generation_id":previous,"generation_id":generation}).to_string());
}

pub fn ready_data() -> String {
    format!(
        r#"{{"instance_id":"{}","observed_at":"{}"}}"#,
        state::instance_id(),
        state::iso8601(SystemTime::now()),
    )
}

pub fn event_id(seq: u64) -> String {
    format!("{}:{seq}", state::instance_id())
}

/// The contract's `EventKind` member named `value`, produced or not.
pub fn known(value: &str) -> Option<&'static str> {
    KINDS
        .iter()
        .chain(UNPRODUCED.iter())
        .find(|kind| **kind == value)
        .copied()
}

pub fn produced(kind: &str) -> bool {
    KINDS.contains(&kind)
}

#[derive(Debug)]
pub enum SubscribeError {
    /// Unknown, previous-instance or expired cursor.
    Expired,
    /// `max_clients` streams are already open.
    TooMany,
}

pub struct Subscription {
    /// Next sequence to deliver.
    cursor: u64,
    kinds: Vec<&'static str>,
    /// Echoes a valid supplied cursor, so the ready frame cannot skip pending
    /// replay; otherwise it is the newest emitted sequence.
    pub ready_id: String,
}

impl Subscription {
    /// The next matching event, or `None` when `timeout` elapses. Events
    /// filtered out by `kinds` advance the cursor without being delivered.
    pub fn next(&mut self, timeout: Duration) -> Option<Event> {
        let (lock, cvar) = bus();
        let mut bus = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let deadline = Instant::now() + timeout;
        loop {
            let candidate = bus
                .events
                .iter()
                .find(|event| event.seq >= self.cursor)
                .map(|event| (event.seq, event.kind, event.data.clone(), event.at));
            if let Some((seq, kind, data, at)) = candidate {
                self.cursor = seq + 1;
                if self.kinds.is_empty() || self.kinds.contains(&kind) {
                    return Some(Event {
                        seq,
                        kind,
                        data,
                        at,
                    });
                }
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (guard, _) = cvar
                .wait_timeout(bus, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            bus = guard;
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let (lock, _) = bus();
        let mut bus = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        bus.clients = bus.clients.saturating_sub(1);
    }
}

pub fn subscribe(
    cursor: Option<&str>,
    kinds: Vec<&'static str>,
) -> Result<Subscription, SubscribeError> {
    let (lock, _) = bus();
    let mut bus = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if bus.clients >= MAX_CLIENTS {
        return Err(SubscribeError::TooMany);
    }

    let start = match cursor {
        None => bus.next,
        Some(id) => {
            let (instance, seq) = id.rsplit_once(':').ok_or(SubscribeError::Expired)?;
            if instance != state::instance_id() {
                return Err(SubscribeError::Expired);
            }
            let seq: u64 = seq.parse().map_err(|_| SubscribeError::Expired)?;
            // Only a sequence already emitted can be resumed from.
            if seq >= bus.next {
                return Err(SubscribeError::Expired);
            }
            seq + 1
        }
    };

    // A gap this ring no longer holds cannot be replayed.
    let oldest = bus.events.front().map_or(bus.next, |event| event.seq);
    if start < oldest {
        return Err(SubscribeError::Expired);
    }

    bus.clients += 1;
    Ok(Subscription {
        cursor: start,
        kinds,
        ready_id: event_id(start.saturating_sub(1)),
    })
}

#[cfg(test)]
mod tests {
    use super::{event_id, subscribe, Event};
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    /// The bus is process-global, so tests that emit into it run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn drain(subscription: &mut super::Subscription) -> Option<Event> {
        subscription.next(Duration::from_millis(1))
    }

    #[test]
    fn replays_only_events_after_the_cursor() {
        let _guard = serial();
        super::emit("runtime.updated", "{\"n\":1}".to_string());
        super::emit("runtime.updated", "{\"n\":2}".to_string());
        let head = super::lock().next - 1;
        let cursor = event_id(head - 1);
        let mut subscription = subscribe(Some(&cursor), Vec::new()).unwrap();
        assert_eq!(subscription.ready_id, cursor);
        let event = drain(&mut subscription).expect("replayed event");
        assert_eq!(event.data, "{\"n\":2}");
        assert_eq!(event_id(event.seq), event_id(head));
    }

    #[test]
    fn a_fresh_stream_starts_at_the_head() {
        let _guard = serial();
        super::emit("runtime.updated", "{}".to_string());
        let mut subscription = subscribe(None, Vec::new()).unwrap();
        assert!(drain(&mut subscription).is_none());
    }

    #[test]
    fn a_cursor_from_another_instance_is_expired() {
        let _guard = serial();
        assert!(matches!(
            subscribe(Some("someone-else:1"), Vec::new()),
            Err(super::SubscribeError::Expired)
        ));
        assert!(matches!(
            subscribe(Some("not-a-cursor"), Vec::new()),
            Err(super::SubscribeError::Expired)
        ));
    }
}
