//! Per-outbound counters behind `GET /api/v1/runtime/outbounds`.
//!
//! The engine attributes a tunnel to the outbound the routing decision named.
//! A group therefore carries its members' traffic, and the member rows keep the
//! connections they carried without counting the same bytes twice, so the sum
//! of the rows stays equal to the runtime totals.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::config;
use crate::json;
use crate::state;

#[derive(Default)]
pub struct Counters {
    active: AtomicU64,
    total: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
    errors: AtomicU64,
}

struct Entry {
    kind: &'static str,
    counters: Arc<Counters>,
}

static OUTBOUNDS: OnceLock<Mutex<BTreeMap<String, Entry>>> = OnceLock::new();

fn registry() -> MutexGuard<'static, BTreeMap<String, Entry>> {
    OUTBOUNDS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn entry(entries: &mut BTreeMap<String, Entry>, name: &str, kind: &'static str) -> Arc<Counters> {
    let entry = entries.entry(name.to_owned()).or_insert_with(|| Entry {
        kind,
        counters: Arc::new(Counters::default()),
    });
    // A reload can turn a name into another kind; the newest decision knows best.
    if entry.kind != kind {
        entry.kind = kind;
    }
    Arc::clone(&entry.counters)
}

/// A cheap byte counter for the tunnel's two directions.
#[derive(Clone)]
pub struct Handle(Arc<Counters>);

impl Handle {
    pub fn upload(&self, bytes: u64) {
        self.0.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn download(&self, bytes: u64) {
        self.0.download.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// One open tunnel's attribution; dropping it closes the active count.
pub struct Meter {
    handle: Handle,
}

impl Meter {
    pub fn open(decision: &config::Decision) -> Meter {
        let counters = entry(&mut registry(), &decision.outbound, kind_of(decision));
        counters.active.fetch_add(1, Ordering::Relaxed);
        counters.total.fetch_add(1, Ordering::Relaxed);
        Meter {
            handle: Handle(counters),
        }
    }

    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.handle.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A dial that failed before a tunnel existed. A policy block is not an error.
pub fn record_error(decision: &config::Decision) {
    if decision.blocked() {
        return;
    }
    entry(&mut registry(), &decision.outbound, kind_of(decision))
        .errors
        .fetch_add(1, Ordering::Relaxed);
}

fn kind_of(decision: &config::Decision) -> &'static str {
    if decision.outbound == "direct" || decision.outbound == "block" {
        "builtin"
    } else if decision
        .chain
        .last()
        .is_some_and(|leaf| leaf == &decision.outbound)
    {
        "node"
    } else {
        "group"
    }
}

/// Every outbound the configuration names appears, with zeros when unused.
pub fn snapshot(seed: &[(String, &'static str)]) -> String {
    let mut entries = registry();
    for (name, kind) in seed {
        entry(&mut entries, name, kind);
    }
    let rows = entries
        .iter()
        .map(|(name, entry)| {
            format!(
                concat!(
                    r#"{{"name":"{}","kind":"{}","active_connections":{},"#,
                    r#""total_connections":"{}","upload_bytes":"{}","download_bytes":"{}","errors":"{}"}}"#
                ),
                json::escape(name),
                entry.kind,
                entry.counters.active.load(Ordering::Relaxed),
                entry.counters.total.load(Ordering::Relaxed),
                entry.counters.upload.load(Ordering::Relaxed),
                entry.counters.download.load(Ordering::Relaxed),
                entry.counters.errors.load(Ordering::Relaxed),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"observed_at":"{}","counter_since":"{}","outbounds":[{rows}]}}"#,
        state::iso8601(std::time::SystemTime::now()),
        state::iso8601(state::started()),
    )
}

#[cfg(test)]
mod tests {
    use super::snapshot;

    #[test]
    fn reports_seeded_outbounds_with_their_counters() {
        let body = snapshot(&[("direct".to_owned(), "builtin")]);
        assert!(body.contains(r#""name":"direct""#));
        assert!(body.contains(r#""kind":"builtin""#));
        assert!(body.contains(r#""upload_bytes":""#));
        assert!(body.contains(r#""active_connections":"#));
    }
}
