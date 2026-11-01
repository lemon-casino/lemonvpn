//! The live tunnel registry behind `GET /api/v1/connections`.
//!
//! The engine can only report what its own inbound sees: the two endpoints, the
//! start instant and the bytes each direction moved. Routing labels (rule,
//! chain, domain) belong to a rule engine this datapath does not have, so they
//! stay null/unknown rather than being invented.

use std::collections::BTreeMap;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

static NEXT: AtomicU64 = AtomicU64::new(1);
static OPEN: OnceLock<Mutex<BTreeMap<u64, Entry>>> = OnceLock::new();

/// Per-tunnel byte counters, written by the tunnel's reads and read by the API.
#[derive(Default)]
pub struct Counters {
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

struct Entry {
    id: String,
    src: String,
    src_ip: String,
    dst: String,
    started_at: SystemTime,
    counters: Arc<Counters>,
    /// A clone of the inbound socket; `shutdown` on it ends the tunnel.
    socket: Option<TcpStream>,
}

/// A registered tunnel; dropping it removes the entry.
pub struct Live {
    key: u64,
    pub counters: Arc<Counters>,
}

impl Live {
    pub fn open(src: SocketAddr, dst: SocketAddr, socket: Option<TcpStream>) -> Live {
        let key = NEXT.fetch_add(1, Ordering::Relaxed);
        let counters = Arc::new(Counters::default());
        let entry = Entry {
            id: format!("tcp-{}-{key}", std::process::id()),
            src: src.to_string(),
            src_ip: src.ip().to_string(),
            dst: dst.to_string(),
            started_at: SystemTime::now(),
            counters: Arc::clone(&counters),
            socket,
        };
        open().insert(key, entry);
        Live { key, counters }
    }
}

/// Force-closes one live tunnel by id. A second close misses the entry and
/// reports false, which the API turns into 404.
pub fn close(id: &str) -> bool {
    let mut map = open();
    let key = map
        .iter()
        .find(|(_, entry)| entry.id == id)
        .map(|(key, _)| *key);
    let Some(key) = key else { return false };
    if let Some(entry) = map.remove(&key) {
        if let Some(socket) = entry.socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
    true
}

impl Drop for Live {
    fn drop(&mut self) {
        open().remove(&self.key);
    }
}

pub struct Snapshot {
    pub id: String,
    pub src: String,
    pub src_ip: String,
    pub dst: String,
    pub started_at: SystemTime,
    pub upload: u64,
    pub download: u64,
}

pub fn snapshot() -> Vec<Snapshot> {
    open()
        .values()
        .map(|entry| Snapshot {
            id: entry.id.clone(),
            src: entry.src.clone(),
            src_ip: entry.src_ip.clone(),
            dst: entry.dst.clone(),
            started_at: entry.started_at,
            upload: entry.counters.upload.load(Ordering::Relaxed),
            download: entry.counters.download.load(Ordering::Relaxed),
        })
        .collect()
}

fn open() -> MutexGuard<'static, BTreeMap<u64, Entry>> {
    OPEN
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{snapshot, Live};
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn registers_and_removes_a_tunnel() {
        let before = snapshot().len();
        let live = Live::open(addr(1234), addr(443), None);
        live.counters.upload.fetch_add(7, Ordering::Relaxed);
        live.counters.download.fetch_add(11, Ordering::Relaxed);

        let rows = snapshot();
        assert_eq!(rows.len(), before + 1);
        let row = rows.iter().find(|row| row.src == "127.0.0.1:1234").unwrap();
        assert_eq!(row.dst, "127.0.0.1:443");
        assert_eq!(row.src_ip, "127.0.0.1");
        assert_eq!(row.upload, 7);
        assert_eq!(row.download, 11);

        drop(live);
        assert_eq!(snapshot().len(), before);
    }
}
