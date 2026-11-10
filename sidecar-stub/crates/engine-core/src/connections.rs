//! The live tunnel registry behind `GET /api/v1/connections`.
//!
//! Routing evidence belongs to the actual tunnel. Hot application retires old
//! tunnels instead of relabelling them as if their transport had migrated.

use std::collections::BTreeMap;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

static NEXT: AtomicU64 = AtomicU64::new(1);
static OPEN: OnceLock<Mutex<Registry>> = OnceLock::new();

#[derive(Default)]
struct Registry {
    entries: BTreeMap<u64, Entry>,
    configuration: u64,
    selections: BTreeMap<(String, String), u64>,
}

/// Captured with a routing decision, before its potentially slow outbound dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouteEpoch {
    configuration: u64,
    selections: Vec<(String, u64)>,
}

impl Registry {
    fn epoch_for(&self, outbounds: &[String], network: &str) -> RouteEpoch {
        RouteEpoch {
            configuration: self.configuration,
            selections: outbounds
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        self.selections
                            .get(&(name.clone(), network.into()))
                            .copied()
                            .unwrap_or(0),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
pub(crate) fn route_epoch(outbound: &str, network: &str) -> RouteEpoch {
    route_epoch_for(&[outbound.to_owned()], network)
}
pub(crate) fn route_epoch_for(outbounds: &[String], network: &str) -> RouteEpoch {
    open().epoch_for(outbounds, network)
}

/// Called while the configuration lock is held, after publishing a valid
/// traffic change. New decisions cannot race ahead of the retirement boundary.
pub(crate) fn configuration_changed() -> usize {
    let mut registry = open();
    registry.configuration = registry.configuration.wrapping_add(1);
    registry.selections.clear();
    let entries = std::mem::take(&mut registry.entries);
    drop(registry);
    retire(entries.into_values())
}

pub(crate) struct Recheck {
    pub host:String,pub port:u16,pub source:Option<SocketAddr>,pub network:&'static str,
    pub route:Option<Route>,
}
/// Bump the dial epoch while holding the registry, then release it before
/// resolving policies: decision construction also reads the registry epoch.
pub(crate) fn configuration_changed_selective(keep:impl Fn(&Recheck)->bool)->usize{
    let candidates={let mut registry=open();registry.configuration=registry.configuration.wrapping_add(1);registry.selections.clear();
        registry.entries.iter().map(|(id,entry)|{
            let(host,port)=crate::proxy::parse_authority(&entry.dst,443).unwrap_or((entry.dst.clone(),0));
            (*id,Recheck{host,port,source:entry.src.parse().ok(),network:entry.network,route:entry.route.clone()})
        }).collect::<Vec<_>>()};
    let remove=candidates.into_iter().filter_map(|(id,input)|(!keep(&input)).then_some(id)).collect::<Vec<_>>();
    let entries={let mut registry=open();remove.into_iter().filter_map(|id|registry.entries.remove(&id)).collect::<Vec<_>>()};retire(entries)
}

/// Only the selected group's requested transport is invalidated. An unrelated
/// group, and UDP when selecting TCP (or vice versa), retain their tunnels.
pub(crate) fn selection_changed(group: &str, network: &str) -> usize {
    let mut registry = open();
    for kind in ["tcp", "udp"] {
        if network == "both" || network == kind {
            let revision = registry
                .selections
                .entry((group.into(), kind.into()))
                .or_default();
            *revision = revision.wrapping_add(1);
        }
    }
    let keys = registry
        .entries
        .iter()
        .filter_map(|(key, entry)| {
            ((network == "both" || entry.network == network)
                && entry.route.as_ref().is_some_and(|route| {
                    route.outbound == group
                        || route
                            .chain
                            .iter()
                            .any(|hop| hop == &format!("group-{group}"))
                }))
            .then_some(*key)
        })
        .collect::<Vec<_>>();
    let entries = keys
        .into_iter()
        .filter_map(|key| registry.entries.remove(&key))
        .collect::<Vec<_>>();
    drop(registry);
    retire(entries)
}

fn retire(entries: impl IntoIterator<Item = Entry>) -> usize {
    let mut count = 0;
    for entry in entries {
        count += 1;
        entry.closed.store(true, Ordering::Release);
        for socket in entry.sockets {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
    count
}

/// Per-tunnel byte counters, written by the tunnel's reads and read by the API.
#[derive(Default)]
pub struct Counters {
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

#[derive(Clone)]
pub struct Route {
    pub process: Option<crate::platform::process::ProcessInfo>,
    pub outbound: String,
    pub chain: Vec<String>,
    pub chain_front_hops: Option<usize>,
    pub generation: String,
    pub rule_id: String,
    pub expression: String,
    pub flow_id: Option<String>,
    pub domain_source: Option<&'static str>,
}

struct Entry {
    network: &'static str,
    closed: Arc<AtomicBool>,
    id: String,
    src: String,
    src_ip: String,
    dst: String,
    domain: Option<String>,
    route: Option<Route>,
    started_at: SystemTime,
    counters: Arc<Counters>,
    /// A clone of the inbound socket; `shutdown` on it ends the tunnel.
    sockets: Vec<TcpStream>,
}

/// A registered tunnel; dropping it removes the entry.
pub struct Live {
    closed: Arc<AtomicBool>,
    key: u64,
    pub counters: Arc<Counters>,
}

impl Live {
    pub fn open(src: SocketAddr, dst: SocketAddr, socket: Option<TcpStream>) -> Live {
        Self::register(src, dst.to_string(), socket, "tcp")
    }
    pub(crate) fn udp(src: SocketAddr, host: &str, port: u16) -> Live {
        Self::register(src, target_address(host, port), None, "udp")
    }
    pub(crate) fn tcp_target(
        src: SocketAddr,
        host: &str,
        port: u16,
        socket: Option<TcpStream>,
    ) -> Live {
        Self::register(src, target_address(host, port), socket, "tcp")
    }
    pub(crate) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed)
    }
    fn register(
        src: SocketAddr,
        dst: String,
        socket: Option<TcpStream>,
        network: &'static str,
    ) -> Live {
        let key = NEXT.fetch_add(1, Ordering::Relaxed);
        let counters = Arc::new(Counters::default());
        let closed = Arc::new(AtomicBool::new(false));
        let host = dst.rsplit_once(':').map(|(host, _)| host).unwrap_or(&dst);
        let domain = (host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_err())
        .then(|| host.to_owned());
        let entry = Entry {
            network,
            closed: Arc::clone(&closed),
            id: format!("{network}-{}-{key}", std::process::id()),
            src: src.to_string(),
            src_ip: src.ip().to_string(),
            dst: dst.to_string(),
            domain,
            route: None,
            started_at: SystemTime::now(),
            counters: Arc::clone(&counters),
            sockets: socket.into_iter().collect(),
        };
        open().entries.insert(key, entry);
        Live {
            key,
            counters,
            closed,
        }
    }

    pub(crate) fn attach_socket(&self, socket: TcpStream) {
        if let Some(entry) = open().entries.get_mut(&self.key) {
            entry.sockets.push(socket);
        } else {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn set_route(
        &self,
        decision: &crate::config::Decision,
        flow: Option<&crate::flows::Guard>,
    ) {
        let id = open().entries.get(&self.key).map(|entry| entry.id.clone());
        let linked = id
            .as_deref()
            .and_then(|id| flow.and_then(|flow| flow.link_connection(id)));
        let route = Route {
            process: decision.process.clone(),
            outbound: decision.outbound.clone(),
            chain: decision.selection_path(),
            chain_front_hops: match &decision.target {
                crate::config::Target::Chain { front_len, .. } => Some(*front_len),
                _ => None,
            },
            generation: decision.generation.clone(),
            rule_id: decision.rule_id.clone(),
            expression: decision.expression.clone(),
            flow_id: linked.as_ref().map(|(id, _)| id.clone()),
            domain_source: linked.and_then(|(_, source)| source),
        };
        let mut registry = open();
        if let Some(entry) = registry.entries.get(&self.key) {
            if registry.epoch_for(&decision.dependencies, entry.network) != decision.epoch {
                // A dial begun before a commit must never revive the old path.
                let entry = registry.entries.remove(&self.key).unwrap();
                drop(registry);
                retire([entry]);
                return;
            }
        }
        if let Some(entry) = registry.entries.get_mut(&self.key) {
            entry.route = Some(route);
        }
    }
}

pub(crate) fn target_address(host: &str, port: u16) -> String {
    host.parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .unwrap_or_else(|_| format!("{host}:{port}"))
}

/// Force-closes one live tunnel by id. A second close misses the entry and
/// reports false, which the API turns into 404.
pub fn close(id: &str) -> bool {
    let mut map = open();
    let key = map
        .entries
        .iter()
        .find(|(_, entry)| entry.id == id)
        .map(|(key, _)| *key);
    let Some(key) = key else { return false };
    if let Some(entry) = map.entries.remove(&key) {
        drop(map);
        retire([entry]);
    }
    true
}

pub(crate) fn close_all() {
    let entries = std::mem::take(&mut open().entries);
    retire(entries.into_values());
}

/// Retire exactly this accepted socket, including its outbound socket. The
/// local endpoint distinguishes LAN sessions from the loopback proxy even if
/// a client reuses a source port across two different listeners.
pub(crate) fn close_inbound(socket: &TcpStream) {
    let (Ok(local), Ok(peer)) = (socket.local_addr(), socket.peer_addr()) else {
        return;
    };
    let mut registry = open();
    let keys: Vec<_> = registry
        .entries
        .iter()
        .filter(|(_, entry)| {
            entry.sockets.first().is_some_and(|inbound| {
                inbound.local_addr().ok() == Some(local) && inbound.peer_addr().ok() == Some(peer)
            })
        })
        .map(|(key, _)| *key)
        .collect();
    let entries: Vec<_> = keys
        .into_iter()
        .filter_map(|key| registry.entries.remove(&key))
        .collect();
    drop(registry);
    retire(entries);
}

impl Drop for Live {
    fn drop(&mut self) {
        open().entries.remove(&self.key);
    }
}

pub struct Snapshot {
    pub network: &'static str,
    pub id: String,
    pub src: String,
    pub src_ip: String,
    pub dst: String,
    pub domain: Option<String>,
    pub route: Option<Route>,
    pub started_at: SystemTime,
    pub upload: u64,
    pub download: u64,
}

pub fn snapshot() -> Vec<Snapshot> {
    snapshot_matching(None)
}

pub(crate) fn snapshot_group(id: &str) -> Vec<Snapshot> {
    snapshot_matching(Some(id))
}

fn snapshot_matching(group: Option<&str>) -> Vec<Snapshot> {
    open()
        .entries
        .values()
        .filter(|entry| {
            group.is_none_or(|id| {
                entry
                    .route
                    .as_ref()
                    .is_some_and(|route| route.chain.iter().any(|hop| hop == id))
            })
        })
        .map(|entry| Snapshot {
            network: entry.network,
            id: entry.id.clone(),
            src: entry.src.clone(),
            src_ip: entry.src_ip.clone(),
            dst: entry.dst.clone(),
            domain: entry.domain.clone(),
            route: entry.route.clone(),
            started_at: entry.started_at,
            upload: entry.counters.upload.load(Ordering::Relaxed),
            download: entry.counters.download.load(Ordering::Relaxed),
        })
        .collect()
}

fn open() -> MutexGuard<'static, Registry> {
    OPEN.get_or_init(|| Mutex::new(Registry::default()))
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
