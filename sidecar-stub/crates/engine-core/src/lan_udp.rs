//! UDP associations are authorized by a live, authenticated TCP session.
//! One shared UDP port also works through Docker's explicit UDP publication.
use std::{
    collections::HashMap,
    io,
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc, Mutex, Weak},
};
type Packet = (Vec<u8>, SocketAddr);
struct Route {
    peer: SocketAddr,
    sender: mpsc::SyncSender<Packet>,
}
pub(crate) struct Hub {
    socket: UdpSocket,
    advertised: Option<std::net::Ipv4Addr>,
    routes: Mutex<HashMap<u64, Route>>,
    next: std::sync::atomic::AtomicU64,
}
static ACTIVE: Mutex<Option<Weak<Hub>>> = Mutex::new(None);
impl Hub {
    pub(crate) fn open(
        address: SocketAddr,
        advertised: Option<std::net::Ipv4Addr>,
        previous: Option<&Arc<Self>>,
    ) -> io::Result<Arc<Self>> {
        let socket = match previous.filter(|p| p.socket.local_addr().ok() == Some(address)) {
            Some(p) => p.socket.try_clone()?,
            None => UdpSocket::bind(address)?,
        };
        socket.set_nonblocking(true)?;
        Ok(Arc::new(Self {
            socket,
            advertised,
            routes: Mutex::new(HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
        }))
    }
    pub(crate) fn activate(self: &Arc<Self>) {
        *ACTIVE.lock().unwrap() = Some(Arc::downgrade(self));
    }
    pub(crate) fn poll(&self) {
        let mut bytes = [0; 65535];
        for _ in 0..64 {
            let Ok((length, from)) = self.socket.recv_from(&mut bytes) else {
                break;
            };
            let mut routes = self.routes.lock().unwrap();
            let selected = routes
                .iter()
                .find(|(_, r)| r.peer == from)
                .map(|(id, _)| *id)
                .or_else(|| {
                    routes
                        .iter()
                        .find(|(_, r)| r.peer.ip() == from.ip() && r.peer.port() == 0)
                        .map(|(id, _)| *id)
                });
            if let Some(route) = selected.and_then(|id| routes.get_mut(&id)) {
                route.peer = from;
                let _ = route.sender.try_send((bytes[..length].to_vec(), from));
            }
        }
    }
}
pub(crate) struct Association {
    hub: Arc<Hub>,
    id: u64,
    receiver: mpsc::Receiver<Packet>,
}
impl Association {
    pub(crate) fn open(peer: SocketAddr) -> io::Result<Self> {
        let hub = ACTIVE
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::other("局域网 UDP 监听未启用"))?;
        let mut routes = hub.routes.lock().unwrap();
        if routes.len() >= 256
            || routes.values().any(|r| {
                r.peer.ip() == peer.ip()
                    && (r.peer.port() == 0 || peer.port() == 0 || r.peer.port() == peer.port())
            })
        {
            return Err(io::Error::other(
                "此客户端需先发送首个 UDP 包或指定不同源端口",
            ));
        }
        let id = hub.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (sender, receiver) = mpsc::sync_channel(32);
        routes.insert(id, Route { peer, sender });
        drop(routes);
        Ok(Self { hub, id, receiver })
    }
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut address = self.hub.socket.local_addr()?;
        if let Some(ip) = self.hub.advertised {
            address.set_ip(ip.into());
        }
        Ok(address)
    }
    pub(crate) fn recv_from(&self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (packet, from) = self
            .receiver
            .try_recv()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let n = packet.len().min(bytes.len());
        bytes[..n].copy_from_slice(&packet[..n]);
        Ok((n, from))
    }
    pub(crate) fn send_to(&self, bytes: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.hub.socket.send_to(bytes, to)
    }
}
impl Drop for Association {
    fn drop(&mut self) {
        self.hub.routes.lock().unwrap().remove(&self.id);
    }
}
