//! Bounded dual-stack dialing over protected physical sockets.
use std::{
    collections::HashMap,
    io,
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static HISTORY: OnceLock<Mutex<HashMap<SocketAddr, (Instant, bool)>>> = OnceLock::new();
pub(crate) fn connect(mut addresses: Vec<SocketAddr>, timeout: Duration) -> io::Result<TcpStream> {
    addresses.sort();
    addresses.dedup();
    {
        let mut history = HISTORY
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        history.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(60));
        addresses.sort_by_key(|a| {
            history
                .get(a)
                .map_or(1, |(_, good)| if *good { 0 } else { 2 })
        });
    }
    let mut ordered = Vec::new();
    while !addresses.is_empty() {
        let first = addresses.remove(0);
        ordered.push(first);
        if let Some(i) = addresses
            .iter()
            .position(|a| a.is_ipv6() != first.is_ipv6())
        {
            ordered.push(addresses.remove(i));
        }
    }
    let budget = crate::io_budget::Budget::new(timeout);
    let _scope = budget.enter();
    let (tx, rx) = mpsc::channel();
    let mut pending = 0;
    let mut next = ordered.into_iter().peekable();
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "没有可用目标地址");
    let mut launch_at = Instant::now();
    loop {
        if pending < 2 && Instant::now() >= launch_at && next.peek().is_some() {
            if crate::admission::reserve(&ACTIVE, 64) {
                let address = next.next().unwrap();
                let sender = tx.clone();
                let worker_budget = budget.clone();
                struct Permit;
                impl Drop for Permit {
                    fn drop(&mut self) {
                        ACTIVE.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let permit = Permit;
                let spawned = std::thread::Builder::new()
                    .name("physical-dial".into())
                    .spawn(move || {
                        let _permit = permit;
                        let result = worker_budget
                            .remaining()
                            .and_then(|left| crate::platform::current().connect_tcp(address, left));
                        if worker_budget.remaining().is_ok() {
                            let mut history = HISTORY
                                .get()
                                .unwrap()
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            if history.len() >= 512 && !history.contains_key(&address) {
                                if let Some(oldest) = history
                                    .iter()
                                    .min_by_key(|(_, (at, _))| *at)
                                    .map(|(key, _)| *key)
                                {
                                    history.remove(&oldest);
                                }
                            }
                            history.insert(address, (Instant::now(), result.is_ok()));
                        }
                        let _ = sender.send(result);
                    });
                match spawned {
                    Ok(_) => {
                        pending += 1;
                        launch_at = Instant::now() + Duration::from_millis(200);
                    }
                    Err(e) => {
                        last = e;
                        launch_at = Instant::now();
                    }
                }
            } else if pending == 0 {
                budget.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "并发拨号已达上限",
                ));
            }
        }
        if pending == 0 && next.peek().is_none() {
            budget.cancel();
            return Err(last);
        }
        let left = match budget.remaining() {
            Ok(v) => v,
            Err(e) => {
                budget.cancel();
                return Err(e);
            }
        };
        match rx.recv_timeout(left.min(Duration::from_millis(25))) {
            Ok(Ok(socket)) => {
                budget.cancel();
                return Ok(socket);
            }
            Ok(Err(e)) => {
                pending -= 1;
                last = e;
                launch_at = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(last),
        }
    }
}
