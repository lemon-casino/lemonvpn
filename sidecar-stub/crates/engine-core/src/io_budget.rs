//! One deadline and cancellation token across DNS dial, TLS, retries and reads.
use std::{
    cell::RefCell,
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
thread_local! { static CURRENT: RefCell<Option<Budget>> = const { RefCell::new(None) }; }
#[derive(Clone)]
pub(crate) struct Budget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    parents: Vec<Arc<AtomicBool>>,
}
impl Budget {
    pub fn new(duration: Duration) -> Self {
        let deadline = Instant::now() + duration;
        let (deadline, parents) = CURRENT.with(|v| {
            v.borrow().as_ref().map_or((deadline, Vec::new()), |b| {
                let mut parents = b.parents.clone();
                parents.push(b.cancelled.clone());
                (b.deadline.min(deadline), parents)
            })
        });
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
            parents,
        }
    }
    pub fn remaining(&self) -> io::Result<Duration> {
        if self.cancelled.load(Ordering::Acquire)
            || self.parents.iter().any(|p| p.load(Ordering::Acquire))
            || crate::runtime::stopping()
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "请求已取消",
            ));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "请求总时限已到"))
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn enter(&self) -> Scope {
        Scope(CURRENT.with(|v| v.replace(Some(self.clone()))))
    }
}
pub(crate) struct Scope(Option<Budget>);
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|v| {
            v.replace(self.0.take());
        });
    }
}
pub(crate) fn remaining(default: Duration) -> io::Result<Duration> {
    CURRENT.with(|v| match v.borrow().as_ref() {
        Some(b) => b.remaining().map(|d| d.min(default)),
        None => Ok(default),
    })
}
fn scoped() -> bool {
    CURRENT.with(|v| v.borrow().is_some())
}
pub(crate) fn cancelled() -> bool {
    CURRENT.with(|v| {
        v.borrow().as_ref().is_some_and(|b| {
            b.cancelled.load(Ordering::Acquire)
                || b.parents.iter().any(|p| p.load(Ordering::Acquire))
        })
    })
}
pub(crate) fn recv_udp(socket: &std::net::UdpSocket, bytes: &mut [u8]) -> io::Result<usize> {
    let budget = Budget::new(Duration::from_secs(10));
    let _scope = budget.enter();
    loop {
        socket.set_read_timeout(Some(remaining(Duration::from_millis(250))?))?;
        match socket.recv(bytes) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            result => return result,
        }
    }
}
/// The budget is read per operation, so a pooled TLS stream uses its next caller's deadline.
pub(crate) struct Stream(pub TcpStream);
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !scoped() {
            self.0.set_read_timeout(Some(Duration::from_secs(10)))?;
            return self.0.read(bytes);
        }
        loop {
            self.0
                .set_read_timeout(Some(remaining(Duration::from_millis(250))?))?;
            match self.0.read(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !scoped() {
            self.0.set_write_timeout(Some(Duration::from_secs(10)))?;
            return self.0.write(bytes);
        }
        loop {
            self.0
                .set_write_timeout(Some(remaining(Duration::from_millis(250))?))?;
            match self.0.write(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        remaining(Duration::from_secs(1))?;
        self.0.flush()
    }
}
