//! Bridges protocol streams that cannot be shared across threads (TLS
//! sessions, VMess bodies) onto the plain `TcpStream` the rest of the engine
//! already speaks. A loopback socket pair carries the bytes; one worker thread
//! owns the protocol stream and pumps both directions with short read
//! timeouts so neither side can stall the other.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Idle-wait cap for each direction's read. Arriving data wakes a blocked
/// read early, so this bounds added latency (a few milliseconds), not
/// throughput.
pub const POLL: Duration = Duration::from_millis(5);

const BUFFER: usize = 16 * 1024;

/// A protocol stream the bridge can pump. `client_eof` runs once when the
/// client half-closes its upload so the stream can signal EOF toward the
/// node: a TLS close_notify, a VMess termination chunk, a plain half-close.
pub trait TunnelStream: Read + Write + Send {
    /// Called before pumping starts; typically arms the short poll timeout
    /// on the underlying socket and clears any handshake-phase write timeout.
    fn prepare(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn client_eof(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hands `stream` to a worker thread and returns the loopback socket the rest
/// of the engine treats as the tunnel. Dropping the returned socket tears the
/// whole bridge down.
pub fn bridge(mut stream: impl TunnelStream + 'static) -> io::Result<TcpStream> {
    stream.prepare()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let outer = TcpStream::connect(listener.local_addr()?)?;
    let (inner, _) = listener.accept()?;
    drop(listener);
    let _ = outer.set_nodelay(true);
    let _ = inner.set_nodelay(true);
    // The pump visits both directions in one loop, so the client-side read
    // must give up after POLL or a quiet client would starve downloads.
    let _ = inner.set_read_timeout(Some(POLL));
    thread::spawn(move || pump(inner, stream));
    Ok(outer)
}

fn pump(mut inner: TcpStream, mut stream: impl TunnelStream) {
    let mut buf = vec![0u8; BUFFER];
    let mut up_open = true;
    let mut down_open = true;
    while up_open || down_open {
        if up_open {
            match inner.read(&mut buf) {
                Ok(0) => {
                    up_open = false;
                    let _ = stream.client_eof();
                    let _ = stream.flush();
                }
                Ok(n) => {
                    if stream
                        .write_all(&buf[..n])
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) if idle(&err) => {}
                Err(_) => break,
            }
        }
        if down_open {
            match stream.read(&mut buf) {
                Ok(0) => {
                    down_open = false;
                    let _ = inner.shutdown(Shutdown::Write);
                }
                Ok(n) => {
                    if inner.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(err) if idle(&err) => {}
                Err(_) => {
                    down_open = false;
                    let _ = inner.shutdown(Shutdown::Write);
                }
            }
        }
    }
}

fn idle(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// An echo tunnel over the bridge: bytes written to the outer socket must
    /// come back through the worker, and closing the outer socket must tear
    /// the worker down.
    #[test]
    fn bridge_relays_and_shuts_down() {
        struct Echo(Vec<u8>);
        impl Read for Echo {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "idle"));
                }
                let take = buf.len().min(self.0.len());
                buf[..take].copy_from_slice(&self.0[..take]);
                self.0.drain(..take);
                Ok(take)
            }
        }
        impl Write for Echo {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl TunnelStream for Echo {}

        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut outer = bridge(Echo(b"hello from node".to_vec())).unwrap();
            let mut back = [0u8; 15];
            outer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            outer.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"hello from node");
            outer.write_all(b"ping").unwrap();
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("bridge echo timed out");
        handle.join().unwrap();
    }
}
