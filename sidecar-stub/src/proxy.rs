//! Shared plumbing for the inbound: dialing upstreams and shuttling bytes.

use std::io::{self, Read};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config;
use crate::connections;
use crate::flows;
use crate::outbounds;
use crate::state;

/// Time allowed to complete a handshake or a request header block. Cleared once
/// a tunnel is established: idle tunnels are legitimate.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub fn configure(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
}

/// Opens the target through the outbound the routing decision resolved to.
pub fn connect(decision: &config::Decision, host: &str, port: u16) -> io::Result<TcpStream> {
    let result = match &decision.target {
        config::Target::Direct => dial(host, port),
        config::Target::Block => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blocked by rule",
        )),
        config::Target::Socks5 {
            name,
            host: node_host,
            port: node_port,
            username,
            password,
        } => crate::outbound::socks5(
            name,
            node_host,
            *node_port,
            username.as_deref(),
            password.as_deref(),
            host,
            port,
        ),
    };
    if result.is_err() {
        outbounds::record_error(decision);
    }
    result
}

/// Resolves and connects to `host:port`, trying every resolved address. Direct
/// dials resolve through the configured DNS upstreams; the system resolver is
/// only the fallback when no upstream is configured.
pub fn dial(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else if crate::dns::available() {
        crate::dns::resolve(host)?
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect()
    } else {
        (host, port).to_socket_addrs()?.collect()
    };
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!("{host}:{port} 没有可用地址"),
    );

    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = err,
        }
    }

    Err(last)
}

/// Reads a request header block up to and including the terminating CRLFCRLF.
/// Reads one byte at a time so no body byte is consumed from the stream.
pub fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    while buf.len() < MAX_HEADER_BYTES {
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "连接在请求头结束前关闭",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "请求头超过大小上限",
    ))
}

/// Copies bytes both ways until either side closes, then shuts both down.
/// Both directions count as they are read, so the traffic ring sees a long
/// transfer instead of one jump when it ends.
pub fn tunnel(
    client: TcpStream,
    upstream: TcpStream,
    flow: Option<flows::Guard>,
    decision: &config::Decision,
) -> io::Result<()> {
    // The guard closes the flow record when this tunnel returns.
    let _flow = flow;
    let meter = outbounds::Meter::open(decision);
    for stream in [&client, &upstream] {
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);
    }

    let _open = OpenConnection::new();
    let live = match (client.peer_addr(), upstream.peer_addr()) {
        (Ok(src), Ok(dst)) => Some(connections::Live::open(src, dst)),
        _ => None,
    };
    let download_counters = live.as_ref().map(|live| Arc::clone(&live.counters));
    let outbound = meter.handle();

    let mut client_read = Counted {
        inner: client.try_clone()?,
        add: state::add_upload,
        counter: download_counters.clone(),
        outbound: Some(outbound.clone()),
        upload: true,
    };
    let mut upstream_write = upstream.try_clone()?;
    let upload = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });

    let mut upstream_read = Counted {
        inner: upstream,
        add: state::add_download,
        counter: download_counters,
        outbound: Some(outbound),
        upload: false,
    };
    let mut client_write = client;
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = upload.join();

    Ok(())
}

/// Counts one open tunnel for as long as it exists, however it ends.
struct OpenConnection;

impl OpenConnection {
    fn new() -> OpenConnection {
        state::connection_opened();
        OpenConnection
    }
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        state::connection_closed();
    }
}

struct Counted<R> {
    inner: R,
    add: fn(u64),
    counter: Option<Arc<connections::Counters>>,
    outbound: Option<outbounds::Handle>,
    upload: bool,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        if count > 0 {
            (self.add)(count as u64);
            if let Some(counters) = &self.counter {
                let counter = if self.upload {
                    &counters.upload
                } else {
                    &counters.download
                };
                counter.fetch_add(count as u64, Ordering::Relaxed);
            }
            if let Some(outbound) = &self.outbound {
                if self.upload {
                    outbound.upload(count as u64);
                } else {
                    outbound.download(count as u64);
                }
            }
        }
        Ok(count)
    }
}

/// Splits `host:port`, `[v6]:port` or a bare host into its parts.
pub fn parse_authority(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail {
            "" => Some((host.to_string(), default_port)),
            _ => {
                let port = tail.strip_prefix(':')?.parse().ok()?;
                Some((host.to_string(), port))
            }
        };
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            Some((host.to_string(), port.parse().ok()?))
        }
        Some(_) => None,
        None => Some((value.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_authority;

    #[test]
    fn parses_host_and_port() {
        assert_eq!(
            parse_authority("example.com:8080", 80),
            Some(("example.com".to_string(), 8080))
        );
        assert_eq!(
            parse_authority("example.com", 80),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            parse_authority("127.0.0.1:443", 80),
            Some(("127.0.0.1".to_string(), 443))
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_authority("[::1]:8080", 80),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(parse_authority("[::1]", 80), Some(("::1".to_string(), 80)));
    }

    #[test]
    fn rejects_malformed_authority() {
        assert_eq!(parse_authority("", 80), None);
        assert_eq!(parse_authority("example.com:notaport", 80), None);
        assert_eq!(parse_authority(":80", 80), None);
        assert_eq!(parse_authority("[::1", 80), None);
    }
}
