//! The rustls client used by the TLS-based outbounds and by subscription
//! fetches. One cached root set, an `allowInsecure` mode that skips chain and
//! name validation (a node flag, not a global default), and a record-framed
//! reader for XTLS Vision whose raw handoff needs exact record boundaries.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{ring as ring_crypto, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned,
};

/// A completed rustls session over a plain TCP socket.
pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// A session over the record-framed socket, for Vision's raw handoff.
pub type FramedTlsStream = StreamOwned<ClientConnection, RecordFramed>;

fn roots() -> &'static RootCertStore {
    static ROOTS: OnceLock<RootCertStore> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots
    })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_crypto::default_provider())
}

/// Accepts any certificate chain. Handshake signatures are still verified
/// against the presented key, so the transcript is authenticated; only the
/// WebPKI trust decision and the name check are skipped.
#[derive(Debug)]
struct AcceptAny {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn config(insecure: bool) -> Arc<ClientConfig> {
    static NORMAL: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let slot = if insecure { &INSECURE } else { &NORMAL };
    slot.get_or_init(|| {
        let provider = provider();
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("default protocol versions");
        let base = builder.with_root_certificates(roots().clone()).with_no_client_auth();
        if insecure {
            let algorithms = provider.signature_verification_algorithms.clone();
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny { algorithms }))
                .with_no_client_auth();
            config.resumption = base.resumption;
            Arc::new(config)
        } else {
            Arc::new(base)
        }
    })
    .clone()
}

/// Drives the rustls handshake to completion on a blocking socket.
fn handshake<S: Read + Write>(
    mut conn: ClientConnection,
    sock: &mut S,
) -> io::Result<ClientConnection> {
    while conn.is_handshaking() {
        conn.complete_io(sock)?;
    }
    Ok(conn)
}

/// rustls client config for QUIC (Hysteria2): the same trust roots and
/// insecure rules as [`config`], with the `hysteria2` ALPN set.
pub(crate) fn quic_config(insecure: bool) -> Arc<ClientConfig> {
    static QUIC_NORMAL: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static QUIC_INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let slot = if insecure { &QUIC_INSECURE } else { &QUIC_NORMAL };
    slot.get_or_init(|| {
        let provider = provider();
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("default protocol versions");
        let mut tls = if insecure {
            let algorithms = provider.signature_verification_algorithms.clone();
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny { algorithms }))
                .with_no_client_auth()
        } else {
            builder.with_root_certificates(roots().clone()).with_no_client_auth()
        };
        tls.alpn_protocols = vec![b"hysteria2".to_vec()];
        Arc::new(tls)
    })
    .clone()
}/// Connects with certificate verification, keeping the socket unframed.
pub fn connect(sock: TcpStream, server_name: &str, insecure: bool) -> io::Result<TlsStream> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SNI 名称无效"))?;
    let conn = ClientConnection::new(config(insecure), name).map_err(io::Error::other)?;
    let mut sock = sock;
    let conn = handshake(conn, &mut sock)?;
    Ok(StreamOwned::new(conn, sock))
}

/// Connects over the record-framed socket, for Vision. The wrapper hands
/// rustls exactly one TLS record per read, so once Vision switches a direction
/// to raw passthrough the bytes after the last record are still on the socket.
pub fn connect_framed(
    sock: TcpStream,
    server_name: &str,
    insecure: bool,
) -> io::Result<FramedTlsStream> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SNI 名称无效"))?;
    let conn = ClientConnection::new(config(insecure), name).map_err(io::Error::other)?;
    let mut borrowed = sock.try_clone()?;
    let conn = handshake(conn, &mut borrowed)?;
    Ok(StreamOwned::new(conn, RecordFramed::with_socket(sock)))
}

/// Splits the underlying socket away from a framed session for raw passthrough.
pub fn framed_socket(stream: &mut FramedTlsStream) -> &mut TcpStream {
    &mut stream.sock.sock
}

/// Copy out plaintext rustls has already decrypted but the caller has not
/// consumed yet. Empty once drained. `Reader::read` reports `WouldBlock`
/// instead of doing socket IO, so this never blocks and never disturbs the
/// record framing on the socket.
pub fn buffered_plaintext(stream: &mut TlsStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.conn.reader().read_to_end(&mut out);
    out
}

/// Serves rustls exactly one TLS record per `read` call. rustls otherwise
/// reads whatever fits its buffer, which would swallow the raw bytes Vision
/// hands the connection after the last TLS record.
pub struct RecordFramed<S = TcpStream> {
    sock: S,
    header: [u8; 5],
    header_have: usize,
    body: Vec<u8>,
    body_at: usize,
}

impl<S: Read> RecordFramed<S> {
    fn with_socket(sock: S) -> Self {
        Self {
            sock,
            header: [0u8; 5],
            header_have: 0,
            body: Vec::new(),
            body_at: 0,
        }
    }

    /// Loads exactly one TLS record from the socket. On return either `body`
    /// holds the record with `body_at == 0` (nothing consumed yet), or the
    /// body is empty (EOF before any record body) — `read` relies on that.
    fn fill(&mut self) -> io::Result<()> {
        self.body.clear();
        self.body_at = 0;
        while self.header_have < 5 {
            let read = self.sock.read(&mut self.header[self.header_have..])?;
            if read == 0 {
                return Ok(());
            }
            self.header_have += read;
        }
        let length = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        self.body = vec![0u8; length];
        self.header_have = 0;
        while self.body_at < length {
            let read = self.sock.read(&mut self.body[self.body_at..])?;
            if read == 0 {
                if self.body_at == 0 {
                    self.body.clear();
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS record body truncated",
                ));
            }
            self.body_at += read;
        }
        self.body_at = 0;
        Ok(())
    }
}

impl<S: Read> Read for RecordFramed<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.body.is_empty() {
            self.fill()?;
            if self.body.is_empty() {
                // fill saw EOF before a complete record arrived.
                return Ok(0);
            }
        }
        let remaining = self.body.len() - self.body_at;
        let take = remaining.min(buf.len());
        buf[..take].copy_from_slice(&self.body[self.body_at..self.body_at + take]);
        self.body_at += take;
        if self.body_at >= self.body.len() {
            // Keep "buffer exhausted" == "body empty" so the fill check in
            // read() stays unambiguous across records.
            self.body.clear();
            self.body_at = 0;
        }
        Ok(take)
    }
}

impl<S: Write> Write for RecordFramed<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl crate::tunnel::TunnelStream for TlsStream {
    fn prepare(&mut self) -> io::Result<()> {
        self.sock.set_read_timeout(Some(crate::tunnel::POLL))?;
        self.sock.set_write_timeout(None)
    }

    fn client_eof(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.conn.write_tls(&mut self.sock)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_reader_reassembles_split_records() {
        // Feed a record whose header and body arrive in pieces; the reader
        // must not surface anything until a full record is available.
        let record = [0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4];
        let mut log: Vec<u8> = Vec::new();
        log.extend_from_slice(&record);
        let mut framed = RecordFramed::with_socket(FakeSock {
            data: std::cell::RefCell::new(log),
            position: std::cell::Cell::new(0),
        });
        let mut out = [0u8; 16];
        assert_eq!(framed.read(&mut out).unwrap(), 4);
        assert_eq!(&out[..4], &[1, 2, 3, 4]);
        // EOF after the record.
        assert_eq!(framed.read(&mut out).unwrap(), 0);
    }

    /// A socket that yields bytes one at a time to force every boundary.
    struct FakeSock {
        data: std::cell::RefCell<Vec<u8>>,
        position: std::cell::Cell<usize>,
    }

    impl Read for FakeSock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let position = self.position.get();
            let data = self.data.borrow();
            if position >= data.len() {
                return Ok(0);
            }
            buf[0] = data[position];
            self.position.set(position + 1);
            Ok(1)
        }
    }

    impl Write for FakeSock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
