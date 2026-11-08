//! The Shadowsocks AEAD outbound (SIP004 stream framing, legacy ciphers):
//! a random salt prefixes each direction and keys an HKDF-SHA1 subkey; every
//! chunk is `AEAD(len 2 BE) || AEAD(payload)` with a little-endian counter
//! nonce advancing once per AEAD operation. The target address rides inside
//! the first payload chunk, and the server only answers after that chunk, so
//! the response salt is read lazily on the read path.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::time::Duration;

use crate::crypto::{self, Aead};
use crate::share;
use crate::tunnel;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Maximum plaintext per chunk (SIP004).
const CHUNK_MAX_LEN: usize = 0x3FFF;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
const HANDSHAKE_TIMEOUT: Duration = tunnel::POLL;

/// Opens `host:port` through a Shadowsocks node dialed at `node_host:node_port`.
/// `link` is the node's share link; it carries `method:password`.
pub fn ss(
    _name: &str,
    node_host: &str,
    node_port: u16,
    link: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let link = link.ok_or_else(|| invalid("Shadowsocks 节点缺少分享链接"))?;
    let share = share::parse(link).map_err(|reason| invalid(reason))?;
    if share.protocol != "ss" {
        return Err(invalid("节点分享链接不是 Shadowsocks"));
    }
    let (method, password) = share
        .secret
        .split_once(':')
        .ok_or_else(|| invalid("Shadowsocks 节点缺少 method:password"))?;
    let (cipher, key_len) = cipher_conf(method).ok_or_else(|| {
        invalid(format!("Shadowsocks 加密方法 `{method}` 尚未实现"))
    })?;
    if password.is_empty() {
        return Err(invalid("Shadowsocks 节点缺少密码"));
    }
    if host.len() > 255 {
        return Err(invalid("目标域名超过 255 字节"));
    }

    let master_key = crypto::evp_bytes_to_key(password.as_bytes(), key_len);
    let send_salt = crypto::random_vec(key_len);
    let send_key =
        crypto::hkdf_sha1(&send_salt, &master_key, SS_SUBKEY_INFO, key_len).map_err(invalid)?;
    let addr = encode_addr(host, port);

    // No handshake bytes: the salt is the stream's first write, and the
    // server answers only after the first payload chunk, so both timeouts
    // are the pump's from the start.
    let sock = crate::proxy::dial(node_host, node_port)?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    sock.set_write_timeout(None)?;
    tunnel::bridge(SsStream::new(
        sock, cipher, master_key, send_salt, send_key, addr, key_len,
    ))
}

/// The three legacy AEAD ciphers and their key lengths. AEAD-2022 needs
/// blake3 key derivation and replay protection and is not implemented.
fn cipher_conf(method: &str) -> Option<(Aead, usize)> {
    match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm" => Some((Aead::Aes128Gcm, 16)),
        "aes-256-gcm" => Some((Aead::Aes256Gcm, 32)),
        "chacha20-ietf-poly1305" => Some((Aead::ChaCha20Poly1305, 32)),
        _ => None,
    }
}

/// SOCKS5-form target: `ATYP addr port(2 BE)`.
fn encode_addr(host: &str, port: u16) -> Vec<u8> {
    let mut addr = Vec::with_capacity(1 + 1 + host.len() + 2);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            addr.push(ATYP_IPV4);
            addr.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            addr.push(ATYP_IPV6);
            addr.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            addr.push(ATYP_DOMAIN);
            addr.push(host.len() as u8);
            addr.extend_from_slice(host.as_bytes());
        }
    }
    addr.extend_from_slice(&port.to_be_bytes());
    addr
}

/// Little-endian counter increment (one step per AEAD operation).
fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
}

/// Seal `payload` as Shadowsocks chunks: `AEAD(len) AEAD(chunk)` per piece.
fn seal_chunks(
    cipher: Aead,
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + CHUNK_MAX_LEN).min(payload.len());
        let len = ((end - offset) as u16).to_be_bytes();
        out.extend_from_slice(&crypto::seal(cipher, key, nonce, &len));
        increment_nonce(nonce);
        out.extend_from_slice(&crypto::seal(cipher, key, nonce, &payload[offset..end]));
        increment_nonce(nonce);
        offset = end;
    }
    Ok(out)
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// The Shadowsocks body stream handed to the tunnel bridge. Read progress
/// (salt, length field, chunk) survives the bridge's short-timeout polls.
struct SsStream {
    sock: TcpStream,
    cipher: Aead,
    master_key: Vec<u8>,
    send_salt: Vec<u8>,
    send_key: Vec<u8>,
    send_nonce: [u8; NONCE_LEN],
    addr: Vec<u8>,
    /// The salt + first `addr || data` chunk go out with the first write.
    unsalted: bool,
    recv_salt: Vec<u8>,
    salt_got: usize,
    recv_key: Vec<u8>,
    recv_nonce: [u8; NONCE_LEN],
    recv_ready: bool,
    len_buf: [u8; 2 + TAG_LEN],
    len_got: usize,
    chunk: Vec<u8>,
    chunk_got: usize,
    pending: Vec<u8>,
    pos: usize,
}

impl SsStream {
    fn new(
        sock: TcpStream,
        cipher: Aead,
        master_key: Vec<u8>,
        send_salt: Vec<u8>,
        send_key: Vec<u8>,
        addr: Vec<u8>,
        key_len: usize,
    ) -> Self {
        Self {
            sock,
            cipher,
            master_key,
            send_salt,
            send_key,
            send_nonce: [0; NONCE_LEN],
            addr,
            unsalted: true,
            recv_salt: vec![0u8; key_len],
            salt_got: 0,
            recv_key: Vec::new(),
            recv_nonce: [0; NONCE_LEN],
            recv_ready: false,
            len_buf: [0; 2 + TAG_LEN],
            len_got: 0,
            chunk: Vec::new(),
            chunk_got: 0,
            pending: Vec::new(),
            pos: 0,
        }
    }

    /// A synthetic would-block: tells the pump to try again after the short
    /// poll without losing the read state machine's progress.
    fn idle() -> io::Error {
        io::Error::from(io::ErrorKind::WouldBlock)
    }
}

impl Read for SsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.pending.len() {
                let take = (self.pending.len() - self.pos).min(buf.len());
                buf[..take].copy_from_slice(&self.pending[self.pos..self.pos + take]);
                self.pos += take;
                if self.pos == self.pending.len() {
                    self.pending.clear();
                    self.pos = 0;
                }
                return Ok(take);
            }
            if !self.recv_ready {
                match self.sock.read(&mut self.recv_salt[self.salt_got..]) {
                    Ok(0) => return Ok(0),
                    Ok(n) => self.salt_got += n,
                    Err(err) => return Err(err),
                }
                if self.salt_got < self.recv_salt.len() {
                    return Err(Self::idle());
                }
                self.recv_key = crypto::hkdf_sha1(
                    &self.recv_salt,
                    &self.master_key,
                    SS_SUBKEY_INFO,
                    self.recv_salt.len(),
                )
                .map_err(invalid)?;
                self.recv_nonce = [0; NONCE_LEN];
                self.recv_ready = true;
            }
            if self.len_got < self.len_buf.len() && self.chunk.is_empty() {
                match self.sock.read(&mut self.len_buf[self.len_got..]) {
                    // The server half-closed after its data — end of stream.
                    Ok(0) => return Ok(0),
                    Ok(n) => self.len_got += n,
                    Err(err) => return Err(err),
                }
                if self.len_got < self.len_buf.len() {
                    return Err(Self::idle());
                }
                let plain = crypto::open(self.cipher, &self.recv_key, &self.recv_nonce, &self.len_buf)
                    .map_err(invalid)?;
                increment_nonce(&mut self.recv_nonce);
                self.len_got = 0;
                let payload_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
                self.chunk = vec![0u8; payload_len + TAG_LEN];
                self.chunk_got = 0;
            }
            if self.chunk_got < self.chunk.len() {
                match self.sock.read(&mut self.chunk[self.chunk_got..]) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    Ok(n) => self.chunk_got += n,
                    Err(err) => return Err(err),
                }
                if self.chunk_got < self.chunk.len() {
                    return Err(Self::idle());
                }
            }
            let plain =
                crypto::open(self.cipher, &self.recv_key, &self.recv_nonce, &self.chunk)
                    .map_err(invalid)?;
            increment_nonce(&mut self.recv_nonce);
            self.chunk = Vec::new();
            self.chunk_got = 0;
            self.pending = plain;
            self.pos = 0;
        }
    }
}

impl Write for SsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.unsalted {
            self.unsalted = false;
            let mut first = Vec::with_capacity(self.addr.len() + buf.len());
            first.extend_from_slice(&self.addr);
            first.extend_from_slice(buf);
            let sealed = seal_chunks(self.cipher, &self.send_key, &mut self.send_nonce, &first)?;
            let mut out = Vec::with_capacity(self.send_salt.len() + sealed.len());
            out.extend_from_slice(&self.send_salt);
            out.extend_from_slice(&sealed);
            self.sock.write_all(&out)?;
            return Ok(buf.len());
        }
        let sealed = seal_chunks(self.cipher, &self.send_key, &mut self.send_nonce, buf)?;
        self.sock.write_all(&sealed)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl tunnel::TunnelStream for SsStream {
    fn client_eof(&mut self) -> io::Result<()> {
        // Shadowsocks has no termination chunk; the upload ends with a
        // TCP half-close.
        self.sock.shutdown(Shutdown::Write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    const METHOD: &str = "aes-128-gcm";
    const PASSWORD: &str = "pw";

    #[test]
    fn nonce_increments_little_endian() {
        let mut nonce = [0xFF, 0x00, 0x01];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0x00, 0x01, 0x01]);
        let mut nonce = [0xFF, 0x01];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0x00, 0x02]);
    }

    #[test]
    fn chunk_framing_round_trip() {
        let key = vec![7u8; 16];
        let mut nonce = [0u8; NONCE_LEN];
        let payload = vec![42u8; 100];
        let sealed = seal_chunks(Aead::Aes128Gcm, &key, &mut nonce, &payload).unwrap();
        // 100 bytes = 1 chunk: 2+16 length field + 100+16 body.
        assert_eq!(sealed.len(), 100 + (2 + 16 + 16));
        // Chunks bigger than the cap are split.
        let mut nonce = [0u8; NONCE_LEN];
        let big = vec![0u8; CHUNK_MAX_LEN + 17];
        let sealed = seal_chunks(Aead::Aes128Gcm, &key, &mut nonce, &big).unwrap();
        assert_eq!(sealed.len(), (CHUNK_MAX_LEN + 17) + 2 * (2 + 16 + 16));
        // Decrypting the first chunk recovers the payload head.
        let plain = crypto::open(Aead::Aes128Gcm, &key, &[0u8; NONCE_LEN], &sealed[..2 + TAG_LEN])
            .unwrap();
        assert_eq!(plain, (CHUNK_MAX_LEN as u16).to_be_bytes());
    }

    #[test]
    fn rejects_unknown_methods() {
        let link = |method: &str| {
            format!(
                "ss://{}@127.0.0.1:1#t",
                base64_of(&format!("{method}:{PASSWORD}"))
            )
        };
        for method in ["rc4-md5", "2022-blake3-aes-128-gcm"] {
            let error = ss("t", "127.0.0.1", 1, Some(&link(method)), "example.com", 80).unwrap_err();
            assert!(
                error.to_string().contains("尚未实现"),
                "method={method}: {error}"
            );
        }
    }

    fn base64_of(text: &str) -> String {
        crate::base64::encode(text.as_bytes())
    }

    /// A fake Shadowsocks server over loopback: derives the client's subkey
    /// from its salt, decrypts the first chunk (`addr || data`), echoes the
    /// data under its own salt, and drains until the client hangs up.
    #[test]
    fn plain_tunnel_round_trip() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let master = crypto::evp_bytes_to_key(PASSWORD.as_bytes(), 16);

            let mut salt = vec![0u8; 16];
            sock.read_exact(&mut salt).unwrap();
            let subkey = crypto::hkdf_sha1(&salt, &master, SS_SUBKEY_INFO, 16).unwrap();
            let mut nonce = [0u8; NONCE_LEN];

            let mut len_field = [0u8; 2 + TAG_LEN];
            sock.read_exact(&mut len_field).unwrap();
            let len_plain =
                crypto::open(Aead::Aes128Gcm, &subkey, &nonce, &len_field).unwrap();
            increment_nonce(&mut nonce);
            let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            let mut body = vec![0u8; payload_len + TAG_LEN];
            sock.read_exact(&mut body).unwrap();
            let first = crypto::open(Aead::Aes128Gcm, &subkey, &nonce, &body).unwrap();
            increment_nonce(&mut nonce);
            // first = ATYP(0x03) len(11) "example.com" port(2 BE) || data
            assert_eq!(first[0], ATYP_DOMAIN);
            assert_eq!(first[1], 11);
            assert_eq!(&first[2..13], b"example.com");
            assert_eq!(&first[13..15], &443u16.to_be_bytes());
            let data = &first[15..];
            assert_eq!(data, b"hello");

            let reply_salt = crypto::random_vec(16);
            sock.write_all(&reply_salt).unwrap();
            let reply_key = crypto::hkdf_sha1(&reply_salt, &master, SS_SUBKEY_INFO, 16).unwrap();
            let mut reply_nonce = [0u8; NONCE_LEN];
            sock.write_all(&seal_chunks(Aead::Aes128Gcm, &reply_key, &mut reply_nonce, data).unwrap())
                .unwrap();
            sock.flush().unwrap();
            // Drain so the close stays graceful on Windows.
            let mut drain = [0u8; 64];
            while matches!(sock.read(&mut drain), Ok(n) if n > 0) {}
        });

        let link = format!(
            "ss://{}@127.0.0.1:{port}#t",
            base64_of(&format!("{METHOD}:{PASSWORD}"))
        );
        let mut outer = ss("ss-test", "127.0.0.1", port, Some(&link), "example.com", 443).unwrap();
        outer.write_all(b"hello").unwrap();
        outer.flush().unwrap();
        outer.shutdown(Shutdown::Write).unwrap();
        outer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut back = Vec::new();
        outer.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"hello");
        server.join().unwrap();
    }
}
