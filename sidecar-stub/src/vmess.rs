//! The VMess AEAD outbound: sealed request header, masked AEAD body chunks in
//! both directions, and the response-header decode — the client path honk's
//! Xray-generated vectors pin byte-for-byte. Links carrying a non-TCP
//! transport (websocket, mKCP, QUIC) are rejected with a clear error so
//! probes never mark such nodes healthy.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::base64;
use crate::crypto::{self, Aead, ShakeMask};
use crate::json;
use crate::share;
use crate::tls;
use crate::tunnel;

const VERSION: u8 = 0x01;
/// ChunkStream | ChunkMasking — what Xray's outbound sets for AES-128-GCM.
const OPTION: u8 = 0x01 | 0x04;
const SECURITY_AES128_GCM: u8 = 0x03;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
/// Suffix for cmd_key derivation (`vmess.Account.ID.CmdKey`).
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
const GCM_TAG_LEN: usize = 16;
/// Maximum plaintext per body chunk (Xray `buf.Size` - tag - size field).
const CHUNK_MAX_LEN: usize = 16384 - GCM_TAG_LEN - 2;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens `host:port` through a VMess node dialed at `node_host:node_port`.
/// `link` is the node's share link; it carries the UUID, transport and TLS
/// settings as a Base64 JSON payload.
pub fn vmess(
    name: &str,
    node_host: &str,
    node_hostname: &str,
    node_port: u16,
    link: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let link = link.ok_or_else(|| invalid("VMess 节点缺少分享链接"))?;
    let share = share::parse(link).map_err(|reason| invalid(reason))?;
    if share.protocol != "vmess" {
        return Err(invalid("节点分享链接不是 VMess"));
    }
    let body = link_body(link)?;
    let net = json::field(&body, "net").unwrap_or_default();
    if !matches!(net.as_str(), "" | "tcp" | "raw") {
        return Err(invalid(format!("VMess 传输层 `{net}` 尚未实现")));
    }
    let kind = json::field(&body, "type").unwrap_or_default();
    if !matches!(kind.as_str(), "" | "none") {
        return Err(invalid(format!("VMess 伪装 `{kind}` 尚未实现")));
    }
    if !json::field(&body, "path").unwrap_or_default().is_empty() {
        return Err(invalid("VMess 传输层 `ws` 尚未实现"));
    }
    let insecure = matches!(
        json::field(&body, "allowInsecure").as_deref(),
        Some("1") | Some("true")
    ) || json::bool_field(&body, "allowInsecure").ok().flatten() == Some(true)
        || json::bool_field(&body, "verify_cert").ok().flatten() == Some(false);
    let uuid =
        crypto::uuid_bytes(&share.secret).ok_or_else(|| invalid("VMess 节点的 UUID 无效"))?;
    if host.len() > 255 {
        return Err(invalid("目标域名超过 255 字节"));
    }

    let cmd_key = cmd_key(&uuid);
    let session = Session::new();
    // Xray rolls 0..=15 padding bytes; the length lives in the high nibble.
    let padding_len = crypto::random_vec(1)[0] % 16;
    let padding = crypto::random_vec(padding_len as usize);
    let plain = build_header_plain(&session, &padding, host, port);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let auth_key = crypto::vmess_kdf16(&cmd_key, &[KDF_SALT_AUTH_ID]);
    let rand4: [u8; 4] = crypto::random_vec(4).try_into().expect("4 bytes");
    let auth_id = crypto::vmess_auth_id(&auth_key, ts, &rand4);
    let conn_nonce: [u8; 8] = crypto::random_vec(8).try_into().expect("8 bytes");
    let wire = seal_request_header(&cmd_key, &auth_id, &conn_nonce, &plain);

    let mut sock = crate::proxy::dial(node_host, node_port)?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    if share.tls {
        let sni = share
            .sni
            .as_deref()
            .filter(|sni| !sni.is_empty())
            .unwrap_or(node_hostname);
        let mut stream = tls::connect(sock, sni, insecure)?;
        stream.write_all(&wire)?;
        stream.flush()?;
        read_response_header(&mut stream, &session, name)?;
        stream.sock.set_read_timeout(Some(tunnel::POLL))?;
        stream.sock.set_write_timeout(None)?;
        tunnel::bridge(VmessStream::new(stream, &session))
    } else {
        sock.write_all(&wire)?;
        sock.flush()?;
        read_response_header(&mut sock, &session, name)?;
        sock.set_read_timeout(Some(tunnel::POLL))?;
        sock.set_write_timeout(None)?;
        tunnel::bridge(VmessStream::new(sock, &session))
    }
}

fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + CMD_KEY_SUFFIX.len());
    input.extend_from_slice(uuid);
    input.extend_from_slice(CMD_KEY_SUFFIX);
    crypto::md5(&input)
}

/// The Base64 JSON payload of a `vmess://` link.
fn link_body(link: &str) -> io::Result<String> {
    let body = link
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| invalid("VMess 链接缺少 scheme"))?;
    let body = body.split('#').next().unwrap_or(body);
    let decoded =
        base64::decode(body.trim()).ok_or_else(|| invalid("VMess 链接不是有效的 Base64"))?;
    String::from_utf8(decoded).map_err(|_| invalid("VMess 链接不是有效的 UTF-8"))
}

struct Session {
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_header: u8,
}

impl Session {
    fn new() -> Self {
        let req_key: [u8; 16] = crypto::random_vec(16).try_into().expect("16 bytes");
        let req_iv: [u8; 16] = crypto::random_vec(16).try_into().expect("16 bytes");
        let (resp_key, resp_iv) = response_keys(&req_key, &req_iv);
        Self {
            req_key,
            req_iv,
            resp_key,
            resp_iv,
            resp_header: crypto::random_vec(1)[0],
        }
    }
}

/// Response body keys derive from the request keys (Xray `NewClientSession`).
fn response_keys(req_key: &[u8; 16], req_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let resp_key: [u8; 16] = crypto::sha256(req_key)[..16].try_into().expect("16 of 32");
    let resp_iv: [u8; 16] = crypto::sha256(req_iv)[..16].try_into().expect("16 of 32");
    (resp_key, resp_iv)
}

/// Header plaintext per Xray `EncodeRequestHeader`, FNV checksum included:
/// ver | req_iv | req_key | resp_v | option | padding<<4|security | 0 | cmd |
/// port(2 BE) | atyp | addr | padding | fnv1a32(everything before it).
fn build_header_plain(session: &Session, padding: &[u8], host: &str, port: u16) -> Vec<u8> {
    let mut plain = Vec::with_capacity(64 + padding.len() + host.len());
    plain.push(VERSION);
    plain.extend_from_slice(&session.req_iv);
    plain.extend_from_slice(&session.req_key);
    plain.push(session.resp_header);
    plain.push(OPTION);
    plain.push(((padding.len() as u8) << 4) | SECURITY_AES128_GCM);
    plain.push(0);
    plain.push(CMD_TCP);
    plain.extend_from_slice(&port.to_be_bytes());
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            plain.push(ATYP_IPV4);
            plain.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            plain.push(ATYP_IPV6);
            plain.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            plain.push(ATYP_DOMAIN);
            plain.push(host.len() as u8);
            plain.extend_from_slice(host.as_bytes());
        }
    }
    plain.extend_from_slice(padding);
    plain.extend_from_slice(&crypto::fnv1a32(&plain).to_be_bytes());
    plain
}

/// `SealVMessAEADHeader`: auth_id | enc_len | conn_nonce | enc_header, both
/// AEAD blocks keyed through the chained KDF with `[auth_id, conn_nonce]`
/// appended and authenticated with auth_id as AAD.
fn seal_request_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    conn_nonce: &[u8; 8],
    plain: &[u8],
) -> Vec<u8> {
    let len_key = crypto::vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_LEN_KEY, auth_id, conn_nonce]);
    let len_nonce = crypto::vmess_kdf12(cmd_key, &[KDF_SALT_HEADER_LEN_IV, auth_id, conn_nonce]);
    let hdr_key = crypto::vmess_kdf16(cmd_key, &[KDF_SALT_HEADER_KEY, auth_id, conn_nonce]);
    let hdr_nonce = crypto::vmess_kdf12(cmd_key, &[KDF_SALT_HEADER_IV, auth_id, conn_nonce]);
    let mut out = Vec::with_capacity(16 + 18 + 8 + plain.len() + GCM_TAG_LEN);
    out.extend_from_slice(auth_id);
    out.extend_from_slice(&crypto::seal_aad(
        Aead::Aes128Gcm,
        &len_key,
        &len_nonce,
        &(plain.len() as u16).to_be_bytes(),
        auth_id,
    ));
    out.extend_from_slice(conn_nonce);
    out.extend_from_slice(&crypto::seal_aad(
        Aead::Aes128Gcm,
        &hdr_key,
        &hdr_nonce,
        plain,
        auth_id,
    ));
    out
}

/// `DecodeResponseHeader`: AEAD-sealed length then AEAD-sealed payload, keyed
/// from the response body key/IV with no AAD.
fn read_response_header(stream: &mut impl Read, session: &Session, name: &str) -> io::Result<()> {
    let mut len_ct = [0u8; 2 + GCM_TAG_LEN];
    stream.read_exact(&mut len_ct)?;
    let len_key = crypto::vmess_kdf16(&session.resp_key, &[KDF_SALT_RESP_LEN_KEY]);
    let len_nonce = crypto::vmess_kdf12(&session.resp_iv, &[KDF_SALT_RESP_LEN_IV]);
    let plain = crypto::open(Aead::Aes128Gcm, &len_key, &len_nonce, &len_ct)
        .map_err(|reason| invalid(format!("节点 {name} 的 VMess 响应头长度解密失败: {reason}")))?;
    let hdr_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    if !(4..=256).contains(&hdr_len) {
        return Err(invalid(format!(
            "节点 {name} 的 VMess 响应头长度无效 {hdr_len}"
        )));
    }
    let mut hdr_ct = vec![0u8; hdr_len + GCM_TAG_LEN];
    stream.read_exact(&mut hdr_ct)?;
    let hdr_key = crypto::vmess_kdf16(&session.resp_key, &[KDF_SALT_RESP_KEY]);
    let hdr_nonce = crypto::vmess_kdf12(&session.resp_iv, &[KDF_SALT_RESP_IV]);
    let hdr = crypto::open(Aead::Aes128Gcm, &hdr_key, &hdr_nonce, &hdr_ct)
        .map_err(|reason| invalid(format!("节点 {name} 的 VMess 响应头解密失败: {reason}")))?;
    if hdr[0] != session.resp_header {
        return Err(invalid(format!(
            "节点 {name} 的 VMess 响应校验字节不匹配"
        )));
    }
    Ok(())
}

/// The upload direction's chunk crypto: masked size field, then
/// `plaintext || tag`. Nonce is the counter followed by `iv[2..12]`; the size
/// mask is a SHAKE128 keystream over the IV.
struct ChunkSealer {
    key: [u8; 16],
    iv: [u8; 16],
    mask: ShakeMask,
    count: u16,
}

impl ChunkSealer {
    fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            key,
            iv,
            mask: ShakeMask::new(&iv),
            count: 0,
        }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let nonce = crypto::vmess_chunk_nonce(&self.iv, self.count);
        self.count = self.count.wrapping_add(1);
        let masked = self.mask.encode_len(payload.len() as u16 + GCM_TAG_LEN as u16);
        let sealed = crypto::seal(Aead::Aes128Gcm, &self.key, &nonce, payload);
        let mut out = Vec::with_capacity(2 + sealed.len());
        out.extend_from_slice(&masked);
        out.extend_from_slice(&sealed);
        out
    }
}

/// The download direction's counterpart. An empty payload (wire length 16)
/// is the server's termination chunk.
struct ChunkOpener {
    key: [u8; 16],
    iv: [u8; 16],
    mask: ShakeMask,
    count: u16,
}

impl ChunkOpener {
    fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            key,
            iv,
            mask: ShakeMask::new(&iv),
            count: 0,
        }
    }

    fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        self.mask.decode_len(encoded)
    }

    fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = crypto::vmess_chunk_nonce(&self.iv, self.count);
        self.count = self.count.wrapping_add(1);
        crypto::open(Aead::Aes128Gcm, &self.key, &nonce, sealed)
    }
}

/// The VMess body stream handed to the tunnel bridge: decrypts masked chunks
/// on the way in, seals them on the way out, and keeps read progress across
/// the bridge's short-timeout polls (a partially read length or chunk
/// resumes where it stopped).
struct VmessStream<S> {
    sock: S,
    up: ChunkSealer,
    down: ChunkOpener,
    pending: Vec<u8>,
    pos: usize,
    len_buf: [u8; 2],
    len_got: usize,
    chunk: Vec<u8>,
    chunk_got: usize,
    finished: bool,
}

impl<S> VmessStream<S> {
    fn new(sock: S, session: &Session) -> Self {
        Self {
            sock,
            up: ChunkSealer::new(session.req_key, session.req_iv),
            down: ChunkOpener::new(session.resp_key, session.resp_iv),
            pending: Vec::new(),
            pos: 0,
            len_buf: [0; 2],
            len_got: 0,
            chunk: Vec::new(),
            chunk_got: 0,
            finished: false,
        }
    }

    /// A synthetic would-block: tells the pump to try again after the short
    /// poll without losing the read state machine's progress.
    fn idle() -> io::Error {
        io::Error::from(io::ErrorKind::WouldBlock)
    }
}

impl<S: Read> Read for VmessStream<S> {
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
            if self.finished {
                return Ok(0);
            }
            if self.len_got < 2 && self.chunk.is_empty() {
                match self.sock.read(&mut self.len_buf[self.len_got..]) {
                    // The node hung up without a termination chunk; the
                    // response is over either way.
                    Ok(0) => {
                        self.finished = true;
                        return Ok(0);
                    }
                    Ok(n) => self.len_got += n,
                    Err(err) => return Err(err),
                }
                if self.len_got < 2 {
                    return Err(Self::idle());
                }
                let encoded = self.len_buf;
                self.len_got = 0;
                let chunk_len = self.down.decode_len(encoded) as usize;
                if chunk_len == GCM_TAG_LEN {
                    self.finished = true;
                    return Ok(0);
                }
                if !(chunk_len > GCM_TAG_LEN && chunk_len <= CHUNK_MAX_LEN + GCM_TAG_LEN) {
                    return Err(invalid(format!("VMess 响应块长度无效 {chunk_len}")));
                }
                self.chunk = vec![0u8; chunk_len];
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
            let plain = self.down.open(&self.chunk).map_err(invalid)?;
            self.chunk = Vec::new();
            self.chunk_got = 0;
            self.pending = plain;
            self.pos = 0;
        }
    }
}

impl<S: Write> Write for VmessStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let take = buf.len().min(CHUNK_MAX_LEN);
        let chunk = self.up.seal(&buf[..take]);
        self.sock.write_all(&chunk)?;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl<S: Read + Write + Send + 'static> tunnel::TunnelStream for VmessStream<S> {
    fn client_eof(&mut self) -> io::Result<()> {
        let term = self.up.seal(&[]);
        self.sock.write_all(&term)?;
        self.sock.flush()
    }
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    // Byte-level regression vectors produced by running the actual
    // Xray-core/sing-vmess Go code, mirrored from honk's vmess tests.
    const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const CMD_KEY_HEX: &str = "b50d916ac0cec067981af8e5f38a758f";
    const AUTH_ID_HEX: &str = "7997d3314952dc37e0b284331b6bb2e7";
    const HEADER_PLAIN_HEX: &str =
        "0122222222222222222222222222222222111111111111111111111111111111115a053300010050015db8d822aabbcc15eba2f4";
    const HEADER_WIRE_HEX: &str = "7997d3314952dc37e0b284331b6bb2e71a963074b6c9f5cd7c0825ace93c69df311f0102030405060708301fcaedd9021cf0eaab9deb25afab08b13d78f0b0ff69acfc123dd0ba0d9b6c24d5edbfbcd20d23d7fd0a9f3d59a64835ccd0253af09feb22cc2affb2942c159c5acdc2";
    const CHUNK0_HEX: &str = "cce0f4cf6e664ef12db2501e5fc2333f0d54118144ce186c4913a9a33a";
    const CHUNK1_HEX: &str = "821e7f5df60be7f0159bdf89de3bda5c55c920d471fda4d17d24ddb5fd";
    const CHUNK_TERM_HEX: &str = "f25f875b48011300760c657294fca053c869";
    const RESP_KEY_HEX: &str = "b8f12ea8c9a95d4b4641b03d9fa5a71a";
    const RESP_IV_HEX: &str = "3dc30fbac8417f76943e9c10e15eeacb";
    const RESP_HEADER_WIRE_HEX: &str =
        "1ed5e218e618e8c5350363b980c93de5efa06015b5dc7a63f67ab72353ff9aa4f47a9ee044da";
    const RCHUNK0_HEX: &str =
        "a519478d162a2f176b9d3e71216983fc910451176407bbc97aa4daccb61c4740c0";
    const RCHUNK1_HEX: &str =
        "7baab45ea2ec0a90ad19bc5cacb263341906c9224a32ff3ce1dd65f2c0f7817120";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixed_session() -> Session {
        Session {
            req_key: [0x11; 16],
            req_iv: [0x22; 16],
            resp_key: unhex(RESP_KEY_HEX).try_into().unwrap(),
            resp_iv: unhex(RESP_IV_HEX).try_into().unwrap(),
            resp_header: 0x5a,
        }
    }

    fn fixed_cmd_key() -> [u8; 16] {
        unhex(CMD_KEY_HEX).try_into().unwrap()
    }

    #[test]
    fn cmd_key_matches_vector() {
        let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
        assert_eq!(cmd_key(&uuid), fixed_cmd_key());
    }

    #[test]
    fn response_keys_derive_from_request_keys() {
        let (resp_key, resp_iv) = response_keys(&[0x11; 16], &[0x22; 16]);
        assert_eq!(resp_key, unhex(RESP_KEY_HEX).as_slice());
        assert_eq!(resp_iv, unhex(RESP_IV_HEX).as_slice());
    }

    #[test]
    fn request_header_plain_vector() {
        let plain = build_header_plain(&fixed_session(), &[0xaa, 0xbb, 0xcc], "93.184.216.34", 80);
        assert_eq!(plain, unhex(HEADER_PLAIN_HEX));
    }

    #[test]
    fn request_header_wire_vector() {
        let session = fixed_session();
        let plain = build_header_plain(&session, &[0xaa, 0xbb, 0xcc], "93.184.216.34", 80);
        let wire = seal_request_header(
            &fixed_cmd_key(),
            &unhex(AUTH_ID_HEX).try_into().unwrap(),
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &plain,
        );
        assert_eq!(wire, unhex(HEADER_WIRE_HEX));
    }

    #[test]
    fn body_chunk_vectors() {
        let mut body = ChunkSealer::new([0x11; 16], [0x22; 16]);
        assert_eq!(body.seal(b"hello vmess"), unhex(CHUNK0_HEX));
        assert_eq!(body.seal(b"hello vmess"), unhex(CHUNK1_HEX));
        assert_eq!(body.seal(b""), unhex(CHUNK_TERM_HEX));
    }

    /// Feed the exact bytes a Go (Xray-semantics) server would send and
    /// check the response header + body chunk decode end to end.
    #[test]
    fn response_decode_vectors() {
        let session = fixed_session();
        let mut wire = unhex(RESP_HEADER_WIRE_HEX);
        wire.extend_from_slice(&unhex(RCHUNK0_HEX));
        wire.extend_from_slice(&unhex(RCHUNK1_HEX));
        let mut cursor: &[u8] = &wire;
        read_response_header(&mut cursor, &session, "t").unwrap();

        let mut body = ChunkOpener::new(session.resp_key, session.resp_iv);
        let mut out = Vec::new();
        for _ in 0..2 {
            let mut len_buf = [0u8; 2];
            cursor.read_exact(&mut len_buf).unwrap();
            let chunk_len = body.decode_len(len_buf) as usize;
            let mut ct = vec![0u8; chunk_len];
            cursor.read_exact(&mut ct).unwrap();
            out.extend_from_slice(&body.open(&ct).unwrap());
        }
        assert_eq!(out, b"HTTP/1.1 200 OKHTTP/1.1 200 OK");
        assert!(cursor.is_empty());
    }

    /// Links whose transport is not plain TCP (+ optional TLS) fail with a
    /// clear error instead of dialing a channel the engine cannot speak.
    #[test]
    fn rejects_non_tcp_transports() {
        let base = |extra: &str| {
            format!(
                r#"{{"v":"2","ps":"t","add":"127.0.0.1","port":"1","id":"{TEST_UUID}","aid":"0"{extra}}}"#
            )
        };
        let link = |json: String| format!("vmess://{}", base64::encode(json.as_bytes()));
        for extra in [r#","net":"ws""#, r#","net":"tcp","type":"http""#, r#","net":"tcp","path":"/ws""#] {
            let error = vmess(
                "t",
                "127.0.0.1",
                "127.0.0.1",
                1,
                Some(&link(base(extra))),
                "example.com",
                80,
            )
            .unwrap_err();
            assert!(error.to_string().contains("尚未实现"), "extra={extra}");
        }
    }

    /// A fake VMess server over loopback: decrypts the sealed header, answers
    /// the response header, echoes one body chunk and terminates. Exercises
    /// the whole client path including the bridge pump.
    #[test]
    fn plain_tunnel_round_trip() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
            let cmd = cmd_key(&uuid);

            let mut head = [0u8; 16 + 18 + 8];
            sock.read_exact(&mut head).unwrap();
            let auth_id: [u8; 16] = head[..16].try_into().unwrap();
            let enc_len: [u8; 18] = head[16..34].try_into().unwrap();
            let conn_nonce: [u8; 8] = head[34..].try_into().unwrap();
            let len_plain = crypto::open_aad(
                Aead::Aes128Gcm,
                &crypto::vmess_kdf16(&cmd, &[KDF_SALT_HEADER_LEN_KEY, &auth_id, &conn_nonce]),
                &crypto::vmess_kdf12(&cmd, &[KDF_SALT_HEADER_LEN_IV, &auth_id, &conn_nonce]),
                &enc_len,
                &auth_id,
            )
            .unwrap();
            let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            let mut hdr_ct = vec![0u8; hdr_len + GCM_TAG_LEN];
            sock.read_exact(&mut hdr_ct).unwrap();
            let plain = crypto::open_aad(
                Aead::Aes128Gcm,
                &crypto::vmess_kdf16(&cmd, &[KDF_SALT_HEADER_KEY, &auth_id, &conn_nonce]),
                &crypto::vmess_kdf12(&cmd, &[KDF_SALT_HEADER_IV, &auth_id, &conn_nonce]),
                &hdr_ct,
                &auth_id,
            )
            .unwrap();
            // ver | req_iv(16) | req_key(16) | resp_v | option | p | 0 | cmd | port | atyp | ...
            assert_eq!(plain[0], VERSION);
            assert_eq!(plain[37], CMD_TCP);
            assert_eq!(plain[40], ATYP_DOMAIN);
            assert_eq!(&plain[42..53], b"example.com");
            let req_iv: [u8; 16] = plain[1..17].try_into().unwrap();
            let req_key: [u8; 16] = plain[17..33].try_into().unwrap();
            let (resp_key, resp_iv) = response_keys(&req_key, &req_iv);

            let sealed_len = crypto::seal(
                Aead::Aes128Gcm,
                &crypto::vmess_kdf16(&resp_key, &[KDF_SALT_RESP_LEN_KEY]),
                &crypto::vmess_kdf12(&resp_iv, &[KDF_SALT_RESP_LEN_IV]),
                &4u16.to_be_bytes(),
            );
            let sealed_hdr = crypto::seal(
                Aead::Aes128Gcm,
                &crypto::vmess_kdf16(&resp_key, &[KDF_SALT_RESP_KEY]),
                &crypto::vmess_kdf12(&resp_iv, &[KDF_SALT_RESP_IV]),
                &[plain[33], 0, 0, 0],
            );
            sock.write_all(&sealed_len).unwrap();
            sock.write_all(&sealed_hdr).unwrap();

            let mut opener = ChunkOpener::new(req_key, req_iv);
            let mut masked = [0u8; 2];
            sock.read_exact(&mut masked).unwrap();
            let chunk_len = opener.decode_len(masked) as usize;
            let mut ct = vec![0u8; chunk_len];
            sock.read_exact(&mut ct).unwrap();
            assert_eq!(opener.open(&ct).unwrap(), b"hello");
            sock.read_exact(&mut masked).unwrap();
            assert_eq!(opener.decode_len(masked) as usize, GCM_TAG_LEN);

            let mut sealer = ChunkSealer::new(resp_key, resp_iv);
            sock.write_all(&sealer.seal(b"hello")).unwrap();
            sock.write_all(&sealer.seal(b"")).unwrap();
            sock.flush().unwrap();
            // Drain so the close is graceful: dropping with unread bytes
            // makes Windows RST, which discards the echo still in flight.
            let mut drain = [0u8; 64];
            while matches!(sock.read(&mut drain), Ok(n) if n > 0) {}
        });

        let payload = format!(
            r#"{{"v":"2","ps":"t","add":"127.0.0.1","port":"{port}","id":"{TEST_UUID}","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}}"#
        );
        let link = format!("vmess://{}", base64::encode(payload.as_bytes()));
        let mut outer = vmess("plain-test", "127.0.0.1", "127.0.0.1", port, Some(&link), "example.com", 443)
            .unwrap();
        outer.write_all(b"hello").unwrap();
        outer.flush().unwrap();
        outer.shutdown(std::net::Shutdown::Write).unwrap();
        outer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut back = Vec::new();
        outer.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"hello");
        server.join().unwrap();
    }
}
