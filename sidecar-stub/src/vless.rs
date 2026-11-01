//! The VLESS outbound: the version-0 request header over a plain or TLS
//! channel. Vision (`xtls-rprx-vision`) and REALITY nodes are rejected with a
//! clear error until their modules land, so probes never mark them healthy.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use crate::crypto;
use crate::share;
use crate::tls;
use crate::tunnel;

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens `host:port` through a VLESS node dialed at `node_host:node_port`.
/// `link` is the node's share link; it carries the UUID, security mode, SNI
/// and flow.
pub fn vless(
    name: &str,
    node_host: &str,
    node_port: u16,
    link: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let link = link.ok_or_else(|| invalid("VLESS 节点缺少分享链接"))?;
    let share = share::parse(link).map_err(|reason| invalid(reason))?;
    if share.protocol != "vless" {
        return Err(invalid("节点分享链接不是 VLESS"));
    }
    let params = share::query_params(query_of(link));
    let flow = params.get("flow").map(String::as_str).unwrap_or("");
    if !flow.is_empty() && flow != "xtls-rprx-vision" {
        return Err(invalid(format!("VLESS flow `{flow}` 不受支持")));
    }
    if !flow.is_empty() {
        return Err(invalid("VLESS Vision (xtls-rprx-vision) 的出站尚未实现"));
    }
    if share.reality {
        return Err(invalid("VLESS REALITY 的出站尚未实现"));
    }
    let uuid =
        crypto::uuid_bytes(&share.secret).ok_or_else(|| invalid("VLESS 节点的 UUID 无效"))?;
    if host.len() > 255 {
        return Err(invalid("目标域名超过 255 字节"));
    }

    let mut sock = crate::proxy::dial(node_host, node_port)?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let request = build_request(&uuid, host, port);
    if !share.tls {
        sock.write_all(&request)?;
        sock.flush()?;
        read_response(&mut sock, name)?;
        return Ok(sock);
    }
    let sni = share
        .sni
        .as_deref()
        .filter(|sni| !sni.is_empty())
        .unwrap_or(node_host);
    let insecure = params
        .get("allowinsecure")
        .is_some_and(|value| value == "1" || value == "true");
    let mut stream = tls::connect(sock, sni, insecure)?;
    stream.write_all(&request)?;
    stream.flush()?;
    read_response(&mut stream, name)?;
    tunnel::bridge(stream)
}

/// `ver(0) | uuid(16) | addon_len(0) | cmd(TCP) | port(2 BE) | atyp | addr`.
fn build_request(uuid: &[u8; 16], host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(21 + 3 + host.len());
    buf.push(VERSION);
    buf.extend_from_slice(uuid);
    buf.push(0);
    buf.push(CMD_TCP);
    buf.extend_from_slice(&port.to_be_bytes());
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf
}

/// `ver(1) | addon_len(1) | addon`; the server sends it once the tunnel is up.
fn read_response(stream: &mut impl Read, name: &str) -> io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    if head[0] != VERSION {
        return Err(invalid(format!("节点 {name} 的 VLESS 响应版本不是 0")));
    }
    let mut addon = vec![0u8; head[1] as usize];
    stream.read_exact(&mut addon)?;
    Ok(())
}

fn query_of(link: &str) -> &str {
    let Some((_, rest)) = link.split_once('?') else {
        return "";
    };
    match rest.split_once('#') {
        Some((query, _)) => query,
        None => rest,
    }
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn request_header_matches_wire_format() {
        let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
        let request = build_request(&uuid, "example.com", 443);
        let mut expected = vec![0x00];
        expected.extend_from_slice(&uuid);
        expected.extend_from_slice(&[0x00, 0x01, 0x01, 0xbb, 0x02, 11]);
        expected.extend_from_slice(b"example.com");
        assert_eq!(request, expected);
    }

    #[test]
    fn request_header_encodes_addresses() {
        let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
        let v4 = build_request(&uuid, "93.184.216.34", 80);
        assert_eq!(v4[21], ATYP_IPV4);
        assert_eq!(v4.len(), 22 + 4);
        assert_eq!(&v4[22..26], &[93, 184, 216, 34]);

        let v6 = build_request(&uuid, "2606:2800:220:1:248:1893:25c8:1946", 80);
        assert_eq!(v6[21], ATYP_IPV6);
        assert_eq!(v6.len(), 22 + 16);
    }

    #[test]
    fn response_rejects_wrong_version() {
        let mut data: &[u8] = &[0x01, 0x00];
        let error = read_response(&mut data, "n1").unwrap_err();
        assert!(error.to_string().contains("版本"));
    }

    #[test]
    fn response_accepts_addon() {
        let mut data: &[u8] = &[0x00, 0x03, 1, 2, 3];
        read_response(&mut data, "n1").unwrap();
    }

    /// A fake VLESS server speaking plain TCP: checks the request bytes, then
    /// answers the handshake and echoes one payload through the tunnel.
    #[test]
    fn plain_tunnel_round_trip() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
            let mut request = vec![0x00];
            request.extend_from_slice(&uuid);
            request.extend_from_slice(&[0x00, 0x01, 0x01, 0xbb, 0x02, 11]);
            request.extend_from_slice(b"example.com");
            let mut seen = vec![0u8; request.len()];
            sock.read_exact(&mut seen).unwrap();
            assert_eq!(seen, request);
            sock.write_all(&[0x00, 0x00]).unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).unwrap();
            sock.write_all(&buf).unwrap();
        });
        let mut outer = vless(
            "plain-test",
            "127.0.0.1",
            port,
            Some(&format!("vless://{TEST_UUID}@127.0.0.1:{port}?security=none#t")),
            "example.com",
            443,
        )
        .unwrap();
        outer.write_all(b"hello").unwrap();
        outer.flush().unwrap();
        let mut back = [0u8; 5];
        outer.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        server.join().unwrap();
    }

    /// A fake VLESS server speaking TLS: exercises `tls::connect`, the
    /// handshake and the bridge pump in both directions.
    #[test]
    fn tls_tunnel_round_trip_through_bridge() {
        let certified = rcgen::generate_simple_self_signed(vec!["node.example".to_owned()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            certified.key_pair.serialize_der().into(),
        );
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certified.cert.der().clone()], key)
                .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, sock);
            let uuid = crypto::uuid_bytes(TEST_UUID).unwrap();
            let mut prefix = vec![0x00];
            prefix.extend_from_slice(&uuid);
            prefix.extend_from_slice(&[0x00, 0x01, 0x01, 0xbb, 0x02, 11]);
            let mut seen = vec![0u8; prefix.len()];
            stream.read_exact(&mut seen).unwrap();
            assert_eq!(seen, prefix);
            let mut domain = vec![0u8; 11];
            stream.read_exact(&mut domain).unwrap();
            assert_eq!(&domain, b"example.com");
            stream.write_all(&[0x00, 0x00]).unwrap();
            stream.flush().unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(&buf).unwrap();
            stream.flush().unwrap();
        });
        let mut outer = vless(
            "tls-test",
            "127.0.0.1",
            port,
            Some(&format!(
                "vless://{TEST_UUID}@127.0.0.1:{port}?security=tls&sni=node.example&allowInsecure=1#t"
            )),
            "example.com",
            443,
        )
        .unwrap();
        outer.write_all(b"hello").unwrap();
        outer.flush().unwrap();
        let mut back = [0u8; 5];
        outer.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        server.join().unwrap();
    }

    /// Vision and REALITY nodes must fail loudly instead of silently dialing
    /// a plain channel they cannot speak.
    #[test]
    fn vision_and_reality_are_rejected() {
        let error = vless(
            "vision-test",
            "127.0.0.1",
            1,
            Some(&format!("vless://{TEST_UUID}@127.0.0.1:1?flow=xtls-rprx-vision#t")),
            "example.com",
            443,
        )
        .unwrap_err();
        assert!(error.to_string().contains("尚未实现"));

        let error = vless(
            "reality-test",
            "127.0.0.1",
            1,
            Some(&format!(
                "vless://{TEST_UUID}@127.0.0.1:1?security=reality&pbk=x#t"
            )),
            "example.com",
            443,
        )
        .unwrap_err();
        assert!(error.to_string().contains("尚未实现"));
    }
}
