//! The Trojan outbound: `hex(sha224(password)) CRLF cmd addr CRLF` inside a
//! TLS channel. There is no response header — a wrong password just makes the
//! server close the connection, which surfaces as EOF on first use, exactly
//! like honk's client.

use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use crate::sha256;
use crate::share;
use crate::tls;
use crate::tunnel;

const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens `host:port` through a Trojan node dialed at `node_host:node_port`.
/// `link` is the node's share link; it carries the password, SNI and security
/// mode.
pub fn trojan(
    _name: &str,
    node_host: &str,
    node_hostname: &str,
    node_port: u16,
    link: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let link = link.ok_or_else(|| invalid("Trojan 节点缺少分享链接"))?;
    let share = share::parse(link).map_err(|reason| invalid(reason))?;
    if share.protocol != "trojan" {
        return Err(invalid("节点分享链接不是 Trojan"));
    }
    if share.reality {
        return Err(invalid("Trojan REALITY 的出站尚未实现"));
    }
    if share.secret.is_empty() {
        return Err(invalid("Trojan 节点缺少密码"));
    }
    if host.len() > 255 {
        return Err(invalid("目标域名超过 255 字节"));
    }
    let request = build_request(&share.secret, host, port);

    let mut sock = crate::proxy::dial(node_host, node_port)?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    if !share.tls {
        sock.write_all(&request)?;
        sock.flush()?;
        return Ok(sock);
    }
    let sni = share
        .sni
        .as_deref()
        .filter(|sni| !sni.is_empty())
        .unwrap_or(node_hostname);
    let insecure = share::query_params(query_of(link))
        .get("allowinsecure")
        .is_some_and(|value| value == "1" || value == "true");
    let mut stream = tls::connect(sock, sni, insecure)?;
    stream.write_all(&request)?;
    stream.flush()?;
    // No response header: the tunnel is transparent from here. A wrong
    // password shows up as the server closing the connection.
    tunnel::bridge(stream)
}

/// `hex(sha224(password)) CRLF cmd ATYP addr port CRLF` (SOCKS5 address form).
fn build_request(password: &str, host: &str, port: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(58 + 4 + host.len() + 7);
    request.extend_from_slice(sha256::sha224_hex(password.as_bytes()).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.push(CMD_TCP);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            request.push(ATYP_DOMAIN);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request
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
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    const PASSWORD: &str = "pw";

    #[test]
    fn request_header_layout() {
        let request = build_request(PASSWORD, "example.com", 443);
        assert_eq!(&request[..56], sha256::sha224_hex(PASSWORD.as_bytes()).as_bytes());
        assert_eq!(request[56], b'\r');
        assert_eq!(request[57], b'\n');
        assert_eq!(request[58], CMD_TCP);
        assert_eq!(request[59], ATYP_DOMAIN);
        assert_eq!(request[60], 11);
        assert_eq!(&request[61..72], b"example.com");
        assert_eq!(&request[72..74], &[0x01, 0xbb]);
        assert_eq!(&request[74..76], b"\r\n");
        assert_eq!(request.len(), 76);
    }

    #[test]
    fn request_header_encodes_addresses() {
        let v4 = build_request(PASSWORD, "93.184.216.34", 80);
        assert_eq!(v4[59], ATYP_IPV4);
        assert_eq!(&v4[60..64], &[93, 184, 216, 34]);
        assert_eq!(&v4[64..66], &[0x00, 0x50]);

        let v6 = build_request(PASSWORD, "2606:2800:220:1:248:1893:25c8:1946", 80);
        assert_eq!(v6[59], ATYP_IPV6);
        assert_eq!(v6.len(), 58 + 1 + 1 + 16 + 2 + 2);
    }

    #[test]
    fn reality_is_rejected() {
        let error = trojan(
            "t",
            "127.0.0.1",
            "127.0.0.1",
            1,
            Some("trojan://pw@127.0.0.1:1?security=reality&pbk=x#t"),
            "example.com",
            443,
        )
        .unwrap_err();
        assert!(error.to_string().contains("尚未实现"));
    }

    /// A fake Trojan server speaking TLS: checks the request bytes and echoes
    /// one payload through the bridge.
    #[test]
    fn tls_tunnel_round_trip_through_bridge() {
        let certified = rcgen::generate_simple_self_signed(vec!["node.example".to_owned()]).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
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
            let mut seen = vec![0u8; 76];
            stream.read_exact(&mut seen).unwrap();
            let expected = build_request(PASSWORD, "example.com", 443);
            assert_eq!(seen, expected);
            // No response header — echo the client's payload directly.
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(&buf).unwrap();
            stream.flush().unwrap();
            // Drain so the close stays graceful on Windows.
            let mut drain = [0u8; 64];
            while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
        });
        let mut outer = trojan(
            "tls-test",
            "127.0.0.1",
            "node.example",
            port,
            Some(&format!(
                "trojan://{PASSWORD}@127.0.0.1:{port}?security=tls&sni=node.example&allowInsecure=1#t"
            )),
            "example.com",
            443,
        )
        .unwrap();
        outer.write_all(b"hello").unwrap();
        outer.flush().unwrap();
        outer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut back = [0u8; 5];
        outer.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        // Half-close the upload so the pump sends a TLS close_notify and the
        // server's drain loop reaches EOF.
        outer.shutdown(std::net::Shutdown::Write).unwrap();
        server.join().unwrap();
    }
}
