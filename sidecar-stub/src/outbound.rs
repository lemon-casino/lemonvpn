//! Outbounds: connects to a configured node and asks it to carry the target.
//!
//! SOCKS5 keeps domain targets as domains, so the node resolves them and the
//! local resolver is not involved. Protocols this engine does not carry yet fail
//! with a clear error instead of pretending the node is healthy.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Dials `host:port` through a SOCKS5 node. The node endpoint itself is dialed
/// directly; only the target travels inside the tunnel.
/// Opens `host:port` through `node`, dialing the node at its configured host.
pub fn connect(node: &config::Node, host: &str, port: u16) -> io::Result<TcpStream> {
    connect_via(node, &node.host, host, port)
}

/// Opens `host:port` through `node`, dialing `address` instead of the node's
/// configured host. Probes use it to pick one resolved address per attempt.
pub fn connect_via(
    node: &config::Node,
    address: &str,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    match node.protocol.as_str() {
        "socks5" => socks5(
            &node.name,
            address,
            node.port,
            node.username.as_deref(),
            node.password.as_deref(),
            host,
            port,
        ),
        protocol => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("节点协议 {protocol} 的出站尚未实现"),
        )),
    }
}

pub fn socks5(
    name: &str,
    node_host: &str,
    node_port: u16,
    username: Option<&str>,
    password: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let mut stream = crate::proxy::dial(node_host, node_port)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    negotiate(&mut stream, name, username, password)?;
    send_connect(&mut stream, name, host, port)?;
    Ok(stream)
}

fn negotiate(
    stream: &mut TcpStream,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> io::Result<()> {
    let authenticated = username.is_some() && password.is_some();
    let methods: &[u8] = if authenticated {
        &[METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(VERSION);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting)?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice)?;
    if choice[0] != VERSION {
        return Err(invalid(format!("节点 {name} 的 SOCKS5 版本不是 5")));
    }
    match choice[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USER_PASS => {
            let (Some(username), Some(password)) = (username, password) else {
                return Err(invalid(format!("节点 {name} 要求用户名pass认证，但配置里没有")));
            };
            authenticate(stream, name, username, password)
        }
        METHOD_NONE_ACCEPTABLE => Err(invalid(format!("节点 {name} 不接受本机提供的认证方式"))),
        method => Err(invalid(format!("节点 {name} 选择了未知认证方式 {method}"))),
    }
}

fn authenticate(stream: &mut TcpStream, name: &str, username: &str, password: &str) -> io::Result<()> {
    if username.len() > 255 || password.len() > 255 {
        return Err(invalid(format!("节点 {name} 的用户名或pass超过 255 字节")));
    }
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0x00 {
        return Err(invalid(format!("节点 {name} 拒绝了用户名pass认证")));
    }
    Ok(())
}

fn send_connect(stream: &mut TcpStream, name: &str, host: &str, port: u16) -> io::Result<()> {
    let mut request = Vec::with_capacity(7 + host.len());
    request.push(VERSION);
    request.push(CMD_CONNECT);
    request.push(0x00);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                return Err(invalid("目标域名长度必须在 1..=255 之间".to_owned()));
            }
            request.push(ATYP_DOMAIN);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != VERSION {
        return Err(invalid(format!("节点 {name} 的 SOCKS5 回复版本不是 5")));
    }
    if reply[1] != 0x00 {
        return Err(invalid(format!(
            "节点 {name} 拒绝连接（SOCKS5 错误码 {}）",
            reply[1]
        )));
    }
    let address_length = match reply[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        atyp => return Err(invalid(format!("节点 {name} 返回了未知地址类型 {atyp}"))),
    };
    let mut discard = vec![0u8; address_length + 2];
    stream.read_exact(&mut discard)?;
    Ok(())
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A one-shot SOCKS5 server that records the target and answers success.
    fn server(reply: u8) -> (u16, thread::JoinHandle<(String, u16)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).unwrap();
            socket.write_all(&[VERSION, METHOD_NO_AUTH]).unwrap();
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).unwrap();
            let host = match request[3] {
                ATYP_DOMAIN => {
                    let mut length = [0u8; 1];
                    socket.read_exact(&mut length).unwrap();
                    let mut raw = vec![0u8; length[0] as usize];
                    socket.read_exact(&mut raw).unwrap();
                    String::from_utf8(raw).unwrap()
                }
                _ => String::new(),
            };
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).unwrap();
            socket
                .write_all(&[VERSION, reply, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .unwrap();
            (host, u16::from_be_bytes(port))
        });
        (port, handle)
    }

    #[test]
    fn sends_the_domain_to_the_node() {
        let (port, handle) = server(0x00);
        let stream = socks5("edge", "127.0.0.1", port, None, None, "example.com", 443);
        assert!(stream.is_ok());
        assert_eq!(handle.join().unwrap(), ("example.com".to_owned(), 443));
    }

    #[test]
    fn surfaces_a_refused_connect() {
        let (port, handle) = server(0x05);
        let error = socks5("edge", "127.0.0.1", port, None, None, "example.com", 443).unwrap_err();
        assert!(error.to_string().contains("错误码 5"));
        let _ = handle.join();
    }
}
