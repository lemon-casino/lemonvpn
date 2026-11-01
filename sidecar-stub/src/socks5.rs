//! SOCKS5 side of the mixed inbound: no-auth CONNECT only, which is what
//! system-level SOCKS clients use for proxied TCP.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};

use crate::config;
use crate::flows;
use crate::logs;
use crate::proxy;

pub const VERSION: u8 = 0x05;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

const CMD_CONNECT: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub fn handle(mut client: TcpStream) -> io::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != VERSION {
        return Err(invalid("SOCKS 版本不是 5"));
    }

    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])?;
        return Ok(());
    }
    client.write_all(&[VERSION, METHOD_NO_AUTH])?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    if request[0] != VERSION {
        return Err(invalid("SOCKS 请求版本不是 5"));
    }
    if request[1] != CMD_CONNECT {
        // Consume the rest of the request before closing: Windows resets a
        // socket that is closed with unread data, which can discard the reply.
        let _ = read_address(&mut client, request[3]);
        let mut port_bytes = [0u8; 2];
        let _ = client.read_exact(&mut port_bytes);
        return reply(&mut client, REP_COMMAND_NOT_SUPPORTED);
    }

    let Some((host, is_domain)) = read_address(&mut client, request[3])? else {
        return reply(&mut client, REP_ADDRESS_TYPE_NOT_SUPPORTED);
    };

    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);

    let decision = config::decide(&host);
    let domain = is_domain.then_some(host.as_str());
    let domain_source = domain.map(|_| "explicit");
    let peer = client.peer_addr().ok();
    if decision.blocked() {
        if let Some(peer) = peer {
            flows::blocked(peer, &host, port, domain, domain_source, &decision);
        }
        return reply(&mut client, REP_CONNECTION_NOT_ALLOWED);
    }
    let flow = peer.map(|peer| flows::begin(peer, &host, port, domain, domain_source, &decision));

    match proxy::connect(&decision, &host, port) {
        Ok(upstream) => {
            logs::info(
                "engine::tunnel",
                "Tunnel established.",
                Some(logs::fields(&[("via", "socks5")])),
            );
            reply(&mut client, REP_SUCCEEDED)?;
            proxy::tunnel(client, upstream, flow, &decision)
        }
        Err(err) => {
            if let Some(flow) = flow {
                flow.finish("failed");
            }
            let kind = format!("{:?}", err.kind());
            logs::warn(
                "engine::tunnel",
                "Tunnel dial failed.",
                Some(logs::fields(&[("via", "socks5"), ("kind", &kind)])),
            );
            eprintln!("lemonvpn-engine-stub: socks5 connect {host}:{port} 失败: {err}");
            reply(&mut client, REP_GENERAL_FAILURE)
        }
    }
}

/// Returns the target host and whether the client sent it as a domain name.
fn read_address(client: &mut TcpStream, atyp: u8) -> io::Result<Option<(String, bool)>> {
    match atyp {
        ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            client.read_exact(&mut raw)?;
            Ok(Some((Ipv4Addr::from(raw).to_string(), false)))
        }
        ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            client.read_exact(&mut raw)?;
            Ok(Some((Ipv6Addr::from(raw).to_string(), false)))
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length)?;
            if length[0] == 0 {
                return Ok(None);
            }
            let mut raw = vec![0u8; length[0] as usize];
            client.read_exact(&mut raw)?;
            Ok(Some((String::from_utf8_lossy(&raw).into_owned(), true)))
        }
        _ => Ok(None),
    }
}

fn reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])?;
    client.flush()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
