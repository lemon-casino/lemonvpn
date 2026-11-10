//! SOCKS5 CONNECT and bounded, cancellable UDP associations.

use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

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

pub fn handle(client: TcpStream) -> io::Result<()> {
    handle_inner(client, false, None, None)
}
pub(crate) fn handle_lan(
    client: TcpStream,
    auth: Option<&crate::lan::Credentials>,
    stop: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    handle_inner(client, true, auth, Some(stop))
}
fn handle_inner(
    mut client: TcpStream,
    lan: bool,
    auth: Option<&crate::lan::Credentials>,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    // A suspended datapath refuses new tunnels before the greeting; the API
    // stays reachable so resume can still arrive on the same listener.
    if crate::control::suspended() {
        return Ok(());
    }
    let mut greeting = [0u8; 2];
    proxy::read_handshake(&mut client, &mut greeting)?;
    if greeting[0] != VERSION {
        return Err(invalid("SOCKS 版本不是 5"));
    }

    let mut methods = vec![0u8; greeting[1] as usize];
    proxy::read_handshake(&mut client, &mut methods)?;
    let mut bridged = false;
    let mut process = None;
    if lan && auth.is_some() && !methods.contains(&2) {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])?;
        return Ok(());
    }
    if (lan && auth.is_some())
        || (!lan && methods.contains(&2) && !crate::compat::router_password().is_empty())
    {
        client.write_all(&[VERSION, 2])?;
        let mut head = [0; 2];
        proxy::read_handshake(&mut client, &mut head)?;
        if head[0] != 1 {
            return Err(invalid("SOCKS 认证版本无效"));
        }
        let mut username = vec![0; head[1] as usize];
        proxy::read_handshake(&mut client, &mut username)?;
        let mut length = [0];
        proxy::read_handshake(&mut client, &mut length)?;
        let mut password = vec![0; length[0] as usize];
        proxy::read_handshake(&mut client, &mut password)?;
        let accepted = if lan {
            auth.is_some_and(|auth| auth.matches(&username, &password))
        } else {
            crate::compat::bridge_process(&username).is_some()
                && password == crate::compat::router_password().as_bytes()
        };
        if !accepted {
            client.write_all(&[1, 1])?;
            return Ok(());
        }
        bridged = !lan;
        if !lan {
            process = crate::compat::bridge_process(&username).flatten();
        }
        client.write_all(&[1, 0])?;
    } else if !methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE])?;
        return Ok(());
    } else {
        client.write_all(&[VERSION, METHOD_NO_AUTH])?;
    }

    let mut request = [0u8; 4];
    proxy::read_handshake(&mut client, &mut request)?;
    if request[0] != VERSION {
        return Err(invalid("SOCKS 请求版本不是 5"));
    }
    if request[1] != CMD_CONNECT && request[1] != 3 {
        // Consume the rest of the request before closing: Windows resets a
        // socket that is closed with unread data, which can discard the reply.
        let _ = read_address(&mut client, request[3]);
        let mut port_bytes = [0u8; 2];
        let _ = proxy::read_handshake(&mut client, &mut port_bytes);
        return reply(&mut client, REP_COMMAND_NOT_SUPPORTED);
    }

    let Some((host, is_domain)) = read_address(&mut client, request[3])? else {
        return reply(&mut client, REP_ADDRESS_TYPE_NOT_SUPPORTED);
    };

    let mut port_bytes = [0u8; 2];
    proxy::read_handshake(&mut client, &mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);

    if request[1] == 3 {
        // LAN sharing currently exposes TCP only; never advertise a loopback
        // UDP relay address to a remote device or bypass the target ACL.
        if lan {
            return reply(&mut client, REP_COMMAND_NOT_SUPPORTED);
        }
        return udp_associate(client, process, bridged);
    }

    let peer = client.peer_addr().ok();
    let decision = config::decide_connection_for(&host, port, peer, "tcp", process, bridged);
    let domain = is_domain.then_some(host.as_str());
    let domain_source = domain.map(|_| "explicit");
    if decision.blocked() {
        if let Some(peer) = peer {
            flows::blocked(peer, &host, port, domain, domain_source, &decision);
        }
        return reply(&mut client, REP_CONNECTION_NOT_ALLOWED);
    }
    let flow = peer.map(|peer| flows::begin(peer, &host, port, domain, domain_source, &decision));

    match proxy::connect_inbound(&decision, &host, port, lan) {
        Ok(upstream) => {
            logs::info(
                "engine::tunnel",
                "Tunnel established.",
                Some(logs::fields(&[("via", "socks5")])),
            );
            reply(&mut client, REP_SUCCEEDED)?;
            proxy::tunnel(client, upstream, flow, &decision, (&host, port), stop)
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

struct UdpFlow {
    live: crate::connections::Live,
    relay: crate::compat::Datagram,
    last: Instant,
    meter: crate::outbounds::Meter,
    _flow: crate::flows::Guard,
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        crate::state::connection_closed();
    }
}

fn udp_associate(
    mut client: TcpStream,
    process: Option<crate::platform::process::ProcessInfo>,
    bridged: bool,
) -> io::Result<()> {
    if !crate::compat::available() {
        return reply(&mut client, REP_COMMAND_NOT_SUPPORTED);
    }
    let peer = client.peer_addr()?;
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    let mut response = vec![5, 0, 0];
    crate::compat::write_address(&mut response, &address.ip().to_string(), address.port())?;
    client.write_all(&response)?;
    client.set_nonblocking(true)?;
    socket.set_nonblocking(true)?;
    let mut recipient: Option<SocketAddr> = None;
    let mut flows: HashMap<(String, u16), UdpFlow> = HashMap::new();
    let mut bytes = vec![0; 65535];
    while !crate::runtime::stopping() && !crate::control::suspended() {
        let mut peek = [0];
        match client.peek(&mut peek) {
            Ok(0) => break,
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        for _ in 0..32 {
            let (length, from) = match socket.recv_from(&mut bytes) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            if from.ip() != peer.ip() || recipient.is_some_and(|r| r != from) {
                continue;
            }
            let Ok((host, port, offset)) = crate::compat::parse_datagram(&bytes[..length]) else {
                continue;
            };
            if port == 0 {
                continue;
            }
            recipient.get_or_insert(from);
            let key = (host.clone(), port);
            // Retire the old relay before handling this packet so a hot change
            // does not consume the first datagram with an already closed path.
            if flows.get(&key).is_some_and(|flow| flow.live.closed()) {
                flows.remove(&key);
            }
            if !flows.contains_key(&key) {
                if flows.len() >= 128 {
                    continue;
                }
                let decision = config::decide_connection_for(
                    &host,
                    port,
                    Some(from),
                    "udp",
                    process.clone(),
                    bridged,
                );
                if decision.blocked() {
                    flows::blocked_udp(from, &host, port, &decision);
                    continue;
                }
                let relay = match crate::compat::Datagram::open(&decision, &host, port) {
                    Ok(r) => r,
                    Err(_) => {
                        crate::outbounds::record_error(&decision);
                        continue;
                    }
                };
                let flow = flows::begin_udp(from, &host, port, &decision);
                let meter = crate::outbounds::Meter::open(&decision);
                crate::state::connection_opened();
                let live = crate::connections::Live::udp(from, &host, port);
                live.set_route(&decision, Some(&flow));
                flows.insert(
                    key.clone(),
                    UdpFlow {
                        live,
                        relay,
                        last: Instant::now(),
                        meter,
                        _flow: flow,
                    },
                );
            }
            let flow = flows.get_mut(&key).unwrap();
            let sent = !flow.live.closed() && flow.relay.send(&bytes[offset..length]).is_ok();
            if sent {
                let n = (length - offset) as u64;
                crate::state::add_upload(n);
                flow.live
                    .counters
                    .upload
                    .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                flow.meter.handle().upload(n);
                flow.last = Instant::now();
            } else {
                flows.remove(&key);
            }
        }
        if let Some(recipient) = recipient {
            for flow in flows.values_mut() {
                if flow.live.closed() {
                    continue;
                }
                for _ in 0..8 {
                    match flow.relay.recv(&mut bytes) {
                        Ok((length, host, port)) => {
                            let mut packet = vec![0, 0, 0];
                            crate::compat::write_address(&mut packet, &host, port)?;
                            packet.extend_from_slice(&bytes[..length]);
                            if !flow.live.closed() && socket.send_to(&packet, recipient).is_ok() {
                                crate::state::add_download(length as u64);
                                flow.live
                                    .counters
                                    .download
                                    .fetch_add(length as u64, std::sync::atomic::Ordering::Relaxed);
                                flow.meter.handle().download(length as u64);
                                flow.last = Instant::now();
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }
        flows.retain(|_, flow| {
            !flow.live.closed() && flow.last.elapsed() < Duration::from_secs(120)
        });
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

/// Returns the target host and whether the client sent it as a domain name.
fn read_address(client: &mut TcpStream, atyp: u8) -> io::Result<Option<(String, bool)>> {
    match atyp {
        ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            proxy::read_handshake(client, &mut raw)?;
            Ok(Some((Ipv4Addr::from(raw).to_string(), false)))
        }
        ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            proxy::read_handshake(client, &mut raw)?;
            Ok(Some((Ipv6Addr::from(raw).to_string(), false)))
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            proxy::read_handshake(client, &mut length)?;
            if length[0] == 0 {
                return Ok(None);
            }
            let mut raw = vec![0u8; length[0] as usize];
            proxy::read_handshake(client, &mut raw)?;
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
