//! An injected VPN host exercises the same TUN API even on a host where no
//! native adapter exists. This test never changes system routing or DNS.
use lemonvpn_engine_core::platform::{self, OpenedTun, Platform, TunConfig, TunSession};
use lemonvpn_engine_core::{Engine, EngineOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Host {
    supported: AtomicBool,
    tcp: AtomicUsize,
    udp: AtomicUsize,
    stopped: Arc<AtomicUsize>,
    packets: Mutex<Option<(Sender<Vec<u8>>, Receiver<Vec<u8>>)>>,
}

struct Session(Arc<AtomicUsize>);
impl TunSession for Session {
    fn shutdown(&mut self) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl Platform for Host {
    fn connect_tcp(&self, address: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        self.tcp.fetch_add(1, Ordering::SeqCst);
        TcpStream::connect_timeout(&address, timeout)
    }
    fn bind_udp(&self, address: SocketAddr) -> std::io::Result<UdpSocket> {
        self.udp.fetch_add(1, Ordering::SeqCst);
        UdpSocket::bind(address)
    }
    fn tun_supported(&self) -> bool {
        self.supported.load(Ordering::SeqCst)
    }
    fn open_tun(&self, config: &TunConfig) -> std::io::Result<OpenedTun> {
        assert_ne!(config.stack_address, config.host_address);
        let (host_tx, incoming) = mpsc::channel();
        let (outgoing, host_rx) = mpsc::channel();
        *self.packets.lock().unwrap() = Some((host_tx, host_rx));
        Ok(OpenedTun {
            incoming,
            outgoing,
            session: Box::new(Session(Arc::clone(&self.stopped))),
        })
    }
}

fn request(address: SocketAddr, method: &str, path: &str, body: &str) -> String {
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(client, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn injected_host_owns_network_sockets_tun_capabilities_and_packet_io() {
    let host = Arc::new(Host {
        supported: AtomicBool::new(false),
        tcp: AtomicUsize::new(0),
        udp: AtomicUsize::new(0),
        stopped: Arc::new(AtomicUsize::new(0)),
        packets: Mutex::new(None),
    });
    platform::install(host.clone()).unwrap();
    let directory =
        std::env::temp_dir().join(format!("lemonvpn-library-host-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    std::fs::write(directory.join("config.dae"), format!(
        "dns {{\n upstream {{\n default: 'udp://{}'\n }}\n}}\nrouting {{\n fallback: direct\n}}\n", dns.local_addr().unwrap())).unwrap();
    let dns_server = std::thread::spawn(move || {
        let mut query = [0; 512];
        let (length, peer) = dns.recv_from(&mut query).unwrap();
        query[2] = 0x81;
        query[3] = 0x80;
        dns.send_to(&query[..length], peer).unwrap();
    });
    let mut engine = Engine::start(EngineOptions {
        port: 0,
        data_dir: Some(directory.clone()),
    })
    .unwrap();
    let address = engine.local_addr();
    assert!(request(address, "GET", "/api/v1/tun", "").contains(r#""supported":false"#));
    assert!(request(address, "GET", "/api/v1/capabilities", "")
        .contains(r#""tun":{"available":false}"#));
    assert!(request(address, "POST", "/api/v1/tun/set", r#"{"enabled":true}"#).contains("501"));
    let dns_reply = request(
        address,
        "POST",
        "/api/v1/dns/query",
        r#"{"domain":"example.test","types":["A"]}"#,
    );
    assert!(dns_reply.contains("200 OK"), "{dns_reply}");
    dns_server.join().unwrap();
    assert_eq!(host.udp.load(Ordering::SeqCst), 1);

    // HTTP forwarding must use the injected TCP dialer too.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_address = origin.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut client, _) = origin.accept().unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            client.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    assert!(request(address, "GET", &format!("http://{origin_address}/"), "").ends_with("ok"));
    server.join().unwrap();
    assert_eq!(host.tcp.load(Ordering::SeqCst), 1);

    host.supported.store(true, Ordering::SeqCst);
    assert!(
        request(address, "POST", "/api/v1/tun/set", r#"{"enabled":true}"#)
            .contains(r#""enabled":true"#)
    );
    assert!(engine.tun_status_json().contains(r#""enabled":true"#));
    let (to_stack, from_stack) = host.packets.lock().unwrap().take().unwrap();
    // Real packet bytes traverse the shared DNS stack through host channels.
    // A literal question avoids external DNS while exercising packet transport.
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 111, 0, 2]);
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53u16.to_be_bytes());
    let mut dns_question = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["127", "0", "0", "1"] {
        dns_question.push(label.len() as u8);
        dns_question.extend_from_slice(label.as_bytes());
    }
    dns_question.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet.extend_from_slice(&dns_question);
    let length = packet.len();
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[24..26].copy_from_slice(&((dns_question.len() + 8) as u16).to_be_bytes());
    to_stack.send(packet).unwrap();
    let reply = from_stack
        .recv_timeout(Duration::from_secs(3))
        .expect("shared stack must return a packet");
    assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
    assert_eq!(&reply[28..30], &[0x12, 0x34]);
    assert_eq!(reply[30] & 0x80, 0x80);
    engine.shutdown().unwrap();
    engine.shutdown().unwrap();
    assert_eq!(host.stopped.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(directory).unwrap();
}
