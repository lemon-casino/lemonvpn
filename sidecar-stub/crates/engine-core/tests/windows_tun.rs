//! Opt-in native smoke: needs administrator rights and wintun.dll on PATH.
//! Captures one documentation-only /32 address, preserving default routes.
#![cfg(windows)]

use lemonvpn_engine_core::platform::{Ipv4Route, TunConfig};
use lemonvpn_engine_core::{Engine, EngineOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

#[test]
#[ignore = "requires administrator rights and the bundled Wintun DLL"]
fn native_adapter_relays_tcp_dns_and_restores_its_route() {
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_address = node.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in node.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).unwrap();
                let mut connect = [0; 10];
                stream.read_exact(&mut connect).unwrap();
                assert_eq!(&connect[..4], &[5, 1, 0, 1]);
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut writer = stream.try_clone().unwrap();
                let _ = std::io::copy(&mut stream, &mut writer);
            });
        }
    });

    let directory =
        std::env::temp_dir().join(format!("lemonvpn-native-tun-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("config.dae"),
        format!("node {{\n echo: 'socks5://{node_address}'\n}}\nrouting {{\n fallback: echo\n}}\n"),
    )
    .unwrap();
    let mut engine = Engine::start(EngineOptions {
        port: 0,
        data_dir: Some(directory.clone()),
    })
    .unwrap();
    let target = Ipv4Addr::new(203, 0, 113, 199);
    let adapter = format!("LemonVPN-Test-{}", std::process::id());
    engine
        .enable_tun(TunConfig {
            name: adapter.clone(),
            routes: vec![Ipv4Route {
                network: target,
                prefix_len: 32,
            }],
            ..TunConfig::default()
        })
        .expect("native adapter and /32 route must open");
    assert!(engine.tun_status_json().contains(r#""enabled":true"#));

    let mut client =
        TcpStream::connect_timeout(&SocketAddr::from((target, 18081)), Duration::from_secs(5))
            .expect("Windows TCP must reach the shared packet stack");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"native TUN echo").unwrap();
    let mut reply = [0; 15];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"native TUN echo");
    drop(client);

    let dns = UdpSocket::bind("0.0.0.0:0").unwrap();
    dns.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["127", "0", "0", "1"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    dns.send_to(&query, (target, 53)).unwrap();
    let mut answer = [0; 512];
    let (length, _) = dns
        .recv_from(&mut answer)
        .expect("Windows UDP DNS must reach the shared packet stack");
    assert_eq!(&answer[..2], &[0x12, 0x34]);
    assert_eq!(answer[2] & 0x80, 0x80);
    assert!(answer[..length].ends_with(&[127, 0, 0, 1]));

    engine.set_tun(false).unwrap();
    assert!(engine.tun_status_json().contains(r#""enabled":false"#));
    // A second enable proves driver handles and session ownership were released.
    engine
        .enable_tun(TunConfig {
            name: adapter,
            routes: vec![Ipv4Route {
                network: target,
                prefix_len: 32,
            }],
            ..TunConfig::default()
        })
        .unwrap();
    engine.shutdown().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
