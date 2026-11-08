//! Exercise the library as an embedded host, without launching the sidecar.
use lemonvpn_engine_core::{Engine, EngineOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn get(address: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn embedded_engine_preserves_proxy_io_and_releases_clients_and_port() {
    let directory =
        std::env::temp_dir().join(format!("lemonvpn-library-lifecycle-{}", std::process::id()));
    let options = EngineOptions {
        port: 0,
        data_dir: Some(directory.clone()),
    };
    let mut engine = Engine::start(options.clone()).unwrap();
    let address = engine.local_addr();
    assert!(get(address, "/health").contains("200 OK"));
    // A read poll is not the handshake deadline: a slow but valid header must
    // survive multiple polls without losing bytes already received.
    let mut slow = TcpStream::connect(address).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    slow.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(600));
    slow.write_all(b"Host: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    slow.read_to_string(&mut response).unwrap();
    assert!(response.contains("200 OK"));
    assert!(
        matches!(Engine::start(options.clone()), Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert!(
        matches!(Engine::start(EngineOptions { port: address.port(), data_dir: Some(directory.clone()) }),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse)
    );

    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_address = echo.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = echo.accept().unwrap();
        let mut response = stream.try_clone().unwrap();
        std::io::copy(&mut stream, &mut response).unwrap();
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        client,
        "CONNECT {echo_address} HTTP/1.1\r\nHost: {echo_address}\r\n\r\n"
    )
    .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    assert!(String::from_utf8(header).unwrap().contains("200"));
    client.write_all(b"shared engine").unwrap();
    let mut reply = [0; 13];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"shared engine");

    let mut pending = Vec::new();
    // Quiet SSE subscriptions must wake for shutdown, independently of their
    // advertised 15-second heartbeat interval.
    for path in ["/api/v1/events", "/api/v1/logs?level=error"] {
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(socket, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut ready = Vec::new();
        while !ready.ends_with(b"\n\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            ready.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&ready).contains("stream.ready"));
        pending.push(socket);
    }
    for payload in [
        b"".as_slice(),
        b"GET /health HTTP/1.1\r\n".as_slice(),
        b"\x05".as_slice(),
        b"POST /api/v1/tun/set HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16\r\n\r\n{"
            .as_slice(),
    ] {
        let mut socket = TcpStream::connect(address).unwrap();
        socket.write_all(payload).unwrap();
        pending.push(socket);
    }
    std::thread::sleep(Duration::from_millis(100));
    let shutdown_started = std::time::Instant::now();
    engine.shutdown().unwrap();
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(2),
        "pending handshakes must not block shutdown"
    );
    drop(pending);
    assert!(client.read(&mut [0]).map_or(true, |length| length == 0));
    server.join().unwrap();
    let rebound = TcpListener::bind(address).expect("shutdown must release the listener");
    drop(rebound);
    assert!(engine.set_tun(true).is_err());

    // Restart uses the same configuration. Dropping an already stopped handle
    // must not stop a newly running engine or remove its TUN state.
    let mut restarted = Engine::start(options).unwrap();
    engine.shutdown().unwrap();
    drop(engine);
    assert!(get(restarted.local_addr(), "/health").contains("200 OK"));
    restarted.shutdown().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
