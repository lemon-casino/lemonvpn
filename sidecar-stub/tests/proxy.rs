//! End-to-end checks against the real engine binary: health endpoint, the HTTP
//! side (CONNECT and absolute-form) and SOCKS5 CONNECT.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_DATA_DIR: AtomicU64 = AtomicU64::new(0);

struct Engine {
    child: Child,
    port: u16,
    data_dir: PathBuf,
}

impl Engine {
    fn start() -> Engine {
        Engine::start_with(None)
    }

    /// Each engine gets its own data directory, so the tests never read or
    /// write the configuration of the machine running them.
    fn start_with(config: Option<&str>) -> Engine {
        let data_dir = std::env::temp_dir().join(format!(
            "lemonvpn-engine-test-{}-{}",
            std::process::id(),
            NEXT_DATA_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&data_dir).expect("创建测试数据目录");
        if let Some(content) = config {
            fs::write(data_dir.join("config.dae"), content).expect("写入测试配置");
        }

        let mut child = Command::new(env!("CARGO_BIN_EXE_lemonvpn-engine-stub"))
            .env("LEMONVPN_ENGINE_PORT", "0")
            .env("LEMONVPN_DATA_DIR", &data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("启动引擎");

        let stderr = child.stderr.take().expect("stderr 管道");
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        let mut port = 0u16;
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(rest) = line.split("listening on http://").nth(1) {
                port = rest
                    .trim()
                    .rsplit_once(':')
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);
                break;
            }
        }
        assert!(port > 0, "未能从引擎输出解析端口");

        thread::spawn(move || {
            let mut sink = String::new();
            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });

        Engine {
            child,
            port,
            data_dir,
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("连接引擎");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    /// One origin-form request, as the native API client sends it.
    fn get(&self, path: &str) -> String {
        self.request("GET", path)
    }

    fn request(&self, method: &str, path: &str) -> String {
        let mut client = self.connect();
        client
            .write_all(
                format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        read_all(&mut client)
    }

    fn post(&self, path: &str, body: &str) -> String {
        let mut client = self.connect();
        client
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        read_all(&mut client)
    }

    fn put(&self, path: &str, if_match: &str, body: &str) -> String {
        let mut client = self.connect();
        client
            .write_all(
                format!(
                    "PUT {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nIf-Match: \"{if_match}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        read_all(&mut client)
    }
}

/// Reads a decimal UInt64 field, which the contract sends as a string.
fn uint_field(body: &str, key: &str) -> u64 {
    let marker = format!("\"{key}\":\"");
    let start = body.find(&marker).unwrap_or_else(|| panic!("缺少字段 {key}: {body}")) + marker.len();
    let rest = &body[start..];
    rest[..rest.find('"').expect("字符串字段未结束")]
        .parse()
        .expect("UInt64 字段不是十进制")
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

/// Accepts connections and echoes every byte back.
fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if stream.write_all(&buffer[..count]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Answers any request with a 200 whose body is the received request line.
fn spawn_http() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line == "\r\n" => break,
                        Ok(_) => {}
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    request_line.len(),
                    request_line
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    port
}

/// A minimal SOCKS5 node: accepts the handshake, ignores the requested target
/// and connects to `target_port` instead, then pipes bytes both ways.
fn spawn_socks5(target_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || -> Option<()> {
                let mut greeting = [0u8; 2];
                stream.read_exact(&mut greeting).ok()?;
                let mut methods = vec![0u8; greeting[1] as usize];
                stream.read_exact(&mut methods).ok()?;
                stream.write_all(&[0x05, 0x00]).ok()?;

                let mut head = [0u8; 4];
                stream.read_exact(&mut head).ok()?;
                let address_length = match head[3] {
                    0x01 => 4,
                    0x04 => 16,
                    0x03 => {
                        let mut length = [0u8; 1];
                        stream.read_exact(&mut length).ok()?;
                        length[0] as usize
                    }
                    _ => return None,
                };
                let mut discard = vec![0u8; address_length + 2];
                stream.read_exact(&mut discard).ok()?;

                let upstream = TcpStream::connect(("127.0.0.1", target_port)).ok()?;
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .ok()?;
                let mut client_read = stream.try_clone().ok()?;
                let mut upstream_write = upstream.try_clone().ok()?;
                let upload =
                    thread::spawn(move || {
                        let _ = std::io::copy(&mut client_read, &mut upstream_write);
                    });
                let mut upstream_read = upstream;
                let mut client_write = stream;
                let _ = std::io::copy(&mut upstream_read, &mut client_write);
                let _ = upload.join();
                Some(())
            });
        }
    });
    port
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn read_all(stream: &mut TcpStream) -> String {
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    text
}

#[test]
fn health_endpoint_still_answers() {
    let engine = Engine::start();
    let mut client = engine.connect();
    client
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_all(&mut client);
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""status":"ok""#), "响应: {response}");
}

#[test]
fn unknown_origin_path_is_not_found() {
    let engine = Engine::start();
    let mut client = engine.connect();
    client
        .write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let response = read_all(&mut client);
    assert!(response.starts_with("HTTP/1.1 400"), "响应: {response}");
}

#[test]
fn socks5_connect_tunnels_bytes() {
    let engine = Engine::start();
    let echo = spawn_echo();
    let mut client = engine.connect();

    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&echo.to_be_bytes());
    client.write_all(&request).unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "SOCKS5 连接被拒绝");

    client.write_all(b"ping-through-socks").unwrap();
    let mut echoed = vec![0u8; "ping-through-socks".len()];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, b"ping-through-socks");
}

#[test]
fn socks5_rejects_non_connect_command() {
    let engine = Engine::start();
    let mut client = engine.connect();

    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x07, "非 CONNECT 命令应返回不支持");
}

#[test]
fn http_connect_tunnels_bytes() {
    let engine = Engine::start();
    let echo = spawn_echo();
    let mut client = engine.connect();

    client
        .write_all(format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .unwrap();

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "响应: {head}");

    client.write_all(b"ping-through-connect").unwrap();
    let mut echoed = vec![0u8; "ping-through-connect".len()];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, b"ping-through-connect");
}

#[test]
fn connections_list_the_open_tunnel_and_forget_it_after_close() {
    let engine = Engine::start();
    let echo = spawn_echo();
    let mut client = engine.connect();

    client
        .write_all(format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

    client.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping");

    let listed = engine.get("/api/v1/connections");
    assert!(listed.starts_with("HTTP/1.1 200"), "响应: {listed}");
    assert!(listed.contains(r#""total_tcp":1"#), "响应: {listed}");
    assert!(
        listed.contains(&format!(r#""dst":"127.0.0.1:{echo}""#)),
        "响应: {listed}"
    );
    assert!(listed.contains(r#""upload_bytes":"4""#), "响应: {listed}");
    assert!(listed.contains(r#""outbound":"direct""#), "响应: {listed}");
    assert!(listed.contains(r#""rule_source":"unknown""#), "响应: {listed}");

    drop(client);
    let mut forgotten = false;
    for _ in 0..40 {
        if engine.get("/api/v1/connections").contains(r#""total_tcp":0"#) {
            forgotten = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(forgotten, "关闭后的隧道仍被列出");
}

/// One SSE frame; a blank line (LF or CRLF) ends it.
fn read_sse_frame(reader: &mut BufReader<TcpStream>) -> String {
    let mut frame = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return frame;
        }
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            return frame;
        }
        frame.push_str(&line);
    }
}

#[test]
fn events_start_with_ready_then_stream_runtime_updates() {
    let engine = Engine::start();
    let mut reader = BufReader::new(engine.connect());
    reader
        .get_mut()
        .write_all(b"GET /api/v1/events HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n")
        .unwrap();

    let mut head = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    assert!(head.starts_with("HTTP/1.1 200"), "响应头: {head}");
    assert!(head.contains("Content-Type: text/event-stream"), "响应头: {head}");

    let ready = read_sse_frame(&mut reader);
    assert!(ready.contains("event: stream.ready"), "首帧: {ready}");
    assert!(ready.contains(r#""instance_id":"lemonvpn-"#), "首帧: {ready}");

    // The producer coalesces runtime updates every five seconds.
    let mut updated = false;
    for _ in 0..2 {
        let frame = read_sse_frame(&mut reader);
        if frame.contains("event: runtime.updated") {
            assert!(frame.contains(r#""href":"/api/v1/runtime""#), "帧: {frame}");
            updated = true;
            break;
        }
    }
    assert!(updated, "未收到 runtime.updated");
}

#[test]
fn events_reject_kinds_this_engine_does_not_produce() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/events?kinds=flow.updated");
    assert!(response.starts_with("HTTP/1.1 422"), "响应: {response}");
    assert!(response.contains(r#""code":"unsupported_value""#), "响应: {response}");

    let response = engine.get("/api/v1/events?kinds=nope");
    assert!(response.starts_with("HTTP/1.1 400"), "响应: {response}");
}

#[test]
fn http_connect_to_closed_port_is_bad_gateway() {
    let engine = Engine::start();
    let closed = free_port();
    let mut client = engine.connect();
    client
        .write_all(format!("CONNECT 127.0.0.1:{closed} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let response = read_all(&mut client);
    assert!(response.starts_with("HTTP/1.1 502"), "响应: {response}");
}

#[test]
fn health_carries_the_process_identity() {
    let engine = Engine::start();
    let pid = engine.child.id();
    let response = engine.get("/health");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(
        response.contains(&format!(r#""instance":"lemonvpn-{pid}""#)),
        "响应: {response}"
    );
    assert!(
        response.contains(&format!(r#""pid":{pid}"#)),
        "响应: {response}"
    );
}

#[test]
fn a_second_engine_on_a_taken_port_exits_with_3() {
    let engine = Engine::start();
    let status = Command::new(env!("CARGO_BIN_EXE_lemonvpn-engine-stub"))
        .env("LEMONVPN_ENGINE_PORT", engine.port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("启动第二个引擎");
    assert_eq!(status.code(), Some(3), "端口被占用时应以退出码 3 结束");
}

#[test]
fn discovery_admits_the_loopback_client() {
    let engine = Engine::start();
    let response = engine.get("/api");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""api_major":1"#), "响应: {response}");
    assert!(response.contains(r#""base_path":"/api/v1""#), "响应: {response}");
    assert!(response.contains(r#""anonymous_loopback":true"#), "响应: {response}");
    assert!(response.contains("Cache-Control: no-store"), "响应: {response}");
}

#[test]
fn version_names_the_engine() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/version");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""name":"lemonvpn""#), "响应: {response}");
    assert!(response.contains(r#""major":1"#), "响应: {response}");
}

#[test]
fn capabilities_advertise_only_what_the_engine_serves() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/capabilities");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""runtime":{"available":true}"#), "响应: {response}");
    assert!(response.contains(r#""traffic_history":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""datapath":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""connections":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""events":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""config":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""rules":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""flows":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""nodes":{"available":true"#), "响应: {response}");
    assert!(response.contains(r#""groups":{"available":true"#), "响应: {response}");
    assert!(!response.contains(r#""policies":"#), "未实现的能力不应被声明: {response}");
}

#[test]
fn nodes_and_groups_come_from_the_source_file() {
    let engine = Engine::start_with(Some(
        "node {\n  edge: 'socks5://10.0.0.2:1080'\n}\n\
         group {\n  proxy {\n    filter: name('edge')\n    policy: fixed(0)\n  }\n}\n\
         routing {\n  fallback: proxy\n}\n",
    ));

    let nodes = engine.get("/api/v1/nodes");
    assert!(nodes.starts_with("HTTP/1.1 200"), "响应: {nodes}");
    assert!(nodes.contains(r#""id":"node-edge""#), "响应: {nodes}");
    assert!(nodes.contains(r#""name":"edge""#), "响应: {nodes}");
    assert!(nodes.contains(r#""protocol":"socks5""#), "响应: {nodes}");
    assert!(nodes.contains(r#""group_ids":["group-proxy"]"#), "响应: {nodes}");

    let groups = engine.get("/api/v1/groups");
    assert!(groups.starts_with("HTTP/1.1 200"), "响应: {groups}");
    assert!(groups.contains(r#""id":"group-proxy""#), "响应: {groups}");
    assert!(groups.contains(r#""member_count":1"#), "响应: {groups}");
    assert!(
        groups.contains(r#""tcp_member_id":"node-edge""#),
        "响应: {groups}"
    );

    let group = engine.get("/api/v1/groups/group-proxy");
    assert!(group.starts_with("HTTP/1.1 200"), "响应: {group}");
    assert!(
        group.contains(r#""members":[{"id":"node-edge","name":"edge","kind":"node"}]"#),
        "响应: {group}"
    );
    assert!(group.contains(r#""can_select":false"#), "响应: {group}");
}

#[test]
fn a_probe_measures_the_node_and_records_health() {
    let echo = spawn_echo();
    let config = format!("node {{\n  edge: 'socks5://127.0.0.1:{echo}'\n}}\n");
    let engine = Engine::start_with(Some(config.as_str()));

    let accepted = engine.post(
        "/api/v1/probes",
        r#"{"target":{"type":"node","node_id":"node-edge"},"kind":"tcp_connect","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}"#,
    );
    assert!(accepted.starts_with("HTTP/1.1 202"), "响应: {accepted}");
    assert!(accepted.contains(r#""kind":"probe""#), "响应: {accepted}");
    assert!(accepted.contains(r#""status":"queued""#), "响应: {accepted}");
    assert!(
        accepted.contains("Location: /api/v1/operations/op-1"),
        "响应: {accepted}"
    );

    let operation = engine.get("/api/v1/operations/op-1");
    assert!(operation.starts_with("HTTP/1.1 200"), "响应: {operation}");
    assert!(
        operation.contains(r#""status":"succeeded""#),
        "响应: {operation}"
    );
    assert!(
        operation.contains(r#""target":{"type":"node","node_id":"node-edge"}"#),
        "响应: {operation}"
    );
    assert!(
        operation.contains(r#""state":"healthy""#),
        "响应: {operation}"
    );
    assert!(
        !operation.contains(r#""latency_ms":null"#),
        "响应: {operation}"
    );

    let nodes = engine.get("/api/v1/nodes");
    assert!(nodes.contains(r#""health":[{"#), "响应: {nodes}");
    assert!(nodes.contains(r#""ip_version":"ipv4""#), "响应: {nodes}");
    assert!(nodes.contains(r#""state":"healthy""#), "响应: {nodes}");
}

#[test]
fn an_http_probe_measures_a_request_through_the_node() {
    let echo = spawn_echo();
    let node = spawn_socks5(echo);
    let config = format!("node {{\n  edge: 'socks5://127.0.0.1:{node}'\n}}\n");
    let engine = Engine::start_with(Some(config.as_str()));

    let accepted = engine.post(
        "/api/v1/probes",
        r#"{"target":{"type":"node","node_id":"node-edge"},"kind":"http","transport":["tcp"],"ip_version":"ipv4","warmth":"warm"}"#,
    );
    assert!(accepted.starts_with("HTTP/1.1 202"), "响应: {accepted}");

    let operation = engine.get("/api/v1/operations/op-1");
    assert!(operation.contains(r#""state":"healthy""#), "响应: {operation}");
    assert!(operation.contains(r#""kind":"http""#), "响应: {operation}");
    assert!(operation.contains(r#""purpose":"data""#), "响应: {operation}");
}

#[test]
fn a_group_probe_runs_every_member() {
    let first = spawn_echo();
    let second = spawn_echo();
    let config = format!(
        "node {{\n  edge-a: 'socks5://127.0.0.1:{first}'\n  edge-b: 'socks5://127.0.0.1:{second}'\n}}\n\
         group {{\n  proxy {{\n    filter: name(keyword: 'edge')\n    policy: fixed(0)\n  }}\n}}\n"
    );
    let engine = Engine::start_with(Some(config.as_str()));

    let accepted = engine.post(
        "/api/v1/probes",
        r#"{"target":{"type":"group","group_id":"group-proxy"},"kind":"tcp_connect","transport":["tcp"],"ip_version":"ipv4","warmth":"warm","members":"direct"}"#,
    );
    assert!(accepted.starts_with("HTTP/1.1 202"), "响应: {accepted}");

    let mut operation = String::new();
    for _ in 0..100 {
        operation = engine.get("/api/v1/operations/op-1");
        if operation.contains(r#""status":"succeeded""#) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(operation.contains(r#""status":"succeeded""#), "响应: {operation}");
    assert!(
        operation.contains(r#""target":{"type":"group","group_id":"group-proxy"}"#),
        "响应: {operation}"
    );
    assert_eq!(operation.matches(r#""member_id":"#).count(), 2, "响应: {operation}");
    assert!(
        operation.contains(r#""selection_before":{"tcp":"node-edge-a","udp":null}"#),
        "响应: {operation}"
    );
    assert!(
        operation.contains(r#""selection_changed":{"tcp":false,"udp":false}"#),
        "响应: {operation}"
    );
}

#[test]
fn outbound_counters_follow_the_tunnel() {
    let echo = spawn_echo();
    let node = spawn_socks5(echo);
    let config = format!(
        "node {{\n  edge: 'socks5://127.0.0.1:{node}'\n}}\n\
         group {{\n  proxy {{\n    filter: name('edge')\n    policy: fixed(0)\n  }}\n}}\n\
         routing {{\n  fallback: proxy\n}}\n"
    );
    let engine = Engine::start_with(Some(config.as_str()));

    let mut client = engine.connect();
    client
        .write_all(b"CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "响应: {}",
        String::from_utf8_lossy(&response)
    );
    client.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).unwrap();
    drop(client);

    let outbounds = engine.get("/api/v1/runtime/outbounds");
    assert!(outbounds.starts_with("HTTP/1.1 200"), "响应: {outbounds}");
    assert!(outbounds.contains(r#""name":"proxy""#), "响应: {outbounds}");
    assert!(outbounds.contains(r#""kind":"group""#), "响应: {outbounds}");
    assert!(
        outbounds.contains(r#""total_connections":"1""#),
        "响应: {outbounds}"
    );
    assert!(
        outbounds.contains(r#""download_bytes":"4""#),
        "响应: {outbounds}"
    );
}

#[test]
fn memory_history_reports_process_memory() {
    let engine = Engine::start();
    let mut response = String::new();
    for _ in 0..100 {
        response = engine.get("/api/v1/runtime/memory/history?window_seconds=60&max_points=10");
        if response.contains(r#""rss_bytes":""#) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""samples":[{"#), "响应: {response}");
    if cfg!(windows) || cfg!(target_os = "linux") {
        assert!(response.contains(r#""rss_bytes":""#), "响应: {response}");
    }
}

#[test]
fn a_config_source_replacement_reloads_and_checks_the_revision() {
    let engine = Engine::start_with(Some("# old\nrouting {\n  fallback: direct\n}\n"));
    let config = engine.get("/api/v1/config");
    let sha = config
        .split(r#""content_sha256":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("content_sha256")
        .to_owned();

    let content = "# new\nrouting {\n  fallback: block\n}\n";
    let body = format!(
        r#"{{"content":"{}"}}"#,
        content
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    );
    let accepted = engine.put("/api/v1/config/sources/source-main", &sha, &body);
    assert!(accepted.starts_with("HTTP/1.1 202"), "响应: {accepted}");
    assert!(accepted.contains(r#""kind":"reload""#), "响应: {accepted}");

    let operation = engine.get("/api/v1/operations/op-1");
    assert!(operation.contains(r#""kind":"reload""#), "响应: {operation}");
    assert!(
        operation.contains(r#""status":"succeeded""#),
        "响应: {operation}"
    );

    let reloaded = engine.get("/api/v1/config");
    assert!(reloaded.contains("# new"), "响应: {reloaded}");
    assert!(!reloaded.contains("# old"), "响应: {reloaded}");

    let stale = engine.put("/api/v1/config/sources/source-main", &sha, &body);
    assert!(stale.starts_with("HTTP/1.1 412"), "响应: {stale}");
}

#[test]
fn an_operation_start_drains_a_json_body_before_answering() {
    // doona's starts client sends `{}`. The operation routes do not read it,
    // and closing a socket with unread bytes makes the client see a reset
    // instead of the 202 — the WebView reports that as "Failed to fetch".
    let engine = Engine::start_with(Some("routing {\n  fallback: direct\n}\n"));
    let accepted = engine.post("/api/v1/operations/reload", "{}");
    assert!(accepted.starts_with("HTTP/1.1 202"), "响应: {accepted}");
    assert!(accepted.contains(r#""kind":"reload""#), "响应: {accepted}");
}

#[test]
fn routing_through_a_socks5_node_reaches_the_origin() {
    let echo = spawn_echo();
    let node = spawn_socks5(echo);
    let config = format!(
        "node {{\n  edge: 'socks5://127.0.0.1:{node}'\n}}\n\
         group {{\n  proxy {{\n    filter: name('edge')\n    policy: fixed(0)\n  }}\n}}\n\
         routing {{\n  domain(full: example.test) -> proxy\n  fallback: direct\n}}\n"
    );
    let engine = Engine::start_with(Some(config.as_str()));

    let mut client = engine.connect();
    client
        .write_all(
            format!("CONNECT example.test:{echo} HTTP/1.1\r\nHost: example.test\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "响应: {}",
        String::from_utf8_lossy(&response)
    );

    client.write_all(b"ping-through-node").unwrap();
    let mut echoed = vec![0u8; "ping-through-node".len()];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, b"ping-through-node");
    drop(client);

    let mut flows = String::new();
    for _ in 0..50 {
        flows = engine.get("/api/v1/flows");
        if flows.contains(r#""state":"closed""#) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(flows.contains(r#""outbound":"proxy""#), "响应: {flows}");
    assert!(flows.contains(r#""chain":["edge"]"#), "响应: {flows}");
}

#[test]
fn config_and_rules_come_from_the_source_file() {
    let engine = Engine::start_with(Some(
        "# test source\nrouting {\n  domain(suffix: example.test) -> block\n  fallback: direct\n}\n",
    ));

    let config = engine.get("/api/v1/config");
    assert!(config.starts_with("HTTP/1.1 200"), "响应: {config}");
    assert!(config.contains(r#""kind":"main""#), "响应: {config}");
    assert!(config.contains(r#""writable":true"#), "响应: {config}");
    assert!(!config.contains("read_only_reason"), "响应: {config}");
    assert!(config.contains("domain(suffix: example.test)"), "响应: {config}");
    assert!(config.contains(r#""generation_id":"generation-"#), "响应: {config}");
    let digest = config
        .split(r#""content_sha256":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("content_sha256");
    assert_eq!(digest.len(), 64, "摘要: {digest}");
    assert!(
        digest.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "摘要不是小写十六进制: {digest}"
    );

    let rules = engine.get("/api/v1/rules");
    assert!(rules.starts_with("HTTP/1.1 200"), "响应: {rules}");
    assert!(rules.contains(r#""rule_id":"traffic:0""#), "响应: {rules}");
    assert!(
        rules.contains(r#""expression":"domain(suffix: example.test) -> block""#),
        "响应: {rules}"
    );
    assert!(rules.contains(r#""kind":"fallback""#), "响应: {rules}");
    assert!(rules.contains(r#""outbound":"direct""#), "响应: {rules}");
}

#[test]
fn routing_rules_block_a_matching_connect_without_dialing() {
    let engine = Engine::start_with(Some(
        "routing {\n  domain(full: example.test) -> block\n  fallback: direct\n}\n",
    ));
    let mut client = engine.connect();
    client
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let response = read_all(&mut client);
    assert!(response.starts_with("HTTP/1.1 403"), "响应: {response}");

    let flows = engine.get("/api/v1/flows");
    assert!(flows.starts_with("HTTP/1.1 200"), "响应: {flows}");
    assert!(flows.contains(r#""state":"blocked""#), "响应: {flows}");
    assert!(flows.contains(r#""outbound":"block""#), "响应: {flows}");
    assert!(
        flows.contains(r#""rule_expression":"domain(full: example.test) -> block""#),
        "响应: {flows}"
    );
}

#[test]
fn flows_record_the_tunnel_decision_and_close() {
    let engine = Engine::start_with(Some(
        "routing {\n  domain(full: localhost) -> direct\n  fallback: block\n}\n",
    ));
    let echo = spawn_echo();
    let mut client = engine.connect();

    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x03, "localhost".len() as u8];
    request.extend_from_slice(b"localhost");
    request.extend_from_slice(&echo.to_be_bytes());
    client.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 连接被拒绝");

    let active = engine.get("/api/v1/flows");
    assert!(active.starts_with("HTTP/1.1 200"), "响应: {active}");
    assert!(active.contains(r#""state":"active""#), "响应: {active}");
    assert!(active.contains(r#""domain_source":"explicit""#), "响应: {active}");
    assert!(active.contains(r#""rule_id":"traffic:0""#), "响应: {active}");
    assert!(active.contains(r#""observed_by":"userspace""#), "响应: {active}");
    assert!(active.contains(r#""userspace_tcp":"full""#), "响应: {active}");

    let id = active
        .split(r#""id":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("flow id");
    let detail = engine.get(&format!("/api/v1/flows/{id}"));
    assert!(detail.starts_with("HTTP/1.1 200"), "响应: {detail}");
    assert!(detail.contains(r#""input""#), "响应: {detail}");
    assert!(
        detail.contains(&format!(r#""dst":"localhost:{echo}""#)),
        "响应: {detail}"
    );
    assert!(
        detail.contains(r#""trace":{"status":"disabled""#),
        "响应: {detail}"
    );
    assert!(
        engine.get("/api/v1/flows/flow-missing").starts_with("HTTP/1.1 404"),
        "未知 flow 应为 404"
    );

    drop(client);
    let mut closed = false;
    for _ in 0..40 {
        if engine
            .get("/api/v1/flows?state=closed")
            .contains(r#""state":"closed""#)
        {
            closed = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(closed, "关闭后的 flow 未进入 closed 状态");
}

#[test]
fn config_reloads_after_the_source_changes() {
    let engine = Engine::start_with(Some("routing {\n  fallback: direct\n}\n"));
    assert!(!engine.get("/api/v1/rules").contains("reloaded.test"));

    fs::write(
        engine.data_dir.join("config.dae"),
        "routing {\n  domain(full: reloaded.test) -> block\n  fallback: direct\n}\n",
    )
    .unwrap();

    let rules = engine.get("/api/v1/rules");
    assert!(rules.contains("reloaded.test"), "响应: {rules}");
    let config = engine.get("/api/v1/config");
    assert!(config.contains("reloaded.test"), "响应: {config}");
}

#[test]
fn flows_reject_filters_the_engine_does_not_apply() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/flows?network=sctp");
    assert!(response.starts_with("HTTP/1.1 400"), "响应: {response}");
    let response = engine.get("/api/v1/flows?cursor=abc");
    assert!(response.starts_with("HTTP/1.1 422"), "响应: {response}");
}

#[test]
fn runtime_reports_a_running_userspace_engine() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/runtime");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""lifecycle":{"state":"running""#), "响应: {response}");
    assert!(response.contains(r#""uptime_seconds":""#), "响应: {response}");
    assert!(response.contains(r#""datapath":{"kind":"userspace","state":"active""#), "响应: {response}");
    assert!(response.contains(r#""bytes":{"upload":""#), "响应: {response}");
}

#[test]
fn unknown_api_route_is_a_contract_404() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/nope");
    assert!(response.starts_with("HTTP/1.1 404"), "响应: {response}");
    assert!(response.contains(r#""code":"resource_not_found""#), "响应: {response}");
    assert!(response.contains(r#""request_id":null"#), "响应: {response}");
}

#[test]
fn api_rejects_writes() {
    let engine = Engine::start();
    let response = engine.request("POST", "/api/v1/runtime");
    assert!(response.starts_with("HTTP/1.1 405"), "响应: {response}");
    assert!(response.contains(r#""code":"method_not_allowed""#), "响应: {response}");
}

#[test]
fn traffic_history_rejects_a_window_above_the_limit() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/runtime/traffic/history?window_seconds=601");
    assert!(response.starts_with("HTTP/1.1 400"), "响应: {response}");
    assert!(response.contains(r#""code":"invalid_request""#), "响应: {response}");
}

#[test]
fn traffic_history_starts_empty_and_then_records() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/runtime/traffic/history?window_seconds=60&max_points=60");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(response.contains(r#""window_seconds":60"#), "响应: {response}");

    thread::sleep(Duration::from_millis(2_400));
    let response = engine.get("/api/v1/runtime/traffic/history?window_seconds=60&max_points=60");
    assert!(response.contains(r#""samples":[{"#), "采样器未记录: {response}");
    assert!(response.contains(r#""sampled_every_seconds":1"#), "响应: {response}");
}

#[test]
fn proxied_traffic_reaches_the_runtime_snapshot() {
    let engine = Engine::start();
    let echo = spawn_echo();
    let mut client = engine.connect();

    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).unwrap();
    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&echo.to_be_bytes());
    client.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 连接被拒绝");

    client.write_all(b"count-me").unwrap();
    let mut echoed = [0u8; 8];
    client.read_exact(&mut echoed).unwrap();
    drop(client);

    let response = engine.get("/api/v1/runtime");
    assert!(uint_field(&response, "upload") >= 8, "上传未计数: {response}");
    assert!(uint_field(&response, "download") >= 8, "下载未计数: {response}");
}

#[test]
fn absolute_form_request_is_forwarded_as_origin_form() {
    let engine = Engine::start();
    let origin = spawn_http();
    let mut client = engine.connect();

    client
        .write_all(
            format!(
                "GET http://127.0.0.1:{origin}/hello?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

    let response = read_all(&mut client);
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(
        response.contains("GET /hello?x=1 HTTP/1.1"),
        "上游收到的请求行: {response}"
    );
    assert!(
        !response.contains("http://127.0.0.1"),
        "绝对 URI 未被改写: {response}"
    );

    let runtime = engine.get("/api/v1/runtime");
    assert!(
        uint_field(&runtime, "upload") >= 40,
        "请求头字节未计入上传: {runtime}"
    );
}
