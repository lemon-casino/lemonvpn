//! End-to-end checks for the resumable log stream: SSE framing, replay,
//! cursor expiry, level filtering and the advertised capabilities.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct Engine {
    child: Child,
    port: u16,
}

impl Engine {
    fn start() -> Engine {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lemonvpn-engine-stub"))
            .env("LEMONVPN_ENGINE_PORT", "0")
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

        Engine { child, port }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("连接引擎");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    fn get(&self, path: &str) -> String {
        self.get_with(path, None)
    }

    fn get_with(&self, path: &str, last_event_id: Option<&str>) -> String {
        let mut client = self.connect();
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(id) = last_event_id {
            request.push_str(&format!("Last-Event-ID: {id}\r\n"));
        }
        request.push_str("\r\n");
        client.write_all(request.as_bytes()).unwrap();
        let mut text = String::new();
        let _ = client.read_to_string(&mut text);
        text
    }

    fn logs(&self, query: &str, last_event_id: Option<&str>) -> TcpStream {
        let mut client = self.connect();
        let mut request = format!(
            "GET /api/v1/logs{query} HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n"
        );
        if let Some(id) = last_event_id {
            request.push_str(&format!("Last-Event-ID: {id}\r\n"));
        }
        request.push_str("\r\n");
        client.write_all(request.as_bytes()).unwrap();
        client
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct Frame {
    id: Option<String>,
    event: String,
    data: String,
}

fn read_headers(client: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// One SSE frame; comments (heartbeats) are skipped without ending the frame.
fn next_frame(reader: &mut impl BufRead) -> Option<Frame> {
    let mut id = None;
    let mut event = String::new();
    let mut data = String::new();
    let mut seen = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            if seen {
                return Some(Frame { id, event, data });
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("id: ") {
            id = Some(rest.to_string());
            seen = true;
        } else if let Some(rest) = line.strip_prefix("event: ") {
            event = rest.to_string();
            seen = true;
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data = rest.to_string();
            seen = true;
        }
    }
}

fn open_stream(
    engine: &Engine,
    query: &str,
    last_event_id: Option<&str>,
) -> (BufReader<TcpStream>, Frame) {
    let mut client = engine.logs(query, last_event_id);
    let head = read_headers(&mut client);
    assert!(head.starts_with("HTTP/1.1 200"), "响应头: {head}");
    assert!(
        head.contains("Content-Type: text/event-stream"),
        "响应头: {head}"
    );
    assert!(head.contains("Cache-Control: no-store"), "响应头: {head}");
    assert!(
        head.contains("X-Content-Type-Options: nosniff"),
        "响应头: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("content-length"),
        "SSE 不应有 Content-Length: {head}"
    );

    let mut reader = BufReader::new(client);
    let ready = next_frame(&mut reader).expect("缺少 stream.ready");
    assert_eq!(
        ready.event, "stream.ready",
        "首帧不是 stream.ready: {ready:?}"
    );
    assert!(ready.id.is_some(), "stream.ready 缺少 id");
    assert!(
        ready.data.contains("\"instance_id\":\"lemonvpn-"),
        "ready data: {}",
        ready.data
    );
    assert!(
        ready.data.contains("\"observed_at\":\""),
        "ready data: {}",
        ready.data
    );
    (reader, ready)
}

fn assert_log_frame(frame: &Frame) {
    assert_eq!(frame.event, "log", "帧不是 log: {frame:?}");
    assert!(frame.id.is_some(), "log 帧缺少 id");
    for key in [
        "\"ts\":",
        "\"level\":",
        "\"target\":",
        "\"message\":",
        "\"fields\":",
    ] {
        assert!(
            frame.data.contains(key),
            "LogRecord 缺少 {key}: {}",
            frame.data
        );
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

#[test]
fn the_stream_starts_with_ready_then_a_log_record() {
    let engine = Engine::start();
    let (mut reader, ready) = open_stream(&engine, "", None);
    assert!(
        ready.data.contains(&format!(
            "\"instance_id\":\"lemonvpn-{}\"",
            engine.pid()
        )),
        "ready data: {}",
        ready.data
    );

    let startup = next_frame(&mut reader).expect("缺少回放的启动记录");
    assert_log_frame(&startup);
    assert!(
        startup.data.contains("\"level\":\"info\""),
        "启动记录应为 info: {}",
        startup.data
    );
    assert!(
        startup.data.contains("\"target\":\"engine::listener\""),
        "首条回放记录应来自监听器: {}",
        startup.data
    );
    assert!(
        startup
            .data
            .contains("\"message\":\"Engine listener bound on loopback.\""),
        "启动记录内容: {}",
        startup.data
    );
    assert_ne!(
        startup.id, ready.id,
        "回放记录的 id 应在 ready 的基线之后"
    );

    let live = next_frame(&mut reader).expect("缺少实时 log 帧");
    assert_log_frame(&live);
    assert!(
        live.data.contains("\"target\":\"engine::logs\""),
        "实时记录应来自日志流: {}",
        live.data
    );
    assert!(
        live.data.contains("\"message\":\"Log stream opened.\""),
        "实时记录内容: {}",
        live.data
    );
    assert_ne!(live.id, startup.id);
}

#[test]
fn a_tunnel_event_reaches_the_stream() {
    let engine = Engine::start();
    let (mut reader, _) = open_stream(&engine, "?level=info", None);

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
    client.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).unwrap();

    let mut found = false;
    for _ in 0..10 {
        let Some(frame) = next_frame(&mut reader) else {
            break;
        };
        if frame.event == "log" && frame.data.contains("\"message\":\"Tunnel established.\"") {
            assert_log_frame(&frame);
            assert!(
                frame.data.contains("\"via\":\"socks5\""),
                "隧道记录缺少来源: {}",
                frame.data
            );
            found = true;
            break;
        }
    }
    assert!(found, "流中没有隧道建立记录");
}

#[test]
fn resume_replays_records_strictly_after_the_cursor() {
    let engine = Engine::start();
    let (mut first, ready) = open_stream(&engine, "", None);
    let baseline = ready.id.clone().expect("ready id");
    let startup = next_frame(&mut first).expect("缺少启动记录");
    assert_log_frame(&startup);
    let opened = next_frame(&mut first).expect("缺少实时记录");
    assert_log_frame(&opened);
    drop(first);

    let (mut second, resumed) = open_stream(&engine, "", Some(&baseline));
    assert_eq!(
        resumed.id.as_deref(),
        Some(baseline.as_str()),
        "恢复时 ready 应回显游标，不能跳过待回放记录"
    );

    let replay_startup = next_frame(&mut second).expect("缺少回放的启动记录");
    assert_eq!(
        replay_startup.id, startup.id,
        "回放应从游标之后的第一条记录开始"
    );
    let replay_opened = next_frame(&mut second).expect("缺少回放的日志流记录");
    assert_eq!(replay_opened.id, opened.id);

    let live = next_frame(&mut second).expect("缺少新的实时记录");
    assert_log_frame(&live);
    assert_ne!(live.id.as_deref(), opened.id.as_deref());
}

#[test]
fn bad_cursors_and_filters_fail_before_the_stream_opens() {
    let engine = Engine::start();
    let unknown = format!("lemonvpn-{}:logs:all:999999", engine.pid());
    let response = engine.get_with("/api/v1/logs", Some(&unknown));
    assert!(response.starts_with("HTTP/1.1 409"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"event_cursor_expired\""),
        "响应: {response}"
    );
    assert!(
        !response.contains("text/event-stream"),
        "游标过期时不应打开流: {response}"
    );

    let response = engine.get_with("/api/v1/logs", Some("bogus"));
    assert!(response.starts_with("HTTP/1.1 409"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"event_cursor_expired\""),
        "响应: {response}"
    );

    let response = engine.get_with("/api/v1/logs", Some(""));
    assert!(response.starts_with("HTTP/1.1 409"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"event_cursor_expired\""),
        "响应: {response}"
    );

    let response = engine.get("/api/v1/logs?level=bogus");
    assert!(response.starts_with("HTTP/1.1 400"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"invalid_request\""),
        "响应: {response}"
    );

    let response = engine.get("/api/v1/logs?level=trace");
    assert!(response.starts_with("HTTP/1.1 422"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"unsupported_value\""),
        "响应: {response}"
    );

    let response = engine.get("/api/v1/logs?target=engine");
    assert!(response.starts_with("HTTP/1.1 422"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"unsupported_value\""),
        "响应: {response}"
    );
}

#[test]
fn a_changed_filter_rejects_the_cursor() {
    let engine = Engine::start();
    let (_, ready) = open_stream(&engine, "", None);
    let baseline = ready.id.expect("ready id");
    let response = engine.get_with("/api/v1/logs?level=info", Some(&baseline));
    assert!(response.starts_with("HTTP/1.1 409"), "响应: {response}");
    assert!(
        response.contains("\"code\":\"event_cursor_expired\""),
        "响应: {response}"
    );
}

#[test]
fn a_minimum_level_hides_lower_severity_records() {
    let engine = Engine::start();
    let (mut reader, _) = open_stream(&engine, "?level=error", None);
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(750)))
        .unwrap();
    assert!(
        next_frame(&mut reader).is_none(),
        "error 级别不应收到 info 记录"
    );
}

#[test]
fn capabilities_advertise_the_log_stream() {
    let engine = Engine::start();
    let response = engine.get("/api/v1/capabilities");
    assert!(response.starts_with("HTTP/1.1 200"), "响应: {response}");
    assert!(
        response.contains(r#""logs":{"available":true"#),
        "响应: {response}"
    );
    assert!(
        response.contains(r#""levels":["debug","info","warn","error"]"#),
        "响应: {response}"
    );
    assert!(
        response.contains(r#""filters":["level"]"#),
        "响应: {response}"
    );
    assert!(
        response.contains(r#""retention_seconds":300"#),
        "响应: {response}"
    );
    assert!(
        response.contains(r#""max_buffered_records":256"#),
        "响应: {response}"
    );
    assert!(
        !response.contains(r#""target""#),
        "未实现的过滤器不应被声明: {response}"
    );
}

fn raw_request(engine: &Engine, request: &str) -> String {
    let mut client = engine.connect();
    client.write_all(request.as_bytes()).unwrap();
    let mut text = String::new();
    let _ = client.read_to_string(&mut text);
    text
}

#[test]
fn the_desktop_origin_is_allowed_and_others_are_not() {
    let engine = Engine::start();
    let allowed = raw_request(
        &engine,
        "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\nOrigin: http://tauri.localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        allowed.contains("Access-Control-Allow-Origin: http://tauri.localhost"),
        "响应: {allowed}"
    );
    assert!(allowed.contains("Vary: Origin"), "响应: {allowed}");

    let foreign = raw_request(
        &engine,
        "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\nConnection: close\r\n\r\n",
    );
    assert!(
        !foreign.contains("Access-Control-Allow-Origin"),
        "响应: {foreign}"
    );
}

#[test]
fn a_preflight_for_the_log_stream_is_answered() {
    let engine = Engine::start();
    let response = raw_request(
        &engine,
        "OPTIONS /api/v1/logs HTTP/1.1\r\nHost: localhost\r\nOrigin: http://tauri.localhost\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: last-event-id\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 204"), "响应: {response}");
    assert!(
        response.contains("Access-Control-Allow-Origin: http://tauri.localhost"),
        "响应: {response}"
    );
    assert!(response.contains("Last-Event-ID"), "响应: {response}");
    assert!(response.contains("Idempotency-Key"), "响应: {response}");
    assert!(response.contains("Content-Length: 0"), "响应: {response}");
}

#[test]
fn the_log_stream_carries_the_desktop_origin() {
    let engine = Engine::start();
    let mut client = engine.connect();
    client
        .write_all(
            b"GET /api/v1/logs HTTP/1.1\r\nHost: localhost\r\nOrigin: http://tauri.localhost\r\nAccept: text/event-stream\r\n\r\n",
        )
        .unwrap();
    let head = read_headers(&mut client);
    assert!(head.starts_with("HTTP/1.1 200"), "响应: {head}");
    assert!(
        head.contains("Access-Control-Allow-Origin: http://tauri.localhost"),
        "响应: {head}"
    );
}
