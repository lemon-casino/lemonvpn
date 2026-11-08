//! HTTP side of the mixed inbound: health endpoint, CONNECT tunnels and
//! absolute-form forwarding (what a system proxy sends for plain HTTP).

use std::io::{self, Write};
use std::net::TcpStream;

use crate::api;
use crate::config;
use crate::control;
use crate::flows;
use crate::logs;
use crate::proxy;
use crate::state;

pub fn handle(mut client: TcpStream) -> io::Result<()> {
    let headers = proxy::read_headers(&mut client)?;
    let text = String::from_utf8_lossy(&headers).into_owned();
    let request_line = text.split("\r\n").next().unwrap_or("").to_string();

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method.is_empty() || target.is_empty() {
        return respond(&mut client, 400, r#"{"error":"bad_request"}"#);
    }

    if method == "GET" && path_of(&target) == "/health" {
        return respond(&mut client, 200, &health());
    }

    // The desktop WebView runs on its own origin, so its API calls are
    // cross-origin: preflights are answered here and every API response carries
    // the matching allow-origin header.
    let cors = cors_headers(&text);
    if method == "OPTIONS"
        && target.starts_with('/')
        && is_api_path(path_of(&target))
        && !cors.is_empty()
    {
        return preflight(&mut client, &cors);
    }

    // The native API is this listener's own; only origin-form requests address
    // it, so an absolute URI for another host keeps going to that host.
    if target.starts_with('/') {
        let path = path_of(&target);
        if is_api_path(path) {
            return api::handle(client, &method, &target, &text, &cors);
        }
    }

    // A suspended datapath keeps serving the API above, but refuses new
    // tunnels; resume stays reachable on the same listener.
    if control::suspended() {
        return respond(&mut client, 503, r#"{"error":"engine_suspended"}"#);
    }

    // Everything past the API and health branches is proxied traffic. Logging
    // the UI's own polling here would crowd the bounded log ring with
    // self-traffic, so only the proxy's inbound connections are recorded.
    logs::debug(
        "engine::inbound",
        "Inbound connection accepted.",
        Some(logs::fields(&[("protocol", "http")])),
    );

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = proxy::parse_authority(&target, 443) else {
            return respond(&mut client, 400, r#"{"error":"bad_connect_target"}"#);
        };
        let peer = client.peer_addr().ok();
        let decision = config::decide_connection(&host, port, peer, "tcp");
        let domain = domain_of(&host);
        let domain_source = domain.map(|_| "explicit");
        if decision.blocked() {
            if let Some(peer) = peer {
                flows::blocked(peer, &host, port, domain, domain_source, &decision);
            }
            return respond(&mut client, 403, r#"{"error":"blocked_by_rule"}"#);
        }
        let flow =
            peer.map(|peer| flows::begin(peer, &host, port, domain, domain_source, &decision));
        let upstream = match proxy::connect(&decision, &host, port) {
            Ok(stream) => stream,
            Err(err) => {
                if let Some(flow) = flow {
                    flow.finish("failed");
                }
                log_dial_failure("http-connect", &err);
                return respond(
                    &mut client,
                    502,
                    &format!(r#"{{"error":"connect_failed","detail":"{err}"}}"#),
                );
            }
        };
        logs::info(
            "engine::tunnel",
            "Tunnel established.",
            Some(logs::fields(&[("via", "http-connect")])),
        );
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        client.flush()?;
        return proxy::tunnel(client, upstream, flow, &decision, (&host, port));
    }

    let Some((host, port, path)) = split_absolute(&target) else {
        return respond(&mut client, 400, r#"{"error":"absolute_uri_required"}"#);
    };
    let peer = client.peer_addr().ok();
    let decision = config::decide_connection(&host, port, peer, "tcp");
    let domain = domain_of(&host);
    let domain_source = domain.map(|_| "http_host");
    if decision.blocked() {
        if let Some(peer) = peer {
            flows::blocked(peer, &host, port, domain, domain_source, &decision);
        }
        return respond(&mut client, 403, r#"{"error":"blocked_by_rule"}"#);
    }
    let flow = peer.map(|peer| flows::begin(peer, &host, port, domain, domain_source, &decision));
    let upstream = match proxy::connect(&decision, &host, port) {
        Ok(stream) => stream,
        Err(err) => {
            if let Some(flow) = flow {
                flow.finish("failed");
            }
            log_dial_failure("http-forward", &err);
            return respond(
                &mut client,
                502,
                &format!(r#"{{"error":"connect_failed","detail":"{err}"}}"#),
            );
        }
    };
    logs::info(
        "engine::tunnel",
        "Tunnel established.",
        Some(logs::fields(&[("via", "http-forward")])),
    );

    // Origin-form for the upstream; everything after the request line is
    // forwarded untouched, including the body still sitting in the socket.
    let rewritten = format!("{method} {path} {version}\r\n");
    let rest = &headers[request_line.len() + 2..];
    let mut request = Vec::with_capacity(rewritten.len() + rest.len());
    request.extend_from_slice(rewritten.as_bytes());
    request.extend_from_slice(rest);

    let mut upstream_write = upstream.try_clone()?;
    upstream_write.write_all(&request)?;
    upstream_write.flush()?;
    drop(upstream_write);
    // The request line and headers never pass through the counted tunnel, so
    // charge them here; a body still in the socket is counted by the tunnel.
    state::add_upload(request.len() as u64);

    proxy::tunnel(client, upstream, flow, &decision, (&host, port))
}

/// A target is a domain only when it is not already an IP literal; the flow
/// record must not claim a domain source for an address.
fn domain_of(host: &str) -> Option<&str> {
    host.parse::<std::net::IpAddr>().is_err().then_some(host)
}

pub(crate) fn path_of(target: &str) -> &str {
    let without_query = target.split('?').next().unwrap_or("");
    match without_query.find("://") {
        Some(index) => match without_query[index + 3..].find('/') {
            Some(slash) => &without_query[index + 3 + slash..],
            None => "/",
        },
        None => without_query,
    }
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// First value of a header, matched case-insensitively; the request line is
/// skipped and scanning stops at the blank line that ends the headers.
pub(crate) fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
}

/// The only cross-origin caller is the shell's own WebView, whose origin is
/// fixed per platform. Any other origin keeps the browser's default deny.
pub(crate) fn cors_headers(headers: &str) -> String {
    const DESKTOP_ORIGINS: [&str; 3] = [
        "http://tauri.localhost",
        "https://tauri.localhost",
        "tauri://localhost",
    ];
    match header_value(headers, "Origin") {
        Some(origin) if DESKTOP_ORIGINS.contains(&origin) => {
            format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n")
        }
        _ => String::new(),
    }
}

fn split_absolute(target: &str) -> Option<(String, u16, String)> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = proxy::parse_authority(authority, 80)?;
    Some((host, port, path.to_string()))
}

/// Health carries the process identity so the shell can tell its own engine
/// from whatever else may be holding the port.
fn health() -> String {
    let pid = std::process::id();
    format!(r#"{{"status":"ok","instance":"lemonvpn-{pid}","pid":{pid}}}"#)
}

fn respond(client: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    respond_with(client, status, body, "")
}

fn log_dial_failure(via: &str, err: &io::Error) {
    let kind = format!("{:?}", err.kind());
    logs::warn(
        "engine::tunnel",
        "Tunnel dial failed.",
        Some(logs::fields(&[("via", via), ("kind", &kind)])),
    );
}

/// Answers a CORS preflight for the API. `Last-Event-ID`, `Authorization` and
/// `Idempotency-Key` are not simple headers, so the log stream, authenticated
/// calls and operation starts need it.
fn preflight(client: &mut TcpStream, cors: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 204 No Content\r\n{cors}Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, Idempotency-Key, If-Match, Last-Event-ID\r\nAccess-Control-Max-Age: 600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    client.write_all(response.as_bytes())?;
    client.flush()
}

pub(crate) fn respond_with(
    client: &mut TcpStream,
    status: u16,
    body: &str,
    extra: &str,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes())?;
    client.flush()
}

#[cfg(test)]
mod tests {
    use super::{cors_headers, path_of, split_absolute};

    #[test]
    fn health_path_is_recognised_in_both_forms() {
        assert_eq!(path_of("/health"), "/health");
        assert_eq!(path_of("/health?probe=1"), "/health");
        assert_eq!(path_of("http://127.0.0.1:18080/health"), "/health");
        assert_eq!(path_of("http://127.0.0.1:18080"), "/");
        assert_eq!(path_of("/healthz"), "/healthz");
    }

    #[test]
    fn splits_absolute_targets() {
        assert_eq!(
            split_absolute("http://example.com/a?b=1"),
            Some(("example.com".to_string(), 80, "/a?b=1".to_string()))
        );
        assert_eq!(
            split_absolute("http://example.com:8080"),
            Some(("example.com".to_string(), 8080, "/".to_string()))
        );
        assert_eq!(split_absolute("/relative"), None);
        assert_eq!(split_absolute("https://example.com/"), None);
    }

    #[test]
    fn cors_is_granted_only_to_the_shell_origins() {
        let shell = "GET /api/v1/runtime HTTP/1.1\r\nOrigin: http://tauri.localhost\r\n\r\n";
        assert_eq!(
            cors_headers(shell),
            "Access-Control-Allow-Origin: http://tauri.localhost\r\nVary: Origin\r\n"
        );
        let foreign = "GET /api/v1/runtime HTTP/1.1\r\nOrigin: https://example.com\r\n\r\n";
        assert_eq!(cors_headers(foreign), "");
        assert_eq!(cors_headers("GET /api/v1/runtime HTTP/1.1\r\n\r\n"), "");
    }
}
