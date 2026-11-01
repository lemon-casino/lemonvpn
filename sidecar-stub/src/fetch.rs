//! A small blocking HTTP/1.1 client for subscription downloads.
//!
//! Only what a subscription URL needs: GET, redirects, `Content-Length` and
//! chunked bodies, and TLS through rustls with the platform-independent
//! Mozilla root set. The connection is dialed through [`crate::proxy::dial`],
//! so the engine's DNS upstreams apply.

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(15);

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct Url {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

/// Downloads `url`. A response with a non-2xx status is returned, not treated
/// as a transport failure, so the caller can report the server's answer.
pub fn get(url: &str, user_agent: &str, max_bytes: usize) -> Result<Response, String> {
    let mut url = parse_url(url)?;
    for _ in 0..=MAX_REDIRECTS {
        let response = once(&url, user_agent, max_bytes)?;
        let redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
        let Some(location) = response.header("location").map(str::to_owned) else {
            return Ok(response);
        };
        if !redirect {
            return Ok(response);
        }
        url = resolve(&url, &location)?;
    }
    Err("订阅地址重定向次数过多".to_owned())
}

fn parse_url(url: &str) -> Result<Url, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "订阅地址缺少 scheme".to_owned())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("不支持的订阅地址 scheme `{scheme}`"));
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let (host, port) = split_host_port(authority)?;
    Ok(Url {
        port: port.unwrap_or(if scheme == "https" { 443 } else { 80 }),
        scheme,
        host,
        path: path.to_owned(),
    })
}

fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "订阅地址的 IPv6 缺少 `]`".to_owned())?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse::<u16>().map_err(|_| "订阅地址端口无效".to_owned())?),
            None => None,
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((
            host.to_owned(),
            Some(port.parse::<u16>().map_err(|_| "订阅地址端口无效".to_owned())?),
        )),
        Some(_) => Err("订阅地址缺少主机名".to_owned()),
        None => {
            if authority.is_empty() {
                return Err("订阅地址缺少主机名".to_owned());
            }
            Ok((authority.to_owned(), None))
        }
    }
}

fn resolve(base: &Url, location: &str) -> Result<Url, String> {
    let location = location.trim();
    if location.contains("://") {
        return parse_url(location);
    }
    let scheme = base.scheme.clone();
    if let Some(rest) = location.strip_prefix("//") {
        return parse_url(&format!("{scheme}://{rest}"));
    }
    let path = if location.starts_with('/') {
        location.to_owned()
    } else {
        let directory = base.path.rsplit_once('/').map_or("/", |(directory, _)| directory);
        format!("{directory}/{location}")
    };
    Ok(Url {
        scheme,
        host: base.host.clone(),
        port: base.port,
        path,
    })
}

fn once(url: &Url, user_agent: &str, max_bytes: usize) -> Result<Response, String> {
    let stream = crate::proxy::dial(&url.host, url.port)
        .map_err(|error| format!("连接订阅服务器失败：{error}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|error| error.to_string())?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path,
        host_header(url),
        user_agent,
    );
    if url.scheme == "https" {
        let server_name = ServerName::try_from(url.host.clone())
            .map_err(|_| format!("订阅地址主机名无效：{}", url.host))?;
        let connection = ClientConnection::new(tls_config().clone(), server_name)
            .map_err(|error| format!("TLS 初始化失败：{error}"))?;
        let mut stream = StreamOwned::new(connection, stream);
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("发送订阅请求失败：{error}"))?;
        stream.flush().map_err(|error| error.to_string())?;
        read_response(&mut stream, max_bytes)
    } else {
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("发送订阅请求失败：{error}"))?;
        stream.flush().map_err(|error| error.to_string())?;
        read_response(&mut stream, max_bytes)
    }
}

fn host_header(url: &Url) -> String {
    let default = if url.scheme == "https" { 443 } else { 80 };
    if url.port == default {
        if url.host.contains(':') {
            format!("[{}]", url.host)
        } else {
            url.host.clone()
        }
    } else if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

fn tls_config() -> &'static Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
}

fn read_response(stream: &mut dyn Read, max_bytes: usize) -> Result<Response, String> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEADER_BYTES {
        if stream.read(&mut byte).map_err(|error| format!("读取订阅响应失败：{error}"))? == 0 {
            return Err("订阅服务器在响应头结束前关闭了连接".to_owned());
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !head.ends_with(b"\r\n\r\n") {
        return Err("订阅响应头超过大小上限".to_owned());
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "订阅响应状态行无效".to_owned())?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };

    let chunked = header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        read_chunked(stream, max_bytes)?
    } else if let Some(length) = header("content-length").and_then(|value| value.parse::<usize>().ok()) {
        if length > max_bytes {
            return Err(format!("订阅内容超过 {max_bytes} 字节上限"));
        }
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .map_err(|error| format!("读取订阅内容失败：{error}"))?;
        body
    } else {
        let mut body = Vec::new();
        stream
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("读取订阅内容失败：{error}"))?;
        if body.len() > max_bytes {
            return Err(format!("订阅内容超过 {max_bytes} 字节上限"));
        }
        body
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

fn read_chunked(stream: &mut dyn Read, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = read_line(stream)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| "订阅响应的分块长度无效".to_owned())?;
        if size == 0 {
            // Trailing headers, ended by an empty line.
            loop {
                if read_line(stream)?.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len() + size > max_bytes {
            return Err(format!("订阅内容超过 {max_bytes} 字节上限"));
        }
        let mut chunk = vec![0u8; size];
        stream
            .read_exact(&mut chunk)
            .map_err(|error| format!("读取订阅内容失败：{error}"))?;
        body.extend_from_slice(&chunk);
        let _ = read_line(stream)?;
    }
    Ok(body)
}

fn read_line(stream: &mut dyn Read) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 1024 {
        if stream.read(&mut byte).map_err(|error| error.to_string())? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// The `subscription-userinfo` values some providers send, in bytes and Unix
/// seconds. Missing or zero quantities stay `None`.
pub struct UserInfo {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
}

pub fn user_info(response: &Response) -> Option<UserInfo> {
    let value = response.header("subscription-userinfo")?;
    let mut info = UserInfo {
        upload: None,
        download: None,
        total: None,
        expire: None,
    };
    for pair in value.split(';') {
        let Some((key, value)) = pair.split_once('=') else { continue };
        let number = value.trim().parse::<u64>().ok().filter(|value| *value > 0);
        match key.trim() {
            "upload" => info.upload = number,
            "download" => info.download = number,
            "total" => info.total = number,
            "expire" => info.expire = number,
            _ => {}
        }
    }
    Some(info)
}
