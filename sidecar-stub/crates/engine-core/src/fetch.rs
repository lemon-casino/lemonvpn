//! Bounded HTTP/1.1 downloads with verified TLS and explicit egress.
//! Retries restart a GET; incomplete TLS/HTTP bodies are never accepted as files.
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, TcpStream},
    sync::{Arc, OnceLock},
    time::Duration,
};
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(15);
const ATTEMPTS: usize = 2;
#[derive(Clone, Debug)]
pub(crate) enum DownloadRoute {
    Direct,
    Routing,
    Outbound(String),
}
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub download_outbound: Option<String>,
    pub fetched_url: String,
}
impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}
struct Failure {
    message: String,
    retryable: bool,
}
impl Failure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }
    fn io(stage: &str, error: io::Error) -> Self {
        let retryable = matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::TimedOut
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::NotConnected
        );
        Self {
            message: format!("{stage}：{error}"),
            retryable,
        }
    }
    fn closed(stage: &str) -> Self {
        Self {
            message: format!("{stage}：服务器提前关闭连接"),
            retryable: true,
        }
    }
}
pub fn get(url: &str, user_agent: &str, max_bytes: usize) -> Result<Response, String> {
    get_via(url, user_agent, max_bytes, "direct")
}
pub(crate) fn get_via(
    url: &str,
    user_agent: &str,
    max_bytes: usize,
    outbound: &str,
) -> Result<Response, String> {
    get_via_headers(url, user_agent, max_bytes, outbound, &BTreeMap::new())
}
pub(crate) fn get_via_headers(
    url: &str,
    user_agent: &str,
    max_bytes: usize,
    outbound: &str,
    headers: &BTreeMap<String, String>,
) -> Result<Response, String> {
    let route = if outbound == "direct" {
        DownloadRoute::Direct
    } else {
        DownloadRoute::Outbound(outbound.to_owned())
    };
    download(url, user_agent, max_bytes, &route, headers)
}
pub(crate) fn get_routed(
    url: &str,
    user_agent: &str,
    max_bytes: usize,
    route: &DownloadRoute,
) -> Result<Response, String> {
    download(url, user_agent, max_bytes, route, &BTreeMap::new())
}
pub(crate) fn valid_url(value: &str) -> Result<url::Url, String> {
    if value.len() > 8192 || value.chars().any(char::is_control) {
        return Err("下载地址过长或含控制字符".into());
    }
    let url = url::Url::parse(value).map_err(|_| "下载地址格式无效")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || url.fragment().is_some()
    {
        return Err("下载地址须为不含片段的 HTTP(S) URL".into());
    }
    Ok(url)
}
fn download(
    address: &str,
    user_agent: &str,
    max_bytes: usize,
    route: &DownloadRoute,
    headers: &BTreeMap<String, String>,
) -> Result<Response, String> {
    if user_agent.len() > 512
        || user_agent.contains(['\r', '\n', '\0'])
        || headers.len() > 32
        || headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            > 16384
    {
        return Err("下载请求头超过上限".into());
    }
    if headers.iter().any(|(key, value)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "accept-encoding"
        ) || key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.len() > 4096
            || value.contains(['\r', '\n', '\0'])
    }) {
        return Err("下载请求头无效".into());
    }
    let mut url = valid_url(address)?;
    let mut headers = headers.clone();
    if !url.username().is_empty() || url.password().is_some() {
        let user = crate::share::percent_decode(url.username());
        let password = crate::share::percent_decode(url.password().unwrap_or(""));
        headers.entry("Authorization".into()).or_insert_with(|| {
            format!(
                "Basic {}",
                crate::base64::encode(format!("{user}:{password}").as_bytes())
            )
        });
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    for redirects in 0..=MAX_REDIRECTS {
        let mut response = None;
        let mut failure = None;
        for attempt in 0..ATTEMPTS {
            if crate::runtime::stopping() {
                return Err("引擎正在退出，下载已取消".into());
            }
            match once(&url, user_agent, max_bytes, route, &headers, attempt) {
                Ok(value)
                    if matches!(value.status, 408 | 429 | 500 | 502 | 503 | 504)
                        && attempt + 1 < ATTEMPTS =>
                {
                    let delay = value
                        .header("retry-after")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(1)
                        .min(2);
                    std::thread::sleep(Duration::from_secs(delay));
                }
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(error) => {
                    let retry = error.retryable;
                    failure = Some(error.message);
                    if !retry || attempt + 1 == ATTEMPTS {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
        }
        let mut response = response.ok_or_else(|| {
            format!(
                "{}：{}",
                url.host_str().unwrap_or("下载服务器"),
                failure.unwrap_or_else(|| "下载失败".into())
            )
        })?;
        if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            response.fetched_url = url.to_string();
            return Ok(response);
        }
        if redirects == MAX_REDIRECTS {
            return Err("下载地址重定向次数超过上限".into());
        }
        let location = response
            .header("location")
            .ok_or("下载重定向缺少 Location")?;
        let next = url.join(location).map_err(|_| "下载重定向地址无效")?;
        let next = valid_url(next.as_str())?;
        if !next.username().is_empty() || next.password().is_some() {
            return Err("下载重定向不能引入认证信息".into());
        }
        if url.scheme() == "https" && next.scheme() != "https" {
            return Err("HTTPS 来源不能重定向到明文 HTTP".into());
        }
        if url.origin() != next.origin() {
            headers.retain(|k, _| {
                !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie")
            });
        }
        url = next;
    }
    Err("下载重定向次数超过上限".into())
}
fn direct(host: &str, port: u16, attempt: usize) -> io::Result<TcpStream> {
    let ips = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        crate::dns::resolve(host)?
    };
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "下载主机没有可用地址",
        ));
    }
    let mut error = io::Error::new(io::ErrorKind::NotConnected, "下载连接不可用");
    for index in 0..ips.len().min(8) {
        let ip = ips[(index + attempt) % ips.len()];
        match crate::proxy::dial(&ip.to_string(), port) {
            Ok(socket) => return Ok(socket),
            Err(e) => error = e,
        }
    }
    Err(error)
}
fn connect(
    route: &DownloadRoute,
    host: &str,
    port: u16,
    attempt: usize,
) -> io::Result<(TcpStream, Option<String>)> {
    match route {
        DownloadRoute::Direct => {
            direct(host, port, attempt).map(|socket| (socket, Some("direct".into())))
        }
        DownloadRoute::Routing => {
            let decision = crate::config::decide_connection(host, port, None, "tcp");
            let socket = if matches!(decision.target, crate::config::Target::Direct) {
                direct(host, port, attempt)
            } else {
                crate::proxy::connect(&decision, host, port)
            }?;
            Ok((socket, Some(decision.outbound)))
        }
        DownloadRoute::Outbound(name) => crate::config::connect_outbound(name, host, port)
            .map(|socket| (socket, Some(name.clone()))),
    }
}

fn once(
    url: &url::Url,
    user_agent: &str,
    max_bytes: usize,
    route: &DownloadRoute,
    headers: &BTreeMap<String, String>,
    attempt: usize,
) -> Result<Response, Failure> {
    let host = url.host_str().unwrap().trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Failure::invalid("下载端口无效"))?;
    let (mut socket, download_outbound) =
        connect(route, host, port, attempt).map_err(|e| Failure::io("连接下载服务器失败", e))?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| Failure::io("设置下载超时失败", e))?;
    socket
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Failure::io("设置下载超时失败", e))?;
    let mut target = url.path().to_string();
    if target.is_empty() {
        target.push('/')
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query)
    }
    let mut authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if let Some(port) = url.port() {
        authority.push_str(&format!(":{port}"))
    }
    let extra = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    let request=format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n{extra}\r\n");
    if url.scheme() == "https" {
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| Failure::invalid("下载 TLS 主机名无效"))?;
        let mut connection = ClientConnection::new(tls_config().clone(), name)
            .map_err(|e| Failure::invalid(format!("下载 TLS 初始化失败：{e}")))?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(|e| Failure::io("下载 TLS 握手失败", e))?;
        }
        let mut stream = StreamOwned::new(connection, socket);
        stream
            .write_all(request.as_bytes())
            .map_err(|e| Failure::io("发送下载请求失败", e))?;
        stream
            .flush()
            .map_err(|e| Failure::io("发送下载请求失败", e))?;
        let mut response = read_response(&mut stream, max_bytes)?;
        response.download_outbound = download_outbound;
        Ok(response)
    } else {
        socket
            .write_all(request.as_bytes())
            .map_err(|e| Failure::io("发送下载请求失败", e))?;
        socket
            .flush()
            .map_err(|e| Failure::io("发送下载请求失败", e))?;
        let mut response = read_response(&mut socket, max_bytes)?;
        response.download_outbound = download_outbound;
        Ok(response)
    }
}
pub(crate) fn tls_config() -> &'static Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    })
}
fn line(stream: &mut dyn Read, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut line = Vec::new();
    let mut byte = [0];
    while line.len() < limit {
        match stream.read(&mut byte) {
            Ok(0) => return Err(Failure::closed("读取下载响应失败")),
            Ok(_) => line.push(byte[0]),
            Err(e) => return Err(Failure::io("读取下载响应失败", e)),
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(Failure::invalid("下载响应行超过上限"))
}
fn read_response(stream: &mut dyn Read, max_bytes: usize) -> Result<Response, Failure> {
    for _ in 0..4 {
        let status_line = line(stream, MAX_HEADER_BYTES)?;
        let text = std::str::from_utf8(&status_line)
            .map_err(|_| Failure::invalid("下载响应状态行无效"))?;
        let mut status_parts = text.split_whitespace();
        if !matches!(status_parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
            return Err(Failure::invalid("下载服务器未返回 HTTP/1.x"));
        }
        let status = status_parts
            .next()
            .and_then(|v| v.parse::<u16>().ok())
            .filter(|s| (100..600).contains(s))
            .ok_or_else(|| Failure::invalid("下载 HTTP 状态无效"))?;
        let mut total = status_line.len();
        let mut headers = Vec::new();
        loop {
            let bytes = line(stream, MAX_HEADER_BYTES)?;
            total += bytes.len();
            if total > MAX_HEADER_BYTES {
                return Err(Failure::invalid("下载响应头超过上限"));
            }
            if bytes == b"\r\n" {
                break;
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| Failure::invalid("下载响应头编码无效"))?;
            let (name, value) = text
                .trim_end_matches("\r\n")
                .split_once(':')
                .ok_or_else(|| Failure::invalid("下载响应头格式无效"))?;
            if name.is_empty()
                || name
                    .bytes()
                    .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
            {
                return Err(Failure::invalid("下载响应头名称无效"));
            }
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
        if status < 200 {
            continue;
        }
        let header = |name: &'static str| {
            headers
                .iter()
                .filter(move |(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        let lengths = header("content-length").collect::<Vec<_>>();
        if lengths.len() > 1 {
            return Err(Failure::invalid("下载响应包含重复长度"));
        }
        let length = lengths
            .first()
            .map(|v| {
                v.parse::<usize>()
                    .map_err(|_| Failure::invalid("下载内容长度无效"))
            })
            .transpose()?;
        let encodings = header("transfer-encoding").collect::<Vec<_>>();
        if encodings.len() > 1 {
            return Err(Failure::invalid("下载传输编码重复"));
        }
        let chunked = encodings
            .first()
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
        if !encodings.is_empty() && !chunked {
            return Err(Failure::invalid("下载传输编码不受支持"));
        }
        if chunked && length.is_some() {
            return Err(Failure::invalid("下载响应长度与分块编码冲突"));
        }
        if header("content-encoding").any(|v| !v.eq_ignore_ascii_case("identity")) {
            return Err(Failure::invalid("服务器返回了未请求的压缩下载内容"));
        }
        let body = if matches!(status, 204 | 304) {
            Vec::new()
        } else if chunked {
            read_chunked(stream, max_bytes)?
        } else if let Some(length) = length {
            if length > max_bytes {
                return Err(Failure::invalid(format!(
                    "下载内容超过 {max_bytes} 字节上限"
                )));
            }
            let mut body = vec![0; length];
            stream
                .read_exact(&mut body)
                .map_err(|e| Failure::io("下载内容不完整", e))?;
            body
        } else {
            let mut body = Vec::new();
            stream
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| Failure::io("下载内容不完整", e))?;
            if body.len() > max_bytes {
                return Err(Failure::invalid(format!(
                    "下载内容超过 {max_bytes} 字节上限"
                )));
            }
            body
        };
        return Ok(Response {
            status,
            headers,
            body,
            download_outbound: None,
            fetched_url: String::new(),
        });
    }
    Err(Failure::invalid("下载服务器返回过多临时响应"))
}
fn read_chunked(stream: &mut dyn Read, max_bytes: usize) -> Result<Vec<u8>, Failure> {
    let mut body = Vec::new();
    loop {
        let bytes = line(stream, 1024)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::invalid("下载分块长度编码无效"))?;
        let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| Failure::invalid("下载分块长度无效"))?;
        if size == 0 {
            let mut trailers = 0;
            loop {
                let bytes = line(stream, MAX_HEADER_BYTES)?;
                trailers += bytes.len();
                if trailers > MAX_HEADER_BYTES {
                    return Err(Failure::invalid("下载尾部响应头超过上限"));
                }
                if bytes == b"\r\n" {
                    return Ok(body);
                }
            }
        }
        if size > max_bytes.saturating_sub(body.len()) {
            return Err(Failure::invalid(format!(
                "下载内容超过 {max_bytes} 字节上限"
            )));
        }
        let at = body.len();
        body.resize(at + size, 0);
        stream
            .read_exact(&mut body[at..])
            .map_err(|e| Failure::io("下载分块内容不完整", e))?;
        let mut end = [0; 2];
        stream
            .read_exact(&mut end)
            .map_err(|e| Failure::io("下载分块内容不完整", e))?;
        if end != *b"\r\n" {
            return Err(Failure::invalid("下载分块结束标记无效"));
        }
    }
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
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
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
