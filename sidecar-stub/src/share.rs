//! Share links: the one representation of a proxy node.
//!
//! A subscription body or an inline node is parsed into a [`Share`] that keeps
//! the link verbatim, so the outbound layer can read the protocol parameters
//! from the same text the configuration shows. Clash-style YAML proxies have no
//! link of their own and are converted to the equivalent share link.

use std::collections::BTreeMap;

use crate::base64;
use crate::json;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// `vless`, `vmess`, `trojan`, `ss` or `hysteria2`.
    pub protocol: String,
    pub host: String,
    pub port: u16,
    /// UUID for VLESS/VMess, password for Trojan/Hysteria2, `method:password` for Shadowsocks.
    pub secret: String,
    pub name: Option<String>,
    pub link: String,
    pub tls: bool,
    pub reality: bool,
    pub sni: Option<String>,
}

/// Parses one share link. The error is a sanitized reason safe to return to the
/// caller: it never contains the link's credentials.
pub fn parse(link: &str) -> Result<Share, String> {
    let link = link.trim();
    let Some((scheme, rest)) = link.split_once("://") else {
        return Err("分享链接缺少 scheme".to_owned());
    };
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless(link, rest),
        "vmess" => parse_vmess(link, rest),
        "trojan" => parse_trojan(link, rest),
        "ss" => parse_ss(link, rest),
        "hysteria2" | "hy2" => parse_hysteria2(link, rest),
        other => Err(format!("不支持分享链接协议 `{other}`")),
    }
}

fn parse_vless(link: &str, rest: &str) -> Result<Share, String> {
    let (authority, query, name) = split_link(rest);
    let (uuid, host, port) = split_authority(authority)?;
    if !is_uuid(&uuid) {
        return Err("VLESS 链接缺少有效的 UUID".to_owned());
    }
    let params = query_params(query);
    let security = params.get("security").map(String::as_str).unwrap_or("");
    let reality = security == "reality";
    Ok(Share {
        protocol: "vless".to_owned(),
        host,
        port,
        secret: uuid,
        name: name.or_else(|| params.get("remarks").cloned()),
        link: link.to_owned(),
        tls: reality || security == "tls" || params.get("tls").is_some_and(|value| value == "1"),
        reality,
        sni: params.get("sni").cloned(),
    })
}

fn parse_vmess(link: &str, rest: &str) -> Result<Share, String> {
    let (body, _, name) = split_link(rest);
    let decoded = base64::decode(body).ok_or_else(|| "VMess 链接不是有效的 Base64".to_owned())?;
    let text = String::from_utf8(decoded).map_err(|_| "VMess 链接不是有效的 UTF-8".to_owned())?;
    let uuid = scalar(&text, "id").ok_or_else(|| "VMess 链接缺少 id".to_owned())?;
    if !is_uuid(&uuid) {
        return Err("VMess 链接缺少有效的 UUID".to_owned());
    }
    let host = scalar(&text, "add").ok_or_else(|| "VMess 链接缺少 add".to_owned())?;
    let port = scalar(&text, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "VMess 链接缺少有效端口".to_owned())?;
    let tls = scalar(&text, "tls").is_some_and(|value| value == "tls");
    Ok(Share {
        protocol: "vmess".to_owned(),
        host,
        port,
        secret: uuid,
        name: name.or_else(|| scalar(&text, "ps")),
        link: link.to_owned(),
        tls,
        reality: false,
        sni: scalar(&text, "sni").filter(|value| !value.is_empty()),
    })
}

fn parse_trojan(link: &str, rest: &str) -> Result<Share, String> {
    let (authority, query, name) = split_link(rest);
    let (password, host, port) = split_authority(authority)?;
    if password.is_empty() {
        return Err("Trojan 链接缺少密码".to_owned());
    }
    let params = query_params(query);
    let security = params.get("security").map(String::as_str).unwrap_or("tls");
    Ok(Share {
        protocol: "trojan".to_owned(),
        host,
        port,
        secret: password,
        name,
        link: link.to_owned(),
        tls: security != "none",
        reality: security == "reality",
        sni: params.get("sni").cloned(),
    })
}

fn parse_ss(link: &str, rest: &str) -> Result<Share, String> {
    let (authority, query, name) = split_link(rest);
    let params = query_params(query);
    if params.contains_key("plugin") {
        return Err("Shadowsocks 插件暂不支持".to_owned());
    }
    // SIP002 keeps the userinfo in Base64; the legacy form encodes the whole
    // `method:password@host:port` in Base64.
    let (secret, host, port) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let decoded = base64::decode(userinfo)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| percent_decode(userinfo));
            let (host, port) = host_port(hostport)?;
            (decoded, host, port)
        }
        None => {
            let decoded = base64::decode(authority)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| "Shadowsocks 链接不是有效的 Base64".to_owned())?;
            let (userinfo, hostport) = decoded
                .rsplit_once('@')
                .ok_or_else(|| "Shadowsocks 链接缺少 host:port".to_owned())?;
            let (host, port) = host_port(hostport)?;
            (percent_decode(userinfo), host, port)
        }
    };
    let (method, password) = secret
        .split_once(':')
        .ok_or_else(|| "Shadowsocks 链接缺少 method:password".to_owned())?;
    if method.is_empty() || password.is_empty() {
        return Err("Shadowsocks 链接缺少 method:password".to_owned());
    }
    Ok(Share {
        protocol: "ss".to_owned(),
        host,
        port,
        secret: format!("{method}:{password}"),
        name,
        link: link.to_owned(),
        tls: false,
        reality: false,
        sni: None,
    })
}

fn parse_hysteria2(link: &str, rest: &str) -> Result<Share, String> {
    let (authority, query, name) = split_link(rest);
    let (password, host, port) = split_authority(authority)?;
    if password.is_empty() {
        return Err("Hysteria2 链接缺少密码".to_owned());
    }
    let params = query_params(query);
    Ok(Share {
        protocol: "hysteria2".to_owned(),
        host,
        port,
        secret: password,
        name,
        link: link.to_owned(),
        tls: true,
        reality: false,
        sni: params.get("sni").cloned(),
    })
}

/// Splits `authority?query#name` (the part after `scheme://`).
fn split_link(rest: &str) -> (&str, &str, Option<String>) {
    let (before, fragment) = match rest.split_once('#') {
        Some((before, fragment)) => (before, Some(percent_decode(fragment))),
        None => (rest, None),
    };
    let (authority, query) = match before.split_once('?') {
        Some((authority, query)) => (authority, query),
        None => (before, ""),
    };
    let authority = authority.trim_end_matches('/');
    let name = fragment.filter(|name| !name.trim().is_empty());
    (authority, query, name)
}

fn split_authority(authority: &str) -> Result<(String, String, u16), String> {
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "分享链接缺少用户信息".to_owned())?;
    let (host, port) = host_port(hostport)?;
    Ok((percent_decode(userinfo), host, port))
}

fn host_port(value: &str) -> Result<(String, u16), String> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "分享链接的 IPv6 地址缺少 `]`".to_owned())?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "分享链接缺少端口".to_owned())?;
        (host.to_owned(), port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "分享链接缺少 host:port".to_owned())?;
        (host.to_owned(), port)
    };
    if host.is_empty() {
        return Err("分享链接缺少主机名".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "分享链接的端口无效".to_owned())?;
    if port == 0 {
        return Err("分享链接的端口无效".to_owned());
    }
    Ok((host, port))
}

pub(crate) fn query_params(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (key.to_ascii_lowercase(), percent_decode(value)),
            None => (pair.to_ascii_lowercase(), String::new()),
        })
        .collect()
}

pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                decoded.push(byte);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
        && value.chars().all(|character| character.is_ascii_hexdigit() || character == '-')
}

/// Reads a string or bare number field from a flat JSON object.
fn scalar(text: &str, key: &str) -> Option<String> {
    if let Some(value) = json::field(text, key) {
        return Some(value);
    }
    let marker = format!("\"{key}\"");
    let start = text.find(&marker)? + marker.len();
    let rest = text[start..].trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|character: char| character == ',' || character == '}' || character.is_whitespace())
        .unwrap_or(rest.len());
    let value = &rest[..end];
    (!value.is_empty() && value != "null").then(|| value.to_owned())
}

/// Splits a subscription body into shares.
///
/// Providers answer with a Base64-wrapped share-link list, the list itself, or
/// a Clash-style YAML document; all three are accepted.
pub fn parse_subscription(body: &str) -> Result<Vec<Share>, String> {
    let body = body.trim_start_matches('\u{feff}').trim();
    if body.is_empty() {
        return Err("订阅内容为空".to_owned());
    }
    if is_clash(body) {
        return parse_clash(body);
    }
    let text = if body.contains("://") {
        body.to_owned()
    } else {
        let decoded = base64::decode(body)
            .ok_or_else(|| "订阅内容既不是分享链接也不是 Base64".to_owned())?;
        String::from_utf8(decoded).map_err(|_| "订阅内容不是有效的 UTF-8".to_owned())?
    };
    let mut shares = Vec::new();
    let mut first_error = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match parse(line) {
            Ok(share) => shares.push(share),
            Err(message) => {
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
    }
    if shares.is_empty() {
        return Err(first_error.unwrap_or_else(|| "订阅里没有可用的节点".to_owned()));
    }
    Ok(shares)
}

fn is_clash(body: &str) -> bool {
    body.lines()
        .any(|line| line.trim_end().eq_ignore_ascii_case("proxies:") || line.starts_with("proxies: ["))
}

/// A Clash document's `proxies` entries, converted to the equivalent links.
fn parse_clash(body: &str) -> Result<Vec<Share>, String> {
    let document = parse_yaml(body);
    let Some(Value::Map(root)) = Some(document) else {
        return Err("Clash 订阅不是有效的 YAML".to_owned());
    };
    let Some(proxies) = root.get("proxies") else {
        return Err("Clash 订阅缺少 proxies".to_owned());
    };
    let Value::Seq(items) = proxies else {
        return Err("Clash 订阅的 proxies 不是列表".to_owned());
    };
    let mut shares = Vec::new();
    let mut first_error = None;
    for item in items {
        match clash_share(item) {
            Ok(Some(share)) => shares.push(share),
            Ok(None) => {}
            Err(message) => {
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
    }
    if shares.is_empty() {
        return Err(first_error.unwrap_or_else(|| "订阅里没有可用的节点".to_owned()));
    }
    Ok(shares)
}

fn clash_share(item: &Value) -> Result<Option<Share>, String> {
    let Value::Map(map) = item else { return Ok(None) };
    let text = |key: &str| map.get(key).and_then(Value::as_str).map(str::to_owned);
    let protocol = text("type").unwrap_or_default().to_ascii_lowercase();
    let host = text("server").ok_or_else(|| format!("Clash 节点缺少 server"))?;
    let port = text("port")
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "Clash 节点缺少有效 port".to_owned())?;
    if port == 0 {
        return Err("Clash 节点缺少有效 port".to_owned());
    }
    let name = text("name").unwrap_or_default();
    let name = (!name.is_empty()).then_some(name);
    let fragment = name
        .as_deref()
        .map(|name| format!("#{}", percent_encode(name)))
        .unwrap_or_default();
    let tls = map.get("tls").and_then(Value::as_bool).unwrap_or(false);
    let sni = text("servername").or_else(|| text("sni")).filter(|value| !value.is_empty());
    let network = text("network").unwrap_or_else(|| "tcp".to_owned());
    let ws = map.get("ws-opts").and_then(Value::as_map);
    let path = ws
        .and_then(|ws| ws.get("path"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let host_header = ws
        .and_then(|ws| ws.get("headers"))
        .and_then(Value::as_map)
        .and_then(|headers| headers.get("Host").or_else(|| headers.get("host")))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());

    match protocol.as_str() {
        "vless" => {
            let uuid = text("uuid").ok_or_else(|| "Clash VLESS 节点缺少 uuid".to_owned())?;
            if !is_uuid(&uuid) {
                return Err("Clash VLESS 节点的 uuid 无效".to_owned());
            }
            let reality = map.get("reality-opts").and_then(Value::as_map);
            let mut query = vec![format!("type={network}")];
            if let Some(reality) = reality {
                query.push("security=reality".to_owned());
                if let Some(key) = reality.get("public-key").and_then(Value::as_str) {
                    query.push(format!("pbk={}", percent_encode(key)));
                }
                if let Some(id) = reality.get("short-id").and_then(Value::as_str) {
                    query.push(format!("sid={}", percent_encode(id)));
                }
            } else if tls {
                query.push("security=tls".to_owned());
            }
            if let Some(sni) = &sni {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            if let Some(flow) = text("flow").filter(|value| !value.is_empty()) {
                query.push(format!("flow={}", percent_encode(&flow)));
            }
            if let Some(fp) = text("client-fingerprint").filter(|value| !value.is_empty()) {
                query.push(format!("fp={}", percent_encode(&fp)));
            }
            if let Some(path) = path {
                query.push(format!("path={}", percent_encode(path)));
            }
            if let Some(host) = host_header {
                query.push(format!("host={}", percent_encode(host)));
            }
            let link = format!("vless://{uuid}@{host}:{port}?{}{fragment}", query.join("&"));
            let mut share = parse_vless(&link, &link["vless://".len()..])?;
            share.name = name;
            Ok(Some(share))
        }
        "vmess" => {
            let uuid = text("uuid").ok_or_else(|| "Clash VMess 节点缺少 uuid".to_owned())?;
            if !is_uuid(&uuid) {
                return Err("Clash VMess 节点的 uuid 无效".to_owned());
            }
            let json = format!(
                concat!(
                    r#"{{"v":"2","ps":"{}","add":"{}","port":"{}","id":"{}","aid":"{}","scy":"{}","net":"{}","#,
                    r#""type":"none","host":"{}","path":"{}","tls":"{}","sni":"{}"}}"#
                ),
                json::escape(name.as_deref().unwrap_or("")),
                json::escape(&host),
                port,
                uuid,
                text("alterId").unwrap_or_else(|| "0".to_owned()),
                text("cipher").unwrap_or_else(|| "auto".to_owned()),
                network,
                json::escape(host_header.unwrap_or("")),
                json::escape(path.unwrap_or("")),
                if tls { "tls" } else { "" },
                json::escape(sni.as_deref().unwrap_or("")),
            );
            let link = format!("vmess://{}{fragment}", base64::encode(json.as_bytes()));
            let mut share = parse_vmess(&link, &link["vmess://".len()..])?;
            share.name = name;
            Ok(Some(share))
        }
        "trojan" => {
            let password = text("password").ok_or_else(|| "Clash Trojan 节点缺少 password".to_owned())?;
            let mut query = Vec::new();
            if let Some(sni) = &sni {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            let link = if query.is_empty() {
                format!("trojan://{}@{host}:{port}{fragment}", percent_encode(&password))
            } else {
                format!(
                    "trojan://{}@{host}:{port}?{}{fragment}",
                    percent_encode(&password),
                    query.join("&")
                )
            };
            let mut share = parse_trojan(&link, &link["trojan://".len()..])?;
            share.name = name;
            Ok(Some(share))
        }
        "ss" => {
            let method = text("cipher").ok_or_else(|| "Clash Shadowsocks 节点缺少 cipher".to_owned())?;
            let password = text("password").ok_or_else(|| "Clash Shadowsocks 节点缺少 password".to_owned())?;
            let userinfo = base64::encode(format!("{method}:{password}").as_bytes());
            let link = format!("ss://{userinfo}@{host}:{port}{fragment}");
            let mut share = parse_ss(&link, &link["ss://".len()..])?;
            share.name = name;
            Ok(Some(share))
        }
        "hysteria2" | "hy2" => {
            let password = text("password").ok_or_else(|| "Clash Hysteria2 节点缺少 password".to_owned())?;
            let mut query = Vec::new();
            if let Some(sni) = &sni {
                query.push(format!("sni={}", percent_encode(sni)));
            }
            let link = if query.is_empty() {
                format!("hysteria2://{}@{host}:{port}{fragment}", percent_encode(&password))
            } else {
                format!(
                    "hysteria2://{}@{host}:{port}/?{}{fragment}",
                    percent_encode(&password),
                    query.join("&")
                )
            };
            let mut share = parse_hysteria2(&link, &link["hysteria2://".len()..])?;
            share.name = name;
            Ok(Some(share))
        }
        // A protocol this engine cannot carry is skipped rather than failing
        // the whole subscription: one unknown node must not hide the rest.
        _ => Ok(None),
    }
}

pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// --- Minimal YAML -----------------------------------------------------------
//
// Clash documents use a small subset: block mappings and sequences, quoted or
// bare scalars, and flow maps. That is all this reader accepts; anything else
// is skipped rather than guessed at.

#[derive(Debug)]
enum Value {
    Map(BTreeMap<String, Value>),
    Seq(Vec<Value>),
    Scalar(String),
}

impl Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::Scalar(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self.as_str()? {
            "true" | "yes" | "on" => Some(true),
            "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }
}

fn parse_yaml(body: &str) -> Value {
    let mut lines: Vec<(usize, String)> = Vec::new();
    for raw in body.lines() {
        let trimmed = raw.trim_end();
        if trimmed.trim().is_empty() || trimmed.trim_start().starts_with('#') {
            continue;
        }
        let indent = trimmed.len() - trimmed.trim_start().len();
        let text = trimmed.trim_start();
        if text == "---" || text == "..." {
            continue;
        }
        lines.push((indent, text.to_owned()));
    }
    let mut index = 0;
    parse_block(&mut lines, &mut index, 0)
}

fn parse_block(lines: &mut Vec<(usize, String)>, index: &mut usize, indent: usize) -> Value {
    if *index >= lines.len() || lines[*index].0 < indent {
        return Value::Map(BTreeMap::new());
    }
    if is_item(&lines[*index].1) {
        let mut items = Vec::new();
        while *index < lines.len() && lines[*index].0 == indent && is_item(&lines[*index].1) {
            let text = lines[*index].1.clone();
            let rest = text[1..].trim_start().to_owned();
            if rest.is_empty() {
                *index += 1;
                if *index < lines.len() && lines[*index].0 > indent {
                    let child = lines[*index].0;
                    items.push(parse_block(lines, index, child));
                } else {
                    items.push(Value::Scalar(String::new()));
                }
            } else if rest.starts_with('{') || rest.starts_with('[') || split_key(&rest).is_none() {
                // A flow collection or plain scalar item.
                *index += 1;
                items.push(parse_scalar(&rest));
            } else {
                // `- key: value` is the first entry of a mapping two columns in.
                lines[*index] = (indent + 2, rest);
                items.push(parse_block(lines, index, indent + 2));
            }
        }
        return Value::Seq(items);
    }

    let mut map = BTreeMap::new();
    while *index < lines.len() && lines[*index].0 == indent && !is_item(&lines[*index].1) {
        let text = lines[*index].1.clone();
        let Some((key, value)) = split_key(&text) else {
            *index += 1;
            continue;
        };
        *index += 1;
        if value.is_empty() {
            let next = if *index < lines.len() && lines[*index].0 > indent {
                Some(lines[*index].0)
            } else {
                None
            };
            let child = match next {
                Some(child) => parse_block(lines, index, child),
                None => Value::Scalar(String::new()),
            };
            map.insert(key, child);
        } else {
            map.insert(key, parse_scalar(value));
        }
    }
    Value::Map(map)
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn split_key(text: &str) -> Option<(String, &str)> {
    let mut quote = None;
    for (index, character) in text.char_indices() {
        match character {
            '"' | '\'' if quote == Some(character) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            ':' if quote.is_none() => {
                let raw = &text[index + 1..];
                if raw.is_empty() || raw.starts_with(' ') || raw.starts_with('\t') {
                    return Some((unquote(text[..index].trim()), raw.trim_start()));
                }
                // `key:value` without a space is a scalar in YAML, but Clash
                // files always use a space; keep the stricter reading.
            }
            _ => {}
        }
    }
    None
}

fn parse_scalar(value: &str) -> Value {
    let value = value.trim();
    if value.starts_with('{') {
        return parse_flow_map(value);
    }
    if value.starts_with('[') {
        return parse_flow_seq(value);
    }
    Value::Scalar(unquote(value))
}

fn parse_flow_map(text: &str) -> Value {
    let inner = text
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(text);
    let mut map = BTreeMap::new();
    for entry in split_flow(inner) {
        if let Some((key, value)) = split_key(entry.trim()) {
            map.insert(key, parse_scalar(value));
        }
    }
    Value::Map(map)
}

fn parse_flow_seq(text: &str) -> Value {
    let inner = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    Value::Seq(split_flow(inner).into_iter().map(parse_scalar).collect())
}

fn split_flow(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote = None;
    let mut start = 0;
    for (index, character) in text.char_indices() {
        match character {
            '"' | '\'' if quote == Some(character) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            '{' | '[' if quote.is_none() => depth += 1,
            '}' | ']' if quote.is_none() => depth -= 1,
            ',' if quote.is_none() && depth == 0 => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < text.len() {
        parts.push(&text[start..]);
    }
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            let inner = &value[1..value.len() - 1];
            return if first == b'"' {
                inner.replace("\\\"", "\"").replace("\\\\", "\\")
            } else {
                inner.replace("''", "'")
            };
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_subscription};

    #[test]
    fn parses_vless_with_reality() {
        let share = parse(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=abc&sid=12&sni=www.apple.com&fp=chrome#HK%2001",
        )
        .unwrap();
        assert_eq!(share.protocol, "vless");
        assert_eq!(share.host, "example.com");
        assert_eq!(share.port, 443);
        assert!(share.reality && share.tls);
        assert_eq!(share.sni.as_deref(), Some("www.apple.com"));
        assert_eq!(share.name.as_deref(), Some("HK 01"));
    }

    #[test]
    fn parses_vmess_base64_json() {
        let json = r#"{"v":"2","ps":"东京","add":"1.2.3.4","port":"8443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","tls":"tls","sni":"a.example"}"#;
        let link = format!("vmess://{}", crate::base64::encode(json.as_bytes()));
        let share = parse(&link).unwrap();
        assert_eq!(share.host, "1.2.3.4");
        assert_eq!(share.port, 8443);
        assert!(share.tls);
        assert_eq!(share.name.as_deref(), Some("东京"));
    }

    #[test]
    fn parses_trojan_and_hysteria2() {
        let trojan = parse("trojan://pass%40word@h.example:443?sni=h.example#t").unwrap();
        assert_eq!(trojan.secret, "pass@word");
        assert!(trojan.tls);
        let hy = parse("hysteria2://secret@h.example:8443/?sni=h.example#h").unwrap();
        assert_eq!(hy.protocol, "hysteria2");
        assert_eq!(hy.port, 8443);
    }

    #[test]
    fn parses_both_shadowsocks_forms() {
        let sip002 = parse("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#n").unwrap();
        assert_eq!(sip002.secret, "aes-256-gcm:pass");
        assert_eq!(sip002.host, "1.2.3.4");
        let legacy = format!(
            "ss://{}#n",
            crate::base64::encode(b"aes-128-gcm:pw@5.6.7.8:8388")
        );
        let parsed = parse(&legacy).unwrap();
        assert_eq!(parsed.secret, "aes-128-gcm:pw");
        assert_eq!(parsed.host, "5.6.7.8");
    }

    #[test]
    fn rejects_unknown_and_malformed_links() {
        assert!(parse("foo://bar").is_err());
        assert!(parse("vless://not-a-uuid@h:1").is_err());
        assert!(parse("trojan://h:1").is_err());
        assert!(parse("ss://").is_err());
    }

    #[test]
    fn reads_base64_and_plain_subscriptions() {
        let plain = "vless://11111111-2222-3333-4444-555555555555@a.example:443#a\nss://YWVzLTI1Ni1nY206cGFzcw==@b.example:8388#b\n";
        assert_eq!(parse_subscription(plain).unwrap().len(), 2);
        let encoded = crate::base64::encode(plain.as_bytes());
        assert_eq!(parse_subscription(&encoded).unwrap().len(), 2);
        assert_eq!(parse_subscription("").unwrap_err(), "订阅内容为空");
    }

    #[test]
    fn reads_clash_yaml_proxies() {
        let yaml = r#"
port: 7890
proxies:
  - name: "HK 01"
    type: vless
    server: a.example
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: www.apple.com
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example
    reality-opts:
      public-key: abc
      short-id: "12"
  - name: ss-1
    type: ss
    server: b.example
    port: 8388
    cipher: aes-256-gcm
    password: pw
  - {name: inline, type: trojan, server: c.example, port: 443, password: x}
  - name: ignored
    type: wireguard
    server: d.example
    port: 1
"#;
        let shares = parse_subscription(yaml).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].protocol, "vless");
        assert!(shares[0].reality);
        assert_eq!(shares[0].name.as_deref(), Some("HK 01"));
        assert_eq!(shares[1].secret, "aes-256-gcm:pw");
        assert_eq!(shares[2].protocol, "trojan");
        assert_eq!(shares[2].name.as_deref(), Some("inline"));
    }
}
