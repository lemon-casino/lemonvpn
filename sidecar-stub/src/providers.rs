//! Subscription and inline-node providers.
//!
//! The managed configuration is still `config.dae`: providers live beside it in
//! `providers.conf` and their nodes are merged into the node table at build
//! time, so groups and rules see them without rewriting the source file. Each
//! provider keeps its nodes as share links, which is also the cache: a provider
//! created with `cache: false` drops them at startup and must be refreshed.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::base64;
use crate::config;
use crate::fetch;
use crate::json;
use crate::probes;
use crate::share::{self, Share};
use crate::state;

const STORE_FILE: &str = "providers.conf";
const STORE_HEADER: &str = "lemonvpn-providers 1";
const INLINE: &str = "inline";
const DEFAULT_USER_AGENT: &str = "LemonVPN/0.1";
const DEFAULT_INTERVAL: u64 = 3600;
const MAX_URL: usize = 4096;
const MAX_LINK: usize = 8192;
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE: usize = 100;
const MAX_INTERVAL: u64 = 31_536_000;
/// How often the automatic refresh checks whether a provider is due.
const SCHEDULER_TICK: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default)]
pub struct Traffic {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    /// `subscription` or `inline`.
    pub kind: &'static str,
    pub url: Option<String>,
    pub update_interval: u64,
    pub user_agent: String,
    pub cache: bool,
    pub nodes: Vec<Share>,
    pub updated_at: Option<SystemTime>,
    pub expires_at: Option<SystemTime>,
    pub traffic: Option<Traffic>,
    /// `ok`, `stale` or `error`.
    pub status: &'static str,
    pub last_error: Option<(String, String)>,
    /// A refresh is queued or running; never persisted.
    pub refreshing: bool,
}

impl Provider {
    fn subscription(name: String, url: String, update_interval: u64, user_agent: String, cache: bool) -> Self {
        Provider {
            name,
            kind: "subscription",
            url: Some(url),
            update_interval,
            user_agent,
            cache,
            nodes: Vec::new(),
            updated_at: None,
            expires_at: None,
            traffic: None,
            status: "stale",
            last_error: None,
            refreshing: false,
        }
    }
}

static STORE: OnceLock<Mutex<Vec<Provider>>> = OnceLock::new();

fn store() -> MutexGuard<'static, Vec<Provider>> {
    STORE
        .get_or_init(|| Mutex::new(load()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn store_path() -> PathBuf {
    config::data_dir().join(STORE_FILE)
}

fn load() -> Vec<Provider> {
    let Ok(text) = fs::read_to_string(store_path()) else {
        return Vec::new();
    };
    let mut providers: Vec<Provider> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.first() {
            Some(&"p") if fields.len() >= 14 => {
                let kind = match fields[2] {
                    "subscription" => "subscription",
                    "inline" => "inline",
                    _ => continue,
                };
                providers.push(Provider {
                    name: fields[1].to_owned(),
                    kind,
                    url: decode_field(fields[3]),
                    update_interval: fields[4].parse().unwrap_or(DEFAULT_INTERVAL),
                    user_agent: decode_field(fields[5]).unwrap_or_else(|| DEFAULT_USER_AGENT.to_owned()),
                    cache: fields[6] == "1",
                    nodes: Vec::new(),
                    updated_at: unix_field(fields[7]),
                    expires_at: unix_field(fields[8]),
                    status: match fields[9] {
                        "ok" => "ok",
                        "error" => "error",
                        _ => "stale",
                    },
                    last_error: decode_field(fields[10]).zip(decode_field(fields[11])),
                    traffic: Some(Traffic {
                        upload: fields[12].parse().ok(),
                        download: fields[13].parse().ok(),
                        total: fields.get(14).and_then(|value| value.parse().ok()),
                    }),
                    refreshing: false,
                });
            }
            Some(&"n") if fields.len() >= 3 => {
                let (Some(name), Some(link)) = (decode_field(fields[1]), decode_field(fields[2])) else {
                    continue;
                };
                let Some(provider) = providers.last_mut() else { continue };
                let mut parsed = match share::parse(&link) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                parsed.name = Some(name);
                provider.nodes.push(parsed);
            }
            _ => {}
        }
    }
    for provider in &mut providers {
        // `cache: false` keeps nothing across restarts; the provider starts
        // stale and a refresh loads it again.
        if !provider.cache {
            provider.nodes.clear();
            provider.status = "stale";
            provider.traffic = None;
        }
        if provider.nodes.is_empty() && provider.status == "ok" {
            provider.status = "stale";
        }
    }
    providers
}

fn render(providers: &[Provider]) -> String {
    let mut text = String::from(STORE_HEADER);
    text.push('\n');
    for provider in providers {
        text.push_str(&format!(
            "p {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
            provider.name,
            provider.kind,
            encode_field(provider.url.as_deref()),
            provider.update_interval,
            encode_field(Some(&provider.user_agent)),
            u8::from(provider.cache),
            unix(provider.updated_at),
            unix(provider.expires_at),
            provider.status,
            encode_field(provider.last_error.as_ref().map(|(code, _)| code.as_str())),
            encode_field(provider.last_error.as_ref().map(|(_, message)| message.as_str())),
            number(provider.traffic.as_ref().and_then(|traffic| traffic.upload)),
            number(provider.traffic.as_ref().and_then(|traffic| traffic.download)),
            number(provider.traffic.as_ref().and_then(|traffic| traffic.total)),
        ));
        for node in &provider.nodes {
            text.push_str(&format!(
                "n {} {}\n",
                encode_field(node.name.as_deref()),
                encode_field(Some(&node.link)),
            ));
        }
    }
    text
}

fn encode_field(value: Option<&str>) -> String {
    match value {
        Some(value) if !value.is_empty() => base64::encode(value.as_bytes()),
        _ => "-".to_owned(),
    }
}

fn decode_field(value: &str) -> Option<String> {
    if value == "-" || value.is_empty() {
        return None;
    }
    base64::decode(value).and_then(|bytes| String::from_utf8(bytes).ok())
}

fn unix(value: Option<SystemTime>) -> String {
    value
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn unix_field(value: &str) -> Option<SystemTime> {
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
}

fn number(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned())
}

fn save(providers: &[Provider]) {
    let path = store_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let text = render(providers);
    let temporary = path.with_extension("tmp");
    if fs::write(&temporary, &text).is_ok() {
        // Windows refuses to rename over an existing file.
        let _ = fs::remove_file(&path);
        if fs::rename(&temporary, &path).is_ok() {
            return;
        }
    }
    let _ = fs::write(&path, text);
}

/// Merged provider nodes, named uniquely against `existing`. Called by the
/// configuration build while its lock is held; this takes the provider lock and
/// must never call back into `config`.
pub fn nodes(existing: &[String]) -> Vec<config::Node> {
    let store = store();
    let mut taken: HashSet<String> = existing.iter().cloned().collect();
    let mut nodes = Vec::new();
    for provider in store.iter() {
        for (index, node) in provider.nodes.iter().enumerate() {
            let base = node
                .name
                .clone()
                .unwrap_or_else(|| format!("{}-{}", provider.name, index + 1));
            let name = unique(&base, &mut taken);
            nodes.push(config::Node {
                name,
                protocol: node.protocol.clone(),
                host: node.host.clone(),
                port: node.port,
                username: None,
                password: None,
                link: Some(node.link.clone()),
                provider: Some(provider.name.clone()),
                subscription_tag: (provider.kind == "subscription").then(|| provider.name.clone()),
            });
        }
    }
    nodes
}

fn unique(base: &str, taken: &mut HashSet<String>) -> String {
    let base = base.trim();
    let base = if base.is_empty() { "node" } else { base };
    let mut name = base.to_owned();
    let mut index = 2;
    while !taken.insert(name.clone()) {
        name = format!("{base} #{index}");
        index += 1;
    }
    name
}

/// Starts the automatic refresh loop and loads the store eagerly.
pub fn start() {
    drop(store());
    thread::spawn(|| loop {
        thread::sleep(SCHEDULER_TICK);
        let now = SystemTime::now();
        let due: Vec<String> = {
            let store = store();
            store
                .iter()
                .filter(|provider| {
                    provider.kind == "subscription"
                        && provider.update_interval > 0
                        && !provider.refreshing
                        && provider.url.is_some()
                        && provider.updated_at.map_or(true, |updated| {
                            now.duration_since(updated)
                                .map(|age| age.as_secs() >= provider.update_interval)
                                .unwrap_or(true)
                        })
                })
                .map(|provider| provider.name.clone())
                .collect()
        };
        for name in due {
            if let Err((code, message)) = fetch_provider(&name) {
                crate::logs::warn(
                    "engine::providers",
                    "Scheduled subscription refresh failed.",
                    Some(crate::logs::fields(&[("provider", name.as_str()), ("code", code.as_str())])),
                );
                let _ = message;
            }
        }
    });
}

// --- API ------------------------------------------------------------------

pub fn capabilities_json() -> String {
    format!(
        concat!(
            r#""providers":{{"available":true,"can_refresh":true,"can_manage":true,"#,
            r#""create_options":{{"update_interval":{interval},"user_agent":"{agent}","cache":true}},"#,
            r#""max_page_size":{page}}}"#
        ),
        interval = DEFAULT_INTERVAL,
        agent = DEFAULT_USER_AGENT,
        page = MAX_PAGE,
    )
}

pub fn list(limit: Option<u64>, cursor: Option<&str>) -> Result<String, (u16, &'static str, String)> {
    let limit = limit.unwrap_or(MAX_PAGE as u64);
    if limit == 0 || limit > MAX_PAGE as u64 {
        return Err((400, "invalid_request", format!("limit 必须在 1..={MAX_PAGE}")));
    }
    let offset = match cursor {
        None | Some("") => 0,
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| (400, "invalid_request", "cursor 无效".to_owned()))?,
    };
    let store = store();
    let entries: Vec<String> = store
        .iter()
        .filter(|provider| provider.kind == "subscription" || !provider.nodes.is_empty())
        .skip(offset)
        .take(limit as usize)
        .map(provider_json)
        .collect();
    let next = offset + entries.len();
    let next_cursor = if next < store.iter().filter(|provider| provider.kind == "subscription" || !provider.nodes.is_empty()).count() {
        format!("\"{next}\"")
    } else {
        "null".to_owned()
    };
    Ok(format!(
        r#"{{"providers":[{}],"next_cursor":{next_cursor}}}"#,
        entries.join(",")
    ))
}

pub fn one(id: &str) -> Option<String> {
    let store = store();
    store
        .iter()
        .find(|provider| provider.name == id && (provider.kind == "subscription" || !provider.nodes.is_empty()))
        .map(provider_json)
}

fn provider_json(provider: &Provider) -> String {
    let traffic = match &provider.traffic {
        Some(traffic) => format!(
            r#"{{"upload_bytes":{},"download_bytes":{},"total_bytes":{}}}"#,
            uint64(traffic.upload),
            uint64(traffic.download),
            uint64(traffic.total)
        ),
        None => r#"{"upload_bytes":null,"download_bytes":null,"total_bytes":null}"#.to_owned(),
    };
    let last_error = match &provider.last_error {
        Some((code, message)) => format!(
            r#"{{"code":"{}","message":"{}"}}"#,
            json::escape(code),
            json::escape(message)
        ),
        None => "null".to_owned(),
    };
    format!(
        concat!(
            r#"{{"id":"{}","name":"{}","kind":"{}","url_redacted":{},"node_count":{},"#,
            r#""updated_at":{},"expires_at":{},"traffic":{traffic},"status":"{}","last_error":{last_error}}}"#
        ),
        json::escape(&provider.name),
        json::escape(&provider.name),
        provider.kind,
        provider
            .url
            .as_deref()
            .map(json::quoted)
            .unwrap_or_else(|| "null".to_owned()),
        provider.nodes.len(),
        timestamp(provider.updated_at),
        timestamp(provider.expires_at),
        provider.status,
        traffic = traffic,
        last_error = last_error,
    )
}

fn uint64(value: Option<u64>) -> String {
    value
        .map(|value| format!("\"{value}\""))
        .unwrap_or_else(|| "null".to_owned())
}

fn timestamp(value: Option<SystemTime>) -> String {
    value
        .map(|value| format!("\"{}\"", state::iso8601(value)))
        .unwrap_or_else(|| "null".to_owned())
}

/// Adds a subscription provider and loads it once. `create_unfetched` is not
/// advertised, so the create reports the state the first fetch left.
pub fn create(body: &str) -> Result<(String, String), (u16, &'static str, String)> {
    let name = json::field(body, "name")
        .ok_or_else(|| (400, "invalid_request", "name 缺失".to_owned()))?;
    let kind = json::field(body, "kind")
        .ok_or_else(|| (400, "invalid_request", "kind 缺失".to_owned()))?;
    let url = json::field(body, "url")
        .ok_or_else(|| (400, "invalid_request", "url 缺失".to_owned()))?;

    for key in json::keys(body) {
        if !matches!(key.as_str(), "name" | "kind" | "url" | "update_interval" | "user_agent" | "cache") {
            return Err((422, "unsupported_value", format!("不支持的字段 {key}")));
        }
    }
    if name.is_empty() || name.len() > 64 || !name.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')) {
        return Err((400, "invalid_request", "name 必须匹配 ^[A-Za-z0-9_.-]+ 且不超过 64 字符".to_owned()));
    }
    if kind != "subscription" {
        return Err((422, "unsupported_value", "只支持创建 subscription".to_owned()));
    }
    if url.len() > MAX_URL {
        return Err((400, "invalid_request", "url 超过 4096 字符".to_owned()));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err((422, "unsupported_value", "url 必须是 http(s)://".to_owned()));
    }
    let update_interval = match json::field(body, "update_interval") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) if value <= MAX_INTERVAL => value,
            _ => return Err((400, "invalid_request", "update_interval 必须在 0..=31536000".to_owned())),
        },
        None => DEFAULT_INTERVAL,
    };
    let user_agent = match json::field(body, "user_agent") {
        Some(value) => {
            if value.is_empty() || value.len() > 256 || !value.chars().all(|character| (' '..='~').contains(&character)) {
                return Err((400, "invalid_request", "user_agent 必须是 1..=256 个可打印 ASCII".to_owned()));
            }
            value
        }
        None => DEFAULT_USER_AGENT.to_owned(),
    };
    let cache = match json::bool_field(body, "cache") {
        Ok(value) => value.unwrap_or(true),
        Err(message) => return Err((400, "invalid_request", message)),
    };

    {
        let mut store = store();
        if name == INLINE || store.iter().any(|provider| provider.name == name) {
            return Err((409, "state_conflict", format!("订阅 `{name}` 已存在")));
        }
        store.push(Provider::subscription(name.clone(), url, update_interval, user_agent, cache));
        save(&store);
    }
    let result = fetch_provider(&name);
    config::reload_providers();
    if let Err((_, message)) = &result {
        // The provider exists with its failure recorded; the caller still gets
        // the created provider so the UI can show why it is empty.
        let _ = message;
    }
    let body = one(&name).ok_or_else(|| (500, "internal_error", "订阅创建后不可见".to_owned()))?;
    Ok((body, format!("/api/v1/providers/{}", share::percent_encode(&name))))
}

pub fn delete(id: &str) -> String {
    let deleted = {
        let mut store = store();
        let before = store.len();
        store.retain(|provider| provider.name != id);
        let deleted = before - store.len();
        if deleted > 0 {
            save(&store);
        }
        deleted
    };
    if deleted > 0 {
        config::reload_providers();
    }
    format!(r#"{{"deleted":{deleted}}}"#)
}

/// Queues a refresh; the fetch runs on its own thread and finishes the
/// operation with the provider.
pub fn refresh(id: &str) -> Result<(String, String), (u16, &'static str, String)> {
    {
        let mut store = store();
        let Some(provider) = store.iter_mut().find(|provider| provider.name == id) else {
            return Err((404, "resource_not_found", "没有这个订阅".to_owned()));
        };
        if provider.kind != "subscription" {
            return Err((422, "unsupported_value", "只有订阅可以刷新".to_owned()));
        }
        if provider.refreshing {
            return Err((409, "state_conflict", "该订阅正在刷新".to_owned()));
        }
        provider.refreshing = true;
    }
    let operation = probes::create_operation("provider_refresh");
    let accepted = probes::accepted(operation.clone(), "provider_refresh");
    let name = id.to_owned();
    thread::spawn(move || match fetch_provider(&name) {
        Ok(provider) => probes::finish_operation(&operation, provider),
        Err((code, message)) => probes::fail_operation(&operation, &code, &message),
    });
    Ok((accepted.body, accepted.location))
}

/// Fetches and stores one provider. Returns its JSON on success and the
/// `SafeError` code and message on failure, with the failure recorded either
/// way. Never called while the store lock is held.
fn fetch_provider(name: &str) -> Result<String, (String, String)> {
    let (url, user_agent) = {
        let mut store = store();
        let found = store
            .iter()
            .find(|provider| provider.name == name)
            .map(|provider| (provider.url.clone(), provider.user_agent.clone()));
        match found {
            Some((Some(url), user_agent)) => (url, user_agent),
            Some((None, _)) => {
                if let Some(provider) = store.iter_mut().find(|provider| provider.name == name) {
                    provider.refreshing = false;
                }
                return Err(("fetch_failed".to_owned(), "订阅没有 url".to_owned()));
            }
            None => return Err(("fetch_failed".to_owned(), "订阅已被删除".to_owned())),
        }
    };

    let outcome = fetch::get(&url, &user_agent, MAX_SUBSCRIPTION_BYTES).and_then(|response| {
        if response.status != 200 {
            return Err(format!("订阅服务器返回 HTTP {}", response.status));
        }
        let text = String::from_utf8_lossy(&response.body);
        let nodes = share::parse_subscription(&text)?;
        Ok((nodes, fetch::user_info(&response)))
    });

    let mut store = store();
    let Some(provider) = store.iter_mut().find(|provider| provider.name == name) else {
        return Err(("fetch_failed".to_owned(), "订阅已被删除".to_owned()));
    };
    provider.refreshing = false;
    match outcome {
        Ok((nodes, info)) => {
            provider.nodes = nodes;
            provider.updated_at = Some(SystemTime::now());
            provider.status = "ok";
            provider.last_error = None;
            provider.traffic = info.as_ref().map(|info| Traffic {
                upload: info.upload,
                download: info.download,
                total: info.total,
            });
            provider.expires_at = info
                .as_ref()
                .and_then(|info| info.expire)
                .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds));
            let body = provider_json(provider);
            save(&store);
            drop(store);
            config::reload_providers();
            Ok(body)
        }
        Err(message) => {
            provider.last_error = Some(("fetch_failed".to_owned(), message.clone()));
            provider.status = if provider.nodes.is_empty() { "error" } else { "stale" };
            save(&store);
            drop(store);
            config::reload_providers();
            Err(("fetch_failed".to_owned(), message))
        }
    }
}

/// Adds an inline node from a share link.
pub fn add_node(body: &str) -> Result<(String, String), (u16, &'static str, String)> {
    let name = json::field(body, "name")
        .ok_or_else(|| (400, "invalid_request", "name 缺失".to_owned()))?;
    let link = json::field(body, "link")
        .ok_or_else(|| (400, "invalid_request", "link 缺失".to_owned()))?;
    for key in json::keys(body) {
        if key != "name" && key != "link" {
            return Err((422, "unsupported_value", format!("不支持的字段 {key}")));
        }
    }
    if name.is_empty() || name.len() > 64 {
        return Err((400, "invalid_request", "name 必须是 1..=64 字符".to_owned()));
    }
    if link.len() > MAX_LINK {
        return Err((400, "invalid_request", "link 超过 8192 字符".to_owned()));
    }
    let mut parsed = share::parse(&link).map_err(|message| (422, "unsupported_value", message))?;
    parsed.name = Some(name.clone());

    if config::node_names().iter().any(|existing| existing == &name) {
        return Err((409, "state_conflict", format!("节点 `{name}` 已存在")));
    }
    {
        let mut store = store();
        if store
            .iter()
            .any(|provider| provider.nodes.iter().any(|node| node.name.as_deref() == Some(name.as_str())))
        {
            return Err((409, "state_conflict", format!("节点 `{name}` 已存在")));
        }
        let inline = match store.iter().position(|provider| provider.kind == "inline") {
            Some(index) => index,
            None => {
                store.push(Provider {
                    name: INLINE.to_owned(),
                    kind: "inline",
                    url: None,
                    update_interval: 0,
                    user_agent: DEFAULT_USER_AGENT.to_owned(),
                    cache: true,
                    nodes: Vec::new(),
                    updated_at: Some(SystemTime::now()),
                    expires_at: None,
                    traffic: None,
                    status: "ok",
                    last_error: None,
                    refreshing: false,
                });
                store.len() - 1
            }
        };
        store[inline].nodes.push(parsed);
        save(&store);
    }
    config::reload_providers();
    let id = format!("node-{name}");
    let node = config::node_json(&id)
        .ok_or_else(|| (500, "internal_error", "节点创建后不可见".to_owned()))?;
    Ok((node, format!("/api/v1/nodes/{}", share::percent_encode(&id))))
}

/// Removes an inline node. Nodes owned by a subscription are removed with their
/// provider, so asking to delete one is the contract's capability 404.
pub fn delete_node(id: &str) -> Result<String, (u16, &'static str, String)> {
    let name = share::percent_decode(id.strip_prefix("node-").unwrap_or(id));
    let removed = {
        let mut store = store();
        let mut removed = false;
        if let Some(inline) = store.iter_mut().find(|provider| provider.kind == "inline") {
            if let Some(index) = inline.nodes.iter().position(|node| node.name.as_deref() == Some(name.as_str())) {
                inline.nodes.remove(index);
                removed = true;
            }
        }
        if removed {
            save(&store);
        } else if store
            .iter()
            .any(|provider| provider.nodes.iter().any(|node| node.name.as_deref() == Some(name.as_str())))
        {
            return Err((
                404,
                "capability_not_supported",
                "订阅节点随订阅刷新或删除，不能单独删除".to_owned(),
            ));
        }
        removed
    };
    if removed {
        config::reload_providers();
        return Ok(r#"{"deleted":1}"#.to_owned());
    }
    if config::node(&format!("node-{name}")).is_some() {
        return Err((
            404,
            "capability_not_supported",
            "配置源里的节点不能通过 API 删除".to_owned(),
        ));
    }
    Ok(r#"{"deleted":0}"#.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{render, Provider, Traffic};
    use crate::share::parse;
    use std::time::{Duration, UNIX_EPOCH};

    fn provider() -> Provider {
        let mut provider = Provider::subscription(
            "sub".to_owned(),
            "https://example.com/sub?token=secret".to_owned(),
            3600,
            "LemonVPN/0.1".to_owned(),
            true,
        );
        provider.nodes = vec![parse("vless://11111111-2222-3333-4444-555555555555@h:443#HK 01").unwrap()];
        provider.updated_at = Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        provider.traffic = Some(Traffic {
            upload: Some(1),
            download: Some(2),
            total: None,
        });
        provider.status = "ok";
        provider
    }

    #[test]
    fn round_trips_the_store_text() {
        let text = render(&[provider()]);
        assert!(text.starts_with("lemonvpn-providers 1\n"));
        assert!(text.contains("p sub subscription "));
        assert!(text.contains("\nn "));
        // Free-form values are Base64, so a name with a space cannot break the
        // line format.
        assert!(!text.contains("HK 01"));
    }
}
