//! Persisted asset settings and one shared manual/automatic update operation.
//! Downloads finish before the configuration transaction takes its decision lock.
use crate::{config, fetch, probes, state};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_ASSET: usize = 64 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Sources {
    urls: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Automatic {
    enabled: bool,
    interval_hours: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Download {
    route: String,
    group_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Settings {
    geosite: Sources,
    geoip: Sources,
    auto_update: Automatic,
    download: Download,
    verify_checksum: bool,
}
impl Default for Settings {
    fn default() -> Self {
        let source = |kind| Sources {
            urls: [
                format!(
                    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/{kind}.dat"
                ),
                format!(
                    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/{kind}.dat"
                ),
                format!(
                    "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/{kind}.dat"
                ),
            ]
            .into(),
        };
        Self {
            geosite: source("geosite"),
            geoip: source("geoip"),
            auto_update: Automatic {
                enabled: true,
                interval_hours: 24,
            },
            download: Download {
                route: "routing".into(),
                group_id: None,
            },
            verify_checksum: true,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    settings: Settings,
    source_override: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct AcceptedAsset {
    sha256: String,
    url: String,
    verified: bool,
    route: Download,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct History {
    checked: Option<u64>,
    updated: Option<u64>,
    assets: BTreeMap<String, AcceptedAsset>,
    error: Option<(String, String)>,
}
struct State {
    stored: Stored,
    history: History,
    next: u64,
    load_error: Option<String>,
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static WRITE: Mutex<()> = Mutex::new(());
static JOB: Mutex<Option<String>> = Mutex::new(None);
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn default_stored() -> Stored {
    Stored {
        settings: Settings::default(),
        source_override: false,
    }
}
fn read_json<T: serde::de::DeserializeOwned>(name: &str) -> Result<Option<T>, String> {
    let path = config::data_dir().join(name);
    match fs::metadata(&path) {
        Ok(meta) if meta.len() > 128 * 1024 => return Err("地理数据状态文件超过上限".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        _ => {}
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map(Some)
        .map_err(|e| e.to_string())
}
fn stored() -> std::sync::MutexGuard<'static, State> {
    STATE
        .get_or_init(|| {
            let (stored, load_error) = match read_json::<Stored>("geodata-settings.json") {
                Ok(Some(stored)) => match validate(&stored.settings, false) {
                    Ok(()) => (stored, None),
                    Err(e) => (default_stored(), Some(e)),
                },
                Ok(None) => (default_stored(), None),
                Err(e) => (default_stored(), Some(e)),
            };
            let history = read_json::<History>("geodata-update.json")
                .ok()
                .flatten()
                .unwrap_or_default();
            let delay = if history.error.is_some() {
                300
            } else {
                u64::from(stored.settings.auto_update.interval_hours) * 3600
            };
            let next = history.checked.unwrap_or_else(now).saturating_add(delay);
            Mutex::new(State {
                stored,
                history,
                next,
                load_error,
            })
        })
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
fn group_exists(id: &str) -> bool {
    id.strip_prefix("group-").is_some_and(|name| {
        config::outbound_seed()
            .iter()
            .any(|(candidate, kind)| *kind == "group" && candidate == name)
    })
}
fn validate(settings: &Settings, check_group: bool) -> Result<(), String> {
    for sources in [&settings.geosite, &settings.geoip] {
        if sources.urls.is_empty() || sources.urls.len() > 4 {
            return Err("每个地理数据文件须配置 1 到 4 个地址".into());
        }
        for value in &sources.urls {
            let url = fetch::valid_url(value)?;
            if value.chars().count() > 4096
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("地理数据地址过长或包含账号信息".into());
            }
        }
    }
    if !(1..=168).contains(&settings.auto_update.interval_hours) {
        return Err("自动更新间隔须为 1 到 168 小时".into());
    }
    match settings.download.route.as_str() {
        "routing" | "direct" if settings.download.group_id.is_none() => {}
        "group"
            if settings.download.group_id.as_deref().is_some_and(|id| {
                id.starts_with("group-") && (!check_group || group_exists(id))
            }) => {}
        _ => return Err("下载出站无效，指定代理时必须选择当前存在的策略组或链式出站".into()),
    }
    Ok(())
}
pub fn settings_json() -> Value {
    let state = stored();
    let mut value = serde_json::to_value(&state.stored.settings).unwrap();
    value["source"] = json!(if state.stored.source_override {
        "override"
    } else {
        "default"
    });
    value
}
pub fn patch(value: &Value) -> Result<(), String> {
    let _write = WRITE.lock().unwrap_or_else(|p| p.into_inner());
    let mut candidate = stored().stored.clone();
    if value.is_null() {
        candidate = default_stored();
    } else {
        let object = value.as_object().ok_or("地理数据设置须为对象或 null")?;
        for (name, value) in object {
            match name.as_str() {
                "geosite" | "geoip" => {
                    let sources: Sources =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    if name == "geosite" {
                        candidate.settings.geosite = sources;
                    } else {
                        candidate.settings.geoip = sources;
                    }
                    candidate.source_override = true;
                }
                "download" => {
                    candidate.settings.download =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?
                }
                "verify_checksum" => {
                    candidate.settings.verify_checksum =
                        value.as_bool().ok_or("校验设置须为布尔值")?
                }
                "auto_update" => {
                    let auto = value.as_object().ok_or("自动更新设置须为对象")?;
                    if auto
                        .keys()
                        .any(|key| !matches!(key.as_str(), "enabled" | "interval_hours"))
                    {
                        return Err("自动更新设置包含未知字段".into());
                    }
                    if let Some(value) = auto.get("enabled") {
                        candidate.settings.auto_update.enabled =
                            value.as_bool().ok_or("自动更新开关须为布尔值")?;
                    }
                    if let Some(value) = auto.get("interval_hours") {
                        candidate.settings.auto_update.interval_hours = value
                            .as_u64()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or("自动更新间隔无效")?;
                    }
                }
                _ => return Err(format!("不支持的地理数据设置字段 {name}")),
            }
        }
    }
    validate(&candidate.settings, true)?;
    crate::storage::write_atomic(
        &config::data_dir().join("geodata-settings.json"),
        &serde_json::to_vec(&candidate).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("保存地理数据设置失败：{e}"))?;
    let mut state = stored();
    state.next = now() + u64::from(candidate.settings.auto_update.interval_hours) * 3600;
    state.stored = candidate;
    state.load_error = None;
    drop(state);
    crate::events::runtime_changed();
    Ok(())
}
fn redacted(url: &str) -> Option<String> {
    let url = fetch::valid_url(url).ok()?;
    Some(format!("{}/…", url.origin().ascii_serialization()))
}
#[derive(Clone)]
struct Fingerprint {
    path: std::path::PathBuf,
    size: u64,
    modified: Option<SystemTime>,
    sha256: String,
}
static FINGERPRINTS: OnceLock<Mutex<BTreeMap<String, Fingerprint>>> = OnceLock::new();
fn fingerprint(kind: &str) -> Option<Fingerprint> {
    let path = crate::geodata::asset_path(kind).ok()?;
    let meta = fs::metadata(&path).ok()?;
    if meta.len() > MAX_ASSET as u64 {
        return None;
    }
    let cache = FINGERPRINTS.get_or_init(Default::default);
    if let Some(value) = cache
        .lock()
        .unwrap()
        .get(kind)
        .filter(|v| v.path == path && v.size == meta.len() && v.modified == meta.modified().ok())
        .cloned()
    {
        return Some(value);
    }
    let bytes = fs::read(&path).ok()?;
    let value = Fingerprint {
        path,
        size: bytes.len() as u64,
        modified: meta.modified().ok(),
        sha256: crate::sha256::hex(&bytes),
    };
    cache.lock().unwrap().insert(kind.into(), value.clone());
    Some(value)
}
fn timestamp(value: Option<u64>) -> Option<String> {
    value
        .and_then(|n| UNIX_EPOCH.checked_add(Duration::from_secs(n)))
        .map(state::iso8601)
}
pub fn status() -> Value {
    let (settings, history, next, load_error) = {
        let state = stored();
        (
            state.stored.settings.clone(),
            state.history.clone(),
            state.next,
            state.load_error.clone(),
        )
    };
    let mut assets = Vec::new();
    for (kind, source) in [("geoip", &settings.geoip), ("geosite", &settings.geosite)] {
        if let Some(file) = fingerprint(kind) {
            let accepted = history.assets.get(kind).filter(|v| v.sha256 == file.sha256);
            assets.push(json!({"kind":kind,"sha256":file.sha256,"size_bytes":file.size.to_string(),"modified_at":file.modified.map(state::iso8601),"source_redacted":source.urls.first().and_then(|s|redacted(s)),"fetched_url_redacted":accepted.and_then(|a|redacted(&a.url)),"verified":accepted.is_some_and(|a|a.verified),"download_route":accepted.map(|a|&a.route)}));
        }
    }
    let error = load_error
        .map(|e| ("geodata_settings_invalid".to_string(), e))
        .or(history.error);
    json!({"observed_at":state::iso8601(SystemTime::now()),"assets":assets,"last_checked_at":timestamp(history.checked),"last_updated_at":timestamp(history.updated),"next_check_at":if settings.auto_update.enabled {timestamp(Some(next))}else{None},"last_error":error.map(|(code,message)|json!({"code":code,"message":message})),"required_codes":config::required_geodata_codes()})
}
fn route(settings: &Settings) -> Result<fetch::DownloadRoute, String> {
    match settings.download.route.as_str() {
        "routing" => Ok(fetch::DownloadRoute::Routing),
        "direct" => Ok(fetch::DownloadRoute::Direct),
        "group" => settings
            .download
            .group_id
            .as_deref()
            .filter(|id| group_exists(id))
            .and_then(|id| id.strip_prefix("group-"))
            .map(|name| fetch::DownloadRoute::Outbound(name.into()))
            .ok_or_else(|| "地理数据的下载代理已不存在，请重新选择出站".into()),
        _ => Err("地理数据下载路由无效".into()),
    }
}
fn checksum(bytes: &[u8], file: &str) -> Result<String, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "校验文件不是有效文本")?
        .trim_start_matches('\u{feff}');
    let mut candidates = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()).take(65) {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields
            .next()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        else {
            continue;
        };
        if fields
            .next()
            .is_none_or(|name| name.trim_start_matches('*').trim_start_matches("./") == file)
        {
            candidates.push(hash.to_ascii_lowercase());
        }
    }
    if candidates.len() == 1 {
        Ok(candidates.remove(0))
    } else {
        Err("校验文件缺少该文件的唯一 SHA256".into())
    }
}
fn download_asset(
    kind: &str,
    url: &str,
    settings: &Settings,
    via: &fetch::DownloadRoute,
) -> Result<(Vec<u8>, AcceptedAsset), String> {
    crate::dns_transport::with_bootstrap(|| {
        let response = fetch::get_routed(url, "LemonVPN-Geodata/1", MAX_ASSET, via)?;
        if response.status != 200 || response.body.is_empty() {
            return Err(format!("下载服务器返回 HTTP {} 或空文件", response.status));
        }
        let digest = crate::sha256::hex(&response.body);
        let mut verified = false;
        if settings.verify_checksum {
            let mut target = fetch::valid_url(url)?;
            let file = target
                .path_segments()
                .and_then(Iterator::last)
                .unwrap_or("")
                .to_string();
            target.set_path(&format!("{}.sha256sum", target.path()));
            let sum = fetch::get_routed(target.as_str(), "LemonVPN-Geodata/1", 16 * 1024, via)?;
            if sum.status == 200 {
                let expected = checksum(&sum.body, &file)?;
                if expected != digest {
                    return Err("SHA256 不匹配，文件未替换".into());
                }
                verified = true;
            } else if sum.status != 404 {
                return Err(format!("校验文件返回 HTTP {}", sum.status));
            }
        }
        crate::geodata::validate_asset(kind, &response.body)?;
        let selected = response
            .download_outbound
            .as_deref()
            .filter(|name| {
                config::outbound_seed()
                    .iter()
                    .any(|(n, kind)| *kind == "group" && n == name)
            })
            .map(|name| format!("group-{name}"));
        let metadata = AcceptedAsset {
            sha256: digest,
            url: response.fetched_url,
            verified,
            route: Download {
                route: settings.download.route.clone(),
                group_id: selected,
            },
        };
        Ok((response.body, metadata))
    })
}
fn update() -> Result<(bool, BTreeMap<String, AcceptedAsset>), String> {
    let settings = stored().stored.settings.clone();
    let via = route(&settings)?;
    let mut assets = Vec::new();
    let mut accepted = BTreeMap::new();
    for (kind, sources) in [("geoip", &settings.geoip), ("geosite", &settings.geosite)] {
        let mut failures = Vec::new();
        let mut asset = None;
        for url in &sources.urls {
            if crate::runtime::stopping() {
                return Err("引擎正在退出，更新已取消".into());
            }
            match download_asset(kind, url, &settings, &via) {
                Ok(value) => {
                    asset = Some(value);
                    break;
                }
                Err(e) => failures.push(format!(
                    "{}：{e}",
                    redacted(url).unwrap_or_else(|| "下载来源".into())
                )),
            }
        }
        let (bytes, metadata) =
            asset.ok_or_else(|| format!("{kind} 更新失败：{}", failures.join("；")))?;
        assets.push((kind.to_string(), bytes));
        accepted.insert(kind.to_string(), metadata);
    }
    let _write = WRITE.lock().unwrap_or_else(|p| p.into_inner());
    if stored().stored.settings != settings {
        return Err("下载期间地理数据设置已变更，结果未覆盖新设置".into());
    }
    if crate::runtime::stopping() {
        return Err("引擎正在退出，更新已取消".into());
    }
    let changed = accepted
        .iter()
        .any(|(kind, next)| fingerprint(kind).is_none_or(|old| old.sha256 != next.sha256));
    if changed {
        config::replace_geodata(&assets)?;
    }
    Ok((changed, accepted))
}
pub fn begin() -> Result<probes::Accepted, String> {
    let mut job = JOB.lock().unwrap();
    if job.is_some() {
        return Err("地理数据已有更新正在进行".into());
    }
    if let Some(error) = stored().load_error.clone() {
        return Err(format!("地理数据设置加载失败，请重新保存：{error}"));
    }
    let id = probes::create_operation("geodata_update");
    *job = Some(id.clone());
    drop(job);
    let worker = id.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("geodata-update".into())
        .spawn(move || {
            struct Finish;
            impl Drop for Finish {
                fn drop(&mut self) {
                    *JOB.lock().unwrap() = None;
                }
            }
            let _finish = Finish;
            let result = update();
            let checked = now();
            let history = {
                let mut state = stored();
                state.history.checked = Some(checked);
                match &result {
                    Ok((changed, assets)) => {
                        if *changed {
                            state.history.updated = Some(checked);
                        }
                        state.history.assets = assets.clone();
                        state.history.error = None;
                    }
                    Err(e) => {
                        state.history.error = Some(("geodata_update_failed".into(), e.clone()))
                    }
                }
                state.next = checked
                    + if result.is_ok() {
                        u64::from(state.stored.settings.auto_update.interval_hours) * 3600
                    } else {
                        300
                    };
                state.history.clone()
            };
            if let Err(error) = crate::storage::write_atomic(
                &config::data_dir().join("geodata-update.json"),
                &serde_json::to_vec(&history).unwrap(),
            ) {
                crate::logs::warn(
                    "engine::geodata",
                    "Could not persist update status.",
                    Some(crate::logs::fields(&[("error", &error.to_string())])),
                );
            }
            match result {
                Ok(_) => probes::finish_operation(&worker, status().to_string()),
                Err(e) => probes::fail_operation(&worker, "geodata_update_failed", &e),
            }
            crate::events::runtime_changed();
        })
    {
        *JOB.lock().unwrap() = None;
        probes::fail_operation(&id, "geodata_update_failed", &e.to_string());
        return Err(e.to_string());
    }
    Ok(probes::accepted(id, "geodata_update"))
}
pub fn start(shutdown: crate::runtime::Shutdown) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !shutdown.wait(Duration::from_secs(30)) {
            let due = {
                let state = stored();
                state.stored.settings.auto_update.enabled
                    && state.load_error.is_none()
                    && now() >= state.next
            };
            if due {
                let _ = begin();
            }
        }
    })
}
