//! One accepted, immutable resource revision shared by routing, DNS and TUN.
pub mod model;
mod mrs;
pub mod removal;
mod set;
pub mod trace;
use crate::config::{Condition, RoutingInput};
use model::*;
use serde_json::{json, Value};
pub use set::{Pattern, SetRef};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fs,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Snapshot {
    pub document: Document,
    pub revision: String,
    pub signature: String,
    pub sets: BTreeMap<String, SetRef>,
    pub policies: Vec<(Policy, Condition)>,
    pub bindings: Vec<(Binding, Condition)>,
}
static ACTIVE: OnceLock<RwLock<Arc<Snapshot>>> = OnceLock::new();
pub static APPLY: Mutex<()> = Mutex::new(());
static ERROR: Mutex<Option<String>> = Mutex::new(None);
static UPDATES: OnceLock<Mutex<BTreeMap<String, Value>>> = OnceLock::new();
static PHASE: OnceLock<Mutex<Value>> = OnceLock::new();
pub fn phase(name: &str, candidate: Option<&str>, message: Option<&str>) {
    *PHASE
        .get_or_init(|| Mutex::new(json!({"state":"idle"})))
        .lock()
        .unwrap() = json!({"state":name,"candidate_revision":candidate,"message":message});
}
pub fn apply_status() -> Value {
    json!({"active_generation":crate::config::generation(),"revision":current().revision,"operation":PHASE.get_or_init(||Mutex::new(json!({"state":"idle"}))).lock().unwrap().clone(),"kernel":serde_json::from_str::<Value>(&crate::compat::hot_apply_json()).unwrap_or(Value::Null)})
}
thread_local! {static CANDIDATE:RefCell<Option<Arc<Snapshot>>>=const{RefCell::new(None)};static PARSING:RefCell<Option<Arc<BTreeMap<String,SetRef>>>>=const{RefCell::new(None)};}
fn directory() -> std::path::PathBuf {
    crate::config::data_dir().join("rules-runtime")
}
pub fn current() -> Arc<Snapshot> {
    if let Some(value) = CANDIDATE.with(|s| s.borrow().clone()) {
        return value;
    }
    ACTIVE
        .get_or_init(|| {
            let loaded = (|| {
                let active = read_active()?;
                let id = active["revision"].as_str()?.to_string();
                if !digest_valid(id.trim()) {
                    return None;
                }
                let path = directory().join(format!("{}.json", id.trim()));
                if fs::metadata(&path).ok()?.len() > 32 * 1024 * 1024 {
                    return None;
                }
                let bytes = fs::read(path).ok()?;
                if bytes.len() > 32 * 1024 * 1024 || crate::sha256::hex(&bytes) != id.trim() {
                    return None;
                }
                let doc: Document = serde_json::from_slice(&bytes).ok()?;
                match compile(doc) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        *ERROR.lock().unwrap() = Some(e);
                        None
                    }
                }
            })();
            RwLock::new(Arc::new(loaded.unwrap_or_else(|| {
                compile(Document::default()).expect("empty resource document")
            })))
        })
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}
pub fn with_candidate<T>(snapshot: Arc<Snapshot>, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<Arc<Snapshot>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CANDIDATE.with(|s| *s.borrow_mut() = self.0.take());
        }
    }
    let prior = CANDIDATE.with(|s| s.replace(Some(snapshot)));
    let _reset = Reset(prior);
    f()
}
pub fn resolve_set(id: &str) -> Option<SetRef> {
    if let Some(sets) = PARSING.with(|s| s.borrow().clone()) {
        return sets.get(id).cloned();
    }
    current().sets.get(id).cloned()
}
pub fn install(snapshot: Arc<Snapshot>) {
    let _ = current();
    *ACTIVE
        .get()
        .unwrap()
        .write()
        .unwrap_or_else(|p| p.into_inner()) = snapshot;
}
fn read_active() -> Option<Value> {
    let path = directory().join("active");
    if fs::metadata(&path).ok()?.len() > 4096 {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text)
        .ok()
        .or_else(|| Some(json!({"revision":text.trim()})))
}
pub fn persist(snapshot: &Snapshot) -> Result<(), String> {
    let bytes = serde_json::to_vec(&snapshot.document).map_err(|e| e.to_string())?;
    crate::storage::write_atomic(
        &directory().join(format!("{}.json", snapshot.revision)),
        &bytes,
    )
    .map_err(|e| e.to_string())?;
    let journal = fs::read(directory().join("source-transaction.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let token = journal
        .filter(|v| v["next_revision"].as_str() == Some(&snapshot.revision))
        .map(|v| v["commit"].clone())
        .unwrap_or(Value::Null);
    crate::storage::write_atomic(
        &directory().join("active"),
        json!({"revision":snapshot.revision,"commit":token})
            .to_string()
            .as_bytes(),
    )
    .map_err(|e| e.to_string())
}
pub fn recover_sources() {
    let path = directory().join("source-transaction.json");
    let result = (|| {
        if fs::metadata(&path).ok()?.len() > 32 * 1024 * 1024 {
            return None;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
        let committed = value["commit"].as_str().is_some()
            && read_active().is_some_and(|active| {
                active["commit"] == value["commit"] && active["revision"] == value["next_revision"]
            });
        if !committed {
            for row in value["sources"].as_array()? {
                let name = row["path"].as_str()?;
                let content = row["content"].as_str()?;
                if !crate::config::source_name_valid(name) {
                    return None;
                }
                crate::storage::write_atomic(
                    &crate::config::data_dir().join(name),
                    content.as_bytes(),
                )
                .ok()?;
            }
        }
        fs::remove_file(&path).ok()?;
        Some(())
    })();
    if path.exists() && result.is_none() {
        *ERROR.lock().unwrap() =
            Some("未完成的资源事务无法自动恢复，请检查数据目录恢复记录".into());
    }
}
pub fn source_journal(revision: &str, sources: &[(String, String)]) -> Result<(), String> {
    let commit =
        crate::sha256::hex(format!("{revision}{:?}{sources:?}", SystemTime::now()).as_bytes());
    let value = json!({"next_revision":revision,"commit":commit,"sources":sources.iter().map(|(path,content)|json!({"path":path,"content":content})).collect::<Vec<_>>()});
    crate::storage::write_atomic(
        &directory().join("source-transaction.json"),
        value.to_string().as_bytes(),
    )
    .map_err(|e| e.to_string())
}
pub fn finish_source_journal() {
    let _ = fs::remove_file(directory().join("source-transaction.json"));
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn digest_valid(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
fn unique<'a>(values: impl Iterator<Item = (&'a str, &'a str)>) -> Result<(), String> {
    let mut ids = HashSet::new();
    for (id, name) in values {
        if !valid_id(id) || !ids.insert(id) || name.trim().is_empty() || name.len() > 200 {
            return Err("名称为空、ID 无效或重复".into());
        }
    }
    Ok(())
}
pub fn compile(document: Document) -> Result<Snapshot, String> {
    if document.schema != 1
        || document.providers.len() > 64
        || document.resolvers.len() > 64
        || document.pools.len() > 32
        || document.policies.len() > 128
        || document.bindings.len() > 128
    {
        return Err("资源版本或数量超过支持范围".into());
    }
    if !(64..=20000).contains(&document.cache.capacity)
        || !(1024 * 1024..=64 * 1024 * 1024).contains(&document.cache.max_bytes)
        || document.cache.stale_seconds > 300
    {
        return Err("DNS 缓存设置超限".into());
    }
    unique(
        document
            .providers
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str())),
    )?;
    unique(
        document
            .resolvers
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str())),
    )?;
    unique(
        document
            .pools
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str())),
    )?;
    unique(
        document
            .policies
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str())),
    )?;
    unique(
        document
            .bindings
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str())),
    )?;
    let mut total_bytes = 0usize;
    let mut sets = BTreeMap::new();
    for provider in &document.providers {
        if !matches!(provider.source.as_str(), "http" | "inline" | "file")
            || !(300..=2592000).contains(&provider.interval)
        {
            return Err(format!("{}：来源或更新周期无效", provider.name));
        }
        if !provider.expected_sha256.is_empty() && !digest_valid(&provider.expected_sha256) {
            return Err("SHA256 应为 64 位十六进制".into());
        }
        if provider.source == "http" {
            let url = url::Url::parse(&provider.url).map_err(|e| e.to_string())?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                return Err("规则集 URL 无效".into());
            }
        }

        let bytes = if provider.source == "inline" {
            provider.content.as_bytes().to_vec()
        } else {
            if !digest_valid(&provider.accepted_sha256) {
                return Err(format!("{} 尚未成功导入规则内容", provider.name));
            }
            let path = directory().join("assets").join(&provider.accepted_sha256);
            if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
                return Err("规则内容超限".into());
            }
            let bytes = fs::read(path).map_err(|e| format!("{}：{e}", provider.name))?;
            if bytes.len() > 16 * 1024 * 1024
                || crate::sha256::hex(&bytes) != provider.accepted_sha256
            {
                return Err("规则内容摘要不一致".into());
            }
            bytes
        };
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= 64 * 1024 * 1024)
            .ok_or("全部规则源合计超过 64 MiB")?;
        let hash = crate::sha256::hex(&bytes);
        if !provider.expected_sha256.is_empty()
            && !hash.eq_ignore_ascii_case(&provider.expected_sha256)
        {
            return Err(format!("{}：SHA256 校验不匹配", provider.name));
        }
        let set = Arc::new(set::compile(provider, &bytes)?);
        sets.insert(
            provider.id.clone(),
            SetRef {
                id: provider.id.clone(),
                digest: hash,
                set,
            },
        );
    }
    for resolver in &document.resolvers {
        crate::dns_transport::validate(resolver)?;
    }
    if document.bootstrap.is_empty() || document.bootstrap.len() > 8 {
        return Err("至少配置一个独立引导 DNS（最多 8 个）".into());
    }
    for value in &document.bootstrap {
        let resolver = Resolver {
            url: value.clone(),
            ..Default::default()
        };
        crate::dns_transport::validate(&resolver)?;
        let endpoint = url::Url::parse(value).map_err(|e| e.to_string())?;
        if endpoint
            .host_str()
            .unwrap_or("")
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_err()
        {
            return Err("引导 DNS 端点必须使用 IP，避免解析循环".into());
        }
    }
    for pool in &document.pools {
        if pool.members.is_empty()
            || pool.members.len() > 8
            || !matches!(pool.strategy.as_str(), "fallback" | "race")
        {
            return Err(format!("{}：解析池成员或策略无效", pool.name));
        }
        let mut members = HashSet::new();
        let mut outbound = None;
        for id in &pool.members {
            let resolver = document
                .resolvers
                .iter()
                .find(|r| &r.id == id)
                .ok_or_else(|| format!("解析池引用了不存在的上游 {id}"))?;
            if !members.insert(id) {
                return Err("解析池成员重复".into());
            }
            if pool.strategy == "race" {
                if outbound.as_ref().is_some_and(|o| o != &resolver.outbound) {
                    return Err("竞速上游必须使用同一出站策略".into());
                }
                outbound = Some(resolver.outbound.clone());
            }
        }
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            PARSING.with(|s| *s.borrow_mut() = None);
        }
    }
    PARSING.with(|s| *s.borrow_mut() = Some(Arc::new(sets.clone())));
    let _reset = Reset;
    let mut policies = Vec::new();
    let mut bindings = Vec::new();
    for policy in document.policies.iter().filter(|p| p.enabled) {
        if !matches!(
            policy.address_mode.as_str(),
            "inherit" | "fake-ip" | "real-ip"
        ) {
            return Err("地址模式无效".into());
        }
        if !document.pools.iter().any(|p| p.id == policy.pool)
            && crate::dns::reply_code(&policy.pool).is_none()
        {
            return Err(format!("{} 引用了不存在的解析池", policy.name));
        }
        let condition = condition(&policy.condition)?;
        if !crate::config::dns_condition_supported(&condition, false) {
            return Err(format!("{}：DNS 请求阶段无法判断此条件", policy.name));
        }
        if policy.address_mode != "inherit" && !set::domain_only(&condition) {
            return Err("Fake-IP 策略只能使用纯域名条件".into());
        }
        policies.push((policy.clone(), condition));
    }
    for binding in document.bindings.iter().filter(|p| p.enabled) {
        let condition = condition(&binding.condition)?;
        if !crate::config::routing_condition_supported(&condition) {
            return Err("路由条件不适用".into());
        }
        bindings.push((binding.clone(), condition));
    }
    let revision = crate::sha256::hex(&serde_json::to_vec(&document).map_err(|e| e.to_string())?);
    let signature=crate::sha256::hex(json!({
        "sets":sets.values().map(|s|json!([s.id,s.digest,s.set.enabled,s.set.effective])).collect::<Vec<_>>(),
        "resolvers":document.resolvers.iter().map(|r|json!([r.id,r.url,r.outbound,r.bootstrap,r.tls_name,r.timeout_ms])).collect::<Vec<_>>(),
        "pools":document.pools.iter().map(|p|json!([p.id,p.members,p.strategy])).collect::<Vec<_>>(),
        "policies":policies.iter().map(|(p,c)|json!([p.id,format!("{c:?}"),p.pool,p.address_mode])).collect::<Vec<_>>(),
        "bindings":bindings.iter().map(|(p,c)|json!([p.id,format!("{c:?}"),p.outbound])).collect::<Vec<_>>(),
        "bootstrap":document.bootstrap,"cache":document.cache,
    }).to_string().as_bytes());
    Ok(Snapshot {
        document,
        revision,
        signature,
        sets,
        policies,
        bindings,
    })
}
pub fn condition(expression: &str) -> Result<Condition, String> {
    crate::geodata::clear_error();
    crate::config::parse_condition(expression).ok_or_else(|| {
        crate::geodata::take_error().unwrap_or_else(|| format!("无法识别条件：{expression}"))
    })
}
pub fn dns_route(host: &str, kind: Option<&str>) -> Option<(String, String)> {
    let snapshot = current();
    let mut input = RoutingInput::new(host, "udp");
    input.query_type = kind;
    snapshot
        .policies
        .iter()
        .find(|(_, c)| crate::config::condition_matches_input(c, &input))
        .map(|(p, _)| (p.pool.clone(), format!("{}: {}", p.name, p.condition)))
}
pub fn status() -> Value {
    let snapshot = current();
    let sets:Vec<_>=snapshot.sets.values().map(|s|json!({"id":s.id,"sha256":s.digest,"count":s.set.entries.len(),"format":s.set.format,"behavior":s.set.behavior,"domain_only":s.set.domain_only,"ref_count":removal::references("provider",&s.id)["references"].as_array().map_or(0,Vec::len),"dns_request":s.set.dns_supported(false),"dns_response":s.set.dns_supported(true),"fakeip":s.set.can_project()})).collect();
    json!({"revision":snapshot.revision,"document":snapshot.document,"resources":sets,"generation_id":crate::config::generation(),"error":*ERROR.lock().unwrap(),"updates":UPDATES.get_or_init(Default::default).lock().unwrap().clone(),"outbounds":crate::config::outbound_seed().into_iter().map(|(id,kind)|json!({"id":id,"kind":kind})).collect::<Vec<_>>()})
}
pub fn update(body: &str) -> Result<Value, (u16, &'static str, String)> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        revision: String,
        document: Document,
    }
    let req: Request =
        serde_json::from_str(body).map_err(|e| (422, "invalid_rules_document", e.to_string()))?;
    let _serial = APPLY.lock().unwrap_or_else(|p| p.into_inner());
    if req.revision != current().revision {
        return Err((409, "conflict", "规则资源已更新，请重新加载后保存".into()));
    }
    apply(req.document).map_err(|e| (422, "rules_apply_failed", e))?;
    Ok(status())
}
pub fn apply(document: Document) -> Result<String, String> {
    phase("validating", None, None);
    let result = (|| {
        let snapshot = Arc::new(compile(document)?);
        phase("applying", Some(&snapshot.revision), None);
        crate::config::apply_resources(snapshot)
    })();
    let generation = match result {
        Ok(value) => value,
        Err(error) => {
            phase("failed", None, Some(&error));
            *ERROR.lock().unwrap() = Some(error.clone());
            return Err(error);
        }
    };
    phase("applied", None, None);
    *ERROR.lock().unwrap() = None;
    crate::events::emit(
        "runtime.updated",
        json!({"reason":"rules_resources","generation_id":generation}).to_string(),
    );
    Ok(generation)
}
pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn refresh(id: &str, cancel: &std::sync::atomic::AtomicBool) -> Result<(), String> {
    let initial = current();
    let mut provider = initial
        .document
        .providers
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or("规则集不存在")?;
    if provider.source != "http" {
        return Err("仅远程规则集需要更新；文件可重新导入".into());
    }
    let mut headers = provider.headers.clone();
    if !provider.etag.is_empty() {
        headers.insert("If-None-Match".into(), provider.etag.clone());
    }
    if !provider.last_modified.is_empty() {
        headers.insert("If-Modified-Since".into(), provider.last_modified.clone());
    }
    let response = crate::dns_transport::with_bootstrap(|| {
        crate::fetch::get_via_headers(
            &provider.url,
            "LemonVPN-Rules/1",
            16 * 1024 * 1024,
            &provider.outbound,
            &headers,
        )
    })?;
    if cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err("更新已取消；原内容保持不变".into());
    }
    if response.status == 304 {
        let _serial = APPLY.lock().unwrap_or_else(|p| p.into_inner());
        let active = current();
        if active.revision != initial.revision {
            return Err("资源已被编辑".into());
        }
        let mut doc = active.document.clone();
        if let Some(p) = doc.providers.iter_mut().find(|p| p.id == id) {
            p.updated_at = timestamp();
        }
        begin_commit(id, cancel)?;
        apply(doc)?;
        return Ok(());
    }
    if response.status != 200 {
        return Err(format!("规则服务器返回 HTTP {}", response.status));
    }
    set::compile(&provider, &response.body)?;
    let hash = crate::sha256::hex(&response.body);
    if !provider.expected_sha256.is_empty() && !provider.expected_sha256.eq_ignore_ascii_case(&hash)
    {
        return Err("规则集 SHA256 不匹配".into());
    }
    crate::storage::write_atomic(&directory().join("assets").join(&hash), &response.body)
        .map_err(|e| e.to_string())?;
    let _serial = APPLY.lock().unwrap_or_else(|p| p.into_inner());
    let active = current();
    if active.revision != initial.revision {
        return Err("下载期间资源已被编辑，结果未覆盖新配置".into());
    }
    if cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err("更新已取消；原内容保持不变".into());
    }
    provider.etag = response.header("etag").unwrap_or("").to_owned();
    provider.last_modified = response.header("last-modified").unwrap_or("").to_owned();
    provider.accepted_sha256 = hash;
    provider.updated_at = timestamp();
    let mut document = active.document.clone();
    let slot = document
        .providers
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or("规则集已移除")?;
    *slot = provider;
    begin_commit(id, cancel)?;
    apply(document)?;
    Ok(())
}
static CANCELS: OnceLock<Mutex<BTreeMap<String, Arc<std::sync::atomic::AtomicBool>>>> =
    OnceLock::new();
fn begin_commit(id: &str, cancel: &std::sync::atomic::AtomicBool) -> Result<(), String> {
    let mut updates = UPDATES.get_or_init(Default::default).lock().unwrap();
    if cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err("更新已取消；原内容保持不变".into());
    }
    if let Some(state) = updates.get_mut(id) {
        state["state"] = json!("applying");
    }
    Ok(())
}
pub fn cancel_refresh(id: &str) -> Result<Value, String> {
    let updates = UPDATES.get_or_init(Default::default).lock().unwrap();
    if !updates.get(id).is_some_and(|v| v["state"] == "running") {
        return Err("更新已进入应用阶段或已结束，请等待结果".into());
    }
    let jobs = CANCELS.get_or_init(Default::default).lock().unwrap();
    let flag = jobs.get(id).ok_or("规则集未在更新")?;
    flag.store(true, std::sync::atomic::Ordering::Release);
    Ok(json!({"cancel_requested":true}))
}
pub fn refresh_async(id: &str) -> Result<Value, String> {
    if !current().document.providers.iter().any(|p| p.id == id) {
        return Err("规则集不存在".into());
    }
    let id = id.to_string();
    let updates = UPDATES.get_or_init(Default::default);
    let operation;
    {
        let mut state = updates.lock().unwrap();
        if state
            .get(&id)
            .is_some_and(|v| v["state"] == "running" || v["state"] == "applying")
        {
            return Err("规则集正在更新".into());
        }
        if state
            .values()
            .filter(|v| v["state"] == "running" || v["state"] == "applying")
            .count()
            >= 2
        {
            return Err("已有两个资源正在下载，请稍后更新".into());
        }
        operation = crate::probes::create_operation("rule_provider_refresh");
        state.insert(
            id.clone(),
            json!({"state":"running","operation_id":operation}),
        );
    }
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    CANCELS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(id.clone(), flag.clone());
    let worker = operation.clone();
    std::thread::spawn(move || {
        let result = refresh(&id, &flag);
        let state = match result {
            Ok(()) => {
                crate::probes::finish_operation(
                    &worker,
                    json!({"id":id,"changed":true}).to_string(),
                );
                json!({"state":"success","at":timestamp()})
            }
            Err(error) => {
                crate::probes::fail_operation(
                    &worker,
                    if flag.load(std::sync::atomic::Ordering::Acquire) {
                        "cancelled"
                    } else {
                        "rule_provider_refresh_failed"
                    },
                    &error,
                );
                json!({"state":if flag.load(std::sync::atomic::Ordering::Acquire){"cancelled"}else{"failed"},"message":error,"at":timestamp()})
            }
        };
        UPDATES
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .insert(id.clone(), state);
        CANCELS.get().unwrap().lock().unwrap().remove(&id);
        crate::events::emit(
            "runtime.updated",
            json!({"reason":"rule_provider_refresh","id":id}).to_string(),
        );
    });
    Ok(
        serde_json::from_str(&crate::probes::accepted(operation, "rule_provider_refresh").body)
            .unwrap(),
    )
}
pub fn start(shutdown: crate::runtime::Shutdown) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut retry = BTreeMap::<String, (u64, u32, u64)>::new();
        while !shutdown.wait(std::time::Duration::from_secs(30)) {
            housekeeping();
            let now = timestamp();
            let snapshot = current();
            retry.retain(|id, _| snapshot.document.providers.iter().any(|p| &p.id == id));
            for p in snapshot
                .document
                .providers
                .iter()
                .filter(|p| p.enabled && p.source == "http")
            {
                let state = retry.entry(p.id.clone()).or_insert((0, 0, p.updated_at));
                if state.2 != p.updated_at {
                    *state = (0, 0, p.updated_at)
                }
                let jitter = u64::from(p.id.bytes().fold(0u8, |a, b| a.wrapping_add(b))) % 31;
                if now
                    >= p.updated_at
                        .saturating_add(p.interval)
                        .saturating_add(jitter)
                    && now >= state.0
                {
                    if refresh_async(&p.id).is_ok() {
                        state.1 = (state.1 + 1).min(7);
                        state.0 = now + (30u64 << state.1).min(3600) + jitter;
                    }
                    break;
                }
            }
        }
    })
}
pub fn entries(id: &str, offset: usize, query: &str) -> Result<Value, String> {
    let snapshot = current();
    let set = snapshot.sets.get(id).ok_or("规则集未启用或不存在")?;
    let needle = query.to_lowercase();
    let rows = set
        .set
        .entries
        .iter()
        .filter(|v| v.to_lowercase().contains(&needle))
        .skip(offset)
        .take(100)
        .cloned()
        .collect::<Vec<_>>();
    Ok(
        json!({"id":id,"total":set.set.entries.len(),"offset":offset,"entries":rows,"sha256":set.digest}),
    )
}
pub fn retarget_outbound(old: &str, replacement: Option<&str>) -> Result<Arc<Snapshot>, String> {
    let mut document = current().document.clone();
    for outbound in document
        .bindings
        .iter_mut()
        .map(|p| &mut p.outbound)
        .chain(document.resolvers.iter_mut().map(|p| &mut p.outbound))
        .chain(document.providers.iter_mut().map(|p| &mut p.outbound))
    {
        if outbound == old {
            *outbound = replacement
                .ok_or("此出站仍被分类规则、DNS 上游或规则集下载引用，请选择替换出站")?
                .to_string();
        }
    }
    Ok(Arc::new(compile(document)?))
}
pub fn import(body: &str) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        revision: String,
        provider: Provider,
        base64: Option<String>,
    }
    let mut req: Request = serde_json::from_str(body).map_err(|e| e.to_string())?;
    if req.provider.source == "http" {
        let response = crate::dns_transport::with_bootstrap(|| {
            crate::fetch::get_via_headers(
                &req.provider.url,
                "LemonVPN-Rules/1",
                16 * 1024 * 1024,
                &req.provider.outbound,
                &req.provider.headers,
            )
        })?;
        req.provider.etag = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        req.provider.last_modified = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if response.status != 200 {
            return Err(format!("规则服务器返回 HTTP {}", response.status));
        }
        req.base64 = Some(crate::base64::encode(&response.body));
    }
    if let Some(encoded) = req.base64 {
        let bytes = crate::base64::decode(&encoded).ok_or("文件编码无效")?;
        set::compile(&req.provider, &bytes)?;
        let digest = crate::sha256::hex(&bytes);
        crate::storage::write_atomic(&directory().join("assets").join(&digest), &bytes)
            .map_err(|e| e.to_string())?;
        req.provider.accepted_sha256 = digest;
        req.provider.content.clear();
        if req.provider.source != "http" {
            req.provider.source = "file".into();
        }
    }
    req.provider.updated_at = timestamp();
    let _serial = APPLY.lock().unwrap_or_else(|p| p.into_inner());
    let active = current();
    if active.revision != req.revision {
        return Err("配置已更新，请重新加载".into());
    }
    let mut doc = active.document.clone();
    if let Some(slot) = doc.providers.iter_mut().find(|p| p.id == req.provider.id) {
        *slot = req.provider
    } else {
        doc.providers.push(req.provider)
    }
    apply(doc)?;
    Ok(status())
}

static IMPORTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub struct ImportPermit;
impl Drop for ImportPermit {
    fn drop(&mut self) {
        IMPORTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
pub fn import_permit() -> Result<ImportPermit, String> {
    if IMPORTS.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= 2 {
        IMPORTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        return Err("已有两个资源正在导入".into());
    }
    Ok(ImportPermit)
}

// Keep the active revision and recent recovery points; orphan downloads age out.
fn housekeeping() {
    let Ok(_serial) = APPLY.try_lock() else {
        return;
    };
    let active = current();
    if let Some(updates) = UPDATES.get() {
        updates.lock().unwrap().retain(|id, value| {
            active.document.providers.iter().any(|p| p.id == *id)
                || value["state"] == "running"
                || value["state"] == "applying"
        });
    }
    let mut keep = HashSet::from([active.revision.clone()]);
    let mut revisions = fs::read_dir(directory())
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .take(5000)
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            let id = name.strip_suffix(".json")?;
            if !digest_valid(id) || !entry.file_type().ok()?.is_file() {
                return None;
            }
            Some((
                entry.metadata().ok()?.modified().ok()?,
                id.to_string(),
                entry.path(),
            ))
        })
        .collect::<Vec<_>>();
    revisions.sort_by_key(|(at, _, _)| std::cmp::Reverse(*at));
    for (_, id, _) in revisions.iter().take(3) {
        keep.insert(id.clone());
    }
    let mut assets = HashSet::new();
    for (_, id, path) in &revisions {
        if keep.contains(id) {
            if fs::metadata(path)
                .ok()
                .is_some_and(|m| m.len() <= 32 * 1024 * 1024)
            {
                if let Ok(bytes) = fs::read(path) {
                    if let Ok(doc) = serde_json::from_slice::<Document>(&bytes) {
                        assets.extend(doc.providers.into_iter().map(|p| p.accepted_sha256));
                    }
                }
            }
        } else if path
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age.as_secs() > 300)
        {
            let _ = fs::remove_file(path);
        }
    }
    assets.extend(
        active
            .document
            .providers
            .iter()
            .map(|p| p.accepted_sha256.clone()),
    );
    for entry in fs::read_dir(directory().join("assets"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .take(5000)
    {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if digest_valid(&name)
            && !assets.contains(&name)
            && entry.file_type().ok().is_some_and(|t| t.is_file())
            && entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age.as_secs() > 300)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}
