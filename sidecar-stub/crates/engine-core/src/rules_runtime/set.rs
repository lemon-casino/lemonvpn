use super::model::Provider;
use crate::config::{Condition, RoutingInput};
use crate::domain_regex::RegexIndex;
use std::borrow::Cow;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    sync::Arc,
};

#[derive(Clone)]
pub struct Pattern {
    text: String,
    regex: Arc<regex::Regex>,
}
impl Pattern {
    pub fn new(text: &str) -> Result<Self, String> {
        if text.len() > 4096 {
            return Err("正则表达式过长".into());
        }
        let regex = regex::RegexBuilder::new(text)
            .case_insensitive(true)
            .size_limit(4 * 1024 * 1024)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            text: text.into(),
            regex: Arc::new(regex),
        })
    }
    pub fn matches(&self, host: &str) -> bool {
        self.regex.is_match(host)
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}
impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}
impl Eq for Pattern {}
impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.text.fmt(f)
    }
}

#[derive(Clone)]
pub struct SetRef {
    pub id: String,
    pub digest: String,
    pub set: Arc<CompiledSet>,
}
impl PartialEq for SetRef {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
            && self.digest == o.digest
            && self.set.enabled == o.set.enabled
            && self.set.effective == o.set.effective
    }
}
impl Eq for SetRef {}
impl fmt::Debug for SetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RuleSet({}:{}:{})",
            self.id, self.digest, self.set.effective
        )
    }
}
pub struct CompiledSet {
    pub effective: String,
    pub enabled: bool,
    pub behavior: String,
    pub format: String,
    pub entries: Vec<String>,
    pub domain_only: bool,
    exact: HashSet<String>,
    suffix: HashSet<String>,
    subdomains: HashSet<String>,
    v4: HashMap<u8, HashSet<u32>>,
    v6: HashMap<u8, HashSet<u128>>,
    rest: Vec<Condition>,
    patterns: RegexIndex,
    pub projection: Vec<String>,
}
impl CompiledSet {
    pub(crate) fn collect_geo_codes(
        &self,
        codes: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    ) {
        if self.enabled {
            for condition in &self.rest {
                crate::config::collect_geo_codes(condition, codes);
            }
        }
    }

    pub fn uses_geo(&self, kind: &str, id: &str) -> bool {
        self.rest
            .iter()
            .any(|c| crate::config::condition_uses_geo(c, kind, id))
    }
    pub fn process_names(&self) -> Vec<String> {
        fn collect(c: &Condition, rows: &mut Vec<String>) {
            match c {
                Condition::Process(v) => rows.extend(v.iter().cloned()),
                Condition::And(v) | Condition::Any(v) => {
                    for c in v {
                        collect(c, rows)
                    }
                }
                Condition::Not(v) => collect(v, rows),
                _ => {}
            }
        }
        let mut rows = Vec::new();
        if self.enabled {
            for c in &self.rest {
                collect(c, &mut rows)
            }
        }
        rows
    }
    pub fn matches(&self, input: &RoutingInput<'_>) -> bool {
        if !self.enabled {
            return false;
        }
        let original = input.host.trim_end_matches('.');
        let normalized = if original.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(original.to_ascii_lowercase())
        } else {
            Cow::Borrowed(original)
        };
        let host = normalized.as_ref();
        if self.exact.contains(host) {
            return true;
        }
        let mut tail = host;
        loop {
            if self.suffix.contains(tail) {
                return true;
            }
            let Some((_, next)) = tail.split_once('.') else {
                break;
            };
            // A leading-dot entry requires at least one label before it.
            if self.subdomains.contains(next) {
                return true;
            }
            tail = next;
        }
        for ip in input
            .destination_ip
            .into_iter()
            .chain(input.answer_ips.iter().copied())
        {
            let yes = match ip {
                IpAddr::V4(ip) => self
                    .v4
                    .iter()
                    .any(|(p, set)| set.contains(&(u32::from(ip) & mask4(*p)))),
                IpAddr::V6(ip) => self
                    .v6
                    .iter()
                    .any(|(p, set)| set.contains(&(u128::from(ip) & mask6(*p)))),
            };
            if yes {
                return true;
            }
        }
        self.patterns.is_match(host)
            || self
                .rest
                .iter()
                .any(|c| crate::config::condition_matches_input(c, input))
    }
    pub fn dns_supported(&self, response: bool) -> bool {
        (response || self.v4.is_empty() && self.v6.is_empty())
            && self
                .rest
                .iter()
                .all(|c| crate::config::dns_condition_supported(c, response))
    }
    pub fn can_project(&self) -> bool {
        self.domain_only
            && self.projection.iter().all(|line| {
                line.split_once(',').is_some_and(|(kind, _)| {
                    matches!(
                        kind,
                        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX"
                    )
                })
            })
    }
    pub fn known(&self, input: &RoutingInput<'_>) -> bool {
        if !self.enabled {
            return true;
        }
        (self.v4.is_empty() && self.v6.is_empty()
            || input.destination_ip.is_some()
            || !input.answer_ips.is_empty())
            && self
                .rest
                .iter()
                .all(|c| crate::config::condition_known(c, input))
    }
}
fn mask4(p: u8) -> u32 {
    if p == 0 {
        0
    } else {
        u32::MAX << (32 - p)
    }
}
fn mask6(p: u8) -> u128 {
    if p == 0 {
        0
    } else {
        u128::MAX << (128 - p)
    }
}
fn glob(text: &str, single: bool) -> String {
    let mut out = String::from("^");
    for ch in text.chars() {
        match ch {
            '*' => out.push_str(if single { "[^.]+" } else { ".*" }),
            '?' => out.push('.'),
            _ => out.push_str(&regex::escape(&ch.to_string())),
        }
    }
    out.push('$');
    out
}
fn domain_text(text: &str) -> Result<String, String> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty()
        || text.len() > 254
        || text
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ',')
    {
        return Err("域名规则格式无效".into());
    }
    Ok(text)
}
fn domain(text: &str) -> Result<(Condition, String), String> {
    let text = domain_text(text)?;
    if let Some(suffix) = text.strip_prefix("+.").filter(|v| !v.contains(['*', '?'])) {
        return Ok((
            Condition::DomainSuffix(suffix.into()),
            format!("DOMAIN-SUFFIX,{suffix}"),
        ));
    }
    if let Some(suffix) = text.strip_prefix("+.") {
        let pattern = glob(suffix, true);
        let regex = format!("^(?:.+\\.)?{}", &pattern[1..]);
        return Ok((
            Condition::DomainPattern(Pattern::new(&regex)?),
            format!("DOMAIN-REGEX,{regex}"),
        ));
    }
    if let Some(suffix) = text.strip_prefix('.') {
        let pattern = glob(suffix, true);
        let regex = format!("^.+\\.{}", &pattern[1..]);
        return Ok((
            Condition::DomainPattern(Pattern::new(&regex)?),
            format!("DOMAIN-REGEX,{regex}"),
        ));
    }
    if text.contains(['*', '?']) {
        let regex = glob(&text, true);
        return Ok((
            Condition::DomainPattern(Pattern::new(&regex)?),
            format!("DOMAIN-REGEX,{regex}"),
        ));
    }
    let text = url::Host::parse(&text)
        .map_err(|_| "域名格式无效")?
        .to_string();
    Ok((
        Condition::DomainFull(text.clone()),
        format!("DOMAIN,{text}"),
    ))
}
pub fn classical(text: &str, depth: usize) -> Result<Condition, String> {
    if depth > 16 {
        return Err("规则组合嵌套超过 16 层".into());
    }
    let (kind, payload) = text.split_once(',').ok_or("classical 条目缺少条件值")?;
    let payload = payload
        .strip_suffix(",no-resolve")
        .unwrap_or(payload)
        .trim();
    let quoted = |v: &str| serde_json::to_string(v).unwrap();
    let expr = match kind.trim().to_ascii_uppercase().as_str() {
        "DOMAIN" => format!("domain(full: {})", quoted(payload)),
        "DOMAIN-SUFFIX" => format!("domain(suffix: {})", quoted(payload)),
        "DOMAIN-KEYWORD" => format!("domain(keyword: {})", quoted(payload)),
        "DOMAIN-REGEX" => return Ok(Condition::DomainPattern(Pattern::new(payload)?)),
        "DOMAIN-WILDCARD" => {
            return Ok(Condition::DomainPattern(Pattern::new(&glob(
                payload, false,
            ))?))
        }
        "GEOSITE" => format!("domain(geosite: {})", quoted(payload)),
        "GEOIP" => format!("dip(geoip: {})", quoted(payload)),
        "SRC-GEOIP" => format!("sip(geoip: {})", quoted(payload)),
        "IP-CIDR" | "IP-CIDR6" => format!("dip(cidr: {})", quoted(payload)),
        "SRC-IP-CIDR" => format!("sip(cidr: {})", quoted(payload)),
        "DST-PORT" => format!("dport({})", payload.replace('/', ",")),
        "SRC-PORT" => format!("sport({})", payload.replace('/', ",")),
        "NETWORK" => format!("l4proto({})", payload.to_ascii_lowercase()),
        "PROCESS-NAME" | "PROCESS-PATH" => format!("pname({})", quoted(payload)),
        "NOT" => {
            return Ok(Condition::Not(Box::new(classical(
                payload
                    .strip_prefix('(')
                    .and_then(|p| p.strip_suffix(')'))
                    .ok_or("NOT 括号无效")?,
                depth + 1,
            )?)))
        }
        "AND" | "OR" => {
            let inner = payload
                .strip_prefix('(')
                .and_then(|p| p.strip_suffix(')'))
                .ok_or("组合规则括号无效")?;
            let parts = crate::group_filter::split_top(inner, ",")?
                .into_iter()
                .map(|p| {
                    let p = p
                        .trim()
                        .strip_prefix('(')
                        .and_then(|p| p.strip_suffix(')'))
                        .ok_or("条件缺少括号")?;
                    classical(p, depth + 1)
                })
                .collect::<Result<Vec<_>, String>>()?;
            return Ok(if kind.trim().eq_ignore_ascii_case("AND") {
                Condition::And(parts)
            } else {
                Condition::Any(parts)
            });
        }
        other => return Err(format!("不支持的 classical 条件 {other}；未忽略此条目")),
    };
    crate::config::parse_condition(&expr)
        .ok_or_else(|| crate::geodata::take_error().unwrap_or_else(|| format!("条件无效：{text}")))
}
pub fn domain_only(c: &Condition) -> bool {
    match c {
        Condition::DomainFull(_)
        | Condition::DomainSuffix(_)
        | Condition::DomainKeyword(_)
        | Condition::DomainPattern(_)
        | Condition::GeoSite(_) => true,
        Condition::RuleSet(set) => set.set.domain_only,
        Condition::Not(v) => domain_only(v),
        Condition::And(parts) | Condition::Any(parts) => parts.iter().all(domain_only),
        _ => false,
    }
}

pub fn compile(provider: &Provider, bytes: &[u8]) -> Result<CompiledSet, String> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("规则源超过 16 MiB".into());
    }
    let (format, mut behavior, entries) = if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let (behavior, entries) = super::mrs::decode(bytes)?;
        ("mrs".to_string(), behavior, entries)
    } else {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "规则文本不是 UTF-8 或不是受支持的 MRS")?
            .trim_start_matches('\u{feff}');
        let yaml = provider.format == "yaml"
            || (provider.format == "auto"
                && (text.trim_start().starts_with("payload:")
                    || text.trim_start().starts_with("- ")));
        let entries = if yaml {
            // Do not permit YAML alias expansion in downloaded rule data.
            if text
                .lines()
                .any(|line| line.contains(" &") || line.trim_start().starts_with('&'))
            {
                return Err("规则 YAML 不接受锚点和别名".into());
            }
            let value: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
            let payload = value
                .get("payload")
                .unwrap_or(&value)
                .as_sequence()
                .ok_or("YAML 缺少 payload 列表")?;
            payload
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or("payload 必须为字符串".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned)
                .collect()
        };
        (
            if yaml { "yaml" } else { "text" }.into(),
            provider.behavior.clone(),
            entries,
        )
    };
    if provider.format != "auto" && provider.format != format {
        return Err(format!("文件实际格式为 {format}，与指定格式不一致"));
    }
    if entries.is_empty() && behavior == "auto" {
        return Err("空规则集无法自动识别类型，请指定匹配类型".into());
    }
    if entries.len() > 1_000_000 {
        return Err("单规则集超过 100 万条".into());
    }
    if behavior == "auto" {
        behavior = if entries.iter().all(|e| {
            e.split_once('/')
                .is_some_and(|(ip, p)| ip.parse::<IpAddr>().is_ok() && p.parse::<u8>().is_ok())
        }) {
            "ipcidr"
        } else if entries.iter().any(|e| e.contains(',')) {
            "classical"
        } else {
            "domain"
        }
        .into();
    }
    if !matches!(behavior.as_str(), "domain" | "ipcidr" | "classical") {
        return Err("规则集类型无效".into());
    }
    if format == "mrs" && provider.behavior != "auto" && provider.behavior != behavior {
        return Err("MRS behavior 与设置不一致".into());
    }
    let mut set = CompiledSet {
        effective: String::new(),
        enabled: provider.enabled,
        behavior: behavior.clone(),
        format,
        entries: entries.clone(),
        domain_only: true,
        exact: HashSet::new(),
        suffix: HashSet::new(),
        subdomains: HashSet::new(),
        v4: HashMap::new(),
        v6: HashMap::new(),
        rest: vec![],
        patterns: RegexIndex::default(),
        projection: vec![],
    };
    let mut patterns = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let result = (|| {
            // MRS serializes suffix-only domains as .example.com. Index those
            // as strings; expanding every one into a regex makes ordinary
            // country/ad lists hit the regex compiler's memory limit.
            let text = entry.trim();
            if behavior == "domain" && text.starts_with('.') && !text.contains(['*', '?']) {
                let text = domain_text(text)?;
                let suffix = url::Host::parse(&text[1..])
                    .map_err(|_| "域名后缀格式无效")?
                    .to_string();
                set.subdomains.insert(suffix);
                return Ok(());
            }
            let (condition, projection) = match behavior.as_str() {
                "domain" => domain(entry)?,
                "ipcidr" => (classical(&format!("IP-CIDR,{entry}"), 0)?, String::new()),
                _ => (classical(entry, 0)?, entry.clone()),
            };
            let is_domain = domain_only(&condition);
            set.domain_only &= is_domain;
            if is_domain && provider.enabled {
                match &condition {
                    Condition::DomainFull(_) | Condition::DomainSuffix(_) => {}
                    Condition::GeoSite(category) => set.projection.extend(category.projection()?),
                    Condition::DomainPattern(pattern) => set
                        .projection
                        .push(format!("DOMAIN-REGEX,{}", pattern.text())),
                    _ => set.projection.push(projection),
                }
            }
            match condition {
                Condition::DomainKeyword(value) => patterns.push(regex::escape(&value)),
                Condition::DomainPattern(pattern) => patterns.push(pattern.text().to_string()),
                Condition::DomainFull(v) => {
                    set.exact.insert(v);
                }
                Condition::DomainSuffix(v) => {
                    set.suffix.insert(v);
                }
                Condition::IpCidr(IpAddr::V4(ip), p) => {
                    set.v4
                        .entry(p)
                        .or_default()
                        .insert(u32::from(ip) & mask4(p));
                }
                Condition::IpCidr(IpAddr::V6(ip), p) => {
                    set.v6
                        .entry(p)
                        .or_default()
                        .insert(u128::from(ip) & mask6(p));
                }
                other => set.rest.push(other),
            };
            Ok::<(), String>(())
        })();
        result.map_err(|e| format!("{} 第 {} 条：{e}", provider.name, i + 1))?;
    }
    // MRS emits exact and subdomain entries independently. Folding a pair
    // into an inclusive suffix preserves both meanings and halves projection
    // payloads for the common case. A suffix-only entry never gains its apex.
    for suffix in std::mem::take(&mut set.subdomains) {
        if set.exact.remove(&suffix) || set.suffix.contains(&suffix) {
            set.suffix.insert(suffix);
        } else {
            set.subdomains.insert(suffix);
        }
    }
    set.patterns = RegexIndex::build(patterns).map_err(|e| format!("{}：{e}", provider.name))?;
    if provider.enabled {
        set.projection
            .extend(set.exact.iter().map(|v| format!("DOMAIN,{v}")));
        set.projection
            .extend(set.suffix.iter().map(|v| format!("DOMAIN-SUFFIX,{v}")));
        set.projection.extend(
            set.subdomains
                .iter()
                .map(|v| format!("DOMAIN-REGEX,^.+\\.{}$", regex::escape(v))),
        );
        set.projection.sort_unstable();
        set.projection.dedup();
    }
    set.effective = crate::sha256::hex(format!("{:?}", set.rest).as_bytes());
    Ok(set)
}
