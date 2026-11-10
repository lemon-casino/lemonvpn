//! Engine-native configuration: one dae-style source file whose `node`, `group`,
//! `dns` and `routing` blocks are the state the datapath actually uses.
//!
//! The source is read from `LEMONVPN_DATA_DIR` (default `%LOCALAPPDATA%\LemonVPN`
//! on Windows) and re-read when its mtime or size changes. The accepted text is
//! served as `GET /api/v1/config`; the parsed rules, nodes and groups as
//! `GET /api/v1/rules`, `/api/v1/nodes` and `/api/v1/groups`.

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

use crate::json;
use crate::logs;
use crate::sha256;
use crate::state;

#[path = "memberships.rs"]
mod memberships;
pub(crate) use memberships::{update_node_groups, update_nodes_groups};
#[path = "group_removal.rs"]
mod group_removal;
pub(crate) use group_removal::remove_group;
#[path = "rule_management.rs"]
mod rule_management;
pub(crate) use rule_management::{manage_rules, rule_defaults_json};
#[path = "proxy_chain.rs"]
mod proxy_chain;
pub(crate) use proxy_chain::sync_selection_changes as sync_chain_selections;

pub const SOURCE_ID: &str = "source-main";
pub const SOURCE_PATH: &str = "config.dae";
pub const MAX_BYTES: usize = 64 * 1024;

const DEFAULT_CONFIG: &str = "\
# LemonVPN engine configuration.
#
# routing is evaluated top to bottom; the first matching rule wins.
# Supported conditions:
#   domain(full: example.com) -> direct
#   domain(suffix: example.com) -> block
#   ip(cidr: 10.0.0.0/8) -> direct
# Outbounds are direct, block, a node name, or a group name.
#
# Proxy nodes and groups (examples; uncomment and edit):
# node {
#   edge: 'socks5://user:pass@127.0.0.1:1080'
# }
# group {
#   proxy {
#     filter: name('edge')
#     policy: fixed(0)
#   }
# }
#
# DNS upstreams used for direct dials and GET /api/v1/dns/query:
dns {
  upstream {
    default: 'udp://223.5.5.5:53'
  }
}

routing {
  domain(full: localhost) -> direct
  ip(cidr: 127.0.0.0/8) -> direct
  fallback: direct
}
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    DomainFull(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainPattern(crate::rules_runtime::Pattern),
    RuleSet(crate::rules_runtime::SetRef),
    GeoSite(crate::geodata::DomainRef),
    GeoIp(crate::geodata::IpRef),
    SourceGeoIp(crate::geodata::IpRef),
    Process(Vec<String>),
    Upstream(Vec<String>),
    Not(Box<Condition>),
    IpCidr(IpAddr, u8),
    SourceIpCidr(IpAddr, u8),
    DestinationPort(Vec<(u16, u16)>),
    SourcePort(Vec<(u16, u16)>),
    And(Vec<Condition>),
    Any(Vec<Condition>),
    Network(Vec<String>),
    QueryType(Vec<String>),
}

#[derive(Clone, Copy)]
pub(crate) struct RoutingInput<'a> {
    pub host: &'a str,
    pub network: &'a str,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub query_type: Option<&'a str>,
    pub process: Option<&'a crate::platform::process::ProcessInfo>,
    pub upstream: Option<&'a str>,
    pub answer_ips: &'a [IpAddr],
}

impl<'a> RoutingInput<'a> {
    pub(crate) fn new(host: &'a str, network: &'a str) -> Self {
        Self {
            host,
            network,
            source_ip: None,
            source_port: None,
            destination_ip: host.parse().ok(),
            destination_port: None,
            query_type: None,
            process: None,
            upstream: None,
            answer_ips: &[],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub index: usize,
    pub expression: String,
    pub outbound: String,
    pub condition: Option<Condition>,
    pub line: u32,
    pub source_id: Option<String>,
}

#[cfg(test)]
impl Rule {
    fn matches(&self, host: &str) -> bool {
        self.condition
            .as_ref()
            .is_some_and(|condition| condition_matches(condition, host))
    }
}

/// Shared by routing rules and DNS request rules.
#[cfg(test)]
fn condition_matches(condition: &Condition, host: &str) -> bool {
    condition_matches_input(condition, &RoutingInput::new(host, "tcp"))
}

pub(crate) fn condition_matches_input(condition: &Condition, input: &RoutingInput<'_>) -> bool {
    let host = input.host;
    match condition {
        Condition::DomainFull(value) => host == value,
        Condition::DomainSuffix(value) => {
            host == value
                || host
                    .strip_suffix(value)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }
        Condition::DomainKeyword(value) => host.contains(value),
        Condition::DomainPattern(pattern) => pattern.matches(host),
        Condition::RuleSet(set) => set.set.matches(input),
        Condition::GeoSite(set) => host.parse::<IpAddr>().is_err() && set.matches(host),
        Condition::GeoIp(set) => input
            .destination_ip
            .into_iter()
            .chain(input.answer_ips.iter().copied())
            .any(|ip| set.matches(ip)),
        Condition::SourceGeoIp(set) => input.source_ip.is_some_and(|ip| set.matches(ip)),
        Condition::Process(values) => input
            .process
            .is_some_and(|process| values.iter().any(|value| process.matches(value))),
        Condition::Upstream(values) => input
            .upstream
            .is_some_and(|upstream| values.iter().any(|value| value == upstream)),
        Condition::Not(inner) => {
            condition_known(inner, input) && !condition_matches_input(inner, input)
        }
        Condition::IpCidr(network, prefix) => input
            .destination_ip
            .into_iter()
            .chain(input.answer_ips.iter().copied())
            .any(|address| cidr_contains(address, *network, *prefix)),
        Condition::SourceIpCidr(network, prefix) => input
            .source_ip
            .is_some_and(|address| cidr_contains(address, *network, *prefix)),
        Condition::DestinationPort(ports) => input
            .destination_port
            .is_some_and(|port| ports.iter().any(|(from, to)| (*from..=*to).contains(&port))),
        Condition::SourcePort(ports) => input
            .source_port
            .is_some_and(|port| ports.iter().any(|(from, to)| (*from..=*to).contains(&port))),
        Condition::And(conditions) => conditions
            .iter()
            .all(|condition| condition_matches_input(condition, input)),
        Condition::Any(conditions) => conditions
            .iter()
            .any(|condition| condition_matches_input(condition, input)),
        Condition::Network(protocols) => protocols.iter().any(|p| p == input.network),
        Condition::QueryType(types) => input
            .query_type
            .is_some_and(|kind| types.iter().any(|value| value.eq_ignore_ascii_case(kind))),
    }
}

pub(crate) fn condition_known(condition: &Condition, input: &RoutingInput<'_>) -> bool {
    match condition {
        Condition::RuleSet(set) => set.set.known(input),
        Condition::Process(_) => input.process.is_some(),
        Condition::GeoIp(_) | Condition::IpCidr(..) => {
            input.destination_ip.is_some() || !input.answer_ips.is_empty()
        }
        Condition::SourceGeoIp(_) | Condition::SourceIpCidr(..) => input.source_ip.is_some(),
        Condition::QueryType(_) => input.query_type.is_some(),
        Condition::Upstream(_) => input.upstream.is_some(),
        Condition::And(parts) | Condition::Any(parts) => {
            parts.iter().all(|part| condition_known(part, input))
        }
        Condition::Not(part) => condition_known(part, input),
        _ => true,
    }
}

#[derive(Debug)]
pub struct Diagnostic {
    pub level: &'static str,
    pub line: u32,
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// The share link a provider or inline node was parsed from. The protocol
    /// outbounds re-parse it for transport details this struct does not model.
    #[allow(dead_code)]
    pub link: Option<String>,
    /// The provider that owns this node; `None` for nodes from `config.dae`.
    pub provider: Option<String>,
    /// The subscription tag shown as the node's source.
    pub subscription_tag: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Selector,
    Fixed(usize),
    Random,
    MovingAverage,
    Average10,
    LastDelay,
    Score,
    Fallback,
    RoundRobin,
}

impl Policy {
    pub fn kind(self) -> &'static str {
        match self {
            Policy::Selector => "selector",
            Policy::Fixed(_) => "fixed",
            Policy::Random => "random",
            Policy::MovingAverage | Policy::Average10 | Policy::LastDelay => "urltest",
            Policy::Score => "score",
            Policy::Fallback => "fallback",
            Policy::RoundRobin => "loadbalance",
        }
    }

    pub fn native(self) -> String {
        match self {
            Policy::Selector => "selector".to_string(),
            Policy::Fixed(index) => format!("fixed({index})"),
            Policy::Random => "random".to_string(),
            Policy::MovingAverage => "min_moving_avg".to_string(),
            Policy::Average10 => "min_avg10".to_string(),
            Policy::LastDelay => "min_last_delay".to_string(),
            Policy::Score => "score".to_string(),
            Policy::Fallback => "fallback".to_string(),
            Policy::RoundRobin => "roundrobin".to_string(),
        }
    }

    pub(crate) fn automatic(self) -> bool {
        !matches!(self, Self::Selector | Self::Fixed(_) | Self::Random)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub policy: Policy,
    pub default: Option<String>,
    pub final_outbound: Option<String>,
    /// Optional front proxy; legacy chains use members as exits without `landing`.
    pub dialer: Option<String>,
    pub landing: Option<String>,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub name: String,
    pub protocol: &'static str,
    pub host: String,
    pub port: u16,
}

/// The outbound a routing decision resolved to. A group is resolved to the leaf
/// node it selected when the decision is made, so a reload between the decision
/// and the dial cannot change which member the connection uses.
#[derive(Clone, Debug)]
pub enum Target {
    Direct,
    Block,
    Node(Box<Node>),
    /// Physical proxy hops in wire order: front first, exit last.
    Chain {
        nodes: Vec<Node>,
        front_len: usize,
    },
}

pub struct Config {
    pub content: String,
    pub sha256: String,
    pub generation: String,
    pub revision: String,
    pub resource_revision: String,
    pub rules: Vec<Rule>,
    pub fallback: Rule,
    pub nodes: Vec<Node>,
    pub groups: Vec<Group>,
    pub upstreams: Vec<Upstream>,
    pub diagnostics: Vec<Diagnostic>,
    /// DNS request rules in evaluation order, before the implicit fallback.
    pub dns_rules: Vec<DnsRule>,
    pub dns_response_rules: Vec<DnsRule>,
    pub dns_request_fallback: Option<String>,
    pub dns_response_fallback: String,
    pub dns_request_fallback_source: Option<(u32, Option<String>)>,
    pub dns_response_fallback_source: Option<(u32, Option<String>)>,
    /// Extra source files the main source pulls in with `include('name.dae')`.
    include_contents: Vec<(String, String)>,
    include_stamps: Vec<SourceStamp>,
    pub loaded_at: SystemTime,
    modified: Option<SystemTime>,
    bytes: usize,
}

/// One DNS request rule: the first condition that matches the query name
/// sends it to the named `dns { upstream }` entry instead of the first one.
#[derive(Clone, Debug)]
pub struct DnsRule {
    pub expression: String,
    pub condition: Condition,
    pub upstream: String,
    pub line: u32,
    pub source_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub(crate) epoch: crate::connections::RouteEpoch,
    pub process: Option<crate::platform::process::ProcessInfo>,
    /// The configured outbound name: `direct`, `block`, a node name or a group name.
    pub outbound: String,
    /// Physical proxy nodes in wire order, ending in the exit node.
    pub chain: Vec<String>,
    pub(crate) dependencies: Vec<String>,
    pub target: Target,
    pub rule_id: String,
    pub generation: String,
    pub expression: String,
}

impl Decision {
    pub(crate) fn selection_path(&self) -> Vec<String> {
        self.dependencies
            .iter()
            .map(|name| format!("group-{name}"))
            .chain(self.chain.iter().map(|name| format!("node-{name}")))
            .collect()
    }

    pub fn blocked(&self) -> bool {
        matches!(self.target, Target::Block)
    }
}

static CONFIG: OnceLock<Mutex<Config>> = OnceLock::new();
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
type SourceStamp = (String, Option<SystemTime>, Option<u64>);
type RejectedSource = (Option<SystemTime>, usize, Vec<SourceStamp>);
static REJECTED_SOURCE: Mutex<Option<RejectedSource>> = Mutex::new(None);

fn include_stamps(contents: &[(String, String)]) -> Vec<SourceStamp> {
    contents
        .iter()
        .map(|(name, _)| {
            let metadata = fs::metadata(data_dir().join(name)).ok();
            (
                name.clone(),
                metadata.as_ref().and_then(|meta| meta.modified().ok()),
                metadata.map(|meta| meta.len()),
            )
        })
        .collect()
}

pub(crate) fn set_data_dir(directory: Option<PathBuf>) -> std::io::Result<()> {
    let directory = directory.unwrap_or_else(data_dir);
    if let Some(existing) = DATA_DIR.get() {
        if existing != &directory {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "同一进程不能切换引擎配置目录",
            ));
        }
        return Ok(());
    }
    DATA_DIR
        .set(directory)
        .map_err(|_| std::io::Error::other("配置目录已初始化"))
}

/// Loads the source file, creating the default one when it does not exist yet.
/// Called once before the listener starts serving.
pub fn start() {
    crate::rules_runtime::recover_sources();
    let path = config_path();
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, DEFAULT_CONFIG);
            DEFAULT_CONFIG.to_string()
        }
    };
    let modified = fs::metadata(&path)
        .ok()
        .and_then(|meta| meta.modified().ok());
    let config = build(content, modified);
    let _ = CONFIG.set(Mutex::new(config));
}

fn current() -> MutexGuard<'static, Config> {
    CONFIG
        .get_or_init(|| Mutex::new(build(DEFAULT_CONFIG.to_string(), None)))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Every accepted write (including provider, membership, rule-order and Geo
/// updates) crosses the same hot-application boundary. Compare executable
/// values, not source digests: comments and source locations do not drop traffic.
fn publish(config: &mut Config, mut next: Config) {
    let rules_equal = |left: &[Rule], right: &[Rule]| {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(a, b)| a.condition == b.condition && a.outbound == b.outbound)
    };
    let dns_equal = |left: &[DnsRule], right: &[DnsRule]| {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(a, b)| a.condition == b.condition && a.upstream == b.upstream)
    };
    let routing_changed = config.nodes != next.nodes || config.groups != next.groups || !rules_equal(&config.rules,&next.rules) || config.fallback.outbound!=next.fallback.outbound;
    let changed_nodes=config.nodes.iter().filter(|old| !next.nodes.iter().any(|n|n==*old)).map(|n|format!("node-{}",n.name)).collect::<std::collections::HashSet<_>>();
    let changed = config.nodes != next.nodes
        || config.groups != next.groups
        || config.upstreams != next.upstreams
        || !rules_equal(&config.rules, &next.rules)
        || config.fallback.outbound != next.fallback.outbound
        || !dns_equal(&config.dns_rules, &next.dns_rules)
        || !dns_equal(&config.dns_response_rules, &next.dns_response_rules)
        || config.dns_request_fallback != next.dns_request_fallback
        || config.dns_response_fallback != next.dns_response_fallback
        || config.resource_revision != next.resource_revision;
    next.include_stamps = include_stamps(&next.include_contents);
    for group in &config.groups {
        if !next.groups.iter().any(|item| item.name == group.name) {
            crate::control::forget_group(&group.name);
        }
    }
    *config = next;
    if changed {
        let count = if routing_changed {crate::connections::configuration_changed_selective(|entry| {
            let Some(previous)=&entry.route else{return false};
            if previous.chain.iter().any(|id|changed_nodes.contains(id)){return false}
            let mut input=RoutingInput::new(&entry.host,entry.network);input.destination_port=Some(entry.port);input.source_ip=entry.source.map(|s|s.ip());input.source_port=entry.source.map(|s|s.port());input.process=previous.process.as_ref();
            let decision=decide_input(config,input,false);
            !decision.blocked() && decision.outbound==previous.outbound && decision.selection_path()==previous.chain
        })}else{0};
        crate::dns::flush();
        crate::compat::queue_hot_apply();
        logs::info(
            "engine::config",
            "Traffic configuration hot-applied; old tunnels retired.",
            Some(logs::fields(&[
                ("generation", &config.generation),
                ("connections_closed", &count.to_string()),
            ])),
        );
    }
}

/// Re-reads the source when its mtime or size changed. A failed read keeps the
/// last accepted snapshot: a transient editor save must not empty the rule set.
pub fn refresh() {
    let path = config_path();
    let Ok(metadata) = fs::metadata(&path) else {
        return;
    };
    let modified = metadata.modified().ok();
    let size = metadata.len() as usize;
    if size > MAX_BYTES {
        return;
    }
    let stamps = {
        let config = current();
        include_stamps(&config.include_contents)
    };
    if REJECTED_SOURCE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        == Some(&(modified, size, stamps.clone()))
    {
        return;
    }
    {
        let config = current();
        if config.bytes == size && config.modified == modified && config.include_stamps == stamps {
            return;
        }
    }
    let Ok(content) = fs::read_to_string(&path) else {
        return;
    };
    if content.len() > MAX_BYTES {
        return;
    }
    let mut config = current();
    if config.content == content && config.include_stamps == stamps {
        config.modified = modified;
        config.bytes = content.len();
        return;
    }
    let next = build(content, modified);
    if next
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.level == "error")
    {
        *REJECTED_SOURCE.lock().unwrap_or_else(|p| p.into_inner()) = Some((modified, size, stamps));
        drop(config);
        logs::warn(
            "engine::config",
            "Configuration reload rejected; the accepted generation is kept.",
            None,
        );
        return;
    }
    *REJECTED_SOURCE.lock().unwrap_or_else(|p| p.into_inner()) = None;
    let previous = config.generation.clone();
    let generation = next.generation.clone();
    publish(&mut config, next);
    drop(config);
    crate::events::generation_changed(&previous, &generation);
    logs::info(
        "engine::config",
        "Configuration source reloaded.",
        Some(logs::fields(&[("generation", &generation)])),
    );
}

/// Read-only access to the accepted snapshot for other modules.
pub fn with_current<T>(reader: impl FnOnce(&Config) -> T) -> T {
    reader(&current())
}

/// The accepted main source text, for text-level rewrites.
pub fn source_content() -> String {
    current().content.clone()
}

/// Re-reads and rebuilds the source even when mtime says nothing changed.
/// Returns the active generation afterwards.
pub fn force_reload() -> String {
    force_reload_checked().unwrap_or_else(|_| current().generation.clone())
}

pub(crate) fn force_reload_checked() -> Result<String, String> {
    let path = config_path();
    let content = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    if content.len() > MAX_BYTES {
        return Err("配置超过 max_bytes".to_owned());
    }
    let modified = fs::metadata(&path)
        .ok()
        .and_then(|meta| meta.modified().ok());
    let mut config = current();
    let built = build(content, modified);
    let errors = built
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.level == "error")
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Err(errors.join("；"));
    }
    let previous = config.generation.clone();
    let generation = built.generation.clone();
    publish(&mut config, built);
    drop(config);
    crate::events::generation_changed(&previous, &generation);
    Ok(generation)
}

/// The operation result body a reload/group update reports.
pub fn reload_result_json() -> String {
    let generation = json::escape(&generation());
    format!(r#"{{"active_generation_id":"{generation}","datapath_generation_id":"{generation}"}}"#)
}

/// Semantic validation: parses, resolves groups and rules, and reports every
/// error-level diagnostic. This is the `full` mode of config/validate.
pub fn validate_full(content: &str) -> (bool, String) {
    let parsed = parse(content);
    let names: Vec<String> = parsed.nodes.iter().map(|node| node.name.clone()).collect();
    let built = build_with_providers(content.to_owned(), None, &crate::providers::nodes(&names));
    let has_error = built.diagnostics.iter().any(|d| d.level == "error");
    (!has_error, diagnostics_json(&built.diagnostics))
}

/// Semantic validation of the accepted source set (after a file landed).
pub fn validate_full_now() -> (bool, String) {
    let content = source_content();
    validate_full(&content)
}

/// The upstream a DNS request rule picks for this name, if any.
#[cfg(test)]
pub fn dns_upstream_for(host: &str) -> Option<String> {
    dns_route_for(host, None).map(|(upstream, _)| upstream)
}

pub(crate) fn dns_route_for(host: &str, kind: Option<&str>) -> Option<(String, String)> {
    let config = current();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut input = RoutingInput::new(&host, "udp");
    input.query_type = kind;
    config
        .dns_rules
        .iter()
        .find(|rule| condition_matches_input(&rule.condition, &input))
        .map(|rule| (rule.upstream.clone(), rule.expression.clone()))
        .or_else(|| crate::rules_runtime::dns_route(&host, kind))
        .or_else(|| {
            config
                .dns_request_fallback
                .as_ref()
                .map(|action| (action.clone(), format!("fallback: {action}")))
        })
}

pub(crate) fn dns_response_action(
    host: &str,
    kind: Option<&str>,
    upstream: &str,
    answers: &[IpAddr],
) -> String {
    let config = current();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut input = RoutingInput::new(&host, "udp");
    input.query_type = kind;
    input.upstream = Some(upstream);
    input.answer_ips = answers;
    config
        .dns_response_rules
        .iter()
        .find(|rule| condition_matches_input(&rule.condition, &input))
        .map(|rule| rule.upstream.clone())
        .unwrap_or_else(|| config.dns_response_fallback.clone())
}

pub(crate) fn process_names() -> Vec<String> {process_names_for(&current())}
fn process_names_for(config:&Config)->Vec<String>{
    fn collect(condition: &Condition, values: &mut Vec<String>) {
        match condition {
            Condition::Process(names) => values.extend(names.iter().cloned()),
            Condition::RuleSet(set)=>values.extend(set.set.process_names()),
            Condition::Not(inner) => collect(inner, values),
            Condition::And(parts) | Condition::Any(parts) => {
                for part in parts {
                    collect(part, values);
                }
            }
            _ => {}
        }
    }
    let mut names = Vec::new();
    for rule in &config.rules {
        if let Some(condition) = &rule.condition {
            collect(condition, &mut names);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Rewrites one group's policy/default/final lines in the source text, keeping
/// every other line (including its filters) where it was.
pub fn rewrite_group(
    content: &str,
    group: &str,
    policy: Option<&str>,
    default: Option<Option<&str>>,
    final_outbound: Option<Option<&str>>,
) -> Result<String, String> {
    let lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let start = lines
        .iter()
        .position(|line| {
            line.trim()
                .strip_suffix('{')
                .is_some_and(|name| unquote(name) == group)
        })
        .ok_or_else(|| format!("group `{group}` 在源文件中不存在"))?;
    let mut end = start;
    for (offset, line) in lines.iter().enumerate().skip(start + 1) {
        if line.trim() == "}" {
            end = offset;
            break;
        }
    }
    let mut body: Vec<String> = Vec::new();
    for line in &lines[start + 1..end] {
        let trimmed = line.trim();
        if (policy.is_some() && trimmed.starts_with("policy:"))
            || (default.is_some() && trimmed.starts_with("default:"))
            || (final_outbound.is_some() && trimmed.starts_with("final:"))
        {
            continue;
        }
        body.push(line.clone());
    }
    if let Some(text) = policy {
        body.push(format!("    policy: {text}"));
    }
    if let Some(value) = default {
        if let Some(text) = value {
            body.push(format!("    default: {}", json::quoted(text)));
        }
    }
    if let Some(value) = final_outbound {
        if let Some(text) = value {
            body.push(format!("    final: {}", json::quoted(text)));
        }
    }
    let mut out: Vec<String> = Vec::new();
    out.extend_from_slice(&lines[..start + 1]);
    out.extend(body);
    out.extend_from_slice(&lines[end..]);
    let mut joined = out.join("\n");
    if content.ends_with('\n') {
        joined.push('\n');
    }
    Ok(joined)
}

/// Rebuilds the accepted snapshot after the provider store changed. The source
/// file, its digest and the revision stay as they were.
pub fn reload_providers() {
    let mut config = current();
    let previous = config.generation.clone();
    let next = build(config.content.clone(), config.modified);
    let generation = next.generation.clone();
    publish(&mut config, next);
    drop(config);
    crate::events::generation_changed(&previous, &generation);
}

/// A managed-node deletion is checked against the accepted source while its
/// publication lock is held. Failed validation/storage leaves both stores intact.
pub(crate) fn delete_managed_node(id: &str) -> Result<String, (u16, &'static str, String)> {
    refresh();
    let mut config = current();
    let name = id.strip_prefix("node-").unwrap_or(id);
    let Some(node) = config.nodes.iter().find(|node| node.name == name).cloned() else {
        return Ok(r#"{"deleted":0}"#.to_owned());
    };
    if node.provider.is_none() {
        return Err((
            404,
            "capability_not_supported",
            "该节点在配置文件中声明，请在配置页删除".to_owned(),
        ));
    }
    let mut references = config
        .rules
        .iter()
        .chain(std::iter::once(&config.fallback))
        .filter(|rule| rule.outbound == name)
        .map(|rule| format!("路由规则 {}", rule.line))
        .collect::<Vec<_>>();
    references.extend(
        config
            .groups
            .iter()
            .filter(|group| {
                [
                    &group.default,
                    &group.final_outbound,
                    &group.dialer,
                    &group.landing,
                ]
                .into_iter()
                .any(|value| value.as_deref() == Some(name))
            })
            .map(|group| format!("出站 {}", group.name)),
    );
    if !references.is_empty() {
        return Err((
            409,
            "state_conflict",
            format!("节点仍被{}引用，请先更换引用再删除", references.join("、")),
        ));
    }
    let names = parse(&config.content)
        .nodes
        .into_iter()
        .map(|node| node.name)
        .collect::<Vec<_>>();
    let mut accepted = None;
    let removed = crate::providers::remove_node_checked(&node, &names, |provider_nodes| {
        let next = build_with_providers(config.content.clone(), config.modified, &provider_nodes);
        let errors = next
            .diagnostics
            .iter()
            .filter(|row| row.level == "error")
            .map(|row| row.message.clone())
            .collect::<Vec<_>>();
        if !errors.is_empty() {
            return Err(format!("删除会使出站或链路失效：{}", errors.join("；")));
        }
        accepted = Some(next);
        Ok(())
    })?;
    if removed == 0 {
        return Ok(r#"{"deleted":0}"#.to_owned());
    }
    let previous = config.generation.clone();
    let next = accepted.expect("validated deletion snapshot");
    let generation = next.generation.clone();
    let groups = config
        .groups
        .iter()
        .map(|group| group.name.clone())
        .collect::<Vec<_>>();
    crate::control::forget_member(&groups, name);
    publish(&mut config, next);
    drop(config);
    crate::events::generation_changed(&previous, &generation);
    Ok(r#"{"deleted":1}"#.to_owned())
}

/// Keep the accepted configuration and both Geo assets on one rollback boundary.
pub(crate) fn replace_geodata(assets: &[(String, Vec<u8>)]) -> Result<String, String> {
    let _serial=crate::rules_runtime::APPLY.lock().unwrap_or_else(|p|p.into_inner());
    let before=crate::rules_runtime::current();
    let old_dns=crate::dns_settings::effective()?;
    let previous=assets.iter().map(|(kind,_)|{
        let path=data_dir().join(format!("{kind}.dat"));
        let bytes=match fs::read(&path) {Ok(bytes)=>Some(bytes),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>None,Err(e)=>return Err(format!("无法备份旧地理数据：{e}"))};
        Ok((path,bytes))
    }).collect::<Result<Vec<_>,String>>()?;
    let result=(||{
        for((_,bytes),(path,_))in assets.iter().zip(&previous){crate::storage::write_atomic(path,bytes).map_err(|e|e.to_string())?;}
        crate::geodata::invalidate();
        let snapshot=std::sync::Arc::new(crate::rules_runtime::compile(before.document.clone())?);
        apply_resources_impl(snapshot, &std::collections::HashMap::new(), None, true)
    })();
    if let Err(mut message)=result{
        for(path,bytes)in previous{
            let restored=if let Some(bytes)=bytes{crate::storage::write_atomic(&path,&bytes)}else{match fs::remove_file(&path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),other=>other}};
            if let Err(e)=restored{message.push_str(&format!("；恢复地理数据失败：{e}"));}
        }
        crate::geodata::invalidate();
        if let Err(e)=crate::compat::apply_dns_settings(&old_dns){message.push_str(&format!("；恢复 DNS 策略失败：{e}"));}
        return Err(message)
    }
    result
}

/// Every node name the merged configuration currently offers.
pub fn node_names() -> Vec<String> {
    refresh();
    current()
        .nodes
        .iter()
        .map(|node| node.name.clone())
        .collect()
}

/// Route with the connection metadata available at the inbound.
pub(crate) fn decide_connection(
    host: &str,
    port: u16,
    source: Option<SocketAddr>,
    network: &str,
) -> Decision {
    decide_connection_for(host, port, source, network, None, false)
}

pub(crate) fn decide_connection_for(
    host: &str,
    port: u16,
    source: Option<SocketAddr>,
    network: &str,
    process: Option<crate::platform::process::ProcessInfo>,
    bridged: bool,
) -> Decision {
    refresh();
    let process = process.or_else(|| {
        (!bridged)
            .then(|| source.and_then(|source| crate::platform::process::owner(source, network)))
            .flatten()
    });
    let mut input = RoutingInput::new(host, network);
    input.destination_port = Some(port);
    input.source_ip = source.map(|source| source.ip());
    input.source_port = source.map(|source| source.port());
    input.process = process.as_ref();
    fn needs_ip(condition: &Condition) -> bool {
        match condition {
            Condition::RuleSet(set) => !set.set.domain_only,
            Condition::GeoIp(_) | Condition::IpCidr(..) => true,
            Condition::Not(part) => needs_ip(part),
            Condition::And(parts) | Condition::Any(parts) => parts.iter().any(needs_ip),
            _ => false,
        }
    }
    let resolve = input.destination_ip.is_none()
        && current()
            .rules
            .iter()
            .any(|rule| rule.condition.as_ref().is_some_and(needs_ip));
    let addresses = if resolve {
        crate::dns::resolve(host).unwrap_or_default()
    } else {
        Vec::new()
    };
    input.answer_ips = &addresses;
    decide_input(&current(), input, true)
}

pub(crate) fn trace_input(input: RoutingInput<'_>) -> serde_json::Value {
    refresh();
    let config = current();
    let host = input.host.trim_end_matches('.').to_ascii_lowercase();
    let input = RoutingInput {
        host: &host,
        ..input
    };
    let mut rules = Vec::new();
    let mut missing = Vec::new();
    let mut outbound = None;
    for rule in config.rules.iter().chain(std::iter::once(&config.fallback)) {
        let (matched, absent) = rule
            .condition
            .as_ref()
            .map_or((Some(true), Vec::new()), |condition| {
                trace_condition(condition, &input)
            });
        rules.push(serde_json::json!({
            "rule_id":rule.id,"expression":rule.expression,
            "result":match matched { Some(true)=>"matched",Some(false)=>"not_matched",None=>"indeterminate" },
            "missing_inputs":absent,"conditions":[]
        }));
        if matched == Some(true) {
            outbound = Some(rule.outbound.clone());
            break;
        }
        if matched.is_none() {
            missing = absent;
            break;
        }
    }
    let chain = outbound
        .as_deref()
        .map(|name| proxy_chain::path(&config, name, input.network))
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({"generation_id":config.generation,"evaluation":{
        "dst_ip":input.destination_ip.map(|ip|ip.to_string()),
        "decision":if missing.is_empty(){"determinate"}else{"indeterminate"},
        "outbound":outbound,"missing_inputs":missing,"rules":rules,"x-lemonvpn-chain":chain
    }})
}

/// Simulation preserves unknown inputs, including under negation and compound
/// conditions. It must not claim a fallback is certain when metadata is absent.
fn trace_condition(
    condition: &Condition,
    input: &RoutingInput<'_>,
) -> (Option<bool>, Vec<&'static str>) {
    let missing = match condition {
        Condition::DomainFull(_)
        | Condition::DomainSuffix(_)
        | Condition::DomainKeyword(_)
        | Condition::GeoSite(_)
            if input.host.parse::<IpAddr>().is_ok() =>
        {
            Some("domain")
        }
        Condition::IpCidr(..) | Condition::GeoIp(_)
            if input.destination_ip.is_none() && input.answer_ips.is_empty() =>
        {
            Some("dst_ip")
        }
        Condition::RuleSet(set) if !set.set.known(input) => Some("rule_context"),
        Condition::SourceIpCidr(..) | Condition::SourceGeoIp(_) if input.source_ip.is_none() => {
            Some("src_ip")
        }
        Condition::SourcePort(_) if input.source_port.is_none() => Some("src_port"),
        Condition::DestinationPort(_) if input.destination_port.is_none() => Some("dst_port"),
        Condition::Process(_) if input.process.is_none() => Some("pname"),
        Condition::QueryType(_) if input.query_type.is_none() => Some("qtype"),
        Condition::Upstream(_) if input.upstream.is_none() => Some("upstream"),
        Condition::Not(inner) => {
            // The datapath only negates conditions whose metadata is known.
            // Do not short-circuit away a missing field inside a negated group.
            let absent = trace_missing(inner, input);
            if !absent.is_empty() {
                return (None, absent);
            }
            let (value, missing) = trace_condition(inner, input);
            return (value.map(|value| !value), missing);
        }
        Condition::And(parts) | Condition::Any(parts) => {
            let all = matches!(condition, Condition::And(_));
            let mut missing = Vec::new();
            for part in parts {
                let (value, absent) = trace_condition(part, input);
                if value == Some(!all) {
                    return (Some(!all), Vec::new());
                }
                if value.is_none() {
                    missing.extend(absent);
                }
            }
            missing.sort_unstable();
            missing.dedup();
            return (missing.is_empty().then_some(all), missing);
        }
        _ => None,
    };
    if let Some(name) = missing {
        (None, vec![name])
    } else {
        (Some(condition_matches_input(condition, input)), Vec::new())
    }
}

fn trace_missing(condition: &Condition, input: &RoutingInput<'_>) -> Vec<&'static str> {
    let mut missing = match condition {
        Condition::And(parts) | Condition::Any(parts) => parts
            .iter()
            .flat_map(|part| trace_missing(part, input))
            .collect(),
        Condition::Not(inner) => trace_missing(inner, input),
        _ => trace_condition(condition, input).1,
    };
    missing.sort_unstable();
    missing.dedup();
    missing
}

#[cfg(test)]
fn decide_from(config: &Config, host: &str) -> Decision {
    decide_input(config, RoutingInput::new(host, "tcp"), true)
}

fn decide_input(config: &Config, input: RoutingInput<'_>, advance: bool) -> Decision {
    let host = input.host.trim_end_matches('.').to_ascii_lowercase();
    let input = RoutingInput {
        host: &host,
        destination_ip: input.destination_ip.or_else(|| host.parse().ok()),
        ..input
    };
    let rule = config
        .rules
        .iter()
        .find(|rule| {
            rule.condition
                .as_ref()
                .is_some_and(|condition| condition_matches_input(condition, &input))
        })
        .unwrap_or(&config.fallback);
    let (target, chain, dependencies) = resolve_outbound_for(
        config,
        &rule.outbound,
        &mut Vec::new(),
        input.network,
        advance,
    )
    .unwrap_or((Target::Block, Vec::new(), vec![rule.outbound.clone()]));
    Decision {
        epoch: crate::connections::route_epoch_for(&dependencies, input.network),
        process: input.process.cloned(),
        outbound: rule.outbound.clone(),
        chain,
        dependencies,
        target,
        rule_id: rule.id.clone(),
        generation: config.generation.clone(),
        expression: rule.expression.clone(),
    }
}

fn resolve_outbound_for(
    config: &Config,
    name: &str,
    visiting: &mut Vec<String>,
    network: &str,
    advance: bool,
) -> Option<(Target, Vec<String>, Vec<String>)> {
    match name {
        "direct" => return Some((Target::Direct, Vec::new(), Vec::new())),
        "block" => return Some((Target::Block, Vec::new(), Vec::new())),
        _ => {}
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == name) {
        return Some((
            Target::Node(Box::new(node.clone())),
            vec![node.name.clone()],
            Vec::new(),
        ));
    }
    let group = config.groups.iter().find(|group| group.name == name)?;
    if visiting.len() >= 16 || visiting.iter().any(|seen| seen == name) {
        return None;
    }
    visiting.push(name.to_owned());
    let selected = select_member_for(group, config, network, advance);
    let result = if group.dialer.is_some() && group.landing.is_some() {
        resolve_outbound_for(
            config,
            group.landing.as_deref()?,
            visiting,
            network,
            advance,
        )
    } else {
        match selected {
            Some(member) => resolve_outbound_for(config, &member, visiting, network, advance),
            None => group.final_outbound.as_deref().and_then(|fallback| {
                resolve_outbound_for(config, fallback, visiting, network, advance)
            }),
        }
    };
    let result = result.and_then(|(target, path, mut dependencies)| {
        dependencies.insert(0, group.name.clone());
        let Some(via) = &group.dialer else {
            return Some((target, path, dependencies));
        };
        let (front, _, front_dependencies) =
            resolve_outbound_for(config, via, visiting, network, advance)?;
        let mut nodes = target_nodes(front)?;
        let front_len = nodes.len();
        nodes.extend(target_nodes(target)?);
        if nodes.len() > 8
            || nodes
                .iter()
                .enumerate()
                .any(|(i, node)| nodes[..i].iter().any(|seen| seen.name == node.name))
        {
            return None;
        }
        let exit_dependencies = dependencies.split_off(1);
        dependencies.extend(front_dependencies);
        dependencies.extend(exit_dependencies);
        let mut seen = HashSet::new();
        dependencies.retain(|name| seen.insert(name.clone()));
        let path = nodes.iter().map(|node| node.name.clone()).collect();
        Some((Target::Chain { nodes, front_len }, path, dependencies))
    });
    visiting.pop();
    result
}

fn target_nodes(target: Target) -> Option<Vec<Node>> {
    match target {
        Target::Node(node) => Some(vec![*node]),
        Target::Chain { nodes, .. } => Some(nodes),
        _ => None,
    }
}

fn select_member(group: &Group, config: &Config) -> Option<String> {
    select_member_for(group, config, "tcp", false)
}
fn select_member_for(
    group: &Group,
    config: &Config,
    network: &str,
    advance: bool,
) -> Option<String> {
    let members = &group.members;
    if members.is_empty() {
        return None;
    }
    // A pinned selection or manual choice from the API beats the policy.
    if let Some(name) = crate::control::selection_override_for(&group.name, network) {
        if members.contains(&name) {
            return Some(name);
        }
    }
    match group.policy {
        Policy::Selector => group
            .default
            .as_ref()
            .filter(|name| members.contains(name))
            .cloned()
            .or_else(|| members.first().cloned()),
        Policy::Fixed(index) => members.get(index).or_else(|| members.first()).cloned(),
        _ => crate::group_policy::select(group, &config.nodes, network, advance),
    }
    .filter(|name| config.nodes.iter().any(|node| &node.name == name))
}

#[cfg(test)]
pub fn revision() -> String {
    current().revision.clone()
}

pub fn generation() -> String {
    current().generation.clone()
}

pub fn upstreams() -> Vec<Upstream> {
    current().upstreams.clone()
}

pub struct GroupSnapshot {
    pub members: Vec<String>,
    pub selected: Option<String>,
    pub selected_udp: Option<String>,
}

/// The members and the current selection of one group, for a group probe.
pub fn group_snapshot(name: &str) -> Option<GroupSnapshot> {
    refresh();
    let config = current();
    let name = name.strip_prefix("group-").unwrap_or(name);
    let group = config.groups.iter().find(|group| group.name == name)?;
    let selected = select_member(group, &config);
    Some(GroupSnapshot {
        members: group.members.clone(),
        selected,
        selected_udp: select_member_for(group, &config, "udp", false),
    })
}

/// Every outbound the source names, so the outbound counters can report zeros
/// before traffic reaches them.
pub fn outbound_seed() -> Vec<(String, &'static str)> {
    refresh();
    let config = current();
    let mut seed = vec![
        ("direct".to_owned(), "builtin"),
        ("block".to_owned(), "builtin"),
    ];
    seed.extend(config.nodes.iter().map(|node| (node.name.clone(), "node")));
    seed.extend(
        config
            .groups
            .iter()
            .map(|group| (group.name.clone(), "group")),
    );
    seed
}

/// Explicit infrastructure egress, without re-routing the resolver/provider
/// server through the very DNS policy it is trying to establish.
pub(crate) fn connect_outbound(name: &str, host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
    let decision = infrastructure_decision(name, "tcp")?;
    if decision.blocked() {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "下载和 DNS 请求不能使用阻断出站"));
    }
    // Include actual infrastructure connections in the same success/failure
    // feedback as user traffic, so recovery does not depend on the probe URL.
    crate::proxy::connect(&decision, host, port)
}
pub(crate) fn infrastructure_decision(name: &str, network: &str) -> std::io::Result<Decision> {
    let config = current();
    let (target, chain, dependencies) = resolve_outbound_for(&config, name, &mut Vec::new(), network, false).ok_or_else(|| {
        let reason = match config.groups.iter().find(|group| group.name == name) {
            Some(group) if group.dialer.is_some() => "链式出站的前置或落地暂未选出成员",
            Some(group) if group.members.is_empty() => "策略组没有匹配的节点",
            Some(_) => "组内节点暂时处于连接失败后的退避期",
            None => "出站不存在或已移除",
        };
        std::io::Error::new(std::io::ErrorKind::NotConnected, format!("出站“{name}”无法选出 {network} 连接：{reason}"))
    })?;
    Ok(Decision {
        epoch: crate::connections::route_epoch_for(&dependencies, network),
        process: None,
        outbound: name.into(),
        chain,
        dependencies,
        target,
        rule_id: "infrastructure".into(),
        generation: config.generation.clone(),
        expression: format!("DNS/download via {name}"),
    })
}

pub(crate) fn apply_resources(snapshot:std::sync::Arc<crate::rules_runtime::Snapshot>)->Result<String,String>{
    apply_resources_with_sources(snapshot,&std::collections::HashMap::new())
}
pub(crate) fn apply_resources_with_sources(snapshot:std::sync::Arc<crate::rules_runtime::Snapshot>,sources:&std::collections::HashMap<String,String>)->Result<String,String>{apply_resources_checked(snapshot,sources,None)}
pub(crate) fn apply_resources_checked(snapshot:std::sync::Arc<crate::rules_runtime::Snapshot>,sources:&std::collections::HashMap<String,String>,expected:Option<&str>)->Result<String,String>{
    apply_resources_impl(snapshot, sources, expected, false)
}
fn apply_resources_impl(snapshot:std::sync::Arc<crate::rules_runtime::Snapshot>,sources:&std::collections::HashMap<String,String>,expected:Option<&str>,force:bool)->Result<String,String>{
    let mut config=current();
    if expected.is_some_and(|g|g!=config.generation){return Err("配置已被其他写入修改，请重新加载".into())}
    if !force&&sources.is_empty()&&snapshot.signature==crate::rules_runtime::current().signature{crate::rules_runtime::persist(&snapshot)?;crate::rules_runtime::install(snapshot);return Ok(config.generation.clone())}
    let main=sources.get(SOURCE_PATH).cloned().unwrap_or_else(||config.content.clone());
    let names=parse(&main).nodes.into_iter().map(|n|n.name).collect::<Vec<_>>();
    let next=crate::rules_runtime::with_candidate(snapshot.clone(),||build_with_sources(main,None,&crate::providers::nodes(&names),sources));
    let errors:Vec<_>=next.diagnostics.iter().filter(|d|d.level=="error").map(|d|d.message.clone()).collect();
    if !errors.is_empty(){return Err(errors.join("；"))}
    let allowed=|name:&str|name=="direct"||next.nodes.iter().any(|n|n.name==name)||next.groups.iter().any(|g|g.name==name);
    for resolver in &snapshot.document.resolvers{if !allowed(&resolver.outbound){return Err(format!("上游 {} 引用的出站不存在",resolver.name))}}
    for provider in &snapshot.document.providers{if !allowed(&provider.outbound){return Err(format!("规则集 {} 的下载出站不存在",provider.name))}}
    let mut originals=Vec::new();
    for name in sources.keys(){
        if !source_name_valid(name)||!(name==SOURCE_PATH||config.include_contents.iter().any(|(n,_)|n==name)){return Err("不能修改未知配置源".into())}
        let text=fs::read_to_string(data_dir().join(name)).map_err(|e|e.to_string())?;originals.push((name.clone(),text));
    }
    let old_processes=process_names_for(&config);let next_processes=process_names_for(&next);
    let old_dns=crate::dns_settings::effective()?;let new_dns=crate::dns_settings::effective_for(&snapshot)?;
    if !originals.is_empty(){crate::rules_runtime::source_journal(&snapshot.revision,&originals)?;}
    let applied=(||{
        for(name,content)in sources{crate::storage::write_atomic(&data_dir().join(name),content.as_bytes()).map_err(|e|e.to_string())?;}
        if old_processes!=next_processes{crate::compat::apply_process_names(next_processes.clone()).map_err(|e|e.to_string())?;}
        crate::compat::apply_dns_settings(&new_dns).map_err(|e|e.to_string())?;
        crate::compat::flush_tun_dns().map_err(|e|e.to_string())?;
        crate::rules_runtime::persist(&snapshot)
    })();
    if let Err(mut error)=applied{
        if old_processes!=next_processes{if let Err(e)=crate::compat::apply_process_names(old_processes){error.push_str(&format!("；进程条件恢复失败：{e}"));}}
        if let Err(rollback)=crate::compat::apply_dns_settings(&old_dns){error.push_str(&format!("；内核恢复失败：{rollback}"));}
        let mut restored=true;for(name,content)in &originals{if let Err(e)=crate::storage::write_atomic(&data_dir().join(name),content.as_bytes()){restored=false;error.push_str(&format!("；源文件恢复失败：{e}"));}}
        if restored{crate::rules_runtime::finish_source_journal();}return Err(error);
    }
    let previous=config.generation.clone();let generation=next.generation.clone();
    crate::rules_runtime::install(snapshot);publish(&mut config,next);drop(config);
    crate::rules_runtime::finish_source_journal();crate::events::generation_changed(&previous,&generation);Ok(generation)
}
pub(crate) fn refers_to(condition:&Condition,id:&str)->bool{match condition{Condition::RuleSet(set)=>set.id==id,Condition::Not(c)=>refers_to(c,id),Condition::And(parts)|Condition::Any(parts)=>parts.iter().any(|p|refers_to(p,id)),_=>false}}
pub(crate) fn resource_references(kind:&str,id:&str)->Vec<serde_json::Value>{
    let config=current();let mut rows=Vec::new();
    if kind=="provider"{for rule in config.rules.iter().filter(|r|r.line>0&&r.condition.as_ref().is_some_and(|c|refers_to(c,id))){rows.push(serde_json::json!({"scope":"source-routing","source_id":rule.source_id,"line":rule.line,"expression":rule.expression}));}}
    for rule in config.dns_rules.iter().chain(&config.dns_response_rules){if kind=="pool"&&rule.upstream==id||kind=="provider"&&refers_to(&rule.condition,id){rows.push(serde_json::json!({"scope":"source-dns","source_id":rule.source_id,"line":rule.line,"expression":rule.expression}));}}
    if kind=="pool"&&config.dns_request_fallback.as_deref()==Some(id){rows.push(serde_json::json!({"scope":"source-dns-fallback"}));}rows
}
pub(crate) fn rewrite_set_condition(expression:&str,id:&str,replacement:&str)->Result<String,String>{
    let pattern=format!(r#"(?P<lead>\bruleset\s*(?:\(\s*|:\s*)['"]?){}(?P<tail>['"]?\s*(?:\)|,))"#,regex::escape(id));
    let regex=regex::Regex::new(&pattern).map_err(|e|e.to_string())?;
    Ok(regex.replace_all(expression,format!("${{lead}}{replacement}${{tail}}")).into_owned())
}
pub(crate) fn rewrite_resource_sources(kind:&str,id:&str,replacement:Option<&str>)->Result<std::collections::HashMap<String,String>,String>{rewrite_resource_sources_from(kind,id,replacement,&std::collections::HashMap::new())}
pub(crate) fn rewrite_resource_sources_from(kind:&str,id:&str,replacement:Option<&str>,prior:&std::collections::HashMap<String,String>)->Result<std::collections::HashMap<String,String>,String>{
    let config=current();let mut originals=vec![(SOURCE_PATH.to_string(),config.content.clone())];originals.extend(config.include_contents.clone());let mut changes=prior.clone();
    for(name,original)in originals{let text=prior.get(&name).cloned().unwrap_or(original);
        let parsed=parse(&text);let mut lines=std::collections::HashSet::new();
        if kind=="provider"{for rule in &parsed.rules{if rule.condition.as_ref().is_some_and(|c|refers_to(c,id)){lines.insert(rule.line);}}}
        for rule in parsed.dns_rules.iter().chain(&parsed.dns_response_rules){if kind=="pool"&&rule.upstream==id||kind=="provider"&&refers_to(&rule.condition,id){lines.insert(rule.line);}}
        if kind=="pool"&&parsed.dns_request_fallback.as_deref()==Some(id){if let Some((line,_))=parsed.dns_request_fallback_source{lines.insert(line);}}
        if lines.is_empty(){continue}
        let mut updated=Vec::new();for(index,line)in text.lines().enumerate(){
            if !lines.contains(&(index as u32+1)){updated.push(line.to_string());continue}
            let Some(replacement)=replacement else{updated.push(format!("# Removed resource reference: {line}"));continue};
            if kind=="provider"{updated.push(rewrite_set_condition(line,id,replacement)?);}else if let Some((left,_))=line.split_once("->"){updated.push(format!("{left}-> '{replacement}'"));}else{let indent=line.len()-line.trim_start().len();updated.push(format!("{}fallback: '{replacement}'",&line[..indent]));}
        }
        changes.insert(name,updated.join("\n")+"\n");
    }Ok(changes)
}

/// Replaces the main source. The caller has already checked the revision; the
/// new text is parsed and becomes the accepted snapshot immediately.
#[cfg(test)]
pub fn replace(content: &str) -> Result<(), String> {
    replace_source(SOURCE_ID, content, None).map_err(|error| error.message)
}

pub(crate) struct SourceWriteError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}
fn write_error(status: u16, code: &'static str, message: impl Into<String>) -> SourceWriteError {
    SourceWriteError {
        status,
        code,
        message: message.into(),
    }
}
pub(crate) fn source_name_valid(name: &str) -> bool {
    name.ends_with(".dae")
        && name.len() <= 1024
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && !std::path::Path::new(name).is_absolute()
        && !name.contains(':')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(crate) fn replace_source(
    id: &str,
    content: &str,
    expected: Option<&str>,
) -> Result<(), SourceWriteError> {
    let _serial=crate::rules_runtime::APPLY.lock().unwrap_or_else(|p|p.into_inner());
    if content.len() > MAX_BYTES {
        return Err(write_error(413, "request_too_large", "配置超过 max_bytes"));
    }
    let main = id == SOURCE_ID || id == SOURCE_PATH;
    let name = if main {
        SOURCE_PATH.to_owned()
    } else {
        include_path(id).ok_or_else(|| write_error(404, "resource_not_found", "无效配置源"))?
    };
    if !source_name_valid(&name) {
        return Err(write_error(404, "resource_not_found", "无效配置源"));
    }
    let path = data_dir().join(&name);
    let config = current();
    let previous = fs::read_to_string(&path)
        .map_err(|error| write_error(404, "resource_not_found", error.to_string()))?;
    if expected.is_some_and(|expected| sha256::hex(previous.as_bytes()) != expected) {
        return Err(write_error(412, "stale_revision", "配置已被其他写入更新"));
    }
    let mut overlay = std::collections::HashMap::new();
    if !main {
        overlay.insert(name.clone(), content.to_owned());
    }
    let main_content = if main {
        content.to_owned()
    } else {
        config.content.clone()
    };
    let parsed = parse(&main_content);
    let names: Vec<_> = parsed.nodes.iter().map(|node| node.name.clone()).collect();
    let next = build_with_sources(
        main_content,
        None,
        &crate::providers::nodes(&names),
        &overlay,
    );
    let own = parse(content);
    if own
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.level == "error")
        || next
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.level == "error")
    {
        let errors = own
            .diagnostics
            .iter()
            .chain(next.diagnostics.iter())
            .filter(|diagnostic| diagnostic.level == "error")
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
            .join("；");
        return Err(write_error(422, "invalid_config", errors));
    }
    let generation=config.generation.clone();drop(config);
    let changes=std::collections::HashMap::from([(name,content.to_string())]);
    apply_resources_checked(crate::rules_runtime::current(),&changes,Some(&generation)).map_err(|e|write_error(422,"config_hot_apply_failed",e))?;
    Ok(())
}

pub(crate) fn validate_sources(sources: &[(String, String, String)], mode: &str) -> (bool, String) {
    if sources.is_empty() {
        return (false, "[]".to_owned());
    }
    let mut overlay = std::collections::HashMap::new();
    let mut diagnostics = Vec::new();
    for (id, path, content) in sources {
        overlay.insert(path.clone(), content.clone());
        let parsed = parse(content);
        for diagnostic in parsed.diagnostics {
            diagnostics.push(serde_json::json!({"level":diagnostic.level,"source_id":id,"line":diagnostic.line,"column":1,"span":null,"code":diagnostic.code,"message":diagnostic.message}));
        }
    }
    if mode == "full" {
        let first = &sources[0];
        let main = if first.1 == SOURCE_PATH || first.0 == SOURCE_ID {
            first.2.clone()
        } else {
            source_content()
        };
        let parsed = parse(&main);
        let names: Vec<_> = parsed.nodes.iter().map(|node| node.name.clone()).collect();
        let built = build_with_sources(main, None, &crate::providers::nodes(&names), &overlay);
        for diagnostic in built.diagnostics {
            if diagnostics.iter().any(|value| {
                value["code"] == diagnostic.code && value["message"] == diagnostic.message
            }) {
                continue;
            }
            diagnostics.push(serde_json::json!({"level":diagnostic.level,"source_id":first.0,"line":null,"column":null,"span":null,"code":diagnostic.code,"message":diagnostic.message}));
        }
    }
    diagnostics.dedup();
    let valid = diagnostics
        .iter()
        .all(|diagnostic| diagnostic["level"] != "error");
    (valid, serde_json::Value::Array(diagnostics).to_string())
}

/// Parses a candidate source without accepting it; the API validates a body
/// before a caller writes it.
#[cfg(test)]
pub fn validate(content: &str) -> (bool, String) {
    let parsed = build(content.to_owned(), None);
    let valid = !parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.level == "error");
    (valid, diagnostics_json(&parsed.diagnostics))
}

pub fn current_sha256() -> String {
    refresh();
    current().sha256.clone()
}

/// One source with its content, as `GET /config/sources/{source_id}` returns it.
fn source_id_for_path(path: &str) -> String {
    format!("source-file-{}", &sha256::hex(path.as_bytes())[..24])
}
fn include_path(id: &str) -> Option<String> {
    if id.starts_with("source-file-") && !id.ends_with(".dae") {
        current()
            .include_contents
            .iter()
            .find(|(path, _)| source_id_for_path(path) == id)
            .map(|(path, _)| path.clone())
    } else {
        source_name_valid(id).then(|| id.to_owned())
    }
}

pub fn config_source_json(id: &str) -> Option<String> {
    if id != SOURCE_ID && id != SOURCE_PATH {
        let path = include_path(id)?;
        if !source_name_valid(&path) {
            return None;
        }
        let content = fs::read_to_string(data_dir().join(&path)).ok()?;
        return Some(serde_json::json!({"id":source_id_for_path(&path),"path":path,"kind":"include","content_sha256":sha256::hex(content.as_bytes()),"bytes":content.len(),"content":content,"line_count":content.lines().count(),"writable":true,"loaded_at":null}).to_string());
    }
    refresh();
    let config = current();
    let content = fs::read_to_string(config_path()).ok()?;
    let loaded_at = (content == config.content).then(|| state::iso8601(config.loaded_at));
    Some(serde_json::json!({"id":SOURCE_ID,"path":SOURCE_PATH,"kind":"main","content_sha256":sha256::hex(content.as_bytes()),"bytes":content.len(),"content":content,"line_count":content.lines().count(),"writable":true,"loaded_at":loaded_at}).to_string())
}

pub fn effective_json() -> String {
    refresh();
    let config = current();
    let mut sources = vec![
        serde_json::json!({"id":SOURCE_ID,"path":SOURCE_PATH,"kind":"main","content_sha256":config.sha256,"bytes":config.bytes,"content":config.content,"line_count":config.content.lines().count(),"writable":true,"loaded_at":state::iso8601(config.loaded_at)}),
    ];
    for (id, content) in &config.include_contents {
        sources.push(serde_json::json!({"id":source_id_for_path(id),"path":id,"kind":"include","content_sha256":sha256::hex(content.as_bytes()),"bytes":content.len(),"content":content,"line_count":content.lines().count(),"writable":true,"loaded_at":state::iso8601(config.loaded_at)}));
    }
    let diagnostics: serde_json::Value =
        serde_json::from_str(&diagnostics_json(&config.diagnostics))
            .unwrap_or_else(|_| serde_json::json!([]));
    serde_json::json!({"generation_id":config.generation,"revision":config.revision,"sources":sources,"diagnostics":diagnostics,"secrets_redacted":false}).to_string()
}

pub fn rules_json() -> String {
    refresh();
    let config = current();
    let mut entries = Vec::with_capacity(config.rules.len() + 1);
    for rule in config.rules.iter().filter(|r|r.line>0).chain(std::iter::once(&config.fallback)) {
        let source = source_json(rule.line, rule.source_id.as_deref());
        let kind = if rule.condition.is_some() {
            "rule"
        } else {
            "fallback"
        };
        entries.push(format!(
            r#"{{"rule_id":"{}","index":{},"expression":"{}","outbound":"{}","must":false,"source":{},"kind":"{}"}}"#,
            rule.id,
            rule.index,
            json::escape(&rule.expression),
            json::escape(&rule.outbound),
            source,
            kind
        ));
    }
    let fallback_source = source_json(config.fallback.line, config.fallback.source_id.as_deref());
    format!(
        r#"{{"generation_id":"{}","rules":[{}],"fallback":{{"outbound":"{}","source":{}}}}}"#,
        config.generation,
        entries.join(","),
        json::escape(&config.fallback.outbound),
        fallback_source
    )
}

pub(crate) fn source_json(line: u32, source: Option<&str>) -> String {
    if line == 0 {
        return "null".to_string();
    }
    format!(
        r#"{{"file":"{}","source_id":"{}","line":{},"column":1}}"#,
        json::escape(source.unwrap_or(SOURCE_PATH)),
        source
            .map(source_id_for_path)
            .unwrap_or_else(|| SOURCE_ID.to_owned()),
        line
    )
}

fn diagnostics_json(diagnostics: &[Diagnostic]) -> String {
    let entries = diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                r#"{{"level":"{}","source_id":"{}","line":{},"column":1,"span":null,"code":"{}","message":"{}"}}"#,
                diagnostic.level,
                SOURCE_ID,
                diagnostic.line,
                diagnostic.code,
                json::escape(&diagnostic.message)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}

/// Nodes with the groups that actually contain them. `group_id` filters to one
/// group (`group-<name>`), matching what `Node.group_ids` reports.
pub fn nodes_json(group_id: Option<&str>) -> String {
    refresh();
    nodes_body(&current(), group_id)
}

fn nodes_body(config: &Config, group_id: Option<&str>) -> String {
    let wanted = group_id
        .and_then(|id| id.strip_prefix("group-"))
        .or(group_id);
    let mut entries = Vec::new();
    for node in &config.nodes {
        let groups: Vec<&Group> = config
            .groups
            .iter()
            .filter(|group| group.members.iter().any(|member| member == &node.name))
            .collect();
        if let Some(wanted) = wanted {
            if !groups.iter().any(|group| group.name == wanted) {
                continue;
            }
        }
        entries.push(node_entry(node, &groups));
    }
    format!(
        r#"{{"observed_at":"{}","nodes":[{}],"next_cursor":null}}"#,
        state::iso8601(SystemTime::now()),
        entries.join(",")
    )
}

fn optional(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(json::quoted)
        .unwrap_or_else(|| "null".to_owned())
}

fn node_entry(node: &Node, groups: &[&Group]) -> String {
    let group_ids = groups
        .iter()
        .map(|group| format!("\"group-{}\"", json::escape(&group.name)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"id":"node-{}","name":"{}","protocol":"{}","stream_transport":"{}","subscription_tag":{},"provider_id":{},"group_ids":[{}],"health":{}}}"#,
        json::escape(&node.name),
        json::escape(&node.name),
        json::escape(&node.protocol),
        json::escape(&crate::compat::stream_transport(node)),
        optional(&node.subscription_tag),
        optional(&node.provider),
        group_ids,
        crate::probes::health_json(&format!("node-{}", node.name))
    )
}

/// One node by its API ID (`node-<name>`), including the latest health samples.
pub fn node_json(id: &str) -> Option<String> {
    refresh();
    let config = current();
    let name = id.strip_prefix("node-").unwrap_or(id);
    let node = config.nodes.iter().find(|node| node.name == name)?;
    let groups: Vec<&Group> = config
        .groups
        .iter()
        .filter(|group| group.members.iter().any(|member| member == &node.name))
        .collect();
    Some(node_entry(node, &groups))
}

/// The current node with this API ID, cloned so a reload cannot change it
/// while a probe is running.
pub fn node(id: &str) -> Option<Node> {
    refresh();
    let name = id.strip_prefix("node-").unwrap_or(id);
    current()
        .nodes
        .iter()
        .find(|node| node.name == name)
        .cloned()
}

pub fn groups_json() -> String {
    refresh();
    groups_body(&current())
}

fn group_selection(config: &Config, group: &Group) -> serde_json::Value {
    let row = |network: &str| {
        if group.dialer.is_some() && group.landing.is_some() {
            return resolve_outbound_for(config, &group.name, &mut Vec::new(), network, false).and_then(|(_, nodes, _)| nodes.last().cloned()).map(|member|serde_json::json!({"member_id":format!("node-{member}"),"resolved_leaf_node_id":format!("node-{member}"),"source":"policy"}));
        }
        select_member_for(group,config,network,false).map(|member|{
        let source=if crate::control::selection_override_for(&group.name,network).is_some(){if matches!(group.policy,Policy::Selector){"runtime"}else{"override"}}else{"policy"};
        serde_json::json!({"member_id":format!("node-{member}"),"resolved_leaf_node_id":format!("node-{member}"),"source":source})
    })
    };
    serde_json::json!({"tcp":row("tcp"),"udp":row("udp")})
}

pub(crate) fn group_selection_snapshot(id: &str) -> Option<(String, serde_json::Value)> {
    refresh();
    let config = current();
    let name = id.strip_prefix("group-").unwrap_or(id);
    let group = config.groups.iter().find(|group| group.name == name)?;
    let selection = group_selection(&config, group);
    let revision =
        sha256::hex(format!("{}:{}:{selection}", config.revision, group.name).as_bytes());
    Some((revision, selection))
}

fn groups_body(config: &Config) -> String {
    let entries = config
        .groups
        .iter()
        .map(|group| {
            let current = group_selection(config,group);
            let selection = serde_json::json!({"tcp_member_id":current["tcp"]["member_id"],"udp_member_id":current["udp"]["member_id"]});
            format!(
                r#"{{"id":"group-{}","name":"{}","icon":null,"config_revision":"{}","policy":{{"kind":"{}","native":"{}"}},"member_count":{},"selection":{},"x-lemonvpn-chain":{}}}"#,
                json::escape(&group.name),
                json::escape(&group.name),
                config.revision,
                group.policy.kind(),
                json::escape(&group.policy.native()),
                group.members.len(),
                selection,
                group.dialer.is_some()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}

/// A group's details, including its members and the selection the datapath uses.
pub fn group_json(id: &str) -> Option<String> {
    refresh();
    group_body(&current(), id)
}

fn group_body(config: &Config, id: &str) -> Option<String> {
    let name = id.strip_prefix("group-").unwrap_or(id);
    let group = config.groups.iter().find(|group| group.name == name)?;
    let members = group
        .members
        .iter()
        .map(|member| {
            format!(
                r#"{{"id":"node-{}","name":"{}","kind":"node"}}"#,
                json::escape(member),
                json::escape(member)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let selection = group_selection(config, group);
    let body = format!(
        concat!(
            r#"{{"id":"group-{}","name":"{}","icon":null,"config_revision":"{}","#,
            r#""policy":{{"kind":"{}","native":"{}"}},"#,
            r#""members":[{}],"#,
            r#""config":{{"default_member_id":{},"final_outbound":{},"check_url":null,"check_interval":null,"tolerance":null,"idle_timeout":null,"interrupt_connections":true}},"#,
            r#""runtime":{{"selection":{},"health":[]}},"#,
            r#""capabilities":{{"can_select":{can_select},"can_override":{can_override},"supports_nested_groups":false,"mutable_config":{mutable},"probe_transports":{transports}}}}}"#
        ),
        json::escape(&group.name),
        json::escape(&group.name),
        config.revision,
        group.policy.kind(),
        json::escape(&group.policy.native()),
        members,
        group
            .default
            .as_ref()
            .map(|member| format!("\"node-{}\"", json::escape(member)))
            .unwrap_or_else(|| "null".to_string()),
        group
            .final_outbound
            .as_ref()
            .map(|outbound| json::quoted(outbound))
            .unwrap_or_else(|| "null".to_string()),
        selection,
        transports = crate::probes::transports_json(),
        can_select = group.dialer.is_none() && matches!(group.policy, Policy::Selector),
        can_override = group.dialer.is_none() && !matches!(group.policy, Policy::Selector),
        mutable = if config.content.lines().any(|line| line
            .trim()
            .strip_suffix('{')
            .is_some_and(|name| unquote(name) == group.name))
        {
            r#"["policy","default_member_id","final_outbound"]"#
        } else {
            "[]"
        }
    );
    let mut body: serde_json::Value = serde_json::from_str(&body).ok()?;
    body["x-lemonvpn-chain"] = proxy_chain::preview(config, group);
    Some(body.to_string())
}

/// One read boundary for current selections and actual retained connections.
pub(crate) fn chain_activity_snapshot(
    id: &str,
) -> Option<(serde_json::Value, Vec<crate::connections::Snapshot>)> {
    refresh();
    let config = current();
    let name = id.strip_prefix("group-")?;
    let group = config
        .groups
        .iter()
        .find(|group| group.name == name && group.dialer.is_some())?;
    Some((
        proxy_chain::preview(&config, group),
        crate::connections::snapshot_group(id),
    ))
}

/// Where the source, the provider store and the other state files live.
pub fn data_dir() -> PathBuf {
    if let Some(directory) = DATA_DIR.get() {
        return directory.clone();
    }
    match std::env::var_os("LEMONVPN_DATA_DIR") {
        Some(directory) => PathBuf::from(directory),
        None => default_data_dir(),
    }
}

fn config_path() -> PathBuf {
    data_dir().join(SOURCE_PATH)
}

fn default_data_dir() -> PathBuf {
    crate::platform::current().default_data_dir()
}

struct RawRule {
    expression: String,
    outbound: String,
    condition: Option<Condition>,
    line: u32,
    source_id: Option<String>,
}

#[derive(Default)]
struct Parsed {
    rules: Vec<RawRule>,
    fallback: Option<RawRule>,
    nodes: Vec<Node>,
    groups: Vec<RawGroup>,
    upstreams: Vec<Upstream>,
    dns_rules: Vec<DnsRuleRaw>,
    dns_response_rules: Vec<DnsRuleRaw>,
    dns_request_fallback: Option<String>,
    dns_response_fallback: Option<String>,
    dns_request_fallback_source: Option<(u32, Option<String>)>,
    dns_response_fallback_source: Option<(u32, Option<String>)>,
    includes: Vec<String>,
    diagnostics: Vec<Diagnostic>,
}

struct RawGroup {
    name: String,
    filters: Vec<String>,
    policy: Option<Policy>,
    default: Option<String>,
    final_outbound: Option<String>,
    dialer: Option<String>,
    landing: Option<String>,
    line: u32,
}

struct DnsRuleRaw {
    expression: String,
    condition: Condition,
    upstream: String,
    line: u32,
    source_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ctx {
    Node,
    GroupRoot,
    Group(String),
    DnsRoot,
    DnsUpstream,
    DnsRequest,
    DnsResponse,
    DnsRouting,
    Routing,
    Ignored,
}

fn build(content: String, modified: Option<SystemTime>) -> Config {
    let parsed = parse(&content);
    let names: Vec<String> = parsed.nodes.iter().map(|node| node.name.clone()).collect();
    build_with_providers(content, modified, &crate::providers::nodes(&names))
}

/// The provider roster is injected so tests can parse a source without the
/// machine's on-disk subscription storage leaking into the assertions.
fn build_with_providers(
    content: String,
    modified: Option<SystemTime>,
    provider_nodes: &[Node],
) -> Config {
    build_with_sources(
        content,
        modified,
        provider_nodes,
        &std::collections::HashMap::new(),
    )
}

fn build_with_sources(
    content: String,
    modified: Option<SystemTime>,
    provider_nodes: &[Node],
    sources: &std::collections::HashMap<String, String>,
) -> Config {
    let sha256 = sha256::hex(content.as_bytes());
    let mut parsed = parse(&content);
    merge_includes(&mut parsed, sources);
    let resources = crate::rules_runtime::current();
    for (binding, condition) in &resources.bindings {
        parsed.rules.push(RawRule {source_id: None, expression: format!("{} -> {}", binding.condition, binding.outbound), outbound: binding.outbound.clone(), condition: Some(condition.clone()), line: 0});
    }
    for pool in &resources.document.pools {
        if parsed.upstreams.iter().any(|p|p.name==pool.id) { parsed.diagnostics.push(diagnostic(0,"dns_pool_collision",format!("解析池 ID {} 与旧上游名称冲突",pool.id))); }
        parsed.upstreams.push(Upstream{name:pool.id.clone(),protocol:"pool",host:pool.id.clone(),port:0});
    }
    let mut generation_seed = sha256.clone();
    generation_seed.push_str(&resources.signature);
    let mut include_contents = Vec::new();
    for name in &parsed.includes {
        let text = sources
            .get(name)
            .cloned()
            .or_else(|| fs::read_to_string(data_dir().join(name)).ok())
            .unwrap_or_default();
        generation_seed.push_str(&sha256::hex(text.as_bytes()));
        include_contents.push((name.clone(), text));
    }
    generation_seed.push_str(&format!("{provider_nodes:?}"));
    // Geo data changes invalidate DNS caches and routing evidence even if text stays the same.
    for condition in parsed
        .rules
        .iter()
        .filter_map(|rule| rule.condition.as_ref())
        .chain(parsed.dns_rules.iter().map(|rule| &rule.condition))
        .chain(parsed.dns_response_rules.iter().map(|rule| &rule.condition))
    {
        generation_seed.push_str(&format!("{condition:?}"));
    }
    let mut process_names = Vec::new();
    fn processes(condition: &Condition, names: &mut Vec<String>) {
        match condition {
            Condition::Process(values) => names.extend(values.iter().cloned()),
            Condition::RuleSet(set)=>names.extend(set.set.process_names()),
            Condition::Not(inner) => processes(inner, names),
            Condition::Any(parts) | Condition::And(parts) => {
                for part in parts {
                    processes(part, names);
                }
            }
            _ => {}
        }
    }
    for rule in &parsed.rules {
        if let Some(condition) = &rule.condition {
            processes(condition, &mut process_names);
        }
    }
    process_names.sort();
    process_names.dedup();
    if process_names.len() > 256 || process_names.iter().map(String::len).sum::<usize>() > 32768 {
        parsed.diagnostics.push(diagnostic(
            0,
            "process_rule_limit",
            "进程条件最多引用 256 个名称，合计不超过 32 KiB".to_owned(),
        ));
    }

    let effective_sha = sha256::hex(generation_seed.as_bytes());
    // Provider nodes join the same table as the source's own nodes, so group
    // filters and routing see one flat roster. The source file and its digest
    // are untouched; the merged view is what every reader gets.
    parsed.nodes.extend(provider_nodes.iter().cloned());
    let fallback = match parsed.fallback.take() {
        Some(rule) => rule,
        None => {
            parsed.diagnostics.push(Diagnostic {
                level: "warning",
                line: 0,
                code: "fallback_missing",
                message: "routing has no fallback; using direct".to_string(),
            });
            RawRule {
                source_id: None,
                expression: "fallback: direct".to_string(),
                outbound: "direct".to_string(),
                condition: None,
                line: 0,
            }
        }
    };

    // Outbound names are validated once every node and group is known.
    let groups = resolve_groups(&parsed.groups, &parsed.nodes, &mut parsed.diagnostics);

    let mut valid: HashSet<String> = HashSet::new();
    valid.insert("direct".to_owned());
    valid.insert("block".to_owned());
    for node in &parsed.nodes {
        valid.insert(node.name.clone());
    }
    for group in &groups {
        valid.insert(group.name.clone());
    }

    let mut rules = Vec::new();
    for raw in parsed.rules {
        if !valid.contains(&raw.outbound) {
            parsed.diagnostics.push(diagnostic(
                raw.line,
                "rule_outbound",
                format!(
                    "routing outbound `{}` is not direct, block, a node or a group",
                    raw.outbound
                ),
            ));
            continue;
        }
        rules.push(raw);
    }
    let fallback = if valid.contains(&fallback.outbound) {
        fallback
    } else {
        parsed.diagnostics.push(Diagnostic {
            level: "error",
            line: fallback.line,
            code: "fallback_outbound",
            message: format!(
                "fallback outbound `{}` is not direct, block, a node or a group; using direct",
                fallback.outbound
            ),
        });
        RawRule {
            source_id: None,
            expression: "fallback: direct".to_string(),
            outbound: "direct".to_string(),
            condition: None,
            line: fallback.line,
        }
    };

    let rules: Vec<Rule> = rules
        .into_iter()
        .enumerate()
        .map(|(index, raw)| Rule {
            source_id: raw.source_id,
            id: format!("traffic:{index}"),
            index,
            expression: raw.expression,
            outbound: raw.outbound,
            condition: raw.condition,
            line: raw.line,
        })
        .collect();
    let fallback = Rule {
        source_id: fallback.source_id,
        id: format!("traffic:{}", rules.len()),
        index: rules.len(),
        expression: fallback.expression,
        outbound: fallback.outbound,
        condition: None,
        line: fallback.line,
    };
    let mut make_dns_rules = |raws: Vec<DnsRuleRaw>, response: bool| {
        raws.into_iter()
            .filter_map(|raw| {
                let special = crate::dns::reply_code(&raw.upstream).is_some() || (response && raw.upstream == "accept");
                if !special
                    && !parsed
                        .upstreams
                        .iter()
                        .any(|upstream| upstream.name == raw.upstream)
                {
                    parsed.diagnostics.push(diagnostic(
                        raw.line,
                        if raw.upstream == "asis" { "dns_action_unsupported" } else { "dns_upstream" },
                        if raw.upstream == "asis" {
                            "当前共享引擎不支持 DNS asis（转发至原始目标）动作，请选择已配置的 DNS 上游".to_owned()
                        } else { format!("DNS 规则引用的上游 `{}` 不存在", raw.upstream) },
                    ));
                    return None;
                }
                Some(DnsRule {
                    source_id: raw.source_id,
                    expression: raw.expression,
                    condition: raw.condition,
                    upstream: raw.upstream,
                    line: raw.line,
                })
            })
            .collect::<Vec<_>>()
    };
    let dns_rules = make_dns_rules(std::mem::take(&mut parsed.dns_rules), false);
    let dns_response_rules = make_dns_rules(std::mem::take(&mut parsed.dns_response_rules), true);
    for (fallback, response) in [
        (&parsed.dns_request_fallback, false),
        (&parsed.dns_response_fallback, true),
    ] {
        if let Some(action) = fallback {
            if crate::dns::reply_code(action).is_none()
                && !(response && action == "accept")
                && !parsed
                    .upstreams
                    .iter()
                    .any(|upstream| &upstream.name == action)
            {
                parsed.diagnostics.push(diagnostic(
                    0,
                    if action == "asis" {
                        "dns_action_unsupported"
                    } else {
                        "dns_upstream"
                    },
                    if action == "asis" {
                        "当前共享引擎不支持 DNS asis 兜底，请选择已配置的 DNS 上游".to_owned()
                    } else {
                        format!("DNS fallback 上游 `{action}` 不存在")
                    },
                ));
            }
        }
    }
    for (name,outbound) in resources.document.resolvers.iter().map(|r|(&r.name,&r.outbound)).chain(resources.document.providers.iter().map(|p|(&p.name,&p.outbound))){
        if outbound!="direct"&&!parsed.nodes.iter().any(|n|&n.name==outbound)&&!groups.iter().any(|g|&g.name==outbound){parsed.diagnostics.push(diagnostic(0,"resource_outbound",format!("资源 {name} 引用的出站 {outbound} 不存在或不适用于基础设施连接")));}
    }
    Config {
        resource_revision: resources.signature.clone(),
        generation: format!("generation-{}", &effective_sha[..16]),
        revision: sha256.clone(),
        sha256,
        bytes: content.len(),
        content,
        rules,
        fallback,
        nodes: parsed.nodes,
        groups,
        upstreams: parsed.upstreams,
        dns_rules,
        dns_response_rules,
        dns_request_fallback: parsed.dns_request_fallback,
        dns_request_fallback_source: parsed.dns_request_fallback_source,
        dns_response_fallback_source: parsed.dns_response_fallback_source,
        dns_response_fallback: parsed
            .dns_response_fallback
            .unwrap_or_else(|| "accept".to_owned()),
        include_stamps: include_stamps(&include_contents),
        include_contents,
        diagnostics: parsed.diagnostics,
        loaded_at: SystemTime::now(),
        modified,
    }
}

fn resolve_groups(
    raw_groups: &[RawGroup],
    nodes: &[Node],
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Group> {
    let node_names: Vec<&str> = nodes.iter().map(|node| node.name.as_str()).collect();
    let mut resolved: Vec<Group> = Vec::new();
    let mut waiting = raw_groups
        .iter()
        .map(|raw| {
            (
                raw,
                raw.filters
                    .iter()
                    .flat_map(|filter| {
                        crate::group_filter::dependencies(filter).unwrap_or_default()
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let mut ready = HashSet::new();
    let mut ordered = Vec::new();
    while !waiting.is_empty() {
        let Some(index) = waiting
            .iter()
            .position(|(_, dependencies)| dependencies.iter().all(|name| ready.contains(name)))
        else {
            diagnostics.push(diagnostic(
                waiting[0].0.line,
                "group_filter",
                "组筛选存在循环或引用了不存在的策略组".to_owned(),
            ));
            ordered.extend(waiting.into_iter().map(|(raw, _)| raw));
            break;
        };
        let (raw, _) = waiting.remove(index);
        ready.insert(raw.name.clone());
        ordered.push(raw);
    }
    for raw in ordered {
        let Some(policy) = raw.policy else {
            diagnostics.push(diagnostic(
                raw.line,
                "group_policy",
                format!(
                    "group `{}` has no supported policy (select, min_moving_avg, min_avg10, min_last_delay, score, fallback, roundrobin, fixed(n) or random)",
                    raw.name
                ),
            ));
            continue;
        };
        // An omitted filter means every node, matching the editor's 'all nodes' choice.
        let mut members: Vec<String> = if raw.filters.is_empty() {
            node_names.iter().map(|name| (*name).to_owned()).collect()
        } else {
            Vec::new()
        };
        for filter in &raw.filters {
            match crate::group_filter::evaluate(filter, &resolved, nodes) {
                Ok(found) => {
                    for name in found {
                        if !members.contains(&name) {
                            members.push(name);
                        }
                    }
                }
                Err(message) => diagnostics.push(diagnostic(
                    raw.line,
                    "group_filter",
                    format!("group `{}`: {message}", raw.name),
                )),
            }
        }
        if raw.dialer.is_some() && raw.landing.is_some() {
            members.clear();
        }
        if let Some(default) = &raw.default {
            if !members.contains(default) {
                diagnostics.push(Diagnostic {
                    level: "warning",
                    line: raw.line,
                    code: "group_default",
                    message: format!(
                        "group `{}` default `{default}` is not one of its members",
                        raw.name
                    ),
                });
            }
        }
        resolved.push(Group {
            name: raw.name.clone(),
            policy,
            default: raw.default.clone(),
            final_outbound: raw.final_outbound.clone(),
            dialer: raw.dialer.clone(),
            landing: raw.landing.clone(),
            members,
        });
    }
    proxy_chain::validate(raw_groups, &resolved, nodes, diagnostics);
    resolved
}

fn parse(content: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut stack: Vec<Ctx> = Vec::new();
    let mut group: Option<RawGroup> = None;
    let mut upstream_block = false;

    fn strip_comment(line: &str) -> &str {
        // `#` only starts a comment outside quotes: node names, passwords and
        // filters legitimately contain it inside quoted values.
        let mut open: Option<char> = None;
        let mut escaped = false;
        for (index, character) in line.char_indices() {
            if open.is_some() && escaped {
                escaped = false;
                continue;
            }
            if open.is_some() && character == '\\' {
                escaped = true;
                continue;
            }
            match open {
                Some(quote) if character == quote => open = None,
                Some(_) => {}
                None if character == '\'' || character == '"' => open = Some(character),
                None if character == '#' => return &line[..index],
                None => {}
            }
        }
        line
    }

    for (offset, raw) in content.lines().enumerate() {
        let line = (offset + 1) as u32;
        let text = strip_comment(raw).trim();
        if text.is_empty() {
            continue;
        }
        if let Some(open) = text.strip_suffix('{') {
            let open = open.trim();
            let context = stack.last().cloned();
            let next = match (&context, open) {
                (None, "node") => Ctx::Node,
                (None, "group") => Ctx::GroupRoot,
                (None, "dns") => Ctx::DnsRoot,
                (None, "routing") => Ctx::Routing,
                (Some(Ctx::GroupRoot), name) if !name.is_empty() => {
                    let name = unquote(name);
                    group = Some(RawGroup {
                        name: name.clone(),
                        filters: Vec::new(),
                        policy: None,
                        default: None,
                        final_outbound: None,
                        dialer: None,
                        landing: None,
                        line,
                    });
                    Ctx::Group(name)
                }
                (Some(Ctx::DnsRoot), "upstream") => {
                    upstream_block = true;
                    Ctx::DnsUpstream
                }
                (Some(Ctx::DnsRoot), "routing") => Ctx::DnsRouting,
                (Some(Ctx::DnsRoot | Ctx::DnsRouting), "request") => Ctx::DnsRequest,
                (Some(Ctx::DnsRoot | Ctx::DnsRouting), "response") => Ctx::DnsResponse,
                _ => Ctx::Ignored,
            };
            stack.push(next);
            continue;
        }
        if text == "}" {
            if let Some(Ctx::Group(name)) = stack.last().cloned() {
                if let Some(raw_group) = group.take() {
                    if raw_group.name == name {
                        parsed.groups.push(raw_group);
                    }
                }
            }
            if let Some(Ctx::DnsUpstream) = stack.last() {
                upstream_block = false;
            }
            if stack.pop().is_none() {
                parsed.diagnostics.push(diagnostic(
                    line,
                    "config_braces",
                    "出现未匹配的右花括号".to_owned(),
                ));
            }
            continue;
        }

        match stack.last().cloned() {
            Some(Ctx::Routing) => parse_routing_line(text, line, &mut parsed),
            Some(Ctx::Node) => parse_node_line(text, line, &mut parsed),
            Some(Ctx::Group(_)) => parse_group_line(text, line, &mut group),
            Some(Ctx::DnsUpstream) => {
                if upstream_block {
                    parse_upstream_line(text, line, &mut parsed);
                }
            }
            Some(Ctx::DnsRequest) => parse_dns_rule_line(text, line, &mut parsed, false),
            Some(Ctx::DnsResponse) => parse_dns_rule_line(text, line, &mut parsed, true),
            None => {
                if let Some(inner) = text
                    .strip_prefix("include(")
                    .and_then(|rest| rest.strip_suffix(')'))
                {
                    parsed.includes.push(unquote(inner.trim()));
                } else {
                    parsed.diagnostics.push(diagnostic(
                        line,
                        "config_root_syntax",
                        "根级别仅支持配置块或 include(...)，当前配置不是可识别的 dae 语法"
                            .to_owned(),
                    ));
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        parsed.diagnostics.push(diagnostic(
            content.lines().count() as u32,
            "config_braces",
            "配置块缺少右花括号".to_owned(),
        ));
    }
    parsed
}

fn parse_node_line(text: &str, line: u32, parsed: &mut Parsed) {
    let Some((name, value)) = text.split_once(':') else {
        parsed.diagnostics.push(diagnostic(
            line,
            "node_syntax",
            "node entry must be name: 'socks5://[user:pass@]host:port'".to_owned(),
        ));
        return;
    };
    let name = name.trim().trim_matches('\'').trim_matches('"');
    if name.is_empty() {
        parsed.diagnostics.push(diagnostic(
            line,
            "node_name",
            "node name is empty".to_owned(),
        ));
        return;
    }
    if parsed.nodes.iter().any(|node| node.name == name) {
        parsed.diagnostics.push(diagnostic(
            line,
            "node_duplicate",
            format!("node `{name}` is declared more than once"),
        ));
        return;
    }
    let value = unquote(value.trim());
    if !value.starts_with("socks5://") {
        match crate::share::parse(&value) {
            Ok(share) => parsed.nodes.push(Node {
                name: name.to_owned(),
                protocol: share.protocol,
                host: share.host,
                port: share.port,
                username: None,
                password: None,
                link: Some(share.link),
                provider: None,
                subscription_tag: None,
            }),
            Err(message) => parsed
                .diagnostics
                .push(diagnostic(line, "node_url", message)),
        }
        return;
    }
    match parse_node_url(&value) {
        Ok((host, port, username, password)) => parsed.nodes.push(Node {
            name: name.to_owned(),
            protocol: "socks5".to_owned(),
            host,
            port,
            username,
            password,
            link: None,
            provider: None,
            subscription_tag: None,
        }),
        Err(message) => parsed
            .diagnostics
            .push(diagnostic(line, "node_url", message)),
    }
}

fn parse_group_line(text: &str, line: u32, group: &mut Option<RawGroup>) {
    let Some(group) = group.as_mut() else { return };
    let Some((key, value)) = text.split_once(':') else {
        return;
    };
    let value = unquote(value.trim());
    match key.trim() {
        "filter" => group.filters.push(value),
        "policy" => {
            group.policy = parse_policy(&value);
            if group.policy.is_none() {
                // Keep the group; the caller reports the unsupported policy and
                // drops it, so a later duplicate line cannot silently accept it.
                group.line = line;
            }
        }
        "default" => group.default = Some(value),
        "final" => group.final_outbound = Some(value),
        "dialer" => group.dialer = Some(value),
        "landing" => group.landing = Some(value),
        _ => {}
    }
}

pub(crate) fn parse_policy(value: &str) -> Option<Policy> {
    match value {
        "select" | "selector" => Some(Policy::Selector),
        "random" => Some(Policy::Random),
        "urltest" | "min" | "min_moving_avg" => Some(Policy::MovingAverage),
        "min_avg10" => Some(Policy::Average10),
        "min_last_delay" => Some(Policy::LastDelay),
        "score" => Some(Policy::Score),
        "fallback" => Some(Policy::Fallback),
        "roundrobin" | "round_robin" | "loadbalance" | "balance" => Some(Policy::RoundRobin),
        _ => value
            .strip_prefix("fixed(")
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|index| index.trim().parse().ok())
            .map(Policy::Fixed),
    }
}

/// Pulls every `include('name.dae')` file next to the source into the same
/// parse. One level deep: an included file may not include further files.
fn merge_includes(parsed: &mut Parsed, sources: &std::collections::HashMap<String, String>) {
    if parsed.includes.is_empty() {
        return;
    }
    let names = parsed.includes.clone();
    for name in names {
        if !source_name_valid(&name) || name == SOURCE_PATH {
            parsed.diagnostics.push(diagnostic(
                0,
                "include_path",
                format!("include 源路径无效：{name}"),
            ));
            continue;
        }
        let path = data_dir().join(&name);
        match sources
            .get(&name)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| fs::read_to_string(&path))
        {
            Ok(extra) => {
                let mut sub = parse(&extra);
                if !sub.includes.is_empty() {
                    parsed.diagnostics.push(diagnostic(
                        0,
                        "include_depth",
                        format!("源文件 {name} 不支持嵌套 include"),
                    ));
                }
                for rule in &mut sub.rules {
                    rule.source_id = Some(name.clone());
                }
                for rule in sub
                    .dns_rules
                    .iter_mut()
                    .chain(sub.dns_response_rules.iter_mut())
                {
                    rule.source_id = Some(name.clone());
                }
                parsed.nodes.extend(sub.nodes.drain(..));
                parsed.groups.extend(sub.groups.drain(..));
                parsed.rules.extend(sub.rules.drain(..));
                parsed.upstreams.extend(sub.upstreams.drain(..));
                parsed.dns_rules.extend(sub.dns_rules.drain(..));
                parsed
                    .dns_response_rules
                    .extend(sub.dns_response_rules.drain(..));
                if sub.dns_request_fallback.is_some() {
                    parsed.dns_request_fallback = sub.dns_request_fallback;
                    parsed.dns_request_fallback_source = sub
                        .dns_request_fallback_source
                        .map(|(line, _)| (line, Some(name.clone())));
                }
                if sub.dns_response_fallback.is_some() {
                    parsed.dns_response_fallback = sub.dns_response_fallback;
                    parsed.dns_response_fallback_source = sub
                        .dns_response_fallback_source
                        .map(|(line, _)| (line, Some(name.clone())));
                }
                parsed.diagnostics.extend(sub.diagnostics.drain(..));
            }
            Err(_) => parsed.diagnostics.push(Diagnostic {
                level: "error",
                line: 0,
                code: "include_missing",
                message: format!("include 的源文件 `{name}` 不存在"),
            }),
        }
    }
}

pub(crate) fn routing_condition_supported(condition: &Condition) -> bool {
    match condition {
        Condition::QueryType(_) | Condition::Upstream(_) => false,
        Condition::Not(inner) => routing_condition_supported(inner),
        Condition::And(conditions) | Condition::Any(conditions) => {
            conditions.iter().all(routing_condition_supported)
        }
        _ => true,
    }
}

pub(crate) fn dns_condition_supported(condition: &Condition, response: bool) -> bool {
    match condition {
        Condition::DomainPattern(_) => true,
        Condition::RuleSet(set) => set.set.dns_supported(response),
        Condition::DomainFull(_)
        | Condition::DomainSuffix(_)
        | Condition::DomainKeyword(_)
        | Condition::GeoSite(_)
        | Condition::QueryType(_) => true,
        Condition::GeoIp(_) | Condition::IpCidr(..) | Condition::Upstream(_) => response,
        Condition::Not(inner) => dns_condition_supported(inner, response),
        Condition::And(conditions) | Condition::Any(conditions) => conditions
            .iter()
            .all(|condition| dns_condition_supported(condition, response)),
        _ => false,
    }
}

fn parse_dns_rule_line(text: &str, line: u32, parsed: &mut Parsed, response: bool) {
    if let Some(value) = text.strip_prefix("fallback:") {
        let action = unquote(value.trim());
        if response {
            parsed.dns_response_fallback = Some(action);
            parsed.dns_response_fallback_source = Some((line, None));
        } else {
            parsed.dns_request_fallback = Some(action);
            parsed.dns_request_fallback_source = Some((line, None));
        }
        return;
    }
    let Some((condition_text, upstream_text)) = text.split_once("->") else {
        parsed.diagnostics.push(diagnostic(
            line,
            "dns_rule",
            "DNS 规则必须是 `条件 -> 动作或上游名`".to_owned(),
        ));
        return;
    };
    crate::geodata::clear_error();
    let Some(condition) = parse_condition(condition_text.trim())
        .filter(|condition| dns_condition_supported(condition, response))
    else {
        parsed.diagnostics.push(diagnostic(
            line,
            "dns_rule",
            crate::geodata::take_error().unwrap_or_else(|| {
                "DNS 条件无效；响应规则支持 qname、qtype、ip/GeoIP 和 upstream".to_owned()
            }),
        ));
        return;
    };
    let upstream = unquote(upstream_text.trim());
    if upstream.is_empty() {
        parsed.diagnostics.push(diagnostic(
            line,
            "dns_rule",
            "DNS 规则缺少动作或上游名".to_owned(),
        ));
        return;
    }
    let rules = if response {
        &mut parsed.dns_response_rules
    } else {
        &mut parsed.dns_rules
    };
    rules.push(DnsRuleRaw {
        source_id: None,
        expression: text.to_owned(),
        condition,
        upstream,
        line,
    });
}

fn parse_upstream_line(text: &str, line: u32, parsed: &mut Parsed) {
    let Some((name, value)) = text.split_once(':') else {
        return;
    };
    let name = unquote(name.trim());
    let value = unquote(value.trim());
    if crate::dns::reply_code(&name.to_ascii_lowercase()).is_some()
        || name.eq_ignore_ascii_case("accept")
    {
        parsed.diagnostics.push(diagnostic(
            line,
            "dns_upstream",
            format!("DNS 上游名称 `{name}` 与保留动作名冲突，请更换名称"),
        ));
        return;
    }
    match parse_upstream_url(&value) {
        Ok((protocol, host, port)) => parsed.upstreams.push(Upstream {
            name,
            protocol,
            host,
            port,
        }),
        Err(message) => parsed
            .diagnostics
            .push(diagnostic(line, "dns_upstream", message)),
    }
}

fn parse_routing_line(text: &str, line: u32, parsed: &mut Parsed) {
    if let Some(value) = text.strip_prefix("fallback:") {
        match outbound_name(value.trim()) {
            Some(outbound) => {
                parsed.fallback = Some(RawRule {
                    source_id: None,
                    expression: format!("fallback: {outbound}"),
                    outbound,
                    condition: None,
                    line,
                })
            }
            None => parsed.diagnostics.push(diagnostic(
                line,
                "fallback_syntax",
                "fallback must name direct, block, a node or a group".to_owned(),
            )),
        }
        return;
    }
    let Some((condition_text, outbound_text)) = text.split_once("->") else {
        parsed.diagnostics.push(diagnostic(
            line,
            "rule_syntax",
            "routing rule must be a condition followed by -> and an outbound".to_owned(),
        ));
        return;
    };
    crate::geodata::clear_error();
    let Some(condition) =
        parse_condition(condition_text.trim()).filter(routing_condition_supported)
    else {
        parsed.diagnostics.push(diagnostic(
            line,
            "rule_condition",
            crate::geodata::take_error().unwrap_or_else(|| "routing 条件支持 domain/GeoSite、dip/ip/GeoIP、sip、pname、dport、sport、l4proto 及组合条件".to_owned()),
        ));
        return;
    };
    let Some(outbound) = outbound_name(outbound_text.trim()) else {
        parsed.diagnostics.push(diagnostic(
            line,
            "rule_outbound",
            "routing outbound must name direct, block, a node or a group".to_owned(),
        ));
        return;
    };
    parsed.rules.push(RawRule {
        source_id: None,
        expression: text.to_string(),
        outbound,
        condition: Some(condition),
        line,
    });
}

fn outbound_name(text: &str) -> Option<String> {
    let text = unquote(text.trim());
    if text.is_empty() || text.contains(char::is_whitespace) {
        return None;
    }
    Some(text)
}

pub(crate) fn parse_condition(text: &str) -> Option<Condition> {
    let text = text.trim();
    let any = crate::group_filter::split_top(text, "||").ok()?;
    if any.len() > 1 {
        return Some(Condition::Any(
            any.into_iter()
                .map(parse_condition)
                .collect::<Option<Vec<_>>>()?,
        ));
    }
    let all = crate::group_filter::split_top(text, "&&").ok()?;
    if all.len() > 1 {
        return Some(Condition::And(
            all.into_iter()
                .map(parse_condition)
                .collect::<Option<Vec<_>>>()?,
        ));
    }
    if let Some(inner) = text.strip_prefix('!') {
        return Some(Condition::Not(Box::new(parse_condition(inner)?)));
    }
    if text.starts_with('(') && text.ends_with(')') {
        return parse_condition(&text[1..text.len() - 1]);
    }
    let open = text.find('(')?;
    let call = text[..open].trim();
    let body = text[open + 1..].strip_suffix(')')?;
    let arguments = crate::group_filter::split_top(body, ",").ok()?;
    if arguments.is_empty() || arguments.iter().any(|value| value.trim().is_empty()) {
        return None;
    }
    match call {
        "ruleset" => {
            if arguments.len()!=1{return None;}
            let id=unquote(arguments[0]);
            let set=crate::rules_runtime::resolve_set(&id);
            if set.is_none(){crate::geodata::set_error(format!("规则集 {id} 未启用或不存在"));}
            set.map(Condition::RuleSet)
        }
        "pname" | "upstream" => {
            let values: Vec<_> = arguments.into_iter().map(unquote).collect();
            if values.iter().any(|value| {
                value.is_empty() || value.len() > 1024 || value.contains([',', '\n', '\r', '\0'])
            }) {
                return None;
            }
            Some(if call == "pname" {
                Condition::Process(values)
            } else {
                Condition::Upstream(values)
            })
        }
        "l4proto" => {
            let protocols: Vec<_> = arguments.into_iter().map(unquote).collect();
            protocols
                .iter()
                .all(|protocol| protocol == "tcp" || protocol == "udp")
                .then_some(Condition::Network(protocols))
        }
        "dport" | "sport" => {
            let ports = arguments
                .into_iter()
                .map(|argument| {
                    let argument = unquote(argument);
                    let (from, to) = argument
                        .split_once('-')
                        .or_else(|| argument.split_once(':'))
                        .unwrap_or((&argument, &argument));
                    let from: u16 = from.trim().parse().ok()?;
                    let to: u16 = to.trim().parse().ok()?;
                    (from > 0 && from <= to).then_some((from, to))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(if call == "dport" {
                Condition::DestinationPort(ports)
            } else {
                Condition::SourcePort(ports)
            })
        }
        "dip" | "sip" | "ip" => {
            let conditions = arguments
                .into_iter()
                .map(|argument| {
                    if let Some(code) = argument.trim().strip_prefix("geoip:") {
                        let set = crate::geodata::IpRef::load(&unquote(code.trim()))?;
                        return Some(if call == "sip" {
                            Condition::SourceGeoIp(set)
                        } else {
                            Condition::GeoIp(set)
                        });
                    }
                    let value = unquote(argument.strip_prefix("cidr:").unwrap_or(argument).trim());
                    let (address, prefix) = match value.split_once('/') {
                        Some((address, prefix)) => (
                            address.trim().parse::<IpAddr>().ok()?,
                            Some(prefix.trim().parse::<u8>().ok()?),
                        ),
                        None => (value.parse::<IpAddr>().ok()?, None),
                    };
                    let maximum = if address.is_ipv4() { 32 } else { 128 };
                    let prefix = prefix.unwrap_or(maximum);
                    if prefix > maximum {
                        return None;
                    }
                    Some(if call == "sip" {
                        Condition::SourceIpCidr(address, prefix)
                    } else {
                        Condition::IpCidr(address, prefix)
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some(if conditions.len() == 1 {
                conditions.into_iter().next()?
            } else {
                Condition::Any(conditions)
            })
        }
        "qtype" => {
            let types: Vec<_> = arguments
                .into_iter()
                .map(|value| unquote(value).to_ascii_uppercase())
                .collect();
            types
                .iter()
                .all(|kind| crate::dns::RECORD_TYPES.contains(&kind.as_str()))
                .then_some(Condition::QueryType(types))
        }
        "domain" | "qname" => {
            let conditions = arguments
                .into_iter()
                .map(|argument| {
                    let (kind, value) = argument.split_once(':')?;
                    let value = unquote(value).trim_end_matches('.').to_ascii_lowercase();
                    if value.is_empty() || value.contains(char::is_whitespace) {
                        return None;
                    }
                    match kind.trim() {
                        "full" => Some(Condition::DomainFull(value)),
                        "suffix" => Some(Condition::DomainSuffix(value)),
                        "keyword" => Some(Condition::DomainKeyword(value)),
                        "regex" => crate::rules_runtime::Pattern::new(&value).ok().map(Condition::DomainPattern),
                        "ruleset" => crate::rules_runtime::resolve_set(&value).map(Condition::RuleSet),
                        "geosite" => {
                            crate::geodata::DomainRef::load(&value).map(Condition::GeoSite)
                        }
                        _ => None,
                    }
                })
                .collect::<Option<Vec<_>>>()?;
            Some(if conditions.len() == 1 {
                conditions.into_iter().next()?
            } else {
                Condition::Any(conditions)
            })
        }
        _ => None,
    }
}

/// Parses `socks5://[user[:pass]@]host:port` (IPv6 in brackets).
fn parse_node_url(value: &str) -> Result<(String, u16, Option<String>, Option<String>), String> {
    let rest = value
        .strip_prefix("socks5://")
        .ok_or_else(|| format!("node `{value}` is not a socks5:// URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if !path.is_empty() {
        return Err(format!(
            "node `{value}` has a path; only socks5://host:port is supported"
        ));
    }
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    let (host, port) =
        parse_host_port(hostport).ok_or_else(|| format!("node `{value}` has no host:port"))?;
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((user, pass)) => (Some(percent_decode(user)), Some(percent_decode(pass))),
            None => (Some(percent_decode(userinfo)), None),
        },
        None => (None, None),
    };
    Ok((host, port, username, password))
}

fn parse_upstream_url(value: &str) -> Result<(&'static str, String, u16), String> {
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("udp", value),
    };
    let protocol = match scheme {
        "udp" | "tcp+udp" => "udp",
        "tcp" => "tcp",
        _ => {
            return Err(format!(
                "DNS upstream `{value}` must be udp://, tcp:// or tcp+udp://"
            ))
        }
    };
    let (host, port) =
        parse_host_port(rest).ok_or_else(|| format!("DNS upstream `{value}` has no host:port"))?;
    Ok((protocol, host, port))
}

fn parse_host_port(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

pub(crate) fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('"') {
        if let Ok(decoded) = serde_json::from_str::<String>(value) {
            return decoded;
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'\'' | b'"') && bytes.last() == Some(&bytes[0]) {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

fn percent_decode(value: &str) -> String {
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

fn diagnostic(line: u32, code: &'static str, message: String) -> Diagnostic {
    Diagnostic {
        level: "error",
        line,
        code,
        message,
    }
}

fn cidr_contains(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(address) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(address) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_condition, parse_node_url, Condition, Policy, Target};
    use std::net::{IpAddr, Ipv4Addr};

    fn config(source: &str) -> super::Config {
        super::build_with_providers(source.to_owned(), None, &[])
    }

    #[test]
    fn parses_the_shipped_default() {
        let config = config(super::DEFAULT_CONFIG);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.fallback.outbound, "direct");
        assert_eq!(config.rules[0].id, "traffic:0");
        assert!(config.diagnostics.is_empty());
        assert_eq!(config.sha256.len(), 64);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].host, "223.5.5.5");
    }

    #[test]
    fn parses_quoted_values_containing_hash_and_trailing_comments() {
        let config = config(
            "node {\n  lan: 'socks5://user:p#ss@10.0.0.2:1080'\n  'United-States #6': 'socks5://10.0.0.3:1081'\n}\n\
             group {\n  proxy {\n    filter: name('lan') # local helper stays\n    filter: name('United-States #6')\n    policy: fixed(1)\n  }\n}\n\
             routing {\n  fallback: proxy\n}\n",
        );
        assert!(config.diagnostics.is_empty());
        let lan = config.nodes.iter().find(|node| node.name == "lan").unwrap();
        assert_eq!(lan.password.as_deref(), Some("p#ss"));
        let group = &config.groups[0];
        assert_eq!(group.members, vec!["lan", "United-States #6"]);
        let decision = super::decide_from(&config, "www.example.com");
        assert_eq!(decision.outbound, "proxy");
        assert_eq!(decision.chain, vec!["United-States #6"]);
    }

    #[test]
    fn parses_nodes_groups_and_a_group_outbound() {
        let config = config(
            "node {\n  edge: 'socks5://user:pw@10.0.0.2:1080'\n}\n\
             group {\n  proxy {\n    filter: name('edge')\n    policy: fixed(0)\n  }\n}\n\
             routing {\n  domain(suffix: example.com) -> proxy\n  fallback: direct\n}\n",
        );
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].host, "10.0.0.2");
        assert_eq!(config.nodes[0].username.as_deref(), Some("user"));
        assert_eq!(config.nodes[0].password.as_deref(), Some("pw"));
        assert_eq!(config.groups.len(), 1);
        assert_eq!(config.groups[0].members, vec!["edge"]);
        assert_eq!(config.groups[0].policy, Policy::Fixed(0));
        assert_eq!(config.rules[0].outbound, "proxy");
        assert!(config.diagnostics.is_empty());

        let decision = super::decide_from(&config, "www.example.com");
        assert_eq!(decision.outbound, "proxy");
        assert_eq!(decision.chain, vec!["edge"]);
        assert!(
            matches!(&decision.target, Target::Node(node) if node.host == "10.0.0.2" && node.port == 1080)
        );
    }

    #[test]
    fn filters_by_keyword_and_nested_group() {
        let config = config(
            "node {\n  hk-1: 'socks5://10.0.0.1:1080'\n  hk-2: 'socks5://10.0.0.2:1080'\n  jp-1: 'socks5://10.0.0.3:1080'\n}\n\
             group {\n  hk {\n    filter: name(keyword: 'hk')\n    policy: selector\n  }\n  all {\n    filter: group('hk')\n    filter: name('jp-1')\n    policy: random\n  }\n}\n\
             routing {\n  fallback: all\n}\n",
        );
        assert_eq!(config.groups[0].members, vec!["hk-1", "hk-2"]);
        assert_eq!(config.groups[1].members, vec!["hk-1", "hk-2", "jp-1"]);
        assert!(
            super::nodes_body(&config, None).contains("\"group_ids\":[\"group-hk\",\"group-all\"]")
        );
        assert!(super::nodes_body(&config, Some("group-hk")).contains("hk-1"));
        assert!(!super::nodes_body(&config, Some("group-hk")).contains("jp-1"));
        assert!(super::group_body(&config, "group-all")
            .unwrap()
            .contains("node-jp-1"));
    }

    #[test]
    fn unsupported_policy_or_filter_is_reported_and_not_applied() {
        let config = config(
            "node {\n  edge: 'socks5://10.0.0.2:1080'\n}\n\
             group {\n  bad {\n    filter: name('edge')\n    policy: unsupported_policy\n  }\n}\n\
             routing {\n  fallback: bad\n}\n",
        );
        assert!(config.groups.is_empty());
        assert!(config
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "group_policy"));
        assert_eq!(config.fallback.outbound, "direct");
    }

    #[test]
    fn parses_node_urls_with_and_without_credentials() {
        assert_eq!(
            parse_node_url("socks5://10.0.0.1:1080").unwrap(),
            ("10.0.0.1".to_owned(), 1080, None, None)
        );
        assert_eq!(
            parse_node_url("socks5://u%40x:p%3Aw@[::1]:1080").unwrap(),
            (
                "::1".to_owned(),
                1080,
                Some("u@x".to_owned()),
                Some("p:w".to_owned())
            )
        );
        assert!(parse_node_url("http://10.0.0.1:1080").is_err());
        assert!(parse_node_url("socks5://10.0.0.1").is_err());
    }

    #[test]
    fn matches_domains_and_ipv4_cidrs() {
        let full = parse_condition("domain(full: Example.COM)").unwrap();
        let suffix = parse_condition("domain(suffix: example.com)").unwrap();
        let cidr = parse_condition("ip(cidr: 10.0.0.0/8)").unwrap();

        let rule = |condition: Condition| super::Rule {
            source_id: None,
            id: "traffic:0".into(),
            index: 0,
            expression: String::new(),
            outbound: "block".into(),
            condition: Some(condition),
            line: 1,
        };
        assert!(rule(full.clone()).matches("example.com"));
        assert!(!rule(full).matches("www.example.com"));
        assert!(rule(suffix.clone()).matches("example.com"));
        assert!(rule(suffix.clone()).matches("a.example.com"));
        assert!(!rule(suffix).matches("notexample.com"));
        assert!(rule(cidr.clone()).matches("10.1.2.3"));
        assert!(!rule(cidr).matches("11.1.2.3"));
        assert_eq!(
            parse_condition("ip(cidr: 127.0.0.0/8)").unwrap(),
            Condition::IpCidr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)
        );
    }

    #[test]
    fn reports_unsupported_lines_without_applying_them() {
        let source = "routing {\n  domain(regex: .*) -> block\n  domain(full: x.test) -> proxy\n  fallback: block\n}\n";
        let config = config(source);
        assert!(config.rules.is_empty());
        assert_eq!(config.diagnostics.len(), 2);
        assert_eq!(config.fallback.outbound, "block");
    }

    #[test]
    fn adds_a_direct_fallback_when_missing() {
        let config = config("routing {\n}\n");
        assert_eq!(config.fallback.outbound, "direct");
        assert_eq!(config.fallback.index, 0);
        assert_eq!(config.diagnostics.len(), 1);
        assert_eq!(config.diagnostics[0].code, "fallback_missing");
    }

    #[test]
    fn parses_dns_request_rules_and_reports_unknown_upstreams() {
        let ok = config(
            "node {\n  edge: 'socks5://10.0.0.2:1080'\n}\n\
             dns {\n  upstream {\n    alidns: 'udp://223.5.5.5:53'\n  }\n  request {\n    domain(suffix: cn) -> alidns\n  }\n}\n\
             routing {\n  fallback: edge\n}\n",
        );
        assert!(ok.diagnostics.is_empty());
        assert_eq!(ok.dns_rules.len(), 1);
        assert_eq!(ok.dns_rules[0].upstream, "alidns");
        assert!(super::condition_matches(
            &ok.dns_rules[0].condition,
            "www.cn"
        ));
        assert!(!super::condition_matches(
            &ok.dns_rules[0].condition,
            "example.com"
        ));

        let broken = config(
            "dns {\n  upstream {\n    alidns: 'udp://223.5.5.5:53'\n  }\n  request {\n    domain(suffix: cn) -> missing\n  }\n}\n\
             routing {\n}\n",
        );
        assert!(broken.dns_rules.is_empty());
        assert!(broken
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "dns_upstream" && diagnostic.level == "error"));
    }

    #[test]
    fn rewrites_a_group_in_place_keeping_the_rest() {
        let source = "node {\n  edge: 'socks5://10.0.0.2:1080'\n  backup: 'socks5://10.0.0.3:1080'\n}\n\
             group {\n  proxy {\n    filter: name('edge')\n    filter: name('backup')\n    policy: fixed(0)\n    default: 'edge'\n  }\n  spare {\n    filter: name('backup')\n    policy: random\n  }\n}\n\
             routing {\n  fallback: proxy\n}\n";
        let rewritten = super::rewrite_group(
            source,
            "proxy",
            Some("selector"),
            Some(Some("backup")),
            Some(None),
        )
        .unwrap();
        assert!(rewritten.contains("policy: selector"));
        assert!(rewritten.contains("default: 'backup'"));
        assert!(!rewritten.contains("fixed(0)"));
        assert!(rewritten.contains("filter: name('backup')"));
        assert!(rewritten.contains("policy: random"));
        let rebuilt = config(&rewritten);
        assert!(rebuilt.diagnostics.is_empty());
        assert_eq!(rebuilt.groups[0].policy, Policy::Selector);
        assert_eq!(rebuilt.groups[0].default.as_deref(), Some("backup"));
        assert_eq!(
            super::rewrite_group(source, "nope", Some("selector"), None, None),
            Err("group `nope` 在源文件中不存在".to_owned())
        );
    }

    #[test]
    fn validates_the_full_configuration_semantically() {
        let good = "node {\n  edge: 'socks5://10.0.0.2:1080'\n}\nrouting {\n  fallback: edge\n}\n";
        assert!(super::validate_full(good).0);
        let bad = "node {\n  edge: 'socks5://10.0.0.2:1080'\n}\n\
             group {\n  proxy {\n    filter: name('edge')\n    policy: unsupported_policy\n  }\n}\n\
             routing {\n  fallback: proxy\n}\n";
        let (valid, diagnostics) = super::validate_full(bad);
        assert!(!valid);
        assert!(diagnostics.contains("group_policy"));
    }
}

pub(crate) fn condition_uses_geo(c:&Condition,kind:&str,id:&str)->bool{match c{Condition::GeoSite(g)if kind=="geosite"=>g.category(id),Condition::GeoIp(g)|Condition::SourceGeoIp(g)if kind=="geoip"=>g.category(id),Condition::RuleSet(set)=>set.set.uses_geo(kind,id),Condition::And(rows)|Condition::Any(rows)=>rows.iter().any(|c|condition_uses_geo(c,kind,id)),Condition::Not(c)=>condition_uses_geo(c,kind,id),_=>false}}
pub(crate) fn geo_references(kind:&str,id:&str)->Vec<serde_json::Value>{let snapshot=crate::rules_runtime::current();let config=current();let mut refs=Vec::new();
    for row in config.rules.iter().filter(|r|r.line>0&&r.condition.as_ref().is_some_and(|c|condition_uses_geo(c,kind,id))){refs.push(serde_json::json!({"name":row.expression,"scope":"routing"}));}
    for row in config.dns_rules.iter().chain(&config.dns_response_rules).filter(|r|condition_uses_geo(&r.condition,kind,id)){refs.push(serde_json::json!({"name":row.expression,"scope":"source-dns"}));}
    for(row,c)in &snapshot.policies{if condition_uses_geo(c,kind,id){refs.push(serde_json::json!({"name":row.name,"scope":"dns/fakeip"}));}}
    for(row,c)in &snapshot.bindings{if condition_uses_geo(c,kind,id){refs.push(serde_json::json!({"name":row.name,"scope":"routing"}));}}refs}


pub(crate) fn collect_geo_codes(condition: &Condition, codes: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<String>>) {
    let category = match condition {
        Condition::GeoSite(g) => g.category_id().map(|id| ("geosite", id)),
        Condition::GeoIp(g) | Condition::SourceGeoIp(g) => g.category_id().map(|id| ("geoip", id)),
        Condition::RuleSet(set) => {set.set.collect_geo_codes(codes); None},
        Condition::And(rows) | Condition::Any(rows) => {for row in rows {collect_geo_codes(row, codes);} None},
        Condition::Not(row) => {collect_geo_codes(row, codes); None},
        _ => None,
    };
    if let Some((kind, code)) = category {codes.entry(kind.into()).or_default().insert(code);}
}
pub(crate) fn required_geodata_codes() -> serde_json::Value {
    let snapshot = crate::rules_runtime::current();
    let config = current();
    let mut codes = std::collections::BTreeMap::from([
        ("geosite".to_string(), std::collections::BTreeSet::<String>::new()),
        ("geoip".to_string(), std::collections::BTreeSet::<String>::new()),
    ]);
    for row in &config.rules {if let Some(condition) = &row.condition {collect_geo_codes(condition, &mut codes);}}
    for row in config.dns_rules.iter().chain(&config.dns_response_rules) {collect_geo_codes(&row.condition, &mut codes);}
    for condition in snapshot.policies.iter().map(|(_, c)| c).chain(snapshot.bindings.iter().map(|(_, c)| c)) {collect_geo_codes(condition, &mut codes);}
    serde_json::to_value(codes).unwrap()
}
