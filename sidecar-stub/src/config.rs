//! Engine-native configuration: one dae-style source file whose `node`, `group`,
//! `dns` and `routing` blocks are the state the datapath actually uses.
//!
//! The source is read from `LEMONVPN_DATA_DIR` (default `%LOCALAPPDATA%\LemonVPN`
//! on Windows) and re-read when its mtime or size changes. The accepted text is
//! served as `GET /api/v1/config`; the parsed rules, nodes and groups as
//! `GET /api/v1/rules`, `/api/v1/nodes` and `/api/v1/groups`.

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

use crate::json;
use crate::logs;
use crate::sha256;
use crate::state;

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
    IpCidr(IpAddr, u8),
    /// `l4proto(...)` that includes TCP: every connection this datapath carries.
    All,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub index: usize,
    pub expression: String,
    pub outbound: String,
    pub condition: Option<Condition>,
    pub line: u32,
}

impl Rule {
    fn matches(&self, host: &str) -> bool {
        match &self.condition {
            Some(Condition::DomainFull(value)) => host == value,
            Some(Condition::DomainSuffix(value)) => {
                host == value
                    || host
                        .strip_suffix(value)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            Some(Condition::IpCidr(network, prefix)) => host
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|address| cidr_contains(address, *network, *prefix)),
            Some(Condition::All) => true,
            None => false,
        }
    }
}

#[derive(Debug)]
pub struct Diagnostic {
    pub level: &'static str,
    pub line: u32,
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    pub protocol: &'static str,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Selector,
    Fixed(usize),
    Random,
}

impl Policy {
    pub fn kind(self) -> &'static str {
        match self {
            Policy::Selector => "selector",
            Policy::Fixed(_) => "fixed",
            Policy::Random => "random",
        }
    }

    pub fn native(self) -> String {
        match self {
            Policy::Selector => "selector".to_string(),
            Policy::Fixed(index) => format!("fixed({index})"),
            Policy::Random => "random".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Group {
    pub name: String,
    pub policy: Policy,
    pub default: Option<String>,
    pub final_outbound: Option<String>,
    pub members: Vec<String>,
}

#[derive(Clone, Debug)]
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
    Socks5 {
        name: String,
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

pub struct Config {
    pub content: String,
    pub sha256: String,
    pub generation: String,
    pub revision: String,
    pub rules: Vec<Rule>,
    pub fallback: Rule,
    pub nodes: Vec<Node>,
    pub groups: Vec<Group>,
    pub upstreams: Vec<Upstream>,
    pub diagnostics: Vec<Diagnostic>,
    pub loaded_at: SystemTime,
    modified: Option<SystemTime>,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub struct Decision {
    /// The configured outbound name: `direct`, `block`, a node name or a group name.
    pub outbound: String,
    /// Members a group resolved through, ending in the leaf node.
    pub chain: Vec<String>,
    pub target: Target,
    pub rule_id: String,
    pub generation: String,
    pub expression: String,
}

impl Decision {
    pub fn blocked(&self) -> bool {
        matches!(self.target, Target::Block)
    }
}

static CONFIG: OnceLock<Mutex<Config>> = OnceLock::new();

/// Loads the source file, creating the default one when it does not exist yet.
/// Called once before the listener starts serving.
pub fn start() {
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
    let modified = fs::metadata(&path).ok().and_then(|meta| meta.modified().ok());
    let config = build(content, modified);
    let _ = CONFIG.set(Mutex::new(config));
}

fn current() -> MutexGuard<'static, Config> {
    CONFIG
        .get_or_init(|| Mutex::new(build(DEFAULT_CONFIG.to_string(), None)))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Re-reads the source when its mtime or size changed. A failed read keeps the
/// last accepted snapshot: a transient editor save must not empty the rule set.
pub fn refresh() {
    let path = config_path();
    let Ok(metadata) = fs::metadata(&path) else { return };
    let modified = metadata.modified().ok();
    let size = metadata.len() as usize;
    if size > MAX_BYTES {
        return;
    }
    {
        let config = current();
        if config.bytes == size && config.modified == modified {
            return;
        }
    }
    let Ok(content) = fs::read_to_string(&path) else { return };
    if content.len() > MAX_BYTES {
        return;
    }
    let mut config = current();
    if config.content == content {
        config.modified = modified;
        config.bytes = content.len();
        return;
    }
    let generation = build(content.clone(), modified).generation.clone();
    *config = build(content, modified);
    logs::info(
        "engine::config",
        "Configuration source reloaded.",
        Some(logs::fields(&[("generation", generation.as_str())])),
    );
}

/// The first matching rule, or the fallback. Reads the accepted snapshot.
pub fn decide(host: &str) -> Decision {
    refresh();
    let config = current();
    decide_from(&config, host)
}

fn decide_from(config: &Config, host: &str) -> Decision {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let rule = config
        .rules
        .iter()
        .find(|rule| rule.matches(&host))
        .unwrap_or(&config.fallback);
    let mut visiting = Vec::new();
    let (target, chain) = resolve_outbound(&config, &rule.outbound, &mut visiting).unwrap_or((
        Target::Block,
        Vec::new(),
    ));
    Decision {
        outbound: rule.outbound.clone(),
        chain,
        target,
        rule_id: rule.id.clone(),
        generation: config.generation.clone(),
        expression: rule.expression.clone(),
    }
}

fn resolve_outbound(
    config: &Config,
    name: &str,
    visiting: &mut Vec<String>,
) -> Option<(Target, Vec<String>)> {
    match name {
        "direct" => return Some((Target::Direct, Vec::new())),
        "block" => return Some((Target::Block, Vec::new())),
        _ => {}
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == name) {
        return Some((
            Target::Socks5 {
                name: node.name.clone(),
                host: node.host.clone(),
                port: node.port,
                username: node.username.clone(),
                password: node.password.clone(),
            },
            vec![node.name.clone()],
        ));
    }
    let group = config.groups.iter().find(|group| group.name == name)?;
    if visiting.iter().any(|seen| seen == name) {
        return None;
    }
    visiting.push(name.to_owned());
    let selected = select_member(group, config);
    let result = match selected {
        Some(member) => resolve_outbound(config, &member, visiting),
        None => group
            .final_outbound
            .as_deref()
            .and_then(|fallback| resolve_outbound(config, fallback, visiting)),
    };
    visiting.pop();
    result
}

fn select_member(group: &Group, config: &Config) -> Option<String> {
    let members = &group.members;
    if members.is_empty() {
        return None;
    }
    match group.policy {
        Policy::Selector => group
            .default
            .as_ref()
            .filter(|name| members.contains(name))
            .cloned()
            .or_else(|| members.first().cloned()),
        Policy::Fixed(index) => members
            .get(index)
            .or_else(|| members.first())
            .cloned(),
        Policy::Random => {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|value| value.subsec_nanos() as usize)
                .unwrap_or(0);
            members.get(nanos % members.len()).cloned()
        }
    }
    .filter(|name| {
        config
            .nodes
            .iter()
            .any(|node| &node.name == name)
    })
}

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

/// Replaces the main source. The caller has already checked the revision; the
/// new text is parsed and becomes the accepted snapshot immediately.
pub fn replace(content: &str) -> Result<(), String> {
    if content.len() > MAX_BYTES {
        return Err(format!("配置超过 {MAX_BYTES} 字节"));
    }
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&path, content).map_err(|error| format!("写入配置失败：{error}"))?;
    let modified = fs::metadata(&path).ok().and_then(|meta| meta.modified().ok());
    let mut config = current();
    let next = build(content.to_owned(), modified);
    let generation = next.generation.clone();
    *config = next;
    logs::info(
        "engine::config",
        "Configuration source replaced.",
        Some(logs::fields(&[("generation", generation.as_str())])),
    );
    Ok(())
}

/// Parses a candidate source without accepting it; the API validates a body
/// before a caller writes it.
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
pub fn config_source_json(id: &str) -> Option<String> {
    if id != SOURCE_ID {
        return None;
    }
    refresh();
    let config = current();
    Some(format!(
        r#"{{"id":"{}","path":"{}","kind":"main","content_sha256":"{}","bytes":{},"content":"{}","line_count":{},"writable":true,"loaded_at":"{}"}}"#,
        SOURCE_ID,
        SOURCE_PATH,
        config.sha256,
        config.bytes,
        json::escape(&config.content),
        config.content.lines().count(),
        state::iso8601(config.loaded_at),
    ))
}

pub fn effective_json() -> String {
    refresh();
    let config = current();
    let line_count = config.content.lines().count();
    let diagnostics = diagnostics_json(&config.diagnostics);
    format!(
        r#"{{"generation_id":"{}","revision":"{}","sources":[{{"id":"{}","path":"{}","kind":"main","content_sha256":"{}","bytes":{},"content":"{}","line_count":{},"writable":true,"loaded_at":"{}"}}],"diagnostics":{},"secrets_redacted":false}}"#,
        config.generation,
        config.revision,
        SOURCE_ID,
        SOURCE_PATH,
        config.sha256,
        config.bytes,
        json::escape(&config.content),
        line_count,
        state::iso8601(config.loaded_at),
        diagnostics
    )
}

pub fn rules_json() -> String {
    refresh();
    let config = current();
    let mut entries = Vec::with_capacity(config.rules.len() + 1);
    for rule in config.rules.iter().chain(std::iter::once(&config.fallback)) {
        let source = source_json(rule.line);
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
    let fallback_source = source_json(config.fallback.line);
    format!(
        r#"{{"generation_id":"{}","rules":[{}],"fallback":{{"outbound":"{}","source":{}}}}}"#,
        config.generation,
        entries.join(","),
        json::escape(&config.fallback.outbound),
        fallback_source
    )
}

fn source_json(line: u32) -> String {
    if line == 0 {
        return "null".to_string();
    }
    format!(
        r#"{{"file":"{}","source_id":"{}","line":{},"column":1}}"#,
        SOURCE_PATH, SOURCE_ID, line
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

fn node_entry(node: &Node, groups: &[&Group]) -> String {
    let group_ids = groups
        .iter()
        .map(|group| format!("\"group-{}\"", json::escape(&group.name)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"id":"node-{}","name":"{}","protocol":"{}","stream_transport":"tcp","subscription_tag":null,"provider_id":null,"group_ids":[{}],"health":{}}}"#,
        json::escape(&node.name),
        json::escape(&node.name),
        node.protocol,
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

fn groups_body(config: &Config) -> String {
    let entries = config
        .groups
        .iter()
        .map(|group| {
            let selection = select_member(group, &config)
                .map(|member| {
                    format!(
                        r#"{{"tcp_member_id":"node-{}","udp_member_id":null}}"#,
                        json::escape(&member)
                    )
                })
                .unwrap_or_else(|| r#"{"tcp_member_id":null,"udp_member_id":null}"#.to_string());
            format!(
                r#"{{"id":"group-{}","name":"{}","icon":null,"config_revision":"{}","policy":{{"kind":"{}","native":"{}"}},"member_count":{},"selection":{}}}"#,
                json::escape(&group.name),
                json::escape(&group.name),
                config.revision,
                group.policy.kind(),
                json::escape(&group.policy.native()),
                group.members.len(),
                selection
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
    let selected = select_member(group, &config);
    let selection = selected
        .map(|member| {
            format!(
                r#"{{"tcp":{{"member_id":"node-{}","resolved_leaf_node_id":"node-{}","source":"policy"}},"udp":null}}"#,
                json::escape(&member),
                json::escape(&member)
            )
        })
        .unwrap_or_else(|| r#"{"tcp":null,"udp":null}"#.to_string());
    Some(format!(
        concat!(
            r#"{{"id":"group-{}","name":"{}","icon":null,"config_revision":"{}","#,
            r#""policy":{{"kind":"{}","native":"{}"}},"#,
            r#""members":[{}],"#,
            r#""config":{{"default_member_id":{},"final_outbound":{},"check_url":null,"check_interval":null,"tolerance":null,"idle_timeout":null,"interrupt_connections":null}},"#,
            r#""runtime":{{"selection":{},"health":[]}},"#,
            r#""capabilities":{{"can_select":false,"can_override":false,"supports_nested_groups":false,"mutable_config":[],"probe_transports":["tcp"]}}}}"#
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
        selection
    ))
}

fn config_path() -> PathBuf {
    let directory = match std::env::var_os("LEMONVPN_DATA_DIR") {
        Some(directory) => PathBuf::from(directory),
        None => default_data_dir(),
    };
    directory.join(SOURCE_PATH)
}

fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("LemonVPN");
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config).join("lemonvpn");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("lemonvpn");
    }
    PathBuf::from(".")
}

struct RawRule {
    expression: String,
    outbound: String,
    condition: Option<Condition>,
    line: u32,
}

#[derive(Default)]
struct Parsed {
    rules: Vec<RawRule>,
    fallback: Option<RawRule>,
    nodes: Vec<Node>,
    groups: Vec<RawGroup>,
    upstreams: Vec<Upstream>,
    diagnostics: Vec<Diagnostic>,
}

struct RawGroup {
    name: String,
    filters: Vec<String>,
    policy: Option<Policy>,
    default: Option<String>,
    final_outbound: Option<String>,
    line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ctx {
    Node,
    GroupRoot,
    Group(String),
    DnsRoot,
    DnsUpstream,
    Routing,
    Ignored,
}

fn build(content: String, modified: Option<SystemTime>) -> Config {
    let sha256 = sha256::hex(content.as_bytes());
    let mut parsed = parse(&content);
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
            level: "warning",
            line: fallback.line,
            code: "fallback_outbound",
            message: format!(
                "fallback outbound `{}` is not direct, block, a node or a group; using direct",
                fallback.outbound
            ),
        });
        RawRule {
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
            id: format!("traffic:{index}"),
            index,
            expression: raw.expression,
            outbound: raw.outbound,
            condition: raw.condition,
            line: raw.line,
        })
        .collect();
    let fallback = Rule {
        id: format!("traffic:{}", rules.len()),
        index: rules.len(),
        expression: fallback.expression,
        outbound: fallback.outbound,
        condition: None,
        line: fallback.line,
    };
    Config {
        generation: format!("generation-{}", &sha256[..12]),
        revision: sha256.clone(),
        sha256,
        bytes: content.len(),
        content,
        rules,
        fallback,
        nodes: parsed.nodes,
        groups,
        upstreams: parsed.upstreams,
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
    for raw in raw_groups {
        let Some(policy) = raw.policy else {
            diagnostics.push(diagnostic(
                raw.line,
                "group_policy",
                format!(
                    "group `{}` has no supported policy (selector, fixed(n) or random)",
                    raw.name
                ),
            ));
            continue;
        };
        let mut members: Vec<String> = Vec::new();
        for filter in &raw.filters {
            match evaluate_filter(filter, &resolved, &node_names) {
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
            members,
        });
    }
    resolved
}

fn evaluate_filter(
    filter: &str,
    resolved: &[Group],
    node_names: &[&str],
) -> Result<Vec<String>, String> {
    let mut result: Option<Vec<String>> = None;
    for term in split_terms(filter) {
        let (negated, term) = match term.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, term.trim()),
        };
        let found = evaluate_term(negated, term, resolved, node_names)?;
        result = Some(match result {
            None => found,
            Some(current) => current
                .into_iter()
                .filter(|name| found.contains(name))
                .collect(),
        });
    }
    Ok(result.unwrap_or_default())
}

fn split_terms(filter: &str) -> Vec<&str> {
    filter.split("&&").map(str::trim).collect()
}

fn evaluate_term(
    negated: bool,
    term: &str,
    resolved: &[Group],
    node_names: &[&str],
) -> Result<Vec<String>, String> {
    let inner = term
        .strip_prefix("name(")
        .and_then(|rest| rest.strip_suffix(')'))
        .map(|value| ("name", value))
        .or_else(|| {
            term
                .strip_prefix("group(")
                .and_then(|rest| rest.strip_suffix(')'))
                .map(|value| ("group", value))
        });
    let Some((kind, inner)) = inner else {
        return Err(format!(
            "filter `{term}` is not name(...), group(...) or a ! negation of them"
        ));
    };
    let values = split_arguments(inner);
    if values.is_empty() {
        return Err(format!("filter `{term}` names nothing"));
    }
    let mut found = Vec::new();
    for value in values {
        match kind {
            "name" => {
                let (keyword, pattern) = match value.strip_prefix("keyword:") {
                    Some(pattern) => (true, pattern.trim()),
                    None => (false, value.as_str()),
                };
                if pattern.is_empty() {
                    return Err("filter name(...) has an empty argument".to_owned());
                }
                let pattern = pattern.to_ascii_lowercase();
                for name in node_names {
                    let matches = if keyword {
                        name.to_ascii_lowercase().contains(&pattern)
                    } else {
                        name.eq_ignore_ascii_case(&pattern)
                    };
                    if matches && !found.contains(&name.to_string()) {
                        found.push((*name).to_owned());
                    }
                }
            }
            _ => {
                let group = resolved
                    .iter()
                    .find(|group| group.name.eq_ignore_ascii_case(&value));
                let Some(group) = group else {
                    return Err(format!(
                        "filter group(`{value}`) names no group declared before this one"
                    ));
                };
                for member in &group.members {
                    if !found.contains(member) {
                        found.push(member.clone());
                    }
                }
            }
        }
    }
    if negated {
        Ok(node_names
            .iter()
            .filter(|name| !found.iter().any(|matched| matched == **name))
            .map(|name| (*name).to_owned())
            .collect())
    } else {
        Ok(found)
    }
}

fn split_arguments(inner: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in inner.chars() {
        match character {
            '\'' | '"' if quote == Some(character) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(character),
            ',' if quote.is_none() => {
                push_argument(&mut values, &mut current);
            }
            _ => current.push(character),
        }
    }
    push_argument(&mut values, &mut current);
    values
}

fn push_argument(values: &mut Vec<String>, current: &mut String) {
    let value = current.trim();
    if !value.is_empty() {
        values.push(value.to_owned());
    }
    current.clear();
}

fn parse(content: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut stack: Vec<Ctx> = Vec::new();
    let mut group: Option<RawGroup> = None;
    let mut upstream_block = false;

    for (offset, raw) in content.lines().enumerate() {
        let line = (offset + 1) as u32;
        let text = raw.split('#').next().unwrap_or("").trim();
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
                    group = Some(RawGroup {
                        name: name.to_owned(),
                        filters: Vec::new(),
                        policy: None,
                        default: None,
                        final_outbound: None,
                        line,
                    });
                    Ctx::Group(name.to_owned())
                }
                (Some(Ctx::DnsRoot), "upstream") => {
                    upstream_block = true;
                    Ctx::DnsUpstream
                }
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
            stack.pop();
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
            _ => {}
        }
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
        parsed.diagnostics.push(diagnostic(line, "node_name", "node name is empty".to_owned()));
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
    match parse_node_url(&value) {
        Ok((host, port, username, password)) => parsed.nodes.push(Node {
            name: name.to_owned(),
            protocol: "socks5",
            host,
            port,
            username,
            password,
        }),
        Err(message) => parsed.diagnostics.push(diagnostic(line, "node_url", message)),
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
        _ => {}
    }
}

fn parse_policy(value: &str) -> Option<Policy> {
    match value {
        "selector" => Some(Policy::Selector),
        "random" => Some(Policy::Random),
        _ => value
            .strip_prefix("fixed(")
            .and_then(|rest| rest.strip_suffix(')'))
            .and_then(|index| index.trim().parse().ok())
            .map(Policy::Fixed),
    }
}

fn parse_upstream_line(text: &str, line: u32, parsed: &mut Parsed) {
    let Some((name, value)) = text.split_once(':') else {
        return;
    };
    let name = unquote(name.trim());
    let value = unquote(value.trim());
    match parse_upstream_url(&value) {
        Ok((protocol, host, port)) => parsed.upstreams.push(Upstream {
            name,
            protocol,
            host,
            port,
        }),
        Err(message) => parsed.diagnostics.push(diagnostic(line, "dns_upstream", message)),
    }
}

fn parse_routing_line(text: &str, line: u32, parsed: &mut Parsed) {
    if let Some(value) = text.strip_prefix("fallback:") {
        match outbound_name(value.trim()) {
            Some(outbound) => {
                parsed.fallback = Some(RawRule {
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
    let Some(condition) = parse_condition(condition_text.trim()) else {
        parsed.diagnostics.push(diagnostic(
            line,
            "rule_condition",
            "routing condition must be domain(full: ...), domain(suffix: ...) or ip(cidr: ...)"
                .to_owned(),
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

fn parse_condition(text: &str) -> Option<Condition> {
    if let Some(inner) = text.strip_prefix("l4proto(").and_then(|rest| rest.strip_suffix(')')) {
        // The datapath carries TCP only; a UDP-only rule cannot match here.
        let includes_tcp = inner.split(',').any(|protocol| protocol.trim() == "tcp");
        return includes_tcp.then_some(Condition::All);
    }
    if let Some(inner) = text.strip_prefix("ip(").and_then(|rest| rest.strip_suffix(')')) {
        let (kind, value) = inner.split_once(':')?;
        if kind.trim() != "cidr" {
            return None;
        }
        let (address, prefix) = value.trim().split_once('/')?;
        let address: IpAddr = address.trim().parse().ok()?;
        let prefix: u8 = prefix.trim().parse().ok()?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        return (prefix <= maximum).then_some(Condition::IpCidr(address, prefix));
    }

    let inner = text
        .strip_prefix("domain(")
        .and_then(|rest| rest.strip_suffix(')'))?;
    let (kind, value) = inner.split_once(':')?;
    let value = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.is_empty() || value.contains(char::is_whitespace) {
        return None;
    }
    match kind.trim() {
        "full" => Some(Condition::DomainFull(value)),
        "suffix" => Some(Condition::DomainSuffix(value)),
        _ => None,
    }
}

/// Parses `socks5://[user[:pass]@]host:port` (IPv6 in brackets).
fn parse_node_url(
    value: &str,
) -> Result<(String, u16, Option<String>, Option<String>), String> {
    let rest = value
        .strip_prefix("socks5://")
        .ok_or_else(|| format!("node `{value}` is not a socks5:// URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if !path.is_empty() {
        return Err(format!("node `{value}` has a path; only socks5://host:port is supported"));
    }
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    let (host, port) = parse_host_port(hostport)
        .ok_or_else(|| format!("node `{value}` has no host:port"))?;
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((user, pass)) => (
                Some(percent_decode(user)),
                Some(percent_decode(pass)),
            ),
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
    let (host, port) = parse_host_port(rest)
        .ok_or_else(|| format!("DNS upstream `{value}` has no host:port"))?;
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

fn unquote(value: &str) -> String {
    value
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string()
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
    use super::{build, parse_condition, parse_node_url, Condition, Policy, Target};
    use std::net::{IpAddr, Ipv4Addr};

    fn config(source: &str) -> super::Config {
        build(source.to_owned(), None)
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
        assert!(matches!(decision.target, Target::Socks5 { ref host, port: 1080, .. } if host == "10.0.0.2"));
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
        assert!(super::nodes_body(&config, None)
            .contains("\"group_ids\":[\"group-hk\",\"group-all\"]"));
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
             group {\n  bad {\n    filter: name('edge')\n    policy: score\n  }\n}\n\
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
            ("::1".to_owned(), 1080, Some("u@x".to_owned()), Some("p:w".to_owned()))
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
}
