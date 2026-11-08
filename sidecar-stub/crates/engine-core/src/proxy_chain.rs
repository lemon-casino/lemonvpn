//! Configured proxy dependencies, static validation and non-network path preview.
use super::*;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Default)]
struct SelectionWatch {
    generation: String,
    choices: HashMap<(String, String), Option<String>>,
}

static WATCH: OnceLock<Mutex<SelectionWatch>> = OnceLock::new();
pub(crate) fn sync_selection_changes() {
    WATCH
        .get_or_init(|| Mutex::new(SelectionWatch::default()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .sync();
}

impl SelectionWatch {
    /// Called by the existing policy worker, without its health mutex held.
    pub(crate) fn sync(&mut self) {
        let config = current();
        if self.generation != config.generation {
            self.generation = config.generation.clone();
            self.choices.clear();
        }
        let mut wanted = HashSet::new();
        let mut pending: Vec<_> = config
            .groups
            .iter()
            .filter(|group| group.dialer.is_some())
            .map(|group| group.name.clone())
            .collect();
        while let Some(name) = pending.pop() {
            if !wanted.insert(name.clone()) {
                continue;
            }
            if let Some(group) = config.groups.iter().find(|group| group.name == name) {
                pending.extend(
                    [&group.dialer, &group.landing, &group.final_outbound]
                        .into_iter()
                        .filter_map(|name| name.clone()),
                );
            }
        }
        let mut next = HashMap::new();
        let mut changed = false;
        for group in config.groups.iter().filter(|group| {
            wanted.contains(&group.name)
                && group.policy.automatic()
                && !matches!(group.policy, Policy::RoundRobin)
        }) {
            for network in ["tcp", "udp"] {
                if crate::control::selection_override_for(&group.name, network).is_some() {
                    continue;
                }
                let key = (group.name.clone(), network.to_owned());
                let choice = select_member_for(group, &config, network, false);
                if self.choices.get(&key).is_some_and(|old| old != &choice) {
                    crate::connections::selection_changed(&group.name, network);
                    changed = true;
                }
                next.insert(key, choice);
            }
        }
        self.choices = next;
        drop(config);
        if changed {
            crate::events::runtime_changed();
        }
    }
}

fn possible(
    name: &str,
    groups: &[Group],
    nodes: &[Node],
    visiting: &mut Vec<String>,
    work: &mut usize,
) -> Result<(HashSet<String>, usize), String> {
    if *work == 0 {
        return Err("链路引用过多，请简化前置组配置".into());
    }
    *work -= 1;
    if matches!(name, "direct" | "block") {
        return Err("前置代理必须是节点或策略组".into());
    }
    if visiting.len() >= 16 || visiting.iter().any(|seen| seen == name) {
        return Err("链路存在循环引用或嵌套过深".into());
    }
    let node = nodes.iter().find(|node| node.name == name);
    let group = groups.iter().find(|group| group.name == name);
    if node.is_some() && group.is_some() {
        return Err(format!("“{name}”同时是节点名和组名"));
    }
    if let Some(node) = node {
        return Ok(([node.name.clone()].into(), 1));
    }
    let group = group.ok_or_else(|| format!("前置代理“{name}”不存在或不是代理节点／组"))?;
    visiting.push(name.to_owned());
    let result = (|| {
        let (mut exits, mut depth) = if group.dialer.is_some() {
            if let Some(exit) = &group.landing {
                possible(exit, groups, nodes, visiting, work)?
            } else {
                (group.members.iter().cloned().collect(), 1)
            }
        } else {
            (group.members.iter().cloned().collect(), 1)
        };
        // Check dormant fallback edges too: subscription updates can activate them.
        if let Some(fallback) = &group.final_outbound {
            if !matches!(fallback.as_str(), "direct" | "block") {
                let (names, count) = possible(fallback, groups, nodes, visiting, work)?;
                exits.extend(names);
                depth = depth.max(count);
            }
        }
        if exits.is_empty() {
            return Err(format!("前置组“{name}”没有可用的节点"));
        }
        if let Some(via) = &group.dialer {
            let (front, count) = possible(via, groups, nodes, visiting, work)?;
            if !front.is_disjoint(&exits) {
                return Err(format!("链路“{name}”的前置与落地不能包含相同节点"));
            }
            exits.extend(front);
            depth += count;
        }
        if depth > 8 {
            return Err("代理链最多支持 8 个物理节点".into());
        }
        Ok((exits, depth))
    })();
    visiting.pop();
    result
}

pub(super) fn validate(
    raw: &[RawGroup],
    groups: &[Group],
    nodes: &[Node],
    diagnostics: &mut Vec<Diagnostic>,
) {
    for group in groups.iter().filter(|group| group.dialer.is_some()) {
        let line = raw
            .iter()
            .find(|raw| raw.name == group.name)
            .map_or(0, |raw| raw.line);
        if let Err(message) = possible(&group.name, groups, nodes, &mut Vec::new(), &mut 2048) {
            diagnostics.push(diagnostic(
                line,
                "proxy_chain",
                format!("链式代理“{}”：{message}", group.name),
            ));
        }
    }
}

pub(super) fn path(config: &Config, name: &str, network: &str) -> Value {
    match resolve_outbound_for(config, name, &mut Vec::new(), network, false) {
        Some((Target::Chain { nodes, front_len }, _, dependencies)) => {
            let problem = if crate::compat::available() {
                crate::compat::chain_error(&nodes, network)
            } else {
                Some("缺少协议兼容内核，无法建立代理链".into())
            };
            let hops: Vec<Value> = nodes.iter().enumerate().map(|(index,node)| json!({"id":format!("node-{}",node.name),"name":node.name,"protocol":node.protocol,"role":if index < front_len {"front"} else {"exit"}})).collect();
            json!({"hops":hops,"front_hops":&hops[..front_len],"exit_hops":&hops[front_len..],"groups":dependencies,"ready":problem.is_none(),"error":problem})
        }
        _ if config
            .groups
            .iter()
            .any(|group| group.name == name && group.dialer.is_some()) =>
        {
            json!({"hops":[],"groups":[name],"ready":false,"error":"链路尚未选出完整节点，流量不会退回直连"})
        }
        _ => Value::Null,
    }
}

pub(super) fn preview(config: &Config, group: &Group) -> Value {
    let Some(via) = &group.dialer else {
        return Value::Null;
    };
    let selected = |network| {
        let value = path(config, &group.name, network);
        if value.is_null() {
            json!({"hops":[],"groups":[],"ready":false,"error":"链路尚未选出完整节点，流量不会退回直连"})
        } else {
            value
        }
    };
    json!({"via":via,"exit":group.landing,"generation_id":config.generation,"tcp":selected("tcp"),"udp":selected("udp"),"source":"configuration","network_performed":false})
}
