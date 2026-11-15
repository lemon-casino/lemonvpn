//! Bounded DNS controls shared with the privileged TUN brokers.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{io, net::IpAddr};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsSettings {
    pub mode: String,
    pub ipv4_range: String,
    pub ipv6_range: String,
    pub filters: Vec<String>,
    pub store_fake_ip: bool,
    #[serde(default = "enabled")]
    pub ipv6_enabled: bool,
    #[serde(default)]
    pub sniff_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_rules: Vec<AddressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_sets: Vec<DomainSet>,
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddressRule {
    pub set_id: String,
    pub mode: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainSet {
    pub id: String,
    pub entries: Vec<String>,
}
impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: "fake-ip".into(),
            ipv4_range: "198.18.0.1/16".into(),
            ipv6_range: "fc00::/18".into(),
            filters: Vec::new(),
            store_fake_ip: false,
            ipv6_enabled: true,
            sniff_enabled: false,
            address_rules: Vec::new(),
            domain_sets: Vec::new(),
        }
    }
}
impl DnsSettings {
    pub fn validated(mut self) -> io::Result<Self> {
        if !matches!(self.mode.as_str(), "fake-ip" | "redir-host") {
            return Err(io::Error::other("DNS 模式仅支持 fake-ip 或 redir-host"));
        }
        self.ipv4_range = self.ipv4_range.trim().to_owned();
        self.ipv6_range = self.ipv6_range.trim().to_owned();
        self.ipv4_range = validate_range(&self.ipv4_range, false)?;
        if !self.ipv6_range.is_empty() {
            self.ipv6_range = validate_range(&self.ipv6_range, true)?;
        }
        if self.filters.len() > 256 {
            return Err(io::Error::other("排除名单最多 256 项"));
        }
        let mut filters = Vec::new();
        for pattern in self.filters {
            let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
            let host = pattern
                .strip_prefix("+.")
                .or_else(|| pattern.strip_prefix('.'))
                .unwrap_or(&pattern);
            if host.is_empty()
                || host.len() > 253
                || !host.is_ascii()
                || host.split('.').any(|label| {
                    label != "*"
                        && (label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                })
            {
                return Err(io::Error::other(format!(
                    "无效排除域名：{pattern}（* 匹配一级，+. 包含所有子域）"
                )));
            }
            if !filters.contains(&pattern) {
                filters.push(pattern);
            }
        }
        self.filters = filters;
        if self.address_rules.len() > 128 || self.domain_sets.len() > 128 {
            return Err(io::Error::other("Fake-IP 分类数量超限"));
        }
        let valid_id = |id: &str| {
            !id.is_empty()
                && id.len() <= 80
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        let mut ids = std::collections::HashSet::new();
        let mut count = 0;
        let mut bytes = 0;
        for set in &self.domain_sets {
            if !valid_id(&set.id) || !ids.insert(&set.id) {
                return Err(io::Error::other("Fake-IP 域名集 ID 无效或重复"));
            }
            for entry in &set.entries {
                count += 1;
                bytes += entry.len();
                let (kind, value) = entry
                    .split_once(',')
                    .ok_or_else(|| io::Error::other("Fake-IP 域名条目无效"))?;
                if !matches!(
                    kind,
                    "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX"
                ) || value.is_empty()
                    || value.len() > 4096
                    || entry.contains(['\n', '\r', '\0'])
                {
                    return Err(io::Error::other("Fake-IP 产物仅接受有界的域名条件"));
                }
            }
        }
        if count > 1_000_000 || bytes > 24 * 1024 * 1024 {
            return Err(io::Error::other("Fake-IP 域名产物超过上限"));
        }
        for rule in &self.address_rules {
            if !ids.contains(&rule.set_id) || !matches!(rule.mode.as_str(), "real-ip" | "fake-ip") {
                return Err(io::Error::other("Fake-IP 分类引用或动作无效"));
            }
        }
        Ok(self)
    }
    pub fn from_request(value: &Value) -> io::Result<Self> {
        if let Some(id) = value.get("dns_settings_artifact").and_then(Value::as_str) {
            return crate::dns_artifact::read(id)?.validated();
        }
        match value.get("dns_settings") {
            Some(value) => serde_json::from_value::<Self>(value.clone())
                .map_err(|e| io::Error::other(format!("DNS 设置格式错误：{e}")))?
                .validated(),
            None => Ok(Self::default()),
        }
    }
    pub fn apply(&self, config: &mut Value) {
        config["ipv6"] = json!(self.ipv6_enabled);
        config["dns"]["ipv6"] = json!(self.ipv6_enabled);
        config["tun"]["inet6-address"] = if self.ipv6_enabled {
            json!(["fdfe:dcba:9876::1/126"])
        } else {
            json!([])
        };
        config["tun"]["route-address"] = if self.ipv6_enabled {
            json!(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"])
        } else {
            json!(["0.0.0.0/1", "128.0.0.0/1"])
        };
        config["sniffer"] = json!({"enable":self.sniff_enabled,"parse-pure-ip":true,"override-destination":true,"skip-domain":["Mijia Cloud","+.push.apple.com"],"sniff":{"HTTP":{"ports":[80,"8080-8880"]},"TLS":{"ports":[443,8443]},"QUIC":{"ports":[443,8443]}}});
        config["dns"]["enhanced-mode"] = json!(self.mode);
        config["dns"]["fake-ip-range"] = json!(self.ipv4_range);
        config["dns"]["fake-ip-range6"] = json!(self.ipv6_range);
        config["dns"]["fake-ip-filter-mode"] = json!("blacklist");
        config["dns"]["fake-ip-filter"] = json!(self.filters);
        config["profile"]["store-fake-ip"] = json!(self.store_fake_ip);
        config["rule-providers"] = json!({});
        if !self.address_rules.is_empty() {
            let mut rules = Vec::new();
            for pattern in &self.filters {
                if let Some(suffix) = pattern.strip_prefix("+.") {
                    rules.push(format!("DOMAIN-SUFFIX,{suffix},real-ip"));
                } else if pattern.contains('*') || pattern.starts_with('.') {
                    rules.push(format!("DOMAIN-REGEX,{},real-ip", filter_regex(pattern)));
                } else {
                    rules.push(format!("DOMAIN,{pattern},real-ip"));
                }
            }
            for set in &self.domain_sets {
                config["rule-providers"][&set.id] = json!({"type":"inline","behavior":"classical","format":"yaml","payload":set.entries});
            }
            for rule in &self.address_rules {
                rules.push(format!("RULE-SET,{},{mode}", rule.set_id, mode = rule.mode));
            }
            rules.push("MATCH,fake-ip".into());
            config["dns"]["fake-ip-filter-mode"] = json!("rule");
            config["dns"]["fake-ip-filter"] = json!(rules);
        }
    }
    pub fn version(&self) -> u64 {
        3
    }
}
/// Match the same label wildcards as Mihomo's DNS domain trie, without regex
/// compilation or a backtracking matcher on the query path.
pub fn filter_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = pattern
        .strip_prefix("+.")
        .or_else(|| pattern.strip_prefix('.'));
    let value = suffix.unwrap_or(pattern);
    let labels: Vec<_> = value.split('.').collect();
    let names: Vec<_> = host.split('.').collect();
    if names.len() < labels.len()
        || (suffix.is_none() && names.len() != labels.len())
        || (pattern.starts_with('.') && names.len() == labels.len())
    {
        return false;
    }
    labels
        .iter()
        .zip(&names[names.len() - labels.len()..])
        .all(|(a, b)| *a == "*" || a == b)
}
fn filter_regex(pattern: &str) -> String {
    let (prefix, value) = if let Some(s) = pattern.strip_prefix("+.") {
        ("(?:[^.]+\\.)*", s)
    } else if let Some(s) = pattern.strip_prefix('.') {
        ("(?:[^.]+\\.)+", s)
    } else {
        ("", pattern)
    };
    let labels = value
        .split('.')
        .map(|s| {
            if s == "*" {
                "[^.]+".to_owned()
            } else {
                s.replace('-', "\\-")
            }
        })
        .collect::<Vec<_>>()
        .join("\\.");
    format!("^{prefix}{labels}$")
}
fn validate_range(text: &str, ipv6: bool) -> io::Result<String> {
    let error = || {
        io::Error::other(if ipv6 {
            "IPv6 地址池须为有效单播 CIDR，前缀 /8～/125；也可留空"
        } else {
            "IPv4 地址池须为有效单播 CIDR，前缀 /8～/29"
        })
    };
    let (address, bits) = text.split_once('/').ok_or_else(error)?;
    let ip: IpAddr = address.parse().map_err(|_| error())?;
    let bits: u32 = bits.parse().map_err(|_| error())?;
    if ip.is_ipv6() != ipv6
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || !(8..=if ipv6 { 125 } else { 29 }).contains(&bits)
    {
        return Err(error());
    }
    if matches!(ip, IpAddr::V4(v4) if v4.octets()[0]==0 || v4.octets()[0]>=224)
        || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
    {
        return Err(error());
    }
    let address = match ip {
        IpAddr::V4(ip) => {
            let network = u32::from(ip) & (u32::MAX << (32 - bits));
            // Mihomo also uses this address as the TUN interface address.
            // Keep it on the reserved gateway, outside the allocated Fake-IP entries.
            IpAddr::V4(std::net::Ipv4Addr::from(network | 1))
        }
        IpAddr::V6(ip) => {
            let network = u128::from(ip) & (u128::MAX << (128 - bits));
            if network == 0 {
                return Err(error());
            }
            IpAddr::V6(std::net::Ipv6Addr::from(network))
        }
    };
    Ok(format!("{address}/{bits}"))
}

pub fn hot_apply(
    process: &crate::managed::CoreProcess,
    old: &Value,
    next: &Value,
) -> io::Result<()> {
    let reset = ["enhanced-mode", "fake-ip-range", "fake-ip-range6"]
        .iter()
        .any(|key| old["dns"][key] != next["dns"][key]);
    let result: io::Result<()> = (|| {
        process.configure(next.clone())?;
        if reset {
            process.request("POST", "/cache/fakeip/flush", None)?;
        }
        process.request("POST", "/cache/dns/flush", None)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(match process.configure(old.clone()) {
            Ok(_) => io::Error::other(format!("DNS 热更新失败，已恢复原配置：{error}")),
            Err(rollback) => {
                io::Error::other(format!("DNS 热更新失败：{error}；恢复失败：{rollback}"))
            }
        });
    }
    Ok(())
}
