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
}
impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: "fake-ip".into(),
            ipv4_range: "198.18.0.1/16".into(),
            ipv6_range: "fc00::/18".into(),
            filters: Vec::new(),
            store_fake_ip: false,
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
                .strip_prefix("*.")
                .or_else(|| pattern.strip_prefix("+."))
                .unwrap_or(&pattern);
            if pattern != "*"
                && (host.is_empty()
                    || host.len() > 253
                    || !host.is_ascii()
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }))
            {
                return Err(io::Error::other(format!(
                    "无效排除域名：{pattern}（支持 *.example.com、+.example.com）"
                )));
            }
            if !filters.contains(&pattern) {
                filters.push(pattern);
            }
        }
        self.filters = filters;
        Ok(self)
    }
    pub fn from_request(value: &Value) -> io::Result<Self> {
        match value.get("dns_settings") {
            Some(value) => serde_json::from_value::<Self>(value.clone())
                .map_err(|e| io::Error::other(format!("DNS 设置格式错误：{e}")))?
                .validated(),
            None => Ok(Self::default()),
        }
    }
    pub fn apply(&self, config: &mut Value) {
        config["dns"]["enhanced-mode"] = json!(self.mode);
        config["dns"]["fake-ip-range"] = json!(self.ipv4_range);
        config["dns"]["fake-ip-range6"] = json!(self.ipv6_range);
        config["dns"]["fake-ip-filter-mode"] = json!("blacklist");
        config["dns"]["fake-ip-filter"] = json!(self.filters);
        config["profile"]["store-fake-ip"] = json!(self.store_fake_ip);
    }
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
        .any(|key| old["dns"][key] != next["dns"][key])
        || old["profile"]["store-fake-ip"] != next["profile"]["store-fake-ip"];
    let result: io::Result<()> = (|| {
        if reset {
            process.request("POST", "/cache/fakeip/flush", None)?;
        }
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
