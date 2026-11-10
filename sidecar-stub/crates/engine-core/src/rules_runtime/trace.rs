use super::*;
#[derive(serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Request {
    domain: String,
    r#type: String,
    live: bool,
    network: String,
    port: u16,
    destination_ip: Option<std::net::IpAddr>,
    source_ip: Option<std::net::IpAddr>,
    source_port: Option<u16>,
    process: Option<String>,
}
impl Default for Request {
    fn default() -> Self {
        Self {
            domain: String::new(),
            r#type: "A".into(),
            live: false,
            network: "tcp".into(),
            port: 443,
            destination_ip: None,
            source_ip: None,
            source_port: None,
            process: None,
        }
    }
}
pub fn run(body: &str) -> Result<Value, String> {
    let request: Request = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let host = url::Host::parse(request.domain.trim().trim_end_matches('.'))
        .map_err(|_| "域名或 IP 格式无效")?
        .to_string();
    if !matches!(request.network.as_str(), "tcp" | "udp")
        || !crate::dns::RECORD_TYPES.contains(&request.r#type.as_str())
    {
        return Err("协议或 DNS 类型无效".into());
    }
    let initial = crate::config::generation();
    let dns = if request.live {
        let result = crate::dns::query_json(
            &json!({"domain":host,"type":[request.r#type],"cache_mode":"normal"}).to_string(),
        )
        .map_err(|(_, _, e)| e)?;
        serde_json::from_str::<Value>(&result).map_err(|e| e.to_string())?
    } else {
        Value::Null
    };
    let resolved = request.destination_ip.or_else(|| {
        dns["results"].as_array().and_then(|rows| {
            rows.iter()
                .flat_map(|r| r["answers"].as_array().into_iter().flatten())
                .filter_map(|a| a["data"].as_str()?.parse().ok())
                .next()
        })
    });
    let process = request
        .process
        .as_deref()
        .map(crate::platform::process::ProcessInfo::selector);
    let mut input = RoutingInput::new(&host, &request.network);
    input.destination_ip = resolved;
    input.destination_port = Some(request.port);
    input.source_ip = request.source_ip;
    input.source_port = request.source_port;
    input.process = process.as_ref();
    input.query_type = Some(&request.r#type);
    let route = crate::config::trace_input(input);
    let snapshot = current();
    let mut matches = Vec::new();
    let mut mode = None;
    let mut dns_input = RoutingInput::new(&host, "udp");
    dns_input.query_type = Some(&request.r#type);
    for (policy, condition) in &snapshot.policies {
        let matched = crate::config::condition_matches_input(condition, &dns_input);
        matches.push(json!({"id":policy.id,"name":policy.name,"condition":policy.condition,"matched":matched,"pool":policy.pool,"address_mode":policy.address_mode}));
        if matched {
            break;
        }
    }
    for (policy, condition) in &snapshot.policies {
        if policy.address_mode != "inherit"
            && crate::config::condition_matches_input(condition, &dns_input)
        {
            mode = Some(policy.address_mode.clone());
            break;
        }
    }
    let provider_matches=snapshot.sets.values().map(|set|json!({"id":set.id,"sha256":set.digest,"known":set.set.known(&input),"matched":set.set.matches(&input),"count":set.set.entries.len()})).collect::<Vec<_>>();
    let settings = crate::dns_settings::current().map_err(|e| e.to_string())?;
    let excluded = settings.filters.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("+.") {
            return host == suffix || host.ends_with(&format!(".{suffix}"));
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return host.ends_with(&format!(".{suffix}"));
        }
        host == *pattern
    });
    let address_mode = if settings.mode == "redir-host" || excluded {
        "real-ip"
    } else {
        match mode.as_deref() {
            Some("real-ip") => "real-ip",
            _ => "fake-ip",
        }
    };
    if initial != crate::config::generation() {
        return Err("追踪期间配置发生变化，请重新查询".into());
    }
    Ok(
        json!({"generation_id":initial,"resource_revision":snapshot.revision,"live":request.live,"domain":host,"route":route,"dns":dns,"dns_policies":matches,"dns_steps":if request.live{crate::dns::trace_steps()}else{vec![]},"selected_dns":crate::config::dns_route_for(&host,Some(&request.r#type)),"resources":provider_matches,"endpoint":if request.live&&crate::dns::cache_source()=="upstream"{crate::dns_transport::last_endpoint()}else{None},
        "fake_ip":{"configured_mode":address_mode,"tun_active":crate::compat::tun_active(),"excluded":excluded,"ipv4_range":settings.ipv4_range,"ipv6_range":settings.ipv6_range,"mapping_allocated":false},
        "cache_source":if request.live{crate::dns::cache_source()}else{"not_queried"},"note":if request.live{"实际执行 DNS 查询；未发送网站连接探测"}else{"离线分析；未发出 DNS 或网站请求"}}),
    )
}
