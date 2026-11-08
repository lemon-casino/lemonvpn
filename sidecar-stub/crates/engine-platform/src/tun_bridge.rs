//! A fixed TUN-to-authenticated-loopback bridge. Privileged code never receives
//! proxy definitions, executable paths, arbitrary core configs or API requests.
use crate::managed::{self, CoreProcess};
#[cfg(windows)]
use crate::service as broker;
#[cfg(target_os = "macos")]
use crate::service_macos as broker;
use serde_json::{json, Value};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

pub fn configuration(router_port: u16, dns_port: u16, password: &str) -> io::Result<Value> {
    if router_port < 1024
        || password.len() != 64
        || !password.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN 桥接参数无效",
        ));
    }
    if dns_port < 1024 {
        return Err(io::Error::other("DNS 桥接端口无效"));
    }
    let mut config = json!({
        "ipv6":true,"allow-lan":false,"mode":"rule","log-level":"warning","find-process-mode":"off",
        "proxies":[{"name":"LemonVPN-Router","type":"socks5","server":"127.0.0.1","port":router_port,"username":"lemonvpn-tun","password":password,"udp":true}],
        "rules":["MATCH,LemonVPN-Router"],
        "tun":{"enable":true,"device":"LemonVPN","stack":"gvisor","auto-route":true,"auto-detect-interface":true,"dns-mode":"native","strict-route":true,"mtu":1500,"dns-hijack":["any:53","tcp://any:53"],"inet6-address":["fdfe:dcba:9876::1/126"],"route-address":["0.0.0.0/1","128.0.0.0/1","::/1","8000::/1"],"route-exclude-address":["127.0.0.0/8","::1/128"],"udp-timeout":120},
        "dns":{"enable":true,"ipv6":true,"enhanced-mode":"fake-ip","fake-ip-range":"198.18.0.1/16","fake-ip-range6":"fc00::/18","default-nameserver":["223.5.5.5","1.1.1.1"],"nameserver":[format!("udp://127.0.0.1:{dns_port}")],"respect-rules":false},
        "profile":{"store-selected":false,"store-fake-ip":false},
    });
    apply_processes(&mut config, &[])?;
    Ok(config)
}

pub fn process_token(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let name = if cfg!(windows) {
        name.replace('/', "\\").to_lowercase()
    } else {
        name.to_owned()
    };
    let digest = Sha256::digest(name.as_bytes());
    format!(
        "lemonvpn-p-{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
pub fn process_list(value: &Value) -> io::Result<Vec<String>> {
    let Some(value) = value.get("process_names") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .filter(|values| values.len() <= 256)
        .ok_or_else(|| io::Error::other("进程规则数量无效"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("进程规则类型无效"))
        })
        .collect()
}
pub fn apply_processes(config: &mut Value, names: &[String]) -> io::Result<()> {
    if names.len() > 256
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 1024
                || name.contains(',')
                || name.chars().any(char::is_control)
        })
    {
        return Err(io::Error::other("进程规则无效"));
    }
    let base = config["proxies"][0].clone();
    let mut proxies = vec![base.clone()];
    let mut rules = Vec::new();
    let mut names = names.to_vec();
    names.sort_by_key(|name| !name.contains(['/', '\\']));
    names.dedup();
    for name in &names {
        let token = process_token(name);
        let mut proxy = base.clone();
        proxy["name"] = json!(token);
        proxy["username"] = json!(token);
        rules.push(format!(
            "{},{},{}",
            if name.contains(['/', '\\']) {
                "PROCESS-PATH"
            } else {
                "PROCESS-NAME"
            },
            name,
            token
        ));
        proxies.push(proxy);
    }
    rules.push("MATCH,LemonVPN-Router".to_owned());
    config["proxies"] = json!(proxies);
    config["rules"] = json!(rules);
    config["find-process-mode"] = json!(if names.is_empty() { "off" } else { "always" });
    Ok(())
}

enum Owner {
    Local(CoreProcess),
    #[cfg(any(windows, target_os = "macos"))]
    Service,
}
pub struct TunBridge {
    owner: Owner,
    checked: Instant,
    cached: bool,
    stopped: bool,
    config: Value,
    process_names: Vec<String>,
}
impl TunBridge {
    pub fn start(
        router_port: u16,
        dns_port: u16,
        password: &str,
        directory: PathBuf,
        process_names: Vec<String>,
    ) -> io::Result<Self> {
        let mut config = configuration(router_port, dns_port, password)?;
        apply_processes(&mut config, &process_names)?;
        #[cfg(any(windows, target_os = "macos"))]
        {
            if broker::installed() {
                broker::request(
                    &json!({"action":"start","router_port":router_port,"dns_port":dns_port,"password":password,"process_names":process_names}),
                )?;
                return Ok(Self {
                    owner: Owner::Service,
                    checked: Instant::now(),
                    cached: true,
                    stopped: false,
                    config,
                    process_names,
                });
            }
            if !broker::is_elevated() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TUN 需要先安装管理员服务",
                ));
            }
        }
        let process = CoreProcess::start(
            &managed::core_path().ok_or_else(|| io::Error::other("缺少 TUN 兼容内核"))?,
            directory.join(format!("tun-{}", std::process::id())),
            config.clone(),
            managed::random_secret()?,
        )?;
        Ok(Self {
            owner: Owner::Local(process),
            checked: Instant::now(),
            cached: true,
            stopped: false,
            config,
            process_names,
        })
    }
    pub fn update_processes(&mut self, names: Vec<String>) -> io::Result<()> {
        if self.stopped || self.process_names == names {
            return Ok(());
        }
        let mut next = self.config.clone();
        apply_processes(&mut next, &names)?;
        match &mut self.owner {
            Owner::Local(process) => process.configure(next.clone())?,
            #[cfg(any(windows, target_os = "macos"))]
            Owner::Service => {
                broker::request(&json!({"action":"process_rules","process_names":names}))?;
            }
        }
        self.config = next;
        self.process_names = names;
        Ok(())
    }
    /// Fixed operation only: never expose an arbitrary privileged controller request.
    pub fn flush_dns(&self) -> io::Result<()> {
        match &self.owner {
            Owner::Local(process) => process
                .request("POST", "/cache/dns/flush", None)
                .map(|_| ()),
            #[cfg(any(windows, target_os = "macos"))]
            Owner::Service => broker::request(&json!({"action":"flush_dns"}))
                .map(|_| ())
                .map_err(|error| {
                    io::Error::other(format!(
                        "TUN DNS 缓存同步失败；旧服务请在 TUN 模式中更新服务：{error}"
                    ))
                }),
        }
    }
    pub fn alive(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        if self.checked.elapsed() < Duration::from_millis(500) {
            return self.cached;
        }
        self.cached = match &mut self.owner {
            Owner::Local(process) => process.alive(),
            #[cfg(any(windows, target_os = "macos"))]
            Owner::Service => broker::request(&json!({"action":"status"}))
                .ok()
                .and_then(|v| v.get("enabled").and_then(Value::as_bool))
                .unwrap_or(false),
        };
        self.checked = Instant::now();
        self.cached
    }
    pub fn shutdown(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        match &mut self.owner {
            Owner::Local(process) => {
                if process.alive() {
                    process.request("PATCH", "/configs", Some(&json!({"tun":{"enable":false}})))?;
                }
            }
            #[cfg(any(windows, target_os = "macos"))]
            Owner::Service => {
                broker::request(&json!({"action":"stop"}))?;
            }
        }
        self.stopped = true;
        self.cached = false;
        Ok(())
    }
}
impl Drop for TunBridge {
    fn drop(&mut self) {
        #[cfg(any(windows, target_os = "macos"))]
        if !self.stopped && matches!(self.owner, Owner::Service) {
            let _ = broker::request(&json!({"action":"stop"}));
        }
    }
}
