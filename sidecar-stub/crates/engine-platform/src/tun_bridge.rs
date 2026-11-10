//! A fixed TUN-to-authenticated-loopback bridge. Privileged code never receives
//! proxy definitions, executable paths, arbitrary core configs or API requests.
use crate::managed::{self, CoreProcess};
use crate::dns_settings::DnsSettings;
#[cfg(windows)]
use crate::service as broker;
#[cfg(target_os = "macos")]
use crate::service_macos as broker;
#[cfg(target_os = "linux")]
use crate::service_linux as broker;
use serde_json::{json, Value};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

#[cfg(any(windows,target_os="macos",target_os="linux"))]
fn broker_payload(mut value:Value)->io::Result<Value>{
    let started=std::time::Instant::now();
    if let Some(settings)=value.get("dns_settings"){
        let bytes=serde_json::to_vec(settings)?;
        if bytes.len()>64*1024{
            use sha2::{Digest,Sha256};
            let status=broker::request(&json!({"action":"status"}))?;
            if status["dns_settings_version"].as_u64().unwrap_or(0)<2{return Err(io::Error::other("TUN 服务需更新后才能应用规则集/Fake-IP 联动"));}
            let id=format!("{:x}",Sha256::digest(&bytes));
            broker::request(&json!({"action":"dns_artifact_begin","id":id,"size":bytes.len()}))?;
            for (i,chunk) in bytes.chunks(24*1024).enumerate(){
                if started.elapsed()>Duration::from_secs(30){return Err(io::Error::new(io::ErrorKind::TimedOut,"DNS 域名产物传输超时"))}
                let hex=chunk.iter().map(|b|format!("{b:02x}")).collect::<String>();
                broker::request(&json!({"action":"dns_artifact_part","id":id,"offset":i*24*1024,"hex":hex}))?;
            }
            broker::request(&json!({"action":"dns_artifact_commit","id":id}))?;
            value.as_object_mut().unwrap().remove("dns_settings");value["dns_settings_artifact"]=json!(id);
        }
    }
    broker::request(&value)
}
#[cfg(any(windows,target_os="macos",target_os="linux"))]
fn send_dns_settings(settings:&DnsSettings)->io::Result<Value>{broker_payload(json!({"action":"dns_settings","dns_settings":settings}))}

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
    #[cfg(target_os = "linux")]
    {
        // The egress broker owns priorities 8750..8799; capture follows them.
        config["tun"]["iproute2-rule-index"] = json!(9000);
        config["tun"]["iproute2-table-index"] = json!(2022);
        config["tun"]["auto-redirect"] = json!(false);
    }
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
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    Service,
}
pub struct TunBridge {
    owner: Owner,
    checked: Instant,
    cached: bool,
    stopped: bool,
    config: Value,
    dns_settings: DnsSettings,
    process_names: Vec<String>,
    #[cfg(any(target_os="macos",target_os="linux"))]
    start_request: Value,
    #[cfg(any(target_os="macos",target_os="linux"))]
    recovery: Option<String>,
}
impl TunBridge {
    pub fn start(
        router_port: u16,
        dns_port: u16,
        password: &str,
        directory: PathBuf,
        process_names: Vec<String>,
        dns_settings: DnsSettings,
    ) -> io::Result<Self> {
        if !crate::current().tun_supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "当前平台尚未提供可用的 TUN 适配器",
            ));
        }
        let mut config = configuration(router_port, dns_port, password)?;
        dns_settings.apply(&mut config);
        apply_processes(&mut config, &process_names)?;
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        {
            if broker::installed() {
                let status = broker::request(&json!({"action":"status"}))?;
                if status.get("dns_settings_version").and_then(Value::as_u64).unwrap_or(0)<dns_settings.version() {
                    return Err(io::Error::other("请先在 TUN 模式中更新服务，以支持 DNS 设置热更新"));
                }
                broker_payload(
                    json!({"action":"start","router_port":router_port,"dns_port":dns_port,"password":password,"process_names":process_names,"dns_settings":dns_settings}),
                )?;
                return Ok(Self {
                    owner: Owner::Service,
                    checked: Instant::now(),
                    cached: true,
                    stopped: false,
                    config,
                    dns_settings: dns_settings.clone(),
                    process_names,
                    #[cfg(any(target_os="macos",target_os="linux"))]
                    start_request: json!({"action":"start","router_port":router_port,"dns_port":dns_port,"password":password,"dns_settings":dns_settings}),
                    #[cfg(any(target_os="macos",target_os="linux"))]
                    recovery: None,
                });
            }
            if cfg!(any(target_os = "macos", target_os = "linux")) || !broker::is_elevated() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TUN 需要先安装管理员服务",
                ));
            }
        }
        let process = CoreProcess::start(
            &managed::core_path().ok_or_else(|| io::Error::other("缺少 TUN 兼容内核"))?,
            directory.join("tun"),
            config.clone(),
            managed::random_secret()?,
        )?;
        Ok(Self {
            owner: Owner::Local(process),
            checked: Instant::now(),
            cached: true,
            stopped: false,
            config,
            dns_settings: dns_settings.clone(),
            process_names,
            #[cfg(any(target_os="macos",target_os="linux"))]
            start_request: json!({"action":"start","router_port":router_port,"dns_port":dns_port,"password":password,"dns_settings":dns_settings}),
            #[cfg(any(target_os="macos",target_os="linux"))]
            recovery: None,
        })
    }
    pub fn update_dns(&mut self, settings: DnsSettings) -> io::Result<()> {
        let settings = settings.validated()?;
        if self.stopped || self.dns_settings == settings { return Ok(()); }
        let mut next = self.config.clone();
        settings.apply(&mut next);
        match &self.owner {
            Owner::Local(process) => crate::dns_settings::hot_apply(process,&self.config,&next)?,
            #[cfg(any(windows, target_os="macos", target_os="linux"))]
            Owner::Service => {
                let response = send_dns_settings(&settings)
                    .map_err(|error|io::Error::other(format!("DNS 热更新失败，请在 TUN 模式中确认服务已更新：{error}")))?;
                if settings.version()>=2 && response["dns_settings_sha256"].as_str()!=Some(crate::dns_artifact::settings_digest(&settings)?.as_str()){return Err(io::Error::other("TUN 服务未确认相同的规则资源摘要，请更新服务后重试"));}
                if response.get("enabled").and_then(Value::as_bool)!=Some(true) {
                    return Err(io::Error::other("TUN 服务当前未运行，DNS 热更新未完成；请先恢复 TUN 服务"));
                }
            }
        }
        self.config = next;
        self.dns_settings = settings.clone();
        #[cfg(any(target_os="macos",target_os="linux"))]
        { self.start_request["dns_settings"] = json!(settings); }
        Ok(())
    }
    pub fn update_processes(&mut self, names: Vec<String>) -> io::Result<()> {
        if self.stopped || self.process_names == names {
            return Ok(());
        }
        let mut next = self.config.clone();
        apply_processes(&mut next, &names)?;
        match &mut self.owner {
            Owner::Local(process) => process.configure(next.clone())?,
            #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
            Owner::Service => {
                broker::request(&json!({"action":"process_rules","process_names":names}))?;
            }
        }
        self.config = next;
        self.process_names = names;
        Ok(())
    }
    /// Fixed operation only: never expose an arbitrary privileged controller request.
    pub fn flush_fake_ip(&self)->io::Result<()>{match &self.owner{
        Owner::Local(process)=>process.request("POST","/cache/fakeip/flush",None).map(|_|()),
        #[cfg(any(windows,target_os="macos",target_os="linux"))]
        Owner::Service=>broker::request(&json!({"action":"flush_fakeip"})).map(|_|()).map_err(|e|io::Error::other(format!("Fake-IP 清理失败，请在 TUN 模式更新旧服务：{e}")))}}
    pub fn flush_dns(&self) -> io::Result<()> {
        match &self.owner {
            Owner::Local(process) => process
                .request("POST", "/cache/dns/flush", None)
                .map(|_| ()),
            #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
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
            #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
            Owner::Service => {
                let response=broker::request(&json!({"action":"status"}));
                #[cfg(any(target_os="macos",target_os="linux"))]
                {self.recovery=match &response {
                    Ok(value)=>value.get("recovering").and_then(Value::as_str).map(str::to_owned),
                    Err(error)=>Some(error.to_string()),
                };}
                let enabled=response.ok().and_then(|v|v.get("enabled").and_then(Value::as_bool)).unwrap_or(false);
                #[cfg(any(target_os="macos",target_os="linux"))]
                if !enabled && broker::installed() {
                    let mut request=self.start_request.clone();
                    request["process_names"]=json!(self.process_names);
                    return {
                        self.recovery=broker_payload(request).err().map(|e|e.to_string());
                        self.cached=self.recovery.is_none();
                        self.checked=Instant::now();
                        self.cached
                    };
                }
                enabled
            },
        };
        self.checked = Instant::now();
        self.cached
    }
    pub fn recovery(&self)->Option<&str> {
        #[cfg(any(target_os="macos",target_os="linux"))]
        {self.recovery.as_deref()}
        #[cfg(not(any(target_os="macos",target_os="linux")))]
        {None}
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
            #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
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
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if !self.stopped && matches!(self.owner, Owner::Service) {
            let _ = broker::request(&json!({"action":"stop"}));
        }
    }
}
