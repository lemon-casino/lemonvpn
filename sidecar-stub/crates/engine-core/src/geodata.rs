//! V2Ray GeoIP/GeoSite protobuf assets. Compile only referenced categories.
use regex::RegexSet;
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    net::IpAddr,
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Clone)]
struct Asset {
    bytes: Arc<Vec<u8>>,
    entries: HashMap<String, Range<usize>>,
    digest: String,
}
struct Cached {
    path: PathBuf,
    modified: Option<SystemTime>,
    size: u64,
    asset: Asset,
}
static ASSETS: OnceLock<Mutex<HashMap<&'static str, Cached>>> = OnceLock::new();
static DOMAINS: OnceLock<Mutex<HashMap<String, Arc<Domains>>>> = OnceLock::new();
static IPS: OnceLock<Mutex<HashMap<String, Arc<Ips>>>> = OnceLock::new();
thread_local! { static ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) }; }
pub(crate) fn clear_error() {
    ERROR.with(|error| *error.borrow_mut() = None);
}
pub(crate) fn take_error() -> Option<String> {
    ERROR.with(|error| error.borrow_mut().take())
}
fn noted<T>(result: Result<T, String>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(message) => {
            ERROR.with(|error| *error.borrow_mut() = Some(message));
            None
        }
    }
}

#[derive(Clone)]
pub struct DomainRef {
    identity: String,
    negate: bool,
    set: Arc<Domains>,
}
#[derive(Clone)]
pub struct IpRef {
    identity: String,
    negate: bool,
    set: Arc<Ips>,
}
macro_rules! identity {
    ($name:ty) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple("GeoData").field(&self.identity).finish()
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.identity == other.identity && self.negate == other.negate
            }
        }
        impl Eq for $name {}
    };
}
identity!(DomainRef);
identity!(IpRef);
struct Domains {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keywords: Vec<String>,
    regex: RegexSet,
}
#[derive(Default)]
struct Ips {
    v4: HashMap<u8, HashSet<u32>>,
    v6: HashMap<u8, HashSet<u128>>,
    inverse: bool,
}
impl DomainRef {
    pub(crate) fn load(code: &str) -> Option<Self> {
        noted((|| {
            let (negate, code) = selector(code)?;
            let asset = asset("geosite")?;
            let identity = format!("{}:{code}", asset.digest);
            let mut cache = DOMAINS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let set = if let Some(set) = cache.get(&identity) {
                set.clone()
            } else {
                let (name, attributes) = code
                    .split_once('@')
                    .map_or((code.as_str(), Vec::new()), |(name, rest)| {
                        (name, rest.split('@').collect())
                    });
                let range = asset
                    .entries
                    .get(name)
                    .ok_or_else(|| format!("GeoSite 分类不存在：{name}"))?;
                let mut exact = HashSet::new();
                let mut suffix = HashSet::new();
                let mut keywords = Vec::new();
                let mut expressions = Vec::new();
                for field in fields(&asset.bytes[range.clone()])? {
                    if let Field::Bytes(2, domain) = field {
                        let mut kind = 0;
                        let mut value = None;
                        let mut tags = HashSet::new();
                        for item in fields(domain)? {
                            match item {
                                Field::Number(1, v) => kind = v,
                                Field::Bytes(2, v) => value = Some(string(v)?.to_owned()),
                                Field::Bytes(3, v) => {
                                    for attr in fields(v)? {
                                        if let Field::Bytes(1, key) = attr {
                                            tags.insert(string(key)?.to_ascii_lowercase());
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !attributes.iter().all(|attr| {
                            attr.strip_prefix('!')
                                .map_or_else(|| tags.contains(*attr), |key| !tags.contains(key))
                        }) {
                            continue;
                        }
                        let value = value.ok_or("GeoSite 域名缺少 value")?;
                        match kind {
                            0 => keywords.push(value.to_ascii_lowercase()),
                            1 => expressions.push(value),
                            2 => {
                                suffix.insert(value.trim_end_matches('.').to_ascii_lowercase());
                            }
                            3 => {
                                exact.insert(value.trim_end_matches('.').to_ascii_lowercase());
                            }
                            _ => return Err("GeoSite 域名类型无效".to_owned()),
                        }
                    }
                }
                let regex = regex::RegexSetBuilder::new(expressions)
                    .case_insensitive(true)
                    .size_limit(32 * 1024 * 1024)
                    .build()
                    .map_err(|error| format!("GeoSite 正则无效：{error}"))?;
                let set = Arc::new(Domains {
                    exact,
                    suffix,
                    keywords,
                    regex,
                });
                if cache.len() >= 128 {
                    cache.clear();
                }
                cache.insert(identity.clone(), set.clone());
                set
            };
            Ok(Self {
                identity,
                negate,
                set,
            })
        })())
    }
    pub(crate) fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut suffix = host.as_str();
        let mut matched = self.set.exact.contains(&host);
        loop {
            if self.set.suffix.contains(suffix) {
                matched = true;
                break;
            }
            if let Some((_, rest)) = suffix.split_once('.') {
                suffix = rest;
            } else {
                break;
            }
        }
        matched |= self.set.keywords.iter().any(|key| host.contains(key))
            || self.set.regex.is_match(&host);
        matched != self.negate
    }
}
impl IpRef {
    pub(crate) fn load(code: &str) -> Option<Self> {
        noted((|| {
            let (negate, code) = selector(code)?;
            if code == "private" {
                return Ok(Self {
                    identity: "builtin:private".to_owned(),
                    negate,
                    set: Arc::new(private()),
                });
            }
            let asset = asset("geoip")?;
            let identity = format!("{}:{code}", asset.digest);
            let mut cache = IPS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let set = if let Some(set) = cache.get(&identity) {
                set.clone()
            } else {
                let range = asset
                    .entries
                    .get(&code)
                    .ok_or_else(|| format!("GeoIP 分类不存在：{code}"))?;
                let mut set = Ips::default();
                for field in fields(&asset.bytes[range.clone()])? {
                    match field {
                        Field::Number(3, value) => set.inverse = value != 0,
                        Field::Bytes(2, cidr) => {
                            let mut ip = None;
                            let mut prefix = 0u8;
                            for field in fields(cidr)? {
                                match field {
                                    Field::Bytes(1, bytes) => ip = Some(bytes),
                                    Field::Number(2, value) => {
                                        prefix =
                                            u8::try_from(value).map_err(|_| "GeoIP 前缀无效")?
                                    }
                                    _ => {}
                                }
                            }
                            let bytes = ip.ok_or("GeoIP CIDR 缺少 IP")?;
                            let address = match bytes.len() {
                                4 => IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap()),
                                16 => IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap()),
                                _ => return Err("GeoIP IP 长度无效".to_owned()),
                            };
                            set.insert(address, prefix)?;
                        }
                        _ => {}
                    }
                }
                let set = Arc::new(set);
                if cache.len() >= 128 {
                    cache.clear();
                }
                cache.insert(identity.clone(), set.clone());
                set
            };
            Ok(Self {
                identity,
                negate,
                set,
            })
        })())
    }
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        self.set.matches(ip) != self.negate
    }
}
fn selector(code: &str) -> Result<(bool, String), String> {
    let code = code.trim().to_ascii_lowercase();
    let (negate, code) = code
        .strip_prefix('!')
        .map_or((false, code.as_str()), |code| (true, code));
    if code.is_empty()
        || code.len() > 256
        || code.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("Geo 数据分类名称无效".to_owned());
    }
    Ok((negate, code.to_owned()))
}
impl Ips {
    fn insert(&mut self, ip: IpAddr, prefix: u8) -> Result<(), String> {
        match ip {
            IpAddr::V4(ip) if prefix <= 32 => {
                self.v4
                    .entry(prefix)
                    .or_default()
                    .insert(u32::from(ip) & mask4(prefix));
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                self.v6
                    .entry(prefix)
                    .or_default()
                    .insert(u128::from(ip) & mask6(prefix));
            }
            _ => return Err("GeoIP CIDR 前缀超出范围".to_owned()),
        }
        Ok(())
    }
    fn matches(&self, ip: IpAddr) -> bool {
        let matched = match ip {
            IpAddr::V4(ip) => self
                .v4
                .iter()
                .any(|(prefix, set)| set.contains(&(u32::from(ip) & mask4(*prefix)))),
            IpAddr::V6(ip) => self
                .v6
                .iter()
                .any(|(prefix, set)| set.contains(&(u128::from(ip) & mask6(*prefix)))),
        };
        matched != self.inverse
    }
}
fn mask4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn mask6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}
fn private() -> Ips {
    let mut ips = Ips::default();
    for cidr in [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ] {
        let (ip, prefix) = cidr.split_once('/').unwrap();
        let _ = ips.insert(ip.parse().unwrap(), prefix.parse().unwrap());
    }
    ips
}

pub(crate) fn asset_path(kind: &str) -> Result<PathBuf, String> {
    let file = format!("{kind}.dat");
    let mut paths = vec![crate::config::data_dir().join(&file)];
    if let Some(path) = crate::platform::managed::resource_path(&file) {
        paths.push(path);
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        paths.extend([
            dir.join(&file),
            dir.join("resources").join(&file),
            dir.join("../Resources").join(&file),
        ]);
    }
    paths
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| format!("missing-{kind}-file: {file}，请先更新地理数据"))
}
fn asset(kind: &'static str) -> Result<Asset, String> {
    let path = asset_path(kind)?;
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_BYTES {
        return Err("Geo 数据超过 64 MiB".to_owned());
    }
    let mut cache = ASSETS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = cache.get(kind) {
        if cached.path == path
            && cached.size == meta.len()
            && cached.modified == meta.modified().ok()
        {
            return Ok(cached.asset.clone());
        }
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let asset = index(bytes)?;
    cache.insert(
        kind,
        Cached {
            path,
            modified: meta.modified().ok(),
            size: meta.len(),
            asset: asset.clone(),
        },
    );
    Ok(asset)
}
pub(crate) fn validate_asset(kind: &str, bytes: &[u8]) -> Result<(), String> {
    let asset = index(bytes.to_vec())?;
    for range in asset.entries.values() {
        for field in fields(&asset.bytes[range.clone()])? {
            if let Field::Bytes(2, item) = field {
                let nested = fields(item)?;
                if kind == "geoip" {
                    let ip = nested
                        .iter()
                        .find_map(|field| {
                            if let Field::Bytes(1, ip) = field {
                                Some(*ip)
                            } else {
                                None
                            }
                        })
                        .ok_or("GeoIP 缺少 CIDR IP")?;
                    let prefix = nested
                        .iter()
                        .find_map(|field| {
                            if let Field::Number(2, prefix) = field {
                                Some(*prefix)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if ![4, 16].contains(&ip.len()) || prefix > ip.len() as u64 * 8 {
                        return Err("GeoIP CIDR 无效".to_owned());
                    }
                } else {
                    let value = nested
                        .iter()
                        .find_map(|field| {
                            if let Field::Bytes(2, value) = field {
                                Some(*value)
                            } else {
                                None
                            }
                        })
                        .ok_or("GeoSite 缺少域名")?;
                    if string(value)?.is_empty() {
                        return Err("GeoSite 域名为空".to_owned());
                    }
                    let domain_type = nested
                        .iter()
                        .find_map(|field| {
                            if let Field::Number(1, value) = field {
                                Some(*value)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if domain_type > 3 {
                        return Err("GeoSite 域名类型无效".to_owned());
                    }
                }
            }
        }
    }
    Ok(())
}

fn index(bytes: Vec<u8>) -> Result<Asset, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
        return Err("Geo 数据大小无效".to_owned());
    }
    let mut entries = HashMap::new();
    for field in fields(&bytes)? {
        if let Field::Bytes(1, message) = field {
            let code = fields(message)?
                .into_iter()
                .find_map(|field| {
                    if let Field::Bytes(1, code) = field {
                        Some(code)
                    } else {
                        None
                    }
                })
                .ok_or("Geo 数据缺少分类名称")?;
            let code = string(code)?.to_ascii_lowercase();
            let start = message.as_ptr() as usize - bytes.as_ptr() as usize;
            if entries.insert(code, start..start + message.len()).is_some() {
                return Err("Geo 数据存在重复分类".to_owned());
            }
        }
    }
    if entries.is_empty() {
        return Err("Geo 数据没有可用分类".to_owned());
    }
    Ok(Asset {
        digest: crate::sha256::hex(&bytes),
        bytes: Arc::new(bytes),
        entries,
    })
}
fn string(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "Geo 数据包含无效 UTF-8".to_owned())
}
enum Field<'a> {
    Number(u32, u64),
    Bytes(u32, &'a [u8]),
}
fn number(bytes: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*at).ok_or("Geo 数据截断")?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return Err("Geo 数据整数溢出".to_owned());
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err("Geo 数据整数无效".to_owned())
}
fn fields(bytes: &[u8]) -> Result<Vec<Field<'_>>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let key = number(bytes, &mut at)?;
        let tag = u32::try_from(key >> 3).map_err(|_| "Geo 数据字段无效")?;
        if tag == 0 {
            return Err("Geo 数据字段为零".to_owned());
        }
        match key & 7 {
            0 => out.push(Field::Number(tag, number(bytes, &mut at)?)),
            2 => {
                let len =
                    usize::try_from(number(bytes, &mut at)?).map_err(|_| "Geo 数据长度无效")?;
                let end = at
                    .checked_add(len)
                    .filter(|end| *end <= bytes.len())
                    .ok_or("Geo 数据截断")?;
                out.push(Field::Bytes(tag, &bytes[at..end]));
                at = end;
            }
            1 | 5 => {
                let len = if key & 7 == 1 { 8 } else { 4 };
                at = at
                    .checked_add(len)
                    .filter(|at| *at <= bytes.len())
                    .ok_or("Geo 数据截断")?;
            }
            _ => return Err("Geo 数据 wire type 无效".to_owned()),
        }
        if out.len() > 2_000_000 {
            return Err("Geo 数据字段数量超限".to_owned());
        }
    }
    Ok(out)
}
