use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Document {
    pub schema: u32,
    pub providers: Vec<Provider>,
    pub resolvers: Vec<Resolver>,
    pub pools: Vec<Pool>,
    pub policies: Vec<Policy>,
    pub bindings: Vec<Binding>,
    pub cache: CacheSettings,
    pub bootstrap: Vec<String>,
}
impl Default for Document {
    fn default() -> Self {
        Self {
            schema: 1,
            providers: vec![],
            resolvers: vec![],
            pools: vec![],
            policies: vec![],
            bindings: vec![],
            cache: CacheSettings::default(),
            bootstrap: vec![
                "udp://223.5.5.5:53".into(),
                "udp://[2400:3200::1]:53".into(),
            ],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub source: String,
    pub url: String,
    pub content: String,
    pub format: String,
    pub behavior: String,
    pub interval: u64,
    pub outbound: String,
    pub expected_sha256: String,
    pub accepted_sha256: String,
    pub updated_at: u64,
    pub etag: String,
    pub last_modified: String,
    pub headers: std::collections::BTreeMap<String, String>,
}
impl Default for Provider {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            source: "inline".into(),
            url: String::new(),
            content: String::new(),
            format: "auto".into(),
            behavior: "auto".into(),
            interval: 86400,
            outbound: "direct".into(),
            expected_sha256: String::new(),
            accepted_sha256: String::new(),
            updated_at: 0,
            etag: String::new(),
            last_modified: String::new(),
            headers: Default::default(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Resolver {
    pub id: String,
    pub name: String,
    pub url: String,
    pub outbound: String,
    pub bootstrap: Vec<String>,
    pub tls_name: String,
    pub timeout_ms: u64,
}
impl Default for Resolver {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            outbound: "direct".into(),
            bootstrap: vec![],
            tls_name: String::new(),
            timeout_ms: 3000,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Pool {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    pub strategy: String,
}
impl Default for Pool {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            members: vec![],
            strategy: "fallback".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: String,
    pub pool: String,
    pub address_mode: String,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            condition: String::new(),
            pool: String::new(),
            address_mode: "inherit".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Binding {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: String,
    pub outbound: String,
}
impl Default for Binding {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            condition: String::new(),
            outbound: "direct".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CacheSettings {
    pub capacity: usize,
    pub max_bytes: usize,
    pub negative: bool,
    pub stale_seconds: u64,
    pub prefetch: bool,
}
impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            capacity: 4096,
            max_bytes: 16 * 1024 * 1024,
            negative: true,
            stale_seconds: 0,
            prefetch: false,
        }
    }
}
