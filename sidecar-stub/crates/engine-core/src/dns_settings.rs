//! Persistent user DNS preferences, applied synchronously to an active TUN core.
use crate::{config, platform::dns_settings::DnsSettings};
use serde::Deserialize;
use serde_json::json;
use std::{fs, io, sync::Mutex};

static SETTINGS: Mutex<Option<DnsSettings>> = Mutex::new(None);
fn project(condition: &crate::config::Condition) -> Result<Vec<String>, String> {
    use crate::config::Condition as C;
    match condition {
        C::DomainFull(v) => Ok(vec![format!("DOMAIN,{v}")]),
        C::DomainSuffix(v) => Ok(vec![format!("DOMAIN-SUFFIX,{v}")]),
        C::DomainKeyword(v) => Ok(vec![format!("DOMAIN-KEYWORD,{v}")]),
        C::DomainPattern(p) => Ok(vec![format!("DOMAIN-REGEX,{}", p.text())]),
        C::GeoSite(set) => set.projection(),
        C::RuleSet(set) if set.set.domain_only => Ok(set.set.projection.clone()),
        C::Any(parts) => {
            let mut lines = Vec::new();
            for c in parts {
                lines.extend(project(c)?);
            }
            Ok(lines)
        }
        _ => Err("此组合条件无法无损用于 Fake-IP；请选择纯域名集合或独立例外".into()),
    }
}
fn compose(
    mut base: DnsSettings,
    snapshot: &crate::rules_runtime::Snapshot,
) -> Result<DnsSettings, String> {
    base.address_rules.clear();
    base.domain_sets.clear();
    for (policy, condition) in &snapshot.policies {
        if policy.address_mode == "inherit" {
            continue;
        }
        let id = format!("dns-{}", &crate::sha256::hex(policy.id.as_bytes())[..32]);
        base.domain_sets
            .push(crate::platform::dns_settings::DomainSet {
                id: id.clone(),
                entries: project(condition)?,
            });
        base.address_rules
            .push(crate::platform::dns_settings::AddressRule {
                set_id: id,
                mode: policy.address_mode.clone(),
            });
    }
    base.validated().map_err(|e| e.to_string())
}
pub(crate) fn effective_for(
    snapshot: &crate::rules_runtime::Snapshot,
) -> Result<DnsSettings, String> {
    compose(current().map_err(|e| e.to_string())?, snapshot)
}
pub(crate) fn effective() -> Result<DnsSettings, String> {
    effective_for(&crate::rules_runtime::current())
}
fn read(slot: &mut Option<DnsSettings>) -> io::Result<DnsSettings> {
    if let Some(settings) = slot {
        return Ok(settings.clone());
    }
    let path = config::data_dir().join("dns-settings.json");
    let settings = match fs::read(&path) {
        Ok(bytes) if bytes.len() <= 65536 => serde_json::from_slice::<DnsSettings>(&bytes)
            .map_err(|e| io::Error::other(format!("DNS 设置文件错误：{e}")))?
            .validated()?,
        Ok(_) => return Err(io::Error::other("DNS 设置文件过大")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => DnsSettings::default(),
        Err(e) => return Err(e),
    };
    *slot = Some(settings.clone());
    Ok(settings)
}
pub(crate) fn current() -> io::Result<DnsSettings> {
    read(&mut SETTINGS.lock().unwrap_or_else(|p| p.into_inner()))
}
fn revision(settings: &DnsSettings) -> String {
    crate::sha256::hex(&serde_json::to_vec(settings).expect("DNS settings serialize"))
}
pub(crate) fn status_json() -> io::Result<String> {
    let settings = current()?;
    Ok(json!({"settings":settings,"revision":revision(&settings),"tun_enabled":crate::compat::tun_active()}).to_string())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    revision: String,
    settings: DnsSettings,
}
pub(crate) fn update(body: &str) -> Result<String, (u16, &'static str, String)> {
    let invalid = |e: String| (422, "invalid_dns_settings", e);
    if body.len() > 65536 {
        return Err((413, "request_too_large", "DNS 设置过大".into()));
    }
    let update: Update = serde_json::from_str(body).map_err(|e| invalid(e.to_string()))?;
    let next = update
        .settings
        .validated()
        .map_err(|e| invalid(e.to_string()))?;
    let _serial = crate::rules_runtime::APPLY
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut slot = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    let old = read(&mut slot).map_err(|e| (500, "dns_settings_read_failed", e.to_string()))?;
    if update.revision != revision(&old) {
        return Err((409, "conflict", "DNS 设置已变更，请重新加载后保存".into()));
    }
    if next != old {
        crate::compat::apply_dns_settings(
            &compose(next.clone(), &crate::rules_runtime::current())
                .map_err(|e| (422, "invalid_fakeip_policy", e))?,
        )
        .map_err(|e| (503, "dns_hot_apply_failed", e.to_string()))?;
        if let Err(error) = crate::storage::write_atomic(
            &config::data_dir().join("dns-settings.json"),
            &serde_json::to_vec_pretty(&next).unwrap(),
        ) {
            let rollback = compose(old.clone(), &crate::rules_runtime::current())
                .map_err(io::Error::other)
                .and_then(|s| crate::compat::apply_dns_settings(&s));
            return Err((
                500,
                "dns_settings_write_failed",
                match rollback {
                    Ok(_) => format!("DNS 设置保存失败，已恢复原配置：{error}"),
                    Err(e) => format!("DNS 设置保存失败：{error}；运行配置恢复失败：{e}"),
                },
            ));
        }
        *slot = Some(next.clone());
        crate::dns::flush();
        crate::events::emit(
            "runtime.updated",
            json!({"reason":"dns_settings","revision":revision(&next)}).to_string(),
        );
    }
    drop(slot);
    status_json().map_err(|e| (500, "dns_settings_read_failed", e.to_string()))
}
