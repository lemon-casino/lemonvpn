//! Persistent user DNS preferences, applied synchronously to an active TUN core.
use crate::{config, platform::dns_settings::DnsSettings};
use serde::Deserialize;
use serde_json::json;
use std::{fs, io, sync::Mutex};

static SETTINGS: Mutex<Option<DnsSettings>> = Mutex::new(None);
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
    let mut slot = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    let old = read(&mut slot).map_err(|e| (500, "dns_settings_read_failed", e.to_string()))?;
    if update.revision != revision(&old) {
        return Err((409, "conflict", "DNS 设置已变更，请重新加载后保存".into()));
    }
    if next != old {
        crate::compat::apply_dns_settings(&next)
            .map_err(|e| (503, "dns_hot_apply_failed", e.to_string()))?;
        if let Err(error) = crate::storage::write_atomic(
            &config::data_dir().join("dns-settings.json"),
            &serde_json::to_vec_pretty(&next).unwrap(),
        ) {
            let rollback = crate::compat::apply_dns_settings(&old);
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
