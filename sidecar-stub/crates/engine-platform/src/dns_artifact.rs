//! Authenticated brokers call this only after checking their ordinary owner.
//! Bounded data chunks, no paths, URLs, commands or arbitrary kernel settings.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::Mutex,
    time::{Duration, Instant},
};
struct Transfer {
    id: String,
    size: usize,
    bytes: Vec<u8>,
    at: Instant,
    complete: bool,
}
static TRANSFER: Mutex<Option<Transfer>> = Mutex::new(None);
fn error() -> io::Error {
    io::Error::other("DNS 域名产物传输无效、超时或摘要不匹配")
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn handle(value: &Value) -> Option<io::Result<Value>> {
    let action = value.get("action")?.as_str()?;
    if !action.starts_with("dns_artifact_") {
        return None;
    }
    Some((|| {
        let id = value["id"]
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(error)?;
        let mut state = TRANSFER.lock().unwrap_or_else(|p| p.into_inner());
        match action {
            "dns_artifact_begin" => {
                let size = value["size"]
                    .as_u64()
                    .filter(|v| *v > 0 && *v <= 32 * 1024 * 1024)
                    .ok_or_else(error)? as usize;
                *state = Some(Transfer {
                    id: id.into(),
                    size,
                    bytes: Vec::new(),
                    at: Instant::now(),
                    complete: false,
                });
            }
            "dns_artifact_part" => {
                let transfer = state
                    .as_mut()
                    .filter(|t| {
                        t.id == id && t.at.elapsed() < Duration::from_secs(120) && !t.complete
                    })
                    .ok_or_else(error)?;
                if value["offset"].as_u64() != Some(transfer.bytes.len() as u64) {
                    return Err(error());
                }
                let text = value["hex"]
                    .as_str()
                    .filter(|s| s.len() <= 49152 && s.len() % 2 == 0)
                    .ok_or_else(error)?;
                if transfer.bytes.len() + text.len() / 2 > transfer.size {
                    return Err(error());
                }
                for pair in text.as_bytes().chunks_exact(2) {
                    let s = std::str::from_utf8(pair).map_err(|_| error())?;
                    transfer
                        .bytes
                        .push(u8::from_str_radix(s, 16).map_err(|_| error())?);
                }
                transfer.at = Instant::now();
            }
            "dns_artifact_commit" => {
                let transfer = state.as_mut().filter(|t| t.id == id).ok_or_else(error)?;
                if transfer.bytes.len() != transfer.size || digest(&transfer.bytes) != id {
                    return Err(error());
                }
                let _: crate::dns_settings::DnsSettings =
                    serde_json::from_slice::<crate::dns_settings::DnsSettings>(&transfer.bytes)
                        .map_err(|_| error())?
                        .validated()?;
                transfer.complete = true;
            }
            _ => return Err(error()),
        }
        Ok(json!({"ok":true,"artifact":id}))
    })())
}
pub fn read(id: &str) -> io::Result<crate::dns_settings::DnsSettings> {
    let state = TRANSFER.lock().unwrap_or_else(|p| p.into_inner());
    let transfer = state
        .as_ref()
        .filter(|t| t.complete && t.id == id && t.at.elapsed() < Duration::from_secs(120))
        .ok_or_else(error)?;
    serde_json::from_slice(&transfer.bytes).map_err(|_| error())
}

pub fn settings_digest(settings: &crate::dns_settings::DnsSettings) -> io::Result<String> {
    Ok(digest(&serde_json::to_vec(settings)?))
}
