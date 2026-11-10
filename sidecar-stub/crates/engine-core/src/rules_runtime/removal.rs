use super::*;
fn mentions(condition: &str, id: &str) -> bool {
    crate::geodata::clear_error();
    let referenced = crate::config::parse_condition(condition)
        .is_some_and(|condition| crate::config::refers_to(&condition, id));
    let _ = crate::geodata::take_error();
    referenced
}
pub fn references(kind: &str, id: &str) -> Value {
    let snapshot = current();
    let mut refs = Vec::new();
    if kind == "provider" {
        refs.extend(
            snapshot
                .document
                .bindings
                .iter()
                .filter(|p| mentions(&p.condition, id))
                .map(|p| json!({"scope":"routing","id":p.id,"name":p.name})),
        );
        refs.extend(
            snapshot
                .document
                .policies
                .iter()
                .filter(|p| mentions(&p.condition, id))
                .map(|p| json!({"scope":"dns/fakeip","id":p.id,"name":p.name})),
        );
    } else if kind == "resolver" {
        refs.extend(
            snapshot
                .document
                .pools
                .iter()
                .filter(|p| p.members.iter().any(|v| v == id))
                .map(|p| json!({"scope":"pool","id":p.id,"name":p.name})),
        );
    } else if kind == "pool" {
        refs.extend(
            snapshot
                .document
                .policies
                .iter()
                .filter(|p| p.pool == id)
                .map(|p| json!({"scope":"dns","id":p.id,"name":p.name})),
        );
    }
    refs.extend(crate::config::resource_references(kind, id));
    json!({"references":refs})
}
pub fn remove(body: &str) -> Result<Value, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        revision: String,
        kind: String,
        id: String,
        replacement: Option<String>,
        remove_references: bool,
    }
    let req: Request = serde_json::from_str(body).map_err(|e| e.to_string())?;
    if !matches!(req.kind.as_str(), "provider" | "resolver" | "pool")
        || req.replacement.as_ref() == Some(&req.id)
    {
        return Err("删除类型或替换资源无效".into());
    }
    let _serial = APPLY.lock().unwrap_or_else(|p| p.into_inner());
    let snapshot = current();
    if snapshot.revision != req.revision {
        return Err("资源已更新，请重新加载".into());
    }
    let exists = |id: &str| match req.kind.as_str() {
        "provider" => snapshot.document.providers.iter().any(|p| p.id == id),
        "resolver" => snapshot.document.resolvers.iter().any(|p| p.id == id),
        _ => snapshot.document.pools.iter().any(|p| p.id == id),
    };
    if !exists(&req.id) || req.replacement.as_deref().is_some_and(|id| !exists(id)) {
        return Err("删除或替换资源不存在".into());
    }
    if req.replacement.is_none()
        && !req.remove_references
        && references(&req.kind, &req.id)["references"]
            .as_array()
            .is_some_and(|r| !r.is_empty())
    {
        return Err("资源仍被引用，请选择替换对象或明确移除关联规则".into());
    }
    let mut doc = snapshot.document.clone();
    let mut removed_pools = Vec::new();
    if req.kind == "provider" {
        doc.providers.retain(|p| p.id != req.id);
        for condition in doc
            .bindings
            .iter_mut()
            .map(|p| &mut p.condition)
            .chain(doc.policies.iter_mut().map(|p| &mut p.condition))
        {
            if mentions(condition, &req.id) {
                if let Some(new) = &req.replacement {
                    *condition = crate::config::rewrite_set_condition(condition, &req.id, new)?;
                } else {
                    condition.clear();
                }
            }
        }
        doc.bindings.retain(|p| !p.condition.is_empty());
        doc.policies.retain(|p| !p.condition.is_empty());
    } else if req.kind == "resolver" {
        doc.resolvers.retain(|p| p.id != req.id);
        for pool in &mut doc.pools {
            pool.members = pool
                .members
                .iter()
                .filter_map(|v| {
                    if v == &req.id {
                        req.replacement.clone()
                    } else {
                        Some(v.clone())
                    }
                })
                .collect();
            let mut seen = HashSet::new();
            pool.members.retain(|v| seen.insert(v.clone()));
        }
        let empty = doc
            .pools
            .iter()
            .filter(|p| p.members.is_empty())
            .map(|p| p.id.clone())
            .collect::<HashSet<_>>();
        if !empty.is_empty() && !req.remove_references {
            return Err("移除后解析池为空，请替换上游或同时移除引用".into());
        }
        removed_pools.extend(empty.iter().cloned());
        doc.pools.retain(|p| !empty.contains(&p.id));
        doc.policies.retain(|p| !empty.contains(&p.pool));
    } else {
        doc.pools.retain(|p| p.id != req.id);
        for policy in &mut doc.policies {
            if policy.pool == req.id {
                policy.pool = req.replacement.clone().unwrap_or_default();
            }
        }
        doc.policies.retain(|p| !p.pool.is_empty());
    }
    let snapshot = Arc::new(compile(doc)?);
    let mut changes =
        crate::config::rewrite_resource_sources(&req.kind, &req.id, req.replacement.as_deref())?;
    for id in removed_pools {
        changes = crate::config::rewrite_resource_sources_from("pool", &id, None, &changes)?;
    }
    crate::config::apply_resources_with_sources(snapshot, &changes)?;
    Ok(status())
}
