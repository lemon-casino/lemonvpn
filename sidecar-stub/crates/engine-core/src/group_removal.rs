//! One accepted generation for source-wide retargeting and group deletion.
use super::*;
use std::collections::HashMap;

fn conflict(message: &str) -> SourceWriteError {
    write_error(409, "state_conflict", message)
}

pub(crate) fn remove_group(body: &str) -> Result<String, SourceWriteError> {
    let _serial=crate::rules_runtime::APPLY.lock().unwrap_or_else(|p|p.into_inner());
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| write_error(400, "invalid_request", "请求不是 JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| write_error(400, "invalid_request", "请求必须是对象"))?;
    if object
        .keys()
        .any(|key| !["generation_id", "group_id", "replacement", "sources"].contains(&key.as_str()))
    {
        return Err(write_error(400, "invalid_request", "删除请求包含未知字段"));
    }
    let generation = object
        .get("generation_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| write_error(400, "invalid_request", "缺少配置代次"))?;
    let name = object
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|v| v.strip_prefix("group-"))
        .filter(|v| !v.is_empty())
        .ok_or_else(|| write_error(400, "invalid_request", "无效的出站 ID"))?;
    let replacement = match object.get("replacement") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|v| !v.is_empty() && *v != name)
                .ok_or_else(|| write_error(400, "invalid_request", "替换出站无效"))?,
        ),
    };
    refresh();
    let resources=crate::rules_runtime::retarget_outbound(name,replacement).map_err(|e|write_error(422,"resource_reference",e))?;
    let config = current();
    if config.generation != generation {
        return Err(conflict("配置、订阅或出站已变更，请刷新删除弹框后重试"));
    }
    if !config.groups.iter().any(|group| group.name == name) {
        return Err(conflict("待删除出站已不存在"));
    }
    if replacement.is_some_and(|target| {
        !matches!(target, "direct" | "block")
            && !config.groups.iter().any(|g| g.name == target)
            && !config.nodes.iter().any(|n| n.name == target)
    }) {
        return Err(conflict("替换出站已不存在，请重新选择"));
    }
    if replacement.is_some_and(|target| {
        config.groups.iter().any(|group| group.name == target)
            && config.nodes.iter().any(|node| node.name == target)
    }) {
        return Err(write_error(
            422,
            "unsupported_value",
            "替换名称同时属于节点和策略组，请选择无歧义的出站",
        ));
    }
    let mut originals = vec![(SOURCE_PATH.to_owned(), config.content.clone())];
    originals.extend(config.include_contents.iter().cloned());
    let requested = object
        .get("sources")
        .and_then(|v| v.as_array())
        .filter(|v| v.len() == originals.len())
        .ok_or_else(|| conflict("删除必须携带全部配置源的完整快照"))?;
    let mut submitted = HashMap::new();
    for item in requested {
        let item = item
            .as_object()
            .ok_or_else(|| write_error(400, "invalid_request", "配置源无效"))?;
        if item
            .keys()
            .any(|key| !["source_id", "content_sha256", "content"].contains(&key.as_str()))
        {
            return Err(write_error(400, "invalid_request", "配置源包含未知字段"));
        }
        let id = item
            .get("source_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| write_error(400, "invalid_request", "缺少配置源 ID"))?;
        let digest = item
            .get("content_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| write_error(400, "invalid_request", "缺少原配置摘要"))?;
        let content = item
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| write_error(400, "invalid_request", "缺少完整配置内容"))?;
        if content.len() > MAX_BYTES {
            return Err(write_error(
                413,
                "request_too_large",
                "替换后配置超过 max_bytes",
            ));
        }
        if submitted.insert(id, (digest, content)).is_some() {
            return Err(write_error(400, "invalid_request", "配置源不能重复"));
        }
    }
    let mut sources = Vec::new();
    for (index, (path, old)) in originals.iter().enumerate() {
        let id = if index == 0 {
            SOURCE_ID.to_owned()
        } else {
            source_id_for_path(path)
        };
        let (digest, text) = submitted
            .remove(id.as_str())
            .ok_or_else(|| conflict("配置源集合已变更"))?;
        if digest != sha256::hex(old.as_bytes())
            || fs::read_to_string(data_dir().join(path)).ok().as_deref() != Some(old)
        {
            return Err(conflict("配置文件已被其他写入修改，请刷新后重试"));
        }
        sources.push((path.clone(), text.to_owned()));
    }
    if !submitted.is_empty() {
        return Err(conflict("请求包含未知配置源"));
    }
    let declarations = |list: &[(String, String)]| {
        list.iter()
            .flat_map(|(_, text)| parse(text).groups)
            .filter(|g| g.name == name)
            .count()
    };
    if declarations(&originals) != 1 || declarations(&sources) != 0 {
        return Err(conflict("删除的组声明不唯一或仍然存在"));
    }
    let overlay = sources.iter().skip(1).cloned().collect::<HashMap<_, _>>();
    let inline = parse(&sources[0].1)
        .nodes
        .into_iter()
        .map(|node| node.name)
        .collect::<Vec<_>>();
    let next = crate::rules_runtime::with_candidate(resources.clone(),||build_with_sources(
        sources[0].1.clone(), None, &crate::providers::nodes(&inline), &overlay,
    ));
    let errors = next
        .diagnostics
        .iter()
        .filter(|row| row.level == "error")
        .map(|row| row.message.clone())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Err(write_error(422, "invalid_config", errors.join("；")));
    }

    // Verify the candidate really is this operation, rather than silently
    // accepting unrelated changes or losing rule order/conditions in a client edit.
    let mapped = |old: &str| -> Result<String, SourceWriteError> {
        if old == name {
            replacement
                .map(str::to_owned)
                .ok_or_else(|| write_error(422, "unsupported_value", "仍有引用，请选择替换出站"))
        } else {
            Ok(old.to_owned())
        }
    };
    if config.nodes != next.nodes
        || config.upstreams != next.upstreams
        || config
            .include_contents
            .iter()
            .map(|(p, _)| p)
            .collect::<Vec<_>>()
            != next
                .include_contents
                .iter()
                .map(|(p, _)| p)
                .collect::<Vec<_>>()
    {
        return Err(conflict(
            "节点、订阅、DNS 上游或配置源集合已变更，请刷新后重试",
        ));
    }
    if config.rules.len() != next.rules.len() {
        return Err(conflict("替换不能增删或重排路由规则"));
    }
    for (old, new) in config
        .rules
        .iter()
        .chain(std::iter::once(&config.fallback))
        .zip(next.rules.iter().chain(std::iter::once(&next.fallback)))
    {
        if old.condition != new.condition || mapped(&old.outbound)? != new.outbound {
            return Err(conflict("路由引用替换校验失败，未保存"));
        }
    }
    let dns_equal = |left: &[DnsRule], right: &[DnsRule]| {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(a, b)| a.condition == b.condition && a.upstream == b.upstream)
    };
    if !dns_equal(&config.dns_rules, &next.dns_rules)
        || !dns_equal(&config.dns_response_rules, &next.dns_response_rules)
        || config.dns_request_fallback != next.dns_request_fallback
        || config.dns_response_fallback != next.dns_response_fallback
    {
        return Err(conflict("替换不能修改 DNS 规则"));
    }
    if next.groups.len() + 1 != config.groups.len() {
        return Err(conflict("替换不能修改其他出站的声明"));
    }
    for old in config.groups.iter().filter(|group| group.name != name) {
        let new = next
            .groups
            .iter()
            .find(|g| g.name == old.name)
            .ok_or_else(|| conflict("其他出站被意外删除"))?;
        let map_option = |value: &Option<String>| value.as_deref().map(&mapped).transpose();
        if old.policy != new.policy
            || old.default != new.default
            || map_option(&old.final_outbound)? != new.final_outbound
            || map_option(&old.dialer)? != new.dialer
            || map_option(&old.landing)? != new.landing
        {
            return Err(conflict("其他出站的策略或引用发生了意外变化"));
        }
    }
    // Commit every affected source before publishing a single runtime snapshot.
    let changed=sources.iter().zip(&originals).filter(|(a,b)|a.1!=b.1).map(|(a,_)|a.clone()).collect::<HashMap<_,_>>();
    let expected=config.generation.clone();let count=changed.len();drop(config);
    let generation=apply_resources_checked(resources,&changed,Some(&expected)).map_err(|e|write_error(422,"resource_apply_failed",e))?;
    Ok(serde_json::json!({"generation_id":generation,"deleted":1,"replacement":replacement,"changed_sources":count}).to_string())
}
