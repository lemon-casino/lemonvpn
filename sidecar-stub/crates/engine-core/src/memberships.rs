//! Node membership edits preserve subscription/region filters and commit all
//! affected sources together. Called as a child of config to share its lock.
use super::*;
use std::collections::{HashMap, HashSet};

fn conflict(message: &str) -> SourceWriteError {
    write_error(409, "state_conflict", message)
}

fn ids(value: Option<&serde_json::Value>) -> Result<HashSet<String>, SourceWriteError> {
    let values = value
        .and_then(|value| value.as_array())
        .filter(|values| values.len() <= 256)
        .ok_or_else(|| write_error(400, "invalid_request", "所属组必须是数组，最多 256 个"))?;
    let mut result = HashSet::new();
    for value in values {
        let name = value
            .as_str()
            .and_then(|value| value.strip_prefix("group-"))
            .filter(|name| !name.is_empty())
            .ok_or_else(|| write_error(400, "invalid_request", "无效的策略组 ID"))?;
        if !result.insert(name.to_owned()) {
            return Err(write_error(400, "invalid_request", "所属组不能重复"));
        }
    }
    Ok(result)
}

struct Requested {
    id: String,
    wanted: HashSet<String>,
    expected: HashSet<String>,
}
struct MembershipEdit {
    name: String,
    wanted: HashSet<String>,
    actual: HashSet<String>,
}
fn request_object(
    body: &str,
    fields: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, SourceWriteError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| write_error(400, "invalid_request", "请求不是 JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| write_error(400, "invalid_request", "请求必须是对象"))?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(write_error(422, "unsupported_value", "不支持的所属组字段"));
    }
    Ok(object.clone())
}
fn generation(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<&str, SourceWriteError> {
    object
        .get("generation_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| write_error(400, "invalid_request", "缺少配置代次"))
}
pub(crate) fn update_node_groups(id: &str, body: &str) -> Result<String, SourceWriteError> {
    let object = request_object(body, &["generation_id", "group_ids", "expected_group_ids"])?;
    let wanted = ids(object.get("group_ids"))?;
    let request = Requested {
        id: id.to_owned(),
        wanted: wanted.clone(),
        expected: ids(object.get("expected_group_ids"))?,
    };
    let mut result = apply_updates(generation(&object)?, vec![request])?;
    result["node_id"] = serde_json::json!(id);
    result["group_ids"] = serde_json::json!(wanted
        .iter()
        .map(|name| format!("group-{name}"))
        .collect::<Vec<_>>());
    Ok(result.to_string())
}
pub(crate) fn update_nodes_groups(body: &str) -> Result<String, SourceWriteError> {
    let object = request_object(body, &["generation_id", "edits"])?;
    let edits = object
        .get("edits")
        .and_then(|value| value.as_array())
        .filter(|items| !items.is_empty() && items.len() <= 256)
        .ok_or_else(|| write_error(400, "invalid_request", "一次所属组操作需要 1..=256 个节点"))?;
    let mut requests = Vec::new();
    let mut seen = HashSet::new();
    for edit in edits {
        let edit = edit
            .as_object()
            .ok_or_else(|| write_error(400, "invalid_request", "节点修改必须是对象"))?;
        if edit
            .keys()
            .any(|key| !["node_id", "group_ids", "expected_group_ids"].contains(&key.as_str()))
        {
            return Err(write_error(
                422,
                "unsupported_value",
                "节点修改包含未知字段",
            ));
        }
        let id = edit
            .get("node_id")
            .and_then(|value| value.as_str())
            .filter(|id| id.starts_with("node-"))
            .ok_or_else(|| write_error(400, "invalid_request", "节点 ID 无效"))?;
        if !seen.insert(id) {
            return Err(write_error(
                400,
                "invalid_request",
                "批量修改不能包含重复节点",
            ));
        }
        requests.push(Requested {
            id: id.to_owned(),
            wanted: ids(edit.get("group_ids"))?,
            expected: ids(edit.get("expected_group_ids"))?,
        });
    }
    Ok(apply_updates(generation(&object)?, requests)?.to_string())
}
fn apply_updates(
    generation: &str,
    requests: Vec<Requested>,
) -> Result<serde_json::Value, SourceWriteError> {
    refresh();
    let mut config = current();
    if generation != config.generation {
        return Err(conflict("配置或订阅已更新，请刷新节点后重新选择所属组"));
    }
    let mut edits = Vec::new();
    for request in requests {
        let node = config
            .nodes
            .iter()
            .find(|node| format!("node-{}", node.name) == request.id)
            .ok_or_else(|| write_error(404, "resource_not_found", "所选节点已不存在"))?;
        let actual = config
            .groups
            .iter()
            .filter(|group| group.members.contains(&node.name))
            .map(|group| group.name.clone())
            .collect::<HashSet<_>>();
        if actual != request.expected {
            return Err(conflict("所选节点的所属组已变更，请刷新后重新选择"));
        }
        if request
            .wanted
            .iter()
            .any(|name| !config.groups.iter().any(|group| &group.name == name))
        {
            return Err(write_error(404, "resource_not_found", "目标策略组不存在"));
        }
        edits.push(MembershipEdit {
            name: node.name.clone(),
            wanted: request.wanted,
            actual,
        });
    }
    let changed_nodes = edits
        .iter()
        .filter(|edit| edit.wanted != edit.actual)
        .count();
    if changed_nodes == 0 {
        return Ok(
            serde_json::json!({"generation_id":config.generation,"changed":false,"changed_nodes":0,"total_nodes":edits.len()}),
        );
    }
    let edited_names = edits
        .iter()
        .map(|edit| edit.name.as_str())
        .collect::<HashSet<_>>();
    let mut sources = vec![(SOURCE_PATH.to_owned(), config.content.clone())];
    sources.extend(config.include_contents.iter().cloned());
    let mut owners = HashMap::new();
    for (index, (_, content)) in sources.iter().enumerate() {
        for group in parse(content).groups {
            if owners.insert(group.name.clone(), index).is_some() {
                return Err(conflict("策略组被重复声明，请先在配置页处理"));
            }
        }
    }
    // Refuse external unsaved changes rather than replacing them with an old snapshot.
    for (path, content) in &sources {
        if fs::read_to_string(data_dir().join(path)).ok().as_deref() != Some(content) {
            return Err(conflict("配置文件已被外部修改，请先重载后再编辑所属组"));
        }
    }
    let previous = sources.clone();
    let mut resolved = Vec::new();
    for group in &config.groups {
        let owner = *owners
            .get(&group.name)
            .ok_or_else(|| conflict("找不到策略组的完整配置源"))?;
        let raw = parse(&sources[owner].1)
            .groups
            .into_iter()
            .find(|raw| raw.name == group.name)
            .ok_or_else(|| conflict("策略组已变更"))?;
        let mut members = resolve_members(&raw.filters, &resolved, &config.nodes)?;
        let add = edits
            .iter()
            .filter(|edit| edit.wanted.contains(&group.name) && !members.contains(&edit.name))
            .map(|edit| edit.name.clone())
            .collect::<Vec<_>>();
        let remove = edits
            .iter()
            .filter(|edit| {
                !edit.wanted.contains(&group.name)
                    && (edit.actual.contains(&group.name) || members.contains(&edit.name))
            })
            .map(|edit| edit.name.clone())
            .collect::<Vec<_>>();
        if !add.is_empty() || !remove.is_empty() {
            sources[owner].1 = rewrite_memberships(&sources[owner].1, &raw, &add, &remove)?;
            if sources[owner].1.len() > MAX_BYTES {
                return Err(write_error(
                    413,
                    "request_too_large",
                    "所属组修改后配置超过 max_bytes",
                ));
            }
            let edited = parse(&sources[owner].1)
                .groups
                .into_iter()
                .find(|raw| raw.name == group.name)
                .ok_or_else(|| conflict("策略组编辑失败"))?;
            members = resolve_members(&edited.filters, &resolved, &config.nodes)?;
        }
        let mut next = group.clone();
        next.members = members;
        resolved.push(next);
    }
    let overlay = sources.iter().skip(1).cloned().collect::<HashMap<_, _>>();
    let names = parse(&sources[0].1)
        .nodes
        .into_iter()
        .map(|node| node.name)
        .collect::<Vec<_>>();
    let mut next = build_with_sources(
        sources[0].1.clone(),
        None,
        &crate::providers::nodes(&names),
        &overlay,
    );
    let errors = next
        .diagnostics
        .iter()
        .filter(|row| row.level == "error")
        .map(|row| row.message.clone())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Err(write_error(422, "invalid_config", errors.join("；")));
    }
    for edit in &edits {
        let next_members = next
            .groups
            .iter()
            .filter(|group| group.members.contains(&edit.name))
            .map(|group| group.name.clone())
            .collect::<HashSet<_>>();
        if next_members != edit.wanted {
            return Err(conflict("无法完成所属组调整，请刷新配置后重试"));
        }
    }
    let roster = |nodes: &[Node]| {
        nodes
            .iter()
            .map(|node| (node.name.clone(), node.link.clone()))
            .collect::<Vec<_>>()
    };
    if roster(&next.nodes) != roster(&config.nodes) {
        return Err(conflict("订阅节点在保存期间变更，请刷新后重试"));
    }
    for group in &config.groups {
        let others = group
            .members
            .iter()
            .filter(|member| !edited_names.contains(member.as_str()))
            .collect::<HashSet<_>>();
        let changed = next
            .groups
            .iter()
            .find(|changed| changed.name == group.name)
            .ok_or_else(|| conflict("策略组在保存期间变更"))?;
        if others
            != changed
                .members
                .iter()
                .filter(|member| !edited_names.contains(member.as_str()))
                .collect()
        {
            return Err(conflict("此修改会影响其他节点，已取消写入"));
        }
    }

    let changed = sources
        .iter()
        .zip(&previous)
        .filter(|(new, old)| new.1 != old.1)
        .collect::<Vec<_>>();
    let mut written: Vec<usize> = Vec::new();
    for (index, ((path, text), (_, old))) in changed.iter().enumerate() {
        let target = data_dir().join(path);
        let result = if fs::read_to_string(&target).ok().as_deref() != Some(old) {
            Err(std::io::Error::other("文件已被其他程序修改"))
        } else {
            crate::storage::write_atomic(&target, text.as_bytes())
        };
        if let Err(error) = result {
            let mut message = format!("所属组保存失败：{error}");
            for index in written.into_iter().rev() {
                let ((path, new), (_, old)) = changed[index];
                let target = data_dir().join(path);
                if fs::read_to_string(&target).ok().as_deref() != Some(new) {
                    message.push_str("；文件已再次变更，未覆盖外部修改");
                    continue;
                }
                if let Err(error) = crate::storage::write_atomic(&target, old.as_bytes()) {
                    message.push_str(&format!("；恢复配置失败：{error}"));
                }
            }
            return Err(write_error(500, "source_write_failed", message));
        }
        written.push(index);
    }
    next.modified = fs::metadata(config_path())
        .ok()
        .and_then(|meta| meta.modified().ok());
    let previous_generation = config.generation.clone();
    let generation = next.generation.clone();
    publish(&mut config, next);
    drop(config);
    for edit in &edits {
        let removed = edit
            .actual
            .difference(&edit.wanted)
            .cloned()
            .collect::<Vec<_>>();
        crate::control::forget_member(&removed, &edit.name);
    }
    crate::events::generation_changed(&previous_generation, &generation);
    Ok(
        serde_json::json!({"generation_id":generation,"changed":true,"changed_nodes":changed_nodes,"total_nodes":edits.len()}),
    )
}

fn resolve_members(
    filters: &[String],
    groups: &[Group],
    nodes: &[Node],
) -> Result<Vec<String>, SourceWriteError> {
    if filters.is_empty() {
        return Ok(nodes.iter().map(|node| node.name.clone()).collect());
    }
    let mut members = Vec::new();
    for filter in filters {
        for member in crate::group_filter::evaluate(filter, groups, nodes)
            .map_err(|message| write_error(422, "invalid_config", message))?
        {
            if !members.contains(&member) {
                members.push(member);
            }
        }
    }
    Ok(members)
}

fn uncomment(line: &str) -> (&str, &str) {
    let mut quote = None;
    let mut escaped = false;
    for (index, c) in line.char_indices() {
        if quote.is_some() && escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && c == '\\' {
            escaped = true;
            continue;
        }
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '#' => return (&line[..index], &line[index..]),
            None => {}
        }
    }
    (line, "")
}
fn exact_names(term: &str, negative: bool) -> Option<Vec<String>> {
    let body = if negative {
        term.trim().strip_prefix('!')?.trim()
    } else {
        term.trim()
    };
    let open = body.find('(')?;
    if body[..open].trim() != "name" {
        return None;
    }
    let arguments =
        crate::group_filter::split_top(body[open + 1..].strip_suffix(')')?, ",").ok()?;
    let mut names = Vec::new();
    for argument in arguments {
        if argument.starts_with("keyword:") || argument.starts_with("regex:") {
            return None;
        }
        let value = unquote(argument);
        if value.is_empty() {
            return None;
        }
        names.push(value);
    }
    Some(names)
}
fn names_call(names: &[String], negative: bool) -> String {
    format!(
        "{}name({})",
        if negative { "!" } else { "" },
        names
            .iter()
            .map(|name| json::quoted(name))
            .collect::<Vec<_>>()
            .join(", ")
    )
}
fn rewrite_memberships(
    text: &str,
    group: &RawGroup,
    add: &[String],
    remove: &[String],
) -> Result<String, SourceWriteError> {
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let start = group.line as usize - 1;
    let end = (start + 1..lines.len())
        .find(|index| lines[*index].trim() == "}")
        .ok_or_else(|| conflict("策略组配置块不完整"))?;
    let mut filters = 0;
    let mut covered = HashSet::new();
    let mut body = Vec::new();
    let indent = lines[start + 1..end]
        .iter()
        .find(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
        .map(|line| line[..line.len() - line.trim_start().len()].to_owned())
        .unwrap_or_else(|| {
            format!(
                "{}  ",
                &lines[start][..lines[start].len() - lines[start].trim_start().len()]
            )
        });
    for line in &lines[start + 1..end] {
        let (code, comment) = uncomment(line);
        let trimmed = code.trim();
        if let Some(filter) = trimmed.strip_prefix("filter:") {
            filters += 1;
            let filter = filter.trim();
            let parts = crate::group_filter::split_top(filter, "&&")
                .map_err(|message| write_error(422, "invalid_config", message))?;
            let mut terms = Vec::new();
            let mut excluded = Vec::new();
            let mut insert = None;
            for part in parts {
                if let Some(names) = exact_names(part, true) {
                    insert.get_or_insert(terms.len());
                    for name in names {
                        if !add.contains(&name) && !excluded.contains(&name) {
                            excluded.push(name);
                        }
                    }
                } else {
                    terms.push(part.to_owned());
                }
            }
            for name in remove {
                if !excluded.contains(name) {
                    excluded.push(name.clone());
                }
            }
            if !excluded.is_empty() {
                terms.insert(
                    insert.unwrap_or(terms.len()).min(terms.len()),
                    names_call(&excluded, true),
                );
            }
            if terms.is_empty() {
                terms.push("name(regex: \"(?s)^.*$\")".to_owned());
                covered.extend(add.iter().cloned());
            }
            if terms.len() == 1 {
                if let Some(names) = exact_names(&terms[0], false) {
                    covered.extend(names);
                }
            }
            let updated = terms.join(" && ");
            let prefix = &code[..code.find("filter:").unwrap() + "filter:".len()];
            body.push(format!(
                "{prefix} {updated}{}{}",
                if comment.is_empty() { "" } else { " " },
                comment
            ));
        } else if !remove.is_empty()
            && ["default:", "final:"].iter().any(|key| {
                trimmed
                    .strip_prefix(key)
                    .is_some_and(|value| remove.contains(&unquote(value.trim())))
            })
        {
            if !comment.is_empty() {
                body.push(format!("{indent}{comment}"));
            }
        } else {
            body.push(line.clone());
        }
    }
    let missing = add
        .iter()
        .filter(|name| !covered.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        body.push(format!("{indent}filter: {}", names_call(&missing, false)));
    }
    if filters == 0 && !remove.is_empty() {
        body.push(format!("{indent}filter: {}", names_call(remove, true)));
    }
    lines.splice(start + 1..end, body);
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut result = lines.join(eol);
    if text.ends_with('\n') {
        result.push_str(eol);
    }
    Ok(result)
}
