//! Delete a provider node and its ordinary group membership in one publication.
use super::*;

type Failure = (u16, &'static str, String);

fn conflict(message: impl Into<String>) -> Failure {
    (409, "state_conflict", message.into())
}

/// Remove only literal membership arguments. Keep dynamic filters and comments;
/// an empty filter must remain empty, rather than becoming the implicit all-nodes.
fn remove_memberships(content: &str, name: &str) -> Result<String, String> {
    let mut lines = content.lines().map(str::to_owned).collect::<Vec<_>>();
    for group in parse(content).groups {
        let start = group.line as usize - 1;
        let end = (start + 1..lines.len())
            .find(|index| memberships::uncomment(&lines[*index]).0.trim() == "}")
            .ok_or("策略组配置块不完整")?;
        for line in &mut lines[start + 1..end] {
            let (code, comment) = memberships::uncomment(line);
            let trimmed = code.trim();
            let Some(filter) = trimmed.strip_prefix("filter:").map(str::trim) else {
                if trimmed
                    .strip_prefix("default:")
                    .is_some_and(|v| unquote(v.trim()) == name)
                {
                    *line = if comment.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "{}{}",
                            &code[..code.len() - code.trim_start().len()],
                            comment
                        )
                    };
                }
                continue;
            };
            let Some((call, args)) = ["outbound", "name"].into_iter().find_map(|call| {
                filter
                    .strip_prefix(&format!("{call}("))
                    .and_then(|v| v.strip_suffix(')'))
                    .map(|args| (call, args))
            }) else {
                continue;
            };
            let arguments = crate::group_filter::split_top(args, ",")?;
            let kept = arguments
                .iter()
                .copied()
                .filter(|arg| unquote(arg) != name)
                .collect::<Vec<_>>();
            if kept.len() == arguments.len() {
                continue;
            }
            let next = if kept.is_empty() {
                "!name(regex: \".*\")".to_owned()
            } else {
                format!("{call}({})", kept.join(", "))
            };
            let prefix = &code[..code.find("filter:").unwrap() + "filter:".len()];
            *line = format!(
                "{prefix} {next}{}{comment}",
                if comment.is_empty() { "" } else { " " }
            );
        }
    }
    let mut next = lines.join("\n");
    if content.ends_with('\n') {
        next.push('\n')
    }
    Ok(next)
}

fn save_sources(changes: &[(String, String, String)]) -> Result<(), String> {
    let mut written: Vec<usize> = Vec::new();
    for (index, (path, old, new)) in changes.iter().enumerate() {
        let target = data_dir().join(path);
        let result = if fs::read_to_string(&target).ok().as_deref() != Some(old) {
            Err(std::io::Error::other("配置文件已被外部修改"))
        } else {
            crate::storage::write_atomic(&target, new.as_bytes())
        };
        if let Err(error) = result {
            let mut message = format!("节点删除保存失败：{error}");
            for index in written.into_iter().rev() {
                let (path, old, new) = &changes[index];
                let target = data_dir().join(path);
                if fs::read_to_string(&target).ok().as_deref() != Some(new) {
                    message.push_str("；配置又被修改，未覆盖外部写入");
                } else if let Err(error) = crate::storage::write_atomic(&target, old.as_bytes()) {
                    message.push_str(&format!("；恢复配置失败：{error}"));
                }
            }
            return Err(message);
        }
        written.push(index);
    }
    Ok(())
}

pub(crate) fn delete_managed_node(id: &str) -> Result<String, Failure> {
    delete_managed(id, false)
}

pub(crate) fn delete_managed_provider(id: &str) -> Result<String, Failure> {
    delete_managed(id, true)
}

fn delete_managed(id: &str, whole_provider: bool) -> Result<String, Failure> {
    let _serial = crate::rules_runtime::APPLY
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    refresh();
    let mut config = current();
    let name = id.strip_prefix("node-").unwrap_or(id);
    let nodes = config
        .nodes
        .iter()
        .filter(|node| {
            if whole_provider {
                node.provider.as_deref() == Some(id)
            } else {
                node.name == name
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    if nodes.is_empty() && !whole_provider {
        return Err((404, "resource_not_found", "节点已不存在，请刷新列表".into()));
    }
    if nodes.iter().any(|node| node.provider.is_none()) {
        return Err((
            404,
            "capability_not_supported",
            "该节点在配置文件中声明，请在配置页删除".into(),
        ));
    }
    let names_to_remove = nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>();
    let mut references = config
        .rules
        .iter()
        .chain(std::iter::once(&config.fallback))
        .filter(|rule| names_to_remove.contains(&rule.outbound.as_str()))
        .map(|rule| format!("路由规则 {}", rule.line))
        .collect::<Vec<_>>();
    references.extend(
        config
            .groups
            .iter()
            .filter(|group| {
                [&group.final_outbound, &group.dialer, &group.landing]
                    .into_iter()
                    .any(|value| {
                        value
                            .as_deref()
                            .is_some_and(|name| names_to_remove.contains(&name))
                    })
            })
            .map(|group| format!("出站 {}", group.name)),
    );
    let resources = crate::rules_runtime::current();
    references.extend(
        resources
            .document
            .resolvers
            .iter()
            .filter(|r| names_to_remove.contains(&r.outbound.as_str()))
            .map(|r| format!("DNS 服务器 {}", r.name)),
    );
    references.extend(
        resources
            .document
            .providers
            .iter()
            .filter(|r| names_to_remove.contains(&r.outbound.as_str()))
            .map(|r| format!("规则集 {}", r.name)),
    );
    if !references.is_empty() {
        return Err(conflict(format!(
            "节点仍被{}引用，请先更换引用再删除",
            references.join("、")
        )));
    }
    let mut sources = vec![(SOURCE_PATH.to_owned(), config.content.clone())];
    sources.extend(config.include_contents.iter().cloned());
    let mut changes = Vec::new();
    for (path, content) in &mut sources {
        if fs::read_to_string(data_dir().join(&*path)).ok().as_deref() != Some(content) {
            return Err(conflict("配置文件已被外部修改，请先重载后再删除"));
        }
        let mut next = content.clone();
        for name in &names_to_remove {
            next = remove_memberships(&next, name).map_err(conflict)?;
        }
        if next != *content {
            changes.push((path.clone(), content.clone(), next.clone()));
            *content = next;
        }
    }
    let overlay = sources.iter().skip(1).cloned().collect();
    let names = parse(&sources[0].1)
        .nodes
        .into_iter()
        .map(|node| node.name)
        .collect::<Vec<_>>();
    let mut accepted = None;
    let validate = |provider_nodes: Vec<Node>| {
        let next = build_with_sources(sources[0].1.clone(), None, &provider_nodes, &overlay);
        let errors = next
            .diagnostics
            .iter()
            .filter(|row| row.level == "error")
            .map(|row| row.message.clone())
            .collect::<Vec<_>>();
        if !errors.is_empty() {
            return Err(format!("删除会使出站或链路失效：{}", errors.join("；")));
        }
        accepted = Some(next);
        Ok(())
    };
    let removed = if whole_provider {
        crate::providers::remove_provider_checked(id, &nodes, &names, validate, || {
            save_sources(&changes)
        })?
    } else {
        crate::providers::remove_node_checked(&nodes[0], &names, validate, || {
            save_sources(&changes)
        })?
    };
    if removed == 0 {
        return Err(conflict("节点已删除，请刷新列表"));
    }
    let mut next = accepted.expect("validated deletion snapshot");
    next.modified = fs::metadata(config_path())
        .ok()
        .and_then(|meta| meta.modified().ok());
    let previous = config.generation.clone();
    let generation = next.generation.clone();
    let groups = config
        .groups
        .iter()
        .map(|group| group.name.clone())
        .collect::<Vec<_>>();
    for name in &names_to_remove {
        crate::control::forget_member(&groups, name);
    }
    publish(&mut config, next);
    drop(config);
    crate::events::generation_changed(&previous, &generation);
    Ok(r#"{"deleted":1}"#.to_owned())
}
