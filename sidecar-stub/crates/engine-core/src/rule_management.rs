//! List-scoped factory reset and reorder. All affected sources are validated
//! and written before publishing one new configuration generation.
use super::*;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

fn failure(message: impl Into<String>) -> SourceWriteError {
    write_error(409, "state_conflict", message)
}
fn scope(value: &str) -> Result<&str, SourceWriteError> {
    match value {
        "routing" | "request" | "response" => Ok(value),
        _ => Err(write_error(400, "invalid_request", "规则列表无效")),
    }
}
struct Listed {
    id: String,
    path: String,
    line: u32,
    expression: String,
}
fn rows(config: &Config, list: &str) -> Vec<Listed> {
    if list == "routing" {
        config
            .rules
            .iter()
            .map(|rule| Listed {
                id: rule.id.clone(),
                path: rule
                    .source_id
                    .clone()
                    .unwrap_or_else(|| SOURCE_PATH.to_owned()),
                line: rule.line,
                expression: rule.expression.clone(),
            })
            .collect()
    } else {
        let rules = if list == "request" {
            &config.dns_rules
        } else {
            &config.dns_response_rules
        };
        rules
            .iter()
            .enumerate()
            .map(|(index, rule)| Listed {
                id: format!(
                    "dns-{}-{index}",
                    if list == "request" { "req" } else { "resp" }
                ),
                path: rule
                    .source_id
                    .clone()
                    .unwrap_or_else(|| SOURCE_PATH.to_owned()),
                line: rule.line,
                expression: rule.expression.clone(),
            })
            .collect()
    }
}
fn fallback(config: &Config, list: &str) -> String {
    match list {
        "routing" => config.fallback.outbound.clone(),
        "request" => config
            .dns_request_fallback
            .clone()
            .unwrap_or_else(|| "<implicit>".to_owned()),
        _ => config.dns_response_fallback.clone(),
    }
}
fn factory_routing() -> Vec<String> {
    let parsed = parse(DEFAULT_CONFIG);
    let mut rules = parsed
        .rules
        .into_iter()
        .map(|rule| rule.expression)
        .collect::<Vec<_>>();
    if let Some(rule) = parsed.fallback {
        rules.push(rule.expression);
    }
    rules
}
pub(crate) fn rule_defaults_json() -> String {
    refresh();
    let config = current();
    serde_json::json!({"generation_id":config.generation,"routing":factory_routing(),"request":config.upstreams.first().map(|upstream|vec![format!("fallback: {}",upstream.name)]).unwrap_or_default(),"response":["fallback: accept"]}).to_string()
}
fn uncomment(line: &str) -> &str {
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
            None if c == '#' => return &line[..index],
            None => {}
        }
    }
    line
}
fn blocks(text: &str, list: &str) -> Vec<Range<usize>> {
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut ranges = Vec::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let code = uncomment(raw).trim();
        if let Some(name) = code.strip_suffix('{') {
            stack.push((name.trim().to_owned(), offset));
        } else if code == "}" {
            if let Some((name, start)) = stack.pop() {
                let parents = stack
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>();
                let own = if list == "routing" {
                    name == "routing" && parents.is_empty()
                } else {
                    name == list && (parents == ["dns"] || parents == ["dns", "routing"])
                };
                if own {
                    ranges.push(start..offset + raw.len());
                }
            }
        }
        offset += raw.len();
    }
    ranges
}
fn source_line(
    sources: &[(String, String)],
    path: &str,
    line: u32,
) -> Result<String, SourceWriteError> {
    let text = &sources
        .iter()
        .find(|(name, _)| name == path)
        .ok_or_else(|| failure("找不到规则的配置源"))?
        .1;
    text.lines()
        .nth(line.checked_sub(1).ok_or_else(|| failure("规则行无效"))? as usize)
        .map(|line| line.trim().to_owned())
        .ok_or_else(|| failure("规则位置已变更"))
}
pub(crate) fn manage_rules(body: &str, reset: bool) -> Result<String, SourceWriteError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| write_error(400, "invalid_request", "请求不是 JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| write_error(400, "invalid_request", "请求必须是对象"))?;
    if object
        .keys()
        .any(|key| !["generation_id", "list", "rule_ids"].contains(&key.as_str()))
    {
        return Err(write_error(
            422,
            "unsupported_value",
            "规则操作包含未知字段",
        ));
    }
    let list = scope(value.get("list").and_then(|v| v.as_str()).unwrap_or(""))?;
    let generation = value
        .get("generation_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| write_error(400, "invalid_request", "缺少配置代次"))?;
    refresh();
    let mut config = current();
    if config.generation != generation {
        return Err(failure("规则或配置已变更，请刷新后重试"));
    }
    let listed = rows(&config, list);
    let mut originals = vec![(SOURCE_PATH.to_owned(), config.content.clone())];
    originals.extend(config.include_contents.iter().cloned());
    for (path, text) in &originals {
        if fs::read_to_string(data_dir().join(path)).ok().as_deref() != Some(text) {
            return Err(failure("配置已被外部修改，请重载后重试"));
        }
    }
    let mut statements = Vec::new();
    let mut expected = Vec::new();
    if reset {
        if list == "routing" {
            statements = factory_routing();
            let parsed = parse(DEFAULT_CONFIG);
            expected = parsed.rules.into_iter().map(|r| r.expression).collect();
        }
    } else {
        let ids = value
            .get("rule_ids")
            .and_then(|v| v.as_array())
            .filter(|ids| ids.len() == listed.len())
            .ok_or_else(|| failure("排序必须包含本列表的全部普通规则"))?;
        let mut seen = HashSet::new();
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| write_error(400, "invalid_request", "规则 ID 无效"))?;
            if !seen.insert(id) {
                return Err(write_error(400, "invalid_request", "规则 ID 重复"));
            }
            let rule = listed
                .iter()
                .find(|rule| rule.id == id)
                .ok_or_else(|| failure("规则已变更，请刷新后排序"))?;
            statements.push(source_line(&originals, &rule.path, rule.line)?);
            expected.push(rule.expression.clone());
        }
        if ids
            .iter()
            .zip(&listed)
            .all(|(id, rule)| id.as_str() == Some(rule.id.as_str()))
        {
            return Ok(
                serde_json::json!({"generation_id":config.generation,"changed":false}).to_string(),
            );
        }
        if list == "routing" {
            statements.push(if config.fallback.line > 0 {
                source_line(
                    &originals,
                    config.fallback.source_id.as_deref().unwrap_or(SOURCE_PATH),
                    config.fallback.line,
                )?
            } else {
                config.fallback.expression.clone()
            });
        } else {
            let origin = if list == "request" {
                &config.dns_request_fallback_source
            } else {
                &config.dns_response_fallback_source
            };
            if let Some((line, path)) = origin {
                statements.push(source_line(
                    &originals,
                    path.as_deref().unwrap_or(SOURCE_PATH),
                    *line,
                )?);
            }
        }
    }
    let mut sources = originals.clone();
    let mut comments = Vec::new();
    for (path, text) in &mut sources {
        let ranges = blocks(text, list);
        for rule in listed.iter().filter(|rule| rule.path == *path) {
            let at = text
                .split_inclusive('\n')
                .take(rule.line.saturating_sub(1) as usize)
                .map(str::len)
                .sum::<usize>();
            if !ranges.iter().any(|range| range.contains(&at)) {
                return Err(failure("不能安全定位规则列表，未写入配置"));
            }
        }
        if !reset {
            for range in &ranges {
                if text[range.clone()]
                    .lines()
                    .skip(1)
                    .any(|line| uncomment(line).trim().ends_with('{'))
                {
                    return Err(failure("列表含有额外配置块，不能安全排序，未写入配置"));
                }
            }
            for range in &ranges {
                comments.extend(
                    text[range.clone()]
                        .lines()
                        .filter(|line| line.trim().starts_with('#'))
                        .map(|line| line.trim().to_owned()),
                );
            }
        }
        for range in ranges.into_iter().rev() {
            text.replace_range(range, "");
        }
    }
    if !statements.is_empty() || !comments.is_empty() {
        let main = &mut sources[0].1;
        if !main.ends_with('\n') {
            main.push('\n');
        }
        main.push('\n');
        let indent = if list == "routing" { "  " } else { "      " };
        if list == "routing" {
            main.push_str("routing {\n");
        } else {
            main.push_str(&format!("dns {{\n  routing {{\n    {list} {{\n"));
        }
        for line in comments.into_iter().chain(statements) {
            main.push_str(indent);
            main.push_str(&line);
            main.push('\n');
        }
        main.push_str(if list == "routing" {
            "}\n"
        } else {
            "    }\n  }\n}\n"
        });
    }
    if sources.iter().any(|(_, text)| text.len() > MAX_BYTES) {
        return Err(write_error(
            413,
            "request_too_large",
            "规则调整后配置超过 max_bytes",
        ));
    }
    let overlay = sources.iter().skip(1).cloned().collect::<HashMap<_, _>>();
    let inline_names = parse(&sources[0].1)
        .nodes
        .into_iter()
        .map(|node| node.name)
        .collect::<Vec<_>>();
    let mut next = build_with_sources(
        sources[0].1.clone(),
        None,
        &crate::providers::nodes(&inline_names),
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
    if rows(&next, list)
        .iter()
        .map(|rule| rule.expression.clone())
        .collect::<Vec<_>>()
        != expected
    {
        return Err(failure("规则顺序校验失败，未写入配置"));
    }
    let desired_fallback = if reset {
        match list {
            "routing" => "direct",
            "request" => "<implicit>",
            _ => "accept",
        }
        .to_owned()
    } else {
        fallback(&config, list)
    };
    if fallback(&next, list) != desired_fallback {
        return Err(failure("默认规则校验失败，未写入配置"));
    }
    for other in ["routing", "request", "response"]
        .into_iter()
        .filter(|other| *other != list)
    {
        if rows(&config, other)
            .iter()
            .map(|r| &r.expression)
            .collect::<Vec<_>>()
            != rows(&next, other)
                .iter()
                .map(|r| &r.expression)
                .collect::<Vec<_>>()
            || fallback(&config, other) != fallback(&next, other)
        {
            return Err(failure("修改会影响其他规则列表，已取消"));
        }
    }
    if format!(
        "{:?}{:?}{:?}",
        config.nodes, config.groups, config.upstreams
    ) != format!("{:?}{:?}{:?}", next.nodes, next.groups, next.upstreams)
    {
        return Err(failure("节点、策略组或 DNS 上游已变更，请刷新后重试"));
    }
    let changed = sources
        .iter()
        .zip(&originals)
        .filter(|(new, old)| new.1 != old.1)
        .collect::<Vec<_>>();
    let mut written: Vec<usize> = Vec::new();
    for (index, ((path, text), (_, old))) in changed.iter().enumerate() {
        let target = data_dir().join(path);
        let result = if fs::read_to_string(&target).ok().as_deref() != Some(old) {
            Err(std::io::Error::other("配置文件已被其他程序修改"))
        } else {
            crate::storage::write_atomic(&target, text.as_bytes())
        };
        if let Err(error) = result {
            let mut message = format!("保存规则失败：{error}");
            for index in written.into_iter().rev() {
                let ((path, new), (_, old)) = changed[index];
                let target = data_dir().join(path);
                if fs::read_to_string(&target).ok().as_deref() != Some(new) {
                    message.push_str("；文件已再次变更，未覆盖外部修改");
                    continue;
                }
                if let Err(error) = crate::storage::write_atomic(&target, old.as_bytes()) {
                    message.push_str(&format!("；恢复失败：{error}"));
                }
            }
            return Err(write_error(500, "source_write_failed", message));
        }
        written.push(index);
    }
    next.modified = fs::metadata(config_path())
        .ok()
        .and_then(|meta| meta.modified().ok());
    let before = config.generation.clone();
    let generation = next.generation.clone();
    publish(&mut config, next);
    drop(config);
    crate::events::generation_changed(&before, &generation);
    crate::logs::info(
        "engine::rules",
        if reset {
            "Rule list reset."
        } else {
            "Rule list reordered."
        },
        Some(crate::logs::fields(&[
            ("list", list),
            ("generation", &generation),
        ])),
    );
    Ok(serde_json::json!({"generation_id":generation,"changed":true}).to_string())
}
