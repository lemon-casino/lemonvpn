//! Group filters share the editor's semantics: OR across lines/arguments,
//! AND across terms, with exact, keyword and Rust regular-expression matches.
use crate::config::{Group, Node};
use regex::Regex;
use std::collections::HashSet;

enum Matcher {
    Exact(String),
    Keyword(String),
    Regex(Regex),
}

impl Matcher {
    fn parse(argument: &str) -> Result<Self, String> {
        let argument = argument.trim();
        let (kind, raw) = if let Some(value) = argument.strip_prefix("keyword:") {
            ("keyword", value)
        } else if let Some(value) = argument.strip_prefix("regex:") {
            ("regex", value)
        } else {
            ("exact", argument)
        };
        let value = unquote(raw.trim());
        if value.is_empty() {
            return Err("筛选条件不能为空".to_owned());
        }
        match kind {
            "regex" => Regex::new(&value)
                .map(Self::Regex)
                .map_err(|error| format!("无效的节点筛选正则表达式：{error}")),
            "keyword" => Ok(Self::Keyword(value.to_owned())),
            _ => Ok(Self::Exact(value.to_owned())),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(pattern) => value == pattern,
            Self::Keyword(pattern) => value.contains(pattern),
            Self::Regex(pattern) => pattern.is_match(value),
        }
    }
}

pub(crate) fn evaluate(
    filter: &str,
    groups: &[Group],
    nodes: &[Node],
) -> Result<Vec<String>, String> {
    let mut selected: Option<HashSet<String>> = None;
    for term in split_top(filter, "&&")? {
        let found = evaluate_term(term, groups, nodes)?;
        match &mut selected {
            Some(selected) => selected.retain(|name| found.contains(name)),
            None => selected = Some(found),
        }
    }
    let selected = selected.unwrap_or_default();
    // Preserve roster order, as the editor's preview does, regardless of argument order.
    Ok(nodes
        .iter()
        .filter(|node| selected.contains(&node.name))
        .map(|node| node.name.clone())
        .collect())
}

/// Exact group edges use the same argument semantics as evaluation, including
/// negation and pipe/comma lists. This permits source-order-independent resolution.
pub(crate) fn dependencies(filter: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for term in split_top(filter, "&&")? {
        let body = term.trim().strip_prefix('!').unwrap_or(term.trim()).trim();
        let Some(open) = body.find('(') else {
            continue;
        };
        if body[..open].trim() != "group" {
            continue;
        }
        let inner = body[open + 1..]
            .strip_suffix(')')
            .ok_or_else(|| "组筛选括号不完整".to_owned())?;
        for argument in split_top(inner, ",")? {
            for name in unquote(argument)
                .split(['|', ','])
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                if !result.iter().any(|found| found == name) {
                    result.push(name.to_owned());
                }
            }
        }
    }
    Ok(result)
}

fn evaluate_term(term: &str, groups: &[Group], nodes: &[Node]) -> Result<HashSet<String>, String> {
    let (negated, body) = match term.strip_prefix('!') {
        Some(body) => (true, body.trim()),
        None => (false, term.trim()),
    };
    let open = body
        .find('(')
        .ok_or_else(|| format!("无法识别筛选条件 `{term}`"))?;
    let call = body[..open].trim();
    let inner = body[open + 1..]
        .strip_suffix(')')
        .ok_or_else(|| format!("筛选条件括号不完整：`{term}`"))?;
    let arguments = split_top(inner, ",")?;
    let mut matched = HashSet::new();
    match call {
        "name" | "subtag" => {
            let matchers = arguments
                .into_iter()
                .map(Matcher::parse)
                .collect::<Result<Vec<_>, _>>()?;
            for node in nodes {
                let value = if call == "name" {
                    Some(node.name.as_str())
                } else {
                    node.subscription_tag.as_deref()
                };
                if value.is_some_and(|value| matchers.iter().any(|matcher| matcher.matches(value)))
                {
                    matched.insert(node.name.clone());
                }
            }
        }
        "group" => {
            for argument in arguments {
                for name in unquote(argument)
                    .split(['|', ','])
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                {
                    let group = groups
                        .iter()
                        .find(|group| group.name == name)
                        .ok_or_else(|| format!("组筛选引用了尚未解析的策略组 `{name}`"))?;
                    matched.extend(group.members.iter().cloned());
                }
            }
        }
        _ => {
            return Err(format!(
                "不支持的筛选条件 `{call}`，请使用 name、subtag 或 group"
            ))
        }
    }
    if negated {
        Ok(nodes
            .iter()
            .filter(|node| !matched.contains(&node.name))
            .map(|node| node.name.clone())
            .collect())
    } else {
        Ok(matched)
    }
}

// Keep quoted commas, && and parentheses inside their values, including regex patterns.
pub(crate) fn split_top<'a>(text: &'a str, separator: &str) -> Result<Vec<&'a str>, String> {
    let mut parts = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut index = 0usize;
    while index < text.len() {
        let character = text[index..].chars().next().unwrap();
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if depth == 0 && text[index..].starts_with(separator) {
            let value = text[start..index].trim();
            if value.is_empty() {
                return Err("筛选条件缺少参数".to_owned());
            }
            parts.push(value);
            index += separator.len();
            start = index;
            continue;
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "筛选条件括号不匹配".to_owned())?;
        }
        index += character.len_utf8();
    }
    if quote.is_some() || depth != 0 {
        return Err("筛选条件存在未闭合的引号或括号".to_owned());
    }
    let value = text[start..].trim();
    if value.is_empty() {
        return Err("筛选条件缺少参数".to_owned());
    }
    parts.push(value);
    Ok(parts)
}

fn unquote(value: &str) -> String {
    crate::config::unquote(value)
}
