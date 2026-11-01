//! Minimal JSON string escaping for the API bodies assembled by hand.

pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn quoted(value: &str) -> String {
    format!("\"{}\"", escape(value))
}

/// Reads one top-level string field from a small JSON object. The API bodies
/// this engine accepts are flat, so a scanner is enough.
pub fn field(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut value = String::new();
    let mut escaped = false;
    for character in rest.chars() {
        if escaped {
            value.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(value);
        } else {
            value.push(character);
        }
    }
    None
}

/// The top-level keys of a JSON object, in order. Nested objects are skipped so
/// a request body's options object cannot smuggle in an unknown field name.
pub fn keys(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'"' if depth == 1 => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() {
                    match bytes[end] {
                        b'\\' => end += 2,
                        b'"' => break,
                        _ => end += 1,
                    }
                }
                if end < bytes.len() {
                    let key = &body[start..end];
                    let after = body[end + 1..].trim_start();
                    if after.starts_with(':') {
                        found.push(key.to_owned());
                    }
                    index = end + 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    found
}

/// The bytes after the colon of a top-level key, or `None` when the key is absent.
/// A same-named key inside a nested object does not count.
fn top_level_value<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b'"' if depth == 1 => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() {
                    match bytes[end] {
                        b'\\' => end += 2,
                        b'"' => break,
                        _ => end += 1,
                    }
                }
                if end >= bytes.len() {
                    return None;
                }
                let after = body[end + 1..].trim_start();
                if let Some(rest) = after.strip_prefix(':') {
                    if &body[start..end] == name {
                        return Some(rest);
                    }
                }
                index = end + 1;
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Reads a boolean field. `Ok(None)` when the key is absent; a value that is
/// not a JSON boolean is a request error.
pub fn bool_field(body: &str, key: &str) -> Result<Option<bool>, String> {
    let Some(rest) = top_level_value(body, key) else {
        return Ok(None);
    };
    let rest = rest.trim_start();
    if rest.starts_with("true") {
        Ok(Some(true))
    } else if rest.starts_with("false") {
        Ok(Some(false))
    } else {
        Err(format!("字段 {key} 不是有效的布尔值"))
    }
}

#[cfg(test)]
mod tests {
    use super::{bool_field, keys, quoted};

    #[test]
    fn lists_only_top_level_keys() {
        let body = r#"{"name":"a","options":{"cache":true},"url":"https://x","cache":false}"#;
        assert_eq!(keys(body), vec!["name", "options", "url", "cache"]);
        assert_eq!(bool_field(body, "cache").unwrap(), Some(false));
        assert_eq!(bool_field(body, "missing").unwrap(), None);
        assert!(bool_field(r#"{"cache":"yes"}"#, "cache").is_err());
    }

    #[test]
    fn escapes_control_characters_and_quotes() {
        assert_eq!(quoted("a\"b\\c\nd\te"), r#""a\"b\\c\nd\te""#);
        assert_eq!(quoted("plain"), r#""plain""#);
    }
}
