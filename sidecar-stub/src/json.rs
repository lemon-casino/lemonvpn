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

#[cfg(test)]
mod tests {
    use super::quoted;

    #[test]
    fn escapes_control_characters_and_quotes() {
        assert_eq!(quoted("a\"b\\c\nd\te"), r#""a\"b\\c\nd\te""#);
        assert_eq!(quoted("plain"), r#""plain""#);
    }
}
