//! Base64 for subscription bodies, share links and the provider store.
//!
//! Subscriptions use both the standard and the URL-safe alphabet, with or
//! without padding and with line breaks inserted, so decoding accepts all of
//! them; encoding always produces the standard padded form.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let bits = (first << 16) | (second << 8) | third;
        out.push(STANDARD[(bits >> 18) as usize & 0x3f] as char);
        out.push(STANDARD[(bits >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(STANDARD[(bits >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(STANDARD[bits as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes standard or URL-safe input, ignoring whitespace and missing padding.
/// Returns None when a character is not part of either alphabet.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trips_standard_input() {
        for text in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "节点 1"] {
            let encoded = encode(text.as_bytes());
            assert_eq!(decode(&encoded).as_deref(), Some(text.as_bytes()), "{encoded}");
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
    }

    #[test]
    fn decodes_url_safe_unpadded_and_wrapped() {
        // Same bytes as "foobar>?" which encodes to "Zm9vYmFyPj8=" in standard.
        assert_eq!(decode("Zm9vYmFyPj8").as_deref(), Some(&b"foobar>?"[..]));
        assert_eq!(decode("Zm9v\r\nYmFy").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(decode("!!!!"), None);
    }
}
