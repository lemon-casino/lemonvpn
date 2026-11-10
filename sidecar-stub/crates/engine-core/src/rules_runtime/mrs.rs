//! MRS v1 wire compatibility with MetaCubeX/mihomo v1.19.33 (GPL-3.0).
//! Decode bounded data; never execute the kernel as a file converter.
use std::{
    collections::VecDeque,
    io::{Cursor, Read},
    net::{IpAddr, Ipv6Addr},
};
const LIMIT: usize = 64 * 1024 * 1024;
fn err() -> String {
    "MRS 文件损坏、版本不支持或超过资源上限".into()
}
fn byte(r: &mut Cursor<Vec<u8>>) -> Result<u8, String> {
    let mut b = [0];
    r.read_exact(&mut b).map_err(|_| err())?;
    Ok(b[0])
}
fn number(r: &mut Cursor<Vec<u8>>) -> Result<u64, String> {
    let mut b = [0; 8];
    r.read_exact(&mut b).map_err(|_| err())?;
    Ok(u64::from_be_bytes(b))
}
fn length(r: &mut Cursor<Vec<u8>>, max: usize) -> Result<usize, String> {
    usize::try_from(number(r)?)
        .ok()
        .filter(|v| *v <= max)
        .ok_or_else(err)
}
fn words(r: &mut Cursor<Vec<u8>>) -> Result<Vec<u64>, String> {
    let n = length(r, LIMIT / 8)?;
    if n == 0 {
        return Err(err());
    }
    (0..n).map(|_| number(r)).collect()
}
fn bit(bits: &[u64], at: usize) -> Result<bool, String> {
    bits.get(at / 64)
        .map(|word| word & (1u64 << (at % 64)) != 0)
        .ok_or_else(err)
}
pub fn decode(bytes: &[u8]) -> Result<(String, Vec<String>), String> {
    let mut decoder = zstd::stream::read::Decoder::new(bytes).map_err(|e| e.to_string())?;
    decoder.window_log_max(26).map_err(|e| e.to_string())?;
    let mut decoded = Vec::new();
    decoder
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|e| e.to_string())?;
    if decoded.len() > LIMIT {
        return Err(err());
    }
    let mut r = Cursor::new(decoded);
    let mut magic = [0; 4];
    r.read_exact(&mut magic).map_err(|_| err())?;
    if magic != *b"MRS\x01" {
        return Err(err());
    }
    let kind = byte(&mut r)?;
    let count = length(&mut r, 1_000_000)?;
    let extra = length(&mut r, 1024 * 1024)?;
    let end = r.position().checked_add(extra as u64).ok_or_else(err)?;
    if end > r.get_ref().len() as u64 {
        return Err(err());
    }
    r.set_position(end);
    if byte(&mut r)? != 1 {
        return Err(err());
    }
    let mut entries = Vec::new();
    let mut entry_bytes = 0usize;
    if kind == 0 {
        let leaves = words(&mut r)?;
        let bitmap = words(&mut r)?;
        let n = length(&mut r, LIMIT)?;
        let mut labels = vec![0; n];
        r.read_exact(&mut labels).map_err(|_| err())?;
        // LOUDS is breadth-first. Each zero introduces the next child; one
        // terminates the current node's children. Bound paths before copying.
        let mut queued_bytes = 0usize;
        let mut queue = VecDeque::from([(0usize, Vec::<u8>::new())]);
        let (mut at, mut edge, mut next) = (0, 0, 1);
        while let Some((node, key)) = queue.pop_front() {
            queued_bytes = queued_bytes.saturating_sub(key.len());
            if bit(&leaves, node)? {
                let mut name = key.clone();
                if name.last() == Some(&b'+') {
                    name.pop();
                }
                let name = String::from_utf8(name).map_err(|_| err())?;
                entry_bytes = entry_bytes
                    .checked_add(name.len())
                    .filter(|n| *n <= LIMIT)
                    .ok_or_else(err)?;
                entries.push(name.chars().rev().collect());
                if entries.len() > 1_000_000 {
                    return Err(err());
                }
            }
            while !bit(&bitmap, at)? {
                if key.len() >= 254 {
                    return Err(err());
                }
                let mut child = key.clone();
                child.push(*labels.get(edge).ok_or_else(err)?);
                queued_bytes = queued_bytes
                    .checked_add(child.len())
                    .filter(|n| *n <= LIMIT)
                    .ok_or_else(err)?;
                if queue.len() > 1_000_000 {
                    return Err(err());
                }
                queue.push_back((next, child));
                next += 1;
                edge += 1;
                at += 1;
                if next > n + 1 {
                    return Err(err());
                }
            }
            at += 1;
        }
        if edge != labels.len() || entries.len() > count.saturating_mul(2).saturating_add(1) {
            return Err(err());
        }
    } else if kind == 1 {
        let ranges = length(&mut r, 1_000_000)?;
        for _ in 0..ranges {
            let mut lo = [0; 16];
            let mut hi = [0; 16];
            r.read_exact(&mut lo).map_err(|_| err())?;
            r.read_exact(&mut hi).map_err(|_| err())?;
            let first = Ipv6Addr::from(lo);
            let last = Ipv6Addr::from(hi);
            let (mut start, finish, bits) = match (first.to_ipv4_mapped(), last.to_ipv4_mapped()) {
                (Some(a), Some(b)) => (u128::from(u32::from(a)), u128::from(u32::from(b)), 32u32),
                (None, None) => (u128::from(first), u128::from(last), 128),
                _ => return Err(err()),
            };
            if start > finish {
                return Err(err());
            }
            loop {
                let alignment = start.trailing_zeros().min(bits);
                let remaining = finish - start;
                let size = if remaining == u128::MAX {
                    128
                } else {
                    127 - (remaining + 1).leading_zeros()
                };
                let power = alignment.min(size);
                let prefix = bits - power;
                let ip = if bits == 32 {
                    IpAddr::V4(std::net::Ipv4Addr::from(start as u32))
                } else {
                    IpAddr::V6(Ipv6Addr::from(start))
                };
                entries.push(format!("{ip}/{prefix}"));
                if entries.len() > 1_000_000 {
                    return Err(err());
                }
                if power == 128 {
                    break;
                }
                let step = 1u128 << power;
                if finish - start < step {
                    break;
                }
                start += step;
            }
        }
    } else {
        return Err("MRS 仅支持 domain 或 ipcidr".into());
    }
    if r.position() != r.get_ref().len() as u64 {
        return Err(err());
    }
    Ok((if kind == 0 { "domain" } else { "ipcidr" }.into(), entries))
}
