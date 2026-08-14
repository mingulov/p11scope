//! Strict lexical facts from Linux `/proc/<pid>/maps`.

use crate::identity::MappingFileKey;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Device {
    pub major: u64,
    pub minor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub permissions: [u8; 4],
    pub device: Device,
    pub inode: u64,
    /// Kernel-rendered pathname bytes. `None` only when the field is absent.
    pub raw_path: Option<Vec<u8>>,
}

/// Parse every nonempty maps line or reject the entire snapshot.
pub fn parse_maps(bytes: &[u8]) -> Result<Vec<MapEntry>, String> {
    bytes
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(index, line)| {
            parse_line(line)
                .map_err(|error| format!("invalid /proc maps line {}: {error}", index + 1))
        })
        .collect()
}

/// Exact file identities for executable mappings in a parsed snapshot.
pub fn executable_file_keys(entries: &[MapEntry]) -> BTreeSet<MappingFileKey> {
    entries
        .iter()
        .filter(|entry| entry.permissions[2] == b'x' && entry.inode != 0)
        .map(|entry| MappingFileKey {
            device_major: entry.device.major,
            device_minor: entry.device.minor,
            inode: entry.inode,
        })
        .collect()
}

fn parse_line(mut line: &[u8]) -> Result<MapEntry, String> {
    // <start>-<end> <perms> <offset> <dev> <inode> [path with possible spaces]
    let range = field(&mut line, "address range")?;
    let permissions: [u8; 4] = field(&mut line, "permissions")?
        .try_into()
        .map_err(|_| "permissions must contain four bytes".to_string())?;
    if !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err("invalid permissions".into());
    }
    let file_offset = parse_hex(field(&mut line, "file offset")?, "file offset")?;
    let device = field(&mut line, "device")?;
    let inode = parse_decimal(field(&mut line, "inode")?, "inode")?;

    let (start, end) = split_once(range, b'-', "address range")?;
    let start = parse_hex(start, "mapping start")?;
    let end = parse_hex(end, "mapping end")?;
    if start >= end {
        return Err("mapping start must be less than end".into());
    }
    let (major, minor) = split_once(device, b':', "device")?;
    let device = Device {
        major: parse_hex(major, "device major")?,
        minor: parse_hex(minor, "device minor")?,
    };
    let raw_path = line.trim_ascii_start();

    Ok(MapEntry {
        start,
        end,
        file_offset,
        permissions,
        device,
        inode,
        raw_path: (!raw_path.is_empty()).then(|| raw_path.to_vec()),
    })
}

fn field<'a>(input: &mut &'a [u8], name: &str) -> Result<&'a [u8], String> {
    *input = input.trim_ascii_start();
    let end = input
        .iter()
        .position(|byte| byte.is_ascii_whitespace())
        .unwrap_or(input.len());
    if end == 0 {
        return Err(format!("missing {name}"));
    }
    let (value, rest) = input.split_at(end);
    *input = rest;
    Ok(value)
}

fn split_once<'a>(
    bytes: &'a [u8],
    delimiter: u8,
    name: &str,
) -> Result<(&'a [u8], &'a [u8]), String> {
    let mut parts = bytes.split(|byte| *byte == delimiter);
    let left = parts.next().unwrap_or_default();
    let right = parts.next().unwrap_or_default();
    if left.is_empty() || right.is_empty() || parts.next().is_some() {
        return Err(format!("invalid {name}"));
    }
    Ok((left, right))
}

fn parse_hex(bytes: &[u8], name: &str) -> Result<u64, String> {
    let value = std::str::from_utf8(bytes).map_err(|_| format!("invalid {name}"))?;
    u64::from_str_radix(value, 16).map_err(|_| format!("invalid {name}"))
}

fn parse_decimal(bytes: &[u8], name: &str) -> Result<u64, String> {
    let value = std::str::from_utf8(bytes).map_err(|_| format!("invalid {name}"))?;
    value.parse().map_err(|_| format!("invalid {name}"))
}
