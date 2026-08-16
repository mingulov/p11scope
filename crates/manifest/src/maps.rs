//! Strict lexical facts from Linux `/proc/<pid>/maps`.

use crate::identity::MappingFileKey;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Device {
    pub major: u64,
    pub minor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectKey {
    pub device: Device,
    pub inode: u64,
}

impl ObjectKey {
    pub fn of(entry: &MapEntry) -> Self {
        Self {
            device: entry.device,
            inode: entry.inode,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedPath {
    Usable(PathBuf),
    Unusable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    File {
        path: MappedPath,
        raw_path: Vec<u8>,
        file_offset: u64,
        device: Device,
        inode: u64,
        permissions: [u8; 4],
    },
    Anonymous,
    Unmapped,
}

fn mapped_path(raw: &[u8]) -> MappedPath {
    let unusable = if raw.windows(4).any(|window| window == b"\\012") {
        Some("ambiguous \\012 pathname")
    } else if raw.ends_with(b" (deleted)") {
        Some("deleted mapping")
    } else {
        None
    };
    if let Some(reason) = unusable {
        return MappedPath::Unusable {
            reason: reason.into(),
        };
    }
    match std::str::from_utf8(raw) {
        Ok(path) => MappedPath::Usable(PathBuf::from(path)),
        Err(_) => MappedPath::Unusable {
            reason: "non-UTF-8 pathname".into(),
        },
    }
}

pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved {
    match maps.iter().find(|m| m.start <= vaddr && vaddr < m.end) {
        None => Resolved::Unmapped,
        Some(m) => match &m.raw_path {
            Some(raw_path) if raw_path.starts_with(b"/") => {
                let Some(file_offset) = m.file_offset.checked_add(vaddr - m.start) else {
                    return Resolved::Unmapped;
                };
                Resolved::File {
                    path: mapped_path(raw_path),
                    raw_path: raw_path.clone(),
                    file_offset,
                    device: m.device,
                    inode: m.inode,
                    permissions: m.permissions,
                }
            }
            _ => Resolved::Anonymous,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = b"\
00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0
7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]
7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so
7f2b50000000-7f2b50001000 r--p 00002000 08:01 998 /usr/lib/gone.so (deleted)
";

    #[test]
    fn parses_entries_and_preserves_path_bytes() {
        let m = parse_maps(FIXTURE).unwrap();
        assert_eq!(m.len(), 5);
        assert_eq!(m[0].start, 0x400000);
        assert_eq!(m[0].end, 0x452000);
        assert_eq!(m[0].file_offset, 0);
        assert_eq!(m[0].permissions, *b"r-xp");
        assert_eq!(m[0].device, Device { major: 8, minor: 2 });
        assert_eq!(m[0].inode, 173521);
        assert_eq!(
            m[0].raw_path.as_deref(),
            Some(b"/usr/bin/dbus-daemon".as_slice())
        );
        // Path with spaces survives; pseudo-paths and anonymous become None.
        assert_eq!(
            m[3].raw_path.as_deref(),
            Some(b"/opt/with space/lib.so".as_slice())
        );
        assert_eq!(m[1].raw_path, None);
        assert_eq!(m[2].raw_path.as_deref(), Some(b"[stack]".as_slice()));
        // Deleted-file suffix preserved verbatim — honest evidence.
        assert_eq!(
            m[4].raw_path.as_deref(),
            Some(b"/usr/lib/gone.so (deleted)".as_slice())
        );
    }

    #[test]
    fn resolves_with_segment_offset_arithmetic() {
        let m = parse_maps(FIXTURE).unwrap();
        assert_eq!(
            resolve(&m, 0x7f2b40000abc),
            Resolved::File {
                path: MappedPath::Usable(PathBuf::from("/opt/with space/lib.so")),
                raw_path: b"/opt/with space/lib.so".to_vec(),
                file_offset: 0x21abc,
                device: Device { major: 8, minor: 1 },
                inode: 999,
                permissions: *b"r-xp",
            }
        );
        assert_eq!(
            resolve(&m, 0x400010),
            Resolved::File {
                path: MappedPath::Usable(PathBuf::from("/usr/bin/dbus-daemon")),
                raw_path: b"/usr/bin/dbus-daemon".to_vec(),
                file_offset: 0x10,
                device: Device { major: 8, minor: 2 },
                inode: 173521,
                permissions: *b"r-xp",
            }
        );
    }

    #[test]
    fn classifies_anonymous_and_unmapped() {
        let m = parse_maps(FIXTURE).unwrap();
        assert_eq!(resolve(&m, 0x7f8a1c000500), Resolved::Anonymous);
        assert_eq!(resolve(&m, 0x7ffc55555100), Resolved::Anonymous); // [stack]
        assert_eq!(resolve(&m, 0x1), Resolved::Unmapped);
        assert_eq!(resolve(&m, 0x00452000), Resolved::Unmapped); // end is exclusive
    }

    #[test]
    fn unusable_file_paths_remain_file_evidence() {
        let input = b"\
1000-2000 r-xp 0000 08:01 1 /tmp/nonutf8-\xff.so
2000-3000 r-xp 0000 08:01 2 /tmp/literal\\012name.so
3000-4000 r-xp 0000 08:01 3 /tmp/gone.so (deleted)
";
        let maps = parse_maps(input).unwrap();
        for (addr, expected) in [
            (0x1000, "non-UTF-8"),
            (0x2000, "ambiguous \\012"),
            (0x3000, "deleted"),
        ] {
            let Resolved::File {
                path: MappedPath::Unusable { reason },
                ..
            } = resolve(&maps, addr)
            else {
                panic!("address {addr:#x} was not preserved as unusable file evidence");
            };
            assert!(reason.contains(expected), "{reason:?}");
        }
    }

    #[test]
    fn malformed_nonempty_line_is_rejected() {
        let error = parse_maps(b"not a maps line\n").unwrap_err();
        assert!(error.contains("line 1"), "{error}");
    }
}
