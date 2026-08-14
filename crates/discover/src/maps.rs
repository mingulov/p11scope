//! /proc/<pid>/maps parsing and vaddr → ELF-file-offset resolution.

pub use p11scope_manifest::maps::{Device, MapEntry, parse_maps};
use std::path::PathBuf;

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
