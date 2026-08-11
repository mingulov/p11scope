//! /proc/<pid>/maps parsing and vaddr → ELF-file-offset resolution.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    /// `None` for anonymous mappings and `[heap]`-style pseudo-paths.
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    File { path: PathBuf, file_offset: u64 },
    Anonymous,
    Unmapped,
}

/// Parse /proc/<pid>/maps text. Unparseable lines are skipped — discovery
/// degrades to "unmapped" evidence rather than aborting.
pub fn parse_maps(text: &str) -> Vec<MapEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MapEntry> {
    // <start>-<end> <perms> <offset> <dev> <inode> [path with possible spaces]
    let mut it = line.splitn(6, ' ');
    let range = it.next()?;
    let _perms = it.next()?;
    let offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let path = it.next().map(str::trim).filter(|p| !p.is_empty());

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let file_offset = u64::from_str_radix(offset, 16).ok()?;
    // Only absolute paths are file-backed; `[stack]` etc. count as anonymous.
    let path = path.filter(|p| p.starts_with('/')).map(PathBuf::from);
    Some(MapEntry { start, end, file_offset, path })
}

pub fn resolve(maps: &[MapEntry], vaddr: u64) -> Resolved {
    match maps.iter().find(|m| m.start <= vaddr && vaddr < m.end) {
        None => Resolved::Unmapped,
        Some(m) => match &m.path {
            None => Resolved::Anonymous,
            Some(p) => Resolved::File {
                path: p.clone(),
                file_offset: m.file_offset + (vaddr - m.start),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0
7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]
7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so
7f2b50000000-7f2b50001000 r--p 00002000 08:01 998 /usr/lib/gone.so (deleted)
not a maps line
";

    #[test]
    fn parses_entries_and_skips_garbage() {
        let m = parse_maps(FIXTURE);
        assert_eq!(m.len(), 5);
        assert_eq!(m[0].start, 0x400000);
        assert_eq!(m[0].end, 0x452000);
        assert_eq!(m[0].file_offset, 0);
        assert_eq!(m[0].path, Some(PathBuf::from("/usr/bin/dbus-daemon")));
        // Path with spaces survives; pseudo-paths and anonymous become None.
        assert_eq!(m[3].path, Some(PathBuf::from("/opt/with space/lib.so")));
        assert_eq!(m[1].path, None);
        assert_eq!(m[2].path, None);
        // Deleted-file suffix preserved verbatim — honest evidence.
        assert_eq!(m[4].path, Some(PathBuf::from("/usr/lib/gone.so (deleted)")));
    }

    #[test]
    fn resolves_with_segment_offset_arithmetic() {
        let m = parse_maps(FIXTURE);
        assert_eq!(
            resolve(&m, 0x7f2b40000abc),
            Resolved::File { path: PathBuf::from("/opt/with space/lib.so"), file_offset: 0x21abc }
        );
        assert_eq!(
            resolve(&m, 0x400010),
            Resolved::File { path: PathBuf::from("/usr/bin/dbus-daemon"), file_offset: 0x10 }
        );
    }

    #[test]
    fn classifies_anonymous_and_unmapped() {
        let m = parse_maps(FIXTURE);
        assert_eq!(resolve(&m, 0x7f8a1c000500), Resolved::Anonymous);
        assert_eq!(resolve(&m, 0x7ffc55555100), Resolved::Anonymous); // [stack]
        assert_eq!(resolve(&m, 0x1), Resolved::Unmapped);
        assert_eq!(resolve(&m, 0x00452000), Resolved::Unmapped); // end is exclusive
    }
}
