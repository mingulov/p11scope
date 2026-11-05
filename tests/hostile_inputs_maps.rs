//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile `/proc/<pid>/maps` regression tests: malformed lines, extreme
//! addresses/offsets/devices/inodes and mutated snapshots must be refused
//! with a named error or yield only consistent entries. Untrusted hex and
//! decimal fields never overflow, and a malformed snapshot never resolves a
//! file attribution outside its own mappings.

use p11scope_manifest::maps::{
    Device, InvalidMapSnapshot, MapEntry, MapIndex, MappedPath, Resolved, executable_file_keys,
    mapped_path, parse_maps, resolve,
};
use std::path::PathBuf;

/// Fixed seeds for the mutation loops below; recorded so failures reproduce.
const MUTATION_SEED: u64 = 0xC2E1_F00D_0000_0002;
const MUTATIONS: usize = 2000;

fn seed() -> Vec<u8> {
    b"00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon\n\
      7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0\n\
      7ffc55555000-7ffc55576000 rw-p 00000000 00:00 0 [stack]\n\
      7f2b40000000-7f2b40021000 r-xp 00021000 08:01 999 /opt/with space/lib.so\n"
        .to_vec()
}

/// Every accepted entry must be consistent with the bytes it came from.
fn assert_entries_consistent(entries: &[MapEntry], input: &[u8], context: &str) {
    let lines = input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    assert_eq!(
        entries.len(),
        lines,
        "{context}: accepted {} entries from {lines} nonempty lines",
        entries.len()
    );
    for entry in entries {
        assert!(
            entry.start < entry.end,
            "{context}: inverted range {:#x}-{:#x}",
            entry.start,
            entry.end
        );
        if let Some(raw) = &entry.raw_path {
            assert!(
                input
                    .windows(raw.len())
                    .any(|window| window == raw.as_slice()),
                "{context}: path {raw:?} is not a substring of the input"
            );
        }
    }
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn valid_seed_parses_and_resolves() {
    let bytes = seed();
    let mut entries = parse_maps(&bytes).expect("seed must parse");
    assert_entries_consistent(&entries, &bytes, "seed");
    entries.sort_by_key(|entry| entry.start);
    let index = MapIndex::new(&entries).expect("sorted seed must index");
    match index.resolve(0x7f2b40000abc) {
        Resolved::File {
            path,
            file_offset,
            device,
            inode,
            ..
        } => {
            assert_eq!(
                path,
                MappedPath::Usable(PathBuf::from("/opt/with space/lib.so"))
            );
            assert_eq!(file_offset, 0x21abc);
            assert_eq!(device, Device { major: 8, minor: 1 });
            assert_eq!(inode, 999);
        }
        other => panic!("expected a file resolution, got {other:?}"),
    }
    assert_eq!(index.resolve(0x7f8a1c000500), Resolved::Anonymous);
    assert_eq!(index.resolve(0x1), Resolved::Unmapped);
    assert_eq!(index.resolve(0x0045_2000), Resolved::Unmapped);
    assert_eq!(executable_file_keys(&entries).len(), 2);
}

#[test]
fn truncation_at_every_byte_boundary_is_refused_or_consistent() {
    let bytes = seed();
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for len in 0..=bytes.len() {
        match parse_maps(&bytes[..len]) {
            Ok(entries) => {
                accepted += 1;
                assert_entries_consistent(&entries, &bytes[..len], &format!("prefix {len}"));
            }
            Err(error) => {
                refused += 1;
                assert!(error.contains("line"), "prefix {len}: {error}");
            }
        }
    }
    assert!(parse_maps(&bytes).is_ok(), "the complete seed must parse");
    assert!(refused > 0 && accepted > 0, "both outcomes must occur");
    assert_eq!(refused + accepted, bytes.len() + 1);
}

#[test]
fn address_and_offset_extremes_never_overflow() {
    // (range, offset, device, inode, expected outcome)
    let cases: &[(&str, &str, &str, &str, bool)] = &[
        ("0-1", "0", "00:00", "0", true),
        ("0-ffffffffffffffff", "0", "00:00", "0", true),
        (
            "fffffffffffffffe-ffffffffffffffff",
            "0",
            "ff:ff",
            "18446744073709551615",
            true,
        ),
        ("0-1000", "ffffffffffffffff", "08:01", "1", true),
        ("0-1000", "1ffffffffffffffff", "08:01", "1", false), // hex overflow
        ("1000-1000", "0", "00:00", "0", false),              // empty range
        ("2000-1000", "0", "00:00", "0", false),              // inverted range
        ("-1000", "0", "00:00", "0", false),                  // empty start
        ("1000-", "0", "00:00", "0", false),                  // empty end
        ("10-20-30", "0", "00:00", "0", false),               // doubled dash
        ("zz-1000", "0", "00:00", "0", false),
        ("0x10-0x20", "0", "00:00", "0", false), // 0x prefix is not hex
        ("+10-20", "0", "00:00", "0", true),     // from_str_radix accepts leading '+', value exact
        ("10 -20", "0", "00:00", "0", false),    // space splits the range field
        ("0-1000", "-1", "00:00", "0", false),
        ("0-1000", "0", "08:01", "18446744073709551616", false), // inode overflow
        ("0-1000", "0", "08:01", "-1", false),
        ("0-1000", "0", "08:01", "", false),
        ("0-1000", "0", "0801", "1", false),     // missing colon
        ("0-1000", "0", "08:01:02", "1", false), // doubled colon
        ("0-1000", "0", ":01", "1", false),
        ("0-1000", "0", "08:", "1", false),
        ("0-1000", "0", "ffffffffffffffffff:00", "1", false), // major overflow
        ("0-1000", "0", "00:ffffffffffffffffff", "1", false), // minor overflow
    ];
    for (range, offset, device, inode, valid) in cases {
        let line = format!("{range} r-xp {offset} {device} {inode} /lib/x.so\n");
        match parse_maps(line.as_bytes()) {
            Ok(entries) => {
                assert!(
                    *valid,
                    "line {line:?} must be refused, parsed as {entries:?}"
                );
                assert_entries_consistent(&entries, line.as_bytes(), &format!("line {line:?}"));
            }
            Err(error) => {
                assert!(!valid, "line {line:?} must parse, got {error}");
                assert!(
                    error.contains("line 1"),
                    "error must name the line: {error}"
                );
            }
        }
    }
    // The leading-'+' range decodes to its exact value.
    let entries = parse_maps(b"+10-20 r-xp 0 00:00 0 /lib/x.so\n").unwrap();
    assert_eq!((entries[0].start, entries[0].end), (16, 32));
    // The maximum accepted values decode exactly.
    let entries = parse_maps(
        b"fffffffffffffffe-ffffffffffffffff r-xp ffffffffffffffff ff:ff 18446744073709551615 /x\n",
    )
    .unwrap();
    assert_eq!(entries[0].start, u64::MAX - 1);
    assert_eq!(entries[0].end, u64::MAX);
    assert_eq!(entries[0].file_offset, u64::MAX);
    assert_eq!(entries[0].inode, u64::MAX);
}

#[test]
fn permission_and_shape_extremes_are_refused() {
    for perms in [
        "r-x", "r-xpp", "", "R-XP", "rwXp", "r-xs", "----", "rwxp", "r--s",
    ] {
        let line = format!("1000-2000 {perms} 00000000 08:01 1 /lib/x.so\n");
        let parsed = parse_maps(line.as_bytes());
        // The parser validates byte positions, not semantic
        // combinations: "r-xs", "r--s" and "rwxp" parse, every other
        // shape here is refused ("----" fails the fourth byte, which
        // real maps restrict to 'p' or 's').
        let well_formed = matches!(perms, "r-xs" | "r--s" | "rwxp");
        assert_eq!(
            parsed.is_ok(),
            well_formed,
            "permissions {perms:?}: {parsed:?}"
        );
    }
    for line in [
        "1000-2000 r-xp 00000000 08:01\n", // missing inode
        "1000-2000 r-xp 00000000\n",       // missing device+inode
        "1000-2000\n",                     // range only
        "   \n",                           // whitespace-only line
        "1000-2000 r-xp 00000000 08:01 1", // no trailing newline: valid
    ] {
        let parsed = parse_maps(line.as_bytes());
        let valid = !line.trim().is_empty() && line.split_ascii_whitespace().count() >= 5;
        assert_eq!(parsed.is_ok(), valid, "line {line:?}: {parsed:?}");
        if let Ok(entries) = parsed {
            assert_entries_consistent(&entries, line.as_bytes(), &format!("line {line:?}"));
        }
    }
    // A bad line anywhere poisons the snapshot and names its line number.
    let mut poisoned = seed();
    poisoned.extend_from_slice(b"bogus line here\n");
    let error = parse_maps(&poisoned).unwrap_err();
    assert!(error.contains("line 5"), "must name line 5: {error}");
}

#[test]
fn mapped_path_classification_is_exact() {
    for (raw, usable, reason) in [
        (b"/lib/x.so".as_slice(), true, ""),
        (b"/opt/with space/lib.so".as_slice(), true, ""),
        (b"[stack]".as_slice(), true, ""),
        (b"".as_slice(), true, ""),
        (b"/tmp/\x01\x02control".as_slice(), true, ""),
        (b"/tmp/nonutf8-\xff.so".as_slice(), false, "non-UTF-8"),
        (b"/tmp/gone.so (deleted)".as_slice(), false, "deleted"),
        (b"/tmp/gone.so(deleted)".as_slice(), true, ""), // suffix needs the space
        (b"/tmp/x.so (deleted) ".as_slice(), true, ""),  // suffix must be trailing
        (b"/tmp/lit\\012eral.so".as_slice(), false, "\\012"),
        (b"/tmp/ends\\012".as_slice(), false, "\\012"),
    ] {
        match mapped_path(raw) {
            MappedPath::Usable(path) => {
                assert!(usable, "{raw:?} must be unusable");
                assert_eq!(path.into_os_string().as_encoded_bytes(), raw);
            }
            MappedPath::Unusable { reason: got } => {
                assert!(!usable, "{raw:?} must be usable");
                assert!(got.contains(reason), "{raw:?}: reason {got:?}");
            }
        }
    }
    // An oversize path stays bounded by the input: usable, length preserved.
    let huge = vec![b'a'; 1024 * 1024];
    match mapped_path(&huge) {
        MappedPath::Usable(path) => assert_eq!(path.into_os_string().len(), huge.len()),
        MappedPath::Unusable { reason } => panic!("oversize ASCII path refused: {reason}"),
    }
}

fn entry(start: u64, end: u64, file_offset: u64, raw_path: Option<&[u8]>) -> MapEntry {
    MapEntry {
        start,
        end,
        file_offset,
        permissions: *b"r-xp",
        device: Device { major: 8, minor: 1 },
        inode: 7,
        raw_path: raw_path.map(|path| path.to_vec()),
    }
}

#[test]
fn map_index_rejects_unsorted_overlapping_and_overflowing() {
    let good = vec![
        entry(0x1000, 0x2000, 0, Some(b"/lib/a.so")),
        entry(0x2000, 0x3000, 0x1000, Some(b"/lib/a.so")),
        entry(0x4000, 0x5000, 0, None),
    ];
    assert!(MapIndex::new(&good).is_ok(), "adjacent ranges are valid");
    assert!(MapIndex::new(&[]).is_ok(), "empty snapshot is valid");

    let mut swapped = good.clone();
    swapped.swap(0, 1);
    assert!(
        matches!(
            MapIndex::new(&swapped),
            Err(InvalidMapSnapshot::UnsortedOrOverlapping { left: 0, right: 1 })
        ),
        "swapped entries must be refused as unsorted"
    );
    let overlapping = vec![
        entry(0x1000, 0x3000, 0, Some(b"/lib/a.so")),
        entry(0x2000, 0x4000, 0, Some(b"/lib/a.so")),
    ];
    assert!(matches!(
        MapIndex::new(&overlapping),
        Err(InvalidMapSnapshot::UnsortedOrOverlapping { .. })
    ));
    for (start, end) in [(0x1000, 0x1000), (0x2000, 0x1000)] {
        assert!(
            matches!(
                MapIndex::new(&[entry(start, end, 0, Some(b"/lib/a.so"))]),
                Err(InvalidMapSnapshot::InvalidRange { index: 0 })
            ),
            "range {start:#x}-{end:#x} must be refused"
        );
    }
    // A file-backed mapping whose offset+length overflows is refused; the
    // same arithmetic on an anonymous mapping is unreachable and accepted.
    assert!(
        matches!(
            MapIndex::new(&[entry(0x1000, 0x1002, u64::MAX, Some(b"/lib/a.so"))]),
            Err(InvalidMapSnapshot::FileOffsetOverflow { index: 0 })
        ),
        "file-offset overflow must be refused"
    );
    assert!(
        MapIndex::new(&[entry(0x1000, 0x1002, u64::MAX, None)]).is_ok(),
        "anonymous overflow is unreachable"
    );
    assert!(
        MapIndex::new(&[entry(0x1000, 0x1002, u64::MAX, Some(b"[stack]"))]).is_ok(),
        "pseudo-path overflow is unreachable"
    );
    // The maximum representable file offset is accepted and resolves exactly.
    let edge = vec![entry(0x1000, 0x2000, u64::MAX - 0xfff, Some(b"/lib/a.so"))];
    let index = MapIndex::new(&edge).expect("edge offset must index");
    match index.resolve(0x1fff) {
        Resolved::File { file_offset, .. } => assert_eq!(file_offset, u64::MAX),
        other => panic!("expected file resolution, got {other:?}"),
    }
}

#[test]
fn resolve_never_attributes_outside_the_mapping() {
    let entries = vec![
        entry(0x1000, 0x2000, 0x5000, Some(b"/lib/a.so")),
        entry(0x3000, 0x4000, 0, None),
    ];
    let index = MapIndex::new(&entries).unwrap();
    for vaddr in [
        0u64,
        0xfff,
        0x1000,
        0x1500,
        0x1fff,
        0x2000,
        0x2500,
        0x3000,
        0x3fff,
        0x4000,
        u64::MAX,
    ] {
        match index.resolve(vaddr) {
            Resolved::File {
                file_offset,
                raw_path,
                ..
            } => {
                assert_eq!(raw_path, b"/lib/a.so");
                assert!(
                    (0x5000..0x6000).contains(&file_offset),
                    "vaddr {vaddr:#x} resolved outside the mapping: {file_offset:#x}"
                );
                assert_eq!(file_offset, 0x5000 + (vaddr - 0x1000));
            }
            Resolved::Anonymous => assert!((0x3000..0x4000).contains(&vaddr), "vaddr {vaddr:#x}"),
            Resolved::Unmapped => assert!(
                !(0x1000..0x2000).contains(&vaddr) && !(0x3000..0x4000).contains(&vaddr),
                "vaddr {vaddr:#x} wrongly unmapped"
            ),
        }
        // The one-shot helper agrees with the index exactly.
        assert_eq!(resolve(&entries, vaddr), Ok(index.resolve(vaddr)));
    }
}

#[test]
fn seeded_mutations_are_refused_or_consistent() {
    let bytes = seed();
    let mut rng = MUTATION_SEED;
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for iteration in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut candidate = bytes.clone();
        for _ in 0..flips {
            let offset = (xorshift64(&mut rng) % candidate.len() as u64) as usize;
            candidate[offset] = (xorshift64(&mut rng) % 256) as u8;
        }
        match parse_maps(&candidate) {
            Ok(entries) => {
                accepted += 1;
                assert_entries_consistent(&entries, &candidate, &format!("mutation {iteration}"));
                let mut sorted = entries.clone();
                sorted.sort_by_key(|entry| entry.start);
                if let Ok(index) = MapIndex::new(&sorted) {
                    for _ in 0..4 {
                        let vaddr = xorshift64(&mut rng);
                        if let Resolved::File { file_offset, .. } = index.resolve(vaddr) {
                            let containing =
                                index.containing(vaddr).expect("file implies containing");
                            assert!(
                                file_offset >= containing.file_offset
                                    && file_offset
                                        < containing.file_offset
                                            + (containing.end - containing.start),
                                "mutation {iteration}: vaddr {vaddr:#x} outside its mapping"
                            );
                        }
                    }
                }
            }
            Err(error) => {
                refused += 1;
                assert!(error.contains("line"), "mutation {iteration}: {error}");
            }
        }
    }
    assert_eq!(refused + accepted, MUTATIONS);
    assert!(
        refused > accepted,
        "mutations must usually break the snapshot (refused {refused}, accepted {accepted})"
    );
}

#[test]
fn executable_keys_stay_bounded_on_large_snapshots() {
    let mut snapshot = Vec::new();
    for i in 0u64..10_000 {
        let start = 0x1000_0000 + i * 0x2000;
        snapshot.extend_from_slice(
            format!(
                "{start:x}-{end:x} r-xp 00000000 08:01 {ino} /lib/dup.so\n",
                end = start + 0x1000,
                ino = (i % 97) + 1
            )
            .as_bytes(),
        );
    }
    let entries = parse_maps(&snapshot).expect("large snapshot must parse");
    assert_eq!(entries.len(), 10_000);
    let keys = executable_file_keys(&entries);
    assert_eq!(keys.len(), 97, "duplicate inodes must collapse");
    // Anonymous, non-executable and inode-zero mappings contribute no keys.
    let entries = parse_maps(b"1000-2000 rw-p 00000000 08:01 7 /lib/x.so\n2000-3000 r--p 00000000 08:01 8 /lib/y.so\n3000-4000 r-xp 00000000 08:01 0 /lib/z.so\n").unwrap();
    assert!(executable_file_keys(&entries).is_empty());
}
