//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile function-table decode regressions (observer-side memory decode):
//! truncated, extreme-valued and mutated table snapshots must decode to
//! `None` or to tables whose every entry survived validation — a null or a
//! file-backed executable address — with entry counts and names exactly
//! matching the walked layout. Untrusted version words never select an
//! unbounded walk, and hostile pointers never become attributed entries.

use super::{
    CaptureWorkBudget, ScannedTable, decode_exact_table, exact_table_addresses, exact_table_bytes,
};
use p11scope_manifest::maps::{MapIndex, parse_maps};
use pkcs11_module::LinuxLayout;

/// Fixed seeds for the mutation loops below; recorded so failures reproduce.
const LP64_SEED: u64 = 0xC2E1_F00D_0000_0009;
const ILP32_SEED: u64 = 0xC2E1_F00D_0000_000A;
const MUTATIONS: usize = 2000;

// The executable file mapping every attributed entry must resolve into.
const EXEC_DEVICE_MAJOR: u64 = 8;
const EXEC_DEVICE_MINOR: u64 = 1;
const EXEC_INODE: u64 = 7;
const EXEC_START: u64 = 0x1000;
const EXEC_END: u64 = 0x3000;
const EXEC_FILE_LEN: u64 = EXEC_END - EXEC_START;

fn fixture_maps() -> Vec<u8> {
    b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n\
      4000-5000 rw-p 00000000 08:01 7 /lib/provider.so\n\
      6000-7000 rw-p 00000000 00:00 0\n"
        .to_vec()
}

fn write_word(snapshot: &mut [u8], layout: LinuxLayout, ordinal: usize, value: u64) {
    let width = match layout {
        LinuxLayout::Lp64 => 8,
        LinuxLayout::Ilp32 => 4,
    };
    let offset = width + ordinal * width;
    match layout {
        LinuxLayout::Lp64 => snapshot[offset..offset + 8].copy_from_slice(&value.to_le_bytes()),
        LinuxLayout::Ilp32 => {
            snapshot[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes())
        }
    }
}

/// A valid 2.40 seed: one executable slot, every other slot NULL.
fn valid_seed(layout: LinuxLayout) -> Vec<u8> {
    let width = match layout {
        LinuxLayout::Lp64 => 8,
        LinuxLayout::Ilp32 => 4,
    };
    let mut snapshot = vec![0u8; width + 68 * width];
    snapshot[0] = 0x02;
    snapshot[1] = 0x28;
    write_word(&mut snapshot, layout, 0, 0x1500);
    snapshot
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Every decoded table must be internally exact: the walked slot count, one
/// entry or null per slot, distinct published names, and every entry inside
/// the executable file range it claims.
fn assert_table_consistent(table: &ScannedTable, _layout: LinuxLayout, context: &str) {
    let slots = table.entries.len() + table.null_entries.len();
    assert!(
        matches!(slots, 67 | 68 | 92 | 104),
        "{context}: unexpected slot count {slots}"
    );
    let mut names = std::collections::BTreeSet::new();
    for entry in &table.entries {
        assert!(
            names.insert(entry.name),
            "{context}: duplicate entry name {}",
            entry.name
        );
        assert_eq!(entry.object.device.major, EXEC_DEVICE_MAJOR, "{context}");
        assert_eq!(entry.object.device.minor, EXEC_DEVICE_MINOR, "{context}");
        assert_eq!(entry.object.inode, EXEC_INODE, "{context}");
        assert!(
            entry.file_offset < EXEC_FILE_LEN,
            "{context}: entry {} offset {:#x} outside the executable range",
            entry.name,
            entry.file_offset
        );
        assert_eq!(entry.object_path, "/lib/provider.so", "{context}");
    }
    for null in &table.null_entries {
        assert!(names.insert(null), "{context}: duplicate null name {null}");
    }
}

fn decode(
    snapshot: &[u8],
    address: u64,
    layout: LinuxLayout,
    maps: &MapIndex<'_>,
) -> Result<Option<ScannedTable>, ()> {
    decode_exact_table(
        snapshot,
        address,
        layout,
        maps,
        &mut CaptureWorkBudget::default(),
        None,
    )
}

#[test]
fn hostile_valid_seed_decodes_with_validated_entries() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let maps = parse_maps(&fixture_maps()).unwrap();
        let index = MapIndex::new(&maps).unwrap();
        let seed = valid_seed(layout);
        let width = if matches!(layout, LinuxLayout::Lp64) {
            8
        } else {
            4
        };
        assert_eq!(
            exact_table_bytes(&seed[..width], layout),
            Some(width + 68 * width),
            "{layout:?}: exact table size"
        );
        assert_eq!(
            exact_table_addresses(&seed, layout),
            Some(vec![0x1500]),
            "{layout:?}: exact table addresses"
        );
        let table = decode(&seed, 0x1000, layout, &index)
            .expect("budget must admit the seed")
            .expect("seed must decode");
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.null_entries.len(), 67);
        assert_table_consistent(&table, layout, &format!("{layout:?} seed"));
    }
}

#[test]
fn hostile_version_words_select_only_bounded_walks() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let width = if matches!(layout, LinuxLayout::Lp64) {
            8
        } else {
            4
        };
        for major in 0..=6u64 {
            for minor in [0u64, 1, 39, 40, 41, 254, 255] {
                for high in [0u64, 0x1_0000, !0xffff] {
                    let word = high | (minor << 8) | major;
                    let mut header = vec![0u8; width];
                    header[..width].copy_from_slice(&word.to_le_bytes()[..width]);
                    let bytes = exact_table_bytes(&header, layout);
                    if high == 0 && matches!(major, 2 | 3) {
                        let size =
                            bytes.unwrap_or_else(|| panic!("{layout:?} {word:#x} must walk"));
                        assert!(
                            [67, 68, 92, 104].contains(&((size - width) / width)),
                            "{layout:?} {word:#x}: unbounded walk size {size}"
                        );
                    } else {
                        assert_eq!(bytes, None, "{layout:?} {word:#x} must not walk");
                    }
                }
            }
        }
        // Unknown majors, padding words and all-set words refuse outright.
        for word in [0u64, u64::MAX, 0x0004, 0x0304, 0x1_2802] {
            let header = word.to_le_bytes();
            assert_eq!(
                exact_table_bytes(&header, LinuxLayout::Lp64),
                None,
                "{word:#x}"
            );
            assert_eq!(
                exact_table_bytes(&header[..4], LinuxLayout::Ilp32),
                None,
                "{word:#x}"
            );
        }
    }
}

#[test]
fn hostile_truncation_never_decodes_partial_tables() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let maps = parse_maps(&fixture_maps()).unwrap();
        let index = MapIndex::new(&maps).unwrap();
        let seed = valid_seed(layout);
        for len in 0..seed.len() {
            let head = &seed[..len];
            // The size probe answers from the header alone; the decoders
            // below must refuse every strict prefix.
            if exact_table_addresses(head, layout).is_some() {
                panic!("{layout:?}: truncated prefix {len} yielded addresses");
            }
            match decode(head, 0x1000, layout, &index) {
                Ok(None) => {}
                Ok(Some(table)) => panic!(
                    "{layout:?}: truncated prefix {len} decoded {} entries",
                    table.entries.len()
                ),
                Err(()) => panic!("{layout:?}: truncated prefix {len} charged the budget"),
            }
        }
        assert!(
            decode(&seed, 0x1000, layout, &index).unwrap().is_some(),
            "{layout:?}: complete seed must decode"
        );
    }
}

#[test]
fn hostile_pointers_never_become_unvalidated_entries() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let maps = parse_maps(&fixture_maps()).unwrap();
        let index = MapIndex::new(&maps).unwrap();
        let addresses: &[u64] = &[
            0,
            1,
            EXEC_START,
            EXEC_START + 1,
            EXEC_END - 1,
            EXEC_END,
            0x4000, // file-backed data: not executable
            0x4fff,
            0x5000,
            0x6000, // anonymous: not a file
            0x7000, // unmapped gap
            0xffff,
            0x1_0000,
            u64::MAX - 1,
            u64::MAX,
        ];
        for (slot, address) in addresses.iter().enumerate() {
            let ordinal = slot % 68;
            let mut snapshot = valid_seed(layout);
            // Ilp32 truncates the value like the target would.
            write_word(&mut snapshot, layout, ordinal, *address);
            match decode(&snapshot, 0x1000, layout, &index) {
                Ok(None) => {}
                Ok(Some(table)) => {
                    assert_table_consistent(
                        &table,
                        layout,
                        &format!("{layout:?} slot {ordinal} {address:#x}"),
                    );
                }
                Err(()) => panic!("{layout:?}: slot {ordinal} charged the budget"),
            }
        }
        // A table of nothing but hostile non-NULL slots never decodes.
        let mut snapshot = valid_seed(layout);
        for ordinal in 0..68 {
            write_word(&mut snapshot, layout, ordinal, 0xdeadbeef);
        }
        assert!(
            decode(&snapshot, 0x1000, layout, &index).unwrap().is_none(),
            "{layout:?}: all-hostile slots must not decode"
        );
        // A table of all NULLs is data, not a table.
        let mut snapshot = valid_seed(layout);
        for ordinal in 0..68 {
            write_word(&mut snapshot, layout, ordinal, 0);
        }
        assert!(
            decode(&snapshot, 0x1000, layout, &index).unwrap().is_none(),
            "{layout:?}: all-NULL slots must not decode"
        );
    }
}

#[test]
fn hostile_base_addresses_are_checked() {
    let maps = parse_maps(&fixture_maps()).unwrap();
    let index = MapIndex::new(&maps).unwrap();
    let seed = valid_seed(LinuxLayout::Lp64);
    // The base only anchors the in-snapshot cursor (offset 0 here, so no
    // base+length addition can overflow); whatever the base, decoding
    // yields nothing or a fully validated table.
    for base in [0u64, 0x5000, 0x8000, u64::MAX - seed.len() as u64, u64::MAX] {
        match decode(&seed, base, LinuxLayout::Lp64, &index) {
            Ok(None) => {}
            Ok(Some(table)) => {
                assert_table_consistent(&table, LinuxLayout::Lp64, &format!("base {base:#x}"))
            }
            Err(()) => panic!("base {base:#x} charged the budget"),
        }
    }
}

fn mutate_table(layout: LinuxLayout, seed_value: u64) {
    let maps = parse_maps(&fixture_maps()).unwrap();
    let index = MapIndex::new(&maps).unwrap();
    let seed = valid_seed(layout);
    let mut rng = seed_value;
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for iteration in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut candidate = seed.clone();
        for _ in 0..flips {
            let offset = (xorshift64(&mut rng) % candidate.len() as u64) as usize;
            candidate[offset] = (xorshift64(&mut rng) % 256) as u8;
        }
        // The base address mutates too: hostile tables live anywhere.
        let base = match xorshift64(&mut rng) % 4 {
            0 => 0x1000,
            1 => xorshift64(&mut rng) & 0xffff,
            2 => u64::MAX - (xorshift64(&mut rng) % 2048),
            _ => xorshift64(&mut rng),
        };
        match decode(&candidate, base, layout, &index) {
            Ok(None) => refused += 1,
            Ok(Some(table)) => {
                accepted += 1;
                assert_table_consistent(
                    &table,
                    layout,
                    &format!("{layout:?} mutation {iteration}"),
                );
            }
            Err(()) => panic!("{layout:?} mutation {iteration} charged the budget"),
        }
    }
    assert_eq!(refused + accepted, MUTATIONS);
    assert!(
        refused > accepted,
        "{layout:?}: mutations must usually break the table (refused {refused}, accepted {accepted})"
    );
}

#[test]
fn hostile_seeded_mutations_decode_only_validated_tables_lp64() {
    mutate_table(LinuxLayout::Lp64, LP64_SEED);
}

#[test]
fn hostile_seeded_mutations_decode_only_validated_tables_ilp32() {
    mutate_table(LinuxLayout::Ilp32, ILP32_SEED);
}
