//! SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile ELF regression tests: truncated, extreme-valued and mutated object
//! bytes must be refused with a bounded error or yield only in-range facts.
//! Untrusted header/table lengths, counts and offsets never drive unbounded
//! allocation or reads, and a malformed image never yields attributed symbols
//! outside its own bytes.

use p11scope_manifest::elf::{
    ElfAbi, ElfSnapshot, classified_object, entry_file_offset, exports_matching, read_export_facts,
    read_export_facts_bounded, symbol_file_offset,
};
use std::path::PathBuf;
use std::process::Command;

const ANSWER: &str = "hostile_answer";
/// Fixed seed for the mutation loop below; recorded so a failure reproduces.
const MUTATION_SEED: u64 = 0xC2E1_F00D_0000_0001;
const MUTATIONS: usize = 2000;

fn workdir(name: &str) -> PathBuf {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_TMPDIR").expect("TMPDIR or CARGO_TARGET_TMPDIR")
    });
    let dir = PathBuf::from(base).join(format!("hostile-elf-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_seed(dir: &std::path::Path) -> Vec<u8> {
    let src = dir.join("seed.c");
    std::fs::write(
        &src,
        "int hostile_answer(void){return 42;}\nint hostile_other(void){return 7;}\n",
    )
    .unwrap();
    let so = dir.join("seed.so");
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-O2", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    std::fs::read(&so).unwrap()
}

fn snapshot_of(dir: &std::path::Path, bytes: &[u8]) -> Result<ElfSnapshot, String> {
    let path = dir.join("candidate.so");
    std::fs::write(&path, bytes).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    ElfSnapshot::read(&file)
}

fn open_of(dir: &std::path::Path, bytes: &[u8]) -> std::fs::File {
    let path = dir.join("candidate.so");
    std::fs::write(&path, bytes).unwrap();
    std::fs::File::open(&path).unwrap()
}

/// Every fact attributed to `bytes` must lie inside them.
fn assert_facts_in_range(snapshot: &ElfSnapshot, bytes: &[u8], context: &str) {
    let len = bytes.len() as u64;
    assert!(
        !snapshot.is_executable_offset(len),
        "{context}: file length {len} must not be an executable offset"
    );
    for name in [ANSWER, "hostile_other", "definitely_absent_symbol"] {
        if let Ok(Some(fact)) = snapshot.defined_symbol(name) {
            assert!(
                fact.file_offset < len,
                "{context}: symbol {name:?} offset {} outside {len} bytes",
                fact.file_offset
            );
        }
    }
    if let Ok(exports) = snapshot.exports_matching(&[ANSWER, "hostile_other"]) {
        for (name, offset) in &exports {
            assert!(
                *offset < len,
                "{context}: export {name:?} offset {offset} outside {len} bytes"
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
fn valid_seed_parses_with_in_range_attribution() {
    let dir = workdir("baseline");
    let seed = build_seed(&dir);
    let (object, abi) = classified_object(&seed).expect("gcc seed must classify");
    assert_eq!(abi, ElfAbi::Lp64);
    drop(object);
    let snapshot = snapshot_of(&dir, &seed).expect("gcc seed must snapshot");
    assert_eq!(snapshot.abi(), ElfAbi::Lp64);
    let fact = snapshot
        .defined_symbol(ANSWER)
        .expect("symbol query must not fail")
        .expect("seed must define the answer symbol");
    assert!(fact.file_offset < seed.len() as u64);
    assert_facts_in_range(&snapshot, &seed, "baseline");
    let file = open_of(&dir, &seed);
    let (facts_abi, exports, charged) =
        read_export_facts(&file, &[ANSWER, "hostile_other"]).expect("export facts must read");
    assert_eq!(facts_abi, ElfAbi::Lp64);
    assert!(exports.iter().any(|(name, _)| name == ANSWER));
    assert!(
        charged <= seed.len() as u64,
        "charged {charged} exceeds mapped {}",
        seed.len()
    );
    assert_eq!(
        exports,
        snapshot
            .exports_matching(&[ANSWER, "hostile_other"])
            .expect("snapshot exports must read"),
        "mmap facts and snapshot facts must agree"
    );
    let file = open_of(&dir, &seed);
    assert!(symbol_file_offset(&file, ANSWER).unwrap().is_some());
    let file = open_of(&dir, &seed);
    assert_eq!(exports_matching(&file, &[ANSWER]).unwrap().len(), 1);
    let file = open_of(&dir, &seed);
    let _ = entry_file_offset(&file).unwrap();
}

#[test]
fn truncation_at_every_byte_boundary_is_refused_or_valid() {
    let dir = workdir("trunc");
    let seed = build_seed(&dir);
    assert!(seed.len() > 64, "seed must exceed one ELF header");
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for len in 0..=seed.len() {
        let head = &seed[..len];
        match classified_object(head) {
            Ok((_, abi)) => match snapshot_of(&dir, head) {
                Ok(snapshot) => {
                    accepted += 1;
                    assert_eq!(abi, ElfAbi::Lp64, "truncated image at {len} changed ABI");
                    assert_facts_in_range(&snapshot, head, &format!("truncation {len}"));
                }
                // The snapshot's own range checks may refuse where the
                // classifier passed; both are bounded refusals.
                Err(_) => refused += 1,
            },
            Err(_) => refused += 1,
        }
        if len < 64 {
            assert!(
                classified_object(head).is_err(),
                "a prefix shorter than the ELF header ({len} bytes) must not parse"
            );
        }
    }
    assert!(
        classified_object(&seed).is_ok(),
        "the complete seed must parse"
    );
    assert!(refused > 0 && accepted > 0, "both outcomes must occur");
    assert_eq!(refused + accepted, seed.len() + 1);
}

#[test]
fn corrupt_magic_class_and_machine_are_named_refusals() {
    let dir = workdir("magic");
    let seed = build_seed(&dir);
    for (offset, width, value, label) in [
        (0usize, 1usize, 0x7eu64, "magic byte 0"),
        (1, 1, b'X' as u64, "magic byte 1"),
        (4, 1, 0u64, "EI_CLASS none"),
        (4, 1, 1u64, "EI_CLASS 32 with x86-64 machine"),
        (4, 1, 3u64, "EI_CLASS bogus"),
        (5, 1, 2u64, "EI_DATA big-endian"),
        (5, 1, 0u64, "EI_DATA none"),
        (18, 2, 0u64, "e_machine none"),
        (18, 2, 40u64, "e_machine foreign (ARM)"),
        (18, 2, 3u64, "e_machine i386 with 64-bit class"),
    ] {
        let mut bytes = seed.clone();
        for i in 0..width {
            bytes[offset + i] = ((value >> (8 * i)) & 0xff) as u8;
        }
        let error = classified_object(&bytes).unwrap_err();
        assert!(
            error.contains("ELF") || error.contains("endian") || error.contains("conventional"),
            "{label} refused without a named reason: {error}"
        );
    }
}

#[test]
fn header_offset_and_count_extremes_are_bounded() {
    let dir = workdir("header");
    let seed = build_seed(&dir);
    // (offset, width, label); every extreme must return, never hang or abort.
    let fields: &[(usize, usize, &str)] = &[
        (24, 8, "e_entry"),
        (32, 8, "e_phoff"),
        (40, 8, "e_shoff"),
        (52, 2, "e_ehsize"),
        (54, 2, "e_phentsize"),
        (56, 2, "e_phnum"),
        (58, 2, "e_shentsize"),
        (60, 2, "e_shnum"),
        (62, 2, "e_shstrndx"),
    ];
    let extremes: &[u64] = &[
        0,
        1,
        0xffff,
        0x1_0000,
        u32::MAX as u64,
        u64::MAX - 1,
        u64::MAX,
    ];
    let file_len = seed.len() as u64;
    for (offset, width, label) in fields {
        for extreme in extremes {
            let mut bytes = seed.clone();
            for i in 0..*width {
                bytes[offset + i] = ((extreme >> (8 * i)) & 0xff) as u8;
            }
            if classified_object(&bytes).is_ok()
                && let Ok(snapshot) = snapshot_of(&dir, &bytes)
            {
                assert_facts_in_range(&snapshot, &bytes, &format!("{label}={extreme:#x}"));
                let file = open_of(&dir, &bytes);
                if let Ok((_, exports, charged)) = read_export_facts(&file, &[ANSWER]) {
                    assert!(charged <= file_len, "{label}={extreme:#x} overcharged");
                    for (_, offset) in &exports {
                        assert!(*offset < file_len, "{label}={extreme:#x} out of range");
                    }
                }
            }
        }
    }
}

fn patch_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> usize {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn program_header_offset_length_overflow_is_refused_or_in_range() {
    let dir = workdir("phdr");
    let seed = build_seed(&dir);
    let phoff = read_u64(&seed, 32) as usize;
    let phentsize = read_u16(&seed, 54);
    let phnum = read_u16(&seed, 56);
    assert!(phnum > 0 && phentsize == 56, "seed must carry 64-bit phdrs");
    let file_len = seed.len() as u64;
    let extremes: &[u64] = &[
        0,
        1,
        file_len - 1,
        file_len,
        file_len + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut cases = 0usize;
    for index in 0..phnum {
        let base = phoff + index * phentsize;
        for (field, label) in [(8usize, "p_offset"), (32, "p_filesz"), (40, "p_memsz")] {
            for extreme in extremes {
                let mut bytes = seed.clone();
                patch_u64(&mut bytes, base + field, *extreme);
                cases += 1;
                if classified_object(&bytes).is_ok()
                    && let Ok(snapshot) = snapshot_of(&dir, &bytes)
                {
                    assert_facts_in_range(
                        &snapshot,
                        &bytes,
                        &format!("phdr{index} {label}={extreme:#x}"),
                    );
                }
            }
        }
        // Offset+length pairs that overflow u64 or straddle EOF.
        for (offset, filesz) in [
            (u64::MAX, 1u64),
            (u64::MAX, u64::MAX),
            (file_len - 1, 2),
            (file_len, file_len),
        ] {
            let mut bytes = seed.clone();
            patch_u64(&mut bytes, base + 8, offset);
            patch_u64(&mut bytes, base + 32, filesz);
            cases += 1;
            if classified_object(&bytes).is_ok()
                && let Ok(snapshot) = snapshot_of(&dir, &bytes)
            {
                assert_facts_in_range(
                    &snapshot,
                    &bytes,
                    &format!("phdr{index} offset={offset:#x} filesz={filesz:#x}"),
                );
            }
        }
    }
    assert!(cases > 0);
}

#[test]
fn section_header_offset_length_overflow_is_refused_or_in_range() {
    let dir = workdir("shdr");
    let seed = build_seed(&dir);
    let shoff = read_u64(&seed, 40) as usize;
    let shentsize = read_u16(&seed, 58);
    let shnum = read_u16(&seed, 60);
    assert!(shnum > 0 && shentsize == 64, "seed must carry 64-bit shdrs");
    let file_len = seed.len() as u64;
    let extremes: &[u64] = &[
        0,
        1,
        file_len - 1,
        file_len,
        file_len + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut cases = 0usize;
    for index in 0..shnum {
        let base = shoff + index * shentsize;
        for (field, label) in [(16usize, "sh_addr"), (24, "sh_offset"), (32, "sh_size")] {
            for extreme in extremes {
                let mut bytes = seed.clone();
                patch_u64(&mut bytes, base + field, *extreme);
                cases += 1;
                if classified_object(&bytes).is_ok()
                    && let Ok(snapshot) = snapshot_of(&dir, &bytes)
                {
                    assert_facts_in_range(
                        &snapshot,
                        &bytes,
                        &format!("shdr{index} {label}={extreme:#x}"),
                    );
                }
            }
        }
        let mut bytes = seed.clone();
        patch_u64(&mut bytes, base + 24, u64::MAX);
        patch_u64(&mut bytes, base + 32, u64::MAX);
        cases += 1;
        if classified_object(&bytes).is_ok()
            && let Ok(snapshot) = snapshot_of(&dir, &bytes)
        {
            assert_facts_in_range(
                &snapshot,
                &bytes,
                &format!("shdr{index} offset+size overflow"),
            );
        }
    }
    assert!(cases > 0);
}

/// Dynamic-table count claims (hash chains, string size) must not drive
/// proportional work: the query returns with an error or in-range facts.
#[test]
fn dynamic_table_count_extremes_stay_bounded() {
    let dir = workdir("dynamic");
    let seed = build_seed(&dir);
    let file_len = seed.len() as u64;
    // Locate PT_DYNAMIC and read its file range.
    let phoff = read_u64(&seed, 32) as usize;
    let phentsize = read_u16(&seed, 54);
    let phnum = read_u16(&seed, 56);
    let mut dynamic = None;
    for index in 0..phnum {
        let base = phoff + index * phentsize;
        if u32::from_le_bytes(seed[base..base + 4].try_into().unwrap()) == 2 {
            let offset = read_u64(&seed, base + 8);
            let filesz = read_u64(&seed, base + 32);
            dynamic = Some((offset as usize, filesz as usize));
            break;
        }
    }
    let Some((dyn_off, dyn_len)) = dynamic else {
        panic!("seed must carry PT_DYNAMIC");
    };
    // Collect dynamic entries: (file offset of d_val, tag).
    let mut entries = Vec::new();
    let mut at = dyn_off;
    while at + 16 <= dyn_off + dyn_len && at + 16 <= seed.len() {
        let tag = i64::from_le_bytes(seed[at..at + 8].try_into().unwrap());
        entries.push((at + 8, tag));
        if tag == 0 {
            break;
        }
        at += 16;
    }
    assert!(!entries.is_empty(), "dynamic table must be non-empty");
    let mut cases = 0usize;
    for (val_off, tag) in &entries {
        for extreme in [0u64, 1, u64::MAX - 1, u64::MAX] {
            let mut bytes = seed.clone();
            patch_u64(&mut bytes, *val_off, extreme);
            cases += 1;
            if classified_object(&bytes).is_ok() {
                if let Ok(snapshot) = snapshot_of(&dir, &bytes) {
                    assert_facts_in_range(
                        &snapshot,
                        &bytes,
                        &format!("dynamic tag {tag} value={extreme:#x}"),
                    );
                }
                let file = open_of(&dir, &bytes);
                if let Ok((_, exports, charged)) = read_export_facts(&file, &[ANSWER]) {
                    assert!(charged <= file_len, "dynamic tag {tag} overcharged");
                    for (_, offset) in &exports {
                        assert!(*offset < file_len, "dynamic tag {tag} out of range");
                    }
                }
            }
        }
    }
    assert!(cases > 0);
}

#[test]
fn seeded_byte_mutations_never_panic_or_over_attribute() {
    let dir = workdir("mutate");
    let seed = build_seed(&dir);
    let mut rng = MUTATION_SEED;
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for iteration in 0..MUTATIONS {
        let flips = 1 + (xorshift64(&mut rng) % 8) as usize;
        let mut bytes = seed.clone();
        for _ in 0..flips {
            // Half the flips land in the ELF header and first page, where a
            // hostile author would place them; the rest land anywhere.
            let offset = if xorshift64(&mut rng).is_multiple_of(2) {
                (xorshift64(&mut rng) % 4096.min(seed.len() as u64)) as usize
            } else {
                (xorshift64(&mut rng) % seed.len() as u64) as usize
            };
            let byte = (xorshift64(&mut rng) % 256) as u8;
            bytes[offset] = byte;
        }
        // The classifier is intentionally lenient (header basics
        // only); the snapshot is the strict oracle, so the verdict
        // split is counted at the snapshot level.
        match classified_object(&bytes) {
            Ok(_) => match snapshot_of(&dir, &bytes) {
                Ok(snapshot) => {
                    accepted += 1;
                    assert_facts_in_range(&snapshot, &bytes, &format!("mutation {iteration}"));
                }
                // The snapshot's own range checks refuse where the
                // classifier passed; both are bounded refusals.
                Err(_) => refused += 1,
            },
            Err(_) => refused += 1,
        }
        // The mmap path shares the snapshot's segment-range validation,
        // so any offsets it returns must lie inside the image — seed
        // mutation 45 once returned an offset past EOF here for an image
        // the snapshot oracle refuses.
        let file = open_of(&dir, &bytes);
        if let Ok((_, exports, charged)) = read_export_facts(&file, &[ANSWER]) {
            assert!(
                charged <= seed.len() as u64,
                "mutation {iteration} overcharged"
            );
            for (_, offset) in &exports {
                assert!(
                    *offset < bytes.len() as u64,
                    "mutation {iteration} attributed offset {offset} past EOF {}",
                    bytes.len()
                );
            }
        }
    }
    assert_eq!(refused + accepted, MUTATIONS);
    assert!(
        refused > 0 && accepted > 0,
        "both outcomes must occur (refused {refused}, accepted {accepted})"
    );
}

#[test]
fn export_charge_never_exceeds_mapped_length() {
    let dir = workdir("charge");
    let seed = build_seed(&dir);
    let file = open_of(&dir, &seed);
    let (_, _, charged) = read_export_facts(&file, &[ANSWER]).unwrap();
    assert!(charged <= seed.len() as u64);
    // The bounded query refuses admission above the reservation without mapping.
    let file = open_of(&dir, &seed);
    let error = read_export_facts_bounded(&file, &[ANSWER], seed.len() as u64 - 1).unwrap_err();
    assert!(
        error.contains("bound"),
        "admission refusal must name the bound: {error}"
    );
    let file = open_of(&dir, &seed);
    let (_, _, charged) = read_export_facts_bounded(&file, &[ANSWER], seed.len() as u64).unwrap();
    assert!(charged <= seed.len() as u64);
}

#[test]
fn hostile_readers_yield_errors_not_panics() {
    let dir = workdir("reader");
    let seed = build_seed(&dir);
    let file = open_of(&dir, &seed);
    let error = ElfSnapshot::read_with_reader(&file, |_, _, _| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "hostile",
        ))
    })
    .unwrap_err();
    assert!(error.contains("read failed"), "unexpected error: {error}");
    let file = open_of(&dir, &seed);
    let error = ElfSnapshot::read_with_reader(&file, |_, _, _| Ok(0)).unwrap_err();
    assert!(!error.is_empty());
    // A reader that returns zeros: the snapshot parses zeros or refuses.
    let file = open_of(&dir, &seed);
    if let Ok(snapshot) = ElfSnapshot::read_with_reader(&file, |_, bytes, _| {
        bytes.fill(0);
        Ok(bytes.len())
    }) {
        assert_facts_in_range(&snapshot, &vec![0u8; seed.len()], "zero reader");
    }
}

#[test]
fn non_elf_inputs_are_refused() {
    for (label, bytes) in [
        ("empty", Vec::new()),
        ("short magic", b"\x7fELF".to_vec()),
        ("text", b"this is not an object file\n".to_vec()),
        ("zeros", vec![0u8; 4096]),
    ] {
        assert!(
            classified_object(&bytes).is_err(),
            "{label} must not classify"
        );
    }
    let mut rng = MUTATION_SEED ^ 0x9e37;
    for iteration in 0..64 {
        let mut bytes = vec![0u8; 256 + (xorshift64(&mut rng) % 4096) as usize];
        for byte in bytes.iter_mut() {
            *byte = (xorshift64(&mut rng) % 256) as u8;
        }
        if classified_object(&bytes).is_ok() {
            panic!("random input {iteration} must not classify as ELF");
        }
    }
}
