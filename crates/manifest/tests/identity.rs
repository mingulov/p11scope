//! SPDX-License-Identifier: GPL-3.0-or-later
use object::elf;
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{
    IdentityKind, MappingFileKey, identify, inspect_file, inspect_file_with_reader_exporting,
    open_object,
};
use p11scope_manifest::maps::{executable_file_keys, parse_maps};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cc_shared(dir: &Path, out: &str, extra: &[&str]) -> PathBuf {
    let src = dir.join("stub.c");
    std::fs::write(&src, "int nothing(void) { return 42; }\n").unwrap();
    let so = dir.join(out);
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .args(extra)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed");
    so
}

fn tmpdir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn strict_maps_refuse_malformed_lines_and_report_executable_inodes() {
    let input = b"\
00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/with space
00500000-00552000 r--p 00000000 08:02 173522 /usr/lib/data
00600000-00652000 r-xp 00000000 08:02 173521 /usr/bin/alias
00700000-00752000 r-xp 00000000 00:00 0 /memfd:anonymous
00800000-00852000 r-xp 00000000 08:03 173523 /tmp/nonutf8-\xff.so
";
    let maps = parse_maps(input).unwrap();
    assert_eq!(
        executable_file_keys(&maps),
        [
            MappingFileKey {
                mount_id: 0,
                device_major: 8,
                device_minor: 2,
                inode: 173521,
            },
            MappingFileKey {
                mount_id: 0,
                device_major: 8,
                device_minor: 3,
                inode: 173523,
            },
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        maps[0].raw_path.as_deref(),
        Some(b"/usr/bin/with space".as_slice())
    );
    assert_eq!(
        maps[4].raw_path.as_deref(),
        Some(b"/tmp/nonutf8-\xff.so".as_slice())
    );

    for malformed in [
        b"not a maps line".as_slice(),
        b" \t".as_slice(),
        b"1000 r-xp 0 08:01 1 /x".as_slice(),
        b"-2000 r-xp 0 08:01 1 /x".as_slice(),
        b"1000- r-xp 0 08:01 1 /x".as_slice(),
        b"1000-2000-3000 r-xp 0 08:01 1 /x".as_slice(),
        b"2000-1000 r-xp 0 08:01 1 /x".as_slice(),
        b"zz-2000 r-xp 0 08:01 1 /x".as_slice(),
        b"1000-2000 rxp 0 08:01 1 /x".as_slice(),
        b"1000-2000 rwqp 0 08:01 1 /x".as_slice(),
        b"1000-2000 r-xz 0 08:01 1 /x".as_slice(),
        b"1000-2000 r-xp zz 08:01 1 /x".as_slice(),
        b"1000-2000 r-xp 0 0801 1 /x".as_slice(),
        b"1000-2000 r-xp 0 08:01:02 1 /x".as_slice(),
        b"1000-2000 r-xp 0 zz:01 1 /x".as_slice(),
        b"1000-2000 r-xp 0 08:01 x /x".as_slice(),
        b"1000-2000 r-xp 0 08:01".as_slice(),
    ] {
        let error = parse_maps(malformed).unwrap_err();
        assert!(error.contains("line 1"), "{malformed:?}: {error}");
    }
}

#[test]
fn inspection_retains_the_classified_object_abi() {
    let d = tmpdir("identity-abi");
    let so = cc_shared(&d, "native.so", &[]);
    let file = open_object(&so).unwrap();
    assert_eq!(inspect_file(&file).unwrap().abi, ElfAbi::Lp64);

    let ilp32 = cc_shared(&d, "ilp32.so", &["-m32"]);
    let file = open_object(&ilp32).unwrap();
    assert_eq!(inspect_file(&file).unwrap().abi, ElfAbi::Ilp32);
}

#[test]
fn gnu_build_id_preferred() {
    let so = cc_shared(&tmpdir("id1"), "with_id.so", &["-Wl,--build-id=sha1"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::GnuBuildId);
    assert!(id.reusable);
    assert_eq!(id.value.unwrap().len(), 40); // sha1 note = 20 bytes hex
    assert_eq!(id.sha256.unwrap().len(), 64);
}

#[test]
fn sha256_fallback_without_build_id() {
    let so = cc_shared(&tmpdir("id2"), "no_id.so", &["-Wl,--build-id=none"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::Sha256);
    assert!(id.reusable);
    assert_eq!(id.value.as_ref().unwrap().len(), 64);
    assert_eq!(id.sha256, id.value);
}

#[test]
fn non_elf_is_not_an_attachable_identity() {
    let d = tmpdir("id3");
    let f = d.join("not_elf.so");
    std::fs::write(&f, b"not an ELF at all").unwrap();
    let id = identify(&f);
    assert_eq!(id.kind, IdentityKind::Unavailable);
    assert!(!id.reusable);
    assert!(id.value.is_none());
    assert!(id.sha256.is_none());
    assert!(id.note.unwrap().contains("not parseable"));
}

#[test]
fn unreadable_is_explicitly_not_reusable() {
    let id = identify(Path::new("/nonexistent/x.so"));
    assert_eq!(id.kind, IdentityKind::Unavailable);
    assert!(!id.reusable);
    assert!(id.value.is_none());
    assert!(id.sha256.is_none());
}

const INSPECT_REGISTRY: &[&str] = &["C_GetFunctionList", "NSC_GetFunctionList"];

fn provider_source() -> &'static str {
    "unsigned long C_GetFunctionList(void **p){(void)p;return 0;}\n\
     unsigned long NSC_GetFunctionList(void **p){(void)p;return 0;}\n"
}

fn cc_provider(dir: &Path, out: &str) -> PathBuf {
    let src = dir.join("provider.c");
    std::fs::write(&src, provider_source()).unwrap();
    let so = dir.join(out);
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc failed");
    so
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn executable_load_header(bytes: &[u8]) -> std::ops::Range<usize> {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "fixture must be ELF64");
    assert_eq!(bytes[5], 1, "fixture must be little-endian");
    let start: usize = le_u64(bytes, 0x20).try_into().unwrap();
    let size = usize::from(le_u16(bytes, 0x36));
    let count = usize::from(le_u16(bytes, 0x38));
    (0..count)
        .map(|index| start + index * size)
        .find(|offset| {
            u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) == elf::PT_LOAD
                && u32::from_le_bytes(bytes[*offset + 4..*offset + 8].try_into().unwrap())
                    & elf::PF_X
                    != 0
        })
        .map(|offset| offset..offset + size)
        .unwrap()
}

#[test]
fn inspect_refuses_segment_past_eof() {
    // The inspect path must apply the snapshot's segment-range validation
    // before walking exports or collecting executable ranges: the same
    // one-field corruption as `export_facts_mmap_refuses_segment_past_eof`
    // (executable PT_LOAD p_offset moved past EOF) must refuse
    // byte-identically to the snapshot oracle, never answer with export
    // offsets and ranges past EOF.
    let d = tmpdir("inspect-segment-past-eof");
    let provider = cc_provider(&d, "provider.so");
    let original = std::fs::read(&provider).unwrap();
    let mut bytes = original.clone();
    let header = executable_load_header(&bytes);
    let offset = le_u64(&bytes, header.start + 8);
    let filesz = le_u64(&bytes, header.start + 32);
    assert!(
        offset
            .checked_add(filesz)
            .is_some_and(|end| end <= original.len() as u64),
        "fixture segment must start in range (offset {offset:#x}, filesz {filesz:#x})"
    );
    let corrupted = original.len() as u64 + 0x1000;
    bytes[header.start + 8..header.start + 16].copy_from_slice(&corrupted.to_le_bytes());
    assert_ne!(bytes, original, "the patch must change the image");
    let path = d.join("segment-past-eof.so");
    std::fs::write(&path, &bytes).unwrap();

    // The oracle pins the setup: the image still classifies, and refuses
    // only on the segment range.
    let file = open_object(&path).unwrap();
    let oracle_err = ElfSnapshot::read(&file).unwrap_err();
    assert_eq!(oracle_err, "segment file range extends past the ELF bytes");
    // The exporting inspect path refuses byte-identically (pre-fix: Ok with
    // exports and ranges past EOF).
    let file = open_object(&path).unwrap();
    match inspect_file_with_reader_exporting(
        &file,
        |file, bytes, offset| file.read_at(bytes, offset),
        INSPECT_REGISTRY,
    ) {
        Err(error) => assert_eq!(error, oracle_err),
        Ok(inspected) => panic!(
            "inspect answered for a past-EOF image: exports {:?}, ranges {:?} (len {})",
            inspected.exports,
            inspected.executable_ranges,
            bytes.len(),
        ),
    }
    // The plain inspect path shares the same refused core.
    let file = open_object(&path).unwrap();
    assert_eq!(inspect_file(&file).unwrap_err(), oracle_err);
}

#[test]
fn inspect_matches_snapshot_on_valid_image() {
    // Healthy twin of the segment-past-EOF refusal: the same seed image,
    // unpatched, yields inspect exports and executable ranges equal to the
    // snapshot path, with every offset inside the file.
    let d = tmpdir("inspect-valid-twin");
    let provider = cc_provider(&d, "provider.so");
    let file_len = std::fs::metadata(&provider).unwrap().len();
    let file = open_object(&provider).unwrap();
    let snapshot = ElfSnapshot::read(&file).unwrap();
    let file = open_object(&provider).unwrap();
    let inspected = inspect_file_with_reader_exporting(
        &file,
        |file, bytes, offset| file.read_at(bytes, offset),
        INSPECT_REGISTRY,
    )
    .unwrap();
    assert_eq!(inspected.abi, snapshot.abi());
    let oracle_exports = snapshot.exports_matching(INSPECT_REGISTRY).unwrap();
    assert!(
        !oracle_exports.is_empty(),
        "the fixture must export hooks, or the offsets are unpinned"
    );
    assert_eq!(inspected.exports, oracle_exports);
    for (name, offset) in &inspected.exports {
        assert!(
            *offset < file_len,
            "{name} offset {offset} outside {file_len} bytes"
        );
        assert!(
            snapshot.is_executable_offset(*offset),
            "{name} offset {offset} is outside every snapshot executable range"
        );
    }
    assert!(
        !inspected.executable_ranges.is_empty(),
        "the fixture must have executable ranges, or admission is unpinned"
    );
    for (start, end) in &inspected.executable_ranges {
        assert!(
            start < end && *end <= file_len,
            "range {start}..{end} outside {file_len} bytes"
        );
        assert!(snapshot.is_executable_offset(*start));
        assert!(snapshot.is_executable_offset(end - 1));
    }
    // Dense admission agreement between the inspect ranges and the snapshot
    // oracle, plus the past-EOF boundary.
    for probe in (0..file_len).step_by(16).chain([file_len, file_len + 1]) {
        assert_eq!(
            inspected.contains_executable_offset(probe),
            snapshot.is_executable_offset(probe),
            "admission differs at {probe:#x}"
        );
    }
}
