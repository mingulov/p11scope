use p11scope_manifest::identity::{IdentityKind, MappingFileKey, identify, inspect_elf_loader};
use p11scope_manifest::maps::{executable_file_keys, parse_maps};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const LOAD_VADDR: u64 = 0x400000;
const INTERP_OFFSET: usize = 0x180;
const DYNAMIC_OFFSET: usize = 0x200;
const STRTAB_OFFSET: usize = 0x300;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_program_header(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    flags: u32,
    file_offset: usize,
    file_size: usize,
) {
    let at = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
    put_u32(bytes, at, kind);
    put_u32(bytes, at + 4, flags);
    put_u64(bytes, at + 8, file_offset as u64);
    put_u64(bytes, at + 16, LOAD_VADDR + file_offset as u64);
    put_u64(bytes, at + 24, LOAD_VADDR + file_offset as u64);
    put_u64(bytes, at + 32, file_size as u64);
    put_u64(bytes, at + 40, file_size as u64);
    put_u64(bytes, at + 48, if kind == 1 { 0x1000 } else { 8 });
}

fn program_header_at(index: usize) -> usize {
    ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE
}

fn put_dynamic(bytes: &mut [u8], index: usize, tag: i64, value: u64) {
    let at = DYNAMIC_OFFSET + index * 16;
    put_i64(bytes, at, tag);
    put_u64(bytes, at + 8, value);
}

fn sectionless_loader_elf() -> Vec<u8> {
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    let strings = b"libalpha.so\0libbeta.so\0p11scope-discover\0";
    let dynamic_count = 6;
    let mut bytes = vec![0u8; 0x400];

    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
    put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 56, 3);
    put_u16(&mut bytes, 58, 64);

    let file_len = bytes.len();
    put_program_header(&mut bytes, 0, 3, 4, INTERP_OFFSET, interpreter.len());
    put_program_header(&mut bytes, 1, 1, 5, 0, file_len);
    put_program_header(&mut bytes, 2, 2, 6, DYNAMIC_OFFSET, dynamic_count * 16);
    bytes[INTERP_OFFSET..INTERP_OFFSET + interpreter.len()].copy_from_slice(interpreter);
    bytes[STRTAB_OFFSET..STRTAB_OFFSET + strings.len()].copy_from_slice(strings);

    put_dynamic(&mut bytes, 0, 5, LOAD_VADDR + STRTAB_OFFSET as u64);
    put_dynamic(&mut bytes, 1, 10, strings.len() as u64);
    put_dynamic(&mut bytes, 2, 1, 0);
    put_dynamic(&mut bytes, 3, 1, 12);
    put_dynamic(&mut bytes, 4, 14, 23);
    put_dynamic(&mut bytes, 5, 0, 0);
    bytes
}

fn loader_fixture(name: &str, bytes: &[u8]) -> File {
    let path = tmpdir("loader").join(name);
    std::fs::write(&path, bytes).unwrap();
    File::open(path).unwrap()
}

fn assert_loader_error(name: &str, bytes: &[u8], expected: &str) {
    let error = inspect_elf_loader(&loader_fixture(name, bytes)).unwrap_err();
    assert!(
        error.contains(expected),
        "expected {expected:?} in {error:?}"
    );
}

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
fn sectionless_elf_loader_facts_are_exact() {
    let facts = inspect_elf_loader(&loader_fixture("sectionless", &sectionless_loader_elf()))
        .expect("sectionless program headers are the loader authority");

    assert_eq!(
        facts.interpreter.as_deref(),
        Some(Path::new("/lib64/ld-linux-x86-64.so.2"))
    );
    assert_eq!(
        facts.needed,
        [OsString::from("libalpha.so"), OsString::from("libbeta.so")]
    );
    assert_eq!(
        facts.soname.as_deref(),
        Some(OsStr::new("p11scope-discover"))
    );
}

#[test]
fn elf_loader_rejects_malformed_or_unsafe_inputs() {
    let mut bytes = sectionless_loader_elf();
    bytes[4] = 1;
    assert_loader_error("wrong-class", &bytes, "ELF64");

    let mut bytes = sectionless_loader_elf();
    bytes[5] = 2;
    assert_loader_error("wrong-endian", &bytes, "little-endian");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 18, 183);
    assert_loader_error("wrong-machine", &bytes, "x86-64");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 16, 1);
    assert_loader_error("wrong-type", &bytes, "ET_EXEC or ET_DYN");

    let mut bytes = sectionless_loader_elf();
    put_u32(&mut bytes, 20, 0);
    assert_loader_error("wrong-version", &bytes, "ELF version");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 52, 0);
    assert_loader_error("bad-elf-header-size", &bytes, "ELF header size");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 54, 0);
    assert_loader_error("bad-program-header-size", &bytes, "program header");

    let mut bytes = sectionless_loader_elf();
    let file_len = bytes.len() as u64;
    put_u64(&mut bytes, 32, file_len);
    assert_loader_error("bad-program-header-bounds", &bytes, "program header");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 4);
    put_program_header(
        &mut bytes,
        1,
        3,
        4,
        INTERP_OFFSET,
        b"/lib64/ld-linux-x86-64.so.2\0".len(),
    );
    let file_len = bytes.len();
    put_program_header(&mut bytes, 2, 1, 5, 0, file_len);
    put_program_header(&mut bytes, 3, 2, 6, DYNAMIC_OFFSET, 6 * 16);
    assert_loader_error("duplicate-interp", &bytes, "multiple PT_INTERP");

    let mut bytes = sectionless_loader_elf();
    let relative = b"ld-linux-x86-64.so.2\0";
    bytes[INTERP_OFFSET..INTERP_OFFSET + relative.len()].copy_from_slice(relative);
    put_program_header(&mut bytes, 0, 3, 4, INTERP_OFFSET, relative.len());
    assert_loader_error("relative-interp", &bytes, "absolute");

    let mut bytes = sectionless_loader_elf();
    let interp_size = b"/lib64/ld-linux-x86-64.so.2\0".len();
    bytes[INTERP_OFFSET + interp_size - 1] = b'x';
    assert_loader_error("unterminated-interp", &bytes, "terminated");

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 4);
    put_program_header(&mut bytes, 3, 2, 6, DYNAMIC_OFFSET, 6 * 16);
    assert_loader_error("duplicate-dynamic", &bytes, "multiple PT_DYNAMIC");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 5, 21, 0);
    assert_loader_error("unterminated-dynamic", &bytes, "DT_NULL");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 2, 5, LOAD_VADDR + STRTAB_OFFSET as u64);
    assert_loader_error("duplicate-strtab", &bytes, "multiple DT_STRTAB");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 2, 10, 44);
    assert_loader_error("duplicate-strsz", &bytes, "multiple DT_STRSZ");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 3, 14, 23);
    assert_loader_error("duplicate-soname", &bytes, "multiple DT_SONAME");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 0, 21, 0);
    assert_loader_error("missing-strtab", &bytes, "missing DT_STRTAB");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 1, 21, 0);
    assert_loader_error("missing-strsz", &bytes, "missing DT_STRSZ");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 0, 5, u64::MAX);
    assert_loader_error("strtab-address-overflow", &bytes, "string table");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 1, 10, u64::MAX);
    assert_loader_error("strtab-size-overflow", &bytes, "string table");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 2, 1, 44);
    assert_loader_error("bad-string-offset", &bytes, "string offset");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 1, 10, 11);
    assert_loader_error("unterminated-string", &bytes, "NUL-terminated");

    let mut bytes = sectionless_loader_elf();
    put_dynamic(&mut bytes, 2, 1, 11);
    assert_loader_error("empty-needed", &bytes, "empty DT_NEEDED");

    let mut bytes = sectionless_loader_elf();
    bytes[STRTAB_OFFSET..STRTAB_OFFSET + 11].copy_from_slice(b"bad/lib.soX");
    assert_loader_error("slash-needed", &bytes, "contains '/'");

    for (name, tag) in [
        ("rpath", 15),
        ("runpath", 29),
        ("depaudit", 0x6fff_fefb),
        ("audit", 0x6fff_fefc),
        ("auxiliary", 0x7fff_fffd),
        ("filter", 0x7fff_ffff),
    ] {
        let mut bytes = sectionless_loader_elf();
        put_dynamic(&mut bytes, 2, tag, 0);
        assert_loader_error(name, &bytes, "forbidden dynamic tag");
    }

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 4);
    let file_len = bytes.len();
    put_program_header(
        &mut bytes,
        3,
        1,
        5,
        DYNAMIC_OFFSET,
        file_len - DYNAMIC_OFFSET,
    );
    assert_loader_error("ambiguous-strtab-segment", &bytes, "exactly one PT_LOAD");
}

#[test]
fn elf_loader_rejects_incoherent_runtime_program_headers() {
    let mut bytes = sectionless_loader_elf();
    put_u64(
        &mut bytes,
        program_header_at(2) + 16,
        LOAD_VADDR + DYNAMIC_OFFSET as u64 + 8,
    );
    assert_loader_error("dynamic-runtime-translation", &bytes, "PT_DYNAMIC mapping");

    let mut bytes = sectionless_loader_elf();
    let file_len = bytes.len();
    put_program_header(&mut bytes, 0, 1, 5, 0, file_len);
    put_program_header(
        &mut bytes,
        1,
        3,
        4,
        INTERP_OFFSET,
        b"/lib64/ld-linux-x86-64.so.2\0".len(),
    );
    assert_loader_error(
        "interp-after-load",
        &bytes,
        "PT_INTERP must precede every PT_LOAD",
    );

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 4);
    let file_len = bytes.len();
    put_program_header(&mut bytes, 3, 1, 5, 0, file_len);
    assert_loader_error("descending-load", &bytes, "ascending virtual address");

    let mut bytes = sectionless_loader_elf();
    let memory_size = bytes.len() as u64 - 1;
    put_u64(&mut bytes, program_header_at(1) + 40, memory_size);
    assert_loader_error("load-file-larger-than-memory", &bytes, "PT_LOAD file size");

    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, program_header_at(1) + 8, u64::MAX);
    assert_loader_error("load-file-overflow", &bytes, "PT_LOAD file range");

    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, program_header_at(1) + 16, u64::MAX);
    assert_loader_error("load-virtual-overflow", &bytes, "PT_LOAD virtual range");

    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, program_header_at(1) + 48, 3);
    assert_loader_error("load-non-power-two-align", &bytes, "power of two");

    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, program_header_at(1) + 16, LOAD_VADDR + 1);
    assert_loader_error("load-incongruent-align", &bytes, "alignment mismatch");

    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, program_header_at(2) + 40, 6 * 16 - 1);
    assert_loader_error(
        "dynamic-file-larger-than-memory",
        &bytes,
        "PT_DYNAMIC file size",
    );
}

#[test]
fn elf_loader_requires_a_coherent_program_header_table_and_load() {
    let mut bytes = sectionless_loader_elf();
    put_u64(&mut bytes, 32, 0);
    assert_loader_error(
        "missing-program-header-table",
        &bytes,
        "program header table",
    );

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 0);
    assert_loader_error(
        "missing-program-header-count",
        &bytes,
        "program header table",
    );

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 0xffff);
    assert_loader_error(
        "extended-program-header-count",
        &bytes,
        "extended program header count",
    );

    let mut bytes = sectionless_loader_elf();
    put_u16(&mut bytes, 56, 1);
    put_program_header(&mut bytes, 0, 0, 0, 0, 0);
    assert_loader_error("no-load-segment", &bytes, "at least one PT_LOAD");
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
                device_major: 8,
                device_minor: 2,
                inode: 173521,
            },
            MappingFileKey {
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
