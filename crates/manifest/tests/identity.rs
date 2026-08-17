use p11scope_manifest::identity::{IdentityKind, MappingFileKey, identify};
use p11scope_manifest::maps::{executable_file_keys, parse_maps};
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
