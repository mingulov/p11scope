use p11scope_manifest::identity::{IdentityKind, identify};
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
fn gnu_build_id_preferred() {
    let so = cc_shared(&tmpdir("id1"), "with_id.so", &["-Wl,--build-id=sha1"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::GnuBuildId);
    assert!(id.reusable);
    assert_eq!(id.value.unwrap().len(), 40); // sha1 note = 20 bytes hex
}

#[test]
fn sha256_fallback_without_build_id() {
    let so = cc_shared(&tmpdir("id2"), "no_id.so", &["-Wl,--build-id=none"]);
    let id = identify(&so);
    assert_eq!(id.kind, IdentityKind::Sha256);
    assert!(id.reusable);
    assert_eq!(id.value.unwrap().len(), 64);
}

#[test]
fn non_elf_still_hashes_bytes() {
    let d = tmpdir("id3");
    let f = d.join("not_elf.so");
    std::fs::write(&f, b"not an ELF at all").unwrap();
    let id = identify(&f);
    assert_eq!(id.kind, IdentityKind::Sha256);
    assert!(id.reusable);
    assert!(id.note.unwrap().contains("not parseable"));
}

#[test]
fn unreadable_is_explicitly_not_reusable() {
    let id = identify(Path::new("/nonexistent/x.so"));
    assert_eq!(id.kind, IdentityKind::Unavailable);
    assert!(!id.reusable);
    assert!(id.value.is_none());
}
