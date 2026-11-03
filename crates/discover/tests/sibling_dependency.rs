//! SPDX-License-Identifier: GPL-3.0-or-later
use p11scope_discover::discover::discover;
use p11scope_discover::manifest::{Acquisition, WalkOutcome};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static DISCOVER_LOCK: Mutex<()> = Mutex::new(());

fn soname(tag: &str) -> String {
    format!("sibdep-{tag}-{}.so", std::process::id())
}

fn fixture_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sibling-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_dep(dir: &Path, soname: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let dep = dir.join(soname);
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC"])
            .arg(format!("-Wl,-soname,{soname}"))
            .arg("-o")
            .arg(&dep)
            .arg(src.join("sibling_dep.c"))
            .status()
            .unwrap()
            .success(),
        "gcc {soname} failed"
    );
    dep
}

/// The standard fixture provider (`provider.c` + `helper.c` in one object,
/// so the sibling is its only non-system dependency), linked against the
/// sibling with no rpath.
fn build_provider(dir: &Path, lib_dir: &Path, soname: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let provider = dir.join("provider.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(src.join("provider.c"))
            .arg(src.join("helper.c"))
            .arg(format!("-L{}", lib_dir.display()))
            .arg("-Wl,--no-as-needed")
            .arg(format!("-l:{soname}"))
            .arg("-Wl,--as-needed")
            .status()
            .unwrap()
            .success(),
        "gcc provider.so failed"
    );
    provider
}

/// Variant of [`build_provider`] that also forces a `libc.so.6` DT_NEEDED
/// entry (the plain fixture needs only its sibling): the corrupt-extra
/// twin needs a needed name with a system copy so the skip-and-succeed
/// retry can resolve it after the corrupt same-dir file is skipped.
fn build_provider_forcing_libc(dir: &Path, lib_dir: &Path, soname: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let provider = dir.join("provider.so");
    assert!(
        Command::new("gcc")
            .arg(format!("-m{}", usize::BITS))
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(src.join("provider.c"))
            .arg(src.join("helper.c"))
            .arg(format!("-L{}", lib_dir.display()))
            .arg("-Wl,--no-as-needed")
            .arg(format!("-l:{soname}"))
            .arg("-lc")
            .arg("-Wl,--as-needed")
            .status()
            .unwrap()
            .success(),
        "gcc provider.so failed"
    );
    provider
}

fn assert_sibling_needed_without_rpath(provider: &Path, soname: &str) {
    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(provider)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains(soname),
        "DT_NEEDED must name the sibling:\n{dynamic}"
    );
    assert!(
        !dynamic.contains("RPATH") && !dynamic.contains("RUNPATH"),
        "fixture must carry no rpath:\n{dynamic}"
    );
}

#[test]
fn provider_with_a_sibling_dependency_in_its_own_directory_is_discovered() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let tag = "pos";
    let soname = soname(tag);
    let dir = fixture_dir(tag);
    build_dep(&dir, &soname);
    let provider = build_provider(&dir, &dir, &soname);
    assert_sibling_needed_without_rpath(&provider, &soname);

    let m = discover(&provider).unwrap();
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    assert!(matches!(m.interface_list, Acquisition::Ok));
    assert!(
        m.provenance_objects
            .iter()
            .any(|object| object.path.ends_with(&soname)),
        "the sibling must be part of provenance"
    );
}

/// Safety pin: a symlink inside the provider directory pointing at an
/// outside library must never be preloaded — the fallback loads regular
/// files only, so this stays refused. (If the fallback followed links,
/// the load below would succeed.)
#[test]
fn provider_whose_sibling_is_a_symlink_pointing_outside_is_refused() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let tag = "link";
    let soname = soname(tag);
    let base = fixture_dir(tag);
    let dep_dir = base.join("dep");
    let prov_dir = base.join("prov");
    std::fs::create_dir_all(&dep_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();
    let dep = build_dep(&dep_dir, &soname);
    let provider = build_provider(&prov_dir, &dep_dir, &soname);
    assert_sibling_needed_without_rpath(&provider, &soname);
    std::os::unix::fs::symlink(&dep, prov_dir.join(&soname)).unwrap();

    let error = discover(&provider).unwrap_err();
    assert!(
        error.contains("cannot dlopen"),
        "a symlink to an outside dependency must refuse, got: {error}"
    );
}

/// Robustness pin (rv-demo-ready-23 F1): one unloadable same-directory file
/// must not abort the whole sibling fallback. The provider needs a good
/// sibling (missing from the system search) and libc (present in the
/// system); the directory holds the good sibling plus a corrupt regular
/// file named `libc.so.6`. Skipping the corrupt file and preloading the
/// good sibling lets the retry succeed with libc resolved from the system.
#[test]
fn corrupt_extra_file_does_not_stop_good_sibling_from_preloading() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let tag = "corrupt-extra";
    let soname = soname(tag);
    let dir = fixture_dir(tag);
    build_dep(&dir, &soname);
    let provider = build_provider_forcing_libc(&dir, &dir, &soname);
    assert_sibling_needed_without_rpath(&provider, &soname);
    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&provider)
        .output()
        .unwrap();
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("libc.so.6"),
        "fixture must need libc.so.6 for the system-copy leg:\n{dynamic}"
    );
    let corrupt = dir.join("libc.so.6");
    std::fs::write(&corrupt, b"corrupt, not an ELF").unwrap();
    assert!(
        std::fs::symlink_metadata(&corrupt).unwrap().is_file(),
        "the corrupt file must pass the regular-file guard"
    );

    let m = discover(&provider).unwrap();
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    assert!(
        m.provenance_objects
            .iter()
            .any(|object| object.path.ends_with(&soname)),
        "the good sibling must be part of provenance"
    );
    let corrupt_text = corrupt.to_str().unwrap().to_string();
    assert!(
        m.provenance_objects
            .iter()
            .all(|object| object.path != corrupt_text),
        "the corrupt file must never load: {corrupt_text}"
    );
}

/// Fail-closed twin: a corrupt file under the provider's own needed name,
/// with no system copy, still refuses after the per-item skip.
#[test]
fn corrupt_needed_sibling_without_system_copy_is_still_refused() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let tag = "corrupt-needed";
    let soname = soname(tag);
    let base = fixture_dir(tag);
    let dep_dir = base.join("dep");
    let prov_dir = base.join("prov");
    std::fs::create_dir_all(&dep_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();
    build_dep(&dep_dir, &soname);
    let provider = build_provider(&prov_dir, &dep_dir, &soname);
    assert_sibling_needed_without_rpath(&provider, &soname);
    std::fs::write(prov_dir.join(&soname), b"corrupt, not an ELF").unwrap();

    let error = discover(&provider).unwrap_err();
    assert!(
        error.contains("cannot dlopen"),
        "corrupt needed sibling with no system copy must refuse, got: {error}"
    );
}

#[test]
fn provider_whose_dependency_lives_outside_its_directory_is_refused() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let tag = "neg";
    let soname = soname(tag);
    let base = fixture_dir(tag);
    let dep_dir = base.join("dep");
    let prov_dir = base.join("prov");
    std::fs::create_dir_all(&dep_dir).unwrap();
    std::fs::create_dir_all(&prov_dir).unwrap();
    build_dep(&dep_dir, &soname);
    let provider = build_provider(&prov_dir, &dep_dir, &soname);
    assert_sibling_needed_without_rpath(&provider, &soname);

    let error = discover(&provider).unwrap_err();
    assert!(
        error.contains("cannot dlopen"),
        "outside-directory dependency must refuse, got: {error}"
    );
}
