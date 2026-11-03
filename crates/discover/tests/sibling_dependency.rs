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
