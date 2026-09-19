//! SPDX-License-Identifier: GPL-3.0-or-later
#[allow(dead_code)]
#[path = "../build_support/bpf_tools.rs"]
mod bpf_tools;

use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::PathBuf,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bpf-build-tools")
        .join(path)
}

fn linked_fixture(root: &std::path::Path, fixture_name: &str, name: &str) -> PathBuf {
    let path = root.join(name);
    std::os::unix::fs::symlink(fixture(fixture_name), &path).expect("link native fixture");
    path
}

fn recording_rustc(root: &std::path::Path) -> PathBuf {
    let rustc = linked_fixture(root, "recording-rustc", "selected rustc");
    fs::create_dir_all(root.join("sysroot with space/lib")).expect("create fixture sysroot lib");
    rustc
}

fn execute(mut command: std::process::Command, record: &std::path::Path) -> String {
    let status = command
        .env("P11SCOPE_BPF_TEST_RECORD", record)
        .status()
        .expect("execute selected BPF Cargo fixture");
    assert!(status.success(), "fixture status: {status}");
    fs::read_to_string(record).expect("read BPF tool record")
}

fn env_change(command: &std::process::Command, name: &str) -> Option<Option<OsString>> {
    command
        .get_envs()
        .find(|(key, _)| *key == OsStr::new(name))
        .map(|(_, value)| value.map(OsStr::to_os_string))
}

fn effective_uid() -> u32 {
    fs::read_to_string("/proc/self/status")
        .expect("read effective uid")
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(2))
        .and_then(|uid| uid.parse().ok())
        .expect("parse effective uid")
}

fn owned_other_execute_only(root: &std::path::Path, fixture_name: &str, name: &str) -> PathBuf {
    let path = root.join(name);
    fs::copy(fixture(fixture_name), &path).expect("copy owned tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o601)).expect("chmod owned tool");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o601
    );
    path
}

#[test]
fn selected_pair_executes_exact_cargo_with_matching_rustc_and_no_rustup_argument() {
    let root = tempfile::tempdir().unwrap();
    let cargo = fixture("selected-cargo");
    let rustc = recording_rustc(root.path());
    let selected_lib = root.path().join("sysroot with space/lib");
    let stable_lib = root.path().join("stable lib");
    let other_lib = root.path().join("other-lib");
    let inherited = std::env::join_paths([&stable_lib, &other_lib]).unwrap();

    for (case, inherited, expected_paths) in [
        ("absent", None, vec![selected_lib.clone()]),
        (
            "populated",
            Some(inherited),
            vec![selected_lib.clone(), stable_lib.clone(), other_lib.clone()],
        ),
    ] {
        let record_path = root.path().join(format!("{case}.record"));
        let mut command = bpf_tools::bpf_cargo_command(
            Some(cargo.clone().into_os_string()),
            Some(rustc.clone().into_os_string()),
            inherited,
        )
        .unwrap();
        command
            .args(["build", "--locked"])
            .env("PATH", fixture("path-decoy"));
        assert_eq!(
            env_change(&command, "RUSTC"),
            Some(Some(rustc.clone().into_os_string()))
        );
        assert_eq!(env_change(&command, "RUSTC_WORKSPACE_WRAPPER"), Some(None));
        assert_eq!(env_change(&command, "RUSTC_WRAPPER"), None);
        let library_path = env_change(&command, "LD_LIBRARY_PATH")
            .expect("selected library path override")
            .expect("selected library path value");
        assert_eq!(
            std::env::split_paths(&library_path).collect::<Vec<_>>(),
            expected_paths
        );

        let record = execute(command, &record_path);
        assert!(record.contains(&format!("program={}\n", cargo.display())));
        assert!(record.contains(&format!("rustc={}\n", rustc.display())));
        assert!(record.contains(&format!(
            "ld_library_path={}\n",
            library_path.to_string_lossy()
        )));
        assert!(record.contains("workspace_wrapper=unset\n"));
        assert!(record.contains("arg=build\narg=--locked\n"));
        assert!(!record.contains("+nightly"));
        assert!(!record.contains("decoy"));
    }
    assert_eq!(
        fs::read_to_string(format!("{}.query", rustc.display())).unwrap(),
        "arg=--print\narg=sysroot\n"
    );
}

#[test]
fn fallback_executes_path_cargo_with_the_pinned_nightly_argument() {
    let root = tempfile::tempdir().unwrap();
    let record = root.path().join("record");
    let mut command =
        bpf_tools::bpf_cargo_command(None, None, Some(OsString::from("/stable/lib:/other/lib")))
            .unwrap();
    command.arg("build").env("PATH", fixture("fallback"));
    assert_eq!(env_change(&command, "RUSTC"), Some(None));
    assert_eq!(env_change(&command, "RUSTC_WORKSPACE_WRAPPER"), Some(None));
    assert_eq!(env_change(&command, "RUSTC_WRAPPER"), None);
    assert_eq!(env_change(&command, "LD_LIBRARY_PATH"), None);

    let record = execute(command, &record);
    assert!(record.contains("program="));
    assert!(record.contains("rustc=unset\n"));
    assert!(record.contains("workspace_wrapper=unset\n"));
    assert!(record.contains("arg=+nightly-2026-05-20\narg=build\n"));
}

#[test]
fn current_user_owned_0601_cargo_uses_effective_execute_access() {
    let root = tempfile::tempdir().unwrap();
    let cargo = owned_other_execute_only(root.path(), "selected-cargo", "owned-cargo");
    let rustc = recording_rustc(root.path());
    let result = bpf_tools::bpf_cargo_command(
        Some(cargo.into_os_string()),
        Some(rustc.into_os_string()),
        None,
    );
    if effective_uid() == 0 {
        assert!(result.is_ok(), "root has effective execute access");
    } else {
        let error = result.expect_err("owner without execute permission must be refused");
        assert!(error.contains(bpf_tools::PREPARED_CARGO_ENV), "{error}");
    }
}

#[test]
fn current_user_owned_0601_rustc_uses_effective_execute_access() {
    let root = tempfile::tempdir().unwrap();
    let rustc = owned_other_execute_only(root.path(), "recording-rustc", "owned-rustc");
    fs::create_dir_all(root.path().join("sysroot with space/lib"))
        .expect("create owned rustc sysroot lib");
    let result = bpf_tools::bpf_cargo_command(
        Some(fixture("selected-cargo").into_os_string()),
        Some(rustc.into_os_string()),
        None,
    );
    if effective_uid() == 0 {
        assert!(result.is_ok(), "root has effective execute access");
    } else {
        let error = result.expect_err("owner without execute permission must be refused");
        assert!(error.contains(bpf_tools::PREPARED_RUSTC_ENV), "{error}");
    }
}

#[test]
fn partial_empty_relative_non_file_and_non_executable_pairs_are_refused() {
    let cargo = fixture("selected-cargo").into_os_string();
    let rustc = fixture("selected-rustc").into_os_string();
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().to_path_buf().into_os_string();
    let non_executable_cargo = root.path().join("cargo-not-executable");
    let non_executable_rustc = root.path().join("rustc-not-executable");
    fs::write(&non_executable_cargo, "not executable").unwrap();
    fs::write(&non_executable_rustc, "not executable").unwrap();
    assert_eq!(
        fs::metadata(&non_executable_cargo)
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );

    for (label, selected_cargo, selected_rustc) in [
        ("cargo only", Some(cargo.clone()), None),
        ("rustc only", None, Some(rustc.clone())),
        ("empty cargo", Some(OsString::new()), Some(rustc.clone())),
        (
            "NUL cargo",
            Some(OsString::from_vec(b"/tmp/cargo\0invalid".to_vec())),
            Some(rustc.clone()),
        ),
        (
            "relative cargo",
            Some(OsString::from("relative-cargo")),
            Some(rustc.clone()),
        ),
        (
            "directory cargo",
            Some(directory.clone()),
            Some(rustc.clone()),
        ),
        (
            "non-executable cargo",
            Some(non_executable_cargo.into_os_string()),
            Some(rustc.clone()),
        ),
        ("empty rustc", Some(cargo.clone()), Some(OsString::new())),
        (
            "relative rustc",
            Some(cargo.clone()),
            Some(OsString::from("relative-rustc")),
        ),
        ("directory rustc", Some(cargo.clone()), Some(directory)),
        (
            "non-executable rustc",
            Some(cargo),
            Some(non_executable_rustc.into_os_string()),
        ),
    ] {
        let error = bpf_tools::bpf_cargo_command(selected_cargo, selected_rustc, None)
            .expect_err("invalid pair must be refused");
        assert!(!error.is_empty(), "{label}");
    }
}

#[test]
fn rustc_sysroot_query_failures_are_refused_before_selected_cargo() {
    for fixture_name in [
        "query-failure-rustc",
        "query-empty-rustc",
        "query-multiline-rustc",
        "query-relative-rustc",
        "query-missing-lib-rustc",
    ] {
        let root = tempfile::tempdir().unwrap();
        let rustc = linked_fixture(root.path(), fixture_name, "rustc");
        if fixture_name == "query-missing-lib-rustc" {
            fs::create_dir(root.path().join("missing-sysroot")).unwrap();
        }
        let cargo_marker = root.path().join("cargo.record");
        let error = bpf_tools::bpf_cargo_command(
            Some(fixture("selected-cargo").into_os_string()),
            Some(rustc.into_os_string()),
            None,
        )
        .expect_err("invalid sysroot query must be refused");
        assert!(error.contains("sysroot"), "{fixture_name}: {error}");
        assert!(!cargo_marker.exists(), "{fixture_name} reached Cargo");
    }
}

#[test]
fn build_script_selects_tools_before_clang_and_declares_cache_inputs() {
    let source = include_str!("../build.rs");
    let selection = source
        .find("bpf_cargo_command_from_env()")
        .expect("BPF tool selection");
    let clang = source.find("Command::new(\"clang-18\")").expect("clang");
    assert!(
        selection < clang,
        "invalid selection must refuse before clang"
    );
    for declaration in [
        "cargo:rerun-if-env-changed=P11SCOPE_PREPARED_BPF_CARGO",
        "cargo:rerun-if-env-changed=P11SCOPE_PREPARED_BPF_RUSTC",
        "cargo:rerun-if-env-changed=LD_LIBRARY_PATH",
        "cargo:rerun-if-changed=build_support/bpf_tools.rs",
    ] {
        assert!(source.contains(declaration), "missing {declaration}");
    }
}
