use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CASES: &[&str] = &[
    "ledger-missing-final-lf",
    "ledger-duplicate-row",
    "ledger-unsorted-row",
    "ledger-noncontiguous-seq",
    "ledger-4097th-row",
    "ledger-bad-field",
    "directory-listing-mutation",
    "undeclared-directory-entry",
    "unsafe-file-kind-or-identity",
    "trace-truncated",
    "trace-unparseable",
    "trace-lost-child",
    "trace-unaccounted-fd",
    "trace-missing-transitive-input",
    "trace-unknown-class",
    "production-undeclared-open",
    "production-input-mutation",
    "landlock-undeclared-read",
    "landlock-outside-write",
    "production-network-denied",
    "staging-collision",
    "staging-partial-pending",
    "staging-unexpected-entry",
    "staging-subject-drift",
    "lane09-mutable-base",
    "lane09-live-package-network",
    "lane09-broad-context",
    "lane09-missing-package",
    "authority-report-opaque",
    "tip-product-input-mutation",
    "tip-unrelated-report-accepted",
    "copy-source-replacement",
    "copy-destination-collision",
    "subject-replace-after-check",
    "subject-close-before-use",
    "subject-path-reopen",
    "subject-same-fd-check-use",
];

#[test]
fn task4_build_subject_self_test_is_rootless_and_complete() {
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "p11scope-task4-build-subjects-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create private Task 4 fixture");
    let _cleanup = Cleanup(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("chmod private Task 4 fixture");

    let fake_bin = root.join("tripwire-bin");
    let work = root.join("work");
    let staging = root.join("staging");
    let runtime = root.join("runtime");
    let report = root.join("report.tsv");
    let tripwire_log = root.join("tripwire.log");
    fs::create_dir(&fake_bin).expect("create private tripwire directory");
    fs::create_dir(&work).expect("create private self-test work directory");
    fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o700))
        .expect("chmod private tripwire directory");
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
        .expect("chmod private self-test work directory");

    let tripwire_names = [
        "bash",
        "bpftool",
        "bpftrace",
        "cargo",
        "cc",
        "clang",
        "clang++",
        "curl",
        "docker",
        "file",
        "gcc",
        "g++",
        "ip",
        "ld",
        "ld.lld",
        "make",
        "ninja",
        "p11scope",
        "p11scope-discover",
        "podman",
        "python",
        "python3",
        "rust-lld",
        "rustc",
        "rustdoc",
        "rustup",
        "setpriv",
        "sh",
        "strace",
        "sudo",
        "systemctl",
        "systemd-run",
        "wget",
    ];
    let tripwire = b"#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$P11SCOPE_TASK4_TRIPWIRE_LOG\"\nexit 97\n";
    for name in tripwire_names {
        let path = fake_bin.join(name);
        fs::write(&path, tripwire).expect("write tripwire");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("chmod tripwire");
    }

    let snapshot = |path: &Path| -> BTreeSet<std::ffi::OsString> {
        fs::read_dir(path)
            .expect("read fixture directory")
            .map(|entry| entry.expect("read fixture entry").file_name())
            .collect()
    };
    let repo_before = snapshot(repo);
    let fake_bin_before = snapshot(&fake_bin);
    let root_before = snapshot(&root);

    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["scripts/task4-build-subject.py", "--self-test"])
        .current_dir(repo)
        .env_clear()
        .env("PATH", &fake_bin)
        .env("TMPDIR", &root)
        .env("P11SCOPE_TASK4_SELF_TEST_WORK", &work)
        .env("P11SCOPE_TASK4_WORK", &work)
        .env("P11SCOPE_TASK4_SELF_TEST_REPORT", &report)
        .env("P11SCOPE_TASK4_SELF_TEST_STAGING", &staging)
        .env("P11SCOPE_TASK4_SELF_TEST_RUNTIME", &runtime)
        .env("P11SCOPE_TASK4_TRIPWIRE_LOG", &tripwire_log);
    for (variable, command_name) in [
        ("BPFTOOL", "bpftool"),
        ("CARGO", "cargo"),
        ("CC", "gcc"),
        ("CXX", "g++"),
        ("DOCKER", "docker"),
        ("LD", "ld"),
        ("PODMAN", "podman"),
        ("RUSTC", "rustc"),
        ("RUSTUP", "rustup"),
        ("STRACE", "strace"),
        ("SUDO", "sudo"),
        ("SYSTEMD_RUN", "systemd-run"),
    ] {
        command.env(variable, fake_bin.join(command_name));
    }

    let output = command
        .output()
        .expect("run /usr/bin/python3 scripts/task4-build-subject.py --self-test");
    assert!(
        output.status.success(),
        "Task 4 build-subject self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "self-test wrote to stdout");
    assert!(output.stderr.len() <= 64 * 1024, "self-test stderr is unbounded");

    let report_bytes = fs::read(&report).expect("read private self-test report");
    assert!(report_bytes.len() <= 4 * 1024 * 1024, "self-test report is unbounded");
    let report_text = String::from_utf8(report_bytes).expect("self-test report is UTF-8");
    let mut expected_report = String::new();
    for case in CASES {
        expected_report.push_str("selftest-v1\tcase\t");
        expected_report.push_str(case);
        expected_report.push_str("\tOK\tOK\n");
    }
    expected_report.push_str("selftest-v1\tcomplete\n");
    assert_eq!(report_text, expected_report);

    assert!(!tripwire_log.exists(), "a self-test tripwire command ran");
    assert_eq!(snapshot(&fake_bin), fake_bin_before, "tripwire was modified");
    assert!(snapshot(&work).is_empty(), "self-test wrote runtime work output");
    assert!(!staging.exists(), "self-test created staging output");
    assert!(!runtime.exists(), "self-test created runtime output");

    let mut expected_root = root_before;
    expected_root.insert(report.file_name().expect("report filename").to_owned());
    assert_eq!(snapshot(&root), expected_root, "fixture gained unexpected output");
    assert_eq!(snapshot(repo), repo_before, "self-test changed repository output");
}
