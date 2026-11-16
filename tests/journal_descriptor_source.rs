//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Journal-object driver for tests/python/test_journal_descriptor_source.py.
//!
//! In-place downgrade (A′): the journal entry/return path narrows through
//! the same per-slot SLOT_COUNT_ONLY switch as Detailed, and the generic
//! outlined `object_return` monomorphization lives only in the journal
//! object. This driver proves the switch-gated descriptor source on the
//! actual embedded journal object. Builds that omit the journal assert
//! the omission instead of running a partial suite.

use std::process::Command;

/// The suite's test count; update with the suite (it proves selection).
const EXPECTED_TESTS: u32 = 5;

#[test]
fn journal_consumers_prove_the_switch_gated_descriptor_source() {
    if p11scope::EBPF_JOURNAL_OBJECT.is_empty() {
        assert_ne!(
            env!("P11SCOPE_JOURNAL_ENABLED"),
            "1",
            "a journal-enabled build must embed the journal object"
        );
        eprintln!("journal descriptor source: journal inapplicable in this build");
        return;
    }
    let directory = tempfile::tempdir().expect("temporary journal object");
    let object = directory.path().join("p11scope-ebpf-journal-v1");
    std::fs::write(&object, p11scope::EBPF_JOURNAL_OBJECT).expect("write journal object");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("P11SCOPE_JOURNAL_DESCRIPTOR_OBJECT", &object)
        .args(["-I", "tests/python/test_journal_descriptor_source.py", "-v"])
        .output()
        .expect("run journal descriptor-source suite");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "journal descriptor-source suite failed: {stderr}"
    );
    assert!(
        stderr.contains(&format!("Ran {EXPECTED_TESTS} tests")),
        "expected {EXPECTED_TESTS} tests: {stderr}"
    );
    assert!(!stderr.contains("(skipped="), "skipped proof: {stderr}");
}
