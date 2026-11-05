//! SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

/// Whether BPF rustflags carry an opt-level override. Flags arrive
/// `\u{1f}`-separated (CARGO_ENCODED_RUSTFLAGS); the host environment can
/// contribute a single-token `-Copt-level=` (no space), so the match is a
/// substring, not a prefix.
fn flags_carry_opt_level_override(flags: &str) -> bool {
    flags
        .split('\u{1f}')
        .any(|token| token.contains("opt-level"))
}

/// Inventory verifier budget: both inventory flavors build the BPF crate
/// with `-C opt-level=3`, restoring the pre-size-first code shape the
/// 5.15/6.1 verifier accepts for `interface_list_worker` (the crate
/// profile's `opt-level = "s"` shrank the worker's static size but doubled
/// its verifier states past the 1M limit). Detailed and counter flavors
/// keep the profile default, so their pinned budgets stay valid.
#[test]
fn inventory_build_restores_worker_opt_level() {
    let manifest = std::fs::read_to_string("crates/ebpf/Cargo.toml").expect("read BPF manifest");
    assert!(
        manifest
            .lines()
            .any(|line| line.trim() == "opt-level = \"s\""),
        "the BPF release profile must keep opt-level \"s\" for Detailed/counters"
    );
    let build = std::fs::read_to_string("build.rs").expect("read build script");
    let lines: Vec<&str> = build.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.contains("append_flag(\"opt-level=3\")"))
        .expect("inventory BPF builds must override opt-level to 3");
    let guard = lines[at.saturating_sub(6)..at]
        .iter()
        .rev()
        .find(|line| line.trim_start().starts_with("if "))
        .expect("opt-level override must sit under a flavor guard");
    assert!(
        guard.trim() == "if inventory {",
        "opt-level 3 must apply to both inventory flavors only, under `{guard}`"
    );
}

/// Last-wins order: rustc takes the LAST `-C opt-level`, so any
/// `opt-level` flag appended after the inventory override would silently
/// restore the E2BIG codegen while the presence pin above stays green.
/// No `opt-level` append may follow the inventory override.
#[test]
fn inventory_opt_level_override_is_not_shadowed() {
    let build = std::fs::read_to_string("build.rs").expect("read build script");
    let lines: Vec<&str> = build.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.contains("append_flag(\"opt-level=3\")"))
        .expect("inventory BPF builds must override opt-level to 3");
    for (offset, line) in lines[at + 1..].iter().enumerate() {
        assert!(
            !(line.contains("append_flag") && line.contains("opt-level")),
            "build.rs:{} appends opt-level after the inventory override, shadowing it: {line}",
            at + offset + 2,
        );
    }
}

/// Effective-flags twin of the ordering pin: build.rs records the exact
/// CARGO_ENCODED_RUSTFLAGS it hands each BPF flavor build. Both inventory
/// flavors must end with `-C opt-level=3` (rustc takes the last
/// `-C opt-level`); the Detailed and counter flavors must carry no
/// opt-level override, so their pinned verifier budgets stay valid.
#[test]
fn effective_bpf_rustflags_keep_inventory_last_and_detailed_plain() {
    for (name, flags) in [
        ("inventory", env!("P11SCOPE_BPF_RUSTFLAGS_INVENTORY")),
        (
            "inventory-callers",
            env!("P11SCOPE_BPF_RUSTFLAGS_INVENTORY_CALLERS"),
        ),
    ] {
        let tail: Vec<&str> = flags.rsplit('\u{1f}').take(2).collect();
        assert_eq!(
            tail.as_slice(),
            ["opt-level=3", "-C"],
            "{name} BPF rustflags must end with `-C opt-level=3`: {flags:?}"
        );
    }
    let mut plain = vec![("detailed", env!("P11SCOPE_BPF_RUSTFLAGS_DETAILED"))];
    for (name, flags) in [
        (
            "counter-counts",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_COUNTS"),
        ),
        (
            "counter-timestamps",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_TIMESTAMPS"),
        ),
        (
            "counter-latency",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_LATENCY"),
        ),
        (
            "counter-counts-proof",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_COUNTS_PROOF"),
        ),
        (
            "counter-timestamps-proof",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_TIMESTAMPS_PROOF"),
        ),
        (
            "counter-latency-proof",
            option_env!("P11SCOPE_BPF_RUSTFLAGS_COUNTER_LATENCY_PROOF"),
        ),
    ] {
        if let Some(flags) = flags {
            plain.push((name, flags));
        }
    }
    for (name, flags) in plain {
        assert!(
            !flags_carry_opt_level_override(flags),
            "{name} BPF rustflags must carry no opt-level override: {flags:?}"
        );
    }
}

#[test]
fn opt_level_override_detector_catches_single_token_from_host_environment() {
    // A single-token `-Copt-level=` from CARGO_ENCODED_RUSTFLAGS (host
    // environment, no space) must be caught; a prefix match misses it.
    // Twin: the two-token `-C`, `opt-level=` shape is caught by both.
    assert!(
        flags_carry_opt_level_override("-Copt-level=3"),
        "single-token -Copt-level= must be caught"
    );
    assert!(
        flags_carry_opt_level_override("-C\u{1f}opt-level=3"),
        "two-token -C opt-level= must be caught"
    );
    assert!(
        !flags_carry_opt_level_override("-C\u{1f}debuginfo=2"),
        "clean flags must not match"
    );
}

#[test]
fn compact_inventory_object_matches_manifest_and_relocates_without_kernel_syscalls() {
    let directory = tempfile::tempdir().expect("inventory object test directory");
    let path = directory.path().join("inventory.o");
    std::fs::write(&path, p11scope::EBPF_INVENTORY_OBJECT)
        .expect("write embedded inventory object");
    let output = Command::new("python3")
        .args([
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--inventory",
            env!("P11SCOPE_INVENTORY_VARIANT"),
        ])
        .arg(&path)
        .output()
        .expect("inventory object check");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("python3")
        .args(["-I", "tests/python/test_inventory_object.py"])
        .env("P11SCOPE_INVENTORY_OBJECT", &path)
        .env(
            "P11SCOPE_INVENTORY_VARIANT",
            env!("P11SCOPE_INVENTORY_VARIANT"),
        )
        .output()
        .expect("actual inventory object mutation checks");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut object =
        aya_obj::Object::parse(p11scope::EBPF_INVENTORY_OBJECT).expect("parse inventory object");
    let maps = object.maps.clone();
    let mut names: Vec<_> = maps.keys().collect();
    names.sort();
    let descriptors: std::collections::BTreeMap<_, _> = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), 1000 + index as i32))
        .collect();
    let code_sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    object
        .relocate_maps(
            maps.iter()
                .map(|(name, map)| (name.as_str(), descriptors[name.as_str()], map)),
            &code_sections,
        )
        .expect("relocate every inventory map reference");
    let referenced: std::collections::BTreeSet<_> = object
        .functions
        .values()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.code == 0x18 && instruction.src_reg() == 1)
        .map(|instruction| instruction.imm)
        .collect();
    for name in [
        "THREAD_OWNER",
        "OWNER_CTL",
        "DISCOVERY_STATE",
        "USAGE",
        "USAGE_CONFIG",
        "USAGE_EVIDENCE",
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "unreferenced inventory map {name}"
        );
    }
}
