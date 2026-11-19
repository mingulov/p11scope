//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
        // Keymeta Task 7 (spec §17.4): the info pair references
        // its stash, ring, kind publication and evidence cells.
        "INFO_START",
        "INFO",
        "INFO_KIND",
        "INFO_EVIDENCE",
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "unreferenced inventory map {name}"
        );
    }
}

/// Task 7 privacy (spec §17.1, allowlist-v3 named positions): the
/// info entry wrapper loads only the probe arguments its kind
/// authorizes — provider {0}, token {0,1}, mechanism {0,1,2} — so
/// ia32 stack-word reads never touch positions outside the function
/// signature. Every constant-index `arg_u64` call site in
/// `stash_info_entry` must sit under the exact non-negated
/// `info_uses_arg(kind, N)` guard for the same N, and no ia32 stack
/// read may bypass it. The contract checks polarity and pairing,
/// not mere presence, and every mutation below must fail it.
#[test]
fn info_entry_guards_each_arg_read_by_kind() {
    fn body_of(source: &str) -> &str {
        let start = source
            .find("fn stash_info_entry(")
            .expect("stash_info_entry exists");
        let tail = &source[start..];
        let end = tail.find("\n}\n").expect("stash_info_entry ends") + "\n}".len();
        &tail[..end]
    }
    fn is_code(line: &str) -> bool {
        !line.trim_start().starts_with("//")
    }
    fn contract(body: &str) -> bool {
        if body.contains("p11_read_ia32_arg") || body.contains("arg_u64(ctx, index") {
            return false;
        }
        let lines: Vec<&str> = body.lines().collect();
        let mut indices = Vec::new();
        for (number, line) in lines.iter().enumerate() {
            if !is_code(line) || !line.contains("arg_u64(ctx,") {
                continue;
            }
            let rest = line.split_once("arg_u64(ctx,").unwrap().1;
            let index = rest.trim_start().chars().next().unwrap();
            if !index.is_ascii_digit() {
                return false;
            }
            // The exact non-negated guard for this same index, in
            // the lines directly above the site.
            let guard = format!("if info_uses_arg(kind, {index}) {{");
            let above = &lines[..number];
            let start = above.len().saturating_sub(4);
            if !above[start..]
                .iter()
                .any(|above| is_code(above) && above.trim_start() == guard)
            {
                return false;
            }
            indices.push(index);
        }
        indices.sort();
        indices == ['0', '1', '2']
    }
    let source =
        std::fs::read_to_string("crates/ebpf/src/inventory_info.rs").expect("read info BPF source");
    let body = body_of(&source).to_string();
    assert!(
        contract(&body),
        "stash_info_entry must guard each constant-index arg site with its exact kind guard"
    );
    // An inverted guard must fail: the predicate name is present
    // but the authorized position is refused instead of read.
    for index in ['0', '1', '2'] {
        let tail = body.replacen(
            &format!("if info_uses_arg(kind, {index}) {{"),
            &format!("if !info_uses_arg(kind, {index}) {{"),
            1,
        );
        assert!(!contract(&tail), "an inverted kind guard for site {index}");
    }
    // A site under another index's guard must fail.
    let tail = body.replacen(
        "if info_uses_arg(kind, 1) {",
        "if info_uses_arg(kind, 0) {",
        1,
    );
    assert!(!contract(&tail), "a site under the wrong guard");
    // A missing guard must fail.
    let tail = body.replacen("if info_uses_arg(kind, 2) {", "if true {", 1);
    assert!(!contract(&tail), "an unguarded arg site");
    // A fourth site must fail.
    let tail = body.replacen("arg_u64(ctx, 2, layout)", "arg_u64(ctx, 3, layout)", 1);
    assert!(!contract(&tail), "an arg site outside the signature");
    // A dynamic index must fail.
    let tail = body.replacen("arg_u64(ctx, 0, layout)", "arg_u64(ctx, index, layout)", 1);
    assert!(!contract(&tail), "a dynamic fetch index");
}

/// The direct code statements of the `{...}` block the condition
/// at `lines[start]` opens, plus the closing line's index:
/// brace-matched to the `}` at the condition's own indent,
/// comments and blanks stripped, nested lines excluded. `None`
/// when the block never closes. Refusal pins match the whole block
/// so a disabled condition or a dead nested branch fails them.
fn refusal_block_statements<'a>(lines: &[&'a str], start: usize) -> Option<(Vec<&'a str>, usize)> {
    let base = lines[start].len() - lines[start].trim_start().len();
    let mut depth = 0i32;
    let mut statements = Vec::new();
    for (offset, line) in lines[start..].iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if depth == 1 && indent == base + 4 {
            statements.push(trimmed);
        }
        depth += trimmed.chars().filter(|c| *c == '{').count() as i32
            - trimmed.chars().filter(|c| *c == '}').count() as i32;
        if depth == 0 {
            return Some((statements, start + offset));
        }
        if depth < 0 {
            return None;
        }
    }
    None
}

/// Task 7 return eligibility (spec §17.4): the info return counts
/// an unmatched return only for eligible (in-scope) calls, whose
/// entries could have stashed. Out-of-scope returns — whose entries
/// never stashed — delete any row silently and return early instead
/// of polluting the diagnostic. The out-of-scope refusal is the
/// exact non-negated `scope_auth().is_none()` block ahead of the
/// unmatched count, and every mutation below must fail it.
#[test]
fn info_return_counts_unmatched_only_in_scope() {
    fn body_of(source: &str) -> &str {
        let start = source
            .find("pub fn p11_info_return")
            .expect("p11_info_return exists");
        let tail = &source[start..];
        let end = tail.find("\n}\n").expect("p11_info_return ends") + "\n}".len();
        &tail[..end]
    }
    fn is_code(line: &str) -> bool {
        !line.trim_start().starts_with("//")
    }
    fn contract(body: &str) -> bool {
        let lines: Vec<&str> = body.lines().collect();
        let scope = lines
            .iter()
            .position(|line| is_code(line) && line.trim_start() == "if scope_auth().is_none() {");
        let unmatched = lines
            .iter()
            .position(|line| is_code(line) && line.contains("INFO_EVIDENCE_UNMATCHED_RETURNS"));
        let (Some(scope), Some(unmatched)) = (scope, unmatched) else {
            return false;
        };
        if scope >= unmatched {
            return false;
        }
        // The refused block itself deletes and returns early as its
        // direct statements, in order (later deletes — the
        // live-kind gate, the unconditional row delete — do not
        // count), and closes ahead of the unmatched count.
        let Some((statements, end)) = refusal_block_statements(&lines, scope) else {
            return false;
        };
        end < unmatched && statements == ["let _ = INFO_START.remove(&key);", "return 0;"]
    }
    let source =
        std::fs::read_to_string("crates/ebpf/src/inventory_info.rs").expect("read info BPF source");
    let body = body_of(&source).to_string();
    assert!(
        contract(&body),
        "p11_info_return must refuse out-of-scope returns before the unmatched count"
    );
    // An inverted scope predicate must fail: in-scope calls would
    // delete silently while out-of-scope calls count.
    let tail = body.replacen(
        "if scope_auth().is_none() {",
        "if scope_auth().is_some() {",
        1,
    );
    assert!(!contract(&tail), "an inverted scope predicate");
    // A scope check that deletes nothing must fail.
    let scope = body.find("if scope_auth().is_none() {").unwrap();
    let tail = format!(
        "{}{}",
        &body[..scope],
        body[scope..].replacen("INFO_START.remove(&key)", "REMOVED", 1)
    );
    assert!(!contract(&tail), "an out-of-scope path without the delete");
    // A scope check without the early return must fail.
    let after = &body[scope..];
    let ret = after.find("return 0;").unwrap();
    let mut tail = after.to_string();
    tail.replace_range(ret..ret + "return 0;".len(), "REMOVED;");
    assert!(
        !contract(&format!("{}{}", &body[..scope], tail)),
        "an out-of-scope path without the early return"
    );
    // A missing scope check must fail.
    let tail = body.replacen("if scope_auth().is_none() {", "if false {", 1);
    assert!(!contract(&tail), "a return without the scope check");
    // A delete and return nested in a dead branch must fail: the
    // refusal path itself must delete and return, not merely sit
    // near the words.
    let after = &body[scope..];
    let tail = after.replacen(
        "let _ = INFO_START.remove(&key);\n        return 0;",
        "if false {\n            let _ = INFO_START.remove(&key);\n            return 0;\n        }",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &body[..scope], tail)),
        "an out-of-scope path whose delete and return cannot execute"
    );
    // A disabled scope check must fail (the exact-condition guard).
    let tail = body.replacen(
        "if scope_auth().is_none() {",
        "if scope_auth().is_none() && false {",
        1,
    );
    assert!(!contract(&tail), "a disabled scope check");
}

/// Task 7 revocation authority (spec §17.4): the info return
/// enforces the endpoint's LIVE kind before reading a saved INFO
/// pointer or counting an unmatched call. A revoked (zero) or
/// unknown live kind deletes any stash row silently and returns
/// before the stash dereference and the unmatched count — a valid
/// stash racing the revocation loses INFO authority here, and
/// later in-scope invocations after revocation count nothing. A
/// live kind that disagrees with the stash kind mismatches without
/// reading. Only a live kind equal to the stash kind reaches the
/// return adapter. The contract checks polarity and order, not
/// mere presence, and every mutation below must fail it.
#[test]
fn info_return_enforces_live_kind_before_reading_or_counting() {
    fn body_of(source: &str) -> &str {
        let start = source
            .find("pub fn p11_info_return")
            .expect("p11_info_return exists");
        let tail = &source[start..];
        let end = tail.find("\n}\n").expect("p11_info_return ends") + "\n}".len();
        &tail[..end]
    }
    fn is_code(line: &str) -> bool {
        !line.trim_start().starts_with("//")
    }
    // The gate is an exact non-negated validity refusal on the
    // live kind: presence of the predicate name alone (or a
    // negated, inverted or disabled use) must not satisfy the
    // contract.
    fn contract(body: &str) -> bool {
        let lines: Vec<&str> = body.lines().collect();
        let live_read = lines
            .iter()
            .position(|line| is_code(line) && line.contains("INFO_KIND.get(endpoint)"));
        let gate = lines.iter().position(|line| {
            is_code(line) && line.trim_start() == "if !info_kind_valid(live_kind) {"
        });
        let unmatched = lines
            .iter()
            .position(|line| is_code(line) && line.contains("INFO_EVIDENCE_UNMATCHED_RETURNS"));
        let adapter = lines
            .iter()
            .position(|line| is_code(line) && line.contains("adapter_info_return("));
        let (Some(live_read), Some(gate), Some(unmatched), Some(adapter)) =
            (live_read, gate, unmatched, adapter)
        else {
            return false;
        };
        if !(live_read < gate && gate < unmatched && gate < adapter) {
            return false;
        }
        // The refused block deletes silently as its direct
        // statements, in order (the unconditional delete below the
        // gate does not count), and closes before the unmatched
        // count.
        let Some((statements, end)) = refusal_block_statements(&lines, gate) else {
            return false;
        };
        if end >= unmatched || statements != ["let _ = INFO_START.remove(&key);", "return 0;"] {
            return false;
        }
        // Kind skew refuses without reading: the stash/live
        // comparison precedes the adapter, with a mismatch count on
        // the skew path and no adapter read before it.
        let skew = lines
            .iter()
            .position(|line| is_code(line) && line.contains("stash.kind != live_kind"));
        let Some(skew) = skew else {
            return false;
        };
        if !(gate < skew && skew < adapter) {
            return false;
        }
        lines[skew..adapter]
            .iter()
            .any(|line| is_code(line) && line.contains("INFO_EVIDENCE_STASH_MISMATCHES"))
    }
    let source =
        std::fs::read_to_string("crates/ebpf/src/inventory_info.rs").expect("read info BPF source");
    let body = body_of(&source).to_string();
    assert!(
        contract(&body),
        "p11_info_return must refuse on a revoked live kind before the stash read \
         and the unmatched count, and mismatch on kind skew before the adapter"
    );
    // An unmasked return (no live-kind read) must fail.
    let tail = body.replacen("INFO_KIND.get(endpoint)", "REMOVED", 1);
    assert!(!contract(&tail), "a return without the live-kind read");
    // An inverted validity gate must fail: the predicate name is
    // present but the refusal polarity is wrong.
    let tail = body.replacen(
        "if !info_kind_valid(live_kind)",
        "if info_kind_valid(live_kind)",
        1,
    );
    assert!(!contract(&tail), "an inverted live-kind gate");
    // A gate that deletes nothing must fail: remove the stash
    // delete on the refused path (after the gate), not the
    // out-of-scope delete above it.
    let gate = body.find("if !info_kind_valid(live_kind)").unwrap();
    let tail = format!(
        "{}{}",
        &body[..gate],
        body[gate..].replacen("INFO_START.remove(&key)", "REMOVED", 1)
    );
    assert!(!contract(&tail), "a gate without the silent stash delete");
    // A gate without the early return must fail.
    let after = &body[gate..];
    let ret = after.find("return 0;").unwrap();
    let mut tail = after.to_string();
    tail.replace_range(ret..ret + "return 0;".len(), "REMOVED;");
    assert!(
        !contract(&format!("{}{}", &body[..gate], tail)),
        "a gate without the early return"
    );
    // A return without the skew check must fail.
    let tail = body.replacen("stash.kind != live_kind", "REMOVED", 1);
    assert!(!contract(&tail), "a return without the kind-skew refusal");
    // A disabled gate must fail: the predicate name is present but
    // the refusal branch cannot execute.
    let tail = body.replacen(
        "if !info_kind_valid(live_kind) {",
        "if !info_kind_valid(live_kind) && false {",
        1,
    );
    assert!(!contract(&tail), "a disabled live-kind gate");
    // A delete and return nested in a dead branch must fail.
    let after = &body[gate..];
    let tail = after.replacen(
        "let _ = INFO_START.remove(&key);\n        return 0;",
        "if false {\n            let _ = INFO_START.remove(&key);\n            return 0;\n        }",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &body[..gate], tail)),
        "a gate whose delete and return cannot execute"
    );
}
