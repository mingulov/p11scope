//! SPDX-License-Identifier: GPL-3.0-or-later
//! W3-1 (Stage 3 Wave D, D2a+b) standalone harness for the task_vma identity
//! object and its loader/parser.
//!
//! TEMPORARY wiring (constraint: only `build.rs` may change among existing
//! files, so `src/attach.rs` cannot declare the new module yet): the module
//! under test is included by path. Its inline `#[cfg(test)]` unit tests
//! (parser tables, byte-flip, reader, uapi offsets, I6 grep) therefore run
//! inside this integration-test binary. W3-2 deletes the `#[path]` include
//! below and switches these tests to `p11scope::attach::identity_iter` once
//! the module is wired into `attach.rs`; the object-level tests in this file
//! stay valid unchanged.

#[path = "../src/attach/identity_iter.rs"]
mod identity_iter;

#[path = "../build_support/clang_resolve.rs"]
mod clang_resolve;

use identity_iter as ii;

/// The clang-built identity object out of this package's `OUT_DIR`. This is
/// the same artifact [`ii::IDENTITY_OBJECT`] embeds; reading it separately
/// here keeps the object-contract tests independent of the loader path.
static OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-identity"));

/// D2a gate: exactly 2 `iter/task_vma` programs and 5 maps with the expected
/// types, sizes and flags (`WRONLY` on the three kernel-only anchor maps,
/// `MMAPABLE` on the scope bitmap). Kills the D2a mutations: a dropped
/// `WRONLY` flag or a third program fails here.
#[test]
fn identity_object_has_two_iter_programs_and_five_maps() {
    let object = aya_obj::Object::parse(OBJECT).expect("parse identity object");
    assert_eq!(object.programs.len(), 2, "exactly two programs");
    for name in ["p11_anchor_vma", "p11_identity_vma"] {
        let program = object.programs.get(name).unwrap_or_else(|| {
            panic!(
                "program {name} missing; have {:?}",
                object.programs.keys().collect::<Vec<_>>()
            )
        });
        assert!(
            matches!(
                program.section,
                aya_obj::ProgramSection::Iter { sleepable: false }
            ),
            "{name} must live in iter/task_vma, got {:?}",
            program.section
        );
    }
    assert_eq!(object.maps.len(), 5, "exactly five maps");
    // (name, type, key_size, value_size, max_entries, flags)
    for (name, map_type, key_size, value_size, max_entries, flags) in [
        ("anchors", 1u32, 8u32, 16u32, 1024u32, 16u32), // HASH, WRONLY
        ("anchor_slots", 2u32, 4u32, 8u32, 1024u32, 16u32), // ARRAY, WRONLY
        ("anchor_observed", 2u32, 4u32, 8u32, 1024u32, 16u32), // ARRAY, WRONLY
        ("config", 2u32, 4u32, 32u32, 1u32, 0u32),      // ARRAY
        ("scope_bitmap", 2u32, 4u32, 8u32, 65_536u32, 1024u32), // ARRAY, MMAPABLE
    ] {
        let map = object.maps.get(name).unwrap_or_else(|| {
            panic!(
                "map {name} missing; have {:?}",
                object.maps.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(map.map_type(), map_type, "{name} type");
        assert_eq!(map.key_size(), key_size, "{name} key size");
        assert_eq!(map.value_size(), value_size, "{name} value size");
        assert_eq!(map.max_entries(), max_entries, "{name} max entries");
        assert_eq!(map.map_flags(), flags, "{name} flags");
    }
    assert_eq!(object.license.to_str().expect("license utf8"), "GPL");
}

/// Aya's map relocation runs over the identity object with sentinel fds, as it
/// does for the embedded Detailed object: parsing plus relocation without any
/// kernel syscall.
#[test]
fn identity_object_relocates_without_syscalls() {
    let mut object = aya_obj::Object::parse(OBJECT).expect("parse identity object");
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
        .expect("relocate every identity map reference");
    let referenced: std::collections::BTreeSet<_> = object
        .functions
        .values()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.code == 0x18 && instruction.src_reg() == 1)
        .map(|instruction| instruction.imm)
        .collect();
    for name in [
        "anchors",
        "anchor_slots",
        "anchor_observed",
        "config",
        "scope_bitmap",
    ] {
        assert!(
            referenced.contains(&descriptors[name]),
            "map {name} must retain its own descriptor after relocation"
        );
    }
}

/// CO-RE relocations in the clang object resolve against the host vmlinux BTF
/// and rewrite at least one instruction (so the check is live, not a no-op).
/// This proves the anonymous-union descent for `vm_start`/`vm_end`/`vm_flags`
/// and the `FIELD_EXISTS` guard evaluate on a real 7.x BTF. Unprivileged: pure
/// userspace BTF matching, no syscalls. Loudly skipped only where host BTF is
/// absent (the multi-kernel matrix itself is W3-2's vng job).
#[test]
fn identity_core_relocations_resolve_against_host_btf() {
    let btf = match aya::Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(error) => {
            eprintln!("W3-1 CO-RE test NEEDS_CONTEXT: host BTF unreadable ({error:#}); skipping");
            return;
        }
    };
    let pristine = aya_obj::Object::parse(OBJECT).expect("parse identity object");
    assert!(
        pristine.has_btf_relocations(),
        "object must carry CO-RE relocations"
    );
    let mut relocated = pristine.clone();
    relocated
        .relocate_btf(&btf)
        .expect("CO-RE must resolve against host BTF");
    let before: Vec<_> = pristine
        .functions
        .values()
        .flat_map(|function| {
            function
                .instructions
                .iter()
                .map(|ins| (ins.code, ins.imm, ins.off))
        })
        .collect();
    let after: Vec<_> = relocated
        .functions
        .values()
        .flat_map(|function| {
            function
                .instructions
                .iter()
                .map(|ins| (ins.code, ins.imm, ins.off))
        })
        .collect();
    assert_eq!(
        before.len(),
        after.len(),
        "relocation must not add/remove instructions"
    );
    assert_ne!(
        before, after,
        "relocation must rewrite at least one instruction"
    );
    // The pristine object keeps its local offsets; relocation is what adapts it.
    drop(pristine);
}

/// D2a byte-identity gate: the three default objects are unchanged by the new
/// flavor. Digests pinned at BASE `cd6ad51` in this toolchain; small-ring and
/// diagnostic features legitimately change the objects, so the pin applies
/// only to the default build.
#[test]
fn default_objects_byte_identical_to_base() {
    if cfg!(feature = "unsafe-unvalidated-metadata")
        || cfg!(feature = "wide-detailed-2112")
        || cfg!(p11scope_small_discovery_ring)
        || std::env::var("P11SCOPE_SMALL_RING").is_ok_and(|v| v == "1" || v == "true")
        || std::env::var("P11SCOPE_SMALL_STATE_MAPS").is_ok_and(|v| v == "1" || v == "true")
        || std::env::var("P11SCOPE_SMALL_DISCOVERY_RING").is_ok_and(|v| v == "1" || v == "true")
    {
        eprintln!("byte-identity pin applies to default builds only; skipping");
        return;
    }
    use sha2::Digest as _;
    // The identity object has no feature variants: its pin (below) applies
    // to every build, while these three skip under small-ring/diagnostic
    // features.
    for (name, bytes, pinned) in [
        (
            "p11scope-ebpf",
            p11scope::EBPF_OBJECT,
            "b62b40541cad83d211cbd80031c4e2bbea60edd20f5a040af35f1f890efb9f08",
        ),
        (
            "p11scope-ebpf-inventory",
            p11scope::EBPF_INVENTORY_OBJECT,
            "a8b93b30813b666ef63a868f0615cfa2b7da8822d0bfa297f35b6f680759bc77",
        ),
        (
            "p11scope-ebpf-inventory-callers",
            p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
            "bc77210dbd74ecf2ec8dbac9bb73553c37f0939512e7d1a71c65df35300be480",
        ),
    ] {
        let digest = sha2::Sha256::digest(bytes);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, pinned, "{name} must stay byte-identical to BASE");
    }
}

/// Digest pin for the identity object itself (F-build): any source or
/// toolchain drift changes these bytes, and the pin fails loudly. Pinned
/// at the arena-containment commit in this toolchain (round 1:
/// `000caca5…`; round 2 adds the fifth map plus the end-containment
/// check; round 3 re-pins comment-only — the observed-map doc comment
/// was rewritten with identical line numbers, so code/maps/BTF are
/// byte-identical and only the DWARF `.debug_line` source MD5 moved;
/// round 4 re-pins comment-only again — the marker-outcome phrase was
/// narrowed to the explicit triple with identical line numbers, so
/// `iter/task_vma`, `.maps`, `license`, `.BTF`, and `.BTF.ext` are
/// byte-identical and only `.debug_line` moved); the build-info test
/// below binds the pin to the compiler digest and CPU baseline it was
/// recorded with.
#[test]
fn identity_object_digest_pinned() {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(OBJECT);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, "e948001ed065c7f731ae3753a3bc59c4923d38e4fffb64bfb789527e9c4a5420",
        "p11scope-ebpf-identity must stay byte-identical to the round-4 pin"
    );
}

/// Qualification binding (F-build): the build records the resolved
/// compiler digest, the explicit CPU baseline, and the object digest in
/// `p11scope-identity-build-info.txt`; this test pins that record's shape,
/// the compiler's IDENTITY (not just digest format: the recorded file
/// must exist, be executable, and re-hash to the recorded digest), the
/// complete argument record, and its agreement with the object under
/// test. Ordinary builds still trust their tool environment (PATH
/// `clang-18`, system headers) — the record makes qualification
/// reproducible, not the build hermetic.
#[test]
fn identity_build_info_binds_compiler_and_baseline() {
    let info = std::fs::read_to_string(concat!(
        env!("OUT_DIR"),
        "/p11scope-identity-build-info.txt"
    ))
    .expect("build must record identity build info");
    let field = |name: &str| -> String {
        info.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("build info lacks {name}"))
            .to_string()
    };
    let compiler = field("compiler_sha256");
    assert_eq!(compiler.len(), 64, "compiler digest must be sha256 hex");
    assert!(
        compiler.chars().all(|c| c.is_ascii_hexdigit()),
        "compiler digest must be hex"
    );
    assert!(
        ["bpfel", "bpfeb"].contains(&field("target").as_str()),
        "target must be a BPF endian flavor"
    );
    assert_eq!(field("mcpu"), "v1", "CPU baseline must be explicit v1");
    // The recorded compiler must be the executed one: an absolute path to
    // an effectively-executable file (same predicate the build resolved
    // with) whose bytes re-hash to the recorded digest, with the
    // recorded realpath agreeing. A non-executable PATH decoy (or any
    // file that did not compile the object) fails here.
    let compiler_path = std::path::PathBuf::from(field("compiler_path"));
    assert!(
        compiler_path.is_absolute(),
        "compiler path must be absolute, got {compiler_path:?}"
    );
    assert!(
        compiler_path.is_file(),
        "compiler path must exist, got {compiler_path:?}"
    );
    assert!(
        clang_resolve::is_executable_file(&compiler_path),
        "compiler path must be effectively executable, got {compiler_path:?}"
    );
    let realpath = compiler_path
        .canonicalize()
        .expect("compiler path must canonicalize");
    assert_eq!(
        realpath,
        std::path::PathBuf::from(field("compiler_realpath")),
        "recorded realpath must match the resolved compiler"
    );
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(std::fs::read(&realpath).expect("read compiler"));
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, compiler,
        "recorded compiler digest must match the resolved compiler's bytes"
    );
    // The complete argument record, pinned: any flag change fails loudly.
    let target = field("target");
    assert_eq!(
        field("cflags"),
        format!(
            "-target {target} -mcpu=v1 -O2 -g -gno-record-gcc-switches -fdebug-compilation-dir=/p11scope/native -Wall -Wextra -Werror -c"
        ),
        "recorded cflags must match the qualification baseline"
    );
    // The full argv record, pinned element by element: any dropped or
    // changed argument (prefix-map, source/object paths, cwd, UAPI
    // argv) fails loudly.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let argv_of = |prefix: &str| -> Vec<String> {
        let argc: usize = field(&format!("{prefix}_argc"))
            .parse()
            .unwrap_or_else(|_| panic!("{prefix}_argc must be a number"));
        (0..argc)
            .map(|i| field(&format!("{prefix}_arg{i}")))
            .collect()
    };
    assert_eq!(
        argv_of("compile"),
        vec![
            field("compiler_path"),
            "-target".to_string(),
            target.clone(),
            "-mcpu=v1".to_string(),
            "-O2".to_string(),
            "-g".to_string(),
            "-gno-record-gcc-switches".to_string(),
            "-fdebug-compilation-dir=/p11scope/native".to_string(),
            "-Wall".to_string(),
            "-Wextra".to_string(),
            "-Werror".to_string(),
            "-c".to_string(),
            format!("-ffile-prefix-map={manifest}=/p11scope"),
            format!("{manifest}/crates/ebpf/native/vma_identity.c"),
            "-o".to_string(),
            "p11scope-ebpf-identity".to_string(),
        ],
        "recorded compile argv must match the executed invocation"
    );
    assert_eq!(
        argv_of("uapi"),
        vec![
            field("compiler_path"),
            "-fsyntax-only".to_string(),
            "-Wall".to_string(),
            "-Wextra".to_string(),
            "-Werror".to_string(),
            format!("{manifest}/crates/ebpf/native/uapi_check.c"),
        ],
        "recorded UAPI argv must match the executed check"
    );
    assert_eq!(
        field("compile_cwd"),
        env!("OUT_DIR"),
        "the compile must run with cwd at OUT_DIR"
    );
    let digest = sha2::Sha256::digest(OBJECT);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        field("object_sha256"),
        hex,
        "recorded object digest must match the object under test"
    );
    assert!(
        field("compiler_path").contains("clang-18"),
        "compiler path must name the resolved clang-18"
    );
}

/// Compare recorded candidate permission bits against the live files:
/// `Ok` when every recorded path still exists with identical
/// `mode & 0o7777` bits, `Err` describing the first stale entry
/// otherwise. Shared by the receipt test (real candidates) and the
/// hermetic chmod-strategem proof below.
fn candidate_modes_match_live(candidates: &[(std::path::PathBuf, u32)]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    for (path, recorded) in candidates {
        let live = path
            .metadata()
            .map(|meta| meta.permissions().mode() & 0o7777)
            .map_err(|error| format!("candidate {} unreadable: {error}", path.display()))?;
        if live != *recorded {
            return Err(format!(
                "candidate {} bits drifted: recorded {recorded:04o}, live {live:04o}",
                path.display(),
            ));
        }
    }
    Ok(())
}

/// Watch + chmod closure (fix round 3, item 3W1F3-10): the build
/// records the `PATH` directories it watches and the candidate
/// permission bits it resolved; this test recomputes both from the
/// recorded `PATH` and fails loudly on any drift. A chmod-only flip
/// (no mtime change, so no rebuild) leaves a stale receipt the
/// bit comparison catches here.
#[test]
fn identity_build_info_watches_path_and_pins_candidate_modes() {
    let info = std::fs::read_to_string(concat!(
        env!("OUT_DIR"),
        "/p11scope-identity-build-info.txt"
    ))
    .expect("build must record identity build info");
    let field = |name: &str| -> String {
        info.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("build info lacks {name}"))
            .to_string()
    };
    // The recorded watch set must equal what the resolver computes
    // from the recorded PATH + cwd (the build prints a
    // `rerun-if-changed` for each existing one).
    let path_env = field("path_env");
    let build_cwd = std::path::PathBuf::from(field("build_cwd"));
    let expected_dirs = clang_resolve::path_dirs_in(std::ffi::OsStr::new(&path_env), &build_cwd);
    let dir_count: usize = field("path_dir_count")
        .parse()
        .expect("path_dir_count must be a number");
    let recorded_dirs: Vec<std::path::PathBuf> = (0..dir_count)
        .map(|i| std::path::PathBuf::from(field(&format!("path_dir{i}"))))
        .collect();
    assert_eq!(
        recorded_dirs, expected_dirs,
        "recorded PATH dirs must match the resolver's enumeration"
    );
    assert!(
        !recorded_dirs.is_empty(),
        "at least one PATH dir must be watched"
    );
    // The recorded candidates must equal the resolver's enumeration,
    // and their live permission bits must still match.
    let expected_cands =
        clang_resolve::candidate_files_in("clang-18", std::ffi::OsStr::new(&path_env), &build_cwd);
    let cand_count: usize = field("candidate_count")
        .parse()
        .expect("candidate_count must be a number");
    let recorded: Vec<(std::path::PathBuf, u32)> = (0..cand_count)
        .map(|i| {
            let path = std::path::PathBuf::from(field(&format!("candidate{i}_path")));
            let mode = u32::from_str_radix(&field(&format!("candidate{i}_mode")), 8)
                .unwrap_or_else(|_| panic!("candidate{i}_mode must be octal"));
            (path, mode)
        })
        .collect();
    let recorded_paths: Vec<std::path::PathBuf> =
        recorded.iter().map(|(path, _)| path.clone()).collect();
    assert_eq!(
        recorded_paths, expected_cands,
        "recorded candidates must match the resolver's enumeration"
    );
    candidate_modes_match_live(&recorded)
        .expect("recorded candidate bits must match the live files");
}

/// Rerun-line emission pin (fix round 4, item 10N): the build must
/// print `cargo:rerun-if-changed` for every existing PATH directory
/// and every non-selected candidate — the recorded-set test pins the
/// receipt, but only this pin fails when the emission loop itself is
/// deleted while receipt generation stays. Source-text pin over
/// `build.rs`: deleting either `println` line fails here (proven by
/// mutation, see the report).
#[test]
fn identity_build_emits_rerun_lines_for_path_watches() {
    let build = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"))
        .expect("read build.rs");
    for needle in [
        "println!(\"cargo:rerun-if-changed={}\", dir.display());",
        "println!(\"cargo:rerun-if-changed={}\", candidate.display());",
    ] {
        assert!(
            build.contains(needle),
            "build.rs must emit rerun-if-changed for PATH watches: missing {needle:?}"
        );
    }
}

/// Hermetic proof for the chmod window: `path_dirs_in` resolves
/// absolute, empty (= cwd), and relative entries to absolute dirs
/// (deduped), and the recorded-vs-live bit comparison passes
/// unflipped but fails after a chmod-only flip.
#[test]
fn path_dirs_and_candidate_modes_close_the_chmod_window() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("p11scope-path-dirs-{}", std::process::id()));
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).expect("first dir");
    std::fs::create_dir_all(&second).expect("second dir");
    std::fs::write(first.join("clang-18"), "#!/bin/sh\nexit 0\n").expect("first file");
    std::fs::write(second.join("clang-18"), "#!/bin/sh\nexit 0\n").expect("second file");
    for file in [first.join("clang-18"), second.join("clang-18")] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("mode");
    }
    // Absolute entries resolve as-is, in order, deduped.
    let path = std::env::join_paths([&first, &second, &first]).expect("join");
    assert_eq!(
        clang_resolve::path_dirs_in(&path, &root),
        vec![first.clone(), second.clone()]
    );
    // Empty entries mean the cwd; relative entries join it.
    let rel = std::env::join_paths(["", "second"]).expect("join");
    assert_eq!(
        clang_resolve::path_dirs_in(&rel, &root),
        vec![root.clone(), second.clone()]
    );
    // Unflipped bits compare clean …
    let recorded = vec![
        (first.join("clang-18"), 0o755),
        (second.join("clang-18"), 0o755),
    ];
    candidate_modes_match_live(&recorded).expect("unflipped bits match");
    // … and a chmod-only flip (no mtime cargo watches) fails loudly.
    std::fs::set_permissions(
        second.join("clang-18"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("flip");
    assert!(
        candidate_modes_match_live(&recorded).is_err(),
        "a chmod-only flip must fail the bit comparison"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Behavioral anchor coverage (fix round 3, items 3W1F3-01/02): the
/// host harness compiles the REAL `vma_identity.c` for host (stub maps +
/// captured emits, zero production-C changes) and stages the
/// replay/arena sequences against the real C logic: (a)
/// X→DUP→drop→Y-remap→replay → CONFLICT + no install + no second OK;
/// (b) between-pass change → OK; (c) same-address replay → OK; (d)
/// fresh generation after CONFLICT → clean OK; (e) straddling VMA →
/// BAD_SHAPE; (f) misaligned/oversized/past-slots/zero-inode shapes →
/// BAD_SHAPE (+ anonymous VMAs silently skipped); (g) contained VMA →
/// OK. Unprivileged and permanent; the strict verifier gate still proves
/// the BPF object loads (re-run as root, see the report).
#[test]
fn anchor_host_harness_replay_and_arena_behavior() {
    let native = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/native");
    let source = native.join("vma_identity_harness.c");
    assert!(
        source.is_file(),
        "harness source {} must exist",
        source.display()
    );
    let work = std::env::temp_dir().join(format!("p11scope-anchor-harness-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("harness work dir");
    let binary = work.join("vma_identity_harness");
    let cwd = std::env::current_dir().expect("cwd");
    let compiler = clang_resolve::resolve_executable_in(
        "clang-18",
        &std::env::var_os("PATH").unwrap_or_default(),
        &cwd,
    )
    .expect("host harness needs an executable clang-18 on PATH");
    let compile = std::process::Command::new(&compiler)
        // Default language mode (GNU `typeof` for the map macros, as in
        // the BPF build); only the BPF-only attribute is silenced.
        .args([
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("spawn host cc for the harness");
    assert!(
        compile.status.success(),
        "harness must compile -Werror-clean: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    // (scenario, ASSERT lines that must appear — the harness exits
    // nonzero on any failed check, and these lines pin the evidence
    // shape so a vacuous PASS cannot slip through).
    for (scenario, asserts) in [
        (
            "replay-remap-conflict",
            &[
                "ASSERT slot0_installs_x",
                "ASSERT dup_aliases_slot0",
                "ASSERT conflict_on_remap_replay",
                "ASSERT no_second_ok",
                "ASSERT y_not_installed",
                "ASSERT x_still_rooted_at_slot0",
                "ASSERT slot1023_bookkeeping_kept",
            ][..],
        ),
        (
            "between-pass-change",
            &[
                "ASSERT ok_first_install",
                "ASSERT ok_on_between_pass_change",
                "ASSERT stale_x_cleared",
                "ASSERT y_installed_at_slot5",
                "ASSERT bookkeeping_follows_new_gen",
            ][..],
        ),
        (
            "same-address-replay",
            &[
                "ASSERT ok_first_install",
                "ASSERT ok_on_same_address_replay",
                "ASSERT anchors_unchanged",
            ][..],
        ),
        (
            "fresh-gen-after-conflict",
            &[
                "ASSERT conflict_in_old_gen",
                "ASSERT ok_after_conflict_in_fresh_gen",
                "ASSERT y_installed_cleanly",
            ][..],
        ),
        (
            "straddle-bad-shape",
            &["ASSERT bad_shape_on_straddle", "ASSERT nothing_installed"][..],
        ),
        (
            "straddle-contained-length",
            &[
                "ASSERT bad_shape_on_contained_length_straddle",
                "ASSERT contained_length_straddle_installs_nothing",
            ][..],
        ),
        (
            "shape-cases",
            &[
                "ASSERT bad_shape_on_misaligned",
                "ASSERT no_install_on_misaligned",
                "ASSERT bad_shape_on_oversized",
                "ASSERT no_install_on_oversized",
                "ASSERT bad_shape_past_slots",
                "ASSERT no_install_past_slots",
                "ASSERT bad_shape_on_zero_inode",
                "ASSERT no_install_on_zero_inode",
                "ASSERT anon_silently_skipped",
                "ASSERT nothing_installed_anywhere",
            ][..],
        ),
        (
            "contained-install",
            &[
                "ASSERT ok_on_contained_install",
                "ASSERT contained_vma_installed",
            ][..],
        ),
    ] {
        let run = std::process::Command::new(&binary)
            .arg(scenario)
            .output()
            .expect("run harness scenario");
        let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
        assert!(
            run.status.success(),
            "harness scenario {scenario} must pass:\n{stdout}\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(
            stdout.contains(&format!("SCENARIO {scenario} PASS")),
            "scenario {scenario} must print PASS:\n{stdout}"
        );
        for needle in asserts {
            assert!(
                stdout.contains(needle),
                "scenario {scenario} must show {needle}:\n{stdout}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// Compiler resolution skips non-executable PATH decoys: an earlier
/// readable-but-not-executable `clang-18` must not win over the real
/// executable later on PATH (the round-2 provenance finding). Hermetic:
/// synthetic PATH roots under `TMPDIR`, no rebuild needed. Relative PATH
/// entries resolve against the given cwd to an absolute path, so the
/// caller executes exactly what was resolved.
#[test]
fn compiler_resolution_skips_non_executable_decoys() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("p11scope-clang-resolve-{}", std::process::id()));
    let decoy = root.join("decoy");
    let real = root.join("real");
    std::fs::create_dir_all(&decoy).expect("decoy dir");
    std::fs::create_dir_all(&real).expect("real dir");
    std::fs::write(decoy.join("clang-18"), "not a compiler\n").expect("decoy file");
    std::fs::write(real.join("clang-18"), "#!/bin/sh\nexit 0\n").expect("real file");
    std::fs::set_permissions(
        decoy.join("clang-18"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("decoy non-executable");
    std::fs::set_permissions(
        real.join("clang-18"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("real executable");
    // The absolute `PATH` hit itself (the caller canonicalizes
    // separately for the realpath field).
    let hit = real.join("clang-18");
    // The fixture discriminates: the old `is_file` predicate would have
    // taken the decoy.
    assert!(decoy.join("clang-18").is_file());
    assert!(!clang_resolve::is_executable_file(&decoy.join("clang-18")));
    assert!(clang_resolve::is_executable_file(&real.join("clang-18")));
    let path = std::env::join_paths([&decoy, &real]).expect("join");
    let resolved =
        clang_resolve::resolve_executable_in("clang-18", &path, &root).expect("must resolve");
    assert!(resolved.is_absolute());
    assert_eq!(resolved, hit);
    // Unusable-but-bit-set shadowing file (fix round 3, item 12):
    // mode 0641 carries an exec bit yet refuses a builder who holds
    // no owner-x — `execvp` skips it, and so must the resolver. (Root
    // bypasses permission checks, so under euid 0 the shadow IS
    // executable and must resolve first — `execvp` agreement either
    // way.)
    let shadow = root.join("shadow");
    std::fs::create_dir_all(&shadow).expect("shadow dir");
    std::fs::write(shadow.join("clang-18"), "#!/bin/sh\nexit 0\n").expect("shadow file");
    std::fs::set_permissions(
        shadow.join("clang-18"),
        std::fs::Permissions::from_mode(0o641),
    )
    .expect("shadow mode");
    assert!(shadow.join("clang-18").is_file());
    assert_ne!(
        shadow
            .join("clang-18")
            .metadata()
            .expect("shadow metadata")
            .permissions()
            .mode()
            & 0o111,
        0,
        "the fixture must carry exec bits (else it proves nothing)"
    );
    if unsafe { libc::geteuid() } == 0 {
        assert!(clang_resolve::is_executable_file(&shadow.join("clang-18")));
        let path = std::env::join_paths([&shadow, &real]).expect("join");
        assert_eq!(
            clang_resolve::resolve_executable_in("clang-18", &path, &root),
            Some(shadow.join("clang-18")),
            "root executes any exec-bit file, like execvp-as-root"
        );
    } else {
        // The fixture is genuinely unusable: spawning it fails EACCES …
        let err = std::process::Command::new(shadow.join("clang-18"))
            .output()
            .expect_err("spawning the shadow must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EACCES),
            "the shadow must refuse execution with EACCES"
        );
        // … and the resolver must skip it for the usable hit.
        assert!(!clang_resolve::is_executable_file(&shadow.join("clang-18")));
        let path = std::env::join_paths([&shadow, &real]).expect("join");
        assert_eq!(
            clang_resolve::resolve_executable_in("clang-18", &path, &root),
            Some(real.join("clang-18")),
            "an EACCES shadow must not win over a usable compiler"
        );
    }
    // No executable anywhere resolves to nothing.
    let empty = root.join("empty");
    std::fs::create_dir_all(&empty).expect("empty dir");
    let path = std::env::join_paths([&decoy, &empty]).expect("join");
    assert_eq!(
        clang_resolve::resolve_executable_in("clang-18", &path, &root),
        None
    );
    // Relative PATH entries resolve against the given cwd, absolutely.
    let resolved =
        clang_resolve::resolve_executable_in("clang-18", std::ffi::OsStr::new("real"), &root)
            .expect("relative entry resolves");
    assert!(resolved.is_absolute());
    assert_eq!(resolved, hit);
    // Candidates list every existing file, executable or not.
    let path = std::env::join_paths([&decoy, &real]).expect("join");
    let mut candidates = clang_resolve::candidate_files_in("clang-18", &path, &root);
    candidates.sort();
    assert_eq!(
        candidates,
        vec![decoy.join("clang-18"), real.join("clang-18")]
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The executability probe ignores ambient-PATH `test` shadows (fix
/// round 4, item 12): a hostile `test` earlier on `PATH` — one that
/// always fails and marks a canary when executed — must change
/// neither the probe outcome nor execute at all, because the probe
/// runs an absolute path, never a `PATH` search. The supervisor
/// stages the shadow and re-runs this same test binary as a child
/// with the hostile `PATH` (mutating the process `PATH` in-thread
/// would race parallel tests); the child asserts the probe outcomes.
#[test]
fn compiler_probe_ignores_ambient_path_test_shadows() {
    use std::os::unix::fs::PermissionsExt as _;
    if std::env::var_os("P11SCOPE_PROBE_SHADOW_CHILD").is_some() {
        let usable = std::env::var_os("P11SCOPE_PROBE_USABLE").expect("child usable path");
        let refused = std::env::var_os("P11SCOPE_PROBE_REFUSED").expect("child refused path");
        let canary = std::env::var_os("P11SCOPE_PROBE_CANARY").expect("child canary path");
        assert!(
            clang_resolve::is_executable_file(std::path::Path::new(&usable)),
            "a usable file must probe executable under a hostile PATH test shadow"
        );
        assert!(
            !clang_resolve::is_executable_file(std::path::Path::new(&refused)),
            "a non-executable file must probe refused under a hostile PATH test shadow"
        );
        assert!(
            !std::path::Path::new(&canary).is_file(),
            "the hostile PATH test must never execute"
        );
        return;
    }
    let root = std::env::temp_dir().join(format!("p11scope-test-shadow-{}", std::process::id()));
    let hostile = root.join("hostile");
    std::fs::create_dir_all(&hostile).expect("hostile dir");
    let canary = root.join("test-executed");
    std::fs::write(
        hostile.join("test"),
        format!("#!/bin/sh\ntouch {}\nexit 1\n", canary.display()),
    )
    .expect("hostile test");
    std::fs::set_permissions(hostile.join("test"), std::fs::Permissions::from_mode(0o755))
        .expect("hostile executable");
    let usable = root.join("usable");
    let refused = root.join("refused");
    std::fs::write(&usable, "#!/bin/sh\nexit 0\n").expect("usable file");
    std::fs::write(&refused, "not executable\n").expect("refused file");
    std::fs::set_permissions(&usable, std::fs::Permissions::from_mode(0o755)).expect("mode");
    std::fs::set_permissions(&refused, std::fs::Permissions::from_mode(0o644)).expect("mode");
    // At least one absolute probe binary must exist for this proof to
    // mean anything (a bare loader environment has coreutils).
    assert!(
        std::path::Path::new("/usr/bin/test").is_file()
            || std::path::Path::new("/bin/test").is_file(),
        "an absolute test probe must exist"
    );
    let saved = std::env::var_os("PATH").unwrap_or_default();
    let mut shadowed = hostile.as_os_str().to_os_string();
    if !saved.is_empty() {
        shadowed.push(":");
        shadowed.push(&saved);
    }
    let child = std::process::Command::new(std::env::current_exe().expect("own test binary"))
        .arg("--exact")
        .arg("compiler_probe_ignores_ambient_path_test_shadows")
        .env("PATH", &shadowed)
        .env("P11SCOPE_PROBE_SHADOW_CHILD", "1")
        .env("P11SCOPE_PROBE_USABLE", &usable)
        .env("P11SCOPE_PROBE_REFUSED", &refused)
        .env("P11SCOPE_PROBE_CANARY", &canary)
        .output()
        .expect("spawn shadowed probe child");
    assert!(
        child.status.success(),
        "shadowed probe child must pass:\n{}",
        String::from_utf8_lossy(&child.stdout)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Extract the kernel errno from a loader failure's syscall-carrying variants.
/// Object-side variants (parse, relocation) yield `None`: they never touched
/// the kernel, so they must fail the gate rather than pass as unprivileged.
fn map_errno(error: &aya::maps::MapError) -> Option<i32> {
    match error {
        aya::maps::MapError::CreateError { io_error, .. } => io_error.raw_os_error(),
        aya::maps::MapError::IoError(io_error) => io_error.raw_os_error(),
        aya::maps::MapError::SyscallError(sys) => sys.io_error.raw_os_error(),
        _ => None,
    }
}

fn prog_errno(error: &aya::programs::ProgramError) -> Option<i32> {
    match error {
        aya::programs::ProgramError::LoadError { io_error, .. } => io_error.raw_os_error(),
        aya::programs::ProgramError::SyscallError(sys) => sys.io_error.raw_os_error(),
        aya::programs::ProgramError::MapError(error) => map_errno(error),
        _ => None,
    }
}

fn syscall_errno(error: &aya::EbpfError) -> Option<i32> {
    match error {
        aya::EbpfError::MapError(error) => map_errno(error),
        aya::EbpfError::ProgramError(error) => prog_errno(error),
        aya::EbpfError::BtfError(aya::BtfError::LoadError { io_error, .. }) => {
            io_error.raw_os_error()
        }
        _ => None,
    }
}

/// D2a STRICT loader gate (mandatory, privileged): aya takes the clang
/// object through parse, CO-RE relocation against READABLE host BTF, map
/// creation, and verification of BOTH programs. Every program-load error
/// fails this gate — no permission-errno acceptance here, because
/// verifier rejections arrive as `EACCES` and must never pass as
/// "unprivileged". Run as root with `--ignored`. Records the kernel
/// release, the BTF identity (path, size, sha256), and both verified
/// program fds; on failure the kernel verifier log is printed.
#[test]
#[ignore = "privileged: verifies both identity programs through the kernel verifier"]
fn identity_loader_strict_gate_requires_btf_and_both_programs() {
    let btf = aya::Btf::from_sys_fs().expect("strict gate requires readable host BTF");
    let loaded = match ii::load_identity_object_strict(&btf) {
        Ok(loaded) => loaded,
        Err(error) => {
            if let Some(log) = ii::verifier_log_of(&error) {
                eprintln!("W3-1 strict gate verifier log:\n{log}");
            }
            panic!("strict gate: identity object failed to verify: {error:#}");
        }
    };
    // The strict constructor required both program fds; prove they are
    // open and distinct here, and that the receipt's object still carries
    // both verified programs.
    assert!(
        loaded.ebpf.program(ii::ANCHOR_PROGRAM).is_some(),
        "receipt object carries the anchor program"
    );
    assert!(
        loaded.ebpf.program(ii::TARGET_PROGRAM).is_some(),
        "receipt object carries the target program"
    );
    use std::os::fd::AsRawFd as _;
    let anchor = loaded.anchor_fd.as_raw_fd();
    let target = loaded.target_fd.as_raw_fd();
    assert_ne!(anchor, target, "both programs must hold distinct fds");
    for (name, fd) in [("anchor", anchor), ("target", target)] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "{name} program fd {fd} must be open");
    }
    // BTF identity: the exact bytes relocation consumed.
    let btf_bytes = std::fs::read("/sys/kernel/btf/vmlinux").expect("read host BTF for identity");
    let mut release = [0 as libc::c_char; 65];
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut uts) }, 0, "uname");
    for (slot, byte) in release.iter_mut().zip(uts.release.iter()) {
        *slot = *byte;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(release.as_ptr()) }.to_string_lossy();
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(&btf_bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    eprintln!(
        "W3-1 strict gate LOADED: kernel {release}, BTF /sys/kernel/btf/vmlinux ({} bytes, sha256 {hex}), anchor fd {anchor}, target fd {target}",
        btf_bytes.len()
    );
}

/// Explicitly-unprivileged smoke: the clang object parses, relocates, and
/// reaches map-creation syscalls. Accepts ONLY a permission errno from a
/// syscall (an unprivileged runner) or a full unverified load (a
/// privileged context); object-side failures panic. Makes NO verification
/// claim — programs are never loaded on this path (pinned by
/// `none_btf_load_never_verifies_programs` below).
#[test]
fn identity_loader_unprivileged_smoke() {
    match ii::load_identity_object_unverified(None) {
        Ok(_) => eprintln!(
            "W3-1 loader smoke: object parsed, maps created (privileged context); programs NOT verified here"
        ),
        Err(ii::LoadError::Ebpf(other))
            if matches!(
                syscall_errno(&other),
                Some(libc::EPERM) | Some(libc::EACCES)
            ) =>
        {
            eprintln!(
                "W3-1 loader smoke NEEDS_CONTEXT for verification: permission errno ({other:#}); parse+relocation proven above"
            );
        }
        Err(other) => panic!("smoke: object-side or unexpected loader failure: {other:#?}"),
    }
}

/// The unverified path must never yield loaded programs: with `None` BTF
/// a privileged load creates maps but loads nothing, and an unprivileged
/// load fails at map creation. Either way no program verifies here.
#[test]
fn none_btf_load_never_verifies_programs() {
    if let Ok(ebpf) = ii::load_identity_object_unverified(None) {
        for name in [ii::ANCHOR_PROGRAM, ii::TARGET_PROGRAM] {
            let program = ebpf
                .program(name)
                .unwrap_or_else(|| panic!("{name} missing from loaded object"));
            assert!(
                program.fd().is_err(),
                "{name} must stay unloaded without BTF-backed verification"
            );
        }
    }
}

/// F6 uapi surface cross-checked against aya's generated bindings, an
/// independent copy of `linux/bpf.h`: every command number, the attach
/// type, map types, map flags, and the attr layouts bindgen exposes as
/// plain structs. (The `link_create` prefix with `iter_info`, the
/// `bpf_iter_link_info` task member, and the `bpf_map_info` prefix are
/// asserted against the host headers by the build-time C check instead:
/// bindgen nests those in anonymous unions awkward for `offset_of!`.)
#[test]
fn identity_uapi_constants_match_aya_bindings() {
    use aya_obj::generated::{
        BPF_F_MMAPABLE as GEN_MMAPABLE, BPF_F_WRONLY as GEN_WRONLY, bpf_attach_type, bpf_cmd,
        bpf_map_type,
    };
    assert_eq!(ii::BPF_LINK_CREATE, bpf_cmd::BPF_LINK_CREATE as u32);
    assert_eq!(ii::BPF_ITER_CREATE, bpf_cmd::BPF_ITER_CREATE as u32);
    assert_eq!(ii::BPF_MAP_CREATE, bpf_cmd::BPF_MAP_CREATE as u32);
    assert_eq!(ii::BPF_MAP_UPDATE_ELEM, bpf_cmd::BPF_MAP_UPDATE_ELEM as u32);
    assert_eq!(ii::BPF_MAP_DELETE_ELEM, bpf_cmd::BPF_MAP_DELETE_ELEM as u32);
    assert_eq!(
        ii::BPF_OBJ_GET_INFO_BY_FD,
        bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32
    );
    assert_eq!(ii::BPF_TRACE_ITER, bpf_attach_type::BPF_TRACE_ITER as u32);
    assert_eq!(
        ii::BPF_MAP_TYPE_HASH,
        bpf_map_type::BPF_MAP_TYPE_HASH as u32
    );
    assert_eq!(
        ii::BPF_MAP_TYPE_ARRAY,
        bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
    );
    assert_eq!(ii::BPF_F_WRONLY, GEN_WRONLY);
    assert_eq!(ii::BPF_F_MMAPABLE, GEN_MMAPABLE);
    // Attr layouts bindgen exposes as plain structs.
    use aya_obj::generated::{
        bpf_attr__bindgen_ty_2 as gen_map_elem, bpf_attr__bindgen_ty_9 as gen_obj_info,
        bpf_attr__bindgen_ty_18 as gen_iter_create,
    };
    use std::mem::offset_of;
    assert_eq!(
        size_of::<ii::IterCreateAttr>(),
        size_of::<gen_iter_create>()
    );
    assert_eq!(
        offset_of!(ii::IterCreateAttr, link_fd),
        offset_of!(gen_iter_create, link_fd)
    );
    assert_eq!(
        offset_of!(ii::IterCreateAttr, flags),
        offset_of!(gen_iter_create, flags)
    );
    assert_eq!(size_of::<ii::ObjGetInfoAttr>(), size_of::<gen_obj_info>());
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, bpf_fd),
        offset_of!(gen_obj_info, bpf_fd)
    );
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, info_len),
        offset_of!(gen_obj_info, info_len)
    );
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, info),
        offset_of!(gen_obj_info, info)
    );
    // The map-elem member carries `value`/`next_key` as a union at 16;
    // our attr fixes the update shape (`value`), same size and offsets.
    assert_eq!(size_of::<ii::MapElemAttr>(), size_of::<gen_map_elem>());
    assert_eq!(
        offset_of!(ii::MapElemAttr, map_fd),
        offset_of!(gen_map_elem, map_fd)
    );
    assert_eq!(
        offset_of!(ii::MapElemAttr, key),
        offset_of!(gen_map_elem, key)
    );
    assert_eq!(
        offset_of!(ii::MapElemAttr, flags),
        offset_of!(gen_map_elem, flags)
    );
}
