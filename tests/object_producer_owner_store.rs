//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 slice B: bounded object-call custody in the native owner.
//!
//! The native owner allocates, binds, scrubs and deletes one 432-byte
//! subordinate row per required object call; exec/exit roots report cleanup
//! failure to the checked fault cell before lifecycle bookkeeping. These
//! tests drive the real native fixture plus the real compiled object; no
//! model stands in for either.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/object_owner_fixture.rs"]
mod owner_fixture;

fn embedded_object(directory: &Path) -> PathBuf {
    let object = directory.join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    object
}

fn run_object_checker(object: &Path, mode: &str) -> String {
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", OBJECT_CHECKER])
        .arg(object)
        .arg(mode)
        .output()
        .expect("inspect actual object custody");
    assert!(
        output.status.success(),
        "object custody {mode} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from + start.len()..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source marker {end:?}"));
    &rest[..until]
}

#[test]
fn object_producer_owner_terminal_matrix() {
    owner_fixture::run_object_subcommand(
        "object_producer_owner_terminal_matrix",
        "object custody terminal matrix passed",
    );
}

#[test]
fn object_seeded_start_construction_preserves_immutable_binding() {
    owner_fixture::run_object_subcommand(
        "object_seeded_start_construction",
        "seeded START construction passed",
    );
}

#[test]
fn object_aggregate_start_preserves_zero_image_marker_and_padding() {
    owner_fixture::run_object_subcommand(
        "object_aggregate_start_construction",
        "aggregate START construction passed",
    );
}

#[test]
fn object_seeded_start_failures_preserve_cleanup_authority() {
    owner_fixture::run_object_subcommand(
        "object_seeded_start_failures",
        "seeded START failure controls passed",
    );
}

#[test]
fn object_seeded_start_emitted_caller_and_causal_mutations() {
    let directory = tempfile::tempdir().expect("seeded START emitted caller");
    let object = embedded_object(directory.path());
    let output = Command::new("python3")
        .args(["-I", "tests/python/test_entry_object.py", "--seeded-object"])
        .arg(object)
        .arg("EntryObjectTests.test_seeded_start_caller_contract")
        .output()
        .expect("run actual seeded START caller and mutations");
    let result = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "seeded START caller: {result}");
    assert!(result.contains("Ran 1 test"), "zero selection: {result}");
    assert!(!result.contains("skipped"), "skipped proof: {result}");
}

#[test]
fn object_producer_side_state_n_and_n_plus_one() {
    owner_fixture::run_object_subcommand(
        "object_producer_side_state_n_and_n_plus_one",
        "object custody side state passed",
    );
}

#[test]
fn object_producer_missing_side_state_faults_before_return() {
    owner_fixture::run_object_subcommand(
        "object_producer_missing_side_state_faults_before_return",
        "object custody missing side state passed",
    );
    let directory = tempfile::tempdir().expect("temporary object custody return check");
    let object = embedded_object(directory.path());
    let report = run_object_checker(&object, "return-fault");
    println!("{report}");
    // Missing/mismatched side state permits no new target read and no
    // successful object tail: the ready/agreement queries fault before
    // the 608-byte reservation, and emission reads only run between a
    // successful reservation and the drain retire. Query plus retire
    // stays the drain: a monolithic native drain would nest one level
    // deeper than the 512-byte call-chain budget allows, so its name
    // must stay out of the drain. (Slice D moves the retire after
    // emission; the pre-read fault arms keep their position ahead of
    // every target read.)
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root");
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    assert!(
        !returned.contains("p11_object_return_remove"),
        "no monolithic native drain: query plus retire fits the chain budget"
    );
    let query = returned
        .find("p11_object_side_get(&key, descriptor, 0)")
        .expect("return must query the side row before retiring");
    let agree = returned
        .find("row.descriptor_index == descriptor")
        .expect("drain must check attached-descriptor agreement");
    let abi = returned
        .find("row.layout == 0 || u32::from(row.layout) == layout_code")
        .expect("drain must check retained-ABI agreement");
    assert_eq!(
        returned.matches("owned_start_remove(&key, true)").count(),
        8,
        "ordinary, ready, agreement, aggregate, image, continuity-gate, reserve-failure and emission arms each retire"
    );
    let drain_retire = returned
        .rfind("owned_start_remove(&key, true)")
        .expect("emission arm retires");
    assert!(
        query < drain_retire,
        "drain must query before retiring (retire deletes the row)"
    );
    let fault = returned
        .find("p11_object_fault()")
        .expect("failed settle must fault");
    let reserve = returned
        .find("reserve::<ObjectEventRecord>")
        .expect("slice D reserves the complete object record");
    let fill = returned
        .find("object_fill_return(")
        .expect("emission fills after the reservation");
    assert!(
        query < reserve && agree < reserve && abi < reserve && fault < reserve,
        "queries, agreement and fault must precede the object reservation"
    );
    assert!(
        reserve < fill && fill < drain_retire,
        "emission reads run between reservation and retire"
    );
    // Slice D emits the completed tail behind the required-object
    // marker: ordinary calls keep their single 368-byte reservation.
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        2,
        "return reserves exactly the ordinary and the object record forms"
    );
}

#[test]
fn object_producer_scalar_scope_flags_preserve_authority_discriminant() {
    use p11scope_ebpf_common::{
        FLAG_CGROUP_FILTER, FLAG_PAUSE_ENABLED, FLAG_PID_FILTER, FLAG_POLICY_AGGREGATE,
        FLAG_POLICY_ALLOWLISTED, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, FLAG_SYSTEM_FILTER,
        valid_config,
    };
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("BPF scope source");
    let word = source_between(&source, "fn scope_flags_word() -> u64 {", "\n}\n");
    let option = source_between(&source, "fn scope_flags() -> Option<u64> {", "\n}\n");
    assert_eq!(
        word.matches("scope_auth()").count(),
        1,
        "one real authority query"
    );
    assert_eq!(
        option.matches("scope_flags_word()").count(),
        1,
        "one scalar query"
    );
    let auth = source_between(
        &source,
        "fn scope_auth() -> Option<ScopeAuth> {",
        "fn scope_flags_word()",
    );
    assert!(auth.find("valid_config(flags)").unwrap() < auth.find("Some(ScopeAuth").unwrap());
    let mut valid = Vec::new();
    for scope in [FLAG_PID_FILTER, FLAG_CGROUP_FILTER, FLAG_SYSTEM_FILTER] {
        for policy in [
            FLAG_POLICY_ALLOWLISTED,
            FLAG_POLICY_AGGREGATE,
            FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
        ] {
            valid.push(scope | policy);
            if scope == FLAG_PID_FILTER {
                valid.push(scope | policy | FLAG_PAUSE_ENABLED);
            }
        }
    }
    // Independent finite configuration oracle, including every unknown bit.
    assert!(!valid_config(0));
    for flags in (0..512).chain((9..64).map(|bit| (1u64 << bit) | valid[0])) {
        assert_eq!(
            valid_config(flags),
            valid.contains(&flags),
            "flags={flags:#x}"
        );
    }
    assert!(valid.iter().all(|flags| *flags != 0));
    let fields = source_between(&source, "struct ScopeAuth {", "\n}\n");
    let mut harness =
        String::from("#![allow(dead_code)]\n#[derive(Clone, Copy)]\nstruct ScopeAuth {");
    harness.push_str(fields);
    harness.push_str("\n}\nfn scope_flags_word() -> u64 {");
    harness.push_str(word);
    harness.push_str("\n}\nfn scope_flags() -> Option<u64> {");
    harness.push_str(option);
    harness.push_str("\n}\n");
    harness.push_str(
        &r#"
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
static AUTH: Mutex<Option<ScopeAuth>> = Mutex::new(None);
static CALLS: AtomicUsize = AtomicUsize::new(0);
fn scope_auth() -> Option<ScopeAuth> {
    CALLS.fetch_add(1, Ordering::SeqCst);
    *AUTH.lock().unwrap()
}
fn set(flags: Option<u64>) {
    *AUTH.lock().unwrap() = flags.map(|flags| ScopeAuth {
        flags, tgid: 73, _pad: 0, generation_token: u64::MAX,
    });
    CALLS.store(0, Ordering::SeqCst);
}
fn main() {
    set(None);
    assert_eq!(scope_flags_word(), 0);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    set(None);
    assert_eq!(scope_flags(), None);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    for flags in __VALID__.into_iter().chain([0, 1u64 << 63, u64::MAX]) {
        // Synthetic high words test representation only; real scope_auth
        // refuses them through valid_config before returning a receipt.
        set(Some(flags));
        assert_eq!(scope_flags_word(), flags);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        set(Some(flags));
        assert_eq!(scope_flags(), if flags == 0 { None } else { Some(flags) });
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    }
}
"#
        .replace("__VALID__", &format!("{valid:?}")),
    );
    let directory = tempfile::tempdir().expect("actual scalar scope wrapper fixture");
    let input = directory.path().join("scope.rs");
    let binary = directory.path().join("scope");
    std::fs::write(&input, harness).expect("write actual wrapper bodies");
    let output = Command::new("rustc")
        .args(["+1.98.1", "--edition=2024"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("compile actual wrappers");
    assert!(
        output.status.success(),
        "scope wrappers: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        Command::new(binary)
            .status()
            .expect("run actual wrappers")
            .success()
    );
}

#[test]
fn object_producer_return_branches_preserve_owned_lifetimes() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("BPF return source");
    let dispatch = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "struct ReturnAccounting",
    );
    assert!(
        dispatch
            .contains("if unsafe { (*start).object_required } == 0 {\n        ordinary_return(")
    );
    assert!(dispatch.contains("} else {\n        object_return("));
    for forbidden in [
        "EVENTS.reserve",
        "account_return(",
        "capture_return_facts(",
        "let Some(&start)",
    ] {
        assert!(
            !dispatch.contains(forbidden),
            "dispatcher must not {forbidden}"
        );
    }
    let ordinary = source_between(&source, "fn ordinary_return(", "fn object_return(");
    let snapshot = ordinary
        .find("let start = unsafe { *start };")
        .expect("ordinary snapshot");
    let retire = ordinary
        .find("owned_start_remove(&key, true)")
        .expect("ordinary retirement");
    let account = ordinary
        .find("account_return(")
        .expect("ordinary accounting");
    let reads = ordinary
        .find("capture_return_facts(")
        .expect("ordinary private reads");
    assert!(snapshot < retire && retire < account && account < reads);
    let object = source_between(
        &source,
        "fn object_return(",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    assert!(
        !object.contains("let start = unsafe { *start }"),
        "object must retain only live raw START"
    );
    assert!(
        !object.contains("let ev = Event"),
        "object fills the reservation directly"
    );
    let fill = object
        .find("fill_call_event(")
        .expect("in-place initialization");
    let retire = object
        .find("emission_finalize(")
        .expect("checked terminal retirement");
    let submit = object
        .find("entry.submit(0)")
        .expect("submit only after retirement");
    assert!(fill < retire && retire < submit);
    for forbidden in [
        "(*start)",
        "&*start",
        "p11_object_side_get",
        "fill_call_event(",
    ] {
        assert!(
            !object[retire..].contains(forbidden),
            "no {forbidden} after terminal retirement"
        );
    }
}

#[test]
fn object_producer_cleanup_result_reaches_exec_exit_fault() {
    owner_fixture::run_object_subcommand(
        "object_producer_cleanup_result_reaches_exec_exit_fault",
        "object custody cleanup result passed",
    );
    let directory = tempfile::tempdir().expect("temporary object custody lifecycle check");
    let object = embedded_object(directory.path());
    let report = run_object_checker(&object, "exec-exit-fault");
    println!("{report}");
    // The fault fires on cleanup failure only, before lifecycle bookkeeping,
    // and never returns early: lifecycle continuation is mandatory.
    let source =
        std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF lifecycle roots");
    for (root, end, before) in [
        (
            "fn sched_process_exec_impl(_ctx: RawTracePointContext) -> u32 {",
            "fn sched_process_exit_impl",
            ["p11_instance_exec()", "scope_auth()"],
        ),
        (
            "fn sched_process_exit_impl(_ctx: RawTracePointContext) -> u32 {",
            "fn cookie_of<C>",
            ["p11_root_current_exit()", "pid_tgid as u32 !="],
        ),
    ] {
        let body = source_between(&source, root, end);
        let guard = "if unsafe { p11_owner_cleanup() } != 0 {";
        let opened = body
            .find(guard)
            .unwrap_or_else(|| panic!("{root} must read the cleanup result before lifecycle work"));
        let arm = &body[opened..];
        let closed = arm.find("\n    }\n").expect("guarded fault arm closes");
        let arm = &arm[..closed];
        assert!(
            arm.contains("p11_object_fault()"),
            "{root} must fault on cleanup failure"
        );
        assert!(
            !arm.contains("return"),
            "{root} must continue lifecycle bookkeeping after the fault"
        );
        let fault_at = opened + arm.find("p11_object_fault()").expect("fault site");
        for marker in before {
            let site = body
                .find(marker)
                .unwrap_or_else(|| panic!("{root} must still contain {marker}"));
            assert!(fault_at < site, "{root} must fault before {marker}");
        }
    }
}

/// G06/E2: side-insert success followed by a readback miss never
/// authorizes ready storage: explicit failure, no publication, no orphan
/// row, exactly settled lease, visible bookkeeping, foreign rows
/// untouched, fail-closed successors and converging repeated cleanup.
#[test]
fn object_owner_readback_failure_never_authorizes() {
    owner_fixture::run_object_subcommand(
        "object_producer_alloc_readback_failure_preserves_cleanup_authority",
        "object custody alloc readback passed",
    );
}

/// G06/E2 fix round 1: a failed orphan sweep keeps START, its count
/// and its lease instead of stranding a permanent zeroed row: explicit
/// failure, no authorization, eventual teardown cleanup, converging
/// repeats and an untouched sibling lease.
#[test]
fn object_owner_orphan_delete_failure_keeps_retry_route() {
    owner_fixture::run_object_subcommand(
        "object_producer_orphan_delete_failure_keeps_cleanup_authority",
        "object custody orphan delete failure passed",
    );
}

/// G06/E2: empty-lease refund failure stays visible: rows retire, the
/// failure is never lost or double-refunded, repeats stay failed, and
/// the sibling lease keeps its row, record and unit. Reconciles the
/// historical empty-lease shorthand (no defect reproduced; pinned).
#[test]
fn object_owner_empty_refund_failure_faults() {
    owner_fixture::run_object_subcommand(
        "object_producer_empty_lease_refund_failure_remains_visible",
        "object custody empty refund passed",
    );
}

/// G06/E2: a sweep-adjacent side lookup miss preserves custody: the
/// hidden orphan is kept intact (never deleted blindly) and later live
/// work sweeps it exactly once with exact accounting and proven scrub.
#[test]
fn object_owner_sweep_adjacent_lookup_preserves_custody() {
    owner_fixture::run_object_subcommand(
        "object_owner_sweep_adjacent_lookup_preserves_custody",
        "object custody sweep adjacent passed",
    );
}

#[test]
fn object_producer_compiled_frames_are_bounded() {
    let directory = tempfile::tempdir().expect("temporary object custody frame check");
    let object = embedded_object(directory.path());
    // Printed, not just carried in the assert message: with --nocapture this
    // is the map-allocation and frame/instruction measurement record.
    // The checker validates the object against the frozen inventory for
    // its exact profile: capacity (wide or default) crossed with
    // metadata (diagnostic or plain).
    let mode = match (
        cfg!(feature = "wide-detailed-2112"),
        cfg!(feature = "unsafe-unvalidated-metadata"),
    ) {
        (true, true) => "frames-wide-diagnostic",
        (true, false) => "frames-wide",
        (false, true) => "frames-diagnostic",
        (false, false) => "frames",
    };
    let report = run_object_checker(&object, mode);
    println!("{report}");
}

#[test]
fn object_producer_compiled_function_abis_fit_five_registers() {
    let directory = tempfile::tempdir().expect("temporary actual BPF ABI check");
    let object = embedded_object(directory.path());
    println!("{}", run_object_checker(&object, "function-abis"));
}

#[test]
fn object_producer_scalar_globals_are_exact_and_reachable() {
    let directory = tempfile::tempdir().expect("temporary scalar object capture check");
    let object = embedded_object(directory.path());
    let mode = if cfg!(feature = "stub-object-attributes") {
        "scalar-globals-p0"
    } else {
        "scalar-globals"
    };
    println!("{}", run_object_checker(&object, mode));
}

#[test]
fn object_producer_sweep_path_within_jump_budget() {
    // Both teardown sweeps run 512 slots per cleanup; every per-slot
    // branch multiplies into the kernel jump budget (live 8193-jump
    // reject). The path stays branch-lean by construction, with no
    // per-iteration carried accumulators: those multiply verifier
    // states instead (live 17k-state blowup). Bulk helpers and the
    // outlined sweep worker stay out for the same reason.
    let native =
        std::fs::read_to_string("crates/ebpf/native/task_owner.c").expect("read native owner");
    for forbidden in [
        "object_sweep_orphan_slot",
        "count_add",
        "u64 retired",
        "u64 swept",
    ] {
        assert!(
            !native.contains(forbidden),
            "sweep path must not carry {forbidden}"
        );
    }
    let sweep = source_between(
        &native,
        "for (u32 i = 0; i < P11SCOPE_OWNER_SLOT_BOUND; i++) {",
        "if (owner->start_count) {",
    );
    assert!(
        !sweep.contains("int retired = "),
        "START sweep must test retirement directly, not materialize it"
    );
    let orphans = source_between(&native, "/* Orphaned side rows", "#endif");
    assert!(
        orphans.contains("count(&ctl->abandoned_start);"),
        "orphan sweep must count per retired row"
    );
    assert!(
        !native.contains("return side ? -1 : 0;"),
        "remove tail must settle branchlessly"
    );
    assert!(
        native.contains("marker - 2 > OBJECT_DESCRIPTORS_COUNT - 2"),
        "marker range must fuse into one unsigned comparison"
    );
    assert!(
        native.contains("^ start_u64(start_value, OBJECT_CALL_START_IMAGE_OFF)"),
        "binding check must combine by xor"
    );
}

/// Actual emitted-object custody checks: exact owned-map allocation,
/// bounded leaf frames with no nested calls, bounded root call chains, and
/// fault-call placement. Modes: `frames`, `return-fault`, `exec-exit-fault`.
const OBJECT_CHECKER: &str = r##"
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path

checker = load_path(Path('scripts/check-bpf-map-defs.py'), 'object_custody_checker')

LEAF_FRAME_BOUND = 64
ROOT_CHAIN_BOUND = 512


def bodies_and_relocations(data):
    elf = checker.Elf(data)
    bodies = {(s[3], s[4]): s
              for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
    raws = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
    offsets = {elf.indices[name]: row[4] for name, (row, _) in elf.sections.items()}
    relocations = {}
    for row, raw in elf.sections.values():
        if row[1] == 9 and row[7] in {key[0] for key in bodies}:
            for at in range(0, len(raw), 16):
                address, info = struct.unpack_from('<QQ', raw, at)
                relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])
    return elf, raws, offsets, bodies, relocations


def only(bodies, name):
    matches = [key for key, symbol in bodies.items() if symbol[0] == name]
    assert len(matches) == 1, f'expected one defined {name}, saw {len(matches)}'
    return matches[0]


def body_of(raws, bodies, key):
    symbol = bodies[key]
    return raws[key[0]][key[1]:key[1] + symbol[5]]


def frame_of(body):
    insns = [struct.unpack_from('<BBhi', body, at) for at in range(0, len(body), 8)]
    depth, deepest = 0, None
    for index, (op, reg, offset, immediate) in enumerate(insns):
        if ((op & 7 in (2, 3) and reg & 15 == 10)
                or (op & 7 == 1 and reg >> 4 == 10)) and offset < 0:
            if -offset > depth:
                depth, deepest = -offset, ('off', index)
        if (index and op == 0x07 and immediate < 0
                and insns[index - 1][:2] == (0xbf, 0xa0 | (reg & 15))):
            if -immediate > depth:
                depth, deepest = -immediate, ('imm', index)
    return depth, deepest, insns


def file_offset(offsets, key, index, field):
    return offsets[key[0]] + key[1] + index * 8 + field


def pseudo_calls(raws, offsets, bodies, relocations, key):
    body = body_of(raws, bodies, key)
    calls = []
    for index in range(0, len(body) // 8):
        op, reg, _, immediate = struct.unpack_from('<BBhi', body, index * 8)
        if op != 0x85 or reg >> 4 != 1:
            continue
        relocation = relocations.get((key[0], key[1] + index * 8))
        if relocation and relocation[0] == 10:
            target = relocation[1]
            resolved = (target[3], target[4] + (immediate + 1) * 8)
        elif relocation:
            raise AssertionError(f'unknown call relocation in {bodies[key][0]}')
        else:
            resolved = (key[0], key[1] + index * 8 + (immediate + 1) * 8)
        assert resolved in bodies, f'unresolved call in {bodies[key][0]}'
        calls.append((index, resolved, file_offset(offsets, key, index, 4)))
    return calls


def longest_chain(raws, bodies, relocations, offsets, root):
    frames = {}

    def frame(key):
        if key not in frames:
            frames[key] = frame_of(body_of(raws, bodies, key))[0]
        return frames[key]

    done = {}

    def visit(key, path):
        assert key not in path, f'call cycle through {bodies[key][0]}'
        if key in done:
            return done[key]
        best, best_path = 0, ()
        for _, target, _ in pseudo_calls(raws, offsets, bodies, relocations, key):
            total, sub = visit(target, path + (key,))
            if total > best:
                best, best_path = total, sub
        # Conservative 32 B floor (>= kernel): round every subprogram on
        # the path up to 32 bytes with a 32-byte floor, even a stackless
        # leaf: round_up(max(depth, 1), 32) per check_max_stack_depth. An
        # empty frame still costs a level, so the static chain counts it
        # too.
        rounded = ((max(frame(key), 1) + 31) // 32) * 32
        done[key] = (rounded + best, (bodies[key][0],) + best_path)
        return done[key]

    return visit(root, ())


def check_maps(report, diagnostic=False, wide=False):
    allowed = checker.DIAGNOSTIC_GLOBAL_HELPERS if diagnostic else frozenset()
    maps, programs, symbols = checker.inspect(sys.argv[1], allowed)
    variant = None
    if diagnostic or wide:
        # Explicit feature mode: allow only its exact decoder helpers, then
        # require the entire frozen map/program/symbol inventory for the
        # exact capacity/metadata profile. Plain 'frames' keeps its
        # object-relative checks below with no frozen comparison.
        variant = ('wide-' if wide else '') + ('diagnostic' if diagnostic else 'default')
    if variant:
        checker.validate_inventory(variant, maps, programs, symbols)
    for name in ('OBJECT_START', 'OBJECT_DESCRIPTORS', 'OBJECT_ZERO'):
        assert name in maps, f'missing owned map {name}'
    start = maps['OBJECT_START']
    assert (start['type'], start['key_size'], start['value_size'], start['flags']) == (1, 16, 432, 0), start
    assert start['max_entries'] == maps['START']['max_entries'], (start, maps['START'])
    descriptors = maps['OBJECT_DESCRIPTORS']
    assert (descriptors['type'], descriptors['key_size'], descriptors['value_size'],
            descriptors['max_entries'], descriptors['flags']) == (2, 4, 16, 105, 128), descriptors
    zero = maps['OBJECT_ZERO']
    assert (zero['type'], zero['key_size'], zero['value_size'],
            zero['max_entries'], zero['flags']) == (2, 4, 432, 1, 128), zero
    for name in ('OBJECT_START', 'OBJECT_DESCRIPTORS', 'OBJECT_ZERO', 'START'):
        got = maps[name]
        report.append(f"map {name}: type={got['type']} key={got['key_size']} "
                      f"value={got['value_size']} max={got['max_entries']} flags={got['flags']}")


def check_leaves(data, report):
    elf, raws, offsets, bodies, relocations = bodies_and_relocations(data)
    text = elf.indices['.text']
    leaves = {}
    # No monolithic native drain exists: query plus retire is the drain, so
    # the retired name stays out of the object. Re-adding it nests one level
    # deeper than the call-chain budget below allows.
    for missing in ('p11_object_return_remove',):
        matches = [key for key, symbol in bodies.items() if symbol[0] == missing]
        assert not matches, f'{missing} must stay out of the BPF object'
        report.append(f'absent {missing}: query-plus-retire drain pinned')
    # The constructor keeps the existing scalar lease/refund boundaries for
    # admission complexity. Query and fault remain true leaves. All own frames
    # stay bounded, and complete constructor paths count in the root budget.
    for name in ('p11_owner_start_begin', 'p11_owner_start_aggregate', 'p11_object_side_get', 'p11_object_fault'):
        key = only(bodies, name)
        symbol = bodies[key]
        assert symbol[3] == text and symbol[5], f'{name} must be a defined .text function'
        depth, deepest, _ = frame_of(body_of(raws, bodies, key))
        assert depth <= LEAF_FRAME_BOUND, f'{name} frame {depth} exceeds {LEAF_FRAME_BOUND}'
        leaves[name] = (key, depth, deepest)
        report.append(f'helper {name}: frame={depth}')
        nested = pseudo_calls(raws, offsets, bodies, relocations, key)
        if name in ('p11_owner_start_begin', 'p11_owner_start_aggregate'):
            children = {bodies[target][0] for _, target, _ in nested}
            assert children == {'p11_owner_lease', 'p11_owner_refund'}, \
                f'{name} must retain only scalar lease/refund children: {children}'
            if name == 'p11_owner_start_aggregate':
                # Aggregate creates no identity/side custody. Ambiguous old
                # invocations may still require checked side retirement.
                maps_section = elf.indices['.maps']
                map_names = {symbol[4]: symbol[0] for symbol in elf.symbols
                             if symbol[3] == maps_section and symbol[1] & 15 == 1}
                referenced = set()
                map_loads = {}
                for (section, address), (kind, target) in relocations.items():
                    if section != key[0] or not key[1] <= address < key[1]+symbol[5] or kind != 1:
                        continue
                    immediate = struct.unpack_from('<i', raws[section], address+4)[0]
                    mapped = (map_names.get(target[4]+immediate)
                              if target[1] & 15 == 3 and target[3] == maps_section else target[0])
                    referenced.add(mapped)
                    map_loads[address] = mapped
                assert {'START', 'OBJECT_ZERO'} <= referenced, f'aggregate zero-prefix maps: {referenced}'
                assert 'TASK_COOKIE' not in referenced, f'aggregate identity mint: {referenced}'
                _, _, instructions = frame_of(body_of(raws, bodies, key))
                updates = [index for index, (op, reg, _, immediate) in enumerate(instructions)
                           if op == 0x85 and reg >> 4 == 0 and immediate == 2]
                assert len(updates) == 1, f'aggregate must have only its START insert: {updates}'
                for update in updates:
                    destination = None
                    for index in range(update-1, -1, -1):
                        op, reg, _, _ = instructions[index]
                        if op == 0x85:
                            break
                        if reg & 15 == 1 and (op == 0x18 or op & 7 in (1, 4, 7)):
                            destination = map_loads.get(key[1]+index*8) if op == 0x18 else None
                            break
                    assert destination == 'START', f'aggregate side/unproven insertion: {destination}'
                assert not any(op == 0x85 and reg >> 4 == 0 and immediate in (4, 112, 114)
                               for op, reg, _, immediate in instructions), 'aggregate target read'
        else:
            assert not nested, f'{name} must make no nested BPF call'
    return leaves


def check_function_abis(data, report):
    elf = checker.Elf(data)
    btf = checker.Btf(elf.sections['.BTF'][1])
    functions = [node for node in btf.types[1:] if node[0] == 12]
    assert functions, 'missing emitted BTF functions'
    names = {node[1] for node in functions}
    expected = {'object_fill_return', 'object_emit_find', 'object_emit_get_attributes'}
    assert expected <= names, f'missing actual return wrappers: {expected - names}'
    over = []
    for node in functions:
        proto = btf.types[node[2]]
        assert proto[0] == 13, f'{node[1]} missing emitted FUNC_PROTO'
        if proto[3] > 5:
            over.append((node[1], proto[3]))
        if node[1] in expected:
            report.append(f'BPF ABI {node[1]}: {proto[3]} arguments')
    assert not over, f'emitted BPF functions exceed five-register ABI: {over}'
    report.append(f'BPF ABI: all {len(functions)} emitted functions <=5 arguments')


def check_roots(data, report):
    elf, raws, offsets, bodies, relocations = bodies_and_relocations(data)
    roots = sorted(key for key, symbol in bodies.items()
                   if symbol[0] in ('p11_return', 'sched_process_exec', 'sched_process_exit')
                   or symbol[0] == 'p11_entry' or symbol[0].startswith('p11_entry_'))
    assert roots, 'missing entry/return/exec/exit roots'
    assert any(bodies[key][0] == 'p11_return' for key in roots), 'missing p11_return root'
    for key in roots:
        total, path = longest_chain(raws, bodies, relocations, offsets, key)
        body = body_of(raws, bodies, key)
        depth = frame_of(body)[0]
        assert total <= ROOT_CHAIN_BOUND, \
            f"{bodies[key][0]} call chain {total} exceeds {ROOT_CHAIN_BOUND}: {' > '.join(path)}"
        report.append(f"root {bodies[key][0]}: frame={depth} insns={len(body) // 8} "
                      f'chain={total} path={" > ".join(path)}')
    return roots


def fault_calls_to(data, root_name):
    elf, raws, offsets, bodies, relocations = bodies_and_relocations(data)
    fault = only(bodies, 'p11_object_fault')
    root = only(bodies, root_name)
    # Outlined return branches remain part of the root's fault obligation.
    # Walk the actual reachable graph; never substitute a symbol-presence check.
    pending = [root]
    visited = set()
    calls = []
    while pending:
        caller = pending.pop()
        if caller in visited:
            continue
        visited.add(caller)
        for call in pseudo_calls(raws, offsets, bodies, relocations, caller):
            if call[1] == fault:
                calls.append(call)
            else:
                pending.append(call[1])
    return calls


def check_frames(data, report, diagnostic=False, wide=False):
    check_maps(report, diagnostic, wide)
    leaves = check_leaves(data, report)
    check_roots(data, report)

    def mutate_frame(named, over):
        key, _, deepest = leaves[named]
        assert deepest, f'no measurable addressing in {named}'
        bad = bytearray(data)
        kind, index = deepest
        at = file_offset(offsets_for(data), key, index, 2 if kind == 'off' else 4)
        struct.pack_into('<h' if kind == 'off' else '<i', bad, at, -over)
        return bad

    def offsets_for(raw):
        _, _, offsets, _, _ = bodies_and_relocations(raw)
        return offsets

    for named in ('p11_owner_start_begin', 'p11_owner_start_aggregate', 'p11_object_fault'):
        bad = mutate_frame(named, LEAF_FRAME_BOUND + 1)
        try:
            check_leaves(bytes(bad), [])
        except AssertionError:
            pass
        else:
            raise AssertionError(f'over-budget {named} frame accepted')
    elf, raws, offsets, bodies, _ = bodies_and_relocations(data)
    fault = only(bodies, 'p11_object_fault')
    body = body_of(raws, bodies, fault)
    call_at = next(index for index in range(len(body) // 8)
                   if struct.unpack_from('<BBhi', body, index * 8)[0] == 0x85)
    bad = bytearray(data)
    bad[file_offset(offsets, fault, call_at, 1)] = 0x10
    try:
        check_leaves(bytes(bad), [])
    except AssertionError:
        pass
    else:
        raise AssertionError('nested fault call accepted')
    entry = only(bodies, 'p11_return')
    depth = frame_of(body_of(raws, bodies, entry))[0]
    assert depth, 'no measurable addressing in p11_return'
    _, deepest, _ = frame_of(body_of(raws, bodies, entry))
    kind, index = deepest
    bad = bytearray(data)
    struct.pack_into('<h' if kind == 'off' else '<i', bad,
                     file_offset(offsets, entry, index, 2 if kind == 'off' else 4),
                     -(ROOT_CHAIN_BOUND + 1))
    try:
        check_roots(bytes(bad), [])
    except AssertionError:
        pass
    else:
        raise AssertionError('over-budget return chain accepted')
    report.append('frames, chains and three mutations refuse as required')


def check_return_fault(data, report):
    calls = fault_calls_to(data, 'p11_return')
    assert calls, 'p11_return must call the fault leaf on terminal-drain failure'
    report.append(f'root p11_return: {len(calls)} reachable fault call site(s)')
    _, _, _, bodies, _ = bodies_and_relocations(data)
    for suffix in ('ordinary_return', 'object_return'):
        names = [symbol[0] for symbol in bodies.values() if suffix in symbol[0]]
        assert len(names) == 1, f'expected exactly one outlined {suffix}: {names}'
        branch_calls = fault_calls_to(data, names[0])
        assert branch_calls, f'{suffix} must propagate its checked-retire failure to fault'
        report.append(f'branch {suffix}: {len(branch_calls)} reachable fault call site(s)')


def check_exec_exit_fault(data, report):
    for root in ('sched_process_exec', 'sched_process_exit'):
        calls = fault_calls_to(data, root)
        assert len(calls) == 1, f'{root} must make one sequential fault call, saw {len(calls)}'
        report.append(f'root {root}: one sequential fault call')
    cleanup = fault_calls_to(data, 'p11_owner_cleanup')
    assert not cleanup, 'cleanup must not nest the fault call'
    report.append('cleanup nests no fault call')


def main():
    data = Path(sys.argv[1]).read_bytes()
    mode = sys.argv[2]
    report = []
    if mode in ('frames', 'frames-diagnostic', 'frames-wide', 'frames-wide-diagnostic'):
        check_frames(data, report, diagnostic='diagnostic' in mode, wide='wide' in mode)
    elif mode == 'function-abis':
        check_function_abis(data, report)
    elif mode in ('scalar-globals', 'scalar-globals-p0'):
        elf = checker.Elf(data)
        checker.validate_object_capture_globals(elf)
        checker.validate_object_capture_reachability(elf, full=mode == 'scalar-globals')
        report.append('scalar capture globals: exact u64 ABI, private reads and root reachability checked')
    elif mode == 'return-fault':
        check_return_fault(data, report)
    elif mode == 'exec-exit-fault':
        check_exec_exit_fault(data, report)
    else:
        raise AssertionError(f'unknown checker mode {mode}')
    print('\n'.join(report))


main()
"##;
