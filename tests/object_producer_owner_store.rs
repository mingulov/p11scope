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

/// Compile the native owner fixture the way the repo builds it.
fn compile_owner_fixture(directory: &Path, name: &str, small: bool) -> PathBuf {
    let binary = directory.join(name);
    let mut compiler = Command::new("clang-18");
    compiler
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/task-owner/helper_tests.c",
            "-o",
        ])
        .arg(&binary);
    if small {
        compiler.arg("-DP11SCOPE_SMALL_STATE_MAPS");
    }
    let output = compiler.output().expect("execute clang-18");
    assert!(
        output.status.success(),
        "native owner compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn run_fixture_subcommand(binary: &Path, subcommand: &str, marker: &str) {
    let output = Command::new(binary)
        .arg(subcommand)
        .output()
        .expect("execute native owner fixture");
    assert!(
        output.status.success(),
        "fixture {subcommand}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(marker),
        "fixture {subcommand} missed its marker: {stdout:?}"
    );
}

/// Run one object-custody fixture control under default and small-state maps.
fn run_object_subcommand(subcommand: &str, marker: &str) {
    let temporary = tempfile::tempdir().expect("native owner test directory");
    for small in [false, true] {
        let binary = compile_owner_fixture(
            temporary.path(),
            &format!("object-{subcommand}-small-{small}"),
            small,
        );
        run_fixture_subcommand(&binary, subcommand, marker);
    }
}

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
    run_object_subcommand(
        "object_producer_owner_terminal_matrix",
        "object custody terminal matrix passed",
    );
}

#[test]
fn object_producer_side_state_n_and_n_plus_one() {
    run_object_subcommand(
        "object_producer_side_state_n_and_n_plus_one",
        "object custody side state passed",
    );
}

#[test]
fn object_producer_missing_side_state_faults_before_return() {
    run_object_subcommand(
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
        4,
        "ordinary, aggregate, reserve-failure and emission arms each retire"
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
fn object_producer_cleanup_result_reaches_exec_exit_fault() {
    run_object_subcommand(
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

#[test]
fn object_producer_compiled_frames_are_bounded() {
    let directory = tempfile::tempdir().expect("temporary object custody frame check");
    let object = embedded_object(directory.path());
    // Printed, not just carried in the assert message: with --nocapture this
    // is the map-allocation and frame/instruction measurement record.
    let report = run_object_checker(&object, "frames");
    println!("{report}");
}

#[test]
fn object_producer_cleanup_sweep_delegates_scrub() {
    let directory = tempfile::tempdir().expect("temporary orphan sweep delegation check");
    let object = embedded_object(directory.path());
    let report = run_object_checker(&object, "sweep-delegate");
    println!("{report}");
    // Branch diet: the sweep helper runs once per slot (512/2112), so it
    // must settle branchlessly — no poison/count calls inside. Poison and
    // the saturating bulk count happen once after the loop.
    let native =
        std::fs::read_to_string("crates/ebpf/native/task_owner.c").expect("read native owner");
    let helper = source_between(
        &native,
        "static __noinline int object_sweep_orphan_slot",
        "/* Settle one subordinate row for START removal.",
    );
    for forbidden in ["poison(", "count("] {
        assert!(
            !helper.contains(forbidden),
            "sweep helper must not call {forbidden} per slot"
        );
    }
    assert!(
        native.contains("static __always_inline void count_add(u64 *cell, u64 add)"),
        "bulk saturating count helper must exist"
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


def check_maps(report):
    maps, _, _ = checker.inspect(sys.argv[1])
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
    # The query row and the fault leaf are true producer leaves: bounded
    # frames, no nesting.
    for name in ('p11_object_side_get', 'p11_object_fault'):
        key = only(bodies, name)
        symbol = bodies[key]
        assert symbol[3] == text and symbol[5], f'{name} must be a defined .text function'
        depth, deepest, _ = frame_of(body_of(raws, bodies, key))
        assert depth <= LEAF_FRAME_BOUND, f'{name} frame {depth} exceeds {LEAF_FRAME_BOUND}'
        leaves[name] = (key, depth, deepest)
        report.append(f'leaf {name}: frame={depth}')
        nested = pseudo_calls(raws, offsets, bodies, relocations, key)
        assert not nested, f'{name} must make no nested BPF call'
    return leaves


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
    return [call for call in pseudo_calls(raws, offsets, bodies, relocations, root)
            if call[1] == fault]


def check_frames(data, report):
    check_maps(report)
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

    bad = mutate_frame('p11_object_fault', LEAF_FRAME_BOUND + 1)
    try:
        check_leaves(bytes(bad), [])
    except AssertionError:
        pass
    else:
        raise AssertionError('over-budget fault frame accepted')
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
    report.append(f'root p11_return: {len(calls)} sequential fault call site(s)')


def check_exec_exit_fault(data, report):
    for root in ('sched_process_exec', 'sched_process_exit'):
        calls = fault_calls_to(data, root)
        assert len(calls) == 1, f'{root} must make one sequential fault call, saw {len(calls)}'
        report.append(f'root {root}: one sequential fault call')
    cleanup = fault_calls_to(data, 'p11_owner_cleanup')
    assert not cleanup, 'cleanup must not nest the fault call'
    report.append('cleanup nests no fault call')


def check_sweep_delegate(data, report):
    elf, raws, offsets, bodies, relocations = bodies_and_relocations(data)
    # The orphan sweep must not inline the 432-byte scrub: the unrolled
    # stores times the 512-slot trip count exceed the kernel jump
    # complexity budget (live 8193-jump reject on 7.2.9/6.12/7.0). One
    # noinline subprogram per slot is verified once instead.
    helper = only(bodies, 'object_sweep_orphan_slot')
    symbol = bodies[helper]
    assert symbol[3] == elf.indices['.text'] and symbol[5], \
        'sweep helper must be a defined .text function'
    depth, _, _ = frame_of(body_of(raws, bodies, helper))
    assert depth <= LEAF_FRAME_BOUND, f'sweep helper frame {depth} exceeds {LEAF_FRAME_BOUND}'
    report.append(f'sweep helper object_sweep_orphan_slot: frame={depth}')
    # Branchless settle: BPF has no conditional-set, so even (rc != 0)
    # compiles to a jump. The helper must carry exactly one conditional
    # jump (the null-row check); the settle code is shifts and logic.
    hbody = body_of(raws, bodies, helper)
    cond = sum(1 for i in range(len(hbody) // 8)
              if (struct.unpack_from('<BBhi', hbody, i * 8)[0] & 7) == 5
              and struct.unpack_from('<BBhi', hbody, i * 8)[0] not in (0x05, 0x85, 0x95))
    assert cond == 1, f'sweep helper must carry one conditional jump, saw {cond}'
    report.append('sweep helper settle is branchless (one null check)')
    cleanup = only(bodies, 'p11_owner_cleanup')
    calls = [call for call in pseudo_calls(raws, offsets, bodies, relocations, cleanup)
             if call[1] == helper]
    assert len(calls) == 1, f'cleanup must call the sweep helper once, saw {len(calls)}'
    report.append('cleanup delegates orphan scrub to one subprogram call')


def main():
    data = Path(sys.argv[1]).read_bytes()
    mode = sys.argv[2]
    report = []
    if mode == 'frames':
        check_frames(data, report)
    elif mode == 'return-fault':
        check_return_fault(data, report)
    elif mode == 'exec-exit-fault':
        check_exec_exit_fault(data, report)
    elif mode == 'sweep-delegate':
        check_sweep_delegate(data, report)
    else:
        raise AssertionError(f'unknown checker mode {mode}')
    print('\n'.join(report))


main()
"##;
