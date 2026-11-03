//! SPDX-License-Identifier: GPL-3.0-or-later
//! Finite native/CO-RE controls. No verifier, kernel load or link-health claim.

use p11scope_ebpf_common::{FLAG_PID_FILTER, FLAG_POLICY_AGGREGATE, FLAG_TRACK_SHORT_LIVED};
use std::{collections::BTreeSet, fs, path::Path, process::Command};

const EXEC_TARGET_SHAPES: u32 = 16;

fn compile(source: &str, output: &Path, bpf: bool, shape: Option<u32>) {
    let mut compiler = Command::new("clang-18");
    compiler.args(["-O2", "-g", "-Wall", "-Wextra", "-Werror"]);
    if bpf {
        compiler.args(["-target", "bpfel", "-mcpu=v1", "-c"]);
    }
    if let Some(shape) = shape {
        compiler.arg(format!("-DEXEC_SHAPE={shape}"));
    }
    let result = compiler
        .args(["-I", "crates/ebpf/native", source, "-o"])
        .arg(output)
        .output()
        .expect("compile finite native EXEC control");
    assert!(
        result.status.success(),
        "native compile: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn load_only_wrapper(directory: &Path) -> aya_obj::Object {
    let wrapper = directory.join("load-only.c");
    fs::write(
        &wrapper,
        r#"/* SPDX-License-Identifier: GPL-2.0-only */
#include "exec_task.c"
__attribute__((section("raw_tp/sched_process_exec"), used))
int exec_load_only(void *ctx) {
    (void)ctx;
    return p11_exec_dumpability();
}
char TEST_LICENSE[] __attribute__((section("license"), used)) = "GPL";
"#,
    )
    .unwrap();
    let binary = directory.join("load-only.o");
    compile(wrapper.to_str().unwrap(), &binary, true, None);
    let object = aya_obj::Object::parse(&fs::read(binary).unwrap()).unwrap();
    assert!(object.has_btf_relocations());
    assert!(object.maps.is_empty());
    assert_eq!(object.programs.len(), 1);
    assert!(object.programs.contains_key("exec_load_only"));
    object
}

#[test]
fn exec_task_native_scalar_and_bitmap_dumpability_are_checked() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("exec-host-test");
    compile(
        "tests/fixtures/exec-task/helper_tests.c",
        &binary,
        false,
        None,
    );
    let result = Command::new(binary).output().unwrap();
    assert!(
        result.status.success(),
        "native predicate: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

/// This deliberately executes only this tiny no-map native helper, with two
/// modeled kernel helpers and an explicit padded task/mm layout. Any unfamiliar
/// instruction, read address, helper, poison or excess work fails the test.
fn execute_predicate(
    function: &aya_obj::Function,
    flags: u64,
    null_task: bool,
    null_mm: bool,
    failed_read: usize,
) -> (u64, usize) {
    const TASK: u64 = 0x1000;
    const MM: u64 = 0x2000;
    const STACK: u64 = 0x10000;
    let mut regs = [0u64; 11];
    let mut stack = [0u8; 512];
    regs[10] = STACK + stack.len() as u64;
    let mut pc = 0usize;
    let mut reads = 0;
    for _ in 0..200 {
        let ins = &function.instructions[pc];
        let dst = ins.dst_reg() as usize;
        let src = ins.src_reg() as usize;
        let imm = ins.imm as i64 as u64;
        let mut next = pc + 1;
        match ins.code {
            0xb7 => regs[dst] = imm,
            0xbf => regs[dst] = regs[src],
            0xb4 => regs[dst] = ins.imm as u32 as u64,
            0xbc => regs[dst] = regs[src] as u32 as u64,
            0x07 => regs[dst] = regs[dst].wrapping_add(imm),
            0x0f => regs[dst] = regs[dst].wrapping_add(regs[src]),
            0x57 => regs[dst] &= imm,
            0x79 => {
                let address = regs[src].wrapping_add(ins.off as i64 as u64);
                let index = usize::try_from(address.checked_sub(STACK).unwrap()).unwrap();
                regs[dst] = u64::from_le_bytes(stack[index..index + 8].try_into().unwrap());
            }
            0x7b | 0x7a => {
                let address = regs[dst].wrapping_add(ins.off as i64 as u64);
                let index = usize::try_from(address.checked_sub(STACK).unwrap()).unwrap();
                let value = if ins.code == 0x7b { regs[src] } else { imm };
                stack[index..index + 8].copy_from_slice(&value.to_le_bytes());
            }
            0x15 | 0x55 | 0x16 | 0x56 | 0x05 => {
                let equal = if ins.code & 7 == 6 {
                    regs[dst] as u32 == ins.imm as u32
                } else {
                    regs[dst] == imm
                };
                if ins.code == 0x05
                    || (ins.code & 0xf0 == 0x10 && equal)
                    || (ins.code & 0xf0 == 0x50 && !equal)
                {
                    next = usize::try_from(pc as isize + 1 + ins.off as isize).unwrap();
                }
            }
            0x85 => {
                assert_eq!(ins.src_reg(), 0, "no unmodeled subprogram call");
                match ins.imm {
                    158 => regs[0] = if null_task { 0 } else { TASK },
                    113 => {
                        reads += 1;
                        assert_eq!(regs[2], 8, "only a checked kernel word is read");
                        let value = match regs[3] {
                            address if address == TASK + 16 => {
                                if null_mm {
                                    0
                                } else {
                                    MM
                                }
                            }
                            address if address == MM + 24 => flags,
                            address => panic!("unexpected/unrelocated kernel read {address:#x}"),
                        };
                        if failed_read == reads {
                            regs[0] = u64::MAX;
                        } else {
                            let index =
                                usize::try_from(regs[1].checked_sub(STACK).unwrap()).unwrap();
                            stack[index..index + 8].copy_from_slice(&value.to_le_bytes());
                            regs[0] = 0;
                        }
                    }
                    helper => panic!("unsupported or poisoned native helper {helper:#x}"),
                }
            }
            0x95 => return (regs[0], reads),
            code => panic!("unsupported finite native instruction {code:#x} at {pc}"),
        }
        assert!(
            next < function.instructions.len(),
            "native branch outside body"
        );
        pc = next;
    }
    panic!("finite native helper exceeded 200 instructions")
}

#[test]
fn exec_task_core_supported_and_unknown_shapes_take_safe_compiled_paths() {
    let temp = tempfile::tempdir().unwrap();
    let native = temp.path().join("exec-native.o");
    compile("crates/ebpf/native/exec_task.c", &native, true, None);
    let pristine = aya_obj::Object::parse(&fs::read(native).unwrap()).unwrap();
    assert!(pristine.has_btf_relocations());
    assert!(pristine.maps.is_empty(), "the native predicate has no maps");
    assert!(pristine.programs.is_empty(), "the predicate adds no hook");
    let wrapper = load_only_wrapper(temp.path());
    for shape in 1..=EXEC_TARGET_SHAPES {
        let target = temp.path().join(format!("target-{shape}.o"));
        compile(
            "tests/fixtures/exec-task/core-target.c",
            &target,
            true,
            Some(shape),
        );
        let target = aya_obj::Object::parse(&fs::read(target).unwrap()).unwrap();
        let mut relocated = pristine.clone();
        relocated
            .relocate_btf(target.btf.as_ref().unwrap())
            .unwrap();
        let function = relocated
            .functions
            .values()
            .find(|function| function.name == "p11_exec_dumpability")
            .unwrap();
        let mut wrapped = wrapper.clone();
        wrapped.relocate_btf(target.btf.as_ref().unwrap()).unwrap();
        let wrapped_function = wrapped
            .functions
            .values()
            .find(|function| function.name == "p11_exec_dumpability")
            .unwrap();
        let code = |function: &aya_obj::Function| {
            function
                .instructions
                .iter()
                .map(|ins| (ins.code, ins.dst_reg(), ins.src_reg(), ins.off, ins.imm))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            code(function),
            code(wrapped_function),
            "the load-only wrapper uses the same relocated native predicate shape={shape}"
        );
        assert!(
            function
                .instructions
                .iter()
                .any(|ins| ins.code == 0x85 && ins.imm == 0x0bad_2310),
            "each shape retains real Aya poison behind an incompatible-path guard"
        );
        for flags in [1, 0, 2, 3, (1u64 << 63) | 1] {
            let (result, reads) = execute_predicate(function, flags, false, false, 0);
            let expected = u64::from(matches!(shape, 1 | 2 | 16) && flags & 3 == 1);
            assert_eq!(result, expected, "shape={shape} flags={flags}");
            let expected_reads = match shape {
                1 | 2 | 16 => 2,
                6 | 7 => 0,
                _ => 1,
            };
            assert_eq!(reads, expected_reads, "shape={shape}");
        }
        assert_eq!(execute_predicate(function, 1, true, false, 0), (0, 0));
        assert_eq!(execute_predicate(function, 1, false, true, 0).0, 0);
        for failed in 1..=2 {
            assert_eq!(execute_predicate(function, 1, false, false, failed).0, 0);
        }
    }
}

/// Root runs this already-built selector under the exclusive privileged lock.
/// Synthetic BTF drives Aya's actual relocator, then the host verifier loads
/// the same native helper. Nothing is attached, executed, pinned or retained.
/// This is host-kernel verifier coverage, not an older-kernel/live H6 claim.
#[test]
#[ignore = "requires the root-owned privileged verifier lane"]
fn exec_task_core_shapes_kernel_load_without_attachment() {
    // SAFETY: geteuid only reads this process's effective user identity.
    assert_eq!(unsafe { libc::geteuid() }, 0, "root owns the verifier lane");
    let temp = tempfile::tempdir().unwrap();
    let _wrapper = load_only_wrapper(temp.path());
    let bytes = fs::read(temp.path().join("load-only.o")).unwrap();
    for shape in 1..=EXEC_TARGET_SHAPES {
        let target = temp.path().join(format!("target-{shape}.o"));
        compile(
            "tests/fixtures/exec-task/core-target.c",
            &target,
            true,
            Some(shape),
        );
        let target = aya_obj::Object::parse(&fs::read(target).unwrap()).unwrap();
        let mut bpf = aya::EbpfLoader::new()
            .btf(target.btf.as_ref())
            .verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS)
            .load(&bytes)
            .unwrap_or_else(|error| panic!("Aya load-only relocation shape={shape}: {error}"));
        let program: &mut aya::programs::RawTracePoint = bpf
            .program_mut("exec_load_only")
            .unwrap()
            .try_into()
            .unwrap();
        program
            .load()
            .unwrap_or_else(|error| panic!("host kernel load-only shape={shape}: {error}"));
        println!("EXEC native host verifier load-only shape={shape}: OK");
        // Program/BTF FDs close at the end of this iteration. Never attach.
    }
}

#[test]
fn exec_task_embedded_lifecycle_preserves_maps_hooks_and_class_boundary() {
    for (bytes, inventory) in [
        (p11scope::EBPF_OBJECT, false),
        (p11scope::EBPF_INVENTORY_OBJECT, true),
        (p11scope::EBPF_INVENTORY_CALLERS_OBJECT, true),
    ] {
        let object = aya_obj::Object::parse(bytes).unwrap();
        assert!(object.programs.contains_key("sched_process_exec"));
        assert!(object.programs.contains_key("sched_process_exit"));
        assert!(
            object
                .functions
                .values()
                .any(|function| function.name == "p11_exec_dumpability")
        );
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("native-object");
        fs::write(&path, bytes).unwrap();
        let script = "import sys; from pathlib import Path; sys.path.insert(0, 'scripts'); from _loader import load_path; c=load_path(Path('scripts/check-bpf-map-defs.py'), 'exec_boundary'); e=c.Elf(Path(sys.argv[1]).read_bytes()); c.validate_exec_helpers(e, inventory=sys.argv[2]=='1')";
        let result = Command::new("python3")
            .args(["-I", "-c", script])
            .arg(path)
            .arg(if inventory { "1" } else { "0" })
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let mutations = Command::new("python3")
        .args([
            "-I",
            "tests/python/test_bpf_map_defs.py",
            "MapDefsTests.test_exec_predicate_boundary",
        ])
        .output()
        .unwrap();
    assert!(
        mutations.status.success(),
        "{}",
        String::from_utf8_lossy(&mutations.stderr)
    );
}

#[test]
fn exec_generation_ticket_helper_respects_flavor_and_reservation_boundary() {
    let mut variants = vec![
        ("detailed", p11scope::EBPF_OBJECT, true, true),
        ("inventory", p11scope::EBPF_INVENTORY_OBJECT, false, false),
        (
            "callers",
            p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
            true,
            true,
        ),
    ];
    for (name, bytes) in [
        ("counts", p11scope::EBPF_COUNTER_COUNTS_OBJECT),
        ("timestamps", p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT),
        ("latency", p11scope::EBPF_COUNTER_LATENCY_OBJECT),
    ] {
        if !bytes.is_empty() {
            variants.push((name, bytes, false, true));
        }
    }
    let script = r#"
import re, struct, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from _loader import load_path
m = load_path(Path('scripts/check-live-discovery-object.py'), 'exec_ticket_flow')
c = load_path(Path('scripts/check-bpf-map-defs.py'), 'exec_ticket_btf')
elf = c.Elf(Path(sys.argv[1]).read_bytes())
btf = c.Btf(elf.sections['.BTF'][1])
nodes = [n for n in btf.types[1:] if n[:2] == (12, 'p11_link_current_cookie')]
assert len(nodes) == 1 and nodes[0][3] == 1
proto = btf.types[nodes[0][2]]
assert proto[0] == 13 and proto[3] == 0, 'cookie helper takes no arguments'
result = btf.resolve(proto[2])
assert result[0] == 1 and result[2] == 8, 'cookie helper returns u64'
dump = subprocess.check_output(['llvm-objdump-18', '-dr', sys.argv[1]], text=True)
blocks = m.function_blocks(dump)
owners = [(name, lines) for name, lines in blocks.items()
          if any(re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line) for line in lines)]
assert len(owners) == 1 and owners[0][0].endswith('emit_lifecycle'), owners
lines = owners[0][1]
ticket_row = next(i for i, line in enumerate(lines) if re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line))
ticket = next(m.line_pc(line) for line in reversed(lines[:ticket_row]) if m.line_pc(line) is not None)
reserve_row = next(i for i, line in enumerate(lines) if re.search(r'\bcall 0x83\b', line))
reserve = m.line_pc(lines[reserve_row])
insns, graph = m.instruction_graph(lines)
assert ticket not in m.reachable(graph, [insns[0][0]], {reserve}), 'ticket before ring reserve'
branch_row = next(i for i in range(reserve_row + 1, min(len(lines), reserve_row + 8))
                  if re.search(r'\bif r\d+ (?:==|!=) 0x0 goto ', lines[i]))
branch = lines[branch_row]
target = m.relative_target(m.line_pc(branch), branch)
following = next(m.line_pc(line) for line in lines[branch_row + 1:] if m.line_pc(line) is not None)
null = target if '== 0x0 goto' in branch else following
assert ticket not in m.reachable(graph, [null]), 'failed reservation acquired a ticket'
kind_checks = [(pc, text) for pc, text in insns if re.search(r'\bif r\d+ (?:==|!=) 0x5 goto ', text)]
assert len(kind_checks) == 1, 'only EXEC kind5 may acquire a lifecycle ticket'
kind_pc, kind_text = kind_checks[0]
kind_target = m.relative_target(kind_pc, kind_text)
kind_next = next(pc for pc, _ in insns if pc > kind_pc)
not_exec = kind_next if '== 0x5 goto' in kind_text else kind_target
assert ticket not in m.reachable(graph, [not_exec]), 'another lifecycle kind acquired a ticket'

# Resolve the actual linked root's local calls, including .text relocations.
# The checked scope-auth return discriminator must dominate emission; its
# refusal arm cannot reach the emitter that owns the only ticket call.
symbols = [s for s in elf.symbols if s[1] & 15 == 2 and s[5]]
root = next(s for s in symbols if s[0] == 'sched_process_exec')
sections = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
calls = []
for header, relocs in elf.sections.values():
    if header[1] != 9 or header[7] != root[3]:
        continue
    for offset in range(0, len(relocs), 16):
        address, info = struct.unpack_from('<QQ', relocs, offset)
        if info & 0xffffffff != 10 or not root[4] <= address < root[4] + root[5]:
            continue
        op, regs, _, immediate = struct.unpack_from('<BBhi', sections[root[3]], address)
        if op != 0x85 or regs >> 4 != 1:
            continue
        named = elf.symbols[info >> 32]
        target = (named[3], named[4] + (immediate + 1) * 8)
        resolved = [s for s in symbols if s[3:5] == target]
        assert len(resolved) == 1, 'unresolved EXEC root call'
        calls.append((address // 8, resolved[0][0]))
auth = [pc for pc, name in calls if name.endswith('10scope_auth')]
emit = [pc for pc, name in calls if name.endswith('14emit_lifecycle')]
assert len(auth) == len(emit) == 1, 'EXEC root uses actual scope/emitter bodies'
root_lines = blocks['sched_process_exec']
root_insns, root_graph = m.instruction_graph(root_lines)
assert emit[0] not in m.reachable(root_graph, [root_insns[0][0]], {auth[0]}), 'scope bypassed'
after = [(pc, text) for pc, text in root_insns if auth[0] < pc <= auth[0] + 3]
assert len(after) >= 2 and re.fullmatch(r'r\d+ = \*\(u64 \*\)\(r10 - 0x[0-9a-f]+\)', after[0][1])
scope_register = after[0][1].split(' = ', 1)[0]
guard_pc, guard_text = after[1]
assert re.search(r'\bif ' + scope_register + r' (?:==|!=) 0x1 goto ', guard_text), 'scope discriminator unchecked'
scope_target = m.relative_target(guard_pc, guard_text)
scope_next = next(pc for pc, _ in root_insns if pc > guard_pc)
refused = scope_next if '== 0x1 goto' in guard_text else scope_target
assert emit[0] not in m.reachable(root_graph, [refused]), 'refused scope emitted an EXEC ticket'
"#;
    for (name, bytes, helper, maps) in variants {
        let object = aya_obj::Object::parse(bytes).unwrap();
        let helpers = object
            .functions
            .values()
            .filter(|function| function.name == "p11_link_current_cookie")
            .count();
        assert_eq!(
            helpers,
            usize::from(helper),
            "{name}: cookie-only helper selection"
        );
        assert_eq!(object.maps.contains_key("TASK_COOKIE"), maps, "{name}");
        assert_eq!(object.maps.contains_key("COOKIE_CTL"), maps, "{name}");
        if helper {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("exec-ticket.o");
            fs::write(&path, bytes).unwrap();
            let check = Command::new("python3")
                .args(["-I", "-c", script])
                .arg(path)
                .output()
                .unwrap();
            assert!(
                check.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&check.stderr)
            );
        }
    }
}

/// PID scope admits a lifecycle record on the tgid number alone, which a
/// process that later reuses the target's PID also passes; only the
/// entries' kernel pid filter keeps that process out. The EXEC ticket must
/// therefore never be acquired under PID scope (its record carries zero,
/// unavailable), or the reused PID gets TASK_COOKIE state and an allocator
/// charge in a capture that never selected it. Every path from the emitter
/// entry to the only ticket call passes a mask of the scope flags (the flags
/// scalar or the first word of the ScopeAuth the third argument points to)
/// that includes the PID-filter bit, compared against a value with that bit
/// clear; the compiler may merge the bit with other flag tests (Detailed
/// folds it into the tracking/aggregate test as one mask). Any PID-set
/// value takes the not-equal arm, which cannot reach the call; the equal
/// arm (cgroup/system) still does. Counter objects carry no ticket call;
/// `exec_ticket_absent_from_counter_flavors` pins that absence.
#[test]
fn exec_generation_ticket_is_never_acquired_under_pid_scope() {
    let mut variants = vec![
        ("detailed", p11scope::EBPF_OBJECT),
        ("callers", p11scope::EBPF_INVENTORY_CALLERS_OBJECT),
    ];
    // The journal variant is covered exactly in journal builds: a build
    // that selected the journal but embedded no object fails here instead
    // of passing on the two ordinary objects alone.
    assert_eq!(
        p11scope::EBPF_JOURNAL_OBJECT.is_empty(),
        env!("P11SCOPE_JOURNAL_ENABLED") != "1",
        "the journal object is embedded exactly when the build selects it"
    );
    if !p11scope::EBPF_JOURNAL_OBJECT.is_empty() {
        variants.push(("journal", p11scope::EBPF_JOURNAL_OBJECT));
    }
    let script = r#"
import re, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from _loader import load_path
m = load_path(Path('scripts/check-live-discovery-object.py'), 'exec_ticket_pid_gate')
dump = subprocess.check_output(['llvm-objdump-18', '-dr', sys.argv[1]], text=True)
blocks = m.function_blocks(dump)
owners = [(name, lines) for name, lines in blocks.items()
          if any(re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line) for line in lines)]
assert len(owners) == 1 and owners[0][0].endswith('emit_lifecycle'), owners
lines = owners[0][1]
ticket_rows = [i for i, line in enumerate(lines) if re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line)]
assert len(ticket_rows) == 1, 'emit_lifecycle must call the ticket helper exactly once'
ticket_row = ticket_rows[0]
ticket = next(m.line_pc(line) for line in reversed(lines[:ticket_row]) if m.line_pc(line) is not None)
insns, graph = m.instruction_graph(lines)
entry = insns[0][0]
assert ticket in m.reachable(graph, [entry]), 'the EXEC ticket call is unreachable'

def names_scope_flags(index, register):
    # Straight-line definitions back to the third argument: the flags
    # scalar itself, or one u64 load of the ScopeAuth word at offset 0.
    loaded = False
    for _, text in reversed(insns[:index]):
        if text.startswith('call') and register in {'r0', 'r1', 'r2', 'r3', 'r4', 'r5'}:
            return False
        if not re.match(register + r' [^ ]*= ', text):
            continue
        copy = re.fullmatch(register + r' = (r\d+)', text)
        if copy:
            register = copy.group(1)
            continue
        load = re.fullmatch(register + r' = \*\(u64 \*\)\((r\d+) \+ 0x0\)', text)
        if load and not loaded:
            register, loaded = load.group(1), True
            continue
        return False
    return register == 'r3'

gates = []
for index, (pc, text) in enumerate(insns[:-2]):
    mask = re.fullmatch(r'(r\d+) &= (0x[0-9a-f]+)', text)
    if not mask or not int(mask.group(2), 16) & 0x1 or not names_scope_flags(index, mask.group(1)):
        continue
    branch_pc, branch = insns[index + 1]
    test = re.fullmatch(mask.group(1) + r' (==|!=) (0x[0-9a-f]+) goto [+-]0x[0-9a-f]+', branch.removeprefix('if '))
    if not test or int(test.group(2), 16) & 0x1:
        continue
    target = m.relative_target(branch_pc, branch)
    following = insns[index + 2][0]
    pid_set, pid_clear = (target, following) if test.group(1) == '!=' else (following, target)
    gates.append((pc, pid_set, pid_clear))
assert gates, 'no PID-filter scope gate guards the EXEC ticket'
for pc, pid_set, pid_clear in gates:
    assert ticket not in m.reachable(graph, [pid_set]), f'PID scope reaches the EXEC ticket (gate {pc})'
    assert ticket in m.reachable(graph, [pid_clear]), f'cgroup/system scope lost the EXEC ticket (gate {pc})'
assert ticket not in m.reachable(graph, [entry], {pc for pc, _, _ in gates}), 'the EXEC ticket bypasses the PID-filter gate'
"#;
    for (name, bytes) in variants {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("exec-ticket-pid.o");
        fs::write(&path, bytes).unwrap();
        let check = Command::new("python3")
            .args(["-I", "-c", script])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

#[test]
fn exec_task_singles_perf_attributes_preserve_healthy_leader_exec() {
    // Characterize the exact patched Aya constructor our Singles path uses.
    // This pins attributes, not live registered-pair activity or a receipt.
    let source = fs::read_to_string("third-party/src/aya-0.14.0-p2/src/sys/perf_event.rs").unwrap();
    let constructor = source
        .split_once("pub(crate) fn perf_event_open_probe(")
        .unwrap()
        .1
        .split_once("fn perf_event_sys(")
        .unwrap()
        .0;
    assert!(constructor.contains("mem::zeroed::<perf_event_attr>()"));
    for attribute in ["remove_on_exec", "enable_on_exec"] {
        assert!(
            !constructor.contains(attribute),
            "probe constructor changed {attribute}"
        );
    }
}

#[test]
fn exec_witness_failures_leave_shared_counters_flat() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("witness-neutrality-tests");
    let compile = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/image-identity/witness_neutrality_tests.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .expect("execute clang-18 for witness neutrality regression");
    assert!(
        compile.status.success(),
        "native compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(binary)
        .output()
        .expect("execute witness neutrality regression");
    assert!(
        run.status.success(),
        "witness neutrality regression failed: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn exec_ticket_absent_from_counter_flavors() {
    let mut checked = 0;
    for (name, bytes) in [
        ("counts", p11scope::EBPF_COUNTER_COUNTS_OBJECT),
        ("timestamps", p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT),
        ("latency", p11scope::EBPF_COUNTER_LATENCY_OBJECT),
    ] {
        if bytes.is_empty() {
            continue;
        }
        checked += 1;
        let object = aya_obj::Object::parse(bytes).unwrap();
        assert!(object.programs.contains_key("sched_process_exec"));
        let helpers = object
            .functions
            .values()
            .filter(|function| function.name == "p11_link_current_cookie")
            .count();
        assert_eq!(helpers, 0, "{name}: counter flavors issue no EXEC ticket");
        // The allocator stays for fork and caller-entry attribution; only
        // the EXEC stamp is gone.
        assert!(object.maps.contains_key("TASK_COOKIE"), "{name}");
        assert!(object.maps.contains_key("COOKIE_CTL"), "{name}");
    }
    assert!(
        checked > 0,
        "counter objects must be present to pin the stamp boundary"
    );
}

#[test]
fn exec_ticket_detailed_requires_armed_flags() {
    let script = r#"
import re, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from _loader import load_path
m = load_path(Path('scripts/check-live-discovery-object.py'), 'exec_ticket_gate')
dump = subprocess.check_output(['llvm-objdump-18', '-dr', sys.argv[1]], text=True)
blocks = m.function_blocks(dump)
owners = [(name, lines) for name, lines in blocks.items()
          if any(re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line) for line in lines)]
assert len(owners) == 1 and owners[0][0].endswith('emit_lifecycle'), owners
lines = owners[0][1]
ticket_row = next(i for i, line in enumerate(lines) if re.search(r'R_BPF_64_32\s+p11_link_current_cookie\s*$', line))
ticket = next(m.line_pc(line) for line in reversed(lines[:ticket_row]) if m.line_pc(line) is not None)
reserve_row = next(i for i, line in enumerate(lines) if re.search(r'\bcall 0x83\b', line))
insns, graph = m.instruction_graph(lines)
branch_row = next(i for i in range(reserve_row + 1, min(len(lines), reserve_row + 8))
                  if re.search(r'\bif r\d+ (?:==|!=) 0x0 goto ', lines[i]))
reserve_guard = m.line_pc(lines[branch_row])
kind_checks = [(pc, text) for pc, text in insns if re.search(r'\bif r\d+ (?:==|!=) 0x5 goto ', text)]
assert len(kind_checks) == 1, 'only EXEC kind5 may acquire a lifecycle ticket'
kind_pc = kind_checks[0][0]
# A branch guards the ticket when exactly one of its arms can reach it.
# Reserve and kind always guard; Detailed needs one more: the armed-flags
# gate, so an unarmed or aggregate capture issues no ticket.
guards = set()
for pc, text in insns:
    if not re.search(r'\bif .*\bgoto ', text):
        continue
    edges = graph.get(pc, [])
    if len(edges) != 2:
        continue
    reaches = [ticket in m.reachable(graph, [edge]) for edge in edges]
    if reaches == [True, False] or reaches == [False, True]:
        guards.add(pc)
assert reserve_guard in guards and kind_pc in guards, 'reserve and kind must guard the ticket'
extra = guards - {reserve_guard, kind_pc}
assert extra, 'Detailed EXEC ticket needs a flags gate beyond reserve and kind'
# Pin the flags mask, not just gate existence. Expected values are
# source-anchored (argv from FLAG_*): TRACK set, AGG clear, and on the
# combined tree with the PID-ticket fix PID clear as well. A wrong-mask
# mutant must fail; a PID-only gate must not satisfy this pin.
track = int(sys.argv[2])
mask_two = int(sys.argv[3])
mask_three = int(sys.argv[4])
texts = dict(insns)
order = [pc for pc, _ in insns]
index_of = {pc: i for i, pc in enumerate(order)}
pinned = []
for guard_pc in sorted(extra):
    guard_text = texts[guard_pc]
    gm = re.search(r'\bif (r\d+) (==|!=) (0x[0-9a-f]+) goto ', guard_text)
    if not gm:
        continue
    reg, polarity, val_hex = gm.groups()
    val = int(val_hex, 16)
    mask = None
    start = index_of[guard_pc]
    for j in range(start - 1, max(start - 6, -1), -1):
        prev = insns[j][1]
        am = re.search(r'\b' + reg + r' &= (0x[0-9a-f]+)', prev)
        if am:
            mask = int(am.group(1), 16)
            break
    if mask is None:
        continue
    edges = graph.get(guard_pc, [])
    if len(edges) != 2:
        continue
    target = m.relative_target(guard_pc, guard_text)
    following = edges[0] if edges[1] == target else edges[1]
    if polarity == '==':
        equal_arm, other_arm = target, following
    else:
        equal_arm, other_arm = following, target
    equal_reaches = ticket in m.reachable(graph, [equal_arm])
    other_reaches = ticket in m.reachable(graph, [other_arm])
    if val == track and mask in (mask_two, mask_three) and equal_reaches and not other_reaches:
        pinned.append((guard_pc, mask, val))
assert pinned, f'Detailed EXEC ticket needs a TRACK/AGG mask gate (& {mask_two:#x}/{mask_three:#x} == {track:#x}); extra guards {sorted(extra)} lack it'
"#;
    let track = FLAG_TRACK_SHORT_LIVED;
    let mask_two = FLAG_TRACK_SHORT_LIVED | FLAG_POLICY_AGGREGATE;
    let mask_three = mask_two | FLAG_PID_FILTER;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("exec-ticket-gate.o");
    fs::write(&path, p11scope::EBPF_OBJECT).unwrap();
    let check = Command::new("python3")
        .args(["-I", "-c", script])
        .arg(path)
        .arg(track.to_string())
        .arg(mask_two.to_string())
        .arg(mask_three.to_string())
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "detailed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn exec_witness_bank_builds_never_feed_ticket_comparison() {
    fn has_bank_identity(names: &BTreeSet<&str>) -> bool {
        const BANK_IDENTITY: [&str; 7] = [
            "TASK_COOKIE_B",
            "COOKIE_CTL_B",
            "IMAGE_BANK_SELECT",
            "p11_image_bank_select",
            "p11_image_bank_cut",
            "p11_link_task_ticket",
            "p11_image_identity_issued",
        ];
        BANK_IDENTITY.iter().any(|name| names.contains(name))
    }
    // The detector is non-vacuous: every bank name fires it, while the
    // single-bank identity surface stays silent.
    let single: BTreeSet<&str> = [
        "TASK_COOKIE",
        "COOKIE_CTL",
        "p11_link_current_identity",
        "p11_link_current_cookie",
    ]
    .into_iter()
    .collect();
    assert!(!has_bank_identity(&single));
    for bank in [
        "TASK_COOKIE_B",
        "COOKIE_CTL_B",
        "IMAGE_BANK_SELECT",
        "p11_image_bank_select",
        "p11_image_bank_cut",
        "p11_link_task_ticket",
        "p11_image_identity_issued",
    ] {
        let mut banked = single.clone();
        banked.insert(bank);
        assert!(
            has_bank_identity(&banked),
            "{bank} must read as a bank build"
        );
    }
    // The comparing domain runs on Inventory-lane objects only, so those
    // objects must never carry bank-local tickets: local numbers recur
    // across re-prepares and exact equality there would not prove task
    // incarnation. The loader gate stays Detailed-only.
    for (name, bytes, identity) in [
        ("inventory", p11scope::EBPF_INVENTORY_OBJECT, false),
        ("callers", p11scope::EBPF_INVENTORY_CALLERS_OBJECT, true),
    ] {
        let object = aya_obj::Object::parse(bytes).unwrap();
        assert!(object.programs.contains_key("sched_process_exec"));
        let mut names: BTreeSet<&str> = object.maps.keys().map(String::as_str).collect();
        names.extend(
            object
                .functions
                .values()
                .map(|function| function.name.as_str()),
        );
        assert!(
            !has_bank_identity(&names),
            "{name}: ticket-comparing domain must be bank-free"
        );
        assert_eq!(object.maps.contains_key("TASK_COOKIE"), identity, "{name}");
        assert_eq!(object.maps.contains_key("COOKIE_CTL"), identity, "{name}");
    }
}
