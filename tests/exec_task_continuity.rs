//! SPDX-License-Identifier: GPL-3.0-or-later
//! Finite native/CO-RE controls. No verifier, kernel load or link-health claim.

use std::{fs, path::Path, process::Command};

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
    for shape in 1..=13 {
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
        for flags in [0, 1, 2, 3, (1u64 << 63) | 1] {
            let (result, reads) = execute_predicate(function, flags, false, false, 0);
            let expected = u64::from(matches!(shape, 1 | 2) && flags & 3 == 1);
            assert_eq!(result, expected, "shape={shape} flags={flags}");
            let expected_reads = match shape {
                1 | 2 => 2,
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
    for shape in 1..=13 {
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
