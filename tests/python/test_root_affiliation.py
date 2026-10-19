# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual native root helper tests and narrow production hook contracts."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    start = source.index("fn " + name + "(")
    start = source.index("{", start)
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def wrapper_contract(main, name):
    wrapper = function(main, name)
    head = re.sub(r"//[^\n]*", "", wrapper)
    if not head.startswith("{\n    if !stop_gate_enter() {\n        return 0;\n    }"):
        raise AssertionError(f"{name} must admit through the stop gate first")
    if wrapper.count("stop_gate_enter") != 1 or wrapper.count("stop_gate_leave") != 1:
        raise AssertionError(f"{name} must enter the gate once and leave once")
    if (wrapper.count(name + "_impl(") != 1 or "p11_owner_cleanup" in wrapper
            or "p11_root_current_exit" in wrapper):
        raise AssertionError(f"{name} must delegate its guarded body to {name}_impl")
    if wrapper.index("stop_gate_leave") < wrapper.index(name + "_impl("):
        raise AssertionError(f"{name} must leave the gate only after its guarded body")


def hook_contract(main, identity):
    wrapper_contract(main, "sched_process_exit")
    exit_body = function(main, "sched_process_exit_impl")
    # Owner cleanup executes first and unconditionally in both cfgs; a
    # failed cleanup faults through a fault-only arm that never diverts
    # teardown (exact text pins the arm: no return, no other call).
    guard = ('#[cfg(not(feature = "inventory-only"))]\n'
             '    if unsafe { p11_owner_cleanup() } != 0 {\n'
             '        unsafe { p11_object_fault() };\n'
             '    }\n'
             '    #[cfg(feature = "inventory-only")]\n'
             '    let _ = unsafe { p11_owner_cleanup() };')
    guard_at = exit_body.index(guard)
    before_guard = re.sub(r"//[^\n]*", "", exit_body[:guard_at]).strip()
    if before_guard != "{":
        raise AssertionError("owner cleanup must unconditionally begin the exit handler")
    if exit_body.count("p11_owner_cleanup") != 2:
        raise AssertionError("exit must run owner cleanup exactly once per cfg")
    tail = exit_body[guard_at + len(guard):]
    root = re.match(
        r'\s*#\[cfg\(not\(feature = "inventory-only"\)\)\]'
        r'\s*unsafe\s*\{\s*p11_root_current_exit\(\)\s*\};', tail)
    if root is None or exit_body.count("p11_root_current_exit") != 1:
        raise AssertionError("Detailed root cleanup must immediately follow owner cleanup; Inventory must omit it")
    wrapper_contract(main, "sched_process_exec")
    if ("p11_root_current_exit" in function(main, "sched_process_exec")
            or "p11_root_current_exit" in function(main, "sched_process_exec_impl")):
        raise AssertionError("exec must retain affiliation")
    for site in ("p11_return", "p11_return_impl", "ordinary_return",
                 "object_return", "capture_return_facts"):
        if "p11_root_current_exit" in function(main, site):
            raise AssertionError("return must retain affiliation")
    impl = function(main, "p11_return_impl")
    for branch in ("ordinary_return", "object_return"):
        if impl.count(branch + "(") != 1:
            raise AssertionError(f"return must dispatch once to {branch}")
    if ("image_pair_matches" in impl or "p11_root_current_tag" in impl
            or "capture_return_facts" in impl):
        raise AssertionError("return dispatch must not inline the image guard or CALL tag")
    facts = function(main, "capture_return_facts")
    if facts.count("p11_root_current_tag") != 1:
        raise AssertionError("CALL tag must live exactly once in capture_return_facts")
    for branch in ("ordinary_return", "object_return"):
        body = function(main, branch)
        if body.count("image_pair_matches") != 1:
            raise AssertionError(f"{branch} must carry exactly one image guard")
        if body.count("capture_return_facts(") != 1:
            raise AssertionError(f"{branch} must capture CALL facts exactly once")
        if body.index("image_pair_matches") > body.index("capture_return_facts("):
            raise AssertionError("CALL tag must follow image guard")
    fork = function(main, "p11_link_emit_fork")
    if "root_affiliation: unsafe { p11_root_current_tag() }" not in fork:
        raise AssertionError("FORK must tag only the emitting parent")
    birth = identity[identity.index("int task_newtask("):]
    if not birth.index("p11_stop_gate_enter()") < birth.index("p11_root_propagate_thread("):
        raise AssertionError("fork admission must precede root propagation")
    if not birth.index("p11_root_propagate_thread(") < birth.index("if (clone_flags & CLONE_THREAD)") < birth.index("p11_link_fork_allowed()"):
        raise AssertionError("pre-wake thread propagation must precede semantic filters")
    if not (birth.index("p11_root_propagate_thread(") < birth.index("p11_instance_fork(")
            < birth.index("if (clone_flags & CLONE_THREAD)")):
        raise AssertionError("instance sharer marking must see every admitted birth before filters")


class RootAffiliationTests(unittest.TestCase):
    def test_production_hook_order(self):
        main = (ROOT / "crates/ebpf/src/main.rs").read_text()
        identity = (ROOT / "crates/ebpf/native/image_identity_fork.c").read_text()
        hook_contract(main, identity)
        exit_body = function(main, "sched_process_exit_impl")
        guard_end = exit_body.index("let _ = unsafe { p11_owner_cleanup() };")
        root_start = exit_body.index('#[cfg(not(feature = "inventory-only"))]', guard_end)
        root_end = exit_body.index('};', root_start) + 2
        root_block = exit_body[root_start:root_end]
        owner = "unsafe { p11_owner_cleanup() };"
        changed_exits = [
            exit_body.replace(root_block, ""),
            exit_body.replace(root_block, "if false { " + root_block + " }"),
            exit_body.replace(owner, "if false { " + owner, 1)
                     .replace(root_block, root_block + " }", 1),
            exit_body.replace(root_block, root_block.replace('#[cfg(not(feature = "inventory-only"))]', "")),
            exit_body.replace(root_block, root_block.replace('not(feature = "inventory-only")', 'feature = "inventory-only"')),
            exit_body.replace(owner, "OWNER_SWAP", 1)
                     .replace(root_block, owner, 1)
                     .replace("OWNER_SWAP", root_block, 1),
            exit_body[:-1] + " unsafe { p11_root_current_exit() }; }",
        ]
        mutants = [main.replace(exit_body, changed, 1) for changed in changed_exits]
        mutants += [
            main.replace("pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {",
                         "pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 { unsafe { p11_root_current_exit() };"),
            main.replace("pub fn p11_return(ctx: RetProbeContext) -> u32 {",
                         "pub fn p11_return(ctx: RetProbeContext) -> u32 { unsafe { p11_root_current_exit() };"),
        ]
        exit_admission = ("pub fn sched_process_exit(_ctx: RawTracePointContext) -> u32 {\n"
                          "    if !stop_gate_enter() {\n        return 0;\n    }\n")
        exit_call = "    let rc = sched_process_exit_impl(_ctx);\n"
        mutants += [
            main.replace(exit_admission,
                         "pub fn sched_process_exit(_ctx: RawTracePointContext) -> u32 {\n", 1),
            main.replace(exit_call + "    stop_gate_leave();\n", exit_call, 1),
            main.replace(exit_call + "    stop_gate_leave();\n",
                         "    stop_gate_leave();\n" + exit_call, 1),
            main.replace(exit_call, "    unsafe { p11_owner_cleanup() };\n" + exit_call, 1),
            main.replace("pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {\n"
                         "    if !stop_gate_enter() {\n        return 0;\n    }\n",
                         "pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {\n", 1),
        ]
        ordinary = function(main, "ordinary_return")
        guard = ("    let mut image = ImageIdentity::default();\n"
                 "    if unsafe { p11_link_current_identity(&mut image) } != 1\n"
                 "        || !image_pair_matches(start.image, image)\n"
                 "    {\n"
                 "        bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);\n"
                 "        return 0;\n"
                 "    }\n")
        facts_line = ("    let facts = capture_return_facts(ctx, &start, flags, layout, accounting);\n")
        swapped = ordinary.replace(guard + facts_line, facts_line + guard, 1)
        self.assertNotEqual(swapped, ordinary, "guard/facts swap must apply")
        mutants += [
            main.replace("        ordinary_return(ctx, &key, start, flags, layout)\n",
                         "        object_return(ctx, &key, start, flags, layout)\n", 1),
            main.replace("        object_return(ctx, &key, start, flags, layout)\n",
                         "        ordinary_return(ctx, &key, start, flags, layout)\n", 1),
            main.replace(ordinary, swapped, 1),
            main.replace("        || !image_pair_matches(start.image, image)\n", "", 1),
            main.replace("        || !image_pair_matches(unsafe { (*start).image }, image)\n", "", 1),
            main.replace("        root_affiliation: unsafe { p11_root_current_tag() },\n", "", 1),
        ]
        for mutant in mutants:
            self.assertNotEqual(mutant, main, "mutation must change the tested source")
            with self.assertRaises((AssertionError, ValueError)):
                hook_contract(mutant, identity)
        gate_removed = identity.replace("    if (!p11_stop_gate_enter())\n        return 0;\n", "")
        self.assertNotEqual(gate_removed, identity, "mutation must change the tested source")
        with self.assertRaises((AssertionError, ValueError)):
            hook_contract(main, gate_removed)
        instance_call = "    (void)p11_instance_fork(child, clone_flags);\n"
        thread_filter = "    if (clone_flags & CLONE_THREAD)\n        return 0;\n"
        for instance_mutant in [
            identity.replace(instance_call, ""),
            identity.replace(instance_call, "").replace(
                thread_filter, thread_filter + instance_call, 1),
        ]:
            self.assertNotEqual(instance_mutant, identity, "mutation must change the tested source")
            with self.assertRaises((AssertionError, ValueError)):
                hook_contract(main, instance_mutant)

    def test_native_production_helpers(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-root-affiliation-") as directory:
            for small in [False, True]:
                binary = Path(directory) / ("small" if small else "normal")
                argv = ["clang-18", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                        "-I", str(ROOT / "crates/ebpf/native"),
                        str(ROOT / "tests/fixtures/root-affiliation/helper_tests.c"),
                        "-o", str(binary)]
                if small:
                    argv.append("-DP11SCOPE_SMALL_STATE_MAPS")
                compiled = subprocess.run(argv, capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                executed = subprocess.run([str(binary)], capture_output=True, text=True)
                self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)

    def test_native_birth_hook(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-root-birth-") as directory:
            binary = Path(directory) / "birth"
            argv = ["clang-18", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unknown-attributes",
                    "-I", str(ROOT / "crates/ebpf/native"),
                    str(ROOT / "tests/fixtures/root-affiliation/birth_hook_tests.c"), "-o", str(binary)]
            compiled = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromNames(args.cases, __import__(__name__))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
