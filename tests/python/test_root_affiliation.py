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


def hook_contract(main, identity):
    exit_body = function(main, "sched_process_exit")
    owner = "unsafe { p11_owner_cleanup() };"
    owner_at = exit_body.index(owner)
    before_owner = re.sub(r"//[^\n]*", "", exit_body[:owner_at]).strip()
    if before_owner != "{" or exit_body.count("p11_owner_cleanup") != 1:
        raise AssertionError("owner cleanup must unconditionally begin the exit handler")
    tail = exit_body[owner_at + len(owner):]
    root = re.match(
        r'\s*#\[cfg\(not\(feature = "inventory-only"\)\)\]'
        r'\s*unsafe\s*\{\s*p11_root_current_exit\(\)\s*\};', tail)
    if root is None or exit_body.count("p11_root_current_exit") != 1:
        raise AssertionError("Detailed root cleanup must immediately follow owner cleanup; Inventory must omit it")
    if "p11_root_current_exit" in function(main, "sched_process_exec"):
        raise AssertionError("exec must retain affiliation")
    call = function(main, "p11_return")
    if "p11_root_current_exit" in call:
        raise AssertionError("return must retain affiliation")
    if call.index("image_pair_matches") > call.index("p11_root_current_tag"):
        raise AssertionError("CALL tag must follow image guard")
    fork = function(main, "p11_link_emit_fork")
    if "root_affiliation: unsafe { p11_root_current_tag() }" not in fork:
        raise AssertionError("FORK must tag only the emitting parent")
    birth = identity[identity.index("int task_newtask("):]
    if not birth.index("p11_root_propagate_thread(") < birth.index("if (clone_flags & CLONE_THREAD)") < birth.index("p11_link_fork_allowed()"):
        raise AssertionError("pre-wake thread propagation must precede semantic filters")


class RootAffiliationTests(unittest.TestCase):
    def test_production_hook_order(self):
        main = (ROOT / "crates/ebpf/src/main.rs").read_text()
        identity = (ROOT / "crates/ebpf/native/image_identity_fork.c").read_text()
        hook_contract(main, identity)
        exit_body = function(main, "sched_process_exit")
        root_start = exit_body.index('#[cfg(not(feature = "inventory-only"))]')
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
        for mutant in mutants:
            self.assertNotEqual(mutant, main, "mutation must change the tested source")
            with self.assertRaises((AssertionError, ValueError)):
                hook_contract(mutant, identity)

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
