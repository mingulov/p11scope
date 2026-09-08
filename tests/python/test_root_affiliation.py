"""Actual native root helper tests and narrow production hook contracts."""
from pathlib import Path
import argparse
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
    root = "unsafe { p11_root_current_exit() };"
    tail = exit_body[exit_body.index(owner) + len(owner):].lstrip()
    if not tail.startswith(root):
        raise AssertionError("root cleanup must unconditionally follow owner cleanup")
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
        identity = (ROOT / "crates/ebpf/native/image_identity.c").read_text()
        hook_contract(main, identity)
        mutants = [
            main.replace("unsafe { p11_root_current_exit() };", ""),
            main.replace("unsafe { p11_root_current_exit() };", "if false { unsafe { p11_root_current_exit() }; }"),
            main.replace("pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {",
                         "pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 { unsafe { p11_root_current_exit() };"),
            main.replace("pub fn p11_return(ctx: RetProbeContext) -> u32 {",
                         "pub fn p11_return(ctx: RetProbeContext) -> u32 { unsafe { p11_root_current_exit() };"),
        ]
        for mutant in mutants:
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
