#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The vng qualify wrappers propagate guest failures to their exit code.

Drives scripts/qualify-public-cli-vng.sh,
scripts/qualify-inventory-c1b-vng.sh and scripts/ci/run-tree-vng.sh
with a stubbed `vng` (no KVM, no root): the inner guest script never
runs; the stub writes the canned result files a guest would. Scratch
lives under $HOME because the wrappers require their binary and
OUTDIR under /home.

Run: python3 -I tests/python/test_vng_wrapper_exits.py -v
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CLI_WRAPPER = ROOT / "scripts/qualify-public-cli-vng.sh"
C1B_WRAPPER = ROOT / "scripts/qualify-inventory-c1b-vng.sh"
RUNTREE_WRAPPER = ROOT / "scripts/ci/run-tree-vng.sh"
RUN_TREE_CELLS = (
    "privileged_run_tree_shell_wrapper_shows_grandchild_calls",
    "privileged_run_tree_double_fork_shows_reparented_calls",
    "privileged_run_tree_outliving_child_is_disclosed",
    "privileged_run_tree_many_children_land_exact",
)

# A canned guest: parses --rwdir from the wrapper's vng invocation and
# writes the result files per FAKE_WRAPPER_MODE. Never boots.
FAKE_VNG = r'''#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --rwdir) out="$2"; shift 2;;
        *) shift;;
    esac
done
write_minimal() {
    mkdir -p "$out/minimal-cells"
    echo '{"cell":"stub","pass":true,"qualification":"qualified","detail":"stub"}' > "$out/minimal-cells/results.jsonl"
    echo "minimal_exit=$1" > "$out/minimal.log"
}
write_qual() {
    mkdir -p "$out/cells"; echo "SUMMARY pass=1 fail=0" > "$out/cells/summary.txt"
    echo "qual_exit=$1" > "$out/qual.log"
}
mode="${FAKE_WRAPPER_MODE:-cli-pass-0}"
case "$mode" in
    vng-fail) echo "vng: unknown kernel"; exit 1;;
esac
echo "6.6.157" > "$out/uname.txt"
case "$mode" in
    cli-pass-*) n="${mode#cli-pass-}";;
    cli-minimal-fail) n=0;;
    cli-smoke-minimal-fail) n=2;;
    cli-minimal-missing) n=0;;
    cli-no-summary) echo "qual_exit=0" > "$out/qual.log"; exit 0;;
    cli-no-qual-exit)
        mkdir -p "$out/cells"; echo "SUMMARY pass=1 fail=0" > "$out/cells/summary.txt"
        echo "no exit recorded" > "$out/qual.log"
        write_minimal 0; exit 0;;
    c1b-pass-*) n="${mode#c1b-pass-}";;
    c1b-no-cells-log) exit 0;;
    c1b-no-cells-exit) echo "no exit recorded" > "$out/cells.log"; exit 0;;
    *) echo "bad fake mode $mode"; exit 3;;
esac
case "$mode" in
    cli-pass-*) write_qual "$n"; write_minimal 0;;
    cli-minimal-fail) write_qual 0; write_minimal 1;;
    cli-smoke-minimal-fail) write_qual 2; write_minimal 1;;
    cli-minimal-missing) write_qual 0;;
    c1b-pass-*)
        { [ "$n" = 0 ] && echo "VERDICT: PASS" || echo "VERDICT: FAIL"; } > "$out/cells.log"
        echo "cells_exit=$n" >> "$out/cells.log";;
esac
'''


class VngWrapperExitTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CLI_WRAPPER.is_file(), "public-cli vng wrapper is missing")
        self.assertTrue(C1B_WRAPPER.is_file(), "c1b vng wrapper is missing")
        self.assertTrue(RUNTREE_WRAPPER.is_file(), "run-tree vng wrapper is missing")
        # Both wrappers refuse paths outside /home, so the scratch tree
        # lives under $HOME and is removed afterwards.
        self.home_scratch = Path(tempfile.mkdtemp(prefix="vng-wrapper-test-",
                                                  dir=str(Path.home())))
        self.addCleanup(shutil.rmtree, self.home_scratch, True)
        self.temp = tempfile.TemporaryDirectory(prefix="vng-wrapper-bin-")
        self.addCleanup(self.temp.cleanup)
        staged = Path(self.temp.name) / "bin"
        staged.mkdir()
        vng = staged / "vng"
        vng.write_text(FAKE_VNG)
        vng.chmod(0o700)
        self.staged_bin = staged
        binary = self.home_scratch / "p11scope"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o700)
        self.binary = binary
        # The run-tree wrapper stages the booted kernel's config from a
        # one-config cache entry.
        cache_boot = self.home_scratch / "vng-cache" / "v6.6.157" / "amd64" / "boot"
        cache_boot.mkdir(parents=True)
        (cache_boot / "config-6.6.157").write_text("CONFIG_LTO=y\n")
        self.vng_cache = self.home_scratch / "vng-cache"

    def run_wrapper(self, wrapper, *extra, mode):
        env = dict(os.environ, FAKE_WRAPPER_MODE=mode)
        env["PATH"] = str(self.staged_bin) + os.pathsep + env["PATH"]
        out = self.home_scratch / ("out-" + mode.replace("/", "-"))
        command = [str(wrapper), "v6.6.157", str(self.binary), str(out), *extra]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=60, env=env), out

    def test_cli_pass_exit_zero(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-pass-0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vng_exit=0", result.stdout)

    def test_cli_keeps_exit_two_for_nonqualifying_smoke(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-pass-2")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("vng_exit=0", result.stdout)

    def test_cli_fail_exits_one(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-pass-1")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_cli_vng_failure_exits_nonzero(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="vng-fail")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("vng_exit=1", result.stdout)

    def test_cli_missing_summary_exits_nonzero(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-no-summary")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_cli_missing_qual_exit_exits_nonzero(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-no-qual-exit")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_cli_minimal_failure_exits_one(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-minimal-fail")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("minimal setcap leg failed", result.stderr)

    def test_cli_minimal_failure_dominates_smoke(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-smoke-minimal-fail")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_cli_minimal_missing_results_exit_nonzero(self):
        result, _ = self.run_wrapper(CLI_WRAPPER, mode="cli-minimal-missing")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("minimal-cells/results.jsonl", result.stderr)

    def test_c1b_pass_and_fail_propagate(self):
        result, _ = self.run_wrapper(C1B_WRAPPER, mode="c1b-pass-0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vng_exit=0", result.stdout)
        result, _ = self.run_wrapper(C1B_WRAPPER, mode="c1b-pass-1")
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_c1b_vng_failure_exits_nonzero(self):
        result, _ = self.run_wrapper(C1B_WRAPPER, mode="vng-fail")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("vng_exit=1", result.stdout)

    def test_c1b_missing_results_exit_nonzero(self):
        for mode in ("c1b-no-cells-log", "c1b-no-cells-exit"):
            with self.subTest(mode=mode):
                result, _ = self.run_wrapper(C1B_WRAPPER, mode=mode)
                self.assertEqual(result.returncode, 1, result.stderr)

    def run_runtree(self, mode, id_stub=None):
        # The run-tree wrapper takes TESTBIN OUTDIR KERNEL and stages
        # the kernel config from RUN_TREE_VNG_CACHE. inner.sh is
        # generated before vng runs, so even a vng failure leaves it
        # behind for inspection.
        staged = Path(self.temp.name) / "bin"
        if id_stub is not None:
            stub = staged / "id"
            stub.write_text(id_stub)
            stub.chmod(0o700)
            self.addCleanup(stub.unlink)
        env = dict(os.environ, FAKE_WRAPPER_MODE=mode,
                   RUN_TREE_VNG_CACHE=str(self.vng_cache))
        env["PATH"] = str(self.staged_bin) + os.pathsep + env["PATH"]
        out = self.home_scratch / ("out-runtree-" + mode.replace("/", "-"))
        command = [str(RUNTREE_WRAPPER), str(self.binary), str(out), "v6.6.157"]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=120, env=env), out

    def test_runtree_inner_names_the_host_drop_target(self):
        # The guest has no sudo session, so the wrapper bakes the
        # invoking ids into inner.sh as the owned-child drop target
        # (the qualify-public-cli.sh RUNUID/RUNGID precedent). Without
        # them every guest cell refuses with "root observer requires a
        # valid non-root SUDO_UID".
        id_stub = "#!/bin/sh\nif [ \"$1\" = -g ]; then echo 1002; else echo 1001; fi\n"
        result, out = self.run_runtree("vng-fail", id_stub=id_stub)
        inner = out / "inner.sh"
        self.assertTrue(inner.is_file(),
                        f"inner.sh missing; wrapper said: {result.stderr}")
        body = inner.read_text(encoding="utf-8")
        self.assertIn("SUDO_UID='1001'", body)
        self.assertIn("SUDO_GID='1002'", body)
        # The dropped child must traverse the guest workdir: the
        # root-owned mode-700 tmpfs would refuse it with EACCES.
        self.assertIn('chown "$SUDO_UID:$SUDO_GID" "$T"', body)

    def test_runtree_refuses_a_root_invoker_without_a_drop_target(self):
        # A root invoker names no non-root account: fail fast in the
        # harness instead of baking SUDO_UID=0 for the cells to refuse.
        id_stub = "#!/bin/sh\necho 0\n"
        result, out = self.run_runtree("vng-fail", id_stub=id_stub)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("non-root", result.stderr)
        self.assertFalse((out / "inner.sh").is_file())


if __name__ == "__main__":
    unittest.main()
