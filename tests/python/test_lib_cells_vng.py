#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The kernel-sensitive lib-cell subset guest script: exact cells, judging, exits.

Drives scripts/ci/lib-cells-vng.sh with a stubbed `vng` that writes canned
guest artifacts (no KVM, no root): every exit code and results.jsonl row is
covered, including the harness-error arms. The guest inner script itself is
pinned statically (tmpfs TMPDIR, exact libtest flags, boot-config staging).

Run: python3 -I tests/python/test_lib_cells_vng.py -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/lib-cells-vng.sh"
RUNNER = ROOT / "scripts/run-privileged-lib-tests.sh"

EXPECTED_CELLS = [
    "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64",
    "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64",
    "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64",
    "attach::identity_iter::tests::anchor_maps_validate_real_handles",
    "attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none",
    "attach::identity_iter::tests::whole_system_run_covers_all_children",
    "attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm",
    "metrics::counter_reader::tests::counter_reader_native_maps_match_all_modes",
    "metrics::counter_reader::tests::counter_reader_requires_exact_maps_and_health",
    "events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict",
]

# A canned guest: parses --run/--rwdir from the script's vng invocation and
# writes the artifacts a real guest would, per FAKE_VNG_MODE. Never boots.
FAKE_VNG = r'''#!/bin/sh
kernel=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --run) kernel="$2"; shift 2;;
        --rwdir) out="$2"; shift 2;;
        *) shift;;
    esac
done
mode="${FAKE_VNG_MODE:-all-pass}"
if [ "$mode" = "rc1" ]; then echo "vng: cannot boot"; exit 1; fi
release="${kernel#v}"
[ "$mode" = "wrong-kernel" ] && release="9.9.9"
echo "$release" > "$out/uname.txt"
echo "staged-boot-config-$release"
i=0
while IFS= read -r cell; do
    [ -z "$cell" ] && continue
    rc=0; body="test result: ok. 1 passed"
    if [ "$mode" = "one-fail" ] && [ "$i" = 3 ]; then rc=1; body="test result: FAILED. 0 passed"; fi
    if [ "$mode" = "zero-passed" ] && [ "$i" = 0 ]; then body="test result: ok. 0 passed"; fi
    if [ "$mode" = "renamed-status" ] && [ "$i" = 1 ]; then cell="renamed::cell"; fi
    if [ "$mode" = "missing-log" ] && [ "$i" = 2 ]; then :; else printf 'line\n%s\n' "$body" > "$out/cell-$i.log"; fi
    echo "$i $rc $cell" >> "$out/status.txt"
    i=$((i + 1))
done < "$FAKE_CELLS_FILE"
if [ "$mode" = "no-finish" ]; then exit 0; fi
echo "cells-done count=$i"
'''


def default_tests(text):
    """The curated DEFAULT_TESTS selectors of run-privileged-lib-tests.sh."""
    cells, inside = [], False
    for line in text.splitlines():
        if line.startswith("DEFAULT_TESTS=("):
            inside = True
            continue
        if inside and line == ")":
            break
        if inside and line and not line.startswith("#"):
            cells.append(line.strip())
    return cells


class LibCellsVngTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "scripts/ci/lib-cells-vng.sh is missing")
        self.assertTrue(RUNNER.is_file(), "run-privileged-lib-tests.sh is missing")
        self.text = SCRIPT.read_text(encoding="utf-8")
        self.temp = tempfile.TemporaryDirectory(prefix="lib-cells-vng-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        vng = self.bin / "vng"
        vng.write_text(FAKE_VNG)
        vng.chmod(0o700)
        cells_file = self.work / "cells.txt"
        cells_file.write_text("\n".join(EXPECTED_CELLS) + "\n")
        self.cells_file = cells_file
        libtest = self.work / "lib-tests"
        libtest.write_text("#!/bin/sh\nexit 0\n")
        libtest.chmod(0o700)
        self.libtest = libtest

    def run_script(self, *args, mode="all-pass", path=None):
        env = dict(os.environ, FAKE_VNG_MODE=mode,
                   FAKE_CELLS_FILE=str(self.cells_file),
                   LIB_CELLS_VNG_TEST="1")
        env["PATH"] = (str(self.bin) if path is None else path) + os.pathsep + env["PATH"]
        out = self.work / "out"
        command = [str(SCRIPT), str(self.libtest), str(out), *args]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=120, env=env), out

    def test_cells_are_exact_and_curated(self):
        self.assertEqual(len(EXPECTED_CELLS), 12)
        curated = default_tests(RUNNER.read_text(encoding="utf-8"))
        self.assertTrue(curated, "no DEFAULT_TESTS parsed from the runner")
        for cell in EXPECTED_CELLS:
            with self.subTest(cell=cell):
                self.assertIn(cell, self.text)
                self.assertIn(cell, curated)

    def test_default_kernels_are_66_and_612(self):
        self.assertIn("set -- v6.6.157 v6.12.111", self.text)

    def test_inner_runs_cells_on_a_guest_tmpfs_like_the_privileged_runner(self):
        for pin in ("mount -t tmpfs", 'TMPDIR="$T"', "--exact",
                    "--test-threads=1", "--nocapture", "ulimit -n 65536",
                    "P11SCOPE_TASK4_EVIDENCE_DIR",
                    "staged-boot-config", "test result: ok\\. 1 passed"):
            with self.subTest(pin=pin):
                self.assertIn(pin, self.text)

    def test_all_pass_writes_one_row_per_cell_and_exits_zero(self):
        result, out = self.run_script("v6.6.157")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in
                (out / "results.jsonl").read_text().splitlines()]
        self.assertEqual([row["cell"] for row in rows], EXPECTED_CELLS)
        for row in rows:
            self.assertEqual(set(row), {"cell", "pass", "qualification", "detail"})
            self.assertTrue(row["pass"])
            self.assertEqual(row["qualification"], "qualified")
            self.assertIn("v6.6.157", row["detail"])

    def test_failing_cell_fails_its_row_and_exits_one(self):
        result, out = self.run_script("v6.6.157", mode="one-fail")
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = [json.loads(line) for line in
                (out / "results.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 12)
        failed = [row for row in rows if not row["pass"]]
        self.assertEqual([row["cell"] for row in failed], [EXPECTED_CELLS[3]])
        self.assertEqual(failed[0]["qualification"], "failed")

    def test_zero_passes_is_not_a_pass(self):
        result, out = self.run_script("v6.6.157", mode="zero-passed")
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = [json.loads(line) for line in
                (out / "results.jsonl").read_text().splitlines()]
        self.assertFalse(rows[0]["pass"])

    def test_renamed_status_cell_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="renamed-status")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_log_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="missing-log")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_wrong_guest_kernel_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="wrong-kernel")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_unfinished_guest_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="no-finish")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_vng_failure_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="rc1")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_vng_exits_77(self):
        # Only realpath is reachable: the script needs it before the vng
        # check, and no real vng may leak in from the ambient PATH (a guest
        # must never boot here).
        narrow = self.work / "narrowbin"
        narrow.mkdir()
        realpath = shutil.which("realpath")
        self.assertTrue(realpath, "realpath not found")
        (narrow / "realpath").symlink_to(realpath)
        env = dict(os.environ, LIB_CELLS_VNG_TEST="1", PATH=str(narrow))
        out = self.work / "out"
        result = subprocess.run([str(SCRIPT), str(self.libtest), str(out), "v6.6.157"],
                                capture_output=True, text=True, timeout=30,
                                env=env)
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_home_guard_stays_for_real_runs(self):
        self.assertIn("must be under /home", self.text)
        scratch = Path(tempfile.mkdtemp(prefix="lib-cells-guard-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, scratch, True)
        libtest = scratch / "lib-tests"
        libtest.write_text("#!/bin/sh\nexit 0\n")
        libtest.chmod(0o700)
        env = dict(os.environ)
        env.pop("LIB_CELLS_VNG_TEST", None)
        # Hermetic: the guard runs after the vng prerequisite check,
        # so a stub vng on PATH keeps this green where virtme-ng is
        # absent. The stub never runs: the guard exits first.
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        result = subprocess.run([str(SCRIPT), str(libtest), str(scratch / "out")],
                                capture_output=True, text=True, timeout=30,
                                env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must be under /home", result.stderr)

    def test_usage_errors_exit_two(self):
        out = self.work / "out"
        # Hermetic: the kernel-name gate runs after the vng
        # prerequisite check, so a stub vng on PATH keeps the
        # not-a-kernel arm green where virtme-ng is absent. The stub
        # never runs: usage gates exit first.
        env = dict(os.environ,
                   PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        for argv in ([], [str(self.libtest)],
                    [str(self.libtest), str(out), "not-a-kernel"]):
            with self.subTest(argv=argv):
                result = subprocess.run([str(SCRIPT), *argv],
                                        capture_output=True, text=True,
                                        timeout=30, env=env)
                self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
