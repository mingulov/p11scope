#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The P2-8 witness CLI executor scripts: exact cells, judging, exits.

tests/prearm_witness_cli.rs holds the 6 P2-8 cells; scripts/ci/run-witness-cli.sh
runs them on the current machine with exact-positive judging, and
scripts/ci/witness-cli-vng.sh runs that runner inside one virtme-ng guest.
This suite pins the executed set to the curated INTEGRATION_TESTS entries,
runs the runner's --self-test, and drives the guest script with a stubbed
`vng` that writes canned guest artifacts (no KVM, no root): every exit
code is covered, including the harness-error arms.

Run: python3 -I tests/python/test_witness_cli_vng.py -v
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
RUNNER = ROOT / "scripts/ci/run-witness-cli.sh"
SCRIPT = ROOT / "scripts/ci/witness-cli-vng.sh"
CURATION = ROOT / "scripts/run-privileged-lib-tests.sh"

EXPECTED_CELLS = [
    "privileged_profile_pid_prearm_clean_exact_counts",
    "privileged_profile_cgroup_prearm_clean_exact_counts",
    "privileged_profile_system_prearm_clean_exact_counts",
    "privileged_profile_metrics_system_prearm_clean_exact_counts",
    "privileged_profile_pid_prearm_twin_exact_window",
    "privileged_trace_system_prearm_clean_exact_counts",
]

# A canned guest: parses --run/--rwdir from the script's vng invocation
# and writes the artifacts a real guest would, per FAKE_VNG_MODE. Never
# boots. Cells come from FAKE_CELLS_FILE, one per line.
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
[ "$mode" = "rc-triplet" ] && release="7.4.0-070400rc1-generic"
[ "$mode" = "rc-mismatch" ] && release="7.4.0-070400rc2-generic"
echo "$release" > "$out/uname.txt"
if [ "$mode" != "no-results" ]; then
    mkdir -p "$out/cells"
    : > "$out/cells/results.jsonl"
    i=0
    while IFS= read -r cell; do
        [ -z "$cell" ] && continue
        if [ "$mode" = "truncated" ] && [ "$i" = 5 ]; then i=$((i + 1)); continue; fi
        pass=true; qual=qualified; detail="rc=0 42ms ok"
        if { [ "$mode" = "one-fail" ] || [ "$mode" = "rows-fail-exit-zero" ]; } \
            && [ "$i" = 3 ]; then
            pass=false; qual=failed; detail="rc=101 42ms: FAILED"
        fi
        printf '{"cell": "%s", "pass": %s, "detail": "%s", "qualification": "%s"}\n' \
            "$cell" "$pass" "$detail" "$qual" >> "$out/cells/results.jsonl"
        i=$((i + 1))
    done < "$FAKE_CELLS_FILE"
    echo "SUMMARY" > "$out/cells/summary.txt"
fi
if [ "$mode" = "no-finish" ]; then exit 0; fi
code=0
if [ "$mode" = "one-fail" ] || [ "$mode" = "truncated" ]; then code=1; fi
if [ "$mode" = "rows-pass-exit-one" ]; then code=1; fi
echo "cells-done witness_exit=$code"
'''


def integration_witness_cells(text):
    """The curated tests/prearm_witness_cli.rs entries of INTEGRATION_TESTS."""
    cells, inside = [], False
    for line in text.splitlines():
        if line.startswith("INTEGRATION_TESTS=("):
            inside = True
            continue
        if inside and line == ")":
            break
        if inside and line.startswith("tests/prearm_witness_cli.rs:"):
            cells.append(line.split(":", 1)[1])
    return cells


class WitnessCliScriptTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(RUNNER.is_file(), "scripts/ci/run-witness-cli.sh is missing")
        self.assertTrue(SCRIPT.is_file(), "scripts/ci/witness-cli-vng.sh is missing")
        self.assertTrue(os.access(RUNNER, os.X_OK), "run-witness-cli.sh is not executable")
        self.assertTrue(os.access(SCRIPT, os.X_OK), "witness-cli-vng.sh is not executable")
        self.runner_text = RUNNER.read_text(encoding="utf-8")
        self.script_text = SCRIPT.read_text(encoding="utf-8")
        self.temp = tempfile.TemporaryDirectory(prefix="witness-cli-vng-")
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
        testbin = self.work / "prearm_witness_cli"
        testbin.write_text("#!/bin/sh\nexit 0\n")
        testbin.chmod(0o700)
        self.testbin = testbin
        # Hermetic vng cache for the stubbed runs below (all use v6.6.157):
        # the script stages the booted kernel's config, so the tests must
        # not depend on the ambient $HOME cache (absent on CI script runners).
        default_cache = self.work / "vng-cache-default"
        config_path = default_cache / "v6.6.157/amd64/boot/config-6.6.157-test"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("CONFIG_LTO_NONE=y\n")
        self.default_cache = default_cache

    def run_script(self, *args, mode="all-pass"):
        env = dict(os.environ, FAKE_VNG_MODE=mode,
                   FAKE_CELLS_FILE=str(self.cells_file),
                   WITNESS_CLI_VNG_TEST="1",
                   WITNESS_VNG_CACHE=str(self.default_cache))
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        out = self.work / "out"
        command = [str(SCRIPT), str(self.testbin), str(out), *args]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=120, env=env), out

    def test_cells_are_exact_and_curated(self):
        self.assertEqual(len(EXPECTED_CELLS), 6)
        curated = integration_witness_cells(CURATION.read_text(encoding="utf-8"))
        self.assertEqual(curated, EXPECTED_CELLS,
                         "the executed set must equal the curated INTEGRATION_TESTS entries")
        for cell in EXPECTED_CELLS:
            with self.subTest(cell=cell):
                self.assertIn(cell, self.runner_text)
                self.assertIn(cell, self.script_text)

    def test_runner_enforces_exact_positive(self):
        for pin in ("--exact", "--ignored", "--test-threads=1", "--nocapture",
                    "test result: ok\\. 1 passed", "timeout 300",
                    "must run as root (invoke via sudo -n)",
                    'TMPDIR="$PRIVTMP"', "selects $selected tests, want 1"):
            with self.subTest(pin=pin):
                self.assertIn(pin, self.runner_text)

    def test_runner_self_test_passes(self):
        result = subprocess.run([str(RUNNER), "--self-test"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-witness-cli self-test: OK", result.stdout)

    def test_runner_usage_errors_exit_two(self):
        out = self.work / "out"
        for argv in ([], [str(self.testbin)],
                    [str(self.testbin), str(out), "extra"]):
            with self.subTest(argv=argv):
                result = subprocess.run([str(RUNNER), *argv],
                                        capture_output=True, text=True,
                                        timeout=30)
                self.assertEqual(result.returncode, 2, result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "the root gate only binds non-root callers")
    def test_runner_refuses_non_root(self):
        out = self.work / "out"
        result = subprocess.run([str(RUNNER), str(self.testbin), str(out)],
                                capture_output=True, text=True,
                                timeout=30)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("must run as root", result.stderr)

    def test_guest_runs_the_runner_on_a_guest_tmpfs(self):
        for pin in ("vng --run", "--user root", "mount -t tmpfs",
                    'TMPDIR="$T"', "run-witness-cli.sh",
                    "cells-done witness_exit=", '"$OUT/uname.txt"',
                    "row set is not exactly the six P2-8 cells"):
            with self.subTest(pin=pin):
                self.assertIn(pin, self.script_text)

    def test_all_pass_writes_six_qualified_rows_and_exits_zero(self):
        result, out = self.run_script("v6.6.157")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in
                (out / "cells/results.jsonl").read_text().splitlines()]
        self.assertEqual([row["cell"] for row in rows], EXPECTED_CELLS)
        for row in rows:
            self.assertEqual(set(row), {"cell", "pass", "qualification", "detail"})
            self.assertTrue(row["pass"])
            self.assertEqual(row["qualification"], "qualified")
        self.assertTrue((out / "uname.txt").is_file())
        self.assertTrue((out / "vng-console.log").is_file())

    def test_failing_cell_fails_and_exits_one(self):
        result, out = self.run_script("v6.6.157", mode="one-fail")
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = [json.loads(line) for line in
                (out / "cells/results.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 6)
        failed = [row for row in rows if not row["pass"]]
        self.assertEqual([row["cell"] for row in failed], [EXPECTED_CELLS[3]])
        self.assertEqual(failed[0]["qualification"], "failed")

    def test_truncated_rows_are_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="truncated")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_results_are_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="no-results")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_exit_zero_with_failed_rows_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="rows-fail-exit-zero")
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_exit_one_with_passing_rows_is_a_harness_error(self):
        result, _ = self.run_script("v6.6.157", mode="rows-pass-exit-one")
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
        env = dict(os.environ, WITNESS_CLI_VNG_TEST="1", PATH=str(narrow))
        out = self.work / "out"
        result = subprocess.run([str(SCRIPT), str(self.testbin), str(out), "v6.6.157"],
                                capture_output=True, text=True, timeout=30,
                                env=env)
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_home_guard_stays_for_real_runs(self):
        self.assertIn("must be under /home", self.script_text)
        scratch = Path(tempfile.mkdtemp(prefix="witness-cli-guard-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, scratch, True)
        testbin = scratch / "prearm_witness_cli"
        testbin.write_text("#!/bin/sh\nexit 0\n")
        testbin.chmod(0o700)
        env = dict(os.environ)
        env.pop("WITNESS_CLI_VNG_TEST", None)
        # Hermetic: the guard runs after the vng prerequisite check,
        # so a stub vng on PATH keeps this green where virtme-ng is
        # absent. The stub never runs: the guard exits first.
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        result = subprocess.run([str(SCRIPT), str(testbin), str(scratch / "out"),
                                 "v6.6.157"],
                                capture_output=True, text=True, timeout=30,
                                env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must be under /home", result.stderr)

    def test_usage_errors_exit_two(self):
        out = self.work / "out"
        for argv in ([], [str(self.testbin)],
                    [str(self.testbin), str(out)],
                    [str(self.testbin), str(out), "not-a-kernel"]):
            with self.subTest(argv=argv):
                result = subprocess.run([str(SCRIPT), *argv],
                                        capture_output=True, text=True,
                                        timeout=30)
                self.assertEqual(result.returncode, 2, result.stderr)

    def run_script_with_cache(self, kernel, cache_files, mode="all-pass"):
        """Run the guest script with a stub vng cache holding cache_files.

        cache_files maps relative paths under the cache root to contents;
        the script must stage the booted kernel's config for the guest LTO
        gate (vng guests share the host rootfs, so /boot lacks it)."""
        cache = self.work / "vng-cache"
        for rel, content in cache_files.items():
            target = cache / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        env = dict(os.environ, FAKE_VNG_MODE=mode,
                   FAKE_CELLS_FILE=str(self.cells_file),
                   WITNESS_CLI_VNG_TEST="1",
                   WITNESS_VNG_CACHE=str(cache))
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        out = self.work / "out"
        command = [str(SCRIPT), str(self.testbin), str(out), kernel]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=120, env=env), out

    def test_guest_gets_booted_kernel_config(self):
        config = "CONFIG_LTO_NONE=y\n"
        result, out = self.run_script_with_cache(
            "v6.18.58",
            {"v6.18.58/amd64/boot/config-6.18.58-061858-generic": config},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        staged = out / "kernel-config"
        self.assertTrue(staged.is_file(),
                        "the harness must stage the booted kernel config")
        self.assertEqual(staged.read_text(encoding="utf-8"), config)

    def test_rc_tag_accepts_the_dotted_triplet_release(self):
        config = "CONFIG_LTO_NONE=y\n"
        result, _ = self.run_script_with_cache(
            "v7.4-rc1",
            {"v7.4-rc1/amd64/boot/config-7.4.0-070400rc1-generic": config},
            mode="rc-triplet",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rc_tag_rejects_another_rc_release(self):
        config = "CONFIG_LTO_NONE=y\n"
        result, _ = self.run_script_with_cache(
            "v7.4-rc1",
            {"v7.4-rc1/amd64/boot/config-7.4.0-070400rc1-generic": config},
            mode="rc-mismatch",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("expected v7.4-rc1", result.stderr)

    def test_partial_release_tags_stay_rejected(self):
        out = self.work / "out"
        for tag in ("v7.4", "7.4-rc1", "v7.4-rc"):
            with self.subTest(tag=tag):
                result = subprocess.run(
                    [str(SCRIPT), str(self.testbin), str(out), tag],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("use an explicit stock kernel release",
                              result.stderr)

    def test_missing_kernel_config_is_a_harness_error(self):
        result, _ = self.run_script_with_cache("v6.18.58", {})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("kernel config", result.stderr)

    def test_guest_installs_kernel_config_over_boot(self):
        for pin in ("kernel-config", "/boot/config-", "mount -t tmpfs",
                    "CONFIG_LTO"):
            with self.subTest(pin=pin):
                self.assertIn(pin, self.script_text)


if __name__ == "__main__":
    unittest.main()
