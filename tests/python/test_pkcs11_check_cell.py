#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the pkcs11-check CI cell (scripts/ci/pkcs11-check-cell.sh).

The cell runs the pinned pkcs11-check suite against SoftHSM in three legs
((a) alone, (b) under `p11scope run`, (c) under `p11scope run --manifest`)
and judges them with scripts/ci/pkcs11_check_cell_compare.py. These tests
pin the two hardening fixes: the compare helper judges per-unit return codes
as part of the identical-results check, and every leg removes stale verdict
files before running so a re-run into a reused OUT cannot pass on old
outputs. Deletion is bounded: only the verdict files and the isolation-state
files go; tokens, configs and logs survive.

Run: python3 -I tests/python/test_pkcs11_check_cell.py -v
"""

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "pkcs11_check_cell_compare.py"
SCRIPT = ROOT / "scripts" / "ci" / "pkcs11-check-cell.sh"

_SPEC = importlib.util.spec_from_file_location(
    "pkcs11_check_cell_compare", HELPER)
_COMPARE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMPARE)

SUMMARY = {
    "passed": 122, "failed": 0, "skipped": 11, "xfailed": 0,
    "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0,
    "crash_limited": 0, "total": 133, "incomplete": False,
}
COUNT_KEYS = (
    "passed", "failed", "skipped", "xfailed", "xpassed", "error",
    "crashed", "timeout", "crash_limited",
)
# Every file suite_args must delete, and every keeper it must preserve.
STALE = (
    "results.json", "report.jsonl", "observed.json",
    "observer.out", "observer.err",
    ".pkcs11-check-isolation-state.json",
    ".pkcs11-check-isolation-state-policy.json",
)
KEEPERS = ("softhsm2.conf", "stdout.log", "stderr.log", "tokens/keep")


def make_unit(target, status="passed", returncode=0, passed=6, skipped=0):
    counts = {key: 0 for key in COUNT_KEYS}
    counts["passed"] = passed
    counts["skipped"] = skipped
    return {"target": target, "status": status,
            "counts": counts, "returncode": returncode}


def results_doc(units):
    return {"provenance": {"framework": {"version": "0.2.3"}},
            "summary": dict(SUMMARY), "units": units}


def base_units():
    return [make_unit("/venv/lib/python3.14/site-packages/pkcs11_check/testcases/test_interface.py"),
            make_unit("/venv/lib/python3.14/site-packages/pkcs11_check/testcases/test_slot.py",
                      passed=106, skipped=4)]


def write_results(path, units):
    Path(path).write_text(json.dumps(results_doc(units)), encoding="utf-8")


def observed_doc():
    return {"schema": "p11scope/observed-profile/v3",
            "functions": [], "evidence": {}}


def suite_args_source():
    """The verbatim suite_args function from the shipped cell script."""
    text = SCRIPT.read_text(encoding="utf-8")
    matches = re.findall(r"(?ms)^suite_args\(\) \{$\n(.*?)\n^\}$", text)
    assert len(matches) == 1, (
        f"expected exactly one suite_args in {SCRIPT}, found {len(matches)}; "
        "the stale-output test cannot run against a refactored script")
    return f"suite_args() {{\n{matches[0]}\n}}"


class CompareHelperTests(unittest.TestCase):
    maxDiff = 2000

    def test_matching_units_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            other = Path(tmp) / "other.json"
            write_results(base, base_units())
            write_results(other, base_units())
            ok, detail = _COMPARE.compare_results(base, other, "a-vs-b")
            self.assertTrue(ok, detail)

    def test_returncode_divergence_fails(self):
        # F1: same status and counts, but the unit exited 137 (SIGKILL-like)
        # on the other leg. Must fail, naming the unit and the codes.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            other = Path(tmp) / "other.json"
            write_results(base, base_units())
            mutated = base_units()
            mutated[0]["returncode"] = 137
            write_results(other, mutated)
            ok, detail = _COMPARE.compare_results(base, other, "a-vs-b")
            self.assertFalse(ok, "returncode 0 vs 137 passed as identical")
            self.assertIn("test_interface.py", detail)
            self.assertIn("137", detail)

    def test_returncode_divergence_in_the_second_unit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            other = Path(tmp) / "other.json"
            write_results(base, base_units())
            mutated = base_units()
            mutated[1]["returncode"] = 1
            write_results(other, mutated)
            ok, detail = _COMPARE.compare_results(base, other, "a-vs-b")
            self.assertFalse(ok, "returncode 0 vs 1 passed as identical")
            self.assertIn("test_slot.py", detail)

    def test_status_divergence_still_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            other = Path(tmp) / "other.json"
            write_results(base, base_units())
            mutated = base_units()
            mutated[0]["status"] = "failed"
            write_results(other, mutated)
            ok, _ = _COMPARE.compare_results(base, other, "a-vs-b")
            self.assertFalse(ok)

    def run_helper_end_to_end(self, tmp, mutate_b=None):
        """Full helper run over matching legs; mutate_b rewrites leg-b units."""
        tmp = Path(tmp)
        units_a = base_units()
        units_b = base_units()
        if mutate_b is not None:
            mutate_b(units_b)
        write_results(tmp / "results-a.json", units_a)
        write_results(tmp / "results-b.json", units_b)
        write_results(tmp / "results-c.json", base_units())
        for name in ("report-a.jsonl", "report-b.jsonl", "report-c.jsonl"):
            (tmp / name).write_text("", encoding="utf-8")
        for name in ("observed-b.json", "observed-c.json"):
            (tmp / name).write_text(json.dumps(observed_doc()), encoding="utf-8")
        out_results = tmp / "results.jsonl"
        out_summary = tmp / "summary.txt"
        result = subprocess.run(
            [sys.executable, "-I", str(HELPER), "--mode", "smoke",
             "--results-a", str(tmp / "results-a.json"),
             "--report-a", str(tmp / "report-a.jsonl"),
             "--exit-a", "0", "--wall-a", "1.0",
             "--results-b", str(tmp / "results-b.json"),
             "--report-b", str(tmp / "report-b.jsonl"),
             "--exit-b", "0", "--wall-b", "1.0",
             "--observed-b", str(tmp / "observed-b.json"),
             "--results-c", str(tmp / "results-c.json"),
             "--report-c", str(tmp / "report-c.jsonl"),
             "--exit-c", "0", "--wall-c", "1.0",
             "--observed-c", str(tmp / "observed-c.json"),
             "--floor", "0.5",
             "--out-results", str(out_results),
             "--out-summary", str(out_summary)],
            capture_output=True, text=True, timeout=60)
        rows = {}
        if out_results.is_file():
            for line in out_results.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    rows[row["cell"]] = row
        return result, rows

    def test_end_to_end_returncode_divergence_fails_identical_results(self):
        # The review's M4 mutation through the real entry point: leg-b unit 0
        # exits 137 with unchanged status/counts.
        def kill_unit_zero(units):
            units[0]["returncode"] = 137
        with tempfile.TemporaryDirectory() as tmp:
            result, rows = self.run_helper_end_to_end(tmp, kill_unit_zero)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("pkcs11-check-identical-results", rows)
            row = rows["pkcs11-check-identical-results"]
            self.assertFalse(row["pass"], row["detail"])
            self.assertIn("test_interface.py", row["detail"])
            self.assertIn("137", row["detail"])

    def test_end_to_end_matching_inputs_pass_the_identical_row(self):
        # The empty reports leave the oracle rows vacuously failing, so the
        # exit stays 1; this test pins only the identical-results row.
        with tempfile.TemporaryDirectory() as tmp:
            _, rows = self.run_helper_end_to_end(tmp)
            self.assertIn("pkcs11-check-identical-results", rows)
            self.assertTrue(rows["pkcs11-check-identical-results"]["pass"],
                            rows["pkcs11-check-identical-results"]["detail"])


class StaleOutputTests(unittest.TestCase):
    def test_each_leg_removes_stale_verdict_files(self):
        function = suite_args_source()
        for leg in ("a", "b", "c"):
            for mode in ("smoke", "full"):
                with self.subTest(leg=leg, mode=mode):
                    with tempfile.TemporaryDirectory() as tmp:
                        out = Path(tmp) / "cells"
                        leg_dir = out / f"leg-{leg}"
                        leg_dir.mkdir(parents=True)
                        for name in STALE:
                            (leg_dir / name).write_text("stale", encoding="utf-8")
                        for name in KEEPERS:
                            keeper = leg_dir / name
                            keeper.parent.mkdir(parents=True, exist_ok=True)
                            keeper.write_text("keep", encoding="utf-8")
                        # OUT/MODE/MODULE are shell variables (not exports):
                        # suite_args reads them the way the cell script sets them.
                        script = (
                            f"OUT={out}\nMODE={mode}\n"
                            "MODULE=/usr/lib/softhsm/libsofthsm2.so\n"
                            f"{function}\nsuite_args {leg}\n"
                        )
                        result = subprocess.run(
                            ["bash", "-c", script],
                            capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        for name in STALE:
                            self.assertFalse((leg_dir / name).exists(),
                                             f"stale {name} survived on leg {leg}")
                        for name in KEEPERS:
                            self.assertTrue((leg_dir / name).is_file(),
                                            f"keeper {name} deleted on leg {leg}")
                        echo = result.stdout
                        self.assertIn(
                            f"--output-file {leg_dir}/results.json", echo)
                        if mode == "smoke":
                            self.assertIn("--marker smoke", echo)
                        else:
                            self.assertNotIn("--marker", echo)


if __name__ == "__main__":
    unittest.main()
