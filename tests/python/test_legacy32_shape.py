# SPDX-License-Identifier: GPL-3.0-or-later
"""SoftHSM 2.7 table-shape seams, unprivileged.

Pins what scripts/ci/legacy32-shape.sh and the qualify-public-cli.sh cell
filter it relies on must do without privileges:

- the --shape-only gates: the positive plus one failing variant per
  reachable gate (version, slot count, shape words, export count,
  non-C_ exports), each asserting the gate it must fail at, so a deleted
  or weakened gate turns its test red;
- the P11SCOPE_PUBLIC_CLI_CELLS validation: unknown cells and control-mode
  combinations fail closed before any privileged setup;
- the LEGACY32_QUALIFY stub seam: it never bypasses the root requirement
  and --shape-only ignores it.

Two shape words (GATED6, GETTER_SLOT) have no failing variant by
construction: any violation of either also violates an earlier gate, so a
variant would fail before reaching them. The nm-level C_GetInterface
refutation is likewise redundant with the INTERFACES word (a symbol
visible to nm -D resolves via dlsym). The positive pins all three words.

Privileged behavior (subset campaigns, wrap/flip exit codes, the
stock-system control) is exercised by authorized live runs, not here.
Run: python3 -I tests/python/test_legacy32_shape.py -v
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEGACY32 = ROOT / "scripts/ci/legacy32-shape.sh"
QUALIFY = ROOT / "scripts/qualify-public-cli.sh"
TIMEOUT = 600
FOUR_KEYS = {"cell", "pass", "detail", "qualification"}


def run_shape(out, *, cflags=None, env_extra=None):
    env = dict(os.environ)
    if cflags is not None:
        env["LEGACY32_CFLAGS"] = cflags
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(LEGACY32), "--shape-only", str(out)],
        env=env, capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
    )


def read_rows(out):
    rows = []
    for line in (out / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def run_qualify(args, *, cells=None):
    env = dict(os.environ)
    if cells is not None:
        env["P11SCOPE_PUBLIC_CLI_CELLS"] = cells
    return subprocess.run(
        ["bash", str(QUALIFY), *args],
        env=env, capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
    )


class ShapeOnlyGateTests(unittest.TestCase):
    def assert_shape_fails_at(self, cflags, env_extra, gate):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out, cflags=cflags, env_extra=env_extra)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            row = rows[0]
            self.assertEqual(set(row), FOUR_KEYS, row)
            self.assertEqual(row["cell"], "legacy32-shape", row)
            self.assertFalse(row["pass"], row)
            self.assertEqual(row["qualification"], "failed", row)
            self.assertIn(gate, row["detail"], row)

    def test_the_documented_shape_passes(self):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = read_rows(out)
            self.assertEqual(len(rows), 1, rows)
            row = rows[0]
            self.assertEqual(set(row), FOUR_KEYS, row)
            self.assertEqual(row["cell"], "legacy32-shape", row)
            self.assertTrue(row["pass"], row)
            self.assertEqual(row["qualification"], "qualified", row)
            for fact in ("VERSION 3 2", "NONNULL68 68", "DISTINCT68 1",
                         "SLOT68 0x1", "GATED6 1", "GETTER_SLOT 1",
                         "INTERFACES 0"):
                self.assertIn(fact, proc.stdout, proc.stdout)

    def test_the_minor_zero_variant_fails_at_the_version_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_MINOR=0", None, "version gate: want VERSION 3 2")

    def test_a_foreign_slot_count_fails_at_the_slot_count_gate(self):
        self.assert_shape_fails_at(None, {"LEGACY32_EXPECT_SLOTS": "92"}, "slot-count gate")

    def test_a_null_slot_fails_at_the_nonnull_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_NULL_SLOT66", None, "want NONNULL68 68")

    def test_an_aliased_slot_fails_at_the_distinct_gate(self):
        self.assert_shape_fails_at("-DLEGACY32_ALIAS_SLOT66", None, "want DISTINCT68 1")

    def test_a_foreign_tail_fails_at_the_slot68_word(self):
        self.assert_shape_fails_at(None, {"LEGACY32_EXPECT_TAIL": "0x2"}, "want SLOT68 0x2")

    def test_an_interface_export_fails_at_the_interfaces_word(self):
        self.assert_shape_fails_at("-DLEGACY32_EXPORT_INTERFACE", None, "want INTERFACES 0")

    def test_a_hidden_slot_fails_at_the_export_count_gate(self):
        self.assert_shape_fails_at(
            "-DLEGACY32_HIDE_SLOT67", None, "want exactly 68 defined C_ exports")

    def test_an_extra_export_fails_at_the_non_c_export_gate(self):
        self.assert_shape_fails_at(
            "-DLEGACY32_EXTRA_EXPORT", None, "non-C_ text export present")

    def test_shape_only_usage_requires_an_outdir(self):
        proc = subprocess.run(
            ["bash", str(LEGACY32), "--shape-only"],
            capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
        )
        self.assertEqual(proc.returncode, 64, proc.stderr)

    def test_shape_only_ignores_the_qualify_stub_seam(self):
        with tempfile.TemporaryDirectory(prefix="legacy32-") as tmp:
            out = Path(tmp) / "out"
            proc = run_shape(out, env_extra={"LEGACY32_QUALIFY": "/nonexistent-stub"})
            self.assertEqual(proc.returncode, 0, proc.stderr)


class CellFilterValidationTests(unittest.TestCase):
    def test_an_unknown_cell_fails_closed(self):
        observer = ROOT / "nonexistent-observer-for-filter-test"
        self.assertFalse(observer.exists())
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            for cells, offender in (("nope", "nope"),
                                    ("profile-pid nope", "nope"),
                                    ("names-pid", "names-pid"),
                                    ("system names-pid", "names-pid")):
                with self.subTest(cells=cells):
                    proc = run_qualify([str(observer), tmp], cells=cells)
                    self.assertEqual(proc.returncode, 64, proc.stderr)
                    self.assertIn("unsupported subset cell", proc.stderr)
                    self.assertIn(offender, proc.stderr)
                    self.assertIn("profile-pid", proc.stderr)

    def test_the_filter_cannot_combine_with_a_control_mode(self):
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            proc = run_qualify(
                ["--control-gated", str(ROOT / "no-observer"), tmp, str(ROOT / "no-fixture")],
                cells="profile-pid",
            )
            self.assertEqual(proc.returncode, 64, proc.stderr)
            self.assertIn("cannot be combined", proc.stderr)

    def test_supported_names_pass_validation(self):
        # A nonexistent observer fails after validation, so reaching its
        # error proves the names were accepted; no campaign can start.
        observer = ROOT / "nonexistent-observer-for-filter-test"
        self.assertFalse(observer.exists())
        with tempfile.TemporaryDirectory(prefix="filter-") as tmp:
            for cells in ("profile-pid system",
                          "profile-pid metrics-pid trace-pid mt-exact system"):
                with self.subTest(cells=cells):
                    proc = run_qualify([str(observer), tmp], cells=cells)
                    self.assertEqual(proc.returncode, 64, proc.stderr)
                    self.assertNotIn("unsupported subset cell", proc.stderr)
                    self.assertNotIn("cannot be combined", proc.stderr)


class StubSeamTests(unittest.TestCase):
    def test_the_stub_seam_never_bypasses_the_root_gate(self):
        self.assertNotEqual(os.geteuid(), 0, "this validation must run unprivileged")
        with tempfile.TemporaryDirectory(prefix="seam-") as tmp:
            env = dict(os.environ, LEGACY32_QUALIFY=str(ROOT / "no-such-qualify"))
            proc = subprocess.run(
                ["bash", str(LEGACY32), "/bin/true", tmp],
                env=env, capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT,
            )
            self.assertEqual(proc.returncode, 64, proc.stderr)
            self.assertIn("must run as root", proc.stderr)


if __name__ == "__main__":
    unittest.main()
