#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the provider-matrix CI cell (scripts/ci/provider-matrix-cell.sh).

The cell runs the pinned pkcs11-check suite (or a pkcs11-tool probe for
reader-less providers) against one provider in two legs ((a) alone,
(b) under `p11scope run`), plus a `p11scope-discover` manifest assertion
and a paced workload under `p11scope inventory --pid`. The judge is
scripts/ci/provider_matrix_cell_compare.py. These tests pin the judge:

- run-observed counts only calls whose functions[].module joins to the
  provider file (sha256, dev/ino fallback); null-module rows never count;
- inventory-pid passes only when the workload pid is a caller AND the
  provider module carries edge calls; anything else fails as not observed;
- the kryoptic discover row is named kryoptic-multi-table and pins the
  exact 4-surface shape; an ambiguity refusal becomes an expected-failure
  pointing at the static-progs I2 fix, never a silent skip;
- providers without pinned surfaces record nonqualifying rows, but a
  discover crash still fails.

Run: python3 -I tests/python/test_provider_matrix_cell.py -v
"""

import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "provider_matrix_cell_compare.py"
SCRIPT = ROOT / "scripts" / "ci" / "provider-matrix-cell.sh"

_SPEC = importlib.util.spec_from_file_location(
    "provider_matrix_cell_compare", HELPER)
_COMPARE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMPARE)

SUMMARY = {
    "passed": 129, "failed": 0, "skipped": 4, "xfailed": 0,
    "xpassed": 0, "error": 0, "crashed": 0, "timeout": 0,
    "crash_limited": 0, "total": 133, "incomplete": False,
}
COUNT_KEYS = (
    "passed", "failed", "skipped", "xfailed", "xpassed", "error",
    "crashed", "timeout", "crash_limited",
)
# Every file leg_prep must delete, and every keeper it must preserve.
STALE = (
    "results.json", "report.jsonl", "observed.json",
    "observer.out", "observer.err",
    ".pkcs11-check-isolation-state.json",
    ".pkcs11-check-isolation-state-policy.json",
)
KEEPERS = ("provider.conf", "stdout.log", "stderr.log", "tokens/keep")

KRYOPTIC_MANIFEST = {
    "schema": "p11scope-manifest/5",
    "interface_list": {"status": "ok"},
    "surfaces": [
        {"source": {"kind": "legacy_function_list"},
         "version": {"major": 2, "minor": 40},
         "walk": {"status": "full"},
         "functions": [{} for _ in range(68)]},
        {"source": {"kind": "interface"},
         "version": {"major": 3, "minor": 2},
         "walk": {"status": "full"},
         "functions": [{} for _ in range(104)]},
        {"source": {"kind": "interface"},
         "version": {"major": 3, "minor": 0},
         "walk": {"status": "full"},
         "functions": [{} for _ in range(92)]},
        {"source": {"kind": "interface"},
         "version": {"major": 2, "minor": 40},
         "walk": {"status": "full"},
         "functions": [{} for _ in range(68)]},
    ],
}


def make_module(tmp, name="libprovider.so", content=b"fake-provider"):
    path = Path(tmp) / name
    path.write_bytes(content)
    return path


def module_identity(path):
    data = Path(path).read_bytes()
    stat = Path(path).stat()
    return {
        "dev": [dev_major(stat.st_dev), dev_minor(stat.st_dev)],
        "ino": stat.st_ino,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def dev_major(dev):
    return (dev >> 8) & 0xFFF | ((dev >> 32) & 0xFFFFF000)


def dev_minor(dev):
    return (dev & 0xFF) | ((dev >> 12) & 0xFFFFFF00)


def function_row(names, module, calls, rv_counts=None):
    return {"names": names, "module": module, "calls": calls,
            "rv_counts": rv_counts or {}}


def observed_doc(rows):
    return {"schema": "p11scope/observed-profile/v3",
            "functions": rows, "evidence": {}}


def inventory_doc(module_path, pid, edge_calls, seen=True, extra_gaps=()):
    identity = module_identity(module_path)
    doc = {
        "modules": [{"id": "m0", "paths": [str(module_path)],
                     "identity": {"device": {"major": identity["dev"][0],
                                             "minor": identity["dev"][1]},
                                  "inode": identity["ino"],
                                  "sha256": identity["sha256"]}}],
        "edges": [{"module": "m0", "entries": {"count": edge_calls}}],
        "callers": ([{"id": "c0", "pid": pid}] if seen else []),
        "gaps": list(extra_gaps),
    }
    return doc


def make_unit(target, status="passed", returncode=0, passed=129, skipped=4):
    counts = {key: 0 for key in COUNT_KEYS}
    counts["passed"] = passed
    counts["skipped"] = skipped
    return {"target": target, "status": status,
            "counts": counts, "returncode": returncode}


def results_doc(units):
    return {"provenance": {"framework": {"version": "0.2.3"}},
            "summary": dict(SUMMARY), "units": units}


def base_units():
    return [make_unit("/venv/lib/python3.14/site-packages/pkcs11_check/testcases/test_slot.py"),
            make_unit("/venv/lib/python3.14/site-packages/pkcs11_check/testcases/test_session.py",
                      passed=0, skipped=0)]


def leg_prep_source():
    """The verbatim leg_prep function from the shipped cell script."""
    text = SCRIPT.read_text(encoding="utf-8")
    matches = re.findall(r"(?ms)^leg_prep\(\) \{$\n(.*?)\n^\}$", text)
    assert len(matches) == 1, (
        f"expected exactly one leg_prep in {SCRIPT}, found {len(matches)}; "
        "the stale-output test cannot run against a refactored script")
    return f"leg_prep() {{\n{matches[0]}\n}}"


class RunObservedTests(unittest.TestCase):
    def test_attributed_calls_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            rows = [function_row(["C_Initialize"], module_identity(module), 61,
                                 {"0x0000000000000000": 61})]
            ok, detail, _ = _COMPARE.judge_run_observed(
                observed_doc(rows), str(module))
            self.assertTrue(ok, detail)
            self.assertIn("61", detail)

    def test_zero_calls_fails_as_not_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            rows = [function_row(["C_Initialize"], module_identity(module), 0)]
            ok, detail, _ = _COMPARE.judge_run_observed(
                observed_doc(rows), str(module))
            self.assertFalse(ok, "0 attributed calls passed as observed")
            self.assertIn("not observed", detail)

    def test_null_module_rows_never_count(self):
        # 500 calls with module null (unowned aggregate cells) must not
        # satisfy the observed row: the owner is not knowable.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            rows = [function_row(["unknown"], None, 500)]
            ok, detail, _ = _COMPARE.judge_run_observed(
                observed_doc(rows), str(module))
            self.assertFalse(ok, "null-module calls passed as observed")
            self.assertIn("not observed", detail)

    def test_other_module_calls_do_not_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp, content=b"provider-a")
            other = make_module(tmp, name="libother.so", content=b"other")
            rows = [function_row(["C_Initialize"], module_identity(other), 61)]
            ok, detail, _ = _COMPARE.judge_run_observed(
                observed_doc(rows), str(module))
            self.assertFalse(ok, "foreign-module calls passed as observed")
            self.assertIn("not observed", detail)

    def test_dev_ino_fallback_counts_when_sha_unpinned(self):
        # sha256 null (nothing pinned the object) still joins on dev/ino.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            identity = module_identity(module)
            identity["sha256"] = None
            rows = [function_row(["C_Initialize"], identity, 7)]
            ok, detail, _ = _COMPARE.judge_run_observed(
                observed_doc(rows), str(module))
            self.assertTrue(ok, detail)
            self.assertIn("dev-ino", detail)


class InventoryPidTests(unittest.TestCase):
    def test_caller_with_edge_calls_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            ok, detail = _COMPARE.judge_inventory_pid(
                inventory_doc(module, 4242, 656), str(module), 4242)
            self.assertTrue(ok, detail)
            self.assertIn("656", detail)

    def test_missing_pid_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            ok, detail = _COMPARE.judge_inventory_pid(
                inventory_doc(module, 4242, 656, seen=False), str(module), 4242)
            self.assertFalse(ok, "workload pid absent passed as observed")
            self.assertIn("not observed", detail)

    def test_zero_edge_calls_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            ok, detail = _COMPARE.judge_inventory_pid(
                inventory_doc(module, 4242, 0), str(module), 4242)
            self.assertFalse(ok, "0 edge calls passed as observed")
            self.assertIn("not observed", detail)

    def test_module_absent_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            doc = inventory_doc(module, 4242, 656)
            doc["modules"] = []
            ok, detail = _COMPARE.judge_inventory_pid(doc, str(module), 4242)
            self.assertFalse(ok, "absent module passed as observed")
            self.assertIn("not observed", detail)

    def test_gap_only_pid_fails_with_the_named_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            gaps = [{"pid": 4242, "reason": "caller_custody_unproven"}]
            ok, detail = _COMPARE.judge_inventory_pid(
                inventory_doc(module, 4242, 0, seen=False, extra_gaps=gaps),
                str(module), 4242)
            self.assertFalse(ok, "gap-only pid passed as observed")
            self.assertIn("caller_custody_unproven", detail)


class DiscoverTests(unittest.TestCase):
    def test_kryoptic_exact_shape_passes(self):
        ok, qual, detail = _COMPARE.judge_discover(
            "kryoptic", "1.5.2", 0, KRYOPTIC_MANIFEST, "")
        self.assertTrue(ok, detail)
        self.assertEqual("qualified", qual)

    def test_kryoptic_surface_drift_fails(self):
        mutated = json.loads(json.dumps(KRYOPTIC_MANIFEST))
        mutated["surfaces"][1]["functions"].pop()
        ok, qual, detail = _COMPARE.judge_discover(
            "kryoptic", "1.5.2", 0, mutated, "")
        self.assertFalse(ok, "104 -> 103 function drift passed")
        self.assertEqual("qualified", qual)
        self.assertIn("103", detail)

    def test_kryoptic_reordered_surfaces_fail(self):
        mutated = json.loads(json.dumps(KRYOPTIC_MANIFEST))
        mutated["surfaces"][1], mutated["surfaces"][2] = (
            mutated["surfaces"][2], mutated["surfaces"][1])
        ok, _, detail = _COMPARE.judge_discover(
            "kryoptic", "1.5.2", 0, mutated, "")
        self.assertFalse(ok, "reordered surfaces passed")

    def test_kryoptic_ambiguity_refusal_is_expected_failure(self):
        ok, qual, detail = _COMPARE.judge_discover(
            "kryoptic", "1.5.2", 1, None,
            "discover: two function tables match; refusing as ambiguous")
        self.assertFalse(ok)
        self.assertEqual("expected-failure", qual)
        self.assertIn("kryoptic-multi-table", detail)
        self.assertIn("I2", detail)

    def test_kryoptic_non_ambiguity_crash_fails_qualified(self):
        ok, qual, detail = _COMPARE.judge_discover(
            "kryoptic", "1.5.2", 1, None, "discover: cannot dlopen: boom")
        self.assertFalse(ok)
        self.assertEqual("qualified", qual)
        self.assertNotIn("expected-failure", detail)

    def test_unpinned_provider_records_nonqualifying(self):
        # spy-softhsm2 has no pinned shape: the row records the surfaces
        # for the pin commit instead of asserting them.
        manifest = {"interface_list": {"status": "ok"}, "surfaces": []}
        ok, qual, detail = _COMPARE.judge_discover(
            "spy-softhsm2", "spy+2.7", 0, manifest, "")
        self.assertTrue(ok, detail)
        self.assertEqual("nonqualifying", qual)
        self.assertIn("not yet pinned", detail)

    def test_unpinned_provider_crash_still_fails(self):
        ok, qual, _ = _COMPARE.judge_discover(
            "spy-softhsm2", "spy+2.7", 1, None,
            "discover: cannot dlopen: boom")
        self.assertFalse(ok)
        self.assertEqual("nonqualifying", qual)

    def test_bouncyhsm_exact_shape_passes(self):
        manifest = {
            "interface_list": {"status": "ok"},
            "surfaces": [
                {"source": {"kind": "legacy_function_list"},
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 3, "minor": 1},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(92)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 3, "minor": 2},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(104)]},
            ],
        }
        ok, qual, detail = _COMPARE.judge_discover(
            "bouncyhsm", "2.3.2", 0, manifest, "")
        self.assertTrue(ok, detail)
        self.assertEqual("qualified", qual)

    def test_haskoki_exact_shape_passes(self):
        manifest = {
            "interface_list": {"status": "ok"},
            "surfaces": [
                {"source": {"kind": "legacy_function_list"},
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 3, "minor": 2},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(104)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 3, "minor": 1},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(92)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 3, "minor": 0},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(92)]},
            ],
        }
        ok, qual, detail = _COMPARE.judge_discover(
            "haskoki", "0.5.0.0", 0, manifest, "")
        self.assertTrue(ok, detail)
        self.assertEqual("qualified", qual)


class MainTests(unittest.TestCase):
    maxDiff = 3000

    def write_cell(self, tmp, provider="kryoptic", version="1.5.2",
                   edge_calls=656, run_calls=61, run_calls_b=0):
        base = Path(tmp)
        module = make_module(tmp)
        for leg in ("a", "b", "c"):
            (base / f"results-{leg}.json").write_text(
                json.dumps(results_doc(base_units())), encoding="utf-8")
            (base / f"report-{leg}.jsonl").write_text("", encoding="utf-8")
        rows_b = [function_row(["C_Initialize"], module_identity(module),
                               run_calls_b,
                               {"0x0000000000000000": run_calls_b})]
        (base / "observed-b.json").write_text(
            json.dumps(observed_doc(rows_b)), encoding="utf-8")
        rows_c = [function_row(["C_Initialize"], module_identity(module),
                               run_calls, {"0x0000000000000000": run_calls})]
        (base / "observed-c.json").write_text(
            json.dumps(observed_doc(rows_c)), encoding="utf-8")
        (base / "inventory.json").write_text(
            json.dumps(inventory_doc(module, 4242, edge_calls)),
            encoding="utf-8")
        (base / "manifest.json").write_text(
            json.dumps(KRYOPTIC_MANIFEST), encoding="utf-8")
        (base / "discover.stderr").write_text("", encoding="utf-8")
        args = ["--provider", provider, "--provider-version", version,
                "--module", str(module),
                "--discover-rc", "0", "--manifest", str(base / "manifest.json"),
                "--discover-stderr", str(base / "discover.stderr"),
                "--suite", "yes",
                "--results-a", str(base / "results-a.json"),
                "--report-a", str(base / "report-a.jsonl"),
                "--exit-a", "0", "--wall-a", "9.0",
                "--results-b", str(base / "results-b.json"),
                "--report-b", str(base / "report-b.jsonl"),
                "--exit-b", "0", "--wall-b", "11.0",
                "--results-c", str(base / "results-c.json"),
                "--report-c", str(base / "report-c.jsonl"),
                "--exit-c", "0", "--wall-c", "12.0",
                "--observed-b", str(base / "observed-b.json"),
                "--observed-c", str(base / "observed-c.json"),
                "--inventory", str(base / "inventory.json"),
                "--workload-pid", "4242",
                "--out-results", str(base / "results.jsonl"),
                "--out-summary", str(base / "summary.txt")]
        return base, args

    def test_green_cell_exits_zero_with_six_rows(self):
        # The manifest leg carries the observed gate; a blind default leg
        # (short-lived workers, no manifest) records its coverage row
        # without failing the cell.
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_cell(tmp)
            rc = _COMPARE.main(args)
            self.assertEqual(0, rc)
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            self.assertEqual(6, len(rows))
            by_cell = {row["cell"]: row for row in rows}
            self.assertIn("kryoptic-multi-table", by_cell)
            self.assertTrue(by_cell["kryoptic-run-observed"]["pass"])
            self.assertEqual(
                "nonqualifying",
                by_cell["kryoptic-default-run-coverage"]["qualification"])
            qualified = [row for row in rows
                         if row["qualification"] == "qualified"]
            self.assertTrue(all(row["pass"] for row in qualified),
                            json.dumps(rows, indent=1))

    def test_unobserved_manifest_leg_fails_the_cell(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_cell(tmp, run_calls=0)
            rc = _COMPARE.main(args)
            self.assertEqual(1, rc)
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            observed = next(row for row in rows
                            if row["cell"] == "kryoptic-run-observed")
            self.assertFalse(observed["pass"])
            self.assertIn("not observed", observed["detail"])

    def test_manifest_leg_divergence_fails_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_cell(tmp)
            mutated = base_units()
            mutated[0]["counts"]["passed"] = 1
            (base / "results-c.json").write_text(
                json.dumps(results_doc(mutated)), encoding="utf-8")
            rc = _COMPARE.main(args)
            self.assertEqual(1, rc)
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            identical = next(row for row in rows
                             if row["cell"] == "kryoptic-identical-results")
            self.assertFalse(identical["pass"])

    def test_tool_mode_marks_identical_nonqualifying(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            module = make_module(tmp)
            rows = [function_row(["C_Initialize"], module_identity(module), 5)]
            (base / "observed-b.json").write_text(
                json.dumps(observed_doc(rows)), encoding="utf-8")
            (base / "observed-c.json").write_text(
                json.dumps(observed_doc(rows)), encoding="utf-8")
            (base / "inventory.json").write_text(
                json.dumps(inventory_doc(module, 4242, 12)),
                encoding="utf-8")
            (base / "manifest.json").write_text(
                json.dumps(KRYOPTIC_MANIFEST), encoding="utf-8")
            (base / "discover.stderr").write_text("", encoding="utf-8")
            args = ["--provider", "kryoptic", "--provider-version", "1.5.2",
                    "--module", str(module),
                    "--discover-rc", "0",
                    "--manifest", str(base / "manifest.json"),
                    "--discover-stderr", str(base / "discover.stderr"),
                    "--suite", "no",
                    "--exit-a", "0", "--wall-a", "1.0",
                    "--exit-b", "0", "--wall-b", "2.0",
                    "--exit-c", "0", "--wall-c", "3.0",
                    "--observed-b", str(base / "observed-b.json"),
                    "--observed-c", str(base / "observed-c.json"),
                    "--inventory", str(base / "inventory.json"),
                    "--workload-pid", "4242",
                    "--out-results", str(base / "results.jsonl"),
                    "--out-summary", str(base / "summary.txt")]
            rc = _COMPARE.main(args)
            self.assertEqual(0, rc)
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            by_cell = {row["cell"]: row for row in rows}
            self.assertEqual(
                "nonqualifying",
                by_cell["kryoptic-identical-results"]["qualification"])
            self.assertTrue(by_cell["kryoptic-run-observed"]["pass"])
            self.assertTrue(by_cell["kryoptic-inventory-pid"]["pass"])


class LegPrepTests(unittest.TestCase):
    def test_leg_prep_deletes_only_verdict_files(self):
        # Runs the shipped leg_prep against a fixture leg dir: every STALE
        # file goes, every KEEPER (and the token dir) survives.
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            leg = Path(tmp) / "leg-b"
            (leg / "tokens").mkdir(parents=True)
            for name in STALE:
                (leg / name).write_text("stale", encoding="utf-8")
            for name in KEEPERS:
                target = leg / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("keep", encoding="utf-8")
            script = leg_prep_source() + f'\nleg_prep "{leg}"\n'
            proc = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True,
                timeout=60)
            self.assertEqual(0, proc.returncode, proc.stderr)
            for name in STALE:
                self.assertFalse((leg / name).exists(),
                                 f"stale file survived: {name}")
            for name in KEEPERS:
                self.assertTrue((leg / name).is_file(),
                                f"keeper deleted: {name}")


if __name__ == "__main__":
    unittest.main()
