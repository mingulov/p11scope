#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the provider-matrix CI cell (scripts/ci/provider-matrix-cell.sh).

The cell runs the pinned pkcs11-check suite (or a pkcs11-tool probe for
reader-less providers) against one provider in three legs ((a) alone,
(b) under `p11scope run`, (c) under `p11scope run --manifest`), plus a
`p11scope-discover` manifest assertion and a paced workload under
`p11scope inventory --pid`. The judge is
scripts/ci/provider_matrix_cell_compare.py. These tests pin the judge:

- run-observed counts only calls whose functions[].module joins to the
  provider file (sha256, dev/ino fallback); null-module rows never count;
- inventory-pid passes only when the workload pid is a caller AND the
  provider module carries edge calls; anything else fails as not observed;
- the kryoptic discover row is named kryoptic-multi-table and pins the
  exact 4-surface shape; an ambiguity refusal becomes an expected-failure
  pointing at the static-progs I2 fix, never a silent skip;
- providers without pinned surfaces record nonqualifying rows, but a
  discover crash still fails;
- in root mode the cells directory is handed to the suite user before
  discover and the paced workload run: both create files directly in
  $OUT (manifest.json, workload.ready) under the setpriv drop, and a
  root-owned $OUT killed the CI cells with EACCES.

Run: python3 -I tests/python/test_provider_matrix_cell.py -v
"""

import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "ci" / "provider_matrix_cell_compare.py"
SCRIPT = ROOT / "scripts" / "ci" / "provider-matrix-cell.sh"
REMOTE_SCRIPT = ROOT / "scripts" / "provider-matrix" / "remote-cell.sh"

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


def preflight_block_source():
    """The verbatim optional-preflight block from the shipped cell script."""
    text = SCRIPT.read_text(encoding="utf-8")
    matches = re.findall(
        r'(?ms)^  if \[ -n "\$PROVIDER_PREFLIGHT" \]; then$'
        r"\n(.*?)\n  fi$", text)
    assert len(matches) == 1, (
        f"expected exactly one PROVIDER_PREFLIGHT block in {SCRIPT}, "
        f"found {len(matches)}; the preflight tests cannot run against "
        "a refactored script")
    return ("if [ -n \"$PROVIDER_PREFLIGHT\" ]; then\n"
            + matches[0] + "\nfi")


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

    def test_same_basename_different_bytes_never_joins(self):
        # A module that merely shares the basename with different bytes
        # must not satisfy the inventory row: a basename substring is
        # not an identity proof.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp, content=b"provider-bytes")
            elsewhere = Path(tmp) / "elsewhere"
            elsewhere.mkdir()
            decoy = make_module(elsewhere, content=b"other-bytes")
            ok, detail = _COMPARE.judge_inventory_pid(
                inventory_doc(decoy, 4242, 656), str(module), 4242)
            self.assertFalse(
                ok, "same-basename different-bytes module joined")
            self.assertIn("not observed", detail)
            self.assertIn("absent", detail)

    def test_unpinned_identity_dev_ino_fallback_joins(self):
        # sha256 null (unpinned object) and no exact path still joins on
        # the recorded device/inode identity, like the observed join.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            doc = inventory_doc(module, 4242, 656)
            doc["modules"][0]["identity"]["sha256"] = None
            doc["modules"][0]["paths"] = ["/elsewhere/libprovider.so"]
            ok, detail = _COMPARE.judge_inventory_pid(doc, str(module), 4242)
            self.assertTrue(ok, detail)
            self.assertIn("dev-ino", detail)

    def test_exact_path_without_digest_joins(self):
        # No identity recorded at all: an exact path match is a
        # same-file proof the cell may rely on.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp)
            doc = inventory_doc(module, 4242, 656)
            del doc["modules"][0]["identity"]
            ok, detail = _COMPARE.judge_inventory_pid(doc, str(module), 4242)
            self.assertTrue(ok, detail)
            self.assertIn("path", detail)

    def test_recorded_conflicting_digest_never_joins(self):
        # Same path, but the recorded sha256 belongs to different
        # bytes: the file changed under the path; refuse, never guess.
        with tempfile.TemporaryDirectory() as tmp:
            module = make_module(tmp, content=b"provider-bytes")
            doc = inventory_doc(module, 4242, 656)
            doc["modules"][0]["identity"]["sha256"] = hashlib.sha256(
                b"other-bytes").hexdigest()
            ok, detail = _COMPARE.judge_inventory_pid(doc, str(module), 4242)
            self.assertFalse(ok, "conflicting recorded digest joined")
            self.assertIn("absent", detail)


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

    def test_nss_softokn_exact_shape_passes(self):
        # NSS softokn (libsoftokn3.so, measured 3.120 Ubuntu + 3.131
        # Fedora, identical): legacy 2.40 plus 3.2/3.0/2.40 interfaces.
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
                 "version": {"major": 3, "minor": 0},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(92)]},
                {"source": {"kind": "interface"},
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
            ],
        }
        ok, qual, detail = _COMPARE.judge_discover(
            "nss-softokn", "system", 0, manifest, "")
        self.assertTrue(ok, detail)
        self.assertEqual("qualified", qual)

    def test_nss_softokn_surface_drift_fails(self):
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
                 "functions": [{} for _ in range(103)]},
            ],
        }
        ok, qual, detail = _COMPARE.judge_discover(
            "nss-softokn", "system", 0, manifest, "")
        self.assertFalse(ok, "dropped interface + 104 -> 103 drift passed")
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


    def test_p11kit_managed_exact_shape_passes(self):
        # The aggregating proxy surface is config-independent: managed
        # and unmanaged rows pin the same 3-surface shape as p11kit-proxy.
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
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
            ],
        }
        for provider in ("p11kit-managed", "p11kit-unmanaged"):
            ok, qual, detail = _COMPARE.judge_discover(
                provider, "system", 0, manifest, "")
            self.assertTrue(ok, f"{provider}: {detail}")
            self.assertEqual("qualified", qual)

    def test_p11kit_managed_surface_drift_fails(self):
        manifest = {
            "interface_list": {"status": "ok"},
            "surfaces": [
                {"source": {"kind": "legacy_function_list"},
                 "version": {"major": 2, "minor": 40},
                 "walk": {"status": "full"},
                 "functions": [{} for _ in range(68)]},
            ],
        }
        for provider in ("p11kit-managed", "p11kit-unmanaged"):
            ok, qual, _ = _COMPARE.judge_discover(
                provider, "system", 0, manifest, "")
            self.assertFalse(ok, f"{provider}: dropped surfaces passed")
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


PROXY_CONFIG_SNIPPET = (ROOT / "scripts" / "provider-matrix"
                        / "providers" / "_p11kit_proxy_config.sh")


def proxy_check_source():
    """The shipped token-list checker plus its fixture seam."""
    text = PROXY_CONFIG_SNIPPET.read_text(encoding="utf-8")
    matches = re.findall(
        r"(?ms)^p11kit_proxy_check_token_list\(\) \{$\n(.*?)\n^\}$", text)
    assert len(matches) == 1, (
        f"expected exactly one p11kit_proxy_check_token_list in "
        f"{PROXY_CONFIG_SNIPPET}, found {len(matches)}")
    return f"p11kit_proxy_check_token_list() {{\n{matches[0]}\n}}"


class P11KitProxyConfigTests(unittest.TestCase):
    def run_check(self, listing, label="p11matrix"):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "slots.txt"
            out.write_text(listing, encoding="utf-8")
            script = (proxy_check_source()
                      + f'\np11kit_proxy_check_token_list "{out}" "{label}"\n')
            proc = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True,
                timeout=60)
            return proc.returncode

    def test_single_expected_token_passes(self):
        listing = ("Available slots:\n"
                   "Slot 0 (0x1): SoftHSM slot 0\n"
                   "  token label        : p11matrix\n")
        self.assertEqual(0, self.run_check(listing))

    def test_second_token_fails(self):
        # user-config:only must isolate our module: a second token
        # means system modules leaked into the proxy view.
        listing = ("Available slots:\n"
                   "Slot 0 (0x1): SoftHSM slot 0\n"
                   "  token label        : p11matrix\n"
                   "Slot 1 (0x2): System Trust\n"
                   "  token label        : System Trust\n")
        self.assertNotEqual(0, self.run_check(listing))

    def test_wrong_label_fails(self):
        listing = ("Available slots:\n"
                   "Slot 0 (0x1): SoftHSM slot 0\n"
                   "  token label        : someone-else\n")
        self.assertNotEqual(0, self.run_check(listing))

    def test_empty_listing_fails(self):
        self.assertNotEqual(0, self.run_check("Available slots:\n"))


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


class PreflightDropTests(unittest.TestCase):
    # The preflight probe dlopens provider code: in root mode it must
    # run under the same setpriv drop as the cell's suite, never as
    # root. A setpriv shim on PATH records the drop the block uses.

    def run_block(self, tmp, rootmode, preflight_on_path=False):
        import subprocess
        base = Path(tmp)
        bin_dir = base / "bin"
        bin_dir.mkdir(exist_ok=True)
        setpriv = bin_dir / "setpriv"
        setpriv.write_text(
            "#!/bin/bash\n"
            "echo \"setpriv-shim $*\"\n"
            "while [ \"${1:0:1}\" = \"-\" ]; do shift; done\n"
            "exec \"$@\"\n", encoding="utf-8")
        setpriv.chmod(0o755)
        env_file = base / "probe.env"
        env_file.write_text(
            "probe() { echo \"probe-ran $(id -un)\"; }\n", encoding="utf-8")
        if preflight_on_path:
            probe = bin_dir / "probe"
            probe.write_text("#!/bin/sh\necho probe-exec-ran\n",
                             encoding="utf-8")
            probe.chmod(0o755)
        out = base / "out"
        out.mkdir(exist_ok=True)
        env = {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "PROVIDER_PREFLIGHT": "probe", "ROOTMODE": rootmode,
            "RUNUID": "4242", "RUNGID": "4242",
            "ENV_FILE": str(env_file), "OUT": str(out),
            "TASK_DIR": str(base / "task"), "PKCS11_MODULE": "/x.so",
            "PKCS11_TOOL": "pkcs11-tool",
            "PROVIDER_MATRIX_DIR": "/m",
        }
        script = preflight_block_source() + "\nexit 0\n"
        proc = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env=env, timeout=60)
        log_path = out / "preflight.log"
        log = (log_path.read_text(encoding="utf-8")
               if log_path.exists() else "")
        return proc, log

    def test_root_mode_preflight_runs_under_the_setpriv_drop(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, log = self.run_block(tmp, "yes")
            self.assertEqual(
                0, proc.returncode, f"{proc.stderr}\npreflight.log={log}")
            self.assertIn(
                "setpriv-shim --reuid=4242 --regid=4242 --clear-groups",
                log)
            self.assertIn("probe-ran", log)

    def test_user_mode_preflight_runs_direct(self):
        # User mode keeps running the preflight directly (no setpriv
        # wrapper): behavior unchanged by the root-mode fix.
        with tempfile.TemporaryDirectory() as tmp:
            proc, log = self.run_block(tmp, "no", preflight_on_path=True)
            self.assertEqual(
                0, proc.returncode, f"{proc.stderr}\npreflight.log={log}")
            self.assertIn("probe-exec-ran", log)
            self.assertNotIn("setpriv-shim", log)


def out_setup_source():
    """The verbatim $OUT setup from the shipped cell script."""
    text = SCRIPT.read_text(encoding="utf-8")
    matches = re.findall(
        r'(?ms)^mkdir -p "\$OUT" \|\| exit 2$\n(.*?)\n^COMPARE=', text)
    assert len(matches) == 1, (
        f"expected exactly one $OUT setup block in {SCRIPT}, "
        f"found {len(matches)}; the ownership tests cannot run against "
        "a refactored script")
    return f'mkdir -p "$OUT" || exit 2\n{matches[0]}\n'


class OutOwnershipTests(unittest.TestCase):
    # Root-mode CI shape: run-cell-script.sh creates the cells directory
    # as root, the cell script then runs discover and the paced workload
    # under setpriv as the suite user, and both create files directly in
    # $OUT with their own open() (manifest.json, workload.ready). A
    # root-owned $OUT makes both writes fail EACCES; the workload dies
    # instantly and the cell reports "workload never became ready"
    # (rc=2). The leg directories are already handed over by make_leg;
    # $OUT itself needs the same handover. A chown shim on PATH records
    # the handover the block performs.

    def run_setup(self, tmp, rootmode):
        import subprocess
        base = Path(tmp)
        bin_dir = base / "bin"
        bin_dir.mkdir(exist_ok=True)
        chown = bin_dir / "chown"
        chown.write_text(
            "#!/bin/bash\n"
            'echo "chown-shim $*" >> "$CHOWN_LOG"\n'
            "exit 0\n", encoding="utf-8")
        chown.chmod(0o755)
        log = base / "chown.log"
        out = base / "cells"
        env = {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "CHOWN_LOG": str(log),
            "ROOTMODE": rootmode, "RUNUID": "4242", "RUNGID": "4243",
            "OUT": str(out),
        }
        proc = subprocess.run(
            ["bash", "-c", out_setup_source()], capture_output=True,
            text=True, env=env, timeout=60)
        recorded = (log.read_text(encoding="utf-8")
                    if log.exists() else "")
        return proc, recorded, out

    def test_root_mode_hands_out_to_the_suite_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, recorded, out = self.run_setup(tmp, "yes")
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn(
                f"chown-shim 4242:4243 {Path(out).resolve()}", recorded,
                "root mode must chown $OUT to RUNUID:RUNGID so the "
                "dropped discover/workload writers can create files in it")

    def test_user_mode_never_chowns_out(self):
        # User (test-host) mode runs everything as one user: no handover.
        with tempfile.TemporaryDirectory() as tmp:
            proc, recorded, _ = self.run_setup(tmp, "no")
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertEqual("", recorded)

    def test_dropped_writers_create_files_directly_in_out(self):
        # Pins the two RUNUID writers that make the handover necessary:
        # discover opens its -o output itself and the workload writes its
        # ready file itself, both directly in $OUT (never inside the
        # make_leg-chowned leg directories).
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'as_user "$DISCOVER" --module "$PKCS11_MODULE"'
            ' -o "$OUT/manifest.json"', text)
        self.assertIn("READY=$OUT/workload.ready", text)


class ProviderNameValidationTests(unittest.TestCase):
    # A provider name containing any whitespace must be rejected at the
    # name check itself, not later at env-file lookup with a vaguer
    # error.
    WHITESPACE_NAMES = ("a b", "a\tb", "a\nb", " a")

    def run_cell(self, provider, task_dir):
        import subprocess
        fake = Path(task_dir) / "p11scope"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PROVIDER": provider, "TASK_DIR": task_dir}
        return subprocess.run(
            ["bash", str(SCRIPT), str(fake), str(Path(task_dir) / "out")],
            capture_output=True, text=True, env=env, timeout=60)

    def test_cell_rejects_names_with_any_whitespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            for provider in self.WHITESPACE_NAMES:
                with self.subTest(provider=repr(provider)):
                    proc = self.run_cell(provider, tmp)
                    self.assertEqual(2, proc.returncode, proc.stderr)
                    self.assertIn("bare provider name", proc.stderr)

    def test_cell_still_accepts_a_bare_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cell("no-such-provider", tmp)
            self.assertEqual(2, proc.returncode, proc.stderr)
            self.assertIn("no such provider env", proc.stderr)
            self.assertNotIn("bare provider name", proc.stderr)

    def run_remote(self, provider, task_dir, repo=None):
        import subprocess
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if repo is not None:
            pins = Path(task_dir) / "pins.env"
            pins.write_text("P11TEST_PIN=1234\n", encoding="utf-8")
            cell = Path(repo) / "scripts" / "ci" / "provider-matrix-cell.sh"
            cell.parent.mkdir(parents=True, exist_ok=True)
            cell.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
            cell.chmod(0o755)
            env.update({"TASK_DIR": task_dir, "REPO": str(repo),
                        "OUT": str(Path(task_dir) / "out"),
                        "P11SCOPE": "/x/p11scope", "DISCOVER": "/x/discover",
                        "P11CHECK": "/x/pkcs11-check", "PINS": str(pins)})
        return subprocess.run(
            ["bash", str(REMOTE_SCRIPT), provider],
            capture_output=True, text=True, env=env, timeout=60)

    def test_remote_rejects_names_with_any_whitespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            for provider in self.WHITESPACE_NAMES:
                with self.subTest(provider=repr(provider)):
                    proc = self.run_remote(provider, tmp)
                    self.assertEqual(2, proc.returncode, proc.stderr)
                    self.assertIn("remote-cell: bad provider name",
                                  proc.stderr)

    def test_remote_still_accepts_a_bare_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            proc = self.run_remote("x", tmp, repo=repo)
            self.assertEqual(3, proc.returncode, proc.stderr)
            self.assertNotIn("bad provider name", proc.stderr)


STATIC_EMBED_HELPER = (ROOT / "scripts" / "provider-matrix"
                        / "static_embed_cell_compare.py")

_STATIC_SPEC = importlib.util.spec_from_file_location(
    "static_embed_cell_compare", STATIC_EMBED_HELPER)
_STATIC = importlib.util.module_from_spec(_STATIC_SPEC)
_STATIC_SPEC.loader.exec_module(_STATIC)


class StaticEmbedTests(unittest.TestCase):
    def test_calls_log_parses_the_last_count(self):
        self.assertEqual(61, _STATIC.parse_calls_log("boot\nCALLS=61\n"))
        self.assertEqual(7, _STATIC.parse_calls_log("CALLS=61\nCALLS=7\n"))
        self.assertIsNone(_STATIC.parse_calls_log("no oracle here\n"))
        self.assertIsNone(_STATIC.parse_calls_log("CALLS=many\n"))

    def test_program_runs_passes_on_clean_oracle(self):
        ok, detail, calls = _STATIC.judge_program_runs(0, "CALLS=61\n")
        self.assertTrue(ok, detail)
        self.assertEqual(61, calls)

    def test_program_runs_fails_on_crash(self):
        ok, detail, _ = _STATIC.judge_program_runs(1, "CALLS=61\n")
        self.assertFalse(ok, "crashed self-test passed")
        self.assertIn("exit=1", detail)

    def test_program_runs_fails_without_oracle(self):
        ok, detail, _ = _STATIC.judge_program_runs(0, "done\n")
        self.assertFalse(ok, "oracle-less self-test passed")
        self.assertIn("no CALLS oracle", detail)

    def test_program_runs_fails_on_zero_calls(self):
        ok, detail, _ = _STATIC.judge_program_runs(0, "CALLS=0\n")
        self.assertFalse(ok, "zero-call self-test passed")

    def test_static_run_observed_passes_when_attributed(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            rows = [function_row(["C_Initialize"],
                                 module_identity(binary), 61)]
            ok, detail = _STATIC.judge_static_run_observed(
                observed_doc(rows), str(binary), 61)
            self.assertTrue(ok, detail)
            self.assertIn("61", detail)

    def test_static_run_observed_fails_with_the_named_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            ok, detail = _STATIC.judge_static_run_observed(
                observed_doc([]), str(binary), 61)
            self.assertFalse(ok, "unobserved static binary passed")
            self.assertIn("not observed", detail)
            self.assertIn("static-executable-unobserved", detail)

    def test_static_run_observed_fails_without_oracle(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            ok, detail = _STATIC.judge_static_run_observed(
                observed_doc([]), str(binary), None)
            self.assertFalse(ok, "oracle-less run leg passed")
            self.assertIn("no CALLS oracle", detail)

    def test_static_discover_passes_on_a_surfaced_manifest(self):
        manifest = {"interface_list": {"status": "ok"},
                    "surfaces": [{"source": {"kind": "file_scan"}}]}
        ok, detail = _STATIC.judge_static_discover(0, manifest, "")
        self.assertTrue(ok, detail)

    def test_static_discover_fails_on_empty_surfaces(self):
        manifest = {"interface_list": {"status": "ok"}, "surfaces": []}
        ok, detail = _STATIC.judge_static_discover(0, manifest, "")
        self.assertFalse(ok, "surface-less manifest passed")

    def test_static_discover_dlopen_refusal_names_the_gap(self):
        ok, detail = _STATIC.judge_static_discover(
            1, None, "p11scope-discover: cannot dlopen /x: dlopen failed")
        self.assertFalse(ok, "dlopen refusal passed")
        self.assertIn("static-executable-unobserved", detail)

    def test_static_discover_other_refusal_quotes_stderr(self):
        ok, detail = _STATIC.judge_static_discover(
            1, None, "p11scope-discover: exploded: boom")
        self.assertFalse(ok, "unexplained refusal passed")
        self.assertIn("exploded: boom", detail)

    def getter_doc(self, binary, table_calls, observation="exact",
                   names=("C_Initialize",)):
        identity = module_identity(binary)
        rows = [function_row(["C_GetFunctionList"], identity, 1),
                function_row(list(names), identity, table_calls)]
        doc = observed_doc(rows)
        doc["evidence"] = {"gap_classes": {"observation": {"status": observation}}}
        return doc

    def test_getter_manifest_passes_on_exact_named_table_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 61), str(binary), 61)
            self.assertTrue(ok, detail)
            self.assertIn("61 named table calls", detail)

    def test_getter_manifest_refuses_a_hidden_miss_and_a_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 60), str(binary), 61)
            self.assertFalse(ok, "an undisclosed miss passed")
            self.assertIn("no observation gap named", detail)
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 60, observation="lossy"),
                str(binary), 61)
            self.assertTrue(ok, detail)
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 62, observation="lossy"),
                str(binary), 61)
            self.assertFalse(ok, "a double count passed")
            self.assertIn("more calls than the program made", detail)

    def test_getter_manifest_fails_unnamed_unobserved_or_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = make_module(tmp, name="kryoptic-static-embed",
                                 content=b"fake-embed")
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 61, names=("unknown",)),
                str(binary), 61)
            self.assertFalse(ok, "unnamed table calls passed")
            self.assertIn("without names", detail)
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 0), str(binary), 61)
            self.assertFalse(ok, "an unobserved leg passed")
            self.assertIn("not observed", detail)
            ok, detail = _STATIC.judge_getter_manifest(
                1, None, str(binary), None)
            self.assertFalse(ok, "a helper refusal passed")
            self.assertIn("exit=1", detail)
            ok, detail = _STATIC.judge_getter_manifest(
                0, self.getter_doc(binary, 61), str(binary), None)
            self.assertFalse(ok, "an oracle-less leg passed")

    def test_getter_leg_adds_a_fourth_qualified_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_static_cell(tmp)
            binary = Path(args[args.index("--binary") + 1])
            (base / "getter.json").write_text(
                json.dumps(self.getter_doc(binary, 61)), encoding="utf-8")
            (base / "getter.out").write_text("CALLS=61\n", encoding="utf-8")
            args += ["--getter-rc", "0",
                     "--getter-observed", str(base / "getter.json"),
                     "--getter-observer-out", str(base / "getter.out")]
            self.assertEqual(1, _STATIC.main(args))
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            self.assertEqual(4, len(rows))
            row = rows[-1]
            self.assertEqual("kryoptic-static-embed-getter-manifest", row["cell"])
            self.assertTrue(row["pass"], row["detail"])
            self.assertEqual("qualified", row["qualification"])
            self.assertIn("getter-manifest: PASS",
                          (base / "summary.txt").read_text(encoding="utf-8"))

    def write_static_cell(self, tmp, selftest_rc=0, selftest_log="CALLS=61\n",
                          run_log="CALLS=61\n", run_calls=0,
                          discover_rc=1,
                          discover_stderr="cannot dlopen /x: failed"):
        base = Path(tmp)
        binary = make_module(tmp, name="kryoptic-static-embed",
                             content=b"fake-embed")
        (base / "selftest.log").write_text(selftest_log, encoding="utf-8")
        rows = [function_row(["C_Initialize"], module_identity(binary),
                             run_calls)]
        (base / "observed.json").write_text(
            json.dumps(observed_doc(rows)), encoding="utf-8")
        (base / "observer.out").write_text(run_log, encoding="utf-8")
        (base / "discover.stderr").write_text(discover_stderr,
                                              encoding="utf-8")
        args = ["--binary", str(binary),
                "--selftest-rc", str(selftest_rc),
                "--selftest-log", str(base / "selftest.log"),
                "--observer-out", str(base / "observer.out"),
                "--observed", str(base / "observed.json"),
                "--discover-rc", str(discover_rc),
                "--discover-stderr", str(base / "discover.stderr"),
                "--out-results", str(base / "results.jsonl"),
                "--out-summary", str(base / "summary.txt")]
        return base, args

    def test_tip_shape_exits_one_with_two_named_gaps(self):
        # This tip: the program runs (CALLS>0) but run and discover
        # cannot observe a static binary: two qualified FAILs carrying
        # the static-executable-unobserved gap, never a skip.
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_static_cell(tmp)
            rc = _STATIC.main(args)
            self.assertEqual(1, rc)
            rows = [json.loads(line) for line in
                    (base / "results.jsonl").read_text(
                        encoding="utf-8").splitlines()]
            self.assertEqual(3, len(rows))
            by_cell = {row["cell"]: row for row in rows}
            self.assertTrue(
                by_cell["kryoptic-static-embed-program-runs"]["pass"])
            for name in ("kryoptic-static-embed-run-observed",
                         "kryoptic-static-embed-discover"):
                row = by_cell[name]
                self.assertFalse(row["pass"])
                self.assertEqual("qualified", row["qualification"])
                self.assertIn("static-executable-unobserved",
                              row["detail"])

    def test_future_observed_shape_exits_zero(self):
        manifest = {"interface_list": {"status": "ok"},
                    "surfaces": [{"source": {"kind": "file_scan"}}]}
        with tempfile.TemporaryDirectory() as tmp:
            base, args = self.write_static_cell(tmp, run_calls=61,
                                                discover_rc=0,
                                                discover_stderr="")
            (base / "manifest.json").write_text(json.dumps(manifest),
                                                encoding="utf-8")
            args += ["--manifest", str(base / "manifest.json")]
            rc = _STATIC.main(args)
            self.assertEqual(0, rc)


if __name__ == "__main__":
    unittest.main()
