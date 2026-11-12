# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Public CLI qualifier harness: expected-failure, summary, startup, ia32, cgroup.

Tests the shell qualifier's handling of known product gaps (expected-failure
with named reasons, unexpected-pass fails), the summary contract, the startup
bound default, ia32 split modes and cgroup force cleanup. Functions are
extracted from scripts/qualify-public-cli.sh (not copied) so the tests track
the real code.
"""

import ast
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUAL = ROOT / "scripts/qualify-public-cli.sh"


def extract_functions(*names):
    """Extract named shell functions plus REASON_* lines from the qualifier."""
    parts = []
    for name in names:
        proc = subprocess.run(
            ["sed", "-n", f"/^{name}()/,/^}}/p", str(QUAL)],
            capture_output=True, text=True, timeout=5)
        parts.append(proc.stdout)
    proc = subprocess.run(
        ["grep", "^REASON_", str(QUAL)],
        capture_output=True, text=True, timeout=5)
    parts.append(proc.stdout)
    return "\n".join(parts)


def run_shell(body, *, cwd):
    """Run body with extracted qualifier functions sourced, return CompletedProcess."""
    funcs = extract_functions("result", "summary", "emit_judged")
    script = funcs + "\n" + body
    return subprocess.run(
        ["bash", "-u", "-c", script],
        capture_output=True, text=True, timeout=10, cwd=str(cwd))


def write_results(tmp, rows):
    path = tmp / "results.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


def extract_inventory_oracle():
    """Extract the inventory-cgroup python oracle block from the qualifier."""
    lines = QUAL.read_text().splitlines(keepends=True)
    start = next(
        i for i, line in enumerate(lines)
        if '"$cell-inside.wl"' in line
        and line.strip().startswith("python3 - "))
    end = next(i for i in range(start, len(lines))
               if lines[i].rstrip("\n") == "PY")
    return "".join(lines[start + 1:end])


MODPATH = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
UNPROVEN = "original_file_unproven: kernel witness unavailable"
UNPROVEN_DIAGNOSED = UNPROVEN + ": kernel identity self-test failed at stage 'scope-write'"
NATIVE = ("no settled expected native image for this caller in the "
          "acquisition domain; scan-pinned fallback retained")


PUBLISHED_PIN = {"dev": [8, 1], "ino": 42, "sha256": "ab" * 32}


def overlay_report():
    """The regressed 0-module overlay shape: the scan-pinned fallback
    dropped the found module. This must fail loudly (never
    expected-failure, never a pass): an empty view never qualifies.
    """
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "cgroup",
        "modules": [],
        "callers": [{"id": "c0", "pid": 100}, {"id": "c1", "pid": 101}],
        "edges": [],
        "gaps": [
            {"caller": "c0", "module": None, "pid": 100,
             "reason": UNPROVEN_DIAGNOSED, "subject": MODPATH, "repeats": 12},
            {"caller": "c0", "module": None, "pid": 100,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 11},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 10},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 9},
        ],
    }


def overlay_published_report():
    """The qualified overlay shape: the owned module is published with
    inside edges and keeps the named unproven gap per inside caller
    (PARTIAL coverage via the gaps).
    """
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "cgroup",
        "modules": [{"id": "m0",
                     "identity": {"device": {"major": 8, "minor": 1},
                                  "inode": 42, "sha256": "ab" * 32},
                     "admission": {"state": "admitted"}}],
        "callers": [{"id": "c0", "pid": 100}, {"id": "c1", "pid": 101}],
        "edges": [{"caller": "c0", "module": "m0"},
                  {"caller": "c1", "module": "m0"}],
        "gaps": [
            {"caller": "c0", "module": None, "pid": 100,
             "reason": UNPROVEN_DIAGNOSED, "subject": MODPATH, "repeats": 12},
            {"caller": "c0", "module": None, "pid": 100,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 11},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 10},
            {"caller": "c1", "module": None, "pid": 101,
             "reason": NATIVE, "subject": "native owner activation refused",
             "repeats": 9},
        ],
    }


def run_oracle(report, *, modfs="overlayfs", pin=None):
    """Run the extracted oracle against a fixture report."""
    block = extract_inventory_oracle()
    if pin is None:
        pin = {"dev": [0, 0], "ino": 0, "sha256": "00"}
    inside_wl = "READY pid=100\nCHILD pid=101\nLEDGER x\n"
    outside_wl = "READY pid=102\nLEDGER y\n"
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        (tmp / "r.json").write_text(json.dumps(report))
        (tmp / "in.wl").write_text(inside_wl)
        (tmp / "out.wl").write_text(outside_wl)
        proc = subprocess.run(
            ["python3", "-I", "-", "r.json", "in.wl", "out.wl",
             json.dumps(pin), MODPATH, modfs],
            input=block, capture_output=True, text=True, timeout=30,
            cwd=str(tmp))
    return proc.returncode, proc.stdout + proc.stderr


class SummaryTests(unittest.TestCase):
    def test_expected_failures_do_not_fail_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "trace-pid", "pass": False, "detail": "smoke",
             "qualification": "nonqualifying"},
            {"cell": "run-short", "pass": False,
             "detail": "run exact loss; product fix lane: [failed] loss or unknown discovery_truncated",
             "qualification": "expected-failure"},
            {"cell": "profile-cgroup", "pass": False,
             "detail": "cgroup fork gaps; product fix lane: [failed] lossy",
             "qualification": "expected-failure"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell(
                "summary doctor trace-pid run-short profile-cgroup; echo EXIT=$?",
                cwd=tmp)
        self.assertIn("EXIT=2", proc.stdout,
                      f"summary must exit 2 (valid with smoke/expected), got: {proc.stdout}\n{proc.stderr}")
        # tmp is cleaned with its summary.txt; check via stdout (tee prints too).
        self.assertIn("terminal_rows_valid=True", proc.stdout)

    def test_unexpected_pass_fails_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "run-short", "pass": True,
             "detail": "UNEXPECTED PASS (reason may have landed)",
             "qualification": "expected-failure"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell("summary doctor run-short; echo EXIT=$?", cwd=tmp)
        self.assertIn("EXIT=1", proc.stdout,
                      f"unexpected pass must fail summary with exit 1, got: {proc.stdout}\n{proc.stderr}")

    def test_qualified_failure_still_fails_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "system", "pass": False, "detail": "loss",
             "qualification": "failed"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell("summary doctor system; echo EXIT=$?", cwd=tmp)
        self.assertIn("EXIT=1", proc.stdout,
                      f"qualified fail must exit 1, got: {proc.stdout}\n{proc.stderr}")


class EmitJudgedTests(unittest.TestCase):
    def test_known_gap_becomes_expected_failure(self):
        oracle_row = json.dumps({
            "cell": "profile-cgroup", "pass": False,
            "detail": "lossy or unknown observation gap class",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged profile-cgroup 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        self.assertIn("EMIT_RC=0", proc.stdout,
                      f"known gap must emit expected with rc 0, got: {proc.stdout}\n{proc.stderr}")
        # Last line should be the emitted row.
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}")
        row = json.loads(lines[-1])
        self.assertEqual(row["cell"], "profile-cgroup")
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertIn("product fix lane", row["detail"])

    def test_qualified_pass_becomes_unexpected_pass(self):
        oracle_row = json.dumps({
            "cell": "profile-cgroup", "pass": True,
            "detail": "owned physical-provider counts match",
            "qualification": "owned-provider-counts"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged profile-cgroup 0 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertTrue(row["pass"])
        self.assertIn("UNEXPECTED PASS", row["detail"])

    def test_unknown_failure_sig_stays_failed(self):
        oracle_row = json.dumps({
            "cell": "profile-cgroup", "pass": False,
            "detail": "some brand new failure mode never seen before",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged profile-cgroup 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "failed")
        self.assertFalse(row["pass"])

    def test_trace_cgroup_smoke_becomes_unexpected_pass(self):
        oracle_row = json.dumps({
            "cell": "trace-cgroup", "pass": False,
            "detail": "trace delivery/count checked with loss identity",
            "qualification": "nonqualifying"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged trace-cgroup 2 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertTrue(row["pass"])
        self.assertIn("UNEXPECTED PASS", row["detail"])

    def test_promoted_cells_pass_oracle_lines_through(self):
        # run-short, run-cover and metrics-cgroup are qualified now:
        # the oracle line passes through untouched, never wrapped as
        # expected-failure.
        for cell in ("run-short", "run-cover", "metrics-cgroup"):
            oracle_row = json.dumps({
                "cell": cell, "pass": True,
                "detail": "owned physical-provider counts match",
                "qualification": "owned-provider-counts"})
            with tempfile.TemporaryDirectory() as raw:
                tmp = Path(raw)
                (tmp / "results.jsonl").write_text("")
                body = f"emit_judged {cell} 0 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
                proc = run_shell(body, cwd=tmp)
            lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
            self.assertTrue(lines, f"no emitted row for {cell} in: {proc.stdout}\n{proc.stderr}")
            row = json.loads(lines[-1])
            self.assertEqual(row["qualification"], "owned-provider-counts", cell)
            self.assertTrue(row["pass"], cell)
            self.assertIn("EMIT_RC=0", proc.stdout, cell)

    def test_trace_cgroup_known_loss_becomes_expected(self):
        oracle_row = json.dumps({
            "cell": "trace-cgroup", "pass": False,
            "detail": "trace lossy or unknown observation gap class",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged trace-cgroup 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertFalse(row["pass"])

    def test_trace_cgroup_unmatched_returns_becomes_expected(self):
        # The same known cgroup-trace observation gap through the
        # earlier loss-counter tripwire: every ledgered call is
        # delivered, but a return misses its entry stamp (the fork
        # child racing fork marking). unmatched_returns > 0 always
        # sets an observation cause (render.rs gap_classes), so the
        # gap-class tripwire would fire next; both details name the
        # same condition and stay expected-failure, never qualified.
        oracle_row = json.dumps({
            "cell": "trace-cgroup", "pass": False,
            "detail": "trace loss or unknown unmatched_returns",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged trace-cgroup 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertFalse(row["pass"])


class ScriptTextTests(unittest.TestCase):
    def test_startup_bound_default_is_45(self):
        text = QUAL.read_text()
        self.assertIn("STARTUP_BOUND_S:-45", text,
                      "startup bound default must be 45s (7.2 measured 22-24s, 30s gives <20% margin)")
        self.assertNotIn("STARTUP_BOUND_S:-30", text,
                         "old 30s default must be gone")

    def test_expected_reasons_present(self):
        text = QUAL.read_text()
        for name in ("REASON_CGROUP", "REASON_TRACE_CGROUP",
                     "REASON_IA32"):
            self.assertIn(name, text, f"missing {name} with named product-gap reason")
        self.assertNotIn("REASON_RUN", text,
                         "run exact loss is fixed and qualified; its reason must be gone")
        self.assertNotIn("REASON_INVENTORY_OVERLAY", text,
                         "overlay empty view is fixed and qualified; its reason must be gone")
        self.assertNotIn("REASON_INVENTORY_7X", text,
                         "the decided no-witness shape qualifies; its reason must be gone")
        self.assertIn("product fix lane", text)

    def test_ia32_prereq_missing_is_expected(self):
        text = QUAL.read_text()
        # Default-mode prereq-missing branch must emit expected-failure, not failed.
        self.assertIn("REASON_IA32", text)
        # The old failed prereq message must be gone from the default branch
        # (ONLY mode still uses failed for missing prereq as a harness error).
        self.assertIn("P11SCOPE_PUBLIC_CLI_ONLY_IA32", text,
                      "ia32-only job mode must exist")
        self.assertIn("summary profile-pid-ia32 run-ia32", text,
                      "ia32-only mode must summarize exactly the two ia32 cells")

    def test_ia32_module_override_allowed(self):
        text = QUAL.read_text()
        self.assertIn("IA32_MODULE=${IA32_MODULE:-", text,
                      "IA32_MODULE must allow override for unpacked i386 copies")

    def test_ia32_only_mode_skips_the_amd64_probe(self):
        # The ia32-only job carries no amd64 provider (libsofthsm2:i386
        # cannot coexist with it), so ONLY_IA32 must select the i386
        # module before the amd64 --select-module probe runs.
        text = QUAL.read_text()
        use = text.index("MODULE=$IA32_MODULE")
        probe = text.index("--select-module")
        self.assertLess(use, probe,
                        "ONLY_IA32 must select IA32_MODULE before the amd64 probe")

    def test_cgroup_force_cleanup_present(self):
        text = QUAL.read_text()
        self.assertIn("cgroup.procs", text)
        self.assertIn("kill -KILL", text,
                      "cgroup cleanup must KILL leftover procs before retrying rmdir")
        self.assertIn("CGROUPS", text,
                      "owned cgroups must be tracked for EXIT cleanup")

    def test_inventory_gaps_fail_loudly(self):
        # The decided no-witness shape qualifies, so the inventory
        # branch maps every failure to failed: no expected-failure arm
        # may remain. The oracle still fails loudly on unnamed
        # owned-module gaps.
        text = QUAL.read_text()
        self.assertIn("inventory gaps about owned module", text,
                      "the oracle must still fail loudly on unnamed owned-module gaps")
        anchor = 'detail="$detail observer_rc=$observer_rc"'
        start = text.index(anchor)
        branch = text[start:text.index("    return 0", start)]
        self.assertIn('result "$cell" 0 "$detail" failed', branch,
                      "inventory failures must stay failed")
        self.assertNotIn("expected-failure", branch,
                         "no inventory expected-failure arm may remain")
        self.assertNotIn("REASON_INVENTORY_7X", text,
                         "the inventory 7.x expected-failure reason must be gone")

    def test_inventory_overlay_published_shape_present(self):
        text = QUAL.read_text()
        self.assertNotIn("REASON_INVENTORY_OVERLAY", text,
                         "the overlay empty view is fixed; its reason must be gone")
        self.assertNotIn("inventory overlay unproven signature", text,
                         "the empty-view signature must be gone: it never qualifies")
        self.assertIn('module_fs=$(stat -f -c %T "$MODULE"', text,
                      "the overlay branch must be gated on the module fs")
        self.assertIn("modfs=='overlayfs'", text,
                      "the gate must use stat(1)'s spelling: GNU stat "
                      "prints 'overlayfs', never 'overlay'")
        self.assertIn("empty view never qualifies", text,
                      "the oracle must refuse an empty view on every filesystem")
        self.assertIn("overlay unproven caller cover", text,
                      "the published overlay shape must keep the named unproven gaps")
        self.assertIn("overlay published extra gap", text,
                      "unknown overlay gaps must fail loudly")


class InventoryOverlayTests(unittest.TestCase):
    def test_overlay_published_shape_passes(self):
        rc, out = run_oracle(overlay_published_report(), pin=PUBLISHED_PIN)
        self.assertEqual(rc, 0, out)
        self.assertIn("inventory cgroup: inside=100 child=101 "
                      "outside=102 excluded module=m0 admission=admitted "
                      "unproven=2 gaps=4", out)

    def test_overlay_published_shape_passes_unresolved(self):
        report = overlay_published_report()
        report["modules"][0]["admission"] = {"state": "unresolved"}
        rc, out = run_oracle(report, pin=PUBLISHED_PIN)
        self.assertEqual(rc, 0, out)
        self.assertIn("admission=unresolved unproven=2 gaps=4", out)

    def test_overlay_empty_view_fails_loudly(self):
        # The regressed 0-module shape: no signature, no
        # expected-failure — an empty view never qualifies.
        rc, out = run_oracle(overlay_report())
        self.assertNotEqual(rc, 0, out)
        self.assertIn("empty view never qualifies", out)
        self.assertNotIn("inventory overlay unproven signature", out)

    def test_overlay_accepts_designed_collection_deadline_gap(self):
        # A pass that starts just before the run deadline is cancelled
        # mid-flight by the designed collection bound and honestly
        # records 'cgroup collection deadline reached' (once per gap
        # site, as the sibling transaction reasons). The published
        # shape must survive that reason and still qualify.
        report = overlay_published_report()
        report["gaps"].append(
            {"caller": None, "module": None, "pid": None,
             "reason": "cgroup collection deadline reached",
             "subject": "cgroup scope transaction incomplete",
             "repeats": 2})
        rc, out = run_oracle(report, pin=PUBLISHED_PIN)
        self.assertEqual(rc, 0, out)
        self.assertIn("unproven=2 gaps=5", out)

    def test_overlay_branch_rejects(self):
        cases = []
        empty = overlay_report()
        cases.append(("empty-view", empty, "overlayfs",
                      "empty view never qualifies"))
        ext4 = overlay_report()
        cases.append(("ext4-empty", ext4, "ext4",
                      "empty view never qualifies"))
        dropped = overlay_published_report()
        dropped["gaps"] = [g for g in dropped["gaps"]
                           if g.get("caller") != "c1"
                           or g.get("reason") != UNPROVEN]
        cases.append(("dropped-unproven", dropped, "overlayfs",
                      "overlay unproven caller cover"))
        leaked = overlay_published_report()
        leaked["callers"].append({"id": "c2", "pid": 102})
        cases.append(("outside-leak", leaked, "overlayfs",
                      "outside workload leaked into cgroup inventory"))
        edgeless = overlay_published_report()
        edgeless["edges"] = []
        cases.append(("no-edge", edgeless, "overlayfs",
                      "no inside edge to owned module"))
        extra = overlay_published_report()
        extra["gaps"].append({"caller": None, "module": None, "pid": None,
                             "reason": "something new",
                             "subject": "novel gap", "repeats": 1})
        cases.append(("extra-gap", extra, "overlayfs",
                      "overlay published extra gap"))
        # Unproven member gaps degrade per caller without incompleting
        # the shared transaction, so this reason must fail loudly here
        # (a regression signal for the cgroup-scan lane), never hide.
        trunc = overlay_published_report()
        trunc["gaps"].append({"caller": None, "module": None, "pid": None,
                             "reason": "cgroup member scan was incomplete",
                             "subject": "cgroup scope transaction incomplete",
                             "repeats": 24})
        cases.append(("truncated-transaction", trunc, "overlayfs",
                      "overlay published extra gap"))
        subject = overlay_published_report()
        subject["gaps"][0]["subject"] = "/some/other/path.so"
        cases.append(("wrong-subject", subject, "overlayfs",
                      "overlay unproven subject"))
        refused = overlay_published_report()
        refused["modules"][0]["admission"] = {"state": "refused"}
        cases.append(("refused-admission", refused, "overlayfs",
                      "overlay owned provider admission"))
        for name, report, modfs, marker in cases:
            with self.subTest(name=name):
                rc, out = run_oracle(report, modfs=modfs, pin=PUBLISHED_PIN)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(marker, out)
                self.assertNotIn("inventory overlay unproven signature",
                                 out)

    def test_bare_overlay_spelling_does_not_match(self):
        # stat(1) never emits the bare 'overlay' spelling (coreutils
        # S_MAGIC_OVERLAYFS prints 'overlayfs'); the gate must not
        # accept it, so a reintroduced misspelling fails loudly here
        # instead of misclassifying CI guests. The unresolved
        # admission qualifies only through the overlay gate.
        report = overlay_published_report()
        report["modules"][0]["admission"] = {"state": "unresolved"}
        rc, out = run_oracle(report, modfs="overlay", pin=PUBLISHED_PIN)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("owned provider not admitted", out)
        self.assertNotIn("inventory overlay unproven signature",
                         out)

    def test_owned_pass_path_still_passes(self):
        pin = {"dev": [8, 1], "ino": 42, "sha256": "ab" * 32}
        report = {
            "schema": "p11scope/inventory/v1",
            "scope": "cgroup",
            "modules": [{"id": "m0",
                         "identity": {"device": {"major": 8, "minor": 1},
                                      "inode": 42, "sha256": "ab" * 32},
                         "admission": {"state": "admitted"}}],
            "callers": [{"id": "c0", "pid": 100},
                        {"id": "c1", "pid": 101}],
            "edges": [{"caller": "c0", "module": "m0"}],
            "gaps": [],
        }
        rc, out = run_oracle(report, modfs="ext4", pin=pin)
        self.assertEqual(rc, 0, out)
        self.assertIn("inventory cgroup: inside=100 child=101 "
                      "outside=102 excluded module=m0 admission=admitted "
                      "unproven=0 gaps=0", out)


def extract_handoff_oracle():
    """Extract the run-prearm python oracle block from the qualifier."""
    lines = QUAL.read_text().splitlines(keepends=True)
    start = next(
        i for i, line in enumerate(lines)
        if line.strip() == "detail=$(python3 - <<'PY' 2>&1")
    end = next(i for i in range(start, len(lines))
               if lines[i].rstrip("\n") == "PY")
    return "".join(lines[start + 1:end])


def load_handoff_pair():
    """Compile assert_handoff_pair from the real oracle block.

    AST-extracted (not copied) so the tests track the shipped oracle;
    only the function is compiled, never the block's top-level capture
    assertions.
    """
    tree = ast.parse(extract_handoff_oracle())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "assert_handoff_pair":
            namespace = {}
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         "<handoff>", "exec"), namespace)
            return namespace["assert_handoff_pair"]
    raise AssertionError("assert_handoff_pair missing from the run-prearm oracle")


def handoff_module(late, unattached, attached):
    """A pre-armed module record with the exact handoff window pair."""
    return {"attached_at_ns": attached,
            "unobserved_windows": [
                {"reason": "late_discovery",
                 "start_ns": late[0], "end_ns": late[1]},
                {"reason": "mapped_unattached",
                 "start_ns": unattached[0], "end_ns": unattached[1]},
            ]}


class HandoffPairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check = staticmethod(load_handoff_pair())

    def test_strictly_earlier_undeclared_end_passes(self):
        # Today's real guest shape (review evidence: unattached end
        # strictly before the declared attach).
        self.check(handoff_module((100, 200), (100, 150), 200))

    def test_equal_undeclared_end_passes(self):
        # Same monotonic tick: the producer takes the undeclared
        # maximum independently of the declared maximum, so equality
        # is a correct disclosure (the old strict < failed it).
        self.check(handoff_module((100, 200), (100, 200), 200))

    def test_later_undeclared_end_passes(self):
        # A later undeclared attach is unordered against the declared
        # maximum by construction; failing it would reject a correct
        # fail-closed disclosure.
        self.check(handoff_module((100, 200), (100, 250), 200))

    def test_non_handoff_shapes_fail(self):
        late = {"reason": "late_discovery", "start_ns": 100, "end_ns": 200}
        unattached = {"reason": "mapped_unattached",
                      "start_ns": 100, "end_ns": 150}
        pre_attach = {"reason": "pre_attach", "start_ns": 100, "end_ns": 200}
        cases = {
            "swapped": {"attached_at_ns": 200,
                        "unobserved_windows": [unattached, late]},
            "single-pre-attach": {"attached_at_ns": 200,
                                  "unobserved_windows": [pre_attach]},
            "empty": {"attached_at_ns": 200, "unobserved_windows": []},
            "late-end-mismatch": {
                "attached_at_ns": 200,
                "unobserved_windows": [
                    {"reason": "late_discovery",
                     "start_ns": 100, "end_ns": 199},
                    unattached]},
            "split-starts": {
                "attached_at_ns": 200,
                "unobserved_windows": [
                    late,
                    {"reason": "mapped_unattached",
                     "start_ns": 101, "end_ns": 150}]},
            "end-before-start": {
                "attached_at_ns": 200,
                "unobserved_windows": [
                    late,
                    {"reason": "mapped_unattached",
                     "start_ns": 100, "end_ns": 99}]},
        }
        for name, module in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    self.check(module)

    def test_handoff_pair_call_sites_are_the_two_pre68_twins(self):
        text = QUAL.read_text()
        self.assertEqual(text.count("assert_handoff_pair("), 3,
                         "def plus exactly the held/passive pre-6.8 calls")

    def test_six_eight_plus_branch_is_unchanged(self):
        # The >= 6.8 path keeps its exact assertions: held [] and the
        # passive single pre_attach with end == attached_at.
        text = QUAL.read_text()
        for line in (
            'assert held["unobserved_windows"] == [], held["unobserved_windows"]',
            'assert windows and len(windows) == 1 and windows[0]["reason"] == "pre_attach", windows',
            'assert windows[0]["end_ns"] == passive["attached_at_ns"], windows',
        ):
            with self.subTest(line=line):
                self.assertIn(line, text)


STUB_ORACLE = """\
import json, os, sys
argv = sys.argv[1:]
open(os.environ["STUB_ARGS"], "w").write("\\n".join(argv))
cell = argv[argv.index("--cell") + 1]
print(json.dumps({"cell": cell, "pass": True, "detail": "stub",
                  "qualification": "owned-provider-counts"}))
"""


def run_judge_case(cell, release):
    """Run the real judge() with a stub oracle and stub uname; return argv seen."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        stub = tmp / "stub-oracle.py"
        stub.write_text(STUB_ORACLE)
        bindir = tmp / "bin"
        bindir.mkdir()
        fake_uname = bindir / "uname"
        fake_uname.write_text('#!/bin/sh\necho "$FAKE_RELEASE"\n')
        fake_uname.chmod(0o755)
        args_file = tmp / "argv.txt"
        funcs = extract_functions("result", "emit_judged", "judge")
        script = (funcs + "\n"
                  f'export ORACLE="{stub}" STUB_ARGS="{args_file}"\n'
                  f'export PATH="{bindir}:$PATH" FAKE_RELEASE="{release}"\n'
                  f'judge report.json ledger.wl receipt.json "{cell}"; echo JUDGE_RC=$?\n')
        proc = subprocess.run(["bash", "-u", "-c", script],
                              capture_output=True, text=True, timeout=10,
                              cwd=str(tmp))
        assert "JUDGE_RC=0" in proc.stdout, proc.stdout + proc.stderr
        return args_file.read_text().splitlines()


class JudgeFlagTests(unittest.TestCase):
    """judge() passes --allow-66-discovery-gap only for its cell on 6.6."""

    FLAG = "--allow-66-discovery-gap"

    def test_flag_passed_for_select_endpoint_on_66(self):
        argv = run_judge_case("select-endpoint-system", "6.6.157-0606157-generic")
        self.assertIn(self.FLAG, argv)

    def test_flag_not_passed_for_select_endpoint_off_66(self):
        for release in ("7.3.1-070301-generic", "6.12.111-0612111-generic",
                        "6.1.188-0601188-generic", "6.60.1-060600-generic"):
            with self.subTest(release=release):
                argv = run_judge_case("select-endpoint-system", release)
                self.assertNotIn(self.FLAG, argv)

    def test_flag_not_passed_for_other_cells_on_66(self):
        for cell in ("counter-counts-system", "system", "select-endpoint-pid"):
            with self.subTest(cell=cell):
                argv = run_judge_case(cell, "6.6.157-0606157-generic")
                self.assertNotIn(self.FLAG, argv)


REFUSAL = ("counter-mode-unavailable-in-build: "
           "this build omits counter objects")
BOGUS_PID = "2147483647"


def run_counter_shell(body, *, cwd):
    """Run body with the qualifier's counter-refusal code extracted."""
    funcs = extract_functions("result", "counter_refused",
                              "counter_build_supported")
    const = subprocess.run(
        ["grep", "-E", "^COUNTER_(BUILD_REFUSAL|BOGUS_PID)=", str(QUAL)],
        capture_output=True, text=True, timeout=5)
    script = funcs + "\n" + const.stdout + "\n" + body
    return subprocess.run(
        ["bash", "-u", "-c", script],
        capture_output=True, text=True, timeout=10, cwd=str(cwd))


def write_fake_observer(path, stdout_text, stderr_text, rc, make_output=False):
    """A fake observer: canned stdout/stderr/rc, optional -o creation."""
    path.write_text(
        "#!/bin/sh\n"
        f"printf '%s' \"{stdout_text}\" \n"
        f"printf '%s' \"{stderr_text}\" >&2\n"
        + ("for arg in \"$@\"; do "
           "if [ \"$seen_o\" = 1 ]; then : > \"$arg\"; fi; "
           "if [ \"$arg\" = -o ]; then seen_o=1; else seen_o=0; fi; done\n"
           if make_output else "")
        + f"exit {rc}\n",
        encoding="utf-8")
    path.chmod(0o755)


class CounterRefusalTests(unittest.TestCase):
    def test_refusal_constant_matches_the_source_gate(self):
        gate = (ROOT / "src" / "attach" / "counter_banks.rs").read_text(
            encoding="utf-8")
        self.assertIn(REFUSAL, gate,
                      "source build gate must emit the pinned refusal")
        script = QUAL.read_text(encoding="utf-8")
        match = re.search(r'^COUNTER_BUILD_REFUSAL="([^"]+)"', script, re.M)
        self.assertIsNotNone(match, "qualifier pins the refusal constant")
        self.assertEqual(match.group(1), REFUSAL)
        self.assertIn("REASON_COUNTER_SMALL", script)
        self.assertIn(BOGUS_PID, script,
                      "probe and refusal arm share one bogus pid")

    def test_counter_cells_run_through_the_refusal_wrapper(self):
        script = QUAL.read_text(encoding="utf-8")
        cells = ("counter-latency-mt",
                 "counter-counts-pid", "counter-timestamps-pid",
                 "counter-latency-pid", "counter-counts-system",
                 "counter-timestamps-system", "counter-latency-system",
                 "select-endpoint-pid", "select-endpoint-system")
        for cell in cells:
            with self.subTest(cell=cell):
                self.assertIn(f"counter_cell {cell} ", script,
                              f"{cell} must run through counter_cell")
        self.assertNotIn("gated counter-", script,
                         "no counter cell may bypass the wrapper")
        self.assertNotIn("gated select-endpoint-", script,
                         "no select-endpoint cell may bypass the wrapper")

    def test_probe_reads_the_exact_wide_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-wide"
            write_fake_observer(fake, "", f"p11scope: {REFUSAL}\n", 1)
            body = (f"P={fake} OUT={tmp} "
                    "counter_build_supported; echo rc=$?")
            proc = run_counter_shell(body, cwd=tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "rc=1")

    def test_probe_passes_a_full_build_through(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-full"
            write_fake_observer(fake, "", "p11scope: no such process\n", 1)
            body = (f"P={fake} OUT={tmp} "
                    "counter_build_supported; echo rc=$?")
            proc = run_counter_shell(body, cwd=tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "rc=0")

    def test_probe_refuses_an_impossible_success(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-ok"
            write_fake_observer(fake, "", "", 0)
            body = (f"P={fake} OUT={tmp} "
                    "counter_build_supported; echo rc=$?")
            proc = run_counter_shell(body, cwd=tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "rc=64")

    def test_probe_refuses_a_noisy_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-noisy"
            write_fake_observer(
                fake, "", f"p11scope: {REFUSAL}\nextra line\n", 1)
            body = (f"P={fake} OUT={tmp} "
                    "counter_build_supported; echo rc=$?")
            proc = run_counter_shell(body, cwd=tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "rc=64")

    def test_refused_cell_records_the_known_gap(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-wide"
            write_fake_observer(fake, "", f"p11scope: {REFUSAL}\n", 1)
            out = tmp / "counter-counts-pid.json"
            body = (f"P={fake} "
                    "counter_refused counter-counts-pid profile "
                    "--mode metrics --counter-mode counts --pid 999 "
                    f"--duration 12 -o {out}")
            proc = run_counter_shell(body, cwd=tmp)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            rows = [json.loads(line) for line in
                    (tmp / "results.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 1, rows)
            row = rows[0]
            self.assertEqual(row["cell"], "counter-counts-pid")
            self.assertFalse(row["pass"])
            self.assertEqual(row["qualification"], "expected-failure")
            self.assertIn("SMALL build", row["detail"])
            self.assertNotIn("0.7.x", row["detail"])
            self.assertFalse(out.exists())

    def test_refused_cell_fails_a_full_style_error(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-full"
            write_fake_observer(fake, "", "p11scope: no such process\n", 1)
            out = tmp / "counter-counts-pid.json"
            body = (f"P={fake} "
                    "counter_refused counter-counts-pid profile "
                    "--mode metrics --counter-mode counts --pid 999 "
                    f"--duration 12 -o {out}")
            proc = run_counter_shell(body, cwd=tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rows = [json.loads(line) for line in
                    (tmp / "results.jsonl").read_text().splitlines()]
            self.assertEqual(rows[0]["qualification"], "failed")

    def test_refused_cell_fails_an_unexpected_success(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-ok"
            write_fake_observer(fake, "", "", 0, make_output=True)
            out = tmp / "counter-counts-pid.json"
            body = (f"P={fake} "
                    "counter_refused counter-counts-pid profile "
                    "--mode metrics --counter-mode counts --pid 999 "
                    f"--duration 12 -o {out}")
            proc = run_counter_shell(body, cwd=tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rows = [json.loads(line) for line in
                    (tmp / "results.jsonl").read_text().splitlines()]
            self.assertEqual(rows[0]["qualification"], "failed")

    def test_refused_cell_fails_stdout_noise(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fake = tmp / "observer-noisy"
            write_fake_observer(fake, "stray output\n",
                                f"p11scope: {REFUSAL}\n", 1)
            out = tmp / "counter-counts-pid.json"
            body = (f"P={fake} "
                    "counter_refused counter-counts-pid profile "
                    "--mode metrics --counter-mode counts --pid 999 "
                    f"--duration 12 -o {out}")
            proc = run_counter_shell(body, cwd=tmp)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rows = [json.loads(line) for line in
                    (tmp / "results.jsonl").read_text().splitlines()]
            self.assertEqual(rows[0]["qualification"], "failed")


if __name__ == "__main__":
    unittest.main()
