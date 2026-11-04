# SPDX-License-Identifier: GPL-3.0-or-later
"""Public CLI qualifier harness: expected-failure, summary, startup, ia32, cgroup.

Tests the shell qualifier's handling of known product gaps (expected-failure
with named reasons, unexpected-pass fails), the summary contract, the startup
bound default, ia32 split modes and cgroup force cleanup. Functions are
extracted from scripts/qualify-public-cli.sh (not copied) so the tests track
the real code.
"""

import json
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
NATIVE = ("no settled expected native image for this caller in the "
          "acquisition domain; scan-pinned fallback retained")


def overlay_report():
    """The exact 0-module overlay signature (CI guest shape)."""
    return {
        "schema": "p11scope/inventory/v1",
        "scope": "cgroup",
        "modules": [],
        "callers": [{"id": "c0", "pid": 100}, {"id": "c1", "pid": 101}],
        "edges": [],
        "gaps": [
            {"caller": "c0", "module": None, "pid": 100,
             "reason": UNPROVEN, "subject": MODPATH, "repeats": 12},
            {"caller": None, "module": None, "pid": None,
             "reason": "cgroup member scan was incomplete",
             "subject": "cgroup scope transaction incomplete",
             "repeats": 24},
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


def run_oracle(report, *, modfs="overlay", pin=None):
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
                     "REASON_INVENTORY_7X", "REASON_INVENTORY_OVERLAY",
                     "REASON_IA32"):
            self.assertIn(name, text, f"missing {name} with named product-gap reason")
        self.assertNotIn("REASON_RUN", text,
                         "run exact loss is fixed and qualified; its reason must be gone")
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

    def test_inventory_conditional_expected(self):
        text = QUAL.read_text()
        self.assertIn("inventory gaps about owned module", text)
        self.assertIn("REASON_INVENTORY_7X", text,
                      "inventory 7.x gap must map to expected-failure with named reason")

    def test_inventory_overlay_reason_present(self):
        text = QUAL.read_text()
        self.assertIn("REASON_INVENTORY_OVERLAY", text,
                      "overlay unproven signature needs a named reason")
        self.assertIn('module_fs=$(stat -f -c %T "$MODULE"', text,
                      "the overlay branch must be gated on the module fs")
        pos = text.index("inventory\\ overlay\\ unproven\\ signature")
        segment = text[pos:pos + 400]
        self.assertIn("REASON_INVENTORY_OVERLAY", segment)
        self.assertIn("expected-failure", segment,
                      "the overlay signature must map to expected-failure")


class InventoryOverlayTests(unittest.TestCase):
    def test_overlay_signature_emits_the_marker(self):
        rc, out = run_oracle(overlay_report())
        self.assertNotEqual(rc, 0, out)
        self.assertIn("inventory overlay unproven signature: "
                      "0 modules, 2 unproven gaps", out)

    def test_overlay_branch_rejects(self):
        cases = []
        ext4 = overlay_report()
        cases.append(("ext4", ext4, "ext4", "owned provider not inventoried"))
        other = overlay_report()
        other["modules"] = [{"id": "m9", "identity": {}}]
        cases.append(("nonempty-modules", other, "overlay",
                      "owned provider not inventoried"))
        dropped = overlay_report()
        dropped["gaps"] = [g for g in dropped["gaps"]
                           if g.get("caller") != "c1"
                           or g.get("reason") != UNPROVEN]
        cases.append(("dropped-unproven", dropped, "overlay",
                      "overlay unproven caller cover"))
        leaked = overlay_report()
        leaked["callers"].append({"id": "c2", "pid": 102})
        cases.append(("outside-leak", leaked, "overlay",
                      "outside workload leaked into cgroup inventory"))
        edged = overlay_report()
        edged["edges"] = [{"caller": "c0", "module": "m0"}]
        cases.append(("edges-present", edged, "overlay",
                      "overlay unproven edges present"))
        extra = overlay_report()
        extra["gaps"].append({"caller": None, "module": None, "pid": None,
                             "reason": "something new",
                             "subject": "novel gap", "repeats": 1})
        cases.append(("extra-gap", extra, "overlay",
                      "overlay unproven extra gap"))
        subject = overlay_report()
        subject["gaps"][0]["subject"] = "/some/other/path.so"
        cases.append(("wrong-subject", subject, "overlay",
                      "overlay unproven subject"))
        for name, report, modfs, marker in cases:
            with self.subTest(name=name):
                rc, out = run_oracle(report, modfs=modfs)
                self.assertNotEqual(rc, 0, out)
                self.assertIn(marker, out)
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
                      "outside=102 excluded module=m0 gaps=0", out)


if __name__ == "__main__":
    unittest.main()
