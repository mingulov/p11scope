#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual matrix preparation, judge and production shell seams."""
import json
import hashlib
import os
import pwd
from pathlib import Path
import re
import runpy
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/release-matrix-contract.py"
CHECKER_MOD = runpy.run_path(str(CHECKER))
RUNNER = ROOT / "scripts/qualify-release-matrix.sh"
LIB_A = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64"
LIB_B = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64"
LIB_C = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64"
LIB_D = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6531_lp64"
PID_TEST = "tests::the_pid_filter_probe_reaches_the_kernel"
CLASSIC_MULTI = "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64"
CAPTURE_MULTI = "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64"
LEADER_MULTI = "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64"
CHURN = "inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"
BROAD = "discovery::engine::publication_tests::broad_p11kit_admission_arithmetic"
DENIAL = "inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed"
# Format-exact with the cell's eprintln marker (see privileged_tests);
# the real guest/host runs prove the binary prints exactly this shape.
DENIED_MARKER = ("IDENTITY_515_DENIAL outcome=denied reason=kernel_fix_missing "
                 "mm_present=false attach=false tasktype=false "
                 "bpf_delta=0 scan_bytes=5277697 fallback=kernel_fix_missing")
ELIGIBLE_MARKER = ("IDENTITY_515_DENIAL outcome=eligible mm_present=true "
                   "attach=true tasktype=true bpf_delta=0 scan_bytes=7067009 sink=ok")
PUBLIC = {
    "profile-pid": "owned-provider-counts", "metrics-pid": "owned-provider-counts",
    "mt-exact": "owned-provider-counts", "system": "owned-provider-counts",
    "names-pid": "semantic-names", "verdict-pid": "verdict-consistency",
    "doctor": "command-contract", "sigint": "command-contract",
    "second-sigint": "command-contract", "fifo-refused": "command-contract",
    "run-short": "nonqualifying", "run-cover": "nonqualifying",
    "trace-pid": "nonqualifying",
}


def candidate_receipt(bins, path, source_root=ROOT):
    # Controlled parser input only: these fixtures never claim a real build.
    sha = lambda source: hashlib.sha256(source.read_bytes()).hexdigest()
    value = {"schema": "p11scope/release-matrix-build/v1", "producer": "cargo-build",
             "lib_sha256": sha(bins / "p11scope-lib"), "source_root": str(source_root),
             "source_revision": "a" * 40, "source_tree": "b" * 40, "source_clean": True,
             "build": {"argv": ["controlled-cargo", "test", "--lib", "--no-run"], "cwd": str(source_root), "exit": 0},
             "runtime_sources": {name: sha(source_root / name) for name in
                                 ("tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c")}}
    path.write_text(json.dumps(value) + "\n")
    return path


def command(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True,
                            env=os.environ.copy(), timeout=20)
    retain_command(args, result)
    return result


def retain_command(args, result):
    directory = os.environ.get("P11SCOPE_MATRIX_TEST_EVIDENCE_DIR")
    if directory:
        path = Path(directory); path.mkdir(parents=True, exist_ok=True)
        with (path / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps({"argv": list(args), "cwd": str(ROOT),
                                     "TMPDIR": os.environ.get("TMPDIR"), "exit": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")


class MatrixContract(unittest.TestCase):
    def tearDown(self):
        directory = os.environ.get("P11SCOPE_MATRIX_TEST_EVIDENCE_DIR")
        if directory:
            destination = Path(directory) / self._testMethodName
            shutil.copytree(self.base, destination)
            manifest = {str(path.relative_to(destination)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in destination.rglob("*") if path.is_file()}
            (destination / "input-output-sha256.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="matrix-contract-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stage = self.base / "stage"
        self.stage.mkdir()
        self.bins = self.base / "bins"
        self.bins.mkdir()
        for name in ("p11scope", "p11scope-lib", "p11scope-bpfmulti"):
            (self.bins / name).write_text("controlled candidate " + name)
        self.candidate = candidate_receipt(self.bins, self.base / "candidate-build.json")
        self.listing = self.base / "ignored.txt"
        self.listing.write_text(f"{LIB_A}: test\n{LIB_B}: test\n{LIB_D}: test\n{LIB_C}: test\n\n4 tests, 0 benchmarks\n")
        self.curation = self.base / "curation.txt"
        self.curation.write_text(f"default (0)\nlong (4, --include-long only)\n{LIB_A}\n{LIB_B}\n{LIB_D}\n{LIB_C}\nskipped (0)\nverify: curation matches the binary (4 tests)\n")
        self.bm_list = self.base / "bpf-list.txt"
        self.bm_list.write_text(f"{PID_TEST}: test\n1 test, 0 benchmarks\n")
        self.kernel = self.base / "vmlinuz-6.1.188"
        self.kernel.write_bytes(b"controlled kernel; never booted")
        (self.base / "config-6.1.188").write_bytes(b"CONFIG_CONTROLLED_GUEST=y\n")
        self.contract = self.stage / "contract.json"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.stage),
                         "--lane", "6.1.188", "--kernel", str(self.kernel), "--bin-dir", str(self.bins),
                         "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(self.candidate),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.run_id = json.loads(self.contract.read_text())["run_id"]
        self.write("uname.txt", "6.1.188\n")
        self.log("version.log", "p11scope 0.4.0\n", "version", 0)
        self.log("doctor.log", "capability tier: T4\nuprobe-multi attach (own libc) .... ok self-link attached and detached\n", "doctor", 0)
        self.log("qual.log", "SUMMARY pass=10 fail=0 nonqualifying=3\n", "qual", 2)
        self.public_rows = [{"cell": name, "pass": qualification != "nonqualifying",
                             "detail": "controlled assertion", "qualification": qualification}
                            for name, qualification in PUBLIC.items()]
        self.write_rows()
        self.log("inv-native.log", "qualified owned inventory\n", "inv_native", 0)
        self.log("inv-scan.log", "valid scan plumbing, nonqualifying\n", "inv_scan", 2)
        self.log("pidflt.log", f"running 1 test\ntest {PID_TEST} ... ok\nPIDFLT_PROBE own=2 other=0 proves=true\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
        self.write("run/results.txt", f"# selectors: {LIB_A} {LIB_B}\nPASS {LIB_A} rc=0 seconds=1 :: test result: ok. 1 passed\nPASS {LIB_B} rc=0 seconds=1 :: test result: ok. 1 passed\nSUMMARY pass=2 fail=0 skipped=0\n")
        for name in (LIB_A, LIB_B):
            self.write("run/logs/" + name.split("::")[-1] + ".log", f"running 1 test\ntest {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.log("priv.log", "SUMMARY pass=2 fail=0 skipped=0\n", "priv", 0)
        self.backend("pid", "uprobe-multi", "kernel-pid+bpf", None)
        self.backend("sys", "uprobe-multi", None, None)
        self.seal()

    def write(self, name, text):
        path = self.stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def log(self, name, text, process, rc):
        self.write(name, text + f"{process}_exit={rc}\nmatrix_run={self.run_id}\n")

    def write_rows(self):
        self.write("cells/results.jsonl", "".join(json.dumps(row) + "\n" for row in self.public_rows))

    def backend(self, scope, mechanism, scope_filter, fallback):
        self.write("backend/inv-" + scope + ".json", json.dumps({"observation": {"attach": {
            "mechanism": mechanism, "scope_filter": scope_filter, "fallback": fallback}}}))
        self.log("backend/inv-" + scope + ".stderr", "", "inv_" + scope, 0)

    def seal(self, guest_exit=0):
        result = command(sys.executable, "-I", str(CHECKER), "--seal", str(self.stage),
                         "--contract", str(self.contract), "--guest-exit", str(guest_exit))
        self.assertEqual(result.returncode, 0, result.stderr)

    def judge(self, shell=False):
        argv = [str(RUNNER), "--judge-stage", str(self.stage)] if shell else [sys.executable, "-I", str(CHECKER), "--judge", str(self.stage)]
        return command(*argv, "--contract", str(self.contract))

    def reject(self, shell=False):
        result = self.judge(shell)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def selected_log(self, name, diagnostic):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "6.1.188", "--lib-test", name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        old = json.loads(self.contract.read_text())
        core = json.loads(result.stdout)["execution"]
        core.update({key: value for key, value in old.items() if key not in core})
        self.write("inputs/ignored.txt", f"{name}: test\n")
        self.write("inputs/curation.txt", f"default (1)\n{name}\nlong (0, --include-long only)\nskipped (0)\nverify: curation matches the binary (1 tests)\n")
        for path in ("inputs/ignored.txt", "inputs/curation.txt"):
            core["bindings"][path] = hashlib.sha256((self.stage / path).read_bytes()).hexdigest()
        self.contract.write_text(json.dumps(core) + "\n")
        self.write("run/results.txt", f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed\n")
        self.write("run/logs/" + name.split("::")[-1] + ".log", f"running 1 test\ntest {name} ... {diagnostic}\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.seal()

    def selected_log_515(self, diagnostic):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "5.15.221", "--lib-test", DENIAL)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        old = json.loads(self.contract.read_text())
        core = json.loads(result.stdout)["execution"]
        core.update({key: value for key, value in old.items() if key not in core})
        self.write("inputs/ignored.txt", f"{DENIAL}: test\n")
        self.write("inputs/curation.txt", f"default (1)\n{DENIAL}\nlong (0, --include-long only)\nskipped (0)\nverify: curation matches the binary (1 tests)\n")
        for path in ("inputs/ignored.txt", "inputs/curation.txt"):
            core["bindings"][path] = hashlib.sha256((self.stage / path).read_bytes()).hexdigest()
        self.contract.write_text(json.dumps(core) + "\n")
        core["expected_osrelease"] = "5.15.221"
        core["guest_boot_config"]["osrelease"] = "5.15.221"
        self.contract.write_text(json.dumps(core) + "\n")
        self.write("uname.txt", "5.15.221\n")
        self.write("run/results.txt", f"PASS {DENIAL} rc=0 seconds=1 :: test result: ok. 1 passed\n")
        self.write("run/logs/" + DENIAL.split("::")[-1] + ".log", f"running 1 test\ntest {DENIAL} ... {diagnostic}\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.seal()

    def test_denial_cell_denied_branch_judges_expected_refusal_on_515(self):
        self.selected_log_515(DENIED_MARKER)
        result = self.judge(shell=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        rows = {row["id"]: row for row in json.loads(result.stdout)["rows"]}
        self.assertEqual(rows["lib:" + DENIAL]["qualification"], "expected-refusal")
        identity = rows["identity:5.15-denied"]
        self.assertEqual(identity["qualification"], "expected-refusal")
        self.assertTrue(identity["detail"].startswith("guest refusal disclosed: " + DENIED_MARKER))

    def test_denial_cell_fabricated_denial_is_rejected_on_515(self):
        fabrications = {
            "eligible branch on 5.15": ELIGIBLE_MARKER,
            "nonzero bpf delta": DENIED_MARKER.replace("bpf_delta=0", "bpf_delta=1"),
            "wrong reason": DENIED_MARKER.replace("reason=kernel_fix_missing", "reason=no_btf"),
            "mm present": DENIED_MARKER.replace("mm_present=false", "mm_present=true"),
            "empty scan": DENIED_MARKER.replace("scan_bytes=5277697", "scan_bytes=0"),
            "extra token": DENIED_MARKER + " extra=1",
            "duplicate marker": DENIED_MARKER + "\n" + DENIED_MARKER,
            "missing marker": "no marker evidence",
        }
        for label, diagnostic in fabrications.items():
            with self.subTest(label=label):
                fresh = self.base / ("denial-red-" + label.replace(" ", "-"))
                shutil.copytree(self.stage, fresh)
                stage, contract = self.stage, self.contract
                self.stage, self.contract = fresh, fresh / "contract.json"
                try:
                    self.selected_log_515(diagnostic)
                    self.reject()
                finally:
                    self.stage, self.contract = stage, contract

    def test_denial_cell_denied_marker_is_rejected_off_515(self):
        self.selected_log(DENIAL, DENIED_MARKER)
        self.reject()

    def test_denial_cell_eligible_branch_judges_positive_off_515(self):
        self.selected_log(DENIAL, ELIGIBLE_MARKER)
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + DENIAL)
        self.assertEqual(row["qualification"], "positive-coverage")

    def test_denial_cell_single_witness_eligible_branches_judge_positive_off_515(self):
        # Honest Ok needs at least one pid_fd witness (attach OR
        # tasktype); both single-witness shapes must still classify
        # positive-coverage.
        for label, marker in (
                ("attach-only", ELIGIBLE_MARKER.replace("attach=true tasktype=true",
                                                        "attach=true tasktype=false")),
                ("tasktype-only", ELIGIBLE_MARKER.replace("attach=true tasktype=true",
                                                          "attach=false tasktype=true"))):
            with self.subTest(label=label):
                fresh = self.base / ("eligible-honest-" + label)
                shutil.copytree(self.stage, fresh)
                stage, contract = self.stage, self.contract
                self.stage, self.contract = fresh, fresh / "contract.json"
                try:
                    self.selected_log(DENIAL, marker)
                    result = self.judge()
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    row = next(r for r in json.loads(result.stdout)["rows"]
                               if r["id"] == "lib:" + DENIAL)
                    self.assertEqual(row["qualification"], "positive-coverage")
                finally:
                    self.stage, self.contract = stage, contract

    def test_denial_cell_witnessless_eligible_forgery_is_rejected_off_515(self):
        # check_kernel_identity_btf returns Ok only when attach OR tasktype
        # holds, so attach=false/tasktype=false is unemittable on Ok: a
        # judge that accepts it would bless a forged eligible marker.
        witnessless = ELIGIBLE_MARKER.replace("attach=true tasktype=true",
                                              "attach=false tasktype=false")
        self.selected_log(DENIAL, witnessless)
        self.reject()

    def test_each_multi_test_uses_its_own_refusal_not_later_positive_probe(self):
        for name, tag in ((CLASSIC_MULTI, "CLASSIC_PID_SCOPE selection=multi"),
                          (CAPTURE_MULTI, "C3_PID_SCOPE backend=Multi"),
                          (LEADER_MULTI, "C3_LEADER_EXIT_PROBE backend=Multi")):
            with self.subTest(name=name):
                self.selected_log(name, tag + ' refused="kernel pid filter unproven: EPERM"')
                result = self.judge(shell=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + name)
                self.assertEqual(row["qualification"], "expected-refusal")

    def test_multi_test_missing_or_contradictory_branch_fails(self):
        positive = 'CLASSIC_PID_SCOPE selection=multi multi=true scope_filter=Some("kernel-pid+bpf") fallback=None target=321 target_runs=1000 foreign_runs=0 reused_runs=0 foreign_ns_per_call_before=1.0 foreign_ns_per_call_during=1.0'
        for diagnostic in ("no branch evidence", 'CLASSIC_PID_SCOPE selection=multi refused="pid filter EPERM"\n' + positive):
            with self.subTest(diagnostic=diagnostic):
                self.selected_log(CLASSIC_MULTI, diagnostic); self.reject()

    def test_required_churn_zero_loss_assertion_cannot_be_skipped(self):
        self.selected_log(CHURN, 'C57_CHURN_BRANCH rate=100 branch=skipped reason="zero-loss not judged (indicative)"\nC57_CHURN_BRANCH rate=1000 branch=loss')
        self.reject()

    def test_broad_admission_total_refusal_is_not_positive_attach_coverage(self):
        self.selected_log(BROAD, 'A2 selected: 1 module(s) 2 table(s) 68 slot(s) spill=0 refused=0\nA2 broad: total refusal: refusing to attach a prefix of a module')
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + BROAD)
        self.assertEqual(row["qualification"], "expected-refusal")

    def test_own_positive_multi_branches_survive_a_later_unproven_probe(self):
        self.log("pidflt.log", f"test {PID_TEST} ... ok\nPIDFLT_PROBE own=1 other=0 proves=false\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
        self.backend("pid", "per-offset", "perf-task+bpf", "uprobe-multi under --pid needs a proven kernel pid filter: own=1")
        diagnostics = {
            CLASSIC_MULTI: 'CLASSIC_PID_SCOPE selection=multi multi=true scope_filter=Some("kernel-pid+bpf") fallback=None target=321 target_runs=1000 foreign_runs=0 reused_runs=0 foreign_ns_per_call_before=1.0 foreign_ns_per_call_during=1.0',
            CAPTURE_MULTI: 'C3_PID_SCOPE backend=Multi target=321 foreign=432 rows=1\nC3_PID_REUSE_EXCLUDED backend=Multi pid=321 rows=0 custody=lost',
            LEADER_MULTI: 'C3_LEADER_EXIT_PROBE backend=Multi pid=321 before_exit_usage1=1 leader_state=Z pidfd_alive=true after_exit_usage2_3=[0, 0] fired_after_exit=false custody=PidUnproven { at_ns: 3210, reason: "PID leader exited" }',
        }
        for name, diagnostic in diagnostics.items():
            with self.subTest(name=name):
                self.selected_log(name, diagnostic)
                result = self.judge()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + name)
                self.assertEqual(row["qualification"], "positive-coverage")

    def test_churn_lossless_and_honest_high_rate_loss_controls(self):
        for low, high in (("lossless attempt=1", "loss"), ("lossless attempt=2", "lossless"),
                          ("starved attempt=1 achieved=80\nC57_CHURN_BRANCH rate=100 branch=lossless attempt=2", "loss")):
            with self.subTest(low=low, high=high):
                self.selected_log(CHURN, "C57_CHURN_BRANCH rate=100 branch=" + low + "\nC57_CHURN_BRANCH rate=1000 branch=" + high)
                result = self.judge()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + CHURN)
                self.assertEqual(row["qualification"], "positive-coverage")
                self.assertIn("rate100=lossless", row["detail"])

    # G01/R7: the T7 8192 boundary cell deliberately succeeds while
    # refusing the envelope (T7_ENVELOPE_REFUSAL, preflight or
    # post-failure). That success is an expected refusal, never
    # 8,192-endpoint positive coverage; only the exact all-ID ledger and
    # raw-map evidence qualifies the positive.
    BOUNDARY_REFUSALS = (
        'T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8192 phase=preflight '
        'verdict="T7 boundary cell out of envelope: 8192 endpoints need 8194 links '
        '(8258 FDs lower bound with 64 reserve) but only 7000 FDs fit under '
        'RLIMIT_NOFILE soft=8192 with 1192 open"',
        'T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8192 '
        'phase=post_failure_classification verdict="attach failed: Too many open files (os error 24)"',
    )
    BOUNDARY_POSITIVE = (
        "TASK4_LEDGER phase=after_go physical_ids=8192 completed_calls=8192 first=0 tail=8191\n"
        "TASK4_RAW_MAPS phase=after_go usage_positive=8192 exact_ids=0..8191"
    )

    def boundary_log(self, diagnostic):
        return (f"running 1 test\ntest {LIB_C} ... {diagnostic}\nok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")

    def test_boundary_refusal_is_not_positive_coverage(self):
        for diagnostic in self.BOUNDARY_REFUSALS:
            with self.subTest(diagnostic=diagnostic[:80]):
                # Direct classification through the actual module path.
                CHECKER_MOD["exact_test"](self.boundary_log(diagnostic), LIB_C)
                qualification, _ = CHECKER_MOD["lib_outcome"](LIB_C, self.boundary_log(diagnostic))
                self.assertEqual(qualification, "expected-refusal")
                # Full judge composition: a valid libtest PASS summary on
                # the refusal-only log must not restore positive coverage.
                self.selected_log(LIB_C, diagnostic)
                result = self.judge()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + LIB_C)
                self.assertEqual(row["qualification"], "expected-refusal")

    def test_boundary_positive_requires_population(self):
        # The nonempty all-ID positive still qualifies.
        CHECKER_MOD["exact_test"](self.boundary_log(self.BOUNDARY_POSITIVE), LIB_C)
        qualification, _ = CHECKER_MOD["lib_outcome"](LIB_C, self.boundary_log(self.BOUNDARY_POSITIVE))
        self.assertEqual(qualification, "positive-coverage")
        self.selected_log(LIB_C, self.BOUNDARY_POSITIVE)
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + LIB_C)
        self.assertEqual(row["qualification"], "positive-coverage")
        # Missing population, or an 8,191 population relabeled 8,192,
        # cannot satisfy the boundary's positive claim.
        bad = (
            "healthy",
            "TASK4_LEDGER phase=after_go physical_ids=8192 completed_calls=8192 first=0 tail=8191",
            "TASK4_RAW_MAPS phase=after_go usage_positive=8192 exact_ids=0..8191",
            self.BOUNDARY_POSITIVE.replace("8192", "8191").replace("tail=8191", "tail=8190").replace("0..8191", "0..8190"),
            self.BOUNDARY_POSITIVE.replace("0..8191", "0..8190"),
        )
        for diagnostic in bad:
            with self.subTest(diagnostic=diagnostic[:60]):
                with self.assertRaises(CHECKER_MOD["Invalid"]):
                    CHECKER_MOD["lib_outcome"](LIB_C, self.boundary_log(diagnostic))
                self.selected_log(LIB_C, diagnostic)
                self.reject()

    def test_boundary_conflicting_outcomes_fail(self):
        ledger, raw = self.BOUNDARY_POSITIVE.split("\n")
        conflicts = (
            # Refusal and positive evidence together.
            self.BOUNDARY_REFUSALS[0] + "\n" + self.BOUNDARY_POSITIVE,
            self.BOUNDARY_REFUSALS[1] + "\n" + ledger,
            # Duplicate or contradictory branches.
            self.BOUNDARY_REFUSALS[0] + "\n" + self.BOUNDARY_REFUSALS[1],
            ledger + "\n" + ledger + "\n" + raw,
            ledger + "\n" + raw + "\n" + raw,
            ledger + "\n" + raw + "\n" + ledger.replace("8192", "8191").replace("tail=8191", "tail=8190"),
            # Malformed refusal marker.
            "T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8192 phase=unknown verdict=\"x\"",
            "T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8191 phase=preflight verdict=\"x\"",
            "T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8192 phase=preflight",
            # Malformed duplicate branch evidence beside a valid positive:
            # an extra field, a contradictory relabeled line or a stray
            # marker is rejected, never silently ignored.
            self.BOUNDARY_POSITIVE + "\n" + ledger + " extra=1",
            self.BOUNDARY_POSITIVE + "\n" + raw.replace("8192", "8191").replace(
                "0..8191", "0..8190") + " rogue=1",
            self.BOUNDARY_POSITIVE + "\nTASK4_LEDGER phase=after_go physical_ids=8192",
            self.BOUNDARY_POSITIVE + "\nTASK4_RAW_MAPS phase=after_go usage_positive=8192",
        )
        for diagnostic in conflicts:
            with self.subTest(diagnostic=diagnostic[:60]):
                with self.assertRaises(CHECKER_MOD["Invalid"]):
                    CHECKER_MOD["lib_outcome"](LIB_C, self.boundary_log(diagnostic))
                self.selected_log(LIB_C, diagnostic)
                self.reject()

    def test_branch_conflicts_and_invalid_counts_fail(self):
        for name, diagnostic in ((CAPTURE_MULTI, 'C3_PID_SCOPE backend=Multi target=321 foreign=432 rows=1'),
                                 (CAPTURE_MULTI, 'C3_PID_SCOPE backend=Multi refused="kernel pid filter EPERM"\nC3_PID_REUSE_EXCLUDED backend=Multi pid=321 rows=0 custody=lost'),
                                 (LEADER_MULTI, 'C3_LEADER_EXIT_PROBE backend=Multi pid=321 before_exit_usage1=1 leader_state=Z pidfd_alive=true after_exit_usage2_3=[1, 0] fired_after_exit=false custody=PidUnproven { at_ns: 32, reason: "PID leader exited" }'),
                                 (CHURN, 'C57_CHURN_BRANCH rate=100 branch=lossless attempt=1\nC57_CHURN_BRANCH rate=1000 branch=loss\nC57_CHURN_BRANCH rate=1000 branch=lossless'),
                                 (CHURN, 'C57_CHURN_BRANCH rate=100 branch=starved attempt=2 achieved=80\nC57_CHURN_BRANCH rate=100 branch=lossless attempt=1\nC57_CHURN_BRANCH rate=1000 branch=loss')):
            with self.subTest(name=name, diagnostic=diagnostic):
                self.selected_log(name, diagnostic); self.reject()

    def test_broad_no_spill_positive_control_and_conflict(self):
        diagnostic = 'A2 selected: 1 module(s) 2 table(s) 68 slot(s) spill=0 refused=0\nA2 broad: 1 module(s) 2 table(s) 68 slot(s) spill=0 refused=0'
        self.selected_log(BROAD, diagnostic)
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        row = next(r for r in json.loads(result.stdout)["rows"] if r["id"] == "lib:" + BROAD)
        self.assertEqual(row["qualification"], "positive-coverage")
        self.selected_log(BROAD, diagnostic + '\nA2 broad: total refusal: refusing to attach a prefix')
        self.reject()

    def test_lifecycle_loss_tolerance_and_observed_loss_fail(self):
        for header, diagnostic in (("# opt-in: P11SCOPE_PRIV_LIFECYCLE_LOSS=report\n", "healthy"),
                                   ("", "LIFECYCLE_LOSS_REPORTED ring_loss=7 consumer_demotion=None mode=report"),
                                   ("# opt-in: P11SCOPE_TEST_TIME_SCALE=4\n", "healthy")):
            with self.subTest(header=header, diagnostic=diagnostic):
                self.selected_log(LIB_A, diagnostic)
                path = self.stage / "run/results.txt"; path.write_text(header + path.read_text())
                self.seal(); self.reject()

    def clone_source(self):
        repo = self.base / "source-clone"
        for name in ("scripts/release-matrix-contract.py", "scripts/qualify-release-matrix.sh",
                     "scripts/run-privileged-lib-tests.sh", "scripts/qualify-public-cli.sh",
                     "scripts/mapped-provider-pin.py", "scripts/public-cli-oracle.py", "scripts/check-capture-evidence.py",
                     "scripts/qualify-inventory-native.sh", "scripts/inventory-native-oracle.py",
                     "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                     "tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / name, path)
        stage = self.base / "clone-stage"
        receipt = candidate_receipt(self.bins, self.base / "clone-build.json", repo)
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--prepare", str(stage),
                         "--lane", "host", "--kernel", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(receipt), "--lib-test", LIB_A)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return repo, stage

    def test_no_object_staged_sources_run_real_public_and_native_oracles_without_checkout(self):
        # Reuse only the existing external child/report fixtures. The staged
        # shell, provider pin, public oracle and verdict reader are real bytes.
        public = runpy.run_path(str(ROOT / "tests/python/test_public_cli_oracle.py"))
        repo, stage = self.clone_source()
        self.assertEqual(json.loads((stage / "contract.json").read_text())["object_cells"], [])
        staged = stage / "artifacts/source/scripts"
        unrelated = self.base / "unrelated cwd"; unrelated.mkdir()
        repo.rename(self.base / "unavailable original checkout")
        self.assertFalse(repo.exists())
        result = subprocess.run([sys.executable, "-I", str(staged / "public-cli-oracle.py"), "--help"],
                                cwd=unrelated, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        shell_control = public["ShellControls"]()
        shell_control.control.__func__.__globals__["SHELL"] = staged / "qualify-public-cli.sh"
        previous = Path.cwd()
        try:
            os.chdir(unrelated)
            shell_control.control("healthy", 0, local_output=True)
        finally:
            os.chdir(previous)
        native = subprocess.run([sys.executable, "-I", str(staged / "inventory-native-oracle.py"), "probe-help"],
                                cwd=unrelated, input="Usage: p11scope inventory --capture --manifest\n",
                                text=True, capture_output=True, timeout=5)
        self.assertEqual((native.returncode, native.stdout), (0, "capture=1\nmanifest=1\n"), native.stderr)
        policy = subprocess.run([sys.executable, "-I", str(staged / "release-matrix-contract.py"), "--verify-launch-policy"],
                                cwd=unrelated, text=True, capture_output=True, timeout=5)
        self.assertEqual(policy.returncode, 0, policy.stdout + policy.stderr)

    def test_no_object_required_public_helpers_refuse_missing_or_changed_inputs(self):
        repo, stage = self.clone_source()
        contract_path = stage / "contract.json"
        original = json.loads(contract_path.read_text())
        for name in ("public-cli-oracle.py", "check-capture-evidence.py"):
            relative = "artifacts/source/scripts/" + name
            source, staged = repo / "scripts" / name, stage / relative
            self.assertIn(relative, original["bindings"])
            content = staged.read_bytes()
            for case in ("missing_binding", "missing_file", "changed_file", "changed_runtime"):
                with self.subTest(helper=name, case=case):
                    data = json.loads(json.dumps(original))
                    if case == "missing_binding": data["bindings"].pop(relative)
                    elif case == "missing_file": staged.unlink()
                    elif case == "changed_file": staged.write_bytes(content + b"\n# stale staged helper\n")
                    else: source.write_bytes(content + b"\n# changed runtime helper\n")
                    contract_path.write_text(json.dumps(data))
                    result = command(str(repo / "scripts/qualify-release-matrix.sh"), "--write-inner-stage", str(stage),
                                     "--contract", str(contract_path))
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertFalse((stage / "inner.sh").exists())
                    staged.write_bytes(content); source.write_bytes(content)
        contract_path.write_text(json.dumps(original))

    def test_runtime_ledger_drift_is_rejected_before_inner_generation(self):
        repo, stage = self.clone_source()
        path = repo / "tests/fixtures/public-cli/inventory-ledger.c"
        path.write_text(path.read_text() + "\n/* controlled drift */\n")
        verify = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--verify-inputs", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(verify.returncode, 1, verify.stdout + verify.stderr)
        writer = command(str(repo / "scripts" / RUNNER.name), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(writer.returncode, 1, writer.stdout + writer.stderr)
        self.assertFalse((stage / "inner.sh").exists())

    def test_missing_required_runtime_source_binding_fails(self):
        data = json.loads(self.contract.read_text())
        data["bindings"].pop("artifacts/source/tests/fixtures/public-cli/inventory-ledger.c", None)
        self.contract.write_text(json.dumps(data) + "\n")
        result = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(self.stage), "--contract", str(self.contract))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_missing_mapped_provider_pin_binding_fails(self):
        data = json.loads(self.contract.read_text())
        data["bindings"].pop("artifacts/source/scripts/mapped-provider-pin.py", None)
        self.contract.write_text(json.dumps(data) + "\n")
        result = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(self.stage), "--contract", str(self.contract))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_changed_mapped_provider_pin_runtime_source_fails(self):
        repo, stage = self.clone_source()
        helper = repo / "scripts/mapped-provider-pin.py"
        helper.write_text(helper.read_text() + "\n# changed runtime helper\n")
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--verify-inputs", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_prebuilt_candidate_without_build_root_receipt_is_refused(self):
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.base / "no-build-receipt"),
                         "--lane", "host", "--kernel", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list), "--lib-test", LIB_A)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def canary_inputs(self, mode="full", bits=64):
        # Controlled parser input, never evidence of an actual native build.
        bundle = self.base / f"canary inputs {mode} {bits}"
        bundle.mkdir(exist_ok=True)
        work = self.base / "disposable build work"
        def elf(elf_class, machine, suffix=b""):
            value = bytearray(20)
            value[:6] = b"\x7fELF" + bytes((elf_class, 1))
            struct.pack_into("<H", value, 18, machine)
            return bytes(value) + suffix
        target = (1, 3) if bits == 32 else (2, 62)
        bpf = elf(2, 247, b"controlled detailed BPF " + mode.encode())
        definitions = {
            "p11scope": (elf(2, 62, bpf), "observer", work / "default-build/release/p11scope"),
            "p11scope-discover": (elf(*target), "helper" if bits == 32 else "observer",
                work / ("helper-build/i686-unknown-linux-gnu/release/p11scope-discover" if bits == 32 else "default-build/release/p11scope-discover")),
            "default-ebpf": (bpf, "observer", work / "default-build/release/build/p11scope-owned/out/p11scope-ebpf"),
            "canary_workload": (elf(*target), "workload", work / "canary_workload"),
            "matrix-provider.so": (elf(*target), "matrix-provider", work / "matrix-provider.so"),
            "privacy-provider.so": (elf(*target), "privacy-provider", work / "privacy-provider.so"),
            "dump-task-storage": (elf(2, 62), "reader", work / "task-storage-reader/dump-task-storage"),
            "dump-task-storage.bpf.o": (elf(2, 247, b"reader"), "reader", work / "task-storage-reader/dump-task-storage.bpf.o"),
        }
        artifacts = {}
        for name, (content, role, origin) in definitions.items():
            (bundle / name).write_bytes(content)
            (bundle / name).chmod(0o644 if name.endswith((".so", ".bpf.o", "-ebpf")) else 0o755)
            artifacts[name] = {"source": str(origin), "build": role, "sha256": hashlib.sha256(content).hexdigest()}
        commands = [ ("observer", ["p11scope_product_build", "ordinary", "--release", "--workspace",
            *(["--features", "stub-object-attributes"] if mode == "p0" else []),
            "--target-dir", str(work / "default-build")]) ]
        if bits == 32:
            commands.append(("helper", ["p11scope_product_build", "ordinary", "--release", "-p", "p11scope-discover",
                "--target", "i686-unknown-linux-gnu", "--target-dir", str(work / "helper-build")]))
        commands.extend([
            ("reader", ["scripts/build-task-storage-reader.sh", str(work / "task-storage-reader")]),
            ("workload", ["gcc", f"-m{bits}", "-std=c11", "-O0", "-Wall", "-Wextra", "-o", str(work / "canary_workload"),
                "scripts/fixtures/canary_workload.c", "-ldl", "-pthread"]),
            ("matrix-provider", ["gcc", f"-m{bits}", "-shared", "-fPIC", "-Wall", "-Wextra", "-DPRIVACY_FIXTURE=1",
                "-o", str(work / "matrix-provider.so"), "crates/discover/tests/fixture/version_matrix.c"]),
            ("privacy-provider", ["gcc", f"-m{bits}", "-shared", "-fPIC", "-Wall", "-Wextra", "-DPRIVACY_FIXTURE=1", "-DPRIVACY_BLOCKS=1",
                "-o", str(work / "privacy-provider.so"), "crates/discover/tests/fixture/version_matrix.c"]),
        ])
        sources = ("scripts/fixtures/canary_workload.c", "crates/discover/tests/fixture/version_matrix.c",
                   "scripts/build-task-storage-reader.sh", "scripts/native/dump-task-storage.c", "scripts/native/dump-task-storage.bpf.c")
        producer_sources = ("scripts/verify-canaries.sh", "scripts/product-build.sh", "scripts/cargo.sh",
                            "scripts/release-matrix-contract.py", ".release-rust-version", "build.rs", "src/lib.rs")
        facts = {"producer": "verify-canaries.sh --prepare-object-inputs", "source_root": str(ROOT),
            "source_revision": "a" * 40, "source_tree": "b" * 40, "source_clean": True,
            "capture_mode": mode, "target_bits": bits, "build_mode": "ordinary", "prepared_tools": {},
            "release_rust": (ROOT / ".release-rust-version").read_text().strip(),
            "build_environment": {name: None for name in ("P11SCOPE_SMALL_RING", "P11SCOPE_SMALL_STATE_MAPS",
                "P11SCOPE_SMALL_DISCOVERY_RING", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")},
            "builds": [{"role": role, "argv": argv, "cwd": str(ROOT), "exit": 0} for role, argv in commands],
            "artifacts": artifacts,
            "runtime_sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
            "producer_sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in producer_sources}}
        (bundle / "canary-build.json").write_text(json.dumps(facts) + "\n")
        return bundle, facts

    def prepare_object_inputs(self, stage, cells):
        argv = [sys.executable, "-I", str(CHECKER), "--prepare", str(stage), "--lane", "host", "--kernel", "host",
            "--bin-dir", str(self.bins), "--binary-list", str(self.listing), "--curation", str(self.curation),
            "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(self.candidate), "--lib-test", LIB_A]
        for mode, bits, bundle in cells:
            argv.extend(("--object-input", mode, str(bits), str(bundle)))
        return command(*argv)

    def prepare_guest_attempt(self, name, lane="6.1.188", kernel=None):
        stage = self.base / name
        if kernel is None:
            boot = self.base / (name + " boot")
            boot.mkdir()
            kernel = boot / ("vmlinuz-" + lane)
            kernel.write_bytes(b"controlled kernel input; never booted")
            (boot / ("config-" + lane)).write_bytes(b"CONFIG_CONTROLLED_GUEST=y\n")
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(stage),
            "--lane", lane, "--kernel", str(kernel), "--bin-dir", str(self.bins),
            "--binary-list", str(self.listing), "--curation", str(self.curation),
            "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(self.candidate),
            "--lib-test", LIB_A)
        return stage, result

    def test_prepare_stages_lane_boot_config_and_binds_osrelease(self):
        stage, result = self.prepare_guest_attempt("bound guest")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contract = json.loads((stage / "contract.json").read_text())
        expected = hashlib.sha256(b"CONFIG_CONTROLLED_GUEST=y\n").hexdigest()
        self.assertEqual(contract["expected_osrelease"], "6.1.188")
        self.assertEqual(contract["guest_boot_config"], {
            "source": str(self.base / "bound guest boot/config-6.1.188"),
            "sha256": expected, "osrelease": "6.1.188"})
        self.assertEqual(contract["bindings"]["inputs/boot-config"], expected)
        self.assertEqual((stage / "inputs/boot-config").read_bytes(), b"CONFIG_CONTROLLED_GUEST=y\n")
        verify = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage),
            "--contract", str(stage / "contract.json"))
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_host_prepare_stages_no_boot_config(self):
        stage, result = self.prepare_guest_attempt("bound host", "host", "host")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contract = json.loads((stage / "contract.json").read_text())
        self.assertIsNone(contract["guest_boot_config"])
        self.assertIsNone(contract["expected_osrelease"])
        self.assertFalse((stage / "inputs/boot-config").exists())

    def test_cached_kernel_tag_binds_its_actual_osrelease(self):
        home = self.base / "owned kernel cache"
        boot = home / ".cache/virtme-ng/v6.1.188/amd64/boot"; boot.mkdir(parents=True)
        config = boot / "config-6.1.188-controlled"; config.write_text("CONFIG_CONTROLLED=y\n")
        with mock.patch.object(Path, "home", return_value=home):
            path, release = CHECKER_MOD["guest_boot_config"]("v6.1.188")
        self.assertEqual((path, release), (config, "6.1.188-controlled"))
        config.rename(boot / "config-5.15.221")
        with mock.patch.object(Path, "home", return_value=home), self.assertRaises(CHECKER_MOD["Invalid"]):
            CHECKER_MOD["guest_boot_config"]("v6.1.188")

    def test_prepare_refuses_unknown_kernel_layouts(self):
        boot = self.base / "bad boot"; boot.mkdir()
        kernel = boot / "vmlinuz-6.1.188"; kernel.write_bytes(b"not booted")
        for case in ("missing", "ambiguous", "wrong_release", "wrong_lane"):
            with self.subTest(case=case):
                for path in boot.glob("config-*"): path.unlink()
                if case == "ambiguous":
                    (boot / "config-6.1.188").write_text("one")
                    (boot / "config-6.1.188-other").write_text("two")
                elif case == "wrong_release": (boot / "config-5.15.221").write_text("foreign")
                elif case == "wrong_lane": (boot / "config-6.1.188").write_text("one")
                stage, result = self.prepare_guest_attempt("invalid guest " + case,
                    "6.6.157" if case == "wrong_lane" else "6.1.188", kernel)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse((stage / "contract.json").exists())

    def test_tampered_boot_binding_fails(self):
        stage, result = self.prepare_guest_attempt("tamper boot")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        original = json.loads((stage / "contract.json").read_text())
        for case in ("missing", "hash", "osrelease", "extra_field", "bytes"):
            with self.subTest(case=case):
                value = json.loads(json.dumps(original))
                (stage / "inputs/boot-config").write_bytes(b"CONFIG_CONTROLLED_GUEST=y\n")
                if case == "missing": value["bindings"].pop("inputs/boot-config")
                elif case == "hash": value["guest_boot_config"]["sha256"] = "0" * 64
                elif case == "osrelease": value["expected_osrelease"] = "6.6.157"
                elif case == "extra_field": value["guest_boot_config"]["ignore"] = True
                else: (stage / "inputs/boot-config").write_bytes(b"changed")
                (stage / "contract.json").write_text(json.dumps(value))
                verify = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage),
                    "--contract", str(stage / "contract.json"))
                self.assertEqual(verify.returncode, 1, verify.stdout + verify.stderr)

    def test_guest_object_dispatch_uses_real_nonroot_identity(self):
        account = pwd.getpwuid(os.getuid())
        with mock.patch.dict(os.environ, {"SUDO_UID": "0", "SUDO_GID": "0", "SUDO_USER": "root"}):
            stage, result = self.prepare_guest_attempt("real caller")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        identity = json.loads((stage / "contract.json").read_text())["run_identity"]
        self.assertEqual(identity, {"uid": os.getuid(), "gid": os.getgid(), "user": account.pw_name})
        validate = CHECKER_MOD["validate_run_identity"]
        self.assertEqual(validate(identity).pw_uid, os.getuid())
        for change in ({"uid": 0}, {"uid": True}, {"gid": 0}, {"user": "root"}, {"user": "p11scope-missing-account"}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(CHECKER_MOD["Invalid"]):
                validate(identity | change)

    def test_guest_local_outputs_copy_bytes_without_9p_metadata(self):
        copy_tree = CHECKER_MOD["copy_guest_tree"]
        source = self.base / "retired public"; source.mkdir()
        (source / "fix").mkdir()
        (source / "fix/gated").write_bytes(b"controlled executable\x00bytes")
        (source / "fix/gated").chmod(0o755)
        (source / "results.jsonl").write_text(json.dumps({"cell": "fifo-refused", "pass": True}) + "\n")
        os.mkfifo(source / "fifo")
        dest = self.base / "9p destination"
        # Unsupported metadata operations must not be attempted by the actual copier.
        with mock.patch.object(shutil, "copystat", side_effect=OSError("9p metadata refused")):
            copy_tree(source, dest, "public")
        self.assertEqual((dest / "fix/gated").read_bytes(), (source / "fix/gated").read_bytes())
        self.assertEqual(stat.S_IMODE((dest / "fix/gated").stat().st_mode), 0o755)
        self.assertFalse((dest / "fifo").exists())
        self.assertTrue(stat.S_ISFIFO((source / "fifo").stat().st_mode))
        native = self.base / "retired native"; (native / "c8-wl.owned/gates").mkdir(parents=True)
        os.mkfifo(native / "c8-wl.owned/gates/release")
        (native / "report.json").write_bytes(b"native bytes")
        copy_tree(native, self.base / "native export", "native")
        self.assertEqual((self.base / "native export/report.json").read_bytes(), b"native bytes")
        for case in ("unproved_fifo", "unknown_fifo", "symlink", "extra_destination", "copy_changed", "copy_failed", "copy_missing"):
            with self.subTest(case=case):
                target = self.base / ("refuse copy " + case)
                if case == "unproved_fifo": (source / "results.jsonl").write_text('{"cell":"fifo-refused","pass":false}\n')
                elif case == "unknown_fifo": os.mkfifo(source / "unknown")
                elif case == "symlink": (source / "link").symlink_to("fix/gated")
                elif case == "extra_destination": target.mkdir(); (target / "unexpected").write_text("foreign")
                with self.assertRaises((CHECKER_MOD["Invalid"], OSError)):
                    if case == "copy_changed":
                        with mock.patch.object(shutil, "copyfileobj", side_effect=lambda src, dst, length: dst.write(b"changed")):
                            copy_tree(source, target, "public")
                    elif case == "copy_failed":
                        with mock.patch.object(shutil, "copyfileobj", side_effect=OSError("copy failed")):
                            copy_tree(source, target, "public")
                    elif case == "copy_missing":
                        def disappear(src, dst, length):
                            dst.write(src.read()); (source / "results.jsonl").unlink()
                        with mock.patch.object(shutil, "copyfileobj", side_effect=disappear):
                            copy_tree(source, target, "public")
                    else: copy_tree(source, target, "public")
                (source / "results.jsonl").write_text('{"cell":"fifo-refused","pass":true}\n')
                (source / "unknown").unlink(missing_ok=True); (source / "link").unlink(missing_ok=True)

    def test_guest_work_root_requires_trusted_local_disk(self):
        validate = CHECKER_MOD["validate_guest_work_root"]
        root = self.base / "local disk"; root.mkdir(); root.chmod(0o711)
        result = subprocess.CompletedProcess([], 0, "btrfs\n", "")
        with mock.patch.object(subprocess, "run", return_value=result):
            self.assertEqual(validate(root), root)
            with mock.patch.object(os, "getuid", return_value=0):
                self.assertEqual(validate(root, pwd.getpwuid(root.stat().st_uid).pw_uid), root)
        for filesystem in ("9p", "virtiofs", "tmpfs", "nfs4", "unknown", "btrfs\n9p"):
            with self.subTest(filesystem=filesystem), mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, filesystem, "")):
                with self.assertRaises(CHECKER_MOD["Invalid"]): validate(root)
        with mock.patch.object(subprocess, "run", return_value=result):
            for case in ("writable", "symlink", "missing", "full"):
                with self.subTest(case=case):
                    path = root
                    if case == "writable": root.chmod(0o777)
                    elif case == "symlink": path = self.base / "disk alias"; path.symlink_to(root)
                    elif case == "missing": path = self.base / "absent disk"
                    with self.assertRaises((CHECKER_MOD["Invalid"], OSError)):
                        if case == "full":
                            with mock.patch.object(shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1, 1, 0)): validate(path)
                        else: validate(path)
                    root.chmod(0o711)

    def test_module_discovery_preserves_explicit_elf_and_refuses_missing_or_wrong_abi(self):
        select = CHECKER_MOD["select_module"]
        module = self.base / "explicit non-Debian module.so"
        header = bytearray(64); header[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<H", header, 18, 62)
        module.write_bytes(header)
        self.assertEqual(select(str(module)), module)
        with mock.patch.object(os, "getuid", return_value=0):
            self.assertEqual(select(str(module)), module)
        for case in ("missing", "wrong_abi", "non_elf"):
            with self.subTest(case=case), self.assertRaises((CHECKER_MOD["Invalid"], OSError)):
                if case == "missing": select(str(self.base / "missing module"))
                elif case == "wrong_abi":
                    value = bytearray(header); value[4] = 1; module.write_bytes(value); select(str(module))
                else: module.write_bytes(b"not ELF"); select(str(module))
        module.write_bytes(header)
        actual_resolve = Path.resolve
        selected = Path("/usr/lib64/softhsm/libsofthsm2.so")
        def exists(path): return True if path == selected else False
        def resolve(path, **kwargs): return module if path == selected else actual_resolve(path, **kwargs)
        with mock.patch.object(Path, "exists", exists), mock.patch.object(Path, "resolve", resolve):
            self.assertEqual(select(), module)

    def test_object_inputs_bind_actual_build_mode_abi_and_sources(self):
        for mode, bits in (("full", 32), ("full", 64), ("p0", 32), ("p0", 64)):
            with self.subTest(mode=mode, bits=bits):
                bundle, facts = self.canary_inputs(mode, bits)
                stage = self.base / f"prepared {mode} {bits}"
                result = self.prepare_object_inputs(stage, [(mode, bits, bundle)])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                contract = json.loads((stage / "contract.json").read_text())
                self.assertEqual(contract["object_cells"], [{"mode": mode, "target_bits": bits,
                    "bundle": f"artifacts/canary/{mode}-{bits}",
                    "required_ids": [f"object:{mode}:{bits}:complete", f"object:{mode}:{bits}:blocked"]}])
                self.assertFalse(contract["full_stage5_ready"])
                for name in ("scripts/lane-lib-oracle-1.py", "scripts/capture-stopped-canary.py",
                             "scripts/fixtures/privacy-stack-workload.c"):
                    self.assertIn("artifacts/source/" + name, contract["bindings"])
                self.assertFalse((self.base / "disposable build work").exists())
                verify = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage),
                    "--contract", str(stage / "contract.json"))
                self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
                missing = contract["bindings"].pop("artifacts/source/scripts/lane-lib-oracle-1.py")
                (stage / "contract.json").write_text(json.dumps(contract))
                self.assertEqual(command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage),
                    "--contract", str(stage / "contract.json")).returncode, 1)
                self.assertEqual(len(missing), 64)

    def test_guest_root_verifies_bound_caller_owned_object_inputs(self):
        bundle, facts = self.canary_inputs()
        stage = self.base / "caller owned guest inputs"
        result = self.prepare_object_inputs(stage, [("full", 64, bundle)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with mock.patch.object(os, "getuid", return_value=0):
            # The generic producer/prebuilt path must not trust an unrelated UID.
            with self.assertRaises(CHECKER_MOD["Invalid"]):
                CHECKER_MOD["validate_canary_payloads"](stage / "artifacts/canary/full-64", 64)
            contract = CHECKER_MOD["verify_inputs"](stage, stage / "contract.json")
        self.assertEqual(contract["run_identity"]["uid"], pwd.getpwnam(contract["run_identity"]["user"]).pw_uid)

    def test_object_input_mutations_refuse_before_contract_publication(self):
        bundle, original = self.canary_inputs()
        original_payloads = {name: (bundle / name).read_bytes() for name in original["artifacts"]}
        cases = ("missing", "untrusted", "symlink", "opposite_mode", "wrong_abi", "wrong_bpf", "mixed_bpf",
                 "failed_build", "boolean_exit", "duplicate_embedding", "wrong_features", "stale_source", "source_tree", "declaration", "duplicate")
        for case in cases:
            with self.subTest(case=case):
                for name, content in original_payloads.items():
                    (bundle / name).unlink(missing_ok=True)
                    (bundle / name).write_bytes(content)
                    (bundle / name).chmod(0o644 if name.endswith((".so", ".bpf.o", "-ebpf")) else 0o755)
                facts = json.loads(json.dumps(original))
                if case == "missing": (bundle / "privacy-provider.so").unlink()
                elif case == "untrusted": (bundle / "p11scope").chmod(0o777)
                elif case == "symlink":
                    (bundle / "p11scope").unlink(); (bundle / "p11scope").symlink_to("p11scope-discover")
                elif case == "opposite_mode": facts["capture_mode"] = "p0"
                elif case in ("wrong_abi", "wrong_bpf", "mixed_bpf"):
                    name = "p11scope-discover" if case == "wrong_abi" else "default-ebpf"
                    value = bytearray(original_payloads[name])
                    if case == "wrong_abi": value[4] = 1; struct.pack_into("<H", value, 18, 3)
                    elif case == "wrong_bpf": struct.pack_into("<H", value, 18, 62)
                    else: value.extend(b"foreign object")
                    (bundle / name).write_bytes(value)
                    facts["artifacts"][name]["sha256"] = hashlib.sha256(value).hexdigest()
                elif case == "failed_build": facts["builds"][0]["exit"] = 1
                elif case == "boolean_exit": facts["builds"][0]["exit"] = False
                elif case == "duplicate_embedding":
                    value = original_payloads["p11scope"] + original_payloads["default-ebpf"]
                    (bundle / "p11scope").write_bytes(value)
                    facts["artifacts"]["p11scope"]["sha256"] = hashlib.sha256(value).hexdigest()
                elif case == "wrong_features": facts["builds"][0]["argv"][2:2] = ["--features", "stub-object-attributes"]
                elif case == "stale_source": facts["runtime_sources"]["scripts/fixtures/canary_workload.c"] = "0" * 64
                elif case == "source_tree": facts["source_tree"] = "c" * 40
                elif case == "declaration": facts["producer"] = "user-declaration"
                (bundle / "canary-build.json").write_text(json.dumps(facts))
                stage = self.base / ("rejected-" + case)
                cells = [("full", 64, bundle)] * (2 if case == "duplicate" else 1)
                result = self.prepare_object_inputs(stage, cells)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse((stage / "contract.json").exists())

    def test_object_input_overlap_refuses_aliases_before_writes(self):
        def snapshot(root):
            result = {}
            for path in sorted(root.rglob("*")):
                mode = path.lstat().st_mode
                result[str(path.relative_to(root))] = (mode,
                    hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(mode) else None)
            return result

        for case in ("same_alias", "child_alias", "same_dotdot", "child_direct", "ancestor_alias"):
            with self.subTest(case=case):
                parent = self.base / (case + " parent")
                parent.mkdir()
                original, _ = self.canary_inputs()
                bundle = original.rename(parent / "owned bundle")
                alias = self.base / (case + " alias")
                alias.symlink_to(parent, target_is_directory=True)
                argument = alias / bundle.name
                stage = bundle
                if case == "child_alias": stage = bundle / "new stage" / "nested"
                elif case == "same_dotdot":
                    (parent / "step").mkdir()
                    argument = parent / "step" / ".." / bundle.name
                elif case == "child_direct": stage = bundle / "new stage"; argument = bundle
                elif case == "ancestor_alias": stage = parent
                before = snapshot(parent)
                result = self.prepare_object_inputs(stage, [("full", 64, argument)])
                after = snapshot(parent)
                self.assertEqual(after, before, f"{case}: preparation changed the input tree")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

        original, _ = self.canary_inputs()
        alias = self.base / "healthy alias"
        alias.symlink_to(self.base, target_is_directory=True)
        before = snapshot(original)
        stage = self.base / "healthy distinct stage"
        result = self.prepare_object_inputs(stage, [("full", 64, alias / original.name)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(original), before)
        self.assertEqual(command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage),
            "--contract", str(stage / "contract.json")).returncode, 0)

    def test_build_receipt_missing_mismatched_or_declared_provenance_fails(self):
        original = json.loads(self.candidate.read_text())
        mutations = ({"producer": "user-declaration"}, {"lib_sha256": "0" * 64}, {"source_root": str(self.base / "absent")},
                     {"runtime_sources": {}}, {"source_revision": "short"}, {"source_tree": "short"}, {"source_clean": False},
                     {"build": {"argv": ["cargo", "test", "--lib", "--no-run"], "cwd": str(ROOT), "exit": 1}})
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation):
                self.candidate.write_text(json.dumps(dict(original, **mutation)) + "\n")
                result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.base / ("invalid-build-" + str(index))),
                                 "--lane", "host", "--kernel", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                                 "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
                                 "--candidate-receipt", str(self.candidate), "--lib-test", LIB_A)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.candidate.write_text(json.dumps(original) + "\n")

    def test_compiled_fixture_root_is_bound_independently_of_current_runtime_root(self):
        builder = self.base / "actual-build-root"
        for name in ("tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = builder / name; path.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / name, path)
        receipt = candidate_receipt(self.bins, self.base / "actual-build.json", builder)
        self.listing.write_text(CHURN + ": test\n")
        self.curation.write_text(f"default (1)\n{CHURN}\nlong (0, --include-long only)\nskipped (0)\nverify: curation matches the binary (1 tests)\n")
        stage = self.base / "compiled-root-stage"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(stage), "--lane", "host", "--kernel", "host",
                         "--bin-dir", str(self.bins), "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(receipt), "--lib-test", CHURN)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        verify = (sys.executable, "-I", str(CHECKER), "--verify-inputs", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(command(*verify).returncode, 0)
        source = builder / "scripts/fixtures/exec_churn.c"; source.write_text(source.read_text() + "\n/* changed compiled fixture root */\n")
        result = command(*verify)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("compiled fixture source changed", result.stdout)
        result = command(str(RUNNER), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse((stage / "inner.sh").exists())

    def test_omitted_compiled_churn_binding_fails_judgment(self):
        contract = json.loads(self.contract.read_text())
        contract["bindings"].pop("artifacts/lib-source/scripts/fixtures/exec_churn.c")
        self.contract.write_text(json.dumps(contract) + "\n")
        self.seal(); self.reject()

    def test_compiled_source_drift_also_fails_actual_judge(self):
        builder = self.base / "judge-build-root"
        for name in ("tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = builder / name; path.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / name, path)
        receipt = candidate_receipt(self.bins, self.stage / "inputs/candidate-build.json", builder)
        contract = json.loads(self.contract.read_text())
        contract["bindings"]["inputs/candidate-build.json"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
        self.contract.write_text(json.dumps(contract) + "\n")
        self.seal()
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        source = builder / "tests/fixtures/public-cli/inventory-ledger.c"
        source.write_text(source.read_text() + "\n/* changed after execution */\n")
        result = self.judge(shell=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("compiled fixture source changed", result.stdout)

    def test_outer_empty_lane_refuses_before_setup_and_preserves_prior_output(self):
        for index, lanes in enumerate(([""], ["--kernels", ""], ["--kernels", " , "])):
            with self.subTest(lanes=lanes):
                prior = self.base / "empty-out" / "previous"; prior.mkdir(parents=True, exist_ok=True)
                (prior / "summary.md").write_text("retained prior output\n")
                stubs = self.base / ("empty-stubs-" + str(index)); stubs.mkdir()
                marker = self.base / ("workload-called-" + str(index))
                for name in ("pgrep", "sleep", "vng", "sudo", "flock"):
                    path = stubs / name; path.write_text("#!/bin/sh\nexit 1\n"); path.chmod(0o755)
                for path in self.bins.iterdir():
                    path.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 87\n"); path.chmod(0o755)
                env = os.environ.copy(); env["PATH"] = str(stubs) + ":" + env["PATH"]
                stage_base = self.base / ("empty-stage-" + str(index))
                result = subprocess.run([str(RUNNER), "--rev", "empty-" + str(index), "--bin-dir", str(self.bins),
                                         "--out-base", str(prior.parent), "--stage-base", str(stage_base), *lanes],
                                        cwd=ROOT, text=True, capture_output=True, env=env, timeout=20)
                retain_command(result.args, result)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("empty kernel", result.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse(stage_base.exists())
                self.assertEqual((prior / "summary.md").read_text(), "retained prior output\n")

    def test_complete_default_smoke_is_nonqualifying(self):
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if CHECKER.exists():
            report = json.loads(result.stdout)
            self.assertFalse(report["pass"])
            self.assertEqual(report["qualification"], "nonqualifying")
            self.assertEqual(next(r for r in report["rows"] if r["id"] == "inventory-scan")["qualification"], "nonqualifying")

    def test_summary_cannot_substitute_for_exact_lib_ids(self):
        self.write("run/results.txt", "SUMMARY pass=1 fail=0 skipped=0\n")
        self.seal(); self.reject()

    def test_duplicate_id_cannot_compensate_for_missing_id(self):
        self.write("run/results.txt", f"PASS {LIB_A} rc=0 seconds=1 :: test result: ok. 1 passed\nPASS {LIB_A} rc=0 seconds=1 :: test result: ok. 1 passed\nSUMMARY pass=2 fail=0 skipped=0\n")
        self.seal(); self.reject()

    def test_wrong_exact_test_log_name_fails(self):
        self.write("run/logs/" + LIB_A.split("::")[-1] + ".log", f"test {LIB_B} ... ok\ntest result: ok. 1 passed\n")
        self.seal(); self.reject()

    def test_required_static_skip_fails(self):
        self.write("run/results.txt", f"SKIP {LIB_A} :: unavailable\nPASS {LIB_B} rc=0 seconds=1 :: test result: ok. 1 passed\nSUMMARY pass=1 fail=0 skipped=1\n")
        self.seal(); self.reject()

    def test_unexpected_executed_id_fails(self):
        with (self.stage / "run/results.txt").open("a") as stream:
            stream.write(f"PASS {LIB_C} rc=0 seconds=1 :: test result: ok. 1 passed\n")
        self.seal(); self.reject()

    def test_all_process_exits_are_checked(self):
        for filename, process in (("priv.log", "priv"), ("qual.log", "qual"),
                                  ("pidflt.log", "pidflt"), ("doctor.log", "doctor"),
                                  ("backend/inv-pid.stderr", "inv_pid"), ("backend/inv-sys.stderr", "inv_sys")):
            with self.subTest(process=process):
                path = self.stage / filename
                original = path.read_text()
                path.write_text(re.sub(process + r"_exit=\d+", process + "_exit=1", original))
                self.seal(); self.reject()
                path.write_text(original)

    def test_conflicting_exit_markers_fail(self):
        with (self.stage / "priv.log").open("a") as stream:
            stream.write("priv_exit=1\n")
        self.seal(); self.reject()

    def test_guest_failure_and_timeout_fail(self):
        for rc in (1, 124, 137):
            with self.subTest(rc=rc):
                self.seal(rc); self.reject()

    def test_stale_artifact_hash_fails(self):
        path = self.stage / "artifacts/p11scope-lib"
        path.parent.mkdir(exist_ok=True)
        path.write_text("changed binary")
        self.reject()

    def test_stale_evidence_hash_fails(self):
        with (self.stage / "priv.log").open("a") as stream:
            stream.write("changed after sealing\n")
        self.reject()

    def test_missing_public_id_fails_despite_summary(self):
        self.public_rows.pop(0); self.write_rows(); self.seal(); self.reject()

    def test_duplicate_public_id_fails(self):
        self.public_rows[0] = self.public_rows[1]; self.write_rows(); self.seal(); self.reject()

    def test_smoke_mislabeled_positive_fails(self):
        self.public_rows[-1].update({"pass": True, "qualification": "owned-provider-counts"})
        self.write_rows(); self.seal(); self.reject()

    def test_failed_public_row_fails(self):
        self.public_rows[0].update({"pass": False, "qualification": "failed"})
        self.write_rows(); self.seal(); self.reject()

    def test_duplicate_public_json_key_is_invalid_evidence(self):
        path = self.stage / "cells/results.jsonl"
        path.write_text(path.read_text().replace('"pass": true', '"pass": false, "pass": true', 1))
        self.seal(); self.reject()

    def test_pid_multi_needs_two_owned_threads_and_zero_foreign_hits(self):
        for evidence in ("PIDFLT_PROBE own=1 other=0 proves=true", "PIDFLT_PROBE own=2 other=1 proves=true", "PIDFLT_PROBE own=2 other=0 proves=false", ""):
            with self.subTest(evidence=evidence):
                self.log("pidflt.log", f"test {PID_TEST} ... ok\n{evidence}\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
                self.seal(); self.reject()

    def test_system_multi_needs_independent_functional_link_proof(self):
        self.log("doctor.log", "capability tier: T4\nuprobe-multi attach (own libc) .... n/a kernel lacks uprobe-multi\n", "doctor", 0)
        self.seal(); self.reject()

    def test_proven_probe_with_disclosed_preparation_fallback_is_not_multi_coverage(self):
        self.backend("sys", "per-offset", None, "the uprobe-multi preparation failed: owned preparation refusal")
        self.seal()
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        rows = json.loads(result.stdout)["rows"]
        self.assertEqual(next(r for r in rows if r["id"] == "backend-system")["qualification"], "expected-fallback")

    def test_backported_system_multi_with_pid_fallback_is_valid(self):
        self.log("pidflt.log", f"test {PID_TEST} ... ok\nPIDFLT_PROBE own=1 other=0 proves=false\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
        self.backend("pid", "per-offset", "perf-task+bpf", "uprobe-multi under --pid needs a proven kernel pid filter: own=1")
        self.seal()
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if CHECKER.exists():
            rows = json.loads(result.stdout)["rows"]
            self.assertEqual(next(r for r in rows if r["id"] == "backend-pid")["qualification"], "expected-fallback")

    def test_scan_exit_zero_is_not_a_plumbing_pass(self):
        self.log("inv-scan.log", "", "inv_scan", 0); self.seal(); self.reject()

    def test_production_shell_uses_the_judge_and_propagates_failure(self):
        self.write("run/results.txt", "SUMMARY pass=1 fail=0 skipped=0\n")
        self.seal(); self.reject(shell=True)

    def test_shell_valid_nonqualifying_exit_is_preserved(self):
        result = self.judge(shell=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_nocapture_output_still_proves_the_exact_test_and_pid_counts(self):
        self.log("pidflt.log", f"running 1 test\ntest {PID_TEST} ... PIDFLT_PROBE own=2 other=0 proves=true\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
        self.write("run/logs/" + LIB_A.split("::")[-1] + ".log", f"running 1 test\ntest {LIB_A} ... independent fixture diagnostic\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.seal()
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def generated_guest(self, lane="host", controls=None):
        # Only external operations are controlled. The generated guest script,
        # contract sealing and judge are the production bytes and entrypoints.
        repo = self.base / "controlled-source"
        (repo / "scripts").mkdir(parents=True)
        for path in (RUNNER, CHECKER, ROOT / "scripts/public-cli-oracle.py", ROOT / "scripts/check-capture-evidence.py"):
            shutil.copy2(path, repo / "scripts" / path.name)
        for name in ("qualify-public-cli.sh", "qualify-inventory-native.sh", "run-privileged-lib-tests.sh"):
            path = repo / "scripts" / name
            path.write_text("#!/bin/bash\nprintf '%s\\n' \"$THREADS\" \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho 'SUMMARY pass=1 fail=0 skipped=0'\nexit 0\n" if name == "qualify-public-cli.sh" else "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho 'SUMMARY pass=1 fail=0 skipped=0'\nexit 0\n")
            text = path.read_text()
            if name == "qualify-public-cli.sh":
                body = "mkdir -p \"$2\"\nprintf '%s\\n' '{\"cell\":\"fifo-refused\",\"pass\":true}' > \"$2/results.jsonl\"\nmkfifo \"$2/fifo\"\nprintf 'public bytes' > \"$2/regular.txt\"\n"
            elif name == "qualify-inventory-native.sh":
                body = "mkdir -p \"$5/c8-wl.owned/gates\"\nmkfifo \"$5/c8-wl.owned/gates/release\"\nprintf 'native bytes' > \"$5/regular.txt\"\n: > \"$5/empty.log\"\n"
            else:
                body = "mkdir -p \"$2\"\nprintf 'controlled lib output' > \"$2/results.txt\"\n"
            path.write_text(text.replace("exit 0\n", body + "exit 0\n"))
            path.chmod(0o755)
        for name in ("scripts/inventory-native-oracle.py", "scripts/mapped-provider-pin.py",
                     "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                     "tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = repo / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("controlled external fixture\n")
        for name in ("p11scope", "p11scope-bpfmulti"):
            path = self.bins / name
            path.write_text("#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho controlled\nexit 0\n")
            path.chmod(0o755)
        stage = self.base / "guest-stage"
        guest_disk = self.base / "guest disk"; guest_disk.mkdir(mode=0o711)
        boot = self.base / "fake guest boot"; boot.mkdir()
        kernel = "host"
        if lane != "host":
            kernel = str(boot / ("vmlinuz-" + lane)); Path(kernel).write_text("not booted")
            (boot / ("config-" + lane)).write_text("CONFIG_OWNED_GUEST=y\n")
        receipt = candidate_receipt(self.bins, self.base / "guest-build.json", repo)
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--prepare", str(stage),
                         "--lane", lane, "--kernel", kernel, "--guest-work-root", str(guest_disk),
                         "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(receipt),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = command(str(repo / "scripts" / RUNNER.name), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        env = os.environ.copy()
        env["CONTROL_ARGS"] = str(self.base)
        stubs = self.base / "guest external commands"; stubs.mkdir()
        stub_sources = {
            "id": "#!/bin/sh\n[ \"$1\" != -u ] || { echo 0; exit 0; }; exec /usr/bin/id \"$@\"\n",
            "runuser": "#!/usr/bin/python3\nimport os,subprocess,sys\na=sys.argv[1:]; assert a[:3]==['-u',os.environ['CONTROL_USER'],'--']; a=a[3:]\nwith open(os.environ['CONTROL_ARGS']+'/account-commands','a') as f: f.write(' '.join(a)+'\\n')\nif a==['sudo','-n','true']: sys.exit(int(os.environ.get('CONTROL_SUDO_EXIT','0')))\nif a==['id','-u'] and os.environ.get('CONTROL_EFFECTIVE_UID'): print(os.environ['CONTROL_EFFECTIVE_UID']);sys.exit(0)\nif a[:1]==['id']: a[0]='/usr/bin/id'\nif a[:1]==['test'] and (os.environ.get('CONTROL_ACCESS_FAIL')=='all' or (os.environ.get('CONTROL_ACCESS_FAIL')=='private' and a[-1].endswith('/caller'))): sys.exit(1)\nsys.exit(subprocess.run(a).returncode)\n",
            "findmnt": "#!/bin/sh\nprintf '%s\\n' \"${CONTROL_FILESYSTEM:-btrfs}\"\n",
            "uname": "#!/bin/sh\nprintf '%s\\n' \"$CONTROL_UNAME\"\n",
            "cp": "#!/usr/bin/python3\nimport os,shutil,sys\na=sys.argv[1:]; assert a[0]=='--'; source,dest=a[1:]; assert dest.startswith('/boot/config-')\nwith open(os.environ['CONTROL_ARGS']+'/boot-installs','a') as f: f.write(dest+'\\n')\nshutil.copyfile(source,os.environ['CONTROL_BOOT']+'/'+dest.rsplit('/',1)[1])\n",
            "sha256sum": "#!/usr/bin/python3\nimport hashlib,os,pathlib,sys\na=sys.argv[1:]; p=a[-1]; assert p.startswith('/boot/config-')\nprint(hashlib.sha256(pathlib.Path(os.environ['CONTROL_BOOT'],p.rsplit('/',1)[1]).read_bytes()).hexdigest()+'  '+p)\n",
        }
        for name in ("gcc", "clang", "cargo", "rustc"):
            stub_sources[name] = "#!/bin/sh\necho compiler-invoked >&2\nexit 97\n"
        for name, text in stub_sources.items():
            path = stubs / name; path.write_text(text); path.chmod(0o755)
        module = self.base / "controlled-module.so"
        header = bytearray(64); header[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<H", header, 18, 62)
        module.write_bytes(header)
        env.update(PATH=str(stubs) + ":" + env["PATH"], CONTROL_USER=pwd.getpwuid(os.getuid()).pw_name,
                   CONTROL_UNAME=lane if lane != "host" else "controlled-host", CONTROL_BOOT=str(boot), MODULE=str(module))
        env.update(controls or {})
        run = subprocess.run(["bash", str(stage / "inner.sh")], cwd=ROOT,
                             capture_output=True, text=True, env=env, timeout=20)
        retain_command(["bash", str(stage / "inner.sh")], run)
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertNotIn("compiler-invoked", run.stdout + run.stderr)
        return stage, boot, run, env

    def test_generated_guest_executes_mt12_exact_selectors_and_fails_bad_evidence(self):
        self.generated_guest()
        public_args = (self.base / "qualify-public-cli.sh.args").read_text().splitlines()
        self.assertEqual(public_args[0], "12")
        privileged_args = (self.base / "run-privileged-lib-tests.sh.args").read_text().splitlines()
        self.assertEqual(privileged_args[2:], ["--include-long", LIB_A, LIB_B])
        self.assertEqual((self.base / "p11scope-bpfmulti.args").read_text().splitlines(),
                         ["--exact", PID_TEST, "--test-threads=1", "--nocapture"])

    def test_inner_renders_guest_boot_install_for_guest_lane(self):
        stage, boot, run, env = self.generated_guest("6.1.188")
        self.assertEqual((self.base / "boot-installs").read_text(), "/boot/config-6.1.188\n")
        self.assertEqual((boot / "config-6.1.188").read_text(), "CONFIG_OWNED_GUEST=y\n")
        self.assertTrue((self.base / "qualify-public-cli.sh.args").is_file(), run.stdout + run.stderr)
        body = (stage / "inner.sh").read_text()
        self.assertIn(str(stage / "artifacts/source"), body)
        self.assertNotIn(str(self.base / "controlled-source/scripts/run-privileged-lib-tests.sh"), body)

    def test_inner_leaves_host_boot_untouched(self):
        self.generated_guest()
        self.assertFalse((self.base / "boot-installs").exists())

    def test_generated_guest_copies_retired_fifo_trees_without_metadata(self):
        stage, boot, run, env = self.generated_guest()
        local = Path(json.loads((stage / "guest-work.json").read_text())["work"])
        self.assertTrue(local.is_relative_to(self.base / "guest disk"))
        self.assertFalse(local.is_relative_to(stage))
        for name in ("c8-native", "c8-scan"):
            self.assertEqual(stat.S_IMODE((local / name).stat().st_mode), 0o711)
            self.assertEqual((stage / name / "regular.txt").read_bytes(), b"native bytes")
            self.assertEqual((stage / name / "empty.log").read_bytes(), b"")
            self.assertTrue(stat.S_ISFIFO((local / name / "c8-wl.owned/gates/release").stat().st_mode))
            self.assertFalse((stage / name / "c8-wl.owned/gates/release").exists())
        self.assertEqual(stat.S_IMODE((local / "caller").stat().st_mode), 0o700)
        self.assertEqual((local / "caller").stat().st_uid, os.getuid())
        self.assertEqual((stage / "cells/regular.txt").read_bytes(), b"public bytes")
        self.assertFalse((stage / "cells/fifo").exists())

    def test_vng_guest_gets_boot_overlay_and_kernel_binding(self):
        body = RUNNER.read_text().split("run_one() {", 1)[1].split("\noverall=", 1)[0]
        self.assertIn('--kernel "$k" --guest-work-root "$GUEST_WORK_ROOT"', body)
        host, guest = body.split('if [ "$k" = host ]; then', 1)[1].split("\n  else\n", 1)
        self.assertNotIn("--overlay-rwdir", host)
        self.assertIn('--rwdir "$stage" --overlay-rwdir /boot', guest)

    def test_generated_guest_refuses_bad_identity_sudo_storage_and_kernel_before_workloads(self):
        stage, boot, run, env = self.generated_guest("6.1.188")
        original = json.loads((stage / "contract.json").read_text())
        for case in ("account", "root", "effective_uid", "sudo", "access", "private", "9p", "tmpfs", "overlap", "kernel"):
            with self.subTest(case=case):
                for path in self.base.glob("*.args"): path.unlink()
                value = json.loads(json.dumps(original)); current = env.copy()
                if case == "account": value["run_identity"]["user"] = "p11scope-missing-account"
                elif case == "root": value["run_identity"]["uid"] = 0
                elif case == "sudo": current["CONTROL_SUDO_EXIT"] = "1"
                elif case == "effective_uid": current["CONTROL_EFFECTIVE_UID"] = "0"
                elif case == "access": current["CONTROL_ACCESS_FAIL"] = "all"
                elif case == "private": current["CONTROL_ACCESS_FAIL"] = "private"
                elif case == "overlap": value["guest_work_root"] = str(stage / "artifacts")
                elif case in ("9p", "tmpfs"): current["CONTROL_FILESYSTEM"] = case
                else: current["CONTROL_UNAME"] = "foreign-release"
                (stage / "contract.json").write_text(json.dumps(value))
                result = subprocess.run(["bash", str(stage / "inner.sh")], text=True, capture_output=True, env=current, timeout=20)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(list(self.base.glob("*.args")), [])
        (stage / "contract.json").write_text(json.dumps(original))

    def test_generated_guest_refuses_tolerance_before_any_workload(self):
        self.test_generated_guest_executes_mt12_exact_selectors_and_fails_bad_evidence()
        for variable, value in (("P11SCOPE_PRIV_LIFECYCLE_LOSS", "report"), ("P11SCOPE_TEST_TIME_SCALE", "4")):
            with self.subTest(variable=variable):
                for path in self.base.glob("*.args"):
                    path.unlink()
                env = os.environ.copy(); env["CONTROL_ARGS"] = str(self.base); env[variable] = value
                args = ["bash", str(self.base / "guest-stage/inner.sh")]
                run = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, env=env, timeout=20)
                retain_command(args, run)
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assertIn("qualification tolerance", run.stdout + run.stderr)
                self.assertEqual(list(self.base.glob("*.args")), [])

    def test_contract_changed_after_receipt_fails(self):
        with self.contract.open("a") as stream:
            stream.write("\n")
        self.reject()

    def test_inner_writer_rejects_invalid_contract_without_writing_commands(self):
        self.contract.write_text('{"lib_tests":[]}\n')
        result = command(str(RUNNER), "--write-inner-stage", str(self.stage), "--contract", str(self.contract))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse((self.stage / "inner.sh").exists())

    def test_existing_campaign_is_preserved_before_candidate_or_guest_setup(self):
        out = self.base / "campaign-out"
        previous = out / "HEAD"
        previous.mkdir(parents=True)
        (previous / "summary.md").write_text("preserved earlier evidence\n")
        stubs = self.base / "stubs"
        stubs.mkdir()
        for name, rc in (("pgrep", 1), ("sleep", 0)):
            path = stubs / name; path.write_text(f"#!/bin/sh\nexit {rc}\n"); path.chmod(0o755)
        env = os.environ.copy(); env["PATH"] = str(stubs) + ":" + env["PATH"]
        stage_base = self.base / "campaign-stage"
        result = subprocess.run([str(RUNNER), "--rev", "HEAD",
                                 "--out-base", str(out), "--stage-base", str(stage_base), "--kernels", "6.1"],
                                cwd=ROOT, text=True, capture_output=True, env=env, timeout=20)
        retain_command(result.args, result)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refusing existing campaign output/stage", result.stderr)
        self.assertEqual((previous / "summary.md").read_text(), "preserved earlier evidence\n")
        self.assertFalse(stage_base.exists())

    def test_raw_evidence_from_a_previous_run_fails(self):
        path = self.stage / "priv.log"
        path.write_text(path.read_text().replace(self.run_id, "previous-run"))
        self.seal(); self.reject()

    def test_wrong_kernel_lane_fails(self):
        self.write("uname.txt", "6.6.157\n"); self.seal(); self.reject()

    def test_retained_public_artifact_is_hash_bound(self):
        self.write("cells/profile-pid.json", '{"controlled":"first"}\n')
        self.seal()
        self.write("cells/profile-pid.json", '{"controlled":"replaced"}\n')
        self.reject()

    def test_required_selector_absent_from_binary_fails_preparation(self):
        self.listing.write_text(f"{LIB_A}: test\n{LIB_C}: test\n")
        self.curation.write_text(f"default (0)\nlong (2, --include-long only)\n{LIB_A}\n{LIB_C}\nskipped (0)\nverify: curation matches the binary (2 tests)\n")
        self.preparation_rejected()

    def test_required_selector_on_static_skip_list_fails_preparation(self):
        self.curation.write_text(f"default (0)\nlong (2, --include-long only)\n{LIB_B}\n{LIB_C}\nskipped (1)\n{LIB_A} :: external prerequisite\nverify: curation matches the binary (3 tests)\n")
        self.preparation_rejected()

    def test_substring_selector_collision_fails_preparation(self):
        extra = LIB_A + "_extra"
        self.listing.write_text(self.listing.read_text() + f"{extra}: test\n")
        self.curation.write_text(f"default (1)\n{extra}\nlong (3, --include-long only)\n{LIB_A}\n{LIB_B}\n{LIB_C}\nskipped (0)\nverify: curation matches the binary (4 tests)\n")
        self.preparation_rejected()

    def test_duplicate_binary_listing_fails_preparation(self):
        self.listing.write_text(self.listing.read_text() + f"{LIB_A}: test\n")
        self.preparation_rejected()

    def preparation_rejected(self):
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.base / "invalid-stage"),
                         "--lane", "6.1.188", "--kernel", str(self.kernel), "--bin-dir", str(self.bins),
                         "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(self.candidate),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_qualifying_selected_subset_may_pass_only_its_claim(self):
        fresh = self.base / "subset"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(fresh),
                         "--lane", "6.1.188", "--kernel", str(self.kernel), "--bin-dir", str(self.bins),
                         "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list), "--lib-test", LIB_A,
                         "--candidate-receipt", str(self.candidate),
                         "--lib-test", LIB_B, "--public-cell", "profile-pid", "--without-scan")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        new_id = json.loads((fresh / "contract.json").read_text())["run_id"]
        for name in ("version.log", "doctor.log", "qual.log", "inv-native.log", "pidflt.log", "priv.log", "uname.txt", "cells/results.jsonl"):
            dest = fresh / name; dest.parent.mkdir(exist_ok=True)
            dest.write_text((self.stage / name).read_text().replace(self.run_id, new_id))
        for name in ("run", "backend"):
            shutil.copytree(self.stage / name, fresh / name)
        for path in (fresh / "backend").glob("*.stderr"):
            path.write_text(path.read_text().replace(self.run_id, new_id))
        (fresh / "qual.log").write_text(f"qual_exit=0\nmatrix_run={new_id}\n")
        (fresh / "cells/results.jsonl").write_text(json.dumps(self.public_rows[0]) + "\n")
        result = command(sys.executable, "-I", str(CHECKER), "--seal", str(fresh), "--contract", str(fresh / "contract.json"), "--guest-exit", "0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = command(str(RUNNER), "--judge-stage", str(fresh), "--contract", str(fresh / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["pass"])
        self.assertFalse(report["full_stage5_ready"])


class Registration(unittest.TestCase):
    def test_named_denied_identity_tier_is_explicit_without_static_skips(self):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "5.15.221")
        self.assertEqual(result.returncode, 0, result.stderr)
        execution = json.loads(result.stdout)["execution"]
        forbidden = "attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none"
        self.assertNotIn(forbidden, execution["lib_tests"])
        self.assertTrue(any(r["id"] == "identity:5.15-denied" for r in execution["obligations"]))

    def test_denied_identity_tier_selects_executable_libtest(self):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "5.15.221")
        self.assertEqual(result.returncode, 0, result.stderr)
        execution = json.loads(result.stdout)["execution"]
        self.assertIn(DENIAL, execution["lib_tests"])
        self.assertIn("lib:" + DENIAL, execution["required_ids"])
        obligation = next(r for r in execution["obligations"] if r["id"] == "identity:5.15-denied")
        self.assertEqual(obligation["status"], "selected")
        self.assertEqual(obligation["libtest"], DENIAL)
        self.assertEqual(execution["lib_outcomes"][DENIAL], "denial-with-zero-bpf-or-eligible-by-lane")
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "5.15.221",
                         "--lib-test", LIB_A)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lane", "6.1.188")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(DENIAL, json.loads(result.stdout)["execution"]["lib_tests"])

    def test_dry_run_has_all_seven_lanes_mt12_and_exact_breadth_names(self):
        result = command(str(RUNNER), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        for literal in ("5.15.221", "6.1.188", "6.6.157", "6.8.0-142", "6.12.111", "7.2.6", "host", "THREADS=12", LIB_A, LIB_B, LIB_D, LIB_C, "unready"):
            with self.subTest(literal=literal):
                self.assertIn(literal, result.stdout)

    def test_empty_selection_is_rejected(self):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lib-test", "")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
