#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual matrix preparation, judge and production shell seams."""
import json
import contextlib
import errno
import hashlib
import io
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
CHECK_IGNORED_MOD = runpy.run_path(str(ROOT / "scripts/check-ignored-tests.py"))
PRIV_RUNNER = ROOT / "scripts/run-privileged-lib-tests.sh"
OVERLAY_CELL = ("discovery::sweep_attribution::tests::d4_overlay_cells::"
                "privileged_d4_overlay_xino_backend_parity")
EXT4_CELL = ("discovery::sweep_attribution::tests::d4_ext4_cells::"
             "privileged_d4_ext4_inode_reuse_confirmation_parity")
COPY_UP_RED = ("discovery::sweep_attribution::tests::d4_overlay_cells::"
               "overlay_copy_up_userspace_edge_absent")
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
        for name in ("p11scope", "p11scope-lib", "p11scope-bpfmulti", "p11scope-discover"):
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
            "--guest-work-root", str(self.base),
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

    def test_prepare_stages_attested_manifest_helper(self):
        contract = json.loads(self.contract.read_text())
        self.assertIn("artifacts/p11scope-discover", contract["bindings"])
        staged = self.stage / "artifacts/p11scope-discover"
        self.assertTrue(staged.is_file())
        self.assertEqual(staged.read_bytes(), (self.bins / "p11scope-discover").read_bytes())
        verify = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(self.stage),
            "--contract", str(self.contract))
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_prepare_refuses_bin_dir_without_attested_manifest_helper(self):
        bare = self.base / "bins without discover"; bare.mkdir()
        for name in ("p11scope", "p11scope-lib", "p11scope-bpfmulti"):
            shutil.copy2(self.bins / name, bare / name)
        stage = self.base / "undiscoverable stage"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(stage),
            "--lane", "6.1.188", "--kernel", str(self.kernel), "--bin-dir", str(bare),
            "--binary-list", str(self.listing), "--curation", str(self.curation),
            "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(self.candidate),
            "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("p11scope-discover", result.stdout)

    def test_verify_inputs_requires_attested_manifest_helper_binding(self):
        # A stage whose contract lost the helper binding is stale, even when
        # the staged file is still present.
        staged = self.stage / "artifacts/p11scope-discover"
        staged.write_bytes((self.bins / "p11scope-discover").read_bytes())
        contract = json.loads(self.contract.read_text())
        contract["bindings"].pop("artifacts/p11scope-discover", None)
        self.contract.write_text(json.dumps(contract))
        result = command(sys.executable, "-I", str(CHECKER), "--verify-inputs", str(self.stage),
            "--contract", str(self.contract))
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_host_prepare_stages_no_boot_config(self):
        stage, result = self.prepare_guest_attempt("bound host", "host", "host")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contract = json.loads((stage / "contract.json").read_text())
        self.assertIsNone(contract["guest_boot_config"])
        self.assertIsNone(contract["expected_osrelease"])
        self.assertFalse((stage / "inputs/boot-config").exists())

    def test_618_prepare_binds_osrelease(self):
        stage, result = self.prepare_guest_attempt("618 stage", "6.18.58")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contract = json.loads((stage / "contract.json").read_text())
        self.assertEqual(contract["lane"], "6.18.58")
        self.assertEqual(contract["expected_osrelease"], "6.18.58")
        self.assertEqual(contract["guest_boot_config"]["osrelease"], "6.18.58")

    def test_fedora_prepare_stages_no_boot_config(self):
        stage, result = self.prepare_guest_attempt("fedora stage", "fedora-7.2.9",
                                                  "fedora-7.2.9")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contract = json.loads((stage / "contract.json").read_text())
        self.assertEqual(contract["lane"], "fedora-7.2.9")
        self.assertIsNone(contract["guest_boot_config"])
        self.assertIsNone(contract["expected_osrelease"])
        self.assertFalse((stage / "inputs/boot-config").exists())

    def test_fedora_prepare_refuses_foreign_kernel(self):
        stage, result = self.prepare_guest_attempt("fedora mismatch", "fedora-7.2.9",
                                                  "host")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fedora lane requires fedora kernel", result.stdout)

    def test_fedora_launch_refuses_with_procedure_pointer(self):
        stage, prepared = self.prepare_guest_attempt("fedora launch", "fedora-7.2.9",
                                                    "fedora-7.2.9")
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        result = command(sys.executable, "-I", str(CHECKER), "--launch-guest", str(stage),
                         "--contract", str(stage / "contract.json"),
                         "--kernel", "fedora-7.2.9")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("live-cell procedure", result.stdout)

    def test_fedora_guest_inner_refuses_with_procedure_pointer(self):
        stage, prepared = self.prepare_guest_attempt("fedora inner", "fedora-7.2.9",
                                                    "fedora-7.2.9")
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        result = command(sys.executable, "-I", str(CHECKER), "--run-guest-inner", str(stage),
                         "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("live-cell procedure", result.stdout)

    def test_fedora_stage_refuses_guest_disk(self):
        stage, prepared = self.prepare_guest_attempt("fedora disk", "fedora-7.2.9",
                                                    "fedora-7.2.9")
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        contract_path = stage / "contract.json"
        contract = json.loads(contract_path.read_text())
        contract["guest_disk"] = {"path": str(self.base / "disk"), "uuid": "0" * 32}
        contract_path.write_text(json.dumps(contract))
        result = command(sys.executable, "-I", str(CHECKER), "--seal", str(stage),
                         "--contract", str(contract_path), "--guest-exit", "0")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fedora lane cannot use a guest disk", result.stdout)

    def judged_stage(self, name, lane, kernel, uname):
        """A sealed healthy stage on any lane; returns the stage path."""
        stage = self.base / name
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(stage),
                         "--lane", lane, "--kernel", kernel, "--bin-dir", str(self.bins),
                         "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(self.candidate),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        run_id = json.loads((stage / "contract.json").read_text())["run_id"]

        def write(name, text):
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

        def log(name, text, process, rc):
            write(name, text + f"{process}_exit={rc}\nmatrix_run={run_id}\n")

        write("uname.txt", uname + "\n")
        log("version.log", "p11scope 0.4.0\n", "version", 0)
        log("doctor.log", "capability tier: T4\nuprobe-multi attach (own libc) .... ok self-link attached and detached\n", "doctor", 0)
        log("qual.log", "SUMMARY pass=10 fail=0 nonqualifying=3\n", "qual", 2)
        write("cells/results.jsonl", "".join(
            json.dumps({"cell": name, "pass": qualification != "nonqualifying",
                        "detail": "controlled assertion", "qualification": qualification}) + "\n"
            for name, qualification in PUBLIC.items()))
        log("inv-native.log", "qualified owned inventory\n", "inv_native", 0)
        log("inv-scan.log", "valid scan plumbing, nonqualifying\n", "inv_scan", 2)
        log("pidflt.log", f"running 1 test\ntest {PID_TEST} ... ok\nPIDFLT_PROBE own=2 other=0 proves=true\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", "pidflt", 0)
        write("run/results.txt", f"# selectors: {LIB_A} {LIB_B}\nPASS {LIB_A} rc=0 seconds=1 :: test result: ok. 1 passed\nPASS {LIB_B} rc=0 seconds=1 :: test result: ok. 1 passed\nSUMMARY pass=2 fail=0 skipped=0\n")
        for name in (LIB_A, LIB_B):
            write("run/logs/" + name.split("::")[-1] + ".log", f"running 1 test\ntest {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        log("priv.log", "SUMMARY pass=2 fail=0 skipped=0\n", "priv", 0)
        for scope, mechanism, scope_filter in (("pid", "uprobe-multi", "kernel-pid+bpf"), ("sys", "uprobe-multi", None)):
            write("backend/inv-" + scope + ".json", json.dumps({"observation": {"attach": {
                "mechanism": mechanism, "scope_filter": scope_filter, "fallback": None}}}))
            log("backend/inv-" + scope + ".stderr", "", "inv_" + scope, 0)
        sealed = command(sys.executable, "-I", str(CHECKER), "--seal", str(stage),
                         "--contract", str(stage / "contract.json"), "--guest-exit", "0")
        self.assertEqual(sealed.returncode, 0, sealed.stdout + sealed.stderr)
        return stage

    def test_fedora_judge_accepts_fedora_uname(self):
        stage = self.judged_stage("fedora judged", "fedora-7.2.9", "fedora-7.2.9",
                                 "7.2.9-fedora-controlled")
        result = command(sys.executable, "-I", str(CHECKER), "--judge", str(stage),
                         "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict["lane"], "fedora-7.2.9")
        self.assertEqual(verdict["qualification"], "nonqualifying")

    def test_guest_judge_still_refuses_wrong_uname(self):
        stage = self.judged_stage("guest judged", "6.1.188", str(self.kernel),
                                 "7.2.9-fedora-controlled")
        result = command(sys.executable, "-I", str(CHECKER), "--judge", str(stage),
                         "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("wrong executed kernel osrelease", result.stdout)

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

    def guest_disk_fixture(self):
        # Synthetic regular input only: no filesystem is created or mounted.
        image = self.base / "guest-work.raw"
        image.write_bytes(b"controlled preformatted disk input")
        tools = self.base / "disk-tools"; tools.mkdir()
        uuid = "12345678-1234-4234-9234-123456789abc"
        scripts = {
            "blkid": "import os,sys\nprint('TYPE='+os.environ.get('CONTROL_DISK_TYPE','ext4'))\nprint('UUID='+os.environ.get('CONTROL_DISK_UUID','" + uuid + "'))\nif os.environ.get('CONTROL_PARTITION'): print('PTTYPE=gpt')\nsys.exit(int(os.environ.get('CONTROL_PROBE_EXIT','0')))\n",
            "losetup": "import json,os\nprint(json.dumps({'loopdevices':[{'name':'/dev/loop0'}] if os.environ.get('CONTROL_HOST_LOOP') else []}))\n",
            "findmnt": "import os,sys\nassert '--source' in sys.argv\nif os.environ.get('CONTROL_HOST_MOUNT'): print(sys.argv[-1]);sys.exit(0)\nsys.exit(1)\n",
            "vng": "import json,os,sys\nopen(os.environ['CONTROL_VNG_LOG'],'w').write(json.dumps(sys.argv[1:]))\nsys.exit(int(os.environ.get('CONTROL_VNG_EXIT','0')))\n",
        }
        for name, body in scripts.items():
            path = tools / name; path.write_text("#!/usr/bin/python3\n" + body); path.chmod(0o755)
        for name in ("mise", "cargo", "mount", "umount", "sudo"):
            path = tools / name
            path.write_text("#!/bin/sh\nprintf '%s\\n' invoked >> \"$CONTROL_FORBIDDEN\"\nexit 89\n")
            path.chmod(0o755)
        env = os.environ.copy()
        env.update(PATH=str(tools) + ":" + env["PATH"], CONTROL_VNG_LOG=str(self.base / "vng-argv.json"),
                   CONTROL_FORBIDDEN=str(self.base / "forbidden-command"))
        return image, uuid, env

    def prepare_disk_stage(self, image, uuid, env):
        stage = self.base / "disk-stage"
        result = subprocess.run([sys.executable, "-I", str(CHECKER), "--prepare", str(stage),
            "--lane", "6.1.188", "--kernel", str(self.kernel), "--guest-disk", str(image),
            "--guest-disk-uuid", uuid, "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
            "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
            "--candidate-receipt", str(self.candidate), "--lib-test", LIB_A, "--lib-test", LIB_B],
            cwd=ROOT, text=True, capture_output=True, env=env, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return stage

    def test_outer_guest_disk_prerequisites_precede_build_and_stage(self):
        image, uuid, env = self.guest_disk_fixture()
        stage, out = self.base / "new-stage", self.base / "new-out"
        args = [str(RUNNER), "--rev", "HEAD", "--kernels", "6.6", "--stage-base", str(stage),
                "--out-base", str(out), "--guest-disk", str(image), "--guest-disk-uuid", uuid]
        healthy = subprocess.run([*args, "--dry-run"], cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
        for case in ("missing", "directory", "symlink", "writable", "uuid", "type", "partition", "probe", "loop", "mounted", "unsafe", "unpaired", "uuid_only", "host"):
            with self.subTest(case=case):
                current, selected = env.copy(), args.copy()
                path = image
                if case == "missing": path = self.base / "absent.raw"
                elif case == "directory": path = self.base
                elif case == "symlink":
                    path = self.base / "disk-alias.raw"; path.symlink_to(image)
                elif case == "writable": image.chmod(0o666)
                elif case == "uuid": current["CONTROL_DISK_UUID"] = "87654321-1234-4234-9234-123456789abc"
                elif case == "type": current["CONTROL_DISK_TYPE"] = "xfs"
                elif case == "partition": current["CONTROL_PARTITION"] = "1"
                elif case == "probe": current["CONTROL_PROBE_EXIT"] = "2"
                elif case == "loop": current["CONTROL_HOST_LOOP"] = "1"
                elif case == "mounted": current["CONTROL_HOST_MOUNT"] = "1"
                elif case == "unsafe": path = self.base / "unsafe$(touch-forbidden).raw"
                elif case == "unpaired": selected = selected[:-2]
                elif case == "uuid_only": selected = selected[:-4] + ["--guest-disk-uuid", uuid]
                elif case == "host": selected[selected.index("--kernels") + 1] = "host"
                if "--guest-disk" in selected: selected[selected.index("--guest-disk") + 1] = str(path)
                result = subprocess.run(selected, cwd=ROOT, env=current, text=True, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("guest disk", result.stdout + result.stderr)
                self.assertFalse(stage.exists()); self.assertFalse(out.exists())
                self.assertFalse(Path(env["CONTROL_FORBIDDEN"]).exists())
                image.chmod(0o644)

    def test_guest_disk_rejects_unsafe_paths_and_untrusted_ancestors(self):
        image, uuid, env = self.guest_disk_fixture()
        for name in ("a b", "a'b", 'a"b', "a$b", "a`b", "a*b", "a?b", "a[b", "a;b", "a&b", "a|b", "a=b", "a,b", "a\\b", "a\nb"):
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, "-I", str(CHECKER), "--check-guest-disk", "--guest-disk",
                                         str(self.base / name), "--guest-disk-uuid", uuid],
                                        cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("unsafe guest disk path", result.stdout)
        parent = self.base / "untrusted-parent"; parent.mkdir(); parent.chmod(0o777)
        moved = parent / image.name; image.replace(moved)
        result = subprocess.run([sys.executable, "-I", str(CHECKER), "--check-guest-disk", "--guest-disk",
                                 str(moved), "--guest-disk-uuid", uuid],
                                cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("untrusted guest disk", result.stdout)

    def test_guest_disk_binding_rechecked_before_bound_nonroot_launch(self):
        image, uuid, env = self.guest_disk_fixture()
        stage = self.prepare_disk_stage(image, uuid, env)
        contract = json.loads((stage / "contract.json").read_text())
        info = image.stat()
        self.assertEqual(contract["guest_disk"], {"path": str(image), "uuid": uuid, "fstype": "ext4",
                         "device": info.st_dev, "inode": info.st_ino, "size": info.st_size})
        args = [sys.executable, "-I", str(CHECKER), "--launch-guest", str(stage),
                "--contract", str(stage / "contract.json"), "--kernel", str(self.kernel)]
        # Filesystem writes change image contents, not the bound file identity.
        image.write_bytes(b"x" * info.st_size)
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        argv = json.loads(Path(env["CONTROL_VNG_LOG"]).read_text())
        self.assertEqual(argv[argv.index("--user") + 1], pwd.getpwuid(os.getuid()).pw_name)
        self.assertEqual(argv[argv.index("--disk") + 1], str(image))
        execution = argv[argv.index("--exec") + 1]
        self.assertTrue(execution.startswith("sudo -n "), execution)
        self.assertIn("--run-guest-inner", execution)
        Path(env["CONTROL_VNG_LOG"]).unlink()
        replacement = self.base / "replacement.raw"; replacement.write_bytes(image.read_bytes()); replacement.replace(image)
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(Path(env["CONTROL_VNG_LOG"]).exists())

    def test_mixed_matrix_disk_options_never_change_host_dispatch(self):
        image, uuid, env = self.guest_disk_fixture()
        names = list(CHECKER_MOD["DEFAULT_LIB_TESTS"] + CHECKER_MOD["BREADTH"])
        self.listing.write_text("".join(name + ": test\n" for name in names))
        self.curation.write_text(f"default ({len(names)})\n" + "\n".join(names) +
                                f"\nlong (0)\nskipped (0)\nverify: curation matches the binary ({len(names)} tests)\n")
        stages, outputs = self.base / "mixed-stages", self.base / "mixed-outputs"
        stages.mkdir(); outputs.mkdir()
        for source, name in ((self.listing, "candidate-ignored.txt"), (self.curation, "curation.txt"), (self.bm_list, "bpfmulti-list.txt")):
            shutil.copyfile(source, stages / name)
        tools = Path(env["PATH"].split(":", 1)[0])
        (tools / "flock").write_text("#!/usr/bin/python3\nimport subprocess,sys\nsys.exit(subprocess.run(sys.argv[2:]).returncode)\n")
        (tools / "flock").chmod(0o755)
        (tools / "sudo").write_text("#!/usr/bin/python3\nimport json,os,sys\na=sys.argv[1:]\nif a[:2]==['-n','chown']: sys.exit(0)\nopen(os.environ['CONTROL_HOST_ARGS'],'w').write(json.dumps(a))\nsys.exit(1)\n")
        env.update(CONTROL_VNG_EXIT="1", CONTROL_HOST_ARGS=str(self.base / "host-argv.json"))
        # Execute the production dispatch function with real contract preparation;
        # external launchers stop before any guest or privileged inner executes.
        body = RUNNER.read_text().split("run_one() {", 1)[1].split("\noverall=", 1)[0]
        import shlex
        words = {"CHECKER": CHECKER, "REPO": ROOT, "STAGE_REV": stages, "OUT_REV": outputs,
                 "BIN_OUT": self.bins, "CANDIDATE_RECEIPT": self.candidate, "LOCK": self.base / "unused-lock",
                 "GUEST_WORK_ROOT": self.base / "unused-work", "SUMMARY": outputs / "summary.md"}
        script = "set -uo pipefail\n" + "".join(key + "=" + shlex.quote(str(value)) + "\n" for key, value in words.items())
        script += "TIMEOUT=10\nOBJECT_ARGS=()\nGUEST_DISK_ARGS=(--guest-disk " + shlex.quote(str(image)) + " --guest-disk-uuid " + uuid + ")\n"
        script += "tag_for_kernel() { basename \"$1\" | sed 's/vmlinuz-//'; }\nwait_quiet() { :; }\n"
        script += "write_inner() { " + shlex.quote(str(RUNNER)) + " --write-inner-stage \"$1\" --contract \"$1/contract.json\"; }\n"
        script += "run_one() {" + body + "\nrun_one " + shlex.quote(str(self.kernel)) + " || :\nrun_one host || :\n"
        result = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        guest = json.loads((stages / "6.1.188/contract.json").read_text())
        host = json.loads((stages / "host/contract.json").read_text())
        self.assertEqual(guest["guest_disk"]["uuid"], uuid)
        self.assertIsNone(host["guest_disk"])
        host_argv = json.loads(Path(env["CONTROL_HOST_ARGS"]).read_text())
        self.assertEqual(host_argv, ["-n", "env", "bash", str(stages / "host/inner.sh")])
        argv = json.loads(Path(env["CONTROL_VNG_LOG"]).read_text())
        self.assertEqual(argv[argv.index("--disk") + 1], str(image))

    def controlled_guest_disk(self, stage, root, case="healthy", mounted=False):
        contract = json.loads((stage / "contract.json").read_text())
        contract["guest_work_root"] = str(root)
        if case == "protected": contract["guest_work_root"] = "/etc"
        elif case == "overlap": contract["guest_work_root"] = str(stage / "artifacts")
        elif case == "symlink":
            link = self.base / "mount-alias"; link.symlink_to(root); contract["guest_work_root"] = str(link)
        (stage / "contract.json").write_text(json.dumps(contract))
        output = stage / "child-output"
        output.unlink(missing_ok=True)
        (stage / "inner.sh").write_text("#!/bin/bash\nprintf 'completed outputs' > '" + str(output) + "'\nexit 7\n")
        root.mkdir(exist_ok=True)
        if case == "nonempty": (root / "foreign").write_text("unrelated data")
        if case == "untrusted": root.chmod(0o777)
        events = []
        state = {"mounted": mounted}
        real_run, real_stat, real_os_open = subprocess.run, Path.stat, os.open
        def device_stat(path, *args, **kwargs):
            if str(path) in ("/dev/c2disk", "/dev/c2other"):
                return mock.Mock(st_mode=stat.S_IFBLK | 0o600,
                                 st_rdev=os.makedev(252, 0 if str(path) == "/dev/c2disk" else 1))
            info = real_stat(path, *args, **kwargs)
            if path == root and state["mounted"]:
                fields = list(info); fields[2] = os.makedev(252, 1 if case == "device_mismatch" else 0)
                return os.stat_result(fields)
            return info
        def external(argv, **kwargs):
            argv = list(map(str, argv))
            def done(rc=0, stdout="", stderr=""): return subprocess.CompletedProcess(argv, rc, stdout, stderr)
            if argv[0] == "uname": return done(stdout="foreign\n" if case == "kernel" else "6.1.188\n")
            if argv[0] == "lsblk":
                rows = [{"path": "/dev/c2disk", "type": "disk", "maj:min": "252:0"}]
                if case == "missing": rows = []
                elif case in ("duplicate", "probe_error", "empty_other", "other_uuid", "fd0_enxio", "fd0_enomedium",
                              "selected_probe_error"):
                    rows += [{"path": "/dev/c2other", "type": "disk", "maj:min": "252:1"}]
                return done(stdout=json.dumps({"blockdevices": rows}))
            if argv[0] == "blkid":
                if case == "probe_error" and argv[-1] == "/dev/c2other": return done(1)
                if case == "empty_other" and argv[-1] == "/dev/c2other": return done(2)
                if case in ("fd0_enxio", "fd0_enomedium") and argv[-1] == "/dev/c2other":
                    detail = "No such device or address" if case == "fd0_enxio" else "No medium found"
                    return done(2, "", "blkid: error: /dev/c2other: " + detail + "\n")
                if case == "selected_probe_error" and argv[-1] == "/dev/c2disk": return done(1)
                if case == "selected_unreadable" and argv[-1] == "/dev/c2disk":
                    return done(2, "", "blkid: error: /dev/c2disk: No such device or address\n")
                other_uuid = case == "uuid" or (case == "other_uuid" and argv[-1] == "/dev/c2other")
                uuid = "87654321-1234-4234-9234-123456789abc" if other_uuid else contract["guest_disk"]["uuid"]
                return done(stdout="TYPE=" + ("xfs" if case == "type" else "ext4") + "\nUUID=" + uuid + "\n")
            if argv[0] == "findmnt":
                if "-n" in argv: return done(stdout="ext4\n")
                target = argv[-1]
                if target == "/":
                    row = {"target": "/", "source": "/dev/root", "fstype": "btrfs" if case == "not_guest" else "9p", "maj:min": "0:1"}
                elif target == "/var/tmp":
                    row = {"target": "/var/tmp", "source": "tmpfs", "fstype": "tmpfs", "maj:min": "0:2"}
                elif not state["mounted"]: return done(1)
                else:
                    row = {"target": target, "source": "/dev/c2other" if case in ("source", "new_source") else "/dev/c2disk",
                           "fstype": "xfs" if case == "mounted_type" else "ext4", "maj:min": "252:1" if case == "major" else "252:0"}
                return done(stdout=json.dumps({"filesystems": [row]}))
            if argv[0] == "mount":
                events.append("mount")
                if case == "mount_failure": return done(1)
                self.assertIn("/dev/c2disk", argv); self.assertEqual(argv[-1], str(root))
                state["mounted"] = True; return done()
            if argv[0] == "umount":
                self.assertEqual(argv[-1], str(root))
                events.append("umount")
                if case == "unmount_failure": return done(1)
                state["mounted"] = False; return done()
            if argv[:1] == ["bash"]:
                events.append("child")
                result = real_run(argv, **kwargs)
                self.assertEqual(output.read_text(), "completed outputs")
                events.append("outputs_complete")
                return result
            self.fail("unexpected external command: " + repr(argv))
        # Controlled block-device readability: only the named cases hold an
        # unreadable device; every other /dev/c2* open behaves as on a host
        # without those nodes, and all other paths use the real opener.
        unreadable_opens = {("fd0_enxio", "/dev/c2other"): errno.ENXIO,
                            ("fd0_enomedium", "/dev/c2other"): errno.ENOMEDIUM,
                            ("selected_unreadable", "/dev/c2disk"): errno.ENXIO}
        def controlled_open(path, *args, **kwargs):
            number = unreadable_opens.get((case, str(path)))
            if number is not None:
                raise OSError(number, os.strerror(number))
            if str(path) in ("/dev/c2disk", "/dev/c2other"):
                if (case, str(path)) == ("selected_probe_error", "/dev/c2disk"):
                    return real_os_open(os.devnull, os.O_RDONLY)  # opens fine: the probe error is genuine
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path))
            return real_os_open(path, *args, **kwargs)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(Path, "stat", device_stat), mock.patch.object(subprocess, "run", side_effect=external), \
                mock.patch.object(os, "open", controlled_open), \
                mock.patch.object(os, "geteuid", return_value=1000 if case == "nonroot" else 0), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = CHECKER_MOD["main"](["--run-guest-inner", str(stage), "--contract", str(stage / "contract.json")])
            except SystemExit as error:
                rc = error.code
        return rc, events, output.exists(), stdout.getvalue() + stderr.getvalue()

    def test_guest_disk_mount_lifetime_follows_child_and_output_completion(self):
        image, uuid, env = self.guest_disk_fixture()
        stage = self.prepare_disk_stage(image, uuid, env)
        mounts = tempfile.TemporaryDirectory(prefix="matrix-guest-mount-", dir="/var/tmp")
        self.addCleanup(mounts.cleanup)
        root = Path(mounts.name) / "disk-mount"
        rc, events, output, detail = self.controlled_guest_disk(stage, root)
        self.assertEqual(rc, 7, detail)
        self.assertTrue(output)
        self.assertEqual(events, ["mount", "child", "outputs_complete", "umount"])
        for case in ("empty_other", "other_uuid"):
            with self.subTest(case=case):
                rc, events, output, detail = self.controlled_guest_disk(stage, root, case)
                self.assertEqual(rc, 7, detail)
                self.assertTrue(output)
                self.assertEqual(events, ["mount", "child", "outputs_complete", "umount"])
        rc, events, output, detail = self.controlled_guest_disk(stage, root, mounted=True)
        self.assertEqual(rc, 7, detail)
        self.assertTrue(output)
        self.assertEqual(events, ["child", "outputs_complete"])
        rc, events, output, detail = self.controlled_guest_disk(stage, root, "unmount_failure")
        self.assertEqual(rc, 1, detail)
        self.assertTrue(output)
        self.assertEqual(events, ["mount", "child", "outputs_complete", "umount"])

    def test_guest_disk_refuses_wrong_devices_and_mount_targets_before_inner(self):
        image, uuid, env = self.guest_disk_fixture()
        stage = self.prepare_disk_stage(image, uuid, env)
        mounts = tempfile.TemporaryDirectory(prefix="matrix-guest-mount-", dir="/var/tmp")
        self.addCleanup(mounts.cleanup)
        for index, case in enumerate(("missing", "duplicate", "probe_error", "uuid", "type", "source", "new_source", "major", "device_mismatch",
                                     "mounted_type", "mount_failure", "protected", "overlap", "symlink", "nonempty", "untrusted",
                                     "not_guest", "nonroot", "kernel")):
            with self.subTest(case=case):
                rc, events, output, detail = self.controlled_guest_disk(stage, Path(mounts.name) / ("mount-" + str(index)), case,
                                                                      mounted=case in ("source", "major", "device_mismatch", "uuid", "type", "duplicate", "mounted_type"))
                self.assertEqual(rc, 1, detail)
                self.assertFalse(output, detail)
                self.assertNotIn("child", events)
                self.assertNotIn("umount", events, "must not unmount an unrelated or preexisting mount")

    def test_guest_disk_skips_unreadable_nonselected_device(self):
        # Phantom-floppy twin: /dev/c2other fails blkid with the empty-drive
        # open error while /dev/c2disk carries the expected UUID; the mount
        # lifetime must proceed on the UUID carrier.
        image, uuid, env = self.guest_disk_fixture()
        stage = self.prepare_disk_stage(image, uuid, env)
        mounts = tempfile.TemporaryDirectory(prefix="matrix-guest-mount-", dir="/var/tmp")
        self.addCleanup(mounts.cleanup)
        root = Path(mounts.name) / "disk-mount"
        for case in ("fd0_enxio", "fd0_enomedium"):
            with self.subTest(case=case):
                rc, events, output, detail = self.controlled_guest_disk(stage, root, case)
                self.assertEqual(rc, 7, detail)
                self.assertTrue(output)
                self.assertEqual(events, ["mount", "child", "outputs_complete", "umount"])

    def test_guest_disk_refuses_selected_device_probe_errors(self):
        # A probe failure on the UUID-carrying candidate still refuses, even
        # when another device probes cleanly (selected_probe_error), and an
        # unreadable sole candidate refuses without selecting anything.
        image, uuid, env = self.guest_disk_fixture()
        stage = self.prepare_disk_stage(image, uuid, env)
        mounts = tempfile.TemporaryDirectory(prefix="matrix-guest-mount-", dir="/var/tmp")
        self.addCleanup(mounts.cleanup)
        for index, case in enumerate(("selected_probe_error", "selected_unreadable")):
            with self.subTest(case=case):
                rc, events, output, detail = self.controlled_guest_disk(stage, Path(mounts.name) / ("mount-" + str(index)), case)
                self.assertEqual(rc, 1, detail)
                self.assertFalse(output, detail)
                self.assertNotIn("mount", events)
                self.assertNotIn("child", events)
                self.assertNotIn("umount", events)
        rc, _, _, detail = self.controlled_guest_disk(stage, Path(mounts.name) / "mount-strict", "selected_probe_error")
        self.assertEqual(rc, 1, detail)
        self.assertNotIn("skipped unreadable", detail)

    def test_selected_guest_device_records_skipped_unreadable_devices(self):
        uuid = "12345678-1234-4234-9234-123456789abc"
        healthy = "TYPE=ext4\nUUID=" + uuid + "\n"
        foreign = "TYPE=ext4\nUUID=87654321-1234-4234-9234-123456789abc\n"
        rows = [{"path": "/dev/c2disk", "type": "disk", "maj:min": "252:0"},
                {"path": "/dev/c2other", "type": "disk", "maj:min": "252:1"}]
        real_stat, real_os_open = Path.stat, os.open
        def select(blkid_by_path, unreadable=()):
            def external(argv, **kwargs):
                argv = list(map(str, argv))
                if argv[0] == "lsblk":
                    return subprocess.CompletedProcess(argv, 0, json.dumps({"blockdevices": rows}), "")
                if argv[0] == "blkid":
                    rc, stdout, stderr = blkid_by_path[argv[-1]]
                    return subprocess.CompletedProcess(argv, rc, stdout, stderr)
                self.fail("unexpected external command: " + repr(argv))
            def device_stat(path, *args, **kwargs):
                for row in rows:
                    if str(path) == row["path"]:
                        major, minor = row["maj:min"].split(":")
                        return mock.Mock(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(int(major), int(minor)))
                return real_stat(path, *args, **kwargs)
            def controlled_open(path, *args, **kwargs):
                if str(path) in unreadable:
                    raise OSError(errno.ENXIO, os.strerror(errno.ENXIO))
                return real_os_open(path, *args, **kwargs)
            with mock.patch.object(subprocess, "run", side_effect=external), \
                    mock.patch.object(Path, "stat", device_stat), \
                    mock.patch.object(os, "open", controlled_open):
                return CHECKER_MOD["selected_guest_device"]({"uuid": uuid})
        device = select({"/dev/c2disk": (0, healthy, ""),
                         "/dev/c2other": (2, "", "blkid: error: /dev/c2other: No such device or address\n")},
                        unreadable=("/dev/c2other",))
        self.assertEqual(device["path"], "/dev/c2disk")
        self.assertEqual(device["skipped_unreadable"], ["/dev/c2other"])
        device = select({"/dev/c2disk": (0, healthy, ""), "/dev/c2other": (0, foreign, "")})
        self.assertEqual(device["skipped_unreadable"], [])
        with self.assertRaises(CHECKER_MOD["Invalid"]) as refused:
            select({"/dev/c2disk": (2, "", "blkid: error: /dev/c2disk: No such device or address\n"),
                    "/dev/c2other": (0, foreign, "")}, unreadable=("/dev/c2disk",))
        self.assertIn("skipped unreadable device(s): /dev/c2disk", str(refused.exception))
        with self.assertRaises(CHECKER_MOD["Invalid"]) as refused:
            select({"/dev/c2disk": (0, healthy, ""), "/dev/c2other": (0, healthy, "")})
        self.assertNotIn("skipped unreadable", str(refused.exception))

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

    def test_outer_plan_forwards_exact_object_modes_abis_and_input_paths(self):
        inputs = []
        for mode in ("full", "p0"):
            for bits in (32, 64):
                directory = self.base / f"selected {mode} {bits}"
                inputs.extend(("--object-input", mode, str(bits), str(directory)))
        result = command(str(RUNNER), "--plan", "--rev", "HEAD", "--kernels", "host", *inputs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value, _ = json.JSONDecoder().raw_decode(result.stdout[result.stdout.index("{"):])
        cells = value["execution"]["object_cells"]
        self.assertEqual([(cell["mode"], cell["target_bits"]) for cell in cells],
                         [(mode, bits) for mode in ("full", "p0") for bits in (32, 64)])
        self.assertEqual([ident for cell in cells for ident in cell["required_ids"]],
                         [f"object:{mode}:{bits}:{role}" for mode in ("full", "p0")
                          for bits in (32, 64) for role in ("complete", "blocked")])
        for offset in range(0, len(inputs), 4): self.assertIn(inputs[offset + 3], result.stdout)
        self.assertFalse(any(self.base.glob("selected *")), "dry-run created input directories")
        for extra in (("--object-input", "full", "64", "relative"),
                      ("--object-input", "unknown", "64", str(self.base / "absent")),
                      ("--object-input", "p0", "16", str(self.base / "absent")), tuple(inputs[:4])):
            with self.subTest(arguments=extra):
                failed = command(str(RUNNER), "--plan", "--rev", "HEAD", "--kernels", "host", *inputs, *extra)
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)

    def object_judgment_fixture(self, cells=(("full", 32), ("full", 64), ("p0", 32), ("p0", 64))):
        # Parser controls only. Actual runner/checker execution is covered by
        # the generated-shell controls; these small snapshots never claim BPF.
        original_stage, original_id = self.stage, self.run_id
        stage = self.base / "object judgment"
        inputs = [(mode, bits, self.canary_inputs(mode, bits)[0]) for mode, bits in cells]
        prepared = self.prepare_object_inputs(stage, inputs)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        self.stage, self.contract = stage, stage / "contract.json"
        self.run_id = json.loads(self.contract.read_text())["run_id"]
        for name in CHECKER_MOD["evidence_paths"](original_stage, json.loads((original_stage / "contract.json").read_text())):
            source = original_stage / name
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes().replace(original_id.encode(), self.run_id.encode()))
        (stage / "run/logs" / (LIB_B.split("::")[-1] + ".log")).unlink()
        self.write("run/results.txt", f"PASS {LIB_A} rc=0 seconds=1 :: test result: ok. 1 passed\n")
        fixtures = runpy.run_path(str(ROOT / "tests/python/test_canary_evidence.py"))
        pilot = fixtures["FinalScannerSurfaceTests"]()
        for mode, bits in cells:
            pilot.object_pilot_fixture.__func__.__globals__["TARGET_BITS"] = bits
            subject = fixtures["load_subject"](bits)
            work = self.base / f"original object {mode} {bits}"
            work.mkdir()
            pilot.object_pilot_fixture(subject, work)
            subject.assert_object_pilot(work, bits)
            lane = "object-ia32" if bits == 32 else "object-lp64"
            names = {"matrix-manifest.json", "privacy-manifest.json"}
            for name in names: (work / name).write_text("{}\n")
            rows = []
            for role, current in (("complete", lane), ("blocked", lane + "-blocked")):
                (work / (current + ".ready")).write_text(json.dumps({"pid": 7001}) + "\n")
                manifest_name = f"mapdump_manifest_{current}.json"
                manifest = json.loads((work / manifest_name).read_text())
                receipt = manifest[0]["snapshot"]["receipt"]
                names.update((manifest_name, Path(receipt).relative_to(work).as_posix(), current + ".ready"))
                names.update(path.relative_to(work).as_posix() for path in
                    subject.final_lane_artifacts(work, current,
                        subject.assert_exact_owned_map_inventory(work, current, subject.SAFE_MAPS)))
                rows.append({"id": f"object:{mode}:{bits}:{role}", "lane": current,
                             "manifest": "evidence/" + manifest_name,
                             "receipt": "evidence/" + Path(receipt).relative_to(work).as_posix()})
            cell = stage / f"object/{mode}-{bits}"
            cell.mkdir(parents=True)
            for name in sorted(names):
                destination = cell / "evidence" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(work / name, destination)
            (cell / "run.log").write_text("object_runner_exit=0\nobject_semantic_exit=0\nobject_final_exit=0\n"
                                          f"matrix_run={self.run_id}\n")
            (cell / "result.json").write_text(json.dumps({"run_id": self.run_id, "mode": mode,
                "target_bits": bits, "original_work_root": str(work), "runner_exit": 0,
                "rows": rows, "evidence_files": ["evidence/" + name for name in sorted(names)]}) + "\n")
        self.seal()
        return stage

    def test_object_pair_judgment_is_exact_and_fail_closed(self):
        self.object_judgment_fixture()
        healthy = self.judge()
        self.assertEqual(healthy.returncode, 2, healthy.stdout + healthy.stderr)
        wanted = {f"object:{mode}:{bits}:{role}" for mode in ("full", "p0")
                  for bits in (32, 64) for role in ("complete", "blocked")}
        rows = [row for row in json.loads(healthy.stdout)["rows"] if row["id"].startswith("object:")]
        self.assertEqual({row["id"] for row in rows}, wanted)
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row["qualification"] == "positive-coverage" for row in rows))
        original = self.stage
        cases = ("missing", "duplicate", "other_tuple", "wrong_mode", "wrong_width", "stale_run", "failed_runner",
                 "extra_field", "missing_manifest", "missing_receipt", "missing_surface", "changed_surface",
                 "extra_file", "escaping_reference", "missing_log", "failed_semantic", "failed_final", "inner_failure")
        for case in cases:
            with self.subTest(case=case):
                stage = self.base / ("mutant-" + case)
                shutil.copytree(original, stage)
                self.stage, self.contract = stage, stage / "contract.json"
                cell = stage / "object/full-32"
                path = cell / "result.json"
                result = json.loads(path.read_text())
                if case == "missing": result["rows"].pop()
                elif case == "duplicate": result["rows"][1] = result["rows"][0]
                elif case == "other_tuple": result["rows"][1]["id"] = "object:full:64:blocked"
                elif case == "wrong_mode": result["mode"] = "p0"
                elif case == "wrong_width": result["target_bits"] = 64
                elif case == "stale_run": result["run_id"] = "0" * 32
                elif case == "failed_runner": result["runner_exit"] = 2
                elif case == "extra_field": result["qualified"] = True
                elif case in ("missing_manifest", "missing_receipt"):
                    (cell / result["rows"][0]["manifest" if case == "missing_manifest" else "receipt"]).unlink()
                elif case in ("missing_surface", "changed_surface"):
                    target = cell / next(name for name in result["evidence_files"] if name.endswith(".bin"))
                    if case == "missing_surface": target.unlink()
                    else: target.write_bytes(target.read_bytes() + b"changed")
                elif case == "extra_file": (cell / "evidence/unlisted").write_text("not named by any manifest")
                elif case == "escaping_reference":
                    manifest = cell / result["rows"][0]["manifest"]
                    values = json.loads(manifest.read_text())
                    next(item for item in values if "file" in item)["file"] = str(self.base / "outside")
                    manifest.write_text(json.dumps(values))
                elif case == "missing_log": (cell / "run.log").unlink()
                elif case in ("failed_semantic", "failed_final"):
                    log = cell / "run.log"
                    log.write_text(log.read_text().replace("object_" + case.removeprefix("failed_") + "_exit=0", "object_" + case.removeprefix("failed_") + "_exit=1"))
                path.write_text(json.dumps(result))
                self.seal(guest_exit=124 if case == "inner_failure" else 0)
                self.reject()
        self.stage, self.contract = original, original / "contract.json"

    def test_object_pilot_keeps_smoke_nonqualifying(self):
        self.object_judgment_fixture((("full", 64),))
        result = self.judge()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value["full_stage5_ready"])
        self.assertEqual(value["qualification"], "nonqualifying")
        self.assertEqual([row["id"] for row in value["rows"] if row["id"].startswith("object:")],
                         ["object:full:64:complete", "object:full:64:blocked"])

    def test_object_judgment_binds_original_work_root_without_reopening_guest_paths(self):
        stage = self.object_judgment_fixture((("full", 64),))
        cell = stage / "object/full-64"
        path = cell / "result.json"
        original_result = json.loads(path.read_text())
        original = Path(original_result["original_work_root"])
        manifests = {row["manifest"]: json.loads((cell / row["manifest"]).read_text())
                     for row in original_result["rows"]}
        shutil.rmtree(original)
        bound = self.base / "absent guest disk"
        self.assertFalse(bound.exists())
        contract = json.loads(self.contract.read_text())
        contract["guest_work_root"] = str(bound)
        self.contract.write_text(json.dumps(contract))

        def returned_root(root):
            # Parser-only guest provenance: references remain self-consistent,
            # but neither the bound base nor these paths exist on the host.
            result = dict(original_result, original_work_root=str(root))
            path.write_text(json.dumps(result))
            for name, items in manifests.items():
                values = json.loads(json.dumps(items))
                for item in values:
                    if "file" in item:
                        item["file"] = str(root / Path(item["file"]).relative_to(original))
                    item["snapshot"]["receipt"] = str(root / Path(item["snapshot"]["receipt"]).relative_to(original))
                (cell / name).write_text(json.dumps(values))
            self.seal()
            return self.judge()

        for root in (bound / "task", bound / "nested/task"):
            with self.subTest(healthy_root=root):
                healthy = returned_root(root)
                self.assertEqual(healthy.returncode, 2, healthy.stdout + healthy.stderr)
                rows = [row["id"] for row in json.loads(healthy.stdout)["rows"] if row["id"].startswith("object:")]
                self.assertEqual(rows, ["object:full:64:complete", "object:full:64:blocked"])
        for root in (bound, self.base / "outside task", Path(str(bound) + "-sibling") / "task",
                     bound / "../outside task"):
            with self.subTest(foreign_root=root):
                refused = returned_root(root)
                self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertFalse(bound.exists(), "host judgment reopened or created the guest base")

    def retained_object_inputs(self, cells=(("full", 64),), native_inputs=None):
        repo = self.base / "original object source"
        names = set().union(*(set(CHECKER_MOD[key]) for key in
            ("SOURCE_FILES", "RUNTIME_SOURCES", "CANARY_SOURCE_FILES", "CANARY_RUNTIME_SOURCES", "CANARY_PRODUCER_SOURCES")))
        for name in names:
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        candidate = candidate_receipt(self.bins, self.base / "object-source-build.json", repo)
        arguments = []
        for mode, bits in cells:
            bundle, facts = self.canary_inputs(mode, bits)
            facts["source_root"] = str(repo)
            for step in facts["builds"]: step["cwd"] = str(repo)
            if native_inputs:
                for name in ("canary_workload", "matrix-provider.so", "privacy-provider.so", "p11scope-discover"):
                    shutil.copyfile(native_inputs / str(bits) / name, bundle / name)
                (bundle / "p11scope").write_bytes(Path("/bin/true").read_bytes() + (bundle / "default-ebpf").read_bytes())
                shutil.copyfile("/bin/true", bundle / "dump-task-storage")
                for name, item in facts["artifacts"].items():
                    item["sha256"] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
            (bundle / "canary-build.json").write_text(json.dumps(facts))
            arguments.extend(("--object-input", mode, str(bits), str(bundle)))
        stage = self.base / "retained object stage"
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--prepare", str(stage),
            "--lane", "host", "--kernel", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
            "--guest-work-root", str(self.base),
            "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(candidate),
            "--lib-test", LIB_A, *arguments)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return repo, stage

    def test_object_dispatch_uses_bound_snapshot_without_relaxing_rust_source_preflight(self):
        repo, stage = self.retained_object_inputs()
        module = runpy.run_path(str(stage / "artifacts/source/scripts" / CHECKER.name))
        contract_path = stage / "contract.json"
        repo.rename(self.base / "unavailable object source")
        self.assertFalse(repo.exists())
        with self.assertRaises((module["Invalid"], OSError)):
            module["verify_inputs"](stage, contract_path)
        # This private resolver is used only by the object dispatcher. Ordinary
        # launch, preparation and lib-fixture judgment stay source-root strict.
        value = module["_verify_object_inputs"](stage, contract_path)
        self.assertEqual(value["object_cells"][0]["required_ids"],
                         ["object:full:64:complete", "object:full:64:blocked"])
        original = json.loads(contract_path.read_text())
        snapshot = stage / "artifacts/canary-source/full-64/scripts/fixtures/canary_workload.c"
        before = snapshot.read_bytes()
        for case in ("missing", "changed", "foreign_rebound", "missing_binding", "build_cwd", "key_tuple"):
            with self.subTest(case=case):
                value = json.loads(json.dumps(original))
                facts_path = stage / "inputs/canary-build/full-64.json"
                facts_before = facts_path.read_bytes()
                if case == "missing": snapshot.unlink()
                elif case in ("changed", "foreign_rebound"):
                    snapshot.write_bytes(before + b"foreign snapshot")
                    if case == "foreign_rebound":
                        value["bindings"][snapshot.relative_to(stage).as_posix()] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                elif case == "missing_binding": value["bindings"].pop("artifacts/source/scripts/lane-lib-oracle-1.py")
                elif case in ("build_cwd", "key_tuple"):
                    facts = json.loads(facts_before)
                    if case == "build_cwd": facts["builds"][0]["cwd"] = str(self.base / "foreign root")
                    else: facts["capture_mode"] = "p0"
                    facts_path.write_text(json.dumps(facts))
                    value["bindings"][facts_path.relative_to(stage).as_posix()] = hashlib.sha256(facts_path.read_bytes()).hexdigest()
                contract_path.write_text(json.dumps(value))
                with self.assertRaises((module["Invalid"], OSError)):
                    module["_verify_object_inputs"](stage, contract_path)
                snapshot.write_bytes(before)
                facts_path.write_bytes(facts_before)
                contract_path.write_text(json.dumps(original))

    def test_generated_inner_binds_object_dispatch_after_strict_preflight(self):
        _, stage = self.retained_object_inputs()
        result = command(str(RUNNER), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inner = (stage / "inner.sh").read_text()
        dispatcher = stage / "object-inner.sh"
        self.assertTrue(dispatcher.is_file(), "generated object-only component is missing")
        text = dispatcher.read_text()
        self.assertIn('"$STAGE/artifacts/source/scripts/release-matrix-contract.py" --run-objects "$STAGE"', text)
        self.assertIn('--object-work-root "$1"', text)
        self.assertNotIn('--verify-inputs', text)
        self.assertLess(inner.index('--verify-inputs'), inner.index('bash "$STAGE/object-inner.sh" "$WORK/caller"'))
        self.assertLess(inner.index('bash "$STAGE/object-inner.sh"'), inner.index('--seal'))

    def test_generated_inner_copies_inventory_evidence_before_failure_gates(self):
        # A failed inventory lane must still leave its evidence in the stage:
        # the copy precedes the exit gate on both the native and scan lanes.
        _, stage = self.retained_object_inputs()
        result = command(str(RUNNER), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inner = (stage / "inner.sh").read_text()
        for base, gate in (("c8-native", "native_rc"), ("c8-scan", "scan_rc")):
            with self.subTest(base=base):
                copy = inner.index(f'--copy-tree native "$WORK/{base}" "$STAGE/{base}"')
                self.assertLess(copy, inner.index(f'[ "${gate}" = 0 ]'))

    def test_outer_runner_carries_attested_manifest_helper(self):
        text = RUNNER.read_text()
        build = text[text.index("build_bins() {"):
                     text.index("CANDIDATE_RECEIPT=$STAGE_REV/candidate-build.json")]
        loop = text[text.index("for b in p11scope"):text.index("LIBBIN=")]
        self.assertIn("-p p11scope-discover", build)
        self.assertIn('"$BIN_OUT/p11scope-discover"', build)
        self.assertIn("p11scope p11scope-lib p11scope-bpfmulti p11scope-discover", loop)
        self.assertIn('"$BIN_DIR/p11scope-discover"', loop)

    def test_invalid_outer_object_selection_refuses_before_build_or_stage(self):
        directory = str(self.base / "selected inputs")
        for arguments in (("unknown", "64", directory), ("full", "16", directory), ("p0", "64", "relative")):
            with self.subTest(arguments=arguments):
                result = command(str(RUNNER), "--rev", "HEAD", "--bin-dir", str(self.bins),
                    "--out-base", str(self.base / "must not create output"),
                    "--stage-base", str(self.base / "must not create stage"), "--kernels", "host",
                    "--object-input", *arguments)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("invalid object input selection", result.stdout)
                self.assertFalse((self.base / "must not create output").exists())
                self.assertFalse((self.base / "must not create stage").exists())

    def test_object_refusal_acquisition_is_exact_and_unknown_sudo_is_refused(self):
        source = self.base / "external probe source"
        scripts = source / "scripts"; scripts.mkdir(parents=True)
        marker = self.base / "uncontrolled acquisition executed"
        probe = scripts / "dump-owned-bpf-maps.py"
        probe.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\nraise SystemExit(77)\n")
        config_path = self.base / "external probe controls.json"
        value = {"events": str(self.base / "external probe events.jsonl"), "templates": str(self.base),
                 "source_root": str(source), "work_root": str(self.base / "caller probe work"), "failure": ""}
        config_path.write_text(json.dumps(value))
        sudo = self.base / "sudo"
        sudo.write_text("#!" + sys.executable + "\n" + OBJECT_EXTERNALS); sudo.chmod(0o755)
        env = os.environ.copy(); env["P11SCOPE_OBJECT_CONTROL"] = str(config_path)
        def run(*arguments):
            return subprocess.run([str(sudo), *arguments], cwd=source, env=env, text=True,
                                  capture_output=True, timeout=5)
        result = run("python3", "-I", "scripts/dump-owned-bpf-maps.py", "--refusal-probe")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("controlled refusal acquisition exit=0", result.stdout)
        self.assertNotIn("ENOTSUPP=524: OK", result.stdout)
        self.assertFalse(marker.exists(), "fixture executed the uncontrolled acquisition")
        value["failure"] = "refusal"; config_path.write_text(json.dumps(value))
        refused = run("-n", "python3", "-I", str(probe), "--refusal-probe")
        self.assertEqual(refused.returncode, 42, refused.stdout + refused.stderr)
        self.assertFalse(marker.exists())
        for arguments in (("/bin/true",), ("python3", "-I", str(probe), "--refusal-probe", "extra"),
                          ("python3", "-I", str(probe), "--unknown"),
                          ("chown", "0:0", str(self.base / "outside")),
                          ("python3", "-I", str(ROOT / "scripts/dump-owned-bpf-maps.py"), "--refusal-probe")):
            with self.subTest(arguments=arguments):
                result = run(*arguments)
                self.assertEqual(result.returncode, 94, result.stdout + result.stderr)
                self.assertIn("unknown external sudo operation", result.stderr)
        self.assertFalse(marker.exists())

    def test_object_inventory_adapter_binds_staged_checker_tuple_path_and_bytes(self):
        _, stage = self.retained_object_inputs()
        contract_path = stage / "contract.json"
        contract = json.loads(contract_path.read_text())
        source = stage / "artifacts/source"
        checker = source / "scripts/check-bpf-map-defs.py"
        payload = stage / "artifacts/canary/full-64/default-ebpf"
        original_payload = payload.read_bytes()
        controls = self.base / "inventory adapter"; controls.mkdir()
        config_path = controls / "control.json"
        value = {"events": str(controls / "events.jsonl"), "source_root": str(source), "stage": str(stage),
                 "failure": "", "inventory_inputs": [{"mode": "full", "target_bits": 64, "path": str(payload),
                     "sha256": contract["bindings"][payload.relative_to(stage).as_posix()]}]}
        config_path.write_text(json.dumps(value))
        wrapper = controls / "python3"
        wrapper.write_text("#!" + sys.executable + "\n" + OBJECT_EXTERNALS); wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update(P11SCOPE_OBJECT_CONTROL=str(config_path), P11SCOPE_CANARY_TARGET_BITS="64")
        argv = ["-I", "scripts/check-bpf-map-defs.py", "--inventory", "default", str(payload)]
        def run(arguments, selected_env=env):
            return subprocess.run([str(wrapper), *arguments], cwd=source, env=selected_env,
                                  text=True, capture_output=True, timeout=5)
        healthy = run(argv)
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
        self.assertIn("controlled inventory preflight mode=full target_bits=64 exit=0", healthy.stdout)
        self.assertNotIn("inventory default: maps=", healthy.stdout)
        value["failure"] = "inventory"; config_path.write_text(json.dumps(value))
        failed = run(argv)
        self.assertEqual(failed.returncode, 42, failed.stdout + failed.stderr)
        value["failure"] = ""; config_path.write_text(json.dumps(value))
        foreign = controls / "foreign-ebpf"; foreign.write_bytes(original_payload)
        for case in ("foreign_path", "wrong_variant", "extra_argument", "wrong_width", "changed_bytes",
                     "changed_binding", "changed_checker", "foreign_checker", "symlink"):
            with self.subTest(case=case):
                arguments, selected_env = list(argv), env.copy()
                before_checker = checker.read_bytes()
                changed_contract = json.loads(json.dumps(contract))
                if case == "foreign_path": arguments[-1] = str(foreign)
                elif case == "wrong_variant": arguments[-2] = "diagnostic"
                elif case == "extra_argument": arguments.append("extra")
                elif case == "wrong_width": selected_env["P11SCOPE_CANARY_TARGET_BITS"] = "32"
                elif case == "changed_bytes": payload.write_bytes(original_payload + b"changed")
                elif case == "changed_binding":
                    changed_contract["bindings"][payload.relative_to(stage).as_posix()] = "0" * 64
                    contract_path.write_text(json.dumps(changed_contract))
                elif case == "changed_checker": checker.write_bytes(before_checker + b"\n# altered staged checker\n")
                elif case == "foreign_checker": arguments[1] = str(ROOT / "scripts/check-bpf-map-defs.py")
                elif case == "symlink": payload.unlink(); payload.symlink_to(foreign)
                refused = run(arguments, selected_env)
                self.assertEqual(refused.returncode, 94, refused.stdout + refused.stderr)
                self.assertIn("refused controlled inventory preflight", refused.stderr)
                if payload.is_symlink(): payload.unlink()
                payload.write_bytes(original_payload)
                checker.write_bytes(before_checker)
                contract_path.write_text(json.dumps(contract))
        ordinary = run(["-I", "-c", "import sys; print('ordinary forward'); raise SystemExit(23)"])
        self.assertEqual(ordinary.returncode, 23, ordinary.stdout + ordinary.stderr)
        self.assertEqual(ordinary.stdout, "ordinary forward\n")
        ordinary_data = run(["-I", "-c", "import sys; print(sys.argv[1]); raise SystemExit(23)", "check-bpf-map-defs.py"])
        self.assertEqual(ordinary_data.returncode, 23, ordinary_data.stdout + ordinary_data.stderr)
        self.assertEqual(ordinary_data.stdout, "check-bpf-map-defs.py\n")
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
        try:
            generation = Path(f"/proc/{child.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
            helper = source / "scripts/lane-lib-oracle-1.py"
            signaled = run(["-I", str(helper), "TERM", str(child.pid), generation])
            self.assertEqual(signaled.returncode, 0, signaled.stdout + signaled.stderr)
            self.assertEqual(child.wait(timeout=5), -15)
            self.assertFalse(Path(f"/proc/{child.pid}").exists())
            rows = [json.loads(line) for line in Path(value["events"]).read_text().splitlines()]
            terms = [row for row in rows if row["kind"] == "signal"]
            self.assertEqual([(row["pid"], row["signal"]) for row in terms], [(child.pid, "TERM")])
            self.assertEqual(terms[0]["helper"], str(helper))
            self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(),
                             contract["bindings"][helper.relative_to(stage).as_posix()])
        finally:
            if child.poll() is None: child.terminate()
            child.wait(timeout=5)

    def test_failed_object_acquisition_preflight_publishes_no_rows_or_workload(self):
        # No native class setup/build: each failure is before any workload can
        # execute, using the same actual generated shell and external adapter.
        fixture = NativeObjectMatrix()
        fixture.scene, fixture.base = self, self.base
        _, stage, work, cwd, env, config_path = fixture.object_stage((("full", 64),), native_inputs=None)
        for failure in ("refusal", "inventory"):
            with self.subTest(failure=failure):
                value = json.loads(config_path.read_text()); value["failure"] = failure
                config_path.write_text(json.dumps(value))
                result = fixture.dispatch(stage, work, cwd, env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("controlled " + ("refusal acquisition" if failure == "refusal" else "inventory preflight"), result.stderr)
                self.assertIn("object_runner_exit=42", result.stderr)
                self.assertFalse(list((stage / "object").rglob("result.json")))
                self.assertFalse(list(work.glob("*/object-*.ready")))
                events = [json.loads(line) for line in Path(value["events"]).read_text().splitlines()]
                self.assertFalse(any(row["kind"] in ("capture", "compiler", "signal") for row in events))
                shutil.rmtree(stage / "object")

    def test_generated_object_dispatch_requires_private_descendant_of_bound_work_root(self):
        # No native setup: a valid root reaches a controlled acquisition failure
        # before any workload, while foreign roots must leave both trees intact.
        fixture = NativeObjectMatrix()
        fixture.scene, fixture.base = self, self.base
        _, stage, _, cwd, env, config_path = fixture.object_stage((("full", 64),), native_inputs=None)
        bound = self.base / "bound object work"; bound.mkdir(mode=0o700)
        direct = bound / "private task"; direct.mkdir(mode=0o700)
        nested_parent = bound / "nested"; nested_parent.mkdir(mode=0o700)
        nested = nested_parent / "private task"; nested.mkdir(mode=0o700)
        outside = self.base / "outside object work"; outside.mkdir(mode=0o700)
        sibling = self.base / "bound object work-sibling"; sibling.mkdir(mode=0o700)
        alias = bound / "linked outside"; alias.symlink_to(outside, target_is_directory=True)
        inside_alias = bound / "linked inside"; inside_alias.symlink_to(direct, target_is_directory=True)
        contract_path = stage / "contract.json"
        contract = json.loads(contract_path.read_text()); contract["guest_work_root"] = str(bound)
        contract_path.write_text(json.dumps(contract))
        config = json.loads(config_path.read_text()); config["failure"] = "refusal"

        def tree(root):
            return {path.relative_to(root).as_posix():
                    (stat.S_IMODE(path.lstat().st_mode),
                     str(path.readlink()) if path.is_symlink() else
                     hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
                    for path in root.rglob("*")}

        for work in (bound, outside, sibling, bound / ".." / outside.name, alias, inside_alias):
            with self.subTest(refused_root=work):
                config["work_root"] = str(work); config_path.write_text(json.dumps(config))
                before = {root: tree(root) for root in (stage, bound, outside, sibling)}
                try:
                    result = fixture.dispatch(stage, work, cwd, env)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertFalse((stage / "object").exists(), result.stderr)
                    self.assertEqual({root: tree(root) for root in before}, before)
                    events_path = Path(config["events"])
                    events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
                    self.assertFalse(any(row["kind"] in ("refusal_acquisition", "inventory_preflight", "capture", "compiler", "signal")
                                         for row in events))
                finally:
                    shutil.rmtree(stage / "object", ignore_errors=True)
                    Path(config["events"]).unlink(missing_ok=True)
        for work in (direct, nested):
            with self.subTest(healthy_root=work):
                config["work_root"] = str(work); config_path.write_text(json.dumps(config))
                result = fixture.dispatch(stage, work, cwd, env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("controlled refusal acquisition exit=42", result.stderr)
                self.assertIn("object_runner_exit=42", result.stderr)
                self.assertFalse(list((stage / "object").rglob("result.json")))
                self.assertFalse(list(work.glob("*/object-*.ready")))
                events = [json.loads(line) for line in Path(config["events"]).read_text().splitlines()]
                self.assertEqual(len([row for row in events if row["kind"] == "refusal_acquisition"]), 1)
                self.assertFalse(any(row["kind"] in ("capture", "compiler", "signal") for row in events))
                shutil.rmtree(stage / "object")
                Path(config["events"]).unlink()

    def test_object_wire_fixture_composition_passes_real_semantic_and_final_checkers(self):
        # Serialized acquisition fixtures only: these PIDs are literal wire
        # identities. Native dispatch/custody is a separate required control.
        objects = runpy.run_path(str(ROOT / "tests/python/test_canary_object.py"))
        templates = self.base / "wire templates"; templates.mkdir()
        NativeObjectMatrix().acquisition_templates(templates)
        acquire = self.base / "wire acquisition.py"; acquire.write_text(OBJECT_ACQUISITION)
        config = self.base / "wire controls.json"
        config.write_text(json.dumps({"templates": str(templates), "events": str(self.base / "wire events.jsonl"), "failure": ""}))
        env = dict(os.environ, P11SCOPE_OBJECT_CONTROL=str(config))
        for mode in ("full", "p0"):
            for bits in (32, 64):
                with self.subTest(mode=mode, bits=bits):
                    work = self.base / f"wire {mode}-{bits}"; work.mkdir()
                    lane = "object-ia32" if bits == 32 else "object-lp64"
                    for blocked, pid in ((False, 4343), (True, 4242)):
                        current = lane + ("-blocked" if blocked else "")
                        roster = {"pid": pid, "tasks": [{"role": "worker", "call_index": index, "tid": 1001 + index}
                                                       for index in range(4)]}
                        (work / (current + ".ready")).write_text(json.dumps(roster))
                        text = ("P11SCOPE_OBJECT_POINTERS " + json.dumps(objects["ObjectSideRowTests"].POINTERS) + "\n"
                                if blocked else objects["ledger_text"]())
                        (work / (current + ".workload.log")).write_text(text)
                        (work / (current + ".done")).touch()
                        argv = [sys.executable, "-I", str(acquire), "--lane", current, "--target-bits", str(bits),
                            "--object-attributes", "present" if mode == "full" else "absent", "--out-dir", str(work),
                            "--workload-pid", str(pid)]
                        for flag, suffix in (("--ready", "ready"), ("--go", "go"), ("--done", "done"), ("--finish", "finish"),
                                             ("--workload-log", "workload.log"), ("--observer-log", "observer.log")):
                            argv.extend((flag, str(work / (current + "." + suffix))))
                        result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    checker = runpy.run_path(str(ROOT / "scripts/check-canary-evidence.py"))
                    checker["initialize"](bits)
                    checker["set_object_attributes"]("present" if mode == "full" else "absent")
                    checker["assert_object_starts"](str(work / f"mapdump_manifest_{lane}.json"),
                        str(work / f"mapdump_manifest_{lane}-blocked.json"), str(work / (lane + ".workload.log")),
                        str(work / (lane + "-blocked.workload.log")), 4343, 4242, bits)
                    checker["assert_object_pilot"](work, bits)

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
            self.assertFalse(any(row["id"].startswith("object:") for row in report["rows"]))
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
        _, _, env = self.guest_disk_fixture()
        stage, prepared = self.prepare_guest_attempt("vng-stage", kernel=self.kernel)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        args = [sys.executable, "-I", str(CHECKER), "--launch-guest", str(stage),
                "--contract", str(stage / "contract.json"), "--kernel", str(self.kernel)]
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        argv = json.loads(Path(env["CONTROL_VNG_LOG"]).read_text())
        self.assertEqual(argv[argv.index("--run") + 1], str(self.kernel))
        self.assertEqual(argv[argv.index("--rwdir") + 1], str(stage))
        self.assertEqual(argv[argv.index("--overlay-rwdir") + 1], "/boot")
        self.assertNotIn("--disk", argv)
        Path(env["CONTROL_VNG_LOG"]).unlink()
        (self.base / "config-6.1.188").write_text("changed boot input\n")
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(Path(env["CONTROL_VNG_LOG"]).exists())

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

    def test_d4_ready_pair_check_rejects_bad_pairs(self):
        cells = {"D4:x": ("sel-x",)}
        lanes = {"D4:x": ("6.1.188",)}
        check_d4_ready_pair(("D4:x", "6.1.188"), cells, lanes, ("6.1.188",), {"sel-x"})
        bad = [
            # (pair, cells, lanes, lanes_all, runnable)
            (("D4:y", "6.1.188"), cells, lanes, ("6.1.188",), {"sel-x"}),
            (("D4:x", "9.9.9"), cells, lanes, ("6.1.188",), {"sel-x"}),
            (("D4:x", "6.1.188"), cells, {"D4:x": ("6.6.157",)}, ("6.1.188", "6.6.157"), {"sel-x"}),
            (("D4:x", "6.1.188"), cells, lanes, ("6.1.188",), set()),
        ]
        for pair, pair_cells, pair_lanes, lanes_all, runnable in bad:
            with self.subTest(pair=pair), self.assertRaises(AssertionError):
                check_d4_ready_pair(pair, pair_cells, pair_lanes, lanes_all, runnable)

    def test_d4_ready_pairs_need_curated_selectors_and_listed_lanes(self):
        cells = CHECKER_MOD["D4_CELLS"]
        lanes = CHECKER_MOD["D4_LANES"]
        ready = CHECKER_MOD["D4_READY"]
        lanes_all = CHECKER_MOD["LANES"]
        lists = CHECK_IGNORED_MOD["runner_lists"](PRIV_RUNNER)
        runnable = (lists["DEFAULT_TESTS"] | lists["ALTERNATIVE_TESTS"] | lists["LONG_TESTS"])
        self.assertTrue(ready, "the staged registry carries the qualified pairs")
        for pair in sorted(ready):
            with self.subTest(pair=pair):
                check_d4_ready_pair(pair, cells, lanes, lanes_all, runnable)

    def test_d4_cells_and_lanes_are_coherent(self):
        cells = CHECKER_MOD["D4_CELLS"]
        lanes = CHECKER_MOD["D4_LANES"]
        lanes_all = CHECKER_MOD["LANES"]
        self.assertEqual(set(cells), set(lanes), "every staged cell names its lanes")
        self.assertEqual(cells["D4:overlay-6.1"], (OVERLAY_CELL,))
        self.assertEqual(cells["D4:overlay-6.6"], (OVERLAY_CELL,))
        self.assertEqual(cells["D4:overlay-6.8+"], (OVERLAY_CELL,))
        self.assertEqual(cells["D4:ext4-inode-reuse"], (EXT4_CELL,))
        for obligation, selectors in cells.items():
            self.assertTrue(selectors, f"{obligation} names its qualifying cells")
            for selector in selectors:
                with self.subTest(selector=selector):
                    self.assertIsInstance(selector, str)
                    self.assertIn("::", selector)
        for obligation, obligation_lanes in lanes.items():
            for lane in obligation_lanes:
                with self.subTest(obligation=obligation, lane=lane):
                    self.assertIn(lane, lanes_all)

    def test_d4_ext4_inode_reuse_ready_on_qualified_lanes(self):
        ready = CHECKER_MOD["D4_READY"]
        self.assertEqual(
            sorted(pair for pair in ready if pair[0] == "D4:ext4-inode-reuse"),
            [
                ("D4:ext4-inode-reuse", "6.1.188"),
                ("D4:ext4-inode-reuse", "6.6.157"),
                ("D4:ext4-inode-reuse", "host"),
            ],
            "ext4-inode-reuse is ready exactly on the lanes whose cell qualified",
        )

    def test_d4_copy_up_red_cell_is_never_a_qualifying_cell(self):
        cells = CHECKER_MOD["D4_CELLS"]
        for obligation, selectors in cells.items():
            with self.subTest(obligation=obligation):
                self.assertNotIn(COPY_UP_RED, selectors)
        lists = CHECK_IGNORED_MOD["runner_lists"](PRIV_RUNNER)
        runnable = (lists["DEFAULT_TESTS"] | lists["ALTERNATIVE_TESTS"] | lists["LONG_TESTS"])
        self.assertNotIn(COPY_UP_RED, runnable)


OBJECT_EXTERNALS = r'''
import hashlib, json, os, pathlib, pwd, stat, sys
config = json.loads(pathlib.Path(os.environ["P11SCOPE_OBJECT_CONTROL"]).read_text())
kind, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
def record(row):
    with open(config["events"], "a") as stream: stream.write(json.dumps(row) + "\n")
if kind == "python3":
    def digest(path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            assert stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 64 * 1024 * 1024
            return hashlib.file_digest(stream, "sha256").hexdigest()
    def bound_script(name):
        stage = pathlib.Path(config["stage"])
        source = pathlib.Path(config["source_root"])
        script = pathlib.Path(args[1])
        assert script.resolve(strict=True) == source / "scripts" / name
        contract = json.loads((stage / "contract.json").read_text())
        assert digest(script) == contract["bindings"][f"artifacts/source/scripts/{name}"]
        return stage, script, contract
    script_index = 1 if args[:1] == ["-I"] else 0
    if len(args) > script_index and pathlib.Path(args[script_index]).name == "check-bpf-map-defs.py":
        try:
            assert len(args) == 5 and args[0] == "-I" and args[2:4] == ["--inventory", "default"]
            stage, script, contract = bound_script("check-bpf-map-defs.py")
            selected = [item for item in config["inventory_inputs"] if item["path"] == args[4]]
            assert len(selected) == 1
            selected = selected[0]
            mode, bits = selected["mode"], selected["target_bits"]
            assert mode in ("full", "p0") and type(bits) is int and bits in (32, 64)
            assert os.environ.get("P11SCOPE_CANARY_TARGET_BITS") == str(bits)
            cells = [cell for cell in contract["object_cells"] if (cell["mode"], cell["target_bits"]) == (mode, bits)]
            assert len(cells) == 1
            payload = stage / cells[0]["bundle"] / "default-ebpf"
            assert str(payload) == args[4] and payload.resolve(strict=True) == payload
            expected = selected["sha256"]
            assert digest(payload) == expected == contract["bindings"][payload.relative_to(stage).as_posix()]
            facts_path = stage / f"inputs/canary-build/{mode}-{bits}.json"
            assert digest(facts_path) == contract["bindings"][facts_path.relative_to(stage).as_posix()]
            facts = json.loads(facts_path.read_text())
            assert (facts["capture_mode"], facts["target_bits"]) == (mode, bits)
            assert facts["artifacts"]["default-ebpf"]["sha256"] == expected
        except (AssertionError, OSError, KeyError, TypeError, ValueError):
            print("refused controlled inventory preflight", file=sys.stderr)
            raise SystemExit(94)
        status = 42 if config["failure"] == "inventory" else 0
        record({"kind": "inventory_preflight", "mode": mode, "target_bits": bits, "path": str(payload),
                "sha256": expected, "fixture_controlled": True, "exit": status})
        print(f"controlled inventory preflight mode={mode} target_bits={bits} exit={status}; no BPF validity claim")
        raise SystemExit(status)
    if len(args) >= 2 and pathlib.Path(args[1]).name == "lane-lib-oracle-1.py":
        try:
            assert args[0] == "-I" and len(args) in (5, 6)
            stage, script, contract = bound_script("lane-lib-oracle-1.py")
            body = args[2:]
            assert body[0] in ("TERM", "KILL") and all(value.isdecimal() and int(value) > 0 for value in body[1:])
        except (AssertionError, OSError, KeyError, TypeError, ValueError):
            raise SystemExit(94)
        record({"kind": "signal", "signal": body[0], "pid": int(body[1]), "generation": int(body[2]),
                "real_uid": os.getuid(), "helper": str(script.resolve())})
    # Everything else, including the real semantic/final scanners, keeps the
    # original interpreter argv, standard streams, environment and status.
    os.execv(sys.executable, [sys.executable, *args])
if kind in ("gcc", "clang", "clang-18", "cargo", "rustc", "cc"):
    record({"kind": "compiler", "name": kind, "argv": args}); raise SystemExit(91)
if kind == "findmnt": print("btrfs"); raise SystemExit(0)
if kind == "bpftool": raise SystemExit(92)  # acquisition must remain controlled
if kind == "runuser":
    assert args[:3] == ["-u", pwd.getpwuid(os.getuid()).pw_name, "--"]
    assert os.getuid() != 0
    record({"kind": "runuser", "argv": args, "real_uid": os.getuid()})
    os.execvp(args[3], args[3:])
assert kind == "sudo", kind
def unknown():
    print("unknown external sudo operation", file=sys.stderr)
    raise SystemExit(94)
if args[:1] == ["-n"]: args.pop(0)
if args == ["true"]: raise SystemExit(0)
if args[:1] == ["chown"]:
    root = pathlib.Path(config["work_root"])
    if (len(args) >= 3 and args[1] == f"{os.getuid()}:{os.getgid()}"
            and all(pathlib.Path(value).is_absolute() and ".." not in pathlib.Path(value).parts
                    and pathlib.Path(value).is_relative_to(root) for value in args[2:])):
        raise SystemExit(0)  # fixture outputs already belong to the real caller
    unknown()
if len(args) < 3 or args[0] not in ("python3", sys.executable) or args[1] != "-I": unknown()
script, body = pathlib.Path(args[2]), args[3:]
source = pathlib.Path(config["source_root"])
if script.resolve() != source / "scripts" / script.name: unknown()
if script.name == "dump-owned-bpf-maps.py" and body == ["--refusal-probe"]:
    status = 42 if config["failure"] == "refusal" else 0
    record({"kind": "refusal_acquisition", "exit": status})
    print(f"controlled refusal acquisition exit={status}; no kernel probe executed")
    raise SystemExit(status)
if script.name == "capture-stopped-canary.py":
    flags = {"--object-attributes", "--lane", "--variant", "--mode", "--privacy", "--target-bits",
             "--workload-mode", "--workload-pid", "--generation", "--out-dir", "--prefix", "--ready",
             "--go", "--done", "--finish", "--observer-log", "--workload-log", "--reader", "--obj"}
    if body.count("--") != 1: unknown()
    front = body[:body.index("--")]
    if len(front) != 2 * len(flags) or set(front[::2]) != flags: unknown()
    os.execv(sys.executable, [sys.executable, str(pathlib.Path(config["templates"]) / "acquire.py"), *body])
if script.name == "check-canary-evidence.py":
    if (len(body) != 10 or body[0] != "--object-attributes" or body[1] not in ("present", "absent")
            or body[2] != "--object-starts" or body[-1] not in ("32", "64")): unknown()
    os.execv(sys.executable, [sys.executable, "-I", str(script), *body])
if script.name == "lane-lib-oracle-1.py":
    if len(body) not in (3, 4) or body[0] not in ("TERM", "KILL") or not all(value.isdecimal() for value in body[1:]): unknown()
    record({"kind": "signal", "signal": body[0], "pid": int(body[1]), "real_uid": os.getuid(), "helper": str(script)})
    os.execv(sys.executable, [sys.executable, "-I", str(script), *body])
unknown()
'''


OBJECT_ACQUISITION = r'''
import hashlib, json, os, pathlib, struct, sys, time
config = json.loads(pathlib.Path(os.environ["P11SCOPE_OBJECT_CONTROL"]).read_text())
args = sys.argv[1:]
def argument(key): return args[args.index(key) + 1]
lane, bits = argument("--lane"), int(argument("--target-bits"))
attributes = argument("--object-attributes")
mode = "full" if attributes == "present" else "p0"
work = pathlib.Path(argument("--out-dir"))
template = pathlib.Path(config["templates"]) / f"{mode}-{bits}"
with open(config["events"], "a") as stream:
    stream.write(json.dumps({"kind": "capture", "lane": lane, "bits": bits, "attributes": attributes}) + "\n")
if config["failure"] == "acquisition": raise SystemExit(42)
for path in template.rglob("*"):
    name = path.relative_to(template)
    if not path.is_file() or not (name.parts[0] == lane or name.as_posix() == f"mapdump_manifest_{lane}.json"
            or name.as_posix().startswith(lane + ".")) or name.as_posix() == lane + ".workload.log": continue
    target = work / name; target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(path.read_bytes().replace(str(template).encode(), str(work).encode()))
pathlib.Path(argument("--go")).touch()
blocked = lane.endswith("-blocked")
if not blocked:
    deadline = time.monotonic() + 4
    while not pathlib.Path(argument("--done")).exists():
        assert time.monotonic() < deadline, "actual C ledger did not complete"
        time.sleep(.005)
    pathlib.Path(argument("--finish")).touch()
roster = json.loads(pathlib.Path(argument("--ready")).read_text())
pid = int(argument("--workload-pid")); assert roster["pid"] == pid
wire = json.loads((template / "wire.json").read_text())
manifest_path = work / f"mapdump_manifest_{lane}.json"
manifest = json.loads(manifest_path.read_text())
def item(name): return next(row for row in manifest if row["name"] == name)
if not blocked:
    records = [bytearray.fromhex(raw) for raw in wire["completed"]]
    for row in records: struct.pack_into("<Q", row, 16, (pid << 32) | pid)
    if config["failure"] == "semantic": struct.pack_into("<Q", records[0], 400, 0xDEAD)
    (work / (lane + ".EVENTS.raw")).write_bytes(b"".join(struct.pack("<II", 608, 0) + row for row in records))
else:
    pointers = [line.removeprefix("P11SCOPE_OBJECT_POINTERS ")
                for line in pathlib.Path(argument("--workload-log")).read_text().splitlines()
                if line.startswith("P11SCOPE_OBJECT_POINTERS ")]
    assert len(pointers) == 1
    pointers = json.loads(pointers[0])
    workers = {row["call_index"]: row["tid"] for row in roster["tasks"] if row["role"] == "worker"}
    assert set(workers) == set(range(4))
    starts, sides = [], []
    for index, pair in enumerate(wire["blocked"]):
        start, side = bytearray.fromhex(pair["start"]), bytearray.fromhex(pair["side"])
        key = [f"0x{byte:02x}" for byte in struct.pack("<QII", (pid << 32) | workers[index], 3, 0)]
        if index == 0: struct.pack_into("<Q", side, 48, pointers["out_create"])
        elif index == 1: struct.pack_into("<QQ", side, 48, pointers["out_pub"], pointers["out_priv"])
        elif index == 2:
            struct.pack_into("<Q", side, 48, pointers["found"])
            struct.pack_into("<Q", side, 88, pointers["found_count"])
        elif attributes == "present":
            struct.pack_into("<QQ", side, 64, pointers["template"], pointers["template"] + 24 * (bits // 8))
            for slot, pointer in enumerate(pointers["get_values"]): struct.pack_into("<Q", side, 96 + 32 * slot, pointer)
        if attributes == "absent":
            side[352:424] = bytes(72)
            if index == 3: side[64:80] = bytes(16); side[96:352] = bytes(256); side[430] = 0
        starts.append({"key": key, "value": [f"0x{byte:02x}" for byte in start]})
        sides.append({"key": key, "value": [f"0x{byte:02x}" for byte in side]})
    pathlib.Path(item("START")["file"]).write_text(json.dumps(starts))
    pathlib.Path(item("OBJECT_START")["file"]).write_text(json.dumps(sides))
    if config["failure"] == "final":
        pathlib.Path(argument("--observer-log")).write_bytes(bytes.fromhex(wire["sentinel"]))
receipt_path = pathlib.Path(manifest[0]["snapshot"]["receipt"])
receipt = json.loads(receipt_path.read_text())
for surface in receipt["surfaces"]:
    row = next(row for row in manifest if row["id"] == surface["id"])
    path = work / f"{lane}.{row['name']}.raw" if row["type"] == "ringbuf" else pathlib.Path(row["file"])
    raw = path.read_bytes()
    surface.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if row["type"] == "ringbuf": surface["positions"] = [0, len(raw)]
receipt_path.write_text(json.dumps(receipt))
'''


class NativeObjectMatrix(unittest.TestCase):
    """Eight tiny C builds once; actual runner/oracles, controlled acquisition.

    The C workload/provider ledger and pidfd TERM are real. The stopped maps
    are existing small wire fixtures, not kernel/BPF qualification.
    """
    @classmethod
    def setUpClass(cls):
        cls.native_temp = tempfile.TemporaryDirectory(prefix="matrix-object-native-")
        cls.addClassCleanup(cls.native_temp.cleanup)
        cls.native = Path(cls.native_temp.name)
        compiler = shutil.which("gcc")
        if compiler is None: raise RuntimeError("gcc is required for the actual object runner controls")
        helper = b'''#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    for (int i=1; i+1<argc; ++i) if (!strcmp(argv[i], "-o")) {
        FILE *f=fopen(argv[i+1], "w");
        if (!f) return 1;
        if (fputs("{}\\n", f)<0) return 1;
        return fclose(f)!=0;
    }
    return 1;
}
'''
        for bits in (32, 64):
            inputs = cls.native / str(bits); inputs.mkdir()
            commands = [
                [compiler, f"-m{bits}", "-O0", "-pthread", str(ROOT / "scripts/fixtures/canary_workload.c"),
                 "-ldl", "-o", str(inputs / "canary_workload")],
                *[[compiler, f"-m{bits}", "-shared", "-fPIC", "-DPRIVACY_FIXTURE=1", *flags,
                   str(ROOT / "crates/discover/tests/fixture/version_matrix.c"), "-o", str(inputs / name)]
                  for name, flags in (("matrix-provider.so", []), ("privacy-provider.so", ["-DPRIVACY_BLOCKS=1"]))],
            ]
            for argv in commands: subprocess.run(argv, check=True, capture_output=True, timeout=20)
            subprocess.run([compiler, f"-m{bits}", "-x", "c", "-", "-o", str(inputs / "p11scope-discover")],
                           input=helper, check=True, capture_output=True, timeout=20)

    def setUp(self):
        self.scene = MatrixContract()
        self.scene.setUp()
        self.addCleanup(self.scene.temp.cleanup)
        self.base = self.scene.base

    def acquisition_templates(self, controls):
        fixtures = runpy.run_path(str(ROOT / "tests/python/test_canary_evidence.py"))
        objects = runpy.run_path(str(ROOT / "tests/python/test_canary_object.py"))
        capture = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        record_fixture = objects["ObjectRecordsTests"]()
        side_fixture = objects["ObjectSideRowTests"]()
        ordinals = {name: ordinal for ordinal, name in objects["evidence"]["OBJECT_LEDGER"]}
        for mode in ("full", "p0"):
            for bits in (32, 64):
                root = controls / f"{mode}-{bits}"; root.mkdir()
                pilot = fixtures["FinalScannerSurfaceTests"]()
                pilot.object_pilot_fixture.__func__.__globals__["TARGET_BITS"] = bits
                subject = fixtures["load_subject"](bits)
                pilot.object_pilot_fixture(subject, root)
                records = [bytearray(row) for row in record_fixture.completion_records(bits)]
                if mode == "p0":
                    absent = bytes(32) + bytes((0, 16, 0, 0))
                    for row in records:
                        ordinal = struct.unpack_from("<I", row, 372)[0] - 1
                        if ordinal in (20, 21, 24, 58, 59, 61, 62): row[496:532] = absent
                        if ordinal == 59: row[532:568] = absent
                        if ordinal == 24: row[568:604] = absent
                starts, sides = side_fixture.blocked_fixture(bits)
                (root / "wire.json").write_text(json.dumps({"sentinel": subject.SENTINELS["PIN"].hex(),
                    "completed": [bytes(row).hex() for row in records],
                    "blocked": [{"start": starts[index + 1001]["raw"].hex(), "side": row["raw"].hex()}
                                for index, (_key, row) in enumerate(sides)]}))
                shape = capture["VERSION_SHAPE_SCANNED_IA32" if bits == 32 else "VERSION_SHAPE_SCANNED"]
                tables = capture["VERSION_TABLES_SCANNED_IA32" if bits == 32 else "VERSION_TABLES_SCANNED"]
                evidence = capture["evidence_fixture"](shape[3], sources=("scan", "manifest"))
                evidence.update(table_entries=shape[0], slots=104, attached_probes=208, vendor_interfaces=1,
                    interface_list="ok", discovery_conflicts=int(bits == 64), orphan_ops=1, operation_state_imports=1)
                evidence["discovery"][0]["tables"] = [{"source": source, "version": list(version), "entries": entries}
                    for (source, version, entries), count in tables.items() for _ in range(count)]
                evidence["discovery"][0].update(corroborated=True, corroboration=["agreed" if bits == 32 else "conflict"])
                report = capture["document_fixture"](evidence)
                report["functions"] = capture["function_items"](
                    [([name], 6 if name == "C_GetAttributeValue" else 1) for name in ordinals]
                    + [([f"C_Uncalled_{index}"], 0) for index in range(79)])
                for row in report["functions"]:
                    get, count = row["names"] == ["C_GetAttributeValue"], row["calls"]
                    row.update(errors=5 if get else 0, pending_returns=0, in_flight=0,
                        latency_ns={"approximate": True, "p50": 1 if count else None, "p95": 1 if count else None,
                                    "p99": 1 if count else None, "total": count, "max": int(count > 0)},
                        rv_counts=({f"0x{rv:016x}": 1 for rv in (0, 17, 18, 336, 5, 1)} if get
                                   else {"0x0000000000000000": 1} if count else {}))
                    if row["names"][0] in ordinals:
                        row["ordinals"] = [{"table_file_offset": None, "ordinal": ordinals[row["names"][0]]}]
                capture["settle_fixture_verdict"](report)
                lane = "object-ia32" if bits == 32 else "object-lp64"
                capture["validate_canary"](lane, report, bits)
                (root / (lane + ".output")).write_text(json.dumps(report))

    def object_stage(self, cells, *, native_inputs):
        repo, stage = self.scene.retained_object_inputs(cells, native_inputs)
        result = command(str(RUNNER), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        controls = self.base / "external controls"; controls.mkdir()
        self.acquisition_templates(controls)
        events = controls / "events.jsonl"
        config = controls / "control.json"
        bindings = json.loads((stage / "contract.json").read_text())["bindings"]
        config.write_text(json.dumps({"events": str(events), "templates": str(controls), "stage": str(stage),
            "source_root": str(stage / "artifacts/source"), "work_root": str(self.base / "caller object work"),
            "inventory_inputs": [{"mode": mode, "target_bits": bits,
                "path": str(stage / f"artifacts/canary/{mode}-{bits}/default-ebpf"),
                "sha256": bindings[f"artifacts/canary/{mode}-{bits}/default-ebpf"]} for mode, bits in cells], "failure": ""}))
        acquire = controls / "acquire.py"
        acquire.write_text(OBJECT_ACQUISITION)
        dispatch = controls / "dispatch.py"
        dispatch.write_text("#!" + sys.executable + "\n" + OBJECT_EXTERNALS)
        dispatch.chmod(0o755)
        for name in ("python3", "sudo", "runuser", "findmnt", "bpftool", "gcc", "clang", "clang-18", "cargo", "rustc", "cc"):
            (controls / name).symlink_to(dispatch.name)
        work = self.base / "caller object work"; work.mkdir(mode=0o700)
        unrelated = self.base / "unrelated object cwd"; unrelated.mkdir()
        env = os.environ.copy()
        env.update(PATH=str(controls) + ":" + env["PATH"], P11SCOPE_OBJECT_CONTROL=str(config))
        return repo, stage, work, unrelated, env, config

    def dispatch(self, stage, work, cwd, env):
        result = subprocess.run(["bash", str(stage / "object-inner.sh"), str(work)],
                                cwd=cwd, env=env, text=True, capture_output=True, timeout=30)
        retain_command(result.args, result)
        if result.returncode:
            result.stderr += "\n" + "\n".join(path.read_text() for path in (stage / "object").glob("*/run.log"))
        return result

    def test_generated_inner_runs_selected_prebuilt_object_pairs(self):
        cells = [(mode, bits) for mode in ("full", "p0") for bits in (32, 64)]
        _, stage, work, cwd, env, config_path = self.object_stage(cells, native_inputs=self.native)
        bindings = json.loads((stage / "contract.json").read_text())["bindings"]
        before = {name: hashlib.sha256((stage / name).read_bytes()).hexdigest() for name in bindings}
        result = self.dispatch(stage, work, cwd, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = CHECKER_MOD["object_rows"](stage, json.loads((stage / "contract.json").read_text()))
        self.assertEqual([row["id"] for row in rows],
                         [f"object:{mode}:{bits}:{role}" for mode, bits in cells for role in ("complete", "blocked")])
        events = [json.loads(line) for line in Path(json.loads(config_path.read_text())["events"]).read_text().splitlines()]
        captures = [row for row in events if row["kind"] == "capture"]
        pilots = [row["argv"] for row in events if row["kind"] == "runuser" and "--object-pilot" in row["argv"]]
        self.assertEqual(len(pilots), 4)
        for (mode, bits), argv in zip(cells, pilots):
            self.assertEqual(argv[argv.index("--capture-mode") + 1], mode)
            self.assertEqual(argv[argv.index("--prebuilt-dir") + 1], str(stage / f"artifacts/canary/{mode}-{bits}"))
            self.assertIn(f"P11SCOPE_CANARY_TARGET_BITS={bits}", argv)
        self.assertEqual([(row["attributes"], row["bits"], row["lane"]) for row in captures],
            [("present" if mode == "full" else "absent", bits,
              ("object-ia32" if bits == 32 else "object-lp64") + suffix)
             for mode, bits in cells for suffix in ("", "-blocked")])
        terms = [row for row in events if row["kind"] == "signal"]
        self.assertEqual(len(terms), 4)
        self.assertTrue(all(row["signal"] == "TERM" and row["real_uid"] == os.getuid() for row in terms))
        self.assertTrue(all(Path(row["helper"]).resolve() == stage / "artifacts/source/scripts/lane-lib-oracle-1.py"
                            if Path(row["helper"]).is_absolute() else row["helper"] == "scripts/lane-lib-oracle-1.py" for row in terms))
        self.assertTrue(all(not Path(f'/proc/{row["pid"]}').exists() for row in terms), "blocked workload was not reaped")
        self.assertFalse(any(row["kind"] == "compiler" for row in events))
        self.assertEqual(before, {name: hashlib.sha256((stage / name).read_bytes()).hexdigest() for name in bindings})

    def test_generated_inner_object_pair_uses_only_staged_sources(self):
        repo, stage, work, cwd, env, config_path = self.object_stage((("full", 64),), native_inputs=self.native)
        repo.rename(self.base / "unavailable native object source")
        self.assertFalse(repo.exists())
        result = self.dispatch(stage, work, cwd, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = [json.loads(line) for line in Path(json.loads(config_path.read_text())["events"]).read_text().splitlines()]
        terms = [row for row in events if row["kind"] == "signal"]
        self.assertEqual(len(terms), 1)
        self.assertEqual(terms[0]["signal"], "TERM")
        self.assertEqual(terms[0]["helper"], str(stage / "artifacts/source/scripts/lane-lib-oracle-1.py"))
        self.assertFalse(Path(f'/proc/{terms[0]["pid"]}').exists(), "blocked child survived its actual143 wait")
        strict = subprocess.run([sys.executable, "-I", str(stage / "artifacts/source/scripts" / CHECKER.name),
            "--verify-inputs", str(stage), "--contract", str(stage / "contract.json")], cwd=cwd, env=env,
            text=True, capture_output=True, timeout=5)
        self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)
        contract_path = stage / "contract.json"
        original = json.loads(contract_path.read_text())
        helper = stage / "artifacts/source/scripts/lane-lib-oracle-1.py"
        helper_bytes = helper.read_bytes()
        for case in ("missing_binding", "missing_helper", "changed_helper"):
            with self.subTest(case=case):
                if (stage / "object").exists(): shutil.rmtree(stage / "object")
                value = json.loads(json.dumps(original))
                if case == "missing_binding": value["bindings"].pop(helper.relative_to(stage).as_posix())
                elif case == "missing_helper": helper.unlink()
                else: helper.write_bytes(helper_bytes + b"\n# changed staged helper\n")
                contract_path.write_text(json.dumps(value))
                failed = self.dispatch(stage, work, cwd, env)
                self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
                self.assertFalse((stage / "object").exists(), "refusal reached object execution")
                helper.write_bytes(helper_bytes)
                contract_path.write_text(json.dumps(original))
        for failure in ("refusal", "inventory", "acquisition", "semantic", "final"):
            with self.subTest(failure=failure):
                value = json.loads(config_path.read_text()); value["failure"] = failure
                config_path.write_text(json.dumps(value))
                failed = self.dispatch(stage, work, cwd, env)
                self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
                self.assertFalse((stage / "object/full-64/result.json").exists())
                shutil.rmtree(stage / "object")


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


class MatrixLaneRegistration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="matrix-lanes-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_contract_registers_both_lanes(self):
        self.assertEqual(CHECKER_MOD["LANES"],
                         ("5.15.221", "6.1.188", "6.6.157", "6.8.0-142-generic",
                          "6.12.111", "6.18.58", "7.2.6", "host",
                          "fedora-7.2.9"))
        lanes = CHECKER_MOD["D4_LANES"]
        self.assertEqual(lanes["D4:overlay-6.8+"],
                         ("6.8.0-142-generic", "6.12.111", "6.18.58", "7.2.6",
                          "host", "fedora-7.2.9"))
        self.assertEqual(lanes["D4:ext4-inode-reuse"],
                         ("6.1.188", "6.6.157", "6.8.0-142-generic", "6.12.111",
                          "6.18.58", "7.2.6", "host", "fedora-7.2.9"))

    def test_plan_accepts_both_lanes_with_full_selection(self):
        for lane in ("6.18.58", "fedora-7.2.9"):
            with self.subTest(lane=lane):
                result = command(sys.executable, "-I", str(CHECKER), "--plan",
                                 "--lane", lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                plan = json.loads(result.stdout)
                self.assertIn(lane, plan["lanes"])
                execution = plan["execution"]
                self.assertEqual(execution["lane"], lane)
                self.assertIn(LIB_A, execution["lib_tests"])

    def test_dry_run_defaults_gain_618_without_fedora(self):
        result = command(str(RUNNER), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kernels (8):", result.stdout)
        self.assertIn("v6.18.58 tag=v6.18.58", result.stdout)
        self.assertNotIn("tag=fedora", result.stdout)

    def test_resolve_kernel_maps_new_names(self):
        for spec, resolved in (("fedora", "fedora-7.2.9"),
                               ("fedora-7.2.9", "fedora-7.2.9"),
                               ("6.18", "v6.18.58"),
                               ("6.18.58", "v6.18.58"),
                               ("v6.18.58", "v6.18.58")):
            with self.subTest(spec=spec):
                result = command(str(RUNNER), "--dry-run", "--kernels", spec)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(f"{resolved} tag={resolved}", result.stdout)

    def test_run_one_refuses_fedora_lane(self):
        import shlex
        stages, outputs = self.base / "stages", self.base / "outputs"
        stages.mkdir()
        outputs.mkdir()
        body = RUNNER.read_text().split("run_one() {", 1)[1].split("\noverall=", 1)[0]
        words = {"CHECKER": CHECKER, "REPO": ROOT, "STAGE_REV": stages,
                 "OUT_REV": outputs}
        script = "set -uo pipefail\n" + "".join(
            key + "=" + shlex.quote(str(value)) + "\n"
            for key, value in words.items())
        script += "run_one() {" + body + "\nrun_one fedora-7.2.9\n"
        result = subprocess.run(["bash", "-c", script], cwd=ROOT,
                                env=os.environ.copy(), text=True,
                                capture_output=True, timeout=20)
        retain_command(["bash", "-c", "run_one fedora-7.2.9"], result)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("live-cell procedure", result.stderr)
        self.assertFalse((stages / "fedora-7.2.9").exists())
        self.assertFalse((outputs / "fedora-7.2.9").exists())


def check_d4_ready_pair(pair, cells, lanes, lanes_all, runnable):
    """A READY (obligation, lane) pair needs a registered obligation, a
    listed lane of that obligation, and every qualifying selector curated
    in the privileged runner's runnable lists."""
    obligation, lane = pair
    assert obligation in cells, f"ready obligation {obligation} has no D4_CELLS entry"
    assert lane in lanes_all, f"ready lane {lane} is not a listed lane"
    assert lane in lanes[obligation], f"ready lane {lane} is not in D4_LANES[{obligation}]"
    for selector in cells[obligation]:
        assert selector in runnable, f"ready selector {selector} is not curated runnable"


if __name__ == "__main__":
    unittest.main()
