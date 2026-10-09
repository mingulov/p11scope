#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual matrix preparation, judge and production shell seams."""
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/release-matrix-contract.py"
RUNNER = ROOT / "scripts/qualify-release-matrix.sh"
LIB_A = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64"
LIB_B = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64"
LIB_C = "attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64"
PID_TEST = "tests::the_pid_filter_probe_reaches_the_kernel"
CLASSIC_MULTI = "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64"
CAPTURE_MULTI = "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64"
LEADER_MULTI = "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64"
CHURN = "inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"
BROAD = "discovery::engine::publication_tests::broad_p11kit_admission_arithmetic"
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
        self.listing.write_text(f"{LIB_A}: test\n{LIB_B}: test\n{LIB_C}: test\n\n3 tests, 0 benchmarks\n")
        self.curation = self.base / "curation.txt"
        self.curation.write_text(f"default (0)\nlong (3, --include-long only)\n{LIB_A}\n{LIB_B}\n{LIB_C}\nskipped (0)\nverify: curation matches the binary (3 tests)\n")
        self.bm_list = self.base / "bpf-list.txt"
        self.bm_list.write_text(f"{PID_TEST}: test\n1 test, 0 benchmarks\n")
        self.contract = self.stage / "contract.json"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.stage),
                         "--lane", "6.1.188", "--bin-dir", str(self.bins),
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
                     "scripts/qualify-inventory-native.sh", "scripts/inventory-native-oracle.py",
                     "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                     "tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / name, path)
        stage = self.base / "clone-stage"
        receipt = candidate_receipt(self.bins, self.base / "clone-build.json", repo)
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--prepare", str(stage),
                         "--lane", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(receipt), "--lib-test", LIB_A)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return repo, stage

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

    def test_prebuilt_candidate_without_build_root_receipt_is_refused(self):
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.base / "no-build-receipt"),
                         "--lane", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list), "--lib-test", LIB_A)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_build_receipt_missing_mismatched_or_declared_provenance_fails(self):
        original = json.loads(self.candidate.read_text())
        mutations = ({"producer": "user-declaration"}, {"lib_sha256": "0" * 64}, {"source_root": str(self.base / "absent")},
                     {"runtime_sources": {}}, {"source_revision": "short"}, {"source_tree": "short"}, {"source_clean": False},
                     {"build": {"argv": ["cargo", "test", "--lib", "--no-run"], "cwd": str(ROOT), "exit": 1}})
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation):
                self.candidate.write_text(json.dumps(dict(original, **mutation)) + "\n")
                result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(self.base / ("invalid-build-" + str(index))),
                                 "--lane", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
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
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(stage), "--lane", "host",
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

    def test_generated_guest_executes_mt12_exact_selectors_and_fails_bad_evidence(self):
        # Only external operations are controlled. The generated guest script,
        # contract sealing and judge are the production bytes and entrypoints.
        repo = self.base / "controlled-source"
        (repo / "scripts").mkdir(parents=True)
        for path in (RUNNER, CHECKER):
            shutil.copy2(path, repo / "scripts" / path.name)
        for name in ("qualify-public-cli.sh", "qualify-inventory-native.sh", "run-privileged-lib-tests.sh"):
            path = repo / "scripts" / name
            path.write_text("#!/bin/bash\nprintf '%s\\n' \"$THREADS\" \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho 'SUMMARY pass=1 fail=0 skipped=0'\nexit 0\n" if name == "qualify-public-cli.sh" else "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho 'SUMMARY pass=1 fail=0 skipped=0'\nexit 0\n")
            path.chmod(0o755)
        for name in ("scripts/inventory-native-oracle.py", "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                     "tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c"):
            path = repo / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("controlled external fixture\n")
        for name in ("p11scope", "p11scope-bpfmulti"):
            path = self.bins / name
            path.write_text("#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$CONTROL_ARGS/" + name + ".args\"\necho controlled\nexit 0\n")
            path.chmod(0o755)
        stage = self.base / "guest-stage"
        receipt = candidate_receipt(self.bins, self.base / "guest-build.json", repo)
        result = command(sys.executable, "-I", str(repo / "scripts" / CHECKER.name), "--prepare", str(stage),
                         "--lane", "host", "--bin-dir", str(self.bins), "--binary-list", str(self.listing),
                         "--curation", str(self.curation), "--bpfmulti-list", str(self.bm_list),
                         "--candidate-receipt", str(receipt),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = command(str(repo / "scripts" / RUNNER.name), "--write-inner-stage", str(stage), "--contract", str(stage / "contract.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        env = os.environ.copy()
        env["CONTROL_ARGS"] = str(self.base)
        run = subprocess.run(["bash", str(stage / "inner.sh")], cwd=ROOT,
                             capture_output=True, text=True, env=env, timeout=20)
        retain_command(["bash", str(stage / "inner.sh")], run)
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        public_args = (self.base / "qualify-public-cli.sh.args").read_text().splitlines()
        self.assertEqual(public_args[0], "12")
        privileged_args = (self.base / "run-privileged-lib-tests.sh.args").read_text().splitlines()
        self.assertEqual(privileged_args[2:], ["--include-long", LIB_A, LIB_B])
        self.assertEqual((self.base / "p11scope-bpfmulti.args").read_text().splitlines(),
                         ["--exact", PID_TEST, "--test-threads=1", "--nocapture"])

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
        previous = out / "existing"
        previous.mkdir(parents=True)
        (previous / "summary.md").write_text("preserved earlier evidence\n")
        stubs = self.base / "stubs"
        stubs.mkdir()
        for name, rc in (("pgrep", 1), ("sleep", 0)):
            path = stubs / name; path.write_text(f"#!/bin/sh\nexit {rc}\n"); path.chmod(0o755)
        env = os.environ.copy(); env["PATH"] = str(stubs) + ":" + env["PATH"]
        stage_base = self.base / "campaign-stage"
        result = subprocess.run([str(RUNNER), "--rev", "existing", "--bin-dir", str(self.bins),
                                 "--out-base", str(out), "--stage-base", str(stage_base), "--kernels", "6.1"],
                                cwd=ROOT, text=True, capture_output=True, env=env, timeout=20)
        retain_command(result.args, result)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
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
                         "--lane", "6.1.188", "--bin-dir", str(self.bins),
                         "--binary-list", str(self.listing), "--curation", str(self.curation),
                         "--bpfmulti-list", str(self.bm_list), "--candidate-receipt", str(self.candidate),
                         "--lib-test", LIB_A, "--lib-test", LIB_B)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_qualifying_selected_subset_may_pass_only_its_claim(self):
        fresh = self.base / "subset"
        result = command(sys.executable, "-I", str(CHECKER), "--prepare", str(fresh),
                         "--lane", "6.1.188", "--bin-dir", str(self.bins),
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

    def test_dry_run_has_all_seven_lanes_mt12_and_exact_breadth_names(self):
        result = command(str(RUNNER), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        for literal in ("5.15.221", "6.1.188", "6.6.157", "6.8.0-142", "6.12.111", "7.2.6", "host", "THREADS=12", LIB_A, LIB_B, LIB_C, "unready"):
            with self.subTest(literal=literal):
                self.assertIn(literal, result.stdout)

    def test_empty_selection_is_rejected(self):
        result = command(sys.executable, "-I", str(CHECKER), "--plan", "--lib-test", "")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
