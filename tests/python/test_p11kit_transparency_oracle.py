# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""p11-kit transparency oracle: parser and judge controls.

The spy parser is fed a real captured log,
``tests/fixtures/p11kit/spy-sample.log``: a verbatim prefix (banner plus
blocks 0-8, stopping before the PIN block) of an OpenSC pkcs11-spy log
captured on Ubuntu on 2026-11-01, when the through-proxy fixture drove
the p11-kit proxy (isolated user config) into an owned SoftHSM copy
wrapped by the spy. All report/receipt/ledger expectations are
independent synthetic inputs; only the spy bytes are real.
"""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/p11kit-transparency-oracle.py"
SPY_SAMPLE = ROOT / "tests/fixtures/p11kit/spy-sample.log"

FUNCS = runpy.run_path(str(ORACLE))

PROXY = {"dev": [8, 1], "ino": 71, "sha256": "a" * 64}
OWNED = {"dev": [8, 1], "ino": 72, "sha256": "b" * 64}

# The real sample's compared counts (blocks 0-8 minus the meta-export).
SAMPLE_COUNTS = {"C_Initialize": 1, "C_GetSlotList": 4,
                 "C_GetSlotInfo": 2, "C_OpenSession": 1}

LOOP = ("C_DigestInit", "C_Digest", "C_FindObjectsInit",
        "C_FindObjects", "C_FindObjectsFinal")
ITERS = 3


def workload_ledger():
    funcs = [{"name": "C_GetFunctionList", "attempts": 1, "successful": 1},
             {"name": "C_Initialize", "attempts": 1, "successful": 1},
             {"name": "C_GetSlotList", "attempts": 1, "successful": 1},
             {"name": "C_OpenSession", "attempts": 1, "successful": 1},
             {"name": "C_Login", "attempts": 1, "successful": 1}]
    for name in LOOP:
        funcs.append({"name": name, "attempts": ITERS, "successful": ITERS})
    funcs += [{"name": "C_CloseSession", "attempts": 1, "successful": 1},
              {"name": "C_Finalize", "attempts": 1, "successful": 1}]
    return {row["name"]: row["successful"] for row in funcs}


LOOP7 = ("C_DigestInit", "C_Digest", "C_FindObjectsInit",
         "C_FindObjects", "C_FindObjectsFinal", "C_CloseSession", "C_Finalize")


def ledger_lines(*, ready_first=True, full_targets=False):
    lines = []
    names = list(workload_ledger()) if full_targets else list(LOOP)
    targets = ["TARGET " + json.dumps({"name": name, "dev": [8, 1], "ino": 71,
                                       "file_offset": 4096 + i * 16})
               for i, name in enumerate(names)]
    if not ready_first:
        lines += targets
    lines.append("READY pid=123")
    if ready_first:
        lines += targets
    lines.append("LEDGER " + json.dumps(
        {"schema": "p11scope/p11kit-ledger/v1", "pid": 123, "complete": True,
         "functions": [{"name": name, "attempts": count, "successful": count}
                       for name, count in workload_ledger().items()]}))
    return lines


def row(ident, name, calls):
    return {"names": [name], "calls": calls, "module": dict(ident),
            "module_ambiguous": False, "module_unresolved": False,
            "target": {"object": dict(ident), "file_offset": 4096}}


def inputs(*, metrics=False, scope="pid"):
    mode = "metrics" if metrics else "profile"
    schema = ("p11scope/observed-profile/v3-metrics" if metrics
              else "p11scope/observed-profile/v3")
    report = {
        "schema": schema, "lane": mode,
        "capture": {"scope": scope if scope != "run" else "pid", "mode": mode},
        "functions": ([row(PROXY, name, count)
                       for name, count in workload_ledger().items()] +
                      [row(OWNED, name, count)
                       for name, count in SAMPLE_COUNTS.items()]),
        "evidence": {
            "gap_classes": {
                "observation": {"status": "exact", "causes": []},
                "attribution": {"status": "attested", "causes": []},
                "semantics": {"status": "complete", "causes": []}},
            "modules_skipped": [], "skipped": [],
            "discovery": [dict(PROXY, path="/proxy.so"),
                          dict(OWNED, path="/owned.so")]},
    }
    if scope == "run":
        report["capture"]["scope"] = "pid"
    receipt = {"schema": "p11scope/p11kit-receipt/v1", "cell": "CELL",
               "scope": scope, "mode": mode,
               "launched_pid": 123, "ready_pid": 123,
               "workload_ready": True, "capture_ready": True,
               "gate_released": scope != "run", "ledger_complete": True,
               "observer_exit": 0, "workload_exit": 0,
               "spy_loaded": "LOADED", "spy_pid": 123}
    return report, ledger_lines(), receipt


class ParserTests(unittest.TestCase):
    def test_spy_parser_real_sample(self):
        counts, meta, loaded, pids, incomplete = FUNCS["parse_spy_log"](
            SPY_SAMPLE.read_text())
        self.assertEqual(counts, SAMPLE_COUNTS)
        self.assertEqual(meta, {"C_GetInterface": 1})
        self.assertTrue(loaded.endswith("libsofthsm2-owned.so"), loaded)
        self.assertEqual(pids, [764625])
        self.assertEqual(incomplete, [])

    def test_spy_parser_ignores_payload_lines(self):
        text = SPY_SAMPLE.read_text()
        # Payload lookalikes inside a block must not count: neither a bare
        # name, nor an unanchored header, nor a non-Returned completion.
        poisoned = text.replace(
            "[out] *phSession = 0x1\nReturned:  0 CKR_OK",
            "[out] *phSession = 0x1\n[in] note C_Digest everywhere\n"
            "x 99: C_Fake\nNotReturned:  0 CKR_OK\nReturned:  0 CKR_OK")
        counts, meta, _, _, incomplete = FUNCS["parse_spy_log"](poisoned)
        self.assertEqual(counts, SAMPLE_COUNTS)
        self.assertEqual(meta, {"C_GetInterface": 1})
        self.assertEqual(incomplete, [])

    def test_spy_parser_reports_block_without_return(self):
        text = SPY_SAMPLE.read_text().rsplit("Returned:", 1)[0] + "trailing-garbage\n"
        _, _, _, _, incomplete = FUNCS["parse_spy_log"](text)
        self.assertEqual(incomplete, [(8, "C_OpenSession")])

    def test_spy_parser_rejects_non_spy_text(self):
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_spy_log"]("0: C_Initialize\nP:1; T:0x1\nReturned:  0\n")

    def test_spy_parser_rejects_unordered_sequences(self):
        text = SPY_SAMPLE.read_text().replace("8: C_OpenSession", "7: C_OpenSession")
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_spy_log"](text)

    def test_spy_parser_multiplexed_accepts_per_pid_sequences(self):
        first = spy_log_text(["C_Initialize", "C_GetSlotList"], pids=[11, 11])
        second = spy_log_text(["C_Initialize", "C_GetSlotList"], pids=[22, 22])
        counts, _, _, pids, incomplete = FUNCS["parse_spy_log"](
            first + second, multiplexed=True)
        self.assertEqual(counts, {"C_Initialize": 2, "C_GetSlotList": 2})
        self.assertEqual(pids, [11, 22])
        self.assertEqual(incomplete, [])
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_spy_log"](first + second)

    def test_spy_parser_multiplexed_rejects_pid_reorder(self):
        text = spy_log_text(["C_Initialize", "C_GetSlotList", "C_OpenSession"],
                            pids=[11, 11, 11])
        text = text.replace("2: C_OpenSession", "1: C_OpenSession")
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_spy_log"](text, multiplexed=True)

    def test_workload_parser_accepts_both_orders(self):
        for ready_first in (True, False):
            expected, targets, pid = FUNCS["parse_workload"](
                "\n".join(ledger_lines(ready_first=ready_first)))
            self.assertEqual(expected, workload_ledger())
            self.assertEqual(pid, 123)
            self.assertEqual(len(targets), len(LOOP))

    def test_workload_parser_rejects_duplicates_and_gaps(self):
        base = ledger_lines()
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_workload"]("\n".join(base + ["READY pid=123"]))
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_workload"]("\n".join(base + [base[-1]]))
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_workload"]("\n".join(base[:-1]))

    def test_workload_parser_rejects_failed_calls(self):
        lines = ledger_lines()
        payload = json.loads(lines[-1][len("LEDGER "):])
        payload["functions"][0]["successful"] = 0
        lines[-1] = "LEDGER " + json.dumps(payload)
        with self.assertRaises(FUNCS["EvidenceError"]):
            FUNCS["parse_workload"]("\n".join(lines))


class JudgeTests(unittest.TestCase):
    maxDiff = 4000

    def run_case(self, mutate=None, *, cell="p11kit-proxy-pid-isolated",
                 scope="pid", metrics=False, want=0, extra=(), spy_text=None,
                 forbid_owned=False, full_targets=False, proxy_offset=False,
                 no_spy=False, workload_only=False, no_workload=False,
                 keep_ledger=False, extra_layers=()):
        report, ledger, receipt = inputs(metrics=metrics, scope=scope)
        if full_targets:
            ledger = ledger_lines(full_targets=True)
        receipt["cell"] = cell
        if spy_text is None:
            spy_text = SPY_SAMPLE.read_text()
        loaded = next(line.split('"')[1] for line in spy_text.splitlines()
                      if line.startswith("Loaded: "))
        pids = {int(line[2:].split(";")[0]) for line in spy_text.splitlines()
                if line.startswith("P:")}
        assert len(pids) == 1
        receipt["spy_loaded"] = loaded
        receipt["spy_pid"] = pids.pop()
        if mutate:
            mutate(report, ledger, receipt, spy_text)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {"report": tmp / "report", "ledger": tmp / "ledger",
                     "spy": tmp / "spy", "receipt": tmp / "receipt",
                     "proxy": tmp / "proxy.pin", "owned": tmp / "owned.pin"}
            paths["report"].write_text(json.dumps(report))
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            paths["spy"].write_text(spy_text)
            paths["receipt"].write_text(json.dumps(receipt))
            paths["proxy"].write_text(json.dumps(PROXY))
            paths["owned"].write_text(json.dumps(OWNED))
            mode = "metrics" if metrics else "profile"
            proxy_layer = "proxy:%s:workload%s" % (
                paths["proxy"], ":offset" if proxy_offset else "")
            args = [sys.executable, "-I", str(ORACLE),
                    "--report", str(paths["report"])]
            if not no_workload or keep_ledger:
                args += ["--ledger", str(paths["ledger"])]
            if not no_spy:
                args += ["--spy", str(paths["spy"])]
            if no_workload:
                args += ["--no-workload"]
            args += ["--receipt", str(paths["receipt"]),
                     "--cell", cell, "--scope", scope, "--mode", mode]
            if not no_workload:
                args += ["--layer", proxy_layer]
            if not workload_only:
                args += ["--layer", "provider:%s:spy" % paths["owned"]]
            for spec in extra_layers:
                args += ["--layer", spec % paths]
            if not no_workload:
                args += ["--target-identity", str(paths["proxy"])]
            args += extra
            if forbid_owned:
                args += ["--forbid", str(paths["owned"])]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], cell)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_strict_exact_passes(self):
        result = self.run_case(extra=("--strict",))
        self.assertEqual(result["qualification"], "p11kit-transparent")
        self.assertIn("provider: exact", result["detail"])
        self.assertIn("proxy: exact", result["detail"])
        self.assertIn("C_GetInterface=1", result["detail"])

    def test_metrics_exact_passes(self):
        self.run_case(metrics=True, extra=("--strict",))

    def test_run_scope_without_gate_passes(self):
        self.run_case(cell="p11kit-proxy-run", scope="run", extra=("--strict",))

    def test_remove_one_spy_call_fails(self):
        lines = SPY_SAMPLE.read_text().splitlines(keepends=True)
        start = next(i for i, line in enumerate(lines)
                     if line.startswith("8: C_OpenSession"))
        trimmed = "".join(lines[:start])
        self.run_case(spy_text=trimmed, extra=("--strict",), want=1)

    def test_exact_claim_with_mismatched_count_fails(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 5
        result = self.run_case(mutate, extra=("--strict",), want=1)
        self.assertIn("C_GetSlotList", result["detail"])

    def test_exact_claim_with_mismatch_fails_without_strict(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 5
        self.run_case(mutate, want=1)

    def test_deleted_owned_row_fails_without_named_gap(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"] = [row for row in report["functions"]
                                   if not (row["module"] == OWNED and
                                           row["names"] == ["C_Initialize"])]
        self.run_case(mutate, extra=("--strict",), want=1)

    def test_merge_only_skip_fails_a_strict_cell(self):
        def mutate(report, ledger, receipt, spy):
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8",
                 "reason": "module needs 6530 against the 512 ceiling"}]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        self.run_case(mutate, extra=("--strict",), want=1)

    def test_lossy_without_cover_fails(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 2
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": []}
        self.run_case(mutate, want=1)

    def test_lossy_with_covering_cause_passes(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 2
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        result = self.run_case(mutate)
        self.assertIn("covered", result["detail"])

    def test_lossy_with_named_module_passes(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"] = [row for row in report["functions"]
                                   if row["module"] != OWNED]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": []}
            report["evidence"]["modules_skipped"] = [
                {"name": "/work/libsofthsm2-owned.so",
                 "reason": "module needs 68 against the 512 ceiling"}]
        result = self.run_case(
            mutate, extra=("--module-name", "provider", "libsofthsm2-owned.so"))
        self.assertIn("covered", result["detail"])

    def test_require_exact_fails_despite_cover(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 2
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        self.run_case(mutate, extra=("--require-exact", "provider"), want=1)

    def test_phantom_observed_function_fails(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_Sign", 1))
        self.run_case(mutate, extra=("--strict",), want=1)

    def test_zero_call_rows_are_ignored(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_Sign", 0))
        self.run_case(mutate, extra=("--strict",))

    def test_unknown_row_fails_strict(self):
        def mutate(report, ledger, receipt, spy):
            bad = row(OWNED, "C_Sign", 1)
            bad["names"] = ["unknown"]
            report["functions"].append(bad)
        self.run_case(mutate, extra=("--strict",), want=1)

    def test_ambiguous_and_unresolved_rows_fail_strict(self):
        def mutate(report, ledger, receipt, spy, flag="module_ambiguous"):
            bad = row(OWNED, "C_Sign", 1)
            bad["module"] = None
            bad[flag] = True
            report["functions"].append(bad)
        for flag in ("module_ambiguous", "module_unresolved"):
            with self.subTest(flag=flag):
                self.run_case(lambda d, l, r, s, f=flag: mutate(d, l, r, s, f),
                              extra=("--strict",), want=1)

    def test_aliased_row_fails(self):
        def mutate(report, ledger, receipt, spy):
            bad = row(OWNED, "C_Sign", 1)
            bad["names"] = ["C_Sign", "C_SignRecover"]
            report["functions"].append(bad)
        self.run_case(mutate, want=1)

    def test_forbidden_identity(self):
        self.run_case(extra=("--strict",), forbid_owned=True, want=1)

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [row for row in report["functions"]
                                   if row["module"] != OWNED]
            report["evidence"]["discovery"] = [dict(PROXY, path="/proxy.so")]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        self.run_case(mutate, extra=("--require-exact", "provider"), want=1)

    def test_target_identity_mismatch_fails(self):
        def mutate(report, ledger, receipt, spy):
            ledger[1] = "TARGET " + json.dumps(
                {"name": "C_DigestInit", "dev": [8, 1], "ino": 72,
                 "file_offset": 4096})
        self.run_case(mutate, extra=("--strict",), want=1)

    def test_spy_loaded_mismatch_fails(self):
        self.run_case(lambda d, l, r, s: r.update(spy_loaded="/elsewhere.so"),
                      extra=("--strict",), want=1)

    def test_spy_pid_mismatch_fails(self):
        self.run_case(lambda d, l, r, s: r.update(spy_pid=999),
                      extra=("--strict",), want=1)

    def test_receipt_lifecycle_mismatch_fails_the_cell(self):
        self.run_case(lambda d, l, r, s: r.update(observer_exit=1), want=1)
        self.run_case(lambda d, l, r, s: r.update(ready_pid=999), want=1)

    def test_receipt_schema_mismatch_is_a_harness_error(self):
        self.run_case(lambda d, l, r, s: r.update(cell="other"), want=2)

    def test_expect_skip(self):
        present = ("--expect-skip", "libp11-kit.so.0.4.8", "module needs")
        self.run_case(extra=present, want=1)

        def mutate(report, ledger, receipt, spy):
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8",
                 "reason": "module needs 6530 against the 512 ceiling"}]
        self.run_case(mutate, extra=present)

    def test_expect_skip_verified_before_layer_failure(self):
        # Both a layer failure and a missing pin: the pin error must win,
        # proving the pin is verified, not vacuous behind the layer raise.
        def mutate(report, ledger, receipt, spy):
            report["functions"] = [row for row in report["functions"]
                                   if row["module"] != OWNED]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        result = self.run_case(
            mutate,
            extra=("--exact-only", "provider", "C_GetSlotList",
                   "--expect-skip", "libp11-kit.so.0", "kept its 410 attached endpoints"),
            want=1)
        self.assertIn("pinned skip text absent", result["detail"])

        # Control: pin present plus the same layer failure reports the
        # layer error, so pins never mask a genuine crowding verdict.
        def mutate_present(report, ledger, receipt, spy):
            report["functions"] = [row for row in report["functions"]
                                   if row["module"] != OWNED]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/libp11-kit.so.0.4.8",
                 "reason": "admitted module needs 6120 more; kept its 410 attached endpoints"}]
        result = self.run_case(
            mutate_present,
            extra=("--exact-only", "provider", "C_GetSlotList",
                   "--expect-skip", "libp11-kit.so.0", "kept its 410 attached endpoints"),
            want=1)
        self.assertIn("exact-subset", result["detail"])

    def test_expect_skip_any_disjunction(self):
        pins = ("--expect-skip-any", "liba.so", "pre-text",
                "--expect-skip-any", "liba.so", "post-text")
        result = self.run_case(extra=pins, want=1)
        self.assertIn("any of", result["detail"])

        def mutate_pre(report, ledger, receipt, spy):
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/liba.so", "reason": "blah pre-text blah"}]
        self.run_case(mutate_pre, extra=pins)

        def mutate_post(report, ledger, receipt, spy):
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/liba.so", "reason": "blah post-text blah"}]
        result = self.run_case(mutate_post, extra=pins)
        self.assertIn("provider: exact", result["detail"])

    def test_t5_post_fix_fake_flips_to_qualified(self):
        # Fake shaped like post-fix T5: providers exact, closure refused
        # whole with the admission lane's text. The disjunctive pins accept
        # it and the layers pass, so rc=0 (the shell maps rc=0 on an
        # expected cell to qualified: the flip is automatic).
        post = "a proxy closure array is admitted whole or not at all"

        def mutate(report, ledger, receipt, spy):
            report["evidence"]["modules_skipped"] = [
                {"name": "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8",
                 "reason": "module needs 6400 more; only 512 attach slots are "
                           "available; 400 are in use - refusing to attach a prefix "
                           "of its 64 lookalike function tables (%s)" % post}]
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["modules_skipped"]}
        result = self.run_case(
            mutate, cell="p11kit-proxy-pid-merge",
            extra=("--exact-only", "provider", "C_GetSlotList,C_GetSlotInfo",
                   "--spy-binding", "provider", "--forbid-unknown",
                   "--expect-skip-any", "libp11-kit.so.0.4.8",
                   "kept its 410 attached endpoints",
                   "--expect-skip-any", "libp11-kit.so.0.4.8", post))
        self.assertIn("provider: exact", result["detail"])

    def test_exact_only_subset_deficit_covered(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_Initialize"])
            target["calls"] = 0
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(
            mutate, extra=("--exact-only", "provider", "C_GetSlotList,C_GetSlotInfo"))
        self.assertIn("covered", result["detail"])

    def test_exact_only_subset_mismatch_fails(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 3
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(
            mutate, extra=("--exact-only", "provider", "C_GetSlotList,C_GetSlotInfo"),
            want=1)
        self.assertIn("exact-subset", result["detail"])

    def test_exact_only_subset_absent_from_ledger_is_harness(self):
        self.run_case(extra=("--exact-only", "provider", "C_Sign"), want=2)

    def test_cover_rejects_surplus_despite_gaps(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 5
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, want=1)
        self.assertIn("phantom", result["detail"])

    def test_cover_rejects_phantom_function_despite_gaps(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_Sign", 1))
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, want=1)
        self.assertIn("phantom", result["detail"])

    def test_forbid_unknown_without_requiring_exact(self):
        def mutate(report, ledger, receipt, spy):
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        self.run_case(mutate, extra=("--forbid-unknown",))

        def mutate_unknown(report, ledger, receipt, spy):
            bad = row(OWNED, "C_Sign", 1)
            bad["names"] = ["unknown"]
            report["functions"].append(bad)
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        self.run_case(mutate_unknown, extra=("--forbid-unknown",), want=1)

    def test_strict_reports_layer_delta_before_lossy(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_GetSlotList"])
            target["calls"] = 5
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, extra=("--strict",), want=1)
        self.assertIn("C_GetSlotList", result["detail"])

    def test_require_exact_dominates_subset(self):
        def mutate(report, ledger, receipt, spy):
            target = next(row for row in report["functions"]
                          if row["module"] == OWNED and row["names"] == ["C_Initialize"])
            target["calls"] = 0
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        self.run_case(mutate, extra=("--require-exact", "provider",
                                     "--exact-only", "provider", "C_GetSlotList"),
                      want=1)

    def test_offset_layer_exact_passes(self):
        names = list(workload_ledger())

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [
                row for row in report["functions"] if row["module"] != PROXY]
            for i, name in enumerate(names):
                unknown = row(PROXY, name, workload_ledger()[name])
                unknown["names"] = ["unknown"]
                unknown["target"]["file_offset"] = 4096 + i * 16
                report["functions"].append(unknown)
            report["functions"].append(row(PROXY, "C_Sign", 0))
        result = self.run_case(mutate, full_targets=True, proxy_offset=True,
                               extra=("--forbid-unknown",))
        self.assertIn("proxy: exact", result["detail"])

    def test_offset_layer_deficit_covered(self):
        names = list(workload_ledger())

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [
                row for row in report["functions"] if row["module"] != PROXY]
            for i, name in enumerate(names):
                calls = 0 if name == "C_Login" else workload_ledger()[name]
                unknown = row(PROXY, name, calls)
                unknown["names"] = ["unknown"]
                unknown["target"]["file_offset"] = 4096 + i * 16
                report["functions"].append(unknown)
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, full_targets=True, proxy_offset=True,
                               extra=("--forbid-unknown", "--exact-only",
                                      "proxy", ",".join(LOOP7)))
        self.assertIn("covered", result["detail"])

    def test_offset_layer_subset_mismatch_fails(self):
        names = list(workload_ledger())

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [
                row for row in report["functions"] if row["module"] != PROXY]
            for i, name in enumerate(names):
                calls = workload_ledger()[name] - (1 if name == "C_Digest" else 0)
                unknown = row(PROXY, name, calls)
                unknown["names"] = ["unknown"]
                unknown["target"]["file_offset"] = 4096 + i * 16
                report["functions"].append(unknown)
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, full_targets=True, proxy_offset=True,
                               extra=("--forbid-unknown", "--exact-only",
                                      "proxy", ",".join(LOOP7)), want=1)
        self.assertIn("C_Digest", result["detail"])

    def test_offset_layer_internal_recorded(self):
        names = list(workload_ledger())

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [
                row for row in report["functions"] if row["module"] != PROXY]
            for i, name in enumerate(names):
                unknown = row(PROXY, name, workload_ledger()[name])
                unknown["names"] = ["unknown"]
                unknown["target"]["file_offset"] = 4096 + i * 16
                report["functions"].append(unknown)
            extra = row(PROXY, "C_Sign", 2)
            extra["names"] = ["unknown"]
            extra["target"]["file_offset"] = 99999
            report["functions"].append(extra)
        result = self.run_case(mutate, full_targets=True, proxy_offset=True,
                               extra=("--forbid-unknown",))
        self.assertIn("internal", result["detail"])

    def test_offset_layer_missing_target_is_harness(self):
        self.run_case(proxy_offset=True, want=2)

    def test_offset_layer_duplicate_offset_is_harness(self):
        def mutate(report, ledger, receipt, spy):
            payload = json.loads(ledger[2][len("TARGET "):])
            payload["file_offset"] = 4096
            ledger[2] = "TARGET " + json.dumps(payload)
        self.run_case(mutate, full_targets=True, proxy_offset=True, want=2)

    def test_offset_layer_surplus_fails(self):
        names = list(workload_ledger())

        def mutate(report, ledger, receipt, spy):
            report["functions"] = [
                row for row in report["functions"] if row["module"] != PROXY]
            for i, name in enumerate(names):
                calls = workload_ledger()[name] + (1 if name == "C_Login" else 0)
                unknown = row(PROXY, name, calls)
                unknown["names"] = ["unknown"]
                unknown["target"]["file_offset"] = 4096 + i * 16
                report["functions"].append(unknown)
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, full_targets=True, proxy_offset=True,
                               extra=("--forbid-unknown", "--exact-only",
                                      "proxy", ",".join(LOOP7)), want=1)
        self.assertIn("phantom", result["detail"])

    def test_spy_binding_recorded(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_GetFunctionList", 1))
        result = self.run_case(mutate, extra=("--strict", "--spy-binding", "provider"))
        self.assertIn("binding below the spy log: 1", result["detail"])

    def test_spy_binding_bound(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_GetFunctionList", 2))
        result = self.run_case(mutate, extra=("--spy-binding", "provider"), want=1)
        self.assertIn("binding calls 2 > 1", result["detail"])

    def test_spy_binding_absent_without_flag(self):
        def mutate(report, ledger, receipt, spy):
            report["functions"].append(row(OWNED, "C_GetFunctionList", 1))
            report["evidence"]["gap_classes"]["observation"] = {
                "status": "lossy", "causes": ["loader_discovery"]}
        result = self.run_case(mutate, want=1)
        self.assertIn("phantom", result["detail"])

    def test_spy_binding_rejects_offset_layer(self):
        self.run_case(full_targets=True, proxy_offset=True,
                      extra=("--spy-binding", "proxy"), want=2)

    def test_require_pause(self):
        def mutate(report, ledger, receipt, spy):
            report["evidence"].update(
                pause="sigstop", pause_attempts=16, pause_confirmed=16,
                pause_partial=0)
        result = self.run_case(mutate, extra=("--strict", "--require-pause"))
        self.assertIn("pause confirmed", result["detail"])

        def mutate_partial(report, ledger, receipt, spy):
            report["evidence"].update(
                pause="partial", pause_attempts=11, pause_confirmed=10,
                pause_partial=1)
        self.run_case(mutate_partial, extra=("--strict", "--require-pause"), want=1)
        self.run_case(extra=("--strict", "--require-pause"), want=1)

    def test_no_spy_passes_without_spy_layers(self):
        self.run_case(extra=("--strict",), no_spy=True, workload_only=True)

    def test_spy_layer_without_spy_is_harness(self):
        self.run_case(extra=("--strict",), no_spy=True, want=2)

    def test_no_workload_passes(self):
        self.run_case(extra=("--strict",), no_workload=True)

    def test_no_workload_minimal_receipt(self):
        def mutate(report, ledger, receipt, spy):
            for key in ("launched_pid", "ready_pid", "workload_ready",
                        "capture_ready", "gate_released", "ledger_complete",
                        "spy_loaded", "spy_pid"):
                receipt.pop(key, None)
        self.run_case(mutate, extra=("--strict",), no_workload=True)

    def test_no_workload_rejects_ledger(self):
        self.run_case(no_workload=True, keep_ledger=True, want=2)

    def test_no_workload_rejects_workload_layer(self):
        self.run_case(no_workload=True,
                      extra_layers=("proxy:%(proxy)s:workload",), want=2)

    def test_no_workload_nonzero_exit_fails(self):
        self.run_case(lambda d, l, r, s: r.update(observer_exit=1),
                      no_workload=True, want=1)

    def test_missing_report_or_receipt_is_a_harness_error(self):
        proc = subprocess.run(
            [sys.executable, "-I", str(ORACLE), "--cell", "x",
             "--scope", "pid", "--mode", "profile"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_missing_layer_is_a_harness_error(self):
        report, ledger, receipt = inputs()
        receipt["cell"] = "p11kit-proxy-pid-isolated"
        spy_text = SPY_SAMPLE.read_text()
        receipt["spy_loaded"] = next(
            line.split('"')[1] for line in spy_text.splitlines()
            if line.startswith("Loaded: "))
        receipt["spy_pid"] = 764625
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            for key, value in (("report", json.dumps(report)),
                               ("ledger", "\n".join(ledger_lines()) + "\n"),
                               ("spy", SPY_SAMPLE.read_text()),
                               ("receipt", json.dumps(receipt))):
                (tmp / key).write_text(value)
            proc = subprocess.run(
                [sys.executable, "-I", str(ORACLE),
                 "--report", str(tmp / "report"), "--ledger", str(tmp / "ledger"),
                 "--spy", str(tmp / "spy"), "--receipt", str(tmp / "receipt"),
                 "--cell", "p11kit-proxy-pid-isolated",
                 "--scope", "pid", "--mode", "profile"],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)


TRUST = {"dev": [8, 1], "ino": 74, "sha256": "d" * 64}


def inventory_entry(pin, state, endpoints, reasons=()):
    return {
        "identity": {"device": {"major": pin["dev"][0], "minor": pin["dev"][1]},
                     "inode": pin["ino"], "sha256": pin["sha256"]},
        "admission": {"state": state, "endpoints": endpoints,
                      "reasons": list(reasons)},
    }


def doubled_ledger_lines():
    lines = ledger_lines()
    payload = json.loads(lines[-1][len("LEDGER "):])
    for func in payload["functions"]:
        func["attempts"] *= 2
        func["successful"] *= 2
    lines[-1] = "LEDGER " + json.dumps(payload)
    return lines


def doubled_spy_names(*, drop=0):
    names = []
    for name, count in workload_ledger().items():
        names += [name] * (2 * count)
    for _ in range(drop):
        if "C_GetFunctionList" in names:
            names.remove("C_GetFunctionList")
        else:
            names.remove("C_Digest")
    return names


def spy_log_text(names, *, pids, loaded="/owned.so"):
    lines = ["OpenSC PKCS#11 spy", 'Loaded: "%s"' % loaded]
    for seq, (pid, name) in enumerate(zip(pids, names)):
        lines += ["%d: %s" % (seq, name), "P:%d; T:0x1" % pid,
                  "Returned:  0 CKR_OK"]
    return "\n".join(lines) + "\n"


class InventoryTests(unittest.TestCase):
    def run_inventory(self, modules, *, want=0, admitted=(), refused=(),
                      module_use=None):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            inv = {"schema": "p11scope/inventory/v1", "modules": modules}
            (tmp / "inv").write_text(json.dumps(inv))
            pins = {}
            for name, pin in (("owned", OWNED), ("proxy", PROXY), ("trust", TRUST)):
                pins[name] = tmp / (name + ".pin")
                pins[name].write_text(json.dumps(pin))
            args = [sys.executable, "-I", str(ORACLE), "--cell", "CELL",
                    "--inventory", str(tmp / "inv")]
            for name, count in admitted:
                args += ["--expect-admitted", "%s:%d" % (pins[name], count)]
            for name, substring in refused:
                args += ["--expect-refused", str(pins[name]), substring]
            if module_use is not None:
                name, ledger, spy, bindings = module_use
                (tmp / "use.ledger").write_text("\n".join(ledger))
                (tmp / "use.spy").write_text(spy)
                args += ["--expect-module-use", str(pins[name]),
                         "--ledger", str(tmp / "use.ledger"),
                         "--spy", str(tmp / "use.spy"),
                         "--bindings", str(bindings)]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def test_admitted_whole_passes(self):
        modules = [inventory_entry(OWNED, "admitted", 68),
                   inventory_entry(TRUST, "admitted", 68),
                   inventory_entry(PROXY, "refused", None, ["needs 6734 more"])]
        result = self.run_inventory(
            modules, admitted=(("owned", 68), ("trust", 68)),
            refused=(("proxy", "needs 6734 more"),))
        self.assertTrue(result["pass"])
        self.assertIn("admitted whole", result["detail"])

    def test_refused_backend_fails(self):
        modules = [inventory_entry(OWNED, "refused", None, ["needs 68 more"])]
        result = self.run_inventory(modules, admitted=(("owned", 68),), want=1)
        self.assertIn("not admitted whole", result["detail"])

    def test_wrong_endpoint_count_fails(self):
        modules = [inventory_entry(OWNED, "admitted", 67)]
        self.run_inventory(modules, admitted=(("owned", 68),), want=1)

    def test_absent_identity_fails(self):
        self.run_inventory([], admitted=(("owned", 68),), want=1)

    def test_missing_pin_text_fails(self):
        modules = [inventory_entry(PROXY, "refused", None, ["other reason"])]
        self.run_inventory(modules, refused=(("proxy", "needs 6734 more"),), want=1)

    def test_admitted_when_refusal_expected_fails(self):
        modules = [inventory_entry(PROXY, "admitted", 410)]
        self.run_inventory(modules, refused=(("proxy", "needs"),), want=1)

    def use_case(self, *, entries, drop=2, bindings=2, pids=None):
        ledger = doubled_ledger_lines()
        names = doubled_spy_names(drop=drop) + ["C_GetInterface"] * bindings
        if pids is None:
            half = len(names) // 2
            first, second = names[:half], names[half:]
            spy = (spy_log_text(first, pids=[123] * len(first))
                   + spy_log_text(second, pids=[124] * len(second)))
        else:
            spy = spy_log_text(names, pids=pids)
        entry = inventory_entry(OWNED, "admitted", 68)
        entry["unbound_use"] = {"first_ns": 1, "rows": bindings,
                                "reasons": ["before-admission"],
                                "entries": entries}
        return [entry], ("owned", ledger, spy, bindings)

    def test_module_use_exact_passes(self):
        modules, use = self.use_case(entries=44)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use)
        self.assertTrue(result["pass"])
        self.assertIn("module use", result["detail"])

    def test_module_use_short_entries_fails(self):
        modules, use = self.use_case(entries=43)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use, want=1)
        self.assertIn("module use", result["detail"])

    def test_module_use_over_entries_fails(self):
        # Observer overcount (folded entries above spy + bindings) must
        # fail: the equation is exact, not a lower bound.
        modules, use = self.use_case(entries=45)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use, want=1)
        self.assertIn("module use", result["detail"])

    def test_module_use_spy_shortfall_fails(self):
        modules, use = self.use_case(entries=44, drop=3)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use, want=1)
        self.assertIn("module use", result["detail"])

    def test_module_use_correlated_loss_fails(self):
        # Drop-detection isolation: entries still match the spy stream
        # (43 == 41 + 2), so only the drop check can reject the spy's
        # shortfall against the ledger (41 < 44 - 2).
        modules, use = self.use_case(entries=43, drop=3)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use, want=1)
        self.assertIn("calls were dropped", result["detail"])

    def test_module_use_proxy_surplus_passes(self):
        modules, use = self.use_case(entries=45, drop=1)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use)
        self.assertTrue(result["pass"])
        self.assertIn("surplus +1", result["detail"])

    def test_module_use_pid_mismatch_fails(self):
        modules, use = self.use_case(entries=46, pids=[123] * 44)
        result = self.run_inventory(modules, admitted=(("owned", 68),),
                                    module_use=use, want=1)
        self.assertIn("module use", result["detail"])


SHELL = ROOT / "scripts/ci/p11kit-transparency.sh"

JUDGE_HARNESS = r"""
set -u
SH=%s; CELL="$1"; STUB_RC="$2"; STUB_DETAIL="$3"; MODE="$4"; shift 4
P11KIT_EXPECT_LEGACY32=1
eval "$(sed -n '/^declare -A EXPECTED_FAIL=(/,/^fi/p' "$SH")"
eval "$(sed -n '/^judge() {/,/^}/p' "$SH")"
eval "$(sed -n '/^judge_composite() {/,/^}/p' "$SH")"
result() { printf 'QUAL=%%s\n' "$4"; }
judge_capture() { JUDGE_RC="$STUB_RC"; JUDGE_DETAIL="$STUB_DETAIL"; }
if [ "$MODE" = judge ]; then
  judge "$CELL" dummy
else
  judge_composite "$CELL" "$STUB_DETAIL" "$@"
fi
""" % repr(str(SHELL))


class JudgeSignatureTests(unittest.TestCase):
    """The shell judge marks expected-failure only for the named bug's
    signature (EXPECTED_DETAIL); any other rc=1 stays failed. The real
    judge() and judge_composite() bodies are extracted verbatim from the
    script and run with a stubbed capture, so the test follows the code."""

    def run_judge(self, cell, rc, detail, mode="judge", rcs=()):
        proc = subprocess.run(
            ["bash", "-c", JUDGE_HARNESS, "_", cell, str(rc), detail, mode, *rcs],
            capture_output=True, text=True, timeout=10)
        return proc

    def test_t5_wrong_reason_stays_failed(self):
        proc = self.run_judge("p11kit-proxy-pid-merge", 1,
                              "gate was not safely released")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("QUAL=failed", proc.stdout)
        # Positive control: the crowding signature still maps as expected.
        proc = self.run_judge(
            "p11kit-proxy-pid-merge", 1,
            "provider: observed {} differs from ledger {x} (exact-subset delta {y})")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("QUAL=expected-failure", proc.stdout)

    def test_t5b_wrong_reason_stays_failed(self):
        proc = self.run_judge("p11kit-real-trust", 1,
                              "gate was not safely released")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("QUAL=failed", proc.stdout)
        proc = self.run_judge(
            "p11kit-real-trust", 1,
            "trust: observed {} differs from ledger {x} (delta {y})")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("QUAL=expected-failure", proc.stdout)

    def test_t7_legacy32_wrong_reason_stays_failed(self):
        proc = self.run_judge(
            "p11kit-remote", 1,
            "client(rc=0): ok || server(rc=1): gate was not safely released",
            mode="composite", rcs=("0", "1"))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("QUAL=failed", proc.stdout)
        proc = self.run_judge(
            "p11kit-remote", 1,
            "client(rc=0): ok || server(rc=1): unattributed calls where none "
            "are allowed: unknown=68 ambiguous=0 unresolved=0",
            mode="composite", rcs=("0", "1"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("QUAL=expected-failure", proc.stdout)


if __name__ == "__main__":
    unittest.main()
