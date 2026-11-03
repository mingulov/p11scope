# SPDX-License-Identifier: GPL-3.0-or-later
"""Real-provider oracle controls: spy ledger parsing and cause ratchet."""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/real-provider-oracle.py"
FIXTURES = ROOT / "tests/fixtures/real-providers"

ORACLE_MOD = runpy.run_path(str(ORACLE))

OWNED = {"dev": [8, 1], "ino": 71, "sha256": "a" * 64}
SPY = {"dev": [8, 1], "ino": 72, "sha256": "b" * 64}
SPY_PATH = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"


def provider_pin(identity=OWNED):
    return dict(identity,
                file_identity={"dev": [0, 38], "ino": identity["ino"], "size": 8192,
                               "mtime_ns": 123, "ctime_ns": 456},
                mapping={"dev": list(identity["dev"]), "ino": identity["ino"], "file_offset": 0,
                         "length": 4096, "permissions": "r--p"})


def receipt(cell="real-pkcs11tool-softhsm", mode="profile"):
    return {"schema": "p11scope/real-provider-receipt/v1", "cell": cell, "mode": mode,
            "tool": "pkcs11-tool", "tool_version": "0.27.0~rc1-1", "os_id": "ubuntu",
            "spied_module": SPY_PATH, "provider_before": provider_pin(),
            "provider_after": provider_pin(), "run_exit": 0, "p11kit_version": "0.26.2-2"}


def expects(cell="real-pkcs11tool-softhsm", causes=(), pause="sigstop", skip=None):
    pause_reasons = {"sigstop": ("pause confirmed on every owner", "exec-real-providers"),
                     "partial": ("OpenSC partial pause; exec-real-providers lane",
                                 "exec-real-providers")}
    reason, owner = pause_reasons[pause]
    entry = {"os": "ubuntu", "tool_version": "0.27.0~rc1-1", "p11kit_version": None,
             "observation": [{"cause": cause, "reason": "pinned gap %s" % cause,
                              "owner": "exec-real-providers"} for cause in causes],
             "pause": {"status": pause, "reason": reason, "owner": owner},
             "p11kit_skip": skip}
    if skip is not None:
        entry["p11kit_version"] = "0.26.2-2"
    return {"schema": "p11scope/real-provider-expected-causes/v1", "cells": {cell: [entry]}}


def report_functions(counts, causes=(), pause="sigstop", mode="profile", cell_module=OWNED,
                    skips=()):
    schema = "p11scope/observed-profile/v3-metrics" if mode == "metrics" else \
        "p11scope/observed-profile/v3"
    functions = []
    for index, (name, calls) in enumerate(sorted(counts.items())):
        functions.append({"names": [name], "calls": calls, "errors": 0, "in_flight": 0,
                          "pending_returns": 0, "module": dict(cell_module),
                          "module_ambiguous": False, "module_unresolved": False,
                          "target": {"object": dict(cell_module), "file_offset": 4096 + index * 16}})
    # A spy-module row the oracle must ignore: same call, other identity.
    functions.append({"names": ["C_Initialize"], "calls": 1, "errors": 0, "in_flight": 0,
                      "pending_returns": 0, "module": dict(SPY), "module_ambiguous": False,
                      "module_unresolved": False,
                      "target": {"object": dict(SPY), "file_offset": 4096}})
    return {"schema": schema, "lane": mode, "capture": {"scope": "run", "mode": mode},
            "functions": functions,
            "evidence": {"pause": pause,
                         "gap_classes": {"observation": {"status": "exact" if not causes else "lossy",
                                                         "causes": list(causes)}},
                         "discovery": [dict(OWNED), dict(SPY)],
                         "modules_skipped": list(skips)}}


def spy_log(counts, loaded=SPY_PATH):
    lines = ["", "", "*************** OpenSC PKCS#11 spy *****************",
             'Loaded: "%s"' % loaded, ""]
    seq = 0
    for name in sorted(counts):
        for _ in range(counts[name]):
            lines += ["%d: %s" % (seq, name),
                      "P:1234; T:0x1 2026-11-03 02:47:22.086",
                      "Returned:  0 CKR_OK", ""]
            seq += 1
    return "\n".join(lines) + "\n"


COUNTS = {"C_Finalize": 1, "C_GetInterface": 1, "C_GetSlotInfo": 2,
          "C_GetSlotList": 2, "C_GetTokenInfo": 2, "C_Initialize": 1}


class SpyParserTests(unittest.TestCase):
    def test_real_softhsm_log_parses_exactly(self):
        loaded, counts = ORACLE_MOD["parse_spy_log"](
            (FIXTURES / "spy-sample-softhsm.log").read_text())
        self.assertEqual(loaded, SPY_PATH)
        self.assertEqual(counts, COUNTS)

    def test_real_opensc_log_parses_exactly(self):
        loaded, counts = ORACLE_MOD["parse_spy_log"](
            (FIXTURES / "spy-sample-opensc.log").read_text())
        self.assertEqual(loaded, "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
        self.assertEqual(counts, {"C_Finalize": 1, "C_GetInterface": 1,
                                  "C_GetSlotList": 1, "C_Initialize": 1})

    def test_shared_log_with_restarted_sequences_parses(self):
        text = (FIXTURES / "spy-sample-opensc.log").read_text()
        loaded, counts = ORACLE_MOD["parse_spy_log"](text + text)
        self.assertEqual(counts["C_Initialize"], 2)
        self.assertEqual(sum(counts.values()), 8)

    def test_truncated_entry_fails(self):
        text = spy_log(COUNTS) + "9: C_Initialize\nP:1; T:0x1 2026-11-03 02:47:22.086\n"
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["parse_spy_log"](text)

    def test_missing_header_fails(self):
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["parse_spy_log"]("0: C_Initialize\nReturned:  0 CKR_OK\n")

    def test_unset_spy_module_is_a_harness_error(self):
        with self.assertRaises(ORACLE_MOD["HarnessError"]):
            ORACLE_MOD["parse_spy_log"]("Error: no module specified. Please set PKCS11SPY environment.\n")

    def test_two_spied_modules_fails(self):
        text = spy_log({"C_Initialize": 1}, loaded="/a.so") + \
            spy_log({"C_Initialize": 1}, loaded="/b.so")
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["parse_spy_log"](text)

    def test_empty_log_fails(self):
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["parse_spy_log"](
                "*************** OpenSC PKCS#11 spy *****************\nLoaded: \"/a.so\"\n")


class JudgeTests(unittest.TestCase):
    def judge(self, counts=COUNTS, causes=(), pause="sigstop", mode="profile",
              tool_version="0.27.0~rc1-1", skip=None, mutate=None):
        skips = ({"subject": "libp11-kit",
                  "reason": "module needs %d more; only 512 slots are available" % skip},) \
            if skip is not None else ()
        doc = report_functions(counts, causes, pause, mode, skips=skips)
        rec = receipt(mode=mode)
        rec["tool_version"] = tool_version
        exp = expects(causes=causes, pause=pause, skip=skip)
        if mutate:
            mutate(doc, rec, exp)
        return ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS), rec, exp, rec["cell"])

    def test_qualified(self):
        qualification, detail = self.judge()
        self.assertEqual(qualification, "qualified")
        self.assertIn("match the independent ledger", detail)

    def test_expected_failure_pins_pause_and_causes(self):
        qualification, detail = self.judge(causes=("pause_partial", "loader_discovery"),
                                           pause="partial")
        self.assertEqual(qualification, "expected-failure")
        self.assertIn("pause_partial", detail)
        self.assertIn("partial", detail)

    def test_tool_exit_nonzero_fails(self):
        doc = report_functions(COUNTS)
        rec = receipt()
        rec["run_exit"] = 1
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS), rec, expects(), rec["cell"])

    def test_mutated_spy_count_fails(self):
        doc = report_functions(COUNTS)
        rec = receipt()
        bad = dict(COUNTS)
        bad["C_GetSlotList"] += 1
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(bad), rec, expects(), rec["cell"])

    def test_dropped_expected_cause_fails(self):
        def mutate(doc, rec, exp):
            exp["cells"][rec["cell"]][0]["observation"] = []
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(causes=("pause_partial",), pause="partial", mutate=mutate)

    def test_new_cause_fails(self):
        doc = report_functions(COUNTS, causes=("event_loss",))
        rec = receipt()
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS), rec, expects(), rec["cell"])

    def test_pause_regression_fails(self):
        doc = report_functions(COUNTS, pause="partial")
        rec = receipt()
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS), rec, expects(), rec["cell"])

    def test_pause_fix_against_stale_pin_fails(self):
        doc = report_functions(COUNTS, causes=("pause_partial",), pause="sigstop")
        rec = receipt()
        exp = expects(causes=("pause_partial",), pause="partial")
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS), rec, exp, rec["cell"])

    def test_spied_ledger_mismatch_fails(self):
        doc = report_functions(COUNTS)
        rec = receipt()
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            ORACLE_MOD["judge"](json.dumps(doc), spy_log(COUNTS, loaded="/other.so"),
                                 rec, expects(), rec["cell"])

    def test_unknown_spied_row_fails(self):
        def mutate(doc, rec, exp):
            doc["functions"][0]["names"] = ["unknown"]
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(mutate=mutate)

    def test_spied_module_not_admitted_fails(self):
        def mutate(doc, rec, exp):
            doc["evidence"]["discovery"] = [dict(SPY)]
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(mutate=mutate)

    def test_changed_spied_identity_fails(self):
        def mutate(doc, rec, exp):
            rec["provider_after"] = provider_pin(SPY)
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(mutate=mutate)

    def test_p11kit_skip_names_pinned_count(self):
        qualification, _ = self.judge(causes=("modules_skipped",), skip=6530)
        self.assertEqual(qualification, "expected-failure")

    def test_p11kit_skip_wrong_count_fails(self):
        def mutate(doc, rec, exp):
            doc["evidence"]["modules_skipped"][0]["reason"] = \
                "module needs 100 more; only 512 slots are available"
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(causes=("modules_skipped",), skip=6530, mutate=mutate)

    def test_p11kit_version_drift_fails(self):
        def mutate(doc, rec, exp):
            rec["p11kit_version"] = "0.26.3-1"
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(causes=("modules_skipped",), skip=6530, mutate=mutate)

    def test_metrics_twin_with_skips_fails(self):
        def mutate(doc, rec, exp):
            doc["evidence"]["modules_skipped"] = [
                {"subject": "x", "reason": "module needs 10 more; only 512 slots are available"}]
        with self.assertRaises(ORACLE_MOD["EvidenceError"]):
            self.judge(mode="metrics", mutate=mutate)

    def test_unknown_host_pin_is_a_harness_error(self):
        with self.assertRaises(ORACLE_MOD["HarnessError"]):
            self.judge(tool_version="9.9.9")

    def test_pin_without_reason_is_a_harness_error(self):
        def mutate(doc, rec, exp):
            exp["cells"][rec["cell"]][0]["observation"][0]["reason"] = ""
        with self.assertRaises(ORACLE_MOD["HarnessError"]):
            self.judge(causes=("pause_partial",), pause="partial", mutate=mutate)


class CliTests(unittest.TestCase):
    def run_oracle(self, doc, rec, exp, spy):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, payload in (("report", doc), ("receipt", rec),
                                  ("expect", exp), ("spy", spy)):
                path = Path(tmp) / name
                path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
                paths[name] = str(path)
            proc = subprocess.run([sys.executable, "-I", str(ORACLE),
                                   "--report", paths["report"], "--spy", paths["spy"],
                                   "--receipt", paths["receipt"], "--expect", paths["expect"],
                                   "--cell", rec["cell"]],
                                  capture_output=True, text=True)
            return proc.returncode, json.loads(proc.stdout)

    def test_cli_qualified_exits_zero(self):
        doc = report_functions(COUNTS)
        code, row = self.run_oracle(doc, receipt(), expects(), spy_log(COUNTS))
        self.assertEqual(code, 0)
        self.assertEqual(row["qualification"], "qualified")
        self.assertTrue(row["pass"])

    def test_cli_expected_failure_exits_three(self):
        doc = report_functions(COUNTS, causes=("pause_partial",), pause="partial")
        rec = receipt()
        exp = expects(causes=("pause_partial",), pause="partial")
        code, row = self.run_oracle(doc, rec, exp, spy_log(COUNTS))
        self.assertEqual(code, 3)
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertTrue(row["pass"])

    def test_cli_failed_exits_one(self):
        doc = report_functions(COUNTS)
        rec = receipt()
        rec["run_exit"] = 1
        code, row = self.run_oracle(doc, rec, expects(), spy_log(COUNTS))
        self.assertEqual(code, 1)
        self.assertEqual(row["qualification"], "failed")
        self.assertFalse(row["pass"])

    def test_cli_harness_error_exits_two(self):
        doc = report_functions(COUNTS)
        rec = receipt()
        code, row = self.run_oracle(doc, rec, {"schema": "wrong"}, spy_log(COUNTS))
        self.assertEqual(code, 2)
        self.assertFalse(row["pass"])


if __name__ == "__main__":
    unittest.main()
