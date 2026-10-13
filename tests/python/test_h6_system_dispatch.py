#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise System cell aggregation through the owned leg, without processes."""

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))


class SystemDispatchTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="h6-system-dispatch-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        source = self.directory / "input"
        source.write_bytes(b"dispatch fixture; never executed or mapped\n")
        provider = H6["FilePin"](source)
        self.addCleanup(provider.close)
        self.ctx = H6["Case"](SimpleNamespace(out=self.directory,
            uid=os.getuid(), gid=os.getgid()))
        self.ctx.pins = {"ledger": provider}
        self.ctx.provider_pin = self.ctx.discover_pin = provider
        self.previous = {"cell": "pid-leader", "leg": "trace/singles", "pass": True}
        self.ctx.completed_results.append(self.previous)
        self.verdict = {"cell": "system-mixed", "leg": "inventory/singles",
            "pass": True, "status": "pass", "errors": [], "physical_counted": 48}
        self.owners, self.receipts = [], []
        self.output = io.StringIO()
        self.oracle = mock.Mock(side_effect=self.evaluate)
        self.ready = mock.Mock(return_value=2)
        self.phases = mock.Mock(return_value={"cursor": object(), "freeze": {},
            "proofs": [], "measurements": [], "stages": [], "teardown": {},
            "sibling_baseline": {}})
        self.patches = {
            "init_token": lambda *_: {}, "build_manifest": lambda *_: {},
            "inventory_manifest_hooks": lambda *_: {},
            "spawn_ledger": self.spawn_ledger,
            "InventoryController": lambda owner, *_: SimpleNamespace(owner=owner,
                ready=lambda *_: None, command=lambda *_: None),
            "wait_ledger_line": lambda *_args, **_kwargs: None,
            "seize_until_exec": lambda *_: None, "ptrace_detach_running": lambda *_: None,
            "spawn_inventory": self.spawn_inventory,
            "wait_inventory_ready": self.ready, "wait_passes": lambda *_: None,
            "inventory_target_phases": self.phases,
            "stop_inventory": lambda *_: (0, 30, 0), "stop_receipt": lambda *_: {},
            "inventory_final_records": lambda *_: [], "wait_process": lambda *_: 0,
            "finish_readers": lambda *_: None,
            "parse_inv_ledger": lambda *_: {"batches": []},
            "phase_window": lambda *_: (10, 20, 0),
            "provider_receipt": lambda pin: {"path": str(pin.path)},
            "evaluate_inventory_h6": self.oracle,
        }

    def spawn_ledger(self, *_args):
        # Only process I/O is mocked; dispatcher, owned_leg, files and pin cleanup run.
        owner = SimpleNamespace(pid=100 + len(self.owners), popen=mock.Mock())
        self.owners.append(owner)
        return owner, SimpleNamespace(lines=[], wait=lambda *_: None), object()

    def spawn_inventory(self, _ctx, directory, *_args):
        document = directory / "inventory.json"
        document.write_text("{}\n")
        return object(), object(), object(), 1, document, directory / "inventory.jsonl"

    def evaluate(self, doc, ledgers, receipt):
        self.receipts.append(receipt)
        if receipt.get("backend_refused"):
            return H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        return self.verdict

    def dispatch(self):
        with mock.patch.dict(H6["run_cell_backend"].__globals__, self.patches), \
                contextlib.redirect_stdout(self.output):
            return H6["run_cell_backend"](self.ctx, "system-mixed", "singles")

    def coverage(self, results):
        return H6["required_recovery_coverage"](
            [("system-mixed", "singles", results)], ["system-mixed"], ["singles"])

    def assert_completed_once(self, results):
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertEqual(self.ctx.completed_results, [self.previous, results[0]])
        self.assertIs(self.ctx.completed_results[-1], results[0])
        self.assertEqual(self.ctx.cleanup_totals["pins"], 3)
        self.assertFalse(self.ctx.cleanup_failed)
        self.assertEqual(len(self.output.getvalue().splitlines()), 1)
        saved = self.directory / "system-mixed/singles/inventory/result.json"
        self.assertEqual(json.loads(saved.read_text()), results[0])

    def test_system_normal_result_reaches_required_coverage_as_one_list_item(self):
        results = self.dispatch()
        self.assert_completed_once(results)
        self.assertIs(results[0], self.verdict)
        self.assertTrue(self.coverage(results)["complete"])
        self.assertEqual(self.coverage(results)["positive"], 1)
        self.phases.assert_called_once()

    def test_system_oracle_failure_remains_nonpositive_without_aggregation_error(self):
        self.verdict.update({"pass": False, "status": "fail", "errors": ["exact count differs"]})
        results = self.dispatch()
        self.assert_completed_once(results)
        self.assertIs(results[0], self.verdict)
        coverage = self.coverage(results)
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["nonpositive"], [
            {"cell": "system-mixed", "leg": "inventory/singles", "pass": False, "status": "fail"}])

    def test_system_backend_refusal_is_one_negative_result_not_a_missing_leg(self):
        self.ready.side_effect = H6["BackendRefused"]("controlled backend refusal")
        results = self.dispatch()
        self.assert_completed_once(results)
        self.assertEqual(results[0]["status"], "negative")
        self.assertEqual(results[0]["negative_reason"], "controlled backend refusal")
        self.assertEqual(results[0]["errors"], ["backend refused: controlled backend refusal"])
        coverage = self.coverage(results)
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["missing"], [])
        self.assertEqual(coverage["nonpositive"][0]["status"], "negative")
        self.phases.assert_not_called()
        self.assertTrue(all(owner.popen.send_signal.call_count == 1 for owner in self.owners))

    def test_system_cleanup_failure_does_not_record_the_unsettled_verdict(self):
        cleanup = H6["cleanup_leg_resources"]
        def refuse_after_pin_cleanup(scope):
            cleanup(scope)
            raise H6["LegCleanupError"]("controlled cleanup failure")
        self.patches["cleanup_leg_resources"] = refuse_after_pin_cleanup
        results = self.dispatch()
        self.assertEqual(self.ctx.completed_results, [self.previous])
        self.assertTrue(self.ctx.cleanup_failed)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "error")
        self.assertEqual(results[0]["errors"], ["LegCleanupError: controlled cleanup failure"])
        self.assertFalse(self.coverage(results)["complete"])

    def test_system_setup_error_is_preserved_as_an_error_result(self):
        self.phases.side_effect = H6["SetupError"]("controlled phase failure")
        results = self.dispatch()
        self.assertEqual(self.ctx.completed_results, [self.previous])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "error")
        self.assertEqual(results[0]["errors"], ["SetupError: controlled phase failure"])
        self.oracle.assert_not_called()
        self.assertFalse(self.coverage(results)["complete"])

    def test_system_unexpected_programming_error_still_propagates_after_cleanup(self):
        self.phases.side_effect = AttributeError("controlled programming failure")
        with self.assertRaisesRegex(AttributeError, "controlled programming failure"):
            self.dispatch()
        self.assertEqual(self.ctx.completed_results, [self.previous])
        self.assertEqual(self.ctx.cleanup_totals["pins"], 3)
        self.oracle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
