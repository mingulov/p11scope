#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Count-only B gets its own held physical calibration, never S1 attestation."""

import copy
import json
import os
from pathlib import Path
import runpy
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SYSTEM = runpy.run_path(str(ROOT / "tests/python/test_inventory_system_sibling.py"))
H6 = SYSTEM["H6"]


class ReachedMeasurement(Exception):
    pass


class InventoryCountOnlyHooksTest(unittest.TestCase):
    def prepare(self, fault=None):
        temporary = tempfile.TemporaryDirectory(prefix="h6-count-only-hooks-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = directory / "ledger-input"
        source.write_bytes(b"fixture executable; never executed")
        blob = bytearray(0x500)
        blob[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", blob, 16,
            3, 62, 1, 0, 64, 0x300, 0, 64, 56, 1, 64, 3, 2)
        struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0x200, 0x1200, 0x1200, 0x80, 0x80, 0x1000)
        names = b"\0C_GetFunctionList\0C_Initialize\0"
        blob[0x400:0x400 + len(names)] = names
        struct.pack_into("<IIQQQQIIQQ", blob, 0x340, 0, 11, 0, 0, 0x280, 72, 2, 0, 8, 24)
        struct.pack_into("<IIQQQQIIQQ", blob, 0x380, 0, 3, 0, 0, 0x400, len(names), 0, 0, 1, 0)
        offsets = {"C_GetFunctionList": 0x220, "C_Initialize": 0x240}
        for index, (name, offset) in enumerate(offsets.items(), 1):
            struct.pack_into("<IBBHQQ", blob, 0x280 + index * 24,
                names.index(name.encode()), 0x12, 0, 1, offset + 0x1000, 1)
        provider_path = directory / "provider-A.so"
        provider_path.write_bytes(blob)
        provider = H6["FilePin"](provider_path)
        self.addCleanup(provider.close)
        ctx = SimpleNamespace(args=SimpleNamespace(uid=os.getuid(), gid=os.getgid()),
            pins={"ledger": SimpleNamespace(path=source)}, provider_pin=provider,
            discover_pin=object(), leg_pins=[], owners=[], readers=[])
        self.addCleanup(lambda: [pin.close() for pin in ctx.leg_pins])
        self.ctx, self.calls, self.observer_manifests, self.hooks = ctx, [], None, None
        cell = directory / "system"
        def manifest(_discover, path, output, _env, _uid, _gid):
            pin = next(pin for pin in [provider, *ctx.leg_pins] if pin.path == Path(path))
            held = H6["provider_receipt"](pin)
            result = {"schema": "p11scope-manifest/5", "objects": [{"id": 0, "path": str(path),
                "identity": {"sha256": held["sha256"]}}], "provenance_objects": [{"path": str(path),
                "device_major": held["dev"][0], "device_minor": held["dev"][1], "inode": held["ino"],
                "identity": {"sha256": held["sha256"]}}], "surfaces": [{"acquisition": {"status": "ok"},
                "functions": [{"name": name, "resolution": {"status": "resolved", "object": 0,
                    "file_offset": offset}} for name, offset in offsets.items()]}]}
            if Path(path).name == "provider-B.so":
                provenance = result["provenance_objects"][0]
                getter = result["surfaces"][0]["functions"][0]["resolution"]
                if fault == "borrow-A-inode":
                    provenance["inode"] = provider.initial.st_ino
                elif fault == "wrong-device":
                    provenance["device_minor"] += 1
                elif fault == "wrong-digest":
                    result["objects"][0]["identity"]["sha256"] = "f" * 64
                elif fault == "wrong-getter":
                    getter["file_offset"] = 0x240
                elif fault == "foreign-getter":
                    getter["object"] = 1
            Path(output).write_text(json.dumps(result))
            self.calls.append((Path(path), Path(output)))
            return result
        def spawn(*_args):
            return SimpleNamespace(pid=100 + len(self.calls)), None, None
        def observer(_ctx, _directory, _scope, _modules, manifests, *_args):
            self.observer_manifests = manifests
            return None, None, None, 1, cell / "doc", cell / "log"
        def phases(*_args, **kwargs):
            self.hooks = kwargs["physical_hooks"]
            raise ReachedMeasurement
        self.patches = {"init_token": lambda *_: {}, "build_manifest": manifest,
            "spawn_ledger": spawn, "InventoryController": lambda owner, *_: SimpleNamespace(
                owner=owner, ready=lambda *_: None), "wait_ledger_line": lambda *_args, **_kwargs: None,
            "seize_until_exec": lambda *_: None, "spawn_inventory": observer,
            "wait_inventory_ready": lambda *_: 1, "wait_passes": lambda *_: None,
            "inventory_target_phases": phases}
        self.cell = cell

    def run_route(self):
        route = H6["run_system_mixed"].__wrapped__
        with mock.patch.dict(route.__globals__, self.patches):
            route(self.ctx, self.cell, "singles")

    def test_B_getter_uses_its_own_calibration_while_observer_attests_only_A(self):
        self.prepare()
        with self.assertRaises(ReachedMeasurement):
            self.run_route()
        b = self.cell / "singles/inventory/provider-B.so"
        self.assertEqual([path for path, _ in self.calls], [self.ctx.provider_pin.path, b])
        self.assertEqual(self.observer_manifests, ["--manifest", str(self.calls[0][1])])
        self.assertNotIn(str(self.calls[1][1]), self.observer_manifests)
        a_hook, b_hook = self.hooks[str(self.ctx.provider_pin.path)], self.hooks[str(b)]
        self.assertEqual(a_hook["provider"]["sha256"], b_hook["provider"]["sha256"])
        self.assertNotEqual(a_hook["provider"]["ino"], b_hook["provider"]["ino"])
        self.assertEqual(b_hook["getter_export_offset"], 0x220)
        batches = [{"pid": 101, "gen": 0, "module": str(b), "phase": "h6-warm1",
                    "t0": 10, "t1": 20, "fn": fn, "n": n, "bad": 0, "mech": "-"}
                   for fn, n in (("C_GetFunctionList", 1), ("C_Initialize", 17))]
        self.assertEqual(H6["counted_totals"](batches, 0, physical_hooks=self.hooks)[(101, 0, str(b))], 18)
        self.assertEqual(H6["counted_totals"](batches, 0,
            physical_hooks={str(self.ctx.provider_pin.path): a_hook})[(101, 0, str(b))], 17)
        self.assertEqual(H6["ledger_s1_totals"](batches, 0)[5][(101, 0, str(b))], 17)

    def test_wrong_B_custody_or_table_getter_refuses_before_observer_start(self):
        for fault in ("borrow-A-inode", "wrong-device", "wrong-digest", "wrong-getter", "foreign-getter"):
            with self.subTest(fault=fault):
                self.prepare(fault)
                with self.assertRaises(H6["SetupError"]):
                    self.run_route()
                self.assertIsNone(self.observer_manifests)

    def test_composed_B_physical_counts_include_getter_but_S1_stays_unattested(self):
        doc, ledgers, receipt = SYSTEM["controlled_inputs"]()
        b = receipt["providers"]["B"]["path"]
        ledger = [row for row in ledgers["MS"]["batches"] if row["module"] == b]
        self.assertEqual(sum(row["n"] for row in ledger), 48)
        self.assertEqual(sum(row["n"] for row in ledger if row["fn"] != "C_GetFunctionList"), 47)
        physical = [row["event"]["entries"]["count"] for row in receipt["inventory_control"]["final_records"]
            if row["kind"] == "edge_observed" and row["event"]["caller"] == "c1"
            and row["event"]["module"] == "m1" and row["event"]["entries"]["count"] > 0]
        self.assertEqual(physical[0], 18)
        self.assertEqual(physical[-1], 48)
        self.assertIn(b, receipt["physical_hooks"])
        self.assertEqual(H6["counted_totals"](ledger, 0,
            physical_hooks=receipt["physical_hooks"])[(2000, 0, b)], 48)
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(receipt["count_only_providers"], ["B"])
        bad = copy.deepcopy(doc)
        row = copy.deepcopy(bad["semantic_edges"][0])
        row.update(caller="c1", module="m1", instance="i9")
        bad["semantic_edges"].append(row)
        result = H6["evaluate_inventory_h6"](bad, ledgers, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("count-only provider publishes semantic positives" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
