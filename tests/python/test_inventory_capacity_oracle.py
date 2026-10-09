# SPDX-License-Identifier: GPL-3.0-or-later
"""Capacity oracle controls use independent target ledgers, never observer totals."""

import copy
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/inventory-native-oracle.py"
SHELL = ROOT / "scripts/qualify-inventory-native.sh"


def population():
    providers = []
    for index in range(97):
        offsets = [4096 + 16 * offset for offset in range(68 if index < 96 else 3)]
        providers.append({"key": f"p{index}", "path": f"/owned/{index}.so",
                          "pin": {"dev": [0, 35], "ino": 100 + index,
                                  "sha256": "a" * 64},
                          "offsets": offsets + [offsets[-1]]})
    owner = {"pid": 4000, "start_time": 50, "exe": "/owned/driver",
             "providers": [provider["key"] for provider in providers], "ledger": "owner.jsonl"}
    ledger = [{"kind": "owner", **{key: owner[key] for key in ("pid", "start_time", "exe")}}]
    for provider in providers:
        ledger.append({"kind": "surface", "pid": 4000, "start_time": 50,
                       "path": provider["path"], "dev": [0, 35],
                       "ino": provider["pin"]["ino"], "offsets": provider["offsets"]})
        index = int(provider["key"][1:])
        phases = ("initial", "middle", "late") if index < 32 else ("middle", "late") if index < 61 else ("late",)
        for phase in phases:
            ledger.append({"kind": "call", "pid": 4000, "start_time": 50,
                           "path": provider["path"], "offset": 4096, "phase": phase,
                           "n": 3, "rv": 0, "t0": {"initial": 100, "middle": 200, "late": 300}[phase],
                           "t1": {"initial": 110, "middle": 210, "late": 310}[phase]})
    document = {"schema": "p11scope/inventory/v1", "scope": "system",
                "budgets": {"inventory_endpoints": {"limit": 8192, "occupied": 2176, "refused": 0}},
                "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
                "observation": {"lane": "native", "started_ns": 50, "ended_ns": 500}, "gaps": [], "gaps_suppressed": 0,
                "modules": [], "callers": [{"id": "c0", "pid": 4000, "start_time": 50,
                                             "image": {"authority": "native_exact"}}], "edges": []}
    for index, provider in enumerate(providers):
        document["modules"].append({"id": f"m{index}", "paths": [provider["path"]],
                                    "identity": {"device": {"major": 0, "minor": 35},
                                                 "inode": 100 + index, "sha256": "a" * 64},
                                    "admission": {"state": "admitted", "endpoints": len(set(provider["offsets"]))}})
        document["edges"].append({"caller": "c0", "module": f"m{index}",
                                  "mapping": {"state": "mapped", "evidence": "deep_scan"},
                                  "entries": {"count": 3, "observation": "observed",
                                              "coverage": {"state": "counted", "lossy": False}}})
    late = copy.deepcopy(document)
    for edge in late["edges"][:32]:
        edge["entries"]["count"] = 9
    for edge in late["edges"][32:61]:
        edge["entries"]["count"] = 6
    late["budgets"]["inventory_endpoints"]["occupied"] = 6531
    middle = copy.deepcopy(late)
    middle["modules"] = middle["modules"][:61]
    middle["edges"] = middle["edges"][:61]
    middle["budgets"]["inventory_endpoints"]["occupied"] = 4148
    for index, edge in enumerate(middle["edges"]):
        edge["entries"]["count"] = 6 if index < 32 else 3
    document["modules"] = document["modules"][:32]
    document["edges"] = document["edges"][:32]
    manifest = {"manifest": "p11scope-inventory-capacity/1", "population": "growth",
                "expect_lane": "native", "limit": 8192, "demand": 6531,
                "providers": providers, "owners": [owner], "middle_doc": middle,
                "phases": [{"name": "initial", "providers": [p["key"] for p in providers[:32]], "snapshot": "initial.json"},
                           {"name": "middle", "providers": [p["key"] for p in providers[:61]], "snapshot": "middle.json"},
                           {"name": "late", "providers": [p["key"] for p in providers], "snapshot": "late.json"}]}
    return manifest, ledger, document, late


def owner_population(manifest, ledger, initial, last):
    manifest.update(population="owners", owner_demand=257, demand=257,
                    native_owner_activation=True, providers=[], owners=[],
                    phases=[{"name": "late", "providers": [], "snapshot": "late.json"}])
    ledger.clear()
    last["modules"], last["callers"], last["edges"] = [], [], []
    last["budgets"]["inventory_endpoints"]["occupied"] = 257
    for index in range(257):
        key, path, pid, inode = f"p{index}", f"/owned/{index}.so", 5000 + index, 300 + index
        manifest["providers"].append({"key": key, "path": path, "pin": {
            "dev": [0, 35], "ino": inode, "sha256": "a" * 64}, "offsets": [4096]})
        manifest["phases"][0]["providers"].append(key)
        manifest["owners"].append({"pid": pid, "start_time": 70, "exe": "/owned/driver",
                                   "providers": [key], "ledger": "owner.jsonl"})
        ledger.extend([{"kind": "owner", "pid": pid, "start_time": 70, "exe": "/owned/driver"},
                       {"kind": "surface", "pid": pid, "start_time": 70, "path": path,
                        "dev": [0, 35], "ino": inode, "offsets": [4096]},
                       {"kind": "call", "pid": pid, "start_time": 70, "path": path,
                        "offset": 4096, "phase": "late", "n": 1, "rv": 0, "t0": 100, "t1": 110}])
        last["modules"].append({"id": f"m{index}", "paths": [path], "identity": {
            "device": {"major": 0, "minor": 35}, "inode": inode, "sha256": "a" * 64},
            "admission": {"state": "admitted", "endpoints": 1}})
        last["callers"].append({"id": f"c{index}", "pid": pid, "start_time": 70,
                                "image": {"authority": "native_exact"}})
        last["edges"].append({"caller": f"c{index}", "module": f"m{index}", "mapping": {
            "state": "mapped", "evidence": "deep_scan"}, "entries": {
            "count": 1, "observation": "observed", "coverage": {"state": "counted", "lossy": False}}})
    initial.update(copy.deepcopy(last))


class CapacityOracleTests(unittest.TestCase):
    def run_case(self, mutate=None, want=0, check=None):
        manifest, ledger, initial, late = population()
        middle = manifest.pop("middle_doc")
        if mutate:
            mutate(manifest, ledger, initial, late)
        with tempfile.TemporaryDirectory(prefix="inventory-capacity-oracle-") as temporary:
            directory = Path(temporary)
            for name, data in (("capacity.json", manifest), ("initial.json", initial), ("late.json", late)):
                (directory / name).write_text(json.dumps(data))
            (directory / "middle.json").write_text(json.dumps(middle))
            if "events" in manifest:
                (directory / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in manifest.pop("events")))
            (directory / "owner.jsonl").write_text("".join(json.dumps(row) + "\n" for row in ledger))
            result = subprocess.run([sys.executable, "-I", str(ORACLE), "capacity-check", temporary],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, want, result.stdout + result.stderr)
            if check:
                self.assertIn(check, result.stdout)

    def test_physical_aliases_and_distinct_inode_copies_pass(self):
        self.run_case()

    def test_duplicate_offsets_cannot_inflate_demand(self):
        self.run_case(lambda m, _l, _a, _b: m.update(demand=6), 1, "CAPACITY-UNION")

    def test_equal_bytes_do_not_collapse_distinct_inodes(self):
        def collapse(_m, _l, first, last):
            for doc in (first, last):
                doc["modules"].pop()
                doc["edges"].pop()
        self.run_case(collapse, 1, "CAPACITY-PROVIDER")

    def test_absent_provider_fails(self):
        self.run_case(lambda _m, _l, _a, last: last["modules"].pop(), 1, "CAPACITY-PROVIDER")

    def test_refused_in_envelope_provider_fails(self):
        self.run_case(lambda _m, _l, _a, last: last["modules"][1]["admission"].update(state="refused"),
                      1, "CAPACITY-ADMISSION")

    def test_observed_shortfall_fails(self):
        self.run_case(lambda _m, _l, _a, last: last["edges"][1]["entries"].update(count=5),
                      1, "CAPACITY-COUNT")

    def test_foreign_positive_fails(self):
        def foreign(_m, _l, _a, last):
            last["callers"].append({"id": "foreign", "pid": 4001, "start_time": 51})
            edge = copy.deepcopy(last["edges"][0])
            edge["caller"] = "foreign"
            last["edges"].append(edge)
        self.run_case(foreign, 1, "CAPACITY-FOREIGN")

    def test_old_count_reset_during_growth_fails(self):
        self.run_case(lambda _m, _l, _a, last: last["edges"][0]["entries"].update(count=3),
                      1, "CAPACITY-COUNT")

    def test_json_callers_do_not_establish_257_owners(self):
        def fabricated(manifest, ledger, first, last):
            owner_population(manifest, ledger, first, last)
            manifest["owners"] = manifest["owners"][:1]
        self.run_case(fabricated, 1, "CAPACITY-OWNERS")

    def test_maps_matched_owner_does_not_count_as_deep_scan(self):
        def matched(manifest, ledger, first, last):
            owner_population(manifest, ledger, first, last)
            last["edges"][0]["mapping"]["evidence"] = "maps_match"
        self.run_case(matched, 1, "CAPACITY-DEEP-SCAN")

    def test_earlier_stream_deep_scan_establishes_each_owner(self):
        def historical(manifest, ledger, first, last):
            owner_population(manifest, ledger, first, last)
            manifest["event_log"] = "events.jsonl"
            rows = [{"seq": 0, "at_ns": 1, "kind": "started", "event": {}}]
            for edge, caller, module in zip(last["edges"], last["callers"], last["modules"]):
                observed = copy.deepcopy(edge)
                observed["identity_context"] = {"version": 1, "caller": {
                    "id": caller["id"], "pid": caller["pid"], "start_time": caller["start_time"]}, "module": {
                    "id": module["id"], "path": module["paths"][0], "device_major": 0,
                    "device_minor": 35, "inode": module["identity"]["inode"]}}
                rows.append({"seq": len(rows), "at_ns": 2, "kind": "edge_observed", "event": observed})
                edge["mapping"]["evidence"] = "maps_match"
            rows.append({"seq": len(rows), "at_ns": 3, "kind": "ended", "event": {}})
            manifest["events"] = rows
        self.run_case(historical)

    def test_owner_activation_unavailable_is_nonqualifying(self):
        def unavailable(manifest, ledger, first, last):
            owner_population(manifest, ledger, first, last)
            manifest.update(native_owner_activation=False)
        self.run_case(unavailable, 2, "CAPACITY-NATIVE-OWNERS")

    def test_provider_surface_must_match_the_held_object(self):
        self.run_case(lambda _m, ledger, _a, _b: ledger[1].update(ino=999),
                      1, "CAPACITY-SURFACE")

    def test_stream_prefix_counts_are_lower_bounds_until_terminal_json(self):
        def prefix(manifest, _ledger, initial, _last):
            rows = [{"seq": 0, "at_ns": 1, "kind": "started", "event": {
                "limits": {"inventory_endpoints": 8192}}}]
            for edge, module in zip(initial["edges"], initial["modules"]):
                observed = copy.deepcopy(edge)
                observed["entries"]["count"] = 2
                observed["identity_context"] = {"version": 1, "caller": {
                    "id": "c0", "pid": 4000, "start_time": 50}, "module": {
                    "id": module["id"], "path": module["paths"][0], "device_major": 0,
                    "device_minor": 35, "inode": module["identity"]["inode"]}}
                rows.append({"seq": len(rows), "at_ns": 2, "kind": "edge_observed", "event": observed})
            manifest["events"] = rows
            manifest["phases"][0] = {"name": "initial", "providers": manifest["phases"][0]["providers"],
                                      "stream": "events.jsonl", "until_ns": 2}
        self.run_case(prefix)

    def test_native_counts_cannot_qualify_a_scan_lane(self):
        self.run_case(lambda _m, _l, _a, last: last["observation"].update(lane="scan"),
                      1, "CAPACITY-LANE")

    def test_calls_outside_capture_cannot_supply_exact_counts(self):
        def outside(_manifest, ledger, _initial, _last):
            next(row for row in ledger if row["kind"] == "call").update(t0=1, t1=2)
        self.run_case(outside, 1, "CAPACITY-WINDOW")

    def test_native_positive_requires_exact_caller_authority(self):
        self.run_case(lambda _m, _l, _a, last: last["callers"][0]["image"].update(authority="scan_pinned"),
                      1, "CAPACITY-AUTHORITY")

    def test_growth_cannot_skip_the_middle_capacity_population(self):
        def skipped(manifest, ledger, _first, _last):
            manifest["phases"].pop(1)
            for row in ledger:
                if row.get("phase") == "middle":
                    row["phase"] = "late"
        self.run_case(skipped, 1, "CAPACITY-GROWTH")


class CapacityFixtureTests(unittest.TestCase):
    def cleanup_case(self, repeated_signals=False, wait_failure=False, close_failure=False, acquisition_signal=False):
        namespace = runpy.run_path(str(ORACLE))
        owned = []
        old_handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        real_popen = subprocess.Popen

        class BrokenClose:
            def __init__(self, handle):
                self.handle = handle

            def close(self):
                raise OSError("injected close failure")

        class Child:
            def __init__(self, process, index):
                self.process, self.index, self.failed = process, index, False

            def __getattr__(self, name):
                if close_failure and self.index == 0 and name == "stdin":
                    return BrokenClose(self.process.stdin)
                return getattr(self.process, name)

            def terminate(self):
                if repeated_signals and self.index == 0:
                    os.kill(os.getpid(), signal.SIGTERM)
                    os.kill(os.getpid(), signal.SIGINT)
                    os.kill(os.getpid(), signal.SIGTERM)
                self.process.terminate()

            def wait(self, timeout=None):
                if wait_failure and self.index == 0 and not self.failed:
                    self.failed = True
                    raise OSError("injected wait failure")
                return self.process.wait(timeout=timeout)

        def launch(arguments, **_kwargs):
            index = len(owned)
            process = real_popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, "
                                  "signal.SIG_IGN); print('ready', flush=True); time.sleep(120)"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            owned.append(process)
            self.assertEqual(process.stdout.readline().strip(), "ready")
            if "--ready" in arguments:
                ready = Path(arguments[arguments.index("--ready") + 1])
                ready.write_text(f"READY {process.pid}\n")
                ledger = Path(arguments[arguments.index("--surface") + 1])
                ledger.write_text(json.dumps({"kind": "owner", "pid": process.pid, "start_time": 1,
                                               "exe": sys.executable}) + "\n")
            if acquisition_signal and index == 0:
                os.kill(os.getpid(), signal.SIGTERM)
            return Child(process, index)

        manifest = {"demand": 2, "providers": [{"key": f"p{index}", "path": f"/owned/{index}.so"}
                                                 for index in range(2)], "owners": [], "phases": []}
        error = None
        try:
            with tempfile.TemporaryDirectory(prefix="inventory-capacity-cleanup-control-") as temporary:
                with mock.patch.dict(namespace["capacity_run"].__globals__, capacity_prepare=lambda *_: manifest):
                    with mock.patch.object(subprocess, "Popen", side_effect=launch):
                        with mock.patch.dict(os.environ, CAPACITY_DURATION="1", CAPACITY_WAIT_S="1"):
                            try:
                                namespace["capacity_run"]("/owned/observer", temporary, "scan", "owners",
                                                           8192, 257, os.getuid(), os.getgid())
                            except BaseException as caught:
                                error = caught
                self.assertEqual(len(owned), 1 if acquisition_signal else 3)
                self.assertTrue(all(child.returncode is not None for child in owned),
                                "cleanup must reap every owned child despite signals/resource failures")
                self.assertTrue(all(child.stdout.closed for child in owned), "every owned output pipe was closed")
                self.assertTrue(all(child.stdin.closed for child in owned[1:]), "later owned input pipes were closed")
                self.assertIsInstance(error, ValueError)
                if acquisition_signal:
                    self.assertIn("interrupted by signal", str(error))
                else:
                    self.assertIn("bounded wait failed:observer initial discovery", str(error))
                if wait_failure or close_failure:
                    detail = "injected wait failure" if wait_failure else "injected close failure"
                    self.assertIn(detail, str(error))
                    self.assertTrue(hasattr(error, "failures"), "aggregate retains underlying resource exceptions")
                    self.assertTrue(any(isinstance(failure, OSError) and detail in str(failure)
                                        for _label, failure in error.failures))
                    self.assertIn("observer initial discovery", str(error.original))
                self.assertEqual({number: signal.getsignal(number) for number in old_handlers}, old_handlers)
        finally:
            for number, handler in old_handlers.items():
                signal.signal(number, handler)
            for child in owned:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                child.stdin.close()
                child.stdout.close()

    def test_repeated_termination_signals_do_not_interrupt_owned_cleanup(self):
        self.cleanup_case(repeated_signals=True)

    def test_one_wait_failure_does_not_skip_later_owned_children(self):
        self.cleanup_case(wait_failure=True)

    def test_one_close_failure_does_not_skip_later_owned_pipes(self):
        self.cleanup_case(close_failure=True)

    def test_signal_during_acquisition_enrolls_child_before_validation(self):
        self.cleanup_case(acquisition_signal=True)

    def test_signal_during_blocking_wait_unwinds_promptly_and_reaps_children(self):
        namespace = runpy.run_path(str(ORACLE))
        custody = namespace["CapacityCustody"]()
        error, wait_elapsed = None, 0
        previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            try:
                with custody:
                    target = custody.launch([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, "
                                             "signal.SIG_IGN); print('ready',flush=True); time.sleep(120)"],
                                            stdout=subprocess.PIPE, text=True)
                    self.assertEqual(target.stdout.readline().strip(), "ready")
                    custody.launch([sys.executable, "-c", "import os,signal,time; signal.signal(signal.SIGTERM, "
                                    f"signal.SIG_IGN); time.sleep(.2); os.kill({os.getpid()},signal.SIGTERM); time.sleep(120)"])
                    started = time.monotonic()
                    try:
                        target.wait(timeout=2)
                    finally:
                        wait_elapsed = time.monotonic() - started
            except BaseException as caught:
                error = caught
            self.assertLess(wait_elapsed, 1.2, "termination must unwind a normal blocking wait before its timeout")
            self.assertIsInstance(error, ValueError)
            self.assertIn("interrupted by signal", str(error))
            self.assertTrue(all(child.returncode is not None for child in custody.children))
            self.assertEqual({number: signal.getsignal(number) for number in previous}, previous)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
            for child in custody.children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                if child.stdout:
                    child.stdout.close()

    def test_failed_observer_reaps_its_owned_capacity_target(self):
        with tempfile.TemporaryDirectory(prefix="inventory-capacity-cleanup-") as temporary:
            directory = Path(temporary)
            observer = directory / "failed-observer"
            observer.write_text("#!/bin/sh\nexit 7\n")
            observer.chmod(0o755)
            environment = dict(os.environ, CAPACITY_DURATION="1", CAPACITY_WAIT_S="1")
            result = subprocess.run([sys.executable, "-I", str(ORACLE), "capacity-run", str(observer),
                                     str(directory), "scan", "growth", "8192", "8192", str(os.getuid()), str(os.getgid())],
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("observer exited", result.stderr)
            ready = next(directory.glob("capacity-*/growth/ready"))
            pid = int(ready.read_text().split()[1])
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_runner_rejects_invalid_capacity_selection_before_any_output(self):
        with tempfile.TemporaryDirectory(prefix="inventory-capacity-usage-") as temporary:
            output = Path(temporary) / "must-not-exist"
            result = subprocess.run(["bash", str(SHELL), sys.executable, "--base", str(output),
                                     "--capacity", "boundary", "--max-endpoints", "8193"],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
            self.assertIn("1..8192", result.stderr)
            self.assertFalse(output.exists())

    def test_capacity_population_requires_explicit_endpoint_selection(self):
        result = subprocess.run(["bash", str(SHELL), sys.executable, "--capacity", "boundary"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("requires --max-endpoints", result.stderr)

    def test_prepared_boundary_demands_come_from_distinct_mapped_objects(self):
        with tempfile.TemporaryDirectory(prefix="inventory-capacity-boundaries-") as temporary:
            for demand in (4097, 6531, 8192):
                directory = Path(temporary) / str(demand)
                result = subprocess.run([sys.executable, "-I", str(ORACLE), "capacity-prepare",
                                         str(directory), "boundary", str(demand)],
                                        text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                manifest = json.loads((directory / "capacity.json").read_text())
                physical = {(*provider["pin"]["dev"], provider["pin"]["ino"], offset)
                            for provider in manifest["providers"] for offset in provider["offsets"]}
                self.assertEqual(len(physical), demand)
                self.assertGreater(len({provider["pin"]["ino"] for provider in manifest["providers"]}), 1)

    def test_alias_surface_and_bounded_control_calls(self):
        with tempfile.TemporaryDirectory(prefix="inventory-capacity-fixture-") as temporary:
            directory = Path(temporary)
            provider, driver = directory / "provider.so", directory / "driver"
            subprocess.run(["gcc", "-shared", "-fPIC", "-DCAPACITY_UNIQUE=3", "-o", str(provider),
                            str(ROOT / "crates/discover/tests/fixture/version_matrix.c")], check=True, timeout=30)
            subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(driver),
                            str(ROOT / "tests/fixtures/catalog-driver.c"), "-ldl"], check=True, timeout=30)
            ledger = directory / "surface.jsonl"
            result = subprocess.run([str(driver), "--ready", str(directory / "ready"), "--call",
                                     "--surface", str(ledger), "--control", str(provider)],
                                    input="call initial 2\nquit\n", text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in ledger.read_text().splitlines()]
            self.assertEqual(len([row for row in rows if row["kind"] == "owner"]), 1)
            surface = next(row for row in rows if row["kind"] == "surface")
            self.assertEqual(len(surface["offsets"]), 68)
            self.assertEqual(len(set(surface["offsets"])), 3)
            calls = [row for row in rows if row["kind"] == "call" and row["phase"] == "initial"]
            self.assertEqual(sum(row["n"] for row in calls), 2)
            self.assertTrue(all(row["offset"] in surface["offsets"] and row["rv"] == 0 for row in calls))


if __name__ == "__main__":
    unittest.main()
