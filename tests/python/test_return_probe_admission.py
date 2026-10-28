#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged EXT-01 fixture/driver controls; no observer/BPF is attached."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-return-probe-admission.py"
SOURCE = ROOT / "tests/fixtures/return-probe-admission.c"
CLEAN = ("uretprobe vs seccomp .............. ok    "
         "the trampoline's syscall is exempt from seccomp; confined targets are safe\n")
PUBLIC_LOSS_COUNTERS = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))["COUNTERS"]


def subject():
    spec = importlib.util.spec_from_file_location("return_probe_admission", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(provider, pid, count):
    st = provider.stat()
    module = {"dev": [os.major(st.st_dev), os.minor(st.st_dev)], "ino": st.st_ino,
              "sha256": hashlib.sha256(provider.read_bytes()).hexdigest()}
    return {
        "schema": "p11scope/observed-profile/v3", "lane": "profile",
        "capture": {"mode": "profile", "scope": f"pid:{pid}",
                    "privacy_mode": "allowlisted", "modules": [{"path": str(provider), **module}]},
        "evidence": {
            **{key: 0 for key in PUBLIC_LOSS_COUNTERS},
            "completeness": "COMPLETE", "drain_proven": True, "verdict_detail": "clean_proven",
            "stop_quiescence": {"state": "proven", "post_q_events": False,
                                "post_q_discovery": False},
            "uretprobe_override": None, "in_flight_at_end": 0,
            "attach_backend": {"selection": "multi", "fallback": None,
                               "scope_filter": "kernel-pid+bpf"},
            "attach_mechanisms": ["uprobe-multi"], "attach_failures": [],
            "event_loss": 0, "start_insert_failures": 0, "unmatched_returns": 0,
            "rv_update_failures": 0, "abi_refusals": 0, "malformed_records": 0,
            "discovery_ring_loss": 0, "discovery_read_failures": 0,
            "discovery_state_failures": 0, "discovery_truncated": 0,
            "task_uprobe_link_losses": 0,
            "kernel_control": {"capture_halted": False, "owner_poison": [],
                               "owner_admission_failures": 0, "identity_unavailable": 0,
                               "identity_budget_exhausted": False,
                               "root_affiliation_failures": []},
        },
        "functions": [{"names": ["C_GetInfo"], "module": module,
                       "module_ambiguous": False, "module_unresolved": False,
                       "calls": count, "errors": 0, "in_flight": 0, "pending_returns": 0,
                       "rv_counts": {"0x0000000000000000": count}}],
    }


class DisclosureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = subject()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="return-admission-oracle-")
        self.addCleanup(self.temp.cleanup)
        self.provider = Path(self.temp.name) / "provider.so"
        self.provider.write_bytes(b"owned provider identity")
        st = self.provider.stat()
        self.device = (os.major(st.st_dev), os.minor(st.st_dev))

    def test_functional_clean_row_is_required_not_doctor_exit_or_version(self):
        self.mod.require_clean_doctor(CLEAN)
        for data in ("", "kernel 6.18\n", CLEAN.replace(" ok ", " warn "),
                     CLEAN.replace("exempt", "not exempt"), CLEAN + CLEAN,
                     CLEAN.replace("uretprobe vs seccomp", "other check")):
            with self.subTest(data=data):
                with self.assertRaises(self.mod.Refused):
                    self.mod.require_clean_doctor(data)

    def test_exact_owned_counts_and_drain_are_accepted(self):
        self.mod.validate_report(report(self.provider, 123, 16), self.provider, 123, 16,
                                 mapping_dev=self.device)

    def test_maps_device_is_authority_for_report_not_filesystem_stat_device(self):
        data = report(self.provider, 123, 16)
        for module in (data["capture"]["modules"][0], data["functions"][0]["module"]):
            module["dev"] = [231, 17]
        self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=(231, 17))
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=(231, 18))

    def test_numeric_booleans_and_boolean_counters_do_not_forge_facts(self):
        for parent, key in (("stop_quiescence", "post_q_events"),
                            ("stop_quiescence", "post_q_discovery"),
                            ("kernel_control", "capture_halted"),
                            ("kernel_control", "identity_budget_exhausted")):
            data = report(self.provider, 123, 16)
            data["evidence"][parent][key] = 0
            with self.subTest(parent=parent, key=key), self.assertRaises(self.mod.Refused):
                self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)
        data = report(self.provider, 123, 1)
        data["functions"][0]["rv_counts"] = {"0x0000000000000000": True}
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_report(data, self.provider, 123, 1, mapping_dev=self.device)

    def test_each_published_loss_counter_refuses_even_when_marked_complete(self):
        for key in PUBLIC_LOSS_COUNTERS:
            data = report(self.provider, 123, 16)
            data["evidence"][key] = 1
            with self.subTest(key=key), self.assertRaises(self.mod.Refused):
                self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)

    def test_zero_call_row_cannot_hide_positive_return_counters(self):
        data = report(self.provider, 123, 16)
        zero = copy.deepcopy(data["functions"][0])
        zero.update(names=["C_GetFunctionList"], calls=0, rv_counts={})
        data["functions"].append(zero)
        self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)
        zero["rv_counts"] = {"0x0000000000000000": 1}
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)

    def test_counts_identity_partial_loss_override_and_drain_poison(self):
        poisons = [
            ("functions.0.calls", 15), ("functions.0.calls", True),
            ("functions.0.errors", 1), ("functions.0.in_flight", 1),
            ("functions.0.pending_returns", 1), ("functions.0.names", ["unknown"]),
            ("functions.0.module.ino", 9), ("functions.0.module.sha256", "0" * 64),
            ("functions.0.module_ambiguous", True), ("functions.0.module_unresolved", True),
            ("functions.0.rv_counts", {"0x0000000000000005": 16}),
            ("capture.scope", "pid:124"), ("capture.modules.0.ino", 9),
            ("capture.privacy_mode", "unsafe-unvalidated-metadata"),
            ("evidence.completeness", "PARTIAL"), ("evidence.drain_proven", False),
            ("evidence.stop_quiescence.post_q_events", True),
            ("evidence.stop_quiescence.post_q_discovery", True),
            ("evidence.uretprobe_override", {"reason": "accepted risk"}),
            ("evidence.event_loss", 1), ("evidence.unmatched_returns", 1),
            ("evidence.abi_refusals", 1), ("evidence.discovery_ring_loss", 1),
            ("evidence.kernel_control.capture_halted", True),
            ("evidence.attach_backend.scope_filter", "perf-task+bpf"),
        ]
        for path, value in poisons:
            with self.subTest(path=path):
                data = report(self.provider, 123, 16)
                dest = data
                parts = path.split(".")
                for part in parts[:-1]:
                    dest = dest[int(part)] if isinstance(dest, list) else dest[part]
                dest[parts[-1]] = value
                with self.assertRaises(self.mod.Refused):
                    self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)

    def test_missing_facts_and_extra_positive_rows_refuse(self):
        base = report(self.provider, 123, 16)
        for parent, key in (("evidence", "drain_proven"), ("evidence", "event_loss"),
                            ("functions", "rv_counts"), ("functions", "module")):
            data = copy.deepcopy(base)
            del (data["functions"][0] if parent == "functions" else data[parent])[key]
            with self.subTest(key=key), self.assertRaises(self.mod.Refused):
                self.mod.validate_report(data, self.provider, 123, 16, mapping_dev=self.device)
        extra = copy.deepcopy(base)
        extra["functions"].append(copy.deepcopy(extra["functions"][0]))
        with self.assertRaises(self.mod.Refused):
            self.mod.validate_report(extra, self.provider, 123, 16, mapping_dev=self.device)

    def test_ledger_is_complete_exact_same_worker_and_has_no_extra_call(self):
        rows = [{"index": i, "pid": 12, "tid": 13, "rv": 0} for i in range(1, 17)]
        self.mod.validate_ledger(rows, 12, 13, 16)
        for bad in (rows[:-1], rows + [rows[-1]], [dict(rows[0], tid=12), *rows[1:]],
                    [dict(rows[0], rv=5), *rows[1:]], [dict(rows[0], index=True), *rows[1:]]):
            with self.assertRaises(self.mod.Refused):
                self.mod.validate_ledger(bad, 12, 13, 16)

    def test_missing_status_is_unknown_not_zero(self):
        with self.assertRaises(self.mod.Refused):
            self.mod.parse_status("Name:\tworker\nPid:\t8\nTgid:\t7\n")

    def test_refused_doctor_never_launches_filtered_fixture(self):
        work = Path(self.temp.name) / "case"
        with mock.patch.object(self.mod, "run_doctor", side_effect=self.mod.Refused("not clean")), \
             mock.patch.object(self.mod, "compile_fixture") as compile_fixture:
            with self.assertRaises(self.mod.Refused):
                self.mod.qualify(SCRIPT, work)
            compile_fixture.assert_not_called()


class OwnedFixtureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = subject()
        cls.build = tempfile.TemporaryDirectory(prefix="return-admission-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.app, cls.provider = cls.mod.compile_fixture(Path(cls.build.name))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="return-admission-case-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def launch(self, mode, count=16):
        app = self.mod.OwnedProcess([str(self.app), str(self.provider), mode, str(count),
                                     str(self.work / "calls.jsonl")], self.work / "app", 3)
        self.addCleanup(app.close)
        return app

    def test_real_both_modes_hold_same_worker_and_mapping_without_extra_calls(self):
        for mode in self.mod.MODES:
            with self.subTest(mode=mode):
                sub = self.work / mode
                sub.mkdir()
                child = self.mod.OwnedProcess([str(self.app), str(self.provider), mode, "16",
                                               str(sub / "calls.jsonl")], sub / "app", 3)
                with child:
                    ready = child.read_json("ready")
                    self.assertEqual(ready["pid"], child.pid)
                    self.assertNotEqual(ready["tid"], child.pid)
                    self.assertEqual(ready["leader_seccomp"], 0)
                    self.assertEqual(ready["worker_seccomp"], 2 if mode == self.mod.MODES[0] else 0)
                    pin = self.mod.capture_identity(child.pid, ready["tid"], self.provider)
                    self.assertEqual((sub / "calls.jsonl").read_bytes(), b"")
                    child.send("A")
                    armed = child.read_json("armed")
                    self.mod.verify_facts(child, armed, self.provider, pin, armed=True)
                    child.send("G")
                    done = child.read_json("done")
                    self.assertEqual(done["calls"], 16)
                    data = (sub / "calls.jsonl").read_bytes()
                    self.mod.validate_ledger([json.loads(row) for row in data.splitlines()],
                                             child.pid, ready["tid"], 16)
                    self.mod.verify_facts(child, done, self.provider, pin, armed=True)
                    # Waiting for explicit release, with no more PKCS#11 calls or unmap.
                    self.assertIsNone(child.poll())
                    self.assertEqual((sub / "calls.jsonl").read_bytes(), data)
                    child.send("R")
                    self.assertEqual(child.wait(), 0)

    def test_unrecognized_call_command_refuses_without_calling_provider(self):
        child = self.launch(self.mod.MODES[0])
        ready = child.read_json("ready")
        self.assertEqual(ready["leader_seccomp"], 0)
        child.send("A")
        child.read_json("armed")
        child.send("X")
        self.assertNotEqual(child.wait(), 0)
        self.assertEqual((self.work / "calls.jsonl").read_bytes(), b"")

    def test_early_go_refuses_without_calls(self):
        child = self.launch(self.mod.MODES[1])
        child.read_json("ready")
        child.send("G")
        self.assertNotEqual(child.wait(), 0)
        self.assertEqual((self.work / "calls.jsonl").read_bytes(), b"")

    def test_existing_ledger_is_preserved(self):
        ledger = self.work / "calls.jsonl"
        ledger.write_text("preserve\n")
        child = self.launch(self.mod.MODES[0])
        self.assertNotEqual(child.wait(), 0)
        self.assertEqual(ledger.read_text(), "preserve\n")

    def test_timeout_and_context_cleanup_reap_only_owned_child(self):
        start = time.monotonic()
        child = self.mod.OwnedProcess([str(self.app), str(self.provider), self.mod.MODES[0],
                                      "16", str(self.work / "calls.jsonl")], self.work / "app", .15)
        with child:
            child.read_json("ready")
            with self.assertRaises(self.mod.Refused):
                child.read_json("done")
        self.assertIsNotNone(child.poll())
        self.assertLess(time.monotonic() - start, 2)
        self.assertFalse(Path(f"/proc/{child.pid}").exists())

    def fake_observer(self, behavior="healthy"):
        fake = self.work / "observer"
        doctor = CLEAN.replace(" ok ", " warn ") if behavior == "doctor-refused" else CLEAN
        fake.write_text("#!/usr/bin/env python3\n" +
            "import hashlib,json,os,pathlib,signal,sys\n" +
            "if sys.argv[1]=='doctor':\n print(" + repr(doctor) + ",end='');sys.exit(0)\n" +
            "pid=int(sys.argv[sys.argv.index('--pid')+1])\n" +
            "provider=pathlib.Path(sys.argv[sys.argv.index('--module')+1])\n" +
            "out=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n" +
            "def stop(*_):\n" +
            " assert pathlib.Path('/proc/'+str(pid)).exists()\n" +
            " assert str(provider) in pathlib.Path('/proc/'+str(pid)+'/maps').read_text()\n" +
            " doc=" + repr(report(self.provider, 1, 16)).replace("'pid:1'", "'pid:'+str(pid)") + "\n" +
            " st=provider.stat()\n" +
            " maps=pathlib.Path('/proc/'+str(pid)+'/maps').read_text().splitlines()\n" +
            " dev=next(row.split()[3] for row in maps if str(provider) in row and 'r-x' in row)\n" +
            " module={'dev':[int(x,16) for x in dev.split(':')],'ino':st.st_ino," +
            "'sha256':hashlib.sha256(provider.read_bytes()).hexdigest()}\n" +
            " doc['capture']['modules']=[{'path':str(provider),**module}]\n" +
            " doc['functions'][0]['module']=module\n" +
            (" doc['evidence']['completeness']='PARTIAL'\n" if behavior == "partial" else "") +
            " out.write_text(json.dumps(doc))\n" +
            " sys.exit(0)\n" +
            "signal.signal(signal.SIGINT,stop)\n" +
            ("sys.exit(1)\n" if behavior == "missing-readiness" else "") +
            "print('p11scope: capturing: 4 probe(s) attached; stop with Ctrl-C',file=sys.stderr,flush=True)\n" +
            "while True: signal.pause()\n")
        fake.chmod(0o700)
        return fake

    def test_fake_observer_drives_actual_fixture_after_readiness_and_holds_till_exit(self):
        fake = self.fake_observer()
        result = self.mod.qualify(fake, self.work / "qualification", calls=16, duration=1)
        self.assertEqual([row["mode"] for row in result["cells"]], list(self.mod.MODES))
        self.assertTrue(all(row["calls"] == 16 and row["owned_cleanup"] for row in result["cells"]))

    def test_public_driver_cli_succeeds_only_after_owned_final_drain(self):
        fake = self.fake_observer()
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--observer", str(fake),
                                 "--output-dir", str(self.work / "qualification"),
                                 "--mode", self.mod.MODES[1]], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        cells = json.loads(result.stdout)["cells"]
        self.assertEqual(len(cells), 1)
        self.assertEqual(cells[0]["calls"], 16)
        self.assertFalse(Path(f'/proc/{cells[0]["pid"]}').exists())

    def test_actual_doctor_refusal_cli_cannot_compile_or_launch_filtered_target(self):
        fake = self.fake_observer("doctor-refused")
        work = self.work / "qualification"
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--observer", str(fake),
                                 "--output-dir", str(work)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("not Clean", result.stderr)
        self.assertEqual(sorted(path.name for path in work.iterdir()), ["doctor.stderr", "doctor.stdout"])

    def test_missing_readiness_never_opens_call_gate_and_reaps_owned_target(self):
        fake = self.fake_observer("missing-readiness")
        work = self.work / "qualification"
        with self.assertRaises(self.mod.Refused):
            self.mod.qualify(fake, work, duration=1, modes=(self.mod.MODES[0],))
        cell = work / self.mod.MODES[0]
        self.assertEqual((cell / "calls.jsonl").read_bytes(), b"")
        pid = json.loads((cell / "caller.stdout").read_text().splitlines()[0])["pid"]
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_partial_final_report_fails_and_cleans_held_fixture(self):
        fake = self.fake_observer("partial")
        work = self.work / "qualification"
        with self.assertRaises(self.mod.Refused):
            self.mod.qualify(fake, work, duration=1, modes=(self.mod.MODES[1],))
        cell = work / self.mod.MODES[1]
        rows = [json.loads(row) for row in (cell / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 16)
        self.assertFalse(Path(f'/proc/{rows[0]["pid"]}').exists())

    def test_owned_term_ignoring_child_is_killed_and_reaped(self):
        with self.mod.OwnedProcess([sys.executable, "-I", "-c",
                                   "import signal;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                                   "print('ready',flush=True);signal.pause()"],
                                  self.work / "ignore-term", 3) as child:
            self.assertEqual(child.read_line(), "ready")
        self.assertIsNotNone(child.poll())
        self.assertFalse(Path(f"/proc/{child.pid}").exists())

    def test_buffered_readiness_cannot_bypass_its_absolute_deadline(self):
        with self.mod.OwnedProcess([sys.executable, "-I", "-c",
                                   "import signal;print('first\\nready',flush=True);signal.pause()"],
                                  self.work / "queued-ready", 3) as child:
            self.assertEqual(child.read_line(), "first")
            self.assertEqual(child.pending["stdout"], ["ready"])
            with self.assertRaises(self.mod.Refused):
                child.read_line(deadline=child.started - 1)


if __name__ == "__main__":
    unittest.main()
