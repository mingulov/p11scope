#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real C protocol controls for leader exit with an already entered frame.

These controls compile and drive the owned LP64 fixture without BPF. They
prove physical call ordering and finite waits, not native capture acceptance.
"""

import os
import copy
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
CONTROL = runpy.run_path(str(ROOT / "tests/python/test_automatic_exec_oracle.py"))


class HeldLeaderEntryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="h6-held-leader-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = ROOT / "tests/fixtures/detailed-nonleader-exec.c"
        for name, flags in (("provider.so", ["-DDETAILED_EXEC_PROVIDER", "-fPIC", "-shared"]),
                            ("before", []), ("after", ["-DDETAILED_EXEC_AFTER"])):
            result = subprocess.run(["cc", *H6["B_CFLAGS"], *flags, str(source), "-ldl",
                                     "-o", str(cls.directory / name)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr)

    def child(self, mode="3", setup_ms=1500, leg_ms=3000, recovery_ms=1500,
              measurement_ms=1000, hold_ms=1000):
        now = time.monotonic_ns()
        argv = [str(self.directory / "before"), str(self.directory / "provider.so"),
                str(self.directory / "after"), str(self.directory / "absent"),
                str(os.getpid()), "43", mode, "25", "0", "1",
                str(now + leg_ms * 1_000_000), str(now + setup_ms * 1_000_000),
                str(recovery_ms), str(measurement_ms), str(hold_ms)]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        reader = H6["Reader"](proc.stdout, self.directory / f"child-{proc.pid}.txt")

        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
            reader.finish()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
            self.assertFalse(Path(f"/proc/{proc.pid}").exists())
        self.addCleanup(cleanup)
        index = 0

        def expect(prefix):
            nonlocal index
            try:
                line, index = H6["expect_line"](reader, index, prefix, 2)
            except EOFError:
                self.fail(f"fixture exited before {prefix}: rc={proc.wait(timeout=2)}")
            return line.split()

        def send(command):
            proc.stdin.write(command)
            proc.stdin.flush()
        return proc, reader, expect, send

    def live_entry(self, **kwargs):
        proc, reader, expect, send = self.child(**kwargs)
        expect("READY")
        birth = H6["proc_birth_ticks"](proc.pid)
        send("W")
        initial = expect("INITIAL_WARM_DONE")
        self.assertEqual([int(value) for value in initial[1:5]], [proc.pid, proc.pid, 1, 0])
        send("G")
        thread = expect("THREAD")
        worker = int(thread[2])
        self.assertNotEqual(worker, proc.pid)
        done = expect("WORKER_DONE")
        self.assertEqual([int(value) for value in done[3:6]], [11, 6, 5])
        body = expect("EXEC_BODY")
        self.assertEqual([int(value) for value in body[1:4]], [proc.pid, worker, 43])
        states = H6["proc_task_states"](proc.pid)
        self.assertIn(states.get(proc.pid), ("R", "S", "D"))
        self.assertIn(states.get(worker), ("R", "S", "D"))
        self.assertEqual(H6["proc_birth_ticks"](proc.pid), birth)
        self.assertEqual(H6["proc_exe"](proc.pid), str(self.directory / "before"))
        self.assertLessEqual(int(initial[6]), int(done[-1]))
        self.assertLessEqual(int(done[-1]), int(body[-1]))
        return proc, reader, expect, send, worker, birth, body

    def finish_successor(self, proc, expect, send):
        send("X")
        expect("NEW_READY")
        for sequence in (1, 2):
            send("W")
            self.assertEqual([int(value) for value in expect("WARM_DONE")[3:5]], [sequence, 0])
        send("P")
        expect("POST_BODY")
        send("R")
        self.assertEqual([int(value) for value in expect("NEW_DONE")[3:7]], [25, 13, 12, 43])
        send("F")
        self.assertEqual(proc.wait(timeout=2), 0)

    def test_held_provider_entry_precedes_original_leader_exit_and_same_birth_exec(self):
        proc, reader, expect, send, worker, birth, body = self.live_entry()
        with self.assertRaises(TimeoutError):
            H6["expect_line"](reader, 0, "LEADER_EXIT", 0.04)
        release_ns = time.monotonic_ns()
        send("E")
        release = expect("HELD_LEADER_RELEASE")
        self.assertEqual([int(value) for value in release[1:4]], [proc.pid, worker, 43])
        self.assertGreaterEqual(int(release[-1]), release_ns)
        exit_intent = expect("LEADER_EXIT")
        deadline = time.monotonic() + 0.5
        while H6["proc_task_states"](proc.pid).get(proc.pid) != "Z":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.001)
        self.assertLessEqual(int(body[-1]), int(release[-1]))
        self.assertLessEqual(int(release[-1]), int(exit_intent[-1]))
        self.assertEqual(H6["proc_birth_ticks"](proc.pid), birth)
        self.assertIn(H6["proc_task_states"](proc.pid).get(worker), ("R", "S", "D"))
        self.assertEqual(H6["proc_worker_identity"](proc.pid, worker)["tgid"], proc.pid)
        self.finish_successor(proc, expect, send)

    def test_mode3_refuses_worker_start_without_an_initial_real_marker(self):
        proc, reader, expect, send = self.child()
        expect("READY")
        send("G")
        self.assertEqual(proc.wait(timeout=2), 110)
        reader.finish()
        self.assertFalse(any(line.startswith(("THREAD ", "EXEC_BODY ")) for line in reader.lines))

    def test_held_frame_refuses_exec_before_controller_permits_leader_exit(self):
        proc, reader, _expect, send, *_ = self.live_entry()
        send("X")
        self.assertEqual(proc.wait(timeout=2), 94)
        reader.finish()
        self.assertFalse(any(line.startswith(("LEADER_EXIT ", "NEW_READY ")) for line in reader.lines))

    def test_held_entry_wait_for_leader_release_keeps_absolute_setup_deadline(self):
        proc, reader, _expect, _send, *_ = self.live_entry(setup_ms=180)
        self.assertEqual(proc.wait(timeout=1), 92)
        reader.finish()
        self.assertFalse(any(line.startswith("LEADER_EXIT ") for line in reader.lines))

    def test_initial_marker_heartbeats_cannot_renew_setup_deadline(self):
        proc, reader, expect, send = self.child(setup_ms=160)
        expect("READY")
        for sequence in (1, 2, 3):
            send("W")
            self.assertEqual(int(expect("INITIAL_WARM_DONE")[3]), sequence)
            time.sleep(0.04)
        self.assertEqual(proc.wait(timeout=1), 92)
        reader.finish()
        self.assertFalse(any(line.startswith("THREAD ") for line in reader.lines))

    def test_initial_marker_attempts_have_a_fixed_twenty_call_cap(self):
        proc, _reader, expect, send = self.child()
        expect("READY")
        for sequence in range(1, 21):
            send("W")
            self.assertEqual(int(expect("INITIAL_WARM_DONE")[3]), sequence)
        send("W")
        self.assertEqual(proc.wait(timeout=2), 111)

    def test_mode3_requires_opt_in_deadlines(self):
        result = subprocess.run([str(self.directory / "before"), str(self.directory / "provider.so"),
            str(self.directory / "after"), str(self.directory / "absent"), str(os.getpid()), "43", "3"],
            capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")

    def fixture_driver(self):
        proc, reader, expect, _send = self.child()
        ready = " ".join(expect("READY"))
        driver = H6["BDriver"].__new__(H6["BDriver"])
        driver.pid, driver.mode, driver.stdout, driver.index = proc.pid, "3", reader, 0
        driver.owned = H6["OwnedProcess"](proc.pid, os.getpid(), os.getuid(), proc)
        self.addCleanup(driver.owned.close)
        driver.birth, driver.token = driver.owned.identity["start_time"], 43
        driver.stamps, driver.lines, driver.tasks = {"READY": time.monotonic_ns()}, {"READY": ready}, {}
        driver.warm_calls, driver.initial_calls = [], []
        return proc, driver

    def test_driver_refuses_worker_before_a_public_initial_provider_proof(self):
        proc, driver = self.fixture_driver()
        try:
            with self.assertRaises(H6["SetupError"]):
                driver.start_worker()
        except EOFError:
            self.fail("driver dispatched G before the missing public initial proof")
        self.assertNotIn("G", driver.stamps)
        self.assertIsNone(proc.poll())

    def test_driver_initial_calls_are_real_original_image_markers(self):
        _proc, driver = self.fixture_driver()
        self.assertTrue(callable(getattr(driver, "initial_warm_attempt", None)),
                        "driver cannot ledger original-image readiness markers")
        for sequence in (1, 2):
            phase = driver.initial_warm_attempt(sequence, 1)
            row = driver.initial_calls[-1]
            self.assertEqual((row["image"], row["fn"], row["pid"], row["tid"], row["rv"]),
                             (0, "C_GetInfo", driver.pid, driver.pid, 0))
            self.assertEqual((row["phase"], row["seq"]), (phase, sequence))
            self.assertLessEqual(row["t0"], row["t1"])

    def held_controller_receipt(self):
        """Real process/entry proof with a synthetic public parser row, no BPF."""
        proc, driver = self.fixture_driver()
        for attribute, name in (("before_pin", "before"), ("after_pin", "after"),
                                ("provider_pin", "provider.so")):
            pin = H6["FilePin"](self.directory / name)
            self.addCleanup(pin.close)
            setattr(driver, attribute, pin)
        driver.exe0 = H6["proc_exe"](proc.pid)
        driver.maps0 = H6["proc_provider_mapping"](proc.pid, str(driver.provider_pin.path))
        driver.measured, driver.delay_ms = 25, 0
        started = time.monotonic_ns()
        phase = driver.initial_warm_attempt(1, 1)
        trace = CONTROL["named_row"](proc.pid, proc.pid, driver.exe0, "C_GetInfo")
        proof = {"image": 0, "proof_kind": "trace-row", "marker_fn": "C_GetInfo",
                 "started_ns": started, "observed_ns": time.monotonic_ns(),
                 "deadline_ns": started + 15_000_000_000, "attempts": 1, "max_attempts": 20,
                 "output_cursor": 0, "proof_cursor": 1, "phases": [phase]}
        driver.accept_initial_proof(SimpleNamespace(lines=[trace]), proof, started - 1)
        driver.start_worker()
        driver.pre_exec()
        driver.release_held_leader()
        driver.do_exec()
        driver.post_exec()
        driver.finish()
        driver.stdout.finish()
        ledger = driver.normalize(H6["symbol_file_offset"](driver.provider_pin.path, "C_Initialize"))
        provider = H6["provider_receipt"](driver.provider_pin)
        receipt = {"pid": proc.pid, "b_setup": driver.b_setup_note(),
                   "known_tids": [proc.pid, driver.worker_tid],
                   "images": [row for row in ledger if row["kind"] == "image"],
                   "provider_before": provider, "provider_after": copy.deepcopy(provider),
                   "abandoned_expected": 1, "abandoned_by_fn": {"C_Initialize": 1},
                   "measured": {"expected_calls": 25}, "observer_ready_ns": started - 1,
                   "observer_stopped_ns": time.monotonic_ns()}
        return trace, ledger, receipt

    def test_real_controller_proves_held_entry_without_observed_counter_expectations(self):
        trace, ledger, receipt = self.held_controller_receipt()
        self.assertEqual(H6["held_entry_errors"](trace, ledger, receipt), [])
        self.assertEqual(receipt["abandoned_expected"], 1)
        self.assertEqual(sum(row["kind"] == "call" and row["phase"] == "post" for row in ledger), 25)

    def test_held_entry_proof_rejects_wrong_original_marker_identity_and_chronology(self):
        trace, ledger, receipt = self.held_controller_receipt()
        for change in ("marker", "worker", "leader-birth", "provider", "entry-after-release", "deadline",
                       "abandoned", "stable-population"):
            with self.subTest(change=change):
                candidate = copy.deepcopy(receipt)
                held = candidate["b_setup"]["held_entry"]
                changed_trace = trace
                if change == "marker": changed_trace = trace.replace("C_GetInfo", "C_GetFunctionList")
                elif change == "worker": held["worker"]["start_time"] += 1
                elif change == "leader-birth": held["leader"]["start_time"] += 1
                elif change == "provider": held["provider"]["ino"] += 1
                elif change == "entry-after-release": held["entered_ns"] = held["released_ns"] + 1
                elif change == "deadline": held["deadline_ns"] = held["observed_live_ns"] + 10_000_000_001
                elif change == "abandoned": candidate["abandoned_expected"] = 0
                else: candidate["measured"]["expected_calls"] = 24
                self.assertTrue(H6["held_entry_errors"](changed_trace, ledger, candidate))


class WorkerPerfPrefixGapTest(unittest.TestCase):
    """Synthetic capability contracts; no native counter records are made."""

    def inputs(self):
        result, receipt = CONTROL["WorkerCapabilityTest"]().inputs(0)
        pin = {"path": "/w/lib.so", "dev": [8, 1], "ino": 111, "sha256": "0" * 64,
               "file_identity": {"dev": [8, 1], "ino": 111, "size": 4096,
                                 "mtime_ns": 222, "ctime_ns": 333},
               "mapping": {"dev": [8, 1], "ino": 111, "file_offset": 0,
                           "permissions": "r--p", "length": 4096}}
        receipt.update(cell="leader-exit-exec", provider_before=copy.deepcopy(pin), provider_after=copy.deepcopy(pin),
                       observer_argv=["/w/p11scope", "trace", "--pid", "1000", "--module", "/w/lib.so",
                                      "--attach-backend", "singles"])
        ev = result["evidence"][0]
        ev.update(authority="hash-pinned", completeness="PARTIAL", verdict_detail="concrete_gap",
                  unprotected_live_windows=0, task_uprobe_link_losses=1,
                  gap_classes={"observation": {"status": "lossy", "causes": ["task_uprobe_link_losses"]}},
                  attach_backend={"selection": "singles", "fallback": None, "scope_filter": "perf-task+bpf"},
                  discovery=[{**{key: pin[key] for key in ("path", "dev", "ino", "sha256")},
                              "objects": [{key: pin[key] for key in ("path", "dev", "ino", "sha256")}]}])
        return result, receipt

    def evaluate(self, result, receipt):
        return H6["evaluate_worker_capability"](result, receipt, "singles")

    def test_exact_post_zombie_perf_target_loss_is_informational_limitation(self):
        result, receipt = self.inputs()
        capability = self.evaluate(result, receipt)
        self.assertEqual(capability["status"], "limitation", capability["errors"])
        self.assertIsNone(capability["pass"])
        self.assertEqual(capability["pre_exec_captured"], 0)
        self.assertEqual(capability["early_coverage"]["deficit"], 11)

    def test_requested_backend_cannot_replace_actual_session_filter(self):
        for backend in ({}, {"selection": "singles", "fallback": None},
                        {"selection": "singles", "fallback": None, "scope_filter": "kernel-pid+bpf"},
                        {"selection": "multi", "fallback": None, "scope_filter": "perf-task+bpf"},
                        {"selection": "singles", "fallback": "global", "scope_filter": "perf-task+bpf"}):
            with self.subTest(backend=backend):
                result, receipt = self.inputs()
                result["evidence"][0]["attach_backend"] = backend
                self.assertEqual(self.evaluate(result, receipt)["status"], "error")


    def test_loss_count_or_later_static_gap_cannot_replace_prefix_proof(self):
        for change in ("no-cause", "not-partial", "not-concrete", "not-lossy", "no-loss", "changed-provider",
                       "wrong-mapped-domain", "wrong-product-provider", "wrong-worker", "release-before-zombie"):
            with self.subTest(change=change):
                result, receipt = self.inputs()
                ev = result["evidence"][0]
                ev["skipped"] = [{"name": "discovery subject", "reason": "static probes detached and exact pairs reattached"}]
                if change == "no-cause": ev["gap_classes"]["observation"]["causes"] = ["skipped"]
                elif change == "not-partial": ev["completeness"] = "COMPLETE"
                elif change == "not-concrete": ev["verdict_detail"] = "attribution_only"
                elif change == "not-lossy": ev["gap_classes"]["observation"]["status"] = "withheld"
                elif change == "no-loss": ev["task_uprobe_link_losses"] = 0
                elif change == "changed-provider": receipt["provider_after"]["ino"] += 1
                elif change == "wrong-mapped-domain": receipt["provider_before"]["mapping"]["dev"] = [9, 9]
                elif change == "wrong-product-provider": ev["discovery"][0]["ino"] += 1
                elif change == "wrong-worker": receipt["b_setup"]["worker_identity"]["tgid"] += 1
                else: receipt["b_setup"]["worker_barrier"]["observed_ns"] += 100
                self.assertEqual(self.evaluate(result, receipt)["status"], "error")


class WarmDeadlineTest(unittest.TestCase):
    def proof(self, shared_deadline=None):
        capture = SimpleNamespace(lines=[], errors=[], thread=SimpleNamespace(is_alive=lambda: False))
        observed = []
        def clock():
            value = 1_000_000_000 + len(observed) * 3507
            observed.append(value)
            return value
        def attempt(sequence, _remaining):
            capture.lines.append(CONTROL["named_row"](1000, 1000, "/w/before", "C_GetInfo"))
            return f"initial-0-{sequence}"
        warm = H6["warm_successor"]
        globals_patch = {"monotonic_ns": clock}
        if shared_deadline is not None:
            globals_patch["wait_deadline"] = lambda _seconds: shared_deadline
        with mock.patch.dict(warm.__globals__, globals_patch):
            proof = warm(capture, {"image": 0, "pid": 1000, "path": "/w/before"}, attempt)
        return proof, observed

    def test_two_clock_reads_cannot_advertise_more_than_fifteen_seconds(self):
        proof, observed = self.proof()
        self.assertGreater(observed[1], observed[0], "control needs genuinely distinct clock reads")
        self.assertEqual(proof["deadline_ns"] - proof["started_ns"], 15_000_000_000)

    def test_earlier_shared_deadline_is_retained(self):
        proof, _observed = self.proof(shared_deadline=6_000_000_000)
        self.assertEqual(proof["deadline_ns"], 6_000_000_000)


class LeaderProtocolRoutingTest(unittest.TestCase):
    def test_only_mode3_is_required_recovery_and_mode2_remains_informational(self):
        for required_pass in (True, False):
            with self.subTest(required_pass=required_pass), tempfile.TemporaryDirectory(prefix="h6-held-route-") as directory:
                calls = []
                source, receipt = WorkerPerfPrefixGapTest().inputs()
                source.update(status="fail", **{"pass": False})
                required = {"cell": "leader-exit-exec", "leg": "trace/singles", "pass": required_pass,
                            "status": "pass" if required_pass else "fail"}
                def leg(_ctx, _cell, _backend, _kind, leg_dir, mode):
                    calls.append(mode)
                    Path(leg_dir).mkdir(parents=True)
                    if mode == "2":
                        H6["write_json"](Path(leg_dir) / "receipt.json", receipt)
                        return source
                    return required
                runner = H6["run_leader_exit_exec"]
                with mock.patch.dict(runner.__globals__, {"run_b_leg": leg}):
                    rows = runner(None, directory, "singles")
                self.assertEqual(calls, ["3", "2"])
                self.assertIs(rows[0], required)
                self.assertEqual((rows[1]["leg"], rows[1]["status"], rows[1]["pass"]),
                                 ("capability-preexec/singles", "limitation", None))
                coverage = H6["required_recovery_coverage"](
                    [("leader-exit-exec", "singles", rows)], ["leader-exit-exec"], ["singles"])
                self.assertEqual(coverage["complete"], required_pass)


if __name__ == "__main__":
    unittest.main()
