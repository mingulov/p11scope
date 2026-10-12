# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged controls for the installed cgroup stop-stage acceptance."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-cgroup-stop.py"
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
STOP = runpy.run_path(str(SCRIPT))


class StopStageOracleTests(unittest.TestCase):
    def test_readiness_and_zero_calls_do_not_prove_traversal_cancellation(self):
        receipt = {"cell": "cgroup-reentry", "leg": "stop-before/singles",
                   "expect_empty": True, "observer_rc": 0,
                   "stop_latency_seconds": 0.1, "stop_limit_seconds": 60}
        trace = "COUNT_EVIDENCE " + json.dumps(
            {"stats_entered": 0, "stats_returned": 0, "raw_calls": 0})
        trace += "\nEVIDENCE " + json.dumps({"attach_backend": {"fallback": None}}) + "\n"
        self.assertTrue(H6["evaluate_trace_h6"](trace, [], receipt)["pass"])
        result = STOP["evaluate_stop_stage"](receipt, [], {}, [])
        self.assertFalse(result["pass"], "readiness is not an actual held traversal stage")

    def inputs(self, stage="final_pre_read", healthy=False):
        outcome = "complete" if healthy else "operator_stop"
        candidate = {"pid": 321, "start_time": 876}
        receipt = {"stage": stage, "healthy": healthy, "candidate": candidate,
                   "baseline": {"caller": "c0", "module": "m0", "count": 3, "seq": 0},
                   "observer_rc": 0, "workload_rc": 0, "stop_latency_seconds": 0.1,
                   "stop_limit_seconds": 60, "forced_cleanup": False}
        provider = {"path": "/w/lib.so", "dev": [0, 35], "ino": 111,
                    "mapping": {"dev": [0, 35], "ino": 111}, "sha256": "0" * 64}
        receipt.update(provider_before=provider, provider_after=dict(provider))
        tx = 1 if stage == "traversed" else 2
        frames = [{"event": "armed", "transaction": 0},
                  {"event": "launch", "transaction": tx}]
        returned = {"event": "worker_returned", "transaction": tx,
                    "outcome": outcome if stage == "traversed" else "complete"}
        joined = {"event": "worker_joined", "transaction": tx}
        gate = {"event": stage, "transaction": tx, "requested": True, **candidate}
        frames.extend([gate, returned, joined] if stage == "traversed" else [returned, joined, gate])
        if stage == "final_pre_read":
            frames.append({"event": "end_sampled", "transaction": tx,
                           "outcome": outcome, "present": healthy})
        frames.extend([{"event": "published", "transaction": tx, "outcome": outcome,
                        "candidate_admitted": healthy, "admitted": int(healthy),
                        "callers": int(healthy), "endpoints": 2 if healthy else 0},
                       {"event": "retiring", "transaction": 0},
                       {"event": "retired", "transaction": 0}])
        for index, frame in enumerate(frames):
            frame.update(version=1, sequence=index)
        doc = {"callers": [], "modules": [], "edges": []}
        records = []
        if stage == "final_pre_read":
            doc["callers"].append({"id": "c0", "pid": 300, "start_time": 800})
            doc["modules"].append({"id": "m0"})
            doc["edges"].append({"caller": "c0", "module": "m0", "entries": {"count": 3,
                "coverage": {"state": "counted", "lossy": False}}})
        if stage == "final_pre_read" or healthy:
            records.append({"kind": "edge_observed", "seq": 0,
                "event": {"caller": "c0", "module": "m0", "identity_context": {
                    "version": 1, "module": {"id": "m0", "status": "observed",
                        "device_major": 0, "device_minor": 35, "inode": 111}}}})
        if healthy:
            doc["callers"].append({"id": "c1", **candidate})
            doc["edges"].append({"caller": "c1", "module": "m0"})
            records.append({"kind": "caller_event", "seq": 1, "event": {"event": "admitted",
                "caller": "c1", "identity_context": {"version": 1, "caller": {"id": "c1", **candidate}}}})
        records.append({"kind": "ended"})
        return receipt, frames, doc, records

    def verdict(self, inputs):
        return STOP["evaluate_stop_stage"](*inputs)

    def test_real_stage_controls_accept_both_stops_and_release_twins(self):
        for stage in ("traversed", "final_pre_read"):
            for healthy in (False, True):
                with self.subTest(stage=stage, healthy=healthy):
                    result = self.verdict(self.inputs(stage, healthy))
                    self.assertTrue(result["pass"], result)

    def test_wrong_phase_sequence_or_prepared_candidate_binding_refuses(self):
        for field, value in (("event", "final_post_read"), ("sequence", 999),
                             ("pid", 322), ("start_time", 877), ("requested", False)):
            inputs = self.inputs()
            next(frame for frame in inputs[1] if frame["event"] == "final_pre_read")[field] = value
            with self.subTest(field=field):
                self.assertFalse(self.verdict(inputs)["pass"])

    def test_missing_return_join_outcome_or_retirement_refuses(self):
        for name in ("worker_returned", "worker_joined", "end_sampled", "published", "retiring", "retired"):
            inputs = self.inputs()
            inputs[1][:] = [frame for frame in inputs[1] if frame["event"] != name]
            with self.subTest(event=name):
                self.assertFalse(self.verdict(inputs)["pass"])
        inputs = self.inputs()
        next(frame for frame in inputs[1] if frame["event"] == "published")["outcome"] = "complete"
        self.assertFalse(self.verdict(inputs)["pass"])

    def test_zero_fixture_calls_cannot_hide_real_extra_admission_or_endpoint(self):
        inputs = self.inputs("traversed")
        inputs[2]["modules"] = [{"id": "m0"}]
        self.assertFalse(self.verdict(inputs)["pass"])
        inputs = self.inputs()
        inputs[2]["callers"].append({"id": "c1", **inputs[0]["candidate"]})
        self.assertFalse(self.verdict(inputs)["pass"])
        inputs = self.inputs()
        inputs[3].insert(0, {"kind": "caller_event", "seq": 2,
            "event": {"event": "admitted", "identity_context": {"caller": {"pid": 999}}}})
        self.assertFalse(self.verdict(inputs)["pass"])

    def test_later_launch_or_lost_baseline_history_refuses(self):
        inputs = self.inputs()
        inputs[1].append({"version": 1, "sequence": len(inputs[1]), "event": "launch", "transaction": 3})
        self.assertFalse(self.verdict(inputs)["pass"])
        inputs = self.inputs()
        inputs[2]["edges"][0]["entries"]["count"] = 0
        self.assertFalse(self.verdict(inputs)["pass"])

    def test_release_twin_needs_actual_membership_sample_and_admission(self):
        for mutation in ("sample", "admission", "edge"):
            inputs = self.inputs(healthy=True)
            if mutation == "sample":
                next(frame for frame in inputs[1] if frame["event"] == "end_sampled")["present"] = False
            elif mutation == "admission":
                inputs[3][:] = [record for record in inputs[3] if record["kind"] != "caller_event"]
            else:
                inputs[2]["edges"] = inputs[2]["edges"][:1]
            with self.subTest(mutation=mutation):
                self.assertFalse(self.verdict(inputs)["pass"])

    def test_forced_or_nonzero_normal_stop_cannot_pass(self):
        for field, value in (("forced_cleanup", True), ("observer_rc", -9),
                             ("workload_rc", 1), ("stop_latency_seconds", 61)):
            inputs = self.inputs()
            inputs[0][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.verdict(inputs)["pass"])

    def test_positive_requires_independent_held_provider_mapping_domain(self):
        for mutation in ("mapping", "module"):
            inputs = self.inputs(healthy=True)
            if mutation == "mapping":
                inputs[0]["provider_after"]["ino"] = 112
            else:
                inputs[3][0]["event"]["identity_context"]["module"]["device_minor"] = 36
            with self.subTest(mutation=mutation):
                self.assertFalse(self.verdict(inputs)["pass"])

    def test_all_unknown_baseline_is_not_a_useful_capture(self):
        inputs = self.inputs()
        inputs[2]["edges"][0]["entries"]["coverage"]["state"] = "unknown"
        self.assertFalse(self.verdict(inputs)["pass"])

    def test_covered_member_permit_preserves_unrelated_finite_scan_gaps(self):
        for healthy in (False, True):
            inputs = self.inputs(healthy=healthy)
            next(frame for frame in inputs[1] if frame["event"] == "worker_returned")["outcome"] = "incomplete"
            if healthy:
                next(frame for frame in inputs[1] if frame["event"] == "published")["outcome"] = "incomplete"
            with self.subTest(healthy=healthy):
                result = self.verdict(inputs)
                self.assertTrue(result["pass"], result)


class StageControllerTests(unittest.TestCase):
    def channel(self, seconds=1):
        channel = STOP["StageController"]("traversed", seconds=seconds)
        self.addCleanup(channel.close)
        config = json.loads(channel.child.recv(1024))
        self.assertEqual(config["stage"], "traversed")
        return channel

    def test_bounded_actual_socket_exchange_and_only_release_command(self):
        channel = self.channel()
        frame = {"version": 1, "sequence": 0, "transaction": 1, "event": "traversed"}
        channel.child.sendall(json.dumps(frame).encode() + b"\n")
        observed = channel.wait("traversed")
        channel.release(observed)
        self.assertEqual(json.loads(channel.child.recv(1024)), {"version": 1, "release": 1})
        with self.assertRaises(ValueError):
            channel.release({"event": "cancel", "transaction": 1})

    def test_wrong_phase_and_sequence_are_protocol_failures(self):
        for field, value in (("event", "cancel"), ("sequence", 3)):
            channel = self.channel()
            frame = {"version": 1, "sequence": 0, "transaction": 1, "event": "armed", field: value}
            channel.child.sendall(json.dumps(frame).encode() + b"\n")
            with self.subTest(field=field), self.assertRaises(ValueError):
                channel.receive()

    def test_eof_truncated_and_oversized_frames_fail(self):
        for content in (b"", b"{", b"x" * 1025):
            channel = self.channel()
            if content:
                channel.child.sendall(content)
            channel.child.close()
            with self.subTest(content=len(content)), self.assertRaises((ValueError, EOFError)):
                channel.receive()

    def test_deadline_is_not_renewed_after_a_phase_or_timeout(self):
        channel = self.channel(seconds=0.02)
        deadline = channel.deadline
        with self.assertRaises(TimeoutError):
            channel.wait("traversed")
        self.assertEqual(channel.deadline, deadline)
        with self.assertRaises(TimeoutError):
            channel.send({"version": 1, "release": 1})

    def test_real_sigint_uses_owned_normal_stop_and_settles_pipe_readers(self):
        child_code = """
import json, os, signal, socket
channel = socket.socket(fileno=int(os.environ['P11SCOPE_CGROUP_STOP_FD']))
config = bytearray()
while not config.endswith(b'\\n'):
    config.extend(channel.recv(1))
assert json.loads(config)['stage'] == 'traversed'
def stopped(signum, _frame):
    assert signum == signal.SIGINT
    print('normal SIGINT', flush=True)
    channel.close()
    raise SystemExit(0)
signal.signal(signal.SIGINT, stopped)
for sequence, event in enumerate(('armed', 'traversed')):
    channel.sendall((json.dumps(dict(version=1, sequence=sequence,
        transaction=1, event=event)) + '\\n').encode())
while True:
    signal.pause()
"""
        with tempfile.TemporaryDirectory() as directory:
            case = H6["Case"](SimpleNamespace(out=Path(directory)))
            @H6["owned_leg"](stop_b=True)
            def run(ctx):
                channel = STOP["StageController"]("traversed", seconds=2)
                try:
                    env, fds = channel.inherited()
                    ctx.observer_start = len(ctx.owners)
                    owner = H6["spawn_owned"](ctx.owners, [sys.executable, "-c", child_code],
                        os.geteuid(), env={**os.environ, **env}, pass_fds=fds,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True)
                    ctx.observer_owned = owner
                    channel.spawned()
                    reader = H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stdout,
                                                Path(directory) / "stdout")
                    H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stderr,
                                       Path(directory) / "stderr")
                    channel.wait("traversed")
                    rc, _stopped, _latency = H6["stop_b_observer"](ctx, owner)
                    channel.finish()
                    H6["finish_readers"](ctx.readers)
                    self.assertEqual(rc, 0)
                    self.assertEqual(reader.lines, ["normal SIGINT\n"])
                    self.assertFalse(owner.stop_receipt["forced_cleanup"])
                    return {"pass": True}
                finally:
                    channel.close()
            self.assertTrue(run(case)["pass"])
            self.assertFalse(case.cleanup_failed)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))


if __name__ == "__main__":
    unittest.main()
