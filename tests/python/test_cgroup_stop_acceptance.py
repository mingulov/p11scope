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
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-cgroup-stop.py"
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
STOP = runpy.run_path(str(SCRIPT))


class StopStageOracleTests(unittest.TestCase):
    def test_run_leg_uses_compiled_h6_caller_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = H6["compile_case_fixtures"](Path(directory) / "bin")
            self.addCleanup(lambda: [pin.close() for pin in pins.values()])
            self.assertIn("caller", pins)
            args = SimpleNamespace(uid=1000, gid=1000)
            ctx = SimpleNamespace(args=args, pins=pins, provider_pin=object(), owners=[], readers=[])
            created = iter(SimpleNamespace(path=Path(directory) / name)
                           for name in ("root", "selected", "outside"))
            observed = {}

            class ReachedCallerSpawn(Exception):
                pass

            def spawn_caller(_owners, _readers, _directory, caller_pin, *_args, **_kwargs):
                observed["pin"] = caller_pin
                raise ReachedCallerSpawn

            patches = {
                "init_token": lambda *_args: {},
                "provider_receipt": lambda _pin: {},
                "create_tracked": lambda *_args: (next(created), None),
                "spawn_caller": spawn_caller,
            }
            with patch.dict(STOP["H6"], patches):
                with self.assertRaises(ReachedCallerSpawn):
                    STOP["run_leg"].__wrapped__(ctx, directory, "singles", "traversed", False)
            self.assertIs(observed["pin"], pins["caller"])

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


class BaselineWaitTests(unittest.TestCase):
    def scene(self, directory):
        path = Path(directory) / "inventory.jsonl"
        owner = SimpleNamespace(pid=300)
        executable = SimpleNamespace(path=Path("/fixture/caller"))
        provider = {"mapping": {"dev": [0, 35], "ino": 111}}
        rows = [
            {"seq": 0, "kind": "caller_event", "event": {
                "event": "admitted", "caller": "c0", "identity_context": {
                    "caller": {"pid": owner.pid, "executable": {"path": str(executable.path)}}}}},
            {"seq": 1, "kind": "edge_observed", "event": {
                "caller": "c0", "module": "m0", "entries": {"count": 0,
                    "coverage": {"state": "unknown", "reason": "scope_membership_unproven"}},
                "identity_context": {"version": 1, "module": {"id": "m0", "status": "observed",
                    "device_major": 0, "device_minor": 35, "inode": 111}}}},
        ]
        self.write_rows(path, rows)
        return path, owner, executable, provider, rows

    def write_rows(self, path, rows):
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def publish_counted(self, path, rows, mutation=None):
        row = json.loads(json.dumps(next(row for row in rows if row["kind"] == "edge_observed")))
        row["seq"] = len(rows)
        row["event"]["entries"] = {"count": 3, "coverage": {"state": "counted", "lossy": False}}
        if mutation:
            mutation(row["event"])
        rows.append(row)
        self.write_rows(path, rows)

    def test_quiet_cgroup_issues_fixed_calls_before_waiting_for_counted_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path, owner, executable, provider, rows = self.scene(directory)
            reader, phases = object(), []
            command = Mock(side_effect=lambda *_args: self.publish_counted(path, rows))
            # Exercise the existing quiet-coverage wait under a short host-test
            # cap. Only the command above can publish the counted JSONL control.
            quiet_wait = lambda *args: H6["wait_usage_armed"](*args, timeout=0.02)
            with patch.dict(STOP["H6"], n3_command=command, wait_usage_armed=quiet_wait):
                try:
                    result = STOP["wait_baseline"](path, owner, executable, provider, reader, phases)
                except TimeoutError:
                    self.fail("quiet cgroup readiness timed out before the fixed baseline calls")
            command.assert_called_once_with(owner, reader, "C_GenerateRandom", 3, 0,
                                            "baseline", "selected", 0, None, phases)
            self.assertEqual(result, {"caller": "c0", "module": "m0", "count": 3, "seq": 2})

    def test_fixed_calls_cannot_release_a_missing_or_unproven_baseline(self):
        def wrong_module(event):
            event["module"] = "m1"
            event["identity_context"]["module"].update(id="m1", inode=112)

        mutations = {
            "wrong module identity": wrong_module,
            "wrong caller": lambda event: event.update(caller="c1"),
            "lossy": lambda event: event["entries"]["coverage"].update(lossy=True),
            "all unknown": lambda event: event["entries"]["coverage"].update(state="unknown"),
            "insufficient": lambda event: event["entries"].update(count=2),
            "missing": None,
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path, owner, executable, provider, rows = self.scene(directory)
                reader, phases = object(), []
                command = Mock(side_effect=(lambda *_args: None) if mutation is None else
                    lambda *_args: self.publish_counted(path, rows, mutation))
                deadline = Mock(side_effect=lambda seconds: H6["wait_deadline"](min(seconds, 0.02)))
                with patch.dict(STOP["H6"], n3_command=command, wait_deadline=deadline):
                    with self.assertRaises(TimeoutError):
                        STOP["wait_baseline"](path, owner, executable, provider, reader, phases)
                command.assert_called_once_with(owner, reader, "C_GenerateRandom", 3, 0,
                                                "baseline", "selected", 0, None, phases)
                deadline.assert_called_once_with(60)

    def test_candidate_move_and_selected_stage_follow_actual_pass_and_counted_baseline(self):
        for sufficient in (True, False):
            with self.subTest(sufficient=sufficient), tempfile.TemporaryDirectory() as directory:
                path, owner, executable, provider, rows = self.scene(directory)
                owner.identity = {"start_time": 800}
                candidate = SimpleNamespace(pid=321, identity={"start_time": 876})
                executable.image_receipt = Mock()
                reader = SimpleNamespace(record=Mock(return_value={}))
                callers = iter(((owner, reader, None), (candidate, reader, None)))
                groups = iter(SimpleNamespace(path=Path(directory) / name)
                              for name in ("root", "selected", "outside"))
                ctx = SimpleNamespace(args=SimpleNamespace(uid=1000, gid=1000),
                    pins={"caller": executable}, provider_pin=SimpleNamespace(path=Path("/fixture/provider.so")),
                    owners=[], readers=[],
                    binary=SimpleNamespace(path=Path("/fixture/p11scope")))
                observer = SimpleNamespace(popen=SimpleNamespace(stdout=object(), stderr=object()))
                order = []

                class ReachedSelectedStage(Exception):
                    pass

                def spawn_observer(_owners, argv, _uid, **kwargs):
                    nonlocal path
                    path = Path(argv[argv.index("--event-log") + 1])
                    rows.append({"seq": len(rows), "kind": "pass_committed", "event": {"pass": 0}})
                    self.write_rows(path, rows)
                    # Service the actual StageController socket; this host test
                    # controls transport and ordering, not native stage facts.
                    frames = [{"version": 1, "sequence": 0, "transaction": 0, "event": "armed"},
                              {"version": 1, "sequence": 1, "transaction": 2,
                               "event": "final_pre_read", "pid": 321, "start_time": 876}]
                    os.write(kwargs["pass_fds"][0], "".join(json.dumps(frame) + "\n"
                             for frame in frames).encode())
                    return observer

                def ready(*args):
                    result = H6["wait_inventory_ready"](*args)
                    order.append("first committed pass")
                    return result

                def command(*args):
                    self.assertEqual(order, ["first committed pass"])
                    self.assertEqual(args[:8], (owner, reader, "C_GenerateRandom", 3, 0,
                                                "baseline", "selected", 0))
                    order.append("fixed baseline calls")
                    mutation = None if sufficient else lambda event: event["entries"].update(count=2)
                    self.publish_counted(path, rows, mutation)

                def move(_group, moved, _moves, label):
                    if label == "fresh-mapped-candidate":
                        self.assertIs(moved, candidate)
                        self.assertTrue(sufficient)
                        self.assertEqual(order, ["first committed pass", "fixed baseline calls"])
                        order.append("candidate moved")

                def stop(_ctx, stopped):
                    self.assertIs(stopped, observer)
                    self.assertEqual(order, ["first committed pass", "fixed baseline calls", "candidate moved"])
                    order.append("selected stage")
                    raise ReachedSelectedStage

                command_spy, move_spy, stop_spy = Mock(side_effect=command), Mock(side_effect=move), Mock(side_effect=stop)
                patches = {"init_token": lambda *_args: {}, "provider_receipt": lambda _pin: provider,
                    "create_tracked": lambda *_args: (next(groups), None),
                    "spawn_caller": lambda *_args, **_kwargs: next(callers),
                    "spawn_owned": spawn_observer, "owned_reader": lambda *_args: reader,
                    "wait_inventory_ready": ready, "n3_command": command_spy,
                    "move_and_verify": move_spy, "stop_b_observer": stop_spy,
                    "wait_deadline": lambda seconds: H6["wait_deadline"](min(seconds, 0.02))}
                with patch.dict(STOP["H6"], patches):
                    with self.assertRaises(ReachedSelectedStage if sufficient else TimeoutError):
                        STOP["run_leg"].__wrapped__(ctx, directory, "singles", "final_pre_read", False)
                self.assertEqual(command_spy.call_count, 1)
                self.assertEqual(move_spy.call_count, 3 if sufficient else 2)
                self.assertEqual(stop_spy.call_count, int(sufficient))
                self.assertEqual(order[-1], "selected stage" if sufficient else "fixed baseline calls")


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
