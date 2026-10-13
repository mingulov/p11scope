#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Initial named readiness: real ordinary callers, synthetic public observer."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BASE = runpy.run_path(str(ROOT / "tests/python/test_automatic_exec_oracle.py"))
H6 = BASE["H6"]
INITIAL_FIXTURE = BASE["InitialLoadFixtureTest"]


def initial_inputs(rapid=False):
    if rapid:
        text, ledger, receipt = BASE["rapid_successor_inputs"]()
        rows, counts, evs, _ = H6["N3_PARSE_TRACE"](text)
        lines = text.splitlines()[3:-2]
        for proof in receipt["successor_ready"]:
            proof["output_cursor"] += 1
            proof["proof_cursor"] += 1
        for phase in receipt["phases"]:
            for field in ("output_cursor", "output_end"):
                if field in phase:
                    phase[field] += 1
        receipt.update(cell="rapid-chain", leg="trace/singles")
        returned = counts[0]["stats_returned"]
        ev = evs[0]
    else:
        image = BASE["image_record"](0, "/w/caller-a", BASE["READY"] - 500_000_000)
        ledger = [image, BASE["target_record"](0, "C_GenerateRandom")]
        t0 = BASE["READY"] + 100_000_000
        ledger.extend(BASE["call_record"](0, "C_GenerateRandom", 0, "measured", "selected",
                                          t0 + seq * 10, t0 + seq * 10 + 1) for seq in range(5))
        receipt = BASE["base_receipt"](cell="rapid-chain", leg="reuse/singles", scope_kind="system",
            images=[image], dead_pid=999, exec_transitions=[], require_named=True, require_named_images=[0],
            first_unknown_images=[], phases=[dict(image=0, fn="C_GenerateRandom", phase="measured",
                scope="selected", count=5, t0=t0, t1=t0 + 50)],
            measured=dict(label="host", t0=t0, t1=t0 + 50, expected_calls=5, phases=["measured"]),
            warmup=dict(label="initial", t0=t0, t1=t0, expected_calls=0, phases=[]))
        lines = [BASE["named_row"](1000, 1000, image["path"], "C_GenerateRandom")] * 5
        returned = 5
        ev = BASE["evidence"](attach_backend=dict(selection="singles", fallback=None, scope_filter=None))
    image = receipt["images"][0]
    started, t0, observed = (BASE["READY"] + value for value in (40_000_000, 50_000_000, 60_000_000))
    ledger.extend((BASE["target_record"](0, "C_GetInfo"),
                   BASE["call_record"](0, "C_GetInfo", 0, "initial-0-1", "selected", t0, t0 + 1)))
    phase = dict(image=0, fn="C_GetInfo", phase="initial-0-1", scope="selected", count=1, t0=t0, t1=t0 + 1)
    receipt["phases"].insert(0, phase)
    receipt["warmup"].update(t0=t0, expected_calls=receipt["warmup"]["expected_calls"] + 1,
                              phases=["initial-0-1", *receipt["warmup"]["phases"]])
    if not rapid:
        receipt["warmup"]["t1"] = t0 + 1
    receipt["initial_ready"] = dict(image=0, pid=1000, proof_kind="trace-row", marker_fn="C_GetInfo",
        budget_phase="setup", started_ns=started, observed_ns=observed,
        deadline_ns=started + 15_000_000_000, setup_deadline_ns=BASE["START"] + 330_000_000_000,
        leg_deadline_ns=BASE["START"] + 485_000_000_000, attempts=1, max_attempts=20,
        output_cursor=3, proof_cursor=4, phases=["initial-0-1"],
        provider={key: receipt["provider_before"][key] for key in ("path", "dev", "ino", "sha256")})
    lines.insert(0, BASE["named_row"](1000, 1000, image["path"], "C_GetInfo"))
    return BASE["trace_text"](lines, returned + 1, returned + 1, ev), ledger, receipt


class InitialOracleTest(unittest.TestCase):
    def evaluate(self, text, ledger, receipt):
        return H6["evaluate_trace_h6"](text, ledger, receipt, text)

    def test_actual_oracle_accepts_separate_initial_and_successor_proofs(self):
        for rapid in (False, True):
            with self.subTest(rapid=rapid):
                result = self.evaluate(*initial_inputs(rapid))
                self.assertTrue(result["pass"], result["errors"])
                self.assertEqual(result["measured_calls"], 2 if rapid else 5)

    def test_reuse_named_initial_marker_cannot_cover_unknown_measured_returns(self):
        for unknown in (1, 5):
            with self.subTest(unknown=unknown):
                text, ledger, receipt = initial_inputs()
                lines = text.splitlines()
                changed = 0
                for index, line in enumerate(lines):
                    match = H6["ROW"].fullmatch(line)
                    if match and match["fn"] == "C_GenerateRandom" and changed < unknown:
                        lines[index] = BASE["unknown_row"](int(match["pid"]), int(match["tid"]), match["fn"])
                        changed += 1
                self.assertEqual(changed, unknown)
                result = self.evaluate("\n".join(lines) + "\n", ledger, receipt)
                self.assertFalse(result["pass"], result["errors"])
                self.assertEqual(result["phase_populations"]["initial-0-1"], {"named": 1})
                self.assertEqual(result["phase_populations"]["measured"].get("unknown", 0), unknown)
                self.assertTrue(any("reuse measured" in error for error in result["errors"]), result["errors"])

    def test_reuse_requires_five_correct_measured_names_with_valid_initial_readiness(self):
        result = self.evaluate(*initial_inputs())
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["phase_populations"]["measured"], {"named": 5})
        for change in ("foreign-pid", "wrong-path", "wrong-label"):
            text, ledger, receipt = initial_inputs()
            lines = text.splitlines()
            index = next(index for index, line in enumerate(lines) if " C_GenerateRandom " in line)
            if change == "foreign-pid":
                lines[index] = lines[index].replace("PID 1000", "PID 999")
            elif change == "wrong-path":
                lines[index] = lines[index].replace('exe="/w/caller-a"', 'exe="/foreign/caller-a"')
            else:
                lines[index] = lines[index].replace('"caller-a"', '"foreign"', 1)
            with self.subTest(change=change):
                self.assertFalse(self.evaluate("\n".join(lines) + "\n", ledger, receipt)["pass"])

    def test_reuse_fixed_measured_function_rv_and_population_cannot_change_coherently(self):
        for change in ("remove", "function", "return"):
            text, ledger, receipt = initial_inputs()
            lines = text.splitlines()[3:-2]
            measured = [row for row in ledger if row.get("phase") == "measured"]
            if change == "remove":
                lines.pop()
                ledger.remove(measured[-1])
                receipt["measured"]["expected_calls"] = 4
                receipt["phases"][-1]["count"] = 4
            elif change == "function":
                lines[-1] = lines[-1].replace("C_GenerateRandom", "C_GetInfo")
                measured[-1]["fn"] = "C_GetInfo"
            else:
                lines[-1] = lines[-1].replace("CKR_OK", "CKR_GENERAL_ERROR")
                measured[-1]["rv"] = 5
            ev = BASE["evidence"](attach_backend=dict(selection="singles", fallback=None, scope_filter=None))
            with self.subTest(change=change):
                changed = BASE["trace_text"](lines, len(lines), len(lines), ev)
                self.assertFalse(self.evaluate(changed, ledger, receipt)["pass"])

    def test_named_measured_rows_do_not_replace_a_required_initial_proof(self):
        for rapid in (False, True):
            text, ledger, receipt = initial_inputs(rapid)
            del receipt["initial_ready"]
            result = self.evaluate(text, ledger, receipt)
            self.assertFalse(result["pass"], result["errors"])

    def test_wrong_owned_subject_provider_cursor_time_and_attempt_proofs_fail(self):
        changes = [("pid", 999), ("image", 1), ("marker_fn", "C_GenerateRandom"),
                   ("budget_phase", "successor-recovery"), ("attempts", True), ("attempts", 21),
                   ("max_attempts", 21), ("output_cursor", 4), ("proof_cursor", 5),
                   ("phases", ["measured"]), ("started_ns", BASE["READY"] - 1),
                   ("observed_ns", BASE["READY"] + 200_000_000)]
        for field, value in changes:
            with self.subTest(field=field):
                text, ledger, receipt = initial_inputs()
                receipt["initial_ready"][field] = value
                self.assertFalse(self.evaluate(text, ledger, receipt)["pass"])
        for change in ("late", "setup", "leg", "provider"):
            text, ledger, receipt = initial_inputs()
            proof = receipt["initial_ready"]
            if change == "late":
                proof["deadline_ns"] += 1
            elif change == "provider":
                proof["provider"]["ino"] += 1
            else:
                proof[f"{change}_deadline_ns"] = proof["deadline_ns"] - 1
            self.assertFalse(self.evaluate(text, ledger, receipt)["pass"])

    def test_foreign_tid_image_provider_and_late_warm_calls_fail(self):
        for field, value in [("pid", 999), ("tid", 999), ("image", 1), ("rv", 5),
                             ("scope", "outside"), ("t1", BASE["READY"] + 70_000_000)]:
            text, ledger, receipt = initial_inputs()
            next(row for row in ledger if row.get("phase") == "initial-0-1")[field] = value
            self.assertFalse(self.evaluate(text, ledger, receipt)["pass"])
        text, ledger, receipt = initial_inputs()
        next(row for row in ledger if row.get("kind") == "target" and row["fn"] == "C_GetInfo")["ino"] += 1
        self.assertFalse(self.evaluate(text, ledger, receipt)["pass"])

    def test_measured_or_later_cyclic_image_rows_cannot_supply_initial_proof(self):
        for rapid in (False, True):
            text, ledger, receipt = initial_inputs(rapid)
            lines = text.splitlines()
            lines.insert(-2, lines.pop(3))
            receipt["initial_ready"]["proof_cursor"] = len(lines) - 2
            changed = "\n".join(lines) + "\n"
            self.assertFalse(self.evaluate(changed, ledger, receipt)["pass"])

    def test_coherent_extra_warm_attempt_is_not_hidden_by_an_earlier_proof(self):
        text, ledger, receipt = initial_inputs()
        original = next(row for row in ledger if row.get("phase") == "initial-0-1")
        extra = dict(original, phase="initial-0-2", t0=original["t0"] + 2, t1=original["t1"] + 2)
        ledger.append(extra)
        receipt["phases"].insert(1, dict(image=0, fn="C_GetInfo", phase=extra["phase"], count=1,
                                         scope="selected", t0=extra["t0"], t1=extra["t1"]))
        receipt["warmup"].update(t1=extra["t1"], expected_calls=2, phases=["initial-0-1", "initial-0-2"])
        lines = text.splitlines()[3:-2]
        lines.insert(1, BASE["unknown_row"](1000, 1000, "C_GetInfo"))
        changed = BASE["trace_text"](lines, 7, 7, BASE["evidence"]())
        self.assertFalse(self.evaluate(changed, ledger, receipt)["pass"])


OBSERVER = r'''
import json,pathlib,signal,sys,time
done=False
def stop(*_):
    global done
    done=True
signal.signal(signal.SIGINT,stop)
ledger_path,output=map(pathlib.Path,sys.argv[1:3])
backend,system=sys.argv[3:5]
def ledger():
    return [json.loads(line[9:]) for line in ledger_path.read_text().splitlines()
            if line.startswith('N3LEDGER ')]
seen=sum(row['kind']=='call' for row in ledger()); warm={}; count=0
headers=['Trace — completed call events in arrival order',
    'Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.',
    'CAPTURE privacy=allowlisted']
output.write_text('\n'.join(headers)+'\n');print('\n'.join(headers),flush=True)
print('p11scope: capturing: 1 probe(s) attached; stop with Ctrl-C',file=sys.stderr,flush=True)
while True:
    records=ledger();images={row['image']:row for row in records if row['kind']=='image'}
    calls=[row for row in records if row['kind']=='call']
    for row in calls[seen:]:
        image=images[row['image']]
        if row['phase'].startswith(('initial-','successor-')):
            warm[row['image']]=warm.get(row['image'],0)+1
        prefix=('21:37:58.638119 '+json.dumps(pathlib.Path(image['path']).name)+
            ' (PID '+str(row['pid'])+', TID '+str(row['tid'])+') exe='+json.dumps(image['path'])) if warm.get(row['image'],0)>=3 else (
            '21:37:58.638119 Unknown executable (PID '+str(row['pid'])+', TID '+str(row['tid'])+')')
        line=prefix+' '+row['fn']+' [semantics unverified] → CKR_OK 10µs'
        print(line,flush=True)
        with output.open('a') as stream:stream.write(line+'\n')
        count+=1
    seen=len(calls)
    if done:break
    time.sleep(.005)
tail=['COUNT_EVIDENCE '+json.dumps(dict(stats_entered=count,stats_returned=count,raw_calls=count)),
    'EVIDENCE '+json.dumps(dict(privacy_mode='allowlisted',trace_truncated=False,event_loss=0,
        start_insert_failures=0,unmatched_returns=0,rv_update_failures=0,cgroup_scope_failures=0,
        process_tracking_failures=0,process_tracking_evictions=0,final_drain=True,completeness='PARTIAL',
        in_flight_at_end=0,task_uprobe_link_losses=0,attach_backend=dict(selection=backend,fallback=None,
            scope_filter=None if system=='yes' else 'perf-task+bpf' if backend=='singles' else 'kernel-pid+bpf')))]
text='\n'.join(tail)+'\n';print(text,end='',flush=True)
with output.open('a') as stream:stream.write(text)
'''


class InitialProducerTest(unittest.TestCase):
    setUpClass = classmethod(INITIAL_FIXTURE.setUpClass.__func__)
    start = INITIAL_FIXTURE.start
    send = INITIAL_FIXTURE.send

    def setUp(self):
        self.directory = type(self).directory / f"initial-{time.monotonic_ns()}"
        self.directory.mkdir()
        self.ctx = H6["Case"](SimpleNamespace(out=self.directory, uid=os.getuid(), gid=os.getgid()))
        self.ctx.provider_pin = H6["FilePin"](self.provider)
        self.ctx.binary = H6["FilePin"](Path(sys.executable))
        self.ctx.leg_pins.extend((self.ctx.provider_pin, self.ctx.binary))
        self.ctx.pins = {"caller": self.pin}
        self.addCleanup(H6["cleanup_leg_resources"], self.ctx)
        self.spawned = []

    def spawn(self, owners, argv, uid, **options):
        if "user" in options:
            self.assertEqual(options.pop("user"), os.getuid())
            self.assertEqual(options.pop("group"), os.getgid())
            self.assertEqual(options.pop("extra_groups"), [])
        owner = self.real_spawn(owners, argv, uid, **options)
        self.spawned.append(owner)
        return owner

    def observer(self, owners, readers, directory, argv, env, **_options):
        started = time.monotonic_ns()
        path = Path(directory)
        source = next(path.glob("*.ledger.jsonl"))
        backend = argv[argv.index("--attach-backend") + 1]
        owner = self.real_spawn(owners, [sys.executable, "-c", OBSERVER, str(source), argv[-1],
            backend, "yes" if "--system" in argv else "no"], os.getuid(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
        self.spawned.append(owner)
        capture = H6["owned_reader"](readers, H6["Reader"], owner.popen.stdout, path / "observer.stdout.txt")
        errors = H6["owned_reader"](readers, H6["Reader"], owner.popen.stderr, path / "observer.stderr.txt")
        return owner, capture, errors, started

    def patches(self):
        self.real_spawn = H6["spawn_owned"]
        return mock.patch.dict(H6["run_rapid_chain"].__globals__, dict(
            init_token=lambda *_args: dict(self.env), spawn_owned=self.spawn,
            spawn_observer=self.observer,
            run_group_death_leg=lambda *_args: {"leg": "group-death/control-excluded"}))

    def assert_released(self):
        self.assertTrue(all(owner.popen.poll() is not None and owner.pidfd is None for owner in self.spawned))
        self.assertTrue(all(not scope.owners and not scope.readers for scope in self.ctx.scopes))

    def test_rapid_real_callers_prove_initial_image_without_a_fourth_successor_slot(self):
        with self.patches():
            results = H6["run_rapid_chain"](self.ctx, self.directory / "rapid", "singles")
        self.assertTrue(results[0]["pass"], results[0]["errors"])
        self.assertTrue(results[1]["pass"], results[1]["errors"])
        receipt = json.loads((self.directory / "rapid/singles/trace/receipt.json").read_text())
        self.assertEqual(receipt["initial_ready"]["attempts"], 3)
        self.assertEqual(results[0]["phase_populations"]["warm"], {"named": 2})
        self.assertEqual(results[0]["phase_populations"]["measured"], {"named": 10})
        self.assertEqual([proof["image"] for proof in receipt["successor_ready"]], [1, 2, 3])
        keys = [{key for phase, key in scope.budget.deadlines if phase == "successor-recovery"}
                for scope in self.ctx.scopes]
        self.assertEqual([group for group in keys if group], [{1, 2, 3}])
        self.assert_released()

    def test_reuse_real_new_child_initial_proof_precedes_the_fixed_five_calls(self):
        owner, reader = self.start()
        reader.record("ready", 0, seconds=2)
        dead_pid = owner.pid
        H6["stop_caller"](owner, reader, 0)
        H6["finish_readers"](self.ctx.readers)
        H6["cleanup_leg_resources"](self.ctx, close_pins=False)
        with self.patches():
            result = H6["run_reuse_control"](self.ctx, self.directory / "reuse", "singles", self.env,
                                             dead_pid, self.pin)
        self.assertTrue(result["pass"], result["errors"])
        receipt = json.loads((self.directory / "reuse/receipt.json").read_text())
        self.assertEqual(receipt["initial_ready"]["attempts"], 3)
        self.assertEqual(receipt["successor_policy"], "no-transition")
        self.assertNotIn("successor_ready", receipt)
        self.assertEqual(result["phase_populations"]["measured"], {"named": 5})
        self.assertFalse(any(phase == "successor-recovery" for phase, _ in self.ctx.scopes[-1].budget.deadlines))
        self.assert_released()

    def test_provider_verification_cannot_dispatch_a_marker_after_the_local_fifteen_seconds(self):
        owner, reader = self.start()
        reader.record("ready", 0, seconds=2)
        image = self.pin.image_receipt(reader.record("image", 0), owner)
        now = [time.monotonic_ns()]
        budget = H6["LegBudget"](clock=lambda: now[0])
        self.ctx.budget = budget
        token = H6["ACTIVE_LEG"].set(budget)
        real_pin = H6["provider_receipt"]
        def slow_pin(pin):
            value = real_pin(pin)
            now[0] = budget.started_ns + 15_000_000_001
            return value
        try:
            with mock.patch.dict(H6["warm_initial_caller"].__globals__, dict(
                    monotonic_ns=lambda: now[0], provider_receipt=slow_pin)):
                with self.assertRaises(TimeoutError):
                    H6["warm_initial_caller"](self.ctx, SimpleNamespace(lines=[]), owner, reader,
                                              image, self.pin, self.ctx.provider_pin, [])
            self.assertFalse(any(row.get("phase", "").startswith("initial-") for row in reader.records),
                             "verification spent the local limit but a real marker still dispatched")
        finally:
            H6["ACTIVE_LEG"].reset(token)


del INITIAL_FIXTURE  # unittest must discover only this module's focused controls.


if __name__ == "__main__":
    unittest.main()
