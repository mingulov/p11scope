#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cgroup replacement controls; synthetic captures, no BPF or cgroup writes."""

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
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-cgroup-replacement.py"
Q = runpy.run_path(str(SCRIPT)) if SCRIPT.exists() else {}
H6 = Q.get("H6") or runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))


def synthetic_inputs():
    image = dict(kind="image", image=0, pid=222, start_time=900,
                 path="/w/caller", dev=8, ino=70, mtime_ns=88,
                 pid_namespace=1, time_namespace=2, t=40)
    identity = dict(pid=222, ppid=99, start_time=900, uid=1000,
                    pid_namespace=1, time_namespace=2)
    old_identity = dict(identity, pid=111, start_time=800)
    old_image = dict(image, pid=111, start_time=800, t=10)
    provider = dict(path="/w/lib.so", dev=[8, 1], ino=77, sha256="a" * 64,
                    mapping=dict(dev=[8, 1], ino=77))
    root = dict(path="/sys/fs/cgroup/owned/selected", dev=5, ino=123)
    descendant = dict(path=root["path"] + "/sub", dev=5, ino=124)
    membership = "/owned/selected/sub"
    receipt = dict(cell="cgroup-process-replacement", leg="replacement/singles",
                   scope_kind="cgroup", owned_pids=[222], images=[image],
                   provider_before=provider, provider_after=copy.deepcopy(provider),
                   privacy_canaries=[], observer_stderr="", observer_rc=0, caller_rc=0,
                   observer_started_ns=50, observer_ready_ns=60, observer_stopped_ns=100,
                   scope_created_ns=1, stop_latency_seconds=0.1, stop_limit_seconds=60,
                   pid_namespace=1, time_namespace=2,
                   scope_intervals=[dict(pid=222, membership="selected", t0=60, t1=100)],
                   measured=dict(label="replacement", t0=70, t1=80,
                                 expected_calls=5, phases=["measured"]),
                   warmup=dict(label="none", t0=70, t1=70, expected_calls=0, phases=[]),
                   phases=[dict(image=0, fn="C_GenerateRandom", phase="measured",
                                scope="selected", count=5, t0=70, t1=80)],
                   exec_transitions=[], require_named=True, require_named_images=[0],
                   first_unknown_images=[], successor_policy="no-transition",
                   manual_rebind=False, abandoned_expected=0, abandoned_by_fn={},
                   reuse_expected={}, requested_backend="singles", fresh_observer=True,
                   observer_argv=["/w/p11scope", "trace", "--cgroup", root["path"],
                                  "--module", provider["path"], "--attach-backend", "singles",
                                  "--duration", "120s", "-o", "/w/trace.file.txt"],
                   executable_pin=dict(path=image["path"], dev=8, ino=70, mtime_ns=88),
                   replacement=dict(original_identity=old_identity, original_image=old_image,
                       replacement_identity=identity, replacement_image=image,
                       original_mapping=dict(dev=[8, 1], ino=77),
                       replacement_mapping=dict(dev=[8, 1], ino=77),
                       root_before=root, root_after=copy.deepcopy(root),
                       descendant_before=descendant, descendant_after=copy.deepcopy(descendant),
                       membership_before=membership, membership_after=membership,
                       original_group=111, kill_ns=20, death_ns=30, replacement_spawn_ns=35,
                       original_reaped=True, original_proc_gone=True, original_pidfd_exited=True,
                       original_rc=-signal.SIGKILL, manufactured_reuse=False,
                       continuous_membership="unknown"))
    ledger = [image, dict(kind="target", image=0, fn="C_GenerateRandom",
                         dev=[8, 1], ino=77, file_offset=4096)]
    ledger.extend(dict(kind="call", image=0, pid=222, tid=222, fn="C_GenerateRandom",
                       rv=0, phase="measured", scope="selected", t0=71 + n, t1=72 + n)
                  for n in range(5))
    rows = ['21:37:58.638119 "caller" (PID 222, TID 222) exe="/w/caller" '
            'C_GenerateRandom [semantics unverified] → CKR_OK 10µs'] * 5
    evidence = dict(privacy_mode="allowlisted", trace_truncated=False, event_loss=0,
                    start_insert_failures=0, unmatched_returns=0, rv_update_failures=0,
                    cgroup_scope_failures=0, process_tracking_failures=0,
                    process_tracking_evictions=0, final_drain=True, completeness="PARTIAL",
                    in_flight_at_end=0, task_uprobe_link_losses=0,
                    attach_backend=dict(selection="singles", fallback=None, scope_filter=None))
    return rows, evidence, ledger, receipt


def trace_text(rows, evidence):
    return "\n".join(["Trace — completed call events in arrival order",
        "Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.",
        "CAPTURE privacy=allowlisted", *rows,
        "COUNT_EVIDENCE " + json.dumps(dict(stats_entered=len(rows), stats_returned=len(rows),
                                            raw_calls=len(rows))),
        "EVIDENCE " + json.dumps(evidence)]) + "\n"


class ReplacementOracleTests(unittest.TestCase):
    def evaluate(self, rows=None, evidence=None, ledger=None, receipt=None):
        base = synthetic_inputs()
        text = trace_text(base[0] if rows is None else rows,
                          base[1] if evidence is None else evidence)
        return Q["evaluate_replacement"](text, base[2] if ledger is None else ledger,
                                         base[3] if receipt is None else receipt, text)

    def test_qualifier_exists(self):
        self.assertIn("evaluate_replacement", Q, "Cgroup process-replacement qualifier is absent")

    def test_nonempty_independent_replacement_is_accepted(self):
        result = self.evaluate()
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual((result["calls"], result["named"], result["unknown"]), (5, 5, 0))

    def test_invalid_death_custody_and_root_proofs_are_rejected(self):
        mutations = [
            ("original_reaped", False), ("original_proc_gone", False),
            ("original_pidfd_exited", False), ("original_rc", 0),
            ("original_group", 222), ("manufactured_reuse", True),
            ("continuous_membership", "proven"), ("replacement_spawn_ns", 29),
            ("death_ns", 51), ("membership_after", "/outside"),
            ("root_after", dict(path="/sys/fs/cgroup/other", dev=5, ino=123)),
            ("descendant_after", dict(path="/sys/fs/cgroup/owned/selected/sub", dev=5, ino=999)),
            ("original_mapping", dict(dev=[9, 9], ino=77)),
            ("replacement_mapping", dict(dev=[8, 1], ino=78)),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                receipt = synthetic_inputs()[3]
                receipt["replacement"][field] = value
                self.assertFalse(self.evaluate(receipt=receipt)["pass"])
        for who, field, value in [("original_image", "start_time", 7),
                                  ("original_image", "ino", 999),
                                  ("original_identity", "ppid", 88),
                                  ("replacement_identity", "pid", 111)]:
            with self.subTest(who=who, field=field):
                receipt = synthetic_inputs()[3]
                receipt["replacement"][who][field] = value
                self.assertFalse(self.evaluate(receipt=receipt)["pass"])

    def test_no_readiness_wrong_scope_forced_stop_and_fallback_are_rejected(self):
        for field, value in [("observer_ready_ns", 0), ("fresh_observer", False),
                             ("forced_cleanup", True), ("observer_rc", 2)]:
            with self.subTest(field=field):
                receipt = synthetic_inputs()[3]
                receipt[field] = value
                self.assertFalse(self.evaluate(receipt=receipt)["pass"])
        for change in ("--system", "--pid"):
            receipt = synthetic_inputs()[3]
            receipt["observer_argv"][2] = change
            self.assertFalse(self.evaluate(receipt=receipt)["pass"])
        for field, value in [("fallback", "global"), ("selection", "multi"),
                             ("scope_filter", "kernel-pid+bpf")]:
            evidence = synthetic_inputs()[1]
            evidence["attach_backend"][field] = value
            self.assertFalse(self.evaluate(evidence=evidence)["pass"])

    def test_empty_unknown_missing_duplicate_wrong_rv_and_foreign_rows_are_rejected(self):
        rows = synthetic_inputs()[0]
        cases = [[], rows[:-1], rows + rows[:1],
                 [row.replace('"caller"', 'Unknown executable').replace(' exe="/w/caller"', '')
                  for row in rows],
                 [row.replace("CKR_OK", "CKR_GENERAL_ERROR") for row in rows],
                 [row.replace("PID 222", "PID 333") for row in rows],
                 [row.replace('/w/caller', '/w/other') for row in rows]]
        for index, changed in enumerate(cases):
            with self.subTest(case=index):
                self.assertFalse(self.evaluate(rows=changed)["pass"])
        evidence = synthetic_inputs()[1]
        evidence["event_loss"] = 1
        self.assertFalse(self.evaluate(evidence=evidence)["pass"])
        ledger = synthetic_inputs()[2]
        ledger[-1]["scope"] = "outside"
        self.assertFalse(self.evaluate(ledger=ledger)["pass"])

    def test_backend_refusal_remains_negative(self):
        result = self.evaluate(rows=[], receipt=dict(synthetic_inputs()[3], backend_refused="unsupported"))
        self.assertFalse(result["pass"])
        self.assertEqual(result["status"], "negative")

    def test_coherent_same_numeric_pid_cannot_claim_independent_replacement(self):
        rows, evidence, ledger, receipt = synthetic_inputs()
        receipt["owned_pids"] = [111]
        receipt["scope_intervals"][0]["pid"] = 111
        receipt["replacement"]["replacement_identity"]["pid"] = 111
        # The trusted image and ledger image share this hand-built input row.
        receipt["images"][0]["pid"] = 111
        for row in ledger:
            if row.get("kind") == "call":
                row["pid"] = row["tid"] = 111
        rows = [row.replace("PID 222, TID 222", "PID 111, TID 111") for row in rows]
        plain = H6["evaluate_trace_h6"](trace_text(rows, evidence), ledger, receipt)
        self.assertTrue(plain["pass"], plain["errors"])
        result = self.evaluate(rows, evidence, ledger, receipt)
        self.assertFalse(result["pass"])
        self.assertTrue(any("different-PID" in error for error in result["errors"]))


class OwnedFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h6-cgroup-replacement-",
                                                dir=os.environ.get("TMPDIR", "/var/tmp"))
        self.directory = Path(self.tmp.name)
        self.ctx = H6["Case"](SimpleNamespace(out=self.directory))
        self.exe = H6["FilePin"](Path(sys.executable))
        self.ctx.leg_pins.append(self.exe)
        path = self.directory / "inert.bin"
        path.write_bytes(b"inert provider mapping\n" * 200)
        self.provider = H6["FilePin"](path)
        self.ctx.leg_pins.append(self.provider)

    def tearDown(self):
        H6["cleanup_leg_resources"](self.ctx)
        self.tmp.cleanup()

    def spawn(self, pin=None):
        pin = pin or self.provider
        code = "import mmap,sys,time; f=open(sys.argv[1],'rb'); m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ); print('ready',flush=True); time.sleep(60)"
        owner = H6["spawn_owned"](self.ctx.owners, [str(self.exe.path), "-c", code, str(pin.path)],
            os.geteuid(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        self.assertEqual(owner.popen.stdout.readline().strip(), "ready")
        image = self.exe.image_receipt(dict(image=0), owner)
        return owner, image


class OwnedDeathAndMappingTests(OwnedFixture, unittest.TestCase):
    def test_owned_group_death_precedes_different_pid_with_same_inert_provider(self):
        old, image = self.spawn()
        original = Q["capture_original"](self.ctx, old, self.exe, image, self.provider)
        death = Q["kill_original"](self.ctx, old, self.exe, original)
        new, new_image = self.spawn()
        Q["check_replacement"](self.ctx, old, original, death, new, new_image, self.exe)
        self.assertNotEqual(old.pid, new.pid)
        self.assertEqual(death["original_rc"], -signal.SIGKILL)
        self.assertFalse((Path("/proc") / str(old.pid)).exists())
        self.assertEqual(Q["mapped_provider"](new, self.provider)["ino"], self.provider.initial.st_ino)

    def test_still_live_original_cannot_admit_replacement(self):
        old, image = self.spawn()
        original = Q["capture_original"](self.ctx, old, self.exe, image, self.provider)
        new, new_image = self.spawn()
        with self.assertRaises(ValueError):
            Q["check_replacement"](self.ctx, old, original, {}, new, new_image, self.exe)

    def test_wrong_original_owner_birth_and_executable_are_refused_before_kill(self):
        old, image = self.spawn()
        original = Q["capture_original"](self.ctx, old, self.exe, image, self.provider)
        new, _ = self.spawn()
        with self.assertRaises(ValueError):
            Q["kill_original"](self.ctx, new, self.exe, original)
        original["original_identity"]["start_time"] += 1
        with self.assertRaises(ValueError):
            Q["kill_original"](self.ctx, old, self.exe, original)
        self.assertIsNone(old.popen.poll())
        with self.assertRaises(ValueError):
            Q["capture_original"](self.ctx, old, self.provider, image, self.provider)

    def test_foreign_inert_provider_mapping_is_refused(self):
        other_path = self.directory / "foreign.bin"
        other_path.write_bytes(b"foreign" * 1000)
        other = H6["FilePin"](other_path)
        self.ctx.leg_pins.append(other)
        owner, _ = self.spawn(other)
        with self.assertRaises(ValueError):
            Q["mapped_provider"](owner, self.provider)


CALLER_CODE = r'''
import json,mmap,os,sys,time
def emit(**row): print('N3LEDGER '+json.dumps(row),flush=True)
pid=os.getpid(); proc='/proc/'+str(pid)
fields=open(proc+'/stat').read().rsplit(')',1)[1].split()
exe=os.readlink(proc+'/exe'); info=os.stat(proc+'/exe')
f=open(sys.argv[1],'rb'); mapping=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
emit(kind='image',image=0,pid=pid,start_time=int(fields[19]),path=exe,dev=info.st_dev,
     ino=info.st_ino,mtime_ns=info.st_mtime_ns,pid_namespace=os.stat(proc+'/ns/pid').st_ino,
     time_namespace=os.stat(proc+'/ns/time').st_ino,t=time.monotonic_ns())
for line in open(proc+'/maps'):
    row=line.split()
    if len(row)>5 and row[-1]==sys.argv[1]:
        dev=[int(v,16) for v in row[3].split(':')]; ino=int(row[4]); break
emit(kind='target',image=0,fn='C_GenerateRandom',dev=dev,ino=ino,file_offset=0)
emit(kind='ready',image=0,pid=pid,t=time.monotonic_ns())
for line in sys.stdin:
    argv=line.split()
    if argv[0]=='stop':
        emit(kind='ack',image=0,phase='done',pid=pid,t=time.monotonic_ns()); break
    _,fn,count,delay,phase,scope=argv
    for n in range(int(count)):
        t=time.monotonic_ns()
        emit(kind='call',image=0,pid=pid,tid=pid,fn=fn,rv=0,phase=phase,scope=scope,t0=t,t1=t+1)
    emit(kind='ack',image=0,phase=phase,pid=pid,t=time.monotonic_ns())
'''

OBSERVER_CODE = r'''
import json,pathlib,signal,sys,time
done=False
def stop(*_):
    global done
    done=True
signal.signal(signal.SIGINT,stop)
print('p11scope: capturing: 1 probe(s) attached; stop with Ctrl-C',file=sys.stderr,flush=True)
while not done: time.sleep(.005)
ledger=[json.loads(line[9:]) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()
        if line.startswith('N3LEDGER ')]
image=next(row for row in ledger if row['kind']=='image')
calls=[row for row in ledger if row['kind']=='call']
lines=['Trace — completed call events in arrival order',
       'Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.',
       'CAPTURE privacy=allowlisted']
for row in calls:
    lines.append('21:37:58.638119 '+json.dumps(pathlib.Path(image['path']).name)+
        ' (PID '+str(row['pid'])+', TID '+str(row['tid'])+') exe='+json.dumps(image['path'])+
        ' '+row['fn']+' [semantics unverified] → CKR_OK 10µs')
lines.append('COUNT_EVIDENCE '+json.dumps(dict(stats_entered=len(calls),stats_returned=len(calls),raw_calls=len(calls))))
lines.append('EVIDENCE '+json.dumps(dict(privacy_mode='allowlisted',trace_truncated=False,
    event_loss=0,start_insert_failures=0,unmatched_returns=0,rv_update_failures=0,
    cgroup_scope_failures=0,process_tracking_failures=0,process_tracking_evictions=0,
    final_drain=True,completeness='PARTIAL',in_flight_at_end=0,task_uprobe_link_losses=0,
    attach_backend=dict(selection=sys.argv[3],fallback=None,scope_filter=None))))
text='\n'.join(lines)+'\n'; pathlib.Path(sys.argv[2]).write_text(text)
print(text,end='',flush=True)
'''


class StandinGroup:
    """Held ordinary disk directory; logical cgroup paths are synthetic."""
    def __init__(self, disk, path):
        self.disk, self.path = disk, path
        self.fd = os.open(disk, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        info = os.fstat(self.fd)
        self.identity = info.st_dev, info.st_ino
        self.group = self

    def verify(self):
        held, current = os.fstat(self.fd), self.disk.stat()
        if self.identity != (held.st_dev, held.st_ino) or self.identity != (current.st_dev, current.st_ino):
            raise ValueError("stand-in original root was replaced")

    def remove(self):
        self.verify()
        self.disk.rmdir()
        os.close(self.fd)
        self.fd = None


class StandinIO:
    """Real ordinary children and readers at the controller's live boundary."""
    def __init__(self, failure=None):
        self.failure, self.memberships, self.owners = failure, {}, []

    def create_tree(self, ctx):
        disk = Path(ctx.args.out) / "groups"
        logical = Path("/sys/fs/cgroup/standin-owned")
        groups = []
        for disk_path, path in [(disk, logical), (disk / "selected", logical / "selected"),
                                (disk / "selected/sub", logical / "selected/sub")]:
            disk_path.mkdir()
            group = StandinGroup(disk_path, path)
            ctx.groups.append(group)
            groups.append(group)
        return groups[1:]

    def spawn_caller(self, ctx, directory, image_pin, env, tag):
        owner = H6["spawn_owned"](ctx.owners, [str(image_pin.path), "-c", CALLER_CODE,
                                                 str(ctx.provider_pin.path)], os.geteuid(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        self.owners.append(owner)
        stdout = H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stdout,
                                     directory / f"{tag}.ledger.jsonl")
        stderr = H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stderr,
                                     directory / f"{tag}.stderr.txt")
        if self.failure == "partial-caller":
            raise ValueError("injected failure after owned child and reader acquisition")
        return owner, stdout, stderr

    def move(self, group, owner):
        self.memberships[owner.pid] = "/" + str(group.path.relative_to("/sys/fs/cgroup"))
        return self.membership(group, owner)

    def membership(self, group, owner):
        group.verify()
        owner.verify()
        actual = self.memberships[owner.pid]
        if actual != "/" + str(group.path.relative_to("/sys/fs/cgroup")):
            raise ValueError("stand-in caller left the selected descendant")
        return actual

    def spawn_observer(self, ctx, directory, argv, env):
        started = time.monotonic_ns()
        if self.failure == "no-readiness":
            code, extra = "raise SystemExit(2)", []
        elif self.failure == "backend-refused":
            code, extra = "import sys; print('requested backend not supported',file=sys.stderr,flush=True); raise SystemExit(2)", []
        elif self.failure == "nonzero-stop":
            code, extra = "import signal,time,sys; signal.signal(signal.SIGINT,lambda *_:sys.exit(2)); print('p11scope: capturing: 1 probe(s) attached; stop with Ctrl-C',file=sys.stderr,flush=True); time.sleep(60)", []
        else:
            code, extra = OBSERVER_CODE, [str(directory / "replacement.ledger.jsonl"), argv[-1], argv[7]]
        owner = H6["spawn_owned"](ctx.owners, [sys.executable, "-c", code, *extra], os.geteuid(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        self.owners.append(owner)
        capture = H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stdout,
                                      directory / "observer.stdout.txt")
        errors = H6["owned_reader"](ctx.readers, H6["Reader"], owner.popen.stderr,
                                     directory / "observer.stderr.txt")
        if self.failure == "partial-observer":
            raise ValueError("injected failure after observer ownership acquisition")
        return owner, capture, errors, started

    def command(self, caller, reader, group, phases):
        self.membership(group, caller)
        H6["n3_command"](caller, reader, "C_GenerateRandom", 5, 0,
                          "measured", "selected", phases=phases)
        if self.failure == "foreign-membership":
            self.memberships[caller.pid] = "/outside"


class ControllerWiringTests(OwnedFixture, unittest.TestCase):
    def run_controller(self, failure=None):
        self.ctx.binary, self.ctx.provider_pin = self.exe, self.provider
        self.ctx.args.uid, self.ctx.args.gid = os.geteuid(), os.getegid()
        io = StandinIO(failure)
        directory = self.directory / "cell"
        try:
            result = Q["run_replacement"](self.ctx, directory, "singles", {}, self.exe, io)
        finally:
            self.assertTrue(all(owner.popen.returncode is not None for owner in io.owners))
            self.assertTrue(all(owner.pidfd is None for owner in io.owners))
            self.assertTrue(all(not scope.owners and not scope.readers and not scope.groups
                                for scope in self.ctx.scopes))
            self.assertFalse((self.directory / "groups").exists())
        return result, directory

    def test_controller_matches_real_child_ledger_to_synthetic_fresh_observer(self):
        result, directory = self.run_controller()
        self.assertTrue(result["pass"], result["errors"])
        receipt = json.loads((directory / "receipt.json").read_text())
        self.assertNotEqual(receipt["replacement"]["original_identity"]["pid"], receipt["owned_pids"][0])
        self.assertLess(receipt["replacement"]["death_ns"], receipt["observer_started_ns"])
        self.assertEqual(result["measured_calls"], 5)

    def test_partial_constructor_and_readiness_failures_release_owned_handles(self):
        for failure in ("partial-caller", "partial-observer", "no-readiness", "foreign-membership"):
            with self.subTest(failure=failure):
                # Each failed leg has independent disk output and owners.
                with tempfile.TemporaryDirectory(dir=self.directory) as disk:
                    previous = self.directory
                    self.directory = Path(disk)
                    self.ctx.args.out = self.directory
                    try:
                        with self.assertRaises((ValueError, H6["SetupError"])):
                            self.run_controller(failure)
                    finally:
                        self.directory = previous

    def test_nonzero_normal_stop_prevents_acceptance(self):
        with self.assertRaises(H6["LegCleanupError"]):
            self.run_controller("nonzero-stop")
        self.assertTrue(self.ctx.cleanup_failed)

    def test_actual_stand_in_refusal_is_negative_and_all_handles_are_released(self):
        result, _ = self.run_controller("backend-refused")
        self.assertFalse(result["pass"])
        self.assertEqual(result["status"], "negative")

    def test_forced_stop_uses_owned_kill_and_blocks_the_next_backend(self):
        code = "import signal,time; signal.signal(signal.SIGINT,signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
        owner = H6["spawn_owned"](self.ctx.owners, [sys.executable, "-c", code], os.geteuid(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.assertEqual(owner.popen.stdout.readline().strip(), "ready")
        with self.assertRaises(H6["LegCleanupError"]):
            Q["stop_capture"](self.ctx, owner, limit_seconds=0.1)
        self.assertTrue(self.ctx.cleanup_failed)
        self.assertEqual(owner.popen.returncode, -signal.SIGKILL)
        self.assertTrue(owner.stop_receipt["forced_cleanup"])
        self.ctx.binary, self.ctx.provider_pin = self.exe, self.provider
        with self.assertRaises(H6["LegCleanupError"]):
            Q["run_replacement"](self.ctx, self.directory / "next", "multi", {}, self.exe, StandinIO())
        self.assertFalse((self.directory / "next").exists())

    def test_reader_failure_prevents_success_and_releases_child_and_pins(self):
        owner, _ = self.spawn()
        reader = H6["owned_reader"](self.ctx.readers, H6["Reader"], owner.popen.stderr,
                                    self.directory / "missing-parent/log.txt")
        deadline = time.monotonic() + 1
        while reader.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.005)
        with self.assertRaises(H6["LegCleanupError"]):
            H6["cleanup_leg_resources"](self.ctx)
        self.assertTrue(self.ctx.cleanup_failed)
        self.assertIsNone(owner.pidfd)
        self.assertIsNone(self.provider.fd)

    def test_stale_root_and_foreign_descriptor_refuse_before_admission(self):
        disk = self.directory / "root"
        disk.mkdir()
        group = StandinGroup(disk, Path("/sys/fs/cgroup/standin-root"))
        with self.assertRaises(ValueError):
            Q["group_receipt"](self.ctx, group)
        self.ctx.groups.append(group)
        self.assertEqual(Q["group_receipt"](self.ctx, group)["ino"], disk.stat().st_ino)
        moved = self.directory / "old-root"
        disk.rename(moved)
        disk.mkdir()
        try:
            with self.assertRaises(ValueError):
                Q["group_receipt"](self.ctx, group)
        finally:
            disk.rmdir()
            moved.rename(disk)

    def test_backstop_reuses_the_scope_deadline(self):
        result, _ = self.run_controller()
        self.assertTrue(result["pass"])
        scope = self.ctx.scopes[0]
        owner = H6["spawn_owned"](scope.owners, [sys.executable, "-c", "import time; time.sleep(60)"],
                                  os.geteuid(), start_new_session=True)
        # Simulate a retained child after an exhausted leg; the final backstop
        # must report exhausted cleanup rather than give it a new allowance.
        scope.budget.deadline_ns = time.monotonic_ns() - 1
        try:
            with self.assertRaises(H6["LegCleanupError"]):
                H6["cleanup_leg_resources"](scope)
            self.assertTrue(self.ctx.cleanup_failed)
        finally:
            if owner.popen.poll() is None:
                signal.pidfd_send_signal(owner.pidfd, signal.SIGKILL)
                owner.popen.wait(timeout=1)
            if owner.pidfd is not None:
                owner.close()
            scope.owners.clear()


class CliTests(unittest.TestCase):
    def test_help_exposes_actual_live_inputs(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        for argument in ("--binary", "--provider", "--caller", "--source-revision", "--out", "--backends"):
            self.assertIn(argument, result.stdout)

    def test_unprivileged_cli_refuses_before_creating_output(self):
        if os.geteuid() == 0:
            self.skipTest("this refusal control requires an ordinary test user")
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", "/var/tmp")) as disk:
            out = Path(disk) / "new-output"
            result = subprocess.run([sys.executable, str(SCRIPT), "--binary", sys.executable,
                "--provider", sys.executable, "--caller", sys.executable, "--source-revision", "a" * 40,
                "--uid", str(os.geteuid()), "--gid", str(os.getegid()), "--out", str(out)],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires root", result.stderr)
            self.assertFalse(out.exists())

    def test_argument_validation_refuses_bad_source_backend_paths_and_existing_output(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", "/var/tmp")) as disk:
            directory = Path(disk)
            args = SimpleNamespace(binary=Path(sys.executable).resolve(), provider=Path(sys.executable).resolve(),
                caller=Path(sys.executable).resolve(), source_revision="a" * 40, backends=["singles", "multi"],
                out=directory / "new")
            Q["validate_inputs"](args)
            for field, value in [("source_revision", "main"), ("backends", ["auto"]),
                                 ("backends", ["singles", "singles"]), ("out", directory),
                                 ("binary", Path("relative")), ("provider", directory)]:
                changed = copy.copy(args)
                setattr(changed, field, value)
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    Q["validate_inputs"](changed)
            link = directory / "input-link"
            link.symlink_to(args.provider)
            changed = copy.copy(args)
            changed.provider = link
            with self.assertRaises(ValueError):
                Q["validate_inputs"](changed)
            dangling = directory / "dangling-output"
            dangling.symlink_to(directory / "missing-target")
            changed = copy.copy(args)
            changed.out = dangling
            with self.assertRaises(ValueError):
                Q["validate_inputs"](changed)
            self.assertFalse(args.out.exists())

    def test_disk_validation_refuses_tmpfs_without_creating_output(self):
        if not Path("/dev/shm").is_dir():
            self.skipTest("no tmpfs directory available")
        args = SimpleNamespace(binary=Path(sys.executable).resolve(), provider=Path(sys.executable).resolve(),
            caller=Path(sys.executable).resolve(), source_revision="a" * 40, backends=["singles"],
            out=Path("/dev/shm") / f"p11scope-replacement-uncreated-{os.getpid()}")
        with self.assertRaisesRegex(ValueError, "disk"):
            Q["validate_inputs"](args)
        self.assertFalse(args.out.exists())


if __name__ == "__main__":
    unittest.main()
