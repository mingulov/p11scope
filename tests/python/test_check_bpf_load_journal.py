#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal load gate: the linked inventory loads the journal pair in guests.

Drives scripts/check-bpf-load-journal.sh through owned fake guests (a fake
`vng` that runs the guest command locally) with an owned fake observer,
workload toolchain and token tool. Each test pins one gate verdict: the
linked pass, every non-vacuity twin (missing root, over-budget row,
unlinked lane, refused build, timeout, crash), the 5.15 refusal control
and its load twin, plus the harness-error and prerequisite exits. The
fake observer records its argv, so the linked command shape
(`inventory --system --capture native --key-operations --manifest ...
--duration 60s`) is pinned against drift, not just the verdicts.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-bpf-load-journal.sh"
KERNEL = "v6.6.157"
CONTROL_KERNEL = "v5.15.221"
CONTROL_KERNEL_61 = "v6.1.188"

next_program_id = 200


def load_row(root, *, loaded=True, errno=0, stats_present=True,
             processed=1000, limit=1000000, auxiliary=None, pid=111,
             btf_id=61):
    global next_program_id
    next_program_id += 1
    return {
        "record": "load", "pid": pid, "root": root,
        "btf_resolved": auxiliary is None and root != "unresolved",
        "btf_fd": 4, "btf_id": btf_id, "returned_btf_id": btf_id,
        "root_type_id": 1,
        "returned_fd": 5 if loaded else -1,
        "program_id": next_program_id if loaded else 0,
        "program_type": 2, "returned_program_type": 2 if loaded else 0,
        "program_flags": 0, "expected_attach_type": 0,
        "insn_count": 100, "relocated_fnv1a64": "123456789abcdef0",
        "loaded": loaded, "errno": errno, "stats_present": stats_present,
        "processed": processed, "limit": limit, "auxiliary": auxiliary,
    }


def summary_row(records, *, pid=111, write_failures=0, overflow=False):
    return {"record": "probe-summary", "pid": pid, "records": records,
            "write_failures": write_failures, "overflow": overflow}


def journal_rows():
    """One journal BTF group plus one Inventory group, as the linked run's
    probe file holds them (small owned counts, distinct per object)."""
    return [
        load_row("p11_entry_journal", processed=99123, btf_id=61),
        load_row("p11_return_journal", processed=234567, btf_id=61),
        load_row("p11_image_query", processed=445, btf_id=61),
        load_row("interface_entry", processed=83350, btf_id=61),
        load_row("interface_return", processed=750806, btf_id=61),
        load_row("p11_usage_entry_lp64", processed=873, btf_id=48),
        load_row("interface_entry", processed=84937, btf_id=48),
    ]


LINKED_TEXT = """p11scope: native usage lane active (Inventory capture activated, uprobe-multi links, --attach-backend auto)
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded only with --key-operations)
p11scope: semantic calls: collected 233, joined 203, shed 30, lost 0, bindings 1, refused 0, hook misses 0, eras 0, instances 1
key operations: not available — per-key tracking never started, so no key can be named yet (reason: bootstrap_unavailable)
"""

LINKED_UNLATCHED_TEXT = """p11scope: native usage lane active (Inventory capture activated, uprobe-multi links, --attach-backend auto)
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded only with --key-operations)
p11scope: semantic calls: collected 233, joined 203, shed 30, lost 0, bindings 1, refused 0, hook misses 0, eras 0, instances 1
key operations: not reported (per-key tracking is off)
"""

#: The current stop line with a sealed lane that joined nothing.
ZERO_JOINED_TEXT = """p11scope: native usage lane active (Inventory capture activated, uprobe-multi links, --attach-backend auto)
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded only with --key-operations)
p11scope: semantic calls: collected 30, joined 0, shed 30, lost 0, bindings 1, refused 0, hook misses 0, eras 0, instances 1
key operations: not reported (per-key tracking is off)
"""

IDLE_TEXT = """p11scope: native usage lane active (Inventory capture activated, uprobe-multi links, --attach-backend auto)
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: recorded only with --key-operations)
key operations: not reported (per-key tracking is off)
"""

TOOL_SOURCE = r'''
import json,os,pathlib,subprocess,sys,tempfile
name=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]
with open(os.environ['FAKE_EVENTS'],'a') as log:
    log.write(json.dumps({'tool':name,'args':args})+'\n')
if name=='vng':
    kernel=args[args.index('--run')+1]
    command=args[args.index('--exec')+1]
    out=pathlib.Path(args[args.index('--rwdir')+1])
    if os.environ.get('FAKE_BAD_HELPER')=='missing': (out/'guest-env.sh').unlink()
    if os.environ.get('FAKE_BAD_HELPER')=='bad': (out/'guest-env.sh').write_text('return 0\n')
    release=os.environ.get('FAKE_RELEASE_PIN') or (kernel[1:]+'-test' if kernel.startswith('v') else kernel+'-test')
    env={**os.environ,'FAKE_RELEASE':release}
    if os.environ.get('FAKE_STRIP_STAGED'):
        done=subprocess.run(['/bin/sh','-c',command],env=env,capture_output=True,text=True)
        for line in done.stdout.splitlines():
            if not line.startswith(('staged-boot-config-','boot-config-present-')):
                print(line)
        sys.stdout.write(done.stderr)
        sys.exit(done.returncode)
    sys.exit(subprocess.run(['/bin/sh','-c',command],env=env).returncode)
if name=='mkfs.ext4': sys.exit(0)
if name=='id': print('0');sys.exit(0)
if name=='uname': print(os.environ.get('FAKE_RELEASE','0-test'));sys.exit(0)
if name=='stat': print('0:700');sys.exit(0)
if name=='losetup':
    if '-f' in args: print('/dev/loop23')
    sys.exit(0)
if name=='mount': sys.exit(0)
if name=='umount': sys.exit(0)
if name=='mktemp': print(tempfile.mkdtemp(prefix='p11scope-bpf.',dir='/var/tmp'));sys.exit(0)
if name=='cp':
    if args[-1].startswith('/boot/'): sys.exit(0)
    os.execv('/bin/cp',['cp',*args])
if name=='cc':
    out=pathlib.Path(args[args.index('-o')+1])
    out.write_text('#!'+sys.executable+'\nimport json,os,sys\njson.dump({"tool":"workload","args":sys.argv[1:]},open(os.environ["FAKE_EVENTS"],"a"))\nopen(os.environ["FAKE_EVENTS"],"a").write(chr(10))\nif not os.environ.get("FAKE_WORKLOAD_SILENT"):\n    print("READY cell=jwork pid=1 start=1 gen=0 exe=j-workload")\nprint("LEDGER cell=jwork pid=1 start=1 gen=0 exe=j-workload module=m fn=C_Sign mech=- n=1 bad=0 phase=main t0=1 t1=2")\n')
    out.chmod(0o755)
    sys.exit(0)
if name=='softhsm2-util': sys.exit(1 if os.environ.get('FAKE_TOKEN_FAIL') else 0)
if name=='observer':
    root=pathlib.Path(os.environ['FAKE_WORK'])
    work=pathlib.Path(os.environ.get('TMPDIR','/tmp'))
    if not str(work).startswith('/var/tmp/p11scope-bpf.') or not work.is_dir():
        print('unsafe inherited TMPDIR',file=sys.stderr);sys.exit(8)
    mode=os.environ.get('FAKE_MODE','linked')
    rows=json.loads((root/'rows.json').read_text())[mode]
    for row in rows: os.write(9,(json.dumps(row)+'\n').encode())
    os.write(9,(json.dumps({'record':'probe-summary','pid':111,'records':len(rows),'write_failures':0,'overflow':False})+'\n').encode())
    texts=json.loads((root/'texts.json').read_text())
    sys.stdout.write(texts[mode]['text'])
    sys.exit(texts[mode]['rc'])
raise SystemExit('unknown owned tool '+name)
'''


class JournalGateTests(unittest.TestCase):
    """Run the real script with owned fake guests."""

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(),
                        "scripts/check-bpf-load-journal.sh is missing")
        # The script refuses OUTDIRs under /var/tmp (vng hides them),
        # so the fake tree lives under /tmp, not the session TMPDIR.
        self.temp = tempfile.TemporaryDirectory(
            prefix="journal-gate-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.events = self.work / "events.jsonl"
        self.cache = self.work / "cache"
        for kernel, release in ((KERNEL, "6.6.157-test"),
                                (CONTROL_KERNEL, "5.15.221-test"),
                                (CONTROL_KERNEL_61, "6.1.188-test")):
            config = self.cache / f"virtme-ng/{kernel}/amd64/boot/config-{release}"
            config.parent.mkdir(parents=True)
            config.write_text("owned test config\n")
        rows = journal_rows()
        (self.work / "rows.json").write_text(json.dumps({
            "linked": rows,
            "linked-unlatched": rows,
            "linked-idle": rows,
            "linked-oldline": rows,
            "linked-zero": rows,
            "refused-noseal": [row for row in rows if row["btf_id"] == 48],
            # The plain build exits before loading anything: the probe
            # file holds only its summary.
            "refused-hard": [],
            # The observed 7.3.1 shape: the pair loads, but the
            # link is refused (no seal, no joined calls).
            "refused-loaded": rows,
            "missing-root": [row for row in rows
                             if row["root"] != "p11_return_journal"],
            "unlinked": [row for row in rows if row["btf_id"] == 48],
            "refused-build": [row for row in rows if row["btf_id"] == 48],
            "over-budget": rows,
            "timeout": [],
            "crash": rows,
            "refusal-515": [],
        }))
        (self.work / "texts.json").write_text(json.dumps({
            "linked": {"rc": 0, "text": LINKED_TEXT},
            "linked-unlatched": {"rc": 0, "text": LINKED_UNLATCHED_TEXT},
            "linked-idle": {"rc": 0, "text": IDLE_TEXT},
            # The stop line before it carried a `lost` term: the gate
            # must not accept it as the current observer's line.
            "linked-oldline": {"rc": 0, "text": LINKED_TEXT.replace(
                "shed 30, lost 0, bindings 1", "shed 30, bindings 1")},
            "linked-zero": {"rc": 0, "text": ZERO_JOINED_TEXT},
            "missing-root": {"rc": 0, "text": LINKED_TEXT},
            "unlinked": {"rc": 0, "text": LINKED_TEXT.replace(
                "key operations: not available — per-key tracking never started, so no "
                "key can be named yet (reason: bootstrap_unavailable)",
                "key operations: not reported (per-key tracking is off)")},
            "refused-build": {"rc": 0, "text":
                "p11scope: semantic lane ready; mechanisms and API results "
                "are recorded from now on (key operations: recorded only "
                "with --key-operations)\n"
                "gap [key operations unavailable] "
                "journal-pair-unavailable-in-build: this build omits the "
                "production journal object; broad inventory continues "
                "with S1 mechanisms and API results\n"},
            "refused-noseal": {"rc": 0, "text":
                "gap [key operations unavailable] "
                "journal-pair-unavailable-in-build: this build omits the "
                "production journal object; broad inventory continues "
                "with S1 mechanisms and API results\n"},
            "refused-hard": {"rc": 1, "text":
                "p11scope: inventory --system: "
                "journal-pair-unavailable-in-build: this build omits the "
                "production journal object\n"},
            "refused-loaded": {"rc": 0, "text":
                "p11scope: key operations unavailable: "
                "semantic_attachment_refused; broad inventory continues "
                "with S1 mechanisms and API results\n"
                "gap [key operations unavailable] "
                "semantic_attachment_refused; broad inventory continues "
                "with S1 mechanisms and API results\n"},
            "over-budget": {"rc": 0, "text": LINKED_TEXT},
            "timeout": {"rc": 124, "text": ""},
            "crash": {"rc": 1, "text": LINKED_TEXT + "thread 'main' panicked at src/x.rs:1\n"},
            "refusal-515": {"rc": 1, "text":
                "p11scope: live capture unavailable: loading p11scope's BPF "
                "programs is not supported on this host; run 'p11scope doctor' "
                "for host readiness\n"},
        }))
        tool = self.bin / "tool"
        tool.write_text("#!" + sys.executable + "\n" + TOOL_SOURCE)
        tool.chmod(0o700)
        for name in ("vng", "mkfs.ext4", "id", "uname", "stat", "losetup",
                     "mount", "umount", "mktemp", "cp", "cc",
                     "softhsm2-util", "observer"):
            (self.bin / name).symlink_to(tool)
        self.probe = self.work / "probe.so"
        shutil.copyfile("/lib/x86_64-linux-gnu/libc.so.6", self.probe)
        self.manifest = self.work / "manifest.json"
        self.manifest.write_text('{"schema": "owned-test"}\n')

    def run_gate(self, *kernels, mode="linked", budgets=None, extra=None,
                 object_name=None):
        out = self.work / "out"
        out.mkdir()
        env = {**os.environ,
               "PATH": str(self.bin) + ":" + os.environ["PATH"],
               "FAKE_EVENTS": str(self.events),
               "FAKE_WORK": str(self.work),
               "FAKE_MODE": mode,
               "XDG_CACHE_HOME": str(self.cache)}
        if extra:
            env.update(extra)
        command = [str(SCRIPT)]
        if budgets is not None:
            command += ["--budgets", str(budgets)]
        if object_name is not None:
            command += ["--object", object_name]
        command += [str(self.bin / "observer"), str(self.probe),
                    str(self.manifest), str(out), *kernels]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=300, env=env)
        return result, out

    def read_rows(self, out):
        rows = (out / "results.jsonl").read_text(encoding="ascii").splitlines()
        self.assertTrue(rows, "results.jsonl is empty")
        return [json.loads(line) for line in rows]

    def observer_argv(self):
        events = [json.loads(line)
                  for line in self.events.read_text().splitlines()]
        calls = [event["args"] for event in events
                 if event["tool"] == "observer"]
        self.assertEqual(len(calls), 1,
                         f"expected one observer call, saw {len(calls)}")
        return calls[0]

    def test_linked_run_passes_unbudgeted(self):
        result, out = self.run_gate(KERNEL)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("# OVERALL: PASS", result.stdout)
        (row,) = self.read_rows(out)
        self.assertEqual(row["cell"], f"journal-load-{KERNEL}")
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("linked sealed live", row["detail"])
        self.assertIn("observations=bootstrap_unavailable", row["detail"])
        self.assertIn("unbudgeted", row["detail"])
        self.assertIn("journal rows", row["detail"])
        # The linked command shape is pinned, not just the verdict.
        argv = self.observer_argv()
        self.assertEqual(argv[:3], ["inventory", "-v", "--system"])
        for flag in ("--capture", "native", "--key-operations",
                     "--manifest", "--duration", "60s"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--manifest") + 1],
                         str(out / "journal-manifest.json"))
        # The guest workload is the owned fixture, compiled by the gate.
        events = [json.loads(line)
                  for line in self.events.read_text().splitlines()]
        compiles = [event["args"] for event in events
                    if event["tool"] == "cc"]
        self.assertEqual(len(compiles), 1)
        self.assertIn("inventory-ledger.c", compiles[0][-3])
        self.assertEqual(compiles[0][-2:], ["-ldl", "-lpthread"])
        self.assertTrue((out / "j-workload").is_file())
        # One persistent caller with spread key-operation iterations:
        # short-lived burst callers exit before admission and shed
        # every call as use-before-admission.
        workloads = [event["args"] for event in events
                     if event["tool"] == "workload"]
        self.assertEqual(len(workloads), 1,
                         "the guest runs one persistent workload")
        args = workloads[0]
        self.assertEqual(args[0], "mech")
        for flag in ("--cell", "--module", "--iters", "--sleep-us",
                     "--hold"):
            self.assertIn(flag, args)

    def write_budgets(self, programs):
        path = self.work / "budgets.json"
        path.write_text(json.dumps(
            {"limit": 1000000, "min_headroom_percent": 5,
             "programs": programs}))
        return path

    def owned_budgets(self, returned=300000):
        return self.write_budgets({
            "journal/p11_entry_journal": {KERNEL: 120000},
            "journal/p11_return_journal": {KERNEL: returned},
            "journal/p11_image_query": {KERNEL: 512},
            "journal/interface_entry": {KERNEL: 95853},
            "journal/interface_return": {KERNEL: 863427},
        })

    def test_missing_journal_root_fails(self):
        # Non-vacuity: the return root never loaded, so the cell fails
        # naming the incomplete pair even though the linked line and
        # every other check pass.
        result, out = self.run_gate(KERNEL, mode="missing-root")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("# OVERALL: FAIL", result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal pair incomplete", row["detail"])

    def test_unlinked_lane_fails(self):
        # No journal rows and no routed calls: the cell fails even
        # though a seal line is present.
        result, out = self.run_gate(KERNEL, mode="unlinked")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal pair missing", row["detail"])

    def test_linked_unlatched_lane_passes(self):
        # The production lane seals linked and routes calls, but the
        # key-operations display latch does not complete in real runs:
        # seal plus no-refusal gap plus loaded pair plus joined calls
        # is the linked proof, whatever the display says.
        result, out = self.run_gate(KERNEL, mode="linked-unlatched")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("linked sealed live", row["detail"])

    def test_sealed_but_idle_fails(self):
        # A seal with no joined calls is vacuous: the lane never
        # observed its caller, so the cell fails.
        result, out = self.run_gate(KERNEL, mode="linked-idle")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("idle", row["detail"])

    def test_stop_line_without_lost_term_fails(self):
        # The current stop line names ring loss separately (`lost N`);
        # the older shape without it is not this observer's evidence.
        result, out = self.run_gate(KERNEL, mode="linked-oldline")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("idle", row["detail"])

    def test_sealed_lane_with_zero_joined_calls_fails(self):
        # The current stop line (with its lost and era counts) still
        # proves nothing when no call joined.
        result, out = self.run_gate(KERNEL, mode="linked-zero")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("idle", row["detail"])

    def test_refused_build_fails_with_finite_reason(self):
        # A build without the journal object fails the cell with the
        # finite build reason, never passing and never crashing.
        result, out = self.run_gate(KERNEL, mode="refused-build")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal-pair-unavailable-in-build", row["detail"])

    def test_refused_lane_without_seal_names_the_reason(self):
        # Both lanes refused, so no seal line exists; the row still
        # names the finite refusal reason instead of just the seal.
        result, out = self.run_gate(KERNEL, mode="refused-noseal")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal-pair-unavailable-in-build", row["detail"])

    def test_hard_refused_build_names_the_reason(self):
        # The plain build rejects --key-operations up front with the
        # bare finite reason (no gap subject, no seal, no loads): the
        # row still names it.
        result, out = self.run_gate(KERNEL, mode="refused-hard")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal-pair-unavailable-in-build", row["detail"])

    def test_loaded_pair_with_refusal_gap_fails(self):
        # The observed 7.3.1 shape: the pair loads, but the link
        # is refused. Refusal wins over the loaded pair: the cell
        # fails naming the refusal, not the missing seal.
        result, out = self.run_gate(KERNEL, mode="refused-loaded")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("linked lane refused", row["detail"])
        self.assertIn("semantic_attachment_refused", row["detail"])

    def test_over_budget_row_fails(self):
        # Non-vacuity: a planted over-budget journal row fails the
        # budgeted cell with both numbers.
        budgets = self.owned_budgets(returned=200000)
        result, out = self.run_gate(KERNEL, mode="over-budget",
                                    budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("over budget", row["detail"])
        self.assertIn("journal/p11_return_journal", row["detail"])

    def test_budgeted_run_passes(self):
        budgets = self.owned_budgets()
        result, out = self.run_gate(KERNEL, budgets=budgets)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("budgeted", row["detail"])
        self.assertNotIn("unbudgeted", row["detail"])

    def test_gate1_object_scores_gate1_keys(self):
        # A gate-1 observer's journal object scores against
        # journal-gate1/ keys: budgeted when they exist, over budget
        # named under the gate-1 key, and plain journal/ keys never
        # stand in for them (the cell is then unbudgeted).
        gate1 = {name.replace("journal/", "journal-gate1/", 1): cells
                 for name, cells in json.loads(
                     self.owned_budgets().read_text())["programs"].items()}
        budgets = self.write_budgets(gate1)
        result, out = self.run_gate(KERNEL, budgets=budgets,
                                    object_name="journal-gate1")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("# object: journal-gate1", result.stdout)
        (row,) = self.read_rows(out)
        self.assertTrue(row["pass"])
        self.assertIn("budgeted", row["detail"])
        self.assertNotIn("unbudgeted", row["detail"])
        self.assertIn("journal-gate1/", row["detail"])

    def test_gate1_object_over_budget_fails(self):
        gate1 = {name.replace("journal/", "journal-gate1/", 1): cells
                 for name, cells in json.loads(
                     self.owned_budgets(returned=200000).read_text())["programs"].items()}
        budgets = self.write_budgets(gate1)
        result, out = self.run_gate(KERNEL, mode="over-budget",
                                    budgets=budgets,
                                    object_name="journal-gate1")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertIn("over budget", row["detail"])
        self.assertIn("journal-gate1/p11_return_journal", row["detail"])

    def test_gate1_object_ignores_gate0_keys(self):
        budgets = self.owned_budgets()
        result, out = self.run_gate(KERNEL, budgets=budgets,
                                    object_name="journal-gate1")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertIn("unbudgeted", row["detail"])

    def test_unknown_object_is_a_harness_error(self):
        result, out = self.run_gate(KERNEL, object_name="detailed")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unknown object", result.stderr)

    def test_corrupt_budgets_is_a_harness_error(self):
        # An explicitly-passed corrupt or unreadable budgets file
        # is a harness error (exit 2 naming budgets), never a
        # silent unbudgeted pass: no kernel leg runs.
        cases = {
            "corrupt.json": b'{"programs": "CORRUPT"\n',
            "binary.json": b'\xff\xfe\x00bad\n',
            "unmapped.json": b'{"programs": "CORRUPT"}\n',
        }
        for name, payload in cases.items():
            path = self.work / name
            path.write_bytes(payload)
            result, _ = self.run_gate(KERNEL, budgets=path)
            self.assertEqual(result.returncode, 2, (name, result.stdout))
            self.assertIn("budgets", result.stderr, name)
            self.assertNotIn("## kernel", result.stdout, name)
            shutil.rmtree(self.work / "out")

    def test_refusal_control_passes(self):
        # 5.15 is a refusal control: the finite pre-Multi refusal with
        # no journal load passes the cell.
        result, out = self.run_gate(CONTROL_KERNEL, mode="refusal-515")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertEqual(row["cell"], f"journal-load-{CONTROL_KERNEL}")
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("live-capture", row["detail"])

    def test_refusal_control_passes_on_61(self):
        # 6.1 is pre-Multi too: the same finite refusal passes the
        # control cell there.
        result, out = self.run_gate(CONTROL_KERNEL_61, mode="refusal-515")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertEqual(row["cell"], f"journal-load-{CONTROL_KERNEL_61}")
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("live-capture", row["detail"])

    def test_control_load_fails(self):
        # The control twin: a 5.15 guest that loads the pair instead of
        # refusing fails the cell.
        result, out = self.run_gate(CONTROL_KERNEL, mode="linked")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("live-capture", row["detail"])
        self.assertIn("journal pair loaded", row["detail"])

    def test_observer_timeout_fails(self):
        result, out = self.run_gate(KERNEL, mode="timeout")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertIn("timed out", row["detail"])

    def test_observer_crash_fails(self):
        # Journal rows and the linked line are present, so the crash
        # marker alone fails the cell.
        result, out = self.run_gate(KERNEL, mode="crash")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertIn("crashed", row["detail"])

    def test_missing_guest_helper_is_nonqualifying(self):
        # Infrastructure failures are nonqualifying rows, never product
        # verdicts and never a silent pass.
        result, out = self.run_gate(KERNEL, extra={"FAKE_BAD_HELPER": "missing"})
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "nonqualifying")

    def test_token_failure_is_nonqualifying(self):
        result, out = self.run_gate(KERNEL, extra={"FAKE_TOKEN_FAIL": "1"})
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "nonqualifying")
        self.assertIn("token setup failed", row["detail"])

    def test_workload_never_ready_is_nonqualifying(self):
        # A workload that never prints READY (broken setup, dead
        # token) fails the leg as infrastructure, never as a product
        # verdict.
        result, out = self.run_gate(
            KERNEL, extra={"FAKE_WORKLOAD_SILENT": "1"})
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "nonqualifying")
        self.assertIn("workload never readied", row["detail"])

    RC_KERNEL = "v7.4-rc1"
    RC_RELEASE = "7.4.0-070400rc1-generic"

    def write_guest_config(self, kernel, release):
        config = self.cache / ("virtme-ng/%s/amd64/boot/config-%s"
                               % (kernel, release))
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("owned test config\n")

    def test_release_candidate_guest_release_passes(self):
        # An rc tag boots the dotted triplet: the shared release match
        # accepts it and the linked leg runs like any other kernel.
        self.write_guest_config(self.RC_KERNEL, self.RC_RELEASE)
        result, out = self.run_gate(
            self.RC_KERNEL, extra={"FAKE_RELEASE_PIN": self.RC_RELEASE})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("linked sealed live", row["detail"])

    def test_wrong_release_candidate_is_nonqualifying(self):
        # ...rc2 does not match an rc1 tag: an infrastructure
        # mismatch, never a product verdict.
        self.write_guest_config(self.RC_KERNEL, self.RC_RELEASE)
        wrong = "7.4.0-070400rc2-generic"
        self.write_guest_config(self.RC_KERNEL, wrong)
        result, out = self.run_gate(
            self.RC_KERNEL, extra={"FAKE_RELEASE_PIN": wrong})
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "nonqualifying")
        self.assertIn("guest booted %s, expected %s" % (wrong, self.RC_KERNEL),
                      row["detail"])

    def test_garbled_staging_line_still_passes(self):
        # vng's console capture demonstrably garbles the boot-config
        # staging line while the leg runs fine; the gate keys on the
        # strictly-later guest-work-ready line instead.
        result, out = self.run_gate(KERNEL, extra={"FAKE_STRIP_STAGED": "1"})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")

    def test_long_path_exceeds_command_budget(self):
        # Past 950 raw bytes the guest would silently never run, so the
        # gate fails fast with a nonqualifying row instead.
        out = self.work.joinpath(*(["long" * 45] * 6))
        out.mkdir(parents=True)
        env = {**os.environ,
               "PATH": str(self.bin) + ":" + os.environ["PATH"],
               "FAKE_EVENTS": str(self.events),
               "FAKE_WORK": str(self.work),
               "FAKE_MODE": "linked",
               "XDG_CACHE_HOME": str(self.cache)}
        result = subprocess.run(
            [str(SCRIPT), str(self.bin / "observer"), str(self.probe),
             str(self.manifest), str(out), KERNEL],
            capture_output=True, text=True, timeout=300, env=env)
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "nonqualifying")
        self.assertIn("kernel-cmdline budget", row["detail"])
        self.assertFalse(any(json.loads(line)["tool"] == "vng"
                             for line in self.events.read_text().splitlines()),
                         "no guest runs past the command budget")

    def test_missing_inputs_are_harness_errors(self):
        out = self.work / "out"
        out.mkdir()
        env = {**os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"]}
        hidden_handle = tempfile.NamedTemporaryFile(
            prefix="journal-gate-obs-", dir="/var/tmp", delete=False)
        hidden = Path(hidden_handle.name)
        hidden_handle.close()
        self.addCleanup(lambda: hidden.unlink(missing_ok=True))
        cases = [
            # (argv, needle, cwd): the path-shape guards sit behind the
            # existence checks, so those cases need files that exist.
            (["/nonexistent/observer", str(self.probe),
              str(self.manifest), str(out)], "observer", None),
            ([str(self.bin / "observer"), "/nonexistent/probe",
              str(self.manifest), str(out)], "probe", None),
            ([str(self.bin / "observer"), str(self.probe),
              "/nonexistent/manifest", str(out)], "manifest", None),
            ([str(self.bin / "observer"), str(self.probe),
              str(self.manifest), str(self.work / "absent")],
             "output dir", None),
            ((["bin/observer", str(self.probe),
               str(self.manifest), str(out)], "absolute", self.work)),
            (([str(hidden), str(self.probe),
               str(self.manifest), str(out)], "/var/tmp", None)),
        ]
        for argv, needle, cwd in cases:
            result = subprocess.run(
                [str(SCRIPT), *argv, KERNEL],
                capture_output=True, text=True, timeout=60, env=env,
                cwd=cwd)
            self.assertEqual(result.returncode, 2, (argv, result.stdout))
            self.assertIn(needle, result.stderr)

    def test_non_fresh_output_dir_is_a_harness_error(self):
        out = self.work / "out"
        out.mkdir()
        (out / "results.jsonl").write_text("{}\n")
        env = {**os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"]}
        result = subprocess.run(
            [str(SCRIPT), str(self.bin / "observer"), str(self.probe),
             str(self.manifest), str(out), KERNEL],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("fresh output directory", result.stderr)

    def test_missing_compiler_exits_77(self):
        # Only the fake vng (plus dirname for the script's own path
        # setup) is on PATH: the gate reaches the cc prerequisite
        # check with no compiler and exits 77.
        out = self.work / "out"
        out.mkdir()
        minbin = self.work / "minbin"
        minbin.mkdir()
        (minbin / "vng").symlink_to(self.bin / "tool")
        real_dirname = shutil.which("dirname")
        self.assertIsNotNone(real_dirname)
        (minbin / "dirname").symlink_to(real_dirname)
        env = {**os.environ, "PATH": str(minbin)}
        result = subprocess.run(
            [str(SCRIPT), str(self.bin / "observer"), str(self.probe),
             str(self.manifest), str(out), KERNEL],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(result.returncode, 77, result.stdout)
        self.assertIn("cc not on PATH", result.stderr)

    def test_missing_vng_exits_77(self):
        # vng is a prerequisite like cc: only dirname is on PATH,
        # so the gate reaches the vng check first and exits 77.
        out = self.work / "out"
        out.mkdir()
        minbin = self.work / "minbin"
        minbin.mkdir()
        real_dirname = shutil.which("dirname")
        self.assertIsNotNone(real_dirname)
        (minbin / "dirname").symlink_to(real_dirname)
        env = {**os.environ, "PATH": str(minbin)}
        result = subprocess.run(
            [str(SCRIPT), str(self.bin / "observer"), str(self.probe),
             str(self.manifest), str(out), KERNEL],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(result.returncode, 77, result.stdout)
        self.assertIn("vng not on PATH", result.stderr)


class ScriptContractTests(unittest.TestCase):
    """Pin the gate's wiring (verdicts are proved by the fake guests)."""

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(),
                        "scripts/check-bpf-load-journal.sh is missing")
        self.text = SCRIPT.read_text(encoding="ascii")

    def test_scores_journal_object_by_btf_group(self):
        self.assertIn("--object journal", self.text)

    def test_checks_both_journal_roots_explicitly(self):
        self.assertIn("p11_entry_journal", self.text)
        self.assertIn("p11_return_journal", self.text)

    def test_requires_the_linked_lane_report(self):
        self.assertIn("bootstrap_unavailable", self.text)

    def test_names_the_finite_refusal_reasons(self):
        self.assertIn("journal-pair-unavailable-in-build", self.text)
        self.assertIn("live capture \\(needs CAP_\\|refused:\\|unavailable:\\|did not start:\\)", self.text)

    def test_runs_one_bounded_guest_per_kernel(self):
        self.assertIn("vng --run", self.text)
        self.assertIn("--duration 60s", self.text)
        self.assertIn("--key-operations", self.text)

    def test_fails_fast_past_the_command_budget(self):
        self.assertIn("-gt 950", self.text)

    def test_control_covers_515_releases(self):
        self.assertIn("v5.15.*", self.text)

    def test_control_covers_61_releases(self):
        self.assertIn("v6.1.*", self.text)

    def test_default_kernel_list(self):
        self.assertIn("v6.6.157 v6.12.111 v6.18.58 v7.0.14", self.text)

    def test_writes_one_results_row_per_kernel(self):
        self.assertIn("results.jsonl", self.text)
        self.assertIn("journal-load-$KERNEL", self.text)

    def test_lists_apt_prerequisites(self):
        for package in ("gcc", "softhsm2", "libsofthsm2", "python3",
                        "virtme-ng"):
            self.assertIn(package, self.text)

    def test_reuses_the_shared_guest_release_match(self):
        # The rc-aware match lives in exactly one place: the journal
        # driver sources it and calls it at the guest-release gate.
        self.assertIn('. "$SCRIPT_DIR/bpf-guest-release.sh"', self.text)
        self.assertIn('if release_ok "$KERNEL" "$GUEST_RELEASE"; then',
                      self.text)
        self.assertNotIn("release_ok() {", self.text)


if __name__ == "__main__":
    unittest.main()
