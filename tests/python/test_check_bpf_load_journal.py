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
p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: planned for 0.6.0)
key operations: unavailable (bootstrap_unavailable)
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
    release=kernel[1:]+'-test' if kernel.startswith('v') else kernel+'-test'
    env={**os.environ,'FAKE_RELEASE':release}
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
    out.write_text('#!/bin/sh\necho "SETTLED after 0s"\necho "LEDGER C_Initialize=1 C_Finalize=1"\n')
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
                                (CONTROL_KERNEL, "5.15.221-test")):
            config = self.cache / f"virtme-ng/{kernel}/amd64/boot/config-{release}"
            config.parent.mkdir(parents=True)
            config.write_text("owned test config\n")
        rows = journal_rows()
        (self.work / "rows.json").write_text(json.dumps({
            "linked": rows,
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
            "missing-root": {"rc": 0, "text": LINKED_TEXT},
            "unlinked": {"rc": 0, "text": LINKED_TEXT.replace(
                "key operations: unavailable (bootstrap_unavailable)",
                "key operations: not reported by this version (planned for 0.6.0)")},
            "refused-build": {"rc": 0, "text":
                "gap: key operations unavailable: "
                "journal-pair-unavailable-in-build: this build omits the "
                "production journal object; broad inventory continues\n"},
            "over-budget": {"rc": 0, "text": LINKED_TEXT},
            "timeout": {"rc": 124, "text": ""},
            "crash": {"rc": 1, "text": LINKED_TEXT + "thread 'main' panicked at src/x.rs:1\n"},
            "refusal-515": {"rc": 1, "text":
                "p11scope: uprobe-multi-required: Multi capability unavailable "
                "at scratch program load\n"},
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

    def run_gate(self, *kernels, mode="linked", budgets=None, extra=None):
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
        self.assertIn("linked bootstrap_unavailable", row["detail"])
        self.assertIn("unbudgeted", row["detail"])
        self.assertIn("journal rows", row["detail"])
        # The linked command shape is pinned, not just the verdict.
        argv = self.observer_argv()
        self.assertEqual(argv[:2], ["inventory", "--system"])
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
        self.assertIn("counter-softhsm-workload.c", compiles[0][-2])
        self.assertIn("-ldl", compiles[0])
        self.assertTrue((out / "journal-workload").is_file())

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
        # The lane sealed ordinary: no journal rows and no linked line.
        result, out = self.run_gate(KERNEL, mode="unlinked")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("linked lane not reported (unlinked lane sealed)",
                      row["detail"])
        self.assertIn("journal pair missing", row["detail"])

    def test_refused_build_fails_with_finite_reason(self):
        # A build without the journal object fails the cell with the
        # finite build reason, never passing and never crashing.
        result, out = self.run_gate(KERNEL, mode="refused-build")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("journal-pair-unavailable-in-build", row["detail"])

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

    def test_refusal_control_passes(self):
        # 5.15 is a refusal control: the finite pre-Multi refusal with
        # no journal load passes the cell.
        result, out = self.run_gate(CONTROL_KERNEL, mode="refusal-515")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        (row,) = self.read_rows(out)
        self.assertEqual(row["cell"], f"journal-load-{CONTROL_KERNEL}")
        self.assertTrue(row["pass"])
        self.assertEqual(row["qualification"], "qualified")
        self.assertIn("uprobe-multi-required", row["detail"])

    def test_control_load_fails(self):
        # The control twin: a 5.15 guest that loads the pair instead of
        # refusing fails the cell.
        result, out = self.run_gate(CONTROL_KERNEL, mode="linked")
        self.assertEqual(result.returncode, 1, result.stdout)
        (row,) = self.read_rows(out)
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "failed")
        self.assertIn("uprobe-multi-required", row["detail"])
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
        self.assertIn("uprobe-multi-required", self.text)

    def test_runs_one_bounded_guest_per_kernel(self):
        self.assertIn("vng --run", self.text)
        self.assertIn("--duration 60s", self.text)
        self.assertIn("--key-operations", self.text)

    def test_fails_fast_past_the_command_budget(self):
        self.assertIn("-gt 950", self.text)

    def test_control_covers_515_releases(self):
        self.assertIn("v5.15.*", self.text)

    def test_default_kernel_list(self):
        self.assertIn("v6.6.157 v6.12.111 v6.18.58 v7.0.14", self.text)

    def test_writes_one_results_row_per_kernel(self):
        self.assertIn("results.jsonl", self.text)
        self.assertIn("journal-load-$KERNEL", self.text)

    def test_lists_apt_prerequisites(self):
        for package in ("gcc", "softhsm2", "libsofthsm2", "python3",
                        "virtme-ng"):
            self.assertIn(package, self.text)


if __name__ == "__main__":
    unittest.main()
