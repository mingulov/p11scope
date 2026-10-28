#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed recipient journeys must execute the selected candidate binary.

G25/C8: the journey resolves its observer through the explicit selected
path (the extracted candidate bytes), never through PATH. A decoy
`p11scope` placed earlier in PATH must stay unexecuted while the journey
receipt binds the exact executed path and digest. Drives the accepted U6
installed-journey harness (tests/fixtures/u6-installed-drive.py) in
--dry-run shape over staged fixture binaries and composes real native-result
files at its substituted qualification boundary; no capture, no privilege.

Run: python3 -I tests/python/test_release_recipient.py -v
"""
import argparse
import ast
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "u6_installed_drive", ROOT / "tests/fixtures/u6-installed-drive.py"
)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
PACKAGE_SPEC = importlib.util.spec_from_file_location(
    "package_release", ROOT / "scripts/package-release.py"
)
PACKAGE = importlib.util.module_from_spec(PACKAGE_SPEC)
PACKAGE_SPEC.loader.exec_module(PACKAGE)


def stage_pair(root, tag):
    """Stage a selected/decoy `p11scope` pair under root.

    Both answer the ledger dry-run help probes; each logs every
    invocation to its own hits file, which stays absent until hit.
    Returns {"selected": ..., "decoy": ..., "selected_log": ..., "decoy_log": ...}.
    """
    stage = {}
    flags = " ".join(DRIVER.LEDGER_HELP_FLAGS)
    for role, marker in (("selected", "SELECTED"), ("decoy", "DECOY")):
        bindir = root / f"{tag}-{role}"
        bindir.mkdir(mode=0o755)
        binary = bindir / "p11scope"
        log = root / f"{tag}-{role}.log"
        binary.write_text(
            "#!/bin/sh\n"
            f'echo "HIT $0 $*" >> "{log}"\n'
            'if [ "$1" = "--help" ]; then '
            f'echo "{marker} probe: inventory trace run"; exit 0; fi\n'
            'if [ "$1" = "inventory" ] && [ "$2" = "--help" ]; then '
            f'echo "{marker} inventory: {flags}"; exit 0; fi\n'
            f'echo "{marker} refuses $*" >&2; exit 1\n'
        )
        binary.chmod(0o755)
        stage[role] = binary
        stage[role + "_log"] = log
    return stage


def dry_run_ledger(binary):
    """Run the harness ledger dry-run over an explicit binary; return the plan."""
    args = argparse.Namespace(workload_coordinator=None, c8_base=None, out=None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = DRIVER.dry_run_plan(args, ["ledger"], str(binary))
    assert code == 0, f"dry-run exited {code}"
    return json.loads(out.getvalue())


TRACE_STUB = """#!__PYTHON__
import json
import sys
from pathlib import Path
MARKER = "__MARKER__"
LOG = "__LOG__"
TOP = MARKER + " probe: inventory trace run"
INVENTORY = MARKER + " inventory: __FLAGS__ diff"
TRACE = MARKER + " trace: __TRACE_FLAGS__"
RUNNER = MARKER + " runner: --trace"


def log(argv):
    with open(LOG, "a", encoding="utf-8") as stream:
        stream.write("HIT " + " ".join(argv) + "\\n")


def evidence(document):
    return {"edges": [{"entries": {"count": edge["entries"]["count"]}}
                      for edge in document["edges"]],
            "edge_occurrences": list(range(len(document["edges"]))),
            "modules": [{"stand_in": True}]}


def report(before, after):
    paths = {}
    for document in (before, after):
        for caller in document["callers"]:
            exe = (caller.get("image") or {}).get("exe") or {}
            if exe.get("path"):
                paths[exe["path"]] = {"stand_in": True}
    return {"schema": "p11scope/inventory-diff/v1",
            "comparison": {"counter_relation": "independent_windows",
                           "application_paths": paths},
            "limitations": ["absence_is_not_removal",
                            "counts_are_independent_windows"],
            "summary": {"application_groups_compared": 1},
            "before": {"evidence": evidence(before)},
            "after": {"evidence": evidence(after)}}


def diff(arguments):
    positionals = []
    want_json = False
    destination = None
    rest = list(arguments)
    while rest:
        word = rest.pop(0)
        if word == "--json":
            want_json = True
        elif word == "-o":
            destination = rest.pop(0)
        else:
            positionals.append(word)
    if len(positionals) != 2:
        sys.stderr.write(MARKER + " needs BEFORE AFTER\\n")
        return 1
    before = json.loads(Path(positionals[0]).read_bytes())
    after = json.loads(Path(positionals[1]).read_bytes())
    if want_json:
        payload = (json.dumps(report(before, after), sort_keys=True) + "\\n").encode()
    else:
        payload = ("Not observed after does not prove removal\\n"
                   "independent observation windows\\n"
                   "no count delta\\n"
                   "Recorded application: stand-in\\n"
                   "Module: stand-in\\n").encode()
    if destination is not None:
        Path(destination).write_bytes(payload)
    sys.stdout.buffer.write(payload)
    return 0


def main(argv):
    log(argv)
    rest = argv[1:]
    if rest == ["--help"]:
        print(TOP)
        return 0
    if rest == ["inventory", "--help"]:
        print(INVENTORY)
        return 0
    if rest == ["inventory", "diff", "--help"]:
        print("BEFORE.json AFTER.json offline --json -o independent windows "
              "absence does not prove removal")
        return 0
    if rest == ["trace", "--help"]:
        print(TRACE)
        return 0
    if rest == ["run", "--trace", "--help"]:
        print(RUNNER)
        return 0
    if len(rest) >= 3 and rest[:2] == ["inventory", "diff"]:
        return diff(rest[2:])
    sys.stderr.write(MARKER + " refuses " + " ".join(rest) + "\\n")
    return 1


raise SystemExit(main(sys.argv))
"""


def stage_trace_pair(root, tag):
    """Stage a selected/decoy pair answering the named-trace dry-run probes.

    Beyond the ledger help probes, each stub answers the trace/run help
    probes and computes the offline `inventory diff` the named-trace twin
    matrix needs, re-deriving counts and paths from the given saved inputs
    instead of hardcoding them. Hits are logged like stage_pair.
    """
    stage = {}
    flags = " ".join(DRIVER.LEDGER_HELP_FLAGS)
    trace_flags = " ".join(DRIVER.TRACE_HELP_FLAGS)
    for role, marker in (("selected", "SELECTED"), ("decoy", "DECOY")):
        bindir = root / f"{tag}-{role}"
        bindir.mkdir(mode=0o755)
        binary = bindir / "p11scope"
        log = root / f"{tag}-{role}.log"
        text = TRACE_STUB.replace("__PYTHON__", sys.executable)
        text = text.replace("__MARKER__", marker).replace("__LOG__", str(log))
        text = text.replace("__FLAGS__", flags).replace("__TRACE_FLAGS__", trace_flags)
        binary.write_text(text)
        binary.chmod(0o755)
        stage[role] = binary
        stage[role + "_log"] = log
    return stage


def dry_run_named_trace(binary):
    """Run the harness named-trace dry-run over an explicit binary; return the plan."""
    args = argparse.Namespace(provider=None, caller=None, manifest=[],
                              manifest_helper=None, helper_source_revision=None,
                              uid=None, gid=None, before=None, after=None,
                              pair_prebuilt=None, out=None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = DRIVER.dry_run_plan(args, ["named-trace"], str(binary))
    assert code == 0, f"dry-run exited {code}"
    return json.loads(out.getvalue())


def self_test(journeys, binary):
    """Run the harness self-test; return (code, summary)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = DRIVER.self_test(journeys, binary)
    return code, json.loads(out.getvalue())


def compact_data(layout='compact'):
    """Source-shaped frames: compact uses separate application/module rows."""
    doc = {'callers': [{'id': 'c17', 'pid': 501}, {'id': 'c18', 'pid': 502}],
           'modules': [{'id': 'm11'}, {'id': 'm12'}],
           'edges': [{'caller': 'c17', 'module': 'm11'}, {'caller': 'c18', 'module': 'm12'}]}
    if layout == 'compact':
        lines = ['p11scope inventory pid=501 (minimal)',
                 'totals: 2 callers 2 modules 2 edges', 'coverage: 0 gaps 0 refusals 0 suppressed',
                 'application app-one [c17]', 'module provider-one [m11]', 'observed 3 entries',
                 'application app-two [c18]', 'module provider-two [m12]', 'observed 2 entries',
                 '', '', 'summary 1-2/2 | j/k tab q quit']
    else:
        lines = ['p11scope inventory pid=501 | 2 passes | 2 callers 2 modules 2 edges',
                 'coverage: 0 gaps 0 refusals 0 suppressed',
                 'app-one [c17] -> provider-one [m11]',
                 'app-two [c18] -> provider-two [m12]']
    transcript = ('\x1b[?1049h\x1b[H' + '\n'.join(line + '\x1b[K' for line in lines)
                  + '\x1b[?1049l').encode()
    ledger = ('IDENT cell=U6 pid=501 start=5777 gen=0 exe=/wl/one\n'
              'IDENT cell=U6 pid=502 start=5778 gen=0 exe=/wl/two\n')
    return doc, transcript, ledger


class ReleaseRecipientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-recipient-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def compose_ledger(self, journey, *, c8_exit=0, failure=None, c8_base=True):
        """Run actual live dispatch with owned files and substituted captures."""
        stage = stage_pair(self.root, f"ledger-{len(list(self.root.iterdir()))}")
        out = self.root / f"ledger-output-{len(list(self.root.iterdir()))}"
        ledger, module = self.root / 'calls.ledger', self.root / 'provider.so'
        ledger.write_text('')
        module.write_text('owned provider stand-in')
        gate = self.root / 'ledger.go'
        config = self.root / 'coordinator.json'
        config.write_text(json.dumps(dict(pid=501, modules=[str(module)],
                                         ledger=str(ledger), gate=str(gate))))
        argv = ['u6-installed-drive.py', '--journey', journey,
                '--binary', str(stage['selected']), '--source-revision', 'a' * 40,
                '--workload-coordinator', str(config), '--out', str(out)]
        if c8_base:
            argv += ['--c8-base', str(self.root / 'c8')]
        commands = []
        self.last_ledger_out, self.last_ledger_commands, self.last_ledger_gate = out, commands, gate

        def capture(command, **bounds):
            commands.append((command, bounds))
            if command[0] == str(DRIVER.QUALIFY_INVENTORY):
                self.assertEqual(command[1:], [str(stage['selected']), '--lane', 'native',
                                               '--base', str(self.root / 'c8')])
                self.assertEqual(bounds, dict(timeout=1500, output_limit=16 * 1024 * 1024))
                self.assertFalse(gate.exists())
                return c8_exit, b'actual C8 boundary substituted', b''
            self.assertTrue(gate.exists())
            self.assertEqual(bounds, dict(timeout=120))
            if command[0] == str(stage['selected']):
                self.assertEqual(command[1:5], ['inventory', '--pid', '501', '--module'])
                self.assertEqual(command[command.index('--module') + 1], str(module))
                self.assertEqual(command[command.index('--duration') + 1], '20s')
                self.assertEqual(command[-4:], ['--event-rotate-bytes', '1K', '--event-max-files', '3'])
                if failure == 'rotation-capture':
                    return 23, b'', b'capture failed'
                doc, _files, text = DRIVER.rotation_fixture(
                    out / 'rotation', missing_use=failure == 'rotation-verdict')
                doc['observation'] = dict(lane='native', started_ns=10, ended_ns=20)
                (out / 'rotation/report.json').write_text(json.dumps(doc))
                ledger.write_text(text)
                return 0, b'', b''
            self.assertEqual(command[:4], [sys.executable, '-I', str(DRIVER.INVENTORY_ORACLE),
                                          'record-pty'])
            self.assertEqual(command[5:10], ['12', '48', '60', '20', '--'])
            self.assertEqual(command[10:14], [str(stage['selected']), 'inventory', '--pid', '501'])
            self.assertEqual(command[command.index('--duration') + 1], '25s')
            if failure == 'pty-capture':
                return 23, b'rc=0', b''
            doc, transcript, _ledger = compact_data()
            if failure == 'compact-verdict':
                doc['callers'][0]['pid'] = 599
            (out / 'compact-pty/report.json').write_text(json.dumps(doc))
            Path(command[4]).write_bytes(transcript)
            if failure == 'receipt-sink':
                (out / 'receipt.json').mkdir()
            return 0, b'rc=0', b''

        with patch.object(sys, 'argv', argv), patch.object(DRIVER, 'run', side_effect=capture), \
                patch.dict(os.environ, {DRIVER.INSTALLED_ENV: str(stage['selected'])}), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                code = DRIVER.main()
            except SystemExit as error:
                self.fail(f'live {journey} must dispatch, not exit {error.code}')
        return code, json.loads((out / 'receipt.json').read_text()), commands

    def test_ledger_component_live_dispatch_reports_only_the_four_tail_cells(self):
        code, receipt, commands = self.compose_ledger('ledger-component', c8_base=False)
        self.assertEqual(code, 0)
        self.assertIs(receipt['pass'], True)
        self.assertEqual((receipt['mode'], receipt['journey'], receipt['qualification']),
                         ('live', 'ledger-component', 'component_only'))
        self.assertEqual(receipt['covers'], ['rotation', 'compact-pty'])
        self.assertEqual(receipt['not_evaluated'], ['c8-system-dashboard-stop'])
        self.assertEqual([row['cell'] for row in receipt['cells']], [
            'rotation-capture', 'rotation-conserves-ledger',
            'u6-compact-pty-capture', 'u6-compact-pty-matches-ledger'])
        self.assertEqual(len(commands), 2)
        self.assertEqual(receipt['binary']['source_revision'], 'a' * 40)
        self.assertEqual(receipt['binary']['role'], 'installed_candidate')

    def test_full_ledger_still_runs_real_c8_boundary_before_the_same_tail(self):
        code, receipt, commands = self.compose_ledger('ledger')
        self.assertEqual(code, 0)
        self.assertEqual(receipt['journey'], 'ledger')
        self.assertNotIn('qualification', receipt)
        self.assertEqual(len(commands), 3)
        self.assertEqual(receipt['cells'][0]['cell'], 'c8-system-dashboard-stop')
        self.assertEqual(len(receipt['cells']), 5)
        self.assertTrue(all(row['pass'] is True for row in receipt['cells']))

    def test_full_ledger_c8_failure_and_missing_base_never_release_tail(self):
        for options, reason in (({'c8_exit': 23}, 'exit 23'),
                                ({'c8_base': False}, '--c8-base')):
            with self.subTest(options=options), self.assertRaisesRegex(AssertionError, reason):
                self.compose_ledger('ledger', **options)
            self.assertFalse(self.last_ledger_gate.exists())
            self.assertFalse((self.last_ledger_out / 'rotation').exists())
            self.assertFalse((self.last_ledger_out / 'receipt.json').exists())

    def test_ledger_component_capture_and_real_rotation_refusals_never_write_pass(self):
        for failure in ('rotation-capture', 'rotation-verdict', 'pty-capture', 'compact-verdict'):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                self.compose_ledger('ledger-component', failure=failure, c8_base=False)
            self.assertFalse((self.last_ledger_out / 'receipt.json').exists())
            self.assertTrue(all(command[0] != str(DRIVER.QUALIFY_INVENTORY)
                                for command, _bounds in self.last_ledger_commands))

    def test_ledger_component_refuses_synthetic_modes_before_output_or_execution(self):
        for mode in ('--self-test', '--dry-run'):
            out = self.root / 'synthetic-component'
            errors = io.StringIO()
            with self.subTest(mode=mode), patch.object(sys, 'argv', [
                    'u6-installed-drive.py', '--journey', 'ledger-component', mode,
                    '--out', str(out)]), patch.object(DRIVER, 'run') as run, \
                    contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as error:
                    DRIVER.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn('ledger-component is live-only', errors.getvalue())
                run.assert_not_called()
                self.assertFalse(out.exists())

    def test_ledger_component_receipt_sink_failure_cannot_report_a_pass(self):
        with self.assertRaises(OSError):
            self.compose_ledger('ledger-component', failure='receipt-sink', c8_base=False)
        self.assertFalse((self.last_ledger_out / 'receipt.json').is_file())
        self.assertEqual(len(self.last_ledger_commands), 2)

    def compact_verdict(self, doc, transcript, ledger):
        path = self.root / 'compact.ledger'
        path.write_text(ledger)
        return DRIVER.compact_pty_verdict(doc, transcript, {'ledger': str(path)})

    def test_compact_oracle_joins_real_frame_references_to_document_pids(self):
        for layout in ('compact', 'full'):
            doc, transcript, ledger = compact_data(layout)
            parser = DRIVER.inventory_oracle_module()
            # The shared full parser exposes c17, never the PID 501. Actual
            # 48x12 output instead uses render_minimal's three-line blocks.
            full_frames = parser['parse_frames'](transcript)
            if layout == 'full':
                self.assertEqual(parser['FRAME']['identity'].match(full_frames[0][2]).group(2), 'c17')
            else:
                self.assertEqual(full_frames, [])
            with self.subTest(layout=layout):
                ok, detail = self.compact_verdict(doc, transcript, ledger)
                self.assertTrue(ok, detail)
                self.assertEqual(detail['frame_pids'], [501, 502])
                self.assertEqual(detail['ledger_pids'], [501, 502])

    def test_compact_oracle_refuses_unknown_duplicate_malformed_and_unbound_references(self):
        for layout in ('compact', 'full'):
            original, transcript, ledger = compact_data(layout)
            cases = []
            for field, rows in (('callers', [original['callers'][0]]),
                                ('modules', [original['modules'][0]]),
                                ('edges', [original['edges'][0]])):
                doc = copy.deepcopy(original)
                doc[field] += rows
                cases.append((field + '-duplicate', doc, transcript, ledger))
            for value in (None, True, '501', 0, -1):
                doc = copy.deepcopy(original)
                doc['callers'][0]['pid'] = value
                cases.append(('invalid-pid', doc, transcript, ledger))
            for old, new in ((b'[c17]', b'[c999]'), (b'[m11]', b'[m999]'),
                             (b'[c17]', b'[c17x]'), (b'[m11]', b'[11]'),
                             (b'[m11]', b'[m12]')):
                cases.append(('unbound-frame', original, transcript.replace(old, new), ledger))
            for field, index, key, value in (('callers', 0, 'id', '501'),
                                            ('modules', 0, 'id', '11'),
                                            ('edges', 0, 'caller', 'c999'),
                                            ('edges', 0, 'module', 'm999')):
                doc = copy.deepcopy(original)
                doc[field][index][key] = value
                cases.append(('invalid-document-ref', doc, transcript, ledger))
            row = (b'application extra [bad]\x1b[K\nmodule extra [m11]\x1b[K\n'
                   if layout == 'compact' else b'extra [bad] -> extra [m11]\x1b[K\n')
            cases.append(('malformed-extra', original,
                          transcript.replace(b'\x1b[?1049l', row + b'\x1b[?1049l'), ledger))
            for label, doc, frame, text in cases:
                with self.subTest(layout=layout, mutation=label):
                    ok, detail = self.compact_verdict(doc, frame, text)
                    self.assertFalse(ok, detail)

    def test_compact_oracle_keeps_totals_session_and_ledger_agreement_hard(self):
        for layout in ('compact', 'full'):
            doc, transcript, ledger = compact_data(layout)
            for label, frame, text in (
                    ('totals', transcript.replace(b'2 callers', b'3 callers'), ledger),
                    ('no-alt-exit', transcript.replace(b'\x1b[?1049l', b''), ledger),
                    ('unledgered-pid', transcript, ledger.replace('pid=501', 'pid=599')),
                    ('malformed-ledger-pid', transcript, ledger.replace('pid=501', 'pid=bad')),
                    ('empty-ledger', transcript, '')):
                with self.subTest(layout=layout, mutation=label):
                    ok, detail = self.compact_verdict(doc, frame, text)
                    self.assertFalse(ok, detail)

    def test_compact_blocks_never_pair_across_application_or_frame_boundaries(self):
        doc, transcript, ledger = compact_data()
        app = b'application app-one [c17]\x1b[K'
        mod = b'module provider-one [m11]\x1b[K'
        split = (b'\x1b[Hp11scope inventory pid=501 (minimal)\x1b[K\n'
                 b'totals: 2 callers 2 modules 2 edges\x1b[K\n')
        for label, frame in (
                ('cross-frame', transcript.replace(app + b'\n' + mod, app + b'\n' + split + mod)),
                ('cross-application', transcript.replace(mod, b'application other [c18]\x1b[K\n' + mod)),
                ('module-first', transcript.replace(app + b'\n' + mod, mod + b'\n' + app)),
                ('duplicate-pair', transcript.replace(mod, mod + b'\n' + app + b'\n' + mod))):
            with self.subTest(mutation=label):
                ok, detail = self.compact_verdict(doc, frame, ledger)
                self.assertFalse(ok, detail)

    @staticmethod
    def trace_results():
        names = ("stable", "onecall", "exec", "run", "mapped-only", "unreadable",
                 "duplicate-basename", "slow-reader")
        rows = {name: {"cell": name, "pass": True, "calls": 3, "named": 2, "unknown": 1,
                       "false_names": 0, "errors": []} for name in names}
        rows["onecall"].update(calls=1, named=0, unknown=1)
        rows["exec"]["image_generation_populations"] = {
            "first": {"named": 1}, "second": {"named": 1}}
        return rows

    def compose_named_trace(self, *, selected=None, results=None, missing=(), supported=None,
                            occupied=None):
        """Run the real receipt composer with only its native boundary substituted."""
        stage = stage_pair(self.root, f"live-{len(list(self.root.iterdir()))}")
        args = DRIVER.build_parser().parse_args([
            "--journey", "named-trace", "--source-revision", "a" * 40,
            "--helper-source-revision", "b" * 40, "--uid", "1000", "--gid", "1000"])
        args.cells = selected
        out = Path(tempfile.mkdtemp(prefix="live-receipt-", dir=self.root))
        inputs = {"provider": str(self.root / "provider.so"),
                  "caller": str(self.root / "caller"),
                  "manifests": [str(self.root / "manifest.json")],
                  "helper": str(self.root / "manifest-helper")}
        rows = self.trace_results() if results is None else results
        commands = []
        self.last_trace_out, self.last_qualify_commands = out, commands
        if occupied is not None:
            target = out / ('qualify' if occupied == 'directory' else 'prior-output')
            target.mkdir()
            (target / 'preserve').write_text('original input')
            if occupied == 'symlink':
                (out / 'qualify').symlink_to(target, target_is_directory=True)
        # Execute the actual qualifier's new-only creation expression in a
        # child. A fake writer under a parent-created directory missed the
        # ownership conflict between these two real command boundaries.
        tree = ast.parse(DRIVER.QUALIFY_TRACE.read_text())
        creates = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and ast.unparse(node.func) == 'args.out.mkdir']
        self.assertEqual(len(creates), 1)
        child = ('import json, sys\nfrom pathlib import Path\n'
                 'from types import SimpleNamespace\n'
                 'args = SimpleNamespace(out=Path(sys.argv[1]))\n'
                 + ast.unparse(creates[0]) + '\n'
                 'rows, names, missing = map(json.loads, sys.argv[2:])\n'
                 'for name in names:\n'
                 '    if name in missing: continue\n'
                 '    (args.out / name).mkdir()\n'
                 '    (args.out / name / "result.json").write_text(json.dumps(rows[name]))\n')

        def qualify(argv, **_bounds):
            self.assertEqual(argv[:3], [sys.executable, "-I", str(DRIVER.QUALIFY_TRACE)])
            self.assertEqual(argv[argv.index("--binary") + 1], str(stage["selected"].resolve()))
            self.assertEqual(argv[argv.index("--manifest") + 1], inputs["manifests"][0])
            commands.append(argv)
            result = subprocess.run([
                sys.executable, '-I', '-c', child, argv[argv.index('--out') + 1],
                json.dumps(rows), json.dumps(argv[argv.index('--cells') + 1].split(',')),
                json.dumps(missing)], capture_output=True, timeout=10)
            self.last_qualify_result = result
            return result.returncode, result.stdout, result.stderr

        with patch.object(DRIVER, "trace_inputs", return_value=inputs) as validate, \
                patch.object(DRIVER, "load_module", return_value={
                    "CELLS": tuple(self.trace_results()) if supported is None else supported}), \
                patch.object(DRIVER, "run", side_effect=qualify), \
                patch.object(DRIVER, "live_pair", return_value=(True, {"exit": 0})), \
                contextlib.redirect_stdout(io.StringIO()):
            code = DRIVER.live_named_trace(args, str(stage["selected"]), out)
        validate.assert_called_once_with(args, live=True)
        return code, json.loads((out / "receipt.json").read_text()), commands

    def test_named_trace_live_maps_all_eight_supported_cells(self):
        code, receipt, commands = self.compose_named_trace()
        self.assertEqual(code, 0)
        self.assertTrue(receipt["pass"])
        self.assertEqual(commands[0][commands[0].index("--cells") + 1],
                         "stable,onecall,exec,run,mapped-only,unreadable,duplicate-basename,slow-reader")
        expected = {"named-positive", "unknown-honest", "exec-generations", "run-parity",
                    "mapped-only", "unreadable", "duplicate-basename", "slow-reader"}
        rows = {row["cell"]: row for row in receipt["cells"] if row["cell"] in expected}
        self.assertEqual(set(rows), expected)
        for name, row in rows.items():
            self.assertTrue(row["pass"], name)
            self.assertEqual(row["detail"]["false_names"], 0)
            self.assertEqual(row["detail"]["errors"], [])
        self.assertEqual(receipt["binary"]["source_revision"], "a" * 40)

    def test_named_trace_qualifier_refuses_existing_directory_and_symlink(self):
        for occupied in ('directory', 'symlink'):
            with self.subTest(occupied=occupied):
                with self.assertRaisesRegex(AssertionError, 'installed trace qualification failed'):
                    self.compose_named_trace(occupied=occupied)
                self.assertEqual(len(self.last_qualify_commands), 1)
                self.assertNotEqual(self.last_qualify_result.returncode, 0)
                self.assertIn(b'FileExistsError', self.last_qualify_result.stderr)
                target = self.last_trace_out / 'qualify'
                self.assertEqual((target / 'preserve').read_text(), 'original input')
                self.assertEqual(target.is_symlink(), occupied == 'symlink')
                self.assertFalse((self.last_trace_out / 'receipt.json').exists())

    def test_named_trace_subset_is_an_incomplete_full_gate(self):
        code, receipt, commands = self.compose_named_trace(selected="stable")
        self.assertEqual(code, 1)
        self.assertFalse(receipt["pass"])
        self.assertEqual(commands[0][commands[0].index("--cells") + 1], "stable")
        rows = {row["cell"]: row for row in receipt["cells"]}
        self.assertTrue(rows["named-positive"]["pass"])
        for name in ("unknown-honest", "exec-generations", "run-parity", "mapped-only",
                     "unreadable", "duplicate-basename", "slow-reader"):
            self.assertFalse(rows[name]["pass"], name)
            self.assertIn("not_requested", rows[name]["detail"])

    def test_named_trace_selected_result_refusals_cannot_hide_behind_other_cells(self):
        for key, value in (("cell", "unreadable"), ("pass", False), ("pass", 1), ("false_names", 1),
                           ("false_names", False), ("calls", 0), ("calls", "3"),
                           ("named", 0), ("unknown", 0), ("errors", ["capture loss"])):
            with self.subTest(field=key, value=value):
                results = self.trace_results()
                results["slow-reader"][key] = value
                code, receipt, _ = self.compose_named_trace(results=results)
                self.assertEqual(code, 1)
                rows = {row["cell"]: row for row in receipt["cells"]}
                self.assertFalse(rows["slow-reader"]["pass"])
                self.assertTrue(rows["mapped-only"]["pass"])
                self.assertTrue(rows["unreadable"]["pass"])
                self.assertTrue(rows["duplicate-basename"]["pass"])

    def test_named_trace_missing_or_malformed_native_result_refuses(self):
        with self.assertRaises(FileNotFoundError):
            self.compose_named_trace(missing=("unreadable",))
        results = self.trace_results()
        results["unreadable"] = []
        with self.assertRaisesRegex(AssertionError, "result.*object"):
            self.compose_named_trace(results=results)

    def test_named_trace_invalid_or_unsupported_selection_refuses_before_execution(self):
        for selected in ("", "stable,stable", "stable,"):
            with self.subTest(selected=selected), self.assertRaisesRegex(
                    AssertionError, "nonempty and unique"):
                self.compose_named_trace(selected=selected)
        with self.assertRaisesRegex(AssertionError, "lacks requested trace cells.*unknown-cell"):
            self.compose_named_trace(selected="unknown-cell")
        supported = tuple(name for name in self.trace_results() if name != "unreadable")
        with self.assertRaisesRegex(AssertionError, "lacks requested trace cells.*unreadable"):
            self.compose_named_trace(supported=supported)

    def test_named_trace_dry_run_recognizes_supported_extended_cells(self):
        stage = stage_trace_pair(self.root, "future-cells")
        original = DRIVER.load_module

        def supported(path):
            return {"CELLS": tuple(self.trace_results())} if path == DRIVER.QUALIFY_TRACE else original(path)

        with patch.object(DRIVER, "load_module", side_effect=supported):
            plan = dry_run_named_trace(stage["selected"])
        rows = {row["cell"]: row for row in plan["cells"]}
        for name in ("mapped-only", "unreadable", "duplicate-basename", "slow-reader"):
            self.assertEqual(rows[name]["qualify_cell"], name)
            self.assertEqual(rows[name]["wiring"], "validated")

    def compose_saved_pair(self, *, occupied=None, fail_child=False, explicit=False):
        stage = stage_trace_pair(self.root, f'pair-{len(list(self.root.iterdir()))}')
        out = Path(tempfile.mkdtemp(prefix='pair-receipt-', dir=self.root))
        args = argparse.Namespace(before=None, after=None, pair_prebuilt=self.root / 'prebuilt',
                                  source_revision='a' * 40)
        fixture = ROOT / 'tests/fixtures/inventory-diff/scan-current.json'
        if occupied is not None:
            target = out / ('pair' if occupied == 'directory' else 'prior-output')
            target.mkdir()
            (target / 'preserve').write_text('original input')
            if occupied == 'symlink':
                (out / 'pair').symlink_to(target, target_is_directory=True)
        if explicit:
            args.before, args.after = out / 'before.json', out / 'after.json'
            for path in (args.before, args.after):
                path.write_bytes(fixture.read_bytes())
        tree = ast.parse(DRIVER.CAPTURE_PAIR.read_text())
        creates = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and ast.unparse(node.func) == 'args.out.mkdir']
        self.assertEqual(len(creates), 1)
        child = ('import json, sys\nfrom pathlib import Path\n'
                 'from types import SimpleNamespace\n'
                 'args = SimpleNamespace(out=Path(sys.argv[1]))\n'
                 + ast.unparse(creates[0]) + '\n'
                 'if sys.argv[3] == "fail":\n'
                 '    print("injected capture failure", file=sys.stderr)\n'
                 '    raise SystemExit(23)\n'
                 'for name in ("before", "after"):\n'
                 '    directory = args.out / name\n'
                 '    directory.mkdir()\n'
                 '    (directory / "snapshot.json").write_bytes(Path(sys.argv[2]).read_bytes())\n')
        commands, original_run = [], DRIVER.run

        def run(argv, **bounds):
            commands.append(argv)
            self.assertEqual(argv[:2], [sys.executable, '-I'])
            self.assertEqual(argv[argv.index('--binary') + 1], str(stage['selected']))
            if argv[2] == str(DRIVER.CAPTURE_PAIR):
                self.assertEqual(argv[argv.index('--prebuilt') + 1], str(args.pair_prebuilt))
                self.assertEqual(argv[argv.index('--source-revision') + 1], args.source_revision)
                result = subprocess.run([
                    sys.executable, '-I', '-c', child, argv[argv.index('--out') + 1],
                    str(fixture), 'fail' if fail_child else 'pass'],
                    capture_output=True, timeout=10)
                return result.returncode, result.stdout, result.stderr
            self.assertEqual(argv[2], str(DRIVER.CROSS_DRIVE))
            return original_run(argv, **bounds)

        with patch.object(DRIVER, 'run', side_effect=run):
            result = DRIVER.live_pair(args, stage['selected'], out)
        return result, commands, stage, out

    def test_saved_pair_shortcut_lets_child_create_fresh_output(self):
        (ok, detail), commands, stage, out = self.compose_saved_pair()
        self.assertTrue(ok, detail)
        self.assertEqual(len(commands), 2)
        self.assertEqual(detail['before'], str(out / 'pair/before/snapshot.json'))
        self.assertEqual(detail['after'], str(out / 'pair/after/snapshot.json'))
        self.assertTrue(stage['selected_log'].exists())
        self.assertFalse(stage['decoy_log'].exists())

    def test_saved_pair_shortcut_refuses_existing_directory_and_symlink(self):
        for occupied in ('directory', 'symlink'):
            with self.subTest(occupied=occupied):
                (ok, detail), commands, _stage, out = self.compose_saved_pair(occupied=occupied)
                self.assertFalse(ok)
                self.assertEqual(len(commands), 1)
                self.assertNotEqual(detail['capture_exit'], 0)
                self.assertIn('FileExistsError', detail['stderr'])
                self.assertEqual((out / 'pair/preserve').read_text(), 'original input')
                self.assertEqual((out / 'pair').is_symlink(), occupied == 'symlink')
                self.assertFalse((out / 'pair/before').exists())

    def test_saved_pair_failed_child_never_runs_diff(self):
        (ok, detail), commands, stage, _out = self.compose_saved_pair(fail_child=True)
        self.assertFalse(ok)
        self.assertEqual(detail['capture_exit'], 23)
        self.assertIn('injected capture failure', detail['stderr'])
        self.assertEqual(len(commands), 1)
        self.assertFalse(stage['selected_log'].exists())

    def test_saved_explicit_pair_bypasses_capture_shortcut(self):
        (ok, detail), commands, _stage, out = self.compose_saved_pair(explicit=True)
        self.assertTrue(ok, detail)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][2], str(DRIVER.CROSS_DRIVE))
        self.assertFalse((out / 'pair').exists())

    def check_selected_binding(self, plan, stage):
        """The receipt binds the executed selected path; the decoy stays cold."""
        selected = stage["selected"].resolve()
        info = plan["binary"]
        self.assertEqual(info["path"], str(selected))
        self.assertEqual(info["sha256"], hashlib.sha256(selected.read_bytes()).hexdigest())
        self.assertEqual(info["role"], "shape_stand_in")
        self.assertEqual(plan["mode"], "dry-run")
        self.assertTrue(
            all(cell.get("wiring") == "validated" for cell in plan["cells"]),
            plan["cells"],
        )
        self.assertGreaterEqual(len(plan["twins"]), 3, plan["twins"])
        self.assertTrue(
            stage["selected_log"].exists(),
            "journey never executed the selected binary",
        )
        hits = stage["selected_log"].read_text()
        self.assertIn("--help", hits)
        self.assertIn("inventory --help", hits)
        self.assertFalse(
            stage["decoy_log"].exists(),
            "decoy earlier in PATH was executed",
        )

    def test_release_recipient_uses_selected_binary(self):
        stage = stage_pair(self.root, "journey")
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            # The failure mutation is armed: a PATH lookup would take the decoy.
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            plan = dry_run_ledger(stage["selected"])
            self.check_selected_binding(plan, stage)
            # Negative control: selecting the decoy names the decoy, so the
            # receipt tracks the executed binary instead of echoing a constant.
            swapped = stage_pair(self.root, "swapped")
            swapped_plan = dry_run_ledger(swapped["decoy"])
            self.assertEqual(swapped_plan["binary"]["path"], str(swapped["decoy"].resolve()))
            self.assertEqual(
                swapped_plan["binary"]["sha256"],
                hashlib.sha256(swapped["decoy"].resolve().read_bytes()).hexdigest(),
            )
            self.assertTrue(swapped["decoy_log"].exists())
            self.assertFalse(swapped["selected_log"].exists())
            # No PATH fallback: a bare name never resolves, even with the
            # decoy earlier in PATH.
            empty = self.root / "empty-cwd"
            empty.mkdir()
            with contextlib.chdir(empty):
                with self.assertRaises((AssertionError, OSError)):
                    DRIVER.resolve_binary("p11scope")

    def install_fixture_archive(self, tag):
        """Write a real packager-shaped tarball around a staged selected binary."""
        stage = stage_pair(self.root, tag)
        payload = {
            "p11scope": (stage["selected"].read_bytes(), 0o755),
            "LICENSE": (b"fixture license\n", 0o644),
            "notices/NOTICES.md": (b"fixture notices\n", 0o644),
            "RELEASE.json": (b'{"schema_version": 1}\n', 0o644),
        }
        prefix = "p11scope-fixture-x86_64-linux-musl"
        tarball = self.root / (prefix + ".tar.gz")
        PACKAGE.write_archive(tarball, prefix, payload)
        return stage, tarball, prefix, payload

    def test_recipient_install_uses_extracted_absolute_bytes(self):
        stage, tarball, prefix, payload = self.install_fixture_archive("install")
        with tarfile.open(tarball) as archive:
            self.assertEqual({m.name for m in archive},
                             {f"{prefix}/{name}" for name in payload})
            for name, (_, mode) in payload.items():
                self.assertEqual(archive.getmember(f"{prefix}/{name}").mode, mode)
        installed = self.root / "installed"
        installed.mkdir(mode=0o700)
        extract = subprocess.run(["tar", "--same-permissions", "--no-same-owner",
                                  "-xzf", str(tarball), "-C", str(installed)],
                                 text=True, capture_output=True, timeout=30)
        self.assertEqual(extract.returncode, 0, extract.stderr)
        binary = installed / prefix / "p11scope"
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual((installed / prefix / "RELEASE.json").stat().st_mode & 0o777, 0o644)
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            plan = dry_run_ledger(binary)
            adapted = {"selected": binary, "selected_log": stage["selected_log"],
                       "decoy_log": stage["decoy_log"]}
            self.check_selected_binding(plan, adapted)
            # Negative control: selecting the decoy names the decoy, so the
            # receipt tracks the executed install path instead of a constant.
            swapped = dry_run_ledger(stage["decoy"])
            self.assertEqual(swapped["binary"]["path"], str(stage["decoy"].resolve()))

    def test_recipient_tampered_input_refuses_actionably(self):
        stage = stage_pair(self.root, "tamper")
        candidate = self.root / "candidate"
        candidate.mkdir(mode=0o700)
        binary = candidate / "p11scope"
        binary.write_bytes(stage["selected"].read_bytes())
        binary.chmod(0o755)
        sums = candidate / "SHA256SUMS"
        sums.write_text(f"{hashlib.sha256(binary.read_bytes()).hexdigest()}  p11scope\n")
        pristine = subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=candidate,
                                   text=True, capture_output=True, timeout=30)
        self.assertEqual(pristine.returncode, 0, pristine.stderr)
        self.assertIn("p11scope: OK", pristine.stdout)
        binary.write_bytes(b"tampered recipient bytes\n")
        binary.chmod(0o755)
        changed = subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=candidate,
                                 text=True, capture_output=True, timeout=30)
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("p11scope", changed.stdout)
        self.assertIn("FAILED", changed.stdout)
        # The refusal precedes execution: the changed bytes never ran.
        self.assertFalse(stage["selected_log"].exists())
        _, tarball, _, _ = self.install_fixture_archive("truncated")
        data = tarball.read_bytes()
        tarball.write_bytes(data[: len(data) // 2])
        listing = subprocess.run(["tar", "-tzf", str(tarball)],
                                 text=True, capture_output=True, timeout=30)
        self.assertNotEqual(listing.returncode, 0, listing.stdout)

    def test_recipient_absent_loader_refuses_without_path_fallback(self):
        # Wrong-libc and missing-dependency recipient failures share one
        # exec shape: the loader/interpreter is absent, so the kernel
        # refuses exec with ENOENT naming the absolute path. A script with
        # an absent interpreter exercises that real kernel refusal without
        # a foreign-libc toolchain; the live cross-libc exec pair on real
        # packaged bytes stays a controller recipient cell.
        good = self.root / "good-p11scope"
        good.write_text('#!/bin/sh\necho "fixture observer 0.0.0"\n')
        good.chmod(0o755)
        bad = self.root / "bad-p11scope"
        bad.write_text("#!/nonexistent-p11scope-loader/ld.so\necho unreachable\n")
        bad.chmod(0o755)
        positive = subprocess.run([str(good), "--version"],
                                  text=True, capture_output=True, timeout=30)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        self.assertIn("fixture observer", positive.stdout)
        with self.assertRaises(FileNotFoundError) as refused:
            subprocess.run([str(bad), "--version"], text=True,
                           capture_output=True, timeout=30)
        self.assertEqual(refused.exception.errno, errno.ENOENT)
        self.assertIn(str(bad), str(refused.exception))
        stage = stage_pair(self.root, "loader-fallback")
        with patch.dict(os.environ):
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            with self.assertRaises(FileNotFoundError):
                subprocess.run([str(bad), "--version"], text=True,
                               capture_output=True, timeout=30)
            self.assertFalse(stage["decoy_log"].exists(),
                             "failed exec fell back to a PATH binary")

    def test_named_trace_dry_run_uses_selected_binary(self):
        stage = stage_trace_pair(self.root, "trace")
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            # The failure mutation is armed: a PATH lookup would take the decoy.
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            plan = dry_run_named_trace(stage["selected"])
            selected = stage["selected"].resolve()
            info = plan["binary"]
            self.assertEqual(info["path"], str(selected))
            self.assertEqual(info["sha256"],
                             hashlib.sha256(selected.read_bytes()).hexdigest())
            self.assertEqual(info["role"], "shape_stand_in")
            self.assertEqual(plan["mode"], "dry-run")
            by_cell = {cell["cell"]: cell for cell in plan["cells"]}
            for name in ("named-positive", "unknown-honest", "exec-generations",
                         "run-parity"):
                self.assertEqual(by_cell[name]["wiring"], "validated", name)
                self.assertIn("qualify_cell", by_cell[name])
            for name in ("mapped-only", "unreadable", "duplicate-basename",
                         "slow-reader"):
                native = DRIVER.load_module(DRIVER.QUALIFY_TRACE)["CELLS"]
                if name in native:
                    self.assertEqual(by_cell[name]["wiring"], "validated", name)
                    self.assertEqual(by_cell[name]["qualify_cell"], name)
                else:
                    self.assertEqual(by_cell[name]["wiring"], "twin-verdict-ready", name)
            twins = {twin["twin"] for twin in plan["twins"]}
            for name in ("trace-green-named-positive", "trace-red-false-name",
                         "diff-green-known-change", "diff-red-empty-population"):
                self.assertIn(name, twins)
            self.assertTrue(any("trusted-manifest inputs absent" in blocker
                                for blocker in plan.get("live_blockers", [])),
                            plan.get("live_blockers"))
            hits = stage["selected_log"].read_text()
            self.assertIn("trace --help", hits)
            self.assertIn("inventory diff", hits)
            self.assertFalse(stage["decoy_log"].exists(),
                             "decoy earlier in PATH was executed")
            # Negative control: selecting the decoy names the decoy, so the
            # receipt tracks the executed binary instead of echoing a constant.
            swapped = stage_trace_pair(self.root, "trace-swapped")
            swapped_plan = dry_run_named_trace(swapped["decoy"])
            self.assertEqual(swapped_plan["binary"]["path"],
                             str(swapped["decoy"].resolve()))
            self.assertTrue(swapped["decoy_log"].exists())
            self.assertFalse(swapped["selected_log"].exists())

    def test_u6_binary_selection_refuses_relative_missing_and_nonexecutable(self):
        stage = stage_pair(self.root, "refuse")
        trapdir = self.root / "trap-cwd"
        (trapdir / "sub").mkdir(parents=True)
        for trap in (trapdir / "p11scope", trapdir / "sub" / "p11scope"):
            trap.write_bytes(stage["selected"].read_bytes())
            trap.chmod(0o755)
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            with contextlib.chdir(trapdir):
                # A relative name is refused even though the working
                # directory holds an executable trap and PATH a decoy.
                with self.assertRaisesRegex(AssertionError, "not absolute"):
                    DRIVER.resolve_binary("p11scope")
                with self.assertRaisesRegex(AssertionError, "not absolute"):
                    DRIVER.resolve_binary("sub/p11scope")
                with self.assertRaisesRegex(AssertionError, "not absolute"):
                    dry_run_ledger("p11scope")
            self.assertFalse(stage["selected_log"].exists(),
                             "relative selection executed the CWD trap")
            self.assertFalse(stage["decoy_log"].exists(),
                             "relative selection fell back to the PATH decoy")
            with self.assertRaises(FileNotFoundError):
                DRIVER.resolve_binary(str(self.root / "no-such-binary"))
            plain = self.root / "plain-file"
            plain.write_bytes(b"not executable\n")
            plain.chmod(0o644)
            with self.assertRaisesRegex(AssertionError, "not executable"):
                DRIVER.resolve_binary(str(plain))

    def test_named_trace_self_test_uses_resolved_binary(self):
        stage = stage_trace_pair(self.root, "selftest")
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{stage['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            self.assertEqual(shutil.which("p11scope"), str(stage["decoy"]))
            code, summary = self_test(["named-trace"], str(stage["selected"]))
            self.assertEqual(code, 0)
            self.assertEqual(summary["mode"], "self-test")
            twins = {twin["twin"] for twin in summary["twins"]}
            for name in ("trace-green-named-positive", "trace-red-false-name",
                         "diff-green-known-change", "diff-red-empty-population"):
                self.assertIn(name, twins)
            self.assertIn("inventory diff", stage["selected_log"].read_text())
            self.assertFalse(stage["decoy_log"].exists(),
                             "decoy earlier in PATH was executed")
            # Ledger-only self-test still needs no binary.
            code, summary = self_test(["ledger"], None)
            self.assertEqual(code, 0)
            self.assertEqual(summary["journeys"], ["ledger"])
        refusal = stage_trace_pair(self.root, "selftest-refuse")
        trapdir = self.root / "selftest-trap-cwd"
        (trapdir / "sub").mkdir(parents=True)
        for trap in (trapdir / "p11scope", trapdir / "sub" / "p11scope"):
            trap.write_bytes(refusal["selected"].read_bytes())
            trap.chmod(0o755)
        with patch.dict(os.environ):
            os.environ.pop("P11SCOPE_U6_RED_PROOF", None)
            os.environ.pop("P11SCOPE_U6_INSTALLED_BINARY", None)
            os.environ["PATH"] = (
                f"{refusal['decoy'].parent}{os.pathsep}{os.environ['PATH']}"
            )
            self.assertEqual(shutil.which("p11scope"), str(refusal["decoy"]))
            with contextlib.chdir(trapdir):
                # A bare name would resolve through PATH to the decoy and a
                # slashed name through the working directory to the trap.
                with self.assertRaisesRegex(AssertionError, "not absolute"):
                    self_test(["named-trace"], "p11scope")
                with self.assertRaisesRegex(AssertionError, "not absolute"):
                    self_test(["named-trace"], "sub/p11scope")
            self.assertFalse(refusal["selected_log"].exists(),
                             "relative selection executed the CWD trap")
            self.assertFalse(refusal["decoy_log"].exists(),
                             "relative selection executed the PATH decoy")


if __name__ == "__main__":
    unittest.main()
