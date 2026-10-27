#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the combined unsupported-host controller without booting a guest."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-multi-host-refusal.py"

FAKE = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
a=sys.argv[1:]; mode=os.environ.get('FAKE_MULTI_REFUSAL','healthy')
if a in [['--help'],['--version']]:
    if mode=='blocks-offline': print('uprobe-multi-required',file=sys.stderr);sys.exit(1)
    print('p11scope help/version');sys.exit(0)
if a[:2]==['inventory','diff']: print('{}');sys.exit(0)
if a[0]=='inventory' and '--capture' in a and a[a.index('--capture')+1]=='scan':
    pathlib.Path(a[a.index('-o')+1]).write_text(json.dumps({'schema':'p11scope/inventory/v1'}));sys.exit(0)
if mode=='accepts-singles' and 'singles' in a:sys.exit(0)
if mode=='writes-sink' and '-o' in a:pathlib.Path(a[a.index('-o')+1]).write_text('TRUNCATED')
if mode=='runs-child' and a[0]=='run':
    import subprocess
    subprocess.run(a[a.index('--')+1:],check=True)
print('different-refusal' if mode=='wrong-reason' else 'uprobe-multi-required: unavailable at link',file=sys.stderr)
sys.exit(1)
'''


class CombinedRefusalTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "combined unsupported-host driver is missing")
        self.temp = tempfile.TemporaryDirectory(prefix="multi-refusal-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.observer = self.work / "observer"
        self.observer.write_text(FAKE)
        self.observer.chmod(0o700)
        self.check = runpy.run_path(str(SCRIPT))["check_commands"]

    def test_combined_capture_refusals_and_offline_twins(self):
        rows = self.check(self.observer, self.work)
        self.assertGreaterEqual(sum(r["outcome"] == "refused" for r in rows), 12)
        self.assertEqual({r["case"] for r in rows if r["outcome"] == "offline-ok"},
                         {"help", "version", "inventory-scan", "inventory-diff"})
        self.assertFalse((self.work / "workload-ran").exists())

    def test_guest_uses_private_disk_stage_and_caller_trust(self):
        namespace = runpy.run_path(str(SCRIPT))
        guest = namespace["guest"]
        observer = self.work / "p11scope"
        observer.write_text(FAKE)
        observer.chmod(0o700)
        metadata = {"kernel": "v" + os.uname().release,
                    "runner_uid": self.work.stat().st_uid,
                    "sha256": {"p11scope": namespace["digest"](observer)}}
        (self.work / "inputs.json").write_text(json.dumps(metadata))

        def check(observer, work):
            self.assertEqual(work.parent, self.work)
            self.assertEqual(work.stat().st_mode & 0o777, 0o700)
            self.assertEqual(os.environ["TMPDIR"], str(work))
            if metadata["runner_uid"]:
                self.assertEqual(os.environ["SUDO_UID"], str(metadata["runner_uid"]))
            else:
                self.assertNotIn("SUDO_UID", os.environ)
            return self.check(observer, work)

        run = subprocess.run

        def unprivileged_run(argv, **kwargs):
            self.assertNotEqual(argv[0], "mount", "offline test must never mount")
            return run(argv, **kwargs)

        with patch.dict(os.environ), patch("os.geteuid", return_value=0), \
                patch("subprocess.run", side_effect=unprivileged_run), \
                patch.dict(guest.__globals__, {"check_commands": check}):
            guest(self.work)
        self.assertEqual(len(json.loads((self.work / "result.json").read_text())["cases"]), 20)
        self.assertFalse(any(path.is_dir() for path in self.work.iterdir()))

    def test_stage_owner_must_match_and_resolve_to_an_account(self):
        trust = runpy.run_path(str(SCRIPT))["trust_stage_owner"]
        owner = self.work.stat().st_uid
        for invalid in (None, True, -1, 2**32 - 1, owner + 1):
            with self.subTest(uid=invalid), patch.dict(os.environ):
                with self.assertRaisesRegex(RuntimeError, "invalid stage owner"):
                    trust(self.work, invalid)
        with patch("pwd.getpwuid", side_effect=KeyError), patch.dict(os.environ):
            with self.assertRaisesRegex(RuntimeError, "no account"):
                trust(self.work, owner)

    def test_singles_cannot_bypass_the_host_requirement(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "accepts-singles"}):
            with self.assertRaisesRegex(RuntimeError, "refusal"):
                self.check(self.observer, self.work)

    def test_an_unrelated_refusal_is_not_capability_evidence(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "wrong-reason"}):
            with self.assertRaisesRegex(RuntimeError, "uprobe-multi-required"):
                self.check(self.observer, self.work)

    def test_output_mutation_is_rejected(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "writes-sink"}):
            with self.assertRaisesRegex(RuntimeError, "sink"):
                self.check(self.observer, self.work)

    def test_user_workload_must_not_run(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "runs-child"}):
            with self.assertRaisesRegex(RuntimeError, "workload"):
                self.check(self.observer, self.work)

    def test_offline_commands_remain_available(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "blocks-offline"}):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                self.check(self.observer, self.work)


if __name__ == "__main__":
    unittest.main()
