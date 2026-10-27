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
from contextlib import contextmanager
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
    if mode=='fails-scan':
        print('x'*10000+'scan-stdout-marker')
        print('y'*10000+'scan-stderr-marker',file=sys.stderr);sys.exit(7)
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

    @contextmanager
    def simulated_guest_disk(self, stage):
        self.assertEqual(stage, self.work)
        with tempfile.TemporaryDirectory(prefix="guest-disk-", dir=self.work.parent) as temp:
            yield Path(temp)

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

        def check(observer, work, progress=None):
            self.assertNotEqual(work.parent, self.work, "product work must leave the 9p stage")
            self.assertEqual(work.stat().st_mode & 0o777, 0o700)
            self.assertEqual(os.environ["TMPDIR"], str(work))
            if metadata["runner_uid"]:
                self.assertEqual(os.environ["SUDO_UID"], str(metadata["runner_uid"]))
            else:
                self.assertNotIn("SUDO_UID", os.environ)
            return self.check(observer, work, progress=progress)

        run = subprocess.run

        def unprivileged_run(argv, **kwargs):
            self.assertNotEqual(argv[0], "mount", "offline test must never mount")
            return run(argv, **kwargs)

        with patch.dict(os.environ), patch("os.geteuid", return_value=0), \
                patch("subprocess.run", side_effect=unprivileged_run), \
                patch.dict(guest.__globals__, {"check_commands": check,
                                              "guest_disk_work": self.simulated_guest_disk}):
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

    def test_guest_disk_is_fresh_bounded_and_private(self):
        namespace = runpy.run_path(str(SCRIPT))
        with patch("subprocess.run") as run:
            namespace["prepare_guest_disk"](self.work)
            image = self.work / "work.img"
            self.assertEqual(image.stat().st_size, 128 * 1024 * 1024)
            self.assertEqual(image.stat().st_mode & 0o777, 0o600)
            run.assert_called_once_with(["mkfs.ext4", "-q", "-F", str(image)], check=True)
            with self.assertRaises(FileExistsError):
                namespace["prepare_guest_disk"](self.work)

    def test_guest_disk_cleanup_runs_after_case_failure(self):
        workspace = runpy.run_path(str(SCRIPT))["guest_disk_work"]
        existing_mount = self.work / "guest-mount"
        existing_mount.mkdir(mode=0o700)
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, "/dev/loop23\n", "")

        with patch("subprocess.run", side_effect=run), \
                patch.dict(workspace.__wrapped__.__globals__, {"GUEST_WORK_MOUNT": existing_mount}):
            with self.assertRaisesRegex(RuntimeError, "owned case failure"):
                with workspace(self.work) as work:
                    mount = work.parent
                    self.assertEqual(mount, existing_mount, "use a pre-existing guest mountpoint")
                    self.assertEqual(work.stat().st_uid, os.geteuid())
                    self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                    raise RuntimeError("owned case failure")
        self.assertEqual([argv[0] for argv in commands], ["losetup", "mount", "umount", "losetup"])
        self.assertEqual(commands[1][1:6], ["-t", "ext4", "-o", "nodev,nosuid", "/dev/loop23"])
        self.assertEqual(commands[-1], ["losetup", "-d", "/dev/loop23"])
        self.assertTrue(mount.is_dir())
        self.assertEqual(list(mount.iterdir()), [], "preserve the empty original mountpoint")

    def test_failed_disk_mount_detaches_only_the_owned_loop(self):
        workspace = runpy.run_path(str(SCRIPT))["guest_disk_work"]
        existing_mount = self.work / "guest-mount"
        existing_mount.mkdir(mode=0o700)
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            if argv[0] == "mount":
                raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0, "/dev/loop23\n", "")

        with patch("subprocess.run", side_effect=run), \
                patch.dict(workspace.__wrapped__.__globals__, {"GUEST_WORK_MOUNT": existing_mount}):
            with self.assertRaises(subprocess.CalledProcessError):
                with workspace(self.work):
                    self.fail("failed mount cannot run a control")
        self.assertEqual([argv[0] for argv in commands], ["losetup", "mount", "losetup"])
        self.assertEqual(commands[-1], ["losetup", "-d", "/dev/loop23"])
        self.assertEqual(Path(commands[1][-1]), existing_mount)
        self.assertTrue(existing_mount.is_dir())

    def test_guest_disk_refuses_an_unexpected_work_owner(self):
        workspace = runpy.run_path(str(SCRIPT))["guest_disk_work"]
        existing_mount = self.work / "guest-mount"
        existing_mount.mkdir(mode=0o700)
        owner = os.geteuid()
        with patch("subprocess.run", return_value=subprocess.CompletedProcess(
                [], 0, "/dev/loop23\n", "")) as run, \
                patch("os.geteuid", return_value=owner + 1), \
                patch.dict(workspace.__wrapped__.__globals__, {"GUEST_WORK_MOUNT": existing_mount}):
            with self.assertRaisesRegex(RuntimeError, "owned by the effective UID"):
                with workspace(self.work):
                    self.fail("a different owner cannot run a control")
        self.assertEqual([call.args[0][0] for call in run.call_args_list],
                         ["losetup", "mount", "umount", "losetup"])

    def test_guest_scan_failure_keeps_completed_rows_and_bounded_output(self):
        namespace = runpy.run_path(str(SCRIPT))
        observer = self.work / "p11scope"
        observer.write_text(FAKE)
        observer.chmod(0o700)
        metadata = {"kernel": "v" + os.uname().release,
                    "runner_uid": self.work.stat().st_uid,
                    "sha256": {"p11scope": namespace["digest"](observer)}}
        (self.work / "inputs.json").write_text(json.dumps(metadata))
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "fails-scan"}), \
                patch("os.geteuid", return_value=0), \
                patch.dict(namespace["guest"].__globals__,
                           {"guest_disk_work": self.simulated_guest_disk}):
            with self.assertRaisesRegex(RuntimeError, "inventory-scan"):
                namespace["guest"](self.work)
        progress = self.work / "case-results.json"
        self.assertTrue(progress.is_file(), "failed19th case erased preceding receipts")
        rows = json.loads(progress.read_text())["cases"]
        self.assertEqual(len(rows), 19)
        self.assertEqual(sum(row["outcome"] == "refused" for row in rows), 16)
        self.assertEqual(sum(row["outcome"] == "offline-ok" for row in rows), 2)
        failed = rows[-1]
        self.assertEqual((failed["case"], failed["outcome"], failed["rc"]),
                         ("inventory-scan", "failed", 7))
        self.assertEqual(set(failed["failed_predicates"]), {"offline_exit", "report_exists"})
        self.assertTrue(failed["stdout"].endswith("scan-stdout-marker\n"))
        self.assertTrue(failed["stderr"].endswith("scan-stderr-marker\n"))
        self.assertLessEqual(len(failed["stdout"]), 4096)
        self.assertLessEqual(len(failed["stderr"]), 4096)
        self.assertTrue(failed["stdout_truncated"] and failed["stderr_truncated"])
        self.assertFalse(any(path.is_dir() for path in self.work.iterdir()))

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
