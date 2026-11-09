#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the combined unsupported-host controller without booting a guest."""
import json
import os
from pathlib import Path
import runpy
import shutil
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
    if mode=='blocks-offline': print('live capture unavailable: test blocks offline',file=sys.stderr);sys.exit(1)
    print('p11scope help/version');sys.exit(0)
if a==['doctor'] and mode=='slow-doctor':
    import time;time.sleep(3)
if a[:2]==['inventory','diff']: print('{}');sys.exit(0)
if a[0]=='inventory' and '--capture' in a and a[a.index('--capture')+1]=='scan':
    if mode=='fails-scan':
        print('x'*10000+'scan-stdout-marker')
        print('y'*10000+'scan-stderr-marker',file=sys.stderr);sys.exit(7)
    pathlib.Path(a[a.index('-o')+1]).write_text(json.dumps({'schema':'p11scope/inventory/v1'}));sys.exit(0)
if a[0]=='inventory' and '--capture' in a and a[a.index('--capture')+1]=='auto' and mode!='refuses-auto':
    if mode=='bad-fallback-doc':
        doc={'schema':'p11scope/inventory/v1','observation':{'usage_feed':False,'passes':1},'gaps':[]}
    elif mode=='fallback-counts-claim':
        doc={'schema':'p11scope/inventory/v1','observation':{'usage_feed':True,'passes':1},'gaps':[{'subject':'native usage feed unavailable','reason':'call counts unavailable on this host: test'}]}
    elif mode=='empty-fallback':
        doc={'schema':'p11scope/inventory/v1','observation':{'usage_feed':False,'passes':0},'gaps':[{'subject':'native usage feed unavailable','reason':'call counts unavailable on this host: test refuses at link'}]}
    else:
        doc={'schema':'p11scope/inventory/v1','observation':{'usage_feed':False,'passes':1},'gaps':[{'subject':'native usage feed unavailable','reason':'call counts unavailable on this host: test refuses at link'}]}
    pathlib.Path(a[a.index('-o')+1]).write_text(json.dumps(doc))
    print('p11scope: native usage feed unavailable, continuing with the scan lane',file=sys.stderr);sys.exit(0)
if mode=='native-exits-zero' and a[0]=='inventory' and '--capture' in a and a[a.index('--capture')+1]=='native':
    pathlib.Path(a[a.index('-o')+1]).write_text('{}');sys.exit(0)
if mode=='accepts-singles' and 'singles' in a:sys.exit(0)
if mode=='writes-sink' and '-o' in a:pathlib.Path(a[a.index('-o')+1]).write_text('TRUNCATED')
if mode=='runs-child' and a[0]=='run':
    import subprocess
    subprocess.run(a[a.index('--')+1:],check=True)
print('different-refusal' if mode=='wrong-reason' else 'live capture unavailable: test refuses at link',file=sys.stderr)
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

    def remove_guest_bindir(self, stage):
        remove_guest_bindir(stage)

    def test_combined_capture_refusals_and_offline_twins(self):
        rows = self.check(self.observer, self.work)
        self.assertGreaterEqual(sum(r["outcome"] == "refused" for r in rows), 12)
        self.assertEqual({r["case"] for r in rows if r["outcome"] == "offline-ok"},
                         {"help", "version", "inventory-scan", "inventory-diff"})
        self.assertFalse((self.work / "workload-ran").exists())

    def test_auto_inventory_fallback_partition_is_exact(self):
        rows = self.check(self.observer, self.work)
        self.assertEqual(len(rows), 20)
        self.assertEqual(sum(r["outcome"] == "refused" for r in rows), 13)
        self.assertEqual(sorted(r["case"] for r in rows if r["outcome"] == "fallback"),
                         ["inventory-auto-auto", "inventory-auto-multi",
                          "inventory-auto-singles"])
        self.assertEqual({r["case"] for r in rows if r["outcome"] == "offline-ok"},
                         {"help", "version", "inventory-scan", "inventory-diff"})

    def test_old_auto_refusal_is_rejected(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "refuses-auto"}):
            with self.assertRaisesRegex(RuntimeError, "fallback"):
                self.check(self.observer, self.work)

    def test_native_inventory_must_still_refuse(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "native-exits-zero"}):
            with self.assertRaisesRegex(RuntimeError, "refusal"):
                self.check(self.observer, self.work)

    def test_fallback_document_must_name_the_gap(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "bad-fallback-doc"}):
            with self.assertRaisesRegex(RuntimeError, "fallback"):
                self.check(self.observer, self.work)

    def test_fallback_must_not_claim_counts(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "fallback-counts-claim"}):
            with self.assertRaisesRegex(RuntimeError, "fallback"):
                self.check(self.observer, self.work)

    def test_fallback_must_keep_a_pass(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "empty-fallback"}):
            with self.assertRaisesRegex(RuntimeError, "fallback"):
                self.check(self.observer, self.work)

    def test_fallback_rejects_non_integer_passes(self):
        fallback_document = runpy.run_path(str(SCRIPT))["fallback_document"]
        missing = object()

        def write(passes):
            observation = {"usage_feed": False}
            if passes is not missing:
                observation["passes"] = passes
            sink = self.work / "fallback.json"
            sink.write_text(json.dumps(
                {"schema": "p11scope/inventory/v1",
                 "observation": observation,
                 "gaps": [{"subject": "native usage feed unavailable",
                           "reason": "call counts unavailable on this host: test"}]}))
            return sink

        for passes in (1, 2):
            with self.subTest(passes=passes):
                self.assertIsNotNone(fallback_document(write(passes)))
        for passes in (True, False, 0, -1, 1.0, "1", None, missing):
            with self.subTest(passes=passes):
                self.assertIsNone(fallback_document(write(passes)))

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

        def check(observer, work, progress=None, doctor_timeout=60):
            self.assertEqual(doctor_timeout, 300)
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
        self.remove_guest_bindir(self.work)
        context = json.loads((self.work / "guest-context.json").read_text())
        self.assertTrue(context["bindir"].startswith("/tmp/refusal-bin-"))
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
        self.remove_guest_bindir(self.work)
        progress = self.work / "case-results.json"
        self.assertTrue(progress.is_file(), "failed19th case erased preceding receipts")
        rows = json.loads(progress.read_text())["cases"]
        self.assertEqual(len(rows), 19)
        self.assertEqual(sum(row["outcome"] == "refused" for row in rows), 13)
        self.assertEqual(sum(row["outcome"] == "fallback" for row in rows), 3)
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
            with self.assertRaisesRegex(RuntimeError, "live-capture refusal"):
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

    def test_doctor_timeout_is_honored(self):
        with patch.dict(os.environ, {"FAKE_MULTI_REFUSAL": "slow-doctor"}):
            with self.assertRaisesRegex(RuntimeError, "command timed out"):
                self.check(self.observer, self.work, doctor_timeout=1)
            rows = self.check(self.observer, self.work, doctor_timeout=30)
        self.assertEqual(rows[0]["case"], "doctor")

    def test_guest_gives_doctor_room_for_old_verifiers(self):
        namespace = runpy.run_path(str(SCRIPT))
        seen = {}

        def check(observer, work, progress=None, doctor_timeout=60):
            seen["doctor_timeout"] = doctor_timeout
            return []

        for release, expected in (("5.15.221-0515221-generic", 300),
                                  ("6.1.188-0601188-generic", 300)):
            stage = self.work / ("stage-" + release)
            stage.mkdir()
            metadata = {"kernel": "v" + release, "runner_uid": stage.stat().st_uid,
                        "sha256": {"p11scope": "x"}}
            (stage / "inputs.json").write_text(json.dumps(metadata))
            (stage / "p11scope").write_text("observer")
            with tempfile.TemporaryDirectory(prefix="guest-disk-",
                                             dir=self.work.parent) as temp, \
                    patch("os.geteuid", return_value=0), \
                    patch("os.uname") as uname, \
                    patch.dict(namespace["guest"].__globals__,
                               {"check_commands": check,
                                "digest": lambda path: "x",
                                "stage_guest_binaries": lambda *a: (Path(temp), {"p11scope": Path(temp)}),
                                "guest_disk_work": lambda stage: _disk(Path(temp))}):
                uname.return_value.release = release
                namespace["guest"](stage)
            with self.subTest(release=release):
                self.assertEqual(seen["doctor_timeout"], expected)


def remove_guest_bindir(stage):
    """Remove exactly the /tmp bindir the guest staged (suite hygiene)."""
    context = json.loads((stage / "guest-context.json").read_text())
    bindir = Path(context["bindir"])
    assert bindir.parent == Path("/tmp"), bindir
    assert bindir.name.startswith("refusal-bin-"), bindir
    shutil.rmtree(bindir)


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "combined unsupported-host driver is missing")
        self.temp = tempfile.TemporaryDirectory(prefix="refusal-stage-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.namespace = runpy.run_path(str(SCRIPT))

    def test_binaries_are_copied_verified_and_private(self):
        observer = self.work / "p11scope"
        observer.write_text("observer-bytes")
        libtest = self.work / "lib-tests"
        libtest.write_text("libtest-bytes")
        metadata = {"denial": "denied",
                    "sha256": {"p11scope": self.namespace["digest"](observer),
                               "lib-tests": self.namespace["digest"](libtest)}}
        parent = self.work / "guest-tmp"
        parent.mkdir()
        destdir, staged = self.namespace["stage_guest_binaries"](
            self.work, parent, metadata)
        self.assertEqual(destdir.parent, parent)
        self.assertEqual(destdir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(set(staged), {"p11scope", "lib-tests"})
        for name in ("p11scope", "lib-tests"):
            with self.subTest(name=name):
                self.assertEqual(staged[name].read_bytes(),
                                 (self.work / name).read_bytes())
                self.assertEqual(staged[name].stat().st_mode & 0o777, 0o700)

    def test_libtest_stays_unstaged_without_denial(self):
        observer = self.work / "p11scope"
        observer.write_text("observer-bytes")
        (self.work / "lib-tests").write_text("libtest-bytes")
        metadata = {"sha256": {"p11scope": self.namespace["digest"](observer)}}
        parent = self.work / "guest-tmp"
        parent.mkdir()
        _, staged = self.namespace["stage_guest_binaries"](
            self.work, parent, metadata)
        self.assertEqual(set(staged), {"p11scope"})

    def test_guest_has_room_for_staged_binaries(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--memory", "4G"', text)

    def test_outer_liveness_bound_fits_a_slow_515_run(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"600", "vng"', text)

    def test_tampered_copy_is_refused(self):
        observer = self.work / "p11scope"
        observer.write_text("observer-bytes")
        metadata = {"sha256": {"p11scope": "0" * 64}}
        parent = self.work / "guest-tmp"
        parent.mkdir()
        with self.assertRaisesRegex(RuntimeError, "staged binary mismatch"):
            self.namespace["stage_guest_binaries"](self.work, parent, metadata)


FAKE_LIBTEST = r'''#!/usr/bin/env python3
import os,sys
assert 'inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed' in sys.argv, sys.argv
assert '--exact' in sys.argv and '--ignored' in sys.argv
mode=os.environ.get('FAKE_DENIAL_CELL','denied')
if mode in ('denied','eligible'):
    print('IDENTITY_515_DENIAL outcome=%s reason=kernel_fix_missing bpf_delta=0' % mode,file=sys.stderr)
    print('test result: ok. 1 passed');sys.exit(0)
if mode=='no-marker':
    print('test result: ok. 1 passed');sys.exit(0)
if mode=='zero-passed':
    print('test result: ok. 0 passed');sys.exit(0)
print('boom',file=sys.stderr);sys.exit(1)
'''


@contextmanager
def _disk(path):
    yield path


class DenialCellTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "combined unsupported-host driver is missing")
        self.temp = tempfile.TemporaryDirectory(prefix="denial-cell-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.libtest = self.work / "lib-tests"
        self.libtest.write_text(FAKE_LIBTEST)
        self.libtest.chmod(0o700)
        self.check = runpy.run_path(str(SCRIPT))["check_denial_cell"]

    def test_denied_branch_is_disclosed(self):
        with patch.dict(os.environ, {"FAKE_DENIAL_CELL": "denied"}):
            row = self.check(self.libtest, self.work, "denied")
        self.assertEqual((row["case"], row["outcome"], row["rc"]),
                         ("identity-515-denial", "disclosed", 0))
        self.assertEqual(row["reason"], "IDENTITY_515_DENIAL outcome=denied")

    def test_eligible_branch_is_disclosed(self):
        with patch.dict(os.environ, {"FAKE_DENIAL_CELL": "eligible"}):
            row = self.check(self.libtest, self.work, "eligible")
        self.assertEqual((row["case"], row["outcome"], row["rc"]),
                         ("identity-515-denial", "disclosed", 0))

    def test_wrong_expected_branch_fails(self):
        with patch.dict(os.environ, {"FAKE_DENIAL_CELL": "denied"}):
            with self.assertRaisesRegex(RuntimeError, "IDENTITY_515_DENIAL"):
                self.check(self.libtest, self.work, "eligible")

    def test_missing_marker_fails(self):
        with patch.dict(os.environ, {"FAKE_DENIAL_CELL": "no-marker"}):
            with self.assertRaisesRegex(RuntimeError, "missing"):
                self.check(self.libtest, self.work, "denied")

    def test_zero_passes_and_nonzero_exit_fail(self):
        for mode, pattern in (("zero-passed", "exactly one pass"),
                              ("rc1", "nonzero")):
            with self.subTest(mode=mode), \
                    patch.dict(os.environ, {"FAKE_DENIAL_CELL": mode}):
                with self.assertRaisesRegex(RuntimeError, pattern):
                    self.check(self.libtest, self.work, "denied")

    def test_unknown_branch_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "denied or eligible"):
            self.check(self.libtest, self.work, "bogus")

    def test_guest_runs_the_denial_cell_when_metadata_requests_it(self):
        namespace = runpy.run_path(str(SCRIPT))
        observer = self.work / "p11scope"
        observer.write_text("observer")
        libtest = self.work / "lib-tests"
        libtest.write_text("libtest")
        metadata = {"kernel": "v" + os.uname().release,
                    "runner_uid": self.work.stat().st_uid,
                    "denial": "denied",
                    "sha256": {"p11scope": namespace["digest"](observer),
                               "lib-tests": namespace["digest"](libtest)}}
        (self.work / "inputs.json").write_text(json.dumps(metadata))
        seen = {}

        def fake_denial(path, work, expect, progress=None):
            seen.update(path=path, expect=expect, progress=progress)
            return {"case": "identity-515-denial", "outcome": "disclosed"}

        with tempfile.TemporaryDirectory(prefix="guest-disk-",
                                         dir=self.work.parent) as temp, \
                patch("os.geteuid", return_value=0), \
                patch.dict(namespace["guest"].__globals__,
                           {"check_commands": lambda *a, **k: [],
                            "check_denial_cell": fake_denial,
                            "guest_disk_work": lambda stage: _disk(Path(temp))}):
            namespace["guest"](self.work)
        remove_guest_bindir(self.work)
        self.assertEqual(seen["path"].parent.name[:12], "refusal-bin-")
        self.assertEqual(seen["path"].name, "lib-tests")
        self.assertEqual(seen["expect"], "denied")
        cases = json.loads((self.work / "result.json").read_text())["cases"]
        self.assertEqual([row["case"] for row in cases],
                         ["identity-515-denial"])

    def test_denial_options_are_required_together(self):
        main = runpy.run_path(str(SCRIPT))["main"]
        base = ["check-multi-host-refusal.py", str(self.libtest),
                str(self.work / "stage"), "v5.15.221"]
        with patch.object(sys, "argv", base[:1] + ["--libtest", str(self.libtest)] + base[1:]):
            with self.assertRaisesRegex(SystemExit, "2"):
                main()
        with patch.object(sys, "argv", base[:1] + ["--denial", "denied"] + base[1:]):
            with self.assertRaisesRegex(SystemExit, "2"):
                main()
        with patch.object(sys, "argv", base[:1] + ["--libtest", str(self.libtest),
                                                   "--denial", "bogus"] + base[1:]):
            with self.assertRaisesRegex(SystemExit, "2"):
                main()


if __name__ == "__main__":
    unittest.main()
