#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed recipient journeys must execute the selected candidate binary.

G25/C8: the journey resolves its observer through the explicit selected
path (the extracted candidate bytes), never through PATH. A decoy
`p11scope` placed earlier in PATH must stay unexecuted while the journey
receipt binds the exact executed path and digest. Drives the accepted U6
installed-journey harness (tests/fixtures/u6-installed-drive.py) in
--dry-run shape over staged fixture binaries; no capture, no privilege.

Run: python3 -I tests/python/test_release_recipient.py -v
"""
import argparse
import contextlib
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


class ReleaseRecipientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-recipient-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

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


if __name__ == "__main__":
    unittest.main()
