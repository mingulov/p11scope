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
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
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


if __name__ == "__main__":
    unittest.main()
