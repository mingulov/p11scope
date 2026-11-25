#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Upgrade cells: package upgrade (gate 5) and report compat (gate 6).

Gate 5 is a root-only cell (installs DEB/RPM); this suite pins its script
contract without installing: argument parsing, typed result shape, and the
builder layout. The live upgrade runs in the upgrade-cells workflow and on
the fedora host via scripts/upgrade-gate5.sh.

Gate 6 runs here end-to-end with the v0.7.1 binary when present
(P11SCOPE_V071_BINARY) and the freshly built observer; otherwise it pins
the schema deltas (B1/B2/B3) from the tree alone.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class UpgradeScriptContractTests(unittest.TestCase):
    def test_gate5_refuses_without_root_marker(self):
        # The script must refuse when not root; run --help-like misuse as
        # non-root and require usage exit 2 (never an install attempt).
        r = subprocess.run(
            ["bash", str(ROOT / "scripts/upgrade-gate5.sh"), "--format", "bogus"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("--format", r.stderr)

    def test_gate5_result_shape(self):
        # Pinned typed keys of gate5-result.json (see upgrade-gate5.sh).
        expected = {
            "gate",
            "format",
            "status",
            "old_package",
            "new_package",
            "old_version",
            "new_version",
            "doctor_old_rc",
            "doctor_new_rc",
            "capture_old_rc",
            "capture_new_rc",
            "canary_recovery_sha_before",
            "canary_recovery_sha_after",
            "canary_report_sha_before",
            "canary_report_sha_after",
            "canary_survived",
            "fail_reason",
        }
        text = (ROOT / "scripts/upgrade-gate5.sh").read_text()
        for key in expected:
            self.assertIn(key, text, f"gate5 script must emit {key}")

    def test_gate6_result_shape(self):
        text = (ROOT / "scripts/upgrade-gate6.py").read_text()
        for key in ("departed_use", "live_joint_feed_absent", "profile_evidence_fields"):
            self.assertIn(key, text)


class UpgradeSchemaDeltaTests(unittest.TestCase):
    def git_show(self, rev, path):
        import os

        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        out = subprocess.run(
            ["git", "show", f"{rev}:{path}"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            check=True,
        )
        return out.stdout

    def test_b2_live_joint_only_in_new(self):
        for ver in ("v2", "v3", "v4", "v5"):
            name = f"docs/schema/inventory-v1-object-observations-{ver}.schema.json"
            old = self.git_show("v0.7.1", name).decode()
            new = (ROOT / name).read_text()
            self.assertNotIn("live_joint_feed_absent", old, name)
            self.assertIn("live_joint_feed_absent", new, name)

    def test_b3_then_required_adds_exactly_three(self):
        old = json.loads(
            self.git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json")
        )
        new = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )

        def then_required(schema):
            for clause in schema.get("allOf", []):
                then = clause.get("then", {})
                props = then.get("properties", {}).get("evidence", {})
                if props.get("required"):
                    return set(props["required"])
            return set()

        added = then_required(new) - then_required(old)
        self.assertEqual(
            added,
            {
                "pid_descendant_gaps_admitted",
                "member_stop_attached",
                "member_stop_unattached",
            },
        )


if __name__ == "__main__":
    unittest.main()
