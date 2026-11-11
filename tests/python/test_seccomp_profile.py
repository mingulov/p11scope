# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for deploy/seccomp-p11scope.json.

The file is the Docker default seccomp profile (vendored from moby/moby
v28.3.3, the last release carrying profiles/seccomp/default.json) plus
exactly one appended allow rule for the bpf() syscall. perf_event_open()
stays at the default (conditional on CAP_PERFMON/CAP_SYS_ADMIN): the
2026-11-11 five-capacity drill proved it unneeded on the default
uprobe-multi lane, so this suite refuses an unconditional perf allow.
"""
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PROFILE = REPO / "deploy" / "seccomp-p11scope.json"


class SeccompProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(PROFILE.read_text(encoding="utf-8"))

    def test_default_deny_shape(self):
        self.assertEqual(self.document["defaultAction"], "SCMP_ACT_ERRNO")

    def test_rule_count_is_vendored_default_plus_one(self):
        # moby v28.3.3 default.json carries 31 syscall groups; the p11scope
        # file appends exactly one bpf group.
        groups = self.document["syscalls"]
        self.assertEqual(len(groups), 32)

    def test_last_rule_is_the_unconditional_bpf_allow(self):
        last = self.document["syscalls"][-1]
        self.assertEqual(last["names"], ["bpf"])
        self.assertEqual(last["action"], "SCMP_ACT_ALLOW")
        self.assertNotIn("includes", last)
        self.assertNotIn("excludes", last)
        self.assertIn("p11scope", last.get("comment", ""))

    def test_vendored_bpf_and_perf_conditionals_survive(self):
        groups = self.document["syscalls"][:-1]
        bpf = [g for g in groups if g.get("names") == ["bpf"]]
        perf = [g for g in groups if g.get("names") == ["perf_event_open"]]
        self.assertEqual(len(bpf), 1)
        self.assertEqual(bpf[0]["includes"], {"caps": ["CAP_BPF"]})
        self.assertEqual(len(perf), 1)
        self.assertEqual(perf[0]["includes"], {"caps": ["CAP_PERFMON"]})

    def test_perf_event_open_has_no_unconditional_allow(self):
        for group in self.document["syscalls"]:
            if "perf_event_open" in group.get("names", []):
                with self.subTest(group=group):
                    self.assertTrue(group.get("includes") or group.get("excludes"),
                                    "perf_event_open must stay conditional (default)")

    def test_bpf_is_the_only_unconditional_addition(self):
        unconditional_bpf = [
            g for g in self.document["syscalls"]
            if g.get("names") == ["bpf"] and g.get("action") == "SCMP_ACT_ALLOW"
            and not g.get("includes") and not g.get("excludes")
        ]
        self.assertEqual(len(unconditional_bpf), 1)


if __name__ == "__main__":
    unittest.main()
