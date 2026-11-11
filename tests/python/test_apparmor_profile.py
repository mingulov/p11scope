# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for deploy/apparmor-p11scope.

The file is the Docker default AppArmor profile (rendered from the
engine template, byte-recovered from dockerd 29.8.1 on 2026-11-11)
plus exactly one p11scope addition: ``ptrace (read, trace)
peer=unconfined``. The 2026-11-11 drill proved maps snapshots need
ptrace read (31/31 docker-default denials that day) and
``/proc/<pid>/mem`` scans plus profile attach need ptrace trace
(denied_mask="trace" under the read-only first revision);
``tracedby``, ``readby`` and ``signal send`` stay denied, so this
suite refuses them.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PROFILE = REPO / "deploy" / "apparmor-p11scope"

# Every deny line of the Docker 29.8.1 default template. The shipped
# file must keep all of them: the p11scope change is purely additive.
BASE_DENIALS = [
    "deny network alg,",
    "deny network vsock,",
    "deny @{PROC}/* w,",
    "deny @{PROC}/{[^1-9/],[^1-9/][^0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,",
    "deny @{PROC}/sys/[^k]** w,",
    "deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,",
    "deny @{PROC}/sysrq-trigger rwklx,",
    "deny @{PROC}/kcore rwklx,",
    "deny mount,",
    "deny /sys/[^f]*/** wklx,",
    "deny /sys/f[^s]*/** wklx,",
    "deny /sys/fs/[^c]*/** wklx,",
    "deny /sys/fs/c[^g]*/** wklx,",
    "deny /sys/fs/cg[^r]*/** wklx,",
    "deny /sys/firmware/** rwklx,",
    "deny /sys/devices/virtual/powercap/** rwklx,",
    "deny /sys/kernel/security/** rwklx,",
]


class ApparmorProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PROFILE.read_text(encoding="utf-8")
        cls.rules = []
        for line in cls.text.splitlines():
            code = line.split("#", 1)[0].strip()
            if code and not code.startswith("#include"):
                cls.rules.append(code)

    def test_profile_header_names_p11scope(self):
        self.assertIn(
            "profile p11scope-observer flags=(attach_disconnected,mediate_deleted) {",
            self.rules,
        )

    def test_base_denials_survive_verbatim(self):
        for denial in BASE_DENIALS:
            with self.subTest(denial=denial):
                self.assertIn(denial, self.rules)

    def test_same_peer_ptrace_and_signal_rules_renamed(self):
        self.assertIn(
            "ptrace (trace,tracedby,read,readby) peer=p11scope-observer,", self.rules
        )
        self.assertIn("signal (send,receive) peer=p11scope-observer,", self.rules)

    def test_ptrace_read_and_trace_addition_to_unconfined(self):
        # Measured 2026-11-11: maps snapshots need ptrace read, and
        # /proc/<pid>/mem scans plus profile attach need ptrace trace
        # (denied_mask="trace" under the read-only revision). Both go
        # to unconfined peers only; tracedby/readby stay denied.
        additions = [
            rule
            for rule in self.rules
            if rule.startswith("ptrace") and "peer=unconfined" in rule
        ]
        self.assertEqual(additions, ["ptrace (read, trace) peer=unconfined,"])
        lines = self.text.splitlines()
        idx = next(
            i for i, line in enumerate(lines)
            if line.strip() == "ptrace (read, trace) peer=unconfined,"
        )
        context = "\n".join(lines[max(0, idx - 7):idx]).lower()
        self.assertIn("p11scope", context)

    def test_no_tracedby_readby_or_signal_send_to_unconfined(self):
        for rule in self.rules:
            if "peer=unconfined" not in rule:
                continue
            with self.subTest(rule=rule):
                perms = rule.split("peer=")[0]
                self.assertNotIn("tracedby", perms)
                self.assertNotIn("readby", perms)
                self.assertFalse(rule.startswith("signal (send"))

    def test_base_allows_present(self):
        # The 29.8.1 default grants these classes; without `file,`
        # the observer cannot even read /sys/kernel/btf/vmlinux
        # (measured EACCES under the first revision of this file).
        for allow in ("network,", "capability,", "file,", "umount,"):
            with self.subTest(allow=allow):
                self.assertIn(allow, self.rules)

    def test_abi_pinned_to_3_0(self):
        # Upstream renders abi <abi/3.0> so `network` keeps unix
        # sockets; a bare profile would take the newest ABI instead.
        self.assertIn("abi <abi/3.0>,", self.rules)

    def test_no_broad_write_or_execute_additions(self):
        # `file,` alone is the base default (pinned by
        # test_base_allows_present); anything broader is refused.
        for rule in self.rules:
            if rule == "file,":
                continue
            with self.subTest(rule=rule):
                self.assertFalse(
                    re.fullmatch(r"(file|/\*\*|\*\*).*,", rule),
                    "no blanket file grants beyond the base `file,`",
                )
                self.assertFalse(rule.startswith("/** "))

    def test_braces_balance(self):
        self.assertEqual(self.text.count("{"), self.text.count("}"))
        self.assertGreater(self.text.count("{"), 0)

    def test_provenance_names_the_engine_template(self):
        head = "\n".join(self.text.splitlines()[:12])
        self.assertIn("29.8.1", head)
        self.assertIn("moby", head.lower())


if __name__ == "__main__":
    unittest.main()
