#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The end-of-integration copyright pass is applied to this checkout.

`scripts/add-copyright-headers.py` inserts one
`SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>` line
beside each first-party SPDX header, in the header's own comment style.
These tests pin the per-style insertion, the skip rules (vendored,
upstream, generated, already-noticed, byte-exact policy files) and the
applied-tree report; the script itself never writes to this checkout
outside a scratch copy.
"""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "add-copyright-headers.py"
SPEC = importlib.util.spec_from_file_location("add_copyright_headers", SCRIPT)
ADD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADD)

NOTICE = "SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>"


def changed(path, before):
    action, after, _ = ADD.plan_for(path, before)
    assert action == "change", (path, action)
    return after


class AddCopyrightHeadersTests(unittest.TestCase):
    def test_rust_inner_doc_style(self):
        before = b"//! SPDX-License-Identifier: GPL-3.0-or-later\nfn main() {}\n"
        self.assertEqual(
            changed("src/example.rs", before),
            b"//! SPDX-License-Identifier: GPL-3.0-or-later\n"
            b"//! " + NOTICE.encode() + b"\nfn main() {}\n",
        )

    def test_comment_styles_mirror_their_header(self):
        n = NOTICE.encode()
        cases = [
            ("src/include.rs",
             b"// SPDX-License-Identifier: GPL-3.0-or-later\nint x;\n",
             b"// SPDX-License-Identifier: GPL-3.0-or-later\n// " + n + b"\nint x;\n"),
            ("tool.py",
             b"# SPDX-License-Identifier: GPL-3.0-or-later\nprint(1)\n",
             b"# SPDX-License-Identifier: GPL-3.0-or-later\n# " + n + b"\nprint(1)\n"),
            ("run.sh",
             b"#!/bin/sh\n# SPDX-License-Identifier: GPL-3.0-or-later\necho hi\n",
             b"#!/bin/sh\n# SPDX-License-Identifier: GPL-3.0-or-later\n# " + n + b"\necho hi\n"),
            ("native.c",
             b"/* SPDX-License-Identifier: GPL-2.0-only */\nint x;\n",
             b"/* SPDX-License-Identifier: GPL-2.0-only */\n/* " + n + b" */\nint x;\n"),
            ("native.h",
             b"/* SPDX-License-Identifier: GPL-3.0-or-later */\nint x;\n",
             b"/* SPDX-License-Identifier: GPL-3.0-or-later */\n/* " + n + b" */\nint x;\n"),
            ("doc.md",
             b"<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\n# Title\n",
             b"<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\n<!-- " + n + b" -->\n# Title\n"),
        ]
        for path, before, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(changed(path, before), expected)

    def test_crlf_bom_and_bare_header_keep_file_shape(self):
        crlf = b"<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\r\n# T\r\n"
        self.assertEqual(
            changed("doc.md", crlf),
            b"<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\r\n"
            b"<!-- " + NOTICE.encode() + b" -->\r\n# T\r\n",
        )
        bom = b"\xef\xbb\xbf# SPDX-License-Identifier: GPL-3.0-or-later\nx = 1\n"
        self.assertEqual(
            changed("tool.py", bom),
            b"\xef\xbb\xbf# SPDX-License-Identifier: GPL-3.0-or-later\n"
            b"# " + NOTICE.encode() + b"\nx = 1\n",
        )

    def test_second_application_is_a_noop(self):
        once = changed("src/example.rs", b"//! SPDX-License-Identifier: GPL-3.0-or-later\nfn f() {}\n")
        action, after, _ = ADD.plan_for("src/example.rs", once)
        self.assertEqual(action, "already")
        self.assertIsNone(after)

    def test_notice_string_in_code_does_not_mark_done(self):
        before = (b"# SPDX-License-Identifier: GPL-3.0-or-later\n"
                  b"NOTICE = \"" + NOTICE.encode() + b"\"\n")
        self.assertEqual(
            changed("tool.py", before),
            b"# SPDX-License-Identifier: GPL-3.0-or-later\n"
            b"# " + NOTICE.encode() + b"\n"
            b"NOTICE = \"" + NOTICE.encode() + b"\"\n",
        )
        quoted = (b"// SPDX-License-Identifier: GPL-3.0-or-later\n"
                  b"const char *n = \"SPDX-FileCopyrightText: 2020 Someone Else\";\n")
        self.assertEqual(
            changed("src/quoted.c", quoted),
            b"// SPDX-License-Identifier: GPL-3.0-or-later\n"
            b"// " + NOTICE.encode() + b"\n"
            b"const char *n = \"SPDX-FileCopyrightText: 2020 Someone Else\";\n",
        )

    def test_foreign_notice_is_kept_not_duplicated(self):
        before = (b"/* SPDX-License-Identifier: Apache-2.0 */\n"
                  b"/* SPDX-FileCopyrightText: 2020 Someone Else */\nint x;\n")
        action, after, reason = ADD.plan_for("third-party/x.c", before)
        self.assertEqual(action, "skip")
        self.assertIsNone(after)
        action, after, reason = ADD.plan_for("src/x.c", before)
        self.assertEqual(action, "skip")
        self.assertIsNone(after)
        self.assertIn("existing", reason)

    def test_skips_vendored_upstream_and_generated_paths(self):
        header = b"# SPDX-License-Identifier: GPL-3.0-or-later\nx = 1\n"
        for path in ("third-party/src/aya/lib.rs",
                     "tests/fixtures/lane13-evidence/releases/custom.yaml",
                     "tests/fixtures/vng-kernel-sha256sums/v9.sums",
                     "Cargo.lock",
                     "crates/ebpf/Cargo.lock"):
            with self.subTest(path=path):
                action, after, _ = ADD.plan_for(path, header)
                self.assertEqual(action, "skip")
                self.assertIsNone(after)

    def test_byte_exact_policy_file_is_skipped(self):
        header = b"<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\n# Title\n"
        action, after, reason = ADD.plan_for("docs/privacy/allowlist-v1.md", header)
        self.assertEqual(action, "skip")
        self.assertIsNone(after)
        self.assertIn("byte-exact", reason)

    def test_binary_and_headerless_files_are_not_touched(self):
        action, after, _ = ADD.plan_for("blob.o", b"\x7fELF\x00binary")
        self.assertEqual(action, "skip")
        self.assertIsNone(after)
        action, after, _ = ADD.plan_for("plain.txt", b"no header here\n")
        self.assertEqual(action, "skip")
        self.assertIsNone(after)

    def test_mid_file_spdx_is_reported_not_edited(self):
        before = b"fn f() {\n    let s = \"SPDX-License-Identifier: GPL-3.0-or-later\";\n}\n"
        action, after, reason = ADD.plan_for("src/quoted.rs", before)
        self.assertEqual(action, "unhandled")
        self.assertIsNone(after)
        self.assertIn("header", reason)

    def test_apply_in_a_temp_repo_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="copyright-pass-") as name:
            repo = Path(name)
            (repo / "a.rs").write_bytes(b"//! SPDX-License-Identifier: GPL-3.0-or-later\nfn f() {}\n")
            (repo / "b.py").write_bytes(b"# SPDX-License-Identifier: GPL-3.0-or-later\nprint(1)\n")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            apply = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--apply", "--root", str(repo)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(apply.returncode, 0, apply.stderr)
            self.assertIn("summary: change=2 already=0 skipped=0 unhandled=0", apply.stdout)
            self.assertIn(NOTICE, (repo / "a.rs").read_text())
            self.assertIn(NOTICE, (repo / "b.py").read_text())
            again = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(repo)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn("summary: change=0 already=2 skipped=0 unhandled=0", again.stdout)

    def test_applied_tree_reports_no_remaining_changes(self):
        probe = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--root", str(ROOT)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        unhandled = [line for line in probe.stdout.splitlines()
                     if line.startswith("unhandled: ")]
        self.assertIn("unhandled: deploy/Dockerfile.knative-holder: no SPDX header on line 1", unhandled)
        self.assertIn("unhandled: tests/fixtures/browser/register-suite.patch: no SPDX header on line 1",
                      unhandled)
        summary = [line for line in probe.stdout.splitlines() if line.startswith("summary: ")]
        self.assertEqual(len(summary), 1)
        fields = dict(part.split("=") for part in summary[0].removeprefix("summary: ").split())
        self.assertEqual(int(fields["change"]), 0)
        self.assertGreaterEqual(int(fields["already"]), 1000)
        self.assertEqual(int(fields["unhandled"]), len(unhandled))


if __name__ == "__main__":
    unittest.main()
