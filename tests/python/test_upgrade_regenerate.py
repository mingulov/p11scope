#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The upgrade fixtures regenerate exactly.

The README `Regenerate` manifest must list precisely the sanitizer's
input set (no missing or extra file can hide in prose), the
sanitizer's scrub rules must hold, and the full
unsanitize-then-sanitize round trip over the committed fixtures must
reproduce them byte for byte.
"""
import filecmp
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPGRADE = ROOT / "tests" / "fixtures" / "upgrade"
README = UPGRADE / "README.md"
SANITIZE = UPGRADE / "tools" / "sanitize.py"


def load_sanitize():
    spec = importlib.util.spec_from_file_location("upgrade_sanitize", SANITIZE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def readme_manifest():
    """The ```manifest block under ## Regenerate: one file per line."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"```manifest\n(.*?)```", text, re.DOTALL)
    assert match is not None, "README has no ```manifest block"
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def unsanitize(document, raw_prefix):
    """Inverse of the sanitizer's canonical maps (structure-preserving).

    Every transform is injective over the values the committed
    fixtures carry, so re-sanitizing in the same encounter order
    restores the exact canonical bytes.
    """
    if isinstance(document, dict):
        return {key: unsanitize(value, raw_prefix) for key, value in document.items()}
    if isinstance(document, list):
        return [unsanitize(value, raw_prefix) for value in document]
    if not isinstance(document, str):
        return document
    text = document.replace("/work", raw_prefix)
    # Same +9000 shift as integer pid fields: the sanitizer keys all
    # pid representations by the number in one shared map, so the
    # inverse must keep equal pids equal across representations.
    text = re.sub(r"pid:(\d+)", lambda m: f"pid:{int(m.group(1)) + 9000}", text)
    text = re.sub(r"/proc/(\d+)", lambda m: f"/proc/{int(m.group(1)) + 9000}", text)
    text = re.sub(r"\bpid (\d+)", lambda m: f"pid {int(m.group(1)) + 9000}", text)
    text = text.replace("user-1000.slice", "user-1001.slice")
    text = text.replace("session-1.scope", "session-c9.scope")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text):
        text = "f" + text[1:]
    return text


def unsanitize_document_integers(document):
    """Inverse integer maps applied field-wise (mirrors walk() keys).

    Unlisted integer fields pass through untouched here and in the
    sanitizer alike, so they need no inverse.
    """
    if isinstance(document, dict):
        rebuilt = {}
        for key, value in document.items():
            if key in ("mtime_secs", "mtime_nanos") and isinstance(value, int):
                rebuilt[key] = 99 if key == "mtime_secs" else 7
            elif key in ("pid", "pid_host", "handoff_child_pid",
                         "ino", "inode", "task_cookie", "exec_id") \
                    and isinstance(value, int) and not isinstance(value, bool):
                rebuilt[key] = value + 9000
            elif key == "dev" and isinstance(value, int) \
                    and not isinstance(value, bool):
                rebuilt[key] = value + 40
            elif key in ("dev", "device") and isinstance(value, dict):
                rebuilt[key] = {
                    "major": value.get("major", 0) + 40,
                    "minor": value.get("minor", 0) + 40,
                }
            elif key == "dev" and isinstance(value, list):
                rebuilt[key] = [part + 40 for part in value]
            elif key in ("device_major", "device_minor") and isinstance(value, int):
                rebuilt[key] = value + 40
            elif key == "exe" and value == "launcher":
                # Every committed "launcher" exe sits under launched_by,
                # where the sanitizer maps any value to "launcher".
                rebuilt[key] = "origlauncher"
            else:
                rebuilt[key] = unsanitize_document_integers(value)
        return rebuilt
    if isinstance(document, list):
        return [unsanitize_document_integers(value) for value in document]
    return document


class RegenerateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitize = load_sanitize()

    def test_readme_manifest_matches_sanitizer_files(self):
        """The documented capture set is exactly the sanitizer input
        set: a file missing on either side fails loudly instead of
        breaking regeneration later."""
        self.assertEqual(readme_manifest(), list(self.sanitize.FILES))
        for name in self.sanitize.FILES:
            with self.subTest(name=name):
                self.assertTrue(
                    (UPGRADE / name).is_file(), f"{name} is committed")

    def test_scrub_canonicalizes_prefix_and_cgroup(self):
        """The scrub rules rewrite the capture prefix and the cgroup
        slice/scope to canonical values."""
        prefixes = self.sanitize.build_prefixes("/custom/work")
        self.assertEqual(
            self.sanitize.scrub_string("/custom/work/f2/bin/tool", prefixes),
            "/work/f2/bin/tool")
        self.assertEqual(
            self.sanitize.scrub_string(
                "user.slice/user-4242.slice/session-z9.scope", prefixes),
            "user.slice/user-1000.slice/session-1.scope")

    def test_sanitizer_usage_errors(self):
        """Wrong argument counts fail with usage, never a traceback."""
        for argv in ([], ["a", "b", "c", "d"]):
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, str(SANITIZE), *argv],
                    capture_output=True, text=True, timeout=60)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Usage", proc.stderr)

    def write_raw_inputs(self, tmp):
        """Unsanitized copies of every committed fixture input."""
        raw = tmp / "raw"
        raw.mkdir()
        for name in self.sanitize.FILES:
            document = json.loads((UPGRADE / name).read_text(encoding="utf-8"))
            document = unsanitize(document, str(raw))
            # Integer fields invert after strings so pid-like
            # numbers inside strings are already handled above.
            document = unsanitize_document_integers(document)
            (raw / name).write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return raw

    def assert_matches_committed(self, out):
        mismatched = [
            name for name in self.sanitize.FILES
            if not filecmp.cmp(str(UPGRADE / name), str(out / name), shallow=False)
        ]
        self.assertEqual(mismatched, [])

    def test_roundtrip_reproduces_committed_fixtures(self):
        """Unsanitized copies of every committed fixture input,
        sanitized from a scratch prefix, reproduce the committed
        bytes exactly."""
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-regen-"))
        try:
            raw = self.write_raw_inputs(tmp)
            out = tmp / "out"
            self.sanitize.fresh_state()
            self.sanitize.sanitize_tree(str(raw), str(out), str(raw))
            self.assert_matches_committed(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cli_roundtrip_reproduces_committed_fixtures(self):
        """Same round trip through the real command line, so the
        rawdir/outdir/prefix argument plumbing is covered too."""
        tmp = Path(tempfile.mkdtemp(prefix="upgrade-regen-cli-"))
        try:
            raw = self.write_raw_inputs(tmp)
            out = tmp / "out"
            proc = subprocess.run(
                [sys.executable, str(SANITIZE), str(raw), str(out), str(raw)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assert_matches_committed(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
