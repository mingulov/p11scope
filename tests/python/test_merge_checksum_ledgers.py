#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native behavior tests for the strict checksum-ledger merger."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
MERGER = REPOSITORY / "scripts/merge-checksum-ledgers.py"
A = "a" * 64
B = "b" * 64
C = "c" * 64


class MergeChecksumLedgersTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name: str, value: bytes) -> Path:
        path = self.root / name
        path.write_bytes(value)
        return path

    def run_merger(self, *paths: Path):
        return subprocess.run(
            [sys.executable, "-I", str(MERGER), *(str(path) for path in paths)],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_refused(self, result, *needles: bytes):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_merges_and_sorts_by_utf8_path_bytes_with_spaces_and_unicode(self):
        first = self.write(
            "first ledger",
            f"{A}   leading.txt\n{B}  zeta/space name \n".encode(),
        )
        second = self.write("second ledger", f"{C}  unicodé/δ.txt\n".encode())
        result = self.run_merger(first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = sorted(
            [(" leading.txt", A), ("zeta/space name ", B), ("unicodé/δ.txt", C)],
            key=lambda item: item[0].encode("utf-8"),
        )
        self.assertEqual(
            result.stdout,
            "".join(f"{digest}  {path}\n" for path, digest in expected).encode(),
        )
        self.assertEqual(result.stderr, b"")

    def test_duplicate_paths_are_refused_even_when_digests_match(self):
        for second_digest in (A, B):
            with self.subTest(second_digest=second_digest):
                first = self.write("one", f"{A}  same path\n".encode())
                second = self.write("two", f"{second_digest}  same path\n".encode())
                self.assert_refused(self.run_merger(first, second), b"duplicate path", b"same path")
        within = self.write("within", f"{A}  same path\n{B}  same path\n".encode())
        self.assert_refused(self.run_merger(within), b"duplicate path", b"within")

    def test_invalid_digest_and_separator_are_refused(self):
        rows = {
            "short": f"{'a' * 63}  ok\n".encode(),
            "uppercase": f"{'A' * 64}  ok\n".encode(),
            "nonhex": f"{'g' * 64}  ok\n".encode(),
            "one-space": f"{A} ok\n".encode(),
            "tab": f"{A}\tok\n".encode(),
        }
        for label, row in rows.items():
            with self.subTest(label=label):
                result = self.run_merger(self.write(label, row))
                self.assert_refused(result, label.encode(), b"row 1")

    def test_noncanonical_or_empty_paths_are_refused(self):
        paths = ["", "/absolute", "../parent", "a/../b", ".", "a/./b", "a//b",
                 "a/", "back\\slash"]
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                ledger = self.write(str(index), f"{A}  {path}\n".encode())
                self.assert_refused(self.run_merger(ledger), b"path", b"row 1")

    def test_control_del_and_cr_characters_in_paths_are_refused(self):
        for index, byte in enumerate((b"\x00", b"\x09", b"\x0d", b"\x1f", b"\x7f")):
            with self.subTest(byte=byte):
                ledger = self.write(f"control-{index}", A.encode() + b"  a" + byte + b"b\n")
                self.assert_refused(self.run_merger(ledger), b"control", b"row 1")

    def test_missing_trailing_lf_and_non_utf8_are_refused(self):
        missing_lf = self.write("missing-lf", f"{A}  path".encode())
        self.assert_refused(self.run_merger(missing_lf), b"trailing LF", b"missing-lf")
        non_utf8 = self.write("non-utf8", A.encode() + b"  bad-\xff\n")
        self.assert_refused(self.run_merger(non_utf8), b"UTF-8", b"non-utf8")

    def test_empty_files_and_empty_rows_emit_empty_output(self):
        result = self.run_merger(self.write("empty", b""), self.write("blank rows", b"\n\n"))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_missing_directory_and_symlink_inputs_are_refused(self):
        missing = self.root / "missing"
        directory = self.root / "directory"
        directory.mkdir()
        target = self.write("target", b"")
        link = self.root / "link"
        os.symlink(target, link)
        for path, needle in ((missing, b"cannot inspect"), (directory, b"regular file"),
                             (link, b"symlink")):
            with self.subTest(path=path):
                self.assert_refused(self.run_merger(path), needle, str(path).encode())

    def test_valid_first_input_then_invalid_later_emits_no_partial_output(self):
        first = self.write("valid", f"{A}  valid/path\n".encode())
        later = self.write("invalid", f"{B}  ../invalid\n".encode())
        self.assert_refused(self.run_merger(first, later), b"invalid", b"row 1")


if __name__ == "__main__":
    unittest.main()
