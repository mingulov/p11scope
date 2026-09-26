#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned workload controls only; these do not qualify observer first use."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/fixtures/system-first-use.c"


class FirstUseFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="p11scope-first-use-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.base = Path(cls.build.name)
        cls.driver = cls.base / "driver"
        flags = ["gcc", "-O0", "-g", "-Wall", "-Wextra", "-Werror"]
        subprocess.run([*flags, str(SOURCE), "-ldl", "-o", str(cls.driver)], check=True)
        cls.providers = {}
        for kind, extra in (("file", []), ("heap", ["-DT2_HEAP_TABLE"]),
                            ("bad", ["-DT2_BAD_TABLE"])):
            path = cls.base / f"provider-{kind}.so"
            subprocess.run([*flags, "-shared", "-fPIC", "-DT2_PROVIDER", *extra,
                            str(SOURCE), "-o", str(path)], check=True)
            cls.providers[kind] = path

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-first-use-case-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.ledger = self.work / "ledger.jsonl"

    def command(self, kind="file", publication="-", entry="-", provider=None):
        return [str(self.driver), str(provider or self.providers[kind]),
                str(self.ledger), str(publication), str(entry)]

    def rows(self, allow_partial=False):
        if not self.ledger.exists():
            return []
        data = self.ledger.read_text()
        lines = data.splitlines(keepends=True)
        if lines and not lines[-1].endswith("\n"):
            if allow_partial:
                lines.pop()
            else:
                self.fail("unterminated ledger record")
        return [json.loads(line) for line in lines]

    def wait_phase(self, child, phase):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            rows = self.rows(allow_partial=True)
            if any(row["phase"] == phase for row in rows):
                return rows
            if child.poll() is not None:
                self.fail(f"fixture exited before {phase}: {child.communicate()}")
            time.sleep(0.005)
        self.fail(f"fixture did not reach {phase}")

    def start(self, command):
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)

        def settle():
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=3)
        self.addCleanup(settle)
        return child

    def assert_complete(self, rows):
        self.assertEqual([row["phase"] for row in rows], [
            "object_stat", "mapped", "publication_returned", "table_verified",
            "entry_executed", "entry_returned", "unloaded"])
        times = [row["mono_ns"] for row in rows]
        self.assertEqual(times, sorted(times))
        self.assertGreater(times[0], 0)
        self.assertEqual(len({(r["pid"], r["birth"], r["module_dev"],
                              r["module_ino"], r["mount_ns_ino"]) for r in rows}), 1)
        for key in ("pid", "birth", "module_ino", "mount_ns_ino"):
            self.assertGreater(rows[0][key], 0)
        self.assertEqual(rows[3]["entries"], 68)
        self.assertEqual(rows[4]["body_count"], 1)
        self.assertEqual(rows[5]["rv"], 0)
        self.assertFalse(any(k in row for row in rows for k in
                             ("observer_known_ns", "scan_ns", "attach_ns", "observed_entry_ns")))

    def test_ungated_load_call_unload_has_independent_body_truth(self):
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_complete(self.rows())

    def test_entry_gate_holds_after_table_verification(self):
        gate = self.work / "entry-go"
        child = self.start(self.command(entry=gate))
        rows = self.wait_phase(child, "table_verified")
        self.assertNotIn("entry_executed", [r["phase"] for r in rows])
        with self.assertRaises(subprocess.TimeoutExpired):
            child.wait(timeout=0.05)
        self.assertNotIn("entry_executed", [r["phase"] for r in self.rows()])
        gate.touch()
        _, error = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, error)
        self.assert_complete(self.rows())

    def test_heap_table_exists_only_after_released_publication(self):
        publication = self.work / "publish-go"
        entry = self.work / "entry-go"
        child = self.start(self.command("heap", publication, entry))
        rows = self.wait_phase(child, "mapped")
        mapped = next(row for row in rows if row["phase"] == "mapped")
        self.assertFalse(mapped["table_present"])
        self.assertNotIn("publication_returned", [r["phase"] for r in rows])
        with self.assertRaises(subprocess.TimeoutExpired):
            child.wait(timeout=0.05)
        self.assertNotIn("publication_returned", [r["phase"] for r in self.rows()])
        publication.touch()
        rows = self.wait_phase(child, "table_verified")
        verified = next(row for row in rows if row["phase"] == "table_verified")
        self.assertEqual(verified["table_storage"], "heap")
        with self.assertRaises(subprocess.TimeoutExpired):
            child.wait(timeout=0.05)
        self.assertNotIn("entry_executed", [r["phase"] for r in self.rows()])
        entry.touch()
        _, error = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, error)
        self.assert_complete(self.rows())

    def test_file_table_is_file_backed_and_ready_at_mapping(self):
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.rows()
        self.assertTrue(rows[1]["table_present"])
        self.assertEqual(rows[3]["table_storage"], "file")

    def test_equal_bytes_on_new_inode_keep_distinct_file_identity(self):
        first = self.providers["file"]
        copy = self.work / "copy.so"
        shutil.copyfile(first, copy)
        self.assertEqual(hashlib.sha256(first.read_bytes()).digest(),
                         hashlib.sha256(copy.read_bytes()).digest())
        result = subprocess.run(self.command(provider=copy), capture_output=True,
                                text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.rows()
        self.assertEqual(rows[0]["module_ino"], copy.stat().st_ino)
        self.assertNotEqual((first.stat().st_dev, first.stat().st_ino),
                            (rows[0]["module_dev"], rows[0]["module_ino"]))
        self.assert_complete(rows)

    def test_incomplete_table_refuses_before_ordinary_call(self):
        result = subprocess.run(self.command("bad"), capture_output=True,
                                text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        phases = [row["phase"] for row in self.rows()]
        self.assertIn("publication_returned", phases)
        self.assertNotIn("entry_executed", phases)
        self.assertIn("invalid table", result.stderr)

    def test_existing_ledger_is_not_overwritten(self):
        self.ledger.write_text("preserve this\n")
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.ledger.read_text(), "preserve this\n")


if __name__ == "__main__":
    unittest.main()
