# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact-process behavioral tests for system-scope-sample.py."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "scripts" / "system-scope-sample.py"


def process_starttime(pid):
    fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
    return int(fields[19])


def load_sampler():
    spec = importlib.util.spec_from_file_location("system_scope_sample", SAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stat_with(stat, *, state=None, starttime=None):
    head, raw_tail = stat.rsplit(")", 1)
    tail = raw_tail.split()
    if state is not None:
        tail[0] = state
    if starttime is not None:
        tail[19] = str(starttime)
    return f"{head}) {' '.join(tail)}"


class SystemScopeSampleTests(unittest.TestCase):
    def sampler_command(self, pid, starttime, output):
        return [
            "python3", "-I", str(SAMPLE),
            "--pid", str(pid), "--starttime", str(starttime),
            "--out", str(output), "--interval", "0.01",
        ]

    def run_sampler(self, pid, starttime, output, timeout=3):
        return subprocess.run(
            self.sampler_command(pid, starttime, output),
            cwd=ROOT, text=True, capture_output=True, timeout=timeout,
        )

    def test_exact_no_child_process_is_sampled_until_normal_exit(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "samples.jsonl"
            release = Path(raw) / "release"
            child = subprocess.Popen([
                "python3", "-I", "-c",
                "import pathlib,sys,time\n"
                "release=pathlib.Path(sys.argv[1])\n"
                "while not release.exists(): time.sleep(0.01)\n",
                str(release),
            ])
            sampler = None
            try:
                starttime = process_starttime(child.pid)
                children = Path(
                    f"/proc/{child.pid}/task/{child.pid}/children"
                ).read_text(encoding="utf-8").strip()
                self.assertEqual(children, "")
                started = time.monotonic()
                sampler = subprocess.Popen(
                    self.sampler_command(child.pid, starttime, output),
                    cwd=ROOT, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                deadline = time.monotonic() + 2
                while (not output.exists() or output.stat().st_size == 0):
                    self.assertIsNone(sampler.poll(), "sampler exited before a row")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                release.touch()
                stdout, stderr = sampler.communicate(timeout=2)
                elapsed = time.monotonic() - started
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
                if sampler is not None and sampler.poll() is None:
                    sampler.terminate()
                    sampler.wait(timeout=2)
            self.assertEqual(sampler.returncode, 0, stdout + stderr)
            self.assertLess(elapsed, 2.0)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertGreater(len(rows), 0)
            self.assertEqual({row["pid"] for row in rows}, {child.pid})

    def test_missing_exact_process_fails_promptly_without_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "samples.jsonl"
            child = subprocess.Popen(["sleep", "30"])
            starttime = process_starttime(child.pid)
            child.terminate()
            child.wait(timeout=2)
            started = time.monotonic()
            result = self.run_sampler(child.pid, starttime, output)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_legacy_parent_mode_still_samples_its_child(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "samples.jsonl"
            release = Path(raw) / "release"
            parent = subprocess.Popen([
                "python3", "-I", "-c",
                "import pathlib,signal,subprocess,sys\n"
                "code='import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                "\\nwhile not p.exists(): time.sleep(0.01)'\n"
                "def stop(signum, frame): raise SystemExit(128 + signum)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "child=subprocess.Popen([sys.executable,'-I','-c',code,sys.argv[1]])\n"
                "try:\n"
                " child.wait()\n"
                "finally:\n"
                " if child.poll() is None: child.terminate()\n"
                " try: child.wait(timeout=1)\n"
                " except subprocess.TimeoutExpired:\n"
                "  child.kill(); child.wait()\n",
                str(release),
            ])
            sampler = None
            try:
                sampler = subprocess.Popen(
                    [
                        "python3", "-I", str(SAMPLE),
                        "--ppid", str(parent.pid), "--out", str(output),
                        "--interval", "0.01", "--settle-s", "2",
                    ],
                    cwd=ROOT, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                deadline = time.monotonic() + 2
                while (not output.exists() or output.stat().st_size == 0):
                    self.assertIsNone(sampler.poll(), "legacy sampler exited early")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                release.touch()
                parent.wait(timeout=2)
                stdout, stderr = sampler.communicate(timeout=2)
            finally:
                release.touch(exist_ok=True)
                if parent.poll() is None:
                    try:
                        parent.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        parent.terminate()
                        parent.wait(timeout=2)
                if sampler is not None and sampler.poll() is None:
                    sampler.terminate()
                    sampler.wait(timeout=2)
            self.assertEqual(sampler.returncode, 0, stdout + stderr)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertGreater(len(rows), 0)
            self.assertNotIn(parent.pid, {row["pid"] for row in rows})

    def test_replaced_birth_fails_promptly_without_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "samples.jsonl"
            child = subprocess.Popen(["sleep", "30"])
            try:
                starttime = process_starttime(child.pid)
                started = time.monotonic()
                result = self.run_sampler(child.pid, starttime + 1, output)
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                child.terminate()
                child.wait(timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_unknown_identity_read_fails_closed(self):
        sampler = load_sampler()
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "samples.jsonl"
            with mock.patch.object(
                sampler, "read_text", side_effect=PermissionError("denied")
            ):
                with self.assertRaisesRegex(SystemExit, "cannot inspect"):
                    sampler.main([
                        "--pid", str(os.getpid()),
                        "--starttime", str(process_starttime(os.getpid())),
                        "--out", str(output), "--interval", "0.01",
                    ])
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(encoding="utf-8"), "")

    def test_replacement_between_bracketing_stat_reads_is_refused(self):
        sampler = load_sampler()
        pid = os.getpid()
        birth = process_starttime(pid)
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        with mock.patch.object(
            sampler, "read_text",
            side_effect=[stat, "1 1\n", stat_with(stat, starttime=birth + 1)],
        ), mock.patch.object(sampler.os, "listdir", return_value=[]):
            with self.assertRaisesRegex(
                sampler.TargetInspectionError, "birth identity changed"
            ):
                sampler.sample_exact(pid, birth)

    def test_unknown_between_bracketing_stat_reads_is_refused(self):
        sampler = load_sampler()
        pid = os.getpid()
        birth = process_starttime(pid)
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        with mock.patch.object(
            sampler, "read_text",
            side_effect=[stat, "1 1\n", PermissionError("denied")],
        ), mock.patch.object(sampler.os, "listdir", return_value=[]):
            with self.assertRaisesRegex(
                sampler.TargetInspectionError, "cannot inspect exact target stat"
            ):
                sampler.sample_exact(pid, birth)

    def test_kernel_terminal_states_do_not_emit_rows(self):
        sampler = load_sampler()
        pid = os.getpid()
        birth = process_starttime(pid)
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        for state in ("X", "x", "Z"):
            with self.subTest(state=state), mock.patch.object(
                sampler, "read_text", return_value=stat_with(stat, state=state)
            ):
                self.assertIsNone(sampler.sample_exact(pid, birth))


if __name__ == "__main__":
    unittest.main()
