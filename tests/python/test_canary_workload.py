#!/usr/bin/env python3
"""Native lifecycle tests for the deterministic canary workload."""

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKLOAD_SOURCE = ROOT / "scripts" / "fixtures" / "canary_workload.c"
PROVIDER_SOURCE = ROOT / "crates" / "discover" / "tests" / "fixture" / "version_matrix.c"

RECORDER_SOURCE = r"""
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG, CK_RV, CK_FLAGS;
typedef struct { CK_BYTE major, minor; } CK_VERSION;
typedef struct { char *name; void *table; CK_FLAGS flags; } CK_INTERFACE;
typedef struct { CK_VERSION version; void *functions[104]; } Table;
static CK_RV record(void) {
    const char *value = getenv("P11SCOPE_TEST_RECORDER_FD");
    if (value) { int fd = atoi(value); char byte = 'C'; (void)write(fd, &byte, 1); }
    return 0;
}
static Table table;
static void fill(void) {
    static int done;
    if (done) return;
    done = 1; table.version = (CK_VERSION){3, 2};
    for (size_t i = 0; i < 104; i++) table.functions[i] = (void *)record;
}
CK_RV C_GetInterfaceList(CK_INTERFACE *out, CK_ULONG *count) {
    static char name[] = "PKCS 11"; fill();
    if (!count) return 7;
    if (!out) { *count = 1; return 0; }
    if (*count < 1) { *count = 1; return 0x150; }
    out[0] = (CK_INTERFACE){name, &table, 0}; *count = 1; return 0;
}
CK_RV C_GetInterface(void *name, void *version, void **out, CK_FLAGS flags) {
    (void)name; (void)version; (void)flags; fill();
    static CK_INTERFACE selected; static char interface_name[] = "PKCS 11";
    selected = (CK_INTERFACE){interface_name, &table, 0}; *out = &selected; return 0;
}
"""

PTHREAD_WRAP_SOURCE = r"""
#include <pthread.h>
int __real_pthread_create(pthread_t *, const pthread_attr_t *,
                          void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg) {
    static unsigned calls;
    unsigned current = __atomic_add_fetch(&calls, 1, __ATOMIC_RELAXED);
    if (current > 1) return 11;
    return __real_pthread_create(thread, attr, start, arg);
}
"""


def task_starttime(pid, tid):
    raw = Path(f"/proc/{pid}/task/{tid}/stat").read_text(encoding="ascii")
    closing = raw.rfind(")")
    if closing < 0:
        raise AssertionError(f"malformed stat for {pid}/{tid}")
    fields_after_comm = raw[closing + 2 :].split()
    value = int(fields_after_comm[19])
    if value <= 0:
        raise AssertionError(f"nonpositive starttime for {pid}/{tid}")
    return value


class CanaryWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix=f"canary-workload-{TARGET_BITS}-")
        cls.directory = Path(cls.build.name)
        cls.workload = cls.directory / "canary-workload"
        cls.wrapped_workload = cls.directory / "canary-workload-wrapped"
        cls.provider = cls.directory / "matrix-provider.so"
        cls.recorder = cls.directory / "recorder-provider.so"
        recorder_source = cls.directory / "recorder.c"
        wrapper_source = cls.directory / "pthread-wrap.c"
        recorder_source.write_text(RECORDER_SOURCE, encoding="utf-8")
        wrapper_source.write_text(PTHREAD_WRAP_SOURCE, encoding="utf-8")
        common = ["cc", f"-m{TARGET_BITS}", "-std=c11", "-Wall", "-Wextra", "-Werror"]
        cls.compile(common + ["-shared", "-fPIC", "-DPRIVACY_FIXTURE=1", "-o",
                            str(cls.provider), str(PROVIDER_SOURCE)])
        cls.compile(common + ["-shared", "-fPIC", "-o", str(cls.recorder),
                            str(recorder_source)])
        cls.compile(common + ["-pthread", "-o", str(cls.workload),
                            str(WORKLOAD_SOURCE), "-ldl"])
        cls.compile(common + ["-pthread", "-o", str(cls.wrapped_workload),
                            str(WORKLOAD_SOURCE), str(wrapper_source),
                            "-Wl,--wrap=pthread_create", "-ldl"])

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    @classmethod
    def compile(cls, command):
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if result.returncode:
            raise AssertionError(
                f"compiler/multilib unavailable for {TARGET_BITS}-bit native suite\n"
                f"command: {' '.join(command)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.directory)
        self.case_dir = Path(self.case.name)
        self.children = []

    def tearDown(self):
        for child in reversed(self.children):
            if child.poll() is None:
                try:
                    os.kill(child.pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                child.terminate()
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        self.case.cleanup()

    def launch(self, mode, *, executable=None, provider=None, ready=None, go=None,
               env=None, pass_fds=()):
        command = [str(executable or self.workload), str(provider or self.provider), mode]
        if ready is not None or go is not None:
            command += [str(ready), str(go)]
        child = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, pass_fds=pass_fds)
        self.children.append(child)
        return child

    def wait_ready(self, child, ready, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if ready.exists():
                return ready.read_bytes()
            if child.poll() is not None:
                stdout, stderr = child.communicate()
                self.fail(f"workload exited before READY: {child.returncode}\n{stdout}\n{stderr}")
            time.sleep(0.01)
        self.fail("workload did not publish READY within bounded test timeout")

    def assert_roster(self, mode, roster, pid):
        expected_workers = {"matrix": 0, "blocked": 4, "faults": 2}[mode]
        self.assertEqual(roster["schema"], "p11scope/canary-roster/v1")
        self.assertEqual(roster["mode"], mode)
        self.assertEqual(roster["pid"], pid)
        tasks = roster["tasks"]
        self.assertEqual(len(tasks), expected_workers + 1)
        self.assertEqual(tasks[0]["role"], "leader")
        self.assertIsNone(tasks[0]["call_index"])
        self.assertEqual(tasks[0]["pid"], pid)
        self.assertEqual(tasks[0]["tid"], pid)
        self.assertEqual([row["call_index"] for row in tasks[1:]], list(range(expected_workers)))
        self.assertTrue(all(row["role"] == "worker" for row in tasks[1:]))
        tids = [row["tid"] for row in tasks]
        self.assertEqual(len(tids), len(set(tids)))
        self.assertEqual(set(tids), {int(entry.name) for entry in Path(f"/proc/{pid}/task").iterdir()})
        for row in tasks:
            self.assertEqual(row["pid"], pid)
            self.assertGreater(row["tid"], 0)
            self.assertEqual(row["generation"], task_starttime(pid, row["tid"]))

    def assert_no_ready_temporaries(self):
        self.assertEqual(
            sorted(str(path.relative_to(self.case_dir)) for path in self.case_dir.rglob("*.tmp.*")),
            [],
            "workload left a READY publication temporary artifact",
        )

    def test_gated_modes_publish_complete_private_live_rosters_and_release_calls(self):
        expected_calls = {"matrix": 25, "blocked": 4, "faults": 2}
        for mode in ("matrix", "blocked", "faults"):
            with self.subTest(mode=mode):
                ready = self.case_dir / f"{mode}.ready"
                go = self.case_dir / f"{mode}.go"
                read_fd, write_fd = os.pipe()
                os.set_blocking(read_fd, False)
                env = dict(os.environ, P11SCOPE_TEST_RECORDER_FD=str(write_fd))
                child = self.launch(mode, provider=self.recorder, ready=ready, go=go,
                                    env=env, pass_fds=(write_fd,))
                os.close(write_fd)
                first = self.wait_ready(child, ready)
                self.assertEqual(stat.S_IMODE(ready.stat().st_mode), 0o600)
                roster = json.loads(first)
                self.assert_roster(mode, roster, child.pid)
                for _ in range(20):
                    self.assertEqual(ready.read_bytes(), first)
                    time.sleep(0.005)
                with self.assertRaises(BlockingIOError):
                    os.read(read_fd, 1)
                self.assertIsNone(child.poll())
                go.touch()
                if mode == "matrix":
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        state = Path(f"/proc/{child.pid}/status").read_text().split("State:", 1)[1].lstrip()[0]
                        if state == "T":
                            break
                        time.sleep(0.01)
                    self.assertEqual(state, "T")
                    os.kill(child.pid, signal.SIGCONT)
                stdout, stderr = child.communicate(timeout=3)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertIn("all calls CKR_OK", stdout)
                recorded = os.read(read_fd, 4096)
                self.assertEqual(len(recorded), expected_calls[mode])
                os.close(read_fd)
                self.assert_no_ready_temporaries()

    def test_gate_timeout_is_nonpass_but_retains_complete_ready_diagnostic(self):
        ready, go = self.case_dir / "timeout.ready", self.case_dir / "timeout.go"
        child = self.launch("blocked", ready=ready, go=go)
        first = self.wait_ready(child, ready)
        stdout, stderr = child.communicate(timeout=12)
        self.assertNotEqual(child.returncode, 0, stdout)
        self.assertEqual(ready.read_bytes(), first)
        self.assertIn("timed out waiting for GO", stderr)
        self.assert_no_ready_temporaries()

    def test_stale_identical_malformed_and_publication_failures_are_nonpass(self):
        stale_ready, stale_go = self.case_dir / "stale.ready", self.case_dir / "stale.go"
        stale_ready.write_text("stale", encoding="ascii")
        stale_go.touch()
        cases = [
            [str(self.workload), str(self.provider), "blocked", str(stale_ready), str(self.case_dir / "new.go")],
            [str(self.workload), str(self.provider), "blocked", str(self.case_dir / "new.ready"), str(stale_go)],
            [str(self.workload), str(self.provider), "blocked", str(self.case_dir / "same"), str(self.case_dir / "same")],
            [str(self.workload), str(self.provider), "blocked", str(self.case_dir / "alias"), f"{self.case_dir}/./alias"],
            [str(self.workload), str(self.provider), "blocked", str(self.case_dir / "only-ready")],
            [str(self.workload), str(self.provider), "blocked", "extra", "go", "extra"],
            [str(self.workload), str(self.provider), "blocked", str(self.case_dir / "missing" / "ready"), str(self.case_dir / "go")],
        ]
        for command in cases:
            with self.subTest(command=command[3:]):
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                        timeout=3, check=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_no_ready_temporaries()
        self.assertEqual(stale_ready.read_text(encoding="ascii"), "stale")

    def test_partial_pthread_creation_aborts_and_joins_without_provider_calls(self):
        ready, go = self.case_dir / "partial.ready", self.case_dir / "partial.go"
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        env = dict(os.environ, P11SCOPE_TEST_RECORDER_FD=str(write_fd))
        child = self.launch("blocked", executable=self.wrapped_workload, provider=self.recorder,
                            ready=ready, go=go, env=env, pass_fds=(write_fd,))
        os.close(write_fd)
        stdout, stderr = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0, stdout)
        self.assertFalse(ready.exists())
        self.assertIn("pthread_create failed", stderr)
        self.assertEqual(os.read(read_fd, 1), b"")
        os.close(read_fd)
        self.assert_no_ready_temporaries()

    def test_legacy_ungated_modes_preserve_outputs(self):
        for mode, marker in (
            ("matrix", "canary_workload matrix: all calls CKR_OK"),
            ("blocked", "blocked hostile subset: all calls CKR_OK"),
            ("faults", "blocked template faults: all calls CKR_OK"),
        ):
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.workload), str(self.provider), mode], cwd=ROOT,
                                        text=True, capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(marker, result.stdout)
                if mode == "matrix":
                    self.assertEqual(sum(line.endswith(" -> 0x0") for line in result.stdout.splitlines()), 25)


def parse_args(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target-bits", type=int, choices=(32, 64), required=True)
    known, remaining = parser.parse_known_args(argv)
    return known.target_bits, remaining


if __name__ == "__main__":
    TARGET_BITS, unittest_args = parse_args(sys.argv[1:])
    if not unittest_args:
        unittest_args = ["-v"]
    unittest.main(argv=[sys.argv[0], *unittest_args])
else:
    TARGET_BITS = 64
