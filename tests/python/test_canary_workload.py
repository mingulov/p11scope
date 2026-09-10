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
    const char *failure = getenv("P11SCOPE_TEST_RECORDER_FAIL_CALL");
    static unsigned calls;
    calls++;
    if (failure && calls == (unsigned)strtoul(failure, NULL, 10)) return 5;
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
    selected = (CK_INTERFACE){interface_name, &table, 0}; *out = &selected;
    const char *value = getenv("P11SCOPE_TEST_INTERFACE_FD");
    if (value) { int fd = atoi(value); char byte = 'I'; (void)write(fd, &byte, 1); }
    const char *failure = getenv("P11SCOPE_TEST_INTERFACE_FAIL_CALL");
    static unsigned calls;
    calls++;
    return failure && calls == (unsigned)strtoul(failure, NULL, 10) ? 7 : 0;
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

CLOCK_WRAP_SOURCE = r"""
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
int __real_clock_gettime(clockid_t, struct timespec *);
int __real_link(const char *, const char *);
static int done_published;
int __wrap_link(const char *oldpath, const char *newpath) {
    int status = __real_link(oldpath, newpath);
    const char *done = getenv("P11SCOPE_TEST_FINISH_TIMEOUT_DONE");
    if (status == 0 && done && strcmp(done, newpath) == 0) done_published = 1;
    return status;
}
int __wrap_clock_gettime(clockid_t clock, struct timespec *value) {
    int status = __real_clock_gettime(clock, value);
    if (status == 0 && clock == CLOCK_MONOTONIC && done_published) {
        value->tv_sec += 61;
        const char *finish = getenv("P11SCOPE_TEST_CREATE_LATE_FINISH");
        if (finish) {
            int fd = open(finish, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd >= 0) close(fd);
        }
    }
    return status;
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
        cls.clock_wrapped_workload = cls.directory / "canary-workload-clock-wrapped"
        cls.provider = cls.directory / "matrix-provider.so"
        cls.recorder = cls.directory / "recorder-provider.so"
        recorder_source = cls.directory / "recorder.c"
        wrapper_source = cls.directory / "pthread-wrap.c"
        clock_wrapper_source = cls.directory / "clock-wrap.c"
        recorder_source.write_text(RECORDER_SOURCE, encoding="utf-8")
        wrapper_source.write_text(PTHREAD_WRAP_SOURCE, encoding="utf-8")
        clock_wrapper_source.write_text(CLOCK_WRAP_SOURCE, encoding="utf-8")
        common = ["cc", f"-m{TARGET_BITS}", "-std=c11", "-Wall", "-Wextra", "-Werror"]
        # The provider uses MAP_ANONYMOUS, hidden by strict C11 on older glibc.
        cls.compile(common + ["-shared", "-fPIC", "-D_DEFAULT_SOURCE", "-DPRIVACY_FIXTURE=1", "-o",
                            str(cls.provider), str(PROVIDER_SOURCE)])
        cls.compile(common + ["-shared", "-fPIC", "-o", str(cls.recorder),
                            str(recorder_source)])
        cls.compile(common + ["-pthread", "-o", str(cls.workload),
                            str(WORKLOAD_SOURCE), "-ldl"])
        cls.compile(common + ["-pthread", "-o", str(cls.wrapped_workload),
                            str(WORKLOAD_SOURCE), str(wrapper_source),
                            "-Wl,--wrap=pthread_create", "-ldl"])
        cls.compile(common + ["-pthread", "-o", str(cls.clock_wrapped_workload),
                            str(WORKLOAD_SOURCE), str(clock_wrapper_source),
                            "-Wl,--wrap=clock_gettime", "-Wl,--wrap=link", "-ldl"])

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
               done=None, finish=None, env=None, pass_fds=(), stdout=subprocess.PIPE):
        command = [str(executable or self.workload), str(provider or self.provider), mode]
        if ready is not None or go is not None:
            command += [str(ready), str(go)]
        if done is not None or finish is not None:
            command += [str(done), str(finish)]
        child = subprocess.Popen(command, cwd=ROOT, text=True, stdout=stdout,
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

    def wait_path(self, child, path, label, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return path.read_bytes()
            if child.poll() is not None:
                stdout, stderr = child.communicate()
                self.fail(f"workload exited before {label}: {child.returncode}\n{stdout}\n{stderr}")
            time.sleep(0.01)
        self.fail(f"workload did not publish {label} within bounded test timeout")

    def assert_no_publication_temporaries(self):
        self.assertEqual(
            sorted(str(path.relative_to(self.case_dir)) for path in self.case_dir.rglob("*.tmp.*")),
            [],
            "workload left an owned publication temporary artifact",
        )

    def matrix_paths(self, prefix="matrix"):
        return tuple(self.case_dir / f"{prefix}.{name}" for name in ("ready", "go", "done", "finish"))

    def communicate_releasing_incorrect_done(self, child, done, finish):
        deadline = time.monotonic() + 1
        while child.poll() is None and not done.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if done.exists() and child.poll() is None:
            finish.touch()
        return child.communicate(timeout=3)

    def launch_recorded_matrix(self, *, executable=None, env_extra=None, prefix="matrix",
                               stdout=subprocess.PIPE):
        ready, go, done, finish = self.matrix_paths(prefix)
        read_fd, write_fd = os.pipe()
        interface_read_fd, interface_write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        os.set_blocking(interface_read_fd, False)
        env = dict(os.environ, P11SCOPE_TEST_RECORDER_FD=str(write_fd),
                   P11SCOPE_TEST_INTERFACE_FD=str(interface_write_fd))
        env.update(env_extra or {})
        child = self.launch("matrix", executable=executable, provider=self.recorder,
                            ready=ready, go=go, done=done, finish=finish,
                            env=env, pass_fds=(write_fd, interface_write_fd), stdout=stdout)
        os.close(write_fd)
        os.close(interface_write_fd)
        return child, read_fd, interface_read_fd, (ready, go, done, finish)

    def test_completed_matrix_barrier_retains_identity_calls_and_process_until_finish(self):
        child, read_fd, interface_fd, (ready, go, done, finish) = self.launch_recorded_matrix()
        ready_bytes = self.wait_ready(child, ready)
        roster = json.loads(ready_bytes)
        self.assert_roster("matrix", roster, child.pid)
        self.assertEqual(stat.S_IMODE(ready.stat().st_mode), 0o600)
        with self.assertRaises(BlockingIOError):
            os.read(read_fd, 1)
        with self.assertRaises(BlockingIOError):
            os.read(interface_fd, 1)
        go.touch()
        done_bytes = self.wait_path(child, done, "DONE")
        completed = json.loads(done_bytes)
        self.assertEqual(completed, {
            "schema": "p11scope/canary-done/v1",
            "mode": "matrix",
            "pid": child.pid,
            "generation": roster["tasks"][0]["generation"],
        })
        self.assertEqual(stat.S_IMODE(done.stat().st_mode), 0o600)
        recorded = os.read(read_fd, 4096)
        self.assertEqual(len(recorded), 25)
        self.assertEqual(os.read(interface_fd, 4096), b"III")
        os.set_blocking(child.stdout.fileno(), False)
        visible = os.read(child.stdout.fileno(), 16384).decode("utf-8")
        self.assertIn("canary_workload matrix: all calls CKR_OK", visible)
        self.assertIsNone(child.poll())
        tasks = list(Path(f"/proc/{child.pid}/task").iterdir())
        self.assertEqual([int(task.name) for task in tasks], [child.pid])
        self.assertEqual(Path(f"/proc/{child.pid}/exe").resolve(), self.workload.resolve())
        self.assertEqual(Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text(), "")
        state = Path(f"/proc/{child.pid}/status").read_text().split("State:", 1)[1].lstrip()[0]
        self.assertNotEqual(state, "T")
        time.sleep(0.05)
        with self.assertRaises(BlockingIOError):
            os.read(read_fd, 1)
        self.assertEqual(ready.read_bytes(), ready_bytes)
        self.assertEqual(done.read_bytes(), done_bytes)
        finish.touch()
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(os.read(read_fd, 1), b"")
        os.close(read_fd)
        self.assertEqual(os.read(interface_fd, 1), b"")
        os.close(interface_fd)
        self.assert_no_publication_temporaries()

    def test_completed_matrix_provider_failure_never_publishes_done(self):
        child, read_fd, interface_fd, (ready, go, done, _finish) = self.launch_recorded_matrix(
            env_extra={"P11SCOPE_TEST_RECORDER_FAIL_CALL": "7"})
        self.wait_ready(child, ready)
        go.touch()
        stdout, stderr = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0, stdout)
        self.assertFalse(done.exists())
        self.assertEqual(len(os.read(read_fd, 4096)), 25)
        self.assertEqual(os.read(interface_fd, 4096), b"III")
        os.close(read_fd)
        os.close(interface_fd)
        self.assert_no_publication_temporaries()

    def test_completed_matrix_rejects_each_interface_export_failure(self):
        for call in (1, 2, 3):
            with self.subTest(call=call):
                child, read_fd, interface_fd, (ready, go, done, finish) = \
                    self.launch_recorded_matrix(
                        prefix=f"interface-{call}",
                        env_extra={"P11SCOPE_TEST_INTERFACE_FAIL_CALL": str(call)})
                self.wait_ready(child, ready)
                go.touch()
                stdout, stderr = self.communicate_releasing_incorrect_done(
                    child, done, finish)
                self.assertNotEqual(child.returncode, 0, stdout)
                self.assertFalse(done.exists())
                self.assertEqual(len(os.read(read_fd, 4096)), 25)
                self.assertEqual(os.read(interface_fd, 4096), b"III")
                os.close(read_fd)
                os.close(interface_fd)
                self.assert_no_publication_temporaries()
        for call in (1, 2, 3):
            with self.subTest(legacy_ungated_call=call):
                env = dict(os.environ, P11SCOPE_TEST_INTERFACE_FAIL_CALL=str(call))
                result = subprocess.run([str(self.workload), str(self.recorder), "matrix"],
                                        cwd=ROOT, text=True, capture_output=True, env=env,
                                        timeout=3, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        for call in (1, 2, 3):
            with self.subTest(legacy_gated_call=call):
                ready, go, _done, _finish = self.matrix_paths(f"legacy-interface-{call}")
                env = dict(os.environ, P11SCOPE_TEST_INTERFACE_FAIL_CALL=str(call))
                child = self.launch("matrix", provider=self.recorder, ready=ready, go=go,
                                    env=env)
                self.wait_ready(child, ready)
                go.touch()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    state = Path(f"/proc/{child.pid}/status").read_text().split(
                        "State:", 1)[1].lstrip()[0]
                    if state == "T":
                        break
                    time.sleep(0.01)
                self.assertEqual(state, "T")
                os.kill(child.pid, signal.SIGCONT)
                stdout, stderr = child.communicate(timeout=3)
                self.assertEqual(child.returncode, 0, stderr)

    def test_completed_matrix_output_failure_suppresses_done_but_legacy_is_unchanged(self):
        with open("/dev/full", "w", encoding="utf-8") as full:
            child, read_fd, interface_fd, (ready, go, done, finish) = \
                self.launch_recorded_matrix(prefix="full", stdout=full)
            ready_bytes = self.wait_ready(child, ready)
            go.touch()
            _stdout, stderr = self.communicate_releasing_incorrect_done(
                child, done, finish)
        self.assertNotEqual(child.returncode, 0, stderr)
        self.assertFalse(done.exists())
        self.assertEqual(ready.read_bytes(), ready_bytes)
        self.assertEqual(len(os.read(read_fd, 4096)), 25)
        self.assertEqual(os.read(interface_fd, 4096), b"III")
        os.close(read_fd)
        os.close(interface_fd)
        self.assert_no_publication_temporaries()
        with open("/dev/full", "w", encoding="utf-8") as full:
            legacy = subprocess.run([str(self.workload), str(self.recorder), "matrix"],
                                    cwd=ROOT, text=True, stdout=full, stderr=subprocess.PIPE,
                                    timeout=3, check=False)
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        ready, go, _done, _finish = self.matrix_paths("legacy-full")
        with open("/dev/full", "w", encoding="utf-8") as full:
            child = self.launch("matrix", provider=self.recorder, ready=ready, go=go,
                                stdout=full)
            self.wait_ready(child, ready)
            go.touch()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                state = Path(f"/proc/{child.pid}/status").read_text().split(
                    "State:", 1)[1].lstrip()[0]
                if state == "T":
                    break
                time.sleep(0.01)
            self.assertEqual(state, "T")
            os.kill(child.pid, signal.SIGCONT)
            _stdout, stderr = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, stderr)

    def test_completed_matrix_refuses_stale_alias_and_late_done_without_provider_calls(self):
        stale = self.case_dir / "stale"
        stale.write_text("unrelated", encoding="ascii")
        cases = []
        for stale_index in range(4):
            paths = [self.case_dir / f"stale-{stale_index}-{name}"
                     for name in ("ready", "go", "done", "finish")]
            paths[stale_index] = stale
            cases.append(tuple(paths))
        for first in range(4):
            for second in range(first + 1, 4):
                paths = [self.case_dir / f"alias-{first}-{second}-{name}"
                         for name in ("ready", "go", "done", "finish")]
                paths[first] = self.case_dir / f"shared-{first}-{second}"
                paths[second] = f"{self.case_dir}/./shared-{first}-{second}"
                cases.append(tuple(paths))
        stale_directory = self.case_dir / "stale-directory"
        stale_directory.mkdir()
        dangling = self.case_dir / "dangling"
        dangling.symlink_to(self.case_dir / "absent-target")
        cases.extend([
            (self.case_dir / "dir-ready", self.case_dir / "dir-go",
             stale_directory, self.case_dir / "dir-finish"),
            (self.case_dir / "link-ready", self.case_dir / "link-go",
             dangling, self.case_dir / "link-finish"),
        ])
        for index, paths in enumerate(cases):
            with self.subTest(index=index):
                read_fd, write_fd = os.pipe()
                os.set_blocking(read_fd, False)
                env = dict(os.environ, P11SCOPE_TEST_RECORDER_FD=str(write_fd))
                command = [str(self.workload), str(self.recorder), "matrix", *map(str, paths)]
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                        env=env, pass_fds=(write_fd,), timeout=3, check=False)
                os.close(write_fd)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(os.read(read_fd, 1), b"")
                os.close(read_fd)
                self.assertEqual(stale.read_text(encoding="ascii"), "unrelated")
                self.assertTrue(stale_directory.is_dir())
                self.assertTrue(dangling.is_symlink())
        ready, go, done, finish = self.matrix_paths("late")
        child = self.launch("matrix", provider=self.recorder, ready=ready, go=go,
                            done=done, finish=finish)
        self.wait_ready(child, ready)
        done.write_text("late-unrelated", encoding="ascii")
        go.touch()
        stdout, stderr = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0, stdout)
        self.assertEqual(done.read_text(encoding="ascii"), "late-unrelated")
        self.assert_no_publication_temporaries()

        ready, go, done, finish = self.matrix_paths("bad-parent")
        done = self.case_dir / "missing" / "done"
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        env = dict(os.environ, P11SCOPE_TEST_RECORDER_FD=str(write_fd))
        child = self.launch("matrix", provider=self.recorder, ready=ready, go=go,
                            done=done, finish=finish, env=env, pass_fds=(write_fd,))
        os.close(write_fd)
        ready_bytes = self.wait_ready(child, ready)
        go.touch()
        stdout, stderr = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0, stdout)
        self.assertEqual(len(os.read(read_fd, 4096)), 25)
        os.close(read_fd)
        self.assertEqual(ready.read_bytes(), ready_bytes)
        self.assertFalse(done.exists())
        self.assert_no_publication_temporaries()

    def test_completed_matrix_finish_timeout_is_nonpass_and_retains_diagnostics(self):
        for late_finish in (False, True):
            with self.subTest(late_finish=late_finish):
                prefix = f"timeout-{int(late_finish)}"
                done_path = self.matrix_paths(prefix)[2]
                finish_path = self.matrix_paths(prefix)[3]
                env_extra = {"P11SCOPE_TEST_FINISH_TIMEOUT_DONE": str(done_path)}
                if late_finish:
                    env_extra["P11SCOPE_TEST_CREATE_LATE_FINISH"] = str(finish_path)
                child, read_fd, interface_fd, (ready, go, done, finish) = \
                    self.launch_recorded_matrix(executable=self.clock_wrapped_workload,
                                                env_extra=env_extra, prefix=prefix)
                ready_bytes = self.wait_ready(child, ready)
                go.touch()
                done_bytes = self.wait_path(child, done, "DONE")
                try:
                    stdout, stderr = child.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    finish.touch(exist_ok=True)
                    stdout, stderr = child.communicate(timeout=3)
                self.assertNotEqual(child.returncode, 0, stdout)
                self.assertIn("timed out waiting for FINISH", stderr)
                self.assertEqual(finish.exists(), late_finish)
                self.assertEqual(ready.read_bytes(), ready_bytes)
                self.assertEqual(done.read_bytes(), done_bytes)
                self.assertEqual(len(os.read(read_fd, 4096)), 25)
                self.assertEqual(os.read(interface_fd, 4096), b"III")
                os.close(read_fd)
                os.close(interface_fd)
                self.assert_no_publication_temporaries()

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
            [str(self.workload), str(self.provider), "blocked", "ready", "go", "done", "finish"],
            [str(self.workload), str(self.provider), "matrix", "ready", "go", "done", "finish", "extra"],
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
