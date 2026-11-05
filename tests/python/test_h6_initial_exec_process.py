#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ordinary-uid raw-fork/ptrace controls; no p11scope or privileged lane."""

from contextlib import contextmanager
import ctypes
import errno
import gc
import json
import os
from pathlib import Path
import runpy
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/h6-initial-exec.py"


class Pin:
    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC)
        self.initial = os.fstat(self.fd)

    def verify(self):
        actual = os.fstat(self.fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(actual, field) != getattr(self.initial, field) for field in fields):
            raise ValueError("fixture pin changed")

    def close(self):
        os.close(self.fd)


class InitialExecProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = runpy.run_path(str(SCRIPT)) if SCRIPT.exists() else {}
        cls.temporary = tempfile.TemporaryDirectory(prefix="h6-initial-exec-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = cls.directory / "caller.c"
        source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 91;
    FILE *marker = fopen(argv[1], "wx");
    if (!marker) return 92;
    fputs("main entered\n", marker);
    fclose(marker);
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 93;
    printf("ENTRY %d %lld\n", getpid(), (long long)now.tv_sec * 1000000000 + now.tv_nsec);
    fflush(stdout);
    char byte;
    return read(0, &byte, 1) == 1 && byte == 'Q' ? 0 : 94;
}
''')
        cls.caller_path = cls.directory / "caller"
        result = subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(source),
                                 "-o", str(cls.caller_path)], capture_output=True,
                                text=True, timeout=20)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.caller_pin = Pin(cls.caller_path)
        cls.addClassCleanup(cls.caller_pin.close)
        cls.setarch_pin = Pin(shutil.which("setarch"))
        cls.addClassCleanup(cls.setarch_pin.close)

    def setUp(self):
        self.owners = []
        self.marker = self.directory / self._testMethodName
        self.before_fds = set(os.listdir("/proc/self/fd"))
        self.addCleanup(self.cleanup_owners)

    def cleanup_owners(self):
        for owner in self.owners:
            owner.close()
            self.assertFalse(Path(f"/proc/{owner.pid}").exists())
            with self.assertRaises(ChildProcessError):
                os.waitpid(owner.pid, os.WNOHANG)
        self.assertEqual(set(os.listdir("/proc/self/fd")), self.before_fds)

    def spawn(self, seconds=2, **kwargs):
        self.assertIn("_spawn_initial_exec", self.module,
                      "the owned initial-exec process primitive is missing")
        options = dict(caller_pin=self.caller_pin, setarch_pin=self.setarch_pin,
                       uid=os.getuid(), gid=os.getgid(), env=dict(os.environ),
                       deadline_ns=time.monotonic_ns() + int(seconds * 1e9),
                       supplementary_groups=tuple(os.getgroups()))
        options.update(kwargs)
        return self.module["_spawn_initial_exec"](
            self.owners, [str(options["caller_pin"].path), str(self.marker)], **options)

    def finish(self, owner):
        self.assertTrue(select.select([owner.popen.stdout], [], [], 1)[0])
        fields = owner.popen.stdout.readline().split()
        self.assertEqual(fields[:2], ["ENTRY", str(owner.pid)])
        owner.popen.stdin.write("Q")
        owner.popen.stdin.flush()
        self.assertEqual(owner.popen.wait(timeout=1), 0)
        return int(fields[2])

    def test_real_dynamic_caller_cannot_enter_main_before_checked_exec_stop(self):
        owner = self.spawn()
        self.assertFalse(self.marker.exists())
        proof = owner.hold_caller_exec()
        self.assertFalse(self.marker.exists())
        self.assertFalse(select.select([owner.popen.stdout], [], [], 0)[0])
        self.assertEqual(proof["path"], str(self.caller_path))
        self.assertEqual(proof["pid"], owner.pid)
        self.assertEqual(proof["start_time"], owner.identity["start_time"])
        self.assertEqual(proof["personality"] & 0x40000, 0x40000)
        self.assertEqual(proof["exec_events"], 2)
        self.assertNotIn("kind", proof)
        with self.assertRaises(RuntimeError):
            owner.popen.poll()
        with self.assertRaises(RuntimeError):
            owner.popen.wait(timeout=0)
        detached = owner.resume_detach()
        entered_ns = self.finish(owner)
        self.assertTrue(self.marker.exists())
        self.assertLessEqual(detached["detach_entry_ns"], entered_ns)
        self.assertLessEqual(detached["detach_entry_ns"], detached["detach_return_ns"])

    def test_single_os_task_guard_prevents_fork_with_a_reader_thread(self):
        blocked = threading.Event()
        thread = threading.Thread(target=lambda: blocked.wait(2))
        thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "single.*task|one.*task"):
                self.spawn()
            self.assertEqual(self.owners, [])
        finally:
            blocked.set()
            thread.join()

    def test_inherited_python_profile_callback_prevents_raw_fork(self):
        previous = sys.getprofile()
        sys.setprofile(lambda *_args: None)
        try:
            with self.assertRaisesRegex(RuntimeError, "uninstrumented"):
                self.spawn()
            self.assertEqual(self.owners, [])
        finally:
            sys.setprofile(previous)

    def test_child_cyclic_gc_is_disabled_and_parent_state_is_restored(self):
        globals_ = self.module["_spawn_initial_exec"].__globals__
        real = globals_["_child"]
        previous = gc.isenabled()

        def reject_child_gc_callbacks(plan):
            if gc.isenabled():
                globals_["_child_fail"](plan, 13, 95)
            real(plan)

        gc.enable()
        try:
            with mock.patch.dict(globals_, _child=reject_child_gc_callbacks):
                try:
                    owner = self.spawn()
                except OSError as error:
                    if error.errno != 95:
                        raise
                    self.fail("raw child can still invoke inherited cyclic GC callbacks")
            self.assertTrue(gc.isenabled())
            owner.hold_caller_exec()
            owner.resume_detach()
            self.finish(owner)
        finally:
            if not previous:
                gc.disable()

    def test_expired_deadline_does_not_create_a_child(self):
        with self.assertRaises(TimeoutError):
            self.spawn(deadline_ns=time.monotonic_ns() - 1)
        self.assertEqual(self.owners, [])

    def test_pidfd_failure_retains_raw_child_custody_and_reaps(self):
        with mock.patch.object(os, "pidfd_open", side_effect=OSError(24, "injected pidfd failure")):
            with self.assertRaises(OSError):
                self.spawn()
        self.assertEqual(len(self.owners), 1)
        self.assertTrue(self.owners[0].reaped)
        self.assertFalse(self.marker.exists())

    def test_adapter_creation_failure_still_reaps_the_enrolled_raw_child(self):
        globals_ = self.module["_spawn_initial_exec"].__globals__
        with mock.patch.dict(globals_, _Process=mock.Mock(side_effect=MemoryError("adapter failure"))):
            with self.assertRaises(MemoryError):
                self.spawn()
        self.assertEqual(len(self.owners), 1)
        self.assertTrue(self.owners[0].reaped)
        self.assertFalse(self.marker.exists())

    def test_pipe_creation_failure_closes_every_pre_fork_descriptor(self):
        before = set(os.listdir("/proc/self/fd"))
        real = os.pipe2
        calls = 0

        def fail_third(flags):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError(24, "injected pipe failure")
            return real(flags)

        with mock.patch.object(os, "pipe2", side_effect=fail_third):
            with self.assertRaises(OSError):
                self.spawn()
        self.assertEqual(self.owners, [])
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_stream_open_failure_closes_pipes_and_reaps(self):
        before = set(os.listdir("/proc/self/fd"))
        real = os.fdopen
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(24, "injected fdopen failure")
            return real(*args, **kwargs)

        with mock.patch.object(os, "fdopen", side_effect=fail_second):
            with self.assertRaises(OSError):
                self.spawn()
        self.assertTrue(self.owners[0].reaped)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_close_failure_still_reaps_and_closes_the_other_owned_fds(self):
        owner = self.spawn()
        failed_fd = owner.birth_fd
        other_fd = owner.ack_fd
        real = os.close

        def fail_one(fd):
            if fd == failed_fd:
                real(fd)  # Linux releases the number even on a late close error
                raise OSError(5, "injected close failure")
            return real(fd)

        with mock.patch.object(os, "close", side_effect=fail_one):
            with self.assertRaises(OSError):
                owner.close()
        self.assertTrue(owner.reaped)
        self.assertIsNone(owner.pidfd)
        self.assertEqual(owner.fds, set())
        with self.assertRaises(OSError):
            os.fstat(other_fd)
        with self.assertRaises(OSError):
            os.fstat(failed_fd)

    def test_seize_failure_closes_pipes_and_reaps_without_main(self):
        owner = self.spawn()
        globals_ = owner.hold_caller_exec.__globals__
        with mock.patch.dict(globals_, _ptrace=mock.Mock(side_effect=PermissionError(1, "seize denied"))):
            with self.assertRaises(PermissionError):
                owner.hold_caller_exec()
        self.assertTrue(owner.reaped)
        self.assertIsNone(owner.pidfd)
        self.assertFalse(self.marker.exists())

    def test_birth_pipe_eof_is_terminal_without_entering_main(self):
        owner = self.spawn()
        owner._close_fd(owner.birth_fd)
        with self.assertRaises(OSError):
            owner.hold_caller_exec()
        self.assertTrue(owner.reaped)
        self.assertFalse(self.marker.exists())

    def test_credential_acknowledgement_eof_reaps(self):
        globals_ = self.module["_spawn_initial_exec"].__globals__

        def exit_without_ack(plan):
            globals_["_SYSCALL"](*plan["exit"])

        with mock.patch.dict(globals_, _child=exit_without_ack):
            with self.assertRaises(EOFError):
                self.spawn()
        self.assertTrue(self.owners[0].reaped)
        self.assertFalse(self.marker.exists())

    def test_production_factory_refuses_nonempty_inherited_groups(self):
        if os.geteuid() == 0 or not os.getgroups():
            self.skipTest("this refusal control requires an ordinary uid with inherited groups")
        with self.assertRaises(PermissionError):
            self.module["spawn_initial_exec"](
                self.owners, [str(self.caller_path), str(self.marker)],
                caller_pin=self.caller_pin, setarch_pin=self.setarch_pin,
                uid=os.getuid(), gid=os.getgid(), env=dict(os.environ),
                deadline_ns=time.monotonic_ns() + 1_000_000_000)
        self.assertTrue(self.owners[0].reaped)
        self.assertFalse(self.marker.exists())

    def test_original_deadline_bounds_both_exec_waits_and_reap(self):
        deadline = time.monotonic_ns() + 150_000_000
        owner = self.spawn(deadline_ns=deadline)
        globals_ = owner.hold_caller_exec.__globals__
        real = globals_["_ptrace"]

        def retain_setarch_stop(request, pid, data=0):
            if request != 7:
                return real(request, pid, data)

        with mock.patch.dict(globals_, _ptrace=retain_setarch_stop):
            with self.assertRaises(TimeoutError):
                owner.hold_caller_exec()
        self.assertEqual(owner.deadline_ns, deadline)
        self.assertGreaterEqual(time.monotonic_ns(), deadline)
        self.assertLess(time.monotonic_ns() - deadline, 500_000_000)
        self.assertTrue(owner.reaped)
        self.assertFalse(self.marker.exists())

    def test_expired_held_caller_is_killed_instead_of_detached(self):
        owner = self.spawn(seconds=0.15)
        owner.hold_caller_exec()
        time.sleep(0.16)
        with self.assertRaises(TimeoutError):
            owner.resume_detach()
        self.assertFalse(owner.detached)
        self.assertTrue(owner.reaped)
        self.assertFalse(self.marker.exists())

    def test_cancellation_while_traced_reaps_without_poll_or_stdin(self):
        class Cancelled(BaseException):
            pass

        owner = self.spawn()
        globals_ = owner.hold_caller_exec.__globals__
        real = globals_["_ptrace"]

        def cancel_at_setarch(request, pid, data=0):
            if request == 7:
                raise Cancelled()
            return real(request, pid, data)

        with mock.patch.dict(globals_, _ptrace=cancel_at_setarch):
            with self.assertRaises(Cancelled):
                owner.hold_caller_exec()
        self.assertTrue(owner.reaped)
        self.assertEqual(owner.popen.returncode, -signal.SIGKILL)
        self.assertFalse(self.marker.exists())

    def test_original_birth_namespace_credentials_and_session_mismatches_fail_closed(self):
        for field in ("start_time", "pid_namespace", "time_namespace", "mount_namespace",
                      "ppid", "uid", "gid", "session", "pgrp"):
            with self.subTest(field=field):
                owner = self.spawn()
                owner.identity[field] += 1
                with self.assertRaises(ValueError):
                    owner.hold_caller_exec()
                self.assertTrue(owner.reaped)
                self.assertFalse(self.marker.exists())

    def test_unrelated_inherited_fd_is_closed_before_birth_acknowledgement(self):
        path = self.directory / (self._testMethodName + ".fd")
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.set_inheritable(fd, True)
            owner = self.spawn()
            self.assertFalse(Path(f"/proc/{owner.pid}/fd/{fd}").exists())
            os.fstat(fd)  # the ordinary parent still owns its descriptor
        finally:
            os.close(fd)

    def test_child_fd_close_failure_prevents_exec_and_reaps(self):
        path = self.directory / (self._testMethodName + ".fd")
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        globals_ = self.module["_spawn_initial_exec"].__globals__
        real = globals_["_SYSCALL"]

        def deny_one_child_close(*args):
            if args[0].value == 3 and args[1].value == fd:
                ctypes.set_errno(errno.EPERM)
                return -1
            return real(*args)

        try:
            with mock.patch.dict(globals_, _SYSCALL=deny_one_child_close):
                with self.assertRaises(PermissionError):
                    self.spawn()
            self.assertTrue(self.owners[0].reaped)
            self.assertFalse(self.marker.exists())
        finally:
            os.close(fd)

    def test_stopped_executable_must_match_the_independently_held_fd(self):
        replacement = self.directory / (self._testMethodName + ".exe")
        shutil.copy2(self.caller_path, replacement)
        pin = Pin(replacement)
        try:
            owner = self.spawn()
            owner.caller_pin = pin
            with self.assertRaisesRegex(ValueError, "stopped executable"):
                owner.hold_caller_exec()
            self.assertTrue(owner.reaped)
            self.assertFalse(self.marker.exists())
        finally:
            pin.close()

    def test_actual_caller_personality_mismatch_fails_closed(self):
        self.assertFalse(int(Path("/proc/self/personality").read_text(), 16) & 0x40000)
        source = self.directory / (self._testMethodName + ".c")
        launcher = self.directory / (self._testMethodName + ".exe")
        source.write_text('#include <unistd.h>\n'
                          'int main(int argc, char **argv) {\n'
                          '  if (argc < 3) return 95;\n'
                          '  execv(argv[2], &argv[2]); return 96;\n}\n')
        result = subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(source),
                                 "-o", str(launcher)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        pin = Pin(launcher)
        try:
            owner = self.spawn(setarch_pin=pin)
            with self.assertRaisesRegex(ValueError, "ADDR_NO_RANDOMIZE"):
                owner.hold_caller_exec()
            self.assertTrue(owner.reaped)
            self.assertFalse(self.marker.exists())
        finally:
            pin.close()

    def test_deferred_real_signal_cannot_escape_before_child_enrollment(self):
        class Cancelled(BaseException):
            pass

        pending = raised = False
        depth = 0

        def handle(_signum, _frame):
            nonlocal pending
            pending = True

        @contextmanager
        def defer():
            nonlocal depth, raised
            depth += 1
            try:
                yield
            finally:
                depth -= 1
                if pending and not raised and depth == 0:
                    raised = True
                    raise Cancelled()

        real = os.pidfd_open

        def signal_after_raw_pid(pid, *args):
            fd = real(pid, *args)
            os.kill(os.getpid(), signal.SIGTERM)
            return fd

        previous = signal.signal(signal.SIGTERM, handle)
        try:
            with mock.patch.object(os, "pidfd_open", side_effect=signal_after_raw_pid):
                with self.assertRaises(Cancelled):
                    self.spawn(cleanup_section=defer)
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.assertEqual(len(self.owners), 1)
        self.assertTrue(self.owners[0].reaped)
        self.assertFalse(self.marker.exists())

    def supervisor_death(self, mode):
        # Subreaping is an ordinary process-local fixture operation. Adopt and
        # terminally reap this test's orphan; do not depend on host init timing.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        code = r'''
import json, os, runpy, sys
module = runpy.run_path(sys.argv[1])
Pin = runpy.run_path(sys.argv[2])["Pin"]
caller, setarch = Pin(sys.argv[3]), Pin(sys.argv[4])
owners = []
owner = module["_spawn_initial_exec"](
    owners, [str(caller.path), sys.argv[5]], caller_pin=caller, setarch_pin=setarch,
    uid=os.getuid(), gid=os.getgid(), supplementary_groups=tuple(os.getgroups()),
    env=dict(os.environ), deadline_ns=__import__("time").monotonic_ns() + 5_000_000_000)
if sys.argv[6] == "held":
    owner.hold_caller_exec()
print(json.dumps({"pid": owner.pid}), flush=True)
sys.stdin.read(1)
owner.close()
'''
        supervisor = None
        parent_fd = child_fd = child = None
        reaped = False
        try:
            supervisor = subprocess.Popen(
                [sys.executable, "-I", "-c", code, str(SCRIPT), str(Path(__file__).resolve()),
                 str(self.caller_path), str(self.setarch_pin.path), str(self.marker), mode],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            parent_fd = os.pidfd_open(supervisor.pid)
            self.assertTrue(select.select([supervisor.stdout], [], [], 2)[0])
            line = supervisor.stdout.readline()
            self.assertTrue(line, supervisor.stderr.read() if supervisor.poll() is not None else "missing PID")
            child = json.loads(line)["pid"]
            child_fd = os.pidfd_open(child)
            self.assertFalse(self.marker.exists())
            signal.pidfd_send_signal(parent_fd, signal.SIGKILL)
            self.assertEqual(supervisor.wait(timeout=2), -signal.SIGKILL)
            self.assertTrue(select.select([child_fd], [], [], 2)[0], "owned child survived tracer/parent")
            pid, status = os.waitpid(child, 0)
            reaped = True
            self.assertEqual(pid, child)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            self.assertFalse(Path(f"/proc/{child}").exists())
            self.assertFalse(self.marker.exists())
        finally:
            if supervisor is not None:
                if supervisor.poll() is None:
                    supervisor.kill()
                supervisor.wait(timeout=2)
                for stream in (supervisor.stdin, supervisor.stdout, supervisor.stderr):
                    stream.close()
            if child_fd is not None:
                if not reaped:
                    try:
                        signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(child, 0)
                os.close(child_fd)
            if parent_fd is not None:
                os.close(parent_fd)
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_tracer_death_kills_and_reaps_the_held_caller(self):
        self.supervisor_death("held")

    def test_parent_death_kills_and_reaps_the_birth_blocked_child(self):
        self.supervisor_death("birth")


if __name__ == "__main__":
    unittest.main()
