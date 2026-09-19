# SPDX-License-Identifier: GPL-3.0-or-later
"""Native real-helper tests with authenticated pidfd custody and bounded teardown."""

import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/root-recorded-launcher"
HELPER = ROOT / "scripts/recorded-process-exec.py"


class RecordedLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Own orphaned fixture children when deliberately interrupting a shell.
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.old_subreaper = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.old_subreaper), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER")
        if cls.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")

    @classmethod
    def tearDownClass(cls):
        cls.libc.prctl(36, cls.old_subreaper.value, 0, 0, 0)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="recorded-launcher-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.bin = self.work / "bin"
        self.bin.mkdir(mode=0o700)
        shutil.copyfile(FIXTURES / "sudo", self.bin / "sudo")
        (self.bin / "sudo").chmod(0o700)
        self.env = dict(os.environ, CASE_DIR=str(self.work), PATH=f"{self.bin}:{os.environ['PATH']}",
                        REAL_PYTHON=shutil.which("python3"), FIXTURE_DIR=str(FIXTURES))
        self.adopted = {}
        self.adopt_none_reasons = {}
        self.direct_children = []
        # Final subreaper drain follows all registered direct-parent and
        # published-record cleanup, before temporary evidence is removed.
        self.addCleanup(self.drain_owned_children)
        # Runs after direct-parent cleanup: orphaned fixtures are then ours to
        # reap with P_PIDFD, while already-reaped originals simply give ECHILD.
        self.addCleanup(self.cleanup_adopted)
        self.shim()

    def child(self, argv, **kwargs):
        proc = subprocess.Popen(argv, cwd=ROOT, env=self.env, **kwargs)
        self.direct_children.append(proc)
        fd = None
        cleaned = False

        def cleanup():
            nonlocal cleaned
            if cleaned:
                return
            try:
                if fd is None:
                    # Only the synchronous acquisition-failure path can enter
                    # here: this direct Popen child has not been exposed,
                    # polled, or reaped. Popen.kill checks its owned status.
                    proc.kill()
                else:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.wait(timeout=5)
            finally:
                cleaned = True
                if fd is not None:
                    os.close(fd)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream:
                        stream.close()

        self.addCleanup(cleanup)
        try:
            fd = os.pidfd_open(proc.pid)
        except OSError as acquisition_error:
            try:
                cleanup()
            except BaseException as cleanup_error:
                raise RuntimeError(f"pidfd acquisition failed: {acquisition_error}; "
                                   f"owned child cleanup unresolved: {cleanup_error}") from acquisition_error
            raise
        return proc, fd

    def driver(self, *args, input=b""):
        proc, _ = self.child(["sh", str(FIXTURES / "driver.sh"), *map(str, args)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input, timeout=20)
        return proc.returncode, out, err

    @staticmethod
    def generation(pid):
        return int(Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19])

    def adopt(self, pid, starttime):
        self.assertTrue(type(pid) is int and pid > 0)
        self.assertTrue(type(starttime) is int and starttime > 0)
        identity = (pid, starttime)
        if identity in self.adopted:
            return self.adopted[identity]
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            self.adopt_none_reasons[identity] = "pidfd-open-gone"
            return
        try:
            try:
                actual = self.generation(pid)
            except (FileNotFoundError, ProcessLookupError):
                self.adopt_none_reasons[identity] = "generation-read-gone"
                return
            if actual != starttime:
                self.adopt_none_reasons[identity] = (
                    f"generation-mismatch expected={starttime} actual={actual}"
                )
                return
            self.adopted[identity] = fd
            self.adopt_none_reasons.pop(identity, None)
        finally:
            if identity not in self.adopted:
                os.close(fd)
        return fd

    @staticmethod
    def diagnostic_file(label, path, limit=4096):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return f"{label}=<missing>"
        except OSError as error:
            return f"{label}=<unreadable {type(error).__name__} errno={error.errno}>"
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return f"{label}=<unreadable non-regular mode={stat.S_IFMT(info.st_mode):#o}>"
            raw = os.read(fd, limit + 1)
            truncated = info.st_size > limit or len(raw) > limit
            rendered = repr(raw[:limit].decode("utf-8", errors="backslashreplace"))
            if truncated:
                rendered += f"<truncated size={info.st_size} limit={limit}>"
            return f"{label}={rendered}"
        except OSError as error:
            return f"{label}=<unreadable {type(error).__name__} errno={error.errno}>"
        finally:
            os.close(fd)

    @staticmethod
    def direct_parent_status(parent_fd):
        try:
            status = os.waitid(os.P_PIDFD, parent_fd,
                               os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except BaseException as error:
            return f"unavailable {type(error).__name__}: {error}"
        if status is None:
            return "running"
        return (f"exited pid={status.si_pid} code={status.si_code} "
                f"status={status.si_status}")

    @staticmethod
    def bounded_repr(value, limit=4096):
        rendered = repr(value)
        if len(rendered) <= limit:
            return rendered
        return rendered[:limit] + f"<truncated repr limit={limit}>"

    def adopt_none_diagnostic(self, identity, snapshot, parent_fd):
        now = time.monotonic_ns()
        try:
            context = json.loads(snapshot["ROOT_RECORD_IDENTITY"])
            deadline = context["deadline"]
        except BaseException as error:
            deadline = f"<unreadable {type(error).__name__}: {error}>"
        parts = [
            f"adopt returned None: authenticated_identity={identity}",
            f"reason={self.adopt_none_reasons.get(identity, '<unrecorded>')}",
            f"context_deadline_ns={deadline}",
            f"monotonic_ns={now}",
            f"published_snapshot={self.bounded_repr(snapshot)}",
            self.diagnostic_file("snapshot-file", self.work / "snapshot.json"),
            self.diagnostic_file("hook-marker", self.work / "hook.waiting"),
            self.diagnostic_file("split-stderr", self.work / "stderr space's.log"),
            f"direct-parent-status={self.direct_parent_status(parent_fd)}",
        ]
        return "; ".join(parts)

    def assert_adopted(self, identity, snapshot, parent_fd):
        fd = self.adopt(*identity)
        diagnostic = None
        if fd is None:
            diagnostic = self.adopt_none_diagnostic(identity, snapshot, parent_fd)
        self.assertIsNotNone(fd, diagnostic)
        return fd

    def cleanup_adopted(self):
        errors = []
        reaped = []
        # Recover custody even if a test failed before explicit adoption, or
        # communicate raised. These are original fixture SELF tuples, never
        # expected generations manufactured by sampling a late bare PID.
        for path in self.work.glob(".owned-*.json"):
            try:
                record = json.loads(path.read_text())
                self.adopt(record["pid"], record["starttime"])
            except BaseException as error:
                errors.append(f"{path.name}: {error}")
        for identity, fd in list(self.adopted.items()):
            try:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.assertTrue(select.select([fd], [], [], 5)[0], f"fixture {identity} failed to exit")
                try:
                    result = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if result is not None:
                        reaped.append(identity)
                except ChildProcessError:
                    # Its original parent already reaped it. P_PIDFD cannot
                    # consume another generation's status, even after reuse.
                    pass
            except BaseException as error:
                errors.append(f"{identity}: {error}")
            finally:
                os.close(fd)
                del self.adopted[identity]
        self.assertFalse(errors, "unresolved fixture custody: " + "; ".join(errors))
        return reaped

    def owned_child_census(self):
        raw = Path(f"/proc/self/task/{os.getpid()}/children").read_text()
        children = [int(value) for value in raw.split()]
        self.assertTrue(all(pid > 0 for pid in children), "invalid owned-child census")
        self.assertEqual(len(children), len(set(children)), "duplicate owned-child census")
        return children

    def owned_child_identity(self, pid):
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        self.assertEqual(int(raw.split(b" ", 1)[0]), pid)
        tail = raw.rsplit(b") ", 1)[1].split()
        parent, generation = int(tail[1]), int(tail[19])
        self.assertEqual(parent, os.getpid(), "candidate is no longer our direct child")
        self.assertGreater(generation, 0, "invalid owned-child generation")
        return pid, generation

    def drain_owned_children(self):
        # This is only the single-threaded test process's final subreaper
        # scope. No arbitrary PID/group census, new Popen, concurrent waiter,
        # or reap can invalidate candidates between census and acquisition.
        self.assertTrue(all(proc.returncode is not None for proc in self.direct_children),
                        "direct fixture parents must be ended/reaped before orphan drain")
        self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL,
                         "orphan drain requires normal unreaped-child ownership")
        self.assertEqual(len(list(Path("/proc/self/task").iterdir())), 1,
                         "orphan drain requires a single-threaded owner")
        deadline = time.monotonic() + 5
        reaped = []
        while True:
            self.assertLess(time.monotonic(), deadline, "owned-child drain deadline expired")
            children = self.owned_child_census()
            if not children:
                return reaped
            pinned = []
            try:
                # Acquire the entire current wave before any reap. Direct
                # unreaped-child ownership prevents PID reuse in this window;
                # pidfd + PPID + WNOWAIT establish the actual owned generation.
                for pid in children:
                    self.assertLess(time.monotonic(), deadline, "owned-child acquisition deadline")
                    fd = os.pidfd_open(pid)
                    try:
                        identity = self.owned_child_identity(pid)
                        status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if status is not None:
                            self.assertEqual(status.si_pid, pid)
                        self.assertEqual(self.owned_child_identity(pid), identity,
                                         "owned-child identity changed before use")
                    except BaseException:
                        os.close(fd)
                        raise
                    pinned.append((identity, fd))
                for _, fd in pinned:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for identity, fd in pinned:
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0, "owned-child reap deadline expired")
                    self.assertTrue(select.select([fd], [], [], remaining)[0],
                                    f"owned child {identity} failed to end")
                    status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    self.assertIsNotNone(status, f"owned child {identity} was not reaped")
                    self.assertEqual(status.si_pid, identity[0])
                    reaped.append(identity)
            finally:
                for _, fd in pinned:
                    os.close(fd)
            # Reaping an adopted parent can expose another owned wave. Only
            # an empty census after the completed waits establishes drainage.

    def wait_path(self, path, timeout=3):
        deadline = time.monotonic() + timeout
        while not path.exists():
            self.assertLess(time.monotonic(), deadline, f"missing fixture boundary {path}")
            time.sleep(0.01)
        return path

    def self_record(self, context, phase, proc):
        path = Path(json.loads(context)["path"]) / (phase + ".self")
        record = json.loads(self.wait_path(path).read_text())
        self.assertEqual(record["pid"], proc.pid)
        return record

    def shim(self):
        shutil.copyfile(FIXTURES / "python3", self.bin / "python3")
        (self.bin / "python3").chmod(0o700)

    def native(self, *args, check=True):
        result = subprocess.run(["python3", "-I", str(HELPER), *map(str, args)],
                                cwd=ROOT, env=self.env, capture_output=True, timeout=12)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def context(self, timeout=2):
        self.assertTrue(HELPER.is_file(), "native SELF/ACK helper is missing")
        lines = self.native("prepare", self.work / "process.pid", timeout).stdout.splitlines()
        context = lines[1].decode()
        self.bind_context(context)
        return context

    def bind_context(self, context, pid=None, starttime=None, check=True):
        pid = os.getpid() if pid is None else pid
        starttime = self.generation(pid) if starttime is None else starttime
        return self.native("bind-coordinator", context, pid, starttime, check=check)

    def test_bind_coordinator_rejects_mismatched_parent_generation_and_owner(self):
        for case in ("parent", "generation", "owner"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.work) as work:
                context = self.native("prepare", Path(work) / "pid", 2).stdout.splitlines()[1].decode()
                if case == "parent":
                    result = self.bind_context(context, pid=os.getpid() + 1, starttime=1, check=False)
                elif case == "generation":
                    result = self.bind_context(context, starttime=self.generation(os.getpid()) + 1,
                                               check=False)
                else:
                    changed = json.loads(context)
                    changed["owner"] += 1
                    result = self.bind_context(json.dumps(changed, separators=(",", ":")), check=False)
                self.assertNotEqual(result.returncode, 0)
                control = Path(json.loads(context)["path"])
                self.assertFalse((control / "coordinator").exists())
                self.native("cleanup", context)
                self.assertFalse(control.exists())

    def test_coordinator_record_missing_malformed_and_replaced_refuse_promptly(self):
        for case in ("missing", "malformed", "replaced", "zombie"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.work) as work:
                context = self.native("prepare", Path(work) / "pid", 8).stdout.splitlines()[1].decode()
                control = Path(json.loads(context)["path"])
                coordinator = control / "coordinator"
                if case == "malformed":
                    coordinator.write_text('{"pid":')
                    coordinator.chmod(0o600)
                elif case in ("replaced", "zombie"):
                    self.bind_context(context)
                    record = json.loads(coordinator.read_text())
                    if case == "replaced":
                        record["starttime"] += 1
                    else:
                        zombie, zombie_fd = self.child(["sleep", "0.1"])
                        record["pid"] = zombie.pid
                        record["starttime"] = self.generation(zombie.pid)
                        self.assertTrue(select.select([zombie_fd], [], [], 3)[0])
                        state = Path(f"/proc/{zombie.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[0]
                        self.assertEqual(state, b"Z")
                    coordinator.write_text(json.dumps(record, separators=(",", ":")) + "\n")
                started = time.monotonic()
                proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                                      "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
                self.assertNotEqual(proc.wait(timeout=3), 0)
                self.assertLess(time.monotonic() - started, 3, "coordinator refusal was not prompt")
                self.assertFalse((self.work / "target.entered").exists())

    def test_direct_subshell_binding_preserves_state_and_dead_coordinator_refuses_promptly(self):
        context = self.native("prepare", self.work / "process.pid", 8).stdout.splitlines()[1].decode()
        environment = dict(self.env, BIND_CONTEXT=context)
        script = r'''
. scripts/lib.sh
set -- "left arg" "" right
IFS=:
(
    recorded_process_coordinator_identity || exit 31
    [ "$#" -eq 3 ] && [ "$1" = "left arg" ] && [ -z "$2" ] && [ "$3" = right ] || exit 32
    [ "$IFS" = : ] || exit 33
    recorded_process_control bind-coordinator "$BIND_CONTEXT" \
        "$RECORDED_COORDINATOR_PID" "$RECORDED_COORDINATOR_STARTTIME" || exit 34
    [ "$#" -eq 3 ] && [ "$1" = "left arg" ] && [ -z "$2" ] && [ "$3" = right ] || exit 35
    [ "$IFS" = : ] || exit 36
)
'''
        binder = subprocess.run(["sh", "-c", script], cwd=ROOT, env=environment,
                                capture_output=True, timeout=3)
        self.assertEqual(binder.returncode, 0, binder.stderr.decode())
        record = json.loads((Path(json.loads(context)["path"]) / "coordinator").read_text())
        coordinator_state = self.native("active", record["pid"], record["starttime"], check=False)
        self.assertNotEqual(coordinator_state.returncode, 0, "subshell coordinator unexpectedly live")
        started = time.monotonic()
        proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                              "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertLess(time.monotonic() - started, 3, "dead coordinator refusal was not prompt")
        self.assertFalse((self.work / "target.entered").exists())
        self.native("cleanup", context)

    def test_root_two_barriers_preserve_identity_argv_stdin_and_status(self):
        args = ["space arg", "", "$(no-evaluation);*", "tail"]
        rc, _, err = self.driver("root", "sh", FIXTURES / "target.sh", *args, input=b"stdin survives\n")
        self.assertEqual(rc, 23, err.decode())
        fields = (self.work / "fields").read_text().splitlines()
        pid, start = (self.work / "process.pid").read_text().split()
        self.assertEqual(fields[:4], [pid, start, pid, start])
        self.assertEqual(fields[4], "committed")
        self.assertEqual((self.work / "target.entered").read_text().strip(), pid)
        self.assertEqual((self.work / "argv").read_bytes(), b"space arg\0\0$(no-evaluation);*\0tail\0")
        self.assertEqual((self.work / "stdin").read_bytes(), b"stdin survives\n")
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_split_root_preserves_streams_identity_argv_stdin_and_status(self):
        args = ["space arg", "", "apostrophe's arg", "$(no-evaluation);*"]
        rc, _, err = self.driver("split", "sh", FIXTURES / "split-target.sh", *args,
                                 input=b"split stdin survives\n")
        self.assertEqual(rc, 37, err.decode())
        fields = (self.work / "fields").read_text().splitlines()
        pid, start = (self.work / "process.pid").read_text().split()
        self.assertEqual(fields, [pid, start, pid, start, "committed"])
        self.assertEqual((self.work / "target.entered").read_text().strip(), pid)
        self.assertEqual((self.work / "argv").read_bytes(),
                         b"space arg\0\0apostrophe's arg\0$(no-evaluation);*\0")
        self.assertEqual((self.work / "stdin").read_bytes(), b"split stdin survives\n")
        self.assertEqual((self.work / "stdout space's.log").read_bytes(), b"stdout from target\n")
        self.assertEqual((self.work / "stderr space's.log").read_bytes(), b"stderr from target\n")

    def test_existing_root_and_user_launchers_still_combine_streams(self):
        for mode in ("root", "user"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.work) as case:
                prior = self.env["CASE_DIR"]
                self.env["CASE_DIR"] = case
                try:
                    rc, _, err = self.driver(mode, "sh", FIXTURES / "split-target.sh")
                finally:
                    self.env["CASE_DIR"] = prior
                self.assertEqual(rc, 37, err.decode())
                self.assertEqual((Path(case) / "target.log").read_bytes(),
                                 b"stdout from target\nstderr from target\n")

    def test_split_refuses_empty_stderr_path_before_prepare(self):
        rc, _, _ = self.driver("split-paths", self.work / "stdout.log", "",
                               "sh", FIXTURES / "split-target.sh")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.work / "process.pid").exists())
        self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "target.entered").exists())

    def test_split_output_open_failures_are_bounded_pending_and_finalizable(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory(dir=self.work) as case:
                case = Path(case)
                prior = self.env["CASE_DIR"]
                self.env.update(CASE_DIR=str(case), CASE_DEADLINE="0.25", FINALIZE="1")
                stdout = case / "stdout.log"
                stderr = case / "stderr.log"
                if stream == "stdout":
                    stdout = case / "missing" / "stdout.log"
                else:
                    stderr = case / "missing" / "stderr.log"
                try:
                    rc, _, _ = self.driver("split-paths", stdout, stderr,
                                           "sh", FIXTURES / "split-target.sh")
                finally:
                    self.env["CASE_DIR"] = prior
                    self.env.pop("CASE_DEADLINE", None)
                    self.env.pop("FINALIZE", None)
                self.assertNotEqual(rc, 0)
                fields = (case / "fields").read_text().splitlines()
                final = (case / "finalized").read_text().splitlines()
                self.assertEqual(fields[4], "spawned")
                self.assertNotEqual(final[0], "0")
                self.assertEqual(final[1], fields[0])
                self.assertEqual(final[2:5], ["", "", ""])
                self.assertTrue(final[5])
                self.assertFalse((case / "sudo.entered").exists())
                self.assertFalse((case / "target.entered").exists())

    def test_split_target_exec_failure_uses_stderr_only_and_is_nonzero(self):
        missing = self.work / "missing target's executable"
        rc, _, err = self.driver("split", missing)
        self.assertNotEqual(rc, 0, err.decode())
        self.assertEqual((self.work / "stdout space's.log").read_bytes(), b"")
        diagnostic = (self.work / "stderr space's.log").read_text()
        self.assertTrue(diagnostic.strip(), "missing exec diagnostic")
        self.assertIn("No such file or directory", diagnostic)

    def test_adopt_none_records_owned_generation_mismatch(self):
        proc, parent_fd = self.child(["sleep", "300"])
        actual = self.generation(proc.pid)
        identity = (proc.pid, actual + 1)

        self.assertIsNone(self.adopt(*identity))
        self.assertEqual(
            self.adopt_none_reasons[identity],
            f"generation-mismatch expected={actual + 1} actual={actual}",
        )
        snapshot = {
            "ROOT_RECORD_IDENTITY": json.dumps({"deadline": 123456789}),
            "ROOT_LAUNCH_PID": str(identity[0]),
            "ROOT_LAUNCH_STARTTIME": str(identity[1]),
            "noise": "X" * 50000,
        }
        (self.work / "snapshot.json").write_text(json.dumps(snapshot))
        (self.work / "hook.waiting").write_text("owned hook marker")
        (self.work / "stderr space's.log").write_text("launcher deadline expired")

        diagnostic = self.adopt_none_diagnostic(identity, snapshot, parent_fd)
        self.assertIn(f"authenticated_identity={identity}", diagnostic)
        self.assertIn(self.adopt_none_reasons[identity], diagnostic)
        self.assertIn("context_deadline_ns=123456789", diagnostic)
        self.assertRegex(diagnostic, r"monotonic_ns=[1-9][0-9]+")
        self.assertIn("hook-marker='owned hook marker'", diagnostic)
        self.assertIn("split-stderr='launcher deadline expired'", diagnostic)
        self.assertIn("direct-parent-status=running", diagnostic)
        self.assertIn("<truncated repr limit=4096>", diagnostic)
        self.assertLess(len(diagnostic), 10000)

    def test_diagnostic_file_names_missing_and_truncates_oversized_input(self):
        missing = self.work / "missing.log"
        oversized = self.work / "oversized.log"
        oversized.write_bytes(b"A" * 5000)

        self.assertEqual(self.diagnostic_file("split-stderr", missing),
                         "split-stderr=<missing>")
        evidence = self.diagnostic_file("split-stderr", oversized)
        self.assertTrue(evidence.startswith("split-stderr='AAAA"))
        self.assertIn("<truncated size=5000 limit=4096>", evidence)
        self.assertLess(len(evidence), 4300)

    def test_adopt_none_collects_diagnostic_before_strict_failure(self):
        proc, parent_fd = self.child(["sleep", "300"])
        identity = (proc.pid, self.generation(proc.pid) + 1)
        snapshot = {"ROOT_RECORD_IDENTITY": json.dumps({"deadline": 123456789})}

        with mock.patch.object(self, "adopt_none_diagnostic",
                               wraps=self.adopt_none_diagnostic) as diagnostic:
            with self.assertRaisesRegex(AssertionError, "generation-mismatch"):
                self.assert_adopted(identity, snapshot, parent_fd)
        diagnostic.assert_called_once_with(identity, snapshot, parent_fd)

    def test_split_ack_success_path_skips_failure_diagnostics(self):
        with mock.patch.object(self, "adopt_none_diagnostic",
                               wraps=self.adopt_none_diagnostic) as diagnostic:
            self.test_split_ack_interruption_cleans_up_original_launcher_handle()
        diagnostic.assert_not_called()

    def test_split_ack_interruption_cleans_up_original_launcher_handle(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="launcher", HOOK_ACTION="hold",
                        CASE_DEADLINE="0.5")
        proc, parent_fd = self.child(["sh", str(FIXTURES / "driver.sh"), "split",
                                      "sh", str(FIXTURES / "split-target.sh")],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        hook = json.loads(self.wait_path(self.work / "hook.waiting").read_text())
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        identity = (int(snapshot["ROOT_LAUNCH_PID"]), int(snapshot["ROOT_LAUNCH_STARTTIME"]))
        original_fd = self.assert_adopted(identity, snapshot, parent_fd)
        hook_identity = (hook["pid"], hook["starttime"])
        self.assert_adopted(hook_identity, snapshot, parent_fd)
        signal.pidfd_send_signal(parent_fd, signal.SIGTERM)
        proc.wait(timeout=3)
        (self.work / "hook.release").touch()
        self.assertTrue(select.select([original_fd], [], [], 3)[0])
        self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "target.entered").exists())

    def test_wrong_generation_never_signals_live_decoy(self):
        decoy, fd = self.child(["sleep", "300"])
        rc, _, _ = self.driver("terminate", decoy.pid, 1)
        self.assertEqual(rc, 0)
        self.assertFalse(select.select([fd], [], [], 0)[0], "wrong-generation decoy was killed")
        self.assertFalse((self.work / "numeric-signals").exists(), "numeric signal attempted")

    def test_missing_generation_is_nonpass_without_signal(self):
        decoy, fd = self.child(["sleep", "300"])
        rc, _, _ = self.driver("terminate", decoy.pid)
        self.assertNotEqual(rc, 0)
        self.assertFalse(select.select([fd], [], [], 0)[0])
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_without_ack_native_wrapper_expires_without_exec(self):
        context = self.context(0.25)
        proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                              "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertFalse((self.work / "target.entered").exists())

    def test_direct_user_preserves_identity_and_input(self):
        rc, _, err = self.driver("user", "sh", FIXTURES / "target.sh", input=b"direct\n")
        self.assertEqual(rc, 23, err.decode())
        fields = (self.work / "fields").read_text().splitlines()
        self.assertEqual(fields[0:2], fields[2:4])
        self.assertEqual((self.work / "stdin").read_bytes(), b"direct\n")

    def test_two_successful_root_launches_can_remain_live(self):
        rc, _, err = self.driver("sequential")
        self.assertEqual(rc, 0, err.decode())

    def test_preexisting_durable_record_never_releases_sudo(self):
        path = self.work / "process.pid"
        path.write_text("123 456\n")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        self.assertEqual(path.read_text(), "123 456\n")
        self.assertFalse((self.work / "sudo.entered").exists())

    def test_parent_acquisition_failure_never_acknowledges_launcher(self):
        self.env.update(HOOK_OPERATION="read", HOOK_PHASE="launcher", HOOK_ACTION="fail", FINALIZE="1")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        fields = (self.work / "fields").read_text().splitlines()
        self.assertEqual(fields[1:4], ["", "", ""])
        final = (self.work / "finalized").read_text().splitlines()
        self.assertNotEqual(final[0], "0")
        self.assertEqual(final[1], fields[0])
        self.assertTrue(final[5])
        self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_launcher_fields_are_published_before_ack_failure(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="launcher", HOOK_ACTION="fail")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        self.assertTrue(snapshot["ROOT_LAUNCH_STARTTIME"])
        self.assertEqual(snapshot["ROOT_RECORD_PHASE"], "launcher-acknowledging")
        self.assertFalse((self.work / "sudo.entered").exists())

    def test_root_fields_are_published_before_ack_failure(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="root", HOOK_ACTION="fail")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        self.assertTrue(snapshot["ROOT_PROCESS_STARTTIME"])
        self.assertEqual(snapshot["ROOT_RECORD_PHASE"], "root-acknowledging")
        self.assertTrue((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "target.entered").exists())

    def test_control_replacement_preserves_authenticated_fields_and_foreign_files(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="root", HOOK_ACTION="replace-directory", FINALIZE="1")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        final = (self.work / "finalized").read_text().splitlines()
        self.assertNotEqual(final[0], "0")
        self.assertEqual(final[3:5], [snapshot["ROOT_PROCESS_PID"], snapshot["ROOT_PROCESS_STARTTIME"]])
        self.assertEqual((Path(snapshot["ROOT_RECORD_CONTROL"]) / "foreign").read_text(), "retain me")
        self.assertFalse((self.work / "target.entered").exists())

    def test_corrupted_self_cannot_be_acknowledged(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="root", HOOK_ACTION="corrupt-self")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.work / "target.entered").exists())

    def test_failure_after_root_ack_retains_target_cleanup_authority(self):
        self.env.update(HOOK_OPERATION="cleanup", HOOK_PHASE="", HOOK_ACTION="fail")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        self.assertTrue(snapshot["ROOT_PROCESS_STARTTIME"])
        self.assertEqual(snapshot["ROOT_RECORD_PHASE"], "root-acknowledged")
        self.wait_path(self.work / "target.entered")

    def delayed_phase(self, phase):
        self.shim()
        self.env.update(DELAY_PHASE=phase, CASE_DEADLINE="0.35")
        mode = "user" if phase == "user" else "root"
        proc, _ = self.child(["sh", str(FIXTURES / "driver.sh"), mode, "sh", str(FIXTURES / "target.sh")],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        record = json.loads(self.wait_path(self.work / "wrapper.stopped").read_text())
        fd = self.adopt(record["pid"], record["starttime"])
        self.assertIsNotNone(fd)
        proc.communicate(timeout=4)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((self.work / "target.entered").exists())
        if phase in ("launcher", "user"):
            self.assertFalse((self.work / "sudo.entered").exists())
        signal.pidfd_send_signal(fd, signal.SIGCONT)
        self.assertTrue(select.select([fd], [], [], 3)[0])
        self.assertFalse((self.work / "target.entered").exists())
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_missing_launcher_self_resumed_after_deadline_never_enters_sudo(self):
        self.delayed_phase("launcher")

    def test_missing_root_self_resumed_after_deadline_never_enters_target(self):
        self.delayed_phase("root")

    def test_missing_user_self_resumed_after_deadline_never_enters_target(self):
        self.delayed_phase("user")

    def parent_eof(self, phase):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE=phase, HOOK_ACTION="hold", CASE_DEADLINE="8")
        mode = "user" if phase == "user" else "root"
        proc, parent_fd = self.child(["sh", str(FIXTURES / "driver.sh"), mode, "sh", str(FIXTURES / "target.sh")],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hook = json.loads(self.wait_path(self.work / "hook.waiting").read_text())
        snapshot = json.loads((self.work / "snapshot.json").read_text())
        context_key = "USER_RECORD_IDENTITY" if mode == "user" else "ROOT_RECORD_IDENTITY"
        context = json.loads(snapshot[context_key])
        remaining_ns = context["deadline"] - time.monotonic_ns()
        self.assertGreater(remaining_ns, 5_000_000_000,
                           "launch deadline must retain headroom before parent EOF")
        prefix = "USER_PROCESS_LAUNCH" if mode == "user" else "ROOT_LAUNCH"
        fd = self.adopt(int(snapshot[prefix + "_PID"]), int(snapshot[prefix + "_STARTTIME"]))
        self.assertIsNotNone(fd)
        self.assertIsNotNone(self.adopt(hook["pid"], hook["starttime"]))
        signal.pidfd_send_signal(parent_fd, signal.SIGTERM)
        proc.wait(timeout=3)
        (self.work / "hook.release").touch()
        self.assertTrue(select.select([fd], [], [], 10)[0])
        self.assertLess(time.monotonic_ns(), context["deadline"],
                        "authenticated launch exited only after its deadline expired")
        self.assertFalse((Path(context["path"]) / f"{phase}.ack").exists(),
                         "orphaned ACK helper resumed after coordinator exit")
        if phase != "root":
            self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "target.entered").exists())

    def test_parent_eof_before_ack_never_releases_command(self):
        self.parent_eof("launcher")

    def test_parent_eof_before_root_ack_never_releases_target(self):
        self.parent_eof("root")

    def test_parent_eof_before_user_ack_never_releases_target(self):
        self.parent_eof("user")

    def test_correct_generation_terminates_real_child(self):
        proc, fd = self.child(["sleep", "300"])
        generation = Path(f"/proc/{proc.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19].decode()
        rc, _, err = self.driver("terminate", proc.pid, generation)
        self.assertEqual(rc, 0, err.decode())
        self.assertTrue(select.select([fd], [], [], 0)[0])

    def test_stopped_term_ignoring_child_requires_pidfd_kill(self):
        proc, fd = self.child(["sh", str(FIXTURES / "hold.sh"), "ignore"])
        generation = Path(f"/proc/{proc.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19].decode()
        time.sleep(0.05)
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        rc, _, err = self.driver("terminate", proc.pid, generation)
        self.assertEqual(rc, 0, err.decode())
        self.assertTrue(select.select([fd], [], [], 0)[0])
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_wrong_generation_cont_does_not_resume_decoy(self):
        proc, fd = self.child(["sleep", "300"])
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        rc, _, _ = self.driver("signal", "CONT", proc.pid, 1)
        self.assertNotEqual(rc, 0)
        self.assertEqual(Path(f"/proc/{proc.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[0], b"T")

    def test_active_invalid_identity_is_unknown(self):
        rc, out, _ = self.driver("active", os.getpid(), "invalid")
        self.assertEqual(rc, 2)
        self.assertEqual(out, b"unknown\n")

    def test_active_reports_replaced_separately_from_gone(self):
        rc, out, _ = self.driver("active", os.getpid(), 1)
        self.assertEqual((rc, out), (1, b"replaced\n"))

    def test_proc_permission_failure_is_unknown_without_signal(self):
        self.shim()
        self.env["FAIL_PROC"] = "1"
        rc, out, err = self.driver("active", os.getpid(), 1)
        self.assertEqual((rc, out), (2, b"unknown\n"), err.decode())
        self.assertIn(b"injected proc stat denial", err)
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_pidfd_failure_retains_pending_authenticated_identity(self):
        self.shim()
        self.env.update(FAIL_PIDFD="1", HOOK_OPERATION="cleanup", HOOK_PHASE="", HOOK_ACTION="fail", FINALIZE="1")
        rc, _, err = self.driver("root", "sleep", "300")
        self.assertNotEqual(rc, 0)
        final = (self.work / "finalized").read_text().splitlines()
        fields = (self.work / "fields").read_text().splitlines()
        self.assertNotEqual(final[0], "0")
        self.assertEqual(final[1:5], fields[:4])
        self.assertTrue(final[5])
        self.assertIn(b"injected pidfd_open denial", err,
                      repr(final) + (self.work / "target.log").read_text()
                      + (self.work / "sudo.calls").read_text())
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_native_refuses_wrong_ack_identity_phase_attempt_and_expiry(self):
        for field, wrong in (("pid", 1), ("starttime", 1), ("phase", "root"), ("attempt", "0" * 48)):
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir=self.work) as work:
                result = self.native("prepare", Path(work) / "pid", 1)
                context = result.stdout.splitlines()[1].decode()
                self.bind_context(context)
                proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                                      "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
                record = self.self_record(context, "launcher", proc)
                record["kind"] = "ack"
                record[field] = wrong
                ack = Path(json.loads(context)["path"]) / "launcher.ack"
                ack.write_text(json.dumps(record) + "\n")
                ack.chmod(0o600)
                self.assertNotEqual(proc.wait(timeout=3), 0)
                self.assertFalse((self.work / "target.entered").exists())

    def test_native_rejects_partial_symlink_and_preexisting_sidecars(self):
        for kind in ("partial", "symlink", "temporary", "complete-stale"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.work) as work:
                context = self.native("prepare", Path(work) / "pid", 1).stdout.splitlines()[1].decode()
                self.bind_context(context)
                control = Path(json.loads(context)["path"])
                record = control / ("launcher.self.tmp" if kind == "temporary" else "launcher.self")
                if kind == "symlink":
                    record.symlink_to(self.work / "foreign")
                else:
                    record.write_text('{"pid":' if kind == "partial" else "123 456\n")
                    record.chmod(0o600)
                proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                                      "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
                self.assertNotEqual(proc.wait(timeout=3), 0)
                self.assertFalse((self.work / "target.entered").exists())
                self.assertTrue(record.is_symlink() if kind == "symlink" else record.exists())

    def test_native_rejects_ack_when_self_pid_does_not_match_captured_child(self):
        context = self.context()
        proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-", "sleep", "300"],
                             stderr=subprocess.PIPE)
        self.self_record(context, "launcher", proc)
        result = self.native("read", context, "launcher", "self", proc.pid + 1, 0, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((Path(json.loads(context)["path"]) / "launcher.ack").exists())

    def test_user_waiting_shell_exec_preserves_session_group_and_generation(self):
        proc, _ = self.child(["sh", str(FIXTURES / "driver.sh"), "user", "sh", str(FIXTURES / "wait-exec.sh"), "kept"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = int(self.wait_path(self.work / "waiting.pid").read_text())
        fields = self.wait_path(self.work / "fields").read_text().splitlines()
        fd = self.adopt(int(fields[0]), int(fields[1]))
        self.assertIsNotNone(fd)
        tail = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        self.assertEqual(fields[:4], [str(pid), tail[19].decode(), str(pid), tail[19].decode()])
        self.assertEqual((int(tail[2]), int(tail[3])), (os.getpgid(proc.pid), os.getsid(proc.pid)))
        self.assertEqual(self.driver("signal", "STOP", pid, fields[1])[0], 0)
        self.assertEqual(self.driver("signal", "CONT", pid, fields[1])[0], 0)
        (self.work / "go").touch()
        proc.communicate(b"waiting stdin", timeout=5)
        self.assertEqual(proc.returncode, 23)
        self.assertTrue(select.select([fd], [], [], 0)[0])
        self.assertEqual((self.work / "target.entered").read_text().strip(), str(pid))
        self.assertEqual((self.work / "stdin").read_bytes(), b"waiting stdin")

    def test_strict_durable_reader_rejects_partial_file_without_ack(self):
        path = self.work / "incomplete.pid"
        path.write_text("123 456")
        path.chmod(0o600)
        rc, _, _ = self.driver("wait-record", path, os.getpid(), 1)
        self.assertNotEqual(rc, 0)
        self.assertFalse(list(self.work.glob("**/*.ack")))

    def test_prepared_state_without_captured_pid_retains_control_authority(self):
        rc, out, _ = self.driver("prepared-finalize")
        self.assertNotEqual(rc, 0)
        path, context = out.decode().splitlines()
        self.assertTrue(Path(path).is_dir())
        self.assertEqual(json.loads(context)["path"], path)

    def test_pending_failure_refuses_second_launch_without_overwriting_identity(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="launcher", HOOK_ACTION="fail")
        rc, _, err = self.driver("pending-repeat")
        self.assertEqual(rc, 0, err.decode())
        self.assertFalse((self.work / "second.pid").exists())

    def test_duplicate_json_keys_are_not_accepted_as_complete_ack(self):
        context = self.context()
        proc, _ = self.child(["python3", "-I", str(HELPER), "exec", context, "launcher", "-",
                              "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
        record = self.self_record(context, "launcher", proc)
        record["kind"] = "ack"
        ack = Path(json.loads(context)["path"]) / "launcher.ack"
        ack.write_text('{"pid":1,' + json.dumps(record)[1:] + "\n")
        ack.chmod(0o600)
        self.assertNotEqual(proc.wait(timeout=3), 23)
        self.assertFalse((self.work / "target.entered").exists())

    def test_correct_ack_consumed_after_deadline_cannot_exec(self):
        for phase in ("launcher", "root", "user"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=self.work) as work:
                pidfile = Path(work) / "pid"
                context = self.native("prepare", pidfile, 0.4).stdout.splitlines()[1].decode()
                self.bind_context(context)
                proc, fd = self.child(["python3", "-I", str(HELPER), "exec", context, phase,
                                       "-" if phase == "launcher" else str(pidfile),
                                       "sh", str(FIXTURES / "target.sh")], stderr=subprocess.PIPE)
                record = self.self_record(context, phase, proc)
                signal.pidfd_send_signal(fd, signal.SIGSTOP)
                self.native("ack", context, phase, record["pid"], record["starttime"])
                deadline = json.loads(context)["deadline"]
                while time.monotonic_ns() <= deadline:
                    time.sleep(0.01)
                signal.pidfd_send_signal(fd, signal.SIGCONT)
                self.assertNotEqual(proc.wait(timeout=3), 0)
                self.assertFalse((self.work / "target.entered").exists())

    def rejected_self(self, action):
        self.env.update(HOOK_OPERATION="read", HOOK_PHASE="launcher", HOOK_ACTION=action)
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        fields = (self.work / "fields").read_text().splitlines()
        self.assertEqual(fields[1:4], ["", "", ""])
        self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_partial_launcher_self_has_no_ack_or_signal_authority(self):
        self.rejected_self("corrupt-self")

    def test_mismatched_launcher_self_has_no_ack_or_signal_authority(self):
        self.rejected_self("mismatched-self")

    def test_root_self_permission_change_prevents_ack(self):
        self.env.update(HOOK_OPERATION="ack", HOOK_PHASE="root", HOOK_ACTION="public-self")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.work / "target.entered").exists())

    def test_early_exit_without_self_never_enters_sudo(self):
        self.shim()
        self.env.update(EARLY_PHASE="launcher", CASE_DEADLINE="0.3")
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.work / "sudo.entered").exists())
        self.assertFalse((self.work / "numeric-signals").exists())

    def test_symlink_durable_file_is_preserved_without_sudo(self):
        foreign = self.work / "foreign"
        foreign.write_text("retain")
        (self.work / "process.pid").symlink_to(foreign)
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.assertNotEqual(rc, 0)
        self.assertEqual(foreign.read_text(), "retain")
        self.assertTrue((self.work / "process.pid").is_symlink())
        self.assertFalse((self.work / "sudo.entered").exists())

    def test_untrusted_writable_parent_is_rejected_before_spawn(self):
        self.work.chmod(0o777)
        rc, _, _ = self.driver("root", "sh", FIXTURES / "target.sh")
        self.work.chmod(0o700)
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.work / "sudo.entered").exists())

    def test_adoption_wrong_generation_never_signals_or_reaps_live_decoy(self):
        proc, fd = self.child(["sleep", "300"])
        generation = self.generation(proc.pid)
        self.assertIsNone(self.adopt(proc.pid, generation + 1))
        self.assertEqual(self.cleanup_adopted(), [])
        self.assertFalse(select.select([fd], [], [], 0)[0], "wrong-generation decoy was signaled")
        self.assertIsNone(os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        self.assertIsNone(proc.returncode)

    def test_adoption_deduplicates_full_tuple_and_accepts_correct_generation(self):
        proc, _ = self.child(["sleep", "300"])
        generation = self.generation(proc.pid)
        self.assertIsNone(self.adopt(proc.pid, generation + 1))
        fd = self.adopt(proc.pid, generation)
        self.assertIsNotNone(fd)
        self.assertEqual(self.adopt(proc.pid, generation), fd)
        self.assertIsNone(self.adopt(proc.pid, generation + 2))
        self.assertEqual(list(self.adopted), [(proc.pid, generation)])

    def test_adoption_gone_original_does_not_acquire_reap_authority(self):
        proc, fd = self.child(["sleep", "300"])
        generation = self.generation(proc.pid)
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        proc.wait(timeout=5)
        self.assertIsNone(self.adopt(proc.pid, generation))
        self.assertFalse(self.adopted)

    def test_adoption_unreadable_generation_closes_candidate_without_signal(self):
        proc, original_fd = self.child(["sleep", "300"])
        generation = self.generation(proc.pid)
        candidate = []
        real_open = os.pidfd_open

        def opened(pid):
            fd = real_open(pid)
            candidate.append(fd)
            return fd

        with mock.patch.object(os, "pidfd_open", opened), \
                mock.patch.object(self, "generation", side_effect=PermissionError("injected identity denial")):
            with self.assertRaisesRegex(PermissionError, "injected identity denial"):
                self.adopt(proc.pid, generation)
        self.assertEqual(len(candidate), 1)
        with self.assertRaises(OSError):
            os.fstat(candidate[0])
        self.assertFalse(self.adopted)
        self.assertFalse(select.select([original_fd], [], [], 0)[0])

    def test_authenticated_adoption_reaps_only_pinned_orphan(self):
        self.env.update(HOOK_OPERATION="cleanup", HOOK_PHASE="", HOOK_ACTION="fail")
        proc, _ = self.child(["sh", str(FIXTURES / "driver.sh"), "root", "sleep", "300"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        fields = (self.work / "fields").read_text().splitlines()
        identity = (int(fields[2]), int(fields[3]))
        proof_fd = os.pidfd_open(identity[0])
        self.assertEqual(self.generation(identity[0]), identity[1])

        def rescue():
            try:
                try:
                    signal.pidfd_send_signal(proof_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.assertTrue(select.select([proof_fd], [], [], 5)[0])
                try:
                    os.waitid(os.P_PIDFD, proof_fd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    pass
            finally:
                os.close(proof_fd)

        self.addCleanup(rescue)
        # No explicit adoption occurred: teardown must recover original
        # fixture records even after an assertion/communicate exception.
        self.assertFalse(self.adopted)
        self.assertIn(identity, self.cleanup_adopted())
        self.assertTrue(select.select([proof_fd], [], [], 0)[0])
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PIDFD, proof_fd, os.WEXITED | os.WNOHANG)

    def test_child_pidfd_acquisition_failure_ends_reaps_and_closes_owned_child(self):
        created = []
        proof = []
        real_popen = subprocess.Popen
        real_open = os.pidfd_open

        def opened(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            created.append(proc)
            return proc

        def denied(pid):
            fd = real_open(pid)
            proof.append(fd)

            def rescue():
                # Independent pidfd authority keeps this fault test contained
                # even if the cleanup implementation being tested regresses.
                try:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.assertTrue(select.select([fd], [], [], 5)[0])
                    try:
                        status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                        if status is not None:
                            created[0].returncode = (status.si_status if status.si_code == os.CLD_EXITED
                                                     else -status.si_status)
                    except ChildProcessError:
                        pass
                finally:
                    os.close(fd)
                    for stream in (created[0].stdin, created[0].stdout, created[0].stderr):
                        stream.close()

            self.addCleanup(rescue)
            raise PermissionError("injected child pidfd acquisition denial")

        with mock.patch.object(subprocess, "Popen", opened), mock.patch.object(os, "pidfd_open", denied):
            with self.assertRaisesRegex(PermissionError, "injected child pidfd acquisition denial"):
                self.child(["sleep", "300"], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(len(created), 1)
        proc = created[0]
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        self.assertTrue(all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr)))
        self.assertTrue(select.select([proof[0]], [], [], 0)[0])
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PIDFD, proof[0], os.WEXITED | os.WNOHANG)

    def entrypoint_case(self, mode):
        proc, _ = self.child([sys.executable, "-I", str(FIXTURES / "entrypoint-case.py"),
                              mode, str(Path(__file__).resolve())],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=5)
        return proc.returncode, out + err

    def test_native_entrypoint_rejects_mandatory_skip(self):
        rc, output = self.entrypoint_case("skip")
        self.assertIn(b"skipped=1", output)
        self.assertNotEqual(rc, 0, output.decode())

    def test_native_entrypoint_rejects_empty_selection(self):
        rc, output = self.entrypoint_case("empty")
        self.assertIn(b"Ran 0 tests", output)
        self.assertNotEqual(rc, 0, output.decode())

    def rescue_fixture(self, record):
        fd = os.pidfd_open(record["pid"])
        try:
            self.assertEqual(self.generation(record["pid"]), record["starttime"])
        except BaseException:
            os.close(fd)
            raise

        def rescue():
            try:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.assertTrue(select.select([fd], [], [], 5)[0])
                try:
                    os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    pass
            finally:
                os.close(fd)

        self.addCleanup(rescue)
        return fd

    def prepublication_family(self, chain=False):
        self.env["DELAY_PHASE"] = "launcher"
        parent, parent_fd = self.child(["sh", str(FIXTURES / "prepublication-parent.sh"),
                                        "chain" if chain else "single"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        record = json.loads(self.wait_path(self.work / "before-publication.json").read_text())
        proof_fd = self.rescue_fixture(record)
        middle = None
        if chain:
            records = [json.loads(p.read_text()) for p in self.work.glob(".owned-*.json")]
            middle = next(item for item in records if item["pid"] == record["ppid"])
            self.rescue_fixture(middle)
        else:
            self.assertEqual(record["ppid"], parent.pid)
            self.assertFalse(list(self.work.glob(".owned-*.json")))
        signal.pidfd_send_signal(parent_fd, signal.SIGKILL)
        # Orphans intentionally retain inherited pipes. Reap the direct parent
        # without waiting for descendant stream EOF before exercising cleanup.
        parent.wait(timeout=5)
        self.assertEqual(parent.returncode, -signal.SIGKILL)
        return record, proof_fd, middle

    def assert_prepublication_drained(self, chain=False):
        record, proof_fd, middle = self.prepublication_family(chain)
        reaped = self.drain_owned_children()
        (self.work / "publication.release").touch()
        self.assertTrue(select.select([proof_fd], [], [], 0.5)[0],
                        "live or stopped fixture survived cleanup before publication")
        self.assertIn((record["pid"], record["starttime"]), reaped)
        if middle:
            self.assertIn((middle["pid"], middle["starttime"]), reaped)
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PIDFD, proof_fd, os.WEXITED | os.WNOHANG)
        self.assertFalse((self.work / "wrapper.stopped").exists())

    def test_prepublication_orphan_is_drained_before_late_stop(self):
        self.assert_prepublication_drained()

    def test_subreaper_drain_repeats_after_second_reparenting_wave(self):
        self.assert_prepublication_drained(chain=True)

    def test_subreaper_census_denial_is_nonpass_without_signal(self):
        _, proof_fd, _ = self.prepublication_family()
        with mock.patch.object(self, "owned_child_census", side_effect=PermissionError("injected census denial")):
            with self.assertRaisesRegex(PermissionError, "injected census denial"):
                self.drain_owned_children()
        self.assertFalse(select.select([proof_fd], [], [], 0)[0])

    def test_subreaper_pidfd_acquisition_denial_is_nonpass_without_signal(self):
        _, proof_fd, _ = self.prepublication_family()
        with mock.patch.object(os, "pidfd_open", side_effect=PermissionError("injected orphan pidfd denial")):
            with self.assertRaisesRegex(PermissionError, "injected orphan pidfd denial"):
                self.drain_owned_children()
        self.assertFalse(select.select([proof_fd], [], [], 0)[0])

    def test_subreaper_refuses_child_not_yet_reparented(self):
        record, proof_fd, _ = self.prepublication_family(chain=True)
        with mock.patch.object(self, "owned_child_census", return_value=[record["pid"]]):
            with self.assertRaisesRegex(AssertionError, "no longer our direct child"):
                self.drain_owned_children()
        self.assertFalse(select.select([proof_fd], [], [], 0)[0])

    def test_subreaper_drain_preserves_live_owned_decoy_until_teardown(self):
        _, proof_fd = self.child(["sleep", "300"])
        with self.assertRaisesRegex(AssertionError, "parents must be ended/reaped"):
            self.drain_owned_children()
        self.assertFalse(select.select([proof_fd], [], [], 0)[0])


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1)
