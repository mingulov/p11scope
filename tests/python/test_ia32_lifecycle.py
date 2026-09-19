# SPDX-License-Identifier: GPL-3.0-or-later
"""Native ia32 caller and exec-guard ownership tests."""

import ctypes
import hashlib
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/ia32-lifecycle"
ROOT_FIXTURES = ROOT / "tests/fixtures/root-recorded-launcher"
DRIVER = FIXTURES / "driver.sh"
TARGET = FIXTURES / "target.sh"
GUARD_SOURCE = ROOT / "scripts/matrix/ia32-compat-trace-exec.c"
EXPECTED_DEFAULT_TESTS = 28


def starttime(pid):
    return int(Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19])


def state(pid):
    return Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[0].decode()


class Ia32LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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
        self.temp = tempfile.TemporaryDirectory(prefix="p11scope-ia32-life-")
        self.work = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env["CASE_DIR"] = str(self.work)
        self.env["IA32_TEST_HOLD_SECONDS"] = "12"
        self.env["IA32_GUARD_TEST_SECONDS"] = "12"
        self.bin = self.work / "bin"
        self.bin.mkdir(mode=0o700)
        self.mock_sudo = self.bin / "sudo"
        shutil.copyfile(ROOT_FIXTURES / "sudo", self.mock_sudo)
        self.mock_sudo.chmod(0o700)
        self.owned = []
        self.guard_children = {}

    def tearDown(self):
        failures = self.cleanup_entries(self.owned)
        if failures:
            self.temp._finalizer.detach()
            self.fail("cleanup ownership unresolved; evidence retained at "
                      f"{self.work}: {'; '.join(failures)}")
        else:
            self.temp.cleanup()

    def own_pid(self, pid, generation):
        fd = os.pidfd_open(pid)
        try:
            actual = starttime(pid)
        except FileNotFoundError as error:
            os.close(fd)
            raise AssertionError(f"custody acquisition lost pid {pid}") from error
        if actual != generation:
            os.close(fd)
            raise AssertionError(
                f"custody acquisition generation mismatch for pid {pid}: {actual} != {generation}"
            )
        owned = {"pid": pid, "generation": generation, "fd": fd,
                 "proc": None, "closed": False, "verified": True,
                 "owner_entry": None, "parent_status": None, "terminal": None}
        self.owned.append(owned)
        return owned

    def popen_owned(self, *args, **kwargs):
        proc = subprocess.Popen(*args, **kwargs)
        owned = {"pid": proc.pid, "generation": None, "fd": None,
                 "proc": proc, "closed": False, "verified": False,
                 "owner_entry": None, "parent_status": None, "terminal": None}
        self.owned.append(owned)
        try:
            owned["fd"] = os.pidfd_open(proc.pid)
        except OSError as error:
            failures = self.retire_direct(owned)
            detail = "; ".join(failures) if failures else "child terminated and reaped"
            raise AssertionError(f"direct-child pidfd acquisition failed: {detail}") from error
        try:
            owned["generation"] = starttime(proc.pid)
        except FileNotFoundError as error:
            failures = self.retire_direct(owned)
            detail = "; ".join(failures) if failures else "child terminated and reaped"
            raise AssertionError(
                f"direct-child custody acquisition lost pid {proc.pid}: {detail}"
            ) from error
        owned["verified"] = True
        return proc, owned

    def close_owned(self, owned):
        if not owned["closed"]:
            if owned["fd"] is not None:
                os.close(owned["fd"])
            owned["closed"] = True

    def signal_owned(self, owned, sig):
        if not owned["verified"] or owned["fd"] is None:
            raise AssertionError(f"pid {owned['pid']} has no verified pidfd signal authority")
        signal.pidfd_send_signal(owned["fd"], sig)

    def retire_direct(self, owned):
        proc = owned["proc"]
        if proc is None:
            return [f"pid {owned['pid']} is not a direct Popen child"]
        if proc.poll() is not None:
            owned["terminal"] = proc.wait()
            self.close_owned(owned)
            return []
        try:
            if owned["fd"] is not None:
                signal.pidfd_send_signal(owned["fd"], signal.SIGTERM)
            else:
                # Popen still owns this unreaped direct child, so PID reuse is impossible.
                proc.terminate()
            owned["terminal"] = proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                if owned["fd"] is not None:
                    signal.pidfd_send_signal(owned["fd"], signal.SIGKILL)
                else:
                    proc.kill()
                owned["terminal"] = proc.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired) as error:
                return [f"direct child {owned['pid']} exit unproved: {error}"]
        except ProcessLookupError:
            try:
                owned["terminal"] = proc.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                return [f"direct child {owned['pid']} reap unproved: {error}"]
        self.close_owned(owned)
        return []

    def parent_reap_status(self, owned):
        record = owned.get("parent_status")
        try:
            if record is not None:
                if not record.exists():
                    return None
                fields = record.read_text().split()
                if (len(fields) == 3
                        and fields[:2] == [str(owned["pid"]), str(owned["generation"])]):
                    return int(fields[2])
                return None
        except OSError:
            return None
        owner = owned.get("owner_entry")
        if owner is not None and owner.get("terminal") is not None:
            return {"reaped_by_owner": owner["terminal"]}
        return None

    def cleanup_entries(self, entries):
        failures = []
        for owned in reversed(entries):
            if not owned["closed"] and owned["proc"] is not None:
                failures.extend(self.retire_direct(owned))
        for owned in reversed(entries):
            if owned["closed"] or owned["proc"] is not None:
                continue
            try:
                self.signal_owned(owned, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                failures.append(f"verified child {owned['pid']} signal failed: {error}")
            try:
                self.wait_pidfd(owned, timeout=2)
            except (ChildProcessError, TimeoutError, ValueError) as error:
                failures.append(f"verified child {owned['pid']} exit/reap unproved: {error}")
        return failures

    def wait_popen(self, owned, timeout):
        status = owned["proc"].wait(timeout=timeout)
        owned["terminal"] = status
        self.close_owned(owned)
        return status

    def wait_pidfd(self, owned, timeout):
        if owned["closed"] or owned["fd"] is None:
            raise ValueError(f"pid {owned['pid']} has no open pidfd for exit proof")
        poller = select.poll()
        poller.register(owned["fd"], select.POLLIN)
        events = poller.poll(round(timeout * 1000))
        if not events:
            raise TimeoutError(f"pidfd wait timed out for pid {owned['pid']}")
        valid = False
        for descriptor, event in events:
            if descriptor != owned["fd"] or event & (select.POLLERR | select.POLLNVAL):
                raise ValueError(f"pid {owned['pid']} pidfd poll returned invalid event {event}")
            valid = valid or bool(event & select.POLLIN)
        if not valid:
            raise ValueError(f"pid {owned['pid']} pidfd poll lacked POLLIN exit proof")
        try:
            result = os.waitid(os.P_PIDFD, owned["fd"], os.WEXITED)
        except ChildProcessError as error:
            status = self.parent_reap_status(owned)
            if status is None:
                raise ChildProcessError(
                    f"pid {owned['pid']} exited but owner reap/adoption is unproved"
                ) from error
            owned["terminal"] = status
            result = None
        else:
            owned["terminal"] = {"waitid_code": result.si_code, "waitid_status": result.si_status}
        self.close_owned(owned)
        return result

    def run_owned(self, command, *, input=b"", timeout=8, env=None, **kwargs):
        proc, owned = self.popen_owned(
            command, cwd=ROOT, env=self.env if env is None else env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs,
        )
        try:
            stdout, stderr = proc.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            failures = self.retire_direct(owned)
            if failures:
                raise AssertionError("; ".join(failures))
            raise
        owned["terminal"] = proc.returncode
        self.close_owned(owned)
        return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)

    def run_driver(self, *args, input=b"", timeout=8, env=None):
        return self.run_owned(
            ["sh", str(DRIVER), *map(str, args)], input=input, timeout=timeout, env=env,
        )

    def root_fixture_env(self):
        env = self.env.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        self.assertEqual(shutil.which("sudo", path=env["PATH"]), str(self.mock_sudo))
        return env

    def test_direct_user_launch_preserves_exact_identity_argv_stdin_and_exit9(self):
        record = self.work / "target"
        result = self.run_driver(
            "launch", TARGET, record, "exit", 9, "quoted path", "", "dollar$literal",
            input=b"caller stdin\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fields = list(map(int, (self.work / "fields").read_text().splitlines()))
        identity = list(map(int, (self.work / "target.identity").read_text().split()))
        self.assertEqual(fields[:2], identity)
        self.assertEqual(fields[0], fields[2])
        self.assertEqual(fields[1], fields[3])
        self.assertEqual((self.work / "target.argv").read_bytes(), b"quoted path\0\0dollar$literal\0")
        self.assertEqual((self.work / "target.stdin").read_bytes(), b"caller stdin\n")
        self.assertEqual((self.work / "wait").read_text().splitlines(), ["gone", "9"])

    def test_ready_before_stop_requires_authenticated_stopped_state_then_reaps(self):
        record = self.work / "target"
        result = self.run_driver("stopped", TARGET, record, "delayed-stop", 0, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        state, status = (self.work / "wait").read_text().splitlines()
        self.assertIn(state, ("gone", "zombie"))
        self.assertIn(int(status), (-signal.SIGTERM, -signal.SIGKILL, 128 + signal.SIGTERM, 128 + signal.SIGKILL))

    def test_replaced_generation_is_nonpass_and_does_not_signal_live_process(self):
        record = self.work / "target"
        result = self.run_driver("replaced", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.work / "wait").read_text().splitlines(), ["2", "replaced"])
        self.assertTrue((self.work / "decoy-survived").exists())

    def test_unknown_observation_is_nonpass_without_signal_or_wait(self):
        record = self.work / "target"
        result = self.run_driver("unknown", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.work / "wait").read_text().splitlines(), ["2", "unknown"])
        self.assertTrue((self.work / "decoy-survived").exists())

    def test_pending_finalizers_are_both_attempted(self):
        result = self.run_driver("pending-cleanup")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.work / "cleanup").read_text(), "0\n")

    def test_no_ack_pending_user_is_cancelled_ended_and_reaped(self):
        result = self.run_driver("no-ack", timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        cleanup, ended, status = (self.work / "cleanup").read_text().splitlines()
        self.assertEqual(cleanup, "0")
        self.assertIn(ended, ("gone", "zombie"))
        self.assertNotEqual(int(status), 0)

    def test_prepared_missing_identity_is_nonpass_without_numeric_signal(self):
        result = self.run_driver("prepared-missing")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.work / "cleanup").read_text(), "1\n")
        self.assertFalse((self.work / "unsafe-signal").exists())

    def test_committed_transfer_is_not_owned_by_pending_finalizers(self):
        record = self.work / "target"
        result = self.run_driver("committed-finalizer", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.work / "committed-survived").exists())
        self.assertEqual((self.work / "cleanup").read_text(), "0\n")

    def test_hup_cleanup_is_single_entry_preserves_status_and_ends_child(self):
        record = self.work / "target"
        result = self.run_driver("signal-cleanup", TARGET, record, "hold", 0, timeout=10)
        self.assertEqual(result.returncode, 129, result.stderr.decode())
        self.assertEqual(result.stdout.count(b"CLEANUP_RESULT=PASS status=129\n"), 1)
        self.assertEqual((self.work / "evidence/cleanup.status").read_text(), "cleanup_status=0\n")

    def test_user_and_root_committed_transfer_signal_is_adopted_by_cleanup(self):
        for role in ("user", "root"):
            with self.subTest(role=role):
                env = self.root_fixture_env()
                record = self.work / f"{role}-target"
                result = self.run_driver(
                    "acquisition-signal", role, TARGET, record, "hold", "0",
                    env=env, timeout=10,
                )
                self.assertEqual(result.returncode, 129, result.stderr.decode())
                self.assertEqual((self.work / "transfer-boundary").read_text(), f"{role}\n")
                self.assertEqual(result.stdout.count(b"CLEANUP_RESULT=PASS status=129\n"), 1)
                status = (self.work / "evidence/status").read_text()
                expected = "fixture_status=" if role == "user" else "tracer_status="
                self.assertIn(expected, status)
                self.assertNotIn(expected + "STARTED\n", status)
                self.assertNotIn(expected + "UNKNOWN\n", status)
                for path in ("transfer-boundary", "process.pid"):
                    (self.work / path).unlink(missing_ok=True)
                for path in (self.work / "evidence").iterdir():
                    if path.is_file():
                        path.unlink()
                (self.work / "evidence").rmdir()

    def test_completion_deadline_records_exact_exit_and_clears_owned_tuple(self):
        record = self.work / "completion-target"
        result = self.run_driver("completion-timeout", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        outcome, reason, status, custody = (self.work / "completion").read_text().splitlines()
        self.assertEqual((outcome, reason, custody), ("1", "DEADLINE_EXPIRED", "CLEARED"))
        self.assertEqual(int(status), 128 + signal.SIGTERM)

    def test_completion_unknown_retains_exact_tuple_until_real_cleanup(self):
        record = self.work / "completion-target"
        result = self.run_driver("completion-unknown", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        outcome, reason, status, pid, generation = (self.work / "completion").read_text().splitlines()
        self.assertEqual((outcome, reason, status), ("1", "IDENTITY_UNRESOLVED", "UNKNOWN"))
        self.assertGreater(int(pid), 0)
        self.assertGreater(int(generation), 0)
        self.assertEqual((self.work / "evidence/cleanup.status").read_text(), "cleanup_status=0\n")
        status_log = dict(
            line.split("=", 1) for line in (self.work / "evidence/status").read_text().splitlines()
        )
        self.assertNotIn(status_log["fixture_status"], ("STARTED", "UNKNOWN"))

    def test_real_cleanup_attempts_timeout_after_guard_failure_and_is_nonpass(self):
        env = self.root_fixture_env()
        record = self.work / "cleanup-target"
        result = self.run_driver(
            "cleanup-independent", TARGET, record, "hold", "0", env=env, timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertIn(b"CLEANUP_RESULT=NONPASS status=1\n", result.stdout)
        self.assertEqual((self.work / "evidence/cleanup.status").read_text(), "cleanup_status=1\n")
        status = dict(line.split("=", 1) for line in (self.work / "evidence/status").read_text().splitlines())
        self.assertTrue((self.work / "sudo.entered").exists())
        sudo_calls = (self.work / "sudo.calls").read_text().splitlines()
        call_fields = [call.split() for call in sudo_calls]
        self.assertTrue(any(
            len(fields) > 3
            and fields[:2] == ["python3", "-I"]
            and Path(fields[2]).name == "recorded-process-exec.py"
            and fields[3] == "exec"
            for fields in call_fields
        ), sudo_calls)
        self.assertTrue(any(fields[:4] == ["python3", "-I", "scripts/lane-lib-oracle-1.py", "CONT"]
                            for fields in call_fields), sudo_calls)
        self.assertEqual(int(status["tracer_status"]), 128 + signal.SIGTERM)

    def test_cleanup_output_failure_is_terminal_nonpass_after_owned_cleanup(self):
        record = self.work / "cleanup-target"
        result = self.run_driver("cleanup-output-failure", TARGET, record, "hold", 0)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"CLEANUP_RESULT=NONPASS status=1\n", result.stdout)
        status = dict(line.split("=", 1) for line in (self.work / "evidence/status").read_text().splitlines())
        self.assertNotIn(status["fixture_status"], ("STARTED", "UNKNOWN"))

    def test_setarch_style_exec_keeps_authenticated_target_identity(self):
        if subprocess.run(["sh", "-c", "command -v setarch"], capture_output=True).returncode != 0:
            self.fail("required test prerequisite setarch is unavailable")
        machine = os.uname().machine
        record = self.work / "target"
        result = self.run_driver("launch", "setarch", machine, TARGET, record, "exit", 0, "setarch arg")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fields = list(map(int, (self.work / "fields").read_text().splitlines()))
        identity = list(map(int, (self.work / "target.identity").read_text().split()))
        self.assertEqual(fields[:2], identity)

    def test_root_launch_transfers_launcher_and_process_generations_before_wait(self):
        env = self.root_fixture_env()
        record = self.work / "target"
        result = self.run_driver(
            "root-launch", TARGET, record, "exit", "9", "root arg",
            env=env, input=b"root stdin\n", timeout=8,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        fields = list(map(int, (self.work / "fields").read_text().splitlines()))
        self.assertTrue(all(value > 0 for value in fields))
        identity = list(map(int, (self.work / "target.identity").read_text().split()))
        self.assertEqual(fields[2:], identity)
        self.assertEqual((self.work / "wait").read_text().splitlines(), ["gone", "9"])

    def test_real_timeout_statuses_remain_distinct(self):
        cases = (
            ("exit9", 9, ["timeout", "2"], ["exit", 9]),
            ("timeout124", 124, ["timeout", "-s", "TERM", "0.2"], ["hold", 0]),
            (
                "escalation137", 137,
                ["timeout", "--kill-after=0.1", "-s", "INT", "0.1"], ["ignore", 0],
            ),
        )
        for name, expected, wrapper, target_args in cases:
            with self.subTest(name=name):
                case_dir = self.work / name
                case_dir.mkdir(mode=0o700)
                env = self.env.copy()
                env["CASE_DIR"] = str(case_dir)
                command = [*wrapper, TARGET, case_dir / name, *target_args]
                result = self.run_driver("launch", *command, timeout=8, env=env)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(int((case_dir / "wait").read_text().splitlines()[1]), expected)

    def test_timeout_status_failure_is_isolated_before_later_oracles(self):
        nested = Ia32LifecycleTests("test_real_timeout_statuses_remain_distinct")
        nested_result = unittest.TestResult()
        case_dirs = []
        later_oracles = []

        def run_case(*args, timeout=8, env=None, **_kwargs):
            case_dir = Path((nested.env if env is None else env)["CASE_DIR"])
            case_dirs.append(case_dir)
            if len(case_dirs) == 1:
                (case_dir / "process.pid").write_text("unresolved\n")
                raise subprocess.TimeoutExpired(args, timeout)
            if (case_dir / "process.pid").exists():
                raise AssertionError("later case reused unresolved process identity")
            expected = (124, 137)[len(case_dirs) - 2]
            (case_dir / "wait").write_text(f"gone\n{expected}\n")
            later_oracles.append(expected)
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with mock.patch.object(nested, "run_driver", side_effect=run_case):
            nested.run(nested_result)

        self.assertEqual(len(nested_result.errors), 1, nested_result.errors)
        self.assertEqual(nested_result.failures, [])
        self.assertEqual(len(set(case_dirs)), 3)
        self.assertEqual(later_oracles, [124, 137])

    def test_killed_foreground_timeout_status_does_not_prove_command_ended(self):
        record = self.work / "orphan"
        wrapper, wrapper_owned = self.popen_owned(
            ["timeout", "--foreground", "30", TARGET, record, "ignore", "0"],
            stdin=subprocess.DEVNULL,
        )
        self.wait_file(Path(str(record) + ".ready"))
        command_pid, generation = map(int, Path(str(record) + ".identity").read_text().split())
        command_owned = self.own_pid(command_pid, generation)
        command_owned["owner_entry"] = wrapper_owned
        self.signal_owned(wrapper_owned, signal.SIGKILL)
        self.assertEqual(self.wait_popen(wrapper_owned, 2), -signal.SIGKILL)
        self.assertEqual(starttime(command_pid), generation)
        self.signal_owned(command_owned, signal.SIGKILL)
        self.wait_pidfd(command_owned, 2)

    def test_self_test_retains_all_fifteen_vectors(self):
        result = self.run_owned(
            ["sh", "scripts/matrix/verify-ia32-compat.sh", "--self-test"], timeout=12,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"SELF_TEST=PASS\n", result.stdout)
        self.assertIn(b"SELF_TEST_UPPER32_POISON=SYNTHETIC_ONLY\n", result.stdout)

    def test_runner_rejects_empty_skipped_and_unknown_selection(self):
        for mode, args in (("empty", []), ("skip", []), (None, ["NoSuchTest"])):
            with self.subTest(mode=mode):
                env = self.env.copy()
                if mode is not None:
                    env["P11SCOPE_IA32_RUNNER_PROBE"] = mode
                result = subprocess.run(
                    [sys.executable, str(Path(__file__)), *args], cwd=ROOT, env=env,
                    capture_output=True, timeout=5,
                )
                self.assertNotEqual(result.returncode, 0)

        signal_mock = mock.Mock()
        close_mock = mock.Mock()
        before = len(self.owned)
        with mock.patch("os.pidfd_open", return_value=900), \
             mock.patch(f"{__name__}.starttime", return_value=222), \
             mock.patch("os.close", close_mock), \
             mock.patch("signal.pidfd_send_signal", signal_mock):
            with self.assertRaisesRegex(AssertionError, "generation mismatch"):
                self.own_pid(12345, 111)
        self.assertEqual(len(self.owned), before)
        close_mock.assert_called_once_with(900)
        signal_mock.assert_not_called()

        close_mock.reset_mock()
        with mock.patch("os.pidfd_open", return_value=903), \
             mock.patch(f"{__name__}.starttime", side_effect=FileNotFoundError), \
             mock.patch("os.close", close_mock), \
             mock.patch("signal.pidfd_send_signal", signal_mock):
            with self.assertRaisesRegex(AssertionError, "custody acquisition lost"):
                self.own_pid(12346, 112)
        self.assertEqual(len(self.owned), before)
        close_mock.assert_called_once_with(903)
        signal_mock.assert_not_called()

        class DirectChild:
            pid = 23456
            returncode = None

            def __init__(self):
                self.terminated = False
                self.waited = False

            def poll(self):
                return None

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                self.waited = True
                self.returncode = 143
                return self.returncode

        direct = DirectChild()
        with mock.patch("subprocess.Popen", return_value=direct), \
             mock.patch("os.pidfd_open", side_effect=OSError("EMFILE")):
            with self.assertRaisesRegex(AssertionError, "child terminated and reaped"):
                self.popen_owned(["pure-control"])
        self.assertTrue(direct.terminated)
        self.assertTrue(direct.waited)
        self.assertTrue(self.owned[-1]["closed"])

        class UnprovedChild:
            pid = 34567

            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("pure-control", timeout)

        unresolved = {"pid": 34567, "generation": 333, "fd": 901,
                      "proc": UnprovedChild(), "closed": False, "verified": True,
                      "owner_entry": None, "parent_status": None, "terminal": None}
        with mock.patch("signal.pidfd_send_signal"):
            failures = self.cleanup_entries([unresolved])
        self.assertTrue(failures)
        self.assertFalse(unresolved["closed"])

        exited_unowned = {"pid": 45678, "generation": 444, "fd": 902,
                          "proc": None, "closed": False, "verified": True,
                          "owner_entry": None, "parent_status": None, "terminal": None}
        poller = mock.Mock()
        poller.poll.return_value = [(902, select.POLLIN)]
        with mock.patch("select.poll", return_value=poller), \
             mock.patch("os.waitid", side_effect=ChildProcessError), \
             mock.patch("os.close"):
            with self.assertRaisesRegex(ChildProcessError, "reap/adoption is unproved"):
                self.wait_pidfd(exited_unowned, 1)
        self.assertFalse(exited_unowned["closed"])

        closed_owner = {"pid": 45679, "generation": 445, "fd": 903,
                        "proc": None, "closed": True, "verified": True,
                        "owner_entry": None, "parent_status": None,
                        "terminal": None}
        with self.assertRaisesRegex(ValueError, "no open pidfd"):
            self.wait_pidfd(closed_owner, 1)
        invalid_owner = dict(closed_owner, pid=45680, fd=904, closed=False)
        poller.poll.return_value = [(904, select.POLLNVAL)]
        with mock.patch("select.poll", return_value=poller):
            with self.assertRaisesRegex(ValueError, "invalid event"):
                self.wait_pidfd(invalid_owner, 1)

        shared_status = self.work / "pure-shared-child.status"
        shared_status.write_text("111 11 -9\n")
        first_child = {"pid": 111, "generation": 11, "fd": 905,
                       "proc": None, "closed": False, "verified": True,
                       "owner_entry": None, "parent_status": shared_status,
                       "terminal": None}
        poller.poll.return_value = [(905, select.POLLIN)]
        with mock.patch("select.poll", return_value=poller), \
             mock.patch("os.waitid", side_effect=ChildProcessError), \
             mock.patch("os.close"):
            self.wait_pidfd(first_child, 1)
        self.assertEqual(first_child["terminal"], -9)
        self.assertTrue(first_child["closed"])
        shared_status.write_text("222 22 -15\n")
        self.assertEqual(first_child["terminal"], -9)

    def build_guard(self):
        guard = self.work / "guard"
        target = self.work / "guard-target"
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", guard, GUARD_SOURCE], check=True)
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", target, FIXTURES / "guard-target.c"], check=True)
        return guard, target

    def launch_guard_parent(self, mode="normal", *, target_mode=None, input=b"guard stdin\n", env=None):
        guard, target = self.build_guard()
        if target_mode == "setid":
            target.chmod(0o4755)
        parent_record = self.work / "parent.pid"
        self_record = self.work / "guard.pid"
        program = self.work / "program.bt"
        program.write_text("BEGIN { exit(); }\n")
        target_record = self.work / "guard-target"
        child_record = Path(str(parent_record) + ".child")
        child_acquired = Path(str(child_record) + ".acquired")
        for stale in (
            parent_record, child_record, child_acquired, Path(str(child_record) + ".status"),
            Path(str(parent_record) + ".bootstrap-cleared"),
            self_record, Path(str(self_record) + ".exec"),
            Path(str(target_record) + ".result"), Path(str(target_record) + ".ready"),
            Path(str(target_record) + ".acquired"),
        ):
            stale.unlink(missing_ok=True)
        chosen_env = (self.env if env is None else env).copy()
        chosen_env["IA32_GUARD_TEST_RECORD"] = str(target_record)
        proc, parent_owned = self.popen_owned(
            [sys.executable, str(FIXTURES / "guard-parent.py"), mode, guard,
             parent_record, self_record, target, program],
            cwd=ROOT, env=chosen_env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.wait_file(child_record)
        child_pid, child_generation = map(int, child_record.read_text().split())
        child_owned = self.own_pid(child_pid, child_generation)
        child_owned["owner_entry"] = parent_owned
        child_owned["parent_status"] = Path(str(child_record) + ".status")
        self.guard_children[id(proc)] = child_owned
        child_acquired.touch()
        Path(str(target_record) + ".acquired").touch()
        proc.stdin.write(input)
        proc.stdin.close()
        return proc, parent_record, self_record, guard, target

    def finish_guard_parent(self, proc, timeout=3):
        parent_owned = next(item for item in self.owned if item["proc"] is proc)
        parent_status = self.wait_popen(parent_owned, timeout)
        child_owned = self.guard_children[id(proc)]
        child_status = self.wait_pidfd(child_owned, timeout)
        return parent_status, child_status, child_owned

    def wait_file(self, path, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        self.fail(f"timed out waiting for {path}")

    def test_guard_execs_exact_target_with_pdeath_identity_hash_and_stdin(self):
        proc, _, self_record, guard, target = self.launch_guard_parent()
        self.wait_file(self.work / "guard-target.ready")
        guard_pid, generation = map(int, self_record.read_text().split())
        result = (self.work / "guard-target.result").read_text()
        self.assertIn(f"pid={guard_pid}\n", result)
        self.assertIn(f"pdeath={signal.SIGKILL}\n", result)
        self.assertIn(f"argv0={target}\nargv1=-kk\nargv2=-q\nargv3=-B\nargv4=line\n", result)
        self.assertTrue(result.endswith("guard stdin\n"))
        metadata = dict(line.split("=", 1) for line in Path(str(self_record) + ".exec").read_text().splitlines())
        self.assertEqual(metadata["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(starttime(guard_pid), generation)
        guard_owned = self.guard_children[id(proc)]
        self.assertEqual((guard_owned["pid"], guard_owned["generation"]), (guard_pid, generation))
        self.signal_owned(guard_owned, signal.SIGKILL)
        parent_status, _, _ = self.finish_guard_parent(proc)
        self.assertNotEqual(parent_status, None)

    def test_guard_child_identity_is_atomic_and_gated_until_authenticated_ack(self):
        guard, target = self.build_guard()
        parent_record = self.work / "parent.pid"
        child_record = Path(str(parent_record) + ".child")
        child_temporary = Path(str(child_record) + ".tmp")
        constructing = Path(str(child_record) + ".constructing")
        construct_release = Path(str(child_record) + ".construct.release")
        child_acquired = Path(str(child_record) + ".acquired")
        self_record = self.work / "guard.pid"
        program = self.work / "program.bt"
        program.write_text("BEGIN { exit(); }\n")
        env = self.env.copy()
        env["IA32_GUARD_TEST_RECORD"] = str(target)
        env["IA32_TEST_HOLD_CHILD_RECORD"] = "1"
        proc, parent_owned = self.popen_owned(
            [sys.executable, str(FIXTURES / "guard-parent.py"), "normal", guard,
             parent_record, self_record, target, program],
            cwd=ROOT, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        self.wait_file(constructing)
        self.assertFalse(child_record.exists(), "partial child identity became public")
        partial = child_temporary.read_text().split()
        self.assertEqual(len(partial), 1, "construction hook did not expose one partial field")
        self.assertGreater(int(partial[0]), 0)
        self.assertFalse(Path(str(target) + ".ready").exists())

        construct_release.touch()
        self.wait_file(child_record)
        fields = child_record.read_text().split()
        self.assertEqual(len(fields), 2)
        child_pid, child_generation = map(int, fields)
        child_owned = self.own_pid(child_pid, child_generation)
        child_owned["owner_entry"] = parent_owned
        child_owned["parent_status"] = Path(str(child_record) + ".status")
        self.guard_children[id(proc)] = child_owned
        self.assertFalse(Path(str(target) + ".ready").exists(),
                         "child passed its gate before authenticated ACK")

        child_acquired.touch()
        Path(str(target) + ".acquired").touch()
        proc.stdin.write(b"guard stdin\n")
        proc.stdin.close()
        self.wait_file(Path(str(target) + ".ready"))
        self.signal_owned(child_owned, signal.SIGKILL)
        parent_status, _, _ = self.finish_guard_parent(proc)
        self.assertNotEqual(parent_status, None)
        self.assertFalse(child_temporary.exists())

    def test_guard_rejects_wrong_parent_generation_and_setid_target(self):
        for mode, target_mode in (("wrong", None), ("normal", "setid")):
            with self.subTest(mode=mode, target=target_mode):
                proc, _, self_record, _, _ = self.launch_guard_parent(mode, target_mode=target_mode)
                parent_status, _, _ = self.finish_guard_parent(proc)
                self.assertNotEqual(parent_status, 0)
                self.assertFalse(self_record.exists())
                self.assertFalse((self.work / "guard-target.ready").exists())

    def test_guard_rejects_missing_collision_and_capability_bearing_target(self):
        guard, target = self.build_guard()
        missing = subprocess.run(
            [guard, self.work / "missing.pid", self.work / "self.pid", target, self.work / "program"],
            capture_output=True,
        )
        self.assertNotEqual(missing.returncode, 0)

        self_record = self.work / "guard.pid"
        self_record.write_text("retain\n")
        parent_record = self.work / "parent.pid"
        raw = Path("/proc/self/stat").read_bytes().rsplit(b") ", 1)[1].split()
        parent_record.write_text(f"{os.getpid()} {int(raw[19])}\n")
        parent_record.chmod(0o600)
        collision = subprocess.run(
            [guard, parent_record, self_record, target, self.work / "program"], capture_output=True,
        )
        self.assertNotEqual(collision.returncode, 0)
        self.assertEqual(self_record.read_text(), "retain\n")
        self_record.unlink()
        Path(str(self_record) + ".exec").unlink()

        preload = self.work / "capability-xattr.so"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o", preload,
            FIXTURES / "capability-xattr.c",
        ], check=True)
        cap_env = self.env.copy()
        cap_env["LD_PRELOAD"] = str(preload)
        proc, _, cap_self, _, _ = self.launch_guard_parent(env=cap_env)
        parent_status, _, _ = self.finish_guard_parent(proc)
        self.assertNotEqual(parent_status, 0)
        self.assertFalse(cap_self.exists())
        self.assertFalse((self.work / "guard-target.ready").exists())

    def test_parent_death_kills_execed_guard_but_foreign_sentinel_survives(self):
        sentinel, sentinel_owned = self.popen_owned(["sleep", "30"])
        try:
            proc, _, self_record, _, _ = self.launch_guard_parent()
            self.wait_file(self.work / "guard-target.ready")
            guard_pid, generation = map(int, self_record.read_text().split())
            guard_owned = self.guard_children[id(proc)]
            self.assertEqual((guard_owned["pid"], guard_owned["generation"]), (guard_pid, generation))
            parent_owned = next(item for item in self.owned if item["proc"] is proc)
            self.signal_owned(parent_owned, signal.SIGKILL)
            parent_status, guard_status, _ = self.finish_guard_parent(proc)
            self.assertEqual(parent_status, -signal.SIGKILL)
            self.assertEqual(guard_status.si_status, signal.SIGKILL)
            self.assertIsNone(sentinel.poll())
        finally:
            if sentinel.poll() is None:
                self.signal_owned(sentinel_owned, signal.SIGTERM)
            self.wait_popen(sentinel_owned, 2)

    def test_timeout_stop_cont_and_kill_ends_guard_command_with_status137(self):
        guard, target = self.build_guard()
        self_record = self.work / "guard.pid"
        program = self.work / "program.bt"
        program.write_text("BEGIN { exit(); }\n")
        self.env["IA32_GUARD_TEST_RECORD"] = str(self.work / "guard-target")
        sentinel, sentinel_owned = self.popen_owned(["sleep", "30"])
        driver, driver_owned = self.popen_owned(
            ["sh", str(DRIVER), "guard-timeout", guard, self_record, target, program],
            cwd=ROOT, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            self.wait_file(self.work / "fields")
            self.wait_file(self.work / "guard-target.ready")
            timeout_pid, timeout_generation, _, _ = map(int, (self.work / "fields").read_text().splitlines())
            guard_pid, guard_generation = map(int, self_record.read_text().split())
            timeout_owned = self.own_pid(timeout_pid, timeout_generation)
            guard_owned = self.own_pid(guard_pid, guard_generation)
            timeout_owned["owner_entry"] = driver_owned
            guard_owned["owner_entry"] = timeout_owned
            Path(str(self.work / "guard-target") + ".acquired").touch()
            self.signal_owned(timeout_owned, signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and state(timeout_pid) not in ("T", "t"):
                time.sleep(0.01)
            self.assertIn(state(timeout_pid), ("T", "t"))
            self.assertEqual(starttime(timeout_pid), timeout_generation)
            self.assertEqual(starttime(guard_pid), guard_generation)
            self.signal_owned(timeout_owned, signal.SIGCONT)
            self.signal_owned(timeout_owned, signal.SIGKILL)
            (self.work / "release").touch()
            out, err = driver.communicate(timeout=5)
            self.assertEqual(driver.returncode, 0, err.decode())
            driver_owned["terminal"] = driver.returncode
            self.close_owned(driver_owned)
            self.assertEqual((self.work / "wait").read_text().splitlines()[1], "137")
            self.wait_pidfd(timeout_owned, 2)
            self.wait_pidfd(guard_owned, 2)
            self.assertIsNone(sentinel.poll())
        finally:
            if driver.poll() is None:
                self.signal_owned(driver_owned, signal.SIGKILL)
                self.wait_popen(driver_owned, 2)
            if sentinel.poll() is None:
                self.signal_owned(sentinel_owned, signal.SIGTERM)
            self.wait_popen(sentinel_owned, 2)

    def test_guard_adopted_before_arming_refuses_exec(self):
        proc, parent_record, self_record, guard, target = self.launch_guard_parent("adopt")
        self.wait_file(Path(str(parent_record) + ".child"))
        child, generation = map(int, Path(str(parent_record) + ".child").read_text().split())
        child_owned = self.guard_children[id(proc)]
        self.assertEqual((child_owned["pid"], child_owned["generation"]), (child, generation))
        Path(str(parent_record) + ".release").touch()
        parent_status, result, _ = self.finish_guard_parent(proc)
        self.assertEqual(parent_status, 0)
        self.assertEqual(result.si_status, signal.SIGKILL)
        self.assertFalse(self_record.exists())
        self.assertFalse((self.work / "guard-target.ready").exists())

        proc, parent_record, self_record, _, _ = self.launch_guard_parent("adopt-refusal")
        child_owned = self.guard_children[id(proc)]
        parent_status, result, _ = self.finish_guard_parent(proc)
        self.assertEqual(parent_status, 0)
        self.assertEqual(result.si_status, 2)
        stderr = proc.stderr.read().decode()
        self.assertIn("ia32 trace exec: authenticated parent is no longer current", stderr)
        self.assertFalse(self_record.exists())
        self.assertFalse((self.work / "guard-target.ready").exists())


if __name__ == "__main__":
    names = [name for name in sys.argv[1:] if name != "-v"]
    probe = os.environ.get("P11SCOPE_IA32_RUNNER_PROBE")
    if probe == "empty":
        suite = unittest.TestSuite()
    elif probe == "skip":
        @unittest.skip("runner rejection probe")
        def skipped_probe():
            pass
        suite = unittest.TestSuite([unittest.FunctionTestCase(skipped_probe)])
    elif probe is not None:
        raise SystemExit(f"unknown runner probe: {probe}")
    elif names:
        suite = unittest.defaultTestLoader.loadTestsFromNames(names, module=sys.modules[__name__])
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Ia32LifecycleTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    expected_count = result.testsRun == EXPECTED_DEFAULT_TESTS if not names and probe is None else result.testsRun > 0
    accepted = result.wasSuccessful() and expected_count and not result.skipped
    raise SystemExit(0 if accepted else 1)
