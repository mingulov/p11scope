# SPDX-License-Identifier: GPL-3.0-or-later
"""Real unprivileged supervisor checks; runnable from any cwd with Python -I."""

import base64
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests/support/owned_process_group.py"
FIXTURE = ROOT / "tests/fixtures/owned-process-group/workload.py"


class OwnedProcessGroupTests(unittest.TestCase):
    def record_adverse(self, value):
        if os.environ.get("OWNED_GROUP_EVIDENCE"):
            path = Path(os.environ["OWNED_GROUP_EVIDENCE"]) / (self._testMethodName + ".json")
            with path.open("x") as stream:
                json.dump(value, stream, indent=2)

    def await_file(self, path, fd, seconds=3):
        deadline = time.monotonic() + seconds
        while not path.exists() and time.monotonic() < deadline:
            if select.select([fd], [], [], 0.01)[0]:
                break
        self.assertTrue(path.exists(), str(path))

    def await_stopped(self, pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = os.waitid(os.P_PID, pid, os.WSTOPPED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                self.assertEqual(status.si_status, signal.SIGSTOP)
                return
            time.sleep(0.01)
        self.fail("owned supervisor did not stop")

    def test_child_diagnostic_failure_cannot_enter_parent_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="owned-diagnostic-") as directory:
            work = Path(directory)
            receipt, ready = work / "receipt.json", work / "ready"
            args = [sys.executable, "-I", str(FIXTURE.with_name("setup_failure.py")),
                    "contained_diagnostic", "--receipt", str(receipt), "--cwd", directory,
                    "--timeout", "2", "--term-grace", "0.1", "--reap-timeout", "1", "--",
                    sys.executable, "-I", str(FIXTURE), "normal", str(ready)]
            proc = subprocess.Popen(args, cwd="/", start_new_session=True,
                                    env=dict(os.environ, OWNED_GROUP_CONTROL=directory),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            fd = None
            adopted = []
            try:
                fd = os.pidfd_open(proc.pid)
                self.assertTrue(select.select([fd], [], [], 6)[0], "container did not terminate")
            finally:
                # Original unreaped session leader anchors even the dangerous
                # old RED. Do not communicate/poll/reap before final group KILL.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                out, err = proc.communicate(timeout=2)
                if fd is not None:
                    os.close(fd)
                deadline = time.monotonic() + 3
                while True:
                    try:
                        child, status = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if child:
                        adopted.append(dict(pid=child, raw_status=status))
                    elif time.monotonic() >= deadline:
                        self.fail("contained RED cleanup did not reach ECHILD")
                    else:
                        time.sleep(0.01)
            result = json.loads(receipt.read_text()) if receipt.exists() and receipt.stat().st_size else None
            container = (json.loads((work / "container-result.json").read_text())
                         if (work / "container-result.json").exists() else None)
            before = json.loads((work / "child-before-setsid.json").read_text())
            waits = (json.loads((work / "container-waits.json").read_text())
                     if (work / "container-waits.json").exists() else None)
            self.record_adverse(dict(argv=args, cwd="/", exit_code=proc.returncode,
                                     stdout=out.decode(), stderr=err.decode(), receipt=result,
                                     adopted=adopted, container=container, container_waits=waits,
                                     child_before_setsid=before, settled=True))
            self.assertEqual(before["pgid"], proc.pid)
            self.assertEqual(before["sid"], proc.pid)
            self.assertEqual(proc.returncode, 0, "failed diagnostic killed the containing session")
            self.assertTrue(container["decoy_survived"])
            self.assertEqual(container["decoy_identity"]["pgid"], proc.pid)
            self.assertEqual(container["decoy_identity"]["sid"], proc.pid)
            self.assertEqual(container["supervisor_exit"], 1)
            self.assertFalse(ready.exists())
            self.assertTrue(result["settled"])
            self.assertFalse(result["workload_released"])
            self.assertEqual(result["original"]["exit_code"], 127)
            self.assertEqual(result["adopted"], [])
            self.assertEqual(adopted, [])

    def late_observation(self, readiness=False):
        with tempfile.TemporaryDirectory(prefix="owned-late-") as directory:
            work = Path(directory)
            ready, receipt = work / "ready", work / "receipt.json"
            args = [sys.executable, "-I", str(RUNNER), "--receipt", str(receipt),
                    "--cwd", directory, "--timeout", "0.5", "--term-grace", "0.1",
                    "--reap-timeout", "2", "--", sys.executable, "-I", str(FIXTURE),
                    "normal" if readiness else "late_exit", str(ready)]
            if readiness:
                args[2:3] = [str(FIXTURE.with_name("setup_failure.py")), "delayed_ready"]
            proc = subprocess.Popen(args, cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=dict(os.environ, OWNED_GROUP_CONTROL=directory))
            fd = None
            try:
                fd = os.pidfd_open(proc.pid)
                self.await_file(work / "ready-observed" if readiness else ready, fd)
                if not readiness:
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                self.await_stopped(proc.pid)
                # A full timeout after acknowledged STOP guarantees that
                # execution/observation is late regardless of startup timing.
                time.sleep(0.65)
                if not readiness:
                    Path(str(ready) + ".release").write_text("release after operation deadline\n")
                    self.await_file(Path(str(ready) + ".exiting"), fd)
                    time.sleep(0.1)
                signal.pidfd_send_signal(fd, signal.SIGCONT)
                out, err = proc.communicate(timeout=4)
                result = json.loads(receipt.read_text())
                self.record_adverse(dict(argv=args, cwd="/", exit_code=proc.returncode,
                                         stdout=out.decode(), stderr=err.decode(), receipt=result))
                self.assertTrue(result["settled"])
                self.assertEqual(result["adopted"], [])
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["status"], "NONPASS")
                self.assertEqual(result["reason"], "timeout")
                if readiness:
                    self.assertFalse(result["workload_released"])
                    self.assertFalse(ready.exists())
                else:
                    self.assertEqual(result["original"]["exit_code"], 0)
            finally:
                if fd is not None:
                    for signum in (signal.SIGCONT, signal.SIGTERM):
                        try:
                            signal.pidfd_send_signal(fd, signum)
                        except ProcessLookupError:
                            pass
                    try:
                        proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                        proc.wait(timeout=2)
                    os.close(fd)
                else:
                    proc.kill()
                    proc.wait(timeout=2)
                for stream in (proc.stdout, proc.stderr):
                    stream.close()

    def test_late_zero_exit_after_supervisor_stop_is_timeout(self):
        self.late_observation()

    def test_session_readiness_after_deadline_never_releases_workload(self):
        self.late_observation(readiness=True)

    @classmethod
    def setUpClass(cls):
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.old_subreaper = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.old_subreaper), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "test PR_GET_CHILD_SUBREAPER")
        if cls.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "test PR_SET_CHILD_SUBREAPER")

    @classmethod
    def tearDownClass(cls):
        if cls.libc.prctl(36, cls.old_subreaper.value, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "restore test subreaper")

    def tearDown(self):
        # Independent fallback: adopt failed-supervisor descendants and wait
        # for their fixture alarms. No PID discovery or late signal authority.
        unexpected = []
        deadline = time.monotonic() + 10
        while True:
            try:
                child, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if child:
                unexpected.append((child, status))
            elif time.monotonic() >= deadline:
                self.fail("test fallback cleanup did not reach ECHILD")
            else:
                time.sleep(0.02)
        self.assertEqual(unexpected, [], "supervisor left adopted children to its test parent")

    def run_case(self, mode, cancel=False, argv=None, setup_failure=None):
        # Fixture alarms are an independent eight-second fallback. The test
        # retains the original supervisor pidfd; it never discovers PIDs.
        self.assertTrue(RUNNER.is_file(), "owned supervisor has not been implemented")
        with tempfile.TemporaryDirectory(prefix="owned-group-") as directory:
            work = Path(directory)
            ready, receipt = work / "ready.json", work / "receipt.json"
            command = argv or [sys.executable, "-I", str(FIXTURE), mode, str(ready)]
            args = [sys.executable, "-I", str(RUNNER), "--receipt", str(receipt),
                    "--cwd", directory, "--timeout", "0.3" if mode == "timeout" else "3",
                    "--term-grace", "0.1", "--reap-timeout", "2", "--", *command]
            if setup_failure:
                args[2:3] = [str(FIXTURE.with_name("setup_failure.py")), setup_failure]
            proc = subprocess.Popen(args, cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            fd = None
            try:
                fd = os.pidfd_open(proc.pid)
                if cancel:
                    deadline = time.monotonic() + 3
                    while not ready.exists() and time.monotonic() < deadline:
                        if select.select([fd], [], [], 0.01)[0]:
                            break
                    self.assertTrue(ready.exists(), "fixture never reached cancellation gate")
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
                out, err = proc.communicate(timeout=6)
                self.assertTrue(receipt.exists(), (proc.returncode, out, err))
                result = json.loads(receipt.read_text())
                if os.environ.get("OWNED_GROUP_EVIDENCE"):
                    evidence = Path(os.environ["OWNED_GROUP_EVIDENCE"])
                    with (evidence / (self._testMethodName + ".json")).open("x") as stream:
                        json.dump(dict(argv=args, cwd="/", exit_code=proc.returncode,
                                       stdout=out.decode(), stderr=err.decode(), receipt=result), stream, indent=2)
                self.assertEqual(result["argv"], command)
                self.assertEqual(result["cwd"], directory)
                self.assertTrue(result["settled"], result)
                self.assertEqual(proc.returncode, 0 if result["status"] == "PASS" else 1)
                if not setup_failure:
                    self.assertEqual(result["errors"], [], result)
                else:
                    self.assertFalse(ready.exists(), "workload executed after setup refusal")
                if ready.exists():
                    identities = json.loads(ready.read_text())
                    self.assertEqual(result["original"]["pid"], identities["leader"])
                    self.assertEqual(identities["pgid"], identities["leader"])
                    self.assertEqual(identities["sid"], identities["leader"])
                    adopted = {item["pid"]: item for item in result["adopted"]}
                    self.assertEqual(set(adopted), {identities["child"]} if "child" in identities else set())
                return result
            finally:
                # Signal only through the original retained descriptor, even
                # if communicate has already reaped the supervisor.
                if fd is not None:
                    if proc.returncode is None:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            proc.wait(timeout=4)
                        except subprocess.TimeoutExpired:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                            proc.wait(timeout=2)
                    os.close(fd)
                else:
                    proc.kill()
                    proc.wait(timeout=2)
                for stream in (proc.stdout, proc.stderr):
                    stream.close()

    def test_normal_zero_passes_without_treating_zombie_group_signal_as_rescue(self):
        result = self.run_case("normal")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["original"]["exit_code"], 0)
        self.assertFalse(result["rescue"])
        self.assertEqual(result["stdout"], "fixture stdout\n")
        self.assertEqual(result["stderr"], "fixture stderr\n")

    def test_nonzero_status_cannot_pass(self):
        result = self.run_case("nonzero")
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["original"]["exit_code"], 23)

    def test_exited_leader_with_live_orphan_is_killed_reaped_and_nonpass(self):
        result = self.run_case("orphan")
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["original"]["exit_code"], 0)
        self.assertEqual(result["adopted"][0]["signal"], signal.SIGKILL)
        self.assertTrue(result["rescue"])

    def test_preexisting_adopted_zombie_is_nonpass_with_exact_exit(self):
        result = self.run_case("zombie")
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["adopted"][0]["exit_code"], 7)

    def test_timeout_settles_term_ignoring_leader_and_child(self):
        result = self.run_case("timeout")
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(result["original"]["signal"], signal.SIGKILL)
        self.assertEqual(result["adopted"][0]["signal"], signal.SIGKILL)

    def test_supervisor_term_settles_term_ignoring_leader_and_child(self):
        result = self.run_case("cancel", cancel=True)
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["reason"], "cancellation")
        self.assertEqual(result["cancellation_signal"], signal.SIGTERM)
        self.assertEqual(result["original"]["signal"], signal.SIGKILL)
        self.assertEqual(result["adopted"][0]["signal"], signal.SIGKILL)

    def test_binary_stdout_is_preserved_exactly(self):
        result = self.run_case("binary")
        self.assertEqual(base64.b64decode(result["stdout_base64"]), b"fixture stdout\n\x00\xff")

    def test_exec_failure_is_nonpass_with_original_wait_result(self):
        result = self.run_case("missing", argv=["/owned-process-group-no-such-command"])
        self.assertEqual(result["status"], "NONPASS")
        self.assertEqual(result["original"]["exit_code"], 127)
        self.assertIn("FileNotFoundError", result["stderr"])

    def test_pidfd_refusal_settles_gated_child_without_executing_workload(self):
        result = self.run_case("normal", setup_failure="pidfd")
        self.assertEqual(result["status"], "NONPASS")
        self.assertFalse(result["workload_released"])
        self.assertEqual(result["original"]["signal"], signal.SIGKILL)
        self.assertEqual(result["adopted"], [])
        self.assertIn("injected pidfd refusal", result["errors"][0])

    def test_prctl_refusal_prevents_any_child_launch(self):
        result = self.run_case("normal", setup_failure="prctl")
        self.assertEqual(result["status"], "NONPASS")
        self.assertFalse(result["workload_released"])
        self.assertIsNone(result["original"])
        self.assertEqual(result["adopted"], [])
        self.assertIn("injected prctl refusal", result["errors"][0])

    def test_separately_owned_same_fixture_survives_group_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="owned-survivor-") as directory:
            ready = Path(directory) / "ready.json"
            proc = subprocess.Popen([sys.executable, "-I", str(FIXTURE), "survivor", str(ready)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fd = None
            try:
                fd = os.pidfd_open(proc.pid)
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    if select.select([fd], [], [], 0.01)[0]:
                        break
                self.assertTrue(ready.exists())
                result = self.run_case("timeout")
                self.assertEqual(result["reason"], "timeout")
                self.assertFalse(select.select([fd], [], [], 0)[0], "unrelated owned fixture was killed")
            finally:
                if fd is not None:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(fd)
                else:
                    proc.kill()
                proc.wait(timeout=2)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    raise SystemExit(
        0 if result.testsRun > 0 and result.wasSuccessful() and not result.skipped else 1
    )
