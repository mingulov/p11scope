# SPDX-License-Identifier: GPL-3.0-or-later
"""Native lifecycle checks for scripts/matrix/verify-oracle.sh."""

import math
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager


ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "scripts/matrix/verify-oracle.sh"
WORKLOAD = ROOT / "scripts/matrix/oracle-workload.sh"
CLEANUP = ROOT / "scripts/matrix/oracle-cgroup-cleanup.py"
FIXTURE = ROOT / "tests/fixtures/oracle-lifecycle/scenarios.sh"
# SLACK bounds (waits whose expiry can only mean failure) scale with
# P11SCOPE_TEST_TIME_SCALE, as in test_lane13_evidence.py. SEMANTIC bounds
# a case asserts (the owned-child wait deadline, the wait-query elapsed
# budget, the cleanup helper's kill deadline, and the negative no-EOF
# probes) stay literal. Hung-descendant promptness is not timed at all: the
# case asserts the exact poll/sleep sequence of the product loops, which no
# host load can change.
DEFAULT_TIME_SCALE = 5.0


def _time_scale():
    raw = os.environ.get("P11SCOPE_TEST_TIME_SCALE", "").strip()
    if not raw:
        return DEFAULT_TIME_SCALE
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 1:
        raise SystemExit("P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1")
    return value


TIME_SCALE = _time_scale()


def slack(seconds):
    """Scale a wait-until bound whose expiry can only mean failure."""
    return seconds * TIME_SCALE


def scaled_whole_seconds(seconds):
    """Scale a process lifetime that must outlast SLACK waits; whole seconds."""
    return str(math.ceil(seconds * TIME_SCALE))


def process_starttime(pid):
    fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
    return int(fields[19])


def assert_process_generation_absent(testcase, pid, starttime):
    try:
        current = process_starttime(pid)
    except (FileNotFoundError, ProcessLookupError):
        return
    testcase.assertNotEqual(
        current, starttime, f"process {pid}/{starttime} remains"
    )


def read_process_identity(path):
    try:
        fields = path.read_text().split()
    except (FileNotFoundError, OSError, UnicodeError):
        return None
    if len(fields) != 2:
        return None
    try:
        pid, starttime = map(int, fields)
    except ValueError:
        return None
    if pid <= 0 or starttime <= 0:
        return None
    return pid, starttime


# The product poll loops sleep 0.05 s between live polls; the hung-clients
# scenario gives its hung child oracle_wait_child's limit of 2 attempts.
POLL_SLEEP = "sleep 0.05"
HUNG_WAIT_ATTEMPTS = 2


def wait_process_identity(testcase, path, process, timeout=1.0):
    deadline = time.monotonic() + slack(timeout)
    while time.monotonic() < deadline:
        identity = read_process_identity(path)
        if identity is not None:
            return identity
        if process.poll() is not None:
            break
        time.sleep(0.005)
    testcase.fail("fixture did not publish a complete child identity")


def wait_process_state(testcase, pid, expected, timeout=1.0):
    deadline = time.monotonic() + slack(timeout)
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1][:1]
        except (FileNotFoundError, ProcessLookupError):
            break
        if state == expected:
            return
        time.sleep(0.005)
    testcase.fail(f"process {pid} did not enter state {expected.decode()}")


def terminate_process_generation(pid, starttime, timeout=2.0):
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        try:
            current = process_starttime(pid)
        except (FileNotFoundError, ProcessLookupError):
            return
        if current != starttime:
            return
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    finally:
        os.close(pidfd)
    deadline = time.monotonic() + slack(timeout)
    while time.monotonic() < deadline:
        try:
            if process_starttime(pid) != starttime:
                return
        except (FileNotFoundError, ProcessLookupError):
            return
        time.sleep(0.005)
    raise AssertionError(f"process {pid}/{starttime} remained after SIGKILL")


@contextmanager
def quiesce_after_kill(kill_path, events_path, timeout=2.0):
    stop = threading.Event()
    observed = threading.Event()
    errors = []

    def watch():
        deadline = time.monotonic() + slack(timeout)
        try:
            while not stop.is_set():
                if kill_path.read_bytes().startswith(b"1"):
                    observed.set()
                    # Replace, never truncate: the helper may read the file
                    # at any moment and must see a whole populated line.
                    staged = events_path.with_name(events_path.name + ".next")
                    staged.write_text("populated 0\n")
                    os.replace(staged, events_path)
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    errors.append(AssertionError("timed out waiting for cgroup.kill write"))
                    return
                stop.wait(min(0.005, remaining))
        except BaseException as error:
            errors.append(error)

    watcher = threading.Thread(target=watch)
    watcher.start()

    def assert_observed():
        if watcher.is_alive():
            raise AssertionError("cgroup.kill watcher did not stop")
        if errors:
            raise errors[0]
        if not observed.is_set():
            raise AssertionError("cgroup.kill write was not observed")

    try:
        yield assert_observed
    finally:
        stop.set()
        watcher.join(slack(timeout))


class OracleLifecycleTests(unittest.TestCase):
    def fixture_env(self, env):
        merged = {**os.environ, **(env or {})}
        merged.setdefault(
            "ORACLE_TEST_HOLD_SECONDS", scaled_whole_seconds(30)
        )
        return merged

    def run_fixture(self, scenario, *args, timeout=5, env=None):
        return subprocess.run(
            ["/bin/sh", str(FIXTURE), str(DRIVER), scenario, *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=slack(timeout),
            env=self.fixture_env(env),
        )

    def start_hung_fixture(self, identity, env=None):
        return subprocess.Popen(
            ["/bin/sh", str(FIXTURE), str(DRIVER), "hung-clients", str(identity)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.fixture_env(env),
        )

    def cleanup_hung_fixture(self, process, identity):
        errors = []
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=slack(1))
        except Exception as error:
            errors.append(error)
        published = read_process_identity(identity)
        if published is not None:
            try:
                terminate_process_generation(*published)
            except Exception as error:
                errors.append(error)
        output = ("", "")
        if any(
            stream is not None and not stream.closed
            for stream in (process.stdout, process.stderr)
        ):
            try:
                output = process.communicate(timeout=slack(2))
            except Exception as error:
                errors.append(error)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
        if errors:
            raise errors[0]
        return output

    def test_workload_preserves_quoted_argv_and_fresh_identity(self):
        with tempfile.TemporaryDirectory(prefix="oracle path's ") as raw:
            base = Path(raw)
            fifo = base / "release fifo"
            record = base / "workload pid"
            output = base / "results file"
            capture = base / "client argv"
            config = base / "softhsm conf"
            module = base / "provider's module.so"
            client = base / "fake client"
            os.mkfifo(fifo)
            config.write_text("config\n")
            module.write_text("module\n")
            client.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$PWD\" \"$SOFTHSM2_CONF\" \"$@\" > \"$ARGV_CAPTURE\"\n"
            )
            client.chmod(0o700)
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    str(WORKLOAD),
                    str(record),
                    str(fifo),
                    str(base),
                    str(config),
                    str(client),
                    str(module),
                    str(output),
                    "2",
                ],
                cwd=ROOT,
                env={**os.environ, "ARGV_CAPTURE": str(capture)},
            )
            self.addCleanup(lambda: process.poll() is None and process.kill())
            # Wait for a complete identity, not mere existence: the
            # workload's redirect creates the file before printf writes
            # the "pid starttime" pair, and under load this reader can
            # slip between the two and parse an empty file.
            pid, starttime = wait_process_identity(self, record, process, timeout=2)
            self.assertEqual(pid, process.pid)
            self.assertEqual(starttime, process_starttime(pid))
            with fifo.open("wb", buffering=0) as stream:
                stream.write(b"x")
            self.assertEqual(process.wait(timeout=slack(2)), 0)
            self.assertEqual(
                capture.read_text().splitlines(),
                [
                    str(base),
                    str(config),
                    "test",
                    "--module",
                    str(module),
                    "--pin",
                    "1234",
                    "--slot",
                    "0",
                    "--marker",
                    "smoke",
                    "--isolation",
                    "file",
                    "--rv-trace",
                    "--output",
                    "json",
                    "--output-file",
                    str(output),
                ],
            )

    def test_workload_fifo_disappearance_is_bounded(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            missing = base / "missing-fifo"
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(WORKLOAD),
                    str(base / "pid"),
                    str(missing),
                    str(base),
                    str(base / "conf"),
                    "/bin/true",
                    str(base / "module"),
                    str(base / "output"),
                    "1",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=slack(2),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((base / "pid").exists(), result.stderr)
            self.assertIn("FIFO release failed", result.stderr)

    def run_cleanup(self, operation, directory, *, starttime=None, identity=None, timeout="1"):
        held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, held)
        actual = os.fstat(held)
        expected = identity or (actual.st_dev, actual.st_ino)
        return subprocess.run(
            [
                "python3",
                "-I",
                str(CLEANUP),
                operation,
                str(os.getpid()),
                str(process_starttime(os.getpid()) if starttime is None else starttime),
                str(held),
                str(expected[0]),
                str(expected[1]),
                timeout,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=slack(2),
        )

    def test_cleanup_helper_probes_and_kills_through_receipt_fd(self):
        with tempfile.TemporaryDirectory() as raw:
            cgroup = Path(raw) / "owned"
            cgroup.mkdir()
            kill = cgroup / "cgroup.kill"
            events = cgroup / "cgroup.events"
            kill.write_text("")
            events.write_text("populated 0\n")
            self.assertEqual(self.run_cleanup("probe", cgroup).returncode, 0)
            events.write_text("populated 1\n")
            with quiesce_after_kill(kill, events) as assert_kill_observed:
                result = self.run_cleanup("kill", cgroup)
            self.assertEqual(result.returncode, 0, result.stderr)
            assert_kill_observed()
            self.assertTrue(kill.read_bytes().startswith(b"1"))

    def test_cleanup_helper_keeps_pinned_instance_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "scope"
            path.mkdir()
            (path / "cgroup.kill").write_text("")
            (path / "cgroup.events").write_text("populated 1\n")
            held = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, held)
            identity = os.fstat(held)
            old = Path(raw) / "old-scope"
            path.rename(old)
            path.mkdir()
            foreign_kill = path / "cgroup.kill"
            foreign_kill.write_text("foreign\n")
            (path / "cgroup.events").write_text("populated 1\n")
            with quiesce_after_kill(
                old / "cgroup.kill", old / "cgroup.events"
            ) as assert_kill_observed:
                result = subprocess.run(
                    [
                        "python3",
                        "-I",
                        str(CLEANUP),
                        "kill",
                        str(os.getpid()),
                        str(process_starttime(os.getpid())),
                        str(held),
                        str(identity.st_dev),
                        str(identity.st_ino),
                        "1",
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    timeout=slack(2),
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            assert_kill_observed()
            self.assertTrue((old / "cgroup.kill").read_bytes().startswith(b"1"))
            self.assertEqual(foreign_kill.read_text(), "foreign\n")

    def test_cleanup_helper_rejects_identity_and_missing_control(self):
        with tempfile.TemporaryDirectory() as raw:
            cgroup = Path(raw)
            (cgroup / "cgroup.events").write_text("populated 0\n")
            wrong_generation = self.run_cleanup(
                "probe", cgroup, starttime=process_starttime(os.getpid()) + 1
            )
            wrong_inode = self.run_cleanup("probe", cgroup, identity=(1, 1))
            missing_control = self.run_cleanup("probe", cgroup)
            for result in (wrong_generation, wrong_inode, missing_control):
                self.assertNotEqual(result.returncode, 0)
            self.assertIn("receipt process generation changed", wrong_generation.stderr)
            self.assertIn("cgroup directory identity changed", wrong_inode.stderr)
            self.assertIn("cgroup.kill unavailable", missing_control.stderr)

    def test_body_runs_probe_before_fifo_and_preserves_errexit(self):
        with tempfile.TemporaryDirectory() as raw:
            events = Path(raw) / "events"
            result = self.run_fixture("body", events)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                events.read_text().splitlines(),
                [
                    "build", "token", "discover", "state-start", "launch",
                    "authenticate", "scope-facts", "observer", "ready", "probe", "fifo",
                    "waits", "state-ids", "reclaim", "subset",
                ],
            )
            failed = self.run_fixture("body", events, env={"FAIL_DISCOVER": "9"})
            self.assertEqual(failed.returncode, 9)
            self.assertEqual(events.read_text().splitlines()[-3:], ["build", "token", "discover"])
            probe_denied = self.run_fixture("body", events, env={"FAIL_PROBE": "8"})
            self.assertEqual(probe_denied.returncode, 8)
            self.assertEqual(events.read_text().splitlines()[-2:], ["ready", "probe"])

    def test_finalizer_runs_cleanup_checks_then_one_publication(self):
        with tempfile.TemporaryDirectory() as raw:
            events = Path(raw) / "events"
            success = self.run_fixture("finalizer", events, "success")
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(events.read_text().splitlines(), ["cleanup-start", "cleanup-finished", "terminal-checks", "validate", "publish:0"])
            events.unlink()
            failure = self.run_fixture("finalizer", events, "failure")
            self.assertNotEqual(failure.returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ["cleanup-start", "cleanup-finished", "terminal-checks", "validate", "publish:1"])
            events.unlink()
            cleanup_failure = self.run_fixture("finalizer", events, "success", env={"CLEANUP_RC": "7"})
            self.assertNotEqual(cleanup_failure.returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ["cleanup-start", "cleanup-finished", "terminal-checks", "validate", "publish:1"])
            events.unlink()
            term = self.run_fixture("finalizer", events, "term")
            self.assertEqual(term.returncode, 143)
            self.assertEqual(events.read_text().splitlines(), ["cleanup-start", "cleanup-finished", "terminal-checks", "validate", "publish:143"])
            events.unlink()
            publication = self.run_fixture("finalizer", events, "success", env={"PUBLISH_RC": "8"})
            self.assertNotEqual(publication.returncode, 0)
            self.assertEqual(events.read_text().splitlines().count("publish:0"), 1)

    def test_actual_publication_refuses_existing_pending_entry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "receipt"
            root.mkdir()
            result = self.run_fixture("publication", root)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "status").exists())

    def test_cleanup_refuses_unacknowledged_launch_and_orders_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            events = Path(raw) / "events"
            sentinel = Path(raw) / "foreign-scope-sentinel"
            sentinel.write_text("foreign\n")
            foreign = self.run_fixture("cleanup", events, sentinel)
            self.assertNotEqual(foreign.returncode, 0)
            self.assertNotIn(
                "cgroup", events.read_text().splitlines() if events.exists() else []
            )
            self.assertEqual(sentinel.read_text(), "foreign\n")
            events.unlink(missing_ok=True)
            owned = self.run_fixture("cleanup", events, sentinel, env={"PINNED": "1"})
            self.assertEqual(owned.returncode, 0, owned.stderr)
            self.assertEqual(events.read_text().splitlines(), ["cgroup", "observer", "launcher", "reclaim", "state"])

    def test_owned_child_wait_has_a_deadline(self):
        started = time.monotonic()
        result = self.run_fixture("wait-deadline", timeout=3)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertLess(time.monotonic() - started, 2)

    def run_hung_descendant_case(self):
        """Run hung-clients with every product poll and sleep logged.

        Returns the hung child's pid, its hold argument, and the event log:
        `poll PID LABEL` per liveness poll (poll-log.py interposes the
        recorded-process helper) and `sleep ARGS` per sleep (a PATH shim
        that execs the real sleep, so the hold keeps its pid and
        starttime).
        """
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            identity = directory / "hung.identity"
            events = directory / "events.log"
            shim_dir = directory / "bin"
            shim_dir.mkdir()
            real_sleep = shutil.which("sleep")
            self.assertIsNotNone(real_sleep, "sleep is required")
            shim = shim_dir / "sleep"
            shim.write_text(
                "#!/bin/sh\n"
                "printf 'sleep %s\\n' \"$*\" >> \"$ORACLE_TEST_EVENT_LOG\"\n"
                f"exec {shlex.quote(real_sleep)} \"$@\"\n"
            )
            shim.chmod(0o700)
            env = {
                "ORACLE_TEST_EVENT_LOG": str(events),
                "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            }
            hold = self.fixture_env(env)["ORACLE_TEST_HOLD_SECONDS"]
            # Capturing the fixture's real stdout makes communicate wait for EOF
            # from every inheriting descendant; a leaked sleep cannot be hidden.
            process = self.start_hung_fixture(identity, env=env)
            try:
                pid, starttime = wait_process_identity(self, identity, process)
                stdout, stderr = process.communicate(timeout=slack(3))
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "hung=124 observer=1")
                assert_process_generation_absent(self, pid, starttime)
                return pid, hold, events.read_text().splitlines()
            finally:
                self.cleanup_hung_fixture(process, identity)

    def assert_hung_poll_rounds(self, events, hung_pid, hold):
        """Assert the exact round structure of the hung-clients scenario.

        - hold: exactly one `sleep HOLD` (the hung child).
        - wait: exactly HUNG_WAIT_ATTEMPTS live polls of the hung child,
          each followed by exactly one 0.05 s poll sleep, then 124.
        - terminate: exactly one live check, then KILL (not logged).
        - reap, then observer wait: each loop ends at its first terminal
          poll (gone/zombie); any live poll before it, which only the
          kernel's exit latency can produce, costs exactly one 0.05 s
          sleep.
        Nothing else may appear: an added round, an extra or longer sleep,
        or a poll after the terminal one fails, whatever the host load.
        """
        remaining = list(events)

        def take(expected):
            self.assertTrue(remaining, f"event log ended before {expected}: {events}")
            return remaining.pop(0)

        def settle(pid, phase):
            while True:
                fields = take(f"{phase} poll").split()
                self.assertEqual(len(fields), 3, f"{phase}: {events}")
                self.assertEqual(fields[:2], ["poll", pid], f"{phase}: {events}")
                if fields[2] in ("gone", "zombie"):
                    return
                self.assertEqual(fields[2], "live", f"{phase}: {events}")
                self.assertEqual(take(f"{phase} sleep"), POLL_SLEEP, f"{phase}: {events}")

        hung = str(hung_pid)
        self.assertEqual(take("hold"), f"sleep {hold}", events)
        for attempt in range(HUNG_WAIT_ATTEMPTS):
            self.assertEqual(take(f"wait poll {attempt}"), f"poll {hung} live", events)
            self.assertEqual(take(f"wait sleep {attempt}"), POLL_SLEEP, events)
        self.assertEqual(take("terminate check"), f"poll {hung} live", events)
        settle(hung, "reap")
        self.assertTrue(remaining, f"observer never polled: {events}")
        observer = remaining[0].split()[1:2]
        self.assertNotEqual(observer, [hung], f"hung child polled after reap: {events}")
        settle(observer[0] if observer else "", "observer")
        self.assertEqual(remaining, [], f"unexpected trailing events: {events}")

    def test_hung_descendant_is_terminated_reaped_and_closes_capture_pipe(self):
        # Promptness is structural, not timed: the hung-path wait makes
        # exactly its 2 attempts, the reap and observer loops stop at the
        # first terminal poll, and every sleep is one accounted 0.05 s poll
        # sleep. That catches a hung or round-adding finalization on any
        # host, where a wall-clock or relative bound could not (a planted
        # 2 s reap stall slipped past an 8x-of-control bound under load).
        # A truly hung wait still trips the communicate guard. Every run
        # proves termination, reaping, and capture-pipe closure.
        hung_pid, hold, events = self.run_hung_descendant_case()
        self.assert_hung_poll_rounds(events, hung_pid, hold)

    def test_outer_timeout_cleans_published_descendant_and_capture_pipe(self):
        with tempfile.TemporaryDirectory() as raw:
            identity = Path(raw) / "hung.identity"
            process = self.start_hung_fixture(
                identity, env={"STOP_AFTER_IDENTITY": "1"}
            )
            try:
                pid, starttime = wait_process_identity(self, identity, process)
                wait_process_state(self, process.pid, b"T")
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(timeout=0.05)
                process.kill()
                process.wait(timeout=slack(1))
                self.assertEqual(process_starttime(pid), starttime)
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(timeout=0.05)
                stdout, stderr = self.cleanup_hung_fixture(process, identity)
                self.assertEqual(process.returncode, -signal.SIGKILL, stderr)
                self.assertEqual(stdout, "")
                assert_process_generation_absent(self, pid, starttime)
            finally:
                self.cleanup_hung_fixture(process, identity)

    def test_parent_cleanup_ignores_unauthenticated_identity_receipts(self):
        decoy = subprocess.Popen(["sleep", scaled_whole_seconds(30)])
        try:
            decoy_start = process_starttime(decoy.pid)
            receipts = (
                f"{decoy.pid}\n",
                f"{decoy.pid} invalid\n",
                f"{decoy.pid} {decoy_start} extra\n",
                "",
                None,
            )
            with tempfile.TemporaryDirectory() as raw:
                identity = Path(raw) / "hung.identity"
                for receipt in receipts:
                    with self.subTest(receipt=receipt):
                        identity.unlink(missing_ok=True)
                        if receipt is not None:
                            identity.write_text(receipt)
                        process = subprocess.Popen(
                            ["/bin/true"],
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        try:
                            stdout, stderr = self.cleanup_hung_fixture(
                                process, identity
                            )
                            self.assertEqual((stdout, stderr), ("", ""))
                            self.assertIsNone(decoy.poll())
                        finally:
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=slack(1))
                            for stream in (process.stdout, process.stderr):
                                stream.close()
        finally:
            if decoy.poll() is None:
                decoy.kill()
            decoy.wait(timeout=slack(1))

    def test_authentication_pins_actual_membership_and_rejects_mismatch(self):
        membership = next(
            line.split("::", 1)[1]
            for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")
        )
        cgroup = Path("/sys/fs/cgroup") / membership.lstrip("/")
        accepted = self.run_fixture("authentication", membership, cgroup)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        rejected = self.run_fixture("authentication", membership + "/wrong", cgroup)
        self.assertNotEqual(rejected.returncode, 0)
        wrong_generation = self.run_fixture("authentication", membership, cgroup, env={"WRONG_START": "1"})
        self.assertNotEqual(wrong_generation.returncode, 0)
        unavailable = self.run_fixture("authentication", membership, cgroup, env={"CONTROL_FAIL": "1"})
        self.assertNotEqual(unavailable.returncode, 0)
        with tempfile.TemporaryDirectory() as raw:
            changed = self.run_fixture("authentication", membership, cgroup, Path(raw) / "invocation")
        self.assertNotEqual(changed.returncode, 0)

    def test_identity_query_error_never_enters_bare_wait_or_touches_foreign_process(self):
        foreign = subprocess.Popen(["sleep", scaled_whole_seconds(30)])
        try:
            started = time.monotonic()
            result = self.run_fixture("wait-query-error", foreign.pid, timeout=2)
            self.assertLess(time.monotonic() - started, 0.75)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "wait=2 reap=2 foreign=live")
            self.assertIsNone(foreign.poll())
        finally:
            if foreign.poll() is None:
                foreign.kill()
            foreign.wait(timeout=slack(1))

    def test_repeated_signals_cannot_interrupt_bounded_finalization(self):
        with tempfile.TemporaryDirectory() as raw:
            for signal_name, status in (("term", 143), ("int", 130), ("hup", 129)):
                events = Path(raw) / signal_name
                result = self.run_fixture("finalizer", events, f"repeated-{signal_name}")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(
                    events.read_text().splitlines(),
                    ["cleanup-start", "cleanup-finished", "terminal-checks", "validate", f"publish:{status}"],
                )

    def test_reclaim_limits_transfer_to_known_root_output_scope(self):
        fixture_path = str(FIXTURE.parent) + os.pathsep + os.environ["PATH"]
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            sibling = base / "sibling"
            work = base / "work"
            sibling.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            reports = work / "reports"
            tokens = work / "tokens"
            target = work / "target" / "release"
            deps = work / "target" / "deps"
            for directory in (reports, tokens, target, deps):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            for output in (
                work / "observed.json",
                work / "observer.pid",
                work / "systemd-run.pid",
                work / "workload.pid",
                reports / "report.jsonl",
                tokens / "token.object",
            ):
                output.write_text("evidence\n")
                output.chmod(0o600)
            os.mkfifo(work / "go", 0o600)
            cargo_binary = target / "p11scope"
            cargo_binary.write_text("caller build\n")
            cargo_binary.chmod(0o700)
            os.link(cargo_binary, deps / "p11scope-hash")
            report_link = reports / "report-copy.jsonl"
            os.link(reports / "report.jsonl", report_link)
            unrelated = work / "unrelated-link"
            unrelated.symlink_to(base / "outside")
            cargo_before = cargo_binary.stat()
            report_before = (reports / "report.jsonl").stat()
            fifo_before = (work / "go").lstat()
            accepted = self.run_fixture(
                "reclaim", work, sibling, env={"PATH": fixture_path}
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            cargo_after = cargo_binary.stat()
            fifo_after = (work / "go").lstat()
            self.assertEqual(
                (cargo_after.st_ino, cargo_after.st_nlink, cargo_after.st_uid, cargo_after.st_mode),
                (cargo_before.st_ino, cargo_before.st_nlink, cargo_before.st_uid, cargo_before.st_mode),
            )
            self.assertEqual(
                (fifo_after.st_ino, fifo_after.st_uid, fifo_after.st_mode),
                (fifo_before.st_ino, fifo_before.st_uid, fifo_before.st_mode),
            )
            report_after = (reports / "report.jsonl").stat()
            self.assertEqual(
                (report_after.st_ino, report_after.st_nlink, report_after.st_uid, report_after.st_mode),
                (report_before.st_ino, report_before.st_nlink, report_before.st_uid, report_before.st_mode),
            )
            self.assertTrue(unrelated.is_symlink())
            selected_link = reports / "foreign-link"
            selected_link.symlink_to(base / "outside")
            rejected = self.run_fixture(
                "reclaim", work, sibling, env={"PATH": fixture_path}
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("symlink in retained artifacts", rejected.stderr)

    def test_reclaim_rejects_inadmissible_selected_directory_before_descent(self):
        fixture_path = str(FIXTURE.parent) + os.pathsep + os.environ["PATH"]
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            sibling = base / "sibling"
            work = base / "work"
            reports = work / "reports"
            sibling.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            reports.mkdir(mode=0o755)
            # mkdir honors the process umask (0700 under 077); the
            # subtree must stay non-private for the rejection below.
            reports.chmod(0o755)
            child = reports / "child"
            child.write_text("unchanged\n")
            child.chmod(0o600)
            before = child.stat()
            work.chmod(0o755)
            retained_root = self.run_fixture(
                "reclaim", work, sibling, env={"PATH": fixture_path}
            )
            self.assertNotEqual(retained_root.returncode, 0)
            self.assertIn("selected directory is not private", retained_root.stderr)
            work.chmod(0o700)
            selected_subtree = self.run_fixture(
                "reclaim", work, sibling, env={"PATH": fixture_path}
            )
            self.assertNotEqual(selected_subtree.returncode, 0)
            self.assertIn("selected directory is not private", selected_subtree.stderr)
            after = child.stat()
            self.assertEqual(
                (after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                (before.st_ino, before.st_uid, before.st_gid, before.st_mode),
            )

    def test_authenticated_scope_receipt_facts_are_explicit(self):
        with tempfile.TemporaryDirectory() as raw:
            facts = Path(raw) / "facts.log"
            result = self.run_fixture("scope-facts", facts)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                facts.read_text().splitlines(),
                [
                    "authenticated_scope_path\t/sys/fs/cgroup/system.slice/p11scope-oracle.scope",
                    "authenticated_cgroup_identity\t42:99",
                    "authenticated_workload_generation\t123:456",
                    "authenticated_invocation_tuple\tp11scope-oracle.scope:/system.slice/p11scope-oracle.scope:invocation-id",
                ],
            )


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    raise SystemExit(
        0 if result.testsRun > 0 and result.wasSuccessful() and not result.skipped else 1
    )
