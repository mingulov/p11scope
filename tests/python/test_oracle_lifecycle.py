"""Native lifecycle checks for scripts/matrix/verify-oracle.sh."""

import os
from pathlib import Path
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


def process_starttime(pid):
    fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
    return int(fields[19])


@contextmanager
def quiesce_after_kill(kill_path, events_path, timeout=2.0):
    stop = threading.Event()
    observed = threading.Event()
    errors = []

    def watch():
        deadline = time.monotonic() + timeout
        try:
            while not stop.is_set():
                if kill_path.read_bytes().startswith(b"1"):
                    observed.set()
                    events_path.write_text("populated 0\n")
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
        watcher.join(timeout)


class OracleLifecycleTests(unittest.TestCase):
    def run_fixture(self, scenario, *args, timeout=5, env=None):
        return subprocess.run(
            ["/bin/sh", str(FIXTURE), str(DRIVER), scenario, *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )

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
            deadline = time.monotonic() + 2
            while not record.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(record.exists(), "workload did not publish identity")
            pid, starttime = map(int, record.read_text().split())
            self.assertEqual(pid, process.pid)
            self.assertEqual(starttime, process_starttime(pid))
            with fifo.open("wb", buffering=0) as stream:
                stream.write(b"x")
            self.assertEqual(process.wait(timeout=2), 0)
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
                timeout=2,
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
            timeout=2,
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
                    timeout=2,
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

    def test_hung_descendant_and_observer_first_are_bounded(self):
        result = self.run_fixture("hung-clients", timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "hung=124 observer=1")

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
        foreign = subprocess.Popen(["sleep", "30"])
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
            foreign.wait(timeout=1)

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
