#!/usr/bin/env python3
"""Native tests for the fixed offline recipient coordinator."""

import json
import importlib.util
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


REPOSITORY = Path(__file__).resolve().parents[2]
FIXTURES = REPOSITORY / "tests/fixtures/build-offline"
OFFLINE_TESTS = REPOSITORY / "tests/python/test_offline_dependencies.py"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


OFFLINE_FIXTURES = load_module(OFFLINE_TESTS, "build_offline_real_fixture")
BUILD_MODULE = load_module(REPOSITORY / "scripts/build-offline.py", "build_offline_module")


def restrictive_child_umask():
    os.umask(0o777)


def _wait_for_descendant_not_live(pid, *, proc_root=Path("/proc"), timeout=10.0):
    """Wait for a non-child fixture process to disappear or become terminal."""
    if pid <= 0:
        raise AssertionError(f"invalid descendant pid {pid}")
    stat_path = proc_root / str(pid) / "stat"
    deadline = time.monotonic() + timeout
    while True:
        try:
            raw = stat_path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise AssertionError(f"cannot inspect descendant {pid}: {error}") from error
        try:
            identity, fields = raw.rsplit(b") ", 1)
            expected = str(pid).encode("ascii") + b" ("
            if not identity.startswith(expected):
                raise ValueError("pid identity changed")
            state = fields.split()[0].decode("ascii")
        except (UnicodeError, ValueError, IndexError):
            raise AssertionError(f"malformed /proc/{pid}/stat") from None
        if state in {"Z", "X", "x"}:
            return None
        if state not in {"R", "S", "D", "T", "t", "W", "K", "I", "P"}:
            raise AssertionError(f"unknown /proc/{pid}/stat state {state!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"descendant {pid} remained live")
        time.sleep(0.02)


def _pidfd_exit_ready(pidfd, timeout):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP)
    return bool(poller.poll(max(1, int(timeout * 1000))))


def _terminate_exact_descendant(pidfd, timeout=2.0):
    try:
        if not _pidfd_exit_ready(pidfd, timeout):
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            if not _pidfd_exit_ready(pidfd, timeout):
                raise AssertionError("descendant remained live after pidfd SIGKILL")
    finally:
        os.close(pidfd)


def _settle_coordinator(process, timeout=2.0):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


class BuildOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-build-offline-")
        self.base = Path(self.temporary.name)
        self.source = self.base / "source with spaces"
        self.source.mkdir()
        (self.source / "scripts").mkdir()
        (self.source / "third-party/offline").mkdir(parents=True)
        (self.source / ".cargo").mkdir()
        (self.source / "test-record").mkdir()
        copies = {
            REPOSITORY / "scripts/build-offline.py": self.source / "scripts/build-offline.py",
            REPOSITORY / "scripts/build-offline.sh": self.source / "scripts/build-offline.sh",
            REPOSITORY / "scripts/prepared-dependency-tools.sh":
                self.source / "scripts/prepared-dependency-tools.sh",
            FIXTURES / "export-source.py": self.source / "scripts/export-source.py",
            FIXTURES / "offline-dependencies.py": self.source / "scripts/offline-dependencies.py",
            FIXTURES / "product-build.sh": self.source / "scripts/product-build.sh",
        }
        for source, target in copies.items():
            shutil.copyfile(source, target)
        (self.source / "scripts/prepare-dependencies.py").write_text("# fixture\n", encoding="utf-8")
        for name in (".p11scope-source-export.json", ".cargo/config.toml",
                     "third-party/offline-dependencies.json", "third-party/offline/marker",
                     "bound-input"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original", encoding="utf-8")
        shutil.copyfile(FIXTURES / "rustup.py", self.source / "rustup")
        for name in ("rustup", "stable-cargo", "stable-rustc", "bpf-cargo",
                     "bpf-rustc", "bpf-linker"):
            if name != "rustup":
                shutil.copyfile(FIXTURES / "tool.py", self.source / name)
            (self.source / name).chmod(0o755)
        self.control({})

    def tearDown(self):
        self.temporary.cleanup()

    def control(self, value):
        (self.source / "test-control.json").write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8")

    def command(self, work, *, wrapper=True):
        if wrapper:
            return ["/bin/sh", "scripts/build-offline.sh", str(work)]
        return ["/usr/bin/python3", "-I", "scripts/build-offline.py", str(work)]

    def run_build(self, work=None, *, wrapper=True, environment=None, restrictive_umask=False):
        work = work or self.base / "work with spaces"
        env = {"PATH": f"{self.source}:/usr/bin:/bin", "LC_ALL": "C"}
        if environment:
            env.update(environment)
        return subprocess.run(self.command(work, wrapper=wrapper), cwd=self.source, env=env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              preexec_fn=restrictive_child_umask if restrictive_umask else None)

    def rows(self, name):
        path = self.source / "test-record" / name
        return [json.loads(row) for row in path.read_text(encoding="utf-8").splitlines()]

    def generated_identity(self):
        generated = self.source / "third-party/src/demo-1.0/content"
        lock = self.source / "third-party/.prepare-dependencies.lock"
        return (generated.read_bytes(), generated.stat().st_mode, generated.stat().st_mtime_ns,
                lock.stat().st_ino, lock.stat().st_mode, lock.stat().st_mtime_ns)

    def test_happy_path_exact_forwarding_clean_environment_and_deterministic_evidence(self):
        work = self.base / "work with spaces"
        result = self.run_build(work)
        self.assertEqual(result.returncode, 0, result.stderr)
        validates = self.rows("validate.jsonl")
        self.assertEqual([row["prepared"] for row in validates], ["allow", "require", "require"])
        self.assertTrue(all(row["environment"] == {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
                            for row in validates))
        offline = self.rows("offline.jsonl")
        self.assertEqual(len(offline), 2)
        self.assertNotIn("--check-prepared", offline[0]["argv"])
        self.assertIn("--check-prepared", offline[1]["argv"])
        for row in offline:
            self.assertEqual(row["environment"]["RUSTUP_AUTO_INSTALL"], "0")
            self.assertEqual(row["environment"]["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(row["environment"]["PATH"], "/usr/bin:/bin")
            self.assertNotIn("http_proxy", row["environment"])
        builds = [row for row in self.rows("tools.jsonl") if row["role"] == "stable-cargo"]
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0]["argv"], ["build", "--locked", "--offline", "--release",
                                             "--workspace", "--no-default-features",
                                             "--target-dir", str(work / "target")])
        self.assertEqual(builds[0]["environment"]["PATH"],
                         f"{work / 'cargo-home/bin'}:/usr/bin:/bin")
        self.assertEqual(os.listdir(work / "cargo-home/bin"), ["bpf-linker"])
        evidence_path = work / "evidence/build-offline.json"
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
        self.assertEqual(evidence_bytes, (json.dumps(evidence, sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"))
        self.assertEqual(stat.S_IMODE(evidence_path.stat().st_mode), 0o600)
        self.assertNotIn(str(self.source), evidence_bytes.decode("ascii"))
        self.assertNotIn(str(work), evidence_bytes.decode("ascii"))
        final_marker = self.source / "test-record/final-validation-returned"
        self.assertFalse((self.source / "test-record/callback-after-final").exists())
        final_marker.unlink()
        retry_work = self.base / "deterministic retry"
        retry = self.run_build(retry_work)
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual((retry_work / "evidence/build-offline.json").read_bytes(), evidence_bytes)

    def test_argument_root_prerequisite_environment_and_no_clobber_refusals(self):
        bad_commands = [
            ["/bin/sh", "scripts/build-offline.sh"],
            ["/bin/sh", "scripts/build-offline.sh", "relative"],
            ["/bin/sh", "scripts/build-offline.sh", str(self.base / "x/../work")],
            ["/bin/sh", "scripts/build-offline.sh", str(self.source / "inside")],
        ]
        env = {"PATH": f"{self.source}:/usr/bin:/bin", "LC_ALL": "C"}
        for command in bad_commands:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=self.source, env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertNotEqual(result.returncode, 0)
        existing = self.base / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        self.assertNotEqual(self.run_build(existing).returncode, 0)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        self.assertNotEqual(self.run_build(self.base / "ambient",
                                           environment={"RUSTFLAGS": "bad"}).returncode, 0)
        prerequisite = self.source / ".cargo/config.toml"
        prerequisite.rename(self.source / ".cargo/config.saved")
        work = self.base / "missing"
        result = self.run_build(work)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(work.exists())

    def test_colon_work_root_refuses_proven_foreign_linker_path_before_creation(self):
        foreign = self.base / "foreign/cargo-home/bin"
        foreign.mkdir(parents=True)
        marker = self.base / "foreign-linker-ran"
        linker = foreign / "bpf-linker"
        linker.write_text(f"#!/bin/sh\n: > '{marker}'\n", encoding="utf-8")
        linker.chmod(0o755)
        vulnerable = self.base / f"work:{self.base / 'foreign'}"
        subprocess.run(["bpf-linker"],
                       env={"PATH": f"{vulnerable}/cargo-home/bin:/usr/bin:/bin"}, check=True)
        self.assertTrue(marker.exists(), "counterexample PATH must reach the foreign linker")
        marker.unlink()
        result = self.run_build(vulnerable)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("colon", result.stderr)
        self.assertFalse(vulnerable.exists())
        self.assertFalse(marker.exists())

    def test_restrictive_inherited_umask_produces_private_modes_and_cleans_failure(self):
        work = self.base / "restrictive-success"
        result = self.run_build(work, restrictive_umask=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative in ("", "cargo-home", "cargo-home/bin", "target", "evidence",
                         "evidence/private", "home"):
            path = work if not relative else work / relative
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, relative)

        for record in (self.source / "test-record").iterdir():
            record.unlink()
        self.control({"validator_fail": 1})
        failed_work = self.base / "restrictive-validation-failure"
        failed = self.run_build(failed_work, restrictive_umask=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("validation", failed.stderr)
        self.assertFalse(failed_work.exists())

    def test_in_process_main_restores_callers_umask(self):
        original = os.umask(0o027)
        observed = []
        try:
            def inspect_umask(_arguments):
                current = os.umask(0o077)
                os.umask(current)
                observed.append(current)
                return 0

            with mock.patch.object(BUILD_MODULE, "_main", side_effect=inspect_umask):
                self.assertEqual(BUILD_MODULE.main([]), 0)
            restored = os.umask(0o027)
            self.assertEqual(observed, [0o077])
            self.assertEqual(restored, 0o027)
        finally:
            os.umask(original)

    def test_failures_cleanup_private_work_and_preserve_prepared_retry_state(self):
        for stage in ("reconstruct", "check"):
            with self.subTest(stage=stage):
                self.control({"offline_fail": stage})
                work = self.base / f"fail-{stage}"
                result = self.run_build(work)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(work.exists())
                self.assertTrue(self.rows("offline.jsonl"))
                if stage == "check":
                    before = self.generated_identity()
                    self.control({})
                    retry = self.run_build(self.base / "retry")
                    self.assertEqual(retry.returncode, 0, retry.stderr)
                    self.assertEqual(self.generated_identity(), before)
                shutil.rmtree(self.source / "third-party/src", ignore_errors=True)
                lock = self.source / "third-party/.prepare-dependencies.lock"
                if lock.exists():
                    lock.unlink()
                for record in (self.source / "test-record").iterdir():
                    record.unlink()

    def test_source_unknown_late_config_and_all_private_directory_swaps_fail_closed(self):
        controls = [{"coherent_mutation": True}, {"payload_mutation": True},
                    {"tool_mutation": True}, {"unknown_sibling": True},
                    {"late_config_mutation": True}, {"build_fail": True},
                    {"validator_fail": 2}, {"rustup_fail": "1.88:cargo"},
                    {"prepared_mtime_mutation": True}]
        controls.append({"swap_root_foreign": True})
        controls.extend({"swap_private": name} for name in
                        ("cargo-home", "cargo-home/bin", "target", "evidence",
                         "evidence/private", "home", "."))
        controls.append({"chmod_private": "target"})
        controls.append({"chmod_private": "."})
        for index, control in enumerate(controls):
            with self.subTest(control=control):
                case = self.base / f"case-{index}"
                shutil.copytree(self.source, case)
                (case / "test-record").mkdir(exist_ok=True)
                (case / "test-control.json").write_text(json.dumps(control), encoding="utf-8")
                work = self.base / f"swap-{index}"
                env = {"PATH": f"{case}:/usr/bin:/bin", "LC_ALL": "C"}
                result = subprocess.run(self.command(work), cwd=case, env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertNotEqual(result.returncode, 0)
                if control.get("unknown_sibling"):
                    self.assertEqual((case / "third-party/src/unknown/sentinel").read_text(), "keep")
                if control.get("late_config_mutation"):
                    rows = (case / "test-record/offline.jsonl").read_text()
                    self.assertIn("--check-prepared", rows)
                if control.get("swap_root_foreign"):
                    self.assertEqual((work / "foreign-sentinel").read_text(), "keep")
                    moved = work.with_name(work.name + "-original")
                    self.assertTrue(moved.is_dir())
                    self.assertEqual(list(moved.iterdir()), [])

    def test_partial_evidence_write_refuses_and_cleans_private_work(self):
        work = self.base / "partial-write"
        coordinator = BUILD_MODULE.Coordinator(self.source, work, self.source / "rustup")
        coordinator.tools = coordinator.select_tools()
        coordinator.create_work()
        with mock.patch.object(BUILD_MODULE.os, "write",
                               side_effect=[1, OSError("synthetic short write")]):
            with self.assertRaisesRegex(BUILD_MODULE.Refusal, "publish"):
                coordinator.publish({"revision": "1" * 40})
        coordinator.cleanup()
        self.assertFalse(work.exists())

    def test_popen_return_boundary_signal_is_forwarded_reaped_and_fast(self):
        coordinator = BUILD_MODULE.Coordinator(self.source, self.base / "unused",
                                               self.source / "rustup")
        real_popen = BUILD_MODULE.subprocess.Popen
        marker = self.base / "boundary-child-pid"
        spawned = []

        def signal_before_return(*arguments, **keywords):
            child = real_popen(*arguments, **keywords)
            spawned.append(child.pid)
            coordinator._signal(signal.SIGTERM, None)
            return child

        started = time.monotonic()
        with mock.patch.object(BUILD_MODULE.subprocess, "Popen",
                               side_effect=signal_before_return):
            with self.assertRaises(BUILD_MODULE.Interrupted):
                coordinator.child(
                    ["/usr/bin/python3", "-I", str(FIXTURES / "boundary-child.py")],
                    {"PATH": "/usr/bin:/bin", "P11SCOPE_BOUNDARY_PID": str(marker)},
                    "boundary child")
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNone(coordinator.active)
        self.assertEqual(len(spawned), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(spawned[0], 0)

    def test_descendant_terminal_wait_accepts_zombie_and_rejects_live_or_malformed(self):
        proc_root = self.base / "proc"
        proc_root.mkdir()
        stat_path = proc_root / "41/stat"
        stat_path.parent.mkdir()
        for state in ("Z", "X", "x"):
            stat_path.write_bytes(f"41 (fixture) {state} 1 2 3 4 5".encode())
            self.assertIsNone(_wait_for_descendant_not_live(
                41, proc_root=proc_root, timeout=0.02))

        stat_path.unlink()
        self.assertIsNone(_wait_for_descendant_not_live(
            41, proc_root=proc_root, timeout=0.02))
        stat_path.parent.mkdir(exist_ok=True)

        stat_path.write_bytes(b"41 (fixture) R 1 2 3 4 5")
        with self.assertRaisesRegex(AssertionError, "remained live"):
            _wait_for_descendant_not_live(41, proc_root=proc_root, timeout=0.02)

        stat_path.write_bytes(b"malformed")
        with self.assertRaisesRegex(AssertionError, "malformed"):
            _wait_for_descendant_not_live(41, proc_root=proc_root, timeout=0.02)

    def test_signal_cleanup_kills_descendant_after_coordinator_exit(self):
        descendant = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pidfd = os.pidfd_open(descendant.pid)
        coordinator = subprocess.Popen(
            [sys.executable, "-c", "raise SystemExit(143)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(coordinator.wait(timeout=2), 143)
            self.assertFalse(_pidfd_exit_ready(pidfd, 0.02))
            _terminate_exact_descendant(pidfd)
            pidfd = None
            descendant.wait(timeout=2)
            self.assertIsNotNone(descendant.returncode)
        finally:
            if pidfd is not None:
                _terminate_exact_descendant(pidfd)
            _settle_coordinator(coordinator)
            if descendant.poll() is None:
                descendant.kill()
                descendant.wait(timeout=2)
            for stream in (descendant.stdout, descendant.stderr):
                if stream is not None:
                    stream.close()

    def test_evidence_collisions_refuse_without_modifying_external_sentinel(self):
        for kind in ("regular", "symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                self.control({"evidence_collision": kind})
                external = self.source / "external-sentinel"
                external.write_text("keep", encoding="utf-8")
                work = self.base / f"collision-{kind}"
                result = self.run_build(work)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(external.read_text(encoding="utf-8"), "keep")
                self.assertFalse(work.exists())
                shutil.rmtree(self.source / "third-party/src", ignore_errors=True)
                lock = self.source / "third-party/.prepare-dependencies.lock"
                if lock.exists():
                    lock.unlink()
                for record in (self.source / "test-record").iterdir():
                    record.unlink()

    def test_direct_and_wrapper_signals_forward_terminal_cleanup_and_return_signal_status(self):
        for wrapper in (False, True):
            for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                with self.subTest(wrapper=wrapper, signal=number):
                    process = None
                    child_pidfd = None
                    work = self.base / f"signal-{wrapper}-{number}"
                    try:
                        self.control({"hold": True})
                        for record in (self.source / "test-record").iterdir():
                            record.unlink()
                        shutil.rmtree(self.source / "third-party/src", ignore_errors=True)
                        (self.source / "third-party/.prepare-dependencies.lock").unlink(
                            missing_ok=True)
                        env = {"PATH": f"{self.source}:/usr/bin:/bin", "LC_ALL": "C"}
                        process = subprocess.Popen(
                            self.command(work, wrapper=wrapper), cwd=self.source,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        marker = self.source / "test-record/child-pid"
                        deadline = time.monotonic() + 10
                        while (not marker.exists() and process.poll() is None
                               and time.monotonic() < deadline):
                            time.sleep(0.02)
                        self.assertTrue(marker.exists())
                        child = int(marker.read_text(encoding="ascii"))
                        child_pidfd = os.pidfd_open(child)
                        process.send_signal(number)
                        process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 128 + number)
                        self.assertFalse(work.exists())
                        _wait_for_descendant_not_live(child)
                    finally:
                        if child_pidfd is not None:
                            _terminate_exact_descendant(child_pidfd)
                        if process is not None:
                            _settle_coordinator(process)
                        shutil.rmtree(work, ignore_errors=True)
                        shutil.rmtree(self.source / "third-party/src", ignore_errors=True)
                        (self.source / "third-party/.prepare-dependencies.lock").unlink(
                            missing_ok=True)
                        for record in (self.source / "test-record").iterdir():
                            record.unlink()

    def test_real_export_extract_verifier_preparer_and_product_helper_compose(self):
        base = self.base / "real integration"
        base.mkdir()
        fixture = OFFLINE_FIXTURES.OfflineFixture(base)
        fixture.testcase = self
        fixture.assemble()
        fixture.approve()
        for name in ("build-offline.py", "build-offline.sh", "product-build.sh",
                     "prepared-dependency-tools.sh", "export-source.py"):
            shutil.copy2(REPOSITORY / "scripts" / name, fixture.root / "scripts" / name)
        shutil.rmtree(fixture.root / "third-party/src")
        (fixture.root / "third-party/.prepare-dependencies.lock").unlink(missing_ok=True)
        fixture.export_manifest.unlink()
        (fixture.root / ".gitignore").write_text(
            "third-party/src/\nthird-party/.prepare-dependencies.lock\n", encoding="utf-8")
        clean_git = {key: value for key, value in os.environ.items()
                     if not key.startswith("GIT_")}
        clean_git.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        for command in (["git", "init", "--quiet", "--template="],
                        ["git", "add", "--all"],
                        ["git", "-c", "user.name=Integration", "-c",
                         "user.email=test.invalid", "commit", "--quiet", "-m", "fixture"]):
            subprocess.run(command, cwd=fixture.root, env=clean_git, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        archive = base / "source.tar.gz"
        export = subprocess.run([
            sys.executable, "-I", str(fixture.root / "scripts/export-source.py"),
            "--output", str(archive), "--offline-payload", str(fixture.output),
            "--nightly-rustc", str(fixture.tools / "nightly rustc"),
        ], cwd=fixture.root.parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(export.returncode, 0, export.stderr)
        extraction = base / "extraction"
        extraction.mkdir()
        unpack = subprocess.run(["tar", "-xzf", str(archive), "-C", str(extraction)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(unpack.returncode, 0, unpack.stderr)
        source = extraction / "pkcs11-scope-source"
        tools = base / "recipient tools"
        tools.mkdir()
        shutil.copy2(FIXTURES / "rustup.py", tools / "rustup")
        shutil.copy2(FIXTURES / "product-cargo.py", tools / "stable-cargo")
        for name in ("stable-rustc", "bpf-cargo", "bpf-linker"):
            shutil.copy2(FIXTURES / "product-cargo.py", tools / name)
        for name in ("rustup", "stable-cargo", "stable-rustc", "bpf-cargo", "bpf-linker"):
            (tools / name).chmod(0o755)
        (tools / "tool-map.json").write_text(json.dumps({
            "1.88:cargo": str(tools / "stable-cargo"),
            "1.88:rustc": str(tools / "stable-rustc"),
            "nightly-2026-05-20:cargo": str(tools / "bpf-cargo"),
            "nightly-2026-05-20:rustc": str(fixture.tools / "nightly rustc"),
        }), encoding="utf-8")
        work = base / "recipient work"
        result = subprocess.run(
            ["/bin/sh", "scripts/build-offline.sh", str(work)], cwd=source,
            env={"PATH": f"{tools}:/usr/bin:/bin", "LC_ALL": "C"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((work / "target/integrated-build").is_file())
        self.assertTrue((source / "third-party/src/demo-1.0.0-p1/value.txt").is_file())
        self.assertTrue((source / "third-party/.prepare-dependencies.lock").is_file())


if __name__ == "__main__":
    unittest.main()
