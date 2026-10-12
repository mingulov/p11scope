#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real ordinary caller/controller protocol with a synthetic observer.

The observer's readiness text and capture verdict are test inputs. These
controls prove scheduling, ledger binding and cleanup, never native capture
or provider VA equality under p11scope.
"""

from contextlib import nullcontext
import json
import os
from pathlib import Path
import runpy
import select
import shutil
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
TARGETS = ("C_GetFunctionList", "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetSlotList",
           "C_OpenSession", "C_CloseSession", "C_GetSessionInfo", "C_GenerateRandom")


class InitialExecControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
        if not cls.provider.is_file() or not shutil.which("softhsm2-util") or not shutil.which("cc"):
            raise unittest.SkipTest("requires installed ordinary SoftHSM/cc fixtures; installs nothing")
        cls.temporary = tempfile.TemporaryDirectory(prefix="h6-exec-controller-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.executable = cls.directory / "caller"
        result = subprocess.run(
            ["cc", "-std=c11", *H6["CALLER_CFLAGS"], str(ROOT / "tests/fixtures/cgroup-trace/caller.c"),
             "-ldl", "-lpthread", "-o", str(cls.executable)],
            capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AssertionError(result.stderr)
        tokens = cls.directory / "tokens"
        tokens.mkdir(mode=0o700)
        config = cls.directory / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
        cls.env = dict(os.environ, SOFTHSM2_CONF=str(config), N3_PRIVATE_ENV=H6["CANARIES"][1])
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "h6-exec-controller",
                        "--so-pin", "5678", "--pin", "1234"], env=cls.env,
                       capture_output=True, check=True, timeout=30)
        cls.pin = H6["FilePin"](cls.executable)
        cls.addClassCleanup(cls.pin.close)

    def setUp(self):
        self.ctx = H6["Case"](SimpleNamespace(out=self.directory, uid=os.getuid(), gid=os.getgid()))
        self.provider_pin = H6["FilePin"](self.provider)
        self.addCleanup(self.provider_pin.close)
        self.ctx.provider_pin = self.provider_pin
        self.ctx.pins = {"caller": self.pin}
        self.events, self.callers = [], []
        self.addCleanup(H6["cleanup_leg_resources"], self.ctx)

    def drive(self, lines=None, mode="trace", changes=None, short_setup=False):
        directory = self.directory / f"{self._testMethodName}-{time.monotonic_ns()}"
        directory.mkdir()
        observer_path = directory / "synthetic-observer"
        observer_path.write_text(
            "#!/usr/bin/env python3\nimport json, pathlib, signal, sys, time\n"
            "args=sys.argv[1:]\n"
            "pathlib.Path(args[args.index('-o')+1]).write_text('{}' if args[0]=='profile' else '')\n"
            "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
            + "for line in " + repr(lines if lines is not None else [
                "p11scope: loader readiness: 1 active hook(s)",
                "p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C"]) + ":\n"
            "    print(line, file=sys.stderr, flush=True)\n"
            "while True: time.sleep(0.02)\n")
        observer_path.chmod(0o755)
        self.ctx.binary = H6["FilePin"](observer_path)
        self.addCleanup(self.ctx.binary.close)
        source = H6["run_pid_caller_leg"].__globals__
        real_spawn = source["spawn_owned"]
        real_observer = source["spawn_observer"]

        def ordinary_spawn(owners, argv, uid, **options):
            # Explicit fixture credential seam, never a production fallback.
            if "user" in options:
                self.assertEqual(options.pop("user"), os.getuid())
                self.assertEqual(options.pop("group"), os.getgid())
                self.assertEqual(options.pop("extra_groups"), [])
            return real_spawn(owners, argv, os.getuid(), **options)

        def ordinary_initial(owners, argv, **options):
            self.assertEqual(len(os.listdir("/proc/self/task")), 1)
            self.assertEqual(options["uid"], os.getuid())
            self.assertEqual(options["gid"], os.getgid())
            return source["INITIAL_EXEC"]["_spawn_initial_exec"](
                owners, argv, supplementary_groups=tuple(os.getgroups()), **options)

        def observer(*args, **kwargs):
            scope = self.ctx.scopes[-1]
            caller = scope.owners[0]
            self.callers.append(caller)
            self.assertTrue(getattr(caller, "held", False), "caller user code ran before observer startup")
            self.assertIn(caller, scope.traced)
            self.assertIn(f"TracerPid:\t{os.getpid()}\n", Path(f"/proc/{caller.pid}/status").read_text())
            self.assertFalse(scope.readers[0].records, "an image ledger was manufactured before main")
            self.assertNotIn(str(self.provider), Path(f"/proc/{caller.pid}/maps").read_text())
            self.events.append("held-observer-start")
            return real_observer(*args, **kwargs)

        def warm(_capture, caller, reader, image, phases, *_args, **_kwargs):
            phase = f"controller-proof-{image['image']}"
            H6["n3_command"](caller, reader, "C_GetInfo", 1, 0, phase,
                             "selected", image["image"], None, phases)
            return {"image": image["image"], "phases": [phase], "scope": "controller-only"}

        def drain(_capture, caller, reader, fn, count, delay, phase, image, phases):
            return H6["n3_command"](caller, reader, fn, count, delay, phase,
                                     "selected", image, None, phases)

        patches = {"init_token": lambda *_: dict(self.env), "spawn_owned": ordinary_spawn,
                   "spawn_initial_exec": ordinary_initial, "spawn_observer": observer,
                   "warm_caller": warm, "drain_trace_phase": drain,
                   "evaluate_trace_h6": lambda *_: {"pass": True, "scope": "controller-only"},
                   "evaluate_profile_h6": lambda *_: {"pass": True, "scope": "controller-only"},
                   "evaluate_metrics_h6": lambda *_: {"pass": True, "scope": "controller-only"}}
        if short_setup:
            budget = source["LegBudget"]
            patches["LegBudget"] = lambda **kwargs: budget(budgets={"setup": 0.4}, leg_seconds=3, **kwargs)
        patches.update(changes or {})
        with mock.patch.dict(source, patches):
            result = H6["run_pid_caller_leg"](
                self.ctx, "pid-reexec", "singles", mode, directory, True)
        return result, json.loads((directory / "receipt.json").read_text()), directory

    def test_production_controller_holds_real_exec_until_exact_loader_and_loop_readiness(self):
        result, receipt, directory = self.drive()
        self.assertTrue(result["pass"])
        self.assertEqual(result["scope"], "controller-only")
        barrier = receipt["initial_exec"]
        load = receipt["initial_load"]
        self.assertEqual(barrier["active_loader_hooks"], 1)
        self.assertLess(barrier["stopped_ns"], barrier["hook_ready_ns"])
        self.assertLessEqual(barrier["hook_ready_ns"], receipt["observer_ready_ns"])
        self.assertLessEqual(receipt["observer_ready_ns"], barrier["detach_entry_ns"])
        self.assertLessEqual(barrier["detach_entry_ns"], load["waiting_ns"])
        self.assertLess(load["waiting_ns"], load["released_ns"])
        self.assertLessEqual(load["ready_ns"], load["deadline_ns"])
        ledger = [json.loads(line[9:]) for line in (directory / "caller.ledger.jsonl").read_text().splitlines()]
        images = [row for row in ledger if row["kind"] == "image"]
        self.assertEqual([row["image"] for row in images], [0, 1])
        for field in H6["IMAGE_FIELDS"]:
            self.assertEqual(images[0][field], receipt["images"][0][field])
            self.assertEqual(images[0][field], ({"image": 0, **barrier["held"]})[field])
        self.assertEqual(sum(row["kind"] == "exec" for row in ledger), 1)
        self.assertEqual(sum(row["kind"] == "call" and row["phase"] == "warm" for row in ledger), 3)
        self.assertEqual(sum(row["kind"] == "call" and row["phase"] == "measured" for row in ledger), 10)
        caller = self.callers[0]
        self.assertTrue(caller.detached)
        self.assertTrue(caller.reaped)
        self.assertIsNone(caller.pidfd)
        self.assertFalse(Path(f"/proc/{caller.pid}").exists())
        self.assertFalse(self.ctx.cleanup_failed, self.ctx.cleanup_errors)

    def test_short_setup_can_finish_warmup_and_measurement_within_the_leg_budget(self):
        result, receipt, directory = self.drive(short_setup=True)
        self.assertTrue(result["pass"])
        caller = self.callers[0]
        self.assertEqual(caller.deadline_ns, receipt["initial_load"]["deadline_ns"])
        self.assertLess(receipt["initial_load"]["ready_ns"], caller.deadline_ns)
        ledger = [json.loads(line[9:]) for line in (directory / "caller.ledger.jsonl").read_text().splitlines()]
        done = next(row for row in ledger if row["kind"] == "ack" and row["phase"] == "done")
        self.assertGreater(done["t"], caller.deadline_ns)
        self.assertEqual(sum(row["kind"] == "exec" for row in ledger), 1)
        self.assertEqual(sum(row["kind"] == "call" and row["phase"] == "warm" for row in ledger), 3)
        self.assertEqual(sum(row["kind"] == "call" and row["phase"] == "measured" for row in ledger), 10)
        self.assertTrue(caller.reaped)
        self.assertFalse(self.ctx.cleanup_failed, self.ctx.cleanup_errors)

    def test_zero_missing_duplicate_or_malformed_hook_count_never_releases_main(self):
        capturing = "p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C"
        for lines in (["p11scope: loader readiness: 0 active hook(s)", capturing], [capturing],
                      ["p11scope: loader readiness: 2 active hook(s)", capturing],
                      ["p11scope: loader readiness: 1 active hook(s)"] * 2 + [capturing],
                      ["p11scope: loader readiness: nan active hook(s)", capturing],
                      ["p11scope: loader readiness: 1 active hook(s)", "foreign line", capturing]):
            with self.subTest(lines=lines):
                with self.assertRaises(H6["SetupError"]):
                    self.drive(lines=lines, short_setup=True)
                caller = self.callers[-1]
                self.assertFalse(caller.detached)
                self.assertTrue(caller.reaped)
                self.assertIsNone(caller.pidfd)
                scope = self.ctx.scopes[-1]
                self.assertFalse(scope.owners)
                self.assertFalse(scope.traced)
                self.assertFalse(scope.readers)
                self.assertFalse(Path(f"/proc/{caller.pid}").exists())

    def test_missing_loop_start_exhausts_original_setup_deadline_and_reaps(self):
        with self.assertRaises(TimeoutError):
            self.drive(lines=["p11scope: loader readiness: 1 active hook(s)"], short_setup=True)
        caller = self.callers[-1]
        self.assertTrue(caller.reaped)
        self.assertFalse(caller.detached)
        self.assertFalse(self.ctx.scopes[-1].traced)

    def test_ready_observer_for_a_foreign_pid_cannot_release_the_held_caller(self):
        source = H6["run_pid_caller_leg"].__globals__
        observer = source["spawn_observer"]

        def foreign(owners, readers, directory, argv, env, **kwargs):
            altered = list(argv)
            altered[altered.index("--pid") + 1] = str(int(altered[altered.index("--pid") + 1]) + 1)
            caller = owners[0]
            self.callers.append(caller)
            return observer(owners, readers, directory, altered, env, **kwargs)

        with self.assertRaises(H6["SetupError"]):
            self.drive(changes={"spawn_observer": foreign}, short_setup=True)
        self.assertTrue(self.callers[-1].reaped)
        self.assertFalse(self.callers[-1].detached)

    def test_bad_readiness_clock_is_rejected_before_detach(self):
        source = H6["run_pid_caller_leg"].__globals__
        self.assertIn("observer_initial_exec_ready", source)
        ready = source["observer_initial_exec_ready"]

        def backwards(*args):
            result = ready(*args)
            result["hook_ready_ns"] = args[4]["stopped_ns"]
            return result

        with self.assertRaises(H6["SetupError"]):
            self.drive(changes={"observer_initial_exec_ready": backwards}, short_setup=True)
        self.assertFalse(self.callers[-1].detached)
        self.assertTrue(self.callers[-1].reaped)

    def test_every_real_image_field_and_held_file_metadata_are_bound_before_load(self):
        source = H6["run_pid_caller_leg"].__globals__
        self.assertIn("release_initial_exec_load", source)
        release = source["release_initial_exec_load"]
        for field in H6["IMAGE_FIELDS"]:
            with self.subTest(field=field):
                def changed(ctx, caller, reader, pin, provider, proof):
                    real = reader.record
                    def record(kind, *args, **kwargs):
                        row = real(kind, *args, **kwargs)
                        if kind == "image":
                            row = dict(row)
                            row[field] = row[field] + "-foreign" if field == "path" else row[field] + 1
                        return row
                    with mock.patch.object(reader, "record", side_effect=record):
                        return release(ctx, caller, reader, pin, provider, proof)
                with self.assertRaises(H6["SetupError"]):
                    self.drive(changes={"release_initial_exec_load": changed}, short_setup=True)
                self.assertTrue(self.callers[-1].reaped)
        for field in ("size", "ctime_ns"):
            with self.subTest(field=field):
                def changed_metadata(ctx, caller, reader, pin, provider, proof):
                    proof["held"][field] += 1
                    return release(ctx, caller, reader, pin, provider, proof)
                with self.assertRaises(H6["SetupError"]):
                    self.drive(changes={"release_initial_exec_load": changed_metadata}, short_setup=True)
                self.assertTrue(self.callers[-1].reaped)

    def test_real_load_wait_may_arrive_during_detach_syscall(self):
        source = H6["run_pid_caller_leg"].__globals__
        self.assertIn("release_initial_exec_load", source)
        release = source["release_initial_exec_load"]

        def delay_return(ctx, caller, reader, pin, provider, proof):
            real = caller.resume_detach
            def detach():
                result = real()
                reader.record("ack", 0, "load-wait", seconds=1)
                result["detach_return_ns"] = time.monotonic_ns()
                return result
            with mock.patch.object(caller, "resume_detach", side_effect=detach):
                return release(ctx, caller, reader, pin, provider, proof)

        result, receipt, _directory = self.drive(changes={"release_initial_exec_load": delay_return})
        self.assertTrue(result["pass"])
        self.assertLess(receipt["initial_load"]["waiting_ns"], receipt["initial_exec"]["detach_return_ns"])

    def held_raw_caller(self, seconds=2):
        initial = H6["INITIAL_EXEC"]
        setarch = H6["FilePin"](Path(shutil.which("setarch")).resolve(strict=True))
        self.addCleanup(setarch.close)
        caller = initial["_spawn_initial_exec"](
            self.ctx.owners, [str(self.pin.path), str(self.provider), "0", "selected"],
            caller_pin=self.pin, setarch_pin=setarch, uid=os.getuid(), gid=os.getgid(),
            supplementary_groups=tuple(os.getgroups()), env=self.env,
            deadline_ns=time.monotonic_ns() + int(seconds * 1e9), cleanup_section=nullcontext)
        self.ctx.traced.append(caller)
        caller.hold_caller_exec()
        return caller

    def test_detached_live_wait_honors_its_explicit_timeout_after_setup_expires(self):
        caller = self.held_raw_caller(seconds=0.4)
        deadline = caller.deadline_ns
        caller.resume_detach()
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.02)
        self.assertIsNone(caller.popen.poll())
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            caller.popen.wait(timeout=0.04)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.03)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(caller.deadline_ns, deadline)
        self.assertIsNone(caller.popen.poll())
        self.assertFalse(caller.reaped)
        self.assertIsNotNone(caller.pidfd)
        caller.popen.stdin.write("stop\n")
        caller.popen.stdin.flush()
        self.assertEqual(caller.popen.wait(timeout=1), 0)
        self.assertTrue(caller.reaped)

    def test_raw_terminal_wait_sets_primitive_reaped_state_before_close(self):
        caller = self.held_raw_caller()
        signal.pidfd_send_signal(caller.pidfd, signal.SIGKILL)
        self.assertTrue(select.select([caller.pidfd], [], [], 1)[0])
        H6["wait_terminal_child"](caller)
        self.assertTrue(caller.reaped)
        self.assertFalse(caller.traced)
        self.assertEqual(caller.popen.returncode, -signal.SIGKILL)
        caller.close()
        self.assertIsNone(caller.pidfd)

    def test_adapter_returncode_cannot_replace_primitive_terminal_reap_proof(self):
        caller = self.held_raw_caller()
        signal.pidfd_send_signal(caller.pidfd, signal.SIGKILL)
        _pid, status = os.waitpid(caller.pid, 0x40000000)
        caller.popen.returncode = os.waitstatus_to_exitcode(status)
        try:
            self.assertFalse(caller.reaped)
            with self.assertRaises(H6["SetupError"]):
                H6["wait_terminal_child"](caller)
        finally:
            caller._terminal(status)  # restore the actual status this fixture consumed

    def test_actual_mandatory_reap_is_retained_but_late_cleanup_cannot_pass(self):
        real_wait = os.waitpid
        shifted = False

        def late_reap(pid, flags):
            nonlocal shifted
            result = real_wait(pid, flags)
            if (not shifted and self.callers and pid == self.callers[-1].pid
                    and flags == 0x40000000 and result[0]
                    and (os.WIFEXITED(result[1]) or os.WIFSIGNALED(result[1]))):
                shifted = True
                budget = self.ctx.scopes[-1].budget
                clock = budget.clock
                budget.clock = lambda: clock() + 6_000_000_000
            return result

        def refuse(*_args):
            raise H6["SetupError"]("controlled startup failure")

        with mock.patch.object(os, "waitpid", side_effect=late_reap), \
                self.assertRaisesRegex(H6["LegCleanupError"], "five-second|cleanup budget"):
            self.drive(changes={"observer_initial_exec_ready": refuse})
        self.assertTrue(shifted)
        caller = self.callers[-1]
        self.assertTrue(caller.reaped)
        self.assertFalse(caller.detached)
        self.assertFalse(Path(f"/proc/{caller.pid}").exists())
        self.assertTrue(self.ctx.cleanup_failed)
        for reader in self.ctx.scopes[-1].readers:
            reader.thread.join(1)  # fixture settlement; the late H6 verdict remains rejected


class AllNineReuseTests(unittest.TestCase):
    def ledger(self):
        return [dict(kind="target", image=image, fn=fn, dev=[8, 1], ino=321,
                     file_offset=4096 + index * 16, vaddr=0x70000000 + index * 16)
                for image in (0, 1) for index, fn in enumerate(TARGETS)]

    def test_one_matching_va_cannot_satisfy_all_nine_actual_target_reuse(self):
        ledger = self.ledger()
        ledger[-1]["vaddr"] += 4096
        self.assertFalse(H6["va_reuse_from"](ledger)["observed"])

    def test_all_nine_unique_physical_targets_must_match(self):
        self.assertTrue(H6["va_reuse_from"](self.ledger())["observed"])
        for field, changed in (("dev", [8, 2]), ("ino", 999), ("file_offset", 2048)):
            with self.subTest(field=field):
                ledger = self.ledger()
                ledger[-1][field] = changed
                self.assertFalse(H6["va_reuse_from"](ledger)["observed"])

    def test_missing_duplicate_extra_or_zero_targets_cannot_pass(self):
        for change in ("missing", "duplicate", "extra-image", "zero-va"):
            with self.subTest(change=change):
                ledger = self.ledger()
                if change == "missing": ledger.pop()
                elif change == "duplicate": ledger.append(dict(ledger[-1]))
                elif change == "extra-image": ledger.append({**ledger[-1], "image": 2})
                else: ledger[-1]["vaddr"] = 0
                self.assertFalse(H6["va_reuse_from"](ledger)["observed"])

    def test_different_names_at_one_physical_target_are_not_nine_unique_targets(self):
        ledger = self.ledger()
        for image in (0, 1):
            rows = [row for row in ledger if row["image"] == image]
            for field in ("dev", "ino", "file_offset", "vaddr"):
                rows[-1][field] = rows[-2][field]
        self.assertFalse(H6["va_reuse_from"](ledger)["observed"])

    def test_oracle_rederives_actual_targets_instead_of_trusting_observed_flag(self):
        ledger = self.ledger()
        ledger[-1]["vaddr"] += 4096
        receipt = {"reuse_expected": {"va": True}, "va_reuse": {"observed": True}}
        self.assertIn("expected va reuse across exec is not demonstrated by the ledger",
                      H6["expected_reuse_errors"](receipt, ledger))


if __name__ == "__main__":
    unittest.main()
