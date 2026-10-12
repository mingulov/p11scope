#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""ia32 H6 controls: ordinary owned ELF32 workloads, never native capture."""
import copy
import contextlib
import io
import json
import os
import pty
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-ia32-automatic-exec.py"


class Ia32GateTests(unittest.TestCase):
    def load(self):
        self.assertTrue(SCRIPT.is_file(), "ia32 installed acceptance controller missing")
        return runpy.run_path(str(SCRIPT))

    def test_required_coverage_needs_all_eight_positive_legs(self):
        gate = self.load()
        legs = [{"cell": cell, "leg": f"{mode}/{backend}", "pass": True, "status": "pass"}
                for backend in ("singles", "multi")
                for cell, modes in (("pid-leader", ("trace", "profile", "metrics")),
                                    ("pid-failed-exec", ("trace",))) for mode in modes]
        self.assertTrue(gate["required_coverage"](legs)["complete"])
        self.assertFalse(gate["required_coverage"](legs[:-1])["complete"])
        self.assertFalse(gate["required_coverage"](legs + [legs[0]])["complete"])
        legs[0].update(status="negative", **{"pass": False})
        self.assertFalse(gate["required_coverage"](legs)["complete"])

    def test_help_runs_without_privilege(self):
        self.load()
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--source-revision", result.stdout)

    def test_cli_refuses_duplicate_cells_bad_revision_and_non_disk_destination_before_side_effects(self):
        self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-cli-") as tmp:
            out = Path("/non-disk-destination") / Path(tmp).name
            argv = [sys.executable, "-I", str(SCRIPT), "--binary", "/installed/p11scope",
                    "--source-revision", "1" * 40, "--uid", "1000", "--gid", "1000", "--out", str(out)]
            for extra, needle in ((["--cells", "pid-leader,pid-leader"], "duplicate"),
                                  (["--backends", "singles,singles"], "duplicate"),
                                  (["--cells", "pid-nonleader-cold"], "supported cells"),
                                  (["--backends", ""], "supported backends"),
                                  (["--source-revision", "not-a-sha"], "source"),
                                  ([], "/var/tmp/p11scope-ws-tmp")):
                with self.subTest(extra=extra):
                    result = subprocess.run(argv + extra, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(needle, result.stderr)
                    self.assertFalse(out.exists())

    def test_cli_requires_root_before_creating_the_valid_disk_destination(self):
        if os.geteuid() == 0:
            self.skipTest("ordinary uid refusal control")
        with tempfile.TemporaryDirectory(prefix="ia32-cli-root-") as tmp:
            out = Path(tmp) / "uncreated"
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--binary", sys.executable,
                "--source-revision", "1" * 40, "--uid", str(os.getuid()), "--gid", str(os.getgid()),
                "--out", str(out)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn("root observer", result.stderr)
            self.assertFalse(out.exists())

    def test_matrix_records_setup_failure_and_continues_only_after_settled_resources(self):
        gate = self.load()
        self.assertTrue("run_selected" in gate, "ia32 installed matrix orchestration missing")
        with tempfile.TemporaryDirectory(prefix="ia32-matrix-") as tmp:
            case = gate["H6"]["Case"](type("Args", (), {"out": Path(tmp), "uid": os.getuid(), "gid": os.getgid()})())
            attempted = []

            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, _directory):
                attempted.append((cell, backend, kind))
                owned = gate["H6"]["spawn_owned"](ctx.owners,
                    [sys.executable, "-c", "raise SystemExit(3)"], os.getuid())
                self.assertEqual(gate["H6"]["wait_process"](owned.popen, 2), 3)
                raise gate["H6"]["SetupError"]("controlled fixture setup failure")

            with contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual(len(attempted), 8)
            self.assertEqual(len(results), 8)
            self.assertTrue(all(row["status"] == "error" and row["pass"] is False for row in results))
            self.assertTrue(all(row["errors"] == ["SetupError: controlled fixture setup failure"] for row in results))
            self.assertFalse(gate["required_coverage"](results)["complete"])
            self.assertFalse(case.cleanup_failed, case.cleanup_errors)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))

    def test_matrix_nonzero_normal_stop_reaps_owned_child_and_prevents_next_leg(self):
        gate = self.load()
        self.assertTrue("run_selected" in gate, "ia32 installed matrix orchestration missing")
        with tempfile.TemporaryDirectory(prefix="ia32-stop-") as tmp:
            directory = Path(tmp)
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(), "gid": os.getgid()})())
            attempted, children = [], []

            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, _directory):
                attempted.append((cell, backend, kind))
                ctx.observer_start = len(ctx.owners)
                owner = gate["H6"]["spawn_owned"](ctx.owners, [sys.executable, "-c",
                    "import signal,time; signal.signal(signal.SIGINT, lambda *_: exit(7)); "
                    "print('ready', flush=True); time.sleep(30)"], os.getuid(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                children.append(owner)
                capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    owner.popen.stdout, directory / "observer.stdout")
                gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    owner.popen.stderr, directory / "observer.stderr")
                ctx.observer_owned = owner
                gate["H6"]["expect_line"](capture, 0, "ready", 2)
                gate["H6"]["stop_b_observer"](ctx, owner)
                self.fail("nonzero normal stop returned as a successful leg")

            with contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual(attempted, [("pid-leader", "singles", "trace")])
            self.assertEqual(len(results), 1)
            self.assertIn("normal stop returned 7", results[0]["errors"][0])
            self.assertTrue(case.cleanup_failed)
            self.assertEqual(children[0].popen.returncode, 7)
            self.assertIsNone(children[0].pidfd)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))

    def test_partial_caller_reader_construction_is_terminal_after_owned_resources_settle(self):
        gate = self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-constructor-") as tmp:
            directory = Path(tmp)
            fixtures = gate["compile_fixtures"](directory / "bin")
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(), "gid": os.getgid()})())
            attempted, children, pins, threads = [], [], [], []
            thread_class = gate["H6"]["threading"].Thread
            original_start = thread_class.start
            starts = 0

            def start(thread):
                nonlocal starts
                starts += 1
                if starts % 2 == 0:
                    raise OSError("controlled second reader constructor failure")
                threads.append(thread)
                return original_start(thread)

            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, leg_directory):
                attempted.append((cell, backend, kind))
                leg_directory.mkdir(parents=True)
                held = {name: gate["H6"]["leg_pin"](ctx, path) for name, path in fixtures.items()}
                pins.extend(held.values())
                try:
                    gate["Ia32Driver"](ctx, leg_directory, held, "leader", os.environ.copy(), delay_ms=0)
                    self.fail("partial caller construction did not raise")
                finally:
                    children.extend(ctx.owners)

            with mock.patch.object(thread_class, "start", start), contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual(attempted, [("pid-leader", "singles", "trace")])
            self.assertIn("controlled second reader constructor failure", results[0]["errors"][0])
            self.assertTrue(case.cleanup_failed)
            self.assertTrue(all(child.popen.returncode is not None and child.pidfd is None for child in children))
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertTrue(all(pin.fd is None for pin in pins))
            self.assertTrue(all(not scope.owners and not scope.readers and not scope.leg_pins for scope in case.scopes))

    def test_matrix_does_not_retry_a_backend_after_its_actual_refusal(self):
        gate = self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-refusal-") as tmp:
            directory = Path(tmp)
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(), "gid": os.getgid()})())
            attempted = []

            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, leg_directory):
                attempted.append((cell, backend, kind))
                leg_directory.mkdir(parents=True)
                refusal = backend == "singles"
                code = ("import sys; print('backend singles unsupported', file=sys.stderr); exit(3)"
                        if refusal else "raise SystemExit(0)")
                child = gate["H6"]["spawn_owned"](ctx.owners, [sys.executable, "-c", code], os.getuid(),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                errors = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    child.popen.stderr, leg_directory / "stderr")
                self.assertEqual(gate["H6"]["wait_process"](child.popen, 2), 3 if refusal else 0)
                errors.finish()
                if refusal:
                    with self.assertRaises(gate["H6"]["BackendRefused"]) as caught:
                        gate["H6"]["observer_ready"](child, errors, backend, timeout=0.05)
                    return {"cell": cell, "leg": f"{kind}/{backend}", "pass": False, "status": "negative",
                            "backend_refused": str(caught.exception), "errors": [str(caught.exception)]}
                return {"cell": cell, "leg": f"{kind}/{backend}", "pass": True, "status": "pass"}

            with contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual([row for row in attempted if row[1] == "singles"],
                             [("pid-leader", "singles", "trace")])
            self.assertEqual(len(results), 5)
            self.assertFalse(gate["required_coverage"](results)["complete"])
            self.assertFalse(case.cleanup_failed, case.cleanup_errors)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))

    def test_observer_eof_after_a_public_row_prevents_measurement_and_next_leg(self):
        gate = self.load()
        self.assertTrue("require_observer_live" in gate, "public proof needs a continuing owned observer")
        with tempfile.TemporaryDirectory(prefix="ia32-ended-observer-") as tmp:
            directory = Path(tmp)
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(), "gid": os.getgid()})())
            attempted, children = [], []

            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, leg_directory):
                attempted.append((cell, backend, kind))
                leg_directory.mkdir(parents=True)
                ctx.observer_start = len(ctx.owners)
                owner = gate["H6"]["spawn_owned"](ctx.owners,
                    [sys.executable, "-c", "print('public row', flush=True)"], os.getuid(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append(owner)
                ctx.observer_owned = owner
                capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    owner.popen.stdout, leg_directory / "stdout")
                errors = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    owner.popen.stderr, leg_directory / "stderr")
                self.assertEqual(gate["H6"]["wait_process"](owner.popen, 2), 0)
                capture.finish(); errors.finish()
                self.assertEqual(capture.lines, ["public row\n"])
                gate["require_observer_live"](owner, capture, errors)
                self.fail("ended observer allowed fixed measurement")

            with contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual(attempted, [("pid-leader", "singles", "trace")])
            self.assertIn("before fixed measurement", results[0]["errors"][0])
            self.assertTrue(case.cleanup_failed)
            self.assertIsNone(children[0].pidfd)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))

    def test_held_elf_parser_rejects_lp64_x32_and_truncated_files(self):
        gate = self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-elf-") as tmp:
            fixtures = gate["compile_fixtures"](Path(tmp))
            good = Path(fixtures["before"]).read_bytes()
            for change in ("class64", "x32", "truncated"):
                with self.subTest(change=change):
                    data = bytearray(good)
                    if change == "class64": data[4] = 2
                    elif change == "x32": data[18:20] = (62).to_bytes(2, "little")
                    else: data = data[:30]
                    path = Path(tmp) / change; path.write_bytes(data)
                    pin = gate["H6"]["FilePin"](path)
                    try:
                        with self.assertRaises(ValueError): gate["elf32_metadata"](pin)
                    finally: pin.close()

    def test_real_ia32_function_list_has_offset4_and68_distinct_canonical_endpoints(self):
        gate = self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-table-") as tmp:
            fixtures = gate["compile_fixtures"](Path(tmp))
            source = Path(tmp) / "check.c"
            source.write_text(r'''#include <dlfcn.h>
#include <stdio.h>
#include <stddef.h>
struct list { unsigned char major, minor; void *functions[68]; };
int main(int argc, char **argv) {
  if (argc != 2 || sizeof(void *) != 4 || sizeof(unsigned long) != 4) return 2;
  void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); if (!h) return 3;
  unsigned long (*getter)(void **) = dlsym(h, "C_GetFunctionList");
  struct list *list = NULL;
  if (!getter || getter((void **)&list) || !list || list->major != 2 || list->minor != 40) return 4;
  if (offsetof(struct list, functions) != 4) return 5;
  for (int i=0; i<68; ++i) {
    if (!list->functions[i]) return 6;
    for (int j=0; j<i; ++j) if (list->functions[i] == list->functions[j]) return 7;
  }
  if (list->functions[0] != dlsym(h, "C_Initialize") || list->functions[2] != dlsym(h, "C_GetInfo") ||
      list->functions[3] != (void *)getter || list->functions[12] != dlsym(h, "C_OpenSession") ||
      list->functions[15] != dlsym(h, "C_GetSessionInfo")) return 8;
  puts("ia32 2.40 offset4 distinct68"); return dlclose(h) ? 9 : 0;
}''')
            binary = Path(tmp) / "check"
            subprocess.run(["cc", "-m32", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(source), "-ldl", "-o", str(binary)], check=True, timeout=30)
            result = subprocess.run([str(binary), str(fixtures["provider.so"])],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "ia32 2.40 offset4 distinct68")

    def protocol(self, mode, before_measure=None, delay_ms=0, gate=None):
        gate = self.load() if gate is None else gate
        with tempfile.TemporaryDirectory(prefix="h6-ia32-") as tmp:
            directory = Path(tmp)
            fixtures = gate["compile_fixtures"](directory)
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(),
                                                       "gid": os.getgid()})())
            self.last_case = case

            @gate["H6"]["owned_leg"](stop_b=True)
            def exercise(ctx):
                pins = {name: gate["H6"]["leg_pin"](ctx, path) for name, path in fixtures.items()}
                driver = gate["Ia32Driver"](ctx, directory, pins, mode, os.environ.copy(), delay_ms=delay_ms)
                self.last_driver = driver
                driver.ready()
                self.assertFalse(any(row["kind"] == "call" for row in driver.stdout.records),
                                 "initial ready declaration performed an unobserved setup API")
                self.assertFalse(gate["H6"]["session_reuse_from"](driver.stdout.records)["observed"])
                original = driver.owned
                pidfd = original.pidfd
                driver.start_held()
                driver.do_exec()
                self.assertIs(driver.owned, original)
                self.assertEqual(driver.owned.pidfd, pidfd)
                if before_measure is not None:
                    before_measure(gate, ctx, driver)
                elif mode == "leader":
                    driver.warm_attempt(1, 5)
                driver.measure()
                snapshot = driver.snapshot()
                self.assertEqual(gate["workload_errors"](snapshot["ledger"], snapshot, mode), [])
                driver.finish()
                gate["H6"]["finish_readers"]([driver.stdout, driver.stderr])
                snapshot["ledger"] = list(driver.stdout.records)
                snapshot["finished_ns"] = gate["H6"]["monotonic_ns"]()
                self.assertEqual(gate["workload_errors"](snapshot["ledger"], snapshot, mode), [])
                return snapshot

            snapshot = exercise(case)
            self.assertFalse(case.cleanup_failed, case.cleanup_errors)
            self.assertIsNone(gate["H6"]["ACTIVE_LEG"].get())
            self.assertTrue(all(not scope.owners and not scope.readers and not scope.leg_pins
                                for scope in case.scopes))
            return gate, snapshot

    def test_real_elf32_leader_exec_preserves_original_process_and_birth(self):
        _, snapshot = self.protocol("leader")
        images = snapshot["images"]
        self.assertEqual([row["image"] for row in images], [0, 1])
        self.assertEqual(images[0]["pid"], images[1]["pid"])
        self.assertEqual(images[0]["start_time"], images[1]["start_time"])
        self.assertNotEqual(images[0]["ino"], images[1]["ino"])
        calls = [row for row in snapshot["ledger"] if row["kind"] == "call"]
        self.assertEqual(len(calls), 31)  # core28 + setup2 + real warm1
        self.assertEqual(sum(row["rv"] != 0 for row in calls), 13)
        self.assertEqual([row["rv"] for row in calls if row["phase"] == "post"],
                         [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0])
        self.assertEqual({row["sess"] for row in calls if row["phase"] == "post"}, {1})
        self.assertTrue(all(row["t0"] > 2**32 for row in calls))
        self.assertTrue(all(row["pointer_bytes"] == row["ck_ulong_bytes"] == 4 for row in images))

    def test_real_failed_exec_returns_held_frame_and_exact_continuation(self):
        _, snapshot = self.protocol("failed")
        self.assertEqual(len(snapshot["images"]), 1)
        self.assertEqual(snapshot["exec_transitions"], [])
        self.assertEqual(snapshot["failed_exec"]["errno"], 2)
        calls = [row for row in snapshot["ledger"] if row["kind"] == "call"]
        core = [row for row in calls if row["phase"] != "setup"]
        self.assertEqual((len(core), sum(row["rv"] == 0 for row in core),
                          sum(row["rv"] == 5 for row in core)), (29, 15, 14))
        self.assertEqual(len(calls), 30)  # plus the actual old setup OK
        held = [row for row in calls if row["phase"] == "held-return"]
        self.assertEqual(len(held), 1)
        self.assertEqual(held[0]["rv"], 5)
        self.assertLess(held[0]["t0"], snapshot["failed_exec"]["t"])
        self.assertGreater(held[0]["t1"], snapshot["failed_exec"]["t"])

    def test_workload_rejects_missing_duplicate_truncated_and_wrong_abi_facts(self):
        gate, snapshot = self.protocol("failed")
        for change in ("duplicate", "missing-return", "truncated", "width", "wide-time", "wrong-exe", "pin", "successor", "scope"):
            with self.subTest(change=change):
                bad = copy.deepcopy(snapshot)
                ledger = bad["ledger"]
                if change == "duplicate": ledger.append(copy.deepcopy(ledger[-1]))
                elif change == "missing-return":
                    ledger[:] = [row for row in ledger if row.get("phase") != "held-return"]
                elif change == "truncated": ledger[-1].pop("t")
                elif change == "width": next(row for row in ledger if row["kind"] == "image")["pointer_bytes"] = 8
                elif change == "wide-time": next(row for row in ledger if row["kind"] == "call")["t0"] %= 2**32
                elif change == "wrong-exe": bad["images"][0]["path"] = "/wrong-executable"
                elif change == "pin": bad["provider_after"]["sha256"] = "f" * 64
                elif change == "successor": bad["exec_transitions"] = [{"to_image": 1}]
                elif change == "scope": next(row for row in ledger if row["kind"] == "call")["scope"] = "outside"
                self.assertTrue(gate["workload_errors"](ledger, bad, "failed"), change)

    def test_maximum_delay_waits_between_measured_calls_instead_of_invalid_nanosleep(self):
        def check(gate, _ctx, driver):
            driver.send("R", "post-start")
            driver.expect_ack("held-return", 2)
            with self.assertRaises(TimeoutError):
                driver.expect_ack("post", 0.05)
            raise RuntimeError("controlled delayed measurement abort")
        with self.assertRaisesRegex(RuntimeError, "controlled delayed measurement abort"):
            self.protocol("failed", check, delay_ms=1000)
        self.assertFalse(self.last_case.cleanup_failed, self.last_case.cleanup_errors)
        self.assertIsNone(self.last_driver.owned.pidfd)
        self.assertTrue(all(not scope.owners and not scope.readers for scope in self.last_case.scopes))

    def trace_marker(self, image, path=None):
        path = image["path"] if path is None else path
        return (f'21:37:58.638119 {json.dumps(Path(path).name)} '
                f'(PID {image["pid"]}, TID {image["pid"]}) exe={json.dumps(path)} '
                'C_GetInfo [semantics unverified] → CKR_OK 10µs\n')

    def live_frame(self, calls, complete=True):
        text = ("\x1b[2J\x1b[Hp11scope — profile\n"
                f"{calls} completed calls; 0 returned errors; 0 entries without an observed return.\n"
                "FUNCTION CALLS ERR p50 p95 p99 IN-FLIGHT\n"
                f"C_GetInfo {calls} 0 1µs 1µs 1µs 0\n"
                "(~ = log2-bucket approximation, lower bound)\n")
        return text + ("Evidence: controlled public transport\n" if complete else "")

    def test_runtime_trace_readiness_uses_fresh_current_path_and_ledgers_every_attempt(self):
        proofs = []
        def check(gate, ctx, driver):
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, "r", encoding="utf-8")
            capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                stream, driver.directory / "public.trace")
            try:
                os.write(write_fd, self.trace_marker(driver.images[1]).encode())
                capture.wait(lambda reader: len(reader.lines) == 1, 2)
                cursor = len(capture.lines)
                def attempt(sequence, remaining):
                    phase = driver.warm_attempt(sequence, remaining)
                    path = "/wrong-current-image" if sequence == 1 else driver.images[1]["path"]
                    data = self.trace_marker(driver.images[1], path).encode()
                    # Exercise the real incremental UTF-8 pipe decoder.
                    cut = data.index("→".encode()) + 1
                    os.write(write_fd, data[:cut]); os.write(write_fd, data[cut:])
                    return phase
                proof = gate["H6"]["warm_successor"](capture, driver.images[1], attempt,
                    max_attempts=20, timeout=15, output_cursor=cursor)
                self.assertEqual(proof["attempts"], 2)
                self.assertGreater(proof["proof_cursor"], cursor)
                proofs.append(proof)
            finally:
                os.close(write_fd)
            capture.finish()
        _, snapshot = self.protocol("leader", check)
        warm = [row for row in snapshot["ledger"] if row.get("phase", "").startswith("successor-") and row["kind"] == "call"]
        self.assertEqual(len(warm), 2)
        self.assertEqual(len([row for row in snapshot["ledger"] if row["kind"] == "call"]), 32)
        self.assertLessEqual(proofs[0]["observed_ns"], snapshot["command_stamps"]["post-start"])

    def test_runtime_profile_metrics_require_complete_advancing_pty_snapshots(self):
        for kind in ("profile", "metrics"):
            with self.subTest(kind=kind):
                def check(gate, ctx, driver):
                    master, slave = pty.openpty()
                    capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["PtyCapture"],
                        master, driver.directory / "public.pty")
                    try:
                        os.write(slave, self.live_frame(0).encode())
                        deadline = gate["H6"]["wait_deadline"](2)
                        gate["H6"]["_output_wait"](capture, lambda: capture.frames[-1] if capture.frames else None, deadline)
                        def attempt(sequence, remaining):
                            phase = driver.warm_attempt(sequence, remaining)
                            if sequence == 1:
                                os.write(slave, self.live_frame(1, complete=False).encode())
                            else:
                                self.assertEqual(len(capture.frames), 1, "partial PTY frame armed measurement")
                                os.write(slave, ("Evidence: controlled public transport\n" + self.live_frame(2)).encode())
                            return phase
                        proof = gate["H6"]["warm_successor"](capture, driver.images[1], attempt,
                            kind, max_attempts=20, timeout=15)
                        self.assertEqual(proof["attempts"], 2)
                        self.assertEqual(proof["baseline"]["functions"]["C_GetInfo"]["calls"], 0)
                        self.assertGreater(proof["snapshot"]["functions"]["C_GetInfo"]["calls"], 0)
                    finally:
                        os.close(slave)
                    capture.finish()
                    self.assertIsNone(capture.master)
                _, snapshot = self.protocol("leader", check)
                self.assertEqual(len([row for row in snapshot["ledger"] if row["kind"] == "call"]), 32)

    def test_partial_pty_eof_never_releases_measurement_and_is_a_cleanup_failure(self):
        gate = self.load()
        captures = []
        def check(gate, ctx, driver):
            master, slave = pty.openpty()
            capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["PtyCapture"],
                master, driver.directory / "partial.pty")
            captures.append(capture)
            try:
                os.write(slave, self.live_frame(0).encode())
                gate["H6"]["_output_wait"](capture, lambda: capture.frames[-1] if capture.frames else None,
                    gate["H6"]["wait_deadline"](2))
                budget = gate["H6"]["LegBudget"](leg_seconds=0.15)
                token = gate["H6"]["ACTIVE_LEG"].set(budget)
                try:
                    def attempt(sequence, remaining):
                        phase = driver.warm_attempt(sequence, remaining)
                        os.write(slave, self.live_frame(sequence, complete=False).encode())
                        return phase
                    gate["H6"]["warm_successor"](capture, driver.images[1], attempt,
                        "metrics", max_attempts=20, timeout=15)
                finally:
                    gate["H6"]["ACTIVE_LEG"].reset(token)
            finally:
                os.close(slave)
        with self.assertRaisesRegex(gate["H6"]["LegCleanupError"], "incomplete public live frame"):
            self.protocol("leader", check, gate=gate)
        self.assertTrue(self.last_case.cleanup_failed)
        self.assertFalse(any(row.get("phase") == "post" for row in self.last_driver.stdout.records))
        self.assertIsNone(self.last_driver.owned.pidfd)
        self.assertIsNone(captures[0].master)
        self.assertFalse(captures[0].thread.is_alive())
        self.assertTrue(all(not scope.owners and not scope.readers for scope in self.last_case.scopes))

    def test_truncated_pipe_ledger_stops_matrix_and_releases_actual_child_and_streams(self):
        gate = self.load()
        with tempfile.TemporaryDirectory(prefix="ia32-partial-pipe-") as tmp:
            directory = Path(tmp)
            case = gate["H6"]["Case"](type("Args", (), {"out": directory, "uid": os.getuid(), "gid": os.getgid()})())
            attempted, children = [], []
            @gate["H6"]["owned_leg"](stop_b=True)
            def runner(ctx, cell, backend, kind, leg_directory):
                attempted.append((cell, backend, kind))
                leg_directory.mkdir(parents=True)
                child = gate["H6"]["spawn_owned"](ctx.owners, [sys.executable, "-c",
                    "import os,time; os.write(1, b'N3LEDGER {\"kind\":\"ack\"'); os.close(1); time.sleep(30)"],
                    os.getuid(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append(child)
                capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    child.popen.stdout, leg_directory / "stdout")
                gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                    child.popen.stderr, leg_directory / "stderr")
                gate["H6"]["expect_line"](capture, 0, "N3LEDGER ", 2)
                self.fail("truncated ledger armed measurement")
            with contextlib.redirect_stdout(io.StringIO()):
                results = gate["run_selected"](case, gate["CELLS"], gate["BACKENDS"], runner)
            self.assertEqual(attempted, [("pid-leader", "singles", "trace")])
            self.assertTrue(case.cleanup_failed)
            self.assertIn("reader", results[0]["errors"][0])
            self.assertIsNone(children[0].pidfd)
            self.assertTrue(children[0].popen.stdout.closed)
            self.assertTrue(children[0].popen.stderr.closed)
            self.assertTrue(all(not scope.owners and not scope.readers for scope in case.scopes))

    def test_nonzero_and_forced_stop_keep_the_caller_at_f_and_share_one_terminal_budget(self):
        for fault in ("nonzero", "forced"):
            with self.subTest(fault=fault):
                gate = self.load()
                observers, signals, waits, budgets = [], [], [], []
                def check(gate, ctx, driver):
                    driver.warm_attempt(1, 2)
                    driver.measure()
                    ctx.observer_start = len(ctx.owners)
                    code = ("import signal,time,sys; "
                            "signal.signal(signal.SIGINT, signal.SIG_IGN if sys.argv[1] == 'forced' else lambda *_: exit(7)); "
                            "print('ready', flush=True); time.sleep(30)")
                    owner = gate["H6"]["spawn_owned"](ctx.owners, [sys.executable, "-c", code, fault], os.getuid(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    observers.append(owner)
                    ctx.observer_owned = owner
                    capture = gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                        owner.popen.stdout, driver.directory / "stop.stdout")
                    gate["H6"]["owned_reader"](ctx.readers, gate["H6"]["Reader"],
                        owner.popen.stderr, driver.directory / "stop.stderr")
                    gate["H6"]["expect_line"](capture, 0, "ready", 2)
                    original_wait, original_send = owner.popen.wait, owner.send
                    def wait(timeout):
                        waits.append(timeout)
                        if fault == "forced" and len(waits) == 1:
                            raise subprocess.TimeoutExpired(owner.popen.args, timeout)
                        return original_wait(timeout=timeout)
                    def send(signum):
                        signals.append(signum)
                        return original_send(signum)
                    try:
                        with mock.patch.object(owner.popen, "wait", wait), mock.patch.object(owner, "send", send):
                            gate["H6"]["stop_b_observer"](ctx, owner)
                    finally:
                        budgets.append((ctx.terminal_budget, ctx.terminal_budget.deadline_ns))
                    self.fail("failed normal stop released caller F")
                with self.assertRaises(gate["H6"]["LegCleanupError"]):
                    self.protocol("leader", check, gate=gate)
                self.assertTrue(self.last_case.cleanup_failed)
                self.assertEqual(len(observers), 1)
                receipt = observers[0].stop_receipt
                self.assertEqual(receipt["stop_limit_seconds"], 60)
                self.assertEqual(receipt["cleanup_limit_seconds"], 5)
                self.assertEqual(receipt["forced_cleanup"], fault == "forced")
                self.assertEqual(signals, [signal.SIGINT, signal.SIGKILL] if fault == "forced" else [signal.SIGINT])
                self.assertGreater(waits[0], 0)
                self.assertLessEqual(waits[0], 60)
                if fault == "forced": self.assertLessEqual(waits[1], 5)
                self.assertEqual(budgets[0][0].deadline_ns, budgets[0][1])
                self.assertNotIn("finish-start", self.last_driver.stamps)
                self.assertFalse(any(row.get("phase") == "done" for row in self.last_driver.stdout.records))
                self.assertEqual(len([row for row in self.last_driver.stdout.records if row.get("phase") == "post" and row["kind"] == "call"]), 17)
                self.assertIsNone(self.last_driver.owned.pidfd)
                self.assertIsNone(observers[0].pidfd)
                self.assertTrue(all(not scope.owners and not scope.readers and not scope.leg_pins for scope in self.last_case.scopes))

    def test_reused_session_requires_two_real_successful_open_session_outputs(self):
        gate, snapshot = self.protocol("leader")
        calls = [r for r in snapshot["ledger"] if r["kind"] == "call" and r["fn"] == "C_OpenSession"]
        self.assertEqual([(r["image"], r["phase"], r["rv"], r["sess"]) for r in calls],
                         [(0, "setup", 0, 1), (1, "setup", 0, 1)])
        reuse = gate["H6"]["session_reuse_from"](snapshot["ledger"])
        self.assertTrue(reuse["observed"])
        for change in ("missing", "failed", "different", "zero"):
            with self.subTest(change=change):
                ledger = copy.deepcopy(snapshot["ledger"])
                row = next(r for r in ledger if r["kind"] == "call" and r["fn"] == "C_OpenSession" and r["image"] == 1)
                if change == "missing": ledger.remove(row)
                elif change == "failed": row["rv"] = 5
                elif change == "different": row["sess"] = 2
                else: row["sess"] = 0
                self.assertTrue(gate["workload_errors"](ledger, snapshot, "leader"), change)

    def capture(self, mode="leader", kind="trace", backend="singles"):
        gate, snapshot = self.protocol(mode)
        self.assertTrue("build_receipt" in gate, "ia32 installed receipt/evaluator boundary missing")
        calls = [r for r in snapshot["ledger"] if r["kind"] == "call"]
        paths = {r["image"]: r["path"] for r in snapshot["images"]}
        rows = [f'21:37:58.638119 {json.dumps(Path(paths[r["image"]]).name)} '
                f'(PID {r["pid"]}, TID {r["tid"]}) exe={json.dumps(paths[r["image"]])} '
                f'{r["fn"]} [semantics unverified] → '
                f'{"CKR_OK" if r["rv"] == 0 else "CKR_GENERAL_ERROR"} 10µs' for r in calls]
        abandoned = int(mode == "leader")
        ev = {"privacy_mode": "aggregate-only" if kind == "metrics" else "allowlisted",
              "trace_truncated": False, "final_drain": True, "completeness": "PARTIAL",
              "event_loss": 0, "start_insert_failures": 0, "unmatched_returns": 0,
              "rv_update_failures": 0, "cgroup_scope_failures": 0,
              "process_tracking_failures": 0, "process_tracking_evictions": 0,
              "in_flight_at_end": abandoned, "task_uprobe_link_losses": 0,
              "attach_backend": {"selection": backend, "fallback": None,
                                 "scope_filter": "perf-task+bpf" if backend == "singles" else "kernel-pid+bpf"}}
        text = "Trace — completed call events in arrival order\nExecutable labels use verified observed paths; event PID/TID remain diagnostic identifiers.\nCAPTURE privacy=allowlisted\n"
        text += "\n".join(rows) + "\nCOUNT_EVIDENCE " + json.dumps({
            "stats_entered": 32 if mode == "leader" else 30,
            "stats_returned": 31 if mode == "leader" else 30,
            "raw_calls": 31 if mode == "leader" else 30}) + "\nEVIDENCE " + json.dumps(ev) + "\n"
        pin = snapshot["provider_before"]
        argv = ["/installed/p11scope", "trace" if kind == "trace" else "profile", "--pid", str(snapshot["pid"]),
                "--module", pin["path"], "--attach-backend", backend]
        if kind != "trace": argv += ["--mode", kind]
        observer = {"argv": argv, "started_ns": snapshot["spawned_ns"],
                    "ready_ns": calls[0]["t0"] - 1, "stopped_ns": snapshot["finished_ns"],
                    "rc": 0, "caller_rc": 0, "stderr": "", "stop": {
                        "stop_limit_seconds": 60, "stop_latency_seconds": 0.1, "forced_cleanup": False}}
        proof = None
        if mode == "leader":
            warm = next(r for r in calls if r["fn"] == "C_GetInfo")
            proof = {"image": 1, "started_ns": warm["t0"] - 1, "observed_ns": warm["t1"] + 1,
                     "deadline_ns": warm["t0"] - 1 + 15_000_000_000, "attempts": 1, "max_attempts": 20,
                     "output_cursor": 15, "proof_cursor": 17, "marker_fn": "C_GetInfo",
                     "phases": ["successor-1-1"], "proof_kind": "trace-row"}
        doc = None
        if kind != "trace":
            def live(functions):
                return ("\x1b[2J\x1b[Hp11scope — profile\n"
                        f'{sum(c for _, c, _, _ in functions)} completed calls; '
                        f'{sum(e for _, _, e, _ in functions)} returned errors; '
                        f'{sum(f for _, _, _, f in functions)} entries without an observed return.\n'
                        "FUNCTION CALLS ERR p50 p95 p99 IN-FLIGHT\n"
                        + "".join(f"{fn} {c} {e} 1µs 1µs 1µs {f}\n" for fn, c, e, f in functions)
                        + "(~ = log2-bucket approximation, lower bound)\nEvidence: owned controlled output\n")
            text = live([("C_Initialize", 11, 5, 1), ("C_OpenSession", 2, 0, 0)])
            text += live([("C_Initialize", 11, 5, 1), ("C_OpenSession", 2, 0, 0), ("C_GetInfo", 1, 0, 0)])
            text += live([("C_Initialize", 11, 5, 1), ("C_OpenSession", 2, 0, 0), ("C_GetInfo", 1, 0, 0), ("C_GetSessionInfo", 17, 8, 0)])
            frames = gate["H6"]["parse_live_frames"](text)
            proof.update(proof_kind="live-counter", baseline=frames[0], snapshot=frames[1],
                         output_cursor=frames[0]["cursor"], proof_cursor=frames[1]["cursor"])
            doc = {"schema": "p11scope/observed-profile/v3" + ("-metrics" if kind == "metrics" else ""),
                   "lane": kind, "capture": {"mode": kind, "scope": "pid",
                       "privacy_mode": ev["privacy_mode"], "modules": [pin]}, "evidence": ev,
                   "functions": [{"names": [fn], "calls": c, "errors": e, "in_flight": f}
                                 for fn, c, e, f in (("C_Initialize", 11, 5, 1), ("C_OpenSession", 2, 0, 0),
                                                     ("C_GetInfo", 1, 0, 0), ("C_GetSessionInfo", 17, 8, 0))]}
        receipt = gate["build_receipt"](snapshot, mode, backend, kind, observer, proof)
        return gate, text, doc, snapshot["ledger"], receipt

    def test_real_ledger_positives_use_existing_trace_profile_metrics_evaluators(self):
        for mode, kinds in (("leader", ("trace", "profile", "metrics")), ("failed", ("trace",))):
            for backend in ("singles", "multi"):
                for kind in kinds:
                    with self.subTest(mode=mode, kind=kind, backend=backend):
                        gate, text, doc, ledger, receipt = self.capture(mode, kind, backend)
                        result = gate["evaluate_ia32"](text, doc, ledger, receipt, kind, text if kind == "trace" else None)
                        self.assertTrue(result["pass"], result["errors"])
                        self.assertEqual(result["measured_calls"], 17)
                        self.assertEqual(result["expected_api_returns"], 31 if mode == "leader" else 30)

    def test_public_trace_gate_rejects_stale_wrong_unknown_missing_duplicate_rv_and_early_measurement(self):
        gate, text, doc, ledger, receipt = self.capture()
        for change in ("stale", "wrong", "unknown", "missing", "duplicate", "rv", "early", "attempts", "deadline", "backend", "filter"):
            with self.subTest(change=change):
                bad = copy.deepcopy(receipt)
                output = text
                lines = output.splitlines()
                if change == "stale": bad["successor_ready"][0]["proof_cursor"] = bad["successor_ready"][0]["output_cursor"]
                elif change == "wrong": lines[16] = lines[16].replace(receipt["images"][1]["path"], "/wrong")
                elif change == "unknown":
                    row = ledger[0]["pid"]
                    lines[16] = f"21:37:58.638119 Unknown executable (PID {row}, TID {row}) C_GetInfo [semantics unverified] → CKR_OK 10µs"
                elif change == "missing": del lines[17]
                elif change == "duplicate": lines.insert(18, lines[17])
                elif change == "rv": lines[17] = lines[17].replace("CKR_OK", "CKR_GENERAL_ERROR")
                elif change == "early": bad["successor_ready"][0]["observed_ns"] = bad["measured"]["t0"] + 1
                elif change == "attempts": bad["successor_ready"][0]["max_attempts"] = 21
                elif change == "deadline": bad["successor_ready"][0]["deadline_ns"] += 1
                elif change in ("backend", "filter"):
                    ev = json.loads(lines[-1][9:])
                    ev["attach_backend"]["selection" if change == "backend" else "scope_filter"] = "auto"
                    lines[-1] = "EVIDENCE " + json.dumps(ev)
                output = "\n".join(lines) + "\n"
                result = gate["evaluate_ia32"](output, doc, ledger, bad, "trace", output)
                self.assertFalse(result["pass"], change)

    def test_failed_exec_gate_rejects_successor_changed_image_lost_return_and_link_loss(self):
        gate, text, doc, ledger, receipt = self.capture("failed")
        for change in ("successor", "image", "return", "loss"):
            with self.subTest(change=change):
                bad, calls, output = copy.deepcopy(receipt), copy.deepcopy(ledger), text
                if change == "successor": bad["successor_ready"] = [{"image": 1}]
                elif change == "image": bad["images"][0]["ino"] += 1
                elif change == "return": calls[:] = [r for r in calls if r.get("phase") != "held-return"]
                elif change == "loss":
                    lines = output.splitlines(); ev = json.loads(lines[-1][9:]); ev["task_uprobe_link_losses"] = 1
                    lines[-1] = "EVIDENCE " + json.dumps(ev); output = "\n".join(lines) + "\n"
                self.assertFalse(gate["evaluate_ia32"](output, doc, calls, bad, "trace", output)["pass"], change)


if __name__ == "__main__":
    unittest.main()
