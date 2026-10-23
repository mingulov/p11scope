#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise final-drain readiness through the real Inventory output driver."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
DRIVER = runpy.run_path(str(ROOT / "tests/fixtures/inventory-output-drive.py"))
RUN_CELL_GLOBALS = DRIVER["run_cell"].__globals__
PASS_MARKER = b"p11scope: pass 0:"


class FakeClock:
    def __init__(self):
        self.now = 1.0

    def monotonic(self):
        self.now += 0.001
        return self.now

    @staticmethod
    def sleep(_seconds):
        pass


class InventoryOutputReadinessTest(unittest.TestCase):
    def run_controlled_cell(self, *, case, payload, chunks=None, stderr=b""):
        temporary = tempfile.TemporaryDirectory(prefix="inventory-output-readiness-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        cell_root = base / "cell"
        self.last_cell_root = cell_root
        ledger = base / "ledger.txt"
        ledger.write_text("CALL fixture\n", encoding="utf-8")
        workload = base / "workload.json"
        workload.write_text(json.dumps({
            "pid": 4242, "modules": [], "ledger": str(ledger),
        }), encoding="utf-8")
        args = SimpleNamespace(case=case, capture="scan", binary="/fixture/p11scope",
                               evidence_dir=base)
        stdout_chunks = list(chunks if chunks is not None else [payload])
        state = {"done": False, "stdout_fd": None, "stderr_fd": None,
                 "stdout_chunks": stdout_chunks, "stderr_chunks": [stderr] if stderr else []}
        target_pid = 42001
        observer_pid = target_pid - 1

        class FakeObserver:
            def __init__(self, command, **_kwargs):
                self.pid = observer_pid
                self.returncode = None
                self.poll_count = 0
                spec = json.loads(Path(command[-1]).read_text(encoding="utf-8"))
                state["launch_spec"] = Path(command[-1])
                Path(spec["target_receipt"]).write_text(
                    json.dumps({"pid": target_pid}), encoding="utf-8"
                )
                Path(spec["ready"]).write_text(f"target {target_pid}\n", encoding="utf-8")
                (cell_root / "events.jsonl").write_text(
                    '{"event":"ended"}\n', encoding="utf-8"
                )

            def poll(self):
                self.poll_count += 1
                if self.poll_count == 1:
                    return None
                state["done"] = True
                self.returncode = 1 if case == "pipe-stall" else 0
                return self.returncode

            def kill(self):
                pass

            def wait(self, timeout=None):
                self.assert_wait_timeout = timeout
                return self.returncode

        def controlled_drain(fd, into):
            if not state["done"]:
                return False
            if state["stdout_fd"] is None:
                state["stdout_fd"] = fd
            if fd == state["stdout_fd"]:
                data = state["stdout_chunks"]
            else:
                if state["stderr_fd"] is None:
                    state["stderr_fd"] = fd
                self.assertEqual(fd, state["stderr_fd"])
                data = state["stderr_chunks"]
            if data:
                into.extend(data.pop(0))
                return True
            return False

        def fake_fixtures(root, _large):
            driver = root / "fake catalog driver"
            module = root / "fake provider.so"
            driver.write_bytes(b"driver fixture")
            module.write_bytes(b"provider fixture")
            return driver, [str(module)]

        clock = FakeClock()
        subprocess_proxy = SimpleNamespace(Popen=FakeObserver, DEVNULL=subprocess.DEVNULL)
        ctypes_proxy = SimpleNamespace(
            CDLL=lambda *_args, **_kwargs: SimpleNamespace(prctl=lambda *_values: 0)
        )
        overrides = {
            "drain": controlled_drain,
            "fixtures": fake_fixtures,
            "subprocess": subprocess_proxy,
            "ctypes": ctypes_proxy,
            "time": clock,
        }
        with mock.patch.dict(RUN_CELL_GLOBALS, overrides), \
                mock.patch.dict(os.environ, {"P11SCOPE_INVENTORY_OUTPUT_NO_REPORT": "1"}), \
                mock.patch.object(os, "getpgid", side_effect=lambda pid: observer_pid
                                  if pid == target_pid else self.fail(f"unexpected getpgid({pid})")), \
                mock.patch.object(os, "waitpid", side_effect=lambda pid, flags: (pid, 0)
                                  if pid == target_pid and flags == os.WNOHANG
                                  else self.fail(f"unexpected waitpid({pid}, {flags})")):
            cell = DRIVER["run_cell"](args, cell_root, "controlled")
        self.last_launch_spec = state["launch_spec"]
        return cell

    def run_fixture_main(self, *, capture="scan", compiler_fails=False):
        temporary = tempfile.TemporaryDirectory(prefix="inventory-output-fixtures-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        evidence = base / "evidence"
        binary = base / "observer"
        binary.write_bytes(b"controlled observer")
        compiler_commands, observed, providers, drivers = [], [], [], []

        def compiler(command, **_kwargs):
            self.assertEqual(capture, "scan", "native cells must never invoke a compiler")
            self.assertEqual(command[0], "gcc")
            compiler_commands.append(command)
            if compiler_fails:
                return SimpleNamespace(returncode=1, stderr=b"controlled compiler refusal")
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(b"compiled provider" if "-shared" in command else b"compiled driver")
            return SimpleNamespace(returncode=0, stderr=b"")

        def observer_cell(args, root, label, **options):
            observed.append(label)
            if capture == "scan":
                root.mkdir(mode=0o700)
                driver, modules = DRIVER["fixtures"](root, options.get("large", False))
                drivers.append(driver)
                providers.extend(Path(module) for module in modules)
            return {"cleanup": {"observer_reaped": True, "descriptors_closed": True,
                                "target_reaped": True}}

        with mock.patch.dict(RUN_CELL_GLOBALS, {
            "subprocess": SimpleNamespace(run=compiler), "run_cell": observer_cell,
        }), mock.patch.object(sys, "argv", [
            "inventory-output-drive.py", "--binary", str(binary), "--capture", capture,
            "--case", "pipe-stall", "--evidence-dir", str(evidence),
        ]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = DRIVER["main"]()
        receipt = json.loads((evidence / "control.json").read_text(encoding="utf-8"))
        return status, receipt, compiler_commands, observed, drivers, providers

    def test_scan_json_and_text_cells_build_once_with_distinct_equal_provider_copies(self):
        status, receipt, commands, observed, drivers, providers = self.run_fixture_main()
        self.assertEqual(status, 0, receipt)
        self.assertEqual(observed, ["json", "text"])
        self.assertEqual(len(commands), 2, "one driver and provider build per invocation")
        self.assertEqual(len(providers), 2)
        self.assertEqual([path.read_bytes() for path in providers], [b"compiled provider"] * 2)
        identities = {(path.stat().st_dev, path.stat().st_ino) for path in providers}
        self.assertEqual(len(identities), 2, "equal bytes must not alias physical modules")
        self.assertEqual(len(set(drivers)), 1, "both cells reuse the same compiled driver")
        template = Path(commands[1][commands[1].index("-o") + 1])
        self.assertNotIn((template.stat().st_dev, template.stat().st_ino), identities)

    def test_scan_compile_failure_precedes_every_observer_cell(self):
        status, receipt, commands, observed, _drivers, _providers = self.run_fixture_main(
            compiler_fails=True,
        )
        self.assertEqual(status, 1)
        self.assertFalse(receipt["success"])
        self.assertIn("controlled compiler refusal", receipt["error"])
        self.assertEqual(len(commands), 1)
        self.assertEqual(observed, [], "a failed build must not start an observer cell")
        self.assertEqual(receipt["cells"], [])

    def test_native_main_never_enters_the_compiler(self):
        status, receipt, commands, observed, drivers, providers = self.run_fixture_main(
            capture="native",
        )
        self.assertEqual(status, 0, receipt)
        self.assertEqual(observed, ["json", "text"])
        self.assertEqual(commands, [])
        self.assertEqual(drivers, [])
        self.assertEqual(providers, [])

    def test_scan_launcher_executes_the_ready_owned_pid_scope(self):
        self.run_controlled_cell(case="signal-baseline", payload=self.healthy_payload())
        target = SimpleNamespace(pid=42001, poll=lambda: None)
        with mock.patch.dict(RUN_CELL_GLOBALS, {
            "subprocess": SimpleNamespace(Popen=lambda *_args, **_kwargs: target,
                                          DEVNULL=subprocess.DEVNULL),
        }), mock.patch.object(os, "execv") as execute:
            DRIVER["launcher"](self.last_launch_spec)
        binary, argv = execute.call_args.args
        self.assertEqual(binary, "/fixture/p11scope")
        self.assertEqual(argv[:4], [binary, "inventory", "--pid", "42001"])
        self.assertNotIn("--system", argv)

    def healthy_payload(self, progress=True):
        return json.dumps({
            "schema": "p11scope/inventory/v1",
            "observation": {"lane": "scan"},
            "progress": "p11scope: pass 0:" if progress else "completed without progress",
        }).encode("utf-8") + b"\n"

    def test_completed_healthy_progress_is_ready_even_when_first_seen_in_final_drain(self):
        payload = self.healthy_payload()
        marker_at = payload.index(PASS_MARKER)
        cell = self.run_controlled_cell(
            case="signal-baseline", payload=payload,
            chunks=[payload[:marker_at + 5], payload[marker_at + 5:]],
        )
        self.assertEqual(cell["exit"], 0)
        self.assertTrue(cell["cleanup"]["observer_reaped"])
        self.assertTrue(cell["cleanup"]["target_reaped"])
        self.assertTrue(cell["cleanup"]["descriptors_closed"])

    def test_stalled_pipe_progress_split_across_final_drain_is_counted(self):
        payload = b"p11scope: pass 0: completed\n"
        split = len(b"p11scope: pass ")
        remaining = 7
        diagnostic = (
            f"accepted {len(payload)} of {len(payload) + remaining} bytes; "
            f"remaining {remaining} not written; no progress\n"
        ).encode()
        # The seed fills the controlled pipe exactly as run_cell expects; the
        # observer bytes arrive only after its exit, during the final drain.
        chunks = [b"S" * 4096 + payload[:split], payload[split:]]
        cell = self.run_controlled_cell(
            case="pipe-stall", payload=payload, chunks=chunks, stderr=diagnostic,
        )
        self.assertEqual(cell["exit"], 1)
        self.assertEqual(cell["stdout_result"], {
            "accepted": len(payload), "total": len(payload) + remaining,
            "remaining": remaining,
        })
        self.assertTrue(cell["cleanup"]["observer_reaped"])
        self.assertTrue(cell["cleanup"]["target_reaped"])
        self.assertTrue(cell["cleanup"]["descriptors_closed"])

    def test_completed_output_without_progress_remains_unready(self):
        payload = self.healthy_payload(progress=False)
        with self.assertRaisesRegex(AssertionError, "command never reached capture readiness"):
            self.run_controlled_cell(case="signal-baseline", payload=payload)
        cell = json.loads((self.last_cell_root / "cell.json").read_text(encoding="utf-8"))
        self.assertTrue(cell["cleanup"]["observer_reaped"])
        self.assertTrue(cell["cleanup"]["target_reaped"])
        self.assertTrue(cell["cleanup"]["descriptors_closed"])


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(InventoryOutputReadinessTest)
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)
