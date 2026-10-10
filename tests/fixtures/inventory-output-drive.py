#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Own scan CLI/PTY controls; reuse with an explicitly supplied native binary.

Native mode requires P11SCOPE_INVENTORY_OUTPUT_WORKLOAD pointing to coordinator
JSON {pid, modules: [paths], ledger: path, gate: optional path}. The coordinator
owns that native workload and lane; this driver owns only its observer/fds.
Scan mode uses an observer-child catalog workload, then subreaps it after exit.
All watchdogs fail; permanently stopped outputs resume only in final cleanup.
Reader timestamps are reader times, never claimed as accepted-write times.
"""

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import termios
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def launcher(spec_path):
    spec = json.loads(Path(spec_path).read_text())
    target = subprocess.Popen(spec["target"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    save(spec["target_receipt"], {"pid": target.pid, "spawned": time.monotonic()})
    deadline = time.monotonic() + 10
    pid = None
    while pid is None:
        assert target.poll() is None, "catalog workload exited before readiness"
        assert time.monotonic() < deadline, "catalog workload readiness watchdog"
        try:
            pid = int(Path(spec["ready"]).read_text().split()[1])
        except (OSError, IndexError, ValueError):
            pid = None
            time.sleep(0.01)
    assert pid == target.pid
    save(spec["target_receipt"], {"pid": pid, "ready": time.monotonic()})
    argv = [x.replace("TARGET_PID", str(pid)) for x in spec["observer"]]
    os.execv(argv[0], argv)


def fixtures(root, large):
    source = Path(__file__).resolve().parents[2]
    driver = root / "catalog-driver"
    provider = root / "provider.so"
    for command in [
        ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(driver),
         str(source / "tests/fixtures/catalog-driver.c"), "-ldl"],
        ["gcc", "-shared", "-fPIC", "-DLEGACY_MINOR=40", "-o", str(provider),
         str(source / "crates/discover/tests/fixture/version_matrix.c")],
    ]:
        result = subprocess.run(command, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    modules = []
    for i in range(96 if large else 1):
        path = root / f"provider-{i:03d}.so"
        shutil.copyfile(provider, path)
        modules.append(str(path))
    return driver, modules


def drain(fd, into):
    try:
        chunk = os.read(fd, 1024)
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO):
            return False
        raise
    if chunk:
        into.extend(chunk)
        return True
    return False


def writer_wait(pid):
    """Observe an owned classic observer waiting in write(fd1) or poll.

    This establishes final-writer engagement; it does not measure accepted
    write progress. Scan capture uses collection/clock waits, not this poll.
    """
    try:
        fields = Path(f"/proc/{pid}/syscall").read_text().split()
        number = int(fields[0])
        if number == 1 and int(fields[1], 0) == 1:
            return "write(fd1)"
        if number == 7:
            return "poll"
    except (OSError, ValueError, IndexError):
        pass
    return None


def run_cell(args, root, label, *, json_output=True, first_signal=None,
             baseline=0, large=False):
    root.mkdir(mode=0o700)
    begin = time.monotonic()
    report, events = root / "report.json", root / "events.jsonl"
    tty = args.case in ("tty-stall", "tty-shared-stderr", "dashboard-json-stall", "xoff-resume")
    dashboard = args.case == "dashboard-json-stall"
    stalled = args.case in ("pipe-stall", "tty-stall", "tty-shared-stderr", "dashboard-json-stall", "signal-stall")
    shared = args.case == "tty-shared-stderr"
    signals = []
    stdout, stderr = bytearray(), bytearray()
    fds = []
    observer = None
    target_pid = None
    original_error = None
    stopped = False
    reader_times = []
    committed_at = None
    cell = {"label": label, "json": json_output, "capture": args.capture,
            "signal_baseline_expected": baseline, "watchdog": False,
            "write_clock_instrumented": False, "cleanup": {}}
    without_report = os.environ.get("P11SCOPE_INVENTORY_OUTPUT_NO_REPORT") == "1"
    assert not without_report or args.capture == "scan", "native acceptance requires the report"
    cell["independent_report_requested"] = not without_report
    try:
        if tty:
            read_fd, write_fd = pty.openpty()
            fds.extend([read_fd, write_fd])
            attrs = termios.tcgetattr(write_fd)
            attrs[1] &= ~(termios.OPOST | termios.ONLCR)
            attrs[0] |= termios.IXON
            termios.tcsetattr(write_fd, termios.TCSANOW, attrs)
            saved_termios = termios.tcgetattr(write_fd)
            input_fd = write_fd
            cell["ixon_enabled"] = bool(saved_termios[0] & termios.IXON)
            seed = 0
        else:
            read_fd, write_fd = os.pipe()
            fds.extend([read_fd, write_fd])
            fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
            input_fd = subprocess.DEVNULL
            seed = 0
            if stalled:
                os.set_blocking(write_fd, False)
                while True:
                    try:
                        seed += os.write(write_fd, b"S" * 4096)
                    except BlockingIOError:
                        break
                os.set_blocking(write_fd, True)
            cell["pipe_capacity"] = fcntl.fcntl(write_fd, fcntl.F_GETPIPE_SZ)
        before_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        err_read, err_write = os.pipe()
        fds.extend([err_read, err_write])
        os.set_blocking(read_fd, False)
        os.set_blocking(err_read, False)
        duration = "120s" if first_signal is not None else "3s"
        scope = ["--system", "--max-scan-pids", "4096"] if args.capture == "scan" else ["--pid", "TARGET_PID"]
        argv = [args.binary, "inventory", *scope, "--capture", args.capture, "--duration", duration]
        if not without_report:
            argv.extend(["-o", str(report), "--event-log", str(events)])
        if json_output:
            argv.append("--json")
        if dashboard:
            argv.append("--dashboard")
        if args.capture == "scan":
            # PR_SET_CHILD_SUBREAPER changes only this owned driver's custody.
            assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
            driver, modules = fixtures(root, large)
            ready = root / "target.ready"
            receipt = root / "target.json"
            spec = root / "launch.json"
            save(spec, {"target": [str(driver), "--ready", str(ready), "--call", "--sleep", "120", *modules],
                        "ready": str(ready), "target_receipt": str(receipt), "observer": argv})
            command = [sys.executable, "-I", str(Path(__file__).resolve()), "--launch-spec", str(spec)]
            cell["workload"] = {"kind": "owned-catalog", "provider_count": len(modules),
                                "driver_sha256": digest(driver), "provider_sha256": digest(modules[0])}
        else:
            config = json.loads(Path(os.environ["P11SCOPE_INVENTORY_OUTPUT_WORKLOAD"]).read_text())
            target_pid = int(config["pid"])
            assert target_pid > 1 and Path(config["ledger"]).is_file()
            argv[argv.index("TARGET_PID")] = str(target_pid)
            for module in config["modules"]:
                argv.extend(["--module", module])
            command = argv
            cell["workload"] = {"kind": "coordinator-owned-native", "pid": target_pid,
                                "ledger": config["ledger"]}
        observer = subprocess.Popen(command, stdin=input_fd, stdout=write_fd,
                                    stderr=write_fd if shared else err_write, start_new_session=True)
        os.close(err_write)
        fds.remove(err_write)
        deadline = begin + (90 if large else 20)
        capture_ready = False
        signal_sent = False
        later_sent = False
        stopped_at = None
        resumed = False
        next_read = 0.0
        while observer.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                cell["watchdog"] = True
                raise AssertionError("owned observer watchdog; kill/reap is failure")
            if not shared:
                while drain(err_read, stderr):
                    pass
            if not stalled or (tty and not stopped):
                if now >= next_read and drain(read_fd, stdout):
                    reader_times.append(now)
                    next_read = now + (0.04 if large else 0)
            if events.exists() and b'"started"' in events.read_bytes():
                capture_ready = True
            if without_report and (b"p11scope: pass 0:" in stderr or b"p11scope: pass 0:" in stdout
                                   or dashboard and b"p11scope inventory" in stdout):
                capture_ready = True
            if capture_ready and tty and not stopped:
                if dashboard and b"p11scope inventory" not in stdout:
                    time.sleep(0.01)
                    continue
                if args.case == "xoff-resume":
                    assert cell["ixon_enabled"], "IXON was not enabled"
                    os.write(read_fd, b"\x13")
                    time.sleep(0.03)
                else:
                    termios.tcflow(write_fd, termios.TCOOFF)
                stopped = True
                stopped_at = time.monotonic()
                probe = os.open(f"/proc/self/fd/{write_fd}", os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
                try:
                    try:
                        os.write(probe, b"backpressure-probe")
                    except BlockingIOError:
                        cell["backpressure_eagain"] = True
                    else:
                        raise AssertionError("PTY stop did not produce real EAGAIN")
                finally:
                    os.close(probe)
            if capture_ready and first_signal is not None and not signal_sent:
                os.kill(observer.pid, first_signal)
                signals.append({"signal": first_signal, "sent": now, "phase": "capture"})
                signal_sent = True
            if args.capture == "native" and capture_ready and config.get("gate"):
                Path(config["gate"]).touch()
            if report.exists() and committed_at is None:
                committed_at = now
                cell["report_commit_observed"] = now
                if signal_sent:
                    cell["capture_stop_ack"] = "report committed after capture signal"
            if without_report and capture_ready and committed_at is None:
                waiting = writer_wait(observer.pid)
                if len(stdout) >= 1024 or waiting:
                    committed_at = now
                    cell["final_writer_engagement"] = waiting or "stdout prefix observed"
                    if signal_sent:
                        cell["capture_stop_ack"] = "writer engaged before the 120s capture deadline"
            if args.case == "xoff-resume" and stopped and not resumed and committed_at is not None:
                if now - committed_at >= 2:
                    os.write(read_fd, b"\x11")
                    resumed = True
                    cell["xoff_resumed"] = now
            if args.case in ("signal-stall", "signal-progress") and committed_at is not None and not later_sent:
                if args.case != "signal-progress" or len(stdout) >= 1024:
                    os.kill(observer.pid, signal.SIGTERM if baseline else signal.SIGINT)
                    signals.append({"signal": signal.SIGTERM if baseline else signal.SIGINT,
                                    "sent": now, "phase": "final output"})
                    later_sent = True
            assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == before_flags, "inherited stdout flags changed"
            time.sleep(0.005)
        ended = time.monotonic()
        cell["exit"] = observer.returncode
        cell["elapsed_seconds"] = ended - begin
        cell["signals"] = signals
        cell["reader_drain_times"] = reader_times
        cell["largest_reader_gap_seconds"] = max((b-a for a,b in zip(reader_times, reader_times[1:])), default=0)
        cell["stdout_flags_unchanged"] = fcntl.fcntl(write_fd, fcntl.F_GETFL) == before_flags
        assert cell["stdout_flags_unchanged"]
        if stopped:
            cell["kept_stopped_through_exit"] = not resumed
            if dashboard:
                cell["termios_restored"] = termios.tcgetattr(write_fd) == saved_termios
                assert cell["termios_restored"], "dashboard key termios not restored"
            termios.tcflow(write_fd, termios.TCOON)
            stopped = False
        os.close(write_fd)
        fds.remove(write_fd)
        drain_deadline = time.monotonic() + 3
        while time.monotonic() < drain_deadline:
            changed = drain(read_fd, stdout)
            if not shared:
                changed |= drain(err_read, stderr)
            if not changed and not select.select([read_fd, err_read], [], [], 0.02)[0]:
                break
            if not changed:
                break
        stdout = stdout[seed:]
        if dashboard or shared:
            start = stdout.find(b"{\n")
            stdout_payload = stdout[start:] if start >= 0 else b""
            if dashboard:
                cell["screen_restore_delivered"] = b"\x1b[?1049l" in stdout
        else:
            stdout_payload = stdout
        (root / "stdout.bin").write_bytes(stdout_payload)
        (root / "stderr.bin").write_bytes(stderr)
        failure = stalled or args.case == "signal-progress"
        document_bytes = report.read_bytes() if not without_report else bytes(stdout_payload)
        if not without_report or not failure:
            document = json.loads(document_bytes)
            assert document["schema"] == "p11scope/inventory/v1"
        if args.capture == "native":
            assert document["observation"]["lane"] == "native", "scan fallback fails native cell"
            ledger = Path(config["ledger"]).read_bytes()
            assert b"CALL " in ledger or b"HELD " in ledger, "native workload ledger is empty"
            cell["workload"]["ledger_sha256"] = digest(config["ledger"])
        cell["report_bytes"] = len(document_bytes) if not without_report else None
        cell["stdout_bytes"] = len(stdout_payload)
        cell["report_sha256"] = digest(report) if not without_report else None
        cell["stdout_sha256"] = digest(root / "stdout.bin")
        assert observer.returncode == (1 if failure else 0), f"unexpected exit {observer.returncode}: {stderr!r}"
        if failure and not shared:
            match = re.search(rb"accepted (\d+) of (\d+) bytes; remaining (\d+) not written", stderr)
            assert match, f"missing exact accepted-byte diagnostic: {stderr!r}"
            accepted, total, remaining = map(int, match.groups())
            assert accepted == len(stdout_payload) and accepted + remaining == total
            assert b"stdout complete" not in stderr
            if json_output and not without_report:
                assert total == len(document_bytes) and document_bytes.startswith(stdout_payload)
            cell["stdout_result"] = {"accepted": accepted, "total": total, "remaining": remaining}
            reason = b"cancelled" if args.case in ("signal-stall", "signal-progress") else b"no progress"
            assert reason in stderr.lower(), stderr
            if signals:
                cell["later_delivery_ack"] = "stdout cancellation result"
                cell["later_signal_to_exit_seconds"] = ended - signals[-1]["sent"]
                assert ended - signals[-1]["sent"] < 1.5, "later cancellation remained blocked"
        if not failure:
            assert json_output and stdout_payload.endswith(b"\n"), "healthy JSON payload lacks its newline"
            if not without_report:
                assert stdout_payload == document_bytes, "healthy JSON/report bytes differ"
                assert b'"ended"' in events.read_bytes(), "healthy event stream did not complete"
        if large:
            total = cell.get("stdout_result", {}).get("total", len(document_bytes))
            assert total > 65536, "large CLI document did not exercise multiple chunks"
            if args.case == "large-slow":
                assert reader_times[-1] - reader_times[0] > 5, "healthy CLI slow output did not last >5s"
        assert capture_ready, "command never reached capture readiness"
        if args.capture == "scan":
            target_pid = json.loads((root / "target.json").read_text())["pid"]
        return cell
    except BaseException as error:
        original_error = error
        cell["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        # Evidence I/O must never gate owned cleanup or hide the cell's error.
        cell["signals"] = signals
        cell["reader_drain_times"] = reader_times
        cell["cleanup_started"] = time.monotonic()
        cleanup_errors, evidence_errors = [], []
        cell["cleanup_errors"] = cleanup_errors
        cell["evidence_errors"] = evidence_errors

        def attempt(errors, stage, action):
            try:
                action()
                return True
            except Exception as error:
                errors.append({"stage": stage, "error": f"{type(error).__name__}: {error}"})
                return False

        if observer is not None:
            attempt(cleanup_errors, "observer kill", observer.kill)
            cell["cleanup"]["observer_reaped"] = attempt(
                cleanup_errors, "observer wait", lambda: observer.wait(timeout=2))
        if args.capture == "scan" and observer is not None:
            # Reaping the observer adopts its remaining owned descendants.
            # Metadata sources are independent; neither is authority to signal.
            candidates, expected = set(), set()

            def cached_target():
                if target_pid is not None:
                    if type(target_pid) is not int or target_pid <= 1:
                        raise ValueError("invalid cached owned target PID")
                    candidates.add(target_pid)
                    expected.add(target_pid)

            def adopted_children():
                values = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text().split()
                candidates.update(int(value) for value in values if int(value) != observer.pid)

            def target_receipt():
                pid = json.loads((root / "target.json").read_text())["pid"]
                if type(pid) is not int or pid <= 1:
                    raise ValueError("invalid owned target PID receipt")
                candidates.add(pid)
                expected.add(pid)

            attempt(cleanup_errors, "cached target", cached_target)
            attempt(cleanup_errors, "adopted child metadata", adopted_children)
            attempt(cleanup_errors, "target receipt", target_receipt)
            reaped = {}
            cell["cleanup"]["owned_targets_reaped"] = reaped

            def reap_target(pid):
                if pid == observer.pid:
                    raise RuntimeError("refusing target receipt naming the observer")
                if os.getpgid(pid) != observer.pid:
                    if pid in expected:
                        raise RuntimeError(f"refusing target PID {pid} outside owned observer group")
                    return
                # waitpid proves direct-child custody; an unreaped child PID
                # cannot be reused between this check and the signal.
                done, _ = os.waitpid(pid, os.WNOHANG)
                reaped[str(pid)] = bool(done)
                if not done:
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 2
                    while not done:
                        done, _ = os.waitpid(pid, os.WNOHANG)
                        if done:
                            reaped[str(pid)] = True
                            break
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f"owned target PID {pid} reap watchdog")
                        time.sleep(0.01)

            targets_ok = []
            for pid in sorted(candidates):
                targets_ok.append(attempt(cleanup_errors, f"target PID {pid}", lambda pid=pid: reap_target(pid)))
            cell["cleanup"]["target_reaped"] = bool(reaped) and all(reaped.values()) and all(targets_ok)
        if stopped and write_fd in fds:
            def resume_pty():
                if observer is not None and not cell["cleanup"].get("observer_reaped"):
                    raise RuntimeError("refusing PTY resume before observer reap")
                termios.tcflow(write_fd, termios.TCOON)

            cell["cleanup"]["pty_resumed"] = attempt(cleanup_errors, "PTY resume", resume_pty)
        closed = []
        for fd in list(fds):
            if attempt(cleanup_errors, f"close fd {fd}", lambda fd=fd: os.close(fd)):
                closed.append(fd)
                fds.remove(fd)
        cell["cleanup"]["closed_descriptors"] = closed
        cell["cleanup"]["unclosed_descriptors"] = list(fds)
        cell["cleanup"]["descriptors_closed"] = not fds
        # Retain partial bytes after all cleanup attempts, including failures.
        attempt(evidence_errors, "stdout raw evidence", lambda: (root / "stdout.raw.bin").write_bytes(stdout))
        attempt(evidence_errors, "stderr raw evidence", lambda: (root / "stderr.raw.bin").write_bytes(stderr))
        attempt(evidence_errors, "cell evidence", lambda: save(root / "cell.json", cell))
        if cleanup_errors or evidence_errors:
            failures = {"cleanup_errors": cleanup_errors, "evidence_errors": evidence_errors}
            error = original_error or RuntimeError(f"cell finalization failed: {json.dumps(failures)}")
            error.fixture_finalization_errors = failures
            if original_error is None:
                raise error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--capture", choices=["scan", "native"], required=True)
    parser.add_argument("--case", choices=["pipe-stall", "tty-stall", "tty-shared-stderr",
                        "dashboard-json-stall", "xoff-resume", "large-slow", "signal-baseline",
                        "signal-stall", "signal-progress"], required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = {"case": args.case, "capture": args.capture, "binary": args.binary,
              "binary_sha256": digest(args.binary), "cells": [], "success": False}
    try:
        cells = [("json", {})]
        if args.case == "pipe-stall":
            cells += [("text", {"json_output": False})]
        elif args.case == "signal-baseline":
            cells = [(str(sig), {"first_signal": sig, "baseline": 1})
                     for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
        elif args.case == "signal-stall":
            cells = [("baseline-zero", {}), ("baseline-one", {"first_signal": signal.SIGINT, "baseline": 1})]
        elif args.case == "signal-progress":
            cells = [("progress", {"first_signal": signal.SIGINT, "baseline": 1, "large": True})]
        elif args.case == "large-slow":
            cells = [("slow", {"large": True})]
        for label, options in cells:
            result["cells"].append(run_cell(args, args.evidence_dir / label, label, **options))
        assert all(c["cleanup"].get("observer_reaped") and c["cleanup"].get("descriptors_closed")
                   and (args.capture == "native" or c["cleanup"].get("target_reaped")) for c in result["cells"])
        result["success"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        if hasattr(error, "fixture_finalization_errors"):
            result["finalization_errors"] = error.fixture_finalization_errors
            print(json.dumps(result["finalization_errors"]), file=sys.stderr)
        result["failed_cell_evidence"] = [str(path.relative_to(args.evidence_dir))
                                          for path in sorted(args.evidence_dir.glob("*/cell.json"))]
        print(result["error"], file=sys.stderr)
    save(args.evidence_dir / "control.json", result)
    print(json.dumps(result))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--launch-spec":
        launcher(sys.argv[2])
    else:
        sys.exit(main())
