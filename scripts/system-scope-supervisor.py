#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Launch one gated command and retain all descendants until terminal."""

import argparse
import ctypes
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SCHEMA = "p11scope/system-scope-supervisor/v2"
CLEANUP_SECONDS = 12.0
# The launching shell publishes the wrapper identity right after `$!`; the
# file must appear for a live launch, so this only bounds a slow shell (a
# fixed 3 s refused healthy launches under host load).
WRAPPER_IDENTITY_SECONDS = 30.0
DIRECT_RESERVE_SECONDS = 4.0
DIAGNOSTIC_BYTES = 65_536
GATED_EXEC = r"""
import os, sys
fd = int(sys.argv[1])
try:
    token = os.read(fd, 1)
finally:
    os.close(fd)
if token != b"G":
    raise SystemExit(126)
os.execvp(sys.argv[2], sys.argv[2:])
"""


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("supervisor cleanup deadline expired")
    return left


def numeric_id(value):
    if not value.isdecimal():
        raise argparse.ArgumentTypeError("receipt owner must be numeric")
    number = int(value)
    if not 0 <= number <= 0xFFFFFFFE:
        raise argparse.ArgumentTypeError("receipt owner is out of range")
    return number


def process_record(pid, deadline=None):
    if deadline is not None:
        _remaining(deadline)
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = text.rsplit(") ", 1)[1].split()
    record = {"pid": pid, "state": fields[0], "ppid": int(fields[1]),
              "starttime": int(fields[19])}
    if record["starttime"] <= 0:
        raise RuntimeError(f"invalid process birth identity for {pid}")
    return record


def starttime(pid, deadline=None):
    return process_record(pid, deadline)["starttime"]


def atomic_json(path, value, owner_uid=None, owner_gid=None):
    if (owner_uid is None) != (owner_gid is None):
        raise ValueError("receipt owner UID/GID must be supplied together")
    path = Path(path)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    fd = os.open(temporary, flags, 0o600)
    try:
        payload = (json.dumps(value, sort_keys=True) + "\n").encode()
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
        if owner_uid is not None:
            os.fchown(fd, owner_uid, owner_gid)
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    os.close(fd)
    os.replace(temporary, path)


def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")


def direct_children(pid, deadline=None):
    found = set()
    task = Path(f"/proc/{pid}/task")
    if deadline is not None:
        _remaining(deadline)
    for path in task.glob("*/children"):
        if deadline is not None:
            _remaining(deadline)
        try:
            words = path.read_text(encoding="ascii").split()
        except FileNotFoundError:
            continue
        for word in words:
            if deadline is not None:
                _remaining(deadline)
            if not word.isdecimal() or int(word) <= 0:
                raise RuntimeError(f"malformed child census for {pid}")
            found.add(int(word))
            if len(found) > 4096:
                raise RuntimeError("owned child census exceeds bound")
    return found


def wait_wrapper_identity(path, deadline):
    while True:
        _remaining(deadline)
        try:
            words = Path(path).read_text(encoding="ascii").split()
        except FileNotFoundError:
            words = []
        if len(words) == 2 and all(word.isdecimal() for word in words):
            pid, birth = map(int, words)
            current = process_record(pid, deadline)
            if current["starttime"] != birth:
                raise RuntimeError("outer wrapper birth identity changed")
            # The supervisor is either the exec-replaced wrapper or a bounded
            # descendant of sudo's monitor.
            cursor = os.getpid()
            for _ in range(8):
                if cursor == pid:
                    return {"pid": pid, "starttime": birth}
                record = process_record(cursor, deadline)
                if record["ppid"] <= 1:
                    break
                cursor = record["ppid"]
            raise RuntimeError("registered supervisor is not owned by wrapper")
        if words:
            raise RuntimeError("outer wrapper identity is malformed")
        time.sleep(min(0.01, _remaining(deadline)))


def acquire_direct_child(pid, deadline=None):
    before = process_record(pid, deadline)
    if before["ppid"] != os.getpid():
        return None
    try:
        if deadline is not None:
            _remaining(deadline)
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        if not Path(f"/proc/{pid}").exists():
            return None
        raise
    try:
        after = process_record(pid, deadline)
        if (after["starttime"] != before["starttime"]
                or after["ppid"] != os.getpid()
                or pid not in direct_children(os.getpid(), deadline)):
            raise RuntimeError(f"adopted child {pid} identity/parent changed")
        return {**after, "pidfd": fd}
    except (FileNotFoundError, ProcessLookupError):
        os.close(fd)
        if not Path(f"/proc/{pid}").exists():
            return None
        raise
    except BaseException:
        os.close(fd)
        raise


def signal_retained(handles, sig, errors, *, send=signal.pidfd_send_signal):
    """Attempt one signal independently through every retained pidfd."""
    for owned in handles:
        try:
            send(owned["pidfd"], sig)
            owned.setdefault("signals", []).append(signal.Signals(sig).name)
        except ProcessLookupError:
            pass
        except OSError as error:
            owned["signal_failed"] = True
            record = {"phase": "signal", "pid": owned["pid"],
                      "signal": signal.Signals(sig).name,
                      "error": f"{type(error).__name__}: {error}"}
            errors.append(record)


def helper_command(args, child_pid, child_birth, first_signal):
    return [
        "python3", "-I", args.receipt_helper, "settle-group",
        "--pid", str(child_pid), "--starttime", str(child_birth),
        "--first-signal", first_signal, "--term-timeout", "2",
        "--total-timeout", "4",
    ]


def run_group_helper(args, child_pid, child_birth, first_signal,
                     deadline, receipt, errors):
    attempts = receipt["helper_attempts"]
    attempt = {"kind": "settle-group", "target_pid": child_pid,
               "started_mono_ns": time.monotonic_ns()}
    attempts.append(attempt)
    helper = None
    fd = None
    helper_terminal = False
    retained = None
    try:
        _remaining(deadline)
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, \
             tempfile.TemporaryFile(mode="w+b") as stderr_file:
            helper = subprocess.Popen(
                helper_command(args, child_pid, child_birth, first_signal),
                stdout=stdout_file, stderr=stderr_file,
                start_new_session=True,
            )
            attempt["pid"] = helper.pid
            attempt["starttime"] = starttime(helper.pid, deadline)
            fd = os.pidfd_open(helper.pid, 0)
            retained = {"pid": helper.pid, "starttime": attempt["starttime"],
                        "pidfd": fd}
            # Reserve time for direct cleanup even if the helper hangs. Regular
            # files prevent a helper descendant from holding communicate pipes.
            helper_budget = min(4.5, max(0.05,
                                _remaining(deadline) - DIRECT_RESERVE_SECONDS))
            try:
                helper.wait(timeout=helper_budget)
            except subprocess.TimeoutExpired:
                attempt["timed_out"] = True
                signal_retained([retained], signal.SIGKILL, errors)
                helper.wait(timeout=_remaining(deadline))
            helper_terminal = True
            stdout_file.flush()
            stderr_file.flush()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_raw = stdout_file.read(DIAGNOSTIC_BYTES + 1)
            stderr_raw = stderr_file.read(DIAGNOSTIC_BYTES + 1)
            stdout = stdout_raw[:DIAGNOSTIC_BYTES].decode("utf-8", "replace")
            stderr = stderr_raw[:DIAGNOSTIC_BYTES].decode("utf-8", "replace")
        attempt.update(exit=helper.returncode, stdout=stdout, stderr=stderr,
                       stdout_captured_bytes=min(len(stdout_raw), DIAGNOSTIC_BYTES),
                       stderr_captured_bytes=min(len(stderr_raw), DIAGNOSTIC_BYTES),
                       stdout_truncated=len(stdout_raw) > DIAGNOSTIC_BYTES,
                       stderr_truncated=len(stderr_raw) > DIAGNOSTIC_BYTES,
                       finished_mono_ns=time.monotonic_ns())
        if helper.returncode != 0:
            receipt["helper_failed"] = True
            errors.append({"phase": "helper", "pid": helper.pid,
                           "exit": helper.returncode,
                           "error": stderr.strip() or "settlement helper failed"})
    except BaseException as error:
        receipt["helper_failed"] = True
        attempt["error"] = f"{type(error).__name__}: {error}"
        errors.append({"phase": "helper", "pid": None if helper is None else helper.pid,
                       "error": attempt["error"]})
    finally:
        if fd is not None:
            if not helper_terminal:
                signal_retained([retained], signal.SIGKILL, errors)
                receipt.setdefault("unresolved", []).append({
                    "pid": helper.pid, "starttime": attempt.get("starttime"),
                    "reason": "helper terminal proof unavailable at cleanup deadline",
                })
            os.close(fd)


def settle_adopted(args, first_signal, deadline, receipt):
    """Directly settle subreaper-owned children without another helper."""
    del args, first_signal
    errors = receipt.setdefault("cleanup_errors", [])
    unresolved = receipt.setdefault("unresolved", [])
    reaped = receipt.setdefault("reaped", [])
    blocked = set()
    while True:
        _remaining(deadline)
        children = direct_children(os.getpid(), deadline)
        candidates = sorted(children - blocked)
        if not candidates:
            if not children:
                try:
                    waited, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    return {"reaped": reaped, "unresolved": unresolved}
                if waited:
                    reaped.append({"pid": waited, "status": status})
                    continue
            return {"reaped": reaped, "unresolved": unresolved}

        handles = []
        terminal = set()
        try:
            for pid in candidates:
                _remaining(deadline)
                try:
                    owned = acquire_direct_child(pid, deadline)
                    if owned is not None:
                        handles.append(owned)
                except TimeoutError:
                    raise
                except BaseException as error:
                    blocked.add(pid)
                    unresolved.append({"pid": pid, "reason":
                                       f"acquire {type(error).__name__}: {error}"})
                    errors.append({"phase": "acquire", "pid": pid,
                                   "error": f"{type(error).__name__}: {error}"})

            signal_retained(handles, signal.SIGKILL, errors)
            for owned in handles:
                _remaining(deadline)
                pid = owned["pid"]
                try:
                    if owned.get("signal_failed") and not select.select(
                            [owned["pidfd"]], [], [], 0)[0]:
                        raise RuntimeError(
                            f"adopted child {pid} signal authority failed")
                    if not select.select(
                            [owned["pidfd"]], [], [],
                            _remaining(deadline))[0]:
                        raise TimeoutError(
                            f"adopted child {pid} terminal deadline expired")
                    _remaining(deadline)
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    if waited != pid:
                        raise RuntimeError(f"adopted child {pid} was not reaped")
                    reaped.append({"pid": pid,
                                   "starttime": owned["starttime"],
                                   "status": status})
                    terminal.add(pid)
                except BaseException as error:
                    blocked.add(pid)
                    unresolved.append({"pid": pid,
                                       "starttime": owned.get("starttime"),
                                       "reason":
                                       f"terminal {type(error).__name__}: {error}"})
                    errors.append({"phase": "terminal", "pid": pid,
                                   "error": f"{type(error).__name__}: {error}"})
        except TimeoutError:
            recorded = {item.get("pid") for item in unresolved}
            for pid in candidates:
                if pid not in recorded:
                    unresolved.append(
                        {"pid": pid,
                         "reason": "cleanup deadline expired before terminal proof"})
            raise
        finally:
            for owned in handles:
                if owned["pid"] not in terminal:
                    # This is the sole action permitted after the common
                    # deadline: a nonblocking signal through already-held
                    # identity-safe custody. Do not discover or wait here.
                    signal_retained([owned], signal.SIGKILL, errors)
                    if not any(item.get("pid") == owned["pid"]
                               for item in unresolved):
                        unresolved.append({
                            "pid": owned["pid"],
                            "starttime": owned.get("starttime"),
                            "reason": "terminal proof unavailable at cleanup deadline",
                        })
                os.close(owned["pidfd"])


def cleanup(args, process, child_fd, child_birth, first_name,
            deadline, receipt):
    errors = receipt["cleanup_errors"]
    receipt["cleanup_started_mono_ns"] = time.monotonic_ns()
    receipt["cleanup_deadline_mono_ns"] = (
        receipt["cleanup_started_mono_ns"]
        + int(max(0, deadline - time.monotonic()) * 1_000_000_000))
    deadline_expired = False
    try:
        if process is not None and child_birth is not None:
            run_group_helper(args, process.pid, child_birth, first_name,
                             deadline, receipt, errors)
        if process is not None and process.poll() is None and child_fd is not None:
            signal_retained([{"pid": process.pid, "pidfd": child_fd}],
                            signal.SIGKILL, errors)
            try:
                process.wait(timeout=_remaining(deadline))
            except BaseException as error:
                errors.append({"phase": "command-terminal", "pid": process.pid,
                               "error": f"{type(error).__name__}: {error}"})
                receipt["unresolved"].append(
                    {"pid": process.pid, "starttime": child_birth,
                     "reason": "command terminal proof failed"})
        elif process is not None:
            try:
                process.wait(timeout=0)
            except BaseException as error:
                errors.append({"phase": "command-reap", "pid": process.pid,
                               "error": f"{type(error).__name__}: {error}"})
        if process is not None:
            receipt["command_exit"] = process.returncode
        settle_adopted(args, signal.SIGKILL, deadline, receipt)
    except BaseException as error:
        deadline_expired = isinstance(error, TimeoutError)
        if deadline_expired:
            receipt["cleanup_deadline_expired"] = True
        errors.append({"phase": "cleanup", "error":
                       f"{type(error).__name__}: {error}"})
        # Deadline expiry permits only nonblocking signals through handles
        # already retained by this frame.
        if process is not None and child_fd is not None and process.poll() is None:
            signal_retained([{"pid": process.pid, "pidfd": child_fd}],
                            signal.SIGKILL, errors)
            receipt["unresolved"].append(
                {"pid": process.pid, "starttime": child_birth,
                 "reason": "cleanup deadline expired"})
    remaining = set()
    if deadline_expired:
        receipt["unresolved"].append({
            "pid": None,
            "reason": "final child census skipped after cleanup deadline",
        })
    else:
        try:
            remaining = direct_children(os.getpid(), deadline)
        except BaseException as error:
            errors.append({"phase": "final-census",
                           "error": f"{type(error).__name__}: {error}"})
            receipt["unresolved"].append({
                "pid": None, "reason": "final child census unavailable"})
    for pid in sorted(remaining):
        if not any(item.get("pid") == pid for item in receipt["unresolved"]):
            receipt["unresolved"].append(
                {"pid": pid, "reason": "final direct child remains"})
    receipt["terminal_proof"] = (
        not deadline_expired and process is not None
        and process.poll() is not None
        and not receipt["unresolved"] and not remaining)
    receipt["cleanup_ok"] = receipt["terminal_proof"] and not errors
    receipt["settled"] = receipt["cleanup_ok"]
    receipt["cleanup_finished_mono_ns"] = time.monotonic_ns()


def shell_status(returncode):
    return 128 + -returncode if returncode < 0 else returncode


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--receipt-helper", required=True)
    parser.add_argument("--wrapper-identity", required=True)
    parser.add_argument("--receipt-owner-uid", type=numeric_id)
    parser.add_argument("--receipt-owner-gid", type=numeric_id)
    parser.add_argument("--root-group", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("command required after --")
    if (args.receipt_owner_uid is None) != (args.receipt_owner_gid is None):
        parser.error("receipt owner UID/GID must be supplied together")
    if args.root_group and args.receipt_owner_uid is None:
        parser.error("root supervisor requires receipt owner UID/GID")

    subreaper()
    wrapper = wait_wrapper_identity(
        args.wrapper_identity, time.monotonic() + WRAPPER_IDENTITY_SECONDS)
    cancelled = []
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda signum, frame: cancelled.append(signum))

    receipt = {
        "schema": SCHEMA,
        "outer_wrapper_pid": wrapper["pid"],
        "outer_wrapper_starttime": wrapper["starttime"],
        "wrapper_identity_file": args.wrapper_identity,
        "supervisor_pid": os.getpid(),
        "supervisor_starttime": starttime(os.getpid()),
        "root_group": args.root_group,
        "helper_attempts": [],
        "helper_failed": False,
        "cleanup_errors": [],
        "unresolved": [],
        "reaped": [],
        "terminal_proof": False,
        "cleanup_ok": False,
        "settled": False,
    }
    owner = (args.receipt_owner_uid, args.receipt_owner_gid)
    process = None
    child_fd = None
    child_birth = None
    gate_read, gate_write = os.pipe()
    primary_error = None
    first_name = "KILL"
    cleanup_deadline = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", GATED_EXEC, str(gate_read), *args.command],
            pass_fds=(gate_read,), preexec_fn=os.setsid,
        )
        os.close(gate_read)
        gate_read = -1
        child_birth = starttime(process.pid)
        child_fd = os.pidfd_open(process.pid, 0)
        receipt.update(command_pid=process.pid,
                       command_starttime=child_birth)
        atomic_json(args.receipt, receipt, *owner)
        os.write(gate_write, b"G")
        os.close(gate_write)
        gate_write = -1
        while not cancelled and not select.select([child_fd], [], [], 0.05)[0]:
            pass
        first_name = "TERM" if cancelled else "KILL"
    except BaseException as error:
        primary_error = f"{type(error).__name__}: {error}"
    finally:
        cleanup_deadline = (time.monotonic() + CLEANUP_SECONDS
                            if cleanup_deadline is None else cleanup_deadline)
        cleanup(args, process, child_fd, child_birth, first_name,
                cleanup_deadline, receipt)
        for fd in (gate_read, gate_write, child_fd):
            if fd is not None and fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    if primary_error:
        receipt["primary_error"] = primary_error
    if cancelled:
        receipt["cancel_signal"] = cancelled[0]
    try:
        atomic_json(args.receipt, receipt, *owner)
    except OSError as error:
        primary_error = primary_error or f"receipt publication failed: {error}"
    if primary_error or not receipt["cleanup_ok"]:
        if primary_error:
            print(f"supervisor: {primary_error}", file=sys.stderr)
        for error in receipt["cleanup_errors"]:
            print(f"supervisor cleanup: {error}", file=sys.stderr)
        return 1
    if cancelled:
        return 128 + cancelled[0]
    return shell_status(process.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
