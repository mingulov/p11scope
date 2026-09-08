#!/usr/bin/env python3
"""One-shot Linux supervisor for trusted commands that never escape their group.

Run as a dedicated process, not inside a process that owns other children.
The original fork child becomes a session/group leader before exec. A gate
prevents workload execution until subreaper, original pidfd and group setup
are complete. WNOWAIT retains that leader, including its zombie, through the
last group KILL. Afterward all signal authority is retired before any reap.

ECHILD after exact waitpid results proves settlement of this supervisor's
original/adopted children. Any adoption is unexpected and nonpass. A final
KILL attempt against a zombie-only group does not itself mean rescue. This
is not containment for untrusted/escaping descendants, SIGKILL of this
supervisor, or uninterruptible kernel work. Exhausted cleanup is UNKNOWN.
Python 3.10 standard library; Linux pidfds and prctl are required.
"""

import argparse
import base64
import ctypes
import json
import math
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import time


CANCEL_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
OUTPUT_LIMIT = 8 * 1024 * 1024


def positive_seconds(value):
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("deadline must be finite and positive")
    return value


def wait_record(pid, status):
    return {"pid": pid, "raw_status": status,
            "exit_code": os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
            "signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
            "core_dumped": os.WCOREDUMP(status)}


def supervise(args):
    started = time.monotonic()
    receipt = dict(schema="owned-process-group/1", argv=args.command, cwd=args.cwd,
                   status="UNKNOWN", reason="setup_error", original=None, adopted=[],
                   cancellation_signal=None, group_signals=[], errors=[], settled=False,
                   rescue=False, workload_released=False,
                   timeout_seconds=args.timeout, term_grace_seconds=args.term_grace,
                   reap_timeout_seconds=args.reap_timeout)
    canceled = []

    def cancel(signum, unused_frame):
        if not canceled:
            canceled.append(signum)

    # A dedicated executable owns this process-wide state for its lifetime.
    for signum in CANCEL_SIGNALS:
        signal.signal(signum, cancel)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    pid = None
    pidfd = None
    group_ready = False
    fds = []
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
                raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
            observed = ctypes.c_int()
            if libc.prctl(37, ctypes.byref(observed), 0, 0, 0) != 0 or observed.value != 1:
                raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER")
            # Refuse an unavailable API before forking. The real child pidfd
            # is opened once, immediately after fork while exec is gated.
            if not hasattr(os, "pidfd_open"):
                raise RuntimeError("os.pidfd_open unavailable")
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            fds.extend((gate_read, gate_write))
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            fds.extend((ready_read, ready_write))
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(gate_write)
                    os.close(ready_read)
                    for signum in CANCEL_SIGNALS:
                        signal.signal(signum, signal.SIG_DFL)
                    os.setsid()
                    os.dup2(stdout.fileno(), 1)
                    os.dup2(stderr.fileno(), 2)
                    with open(os.devnull, "rb") as stdin:
                        os.dup2(stdin.fileno(), 0)
                    os.write(ready_write, b"R")
                    os.close(ready_write)
                    if os.read(gate_read, 1) != b"G":
                        os._exit(125)
                    os.close(gate_read)
                    os.chdir(args.cwd)
                    os.execvp(args.command[0], args.command)
                except BaseException as error:
                    try:
                        os.write(2, (type(error).__name__ + ": " + str(error) + "\n").encode())
                    except BaseException:
                        pass  # Diagnostics must never enter parent cleanup.
                finally:
                    os._exit(127)
            os.close(gate_read)
            fds.remove(gate_read)
            os.close(ready_write)
            fds.remove(ready_write)
            pidfd = os.pidfd_open(pid)
            operation_deadline = started + args.timeout
            while not canceled:
                remaining = operation_deadline - time.monotonic()
                if remaining <= 0:
                    receipt["reason"] = "timeout"
                    break
                readable = select.select([ready_read, pidfd], [], [], min(remaining, 0.02))[0]
                if time.monotonic() >= operation_deadline:
                    receipt["reason"] = "timeout"
                    break
                if ready_read in readable:
                    if os.read(ready_read, 1) != b"R":
                        raise RuntimeError("child session setup failed before exec")
                    group_ready = True
                    if canceled:
                        break
                    if time.monotonic() >= operation_deadline:
                        receipt["reason"] = "timeout"
                        break
                    os.write(gate_write, b"G")
                    receipt["workload_released"] = True
                    receipt["reason"] = "exit"
                    break
                if pidfd in readable:
                    raise RuntimeError("child exited before session readiness")
            os.close(gate_write)
            fds.remove(gate_write)
            if receipt["workload_released"]:
                while not canceled:
                    if time.monotonic() >= operation_deadline:
                        receipt["reason"] = "timeout"
                        break
                    # Observation only: this must never consume leader status.
                    status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    remaining = operation_deadline - time.monotonic()
                    if remaining <= 0:
                        receipt["reason"] = "timeout"
                        break
                    if status is not None:
                        break
                    select.select([pidfd], [], [], min(remaining, 0.02))
            if canceled:
                receipt["reason"] = "cancellation"
        except Exception as error:
            receipt["errors"].append(type(error).__name__ + ": " + str(error))
        finally:
            if pid is not None and pid > 0:
                # No wait that consumes status has happened. pid is still our
                # original child and anchors its group number, even if dead.
                def group_signal(signum):
                    event = {"signal": signum, "leader_unreaped": True}
                    try:
                        os.killpg(pid, signum)
                        event["result"] = "sent"
                    except ProcessLookupError:
                        event["result"] = "absent"
                    except OSError as error:
                        event["result"] = "error"
                        receipt["errors"].append(str(error))
                    receipt["group_signals"].append(event)

                if group_ready:
                    if receipt["reason"] != "exit" or receipt["errors"]:
                        group_signal(signal.SIGTERM)
                        term_deadline = time.monotonic() + args.term_grace
                        while time.monotonic() < term_deadline:
                            time.sleep(min(0.02, max(0, term_deadline - time.monotonic())))
                    # Also required on normal exit: kill any orphan left by
                    # the exited leader before relinquishing group authority.
                    group_signal(signal.SIGKILL)
                else:
                    # Exec was never released; this child cannot have created
                    # workload descendants. Original unreaped-child authority
                    # is sufficient even if pidfd/session setup failed.
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        receipt["errors"].append(str(error))

                # SIGNAL AUTHORITY ENDS HERE. No signal or pidfd open occurs
                # while consuming statuses, or after the leader is reaped.
                reap_deadline = time.monotonic() + args.reap_timeout
                while True:
                    if time.monotonic() >= reap_deadline:
                        receipt["errors"].append("cleanup deadline expired before ECHILD")
                        break
                    try:
                        child, status = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        receipt["settled"] = receipt["original"] is not None
                        break
                    except OSError as error:
                        receipt["errors"].append(str(error))
                        break
                    if child:
                        record = wait_record(child, status)
                        if child == pid:
                            receipt["original"] = record
                        else:
                            receipt["adopted"].append(record)
                    else:
                        time.sleep(0.01)
            else:
                receipt["settled"] = True  # No workload child was created.
            for fd in fds:
                os.close(fd)
            if pidfd is not None:
                os.close(pidfd)

        for name, stream in (("stdout", stdout), ("stderr", stderr)):
            stream.seek(0)
            raw = stream.read(OUTPUT_LIMIT + 1)
            receipt[name + "_truncated"] = len(raw) > OUTPUT_LIMIT
            if receipt[name + "_truncated"]:
                receipt["errors"].append(name + " exceeded receipt output limit")
                raw = raw[:OUTPUT_LIMIT]
            receipt[name] = raw.decode("utf-8", errors="replace")
            receipt[name + "_base64"] = base64.b64encode(raw).decode("ascii")
    if canceled:
        receipt["cancellation_signal"] = canceled[0]
        receipt["reason"] = "cancellation"
    receipt["rescue"] = bool(receipt["adopted"] or receipt["reason"] != "exit"
                             or (receipt["errors"] and pid is not None))
    if receipt["settled"]:
        clean = (receipt["reason"] == "exit" and not receipt["errors"]
                 and not receipt["adopted"] and receipt["workload_released"]
                 and receipt["original"] is not None
                 and receipt["original"]["exit_code"] == 0)
        receipt["status"] = "PASS" if clean else "NONPASS"
    receipt["elapsed_seconds"] = time.monotonic() - started
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout", required=True, type=positive_seconds)
    parser.add_argument("--term-grace", default=1.0, type=positive_seconds)
    parser.add_argument("--reap-timeout", default=5.0, type=positive_seconds)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a direct argv command is required after --")
    args.cwd = os.path.abspath(args.cwd)
    # Fail before any workload if the receipt cannot be created. Exclusive
    # creation preserves previous evidence rather than silently overwriting it.
    with args.receipt.open("x", encoding="utf-8") as output:
        receipt = supervise(args)
        json.dump(receipt, output, indent=2)
        output.write("\n")
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
