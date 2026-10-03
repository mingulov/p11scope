# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged lane-13 body; explicit original-handle handoff before holding."""

import argparse
import array
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time

# The harness passes its resolved scale. SLACK waits (a peer message, a
# readiness file, a KILLed child's exit) and the body's hold, which must
# outlast them, scale together; the 200 ms ready-timeout fault is SEMANTIC.
TIME_SCALE = float(os.environ.get("P11SCOPE_TEST_TIME_SCALE", "1"))


def slack(seconds):
    return seconds * TIME_SCALE


def parent_death_signal(value):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG")


def body(channel, parent, ready, ignore_term, fault):
    # Prearm has no hold, ignored signal, or fork. If the parent dies before
    # prctl, the subsequent parent comparison exits instead of entering hold.
    parent_death_signal(signal.SIGKILL)
    if os.getppid() != parent:
        return
    os.setsid()
    channel.settimeout(slack(5))
    if channel.recv(16) != b"owned":
        raise RuntimeError("body lacks transferred-handle owner")
    # The test now owns the exact original handle even on abnormal outer exit.
    parent_death_signal(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN if ignore_term else signal.SIG_DFL)
    if fault != "ready-timeout":
        ready.write_text("ready\n")
    time.sleep(slack(20))


def run_outer(args):
    def interrupted(signum, frame):
        raise RuntimeError(f"controlled outer signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with socket.socket(fileno=args.control_fd) as control:
        control.settimeout(slack(5))
        if control.recv(16) != b"start":
            raise RuntimeError("outer lacks original launch owner")
        args.evidence.mkdir(mode=0o700)
        ready = args.evidence / ".controlled-body-ready"
        parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = None
        descriptor = None
        detached = False
        try:
            parent = os.getpid()
            pid = os.fork()
            if pid == 0:
                parent_channel.close()
                control.close()
                status = 1
                try:
                    # Do not retain the outer's captured communication pipes.
                    null = os.open(os.devnull, os.O_RDWR)
                    try:
                        for target in (0, 1, 2):
                            os.dup2(null, target)
                    finally:
                        os.close(null)
                    body(child_channel, parent, ready, args.ignore_term, args.fault)
                    status = 0
                finally:
                    os._exit(status)
            child_channel.close()
            # pid is our unreaped direct child; it cannot be reused here.
            descriptor = os.pidfd_open(pid)
            control.sendmsg([str(pid).encode()], [
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))
            ])
            if control.recv(16) != b"owned":
                raise RuntimeError("test did not accept original child handle")
            parent_channel.sendall(b"owned")
            if args.fault == "before-ready":
                raise RuntimeError("controlled failure before readiness wait")
            deadline = time.monotonic() + (0.2 if args.fault == "ready-timeout" else slack(5))
            while not ready.exists() and time.monotonic() < deadline:
                if select.select([descriptor], [], [], 0)[0]:
                    raise RuntimeError("controlled body exited before readiness")
                time.sleep(0.01)
            if not ready.exists():
                raise RuntimeError("controlled body readiness timeout")
            if args.fault == "stat":
                raise ValueError("controlled body stat failure")
            raw = Path(f"/proc/{pid}/stat").read_bytes()
            _, separator, tail = raw.rpartition(b") ")
            fields = tail.split()
            if not separator or len(fields) < 20:
                raise ValueError("malformed controlled body stat")
            record = {
                "pid": pid, "starttime": int(fields[19]),
                "pgid": int(fields[2]), "sid": int(fields[3]),
                "argv": [sys.executable, "-I", *sys.argv],
            }
            if args.fault == "publication":
                raise OSError("controlled body publication failure")
            pidfile = args.evidence / ".lane13-body.pid"
            pidfile.write_text(json.dumps(record, separators=(",", ":")))
            pidfile.chmod(0o600)
            args.ready.write_text("ready\n")
            retained = False
            while not select.select([descriptor], [], [], 0)[0]:
                if select.select([control], [], [], 0.01)[0]:
                    if control.recv(16) != b"retained":
                        raise RuntimeError("controlled owner disconnected before release")
                    retained = True
                    control.sendall(b"retained")
                if args.release.exists():
                    if not retained:
                        raise RuntimeError("live body release lacks retained-handle acceptance")
                    detached = True
                    break
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            parent_channel.close()
            child_channel.close()
            try:
                if pid not in (None, 0) and not detached:
                    # Never reap before this final ownership action. Even an
                    # exited child remains reserved to this parent until waitpid.
                    os.kill(pid, signal.SIGKILL)
                    deadline = time.monotonic() + slack(2)
                    while os.waitpid(pid, os.WNOHANG)[0] == 0:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("owned child did not settle")
                        time.sleep(0.01)
                    print(f"controlled child settled {pid}", flush=True)
            finally:
                if descriptor is not None:
                    os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["outer"])
    parser.add_argument("--control-fd", type=int, required=True)
    for name in ("evidence", "gate", "ready", "release", "stdout-log", "stderr-log"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--ignore-term", action="store_true")
    parser.add_argument("--fault", choices=["none", "before-ready", "ready-timeout", "stat", "publication"], default="none")
    args = parser.parse_args()
    run_outer(args)


if __name__ == "__main__":
    main()
