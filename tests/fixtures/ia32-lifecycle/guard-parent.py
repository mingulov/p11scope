"""Own a guard child until the suite acknowledges its exact pidfd identity."""

import ctypes
import os
from pathlib import Path
import signal
import sys
import time


mode, guard, parent_record, self_record, target, program = sys.argv[1:]
raw = Path("/proc/self/stat").read_bytes().rsplit(b") ", 1)[1].split()
starttime = int(raw[19])
Path(parent_record).write_text(f"{os.getpid()} {starttime + (1 if mode == 'wrong' else 0)}\n")
os.chmod(parent_record, 0o600)
interrupted = 0


def record_signal(signum, _frame):
    global interrupted
    interrupted = signum


def wait_exact_child(pid, deadline, stop_on_interrupt=False):
    while time.monotonic() < deadline:
        if stop_on_interrupt and interrupted:
            raise InterruptedError
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    raise TimeoutError(f"child {pid} did not exit")


for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(handled_signal, record_signal)

gate_read, gate_write = os.pipe()
parent_pid = os.getpid()
pid = os.fork()
if pid == 0:
    os.close(gate_write)
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled_signal, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise SystemExit(121)
    if os.getppid() != parent_pid:
        raise SystemExit(122)
    signal.alarm(12)
    if os.read(gate_read, 1) != b"1":
        raise SystemExit(123)
    os.close(gate_read)
    if mode == "adopt":
        os.kill(os.getpid(), signal.SIGSTOP)
    elif mode == "adopt-refusal":
        if libc.prctl(1, 0, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            raise SystemExit(127)
        self_raw = Path("/proc/self/stat").read_bytes().rsplit(b") ", 1)[1].split()
        Path(parent_record + ".bootstrap-cleared").write_text(
            f"{os.getpid()} {int(self_raw[19])}\n"
        )
        while os.getppid() == parent_pid:
            time.sleep(0.01)
    os.execve(guard, [guard, parent_record, self_record, target, program], os.environ)

os.close(gate_read)
child_fd = None
child_generation = None
child_record = Path(parent_record + ".child")
status_record = Path(parent_record + ".child.status")


def publish_status(status):
    if child_generation is not None:
        status_record.write_text(
            f"{pid} {child_generation} {os.waitstatus_to_exitcode(status)}\n"
        )


def terminate_and_reap(exit_status):
    try:
        if child_fd is not None:
            signal.pidfd_send_signal(child_fd, signal.SIGKILL)
        else:
            # The unreaped direct-child relationship pins this numeric PID.
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        status = wait_exact_child(pid, time.monotonic() + 2)
    except (ChildProcessError, TimeoutError):
        raise SystemExit(126)
    publish_status(status)
    if child_fd is not None:
        os.close(child_fd)
    raise SystemExit(exit_status)


try:
    child_fd = os.pidfd_open(pid)
    child_raw = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
    child_generation = int(child_raw[19])
    child_record.write_text(f"{pid} {child_generation}\n")
except (OSError, ValueError):
    os.close(gate_write)
    terminate_and_reap(124)

acquired = Path(parent_record + ".child.acquired")
deadline = time.monotonic() + 5
while time.monotonic() < deadline and not acquired.exists() and interrupted == 0:
    time.sleep(0.01)
if interrupted:
    os.close(gate_write)
    terminate_and_reap(128 + interrupted)
if not acquired.exists():
    os.close(gate_write)
    terminate_and_reap(125)
os.write(gate_write, b"1")
os.close(gate_write)

if mode == "adopt-refusal":
    bootstrap_cleared = Path(parent_record + ".bootstrap-cleared")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not bootstrap_cleared.exists() and interrupted == 0:
        time.sleep(0.01)
    if interrupted or not bootstrap_cleared.exists():
        terminate_and_reap(128 + interrupted if interrupted else 124)
    os.close(child_fd)
    raise SystemExit(0)

if mode == "adopt":
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and interrupted == 0:
        child_raw = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        if int(child_raw[19]) != child_generation:
            terminate_and_reap(127)
        if child_raw[0] in (b"T", b"t"):
            break
        time.sleep(0.01)
    else:
        terminate_and_reap(128 + interrupted if interrupted else 124)
    release = Path(parent_record + ".release")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not release.exists() and interrupted == 0:
        time.sleep(0.01)
    if interrupted or not release.exists():
        terminate_and_reap(128 + interrupted if interrupted else 125)
    os.close(child_fd)
    raise SystemExit(0)

try:
    status = wait_exact_child(pid, time.monotonic() + 15, stop_on_interrupt=True)
except (InterruptedError, TimeoutError):
    terminate_and_reap(128 + interrupted if interrupted else 124)
publish_status(status)
os.close(child_fd)
raise SystemExit(os.waitstatus_to_exitcode(status))
