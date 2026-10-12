#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Own a birth-blocked raw child through two checked initial exec events.

Call before starting any Reader or other OS thread. The caller supplies the
original absolute monotonic deadline and independently held FilePin objects.
caller_argv is the real caller argv; this module prepends the pinned setarch
-R exactly once. The held-exec proof is a kernel/proc receipt, never a fixture
ledger image. Detach can release user code before the detach syscall returns.

The raw-fork child dispatches preloaded syscall tuples from Python. It does
not run atfork handlers, imports, Python I/O, subprocess machinery or user
callbacks. This is suitable only for the single-task ordinary Python driver;
it is not an async-signal-safe fork facility for arbitrary embedded runtimes.
"""

from contextlib import nullcontext
import ctypes
import errno
import gc
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import time


PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_SEIZE = 0x4206
PTRACE_EVENT_EXEC = 4
PTRACE_O_TRACEEXEC = 0x10
PTRACE_O_EXITKILL = 0x00100000
WAIT_WALL = 0x40000000
ADDR_NO_RANDOMIZE = 0x40000

# Linux x86-64 only. Resolve ctypes/libc and prepare every child buffer before
# raw fork; os.fork would invoke arbitrary registered Python atfork callbacks.
_LIBC = ctypes.CDLL(None, use_errno=True)
_SYSCALL = _LIBC.syscall
_SYSCALL.restype = ctypes.c_long
_ERRNO = ctypes.get_errno
_STAGES = ("close", "stdio", "parent-death signal", "parent identity", "session",
           "groups", "gid", "uid", "parent-death signal after credentials",
           "parent identity after credentials", "acknowledgement", "birth gate",
           "signal disposition", "signal mask", "setarch exec")


def _call(number, *args):
    return (ctypes.c_long(number), *(ctypes.c_long(value) if isinstance(value, int)
                                   else value for value in args))


def _raw_fork():
    result = _SYSCALL(*_call(57))
    if result < 0:
        raise OSError(_ERRNO(), "raw fork failed")
    return result


def _ptrace(request, pid, data=0):
    result = _SYSCALL(*_call(101, request, pid, 0, data))
    if result < 0:
        raise OSError(_ERRNO(), "owned child ptrace failed")


def _remaining(deadline_ns):
    remaining = (deadline_ns - time.monotonic_ns()) / 1e9
    if remaining <= 0:
        raise TimeoutError("original initial-exec deadline exhausted")
    return remaining


def _single_task():
    if len(os.listdir("/proc/self/task")) != 1:
        raise RuntimeError("initial exec requires exactly one OS task before raw fork")
    monitoring = getattr(sys, "monitoring", None)
    if (sys.gettrace() is not None or sys.getprofile() is not None
            or monitoring is not None and any(monitoring.get_tool(tool) is not None
                                              for tool in range(6))):
        raise RuntimeError("initial exec requires an uninstrumented Python driver")


def _identity(pid):
    proc = Path("/proc") / str(pid)
    text = (proc / "stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines()
                  if ":" in line)
    uids = tuple(map(int, status["Uid"].split()))
    gids = tuple(map(int, status["Gid"].split()))
    return dict(pid=pid, ppid=int(fields[1]), pgrp=int(fields[2]), session=int(fields[3]),
                start_time=int(fields[19]), uid=uids[0], gid=gids[0], uids=uids, gids=gids,
                groups=tuple(sorted(map(int, status["Groups"].split()))),
                pid_namespace=(proc / "ns/pid").stat().st_ino,
                time_namespace=(proc / "ns/time").stat().st_ino,
                mount_namespace=(proc / "ns/mnt").stat().st_ino)


def _file_identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _child_fail(plan, stage, error):
    plan["ack"][0], plan["ack"][1] = stage, error
    _SYSCALL(*plan["ack_write"])
    while True:
        _SYSCALL(*plan["exit"])  # never fall back into the parent on a denied exit


def _child(plan):
    # All syscall arguments, pointers, fd lists and bytes already exist. The
    # single-task guard excludes inherited locks owned by another OS thread.
    if _SYSCALL(*plan["pdeath"]) < 0:
        _child_fail(plan, 2, _ERRNO())
    if _SYSCALL(*plan["getppid"]) != plan["parent"]:
        _child_fail(plan, 3, errno.ESRCH)
    for call in plan["close"]:
        if _SYSCALL(*call) < 0:
            error = _ERRNO()
            if error not in (errno.EBADF, errno.EINTR):
                _child_fail(plan, 0, error)
    for stage, call in plan["setup"]:
        if _SYSCALL(*call) < 0:
            _child_fail(plan, stage, _ERRNO())
    for stage, call in plan["credentials"]:
        if _SYSCALL(*call) < 0:
            _child_fail(plan, stage, _ERRNO())
    if _SYSCALL(*plan["getppid"]) != plan["parent"]:
        _child_fail(plan, 9, errno.ESRCH)
    if _SYSCALL(*plan["ack_write"]) != 8:
        while True:
            _SYSCALL(*plan["exit"])
    if _SYSCALL(*plan["birth_read"]) != 1 or plan["birth"].value != b"B":
        _child_fail(plan, 11, errno.EPIPE)
    for call in plan["signals"]:
        if _SYSCALL(*call) < 0:
            _child_fail(plan, 12, _ERRNO())
    if _SYSCALL(*plan["mask"]) < 0:
        _child_fail(plan, 13, _ERRNO())
    _SYSCALL(*plan["exec"])
    _child_fail(plan, 14, _ERRNO())


class _Process:
    """The narrow Popen-shaped adapter; ptrace stops are never exit codes."""
    def __init__(self, owner):
        self.owner = owner
        self.pid = owner.pid
        self.returncode = None
        self.stdin = self.stdout = self.stderr = None

    def _ordinary(self):
        if not self.owner.detached and not self.owner.reaped:
            raise RuntimeError("ordinary poll/wait is forbidden before detach or terminal reap")

    def poll(self):
        self._ordinary()
        if not self.owner.reaped:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.owner._terminal(status)
        return self.returncode

    def wait(self, timeout=None):
        self._ordinary()
        started = time.monotonic()
        while self.poll() is None:
            remaining = _remaining(self.owner.deadline_ns)
            if timeout is not None:
                remaining = min(remaining, timeout - (time.monotonic() - started))
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("owned initial-exec caller", timeout)
            select.select([self.owner.pidfd], [], [], min(remaining, 0.01))
        return self.returncode

    def send_signal(self, signum):
        self.owner.send(signum)


class InitialExecProcess:
    """Original raw PID/pidfd, credentials and streams, retained until reap."""
    def __init__(self, deadline_ns, caller_pin, setarch_pin, cleanup_section):
        self.deadline_ns = deadline_ns
        self.caller_pin, self.setarch_pin = caller_pin, setarch_pin
        self.cleanup_section = cleanup_section
        self.pid = self.pidfd = self.popen = self.identity = None
        self.birth_fd = self.ack_fd = None
        self.fds = set()
        self.traced = self.detached = self.reaped = self.held = False
        self.held_exec = None
        self.returncode = None

    def _close_fd(self, fd):
        if fd in self.fds:
            # Linux releases the descriptor number before reporting a late
            # close error. Retrying that number could close a reused fd.
            self.fds.remove(fd)
            os.close(fd)

    def verify(self):
        if self.identity is None or _identity(self.pid) != self.identity:
            raise ValueError("not the original owned child/birth/credentials/session/namespace")

    def send(self, signum):
        if not self.detached and signum != signal.SIGKILL:
            raise RuntimeError("only pidfd SIGKILL is permitted before detach")
        self.verify()
        signal.pidfd_send_signal(self.pidfd, signum)

    def wait_exit(self, seconds):
        remaining = min(seconds, _remaining(self.deadline_ns))
        return bool(select.select([self.pidfd], [], [], remaining)[0])

    def _terminal(self, status):
        if not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            raise RuntimeError("owned child wait status is not terminal")
        self.reaped, self.traced = True, False
        self.returncode = os.waitstatus_to_exitcode(status)
        if self.popen is not None:
            self.popen.returncode = self.returncode

    def kill_and_reap(self):
        """Mandatory terminal cleanup; never allocate a replacement deadline.

        SIGKILL and the terminal raw wait are also required after the setup
        deadline expires. Kernel completion of this reap cannot be timed out
        safely: until it completes we still own the original child and tracer.
        """
        if self.pid is None or self.reaped:
            return
        with self.cleanup_section():
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
            try:
                try:
                    if self.pidfd is not None:
                        signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    else:
                        # pidfd acquisition itself failed. This direct child
                        # has never been reaped, so its PID cannot be recycled.
                        os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                while not self.reaped:
                    pid, status = os.waitpid(self.pid, WAIT_WALL)
                    if pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                        self._terminal(status)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def close(self):
        with self.cleanup_section():
            errors = []
            try:
                self.kill_and_reap()
            except BaseException as error:
                errors.append(error)
            if self.popen is not None:
                for stream in (self.popen.stdin, self.popen.stdout, self.popen.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except (OSError, ValueError) as error:
                            errors.append(error)
            for fd in tuple(self.fds):
                try:
                    self._close_fd(fd)
                except OSError as error:
                    errors.append(error)
            if self.pidfd is not None and self.reaped:
                fd, self.pidfd = self.pidfd, None
                try:
                    os.close(fd)
                except OSError as error:
                    errors.append(error)
            if errors:
                for error in errors[1:]:
                    errors[0].add_note("another owned cleanup failure: " + repr(error))
                raise errors[0]

    def _acknowledgement(self):
        data = bytearray()
        while len(data) < 8:
            remaining = _remaining(self.deadline_ns)
            if select.select([self.ack_fd], [], [], remaining)[0]:
                chunk = os.read(self.ack_fd, 8 - len(data))
                if not chunk:
                    raise EOFError("owned child closed its credential acknowledgement")
                data.extend(chunk)
        stage, error = struct.unpack("=ii", data)
        if error:
            name = _STAGES[stage] if 0 <= stage < len(_STAGES) else "unknown stage"
            raise OSError(error, "owned initial-exec child failed: " + name)
        if stage != 10:
            raise ValueError("invalid owned credential acknowledgement")
        _remaining(self.deadline_ns)

    def _exec_event(self, pin):
        while True:
            remaining = _remaining(self.deadline_ns)
            pid, status = os.waitpid(self.pid, os.WNOHANG | WAIT_WALL)
            if pid:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self._terminal(status)
                    raise EOFError("owned child exited before its checked exec event")
                if not (os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP
                        and status >> 16 == PTRACE_EVENT_EXEC):
                    raise ValueError("owned child stop was not PTRACE_EVENT_EXEC")
                break
            select.select([], [], [], min(remaining, 0.002))
        self.verify()
        pin.verify()
        path = Path("/proc") / str(self.pid) / "exe"
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            actual, expected = _file_identity(fd), _file_identity(pin.fd)
            if actual != expected or os.readlink(path) != str(pin.path):
                raise ValueError("actual stopped executable differs from independently held pin")
        finally:
            os.close(fd)
        self.verify()
        _remaining(self.deadline_ns)
        dev, ino, size, mtime_ns, ctime_ns = actual
        return dict(pid=self.pid, start_time=self.identity["start_time"], path=str(pin.path),
                    dev=dev, ino=ino, size=size, mtime_ns=mtime_ns, ctime_ns=ctime_ns,
                    pid_namespace=self.identity["pid_namespace"],
                    time_namespace=self.identity["time_namespace"],
                    mount_namespace=self.identity["mount_namespace"])

    def hold_caller_exec(self):
        try:
            _remaining(self.deadline_ns)
            if self.traced or self.detached or self.reaped:
                raise RuntimeError("initial exec barrier can be acquired only once")
            self.verify()
            _ptrace(PTRACE_SEIZE, self.pid, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)
            self.traced = True
            _remaining(self.deadline_ns)
            if os.write(self.birth_fd, b"B") != 1:
                raise EOFError("owned child birth gate was not released")
            self._close_fd(self.birth_fd)
            self.birth_fd = None
            self._exec_event(self.setarch_pin)
            _remaining(self.deadline_ns)
            _ptrace(PTRACE_CONT, self.pid)
            proof = self._exec_event(self.caller_pin)
            personality = int((Path("/proc") / str(self.pid) / "personality").read_text(), 16)
            if not personality & ADDR_NO_RANDOMIZE:
                raise ValueError("actual caller lacks ADDR_NO_RANDOMIZE")
            self._close_fd(self.ack_fd)
            self.ack_fd = None
            _remaining(self.deadline_ns)
            self.held = True
            self.held_exec = dict(proof, personality=personality, exec_events=2)
            return self.held_exec
        except BaseException:
            self.close()
            raise

    def resume_detach(self):
        try:
            _remaining(self.deadline_ns)
            if not self.held or not self.traced or self.detached or self.reaped:
                raise RuntimeError("caller must be held at its checked initial exec event")
            self.verify()
            _remaining(self.deadline_ns)
            entered = time.monotonic_ns()
            _ptrace(PTRACE_DETACH, self.pid)
            returned = time.monotonic_ns()
            self.detached, self.traced, self.held = True, False, False
            _remaining(self.deadline_ns)
            return dict(detach_entry_ns=entered, detach_return_ns=returned)
        except BaseException:
            self.close()
            raise


def spawn_initial_exec(owners, caller_argv, *, caller_pin, setarch_pin, uid, gid,
                       env, deadline_ns, cleanup_section=nullcontext):
    """Production factory: requested uid/gid and empty supplementary groups."""
    return _spawn_initial_exec(owners, caller_argv, caller_pin=caller_pin,
                              setarch_pin=setarch_pin, uid=uid, gid=gid, env=env,
                              deadline_ns=deadline_ns, cleanup_section=cleanup_section,
                              supplementary_groups=())


def _spawn_initial_exec(owners, caller_argv, *, caller_pin, setarch_pin, uid, gid,
                        env, deadline_ns, supplementary_groups, cleanup_section=nullcontext):
    """Explicit lower-level credential seam for ordinary-uid protocol tests.

    This does not fall back from production credential failure. A current
    nonempty group tuple is suitable only for these ordinary-uid controls;
    it is never the H6 production factory's credential policy.
    """
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        raise RuntimeError("initial exec primitive requires Linux x86-64")
    if not isinstance(deadline_ns, int) or deadline_ns <= 0:
        raise ValueError("one absolute monotonic deadline is required")
    if not caller_argv or caller_argv[0] != str(caller_pin.path):
        raise ValueError("caller argv must begin with the independently pinned absolute caller")
    if not all(isinstance(value, int) and 0 <= value < 2 ** 32 - 1
               for value in (uid, gid, *supplementary_groups)):
        raise ValueError("invalid requested credentials")
    _remaining(deadline_ns)
    caller_pin.verify()
    setarch_pin.verify()
    argv = [os.fsencode(value) for value in (str(setarch_pin.path), "-R", *caller_argv)]
    environment = [os.fsencode(key) + b"=" + os.fsencode(value) for key, value in env.items()]
    if any(b"\0" in value for value in argv + environment):
        raise ValueError("exec argv/environment contains a NUL byte")
    argv_c = (ctypes.c_char_p * (len(argv) + 1))(*argv, None)
    env_c = (ctypes.c_char_p * (len(environment) + 1))(*environment, None)
    owner = InitialExecProcess(deadline_ns, caller_pin, setarch_pin, cleanup_section)
    original_mask = None
    gc_enabled = False
    try:
        with cleanup_section():
            _remaining(deadline_ns)
            original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signal.valid_signals())
            pairs = []
            for _ in range(5):
                pair = os.pipe2(os.O_CLOEXEC)
                owner.fds.update(pair)
                if min(pair) < 3:
                    raise ValueError("initial-exec driver requires open standard descriptors")
                pairs.append(pair)
            (stdin_r, stdin_w), (stdout_r, stdout_w), (stderr_r, stderr_w), birth, ack = pairs
            owner.birth_fd, owner.ack_fd = birth[1], ack[0]
            child_fds = {stdin_r, stdout_w, stderr_w, birth[0], ack[1]}
            ack_c = (ctypes.c_int * 2)(10, 0)
            byte_c = ctypes.create_string_buffer(1)
            groups = tuple(sorted(supplementary_groups))
            groups_c = (ctypes.c_uint * len(groups))(*groups)
            action = (ctypes.c_ulong * 4)(0, 0, 0, 0)
            mask = ctypes.c_ulong(sum(1 << (value - 1) for value in original_mask))
            setup = [(1, _call(33, stdin_r, 0)), (1, _call(33, stdout_w, 1)),
                     (1, _call(33, stderr_w, 2)), (4, _call(112))]
            credentials = []
            if os.geteuid() == 0 or groups != tuple(sorted(os.getgroups())):
                credentials.append((5, _call(116, len(groups), ctypes.cast(groups_c, ctypes.c_void_p))))
            credentials.extend(((6, _call(119, gid, gid, gid)),
                                (7, _call(117, uid, uid, uid)),
                                (8, _call(157, 1, signal.SIGKILL))))
            plan = dict(parent=os.getpid(),
                        close=[_call(3, int(fd)) for fd in os.listdir("/proc/self/fd")
                               if int(fd) >= 3 and int(fd) not in child_fds],
                        pdeath=_call(157, 1, signal.SIGKILL),
                        setup=setup, credentials=credentials, ack=ack_c,
                        ack_write=_call(1, ack[1], ctypes.cast(ack_c, ctypes.c_void_p), 8),
                        birth=byte_c,
                        birth_read=_call(0, birth[0], ctypes.cast(byte_c, ctypes.c_void_p), 1),
                        getppid=_call(110), exit=_call(231, 125),
                        signals=[_call(13, int(sig), ctypes.cast(action, ctypes.c_void_p), 0, 8)
                                 for sig in signal.valid_signals()
                                 if int(sig) not in (signal.SIGKILL, signal.SIGSTOP)],
                        mask=_call(14, signal.SIG_SETMASK, ctypes.pointer(mask), 0, 8),
                        exec=_call(59, argv_c[0], ctypes.cast(argv_c, ctypes.c_void_p),
                                   ctypes.cast(env_c, ctypes.c_void_p)))
            _remaining(deadline_ns)
            gc_enabled = gc.isenabled()
            gc.disable()  # child allocations must not invoke cyclic finalizers
            _single_task()
            pid = _raw_fork()
            if pid == 0:
                try:
                    _child(plan)
                except BaseException:
                    pass
                while True:
                    _SYSCALL(*plan["exit"])
            owner.pid = pid
            owners.append(owner)  # raw PID custody before pidfd/ACK/identity can fail
            owner.popen = _Process(owner)
            owner.pidfd = os.pidfd_open(pid)
            for fd in child_fds:
                owner._close_fd(fd)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            original_mask = None
            owner._acknowledgement()
            actual, parent = _identity(pid), _identity(os.getpid())
            if (actual["ppid"] != os.getpid() or actual["uids"] != (uid,) * 4
                    or actual["gids"] != (gid,) * 4 or actual["groups"] != groups
                    or actual["pgrp"] != pid or actual["session"] != pid
                    or any(actual[field] != parent[field] for field in
                           ("pid_namespace", "time_namespace", "mount_namespace"))
                    or actual["start_time"] <= 0):
                raise ValueError("owned birth acknowledgement lacks requested identity/credentials")
            owner.identity = actual
            owner.verify()
            for attribute, fd, mode in (("stdin", stdin_w, "w"), ("stdout", stdout_r, "r"),
                                        ("stderr", stderr_r, "r")):
                stream = os.fdopen(fd, mode, encoding="utf-8")
                owner.fds.remove(fd)
                setattr(owner.popen, attribute, stream)
            _remaining(deadline_ns)
            return owner
    except BaseException:
        owner.close()
        raise
    finally:
        try:
            if original_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        finally:
            if gc_enabled:
                gc.enable()
