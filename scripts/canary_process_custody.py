# SPDX-License-Identifier: GPL-3.0-or-later
"""Linux custody for a dedicated, single-threaded canary coordinator.

The caller owns signal/wait policy throughout the scope and must survive cleanup.
Other asynchronous Python handlers must not raise or perform competing waits.
Fixtures must not exec, independently stop/continue, or mutate their expected
thread/child population during acquisition. A pidfd does not enforce these
conditions or protect cleanup against coordinator SIGKILL. Borrowed groups keep
their external ordinary waiter. Direct children and explicitly validated
observer handoffs are reaped here; unexpected adopted orphans fail cleanup.
All deadlines are absolute finite time.monotonic() values.
"""
import contextlib
import ctypes
import math
import os
import select
import signal
import subprocess
import threading
import time


class CustodyError(RuntimeError):
    pass


class DeadlineExpired(CustodyError):
    """A finite custody deadline elapsed; safe to classify without its text."""


class Cancelled(CustodyError):
    pass


class CleanupError(CustodyError):
    """All original failures remain available, including their own chains."""
    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__('; '.join(f'{type(e).__name__}: {e}' for e in errors))


def _raise_errors(errors):
    if errors:
        chain = errors[0]
        for error in errors[1:]:
            # Preserve an existing explicit cause chain instead of replacing it.
            tail, seen = error, set()
            while tail.__cause__ is not None and id(tail) not in seen:
                seen.add(id(tail))
                tail = tail.__cause__
            if tail is not chain and id(chain) not in seen:
                tail.__cause__ = chain
            chain = error
        raise CleanupError(errors) from chain


def _remaining(deadline):
    if not math.isfinite(deadline):
        raise CustodyError('deadline must be finite')
    value = deadline - time.monotonic()
    if value <= 0:
        raise DeadlineExpired('custody deadline expired')
    return value


def _read(path, limit, deadline):
    _remaining(deadline)
    with open(path, 'rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CustodyError('proc record exceeds bound')
    return data


def _stat(pid, deadline, tid=None):
    target = pid if tid is None else tid
    path = f'/proc/{pid}/stat' if tid is None else f'/proc/{pid}/task/{tid}/stat'
    raw = _read(path, 8192, deadline)
    try:
        prefix, tail = raw.rsplit(b') ', 1)
        if int(prefix.split(b' ', 1)[0]) != target:
            raise ValueError('pid mismatch')
        fields = tail.split()
        record = (int(fields[19]), fields[0].decode('ascii'), int(fields[1]))
        if record[0] <= 0:
            raise ValueError('invalid generation')
        return record
    except (ValueError, IndexError, UnicodeError) as error:
        raise CustodyError('invalid proc identity') from error


def _tasks(pid, deadline):
    _remaining(deadline)
    result = []
    with os.scandir(f'/proc/{pid}/task') as entries:
        for entry in entries:
            _remaining(deadline)
            if not entry.name.isdecimal() or len(result) == 4096:
                raise CustodyError('invalid or oversized task roster')
            result.append(int(entry.name))
    if not result:
        raise CustodyError('empty task roster')
    return sorted(result)


def _children(pid, tids, deadline):
    result = set()
    for tid in tids:
        raw = _read(f'/proc/{pid}/task/{tid}/children', 65536, deadline)
        for token in raw.split():
            if not token.isdigit() or int(token) <= 0 or int(token) in result:
                raise CustodyError('invalid child census')
            result.add(int(token))
            if len(result) > 4096:
                raise CustodyError('oversized child census')
    return sorted(result)


def _ready(fd):
    return bool(select.select([fd], [], [], 0)[0])


def read_generation(pid, deadline, tid=None):
    """Public seam for one process/thread generation: /proc stat field 22.

    The same bounded decoder Group identity uses, so a caller outside this
    module never needs its privates. Raises CustodyError for a nonfinite or
    expired deadline, an oversized record or an identity that does not decode,
    and propagates the OSError of an unreadable /proc path unchanged.
    """
    return _stat(pid, deadline, tid)[0]


def check_owner_policy():
    """Validate original owner policy without mutation; return its signal mask.

    A coordinator installing encompassing nonraising handlers must call this
    before replacing its original policy. Native policy must remain stable for
    the complete scope. The no-existing-children check belongs to Custody entry.
    """
    if threading.current_thread() is not threading.main_thread():
        raise CustodyError('custody requires the Python main thread')
    if len(_tasks(os.getpid(), time.monotonic() + 1)) != 1:
        raise CustodyError('custody requires one actual owner thread')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise CustodyError('custody requires default SIGCHLD retention')
    for number in (signal.SIGINT, signal.SIGTERM):
        if signal.getsignal(number) == signal.SIG_IGN:
            raise CustodyError('custody requires nonignored INT and TERM')
    # Check actual native policy too: getsignal only describes Python's saved
    # disposition. Keep the same Linux libc decoder for all three signals.
    class Action(ctypes.Structure):
        _fields_ = [('handler', ctypes.c_void_p), ('mask', ctypes.c_ubyte * 128),
                    ('flags', ctypes.c_int), ('restorer', ctypes.c_void_p)]
    action = Action()
    libc = ctypes.CDLL(None, use_errno=True)
    for number in (signal.SIGCHLD, signal.SIGINT, signal.SIGTERM):
        if libc.sigaction(number, None, ctypes.byref(action)) != 0:
            raise OSError(ctypes.get_errno(), 'read native signal policy')
        if number == signal.SIGCHLD:
            if action.handler or action.flags & 2:
                raise CustodyError('custody requires native default SIGCHLD retention')
        elif action.handler == int(signal.SIG_IGN):
            raise CustodyError('custody requires native nonignored INT and TERM')
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    if mask.intersection((signal.SIGINT, signal.SIGTERM)):
        raise CustodyError('incoming mask blocks INT or TERM')
    return mask


def _subreaper(value=None):
    libc = ctypes.CDLL(None, use_errno=True)
    if value is None:
        result = ctypes.c_int()
        status = libc.prctl(37, ctypes.byref(result), 0, 0, 0)
    else:
        status = libc.prctl(36, int(value), 0, 0, 0)
    if status != 0:
        raise OSError(ctypes.get_errno(), 'subreaper policy')
    return result.value if value is None else None


class Group:
    """Retained leader identity; successful STOP creates an owed same-fd CONT."""
    def __init__(self, scope, pid, generation, role, wait_owner, origin):
        self.scope, self.pid, self.generation = scope, pid, generation
        self.role, self.wait_owner, self.origin = role, wait_owner, origin
        self.fd = None
        self.closed = False
        self.owed_cont = False
        self.stopped_members = None
        self.allowed_children = None
        self.process = None
        self.observer_parent = None

    def _live(self):
        if self.closed or self.fd is None or _ready(self.fd):
            raise CustodyError(f'{self.role} retained process has exited or closed')

    def check_alive(self, deadline):
        """Check retained leader identity while startup may create threads.

        This makes no claim about a stable task or child population. Callers
        must still use snapshot/children for acquisition and STOP/CONT.
        """
        self._live()
        generation, state, _ = _stat(self.pid, deadline)
        if generation != self.generation:
            raise CustodyError('leader generation changed')
        if state in ('Z', 'X', 'x', 't'):
            raise CustodyError('dead or tracer-stopped task')
        self._live()
        _remaining(deadline)

    def snapshot(self, deadline, *, expected=None):
        self._live()
        if _stat(self.pid, deadline)[0] != self.generation:
            raise CustodyError('leader generation changed')
        tids = _tasks(self.pid, deadline)
        records = {tid: _stat(self.pid, deadline, tid) for tid in tids}
        repeated = {tid: _stat(self.pid, deadline, tid) for tid in tids}
        if any(records[tid][0] != repeated[tid][0] for tid in tids):
            raise CustodyError('task generation changed during roster read')
        if tids != _tasks(self.pid, deadline):
            raise CustodyError('task membership changed')
        if _stat(self.pid, deadline)[0] != self.generation:
            raise CustodyError('leader generation changed')
        self._live()
        members = {tid: record[0] for tid, record in records.items()}
        if expected is not None and members != expected:
            raise CustodyError('unexpected task membership or generation')
        if any(record[1] in ('Z', 'X', 'x', 't')
               for record in (*records.values(), *repeated.values())):
            raise CustodyError('dead or tracer-stopped task')
        return repeated

    def children(self, deadline, *, allowed):
        before = self.snapshot(deadline)
        found = {}
        for pid in _children(self.pid, sorted(before), deadline):
            generation, _, parent = _stat(pid, deadline)
            if parent != self.pid:
                raise CustodyError('child parent changed')
            found[pid] = generation
        if _children(self.pid, sorted(before), deadline) != sorted(found):
            raise CustodyError('child membership changed during census')
        for pid, generation in found.items():
            repeated = _stat(pid, deadline)
            if repeated[0] != generation or repeated[2] != self.pid:
                raise CustodyError('child identity changed during census')
        self.snapshot(deadline, expected={tid: r[0] for tid, r in before.items()})
        if found != allowed:
            raise CustodyError('unexpected observer children')
        return found

    def stop(self, deadline, *, expected=None, allowed_children=None):
        self.scope.check_cancelled()
        if self.owed_cont:
            raise CustodyError('group already owes CONT')
        before = self.snapshot(deadline, expected=expected)
        if any(r[1] == 'T' for r in before.values()):
            raise CustodyError('group already stopped')
        members = {tid: r[0] for tid, r in before.items()}
        if allowed_children is not None:
            self.children(deadline, allowed=allowed_children)
        _remaining(deadline)
        signal.pidfd_send_signal(self.fd, signal.SIGSTOP)
        # The dedicated INT/TERM handlers cannot raise between delivery and debt.
        self.owed_cont = True
        self.stopped_members, self.allowed_children = members, allowed_children
        self._confirm(deadline, members, stopped=True)
        if allowed_children is not None:
            self.children(deadline, allowed=allowed_children)
        self.scope.check_cancelled()

    def _confirm(self, deadline, members, *, stopped):
        stable = 0
        while stable < 2:
            _remaining(deadline)
            records = self.snapshot(deadline, expected=members)
            matching = all((r[1] == 'T') == stopped for r in records.values())
            stable = stable + 1 if matching else 0
            if stable < 2:
                time.sleep(min(.005, _remaining(deadline)))

    def resume(self, deadline, *, allow_successful_exit=False):
        self.scope._require_active()
        if self.closed:
            raise CustodyError('group handle is closed')
        if not self.owed_cont:
            return
        # Delivery is owed even if the confirmation deadline is already expired.
        signal.pidfd_send_signal(self.fd, signal.SIGCONT)
        self.owed_cont = False
        try:
            self._confirm(deadline, self.stopped_members, stopped=False)
        except (CustodyError, OSError):
            if not (allow_successful_exit and self.process is not None):
                raise
            # During group exit a task can disappear or become a zombie before
            # the process pidfd is readable. Only our owned ordinary wait can
            # establish successful exit; keep the existing absolute deadline.
            if self.process.wait(deadline) != 0:
                raise CustodyError('resumed owned process exited unsuccessfully')

    def _close(self):
        if self.fd is not None and not self.closed:
            # close(2) errors must not cause retry on a possibly reused descriptor.
            self.closed = True
            os.close(self.fd)


class OwnedProcess:
    """One Popen, its ordinary waiter, and its retained group handle."""
    def __init__(self, scope):
        self.scope, self.popen, self.group = scope, None, None
        self.settled = False

    def wait(self, deadline):
        if self.popen is None:
            raise CustodyError('process launch did not complete')
        value = self.popen.wait(timeout=_remaining(deadline))
        self.settled = True
        return value

    def terminate(self, deadline, *, sig=signal.SIGKILL):
        self.scope._require_active()
        if self.popen is None or self.settled:
            return
        errors = []
        try:
            if self.group is not None and self.group.fd is not None:
                try:
                    signal.pidfd_send_signal(self.group.fd, sig)
                except ProcessLookupError:
                    pass
            else:
                # Exclusive wait ownership + WNOWAIT are required before the
                # sole permitted numeric signal, only when pidfd acquisition failed.
                status = os.waitid(os.P_PID, self.popen.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None and status.si_pid != self.popen.pid:
                    raise CustodyError('pre-pin child identity mismatch')
                if status is None:
                    os.kill(self.popen.pid, sig)
        except BaseException as error:
            errors.append(error)
        try:
            self.wait(deadline)
        except BaseException as error:
            errors.append(error)
            # An earlier child can consume the shared budget. Still attempt a
            # nonblocking reap of this independently owned, already-ended child.
            try:
                self.popen.wait(timeout=0)
                self.settled = True
            except BaseException as error:
                errors.append(error)
        _raise_errors(errors)


class Custody:
    """One dedicated coordinator lifetime; enter before any child is launched.

    cleanup_seconds is a separate finite total budget. Normal phase APIs accept
    a shared absolute deadline. helper_wait() declares a C1 helper's exclusive
    spawn/wait interval; callers must settle it before sealing and orphan drain.
    """
    def __init__(self, *, cleanup_seconds=5):
        if not math.isfinite(cleanup_seconds) or not 0 < cleanup_seconds <= 60:
            raise ValueError('cleanup_seconds must be in (0, 60]')
        self.cleanup_seconds = cleanup_seconds
        self.groups, self.processes, self.reaped_orphans = [], [], []
        self.cancelled = None
        self.active = self.closed = self.sealed = False
        self.helper_depth = 0
        self.handlers = {}
        self.old_subreaper = None

    def _record_signal(self, number, frame):
        if self.cancelled is None:
            self.cancelled = number

    def check_cancelled(self):
        if self.cancelled is not None:
            raise Cancelled(f'coordinator received signal {self.cancelled}')

    def __enter__(self):
        if self.active or self.closed:
            raise CustodyError('custody scope cannot be reused')
        self.child_mask = check_owner_policy()
        deadline = time.monotonic() + self.cleanup_seconds
        if _children(os.getpid(), _tasks(os.getpid(), deadline), deadline):
            raise CustodyError('custody owner already has children')
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                self.handlers[number] = signal.getsignal(number)
                signal.signal(number, self._record_signal)
            self.old_subreaper = _subreaper()
            _subreaper(1)
            if _subreaper() != 1:
                raise CustodyError('subreaper readback failed')
            self.active = True
            self.check_cancelled()
            return self
        except BaseException as error:
            errors = [error]
            self._restore(errors)
            self.closed = True
            _raise_errors(errors)

    def _require_active(self):
        if not self.active or self.closed:
            raise CustodyError('inactive custody scope')

    def _pin(self, pid, generation, *, role, wait_owner, origin, deadline, owned=None):
        if not isinstance(pid, int) or pid <= 0 or (generation is not None and generation <= 0):
            raise CustodyError('invalid process identity')
        group = Group(self, pid, generation, role, wait_owner, origin)
        self.groups.append(group)
        if owned is not None:
            owned.group, group.process = group, owned
        _remaining(deadline)
        group.fd = os.pidfd_open(pid)
        if owned is None:
            group._live()
        first = _stat(pid, deadline)
        if generation is None:
            group.generation = first[0]
        if first[0] != group.generation or _stat(pid, deadline)[0] != group.generation:
            raise CustodyError('leader generation mismatch')
        if owned is None:
            records = group.snapshot(deadline)
            if any(r[1] == 'T' for r in records.values()):
                raise CustodyError('group already stopped')
        return group

    def borrow(self, pid, generation, *, role, wait_owner='shell', deadline=None):
        self._require_active()
        self.check_cancelled()
        if wait_owner != 'shell':
            raise CustodyError('borrowed external group requires shell wait owner')
        if any(g.pid == pid for g in self.groups):
            raise CustodyError('group already retained')
        return self._pin(pid, generation, role=role, wait_owner=wait_owner,
                         origin='external', deadline=deadline if deadline is not None else time.monotonic() + 1)

    def retain_observer_child(self, observer, pid, generation, deadline):
        """Retain this scope's live observer's sole child without taking its wait."""
        self._require_active()
        self.check_cancelled()
        _remaining(deadline)
        if (self.sealed or self.helper_depth or not isinstance(observer, OwnedProcess)
                or observer.scope is not self or observer not in self.processes
                or observer.settled or observer.popen is None or observer.group is None):
            raise CustodyError('child retention requires this active owned observer')
        parent = observer.group
        if (parent not in self.groups or parent.scope is not self or parent.process is not observer
                or parent.pid != observer.popen.pid or parent.role != 'observer'
                or parent.origin != 'direct' or parent.wait_owner != 'custody'):
            raise CustodyError('child retention requires the original direct observer')
        if type(pid) is not int or pid <= 0 or type(generation) is not int or generation <= 0:
            raise CustodyError('invalid observer child identity')
        if any(group.pid == pid for group in self.groups):
            raise CustodyError('group already retained')
        allowed = {pid: generation}
        parent.children(deadline, allowed=allowed)
        group = self._pin(pid, generation, role='workload', wait_owner='observer',
                          origin='observer-child', deadline=deadline)
        parent.children(deadline, allowed=allowed)
        if any(record[2] != parent.pid for record in group.snapshot(deadline).values()):
            raise CustodyError('observer child parent changed')
        group.observer_parent = observer
        self.check_cancelled()
        return group

    def adopt_observer_child(self, observer, group, deadline):
        """Claim only a retained child handed back by its successful observer."""
        self._require_active()
        self.check_cancelled()
        _remaining(deadline)
        if (self.sealed or self.helper_depth or observer not in self.processes
                or observer.scope is not self or not observer.settled
                or observer.popen is None or observer.popen.returncode != 0
                or group not in self.groups or group.scope is not self
                or group.observer_parent is not observer or group.origin != 'observer-child'
                or group.wait_owner != 'observer' or group.process is not None):
            raise CustodyError('handoff requires the retained successful observer and child')
        group.check_alive(deadline)
        rows = group.snapshot(deadline, expected=group.stopped_members)
        if any(row[2] != os.getpid() for row in rows.values()):
            raise CustodyError('handoff child was not adopted by this coordinator')
        group.children(deadline, allowed={})
        self.check_cancelled()
        group.wait_owner = 'custody'

    def wait_observer_child(self, group, deadline):
        """Reap an explicitly claimed handoff, never another observer's wait."""
        self._require_active()
        self.check_cancelled()
        if (group not in self.groups or group.scope is not self or group.closed
                or group.origin != 'observer-child' or group.wait_owner != 'custody'
                or group.observer_parent is None or not group.observer_parent.settled):
            raise CustodyError('child wait requires an explicitly adopted handoff')
        generation, _, parent = _stat(group.pid, deadline)
        if generation != group.generation or parent != os.getpid():
            raise CustodyError('handoff child identity or parent changed')
        while True:
            self.check_cancelled()
            _remaining(deadline)
            status = os.waitid(os.P_PIDFD, group.fd, os.WEXITED | os.WNOHANG)
            if status is not None:
                if status.si_pid != group.pid:
                    raise CustodyError('handoff child wait identity mismatch')
                group.wait_owner = 'reaped'
                if status.si_code != os.CLD_EXITED or status.si_status != 0:
                    raise CustodyError('handoff child did not exit normally with status zero')
                return
            select.select([group.fd], [], [], min(.05, _remaining(deadline)))

    def launch(self, argv, *, role='observer', stdout=None, stderr=None, deadline=None, pass_fds=()):
        self._require_active()
        self.check_cancelled()
        if self.sealed or self.helper_depth:
            raise CustodyError('spawning sealed or helper wait active')
        if stdout == subprocess.PIPE or stderr == subprocess.PIPE:
            raise CustodyError('custody requires caller-owned output files')
        deadline = deadline if deadline is not None else time.monotonic() + self.cleanup_seconds
        _remaining(deadline)
        owned = OwnedProcess(self)
        self.processes.append(owned)
        owned.popen = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       pass_fds=pass_fds,
                                       preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, self.child_mask))
        self._pin(owned.popen.pid, None, role=role, wait_owner='custody', origin='direct',
                  deadline=deadline, owned=owned)
        self.check_cancelled()
        return owned

    @contextlib.contextmanager
    def helper_wait(self):
        self._require_active()
        if self.sealed or self.helper_depth:
            raise CustodyError('helper spawning sealed or already active')
        self.check_cancelled()
        self.helper_depth += 1
        try:
            yield
        finally:
            self.helper_depth -= 1

    def seal_spawns(self):
        self._require_active()
        self.sealed = True

    def resume_all(self, deadline, *, order=None):
        self._require_active()
        errors = []
        groups = list(order) if order is not None else sorted(self.groups, key=lambda g: g.role != 'observer')
        if len(groups) != len(set(groups)) or set(groups) != set(self.groups):
            errors.append(CustodyError('resume order must contain every retained group exactly once'))
            groups = sorted(self.groups, key=lambda g: g.role != 'observer')
        for group in groups:
            try:
                group.resume(deadline)
            except BaseException as error:
                errors.append(error)
        _raise_errors(errors)

    def drain_orphans(self, deadline):
        self._require_active()
        if not self.sealed or self.helper_depth or any(not p.settled for p in self.processes):
            raise CustodyError('orphan drain requires sealed spawns and all direct waits settled')
        check_owner_policy()
        errors, blocked = [], set()
        while True:
            try:
                _remaining(deadline)
                pids = _children(os.getpid(), _tasks(os.getpid(), deadline), deadline)
            except BaseException as error:
                errors.append(error)
                break
            if not pids:
                break
            if not errors:
                errors.append(CustodyError('unexpected adopted children'))
            if set(pids).issubset(blocked):
                break
            wave = []
            # Pin/validate the whole current wave before *any* reap.
            for pid in pids:
                if pid in blocked:
                    continue
                fd = None
                try:
                    _remaining(deadline)
                    fd = os.pidfd_open(pid)
                    generation, _, parent = _stat(pid, deadline)
                    if parent != os.getpid():
                        raise CustodyError('orphan is not a direct child')
                    status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if status is not None and status.si_pid != pid:
                        raise CustodyError('orphan wait identity mismatch')
                    second = _stat(pid, deadline)
                    if second[0] != generation or second[2] != parent:
                        raise CustodyError('orphan generation or parent changed')
                    wave.append((pid, generation, fd))
                    fd = None
                except BaseException as error:
                    errors.append(error)
                    blocked.add(pid)
                finally:
                    if fd is not None:
                        try:
                            os.close(fd)
                        except BaseException as error:
                            errors.append(error)
            for pid, _, fd in wave:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    errors.append(error)
            for pid, generation, fd in wave:
                try:
                    status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if status is None:
                        if not select.select([fd], [], [], _remaining(deadline))[0]:
                            raise DeadlineExpired('orphan reap deadline expired')
                        status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if status is None or status.si_pid != pid:
                        raise CustodyError('orphan was not reaped')
                    self.reaped_orphans.append((pid, generation))
                except BaseException as error:
                    errors.append(error)
                    blocked.add(pid)
                finally:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        errors.append(error)
        _raise_errors(errors)

    def _restore(self, errors):
        # Keep INT/TERM deferred while replacing their nonraising handlers.
        # Record the mask before mutation and restore it only after every
        # policy restoration has been attempted. Signals pending in this final
        # interval are cancellation, not delivery to a half-restored policy.
        original_mask = None
        try:
            original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        except BaseException as error:
            errors.append(error)
        if self.old_subreaper is not None:
            try:
                _subreaper(self.old_subreaper)
                if _subreaper() != self.old_subreaper:
                    raise CustodyError('subreaper restoration readback failed')
            except BaseException as error:
                errors.append(error)
        for number, handler in self.handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException as error:
                errors.append(error)
        try:
            pending = signal.sigpending().intersection((signal.SIGINT, signal.SIGTERM))
        except BaseException as error:
            errors.append(error)
            pending = set()
        for number in sorted(pending):
            try:
                status = signal.sigtimedwait({number}, 0)
                if status is None:
                    raise CustodyError('pending cancellation was not retained')
                self._record_signal(status.si_signo, None)
            except BaseException as error:
                errors.append(error)
        if original_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            except BaseException as error:
                errors.append(error)

    def close(self):
        if self.closed:
            return
        self._require_active()
        deadline, errors = time.monotonic() + self.cleanup_seconds, []
        try:
            self.resume_all(deadline)
        except BaseException as error:
            errors.append(error)
        self.sealed = True
        for owned in self.processes:
            try:
                owned.terminate(deadline)
            except BaseException as error:
                errors.append(error)
        try:
            self.drain_orphans(deadline)
        except BaseException as error:
            errors.append(error)
        for group in self.groups:
            try:
                group._close()
            except BaseException as error:
                errors.append(error)
        self._restore(errors)
        if self.cancelled is not None:
            errors.append(Cancelled(f'coordinator received signal {self.cancelled}'))
        self.active, self.closed = False, True
        _raise_errors(errors)

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.close()
        except BaseException as error:
            if exc is not None:
                _raise_errors([exc, error])
            raise
        return False
