#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Isolated Linux process-custody probes; every probe has an external watchdog."""
import ctypes
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

c = load_path(ROOT / 'scripts/canary_process_custody.py', 'custody')


def identity(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19])


def state(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0]


def until(predicate):
    end = time.monotonic() + 2
    while not predicate():
        assert time.monotonic() < end, 'probe condition deadline'
        time.sleep(.005)


def first_red(observer, workload):
    sent = []
    original = signal.pidfd_send_signal
    held = []
    def send(fd, sig, *args):
        sent.append((fd, sig))
        if fd == held[1].fd and sig == signal.SIGSTOP:
            raise PermissionError('injected workload STOP refusal')
        return original(fd, sig, *args)
    with patch.object(signal, 'pidfd_send_signal', side_effect=send):
        try:
            with c.Custody() as owner:
                held.append(owner.borrow(observer, identity(observer), role='observer'))
                held.append(owner.borrow(workload, identity(workload), role='workload'))
                held[0].stop(time.monotonic() + 2)
                until(lambda: state(observer) == 'T')
                held[1].stop(time.monotonic() + 2)
        except PermissionError:
            pass
    assert state(observer) != 'T', 'successful observer STOP was not resumed'
    assert (held[0].fd, signal.SIGCONT) in sent
    assert (held[1].fd, signal.SIGCONT) not in sent
    for group in held:
        try:
            os.fstat(group.fd)
        except OSError:
            continue
        raise AssertionError('retained pidfd was not closed')


def raises(kind, action):
    try:
        action()
    except kind as error:
        return error
    raise AssertionError(f'expected {kind.__name__}')


def gone(fd):
    assert select.select([fd], [], [], 1)[0], 'retained child did not exit'
    raises(ChildProcessError, lambda: os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG))


def launch(owner, code='time.sleep(30)'):
    prefix = 'import ctypes,os,signal,time; ctypes.CDLL(None).prctl(1,9,0,0,0); '
    return owner.launch([sys.executable, '-c', prefix + code], stdout=subprocess.DEVNULL)


def direct_term(observer, workload):
    before = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / 'ready')
        with c.Custody() as owner:
            child = launch(owner, f"signal.signal(signal.SIGTERM, lambda n,f: os._exit(23)); open({path!r}, 'w').close(); time.sleep(30)")
            until(lambda: Path(path).exists())
            fd = os.dup(child.group.fd)
            child.terminate(time.monotonic() + 2, sig=signal.SIGTERM)
            assert child.popen.returncode == 23, 'TERM was not handled by actual child'
            gone(fd)
            os.close(fd)
    assert before == (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())


def complete_threads(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / 'ready')
        with c.Custody() as owner:
            child = launch(owner, "ctypes.CDLL(None).prctl(15, b'odd ) name (', 0, 0, 0); import threading; "
                           "[threading.Thread(target=lambda: time.sleep(30)).start() for _ in range(3)]; "
                           f"open({path!r}, 'w').close(); time.sleep(30)")
            until(lambda: Path(path).exists())
            group = child.group
            roster = group.snapshot(time.monotonic() + 2)
            assert len(roster) == 4
            expected = {tid: value[0] for tid, value in roster.items()}
            group.stop(time.monotonic() + 2, expected=expected, allowed_children={})
            assert all(r[1] == 'T' for r in group.snapshot(time.monotonic() + 2).values())
            group.resume(time.monotonic() + 2)
            assert all(r[1] != 'T' for r in group.snapshot(time.monotonic() + 2).values())
            raises(c.CustodyError, lambda: group.snapshot(time.monotonic() + 2, expected={child.popen.pid: child.group.generation}))
            real = c._stat
            worker = next(tid for tid in roster if tid != child.popen.pid)
            def fail_worker(pid, deadline, tid=None):
                if tid == worker:
                    raise FileNotFoundError('injected worker stat failure')
                return real(pid, deadline, tid)
            with patch.object(c, '_stat', side_effect=fail_worker):
                raises(FileNotFoundError, lambda: group.snapshot(time.monotonic() + 2))


def identity_refusals(observer, workload):
    with c.Custody() as owner:
        raises(c.CustodyError, lambda: owner.borrow(observer, identity(observer) + 1, role='observer'))
        child = launch(owner, 'os._exit(0)')
        until(lambda: select.select([child.group.fd], [], [], 0)[0])
        raises(c.CustodyError, lambda: child.group.snapshot(time.monotonic() + 1))
        assert child.wait(time.monotonic() + 1) == 0
    assert all(g.closed for g in owner.groups)


def live_identity_refusals(observer, workload):
    with c.Custody() as owner:
        child = launch(owner)
        group = child.group
        group.check_alive(time.monotonic() + 1)
        raises(c.DeadlineExpired, lambda: group.check_alive(time.monotonic() - 1))
        raises(c.CustodyError, lambda: group.check_alive(float('nan')))
        with patch.object(group, 'generation', group.generation + 1):
            raises(c.CustodyError, lambda: group.check_alive(time.monotonic() + 1))
        child.terminate(time.monotonic() + 2)
        raises(c.CustodyError, lambda: group.check_alive(time.monotonic() + 1))
    raises(c.CustodyError, lambda: group.check_alive(time.monotonic() + 1))


def prestop_refusal(observer, workload):
    fd = os.pidfd_open(workload)
    try:
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        until(lambda: state(workload) == 'T')
        with c.Custody() as owner:
            with patch.object(signal, 'pidfd_send_signal', wraps=signal.pidfd_send_signal) as sent:
                raises(c.CustodyError, lambda: owner.borrow(workload, identity(workload), role='workload'))
            assert not sent.called
        assert state(workload) == 'T', 'independent stop was resumed'
    finally:
        signal.pidfd_send_signal(fd, signal.SIGCONT)
        os.close(fd)


def traced_refusal(observer, workload):
    assert state(workload) == 't'
    with c.Custody() as owner:
        raises(c.CustodyError, lambda: owner.borrow(workload, identity(workload), role='workload'))


def partial_timeout(observer, workload):
    with c.Custody() as owner:
        group = owner.borrow(workload, identity(workload), role='workload')
        real = group.snapshot
        def incomplete(*args, **kwargs):
            records = real(*args, **kwargs)
            if group.owed_cont:
                return {tid: (r[0], 'S', r[2]) for tid, r in records.items()}
            return records
        with patch.object(group, 'snapshot', side_effect=incomplete):
            raises(c.CustodyError, lambda: group.stop(time.monotonic() + .03))
        assert state(workload) == 'T'
    assert state(workload) != 'T'


def resume_attempts(observer, workload):
    original = signal.pidfd_send_signal
    with c.Custody() as owner:
        groups = [owner.borrow(pid, identity(pid), role=role) for pid, role in ((observer, 'observer'), (workload, 'workload'))]
        for group in groups:
            group.stop(time.monotonic() + 1)
        calls = []
        def refuse(fd, sig, *args):
            calls.append((fd, sig))
            if fd == groups[0].fd and sig == signal.SIGCONT:
                raise PermissionError('injected observer CONT refusal')
            return original(fd, sig, *args)
        with patch.object(signal, 'pidfd_send_signal', side_effect=refuse):
            raises(c.CleanupError, lambda: owner.resume_all(time.monotonic() - 1))
        assert calls == [(groups[0].fd, signal.SIGCONT), (groups[1].fd, signal.SIGCONT)]
        until(lambda: state(workload) != 'T')
    assert state(observer) != 'T'


def cancellation_boundaries(observer, workload):
    original = signal.pidfd_send_signal
    for number, boundary in ((signal.SIGINT, signal.SIGSTOP), (signal.SIGTERM, signal.SIGCONT)):
        groups, calls = [], []
        delivered = False
        def send(fd, sig, *args):
            nonlocal delivered
            result = original(fd, sig, *args)
            calls.append((fd, sig))
            if sig == boundary and not delivered:
                delivered = True
                os.kill(os.getpid(), number)
            return result
        try:
            with patch.object(signal, 'pidfd_send_signal', side_effect=send):
                with c.Custody() as owner:
                    groups = [owner.borrow(pid, identity(pid), role=role) for pid, role in ((observer, 'observer'), (workload, 'workload'))]
                    for group in groups:
                        group.stop(time.monotonic() + 1)
        except c.CustodyError:
            pass
        else:
            raise AssertionError('cancellation was reported as success')
        assert delivered
        assert state(observer) != 'T' and state(workload) != 'T'
        assert all(g.closed for g in groups)
        for group in groups:
            if (group.fd, signal.SIGSTOP) in calls:
                assert (group.fd, signal.SIGCONT) in calls


def policy_refusals(observer, workload):
    before = c._subreaper()
    assert c.check_owner_policy() == signal.pthread_sigmask(signal.SIG_BLOCK, [])
    for number in (signal.SIGINT, signal.SIGTERM):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, [number])
        try:
            raises(c.CustodyError, c.check_owner_policy)
            raises(c.CustodyError, lambda: c.Custody().__enter__())
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        assert c._subreaper() == before
    old = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        raises(c.CustodyError, lambda: c.Custody().__enter__())
    finally:
        signal.signal(signal.SIGCHLD, old)
    done = threading.Event()
    thread = threading.Thread(target=done.wait)
    thread.start()
    try:
        raises(c.CustodyError, lambda: c.Custody().__enter__())
    finally:
        done.set()
        thread.join(timeout=1)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    fd = os.pidfd_open(child.pid)
    try:
        raises(c.CustodyError, lambda: c.Custody().__enter__())
    finally:
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        child.wait(timeout=1)
        os.close(fd)
    assert c._subreaper() == before


def child_mask_restoration(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        ready = str(Path(directory) / 'ready')
        with c.Custody() as owner:
            old = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
            try:
                child = launch(owner, f"signal.signal(signal.SIGTERM, lambda n,f: os._exit(24)); open({ready!r}, 'w').close(); time.sleep(30)")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old)
            until(lambda: Path(ready).exists())
            child.terminate(time.monotonic() + 1, sig=signal.SIGTERM)
            assert child.popen.returncode == 24


def post_reap_interruption(observer, workload):
    with patch.object(os, 'kill', side_effect=AssertionError('numeric signal after pin')):
        with c.Custody() as owner:
            child = launch(owner, 'os._exit(0)')
            fd = os.dup(child.group.fd)
            wait = child.popen.wait
            calls = []
            def interrupted(*args, **kwargs):
                result = wait(*args, **kwargs)
                calls.append(result)
                if len(calls) == 1:
                    raise KeyboardInterrupt('injected after ordinary reap')
                return result
            with patch.object(child.popen, 'wait', side_effect=interrupted):
                raises(KeyboardInterrupt, lambda: child.wait(time.monotonic() + 1))
                child.terminate(time.monotonic() + 1)
            assert child.settled and len(calls) == 2
            gone(fd)
            os.close(fd)


def pin_refusal(observer, workload):
    real = os.pidfd_open
    calls = []
    numeric = os.kill
    def track(pid, sig):
        calls.append((pid, sig))
        return numeric(pid, sig)
    owner = c.Custody()
    with patch.object(os, 'kill', side_effect=track):
        try:
            with owner:
                with patch.object(os, 'pidfd_open', side_effect=PermissionError('injected pidfd refusal')):
                    launch(owner)
        except PermissionError:
            pass
        else:
            raise AssertionError('pin refusal accepted')
    assert owner.processes[0].settled
    assert calls == [(owner.processes[0].popen.pid, signal.SIGKILL)]
    raises(ProcessLookupError, lambda: real(owner.processes[0].popen.pid))
    # Once another waiter has reaped before pre-pin cleanup, WNOWAIT must refuse
    # ownership and the numeric fallback must never be attempted.
    owner = c.Custody()
    try:
        with owner:
            with patch.object(os, 'pidfd_open', side_effect=PermissionError('injected pidfd refusal')):
                raises(PermissionError, lambda: launch(owner, 'os._exit(0)'))
            child = owner.processes[0]
            child.popen.wait(timeout=1)
            with patch.object(os, 'kill', side_effect=AssertionError('stale numeric fallback')):
                raises(c.CleanupError, lambda: child.terminate(time.monotonic() + 1))
    except c.CleanupError:
        pass


def living_observer_wait(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        ready, release = [str(Path(directory) / x) for x in ('ready', 'release')]
        code = f"""
pid = os.fork()
if pid == 0:
    os._exit(7)
open({ready!r}, 'w').write(str(pid))
while not os.path.exists({release!r}):
    time.sleep(.005)
got, status = os.waitpid(pid, 0)
os._exit(0 if got == pid and os.waitstatus_to_exitcode(status) == 7 else 9)
"""
        with c.Custody() as owner:
            child = launch(owner, '\n' + code)
            until(lambda: Path(ready).exists() and Path(ready).read_text())
            pid = int(Path(ready).read_text())
            until(lambda: state(pid) == 'Z')
            child.group.children(time.monotonic() + 1, allowed={pid: identity(pid)})
            raises(c.CustodyError, lambda: child.group.children(time.monotonic() + 1, allowed={}))
            owner.seal_spawns()
            raises(c.CustodyError, lambda: owner.drain_orphans(time.monotonic() + 1))
            assert state(pid) == 'Z', 'live observer lost its exclusive child wait'
            Path(release).touch()
            assert child.wait(time.monotonic() + 1) == 0
            owner.drain_orphans(time.monotonic() + 1)


def orphan_case(kind):
    with tempfile.TemporaryDirectory() as directory:
        ready = str(Path(directory) / 'forked')
        if kind == 'pre_ready':
            code = "\npid = os.fork()\nif pid: os._exit(0)\ntime.sleep(30)\n"
        elif kind == 'zombie':
            code = "\npid = os.fork()\nif not pid: os._exit(7)\ntime.sleep(.08)\nos._exit(0)\n"
        elif kind == 'second_generation':
            code = f"""
pid = os.fork()
if not pid:
    grandchild = os.fork()
    if not grandchild:
        time.sleep(30)
        os._exit(0)
    open({ready!r}, 'w').write(str(grandchild))
    time.sleep(30)
    os._exit(0)
while not os.path.exists({ready!r}):
    time.sleep(.005)
os._exit(0)
"""
        else:
            code = "\nfor _ in range(2):\n    if not os.fork():\n        time.sleep(30)\n        os._exit(0)\ntime.sleep(.03)\nos._exit(0)\n"
        retained = []
        try:
            with c.Custody() as owner:
                child = launch(owner, code)
                assert child.wait(time.monotonic() + 2) == 0
                pids = c._children(os.getpid(), [os.getpid()], time.monotonic() + 1)
                assert pids and child.popen.pid not in pids
                if kind == 'zombie':
                    assert all(state(pid) == 'Z' for pid in pids)
                if kind == 'second_generation':
                    pids.append(int(Path(ready).read_text()))
                retained = [(pid, os.pidfd_open(pid)) for pid in pids]
                owner.seal_spawns()
                if kind == 'pin_failure':
                    real = os.pidfd_open
                    failed = pids[0]
                    def refuse(pid, *args):
                        if pid == failed:
                            raise PermissionError('injected orphan acquisition refusal')
                        return real(pid, *args)
                    with patch.object(os, 'pidfd_open', side_effect=refuse):
                        raises(c.CleanupError, lambda: owner.drain_orphans(time.monotonic() + 1))
                    assert [pid for pid, _ in owner.reaped_orphans] == pids[1:]
                    assert not select.select([retained[0][1]], [], [], 0)[0]
                elif kind == 'deadline':
                    raises(c.CleanupError, lambda: owner.drain_orphans(time.monotonic() - 1))
                    assert not owner.reaped_orphans
                else:
                    raises(c.CleanupError, lambda: owner.drain_orphans(time.monotonic() + 2))
                    assert len(owner.reaped_orphans) == len(pids)
        except c.CleanupError:
            # Deliberately incomplete manual drain is retried during close;
            # unknown adoptees still make close explicitly nonpass.
            if kind not in ('pin_failure', 'deadline'):
                raise
        finally:
            for _, fd in retained:
                try:
                    gone(fd)
                finally:
                    os.close(fd)
        raises(ChildProcessError, lambda: os.waitpid(-1, os.WNOHANG))


def pre_ready_orphan(observer, workload):
    orphan_case('pre_ready')


def adopted_zombie(observer, workload):
    orphan_case('zombie')


def second_generation(observer, workload):
    orphan_case('second_generation')


def orphan_pin_failure(observer, workload):
    orphan_case('pin_failure')


def orphan_deadline(observer, workload):
    orphan_case('deadline')


def ownership_guards(observer, workload):
    with c.Custody() as owner:
        raises(c.CustodyError, lambda: owner.borrow(workload, identity(workload), role='workload', wait_owner='custody'))
        with owner.helper_wait():
            owner.seal_spawns()
            raises(c.CustodyError, lambda: owner.drain_orphans(time.monotonic() + 1))
        raises(c.CustodyError, lambda: launch(owner))
        raises(c.CustodyError, lambda: owner.helper_wait().__enter__())
        owner.drain_orphans(time.monotonic() + 1)


def worker_child_census(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        ready, release = [str(Path(directory) / x) for x in ('ready', 'release')]
        code = f"""
import threading
def worker():
    pid = os.fork()
    if not pid:
        while not os.path.exists({release!r}):
            time.sleep(.005)
        os._exit(0)
    open({ready!r}, 'w').write(str(pid))
    got, status = os.waitpid(pid, 0)
    assert got == pid and status == 0
thread = threading.Thread(target=worker)
thread.start()
thread.join()
"""
        with c.Custody() as owner:
            child = launch(owner, '\n' + code)
            until(lambda: Path(ready).exists() and Path(ready).read_text())
            pid = int(Path(ready).read_text())
            assert not Path(f'/proc/{child.popen.pid}/task/{child.popen.pid}/children').read_text().strip()
            allowed = {pid: identity(pid)}
            raises(c.CustodyError, lambda: child.group.stop(time.monotonic() + 1, allowed_children={}))
            assert state(child.popen.pid) != 'T'
            child.group.stop(time.monotonic() + 1, allowed_children=allowed)
            child.group.children(time.monotonic() + 1, allowed=allowed)
            child.group.resume(time.monotonic() + 1)
            Path(release).touch()
            assert child.wait(time.monotonic() + 1) == 0


def real_roster_change(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        ready, change, changed = [str(Path(directory) / x) for x in ('ready', 'change', 'changed')]
        code = f"""
import threading
open({ready!r}, 'w').close()
while not os.path.exists({change!r}):
    time.sleep(.005)
threading.Thread(target=lambda: time.sleep(30)).start()
open({changed!r}, 'w').close()
time.sleep(30)
"""
        with c.Custody() as owner:
            child = launch(owner, '\n' + code)
            until(lambda: Path(ready).exists())
            roster = child.group.snapshot(time.monotonic() + 1)
            Path(change).touch()
            until(lambda: Path(changed).exists())
            with patch.object(signal, 'pidfd_send_signal', wraps=signal.pidfd_send_signal) as sent:
                raises(c.CustodyError, lambda: child.group.stop(time.monotonic() + 1, expected={tid: r[0] for tid, r in roster.items()}))
            assert not sent.called


def cleanup_failures(observer, workload):
    old = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())
    owner = c.Custody()
    owner.__enter__()
    groups = [owner.borrow(pid, identity(pid), role=role) for pid, role in ((observer, 'observer'), (workload, 'workload'))]
    for group in groups:
        group.stop(time.monotonic() + 1)
    closed = []
    real = os.close
    def close(fd):
        real(fd)
        if fd in [g.fd for g in groups]:
            closed.append(fd)
            if len(closed) == 1:
                os.kill(os.getpid(), signal.SIGINT)
                raise OSError('injected first descriptor close failure')
    with patch.object(os, 'close', side_effect=close):
        error = raises(c.CleanupError, owner.close)
    assert closed == [g.fd for g in groups]
    assert state(observer) != 'T' and state(workload) != 'T'
    messages, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        messages.append(str(error))
        error = error.__cause__
    assert any('injected first descriptor close failure' in text for text in messages)
    assert any('coordinator received signal' in text for text in messages)
    assert old == (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())
    owner = c.Custody()
    owner.__enter__()
    subreaper = c._subreaper
    def restore(value=None):
        result = subreaper(value)
        if value is not None:
            os.kill(os.getpid(), signal.SIGTERM)
        return result
    with patch.object(c, '_subreaper', side_effect=restore):
        raises(c.CleanupError, owner.close)
    assert owner.cancelled == signal.SIGTERM and owner.closed
    assert old == (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())
    owner = c.Custody()
    owner.__enter__()
    disposition = signal.signal
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    def restore_handler(number, handler):
        result = disposition(number, handler)
        if number == signal.SIGTERM:
            os.kill(os.getpid(), signal.SIGTERM)
        return result
    with patch.object(signal, 'signal', side_effect=restore_handler):
        raises(c.CleanupError, owner.close)
    assert owner.cancelled == signal.SIGTERM and owner.closed
    assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == mask
    assert old == (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM), c._subreaper())


def native_sigchld_refusal(observer, workload):
    class Action(ctypes.Structure):
        _fields_ = [('handler', ctypes.c_void_p), ('mask', ctypes.c_ubyte * 128),
                    ('flags', ctypes.c_int), ('restorer', ctypes.c_void_p)]
    old, changed = Action(), Action()
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.sigaction(signal.SIGCHLD, None, ctypes.byref(old)) == 0
    changed.flags = 2  # SA_NOCLDWAIT with SIG_DFL remains invisible to getsignal.
    assert libc.sigaction(signal.SIGCHLD, ctypes.byref(changed), None) == 0
    try:
        assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        raises(c.CustodyError, lambda: c.Custody().__enter__())
    finally:
        assert libc.sigaction(signal.SIGCHLD, ctypes.byref(old), None) == 0


def ignored_disposition(number, *, native_only):
    class Action(ctypes.Structure):
        _fields_ = [('handler', ctypes.c_void_p), ('mask', ctypes.c_ubyte * 128),
                    ('flags', ctypes.c_int), ('restorer', ctypes.c_void_p)]
    libc = ctypes.CDLL(None, use_errno=True)
    old_native = Action()
    assert libc.sigaction(number, None, ctypes.byref(old_native)) == 0
    old_python = signal.getsignal(number)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    old_subreaper = c._subreaper()
    owner = None
    try:
        if native_only:
            ignored = Action()
            ignored.handler = int(signal.SIG_IGN)
            assert libc.sigaction(number, ctypes.byref(ignored), None) == 0
            assert signal.getsignal(number) != signal.SIG_IGN
        else:
            signal.signal(number, signal.SIG_IGN)
        # Establish that this is an actual ignored disposition, not a mocked
        # getsignal result. Delivery must leave the isolated probe alive.
        os.kill(os.getpid(), number)
        for cached_only in ([False] if native_only else [False, True]):
            if cached_only:
                # Also prove admission checks Python's saved SIG_IGN when the
                # actual native disposition has already become nonignored.
                assert libc.sigaction(number, ctypes.byref(old_native), None) == 0
                assert signal.getsignal(number) == signal.SIG_IGN
            incoming = Action()
            assert libc.sigaction(number, None, ctypes.byref(incoming)) == 0
            saved_python = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            descriptors = set(os.listdir('/proc/self/fd'))
            owner = c.Custody()
            with patch.object(signal, 'signal', wraps=signal.signal) as disposition, \
                    patch.object(c, '_subreaper', wraps=c._subreaper) as subreaper, \
                    patch.object(os, 'pidfd_open', wraps=os.pidfd_open) as pin, \
                    patch.object(subprocess, 'Popen', wraps=subprocess.Popen) as spawn:
                raises(c.CustodyError, c.check_owner_policy)
                raises(c.CustodyError, owner.__enter__)
                assert not disposition.called and not subreaper.called
                assert not pin.called and not spawn.called
            assert not owner.active and not owner.groups and not owner.processes
            assert not owner.handlers and owner.old_subreaper is None
            assert set(os.listdir('/proc/self/fd')) == descriptors
            assert not c._children(os.getpid(), [os.getpid()], time.monotonic() + 1)
            assert c._subreaper() == old_subreaper
            assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == old_mask
            assert saved_python == {sig: signal.getsignal(sig) for sig in saved_python}
            after = Action()
            assert libc.sigaction(number, None, ctypes.byref(after)) == 0
            assert after.handler == incoming.handler and after.flags == incoming.flags
            # Compare defined signal membership, not unused libc sigset_t bytes.
            assert all(libc.sigismember(ctypes.byref(after.mask), sig)
                       == libc.sigismember(ctypes.byref(incoming.mask), sig)
                       for sig in signal.valid_signals())
            assert after.restorer == incoming.restorer
    finally:
        # RED may have admitted a scope. Restore it before the independently
        # saved test policy; no children are launched by this admission probe.
        if owner is not None and owner.active:
            owner.close()
        signal.signal(number, old_python)
        assert libc.sigaction(number, ctypes.byref(old_native), None) == 0
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        c._subreaper(old_subreaper)


def python_ignored_int(observer, workload):
    ignored_disposition(signal.SIGINT, native_only=False)


def python_ignored_term(observer, workload):
    ignored_disposition(signal.SIGTERM, native_only=False)


def native_ignored_int(observer, workload):
    ignored_disposition(signal.SIGINT, native_only=True)


def native_ignored_term(observer, workload):
    ignored_disposition(signal.SIGTERM, native_only=True)


def bounded_direct_wait(observer, workload):
    with c.Custody() as owner:
        child = launch(owner)
        raises(subprocess.TimeoutExpired, lambda: child.wait(time.monotonic() + .02))
        assert not child.settled
        fd = os.dup(child.group.fd)
    gone(fd)
    os.close(fd)


def owned_stop_refusal(observer, workload):
    groups, fd, resumed = [], None, []
    real = signal.pidfd_send_signal
    def refuse(handle, sig, *args):
        if len(groups) == 2 and handle == groups[1].fd and sig == signal.SIGSTOP:
            raise PermissionError('injected workload STOP refusal')
        result = real(handle, sig, *args)
        if sig == signal.SIGCONT:
            resumed.append(handle)
        return result
    try:
        with patch.object(signal, 'pidfd_send_signal', side_effect=refuse):
            with c.Custody() as owner:
                child = launch(owner)
                fd = os.dup(child.group.fd)
                groups = [child.group, owner.borrow(workload, identity(workload), role='workload')]
                groups[0].stop(time.monotonic() + 1)
                groups[1].stop(time.monotonic() + 1)
    except PermissionError:
        pass
    assert resumed == [groups[0].fd]
    assert all(group.closed for group in groups)
    gone(fd)
    os.close(fd)


def retained_observer_child_wait(observer, workload):
    with tempfile.TemporaryDirectory() as directory:
        ready, release, waited = [Path(directory) / name for name in ('ready', 'release', 'waited')]
        code = f"""
pid = os.fork()
if pid == 0:
    while not os.path.exists({str(release)!r}):
        time.sleep(.005)
    os._exit(7)
open({str(ready)!r}, 'w').write(str(pid))
got, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
open({str(waited)!r}, 'w').write(str(code))
os._exit(0 if got == pid and code == 7 else 19)
"""
        owner = c.Custody()
        parent, test_handles = None, []
        owner.__enter__()
        try:
            parent = launch(owner, '\n' + code)
            test_handles.append(os.dup(parent.group.fd))
            until(lambda: ready.exists() and ready.read_text())
            pid = int(ready.read_text())
            test_handles.append(os.pidfd_open(pid))
            child = owner.retain_observer_child(parent, pid, identity(pid), time.monotonic() + 2)
            assert child.wait_owner == 'observer' and child.origin == 'observer-child'
            assert child.process is None and len(owner.processes) == 1
            raises(ChildProcessError, lambda: os.waitid(os.P_PIDFD, child.fd, os.WEXITED | os.WNOHANG))
            parent.group.stop(time.monotonic() + 1, allowed_children={pid: child.generation})
            child.stop(time.monotonic() + 1, allowed_children={})
            assert state(parent.popen.pid) == state(pid) == 'T'
            parent.group.resume(time.monotonic() + 1)
            child.resume(time.monotonic() + 1)
            release.touch()
            assert parent.wait(time.monotonic() + 2) == 0
            assert waited.read_text() == '7', 'observer lost its ordinary child wait status'
            owner.close()
            assert not owner.reaped_orphans and all(group.closed for group in owner.groups)
            for fd in test_handles:
                gone(fd)
        finally:
            # Independently retained handles protect the failure-first probe.
            for fd in test_handles:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            release.touch()
            if parent is not None and not parent.settled:
                parent.wait(time.monotonic() + 2)
            if owner.active:
                owner.close()
            for fd in test_handles:
                os.close(fd)


def retained_child_refusal(kind, outside):
    with tempfile.TemporaryDirectory() as directory:
        ready, release, wait_gate, waited = [Path(directory) / name for name in ('ready', 'release', 'wait', 'waited')]
        count = 2 if kind == 'extra' else 1
        code = f"""
pids = []
for _ in range({count}):
    pid = os.fork()
    if pid == 0:
        while not os.path.exists({str(release)!r}):
            time.sleep(.005)
        os._exit(7)
    pids.append(pid)
open({str(ready)!r}, 'w').write(' '.join(map(str, pids)))
while not os.path.exists({str(wait_gate)!r}):
    time.sleep(.005)
statuses = [os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) for pid in pids]
open({str(waited)!r}, 'w').write(str(statuses))
os._exit(0 if statuses == [7] * {count} else 19)
"""
        owner, parent, test_handles = c.Custody(), None, []
        owner.__enter__()
        try:
            parent = launch(owner, '\n' + code)
            test_handles.append(os.dup(parent.group.fd))
            until(lambda: ready.exists() and ready.read_text())
            pids = list(map(int, ready.read_text().split()))
            test_handles.extend(os.pidfd_open(pid) for pid in pids)
            pid, gen = pids[0], identity(pids[0])
            deadline = time.monotonic() + 2
            if kind == 'outside':
                raises(c.CustodyError, lambda: owner.retain_observer_child(parent, outside, identity(outside), deadline))
            elif kind == 'stale':
                raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen + 1, deadline))
                for bad_pid, bad_gen in ((True, gen), (pid, True), (0, gen), (pid, 0)):
                    raises(c.CustodyError, lambda: owner.retain_observer_child(parent, bad_pid, bad_gen, deadline))
            elif kind == 'extra':
                raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
            elif kind == 'foreign_observer':
                raises(c.CustodyError, lambda: owner.retain_observer_child(c.OwnedProcess(c.Custody()), pid, gen, deadline))
                raises(c.CustodyError, lambda: owner.retain_observer_child(c.OwnedProcess(owner), pid, gen, deadline))
                with patch.object(parent, 'settled', True):
                    raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
            elif kind == 'duplicate':
                owner.retain_observer_child(parent, pid, gen, deadline)
                raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
            elif kind == 'dead':
                release.touch()
                until(lambda: state(pid) == 'Z')
                raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
                assert state(pid) == 'Z', 'observer child wait was consumed'
            elif kind in ('unavailable', 'post_pin_census'):
                census, calls = parent.group.children, []
                def unavailable(*args, **kwargs):
                    calls.append(True)
                    if kind == 'unavailable' or len(calls) == 2:
                        raise PermissionError('child census unavailable')
                    return census(*args, **kwargs)
                with patch.object(parent.group, 'children', side_effect=unavailable):
                    raises(PermissionError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
                if kind == 'post_pin_census':
                    group = next(group for group in owner.groups if group.pid == pid)
                    os.fstat(group.fd)
            elif kind == 'parent_death':
                pin = owner._pin
                def lost_parent(*args, **kwargs):
                    group = pin(*args, **kwargs)
                    signal.pidfd_send_signal(parent.group.fd, signal.SIGKILL)
                    assert select.select([parent.group.fd], [], [], 1)[0]
                    return group
                with patch.object(owner, '_pin', side_effect=lost_parent):
                    raises(c.CustodyError, lambda: owner.retain_observer_child(parent, pid, gen, deadline))
                assert parent.wait(time.monotonic() + 1) == -signal.SIGKILL
                error = raises(c.CleanupError, owner.close)
                assert 'unexpected adopted children' in str(error)
                assert {row[0] for row in owner.reaped_orphans} == set(pids)
            else:
                raise AssertionError(kind)
            if kind != 'parent_death':
                release.touch()
                wait_gate.touch()
                assert parent.wait(time.monotonic() + 2) == 0
                assert waited.read_text() == str([7] * count)
                owner.close()
                assert not owner.reaped_orphans
            assert all(group.closed for group in owner.groups)
            for fd in test_handles:
                gone(fd)
        finally:
            for fd in test_handles:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            release.touch()
            wait_gate.touch()
            if parent is not None and not parent.settled:
                parent.wait(time.monotonic() + 2)
            if owner.active:
                try:
                    owner.close()
                except c.CleanupError:
                    if kind != 'parent_death':
                        raise
            for fd in test_handles:
                os.close(fd)


class ProcessCustodyTests(unittest.TestCase):
    def probe(self, name):
        old_subreaper = c._subreaper()
        c._subreaper(1)
        script = 'import time; time.sleep(30)'
        tracer = 'import ctypes,os,signal,time; assert ctypes.CDLL(None).ptrace(0,0,0,0)==0; os.kill(os.getpid(), signal.SIGSTOP); time.sleep(30)'
        children = [subprocess.Popen([sys.executable, '-c', script]), subprocess.Popen([sys.executable, '-c', tracer if name == 'traced_refusal' else script])]
        handles = [os.pidfd_open(child.pid) for child in children]
        try:
            if name == 'traced_refusal':
                until(lambda: state(children[1].pid) == 't')
            result = subprocess.run(['timeout', '--kill-after=1s', '8s', sys.executable, '-I', __file__, '--probe', name, *[str(p.pid) for p in children]], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(select.select(handles, [], [], 0)[0], 'an outside child was killed')
            # Orphans escaping a probe are adopted by this watchdog owner. Their
            # presence fails the test; teardown still pins/kills/reaps them.
            self.assertEqual(c._children(os.getpid(), [os.getpid()], time.monotonic() + 1), sorted(p.pid for p in children))
        finally:
            for child, fd in zip(children, handles):
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=2)
                os.close(fd)
            end = time.monotonic() + 2
            while time.monotonic() < end:
                pids = c._children(os.getpid(), [os.getpid()], end)
                if not pids:
                    break
                wave = [(pid, os.pidfd_open(pid)) for pid in pids]
                try:
                    for _, fd in wave:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    for pid, fd in wave:
                        assert select.select([fd], [], [], max(0, end - time.monotonic()))[0]
                        assert os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG).si_pid == pid
                finally:
                    for _, fd in wave:
                        os.close(fd)
            c._subreaper(old_subreaper)

    def test_retained_observer_child_keeps_its_observers_ordinary_wait(self): self.probe('retained_observer_child_wait')
    def test_stop_refusal_resumes_only_successful_stop(self): self.probe('first_red')
    def test_direct_term_and_policy_restoration(self): self.probe('direct_term')
    def test_complete_thread_roster_and_read_failure(self): self.probe('complete_threads')
    def test_identity_and_dead_refusals(self): self.probe('identity_refusals')
    def test_live_identity_checks_preserve_deadline_generation_and_exit_guards(self): self.probe('live_identity_refusals')
    def test_independent_prestop_is_not_resumed(self): self.probe('prestop_refusal')
    def test_real_tracer_stop_refused(self): self.probe('traced_refusal')
    def test_partial_stop_timeout_still_resumes(self): self.probe('partial_timeout')
    def test_every_resume_attempted_after_error_and_expiry(self): self.probe('resume_attempts')
    def test_actual_signals_at_stop_ledger_and_cleanup(self): self.probe('cancellation_boundaries')
    def test_dedicated_owner_policy_refusals(self): self.probe('policy_refusals')
    def test_child_intended_mask_restored(self): self.probe('child_mask_restoration')
    def test_post_reap_interruption_never_signals_numeric_pid(self): self.probe('post_reap_interruption')
    def test_pin_refusal_uses_only_proven_direct_child(self): self.probe('pin_refusal')
    def test_living_observer_retains_child_wait(self): self.probe('living_observer_wait')
    def test_unknown_pre_ready_child_is_reaped(self): self.probe('pre_ready_orphan')
    def test_adopted_zombie_is_reaped(self): self.probe('adopted_zombie')
    def test_second_orphan_generation_is_reaped(self): self.probe('second_generation')
    def test_orphan_acquisition_failure_still_drains_other_child(self): self.probe('orphan_pin_failure')
    def test_orphan_deadline_is_nonpass_then_cleanup_drains(self): self.probe('orphan_deadline')
    def test_wait_ownership_and_spawn_seal(self): self.probe('ownership_guards')
    def test_child_census_includes_nonleader_threads(self): self.probe('worker_child_census')
    def test_real_clone_changes_expected_roster(self): self.probe('real_roster_change')
    def test_cleanup_close_failure_and_signal_preserve_all_actions(self): self.probe('cleanup_failures')
    def test_native_no_child_wait_policy_refused(self): self.probe('native_sigchld_refusal')
    def test_python_ignored_int_refused_before_mutation(self): self.probe('python_ignored_int')
    def test_python_ignored_term_refused_before_mutation(self): self.probe('python_ignored_term')
    def test_native_only_ignored_int_refused_before_mutation(self): self.probe('native_ignored_int')
    def test_native_only_ignored_term_refused_before_mutation(self): self.probe('native_ignored_term')
    def test_direct_wait_is_bounded_and_failure_reaped(self): self.probe('bounded_direct_wait')
    def test_direct_owned_observer_resumed_and_reaped_after_refusal(self): self.probe('owned_stop_refusal')


for kind in ('outside', 'stale', 'extra', 'unavailable', 'duplicate', 'dead',
             'post_pin_census', 'foreign_observer', 'parent_death'):
    name = 'retained_child_' + kind
    def probe_case(observer, workload, kind=kind):
        retained_child_refusal(kind, workload)
    globals()[name] = probe_case
    def test(self, name=name):
        self.probe(name)
    setattr(ProcessCustodyTests, 'test_' + name, test)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--probe':
        globals()[sys.argv[2]](*map(int, sys.argv[3:]))
    else:
        unittest.main()
