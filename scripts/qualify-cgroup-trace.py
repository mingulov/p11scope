#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded installed trace cells; run only with the separately granted live lane.

No controllers, existing cgroups, namespaces, sysctls or containers are changed.
Resource samples on the shared build host are exploratory, not performance gates.
"""

import argparse
from contextlib import contextmanager, nullcontext
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import runpy
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
CGROUP2_MAGIC = 0x63677270
CELLS = ('stable', 'onecall', 'burst', 'migrate', 'exec', 'run')
CANARIES = ('N3_PRIVATE_BUFFER_91b947', 'N3_PRIVATE_ENV_a279d2', 'N3_PRIVATE_ARG_248abc')
REMAINING = ('sparse calls at 1s, 10s, 59s and >60s', 'short-lived caller',
             'unchanged leave while the allowed identity sample actually runs, then reenter',
             'same-path exec', 'nonleader exec', 'PID reuse', 'PID/time/mount namespaces and domains',
             'event/discovery loss', 'entry/path/interest capacity and fairness',
             'long resource/read plateau and isolated-host performance qualification')


class TerminationRequested(BaseException):
    def __init__(self, signum):
        self.signum = signum


_active_signals = None


class TerminationGuard:
    def __init__(self):
        self.pending, self.raised, self.depth = None, False, 0
        self.previous = {}

    def deliver(self):
        if self.pending is not None and not self.raised and self.depth == 0:
            self.raised = True
            raise TerminationRequested(self.pending)

    def handle(self, signum, _frame):
        if self.pending is None:
            self.pending = signum
        # Once unwinding starts, another TERM/INT cannot abort cleanup.
        self.deliver()

    @contextmanager
    def defer(self):
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1
            self.deliver()


@contextmanager
def signal_cleanup():
    global _active_signals
    guard, previous_guard = TerminationGuard(), _active_signals
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            guard.previous[signum] = signal.signal(signum, guard.handle)
        _active_signals = guard
        yield
    finally:
        _active_signals = previous_guard
        for signum, previous_handler in guard.previous.items():
            signal.signal(signum, previous_handler)


def cleanup_section():
    return _active_signals.defer() if _active_signals else nullcontext()


class DirectChild:
    """Only the actual direct Popen fork, before richer validation succeeds.

    This child remains unreaped, so its PID cannot identify a replacement.
    No arbitrary PID or independently supplied descendant gets this fallback.
    """
    def __init__(self, popen):
        self.popen, self.pid = popen, popen.pid

    def send(self, signum):
        self.popen.send_signal(signum)

    def close(self):
        for stream in (self.popen.stdin, self.popen.stdout, self.popen.stderr):
            if stream is not None:
                stream.close()


def spawn_owned(owners, argv, uid, **options):
    with cleanup_section():
        proc = subprocess.Popen(argv, **options)
        pending = DirectChild(proc)
        owners.append(pending)  # before proc reads, pidfd open or validation
        owner = OwnedProcess(proc.pid, os.getpid(), uid, proc)
        owners[owners.index(pending)] = owner
    return owner


class CreatedDirectory:
    """Enroll mkdir before attempting the higher-level Cgroup acquisition."""
    def __init__(self, path):
        self.path, self.created, self.identity, self.group = path, False, None, None
        self.parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.parent_fd)
            self.parent_identity = info.st_dev, info.st_ino
            self.verify_parent()
        except BaseException:
            os.close(self.parent_fd)
            raise

    def verify_parent(self):
        held = os.fstat(self.parent_fd)
        current = self.path.parent.stat(follow_symlinks=False)
        assert_directory_identity(self.parent_identity, (held.st_dev, held.st_ino), fs_magic(self.parent_fd))
        assert_directory_identity(self.parent_identity, (current.st_dev, current.st_ino), fs_magic(self.parent_fd))
        if not stat.S_ISDIR(current.st_mode):
            raise ValueError('created cgroup parent was replaced')

    def create(self):
        os.mkdir(self.path.name, 0o755, dir_fd=self.parent_fd)
        self.created = True
        info = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('new cgroup directory was replaced before enrollment')
        self.identity = info.st_dev, info.st_ino

    def remove(self):
        try:
            if not self.created:
                return  # mkdir failed; never remove an existing directory
            self.verify_parent()
            current = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if self.identity is None or not stat.S_ISDIR(current.st_mode):
                raise ValueError('created cgroup has no verifiable original directory identity')
            assert_directory_identity(self.identity, (current.st_dev, current.st_ino), fs_magic(self.parent_fd))
            if self.group is not None:
                self.group.verify()
                if self.group.members():
                    raise ValueError('refusing to remove a populated owned cgroup')
            # For failed acquisition the kernel rmdir emptiness check also
            # refuses live tasks/children; no cgroup.kill or foreign cleanup.
            os.rmdir(self.path.name, dir_fd=self.parent_fd)
        finally:
            if self.group is not None:
                self.group.close()
            os.close(self.parent_fd)


def create_cgroup(path, groups):
    with cleanup_section():
        pending = CreatedDirectory(path)
        groups.append(pending)  # includes failed mkdir, before higher-level open
        pending.create()
        group = Cgroup(path)
        pending.group = group
        if group.identity != pending.identity:
            raise ValueError('opened cgroup differs from the actual created directory')
    return group


def cleanup_processes(owners):
    with cleanup_section():
        errors = []
        for owner in owners:
            try:
                terminate(owner)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                errors.append(error)
            finally:
                owner.close()
        if errors:
            raise ExceptionGroup('owned process cleanup failed', errors)


def cleanup_cgroups(groups):
    with cleanup_section():
        errors = []
        for group in reversed(groups):
            try:
                group.remove()
            except (OSError, ValueError) as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup('owned cgroup cleanup failed', errors)


def assert_process_identity(expected, actual):
    fields = ('pid', 'ppid', 'start_time', 'uid', 'pid_namespace', 'time_namespace')
    if any(expected.get(field) != actual.get(field) for field in fields):
        raise ValueError('process is not the original owned child/birth/parent/namespace')
    if any(expected[field] <= 0 for field in ('pid', 'ppid', 'start_time', 'pid_namespace', 'time_namespace')):
        raise ValueError('missing process birth or namespace identity')
    return True


def assert_directory_identity(expected, actual, magic):
    if expected != actual or magic != CGROUP2_MAGIC:
        raise ValueError('directory is not the held owned cgroup2 directory')
    return True


def process_identity(pid):
    proc = Path('/proc') / str(pid)
    text = (proc / 'stat').read_text()
    fields = text[text.rindex(')') + 2:].split()
    return dict(pid=pid, ppid=int(fields[1]), start_time=int(fields[19]),
                uid=proc.stat().st_uid, pid_namespace=(proc / 'ns/pid').stat().st_ino,
                time_namespace=(proc / 'ns/time').stat().st_ino)


def cgroup_of(pid):
    rows = [line[3:] for line in (Path('/proc') / str(pid) / 'cgroup').read_text().splitlines()
            if line.startswith('0::')]
    if len(rows) != 1:
        raise ValueError('missing unified cgroup membership')
    return rows[0]


def fs_magic(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fstatfs.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(256)  # larger than Linux x86-64 struct statfs
    if libc.fstatfs(fd, buffer):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long))[0]


class Cgroup:
    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        self.identity = info.st_dev, info.st_ino
        try:
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        held, current = os.fstat(self.fd), self.path.stat(follow_symlinks=False)
        assert_directory_identity(self.identity, (held.st_dev, held.st_ino), fs_magic(self.fd))
        assert_directory_identity(self.identity, (current.st_dev, current.st_ino), fs_magic(self.fd))
        if not stat.S_ISDIR(current.st_mode):
            raise ValueError('owned cgroup path was replaced')

    def move(self, process):
        process.verify()
        self.verify()
        fd = os.open('cgroup.procs', os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            os.write(fd, f'{process.pid}\n'.encode())
        finally:
            os.close(fd)
        process.verify()
        expected = '/' + str(self.path.relative_to('/sys/fs/cgroup'))
        if cgroup_of(process.pid) != expected:
            raise ValueError('owned caller migration did not reach the requested cgroup')

    def members(self):
        self.verify()
        fd = os.open('cgroup.procs', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            data = os.read(fd, 65536)
            if len(data) == 65536:
                raise ValueError('unexpected owned cgroup population')
            return [int(pid) for pid in data.split()]
        finally:
            os.close(fd)

    def remove(self):
        self.verify()
        fd = os.open('cgroup.procs', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            if os.read(fd, 65536).strip():
                raise ValueError('refusing to remove a populated owned cgroup')
        finally:
            os.close(fd)
        os.rmdir(self.path)
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class OwnedProcess:
    def __init__(self, pid, parent, uid, popen=None):
        self.pid, self.popen = pid, popen
        self.pidfd = None
        try:
            self.identity = process_identity(pid)
            if self.identity['ppid'] != parent or self.identity['uid'] != uid:
                raise ValueError('not a child of the expected owned parent/uid')
            self.pidfd = os.pidfd_open(pid)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        assert_process_identity(self.identity, process_identity(self.pid))

    def send(self, sig):
        self.verify()
        signal.pidfd_send_signal(self.pidfd, sig)

    def wait_exit(self, seconds):
        poll = select.poll()
        poll.register(self.pidfd, select.POLLIN)
        events = poll.poll(int(seconds * 1000))
        if any(mask & (select.POLLERR | select.POLLNVAL) for _, mask in events):
            raise OSError('held owned pidfd exit poll failed')
        return any(mask & (select.POLLIN | select.POLLHUP) for _, mask in events)

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


class FilePin:
    def __init__(self, path):
        self.path = path.resolve(strict=True)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            self.initial = os.fstat(self.fd)
            if not stat.S_ISREG(self.initial.st_mode):
                raise ValueError('expected a regular executable/provider')
            self.digest = self.hash()
        except BaseException:
            os.close(self.fd)
            raise

    def hash(self):
        digest, offset = hashlib.sha256(), 0
        while chunk := os.pread(self.fd, 1024 * 1024, offset):
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()

    def verify(self):
        before, current = self.initial, os.fstat(self.fd)
        if any(getattr(before, field) != getattr(current, field) for field in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) or self.hash() != self.digest:
            raise ValueError('held file changed')

    def image_receipt(self, row, owner):
        owner.verify()
        path = Path('/proc') / str(owner.pid) / 'exe'
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            actual, held = os.fstat(fd), os.fstat(self.fd)
            if (actual.st_dev, actual.st_ino, actual.st_mtime_ns) != (held.st_dev, held.st_ino, held.st_mtime_ns):
                raise ValueError('actual owned process executable differs from the held expected file')
            result = dict(kind='image', image=row['image'], pid=owner.pid,
                          start_time=owner.identity['start_time'], path=os.readlink(path),
                          dev=actual.st_dev, ino=actual.st_ino, mtime_ns=actual.st_mtime_ns,
                          pid_namespace=owner.identity['pid_namespace'],
                          time_namespace=owner.identity['time_namespace'])
        finally:
            os.close(fd)
        if result['path'] != str(self.path):
            raise ValueError('actual executable path differs from the owned expected path')
        owner.verify()
        return result

    def metadata(self):
        info = self.initial
        return dict(path=str(self.path), dev=info.st_dev, ino=info.st_ino,
                    size=info.st_size, mtime_ns=info.st_mtime_ns, sha256=self.digest)

    def close(self):
        os.close(self.fd)


class Reader:
    def __init__(self, stream, path):
        self.stream, self.path = stream, path
        self.lines, self.records, self.errors = [], [], []
        self.updates = queue.Queue()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        total = 0
        with self.path.open('w', encoding='utf-8') as output:
            try:
                for line in self.stream:
                    total += len(line.encode())
                    if total > 8 * 1024 * 1024 or len(line) > 65536:
                        if not self.errors:
                            self.errors.append('owned output exceeds bounded fixture limit')
                        continue
                    self.lines.append(line)
                    output.write(line)
                    output.flush()
                    if line.startswith('N3LEDGER '):
                        self.records.append(json.loads(line[9:]))
                    self.updates.put(None)
            except (ValueError, UnicodeError, OSError) as error:
                self.errors.append(str(error))
            finally:
                self.updates.put(None)

    def wait(self, predicate, seconds=10):
        deadline = time.monotonic() + seconds
        while True:
            if self.errors:
                raise ValueError('; '.join(self.errors))
            result = predicate(self)
            if result:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.thread.is_alive():
                raise TimeoutError('owned fixture/capture readiness acknowledgement missing')
            try:
                self.updates.get(timeout=min(remaining, 0.2))
            except queue.Empty:
                pass

    def record(self, kind, image=0, phase=None):
        return self.wait(lambda reader: next((row for row in reader.records
            if row.get('kind') == kind and row.get('image') == image
            and (phase is None or row.get('phase') == phase)), None))

    def finish(self):
        self.thread.join(timeout=3)
        if self.thread.is_alive() or self.errors:
            raise ValueError('owned output did not finish cleanly: ' + '; '.join(self.errors))
        return ''.join(self.lines)


def wait_capture_started(errors, allow_empty=False, seconds=10):
    count = r'(?:0|[1-9]\d*)' if allow_empty else r'[1-9]\d*'
    return errors.wait(lambda reader: any(re.fullmatch(
        rf'p11scope: capturing: {count} probe\(s\) attached; stop with Ctrl-C\n?', line)
        for line in reader.lines), seconds)


def wait_run_provider_ready(capture, image, provider, seconds=10):
    row_pattern = runpy.run_path(str(ROOT / 'scripts/cgroup-trace-oracle.py'))['ROW']
    def attached_setup(reader):
        key = image['image'], 'C_OpenSession'
        ready = [row for row in reader.records
                 if row.get('kind') == 'ready' and row.get('image') == key[0]]
        calls = [row for row in reader.records if row.get('kind') == 'call'
                 and (row.get('image'), row.get('fn'), row.get('phase')) == (*key, 'setup')]
        targets = [row for row in reader.records if row.get('kind') == 'target'
                   and (row.get('image'), row.get('fn')) == key]
        if not ready or not calls or not targets:
            return None
        if len(ready) != 1 or len(calls) != 1 or len(targets) != 1:
            raise ValueError('run setup readiness requires one authentic setup completion')
        call, target = calls[0], targets[0]
        if (call.get('pid') != image['pid'] or call.get('tid') != image['pid']
                or call.get('rv') != 0 or call.get('scope') != 'selected'
                or not 0 <= call['t0'] <= call['t1'] <= ready[0]['t']):
            raise ValueError('run setup readiness disagrees with owned caller identity/interval')
        if (target.get('dev') != provider['dev'] or target.get('ino') != provider['ino']
                or not isinstance(target.get('file_offset'), int) or target['file_offset'] < 0):
            raise ValueError('run setup readiness lacks the independently held provider target')
        for line in reader.lines:
            match = row_pattern.fullmatch(line.rstrip('\n'))
            if match and (int(match['pid']), int(match['tid']), match['fn'], match['rv']) == (
                    call['pid'], call['tid'], call['fn'], 'CKR_OK'):
                return call
        return None
    return capture.wait(attached_setup, seconds)


class Resources:
    def __init__(self, owner):
        self.owner, self.samples, self.stop_event = owner, [], threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)
        self.thread.start()

    def _sample(self):
        while not self.stop_event.is_set():
            try:
                self.owner.verify()
                proc = Path('/proc') / str(self.owner.pid)
                fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                rss = next(line.split()[1] for line in (proc / 'status').read_text().splitlines()
                           if line.startswith('VmRSS:'))
                reads = next(line.split()[1] for line in (proc / 'io').read_text().splitlines()
                             if line.startswith('syscr:'))
                self.samples.append(dict(t=time.monotonic_ns(), cpu_ticks=int(fields[11]) + int(fields[12]),
                    rss_kib=int(rss), fds=len(list((proc / 'fd').iterdir())), read_syscalls=int(reads)))
            except (OSError, ValueError, StopIteration):
                break  # owned process ended; no PID-selected replacement reads
            self.stop_event.wait(0.2)

    def finish(self):
        self.stop_event.set()
        self.thread.join(timeout=1)
        return dict(qualification='exploratory_shared_build_host', sample_period_seconds=0.2,
                    clock_ticks_per_second=os.sysconf('SC_CLK_TCK'), samples=self.samples,
                    limitation='aggregate /proc/io reads; not identity-reader counts or a capacity plateau')


def command(caller, reader, fn, count, delay, phase, scope, image=0, group=None, phases=None):
    caller.verify()
    expected_group = None
    if group is not None:
        group.verify()
        expected_group = '/' + str(group.path.relative_to('/sys/fs/cgroup'))
        if cgroup_of(caller.pid) != expected_group:
            raise ValueError('workload phase starts outside its independently expected membership')
    begin = time.monotonic_ns()
    caller.popen.stdin.write(f'calls {fn} {count} {delay} {phase} {scope}\n')
    caller.popen.stdin.flush()
    acknowledgement = reader.record('ack', image, phase)
    finish = time.monotonic_ns()
    caller.verify()
    if expected_group is not None and cgroup_of(caller.pid) != expected_group:
        raise ValueError('workload membership changed during a controlled phase')
    if phases is not None:
        phases.append(dict(image=image, fn=fn, count=count, phase=phase, scope=scope,
                           t0=begin, t1=finish, actual_cgroup=expected_group))
    return acknowledgement


def terminate(owner):
    if owner.popen is not None and owner.popen.poll() is not None:
        return
    try:
        owner.send(signal.SIGTERM)
        if owner.popen is not None:
            try:
                owner.popen.wait(timeout=2)
            except subprocess.TimeoutExpired:
                owner.send(signal.SIGKILL)
                owner.popen.wait(timeout=3)
        elif not owner.wait_exit(2):
            # run owns/reaps this child. We retain only the verified pidfd,
            # so confirm exit without waiting on somebody else's child.
            # Keep its original observer parent alive through escalation.
            owner.send(signal.SIGKILL)
            if not owner.wait_exit(3):
                raise TimeoutError('owned run child did not exit after bounded SIGKILL')
    except (ProcessLookupError, FileNotFoundError):
        pass


def initialize_tokens(directory, uid, gid):
    tokens = directory / 'tokens'
    tokens.mkdir(mode=0o700)
    os.chown(directory, uid, gid)
    os.chown(tokens, uid, gid)
    config = directory / 'softhsm2.conf'
    config.write_text(f'directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n')
    config.chmod(0o644)
    env = dict(os.environ, SOFTHSM2_CONF=str(config), N3_PRIVATE_ENV=CANARIES[1])
    result = subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', 'n3-owned',
                             '--so-pin', '5678', '--pin', '1234'], env=env, user=uid, group=gid,
                            extra_groups=[], text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError('owned SoftHSM token initialization failed: ' + result.stderr)
    return env


def run_cell(args, name, directory, env, provider, binary, callers, cgroups, scope_created_ns):
    selected, outside = cgroups
    owners, readers, images, sampler = [], [], [], None
    observer = caller = None
    receipt = dict(cell=name, require_named=name in ('stable', 'migrate', 'exec', 'run'),
                   fresh_observer=True, scope_created_ns=scope_created_ns,
                   pid_namespace=process_identity(os.getpid())['pid_namespace'],
                   time_namespace=process_identity(os.getpid())['time_namespace'],
                   privacy_canaries=list(CANARIES), images=images, stop_limit_seconds=5)
    if name in ('stable', 'migrate', 'run'):
        receipt['require_named_images'] = [0]
    elif name == 'exec':
        receipt['require_named_images'] = [0, 1]
    phases = []
    if name != 'run':
        receipt['phases'] = phases
    def workload(fn, count, delay, phase, scope, image=0):
        return command(caller, stdout, fn, count, delay, phase, scope, image,
                       selected if scope == 'selected' else outside, phases)
    pin_fd = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['pin_fd']
    receipt['provider_before'] = pin_fd(provider.fd)
    try:
        trace_path = directory / 'trace.file.txt'
        if name != 'run':
            caller = spawn_owned(owners, [str(callers[0].path), str(provider.path), '0', 'selected',
                                     '--canary', CANARIES[2]], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env=env, uid=args.uid, user=args.uid, group=args.gid,
                                    extra_groups=[], start_new_session=True)
            proc = caller.popen
            stdout = Reader(proc.stdout, directory / 'caller.ledger.jsonl')
            stderr = Reader(proc.stderr, directory / 'caller.stderr.txt')
            readers.extend((stdout, stderr))
            stdout.record('ready')
            image = stdout.record('image')
            images.append(callers[0].image_receipt(image, caller))
            selected.move(caller)
            receipt['selected_initial_pids'] = selected.members()
            if receipt['selected_initial_pids'] != [caller.pid]:
                raise ValueError('selected cgroup contains a process other than the owned caller')
            argv = [str(binary.path), 'trace', '--cgroup', str(selected.path), '--module', str(provider.path),
                    '--duration', '20s', '-o', str(trace_path)]
        else:
            gate = directory / 'run-gate'
            argv = [str(binary.path), 'run', '--trace', '--module', str(provider.path), '--pause', 'auto',
                    '--duration', '20s', '-o', str(trace_path), '--', str(callers[0].path),
                    str(provider.path), '0', 'selected', '--auto-gate', str(gate), '--canary', CANARIES[2]]
        receipt['observer_started_ns'] = time.monotonic_ns()
        observer = spawn_owned(owners, argv, uid=0, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, start_new_session=True)
        proc = observer.popen
        binary.image_receipt(dict(image=0), observer)
        capture = Reader(proc.stdout, directory / 'trace.stdout.txt')
        errors = Reader(proc.stderr, directory / 'observer.stderr.txt')
        readers.extend((capture, errors))
        sampler = Resources(observer)
        wait_capture_started(errors, allow_empty=name == 'run')
        receipt['observer_ready_ns'] = time.monotonic_ns()
        if name == 'run':
            capture.record('ready')
            image = capture.record('image')
            with cleanup_section():
                caller = OwnedProcess(image['pid'], observer.pid, args.uid)
                owners.insert(0, caller)
            images.append(callers[0].image_receipt(image, caller))
            wait_run_provider_ready(capture, images[0], receipt['provider_before'])
            # Setup remains explicitly ledgered before this gate-release
            # readiness; every later main/teardown call stays mandatory.
            receipt['observer_ready_ns'] = time.monotonic_ns()
            gate.touch(mode=0o644)
            done = capture.record('ack', 0, 'done')
            stop_started = time.monotonic_ns()
            receipt['stop_kind'] = 'child_exit'
            receipt['caller_rc_source'] = 'run exit status and final fixture acknowledgement'
            receipt['fixture_done_ns'] = done['t']
            receipt['observer_rc'] = proc.wait(timeout=5)
            receipt['caller_rc'] = receipt['observer_rc']
            ledger_reader = capture
        else:
            if name == 'stable':
                workload('C_GenerateRandom', 20, 200, 'main', 'selected')
            elif name == 'onecall':
                workload('C_GenerateRandom', 1, 0, 'main', 'selected')
            elif name == 'burst':
                workload('C_GenerateRandom', 256, 0, 'main', 'selected')
            else:
                workload('C_GenerateRandom', 20, 200, 'a', 'selected')
                outside.move(caller)
                workload('C_GetInfo', 3, 50, 'outside-a', 'outside')
                image_id = 0
                if name == 'exec':
                    caller.popen.stdin.write(f'exec {callers[1].path}\n')
                    caller.popen.stdin.flush()
                    stdout.record('ready', 1)
                    image = stdout.record('image', 1)
                    images.append(callers[1].image_receipt(image, caller))
                    image_id = 1
                    workload('C_GetInfo', 3, 50, 'outside-b', 'outside', 1)
                selected.move(caller)
                workload('C_GetSessionInfo' if name == 'exec' else 'C_GenerateRandom',
                         20, 200, 'reenter', 'selected', image_id)
            stop_started = time.monotonic_ns()
            receipt['stop_kind'] = 'SIGINT'
            observer.send(signal.SIGINT)
            receipt['observer_rc'] = proc.wait(timeout=5)
            receipt['observer_stopped_ns'] = time.monotonic_ns()
            outside.move(caller)
            caller.popen.stdin.write('stop\n')
            caller.popen.stdin.flush()
            stdout.record('ack', 1 if name == 'exec' else 0, 'done')
            receipt['caller_rc'] = caller.popen.wait(timeout=3)
            ledger_reader = stdout
        if 'observer_stopped_ns' not in receipt:
            receipt['observer_stopped_ns'] = time.monotonic_ns()
        # Measure observer stop only; workload teardown/cleanup is separate.
        receipt['stop_latency_seconds'] = (receipt['observer_stopped_ns'] - stop_started) / 1e9
        receipt['resources'] = sampler.finish()
        sampler = None
        receipt['provider_after'] = pin_fd(provider.fd)
        binary.verify()
        for pin in callers:
            pin.verify()
        for reader in readers:
            reader.finish()
        trace = ''.join(capture.lines)
        receipt['observer_stderr'] = ''.join(errors.lines)
        ledger = ledger_reader.records
        (directory / 'ledger.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in ledger))
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        oracle = runpy.run_path(str(ROOT / 'scripts/cgroup-trace-oracle.py'))['evaluate']
        result = oracle(trace, ledger, receipt, trace_path.read_text())
        (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        with cleanup_section():
            if sampler:
                sampler.finish()
            try:
                # Caller first, before losing its independently expected parent.
                cleanup_processes(owners)
            finally:
                for reader in readers:
                    reader.thread.join(timeout=1)


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--provider', type=Path, required=True)
    parser.add_argument('--caller', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    parser.add_argument('--cells', default=','.join(CELLS))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    names = args.cells.split(',')
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error('live harness requires root observer and an ordinary workload uid/gid')
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_revision) or any(name not in CELLS for name in names):
        parser.error('supply the exact source commit and supported bounded cells')
    if not args.out.is_absolute() or any(not path.is_absolute() for path in
                                        (args.binary, args.provider, args.caller)):
        parser.error('all input/output paths must be absolute')
    args.out.mkdir(mode=0o755)  # new-only; refuse accidental reuse
    workload = args.out / 'workload'
    workload.mkdir(mode=0o755)
    groups, pins, results = [], [], []
    owned_root = Path('/sys/fs/cgroup') / ('p11scope-n3-' + uuid.uuid4().hex)
    try:
        env = initialize_tokens(workload, args.uid, args.gid)
        # run's public contract drops its owned child to these ordinary
        # invocation credentials; never run the provider workload as root.
        env['SUDO_UID'], env['SUDO_GID'] = str(args.uid), str(args.gid)
        with cleanup_section():
            binary = FilePin(args.binary)
            pins.append(binary)
            provider = FilePin(args.provider)
            pins.append(provider)
        callers = []
        for name in ('trace-a', 'trace-b'):
            path = args.out / name
            shutil.copyfile(args.caller, path)
            path.chmod(0o755)
            with cleanup_section():
                pin = FilePin(path)
                pins.append(pin)
            callers.append(pin)
        # Only mkdir under the unified root; no controllers are enabled.
        create_cgroup(owned_root, groups)
        cgroups = []
        for name in ('selected', 'outside'):
            path = owned_root / name
            cgroups.append(create_cgroup(path, groups))
        created = time.monotonic_ns()
        if cgroup_of(os.getpid()).startswith('/' + owned_root.name):
            raise ValueError('controller unexpectedly belongs to the selected scope')
        for name in names:
            directory = args.out / name
            directory.mkdir(mode=0o755)
            result = run_cell(args, name, directory, env, provider, binary, callers, cgroups, created)
            results.append(result)
            print(json.dumps({key: result.get(key) for key in
                              ('cell', 'pass', 'calls', 'named', 'unknown', 'false_names', 'errors')}), flush=True)
        summary = dict(source_revision=args.source_revision, candidate=binary.metadata(),
                       provider=provider.metadata(), abi='Linux x86-64 LP64', kernel=os.uname().release,
                       cells=results, remaining=list(REMAINING),
                       resource_qualification='exploratory shared loaded build host')
        (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0 if all(result['pass'] for result in results) else 1
    finally:
        with cleanup_section():
            try:
                cleanup_cgroups(groups)
            finally:
                for pin in reversed(pins):
                    pin.close()


def main():
    try:
        with signal_cleanup():
            return _main()
    except TerminationRequested as error:
        print(f'qualification interrupted by signal {error.signum}', file=sys.stderr)
        return 128 + error.signum


if __name__ == '__main__':
    sys.exit(main())
