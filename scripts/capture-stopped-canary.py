#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One retained, stopped acquisition for the closed canary lanes.

The shell owns external workload waits. Owned runs retain their child through
terminal collection, then this coordinator claims and reaps the exact handoff.
This coordinator owns its observer, BPF references and acquisition files. Controlled fixtures must
not exec or independently mutate STOP/CONT, task membership or output paths.
No Python result alone qualifies a live kernel, BPF build or target ABI.
"""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_sibling


custody = load_sibling('canary_process_custody.py')
dumper = load_sibling('dump-owned-bpf-maps.py')
evidence = load_sibling('check-canary-evidence.py')
definitions = load_sibling('check-bpf-map-defs.py')
LANES = {
    'default-safe-profile': ('default', 'profile', 'allowlisted', 'matrix'),
    'default-safe-trace': ('default', 'trace', 'allowlisted', 'matrix'),
    'feature-safe-profile': ('diagnostic', 'profile', 'allowlisted', 'matrix'),
    'feature-safe-trace': ('diagnostic', 'trace', 'allowlisted', 'matrix'),
    'feature-unsafe-profile': ('diagnostic', 'profile', 'unsafe-unvalidated-metadata', 'matrix'),
    'feature-unsafe-trace': ('diagnostic', 'trace', 'unsafe-unvalidated-metadata', 'matrix'),
    'aggregate-only-metrics': ('default', 'metrics', 'aggregate-only', 'matrix'),
    'default-safe-start': ('default', 'profile', 'allowlisted', 'blocked'),
    'feature-safe-start': ('diagnostic', 'profile', 'allowlisted', 'blocked'),
    'feature-unsafe-fault': ('diagnostic', 'profile', 'unsafe-unvalidated-metadata', 'faults'),
    'owned-default-metrics': ('default', 'metrics', 'aggregate-only', 'matrix'),
    'owned-feature-metrics': ('diagnostic', 'metrics', 'aggregate-only', 'matrix'),
}
OWNED_LANES = frozenset(('owned-default-metrics', 'owned-feature-metrics'))
OWNED_DURATION_SECONDS = 35
OWNED_CHILD_WAIT_SECONDS = 5
MAP_TYPES = {1: 'hash', 2: 'array', 3: 'prog_array', 5: 'percpu_hash',
             6: 'percpu_array', 8: 'cgroup_array', 27: 'ringbuf', 29: 'task_storage'}
STOP_SECONDS = 30
READY_SECONDS = 8
RESUME_SECONDS = 5
OBSERVER_WAIT_SECONDS = 20
PUBLICATION_SECONDS = 10
MAX_BYTES = dumper.TASK_STORAGE_MAX_BYTES
MAX_LOG_BYTES = 4 * 1024 * 1024
DIAGNOSTIC_SCRIPTS = {str(Path(__file__).resolve().parent / name): name for name in (
    'capture-stopped-canary.py', 'check-canary-evidence.py',
    'check-capture-evidence.py', 'canary_process_custody.py',
    'dump-owned-bpf-maps.py', 'qualify-task-storage-canary.py',
)}


class CaptureError(RuntimeError):
    """Only bounded coordinator-owned diagnostics, never legacy raw context."""
    def __init__(self, issues):
        self.issues = (issues,) if isinstance(issues, str) else tuple(issues)
        super().__init__('; '.join(self.issues))


def report_failure_locations(error):
    """Keep trusted code locations before sanitization discards traceback data."""
    locations, trace = [], error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        script = DIAGNOSTIC_SCRIPTS.get(trace.tb_frame.f_code.co_filename)
        location = (script, trace.tb_lineno)
        if script and 0 < trace.tb_lineno < 1000000 and location not in locations:
            locations.append(location)
        trace = trace.tb_next
    for script, line in locations[-8:]:
        try:
            print(f'canary-failure-location: {script}:{line}', file=sys.stderr)
        except (OSError, ValueError):
            # Optional diagnostics must not interrupt custody cleanup or
            # replace the failure already being retained by the caller.
            break


def sanitized(phase, error):
    issues, pending, seen = [], [error], set()
    while pending and len(issues) < 32:
        item = pending.pop(0)
        if id(item) in seen:
            continue
        seen.add(id(item))
        report_failure_locations(item)
        if isinstance(item, CaptureError):
            issues.extend(item.issues[:32 - len(issues)])
        else:
            # Do not use str(error): accepted legacy validators can attach raw
            # bytes, and subprocess failures can attach argv/stdout/stderr.
            if isinstance(item, custody.DeadlineExpired):
                kind = 'phase deadline expired'
            else:
                kind = type(item).__name__
                kind = kind if re.fullmatch(r'[A-Za-z0-9_]{1,64}', kind) else 'Error'
            issues.append(f'{phase}: {kind}')
            if isinstance(item, custody.CleanupError):
                pending.extend(item.errors)
            if item.__cause__ is not None:
                pending.append(item.__cause__)
    return issues


def require(condition, issue):
    if not condition:
        raise CaptureError(issue)


def remaining(deadline, maximum=None):
    value = deadline - time.monotonic()
    require(math.isfinite(value) and value > 0, 'phase deadline expired')
    return min(value, maximum) if maximum is not None else value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def read_bytes(path, bound, deadline):
    # O_NONBLOCK prevents a FIFO open from waiting for a peer before fstat can
    # reject it. Check the opened object, not pathname metadata; proc fdinfo
    # is regular but commonly reports st_size=0, so bound actual reads instead.
    remaining(deadline)
    raw, issues = bytearray(), []
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        remaining(deadline)
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'input is not a regular file')
        while True:
            remaining(deadline)
            chunk = os.read(fd, min(65536, bound + 1 - len(raw)))
            remaining(deadline)
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= bound, 'input byte bound exceeded')
    except BaseException as error:
        issues.extend(sanitized('read-input', error))
    finally:
        try:
            # Linux close errors must not trigger a retry on a possibly reused
            # descriptor. Keep an independent close failure visible as well.
            os.close(fd)
        except BaseException as error:
            issues.extend(sanitized('close-input', error))
    if issues:
        raise CaptureError(issues) from None
    result = bytes(raw)
    remaining(deadline)
    return result


def read_json(path, bound=65536, *, deadline):
    value = json.loads(read_bytes(path, bound, deadline), object_pairs_hook=unique_object)
    remaining(deadline)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def validate_owned_argv(config):
    argv = config.observer_args
    require(len(argv) == 20, 'owned observer command has unexpected arguments')
    manifest, executable, provider = config.out_dir / 'matrix-manifest.json', Path(argv[13]), Path(argv[14])
    require(argv == [argv[0], 'run', '--manifest', str(manifest), '--mode', 'metrics',
                    '--pause', 'never', '--duration', str(OWNED_DURATION_SECONDS),
                    '-o', f'{config.prefix}.output', '--',
                    str(executable), str(provider), 'matrix', str(config.ready),
                    str(config.go), str(config.done), str(config.finish)],
            'owned observer command contradicts lane or barrier paths')
    require(manifest.is_file() and executable.is_absolute() and executable.is_file()
            and os.access(executable, os.X_OK) and provider.is_absolute() and provider.is_file(),
            'owned manifest, executable or provider unavailable')
    config.workload_executable = executable


def validate_config(config):
    require(config.lane in LANES, 'unknown canary lane')
    require((config.variant, config.mode, config.privacy, config.workload_mode) == LANES[config.lane],
            'lane configuration contradiction')
    require(type(config.target_bits) is int and config.target_bits in (32, 64), 'invalid target width')
    config.workload_origin = getattr(config, 'workload_origin', 'external')
    require(config.workload_origin in ('external', 'owned')
            and (config.lane in OWNED_LANES) == (config.workload_origin == 'owned'),
            'workload origin contradicts lane')
    if config.workload_origin == 'owned':
        require(config.workload_pid is None and config.generation is None, 'owned workload identity must come from READY')
    else:
        require(dumper.snapshot_uint(config.workload_pid, 32, positive=True)
                and dumper.snapshot_uint(config.generation, positive=True), 'invalid workload identity')
    for name in ('out_dir', 'prefix', 'ready', 'go', 'done', 'finish', 'observer_log',
                 'workload_log', 'reader', 'obj'):
        value = getattr(config, name)
        require(isinstance(value, (str, Path)) and 0 < len(str(value)) <= 4096
                and '\0' not in str(value) and Path(value).is_absolute(), 'invalid absolute path')
        setattr(config, name, Path(value))
    require(config.out_dir.is_dir() and not config.out_dir.is_symlink()
            and config.out_dir.resolve() == config.out_dir
            and stat.S_IMODE(config.out_dir.stat().st_mode) & 0o077 == 0, 'output directory must be private')
    require(config.prefix == config.out_dir / config.lane, 'output prefix contradicts lane')
    for field, suffix in (('ready', 'ready'), ('go', 'go'), ('done', 'done'), ('finish', 'finish'),
                          ('observer_log', 'observer.log')):
        require(getattr(config, field) == Path(f'{config.prefix}.{suffix}'), 'lane path contradiction')
    require(config.workload_log == (config.observer_log if config.workload_origin == 'owned'
                                   else Path(f'{config.prefix}.workload.log')), 'workload log contradicts origin')
    require(config.reader.is_file() and os.access(config.reader, os.X_OK) and config.obj.is_file(),
            'native reader or object unavailable')
    argv = config.observer_args
    require(isinstance(argv, (list, tuple)) and 1 <= len(argv) <= 128
            and all(type(arg) is str and '\0' not in arg and len(arg) <= 4096 for arg in argv)
            and sum(len(arg) for arg in argv) <= 32768, 'invalid observer argv')
    require(Path(argv[0]).is_absolute() and Path(argv[0]).is_file() and os.access(argv[0], os.X_OK),
            'observer executable must be absolute')
    if config.workload_origin == 'owned':
        validate_owned_argv(config)
    expected = definitions.SAFE_MAPS if config.variant == 'default' else definitions.UNSAFE_MAPS
    destinations = [config.go, config.finish, config.observer_log, Path(f'{config.prefix}.output'),
                    config.out_dir / f'mapdump_manifest_{config.lane}.json',
                    config.out_dir / f'mapdump_snapshot_{config.lane}.json']
    if config.workload_mode == 'matrix':
        destinations.append(config.done)
    if config.workload_origin == 'owned':
        destinations.append(config.ready)
    for name, item in expected.items():
        if item['type'] == 27:
            destinations.append(evidence.ring_raw_path(config.prefix, name))
        else:
            extension = 'bin' if item['type'] == 29 else 'json'
            destinations.append(config.out_dir / f'mapdump_{name}_{config.lane}.{extension}')
    require(not any(os.path.lexists(path) for path in destinations), 'existing acquisition destination')
    return config


def ready_roster(config, deadline):
    doc = read_json(config.ready, deadline=deadline)
    if config.workload_origin == 'owned' and config.workload_pid is None and config.generation is None:
        require(isinstance(doc, dict) and dumper.snapshot_uint(doc.get('pid'), 32, positive=True)
                and isinstance(doc.get('tasks'), list) and len(doc['tasks']) == 1
                and isinstance(doc['tasks'][0], dict)
                and dumper.snapshot_uint(doc['tasks'][0].get('generation'), positive=True), 'invalid owned READY identity')
        config.workload_pid, config.generation = doc['pid'], doc['tasks'][0]['generation']
    require(isinstance(doc, dict) and set(doc) == {'schema', 'mode', 'pid', 'tasks'}
            and doc['schema'] == 'p11scope/canary-roster/v1'
            and doc['mode'] == config.workload_mode and type(doc['pid']) is int
            and doc['pid'] == config.workload_pid, 'invalid READY identity or schema')
    count = {'matrix': 0, 'blocked': 4, 'faults': 2}[config.workload_mode]
    tasks = doc['tasks']
    require(isinstance(tasks, list) and len(tasks) == count + 1, 'incomplete READY roster')
    tids, indices, leaders = set(), set(), 0
    for row in tasks:
        require(isinstance(row, dict) and set(row) == {'pid', 'tid', 'generation', 'role', 'call_index'}
                and type(row['pid']) is int and row['pid'] == config.workload_pid
                and dumper.snapshot_uint(row['tid'], 32, positive=True)
                and dumper.snapshot_uint(row['generation'], positive=True)
                and row['tid'] not in tids, 'invalid READY task identity')
        tids.add(row['tid'])
        if row['role'] == 'leader':
            require(row['tid'] == config.workload_pid and row['generation'] == config.generation
                    and row['call_index'] is None, 'invalid READY leader')
            leaders += 1
        else:
            require(row['role'] == 'worker' and row['tid'] != config.workload_pid
                    and type(row['call_index']) is int and 0 <= row['call_index'] < count
                    and row['call_index'] not in indices, 'invalid READY worker call binding')
            indices.add(row['call_index'])
    require(leaders == 1 and indices == set(range(count)), 'incomplete READY roles')
    return tasks


def wait_done(config, group, deadline, check):
    while True:
        check('matrix-DONE', deadline)
        group.snapshot(deadline)
        if os.path.lexists(config.done):
            value = read_json(config.done, 4096, deadline=deadline)
            require(value == {'schema': 'p11scope/canary-done/v1', 'mode': 'matrix',
                              'pid': config.workload_pid, 'generation': config.generation}
                    and type(value.get('pid')) is int and type(value.get('generation')) is int,
                    'invalid matrix DONE')
            return
        time.sleep(min(.01, remaining(deadline)))


def manifest_row(item):
    return {'id': item['id'], 'name': item['name'], 'type': item['type'],
            'key_size': item['bytes_key'], 'value_size': item['bytes_value'],
            'max_entries': item['max_entries'], 'map_flags': item['map_flags'], 'oracle': item['oracle']}


def stopped_rows(group, deadline, expected):
    records = group.snapshot(deadline, expected=expected)
    require(all(record[1] == 'T' for record in records.values()), 'incomplete stopped roster')
    return [{'pid': group.pid, 'tid': tid, 'generation': record[0], 'state': record[1]}
            for tid, record in sorted(records.items())]


def start_bindings(entries, tasks, config, *, complete):
    workers = {row['tid']: row for row in tasks if row['role'] == 'worker'}
    require(isinstance(entries, list) and len(entries) <= len(workers), 'unexpected START population')
    bindings, starts, slots = {}, [], {}
    for entry in entries:
        key = evidence.bpftool_bytes(entry['key'], 16)
        pid_tgid, slot, padding = struct.unpack('<QII', key)
        pid, tid = pid_tgid >> 32, pid_tgid & 0xffffffff
        require(pid == config.workload_pid and tid in workers and tid not in bindings
                and slot < 512 and padding == 0, 'invalid START worker key')
        start = evidence.decode_start(evidence.bpftool_bytes(entry['value'], evidence.CALL_START_SIZE))
        index = workers[tid]['call_index']
        base = 0x301 if config.workload_mode == 'blocked' else 0x401
        require(start['session'] == base + index, 'START session contradicts READY call')
        bindings[tid], slots[index] = key, slot
        starts.append(start)
    if complete:
        require(set(bindings) == set(workers), 'incomplete START worker keys')
        if config.workload_mode == 'blocked':
            require(slots[1] == slots[2] == slots[3] and slots[0] != slots[1], 'START runtime slot relationship mismatch')
        else:
            require(slots[0] != slots[1], 'START fault runtime slots must differ')
    return bindings, starts


class LiveMaps:
    """Only live BPF acquisition boundaries; process lifetime belongs to Custody."""
    def __init__(self, config):
        self.config, self.owner = config, None
        self.fds, self.fd_by_id, self.rings = [], {}, {}
        self.cpus = dumper.possible_cpu_ids()

    def _json(self, args, deadline, *, bound, item=None):
        with self.owner.helper_wait():
            return dumper.run_json(args, require_list=item is not None, map_identity=item,
                                   timeout_seconds=remaining(deadline, dumper.JSON_TIMEOUT_SECONDS), max_bytes=bound)

    def inventory(self, group, deadline):
        remaining(deadline)
        group.snapshot(deadline)
        directory = Path(f'/proc/{group.pid}/fdinfo')
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(entry.name.isdecimal() and len(names) < 4096, 'invalid observer fdinfo census')
                names.append(entry.name)
        texts = []
        for name in sorted(names):
            remaining(deadline)
            texts.append(read_bytes(directory / name, 65536, deadline).decode('ascii'))
        after_names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(entry.name.isdecimal() and len(after_names) < 4096, 'invalid observer fdinfo census')
                after_names.append(entry.name)
        require(sorted(names) == sorted(after_names), 'observer fdinfo membership changed')
        ids = dumper.map_ids_from_fdinfo(texts)
        maps = [dumper.normalize_map_metadata(dumper.one(self._json(
            ['bpftool', '-j', 'map', 'show', 'id', str(map_id)], deadline, bound=65536)), map_id)
                for map_id in ids]
        validate_inventory(maps, self.config.variant)
        group.snapshot(deadline)
        return sorted(maps, key=lambda item: item['name'])

    def pin(self, maps, deadline):
        libc = ctypes.CDLL(None, use_errno=True)
        for item in maps:
            remaining(deadline)
            attr = ctypes.create_string_buffer(struct.pack('=III', item['id'], 0, 0))
            fd = libc.syscall(321, 14, ctypes.byref(attr), ctypes.sizeof(attr))
            if fd < 0:
                raise OSError(ctypes.get_errno(), 'retain acquisition map')
            self.fds.append(fd)
            self.fd_by_id[item['id']] = fd

    def dump(self, item, deadline, bound):
        raw = self._json(['bpftool', '-j', 'map', 'dump', 'id', str(item['id'])],
                         deadline, bound=bound, item=item)
        return dumper.normalize_map_dump(raw, item, possible_cpus=self.cpus)

    def refuse(self, item, deadline):
        # An in-process syscall on the descriptor already retained for this
        # map id: no child, so none of _run_bounded_bytes' preconditions apply,
        # and no second reference to the map is opened mid-acquisition.
        remaining(deadline)
        return dumper.normalize_refused_lookup(
            dumper.probe_refused_lookup(item, fd=self.fd_by_id[item['id']]), item)

    def frames(self, pid, maps, deadline, bound):
        with self.owner.helper_wait():
            return dumper.run_task_storage_reader(self.config.reader, self.config.obj, pid, maps,
                timeout_seconds=remaining(deadline, dumper.TASK_STORAGE_TIMEOUT_SECONDS),
                max_records=dumper.TASK_STORAGE_MAX_RECORDS, max_bytes=bound)

    def open_rings(self, maps, deadline):
        for item in maps:
            if item['type'] == 'ringbuf':
                remaining(deadline)
                reader = evidence.RetainedRingReader(manifest_row(item))
                self.rings[item['name']] = reader
        require(set(self.rings) == set(evidence.RING_RECORD_SIZES), 'incomplete ring readers')

    def positions(self):
        return {name: reader.positions() for name, reader in self.rings.items()}

    def ring_records(self, positions):
        return {name: reader.read_records(positions[name]) for name, reader in self.rings.items()}

    def close(self):
        issues = []
        for name, reader in self.rings.items():
            try:
                reader.close()
            except BaseException as error:
                issues.extend(sanitized(f'close-ring-{name}', error))
        self.rings.clear()
        fds, self.fds = self.fds, []
        self.fd_by_id.clear()
        for fd in fds:
            try:
                os.close(fd)
            except BaseException as error:
                issues.extend(sanitized('close-map', error))
        if issues:
            raise CaptureError(issues) from None


def validate_inventory(maps, variant):
    expected = definitions.SAFE_MAPS if variant == 'default' else definitions.UNSAFE_MAPS
    require(isinstance(maps, list) and len(maps) == len(expected)
            and {item['name'] for item in maps} == set(expected)
            and len({item['id'] for item in maps}) == len(maps), 'map inventory mismatch')
    for item in maps:
        dumper.snapshot_map_metadata(item)
        wanted = expected[item['name']]
        require((item['type'], item['bytes_key'], item['bytes_value'], item['max_entries'], item['map_flags'])
                == (MAP_TYPES[wanted['type']], wanted['key_size'], wanted['value_size'], wanted['max_entries'], wanted['flags']),
                f'map definition mismatch name={item["name"]}')


class AcquisitionFiles:
    """Private files of this acquisition only; publication is no-replacement."""
    def __init__(self, config):
        self.config, self.stage = config, None
        self.stage_identity = None
        self.owned = []
        self.total = 0

    def create_stage(self):
        self.stage = Path(tempfile.mkdtemp(prefix=f'.{self.config.lane}.', dir=self.config.out_dir))
        identity = self.stage.lstat()
        self.stage_identity = (identity.st_dev, identity.st_ino)

    def write(self, path, raw):
        require(len(raw) <= MAX_BYTES - self.total, 'aggregate acquisition byte bound exceeded')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            # The private, exclusively-created pathname is also usable if the
            # descriptor metadata operation fails. No cancellation is raised
            # between creation and the ownership ledger entry.
            try:
                identity = os.fstat(fd)
            except OSError:
                identity = Path(path).lstat()
                self.owned.append((Path(path), identity.st_dev, identity.st_ino))
                raise
            self.owned.append((Path(path), identity.st_dev, identity.st_ino))
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd is not None:
                os.close(fd)
        self.total += len(raw)

    def adopt(self, path):
        """Ledger a path this acquisition created outside write().

        Handshake files are created by the fixture or by a bare `O_EXCL`
        open, so they never reach the ledger through write(); without
        an entry a rolled-back run leaves them behind and a later run refuses
        its own destinations. Ownership is recorded the same way, so rollback
        still refuses to unlink a path that is no longer the file we created.
        """
        identity = Path(path).lstat()
        require(stat.S_ISREG(identity.st_mode), 'adopted acquisition file is not regular')
        self.owned.append((Path(path), identity.st_dev, identity.st_ino))

    def publish(self, staged, destination):
        identity = staged.stat()
        os.link(staged, destination, follow_symlinks=False)
        self.owned.append((Path(destination), identity.st_dev, identity.st_ino))

    def remove(self, *, staged_only=False):
        issues, retained = [], []
        for path, device, inode in reversed(self.owned):
            if staged_only and path.parent != self.stage:
                retained.append((path, device, inode))
                continue
            try:
                current = path.lstat()
                require((current.st_dev, current.st_ino) == (device, inode), 'rollback file ownership changed')
                path.unlink()
            except FileNotFoundError:
                pass
            except BaseException as error:
                issues.extend(sanitized('remove-acquisition-file', error))
                retained.append((path, device, inode))
        self.owned = list(reversed(retained))
        if self.stage is not None:
            try:
                current = self.stage.lstat()
                require((current.st_dev, current.st_ino) == self.stage_identity, 'staging directory ownership changed')
                self.stage.rmdir()
                self.stage = None
            except BaseException as error:
                issues.extend(sanitized('remove-staging-directory', error))
        return issues


def create_control(path, created=None):
    # GO and FINISH are handshake/diagnostic files, not published BPF evidence.
    # Keep them available for the shell's still-owned workload on failure.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        # The hook records ownership between creation and close; a raising hook
        # must not leak the descriptor it was handed the path for.
        if created is not None:
            created()
    finally:
        os.close(fd)


class CoordinatorSignals:
    """Outer cancellation policy remains live through publication and rollback."""
    def __init__(self):
        self.handlers, self.mask, self.cancelled = {}, None, None

    def record(self, number, frame):
        if self.cancelled is None:
            self.cancelled = number

    def enter(self):
        self.mask = custody.check_owner_policy()
        for number in (signal.SIGINT, signal.SIGTERM):
            self.handlers[number] = signal.getsignal(number)
            signal.signal(number, self.record)

    def check(self):
        require(self.cancelled is None, 'coordinator cancellation')

    def finish(self, files, issues):
        if self.mask is None:
            return
        # Terminal boundary: all owned process resources are settled first.
        # While masked, attempt every policy restoration and roll back any
        # failed/cancelled publication before restoring the original mask last.
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        except BaseException as error:
            issues.extend(sanitized('terminal-mask', error))
        for number, handler in self.handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException as error:
                issues.extend(sanitized('terminal-handler', error))
        try:
            for number in sorted(signal.sigpending().intersection((signal.SIGINT, signal.SIGTERM))):
                status = signal.sigtimedwait({number}, 0)
                require(status is not None, 'terminal cancellation could not be retained')
                self.record(status.si_signo, None)
        except BaseException as error:
            issues.extend(sanitized('terminal-cancellation', error))
        if self.cancelled is not None:
            issues.append('coordinator cancellation')
        if issues:
            issues.extend(files.remove())
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)
        except BaseException as error:
            issues.extend(sanitized('terminal-mask-restoration', error))
            issues.extend(files.remove())


class Coordinator:
    def __init__(self, config, source):
        self.config, self.source = config, source
        self.signals, self.owner = CoordinatorSignals(), None
        self.files = AcquisitionFiles(config)
        self.phase = 'configuration'
        self.stopped_deadline = None
        self.owned_observer_deadline = None
        self.go_created = False

    def check(self, phase, deadline=None):
        self.phase = phase
        self.signals.check()
        if self.owner is not None:
            self.owner.check_cancelled()
        if deadline is not None:
            remaining(deadline)

    def capture_ready(self, deadline):
        if self.config.mode == 'trace':
            marker = f'CAPTURE privacy={self.config.privacy}'.encode()
            lines = read_bytes(self.config.observer_log, MAX_LOG_BYTES, deadline).splitlines()
            return marker in lines
        # Profile/metrics: the live frame is TTY-only (src/run.rs LiveDisplay),
        # so on this log file its privacy marker lands only in the final frame,
        # after the capture has ended. Readiness is the attach-complete stderr
        # line (src/run.rs capture_ready_line); the privacy tier is proven
        # post-exit by final_privacy_present instead.
        attach = b'p11scope: capturing: '
        lines = read_bytes(self.config.observer_log, MAX_LOG_BYTES, deadline).splitlines()
        return any(attach in line for line in lines)

    def final_privacy_present(self, deadline):
        marker = f' — privacy={self.config.privacy}'.encode()
        lines = read_bytes(self.config.observer_log, MAX_LOG_BYTES, deadline).splitlines()
        return any(marker in line for line in lines)

    def finish_owned_observer(self, observer, workload):
        # One absolute deadline from readiness: STOP overlaps capture duration.
        # The final child release/reap fits inside the fixture's DONE+60s bound.
        deadline = self.owned_observer_deadline
        self.check('owned-observer-wait', deadline)
        while observer.popen.poll() is None:
            self.check('owned-observer-wait', deadline)
            time.sleep(min(.01, remaining(deadline)))
        require(observer.wait(deadline) == 0, 'owned observer ordinary wait was not successful')
        self.check('owned-handoff', deadline)
        report = read_json(Path(f'{self.config.prefix}.output'), MAX_LOG_BYTES, deadline=deadline)
        facts = report['evidence']
        require(facts['child_still_running'] is True, 'owned observer did not hand back a live child')
        pid = facts['handoff_child_pid']
        require(type(pid) is int and pid == workload.pid, 'owned observer handed back another child')
        require(facts['scheduling']['phase_mono_ns']['loop_end_reason'] == 'expiry',
                'owned observer did not finish by duration expiry')
        self.owner.adopt_observer_child(observer, workload, deadline)

    def readiness(self, observer, deadline):
        while True:
            self.check('observer-readiness', deadline)
            observer.group.check_alive(deadline)
            if self.capture_ready(deadline):
                return
            time.sleep(min(.01, remaining(deadline)))

    def owned_lineage(self, observer, workload, tasks, deadline):
        observer.group.children(deadline, allowed={workload.pid: workload.generation})
        workload.children(deadline, allowed={})
        expected = {row['tid']: row['generation'] for row in tasks}
        before = workload.snapshot(deadline, expected=expected)
        actual = os.stat(f'/proc/{workload.pid}/exe')
        wanted = self.config.workload_executable.stat()
        require(stat.S_ISREG(actual.st_mode) and (actual.st_dev, actual.st_ino) == (wanted.st_dev, wanted.st_ino),
                'owned workload executable changed')
        after = workload.snapshot(deadline, expected=expected)
        require(all(row[2] == observer.group.pid for row in (*before.values(), *after.values())),
                'owned workload parent changed')
        remaining(deadline)

    def owned_readiness(self, observer, deadline):
        tasks = None
        while True:
            self.check('owned-readiness', deadline)
            observer.group.check_alive(deadline)
            if tasks is None and os.path.lexists(self.config.ready):
                tasks = ready_roster(self.config, deadline)
            if self.capture_ready(deadline) and tasks is not None:
                workload = self.owner.retain_observer_child(observer, self.config.workload_pid,
                                                            self.config.generation, deadline)
                self.owned_lineage(observer, workload, tasks, deadline)
                return workload, tasks
            time.sleep(min(.01, remaining(deadline)))

    def acquire(self, observer, workload, tasks):
        cfg, source, deadline = self.config, self.source, self.stopped_deadline
        owned = cfg.workload_origin == 'owned'
        allowed_children = {workload.pid: workload.generation} if owned else {}
        if owned:
            self.owned_lineage(observer, workload, tasks, deadline)
        expected_members = {row['tid']: row['generation'] for row in tasks}
        observer_members = {tid: row[0] for tid, row in observer.group.snapshot(deadline).items()}
        observer.group.stop(deadline, expected=observer_members, allowed_children=allowed_children)
        self.check('observer-stopped', deadline)
        create_control(cfg.go, lambda: setattr(self, 'go_created', True))
        self.check('GO-created', deadline)
        maps, bindings = None, None
        if cfg.workload_mode == 'matrix':
            wait_done(cfg, workload, deadline, self.check)
        else:
            maps = source.inventory(observer.group, deadline)
            source.pin(maps, deadline)
            start = next(item for item in maps if item['name'] == 'START')
            while True:
                self.check('START-readiness', deadline)
                current = source.dump(start, deadline, MAX_BYTES)
                found, _ = start_bindings(current, tasks, cfg, complete=False)
                if len(found) == len(tasks) - 1:
                    bindings, _ = start_bindings(current, tasks, cfg, complete=True)
                    break
                time.sleep(min(.01, remaining(deadline)))
        self.check('workload-readiness', deadline)
        workload.stop(deadline, expected=expected_members, allowed_children={} if owned else None)
        self.check('workload-stopped', deadline)
        before = stopped_rows(workload, deadline, expected_members)
        observer_before = stopped_rows(observer.group, deadline, observer_members)
        inventory = source.inventory(observer.group, deadline)
        if maps is None:
            maps = inventory
            source.pin(maps, deadline)
        else:
            require(maps == inventory, 'map inventory changed after readiness')
        source.open_rings(maps, deadline)
        positions = source.positions()
        self.check('rings-retained', deadline)
        self.files.create_stage()
        self.check('stage-created', deadline)
        ordinary, values = {}, {}
        for item in maps:
            if item['oracle'] == 'dump':
                self.check(f'dump-{item["name"]}', deadline)
                cells = source.dump(item, deadline, MAX_BYTES - self.files.total)
                raw = encoded(cells)
                self.files.write(self.files.stage / f'mapdump_{item["name"]}_{cfg.lane}.json', raw)
                ordinary[item['name']], values[item['name']] = cells, raw
            elif item['oracle'] == 'refused-lookup':
                # The kernel's own per-key refusal is this map's whole surface.
                # It is deliberately not `ordinary`: that dict carries decoded
                # control/START/EVIDENCE cells, and there is no cell to decode.
                self.check(f'refuse-{item["name"]}', deadline)
                raw = encoded(source.refuse(item, deadline))
                self.files.write(self.files.stage / f'mapdump_{item["name"]}_{cfg.lane}.json', raw)
                values[item['name']] = raw
        task_maps = [item for item in maps if item['type'] == 'task_storage']
        self.check('task-frames', deadline)
        frames = source.frames(observer.popen.pid, task_maps, deadline, MAX_BYTES - self.files.total)
        records = dumper.parse_task_storage_frames(frames, task_maps,
                    max_records=dumper.TASK_STORAGE_MAX_RECORDS, max_bytes=MAX_BYTES - self.files.total)
        for item in task_maps:
            # Idle owners are retained storage without a lease: reconcile binds
            # only the leased population, so the staged bytes must use the same
            # predicate or the replay's byte count mismatches the receipt.
            raw = b''.join(record['value'] for record in records
                           if record['map_id'] == item['id']
                           and not (item['name'] == 'THREAD_OWNER'
                                    and dumper.idle_owner_value(record['value'])))
            self.files.write(self.files.stage / f'mapdump_{item["name"]}_{cfg.lane}.bin', raw)
            values[item['name']] = raw
        self.check('retained-rings', deadline)
        rings = source.ring_records(positions)
        for name, rows in rings.items():
            raw = b''.join(rows)
            self.files.write(evidence.ring_raw_path(self.files.stage / cfg.lane, name), raw)
            values[name] = raw
        self.check('after-identities', deadline)
        after = stopped_rows(workload, deadline, expected_members)
        require(observer_before == stopped_rows(observer.group, deadline, observer_members), 'observer roster changed')
        observer.group.children(deadline, allowed=allowed_children)
        if owned:
            self.owned_lineage(observer, workload, tasks, deadline)
        require(maps == source.inventory(observer.group, deadline), 'map inventory changed during acquisition')
        require(positions == source.positions(), 'retained ring positions changed')
        self.check('retained-semantics', deadline)
        controls = {}
        for item in maps:
            if item['name'] in ('COOKIE_CTL', 'OWNER_CTL', 'ROOT_CTL'):
                cells = ordinary[item['name']]
                require(len(cells) == 1, 'incomplete control cells')
                controls[item['name']] = {**item, 'value': evidence.bpftool_bytes(cells[0]['value'], item['bytes_value'])}
        expected = [{key: row[key] for key in ('pid', 'tid', 'generation')} |
                    {'cookie': row['role'] == 'leader' and cfg.mode != 'metrics',
                     'owner': row['role'] == 'worker', 'root': owned and row['role'] == 'leader'} for row in tasks]
        receipt_lane = 'owned-root' if owned else 'external'
        bound = dumper.reconcile_task_storage(task_maps, records, expected=expected, before=before, after=after,
                                             controls=controls, lane=receipt_lane, small_state=False)
        if cfg.mode == 'metrics':
            require(evidence.u64(controls['COOKIE_CTL']['value'], 8) == 0, 'aggregate-only cookie allocation history')
        if cfg.workload_mode == 'matrix':
            require(not ordinary['START'], 'completed matrix START is not empty')
        else:
            final_bindings, starts = start_bindings(ordinary['START'], tasks, cfg, complete=True)
            require(bindings == final_bindings, 'START keys changed after readiness')
            owner_id = next(item['id'] for item in task_maps if item['name'] == 'THREAD_OWNER')
            # Idle (all-zero) owners are retained storage without a lease.
            require(all(evidence.u32(record['value'], 536) == 1 for record in records
                        if record['map_id'] == owner_id and any(record['value'])),
                    'THREAD_OWNER start_count contradicts START worker keys')
            if cfg.workload_mode == 'blocked':
                lines = [line.removeprefix('P11SCOPE_POINTERS ') for line in
                         read_bytes(cfg.workload_log, MAX_LOG_BYTES, deadline).decode().splitlines()
                         if line.startswith('P11SCOPE_POINTERS ')]
                require(len(lines) == 1, 'missing exact hostile pointer record')
                evidence.assert_hostile_records(starts, json.loads(lines[0], object_pairs_hook=unique_object))
            else:
                cells = [cell for cell in ordinary['EVIDENCE'] if evidence.u32(evidence.bpftool_bytes(cell['key'], 4), 0) == 5]
                require(len(cells) == 1, 'missing fault evidence cell')
                evidence.assert_fault_records(starts, evidence.value_total(cells[0].get('values', [])))
        evidence.assert_retained_ring_records(rings, cfg.lane, cfg.workload_pid, positions)
        acquisition = uuid.uuid4().hex
        receipt = {'contract': dumper.STOPPED_SNAPSHOT_CONTRACT, 'acquisition_id': acquisition,
                   'phase': 'stopped', 'lane': receipt_lane, 'small_state': False,
                   'expected': expected, 'before': before, 'after': after, 'surfaces': []}
        for item in maps:
            raw = values[item['name']]
            row = {'id': item['id'], 'acquisition_id': acquisition, 'phase': 'stopped',
                   'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            if item['type'] == 'task_storage':
                row['records'] = bound[item['name']]
            elif item['type'] == 'ringbuf':
                # The two kernel byte counters the retained bytes were read
                # between, re-verified above against a second sample. An
                # observer that drains its own ring retains nothing on a healthy
                # run, so the residue alone cannot say what the ring carried and
                # a replay reading only these files would have no way to ask.
                row['positions'] = list(positions[item['name']])
            receipt['surfaces'].append(row)
        self.receipt_name = f'mapdump_snapshot_{cfg.lane}.json'
        self.files.write(self.files.stage / self.receipt_name, encoded(receipt))
        self.maps, self.acquisition = maps, acquisition
        staged = self.manifest(self.files.stage)
        self.check('staged-replay', deadline)
        evidence.assert_stopped_snapshot(staged, self.files.stage / cfg.lane)
        self.check('staged-replay-complete', deadline)

    def manifest(self, directory):
        claim = {'contract': dumper.STOPPED_SNAPSHOT_CONTRACT, 'acquisition_id': self.acquisition,
                 'phase': 'stopped', 'receipt': str(directory / self.receipt_name)}
        rows = []
        for item in self.maps:
            row = manifest_row(item) | {'snapshot': claim}
            if item['type'] != 'ringbuf':
                extension = 'bin' if item['type'] == 'task_storage' else 'json'
                row['file'] = str(directory / f'mapdump_{item["name"]}_{self.config.lane}.{extension}')
            rows.append(row)
        return rows

    def publish(self):
        deadline = time.monotonic() + PUBLICATION_SECONDS
        for path, _, _ in list(self.files.owned):
            if path.parent == self.files.stage:
                self.check(f'publish-{path.name}', deadline)
                self.files.publish(path, self.config.out_dir / path.name)
                self.check(f'published-{path.name}', deadline)
        final = self.manifest(self.config.out_dir)
        self.check('final-replay', deadline)
        evidence.assert_stopped_snapshot(final, self.config.prefix)
        self.check('final-replay-complete', deadline)
        staged_manifest = self.files.stage / '.final-manifest.json'
        self.files.write(staged_manifest, encoded(final))
        self.check('manifest-ready', deadline)
        self.files.publish(staged_manifest, self.config.out_dir / f'mapdump_manifest_{self.config.lane}.json')
        self.check('manifest-published', deadline)
        issues = self.files.remove(staged_only=True)
        if issues:
            raise CaptureError(issues)
        self.check('publication-complete', deadline)

    def run(self):
        issues, observer, workload, log = [], None, None, None
        owned = False
        try:
            validate_config(self.config)
            self.signals.enter()
            self.owner = custody.Custody(cleanup_seconds=RESUME_SECONDS)
            self.owner.__enter__()
            evidence.initialize(self.config.target_bits)
            owned = self.config.workload_origin == 'owned'
            if not owned:
                ready_deadline = time.monotonic() + READY_SECONDS
                tasks = ready_roster(self.config, ready_deadline)
                workload = self.owner.borrow(self.config.workload_pid, self.config.generation, role='workload')
                workload.snapshot(ready_deadline,
                                  expected={row['tid']: row['generation'] for row in tasks})
            if self.source is None:
                self.source = LiveMaps(self.config)
            self.source.owner = self.owner
            self.check('observer-log')
            fd = os.open(self.config.observer_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                log = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
            ready_deadline = time.monotonic() + READY_SECONDS
            observer = self.owner.launch(self.config.observer_args, stdout=log, stderr=log,
                                         deadline=ready_deadline if owned else None)
            if owned:
                workload, tasks = self.owned_readiness(observer, ready_deadline)
                self.owned_observer_deadline = (time.monotonic() + OWNED_DURATION_SECONDS
                                                + OBSERVER_WAIT_SECONDS)
            else:
                self.readiness(observer, time.monotonic() + READY_SECONDS)
            self.stopped_deadline = time.monotonic() + STOP_SECONDS
            self.acquire(observer, workload, tasks)
        except BaseException as error:
            issues.extend(sanitized(self.phase, error))
        finally:
            resume_deadline = time.monotonic() + RESUME_SECONDS
            for group, allow_exit in ((observer.group if observer else None, True), (workload, False)):
                if group is not None:
                    try:
                        group.resume(resume_deadline, allow_successful_exit=allow_exit)
                    except BaseException as error:
                        issues.extend(sanitized(f'resume-{group.role}', error))
            if self.source is not None:
                try:
                    self.source.close()
                except BaseException as error:
                    issues.extend(sanitized('acquisition-resources', error))
            if owned and observer is not None and not issues:
                try:
                    self.finish_owned_observer(observer, workload)
                except BaseException as error:
                    issues.extend(sanitized('owned-handoff', error))
            if self.go_created and self.config.workload_mode == 'matrix':
                try:
                    create_control(self.config.finish)
                    if owned and not issues:
                        deadline = self.owned_observer_deadline + OWNED_CHILD_WAIT_SECONDS
                        self.check('owned-child-wait', deadline)
                        self.owner.wait_observer_child(workload, deadline)
                    elif not owned and self.stopped_deadline is not None:
                        require(time.monotonic() <= self.stopped_deadline + 20, 'matrix FINISH exceeded safety margin')
                except BaseException as error:
                    issues.extend(sanitized('FINISH-release', error))
            if observer is not None and not owned and not issues:
                try:
                    require(observer.wait(time.monotonic() + OBSERVER_WAIT_SECONDS) == 0, 'observer ordinary wait was not successful')
                except BaseException as error:
                    issues.extend(sanitized('observer-wait', error))
            if observer is not None and not issues and self.config.mode != 'trace':
                # The capturing line carries no tier, so the finished observer's
                # log must still contain the final frame's privacy marker (still
                # written on non-terminals). Fail closed if absent.
                try:
                    privacy_deadline = time.monotonic() + PUBLICATION_SECONDS
                    require(self.final_privacy_present(privacy_deadline), 'observer privacy marker missing')
                except BaseException as error:
                    issues.extend(sanitized('observer-privacy', error))
            if log is not None:
                try:
                    log.close()
                except BaseException as error:
                    issues.extend(sanitized('observer-log-close', error))
            if self.owner is not None and self.owner.active:
                try:
                    self.owner.close()
                except BaseException as error:
                    issues.extend(sanitized('custody-close', error))
            if self.owner is not None and self.owner.cancelled is not None:
                issues.append('custody cancellation')
        try:
            self.check('custody-closed')
            if not issues:
                self.publish()
        except BaseException as error:
            issues.extend(sanitized(self.phase, error))
        if issues:
            issues.extend(self.files.remove())
        self.signals.finish(self.files, issues)
        if issues:
            raise CaptureError(issues) from None
        return self.config.out_dir / f'mapdump_manifest_{self.config.lane}.json'


def capture(config, source=None):
    return Coordinator(config, source).run()


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('lane', 'variant', 'mode', 'privacy', 'workload-mode', 'out-dir', 'prefix',
                 'ready', 'go', 'done', 'finish', 'observer-log', 'workload-log', 'reader', 'obj'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--workload-origin', choices=('external', 'owned'), default='external')
    parser.add_argument('--target-bits', required=True, type=int)
    for name in ('workload-pid', 'generation'):
        parser.add_argument('--' + name, type=int)
    parser.add_argument('observer_args', nargs=argparse.REMAINDER)
    result = parser.parse_args(argv)
    if result.workload_origin == 'external' and (result.workload_pid is None or result.generation is None):
        parser.error('external workloads require --workload-pid and --generation')
    if result.workload_origin == 'owned' and (result.workload_pid is not None or result.generation is not None):
        parser.error('owned workloads must obtain identity from READY')
    if result.observer_args[:1] == ['--']:
        result.observer_args = result.observer_args[1:]
    return result


def main(argv=None):
    try:
        result = capture(parse_args(sys.argv[1:] if argv is None else argv))
    except CaptureError as error:
        print(f'capture-stopped-canary: {error}', file=sys.stderr)
        return 1
    print(f'stopped canary manifest: {result}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
