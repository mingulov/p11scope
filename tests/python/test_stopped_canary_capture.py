#!/usr/bin/env python3
"""Unprivileged coordinator probes with injected BPF acquisition boundaries."""
import importlib.util
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('capture', ROOT / 'scripts/capture-stopped-canary.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
c = capture.custody
fixture_spec = importlib.util.spec_from_file_location('canary_fixtures', ROOT / 'tests/python/test_canary_evidence.py')
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


def generation(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19])


def open_descriptors():
    descriptors = set()
    for entry in os.listdir('/proc/self/fd'):
        try:
            os.fstat(int(entry))
        except OSError:
            continue
        descriptors.add(int(entry))
    return descriptors


def config_for(pid, directory, lane='aggregate-only-metrics'):
    directory = Path(directory)
    variant, mode, privacy, workload_mode = capture.LANES[lane]
    prefix = directory / lane
    config = SimpleNamespace(lane=lane, variant=variant, mode=mode, privacy=privacy,
        workload_mode=workload_mode, workload_pid=pid, generation=generation(pid), target_bits=64,
        out_dir=directory, prefix=prefix, reader=Path(sys.executable), obj=Path(sys.executable),
        **{name: Path(f'{prefix}.{suffix}') for name, suffix in (
            ('ready', 'ready'), ('go', 'go'), ('done', 'done'), ('finish', 'finish'),
            ('observer_log', 'observer.log'), ('workload_log', 'workload.log'))})
    marker = f'CAPTURE privacy={privacy}' if mode == 'trace' else f'fixture — privacy={privacy}'
    config.observer_args = [sys.executable, '-c', f'import time; print({marker!r}, flush=True); time.sleep(.2)']
    if not config.ready.exists():
        config.ready.write_text(json.dumps({'schema': 'p11scope/canary-roster/v1', 'mode': workload_mode,
            'pid': pid, 'tasks': [{'pid': pid, 'tid': pid, 'generation': config.generation,
                                'role': 'leader', 'call_index': None}]}))
    config.workload_log.touch(exist_ok=True)
    return config


def synthetic_done(config, group, deadline, check):
    config.done.write_text(json.dumps({'schema': 'p11scope/canary-done/v1', 'mode': 'matrix',
                                      'pid': config.workload_pid, 'generation': config.generation}))


class FakeRing:
    def __init__(self, rows):
        self.rows, self.closed = rows, False
        self.fd = os.open('/dev/null', os.O_RDONLY)

    def positions(self):
        assert not self.closed
        return (0, 0)

    def read_records(self, positions):
        assert not self.closed and positions == (0, 0)
        return self.rows

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.fd)


class FakeMaps(capture.LiveMaps):
    def __init__(self, config):
        self.config, self.owner, self.cpus = config, None, [0]
        self.fds, self.rings, self.opened_rings, self.closed_fds = [], {}, [], []
        self.calls = []
        definitions = capture.definitions.SAFE_MAPS if config.variant == 'default' else capture.definitions.UNSAFE_MAPS
        self.maps = [capture.dumper.normalize_map_metadata({
            'id': index + 100, 'name': name, 'type': capture.MAP_TYPES[row['type']],
            'bytes_key': row['key_size'], 'bytes_value': row['value_size'],
            'max_entries': row['max_entries'], 'flags': row['flags']}, index + 100)
            for index, (name, row) in enumerate(sorted(definitions.items()))]

    def inventory(self, group, deadline):
        capture.remaining(deadline)
        group.snapshot(deadline)
        self.calls.append(('inventory', deadline))
        maps = copy.deepcopy(self.maps)
        capture.validate_inventory(maps, self.config.variant)
        return maps

    def pin(self, maps, deadline):
        capture.remaining(deadline)
        self.fds.extend(os.open('/dev/null', os.O_RDONLY) for _ in maps)

    def dump(self, item, deadline, bound):
        capture.remaining(deadline)
        self.calls.append((item['name'], deadline))
        name, size = item['name'], item['bytes_value']
        workers = [row for row in capture.ready_roster(self.config, deadline) if row['role'] == 'worker']
        controls = {'COOKIE_CTL': [16384, int(self.config.mode != 'metrics'), 0, 0, 0],
                    'OWNER_CTL': [16448, len(workers), 0, 0, 0, 0, 0],
                    'ROOT_CTL': [int(self.config.lane in capture.OWNED_LANES)] + [0] * 7}
        if name in controls:
            raw = struct.pack('<' + 'Q' * len(controls[name]), *controls[name])
            cells = [{'key': [0] * 4, 'value': list(raw)}]
        elif name == 'START':
            cells = []
            for worker in workers:
                index = worker['call_index']
                if self.config.workload_mode == 'blocked':
                    lines = [line.removeprefix('P11SCOPE_POINTERS ') for line in self.config.workload_log.read_text().splitlines()
                             if line.startswith('P11SCOPE_POINTERS ')]
                    pointer = json.loads(lines[0])['unknown_mechanism']
                    raw = fixtures.start_bytes(capture.evidence, 0x301 + index,
                        target=30 if index == 1 else None, mechanism_ptr=pointer if index == 0 else 0,
                        capture=capture.evidence.ARG_READ_FAILURE if index >= 2 else 0)
                    slot = 7 if index == 0 else 29
                else:
                    raw = fixtures.start_bytes(capture.evidence, 0x401 + index, attr_type=2 - index,
                                               capture=capture.evidence.ARG_READ_FAILURE)
                    slot = 7 + index
                key = struct.pack('<QII', (worker['pid'] << 32) | worker['tid'], slot, 0)
                cells.append({'key': list(key), 'value': list(raw)})
        elif item['type'] in ('array', 'percpu_array'):
            cells = []
            for index in range(item['max_entries']):
                value = list(bytes(size))
                if name == 'EVIDENCE' and index == 5 and self.config.workload_mode == 'faults':
                    value = list(struct.pack('<Q', 2))
                cell = {'key': list(struct.pack('<I', index))}
                cell.update({'values': [{'cpu': 0, 'value': value}]} if item['type'] == 'percpu_array' else {'value': value})
                cells.append(cell)
        else:
            cells = []
        normalized = capture.dumper.normalize_map_dump(cells, item, possible_cpus=self.cpus)
        assert len(capture.encoded(normalized)) <= bound
        return normalized

    def frames(self, pid, maps, deadline, bound):
        capture.remaining(deadline)
        tasks = capture.ready_roster(self.config, deadline)
        stream = []
        for item in maps:
            for task in tasks:
                if item['name'] == 'ROOT_AFFILIATION' and self.config.lane in capture.OWNED_LANES:
                    raw = struct.pack('<Q', 1)
                elif item['name'] == 'TASK_COOKIE' and task['role'] == 'leader' and self.config.mode != 'metrics':
                    raw = struct.pack('<Q', 1)
                elif item['name'] == 'THREAD_OWNER' and task['role'] == 'worker':
                    raw = bytearray(544)
                    struct.pack_into('<Q', raw, 0, (task['pid'] << 32) | task['tid'])
                    struct.pack_into('<QQII', raw, 520, 0, 0, 1, 1)
                else:
                    continue
                stream.append(capture.dumper.TASK_STORAGE_HEADER.pack(capture.dumper.TASK_STORAGE_MAGIC, 1,
                    item['id'], task['pid'], task['tid'], len(raw)) + raw)
        stream.append(capture.dumper.TASK_STORAGE_HEADER.pack(capture.dumper.TASK_STORAGE_MAGIC, 2, 0, 0, 0, 0))
        return b''.join(stream)

    def open_rings(self, maps, deadline):
        for name in ('DISCOVERY', 'EVENTS'):
            rows = []
            if name == 'DISCOVERY' and self.config.lane in capture.OWNED_LANES:
                rows = [bytes(capture.evidence.RING_RECORD_SIZES[name])]
            if name == 'EVENTS' and self.config.workload_mode == 'matrix' and self.config.mode != 'metrics':
                for index in range(28):
                    kwargs = {}
                    if 'unsafe' in self.config.lane:
                        e = capture.evidence
                        kwargs = {
                            1: dict(shape=1, p0=e.ALIASES['pss_hash'], p1=e.ALIASES['pss_mgf'], p2=e.ALIASES['pss_salt']),
                            2: dict(shape=3, p0=e.ALIASES['gcm220_iv'], p1=e.ALIASES['gcm220_aad'], p2=e.ALIASES['gcm220_tag']),
                            3: dict(mechanism=0x1087, shape=4, p0=e.ALIASES['gcm240_iv'], p1=e.ALIASES['gcm240_aad'], p2=e.ALIASES['gcm240_tag']),
                            4: dict(mechanism=e.UNKNOWN), 5: dict(mechanism=e.MAXIMUM),
                            6: dict(attrs=(e.ALIASES['template_type'], *e.POLICY_BOOLEAN_TYPES[:6]), attr_count=7, attr_total=7, attr_bools=0x3F, attr_seen=0x3F),
                            7: dict(attrs=(e.ALIASES['template_type'], *e.POLICY_BOOLEAN_TYPES[6:]), attr_count=6, attr_total=6, attr_bools=0x7C0, attr_seen=0x7C0),
                            8: dict(attrs=(1,), attr_count=1, attr_total=1, capture=e.ARG_READ_FAILURE),
                            9: dict(attrs=(2,), attr_count=1, attr_total=1, capture=e.ARG_READ_FAILURE),
                        }.get(index, {})
                    raw = bytearray(fixtures.event_bytes(index, **kwargs))
                    struct.pack_into('<Q', raw, 16, (self.config.workload_pid << 32) | self.config.workload_pid)
                    rows.append(bytes(raw))
            reader = FakeRing(rows)
            self.rings[name] = reader
            self.opened_rings.append(reader)

    def close(self):
        self.closed_fds.extend(self.fds)
        super().close()


def first_refusal(pid, directory):
    owner = c.Custody()
    original_launch = owner.launch
    test_handles = []
    calls = []
    original_signal = signal.pidfd_send_signal
    def launch(*args, **kwargs):
        child = original_launch(*args, **kwargs)
        test_handles.append(os.dup(child.group.fd))
        return child
    def refuse(fd, sig, *args):
        calls.append((fd, sig))
        if sig == signal.SIGSTOP and any(g.pid == pid and g.fd == fd for g in owner.groups):
            raise PermissionError('injected workload STOP refusal')
        return original_signal(fd, sig, *args)
    config = config_for(pid, directory)
    try:
        with patch.object(c, 'Custody', return_value=owner), \
                patch.object(owner, 'launch', side_effect=launch), \
                patch.object(signal, 'pidfd_send_signal', side_effect=refuse), \
                patch.object(capture, 'wait_done', side_effect=synthetic_done):
            try:
                capture.capture(config)
            except (PermissionError, c.CustodyError, capture.CaptureError):
                pass
            else:
                raise AssertionError('STOP refusal was accepted')
        observer = next(g for g in owner.groups if g.role == 'observer')
        workload = next(g for g in owner.groups if g.role == 'workload')
        assert (observer.fd, signal.SIGSTOP) in calls
        assert (observer.fd, signal.SIGCONT) in calls, 'coordinator omitted original observer CONT'
        assert (workload.fd, signal.SIGCONT) not in calls
        assert all(g.closed for g in owner.groups), 'coordinator retained owned descriptors'
        assert not (Path(directory) / 'mapdump_manifest_aggregate-only-metrics.json').exists()
        for fd in test_handles:
            assert select.select([fd], [], [], 1)[0]
            try:
                os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                raise AssertionError('observer was not reaped')
    finally:
        # Independently retained handles bound RED teardown as well as GREEN.
        for fd in test_handles:
            try:
                original_signal(fd, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if owner.active:
            owner.close()
        for fd in test_handles:
            os.close(fd)


def complete_metrics(pid, directory):
    config = config_for(pid, directory)
    source = FakeMaps(config)
    replays = []
    replay = capture.evidence.assert_stopped_snapshot
    def check(manifest, prefix):
        replays.append((manifest, Path(prefix)))
        if len(replays) == 2:
            assert not (Path(directory) / f'mapdump_manifest_{config.lane}.json').exists()
            assert all(reader.closed for reader in source.opened_rings)
        return replay(manifest, prefix)
    with patch.object(capture, 'wait_done', side_effect=synthetic_done), \
            patch.object(capture.evidence, 'assert_stopped_snapshot', side_effect=check):
        manifest = capture.capture(config, source)
    assert manifest.exists() and len(replays) == 2
    assert replays[0][1].parent != Path(directory) and replays[1][1] == config.prefix
    assert not list(Path(directory).glob(f'.{config.lane}.*'))
    assert all(reader.closed for reader in source.opened_rings)
    assert config.finish.exists()
    assert len({deadline for _, deadline in source.calls}) == 1
    for fd in source.closed_fds:
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            raise AssertionError('map reference not closed')


def shell_wait_failure(directory, mode):
    directory = Path(directory)
    workload = directory / 'canary_workload'
    workload.write_text('#!/bin/sh\ntouch "$3"\nexec sleep 30\n')
    workload.chmod(0o700)
    shell = (ROOT / 'scripts/verify-canaries.sh').read_text()
    def function(name):
        return shell.split(name + '() {', 1)[1].split('\n}\n', 1)[0].join((name + '() {', '\n}\n'))
    program = ('set -eu\nWORK=' + str(directory) + '\n'
        'WPID=\nWORKLOAD_STARTTIME=\nTARGET_BITS=64\n'
        'P11SCOPE_DEFAULT=/bin/true\nP11SCOPE_FEATURE=/bin/true\n'
        'TASK_STORAGE_READER=/bin/true\nTASK_STORAGE_OBJECT=/bin/true\n'
        'process_starttime() { echo 1; }\n'
        'process_matches_starttime() { kill -0 "$1"; }\n'
        'signal_verified_process() { kill -"$1" "$2"; }\n'
        'reclaim_root_output() { :; }\n'
        'sudo() { :; }\nassert_lanes() { :; }\npython3() { :; }\n'
        'WAIT_FAILED=\nwait() { if [ -z "$WAIT_FAILED" ]; then WAIT_FAILED=1; return 127; fi; command wait "$@"; }\n'
        + function('cleanup') + 'trap cleanup EXIT\n' + function('refuse_lane_destinations')
        + function('run_lane') + function('run_start_lane')
        + ('run_lane aggregate-only-metrics default metrics\n' if mode == 'matrix' else
           'run_start_lane default-safe-start default blocked 4 --hostile-starts\n')
        + 'echo "=== canary matrix: ALL OK ==="\n')
    result = subprocess.run(['sh', '-c', program], capture_output=True, text=True, timeout=4)
    assert result.returncode != 0 and 'ALL OK' not in result.stdout, result
    assert '127' in result.stdout, result


def coordinator_case(pid, directory, case):
    if case.startswith('shell:'):
        return shell_wait_failure(directory, case.split(':', 1)[1])
    kind, _, detail = case.partition(':')
    lane = detail if kind in ('native', 'binding') else 'aggregate-only-metrics'
    if kind == 'binding':
        lane, detail = detail.split(':', 1)
    config = config_for(pid, directory, lane)
    source = FakeMaps(config)
    coordinator = capture.Coordinator(config, source)
    owner, test_handles, signals, checks, replay_paths = c.Custody(), [], [], [], []
    original_launch, original_signal = owner.launch, signal.pidfd_send_signal
    original_check = coordinator.check
    original_replay, original_dump, original_frames = capture.evidence.assert_stopped_snapshot, source.dump, source.frames
    original_inventory, original_positions = source.inventory, source.positions
    original_stopped_rows = capture.stopped_rows
    roster_samples, start_dumps = {}, 0
    original_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    expected_success = kind in ('native', 'immediate_exit')
    started_at = time.monotonic()
    initial_descriptors = open_descriptors()
    failed_resume = False
    replay_count, inventory_count, position_count = 0, 0, 0
    sentinel = Path(directory) / 'unrelated.sentinel'
    sentinel.write_bytes(b'preserve unrelated bytes')
    if kind == 'fifo' and detail == 'ready':
        config.ready.unlink()
        os.mkfifo(config.ready, 0o600)
    if kind == 'stale':
        destination = Path(directory) / ('mapdump_START_aggregate-only-metrics.json' if detail == 'ordinary'
                                       else 'mapdump_manifest_aggregate-only-metrics.json')
        destination.write_bytes(b'preserve stale bytes')
    if kind == 'policy':
        if detail == 'ignored':
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        else:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    if kind == 'config':
        if detail == 'lane':
            config.privacy = 'allowlisted'
        elif detail == 'width':
            config.target_bits = 16
        else:
            roster = json.loads(config.ready.read_text())
            roster['tasks'].append(dict(roster['tasks'][0]))
            config.ready.write_text(json.dumps(roster))
    if kind in ('immediate_exit', 'immediate_bad_exit'):
        config.observer_args = [sys.executable, '-c',
            f"import signal,time,sys; signal.signal(signal.SIGCONT,lambda *_: sys.exit({0 if kind == 'immediate_exit' else 7})); "
            "print('fixture — privacy=aggregate-only',flush=True); time.sleep(10)"]
    def launch(*args, **kwargs):
        observer = original_launch(*args, **kwargs)
        test_handles.append(os.dup(observer.group.fd))
        if kind == 'fifo':
            (Path(directory) / 'fifo-observer.pid').write_text(str(observer.popen.pid))
        return observer
    def send(fd, number, *args):
        nonlocal failed_resume
        signals.append((fd, number))
        if number == signal.SIGSTOP and any(group.fd == fd and group.role == 'workload' for group in owner.groups):
            if config.workload_mode == 'matrix':
                assert config.done.is_file(), 'matrix STOP preceded DONE'
                assert capture.read_json(config.done, deadline=coordinator.stopped_deadline)['generation'] == config.generation
        if kind == 'resume' and number == signal.SIGCONT and not failed_resume:
            failed_resume = True
            raise PermissionError('resume sentinel raw material')
        return original_signal(fd, number, *args)
    def check(phase, deadline=None):
        checks.append(phase)
        original_check(phase, deadline)
        if kind == 'fifo' and detail == 'done' and phase == 'GO-created':
            observer = next(group for group in owner.groups if group.role == 'observer')
            assert all(row[1] == 'T' for row in observer.snapshot(deadline).values())
            assert config.go.is_file()
            os.mkfifo(config.done, 0o600)
        if kind in ('phase', 'cancel') and phase == detail:
            if kind == 'cancel':
                os.kill(os.getpid(), signal.SIGTERM)
                original_check(phase, deadline)
            raise AssertionError('SECRET_RAW_CONTEXT')
        if kind == 'ring_open' and phase == 'rings-retained':
            raise OSError('injected after both retained readers')
    def replay(manifest, prefix):
        nonlocal replay_count
        replay_count += 1
        replay_paths.append(Path(prefix))
        assert not (Path(directory) / f'mapdump_manifest_{config.lane}.json').exists()
        if replay_count == 2:
            assert not owner.active and all(group.closed for group in owner.groups)
            assert all(reader.closed for reader in source.opened_rings)
        if kind == 'replay' and replay_count == int(detail):
            raise AssertionError('SECRET_RAW_CONTEXT')
        return original_replay(manifest, prefix)
    def inventory(group, deadline):
        nonlocal inventory_count
        inventory_count += 1
        maps = original_inventory(group, deadline)
        if kind == 'inventory':
            if detail == 'definition':
                maps[0]['max_entries'] += 1
                capture.validate_inventory(maps, config.variant)
            elif inventory_count == 2:
                maps[0]['id'] += 9000
        return maps
    def stopped_rows(group, deadline, expected):
        rows = original_stopped_rows(group, deadline, expected)
        roster_samples[group.role] = roster_samples.get(group.role, 0) + 1
        if kind == 'roster' and group.role == detail and roster_samples[group.role] == 2:
            rows[0]['generation'] += 1
        return rows
    def positions():
        nonlocal position_count
        position_count += 1
        result = original_positions()
        if kind == 'ring' and position_count == 2:
            result[detail] = (0, 8)
        return result
    def dump(item, deadline, bound):
        nonlocal start_dumps
        if kind == 'deadline':
            time.sleep(.1)
        rows = original_dump(item, deadline, bound)
        if kind == 'population' and item['name'] == 'COOKIE_CTL':
            rows[0]['value'][8] = '01'
        if kind == 'binding' and item['name'] == 'START':
            start_dumps += 1
            raw = bytearray(capture.evidence.bpftool_bytes(rows[0]['key'], 16))
            value = bytearray(capture.evidence.bpftool_bytes(rows[0]['value'], 288))
            if detail == 'tid':
                struct.pack_into('<Q', raw, 0, (pid << 32) | pid)
            elif detail == 'padding':
                struct.pack_into('<I', raw, 12, 1)
            elif detail == 'slot':
                struct.pack_into('<I', raw, 8, 512)
            elif detail == 'session':
                struct.pack_into('<Q', value, 8, 0xDEAD)
            elif detail == 'slot_relationship':
                struct.pack_into('<I', raw, 8, 29)
            elif detail == 'key_change' and start_dumps > 1:
                struct.pack_into('<I', raw, 8, 8)
            rows[0]['key'], rows[0]['value'] = list(raw), list(value)
        return rows
    def frames(*args):
        raw = original_frames(*args)
        if kind == 'frames':
            return raw[:-1]
        if kind == 'cookie':
            cookie_id = next(item['id'] for item in source.maps if item['name'] == 'TASK_COOKIE')
            return (capture.dumper.TASK_STORAGE_HEADER.pack(capture.dumper.TASK_STORAGE_MAGIC, 1,
                    cookie_id, pid, pid, 8) + struct.pack('<Q', 1) + raw)
        if kind == 'binding' and detail == 'owner_count':
            raw = bytearray(raw)
            offset = 0
            while offset < len(raw):
                header = capture.dumper.TASK_STORAGE_HEADER.unpack_from(raw, offset)
                if header[5] == 544:
                    struct.pack_into('<I', raw, offset + capture.dumper.TASK_STORAGE_HEADER.size + 536, 2)
                offset += capture.dumper.TASK_STORAGE_HEADER.size + header[5]
            return bytes(raw)
        return raw
    errors = []
    try:
        with ExitStack() as stack:
            for target, attr, kwargs in (
                (c, 'Custody', {'return_value': owner}), (owner, 'launch', {'side_effect': launch}),
                (signal, 'pidfd_send_signal', {'side_effect': send}),
                (coordinator, 'check', {'side_effect': check}),
                (capture.evidence, 'assert_stopped_snapshot', {'side_effect': replay}),
                (source, 'inventory', {'side_effect': inventory}),
                (source, 'positions', {'side_effect': positions}),
                (capture, 'stopped_rows', {'side_effect': stopped_rows}),
                (source, 'dump', {'side_effect': dump}), (source, 'frames', {'side_effect': frames})):
                stack.enter_context(patch.object(target, attr, **kwargs))
            if kind not in ('native', 'binding', 'fifo'):
                stack.enter_context(patch.object(capture, 'wait_done', side_effect=synthetic_done))
            if kind == 'terminal_restore':
                set_signal = signal.signal
                failed_restore = []
                def restore_failed(number, handler):
                    if not owner.active and number == signal.SIGINT and handler == original_handlers[number] and not failed_restore:
                        failed_restore.append(number)
                        raise OSError('SECRET_RAW_CONTEXT')
                    return set_signal(number, handler)
                stack.enter_context(patch.object(signal, 'signal', side_effect=restore_failed))
            if kind == 'deadline':
                stack.enter_context(patch.object(capture, 'STOP_SECONDS', .08))
            if kind == 'boundary':
                if detail == 'pin':
                    def pin_failed(*args):
                        source.fds.append(os.open('/dev/null', os.O_RDONLY))
                        raise OSError('SECRET_RAW_CONTEXT')
                    stack.enter_context(patch.object(source, 'pin', side_effect=pin_failed))
                elif detail == 'open_rings':
                    def open_failed(*args):
                        reader = FakeRing([])
                        source.rings['DISCOVERY'] = reader
                        source.opened_rings.append(reader)
                        raise OSError('SECRET_RAW_CONTEXT')
                    stack.enter_context(patch.object(source, 'open_rings', side_effect=open_failed))
                elif detail == 'ring_records':
                    stack.enter_context(patch.object(source, 'ring_records', side_effect=OSError('SECRET_RAW_CONTEXT')))
                elif detail == 'fsync':
                    stack.enter_context(patch.object(os, 'fsync', side_effect=OSError('SECRET_RAW_CONTEXT')))
                elif detail == 'ring_close':
                    ring_close = FakeRing.close
                    def ring_close_failed(reader):
                        ring_close(reader)
                        if reader is source.opened_rings[0]:
                            raise OSError('SECRET_RAW_CONTEXT')
                    stack.enter_context(patch.object(FakeRing, 'close', ring_close_failed))
            if kind == 'bytes':
                stack.enter_context(patch.object(capture, 'MAX_BYTES', 1024))
            if kind == 'close':
                close = source.close
                def close_failed():
                    close()
                    raise OSError('SECRET_RAW_CONTEXT') from PermissionError('second cleanup secret')
                stack.enter_context(patch.object(source, 'close', side_effect=close_failed))
            if kind == 'publication':
                publish = coordinator.files.publish
                def publish_failed(staged, destination):
                    if detail == 'collision':
                        destination.write_bytes(b'preserve raced destination')
                        return publish(staged, destination)
                    publish(staged, destination)
                    raise OSError('SECRET_RAW_CONTEXT')
                stack.enter_context(patch.object(coordinator.files, 'publish', side_effect=publish_failed))
            if kind in ('rollback', 'stage_remove'):
                unlink = Path.unlink
                refused = []
                def unlink_failed(path, *args, **kwargs):
                    if not refused and path.name.startswith('mapdump_'):
                        refused.append(path)
                        raise PermissionError('SECRET_RAW_CONTEXT')
                    return unlink(path, *args, **kwargs)
                stack.enter_context(patch.object(Path, 'unlink', unlink_failed))
                if kind == 'rollback':
                    stack.enter_context(patch.object(capture.evidence, 'assert_stopped_snapshot', side_effect=AssertionError('SECRET_RAW_CONTEXT')))
            try:
                result = coordinator.run()
            except capture.CaptureError as error:
                errors.append(str(error))
                assert 'SECRET' not in str(error) and 'raw material' not in str(error)
                assert error.__suppress_context__
            else:
                assert expected_success, ('unexpected successful capture', case)
                assert result.is_file()
        assert bool(errors) != expected_success, (case, errors)
        assert not owner.active and all(group.closed for group in owner.groups)
        assert all(reader.closed for reader in source.opened_rings)
        assert sentinel.read_bytes() == b'preserve unrelated bytes'
        if kind == 'fifo':
            assert open_descriptors() == initial_descriptors | set(test_handles)
            assert time.monotonic() - started_at < 2, 'FIFO refusal was not prompt'
            assert not source.opened_rings and not source.closed_fds
            if detail == 'ready':
                assert not owner.groups and not test_handles and not config.observer_log.exists()
                assert not config.go.exists() and not config.finish.exists()
            else:
                observer = next(group for group in owner.groups if group.role == 'observer')
                assert (observer.fd, signal.SIGSTOP) in signals
                assert (observer.fd, signal.SIGCONT) in signals
                assert config.finish.is_file()
        if kind == 'policy':
            assert not owner.groups and not test_handles
            if detail == 'ignored':
                assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
            else:
                assert signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if kind == 'stale':
            assert destination.read_bytes() == b'preserve stale bytes'
            assert not owner.groups and not test_handles
        elif not expected_success:
            assert not (Path(directory) / f'mapdump_manifest_{config.lane}.json').exists()
            published = list(Path(directory).glob('mapdump_*'))
            if kind == 'publication' and detail == 'collision':
                assert len(published) == 1 and published[0].read_bytes() == b'preserve raced destination'
            else:
                assert not published, published
            assert not list(Path(directory).glob(f'.{config.lane}.*'))
        if kind == 'close':
            assert 'OSError' in errors[0] and 'PermissionError' in errors[0]
        if coordinator.go_created and config.workload_mode == 'matrix':
            assert config.finish.exists()
        if kind == 'deadline':
            assert 'deadline expired' in errors[0] and time.monotonic() - started_at < 2
        if kind in ('resume', 'immediate_bad_exit'):
            groups = {group.role: group for group in owner.groups}
            assert (groups['observer'].fd, signal.SIGCONT) in signals
            assert (groups['workload'].fd, signal.SIGCONT) in signals
        if expected_success:
            assert replay_count == 2 and replay_paths[0].parent != Path(directory)
        for fd in test_handles:
            assert select.select([fd], [], [], 1)[0]
            try:
                os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                raise AssertionError('observer ordinary wait was not owned and settled')
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        for number, handler in original_handlers.items():
            signal.signal(number, handler)
        for fd in test_handles:
            try:
                original_signal(fd, signal.SIGCONT)
                original_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if owner.active:
            owner.close()
        for fd in test_handles:
            os.close(fd)


OWNED_OBSERVER = r'''import json, os, pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[0]).parent
control = json.loads((root / 'owned-control.json').read_text())
case = control['case']
args = sys.argv[1:]
assert len(args) == 20 and args[:2] == ['run', '--manifest']
assert args[3:10] == ['--mode', 'metrics', '--pause', 'never', '--duration', '120', '--kill-on-timeout']
assert args[10] == '-o' and args[12] == '--'
assert args[15] == 'matrix'
ready = pathlib.Path(args[16])
def marker():
    print('fixture — privacy=aggregate-only', flush=True)
def record(pid):
    with (root / 'owned-pids').open('a') as stream:
        stream.write(str(pid) + '\n')
record(os.getpid())
if case.startswith('capture_first'):
    marker()
    time.sleep(.08)
if case in ('death_unknown', 'missing_ready'):
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    record(child.pid)
    if case == 'missing_ready':
        marker()
        child.wait()
    time.sleep(.08)
    os._exit(7)
if case == 'wrong_executable':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    record(child.pid)
    generation = int(pathlib.Path('/proc/%d/stat' % child.pid).read_text().rsplit(') ',1)[1].split()[19])
    ready.write_text(json.dumps(dict(schema='p11scope/canary-roster/v1', mode='matrix', pid=child.pid,
        tasks=[dict(pid=child.pid, tid=child.pid, generation=generation, role='leader', call_index=None)])))
else:
    child = subprocess.Popen(args[13:])
    record(child.pid)
end = time.monotonic() + 3
while not ready.exists():
    assert child.poll() is None and time.monotonic() < end
    time.sleep(.005)
if case == 'extra_child':
    extra = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    record(extra.pid)
if case in ('stale_generation', 'foreign_ready'):
    roster = json.loads(ready.read_text())
    if case == 'stale_generation':
        roster['tasks'][0]['generation'] += 1
    else:
        roster['pid'] = control['outside_pid']
        roster['tasks'][0].update(pid=roster['pid'], tid=roster['pid'], generation=control['outside_generation'])
    ready.write_text(json.dumps(roster))
if not case.startswith('capture_first'):
    time.sleep(1 if case == 'missing_capture' else .08)
    marker()
status = child.wait()
(root / 'owned-wait.json').write_text(json.dumps({'status': status, 'pid': child.pid}))
sys.exit(7 if case == 'observer_bad_exit' else status)
'''


def owned_config(pid, directory, case, program, provider):
    directory = Path(directory)
    lane = 'owned-feature-metrics' if case.endswith('_feature') else 'owned-default-metrics'
    prefix = directory / lane
    executable = directory / 'owned-observer'
    executable.write_text('#!' + sys.executable + '\n' + OWNED_OBSERVER)
    executable.chmod(0o700)
    (directory / 'owned-control.json').write_text(json.dumps({'case': case,
        'outside_pid': pid, 'outside_generation': generation(pid)}))
    (directory / 'matrix-manifest.json').write_text('{}')
    variant, mode, privacy, workload_mode = capture.LANES[lane]
    config = SimpleNamespace(lane=lane, variant=variant, mode=mode, privacy=privacy,
        workload_mode=workload_mode, workload_origin='owned', workload_pid=None, generation=None,
        target_bits=64, out_dir=directory, prefix=prefix, reader=Path(sys.executable), obj=Path(sys.executable),
        **{name: Path(f'{prefix}.{suffix}') for name, suffix in (
            ('ready', 'ready'), ('go', 'go'), ('done', 'done'), ('finish', 'finish'),
            ('observer_log', 'observer.log'), ('workload_log', 'observer.log'))})
    config.observer_args = [str(executable), 'run', '--manifest', str(directory / 'matrix-manifest.json'),
        '--mode', 'metrics', '--pause', 'never', '--duration', '120', '--kill-on-timeout', '-o',
        str(prefix) + '.output', '--', program, provider, 'matrix', str(config.ready),
        str(config.go), str(config.done), str(config.finish)]
    return config


def owned_case(pid, directory, case, program, provider):
    config = owned_config(pid, directory, case, program, provider)
    source = FakeMaps(config)
    coordinator, owner = capture.Coordinator(config, source), c.Custody()
    handles, signals, waits, replays, readiness_deadlines = [], [], [], [], []
    launch, retain, send = owner.launch, owner.retain_observer_child, signal.pidfd_send_signal
    check, frames, dump = coordinator.check, source.frames, source.dump
    replay = capture.evidence.assert_stopped_snapshot
    positive = case.startswith(('ready_first', 'capture_first'))
    def launched(*args, **kwargs):
        readiness_deadlines.append(kwargs['deadline'])
        observer = launch(*args, **kwargs)
        handles.append(os.dup(observer.group.fd))
        return observer
    def retained(*args, **kwargs):
        assert args[3] == readiness_deadlines[0], 'owned readiness budget was reset'
        group = retain(*args, **kwargs)
        handles.append(os.dup(group.fd))
        assert group.wait_owner == 'observer' and group.origin == 'observer-child'
        assert all(process.group is not group for process in owner.processes)
        # While the observer is alive, this coordinator cannot consume its
        # child's ordinary status even when using its retained pidfd.
        try:
            os.waitid(os.P_PIDFD, group.fd, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            waits.append('ECHILD')
        else:
            raise AssertionError('coordinator stole observer child wait')
        return group
    def sent(fd, number, *args):
        signals.append((fd, number))
        if number == signal.SIGSTOP:
            group = next(group for group in owner.groups if group.fd == fd)
            if group.role == 'workload':
                assert config.done.is_file(), 'owned workload STOP preceded DONE'
        return send(fd, number, *args)
    def checked(phase, deadline=None):
        check(phase, deadline)
        if case == 'death_stopped' and phase == 'workload-stopped':
            observer = next(group for group in owner.groups if group.role == 'observer')
            send(observer.fd, signal.SIGKILL)
            assert select.select([observer.fd], [], [], 1)[0]
            raise capture.CaptureError('injected observer death after workload STOP')
    def framed(*args):
        raw = frames(*args)
        header = capture.dumper.TASK_STORAGE_HEADER
        if case == 'root_missing':
            return raw[header.size + 8:]
        if case == 'root_invalid':
            raw = bytearray(raw)
            struct.pack_into('<Q', raw, header.size, 0x100000001)
            return bytes(raw)
        if case in ('cookie', 'owner'):
            name, size = ('TASK_COOKIE', 8) if case == 'cookie' else ('THREAD_OWNER', 544)
            item = next(item for item in source.maps if item['name'] == name)
            value = struct.pack('<Q', 1) + bytes(size - 8)
            return header.pack(capture.dumper.TASK_STORAGE_MAGIC, 1, item['id'], config.workload_pid,
                               config.workload_pid, size) + value + raw
        return raw
    def dumped(item, *args):
        rows = dump(item, *args)
        if (case == 'root_control' and item['name'] == 'ROOT_CTL') or (
                case == 'cookie_history' and item['name'] == 'COOKIE_CTL'):
            rows[0]['value'][8] = '01'
        if case == 'start' and item['name'] == 'START':
            rows.append({'key': list(bytes(16)), 'value': list(bytes(288))})
        return rows
    def replayed(manifest, prefix):
        replays.append(Path(prefix))
        assert not (Path(directory) / f'mapdump_manifest_{config.lane}.json').exists()
        if len(replays) == 2:
            observer = next(process for process in owner.processes if process.group.role == 'observer')
            assert observer.settled and observer.popen.returncode == 0
            assert json.loads((Path(directory) / 'owned-wait.json').read_text())['status'] == 0
            assert not owner.active and all(group.closed for group in owner.groups)
        return replay(manifest, prefix)
    error = None
    try:
        with ExitStack() as stack:
            for target, name, side_effect in ((owner, 'launch', launched),
                    (owner, 'retain_observer_child', retained), (signal, 'pidfd_send_signal', sent),
                    (coordinator, 'check', checked), (source, 'frames', framed), (source, 'dump', dumped),
                    (capture.evidence, 'assert_stopped_snapshot', replayed)):
                stack.enter_context(patch.object(target, name, side_effect=side_effect))
            stack.enter_context(patch.object(c, 'Custody', return_value=owner))
            if case in ('missing_ready', 'missing_capture'):
                stack.enter_context(patch.object(capture, 'READY_SECONDS', .25))
            if case == 'unavailable_children':
                children = c.Group.children
                def unavailable(group, *args, **kwargs):
                    if group.role == 'observer':
                        raise c.CustodyError('injected unavailable complete child census')
                    return children(group, *args, **kwargs)
                stack.enter_context(patch.object(c.Group, 'children', side_effect=unavailable, autospec=True))
            if case == 'events':
                opened = source.open_rings
                def event(*args):
                    opened(*args)
                    source.rings['EVENTS'].rows = [fixtures.event_bytes(0)]
                stack.enter_context(patch.object(source, 'open_rings', side_effect=event))
            try:
                manifest = coordinator.run()
            except capture.CaptureError as caught:
                error = caught
        assert (error is None) == positive, (case, error)
        assert not owner.active and all(group.closed for group in owner.groups)
        assert all(reader.closed for reader in source.opened_rings)
        assert not Path(str(config.prefix) + '.workload.log').exists()
        if positive:
            assert manifest.is_file() and len(replays) == 2 and waits == ['ECHILD']
            assert config.done.is_file() and config.finish.is_file()
            assert 'canary_workload matrix: all calls CKR_OK' in config.observer_log.read_text()
            receipt = json.loads((Path(directory) / f'mapdump_snapshot_{config.lane}.json').read_text())
            assert receipt['lane'] == 'owned-root' and receipt['expected'][0]['root'] is True
            assert receipt['expected'][0]['cookie'] is False and receipt['expected'][0]['owner'] is False
            for group in owner.groups:
                if group.role in ('observer', 'workload'):
                    assert (group.fd, signal.SIGSTOP) in signals and (group.fd, signal.SIGCONT) in signals
        else:
            assert not list(Path(directory).glob('mapdump_*'))
            assert not list(Path(directory).glob(f'.{config.lane}.*'))
        if case in ('death_unknown', 'death_stopped'):
            assert 'custody-close' in str(error), str(error)
        if case in ('missing_ready', 'missing_capture'):
            assert 'phase deadline expired' in str(error), str(error)
            assert not config.go.exists() and not source.opened_rings
        for fd in handles:
            assert select.select([fd], [], [], 1)[0], 'owned process survived cleanup'
    finally:
        for fd in handles:
            try:
                send(fd, signal.SIGCONT)
                send(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if owner.active:
            owner.close()
        for fd in handles:
            os.close(fd)


class StoppedCanaryCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.program = Path(cls.build.name) / 'workload'
        cls.matrix = Path(cls.build.name) / 'matrix.so'
        cls.blocked = Path(cls.build.name) / 'blocked.so'
        for argv in (["cc", "-m64", "-std=c11", "-pthread", "-o", str(cls.program),
                      str(ROOT / 'scripts/fixtures/canary_workload.c'), "-ldl"],
                     ["cc", "-m64", "-shared", "-fPIC", "-DPRIVACY_FIXTURE=1", "-o", str(cls.matrix),
                      str(ROOT / 'crates/discover/tests/fixture/version_matrix.c')],
                     ["cc", "-m64", "-shared", "-fPIC", "-DPRIVACY_FIXTURE=1", "-DPRIVACY_BLOCKS=1",
                      "-o", str(cls.blocked), str(ROOT / 'crates/discover/tests/fixture/version_matrix.c')]):
            subprocess.run(argv, check=True, capture_output=True, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def probe(self, name):
        old = c._subreaper()
        c._subreaper(1)
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        outside = os.pidfd_open(child.pid)
        workload, workload_fd, log, fifo_observer_fd = None, None, None, None
        owned_handles = {}
        try:
            with tempfile.TemporaryDirectory() as directory:
                pid = child.pid
                if name.startswith(('case:native:', 'case:binding:')):
                    lane = name.split(':')[2]
                    mode = capture.LANES[lane][3]
                    prefix = Path(directory) / lane
                    argv = [str(self.program), str(self.matrix if mode == 'matrix' else self.blocked), mode,
                            str(prefix) + '.ready', str(prefix) + '.go']
                    if mode == 'matrix':
                        argv += [str(prefix) + '.done', str(prefix) + '.finish']
                    log = open(str(prefix) + '.workload.log', 'wb')
                    workload = subprocess.Popen(argv, stdout=log, stderr=log)
                    workload_fd = os.pidfd_open(workload.pid)
                    pid = workload.pid
                    end = time.monotonic() + 3
                    while not Path(str(prefix) + '.ready').exists():
                        assert workload.poll() is None and time.monotonic() < end, 'native READY unavailable'
                        time.sleep(.005)
                command = ['timeout', '--kill-after=1s', '2s' if name.startswith('case:fifo:') else '12s',
                           sys.executable, '-I', __file__, '--probe', name, str(pid), directory]
                if name.startswith('owned:'):
                    command += [str(self.program), str(self.matrix)]
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    marker = Path(directory) / 'owned-pids'
                    end = time.monotonic() + 14
                    while process.poll() is None and time.monotonic() < end:
                        if marker.exists():
                            for line in marker.read_text().splitlines():
                                if line.isdecimal() and int(line) not in owned_handles:
                                    try:
                                        owned_handles[int(line)] = os.pidfd_open(int(line))
                                    except ProcessLookupError:
                                        pass
                        time.sleep(.005)
                    stdout, stderr = process.communicate(timeout=2)
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                elif name.startswith('case:fifo:'):
                    # Keep an observer handle outside the watchdog's process
                    # tree: even a RED coordinator killed while blocked cannot
                    # strand its stopped observer during test teardown.
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    marker = Path(directory) / 'fifo-observer.pid'
                    end = time.monotonic() + 4
                    while process.poll() is None and time.monotonic() < end:
                        if fifo_observer_fd is None and marker.exists():
                            try:
                                fifo_observer_fd = os.pidfd_open(int(marker.read_text()))
                            except (ProcessLookupError, ValueError):
                                pass
                        time.sleep(.005)
                    stdout, stderr = process.communicate(timeout=2)
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    if name == 'case:fifo:done' and result.returncode != 0:
                        self.assertIsNotNone(fifo_observer_fd, 'RED observer teardown handle was not retained')
                else:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=14)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(select.select([outside], [], [], 0)[0])
                if workload is not None:
                    if mode == 'matrix':
                        self.assertEqual(workload.wait(timeout=2), 0)
                    else:
                        signal.pidfd_send_signal(workload_fd, signal.SIGTERM)
                        self.assertEqual(workload.wait(timeout=2), -signal.SIGTERM)
                self.assertEqual(c._children(os.getpid(), [os.getpid()], time.monotonic() + 1), [child.pid])
        finally:
            for fd in owned_handles.values():
                try:
                    signal.pidfd_send_signal(fd, signal.SIGCONT)
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(fd)
            if fifo_observer_fd is not None:
                try:
                    signal.pidfd_send_signal(fifo_observer_fd, signal.SIGCONT)
                    signal.pidfd_send_signal(fifo_observer_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(fifo_observer_fd)
            if workload_fd is not None:
                try:
                    signal.pidfd_send_signal(workload_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                workload.wait(timeout=2)
                os.close(workload_fd)
            if log is not None:
                log.close()
            try:
                signal.pidfd_send_signal(outside, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2)
            os.close(outside)
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
            c._subreaper(old)

    def test_regular_reader_rejects_symlink_directory_device_and_socket(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as sock:
            root = Path(directory)
            target = root / 'target'
            target.write_bytes(b'SECRET_FILE_BYTES')
            alias = root / 'alias'
            alias.symlink_to(target)
            endpoint = root / 'socket'
            sock.bind(str(endpoint))
            for path in (alias, root, Path('/dev/null'), endpoint):
                with self.subTest(path=path.name):
                    before = open_descriptors()
                    with patch.object(os, 'read', side_effect=AssertionError('nonregular read attempted')) as read:
                        with self.assertRaises((capture.CaptureError, OSError)):
                            capture.read_bytes(path, 64, time.monotonic() + 1)
                        read.assert_not_called()
                    self.assertEqual(open_descriptors(), before)
            self.assertEqual(target.read_bytes(), b'SECRET_FILE_BYTES')

    def test_regular_reader_bounds_actual_bytes_and_accepts_zero_size_proc_fdinfo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bytes'
            raw = b'x' * 65536 + b'y'
            path.write_bytes(raw)
            before = open_descriptors()
            self.assertEqual(capture.read_bytes(path, len(raw), time.monotonic() + 1), raw)
            with self.assertRaisesRegex(capture.CaptureError, 'input byte bound exceeded'):
                capture.read_bytes(path, len(raw) - 1, time.monotonic() + 1)
            real_read = os.read
            path.write_bytes(b'partial reads')
            with patch.object(os, 'read', side_effect=lambda fd, bound: real_read(fd, min(bound, 3))):
                self.assertEqual(capture.read_bytes(path, 13, time.monotonic() + 1), b'partial reads')
            path.write_bytes(b'')
            self.assertEqual(capture.read_bytes(path, 0, time.monotonic() + 1), b'')
            with path.open('rb') as stream:
                fdinfo = Path(f'/proc/self/fdinfo/{stream.fileno()}')
                self.assertEqual(fdinfo.stat().st_size, 0)
                self.assertIn(b'pos:', capture.read_bytes(fdinfo, 65536, time.monotonic() + 1))
            self.assertEqual(open_descriptors(), before)

    def test_regular_reader_checks_deadlines_before_open_and_after_io_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'{}')
            before = open_descriptors()
            with patch.object(os, 'open') as opened:
                with self.assertRaisesRegex(capture.CaptureError, 'deadline expired'):
                    capture.read_bytes(path, 64, time.monotonic() - 1)
                opened.assert_not_called()
            for boundary in ('open', 'read', 'close', 'json'):
                with self.subTest(boundary=boundary):
                    now, handles = [10.0], []
                    real_open, real_read, real_close, real_json = os.open, os.read, os.close, json.loads
                    def opened(*args):
                        fd = real_open(*args)
                        handles.append(fd)
                        if boundary == 'open':
                            now[0] = 12.0
                        return fd
                    def read(*args):
                        value = real_read(*args)
                        if boundary == 'read':
                            now[0] = 12.0
                        return value
                    def closed(fd):
                        real_close(fd)
                        if boundary == 'close':
                            now[0] = 12.0
                    def decoded(*args, **kwargs):
                        value = real_json(*args, **kwargs)
                        if boundary == 'json':
                            now[0] = 12.0
                        return value
                    with patch.object(time, 'monotonic', side_effect=lambda: now[0]), \
                            patch.object(os, 'open', side_effect=opened), \
                            patch.object(os, 'read', side_effect=read), \
                            patch.object(os, 'close', side_effect=closed) as close, \
                            patch.object(json, 'loads', side_effect=decoded):
                        with self.assertRaisesRegex(capture.CaptureError, 'deadline expired'):
                            capture.read_json(path, deadline=11.0)
                        self.assertEqual(close.call_count, 1)
                    self.assertEqual(len(handles), 1)
                    self.assertEqual(open_descriptors(), before)

    def test_regular_reader_closes_once_and_preserves_sanitized_read_and_close_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'SECRET_FILE_BYTES')
            for failure in ('fstat', 'read', 'close', 'read_and_close'):
                with self.subTest(failure=failure):
                    before = open_descriptors()
                    real_close = os.close
                    def closed(fd):
                        real_close(fd)
                        if failure in ('close', 'read_and_close'):
                            raise OSError('SECRET_CLOSE_FAILURE')
                    with ExitStack() as stack:
                        close = stack.enter_context(patch.object(os, 'close', side_effect=closed))
                        if failure == 'fstat':
                            stack.enter_context(patch.object(os, 'fstat', side_effect=PermissionError('SECRET_STAT_FAILURE')))
                        if failure in ('read', 'read_and_close'):
                            stack.enter_context(patch.object(os, 'read', side_effect=PermissionError('SECRET_READ_FAILURE')))
                        with self.assertRaises(capture.CaptureError) as raised:
                            capture.read_bytes(path, 64, time.monotonic() + 1)
                        self.assertEqual(close.call_count, 1)
                    message = str(raised.exception)
                    self.assertNotIn('SECRET', message)
                    self.assertTrue(raised.exception.__suppress_context__)
                    if failure == 'read_and_close':
                        self.assertIn('read-input: PermissionError', message)
                        self.assertIn('close-input: OSError', message)
                    self.assertEqual(open_descriptors(), before)

    def test_real_stop_refusal_resumes_only_observer_and_never_publishes(self):
        self.probe('first_refusal')

    def test_complete_metrics_replays_stage_and_final_before_manifest(self):
        self.probe('complete_metrics')

    def test_owned_argv_rejects_options_overrides_and_mismatched_paths_before_launch(self):
        changes = {'command': (1, 'profile'), 'manifest': (3, '/tmp/other-manifest.json'),
            'mode': (5, 'profile'), 'pause': (7, 'always'), 'duration': (9, '6'),
            'kill_timeout': (10, '--other'), 'output': (12, '/tmp/other-output'),
            'separator': (13, '--pid'), 'provider': (15, 'relative-provider.so'),
            'matrix': (16, 'blocked'), 'ready': (17, '/tmp/other-ready'),
            'go': (18, '/tmp/other-go'), 'done': (19, '/tmp/other-done'),
            'finish': (20, '/tmp/other-finish')}
        for problem in (*changes, 'duplicate_pause', 'missing_tail', 'missing_manifest'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                config = owned_config(os.getpid(), directory, 'ready_first', str(self.program), str(self.matrix))
                if problem in changes:
                    index, value = changes[problem]
                    config.observer_args[index] = value
                elif problem == 'duplicate_pause':
                    config.observer_args[10:10] = ['--pause', 'never']
                elif problem == 'missing_tail':
                    config.observer_args.pop()
                else:
                    (Path(directory) / 'matrix-manifest.json').unlink()
                with patch.object(c.Custody, 'launch') as launched:
                    with self.assertRaises(capture.CaptureError):
                        capture.capture(config, FakeMaps(config))
                    launched.assert_not_called()
                self.assertFalse(config.observer_log.exists())

    def test_owned_config_rejects_external_identity_origin_split_logs_and_stale_ready(self):
        for problem in ('pid', 'generation', 'origin', 'separate_log', 'stale_ready'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                config = owned_config(os.getpid(), directory, 'ready_first', str(self.program), str(self.matrix))
                if problem == 'pid':
                    config.workload_pid = os.getpid()
                elif problem == 'generation':
                    config.generation = generation(os.getpid())
                elif problem == 'origin':
                    config.workload_origin = 'external'
                elif problem == 'separate_log':
                    config.workload_log = Path(str(config.prefix) + '.workload.log')
                else:
                    config.ready.write_bytes(b'preserve stale READY')
                with patch.object(c.Custody, 'launch') as launched:
                    with self.assertRaises(capture.CaptureError):
                        capture.capture(config, FakeMaps(config))
                    launched.assert_not_called()
                self.assertFalse(config.observer_log.exists())
                if problem == 'stale_ready':
                    self.assertEqual(config.ready.read_bytes(), b'preserve stale READY')

    def test_origin_cli_requires_external_identity_and_forbids_owned_supplied_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            config = owned_config(os.getpid(), directory, 'ready_first', str(self.program), str(self.matrix))
            base = []
            for name in ('lane', 'variant', 'mode', 'privacy', 'workload_mode', 'out_dir', 'prefix',
                         'ready', 'go', 'done', 'finish', 'observer_log', 'workload_log', 'reader', 'obj',
                         'target_bits'):
                base += ['--' + name.replace('_', '-'), str(getattr(config, name))]
            parsed = capture.parse_args(base + ['--workload-origin', 'owned', '--'] + config.observer_args)
            self.assertIsNone(parsed.workload_pid)
            self.assertIsNone(parsed.generation)
            capture.validate_config(parsed)
            for options in ([], ['--workload-pid', str(os.getpid())], ['--generation', '1'],
                    ['--workload-origin', 'owned', '--workload-pid', '1'],
                    ['--workload-origin', 'owned', '--generation', '1'],
                    ['--workload-origin', 'unknown']):
                with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        capture.parse_args(base + options + ['--'] + config.observer_args)
                    self.assertEqual(raised.exception.code, 2)
            external = capture.parse_args(base + ['--workload-pid', str(os.getpid()), '--generation', '1',
                                                   '--'] + config.observer_args)
            self.assertEqual(external.workload_origin, 'external')


CASES = (
    ['native:' + lane for lane in ('aggregate-only-metrics', 'default-safe-profile', 'default-safe-trace',
                                   'feature-safe-profile', 'feature-safe-trace', 'default-safe-start',
                                   'feature-safe-start', 'feature-unsafe-fault',
                                   'feature-unsafe-profile', 'feature-unsafe-trace')]
    + ['binding:default-safe-start:' + problem for problem in
       ('tid', 'padding', 'slot', 'session', 'slot_relationship', 'owner_count', 'key_change')]
    + ['phase:' + phase for phase in ('observer-log', 'observer-stopped', 'GO-created', 'workload-stopped',
       'rings-retained', 'stage-created', 'dump-START', 'task-frames', 'retained-rings', 'after-identities',
       'retained-semantics', 'staged-replay-complete', 'custody-closed', 'final-replay-complete',
       'manifest-ready', 'manifest-published', 'publication-complete')]
    + ['cancel:' + phase for phase in ('workload-stopped', 'custody-closed', 'manifest-published')]
    + ['config:lane', 'config:width', 'config:roster', 'stale:ordinary', 'stale:manifest',
       'immediate_exit', 'immediate_bad_exit', 'resume', 'deadline', 'ring:EVENTS', 'ring:DISCOVERY',
       'inventory:definition', 'inventory:changed', 'population', 'frames', 'close',
       'replay:1', 'replay:2', 'publication:failure', 'publication:collision', 'rollback',
       'roster:observer', 'roster:workload', 'bytes', 'shell:matrix', 'shell:blocked', 'stage_remove',
       'policy:ignored', 'policy:blocked', 'terminal_restore', 'cookie', 'fifo:ready', 'fifo:done']
    + ['boundary:' + point for point in ('pin', 'open_rings', 'ring_records', 'fsync', 'ring_close')])
for case in CASES:
    def test(self, case=case):
        self.probe('case:' + case)
    setattr(StoppedCanaryCaptureTests, 'test_' + case.replace(':', '_').replace('-', '_'), test)

for case in ('ready_first', 'capture_first', 'ready_first_feature', 'capture_first_feature',
             'death_unknown', 'death_stopped', 'wrong_executable', 'extra_child', 'stale_generation',
             'foreign_ready', 'unavailable_children', 'root_missing', 'root_invalid', 'root_control',
             'cookie', 'cookie_history', 'owner', 'start', 'events', 'observer_bad_exit',
             'missing_ready', 'missing_capture'):
    def test(self, case=case):
        self.probe('owned:' + case)
    setattr(StoppedCanaryCaptureTests, 'test_owned_' + case, test)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--probe':
        if sys.argv[2].startswith('owned:'):
            owned_case(int(sys.argv[3]), sys.argv[4], sys.argv[2][6:], sys.argv[5], sys.argv[6])
        elif sys.argv[2].startswith('case:'):
            coordinator_case(int(sys.argv[3]), sys.argv[4], sys.argv[2][5:])
        else:
            globals()[sys.argv[2]](int(sys.argv[3]), sys.argv[4])
    else:
        unittest.main()
