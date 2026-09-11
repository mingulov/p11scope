#!/usr/bin/env python3
"""Isolated seeded task-storage byte controls for the closed canary oracle.

A fresh fixture process and fresh maps per control case, each inside its own
custody scope. The seeded bytes are private: they are written 0600 with O_EXCL
under a private out-dir that is never a capture-lane work root, and they never
reach a diagnostic. Full expected and read bytes are compared before any
expected scanner refusal is evaluated, so malformed evidence cannot pose as a
control. No Python result alone qualifies a live kernel, BPF build or target
ABI; the live run is a privileged gate.
"""
import argparse
import ctypes
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct
import sys
import time
from types import SimpleNamespace


def sibling(filename):
    spec = importlib.util.spec_from_file_location(filename, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coordinator = sibling('capture-stopped-canary.py')
custody = coordinator.custody
dumper = coordinator.dumper
evidence = coordinator.evidence
CaptureError = coordinator.CaptureError
require = coordinator.require
remaining = coordinator.remaining
sanitized = coordinator.sanitized

CONTRACT = 'p11scope/task-storage-seed-qualification/v1'
SCHEMA = 'p11scope/task-storage-canary/v1'
ABI = 'x86-64'
TARGET_BITS = 64
CASES = ('baseline', 'early', 'late')
# The fixture's fixed 560-byte seed: name, offset and value size, in order.
MAP_LAYOUT = (('TASK_COOKIE', 0, 8), ('THREAD_OWNER', 8, 544), ('ROOT_AFFILIATION', 552, 8))
OWNER_NAME = 'THREAD_OWNER'
SEED_SIZE = 560
OWNER_SIZE = 544
EARLY_OFFSET = 0
LATE_OFFSET = 535
COOKIE_CONTROL = b'SEEDCKVA'
ROOT_CONTROL = b'SEEDRTVA'
READY_FIELDS = frozenset(('schema', 'abi', 'pid', 'tid', 'generation', 'tasks', 'maps'))
TASK_FIELDS = frozenset(('pid', 'tid', 'generation'))
MAP_FIELDS = frozenset(('name', 'id', 'type', 'bytes_key', 'bytes_value', 'max_entries',
                        'map_flags'))
MAP_INTEGERS = ('id', 'bytes_key', 'bytes_value', 'max_entries', 'map_flags')
READY_BOUND = 2048
READY_SECONDS = 10
STOP_SECONDS = 30
RELEASE_SECONDS = 20
CLEANUP_SECONDS = 5
RECEIPT_SECONDS = 10
FIXTURE_TIMEOUT_MS = 60000
DIGEST_LIMIT = 64 * 1024 * 1024
FDINFO_LIMIT = 4096
BPF_SYSCALL = 321
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_TYPE_TASK_STORAGE = 29
INFO_SIZE = 192
KERNEL_NAME_LIMIT = 15
ELF_CLASS64 = 2
ELF_LITTLE_ENDIAN = 1
ELF_MACHINE_X86_64 = 62
ELF_MACHINE_I386 = 3


def is_uint(value, *, positive=False):
    return type(value) is int and value >= (1 if positive else 0)


def owner_baseline():
    """A known safe 544-byte value the real final-artifact scanner accepts."""
    return bytes(0x41 + (index % 26) for index in range(OWNER_SIZE))


def control_values(case):
    """The frozen three seeded values for one control case."""
    require(case in CASES, 'unknown seed control case')
    require(COOKIE_CONTROL != ROOT_CONTROL, 'cookie and root controls must be distinct')
    marker = evidence.SENTINELS['LEGACY_NAME']
    owner = bytearray(owner_baseline())
    if case == 'early':
        owner[EARLY_OFFSET:EARLY_OFFSET + len(marker)] = marker
    elif case == 'late':
        owner[LATE_OFFSET:LATE_OFFSET + len(marker)] = marker
        require(LATE_OFFSET + len(marker) == OWNER_SIZE, 'late control does not end at 544')
    values = {'TASK_COOKIE': COOKIE_CONTROL, OWNER_NAME: bytes(owner),
              'ROOT_AFFILIATION': ROOT_CONTROL}
    for name, _, size in MAP_LAYOUT:
        require(len(values[name]) == size, 'seed control value has the wrong length')
        require(any(values[name]), 'seed control value is entirely zero')
    return values


def seed_bytes(case):
    raw = b''.join(control_values(case)[name] for name, _, _ in MAP_LAYOUT)
    require(len(raw) == SEED_SIZE, 'seed is not the fixed 560-byte layout')
    return raw


def read_generation(pid, deadline):
    """/proc/PID/stat field 22, through the accepted custody proc decoder."""
    return custody._stat(pid, deadline)[0]


def validate_ready(document, pid, generation):
    """Exact frozen READY document, refusing every extra or altered field."""
    require(isinstance(document, dict) and set(document) == set(READY_FIELDS),
            'unexpected READY fields')
    require(document['schema'] == SCHEMA, 'unexpected READY schema')
    require(document['abi'] == ABI, 'unexpected READY ABI')
    require(is_uint(document['pid'], positive=True) and document['pid'] == pid,
            'READY names another process')
    require(is_uint(document['tid'], positive=True) and document['tid'] == pid,
            'READY names another task')
    require(is_uint(document['generation'], positive=True)
            and document['generation'] == generation, 'READY generation does not match proc')
    tasks = document['tasks']
    require(isinstance(tasks, list) and len(tasks) == 1, 'READY roster is not a single task')
    row = tasks[0]
    require(isinstance(row, dict) and set(row) == set(TASK_FIELDS),
            'unexpected READY roster fields')
    require(all(is_uint(row[key], positive=True) for key in TASK_FIELDS),
            'invalid READY roster identity')
    require((row['pid'], row['tid'], row['generation']) == (pid, pid, generation),
            'READY roster names another task')
    maps = document['maps']
    require(isinstance(maps, list) and len(maps) == len(MAP_LAYOUT),
            'READY does not carry the exact three maps')
    for item, (name, _, size) in zip(maps, MAP_LAYOUT):
        require(isinstance(item, dict) and set(item) == set(MAP_FIELDS),
                'unexpected READY map fields')
        require(item['name'] == name, 'unexpected READY map name or order')
        require(all(type(item[key]) is int for key in MAP_INTEGERS),
                'READY map metadata is not integral')
        require(is_uint(item['id'], positive=True), 'invalid READY map id')
        require((item['type'], item['bytes_key'], item['bytes_value'], item['max_entries'],
                 item['map_flags']) == ('task_storage', 4, size, 0, 1),
                'unexpected READY map metadata')
    ids = [item['id'] for item in maps]
    require(len(set(ids)) == len(ids), 'READY map ids are not distinct')
    # Agree with the frozen reader consumer before any acquisition is attempted.
    dumper.task_storage_specs(maps)
    return maps


def validate_infos(infos, maps):
    """Exact kernel-side identity and shape for the three retained maps."""
    for item, (name, _, size) in zip(maps, MAP_LAYOUT):
        info = infos[item['id']]
        require((info['type'], info['id'], info['bytes_key'], info['bytes_value'],
                 info['max_entries'], info['map_flags'])
                == (BPF_MAP_TYPE_TASK_STORAGE, item['id'], 4, size, 0, 1),
                'retained map identity or metadata does not match READY')
        require(info['name'] == name[:KERNEL_NAME_LIMIT],
                'retained map name does not match the kernel readback')
    require(len({infos[item['id']]['id'] for item in maps}) == len(maps),
            'retained map ids are not distinct')


def terminal_eof_proof(frames, records):
    """Record the terminal-EOF proof the frozen parser already established."""
    size = dumper.TASK_STORAGE_HEADER.size
    expected = (len(records) + 1) * size + sum(len(row['value']) for row in records)
    require(len(frames) == expected,
            'task-storage stream is not exactly the records plus one terminal EOF frame')
    fields = dumper.TASK_STORAGE_HEADER.unpack_from(frames, len(frames) - size)
    require(fields == (dumper.TASK_STORAGE_MAGIC, dumper.TASK_STORAGE_EOF, 0, 0, 0, 0),
            'task-storage stream does not end with the proved terminal EOF frame')
    return {'proved_by': 'dump-owned-bpf-maps.parse_task_storage_frames',
            'stream_bytes': len(frames), 'terminal_frame_offset': len(frames) - size,
            'records': len(records)}


def validate_records(records, maps, pid, values):
    """Exactly one record per map, complete expected bytes, before any scan."""
    require(len(records) == len(MAP_LAYOUT), 'expected exactly one record per seeded map')
    by_id = {}
    for record in records:
        require(record['map_id'] not in by_id, 'duplicate seeded task-storage record')
        by_id[record['map_id']] = record
    require(set(by_id) == {item['id'] for item in maps},
            'seeded records do not name the exact three maps')
    surfaces = {}
    for item, (name, _, size) in zip(maps, MAP_LAYOUT):
        record = by_id[item['id']]
        require(record['pid'] == pid and record['tid'] == pid,
                'seeded record names another task')
        require(len(record['value']) == size,
                'seeded record value length differs from the map value size')
        require(record['value'] == values[name],
                'seeded record value differs from the expected control bytes')
        surfaces[name] = record['value']
    return surfaces


def read_records(frames, maps, pid, values):
    records = dumper.parse_task_storage_frames(frames, maps, max_records=len(MAP_LAYOUT),
                                               max_bytes=SEED_SIZE)
    proof = terminal_eof_proof(frames, records)
    return validate_records(records, maps, pid, values), proof


def elf_identity(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        header = os.read(fd, 20)
    finally:
        os.close(fd)
    require(len(header) == 20 and header[:4] == b'\x7fELF', 'input is not an ELF object')
    return (header[4], header[5], struct.unpack_from('<H', header, 18)[0])


def fixture_abi(path):
    """The fixture's actual native ABI, stated apart from any paired ia32 load."""
    identity = elf_identity(path)
    require(identity == (ELF_CLASS64, ELF_LITTLE_ENDIAN, ELF_MACHINE_X86_64),
            'fixture is not a native little-endian x86-64 ELF executable')
    return {'elf_class': 'ELF64', 'machine': 'x86-64', 'e_machine': ELF_MACHINE_X86_64,
            'paired_production_workload_e_machine': ELF_MACHINE_I386,
            'distinct_from_paired_ia32_workload': True,
            'note': 'the fixture is always native x86-64 and is never the paired '
                    'ia32 (EM_386) production workload'}


def digest(path):
    total, value = 0, hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'digest input is not a regular file')
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= DIGEST_LIMIT, 'digest input byte bound exceeded')
            value.update(chunk)
    finally:
        os.close(fd)
    return value.hexdigest()


def require_regular(label, path, *, executable=False):
    require(isinstance(path, Path) and path.is_absolute(), f'{label} path must be absolute')
    require(os.path.lexists(path), f'{label} path does not exist')
    require(stat.S_ISREG(path.lstat().st_mode), f'{label} is not a regular file')
    if executable:
        require(os.access(path, os.X_OK), f'{label} is not executable')


def refuse_lane_root(label, directory):
    """A seed artifact may never join a production lane's surfaces or manifest."""
    lanes = set(coordinator.LANES)
    names = sorted(os.listdir(directory))
    require(len(names) <= FDINFO_LIMIT, f'{label} census is oversized')
    for name in names:
        require(not name.startswith('mapdump_'), f'{label} already holds lane map surfaces')
        require(name.split('.', 1)[0] not in lanes, f'{label} is a capture-lane work root')


def validate_config(config):
    require(isinstance(config.cases, tuple) and config.cases, 'no seed control case requested')
    require(len(set(config.cases)) == len(config.cases)
            and all(case in CASES for case in config.cases),
            'unknown or repeated seed control case')
    require_regular('fixture', config.fixture, executable=True)
    require_regular('reader', config.reader, executable=True)
    require_regular('object', config.obj)
    require(isinstance(config.out_dir, Path) and config.out_dir.is_absolute(),
            'out-dir must be absolute')
    try:
        os.mkdir(config.out_dir, 0o700)
    except FileExistsError:
        pass
    info = config.out_dir.lstat()
    require(stat.S_ISDIR(info.st_mode), 'out-dir is not a directory')
    require(not info.st_mode & 0o077, 'out-dir must be a private directory')
    refuse_lane_root('out-dir', config.out_dir)
    require(isinstance(config.receipt, Path) and config.receipt.is_absolute(),
            'receipt path must be absolute')
    parent = config.receipt.parent
    require(os.path.lexists(parent) and stat.S_ISDIR(parent.lstat().st_mode),
            'receipt directory does not exist')
    refuse_lane_root('receipt directory', parent)
    require(not os.path.lexists(config.receipt), 'receipt already exists')
    # x86-64 only: the fixture has no width flag and no ia32 variant.
    fixture_abi(config.fixture)


class LiveSeedMaps:
    """Only live BPF acquisition boundaries; process lifetime belongs to Custody."""
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fds = {}

    def _bpf(self, command, attr):
        ctypes.set_errno(0)
        result = self.libc.syscall(BPF_SYSCALL, command, ctypes.byref(attr),
                                   ctypes.sizeof(attr))
        return result, ctypes.get_errno()

    def inventory(self, group, deadline):
        """The complete live /proc/PID/fdinfo map-id inventory of the fixture."""
        directory = Path(f'/proc/{group.pid}/fdinfo')
        group.snapshot(deadline)
        names = self._census(directory)
        texts = []
        for name in names:
            remaining(deadline)
            texts.append(coordinator.read_bytes(directory / name, 65536, deadline)
                         .decode('ascii', 'replace'))
        require(names == self._census(directory), 'fixture fdinfo membership changed')
        group.snapshot(deadline)
        return dumper.map_ids_from_fdinfo(texts)

    @staticmethod
    def _census(directory):
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(entry.name.isdecimal() and len(names) < FDINFO_LIMIT,
                        'invalid fixture fdinfo census')
                names.append(entry.name)
        return sorted(names)

    def pin(self, maps, deadline):
        for item in maps:
            remaining(deadline)
            attr = ctypes.create_string_buffer(struct.pack('=III', item['id'], 0, 0))
            fd, code = self._bpf(BPF_MAP_GET_FD_BY_ID, attr)
            if fd < 0:
                raise OSError(code, 'retain seeded task-storage map')
            self.fds[item['id']] = fd

    def info(self, map_id):
        buffer = ctypes.create_string_buffer(INFO_SIZE)
        attr = ctypes.create_string_buffer(
            struct.pack('=IIQ', self.fds[map_id], INFO_SIZE, ctypes.addressof(buffer)))
        result, code = self._bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
        if result < 0:
            raise OSError(code, 'query seeded task-storage map info')
        fields = struct.unpack_from('<IIIIII', buffer.raw, 0)
        return {'type': fields[0], 'id': fields[1], 'bytes_key': fields[2],
                'bytes_value': fields[3], 'max_entries': fields[4], 'map_flags': fields[5],
                'name': buffer.raw[24:40].split(b'\0')[0].decode('ascii', 'replace')}

    def frames(self, owner, config, pid, maps, deadline):
        with owner.helper_wait():
            return dumper.run_task_storage_reader(
                config.reader, config.obj, pid, maps,
                timeout_seconds=remaining(deadline, dumper.TASK_STORAGE_TIMEOUT_SECONDS),
                max_records=len(MAP_LAYOUT), max_bytes=SEED_SIZE)

    def absent(self, map_id):
        """ENOENT is the only cleanup pass; EPERM or any other code is unresolved."""
        attr = ctypes.create_string_buffer(struct.pack('=III', map_id, 0, 0))
        fd, code = self._bpf(BPF_MAP_GET_FD_BY_ID, attr)
        if fd >= 0:
            os.close(fd)
            return 'resolvable'
        return 'absent' if code == errno.ENOENT else 'unresolved'

    def close(self):
        issues = []
        fds, self.fds = self.fds, {}
        for fd in fds.values():
            try:
                # Linux close errors must not trigger a retry on a reused descriptor.
                os.close(fd)
            except BaseException as error:
                issues.extend(sanitized('close-seeded-map', error))
        if issues:
            raise CaptureError(issues) from None


def live_seed_maps(case):
    return LiveSeedMaps()


class Qualifier:
    """One bounded seed qualification run; publication is no-replacement."""
    def __init__(self, config, source_factory=None):
        self.config = config
        self.source_factory = source_factory if source_factory is not None else live_seed_maps
        self.signals = coordinator.CoordinatorSignals()
        self.files = coordinator.AcquisitionFiles(config)
        self.phase = 'configuration'
        self.owner = None

    def check(self, phase, deadline=None):
        self.phase = phase
        self.signals.check()
        if self.owner is not None:
            self.owner.check_cancelled()
        if deadline is not None:
            remaining(deadline)

    def scan(self, case, paths):
        """The real shared scanner only, after the full byte comparison passed."""
        if case == 'baseline':
            evidence.assert_final_artifact_privacy(paths)
            return 'accepted'
        try:
            evidence.assert_final_artifact_privacy(paths)
        except AssertionError:
            # Never render the assertion context or any seeded byte.
            return 'refused'
        raise CaptureError('seeded control was not refused by the shared scanner')

    def run_case(self, case):
        cfg = self.config
        self.check(f'{case}-seed')
        values = control_values(case)
        seed = cfg.out_dir / f'{case}.seed'
        ready = cfg.out_dir / f'{case}.ready.json'
        release = cfg.out_dir / f'{case}.release'
        log_path = cfg.out_dir / f'{case}.fixture.log'
        for path in (ready, release, log_path):
            require(not os.path.lexists(path), 'seed control destination already exists')
        self.files.write(seed, seed_bytes(case))
        source, log, errors, summary = self.source_factory(case), None, [], None
        owner = custody.Custody(cleanup_seconds=CLEANUP_SECONDS)
        owner.__enter__()
        self.owner = owner
        try:
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                log = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
            summary = self.acquire(case, owner, source, seed, ready, release, log, values)
        except BaseException as error:
            errors.extend(sanitized(self.phase, error))
        finally:
            self.owner = None
            for phase, action in (('seeded-map-resources', source.close),
                                  ('fixture-log-close', log.close if log is not None else None),
                                  ('custody-close', owner.close if owner.active else None)):
                if action is None:
                    continue
                try:
                    action()
                except BaseException as error:
                    errors.extend(sanitized(phase, error))
            if owner.cancelled is not None:
                errors.append('custody cancellation')
        if errors:
            raise CaptureError(errors) from None
        return summary

    def acquire(self, case, owner, source, seed, ready, release, log, values):
        cfg = self.config
        deadline = time.monotonic() + READY_SECONDS
        argv = [str(cfg.fixture), str(cfg.obj), str(seed), str(ready), str(release),
                str(FIXTURE_TIMEOUT_MS)]
        self.check(f'{case}-launch', deadline)
        process = owner.launch(argv, role='fixture', stdout=log, stderr=log, deadline=deadline)
        group = process.group
        while not os.path.lexists(ready):
            self.check(f'{case}-readiness', deadline)
            # A fixture exit before READY is a failure here, never a retry.
            group.snapshot(deadline)
            time.sleep(min(.005, remaining(deadline)))
        group.snapshot(deadline)
        self.check(f'{case}-ready-document', deadline)
        document = coordinator.read_json(ready, READY_BOUND, deadline=deadline)
        generation = read_generation(group.pid, deadline)
        require(generation == group.generation, 'fixture generation changed before READY')
        maps = validate_ready(document, group.pid, generation)
        identities = sorted(item['id'] for item in maps)
        self.check(f'{case}-live-inventory', deadline)
        require(source.inventory(group, deadline) == identities,
                'fixture map inventory is not exactly the three READY maps')
        source.pin(maps, deadline)
        before = {item['id']: source.info(item['id']) for item in maps}
        validate_infos(before, maps)
        stopped = time.monotonic() + STOP_SECONDS
        members = {tid: row[0] for tid, row in group.snapshot(stopped).items()}
        self.check(f'{case}-stop', stopped)
        group.stop(stopped, expected=members, allowed_children={})
        self.check(f'{case}-frames', stopped)
        frames = source.frames(owner, cfg, group.pid, maps, stopped)
        surfaces, proof = read_records(frames, maps, group.pid, values)
        self.check(f'{case}-after-identities', stopped)
        group.snapshot(stopped, expected=members)
        after = {item['id']: source.info(item['id']) for item in maps}
        validate_infos(after, maps)
        require(after == before, 'retained map metadata changed across the stopped interval')
        require(read_generation(group.pid, stopped) == generation,
                'fixture generation changed across the stopped interval')
        require(source.inventory(group, stopped) == identities,
                'fixture map inventory changed across the stopped interval')
        self.check(f'{case}-surfaces', stopped)
        paths = []
        for name, _, _ in MAP_LAYOUT:
            path = cfg.out_dir / f'{case}-{name}.bin'
            self.files.write(path, surfaces[name])
            paths.append(path)
        outcome = self.scan(case, paths)
        resume = time.monotonic() + CLEANUP_SECONDS
        self.check(f'{case}-release', resume)
        group.resume(resume)
        coordinator.create_control(release)
        self.check(f'{case}-fixture-wait')
        require(process.wait(time.monotonic() + RELEASE_SECONDS) == 0,
                'fixture did not exit successfully after release')
        self.check('seeded-map-cleanup')
        source.close()
        for item in maps:
            state = source.absent(item['id'])
            require(state != 'resolvable', 'seeded map id remained resolvable after close')
            require(state == 'absent', 'seeded map id absence is unresolved')
        owner.seal_spawns()
        owner.drain_orphans(time.monotonic() + CLEANUP_SECONDS)
        require(not owner.reaped_orphans, 'seed case adopted a child')
        return {'pid': group.pid, 'generation': generation, 'outcome': outcome,
                'terminal_eof': proof, 'cleanup': 'map ids absent with ENOENT',
                'maps': [{'name': name, 'id': item['id'], 'bytes_value': size,
                          'value_bytes': len(surfaces[name])}
                         for item, (name, _, size) in zip(maps, MAP_LAYOUT)],
                'surfaces': [str(path) for path in paths]}

    def publish(self, summaries):
        cfg = self.config
        require(set(summaries) == set(CASES),
                'a terminal qualification requires all three controls')
        require(summaries['baseline']['outcome'] == 'accepted', 'baseline was not accepted')
        require(all(summaries[case]['outcome'] == 'refused' for case in ('early', 'late')),
                'a seeded control was not refused')
        document = {
            'contract': CONTRACT,
            'kernel_release': os.uname().release,
            'fixture': {'path': str(cfg.fixture), 'sha256': digest(cfg.fixture),
                        'abi': fixture_abi(cfg.fixture)},
            'reader': {'path': str(cfg.reader), 'sha256': digest(cfg.reader)},
            'object': {'path': str(cfg.obj), 'sha256': digest(cfg.obj)},
            'controls': {'cookie_bytes': len(COOKIE_CONTROL), 'owner_bytes': OWNER_SIZE,
                         'root_bytes': len(ROOT_CONTROL), 'early_offset': EARLY_OFFSET,
                         'late_offset': LATE_OFFSET, 'seed_bytes': SEED_SIZE},
            'cases': summaries,
            'scanner': {'baseline': summaries['baseline']['outcome'],
                        'early': summaries['early']['outcome'],
                        'late': summaries['late']['outcome'],
                        'oracle': 'check-canary-evidence.assert_final_artifact_privacy'},
            'cleanup': 'complete',
            'terminal_pass': True,
        }
        self.files.write(cfg.receipt, coordinator.encoded(document))
        return cfg.receipt

    def run(self):
        issues, summaries, receipt = [], {}, None
        try:
            validate_config(self.config)
            self.signals.enter()
            evidence.initialize(TARGET_BITS)
            for case in self.config.cases:
                summaries[case] = self.run_case(case)
        except BaseException as error:
            issues.extend(sanitized(self.phase, error))
        try:
            self.check('receipt', time.monotonic() + RECEIPT_SECONDS)
            if not issues and set(self.config.cases) == set(CASES):
                receipt = self.publish(summaries)
        except BaseException as error:
            issues.extend(sanitized(self.phase, error))
            receipt = None
        if issues:
            issues.extend(self.files.remove())
        self.signals.finish(self.files, issues)
        if issues:
            raise CaptureError(issues) from None
        return receipt


def qualify(config, source_factory=None):
    return Qualifier(config, source_factory).run()


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'reader', 'obj', 'out-dir', 'receipt'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--cases', default=','.join(CASES))
    result = parser.parse_args(argv)
    return SimpleNamespace(
        fixture=Path(result.fixture), reader=Path(result.reader), obj=Path(result.obj),
        out_dir=Path(result.out_dir), receipt=Path(result.receipt),
        cases=tuple(result.cases.split(',')), lane='task-storage-seed',
        target_bits=TARGET_BITS)


def main(argv=None):
    try:
        receipt = qualify(parse_args(sys.argv[1:] if argv is None else argv))
    except CaptureError as error:
        print(f'qualify-task-storage-canary: {error}', file=sys.stderr)
        return 1
    if receipt is None:
        print('task-storage seed controls: requested subset passed; no receipt published')
        return 0
    print(f'task-storage seed qualification receipt: {receipt}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
