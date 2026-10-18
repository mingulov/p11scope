# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate-bound reporter witness primitives; no automatic live attachment.

The parent retains the observer pidfd/unreaped child and FilePin throughout.
Decoder fixtures and symbol controls do not qualify installed cancellation.
"""
import os
from pathlib import Path
import re
import runpy
import signal
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
MAPPING_FROM_FD = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['mapping_from_fd']
SYMBOL = 'p11scope::run::report_capture_cancel'
ROLE_SYMBOLS = {'reporter': SYMBOL, 'callback': 'p11scope::run::install_stop_flag::{closure#0}'}


def symbol_file_offset(fd, address):
    header = os.pread(fd, 64, 0)
    if len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('reporter requires ELF64 little-endian input')
    fields = struct.unpack('<16sHHIQQQIHHHHHH', header)
    _, kind, machine, version, _, phoff, _, _, ehsize, phsize, phcount, *_ = fields
    extent = os.fstat(fd).st_size
    if (kind not in (2, 3) or machine != 62 or version != 1 or ehsize != 64
            or phsize != 56 or not 0 < phcount <= 128 or phoff < 64
            or phoff + phsize * phcount > extent):
        raise ValueError('unsupported or malformed executable program headers')
    offsets = []
    for index in range(phcount):
        segment = os.pread(fd, 56, phoff + index * 56)
        if len(segment) != 56:
            raise ValueError('short executable segment')
        tag, flags, offset, virtual, _, filesz, memsz, _ = struct.unpack('<IIQQQQQQ', segment)
        if tag == 1 and flags & 1:
            if filesz > memsz or offset + filesz > extent:
                raise ValueError('invalid executable PT_LOAD extent')
            if virtual <= address < virtual + filesz:
                offsets.append(offset + address - virtual)
    if len(offsets) != 1:
        raise ValueError('actual reporter symbol does not map uniquely into executable file bytes')
    return offsets[0]


def verify_path(pin):
    pin.verify()
    current = pin.path.stat()
    if (current.st_dev, current.st_ino) != (pin.initial.st_dev, pin.initial.st_ino):
        raise ValueError('actual candidate pathname differs from held executable')


def read_reporter_symbols(output, role='reporter'):
    if role not in ROLE_SYMBOLS:
        raise ValueError('unsupported finite probe role')
    output.seek(0, os.SEEK_END)
    if output.tell() > 64 * 1024 * 1024:
        raise ValueError('actual candidate symbol table exceeds bounded disk extent')
    output.seek(0)
    matches = []
    pattern = re.compile(r'^' + re.escape(ROLE_SYMBOLS[role]) + r'(?:::h[0-9a-f]{16})? [tT] ([0-9a-fA-F]+)(?: [0-9a-fA-F]+)?$')
    while line := output.readline(65537):
        if len(line) > 65536:
            raise ValueError('actual candidate symbol line exceeds bounded input')
        if match := pattern.fullmatch(line.decode('utf-8', errors='strict').rstrip('\n')):
            matches.append(int(match[1], 16))
            if len(matches) > 1:
                raise ValueError('actual outlined reporter symbol is ambiguous')
    if len(matches) != 1:
        raise ValueError('exact actual outlined reporter symbol is absent')
    return matches


def resolve_role(pin, role):
    verify_path(pin)
    # Disk-backed nm output, bounded before reading into memory. Symbol names
    # come from the actual held candidate, never a source-name/offset guess.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(['nm', '--demangle=rust', '--defined-only', '--format=posix',
                                 f'/proc/self/fd/{pin.fd}'], pass_fds=(pin.fd,),
                                stdout=output, stderr=errors, timeout=10)
        if result.returncode:
            raise ValueError('actual candidate symbol table is unavailable')
        matches = read_reporter_symbols(output, role)
    offset = symbol_file_offset(pin.fd, matches[0])
    verify_path(pin)
    return dict(role=role, symbol=ROLE_SYMBOLS[role], virtual_address=matches[0], file_offset=offset,
                candidate=pin.metadata())


def resolve_reporter(pin):
    return resolve_role(pin, 'reporter')


def expected_witness(pin, owner, resolved):
    """Bind PIE runtime IP to the actual held main-thread executable mapping."""
    owner.verify()
    verify_path(pin)
    actual = os.stat(f'/proc/{owner.pid}/exe')
    if (actual.st_dev, actual.st_ino) != (pin.initial.st_dev, pin.initial.st_ino):
        raise ValueError('actual observer image differs from held reporter candidate')
    if resolved.get('candidate') != pin.metadata():
        raise ValueError('resolved reporter belongs to another held candidate')
    role = resolved.get('role')
    if role not in ROLE_SYMBOLS or resolved.get('symbol') != ROLE_SYMBOLS[role]:
        raise ValueError('resolved symbol does not bind a finite probe role')
    with open(f'/proc/{owner.pid}/maps', 'rb') as source:
        payload = source.read(4 * 1024 * 1024 + 1)
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError('actual observer mapping exceeds input bound')
    # Mapped device identity is independently measured from this exact FD.
    # Btrfs fstat st_dev and /proc/maps device are distinct identity domains.
    anchor = MAPPING_FROM_FD(pin.fd, pin.initial.st_size)
    addresses = []
    for line in payload.decode('utf-8', errors='strict').splitlines():
        match = re.match(r'^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) '
                         r'([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: |$)', line)
        if not match:
            raise ValueError('malformed actual observer mapping')
        start, end, permissions, offset, major, minor, inode = match.groups()
        if (int(inode) == pin.initial.st_ino
                and (int(major, 16), int(minor, 16)) ==
                    tuple(anchor['dev'])
                and 'x' in permissions):
            start, end, offset = int(start, 16), int(end, 16), int(offset, 16)
            if offset <= resolved['file_offset'] < offset + end - start:
                addresses.append(start + resolved['file_offset'] - offset)
    if len(addresses) != 1:
        raise ValueError('actual reporter executable mapping is absent or ambiguous')
    owner.verify()
    verify_path(pin)
    return dict(role=role, pid=owner.pid, tid=owner.pid, start_time=owner.identity['start_time'],
                dev=pin.initial.st_dev, ino=pin.initial.st_ino,
                file_offset=resolved['file_offset'], ip=addresses[0], mapped_identity=anchor)


def _validate_binding(records, expected, role):
    """Actual identity/clock/zero-loss envelope, independent of latency policy."""
    if (not isinstance(records, (list, tuple)) or len(records) != 3
            or any(not isinstance(row, dict) for row in records)
            or expected.get('role') != role
            or [row.get('kind') for row in records] != ['ready', role, 'final']):
        raise ValueError('need exactly one actual ready/sample/final reporter witness')
    ready, event, final = records
    if any(row.get('mode') != 'perf_uprobe' for row in records):
        raise ValueError('fixture evidence cannot qualify live acknowledgement')
    if ready.get('clock') != 'CLOCK_MONOTONIC' or ready.get('role') != role:
        raise ValueError('probe timestamp clock is not the signal-send clock')
    for key in ('pid', 'tid', 'start_time', 'dev', 'ino', 'file_offset'):
        if type(ready.get(key)) is not int or ready[key] < 0 or ready[key] != expected[key]:
            raise ValueError('probe readiness differs from original held candidate/main thread')
    if (any(type(event.get(key)) is not int or event[key] <= 0 for key in ('pid', 'tid', 'ip'))
            or event.get('pid') != expected['pid'] or event.get('tid') != expected['tid']
            or event.get('ip') != expected['ip'] or expected['pid'] != expected['tid']):
        raise ValueError('foreign reporter IP/process/thread')
    if (any(type(final.get(key)) is not int or not 0 <= final[key] < 2**64
                for key in ('lost', 'samples', 'kernel_count', 'time_enabled', 'time_running'))
            or final.get('lost') != 0 or final.get('samples') != 1 or final.get('kernel_count') != 1
            or final['time_enabled'] <= 0
            or final['time_enabled'] != final.get('time_running')):
        raise ValueError('lost/multiplexed/unreconciled kernel reporter evidence')


def validate_binding(records, expected):
    return _validate_binding(records, expected, 'reporter')


def validate_callback_binding(records, expected):
    """Delivery evidence only: this finite role can never qualify an ACK."""
    return _validate_binding(records, expected, 'callback')


def validate_witness(records, expected, signals):
    """Validate retained actual perf facts; caller also owns pressure/custody.

    No Rust argument-register ABI is assumed. The reviewed actual reporter is
    reachable only after the main thread wins the first-signal observation.
    Source/candidate binding and readable-marker controls remain prerequisites.
    """
    validate_binding(records, expected)
    ready, event, _ = records
    if (not isinstance(signals, (list, tuple)) or not signals or not isinstance(signals[0], dict)
            or signals[0].get('signal') not in ('SIGINT', 'SIGTERM')
            or int(signal.Signals[signals[0]['signal']]) not in (2, 15)):
        raise ValueError('no independently sent finite first signal')
    times = [ready.get('t_ns'), signals[0].get('t_ns'), event.get('t_ns')]
    if (any(type(value) is not int or not 0 < value < 2**64 for value in times)
            or not times[0] <= times[1] <= times[2] or times[2] - times[1] >= 100_000_000):
        raise ValueError('probe was not ready or actual cancellation acknowledgement missed<100ms')
    return dict(ack_ns=event['t_ns'], channel='owned_perf_reporter',
                cancellation_response_seconds=(times[2] - times[1]) / 1e9)
