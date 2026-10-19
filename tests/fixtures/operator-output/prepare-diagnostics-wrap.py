#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build/check owned32-body physical-count fixtures on a dev host, not Fedora."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import queue
import runpy
import signal
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve().with_name('diagnostics-wrap-ledger.c')
BASE_SOURCE = ROOT / 'tests/fixtures/public-cli/demotion-ledger.c'
COMMON_NAMES = tuple(f'libdemotion-common-{index:02d}.so' for index in range(32))
NAMES = COMMON_NAMES + ('provider-A.so', 'provider-B.so', 'workload')
PIN = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['pin_fd']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_ledger(rows, acks, nonce, pid, directory, counted, shared, probe=False):
    identity = rows[0]
    commons = [directory / name for name in COMMON_NAMES]
    digests = [digest(path) for path in commons]
    if (identity.get('kind') != 'identity' or identity['nonce'] != nonce
            or identity['pid'] != pid or identity['exe_sha256'] != digest(directory / 'workload')
            or identity['common_sha256'] != digests):
        raise ValueError('native fixture identity differs from independently launched inputs')
    pins = []
    for path in commons:
        fd = os.open(path, os.O_RDONLY)
        try:
            pins.append(PIN(fd))
        finally:
            os.close(fd)
    if len({(pin['dev'][0], pin['dev'][1], pin['ino']) for pin in pins}) != 32:
        raise ValueError('native fixture commons are not32 distinct physical objects')
    targets = [row for row in rows if row.get('kind') == 'target']
    if len(targets) != 32 or {row['slot'] for row in targets} != set(range(4, 36)):
        raise ValueError('native fixture lacks32 distinct physically bound shared entry bodies')
    for row in targets:
        pin = pins[row['slot'] - 4]
        if ([row['dev_major'], row['dev_minor']] != pin['dev']
                or row['ino'] != pin['ino']
                or not 0 <= row['offset'] < pin['file_identity']['size']):
            raise ValueError('native fixture lacks32 distinct physically bound shared entry bodies')
    calls = [row for row in rows if row.get('kind') == 'call']
    if probe and (counted != 3 or shared != 1):
        raise ValueError('startup probe requires exactly three A rounds')
    schedule = [('a', index) for index in range(1, counted + 1)]
    if not probe:
        schedule += [('shared', index) for index in range(1, shared + 1)] + [('fence', 1), ('proof', 1)]
    expected_acks = [('prepared', 0), ('ready', 0)] + [
        ('a-done', index) for index in range(1, counted + 1)]
    if not probe:
        expected_acks += [('b-ready', 0)] + [
            ('shared-done', index) for index in range(1, shared + 1)] + [
            ('a-unmapped', 0), ('fence-done', 1), ('final-calls', 1)]
    expected_acks.append(('done', 0))
    if [(row['event'], row['round']) for row in acks] != expected_acks:
        raise ValueError('actual native ACK sequence differs from the independent command schedule')
    expected = [(phase, index, slot) for phase, index in schedule for slot in range(4, 36)]
    if [(row['phase'], row['round'], row['slot']) for row in calls] != expected:
        raise ValueError('actual per-slot call ledger differs from independently issued schedule')
    previous = identity['ready_ns']
    for index, row in enumerate(calls, 1):
        if (row['sequence'] != index or row['return_status'] != 0
                or not previous <= row['before_call_ns'] < row['after_return_ns']):
            raise ValueError('native call sequence/return/clock interval differs')
        previous = row['after_return_ns']
    terminal = rows[-1]
    if terminal != dict(kind='complete', complete=True, calls=len(expected)):
        raise ValueError('actual native workload lacks complete terminal')
    phase_events = {'a': 'a-done', 'shared': 'shared-done', 'fence': 'fence-done', 'proof': 'final-calls'}
    for ordinal, (phase, index) in enumerate(schedule, 1):
        matches = [row for row in acks if row['event'] == phase_events[phase] and row['round'] == index]
        if (len(matches) != 1 or matches[0]['calls'] != ordinal * 32
                or calls[ordinal * 32 - 1]['after_return_ns'] > matches[0]['t']):
            raise ValueError('native phase ACK differs from its actual complete32slot round')
    return dict(calls=len(expected), targets=32, physical_pairs=32, counted_rounds=counted,
                shared_rounds=0 if probe else shared,
                phase_calls=dict(Counter(row['phase'] for row in calls)))


def execute_fixture(directory, counted=2, shared=2, probe=False):
    with tempfile.TemporaryDirectory(prefix='.native-', dir=directory) as scratch:
        root = Path(scratch)
        fifo, ledger = root / 'control', root / 'calls.jsonl'
        os.mkfifo(fifo, 0o600)
        nonce = uuid.uuid4().hex
        child = subprocess.Popen([str(directory / 'workload'),
            str(directory / 'provider-A.so'), str(directory / 'provider-B.so'),
            str(directory), str(fifo), str(ledger), nonce,
            '10000', str(counted), str(shared), *(['probe'] if probe else [])], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        updates, acks = queue.Queue(), []
        def read():
            try:
                for line in child.stdout:
                    updates.put(json.loads(line))
            except (ValueError, OSError) as error:
                updates.put(error)
            finally:
                updates.put(None)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        control = None
        try:
            def wait(event, index=0):
                row = updates.get(timeout=3)
                if not isinstance(row, dict) or (row.get('event'), row.get('round')) != (event, index):
                    raise ValueError(f'native ACK differs from {event}/{index}: {row}')
                acks.append(row)
            wait('prepared')
            control = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            commands = [('ready', 'ready', 0)] + [
                ('count', 'a-done', index) for index in range(1, counted + 1)]
            if not probe:
                commands += [('load-b', 'b-ready', 0)] + [
                    ('shared', 'shared-done', index) for index in range(1, shared + 1)] + [
                    ('unload-a', 'a-unmapped', 0), ('fence', 'fence-done', 1),
                    ('proof', 'final-calls', 1)]
            commands.append(('stop', 'done', 0))
            for command, event, index in commands:
                os.write(control, (command + '\n').encode())
                wait(event, index)
            if child.wait(timeout=3) != 0:
                raise ValueError('native wrap workload failed')
            rows = [json.loads(line) for line in ledger.read_text().splitlines()]
            return dict(rows=rows, acks=acks, nonce=nonce, pid=child.pid)
        finally:
            if control is not None:
                os.close(control)
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            reader.join(timeout=1)
            child.stdout.close()
            child.stderr.close()


def check_fixture(directory, counted=2, shared=2, probe=False):
    observed = execute_fixture(directory, counted, shared, probe)
    return check_ledger(**observed, directory=directory, counted=counted, shared=shared, probe=probe)


def build(directory, cc='cc'):
    sources = {str(path.relative_to(ROOT)): digest(path) for path in (SOURCE, BASE_SOURCE)}
    directory.mkdir(mode=0o700)
    base = [cc, '-std=c11', '-O2', '-fno-ipa-icf', '-Wall', '-Wextra', '-Werror']
    for index, name in enumerate(COMMON_NAMES):
        command = base + ['-shared', '-fPIC', '-DDEMOTION_COMMON',
                          f'-DCOMMON_BODY=diagnostics_slot_{4 + index}']
        if index == 0:
            command += ['-DCOMMON_FIRST']
        command += [str(SOURCE), '-o', str(directory / name)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('owned fixture compile failed: ' + result.stderr.decode('utf-8', 'replace'))
    common_libs = [f'-ldemotion-common-{index:02d}' for index in range(32)]
    for name, mode in (('provider-A.so', 'DEMOTION_PROVIDER_A'),
                       ('provider-B.so', 'DEMOTION_PROVIDER_B')):
        command = base + ['-shared', '-fPIC', '-D' + mode, str(SOURCE),
                          '-o', str(directory / name), '-L' + str(directory),
                          *common_libs, '-Wl,-rpath,$ORIGIN', '-Wl,-z,defs']
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('owned fixture compile failed: ' + result.stderr.decode('utf-8', 'replace'))
    command = base + [str(SOURCE), '-o', str(directory / 'workload'), '-ldl']
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('owned fixture compile failed: ' + result.stderr.decode('utf-8', 'replace'))
    if sources != {str(path.relative_to(ROOT)): digest(path) for path in (SOURCE, BASE_SOURCE)}:
        raise ValueError('fixture source changed while building')
    return dict(sources=sources, native_check=check_fixture(directory),
                probe_check=check_fixture(directory, counted=3, shared=1, probe=True),
                inputs=[dict(name=name, size=(directory / name).stat().st_size,
                             sha256=digest(directory / name)) for name in NAMES],
                qualification='unprivileged physical-entry topology/ledger only; no observer/BPF/wrap')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not args.out.is_absolute():
        parser.error('--out must be an absolute new directory on build-host disk')
    os.umask(0o022)
    print(json.dumps(build(args.out), indent=2))


if __name__ == '__main__':
    main()
