#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build/check only owned demotion fixtures on a build host, never on Fedora.

Print temporary arrival-check metadata to stdout. Outputs are active test inputs,
not an archive. This topology check does not perform installed BPF acceptance.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'tests/fixtures/public-cli/demotion-ledger.c'
NAMES = ('libdemotion-common.so', 'provider-A.so', 'provider-B.so', 'workload')
PHASES = (('ready', 'a-done'), ('load-b', 'b-ready'), ('shared', 'shared-done'),
          ('unload-a', 'a-unmapped'), ('fence', 'fence-done'),
          ('proof', 'final-calls'), ('stop', 'done'))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_ledger(rows, nonce, pid, workload, common):
    if not rows or rows[0].get('kind') != 'identity':
        raise ValueError('actual native identity record missing')
    identity = rows[0]
    if (identity['nonce'] != nonce or identity['caller']['pid'] != pid
            or identity['caller']['exe_sha256'] != sha256(workload)
            or identity['target']['sha256'] != sha256(common)):
        raise ValueError('native identity differs from the independently launched fixture')
    calls = [row for row in rows if row.get('kind') == 'call']
    expected = Counter(a=5, shared=2, fence=1, proof=2)
    if Counter(row['phase'] for row in calls) != expected:
        raise ValueError('native phased call ledger disagrees with issued command schedule')
    previous = identity['ready_ns']
    for sequence, row in enumerate(calls, 1):
        if (row['sequence'] != sequence or row['function'] != 'C_Initialize'
                or row['entered'] is not True or row['completed'] is not True
                or not previous <= row['before_call_ns'] < row['after_return_ns']
                or row['return_status'] not in (0, 7)):
            raise ValueError('native call lacks exact sequence/function/return/monotonic completion')
        previous = row['after_return_ns']
    if Counter(row['return_status'] for row in calls) != Counter({0: 6, 7: 4}):
        raise ValueError('actual healthy/error return populations disagree')
    terminal = rows[-1]
    if terminal.get('kind') != 'complete' or terminal.get('complete') is not True or terminal.get('calls') != 10:
        raise ValueError('native terminal completion missing')
    return dict(calls=len(calls), phases=dict(expected), successful_calls=6, error_calls=4)


def check_fixture(directory):
    """Execute only owned native calls, with no observer or privilege needed."""
    with tempfile.TemporaryDirectory(prefix='.topology-', dir=directory) as scratch:
        root = Path(scratch)
        fifo, ledger = root / 'control', root / 'calls.jsonl'
        os.mkfifo(fifo, 0o600)
        nonce = uuid.uuid4().hex
        child = subprocess.Popen([str(directory / 'workload'),
            str(directory / 'provider-A.so'), str(directory / 'provider-B.so'),
            str(directory / 'libdemotion-common.so'), str(fifo), str(ledger), nonce, '10000'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        updates = queue.Queue()
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
            def wait(expected):
                row = updates.get(timeout=3)
                if not isinstance(row, dict) or row.get('event') != expected:
                    raise ValueError(f'native acknowledgement differs from {expected}: {row}')
                return row
            prepared = wait('prepared')
            control = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            milestones = {}
            for command, ack in PHASES:
                os.write(control, (command + '\n').encode())
                milestones[ack] = wait(ack)
            if child.wait(timeout=3) != 0:
                raise ValueError('owned native workload failed')
            if not milestones['b-ready'].get('same_target'):
                raise ValueError('A/B did not call one physical body')
            if prepared['a_root_ino'] == milestones['b-ready']['b_root_ino']:
                raise ValueError('A/B tables did not occupy distinct physical provider files')
            if milestones['a-unmapped'] != dict(event='a-unmapped', a_mapped=False,
                                                b_mapped=True, common_mapped=True):
                raise ValueError('native mapping retirement topology differs')
            rows = [json.loads(line) for line in ledger.read_text().splitlines()]
            return check_ledger(rows, nonce, child.pid, directory / 'workload',
                                directory / 'libdemotion-common.so')
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


def build(directory, cc='cc'):
    source_before = sha256(SOURCE)
    directory.mkdir(mode=0o700)  # new-only; preserve any existing payload
    for name, mode in zip(NAMES, ('DEMOTION_COMMON', 'DEMOTION_PROVIDER_A',
                                  'DEMOTION_PROVIDER_B', None)):
        command = [cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror']
        if mode:
            command += ['-shared', '-fPIC', '-D' + mode]
        else:
            command += ['-DDEMOTION_PHASED_LEDGER']
        command += [str(SOURCE), '-o', str(directory / name)]
        if mode and mode != 'DEMOTION_COMMON':
            command += ['-L' + str(directory), '-ldemotion-common',
                        '-Wl,-rpath,$ORIGIN', '-Wl,-z,defs']
        elif mode is None:
            command += ['-ldl']
        subprocess.run(command, check=True, capture_output=True, timeout=30)
    if sha256(SOURCE) != source_before:
        raise ValueError('fixture source changed while building')
    result = check_fixture(directory)
    return dict(source=str(SOURCE.relative_to(ROOT)), source_sha256=source_before,
                topology_check=result,
                inputs=[dict(name=name, size=(directory / name).stat().st_size,
                             sha256=sha256(directory / name)) for name in NAMES],
                limitations=['No installed observer/BPF execution',
                             'One ten-call transition does not wrap diagnostics rings',
                             'Native acknowledgements do not establish observer milestones'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    if not args.out.is_absolute():
        parser.error('--out must be an absolute new directory on the build host disk')
    os.umask(0o022)
    result = build(args.out, args.cc)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
