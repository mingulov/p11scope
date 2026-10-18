#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture two real independent Inventory CLI windows with prebuilt fixtures.

Each window captures only the original control's first five physical entries.
The remaining five calls complete its original protocol after observer reap.
No compiler, container, namespace or capture-admission override is invoked.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
NATIVE = runpy.run_path(str(ROOT / 'scripts/qualify-cgroup-trace.py'))
LEDGER = runpy.run_path(str(Path(__file__).with_name('prepare-demotion.py')))
LIMIT = 16 * 1024 * 1024


def read_bounded(path):
    with path.open('rb') as stream:
        payload = stream.read(LIMIT + 1)
    if len(payload) > LIMIT:
        raise ValueError('owned capture exceeds16MiB')
    return payload


class CaptureView:
    def __init__(self, pid, provider_path):
        self.pid, self.provider_path = pid, str(provider_path)
        self.pending, self.edge, self.offset = [], None, 0

    def consume(self, rows):
        committed = False
        for row in rows:
            self.pending.append(row)
            if len(self.pending) > 4096:
                raise ValueError('owned uncommitted event population exceeds bound')
            if row.get('kind') == 'pass_committed':
                for pending in self.pending:
                    event = pending.get('event', {})
                    context = event.get('identity_context', {})
                    if (pending.get('kind') == 'edge_observed'
                            and context.get('caller', {}).get('pid') == self.pid
                            and context.get('module', {}).get('path') == self.provider_path):
                        self.edge = event
                self.pending.clear()
                committed = True
        return committed

    def refresh(self, path):
        if not path.exists():
            return False
        with path.open('rb') as stream:
            stream.seek(self.offset)
            payload = stream.read(LIMIT + 1)
        if len(payload) > LIMIT:
            raise ValueError('owned capture event delta exceeds bound')
        end = payload.rfind(b'\n') + 1
        self.offset += end
        return self.consume([json.loads(line) for line in payload[:end].splitlines()])


def check_snapshot(document):
    if (document.get('schema') != 'p11scope/inventory/v1'
            or any(len(document.get(key, [])) != 1 for key in ('callers', 'modules', 'edges'))
            or document.get('observation', {}).get('lane') != 'native'
            or document['observation'].get('retirement') != 'closed'
            or document['edges'][0].get('entries', {}).get('count') != 5):
        raise ValueError('saved native snapshot lacks exact independently issued five-entry population')
    return 5


def capture(binary, prebuilt, directory, source_revision):
    directory.mkdir(mode=0o755)
    owners, readers, pins = [], [], []
    control = None
    observer = None
    started = time.monotonic()
    fifo, ledger = directory / 'control', directory / 'calls.jsonl'
    os.mkfifo(fifo, 0o600)
    nonce = uuid.uuid4().hex
    try:
        for name in LEDGER['NAMES']:
            pins.append(NATIVE['FilePin'](prebuilt / name))
        for pin in (binary, *pins):
            NATIVE['verify_input_path'](pin)
        caller = NATIVE['spawn_owned'](owners,
            [str(prebuilt / 'workload'), str(prebuilt / 'provider-A.so'), str(prebuilt / 'provider-B.so'),
             str(prebuilt / 'libdemotion-common.so'), str(fifo), str(ledger), nonce, '90000'],
            os.geteuid(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        output = NATIVE['Reader'](caller.popen.stdout, directory / 'caller.stdout')
        errors = NATIVE['Reader'](caller.popen.stderr, directory / 'caller.stderr')
        readers.extend((output, errors))
        image = pins[3].image_receipt(dict(image=0), caller)
        def ack(event):
            return output.wait(lambda reader: next((json.loads(line) for line in reader.lines
                if json.loads(line).get('event') == event), None), seconds=5)
        prepared = ack('prepared')
        control = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        def command(name, event):
            caller.verify()
            os.write(control, (name + '\n').encode())
            return ack(event)
        snapshot, events = directory / 'snapshot.json', directory / 'events.jsonl'
        with (directory / 'inventory.stdout').open('wb') as stdout, (directory / 'inventory.stderr').open('wb') as stderr:
            observer = NATIVE['spawn_owned'](owners,
                [str(binary.path), 'inventory', '--pid', str(caller.pid), '--capture', 'native',
                 '--duration', '30s', '--json', '-o', str(snapshot), '--event-log', str(events)],
                os.geteuid(), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            observer_image = binary.image_receipt(dict(image=0), observer)
            if any(caller.identity[key] != observer.identity[key] for key in ('pid_namespace', 'time_namespace')):
                raise ValueError('caller and observer clocks/namespaces differ')
            view, released, armed_ns = CaptureView(caller.pid, prebuilt / 'provider-A.so'), False, None
            while True:
                if time.monotonic() - started > 30 or observer.wait_exit(0):
                    raise TimeoutError('actual native five-entry milestone missing before bounded stop')
                if view.refresh(events) and view.edge:
                    if not released and view.edge.get('capture') == 'armed' and view.edge.get('presence') == 'mapped':
                        armed_ns = time.monotonic_ns()
                        command('ready', 'a-done')
                        released = True
                    elif released and view.edge.get('entries', {}).get('count') == 5:
                        break
                time.sleep(0.005)
            stop_ns = time.monotonic_ns()
            observer.send(signal.SIGINT)
            if observer.popen.wait(timeout=60) != 0:
                raise ValueError('real Inventory CLI capture failed')
        # Only A's five calls were issued during the independent capture window.
        # Complete all original ten-call controls after the observer has reaped.
        for name, event in LEDGER['PHASES'][1:]:
            command(name, event)
        if caller.popen.wait(timeout=5) != 0:
            raise ValueError('original ten-call fixture completion failed')
        for reader in readers:
            reader.finish()
        acks = [json.loads(line) for line in output.lines]
        if [row.get('event') for row in acks] != ['prepared', *[event for _, event in LEDGER['PHASES']]]:
            raise ValueError('native ACK sequence differs from independent original ten-call protocol')
        b_ready = next(row for row in acks if row['event'] == 'b-ready')
        unmapped = next(row for row in acks if row['event'] == 'a-unmapped')
        if (not b_ready.get('same_target') or prepared['a_root_ino'] == b_ready['b_root_ino']
                or unmapped != dict(event='a-unmapped', a_mapped=False, b_mapped=True, common_mapped=True)):
            raise ValueError('original physical target/retirement topology controls failed')
        rows = [json.loads(line) for line in read_bounded(ledger).splitlines()]
        native = LEDGER['check_ledger'](rows, nonce, caller.pid, prebuilt / 'workload', prebuilt / 'libdemotion-common.so')
        captured = [row for row in rows if row.get('kind') == 'call' and row.get('phase') == 'a']
        if (len(captured) != 5 or any(not armed_ns <= row['before_call_ns'] < row['after_return_ns'] <= stop_ns
                                     for row in captured)):
            raise ValueError('independent native calls differ from actual capture window')
        payload = read_bounded(snapshot)
        if payload != read_bounded(directory / 'inventory.stdout'):
            raise ValueError('actual Inventory JSON stdout/file parity failed')
        document = json.loads(payload)
        check_snapshot(document)
        if (document['callers'][0]['pid'] != caller.pid
                or document['callers'][0]['image']['exe']['path'] != str(prebuilt / 'workload')
                or str(prebuilt / 'provider-A.so') not in document['modules'][0]['paths']):
            raise ValueError('saved capture differs from independent actual image/provider')
        lifecycle = document['observation']['lifecycle']
        if (any(lifecycle[key] != 0 for key in ('ring_loss', 'malformed', 'failed_quanta'))
                or document['observation']['native_witnesses']['integrity'] != 0):
            raise ValueError('actual native capture has lifecycle/witness failure')
        for pin in (binary, *pins):
            NATIVE['verify_input_path'](pin)
        receipt = dict(source_revision=source_revision, candidate=binary.metadata(), image=image,
            observer_image=observer_image, prebuilt=[pin.metadata() for pin in pins], native_ledger=native,
            captured_physical_entries=5, armed_ns=armed_ns, stop_ns=stop_ns,
            elapsed_seconds=time.monotonic() - started, snapshot=str(snapshot), counter_relation='independent_windows')
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt
    finally:
        if control is not None:
            os.close(control)
        if observer is not None and observer.popen.returncode is None:
            try:
                observer.send(signal.SIGINT)
                observer.popen.wait(timeout=60)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass  # bounded fallback below remains failure cleanup, never acceptance
        try:
            NATIVE['cleanup_processes'](owners)
        finally:
            for reader in readers:
                reader.thread.join(timeout=1)
                reader.stream.close()
            for pin in pins:
                pin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'prebuilt', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.source_revision)
            or any(not getattr(args, name).is_absolute() for name in ('binary', 'prebuilt', 'out'))):
        parser.error('requires root, exact observer source and absolute prebuilt/new-output paths')
    os.umask(0o022)
    args.out.mkdir(mode=0o755)
    binary = NATIVE['FilePin'](args.binary)
    try:
        receipts = [capture(binary, args.prebuilt, args.out / name, args.source_revision) for name in ('before', 'after')]
        print(json.dumps(dict(captures=receipts, qualification='real independent Inventory CLI snapshots; run saved-input diff separately')))
    finally:
        binary.close()


if __name__ == '__main__':
    with NATIVE['signal_cleanup']():
        main()
