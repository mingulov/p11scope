# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual owned negative adapters; no blocked-stderr positive is implied."""
import ctypes
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import time

if 'BASE' not in globals():
    # Standalone primitive tests only. The real entrypoint injects its own
    # namespace so acquisition and cleanup share its active signal guard.
    BASE = runpy.run_path(str(Path(__file__).with_name('qualify_reporter_probe.py')))
NATIVE, PROBE, HARNESS = BASE['NATIVE'], BASE['PROBE'], BASE['HARNESS']


def wait_row(reader, kind, seconds=5):
    return reader.wait(lambda source: next((row for row in BASE['json_rows'](source)
        if row.get('kind') == kind), None), seconds=seconds)


def start_probe(owners, readers, directory, label, helper, binary, observer, expected):
    argv = [str(helper.path), '--probe-task', str(binary.fd), str(expected['pid']),
            str(expected['tid']), str(expected['start_time']), str(expected['file_offset']),
            '90000', expected['role']]
    process = NATIVE.spawn_owned(owners, argv, 0, pass_fds=(binary.fd,),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True)
    image = helper.image_receipt(dict(image=0), process)
    facts = NATIVE.Reader(process.popen.stdout, directory / (label + '.jsonl'))
    errors = NATIVE.Reader(process.popen.stderr, directory / (label + '.stderr'))
    readers.extend((facts, errors))
    ready = wait_row(facts, 'ready')
    if (ready.get('mode') != 'perf_uprobe' or ready.get('clock') != 'CLOCK_MONOTONIC'
            or ready.get('role') != expected['role']
            or any(type(ready.get(key)) is not int or ready[key] != expected[key]
                   for key in ('pid', 'tid', 'start_time', 'dev', 'ino', 'file_offset'))
            or any(process.identity[key] != observer.identity[key]
                   for key in ('pid_namespace', 'time_namespace'))):
        raise ValueError('negative probe readiness/clock differs from actual bound task/role')
    return dict(process=process, facts=facts, errors=errors, image=image, stopped=False)


def finish_probe(probe):
    if not probe['stopped']:
        probe['process'].popen.stdin.write('stop\n')
        probe['process'].popen.stdin.flush()
        if probe['process'].popen.wait(timeout=5) != 0:
            raise ValueError('negative probe did not reconcile actual loss-free kernel counters')
        probe['facts'].finish()
        probe['errors'].finish()
        probe['stopped'] = True
    return BASE['json_rows'](probe['facts'])


def verify_preload(pin, observer):
    observer.verify()
    NATIVE.verify_input_path(pin)
    mapped = PROBE['MAPPING_FROM_FD'](pin.fd, pin.initial.st_size)
    with open(f'/proc/{observer.pid}/maps', 'rb') as source:
        payload = source.read(4 * 1024 * 1024 + 1)
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError('preload mapping input exceeds bound')
    matches = []
    for line in payload.decode('utf-8', errors='strict').splitlines():
        match = re.match(r'^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) '
                         r'([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: |$)', line)
        if not match:
            raise ValueError('malformed actual preload mapping')
        if ('x' in match[3] and int(match[7]) == pin.initial.st_ino
                and (int(match[5], 16), int(match[6], 16)) == tuple(mapped['dev'])):
            matches.append(dict(start=int(match[1], 16), end=int(match[2], 16), offset=int(match[4], 16)))
    if not matches:
        raise ValueError('actual observer did not map the held negative-only preload')
    observer.verify()
    return dict(input=pin.metadata(), mapped_identity=mapped, executable_ranges=matches)


class Worker:
    def __init__(self, observer):
        self.observer, self.fd = observer, None
        observer.verify()
        tasks = sorted(int(path.name) for path in Path(f'/proc/{observer.pid}/task').iterdir()
                       if path.name.isdecimal() and int(path.name) != observer.pid)
        if not tasks:
            raise ValueError('actual original observer has no live worker for negative')
        self.tid = tasks[0]  # No retry/replacement if this original worker exits.
        self.path = Path(f'/proc/{observer.pid}/task/{self.tid}')
        try:
            self.fd = os.open(self.path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            self.initial = os.fstat(self.fd)
            self.identity = NATIVE.process_identity(self.tid)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        self.observer.verify()
        held, current = os.fstat(self.fd), self.path.stat()
        if ((held.st_dev, held.st_ino) != (self.initial.st_dev, self.initial.st_ino)
                or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)
                or NATIVE.process_identity(self.tid) != self.identity):
            raise ValueError('original worker task changed or exited')
        status = (self.path / 'status').read_text()
        if (not re.search(r'^Tgid:\s*' + str(self.observer.pid) + r'\s*$', status, re.MULTILINE)
                or re.search(r'^State:\s*[ZX]', status, re.MULTILINE)):
            raise ValueError('worker is not a live task of the actual observer')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def send_main_sigint(observer):
    observer.verify()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.tgkill.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
    libc.tgkill.restype = ctypes.c_int
    stamp = time.monotonic_ns()
    if libc.tgkill(observer.pid, observer.pid, signal.SIGINT):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return dict(signal='SIGINT', t_ns=stamp, delivery='tgkill_original_main')


def gate_pipes(descriptors):
    with NATIVE.cleanup_section():
        control, release = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        descriptors.extend((control, release))
        facts, notify = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        descriptors.extend((facts, notify))
    return control, release, facts, notify


def cell(args, name, directory, env, binary, provider, caller_pin, helper, manifest, resolved, gate_pin):
    if name not in BASE['NEGATIVE_CELLS']:
        raise ValueError('unsupported finite negative cell')
    directory.mkdir(mode=0o755)
    owners, readers, descriptors, probes = [], [], [], []
    observer = worker = None
    release = None
    receipt = dict(cell=name, source_revision=args.source_revision, candidate=binary.metadata(),
        helper=helper.metadata(), provider=provider.metadata(), manifest=manifest.metadata(),
        observer_reaped_after_probe=False, signals=[], control_pass=False)
    try:
        caller = NATIVE.spawn_owned(owners,
            [str(caller_pin.path), str(provider.path), '0', 'selected'], args.uid,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            user=args.uid, group=args.gid, extra_groups=[], env=env, start_new_session=True)
        ledger = NATIVE.Reader(caller.popen.stdout, directory / 'caller.jsonl')
        caller_errors = NATIVE.Reader(caller.popen.stderr, directory / 'caller.stderr')
        readers.extend((ledger, caller_errors))
        ledger.record('ready')
        receipt['caller_image'] = caller_pin.image_receipt(ledger.record('image'), caller)
        observer_env, inherited = dict(env), ()
        gate_reader = None
        if name == 'handlerblocked':
            if gate_pin is None:
                raise ValueError('handler negative requires explicit held prebuilt readiness gate')
            control, release, facts, notify = gate_pipes(descriptors)
            os.set_blocking(facts, True)
            observer_env.update(LD_PRELOAD=str(gate_pin.path),
                P11SCOPE_TEST_GATE_CONTROL_FD=str(control), P11SCOPE_TEST_GATE_FACT_FD=str(notify))
            inherited = (control, notify)
            with NATIVE.cleanup_section():
                stream = os.fdopen(facts, 'r')
                descriptors.remove(facts)
                try:
                    gate_reader = NATIVE.Reader(stream, directory / 'gate.jsonl')
                except BaseException:
                    stream.close()
                    raise
                readers.append(gate_reader)
        with (directory / 'trace.stdout').open('wb') as output:
            observer = NATIVE.spawn_owned(owners,
                [str(binary.path), 'trace', '--pid', str(caller.pid), '--module', str(provider.path),
                 *HARNESS['manifest_arguments']([manifest], provider), '--duration', '6s',
                 '-o', str(directory / 'trace.txt')], 0, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.PIPE, text=True, env=observer_env, pass_fds=inherited, start_new_session=True)
            with NATIVE.cleanup_section():
                for fd in inherited:
                    os.close(fd)
                    descriptors.remove(fd)
            receipt['observer_image'] = binary.image_receipt(dict(image=0), observer)
            errors = NATIVE.Reader(observer.popen.stderr, directory / 'observer.stderr')
            readers.append(errors)
            expected = PROBE['expected_witness'](binary, observer, resolved)
            receipt['expected_probe'] = expected
            if any(observer.identity[key] != NATIVE.process_identity(os.getpid())[key]
                   for key in ('pid_namespace', 'time_namespace')):
                raise ValueError('observer differs from controller clock/namespace context')
            if gate_reader:
                wait_row(gate_reader, 'entered')
                receipt['preload'] = verify_preload(gate_pin, observer)
            primary = start_probe(owners, readers, directory, 'reporter', helper, binary, observer, expected)
            probes.append(primary)
            if name == 'handlerblocked':
                secondary_expected = PROBE['expected_witness'](binary, observer, PROBE['resolve_role'](binary, 'callback'))
            else:
                NATIVE.wait_capture_started(errors)
                with NATIVE.cleanup_section():
                    worker = Worker(observer)
                secondary_expected = dict(expected, tid=worker.tid, start_time=worker.identity['start_time'])
                worker.verify()
            secondary = start_probe(owners, readers, directory, 'secondary', helper, binary, observer, secondary_expected)
            probes.append(secondary)
            receipt['expected_secondary'] = secondary_expected
            receipt['probe_images'] = [probe['image'] for probe in probes]
            NATIVE.wait_capture_started(errors)
            command_start = time.monotonic_ns()
            caller.popen.stdin.write('calls C_GenerateRandom 20 0 reporter selected\n')
            caller.popen.stdin.flush()
            ledger.record('ack', 0, 'reporter')
            calls = [row for row in ledger.records if row.get('kind') == 'call' and row.get('phase') == 'reporter']
            if (len(calls) != 20 or any(row.get('fn') != 'C_GenerateRandom' or row.get('rv') != 0
                    or row.get('pid') != caller.pid or row.get('tid') != caller.pid
                    or row.get('scope') != 'selected' or not command_start <= row['t0'] <= row['t1'] for row in calls)):
                raise ValueError('independent actual safe-provider calls did not complete')
            receipt['actual_safe_calls'] = len(calls)
            if worker:
                worker.verify()
            receipt['signals'].append(send_main_sigint(observer))
            if gate_reader:
                wait_row(gate_reader, 'interrupted')
                remaining = (receipt['signals'][0]['t_ns'] + 150_000_000 - time.monotonic_ns()) / 1e9
                if remaining > 0:
                    time.sleep(remaining)
                receipt['release_ns'] = time.monotonic_ns()
                os.write(release, b'R')
                wait_row(gate_reader, 'released')
            else:
                wait_row(primary['facts'], 'reporter')
                worker.verify()
                receipt['secondary_records'] = finish_probe(secondary)
                worker.verify()
            if not observer.wait_exit(30) or observer.popen.returncode is not None:
                raise ValueError('observer failed bounded exit or lost unreaped custody')
            diagnostics = BASE['observer_diagnostics'](errors)
            receipt['reporter_records'] = finish_probe(primary)
            if gate_reader:
                receipt['secondary_records'] = finish_probe(secondary)
                gate_reader.finish()
                receipt['gate_records'] = BASE['json_rows'](gate_reader)
                receipt.update(BASE['validate_handler_blocked'](receipt['reporter_records'], expected,
                    receipt['secondary_records'], secondary_expected, receipt['gate_records'],
                    receipt['signals'], receipt['release_ns'], diagnostics))
                # The original child is now a zombie, so its mappings have
                # correctly disappeared. Retain the pre-signal mapping receipt
                # and held unchanged input; never demand/reopen a dead map.
                NATIVE.verify_input_path(gate_pin)
            else:
                receipt.update(BASE['validate_worker_negative'](receipt['secondary_records'], secondary_expected,
                    receipt['reporter_records'], expected, receipt['signals'], diagnostics))
            receipt['observer_rc'] = observer.popen.wait(timeout=1)
            receipt['observer_reaped_after_probe'] = True
            if receipt['observer_rc'] != 0:
                raise ValueError('actual observer failed')
        caller.popen.stdin.write('stop\n')
        caller.popen.stdin.flush()
        ledger.record('ack', 0, 'done')
        if caller.popen.wait(timeout=3) != 0:
            raise ValueError('actual ordinary caller failed')
        for reader in readers:
            reader.finish()
        for pin in (binary, provider, caller_pin, helper, manifest, gate_pin):
            if pin is not None:
                NATIVE.verify_input_path(pin)
        receipt['control_pass'] = True
        return receipt
    finally:
        # Always unblock the negative main BEFORE waiting or signalling cleanup.
        if release is not None:
            try:
                os.write(release, b'R')
            except OSError:
                pass
        if worker:
            worker.close()
        try:
            NATIVE.cleanup_processes(owners)
        except BaseException as error:
            receipt.update(control_pass=False, cleanup_error=str(error))
            raise
        finally:
            for fd in descriptors:
                os.close(fd)
            for reader in readers:
                reader.thread.join(timeout=1)
                reader.stream.close()
            for owner in owners:
                for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                    if stream is not None:
                        stream.close()
            (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
