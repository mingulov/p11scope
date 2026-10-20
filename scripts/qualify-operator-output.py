#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed E17 ordinary-EVENTS matrix, using only supplied prebuilt inputs.

Root and an independently held host lane are required. No compilation, cgroup,
namespace, container or host-policy mutation is performed. NOT_RUN is nonzero.
"""
import argparse
import array
import fcntl
import itertools
import json
import os
from pathlib import Path
import re
import resource
import runpy
import select
import signal
import subprocess
import sys
import termios
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
NATIVE = SimpleNamespace(**runpy.run_path(str(ROOT / 'scripts/qualify-cgroup-trace.py')))
PIN_PROVIDER = runpy.run_path(str(ROOT / 'scripts/mapped-provider-pin.py'))['pin_fd']
ORACLE = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/oracle.py'))['evaluate']
PROBE = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/reporter_probe.py'))
BLOCKED = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/blocked_stderr.py'))
RINGS = ('4K', '4M', '16M')
SINKS = ('file', 'discard', 'slowpipe')
STAGES = ('none', 'midcapture', 'midfinal')
CELLS = tuple('-'.join(parts) for parts in itertools.product(RINGS, SINKS, STAGES))
LIMIT = 16 * 1024 * 1024


def cancellation_marker(data, expected_signal):
    """A complete real reporter line; arrival time is only an upper bound."""
    pattern = (rb'^p11scope: cancel: (?:loop exited on signal ([0-9]+) after ([0-9]+) ticks'
               rb'|signal ([0-9]+) observed during finalization after ([0-9]+) ticks)\n')
    matches = list(re.finditer(pattern, data, re.MULTILINE))
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError('duplicate once-only cancellation acknowledgement')
    groups = matches[0].groups()
    signum, ticks = (int(value) for value in (groups[:2] if groups[0] else groups[2:]))
    if signum != expected_signal or ticks > 2**64 - 1:
        raise ValueError('cancellation marker differs from the independently sent first signal')
    return dict(signal=signum, ticks=ticks, phase='capture' if groups[0] else 'finalization',
                channel='readable_stderr')


def record_cancellation_marker(receipt, data):
    if not receipt['signals']:
        return
    expected = int(signal.Signals[receipt['signals'][0]['signal']])
    marker = cancellation_marker(data, expected)
    if marker is not None and receipt['cancellation_ack_ns'] is None:
        receipt['cancellation_ack_ns'] = time.monotonic_ns()
        receipt['cancellation_ack'] = marker


class OutputPipe:
    """Bounded, truly stalled output; measurement ends at observer reap, not EOF."""
    def __init__(self):
        self.read_fd, self.write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            fcntl.fcntl(self.write_fd, fcntl.F_SETPIPE_SZ, 4096)
            self.capacity = fcntl.fcntl(self.write_fd, fcntl.F_GETPIPE_SZ)
            os.set_blocking(self.read_fd, False)
            self.received = bytearray()
        except BaseException:
            self.close()
            raise

    def buffered(self):
        count = array.array('i', [0])
        fcntl.ioctl(self.read_fd, termios.FIONREAD, count, True)
        return count[0]

    def full(self):
        return self.buffered() >= self.capacity

    def stalled(self):
        """Kernel write readiness, including atomic-write pressure below capacity."""
        if self.write_fd is None:
            raise ValueError('pressure witness requires the original owned write descriptor')
        if not self.buffered():
            return False
        poll = select.poll()
        poll.register(self.write_fd, select.POLLOUT)
        events = poll.poll(0)
        if any(mask & (select.POLLERR | select.POLLNVAL | select.POLLHUP) for _, mask in events):
            raise ValueError('owned output pressure descriptor is unavailable')
        return not any(mask & select.POLLOUT for _, mask in events)

    def read(self, amount=65536):
        try:
            chunk = os.read(self.read_fd, amount)
        except BlockingIOError:
            return False
        self.received.extend(chunk)
        if len(self.received) > LIMIT:
            raise ValueError('owned output exceeded the bounded16MiB fixture limit')
        return bool(chunk)

    def drain_available(self):
        while self.read():
            pass
        return bytes(self.received)

    def close_writer(self):
        if self.write_fd is not None:
            os.close(self.write_fd)
            self.write_fd = None

    def close(self):
        for name in ('read_fd', 'write_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


def probe_rows(reader):
    return [json.loads(line) for line in reader.lines]


def observer_exited(observer, retain_custody):
    """Detect observer exit, optionally without reaping the original child.

    A blocked-stderr cell reconciles the independent probe's kernel counters
    before the observer is reaped, so its loop polls the held pidfd instead
    of the reaping Popen handle. Ordinary cells keep the existing behavior.
    """
    if retain_custody:
        return observer.wait_exit(0)
    return observer.popen.poll() is not None


def events_ring_capacity(pid):
    """Read the actual owned observer's EVENTS map, rather than trust argv."""
    capacities = set()
    for path in (Path('/proc') / str(pid) / 'fdinfo').iterdir():
        try:
            info = path.read_text()
        except FileNotFoundError:
            continue
        # BPF_MAP_TYPE_RINGBUF=27 in Linux UAPI. Avoid spawning one bpftool
        # process per unrelated map while a bounded capture is already live.
        # fdinfo is from this held observer; bpftool still proves the name,
        # type and configured capacity of each candidate ring.
        if not re.search(r'^map_type:\s*27$', info, re.MULTILINE):
            continue
        match = re.search(r'^map_id:\s*([0-9]+)$', info, re.MULTILINE)
        if not match:
            continue
        output = subprocess.run(['bpftool', '-j', 'map', 'show', 'id', match[1]],
                                capture_output=True, timeout=2, check=True)
        if len(output.stdout) > 65536:
            raise ValueError('unexpectedly large map metadata')
        rows = json.loads(output.stdout)
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if row.get('name') == 'EVENTS':
                if row.get('type') != 'ringbuf':
                    raise ValueError('owned EVENTS map is not a ring buffer')
                capacities.add(row['max_entries'])
    if len(capacities) != 1:
        raise ValueError('could not identify one actual owned EVENTS ring capacity')
    return capacities.pop()


def bounded_read(path, limit=LIMIT):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('owned file exceeded the retained-input memory bound')
    return data


def manifest_arguments(manifests, provider):
    """Forward explicit operator attestation only for the pinned provider.

    The runtime validates the full manifest contract and entry offsets. This
    gate binds the separately generated helper output to this workload input;
    it neither invents authority nor claims scan-only discovery succeeded.
    """
    provider.verify()
    arguments = []
    for pin in manifests:
        pin.verify()
        current = pin.path.stat()
        if (current.st_dev, current.st_ino) != (pin.initial.st_dev, pin.initial.st_ino):
            raise ValueError('manifest pathname no longer names the held input')
        document = json.loads(bounded_read(pin.path))
        objects = [row for row in document.get('objects', [])
                   if row.get('path') == str(provider.path)]
        if (document.get('schema') != 'p11scope-manifest/5'
                or document.get('module_path') != str(provider.path)
                or len(objects) != 1
                or objects[0].get('identity', {}).get('sha256') != provider.digest):
            raise ValueError('manifest does not bind exactly the held provider content')
        arguments.extend(('--manifest', str(pin.path)))
    return arguments


def file_limit():
    # Only this direct exec child; regular-file output failure is a negative
    # control, never evidence of interruptibility of kernel-blocked file I/O.
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def cell(args, label, directory, env, binary, provider, caller_pin, manifests=(), blocked=None):
    ring, sink, cancel = label.split('-')
    owners, readers, pipes = [], [], []
    receipt = dict(cell=label, source_revision=args.source_revision, sink=sink, cancel=cancel,
                   ring_requested=ring, ring_actual_bytes=None, pid=None, issued_calls=args.calls, ready_ns=None,
                   workload_complete_ns=None, observer_rc=None, cleanup_seconds=None,
                   signals=[], cancellation_ack_ns=None, terminal_observed_alive=False,
                   stdout_stalled=False, stderr_blocked=args.control == 'blocked-stderr',
                   stderr_stalled=False, stderr_buffered_bytes=0, stderr_release_ns=None,
                   reporter_ack=None, reporter_kernel=None, observer_reaped_after_probe=False,
                   reporter_controls=None, candidate_sha256=None,
                   trace_file_error=None, watchdog=False, control=args.control)
    observer = caller = witness = witness_facts = witness_errors = expected = None
    stdout_file = None
    errors = bytearray()
    trace_path = directory / 'trace.txt'
    start = time.monotonic()
    try:
        if receipt['stderr_blocked']:
            if blocked is None or blocked.get('error'):
                reason = blocked.get('error') if blocked else \
                    'blocked-stderr needs its independent reporter channel and qualified dependencies'
                result = dict(api_calls=None, events_lost=None,
                              stdout_shed_bytes=None, stdout_delivered_bytes=None,
                              cancellation_response_seconds=None,
                              status='NOT_RUN', errors=[], unqualified=[reason])
                result['pass'] = False
                save(directory / 'receipt.json', receipt)
                save(directory / 'result.json', result)
                return result
            receipt['candidate_sha256'] = binary.digest
            receipt['reporter_controls'] = blocked['dependencies']
        receipt['provider_before'] = PIN_PROVIDER(provider.fd)
        manifest_argv = manifest_arguments(manifests, provider)
        receipt['discovery_mode'] = 'explicit-manifest' if manifests else 'scan-only'
        receipt['manifests'] = [pin.metadata() for pin in manifests]
        caller = NATIVE.spawn_owned(owners,
            [str(caller_pin.path), str(provider.path), '0', 'selected'], args.uid,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, user=args.uid, group=args.gid, extra_groups=[],
            start_new_session=True)
        ledger_reader = NATIVE.Reader(caller.popen.stdout, directory / 'caller.jsonl')
        caller_errors = NATIVE.Reader(caller.popen.stderr, directory / 'caller.stderr')
        readers.extend((ledger_reader, caller_errors))
        ledger_reader.record('ready')
        receipt['image'] = caller_pin.image_receipt(ledger_reader.record('image'), caller)
        receipt['pid'] = caller.pid
        pipe = None
        if sink == 'slowpipe':
            pipe = OutputPipe()
            pipes.append(pipe)
            receipt['stdout_pipe_capacity'] = pipe.capacity
            stdout_fd = pipe.write_fd
        else:
            path = directory / 'stdout.txt' if sink == 'file' else Path('/dev/null')
            stdout_file = path.open('xb' if sink == 'file' else 'wb')
            stdout_fd = stdout_file.fileno()
        stderr_pipe = OutputPipe()
        pipes.append(stderr_pipe)
        argv = [str(binary.path), 'trace', '--pid', str(caller.pid),
                '--module', str(provider.path), '--ring-bytes', ring,
                '--duration', '6s', '-o', str(trace_path), *manifest_argv]
        observer = NATIVE.spawn_owned(owners, argv, 0, stdin=subprocess.DEVNULL,
            stdout=stdout_fd, stderr=stderr_pipe.write_fd, env=env,
            start_new_session=True,
            preexec_fn=file_limit if args.control == 'file-limit' else None)
        binary.image_receipt(dict(image=0), observer)
        if args.control == 'child-held-stdout':
            if pipe is None:
                raise ValueError('child-held-stdout requires a slowpipe cell')
            NATIVE.spawn_owned(owners,
                [sys.executable, '-I', '-c', 'import time; time.sleep(90)'], 0,
                stdin=subprocess.DEVNULL, stdout=pipe.write_fd,
                stderr=subprocess.DEVNULL, start_new_session=True)
        if receipt['stderr_blocked']:
            expected = PROBE['expected_witness'](binary, observer, blocked['resolved'])
            receipt['expected_probe'] = expected
            if any(observer.identity[key] != NATIVE.process_identity(os.getpid())[key]
                   for key in ('pid_namespace', 'time_namespace')):
                raise ValueError('observer differs from controller timestamp/namespace context')
            witness = NATIVE.spawn_owned(owners,
                [str(blocked['helper'].path), '--probe', str(binary.fd), str(observer.pid),
                 str(observer.identity['start_time']), str(blocked['resolved']['file_offset']), '90000'],
                0, pass_fds=(binary.fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
            blocked['helper'].image_receipt(dict(image=0), witness)
            witness_facts = NATIVE.Reader(witness.popen.stdout, directory / 'probe.jsonl')
            witness_errors = NATIVE.Reader(witness.popen.stderr, directory / 'probe.stderr')
            readers.extend((witness_facts, witness_errors))
            witness_ready = witness_facts.wait(lambda reader: next((row for row in probe_rows(reader)
                if row.get('kind') == 'ready'), None), seconds=5)
            if (witness_ready.get('mode') != 'perf_uprobe' or witness_ready.get('clock') != 'CLOCK_MONOTONIC'
                    or witness_ready.get('role') != 'reporter'
                    or any(witness_ready.get(key) != expected[key]
                           for key in ('pid', 'tid', 'start_time', 'dev', 'ino', 'file_offset'))):
                raise ValueError('probe readiness does not bind the actual original observer')
            for key in ('pid_namespace', 'time_namespace'):
                if witness.identity[key] != observer.identity[key]:
                    raise ValueError('independent helper clock/namespace differs from observer')
        # Keep the original stdout writer solely as the kernel POLLOUT
        # witness, closing it at bounded observer completion. Never wait EOF.
        # Parent keeps stderr writer only for the explicit blocked-stderr fill.
        if args.control != 'blocked-stderr':
            stderr_pipe.close_writer()
        ready = False
        ack_complete = False
        sent_more = False
        stop_started = None
        last_read = 0.0
        final_ns = None
        while not observer_exited(observer, receipt['stderr_blocked']):
            now = time.monotonic()
            if now - start > 90:
                receipt['watchdog'] = True
                raise TimeoutError('owned observer watchdog; forced cleanup is failure')
            if args.control != 'blocked-stderr' or not receipt['signals']:
                while stderr_pipe.read():
                    pass
                errors = stderr_pipe.received
            # Each chunk arrival provides an upper bound on marker emission;
            # it is never called a kernel accepted-write or handler timestamp.
            if receipt['cancellation_ack_ns'] is None:
                record_cancellation_marker(receipt, errors)
            if not ready:
                if re.search(rb'p11scope: capturing: [1-9][0-9]* probe\(s\) attached; stop with Ctrl-C\n', errors):
                    observer.verify()
                    receipt['ring_actual_bytes'] = events_ring_capacity(observer.pid)
                    expected_ring = {'4K': 4096, '4M': 4194304, '16M': 16777216}[ring]
                    if receipt['ring_actual_bytes'] != expected_ring:
                        raise ValueError('actual EVENTS ring differs from requested matrix cell')
                    receipt['ready_ns'] = time.monotonic_ns()
                    ready = True
                    caller.popen.stdin.write(f'calls C_GenerateRandom {args.calls} 0 e17 selected\n')
                    caller.popen.stdin.flush()
                elif now - start > 15:
                    raise TimeoutError('no positive provider-probe readiness')
            if ready and not ack_complete and any(row.get('kind') == 'ack' and row.get('phase') == 'e17' and row.get('image') == 0
                                                   for row in ledger_reader.records):
                receipt['workload_complete_ns'] = time.monotonic_ns()
                ack_complete = True
            if pipe:
                receipt['stdout_stalled'] |= pipe.stalled()
                # Hold until positive buffered bytes and kernel nonwritability
                # are observed on the live observer's original owned pipe.
                # The oracle also requires actual product sink timeouts.
                if receipt['stdout_stalled'] and now - last_read > 0.05:
                    pipe.read(256)
                    last_read = now
            if receipt['stderr_blocked'] and receipt['signals'] and stderr_pipe.write_fd is not None:
                # Prove the independent ACK below was measured while stderr
                # was actually blocked: positive buffered bytes plus kernel
                # POLLOUT nonwritability on the original owned writer, seen
                # while this loop still holds the live observer.
                if stderr_pipe.stalled():
                    receipt['stderr_stalled'] = True
                    receipt['stderr_buffered_bytes'] = stderr_pipe.buffered()
            # Longrun is emitted only after loop end/request_stop in run.rs.
            # Buffered -o output cannot reliably reveal COUNT_EVIDENCE early.
            if b'p11scope: longrun:' in errors and final_ns is None:
                final_ns = time.monotonic_ns()
                receipt['terminal_observed_alive'] = True
            signal_now = ack_complete and not receipt['signals'] and (
                cancel == 'midcapture' or cancel == 'midfinal' and final_ns is not None)
            if signal_now:
                if args.control == 'blocked-stderr':
                    os.set_blocking(stderr_pipe.write_fd, False)
                    while True:
                        try:
                            os.write(stderr_pipe.write_fd, b'B' * 4096)
                        except BlockingIOError:
                            break
                stamp = time.monotonic_ns()
                observer.send(signal.SIGINT)
                receipt['signals'].append(dict(signal='SIGINT', t_ns=stamp))
                stop_started = time.monotonic()
            if args.control == 'repeated-signals' and receipt['signals'] and not sent_more and time.monotonic_ns() - receipt['signals'][0]['t_ns'] >= 30_000_000:
                observer.send(signal.SIGTERM)
                receipt['signals'].append(dict(signal='SIGTERM', t_ns=time.monotonic_ns()))
                sent_more = True
            if receipt['stderr_blocked'] and receipt['signals'] and now - stop_started > 1 \
                    and stderr_pipe.write_fd is not None:
                # Release only for cleanup. Prompt acknowledgement is measured
                # through the independent probe while this channel stays blocked.
                stderr_pipe.close_writer()
                receipt['stderr_release_ns'] = time.monotonic_ns()
                while stderr_pipe.read():
                    pass
            if stop_started is None and final_ns is not None:
                stop_started = time.monotonic()
            time.sleep(0.001)
        exited = time.monotonic()
        if receipt['stderr_blocked'] and receipt['stderr_release_ns'] is None:
            receipt['stderr_release_ns'] = time.monotonic_ns()
        if receipt['stderr_blocked']:
            # The pidfd-gated loop above never reaped the original child; its
            # pidfd and unreaped identity retain custody until the helper's
            # final kernel counters reconcile.
            if observer.popen.returncode is not None:
                raise ValueError('observer was reaped before probe reconciliation')
            witness.popen.stdin.write('stop\n')
            witness.popen.stdin.flush()
            if witness.popen.wait(timeout=5) != 0:
                raise ValueError('actual external probe failed; its rows are unqualified')
            witness_facts.finish()
            witness_errors.finish()
            rows = probe_rows(witness_facts)
            witness_verdict = PROBE['validate_witness'](rows, expected, receipt['signals'])
            receipt['reporter_ack'] = dict(channel=witness_verdict['channel'], ack_ns=witness_verdict['ack_ns'])
            receipt['reporter_kernel'] = dict(samples=rows[2]['samples'],
                                              kernel_count=rows[2]['kernel_count'], lost=rows[2]['lost'])
            receipt['probe_records'] = rows
            receipt['observer_rc'] = observer.popen.wait()
            receipt['observer_reaped_after_probe'] = True
        else:
            receipt['observer_rc'] = observer.popen.wait()
        receipt['cleanup_seconds'] = exited - (stop_started if stop_started is not None else start)
        while stderr_pipe.read():
            pass
        errors = stderr_pipe.received
        (directory / 'observer.stderr').write_bytes(errors)
        if pipe:
            pipe.close_writer()
            stdout = pipe.drain_available()  # no EOF wait, even with held writer
            (directory / 'stdout.txt').write_bytes(stdout)
        elif sink == 'file':
            stdout_file.flush()
            stdout = bounded_read(directory / 'stdout.txt')
        else:
            stdout = None
        record_cancellation_marker(receipt, errors)
        if not ack_complete:
            raise ValueError('independent provider workload did not acknowledge every issued call')
        caller.popen.stdin.write('stop\n')
        caller.popen.stdin.flush()
        ledger_reader.record('ack', 0, 'done')
        if caller.popen.wait(timeout=3) != 0:
            raise ValueError('actual provider caller failed')
        for reader in readers:
            reader.finish()
        receipt['provider_after'] = PIN_PROVIDER(provider.fd)
        trace = bounded_read(trace_path)
        result = ORACLE(trace, stdout, ledger_reader.records, receipt)
        if args.control == 'repeated-signals' and len(receipt['signals']) < 2:
            result.update({'pass': False, 'status': 'NOT_RUN'})
            result['unqualified'].append('observer exited before repeated-signal delivery')
        # A file-limit cell is an intentionally failing output, never a source
        # of authoritative API/byte totals or a hard regular-file stop guarantee.
        if args.control == 'file-limit':
            result['regular_file_limit_observed'] = receipt['observer_rc'] != 0
        for pin in (binary, provider, caller_pin):
            pin.verify()
        manifest_arguments(manifests, provider)
        save(directory / 'receipt.json', receipt)
        save(directory / 'result.json', result)
        return result
    except BaseException as error:
        receipt['trace_file_error'] = str(error)
        save(directory / 'receipt.json', receipt)
        raise
    finally:
        try:
            with NATIVE.cleanup_section():
                NATIVE.cleanup_processes(owners)
        finally:
            for reader in readers:
                reader.thread.join(timeout=1)
                reader.stream.close()
            for owner in owners:
                for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                    if stream is not None:
                        stream.close()
            for pipe in pipes:
                pipe.close()
            if stdout_file:
                stdout_file.close()


def dry_run(args, names):
    """Prove blocked-stderr wiring without privilege; spawn nothing, write nothing.

    Pins every held input, binds the reporter-controls summary to this exact
    source and candidate, resolves the actual reporter file offset, and runs
    the real stderr pressure witness against a bounded pipe. Exit 0 prints a
    JSON plan; any broken input exits 1 with a JSON error.
    """
    pins = []
    try:
        if (args.uid <= 0 or args.gid <= 0
                or not re.fullmatch('[0-9a-f]{40}', args.source_revision)
                or not 1 <= args.calls <= 10000 or not names or len(set(names)) != len(names)
                or any(name not in CELLS for name in names)
                or any(not getattr(args, name).is_absolute() for name in ('binary', 'provider', 'caller', 'out'))
                or any(not path.is_absolute() for path in args.manifest)):
            raise ValueError('requires ordinary workload uid/gid, exact source commit, bounded unique cells and absolute paths')
        if (args.control == 'blocked-stderr') != (args.reporter_probe is not None and args.reporter_controls is not None):
            raise ValueError('blocked-stderr needs exactly --reporter-probe and --reporter-controls; other controls take neither')
        if args.reporter_probe is not None and (not args.reporter_probe.is_absolute() or not args.reporter_controls.is_absolute()):
            raise ValueError('reporter inputs need absolute paths')
        if args.control == 'child-held-stdout' and any('-slowpipe-' not in name for name in names):
            raise ValueError('child-held-stdout requires only slowpipe cells')
        if args.control in ('blocked-stderr', 'repeated-signals') and any(name.endswith('-none') for name in names):
            raise ValueError('signal controls require a cancellation cell')
        for path in (args.binary, args.provider, args.caller):
            pins.append(NATIVE.FilePin(path))
        manifests = [NATIVE.FilePin(path) for path in args.manifest]
        pins.extend(manifests)
        manifest_arguments(manifests, pins[1])
        plan = dict(mode='dry_run', cells=names, control=args.control,
                    source_revision=args.source_revision,
                    inputs=[pin.metadata() for pin in pins])
        if args.control == 'blocked-stderr':
            helper = NATIVE.FilePin(args.reporter_probe)
            pins.append(helper)
            summary = BLOCKED['load_controls_summary'](args.reporter_controls)
            dependencies = BLOCKED['check_dependencies'](summary, source_revision=args.source_revision,
                                                         candidate_sha256=pins[0].digest)
            resolved = PROBE['resolve_reporter'](pins[0])
            pipe = OutputPipe()
            try:
                os.set_blocking(pipe.write_fd, False)
                witnessed = os.write(pipe.write_fd, b'H' * 169)
                try:
                    os.write(pipe.write_fd, b'X' * 4096)
                except BlockingIOError:
                    stalled = pipe.stalled()
                else:
                    raise ValueError('stderr pressure witness did not stall below pipe capacity')
                pressure = dict(stalled=stalled, buffered_bytes=pipe.buffered(), witnessed_write=witnessed)
                if not pressure['stalled'] or pressure['buffered_bytes'] <= 0:
                    raise ValueError('stderr pressure witness cannot prove kernel nonwritability')
            finally:
                pipe.close()
            plan.update(reporter_probe=helper.metadata(), dependencies=dependencies,
                        reporter_file_offset=resolved['file_offset'],
                        probe_argv=['<reporter-probe>', '--probe', '<binary-fd>', '<pid>', '<birth>',
                                    str(resolved['file_offset']), '90000'],
                        pressure_selfcheck=pressure)
        print(json.dumps(plan))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(mode='dry_run', error=str(error))), file=sys.stderr)
        return 1
    finally:
        for pin in pins:
            pin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'provider', 'caller', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--manifest', type=Path, action='append', default=[],
                        help='explicit trusted-helper attestation for this exact provider; repeatable')
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    parser.add_argument('--cells', default=','.join(CELLS))
    parser.add_argument('--calls', type=int, default=4096)
    parser.add_argument('--control', choices=('ordinary', 'child-held-stdout', 'blocked-stderr',
                                             'file-limit', 'repeated-signals'), default='ordinary')
    parser.add_argument('--reporter-probe', type=Path,
                        help='verified prebuilt reporter-probe helper; required exactly for blocked-stderr')
    parser.add_argument('--reporter-controls', type=Path,
                        help='qualify_reporter_probe.py summary; required exactly for blocked-stderr')
    parser.add_argument('--dry-run', action='store_true',
                        help='validate wiring without privilege and spawn nothing')
    args = parser.parse_args()
    names = args.cells.split(',')
    if args.dry_run:
        return dry_run(args, names)
    if (os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0
            or not re.fullmatch('[0-9a-f]{40}', args.source_revision)
            or not 1 <= args.calls <= 10000 or not names or len(set(names)) != len(names)
            or any(name not in CELLS for name in names)
            or any(not getattr(args, name).is_absolute() for name in ('binary', 'provider', 'caller', 'out'))
            or any(not path.is_absolute() for path in args.manifest)
            or any(path is not None and not path.is_absolute()
                   for path in (args.reporter_probe, args.reporter_controls))):
        parser.error('requires root, ordinary workload uid/gid, exact source commit, bounded unique cells and absolute paths')
    if (args.control == 'blocked-stderr') != (args.reporter_probe is not None and args.reporter_controls is not None):
        parser.error('blocked-stderr needs exactly --reporter-probe and --reporter-controls; other controls take neither')
    if args.control == 'child-held-stdout' and any('-slowpipe-' not in name for name in names):
        parser.error('child-held-stdout requires only slowpipe cells')
    if args.control in ('blocked-stderr', 'repeated-signals') and any(name.endswith('-none') for name in names):
        parser.error('signal controls require a cancellation cell')
    os.umask(0o022)
    args.out.mkdir(mode=0o755)  # new-only; never overwrite a previous run
    work = args.out / 'workload'
    work.mkdir(mode=0o755)
    pins, manifests, results = [], [], []
    try:
        env = NATIVE.initialize_tokens(work, args.uid, args.gid)
        for path in (args.binary, args.provider, args.caller):
            pins.append(NATIVE.FilePin(path))
        for path in args.manifest:
            manifests.append(NATIVE.FilePin(path))
        manifest_arguments(manifests, pins[1])
        blocked = None
        if args.control == 'blocked-stderr':
            helper = NATIVE.FilePin(args.reporter_probe)
            pins.append(helper)
            try:
                controls_summary = BLOCKED['load_controls_summary'](args.reporter_controls)
                dependencies = BLOCKED['check_dependencies'](controls_summary,
                    source_revision=args.source_revision, candidate_sha256=pins[0].digest)
                resolved = PROBE['resolve_reporter'](pins[0])
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                blocked = {'error': str(error)}
            else:
                blocked = {'helper': helper, 'resolved': resolved, 'dependencies': dependencies}
        for name in names:
            directory = args.out / name
            directory.mkdir(mode=0o755)
            try:
                result = cell(args, name, directory, env, pins[0], pins[1], pins[2], manifests, blocked=blocked)
            except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                result = {'pass': False, 'status': 'FAIL', 'errors': [str(error)]}
            results.append(dict(cell=name, **result))
            print(json.dumps(results[-1]), flush=True)
        remaining = [result['cell'] for result in results if not result['pass']]
        if blocked is not None and blocked.get('error'):
            remaining.append(blocked['error'])
        save(args.out / 'summary.json', dict(source_revision=args.source_revision,
            kernel=os.uname().release, control=args.control,
            inputs=[pin.metadata() for pin in pins], manifests=[pin.metadata() for pin in manifests],
            discovery_mode='explicit-manifest' if manifests else 'scan-only', cells=results,
            reporter_probe=pins[3].metadata() if blocked is not None else None,
            reporter_dependencies=blocked.get('dependencies') if blocked else None,
            reporter_error=blocked.get('error') if blocked else None,
            remaining=remaining,
            qualification=('blocked-stderr E17 with independent reporter acknowledgement'
                           if args.control == 'blocked-stderr'
                           else 'ordinary E17 output matrix; blocked-stderr needs --control blocked-stderr'),
            unexecuted=[name for name in CELLS if name not in names]))
        return 0 if all(result['pass'] for result in results) else 1
    finally:
        for pin in (*pins, *manifests):
            pin.close()


if __name__ == '__main__':
    try:
        with NATIVE.signal_cleanup():
            sys.exit(main())
    except NATIVE.TerminationRequested as error:
        sys.exit(128 + error.signum)
