#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned actual-reporter controls; never a complete blocked-stderr acceptance.

The delayed control queues a signal while the process is stopped. It does not
claim that its handler ran while the main thread was blocked.
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

ROOT = Path(__file__).resolve().parents[3]
HARNESS = runpy.run_path(str(ROOT / 'scripts/qualify-operator-output.py'))
NATIVE = HARNESS['NATIVE']
PROBE = runpy.run_path(str(Path(__file__).with_name('reporter_probe.py')))
CELLS = ('none', 'readable', 'repeated', 'delayed', 'wrongexe', 'wrongprocess')
NEGATIVE_CELLS = ('handlerblocked', 'wrongworker')


def json_rows(reader):
    return [json.loads(line) for line in reader.lines]


def observer_diagnostics(reader, *, no_signal=False):
    # A zombie can still have bytes pending in this independent reader. EOF
    # completion is bounded and does not reap/release original observer custody.
    reader.finish()
    payload = ''.join(reader.lines).encode()
    if no_signal and b'p11scope: cancel:' in payload:
        raise ValueError('no-signal observer reported cancellation')
    return payload


def _check_zero(records, expected, *, main_thread):
    if (not isinstance(records, (list, tuple)) or len(records) != 2
            or any(not isinstance(row, dict) for row in records)
            or [row.get('kind') for row in records] != ['ready', 'final']
            or any(row.get('mode') != 'perf_uprobe' for row in records)):
        raise ValueError('no-signal control lacks actual ready/final with zero samples')
    ready, final = records
    if (ready.get('clock') != 'CLOCK_MONOTONIC'
            or ready.get('role') != 'reporter' or expected.get('role') != 'reporter'
            or (expected.get('pid') == expected.get('tid')) != main_thread
            or any(type(ready.get(key)) is not int or ready[key] < 0 or ready[key] != expected[key]
                   for key in ('pid', 'tid', 'start_time', 'dev', 'ino', 'file_offset'))
            or any(type(final.get(key)) is not int or final[key] != 0 for key in ('samples', 'kernel_count', 'lost'))
            or type(final.get('time_enabled')) is not int or final['time_enabled'] <= 0
            or final['time_enabled'] != final.get('time_running')):
        raise ValueError('no-signal control has foreign identity, samples, loss or multiplexing')
    return dict(no_signal_samples=0, kernel_count=0, lost=0)


def check_zero(records, expected):
    return _check_zero(records, expected, main_thread=True)


def validate_worker_negative(callback, callback_expected, worker, worker_expected,
                             reporter, expected, gates, signals, release_ns, diagnostics):
    """Worker delivery while main is gated; neither delivery nor late entry is an ACK.

    The redesigned wrongworker control: main is held behind the readiness
    gate, one tgkill-targeted worker runs only the signal-handler closure,
    and main reports only after release. This requires prompt genuine worker
    delivery (<=100ms), exact entered/released main gate facts with main
    gated >=150ms past the signal, zero worker reporter events with positive
    enabled==running counters, and a real late main reporter entry. Both the
    worker delivery and the late main entry must fail the prompt-ACK
    validator: handler delivery, a non-main TID and the callback symbol are
    never an acknowledgement. Callback/gate timestamps never select an ACK.
    """
    facts = _check_zero(worker, worker_expected, main_thread=False)
    if (any(worker_expected.get(key) != expected.get(key)
            for key in ('pid', 'dev', 'ino', 'file_offset', 'ip'))
            or worker_expected['tid'] == expected['pid']):
        raise ValueError('worker probe does not belong to the same candidate process/reporter')
    if (any(callback_expected.get(key) != worker_expected.get(key)
            for key in ('pid', 'tid', 'start_time', 'dev', 'ino'))
            or callback_expected.get('role') != 'callback'
            or callback_expected['file_offset'] == worker_expected['file_offset']):
        raise ValueError('worker probes are not distinct roles on the same pinned worker')
    delivery = PROBE['validate_worker_delivery'](callback, callback_expected, signals)
    if (not isinstance(gates, (list, tuple)) or len(gates) != 2
            or any(not isinstance(row, dict) for row in gates)
            or [row.get('kind') for row in gates] != ['entered', 'released']
            or any(row.get('pid') != expected['pid'] or row.get('tid') != expected['tid']
                   or row.get('clock') != 'CLOCK_MONOTONIC' for row in gates)):
        raise ValueError('missing or foreign actual main gate entry/release facts')
    entered, released = gates[0].get('t_ns'), gates[1].get('t_ns')
    sent, delivered, observed = signals[0].get('t_ns'), callback[1].get('t_ns'), reporter[1].get('t_ns')
    if (any(type(stamp) is not int or not 0 < stamp < 2**64
            for stamp in [entered, released, sent, delivered, observed, release_ns])
            or not entered <= sent <= delivered <= released
            or released - sent < 150_000_000 or release_ns - sent < 150_000_000
            or not release_ns <= released <= observed):
        raise ValueError('worker delivery/main gating/release/late entry interval is unproved')
    PROBE['validate_binding'](reporter, expected)
    if HARNESS['cancellation_marker'](diagnostics, 2) is None:
        raise ValueError('late real main entry lacks complete matching readable marker')
    try:
        PROBE['validate_witness'](reporter, expected, signals)
    except ValueError as error:
        if 'missed<100ms' not in str(error):
            raise
    else:
        raise ValueError('late main entry was accepted as prompt acknowledgement')
    try:
        PROBE['validate_witness'](callback, callback_expected, signals)
    except ValueError:
        pass
    else:
        raise ValueError('worker delivery was accepted as prompt acknowledgement')
    try:
        check_zero(worker, worker_expected)
    except ValueError:
        pass
    else:
        raise ValueError('ordinary main validator accepted worker identity')
    return dict(worker_samples=facts['no_signal_samples'], worker_kernel_count=0,
                worker_delivery_ns=delivery['delivery_ns'],
                late_main_observation_ns=observed)


def validate_handler_blocked(reporter, expected, callback, callback_expected, gates,
                             signals, release_ns, diagnostics):
    """Reconcile a negative interval; callback/gate timestamps never select ACK."""
    PROBE['validate_binding'](reporter, expected)
    PROBE['validate_callback_binding'](callback, callback_expected)
    if (len(signals) != 1 or signals[0].get('signal') != 'SIGINT'
            or any(expected.get(key) != callback_expected.get(key)
                   for key in ('pid', 'tid', 'start_time', 'dev', 'ino'))
            or expected['file_offset'] == callback_expected['file_offset']
            or expected['ip'] == callback_expected['ip']):
        raise ValueError('negative needs one actual main SIGINT and distinct same-candidate probe roles')
    if (not isinstance(gates, (list, tuple)) or len(gates) != 3
            or any(not isinstance(row, dict) for row in gates)
            or [row.get('kind') for row in gates] != ['entered', 'interrupted', 'released']
            or any(row.get('pid') != expected['pid'] or row.get('tid') != expected['tid']
                   or row.get('clock') != 'CLOCK_MONOTONIC' for row in gates)):
        raise ValueError('missing or foreign actual main gate/EINTR/release facts')
    entered, interrupted, consumed = [row.get('t_ns') for row in gates]
    sent, delivered, observed = signals[0].get('t_ns'), callback[1].get('t_ns'), reporter[1].get('t_ns')
    ready = [reporter[0].get('t_ns'), callback[0].get('t_ns')]
    if (any(type(stamp) is not int or not 0 < stamp < 2**64
            for stamp in [entered, interrupted, consumed, sent, delivered, observed, release_ns, *ready])
            or not max(ready) <= sent <= delivered <= interrupted < release_ns <= consumed <= observed
            or not entered <= sent or release_ns - sent < 150_000_000):
        raise ValueError('delivery/EINTR/continued gate/release/main observation interval is unproved')
    if HARNESS['cancellation_marker'](diagnostics, 2) is None:
        raise ValueError('late real main observation lacks complete matching readable marker')
    try:
        PROBE['validate_witness'](reporter, expected, signals)
    except ValueError as error:
        if 'missed<100ms' not in str(error):
            raise
    else:
        raise ValueError('handler-only interval was accepted as prompt main acknowledgement')
    return dict(late_reporter_rejected=True, handler_delivery_ns=delivered,
                gate_release_consumed_ns=consumed, late_main_observation_ns=observed)


def cell(args, name, directory, env, binary, provider, caller_pin, helper, manifest, resolved):
    directory.mkdir(mode=0o755)
    owners, readers = [], []
    observer = witness = None
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
        with (directory / 'trace.stdout').open('wb') as output:
            observer = NATIVE.spawn_owned(owners,
                [str(binary.path), 'trace', '--pid', str(caller.pid), '--module', str(provider.path),
                 *HARNESS['manifest_arguments']([manifest], provider), '--duration', '6s',
                 '-o', str(directory / 'trace.txt')], 0, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
            receipt['observer_image'] = binary.image_receipt(dict(image=0), observer)
            errors = NATIVE.Reader(observer.popen.stderr, directory / 'observer.stderr')
            readers.append(errors)
            expected = PROBE['expected_witness'](binary, observer, resolved)
            receipt['expected_probe'] = expected
            if any(observer.identity[key] != NATIVE.process_identity(os.getpid())[key]
                   for key in ('pid_namespace', 'time_namespace')):
                raise ValueError('observer differs from controller timestamp/namespace context')
            wrong = name in ('wrongexe', 'wrongprocess')
            fd = caller_pin.fd if name == 'wrongexe' else binary.fd
            target = caller if name == 'wrongprocess' else observer
            argv = [str(helper.path), '--probe', str(fd), str(target.pid),
                    str(target.identity['start_time']), str(resolved['file_offset']), '90000']
            if wrong:
                rejected = subprocess.run(argv, pass_fds=(fd,), stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=5)
                receipt['refusal'] = dict(rc=rejected.returncode, stdout=rejected.stdout, stderr=rejected.stderr)
                if (rejected.returncode != 2 or rejected.stdout
                        or 'observer executable differs' not in rejected.stderr):
                    raise ValueError('wrong executable/process was not refused before probe readiness')
            else:
                witness = NATIVE.spawn_owned(owners, argv, 0, pass_fds=(fd,),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True)
                helper.image_receipt(dict(image=0), witness)
                facts = NATIVE.Reader(witness.popen.stdout, directory / 'probe.jsonl')
                probe_errors = NATIVE.Reader(witness.popen.stderr, directory / 'probe.stderr')
                readers.extend((facts, probe_errors))
                ready = facts.wait(lambda reader: next((row for row in json_rows(reader)
                    if row.get('kind') == 'ready'), None), seconds=5)
                if (ready.get('mode') != 'perf_uprobe' or ready.get('clock') != 'CLOCK_MONOTONIC'
                        or ready.get('role') != 'reporter'
                        or any(ready.get(key) != expected[key] for key in ('pid', 'tid', 'start_time', 'dev', 'ino', 'file_offset'))):
                    raise ValueError('probe readiness does not bind the actual original observer')
                for key in ('pid_namespace', 'time_namespace'):
                    if witness.identity[key] != observer.identity[key]:
                        raise ValueError('independent helper clock/namespace differs from observer')
            NATIVE.wait_capture_started(errors)
            command_start = time.monotonic_ns()
            caller.popen.stdin.write('calls C_GenerateRandom 20 0 reporter selected\n')
            caller.popen.stdin.flush()
            ledger.record('ack', 0, 'reporter')
            calls = [row for row in ledger.records if row.get('kind') == 'call' and row.get('phase') == 'reporter']
            if (len(calls) != 20 or any(row.get('fn') != 'C_GenerateRandom' or row.get('rv') != 0
                    or row.get('pid') != caller.pid or row.get('tid') != caller.pid
                    or row.get('scope') != 'selected' or not command_start <= row['t0'] <= row['t1'] for row in calls)):
                raise ValueError('independent real safe-provider calls did not complete')
            receipt['actual_safe_calls'] = len(calls)
            if name == 'delayed':
                observer.send(signal.SIGSTOP)
                deadline = time.monotonic() + 2
                while '\nState:\tT' not in (Path('/proc') / str(observer.pid) / 'status').read_text():
                    if time.monotonic() >= deadline:
                        raise TimeoutError('owned delayed-control stop not observed')
                    time.sleep(0.001)
            if name != 'none':
                stamp = time.monotonic_ns()
                observer.send(signal.SIGINT)
                receipt['signals'].append(dict(signal='SIGINT', t_ns=stamp))
            if name == 'delayed':
                time.sleep(0.15)
                receipt['continued_ns'] = time.monotonic_ns()
                observer.send(signal.SIGCONT)
            if name == 'repeated':
                time.sleep(0.03)
                if observer.wait_exit(0):
                    raise ValueError('observer exited before actual repeated signal')
                stamp = time.monotonic_ns()
                observer.send(signal.SIGTERM)
                receipt['signals'].append(dict(signal='SIGTERM', t_ns=stamp))
            marker_ns, deadline = None, time.monotonic() + 30
            while not observer.wait_exit(0.001):
                if time.monotonic() >= deadline:
                    raise TimeoutError('actual observer exceeded bounded control cleanup')
                if receipt['signals'] and marker_ns is None and HARNESS['cancellation_marker'](''.join(errors.lines).encode(), 2):
                    marker_ns = time.monotonic_ns()
            # No poll()/wait() has reaped the observer. Its pidfd and original
            # unreaped child retain custody until the helper's final counters.
            if observer.popen.returncode is not None:
                raise ValueError('observer was reaped before probe reconciliation')
            observer_diagnostics(errors, no_signal=name == 'none')
            if witness:
                witness.popen.stdin.write('stop\n')
                witness.popen.stdin.flush()
                if witness.popen.wait(timeout=5) != 0:
                    raise ValueError('actual external probe failed; its rows are unqualified')
                facts.finish()
                probe_errors.finish()
                rows = json_rows(facts)
                receipt['probe_records'] = rows
                if name == 'none':
                    receipt.update(check_zero(rows, expected))
                elif name == 'delayed':
                    PROBE['validate_binding'](rows, expected)
                    if (len(rows) != 3 or rows[1].get('t_ns', 0) < receipt['continued_ns']
                            or not rows[0]['t_ns'] <= receipt['signals'][0]['t_ns'] <= receipt['continued_ns']
                            or rows[1]['t_ns'] - receipt['signals'][0]['t_ns'] < 150_000_000):
                        raise ValueError('queued-signal delayed control lacks actual late main observation')
                    try:
                        PROBE['validate_witness'](rows, expected, receipt['signals'])
                    except ValueError as error:
                        if 'missed<100ms' not in str(error):
                            raise
                    else:
                        raise ValueError('delayed actual acknowledgement was accepted as prompt')
                    receipt['late_observation_rejected'] = True
                else:
                    receipt.update(PROBE['validate_witness'](rows, expected, receipt['signals']))
                    if marker_ns is None or not 0 <= marker_ns - receipt['signals'][0]['t_ns'] < 100_000_000:
                        raise ValueError('readable control lacks promptly matching actual marker')
                    receipt['readable_marker_arrival_ns'] = marker_ns
            receipt['observer_rc'] = observer.popen.wait(timeout=1)
            receipt['observer_reaped_after_probe'] = True
            if receipt['observer_rc'] != 0:
                raise ValueError('actual observer failed')
        caller.popen.stdin.write('stop\n')
        caller.popen.stdin.flush()
        ledger.record('ack', 0, 'done')
        if caller.popen.wait(timeout=3) != 0:
            raise ValueError('actual ordinary provider caller failed')
        for reader in readers:
            reader.finish()
        for pin in (binary, provider, caller_pin, helper, manifest):
            NATIVE.verify_input_path(pin)
        receipt['control_pass'] = True
        return receipt
    finally:
        if observer is not None and observer.popen.returncode is None:
            try:
                observer.send(signal.SIGCONT)
                observer.send(signal.SIGINT)
                if observer.wait_exit(60) and witness and witness.popen.returncode is None:
                    witness.popen.stdin.write('stop\n')
                    witness.popen.stdin.flush()
                    witness.popen.wait(timeout=5)
                observer.popen.wait(timeout=1)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        try:
            NATIVE.cleanup_processes(owners)
        except BaseException as error:
            receipt.update(control_pass=False, cleanup_error=str(error))
            raise
        finally:
            for reader in readers:
                reader.thread.join(timeout=1)
                reader.stream.close()
            for owner in owners:
                for stream in (owner.popen.stdin, owner.popen.stdout, owner.popen.stderr):
                    if stream is not None:
                        stream.close()
            (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'provider', 'caller', 'reporter-probe', 'manifest', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--cells', default=','.join(CELLS))
    parser.add_argument('--readiness-gate', type=Path,
                        help='explicit verified prebuilt negative-only preload; needed by handlerblocked')
    args = parser.parse_args()
    names = args.cells.split(',')
    if (os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0
            or not re.fullmatch('[0-9a-f]{40}', args.source_revision)
            or any(name not in CELLS + NEGATIVE_CELLS for name in names) or len(set(names)) != len(names)
            or any(not getattr(args, name).is_absolute() for name in ('binary', 'provider', 'caller', 'reporter_probe', 'manifest', 'out'))):
        parser.error('requires root, ordinary caller uid/gid, exact source, bounded unique cells and absolute paths')
    if ((any(name in NEGATIVE_CELLS for name in names)) != (args.readiness_gate is not None)
            or args.readiness_gate is not None and not args.readiness_gate.is_absolute()
            or os.environ.get('LD_PRELOAD')
            or any(key.startswith('P11SCOPE_TEST_GATE_') for key in os.environ)):
        parser.error('select a negative cell exactly when supplying an absolute gate; baseline environment must contain no preload/gate')
    os.umask(0o022)
    args.out.mkdir(mode=0o755)
    work = args.out / 'workload'
    work.mkdir(mode=0o755)
    pins, results = [], []
    try:
        env = NATIVE.initialize_tokens(work, args.uid, args.gid)
        for name in ('binary', 'provider', 'caller', 'reporter_probe', 'manifest'):
            pins.append(NATIVE.FilePin(getattr(args, name)))
        gate_pin = NATIVE.FilePin(args.readiness_gate) if args.readiness_gate is not None else None
        if gate_pin:
            pins.append(gate_pin)
        resolved = PROBE['resolve_reporter'](pins[0])
        negative = (runpy.run_path(str(Path(__file__).with_name('negative_reporter_controls.py')),
                                  init_globals={'BASE': globals()})
                    if any(name in NEGATIVE_CELLS for name in names) else None)
        for name in names:
            try:
                if name in NEGATIVE_CELLS:
                    result = negative['cell'](args, name, args.out / name, env, *pins[:5], resolved, gate_pin)
                else:
                    result = cell(args, name, args.out / name, env, *pins[:5], resolved)
            except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                result = dict(cell=name, control_pass=False, error=str(error))
            results.append(result)
            print(json.dumps(result), flush=True)
        passed = {row['cell'] for row in results if row['control_pass']}
        summary = dict(source_revision=args.source_revision, controls=results,
            remaining=[name for name in CELLS + NEGATIVE_CELLS if name not in passed]
                + ['complete blocked-stderr E17 pressure/content/cleanup oracles'],
            qualification='owned reporter controls only; no blocked-stderr or full E17 acceptance')
        (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0 if all(row['control_pass'] for row in results) else 1
    finally:
        for pin in pins:
            pin.close()


if __name__ == '__main__':
    with NATIVE.signal_cleanup():
        raise SystemExit(main())
