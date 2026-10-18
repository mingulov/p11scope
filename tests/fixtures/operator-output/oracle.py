#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent E17 accounting oracle; fixture checks do not qualify live output."""
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[3]
TRACE = runpy.run_path(str(ROOT / 'scripts/cgroup-trace-oracle.py'))
LOSS = re.compile(r'LOST ([1-9][0-9]*) events')


def evaluate(trace, stdout, ledger, receipt):
    """Compare caller-issued API units, lost records and delivered/shed bytes.

    The exact EVENT loss equation applies only to this one owned single-threaded
    PID, which makes no forks/execs while attached and issues only GenerateRandom.
    The harness finishes all issued calls before any stop; it never estimates an
    attachment or interrupted-call prefix from observer output.
    """
    errors, unavailable = [], []
    result = dict(pass_=False, api_calls=None, events_lost=None,
                  stdout_shed_bytes=None,
                  stdout_delivered_bytes=None if stdout is None else len(stdout),
                  cancellation_response_seconds=None)
    try:
        text = trace.decode('utf-8', 'strict')
        losses, lines = [], []
        for line in text.splitlines():
            match = LOSS.fullmatch(line)
            if match:
                losses.append(int(match[1]))
            else:
                lines.append(line)
        rows, counts, evidence, parse_errors = TRACE['parse_trace']('\n'.join(lines))
        errors.extend(parse_errors)
        calls = [row for row in ledger if row.get('kind') == 'call' and row.get('phase') == 'e17']
        if not re.fullmatch('[0-9a-f]{40}', receipt['source_revision']):
            errors.append('missing immutable source revision')
        expected_ring = {'4K': 4096, '4M': 4194304, '16M': 16777216}.get(receipt['ring_requested'])
        if expected_ring is None or receipt['ring_actual_bytes'] != expected_ring:
            errors.append('actual owned EVENTS ring differs from the selected cell')
        expected = receipt['issued_calls']
        if type(expected) is not int or expected <= 0 or len(calls) != expected:
            errors.append('independent issued/acknowledged call population is empty or disagrees')
        for call in calls:
            if (call['fn'] != 'C_GenerateRandom' or call['rv'] != 0
                    or call['pid'] != receipt['pid'] or call['tid'] != receipt['pid']
                    or not receipt['ready_ns'] <= call['t0'] <= call['t1'] <= receipt['workload_complete_ns']):
                errors.append('independent call lacks expected safe function, success, identity or capture interval')
        if any((row['pid'], row['tid'], row['fn'], row['rv']) !=
               (receipt['pid'], receipt['pid'], 'C_GenerateRandom', 'CKR_OK') for row in rows):
            errors.append('trace row differs from the independently controlled call population')
        if not rows:
            errors.append('actual safe-provider trace positive is empty')
        if counts and evidence:
            count, ev = counts[0], evidence[0]
            actual = count['raw_calls']
            lost = ev['event_loss']
            shed = ev['scheduling']['sink_dropped_bytes']
            if any(type(value) is not int or value < 0 for value in
                   (actual, lost, shed, count['stats_entered'], count['stats_returned'])):
                errors.append('accounting units must be nonnegative integers')
            if count['stats_entered'] != expected or count['stats_returned'] != expected:
                errors.append('aggregate API counts disagree with independent issued/acknowledged calls')
            if actual != len(rows) or expected - actual != lost:
                errors.append('lost EVENTS records do not reconcile with independent completed calls')
            if losses and (losses != sorted(set(losses)) or losses[-1] != lost):
                errors.append('cumulative LOST record disagrees with final event loss')
            if lost and not losses:
                errors.append('lossy trace omitted its mandatory LOST record')
            if ev.get('malformed_records', 0) or ev.get('unmatched_returns', 0):
                errors.append('malformed/unmatched records invalidate the one-record-per-call control')
            if receipt['sink'] == 'discard':
                if stdout is not None or shed or ev['scheduling']['sink_timeouts']:
                    errors.append('discard control must shed zero bytes without invented byte delivery')
            elif stdout is None or len(trace) - len(stdout) != shed or (shed == 0 and stdout != trace):
                errors.append('stdout shed bytes do not equal the complete saved-trace byte difference')
            if receipt['sink'] == 'slowpipe' and not receipt['stdout_stalled']:
                errors.append('slow pipe never established a genuinely full owned output')
            result.update(api_calls=expected, events_lost=lost, stdout_shed_bytes=shed)
        if receipt['trace_file_error'] or receipt['observer_rc'] != 0 or receipt['watchdog']:
            errors.append('failed observer, saved trace or watchdog cannot supply authoritative totals')
        if not 0 <= receipt['cleanup_seconds'] <= 60:
            errors.append('trace cleanup exceeded its separate60s normal-stop bound')
        cancel = receipt['cancel']
        if cancel not in ('none', 'midcapture', 'midfinal'):
            errors.append('unknown cancellation stage')
        if cancel == 'none' and receipt['signals']:
            errors.append('unsignalled control received a signal')
        if cancel == 'midfinal' and not receipt['terminal_observed_alive']:
            unavailable.append('mid-final delivery window was not observed while observer lived')
        if cancel != 'none':
            if not receipt['signals']:
                unavailable.append('requested signal was not delivered to a live owned observer')
            elif receipt['cancellation_ack_ns'] is None:
                unavailable.append('no independently observable cancellation acknowledgement')
            else:
                latency = (receipt['cancellation_ack_ns'] - receipt['signals'][0]['t_ns']) / 1e9
                result['cancellation_response_seconds'] = latency
                if not 0 <= latency < 0.1:
                    errors.append('observed cancellation acknowledgement missed the separate<100ms target')
        if receipt.get('stderr_blocked'):
            unavailable.append('blocked stderr cannot measure acknowledgement through that same channel')
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        errors.append(f'invalid qualification input: {error}')
    result.pop('pass_')
    result.update({'pass': not errors and not unavailable,
                   'status': 'FAIL' if errors else 'NOT_RUN' if unavailable else 'PASS',
                   'errors': errors, 'unqualified': unavailable})
    return result
