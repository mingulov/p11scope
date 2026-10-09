#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real-provider trace cells against independent caller and held-FD evidence.

Event wall times are unused: rendering anchors them on receipt. The first package
assigns a unique executable to each (PID, TID, function); ambiguous keys refuse.
"""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

JSON_STRING = r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"'
ROW = re.compile(
    rf'\d{{2}}:\d{{2}}:\d{{2}}\.\d{{6}} (?P<label>Unknown executable|{JSON_STRING}) '
    rf'\(PID (?P<pid>[1-9]\d*), TID (?P<tid>[1-9]\d*)\)'
    rf'(?: exe=(?P<path>{JSON_STRING}))?(?: sess#[1-9]\d*)? '
    r'(?P<fn>C_[A-Za-z0-9_]+)(?: \[semantics unverified\])? '
    r'→ (?P<rv>CKR_[A-Z0-9_]+|0x[0-9a-fA-F]+) '
    r'(?P<duration>[0-9]+(?:\.[0-9]+)?(?:ns|µs|ms|s))')
IMAGE_FIELDS = ('image', 'pid', 'start_time', 'path', 'dev', 'ino', 'mtime_ns',
                'pid_namespace', 'time_namespace')


def parse_trace(text):
    rows, counts, evidence, errors = [], [], [], []
    for line in text.splitlines():
        match = ROW.fullmatch(line)
        if match:
            row = match.groupdict()
            row['pid'], row['tid'] = int(row['pid']), int(row['tid'])
            if row['label'] == 'Unknown executable':
                if row['path'] is not None:
                    errors.append('unknown row carries an executable path')
                row['path'], row['label'] = None, None
            else:
                row['label'] = json.loads(row['label'])
                row['path'] = json.loads(row['path']) if row['path'] else None
                if not row['path']:
                    errors.append('named row lacks an executable path')
            rows.append(row)
        elif line.startswith(('COUNT_EVIDENCE ', 'EVIDENCE ')):
            prefix, body = line.split(' ', 1)
            try:
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise ValueError('record is not an object')
                (counts if prefix == 'COUNT_EVIDENCE' else evidence).append(value)
            except (ValueError, TypeError) as error:
                errors.append(f'invalid {prefix}: {error}')
        elif line.startswith('N3LEDGER '):
            # run --trace shares stdout with its child. These are fixture
            # records, separately saved as the independent caller ledger.
            try:
                if not isinstance(json.loads(line[9:]), dict):
                    raise ValueError('fixture record is not an object')
            except ValueError as error:
                errors.append(f'invalid caller record: {error}')
        elif not line or line in (
                'Trace — completed call events in arrival order',
                'Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.',
                'CAPTURE privacy=allowlisted'):
            continue
        else:
            errors.append(f'unexpected trace record: {line[:160]}')
    if len(counts) != 1 or len(evidence) != 1:
        errors.append('expected exactly one terminal count and evidence record')
    return rows, counts, evidence, errors


def _evaluate(trace, ledger, receipt, file_trace):
    rows, counts, evidence, errors = parse_trace(trace)
    if file_trace is not None:
        other_rows, other_counts, other_evidence, other_errors = parse_trace(file_trace)
        errors.extend(other_errors)
        if (rows, counts) != (other_rows, other_counts):
            errors.append('stdout/file event or count disagreement')
        # Only terminal stdout flush accounting may change after its snapshot.
        # Keep every other scheduling field in the parity comparison.
        def without_sink(value):
            value = dict(value)
            if 'scheduling' in value:
                scheduling = dict(value['scheduling'])
                for field in ('sink_stall_ms', 'sink_timeouts', 'sink_dropped_bytes'):
                    scheduling.pop(field, None)
                value['scheduling'] = scheduling
            return value
        if [without_sink(v) for v in evidence] != [without_sink(v) for v in other_evidence]:
            errors.append('stdout/file terminal evidence disagreement')
        if any(ev.get('scheduling', {}).get(field, 0) for ev in evidence + other_evidence
               for field in ('sink_timeouts', 'sink_dropped_bytes')):
            errors.append('capture lost output in this no-loss parity cell')
    for canary in receipt['privacy_canaries']:
        if not canary or any(canary in output for output in
                             (trace, file_trace or '', receipt['observer_stderr'])):
            errors.append('private fixture canary appears in capture output')
    if receipt['observer_rc'] != 0 or receipt['caller_rc'] != 0:
        errors.append('observer or caller did not exit successfully')
    if not 0 <= receipt['stop_latency_seconds'] <= receipt.get('stop_limit_seconds', 5):
        errors.append('normal stop exceeded the bounded cell limit')
    before, after = receipt['provider_before'], receipt['provider_after']
    if (before != after or before['dev'] != before['mapping']['dev']
            or before['ino'] != before['mapping']['ino']):
        errors.append('held provider pin changed or lacks the independent mapped-device anchor')
    if not re.fullmatch(r'[0-9a-f]{64}', before['sha256']):
        errors.append('invalid held provider digest')

    images = {row['image']: row for row in ledger if row['kind'] == 'image'}
    trusted_images = {row['image']: row for row in receipt['images']}
    if len(images) != sum(row['kind'] == 'image' for row in ledger):
        errors.append('duplicate caller image generation')
    if set(images) != set(trusted_images):
        errors.append('independent image receipts do not cover every caller image')
    for image_id, image in images.items():
        trusted = trusted_images.get(image_id, {})
        if any(image.get(field) != trusted.get(field) for field in IMAGE_FIELDS):
            errors.append('caller image disagrees with independently held executable/birth receipt')
        if any(image[field] != receipt[field] for field in ('pid_namespace', 'time_namespace')):
            errors.append('caller and observer clock/PID namespace disagree')
        if not image['path'].startswith('/') or any(image[field] <= 0 for field in
                ('pid', 'start_time', 'ino', 'mtime_ns', 'pid_namespace', 'time_namespace')):
            errors.append('incomplete caller image identity')
    targets = {(row['image'], row['fn']): row for row in ledger if row['kind'] == 'target'}
    calls = [row for row in ledger if row['kind'] == 'call']
    if 'phases' in receipt:
        phase_calls = [call for call in calls if call['phase'] not in ('setup', 'teardown')]
        phase_keys = set()
        for phase in receipt['phases']:
            key = phase['image'], phase['fn'], phase['phase']
            if key in phase_keys:
                errors.append('duplicate controller phase')
            phase_keys.add(key)
            population = [call for call in phase_calls
                          if (call['image'], call['fn'], call['phase']) == key]
            if len(population) != phase['count'] or any(
                    call['scope'] != phase['scope'] or not phase['t0'] <= call['t0'] <= call['t1'] <= phase['t1']
                    for call in population):
                errors.append('fixture phase disagrees with independently issued command/membership interval')
        if any((call['image'], call['fn'], call['phase']) not in phase_keys for call in phase_calls):
            errors.append('fixture call has no independently issued workload phase')
    start, ready, stop = (receipt[field] for field in
                          ('observer_started_ns', 'observer_ready_ns', 'observer_stopped_ns'))
    if not receipt['scope_created_ns'] < start <= ready < stop:
        errors.append('invalid independent observer interval')
    mandatory, possible, expected_images = Counter(), Counter(), defaultdict(set)
    selected_interval = []
    for call in calls:
        image = images[call['image']]
        target = targets.get((call['image'], call['fn']))
        if (not target or target['dev'] != before['dev'] or target['ino'] != before['ino']
                or target['file_offset'] < 0):
            errors.append(f"call lacks a matching physical provider target: {call['fn']}")
        if call['pid'] != image['pid'] or call['tid'] != image['pid'] or call['t1'] < call['t0']:
            errors.append('call identity/interval disagrees with its caller image')
        if call['rv'] != 0:
            errors.append(f"real provider call failed: {call['fn']} rv={call['rv']}")
        if call['scope'] != 'selected' or call['t1'] < start or call['t0'] >= stop:
            continue
        selected_interval.append(call)
        key = (call['pid'], call['tid'], call['fn'])
        expected_images[key].add(image['path'])
        if call['t0'] >= ready and call['t1'] < stop:
            mandatory[key] += 1
        elif receipt['cell'] == 'run' and call['phase'] == 'setup' and call['t1'] < ready:
            # Every setup call is ledgered. This explicitly uncertain prefix
            # can be attached or missed; never infer expectations from output.
            possible[key] += 1
        else:
            errors.append('provider call overlaps an unresolved observer boundary')
    if not mandatory:
        errors.append('no independently ledgered calls after capture readiness')
    if any(len(paths) != 1 for paths in expected_images.values()):
        errors.append('ambiguous executable for a PID/TID/function; a stronger oracle is required')
    actual = Counter((row['pid'], row['tid'], row['fn']) for row in rows)
    for key in actual.keys() | mandatory.keys():
        if not mandatory[key] <= actual[key] <= mandatory[key] + possible[key]:
            errors.append(f'captured provider-call population disagrees with ledger: {key}')
    named = unknown = false_names = 0
    populations = {image['path']: {'named': 0, 'unknown': 0} for image in images.values()}
    for row in rows:
        key = row['pid'], row['tid'], row['fn']
        if row['rv'] != 'CKR_OK':
            errors.append('capture disagrees with successful provider return ledger')
        if row['path'] is None:
            unknown += 1
        else:
            named += 1
            paths = expected_images.get(key, set())
            if len(paths) != 1 or row['path'] not in paths or row['label'] != Path(row['path']).name:
                false_names += 1
        paths = expected_images.get(key, set())
        if len(paths) == 1:
            populations[next(iter(paths))]['named' if row['path'] else 'unknown'] += 1
    if false_names:
        errors.append('capture published an executable other than the independently observed image')
    if receipt['require_named'] and not named:
        errors.append('required stable positive contains no named event')
    for image_id in receipt.get('require_named_images', []):
        if not populations[images[image_id]['path']]['named']:
            errors.append('required image contains no independently correct named event')
    if counts and any(counts[0].get(field) != len(rows) for field in
                      ('stats_entered', 'stats_returned', 'raw_calls')):
        errors.append('terminal counts disagree with independently accounted completed events')
    if evidence:
        ev = evidence[0]
        if ev.get('privacy_mode') != 'allowlisted' or ev.get('trace_truncated') is not False:
            errors.append('capture privacy policy/truncation differs from the requested policy')
        if any(ev.get(field, 0) != 0 for field in
               ('event_loss', 'start_insert_failures', 'unmatched_returns', 'rv_update_failures',
                'cgroup_scope_failures', 'process_tracking_failures', 'process_tracking_evictions')):
            errors.append('capture reports event/identity loss in this no-loss cell')
        if ev.get('final_drain') is False and ev.get('completeness') == 'COMPLETE':
            errors.append('capture claims complete without its final drain proof')
    # A fresh session with just one authentic provider CALL has no upper
    # witness. This is independent setup proof, not a timing assumption.
    first_proved = (receipt['cell'] != 'run' and receipt.get('fresh_observer') is True
                    and bool(selected_interval) and not possible
                    and set(receipt.get('selected_initial_pids', [])) == {call['pid'] for call in selected_interval}
                    and all(ready <= call['t0'] <= call['t1'] < stop for call in selected_interval))
    if first_proved and rows:
        first = min(selected_interval, key=lambda call: call['t0'])
        if (rows[0]['pid'], rows[0]['tid'], rows[0]['fn']) != (first['pid'], first['tid'], first['fn']):
            errors.append('first completed event disagrees with sequential independent call order')
        if rows[0]['path'] is not None:
            errors.append('fresh cgroup first CALL was named before any possible upper witness')
    cold_proved = (receipt['cell'] == 'onecall' and first_proved
                   and len(selected_interval) == 1 and sum(mandatory.values()) == 1
                   and not possible and all(call['t1'] < start or call['t0'] >= stop
                       or call in selected_interval for call in calls))
    if cold_proved and named:
        errors.append('fresh one-call session named an image without a possible second CALL witness')
    return {'pass': not errors, 'cell': receipt['cell'], 'calls': len(rows),
            'named': named, 'unknown': unknown, 'false_names': false_names,
            'named_share': named / len(rows) if rows else None,
            'unknown_share': unknown / len(rows) if rows else None,
            'image_populations': populations,
            'mandatory_calls': sum(mandatory.values()), 'possible_setup_calls': sum(possible.values()),
            'first_call_receipt_impossible': first_proved,
            'cold_receipt_impossible': cold_proved, 'counts': counts,
            'evidence': evidence, 'errors': errors}


def evaluate(trace, ledger, receipt, file_trace=None):
    try:
        return _evaluate(trace, ledger, receipt, file_trace)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {'pass': False, 'named': 0, 'unknown': 0, 'false_names': 0,
                'errors': [f'invalid independent evidence: {error}']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('ledger', type=Path)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--file-trace', type=Path)
    args = parser.parse_args()
    ledger = [json.loads(line.removeprefix('N3LEDGER ')) for line in args.ledger.read_text().splitlines()]
    result = evaluate(args.trace.read_text(), ledger, json.loads(args.receipt.read_text()),
                      args.file_trace.read_text() if args.file_trace else None)
    print(json.dumps(result, indent=2))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
