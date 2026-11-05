#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Blocked-stderr E17 acceptance: dependency binding plus ACK/pressure/cleanup verdict.

The blocked stderr channel cannot prove its own prompt acknowledgement, so a
blocked-stderr cell is qualified only through the independent owned reporter
probe: same-source, same-candidate `none`, `handlerblocked` and `wrongworker`
controls must have actually passed, the probe must observe exactly one timely
main-thread reporter entry with reconciled zero-loss kernel counters, kernel
stderr pressure must be proved while the observer lived, and probe
reconciliation must precede observer reap. Missing measurement stays
unqualified; corrupt or late evidence fails. This module is pure stdlib so both
the E17 harness and its oracle can load it without a dependency cycle.
"""

import json

REQUIRED_CONTROLS = ('none', 'handlerblocked', 'wrongworker')
SUMMARY_LIMIT = 1024 * 1024


def load_controls_summary(path):
    """Read a bounded `qualify_reporter_probe.py` summary document."""
    with open(path, 'rb') as stream:
        payload = stream.read(SUMMARY_LIMIT + 1)
    if len(payload) > SUMMARY_LIMIT:
        raise ValueError('reporter controls summary exceeds its 1MiB bound')
    try:
        summary = json.loads(payload)
    except ValueError as error:
        raise ValueError(f'reporter controls summary is not valid JSON: {error}')
    if not isinstance(summary, dict):
        raise ValueError('reporter controls summary is not a JSON object')
    return summary


def check_dependencies(summary, *, source_revision, candidate_sha256):
    """Bind actually passed controls to this exact source and candidate.

    Every required control must have `control_pass` true in the supplied
    summary, on the same source revision and candidate bytes. A control
    receipt that names its own candidate must agree too; mixed-candidate
    summaries cannot qualify any cell.
    """
    if not isinstance(summary, dict):
        raise ValueError('reporter controls summary is not a JSON object')
    if summary.get('source_revision') != source_revision:
        raise ValueError('reporter controls were qualified on another source revision')
    candidate = summary.get('candidate')
    if not isinstance(candidate, dict) or candidate.get('sha256') != candidate_sha256:
        raise ValueError('reporter controls were qualified on another candidate')
    controls = summary.get('controls')
    if not isinstance(controls, list) or not controls:
        raise ValueError('reporter controls summary names no actual control receipts')
    passed = []
    for row in controls:
        if not isinstance(row, dict) or type(row.get('control_pass')) is not bool:
            raise ValueError('malformed reporter control receipt')
        row_candidate = row.get('candidate')
        if isinstance(row_candidate, dict) and row_candidate.get('sha256') != candidate_sha256:
            raise ValueError(f'reporter control {row.get("cell")} was qualified on another candidate')
        if row.get('control_pass') and row.get('cell') in REQUIRED_CONTROLS and row['cell'] not in passed:
            passed.append(row['cell'])
    missing = [name for name in REQUIRED_CONTROLS if name not in passed]
    if missing:
        raise ValueError('reporter dependencies not qualified on this candidate: ' + ','.join(missing))
    return dict(source_revision=source_revision, candidate_sha256=candidate_sha256, passed=sorted(passed))


def verdict(receipt):
    """Judge one blocked-stderr cell receipt; returns (errors, unqualified, latency)."""
    errors, unavailable = [], []
    latency = None
    controls = receipt.get('reporter_controls')
    if not isinstance(controls, dict):
        unavailable.append('blocked-stderr acknowledgement needs qualified reporter dependencies '
                           '(none, handlerblocked, wrongworker) on this source/candidate')
    else:
        passed = controls.get('passed')
        if (controls.get('source_revision') != receipt.get('source_revision')
                or controls.get('candidate_sha256') != receipt.get('candidate_sha256')
                or not isinstance(passed, list)):
            unavailable.append('reporter dependency source/candidate differs from this blocked-stderr cell')
        else:
            missing = [name for name in REQUIRED_CONTROLS if name not in passed]
            if missing:
                unavailable.append('reporter dependencies not qualified on this candidate: ' + ','.join(missing))
    ack = receipt.get('reporter_ack')
    signals = receipt.get('signals')
    delivered = isinstance(signals, list) and len(signals) > 0
    if ack is None and not delivered:
        unavailable.append('requested signal was not delivered to a live owned observer')
        return errors, unavailable, latency
    if ack is None:
        unavailable.append('no independently observed cancellation acknowledgement through the '
                           'reporter channel while stderr was blocked')
    elif (not isinstance(ack, dict) or ack.get('channel') != 'owned_perf_reporter'
            or type(ack.get('ack_ns')) is not int):
        errors.append('blocked-stderr acknowledgement did not arrive through the independent reporter channel')
    elif (not isinstance(signals, list) or not signals or not isinstance(signals[0], dict)
            or type(signals[0].get('t_ns')) is not int):
        errors.append('blocked-stderr acknowledgement lacks its independently sent first signal')
    else:
        delta = ack['ack_ns'] - signals[0]['t_ns']
        if not 0 <= delta < 100_000_000:
            errors.append('independent blocked-stderr acknowledgement missed the separate <100ms target')
        else:
            latency = delta / 1e9
    if ack is not None:
        kernel = receipt.get('reporter_kernel')
        if (not isinstance(kernel, dict)
                or any(type(kernel.get(key)) is not int for key in ('samples', 'kernel_count', 'lost'))
                or (kernel['samples'], kernel['kernel_count'], kernel['lost']) != (1, 1, 0)):
            errors.append('unreconciled or lossy independent reporter kernel evidence')
        release = receipt.get('stderr_release_ns')
        if type(release) is not int or not isinstance(ack, dict) or type(ack.get('ack_ns')) is not int:
            errors.append('independent acknowledgement was not measured while stderr was still blocked')
        elif release < ack['ack_ns']:
            errors.append('independent acknowledgement was not measured while stderr was still blocked')
    if receipt.get('stderr_stalled') is not True or type(receipt.get('stderr_buffered_bytes')) is not int \
            or receipt['stderr_buffered_bytes'] <= 0:
        errors.append('blocked stderr lacks actual kernel pressure proof while the observer lived')
    if receipt.get('observer_reaped_after_probe') is not True:
        errors.append('independent probe kernel counters were not reconciled before observer reap')
    return errors, unavailable, latency
