#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-inventory-native.sh — installed `p11scope inventory` acceptance (Task 6 C8).
#
#   qualify-inventory-native.sh P11SCOPE [--lane scan|native] [--base DIR] [--no-dashboard] [--max-endpoints N]
#   qualify-inventory-native.sh P11SCOPE --capacity boundary|growth|owners|real|refusal --max-endpoints N [--demand 4097|6531|8192]
#   A refusal cell needs --demand exactly one above --max-endpoints (4096/4097, 6530/6531, 8191/8192).
#   qualify-inventory-native.sh --self-test
#
# Host runs need a ROOT-OWNED --base (not group/other-writable); the default
# /var/tmp/p11scope-ws-tmp/c8-root is created 0711 by root when missing, and an
# existing non-root-owned BASE is refused before anything is created in it:
#   sudo install -d -o root -g root -m 0711 /var/tmp/p11scope-ws-tmp/c8-root
#
# Runs the shipped binary exactly as an operator would, against the ledgered
# SoftHSM2 workload tests/fixtures/public-cli/inventory-ledger.c, and judges the
# result with the independent oracle scripts/inventory-native-oracle.py:
#   run "system"     inventory --system, classic loop, -o + --event-log, over the cells
#                    P1 (attested A, mechanisms), P2 (byte copy B, distinct inode),
#                    P3 (maps A and C, never calls), P4 (~100 ms CLIs), P5 (exec chain:
#                    same binary, other binary, non-leader thread), P7 (late dlopen),
#                    LX (leader pthread_exit, worker keeps calling)
#   run "dashboard"  inventory --system --dashboard under a pty, -o + --event-log, over
#                    the still-held, now idle cells (frames must agree with the documents)
#   run "stop"       inventory --pid on P6 (a call held in the held provider until the
#                    harness releases it), SIGINT while the call is held
# --lane names the lane the run must prove (default native). --no-dashboard is
# recorded in run.json as a skipped run, which makes the verdict non-qualifying.
# Capacity populations use independent owned table/call ledgers and a separate
# capacity.json manifest. Synthetic boundaries and real SoftHSM/trust activity
# are separate cells. The real ledger still uses at most4 modules/process.
# The owners cell requires257 independently ledgered deep scans; retained
# native-owner activation remains unavailable untilP2. Candidate8192 is not a
# measured release envelope. CAPACITY_DURATION (1..600 seconds, default180),
# CAPACITY_WAIT_S (1..120, default60) and CAPACITY_ATTACH_BACKEND bound this runner.
#
# Exit codes are the oracle's: 0 qualified, 1 failed, 2 non-qualifying (no
# failure, but native assertions absent — every `--lane scan` plumbing run — or a
# skipped run); 64 usage; any other nonzero is a harness failure before judging.
#
# The observer runs as root; every workload runs as RUNUID:RUNGID (default
# 1000:1000) under setpriv --no-new-privs with a clean environment. Temp state
# lives in BASE (default /var/tmp/p11scope-ws-tmp/c8-root), which must be
# root-owned and not group/other-writable (created 0711 when missing): an
# observer dir (root 0700: evidence, ledgers, run.json) and a workload dir (root
# 0711: root-owned binaries and providers, gates, and one RUNUID-owned 0700 dir
# per cell for its SoftHSM2 token). A virtme-ng guest hides /var/tmp and /tmp:
# pass --base with a guest-local root-owned dir (e.g. a tmpfs mounted in the guest).
#
# Clock: the oracle compares ledger CLOCK_MONOTONIC times with p11scope's
# CLOCK_MONOTONIC capture clock, so workloads and observer must share one time
# namespace (host and vng guests do; a container lane must translate).
#
# Environment: RUNUID/RUNGID, MODULE (provider A), ITERS, DURATION (system run
# window, default 90 s), LATE_MS, STOP_WAIT_S, SYSTEM_ARGS (extra --system flags,
# e.g. "--max-scan-pids 4096"), P11SCOPE_DISCOVER.
#
# --self-test is unprivileged and hosted-CI safe: it compiles the fixture, runs
# every workload mode as the calling user against SoftHSM2 (each under a timeout),
# checks the ledgers' self-consistency, and runs the oracle's synthetic self-test.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd) || exit 64
SRC=$REPO/tests/fixtures/public-cli/inventory-ledger.c
ORACLE=$REPO/scripts/inventory-native-oracle.py
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
ITERS=${ITERS:-4}
ROTATE_BYTES=1024M  # far above any run: the oracle fails a rotated stream

die() { echo "qualify-inventory-native: $*" >&2; exit 70; }

# Closed C8 controller. Tests execute this exact embedded code; only P2 and
# required P5 images use its gates. Parent-held FDs survive every query/exec.
c8_gate() {
python3 -I - "$REPO" "$@" <<'C8_GATE_PY'
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

monotonic_ns = time.monotonic_ns
LIMIT = 16 * 1024 * 1024
# Same allowed exec reasons as inventory-native-oracle.py; progress is not its
# global allocation or an API count. Registered controls check this interface.
EXEC_REASONS = ('exec_after_admission', 'exec_transition', 'exec_coverage_gap',
                'cookie_mismatch', 'before_admission', 'no_live_caller')


def integer(value):
    return type(value) is int


def check_deadline(deadline):
    now = monotonic_ns()
    if not integer(deadline) or now >= deadline:
        raise ValueError('original C8 work deadline expired')
    return now


def same_caller(context, want, lifecycle='mapped'):
    if not isinstance(context, dict):
        return False
    exe = context.get('executable') or {}
    pin = want['exe']
    return (context.get('pid') == want['pid'] and context.get('start_time') == want['start']
        and integer(context.get('pid')) and integer(context.get('start_time'))
        and integer(context.get('incarnation')) and context['incarnation'] >= 0
        and context.get('status') == 'observed' and context.get('lifecycle') == lifecycle
        and context.get('authority') in ('scan_pinned', 'native_exact')
        and exe.get('path') == pin['path']
        and all(integer(exe.get(k)) and exe[k] == pin[k] for k in ('dev', 'ino'))
        and integer(exe.get('mtime_secs')) and integer(exe.get('mtime_nanos'))
        and exe.get('mtime_secs') == pin['mtime_ns'] // 1_000_000_000
        and exe.get('mtime_nanos') == pin['mtime_ns'] % 1_000_000_000)


def select_gate(records, want, phase):
    observed_ns = check_deadline(want['deadline'])
    result = select_publication(records, want, phase, observed_ns)
    check_deadline(want['deadline'])
    return result


def quiet_registration(instances, children, invalid, cid, mid, previous, commit):
    current = [(iid, event, row) for iid, (event, row) in instances.items()
               if event.get('caller') == cid and event.get('module') == mid and event.get('state') == 'observed']
    if len(current) != 1:
        return None
    iid, instance, publication = current[0]
    child, child_row = children.get(iid, ({}, {}))
    returns, coverage = child.get('api_returns') or {}, child.get('coverage') or {}
    if (iid in invalid or instance.get('reason') is not None
            or not integer(instance.get('first_seen_ns')) or not integer(instance.get('last_seen_ns'))
            or not previous['done_ns'] < instance['first_seen_ns'] <= instance['last_seen_ns'] <= publication['at_ns']
            or child.get('caller') != cid or child.get('module') != mid
            or not previous['seq'] < publication['seq'] < commit['seq']
            or not previous['seq'] < child_row.get('seq', -1) < commit['seq']):
        return None
    if (child.get('entries') != {'count': None, 'observation': 'unavailable', 'unit': 'api_entries'}
            or not integer(returns.get('historical_only_returns')) or returns['historical_only_returns'] != 0
            or returns.get('saturated') is not False or coverage.get('lossy') is not False
            or child.get('api_returns') != {'count': None, 'historical_only_returns': 0,
                                          'saturated': False, 'unit': 'api_returns'}
            or child.get('semantics') != 'unknown (no calls observed)'
            or child.get('mechanisms') is not None or child.get('operations') is not None
            or child.get('coverage') != {'lossy': False, 'reasons': ['no_calls']}):
        return None
    return {'instance': iid, 'instance_seq': publication['seq'], 'semantic_edge_seq': child_row['seq']}


def select_publication(records, want, phase, observed_ns):
    dead, candidates, edges, inconsistent = set(), {}, {}, set()
    gaps, witnesses = set(), []
    instances, children, invalid_instances = {}, {}, set()
    last_at, commit = 0, None
    previous = want.get('previous')
    pre = want.get('pre')
    native_pre = pre and pre.get('proof') == 'native_ready'
    expected_module = (pre or {}).get('module', (previous or {}).get('module'))
    floor = (pre if phase == 'post' and not native_pre else previous or {}).get('seq', -1)
    watermark = max(want.get('unbound_watermark', -1), (previous or {}).get('unbound_watermark', -1))
    origin = None
    for index, row in enumerate(records):
        if (row.get('schema') != 'p11scope/inventory-events/v1' or row.get('seq') != index
                or not integer(row.get('seq')) or not integer(row.get('at_ns'))
                or row['at_ns'] < last_at or row['at_ns'] > observed_ns
                or not isinstance(row.get('event'), dict)):
            return None
        kind, event, last_at = row.get('kind'), row['event'], row['at_ns']
        if index == 0:
            if (kind != 'started' or not integer(event.get('started_ns'))
                    or event.get('clock') != {'basis': 'CLOCK_MONOTONIC', 'unit': 'ns'}):
                return None
            origin = event['started_ns']
            if want.get('origin', origin) != origin:
                return None
        elif kind in ('started', 'ended', 'rotated', 'retention_evicted'):
            return None
        if kind == 'caller_event':
            context = event.get('identity_context') or {}
            if event.get('event') in ('retired', 'exited', 'unloaded', 'exec_retired', 'reused'):
                old = event.get('old', event.get('caller'))
                if isinstance(old, str): dead.add(old)
            subject = None
            if event.get('event') == 'admitted':
                subject = context.get('caller')
                eligible = want['gen'] == 0
                cid = event.get('caller')
            elif event.get('event') == 'exec_retired':
                subject = context.get('new')
                old = context.get('old') or {}
                cid = event.get('new')
                eligible = (previous is not None and event.get('old') == previous['caller']
                    and old.get('id') == previous['caller'] and old.get('pid') == want['pid']
                    and old.get('start_time') == want['start']
                    and old.get('incarnation') == previous['incarnation']
                    and same_caller(old, previous, 'exec_retired') and row['seq'] > floor)
            else:
                cid, eligible = None, False
            if isinstance(subject, dict) and isinstance(cid, str):
                if subject.get('lifecycle') in ('exited', 'exec_retired', 'unloaded'):
                    dead.add(cid)
                if (eligible and type(context.get('version')) is int and context['version'] == 1 and subject.get('id') == cid
                        and same_caller(subject, want)
                        and (previous is None or (cid != previous['caller']
                             and subject['incarnation'] > previous['incarnation']))):
                    candidates[cid] = (subject, row['seq'])
        elif kind == 'edge_observed':
            context = event.get('identity_context') or {}
            caller, module = context.get('caller') or {}, context.get('module') or {}
            cid, mid = event.get('caller'), event.get('module')
            pin = want['provider']
            if caller.get('id') == cid and caller.get('lifecycle') in ('exited', 'exec_retired', 'unloaded'):
                dead.add(cid)
            provider_matches = (module.get('status') == 'observed' and module.get('path') == pin['path']
                and integer(module.get('inode')) and module['inode'] == pin['ino']
                and integer(module.get('device_major')) and integer(module.get('device_minor'))
                and [module.get('device_major'), module.get('device_minor')] == pin['dev'])
            valid = (provider_matches and type(context.get('version')) is int and context['version'] == 1
                and caller.get('id') == cid and module.get('id') == mid and same_caller(caller, want))
            if cid in candidates or (pre and cid == pre.get('caller')):
                key = (cid, mid)
                known_pair = key in edges or (pre and key == (pre.get('caller'), pre.get('module')))
                expected_identity = {'id': mid, 'path': pin['path'], 'inode': pin['ino'],
                                     'device_major': pin['dev'][0], 'device_minor': pin['dev'][1]}
                identity_changed = any(module.get(k) is not None
                    and (type(module[k]) is not type(v) or module[k] != v)
                    for k, v in expected_identity.items())
                if known_pair and identity_changed:
                    inconsistent.add(key)  # Identity disagreement, not an unready coverage state.
                if provider_matches or known_pair:
                    edges[key] = (event, row) if valid else None
        elif kind in ('instance_observed', 'semantic_edge_observed'):
            iid = event.get('id' if kind == 'instance_observed' else 'instance')
            if isinstance(iid, str):
                for old_event, _old_row in (store[iid] for store in (instances, children) if iid in store):
                    if (old_event.get('caller'), old_event.get('module')) != (event.get('caller'), event.get('module')):
                        invalid_instances.add(iid)
                if kind == 'instance_observed' and event.get('state') == 'retired':
                    invalid_instances.add(iid)
                (instances if kind == 'instance_observed' else children)[iid] = (event, row)
        elif kind == 'gap_recorded':
            if (event.get('pid') is None and re.search(r'unidentified caller|unbound (caller|witness)',
                    f"{event.get('subject', '')} {event.get('reason', '')}", re.I)):
                gaps.add(event.get('module'))
        elif kind == 'pass_committed':
            if event.get('final') is True:
                return None
            if integer(event.get('pass')) and event['pass'] >= 0 and event.get('final', False) is False:
                commit = row
                for item in event.get('unbound_rows') or []:
                    if (isinstance(item, dict) and integer(item.get('rows')) and item['rows'] > 0
                            and item.get('reason') in EXEC_REASONS):
                        witnesses.append((row, item))
    if phase == 'native' and previous and commit is not None:
        return {'proof': 'native_ready', 'module': previous['module'], 'seq': commit['seq'],
            'origin': origin, 'deadline': want['deadline'], 'pid': want['pid'], 'start': want['start'],
            'gen': want['gen'], 'exe': want['exe']}
    if phase == 'post' and pre and not native_pre:
        candidates = {pre['caller']: ({'incarnation': pre['incarnation']}, pre['seq'])}
    for cid, (caller, admitted_seq) in sorted(candidates.items(), key=lambda item: item[1][1], reverse=True):
        pairs = [pair for key, pair in edges.items() if key[0] == cid and pair is not None
                 and key not in inconsistent and (phase != 'post' or key[1] == expected_module)]
        if cid in dead or len(pairs) != 1 or commit is None:
            continue
        edge, publication = pairs[0]
        if edge['identity_context']['caller']['incarnation'] != caller['incarnation']:
            continue
        entries = edge.get('entries') or {}
        coverage = entries.get('coverage') or {}
        if (edge.get('mapping', {}).get('state') != 'mapped'
                or not admitted_seq < publication['seq'] < commit['seq']):
            continue
        base = {'caller': cid, 'incarnation': caller['incarnation'], 'module': edge['module'],
            'seq': commit['seq'], 'edge_seq': publication['seq'], 'origin': origin,
            'deadline': want['deadline'], 'pid': want['pid'], 'start': want['start'],
            'gen': want['gen'], 'exe': want['exe'], 'unbound_watermark': watermark}
        # The native PID and public caller identify this held image, not the
        # anonymous row. Only the unchanged final oracle allocates that row.
        if (phase == 'post' and native_pre and publication['seq'] > floor
                and coverage.get('state') != 'counted'
                and commit['at_ns'] >= want['done_ns']
                and (edge['module'] in gaps or (coverage.get('state') == 'unknown'
                     and coverage.get('reason') == 'use_before_admission'))):
            for witness, item in witnesses:
                if (item['module'] == edge['module'] and witness['seq'] > max(floor, watermark)
                        and witness['at_ns'] >= want['first_entry_ns'] and witness['seq'] <= commit['seq']):
                    return dict(base, proof='publication_progress', done_ns=want['done_ns'],
                        unbound_watermark=witness['seq'],
                        witness={'seq': witness['seq'], 'module': item['module'], 'reason': item['reason']})
        inherited_zero = (phase == 'pre' and want['gen'] == 2
            and coverage.get('state') == 'unknown' and coverage.get('reason') == 'use_before_admission'
            and coverage.get('since_ns') is None and coverage.get('lossy') is None)
        timed_coverage = (coverage.get('reason') is None and integer(coverage.get('since_ns'))
                          and coverage['since_ns'] > 0)
        if (entries.get('saturated') is not False
                or entries.get('in_flight') is not False or not integer(entries.get('count'))
                or coverage.get('until_ns') is not None or coverage.get('detail') is not None
                or not (timed_coverage or inherited_zero)):
            continue
        if phase == 'pre':
            if ((not inherited_zero and coverage.get('state') != 'watched_no_use') or coverage.get('lossy') is not None
                    or entries['count'] != 0 or entries.get('first_seen_ns') is not None
                    or entries.get('last_seen_ns') is not None):
                continue
            if want['gen'] == 2:
                quiet = quiet_registration(instances, children, invalid_instances, cid, edge['module'], previous, commit)
                if quiet is None:
                    continue
                return dict(base, proof='quiet_ready', count=0, coverage_state=coverage['state'],
                            coverage_reason=coverage.get('reason'), **quiet)
        elif (coverage.get('state') != 'counted' or coverage.get('lossy') is not False
                or entries['count'] != want['count'] or publication['seq'] <= floor
                or publication['at_ns'] < want['last_entry_ns']
                or commit['at_ns'] < want['done_ns'] or edge['module'] != expected_module):
            continue
        return dict(base, proof='watch' if phase == 'pre' else 'bound_exact', count=entries['count'],
                    **({'done_ns': want['done_ns']} if phase == 'post' else {}))
    return None


def records_from(data):
    if len(data) > LIMIT:
        raise ValueError('C8 stream exceeds original byte bound')
    if not data.endswith(b'\n'):
        return None
    return [json.loads(line) for line in data.splitlines()]


def fd_identity(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('C8 input descriptor is not a regular file')
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def write_new(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream)
        stream.write('\n')


def main():
    root, operation, path, *args = sys.argv[1:]
    path = Path(path)
    h = runpy.run_path(str(Path(root) / 'scripts/qualify-cgroup-trace.py'))
    if operation == 'prepare':
        mapping = runpy.run_path(str(Path(root) / 'scripts/mapped-provider-pin.py'))
        pins = {}
        for role, number in zip(('L', 'L2', 'A', 'B'), args, strict=True):
            fd = int(number)
            source = str(Path(f'/proc/self/fd/{fd}').resolve(strict=True))
            pin = h['FilePin'](Path(source))
            try:
                ident = fd_identity(fd)
                if ident != fd_identity(pin.fd): raise ValueError('parent-held C8 pin differs')
                view = mapping['pin_fd'](fd) if role in ('A', 'B') else None
                pins[role] = {'fd': fd, 'path': source, 'identity': ident, 'sha256': pin.digest,
                    'exe': {'path': source, 'dev': ident[0], 'ino': ident[1], 'mtime_ns': ident[3]},
                    'provider': ({'path': source, 'dev': view['dev'], 'ino': view['ino']} if view else None)}
            finally: pin.close()
        write_new(path, {'pins': pins})
        return
    state = json.loads(path.read_text())
    if operation == 'start':
        stream_path, number, duration, observer_pid, parent = args
        fd = int(number)
        size = fd_identity(fd)[2]
        rows = records_from(os.pread(fd, min(size, LIMIT + 1), 0))
        if not rows or rows[0].get('kind') != 'started': raise ValueError('C8 stream has no start')
        origin = rows[0]['event']['started_ns']
        deadline = origin + int(duration) * 1_000_000_000
        check_deadline(deadline)
        observer = h['OwnedProcess'](int(observer_pid), int(parent), os.geteuid())
        try:
            if observer.wait_exit(0): raise ValueError('C8 observer exited before its work')
            observed = observer.identity
        finally: observer.close()
        state.update(stream={'fd': fd, 'path': stream_path, 'identity': fd_identity(fd)[:2]},
                     origin=origin, deadline=deadline, observer=observed)
        path.write_text(json.dumps(state) + '\n')
        print(deadline)
        return
    if operation not in ('pre', 'post'):
        raise ValueError('unknown C8 gate operation')
    cell, number, generation, exe_role, provider_role, ledger_path, prefix, parent, uid = args
    pid, gen = int(number), int(generation)
    ledger_path, prefix = Path(ledger_path), Path(prefix)
    deadline = state['deadline']
    exe, provider = state['pins'][exe_role], state['pins'][provider_role]
    maps_line = runpy.run_path(str(Path(root) / 'scripts/mapped-provider-pin.py'))['MAPS_LINE']
    pin = provider_pin = owner = observer = None
    try:
        pin = h['FilePin'](Path(exe['path']))
        provider_pin = h['FilePin'](Path(provider['path']))
        owner = h['OwnedProcess'](pid, int(parent), int(uid))
        observer = h['OwnedProcess'](state['observer']['pid'], int(parent), os.geteuid())
        def verify(require_image=False):
            check_deadline(deadline)
            if owner.wait_exit(0): raise ValueError('owned C8 actor died before gate')
            if observer.wait_exit(0): raise ValueError('C8 observer died before gate')
            owner.verify()
            observer.verify()
            h['assert_process_identity'](state['observer'], observer.identity)
            for original, held_pin in ((exe, pin), (provider, provider_pin)):
                held_pin.verify()
                if (fd_identity(original['fd']) != original['identity']
                        or fd_identity(held_pin.fd) != original['identity']
                        or held_pin.digest != original['sha256']):
                    raise ValueError('original C8 held file changed')
            if require_image:
                pin.image_receipt({'image': gen}, owner)
                with (Path('/proc') / str(pid) / 'maps').open() as mapped:
                    text = mapped.read(LIMIT + 1)
                if len(text) > LIMIT: raise ValueError('owned C8 maps exceed original byte bound')
                mappings = [maps_line.fullmatch(line) for line in text.splitlines()]
                if any(row is None for row in mappings): raise ValueError('malformed owned C8 maps')
                if not any(row[3][2] == 'x' and int(row[7]) == provider['provider']['ino']
                        and [int(row[5], 16), int(row[6], 16)] == provider['provider']['dev']
                        for row in mappings):
                    raise ValueError('owned C8 actor has no held provider code mapping')
            check_deadline(deadline)
        previous = (json.loads(Path(str(prefix) + f'.{gen-1}.post.json').read_text())
                    if gen else None)
        pre = (json.loads(Path(str(prefix) + f'.{gen}.pre.json').read_text())
               if operation == 'post' else None)
        if previous and (previous['pid'] != pid or previous['gen'] != gen - 1):
            raise ValueError('C8 prior completed generation differs')
        stream = state['stream']
        saved = pre or previous or {}
        last_size = observed_bytes = saved.get('stream_bytes', 0)
        observed_digest = saved.get('stream_sha256', hashlib.sha256(b'').hexdigest())
        while True:
            verify()
            size = fd_identity(stream['fd'])[2]
            info = Path(stream['path']).stat()
            if ([info.st_dev, info.st_ino] != stream['identity']
                    or fd_identity(stream['fd'])[:2] != stream['identity'] or size < last_size):
                raise ValueError('original C8 stream was replaced or truncated')
            last_size = size
            if size > LIMIT: raise ValueError('C8 stream exceeds original byte bound')
            payload = os.pread(stream['fd'], size, 0)
            if len(payload) != size or hashlib.sha256(payload[:observed_bytes]).hexdigest() != observed_digest:
                raise ValueError('C8 stream rewrote saved publication history')
            observed_bytes, observed_digest = size, hashlib.sha256(payload).hexdigest()
            records = records_from(payload)
            if records and any(row.get('kind') == 'ended' for row in records):
                raise ValueError('C8 observer stream ended before gate')
            data = ledger_path.read_bytes()
            if len(data) > LIMIT: raise ValueError('native C8 ledger exceeds bound')
            native = []
            if data.endswith(b'\n'):
                for line in data.decode().splitlines():
                    parts = line.split()
                    row = dict(part.split('=', 1) for part in parts[1:])
                    if row.get('cell') == cell and row.get('gen') == str(gen):
                        if (row.get('pid') != str(pid) or row.get('start') != str(owner.identity['start_time'])
                                or row.get('exe') != exe['path']):
                            raise ValueError('native C8 image differs from original held birth/file')
                        native.append((parts[0], row))
            ready = [r for k, r in native if k == 'WATCH_READY' and r.get('phase') == ('go' if operation == 'pre' else 'next')]
            mapped = [r for k, r in native if k == 'MAPPED' and r.get('module') == provider['path']
                      and r.get('ino') == str(provider['identity'][1])]
            identified = [r for k, r in native if k == 'IDENT']
            calls = [r for k, r in native if k == 'LEDGER']
            want = {'pid': pid, 'start': owner.identity['start_time'], 'gen': gen, 'exe': exe['exe'],
                    'provider': provider['provider'], 'origin': state['origin'], 'deadline': deadline,
                    'previous': previous, 'pre': pre}
            if previous and previous['start'] != want['start']: raise ValueError('C8 birth changed across exec')
            if ready and int(ready[0]['deadline']) != deadline: raise ValueError('native C8 deadline renewed')
            if ready and (len(ready) != 1 or len(mapped) != 1 or len(identified) != 1):
                raise ValueError('native C8 current image/provider readiness differs')
            if ready and previous and int(ready[0]['t']) <= previous['done_ns']:
                raise ValueError('native C8 successor predates the completed generation')
            if ready: verify(require_image=True)
            complete = operation == 'pre'
            if operation == 'pre' and calls: raise ValueError('C8 calls preceded their native gate')
            if operation == 'post':
                done = [r for k, r in native if k == 'DONE' and r.get('status') == 'ok']
                expected = 18 + gen * 10
                if done and calls:
                    if (len(calls) != expected or any(r['n'] != '1' or r['bad'] != '0'
                            or r['t0'] != r['t1'] or r['module'] != provider['path'] for r in calls)):
                        raise ValueError('C8 original singleton call plan differs')
                    want.update(count=expected, done_ns=int(done[0]['t']),
                                first_entry_ns=min(int(r['t0']) for r in calls),
                                last_entry_ns=max(int(r['t1']) for r in calls))
                    complete = True
            phase = 'native' if operation == 'pre' and gen == 1 else operation
            proof = select_gate(records, want, phase) if records and ready and complete else None
            verify()
            if proof:
                if fd_identity(stream['fd'])[2] != size:
                    continue  # An append may invalidate the previously read state.
                proof.update(stream_bytes=len(payload), stream_sha256=hashlib.sha256(payload).hexdigest())
                receipt = Path(str(prefix) + f'.{gen}.{operation}.json')
                gate = Path(str(prefix) + f'.{gen}.' + ('go' if operation == 'pre' else 'next'))
                if gate.exists(): raise ValueError('C8 gate already exists')
                write_new(receipt, proof)
                verify(require_image=True)
                gate.touch(exist_ok=False)
                print(json.dumps(proof))
                return
            time.sleep(.02)
    finally:
        for owned in (observer, owner, provider_pin, pin):
            if owned is not None: owned.close()


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f'C8 readiness refused: {error}')
C8_GATE_PY
}

mono_ns() { python3 -I -c 'import time; print(time.monotonic_ns())'; }
count_kind() { python3 -I "$ORACLE" count-kind "$1" "$2"; }

# Positive controls: signal tests are meaningless where SIGHUP is ignored (nohup,
# some CI wrappers), and a background SIGINT must actually be deliverable once
# its inherited ignore is reset. Never run this script under nohup.
positive_controls() {
    local status
    { sh -c 'kill -HUP $$' >/dev/null 2>&1; } 2>/dev/null
    status=$?
    [ "$status" -eq 129 ] || die "positive control failed: sh -c 'kill -HUP \$\$' exited $status, want 129 (SIGHUP ignored here?)"
    env --default-signal=INT true 2>/dev/null || die "env --default-signal is unsupported (coreutils >= 8.31 needed)"
    env --default-signal=INT sh -c 'kill -INT $$' >/dev/null 2>&1 &
    wait "$!"
    status=$?
    [ "$status" -eq 130 ] || die "positive control failed: background SIGINT exited $status, want 130"
}

need_tools() {
    for tool in gcc softhsm2-util python3 timeout "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
    done
    [ -r "$MODULE" ] || die "SoftHSM2 provider not found: $MODULE (set MODULE=)"
}

# build_fixtures DIR: workload, a byte copy at a distinct inode (the exec chain's
# "other binary"), the held provider, and provider copies B and C (byte-identical
# to A, distinct inodes).
build_fixtures() {
    local dir=$1
    gcc -O1 -Wall -Wextra -Werror -o "$dir/ledger" "$SRC" -ldl -lpthread || die "fixture build failed"
    cp "$dir/ledger" "$dir/ledger2" || die "copy ledger2"
    gcc -O1 -Wall -Wextra -Werror -shared -fPIC -DINVENTORY_LEDGER_HELD_PROVIDER -o "$dir/held.so" "$SRC" \
        || die "held provider build failed"
    mkdir -p "$dir/copyB" "$dir/copyC" || die "mkdir provider copies"
    { cp "$MODULE" "$dir/copyB/libsofthsm2.so" && cp "$MODULE" "$dir/copyC/libsofthsm2.so"; } || die "copy providers"
    chmod 755 "$dir/ledger" "$dir/ledger2" "$dir/held.so" "$dir/copyB" "$dir/copyC"
}

write_conf() { # DIR: a SoftHSM2 config whose token store is DIR/tokens
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$1" > "$1/softhsm2.conf"
}

waitfor() { # FILE PATTERN TIMEOUT_S
    local _
    for _ in $(seq $(($3 * 10))); do
        grep -qa -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

wait_kind() { # JSONL KIND N TIMEOUT_S: the stream holds at least N events of KIND
    local _
    for _ in $(seq $(($4 * 4))); do
        [ "$(count_kind "$1" "$2")" -ge "$3" ] && return 0
        sleep 0.25
    done
    return 1
}

# bounded_wait PID TIMEOUT_S: reap PID, SIGKILLing it at the deadline; BW_RC = status.
bounded_wait() {
    local _
    for _ in $(seq $(($2 * 10))); do
        kill -0 "$1" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$1" 2>/dev/null; then
        echo "pid $1 outlived ${2}s; SIGKILL" >&2
        kill -KILL "$1" 2>/dev/null
    fi
    wait "$1"
    BW_RC=$?
}

release_held() { # FIFO: let a held call return; never blocks (no reader = nothing held)
    [ -p "$1" ] || return 0
    python3 -I -c 'import errno,os,sys
try:
    os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK))
except OSError as e:
    if e.errno != errno.ENXIO:
        raise' "$1"
}

# cell NAME ROLE MODE PROVIDERS(comma) ITERS HOLD [EXTRA_JSON]: one run.json cell entry.
cell() {
    python3 -I -c 'import json,sys
n,role,mode,prov,iters,hold,extra=sys.argv[1:8]
spec={"role":role,"mode":mode,"providers":prov.split(","),"iters":int(iters),"hold":hold=="1","ledger":"ledgers/%s.out"%n}
spec.update(json.loads(extra or "{}"))
print(json.dumps({n:spec}))' "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}" >> "$CELLS"
}

# write_manifest OUTDIR LANE ATTESTED NOTE CELLS RUNS SKIPPED A B C HELD: run.json.
write_manifest() {
    python3 -I -c 'import hashlib,json,os,sys
out,lane,attested,note,cells,runs,skipped,a,b,c,held=sys.argv[1:12]
def prov(path,att,private):
    real=os.path.realpath(path)
    with open(real,"rb") as f:
        digest=hashlib.sha256(f.read()).hexdigest()
    return {"path":real,"ino":os.stat(real).st_ino,"sha256":digest,"attested":att,"private":private}
m={"manifest":"p11scope-c8-run/2","expect_lane":lane,"attested_delivery":attested=="1","attested_note":note,
   "providers":{"A":prov(a,True,False),"B":prov(b,False,True),"C":prov(c,False,True),"BLK":prov(held,False,True)},
   "cells":{},"runs":[],"skipped_runs":[s for s in skipped.split(",") if s]}
for line in open(cells):
    m["cells"].update(json.loads(line))
if os.path.exists(runs):
    m["runs"]=[json.loads(line) for line in open(runs)]
with open(os.path.join(out,"run.json"),"w") as f:
    json.dump(m,f,indent=1,sort_keys=True)' "$@"
}

# run_entry NAME CELLS JSON JSONL FRAMES RC STOP_JSON [SETTLE_PASSES]: one observer run record.
run_entry() {
    python3 -I -c 'import json,sys
n,cells,j,jl,fr,rc,stop,settle=sys.argv[1:9]
print(json.dumps({"name":n,"cells":cells.split(","),"json":j or None,"jsonl":jl or None,"frames":fr or None,
                  "rc":int(rc),"stop":json.loads(stop) if stop else None,
                  "settle_passes":int(settle) if settle else None}))' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${8:-}" >> "$RUNS"
}

self_test() {
    need_tools
    timeout 300 python3 -I "$ORACLE" --self-test || die "oracle self-test failed"
    timeout 60 python3 -I "$REPO/tests/python/test_inventory_capacity_oracle.py" \
        CapacityFixtureTests C8GatePredicateTests C8GateFixtureTests || die "native fixture self-test failed"
    SELFTEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/c8-selftest.XXXXXX") || die "mktemp"
    SELFTEST_HELD=""
    trap 'release_held "$SELFTEST_TMP/release"; [ -z "$SELFTEST_HELD" ] || kill -KILL "$SELFTEST_HELD" 2>/dev/null; rm -rf "$SELFTEST_TMP"' EXIT
    local tmp
    tmp=$(realpath -e "$SELFTEST_TMP") || die "realpath"
    chmod 700 "$tmp"
    build_fixtures "$tmp"
    mkdir -m 700 "$tmp/tokens" || die "token dir"
    write_conf "$tmp"
    export SOFTHSM2_CONF=$tmp/softhsm2.conf
    softhsm2-util --init-token --free --label c8 --so-pin 5678 --pin 1234 >/dev/null || die "token init failed"
    mkdir -p "$tmp/ledgers"
    CELLS=$tmp/cells.jsonl RUNS=$tmp/runs.jsonl
    : > "$CELLS"
    local A=$MODULE B=$tmp/copyB/libsofthsm2.so C=$tmp/copyC/libsofthsm2.so L=$tmp/ledger
    local T=(timeout --kill-after=5 60)
    "${T[@]}" "$L" mech --cell P1 --module "$A" --iters 3 > "$tmp/ledgers/P1.out" || die "P1 failed"
    cell P1 P1 mech A 3 0
    "${T[@]}" "$L" mech --cell P2 --module "$B" --iters 2 > "$tmp/ledgers/P2.out" || die "P2 failed"
    cell P2 P2 mech B 2 0
    "${T[@]}" "$L" mech --cell PB --module "$A" --module "$B" --iters 1 > "$tmp/ledgers/PB.out" || die "PB failed"
    cell PB P2 mech A,B 1 0
    "${T[@]}" "$L" map --cell P3 --module "$A" --module "$C" > "$tmp/ledgers/P3.out" || die "P3 failed"
    cell P3 P3 map A,C 0 0
    for _ in 1 2; do
        "${T[@]}" "$L" mech --cell P4 --module "$A" --iters 2 --sleep-us 1000 >> "$tmp/ledgers/P4.out" || die "P4 failed"
    done
    cell P4 P4 mech A 2 0 '{"instances": 2}'
    "${T[@]}" "$L" exec-chain --cell P5 --module "$A" --iters 1 --delay-ms 120 \
        --chain "leader:$L,leader:$tmp/ledger2,thread:$L" > "$tmp/ledgers/P5.out" || die "P5 failed"
    cell P5 P5 exec-chain A 1 0 "{\"exe\": \"$L\", \"chain\": [\"leader:$L\", \"leader:$tmp/ledger2\", \"thread:$L\"]}"
    mkfifo "$tmp/release" || die "mkfifo"
    INVENTORY_LEDGER_RELEASE=$tmp/release "${T[@]}" "$L" held --cell P6 --module "$tmp/held.so" \
        > "$tmp/ledgers/P6.out" &
    SELFTEST_HELD=$!
    waitfor "$tmp/ledgers/P6.out" '^HELD ' 10 || die "P6 never entered its held call"
    sleep 0.3
    kill -TERM "$SELFTEST_HELD"  # a signal must not end the held call ...
    sleep 0.3
    kill -0 "$SELFTEST_HELD" 2>/dev/null || die "P6 held call ended on SIGTERM; it must hold until released"
    release_held "$tmp/release"  # ... only the release does
    bounded_wait "$SELFTEST_HELD" 10
    SELFTEST_HELD=""
    grep -q '^RETURNED ' "$tmp/ledgers/P6.out" || die "P6 did not return after release (rc=$BW_RC)"
    cell P6 P6 held BLK 0 0
    "${T[@]}" "$L" mech --late --cell P7 --module "$A" --iters 2 --delay-ms 50 > "$tmp/ledgers/P7.out" || die "P7 failed"
    cell P7 P7 mech A 2 0
    "${T[@]}" "$L" leader-exit --cell LX --module "$A" --iters 2 > "$tmp/ledgers/LX.out" || die "LX failed"
    cell LX LX leader-exit A 2 0
    write_manifest "$tmp" scan 0 "self-test: no observer" "$CELLS" "$RUNS" "" "$A" "$B" "$C" "$tmp/held.so"
    timeout 60 python3 -I "$ORACLE" ledgers "$tmp" || die "ledger self-consistency failed"
    echo "qualify-inventory-native: self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then
    positive_controls
    self_test
    exit 0
fi

# ---------------------------------------------------------------------------
# Privileged qualification
# ---------------------------------------------------------------------------
[ $# -ge 1 ] || { sed -n '3,11p' "$0" >&2; exit 64; }
P=$(realpath -e "$1") || { echo "binary not found: $1" >&2; exit 64; }
shift
LANE=native BASE=/var/tmp/p11scope-ws-tmp/c8-root DASHBOARD=1
CAPACITY= ENDPOINT_LIMIT=4096 ENDPOINT_SELECTED=0 CAPACITY_DEMAND=8192
while [ $# -gt 0 ]; do
    case $1 in
        --lane) LANE=$2; shift 2 ;;
        --base) BASE=$2; shift 2 ;;
        --no-dashboard) DASHBOARD=0; shift ;;
        --capacity|--max-endpoints|--demand)
            [ $# -ge 2 ] || { echo "missing value for $1" >&2; exit 64; }
            case $1 in
                --capacity) CAPACITY=$2 ;;
                --max-endpoints) ENDPOINT_LIMIT=$2; ENDPOINT_SELECTED=1 ;;
                --demand) CAPACITY_DEMAND=$2 ;;
            esac
            shift 2 ;;
        *) echo "unknown argument $1" >&2; exit 64 ;;
    esac
done
case $LANE in scan|native) ;; *) echo "--lane must be scan or native" >&2; exit 64 ;; esac
case $ENDPOINT_LIMIT in ''|*[!0-9]*|??????????*) echo "--max-endpoints must be in1..8192" >&2; exit 64 ;; esac
[ "$ENDPOINT_LIMIT" -ge 1 ] && [ "$ENDPOINT_LIMIT" -le 8192 ] || { echo "--max-endpoints must be in1..8192" >&2; exit 64; }
case $CAPACITY in ''|boundary|growth|owners|real|refusal) ;; *) echo "unknown capacity population $CAPACITY" >&2; exit 64 ;; esac
case $CAPACITY_DEMAND in 4097|6531|8192) ;; *) echo "--demand must be4097,6531,8192" >&2; exit 64 ;; esac
if [ -n "$CAPACITY" ] && [ "$ENDPOINT_SELECTED" = 0 ]; then
    echo "--capacity requires --max-endpoints" >&2; exit 64
fi
if [ "$CAPACITY" = refusal ] && [ "$CAPACITY_DEMAND" != $((ENDPOINT_LIMIT + 1)) ]; then
    echo "--capacity refusal needs --demand exactly one above --max-endpoints" >&2; exit 64
fi
ENDPOINT_ARGS=()
if [ "$ENDPOINT_SELECTED" = 1 ]; then ENDPOINT_ARGS=(--max-endpoints "$ENDPOINT_LIMIT"); fi
RUNUID=${RUNUID:-1000} RUNGID=${RUNGID:-1000}
DURATION=${DURATION:-90} LATE_MS=${LATE_MS:-2500} STOP_WAIT_S=${STOP_WAIT_S:-60}
read -r -a SYSTEM_EXTRA <<< "${SYSTEM_ARGS:-}"
positive_controls
[ "$(id -u)" = 0 ] || die "must run as root (the observer needs it; workloads drop to RUNUID)"
[ "$RUNUID" != 0 ] || die "RUNUID must not be root"
if [ -n "$CAPACITY" ]; then
    for tool in gcc python3 timeout setpriv stat install; do command -v "$tool" >/dev/null 2>&1 || die "missing tool:$tool"; done
    if [ "$CAPACITY" = real ]; then command -v softhsm2-util >/dev/null 2>&1 || die "missing softhsm2-util"; fi
else
    need_tools setpriv stat install
fi
umask 077
if [ ! -e "$BASE" ]; then
    { mkdir -p "$(dirname "$BASE")" && mkdir -m 0711 "$BASE"; } || die "cannot create $BASE"
fi
BASE=$(realpath -e "$BASE") || die "realpath $BASE"
read -r base_uid base_mode <<< "$(stat -c '%u %a' "$BASE")"
[ "$base_uid" = 0 ] || die "--base $BASE must be root-owned (owner uid $base_uid); create one with: install -d -o root -g root -m 0711 DIR"
[ $((8#$base_mode & 8#022)) -eq 0 ] || die "BASE $BASE is group/other-writable (mode $base_mode)"
dir=$(dirname "$BASE")
while [ "$dir" != / ]; do
    read -r d_uid d_mode <<< "$(stat -c '%u %a' "$dir")"
    if [ "$d_uid" != 0 ] || { [ $((8#$d_mode & 8#022)) -ne 0 ] && [ $((8#$d_mode & 8#1000)) -eq 0 ]; }; then
        echo "WARNING: ancestor $dir (uid $d_uid mode $d_mode) is writable by a non-root user" >&2
    fi
    dir=$(dirname "$dir")
done
if [ -n "$CAPACITY" ]; then
    python3 -I "$ORACLE" capacity-run "$P" "$BASE" "$LANE" "$CAPACITY" "$ENDPOINT_LIMIT" "$CAPACITY_DEMAND" "$RUNUID" "$RUNGID"
    exit "$?"
fi
OBS=$(mktemp -d "$BASE/c8-obs.XXXXXX") || die "mktemp obs"
WL=$(mktemp -d "$BASE/c8-wl.XXXXXX") || die "mktemp workload"
{ chmod 0711 "$WL" && install -d -m 0755 "$WL/bin" && install -d -m 0711 "$WL/gates" "$WL/cells" "$OBS/ledgers"; } \
    || die "workload layout"
(umask 022; build_fixtures "$WL/bin") || die "fixture build"
L=$WL/bin/ledger A=$MODULE B=$WL/bin/copyB/libsofthsm2.so C=$WL/bin/copyC/libsofthsm2.so BLK=$WL/bin/held.so
RELEASE=$WL/gates/release GATE=$WL/gates/gate GATE6=$WL/gates/gate6
mkfifo -m 0644 "$RELEASE" || die "mkfifo"

# as_cell CELL: AS = the argv prefix running a command as RUNUID for CELL. Never
# background a shell function: `f &` forks a subshell, so $! names that subshell
# and a signal sent to it never reaches the real process.
as_cell() {
    AS=(setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups --no-new-privs
        env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C
        SOFTHSM2_CONF="$WL/cells/$1/softhsm2.conf" INVENTORY_LEDGER_RELEASE="$RELEASE")
}
# setup_cell CELL: the cell's own RUNUID-owned 0700 dir and SoftHSM2 token.
setup_cell() {
    install -d -o "$RUNUID" -g "$RUNGID" -m 0700 "$WL/cells/$1" || die "cell dir $1"
    { write_conf "$WL/cells/$1" && chmod 0644 "$WL/cells/$1/softhsm2.conf"; } || die "conf $1"
    as_cell "$1"
    # shellcheck disable=SC2016  # $1 expands in the RUNUID shell, by design
    "${AS[@]}" sh -c 'mkdir -m 700 "$1" && softhsm2-util --init-token --free --label c8 --so-pin 5678 --pin 1234 >/dev/null' \
        _ "$WL/cells/$1/tokens" || die "token init for $1 as RUNUID $RUNUID failed (is $BASE traversable?)"
}
for c in P1 P2 P3 P4 P5 P6 P7 LX discover; do setup_cell "$c"; done
CELLS=$OBS/cells.jsonl RUNS=$OBS/runs.jsonl
: > "$CELLS"; : > "$RUNS"
echo "observer=$OBS workload=$WL lane=$LANE binary=$P"

WORKLOADS=() OBSERVERS=()
# Every exit path (including die) releases the held call and reaps what this
# run started: TERM, a grace period, then KILL. No cell may outlive the run.
cleanup() {
    local pid _
    release_held "$RELEASE"
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    for _ in $(seq 30); do  # 3 s grace, then KILL
        local alive=0
        for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && break
        sleep 0.1
    done
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do kill -KILL "$pid" 2>/dev/null; done
    for pid in "${OBSERVERS[@]}" "${WORKLOADS[@]}"; do wait "$pid" 2>/dev/null; done
    OBSERVERS=() WORKLOADS=()
    # Close only this invocation's parent-held pins, once all children stopped.
    if [[ -v C8_STREAM_FD ]]; then exec {C8_STREAM_FD}<&-; unset C8_STREAM_FD; fi
    if [[ -v C8_LFD ]]; then exec {C8_LFD}<&-; unset C8_LFD; fi
    if [[ -v C8_L2FD ]]; then exec {C8_L2FD}<&-; unset C8_L2FD; fi
    if [[ -v C8_AFD ]]; then exec {C8_AFD}<&-; unset C8_AFD; fi
    if [[ -v C8_BFD ]]; then exec {C8_BFD}<&-; unset C8_BFD; fi
}
trap cleanup EXIT
launch() { # CELL ARGS...: a workload as RUNUID; stdout = its ledger; $! is the workload itself
    local name=$1; shift
    as_cell "$name"
    "${AS[@]}" "$L" "$@" >> "$OBS/ledgers/$name.out" 2>> "$OBS/ledgers/$name.err" &
    WORKLOADS+=("$!")
}
# Background jobs of a non-interactive shell inherit SIGINT/SIGQUIT as ignored;
# reset them so a SIGINT reaches the observer exactly as it would from a terminal.
OBSERVER=(env --default-signal=INT --default-signal=QUIT "$P")
EVENTS=(--event-rotate-bytes "$ROTATE_BYTES")

# Lane probe: what the binary under test can be asked for.
timeout 30 "$P" --help > "$OBS/help.txt" 2>&1 || echo "WARNING: $P --help exited nonzero" >&2
probe_capture=0 probe_manifest=0
while IFS='=' read -r key value; do
    case $key in capture) probe_capture=$value ;; manifest) probe_manifest=$value ;; esac
done < <(python3 -I "$ORACLE" probe-help < "$OBS/help.txt")
CAPTURE_ARGS=() MANIFEST_ARGS=() ATTESTED=0 NOTE="inventory has no --manifest flag (Task 6 C6)"
[ "$probe_capture" = 1 ] && CAPTURE_ARGS=(--capture "$LANE")
if [ "$probe_manifest" = 1 ]; then
    DISCOVER=${P11SCOPE_DISCOVER:-$(dirname "$P")/p11scope-discover}
    as_cell discover
    if [ -x "$DISCOVER" ] && timeout --kill-after=5 120 "${AS[@]}" "$DISCOVER" --module "$A" \
            -o "$WL/cells/discover/manifest-A.json" > "$OBS/discover.log" 2>&1; then
        cp "$WL/cells/discover/manifest-A.json" "$OBS/manifest-A.json" \
            && MANIFEST_ARGS=(--manifest "$OBS/manifest-A.json") && ATTESTED=1
    else
        NOTE="p11scope-discover unavailable or failed ($DISCOVER); see discover.log"
    fi
fi
echo "probe: capture_args=${CAPTURE_ARGS[*]:-none} manifest=${MANIFEST_ARGS[*]:-none}"

C8_P2=() C8_P5=()
if [ "$LANE" = native ]; then
    exec {C8_LFD}<"$L"
    exec {C8_L2FD}<"$WL/bin/ledger2"
    exec {C8_AFD}<"$A"
    exec {C8_BFD}<"$B"
    C8_PINS=$OBS/c8-pins.json
    c8_gate prepare "$C8_PINS" "$C8_LFD" "$C8_L2FD" "$C8_AFD" "$C8_BFD" \
        > "$OBS/c8-prepare.log" || die "C8 held-file calibration failed"
fi

# ---- run "system" ----
"${OBSERVER[@]}" inventory --system --duration "$DURATION" -o "$OBS/system.json" --event-log "$OBS/system.jsonl" \
    "${EVENTS[@]}" "${SYSTEM_EXTRA[@]}" "${CAPTURE_ARGS[@]}" "${MANIFEST_ARGS[@]}" "${ENDPOINT_ARGS[@]}" \
    > "$OBS/system.stdout" 2> "$OBS/system.stderr" &
SYS=$!
OBSERVERS+=("$SYS")
wait_kind "$OBS/system.jsonl" pass 1 120 || die "system observer never committed a pass (see $OBS/system.stderr)"
if [ "$LANE" = native ]; then
    exec {C8_STREAM_FD}<"$OBS/system.jsonl"
    C8_DEADLINE=$(c8_gate start "$C8_PINS" "$OBS/system.jsonl" "$C8_STREAM_FD" "$DURATION" "$SYS" "$$") \
        || die "C8 original work deadline unavailable"
    C8_P2=(--ledger-singletons --c8-gate-prefix "$WL/gates/P2" --c8-gated-images 1 --c8-deadline "$C8_DEADLINE")
    C8_P5=(--ledger-singletons --c8-gate-prefix "$WL/gates/P5" --c8-gated-images 3 --c8-deadline "$C8_DEADLINE")
fi
launch P1 mech --cell P1 --module "$A" --iters "$ITERS" --gate "$GATE" --hold
launch P2 mech --cell P2 --module "$B" --iters "$ITERS" --gate "$GATE" --hold "${C8_P2[@]}"
C8_P2_PID=${WORKLOADS[-1]}
launch P3 map --cell P3 --module "$A" --module "$C" --gate "$GATE" --hold
launch P7 mech --late --cell P7 --module "$A" --iters "$ITERS" --gate "$GATE" --delay-ms "$LATE_MS" --hold
launch LX leader-exit --cell LX --module "$A" --iters "$ITERS" --gate "$GATE"
launch P5 exec-chain --cell P5 --module "$A" --iters 1 --gate "$GATE" --delay-ms 300 \
    --chain "leader:$L,leader:$WL/bin/ledger2,thread:$L" "${C8_P5[@]}"
C8_P5_PID=${WORKLOADS[-1]}
if [ "$LANE" = native ]; then
    c8_gate pre "$C8_PINS" P2 "$C8_P2_PID" 0 L B "$OBS/ledgers/P2.out" "$WL/gates/P2" "$$" "$RUNUID" \
        > "$OBS/c8-P2-pre.log" || die "P2 current provider watch unproved"
    c8_gate pre "$C8_PINS" P5 "$C8_P5_PID" 0 L A "$OBS/ledgers/P5.out" "$WL/gates/P5" "$$" "$RUNUID" \
        > "$OBS/c8-P5-0-pre.log" || die "P5 initial provider watch unproved"
fi
for c in P1 P2 P3 P7 LX P5; do waitfor "$OBS/ledgers/$c.out" '^READY ' 30 || die "$c never became ready"; done
# Two more passes: the native lane admits and attaches the new mappings first.
base=$(count_kind "$OBS/system.jsonl" pass); wait_kind "$OBS/system.jsonl" pass $((base + 2)) 60 || die "observer stalled"
touch "$GATE"
as_cell P4
for i in 1 2 3; do  # P4: ~100 ms CLIs, ungated, while capture runs
    timeout --kill-after=5 60 "${AS[@]}" "$L" mech --cell P4 --module "$A" --iters 2 --sleep-us 10000 \
        >> "$OBS/ledgers/P4.out" 2>> "$OBS/ledgers/P4.err" || echo "P4 instance $i failed" >&2
    sleep 1
done
if [ "$LANE" = native ]; then
    for c8_gen in 0 1 2; do  # The final thread-reached image remains optional.
        c8_exe=L
        [ "$c8_gen" = 2 ] && c8_exe=L2
        if [ "$c8_gen" != 0 ]; then
            c8_gate pre "$C8_PINS" P5 "$C8_P5_PID" "$c8_gen" "$c8_exe" A \
                "$OBS/ledgers/P5.out" "$WL/gates/P5" "$$" "$RUNUID" \
                > "$OBS/c8-P5-$c8_gen-pre.log" || die "P5 image$c8_gen native image/provider readiness unproved"
        fi
        c8_gate post "$C8_PINS" P5 "$C8_P5_PID" "$c8_gen" "$c8_exe" A \
            "$OBS/ledgers/P5.out" "$WL/gates/P5" "$$" "$RUNUID" \
            > "$OBS/c8-P5-$c8_gen-post.log" || die "P5 image$c8_gen count/publication progress unproved"
    done
fi
for c in P1 P2 P3 P7 LX P5; do waitfor "$OBS/ledgers/$c.out" '^DONE .*gen=0' 60 || echo "$c: no DONE" >&2; done
waitfor "$OBS/ledgers/P5.out" '^DONE .*gen=3' 60 || echo "P5: chain incomplete" >&2
# Exits and the late dlopen must be seen by a pass that STARTED after them:
# the oracle requires two commits after this point (WINDOW-SETTLED).
settled_at=$(count_kind "$OBS/system.jsonl" pass)
bounded_wait "$SYS" $((DURATION + 120)); SYS_RC=$BW_RC; OBSERVERS=()
SETTLE=$(( $(count_kind "$OBS/system.jsonl" pass) - settled_at ))
run_entry system P1,P2,P3,P4,P5,P7,LX system.json system.jsonl "" "$SYS_RC" "" "$SETTLE"
cell P1 P1 mech A "$ITERS" 1
cell P2 P2 mech B "$ITERS" 1
cell P3 P3 map A,C 0 1
cell P4 P4 mech A 2 0 '{"instances": 3}'
cell P5 P5 exec-chain A 1 0 "{\"exe\": \"$L\", \"chain\": [\"leader:$L\", \"leader:$WL/bin/ledger2\", \"thread:$L\"]}"
cell P7 P7 mech A "$ITERS" 1
cell LX LX leader-exit A "$ITERS" 0

# ---- run "dashboard" (held cells P1 P2 P3 P7 are alive and idle) ----
SKIPPED=""
if [ "$DASHBOARD" = 1 ]; then
    # --module narrows discovery to the cell providers, so every cell edge fits the
    # frame; the run is still --system scope.
    python3 -I "$ORACLE" record-pty "$OBS/dashboard.pty" 120 250 90 0 -- "$P" inventory --system --dashboard \
        --module "$A" --module "$B" --module "$C" "${SYSTEM_EXTRA[@]}" --duration 15 -o "$OBS/dashboard.json" \
        --event-log "$OBS/dashboard.jsonl" "${EVENTS[@]}" "${CAPTURE_ARGS[@]}" "${MANIFEST_ARGS[@]}" "${ENDPOINT_ARGS[@]}" \
        > "$OBS/dashboard.rc" 2>&1
    DASH_RC=$(sed -n 's/^rc=//p' "$OBS/dashboard.rc")
    run_entry dashboard P1,P2,P3,P7 dashboard.json dashboard.jsonl dashboard.pty "${DASH_RC:-255}" ""
else
    SKIPPED=dashboard
fi

# ---- run "stop": a call held until released, SIGINT mid-capture ----
launch P6 held --cell P6 --module "$BLK" --gate "$GATE6"
P6=${WORKLOADS[-1]}
waitfor "$OBS/ledgers/P6.out" '^READY ' 30 || die "P6 never became ready"
P6PID=$(sed -n 's/^READY .* pid=\([0-9]*\) .*/\1/p' "$OBS/ledgers/P6.out" | head -1)
"${OBSERVER[@]}" inventory --pid "$P6PID" --duration 600 -o "$OBS/stop.json" --event-log "$OBS/stop.jsonl" \
    "${EVENTS[@]}" "${CAPTURE_ARGS[@]}" "${ENDPOINT_ARGS[@]}" > "$OBS/stop.stdout" 2> "$OBS/stop.stderr" &
STOP=$!
OBSERVERS+=("$STOP")
wait_kind "$OBS/stop.jsonl" pass 2 120 || echo "stop observer slow to start" >&2
touch "$GATE6"
waitfor "$OBS/ledgers/P6.out" '^HELD ' 30 || echo "P6 never entered its held call" >&2
base=$(count_kind "$OBS/stop.jsonl" pass); wait_kind "$OBS/stop.jsonl" pass $((base + 2)) 60 || true
SENT=$(mono_ns)
kill -INT "$STOP"
bounded_wait "$STOP" "$STOP_WAIT_S"; STOP_RC=$BW_RC; OBSERVERS=()
EXITED=$(mono_ns)
release_held "$RELEASE"  # only now may the held call return (RETURNED t > SENT)
waitfor "$OBS/ledgers/P6.out" '^RETURNED ' 10 || echo "P6 did not return after release" >&2
bounded_wait "$P6" 10
STOP_JSON=""
[ -s "$OBS/stop.json" ] && STOP_JSON=stop.json
run_entry stop P6 "$STOP_JSON" stop.jsonl "" "$STOP_RC" \
    "{\"signal\": \"INT\", \"sent_ns\": $SENT, \"exited_ns\": $EXITED}"
cell P6 P6 held BLK 0 1

# ---- judge ----
cleanup
write_manifest "$OBS" "$LANE" "$ATTESTED" "$NOTE" "$CELLS" "$RUNS" "$SKIPPED" "$A" "$B" "$C" "$BLK"
timeout 300 python3 -I "$ORACLE" check "$OBS" | tee "$OBS/oracle.txt"
rc=${PIPESTATUS[0]}
echo "evidence: $OBS (workload state: $WL)"
exit "$rc"
