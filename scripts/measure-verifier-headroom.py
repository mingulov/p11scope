#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure successful verifier work through the actual native loader on Linux.

Build the bounded x86-64 probe elsewhere with `build OUTDIR`. `run` NEVER builds:
it preloads that probe into one supplied observer, checks the exact host kernel
and prebuilt input hashes, and requires successful, FD/BTF-bound verifier STATS
for every affected root with at least five percent of the actual limit unused.
Use the authorized privileged lane, and an observer invocation which exits after
loading its normal programs. Original instructions, flags and types stay with
the actual loader; no reconstructed program or xlated length supplies a count.

The candidate revision is an explicit provenance declaration, paired with the
checked executable hash. The caller still must establish that build provenance;
this script cannot derive a source revision or enabled feature set from an ELF.
Oracle/C self-tests are unprivileged and are not kernel qualification.
"""
import argparse
import copy
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _loader import load_sibling

CONTRACT = 'p11scope-verifier-headroom-v1'
MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 4096
BASE_ROOTS = frozenset(('p11_entry', 'p11_return', 'sched_process_exec', 'sched_process_exit'))
DIAGNOSTIC_ROOTS = frozenset(('p11_entry_ia32', 'p11_entry_template', 'p11_entry_template_pair',
                              'p11_entry_template_second', 'p11_entry_template_types'))
VARIANTS = ('default', 'small', 'wide', 'diagnostic')
LOAD_FIELDS = frozenset(('record', 'pid', 'root', 'btf_resolved', 'btf_fd', 'btf_id',
                         'returned_btf_id', 'root_type_id', 'returned_fd', 'program_id',
                         'program_type', 'returned_program_type', 'program_flags',
                         'expected_attach_type', 'insn_count', 'relocated_fnv1a64',
                         'loaded', 'errno', 'stats_present', 'processed', 'limit'))
HEADER_FIELDS = frozenset(('record', 'contract', 'candidate', 'kernel', 'variant',
                           'executable_sha256', 'probe_sha256'))


class MeasurementError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise MeasurementError(message)


def unsigned(value, *, minimum=0):
    return type(value) is int and minimum <= value <= 0xffffffff


def digest_text(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None and int(value, 16) != 0


def validate(rows, *, expected=None):
    """Closed oracle. `expected` binds a running acquisition to its input header."""
    require(4 <= len(rows) <= MAX_ROWS, 'missing or oversized measurement records')
    header, summary, footer = rows[0], rows[-2], rows[-1]
    require(type(header) is dict and header.keys() == HEADER_FIELDS, 'invalid measurement header')
    require(header['record'] == 'measurement' and header['contract'] == CONTRACT, 'wrong measurement contract')
    require(digest_text(header['candidate'], 40), 'candidate must be a full nonzero revision')
    require(digest_text(header['executable_sha256'], 64) and digest_text(header['probe_sha256'], 64),
            'prebuilt input hashes missing')
    require(isinstance(header['kernel'], str) and re.fullmatch('[A-Za-z0-9_.+~-]{1,128}', header['kernel']),
            'invalid exact kernel release')
    require(header['variant'] in VARIANTS, 'unknown object configuration')
    if expected is not None:
        require(header == expected, 'measurement input binding changed')
    require(type(footer) is dict and footer.keys() == {'record', 'pid', 'status'} and
            footer['record'] == 'exit' and unsigned(footer['pid'], minimum=1) and
            type(footer['status']) is int and footer['status'] == 0, 'observer did not exit successfully')
    require(type(summary) is dict and summary.keys() == {'record', 'pid', 'records', 'write_failures', 'overflow'} and
            summary['record'] == 'probe-summary' and unsigned(summary['pid'], minimum=1) and
            summary['pid'] == footer['pid'] and unsigned(summary['records']) and
            summary['records'] == len(rows) - 3 and type(summary['write_failures']) is int and
            summary['write_failures'] == 0 and summary['overflow'] is False,
            'probe summary is missing, incomplete or reports output failure')
    roots = BASE_ROOTS | (DIAGNOSTIC_ROOTS if header['variant'] == 'diagnostic' else frozenset())
    measured = {name: [] for name in roots}
    ids = set()
    for row in rows[1:-2]:
        require(type(row) is dict and row.keys() == LOAD_FIELDS and row['record'] == 'load',
                'missing, unknown or failed probe record')
        require(unsigned(row['pid'], minimum=1) and row['pid'] == footer['pid'],
                'program load came from another process')
        require(isinstance(row['root'], str) and re.fullmatch('[A-Za-z0-9_.$]{1,127}', row['root']),
                'invalid full BTF root')
        require(header['variant'] == 'diagnostic' or row['root'] not in DIAGNOSTIC_ROOTS,
                'diagnostic decoder loaded under a default configuration declaration')
        require(row['btf_resolved'] is True and row['loaded'] is True and row['stats_present'] is True,
                'load, BTF identity or successful stats absent')
        for field in ('btf_fd', 'btf_id', 'returned_btf_id', 'root_type_id', 'program_id',
                      'program_type', 'returned_program_type', 'insn_count', 'processed', 'limit'):
            require(unsigned(row[field], minimum=1), f'invalid {field} for {row["root"]}')
        for field in ('returned_fd', 'program_flags', 'expected_attach_type', 'errno'):
            require(unsigned(row[field]), f'invalid {field} for {row["root"]}')
        require(row['errno'] == 0, 'successful load carried an error')
        require(row['btf_id'] == row['returned_btf_id'], 'returned program belongs to another BTF')
        require(row['program_type'] == row['returned_program_type'], 'returned program type changed')
        require(digest_text(row['relocated_fnv1a64'], 16), 'actual relocated instruction binding absent')
        require(row['insn_count'] <= 1000000 and row['limit'] == 1000000 and
                row['processed'] <= row['limit'], 'unexpected verifier instruction bounds')
        require(row['program_id'] not in ids, 'duplicate returned kernel program id')
        ids.add(row['program_id'])
        if row['root'] in roots:
            wanted_type = 17 if row['root'].startswith('sched_') else 2  # Linux UAPI raw_tp/kprobe.
            require(row['program_type'] == wanted_type, 'affected root loaded as the wrong program type')
            require(row['processed'] * 100 <= row['limit'] * 95,
                    f'{row["root"]} has less than five percent verifier headroom')
            measured[row['root']].append(row['processed'])
    require(all(measured.values()), 'an affected full BTF root was never successfully loaded')
    return {name: max(values) for name, values in sorted(measured.items())}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate measurement JSON key')
        result[key] = value
    return result


def read_records(path):
    with open(path, 'rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES and raw.endswith(b'\n'), 'measurement is oversized or truncated')
    lines = raw.splitlines()
    require(len(lines) <= MAX_ROWS and all(lines), 'invalid measurement line count')
    try:
        return [json.loads(line, object_pairs_hook=unique_object,
                           parse_constant=lambda text: (_ for _ in ()).throw(MeasurementError('nonfinite JSON')))
                for line in lines]
    except (ValueError, UnicodeError, RecursionError) as error:
        raise MeasurementError('invalid measurement JSON') from error


def prebuilt(path, expected_hash):
    resolved = Path(path).resolve(strict=True)
    require(resolved.is_file(), 'prebuilt input is not a file')
    digest = hashlib.sha256()
    with resolved.open('rb') as stream:
        elf = stream.read(20)
        require(elf[:6] == b'\x7fELF\x02\x01' and len(elf) == 20 and elf[18:20] == b'\x3e\x00',
                'prebuilt input must be a native little-endian x86-64 ELF')
        digest.update(elf)
        while block := stream.read(1024 * 1024):
            digest.update(block)
    require(digest_text(expected_hash, 64) and digest.hexdigest() == expected_hash,
            'prebuilt input differs from its expected SHA-256')
    return resolved


def append_record(fd, record):
    data = (json.dumps(record, separators=(',', ':'), sort_keys=True) + '\n').encode('ascii')
    require(os.write(fd, data) == len(data), 'measurement record write was incomplete')


def run(args):
    require(platform.machine() == 'x86_64' and platform.release() == args.kernel,
            'measurement host does not match the exact requested x86-64 kernel')
    require(math.isfinite(args.timeout) and 0 < args.timeout <= 3600, 'timeout must be finite and at most one hour')
    require(digest_text(args.candidate, 40), 'candidate must be a full nonzero revision')
    require(not os.environ.get('LD_PRELOAD') and 'P11SCOPE_VERIFIER_STATS_FD' not in os.environ,
            'refuse an existing preload/probe environment')
    require(args.command and args.command[0] == '--' and len(args.command) >= 2,
            'supply -- followed by the actual prebuilt observer command')
    executable = prebuilt(args.command[1], args.executable_sha256)
    require(os.access(executable, os.X_OK), 'observer input is not executable')
    probe = prebuilt(args.probe, args.probe_sha256)
    require(not any(character.isspace() or character == ':' for character in str(probe)),
            'preload path contains an LD_PRELOAD separator')
    header = {'record': 'measurement', 'contract': CONTRACT, 'candidate': args.candidate,
              'kernel': args.kernel, 'variant': args.variant, 'executable_sha256': args.executable_sha256,
              'probe_sha256': args.probe_sha256}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_CLOEXEC, 0o600)
    try:
        append_record(fd, header)
        custody = load_sibling('canary_process_custody.py')
        with custody.Custody(cleanup_seconds=5) as owner:
            deadline = time.monotonic() + args.timeout
            # Custody.launch deliberately inherits the dedicated single-threaded
            # coordinator environment. Restore it immediately after child launch.
            os.environ['LD_PRELOAD'] = str(probe)
            os.environ['P11SCOPE_VERIFIER_STATS_FD'] = str(fd)
            try:
                child = owner.launch([str(executable), *args.command[2:]],
                                     deadline=deadline, pass_fds=(fd,))
            finally:
                os.environ.pop('LD_PRELOAD', None)
                os.environ.pop('P11SCOPE_VERIFIER_STATS_FD', None)
            while True:
                owner.check_cancelled()
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'observer timed out')
                try:
                    status = child.wait(time.monotonic() + min(.05, remaining))
                    break
                except (subprocess.TimeoutExpired, custody.DeadlineExpired):
                    continue
            owner.check_cancelled()
            append_record(fd, {'record': 'exit', 'pid': child.popen.pid, 'status': status})
    finally:
        os.close(fd)
    maxima = validate(read_records(args.output), expected=header)
    for name, count in maxima.items():
        print(f'{name}: processed {count}/1000000; unused {(1000000 - count) / 10000:.2f}%')


def build(args):
    destination = Path(args.output).resolve()
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = Path(__file__).with_name('native') / 'verifier-stats-probe.c'
    common = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread']
    subprocess.run([*common, '-fPIC', '-shared', '-o', str(destination / 'verifier-stats-probe.so'), str(source)], check=True)
    subprocess.run([*common, '-DPROBE_SELF_TEST', '-o', str(destination / 'verifier-stats-probe-self-test'), str(source)], check=True)
    subprocess.run([str(destination / 'verifier-stats-probe-self-test')], check=True)
    forwarding = destination / 'verifier-stats-probe-forwarding-test'
    subprocess.run([*common, '-DPROBE_SELF_TEST', '-DPROBE_FORWARD_ONLY', '-o', str(forwarding), str(source)], check=True)
    environment = {**os.environ, 'LD_PRELOAD': str(destination / 'verifier-stats-probe.so')}
    environment.pop('P11SCOPE_VERIFIER_STATS_FD', None)
    subprocess.run([str(forwarding)], env=environment, check=True)
    print(destination / 'verifier-stats-probe.so')


def self_test(probe=None):
    header = {'record': 'measurement', 'contract': CONTRACT, 'candidate': 'a' * 40,
              'kernel': '5.15.221-test', 'variant': 'default', 'executable_sha256': 'b' * 64,
              'probe_sha256': 'c' * 64}
    rows = [header]
    for index, root in enumerate(sorted(BASE_ROOTS | DIAGNOSTIC_ROOTS), 1):
        kind = 17 if root.startswith('sched_') else 2
        rows.append({'record': 'load', 'pid': 123, 'root': root, 'btf_resolved': True,
                     'btf_fd': 4, 'btf_id': 77, 'returned_btf_id': 77, 'root_type_id': index,
                     'returned_fd': 5 + index, 'program_id': 100 + index, 'program_type': kind,
                     'returned_program_type': kind, 'program_flags': 0, 'expected_attach_type': 0,
                     'insn_count': 100, 'relocated_fnv1a64': '123456789abcdef0', 'loaded': True,
                     'errno': 0, 'stats_present': True, 'processed': 950000, 'limit': 1000000})
    rows.append({'record': 'probe-summary', 'pid': 123, 'records': 9, 'write_failures': 0, 'overflow': False})
    rows.append({'record': 'exit', 'pid': 123, 'status': 0})
    default_rows = [header, *(row for row in rows[1:-2] if row['root'] in BASE_ROOTS),
                    {**rows[-2], 'records': 4}, rows[-1]]
    require(len(validate(default_rows, expected=header)) == 4, 'default roots not selected')
    rows[0]['variant'] = 'diagnostic'
    require(len(validate(rows, expected=header)) == 9, 'diagnostic roots not selected')
    refused = 0

    def rejects(change):
        nonlocal refused
        mutant = copy.deepcopy(rows)
        change(mutant)
        try:
            validate(mutant)
        except MeasurementError:
            refused += 1
            return
        raise AssertionError('oracle accepted a refusal control')

    for index in range(1, len(rows) - 2):
        rejects(lambda doc, i=index: doc.pop(i))
    for key, value in (('loaded', False), ('loaded', 1), ('stats_present', False),
                       ('btf_resolved', False), ('btf_id', 0), ('returned_btf_id', 78),
                       ('root_type_id', 0), ('returned_fd', -1), ('program_id', 0),
                       ('program_id', True), ('returned_program_type', 99),
                       ('errno', 13), ('processed', 0), ('processed', 950001),
                       ('processed', True), ('processed', 1000001), ('limit', 0),
                       ('limit', 999999), ('pid', 124), ('root', 'p11_entry_trun'),
                       ('relocated_fnv1a64', '0' * 16), ('insn_count', 0),
                       ('unexpected_private_bytes', 'forbidden')):
        rejects(lambda doc, k=key, v=value: doc[1].__setitem__(k, v))
    rejects(lambda doc: doc[-1].__setitem__('status', 1))
    rejects(lambda doc: doc[-1].__setitem__('status', False))
    rejects(lambda doc: doc[0].__setitem__('variant', 'synthetic-positive'))
    rejects(lambda doc: doc[0].__setitem__('variant', 'default'))
    rejects(lambda doc: doc[0].__setitem__('candidate', 'a' * 8))
    rejects(lambda doc: doc[0].__setitem__('executable_sha256', '0' * 64))
    rejects(lambda doc: doc.insert(-1, {'record': 'probe-error', 'reason': 'finite-refusal'}))
    rejects(lambda doc: doc[2].__setitem__('program_id', doc[1]['program_id']))
    rejects(lambda doc: doc.insert(-1, copy.deepcopy(doc[1])))
    rejects(lambda doc: doc.pop(-2))
    rejects(lambda doc: doc[-2].__setitem__('records', 8))
    rejects(lambda doc: doc[-2].__setitem__('write_failures', 1))
    rejects(lambda doc: doc[-2].__setitem__('overflow', True))
    try:
        unique_object([('record', 'load'), ('record', 'load')])
    except MeasurementError:
        refused += 1
    else:
        raise AssertionError('duplicate JSON key accepted')
    print(f'headroom oracle: default/diagnostic boundary positives, {refused} refusal controls PASS')
    if probe is not None:
        # Exercise the real prebuilt-only path and child cleanup with no BPF or
        # privileges: an empty/failed observer must never qualify, nor a timeout.
        probe = Path(probe).resolve(strict=True)
        probe_hash = hashlib.sha256(probe.read_bytes()).hexdigest()
        prefix = [sys.executable, '-I', str(Path(__file__).resolve()), 'run', '--probe', str(probe),
                  '--probe-sha256', probe_hash, '--kernel', platform.release(),
                  '--candidate', 'a' * 40, '--variant', 'default']
        with tempfile.TemporaryDirectory(prefix='headroom-check-',
                                          dir=os.environ.get('TMPDIR', '/var/tmp/p11scope-ws-tmp')) as temporary:
            for name, binary, extra, timeout, message in (
                    ('empty', '/bin/true', [], '3', 'missing or oversized'),
                    ('failed', '/bin/false', [], '3', 'missing or oversized'),
                    ('timeout', '/bin/sleep', ['60'], '.1', 'timed out')):
                output = Path(temporary) / (name + '.jsonl')
                binary_hash = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
                command = [*prefix, '--executable-sha256', binary_hash, '--output', str(output),
                           '--timeout', timeout, '--', binary, *extra]
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                require(result.returncode == 1 and message in result.stderr, f'{name} observer qualified')
                require(len(output.read_text().splitlines()) == (1 if name == 'timeout' else 3),
                        f'{name} failure did not preserve the expected incomplete measurement')
                print(f'{name} observer: refused; owned child reaped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    builder = commands.add_parser('build', help='explicit unprivileged probe build and C checks')
    builder.add_argument('output')
    builder.set_defaults(function=build)
    checker = commands.add_parser('self-test', help='unprivileged finite oracle checks')
    checker.add_argument('--probe', help='also test prebuilt-only empty/failure/timeout acquisition')
    checker.set_defaults(function=lambda args: self_test(args.probe))
    runner = commands.add_parser('run', help='prebuilt-only real loader measurement')
    for flag in ('probe', 'probe-sha256', 'executable-sha256', 'kernel', 'candidate', 'output'):
        runner.add_argument('--' + flag, required=True)
    runner.add_argument('--variant', choices=VARIANTS, required=True)
    runner.add_argument('--timeout', type=float, default=60)
    runner.add_argument('command', nargs=argparse.REMAINDER)
    runner.set_defaults(function=run)
    args = parser.parse_args()
    try:
        args.function(args)
    except (MeasurementError, OSError, subprocess.SubprocessError, RuntimeError) as error:
        print(f'verifier headroom: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
