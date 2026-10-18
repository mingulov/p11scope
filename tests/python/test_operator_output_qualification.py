# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle mutations and genuine fd controls, never installed acceptance."""
import copy
import json
import os
import subprocess
import struct
import tempfile
import sys
import time
from pathlib import Path
import runpy
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ORACLE = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/oracle.py'))
HARNESS = runpy.run_path(str(ROOT / 'scripts/qualify-operator-output.py'))
DEMOTION = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/prepare-demotion.py'))
WRAP = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/prepare-diagnostics-wrap.py'))


def fixture():
    ledger = [dict(kind='call', pid=123, tid=123, fn='C_GenerateRandom', rv=0,
                   phase='e17', image=0, scope='selected', t0=200 + i, t1=201 + i) for i in range(3)]
    receipt = dict(issued_calls=3, pid=123, ready_ns=100, workload_complete_ns=300,
                   observer_rc=0, sink='file', cancel='none', source_revision='a' * 40,
                   cleanup_seconds=0.3, terminal_observed_alive=False,
                   ring_requested='4K', ring_actual_bytes=4096,
                   signals=[], cancellation_ack_ns=None, stdout_stalled=False,
                   trace_file_error=None, watchdog=False)
    image = dict(kind='image', image=0, pid=123, start_time=9, path='/owned/caller',
                 dev=1, ino=2, mtime_ns=3, pid_namespace=4, time_namespace=5)
    provider = dict(dev=[8, 1], ino=42, sha256='b' * 64,
                    mapping=dict(dev=[8, 1], ino=42), file_identity=dict(size=4096))
    receipt.update(image=dict(image), provider_before=copy.deepcopy(provider),
                   provider_after=copy.deepcopy(provider))
    ledger = [image, dict(kind='target', image=0, fn='C_GenerateRandom',
                         dev=[8, 1], ino=42, file_offset=32),
              dict(kind='ready', image=0, t=50), *ledger,
              dict(kind='ack', image=0, phase='e17', t=250)]
    evidence = dict(event_loss=0, malformed_records=0, unmatched_returns=0,
                    scheduling=dict(sink_dropped_bytes=0, sink_timeouts=0))
    counts = dict(stats_entered=3, stats_returned=3, raw_calls=3)
    return ledger, receipt, evidence, counts


def render(counts, evidence, rows=3):
    text = ''.join('12:00:00.000001 Unknown executable (PID 123, TID 123) '
                   'C_GenerateRandom → CKR_OK 1µs\n' for _ in range(rows))
    return (text + (f"LOST {evidence['event_loss']} events\n" if evidence['event_loss'] else '') + 'COUNT_EVIDENCE ' + json.dumps(counts) + '\nEVIDENCE '
            + json.dumps(evidence) + '\n').encode()


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.receipt, self.evidence, self.counts = fixture()

    def check(self, *, rows=3, stdout=None):
        trace = render(self.counts, self.evidence, rows)
        return ORACLE['evaluate'](trace, trace if stdout is None else stdout,
                                  self.ledger, self.receipt)

    def test_nonempty_lossless_healthy_twin(self):
        self.assertTrue(self.check()['pass'])

    def test_ring_record_loss_is_distinct_from_output_byte_loss(self):
        self.counts['raw_calls'] = 2
        self.evidence['event_loss'] = 1
        result = self.check(rows=2)
        self.assertTrue(result['pass'], result)
        self.assertEqual(result['api_calls'], 3)
        self.assertEqual(result['events_lost'], 1)
        self.assertEqual(result['stdout_shed_bytes'], 0)

    def test_missing_ring_loss_cannot_hide_behind_exact_aggregate(self):
        self.counts['raw_calls'] = 2
        self.assertFalse(self.check(rows=2)['pass'])

    def test_exact_stdout_shed_includes_terminal_record_bytes(self):
        self.receipt.update(sink='slowpipe', stdout_stalled=True)
        self.evidence['scheduling']['sink_timeouts'] = 1
        self.evidence['scheduling']['sink_dropped_bytes'] = 17
        trace = render(self.counts, self.evidence)
        self.assertTrue(self.check(stdout=trace[17:])['pass'])
        self.assertFalse(self.check(stdout=trace[16:])['pass'])

    def test_equal_size_stdout_corruption_is_rejected_without_loss(self):
        trace = render(self.counts, self.evidence)
        self.assertFalse(self.check(stdout=b'X' + trace[1:])['pass'])

    def test_wrong_actual_ring_cannot_qualify_requested_size(self):
        self.receipt['ring_actual_bytes'] = 4194304
        self.assertFalse(self.check()['pass'])

    def test_nonstalled_pipe_cannot_claim_stall_acceptance(self):
        self.receipt['sink'] = 'slowpipe'
        self.assertFalse(self.check()['pass'])
        self.receipt['stdout_stalled'] = True
        self.assertFalse(self.check()['pass'], 'kernel pressure alone needs actual sink timeout evidence')

    def test_zero_or_unacknowledged_or_failed_provider_calls_are_rejected(self):
        for change in ('zero', 'issued', 'failed', 'prefix', 'wrongpid', 'function'):
            with self.subTest(change=change):
                ledger, receipt = copy.deepcopy(self.ledger), dict(self.receipt)
                if change == 'zero':
                    ledger.clear()
                elif change == 'issued':
                    receipt['issued_calls'] += 1
                elif change == 'failed':
                    ledger[3]['rv'] = 1
                elif change == 'prefix':
                    ledger[3]['t0'] = 1
                elif change == 'wrongpid':
                    ledger[3]['pid'] += 1
                else:
                    ledger[3]['fn'] = 'C_GetInfo'
                trace = render(self.counts, self.evidence)
                self.assertFalse(ORACLE['evaluate'](trace, trace, ledger, receipt)['pass'])

    def test_image_provider_scope_and_ack_mutations_are_rejected(self):
        for change in ('noimage', 'image', 'targetdev', 'targetino', 'targetimage',
                       'targetoffset', 'noack', 'foreignack', 'duplicateack',
                       'earlyack', 'lateack', 'scope', 'callimage', 'noready', 'duplicateimage'):
            with self.subTest(change=change):
                ledger, receipt = copy.deepcopy(self.ledger), copy.deepcopy(self.receipt)
                if change == 'noimage':
                    ledger.pop(0)
                elif change == 'image':
                    ledger[0]['path'] = '/wrong/caller'
                elif change == 'targetdev':
                    ledger[1]['dev'] = [1, 2]
                elif change == 'targetino':
                    ledger[1]['ino'] += 1
                elif change == 'targetimage':
                    ledger[1]['image'] = 99
                elif change == 'targetoffset':
                    ledger[1]['file_offset'] = 99999
                elif change == 'noack':
                    ledger.pop()
                elif change == 'foreignack':
                    ledger[-1]['image'] = 99
                elif change == 'duplicateack':
                    ledger.append(dict(ledger[-1]))
                elif change == 'earlyack':
                    ledger[-1]['t'] = 200
                elif change == 'lateack':
                    ledger[-1]['t'] = 301
                elif change == 'scope':
                    ledger[3]['scope'] = 'outside'
                elif change == 'callimage':
                    ledger[3]['image'] = 99
                elif change == 'noready':
                    ledger.pop(2)
                else:
                    ledger.append(dict(ledger[0]))
                trace = render(self.counts, self.evidence)
                self.assertFalse(ORACLE['evaluate'](trace, trace, ledger, receipt)['pass'])

    def test_lossy_same_size_corruption_and_reordering_are_rejected(self):
        self.receipt.update(sink='slowpipe', stdout_stalled=True)
        self.evidence['scheduling']['sink_timeouts'] = 1
        self.evidence['scheduling']['sink_dropped_bytes'] = 17
        trace = render(self.counts, self.evidence)
        for damaged in (b'X' * (len(trace) - 17), trace[:-17][::-1]):
            self.assertFalse(self.check(stdout=damaged)['pass'])

    def test_lossy_stdout_terminal_may_have_only_prior_sink_totals(self):
        self.receipt.update(sink='slowpipe', stdout_stalled=True)
        self.evidence['scheduling']['sink_timeouts'] = 1
        stdout_ev = copy.deepcopy(self.evidence)
        stdout_ev['scheduling']['sink_dropped_bytes'] = 0
        stdout = render(self.counts, stdout_ev)[20:]
        # Final file counter includes both dropped ordinary bytes and its own
        # decimal-width difference from the earlier stdout terminal snapshot.
        self.evidence['scheduling']['sink_dropped_bytes'] = 21
        self.assertTrue(self.check(stdout=stdout)['pass'])

    def test_wrong_aggregate_raw_or_duplicate_terminal_rejected(self):
        for field in self.counts:
            counts = dict(self.counts)
            counts[field] += 1
            trace = render(counts, self.evidence)
            self.assertFalse(ORACLE['evaluate'](trace, trace, self.ledger, self.receipt)['pass'])
        trace = render(self.counts, self.evidence) * 2
        self.assertFalse(ORACLE['evaluate'](trace, trace, self.ledger, self.receipt)['pass'])

    def test_saved_file_failure_never_supplies_authoritative_totals(self):
        self.receipt['trace_file_error'] = 'EFBIG'
        self.assertFalse(self.check()['pass'])
        self.receipt['trace_file_error'] = None
        self.receipt['observer_rc'] = 1
        self.assertFalse(self.check()['pass'])

    def test_discard_requires_zero_shed_without_invented_delivered_byte_count(self):
        self.receipt['sink'] = 'discard'
        trace = render(self.counts, self.evidence)
        result = ORACLE['evaluate'](trace, None, self.ledger, self.receipt)
        self.assertTrue(result['pass'], result)
        self.assertIsNone(result['stdout_delivered_bytes'])
        self.evidence['scheduling']['sink_dropped_bytes'] = 1
        trace = render(self.counts, self.evidence)
        self.assertFalse(ORACLE['evaluate'](trace, None, self.ledger, self.receipt)['pass'])

    def test_cancellation_ack_and_cleanup_are_separate(self):
        self.receipt.update(cancel='midcapture', signals=[dict(t_ns=400)],
                            cancellation_ack_ns=50_000_400, cleanup_seconds=4)
        result = self.check()
        self.assertTrue(result['pass'], result)
        self.assertEqual(result['cancellation_response_seconds'], 0.05)
        self.receipt['cancellation_ack_ns'] = 100_000_400
        self.assertFalse(self.check()['pass'])
        self.receipt['cancellation_ack_ns'] = None
        self.assertFalse(self.check()['pass'])

    def test_reap_over_sixty_seconds_is_not_prompt_ack(self):
        self.receipt['cleanup_seconds'] = 60.01
        self.assertFalse(self.check()['pass'])

    def test_midfinal_requires_observed_final_phase_and_separate_ack(self):
        self.receipt.update(cancel='midfinal', signals=[dict(t_ns=400)],
                            cancellation_ack_ns=401)
        result = self.check()
        self.assertFalse(result['pass'])
        self.assertIn('NOT_RUN', result['status'])
        self.receipt['terminal_observed_alive'] = True
        self.assertTrue(self.check()['pass'])

    def test_watchdog_malformed_and_unmatched_are_not_accepted(self):
        self.receipt['watchdog'] = True
        self.assertFalse(self.check()['pass'])
        self.receipt['watchdog'] = False
        for field in ('malformed_records', 'unmatched_returns'):
            self.evidence[field] = 1
            self.assertFalse(self.check()['pass'])
            self.evidence[field] = 0

    def test_unexpected_trace_row_or_loss_marker_refuses(self):
        trace = render(self.counts, self.evidence)
        for prefix in (b'unexpected private data\n', b'LOST 1 events\n'):
            self.assertFalse(ORACLE['evaluate'](prefix + trace, trace,
                                              self.ledger, self.receipt)['pass'])


class BoundedInputAndProviderControls(unittest.TestCase):
    def test_file_limit_is_enforced_before_retaining_oversized_input(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / 'output'
            path.write_bytes(b'X' * 1000000)
            with self.assertRaisesRegex(ValueError, 'memory bound'):
                HARNESS['bounded_read'](path, 31)
            path.write_bytes(b'X' * 31)
            self.assertEqual(HARNESS['bounded_read'](path, 31), b'X' * 31)

    def test_stable_held_original_does_not_bind_a_replaced_loaded_path(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            path, replacement = root / 'provider', root / 'replacement'
            path.write_bytes(b'A' * 4096)
            replacement.write_bytes(b'B' * 4096)
            fd = os.open(path, os.O_RDONLY)
            try:
                path.rename(root / 'held-original')
                replacement.rename(path)
                before = HARNESS['PIN_PROVIDER'](fd)
                foreign_fd = os.open(path, os.O_RDONLY)
                try:
                    loaded = HARNESS['PIN_PROVIDER'](foreign_fd)
                finally:
                    os.close(foreign_fd)
                self.assertEqual(before, HARNESS['PIN_PROVIDER'](fd))
                ledger, receipt, evidence, counts = fixture()
                receipt.update(provider_before=before, provider_after=copy.deepcopy(before))
                ledger[1].update(dev=loaded['dev'], ino=loaded['ino'])
                trace = render(counts, evidence)
                result = ORACLE['evaluate'](trace, trace, ledger, receipt)
                self.assertFalse(result['pass'])
                self.assertTrue(any('mapped held provider' in error for error in result['errors']))
            finally:
                os.close(fd)


class PrebuiltDemotionControls(unittest.TestCase):
    def test_actual_four_file_fixture_executes_ledger_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / 'payload'
            result = DEMOTION['build'](directory)
            self.assertEqual(result['topology_check'], dict(calls=10,
                phases=dict(a=5, shared=2, fence=1, proof=2), successful_calls=6, error_calls=4))
            self.assertEqual({row['name'] for row in result['inputs']}, set(DEMOTION['NAMES']))
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            with self.assertRaises(FileExistsError):
                DEMOTION['build'](directory)
            self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})
            self.assertEqual(len(before), 4, 'topology control must clean its own temporary files')


class NativeWrapControls(unittest.TestCase):
    def test_three_round_probe_has_one_physical_pair_and_exact96_call_oracle(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / 'payload'
            WRAP['build'](directory)
            observed = WRAP['execute_fixture'](directory, counted=3, shared=1, probe=True)
            def validate(value):
                return WRAP['check_ledger'](**value, directory=directory,
                                            counted=3, shared=1, probe=True)
            facts = validate(observed)
            self.assertEqual(facts['calls'], 96)
            self.assertEqual(facts['physical_pairs'], 1)
            self.assertEqual(facts['phase_calls'], {'a': 96})
            self.assertEqual([r['round'] for r in observed['acks'] if r['event'] == 'a-done'], [1, 2, 3])
            for mutation in ('missing_third_call', 'foreign_pair', 'shared_call', 'unacked_round', 'unexpected_b_ack'):
                with self.subTest(mutation=mutation):
                    changed = copy.deepcopy(observed)
                    calls = [r for r in changed['rows'] if r['kind'] == 'call']
                    if mutation == 'missing_third_call':
                        changed['rows'].remove(calls[-1])
                    elif mutation == 'foreign_pair':
                        next(r for r in changed['rows'] if r['kind'] == 'target')['ino'] += 1
                    elif mutation == 'shared_call':
                        calls[-1]['phase'] = 'shared'
                    elif mutation == 'unacked_round':
                        changed['acks'] = [r for r in changed['acks']
                                           if not (r['event'] == 'a-done' and r['round'] == 3)]
                    else:
                        changed['acks'].insert(-1, dict(event='b-ready', round=0, calls=96, t=1))
                    with self.assertRaises(ValueError):
                        validate(changed)

    def test_actual32_body_topology_and_independent_schedule_mutations(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / 'payload'
            prepared = WRAP['build'](directory)
            self.assertEqual(prepared['native_check']['calls'], 192)
            self.assertEqual(prepared['native_check']['targets'], 32)
            self.assertEqual(prepared['probe_check']['calls'], 96)
            self.assertEqual(prepared['probe_check']['physical_pairs'], 1)
            observed = WRAP['execute_fixture'](directory, 1, 1)
            def validate(value):
                return WRAP['check_ledger'](**value, directory=directory, counted=1, shared=1)
            self.assertEqual(validate(observed)['calls'], 128)
            for change in ('missing', 'duplicate', 'wrongslot', 'clock', 'return', 'target', 'ack', 'earlyack'):
                with self.subTest(change=change):
                    value = copy.deepcopy(observed)
                    calls = [row for row in value['rows'] if row['kind'] == 'call']
                    if change == 'missing':
                        value['rows'].remove(calls[0])
                    elif change == 'duplicate':
                        value['rows'].append(dict(calls[0]))
                    elif change == 'wrongslot':
                        calls[0]['slot'] = 99
                    elif change == 'clock':
                        calls[0]['after_return_ns'] = calls[0]['before_call_ns']
                    elif change == 'return':
                        calls[0]['return_status'] = 7
                    elif change == 'target':
                        value['rows'][1]['ino'] += 1
                    elif change == 'ack':
                        value['acks'].append(dict(value['acks'][2]))
                    else:
                        value['acks'][2]['t'] = calls[0]['before_call_ns']
                    with self.assertRaises(ValueError):
                        validate(value)


class LiveMetadataControls(unittest.TestCase):
    def test_events_capacity_queries_only_owned_ring_fds_with_real_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            files = []
            for identity, kind in ((1, 1), (2, 27), (3, 27)):
                path = Path(temporary) / str(identity)
                path.write_text(f'map_id:\t{identity}\nmap_type:\t{kind}\n')
                files.append(path)
            def answer(argv, **unused):
                identity = int(argv[-1])
                row = dict(name='EVENTS' if identity == 2 else 'DISCOVERY',
                           type='ringbuf', max_entries=4194304)
                return subprocess.CompletedProcess(argv, 0, json.dumps(row).encode())
            with mock.patch.object(Path, 'iterdir', return_value=iter(files)), \
                    mock.patch.object(subprocess, 'run', side_effect=answer) as query:
                self.assertEqual(HARNESS['events_ring_capacity'](123), 4194304)
            self.assertEqual([call.args[0][-1] for call in query.call_args_list], ['2', '3'])
            with mock.patch.object(Path, 'iterdir', return_value=iter(files[:1])), \
                    mock.patch.object(subprocess, 'run', side_effect=answer) as query:
                with self.assertRaises(ValueError):
                    HARNESS['events_ring_capacity'](123)
            query.assert_not_called()


class ManifestControls(unittest.TestCase):
    def test_explicit_manifest_uses_held_matching_provider_and_rejects_mutations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider = root / 'provider.so'
            provider.write_bytes(b'owned provider')
            manifest = root / 'manifest.json'
            provider_pin = HARNESS['NATIVE'].FilePin(provider)
            try:
                document = dict(schema='p11scope-manifest/5', module_path=str(provider),
                    objects=[dict(path=str(provider), identity=dict(sha256=provider_pin.digest))])
                manifest.write_text(json.dumps(document))
                pin = HARNESS['NATIVE'].FilePin(manifest)
                try:
                    self.assertEqual(HARNESS['manifest_arguments']([pin], provider_pin),
                                     ['--manifest', str(manifest)])
                    replacement = root / 'replacement'
                    replacement.write_bytes(manifest.read_bytes())
                    replacement.replace(manifest)
                    with self.assertRaises(ValueError):
                        HARNESS['manifest_arguments']([pin], provider_pin)
                finally:
                    pin.close()
                for mutation in ('hash', 'path', 'duplicate', 'schema', 'malformed'):
                    value = copy.deepcopy(document)
                    if mutation == 'hash':
                        value['objects'][0]['identity']['sha256'] = '0' * 64
                    elif mutation == 'path':
                        value['module_path'] = str(root / 'other.so')
                    elif mutation == 'duplicate':
                        value['objects'].append(copy.deepcopy(value['objects'][0]))
                    elif mutation == 'schema':
                        value['schema'] = 'wrong'
                    manifest.write_text('{' if mutation == 'malformed' else json.dumps(value))
                    pin = HARNESS['NATIVE'].FilePin(manifest)
                    try:
                        with self.assertRaises(ValueError):
                            HARNESS['manifest_arguments']([pin], provider_pin)
                    finally:
                        pin.close()
            finally:
                provider_pin.close()


class ReporterProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.probe = cls.root / 'reporter-probe'
        result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            str(ROOT / 'tests/fixtures/operator-output/reporter-probe.c'), '-o', str(cls.probe)],
            capture_output=True, text=True, timeout=20)
        if result.returncode:
            cls.temporary.cleanup()
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def decode(self, payload, tail=0, head=None):
        path = self.root / 'records.bin'
        path.write_bytes(payload)
        return subprocess.run([str(self.probe), '--decode-fixture', '123', str(tail),
            str(tail + len(payload) if head is None else head), str(path)],
            capture_output=True, text=True, timeout=3)

    def test_actual_c_decoder_accepts_only_one_loss_free_main_tid_sample(self):
        sample = struct.pack('<IHHQIIQ', 9, 0, 32, 0x1234, 123, 123, 700)
        for tail in (0, 250):
            result = self.decode(sample, tail)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(rows[0], dict(kind='reporter', mode='decode_fixture',
                ip=0x1234, pid=123, tid=123, t_ns=700))
            self.assertEqual(rows[1]['samples'], 1)
        for name, payload, head in (
                ('duplicate', sample * 2, None),
                ('foreign-tid', struct.pack('<IHHQIIQ', 9, 0, 32, 0x1234, 123, 124, 700), None),
                ('foreign-pid', struct.pack('<IHHQIIQ', 9, 0, 32, 0x1234, 124, 123, 700), None),
                ('lost', struct.pack('<IHHQQ', 2, 0, 24, 1, 1), None),
                ('lost-samples', struct.pack('<IHHQ', 13, 0, 16, 1), None),
                ('short', sample[:-1], None),
                ('unknown', struct.pack('<IHH', 99, 0, 8), None),
                ('overrun', sample, 300),
                ('backward-head', sample, 0)):
            with self.subTest(mutation=name):
                result = self.decode(payload, 1 if name == 'backward-head' else 0, head)
                self.assertNotEqual(result.returncode, 0, 'invalid evidence must not become an ACK')

    def test_symbol_reader_streams_a_large_table_with_bounded_lines_and_extent(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/reporter_probe.py'))
        with tempfile.TemporaryFile() as output:
            chunk = b'unrelated_symbol t 1 1\n' * 1024
            for _ in range(800):
                output.write(chunk)
            output.write(b'p11scope::run::report_capture_cancel t 1234 160\n')
            self.assertGreater(output.tell(), 16 * 1024 * 1024)
            self.assertEqual(module['read_reporter_symbols'](output), [0x1234])
            output.write(b'p11scope::run::report_capture_cancel t 5678 160\n')
            with self.assertRaises(ValueError):
                module['read_reporter_symbols'](output)
            output.seek(0)
            output.truncate()
            output.write(b'x' * 65537 + b'\n')
            with self.assertRaises(ValueError):
                module['read_reporter_symbols'](output)
            output.truncate(64 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                module['read_reporter_symbols'](output)

    def test_actual_elf_symbol_resolution_and_offset_reject_foreign_surfaces(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/reporter_probe.py'))
        source = self.root / 'reporter.c'
        target = self.root / 'reporter-target'
        source.write_text('#include <unistd.h>\nvoid reporter(int) __asm__("_ZN8p11scope3run21report_capture_cancel17h0123456789abcdefE");\n'
            '__attribute__((noinline,used)) void reporter(int x) { __asm__ volatile("" : : "r"(x)); }\n'
            'int main(int argc, char **argv) { (void)argv; if (argc > 1) pause(); reporter(2); return 0; }\n')
        result = subprocess.run(['cc', '-O2', '-fPIE', '-pie', str(source), '-o', str(target)],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        pin = HARNESS['NATIVE'].FilePin(target)
        foreign = HARNESS['NATIVE'].FilePin(self.probe)
        try:
            resolved = module['resolve_reporter'](pin)
            self.assertEqual(resolved['symbol'], 'p11scope::run::report_capture_cancel')
            self.assertGreater(resolved['file_offset'], 0)
            self.assertEqual(module['symbol_file_offset'](pin.fd, resolved['virtual_address']), resolved['file_offset'])
            child = subprocess.Popen([str(target), 'hold'])
            owner = None
            try:
                owner = HARNESS['NATIVE'].OwnedProcess(child.pid, os.getpid(), os.getuid())
                expected = module['expected_witness'](pin, owner, resolved)
                self.assertEqual(expected['pid'], child.pid)
                self.assertEqual(expected['tid'], child.pid)
                self.assertGreater(expected['ip'], 0)
                with self.assertRaises(ValueError):
                    module['expected_witness'](foreign, owner, resolved)
            finally:
                child.terminate()
                child.wait(timeout=3)
                if owner:
                    owner.close()
            with self.assertRaises(ValueError):
                module['symbol_file_offset'](pin.fd, 0)
            with self.assertRaises(ValueError):
                module['resolve_reporter'](foreign)
        finally:
            foreign.close()
            pin.close()

    def test_wire_witness_requires_actual_mode_identity_and_loss_free_causal_once(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/reporter_probe.py'))
        expected = dict(pid=123, tid=123, start_time=9, dev=2, ino=3, file_offset=80, ip=0x1234)
        ready = dict(kind='ready', mode='perf_uprobe', clock='CLOCK_MONOTONIC', t_ns=400,
                     **{key: value for key, value in expected.items() if key != 'ip'})
        event = dict(kind='reporter', mode='perf_uprobe', pid=123, tid=123, ip=0x1234, t_ns=700)
        final = dict(kind='final', mode='perf_uprobe', samples=1, lost=0, kernel_count=1,
                     time_enabled=500, time_running=500)
        records, signals = [ready, event, final], [dict(signal='SIGINT', t_ns=600)]
        self.assertEqual(module['validate_witness'](records, expected, signals)['ack_ns'], 700)
        for mutation in ('fixture', 'birth', 'inode', 'offset', 'thread', 'ip', 'lost',
                         'kernel-count', 'multiplex', 'duplicate', 'pre-signal', 'slow', 'not-ready',
                         'bool-kernel-count', 'bool-enabled', 'bool-lost'):
            changed = copy.deepcopy(records)
            if mutation == 'fixture': changed[1]['mode'] = 'decode_fixture'
            elif mutation == 'birth': changed[0]['start_time'] += 1
            elif mutation == 'inode': changed[0]['ino'] += 1
            elif mutation == 'offset': changed[0]['file_offset'] += 1
            elif mutation == 'thread': changed[1]['tid'] += 1
            elif mutation == 'ip': changed[1]['ip'] += 1
            elif mutation == 'lost': changed[2]['lost'] = 1
            elif mutation == 'kernel-count': changed[2]['kernel_count'] = 2
            elif mutation == 'multiplex': changed[2]['time_running'] = 499
            elif mutation == 'duplicate': changed.insert(2, copy.deepcopy(changed[1]))
            elif mutation == 'pre-signal': changed[1]['t_ns'] = 599
            elif mutation == 'slow': changed[1]['t_ns'] = 100000600
            elif mutation == 'bool-kernel-count': changed[2]['kernel_count'] = True
            elif mutation == 'bool-enabled': changed[2].update(time_enabled=True, time_running=True)
            elif mutation == 'bool-lost': changed[2]['lost'] = False
            else: changed[0]['t_ns'] = 601
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module['validate_witness'](changed, expected, signals)
        with self.assertRaises(ValueError):
            module['validate_witness'](records, expected, [])

    def test_live_mode_refuses_a_foreign_executable_before_attaching(self):
        fd = os.open(self.probe, os.O_RDONLY)
        try:
            result = subprocess.run([str(self.probe), '--probe', str(fd), str(os.getpid()),
                '1', '0', '1000'], pass_fds=(fd,), capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('observer executable differs', result.stderr)
            self.assertNotIn('"kind":"ready"', result.stdout)
        finally:
            os.close(fd)


class InventorySavedCaptureTests(unittest.TestCase):
    def test_only_committed_owned_positive_milestones_release_calls(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/capture_inventory_pair.py'))
        view = module['CaptureView'](123, '/owned/provider-A.so')
        edge = dict(kind='edge_observed', event=dict(capture='armed', presence='mapped',
            entries=dict(count=None), identity_context=dict(caller=dict(pid=123),
            module=dict(path='/owned/provider-A.so'))))
        self.assertFalse(view.consume([edge]))
        self.assertIsNone(view.edge)
        self.assertTrue(view.consume([dict(kind='pass_committed')]))
        self.assertEqual(view.edge['capture'], 'armed')
        for row in (dict(edge, event={**edge['event'], 'identity_context':dict(caller=dict(pid=124), module=dict(path='/owned/provider-A.so'))}),
                    dict(edge, event={**edge['event'], 'identity_context':dict(caller=dict(pid=123), module=dict(path='/foreign/provider-A.so'))})):
            other = module['CaptureView'](123, '/owned/provider-A.so')
            other.consume([row, dict(kind='pass_committed')])
            self.assertIsNone(other.edge)

    def test_saved_capture_population_and_exact_primary_count_controls(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/capture_inventory_pair.py'))
        document = dict(schema='p11scope/inventory/v1',callers=[dict(pid=123)],modules=[dict(id='m0')],
            edges=[dict(entries=dict(count=5))],observation=dict(lane='native',retirement='closed'))
        self.assertEqual(module['check_snapshot'](document), 5)
        for mutation in ('empty', 'count', 'lane', 'retirement'):
            changed = copy.deepcopy(document)
            if mutation == 'empty': changed['edges'] = []
            elif mutation == 'count': changed['edges'][0]['entries']['count'] = 4
            elif mutation == 'lane': changed['observation']['lane'] = 'scan'
            else: changed['observation']['retirement'] = 'open'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module['check_snapshot'](changed)


class ReporterControlAdapterTests(unittest.TestCase):
    def test_no_signal_control_cannot_accept_sample_fixture_loss_or_foreign_ready(self):
        module = runpy.run_path(str(ROOT / 'tests/fixtures/operator-output/qualify_reporter_probe.py'))
        expected = dict(pid=123, tid=123, start_time=9, dev=2, ino=3, file_offset=80)
        rows = [dict(kind='ready', mode='perf_uprobe', clock='CLOCK_MONOTONIC', **expected),
                dict(kind='final', mode='perf_uprobe', samples=0, kernel_count=0, lost=0,
                     time_enabled=100, time_running=100)]
        self.assertEqual(module['check_zero'](rows, expected)['no_signal_samples'], 0)
        for mutation in ('sample', 'fixture', 'loss', 'foreign', 'multiplex'):
            changed = copy.deepcopy(rows)
            if mutation == 'sample': changed[1]['samples'] = 1
            elif mutation == 'fixture': changed[0]['mode'] = 'decode_fixture'
            elif mutation == 'loss': changed[1]['lost'] = 1
            elif mutation == 'foreign': changed[0]['ino'] += 1
            else: changed[1]['time_running'] = 99
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module['check_zero'](changed, expected)


class CancellationMarkerTests(unittest.TestCase):
    def test_only_sent_first_signal_gets_one_conservative_arrival_timestamp(self):
        receipt = dict(signals=[], cancellation_ack_ns=None)
        line = b'p11scope: cancel: signal 2 observed during finalization after 3 ticks\n'
        record = HARNESS['record_cancellation_marker']
        with mock.patch.object(record.__globals__['time'], 'monotonic_ns', side_effect=[700, 900]):
            record(receipt, line)
            self.assertIsNone(receipt['cancellation_ack_ns'])
            receipt['signals'].append(dict(signal='SIGINT', t_ns=600))
            record(receipt, line[:-1])
            self.assertIsNone(receipt['cancellation_ack_ns'])
            record(receipt, line)
            self.assertEqual(receipt['cancellation_ack_ns'], 700)
            self.assertEqual(receipt['cancellation_ack']['phase'], 'finalization')
            record(receipt, line)
            self.assertEqual(receipt['cancellation_ack_ns'], 700, 'final drain must retain earlier arrival bound')
            with self.assertRaises(ValueError):
                record(receipt, line + line)

    def test_complete_live_and_late_first_signal_markers(self):
        for phase, line in (
                ('capture', b'p11scope: cancel: loop exited on signal 2 after 7 ticks\n'),
                ('finalization', b'p11scope: cancel: signal 2 observed during finalization after 7 ticks\n')):
            with self.subTest(phase=phase):
                self.assertEqual(HARNESS['cancellation_marker'](b'other diagnostic\n' + line, 2),
                                 dict(signal=2, ticks=7, phase=phase, channel='readable_stderr'))
                self.assertIsNone(HARNESS['cancellation_marker'](line[:-1], 2), 'partial line is not an ACK')
                with self.assertRaises(ValueError):
                    HARNESS['cancellation_marker'](line, 15)
                with self.assertRaises(ValueError):
                    HARNESS['cancellation_marker'](line + line, 2)
        for data in (b'', b'noise p11scope: cancel: loop exited on signal 2 after 7 ticks\n',
                     b'p11scope: cancel: loop exited on signal 2 after -1 ticks\n',
                     b'p11scope: cancel: signal 2 observed in worker after 7 ticks\n'):
            self.assertIsNone(HARNESS['cancellation_marker'](data, 2))


class FdControls(unittest.TestCase):
    def test_atomic_writer_stalls_before_pipe_byte_capacity_is_full(self):
        pipe = HARNESS['OutputPipe']()
        try:
            os.set_blocking(pipe.write_fd, False)
            self.assertEqual(os.write(pipe.write_fd, b'H' * 169), 169)
            with self.assertRaises(BlockingIOError):
                os.write(pipe.write_fd, b'X' * 4096)
            self.assertFalse(pipe.full(), 'this regression requires occupancy below4096')
            self.assertTrue(pipe.stalled(), 'actual atomic write returned EAGAIN')
            self.assertEqual(pipe.drain_available(), b'H' * 169)
            self.assertFalse(pipe.stalled(), 'empty pipe cannot qualify pressure')
            self.assertEqual(os.write(pipe.write_fd, b'X' * 4096), 4096)
            self.assertEqual(pipe.drain_available(), b'H' * 169 + b'X' * 4096)
        finally:
            pipe.close()

    def test_real_writer_stalls_and_drain_counts_exact_bytes(self):
        pipe = HARNESS['OutputPipe']()
        child = None
        try:
            child = subprocess.Popen([sys.executable, '-I', '-c',
                'import os; os.write(1, b"X" * 8192)'], stdout=pipe.write_fd)
            pipe.close_writer()
            deadline = time.monotonic() + 3
            while not pipe.full() and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(pipe.full(), 'actual output never filled the pipe')
            self.assertIsNone(child.poll(), 'writer must still be blocked')
            while child.poll() is None:
                pipe.drain_available()
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.001)
            child.wait(timeout=1)
            self.assertEqual(pipe.drain_available(), b'X' * 8192)
        finally:
            if child and child.poll() is None:
                child.kill()
                child.wait(timeout=1)
            pipe.close()

    def test_held_child_stdout_does_not_require_eof_for_reap_measurement(self):
        pipe = HARNESS['OutputPipe']()
        holder = None
        try:
            holder = subprocess.Popen([sys.executable, '-I', '-c',
                'import os,time; os.write(1,b"held"); time.sleep(60)'], stdout=pipe.write_fd)
            pipe.close_writer()
            deadline = time.monotonic() + 3
            while len(pipe.received) < 4:
                pipe.read()
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.001)
            begin = time.monotonic()
            self.assertEqual(pipe.drain_available(), b'held')
            self.assertLess(time.monotonic() - begin, 0.1)
            self.assertIsNone(holder.poll(), 'stdout owner should still hold its fd')
        finally:
            if holder:
                holder.terminate()
                holder.wait(timeout=1)
            pipe.close()

    def test_regular_file_limit_is_real_failed_io_not_authoritative_trace(self):
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([sys.executable, '-I', '-c',
                'import os; os.write(1,b"X"*65536); os.write(1,b"Y")'],
                stdout=output, stderr=subprocess.PIPE, preexec_fn=HARNESS['file_limit'])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(os.fstat(output.fileno()).st_size, 65536)
            self.assertIn(b'File too large', result.stderr)

    def test_matrix_enumerates_exact_27_cells(self):
        self.assertEqual(len(HARNESS['CELLS']), 27)
        self.assertEqual(len(set(HARNESS['CELLS'])), 27)


if __name__ == '__main__':
    unittest.main()
