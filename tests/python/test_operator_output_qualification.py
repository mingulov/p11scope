# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle mutations and genuine fd controls, never installed acceptance."""
import copy
import json
import os
import subprocess
import tempfile
import sys
import time
from pathlib import Path
import runpy
import unittest

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
        self.evidence['scheduling']['sink_dropped_bytes'] = 17
        trace = render(self.counts, self.evidence)
        for damaged in (b'X' * (len(trace) - 17), trace[:-17][::-1]):
            self.assertFalse(self.check(stdout=damaged)['pass'])

    def test_lossy_stdout_terminal_may_have_only_prior_sink_totals(self):
        self.receipt.update(sink='slowpipe', stdout_stalled=True)
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
    def test_actual32_body_topology_and_independent_schedule_mutations(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / 'payload'
            prepared = WRAP['build'](directory)
            self.assertEqual(prepared['native_check']['calls'], 192)
            self.assertEqual(prepared['native_check']['targets'], 32)
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


class FdControls(unittest.TestCase):
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
