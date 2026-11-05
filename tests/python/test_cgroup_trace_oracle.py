# SPDX-License-Identifier: GPL-3.0-or-later
"""The trace oracle must reject false names and unknown-only positive cells."""

import copy
import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = runpy.run_path(str(ROOT / "scripts/cgroup-trace-oracle.py"))


def inputs():
    image = {"kind": "image", "image": 0, "pid": 123, "start_time": 77,
             "path": "/owned/trace-a", "dev": 2, "ino": 3,
             "mtime_ns": 4, "pid_namespace": 5, "time_namespace": 6, "t": 70}
    target = {"kind": "target", "image": 0, "fn": "C_GenerateRandom",
              "dev": [8, 1], "ino": 9, "file_offset": 100}
    ledger = [image, target, {"kind": "ready", "image": 0, "t": 80}]
    ledger += [{"kind": "call", "image": 0, "pid": 123, "tid": 123,
                "fn": "C_GenerateRandom", "rv": 0, "phase": "main",
                "scope": "selected", "t0": 110 + i * 10, "t1": 111 + i * 10}
               for i in range(3)]
    pin = {"dev": [8, 1], "ino": 9, "sha256": "a" * 64,
           "mapping": {"dev": [8, 1], "ino": 9, "file_offset": 0}}
    receipt = {"cell": "stable", "require_named": True, "pid_namespace": 5,
               "selected_initial_pids": [123],
               "time_namespace": 6, "images": [copy.deepcopy(image)],
               "provider_before": pin, "provider_after": copy.deepcopy(pin),
               "observer_started_ns": 90, "observer_ready_ns": 100,
               "observer_stopped_ns": 200, "scope_created_ns": 50,
               "stop_latency_seconds": 0.1, "observer_rc": 0, "caller_rc": 0,
               "privacy_canaries": ["PRIVATE_N3_SENTINEL"], "observer_stderr": ""}
    evidence = ('EVIDENCE {"privacy_mode":"allowlisted","final_drain":true,'
                '"trace_truncated":false,"event_loss":0}\n')
    counts = 'COUNT_EVIDENCE {"stats_entered":3,"stats_returned":3,"raw_calls":3}\n'
    rows = ['12:00:00.00000%d %s (PID 123, TID 123)%s C_GenerateRandom → CKR_OK 1.0µs\n'
            % (i, 'Unknown executable' if i == 0 else '"trace-a"',
               '' if i == 0 else ' exe="/owned/trace-a"') for i in range(3)]
    return ''.join(rows) + counts + evidence, ledger, receipt


def exec_inputs(mode='leader'):
    trace, ledger, receipt = inputs()
    image = dict(ledger[0], image=1, t=135)
    request = dict(kind='exec', image=0, pid=123, tid=124 if mode == 'nonleader' else 123,
                   start_time=77, mode=mode, path=image['path'], scope='outside', t=134)
    ledger.extend((request, image, dict(ledger[1], image=1, fn='C_GetSessionInfo')))
    ledger.extend(dict(ledger[3], image=1, fn='C_GetSessionInfo', phase='reenter',
                       t0=140 + i * 10, t1=141 + i * 10) for i in range(3))
    receipt.update(cell='reexec', require_named_images=[0, 1], first_unknown_images=[1],
                   exec_transitions=[dict(from_image=0, to_image=1, mode=mode, same_path=True,
                                          t0=133, t1=136, request=copy.deepcopy(request))])
    receipt['images'].append(copy.deepcopy(image))
    lines = trace.splitlines()
    lines[3:3] = ['12:00:00.00000%d %s (PID 123, TID 123)%s C_GetSessionInfo → CKR_OK 1.0µs'
                 % (i + 3, 'Unknown executable' if i == 0 else '"trace-a"',
                    '' if i == 0 else ' exe="/owned/trace-a"') for i in range(3)]
    return ('\n'.join(lines) + '\n').replace(':3', ':6'), ledger, receipt


def short_setup_inputs():
    trace, ledger, receipt = inputs()
    image = dict(ledger[0], t=105)
    receipt.update(cell='short', require_named=False, images=[copy.deepcopy(image)],
                   selected_initial_pids=[999], first_unknown_images=[0],
                   short_lifetime=dict(image=0, spawn_started_ns=101,
                                       exit_observed_ns=190, limit_seconds=1))
    functions = ('C_GetFunctionList', 'C_Initialize', 'C_GetSlotList', 'C_OpenSession',
                 'C_GenerateRandom', 'C_CloseSession', 'C_Finalize')
    ledger, rows = [image], []
    for index, fn in enumerate(functions):
        phase = 'setup' if index < 4 else 'main' if index == 4 else 'teardown'
        ledger.extend((dict(kind='target', image=0, fn=fn, dev=[8, 1], ino=9, file_offset=100),
                       dict(kind='call', image=0, pid=123, tid=123, fn=fn, rv=0,
                            phase=phase, scope='selected', t0=110 + index * 10, t1=111 + index * 10)))
        rows.append('12:00:00.00000%d %s (PID 123, TID 123)%s %s → CKR_OK 1.0µs\n'
                    % (index, 'Unknown executable' if index == 0 else '"trace-a"',
                       '' if index == 0 else ' exe="/owned/trace-a"', fn))
    return ''.join(rows) + '\n'.join(trace.splitlines()[3:]).replace(':3', ':7') + '\n', ledger, receipt


def u6_inputs(cell):
    trace, ledger, receipt = inputs()
    receipt['cell'] = cell
    if cell == 'slow-reader':
        for row in ledger:
            for field in ('t', 't0', 't1'):
                if field in row:
                    row[field] *= 10_000_000
        for field in ('scope_created_ns', 'observer_started_ns', 'observer_ready_ns', 'observer_stopped_ns'):
            receipt[field] *= 10_000_000
        receipt['reader_pause'] = dict(paused_ns=1_000_000_000, resumed_ns=1_400_000_000,
                                      hold_ns=250_000_000)
        return trace, ledger, receipt
    first = ledger[0]
    second = dict(first, image=1, pid=124, start_time=78, path='/owned/b/trace-a', ino=4)
    receipt['images'].append(copy.deepcopy(second))
    receipt['selected_initial_pids'] = [123, 124]
    ledger.extend((second, dict(ledger[1], image=1)))
    if cell == 'mapped-only':
        ledger[-1]['fn'] = 'C_GetFunctionList'
        mapping = dict(dev=[8, 1], ino=9, file_offset=100, permissions='r-xp')
        receipt['mapped_only'] = dict(image=1, before=mapping, after=copy.deepcopy(mapping),
                                      before_ns=80, after_ns=201)
        return trace, ledger, receipt
    first['path'] = '/owned/a/trace-a'
    receipt['images'][0]['path'] = first['path']
    calls = [dict(row, image=1, pid=124, tid=124)
             for row in ledger if row['kind'] == 'call']
    ledger.extend(calls)
    rows = trace.splitlines()
    events = [line.replace('/owned/trace-a', first['path']) for line in rows[:3]]
    events += [line.replace('PID 123, TID 123', 'PID 124, TID 124')
                   .replace('/owned/trace-a', second['path']) for line in rows[:3]]
    counts = json.loads(rows[3].split(' ', 1)[1])
    counts = {field: 6 for field in counts}
    if cell == 'unreadable':
        events[3:] = [line.replace('"trace-a"', 'Unknown executable')
                           .replace(' exe="/owned/b/trace-a"', '') for line in events[3:]]
        full = (1 << 41) - 1
        caps = dict(uid=0, gid=0, groups=[], effective=full & ~(1 << 19), permitted=full & ~(1 << 19),
                    bounding=full & ~(1 << 19))
        controller = dict(uid=0, gid=0, groups=[0], pid=111, effective=full, permitted=full, bounding=full)
        def probe(started, finished):
            return dict(credentials=copy.deepcopy(caps), started_ns=started, finished_ns=finished,
                anchor=dict(pid=123, ppid=111, start_time=77, credentials=copy.deepcopy(caps),
                    exe={field: first[field] for field in ('path', 'dev', 'ino', 'mtime_ns')},
                    mount_namespace=99, metadata_readable=dict(stat=True, maps=True, cgroup=True)),
                target=dict(pid=124, ppid=111, start_time=78, credentials=copy.deepcopy(caps),
                    exe_errors=dict(stat=13, readlink=13), namespace_errno=13,
                    metadata_readable=dict(stat=True, maps=True, cgroup=True)))
        receipt['unreadable'] = dict(image=1, controller=controller,
            dumpability=dict(kind='dumpability', image=1, pid=124, tid=124, uid=0, dumpable=0, t=80),
            before=probe(92, 95), after=probe(150, 160), observer_credentials=copy.deepcopy(caps),
            final_observer_credentials=copy.deepcopy(caps))
    return '\n'.join(events + ['COUNT_EVIDENCE ' + json.dumps(counts), rows[4]]) + '\n', ledger, receipt


class OracleTests(unittest.TestCase):
    def test_event_loss_and_final_drain_are_required_literal_proofs_with_partial_names(self):
        trace, ledger, receipt = inputs()
        lines = trace.splitlines()
        original = json.loads(lines[-1].split(' ', 1)[1])
        original['completeness'] = 'PARTIAL'
        healthy = '\n'.join(lines[:-1] + ['EVIDENCE ' + json.dumps(original)]) + '\n'
        self.assertTrue(ORACLE['evaluate'](healthy, ledger, receipt, healthy)['pass'])
        for field, values in (('event_loss', ('missing', False, None, '0', 1)),
                              ('final_drain', ('missing', False, None, 0, 1, 'true'))):
            for value in values:
                evidence = copy.deepcopy(original)
                if value == 'missing':
                    del evidence[field]
                else:
                    evidence[field] = value
                poisoned = '\n'.join(lines[:-1] + ['EVIDENCE ' + json.dumps(evidence)]) + '\n'
                with self.subTest(field=field, value=value):
                    self.assertFalse(ORACLE['evaluate'](poisoned, ledger, receipt, poisoned)['pass'])

    def test_unreadable_requires_real_matching_credentials_and_both_access_denials(self):
        trace, ledger, receipt = u6_inputs('unreadable')
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt, trace)['pass'])
        for change in ('missing', 'wrong-errno', 'missing-proof', 'ptrace-restored', 'other-cap-lost',
                       'wrong-birth', 'wrong-parent', 'early-final-proof', 'wrong-dumpability', 'ordinary-uid',
                       'gid-mismatch', 'groups-mismatch', 'namespace-readable', 'maps-unavailable'):
            bad = copy.deepcopy(receipt)
            proof = bad['unreadable']
            if change == 'missing':
                del bad['unreadable']
            elif change == 'wrong-errno':
                proof['after']['target']['exe_errors']['stat'] = 2
            elif change == 'missing-proof':
                del proof['before']['target']['exe_errors']['readlink']
            elif change == 'ptrace-restored':
                proof['final_observer_credentials']['effective'] |= 1 << 19
            elif change == 'other-cap-lost':
                proof['before']['credentials']['effective'] &= ~(1 << 21)
            elif change == 'wrong-birth':
                proof['after']['target']['start_time'] += 1
            elif change == 'wrong-parent':
                proof['before']['target']['ppid'] += 1
            elif change == 'early-final-proof':
                proof['after']['started_ns'] = 100
            elif change == 'wrong-dumpability':
                proof['dumpability']['dumpable'] = 1
            elif change == 'gid-mismatch':
                proof['after']['target']['credentials']['gid'] = 1000
            elif change == 'groups-mismatch':
                proof['after']['target']['credentials']['groups'] = [0]
            elif change == 'namespace-readable':
                proof['before']['target']['namespace_errno'] = 0
            elif change == 'maps-unavailable':
                proof['after']['target']['metadata_readable']['maps'] = False
            else:
                proof['controller']['uid'] = 1000
            with self.subTest(change=change):
                self.assertFalse(ORACLE['evaluate'](trace, ledger, bad, trace)['pass'])

    def test_unreadable_target_cannot_gain_a_name_or_hide_a_missing_call(self):
        trace, ledger, receipt = u6_inputs('unreadable')
        invented = trace.replace('Unknown executable (PID 124, TID 124)',
                                 '"trace-a" (PID 124, TID 124) exe="/owned/b/trace-a"')
        self.assertFalse(ORACLE['evaluate'](invented, ledger, receipt, invented)['pass'])
        missing = '\n'.join(trace.splitlines()[1:]) + '\n'
        self.assertFalse(ORACLE['evaluate'](missing, ledger, receipt, missing)['pass'])

    def test_mapped_only_requires_a_real_mapping_held_across_the_capture(self):
        trace, ledger, receipt = u6_inputs('mapped-only')
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt)['pass'])
        for change in ('missing', 'changed', 'late', 'early'):
            bad = copy.deepcopy(receipt)
            if change == 'missing':
                del bad['mapped_only']
            elif change == 'changed':
                bad['mapped_only']['after']['ino'] += 1
            elif change == 'late':
                bad['mapped_only']['before_ns'] = bad['observer_started_ns'] + 1
            else:
                bad['mapped_only']['after_ns'] = bad['observer_stopped_ns'] - 1
            with self.subTest(change=change):
                self.assertFalse(ORACLE['evaluate'](trace, ledger, bad)['pass'])

    def test_duplicate_basename_requires_two_distinct_files_and_two_named_populations(self):
        trace, ledger, receipt = u6_inputs('duplicate-basename')
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt)['pass'])
        unknown = trace.replace('"trace-a" (PID 124, TID 124) exe="/owned/b/trace-a"',
                                'Unknown executable (PID 124, TID 124)')
        self.assertFalse(ORACLE['evaluate'](unknown, ledger, receipt)['pass'])
        for population in (ledger, receipt['images']):
            next(row for row in population if row.get('kind') == 'image' and row['image'] == 1)['ino'] = 3
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_slow_reader_requires_an_acknowledged_pause_over_a_real_call(self):
        trace, ledger, receipt = u6_inputs('slow-reader')
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt, trace)['pass'])
        for change in ('missing', 'short', 'after-calls', 'late'):
            bad = copy.deepcopy(receipt)
            if change == 'missing':
                del bad['reader_pause']
            elif change == 'short':
                bad['reader_pause']['resumed_ns'] = 1_110_000_001
            elif change == 'after-calls':
                bad['reader_pause']['paused_ns'] = 1_500_000_000
                bad['reader_pause']['resumed_ns'] = 1_800_000_000
            else:
                bad['reader_pause']['resumed_ns'] = bad['observer_stopped_ns'] + 1
            with self.subTest(change=change):
                self.assertFalse(ORACLE['evaluate'](trace, ledger, bad, trace)['pass'])

    def test_short_actual_first_setup_call_unknown_passes_with_sink_parity(self):
        trace, ledger, receipt = short_setup_inputs()
        result = ORACLE['evaluate'](trace, ledger, receipt, trace)
        self.assertTrue(result['pass'], result)
        self.assertEqual((result['calls'], result['mandatory_calls'], result['false_names']), (7, 7, 0))

    def test_reordered_short_setup_cannot_hide_a_named_actual_first_call(self):
        trace, ledger, receipt = short_setup_inputs()
        lines = trace.splitlines()
        lines[0] = lines[0].replace('Unknown executable', '"trace-a"').replace(
            ') C_', ') exe="/owned/trace-a" C_')
        lines[1] = lines[1].replace('"trace-a"', 'Unknown executable').replace(
            ' exe="/owned/trace-a"', '')
        lines[0], lines[1] = lines[1], lines[0]
        reordered = '\n'.join(lines) + '\n'
        result = ORACLE['evaluate'](reordered, ledger, receipt, reordered)
        self.assertFalse(result['pass'], result)
        self.assertEqual((result['calls'], result['mandatory_calls'], result['false_names']), (7, 7, 0))

    def test_same_path_generations_have_independent_positive_populations(self):
        trace, ledger, receipt = exec_inputs()
        result = ORACLE['evaluate'](trace, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertEqual(result.get('image_generation_populations', {}).get(1),
                         dict(named=2, unknown=1))

    def test_same_path_first_successor_call_cannot_use_the_old_receipt(self):
        trace, ledger, receipt = exec_inputs()
        trace = trace.replace('Unknown executable (PID 123, TID 123) C_GetSessionInfo',
                              '"trace-a" (PID 123, TID 123) exe="/owned/trace-a" C_GetSessionInfo')
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_nonleader_claim_requires_a_distinct_actual_exec_tid(self):
        trace, ledger, receipt = exec_inputs('nonleader')
        request = next(x for x in ledger if x['kind'] == 'exec')
        request['tid'] = request['pid']
        receipt['exec_transitions'][0]['request'] = copy.deepcopy(request)
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_exec_request_requires_the_original_owned_birth(self):
        trace, ledger, receipt = exec_inputs()
        request = next(x for x in ledger if x['kind'] == 'exec')
        request['start_time'] += 1
        receipt['exec_transitions'][0]['request'] = copy.deepcopy(request)
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_same_path_generations_with_the_same_event_key_are_ambiguous(self):
        trace, ledger, receipt = inputs()
        successor = dict(ledger[0], image=1, t=125)
        ledger.extend((successor, dict(ledger[1], image=1)))
        receipt['images'].append(copy.deepcopy(successor))
        ledger[5]['image'] = 1
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_same_path_successor_cannot_borrow_predecessor_named_population(self):
        trace, ledger, receipt = inputs()
        successor = dict(ledger[0], image=1, t=125)
        ledger.extend((successor, dict(ledger[1], image=1, fn='C_GetSessionInfo')))
        ledger[5].update(image=1, fn='C_GetSessionInfo')
        receipt['images'].append(copy.deepcopy(successor))
        receipt['require_named_images'] = [0, 1]
        lines = trace.splitlines()
        lines[2] = '12:00:00.000002 Unknown executable (PID 123, TID 123) C_GetSessionInfo → CKR_OK 1.0µs'
        self.assertFalse(ORACLE['evaluate']('\n'.join(lines) + '\n', ledger, receipt)['pass'])

    def test_spaced_calls_must_obey_the_independently_commanded_gap(self):
        trace, ledger, receipt = inputs()
        receipt['cell'] = 'sparse1'
        receipt['phases'] = [dict(image=0, fn='C_GenerateRandom', phase='main', scope='selected',
                                 count=3, gap_ms=1000, t0=105, t1=135)]
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_sparse_boundary_labels_do_not_claim_a_deadline_proof(self):
        trace, ledger, receipt = inputs()
        receipt.update(cell='sparse61', require_named=False)
        result = ORACLE['evaluate'](trace, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertEqual(result.get('deadline_boundary_proof'), 'not_exposed_by_public_output')

    def test_short_lifetime_limit_requires_an_actual_exit_upper_bound(self):
        trace, ledger, receipt = inputs()
        ledger[0]['t'] = receipt['images'][0]['t'] = 105
        receipt['cell'] = 'short'
        receipt['observer_stopped_ns'] = 3_000_000_000
        receipt['short_lifetime'] = dict(image=0, spawn_started_ns=101,
                                        exit_observed_ns=2_000_000_101, limit_seconds=1)
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_short_exit_stamp_cannot_precede_the_last_real_call(self):
        trace, ledger, receipt = inputs()
        ledger[0]['t'] = receipt['images'][0]['t'] = 105
        receipt['cell'] = 'short'
        receipt['short_lifetime'] = dict(image=0, spawn_started_ns=101,
                                        exit_observed_ns=125, limit_seconds=1)
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_short_lifetime_with_independent_actual_exit_passes(self):
        trace, ledger, receipt = inputs()
        ledger[0]['t'] = 105
        receipt['images'][0]['t'] = 105
        receipt.update(cell='short', first_unknown_images=[0])
        receipt['short_lifetime'] = dict(image=0, spawn_started_ns=101,
                                        exit_observed_ns=160, limit_seconds=1)
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_actual_spaced_calls_with_matching_gap_pass(self):
        trace, ledger, receipt = inputs()
        calls = [x for x in ledger if x['kind'] == 'call']
        for index, call in enumerate(calls):
            call.update(t0=110 + index * 1_000_000_005, t1=111 + index * 1_000_000_005)
        receipt['observer_stopped_ns'] = 3_000_000_000
        receipt['phases'] = [dict(image=0, fn='C_GenerateRandom', phase='main', scope='selected',
                                 count=3, gap_ms=1000, t0=105, t1=2_000_000_125)]
        self.assertTrue(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_nonempty_positive_and_unknown_shares_are_separate(self):
        trace, ledger, receipt = inputs()
        result = ORACLE["evaluate"](trace, ledger, receipt, trace)
        self.assertTrue(result["pass"], result)
        self.assertEqual((result["named"], result["unknown"]), (2, 1))

    def test_successor_name_is_rejected(self):
        trace, ledger, receipt = inputs()
        result = ORACLE["evaluate"](trace.replace('/owned/trace-a', '/owned/trace-b'), ledger, receipt)
        self.assertFalse(result["pass"], result)
        self.assertGreater(result["false_names"], 0)

    def test_unknown_only_cannot_pass_a_required_positive(self):
        trace, ledger, receipt = inputs()
        trace = trace.replace('"trace-a"', 'Unknown executable').replace(' exe="/owned/trace-a"', '')
        self.assertFalse(ORACLE["evaluate"](trace, ledger, receipt)["pass"])

    def test_physical_device_mismatch_is_not_hidden_by_equal_inode(self):
        trace, ledger, receipt = inputs()
        ledger[1]["dev"] = [8, 2]
        self.assertFalse(ORACLE["evaluate"](trace, ledger, receipt)["pass"])

    def test_unledgered_setup_call_is_rejected(self):
        trace, ledger, receipt = inputs()
        trace = '12:00:00.000000 "trace-b" (PID 123, TID 123) exe="/owned/trace-b" C_Initialize → CKR_OK 1.0µs\n' + trace
        self.assertFalse(ORACLE["evaluate"](trace, ledger, receipt)["pass"])

    def test_stdout_file_disagreement_fails(self):
        trace, ledger, receipt = inputs()
        self.assertFalse(ORACLE["evaluate"](trace, ledger, receipt, trace.replace('/owned/trace-a', '/other'))["pass"])

    def test_private_canary_in_output_fails(self):
        trace, ledger, receipt = inputs()
        self.assertFalse(ORACLE["evaluate"](trace + 'PRIVATE_N3_SENTINEL\n', ledger, receipt)["pass"])

    def test_independent_executable_receipt_cannot_be_replaced_by_caller_claim(self):
        trace, ledger, receipt = inputs()
        ledger[0]['ino'] += 1
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_other_scheduling_changes_are_not_hidden_by_sink_exception(self):
        trace, ledger, receipt = inputs()
        other = trace.replace('"event_loss":0', '"event_loss":0,"scheduling":{"drain_repolls":1}')
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt, other)['pass'])

    def test_cold_onecall_unknown_is_required_only_with_independent_proof(self):
        trace, ledger, receipt = inputs()
        ledger = ledger[:4]
        trace = trace.splitlines()[0] + '\n' + '\n'.join(trace.splitlines()[3:]) + '\n'
        trace = trace.replace(':3', ':1')
        receipt.update(cell='onecall', require_named=False, fresh_observer=True)
        result = ORACLE['evaluate'](trace, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertTrue(result['cold_receipt_impossible'])
        named = trace.replace('Unknown executable', '"trace-a"').replace(') C_', ') exe="/owned/trace-a" C_')
        self.assertFalse(ORACLE['evaluate'](named, ledger, receipt)['pass'])
        receipt['fresh_observer'] = False
        result = ORACLE['evaluate'](named, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertFalse(result['cold_receipt_impossible'])

    def test_run_setup_prefix_is_ledgered_and_bounded(self):
        trace, ledger, receipt = inputs()
        setup = dict(ledger[-1], fn='C_Initialize', phase='setup', t0=95, t1=96)
        ledger.append(setup)
        ledger.append(dict(ledger[1], fn='C_Initialize'))
        receipt['cell'] = 'run'
        result = ORACLE['evaluate'](trace, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertEqual(result['possible_setup_calls'], 1)
        setup_row = '12:00:00.000000 Unknown executable (PID 123, TID 123) C_Initialize → CKR_OK 1.0µs\n'
        captured = (setup_row + trace).replace(':3', ':4')
        result = ORACLE['evaluate'](captured, ledger, receipt)
        self.assertTrue(result['pass'], result)
        self.assertFalse(ORACLE['evaluate'](setup_row + captured, ledger, receipt)['pass'])

    def test_ambiguous_same_function_across_exec_needs_a_stronger_oracle(self):
        trace, ledger, receipt = inputs()
        successor = dict(ledger[0], image=1, path='/owned/trace-b', ino=4)
        ledger.extend((successor, dict(ledger[1], image=1)))
        receipt['images'].append(copy.deepcopy(successor))
        ledger[5]['image'] = 1
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_each_required_successor_image_needs_a_named_population(self):
        trace, ledger, receipt = inputs()
        successor = dict(ledger[0], image=1, path='/owned/trace-b', ino=4)
        ledger.extend((successor, dict(ledger[1], image=1, fn='C_GetSessionInfo')))
        ledger[5].update(image=1, fn='C_GetSessionInfo')
        receipt['images'].append(copy.deepcopy(successor))
        receipt['require_named_images'] = [0, 1]
        lines = trace.splitlines()
        lines[2] = '12:00:00.000002 Unknown executable (PID 123, TID 123) C_GetSessionInfo → CKR_OK 1.0µs'
        self.assertFalse(ORACLE['evaluate']('\n'.join(lines) + '\n', ledger, receipt)['pass'])

    def test_controller_phase_count_is_not_derived_from_fixture_output(self):
        trace, ledger, receipt = inputs()
        receipt['phases'] = [dict(image=0, fn='C_GenerateRandom', phase='main', scope='selected',
                                 count=4, t0=105, t1=135)]
        self.assertFalse(ORACLE['evaluate'](trace, ledger, receipt)['pass'])

    def test_fresh_first_call_stays_unknown_without_an_earlier_witness(self):
        trace, ledger, receipt = inputs()
        receipt['fresh_observer'] = True
        named = trace.replace('Unknown executable', '"trace-a"').replace(') C_', ') exe="/owned/trace-a" C_')
        self.assertFalse(ORACLE['evaluate'](named, ledger, receipt)['pass'])


if __name__ == "__main__":
    unittest.main()
