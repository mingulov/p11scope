# SPDX-License-Identifier: GPL-3.0-or-later
"""The trace oracle must reject false names and unknown-only positive cells."""

import copy
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


class OracleTests(unittest.TestCase):
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
