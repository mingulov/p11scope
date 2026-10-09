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


class OracleTests(unittest.TestCase):
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
