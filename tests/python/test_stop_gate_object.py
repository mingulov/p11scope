#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Decoded stop-gate mutation tests; objects must be supplied explicitly."""
import argparse
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

C = load_path(ROOT / 'scripts/check-stop-gate-object.py', 'stop_gate_contract')
OBJECTS = []


def change_all(disassembly, suffix, old, new):
    matches = list(re.finditer(r'(?m)^\s*[0-9a-f]+ <([^>]+)>:\s*$', disassembly))
    selected = [(m.end(), matches[i + 1].start() if i + 1 < len(matches) else len(disassembly))
                for i, m in enumerate(matches) if m.group(1) == suffix]
    assert len(selected) == 1, (suffix, selected)
    start, end = selected[0]
    body = disassembly[start:end]
    assert body.count(old) >= 1, (suffix, old)
    mutated = disassembly[:start] + body.replace(old, new) + disassembly[end:]
    assert mutated != disassembly
    assert len(mutated.splitlines()) == len(disassembly.splitlines())
    return mutated


def decoded_text(analysis, pc):
    return dict(analysis.consumer.insns)[pc]


def replace_decoded(disassembly, suffix, pc, old, new):
    """Replace one decoded instruction, keeping its raw bytes and address."""
    matches = list(re.finditer(r'(?m)^\s*[0-9a-f]+ <([^>]+)>:\s*$', disassembly))
    selected = [(m.end(), matches[i + 1].start() if i + 1 < len(matches) else len(disassembly))
                for i, m in enumerate(matches) if m.group(1) == suffix]
    assert len(selected) == 1, (suffix, selected)
    start, end = selected[0]
    lines = disassembly[start:end].splitlines(keepends=True)
    indices = [i for i, line in enumerate(lines) if C.D.line_pc(line) == pc]
    assert len(indices) == 1, (suffix, pc)
    index = indices[0]
    assert lines[index].count(old) == 1, (suffix, pc, old)
    lines[index] = lines[index].replace(old, new)
    mutated = disassembly[:start] + ''.join(lines) + disassembly[end:]
    assert mutated != disassembly
    return mutated


class StopGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OBJECTS:
            raise RuntimeError('explicit objects are required: --object with --variant, '
                               'or --default-object with --unsafe-object')
        cls.objects = [(variant, C.disassemble(path)) for variant, path in OBJECTS]

    def analyses(self, disassembly, variant):
        return {
            name: analysis.classify()
            for name, analysis in C.analyze(disassembly, variant).items()
        }

    def reject(self, disassembly, variant, reason):
        with self.assertRaisesRegex(RuntimeError, re.escape(reason)):
            C.check_decoded(disassembly, variant)

    def test_untouched_objects(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                report = C.check_decoded(disassembly, variant)
                for name, program in sorted(report['programs'].items()):
                    print(f"verified {variant} {name}: {program['instructions']} instructions, "
                          f"role={program['role']}, cas={program['cas']}, "
                          f"inc={program['inc']}, dec={program['dec']}")

    def test_missing_relocation(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                bad = change_all(disassembly, 'p11_entry',
                                 'R_BPF_64_64\tSTOP_GATE', 'R_BPF_64_64\tEVIDENCE')
                self.reject(bad, variant, 'p11_entry: missing STOP_GATE relocation')
                print(f'verified {variant} relocation missing')

    def test_cas_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertGreaterEqual(len(entry.cas_sites), 1)
                bad = disassembly
                for pc in sorted(entry.cas_sites):
                    bad = replace_decoded(bad, 'p11_entry', pc, decoded_text(entry, pc), 'r0 = 0x0')
                self.reject(bad, variant, 'capture-map access before the gate CAS read')
                print(f'verified {variant} cas-removed')

    def test_increment_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.inc_sites), 1)
                (pc,) = sorted(entry.inc_sites)
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      decoded_text(entry, pc), 'r0 = r0')
                self.reject(bad, variant, 'capture-map access outside admission')
                print(f'verified {variant} increment-removed')

    def test_decrement_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                # LLVM shares one release epilogue between the enter
                # second-read-failure path and the guarded-body release.
                self.assertEqual(len(entry.dec_sites), 1)
                (pc,) = sorted(entry.dec_sites)
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      decoded_text(entry, pc), 'r0 = r0')
                self.reject(bad, variant, 'exit without a balancing decrement')
                print(f'verified {variant} decrement-removed')

    def test_fetch_form_rejected(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.dec_sites), 1)
                (pc,) = sorted(entry.dec_sites)
                raw = entry.raw[pc]
                self.assertGreaterEqual(len(raw), 8)
                fetched = raw[0:4] + bytes([raw[4] | 0x01]) + raw[5:8]
                old = ' '.join(f'{byte:02x}' for byte in raw[:8])
                new = ' '.join(f'{byte:02x}' for byte in fetched)
                self.assertNotEqual(old, new)
                bad = replace_decoded(disassembly, 'p11_entry', pc, old, new)
                self.reject(bad, variant, 'gate atomic raw encoding differs')
                print(f'verified {variant} fetch-form')

    def test_return_decrement_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                program = self.analyses(disassembly, variant)['p11_return']
                self.assertEqual(len(program.dec_sites), 1)
                (pc,) = sorted(program.dec_sites)
                bad = replace_decoded(disassembly, 'p11_return', pc,
                                      decoded_text(program, pc), 'r0 = r0')
                self.reject(bad, variant, 'exit without a balancing decrement')
                print(f'verified {variant} return-decrement-removed')

    def unsafe_only(self, variant):
        if variant != 'unsafe':
            self.skipTest('template continuation exists only in the unsafe object')

    def test_pair_tail_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                self.unsafe_only(variant)
                pair = self.analyses(disassembly, variant)['p11_entry_template_pair']
                self.assertEqual(len(pair.tail_sites), 1)
                (pc,) = sorted(pair.tail_sites)
                bad = replace_decoded(disassembly, 'p11_entry_template_pair', pc,
                                      decoded_text(pair, pc), 'r0 = r0')
                self.reject(bad, variant, 'carrying program lost its tail call')
                print(f'verified {variant} pair-tail-removed')

    def test_pair_leave_before_tail(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                self.unsafe_only(variant)
                pair = self.analyses(disassembly, variant)['p11_entry_template_pair']
                self.assertEqual(len(pair.inc_sites), 1)
                (pc,) = sorted(pair.inc_sites)
                definition, old, new = self.flip_delta(pair, pc, -1)
                bad = replace_decoded(disassembly, 'p11_entry_template_pair',
                                      definition, old, new)
                self.reject(bad, variant, 'decrement before the tail call')
                print(f'verified {variant} pair-leave-before-tail')

    def test_continuation_decrement_removed(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                self.unsafe_only(variant)
                program = self.analyses(disassembly, variant)['p11_entry_template_second']
                self.assertEqual(len(program.dec_sites), 1)
                (pc,) = sorted(program.dec_sites)
                bad = replace_decoded(disassembly, 'p11_entry_template_second', pc,
                                      decoded_text(program, pc), 'r0 = r0')
                self.reject(bad, variant, 'exit without a balancing decrement')
                print(f'verified {variant} continuation-decrement-removed')

    def test_continuation_recheck(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                self.unsafe_only(variant)
                program = self.analyses(disassembly, variant)['p11_entry_template_second']
                self.assertEqual(len(program.dec_sites), 1)
                (pc,) = sorted(program.dec_sites)
                definition, old, new = self.flip_delta(program, pc, 1)
                bad = replace_decoded(disassembly, 'p11_entry_template_second',
                                      definition, old, new)
                self.reject(bad, variant, 'continuation re-checks the gate')
                print(f'verified {variant} continuation-recheck')

    @staticmethod
    def gate_null_branch(analysis, pc, text):
        """The tested register if this branch null-checks the gate cell."""
        match = C.GATE_NULL_EQ.fullmatch(text) or C.GATE_NULL_NE.fullmatch(text)
        if match is None:
            return None
        return match.group(1) if analysis.is_gate_cell(pc, match.group(1)) else None

    def test_leave_guard_inventory(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                analyses = self.analyses(disassembly, variant)
                nongate_found = False
                for name, entry in sorted(analyses.items()):
                    with self.subTest(program=name):
                        guards = entry.leave_guards
                        self.assertEqual(len(guards), 1, (name, sorted(guards)))
                        (guard, null_edge) = next(iter(guards.items()))
                        text = decoded_text(entry, guard)
                        match = C.GATE_NULL_EQ.fullmatch(text) or C.GATE_NULL_NE.fullmatch(text)
                        self.assertIsNotNone(match, (name, guard, text))
                        target = guard + 1 + int(match.group(2), 16)
                        sibling = guard + 1 if '==' in text else target
                        if '==' in text:
                            self.assertEqual(null_edge, target)
                        else:
                            self.assertEqual(null_edge, guard + 1)
                        # The sibling path still holds the decrement: walk at
                        # most two straight-line steps to a classified dec.
                        current, steps, found = sibling, 0, None
                        while steps <= 2:
                            if current in entry.dec_sites:
                                found = current
                                break
                            successors = entry.consumer.graph.get(current, ())
                            if len(successors) != 1:
                                break
                            current, steps = successors[0], steps + 1
                        self.assertIsNotNone(found, (name, guard, text))
                        # Every other gate-cell null check (enter's) is not a
                        # guard, and no non-gate null check is either.
                        others = [pc for pc, candidate in entry.consumer.insns
                                  if pc != guard
                                  and self.gate_null_branch(entry, pc, candidate) is not None]
                        if entry.role in (C.ENTER, C.CARRY):
                            self.assertEqual(len(others), 1, (name, others))
                        else:
                            self.assertEqual(others, [], (name, others))
                        for pc, candidate in entry.consumer.insns:
                            branch = (C.GATE_NULL_EQ.fullmatch(candidate)
                                      or C.GATE_NULL_NE.fullmatch(candidate))
                            if branch is not None and self.gate_null_branch(
                                    entry, pc, candidate) is None:
                                nongate_found = True
                                self.assertNotIn(pc, guards, (name, pc, candidate))
                self.assertTrue(nongate_found, variant)
                print(f'verified {variant} leave-guard-inventory')

    def test_leave_guard_shape_b_dissolution(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                program = self.analyses(disassembly, variant)['sched_process_exec']
                self.assertEqual(len(program.dec_sites), 1)
                (pc,) = sorted(program.dec_sites)
                bad = replace_decoded(disassembly, 'sched_process_exec', pc,
                                      decoded_text(program, pc), 'r0 = r0')
                self.reject(bad, variant, 'exit without a balancing decrement')
                print(f'verified {variant} shape-b-dissolution')

    def test_leave_guard_direction_flip_rejected(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.leave_guards), 1)
                (pc,) = sorted(entry.leave_guards)
                old = decoded_text(entry, pc)
                self.assertIn('== 0x0', old)
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      old, old.replace('==', '!='))
                self.reject(bad, variant, 'exit without a balancing decrement')
                print(f'verified {variant} guard-direction-flip')

    def test_capture_after_null_skip_rejected(self):
        # The leave-tail worker has no enter/deny path, so a capture made
        # reachable from the null edge arrives excused: the balance walk
        # must fail it. (On p11_entry the same mutant trips
        # the earlier CAS-before-capture clause via the deny path instead,
        # so the worker isolates the excused-capture clause.)
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                worker = self.analyses(disassembly, variant)['interface_list_worker']
                self.assertEqual(len(worker.leave_guards), 1)
                (guard,) = sorted(worker.leave_guards)
                null_target = worker.leave_guards[guard]
                old = decoded_text(worker, null_target)
                self.assertNotIn('goto', old)
                natives = [pc for pc in worker.capture_sites
                           if worker.consumer.calls.get(pc, '').startswith('p11_')
                           and pc < guard]
                self.assertTrue(natives, (variant, guard))
                capture = max(natives)
                offset = (null_target + 1) - capture
                self.assertGreater(offset, 0)
                bad = replace_decoded(disassembly, 'interface_list_worker', null_target,
                                      old, f'goto -0x{offset:x}')
                self.reject(bad, variant, 'capture-map access outside admission')
                print(f'verified {variant} capture-after-null-skip')

    def test_cas_operand_nonzero(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertGreaterEqual(len(entry.cas_sites), 1)
                (pc,) = sorted(entry.cas_sites)[:1]
                definition, register, old = self.zero_operand_def(entry, pc)
                bad = replace_decoded(disassembly, 'p11_entry', definition,
                                      old, f'{register} = 0x1')
                self.reject(bad, variant, 'gate read CAS operand is nonzero')
                print(f'verified {variant} cas-operand-nonzero')

    def test_cas_operand_unknown(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertGreaterEqual(len(entry.cas_sites), 1)
                (pc,) = sorted(entry.cas_sites)[:1]
                definition, register, old = self.zero_operand_def(entry, pc)
                scratch = self.unknown_scratch(entry, definition, register)
                bad = replace_decoded(disassembly, 'p11_entry', definition,
                                      old, f'{register} = {scratch}')
                self.reject(bad, variant, 'gate read CAS operand is not a known constant')
                print(f'verified {variant} cas-operand-unknown')

    def test_delta_non_unit(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.inc_sites), 1)
                (pc,) = sorted(entry.inc_sites)
                text = decoded_text(entry, pc)
                match = C.GATE_ADD.fullmatch(text)
                assert match, text
                register = match.group(5)
                assert register.startswith('r'), text
                definitions = [at for at, candidate in entry.consumer.insns
                               if at < pc and candidate == f'{register} = 0x1']
                assert definitions, (entry.name, pc, text)
                definition = max(definitions)
                bad = replace_decoded(disassembly, 'p11_entry', definition,
                                      f'{register} = 0x1', f'{register} = 0x2')
                self.reject(bad, variant, 'gate delta is not +1/-1')
                print(f'verified {variant} delta-non-unit')

    def test_delta_unknown(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.inc_sites), 1)
                (pc,) = sorted(entry.inc_sites)
                text = decoded_text(entry, pc)
                match = C.GATE_ADD.fullmatch(text)
                assert match, text
                register = match.group(5)
                assert register.startswith('r'), text
                definitions = [at for at, candidate in entry.consumer.insns
                               if at < pc and candidate == f'{register} = 0x1']
                assert definitions, (entry.name, pc, text)
                definition = max(definitions)
                scratch = self.unknown_scratch(entry, definition, register)
                bad = replace_decoded(disassembly, 'p11_entry', definition,
                                      f'{register} = 0x1', f'{register} = {scratch}')
                self.reject(bad, variant, 'gate delta is not a known constant')
                print(f'verified {variant} delta-unknown')

    def test_cas_width_32(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertGreaterEqual(len(entry.cas_sites), 1)
                (pc,) = sorted(entry.cas_sites)[:1]
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      'cmpxchg_64', 'cmpxchg_32')
                self.reject(bad, variant, 'unrecognized gate compare-exchange')
                print(f'verified {variant} cas-width-32')

    def test_cas_offset_nonzero(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertGreaterEqual(len(entry.cas_sites), 1)
                (pc,) = sorted(entry.cas_sites)[:1]
                text = decoded_text(entry, pc)
                match = C.GATE_CAS.fullmatch(text)
                assert match, text
                _, _, base, sign, offset, _, _ = match.groups()
                old = f'(r{base} {sign} 0x{offset},'
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      old, f'(r{base} {sign} 0x8,')
                self.reject(bad, variant, 'unrecognized gate compare-exchange')
                print(f'verified {variant} cas-offset-nonzero')

    def test_add_width_32(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.inc_sites), 1)
                (pc,) = sorted(entry.inc_sites)
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      '*(u64 *)', '*(u32 *)')
                self.reject(bad, variant, 'unrecognized gate add')
                print(f'verified {variant} add-width-32')

    def test_add_offset_nonzero(self):
        for variant, disassembly in self.objects:
            with self.subTest(variant=variant):
                entry = self.analyses(disassembly, variant)['p11_entry']
                self.assertEqual(len(entry.dec_sites), 1)
                (pc,) = sorted(entry.dec_sites)
                text = decoded_text(entry, pc)
                match = C.GATE_ADD.fullmatch(text)
                assert match, text
                _, base, sign, offset, _ = match.groups()
                old = f'(r{base} {sign} 0x{offset})'
                bad = replace_decoded(disassembly, 'p11_entry', pc,
                                      old, f'(r{base} {sign} 0x8)')
                self.reject(bad, variant, 'unrecognized gate add')
                print(f'verified {variant} add-offset-nonzero')

    @staticmethod
    def zero_operand_def(analysis, pc):
        """Locate the reaching `rN = 0x0` definition of a CAS zero operand.

        Returns the definition pc, register, and old decoded text. The
        operand must be callee-saved (calls between the definition and the
        CAS preserve it) with no redefinition in between.
        """
        text = decoded_text(analysis, pc)
        match = C.GATE_CAS.fullmatch(text)
        assert match, text
        for operand in (match.group(6), match.group(7)):
            if int(operand) < 6:
                continue
            register = 'r' + operand
            definitions = [at for at, candidate in analysis.consumer.insns
                           if at < pc and candidate == f'{register} = 0x0']
            if not definitions:
                continue
            definition = max(definitions)
            shadowed = re.compile(rf'[rw]{operand} = .*')
            for at, candidate in analysis.consumer.insns:
                if definition < at < pc:
                    assert not shadowed.fullmatch(candidate), (at, candidate)
            return definition, register, f'{register} = 0x0'
        raise AssertionError((analysis.name, pc, text))

    @staticmethod
    def unknown_scratch(analysis, definition, target):
        """Pick a callee-saved register with no fact at the definition."""
        state = analysis.facts.get(definition, {})
        for operand in ('6', '7', '8', '9'):
            scratch = 'r' + operand
            if scratch != target and scratch not in state:
                return scratch
        raise AssertionError((analysis.name, definition, sorted(state)))

    @staticmethod
    def flip_delta(analysis, pc, sign):
        """Flip a register-form gate add by rewriting its reaching definition.

        Returns the definition pc plus the old/new decoded texts. The raw
        bytes stay valid: the register form carries the operation, not the
        delta, in the immediate field.
        """
        text = decoded_text(analysis, pc)
        match = C.GATE_ADD.fullmatch(text)
        assert match, text
        register = match.group(5)
        assert register.startswith('r'), text
        raw = analysis.raw[pc]
        assert len(raw) >= 8 and raw[0] == 0xDB and int.from_bytes(raw[4:8], 'little') == 0
        old_value, new_value = ('0x1', '-0x1') if sign < 0 else ('-0x1', '0x1')
        definitions = [at for at, candidate in analysis.consumer.insns
                       if at < pc and candidate == f'{register} = {old_value}']
        assert definitions, (analysis.name, pc, text)
        definition = max(definitions)
        shadowed = re.compile(rf'[rw]{register[1:]} = .*')
        for at, candidate in analysis.consumer.insns:
            if definition < at < pc:
                assert not shadowed.fullmatch(candidate), (at, candidate)
        return definition, f'{register} = {old_value}', f'{register} = {new_value}'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--object', type=Path, help='test the current Cargo build object')
    parser.add_argument('--variant', choices=('default', 'unsafe'))
    parser.add_argument('--default-object', type=Path)
    parser.add_argument('--unsafe-object', type=Path)
    parser.add_argument('--disable-contract', action='store_true', help='test-only acceptance control; negative tests must fail')
    args, rest = parser.parse_known_args()
    usage = 'use --object with --variant, or both --default-object and --unsafe-object'
    if args.object is not None or args.variant is not None:
        if (args.object is None or args.variant is None
                or args.default_object is not None or args.unsafe_object is not None):
            parser.error(usage)
        OBJECTS = [(args.variant, args.object)]
    else:
        if args.default_object is None or args.unsafe_object is None:
            parser.error(usage)
        OBJECTS = [('default', args.default_object), ('unsafe', args.unsafe_object)]
    if args.disable_contract:
        C.check_decoded = lambda *_: {'disabled': True}
    unittest.main(argv=[sys.argv[0], *rest])
