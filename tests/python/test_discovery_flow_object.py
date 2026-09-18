#!/usr/bin/env python3
"""Decoded production-object mutation tests; objects must be supplied explicitly."""
import argparse
import copy
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

C = load_path(ROOT / 'scripts/check-discovery-flow-object.py', 'flow_contract')
OBJECTS = []


def instruction_site(lines, sequence, offset=0):
    """Select one instruction by a short, function-local decoded neighborhood."""
    insns = C.D.instructions(lines)
    starts = [i for i in range(len(insns) - len(sequence) + 1)
              if tuple(op for _, op in insns[i:i + len(sequence)]) == sequence]
    assert len(starts) == 1, (sequence, starts)
    return insns[starts[0] + offset]


def early_class_site(lines, offset=0):
    return instruction_site(lines, ('r9 = 0x40000', 'r5 = 0x0', 'r6 = 0x0'), offset)


def instruction_change(lines, instruction, new):
    pc, old = instruction
    raw = [line for line in lines if C.D.line_pc(line) == pc]
    assert len(raw) == 1, (pc, raw)
    assert raw[0].count(old) == 1, (pc, old)
    return raw[0], raw[0].replace(old, new)


def change_function(disassembly, suffix, old, new):
    matches = list(re.finditer(r'(?m)^\s*[0-9a-f]+ <([^>]+)>:\s*$', disassembly))
    selected = [(m.end(), matches[i + 1].start() if i + 1 < len(matches) else len(disassembly))
                for i, m in enumerate(matches) if m.group(1).endswith(suffix)]
    assert len(selected) == 1, (suffix, selected)
    start, end = selected[0]
    body = disassembly[start:end]
    assert body.count(old) == 1, (suffix, old, body.count(old))
    mutated = disassembly[:start] + body.replace(old, new) + disassembly[end:]
    assert mutated != disassembly
    assert len(mutated.splitlines()) == len(disassembly.splitlines())
    assert sum(a != b for a, b in zip(mutated.splitlines(), disassembly.splitlines())) == 1
    return mutated


class DiscoveryFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OBJECTS:
            raise RuntimeError('explicit --default-object and --unsafe-object are required')
        cls.objects = [(v, *C.load_object(p)) for v, p in OBJECTS]

    def reject(self, elf, disassembly, contract, reason):
        with self.assertRaisesRegex(RuntimeError, re.escape(contract + ':' + reason)):
            C.check_decoded(elf, disassembly, contract)

    def reject_and_restore(self, elf, disassembly, function, old, new, contract, reason):
        bad = change_function(disassembly, function, old, new)
        self.reject(elf, bad, contract, reason)
        (original, changed), = [(a, b) for a, b in zip(disassembly.splitlines(), bad.splitlines()) if a != b]
        restored = change_function(bad, function, changed, original)
        self.assertEqual(restored, disassembly)
        self.assertTrue(C.check_decoded(elf, restored, contract))

    def test_untouched_objects(self):
        for variant, elf, disassembly in self.objects:
            for contract in ('typed-birth', 'interface-name', 'all'):
                with self.subTest(variant=variant, contract=contract):
                    self.assertTrue(C.check_decoded(elf, disassembly, contract))

    def test_typed_section_metadata(self):
        for variant, elf, disassembly in self.objects:
            for mutation in ('removed', 'renamed', 'nonexec', 'legacy', 'undefined'):
                with self.subTest(variant=variant, mutation=mutation):
                    bad = copy.deepcopy(elf)
                    name = 'tp_btf/task_newtask'
                    if mutation == 'removed':
                        del bad.sections[name]
                    elif mutation == 'renamed':
                        bad.sections['tp_btf/not_task_newtask'] = bad.sections.pop(name)
                    elif mutation == 'nonexec':
                        row, body = bad.sections[name]
                        row = list(row); row[2] &= ~4
                        bad.sections[name] = (tuple(row), body)
                    elif mutation == 'legacy':
                        bad.sections['tracepoint/task/task_newtask'] = bad.sections[name]
                    else:
                        bad.symbols = [(*s[:3], 0, *s[4:]) if s[0] == 'task_newtask' else s for s in bad.symbols]
                    self.reject(bad, disassembly, 'typed-birth', 'section')
                    print(f'verified {variant} typed-birth:section {mutation}')

    def test_typed_mutations(self):
        cases = [
            ('redirect-propagation', 'task_newtask', '@propagation-call', 'call 0x0', 'link'),
            ('parent-null', 'p11_link_emit_fork', 'if r3 == 0x0 goto', 'if r3 != 0x0 goto', 'classification'),
            ('child-null', 'p11_link_emit_fork', 'if r4 == 0x0 goto', 'if r4 != 0x0 goto', 'classification'),
            ('context-child-width', 'task_newtask', 'r7 = *(u64 *)(r1 + 0x0)', 'r7 = *(u32 *)(r1 + 0x0)', 'context'),
            ('context-flags-width', 'task_newtask', 'r6 = *(u64 *)(r1 + 0x8)', 'r6 = *(u32 *)(r1 + 0x8)', 'context'),
            ('flags-restore', 'task_newtask', '@flags-restore', 'w2 = w6', 'flags'),
            ('redirect-allowed', 'task_newtask', 'R_BPF_64_32\tp11_link_fork_allowed', 'R_BPF_64_32\tp11_link_emit_fork', 'link'),
            ('omit-emit', 'task_newtask', 'R_BPF_64_32\tp11_link_emit_fork', 'R_BPF_64_32\tmissing_bridge', 'link'),
            ('scope-bypass', 'task_newtask', 'if r0 == 0x0 goto +0x21', 'if r0 == 0x1 goto +0x21', 'scope'),
            ('scope-result', 'p11_link_fork_allowed', 'if r1 != 0x1 goto', 'if r1 == 0x1 goto', 'scope'),
            ('cgroup-bypass', 'p11_link_fork_allowed', 'r2 &= 0x2', 'r2 &= 0x0', 'scope'),
            ('aggregate-bypass', 'p11_link_fork_allowed', 'r1 &= 0x10', 'r1 &= 0x0', 'scope'),
            ('thread-bypass', 'p11_link_emit_fork', 'r5 &= 0x10000', 'r5 &= 0x0', 'classification'),
            ('child-zero', 'p11_link_emit_fork', 'if r2 == 0x0 goto -0xc', 'if r2 != 0x0 goto -0xc', 'classification'),
            ('parent-identity', 'p11_link_emit_fork', 'if r9 == 0x0 goto', 'if r9 != 0x0 goto', 'classification'),
            ('child-identity', 'p11_link_emit_fork', 'if r6 != 0x0 goto', 'if r6 == 0x0 goto', 'classification'),
            ('reserve-too-early', 'p11_link_emit_fork', '\tr5 = r2', '\tcall 0x83', 'classification'),
        ]
        self.mutations(cases, 'typed-birth')

    def test_name_mutations(self):
        cases = [
            ('exact-wrong-bits', 'classify_direct_interface', 'r9 = 0x10000', 'r9 = 0x100', 'classification'),
            ('length-nine', 'classify_direct_interface', '\tr2 = 0x9', '\tr2 = 0x8', 'read'),
            ('result-eight', 'classify_direct_interface', 'if r0 != 0x8 goto', 'if r0 != 0x7 goto', 'classification'),
            ('byte-constant', 'classify_direct_interface', '0x31312053434b50 ll', '0x31312053434b51 ll', 'classification'),
            ('nul-constant', 'classify_direct_interface', '0x31312053434b50 ll', '0x131312053434b50 ll', 'classification'),
            ('wrong-destination', 'classify_direct_interface', '@name-read-destination', 'r1 = r8', 'read'),
            ('wrong-source', 'classify_direct_interface', '\tr3 = *(u64 *)(r10 - 0x48)', '\tr3 = *(u64 *)(r10 - 0x50)', 'read'),
            ('wrong-readback', 'classify_direct_interface', '\tr1 = *(u64 *)(r10 - 0x40)', '\tr1 = *(u64 *)(r10 - 0x38)', 'classification'),
            ('inverted-length', 'classify_direct_interface', 'if r0 != 0x8 goto', 'if r0 == 0x8 goto', 'classification'),
            ('inverted-bytes', 'classify_direct_interface', 'if r1 != r2 goto', 'if r1 == r2 goto', 'classification'),
            ('unconditional-exact', 'classify_direct_interface', 'if r1 != r2 goto +0x1', 'goto +0x0', 'classification'),
            ('negative-as-other', 'classify_direct_interface', 'if r1 s> r0 goto', 'if r1 s< r0 goto', 'classification'),
            ('null-as-exact', 'classify_direct_interface', 'r9 = 0x30000', 'r9 = 0x10000', 'null'),
            ('other-as-exact', 'classify_direct_interface', 'r9 = 0x20000', 'r9 = 0x10000', 'classification'),
            ('wrong-class-field', 'classify_direct_interface', '*(u64 *)(r10 - 0x40) = r9', '*(u64 *)(r10 - 0x38) = r9', 'metadata'),
            ('metadata-width', 'classify_direct_interface', '@metadata-u32-store', '*(u64 *)(r10 - 0x8) = r1', 'metadata'),
            ('metadata-destination', 'classify_direct_interface', '@metadata-u32-store', '*(u32 *)(r10 - 0x10) = r1', 'metadata'),
            ('metadata-source', 'classify_direct_interface', '@metadata-u32-store', '*(u32 *)(r10 - 0x8) = r2', 'metadata'),
            ('dead-class', 'classify_direct_interface', 'r9 |= r8', 'r9 = r8', 'metadata'),
            ('old-class-retained', 'classify_direct_interface', '0xffffff0000ffff ll', '0xffffffffffffffff ll', 'metadata'),
        ]
        self.mutations(cases, 'interface-name')

    def test_all_payload_predecessors(self):
        # Single decoded instructions, including the independent BN-R1 control.
        cases = [
            ('BN-R1-early-w9-exact', 'early-class', 'w9 = 0x10000'),
            ('early-copy', 'early-class', 'r9 = r1'),
            ('early-alias-copy', 'early-class', 'w9 = w1'),
            ('early-arithmetic', 'early-class', 'r9 += 0x10000'),
            ('early-bitwise', 'early-class', 'w9 |= 0x10000'),
            ('early-unknown-load', 'early-class', 'w9 = *(u32 *)(r10 - 0x40)'),
            ('early-wrong-finite-class', 'early-class', 'w9 = 0x20000'),
            ('later-clobber', 'early-r5', 'w9 = 0x10000'),
            ('later-unconditional-exact', 'early-r6', 'r9 = 0x10000'),
            ('flag-class-contamination', 'flag-init', 'r2 = 0x10000'),
            ('flag-slot-clobber', 'early-r5', '*(u64 *)(r10 - 0x48) = r8'),
            ('unknown-atomic-flag-write', 'early-r5', 'r0 = cmpxchg_64(r10 - 0x48, r0, r8)'),
            ('unknown-lock-flag-write', 'early-r5', 'lock *(u64 *)(r10 - 0x48) += r8'),
            ('builder-bypass', 'early-null', None),
        ]
        for variant, elf, disassembly in self.objects:
            _, lines = C.function(C.sections(disassembly)['.text'], 'classify_direct_interface', 'fixture')
            sites = {name: early_class_site(lines, offset) for offset, name in enumerate(
                ('early-class', 'early-r5', 'early-r6', 'early-null'))}
            sites['flag-init'] = instruction_site(lines, ('r2 = 0x1000000', '*(u64 *)(r10 - 0x50) = r2'))
            branch_pc, branch = sites['early-null']
            self.assertTrue(branch.startswith('if r3 == 0x0 goto '))
            insns = C.D.instructions(lines)
            builder = instruction_site(lines, ('r1 = 0xffffff0000ffff ll', 'r8 &= r1'))
            self.assertEqual(C.D.relative_target(branch_pc, branch), builder[0])
            # Enter at the next decoded instruction, skipping the mask initializer.
            target = insns[insns.index(builder) + 1][0]
            bypass = f'if r3 == 0x0 goto {target - branch_pc - 1:+#x}'
            for label, site, new in cases:
                with self.subTest(variant=variant, mutation=label):
                    old, new = instruction_change(lines, sites[site], bypass if new is None else new)
                    self.reject_and_restore(elf, disassembly, 'classify_direct_interface', old, new,
                                            'interface-name', 'provenance')
                    print(f'verified {variant} interface-name:provenance {label}')

    def test_equivalent_class_alias(self):
        for variant, elf, disassembly in self.objects:
            _, lines = C.function(C.sections(disassembly)['.text'], 'classify_direct_interface', 'fixture')
            old, new = instruction_change(lines, early_class_site(lines), 'w9 = 0x40000')
            bad = change_function(disassembly, 'classify_direct_interface', old, new)
            with self.subTest(variant=variant):
                self.assertTrue(C.check_decoded(elf, bad, 'interface-name'))
                restored = change_function(bad, 'classify_direct_interface', new, old)
                self.assertEqual(restored, disassembly)
                self.assertTrue(C.check_decoded(elf, restored, 'interface-name'))

    def mutations(self, cases, contract):
        for variant, elf, disassembly in self.objects:
            for label, function, old, new, reason in cases:
                with self.subTest(variant=variant, mutation=label):
                    if old == '@propagation-call':
                        secs = C.sections(disassembly)
                        links = C.D.internal_call_targets(secs['tp_btf/task_newtask'] + secs['.text'])
                        targets = [c for c in links if c[0] == 'task_newtask' and c[3] == 'p11_root_propagate_thread']
                        self.assertEqual(len(targets), 1)
                        hook = C.D.function_blocks(secs['tp_btf/task_newtask'])['task_newtask']
                        old = dict(C.D.instructions(hook))[targets[0][2]]
                    elif old == '@flags-restore':
                        secs = C.sections(disassembly)
                        links = C.D.internal_call_targets(secs['tp_btf/task_newtask'] + secs['.text'])
                        targets = [c for c in links if c[0] == 'task_newtask' and c[3] == 'p11_link_emit_fork']
                        self.assertEqual(len(targets), 1)
                        _, lines = C.function(secs['tp_btf/task_newtask'], function, 'fixture')
                        insns = C.D.instructions(lines)
                        call_index = [i for i, (pc, _) in enumerate(insns) if pc == targets[0][2]]
                        self.assertEqual(len(call_index), 1)
                        self.assertGreater(call_index[0], 0)
                        site = insns[call_index[0] - 1]
                        self.assertEqual(site[1], 'r2 = r6')
                        old, new = instruction_change(lines, site, new)
                    elif old == '@name-read-destination':
                        _, lines = C.function(C.sections(disassembly)['.text'], function, 'fixture')
                        site = instruction_site(lines, ('r1 = r9', 'r2 = 0x9',
                                                       'r3 = *(u64 *)(r10 - 0x48)', 'call 0x72'))
                        old, new = instruction_change(lines, site, new)
                    elif old == '@metadata-u32-store':
                        _, lines = C.function(C.sections(disassembly)['.text'], function, 'fixture')
                        matches = [(pc, text) for pc, text in C.D.instructions(lines)
                                   if re.fullmatch(r'\*\(u32 \*\)\(r10 - 0x8\) = [rw]1', text)]
                        self.assertEqual(len(matches), 1)
                        mutation = re.sub(r' = r1$', ' = ' + matches[0][1].rsplit(' = ', 1)[1], new)
                        old, new = instruction_change(lines, matches[0], mutation)
                    self.reject_and_restore(elf, disassembly, function, old, new, contract, reason)
                    print(f'verified {variant} {contract}:{reason} {label}')


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
