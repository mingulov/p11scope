#!/usr/bin/env python3
"""Conservative compiled birth/name wiring contracts, without loading BPF.

Reuse the frozen ELF/LLVM decoder and finite CFG helpers. Small instruction
recipes describe the current compiler's guard/dataflow lowering; they deliberately
fail closed on a new lowering, rather than approximating a BPF interpreter.
Recipes bind branch labels to decoded instruction positions, never absolute PCs.
Native birth_hook_tests.c remains the oracle for C identity/refusal semantics.
The name contract ends at ExportPayload.record_meta passed to real emit_export;
downstream ring-byte propagation and consumer privacy are separate obligations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_sibling

DECODER_SHA256 = '73994dec1ea7a025f5114b3d1186bc8813e358822702b613ff2cce0155766db0'
_decoder = Path(__file__).with_name('check-live-discovery-object.py')
if hashlib.sha256(_decoder.read_bytes()).hexdigest() != DECODER_SHA256:
    raise RuntimeError('discovery decoder source hash changed; review required')
D = load_sibling('check-live-discovery-object.py')
SCHEMA = 'p11scope-discovery-flow-object/v1'


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def load_object(path):
    elf = D.map_checker()['Elf'](Path(path).read_bytes())
    result = subprocess.run(['llvm-objdump', '-dr', '--print-imm-hex', str(path)],
                            capture_output=True, text=True, check=True)
    return elf, result.stdout


def sections(disassembly):
    # LLVM prints CO-RE annotation addresses in hex; digit-only addresses must
    # not enter the decoder's decimal instruction-PC graph.
    disassembly = '\n'.join(line for line in disassembly.splitlines() if ':  CO-RE ' not in line)
    parts = re.split(r'(?m)^Disassembly of section ([^:]+):\s*$', disassembly)
    require(len(set(parts[1::2])) == len(parts[1::2]), 'duplicate decoded section')
    return dict(zip(parts[1::2], parts[2::2]))


def function(text, suffix, reason):
    matches = [(n, lines) for n, lines in D.function_blocks(text).items() if n.endswith(suffix)]
    require(len(matches) == 1, reason + ': function missing/ambiguous ' + suffix)
    return matches[0]


def defined(elf, name, section, reason):
    symbols = [s for s in elf.symbols if s[0] == name]
    require(len(symbols) == 1 and section in elf.sections, reason + ': missing symbol ' + name)
    _, info, _, index, value, size = symbols[0]
    row, body = elf.sections[section]
    require(info & 15 == 2 and index == elf.indices[section] and row[1] == 1
            and row[2] & 4 and size > 0 and value % 8 == 0 and size % 8 == 0
            and value + size <= len(body), reason + ': nonexecutable/undefined ' + name)


def recipe(insns, source, reason, calls=()):
    """Match one contiguous lowering and its local branch targets, not PCs."""
    expected, labels = [], {}
    for text in source.strip().splitlines():
        text = text.strip()
        if text.endswith(':'):
            labels[text[:-1]] = len(expected)
        else:
            expected.append(text)
    matches = []
    for begin in range(len(insns) - len(expected) + 1):
        region = insns[begin:begin + len(expected)]
        for (pc, actual), wanted in zip(region, expected):
            if wanted.startswith('CALL:'):
                if not any(c[2] == pc and c[3].endswith(wanted[5:]) for c in calls):
                    break
            elif 'goto @' in wanted:
                prefix, label = wanted.split('goto @')
                if not actual.startswith(prefix + 'goto ') or D.relative_target(pc, actual) != region[labels[label]][0]:
                    break
            elif wanted.endswith('goto ?'):
                if not actual.startswith(wanted[:-1]) or D.relative_target(pc, actual) is None:
                    break
            elif actual != wanted:
                break
        else:
            matches.append(region)
    require(len(matches) == 1, reason + ': expected one guard/dataflow lowering')
    return matches[0]


def dominates(graph, start, required, target, reason):
    require(target in D.reachable(graph, [start]) and
            target not in D.reachable(graph, [start], {required}), reason + ': bypass path')


def typed_birth(elf, secs):
    tag = 'typed-birth:'
    section = 'tp_btf/task_newtask'
    require(section in secs and section in elf.sections and not any(
        'task_newtask' in n and n.startswith(('tracepoint/', 'tp/')) for n in elf.sections), tag + 'section')
    defined(elf, 'task_newtask', section, tag + 'section')
    require('.text' in secs, tag + 'link: .text missing')
    # Only this real program section and .text participate: other sections reuse PCs.
    text = secs[section] + secs['.text']
    calls = D.internal_call_targets(text)
    _, hook = function(secs[section], 'task_newtask', tag + 'section')
    hi, hg = D.instruction_graph(hook)
    links = {}
    for target in ('p11_root_propagate_thread', 'p11_link_fork_allowed', 'p11_link_emit_fork'):
        defined(elf, target, '.text', tag + 'link')
        found = [c for c in calls if c[0] == 'task_newtask' and c[3] == target]
        require(len(found) == 1, tag + 'link: missing/redirected ' + target)
        links[target] = found[0][2]
    prefix = recipe(hi, '''
        if r1 == 0x0 goto ?
        r7 = *(u64 *)(r1 + 0x0)
        r6 = *(u64 *)(r1 + 0x8)
        r1 = r7
        r2 = r6
        CALL:p11_root_propagate_thread
        ''', tag + 'context', calls)
    require(prefix[0][0] == hi[0][0], tag + 'context: not entry')
    emit_pc = links['p11_link_emit_fork']
    before_emit = [i for i, (pc, _) in enumerate(hi) if pc == emit_pc][0]
    require(hi[before_emit - 1][1] == 'r2 = r6' and not any(
        re.match(r'[rw]6\b', op) for pc, op in hi if prefix[2][0] < pc < emit_pc), tag + 'flags: fullwidth lifetime')
    gate = recipe(hi, '''
        CALL:p11_link_fork_allowed
        r0 <<= 0x20
        r0 >>= 0x20
        if r0 == 0x0 goto ?
        ''', tag + 'scope', calls)
    for pc, _ in gate:
        dominates(hg, hi[0][0], pc, emit_pc, tag + 'scope')
    require(emit_pc not in D.reachable(hg, [D.relative_target(*gate[-1])]), tag + 'scope: refusal reaches emit')
    _, allowed = function(secs['.text'], 'p11_link_fork_allowed', tag + 'scope')
    ai, _ = D.instruction_graph(allowed)
    scope_calls = [c for c in calls if c[0] == 'p11_link_fork_allowed' and c[3].endswith('scope_auth')]
    require(len(scope_calls) == 1, tag + 'scope: real scope_auth link')
    defined(elf, scope_calls[0][3], '.text', tag + 'scope')
    ar = recipe(ai, '''
        r1 = r10
        r1 += -0x20
        CALL:scope_auth
        r1 = *(u64 *)(r10 - 0x20)
        if r1 != 0x1 goto @zero
        r0 = 0x0
        r1 = *(u64 *)(r10 - 0x18)
        r2 = r1
        r2 &= 0x2
        if r2 == 0x0 goto @done
        r1 &= 0x10
        r0 = 0x1
        if r1 == 0x0 goto @done
        zero:
        r0 = 0x0
        done:
        exit
        ''', tag + 'scope', scope_calls)
    require(ar == ai, tag + 'scope: extra instructions')
    _, emitter = function(secs['.text'], 'p11_link_emit_fork', tag + 'classification')
    ei, eg = D.instruction_graph(emitter)
    er = recipe(ei, '''
        if r3 == 0x0 goto @zero
        if r4 == 0x0 goto @zero
        r5 = r2
        r5 &= 0x10000
        if r5 != 0x0 goto @zero
        r9 = *(u64 *)(r3 + 0x0)
        if r9 == 0x0 goto @zero
        r6 = *(u64 *)(r4 + 0x0)
        if r6 != 0x0 goto @classify
        zero:
        r0 = 0x0
        exit
        classify:
        r5 = 0x200000000 ll
        r2 &= r5
        r5 = 0x1
        if r2 == 0x0 goto @pid
        r5 = 0x2
        pid:
        r2 = r1
        r2 <<= 0x20
        r2 >>= 0x20
        if r2 == 0x0 goto @zero
        ''', tag + 'classification')
    require(er[0][0] == ei[0][0], tag + 'classification: guard not entry')
    reserves = D.map_call_sites(emitter, 'EVENTS', 0x83)
    require(len(reserves) == 1 and [pc for pc, op in ei if op == 'call 0x83'] == [reserves[0][1]], tag + 'classification: EVENTS reserve')
    dominates(eg, ei[0][0], er[-1][0], reserves[0][1], tag + 'classification')
    return True


def class_provenance(lines, insns, graph, calls, null, read, classified, meta):
    """Finite class-byte facts, correlated with the validated classification edges.

    Only bits16..23 of registers and the two ORed flag slots are tracked. Copies
    and bitwise operations preserve those bits; other writes lose the fact,
    including w/r aliases. This is not instruction execution or a memory model.
    Unknown/overlapping stores and unknown helper writes invalidate flag facts.
    The existing recipes establish the read arguments, compared bytes and final
    payload layout. Every builder input must have its expected class and flags
    that cannot introduce class bits. Exact class additionally needs all three
    read/result/bytes proofs on that same path.
    """
    tag = 'interface-name:provenance'
    start, builder = insns[0][0], meta[0][0]
    live = D.reachable(graph, [start])
    for pc in live:
        require(pc not in D.reachable(graph, graph[pc]), tag + ': cyclic classifier')
    for previous, current in zip(meta, meta[1:]):
        require({pc for pc in live if current[0] in graph[pc]} == {previous[0]},
                tag + ': payload builder entered midway')
    arguments = D.call_argument_facts(lines)
    texts = dict(insns)
    flag_slots = (-0x48, -0x50)
    helper_reads = {'call 0x70', 'call 0x72'}
    helper_pcs = {pc for _, pc, raw in D.instruction_entries(lines) if raw.startswith('85 00 ')}
    require(read[-1][0] in helper_pcs, tag + ': string read is not a raw helper')
    memset = {c[2] for c in calls if c[3] == 'memset'}
    # Keys keep expected classification and validation bits correlated at joins.
    incoming = {(start, 4, 0): {}}
    pending = [(start, 4, 0)]
    builders = set()

    def alias(register):
        return 'r' + register[1:]

    def project(value):
        return (int(value, 16) >> 16) & 0xff

    def write_flags(state, address=None, size=None, value=None):
        for slot in flag_slots:
            # The only relevant byte of each OR operand is at slot+2.
            if address is None or size is None or address <= slot + 2 < address + size:
                if address == slot and size in (4, 8) and value is not None:
                    state[slot] = value
                else:
                    state.pop(slot, None)

    while pending:
        key = pending.pop()
        pc, expected, proof = key
        state = incoming[key].copy()
        if pc == builder:
            builders.add(key)
            continue
        text = texts[pc]
        args = arguments.get(pc, {})
        store = re.fullmatch(r'\*\(u(8|16|32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) = ([rw]\d+)', text)
        if store:
            width, base, sign, offset, source = store.groups()
            pointer = args.get('r' + base)
            address = (pointer[1] + int(offset, 16) * (1 if sign == '+' else -1)
                       if pointer and pointer[0] == 'stack' else None)
            write_flags(state, address, int(width) // 8, state.get(alias(source)))
        elif text.startswith('call '):
            if (pc in helper_pcs and text in helper_reads) or pc in memset:
                pointer = args.get('r1')
                size = args.get('r3' if pc in memset else 'r2')
                write_flags(state,
                            pointer[1] if pointer and pointer[0] == 'stack' else None,
                            size[1] if size and size[0] == 'constant' else None)
            elif text != 'call 0x1' or pc not in helper_pcs:
                write_flags(state)
            for register in range(6):
                state.pop('r' + str(register), None)
            if pc == read[-1][0]:
                expected, proof = 4, 1
        elif match := re.fullmatch(r'([rw]\d+) (=|\|=|&=|\^=) ([rw]\d+|-?0x[0-9a-f]+)(?: ll)?', text):
            destination, operation, source = match.groups()
            destination = alias(destination)
            value = state.get(alias(source)) if source[0] in 'rw' else project(source)
            previous = state.get(destination)
            if operation != '=':
                value = ({'|=': lambda a, b: a | b, '&=': lambda a, b: a & b,
                          '^=': lambda a, b: a ^ b}[operation](previous, value)
                         if previous is not None and value is not None else None)
            state.pop(destination, None)
            if value is not None:
                state[destination] = value
        elif match := re.match(r'([rw]\d+)\b', text):
            state.pop(alias(match.group(1)), None)
            pure_load = re.fullmatch(r'[rw]\d+ = \*\(u(?:8|16|32|64) \*\)\(r\d+ [+-] 0x[0-9a-f]+\)', text)
            pure_alu = re.fullmatch(r'[rw]\d+ (?:\+=|-=|\*=|/=|%=|<<=|>>=|s>>=) (?:[rw]\d+|-?0x[0-9a-f]+)', text)
            if not (pure_load or pure_alu):
                # A result assignment may also write memory (e.g. cmpxchg).
                state.clear()
        elif text.startswith('*'):
            write_flags(state)
        elif not (text.startswith(('if ', 'goto ')) or text == 'exit'):
            # Includes implicit memory writes such as LLVM's lock syntax.
            state.clear()
        for successor in graph[pc]:
            next_expected, next_proof = expected, proof
            taken = successor == D.relative_target(pc, text)
            if pc == null[-1][0] and taken:
                next_expected = 3
            elif pc == classified[4][0]:
                next_expected = 4 if taken else 2
            elif pc == classified[7][0] and not taken:
                next_proof |= 2
            elif pc == classified[10][0] and not taken:
                next_expected, next_proof = 1, proof | 4
            next_key = (successor, next_expected, next_proof)
            old = incoming.get(next_key)
            merged = state.copy() if old is None else {k: v for k, v in old.items() if state.get(k) == v}
            if old != merged:
                incoming[next_key] = merged
                pending.append(next_key)
    require(builders, tag + ': no reachable payload builder')
    for key in builders:
        _, expected, proof = key
        state = incoming[key]
        require(state.get('r9') == expected and all(state.get(slot) == 0 for slot in flag_slots)
                and (expected != 1 or proof == 7), tag + ': unproved class or flag bits at payload builder')


def interface_name(elf, secs):
    tag = 'interface-name:'
    require('.text' in secs and 'uretprobe' in secs, tag + 'tail: sections missing')
    # The reused tail contract needs return + worker + .text. No other sections
    # enter its PC lookup; .text comes last for relocations targeting .text.
    text = secs['uretprobe'] + secs['.text']
    require(D.interface_tail_contract(text), tag + 'tail: existing interface-tail contract')
    name, lines = function(secs['.text'], 'classify_direct_interface', tag + 'read')
    defined(elf, name, '.text', tag + 'read')
    insns, graph = D.instruction_graph(lines)
    calls = [c for c in D.internal_call_targets(secs['.text']) if c[0] == name]
    emitter_calls = [c for c in calls if c[3].endswith('emit_export')]
    require(len(emitter_calls) == 1, tag + 'metadata: emitter link')
    defined(elf, emitter_calls[0][3], '.text', tag + 'metadata')
    null = recipe(insns, '''
        r1 = 0x0
        *(u64 *)(r10 - 0x48) = r1
        r9 = 0x30000
        *(u64 *)(r10 - 0x50) = r1
        r4 = *(u64 *)(r10 - 0x60)
        if r3 == 0x0 goto ?
        ''', tag + 'null')
    read = recipe(insns, '''
        *(u64 *)(r10 - 0x68) = r5
        r9 = r10
        r9 += -0x40
        r1 = r9
        r2 = 0x0
        *(u64 *)(r10 - 0x48) = r3
        r3 = 0x9
        CALL:memset
        r1 = r9
        r2 = 0x9
        r3 = *(u64 *)(r10 - 0x48)
        call 0x72
        ''', tag + 'read', calls)
    classified = recipe(insns, '''
        r3 = 0x1000000
        r9 = 0x40000
        r1 = 0x0
        *(u64 *)(r10 - 0x48) = r1
        if r1 s> r0 goto @join
        r9 = 0x20000
        r3 = 0x0
        if r0 != 0x8 goto @join
        r1 = *(u64 *)(r10 - 0x40)
        r2 = 0x31312053434b50 ll
        if r1 != r2 goto @join
        r9 = 0x10000
        join:
        *(u64 *)(r10 - 0x50) = r3
        r4 = *(u64 *)(r10 - 0x60)
        r5 = *(u64 *)(r10 - 0x68)
        ''', tag + 'classification')
    metadata_stores = [text for _, text in insns
                       if re.fullmatch(r'\*\(u32 \*\)\(r10 - 0x8\) = [rw]1', text)]
    require(len(metadata_stores) == 1, tag + 'metadata: exact u32 field store')
    meta = recipe(insns, f'''
        r1 = 0xffffff0000ffff ll
        r8 &= r1
        r1 = *(u64 *)(r10 - 0x58)
        {metadata_stores[0]}
        *(u64 *)(r10 - 0x30) = r5
        *(u64 *)(r10 - 0x38) = r6
        r9 |= r8
        r1 = *(u64 *)(r10 - 0x48)
        r9 |= r1
        r1 = *(u64 *)(r10 - 0x50)
        r9 |= r1
        *(u64 *)(r10 - 0x40) = r9
        r1 = r10
        r1 += -0x28
        r2 = *(u64 *)(r7 + 0x0)
        *(u64 *)(r1 + 0x0) = r2
        r2 = *(u64 *)(r7 + 0x8)
        *(u64 *)(r1 + 0x8) = r2
        r2 = *(u64 *)(r7 + 0x10)
        *(u64 *)(r1 + 0x10) = r2
        r2 = *(u64 *)(r7 + 0x18)
        *(u64 *)(r1 + 0x18) = r2
        r1 = r10
        r1 += -0x40
        r2 = r4
        CALL:emit_export
        ''', tag + 'metadata', calls)
    require(graph[null[-1][0]] == [meta[0][0], read[0][0]], tag + 'null: branch wiring')
    require(graph[read[-1][0]] == [classified[0][0]] and graph[classified[-1][0]] == [meta[0][0]], tag + 'classification: adjacency')
    class_provenance(lines, insns, graph, calls, null, read, classified, meta)
    exact = classified[11][0]
    require([pc for pc, op in insns if op == 'call 0x72'] == [read[-1][0]] and
            [pc for pc, op in insns if op == 'r9 = 0x10000'] == [exact], tag + 'classification: alternate exact assignment')
    for required in (read[0][0], read[-1][0], classified[4][0], classified[7][0], classified[10][0]):
        dominates(graph, insns[0][0], required, exact, tag + 'classification')
    dominates(graph, insns[0][0], meta[0][0], meta[-1][0], tag + 'metadata')
    return True


def check_decoded(elf, disassembly, contract):
    require(contract in ('typed-birth', 'interface-name', 'all'), 'unknown contract')
    secs = sections(disassembly)
    results = {}
    if contract in ('typed-birth', 'all'):
        results['typed-birth'] = typed_birth(elf, secs)
    if contract in ('interface-name', 'all'):
        results['interface-name'] = interface_name(elf, secs)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--variant', choices=('default', 'unsafe'), required=True)
    parser.add_argument('--contract', choices=('typed-birth', 'interface-name', 'all'), required=True)
    args = parser.parse_args(argv)
    report = dict(schema=SCHEMA, variant=args.variant, contract=args.contract, object=str(args.object),
                  decoder_sha256=DECODER_SHA256,
                  boundary='typed birth caller/bridge gates; direct-name ExportPayload.record_meta to emit_export',
                  excluded=['C hook identity semantics (native fixture)', 'downstream ring-byte propagation', 'consumer privacy'],
                  normalization='strip LLVM CO-RE annotation lines before shared decimal-PC CFG helpers')
    try:
        report['object_sha256'] = hashlib.sha256(args.object.read_bytes()).hexdigest()
        elf, disassembly = load_object(args.object)
        report['contracts'] = check_decoded(elf, disassembly, args.contract)
        report['status'] = 'verified'
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        report.update(status='failed', error=str(error))
        if isinstance(error, subprocess.CalledProcessError):
            report.update(stdout=error.stdout, stderr=error.stderr, returncode=error.returncode)
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
