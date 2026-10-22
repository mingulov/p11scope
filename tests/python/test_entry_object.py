#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native tests; supply immutable objects with --default-object/--unsafe-object."""

import argparse
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
from types import SimpleNamespace
import unittest

CHECKER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/check-entry-object.py"))
OBJECTS = {}
OBJECT_BYTES = {}


def instructions(variant, suffix):
    blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
    names = [name for name in blocks if name.endswith(suffix)]
    if len(names) != 1:
        raise AssertionError(f"ambiguous instruction owner {suffix}: {names}")
    return names[0], CHECKER["D"].instructions(blocks[names[0]])


def site(variant, suffix, pattern, occurrence=None):
    """Select an instruction role in the immutable object, before mutation."""
    _, insns = instructions(variant, suffix)
    matches = [pc for pc, text in insns if re.fullmatch(pattern, text)]
    if occurrence is None:
        if len(matches) != 1:
            raise AssertionError(f"{suffix}: expected one {pattern!r}, got {matches}")
        return matches[0]
    if not matches or occurrence >= len(matches):
        raise AssertionError(f"{suffix}: missing occurrence {occurrence} of {pattern!r}")
    return matches[occurrence]


def call_site(variant, suffix, target_suffix, occurrence=0):
    name, _ = instructions(variant, suffix)
    calls = [pc for caller, _, pc, target in CHECKER["D"].internal_call_targets(OBJECTS[variant])
             if caller == name and target.endswith(target_suffix)]
    return calls[occurrence]


def before_call(variant, suffix, target, pattern, occurrence=0):
    call = call_site(variant, suffix, target, occurrence)
    _, insns = instructions(variant, suffix)
    return next(pc for pc, text in reversed(insns) if pc < call and re.fullmatch(pattern, text))


def after_call(variant, suffix, target, pattern, occurrence=0):
    call = call_site(variant, suffix, target, occurrence)
    _, insns = instructions(variant, suffix)
    return next(pc for pc, text in insns if pc > call and re.fullmatch(pattern, text))


def internal_callee_instruction(variant, fragment):
    """The .text relocation encodes callee start minus one."""
    blocks = CHECKER["D"].function_blocks(CHECKER["sections"](OBJECTS[variant])[".text"])
    names = [name for name in blocks if fragment in name]
    if len(names) != 1:
        raise AssertionError(f"ambiguous callee fragment {fragment}: {names}")
    pc = CHECKER["D"].instructions(blocks[names[0]])[0][0]
    return f"call {pc - 1:#x}"


def internal_contract(variant, name, disassembly=None):
    split = CHECKER["sections"](OBJECTS[variant] if disassembly is None else disassembly)
    blocks = CHECKER["D"].function_blocks(split[".text"])
    calls = {}
    for caller, _, pc, target in CHECKER["D"].internal_call_targets(split[".text"]):
        calls.setdefault(caller, {})[pc] = target
    if name == "scalar_body_contract":
        return CHECKER[name](blocks, calls, variant)
    return CHECKER[name](blocks, calls)



def entry_contract(variant, name, disassembly=None):
    """Exercise final entry sinks without hiding behind an earlier contract."""
    split = CHECKER["sections"](OBJECTS[variant] if disassembly is None else disassembly)
    blocks = CHECKER["D"].function_blocks(split[".text"])
    calls = {}
    for caller, _, pc, target in CHECKER["D"].internal_call_targets(split["uprobe"]+"\n"+split[".text"]):
        calls.setdefault(caller, {})[pc] = target
    consumer = CHECKER["_SeedCaller"]("uprobe", name,
        CHECKER["D"].function_blocks(split["uprobe"])[name], calls[name])
    selectors = [0x33] if variant == "unsafe" and name == "p11_entry" else [0x23] if name == "p11_entry_ia32" else [0x23, 0x33]
    return CHECKER["final_sink_contract"](consumer, variant, selectors, blocks, calls)



def return_contract(variant, disassembly=None):
    split = CHECKER["sections"](OBJECTS[variant] if disassembly is None else disassembly)
    blocks = CHECKER["D"].function_blocks(split[".text"])
    calls = {}
    for caller, _, pc, target in CHECKER["D"].internal_call_targets(split["uretprobe"]+"\n"+split[".text"]):
        calls.setdefault(caller, {})[pc] = target
    root = CHECKER["_SeedCaller"]("uretprobe", "p11_return",
        CHECKER["D"].function_blocks(split["uretprobe"])["p11_return"], calls["p11_return"])
    return CHECKER["final_sink_contract"](root, variant, [0x23, 0x33], blocks, calls)



def consumer_case(variant, suffix, disassembly=None):
    split = CHECKER["sections"](OBJECTS[variant] if disassembly is None else disassembly)
    matches = [(section, name, lines) for section in ("uprobe", "uretprobe", ".text")
               for name, lines in CHECKER["D"].function_blocks(split[section]).items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError((suffix, len(matches)))
    section, name, lines = matches[0]
    text = split[section] + ("\n"+split[".text"] if section != ".text" else "")
    calls = {pc: target for caller, _, pc, target in CHECKER["D"].internal_call_targets(text) if caller == name}
    outlined = section == ".text" and name.endswith(("ordinary_return", "object_return"))
    cls = CHECKER["_ReturnCaller"] if outlined or name == "p11_return" else CHECKER["_SeedCaller"]
    initial = {"r1": ("context", 0), "r2": ("external_key", ("uretprobe", "p11_return"), 0),
        "r3": ("owned", 7, 0), "r4": ("scope_flags", ("uretprobe", "p11_return")),
        "r5": ("constant", 0), "r10": ("stack", 0)} if outlined else None
    return cls(section, name, lines, calls), initial, CHECKER["D"].function_blocks(split[".text"]), outlined


def consumer_contract(variant, suffix, disassembly=None):
    consumer, initial, blocks, outlined = consumer_case(variant, suffix, disassembly)
    return CHECKER["consumer_contract"](consumer, variant, blocks, initial, outlined)


def entry_role_contract(variant, name, role, disassembly=None):
    original, _, _, _ = consumer_case(variant, name, disassembly)
    consumer = CHECKER["_OwnedCaller"](original.section, name, original.lines, original.calls)
    calls = sorted(pc for pc, target in consumer.calls.items() if target.endswith("capture_scalar"))
    if len(calls) != 9:
        raise AssertionError((name, calls))
    owner = next(pc for pc, target in consumer.calls.items() if target == "p11_owner_start_begin")
    proof = CHECKER["_OwnedSinkProof"](role, int(name.endswith("ia32")), True, ("owned", owner, 0),
        calls=dict(zip(calls, (6, 7, 10, 11, 9, 8, 16, "join", "get"))))
    proof.decoder_required = variant == "unsafe" and role == 8
    consumer.facts(proof=proof)
    return proof


def mechanism_guard(variant, name):
    _, insns = instructions(variant, name)
    store = next(pc for pc, text in insns if re.fullmatch(r"\*\(u64 \*\)\(r[6-9] \+ 0x20\) = r\d+", text))
    return next((pc, text) for pc, text in reversed(insns) if pc < store and re.fullmatch(r"if r\d+ == 0x0 goto .*", text))


def consumer_names(variant):
    names = ["p11_entry", "p11_return", "ordinary_return", "object_return"]
    if variant == "unsafe":
        names += ["p11_entry_ia32", "p11_entry_template", "p11_entry_template_pair",
                  "p11_entry_template_second", "p11_entry_template_types"]
    return names


def mutate(disassembly, function, pc, old, new, internal_call=False, helper_call=False):
    """Change exactly one decoded instruction, retaining its actual-object origin."""
    symbols = list(re.finditer(r"(?m)^[0-9a-f]+ <([^>]+)>:$", disassembly))
    matches = [i for i, symbol in enumerate(symbols) if symbol[1] == function]
    if len(matches) != 1:
        raise AssertionError(f"ambiguous function {function}")
    index = matches[0]
    start = symbols[index].end()
    end = symbols[index + 1].start() if index + 1 < len(symbols) else len(disassembly)
    block = disassembly[start:end]
    pattern = rf"(?m)(^\s*{pc}:[^\n]*\t)({re.escape(old)})(\s*(?:<[^>]+>)?$)"
    def replacement(match):
        prefix = match[1]
        if internal_call or helper_call:
            opcode = "85 10" if internal_call else "85 00"
            prefix, count = re.subn(r"(^\s*\d+:\s+)[0-9a-f]{2} [0-9a-f]{2}",
                lambda found: found[1]+opcode, prefix)
            if count != 1:
                raise AssertionError("mutation did not select one instruction opcode")
        return prefix+new+match[3]
    changed, count = re.subn(pattern, replacement, block)
    if count != 1 or changed == block:
        raise AssertionError(f"mutation did not change {function}:{pc}: {old!r}")
    return disassembly[:start] + changed + disassembly[end:]


class EntryObjectTests(unittest.TestCase):
    def test_bounded_entry_cycles_require_proved_progress(self):
        for variant in OBJECTS:
            name, insns = instructions(variant, "p11_entry")
            texts = dict(insns)
            guard = next(pc for pc, text in insns
                         if re.fullmatch(r"if r2 != 0x20 goto -0x7", text))
            head = guard-6
            entry, exit_pc = head-2, guard+1
            self.assertEqual(texts[entry], "r1 = 0x0")
            self.assertEqual(texts[entry+1], "r2 = 0x0")
            self.assertEqual(texts[guard-1], "r2 += 0x4")

            def prove(disassembly, sink=-0x40):
                # The actual emitted clear-eight CFG, with its caller state
                # supplied at entry and a checked final sink at its exit.
                parts = CHECKER["sections"](disassembly)
                lines = CHECKER["D"].function_blocks(parts["uprobe"])[name]
                consumer = CHECKER["Consumer"]("uprobe", name, lines, {})
                consumer.insns = [(pc, text) for pc, text in consumer.insns if entry <= pc <= exit_pc]
                consumer.graph = {pc: ([] if pc == exit_pc else consumer.graph[pc])
                                  for pc, _ in consumer.insns}
                consumer.text[exit_pc] = "exit"
                proof = CHECKER["SinkProof"](6, 0, True, ("stack", sink))
                consumer.facts({"r6": ("stack", -512), "r10": ("stack", 0),
                    ("success",): True, ("stack", sink+8, 8): ("scalar", 6, 64)}, proof)
                self.assertTrue(proof.witnesses)

            for bound in ("0x20", "0x10"):
                healthy = mutate(OBJECTS[variant], name, guard, texts[guard],
                                 texts[guard].replace("0x20", bound)) if bound != "0x20" else OBJECTS[variant]
                with self.subTest(variant=variant, control="proved bounded loop", bound=bound):
                    prove(healthy)
            for pc, new in ((entry+1, "r2 = r9"), (guard-1, "r2 += 0x0"),
                            (guard, texts[guard].replace("0x20", "0x24")),
                            (guard, f"if r2 != 0x20 goto {entry+1-guard-1:+#x}"),
                            (guard, "if r2 != 0x20 goto -0x1")):
                with self.subTest(variant=variant, mutant=new):
                    with self.assertRaisesRegex(RuntimeError, "cyclic|loop"):
                        prove(mutate(OBJECTS[variant], name, pc, texts[pc], new))
            for sink in (-0xa8, -0x90):
                with self.subTest(variant=variant, control="loop effects cannot skip first or last cells", sink=sink):
                    with self.assertRaisesRegex(RuntimeError, "successful capture lost"):
                        prove(OBJECTS[variant], sink)

    def _assert_entry_side_query_requires_key_null_and_start_lifetime(self):
        for variant in OBJECTS:
            name, insns = instructions(variant, "p11_entry")
            lines = CHECKER["D"].function_blocks(CHECKER["sections"](OBJECTS[variant])["uprobe"])[name]
            query = call_site(variant, name, "p11_object_side_get", 4)
            consumer = CHECKER["_OwnedCaller"]("uprobe", name, lines, {query: "p11_object_side_get"})
            proof = CHECKER["_OwnedSinkProof"](6, 0, True, ("owned", 77, 0))
            consumer.proof = proof
            identity = ("uprobe", name)
            key = {("stack", -64, 8): ("pid_tgid", identity),
                   ("stack", -56, 4): ("low", identity), ("stack", -52, 4): ("constant", 0)}
            state = {**key, "r1": ("stack", -64), "r2": ("constant", 5), "r3": ("constant", 0),
                "r7": ("owned", 77, 0), "r10": ("stack", 0), ("live", 77): True,
                ("success",): True, ("owned_word", 77, 8, 8): ("scalar", 6, 64),
                ("stack", -128, 8): ("constant", 37)}
            acquired = consumer.step(query, state)
            alias, guard, store = (pc for pc, _ in insns if query < pc <= query+3)
            consumer.text[alias] = "r8 = r0"
            acquired = consumer.step(alias, acquired)
            consumer.text[guard] = "if r8 != 0x0 goto +0x1"
            consumer.graph[guard] = [guard+1, guard+2]
            edges = dict(proof.edges(consumer, guard, acquired, acquired))
            consumer.text[store] = "*(u32 *)(r8 + 0x40) = w7"
            with self.subTest(variant=variant, control="nonnull private row writes preserve START and frame"):
                written = consumer.step(store, edges[guard+2])
                proof.check_sink(consumer, store, written)
                self.assertEqual(written[("stack", -128, 8)], ("constant", 37))
            nullable = proof.join(edges[guard+1], edges[guard+2])
            with self.subTest(variant=variant, control="joined null remains nullable until a fresh full-width guard"):
                with self.assertRaisesRegex(RuntimeError, "side.*nonnull"):
                    consumer.step(store, nullable)
                refined = dict(proof.edges(consumer, guard, nullable, nullable))[guard+2]
                proof.check_sink(consumer, store, consumer.step(store, refined))
            for candidate, control in ((edges[guard+1], "null side row"),
                    ({key: val for key, val in edges[guard+2].items() if key != ("live", 77)}, "expired START")):
                with self.subTest(variant=variant, control=control):
                    with self.assertRaisesRegex(RuntimeError, "side.*(nonnull|lifetime)"):
                        consumer.step(store, candidate)
            def indexed_write(values, comparison=None):
                joined = None
                for number in values:
                    joined = proof.join(joined, edges[guard+2] | {"r1": ("constant", number)})
                if comparison:
                    consumer.text[guard] = f"if {comparison} == 0x0 goto +0x1"
                    joined = dict(proof.edges(consumer, guard, joined, joined))[guard+2]
                consumer.text[alias] = "r1 <<= 0x5"
                shifted = consumer.step(alias, joined)
                consumer.text[store] = "r8 += r1"
                shifted = consumer.step(store, shifted)
                consumer.text[store] = "*(u64 *)(r8 + 0x60) = r7"
                written = consumer.step(store, shifted)
                proof.check_sink(consumer, store, written)
                self.assertEqual(written[("stack", -128, 8)], ("constant", 37))
            with self.subTest(variant=variant, control="exact selected-slot join keeps bounded row offsets"):
                indexed_write((0, 1))
            with self.subTest(variant=variant, control="full-width predicate retains only the safe offset"):
                indexed_write((0, 1 << 32), "r1")
            for values, comparison in (((0, 16), None), (range(10), None),
                    ((0, 1 << 63), None), ((0, 1 << 32), "w1")):
                with self.subTest(variant=variant, control="unknown or out-of-row index cannot preserve a sink",
                                  values=tuple(values), comparison=comparison):
                    with self.assertRaisesRegex(RuntimeError, "side.*footprint|unknown entry write footprint|branch width 32"):
                        indexed_write(values, comparison)
            for offsets, allowed in (((0, 32), True), ((0, 512), False), (range(0, 320, 32), False)):
                joined = None
                for offset in offsets:
                    joined = proof.join(joined, edges[guard+2] | {"r8": ("side", query, offset)})
                consumer.text[store] = "*(u64 *)(r8 + 0x60) = r7"
                with self.subTest(variant=variant, control="joined private pointer offsets stay bounded", offsets=tuple(offsets)):
                    if allowed:
                        proof.check_sink(consumer, store, consumer.step(store, joined))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "side.*footprint|unknown entry write footprint"):
                            consumer.step(store, joined)
            for changed, control in (({("stack", -52, 4): ("constant", 1)}, "key padding"),
                    ({("stack", -56, 4): ("low", ("uprobe", "foreign"))}, "foreign slot"),
                    ({"r3": ("constant", 1)}, "wrong required flag"),
                    ({"r2": ("owned", 77, 0)}, "pointer used as descriptor"),
                    ({("live", 77): False}, "expired query")):
                with self.subTest(variant=variant, control=control):
                    with self.assertRaisesRegex(RuntimeError, "side query"):
                        consumer.step(query, state | changed)

    def test_seeded_start_caller_contract(self):
        for variant, disassembly in OBJECTS.items():
            with self.subTest(variant=variant):
                reports = CHECKER["seeded_start_contract"](disassembly)
                self.assertIn("p11_entry", reports)
                scalar = CHECKER["scalar_scope_flags_contract"](disassembly)
                if scalar is not None:
                    _, scalar_insns = instructions(variant, scalar)
                    # Each mutant changes actual emitted wrapper instructions;
                    # unknown/private callees and malformed summaries stay closed.
                    scalar_texts = dict(scalar_insns)
                    flag_pc, flag_text = next((pc, text) for pc, text in scalar_insns
                        if text == "r0 = *(u64 *)(r10 - 0x18)")
                    tag_pc, tag_text = next((pc, text) for pc, text in scalar_insns
                        if text == "r1 = *(u64 *)(r10 - 0x20)")
                    guard_pc, guard_text = next((pc, text) for pc, text in scalar_insns
                        if re.fullmatch(r"if r1 (==|!=) 0x[01] goto .*", text))
                    zero_pc, zero_text = next((pc, text) for pc, text in scalar_insns if text == "r0 = 0x0")
                    for pc, replacement in [(scalar_insns[0][0], "r1 = r2"),
                            (scalar_insns[2][0], "call 0x70"),
                            (flag_pc, "r0 = *(u32 *)(r10 - 0x18)"),
                            (guard_pc, guard_text.replace(" == ", " != ") if " == " in guard_text
                                else guard_text.replace(" != ", " == ")),
                            (guard_pc, "goto +0x0"), (tag_pc, flag_text), (zero_pc, "r0 = 0x1")]:
                        with self.subTest(scalar_mutation=pc):
                            with self.assertRaisesRegex(RuntimeError, "scalar scope flags"):
                                CHECKER["seeded_start_contract"](mutate(disassembly, scalar, pc,
                                    scalar_texts[pc], replacement))
                    with self.assertRaisesRegex(RuntimeError, "scalar scope flags"):
                        CHECKER["seeded_start_contract"](mutate(disassembly, scalar, zero_pc,
                            zero_text, scalar_insns[2][1]))
                memset_name, memset_insns = instructions(variant, "memset")
                # llvm-objdump 18 spells the stored sub-register `r2`, 21 spells
                # the same bytes `w2`; the mutant must keep the local spelling.
                sub = "r2" if any(text == "*(u8 *)(r5 + 0x0) = r2" for _, text in memset_insns) else "w2"
                zero_store, zero_text = next((pc, text) for pc, text in memset_insns
                                            if text == f"*(u8 *)(r5 + 0x0) = {sub}")
                with self.assertRaisesRegex(RuntimeError, "memset byte-loop summary"):
                    CHECKER["seeded_start_contract"](mutate(disassembly, memset_name, zero_store,
                        zero_text, f"*(u8 *)(r5 + 0x0) = {sub[0]}1"))
                for name, report in reports.items():
                    _, insns = instructions(variant, name)
                    texts = dict(insns)
                    split = CHECKER["sections"](disassembly)
                    calls = CHECKER["D"].internal_call_targets(split["uprobe"] + "\n" + split[".text"])
                    consumer = CHECKER["_SeedCaller"]("uprobe", name,
                        CHECKER["D"].function_blocks(split["uprobe"])[name],
                        {pc: target for caller, _, pc, target in calls if caller == name})
                    facts = consumer.facts()
                    if scalar is not None:
                        pc = next(pc for pc, target in consumer.calls.items() if target == scalar)
                        with self.assertRaisesRegex(RuntimeError, "one scalar scope call"):
                            CHECKER["seeded_start_contract"](mutate(disassembly, name, pc,
                                texts[pc], "r0 = 0x1"))
                    mutations = []
                    begin = report["constructor"]
                    seed_arg = next((pc, text) for pc, text in reversed(insns)
                                    if pc < begin and re.match(r"r2 (=|\+=) ", text))
                    mutations.append((seed_arg[0], seed_arg[1], "r2 = r1", "key/seed"))
                    aggregate_arg = next((pc, text) for pc, text in reversed(insns)
                                         if pc < report["aggregate"] and re.match(r"r2 (=|\+=) ", text))
                    mutations.append((aggregate_arg[0], aggregate_arg[1], "r2 = 0x0", "original scalar timestamp"))
                    for pc, text in insns:
                        store = CHECKER["STORE"].fullmatch(text)
                        if not store or pc >= begin:
                            continue
                        width, base, sign, offset, source = store.groups()
                        pointer = CHECKER["address"](facts.get(pc, {}), base, sign, offset)
                        if pointer == ("stack", report["key"]+12) and width == "32":
                            mutations.append((pc, text, text.rsplit(" = ", 1)[0]+" = 0x1", "owner key/padding"))
                        if pointer == ("stack", report["seed"]) and width == "64":
                            mutations.append((pc, text, text.rsplit(" = ", 1)[0]+" = 0x1", "original timestamp"))
                    self.assertEqual(sum(reason == "owner key/padding" for _, _, _, reason in mutations), 1)
                    self.assertEqual(sum(reason == "original timestamp" for _, _, _, reason in mutations), 1)
                    for field in ("identity_guard", "cookie_guard", "null_guard"):
                        pc = report[field]
                        mutations.append((pc, texts[pc], "goto +0x0", "guard|refusal"))
                    identity_call = next(pc for pc, target in consumer.calls.items() if target == "p11_link_current_identity")
                    image_arg = next((pc, text) for pc, text in reversed(insns)
                                     if pc < identity_call and text.startswith("r1 = "))
                    mutations.append((image_arg[0], image_arg[1], "r1 = r10", "current image words"))
                    zero_call = max(pc for pc, target in consumer.calls.items() if target == "memset" and pc < identity_call)
                    for register, replacement, reason in (("r3", "0x10", "marker"), ("r2", "0x1", "marker")):
                        pc, text = next((pc, text) for pc, text in reversed(insns)
                                        if pc < zero_call and text.startswith(register+" = "))
                        mutations.append((pc, text, register+" = "+replacement, reason))
                    for pc, old, new, reason in mutations:
                        with self.subTest(function=name, mutation=reason, pc=pc):
                            with self.assertRaisesRegex(RuntimeError, "(?:seeded|aggregate) START.*("+reason+")"):
                                CHECKER["seeded_start_contract"](mutate(disassembly, name, pc, old, new))
                    # Turn a real pre-construction policy-mask instruction into
                    # a genuine user-read helper. Seed fields and guards survive;
                    # only the private-read boundary must reject this mutation.
                    marker_call = next(pc for pc, target in consumer.calls.items() if target.endswith("object_marker_for"))
                    pc, old = next((pc, text) for pc, text in reversed(insns)
                                   if report["witness"] < pc < marker_call and re.fullmatch(r"r\d+ &= 0x4", text))
                    changed = mutate(disassembly, name, pc, old, "call 0x70", helper_call=True)
                    with self.assertRaisesRegex(RuntimeError, "private read before construction"):
                        CHECKER["seeded_start_contract"](changed)

    def test_ia32_span_rejection_edge_is_causal(self):
        for variant in OBJECTS:
            internal_contract(variant, "ia32_reader_contract")
            name, insns = instructions(variant, "p11_read_ia32_arg")
            pc = site(variant, name, r"if r3 > r1 goto .*")
            old = dict(insns)[pc]
            for new in ("if r3 > r1 goto +0x0", "goto +0x0"):
                with self.subTest(variant=variant, mutation=new):
                    with self.assertRaisesRegex(RuntimeError, "ia32.*span"):
                        internal_contract(variant, "ia32_reader_contract",
                            mutate(OBJECTS[variant], name, pc, old, new))
            # Bypassing the read is insufficient if the rejected path picks up
            # an uninitialized successful-read payload instead of the sentinel.
            payload = site(variant, name, r"[rw]\d+ = \*\(u32 \*\)\(r10 - 0x4\)")
            self.assertTrue(all(CHECKER["contract"](OBJECTS[variant], variant)["verified"].values()))
            for pattern in (r"if r1 > 0x6 goto .*", r"if r0 != 0x0 goto .*"):
                guard = site(variant, name, pattern)
                original = dict(insns)[guard]
                changed = mutate(OBJECTS[variant], name, guard, original,
                                 original.split(" goto ")[0]+f" goto {payload-guard-1:+#x}")
                with self.subTest(variant=variant, mutation="non-span rejection reaches payload", guard=pattern):
                    with self.assertRaisesRegex(RuntimeError, "ia32.*(rejection|sentinel|payload)"):
                        CHECKER["contract"](changed, variant)
            with self.subTest(variant=variant, mutation="rejection returns payload"):
                with self.assertRaisesRegex(RuntimeError, "ia32.*span.*sentinel"):
                    internal_contract(variant, "ia32_reader_contract",
                        mutate(OBJECTS[variant], name, pc, old,
                            f"if r3 > r1 goto {payload-pc-1:+#x}"))
            saved_pc, saved = next((p, t) for p, t in insns if t.endswith(" = 0x100000000 ll"))
            register = saved.split(" = ")[0]
            restore = site(variant, name, rf"r0 = {register}")
            texts = dict(insns)
            for where, replacement in ((saved_pc, register + " = 0x200000000 ll"),
                                        (saved_pc, register + " = r9"),
                                        (restore, "w0 = w" + register[1:]),
                                        (restore, "r0 = (s16)" + register)):
                with self.subTest(variant=variant, mutation=replacement):
                    with self.assertRaisesRegex(RuntimeError, "ia32.*span.*sentinel"):
                        internal_contract(variant, "ia32_reader_contract",
                            mutate(OBJECTS[variant], name, where, texts[where], replacement))
        # Equivalent explicit/saved return blocks remain valid; a helper only
        # preserves the callee-saved form. Each path must retain its own fact.
        graph = {0: [1], 1: [2, 4], 2: [3], 3: [], 4: [5], 5: [6], 6: []}
        for saved in (False, True):
            texts = {0: "r6 = 0x100000000 ll" if saved else "r0 = 0x100000000 ll",
                     1: "if r3 > r1 goto +0x2", 2: "call 0x70", 3: "exit",
                     4: "call 0x5" if saved else "r1 = r1",
                     5: "r0 = r6" if saved else "r0 = r0", 6: "exit"}
            CHECKER["SPAN"].validate_ia32_span_paths(graph, 0, 1, 4, 2, {}, {3, 6},
                register_transfer=lambda pc, state: CHECKER["ia32_register_transfer"](texts[pc], state))
        for replacement in ("w0 = w6", "r0 = w6", "w0 = r6", "r0 = (s8)r6",
                            "r0 = (s16)r6", "r0 = (s32)r6", "r0 = r5"):
            with self.subTest(mutation=replacement), self.assertRaisesRegex(RuntimeError, "span.*sentinel"):
                CHECKER["SPAN"].validate_ia32_span_paths(graph, 0, 1, 4, 2, {}, {3, 6},
                    register_transfer=lambda pc, state: CHECKER["ia32_register_transfer"](
                        replacement if pc == 5 else texts[pc], state))
        for fault in ("caller-saved", "atomic-write"):
            changed = dict(texts)
            if fault == "caller-saved":
                changed.update({0: "r5 = 0x100000000 ll", 5: "r0 = r5"})
            else:
                changed[4] = "r6 = atomic_fetch_or((u64 *)(r10 - 0x8), r6)"
            with self.subTest(mutation=fault), self.assertRaisesRegex(RuntimeError, "span.*sentinel"):
                CHECKER["SPAN"].validate_ia32_span_paths(graph, 0, 1, 4, 2, {}, {3, 6},
                    register_transfer=lambda pc, state: CHECKER["ia32_register_transfer"](changed[pc], state))
        merge = {0: [1], 1: [2, 4], 2: [3], 3: [], 4: [5, 6], 5: [7], 6: [7], 7: [8], 8: []}
        changed = texts | {4: "if r7 == 0x0 goto +0x1", 5: "r6 = 0x0",
                           6: "r7 = r7", 7: "r0 = r6", 8: "exit"}
        with self.assertRaisesRegex(RuntimeError, "span.*sentinel"):
            CHECKER["SPAN"].validate_ia32_span_paths(merge, 0, 1, 4, 2, {}, {3, 8},
                register_transfer=lambda pc, state: CHECKER["ia32_register_transfer"](changed[pc], state))

    def test_async_string_read_requires_genuine_helper_call_kind(self):
        # Select the owning proof so another role's unknown-call footprint
        # cannot turn an unrelated rejection into apparent async coverage.
        entry_role_contract("default", "p11_entry", 16)
        name, _ = instructions("default", "p11_entry")
        pc = site("default", name, r"call 0x72")
        with self.assertRaisesRegex(RuntimeError, "async.*genuine helper"):
            entry_role_contract("default", name, 16, mutate(OBJECTS["default"], name, pc,
                "call 0x72", "call 0x72", internal_call=True))
        internal_contract("unsafe", "scalar_body_contract")
        name, _ = instructions("unsafe", "capture_async_target")
        pc = site("unsafe", name, r"call 0x72")
        with self.assertRaisesRegex(RuntimeError, "async.*(unresolved internal call|genuine helper)"):
            internal_contract("unsafe", "scalar_body_contract", mutate(OBJECTS["unsafe"], name, pc,
                "call 0x72", "call 0x72", internal_call=True))

    def test_global_ia32_reader_retains_stride_span_width_and_linkage(self):
        checker = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/check-bpf-map-defs.py"))
        for variant, data in OBJECT_BYTES.items():
            checker["validate_ia32_reader"](checker["Elf"](data))
            for pattern, immediate in ((r"r2 <<= 0x2", 3),
                                       (r"r2 = 0x4", 8)):
                with self.subTest(variant=variant, mutation=pattern):
                    elf = checker["Elf"](data)
                    row, body = elf.sections[".text"]
                    changed = bytearray(body)
                    pc = site(variant, "p11_read_ia32_arg", pattern)
                    struct.pack_into("<i", changed, pc * 8 + 4, immediate)
                    elf.sections[".text"] = (row, bytes(changed))
                    with self.assertRaisesRegex(RuntimeError, "ia32"):
                        checker["validate_ia32_reader"](elf)
            pc = site(variant, "p11_read_ia32_arg", r"r3 >>= 0x20")
            with self.subTest(variant=variant, mutation="stack-pointer normalization"):
                with self.assertRaisesRegex(RuntimeError, "ia32.*normalization"):
                    CHECKER["contract"](mutate(OBJECTS[variant], "p11_read_ia32_arg", pc,
                        "r3 >>= 0x20", "r3 >>= 0x1f"), variant)
            pc = site(variant, "p11_read_ia32_arg", r"if r3 > r1 goto .*")
            old = dict(instructions(variant, "p11_read_ia32_arg")[1])[pc]
            with self.subTest(variant=variant, mutation="full-width address span"):
                with self.assertRaisesRegex(RuntimeError, "ia32.*span"):
                    CHECKER["contract"](mutate(OBJECTS[variant], "p11_read_ia32_arg", pc,
                        old, re.sub(r"\br(\d+)\b", r"w\1", old)), variant)
            for pattern, replacement in ((r"if r1 > 0x6 goto .*", lambda text: text.replace("0x6", "0x7")),
                    (r"if r0 != 0x0 goto .*", lambda text: text.replace("r0", "w0")),
                    (r"w6 = \*\(u32 \*\)\(r10 - 0x4\)", lambda text: text.replace("w6", "r6").replace("u32", "u64"))):
                pc = site(variant, "p11_read_ia32_arg", pattern)
                old = dict(instructions(variant, "p11_read_ia32_arg")[1])[pc]
                with self.subTest(variant=variant, mutation=pattern), self.assertRaisesRegex(RuntimeError, "ia32.*(index|helper|payload)"):
                    internal_contract(variant, "ia32_reader_contract",
                        mutate(OBJECTS[variant], "p11_read_ia32_arg", pc, old, replacement(old)))
            elf = checker["Elf"](data)
            elf.symbols = [(symbol[0], 2, *symbol[2:]) if symbol[0] == "p11_read_ia32_arg"
                           else symbol for symbol in elf.symbols]
            with self.subTest(variant=variant, mutation="GLOBAL linkage"):
                with self.assertRaisesRegex(RuntimeError, "GLOBAL"):
                    checker["validate_ia32_reader"](elf)

    def test_async_scalar_failure_preserves_lifecycle_continuation(self):
        for variant, name in (("default", "p11_entry"), ("unsafe", "p11_entry_ia32")):
            entry_contract(variant, name)
            call = call_site(variant, name, "capture_scalar", 6)
            _, insns = instructions(variant, name)
            pc, old = next((pc, text) for pc, text in insns if pc > call and text.startswith("if "))
            exit_pc = site(variant, name, "exit")
            # Both Some and None must continue to the lifecycle match.
            changed = mutate(OBJECTS[variant], name, pc, old,
                old.split(" goto ")[0]+f" goto {exit_pc-pc-1:+#x}")
            with self.subTest(variant=variant), self.assertRaisesRegex(RuntimeError, "async.*continuation"):
                entry_contract(variant, name, changed)

    def test_pointer_only_async_boundary_mutations(self):
        variant, entry = "unsafe", "p11_entry_ia32"
        internal_contract(variant, "scalar_body_contract")
        entry_role_contract(variant, entry, 16)
        name, insns = instructions(variant, "capture_async_target")
        cases = [(entry, before_call(variant, entry, "capture_async_target", r"r1 = .*"), "r1 = r10"),
                 (entry, before_call(variant, entry, "capture_async_target", r"r2 = .*"), "r2 = r10"),
                 (name, site(variant, name, r"if r1 s> r0 goto .*"), "r0 = r0"),
                 (name, site(variant, name, r"if r0 s> 0x1c goto .*"), "r0 = r0")]
        for function, pc, new in cases:
            old = dict(instructions(variant, function)[1])[pc]
            with self.subTest(function=function, pc=pc), self.assertRaisesRegex(RuntimeError, "final-sink"):
                changed = mutate(OBJECTS[variant], function, pc, old, new)
                if function == entry:
                    entry_role_contract(variant, entry, 16, changed)
                else:
                    internal_contract(variant, "scalar_body_contract", changed)
        scalar, scalar_insns = instructions(variant, "capture_scalar")
        pc = site(variant, name, r"call 0x72")
        nested = mutate(OBJECTS[variant], name, pc, "call 0x72",
            f"call {scalar_insns[0][0]-pc-1:#x}", internal_call=True)
        with self.assertRaisesRegex(RuntimeError, "async callee reaches scalar/ia32 reader"):
            internal_contract(variant, "scalar_body_contract", nested)

    def test_async_target_does_not_nest_scalar_capture(self):
        for variant, disassembly in OBJECTS.items():
            with self.subTest(variant=variant):
                blocks = CHECKER["D"].function_blocks(disassembly)
                async_helpers = [name for name in blocks if name.endswith("capture_async_target")]
                self.assertLessEqual(len(async_helpers), 1)
                scalar = next(name for name in blocks if name.endswith("capture_scalar"))
                callees = {
                    target
                    for caller, _, _, target in CHECKER["D"].internal_call_targets(disassembly)
                    if async_helpers and caller == async_helpers[0]
                }
                self.assertNotIn(scalar, callees)

    def test_final_scalar_sink_controls(self):
        for variant in OBJECTS:
            names = ["p11_entry"] if variant == "default" else ["p11_entry", "p11_entry_ia32",
                "p11_entry_template", "p11_entry_template_pair", "p11_entry_template_types"]
            for name in names:
                entry_contract(variant, name)
                _, insns = instructions(variant, name)
                texts = dict(insns)
                scalar = call_site(variant, name, "capture_scalar")
                # Real caller context, descriptor index, ABI, START, Option
                # destination, then the full-width finite F6 boundary.
                args = {}
                for register in ("r1", "r2", "r3", "r4", "r5"):
                    args[register] = next((pc, text) for pc, text in reversed(insns)
                        if pc < scalar and re.match("[rw]"+register[1:]+r" (=|\+=) ", text))
                guard = site(variant, name, r"if r2 > r1 goto .*", 0)
                sentinel = next((pc, text) for pc, text in insns if pc > guard and text == "r1 = -0x1")
                init = next((pc, text) for pc, text in insns if text == "r1 = 0xffffffff ll")
                user_payload = next((pc, text) for pc, text in reversed(insns)
                    if pc < guard and re.fullmatch(r"r1 = \*\(u64 \*\)\(r10 - 0x[0-9a-f]+\)", text))
                cases = [(args["r2"][0], "r2 = r10"), (args["r3"][0], "r3 = 0xff"),
                         (args["r4"][0], "r4 = 0x2"), (args["r5"][0], "r5 = r10"),
                         (args["r1"][0], "r1 = r6"),
                         (guard, texts[guard].replace(" > ", " >= ")),
                         (guard, "goto +0x0"), (sentinel[0], "r1 = 0x0"),
                         (init[0], "r1 = 0x0")]
                # A truncated payload can turn 0x100000002 into CKU_CONTEXT_SPECIFIC.
                # IA32 legitimately produces only a zero-extended u32 payload.
                if name != "p11_entry_ia32":
                    cases.append((user_payload[0], user_payload[1].replace("u64", "u32")))
                    cases.append((guard, re.sub(r"\br(\d+)\b", r"w\1", texts[guard])))
                else:
                    entry_contract(variant, name, mutate(OBJECTS[variant], name, guard, texts[guard],
                        re.sub(r"\br(\d+)\b", r"w\1", texts[guard])))
                for pc, new in cases:
                    with self.subTest(variant=variant, function=name, pc=pc, mutation=new):
                        with self.assertRaisesRegex(RuntimeError, "final-sink"):
                            entry_contract(variant, name,
                                mutate(OBJECTS[variant], name, pc, texts[pc], new))
        # Exact interval complement includes every high-bit alias, not a sample
        # set inferred from current emitted values.
        entire = ((0, (1 << 64)-1),)
        self.assertEqual(CHECKER["finite_intervals"](entire, "<", 3, True), ((0, 2),))
        invalid = CHECKER["finite_intervals"](entire, "<", 3, False)
        self.assertEqual(invalid, ((3, 3), (4, (1 << 64)-1)))
        for value in (3, 0xffffffff, 1 << 32, (1 << 32)+1, (1 << 32)+2, (1 << 64)-1):
            self.assertTrue(any(low <= value <= high for low, high in invalid))

    def test_mode_and_return_sink_controls(self):
        for variant in OBJECTS:
            with self.subTest(variant=variant, control="healthy outlined returns"):
                try:
                    report = return_contract(variant)
                except RuntimeError as error:
                    self.fail("actual outlined return rejected: " + str(error))
                self.assertEqual(set(report["outlined"]), {"ordinary", "object"})
            root_name, root_insns = instructions(variant, "p11_return")
            root_texts = dict(root_insns)
            epilogue, epilogue_text = next((pc, text) for pc, text in reversed(root_insns)
                                           if text == "r0 = 0x0")
            for suffix in ("ordinary_return", "object_return"):
                alias = before_call(variant, root_name, suffix, r"r8 &= 0x1")
                # The accepted ABI is already 0/1 at this redundant mask.
                # A value snapshot may cross the retiring callee; an alias
                # to its original live START may not be read afterwards.
                snapshot = mutate(OBJECTS[variant], root_name, alias, root_texts[alias],
                                  "r9 = *(u32 *)(r0 + 0x38)")
                snapshot = mutate(snapshot, root_name, epilogue, epilogue_text, "r0 = r9")
                with self.subTest(variant=variant, call=suffix, control="caller snapshot survives retirement"):
                    self.assertTrue(all(CHECKER["contract"](snapshot, variant)["verified"].values()))
                stale = mutate(OBJECTS[variant], root_name, alias, root_texts[alias], "r9 = r0")
                stale = mutate(stale, root_name, epilogue, epilogue_text,
                               "r0 = *(u32 *)(r9 + 0x38)")
                with self.subTest(variant=variant, call=suffix, control="caller alias cannot outlive retirement"):
                    with self.assertRaisesRegex(RuntimeError, "return.*START read after retirement"):
                        CHECKER["contract"](stale, variant)
                # A saved pointer's nonnull value survives a callee, but the
                # lifetime of the original row does not. This later guard
                # must not reacquire ownership before the same stale read.
                guard, old_guard = next((pc, text) for pc, text in reversed(root_insns)
                                        if re.fullmatch(r"if r1 == 0x0 goto .*", text))
                exit_pc = root_insns[-1][0]
                new_guard = f"if r9 == 0x0 goto {exit_pc-guard-1:+#x}"
                guarded = mutate(stale, root_name, guard, old_guard, new_guard)
                with self.subTest(variant=variant, call=suffix, control="nonnull alias cannot revive retired row"):
                    with self.assertRaisesRegex(RuntimeError, "return.*START read after retirement"):
                        CHECKER["contract"](guarded, variant)
                guarded_snapshot = mutate(snapshot, root_name, guard, old_guard, new_guard)
                with self.subTest(variant=variant, call=suffix, control="guarded value snapshot survives retirement"):
                    self.assertTrue(all(CHECKER["contract"](guarded_snapshot, variant)["verified"].values()))
                for register, new in (("r1", "r1 = r10"), ("r2", "r2 += 0x8"),
                                      ("r3", "r3 = r10"), ("r4", "r4 = 0x0"), ("r5", "r5 = 0x2")):
                    pc = before_call(variant, root_name, suffix, register+r" (=|\+=) .*")
                    with self.subTest(variant=variant, call=suffix, parameter=register):
                        with self.assertRaisesRegex(RuntimeError, "return.*boundary"):
                            return_contract(variant, mutate(OBJECTS[variant], root_name, pc, root_texts[pc], new))
                name, insns = instructions(variant, suffix)
                texts = dict(insns)
                if suffix == "object_return":
                    clear = call_site(variant, name, "memset", 1)
                    base, old_base = next((pc, text) for pc, text in reversed(insns) if pc < clear and text == "r1 = r7")
                    offset, old_offset = next((pc, text) for pc, text in reversed(insns) if pc < clear and text == "r1 += 0x130")
                    clobber = mutate(OBJECTS[variant], name, base, old_base, "r1 = r4")
                    clobber = mutate(clobber, name, offset, old_offset, "r1 += 0x38")
                    with self.subTest(variant=variant, control="known writer cannot clobber live START"):
                        with self.assertRaisesRegex(RuntimeError, "return.*(immutable|footprint|output)"):
                            CHECKER["contract"](clobber, variant)
                # The caller's key is not this function's r10 frame.
                pc, old = next((pc, text) for pc, text in insns
                               if re.fullmatch(r"r[14] = \*\(u64 \*\)\(r2 \+ 0x0\)", text))
                with self.subTest(variant=variant, function=suffix, control="separate key frame"):
                    with self.assertRaisesRegex(RuntimeError, "return.*key"):
                        return_contract(variant, mutate(OBJECTS[variant], name, pc, old,
                            old.replace("(r2 +", "(r10 +")))
                reads = [pc for pc, text in insns if text == "call 0x70"]
                self.assertEqual(len(reads), 6)
                for call in reads:
                    width, old = next((pc, text) for pc, text in reversed(insns)
                                      if pc < call and text in ("r2 = 0x4", "r2 = 0x8"))
                    new = "r2 = 0x8" if old == "r2 = 0x4" else "r2 = 0x4"
                    with self.subTest(variant=variant, function=suffix, read=call):
                        with self.assertRaisesRegex(RuntimeError, "return|retained|layout"):
                            return_contract(variant, mutate(OBJECTS[variant], name, width, old, new))
                if suffix == "ordinary_return":
                    remove = call_site(variant, name, "p11_owner_start_remove")
                    pc, old = next((pc, text) for pc, text in insns if pc > remove
                                   and re.fullmatch(r"r1 = \*\(u64 \*\)\(r10 - 0x[0-9a-f]+\)", text))
                    with self.subTest(variant=variant, control="unknown outlined callee"):
                        with self.assertRaisesRegex(RuntimeError, "return.*(callee|unresolved)"):
                            return_contract(variant, mutate(OBJECTS[variant], name, pc, old,
                                "call 0x123456", internal_call=True))
                user_stores = [(pc, text) for pc, text in insns
                               if re.fullmatch(r"\*\(u32 \*\)\(r7 \+ 0x70\) = [rw]\d+", text)]
                self.assertEqual(len(user_stores), 1)
                pc, old = user_stores[0]
                with self.subTest(variant=variant, function=suffix, control="finite user type copy"):
                    with self.assertRaisesRegex(RuntimeError, "return.*user.type"):
                        return_contract(variant, mutate(OBJECTS[variant], name, pc, old, "r0 = r0"))
                if suffix == "object_return":
                    fill = call_site(variant, name, "object_fill_return")
                    pc, old = next((pc, text) for pc, text in insns if pc > fill
                                   and re.fullmatch(r"if r6 == 0x0 goto .*", text))
                    with self.subTest(variant=variant, control="failed emission cannot submit"):
                        with self.assertRaisesRegex(RuntimeError, "return.*emission"):
                            return_contract(variant, mutate(OBJECTS[variant], name, pc, old, "goto +0x0"))
                for caller, _, pc, target in CHECKER["D"].internal_call_targets(OBJECTS[variant]):
                    if caller == name and target == "p11_owner_start_remove":
                        with self.subTest(variant=variant, function=suffix, retirement=pc):
                            with self.assertRaisesRegex(RuntimeError, "return|retir|START"):
                                return_contract(variant, mutate(OBJECTS[variant], name, pc, texts[pc], "r0 = 0x0"))

    def test_scalar_index_register_alias(self):
        entry_contract("default", "p11_entry")
        pc = before_call("default", "p11_entry", "capture_scalar", r"r3 = r9", 1)
        changed = mutate(OBJECTS["default"], "p11_entry", pc, "r3 = r9", "w3 = w9")
        self.assertTrue(entry_contract("default", "p11_entry", changed))

    def test_jmp32_cannot_prove_full_pointer_or_address(self):
        for variant in OBJECTS:
            entry_role_contract(variant, "p11_entry", 8)
            pc, old = mechanism_guard(variant, "p11_entry")
            with self.subTest(variant=variant, boundary="pointer"), self.assertRaisesRegex(RuntimeError, "branch width 32.*full-width"):
                entry_role_contract(variant, "p11_entry", 8, mutate(OBJECTS[variant], "p11_entry", pc, old,
                    re.sub(r"\br(\d+)\b", r"w\1", old)))
            internal_contract(variant, "scalar_body_contract")
            for suffix, pattern in (("arg_u64", r"if r3 > -0x9 goto .*"),
                                    ("arg_u64", r"if r1 >= r3 goto .*"),
                                    ("p11_read_ia32_arg", r"if r3 > r1 goto .*")):
                name, insns = instructions(variant, suffix)
                pc = site(variant, name, pattern)
                old = dict(insns)[pc]
                with self.subTest(variant=variant, boundary=suffix, pc=pc), self.assertRaisesRegex(RuntimeError, "full-width|ia32.*span"):
                    internal_contract(variant, "scalar_body_contract", mutate(OBJECTS[variant], name, pc, old,
                        re.sub(r"\br(\d+)\b", r"w\1", old)))

    def test_full_pointer_branch_restoration(self):
        for variant in OBJECTS:
            pc, old = mechanism_guard(variant, "p11_entry")
            new = re.sub(r"\br(\d+)\b", r"w\1", old)
            changed = mutate(OBJECTS[variant], "p11_entry", pc, old, new)
            with self.assertRaisesRegex(RuntimeError, "branch width 32.*full-width"):
                entry_role_contract(variant, "p11_entry", 8, changed)
            restored = mutate(changed, "p11_entry", pc, new, old)
            self.assertEqual(restored, OBJECTS[variant])
            self.assertTrue(entry_role_contract(variant, "p11_entry", 8, restored).witnesses)

    def test_signed_pointer_sink_causal_pair(self):
        name = "p11_entry_ia32"
        entry_role_contract("unsafe", name, 8)
        _, insns = instructions("unsafe", name)
        guard, old = mechanism_guard("unsafe", name)
        register = CHECKER["BRANCH"].fullmatch(old)[1]
        original_null = CHECKER["D"].relative_target(guard, old)
        store, store_text = next((pc, text) for pc, text in insns if pc > guard)
        landing, landing_text = next((pc, text) for pc, text in insns if pc > store)
        # Move the real store onto the signed-positive edge. The false edge
        # retains the original null continuation. JMP64 is exact for u32;
        # JMP32 loses the obligation for high-bit u32 values.
        for spelling in ("r", "w"):
            changed = mutate(OBJECTS["unsafe"], name, guard, old,
                f"if {spelling+register[1:]} s> 0x0 goto {landing-guard-1:+#x}")
            changed = mutate(changed, name, store, store_text, f"goto {original_null-store-1:+#x}")
            changed = mutate(changed, name, landing, landing_text, store_text)
            with self.subTest(width=spelling):
                if spelling == "w":
                    with self.assertRaisesRegex(RuntimeError, "nonzero pointer predicate|decoder mechanism field|successful capture lost"):
                        entry_role_contract("unsafe", name, 8, changed)
                else:
                    self.assertTrue(entry_role_contract("unsafe", name, 8, changed).witnesses)

    def test_signed_u32_false_edge_keeps_sink_obligation(self):
        proof = CHECKER["SinkProof"](8, 1, True, ("stack", -0x128))
        state = {"r7": ("scalar", 8, 32), ("success",): True}
        for register in ("w7", "r7"):
            with self.subTest(register=register):
                consumer = SimpleNamespace(text={1: f"if {register} s> 0x0 goto +0x1"},
                                           graph={1: [2, 3]}, label=lambda pc: f"signed-pointer:{pc}")
                edges = dict(proof.edges(consumer, 1, state, state))
                if register == "w7":
                    self.assertIsNot(edges[2].get(("nonnull",)), False)
                    self.assertTrue(proof.required(edges[2]))
                    with self.assertRaisesRegex(RuntimeError, "nonzero pointer predicate not proved"):
                        proof.check_sink(consumer, 2, edges[2])
                else:
                    self.assertIs(edges[2].get(("nonnull",)), False)
                    self.assertFalse(proof.required(edges[2]))

    def test_map_pointer_refinement_requires_zero_partition(self):
        self._assert_entry_side_query_requires_key_null_and_start_lifetime()
        proof = CHECKER["SinkProof"](8, 0, True, ("stack", -0x128))
        for fact in (("descriptor", 77), ("owned", 77, 0), ("function_value", 77, 0)):
            for op in ("s>", ">=", "==", "!="):
                with self.subTest(fact=fact, op=op):
                    state = {"r7": fact}
                    consumer = SimpleNamespace(text={1: f"if r7 {op} 0x0 goto +0x1"},
                                               graph={1: [2, 3]}, label=lambda pc: f"map-pointer:{pc}")
                    edges = dict(proof.edges(consumer, 1, state, state))
                    if op in ("s>", ">="):
                        # These predicates do not partition all u64 pointers
                        # into exactly zero and nonzero classes.
                        for edge in edges.values():
                            self.assertEqual(edge["r7"], fact)
                            self.assertIsNot(edge.get(("live", 77)), True)
                        if op == "s>":
                            self.assertEqual(set(edges), {2, 3})
                    else:
                        zero_edge, nonzero_edge = (3, 2) if op == "==" else (2, 3)
                        if fact[0] == "descriptor":
                            self.assertEqual(set(edges), {nonzero_edge})
                        else:
                            self.assertEqual(edges[zero_edge]["r7"], ("constant", 0))
                            self.assertIs(edges[nonzero_edge][("live", 77)], True)
        # Exercise the real call transfer followed by the shared null edge.
        # Callee-saved registers and a spilled alias all retain the original
        # owner identity; only a copied field value survives its retirement.
        for family in ("root", "ordinary", "object", "entry"):
            section, name = ("uprobe", "p11_entry") if family == "entry" else ("uretprobe", "p11_return")
            lines = CHECKER["D"].function_blocks(OBJECTS["default"])[name]
            cls = CHECKER["_OwnedCaller"] if family == "entry" else CHECKER["_ReturnCaller"]
            consumer = cls(section, name, lines, {})
            pcs = [pc for pc, _ in consumer.insns[:6]]
            snapshot_pc, spill_pc, retire_pc, reload_pc, guard_pc, load_pc = pcs
            if family == "root":
                proof = CHECKER["_ReturnRootProof"](0, 77, {retire_pc: "ordinary"})
                target = "ordinary_return"
            elif family == "entry":
                proof = CHECKER["_OwnedSinkProof"](6, 0, True, ("owned", 77, 0))
                target = "p11_owner_start_remove"
            else:
                proof = CHECKER["_ReturnProof"](0, True, 77, family, {})
                target = "p11_owner_start_remove"
            consumer.proof = proof
            consumer.helper.difference_update(pcs)
            for pc in pcs:
                consumer.maps.pop(pc, None)
            identity = consumer.identity if family != "entry" else (section, name)
            state = {"r10": ("stack", 0), "r3": ("owned", 77, 0),
                "r4": ("scope_flags", identity), "r5": ("constant", 0),
                **{f"r{n}": ("owned", 77, 0) for n in range(6, 10)},
                ("stack", -0x40, 8): ("pid_tgid", identity),
                ("stack", -0x38, 4): ("low", identity),
                ("stack", -0x34, 4): ("constant", 0),
                ("stack", -0x60, 8): ("owned", 77, 0),
                ("owned_word", 77, 0x38, 4): ("constant", 2),
                ("live", 77): True, ("object_mode",): False}
            state["r8"] = ("owned", 77, 0x38)
            state.update({"r1": ("context", 0), "r2": ("stack", -0x40)} if family == "root"
                         else {"r1": ("stack", -0x40), "r2": ("constant", 1)})
            consumer.text[snapshot_pc] = "r0 = *(u32 *)(r6 + 0x38)"
            snapshot_state = consumer.step(snapshot_pc, state)
            consumer.text[spill_pc] = "*(u64 *)(r10 - 0x80) = r0"
            snapshot_state = consumer.step(spill_pc, snapshot_state)
            consumer.text[retire_pc] = "call -0x1"
            consumer.calls[retire_pc] = target
            expired = consumer.step(retire_pc, snapshot_state)
            self.assertIsNot(expired.get(("live", 77)), True)
            for alias in ("r6", "r7", "r8", "r9", "spill"):
                candidate = expired
                register = "r6" if alias == "spill" else alias
                if alias == "spill":
                    consumer.text[reload_pc] = "r6 = *(u64 *)(r10 - 0x60)"
                    candidate = consumer.step(reload_pc, candidate)
                consumer.text[guard_pc] = f"if {register} != 0x0 goto +0x1"
                consumer.graph[guard_pc] = [guard_pc+1, guard_pc+2]
                refined = dict(proof.edges(consumer, guard_pc, candidate, candidate))[guard_pc+2]
                with self.subTest(family=family, alias=alias):
                    self.assertIsNot(refined.get(("live", 77)), True)
                    consumer.text[load_pc] = f"r0 = *(u32 *)({register} + 0x38)"
                    with self.assertRaisesRegex(RuntimeError, "START.*(lifetime|retirement)"):
                        consumer.step(load_pc, refined)
                    consumer.text[load_pc] = "r0 = *(u64 *)(r10 - 0x80)"
                    snapshot_fact = ("constant", 2) if family == "entry" else ("retained", 0x38, 32)
                    self.assertEqual(consumer.step(load_pc, refined)["r0"], snapshot_fact)
            consumer.text[guard_pc] = "if r6 != 0x0 goto +0x1"
            null_snapshot = {key: (("constant", 0) if val == ("owned", 77, 0) else val)
                             for key, val in snapshot_state.items() if key != ("live", 77)}
            for predecessors in ((expired, snapshot_state), (snapshot_state, expired),
                                 (expired, null_snapshot), (null_snapshot, expired)):
                merged = proof.join(*predecessors)
                refined = dict(proof.edges(consumer, guard_pc, merged, merged))[guard_pc+2]
                with self.subTest(family=family, retired_first=predecessors[0] is expired,
                                  control="retirement survives a live predecessor join"):
                    self.assertIsNot(refined.get(("live", 77)), True)
                    consumer.text[load_pc] = "r0 = *(u32 *)(r6 + 0x38)"
                    with self.assertRaisesRegex(RuntimeError, "START.*(lifetime|retirement)"):
                        consumer.step(load_pc, refined)
        # A new constructor receives a distinct owner token without granting
        # another lifetime to any of the original row's saved aliases.
        generic = CHECKER["SinkProof"](6, 0, True, ("stack", -0x128))
        self.assertNotIn(("stack", -0x80, 8), generic.join({}, merged),
                         "a value snapshot needs provenance on both predecessors")
        fresh = CHECKER["_OwnedCaller"]("uprobe", "p11_entry", lines, {retire_pc: "p11_owner_start_begin"})
        fresh.helper.discard(retire_pc)
        fresh.maps.pop(retire_pc, None)
        fresh.text[retire_pc] = "call -0x1"
        fresh.proof = generic
        acquired = fresh.step(retire_pc, merged)
        self.assertEqual(acquired["r0"], ("owned", retire_pc, 0))
        fresh.text[guard_pc] = "if r0 != 0x0 goto +0x1"
        fresh.graph[guard_pc] = [guard_pc+1, guard_pc+2]
        acquired = dict(generic.edges(fresh, guard_pc, acquired, acquired))[guard_pc+2]
        self.assertIs(acquired[("live", retire_pc)], True)
        self.assertIsNot(acquired.get(("live", 77)), True)
        fresh.text[guard_pc] = "if r6 != 0x0 goto +0x1"
        original = dict(generic.edges(fresh, guard_pc, acquired, acquired))[guard_pc+2]
        self.assertIsNot(original.get(("live", 77)), True)
        self.assertIs(original[("live", retire_pc)], True)

    def test_proven_32bit_comparisons_and_shared_index_alias(self):
        # Descriptor bytes and normalized IA32 user words may use JMP32;
        # mixed register-copy spellings must still truncate their source.
        for variant in OBJECTS:
            entry_contract(variant, "p11_entry")
            split = CHECKER["sections"](OBJECTS[variant])
            lines = CHECKER["D"].function_blocks(split["uprobe"])["p11_entry"]
            consumer = CHECKER["_OwnedCaller"]("uprobe", "p11_entry", lines, {})
            proof = CHECKER["_OwnedSinkProof"](11, 0, True, ("owned", 7, 0))
            pc = consumer.insns[0][0]
            consumer.proof = proof
            for copy in ("r1 = w6", "w1 = r6", "w1 = w6"):
                with self.subTest(variant=variant, copy=copy):
                    consumer.text[pc] = copy
                    state = consumer.step(pc, {"r6": ("scalar", 11, 64)})
                    self.assertEqual(state.get("r1"), ("scalar", 11, 32))
            consumer.proof = None
        self.assertEqual(CHECKER["finite_intervals"](((0, (1 << 64)-1),), "==", -1, True),
                         (((1 << 64)-1, (1 << 64)-1),))
        # The actual IA32 capture returns zero-extended u32 facts, so its
        # finite classifier's comparison is a valid narrowed healthy twin.
        name = "p11_entry_ia32"
        _, insns = instructions("unsafe", name)
        pc = site("unsafe", name, r"if r2 > r1 goto .*", 0)
        old = dict(insns)[pc]
        self.assertTrue(entry_contract("unsafe", name, mutate(OBJECTS["unsafe"], name, pc, old,
            re.sub(r"\br(\d+)\b", r"w\1", old))))

    def test_async_callee_and_deleted_decoder_boundaries(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        async_name = next(name for name in blocks if name.endswith("capture_async_target"))
        cases = [(async_name, site("unsafe", async_name, r"r3 = r1"), "r3 = r7"),
                 (async_name, site("unsafe", async_name, r"r2 = 0x1d"), "r2 = 0x1c"),
                 (async_name, site("unsafe", async_name, r"\*\(u32 \*\)\(r6 \+ 0x104\) = [rw]1"), "r1 = r1"),
                 (async_name, site("unsafe", async_name, r"\*\(u32 \*\)\(r6 \+ 0x104\) = [rw]1"), "*(u32 *)(r6 + 0x100) = w1"),
                 ("p11_entry", call_site("unsafe", "p11_entry", "p11_decode_params"), "r0 = 0x0"),
                 ("p11_entry_template", call_site("unsafe", "p11_entry_template", "p11_decode_params"), "r0 = 0x0")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc, new=new):
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink|mode|decoder"):
                    CHECKER["contract"](mutate(OBJECTS["unsafe"], name, pc, old, new), "unsafe")

    def test_each_final_role_store_cannot_disappear(self):
        # These are independently specified CallStart fields. Owned construction
        # is not evidence that any semantic capture reached its destination.
        expected = {6: (8, 8), 7: (0x10, 8), 10: (0x28, 8), 11: (0x38, 4),
                    8: (0x20, 8), 9: (0x30, 8), "join": (0x58, 8), "get": (0x30, 8)}
        for variant in OBJECTS:
            names = ["p11_entry"] if variant == "default" else ["p11_entry", "p11_entry_ia32",
                "p11_entry_template", "p11_entry_template_pair", "p11_entry_template_types"]
            for name in names:
                with self.subTest(variant=variant, function=name, control="healthy"):
                    try:
                        result = entry_contract(variant, name)
                    except RuntimeError as error:
                        self.fail("actual owned-START sink rejected: " + str(error))
                    self.assertIn(11, result["roles"])
                _, insns = instructions(variant, name)
                calls = [pc for caller, _, pc, target in CHECKER["D"].internal_call_targets(OBJECTS[variant])
                         if caller == name and target.endswith("capture_scalar")]
                roles = (6, 7, 10, 11, 9, 8) + ((16, "join", "get") if name in ("p11_entry", "p11_entry_ia32") else (12, 13))
                self.assertEqual(len(calls), len(roles))
                for role, (offset, size) in expected.items():
                    if role not in roles:
                        continue
                    call = calls[roles.index(role)]
                    end = calls[roles.index(role)+1] if roles.index(role)+1 < len(calls) else insns[-1][0]+1
                    stores = [(pc, text) for pc, text in insns if call < pc < end
                              and re.fullmatch(rf"\*\(u{size*8} \*\)\(r[6-9] \+ {offset:#x}\) = [rw]\d+", text)]
                    self.assertEqual(len(stores), 1, (name, role, stores))
                    pc, old = stores[0]
                    with self.subTest(variant=variant, function=name, role=role):
                        with self.assertRaisesRegex(RuntimeError, "final-sink"):
                            entry_contract(variant, name,
                                mutate(OBJECTS[variant], name, pc, old, "r0 = r0"))

    def test_callee_scalar_reads_and_option_success(self):
        for variant in OBJECTS:
            internal_contract(variant, "scalar_body_contract")
            cases = [
                ("arg_u64", r"r2 = r3", "r2 = r4"),
                ("arg_u64", r"r1 = \*\(u64 \*\)\(r2 \+ 0x98\)", "r1 = r10"),
                ("arg_u64", r"call -0x1", "r0 = 0x0"),
                ("arg_u64", r"r2 = 0x8", "r2 = 0x4"),
                ("arg_u64", r"r1 = \*\(u64 \*\)\(r2 \+ 0x70\)", "r1 = *(u64 *)(r2 + 0x68)"),
                ("arg_u64", r"r7 = 0x0", "r7 = 0x1"),
                ("arg_u64", r"\*\(u64 \*\)\(r6 \+ 0x8\) = r0", "*(u64 *)(r6 + 0x0) = r0"),
                ("arg_u64", r"if r0 > r1 goto .*", "if w0 > w1 goto +0x11"),
                ("arg_u64", r"r1 = \*\(u64 \*\)\(r10 - 0x8\)", "r1 = *(u32 *)(r10 - 0x8)"),
                ("arg_u64", r"if r3 > -0x9 goto .*", "r3 = r3"),
                ("arg_u64", r"if r1 >= r3 goto .*", "goto +0x0"),
                ("arg_u64", r"if r1 >= r3 goto .*", "if w1 >= w3 goto +0xc"),
                ("capture_scalar", r"r1 = 0x1", "r1 = 0x0"),
                ("capture_scalar", r"r1 = \*\(u64 \*\)\(r10 - 0x10\)", "r1 = *(u32 *)(r10 - 0x10)"),
                ("capture_scalar", r"if r1 != 0x0 goto .*", "if r1 == 0x0 goto +0x1"),
                ("capture_scalar", r"\*\(u32 \*\)\(r7 \+ 0x100\) = w1", "*(u32 *)(r7 + 0x104) = w1"),
            ]
            for suffix, pattern, new in cases:
                name, instructions_ = instructions(variant, suffix)
                insns = dict(instructions_)
                pc = site(variant, name, pattern)
                with self.subTest(variant=variant, function=suffix, mutation=pattern):
                    with self.assertRaisesRegex(RuntimeError, "scalar-read|final-sink"):
                        internal_contract(variant, "scalar_body_contract",
                            mutate(OBJECTS[variant], name, pc, insns[pc], new))

    def test_template_order_layout_and_disabled_controls(self):
        for suffix, walker, destination in (("p11_entry_template", "p11_walk_template", 0x60),
                ("p11_entry_template_pair", "p11_walk_template", 0x60),
                ("p11_entry_template_types", "p11_walk_template_types", 0x60),
                ("p11_entry_template_second", "p11_walk_template", 0xb0)):
            entry_contract("unsafe", suffix)
            name, insns = instructions("unsafe", suffix)
            call = call_site("unsafe", name, walker)
            texts = dict(insns)
            cases = [(before_call("unsafe", name, walker, rf"r4 \+= {destination:#x}"), "r4 += 0x58"),
                     (before_call("unsafe", name, walker, r"r3 = 0x4"), "r3 = 0x8"),
                     (before_call("unsafe", name, walker, r"r3 = 0x8"), "r3 = 0x4"),
                     (before_call("unsafe", name, walker, r"r1 = .*"), "r1 = r2"),
                     (before_call("unsafe", name, walker, r"r2 = .*"), "r2 = r1"),
                     (call, "r0 = 0x0")]
            for pc, new in cases:
                with self.subTest(function=name, pc=pc), self.assertRaisesRegex(RuntimeError, "final-sink|layout|mode"):
                    entry_contract("unsafe", name, mutate(OBJECTS["unsafe"], name, pc, texts[pc], new))

    def test_ordinary_walker_cannot_become_types_walker(self):
        changed, count = re.subn(r"(R_BPF_64_32[ \t]+)p11_walk_template\b",
                                 lambda match: match[1] + "p11_walk_template_types",
                                 OBJECTS["unsafe"], count=1)
        self.assertEqual(count, 1, "actual ordinary-walker relocation must exist")
        with self.assertRaisesRegex(RuntimeError, "final-sink.*mode walker callee"):
            CHECKER["contract"](changed, "unsafe")

    def test_types_walker_cannot_become_ordinary_walker(self):
        changed, count = re.subn(r"(R_BPF_64_32[ \t]+)p11_walk_template_types\b",
                                 lambda match: match[1] + "p11_walk_template",
                                 OBJECTS["unsafe"], count=1)
        self.assertEqual(count, 1, "actual types-walker relocation must exist")
        with self.assertRaisesRegex(RuntimeError, "final-sink.*mode walker callee"):
            CHECKER["contract"](changed, "unsafe")

    def test_types_walker_cannot_call_local_directly(self):
        call = call_site("unsafe", "p11_entry_template_types", "p11_walk_template_types")
        for fragment in ("walk_template_typesKb0_", "walk_template_typesKb1_"):
            with self.subTest(local=fragment):
                name = next(n for n in CHECKER["D"].function_blocks(OBJECTS["unsafe"])
                            if fragment in n)
                relocated, count = re.subn(
                    r"(R_BPF_64_32[ \t]+)p11_walk_template_types\b",
                    lambda match: match[1] + name, OBJECTS["unsafe"], count=1)
                self.assertEqual(count, 1, "actual types-walker relocation must exist")
                old = dict(CHECKER["D"].instructions(
                    CHECKER["D"].function_blocks(relocated)["p11_entry_template_types"]))[call]
                changed = mutate(relocated, "p11_entry_template_types", call, old,
                                 internal_callee_instruction("unsafe", fragment))
                resolved = [target for caller, _, pc, target
                            in CHECKER["D"].internal_call_targets(changed)
                            if caller == "p11_entry_template_types" and pc == call]
                self.assertEqual(resolved, [name])
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    CHECKER["contract"](changed, "unsafe")

    def test_post_capture_overlap_and_atomic_corruption(self):
        entry_role_contract("default", "p11_entry", 6)
        name, insns = instructions("default", "p11_entry")
        pc, old = next((pc, text) for pc, text in insns
                       if re.fullmatch(r"\*\(u64 \*\)\(r8 \+ 0x28\) = r1", text))
        # An atomic write elsewhere in the owned row cannot erase local
        # descriptor/Option facts or the disjoint session field.
        disjoint = mutate(OBJECTS["default"], name, pc, old, "lock *(u64 *)(r8 + 0x100) += r1")
        self.assertTrue(entry_role_contract("default", name, 6, disjoint).witnesses)
        for new in ("*(u32 *)(r8 + 0x9) = w1", "r1 = atomic_fetch_or((u64 *)(r8 + 0x8), r1)"):
            with self.subTest(new=new):
                changed = mutate(OBJECTS["default"], name, pc, old, new)
                with self.assertRaisesRegex(RuntimeError, "final-sink 6: successful capture lost"):
                    entry_role_contract("default", name, 6, changed)
                restored = mutate(changed, name, pc, new, old)
                self.assertEqual(restored, OBJECTS["default"])
                self.assertTrue(entry_role_contract("default", name, 6, restored).witnesses)

    def test_unknown_postwrite_and_callee_start_clobber(self):
        for variant in OBJECTS:
            entry_contract(variant, "p11_entry")
            name, insns = instructions(variant, "p11_entry")
            epilogue = next((pc, text) for pc, text in reversed(insns)
                            if text == "r0 = 0x0")
            # An unresolved call at the final live exit cannot inherit the
            # field guarantees established before it, even with no pointer arg.
            with self.subTest(variant=variant, control="unknown call"):
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    entry_contract(variant, name, mutate(OBJECTS[variant], name, epilogue[0],
                        epilogue[1], "call 0x123456", internal_call=True))
            with self.subTest(variant=variant, control="unknown write"):
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    entry_contract(variant, name, mutate(OBJECTS[variant], name, epilogue[0],
                        epilogue[1], "*(u64 *)(r5 + 0x0) = r4"))
            internal_contract(variant, "scalar_body_contract")
            self.assertTrue(all(CHECKER["contract"](OBJECTS[variant], variant)["verified"].values()))
            for suffix, pattern in (("arg_u64", r"r7 = 0x0"),
                                    ("capture_scalar", r"r1 \|= 0x10")):
                callee, body = instructions(variant, suffix)
                pc = site(variant, callee, pattern)
                changed = mutate(OBJECTS[variant], callee, pc, dict(body)[pc],
                                 "call 0x123456", internal_call=True)
                with self.subTest(variant=variant, callee=suffix, control="unresolved scalar call"):
                    with self.assertRaisesRegex(RuntimeError, "scalar-read.*(callee|call)"):
                        CHECKER["contract"](changed, variant)
            scalar, scalar_insns = instructions(variant, "capture_scalar")
            pc, old = next((pc, text) for pc, text in scalar_insns
                           if re.fullmatch(r"\*\(u32 \*\)\(r7 \+ 0x100\) = [rw]1", text))
            with self.subTest(variant=variant, control="callee START clobber"):
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    internal_contract(variant, "scalar_body_contract", mutate(OBJECTS[variant], scalar, pc,
                        old, old.replace("+ 0x100", "+ 0x8")))

    def test_helper_invocation_without_success_path_is_insufficient(self):
        for variant in OBJECTS:
            internal_contract(variant, "scalar_body_contract")
            name, insns = instructions(variant, "arg_u64")
            read = site(variant, name, r"call 0x70")
            pc, old = next((pc, text) for pc, text in insns if pc > read and text.startswith("if "))
            with self.subTest(variant=variant, boundary="Result"), self.assertRaisesRegex(RuntimeError, "scalar-read 6: incomplete index coverage"):
                internal_contract(variant, "scalar_body_contract", mutate(OBJECTS[variant], name, pc, old,
                    "goto +0x0"))  # Force the actual Result::Err arm after a successful read.
            name, insns = instructions(variant, "capture_scalar")
            pc = site(variant, name, r"if r1 != 0x0 goto .*", 0)
            old = dict(insns)[pc]
            with self.subTest(variant=variant, boundary="Option"), self.assertRaisesRegex(RuntimeError, "final-sink 6: no positive successful sink witness"):
                internal_contract(variant, "scalar_body_contract", mutate(OBJECTS[variant], name, pc, old,
                    "goto "+old.split(" goto ")[1]))

    def test_success_cannot_exit_before_sink_or_lose_pair_tail(self):
        entry_role_contract("unsafe", "p11_entry", 6)
        name, insns = instructions("unsafe", "p11_entry")
        call = call_site("unsafe", name, "capture_scalar")
        pc, old = next((pc, text) for pc, text in insns if pc > call and text.startswith("if "))
        exit_pc = site("unsafe", name, "exit")
        with self.assertRaisesRegex(RuntimeError, "final-sink"):
            entry_role_contract("unsafe", name, 6, mutate(OBJECTS["unsafe"], name, pc, old,
                old.split(" goto ")[0]+f" goto {exit_pc-pc-1:+#x}"))
        name = "p11_entry_template_pair"
        entry_contract("unsafe", name)
        consumer, initial, _, _ = consumer_case("unsafe", name)
        facts = consumer.facts(initial)
        tails = [pc for pc, text in consumer.insns if text == "call 0xc"
                 and facts.get(pc, {}).get("r2") == ("map", "PAIR_CALLS")]
        self.assertEqual(len(tails), 1)
        tail = tails[0]
        with self.assertRaisesRegex(RuntimeError, "final-sink.*tail"):
            entry_contract("unsafe", name, mutate(OBJECTS["unsafe"], name, tail, "call 0xc", "r0 = 0x0"))
        # Failure must disclose the failed transfer while retaining START.
        failure = next(pc for pc, text in consumer.insns if pc > tail and text == "call 0x1"
                       and facts.get(pc, {}).get("r1") == ("map", "EVIDENCE")
                       and CHECKER["stack_read"](facts[pc], facts[pc].get("r2"), 4) == ("constant", 6))
        add, old = next((pc, text) for pc, text in consumer.insns if pc > failure and text.startswith("lock "))
        with self.assertRaisesRegex(RuntimeError, "pair.*failure"):
            entry_contract("unsafe", name, mutate(OBJECTS["unsafe"], name, add, old, "r1 = r1"))
        key, old = next((pc, text) for pc, text in consumer.insns if tail < pc < failure
                        and re.fullmatch(r"r\d+ = 0x6", text))
        exit_pc = site("unsafe", name, "exit")
        for new in (old.replace("0x6", "0x5"), f"goto {exit_pc-key-1:+#x}"):
            with self.subTest(failure=new), self.assertRaisesRegex(RuntimeError, "pair.*failure"):
                entry_contract("unsafe", name, mutate(OBJECTS["unsafe"], name, key, old, new))

    def test_unchanged_objects(self):
        for variant, disassembly in OBJECTS.items():
            with self.subTest(variant=variant):
                report = CHECKER["contract"](disassembly, variant)
                self.assertEqual(report["status"], "partial")
                self.assertTrue(all(report["verified"].values()))

    def test_actual_instruction_controls(self):
        for variant in OBJECTS:
            for suffix in ("p11_entry", "p11_return"):
                consumer_contract(variant, suffix)
                consumer, initial, _, _ = consumer_case(variant, suffix)
                facts = consumer.facts(initial)
                mutations = []
                for pc, text in consumer.insns:
                    shift = re.fullmatch(r"(r\d+) (<<=|>>=) 0x20", text)
                    if shift and facts.get(pc, {}).get(shift[1], (None,))[0] in ("cookie", "low_shifted"):
                        mutations.append((pc, text, text.replace("0x20", "0x1f")))
                    if re.fullmatch(r"if r\d+ > 0x1ff goto .*", text):
                        mutations.append((pc, text, "goto +0x0"))
                cookies = [pc for pc, text in consumer.insns if pc in consumer.helper and text == "call 0xae"]
                first = cookies[0]
                pc, old = next((pc, text) for pc, text in reversed(consumer.insns) if pc < first and text.startswith("r1 = "))
                mutations.append((pc, old, "r1 = r10"))
                self.assertGreaterEqual(len(mutations), 4)
                for pc, old, new in mutations:
                    with self.subTest(variant=variant, function=suffix, pc=pc), self.assertRaises(RuntimeError):
                        consumer_contract(variant, suffix, mutate(OBJECTS[variant], consumer.name, pc, old, new))

    def test_each_consumer_descriptor_fields_and_word(self):
        for variant in OBJECTS:
            split = CHECKER["sections"](OBJECTS[variant])
            all_calls = CHECKER["D"].internal_call_targets(split["uprobe"]+"\n"+split[".text"])
            for section in ("uprobe", ".text"):
                for name, lines in CHECKER["D"].function_blocks(split[section]).items():
                    outlined = name.endswith(("ordinary_return", "object_return"))
                    if not (name.startswith("p11_entry") or outlined):
                        continue
                    consumer = CHECKER["_ReturnCaller" if outlined else "_SeedCaller"](section, name, lines,
                        {pc: target for caller, _, pc, target in all_calls if caller == name})
                    initial = {"r1": ("context", 0), "r2": ("external_key", ("uretprobe", "p11_return"), 0),
                        "r3": ("owned", 7, 0), "r4": ("scope_flags", ("uretprobe", "p11_return")),
                        "r5": ("constant", 0), "r10": ("stack", 0)} if outlined else None
                    facts = consumer.facts(initial)
                    if outlined:
                        for pc, text in consumer.insns:
                            state = facts.get(pc, {})
                            kind = state.get("r1")
                            if pc in consumer.helper and text in ("call 0x1", "call 0x2") and kind in (
                                    ("map", "DESCRIPTORS"), ("map", "STATS"), ("map", "RV_COUNTS")):
                                with self.subTest(variant=variant, function=name, map=kind[1], pc=pc):
                                    expected = "high" if kind[1] == "DESCRIPTORS" else "low"
                                    self.assertEqual(CHECKER["stack_read"](state, state.get("r2"), 4),
                                        (expected, ("uretprobe", "p11_return")))
                    lookups = [pc for pc, text in consumer.insns if pc in consumer.helper and text == "call 0x1"
                               and facts.get(pc, {}).get("r1") == ("map", "DESCRIPTORS")]
                    groups = [{3}] if outlined else [{14, 15}] if name.endswith("template_second") else [
                        {3, 6, 7, 8, 9, 10, 11} | ({12, 13} if "template" in name else {16, 17}), {5}]
                    self.assertEqual(len(lookups), len(groups))
                    for lookup, expected in zip(lookups, groups):
                        with self.subTest(variant=variant, function=name, lookup=lookup, control="healthy"):
                            try:
                                fields = CHECKER["descriptor_contract"](consumer, facts, lookup)
                            except RuntimeError as error:
                                self.fail("actual descriptor materialization rejected: "+str(error))
                            self.assertEqual(set(fields), expected)
                        loads = [(pc, text) for pc, text in consumer.insns if (m := CHECKER["LOAD"].fullmatch(text))
                            and (pointer := CHECKER["address"](facts.get(pc, {}), m[3], m[4], m[5]))
                            and pointer[:2] == ("descriptor", lookup)]
                        self.assertEqual(len(loads), len(expected))
                        for pc, old in loads:
                            with self.subTest(variant=variant, function=name, mutation=pc):
                                changed = mutate(OBJECTS[variant], name, pc, old, old.replace("u8", "u16"))
                                changed_lines = CHECKER["D"].function_blocks(changed)[name]
                                mutant = type(consumer)(section, name, changed_lines, consumer.calls)
                                with self.assertRaisesRegex(RuntimeError, "descriptor"):
                                    CHECKER["descriptor_contract"](mutant, mutant.facts(initial), lookup)

    def test_diagnostic_specialization_and_template_cleanup(self):
        for suffix in consumer_names("unsafe"):
            consumer, initial, _, outlined = consumer_case("unsafe", suffix)
            if outlined:
                continue  # ABI admission is proved at the actual root caller.
            facts = consumer.facts(initial)
            CHECKER["abi_contract"](consumer, facts, "unsafe")
            # LP64-only p11_entry's 0x23 classification is redundant after
            # specialization; its actual admission decision is the 0x33 arm.
            admitted = "0x33" if suffix == "p11_entry" else "0x23"
            pc, old = next((pc, text) for pc, text in consumer.insns
                if (m := CHECKER["BRANCH"].fullmatch(text)) and m[2] == "==" and m[3] == admitted
                and CHECKER["value"](facts.get(pc, {}), m[1]) == ("selector",))
            for new in ("goto "+old.split(" goto ")[1], re.sub(r"\br(\d+)\b", r"w\1", old)):
                changed = mutate(OBJECTS["unsafe"], consumer.name, pc, old, new)
                mutant, initial, _, _ = consumer_case("unsafe", suffix, changed)
                with self.subTest(function=suffix, control=new), self.assertRaisesRegex(RuntimeError, "ABI|selector"):
                    CHECKER["abi_contract"](mutant, mutant.facts(initial), "unsafe")
            # Several refusal counters share a merged lookup block. Locate
            # the literal key in the ABI prefix, before admission, rather
            # than inventing a constant at that merged helper state.
            selector = next(pc for pc, text in consumer.insns if (m := CHECKER["LOAD"].fullmatch(text))
                and CHECKER["address"](facts.get(pc, {}), m[3], m[4], m[5]) == ("context", 0x88))
            admissions = {pc for pc, text in consumer.insns if
                (text == "call 0x1" and facts.get(pc, {}).get("r1") == ("map", "STATS"))
                or consumer.calls.get(pc) in ("p11_owner_start_get", "p11_owner_start_begin")}
            prefix = CHECKER["D"].reachable(consumer.graph, [selector], blocked=admissions)
            refusals = [(pc, text) for pc, text in consumer.insns if pc in prefix
                        and re.fullmatch(r"[rw]\d+ = 0x8", text)]
            self.assertTrue(refusals)
            for store, old in refusals:
                changed = mutate(OBJECTS["unsafe"], consumer.name, store, old, old.rsplit(" = ", 1)[0]+" = 0x7")
                mutant, initial, _, _ = consumer_case("unsafe", suffix, changed)
                with self.subTest(function=suffix, refusal=store), self.assertRaisesRegex(RuntimeError, "ABI refusal evidence"):
                    CHECKER["abi_contract"](mutant, mutant.facts(initial), "unsafe")

    def test_register_aliases_and_unknown_writes(self):
        consumer_contract("default", "p11_entry")
        name, insns = instructions("default", "p11_entry")
        pc, old = next((pc, text) for pc, text in insns if re.fullmatch(r"r\d+ = 0xff", text))
        register = old.split(" = ")[0]
        healthy = mutate(OBJECTS["default"], name, pc, old, "w"+register[1:]+" = 0xff")
        self.assertTrue(consumer_contract("default", name, healthy))
        changed = mutate(OBJECTS["default"], name, pc, old, "w"+register[1:]+" ^= 0xff")
        with self.assertRaisesRegex(RuntimeError, "COUNT_ONLY|descriptor"):
            consumer_contract("default", name, changed)

    def test_each_required_operation_cannot_disappear(self):
        for variant in OBJECTS:
            for suffix in consumer_names(variant):
                report = consumer_contract(variant, suffix)
                consumer, _, _, _ = consumer_case(variant, suffix)
                self.assertTrue(report["operations"])
                for pc, operation in report["operations"]:
                    with self.subTest(variant=variant, function=suffix, pc=pc, operation=operation):
                        changed = mutate(OBJECTS[variant], consumer.name, pc, consumer.text[pc], "r0 = 0x0")
                        with self.assertRaises(RuntimeError):
                            consumer_contract(variant, suffix, changed)

    def test_full_start_key_in_every_consumer(self):
        for variant in OBJECTS:
            for suffix in consumer_names(variant):
                consumer_contract(variant, suffix)
                consumer, initial, _, outlined = consumer_case(variant, suffix)
                facts = consumer.facts(initial)
                first = min(pc for pc, target in consumer.calls.items() if target.startswith("p11_owner_start_"))
                key = facts[first]["r1"]
                identity = consumer.identity if outlined or suffix == "p11_return" else (consumer.section, consumer.name)
                controls = []
                for pc, text in consumer.insns:
                    if pc >= first:
                        continue
                    if outlined and (m := CHECKER["LOAD"].fullmatch(text)):
                        pointer = CHECKER["address"](facts.get(pc, {}), m[3], m[4], m[5])
                        if pointer and pointer[0] == "external_key":
                            controls.append((pc, text, text.replace("(r2 +", "(r10 +")))
                    elif not outlined and (m := CHECKER["STORE"].fullmatch(text)):
                        pointer = CHECKER["address"](facts.get(pc, {}), m[2], m[3], m[4])
                        expected = {key[1]: ("pid_tgid", identity), key[1]+8: ("low", identity), key[1]+12: ("constant", 0)}
                        if (pointer and pointer[0] == "stack" and pointer[1] in expected
                                and CHECKER["narrow"](CHECKER["value"](facts[pc], m[5]), int(m[1])) == expected[pointer[1]]):
                            controls.append((pc, text, text.rsplit(" = ", 1)[0]+" = r10"))
                    if not outlined and text == "call 0xe":
                        controls.append((pc, text, "call 0x5"))
                self.assertEqual(len(controls), 2 if outlined else 4, (variant, suffix, controls))
                for pc, old, new in controls:
                    with self.subTest(variant=variant, function=suffix, pc=pc), self.assertRaises(RuntimeError):
                        consumer_contract(variant, suffix, mutate(OBJECTS[variant], consumer.name, pc, old, new))

    def test_event_overlap_can_be_restored_before_submission(self):
        return_contract("default")
        name, insns = instructions("default", "ordinary_return")
        pc, old = next((pc, text) for pc, text in insns if re.fullmatch(r"\*\(u32 \*\)\(r7 \+ 0x6c\) = [rw]2", text))
        # This overlap precedes the real Event.slot store, which restores it.
        changed = mutate(OBJECTS["default"], name, pc, old, old.replace("+ 0x6c", "+ 0x69"))
        self.assertTrue(return_contract("default", changed)["outlined"])

    def test_owner_required_and_insert_value_arguments(self):
        # Current construction passes an immutable seed, not an inserted value.
        for variant in OBJECTS:
            for suffix in consumer_names(variant):
                consumer_contract(variant, suffix)
                consumer, _, _, _ = consumer_case(variant, suffix)
                for pc, target in consumer.calls.items():
                    if not target.startswith("p11_owner_start_"):
                        continue
                    if target.endswith("get") and variant == "default":
                        continue  # Actual compiled API does not consume r2.
                    argument, old = next((p, t) for p, t in reversed(consumer.insns)
                        if p < pc and re.match(r"r2 (=|\+=) ", t))
                    new = "r2 = 0x1" if old == "r2 = 0x0" else "r2 = 0x0"
                    with self.subTest(variant=variant, function=suffix, operation=target, pc=pc), self.assertRaises(RuntimeError):
                        consumer_contract(variant, suffix, mutate(OBJECTS[variant], consumer.name, argument, old, new))

    def test_atomic_event_slot_corruption(self):
        for variant in OBJECTS:
            return_contract(variant)
            for suffix in ("ordinary_return", "object_return"):
                name, insns = instructions(variant, suffix)
                slot = next(pc for pc, text in insns if re.fullmatch(r"\*\(u32 \*\)\(r7 \+ 0x68\) = [rw]1", text))
                pc, old = next((pc, text) for pc, text in insns if pc > slot
                               and re.fullmatch(r"\*\(u64 \*\)\(r7 \+ 0x60\) = r\d+", text))
                # r1 is overwritten by the next field load. Do not also
                # destroy r9's descriptor before the later side query.
                for new in ("*(u32 *)(r7 + 0x69) = w1", "r1 = atomic_fetch_or((u64 *)(r7 + 0x68), r1)"):
                    with self.subTest(variant=variant, function=suffix, write=new), self.assertRaisesRegex(RuntimeError, "Event.slot corrupted before submit"):
                        return_contract(variant, mutate(OBJECTS[variant], name, pc, old, new))

    def test_lifecycle_start_insert_bypass_is_rejected(self):
        # Construction is already committed. A semantic refusal must take its
        # removal attempt and fault terminal; a live normal exit cannot mask it.
        for variant in OBJECTS:
            name = "p11_entry"
            entry_contract(variant, name)
            _, insns = instructions(variant, name)
            texts = dict(insns)
            fault = call_site(variant, name, "p11_object_fault")
            remove = max(pc for caller, _, pc, target in CHECKER["D"].internal_call_targets(OBJECTS[variant])
                         if caller == name and target == "p11_owner_start_remove" and pc < fault)
            adapter = call_site(variant, name, "object_fill_entry")
            guard, old = next((pc, text) for pc, text in insns if pc > adapter and text.startswith("if "))
            exit_pc = site(variant, name, "exit")
            cases = [(fault, "r0 = 0x0"), (remove, "r0 = 0x0"),
                     (guard, f"goto {exit_pc-guard-1:+#x}")]
            for pc, new in cases:
                with self.subTest(variant=variant, pc=pc):
                    with self.assertRaisesRegex(RuntimeError, "final-sink.*(terminal|refusal|removal|pending)"):
                        entry_contract(variant, name, mutate(OBJECTS[variant], name, pc, texts[pc], new))

    def test_kernel_stack_opt_out_is_only_the_out_of_range_index(self):
        # Every uprobe program first tail-calls a program array (p11_entry:
        # the never-populated STACK_GUARD) with an index past every slot (the
        # verifier then keeps the kernel stack; the kernel always falls
        # through). Pointing it at a real slot would be a continuation outside
        # the pair mode and must be rejected.
        _, insns = instructions("default", "p11_entry")
        sentinel = [p for p, t in insns if t == "r3 = 0xffffffff ll"]
        self.assertEqual(len(sentinel), 1)
        self.assertTrue(CHECKER["contract"](OBJECTS["default"], "default")["verified"])
        changed = mutate(OBJECTS["default"], "p11_entry", sentinel[0],
                         "r3 = 0xffffffff ll", "r3 = 0x1 ll")
        with self.assertRaisesRegex(RuntimeError, "mode pair tail"):
            CHECKER["contract"](changed, "default")

    def test_counter_adds_keep_frame_facts_only_through_map_values(self):
        # A non-fetch counter add through a map value (even after a
        # verifier-bounded index offset, or where two lookups joined) cannot
        # write the local frame; through an unresolved base it still can.
        lines = CHECKER["D"].function_blocks(OBJECTS["default"])["p11_return"]
        consumer = CHECKER["Consumer"]("uretprobe", "p11_return", lines, {})
        pc = consumer.insns[0][0]
        frame = ("stack", -0x188, 8)
        self.assertEqual(CHECKER["join_fact"](("result", 1), ("result", 2)), ("result", "map"))
        self.assertIsNone(CHECKER["join_fact"](("result", 1), ("stack", -8)))
        consumer.text[pc] = "r0 += r2"
        stepped = consumer.step(pc, {"r0": ("result", 7), "r2": ("constant", 8), frame: ("low", 1)})
        self.assertEqual(stepped["r0"], ("result", "map"))
        consumer.text[pc] = "lock *(u64 *)(r0 + 0x28) += r2"
        for base, survives in ((("result", "map"), True), (("result", 7), True),
                               (None, False), (("stack", -0x1b0), False)):
            with self.subTest(base=base):
                state = {"r2": ("constant", 1), frame: ("low", 1)}
                if base is not None:
                    state["r0"] = base
                self.assertEqual(frame in consumer.step(pc, state), survives)

    def test_atomic_memory_effects_and_result_registers(self):
        # The immutable objects contain atomic_fetch_or and cmpxchg_64.
        # Exercise their LLVM 32/64-bit and exchange spellings, including
        # unknown spellings which must conservatively lose memory facts.
        syntaxes = [
            ("r9 = atomic_fetch_or((u64 *)(r0 + 0x68), r9)", "r9"),
            ("w9 = atomic_fetch_add((u32 *)(r0 + 0x68), w9)", "r9"),
            ("r0 = cmpxchg_64(r6 + 0x68, r0, r9)", "r0"),
            ("w0 = cmpxchg_32(r6 + 0x68, w0, w9)", "r0"),
            ("r9 = xchg_64(r0 + 0x68, r9)", "r9"),
            ("w9 = xchg_32(r0 + 0x68, w9)", "r9"),
            ("lock *(u64 *)(r0 + 0x68) += r9", None),
            ("r9 = atomic_unknown(r0, r9)", "r9"),
        ]
        lines = CHECKER["D"].function_blocks(OBJECTS["default"])["p11_return"]
        consumer = CHECKER["Consumer"]("uretprobe", "p11_return", lines, {})
        identity = ("uretprobe", "p11_return")
        for text, result_register in syntaxes:
            for kind, address_offset in (("event", 0), ("stack", -0x70)):
                with self.subTest(text=text, memory=kind):
                    consumer.text[1414] = text
                    memory_key = ("event_slot",) if kind == "event" else ("stack", -8, 8)
                    state = {"r0": (kind, address_offset), "r6": (kind, address_offset),
                             "r9": ("constant", 0x400), memory_key: ("low", identity),
                             ("stack", -32, 8): ("constant", 0)}
                    result = consumer.step(1414, state)
                    self.assertNotIn(memory_key, result)
                    if result_register:
                        self.assertNotIn(result_register, result)
                    if "unknown" not in text:
                        self.assertEqual(result[("stack", -32, 8)], ("constant", 0))
        consumer.text[1414] = "r9 = atomic_fetch_or((u64 *)(r0 + 0x70), r9)"
        state = {"r0": ("event", 0), "r9": ("constant", 1), ("event_slot",): ("low", identity)}
        self.assertEqual(consumer.step(1414, state)[("event_slot",)], ("low", identity))
        # Return's START and external caller key are immutable parameters,
        # distinct from the callee's writable local frame and ring record.
        _, body = instructions("default", "object_return")
        outlined = CHECKER["_ReturnCaller"](".text", "object_return",
            CHECKER["D"].function_blocks(OBJECTS["default"])[next(name for name in
                CHECKER["D"].function_blocks(OBJECTS["default"]) if name.endswith("object_return"))], {})
        pc = body[0][0]
        outlined.proof = CHECKER["_ReturnProof"](0, True, 7, "object", {})
        for syntax in ("lock *(u64 *)(r3 + 0x38) += r5", "*(u32 *)(r3 + 0x38) = w5",
                       "*(u64 *)(r2 + 0x8) = r5", "*(u32 *)(r1 + 0x0) = w5"):
            with self.subTest(readonly_write=syntax):
                outlined.text[pc] = syntax
                with self.assertRaisesRegex(RuntimeError, "return.*(immutable|footprint)"):
                    outlined.step(pc, {"r1": ("context", 0), "r2": ("external_key", identity, 0),
                        "r3": ("owned", 7, 0), "r5": ("constant", 1), ("live", 7): True})
        outlined.text[pc] = "call -0x1"
        for target in ("memset", "p11_link_current_identity"):
            outlined.calls[pc] = target
            for destination in (("owned", 7, 0x38), ("external_key", identity, 0),
                                ("context", 0), ("stack", -4), ("event", 600)):
                with self.subTest(writer=target, forbidden_output=destination), self.assertRaisesRegex(RuntimeError, "return.*(immutable|footprint|output)"):
                    outlined.step(pc, {"r1": destination, "r2": ("constant", 0), "r3": ("constant", 16),
                        ("live", 7): True})
            for destination in (("stack", -64), ("event", 0x130), ("event", 0x70)):
                state = {"r1": destination, "r2": ("constant", 0), "r3": ("constant", 16),
                    ("stack", -64, 8): ("retained", 0x38, 32), ("stack", -32, 8): ("constant", 123),
                    ("event_slot",): ("low", identity), ("event_user_type",): ("retained", 0x38, 32),
                    ("live", 7): True}
                with self.subTest(writer=target, writable_output=destination):
                    result = outlined.step(pc, state)
                    self.assertEqual(result[("stack", -32, 8)], ("constant", 123))
                    self.assertEqual(result[("event_slot",)], ("low", identity))
                    if destination == ("stack", -64):
                        self.assertNotEqual(result.get(("stack", -64, 8)), ("retained", 0x38, 32))
                    if destination == ("event", 0x70):
                        self.assertNotIn(("event_user_type",), result)
        fill = next(target for _, _, _, target in CHECKER["D"].internal_call_targets(OBJECTS["default"])
                    if target.endswith("object_fill_return"))
        outlined.calls[pc] = fill
        for destination in (("owned", 7, 0), ("external_key", identity, 0), ("context", 0),
                            ("stack", -64), ("event", 0)):
            with self.subTest(writer="object_fill_return", forbidden_output=destination), self.assertRaisesRegex(RuntimeError, "return.*(side|footprint)"):
                outlined.step(pc, {"r1": destination, ("live", 7): True})
        self.assertEqual(outlined.step(pc, {"r1": ("constant", 0), ("live", 7): True})["r0"],
                         ("constant", 0), "a missing side cannot invent emission success")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--default-object", type=Path)
    parser.add_argument("--seeded-object", type=Path)
    parser.add_argument("--unsafe-object", type=Path)
    args, remaining = parser.parse_known_args()
    if args.seeded_object:
        if args.default_object or args.unsafe_object or remaining != ["EntryObjectTests.test_seeded_start_caller_contract"]:
            parser.error("--seeded-object requires exactly the seeded START caller test")
        selected = (("seeded", args.seeded_object),)
    else:
        if not args.default_object or not args.unsafe_object:
            parser.error("supply both --default-object and --unsafe-object")
        selected = (("default", args.default_object), ("unsafe", args.unsafe_object))
    for variant, path in selected:
        OBJECT_BYTES[variant] = path.read_bytes()
        OBJECTS[variant] = subprocess.run(
            ["llvm-objdump", "-dr", "--print-imm-hex", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout
    unittest.main(argv=[sys.argv[0], *remaining])
