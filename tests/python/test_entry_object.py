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


def mutate(disassembly, function, pc, old, new, internal_call=False):
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
    changed, count = re.subn(pattern, lambda m: (m[1].replace("85 00 ", "85 10 ")
        if internal_call else m[1]) + new + m[3], block)
    if count != 1 or changed == block:
        raise AssertionError(f"mutation did not change {function}:{pc}: {old!r}")
    return disassembly[:start] + changed + disassembly[end:]


class EntryObjectTests(unittest.TestCase):
    def test_ia32_span_rejection_edge_is_causal(self):
        for variant in OBJECTS:
            name, insns = instructions(variant, "p11_read_ia32_arg")
            pc = site(variant, name, r"if r3 > r1 goto .*")
            old = dict(insns)[pc]
            for new in ("if r3 > r1 goto +0x0", "goto +0x0"):
                with self.subTest(variant=variant, mutation=new):
                    with self.assertRaisesRegex(RuntimeError, "ia32.*span"):
                        CHECKER["contract"](mutate(OBJECTS[variant], name, pc, old, new), variant)
            # Bypassing the read is insufficient if the rejected path picks up
            # an uninitialized successful-read payload instead of the sentinel.
            payload = site(variant, name, r"r0 = \*\(u32 \*\)\(r10 - 0x4\)")
            with self.subTest(variant=variant, mutation="rejection returns payload"):
                with self.assertRaisesRegex(RuntimeError, "ia32.*span.*sentinel"):
                    CHECKER["contract"](mutate(OBJECTS[variant], name, pc, old,
                        f"if r3 > r1 goto {payload-pc-1:+#x}"), variant)
            # A different real rejection block that explicitly restores the
            # sentinel is valid; the checker must not freeze the branch offset.
            sentinel = site(variant, name, r"r0 = 0x100000000 ll", 1)
            changed = mutate(OBJECTS[variant], name, pc, old,
                             f"if r3 > r1 goto {sentinel-pc-1:+#x}")
            self.assertTrue(CHECKER["contract"](changed, variant)["verified"])

    def test_async_string_read_requires_genuine_helper_call_kind(self):
        for variant, suffix in (("default", "p11_entry"), ("unsafe", "capture_async_target")):
            name, _ = instructions(variant, suffix)
            pc = site(variant, name, r"call 0x72")
            changed = mutate(OBJECTS[variant], name, pc, "call 0x72", "call 0x72", internal_call=True)
            with self.subTest(variant=variant):
                with self.assertRaisesRegex(RuntimeError, "async.*(unresolved internal call|genuine helper)"):
                    CHECKER["contract"](changed, variant)

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
            elf = checker["Elf"](data)
            elf.symbols = [(symbol[0], 2, *symbol[2:]) if symbol[0] == "p11_read_ia32_arg"
                           else symbol for symbol in elf.symbols]
            with self.subTest(variant=variant, mutation="GLOBAL linkage"):
                with self.assertRaisesRegex(RuntimeError, "GLOBAL"):
                    checker["validate_ia32_reader"](elf)

    def test_async_scalar_failure_preserves_lifecycle_continuation(self):
        for variant, name, target in (("default", "p11_entry", "capture_scalar"),
                                      ("unsafe", "p11_entry_ia32", "p11_read_ia32_arg")):
            # The descriptor-selected async read follows all six base fields.
            call = call_site(variant, name, target, 6)
            _, insns = instructions(variant, name)
            pc, old = next((p, t) for p, t in insns if p > call and t.startswith("if "))
            exit_pc = site(variant, name, "exit")
            if variant == "default":
                new = old.split(" goto ")[0] + f" goto {exit_pc - pc - 1:+#x}"
            else:
                # The sentinel failure is the comparison's fallthrough edge.
                pc, old = next((p, t) for p, t in insns if p > pc)
                new = f"goto {exit_pc - pc - 1:+#x}"
            with self.subTest(variant=variant, pc=pc):
                with self.assertRaisesRegex(RuntimeError, "async.*continuation"):
                    CHECKER["contract"](mutate(OBJECTS[variant], name, pc, old, new), variant)

    def test_pointer_only_async_boundary_mutations(self):
        variant = "unsafe"
        name, insns = instructions(variant, "capture_async_target")
        entry = "p11_entry_ia32"
        cases = [
            (entry, before_call(variant, entry, "capture_async_target", r"r1 = r0"), "r1 = r7"),
            (entry, before_call(variant, entry, "capture_async_target", r"r2 \+= -0x128"), "r2 += -0x120"),
            (name, site(variant, name, r"if r1 s> r0 goto .*"), "r0 = r0"),
            (name, site(variant, name, r"if r0 s> 0x1c goto .*"), "r0 = r0"),
        ]
        for function, pc, new in cases:
            with self.subTest(function=function, pc=pc):
                old = dict(instructions(variant, function)[1])[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    CHECKER["contract"](mutate(OBJECTS[variant], function, pc, old, new), variant)
        # Redirect a real helper call to the actual scalar function. This
        # negative control recreates the prohibited nested responsibility.
        scalar, scalar_insns = instructions(variant, "capture_scalar")
        pc = site(variant, name, r"call 0x72")
        nested = mutate(OBJECTS[variant], name, pc, "call 0x72",
                        f"call {scalar_insns[0][0] - pc - 1:#x}", internal_call=True)
        with self.assertRaisesRegex(RuntimeError, "async callee reaches scalar/ia32 reader"):
            CHECKER["contract"](nested, variant)

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
        # Destinations come from CallStart, independently of the capture order.
        default_store = after_call("default", "p11_entry", "capture_scalar", r"\*\(u64 \*\)\(r10 - 0x160\) = r1")
        ia32_store = site("unsafe", "p11_entry_ia32", r"\*\(u64 \*\)\(r10 - 0x120\) = r0")
        cases = [
            ("default", "p11_entry", before_call("default", "p11_entry", "capture_scalar", r"r3 = r8"), "r3 = r9"),
            ("default", "p11_entry", default_store, "r1 = r1"),
            ("default", "p11_entry", default_store, "*(u64 *)(r10 - 0x158) = r1"),
            ("default", "p11_entry", before_call("default", "p11_entry", "capture_scalar", r"r4 = r7"), "r4 = 0x1"),
            ("unsafe", "p11_entry", site("unsafe", "p11_entry", r"if r7 s> 0x3 goto .*", 0), "if r8 s> 0x3 goto +0x57"),
            ("unsafe", "p11_entry", site("unsafe", "p11_entry", r"r1 = \*\(u64 \*\)\(r6 \+ 0x70\)", 0), "r1 = *(u64 *)(r6 + 0x68)"),
            ("unsafe", "p11_entry", site("unsafe", "p11_entry", r"\*\(u64 \*\)\(r10 - 0x128\) = r1", 3), "r1 = r1"),
            ("unsafe", "p11_entry", site("unsafe", "p11_entry", r"r2 = 0x8", 0), "r2 = 0x4"),
            ("unsafe", "p11_entry_ia32", before_call("unsafe", "p11_entry_ia32", "p11_read_ia32_arg", r"r2 = r8"), "r2 = r7"),
            ("unsafe", "p11_entry_ia32", before_call("unsafe", "p11_entry_ia32", "p11_read_ia32_arg", r"r1 = .*"), "r1 = r10"),
            ("unsafe", "p11_entry_ia32", call_site("unsafe", "p11_entry_ia32", "p11_read_ia32_arg"), "r0 = 0x0"),
            ("unsafe", "p11_entry_ia32", ia32_store, "*(u64 *)(r10 - 0x120) = r1"),
            ("unsafe", "p11_entry_ia32", ia32_store, "*(u64 *)(r10 - 0x118) = r0"),
            ("unsafe", "p11_entry_ia32", ia32_store, "r0 = r0"),
        ]
        for variant, function, pc, new in cases:
            with self.subTest(variant=variant, function=function, pc=pc):
                insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[function]))
                changed = mutate(OBJECTS[variant], function, pc, insns[pc], new)
                with self.assertRaisesRegex(RuntimeError, "final-sink|scalar-read|layout"):
                    CHECKER["contract"](changed, variant)

    def test_mode_and_return_sink_controls(self):
        cases = [
            ("p11_entry_template", site('unsafe', 'p11_entry_template', 'r4\\ \\+=\\ \\-0xc8'), "r4 += -0x78"),
            ("p11_entry_template", site('unsafe', 'p11_entry_template', 'r3\\ =\\ 0x8', 0), "r3 = 0x4"),
            ("p11_entry_template", site('unsafe', 'p11_entry_template', 'r1\\ =\\ r8', 1), "r1 = r2"),
            ("p11_entry_template_pair", site('unsafe', 'p11_entry_template_pair', 'r3\\ =\\ 0x1'), "r3 = 0x0"),
            ("p11_entry_template_pair", site('unsafe', 'p11_entry_template_pair', 'if\\ r0\\ ==\\ 0x0\\ goto\\ \\+0x9'), "if r0 != 0x0 goto +0x9"),
            ("p11_entry_template_types", site('unsafe', 'p11_entry_template_types', 'r3\\ \\+=\\ \\-0x128', 0), "r3 += -0xc8"),
            ("p11_entry_template_types", site('unsafe', 'p11_entry_template_types', 'if\\ r7\\ ==\\ 0x0\\ goto\\ \\+0x17'), "if r7 != 0x0 goto +0x17"),
            ("p11_entry_template_second", site('unsafe', 'p11_entry_template_second', 'r9\\ \\+=\\ 0xb0'), "r9 += 0x60"),
            ("p11_entry_template_second", site('unsafe', 'p11_entry_template_second', 'r4\\ =\\ r9'), "r4 = r10"),
            ("p11_return", 1407, "if r8 != 0x1 goto +0x19"),
            ("p11_return", 1418, "r2 = 0x8"),
            ("p11_return", 1588, "r3 = *(u64 *)(r10 - 0xf8)"),
        ]
        for function, pc, new in cases:
            with self.subTest(function=function, pc=pc):
                insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS["unsafe"])[function]))
                changed = mutate(OBJECTS["unsafe"], function, pc, insns[pc], new)
                with self.assertRaisesRegex(RuntimeError, "final-sink|layout|mode|lifecycle|retained"):
                    CHECKER["contract"](changed, "unsafe")

    def test_scalar_index_register_alias(self):
        pc = before_call("default", "p11_entry", "capture_scalar", r"r3 = r8")
        changed = mutate(OBJECTS["default"], "p11_entry", pc, "r3 = r8", "w3 = w8")
        self.assertTrue(CHECKER["contract"](changed, "default")["verified"])

    def test_jmp32_cannot_prove_full_pointer_or_address(self):
        # Low32(0x100000000) is zero. Low32(RSP32 + argument offset)
        # can also fit the IA32 limit while the complete address overflows.
        cases = [("default", "p11_entry", site('default', 'p11_entry', 'if\\ r1\\ ==\\ 0x0\\ goto\\ \\+0xe')),
                 ("unsafe", "p11_entry", site("unsafe", "p11_entry", r"if r7 == 0x0 goto \+0xbd")),
                 ("default", "capture_scalar", site("default", "capture_scalar", r"if r1 > r0 goto .*")),
                 ("default", "capture_scalar", site("default", "capture_scalar", r"if r3 > -0x10 goto .*")),
                 ("unsafe", "capture_scalar", site("unsafe", "capture_scalar", r"if r1 > r0 goto .*")),
                 ("unsafe", "capture_scalar", site("unsafe", "capture_scalar", r"if r3 > -0x10 goto .*")),
                 ("unsafe", "p11_entry_ia32", site("unsafe", "p11_entry_ia32", r"if r1 > r0 goto .*", 0))]
        for variant, suffix, pc in cases:
            with self.subTest(variant=variant, function=suffix, pc=pc):
                blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
                name = next(name for name in blocks if name.endswith(suffix))
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                new = re.sub(r"\br(\d+)\b", r"w\1", old)
                changed = mutate(OBJECTS[variant], name, pc, old, new)
                with self.assertRaisesRegex(RuntimeError, "branch width 32.*full-width"):
                    CHECKER["contract"](changed, variant)

    def test_full_pointer_branch_restoration(self):
        for variant, pc in (("default", site("default", "p11_entry", r"if r1 == 0x0 goto \+0xe")),
                            ("unsafe", site("unsafe", "p11_entry", r"if r7 == 0x0 goto \+0xbd"))):
            with self.subTest(variant=variant):
                original = OBJECTS[variant]
                old = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(original)["p11_entry"]))[pc]
                new = re.sub(r"\br(\d+)\b", r"w\1", old)
                changed = mutate(original, "p11_entry", pc, old, new)
                restored = mutate(changed, "p11_entry", pc, new, old)
                self.assertEqual(restored, original)
                self.assertTrue(CHECKER["contract"](restored, variant)["verified"])

    def test_signed_pointer_sink_causal_pair(self):
        # Both layouts store signed-positive pointers. A u32 value 0x80000000
        # is positive in JMP64 but negative in JMP32 and must not lose its sink.
        for register in ("w0", "r0"):
            with self.subTest(register=register):
                changed = OBJECTS["unsafe"]
                for pc, old, new in (
                    (site("unsafe", "p11_entry_ia32", r"if r0 == 0x0 goto \+0x1e"), "if r0 == 0x0 goto +0x1e", f"if {register} s> 0x0 goto +0x1"),
                    (site("unsafe", "p11_entry_ia32", r"\*\(u64 \*\)\(r10 - 0x108\) = r0"), "*(u64 *)(r10 - 0x108) = r0", "goto +0x1d"),
                    (site("unsafe", "p11_entry_ia32", r"r9 &= 0x8"), "r9 &= 0x8", "*(u64 *)(r10 - 0x108) = r0"),
                ):
                    changed = mutate(changed, "p11_entry_ia32", pc, old, new)
                if register == "w0":
                    # Uncertain nonzero provenance can fail at the decoder
                    # boundary before the final insertion is reached.
                    with self.assertRaisesRegex(RuntimeError, r"final-sink 8: (decoder mechanism field 8 pointer|nonzero pointer predicate not proved|successful capture lost)"):
                        CHECKER["contract"](changed, "unsafe")
                else:
                    self.assertTrue(CHECKER["contract"](changed, "unsafe")["verified"])

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

    def test_proven_32bit_comparisons_and_shared_index_alias(self):
        cases = [("default", "capture_scalar", site("default", "capture_scalar", r"if r4 == 0x0 goto .*")),
                 ("default", "capture_scalar", site("default", "capture_scalar", r"if r1 == 0xff goto .*")),
                 ("default", "capture_scalar", site("default", "capture_scalar", r"if r3 s> 0x2 goto .*")),
                 ("unsafe", "capture_scalar", site("unsafe", "capture_scalar", r"r1 = r3", 0)),
                 ("unsafe", "p11_entry_ia32", site("unsafe", "p11_entry_ia32", r"if r8 == 0xff goto .*")),
                 ("unsafe", "p11_entry_ia32", site("unsafe", "p11_entry_ia32", r"if r0 == 0x0 goto \+0x1e")),
                 ("unsafe", "p11_entry_ia32", site("unsafe", "p11_entry_ia32", r"if r0 > r1 goto .*"))]
        for variant, suffix, pc in cases:
            with self.subTest(variant=variant, function=suffix, pc=pc):
                blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
                name = next(name for name in blocks if name.endswith(suffix))
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                new = re.sub(r"\br(\d+)\b", r"w\1", old)
                changed = mutate(OBJECTS[variant], name, pc, old, new)
                self.assertTrue(CHECKER["contract"](changed, variant)["verified"])

    def test_async_callee_and_deleted_decoder_boundaries(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        async_name = next(name for name in blocks if name.endswith("capture_async_target"))
        cases = [(async_name, site("unsafe", async_name, r"r3 = r1"), "r3 = r7"),
                 (async_name, site("unsafe", async_name, r"r2 = 0x1d"), "r2 = 0x1c"),
                 (async_name, site("unsafe", async_name, r"\*\(u32 \*\)\(r6 \+ 0x104\) = r1"), "r1 = r1"),
                 (async_name, site("unsafe", async_name, r"\*\(u32 \*\)\(r6 \+ 0x104\) = r1"), "*(u32 *)(r6 + 0x100) = r1"),
                 ("p11_entry", call_site("unsafe", "p11_entry", "p11_decode_params"), "r0 = 0x0"),
                 ("p11_entry_template", call_site("unsafe", "p11_entry_template", "p11_decode_params"), "r0 = 0x0")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc, new=new):
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink|mode|decoder"):
                    CHECKER["contract"](mutate(OBJECTS["unsafe"], name, pc, old, new), "unsafe")

    def test_each_final_role_store_cannot_disappear(self):
        # Literal role stores from the independently inspected objects/layout.
        cases = {
            ('default', 'p11_entry'): [
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x160\\)\\ =\\ r1', 2),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x158\\)\\ =\\ r1', 1),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x140\\)\\ =\\ r1', 1),
                site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x130\\)\\ =\\ r1'),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x148\\)\\ =\\ r1', 2),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x138\\)\\ =\\ r1', 2),
                site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x64\\)\\ =\\ r1'),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x110\\)\\ =\\ r1', 2),
                site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x138\\)\\ =\\ r1', 3),
            ],
            ('unsafe', 'p11_entry'): [
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x128\\)\\ =\\ r1', 3),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x120\\)\\ =\\ r1', 2),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x108\\)\\ =\\ r1', 2),
                site('unsafe', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0xf8\\)\\ =\\ r1'),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x110\\)\\ =\\ r7'),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 2),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 6),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 2),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 8),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 4),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 7),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 3),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd8\\)\\ =\\ r1', 5),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 7),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 3),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 9),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 5),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 8),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 4),
                site('unsafe', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r1', 6),
            ],
            ('unsafe', 'p11_entry_ia32'): [
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x120\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x118\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x100\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0xf0\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x108\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xf8\\)\\ =\\ r0', 0),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xd0\\)\\ =\\ r0'),
                site('unsafe', 'p11_entry_ia32', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0xf8\\)\\ =\\ r0', 1),
            ],
        }
        for (variant, name), pcs in cases.items():
            insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[name]))
            for pc in pcs:
                with self.subTest(variant=variant, function=name, pc=pc):
                    self.assertTrue(insns[pc].startswith("*(u"))
                    with self.assertRaisesRegex(RuntimeError, "final-sink"):
                        CHECKER["contract"](mutate(OBJECTS[variant], name, pc, insns[pc], "r0 = r0"), variant)

    def test_callee_scalar_reads_and_option_success(self):
        for variant in OBJECTS:
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            name = next(name for name in blocks if name.endswith("capture_scalar"))
            insns = dict(CHECKER["D"].instructions(blocks[name]))
            # ia32 stride/span/width moved to the globally verified reader;
            # this callee must now retain its scalar-only call boundary.
            cases = [(r"r2 = r3", "r2 = r4"),
                     (r"r1 = \*\(u64 \*\)\(r2 \+ 0x98\)", "r1 = r10"),
                     (r"call -0x1", "r0 = 0x0"),
                     (r"r2 = 0x8", "r2 = 0x4"),
                     (r"r0 = \*\(u64 \*\)\(r2 \+ 0x70\)", "r0 = *(u64 *)(r2 + 0x68)"),
                     (r"r7 = 0x1", "r7 = r7"),
                     (r"\*\(u64 \*\)\(r6 \+ 0x8\) = r0", "*(u64 *)(r6 + 0x0) = r0"),
                     (r"if r1 > r0 goto .*", "if r1 == r0 goto +0x1"),
                     (r"r0 = \*\(u64 \*\)\(r10 - 0x10\)", "r0 = *(u32 *)(r10 - 0x10)")]
            for pattern, new in cases:
                pc = site(variant, name, pattern)
                with self.subTest(variant=variant, pc=pc):
                    with self.assertRaisesRegex(RuntimeError, "scalar-read|final-sink"):
                        CHECKER["contract"](mutate(OBJECTS[variant], name, pc, insns[pc], new), variant)

    def test_template_order_layout_and_disabled_controls(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        types_callee = next(name for name in blocks if "walk_template_typesKb1_" in name)
        cases = [("p11_entry_template", site('unsafe', 'p11_entry_template', 'r3\\ =\\ \\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x168\\)'), "r3 = *(u64 *)(r10 - 0x180)"),
                 ("p11_entry_template", site('unsafe', 'p11_entry_template', 'r3\\ =\\ \\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x198\\)'), "r3 = *(u64 *)(r10 - 0x160)"),
                 ("p11_entry_template", call_site("unsafe", "p11_entry_template", "p11_walk_template"), "r0 = 0x0"),
                 ("p11_entry_template_pair", call_site("unsafe", "p11_entry_template_pair", "p11_walk_template"), "r0 = 0x0"),
                 ("p11_entry_template_pair", after_call("unsafe", "p11_entry_template_pair", "p11_walk_template", r"call 0x1"), "call 0xc"),
                 ("p11_entry_template_types", call_site("unsafe", "p11_entry_template_types", types_callee), internal_callee_instruction("unsafe", "walk_template_typesKb0_")),
                 ("p11_entry_template_second", call_site("unsafe", "p11_entry_template_second", "p11_walk_template"), "r0 = 0x0"),
                 ("p11_entry", before_call("unsafe", "p11_entry", "p11_decode_params", r"r3 = 0x8"), "r3 = 0x4"),
                 ("p11_entry_ia32", before_call("unsafe", "p11_entry_ia32", "p11_decode_params", r"r3 = 0x4"), "r3 = 0x8")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc):
                insns = CHECKER["D"].instructions(blocks[name])
                old = dict(insns)[pc]
                changed = mutate(OBJECTS["unsafe"], name, pc, old, new)
                if new == "call 0xc":
                    add_pc, add = next((p, t) for p, t in insns
                                       if p > pc and t.startswith("lock *(u64 *)(r0 + 0x0) += "))
                    changed = mutate(changed, name, add_pc, add, "r1 = r1")
                with self.assertRaisesRegex(RuntimeError, "final-sink|mode|layout"):
                    CHECKER["contract"](changed, "unsafe")

    def test_ordinary_walker_cannot_become_types_walker(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        target = next(name for name in blocks if "walk_template_typesKb1_" in name)
        changed, count = re.subn(r"(R_BPF_64_32[ \t]+)p11_walk_template\b",
                                 lambda match: match[1] + target, OBJECTS["unsafe"], count=1)
        self.assertEqual(count, 1, "actual ordinary-walker relocation must exist")
        with self.assertRaisesRegex(RuntimeError, "final-sink.*mode walker callee"):
            CHECKER["contract"](changed, "unsafe")

    def test_post_capture_overlap_and_atomic_corruption(self):
        old = "*(u32 *)(r10 - 0x68) = r4"
        for new in ("*(u32 *)(r10 - 0x15f) = r4",
                    "r4 = atomic_fetch_or((u64 *)(r10 - 0x160), r4)"):
            with self.subTest(new=new):
                changed = mutate(OBJECTS["default"], "p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x68\\)\\ =\\ r4'), old, new)
                with self.assertRaisesRegex(RuntimeError, "final-sink 6: successful capture lost"):
                    CHECKER["contract"](changed, "default")
        restored = mutate(changed, "p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x68\\)\\ =\\ r4'), new, old)
        self.assertTrue(CHECKER["contract"](restored, "default")["verified"])

    def test_unknown_postwrite_and_callee_start_clobber(self):
        changed = mutate(OBJECTS["default"], "p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x68\\)\\ =\\ r4'),
                         "*(u32 *)(r10 - 0x68) = r4", "*(u64 *)(r5 + 0x0) = r4")
        with self.subTest(control="unknown postwrite"):
            with self.assertRaisesRegex(RuntimeError, "final-sink"):
                CHECKER["contract"](changed, "default")
        for variant in OBJECTS:
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            name = next(name for name in blocks if name.endswith("capture_scalar"))
            with self.subTest(variant=variant):
                changed = mutate(OBJECTS[variant], name, site(variant, name, r"\*\(u32 \*\)\(r5 \+ 0x100\) = r1"),
                                 "*(u32 *)(r5 + 0x100) = r1", "*(u32 *)(r5 + 0x8) = r1")
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    CHECKER["contract"](changed, variant)

    def test_helper_invocation_without_success_path_is_insufficient(self):
        cases = [("unsafe", "p11_entry", site("unsafe", "p11_entry", r"if r0 != 0x0 goto \+0x3", 0), "goto +0x3")]
        for variant in OBJECTS:
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            scalar = next(name for name in blocks if name.endswith("capture_scalar"))
            pc = site(variant, scalar, r"if r0 != 0x0 goto .*", 0)
            old = dict(instructions(variant, scalar)[1])[pc]
            cases.append((variant, scalar, pc, "goto " + old.split(" goto ")[1]))
        for variant, name, pc, new in cases:
            with self.subTest(variant=variant, function=name, pc=pc):
                old = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "scalar-read.*index coverage"):
                    CHECKER["contract"](mutate(OBJECTS[variant], name, pc, old, new), variant)

    def test_success_cannot_exit_before_sink_or_lose_pair_tail(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        entry = dict(CHECKER["D"].instructions(blocks["p11_entry"]))
        exit_pc = next(pc for pc, text in entry.items() if text == "exit")
        cases = [("p11_entry", site('unsafe', 'p11_entry', 'goto\\ \\+0x3', 0), f"goto +{exit_pc-1035:#x}"),
                 ("p11_entry_template_pair", site('unsafe', 'p11_entry_template_pair', 'call\\ 0xc'), "r0 = 0x0")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc):
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    CHECKER["contract"](mutate(OBJECTS["unsafe"], name, pc, old, new), "unsafe")

    def test_unchanged_objects(self):
        for variant, disassembly in OBJECTS.items():
            with self.subTest(variant=variant):
                report = CHECKER["contract"](disassembly, variant)
                self.assertEqual(report["status"], "partial")
                self.assertTrue(all(report["verified"].values()))

    def test_actual_instruction_controls(self):
        cases = [
            ("p11_entry", site('default', 'p11_entry', 'r1\\ <<=\\ 0x20'), "r1 <<= 0x20", "r1 <<= 0x1f"),
            ("p11_entry", site('default', 'p11_entry', 'r0\\ >>=\\ 0x20', 0), "r0 >>= 0x20", "r0 >>= 0x1f"),
            ("p11_entry", site('default', 'p11_entry', 'r1\\ =\\ r6', 1), "r1 = r6", "r1 = r10"),
            ("p11_entry", site('default', 'p11_entry', 'if\\ r0\\ ==\\ 0x0\\ goto\\ \\+0xd'), "if r0 == 0x0 goto +0xd", "goto +0xd"),
            ("p11_entry", site('default', 'p11_entry', 'if\\ r0\\ ==\\ 0x0\\ goto\\ \\+0xd'), "if r0 == 0x0 goto +0xd", "if r0 != 0x0 goto +0xd"),
            ("p11_entry", site('default', 'p11_entry', 'if\\ r0\\ ==\\ 0x0\\ goto\\ \\+0xd'), "if r0 == 0x0 goto +0xd", "if r0 == 0x0 goto +0xc"),
            ("p11_entry", site('default', 'p11_entry', 'r2\\ =\\ 0xff', 0), "r2 = 0xff", "r2 = 0x0"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x168\\)\\ =\\ r8'), "*(u32 *)(r10 - 0x168) = r8", "*(u32 *)(r10 - 0x168) = r0"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x180\\)\\ =\\ r8'), '*(u32 *)(r10 - 0x180) = r8', "*(u32 *)(r10 - 0x180) = r0"),
            ("p11_return", 1209, "*(u32 *)(r10 - 0xb8) = r1", "*(u32 *)(r10 - 0xb8) = r0"),
            ("p11_entry", site('default', 'p11_entry', 'if\\ r1\\ ==\\ 0x23\\ goto\\ \\+0xe'), "if r1 == 0x23 goto +0xe", "goto +0xe"),
            ("p11_entry", site('default', 'p11_entry', 'r2\\ =\\ 0x0', 0), "r2 = 0x0", "r2 = 0x1"),
            ("p11_entry", site('default', 'p11_entry', 'call\\ 0x755', 0), 'call 0x755', "r0 = 0x0"),
            ("p11_entry", site('default', 'p11_entry', 'r1\\ =\\ 0x8'), "r1 = 0x8", "r1 = 0x7"),
            ("p11_entry", site('default', 'p11_entry', 'goto\\ \\+0x134'), "goto +0x134", "goto +0x1"),
            ("p11_return", 1412, "*(u32 *)(r0 + 0x68) = r1", "*(u32 *)(r0 + 0x68) = r2"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x17c\\)\\ =\\ r7'), '*(u32 *)(r10 - 0x17c) = r7', "if r7 == 0x0 goto +0x10"),
            ("p11_return", 1227, "call 0x2", "r0 = 0x0"),
            ("p11_return", call_site("default", "p11_return", "p11_owner_start_remove"), "call 0x755", "r0 = 0x0"),
            ("p11_return", 1413, "*(u64 *)(r0 + 0x60) = r9", "*(u32 *)(r0 + 0x69) = r9"),
            ("p11_entry", site('default', 'p11_entry', 'call\\ 0xe'), "call 0xe", "call 0x5"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u32\\ \\*\\)\\(r10\\ \\-\\ 0x17c\\)\\ =\\ r7'), '*(u32 *)(r10 - 0x17c) = r7', "*(u32 *)(r10 - 0x17c) = r8"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x188\\)\\ =\\ r0'), '*(u64 *)(r10 - 0x188) = r0', "*(u32 *)(r10 - 0x188) = r0"),
            ("p11_entry", site('default', 'p11_entry', '\\*\\(u64\\ \\*\\)\\(r10\\ \\-\\ 0x168\\)\\ =\\ r1', 0), "*(u64 *)(r10 - 0x168) = r1", "*(u8 *)(r10 - 0x185) = r1"),
        ]
        for function, pc, old, new in cases:
            with self.subTest(function=function, pc=pc, new=new):
                changed = mutate(OBJECTS["default"], function, pc, old, new)
                with self.assertRaises(RuntimeError):
                    CHECKER["contract"](changed, "default")

    def test_each_consumer_descriptor_fields_and_word(self):
        discovery = CHECKER["D"]
        for variant, disassembly in OBJECTS.items():
            report = CHECKER["contract"](disassembly, variant)
            blocks = discovery.function_blocks(disassembly)
            for name, result in report["consumers"].items():
                insns = discovery.instructions(blocks[name])
                lookup = next(pc for pc, sink in result["sinks"] if sink == "DESCRIPTORS")
                high = [(pc, text) for pc, text in insns if pc < lookup and text == "r0 >>= 0x20"][-1]
                controls = [(high[0], high[1], "r0 <<= 0x20")]
                for pc, text in insns:
                    match = CHECKER["LOAD"].fullmatch(text)
                    if lookup < pc < lookup + 32 and match and match[3] == "0":
                        controls.append((pc, text, text.replace("+ 0x" + match[5], "+ 0xff")))
                self.assertEqual(len(controls), 1 + len(result["descriptor_fields"]))
                for pc, old, new in controls:
                    with self.subTest(variant=variant, function=name, pc=pc):
                        changed = mutate(disassembly, name, pc, old, new)
                        with self.assertRaises(RuntimeError):
                            CHECKER["contract"](changed, variant)

    def test_diagnostic_specialization_and_template_cleanup(self):
        discovery = CHECKER["D"]
        disassembly = OBJECTS["unsafe"]
        blocks = discovery.function_blocks(disassembly)
        for name in ("p11_entry", "p11_entry_ia32", "p11_entry_template", "p11_entry_template_pair", "p11_entry_template_second", "p11_entry_template_types", "p11_return"):
            insns = discovery.instructions(blocks[name])
            pc, text = next((pc, text) for pc, text in insns if text.startswith("if r1 == 0x23 goto"))
            with self.subTest(function=name, control="selector bypass"):
                changed = mutate(disassembly, name, pc, text, "goto " + text.split(" goto ")[1])
                with self.assertRaises(RuntimeError):
                    CHECKER["contract"](changed, "unsafe")
            # Every ABI-refusal key in each diagnostic consumer must remain 8.
            first_descriptor = next(pc for _, pc, _ in discovery.map_call_sites(blocks[name], "DESCRIPTORS", 1))
            for pc, text in insns:
                if pc < first_descriptor and text == "r1 = 0x8":
                    with self.subTest(function=name, pc=pc, control="refusal key"):
                        changed = mutate(disassembly, name, pc, text, "r1 = 0x7")
                        with self.assertRaises(RuntimeError):
                            CHECKER["contract"](changed, "unsafe")

    def test_register_aliases_and_unknown_writes(self):
        disassembly = OBJECTS["default"]
        changed = mutate(disassembly, "p11_entry", site('default', 'p11_entry', 'r2\\ =\\ 0xff', 0), "r2 = 0xff", "w2 = 0xff")
        self.assertTrue(CHECKER["contract"](changed, "default")["verified"])
        changed = mutate(disassembly, "p11_entry", site('default', 'p11_entry', 'r2\\ =\\ 0xff', 0), "r2 = 0xff", "w2 ^= 0xff")
        with self.assertRaises(RuntimeError):
            CHECKER["contract"](changed, "default")

    def test_each_required_operation_cannot_disappear(self):
        discovery = CHECKER["D"]
        for variant, disassembly in OBJECTS.items():
            report = CHECKER["contract"](disassembly, variant)
            blocks = discovery.function_blocks(disassembly)
            for name, result in report["consumers"].items():
                insns = dict(discovery.instructions(blocks[name]))
                for pc, sink in result["sinks"]:
                    if sink == "Event.slot":
                        continue
                    with self.subTest(variant=variant, function=name, pc=pc, sink=sink):
                        changed = mutate(disassembly, name, pc, insns[pc], "r0 = 0x0")
                        with self.assertRaises(RuntimeError):
                            CHECKER["contract"](changed, variant)

    def test_full_start_key_in_every_consumer(self):
        discovery = CHECKER["D"]
        for variant, disassembly in OBJECTS.items():
            split = CHECKER["sections"](disassembly)
            for section in ("uprobe", "uretprobe"):
                calls = discovery.internal_call_targets(split[section] + "\n" + split[".text"])
                for name, lines in discovery.function_blocks(split[section]).items():
                    if not (name.startswith("p11_entry") or name == "p11_return"):
                        continue
                    consumer = CHECKER["Consumer"](section, name, lines,
                        {pc: target for caller, _, pc, target in calls if caller == name})
                    facts = consumer.facts()
                    first = min(pc for pc, target in consumer.calls.items() if target.startswith("p11_owner_start_"))
                    key = facts[first]["r1"]
                    controls = []
                    for pc, text in consumer.insns:
                        if pc >= first:
                            continue
                        match = CHECKER["STORE"].fullmatch(text)
                        if match:
                            pointer = CHECKER["address"](facts[pc], match[2], match[3], match[4])
                            if pointer in (("stack", key[1]), ("stack", key[1] + 8), ("stack", key[1] + 12)):
                                controls.append((pc, text, text.rsplit(" = ", 1)[0] + " = r10"))
                        if text == "call 0xe":
                            controls.append((pc, text, "call 0x5"))
                    self.assertEqual(len(controls), 4)
                    for pc, old, new in controls:
                        with self.subTest(variant=variant, function=name, pc=pc):
                            with self.assertRaises(RuntimeError):
                                CHECKER["contract"](mutate(disassembly, name, pc, old, new), variant)

    def test_event_overlap_can_be_restored_before_submission(self):
        changed = mutate(OBJECTS["default"], "p11_return", 1362,
                         "*(u64 *)(r0 + 0x60) = r1", "*(u32 *)(r0 + 0x69) = r1")
        changed = mutate(changed, "p11_return", 1498, "r1 = 0x0", "r1 = *(u64 *)(r10 - 0xd0)")
        changed = mutate(changed, "p11_return", 1499,
                         "*(u32 *)(r0 + 0x11c) = r1", "*(u32 *)(r0 + 0x68) = r1")
        self.assertTrue(CHECKER["contract"](changed, "default")["verified"]["event_slot_through_submit"])

    def test_owner_required_and_insert_value_arguments(self):
        discovery = CHECKER["D"]
        for variant, disassembly in OBJECTS.items():
            split = CHECKER["sections"](disassembly)
            for section in ("uprobe", "uretprobe"):
                calls = discovery.internal_call_targets(split[section] + "\n" + split[".text"])
                for name, lines in discovery.function_blocks(split[section]).items():
                    if not (name.startswith("p11_entry") or name == "p11_return"):
                        continue
                    insns = discovery.instructions(lines)
                    positions = {pc: index for index, (pc, _) in enumerate(insns)}
                    for caller, _, pc, target in calls:
                        if caller != name or not target.startswith("p11_owner_start_"):
                            continue
                        if target.endswith("get") and variant == "default":
                            continue  # This compiled callee does not consume incoming r2.
                        argument_pc, old = next((p, t) for p, t in reversed(insns[:positions[pc]])
                                               if re.match(r"r2 (=|\+=) ", t))
                        new = "r2 = 0x1" if old == "r2 = 0x0" else "r2 = 0x0"
                        with self.subTest(variant=variant, function=name, pc=pc):
                            with self.assertRaises(RuntimeError):
                                CHECKER["contract"](mutate(disassembly, name, argument_pc, old, new), variant)

    def test_atomic_event_slot_corruption(self):
        changed = mutate(OBJECTS["default"], "p11_return", 1457,
                         "*(u64 *)(r0 + 0x60) = r1", "r1 = 0x400")
        changed = mutate(changed, "p11_return", 1458,
                         "r1 = *(u64 *)(r10 - 0x128)",
                         "r9 = atomic_fetch_or((u64 *)(r0 + 0x68), r9)")
        with self.assertRaisesRegex(RuntimeError, r"Event.slot corrupted before submit"):
            CHECKER["contract"](changed, "default")

    def test_lifecycle_start_insert_bypass_is_rejected(self):
        # The async lifecycle continuation must reach the semantic START
        # insertion on every path; a direct exit after the lifecycle match is
        # exactly the bypass the rule exists to catch.
        _, insns = instructions("default", "p11_entry")
        lifecycle = [p for p, t in insns if re.fullmatch(r"if r\d+ == 0xc goto .*", t)]
        self.assertEqual(len(lifecycle), 1)
        exit_pc = site("default", "p11_entry", "exit")
        pc, old = next((p, t) for p, t in insns if p > lifecycle[0])
        new = f"goto {exit_pc - pc - 1:+#x}"
        with self.assertRaisesRegex(RuntimeError, "bypasses START insertion"):
            CHECKER["contract"](mutate(OBJECTS["default"], "p11_entry", pc, old, new), "default")

    def test_kernel_stack_opt_out_is_only_the_out_of_range_index(self):
        # Every classic uprobe program first tail-calls TAIL_CALLS with an
        # index past every slot (the verifier then keeps the kernel stack; the
        # kernel always falls through). Pointing it at a real slot would be a
        # continuation outside the pair mode and must be rejected.
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--default-object", required=True, type=Path)
    parser.add_argument("--unsafe-object", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    for variant, path in (("default", args.default_object), ("unsafe", args.unsafe_object)):
        OBJECT_BYTES[variant] = path.read_bytes()
        OBJECTS[variant] = subprocess.run(
            ["llvm-objdump", "-dr", "--print-imm-hex", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout
    unittest.main(argv=[sys.argv[0], *remaining])
