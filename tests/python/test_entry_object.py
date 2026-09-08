#!/usr/bin/env python3
"""Native tests; supply immutable objects with --default-object/--unsafe-object."""

import argparse
from pathlib import Path
import re
import runpy
import subprocess
import sys
from types import SimpleNamespace
import unittest

CHECKER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/check-entry-object.py"))
OBJECTS = {}


def mutate(disassembly, function, pc, old, new):
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
    changed, count = re.subn(pattern, lambda m: m[1] + new + m[3], block)
    if count != 1 or changed == block:
        raise AssertionError(f"mutation did not change {function}:{pc}: {old!r}")
    return disassembly[:start] + changed + disassembly[end:]


class EntryObjectTests(unittest.TestCase):
    def test_final_scalar_sink_controls(self):
        # Destinations come from CallStart, independently of the capture order.
        cases = [
            ("default", "p11_entry", 976, "r3 = r9"),
            ("default", "p11_entry", 983, "r1 = r1"),
            ("default", "p11_entry", 983, "*(u64 *)(r10 - 0x158) = r1"),
            ("default", "p11_entry", 977, "r4 = 0x1"),
            ("unsafe", "p11_entry", 971, "if r7 s> 0x3 goto +0x57"),
            ("unsafe", "p11_entry", 1099, "r1 = *(u64 *)(r6 + 0x68)"),
            ("unsafe", "p11_entry", 1104, "r1 = r1"),
            ("unsafe", "p11_entry", 1078, "r2 = 0x4"),
            ("unsafe", "p11_entry_ia32", 1775, "r7 <<= 0x3"),
            ("unsafe", "p11_entry_ia32", 1780, "r3 >>= 0x1f"),
            ("unsafe", "p11_entry_ia32", 1787, "r2 = 0x8"),
            ("unsafe", "p11_entry_ia32", 1934, "r1 = *(u64 *)(r10 - 0x130)"),
            ("unsafe", "p11_entry_ia32", 1935, "*(u64 *)(r10 - 0x118) = r1"),
            ("unsafe", "p11_entry_ia32", 1935, "r1 = r1"),
        ]
        for variant, function, pc, new in cases:
            with self.subTest(variant=variant, function=function, pc=pc):
                insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[function]))
                changed = mutate(OBJECTS[variant], function, pc, insns[pc], new)
                with self.assertRaisesRegex(RuntimeError, "final-sink|scalar-read|layout"):
                    CHECKER["contract"](changed, variant)

    def test_mode_and_return_sink_controls(self):
        cases = [
            ("p11_entry_template", 2620, "r4 += -0x78"),
            ("p11_entry_template", 2623, "r3 = 0x4"),
            ("p11_entry_template", 2625, "r1 = r2"),
            ("p11_entry_template_pair", 3141, "r3 = 0x0"),
            ("p11_entry_template_pair", 3128, "if r0 != 0x0 goto +0x9"),
            ("p11_entry_template_types", 3711, "r3 += -0xc8"),
            ("p11_entry_template_types", 3709, "if r7 != 0x0 goto +0x17"),
            ("p11_entry_template_second", 3322, "r9 += 0x60"),
            ("p11_entry_template_second", 3324, "r4 = r10"),
            ("p11_return", 1286, "if r8 != 0x1 goto +0x64"),
            ("p11_return", 1297, "r2 = 0x8"),
            ("p11_return", 1339, "r3 = *(u64 *)(r10 - 0xf8)"),
        ]
        for function, pc, new in cases:
            with self.subTest(function=function, pc=pc):
                insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS["unsafe"])[function]))
                changed = mutate(OBJECTS["unsafe"], function, pc, insns[pc], new)
                with self.assertRaisesRegex(RuntimeError, "final-sink|layout|mode|lifecycle|retained"):
                    CHECKER["contract"](changed, "unsafe")

    def test_scalar_index_register_alias(self):
        changed = mutate(OBJECTS["default"], "p11_entry", 976, "r3 = r8", "w3 = w8")
        self.assertTrue(CHECKER["contract"](changed, "default")["verified"])

    def test_jmp32_cannot_prove_full_pointer_or_address(self):
        # Low32(0x100000000) is zero. Low32(RSP32 + argument offset)
        # can also fit the IA32 limit while the complete address overflows.
        cases = [("default", "p11_entry", 1109),
                 ("unsafe", "p11_entry", 1289),
                 ("default", "capture_scalar", 883),
                 ("default", "capture_scalar", 912),
                 ("unsafe", "capture_scalar", 1135),
                 ("unsafe", "capture_scalar", 1164),
                 ("unsafe", "p11_entry_ia32", 1784)]
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
        for variant, pc in (("default", 1109), ("unsafe", 1289)):
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
        for register in ("w7", "r7"):
            with self.subTest(register=register):
                changed = OBJECTS["unsafe"]
                for pc, old, new in (
                    (2096, "if r7 == 0x0 goto +0x1e", f"if {register} s> 0x0 goto +0x1"),
                    (2097, "*(u64 *)(r10 - 0x108) = r7", "goto +0x1d"),
                    (2098, "r9 &= 0x8", "*(u64 *)(r10 - 0x108) = r7"),
                ):
                    changed = mutate(changed, "p11_entry_ia32", pc, old, new)
                if register == "w7":
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
        cases = [("default", "capture_scalar", 870),  # ABI constant
                 ("default", "capture_scalar", 873),  # descriptor byte
                 ("default", "capture_scalar", 895),  # signed byte dispatch
                 ("unsafe", "capture_scalar", 1119),  # byte MOV32 alias
                 ("unsafe", "p11_entry_ia32", 1773),   # inline descriptor byte
                 ("unsafe", "p11_entry_ia32", 2096),   # successful u32 pointer
                 ("unsafe", "p11_entry_ia32", 2102)]   # u32 pointer and limit
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
        cases = [(async_name, 1203, "r3 = r7"),
                 (async_name, 1216, "r2 = 0x1c"),
                 (async_name, 1354, "r1 = r1"),
                 (async_name, 1354, "*(u32 *)(r6 + 0x100) = r1"),
                 ("p11_entry", 1596, "r0 = 0x0"),
                 ("p11_entry_template", 2710, "r0 = 0x0")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc, new=new):
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink|mode|decoder"):
                    CHECKER["contract"](mutate(OBJECTS["unsafe"], name, pc, old, new), "unsafe")

    def test_each_final_role_store_cannot_disappear(self):
        # Literal role stores from the independently inspected objects/layout.
        cases = {
            ("default", "p11_entry"): [983, 996, 1009, 1025, 1110, 1153, 1331, 1361, 1375],
            ("unsafe", "p11_entry"): [1104, 1157, 1210, 1270, 1550, 1392,
                1531, 1428, 1537, 1467, 1534, 1444, 1481,
                1540, 1437, 1546, 1487, 1543, 1451, 1501],
            ("unsafe", "p11_entry_ia32"): [1935, 1938, 1941, 2075, 2097, 2089, 2251, 2254],
        }
        for (variant, name), pcs in cases.items():
            insns = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[name]))
            for pc in pcs:
                with self.subTest(variant=variant, function=name, pc=pc):
                    self.assertTrue(insns[pc].startswith("*(u"))
                    with self.assertRaisesRegex(RuntimeError, "final-sink"):
                        CHECKER["contract"](mutate(OBJECTS[variant], name, pc, insns[pc], "r0 = r0"), variant)

    def test_callee_scalar_reads_and_option_success(self):
        for variant, delta in (("default", 0), ("unsafe", 252)):
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            name = next(name for name in blocks if name.endswith("capture_scalar"))
            insns = dict(CHECKER["D"].instructions(blocks[name]))
            cases = [(874, "r3 <<= 0x3"), (879, "r4 >>= 0x1f"),
                     (888, "r2 = 0x8"), (917, "r2 = 0x4"),
                     (938, "r1 = *(u64 *)(r2 + 0x68)"),
                     (945, "r1 = r1"), (947, "*(u64 *)(r6 + 0x0) = r1"),
                     (891, "if r0 == 0x0 goto +0x1e"),
                     (920, "r1 = *(u32 *)(r10 - 0x8)")]
            for pc, new in cases:
                pc += delta
                with self.subTest(variant=variant, pc=pc):
                    with self.assertRaisesRegex(RuntimeError, "scalar-read|final-sink"):
                        CHECKER["contract"](mutate(OBJECTS[variant], name, pc, insns[pc], new), variant)

    def test_template_order_layout_and_disabled_controls(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        cases = [("p11_entry_template", 2454, "r3 = *(u64 *)(r10 - 0x180)"),
                 ("p11_entry_template", 2613, "r3 = *(u64 *)(r10 - 0x160)"),
                 ("p11_entry_template", 2626, "r0 = 0x0"),
                 ("p11_entry_template_pair", 3105, "r0 = 0x0"),
                 ("p11_entry_template_pair", 3118, "call 0xc"),
                 ("p11_entry_template_types", 3713, "call 0x6bf"),
                 ("p11_entry_template_second", 3325, "r0 = 0x0"),
                 ("p11_entry", 1595, "r3 = 0x4"),
                 ("p11_entry_ia32", 2151, "r3 = 0x8")]
        for name, pc, new in cases:
            with self.subTest(function=name, pc=pc):
                old = dict(CHECKER["D"].instructions(blocks[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "final-sink|mode|layout"):
                    CHECKER["contract"](mutate(OBJECTS["unsafe"], name, pc, old, new), "unsafe")

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
                changed = mutate(OBJECTS["default"], "p11_entry", 1150, old, new)
                with self.assertRaisesRegex(RuntimeError, "final-sink 6: successful capture lost"):
                    CHECKER["contract"](changed, "default")
        restored = mutate(changed, "p11_entry", 1150, new, old)
        self.assertTrue(CHECKER["contract"](restored, "default")["verified"])

    def test_unknown_postwrite_and_callee_start_clobber(self):
        changed = mutate(OBJECTS["default"], "p11_entry", 1150,
                         "*(u32 *)(r10 - 0x68) = r4", "*(u64 *)(r5 + 0x0) = r4")
        with self.subTest(control="unknown postwrite"):
            with self.assertRaisesRegex(RuntimeError, "final-sink"):
                CHECKER["contract"](changed, "default")
        for variant, delta in (("default", 0), ("unsafe", 252)):
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            name = next(name for name in blocks if name.endswith("capture_scalar"))
            with self.subTest(variant=variant):
                changed = mutate(OBJECTS[variant], name, 925+delta,
                                 "*(u32 *)(r5 + 0x100) = r1", "*(u32 *)(r5 + 0x8) = r1")
                with self.assertRaisesRegex(RuntimeError, "final-sink"):
                    CHECKER["contract"](changed, variant)

    def test_helper_invocation_without_success_path_is_insufficient(self):
        cases = [("unsafe", "p11_entry", 1080, "goto +0x3")]
        for variant, delta in (("default", 0), ("unsafe", 252)):
            blocks = CHECKER["D"].function_blocks(OBJECTS[variant])
            scalar = next(name for name in blocks if name.endswith("capture_scalar"))
            cases.append((variant, scalar, 919+delta, "goto +0x2"))
        for variant, name, pc, new in cases:
            with self.subTest(variant=variant, function=name, pc=pc):
                old = dict(CHECKER["D"].instructions(CHECKER["D"].function_blocks(OBJECTS[variant])[name]))[pc]
                with self.assertRaisesRegex(RuntimeError, "scalar-read.*index coverage"):
                    CHECKER["contract"](mutate(OBJECTS[variant], name, pc, old, new), variant)

    def test_success_cannot_exit_before_sink_or_lose_pair_tail(self):
        blocks = CHECKER["D"].function_blocks(OBJECTS["unsafe"])
        entry = dict(CHECKER["D"].instructions(blocks["p11_entry"]))
        exit_pc = next(pc for pc, text in entry.items() if text == "exit")
        cases = [("p11_entry", 1100, f"goto +{exit_pc-1101:#x}"),
                 ("p11_entry_template_pair", 3142, "r0 = 0x0")]
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
            ("p11_entry", 835, "r1 <<= 0x20", "r1 <<= 0x1f"),
            ("p11_entry", 880, "r0 >>= 0x20", "r0 >>= 0x1f"),
            ("p11_entry", 878, "r1 = r6", "r1 = r10"),
            ("p11_entry", 899, "if r0 == 0x0 goto +0xd", "goto +0xd"),
            ("p11_entry", 899, "if r0 == 0x0 goto +0xd", "if r0 != 0x0 goto +0xd"),
            ("p11_entry", 899, "if r0 == 0x0 goto +0xd", "if r0 == 0x0 goto +0xc"),
            ("p11_entry", 888, "r2 = 0xff", "r2 = 0x0"),
            ("p11_entry", 866, "*(u32 *)(r10 - 0x168) = r8", "*(u32 *)(r10 - 0x168) = r0"),
            ("p11_entry", 845, "*(u32 *)(r10 - 0x170) = r8", "*(u32 *)(r10 - 0x170) = r0"),
            ("p11_return", 1209, "*(u32 *)(r10 - 0xb8) = r1", "*(u32 *)(r10 - 0xb8) = r0"),
            ("p11_entry", 850, "if r1 == 0x23 goto +0xe", "goto +0xe"),
            ("p11_entry", 854, "r2 = 0x0", "r2 = 0x1"),
            ("p11_entry", 855, "call 0x64d", "r0 = 0x0"),
            ("p11_entry", 856, "r1 = 0x8", "r1 = 0x7"),
            ("p11_entry", 864, "goto +0x134", "goto +0x1"),
            ("p11_return", 1412, "*(u32 *)(r0 + 0x68) = r1", "*(u32 *)(r0 + 0x68) = r2"),
            ("p11_entry", 848, "*(u32 *)(r10 - 0x16c) = r7", "if r7 == 0x0 goto +0x10"),
            ("p11_return", 1227, "call 0x2", "r0 = 0x0"),
            ("p11_return", 1074, "call 0x64d", "r0 = 0x0"),
            ("p11_return", 1413, "*(u64 *)(r0 + 0x60) = r9", "*(u32 *)(r0 + 0x69) = r9"),
            ("p11_entry", 844, "call 0xe", "call 0x5"),
            ("p11_entry", 848, "*(u32 *)(r10 - 0x16c) = r7", "*(u32 *)(r10 - 0x16c) = r8"),
            ("p11_entry", 846, "*(u64 *)(r10 - 0x178) = r0", "*(u32 *)(r10 - 0x178) = r0"),
            ("p11_entry", 916, "*(u64 *)(r10 - 0x168) = r1", "*(u8 *)(r10 - 0x175) = r1"),
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
        changed = mutate(disassembly, "p11_entry", 888, "r2 = 0xff", "w2 = 0xff")
        self.assertTrue(CHECKER["contract"](changed, "default")["verified"])
        changed = mutate(disassembly, "p11_entry", 888, "r2 = 0xff", "w2 ^= 0xff")
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
        changed = mutate(OBJECTS["default"], "p11_return", 1413,
                         "*(u64 *)(r0 + 0x60) = r9", "*(u32 *)(r0 + 0x69) = r9")
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
        changed = mutate(OBJECTS["default"], "p11_return", 1413,
                         "*(u64 *)(r0 + 0x60) = r9", "r9 = 0x400")
        changed = mutate(changed, "p11_return", 1414,
                         "r1 = *(u64 *)(r10 - 0x130)",
                         "r9 = atomic_fetch_or((u64 *)(r0 + 0x68), r9)")
        with self.assertRaisesRegex(RuntimeError, r"Event.slot corrupted before submit"):
            CHECKER["contract"](changed, "default")

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
        OBJECTS[variant] = subprocess.run(
            ["llvm-objdump", "-dr", "--print-imm-hex", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout
    unittest.main(argv=[sys.argv[0], *remaining])
