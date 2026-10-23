# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-free counter checker controls and exact command-line modes."""

import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-counter-object.py"


def bank_template_fixture(*, outer_banks=2, inner_type=6, inner_cells=1,
                          value_bytes=24, values_length=0):
    """Small literal BTF shapes; no compiler, host BTF or runtime map needed."""
    strings = bytearray(b"\0")
    types = []

    def name(value):
        at = len(strings)
        strings.extend(value.encode() + b"\0")
        return at

    def add(kind, value, payload=b"", *, label="", count=0):
        types.append(struct.pack("<III", name(label) if label else 0,
                                 kind << 24 | count, value) + payload)
        return len(types)

    u32 = add(1, 4, struct.pack("<I", 32), label="u32")
    u64 = add(1, 8, struct.pack("<I", 64), label="u64")

    def pointer(ref):
        return add(2, ref)

    def integer(value):
        return pointer(add(3, 0, struct.pack("<III", u32, u32, value)))

    def structure(fields, size):
        return add(4, size, b"".join(struct.pack("<III", name(n), ref, offset)
                                   for n, ref, offset in fields), count=len(fields))

    counts = structure([("entered", u64, 0), ("returned", u64, 64),
                        ("errors", u64, 128)], value_bytes)
    inner = structure([("type", integer(inner_type), 0),
                       ("max_entries", integer(inner_cells), 64),
                       ("key", pointer(u32), 128), ("value", pointer(counts), 192)], 32)
    values = add(3, 0, struct.pack("<III", pointer(inner), u32, values_length))
    outer = structure([("type", integer(13), 0), ("max_entries", integer(outer_banks), 64),
                       ("map_flags", integer(128), 128), ("key", pointer(u32), 192),
                       ("values", values, 256)], 32)
    raw = b"".join(types)
    return struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(raw), len(raw),
                       len(strings)) + raw + strings, outer


class CounterObjectCliTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(CHECKER), *arguments],
                              cwd=ROOT, text=True, capture_output=True)

    def test_self_test_runs_real_transfer_controls_without_an_object(self):
        result = self.invoke("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        controls = json.loads(result.stdout)["transfer_controls"]
        self.assertGreaterEqual(len(controls), 37)
        self.assertEqual(controls["le_equality32_oob"], "refused")
        self.assertEqual(controls["constant_left_clamp32_high_alias"], "refused")
        self.assertEqual(controls["le_healthy_index31"], "accepted")
        self.assertEqual(controls["constant_left_clamp64"], "accepted")

    def test_self_test_refuses_mixed_object_modes(self):
        for arguments in (("--mode", "counts"), ("missing.o",), ("--self-test-mutants",)):
            with self.subTest(arguments=arguments):
                result = self.invoke("--self-test", *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--self-test accepts no other arguments", result.stderr)

    def test_object_modes_still_require_both_inputs_and_exact_options(self):
        for arguments in ((), ("--mode", "counts"), ("missing.o",),
                          ("--self-test-mutants",), ("--self-t",)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
        result = self.invoke("missing.o", "--mode", "counts")
        self.assertEqual(result.returncode, 2)
        self.assertIn("counter object refused:", result.stderr)
        result = self.invoke("--self-test-m", "missing.o", "--mode", "counts")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --self-test-m", result.stderr)

    def test_bank_proof_profile_is_explicit_and_counts_only(self):
        result = self.invoke("--profile", "counts-bank-proof", "--mode", "counts", "missing.o")
        self.assertEqual(result.returncode, 2)
        self.assertIn("counter object refused:", result.stderr)
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode):
                result = self.invoke("--profile", "counts-bank-proof", "--mode", mode,
                                     "missing.o")
                self.assertEqual(result.returncode, 2)
                self.assertIn("bank proof requires counts", result.stderr)
        result = self.invoke("--self-test", "--profile", "counts-bank-proof")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--self-test accepts no other arguments", result.stderr)

    def test_growth_profile_is_explicit_and_counts_only(self):
        profile = "counts-bank-growth-v2"
        result = self.invoke("--profile", profile, "--mode", "counts", "missing.o")
        self.assertEqual(result.returncode, 2)
        self.assertIn("counter object refused:", result.stderr)
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode):
                result = self.invoke("--profile", profile, "--mode", mode, "missing.o")
                self.assertEqual(result.returncode, 2)
                self.assertIn("bank proof requires counts", result.stderr)
        result = self.invoke("--self-test", "--profile", profile)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--self-test accepts no other arguments", result.stderr)

    def test_native_owner_bound_is_explicit_and_independent_of_stats_capacity(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_owner_bound_test")
        key = (1, 0)

        class Graph:
            def __init__(self, limit):
                self.instructions = {key: {
                    0: (0x61, 0x12, 8, 0), 1: (0x25, 2, 1, limit - 1),
                    2: (0xb7, 0, 0, 1), 3: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("owner_bound",)}

            @staticmethod
            def only(name):
                if name != "p11_owner_start_aggregate":
                    raise RuntimeError("unexpected owner-bound callee")
                return key

        maps = {"STATS": {"max_entries": 512}}
        self.assertEqual(checker["native_owner_bound"](Graph(512), maps).native_bound, 512)
        self.assertEqual(checker["native_owner_bound"](
            Graph(8192), maps, expected_bound=8192).native_bound, 8192)
        for limit, expected in ((8192, 512), (512, 8192), (8191, 8192), (8193, 8192)):
            with self.subTest(limit=limit, expected=expected):
                with self.assertRaises(RuntimeError):
                    checker["native_owner_bound"](Graph(limit), maps, expected_bound=expected)
        missing = Graph(8192)
        missing.instructions[key][1] = (0xbf, 0, 0, 0)
        with self.assertRaises(RuntimeError):
            checker["native_owner_bound"](missing, maps, expected_bound=8192)

    def test_native_owner_shift_guard_is_key_bound_and_profile_specific(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_owner_shift_test")
        key = (1, 0)

        class Graph:
            def __init__(self, shift, key_offset=8):
                self.instructions = {key: {
                    0: (0x79, 0x12, key_offset, 0), 1: (0x77, 2, 0, shift),
                    2: (0x55, 2, 1, 0), 3: (0xb7, 0, 0, 1), 4: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("owner_shift",)}

            @staticmethod
            def only(name):
                if name != "p11_owner_start_aggregate":
                    raise RuntimeError("unexpected owner-shift callee")
                return key

        for shift, expected in ((9, 512), (13, 8192)):
            with self.subTest(healthy_shift=shift):
                proof = checker["native_owner_bound"](Graph(shift), {}, expected_bound=expected)
                self.assertEqual(proof.native_bound, expected)
                self.assertEqual(proof.guards, {(key, 2, "shift", shift)})
        for shift, expected, offset in ((9, 8192, 8), (13, 512, 8),
                                         (12, 8192, 8), (14, 8192, 8), (13, 8192, 0),
                                         (-1, 8192, 8), (63, 8192, 8), (77, 8192, 8)):
            with self.subTest(shift=shift, expected=expected, offset=offset):
                with self.assertRaises(RuntimeError):
                    checker["native_owner_bound"](
                        Graph(shift, offset), {}, expected_bound=expected)
        truncated = Graph(13)
        truncated.instructions[key][2] = (0x56, 2, 1, 0)
        with self.assertRaises(RuntimeError):
            checker["native_owner_bound"](truncated, {}, expected_bound=8192)

    def test_bank_endpoint_cannot_inherit_cleanup_loop_helper_permission(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_endpoint_helper_test")
        key = (1, 0)

        class Graph:
            def __init__(self, helper):
                self.instructions = {key: {0: (0x85, 0, 0, helper), 1: (0x95, 0, 0, 0)}}
                self.calls = {(key, 0): ("helper", helper)}
                self.loops, self.bodies = {key: {}}, {key: ("bank_endpoint",)}

        checker["BankFootprint"](Graph(14), {}).run(key, [None] * 5)
        with self.assertRaisesRegex(RuntimeError, "forbidden/unknown helper 181"):
            checker["BankFootprint"](Graph(181), {}).run(key, [None] * 5)

    def test_bank_native_bound_mutants_change_the_tagged_guard_producer(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_owner_mutant_test")
        key = (1, 0)
        instructions = [(0x79, 0x12, 8, 0), (0x77, 2, 0, 13),
                        (0x55, 2, 1, 0), (0xb7, 0, 0, 1), (0x95, 0, 0, 0)]
        body = b"".join(struct.pack("<BBhi", *row) for row in instructions)

        class Graph:
            def __init__(self, raw):
                self.instructions = {key: {at // 8: struct.unpack_from("<BBhi", raw, at)
                                           for at in range(0, len(raw), 8)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("owner_mutant",)}

            @staticmethod
            def only(name):
                if name != "p11_owner_start_aggregate":
                    raise RuntimeError("unexpected owner-mutant callee")
                return key

            @staticmethod
            def file_offset(function, pc):
                if function != key:
                    raise RuntimeError("unexpected owner-mutant function")
                return pc * 8

        graph = Graph(body)
        proof = checker["native_owner_bound"](graph, {}, expected_bound=8192)
        mutants = checker["bank_owner_bound_mutants"](body, graph, proof)
        self.assertEqual(set(mutants), {"native_owner_slot_bound", "missing_native_owner_slot_bound",
                                       "legacy_native_owner_slot_bound"})
        self.assertEqual(struct.unpack_from("<BBhi", mutants["native_owner_slot_bound"], 8),
                         (0x77, 2, 0, 12))
        self.assertEqual(struct.unpack_from("<BBhi", mutants["legacy_native_owner_slot_bound"], 8),
                         (0x77, 2, 0, 9))
        for label, changed in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(changed, body)
                with self.assertRaises(RuntimeError):
                    checker["native_owner_bound"](Graph(changed), {}, expected_bound=8192)
        legacy = Graph(mutants["legacy_native_owner_slot_bound"])
        self.assertEqual(checker["native_owner_bound"](legacy, {}).native_bound, 512)
        direct = [(0x61, 0x12, 8, 0), (0x25, 2, 1, 8191),
                  (0xb7, 0, 0, 1), (0x95, 0, 0, 0)]
        body = b"".join(struct.pack("<BBhi", *row) for row in direct)
        graph = Graph(body)
        proof = checker["native_owner_bound"](graph, {}, expected_bound=8192)
        mutants = checker["bank_owner_bound_mutants"](body, graph, proof)
        self.assertEqual(struct.unpack_from("<BBhi", mutants["native_owner_slot_bound"], 8),
                         (0x25, 2, 1, 8190))
        self.assertEqual(struct.unpack_from("<BBhi", mutants["legacy_native_owner_slot_bound"], 8),
                         (0x25, 2, 1, 511))
        for label, changed in mutants.items():
            with self.subTest(direct_mutant=label):
                with self.assertRaises(RuntimeError):
                    checker["native_owner_bound"](Graph(changed), {}, expected_bound=8192)

    def test_bank_template_decoder_is_scoped_and_refuses_wrong_inner_shapes(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_template_test")
        body, ref = bank_template_fixture()
        with self.assertRaises(RuntimeError):
            checker["MAPS"].Btf(body).map_definition(ref)
        self.assertIn("BankBtf", checker, "proof-only template decoder is not implemented")
        definition, size = checker["BankBtf"](body).map_definition(ref)
        self.assertEqual(size, 32)
        self.assertEqual(definition["type"], 13)
        self.assertEqual(definition["value_size"], 4)
        self.assertEqual(definition["inner_template"]["type"], 6)
        self.assertEqual(definition["inner_template"]["value_size"], 24)
        for changes in ({"inner_type": 2}, {"inner_cells": 2},
                        {"value_bytes": 40}, {"values_length": 1}):
            with self.subTest(changes=changes):
                body, ref = bank_template_fixture(**changes)
                with self.assertRaises(RuntimeError):
                    checker["BankBtf"](body).map_definition(ref)

    def test_growth_template_is_exact_and_does_not_broaden_format1(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_template_test")
        self.assertTrue("BankGrowthBtf" in checker, "explicit format2 template decoder is missing")
        body, ref = bank_template_fixture(outer_banks=16, inner_cells=512)
        for decoder in (checker["MAPS"].Btf, checker["BankBtf"]):
            with self.subTest(decoder=decoder.__name__):
                with self.assertRaises(RuntimeError):
                    decoder(body).map_definition(ref)
        definition, size = checker["BankGrowthBtf"](body).map_definition(ref)
        self.assertEqual(size, 32)
        self.assertEqual(definition, {
            "type": 13, "key_size": 4, "value_size": 4, "max_entries": 16, "flags": 128,
            "id": 0, "pinning": 0,
            "inner_template": {
                "type": 6, "key_size": 4, "value_size": 24, "max_entries": 512, "flags": 0,
                "id": 0, "pinning": 0,
            },
        })
        for changes in ({"outer_banks": 2}, {"outer_banks": 0}, {"outer_banks": 17},
                        {"inner_cells": 1}, {"inner_cells": 511}, {"inner_cells": 513},
                        {"inner_type": 2}, {"value_bytes": 40}, {"values_length": 1}):
            with self.subTest(changes=changes):
                options = {"outer_banks": 16, "inner_cells": 512, **changes}
                body, ref = bank_template_fixture(**options)
                with self.assertRaises(RuntimeError):
                    checker["BankGrowthBtf"](body).map_definition(ref)
        legacy, ref = bank_template_fixture()
        with self.assertRaises(RuntimeError):
            checker["BankGrowthBtf"](legacy).map_definition(ref)
        legacy_definition, _ = checker["BankBtf"](legacy).map_definition(ref)
        self.assertEqual(legacy_definition["max_entries"], 2)
        self.assertEqual(legacy_definition["inner_template"]["max_entries"], 1)

    def test_growth_footprint_requires_bounded_outer_and_inner_keys(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_footprint_test")
        frame = (1, 0)
        maps = {"COUNTER_BANKS": {"value_size": 4},
                "COUNTER_BANK_VALUE": {"value_size": 24}}
        proof = checker["BankFootprint"](None, maps, native_bound=8192, growth=True)

        def lookup(mapped, low, high):
            registers = [None] * 11
            registers[1], registers[2] = mapped, ("stack", frame, -4)
            memory = {(frame, -4, 4): checker["scalar"](low, high)}
            proof.helper(1, registers, memory, frame, 0)
            return registers[0]

        outer = lookup(("map", "COUNTER_BANKS"), 0, 15)
        self.assertEqual(outer[:4], ("ptr", "COUNTER_BANKS", 0, 0))
        self.assertEqual(lookup(outer, 0, 511)[:4], ("ptr", "COUNTER_BANK_VALUE", 0, 0))
        for mapped, low, high in ((("map", "COUNTER_BANKS"), 0, 16),
                                  (outer, 0, 512), (("ptr", "COUNTER_BANKS", 1, 1, None), 0, 0)):
            with self.subTest(mapped=mapped, low=low, high=high):
                with self.assertRaises(RuntimeError):
                    lookup(mapped, low, high)
        legacy = checker["BankFootprint"](None, maps)
        registers = [None] * 11
        registers[1], registers[2] = outer, ("stack", frame, -4)
        with self.assertRaises(RuntimeError):
            legacy.helper(1, registers, {(frame, -4, 4): checker["constant"](1)}, frame, 0)

    def test_growth_execution_separates_shared_cells_and_full64_commit_keys(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_lookup_test")
        vm = checker["BankExecution"](None, growth=True)

        def lookup(handle, raw_key):
            key = vm.set("lookup_fixture_key", 0, raw_key)
            registers = [0] * 11
            registers[1], registers[2] = handle, key
            return vm.helper(1, registers, (1, 0), 0)

        bank0 = lookup(vm.handles["COUNTER_BANKS"], bytes(4))
        first = lookup(bank0, bytes(4))
        last = lookup(bank0, (511).to_bytes(4, "little"))
        self.assertEqual(first, vm.bank_storage[0])
        self.assertEqual(last, vm.bank_storage[511])
        self.assertNotEqual(first, last)
        self.assertEqual(lookup(bank0, (512).to_bytes(4, "little")), 0)
        high = 0x1_0000_0007
        low_body, high_body = struct.pack("<IIQ", 0, 1, 0x18000102), struct.pack("<IIQ", 511, 513, 0x0200001800100200)
        low_address = vm.set("COUNTER_BANK_COMMIT", 7, low_body)
        self.assertEqual(lookup(vm.handles["COUNTER_BANK_COMMIT"], high.to_bytes(8, "little")), 0)
        high_address = vm.set("COUNTER_BANK_COMMIT", high, high_body)
        self.assertEqual(lookup(vm.handles["COUNTER_BANK_COMMIT"], high.to_bytes(8, "little")), high_address)
        self.assertEqual(lookup(vm.handles["COUNTER_BANK_COMMIT"], (7).to_bytes(8, "little")), low_address)
        self.assertNotEqual(low_address, high_address)

    def test_bank_instruction_execution_preserves_existing_sticky_fault_bits(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_vm_test")

        class Graph:
            def __init__(self, atomic):
                self.instructions = {(1, 0): {0: (0xdb, 0x21, 0, atomic),
                                              1: (0xbf, 0x20, 0, 0), 2: (0x95, 0, 0, 0)}}

        for atomic, returned in ((0x40, 1), (0x41, 2)):
            with self.subTest(atomic=atomic):
                vm = checker["BankExecution"](Graph(atomic))
                at = vm.set("COUNTER_BANK_FAULT", 0, (2).to_bytes(8, "little"))
                self.assertEqual(vm.execute((1, 0), [at, 1], 0), returned,
                                 "only OR|FETCH replaces its source with the old cell")
                self.assertEqual(vm.fault(), 3, "actual OR must retain both refusal bits")

    def test_bank_fault_footprint_requires_finite_full_width_or_and_clobbers_fetch(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_fault_transfer_test")
        key = (1, 0)

        class Graph:
            def __init__(self, instructions):
                self.instructions = {key: dict(enumerate(instructions + [(0x95, 0, 0, 0)]))}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("fault_control",)}

        pointer = ("ptr", "COUNTER_BANK_FAULT", 0, 0, checker["ZERO"])
        maps = {"COUNTER_BANK_FAULT": {"value_size": 8}}

        def run(instructions, operand=None):
            proof = checker["BankFootprint"](Graph(instructions), maps)
            proof.run(key, [pointer, checker["ONE"] if operand is None else operand,
                            None, None, None])
            return proof

        for atomic in (0x40, 0x41):
            with self.subTest(healthy_atomic=atomic):
                proof = run([(0xdb, 0x21, 0, atomic)])
                self.assertEqual(len(proof.touches), 1)
        for instructions, operand in (
                ([(0xc3, 0x21, 0, 0x41)], None),
                ([(0xdb, 0x21, 0, 0x51)], None),
                ([(0xdb, 0x21, 1, 0x41)], None),
                ([(0xdb, 0x21, 0, 0x41)], checker["ZERO"]),
                ([(0xdb, 0x21, 0, 0x41)], checker["constant"](16)),
                ([(0xdb, 0x21, 0, 0x41)], checker["scalar"]()),
                ([(0xdb, 0x21, 0, 0x41), (0xdb, 0x21, 0, 0x40)], None)):
            with self.subTest(instructions=instructions, operand=operand):
                with self.assertRaisesRegex(RuntimeError, "finite sticky OR"):
                    run(instructions, operand)

    def test_bank_instruction_execution_does_not_reuse_previous_stack_bytes(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_stack_test")

        class Graph:
            instructions = {(1, 0): {0: (0x79, 0xa0, -8, 0), 1: (0x95, 0, 0, 0)}}

        vm = checker["BankExecution"](Graph())
        for index, byte in enumerate((17).to_bytes(8, "little")):
            vm.memory[0x80000000 - 8 + index] = byte
        with self.assertRaisesRegex(RuntimeError, "unknown/out-of-bounds"):
            vm.execute((1, 0), [], 0)

    def test_bank_footprint_prunes_only_proven_constant_equality_edges(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_null_edge_test")
        key = (1, 0)
        exit_instruction = (0x95, 0, 0, 0)
        invalid_read = (0x79, 0x10, 8, 0)

        class Graph:
            def __init__(self, instructions):
                self.instructions = {key: dict(enumerate(instructions))}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("null_edge",)}

        def run(opcode, value):
            # A literal zero must bypass the invalid scalar-as-pointer read;
            # a nonzero value must reach it and remain a refusal.
            instructions = ([(opcode, 1, 1, 0), invalid_read, exit_instruction]
                            if opcode & 0xf0 == 0x10 else
                            [(opcode, 1, 1, 0), exit_instruction, invalid_read,
                             exit_instruction])
            proof = checker["BankFootprint"](Graph(instructions), {})
            proof.run(key, [checker["constant"](value), None, None, None, None])
            return proof

        for opcode in (0x15, 0x55, 0x16, 0x56):
            with self.subTest(opcode=opcode):
                self.assertEqual(run(opcode, 0).touches, set())
                with self.assertRaisesRegex(RuntimeError, "unknown counter read"):
                    run(opcode, 1)
                if opcode & 7 == 6:
                    with self.assertRaisesRegex(RuntimeError, "unknown counter read"):
                        run(opcode, 1 << 32)

    def test_bank_optional_get_requires_dead_argument_and_real_quiet_absence(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_optional_get_test")
        key = (1, 0)

        class Graph:
            def __init__(self):
                self.instructions = {key: {
                    0: (0xbf, 0x17, 0, 0), 1: (0xbf, 0xa2, 0, 0),
                    2: (0x07, 2, 0, -4), 3: (0x62, 10, -4, 0),
                    4: (0x18, 1, 0, 0), 6: (0x85, 0, 0, 1),
                    7: (0xbf, 8, 0, 0), 8: (0xbf, 0x72, 0, 0),
                    9: (0x18, 1, 0, 0), 11: (0x85, 0, 0, 1),
                    12: (0x55, 0, 9, 0), 13: (0x85, 0, 0, 158),
                    14: (0xbf, 2, 0, 0), 15: (0x18, 1, 0, 0),
                    17: (0xb7, 3, 0, 0), 18: (0xb7, 4, 0, 0),
                    19: (0x85, 0, 0, 156), 20: (0xb7, 0, 0, 0),
                    21: (0x95, 0, 0, 0), 22: (0xb7, 1, 0, 1),
                    23: (0xdb, 0x18, 16, 0x41), 24: (0xb7, 0, 0, 0),
                    25: (0x95, 0, 0, 0)}}
                self.calls = {(key, pc): ("helper", helper) for pc, helper in
                              ((6, 1), (11, 1), (13, 158), (19, 156))}

            def only(self, name):
                if name != "p11_owner_start_get":
                    raise RuntimeError("unexpected test callee")
                return key

            def map_at(self, function, pc):
                self.assert_key(function)
                return {4: "OWNER_CTL", 9: "START", 15: "THREAD_OWNER"}[pc]

            @staticmethod
            def assert_key(function):
                if function != key:
                    raise RuntimeError("unexpected test function")

        graph = Graph()
        self.assertEqual(checker["bank_optional_start_get"](graph), (key, 11))
        for first in ((0xbf, 0x27, 0, 0), (0x07, 2, 0, 1),
                      (0x79, 0x20, 0, 0), (0x15, 1, 0, 0), (0x85, 0, 0, 1)):
            with self.subTest(live_argument=first):
                changed = Graph()
                changed.instructions[key][0] = first
                self.assertIsNone(checker["bank_optional_start_get"](changed))
        for pc, instruction in ((11, (0xb7, 0, 0, 1)),
                                (18, (0xb7, 4, 0, 1)), (20, (0xb7, 0, 0, 1))):
            with self.subTest(unsafe_absence=(pc, instruction)):
                changed = Graph()
                changed.instructions[key][pc] = instruction
                with self.assertRaises(RuntimeError):
                    checker["bank_optional_start_get"](changed)

    def test_bank_counts_start_timestamp_requires_one_full_zero_word(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_timestamp_test")
        key = (1, 0)

        class Graph:
            def __init__(self, instruction):
                self.instructions = {key: {0: instruction, 1: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("seed_control",)}

        pointer = ("ptr", "START", 0, 0, checker["ZERO"])

        def run(instruction, value):
            proof = checker["BankFootprint"](Graph(instruction), {"START": {"value_size": 288}})
            proof.run(key, [pointer, value, None, None, None])
            return proof

        self.assertEqual(len(run((0x7b, 0x21, 0, 0), checker["ZERO"]).touches), 1)
        for instruction, value in (((0x7b, 0x21, 0, 0), checker["ONE"]),
                                   ((0x7b, 0x21, 0, 0), checker["scalar"]()),
                                   ((0x63, 0x21, 0, 0), checker["ZERO"]),
                                   ((0xdb, 0x21, 0, 0x40), checker["ZERO"])):
            with self.subTest(instruction=instruction, value=value):
                with self.assertRaisesRegex(RuntimeError, "START timestamp"):
                    run(instruction, value)

    def test_bank_instruction_contention_keeps_the_interfering_writer_value(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_cas_test")

        class Graph:
            instructions = {(1, 0): {0: (0x79, 0x10, 0, 0), 1: (0xb7, 2, 0, 99),
                                     2: (0xdb, 0x21, 0, 0xf1), 3: (0xb7, 0, 0, 0),
                                     4: (0x95, 0, 0, 0)}}

        vm = checker["BankExecution"](Graph())
        vm.contended.add("bank0")
        self.assertEqual(vm.execute((1, 0), [vm.bank_storage[0]], 0), 0)
        self.assertEqual(vm.row(0), (1, 0, 0), "failed CAS must preserve the real interfering update")


if __name__ == "__main__":
    unittest.main()
