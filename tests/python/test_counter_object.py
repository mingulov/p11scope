# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-free counter checker controls and exact command-line modes."""

import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-counter-object.py"
GROWTH_PROFILE_MODES = {
    "counts-bank-growth-v2": "counts",
    "timestamps-bank-growth-v2": "timestamps",
    "latency-bank-growth-v2": "latency",
}
GROWTH_CONFIG_WORDS = {
    "counts": 0x0200001800100200,
    "timestamps": 0x0200002800100200,
    "latency": 0x0200012800100200,
}


def bank_template_fixture(*, outer_banks=2, inner_type=6, inner_cells=1,
                          value_bytes=24, values_length=0, value_shape="counts"):
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

    if value_shape == "counts":
        members = [("entered", u64, 0), ("returned", u64, 64), ("errors", u64, 128)]
    elif value_shape == "counts_wrong_fields":
        members = [("entered", u64, 0), ("returned", u64, 64), ("total_ns", u64, 128)]
    elif value_shape == "timestamps":
        members = [("entered", u64, 0), ("returned", u64, 64), ("errors", u64, 128),
                   ("total_ns", u64, 192), ("max_ns", u64, 256)]
    elif value_shape == "latency":
        buckets = add(3, 0, struct.pack("<III", u64, u32, 32))
        members = [("entered", u64, 0), ("returned", u64, 64), ("errors", u64, 128),
                   ("total_ns", u64, 192), ("max_ns", u64, 256),
                   ("buckets", buckets, 320)]
    else:
        raise AssertionError(f"unknown bank value shape: {value_shape}")
    value = structure(members, value_bytes)
    inner = structure([("type", integer(inner_type), 0),
                       ("max_entries", integer(inner_cells), 64),
                       ("key", pointer(u32), 128), ("value", pointer(value), 192)], 32)
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

    def test_growth_profiles_are_explicit_and_mode_exact(self):
        for profile, mode in GROWTH_PROFILE_MODES.items():
            with self.subTest(profile=profile):
                result = self.invoke("--profile", profile, "--mode", mode, "missing.o")
                self.assertEqual(result.returncode, 2)
                self.assertIn("counter object refused:", result.stderr)
        for profile, mode in GROWTH_PROFILE_MODES.items():
            for other in ("counts", "timestamps", "latency"):
                if other == mode:
                    continue
                with self.subTest(profile=profile, mode=other):
                    result = self.invoke("--profile", profile, "--mode", other,
                                         "missing.o")
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(f"bank proof requires {mode}", result.stderr)
        for profile in GROWTH_PROFILE_MODES:
            with self.subTest(profile=profile):
                result = self.invoke("--self-test", "--profile", profile)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--self-test accepts no other arguments", result.stderr)
        with tempfile.NamedTemporaryFile(prefix="counter-timing-mutants-", suffix=".o") as stale:
            stale.write(b"not an ELF object")
            stale.flush()
            for profile, mode in GROWTH_PROFILE_MODES.items():
                if mode == "counts":
                    continue
                with self.subTest(profile=profile):
                    result = self.invoke("--profile", profile, "--mode", mode,
                                         "--self-test-mutants", stale.name)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(f"bank {mode} causal mutants need their built object",
                                  result.stderr)

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

    def test_growth_precomputed_bank_key_requires_all_unsigned_guards_and_defs(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_guarded_spill_test")
        key = (1, 0)

        class Graph:
            def __init__(self):
                self.instructions = {key: {
                    0: (0x61, 0x08, 12, 0), 1: (0x61, 0xa3, -4, 0),
                    2: (0xbf, 0x32, 0, 0), 3: (0x77, 2, 0, 9),
                    4: (0x63, 0x2a, -8, 0), 5: (0xbf, 0, 0, 0),
                    6: (0x25, 8, 6, 8192), 7: (0x3d, 0x83, 5, 0),
                    8: (0x61, 3, 16, 0), 9: (0x5d, 0x23, 3, 0),
                    10: (0xbf, 0, 0, 0), 11: (0x85, 0, 0, 1),
                    12: (0x95, 0, 0, 0), 13: (0x95, 0, 0, 0),
                }}
                self.calls = {(key, 11): ("helper", 1)}

        def lookup(graph):
            proof = checker["BankFootprint"](graph, {"COUNTER_BANKS": {"value_size": 4}},
                                               native_bound=8192, growth=True)
            proof.touches.update({
                (key, 0, "COUNTER_BANK_META", "read", (12, 12), 4, None),
                (key, 8, "COUNTER_BANK_META", "read", (16, 16), 4, None),
            })
            registers = [None] * 11
            frame = (key, 0)
            registers[1], registers[2] = ("map", "COUNTER_BANKS"), ("stack", frame, -8)
            proof.helper(1, registers, {(frame, -8, 4): checker["scalar"](0, 8388607)}, key, 11)
            self.assertEqual(registers[0][:4], ("ptr", "COUNTER_BANKS", 0, 0))
            self.assertEqual(proof.bank_key_proofs[key, 11, -8], (4, 6, 7, 9))

        lookup(Graph())
        narrow = Graph()
        for pc in (6, 7, 9):
            op, encoded, offset, immediate = narrow.instructions[key][pc]
            narrow.instructions[key][pc] = (op + 1, encoded, offset, immediate)
        lookup(narrow)  # both operands are genuine zero-extended words
        after_guard = Graph()
        after_guard.instructions[key][10] = (0x85, 0, 0, 1)
        after_guard.calls[key, 10] = ("helper", 1)
        lookup(after_guard)  # committed-map lookup cannot write the saved key
        damages = {
            "missing_end_bound": (6, (0xbf, 0, 0, 0)),
            "missing_slot_less_end": (7, (0xbf, 0, 0, 0)),
            "missing_bank_equality": (9, (0xbf, 0, 0, 0)),
            "wrong_bank_operand": (9, (0x5d, 0x43, 3, 0)),
            "wrong_shift": (3, (0x77, 2, 0, 8)),
            "high32_alias_slot": (1, (0x79, 0xa3, -4, 0)),
            "signed_comparison": (7, (0x7d, 0x83, 5, 0)),
            "failed_guard_reaches_lookup": (6, (0x25, 8, 4, 8192)),
            "end_guard_has_identical_edges": (6, (0x25, 8, 0, 8192)),
            "less_guard_has_identical_edges": (7, (0x3d, 0x83, 0, 0)),
            "bank_guard_has_identical_edges": (9, (0x5d, 0x23, 0, 0)),
            "clobbered_slot": (5, (0xb7, 3, 0, 1)),
            "overwritten_spill": (10, (0x63, 0x9a, -8, 0)),
            "unknown_writing_call": (10, (0x85, 0x10, 0, 1)),
            "caller_saved_before_guard": (5, (0x85, 0, 0, 1)),
            "cyclic_slot_redefinition": (5, (0x55, 9, -5, 0)),
            "changed_frame_pointer": (5, (0x07, 10, 0, 4)),
        }
        for label, (pc, replacement) in damages.items():
            with self.subTest(label=label):
                graph = Graph()
                graph.instructions[key][pc] = replacement
                if replacement[0] == 0x85:
                    graph.calls[key, pc] = ("helper", 1) if pc == 5 else ("function", (1, 1))
                with self.assertRaisesRegex(RuntimeError, "guarded|bounded"):
                    lookup(graph)

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

    def test_growth_timing_profiles_require_clock_and_exact_value_size(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_timing_rules_test")
        self.assertIn("bank_require_root_helpers", checker, "timing clock rule is not implemented")
        self.assertIn("bank_require_health", checker, "timing health rule is not implemented")
        self.assertIn("bank_require_inner_writes", checker, "timing inner-write rule is not implemented")
        self.assertIn("BankTimestampsGrowthBtf", checker,
                      "timestamps template decoder is not implemented")
        self.assertIn("BankLatencyGrowthBtf", checker, "latency template decoder is not implemented")
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode, clocks="present"):
                self.assertIsNone(checker["bank_require_root_helpers"]([1, 5, 14], mode))
            with self.subTest(mode=mode, clocks="absent"):
                with self.assertRaisesRegex(RuntimeError, "has no clock read"):
                    checker["bank_require_root_helpers"]([1, 14], mode)
            with self.subTest(mode=mode, clocks="semantic helper"):
                with self.assertRaisesRegex(RuntimeError, "forbidden/unknown helper 112"):
                    checker["bank_require_root_helpers"]([5, 112], mode)
        key = (1, 0)
        self.assertIsNone(checker["bank_require_health"]({(key, 0, 0, 0), (key, 1, 1, 1)}))
        self.assertIsNone(checker["bank_require_health"]({(key, 0, 0, 1)}))
        for health in (set(), {(key, 0, 0, 0)}, {(key, 0, 1, 1)}):
            with self.subTest(health=health):
                with self.assertRaisesRegex(RuntimeError, "saturated/contended health"):
                    checker["bank_require_health"](health)

        def writes(*offsets):
            return {(key, pc, "COUNTER_BANK_VALUE", "write", (offset, offset), 8, 0xf1)
                    for pc, offset in enumerate(offsets)}

        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode, root="entry"):
                self.assertIsNone(checker["bank_require_inner_writes"](writes(0), mode, True))
                with self.assertRaisesRegex(
                        RuntimeError, f"bank {mode} proof omits its inner field update at 0"):
                    checker["bank_require_inner_writes"](set(), mode, True)
            with self.subTest(mode=mode, root="return"):
                full = writes(8, 16, 24, 32)
                self.assertIsNone(checker["bank_require_inner_writes"](full, mode, False))
                for offset in (8, 16, 24, 32):
                    with self.subTest(missing=offset):
                        with self.assertRaisesRegex(RuntimeError, f"at {offset}"):
                            checker["bank_require_inner_writes"](
                                {touch for touch in full if touch[4] != (offset, offset)},
                                mode, False)
                touched = {(key, 9, "COUNTER_BANK_VALUE", "read", (32, 32), 8, None)}
                with self.subTest(reads_do_not_count=True):
                    with self.assertRaisesRegex(RuntimeError, "at 32"):
                        checker["bank_require_inner_writes"](
                            writes(8, 16, 24) | touched, mode, False)
        for mode, decoder, size in (("timestamps", "BankTimestampsGrowthBtf", 40),
                                    ("latency", "BankLatencyGrowthBtf", 296)):
            with self.subTest(mode=mode):
                body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                                  value_bytes=size, value_shape=mode)
                definition, _ = checker[decoder](body).map_definition(ref)
                self.assertEqual(definition["max_entries"], 16)
                self.assertEqual(definition["inner_template"]["value_size"], size)

        class SeedGraph:
            def __init__(self, instruction):
                self.instructions = {key: {0: instruction, 1: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("timing_seed",)}

        pointer = ("ptr", "START", 0, 0, checker["ZERO"])

        def run(instruction, value, mode="timestamps"):
            proof = checker["BankFootprint"](SeedGraph(instruction),
                                             {"START": {"value_size": 288}}, mode=mode)
            proof.run(key, [pointer, value, None, None, None])
            return proof

        self.assertEqual(len(run((0x7b, 0x21, 0, 0), checker["scalar"]()).touches), 1)
        self.assertEqual(len(run((0x7b, 0x21, 0, 0), checker["scalar"](), "latency").touches), 1)
        for instruction, value in (((0x7b, 0x21, 0, 0), checker["ZERO"]),
                                   ((0x7b, 0x21, 0, 0), checker["constant"](7)),
                                   ((0x7b, 0x21, 4, 0), checker["scalar"]()),
                                   ((0x63, 0x21, 0, 0), checker["scalar"]()),
                                   ((0xdb, 0x21, 0, 0xf1), checker["scalar"]())):
            with self.subTest(instruction=instruction, value=value):
                with self.assertRaisesRegex(
                        RuntimeError, "timestamps START timestamp is not one full clock word"):
                    run(instruction, value)
        with self.subTest(mode="latency", value="zero"):
            with self.assertRaisesRegex(
                    RuntimeError, "latency START timestamp is not one full clock word"):
                run((0x7b, 0x21, 0, 0), checker["ZERO"], "latency")

    def test_growth_counts_profile_forbids_clock_and_histogram(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_counts_rules_test")
        self.assertIn("bank_require_root_helpers", checker, "bank clock rule is not implemented")
        self.assertIsNone(checker["bank_require_root_helpers"]([1, 2, 14], "counts"))
        with self.assertRaisesRegex(RuntimeError, "reaches clock/semantic/event/unknown helper"):
            checker["bank_require_root_helpers"]([1, 5], "counts")
        key = (1, 0)

        class Graph:
            def __init__(self, instruction):
                self.instructions = {key: {0: instruction, 1: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("counts_cells",)}

        pointer = ("ptr", "COUNTER_BANK_VALUE", 0, 0, checker["ZERO"])
        maps = {"COUNTER_BANK_VALUE": {"value_size": 24}}

        def run(instruction):
            proof = checker["BankFootprint"](Graph(instruction), maps, mode="counts")
            proof.run(key, [pointer, checker["ONE"], None, None, None])
            return proof

        for offset in (0, 8, 16):
            with self.subTest(offset=offset):
                self.assertEqual(len(run((0xdb, 0x21, offset, 0xf1)).touches), 1)
        for offset in (24, 32, 40, 288):
            with self.subTest(histogram_write=offset):
                with self.assertRaisesRegex(RuntimeError, "not an exact full-width field"):
                    run((0xdb, 0x21, offset, 0xf1))
        with self.subTest(histogram_read=40):
            with self.assertRaisesRegex(RuntimeError, "not an exact full-width field"):
                run((0x79, 0x10, 40, 0))

    def test_growth_mode_tokens_cannot_cross_configs(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_config_test")
        self.assertIn("BANK_GROWTH_CONFIGS", checker,
                      "per-mode bank configuration words are not implemented")
        self.assertIn("bank_require_growth_configuration", checker,
                      "configuration-word rule is not implemented")
        self.assertEqual(checker["BANK_GROWTH_CONFIGS"], GROWTH_CONFIG_WORDS)
        self.assertEqual(checker["BANK_GROWTH_CONFIG"], GROWTH_CONFIG_WORDS["counts"])
        key = (1, 0)

        class Graph:
            def __init__(self, words, mapped=()):
                self.instructions = {key: {pc * 2: (0x18, 1, 0, word & 0xffffffff)
                                           for pc, word in enumerate(words)}}
                body = bytearray()
                for word in words:
                    body += struct.pack("<BBhi", 0x18, 1, 0, word & 0xffffffff)
                    body += bytes(4) + struct.pack("<I", word >> 32)
                self.sections = {1: (None, bytes(body))}
                self.mapped = {(key, pc * 2) for pc in mapped}

            def map_at(self, function, pc):
                return "COUNTER_BANKS" if (function, pc) in self.mapped else None

        for mode, word in GROWTH_CONFIG_WORDS.items():
            with self.subTest(mode=mode, word="own"):
                self.assertIsNone(checker["bank_require_growth_configuration"](
                    Graph([word]), {key}, mode))
        for mode in GROWTH_CONFIG_WORDS:
            for other, other_word in GROWTH_CONFIG_WORDS.items():
                if other == mode:
                    continue
                with self.subTest(mode=mode, word=other):
                    with self.assertRaisesRegex(RuntimeError, "another mode's configuration word"):
                        checker["bank_require_growth_configuration"](
                            Graph([other_word]), {key}, mode)
        for mode in GROWTH_CONFIG_WORDS:
            with self.subTest(mode=mode, word="missing"):
                with self.assertRaisesRegex(RuntimeError, "omits its configuration word"):
                    checker["bank_require_growth_configuration"](
                        Graph([0x0102030405060708]), {key}, mode)
            with self.subTest(mode=mode, word="absent"):
                with self.assertRaisesRegex(RuntimeError, "omits its configuration word"):
                    checker["bank_require_growth_configuration"](Graph([]), {key}, mode)

    def test_growth_counts_mutant_clock_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_counts_clock_test")
        self.assertIn("bank_require_root_helpers", checker, "bank clock rule is not implemented")
        with self.assertRaisesRegex(
                RuntimeError, "^Counts bank root reaches clock/semantic/event/unknown helper$"):
            checker["bank_require_root_helpers"]([1, 5, 14], "counts")
        self.assertIsNone(checker["bank_require_root_helpers"]([1, 14], "counts"))

    def test_growth_timestamps_mutant_histogram_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_timestamps_cells_test")
        self.assertIn("BankTimestampsGrowthBtf", checker,
                      "timestamps template decoder is not implemented")
        key = (1, 0)

        class Graph:
            def __init__(self, instruction):
                self.instructions = {key: {0: instruction, 1: (0x95, 0, 0, 0)}}
                self.loops, self.calls, self.bodies = {key: {}}, {}, {key: ("timestamp_cells",)}

        pointer = ("ptr", "COUNTER_BANK_VALUE", 0, 0, checker["ZERO"])
        maps = {"COUNTER_BANK_VALUE": {"value_size": 40}}

        def run(instruction):
            proof = checker["BankFootprint"](Graph(instruction), maps, mode="timestamps")
            proof.run(key, [pointer, checker["ONE"], None, None, None])
            return proof

        for offset in (0, 8, 16, 24, 32):
            with self.subTest(offset=offset):
                self.assertEqual(len(run((0xdb, 0x21, offset, 0xf1)).touches), 1)
        for offset in (40, 48, 288):
            with self.subTest(histogram_write=offset):
                with self.assertRaisesRegex(
                        RuntimeError, "^bank Timestamps access is not an exact full-width field$"):
                    run((0xdb, 0x21, offset, 0xf1))
        with self.subTest(histogram_read=40):
            with self.assertRaisesRegex(
                    RuntimeError, "^bank Timestamps access is not an exact full-width field$"):
                run((0x79, 0x10, 40, 0))
        with self.subTest(max_read=32):
            self.assertEqual(len(run((0x79, 0x10, 32, 0)).touches), 1)

    def test_growth_mutant_wrong_config_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_config_mutant_test")
        self.assertIn("bank_require_growth_configuration", checker,
                      "configuration-word rule is not implemented")
        key = (1, 0)

        class Graph:
            def __init__(self, words, mapped=()):
                self.instructions = {key: {pc * 2: (0x18, 1, 0, word & 0xffffffff)
                                           for pc, word in enumerate(words)}}
                body = bytearray()
                for word in words:
                    body += struct.pack("<BBhi", 0x18, 1, 0, word & 0xffffffff)
                    body += bytes(4) + struct.pack("<I", word >> 32)
                self.sections = {1: (None, bytes(body))}
                self.mapped = {(key, pc * 2) for pc in mapped}

            def map_at(self, function, pc):
                return "COUNTER_BANKS" if (function, pc) in self.mapped else None

        words = GROWTH_CONFIG_WORDS
        with self.subTest(case="coexisting words name the intruder"):
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timestamps proof carries another mode's configuration word: counts$"):
                checker["bank_require_growth_configuration"](
                    Graph([words["timestamps"], words["counts"]]), {key}, "timestamps")
        with self.subTest(case="relocated literal is not a configuration word"):
            with self.assertRaisesRegex(
                    RuntimeError, "^bank latency proof omits its configuration word$"):
                checker["bank_require_growth_configuration"](
                    Graph([words["latency"]], mapped=(0,)), {key}, "latency")
        with self.subTest(case="garbage word"):
            with self.assertRaisesRegex(
                    RuntimeError, "^bank counts proof omits its configuration word$"):
                checker["bank_require_growth_configuration"](
                    Graph([words["counts"] ^ 0x0100000000000000]), {key}, "counts")
        with self.subTest(case="unknown mode"):
            with self.assertRaisesRegex(RuntimeError, "unknown counter mode"):
                checker["bank_require_growth_configuration"](
                    Graph([words["counts"]]), {key}, "bogus")

    def test_growth_counts_mutant_wider_template_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_template_mutant_test")
        self.assertIn("BankTimestampsGrowthBtf", checker,
                      "timestamps template decoder is not implemented")
        body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                          value_bytes=40, value_shape="timestamps")
        with self.assertRaisesRegex(RuntimeError, "exact Counts profile"):
            checker["BankGrowthBtf"](body).map_definition(ref)
        body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                          value_bytes=24, value_shape="counts")
        with self.assertRaisesRegex(RuntimeError, "exact Timestamps profile"):
            checker["BankTimestampsGrowthBtf"](body).map_definition(ref)

    def test_growth_timing_mutant_missing_start_removal_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_bridge_work_test")
        self.assertIn("bank_require_root_work", checker, "bank root-work rule is not implemented")
        expected = {
            ("counts", True): {"p11_bank_enter", "p11_owner_start_aggregate"},
            ("counts", False): {"p11_bank_complete", "p11_owner_start_get",
                                "p11_owner_start_remove"},
            ("timestamps", True): {"p11_bank_enter_timed", "p11_owner_start_aggregate"},
            ("timestamps", False): {"p11_bank_complete_timed", "p11_owner_start_get",
                                     "p11_owner_start_remove"},
            ("latency", True): {"p11_bank_enter_timed", "p11_owner_start_aggregate"},
            ("latency", False): {"p11_bank_complete_timed", "p11_owner_start_get",
                                 "p11_owner_start_remove"},
        }
        for (mode, entry), names in expected.items():
            with self.subTest(mode=mode, entry=entry, names="complete"):
                self.assertIsNone(checker["bank_require_root_work"](
                    names | {"p11_counter_bank_entry"}, mode, entry))
            for missing in sorted(names):
                with self.subTest(mode=mode, entry=entry, missing=missing):
                    with self.assertRaisesRegex(
                            RuntimeError, "^bank proof root loses mandatory START/bridge work$"):
                        checker["bank_require_root_work"](names - {missing}, mode, entry)
        with self.subTest(mode="bogus"):
            with self.assertRaisesRegex(RuntimeError, "unknown counter mode"):
                checker["bank_require_root_work"](set(), "bogus", True)

    def test_growth_mutants_swapped_mode_tokens_are_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_token_swap_test")
        self.assertIn("BankTimestampsGrowthBtf", checker,
                      "timestamps template decoder is not implemented")
        self.assertIn("BankLatencyGrowthBtf", checker, "latency template decoder is not implemented")
        decoders = {"counts": "BankGrowthBtf", "timestamps": "BankTimestampsGrowthBtf",
                    "latency": "BankLatencyGrowthBtf"}
        labels = {"counts": "Counts", "timestamps": "Timestamps", "latency": "Latency"}
        shapes = {"counts": 24, "timestamps": 40, "latency": 296}
        for shape, size in shapes.items():
            body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                              value_bytes=size, value_shape=shape)
            for token, decoder in decoders.items():
                with self.subTest(shape=shape, token=token):
                    if shape == token:
                        definition, _ = checker[decoder](body).map_definition(ref)
                        self.assertEqual(definition["inner_template"]["value_size"], size)
                    else:
                        with self.assertRaisesRegex(
                                RuntimeError, f"exact {labels[token]} profile"):
                            checker[decoder](body).map_definition(ref)
        for token, decoder in decoders.items():
            # Well-formed value struct in the token's own size with the wrong
            # field names, so each twin reaches the bank field check.
            wrong_fields = "counts_wrong_fields" if token == "counts" else "counts"
            with self.subTest(token=token, fields=wrong_fields):
                body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                                  value_bytes=shapes[token],
                                                  value_shape=wrong_fields)
                with self.assertRaisesRegex(
                        RuntimeError, f"bank {labels[token]} value fields/layout differ"):
                    checker[decoder](body).map_definition(ref)
        with self.subTest(token="counts", fields="timestamps_malformed"):
            # Five u64 members packed into a 24-byte struct are malformed BTF;
            # the shared decoder refuses them before the bank field check.
            body, ref = bank_template_fixture(outer_banks=16, inner_cells=512,
                                              value_bytes=24, value_shape="timestamps")
            with self.assertRaisesRegex(RuntimeError, "BTF value member bounds"):
                checker["BankGrowthBtf"](body).map_definition(ref)

    def test_growth_latency_mutant_entry_bucket_is_refused(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_bucket_placement_test")
        self.assertIn("bank_require_bucket_placement", checker,
                      "bucket placement rule is not implemented")
        key = (1, 0)

        def touch(action, span, width=8, pc=0):
            return (key, pc, "COUNTER_BANK_VALUE", action, span, width,
                    0xf1 if action == "write" else None)

        entry_clean = {touch("write", (0, 0)), touch("read", (32, 32))}
        self.assertIsNone(checker["bank_require_bucket_placement"](entry_clean, True))
        with self.subTest(entry="bucket write"):
            with self.assertRaisesRegex(
                    RuntimeError, "^latency bank entry writes histogram buckets$"):
                checker["bank_require_bucket_placement"](
                    entry_clean | {touch("write", (40, 40), pc=1)}, True)
        with self.subTest(entry="bucket range write"):
            with self.assertRaisesRegex(
                    RuntimeError, "^latency bank entry writes histogram buckets$"):
                checker["bank_require_bucket_placement"](
                    entry_clean | {touch("write", (40, 288), pc=1)}, True)
        with self.subTest(entry="bucket read"):
            with self.assertRaisesRegex(
                    RuntimeError, "^latency bank entry reads histogram buckets$"):
                checker["bank_require_bucket_placement"](
                    entry_clean | {touch("read", (40, 288), pc=1)}, True)
        self.assertIsNone(checker["bank_require_bucket_placement"](
            {touch("write", (8, 8)), touch("write", (40, 288), pc=1)}, False))
        with self.subTest(returned="no bucket write"):
            with self.assertRaisesRegex(
                    RuntimeError, "^latency bank return omits its histogram bucket write$"):
                checker["bank_require_bucket_placement"](
                    {touch("write", (8, 8)), touch("write", (32, 32), pc=1)}, False)
        with self.subTest(returned="bucket read without write"):
            with self.assertRaisesRegex(
                    RuntimeError, "^latency bank return omits its histogram bucket write$"):
                checker["bank_require_bucket_placement"]({touch("read", (40, 288))}, False)

        class ClampGraph:
            def __init__(self, instructions):
                self.instructions = {key: dict(enumerate(instructions))}
                self.calls = {}
                self.loops = {key: {}}
                self.bodies = {key: ("bucket_clamp",)}

        bucket_pointer = ("ptr", "COUNTER_BANK_VALUE", 0, 0, checker["ZERO"])
        bucket_maps = {"COUNTER_BANK_VALUE": {"value_size": 296}}
        clamp = [(0xbf, 0x17, 0, 0), (0xb7, 1, 0, 31), (0x2d, 0x21, 1, 0),
                 (0xb7, 2, 0, 31), (0x67, 2, 0, 3), (0x0f, 0x27, 0, 0),
                 (0x07, 7, 0, 40)]

        def clamp_run(tail):
            proof = checker["BankFootprint"](
                ClampGraph(clamp + [tail, (0x95, 0, 0, 0)]), bucket_maps, mode="latency")
            proof.run(key, [bucket_pointer, checker["scalar"](), None, None, None])
            return proof

        for tail, action in (((0x79, 0x70, 0, 0), "read"), ((0xdb, 0x27, 0, 0xf1), "write")):
            with self.subTest(clamped=action):
                touches = [touch for touch in clamp_run(tail).touches
                           if touch[2:4] == ("COUNTER_BANK_VALUE", action)]
                self.assertTrue(touches, "clamped bucket access left no proven touch")
                for _, _, _, _, span, width, _ in touches:
                    self.assertGreaterEqual(span[0], 40)
                    self.assertLessEqual(span[1], 288)
                    self.assertEqual(width, 8)
        for label, at, replacement in (("guard_direction", 2, (0xad, 0x21, 1, 0)),
                                       ("index32", 3, (0xb7, 2, 0, 32)),
                                       ("stride16", 4, (0x67, 2, 0, 4))):
            with self.subTest(damaged=label):
                damaged = list(clamp)
                damaged[at] = replacement
                proof = checker["BankFootprint"](
                    ClampGraph(damaged + [(0xdb, 0x27, 0, 0xf1), (0x95, 0, 0, 0)]),
                    bucket_maps, mode="latency")
                with self.assertRaisesRegex(RuntimeError, "escapes its bounded cell"):
                    proof.run(key, [bucket_pointer, checker["scalar"](), None, None, None])

    def test_growth_timing_start_read_must_precede_removal(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_growth_start_order_test")
        self.assertIn("bank_require_start_read_before_remove", checker,
                      "START read-before-remove rule is not implemented")
        remove_body, bridge_body = (2, 0), (1, 8)
        bodies = {remove_body: ("p11_owner_start_remove",),
                  bridge_body: ("p11_bank_complete_timed",)}
        reached = {(1, 0), remove_body, bridge_body}

        def check(touches, calls):
            return checker["bank_require_start_read_before_remove"](
                touches, calls, bodies, reached)

        def read(pc, function=(1, 0)):
            return (function, pc, "START", "read", (0, 0), 8, None)

        remove_call = {((1, 0), 9): ("function", remove_body)}
        self.assertIsNone(check({read(5)}, remove_call))
        for label, touches in (("after removal", {read(12)}),
                               ("another function", {read(1, bridge_body)}),
                               ("marker only", {((1, 0), 5, "START", "read", (264, 264), 8, None)}),
                               ("write only", {((1, 0), 5, "START", "write", (0, 0), 8, None)}),
                               ("no read", set())):
            with self.subTest(order=label):
                with self.assertRaisesRegex(
                        RuntimeError,
                        "^bank timing return retires START before reading its entry timestamp$"):
                    check(touches, remove_call)
        with self.subTest(order="no removal is vacuous"):
            self.assertIsNone(check(set(), {}))
        with self.subTest(order="getter calls are ignored"):
            get_call = {((1, 0), 9): ("function", (3, 0))}
            bodies_with_get = {**bodies, (3, 0): ("p11_owner_start_get",)}
            self.assertIsNone(checker["bank_require_start_read_before_remove"](
                set(), get_call, bodies_with_get, reached | {(3, 0)}))

    def test_growth_timing_clock_tag_is_required_on_bridge_arguments(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_timing_clock_test")
        self.assertIn("CLOCK_TAG", checker, "clock tag is not implemented")
        self.assertIn("bank_is_clock", checker, "clock predicate is not implemented")
        self.assertIn("bank_require_timed_bridge_clock", checker,
                      "bridge clock rule is not implemented")
        self.assertEqual(checker["CLOCK_TAG"], "clock")
        clock = checker["scalar"](0, (1 << 64) - 1, "clock")
        self.assertTrue(checker["bank_is_clock"](clock))
        for other in (checker["ZERO"], checker["constant"](0), checker["scalar"](),
                      checker["scalar"](0, 100), None, ("ptr", "START", 0, 0, None)):
            with self.subTest(other=other):
                self.assertFalse(checker["bank_is_clock"](other))
        proof = checker["BankFootprint"](None, {}, native_bound=8192,
                                         growth=True, mode="timestamps")
        registers = [None] * 11
        proof.helper(5, registers, {}, (1, 0), 0)
        self.assertTrue(checker["bank_is_clock"](registers[0]),
                        "helper 5 must tag its result as a clock value")
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode, bridge="entry"):
                good = [None] * 11
                good[3] = clock
                self.assertIsNone(checker["bank_require_timed_bridge_clock"](
                    "p11_bank_enter_timed", good, mode))
                for label, value in (("constant zero", checker["constant"](0)),
                                     ("untagged range", checker["scalar"]()),
                                     ("absent", None)):
                    with self.subTest(mutant=label):
                        bad = [None] * 11
                        bad[3] = value
                        with self.assertRaisesRegex(
                                RuntimeError,
                                f"^bank {mode} entry passes a non-clock timestamp "
                                r"to its timed bridge$"):
                            checker["bank_require_timed_bridge_clock"](
                                "p11_bank_enter_timed", bad, mode)
            with self.subTest(mode=mode, bridge="return"):
                good = [None] * 11
                good[5] = clock
                self.assertIsNone(checker["bank_require_timed_bridge_clock"](
                    "p11_bank_complete_timed", good, mode))
                for label, value in (("constant zero", checker["constant"](0)),
                                     ("stale untagged", checker["scalar"](1000, 2000)),
                                     ("absent", None)):
                    with self.subTest(mutant=label):
                        bad = [None] * 11
                        bad[5] = value
                        with self.assertRaisesRegex(
                                RuntimeError,
                                f"^bank {mode} return passes a non-clock timestamp "
                                r"to its timed bridge$"):
                            checker["bank_require_timed_bridge_clock"](
                                "p11_bank_complete_timed", bad, mode)

        def clock_graph(root_name, bridge_name, root_instructions, root_calls):
            root, bridge = (1, 0), (1, 8)

            class Graph:
                def __init__(self):
                    self.instructions = {
                        root: dict(enumerate(root_instructions)),
                        bridge: {0: (0x95, 0, 0, 0)},
                    }
                    self.calls = {(root, pc): call for pc, call in root_calls.items()}
                    self.loops = {root: {}, bridge: {}}
                    self.bodies = {root: (root_name,), bridge: (bridge_name,)}
            return Graph(), root

        maps = {"START": {"value_size": 288}}
        entry_bridge = "p11_bank_enter_timed"
        positive, root = clock_graph(
            "p11_counter_bank_entry", entry_bridge,
            [(0x85, 0, 0, 5), (0xbf, 0x03, 0, 0), (0x85, 0x10, 0, 0),
             (0x95, 0, 0, 0)],
            {0: ("helper", 5), 2: ("function", (1, 8))})
        proof = checker["BankFootprint"](positive, maps, native_bound=8192,
                                         growth=True, mode="timestamps")
        proof.run(root, [("external", "ctx", 0), checker["scalar"](),
                         checker["scalar"](), None, None])
        spilled, root = clock_graph(
            "p11_counter_bank_entry", entry_bridge,
            [(0x85, 0, 0, 5), (0x7b, 0x0a, -8, 0), (0x79, 0xa3, -8, 0),
             (0x85, 0x10, 0, 0), (0x95, 0, 0, 0)],
            {0: ("helper", 5), 3: ("function", (1, 8))})
        proof = checker["BankFootprint"](spilled, maps, native_bound=8192,
                                         growth=True, mode="latency")
        proof.run(root, [("external", "ctx", 0), checker["scalar"](),
                         checker["scalar"](), None, None])
        pid_graph, root = clock_graph(
            "p11_counter_bank_entry", entry_bridge,
            [(0x85, 0, 0, 5), (0xbf, 0x23, 0, 0), (0x85, 0x10, 0, 0),
             (0x95, 0, 0, 0)],
            {0: ("helper", 5), 2: ("function", (1, 8))})
        with self.subTest(mutant="pid_tgid passed as ts"):
            proof = checker["BankFootprint"](pid_graph, maps, native_bound=8192,
                                             growth=True, mode="timestamps")
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timestamps entry passes a non-clock timestamp "
                    "to its timed bridge$"):
                proof.run(root, [("external", "ctx", 0), checker["scalar"](),
                                 checker["scalar"](), None, None])
        return_bridge = "p11_bank_complete_timed"
        zero_graph, root = clock_graph(
            "p11_counter_bank_return", return_bridge,
            [(0x85, 0, 0, 5), (0xb7, 5, 0, 0), (0x85, 0x10, 0, 0),
             (0x95, 0, 0, 0)],
            {0: ("helper", 5), 2: ("function", (1, 8))})
        with self.subTest(mutant="now is constant zero"):
            proof = checker["BankFootprint"](zero_graph, maps, native_bound=8192,
                                             growth=True, mode="timestamps")
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timestamps return passes a non-clock timestamp "
                    "to its timed bridge$"):
                proof.run(root, [("external", "ctx", 0), None, None, None, None])
        stale_graph, root = clock_graph(
            "p11_counter_bank_return", return_bridge,
            [(0x79, 0x15, 0, 0), (0x85, 0x10, 0, 0), (0x95, 0, 0, 0)],
            {1: ("function", (1, 8))})
        with self.subTest(mutant="now is a stale START timestamp"):
            proof = checker["BankFootprint"](stale_graph, maps, native_bound=8192,
                                             growth=True, mode="latency")
            start_pointer = ("ptr", "START", 0, 0, checker["ZERO"])
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank latency return passes a non-clock timestamp "
                    "to its timed bridge$"):
                proof.run(root, [start_pointer, None, None, None, None])

    def test_growth_timing_return_order_requires_cfg_dominance(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_timing_order_test")
        self.assertIn("bank_require_timing_return_order", checker,
                      "CFG timing order rule is not implemented")
        key, remove_body = (1, 0), (2, 0)
        bodies = {remove_body: ("p11_owner_start_remove",)}
        reached = {key, remove_body}

        class Graph:
            def __init__(self, instructions):
                self.instructions = {key: dict(enumerate(instructions))}

        def read(pc):
            return (key, pc, "START", "read", (0, 0), 8, None)

        def write(pc, offset=8):
            return (key, pc, "COUNTER_BANK_VALUE", "write", (offset, offset), 8, 0xf1)

        def check(instructions, touches, calls):
            return checker["bank_require_timing_return_order"](
                Graph(instructions), reached, touches, calls, bodies)

        straight_read = [(0x79, 0x10, 0, 0), (0x85, 0x10, 0, 0),
                         (0x95, 0, 0, 0)]
        self.assertIsNone(check(straight_read, {read(0)}, {(key, 1): ("function", remove_body)}))
        full = [(0x79, 0x10, 0, 0), (0x85, 0x10, 0, 0),
                (0xdb, 0x21, 8, 0xf1), (0x95, 0, 0, 0)]
        self.assertIsNone(check(full, {read(0), write(2)},
                                {(key, 1): ("function", remove_body)}))
        branched = [(0x55, 1, 2, 0), (0x79, 0x10, 0, 0), (0x85, 0x10, 0, 0),
                    (0x85, 0x10, 0, 0), (0x95, 0, 0, 0)]
        with self.subTest(mutant="ts read after removal on one branch only"):
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timing return retires START before reading its entry timestamp$"):
                check(branched, {read(1)},
                      {(key, 2): ("function", remove_body),
                       (key, 3): ("function", remove_body)})
        early_write = [(0x79, 0x10, 0, 0), (0xdb, 0x21, 8, 0xf1),
                       (0x85, 0x10, 0, 0), (0x95, 0, 0, 0)]
        with self.subTest(mutant="accounting write before START removal"):
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timing return accounts before retiring START$"):
                check(early_write, {read(0), write(1)},
                      {(key, 2): ("function", remove_body)})
        unguarded_write = [(0x55, 1, 3, 0), (0x79, 0x10, 0, 0),
                           (0x85, 0x10, 0, 0), (0xdb, 0x21, 8, 0xf1),
                           (0x79, 0x10, 0, 0), (0xdb, 0x21, 8, 0xf1),
                           (0x95, 0, 0, 0)]
        with self.subTest(mutant="accounting write on a branch without removal"):
            with self.assertRaisesRegex(
                    RuntimeError,
                    "^bank timing return accounts before retiring START$"):
                check(unguarded_write, {read(1), read(4), write(3), write(5)},
                      {(key, 2): ("function", remove_body)})
        with self.subTest(order="no removal and no accounting is vacuous"):
            self.assertIsNone(check([(0x95, 0, 0, 0)], set(), {}))

    def test_growth_timing_execution_uses_per_mode_cells_and_clock(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_timing_cells_test")
        self.assertIn("bank_timing_growth_scenarios", checker,
                      "timing scenarios are not implemented")
        for mode, size in (("counts", 24), ("timestamps", 40), ("latency", 296)):
            with self.subTest(mode=mode):
                vm = checker["BankExecution"](None, growth=True, mode=mode)
                self.assertEqual(vm.mode, mode)
                self.assertEqual(vm.cell_bytes, size)
                self.assertEqual(vm.config_word, GROWTH_CONFIG_WORDS[mode])
                address = vm.bank_storage[0]
                region = vm.region(address, size)
                self.assertIsNotNone(region)
                self.assertEqual(region[1], size)
        vm = checker["BankExecution"](None, growth=True, mode="timestamps")
        vm.start(7, ts=1234)
        key = struct.pack("<QII", 9, 7, 0)
        self.assertEqual(vm.read(vm.starts[key], 8), 1234)
        vm = checker["BankExecution"](None, growth=True, mode="latency")
        vm.start(9, ts=(1 << 64) - 1)
        key = struct.pack("<QII", 9, 9, 0)
        self.assertEqual(vm.read(vm.starts[key], 8), (1 << 64) - 1)
        vm = checker["BankExecution"](None, growth=True, mode="counts")
        vm.start(3)
        key = struct.pack("<QII", 9, 3, 0)
        self.assertEqual(vm.read(vm.starts[key], 8), 0)
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode, row="timing"):
                vm = checker["BankExecution"](None, growth=True, mode=mode)
                slot = 511 if mode == "timestamps" else 512
                bank, cell = slot >> 9, slot & 511
                body = struct.pack("<QQQQQ", 1, 1, 0, 1000, 1000)
                if mode == "latency":
                    body += bytes(8 * 32)
                    bucket = bytearray(body)
                    struct.pack_into("<Q", bucket, 40 + 10 * 8, 1)
                    body = bytes(bucket)
                vm.bank_storage[slot] = vm.set(f"bank{bank}", cell, body)
                self.assertEqual(vm.timing_row(slot), (1, 1, 0, 1000, 1000))
                if mode == "latency":
                    self.assertEqual(vm.bucket(slot, 10), 1)
                    self.assertEqual(vm.bucket(slot, 0), 0)

    def test_growth_timing_scenarios_cover_cells_boundaries_and_health(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_timing_cover_test")
        self.assertIn("bank_timing_growth_scenarios", checker,
                      "timing scenarios are not implemented")
        self.assertIn("bank_timing_bucket", checker,
                      "timing bucket helper is not implemented")
        self.assertEqual(checker["bank_timing_bucket"](0), 0)
        self.assertEqual(checker["bank_timing_bucket"](1), 1)
        self.assertEqual(checker["bank_timing_bucket"](2), 2)
        self.assertEqual(checker["bank_timing_bucket"](3), 2)
        self.assertEqual(checker["bank_timing_bucket"](1 << 30), 31)
        self.assertEqual(checker["bank_timing_bucket"]((1 << 64) - 1), 31)

        class Graph:
            instructions = {(1, 0): {0: (0x3d, 0x12, 2, 0), 1: (0xb7, 0, 0, 0),
                                     2: (0x05, 0, 2, 0), 3: (0xbf, 0x20, 0, 0),
                                     4: (0x1f, 0x10, 0, 0), 5: (0x95, 0, 0, 0)}}

        for ts, now, delta in ((1000, 2000, 1000), (2000, 1000, 0), (7, 7, 0)):
            with self.subTest(ts=ts, now=now):
                vm = checker["BankExecution"](Graph(), growth=True, mode="timestamps")
                self.assertEqual(vm.execute((1, 0), [ts, now], 0), delta)
        healthy = checker["BankExecution"](None, growth=True, mode="timestamps")
        healthy.set("COUNTER_HEALTH", 0, (1).to_bytes(8, "little"))
        self.assertEqual(healthy.health(0), 1)
        self.assertEqual(healthy.health(1), 0)


if __name__ == "__main__":
    unittest.main()
