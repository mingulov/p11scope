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


def bank_template_fixture(*, inner_type=6, inner_cells=1, value_bytes=24, values_length=0):
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
    outer = structure([("type", integer(13), 0), ("max_entries", integer(2), 64),
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

    def test_bank_instruction_execution_preserves_existing_sticky_fault_bits(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_vm_test")

        class Graph:
            instructions = {(1, 0): {0: (0xdb, 0x21, 0, 0x40),
                                     1: (0xb7, 0, 0, 0), 2: (0x95, 0, 0, 0)}}

        vm = checker["BankExecution"](Graph())
        at = vm.set("COUNTER_BANK_FAULT", 0, (2).to_bytes(8, "little"))
        self.assertEqual(vm.execute((1, 0), [at, 1], 0), 0)
        self.assertEqual(vm.fault(), 3, "actual OR execution must retain both refusal bits")

    def test_bank_instruction_execution_does_not_reuse_previous_stack_bytes(self):
        checker = runpy.run_path(str(CHECKER), run_name="counter_bank_stack_test")

        class Graph:
            instructions = {(1, 0): {0: (0x79, 0xa0, -8, 0), 1: (0x95, 0, 0, 0)}}

        vm = checker["BankExecution"](Graph())
        for index, byte in enumerate((17).to_bytes(8, "little")):
            vm.memory[0x80000000 - 8 + index] = byte
        with self.assertRaisesRegex(RuntimeError, "unknown/out-of-bounds"):
            vm.execute((1, 0), [], 0)

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
