# SPDX-License-Identifier: GPL-3.0-or-later
"""Compiled ELF fixtures exercise the production map inventory decoder."""
import argparse
import contextlib
import io
import json
import os
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

checker = load_path(ROOT / "scripts/check-bpf-map-defs.py", "map_checker")

class MapDefsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="p11scope-map-defs-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.fixture_object = Path(cls.temp.name) / "mixed.o"

    @property
    def object(self):
        # Prebuilt ia32 mutations do not consume the generic decoder fixture.
        if not self.fixture_object.exists():
            subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-c",
                            str(ROOT / "tests/fixtures/bpf-map-defs/mixed.c"),
                            "-o", str(self.fixture_object)], check=True, capture_output=True)
        return self.fixture_object

    def mutate(self, changes, source=None):
        body = bytearray((source or self.object).read_bytes())
        for offset, fmt, value in changes:
            struct.pack_into(fmt, body, offset, value)
        path = Path(self.temp.name) / "mutated.o"
        path.write_bytes(body)
        return path

    def metadata(self, path=None):
        body = (path or self.object).read_bytes()
        elf = checker.Elf(body)
        btf = checker.Btf(elf.sections[".BTF"][1])
        return body, elf, btf

    def test_mixed_extraction(self):
        maps, programs, _ = checker.inspect(self.object)
        self.assertEqual(set(maps), {"LEGACY", "NATIVE"})
        self.assertEqual(maps["NATIVE"], checker.map_def(29, 4, 8, 0, 1))
        self.assertEqual(maps["LEGACY"], checker.map_def(1, 4, 8, 3))
        self.assertEqual(programs, {"probe"})

    def test_frozen_map_names_survive_kernel_truncation(self):
        """Frozen names must match the kernel-visible names bpftool reports.

        BPF_OBJ_NAME_LEN truncates map names to 15 chars; the stopped
        canary compares those truncated names against FROZEN_INVENTORY.
        Only the exact task-storage, private image-hash and object-array
        names have a canonical remap, so every other frozen
        name must fit, and no two names in a flavor may share a prefix.
        """
        dumper = load_path(ROOT / "scripts/dump-owned-bpf-maps.py", "map_dumper")
        for variant, (maps, _programs) in checker.FROZEN_INVENTORY.items():
            with self.subTest(variant=variant):
                prefixes = {}
                for name in maps:
                    if len(name) > 15:
                        canonical_type = ("task_storage" if maps[name]["type"] == 29 else
                                          "hash" if maps[name]["type"] == 1 else
                                          "array" if maps[name]["type"] == 2 else "other")
                        self.assertEqual(name, dumper.canonical_map_name({"name": name[:15], "type": canonical_type}),
                                      f"{name} exceeds 15 chars without a canonical remap")
                    truncated = name[:15]
                    self.assertNotIn(truncated, prefixes,
                                     f"{name} collides with {prefixes.get(truncated)}")
                    prefixes[truncated] = name


    def test_elf_refusals(self):
        body, elf, _ = self.metadata()
        shoff = struct.unpack_from("<Q", body, 40)[0]
        maps_header = shoff + 64 * elf.indices[".maps"]
        legacy_header = shoff + 64 * elf.indices["maps"]
        native = next(i for i, sym in enumerate(elf.symbols) if sym[0] == "NATIVE")
        legacy = next(i for i, sym in enumerate(elf.symbols) if sym[0] == "LEGACY")
        spare = next(i for i, sym in enumerate(elf.symbols) if sym[0] == "LICENSE")
        symbase = elf.sections[".symtab"][0][4]
        native_name = struct.unpack_from("<I", body, symbase + 24 * native)[0]
        cases = {
            "endian": ([(5, "B", 2)], "endian"),
            "section_bounds": ([(maps_header + 32, "Q", len(body))], "bounds"),
            "duplicate_sections": ([(legacy_header, "I", struct.unpack_from("<I", body, maps_header)[0])], "duplicate"),
            "missing_native_section": ([(maps_header, "I", struct.unpack_from("<I", body, maps_header)[0] + 2)], "missing ELF"),
            "symbol_size": ([(symbase + 24 * native + 16, "Q", 24)], "mismatch"),
            "symbol_offset": ([(symbase + 24 * native + 8, "Q", 8)], "mismatch"),
            "extra_symbol": ([(symbase + 24 * spare + 6, "H", elf.indices[".maps"])], "coverage|mismatch"),
            "duplicate_symbol": ([(symbase + 24 * spare, "I", native_name),
                                  (symbase + 24 * spare + 6, "H", elf.indices[".maps"])], "duplicate"),
            "cross_section_name": ([(symbase + 24 * legacy, "I", native_name)], "duplicate|VAR/symbol mismatch"),
        }
        for name, (changes, reason) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, reason):
                checker.inspect(self.mutate(changes))
        with self.assertRaisesRegex(RuntimeError, "bounds"):
            checker.Elf(body[:63])

    def test_btf_refusals(self):
        _, elf, btf = self.metadata()
        base = elf.sections[".BTF"][0][4]
        section = next(n for n in btf.types[1:] if n[0] == 15 and n[1] == ".maps")
        var_id = section[5][0]
        var = btf.types[var_id]
        definition = btf.types[var[2]]
        pointer_id = definition[5][1]
        pointer = btf.types[pointer_id]
        dp, vp, sp, pp = [base + n[6] for n in (definition, var, section, pointer)]
        other_section = next(n for n in btf.types[1:] if n[0] == 15 and n[1] == "license")
        license_var = next(n for n in btf.types[1:] if n[0] == 14 and n[1] == "LICENSE")
        body = self.object.read_bytes()
        section_name = struct.unpack_from("<I", body, sp)[0]
        var_name = struct.unpack_from("<I", body, vp)[0]
        key_member = next(definition[5][i + 1] for i in range(0, len(definition[5]), 3)
                          if checker.string_at(btf.strings, definition[5][i]) == "key")
        key_int = btf.resolve(btf.resolve(key_member)[2])
        self.assertEqual(key_int[0], 1)
        ip = base + key_int[6]
        cases = {
            "int_reserved_encoding": ([(ip + 12, "I", 0xffffffff)], "INT encoding"),
            "int_reserved_middle_bits": ([(ip + 12, "I", 0x00000120)], "INT encoding"),
            "int_reserved_high_bits": ([(ip + 12, "I", 0x08000020)], "INT encoding"),
            "int_zero_width": ([(ip + 12, "I", 0)], "INT encoding"),
            "int_width_exceeds_size": ([(ip + 12, "I", 33)], "INT encoding"),
            "int_offset_exceeds_size": ([(ip + 12, "I", (31 << 16) | 2)], "INT encoding"),
            "int_zero_size": ([(ip + 8, "I", 0)], "INT encoding|size out of range"),
            "int_oversized": ([(ip + 8, "I", 17)], "INT encoding"),
            "duplicate_datasec": ([(base + other_section[6], "I", section_name)], "duplicate"),
            "duplicate_var_name": ([(base + license_var[6], "I", var_name)], "duplicate"),
            "cross_datasec_var": ([(base + other_section[6] + 12, "I", var_id)], "multiple"),
            "missing_var": ([(sp + 12, "I", var[2])], "VAR"),
            "var_name": ([(vp, "I", 0)], "VAR"),
            "unknown_member": ([(dp + 12, "I", 0)], "unknown"),
            "duplicate_member": ([(dp + 24, "I", definition[5][0])], "duplicate"),
            "bad_reference": ([(dp + 16, "I", len(btf.types))], "reference"),
            "type_cycle": ([(pp + 4, "I", 8 << 24), (pp + 8, "I", pointer_id)], "cycle"),
            "bad_string": ([(dp + 12, "I", len(btf.strings))], "string"),
            "member_offset": ([(dp + 20, "I", 8)], "layout"),
            "struct_size": ([(dp + 8, "I", 8)], "layout"),
            "datasec_size": ([(sp + 8, "I", 1)], "size"),
            "coverage_offset": ([(sp + 16, "I", 8)], "mismatch"),
            "coverage_size": ([(sp + 20, "I", 8)], "mismatch"),
            "length": ([(base + 12, "I", 0xffffffff)], "length"),
            "btf_endian": ([(base, "H", 0x9feb)], "endian"),
            "unknown_kind": ([(dp + 4, "I", 31 << 24)], "unsupported"),
        }
        for name, (changes, reason) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, reason):
                checker.inspect(self.mutate(changes))

    def test_relocation_refusals(self):
        _, elf, btf = self.metadata()
        section = next(n for n in btf.types[1:] if n[0] == 15 and n[1] == ".maps")
        wanted = section[6] + 16
        row, data = elf.sections[".rel.BTF"]
        slot = next(i for i in range(0, len(data), 16) if struct.unpack_from("<Q", data, i)[0] == wanted)
        offset, info = struct.unpack_from("<QQ", data, slot)
        symbase = elf.sections[".symtab"][0][4] + (info >> 32) * 24
        native_var = btf.types[section[5][0]]
        definition = btf.resolve(native_var[2])
        key_member = next(definition[5][i + 1] for i in range(0, len(definition[5]), 3)
                          if checker.string_at(btf.strings, definition[5][i]) == "key")
        key_int = btf.resolve(btf.resolve(key_member)[2])
        license_section = next(n for n in btf.types[1:] if n[0] == 15 and n[1] == "license")
        foreign_slot = next(i for i in range(0, len(data), 16)
                            if struct.unpack_from("<Q", data, i)[0] == license_section[6] + 16)
        foreign_info = struct.unpack_from("<Q", data, foreign_slot + 8)[0]
        cases = {
            "foreign_into_native_type": [(row[4] + foreign_slot, "Q", key_int[6] + 8)],
            "foreign_wrong_kind": [(row[4] + foreign_slot + 8, "Q", (foreign_info & ~0xffffffff) | 3)],
            "foreign_wrong_section": [(row[4] + foreign_slot + 8, "Q", info)],
            "foreign_into_native_member": [(row[4] + foreign_slot, "Q", definition[6] + 16)],
            "wrong_kind": [(row[4] + slot + 8, "Q", (info & ~0xffffffff) | 3)],
            "wrong_symbol": [(row[4] + slot + 8, "Q", 4)],
            "wrong_offset": [(row[4] + slot, "Q", offset + 4)],
            "out_of_bounds": [(row[4] + slot, "Q", 0xfffffff0)],
            "nonzero_base": [(symbase + 8, "Q", 8)],
        }
        for name, changes in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "relocation"):
                checker.inspect(self.mutate(changes))

    def test_exact_helpers(self):
        obj = Path(self.temp.name) / "helpers.o"
        subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-DHELPERS", "-c",
                        str(ROOT / "tests/fixtures/bpf-map-defs/mixed.c"), "-o", str(obj)],
                       check=True, capture_output=True)
        _, programs, symbols = checker.inspect(obj)
        self.assertEqual(programs, {"probe", "task_newtask", "sched_process_exec", "sched_process_exit",
                                   "p11_inst_vma_map", "p11_inst_vma_unmap", "p11_inst_vma_copy",
                                   "p11_image_exec_release", "p11_image_query"})
        self.assertTrue(checker.REQUIRED_GLOBAL_HELPERS <= symbols)
        body, elf, _ = self.metadata(obj)
        symbase = elf.sections[".symtab"][0][4]
        hidden = next(i for i, s in enumerate(elf.symbols) if s[0] == "memset")
        self.assertEqual(elf.symbols[hidden][1:3], (0x12, 2))
        self.assertEqual(elf.symbols[hidden][3], elf.indices[".text"])
        hidden_name = struct.unpack_from("<I", body, symbase + hidden * 24)[0]
        for section in (elf.indices["uprobe"], elf.indices["raw_tp/sched_process_exit"]):
            with self.subTest(hidden_section=section), self.assertRaisesRegex(RuntimeError, "unclassified"):
                checker.inspect(self.mutate([(symbase + hidden * 24 + 6, "H", section)], obj))
        probe = next(i for i, s in enumerate(elf.symbols) if s[0] == "probe")
        with self.assertRaisesRegex(RuntimeError, "unclassified local"):
            checker.inspect(self.mutate([(symbase + probe * 24 + 4, "B", 2)], obj))
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            checker.inspect(self.mutate([(symbase + probe * 24, "I", hidden_name),
                                        (symbase + probe * 24 + 5, "B", 2),
                                        (symbase + probe * 24 + 6, "H", elf.indices[".text"])], obj))
        helper = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_owner_cleanup")
        for section in (0, elf.indices["uprobe"], elf.indices["raw_tp/sched_process_exec"]):
            with self.subTest(section=section), self.assertRaisesRegex(RuntimeError, "helper|unclassified"):
                checker.inspect(self.mutate([(symbase + helper * 24 + 6, "H", section)], obj))
        strings = elf.sections[".strtab"][0][4]
        no = struct.unpack_from("<I", body, symbase + helper * 24)[0]
        with self.assertRaisesRegex(RuntimeError, "missing.*owner|unclassified"):
            checker.inspect(self.mutate([(strings + no, "B", ord("q"))], obj))
        hook = next(i for i, s in enumerate(elf.symbols) if s[0] == "task_newtask")
        with self.assertRaisesRegex(RuntimeError, "unclassified"):
            checker.inspect(self.mutate([(symbase + hook * 24 + 6, "H", elf.indices["uprobe"])], obj))

    def test_exec_predicate_boundary(self):
        obj = Path(self.temp.name) / "exec-linkage.o"
        subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-DHELPERS", "-c",
                        str(ROOT / "tests/fixtures/bpf-map-defs/mixed.c"), "-o", str(obj)],
                       check=True, capture_output=True)
        checker.inspect(obj)
        body, elf, btf = self.metadata(obj)
        helper_index = next(i for i, symbol in enumerate(elf.symbols)
                            if symbol[0] == "p11_exec_dumpability")
        helper = elf.symbols[helper_index]
        symbol_at = elf.sections[".symtab"][0][4] + helper_index * 24
        function = next(node for node in btf.types[1:]
                        if node[:2] == (12, "p11_exec_dumpability"))
        function_at = elf.sections[".BTF"][0][4] + function[6]
        scalar = btf.resolve(btf.types[function[2]][2])
        pointer_proto = next(node[2] for node in btf.types[1:]
                             if node[:2] == (12, "p11_owner_cleanup"))
        raw = elf.sections[".text"][1][helper[4]:helper[4] + helper[5]]
        read_at = [elf.sections[".text"][0][4] + helper[4] + pos
                   for pos in range(0, len(raw), 8)
                   if raw[pos] == 0x85 and struct.unpack_from("<i", raw, pos + 4)[0] == 113]
        self.assertEqual(len(read_at), 1)
        row, relocations = elf.sections[".relraw_tp/sched_process_exec"]
        calls = []
        for pos in range(0, len(relocations), 16):
            address, info = struct.unpack_from("<QQ", relocations, pos)
            if elf.symbols[info >> 32][0] == helper[0]:
                calls.append(elf.sections["raw_tp/sched_process_exec"][0][4] + address)
        self.assertEqual(len(calls), 1)
        self.assertEqual(body[calls[0]:calls[0] + 2], b"\x85\x10")
        cases = {
            "local": ([(symbol_at + 4, "B", 2)], "EXEC.*GLOBAL"),
            "hidden": ([(symbol_at + 5, "B", 2)], "EXEC.*GLOBAL"),
            "wrong_section": ([(symbol_at + 6, "H", elf.indices["uprobe"])], "EXEC.*GLOBAL"),
            "static_btf": ([(function_at + 4, "I", 12 << 24)], "EXEC.*GLOBAL"),
            "pointer_argument": ([(function_at + 8, "I", pointer_proto)], "no-argument scalar"),
            "signed_result": ([(elf.sections[".BTF"][0][4] + scalar[6] + 12,
                                "I", (1 << 24) | 32)], "unsigned u32"),
            "user_read": ([(read_at[0] + 4, "i", 112)], "only current-task and kernel-read"),
            "map_lookup": ([(read_at[0] + 4, "i", 1)], "only current-task and kernel-read"),
            "uncalled": ([(calls[0], "H", 0xb7)], "no reachable call boundary"),
        }
        for name, (changes, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, message):
                checker.validate_exec_helpers(checker.Elf(self.mutate(changes, obj).read_bytes()))

    def test_classic_uprobe_kernel_stack(self):
        """A classic uprobe program with a frame must carry a tail call (the
        verifier then keeps the task's kernel stack instead of a shared
        per-CPU private stack); an opt-out index must never select a slot.
        Each program array keeps one expected attach type (CVE-2025-40123):
        multi-loaded programs opt out through STACK_GUARD, every other
        program through TAIL_CALLS, the multi-loaded pair continues through
        its own PAIR_CALLS into the multi-loaded second, TAIL_CALLS slot 1
        is retired, and nothing else references any of them."""
        source = Path(self.temp.name) / "kernel-stack.c"
        obj = Path(self.temp.name) / "kernel-stack.o"
        source.write_text(
            '#define SEC(n) __attribute__((section(n), used))\n'
            'struct { int (*type)[3]; int (*max_entries)[2]; int (*key_size)[4]; '
            'int (*value_size)[4]; } TAIL_CALLS SEC(".maps");\n'
            'struct { int (*type)[3]; int (*max_entries)[1]; int (*key_size)[4]; '
            'int (*value_size)[4]; } STACK_GUARD SEC(".maps");\n'
            'struct { int (*type)[3]; int (*max_entries)[1]; int (*key_size)[4]; '
            'int (*value_size)[4]; } PAIR_CALLS SEC(".maps");\n'
            'static long (*tail)(void *, void *, unsigned) = (void *)12;\n'
            '#ifndef ARRAY\n#define ARRAY TAIL_CALLS\n#endif\n'
            '#ifndef NAME\n#define NAME big\n#endif\n'
            '#ifdef SUBPROGRAM\n'
            '__attribute__((noinline)) static long guard(void *ctx) '
            '{ return tail(ctx, &ARRAY, 0xffffffffU); }\n#endif\n'
            'SEC("uprobe") int NAME(void *ctx) {\n'
            '#ifdef INDEX\n    tail(ctx, &ARRAY, INDEX);\n#endif\n'
            '#ifdef SUBPROGRAM\n    guard(ctx);\n#endif\n'
            '    volatile char frame[128]; frame[0] = 1; frame[127] = 2;\n'
            '    return frame[0] + frame[127];\n}\n'
            'SEC("uretprobe") int tiny(void *ctx) { return 0; }\n'
            'char LICENSE[] SEC("license") = "GPL";\n')

        def classify(*flags):
            subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", *flags,
                            "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
            return checker.validate_classic_uprobe_kernel_stack(checker.Elf(obj.read_bytes()))

        with self.assertRaisesRegex(RuntimeError, "big: .*private stack"):
            classify()
        self.assertEqual(classify("-DINDEX=0xffffffffU"),
                         {"big": {"opt_out": 1, "continuation": 0, "arrays": ["TAIL_CALLS"]},
                          "tiny": {"opt_out": 0, "continuation": 0, "arrays": []}})
        self.assertEqual(classify("-DINDEX=0")["big"],
                         {"opt_out": 0, "continuation": 1, "arrays": ["TAIL_CALLS"]})
        # TAIL_CALLS slot 1 is retired: the pair continuation moved to PAIR_CALLS.
        with self.assertRaisesRegex(RuntimeError, "not a known slot or the opt-out"):
            classify("-DINDEX=1")
        with self.assertRaisesRegex(RuntimeError, "not a known slot or the opt-out"):
            classify("-DINDEX=7")
        # A multi-loaded program opts out through STACK_GUARD only.
        self.assertEqual(classify("-DINDEX=0xffffffffU", "-DNAME=p11_entry", "-DARRAY=STACK_GUARD")
                         ["p11_entry"], {"opt_out": 1, "continuation": 0, "arrays": ["STACK_GUARD"]})
        with self.assertRaisesRegex(RuntimeError, "p11_entry: references \\['TAIL_CALLS'\\]"):
            classify("-DINDEX=0xffffffffU", "-DNAME=p11_entry")
        with self.assertRaisesRegex(RuntimeError, "big: references \\['STACK_GUARD'\\]"):
            classify("-DINDEX=0xffffffffU", "-DARRAY=STACK_GUARD")
        # STACK_GUARD never has a real slot, not even for a multi-loaded program.
        with self.assertRaisesRegex(RuntimeError, "not a known slot or the opt-out"):
            classify("-DINDEX=0", "-DNAME=p11_entry", "-DARRAY=STACK_GUARD")
        # A shared subprogram would hide which program owns the reference.
        with self.assertRaisesRegex(RuntimeError, "outside a uprobe program body"):
            classify("-DSUBPROGRAM")
        # The multi-loaded pair continues only through its own PAIR_CALLS: a
        # TAIL_CALLS reference would share the array with the plainly loaded
        # programs and fail to load for multi (CVE-2025-40123).
        self.assertEqual(classify("-DINDEX=0", "-DNAME=p11_entry_template_pair",
                                  "-DARRAY=PAIR_CALLS")["p11_entry_template_pair"],
                         {"opt_out": 0, "continuation": 1, "arrays": ["PAIR_CALLS"]})
        with self.assertRaisesRegex(
                RuntimeError, "p11_entry_template_pair: references \\['TAIL_CALLS'\\]"):
            classify("-DINDEX=0xffffffffU", "-DNAME=p11_entry_template_pair")
        with self.assertRaisesRegex(RuntimeError, "not a known slot or the opt-out"):
            classify("-DINDEX=1", "-DNAME=p11_entry_template_pair")
        # The continuation loads with the same attach type as its caller, so
        # it opts out through STACK_GUARD like every multi-loaded program.
        self.assertEqual(classify("-DINDEX=0xffffffffU", "-DNAME=p11_entry_template_second",
                                  "-DARRAY=STACK_GUARD")["p11_entry_template_second"],
                         {"opt_out": 1, "continuation": 0, "arrays": ["STACK_GUARD"]})
        with self.assertRaisesRegex(
                RuntimeError, "p11_entry_template_second: references \\['TAIL_CALLS'\\]"):
            classify("-DINDEX=0xffffffffU", "-DNAME=p11_entry_template_second")

    def test_owner_linkage(self):
        obj = Path(self.temp.name) / "owner-linkage.o"
        source = Path(self.temp.name) / "owner-linkage.c"
        fixture = (ROOT / "tests/fixtures/bpf-map-defs/mixed.c").read_text()
        fixture = fixture.replace(
            'SEC("uprobe") int probe(void *ctx) { return 0; }',
            'static struct { UINT(type, 2); UINT(max_entries, 1); TYPE(key, unsigned); '
            'TYPE(value, unsigned long long); } OWNER_CTL SEC(".maps");\n'
            'SEC("uprobe") int probe(void *ctx) { return 0; }',
        )
        fixture = fixture.replace(
            '#ifdef OWNER_GLOBAL',
            'static void *(*fixture_map_lookup)(void *, const void *) = (void *)1;\n'
            '__attribute__((noinline, used)) unsigned p11_owner_lease(void) {\n'
            '    unsigned key = 0; unsigned long long *ctl = fixture_map_lookup(&OWNER_CTL, &key);\n'
            '    return ctl && *ctl;\n}\n'
            '__attribute__((noinline, used)) unsigned p11_owner_refund(void) {\n'
            '    unsigned key = 0; unsigned long long *ctl = fixture_map_lookup(&OWNER_CTL, &key);\n'
            '    return ctl && *ctl;\n}\n'
            '#ifdef OWNER_EXTRA_GLOBAL\n'
            '__attribute__((noinline, used)) unsigned p11_owner_extra(void) { return 0; }\n'
            '#endif\n'
            '#ifdef OWNER_GLOBAL',
        )
        fixture = fixture.replace(
            'int result = p11_owner_start_get(ctx)',
            'int result = p11_owner_lease() + p11_owner_refund() + p11_owner_start_get(ctx)',
        )
        source.write_text(fixture)
        def compile_fixture(*flags):
            subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-DHELPERS", *flags,
                            "-c", str(source), "-o", str(obj)],
                           check=True, capture_output=True)
        compile_fixture("-DOWNER_GLOBAL", "-DOWNER_HEALTHY")
        with self.assertRaisesRegex(RuntimeError, "owner.*LOCAL"):
            checker.inspect(obj)
        for flags in [(), ("-DOWNER_HEALTHY",)]:
            compile_fixture(*flags)
            checker.inspect(obj)
        body, elf, btf = self.metadata(obj)
        sb = elf.sections[".symtab"][0][4]
        index = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_owner_cleanup")
        at = sb + index * 24
        func_id = next(i for i, n in enumerate(btf.types) if n and n[:2] == (12, "p11_owner_cleanup"))
        func = btf.types[func_id]
        fb = elf.sections[".BTF"][0][4] + func[6]
        other = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_owner_start_get")
        seeded = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_owner_start_begin")
        seeded_at = sb + seeded * 24
        seeded_name = struct.unpack_from("<I", body, seeded_at)[0]
        seeded_func = next(n for n in btf.types[1:] if n[:2] == (12, "p11_owner_start_begin"))
        global_owner_helpers = {"p11_owner_lease", "p11_owner_refund"}
        exported = {
            name: next(i for i, s in enumerate(elf.symbols) if s[0] == name)
            for name in global_owner_helpers
        }
        exported_btf = {
            name: next((i, n) for i, n in enumerate(btf.types) if n and n[:2] == (12, name))
            for name in global_owner_helpers
        }
        pointer_proto_id = next(
            n[2] for n in btf.types[1:]
            if n and n[:2] == (12, "p11_owner_start_get")
        )
        bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
        call_relocations = {}
        for section_row, relocations in elf.sections.values():
            if section_row[1] != 9 or section_row[7] not in {key[0] for key in bodies}:
                continue
            for pos in range(0, len(relocations), 16):
                address, info = struct.unpack_from("<QQ", relocations, pos)
                call_relocations[section_row[7], address] = (
                    info & 0xffffffff, elf.symbols[info >> 32]
                )
        healthy = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_owner_healthy")
        healthy_btf = next(n for n in btf.types[1:] if n[:2] == (12, "p11_owner_healthy"))
        healthy_name = struct.unpack_from("<I", body, sb + healthy * 24)[0]
        name = struct.unpack_from("<I", body, at)[0]
        extbase = elf.sections[".BTF.ext"][0][4]
        ext = elf.sections[".BTF.ext"][1]
        hlen, off, length = struct.unpack_from("<III", ext, 4)
        pos = hlen + off
        stride = struct.unpack_from("<I", ext, pos)[0]
        pos += 4
        records = []
        while pos < hlen + off + length:
            _, count = struct.unpack_from("<II", ext, pos)
            pos += 8
            for _ in range(count):
                if struct.unpack_from("<I", ext, pos + 4)[0] == func_id:
                    records.append(pos)
                pos += stride
        self.assertEqual(len(records), 1)
        relrow, relbody = elf.sections[".rel.BTF.ext"]
        relslot = next(i for i in range(0, len(relbody), 16)
                       if struct.unpack_from("<Q", relbody, i)[0] == records[0])
        relinfo = struct.unpack_from("<Q", relbody, relslot + 8)[0]
        remove_calls = []
        for section in ["raw_tp/sched_process_exec", "raw_tp/sched_process_exit"]:
            row, code = elf.sections[section]
            remove_calls.extend((row[4] + i, "H", 0xb7) for i in range(0, len(code), 8)
                                if code[i:i+2] == b"\x85\x10")
        self.assertEqual(len(remove_calls), 4)
        seeded_calls = []
        seeded_row, seeded_code = elf.sections["tp_btf/task_newtask"]
        for key, symbol in bodies.items():
            if key[0] != elf.indices["tp_btf/task_newtask"]:
                continue
            for address in range(symbol[4], symbol[4] + symbol[5], 8):
                relocation = call_relocations.get((key[0], address))
                if relocation:
                    kind, target = relocation
                    immediate = struct.unpack_from("<i", seeded_code, address + 4)[0]
                    if kind == 10 and (target[3], target[4] + (immediate + 1) * 8) == (elf.symbols[seeded][3], elf.symbols[seeded][4]):
                        seeded_calls.append((seeded_row[4] + address, "H", 0xb7))
        self.assertEqual(len(seeded_calls), 1)
        cases = {
            "seeded_missing": ([(elf.sections[".strtab"][0][4] + seeded_name, "B", 0)], "missing required owner"),
            "seeded_public": ([(seeded_at + 4, "B", 0x12)], "owner.*LOCAL"),
            "seeded_btf_global": ([(elf.sections[".BTF"][0][4] + seeded_func[6] + 4, "I", (12 << 24) | 1)], "owner.*STATIC"),
            "seeded_uncalled": (seeded_calls, "no reachable call boundary"),
            "public": ([(at + 4, "B", 0x12)], "owner.*LOCAL"),
            "hidden_only": ([(at + 5, "B", 2)], "owner.*LOCAL"),
            "public_healthy": ([(sb + healthy * 24 + 4, "B", 0x12)], "owner.*LOCAL"),
            "healthy_btf_global": ([(elf.sections[".BTF"][0][4] + healthy_btf[6] + 4, "I", (12 << 24) | 1)], "owner.*STATIC"),
            "unknown_owner_body": ([(elf.sections[".strtab"][0][4] + healthy_name + len("p11_owner_health"), "B", ord("x"))], "unexpected owner"),
            "undefined": ([(at + 6, "H", 0)], "owner.*LOCAL"),
            "wrong_section": ([(at + 6, "H", elf.indices["uprobe"])], "owner.*LOCAL"),
            "empty_body": ([(at + 16, "Q", 0)], "owner.*body"),
            "duplicate": ([(sb + other * 24, "I", name)], "duplicate.*owner"),
            "btf_global_only": ([(fb + 4, "I", (12 << 24) | 1)], "owner.*STATIC"),
            "btf_extern_only": ([(fb + 4, "I", (12 << 24) | 2)], "owner.*STATIC"),
            "wrong_proto": ([(fb + 8, "I", func_id)], "owner.*FUNC_PROTO"),
            "missing_func": ([(fb, "I", 0)], "owner.*BTF FUNC"),
            "wrong_func_info": ([(extbase + records[0] + 4, "I", func[2])], "function info"),
            "wrong_func_offset": ([(extbase + records[0], "I", 0xfffffff8)], "function info"),
            "wrong_func_relocation": ([(relrow[4] + relslot + 8, "Q", (relinfo & ~0xffffffff) | 10)], "function info relocation"),
            "uncalled_body": (remove_calls, "no reachable call boundary"),
        }
        for public_name, public_index in exported.items():
            public = elf.symbols[public_index]
            public_at = sb + public_index * 24
            func_id, func_node = exported_btf[public_name]
            func_at = elf.sections[".BTF"][0][4] + func_node[6]
            public_info_records = []
            pos = hlen + off + 4
            while pos < hlen + off + length:
                _, count = struct.unpack_from("<II", ext, pos)
                pos += 8
                for _ in range(count):
                    if struct.unpack_from("<I", ext, pos + 4)[0] == func_id:
                        public_info_records.append(pos)
                    pos += stride
            self.assertEqual(len(public_info_records), 1)
            public_relslot = next(
                i for i in range(0, len(relbody), 16)
                if struct.unpack_from("<Q", relbody, i)[0] == public_info_records[0]
            )
            public_relinfo = struct.unpack_from("<Q", relbody, public_relslot + 8)[0]
            target = (public[3], public[4])
            call_changes = []
            for (section, start), caller in bodies.items():
                section_row, section_code = next(
                    row for name, row in elf.sections.items() if elf.indices[name] == section
                )
                code = section_code[start:start + caller[5]]
                for pos in range(0, len(code), 8):
                    if code[pos:pos + 2] != b"\x85\x10":
                        continue
                    imm = struct.unpack_from("<i", code, pos + 4)[0]
                    relocation = call_relocations.get((section, start + pos))
                    if relocation:
                        kind, symbol = relocation
                        destination = (symbol[3], symbol[4] + (imm + 1) * 8) if kind == 10 else None
                    else:
                        destination = (section, start + pos + (imm + 1) * 8)
                    if destination == target:
                        call_changes.append((section_row[4] + start + pos, "H", 0xb7))
            self.assertTrue(call_changes, f"fixture must call {public_name}")

            map_relocations = []
            owner_ctl = next(symbol for symbol in elf.symbols if symbol[0] == "OWNER_CTL")
            for section_row, relocations in elf.sections.values():
                if section_row[1] != 9 or section_row[7] != public[3]:
                    continue
                for pos in range(0, len(relocations), 16):
                    address, info = struct.unpack_from("<QQ", relocations, pos)
                    symbol = elf.symbols[info >> 32]
                    code = elf.sections[".text"][1]
                    imm = struct.unpack_from("<i", code, address + 4)[0]
                    targets_owner_ctl = (
                        (symbol == owner_ctl and imm == 0)
                        or (symbol[1:] == (3, 0, owner_ctl[3], 0, 0) and imm == owner_ctl[4])
                    )
                    if public[4] <= address < public[4] + public[5] and targets_owner_ctl:
                        map_relocations.append((section_row[4] + pos + 8, "Q", info & ~0xffffffff))
            self.assertEqual(len(map_relocations), 1)

            cases.update({
                f"{public_name}_static_elf": ([(public_at + 4, "B", 0x02)], "GLOBAL DEFAULT"),
                f"{public_name}_extern_elf": ([(public_at + 6, "H", 0)], "GLOBAL DEFAULT"),
                f"{public_name}_static_btf": ([(func_at + 4, "I", 12 << 24)], "GLOBAL BTF"),
                f"{public_name}_pointer_proto": ([(func_at + 8, "I", pointer_proto_id)], "no-argument scalar"),
                f"{public_name}_wrong_func_info": ([(extbase + public_info_records[0] + 4, "I", func_node[2])], "function info"),
                f"{public_name}_wrong_func_relocation": ([(relrow[4] + public_relslot + 8, "Q", (public_relinfo & ~0xffffffff) | 10)], "function info relocation"),
                f"{public_name}_empty_body": ([(public_at + 16, "Q", 0)], "body"),
                f"{public_name}_uncalled": (call_changes, "no reachable call boundary"),
                f"{public_name}_missing_owner_ctl": (map_relocations, "OWNER_CTL relocation"),
            })
        for name, (changes, reason) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, reason):
                checker.inspect(self.mutate(changes, obj))
        compile_fixture("-DOWNER_EXTRA_GLOBAL")
        with self.assertRaisesRegex(RuntimeError, "unexpected owner"):
            checker.inspect(obj)

    def test_ia32_reader_linkage_signature_body_and_call(self):
        obj = Path(os.environ["P11SCOPE_IA32_OBJECT"])
        variant = os.environ["P11SCOPE_IA32_VARIANT"]
        self.assertIn(variant, ("default", "diagnostic"))
        allowed = checker.DIAGNOSTIC_GLOBAL_HELPERS if variant == "diagnostic" else frozenset()
        checker.inspect(obj, allowed)
        body, elf, btf = self.metadata(obj)
        symbol_index = next(
            i for i, symbol in enumerate(elf.symbols)
            if symbol[0] == "p11_read_ia32_arg"
        )
        symbol = elf.symbols[symbol_index]
        symbol_at = elf.sections[".symtab"][0][4] + symbol_index * 24
        func_id, func = next(
            (i, node) for i, node in enumerate(btf.types)
            if node and node[:2] == (12, "p11_read_ia32_arg")
        )
        btf_base = elf.sections[".BTF"][0][4]
        func_at = btf_base + func[6]
        proto = btf.types[func[2]]
        proto_at = btf_base + proto[6]
        pointer_type = next(
            i for i, node in enumerate(btf.types)
            if node and node[0] == 2
        )
        u64_type = next(
            i for i, node in enumerate(btf.types)
            if node and node[0] == 1 and node[2] == 8 and node[5][0] >> 24 == 0
        )

        ext = elf.sections[".BTF.ext"][1]
        hlen, off, length = struct.unpack_from("<III", ext, 4)
        pos = hlen + off
        stride = struct.unpack_from("<I", ext, pos)[0]
        pos += 4
        records = []
        while pos < hlen + off + length:
            _, count = struct.unpack_from("<II", ext, pos)
            pos += 8
            for _ in range(count):
                if struct.unpack_from("<I", ext, pos + 4)[0] == func_id:
                    records.append(pos)
                pos += stride
        self.assertEqual(len(records), 1)

        text_row, text = elf.sections[".text"]
        instructions = [
            (pc, *struct.unpack_from("<BBhi", text, pc))
            for pc in range(symbol[4], symbol[4] + symbol[5], 8)
        ]
        read_call = next(pc for pc, op, reg, _, imm in instructions
                         if (op, reg, imm) == (0x85, 0, 112))
        width_move = next(
            pc for pc, op, reg, _, imm in reversed(instructions)
            if pc < read_call and op in (0xb4, 0xb7) and reg & 15 == 2 and imm == 4
        )
        sentinel_high = next(
            pc + 8 for pc, op, _, _, imm in instructions[:-1]
            if op == 0x18 and imm == 0
            and struct.unpack_from("<BBhi", text, pc + 8)[3] == 1
        )
        slot_offset = next(
            pc for pc, op, _, _, imm in instructions
            if op == 0x07 and imm == 4 and pc < read_call
        )
        span_guard, _, _, span_offset, _ = next(
            insn for insn in instructions if insn[1:3] == (0x2d, 0x13)
        )
        payload_loads = [pc for pc, op, _, _, _ in instructions
                         if op == 0x61 and pc > read_call]
        self.assertEqual(len(payload_loads), 1, "one real post-read four-byte payload")
        payload = payload_loads[0]
        saved_copies = [(pc, reg) for pc, op, reg, _, _ in instructions
                        if op == 0xbf and reg & 15 == 0 and reg >> 4 in range(6, 10)]
        rejection_sentinel = max(
            [pc for pc, op, reg, _, imm in instructions if op == 0x18 and reg == 0 and imm == 0]
            + [pc for pc, _ in saved_copies])
        self.assertGreater(span_offset, 0)
        # The alternate real sentinel block is also a valid rejection target.
        checker.inspect(self.mutate([(text_row[4] + span_guard + 2, "h",
                                      (rejection_sentinel - span_guard) // 8 - 1)], obj), allowed)

        bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[5] and s[3]}
        call_relocations = {}
        for section_row, relocations in elf.sections.values():
            if section_row[1] != 9 or section_row[7] not in {key[0] for key in bodies}:
                continue
            for at in range(0, len(relocations), 16):
                address, info = struct.unpack_from("<QQ", relocations, at)
                call_relocations[section_row[7], address] = (
                    info & 0xffffffff,
                    elf.symbols[info >> 32],
                    section_row[4] + at + 8,
                )
        target = (symbol[3], symbol[4])
        real_calls = []
        for (section, start), caller in bodies.items():
            row, code = next(value for name, value in elf.sections.items()
                             if elf.indices[name] == section)
            for at in range(start, start + caller[5], 8):
                op, reg, _, imm = struct.unpack_from("<BBhi", code, at)
                if (op, reg) != (0x85, 0x10):
                    continue
                relocation = call_relocations.get((section, at))
                destination = None
                if relocation and relocation[0] == 10:
                    destination = (
                        relocation[1][3],
                        relocation[1][4] + (imm + 1) * 8,
                    )
                elif not relocation:
                    destination = (section, at + (imm + 1) * 8)
                if destination == target:
                    real_calls.append((row[4] + at, "B", 0xb7))
        self.assertTrue(real_calls, "fixture must retain a real BPF-to-BPF reader call")

        edges = {key: set() for key in bodies}
        call_sites = []
        for (section, start), caller in bodies.items():
            row, code = next(value for name, value in elf.sections.items()
                             if elf.indices[name] == section)
            for at in range(start, start + caller[5], 8):
                op, reg, _, imm = struct.unpack_from("<BBhi", code, at)
                if (op, reg) != (0x85, 0x10):
                    continue
                relocation = call_relocations.get((section, at))
                if relocation and relocation[0] == 10:
                    destination = (
                        relocation[1][3],
                        relocation[1][4] + (imm + 1) * 8,
                    )
                elif relocation:
                    destination = None
                else:
                    destination = (section, at + (imm + 1) * 8)
                if destination in bodies:
                    edges[section, start].add(destination)
                    call_sites.append(((section, start), destination, row[4] + at, relocation))

        reaches_reader = {target}
        changed = True
        while changed:
            changed = False
            for caller, destinations in edges.items():
                if caller not in reaches_reader and destinations & reaches_reader:
                    reaches_reader.add(caller)
                    changed = True
        root_name = "p11_entry_ia32" if variant == "diagnostic" else "p11_entry"
        root_symbol = next(symbol for symbol in elf.symbols if symbol[0] == root_name)
        root = (root_symbol[3], root_symbol[4])
        remove_entry_calls = [
            (file_at, "B", 0xb7)
            for caller, destination, file_at, _ in call_sites
            if caller == root and destination in reaches_reader
        ]
        self.assertTrue(remove_entry_calls, f"{root_name} must reach the ia32 reader")

        discovery_names = {
            "dl_debug_state", "function_list_entry", "function_list_return",
            "interface_entry", "interface_list_entry", "interface_list_return",
            "interface_list_worker", "interface_return",
        }
        discovery_keys = {
            (candidate[3], candidate[4])
            for candidate in elf.symbols if candidate[0] in discovery_names
        }
        discovery_call = next(
            (relocation[2], "Q", (symbol_index << 32) | 10)
            for caller, _, _, relocation in call_sites
            if caller in discovery_keys and relocation and relocation[0] == 10
        )

        cases = {
            "static_elf": ([(symbol_at + 4, "B", 0x02)], "GLOBAL DEFAULT"),
            "absent_elf": ([(symbol_at + 6, "H", 0)], "GLOBAL DEFAULT"),
            "static_btf": ([(func_at + 4, "I", 12 << 24)], "GLOBAL BTF"),
            "inlined_body": ([(symbol_at + 16, "Q", 0)], "body"),
            "pointer_return": ([(proto_at + 8, "I", pointer_type)], "return.*u64"),
            "pointer_argument": ([(proto_at + 16, "I", pointer_type)], "argument.*scalar"),
            "wrong_index_width": ([(proto_at + 24, "I", u64_type)], "index.*u32"),
            "wrong_read_width": ([(text_row[4] + width_move + 4, "i", 8)], "four-byte user read"),
            "wrong_slot_offset": ([(text_row[4] + slot_offset + 4, "i", 8)], "slot/address"),
            "wrong_read_helper": ([(text_row[4] + read_call + 4, "i", 113)], "one user read"),
            "wrong_sentinel": ([(text_row[4] + sentinel_high + 4, "i", 2)], "failure sentinel"),
            "span_rejection_falls_through": ([(text_row[4] + span_guard + 2, "h", 0)], "span"),
            "span_rejection_deleted": ([(text_row[4] + span_guard, "B", 0x05),
                                         (text_row[4] + span_guard + 2, "h", 0)], "span"),
            "span_rejection_returns_payload": ([(text_row[4] + span_guard + 2, "h",
                                                  (payload - span_guard) // 8 - 1)], "span.*sentinel"),
            "uncalled": (real_calls, "entry.*reachable"),
            "unreachable_decoy": (remove_entry_calls, "entry.*reachable"),
            "discovery_only": (remove_entry_calls + [discovery_call], "entry.*reachable"),
        }
        for pc, reg in saved_copies:
            cases[f"saved_sentinel_narrowed_{pc}"] = (
                [(text_row[4] + pc, "B", 0xbc)], "span.*sentinel")
            cases[f"saved_sentinel_unknown_{pc}"] = (
                [(text_row[4] + pc + 1, "B", 0x90 if reg >> 4 != 9 else 0x80)], "span.*sentinel")
            for width in (8, 16, 32):
                cases[f"saved_sentinel_sign_extended_{width}_{pc}"] = (
                    [(text_row[4] + pc + 2, "h", width)], "span.*sentinel")
        for name, (changes, reason) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, reason):
                checker.inspect(self.mutate(changes, obj), allowed)

    def test_root_helpers(self):
        obj = Path(self.temp.name) / "root-helpers.o"
        subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-DHELPERS", "-c",
                        str(ROOT / "tests/fixtures/bpf-map-defs/mixed.c"), "-o", str(obj)],
                       check=True, capture_output=True)
        checker.inspect(obj)
        body, elf, btf = self.metadata(obj)
        sb = elf.sections[".symtab"][0][4]
        ident = next(i for i, s in enumerate(elf.symbols) if s[0] == "p11_root_current_tag")
        at = sb + ident * 24
        name = struct.unpack_from("<I", body, at)[0]
        with self.assertRaisesRegex(RuntimeError, "missing required root"):
            checker.inspect(self.mutate([(elf.sections[".strtab"][0][4] + name, "B", ord("q"))], obj))
        with self.assertRaisesRegex(RuntimeError, "root.*LOCAL"):
            checker.inspect(self.mutate([(at + 4, "B", 0x12)], obj))
        node = next(n for n in btf.types[1:] if n[:2] == (12, "p11_root_current_tag"))
        with self.assertRaisesRegex(RuntimeError, "root.*STATIC"):
            checker.inspect(self.mutate([(elf.sections[".BTF"][0][4] + node[6] + 4, "I", (12 << 24) | 1)], obj))

    def test_duplicate_and_missing_native_entries(self):
        source = Path(self.temp.name) / "two.c"
        source.write_text((ROOT / "tests/fixtures/bpf-map-defs/mixed.c").read_text().replace(
            'NATIVE SEC(".maps");', 'NATIVE SEC(".maps"), NATIVE_TWO SEC(".maps");'))
        obj = Path(self.temp.name) / "two.o"
        subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-c", str(source), "-o", str(obj)],
                       check=True, capture_output=True)
        self.assertEqual(set(checker.inspect(obj)[0]), {"LEGACY", "NATIVE", "NATIVE_TWO"})
        _, elf, btf = self.metadata(obj)
        section = next(n for n in btf.types[1:] if n[0] == 15 and n[1] == ".maps")
        base = elf.sections[".BTF"][0][4] + section[6]
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            checker.inspect(self.mutate([(base + 24, "I", section[5][0])], obj))
        # Preserve the DATASEC payload length while replacing the second entry
        # with an unrelated actual VAR: the extra ELF symbol remains visible.
        foreign = next(i for i, n in enumerate(btf.types) if n and n[0] == 14 and n[1] == "LICENSE")
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            checker.inspect(self.mutate([(base + 24, "I", foreign)], obj))
        relrow, data = elf.sections[".rel.BTF"]
        first = next(i for i in range(0, len(data), 16) if struct.unpack_from("<Q", data, i)[0] == section[6] + 16)
        second = next(i for i in range(0, len(data), 16) if struct.unpack_from("<Q", data, i)[0] == section[6] + 28)
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            checker.inspect(self.mutate([(relrow[4] + second, "Q", struct.unpack_from("<Q", data, first)[0])], obj))

    def test_json_and_legacy_cli(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/check-bpf-map-defs.py"),
                                 "--json", str(self.object)], capture_output=True, text=True, check=True)
        actual = json.loads(result.stdout)
        self.assertEqual(actual["maps"], checker.inspect(self.object)[0])
        self.assertEqual(actual["maps"]["LEGACY"]["max_entries"], 3)
        subprocess.run([sys.executable, "-I", str(ROOT / "scripts/check-bpf-map-defs.py"),
                        str(self.object), "LEGACY=3", "NATIVE=0"], check=True, capture_output=True)
        checker.self_test()

    def test_runner_guards(self):
        self.assertFalse(run_suite(unittest.TestSuite(), io.StringIO()))
        for action in (lambda: self.fail("deliberate failure"), lambda: self.skipTest("deliberate skip")):
            self.assertFalse(run_suite(unittest.TestSuite([unittest.FunctionTestCase(action)]), io.StringIO()))
        for selection in ([], ["MapDefsTests.test_missing"]):
            result = subprocess.run([sys.executable, "-I", __file__, *selection], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


class JournalMarkerInventoryTests(unittest.TestCase):
    """R52 releases omit marker state; retained native marker models stay strict."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="p11scope-marker-freeze-")
        cls.addClassCleanup(cls.temp.cleanup)

    def detailed_symbols(self, missing=frozenset()):
        return (
            {"p11_entry"}
            | checker.REQUIRED_GLOBAL_HELPERS
            | checker.REQUIRED_GLOBAL_EXEC_HELPERS
            | checker.SELECTED_GLOBAL_HELPERS
        ) - set(missing)

    def quiet(self, func, *args):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            try:
                func(*args)
            except RuntimeError as error:
                raise AssertionError(f"unexpected refusal: {error}") from error
        return errors.getvalue()

    def refused(self, func, *args):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(RuntimeError):
            func(*args)
        return errors.getvalue()

    def test_release_detailed_marker_absence_accepts(self):
        maps = {name: value for name, value in checker.SAFE_MAPS.items()
                if name != "JOURNAL_MARKER_CTL"}
        self.quiet(checker.validate_inventory, "default", maps,
                   checker.SAFE_PROGRAMS,
                   self.detailed_symbols(missing=checker.REQUIRED_GLOBAL_MARKER_HELPERS))

    def test_release_detailed_stale_marker_inventory_refused(self):
        maps = dict(checker.SAFE_MAPS)
        maps["JOURNAL_MARKER_CTL"] = checker.map_def(2, 4, 16, 1)
        reason = self.refused(checker.validate_inventory, "default", maps,
                              checker.SAFE_PROGRAMS, self.detailed_symbols())
        self.assertIn("map added: JOURNAL_MARKER_CTL", reason)

    def test_release_half_linked_marker_globals_refused(self):
        for extra in ({"p11_instance_exec_birth"}, {"p11_instance_scope_gap"},
                      set(checker.REQUIRED_GLOBAL_MARKER_HELPERS)):
            with self.subTest(extra=sorted(extra)), \
                    self.assertRaisesRegex(RuntimeError, "forbidden birth marker symbols"):
                checker.validate_inventory("default", checker.SAFE_MAPS,
                                           checker.SAFE_PROGRAMS,
                                           self.detailed_symbols() | extra)

    def test_inventory_with_marker_map_refused(self):
        maps = dict(checker.INVENTORY_MAPS)
        maps["JOURNAL_MARKER_CTL"] = checker.map_def(2, 4, 16, 1)
        reason = self.refused(
            checker.validate_inventory,
            "inventory",
            maps,
            checker.INVENTORY_PROGRAMS,
            set(),
        )
        self.assertIn("map added: JOURNAL_MARKER_CTL", reason)

    def test_inventory_with_marker_symbols_refused(self):
        symbols = (
            set(checker.REQUIRED_GLOBAL_OWNER_HELPERS)
            | set(checker.REQUIRED_GLOBAL_SCALAR_HELPERS)
            | set(checker.REQUIRED_GLOBAL_EXEC_HELPERS)
            | {"JOURNAL_MARKER_CTL", "p11_instance_exec_birth", "p11_instance_scope_gap"}
        )
        with self.assertRaisesRegex(RuntimeError, "forbidden detailed symbols"):
            checker.validate_inventory(
                "inventory",
                checker.INVENTORY_MAPS,
                checker.INVENTORY_PROGRAMS,
                symbols,
            )

    def test_release_stale_marker_wrong_abi_refused(self):
        maps = dict(checker.SAFE_MAPS)
        maps["JOURNAL_MARKER_CTL"] = checker.map_def(2, 4, 8, 1)
        reason = self.refused(
            checker.validate_inventory,
            "default",
            maps,
            checker.SAFE_PROGRAMS,
            self.detailed_symbols(),
        )
        self.assertIn("map added: JOURNAL_MARKER_CTL", reason)

    def test_core_instance_helper_missing_still_refused(self):
        for missing in ("p11_instance_entry", "p11_instance_return", "p11_instance_exec"):
            with self.subTest(missing=missing), \
                    self.assertRaisesRegex(RuntimeError, "missing required \\.text helpers.*" + missing):
                checker.validate_inventory("default", checker.SAFE_MAPS,
                                           checker.SAFE_PROGRAMS,
                                           self.detailed_symbols(missing={missing}))

    def marker_fixture(self, name):
        source = Path(self.temp.name) / f"{name}.c"
        obj = Path(self.temp.name) / f"{name}.o"
        source.write_text(
            "#define SEC(n) __attribute__((section(n), used))\n"
            "#define LOOKUP(map, key) ((void *(*)(void *, void *))1)((map), (key))\n"
            "#define STORAGE(map, task, value, flags) \\\n"
            "    ((void *(*)(void *, void *, void *, unsigned long long))156)( \\\n"
            "        (map), (task), (value), (flags))\n"
            "#define CURRENT() ((void *(*)(void))158)()\n"
            "#define BODY() \\\n"
            "    unsigned key = 0; void *map = 0; \\\n"
            "    void *found = LOOKUP(map, &key); \\\n"
            "    void *task = CURRENT(); \\\n"
            "    void *row = STORAGE(map, task, 0, 0); \\\n"
            "    return (found != 0) + (task != 0) + (row != 0);\n"
            "__attribute__((noinline, used)) unsigned p11_instance_exec_birth(void) { BODY() }\n"
            "__attribute__((noinline, used)) unsigned p11_instance_scope_gap(void) { BODY() }\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )
        subprocess.run(
            ["clang-18", "-target", "bpfel", "-O2", "-c", str(source), "-o", str(obj)],
            check=True,
            capture_output=True,
        )
        return obj

    def test_marker_helper_boundary(self):
        """Healthy twin: two globals using only {1, 156, 158} validate."""
        obj = self.marker_fixture("marker-boundary")
        checker.validate_marker_helpers(checker.Elf(obj.read_bytes()))

    def test_marker_helper_boundary_refuses_user_read(self):
        """Named mutant: a user-memory read (112) in one body is refused."""
        obj = self.marker_fixture("marker-mutant")
        body = bytearray(obj.read_bytes())
        elf = checker.Elf(bytes(body))
        victim = next(
            symbol for symbol in elf.symbols if symbol[0] == "p11_instance_scope_gap"
        )
        text_at = elf.sections[".text"][0][4] + victim[4]
        patched = 0
        for pos in range(0, victim[5], 8):
            op, reg, _, imm = struct.unpack_from("<BBhi", body, text_at + pos)
            if op == 0x85 and reg >> 4 == 0 and imm == 156:
                struct.pack_into("<i", body, text_at + pos + 4, 112)
                patched += 1
                break
        self.assertEqual(patched, 1, "the fixture must carry a storage call to mutate")
        with self.assertRaisesRegex(RuntimeError, "only map lookup"):
            checker.validate_marker_helpers(checker.Elf(bytes(body)))

    def test_marker_single_global_refused(self):
        """One global without its sibling is refused."""
        source = Path(self.temp.name) / "marker-single.c"
        obj = Path(self.temp.name) / "marker-single.o"
        source.write_text(
            "#define SEC(n) __attribute__((section(n), used))\n"
            "__attribute__((noinline, used)) unsigned p11_instance_exec_birth(void) {\n"
            "    unsigned key = 0; void *map = 0;\n"
            "    void *found = ((void *(*)(void *, void *))1)(map, &key);\n"
            "    void *task = ((void *(*)(void))158)();\n"
            "    void *row = ((void *(*)(void *, void *, void *, "
            "unsigned long long))156)(map, task, 0, 0);\n"
            "    return (found != 0) + (task != 0) + (row != 0);\n}\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )
        subprocess.run(
            ["clang-18", "-target", "bpfel", "-O2", "-c", str(source), "-o", str(obj)],
            check=True,
            capture_output=True,
        )
        with self.assertRaisesRegex(RuntimeError, "complete unique set"):
            checker.validate_marker_helpers(checker.Elf(obj.read_bytes()))


class JournalMarkerCallSiteTests(unittest.TestCase):
    """H8-D birth marker call sites: every defined Detailed root that can
    birth or gap must call its marker global. Core roots (entry, return,
    exec, exit) must exist; unsafe-only roots (ia32 entry, template
    continuation) must call when defined."""

    ROOTS = (
        ("p11_entry", "uprobe", "p11_instance_scope_gap"),
        ("p11_entry_ia32", "uprobe", "p11_instance_scope_gap"),
        ("p11_return", "uretprobe", "p11_instance_scope_gap"),
        ("p11_entry_template", "uprobe", "p11_instance_scope_gap"),
        ("p11_entry_template_types", "uprobe", "p11_instance_scope_gap"),
        ("p11_entry_template_pair", "uprobe", "p11_instance_scope_gap"),
        ("p11_entry_template_second", "uprobe", "p11_instance_scope_gap"),
        ("sched_process_exec", "raw_tp/sched_process_exec", "p11_instance_exec_birth"),
        ("sched_process_exit", "raw_tp/sched_process_exit", "p11_instance_scope_gap"),
    )

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="p11scope-marker-calls-")
        cls.addClassCleanup(cls.temp.cleanup)

    def calls_fixture(self, name, wired, roots=None, markers=True):
        """Compile roots that call (or drop) their marker global.

        wired: root names that call; roots: names to emit (default all
        nine); markers: emit the two marker globals. Each body is
        textually distinct so the optimizer cannot merge two roots.
        """
        roots = [root for root in self.ROOTS if roots is None or root[0] in roots]
        lines = [
            '#define SEC(n) __attribute__((section(n), used))\n',
            '#define LOOKUP(map, key) ((void *(*)(void *, void *))1)((map), (key))\n',
            '#define STORAGE(map, task, value, flags) \\\n',
            '    ((void *(*)(void *, void *, void *, unsigned long long))156)( \\\n',
            '        (map), (task), (value), (flags))\n',
            '#define CURRENT() ((void *(*)(void))158)()\n',
            '#define BODY() \\\n',
            '    unsigned key = 0; void *map = 0; \\\n',
            '    void *found = LOOKUP(map, &key); \\\n',
            '    void *task = CURRENT(); \\\n',
            '    void *row = STORAGE(map, task, 0, 0); \\\n',
            '    return (found != 0) + (task != 0) + (row != 0);\n',
        ]
        if markers:
            lines += [
                '__attribute__((noinline, used)) unsigned p11_instance_exec_birth(void)'
                ' { BODY() }\n',
                '__attribute__((noinline, used)) unsigned p11_instance_scope_gap(void)'
                ' { BODY() }\n',
            ]
        else:
            lines += [
                'unsigned p11_instance_exec_birth(void);\n',
                'unsigned p11_instance_scope_gap(void);\n',
            ]
        shapes = {
            "p11_entry": "return (int)MARKER();",
            "p11_entry_ia32": "{ unsigned r = MARKER(); return (int)(r & 255); }",
            "p11_return": "{ unsigned r = MARKER(); return (int)(r | 256); }",
            "p11_entry_template": "{ unsigned r = MARKER(); return (int)(r + 2048); }",
            "p11_entry_template_types": "{ unsigned r = MARKER(); return (int)(r + 4096); }",
            "p11_entry_template_pair": "{ unsigned r = MARKER(); return (int)(r + 6144); }",
            "p11_entry_template_second": "{ unsigned r = MARKER(); return (int)(r ^ 512); }",
            "sched_process_exec": "return (int)MARKER();",
            "sched_process_exit": "{ unsigned r = MARKER(); return (int)(r & 1023); }",
        }
        for index, (root, section, marker) in enumerate(roots):
            if root in wired:
                body = shapes[root].replace("MARKER()", f"{marker}()")
            else:
                body = f"{{ (void)ctx; return {100 + index}; }}"
            lines.append(f'SEC("{section}") int {root}(void *ctx) {{ (void)ctx; {body} }}\n')
        lines.append('char LICENSE[] SEC("license") = "GPL";\n')
        source = Path(self.temp.name) / f"{name}.c"
        obj = Path(self.temp.name) / f"{name}.o"
        source.write_text("".join(lines))
        subprocess.run(
            ["clang-18", "-target", "bpfel", "-O2", "-c", str(source), "-o", str(obj)],
            check=True,
            capture_output=True,
        )
        return obj

    def check_calls(self, name, wired, roots=None, markers=True):
        obj = self.calls_fixture(name, wired, roots, markers)
        return checker.validate_marker_call_sites(checker.Elf(obj.read_bytes()))

    def test_marker_calls_healthy_diagnostic(self):
        """Healthy twin: all nine roots wired validates."""
        self.check_calls(
            "marker-calls-healthy",
            {root for root, _, _ in self.ROOTS},
        )

    def test_marker_calls_healthy_default(self):
        """Healthy twin: the four core roots wired validates when the
        unsafe-only roots are absent."""
        self.check_calls(
            "marker-calls-default",
            {"p11_entry", "p11_return", "sched_process_exec", "sched_process_exit"},
            roots={"p11_entry", "p11_return", "sched_process_exec", "sched_process_exit"},
        )

    def test_marker_calls_without_markers_skipped(self):
        """Healthy twin: an object without the globals skips the check."""
        self.check_calls("marker-calls-skip", set(), markers=False)

    def test_marker_call_dropped_from_entry_refused(self):
        """Named mutant: entry without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-entry",
                {"p11_entry_ia32", "p11_return", "p11_entry_template",
                 "p11_entry_template_types", "p11_entry_template_pair",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_ia32_entry_refused(self):
        """Named mutant: the ia32 entry without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry_ia32 must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-ia32",
                {"p11_entry", "p11_return", "p11_entry_template",
                 "p11_entry_template_types", "p11_entry_template_pair",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_return_refused(self):
        """Named mutant: return without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_return must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-return",
                {"p11_entry", "p11_entry_ia32", "p11_entry_template",
                 "p11_entry_template_types", "p11_entry_template_pair",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_template_continuation_refused(self):
        """Named mutant: the template continuation without its gap call
        is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry_template_second must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-second",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template", "p11_entry_template_types",
                 "p11_entry_template_pair", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_exec_refused(self):
        """Named mutant: exec without its birth call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed sched_process_exec must call p11_instance_exec_birth"
        ):
            self.check_calls(
                "marker-calls-drop-exec",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template", "p11_entry_template_types",
                 "p11_entry_template_pair", "p11_entry_template_second",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_exit_refused(self):
        """Named mutant: exit without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed sched_process_exit must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-exit",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template", "p11_entry_template_types",
                 "p11_entry_template_pair", "p11_entry_template_second",
                 "sched_process_exec"},
            )

    def test_marker_call_dropped_from_template_refused(self):
        """Named mutant: the template entry without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry_template must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-template",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template_types", "p11_entry_template_pair",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_template_types_refused(self):
        """Named mutant: the template types entry without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry_template_types must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-template-types",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template", "p11_entry_template_pair",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )

    def test_marker_call_dropped_from_template_pair_refused(self):
        """Named mutant: the template pair entry without its gap call is refused."""
        with self.assertRaisesRegex(
            RuntimeError, r"Detailed p11_entry_template_pair must call p11_instance_scope_gap"
        ):
            self.check_calls(
                "marker-calls-drop-template-pair",
                {"p11_entry", "p11_entry_ia32", "p11_return",
                 "p11_entry_template", "p11_entry_template_types",
                 "p11_entry_template_second", "sched_process_exec",
                 "sched_process_exit"},
            )


class Ia32SpanProofTests(unittest.TestCase):
    def test_saved_sentinel_requires_proven_full_width_register_flow(self):
        def reader(saved, suffix, high=1):
            return [(0x18, saved, 0, 0), (0, 0, 0, high), (0x2d, 0x13, 2, 0),
                    (0x85, 0, 0, 112), (0x95, 0, 0, 0), *suffix]

        copy = (0xbf, 0x60, 0, 0)
        exit = (0x95, 0, 0, 0)
        checker.validate_ia32_raw_span(reader(6, [copy, exit]), 3)
        # A helper preserves r6, but must destroy an otherwise identical r5 fact.
        checker.validate_ia32_raw_span(reader(6, [(0x85, 0, 0, 5), copy, exit]), 3)
        mutants = {
            "wrong_value": reader(6, [copy, exit], high=2),
            "narrowed_copy": reader(6, [(0xbc, 0x60, 0, 0), exit]),
            "unknown_write": reader(6, [(0x61, 0xa6, -4, 0), copy, exit]),
            "atomic_fetch_write": reader(6, [(0xdb, 0x6a, -8, 1), copy, exit]),
            "pseudo_address": reader(0x16, [copy, exit]),
            "caller_saved_clobber": reader(5, [(0x85, 0, 0, 5), (0xbf, 0x50, 0, 0), exit]),
            "unsafe_merge": reader(6, [(0x15, 7, 1, 0), (0xb7, 6, 0, 0), copy, exit]),
        }
        mutants.update({f"sign_extended_copy_{width}": reader(6, [(0xbf, 0x60, width, 0), exit])
                        for width in (8, 16, 32)})
        for name, instructions in mutants.items():
            with self.subTest(mutation=name), self.assertRaisesRegex(RuntimeError, "span.*sentinel"):
                checker.validate_ia32_raw_span(instructions, 3)


class ObjectCaptureGlobalsTests(unittest.TestCase):
    """Prebuilt-only checks: selecting this class never compiles a fixture."""

    def setUp(self):
        self.object = Path(os.environ["P11SCOPE_OBJECT_CAPTURE_OBJECT"])
        self.assertTrue(self.object.is_file(), "a real compiled object is required")
        self.temp = tempfile.TemporaryDirectory(prefix="p11scope-object-globals-")
        self.addCleanup(self.temp.cleanup)

    def mutated(self, changes):
        body = bytearray(self.object.read_bytes())
        for offset, fmt, value in changes:
            struct.pack_into(fmt, body, offset, value)
        return checker.Elf(bytes(body))

    def sixth_argument(self, elf, btf, function, proto):
        """Append a valid six-argument BTF prototype without corrupting types."""
        body = bytearray(self.object.read_bytes())
        raw = bytearray(elf.sections[".BTF"][1])
        hlen, _, tlen, soff, _ = struct.unpack_from("<IIIII", raw, 4)
        record = struct.pack("<III", 0, (13 << 24) | 6, proto[2])
        record += struct.pack("<12I", *proto[5], 0, proto[5][1])
        struct.pack_into("<I", raw, function[6] + 8, len(btf.types))
        raw = raw[:hlen + tlen] + record + raw[hlen + tlen:]
        struct.pack_into("<II", raw, 12, tlen + len(record), soff + len(record))
        body += b"\0" * (-len(body) % 8)
        at = len(body)
        body += raw
        section_headers = struct.unpack_from("<Q", body, 40)[0]
        section = section_headers + 64 * elf.indices[".BTF"]
        struct.pack_into("<QQ", body, section + 24, at, len(raw))
        return checker.Elf(bytes(body))

    def test_object_capture_globals_linkage_signature_and_calls(self):
        elf = checker.Elf(self.object.read_bytes())
        expected = {"p11_stable_cell", "p11_alias_scan", "p11_alias_capacity", "p11_request_cell"}
        self.assertTrue(expected <= {symbol[0] for symbol in elf.symbols},
                        "the actual compiled object must retain all four scalar globals")
        checker.validate_object_capture_globals(elf)
        full = os.environ.get("P11SCOPE_OBJECT_CAPTURE_FULL", "1")
        self.assertIn(full, ("0", "1"))
        checker.validate_object_capture_reachability(elf, full=full == "1")
        with self.assertRaisesRegex(RuntimeError, "Inventory"):
            checker.validate_object_capture_globals(elf, inventory=True)

        btf = checker.Btf(elf.sections[".BTF"][1])
        btf_base = elf.sections[".BTF"][0][4]
        pointer = next(i for i, node in enumerate(btf.types) if node and node[0] == 2)
        u32_type = next(i for i, node in enumerate(btf.types)
                       if node and node[0] == 1 and node[2] == 4 and node[5] == (32,))
        for name in sorted(expected):
            symbol_index, symbol = next((i, symbol) for i, symbol in enumerate(elf.symbols)
                                        if symbol[0] == name)
            symbol_at = elf.sections[".symtab"][0][4] + 24 * symbol_index
            function = next(node for node in btf.types if node and node[:2] == (12, name))
            function_at = btf_base + function[6]
            proto = btf.types[function[2]]
            proto_at = btf_base + proto[6]
            cases = {
                "missing_name": ([(symbol_at, "I", 0)], "complete.*globals"),
                "local": ([(symbol_at + 4, "B", 0x02)], "GLOBAL DEFAULT"),
                "hidden": ([(symbol_at + 5, "B", 2)], "GLOBAL DEFAULT"),
                "wrong_section": ([(symbol_at + 6, "H", elf.indices["uprobe"])],
                                  "GLOBAL DEFAULT"),
                "empty_body": ([(symbol_at + 16, "Q", 0)], "body"),
                "static_btf": ([(function_at + 4, "I", 12 << 24)], "GLOBAL BTF"),
                "pointer_return": ([(proto_at + 8, "I", pointer)], "return.*u64"),
                "narrow_return": ([(proto_at + 8, "I", u32_type)], "return.*u64"),
            }
            for argument in range(5):
                cases[f"pointer_argument_{argument}"] = (
                    [(proto_at + 16 + argument * 8, "I", pointer)], "argument.*u64")
                cases[f"narrow_argument_{argument}"] = (
                    [(proto_at + 16 + argument * 8, "I", u32_type)], "argument.*u64")
            for mutation, (changes, reason) in cases.items():
                with self.subTest(helper=name, mutation=mutation), self.assertRaisesRegex(RuntimeError, reason):
                    checker.validate_object_capture_globals(self.mutated(changes))
            with self.subTest(helper=name, mutation="sixth_argument"):
                mutant = self.sixth_argument(elf, btf, function, proto)
                parsed = checker.Btf(mutant.sections[".BTF"][1])
                changed = next(node for node in parsed.types if node and node[:2] == (12, name))
                self.assertEqual(parsed.types[changed[2]][3], 6)
                with self.assertRaisesRegex(RuntimeError, "exactly five"):
                    checker.validate_object_capture_globals(mutant)

        bodies, edges, calls = checker.bpf_call_graph(elf)
        roots = {symbol[0]: key for key, symbol in bodies.items()
                 if symbol[0] == "p11_return" or symbol[0].startswith("p11_entry")}
        if full == "1":
            for name in sorted(expected):
                target = next(key for key, symbol in bodies.items() if symbol[0] == name)
                reaches = {target}
                while True:
                    expanded = reaches | {caller for caller, destinations in edges.items()
                                          if destinations & reaches}
                    if expanded == reaches:
                        break
                    reaches = expanded
                for root_name, root in roots.items():
                    if root_name == "p11_entry_template_second":
                        continue
                    required = ({"p11_stable_cell", "p11_alias_capacity"}
                                if root_name == "p11_return"
                                else {"p11_stable_cell", "p11_alias_scan", "p11_request_cell"})
                    if name not in required:
                        continue
                    changes = [change for caller, destination, at in calls
                               if caller == root and destination in reaches
                               for change in [(at, "B", 0xb7), (at + 1, "B", 0)]]
                    self.assertTrue(changes, f"actual {root_name} must reach {name}")
                    with self.subTest(root=root_name, helper=name, mutation="unreachable_global"), \
                            self.assertRaisesRegex(RuntimeError, "reachable"):
                        checker.validate_object_capture_reachability(self.mutated(changes), full=True)
        else:
            with self.assertRaisesRegex(RuntimeError, "reachable"):
                checker.validate_object_capture_reachability(elf, full=True)

        if full == "1":
            # Return keeps its ordinary/object capture paths intact, but may
            # never gain the entry-only request reader through another call.
            target = next(key for key, symbol in bodies.items() if symbol[0] == "p11_request_cell")
            caller, destination, call_at = next(call for call in calls
                if call[0] == roots["p11_return"] and bodies[call[1]][0] == "p11_owner_start_get")
            immediate = struct.unpack_from("<i", self.object.read_bytes(), call_at + 4)[0]
            mutant = self.mutated([(call_at + 4, "i", immediate + (target[1] - destination[1]) // 8)])
            _, mutated_edges, _ = checker.bpf_call_graph(mutant)
            self.assertIn(target, mutated_edges[caller], "return mutant must reach request cell")
            with self.subTest(root="p11_return", mutation="entry_reader_on_return"), \
                    self.assertRaisesRegex(RuntimeError, "reachable"):
                checker.validate_object_capture_reachability(mutant, full=True)

        continuation = roots.get("p11_entry_template_second")
        if continuation is not None:
            symbol_index, symbol = next((i, symbol) for i, symbol in enumerate(elf.symbols)
                                        if symbol[0] == "p11_entry_template_second")
            symbol_at = elf.sections[".symtab"][0][4] + 24 * symbol_index
            for mutation, change in {
                "local_continuation": (symbol_at + 4, "B", 0x02),
                "hidden_continuation": (symbol_at + 5, "B", 2),
            }.items():
                with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "GLOBAL DEFAULT.*root"):
                    checker.validate_object_capture_reachability(self.mutated([change]), full=full == "1")
            if full == "1":
                name_offset = struct.unpack_from("<I", self.object.read_bytes(), symbol_at)[0]
                strings_index = elf.sections[".symtab"][0][6]
                strings = next(row for label, (row, _) in elf.sections.items()
                               if elf.indices[label] == strings_index)
                # A capture-free root with a merely similar name is not the
                # second-template continuation and must not gain its role.
                renamed = self.mutated([(strings[4] + name_offset + len(symbol[0]) - 1, "B", ord("x"))])
                with self.subTest(mutation="similar_continuation_name"), self.assertRaisesRegex(RuntimeError, "reachable"):
                    checker.validate_object_capture_reachability(renamed, full=True)
            # The second-template tail continuation consumes an existing START;
            # its parent has already run the object-attribute capture path.
            # Redirect a real pseudo-call, retaining its relocation, to prove
            # the exact continuation must still reject capture-global reach.
            target = next(key for key, symbol in bodies.items() if symbol[0] == "p11_stable_cell")
            _, destination, call_at = next(call for call in calls
                                           if call[0] == continuation and call[1][0] == target[0])
            immediate = struct.unpack_from("<i", self.object.read_bytes(), call_at + 4)[0]
            mutant = self.mutated([(call_at + 4, "i", immediate + (target[1] - destination[1]) // 8)])
            _, mutated_edges, _ = checker.bpf_call_graph(mutant)
            self.assertIn(target, mutated_edges[continuation], "mutation must reach the actual scalar global")
            with self.subTest(root="p11_entry_template_second", mutation="unexpected_capture_global"), \
                    self.assertRaisesRegex(RuntimeError, "reachable"):
                checker.validate_object_capture_reachability(mutant, full=full == "1")

        text_row, text = elf.sections[".text"]
        for name in sorted(expected - {"p11_alias_capacity"}):
            symbol = next(symbol for symbol in elf.symbols if symbol[0] == name)
            read_at = next(at for at in range(symbol[4], symbol[4] + symbol[5], 8)
                           if struct.unpack_from("<BBhi", text, at) == (0x85, 0, 0, 112))
            with self.subTest(helper=name, mutation="global_reserves_ring"), \
                    self.assertRaisesRegex(RuntimeError, "non-read helper"):
                checker.validate_object_capture_reachability(
                    self.mutated([(text_row[4] + read_at + 4, "i", 131)]), full=full == "1")

        map_at = None
        for row, relocations in elf.sections.values():
            if row[1] != 9 or row[7] != elf.indices[".text"]:
                continue
            map_at = next((at for at in range(0, len(relocations), 16)
                           if struct.unpack_from("<Q", relocations, at + 8)[0] & 0xffffffff == 1), None)
            if map_at is not None:
                break
        self.assertIsNotNone(map_at, "real object must provide a map relocation mutation")
        for name in sorted(expected):
            symbol = next(symbol for symbol in elf.symbols if symbol[0] == name)
            with self.subTest(helper=name, mutation="global_references_map"), \
                    self.assertRaisesRegex(RuntimeError, "map/state"):
                checker.validate_object_capture_reachability(
                    self.mutated([(row[4] + map_at, "Q", symbol[4])]), full=full == "1")


def run_suite(suite, stream=None):
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return result.testsRun > 0 and result.wasSuccessful() and not result.skipped


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("cases", nargs="*")
    args = parser.parse_args()
    if args.all == bool(args.cases):
        parser.error("select --all or one or more exact test cases")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(MapDefsTests) if args.all else loader.loadTestsFromNames(args.cases, sys.modules[__name__])
    sys.exit(0 if run_suite(suite) else 1)
