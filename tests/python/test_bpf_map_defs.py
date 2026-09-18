"""Compiled ELF fixtures exercise the production map inventory decoder."""
import argparse
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
        cls.object = Path(cls.temp.name) / "mixed.o"
        subprocess.run(["clang-18", "-target", "bpfel", "-g", "-O2", "-c",
                        str(ROOT / "tests/fixtures/bpf-map-defs/mixed.c"),
                        "-o", str(cls.object)], check=True, capture_output=True)

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
        self.assertEqual(programs, {"probe", "task_newtask", "sched_process_exec", "sched_process_exit"})
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
            '__attribute__((noinline, used)) unsigned p11_owner_reserve(void) {\n'
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
            'int result = p11_owner_reserve() + p11_owner_refund() + p11_owner_start_get(ctx)',
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
        global_owner_helpers = {"p11_owner_reserve", "p11_owner_refund"}
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
        self.assertEqual(len(remove_calls), 3)
        cases = {
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

        ext_base = elf.sections[".BTF.ext"][0][4]
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
        payload = next(pc for pc, op, reg, _, _ in instructions
                       if op == 0x61 and reg & 15 == 0 and pc > read_call)
        rejection_sentinel = max(pc for pc, op, reg, _, imm in instructions
                                 if op == 0x18 and reg == 0 and imm == 0)
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
