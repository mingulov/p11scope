# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory object ABI and negative controls over the actual compiled ELF."""
import contextlib
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

checker = load_path(ROOT / "scripts/check-bpf-map-defs.py", "inventory_map_checker")

# The approved ABI, independent of the checker's manifest construction.
MAPS = {name: checker.map_def(*shape) for name, shape in {
    "CONFIG": (2, 4, 8, 2, 128), "PID_FILTER": (1, 4, 8, 1024, 128),
    "CGROUP_FILTER": (8, 4, 4, 1), "TAIL_CALLS": (3, 4, 4, 2),
    "STACK_GUARD": (3, 4, 4, 1),
    "EVIDENCE": (6, 4, 8, 9), "COUNTERS": (6, 4, 8, 5),
    "DISCOVERY": (27, 0, 0, 2097152), "DISCOVERY_STATE": (1, 24, 24, 64),
    "THREAD_OWNER": (29, 4, 544, 0, 1), "OWNER_CTL": (2, 4, 56, 1),
    "USAGE": (2, 4, 8, 1), "USAGE_CONFIG": (2, 4, 8, 1, 128),
    "USAGE_EVIDENCE": (6, 4, 8, 3),
}.items()}
PROGRAMS = {"p11_usage_entry_lp64", "p11_usage_entry_ia32", "dl_debug_state",
            "function_list_entry", "function_list_return", "interface_list_entry",
            "interface_list_return", "interface_list_worker", "interface_entry",
            "interface_return", "sched_process_exec", "sched_process_exit"}
SYMBOLS = {"p11_owner_lease", "p11_owner_refund", "p11_read_ia32_arg",
           "p11_exec_dumpability", "p11_exe_identity"}

class InventoryManifestTests(unittest.TestCase):
    def test_exact_inventory_and_mutated_policy_shapes(self):
        try:
            checker.validate_inventory("inventory", MAPS, PROGRAMS, SYMBOLS)
        except (RuntimeError, KeyError) as error:
            self.fail(f"inventory ABI is not admitted: {error}")
        with self.assertRaisesRegex(RuntimeError, "missing required .text helpers"):
            checker.validate_inventory("inventory", MAPS, PROGRAMS,
                                       SYMBOLS - {"p11_exec_dumpability"})
        for name in MAPS:
            for field in checker.MAP_FIELDS:
                changed = {key: dict(value) for key, value in MAPS.items()}
                changed[name][field] ^= 1
                with self.subTest(name=name, field=field), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                    checker.validate_inventory("inventory", changed, PROGRAMS, SYMBOLS)
        for name in PROGRAMS:
            with self.subTest(program=name), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory", MAPS, PROGRAMS - {name}, SYMBOLS)
        for extra in ["p11_return", "p11_entry", "task_newtask"]:
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory", MAPS, PROGRAMS | {extra}, SYMBOLS)
        for forbidden in ["START", "EVENTS", "p11_owner_start_get", "p11_link_current_identity", "p11_root_current_exit"]:
            with self.subTest(symbol=forbidden), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory", MAPS, PROGRAMS, SYMBOLS | {forbidden})

@unittest.skipUnless(os.environ.get("P11SCOPE_INVENTORY_OBJECT"), "actual object supplied by Rust integration gate")
def relocations(elf):
    found = {}
    for row, raw in elf.sections.values():
        if row[1] == 9:
            for offset in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, offset)
                found[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])
    return found


class ActualInventoryTests(unittest.TestCase):
    def usage_cas_roles(self, body, elf, symbol):
        """Select the actual CAS roles in the two emitted pointer placements."""
        section = elf.sections["uprobe"]
        start = section[0][4] + symbol[4]
        raw = section[1][symbol[4]:symbol[4] + symbol[5]]
        insns = [struct.unpack_from("<BBhi", raw, at) for at in range(0, len(raw), 8)]

        def one(label, predicate, positions):
            found = [at for at in positions if predicate(insns[at])]
            self.assertEqual(len(found), 1, (label, found))
            return found[0]

        atomic = one("CAS", lambda insn: insn[0] == 0xdb and insn[3] == 0xf1, range(len(insns)))
        lookup_calls = [at for at in range(atomic) if insns[at] == (0x85, 0, 0, 1)]
        self.assertTrue(lookup_calls)
        lookup_call = lookup_calls[-1]
        window = range(lookup_call + 1, atomic)
        pointer, replacement = insns[atomic][1] & 15, insns[atomic][1] >> 4
        copy = one("pointer copy", lambda insn: insn == (0xbf, pointer, 0, 0), window)
        load = one("u64 load", lambda insn: insn[0] == 0x79 and insn[2:] == (0, 0), window)
        live_pointer, value = insns[load][1] >> 4, insns[load][1] & 15
        positions = {
            "lookup": lookup_call - 2, "pointer": copy, "load": load, "atomic": atomic,
            "null": one("null guard", lambda insn: insn[:2] == (0x15, live_pointer) and insn[3] == 0,
                        range(lookup_call + 1, load)),
            "positive": one("one guard", lambda insn: insn[:2] == (0x15, value) and insn[3] == 1,
                            range(load + 1, atomic)),
            "zero": one("zero guard", lambda insn: insn[:2] == (0x55, value) and insn[3] == 0,
                        range(load + 1, atomic)),
            "replacement": one("replacement", lambda insn: insn == (0xb7, replacement, 0, 1), window),
            "expected": one("expected zero", lambda insn: insn == (0xb7, 0, 0, 0), window),
            "exit": one("exit", lambda insn: insn == (0x95, 0, 0, 0), range(len(insns))),
        }
        roles = {name: start + at * 8 for name, at in positions.items()}
        return roles, pointer, live_pointer, copy < load

    def test_actual_usage_scope_refusal_cannot_reach_marking(self):
        """Deleting, bypassing or reversing authorization must fail admission."""
        body = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"]).read_bytes()
        elf = checker.Elf(body)
        # Positive control uses the same entry checker as every mutation.
        checker.validate_inventory_entry_reachability(elf)
        roots = [symbol for symbol in elf.symbols
                 if symbol[0] in {"p11_usage_entry_lp64", "p11_usage_entry_ia32"}]
        self.assertEqual(len(roots), 2)
        section = elf.sections["uprobe"]
        for root in roots:
            start = section[0][4] + root[4]
            # The exact kernel-stack opt-out (a tail call that never jumps)
            # sits between saving the context and the authorization call. The
            # usage entries load for uprobe-multi, so it goes through the
            # never-populated STACK_GUARD, never TAIL_CALLS.
            instructions = [struct.unpack_from("<BBhi", body, start + i * 8) for i in range(11)]
            relocation_of = (lambda i: next((r for (sec, address), r in relocations(elf).items()
                                            if sec == root[3] and address == root[4] + i * 8), None))
            self.assertTrue(checker.kernel_stack_opt_out_at(
                instructions, 1, relocation_of, arrays=("STACK_GUARD",)))
            self.assertFalse(checker.kernel_stack_opt_out_at(
                instructions, 1, relocation_of, arrays=("TAIL_CALLS",)))
            start += 5 * 8
            prefix = [instructions[0]] + instructions[6:11]
            # Hand-checked actual lowering: returned Option discriminator,
            # followed by the first conditional branch, before any USAGE work.
            self.assertEqual(prefix[3], (0x85, 0x10, 0, -1))
            self.assertEqual(prefix[4], (0x79, 0xa1, -32, 0))
            self.assertEqual(prefix[5][0:2], (0x15, 1))
            self.assertEqual(prefix[5][3], 0)
            refusal = prefix[5][2]
            for label, instruction in [
                ("removed-authorization-branch", (0xbf, 0x11, 0, 0)),
                ("bypassed-authorization-branch", (0x05, 0, 0, 0)),
                ("inverted-authorization-branch", (0x55, 1, refusal, 0)),
                ("refusal-continues-to-collection", (0x15, 1, 0, 0)),
            ]:
                changed = bytearray(body)
                struct.pack_into("<BBhi", changed, start + 5 * 8, *instruction)
                with self.subTest(program=root[0], mutation=label), self.assertRaises(RuntimeError):
                    checker.validate_inventory_entry_reachability(checker.Elf(bytes(changed)))

    def test_actual_usage_cannot_read_inventory_state_inside_authorization(self):
        """A scope helper must not touch USAGE before returning authorization."""
        body = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"]).read_bytes()
        elf = checker.Elf(body)
        usage = next(i for i, symbol in enumerate(elf.symbols) if symbol[0] == "USAGE")
        auth = [s for s in elf.symbols if s[0].endswith("10scope_auth")]
        self.assertEqual(len(auth), 1)
        locations = []
        for row, raw in elf.sections.values():
            if row[1] != 9 or row[7] != auth[0][3]:
                continue
            for offset in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, offset)
                if (auth[0][4] <= address < auth[0][4] + auth[0][5]
                        and elf.symbols[info >> 32][0] == "PID_FILTER"):
                    self.assertEqual(info & 0xffffffff, 1)
                    locations.append(row[4] + offset + 8)
        self.assertEqual(len(locations), 1)
        changed = bytearray(body)
        struct.pack_into("<Q", changed, locations[0], (usage << 32) | 1)
        with self.assertRaises(RuntimeError):
            checker.validate_inventory_entry_reachability(checker.Elf(bytes(changed)))

    def test_actual_object_and_legacy_map_mutations(self):
        source = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"])
        maps, programs, symbols = checker.inspect(source, variant=os.environ.get("P11SCOPE_INVENTORY_VARIANT", "inventory"))
        checker.validate_inventory(os.environ.get("P11SCOPE_INVENTORY_VARIANT", "inventory"), maps, programs, symbols)
        elf = checker.Elf(source.read_bytes())
        with tempfile.TemporaryDirectory(prefix="inventory-object-") as tmp:
            path = Path(tmp) / "mutated.o"
            for symbol in elf.symbols:
                if symbol[0] not in {"USAGE", "USAGE_CONFIG", "USAGE_EVIDENCE"}:
                    continue
                for field in range(7):
                    body = bytearray(source.read_bytes())
                    offset = elf.sections["maps"][0][4] + symbol[4] + 4 * field
                    struct.pack_into("<I", body, offset, struct.unpack_from("<I", body, offset)[0] ^ 1)
                    path.write_bytes(body)
                    with self.subTest(map=symbol[0], field=field), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                        checker.validate_inventory(os.environ.get("P11SCOPE_INVENTORY_VARIANT", "inventory"), *checker.inspect(path, variant=os.environ.get("P11SCOPE_INVENTORY_VARIANT", "inventory")))

    def test_actual_usage_load_and_conditional_cas_guards(self):
        source = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"])
        body = source.read_bytes()
        elf = checker.Elf(body)
        checker.validate_inventory_entry_reachability(elf)
        with tempfile.TemporaryDirectory(prefix="inventory-usage-cas-") as tmp:
            path = Path(tmp) / "mutated.o"
            for symbol in elf.symbols:
                if symbol[0] not in {"p11_usage_entry_lp64", "p11_usage_entry_ia32"}:
                    continue
                roles, _, _, _ = self.usage_cas_roles(body, elf, symbol)
                for label, offset, fmt, value in [
                    ("wrong-lookup-register", roles["lookup"] + 1, "B", 2),
                    ("null-lookup-falls-through", roles["null"] + 2, "h", 0),
                    ("inverted-null-guard", roles["null"], "B", 0x55),
                    ("torn-width-load", roles["load"], "B", 0x61),
                    ("write-on-used-fast-path", roles["positive"] + 2, "h",
                     (roles["atomic"] - roles["positive"]) // 8 - 1),
                    ("used-fast-path-bypasses-zero-return", roles["positive"] + 2, "h",
                     (roles["exit"] - roles["positive"]) // 8 - 1),
                    ("wrong-positive-value", roles["positive"] + 4, "i", 2),
                    ("missing-zero-guard", roles["zero"] + 4, "i", 1),
                    ("wrong-cas-replacement", roles["replacement"] + 4, "i", 2),
                    ("sign-extending-pointer-copy", roles["pointer"] + 2, "h", 32),
                    ("wrong-cas-cell", roles["atomic"] + 2, "h", 8),
                ]:
                    changed = bytearray(body)
                    struct.pack_into("<" + fmt, changed, offset, value)
                    path.write_bytes(changed)
                    with self.subTest(program=symbol[0], mutation=label), self.assertRaises(RuntimeError):
                        checker.validate_inventory_entry_reachability(checker.Elf(path.read_bytes()))

    def test_actual_usage_preserves_lookup_pointer_and_distinct_cas_operands(self):
        body = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"]).read_bytes()
        elf = checker.Elf(body)
        checker.validate_inventory_entry_reachability(elf)
        for symbol in elf.symbols:
            if symbol[0] not in {"p11_usage_entry_lp64", "p11_usage_entry_ia32"}:
                continue
            roles, pointer, live_pointer, early = self.usage_cas_roles(body, elf, symbol)
            replacement = body[roles["replacement"] + 1]
            r0_pointer = [(roles["pointer"] + 1, 0),
                          (roles["atomic"] + 1, replacement << 4)]
            aliases = [(roles["pointer"] + 1, replacement),
                       (roles["atomic"] + 1, replacement << 4 | replacement)]
            if early:
                # Keep the guards/load coherent before the aliased replacement
                # destroys the preserved pointer, rather than failing on a stale register pin.
                aliases += [(roles["null"] + 1, replacement),
                            (roles["load"] + 1, replacement << 4 | 9),
                            (roles["positive"] + 1, 9), (roles["zero"] + 1, 9)]
                r0_pointer += [(roles["null"] + 1, 0),
                               (roles["load"] + 1, body[roles["load"] + 1] & 15)]
            cases = [
                ("load-clobbers-lookup-pointer", [(roles["load"] + 1, live_pointer << 4 | live_pointer),
                                                  (roles["positive"] + 1, live_pointer),
                                                  (roles["zero"] + 1, live_pointer)]),
                ("replacement-clobbers-lookup-pointer", [(roles["replacement"] + 1, live_pointer),
                                                         (roles["atomic"] + 1, live_pointer << 4 | pointer)]),
                ("expected-clobbers-pointer", [(roles["expected"] + 1, pointer)]),
                ("expected-overwrites-r0-pointer", r0_pointer),
                ("replacement-and-pointer-alias", [(roles["replacement"] + 1, pointer),
                                                   (roles["atomic"] + 1, pointer << 4 | pointer)]),
                ("pointer-aliases-replacement", aliases),
            ]
            if early:
                cases += [
                    ("hoisted-pointer-wrong-source", [(roles["pointer"] + 1, 0x60 | pointer)]),
                    ("hoisted-pointer-truncated", [(roles["pointer"], 0xbc)]),
                ]
            for label, register_bytes in cases:
                changed = bytearray(body)
                for offset, value in register_bytes:
                    changed[offset] = value
                with self.subTest(program=symbol[0], mutation=label), self.assertRaises(RuntimeError):
                    checker.validate_inventory_entry_reachability(checker.Elf(bytes(changed)))

    def test_actual_program_section_and_usage_atomic_mutations(self):
        source = Path(os.environ["P11SCOPE_INVENTORY_OBJECT"])
        body = source.read_bytes()
        elf = checker.Elf(body)
        with tempfile.TemporaryDirectory(prefix="inventory-program-") as tmp:
            path = Path(tmp) / "mutated.o"
            symbase = elf.sections[".symtab"][0][4]
            for index, symbol in enumerate(elf.symbols):
                if symbol[0] not in {"p11_usage_entry_lp64", "p11_usage_entry_ia32"}:
                    continue
                changed = bytearray(body)
                struct.pack_into("<H", changed, symbase + 24 * index + 6, elf.indices[".text"])
                path.write_bytes(changed)
                with self.subTest(program=symbol[0]), self.assertRaises(RuntimeError):
                    checker.inspect(path, variant=os.environ.get("P11SCOPE_INVENTORY_VARIANT", "inventory"))
            # Removing all CAS instructions must invalidate the entry reachability
            # contract even if map/program names remain unchanged.
            changed = bytearray(body)
            for name, (row, raw) in elf.sections.items():
                if row[2] & 4:
                    for offset in range(0, len(raw), 8):
                        op, _, _, imm = struct.unpack_from("<BBhi", raw, offset)
                        if op == 0xdb and imm == 0xf1:
                            changed[row[4] + offset:row[4] + offset + 8] = bytes([0xbf, 0x00, 0, 0, 0, 0, 0, 0])
            path.write_bytes(changed)
            with self.assertRaisesRegex(RuntimeError, "atomic|CAS|compare"):
                checker.validate_inventory_entry_reachability(checker.Elf(path.read_bytes()))

if __name__ == "__main__":
    unittest.main()
