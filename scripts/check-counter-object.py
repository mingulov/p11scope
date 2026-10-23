#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect fixed-capacity, unselected counter artifacts and causal mutants.

This is a compiled-object contract, not an installed count-conservation or
resource-admission claim. Lifecycle clocks remain outside the endpoint roots.
"""

import argparse
from collections import deque
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _loader import load_sibling

MAPS = load_sibling("check-bpf-map-defs.py")
SCHEMA = "p11scope-counter-object/v3"
ROOTS = {"p11_entry": "uprobe", "p11_return": "uretprobe"}
STATS_BYTES = {"counts": 24, "timestamps": 40, "latency": 296}
U64_MAX = (1 << 64) - 1
WIDTHS = {0: 4, 8: 2, 16: 1, 24: 8}
FORBIDDEN_HELPERS = {4, 25, 112, 114, 115, 130, 131, 132, 133, 134}
# Exact endpoint helper family consumed by the current producer. Other clock
# helpers (boot/coarse/TAI), arbitrary kernel reads and new helper IDs do not
# inherit helper5's timing role or an automatic scope exemption.
ALLOWED_HELPERS = {1, 2, 3, 5, 12, 14, 37, 80, 156, 158, 174}
FORBIDDEN_ENDPOINT_MAPS = {
    "EVENTS", "DESCRIPTORS", "MECH_SHAPE", "ATTR_BOOL_BITS", "ASYNC_FUNCTIONS",
    "TAIL_CALLS", "PAIR_CALLS",
}
# Aggregate-only endpoints construct START without semantic image/marker
# seeding. This closed inventory keeps the same physical owner/lease and
# discovery custody; Detailed's semantic start_begin requirement is separate.
COUNTER_OWNER_HELPERS = frozenset({
    "p11_owner_cleanup", "p11_owner_discovery_get", "p11_owner_discovery_insert",
    "p11_owner_discovery_remove", "p11_owner_start_aggregate", "p11_owner_start_get",
    "p11_owner_start_remove",
})

BANK_ROOTS = {"p11_counter_bank_entry": "uprobe", "p11_counter_bank_return": "uretprobe"}
BANK_GLOBALS = frozenset({"p11_bank_enter", "p11_bank_complete"})
BANK_CONFIG = 0x18000102


class BankBtf(MAPS.Btf):
    """Proof-only exact HASH_OF_MAPS/one-cell Counts template.

    The shared decoder retains its default refusal for `values`; only the
    explicit proof profile supplies this class. All DATASEC/symbol/relocation
    validation remains the shared decoder's original implementation.
    """

    def map_definition(self, ref):
        node = self.resolve(ref)
        if node[0] != 4:
            return super().map_definition(ref)
        names = [MAPS.string_at(self.strings, item) for item in node[5][::3]]
        if "values" not in names:
            return super().map_definition(ref)
        if (names != ["type", "max_entries", "map_flags", "key", "values"]
                or node[2:5] != (32, 5, 0) or node[5][2::3] != (0, 64, 128, 192, 256)):
            raise RuntimeError("unsupported bank outer template layout")
        integers = []
        for ref in node[5][1:10:3]:
            pointer = self.resolve(ref)
            if pointer[0] != 2:
                raise RuntimeError("bank outer integer is not a pointer")
            array = self.resolve(pointer[2])
            if (array[0] != 3 or self.resolve(array[5][0])[0] != 1
                    or self.resolve(array[5][1])[0] != 1):
                raise RuntimeError("bank outer integer encoding")
            integers.append(array[5][2])
        key = self.resolve(node[5][10])
        if integers != [13, 2, 128] or key[0] != 2 or self.size(key[2]) != 4:
            raise RuntimeError("bank outer must be readonly HASH_OF_MAPS with two u32 keys")
        array = self.resolve(node[5][13])
        if (array[0] != 3 or array[5][2] != 0
                or self.resolve(array[5][1])[0] != 1):
            raise RuntimeError("bank values must be a zero-length pointer array")
        pointer = self.resolve(array[5][0])
        if pointer[0] != 2:
            raise RuntimeError("bank values element is not an inner-map pointer")
        inner_ref = pointer[2]
        inner, size = super().map_definition(inner_ref)
        if inner != MAPS.map_def(6, 4, 24, 1) or size != 32:
            raise RuntimeError("bank inner template must be one 24-byte Counts cell")
        inner_node = self.resolve(inner_ref)
        value_refs = [inner_node[5][i + 1] for i in range(0, len(inner_node[5]), 3)
                      if MAPS.string_at(self.strings, inner_node[5][i]) == "value"]
        if len(value_refs) != 1:
            raise RuntimeError("bank inner template requires a typed Counts value")
        value = self.resolve(self.resolve(value_refs[0])[2])
        value_names = [MAPS.string_at(self.strings, item) for item in value[5][::3]]
        if (value[:1] != (4,) or value[2:5] != (24, 3, 0)
                or value_names != ["entered", "returned", "errors"]
                or value[5][2::3] != (0, 64, 128)):
            raise RuntimeError("bank Counts value fields/layout differ")
        for ref in value[5][1::3]:
            field = self.resolve(ref)
            if field[0] != 1 or field[2] != 8 or field[5] != (64,):
                raise RuntimeError("bank Counts fields must be full-width unsigned u64")
        return {**MAPS.map_def(13, 4, 4, 2, 128), "inner_template": inner}, 32


def bank_maps(graph):
    elf = graph.elf
    section = elf.indices["maps"]
    records = [(s[4], s[5], "OBJECT", "", "", str(s[3]), s[0])
               for s in elf.symbols if s[3] == section and s[1] & 15 == 1]
    maps = MAPS.decode_map_definitions(records, section, elf.sections["maps"][1])
    native = MAPS.decode_btf_maps(elf, decoder_class=BankBtf)
    if maps.keys() & native.keys():
        raise RuntimeError("duplicate bank proof map")
    maps.update(native)
    expected = {
        "STATS": (6, 4, 24, 512, 0), "RV_COUNTS": (5, 16, 8, 4096, 0),
        "START": (1, 16, 288, 16384, 0), "COUNTER_HEALTH": (6, 4, 8, 2, 0),
        "OWNER_CTL": (2, 4, 56, 1, 0), "THREAD_OWNER": (29, 4, 560, 0, 1),
        "COUNTER_BANKS": (13, 4, 4, 2, 128), "COUNTER_BANK_META": (1, 4, 24, 2, 128),
        "COUNTER_BANK_COMMIT": (1, 8, 16, 2, 128), "COUNTER_BANK_FAULT": (6, 4, 8, 1, 0),
    }
    for name, fields in expected.items():
        if name not in maps or tuple(maps[name][field] for field in
                                    ("type", "key_size", "value_size", "max_entries", "flags")) != fields:
            raise RuntimeError(f"bank proof map shape differs: {name}")
    if maps["COUNTER_BANKS"].get("inner_template") != MAPS.map_def(6, 4, 24, 1):
        raise RuntimeError("bank proof has no exact typed inner template")
    return maps, expected


def bank_global_abi(graph):
    elf = graph.elf
    helpers = [symbol for symbol in elf.symbols if symbol[0].startswith("p11_bank_")]
    if len(helpers) != 2 or {symbol[0] for symbol in helpers} != BANK_GLOBALS:
        raise RuntimeError("bank proof global inventory differs")
    for _, info, other, section, address, size in helpers:
        if (info != 0x12 or other or section != elf.indices.get(".text")
                or not size or address % 8 or size % 8):
            raise RuntimeError("bank proof requires defined GLOBAL DEFAULT bridge functions")
    btf = MAPS.Btf(elf.sections[".BTF"][1])
    bank_functions = [node for node in btf.types[1:]
                      if node[0] == 12 and node[1].startswith("p11_bank_")]
    if len(bank_functions) != 2 or {node[1] for node in bank_functions} != BANK_GLOBALS:
        raise RuntimeError("bank proof BTF global inventory differs")
    all_functions = [node for node in btf.types[1:] if node[0] == 12]
    if any(not node[2] or btf.types[node[2]][0] != 13 or btf.types[node[2]][3] > 5
           for node in all_functions):
        raise RuntimeError("bank proof exceeds the five-register function ABI")
    for name, widths in (("p11_bank_enter", (4, 8)), ("p11_bank_complete", (4, 8, 8, 4))):
        functions = [node for node in btf.types[1:] if node[0] == 12 and node[1] == name]
        if len(functions) != 1 or functions[0][3] != 1:
            raise RuntimeError("bank proof global BTF function missing/duplicate")
        proto = btf.resolve(functions[0][2])
        refs = (proto[2],) + proto[5][1::2]
        if proto[0] != 13 or proto[3] != len(widths):
            raise RuntimeError("bank proof global argument count differs")
        for ref, width in zip(refs, (4,) + widths):
            integer = btf.resolve(ref)
            if integer[0] != 1 or integer[2] != width or integer[5] != (width * 8,):
                raise RuntimeError("bank proof requires exact unsigned scalar ABI")
    # Preserve exact FUNC_INFO ownership and its emitted section relocation;
    # the shared private-helper validator intentionally supports only zero-
    # argument globals, so do not broaden its ordinary owner/EXEC contract.
    ext = elf.sections[".BTF.ext"][1]
    magic, version, flags, hlen, offset, length = struct.unpack_from("<HBBIII", ext)
    if (magic, version, flags, hlen) != (0xeb9f, 1, 0, 32):
        raise RuntimeError("unsupported bank function info header")
    raw = MAPS.checked_slice(ext, hlen + offset, length, "bank function info")
    if struct.unpack_from("<I", raw)[0] != 8:
        raise RuntimeError("unsupported bank function info stride")
    relocations = {}
    for row, body in elf.sections.values():
        if row[1] != 9 or row[7] != elf.indices[".BTF.ext"]:
            continue
        if row[9] != 16 or len(body) % 16 or row[6] != elf.indices[".symtab"]:
            raise RuntimeError("invalid bank function info relocation table")
        for at in range(0, len(body), 16):
            address, info = struct.unpack_from("<QQ", body, at)
            if address in relocations or info >> 32 >= len(elf.symbols):
                raise RuntimeError("duplicate/invalid bank function info relocation")
            relocations[address] = info & 0xffffffff, elf.symbols[info >> 32]
    found, cursor = set(), 4
    while cursor < len(raw):
        section_name, count = struct.unpack("<II", MAPS.checked_slice(raw, cursor, 8, "bank info section"))
        section_name = MAPS.string_at(btf.strings, section_name)
        cursor += 8
        for _ in range(count):
            address, ident = struct.unpack("<II", MAPS.checked_slice(raw, cursor, 8, "bank info record"))
            record = hlen + offset + cursor
            cursor += 8
            if not 0 < ident < len(btf.types) or btf.types[ident][0] != 12:
                raise RuntimeError("bank function info is not a BTF FUNC")
            name = btf.types[ident][1]
            if name not in BANK_GLOBALS:
                continue
            symbol = next(symbol for symbol in helpers if symbol[0] == name)
            relocation = relocations.get(record)
            if (name in found or elf.indices.get(section_name) != symbol[3] or address != symbol[4]
                    or not relocation or relocation[0] != 4
                    or relocation[1][1:] != (3, 0, symbol[3], 0, 0)):
                raise RuntimeError("bank function info/symbol/relocation mismatch")
            found.add(name)
    if found != BANK_GLOBALS:
        raise RuntimeError("bank global function info is incomplete")


class CallGraph:
    """Selected donor graph parser, with exact roots and closed call targets."""

    def __init__(self, body):
        self.body = body
        self.elf = MAPS.Elf(body)
        self.sections = {self.elf.indices[name]: (row, raw)
                         for name, (row, raw) in self.elf.sections.items()}
        self.bodies = {}
        for symbol in self.elf.symbols:
            if symbol[1] & 15 != 2 or not symbol[5] or not symbol[3]:
                continue
            key = symbol[3], symbol[4]
            if key in self.bodies or symbol[4] % 8 or symbol[5] % 8:
                raise RuntimeError("duplicate or unaligned counter function")
            MAPS.checked_slice(self.sections[key[0]][1], key[1], symbol[5], "function")
            self.bodies[key] = symbol
        self.relocations = {}
        for row, raw in self.elf.sections.values():
            if row[1] != 9 or row[7] not in {key[0] for key in self.bodies}:
                continue
            if row[9] != 16 or len(raw) % 16 or row[6] != self.elf.indices[".symtab"]:
                raise RuntimeError("invalid counter relocation table")
            for at in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, at)
                key = row[7], address
                if key in self.relocations or info >> 32 >= len(self.elf.symbols):
                    raise RuntimeError("duplicate or invalid counter relocation")
                self.relocations[key] = info & 0xffffffff, self.elf.symbols[info >> 32]
        self.instructions = {}
        self.calls = {}
        self.edges = {key: set() for key in self.bodies}
        for key, symbol in self.bodies.items():
            raw = MAPS.checked_slice(self.sections[key[0]][1], key[1], symbol[5], "function")
            instructions, continuations = {}, set()
            at = 0
            while at < len(raw):
                instruction = struct.unpack_from("<BBhi", raw, at)
                instructions[at // 8] = instruction
                op, registers, offset, immediate = instruction
                if op == 0x18:
                    MAPS.checked_slice(raw, at, 16, "wide counter instruction")
                    if struct.unpack_from("<BBh", raw, at + 8) != (0, 0, 0):
                        raise RuntimeError("invalid wide instruction continuation")
                    continuations.add(at // 8 + 1)
                    at += 16
                    continue
                if op == 0x8d:
                    raise RuntimeError("indirect counter call")
                if op == 0x85:
                    if offset:
                        raise RuntimeError("counter call has a nonzero offset")
                    if registers == 0:
                        self.calls[key, at // 8] = "helper", immediate
                    elif registers == 0x10:
                        relocation = self.relocations.get((key[0], key[1] + at))
                        if relocation:
                            kind, target = relocation
                            if kind != 10:
                                raise RuntimeError("invalid BPF call relocation")
                            destination = target[3], target[4] + (immediate + 1) * 8
                        else:
                            destination = key[0], key[1] + at + (immediate + 1) * 8
                        if destination not in self.bodies:
                            raise RuntimeError(f"unknown call target in {symbol[0]}")
                        self.calls[key, at // 8] = "function", destination
                        self.edges[key].add(destination)
                    else:
                        raise RuntimeError("unsupported counter call encoding")
                at += 8
            for pc, (op, _, offset, _) in instructions.items():
                if op & 7 in (5, 6) and op not in (0x85, 0x95):
                    delta = instructions[pc][3] if op == 0x06 else offset
                    target = pc + 1 + delta
                    if target not in instructions or target in continuations:
                        raise RuntimeError("counter branch leaves its function")
            self.instructions[key] = instructions
        self.loops = {key: self.finite_store_loops(instructions)
                      for key, instructions in self.instructions.items()}

    @staticmethod
    def finite_store_loops(instructions):
        """Recognize only straight-line, constant-stride, equality-exit loops.

        The actual native lease initializer has this shape. No outside edge
        may enter its body, the induction register has one writer, and the
        exact positive stride divides the nonwrapping bound. An arbitrary
        backedge or source-level loop name earns no range fact.
        """
        predecessors = {pc: set() for pc in instructions}
        for pc, (op, _, offset, immediate) in instructions.items():
            next_pc = pc + (2 if op == 0x18 else 1)
            targets = [] if op == 0x95 else [next_pc]
            if op & 7 in (5, 6) and op not in (0x85, 0x95):
                targets = [pc + 1 + (immediate if op == 0x06 else offset)]
                if op & 0xf0:
                    targets.append(next_pc)
            for target in targets:
                if target in predecessors:
                    predecessors[target].add(pc)
        found = {}
        for tail, (op, _, offset, immediate) in instructions.items():
            if op not in (0x05, 0x06):
                continue
            head = tail + 1 + (immediate if op == 0x06 else offset)
            if head >= tail or head < 1:
                continue
            init, step, guard = (instructions.get(at) for at in (head - 1, tail - 2, tail - 1))
            if not init or not step or not guard:
                continue
            if init[0] not in (0xb4, 0xb7) or step[0] not in (0x04, 0x07) or guard[0] not in (0x15, 0x16):
                continue
            register = init[1]
            begin, stride, end = init[3], step[3], guard[3]
            if (register > 9 or step[1] != register or guard[1] != register
                    or init[2] or step[2] or guard[2] != 1
                    or not 0 <= begin < end <= 0x7fffffff or stride <= 0
                    or (end - begin) % stride or predecessors[head] != {head - 1, tail}):
                continue
            if (predecessors[tail - 2] != {tail - 3}
                    or predecessors[tail - 1] != {tail - 2}
                    or predecessors[tail] != {tail - 1}):
                continue
            valid = True
            for pc in range(head, tail - 2):
                instruction = instructions.get(pc)
                if not instruction or predecessors[pc] != ({head - 1, tail} if pc == head else {pc - 1}):
                    valid = False
                    break
                operation, encoded, _, _ = instruction
                if (operation & 7 in (5, 6) or operation == 0x18
                        or operation & 7 in (1, 4, 7) and encoded & 15 == register
                        or operation & 0xe0 == 0xc0):
                    valid = False
                    break
            if valid:
                found[head] = register, begin, end - stride
        # Rotated zero-template scan: initialization jumps to the first read;
        # a successful word check returns through increment + equality exit.
        for tail, instruction in instructions.items():
            if instruction[0] not in (0x15, 0x55, 0x16, 0x56):
                continue
            increment = tail + 1 + instruction[2]
            head = increment + 2
            if head >= tail or increment < 2:
                continue
            init, skip, step, guard = (instructions.get(at)
                                       for at in (increment - 2, increment - 1, increment, increment + 1))
            if not all((init, skip, step, guard)):
                continue
            register = init[1]
            begin, stride, end = init[3], step[3], guard[3]
            if (init[0] not in (0xb4, 0xb7) or skip[0] != 0x05
                    or increment + skip[2] != head or step[0] not in (0x04, 0x07)
                    or guard[0] not in (0x15, 0x16) or register > 9
                    or step[1] != register or guard[1] != register or init[2] or step[2]
                    or increment + 2 + guard[2] <= tail
                    or not 0 <= begin < end <= 0x7fffffff or stride <= 0
                    or (end - begin) % stride
                    or predecessors[head] != {increment - 1, increment + 1}
                    or predecessors[increment] != {tail}
                    or predecessors[increment + 1] != {increment}
                    or predecessors[increment - 1] != {increment - 2}):
                continue
            valid = True
            for pc in range(head, tail):
                item = instructions.get(pc)
                if not item or predecessors[pc] != ({increment - 1, increment + 1} if pc == head else {pc - 1}):
                    valid = False
                    break
                operation, encoded, _, _ = item
                if (operation & 7 in (5, 6) or operation == 0x18
                        or operation & 7 in (1, 4, 7) and encoded & 15 == register
                        or operation & 0xe0 == 0xc0):
                    valid = False
                    break
            if valid and instruction[1] & 15 != register and predecessors[tail] == {tail - 1}:
                found[head] = register, begin, end - stride
        return found

    def only(self, name):
        found = [key for key, symbol in self.bodies.items() if symbol[0] == name]
        if len(found) != 1:
            raise RuntimeError(f"requires exactly one {name}")
        return found[0]

    def root(self, name, section):
        key = self.only(name)
        symbol = self.bodies[key]
        if symbol[1] != 0x12 or symbol[2] != 0 or key[0] != self.elf.indices.get(section):
            raise RuntimeError(f"requires GLOBAL DEFAULT {section} {name}")
        return key

    def reachable(self, root):
        reached, pending = set(), [root]
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(self.edges[key])
        return reached

    def file_offset(self, key, pc, field=0):
        return self.sections[key[0]][0][4] + key[1] + pc * 8 + field

    def map_at(self, key, pc):
        relocation = self.relocations.get((key[0], key[1] + pc * 8))
        if relocation is None:
            return None
        kind, target = relocation
        if kind != 1 or target[1] & 15 not in (1, 3):
            raise RuntimeError("unsupported counter data relocation")
        if target[3] not in {self.elf.indices.get("maps"), self.elf.indices.get(".maps")}:
            raise RuntimeError("counter endpoint reaches global data")
        raw = self.sections[key[0]][1]
        immediate = struct.unpack_from("<i", raw, key[1] + pc * 8 + 4)[0]
        high = struct.unpack_from("<i", raw, key[1] + pc * 8 + 12)[0]
        addend = ((high & 0xffffffff) << 32) | (immediate & 0xffffffff)
        found = [symbol[0] for symbol in self.elf.symbols
                 if symbol[1] & 15 == 1 and symbol[3] == target[3]
                 and symbol[4] == target[4] + addend]
        if len(found) != 1:
            raise RuntimeError("map relocation does not name one exact map")
        return found[0]


def counter_maps(graph, mode):
    elf = graph.elf
    if "maps" not in elf.sections:
        raise RuntimeError("counter artifact has no Rust map definitions")
    section = elf.indices["maps"]
    records = [(s[4], s[5], "OBJECT", "", "", str(s[3]), s[0])
               for s in elf.symbols if s[3] == section and s[1] & 15 == 1]
    maps = MAPS.decode_map_definitions(records, section, elf.sections["maps"][1])
    native = MAPS.decode_btf_maps(elf)
    if maps.keys() & native.keys():
        raise RuntimeError("duplicate Rust/native counter map")
    maps.update(native)
    expected = {
        "STATS": (6, 4, STATS_BYTES[mode], 512),
        "RV_COUNTS": (5, 16, 8, 4096),
        "COUNTER_HEALTH": (6, 4, 8, 2),
        "START": (1, 16, 288, 16384),
    }
    for name, fields in expected.items():
        if name not in maps:
            raise RuntimeError(f"counter artifact has no {name} map")
        for field, wanted in zip(("type", "key_size", "value_size", "max_entries"), fields):
            if maps[name][field] != wanted:
                raise RuntimeError(f"{mode}: {name}.{field}={maps[name][field]}, expected {wanted}")
        if maps[name].get("flags", 0) or maps[name].get("pinning", 0):
            raise RuntimeError(f"unexpected {name} flags or pinning")
    return maps, expected


def scalar(low=0, high=U64_MAX, tag=None):
    return "scalar", tag, low, high


ZERO = scalar(0, 0)
ONE = scalar(1, 1)


def constant(value):
    value &= U64_MAX
    return scalar(value, value)


def singleton(value):
    return value[2] if value and value[0] == "scalar" and value[2] == value[3] else None


def join_fact(left, right):
    if left == right:
        return left
    if left is None or right is None:
        return None
    if left == ZERO and right[0] in ("ptr", "stack", "key", "external"):
        return right
    if right == ZERO and left[0] in ("ptr", "stack", "key", "external"):
        return left
    if left[0] == right[0] == "scalar":
        return scalar(min(left[2], right[2]), max(left[3], right[3]),
                      left[1] if left[1] == right[1] else None)
    if left[0] == right[0] == "ptr" and left[1] == right[1]:
        return ("ptr", left[1], min(left[2], right[2]), max(left[3], right[3]),
                join_fact(left[4], right[4]))
    return None


def narrowed(value, bits):
    if not value or value[0] != "scalar":
        return scalar(0, (1 << bits) - 1)
    maximum = (1 << bits) - 1
    if value[3] <= maximum:
        return value
    exact = singleton(value)
    return constant(exact & maximum) if exact is not None else scalar(0, maximum)


def scalar_alu(left, right, operation, bits):
    mask = (1 << bits) - 1
    left, right = narrowed(left, bits), narrowed(right, bits)
    a, b = singleton(left), singleton(right)
    if a is not None and b is not None:
        operations = {0x00: lambda: a + b, 0x10: lambda: a - b,
                      0x20: lambda: a * b, 0x30: lambda: a // b if b else 0,
                      0x40: lambda: a | b, 0x50: lambda: a & b,
                      0x60: lambda: a << (b & (bits - 1)),
                      0x70: lambda: a >> (b & (bits - 1)),
                      0x90: lambda: a % b if b else a, 0xa0: lambda: a ^ b}
        if operation in operations:
            return constant(operations[operation]() & mask)
    if operation == 0x50 and b is not None:
        tag = left[1] if b == mask else (
            "key_slot" if left[1] == "key_slot_pad" and b == 0xffffffff else None)
        return scalar(0, min(left[3], b), tag)
    if operation == 0x70 and b is not None:
        tag = ("key_shift", b) if left[1] in ("key_slot", "key_slot_pad") else None
        return scalar(left[2] >> (b & (bits - 1)), left[3] >> (b & (bits - 1)), tag)
    if operation == 0x60 and b is not None and left[3] << (b & (bits - 1)) <= mask:
        return scalar(left[2] << (b & (bits - 1)), left[3] << (b & (bits - 1)))
    if operation == 0x00 and left[3] + right[3] <= mask:
        return scalar(left[2] + right[2], left[3] + right[3])
    if operation == 0x10 and left[2] >= right[3]:
        return scalar(left[2] - right[3], left[3] - right[2])
    if operation == 0x20 and left[3] * right[3] <= mask:
        return scalar(left[2] * right[2], left[3] * right[3])
    if operation == 0x40:
        maximum = (1 << max(left[3].bit_length(), right[3].bit_length())) - 1
        return scalar(0, min(maximum, mask))
    return scalar(0, mask)


def frame_and_chain(graph, root, observed):
    def walk(key, ancestors):
        if key in ancestors or len(ancestors) >= 8:
            raise RuntimeError("cyclic/deep counter BPF call graph")
        depth = observed.get(key, 0)
        for pc, (op, registers, offset, immediate) in graph.instructions[key].items():
            if op & 7 in (1, 2, 3):
                base = registers >> 4 if op & 7 == 1 else registers & 15
                if base == 10:
                    if offset >= 0:
                        raise RuntimeError("nonnegative counter stack access")
                    depth = max(depth, -offset)
            if (op == 0x07 and immediate < 0
                    and graph.instructions[key].get(pc - 1, ())[:2]
                    == (0xbf, 0xa0 | (registers & 15))):
                depth = max(depth, -immediate)
        if depth > 512:
            raise RuntimeError("counter function frame exceeds 512 bytes")
        children = [walk(child, ancestors + (key,)) for child in graph.edges[key]]
        total = ((max(depth, 1) + 31) // 32 * 32) + max(children, default=0)
        if total > 512:
            raise RuntimeError(f"counter root call chain exceeds 512 bytes: {total}")
        return total
    return walk(root, ())


class MemoryProof:
    """Conservative register/stack provenance over actual reachable bodies.

    Joins forget facts rather than accepting a write from one favorable path.
    Null joins retain only a map's provenance; kernel null safety is still a
    separate verifier obligation. No unknown destination may write STATS by
    being silently treated as an unrelated pointer.
    """

    def __init__(self, graph, maps, strict=True, *, native_bound=512):
        if type(native_bound) is not int or native_bound not in (512, 8192):
            raise RuntimeError("unsupported explicit native owner slot bound")
        self.graph, self.maps, self.strict = graph, maps, strict
        self.native_bound = native_bound
        self.touches, self.health, self.guards = set(), set(), set()
        self.guard_sources = {}
        self.frames = {}
        self.steps = 0

    @staticmethod
    def merge(left, right, widen=False):
        registers = [join_fact(a, b) for a, b in zip(left[0], right[0])]
        memory = {key: join_fact(value, right[1][key]) for key, value in left[1].items()
                  if key in right[1]}
        if widen:
            for index, value in enumerate(registers):
                previous = left[0][index]
                if (value != previous and value and previous
                        and value[0] == previous[0] == "scalar"):
                    registers[index] = scalar(tag=value[1])
        return registers, memory

    def stack_address(self, pointer, offset, width, key):
        at = pointer[2] + offset
        if at < -512 or at + width > 0 or at % width:
            raise RuntimeError("invalid or unaligned counter stack access")
        self.frames[key] = max(self.frames.get(key, 0), -at)
        return pointer[1], at, width

    def read(self, pointer, offset, width, memory, key, pc):
        if pointer and pointer[0] == "stack":
            address = self.stack_address(pointer, offset, width, key)
            return self.stack_cell(memory, *address)
        if pointer and pointer[0] == "key":
            at = pointer[1] + offset
            tag = "key_slot" if at == 8 and width == 4 else (
                "key_slot_pad" if at == 8 and width == 8 else None)
            return scalar(0, (1 << (width * 8)) - 1, tag)
        if pointer and pointer[0] == "ptr":
            self.touch(pointer, offset, width, "read", None, key, pc)
        elif self.strict and (not pointer or pointer[0] != "external"):
            raise RuntimeError(f"unknown counter read in {self.graph.bodies[key][0]}:{pc}")
        return scalar(0, (1 << (width * 8)) - 1)

    def write(self, pointer, offset, width, value, memory, key, pc, atomic=None):
        if pointer and pointer[0] == "stack":
            address = self.stack_address(pointer, offset, width, key)
            frame, at, _ = address
            for old in list(memory):
                if old[0] == frame and at < old[1] + old[2] and old[1] < at + width:
                    del memory[old]
            memory[address] = narrowed(value, width * 8) if width < 8 else value
        elif pointer and pointer[0] == "ptr":
            self.touch(pointer, offset, width, "write", value, key, pc, atomic)
        elif self.strict:
            raise RuntimeError(f"unknown counter write in {self.graph.bodies[key][0]}:{pc}")

    def touch(self, pointer, offset, width, action, value, key, pc, atomic=None):
        name, low, high, index = pointer[1:]
        if name not in self.maps or low + offset < 0 or high + offset + width > self.maps[name]["value_size"]:
            raise RuntimeError(f"out-of-bounds {name} {action} in {self.graph.bodies[key][0]}:{pc}")
        span = low + offset, high + offset
        self.touches.add((key, pc, name, action, span, width, atomic))
        if name in {"STATS", "RV_COUNTS"} and action == "write":
            if width != 8 or atomic != 0xf1:
                raise RuntimeError(f"{name} requires full-width bounded-CAS updates")
        if name == "COUNTER_HEALTH" and action == "write":
            if width != 8 or span != (0, 0) or value != ONE or atomic is not None:
                raise RuntimeError("counter health must write one full-width sticky one")
            if not index or index[0] != "scalar" or not 0 <= index[2] <= index[3] <= 1:
                raise RuntimeError("counter health key is not a finite disposition")
            self.health.add((key, pc, index[2], index[3]))

    @staticmethod
    def adjusted(pointer, amount):
        if pointer and pointer[0] in ("stack", "external"):
            return pointer[:2] + (pointer[2] + amount,)
        if pointer and pointer[0] == "key":
            return "key", pointer[1] + amount
        if pointer and pointer[0] == "ptr":
            return "ptr", pointer[1], pointer[2] + amount, pointer[3] + amount, pointer[4]
        return None

    @staticmethod
    def stack_cell(memory, frame, at, width):
        direct = memory.get((frame, at, width))
        if direct is not None:
            return direct
        for (other_frame, old_at, old_width), value in memory.items():
            if (other_frame == frame and old_at <= at and at + width <= old_at + old_width
                    and value and value[0] == "scalar"):
                exact = singleton(value)
                if exact is not None:
                    return constant((exact >> ((at - old_at) * 8)) & ((1 << (width * 8)) - 1))
                if at == old_at:
                    return narrowed(value, width * 8)
        return scalar(0, (1 << (width * 8)) - 1)

    def key_value(self, pointer, memory, width=4):
        if pointer and pointer[0] == "stack":
            return self.stack_cell(memory, pointer[1], pointer[2], width)
        return None

    def helper(self, number, registers, memory, key, pc):
        if number in FORBIDDEN_HELPERS or number not in ALLOWED_HELPERS:
            raise RuntimeError(f"endpoint reaches forbidden/unknown helper {number}")
        result = scalar()
        if number in (1, 2, 3, 156, 157):
            mapped = registers[1]
            if not mapped or mapped[0] != "map" or mapped[1] not in self.maps:
                raise RuntimeError("map helper lost its exact map provenance")
            name = mapped[1]
            if number in (1, 156):
                index = self.key_value(registers[2], memory)
                result = "ptr", name, 0, 0, index
            if number == 2 and name in {"STATS", "COUNTER_HEALTH"}:
                raise RuntimeError(f"unexpected replacement of {name}")
            if number == 3 and name in {"STATS", "RV_COUNTS", "COUNTER_HEALTH"}:
                raise RuntimeError(f"unexpected deletion of cumulative {name}")
            if number == 2 and name == "RV_COUNTS":
                if self.key_value(registers[3], memory, 8) != ONE:
                    raise RuntimeError("RV insertion must initialize one, never overwrite a level")
                if singleton(registers[4]) != 1:
                    raise RuntimeError("RV insertion requires BPF_NOEXIST")
        elif number == 12:
            if registers[2] != ("map", "STACK_GUARD"):
                raise RuntimeError("endpoint reaches an unclassified tail call")
        elif number == 158:
            result = "external", "task", 0
        for register in range(1, 6):
            registers[register] = None
        registers[0] = result

    def branch(self, op, left, right, key, pc):
        operation = op & 0xf0
        immediate = singleton(right)
        if left and left[0] == "scalar" and immediate is not None:
            tag = left[1]
            if tag in ("key_slot", "key_slot_pad") and operation in (0x20, 0x30, 0xa0, 0xb0):
                bound = immediate + (1 if operation in (0x20, 0xb0) else 0)
                if bound != self.native_bound:
                    raise RuntimeError(f"native owner slot bound differs from expected {self.native_bound}")
                self.guards.add((key, pc, "immediate", immediate))
            if isinstance(tag, tuple) and tag[0] == "key_shift" and operation in (0x10, 0x50) and immediate == 0:
                if tag[1] != self.native_bound.bit_length() - 1:
                    raise RuntimeError(f"native owner shifted slot bound differs from expected {self.native_bound}")
                self.guards.add((key, pc, "shift", tag[1]))
                if len(tag) == 3:
                    self.guard_sources[key, pc] = tag[2]
        return operation

    @staticmethod
    def refine(registers, destination, left, immediate, operation, taken):
        if not left or left[0] != "scalar" or immediate is None:
            return True
        low, high = left[2:]
        if operation == 0x10:
            if taken:
                low, high = max(low, immediate), min(high, immediate)
        elif operation == 0x50:
            if not taken:
                low, high = max(low, immediate), min(high, immediate)
        elif operation == 0x20:  # unsigned greater than
            if taken:
                low = max(low, immediate + 1)
            else:
                high = min(high, immediate)
        elif operation == 0x30:  # unsigned greater than or equal
            if taken:
                low = max(low, immediate)
            else:
                high = min(high, immediate - 1)
        elif operation == 0xa0:  # unsigned less than
            if taken:
                high = min(high, immediate - 1)
            else:
                low = max(low, immediate)
        elif operation == 0xb0:  # unsigned less than or equal
            if taken:
                high = min(high, immediate)
            else:
                low = max(low, immediate + 1)
        if low > high:
            return False
        registers[destination] = scalar(low, high, left[1])
        return True

    def run(self, key, arguments, memory=None, path=()):
        if key in path or len(path) >= 8:
            raise RuntimeError("cyclic/deep counter provenance call")
        frame = key, len(path)
        registers = [None] * 11
        registers[1:6] = arguments
        registers[10] = "stack", frame, 0
        states = {0: (registers, dict(memory or {}))}
        changes = {}
        pending = deque([0])
        exits = None

        def enqueue(pc, state):
            if pc not in self.graph.instructions[key]:
                raise RuntimeError("counter control flow leaves its function")
            if pc in self.graph.loops[key]:
                register, low, high = self.graph.loops[key][pc]
                state = list(state[0]), state[1]
                state[0][register] = scalar(low, high)
            if pc in states:
                state = self.merge(states[pc], state, changes.get(pc, 0) >= 8)
                if state == states[pc]:
                    return
            states[pc] = state
            changes[pc] = changes.get(pc, 0) + 1
            pending.append(pc)

        while pending:
            self.steps += 1
            if self.steps > 250_000:
                raise RuntimeError("counter provenance exceeds finite analysis budget")
            pc = pending.popleft()
            registers, memory = states[pc]
            registers, memory = list(registers), dict(memory)
            op, encoded, offset, immediate = self.graph.instructions[key][pc]
            destination, source = encoded & 15, encoded >> 4
            if destination > 10 or source > 10:
                raise RuntimeError("invalid counter register")
            next_pc = pc + 1
            if op == 0x18:
                mapped = self.graph.map_at(key, pc)
                if mapped:
                    registers[destination] = "map", mapped
                else:
                    high = struct.unpack_from("<I", self.graph.sections[key[0]][1], key[1] + pc * 8 + 12)[0]
                    registers[destination] = constant((high << 32) | (immediate & 0xffffffff))
                next_pc += 1
            elif op == 0x85:
                kind, target = self.graph.calls[key, pc]
                if kind == "helper":
                    self.helper(target, registers, memory, key, pc)
                else:
                    result, memory = self.run(target, registers[1:6], memory, path + (key,))
                    registers[:6] = [result, None, None, None, None, None]
            elif op == 0x95:
                state = registers, memory
                exits = state if exits is None else self.merge(exits, state)
                continue
            elif op & 7 == 1 and op & 0xe0 == 0x60:
                registers[destination] = self.read(registers[source], offset, WIDTHS[op & 0x18], memory, key, pc)
            elif op & 7 in (2, 3) and op & 0xe0 in (0x60, 0xc0):
                width = WIDTHS[op & 0x18]
                atomic = immediate if op & 0xe0 == 0xc0 else None
                value = constant(immediate) if op & 7 == 2 else registers[source]
                if atomic is not None and (op not in (0xc3, 0xdb)
                        or atomic not in (0, 1, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1)):
                    raise RuntimeError("unsupported counter atomic operation")
                self.write(registers[destination], offset, width, value, memory, key, pc, atomic)
                if atomic == 0xf1:
                    registers[0] = scalar(0, (1 << (width * 8)) - 1)
                elif atomic is not None and atomic & 1:
                    registers[source] = scalar(0, (1 << (width * 8)) - 1)
            elif op & 7 in (4, 7):
                bits, operation = (32 if op & 7 == 4 else 64), op & 0xf0
                right = registers[source] if op & 8 else constant(immediate)
                left = registers[destination]
                if operation == 0xb0:
                    registers[destination] = (right if bits == 64 and offset == 0
                                              else narrowed(right, bits) if not offset else scalar())
                elif bits == 64 and left and left[0] in ("ptr", "stack", "key", "external") and operation in (0, 0x10):
                    amount = singleton(right)
                    if op & 8 == 0:
                        amount = immediate
                    if amount is not None:
                        registers[destination] = self.adjusted(left, amount if operation == 0 else -amount)
                    elif left[0] == "ptr" and operation == 0 and right and right[0] == "scalar":
                        registers[destination] = "ptr", left[1], left[2] + right[2], left[3] + right[3], left[4]
                    else:
                        registers[destination] = None
                else:
                    value = scalar_alu(left, right, operation, bits)
                    if operation == 0x70 and isinstance(value[1], tuple) and value[1][0] == "key_shift":
                        # Keep the actual producing instruction for causal
                        # bound mutants; never select an unrelated same-size shift.
                        value = scalar(value[2], value[3], value[1] + ((key, pc),))
                    registers[destination] = value
            elif op & 7 in (5, 6):
                if op & 0xf0 == 0:
                    enqueue(pc + 1 + (immediate if op == 0x06 else offset), (registers, memory))
                    continue
                left = registers[destination]
                right = registers[source] if op & 8 else constant(immediate)
                comparison_left, comparison_right = left, right
                can_refine = True
                if op & 7 == 6:
                    comparison_left, comparison_right = narrowed(left, 32), narrowed(right, 32)
                    can_refine = bool(left and left[0] == "scalar" and left[3] <= 0xffffffff)
                operation = self.branch(op, comparison_left, comparison_right, key, pc)
                refined_register, refined_value = destination, comparison_left
                bound = singleton(comparison_right)
                refined_operation = operation
                inverse = {0x10: 0x10, 0x50: 0x50, 0x20: 0xa0,
                           0x30: 0xb0, 0xa0: 0x20, 0xb0: 0x30}
                if (op & 8 and operation in inverse and bound is None
                        and singleton(comparison_left) is not None
                        and right and right[0] == "scalar"):
                    # Reverse only the comparison operands, never the taken
                    # edge. A JMP32 bound constrains the full source only
                    # when its original value already fits that low word.
                    refined_register, refined_value = source, comparison_right
                    bound, refined_operation = singleton(comparison_left), inverse[operation]
                    can_refine = op & 7 == 5 or right[3] <= 0xffffffff
                for taken, target in ((True, pc + 1 + offset), (False, pc + 1)):
                    branch_registers = list(registers)
                    if (not can_refine or self.refine(branch_registers, refined_register, refined_value,
                                                     bound, refined_operation, taken)):
                        enqueue(target, (branch_registers, dict(memory)))
                continue
            else:
                raise RuntimeError(f"unsupported counter opcode {op:#x}")
            enqueue(next_pc, (registers, memory))
        if exits is None:
            raise RuntimeError("counter function has no proven exit")
        returned, memory = exits[0][0], exits[1]
        if returned and returned[0] == "stack" and returned[1] == frame:
            raise RuntimeError("counter helper returns dead stack storage")
        return returned, {address: value for address, value in memory.items() if address[0] != frame}


def native_owner_bound(graph, maps, *, expected_bound=512):
    proof = MemoryProof(graph, maps, strict=False, native_bound=expected_bound)
    proof.run(graph.only("p11_owner_start_aggregate"), [("key", 0), scalar(), None, None, None])
    if not proof.guards:
        raise RuntimeError(f"native aggregate constructor has no proven {expected_bound}-slot key guard")
    return proof


def transfer_controls():
    """Exercise the same footprint interpreter used for actual ELF bodies.

    These small controls protect joins, spills and call clobbers. They do
    not stand in for a compiled counter positive or the actual-byte mutants.
    """
    key = (1, 0)

    class Graph:
        def __init__(self, instructions, helpers=()):
            self.instructions = {key: dict(enumerate(instructions))}
            self.calls = {(key, pc): ("helper", helper) for pc, helper in helpers}
            self.loops = {key: {}}
            self.bodies = {key: ("transfer_control",)}

    maps = {"STATS": {"value_size": 24}, "COUNTER_HEALTH": {"value_size": 8}}
    pointer = ("ptr", "STATS", 0, 0, ZERO)
    exit_instruction = (0x95, 0, 0, 0)
    store = (0xdb, 0x27, 0, 0xf1)  # *(u64 *)r7 CAS r2

    def run(instructions, arguments=None, helpers=(), stats_size=24):
        proof_maps = {**maps, "STATS": {"value_size": stats_size}}
        proof = MemoryProof(Graph(instructions + [exit_instruction], helpers), proof_maps)
        proof.run(key, arguments or [pointer, ONE, scalar(), None, None])
        return proof

    report = {}

    def refuses(name, instructions, arguments=None, helpers=(), stats_size=24, message=None):
        try:
            run(instructions, arguments, helpers, stats_size)
        except RuntimeError as error:
            if message and message not in str(error):
                raise RuntimeError(f"wrong refusal for counter control {name}: {error}") from error
            report[name] = "refused"
        else:
            raise RuntimeError(f"counter transfer control accepted: {name}")

    # Full-width pointer copies and spills stay usable. A caller-saved
    # register is lost across a helper, while a saved register survives.
    for name, instructions, helpers in [
        ("ordinary_copy", [(0xbf, 0x17, 0, 0), store], ()),
        ("full_spill", [(0x7b, 0x1a, -8, 0), (0x79, 0xa7, -8, 0), store], ()),
        ("saved_call_copy", [(0xbf, 0x17, 0, 0), (0x85, 0, 0, 14),
                             (0xb7, 2, 0, 1), store], ((1, 14),)),
    ]:
        proof = run(instructions, helpers=helpers)
        if not any(touch[2:4] == ("STATS", "write") for touch in proof.touches):
            raise RuntimeError(f"counter transfer positive did not write STATS: {name}")
        report[name] = "accepted"
    for offset in (8, 16, 32):
        refuses(f"movsx{offset}_copy", [(0xbf, 0x17, offset, 0), store])
    refuses("mov32_copy", [(0xbc, 0x17, 0, 0), store])
    refuses("unknown_destination", [(0xb7, 7, 0, 0), store])
    refuses("partial_spill", [(0x7b, 0x1a, -8, 0), (0x62, 10, -4, 0),
                              (0x79, 0xa7, -8, 0), store])
    refuses("caller_saved_clobber", [(0xbf, 0x12, 0, 0), (0x85, 0, 0, 14),
                                     (0xbf, 0x27, 0, 0), store], helpers=((1, 14),))
    refuses("unknown_call", [(0x85, 0, 0, 999)], helpers=((0, 999),))
    refuses("mixed_pointer_join", [(0x15, 3, 2, 0), (0xbf, 0x17, 0, 0),
                                   (0x05, 0, 1, 0), (0xb7, 7, 0, 0), store])
    for disposition in (0, 1):
        arguments = [("ptr", "COUNTER_HEALTH", 0, 0, constant(disposition)),
                     None, None, None, None]
        proof = run([(0x7a, 1, 0, 1)], arguments)
        if not proof.health:
            raise RuntimeError("counter health positive has no actual sticky store")
        report[f"health_one_{disposition}"] = "accepted"
        refuses(f"health_zero_{disposition}", [(0x7a, 1, 0, 0)], arguments)
    refuses("health_unknown_key", [(0x7a, 1, 0, 1)],
            [("ptr", "COUNTER_HEALTH", 0, 0, scalar()), None, None, None, None])
    refuses("cumulative_delete", [(0x85, 0, 0, 3)],
            [("map", "STATS"), None, None, None, None], ((0, 3),))

    def histogram_positive(name, instructions, index):
        proof = run(instructions, [pointer, index, None, None, None], stats_size=296)
        reads = [touch for touch in proof.touches if touch[2:4] == ("STATS", "read")]
        if not reads or any(touch[4][0] < 40 or touch[4][1] > 288 for touch in reads):
            raise RuntimeError(f"counter control did not prove a real bounded bucket read: {name}")
        report[name] = "accepted"

    # Equality index32 is feasible on JLE-taken and JLT-fallthrough. Losing
    # it makes a real 8-byte read at STATS+296 disappear from the proof.
    le_read = [(0xbf, 0x17, 0, 0), (0xb5, 2, 1, 32), exit_instruction,
               (0x67, 2, 0, 3), (0x0f, 0x27, 0, 0),
               (0x07, 7, 0, 40), (0x79, 0x70, 0, 0)]
    lt_read = [(0xbf, 0x17, 0, 0), (0xa5, 2, 4, 32),
               (0x67, 2, 0, 3), (0x0f, 0x27, 0, 0),
               (0x07, 7, 0, 40), (0x79, 0x70, 0, 0)]
    refuses("le_equality32_oob", le_read, [pointer, scalar(0, 32), None, None, None],
            stats_size=296, message="out-of-bounds STATS read")
    refuses("lt_fallthrough_equality32_oob", lt_read,
            [pointer, scalar(31, 32), None, None, None],
            stats_size=296, message="out-of-bounds STATS read")
    histogram_positive("le_healthy_index31", le_read, constant(31))
    lt_healthy = list(lt_read)
    lt_healthy[1] = (0xa5, 2, 4, 31)
    histogram_positive("lt_healthy_index31", lt_healthy, constant(31))

    # This is the emitted constant-left JGT/clamp/shift/pointer shape, with
    # an initially opaque full-width index. A JMP32 guard cannot constrain
    # its high half; a separately bounded 32-bit input can use that guard.
    clamp = [(0xbf, 0x17, 0, 0), (0xb7, 1, 0, 31), (0x2d, 0x21, 1, 0),
             (0xb7, 2, 0, 31), (0x67, 2, 0, 3), (0x0f, 0x27, 0, 0),
             (0x07, 7, 0, 40), (0x79, 0x70, 0, 0)]
    histogram_positive("constant_left_clamp64", clamp, scalar())
    clamp32 = list(clamp)
    clamp32[2] = (0x2e, 0x21, 1, 0)
    histogram_positive("constant_left_clamp32_bounded", clamp32, scalar(0, 0xffffffff))
    refuses("constant_left_clamp32_high_alias", clamp32,
            [pointer, constant(1 << 32), None, None, None],
            stats_size=296, message="out-of-bounds STATS read")
    for name, at, instruction in [
        ("histogram_guard_direction", 2, (0xad, 0x21, 1, 0)),
        ("histogram_index32", 3, (0xb7, 2, 0, 32)),
        ("histogram_stride16", 4, (0x67, 2, 0, 4)),
    ]:
        damaged = list(clamp)
        damaged[at] = instruction
        refuses(name, damaged, [pointer, scalar(), None, None, None],
                stats_size=296, message="out-of-bounds STATS read")

    for name, operation, taken, wanted in [
        ("unsigned_gt_taken", 0x20, True, (33, 63)),
        ("unsigned_gt_untaken", 0x20, False, (0, 32)),
        ("unsigned_ge_taken", 0x30, True, (32, 63)),
        ("unsigned_ge_untaken", 0x30, False, (0, 31)),
        ("unsigned_lt_taken", 0xa0, True, (0, 31)),
        ("unsigned_lt_untaken", 0xa0, False, (32, 63)),
        ("unsigned_le_taken", 0xb0, True, (0, 32)),
        ("unsigned_le_untaken", 0xb0, False, (33, 63)),
    ]:
        registers = [scalar(0, 63)]
        if (not MemoryProof.refine(registers, 0, registers[0], 32, operation, taken)
                or registers[0][2:] != wanted):
            raise RuntimeError(f"wrong unsigned comparison boundary: {name}")
        report[name] = "accepted"
    for bound, operation, taken, wanted in [
        (0, 0x20, True, (1, U64_MAX)), (0, 0x20, False, (0, 0)),
        (0, 0x30, True, (0, U64_MAX)), (0, 0x30, False, None),
        (0, 0xa0, True, None), (0, 0xa0, False, (0, U64_MAX)),
        (0, 0xb0, True, (0, 0)), (0, 0xb0, False, (1, U64_MAX)),
        (U64_MAX, 0x20, True, None), (U64_MAX, 0x20, False, (0, U64_MAX)),
        (U64_MAX, 0x30, True, (U64_MAX, U64_MAX)),
        (U64_MAX, 0x30, False, (0, U64_MAX - 1)),
        (U64_MAX, 0xa0, True, (0, U64_MAX - 1)),
        (U64_MAX, 0xa0, False, (U64_MAX, U64_MAX)),
        (U64_MAX, 0xb0, True, (0, U64_MAX)), (U64_MAX, 0xb0, False, None),
    ]:
        registers = [scalar()]
        before = list(registers)
        feasible = MemoryProof.refine(registers, 0, registers[0], bound, operation, taken)
        if ((wanted is None and (feasible or registers != before))
                or (wanted is not None and (not feasible or registers[0][2:] != wanted))):
            raise RuntimeError("wrong zero/MAX/empty unsigned comparison intersection")
    report["unsigned_zero_max_empty_intersections"] = "accepted"
    return report


def validate_counter_owner_helpers(elf):
    MAPS.validate_private_helpers(
        elf, "p11_owner_", COUNTER_OWNER_HELPERS,
        MAPS.OPTIONAL_LOCAL_OWNER_HELPERS, "counter owner",
        MAPS.REQUIRED_GLOBAL_OWNER_HELPERS, "OWNER_CTL")


def validate(body, mode):
    if mode not in STATS_BYTES:
        raise RuntimeError("unknown counter mode")
    graph = CallGraph(body)
    maps, expected = counter_maps(graph, mode)
    if any(name.startswith((".rodata", ".data", ".bss")) for name in graph.elf.sections):
        raise RuntimeError("counter artifact carries global data")
    validate_counter_owner_helpers(graph.elf)
    MAPS.validate_exec_helpers(graph.elf)
    MAPS.validate_classic_uprobe_kernel_stack(graph.elf)
    btf = MAPS.Btf(graph.elf.sections[".BTF"][1])
    functions = [node for node in btf.types[1:] if node[0] == 12]
    if not functions or any(btf.types[node[2]][0] != 13 or btf.types[node[2]][3] > 5
                            for node in functions):
        raise RuntimeError("counter artifact exceeds the five-register BPF function ABI")
    unexpected = [symbol[0] for symbol in graph.bodies.values()
                  if symbol[0].startswith("p11_entry_") and symbol[1] == 0x12]
    if unexpected:
        raise RuntimeError("fixed counter artifact carries unsupported diagnostic entry roots")
    owner = native_owner_bound(graph, maps)
    report, proofs = {}, {}
    frames = dict(owner.frames)
    for name, section in ROOTS.items():
        root = graph.root(name, section)
        reached = graph.reachable(root)
        names = {graph.bodies[key][0] for key in reached}
        required = ({"p11_owner_start_aggregate"} if name == "p11_entry" else
                    {"p11_owner_start_get", "p11_owner_start_remove"})
        if not required <= names:
            raise RuntimeError(f"{name}: missing matched START custody {sorted(required - names)}")
        calls = [(key, pc, target) for (key, pc), (kind, target) in graph.calls.items()
                 if key in reached and kind == "helper"]
        clocks = [(graph.bodies[key][0], pc) for key, pc, helper in calls if helper == 5]
        if (mode == "counts") != (not clocks):
            raise RuntimeError(f"{name}: wrong reachable clock work for {mode}")
        for _, _, helper in calls:
            if helper in FORBIDDEN_HELPERS or helper not in ALLOWED_HELPERS:
                raise RuntimeError(f"{name}: forbidden/unknown endpoint helper {helper}")
        for key in reached:
            for pc, instruction in graph.instructions[key].items():
                if (instruction[0] == 0x18
                        and graph.map_at(key, pc) in FORBIDDEN_ENDPOINT_MAPS):
                    raise RuntimeError("counter endpoint reaches semantic/event storage")
        proof = MemoryProof(graph, maps)
        proof.run(root, [("external", "ctx", 0), None, None, None, None])
        proofs[name] = proof
        frames.update({key: max(frames.get(key, 0), depth) for key, depth in proof.frames.items()})
        stats = [touch for touch in proof.touches if touch[2] == "STATS"]
        writes = [touch for touch in stats if touch[3] == "write"]
        required_fields = [0] if name == "p11_entry" else [8, 16]
        if name == "p11_return" and mode != "counts":
            required_fields += [24, 32]
        for field in required_fields:
            if not any(touch[4] == (field, field) for touch in writes):
                raise RuntimeError(f"{name}: no proven CAS update of STATS field {field}")
        histogram = any(touch[4][1] + touch[5] > 40 for touch in stats)
        histogram_write = any(touch[4][0] >= 40 for touch in writes)
        wants_histogram = mode == "latency" and name == "p11_return"
        if histogram != wants_histogram or histogram_write != wants_histogram:
            raise RuntimeError(f"{name}: wrong reachable histogram memory work for {mode}")
        dispositions = {index for _, _, low, high in proof.health for index in range(low, high + 1)}
        if dispositions != {0, 1}:
            raise RuntimeError(f"{name}: missing saturated/contended sticky health writes")
        report[name] = {
            "functions": sorted(names),
            "clocks": clocks,
            "histogram_work": histogram,
            "stats_memory_operations": len(stats),
            "health_writers": len(proof.health),
        }
    chains = {}
    text = graph.elf.indices[".text"]
    for key, symbol in graph.bodies.items():
        if symbol[3] != text:
            chains[symbol[0]] = frame_and_chain(graph, key, frames)
    result = {
        "schema": SCHEMA,
        "mode": mode,
        "native_owner_slot_bound": owner.native_bound,
        "maps": {name: {field: maps[name][field] for field in
                         ("type", "key_size", "value_size", "max_entries")}
                 for name in expected},
        "payload_per_possible_cpu_bytes": {
            "STATS": maps["STATS"]["max_entries"] * maps["STATS"]["value_size"],
            "RV_COUNTS": maps["RV_COUNTS"]["max_entries"] * 8,
            "COUNTER_HEALTH": maps["COUNTER_HEALTH"]["max_entries"] * 8,
        },
        "endpoint_timing": report,
        "stack_chains": chains,
    }
    return result, (graph, maps, owner, proofs)


def mutated_instruction(body, graph, key, pc, replacement):
    changed = bytearray(body)
    struct.pack_into("<BBhi", changed, graph.file_offset(key, pc), *replacement)
    if changed == body:
        raise RuntimeError("causal counter mutation did not change actual bytes")
    return bytes(changed)


def map_mutant(body, graph, name, field, value):
    symbols = [symbol for symbol in graph.elf.symbols if symbol[0] == name
               and symbol[1] & 15 == 1 and symbol[3] == graph.elf.indices["maps"]]
    if len(symbols) != 1 or field not in MAPS.MAP_FIELDS:
        raise RuntimeError("counter map mutant has no exact map/field")
    changed = bytearray(body)
    address = graph.elf.sections["maps"][0][4] + symbols[0][4] + MAPS.MAP_FIELDS.index(field) * 4
    struct.pack_into("<I", changed, address, value)
    if changed == body:
        raise RuntimeError("counter map mutant did not change bytes")
    return bytes(changed)


def owner_linkage_mutant(body, graph):
    aggregate = [index for index, symbol in enumerate(graph.elf.symbols)
                 if symbol[0] == "p11_owner_start_aggregate"]
    if len(aggregate) != 1:
        raise RuntimeError("counter owner-linkage mutant has no exact aggregate helper")
    changed = bytearray(body)
    # LOCAL pointer-taking native boundary must never become a GLOBAL
    # independently verified subprogram. Change the actual ELF st_info.
    changed[graph.elf.sections[".symtab"][0][4] + aggregate[0] * 24 + 4] = 0x12
    if changed == body:
        raise RuntimeError("counter owner-linkage mutant did not change actual bytes")
    return bytes(changed)


def histogram_index_mutants(body, graph, histogram_keys):
    matches = []
    for key in histogram_keys:
        instructions = graph.instructions[key]
        for pc, (op, encoded, offset, immediate) in instructions.items():
            if op != 0x2d or offset != 1 or immediate:
                continue
            threshold, index = encoded & 15, encoded >> 4
            clamp = instructions.get(pc + 1)
            shift = instructions.get(pc + 2)
            pointer_add = instructions.get(pc + 3)
            if (instructions.get(pc - 1) != (0xb7, threshold, 0, 31)
                    or clamp != (0xb7, index, 0, 31)
                    or shift != (0x67, index, 0, 3)
                    or not pointer_add or pointer_add[0] != 0x0f
                    or pointer_add[1] >> 4 != index):
                continue
            pointer = pointer_add[1] & 15
            if (pointer_add[2:] != (0, 0)
                    or instructions.get(pc + 5) != (0x07, pointer, 0, 40)):
                continue
            matches.append((key, pc, index))
    if len(matches) != 1:
        raise RuntimeError("histogram mutants require one actual checked clamp/index chain")
    key, pc, index = matches[0]
    op, encoded, offset, immediate = graph.instructions[key][pc]
    return {
        "histogram_guard_direction": mutated_instruction(
            body, graph, key, pc, (0xad, encoded, offset, immediate)),
        "histogram_index32": mutated_instruction(body, graph, key, pc + 1, (0xb7, index, 0, 32)),
        "histogram_stride16": mutated_instruction(body, graph, key, pc + 2, (0x67, index, 0, 4)),
    }


def causal_mutants(body, mode):
    controls = transfer_controls()
    _, (graph, _, owner, proofs) = validate(body, mode)
    mutants = {}
    for label, name, field, value in [
        ("stats_value_size", "STATS", "value_size", STATS_BYTES[mode] + 8),
        ("stats_endpoint_limit", "STATS", "max_entries", 513),
        ("rv_key_size", "RV_COUNTS", "key_size", 8),
        ("rv_capacity", "RV_COUNTS", "max_entries", 4097),
        ("health_value_size", "COUNTER_HEALTH", "value_size", 16),
        ("health_capacity", "COUNTER_HEALTH", "max_entries", 3),
        ("start_capacity", "START", "max_entries", 16385),
    ]:
        mutants[label] = map_mutant(body, graph, name, field, value)
    key, pc, kind, immediate = sorted(owner.guards)[0]
    if kind != "immediate":
        raise RuntimeError("actual shifted owner guard needs its own causal mutator")
    instruction = graph.instructions[key][pc]
    mutants["native_owner_slot_bound"] = mutated_instruction(
        body, graph, key, pc, instruction[:3] + (immediate - 1,))
    mutants["owner_aggregate_linkage"] = owner_linkage_mutant(body, graph)

    for label, root_name, callee in [
        ("missing_start_entry", "p11_entry", "p11_owner_start_aggregate"),
        ("missing_start_return_get", "p11_return", "p11_owner_start_get"),
        ("missing_start_return_remove", "p11_return", "p11_owner_start_remove"),
    ]:
        reached = graph.reachable(graph.only(root_name))
        sites = [(key, pc) for (key, pc), (kind, target) in graph.calls.items()
                 if key in reached and kind == "function" and graph.bodies[target][0] == callee]
        if not sites:
            raise RuntimeError("matched START mutant has no actual call")
        changed = body
        for key, pc in sites:
            changed = mutated_instruction(changed, graph, key, pc, (0xb7, 0, 0, 0))
        mutants[label] = changed
    entry = graph.reachable(graph.only("p11_entry"))
    ordinary_helper = next(((key, pc) for (key, pc), (kind, number) in graph.calls.items()
                            if key in entry and kind == "helper" and number in (14, 174)), None)
    if ordinary_helper is None:
        raise RuntimeError("privacy/clock mutants have no actual ordinary helper")
    for label, helper in (("semantic_helper", 112), ("event_helper", 131)):
        mutants[label] = mutated_instruction(body, graph, *ordinary_helper, (0x85, 0, 0, helper))
    if mode == "counts":
        mutants["endpoint_clock"] = mutated_instruction(body, graph, *ordinary_helper, (0x85, 0, 0, 5))
    else:
        changed, count = body, 0
        for (key, pc), (kind, helper) in graph.calls.items():
            if key in entry and kind == "helper" and helper == 5:
                changed = mutated_instruction(changed, graph, key, pc, (0xb7, 0, 0, 0))
                count += 1
        if not count:
            raise RuntimeError("clock-removal mutant has no actual clock")
        mutants["missing_clock"] = changed
    pseudo = next(((key, pc) for (key, pc), (kind, _) in graph.calls.items()
                   if key in entry and kind == "function"), None)
    if pseudo is None:
        raise RuntimeError("unknown-call mutant has no actual BPF call")
    instruction = graph.instructions[pseudo[0]][pseudo[1]]
    mutants["unknown_call"] = mutated_instruction(body, graph, *pseudo, (0x85, 0x20, 0, instruction[3]))

    reads = sorted(touch for proof in proofs.values() for touch in proof.touches
                   if touch[2:4] == ("STATS", "read"))
    if not reads:
        raise RuntimeError("STATS footprint mutants have no actual load")
    key, pc = reads[0][:2]
    op, encoded, _, immediate = graph.instructions[key][pc]
    mutants["stats_out_of_bounds"] = mutated_instruction(
        body, graph, key, pc, (op, encoded, STATS_BYTES[mode] + 8, immediate))
    if mode == "latency":
        # A CFG site can be visited under several ranges. Mutate physical
        # instructions once, while removing every distinct bucket writer.
        histogram = sorted({touch[:2] for proof in proofs.values() for touch in proof.touches
                            if touch[2:4] == ("STATS", "write") and touch[4][0] >= 40})
        if not histogram:
            raise RuntimeError("histogram-removal mutant has no actual bucket update")
        changed = body
        for key, pc in histogram:
            changed = mutated_instruction(changed, graph, key, pc, (0xbf, 0, 0, 0))
        mutants["missing_histogram_write"] = changed
        histogram_keys = {touch[0] for touch in proofs["p11_return"].touches
                          if touch[2:4] == ("STATS", "read") and touch[4][1] + touch[5] > 40}
        mutants.update(histogram_index_mutants(body, graph, histogram_keys))
    else:
        mutants["histogram_access"] = mutated_instruction(body, graph, key, pc, (op, encoded, 40, immediate))
    health = sorted(site for proof in proofs.values() for site in proof.health)
    for label, disposition in (("health_saturated_writer", 0), ("health_contended_writer", 1)):
        sites = [site for site in health if site[2] <= disposition <= site[3]]
        if not sites:
            raise RuntimeError("health writer mutant has no actual disposition")
        # Prefer a separate emitted writer when available. A compiler may
        # share the sticky-one store for both finite keys; changing that real
        # store invalidates both dispositions, not an invented second site.
        key, pc, _, _ = min(sites, key=lambda item: item[3] - item[2])
        _, encoded, offset, _ = graph.instructions[key][pc]
        mutants[label] = mutated_instruction(body, graph, key, pc, (0x7a, encoded & 15, offset, 0))
    report = {}
    for label, changed in mutants.items():
        try:
            validate(changed, mode)
        except (RuntimeError, struct.error):
            report[label] = "refused"
        else:
            raise RuntimeError(f"actual causal mutant accepted: {label}")
    return {"schema": SCHEMA, "mode": mode, "mutants": report,
            "transfer_controls": controls}


class BankFootprint(MemoryProof):
    """Existing conservative memory proof with one exact map-of-maps edge."""

    @staticmethod
    def refine(registers, destination, left, immediate, operation, taken):
        known = singleton(left)
        if known is not None and immediate is not None and operation in (0x10, 0x50):
            condition = known == immediate if operation == 0x10 else known != immediate
            if taken != condition:
                return False
        return MemoryProof.refine(registers, destination, left, immediate, operation, taken)

    def helper(self, number, registers, memory, key, pc):
        mapped = registers[1]
        if number == 1 and mapped and mapped[:2] == ("ptr", "COUNTER_BANKS"):
            if mapped[2:4] != (0, 0):
                raise RuntimeError("inner lookup uses an adjusted outer-map pointer")
            if self.key_value(registers[2], memory) != ZERO:
                raise RuntimeError("bank inner lookup does not use its only cell zero")
            registers[1] = "map", "COUNTER_BANK_VALUE"
        elif number in (2, 3) and mapped and mapped[:2] in {
                ("map", name) for name in
                ("COUNTER_BANKS", "COUNTER_BANK_META", "COUNTER_BANK_COMMIT", "COUNTER_BANK_VALUE")}:
            raise RuntimeError("endpoint mutates an immutable bank route")
        super().helper(number, registers, memory, key, pc)

    def touch(self, pointer, offset, width, action, value, key, pc, atomic=None):
        name = pointer[1]
        if name == "COUNTER_BANKS":
            raise RuntimeError("endpoint dereferences outer map as a value")
        if name == "COUNTER_BANK_VALUE":
            span = pointer[2] + offset, pointer[3] + offset
            if width != 8 or span[0] != span[1] or span[0] not in (0, 8, 16):
                raise RuntimeError("bank Counts access is not an exact full-width field")
            if action == "write" and atomic != 0xf1:
                raise RuntimeError("bank Counts update is not bounded CAS")
        if (name == "START" and action == "write"
                and pointer[2] + offset < 8 and pointer[3] + offset + width > 0):
            if (pointer[2] + offset or pointer[3] + offset or width != 8
                    or value != ZERO or atomic is not None):
                raise RuntimeError("Counts START timestamp is not one full zero word")
        if name == "COUNTER_BANK_FAULT" and action == "write":
            if (width != 8 or pointer[2] + offset or pointer[3] + offset
                    or atomic not in (0x40, 0x41) or not value or value[0] != "scalar"
                    or not 1 <= value[2] <= value[3] <= 15):
                raise RuntimeError("bank routing fault is not a finite sticky OR")
        if name in ("COUNTER_BANK_META", "COUNTER_BANK_COMMIT") and action == "write":
            raise RuntimeError("endpoint writes immutable bank metadata")
        super().touch(pointer, offset, width, action, value, key, pc, atomic)


class BankExecution:
    """Finite causal executions of actual emitted scalar bridge instructions.

    The unchanged owner APIs use their existing custody contract. Explicit
    failure inputs supply map-I/O errors and intervening cumulative writers.
    This does not replace native owner tests, verifier loading or the later
    real held-START/publication transaction test. Bank branch, memory, CAS,
    RV and fault operations execute the actual ELF.
    """

    def __init__(self, graph, *, optimized_optional_get=False, optimized_aggregate=False):
        self.graph = graph
        self.optimized_optional_get = optimized_optional_get
        self.optimized_aggregate = optimized_aggregate
        self.native_get_probe = None
        self.memory, self.regions, self.cells = {}, [], {}
        self.cursor = 0x1000000
        names = ("COUNTER_BANK_META", "COUNTER_BANK_COMMIT", "COUNTER_BANKS",
                 "COUNTER_BANK_FAULT", "COUNTER_HEALTH", "RV_COUNTS", "bank0", "bank1")
        self.handles = {name: 0x10000 + index * 0x100 for index, name in enumerate(names)}
        self.by_handle = {value: name for name, value in self.handles.items()}
        self.starts, self.debt = {}, 0
        self.failed_admission = False
        self.failed_retirement = False
        self.failed_rv_insert = False
        self.contended, self.cas_attempts = set(), {}
        self.trace, self.steps = [], 0
        self.last_read = None
        self.bank_storage = {}
        for slot in (0, 1):
            self.set("COUNTER_BANK_META", slot, struct.pack("<QQII", slot + 1, 1 << slot, slot, 1))
            self.set("COUNTER_BANK_COMMIT", slot + 1, struct.pack("<QQ", 1 << slot, BANK_CONFIG))
            self.set("COUNTER_BANKS", slot, self.handles[f"bank{slot}"].to_bytes(8, "little"))
            self.bank_storage[slot] = self.set(f"bank{slot}", 0, bytes(24))
        self.set("COUNTER_BANK_FAULT", 0, bytes(8))
        for index in (0, 1):
            self.set("COUNTER_HEALTH", index, bytes(8))

    @staticmethod
    def key(name, key):
        if isinstance(key, bytes):
            return key
        return key.to_bytes(8 if name == "COUNTER_BANK_COMMIT" else 4, "little")

    def set(self, name, key, body):
        key = self.key(name, key)
        address = self.cursor
        self.cursor += max(0x1000, len(body))
        self.regions.append((address, len(body), name, key))
        self.cells[name, key] = address
        for offset, byte in enumerate(body):
            self.memory[address + offset] = byte
        return address

    def delete(self, name, key):
        self.cells.pop((name, self.key(name, key)), None)

    def row(self, slot):
        # Retain the fixture's original backing to assert no credit even
        # when a causal control makes lookup of that cell unavailable.
        at = self.bank_storage[slot]
        return tuple(self.read(at + offset, 8) for offset in (0, 8, 16))

    def fault(self):
        return self.read(self.cells["COUNTER_BANK_FAULT", bytes(4)], 8)

    def health(self, index):
        return self.read(self.cells["COUNTER_HEALTH", index.to_bytes(4, "little")], 8)

    def start(self, slot, marker=0):
        key = struct.pack("<QII", 9, slot, 0)
        body = bytearray(288)
        struct.pack_into("<Q", body, 264, marker)
        self.starts[key] = self.set("START", key, body)
        self.debt += 1

    def region(self, address, width):
        return next((item for item in self.regions
                     if item[0] <= address and address + width <= item[0] + item[1]), None)

    def read(self, address, width):
        if any(address + index not in self.memory for index in range(width)):
            raise RuntimeError("bank execution reads unknown/out-of-bounds storage")
        return int.from_bytes(bytes(self.memory[address + index] for index in range(width)), "little")

    def write(self, address, width, value, atomic, key, pc, stack):
        region = self.region(address, width)
        if region:
            base, _, name, _ = region
            if name in ("bank0", "bank1", "RV_COUNTS") and (width != 8 or atomic != 0xf1):
                raise RuntimeError("bank execution writes a cumulative cell without u64 CAS")
            if name == "COUNTER_BANK_FAULT" and (width != 8 or atomic not in (0x40, 0x41)
                                                 or not 1 <= value <= 15):
                raise RuntimeError("bank execution has an invalid sticky routing fault")
            if name == "COUNTER_HEALTH" and (width != 8 or atomic is not None or value != 1):
                raise RuntimeError("bank execution clears/changes sticky counter health")
            if name not in ("bank0", "bank1", "RV_COUNTS", "COUNTER_BANK_FAULT", "COUNTER_HEALTH"):
                raise RuntimeError("bank execution writes readonly/custody storage directly")
            self.trace.append(("write", key, pc, name, address - base, value))
        elif not stack - 512 <= address <= stack - width:
            raise RuntimeError("bank execution writes outside its own bounded stack")
        else:
            self.trace.append(("stack_write", key, pc, address, width, value))
        for index, byte in enumerate((value & ((1 << (width * 8)) - 1)).to_bytes(width, "little")):
            self.memory[address + index] = byte

    def owner(self, name, registers, origins, key, pc):
        raw_key = self.read(registers[1], 16).to_bytes(16, "little")
        pid, slot, pad = struct.unpack("<QII", raw_key)
        if pid != 9 or slot >= 512 or pad:
            raise RuntimeError("bank owner call lost original physical START key")
        self.trace.append(("owner", key, pc, name, tuple(registers[1:6]), tuple(origins)))
        if name == "p11_owner_start_aggregate":
            if registers[2] != 0 and not self.optimized_aggregate:
                raise RuntimeError("Counts START acquires a nonzero timestamp")
            if self.failed_admission:
                return 0
            if raw_key in self.starts:
                raise RuntimeError("bank execution attempts duplicate START admission")
            self.start(slot)
            return 1
        if name == "p11_owner_start_get":
            if registers[2] != 0 and not self.optimized_optional_get:
                raise RuntimeError("bank return requires START instead of optional non-settlement lookup")
            return self.starts.get(raw_key, 0)
        if name == "p11_owner_start_remove":
            if registers[2] != 1:
                raise RuntimeError("bank return does not require retirement of observed START")
            if self.failed_retirement:
                return U64_MAX
            if raw_key not in self.starts:
                raise RuntimeError("bank return attempts to settle an absent START")
            address = self.starts[raw_key]
            for index in range(288):
                self.memory.pop(address + index, None)
            del self.starts[raw_key]
            self.debt -= 1
            return 0
        raise RuntimeError("bank execution calls an unsupported owner API")

    def helper(self, number, registers, key, pc):
        if self.native_get_probe is not None:
            if key != self.native_get_probe:
                raise RuntimeError("native absence probe escapes its exact START getter")
            if number == 158:
                return 0x40000  # one present task; no task-storage owner
            name = self.by_handle.get(registers[1])
            if number == 156:
                if name != "THREAD_OWNER" or registers[2:5] != [0x40000, 0, 0]:
                    raise RuntimeError("native absence probe changes task-storage lookup")
                return 0
            if number != 1 or name not in ("OWNER_CTL", "START"):
                raise RuntimeError("native absence probe reaches an unexpected helper/map")
            width = 16 if name == "START" else 4
            index = self.read(registers[2], width).to_bytes(width, "little")
            expected = struct.pack("<QII", 9, 0, 0) if name == "START" else bytes(4)
            if index != expected:
                raise RuntimeError("native absence probe loses its exact physical key")
            self.trace.append(("lookup", key, pc, name, index, registers[2]))
            return self.cells.get((name, index), 0)
        if number not in (1, 2):
            raise RuntimeError("bank bridge reaches an unknown/privacy/clock helper")
        name = self.by_handle.get(registers[1])
        if name is None:
            raise RuntimeError("bank lookup loses its exact outer/inner map handle")
        width = 16 if name == "RV_COUNTS" else 8 if name == "COUNTER_BANK_COMMIT" else 4
        index = self.read(registers[2], width).to_bytes(width, "little")
        self.trace.append(("lookup" if number == 1 else "insert", key, pc, name, index, registers[2]))
        if number == 2:
            if name != "RV_COUNTS" or registers[4] != 1 or self.read(registers[3], 8) != 1:
                raise RuntimeError("bank bridge replaces/inserts an unowned cumulative value")
            if self.failed_rv_insert:
                return (1 << 64) - 7
            if (name, index) in self.cells:
                return (1 << 64) - 17
            self.set(name, index, (1).to_bytes(8, "little"))
            return 0
        address = self.cells.get((name, index), 0)
        return self.read(address, 8) if address and name == "COUNTER_BANKS" else address

    def run(self, name, arguments):
        key = self.graph.only(name)
        result = self.execute(key, list(arguments), 0)
        if result:
            raise RuntimeError("bank bridge did not return scalar zero")

    def execute(self, key, arguments, depth):
        if depth >= 8:
            raise RuntimeError("bank execution call depth exceeds ABI")
        registers, origins = [0] * 11, [None] * 11
        registers[1:1 + len(arguments)] = arguments
        stack = registers[10] = 0x80000000 + depth * 0x10000
        for address in range(stack - 512, stack):
            self.memory.pop(address, None)
        pc = 0
        instructions = self.graph.instructions[key]
        while pc in instructions:
            self.steps += 1
            if self.steps > 20000:
                raise RuntimeError("bank execution exceeds finite instruction budget")
            op, encoded, offset, immediate = instructions[pc]
            dst, src = encoded & 15, encoded >> 4
            if dst > 10 or src > 10:
                raise RuntimeError("invalid bank execution register")
            next_pc = pc + 1
            if op == 0x18:
                mapped = self.graph.map_at(key, pc)
                if mapped:
                    if mapped not in self.handles:
                        raise RuntimeError("bank bridge references unexpected map")
                    registers[dst] = self.handles[mapped]
                else:
                    high = struct.unpack_from("<I", self.graph.sections[key[0]][1], key[1] + pc * 8 + 12)[0]
                    registers[dst] = high << 32 | immediate & 0xffffffff
                origins[dst] = (key, pc)
                next_pc += 1
            elif op == 0x85:
                kind, target = self.graph.calls[key, pc]
                if kind == "helper":
                    returned = self.helper(target, registers, key, pc)
                else:
                    callee = self.graph.bodies[target][0]
                    returned = (self.owner(callee, registers, origins, key, pc)
                                if callee.startswith("p11_owner_") else
                                self.execute(target, registers[1:6], depth + 1))
                registers[:6] = [returned] + [0xbad0000000000000] * 5
                origins[:6] = [(key, pc)] + [None] * 5
            elif op == 0x95:
                return registers[0]
            elif op & 7 == 1 and op & 0xe0 == 0x60:
                width, address = WIDTHS[op & 0x18], registers[src] + offset
                registers[dst] = self.read(address, width)
                origins[dst] = (key, pc)
                region = self.region(address, width)
                self.last_read = (region[2], address - region[0]) if region else None
                self.trace.append(("read", key, pc, self.last_read, width))
            elif op & 7 in (2, 3) and op & 0xe0 in (0x60, 0xc0):
                width, address = WIDTHS[op & 0x18], registers[dst] + offset
                value = immediate & U64_MAX if op & 7 == 2 else registers[src]
                atomic = immediate if op & 0xe0 == 0xc0 else None
                if atomic == 0xf1:
                    before = self.read(address, width)
                    region = self.region(address, width)
                    name = region[2] if region else "stack"
                    self.cas_attempts[name] = self.cas_attempts.get(name, 0) + 1
                    if name in self.contended:
                        if before == U64_MAX:
                            raise RuntimeError("contention fixture cannot increment a saturated cell")
                        before += 1  # a real intervening cumulative update
                        for index, byte in enumerate(before.to_bytes(width, "little")):
                            self.memory[address + index] = byte
                    elif before == registers[0]:
                        self.write(address, width, value, atomic, key, pc, stack)
                    registers[0], origins[0] = before, (key, pc)
                elif atomic in (0x40, 0x41):
                    before = self.read(address, width)
                    self.write(address, width, value, atomic, key, pc, stack)
                    # write() validates the finite operand; OR preserves all
                    # prior fault bits rather than replacing their history.
                    for i, byte in enumerate((before | value).to_bytes(width, "little")):
                        self.memory[address + i] = byte
                    if atomic == 0x41:
                        registers[src], origins[src] = before, (key, pc)
                elif atomic is None:
                    self.write(address, width, value, None, key, pc, stack)
                else:
                    raise RuntimeError("unsupported bank execution atomic")
            elif op & 7 in (4, 7):
                bits, operation = (32 if op & 7 == 4 else 64), op & 0xf0
                mask = (1 << bits) - 1
                left = registers[dst] & mask
                right = (registers[src] if op & 8 else immediate) & mask
                if operation == 0xb0:
                    if offset:
                        raise RuntimeError("bank execution refuses sign-extending MOV")
                    value = right
                    origins[dst] = origins[src] if op & 8 else (key, pc)
                elif operation == 0x80:
                    value = -left
                    origins[dst] = (key, pc)
                elif operation == 0xc0:
                    signed = left - (1 << bits) if left >> (bits - 1) else left
                    value = signed >> (right & (bits - 1))
                    origins[dst] = (key, pc)
                else:
                    result = scalar_alu(constant(left), constant(right), operation, bits)
                    value = singleton(result)
                    if value is None:
                        raise RuntimeError("unsupported bank execution ALU")
                    origins[dst] = (key, pc)
                registers[dst] = value & mask
            elif op & 7 in (5, 6):
                operation = op & 0xf0
                if not operation:
                    next_pc = pc + 1 + (immediate if op == 0x06 else offset)
                else:
                    bits = 32 if op & 7 == 6 else 64
                    left, right = registers[dst], registers[src] if op & 8 else immediate & U64_MAX
                    left, right = left & ((1 << bits) - 1), right & ((1 << bits) - 1)
                    signed_left = left - (1 << bits) if left >> (bits - 1) else left
                    signed_right = right - (1 << bits) if right >> (bits - 1) else right
                    comparisons = {0x10: left == right, 0x50: left != right, 0x20: left > right,
                                   0x30: left >= right, 0x40: bool(left & right), 0xa0: left < right,
                                   0xb0: left <= right, 0x60: signed_left > signed_right,
                                   0x70: signed_left >= signed_right, 0xc0: signed_left < signed_right,
                                   0xd0: signed_left <= signed_right}
                    if operation not in comparisons:
                        raise RuntimeError("unsupported bank execution branch")
                    taken = comparisons[operation]
                    self.trace.append(("branch", key, pc, left, right, taken, self.last_read))
                    if taken:
                        next_pc = pc + 1 + offset
            else:
                raise RuntimeError(f"unsupported bank execution opcode {op:#x}")
            pc = next_pc
        raise RuntimeError("bank execution leaves its function")


def bank_erased_second_argument(graph, key):
    """Conservative entry-register kill before any read/control transfer."""
    for _, (op, encoded, _, _) in sorted(graph.instructions[key].items()):
        destination, source = encoded & 15, encoded >> 4
        if op == 0x18:
            overwritten = destination == 2
        elif op & 7 in (4, 7):
            if (op & 8 and source == 2) or (op & 0xf0 != 0xb0 and destination == 2):
                return False
            overwritten = destination == 2
        elif op & 7 == 1:
            if source == 2:
                return False
            overwritten = destination == 2
        elif op & 7 in (2, 3):
            if destination == 2 or (op & 7 == 3 and source == 2):
                return False
            overwritten = False
        else:
            # No branches/calls before this definite incoming-R2 kill.
            return False
        if overwritten:
            return True
    return False


def bank_optional_start_get(graph):
    """Bind a removed LOCAL argument to the actual optional-absence path.

    The source getter's required=0 can disappear under constant-argument
    optimization, while debug BTF keeps its source signature. Never infer
    that constant merely from an unused register: also execute the native
    healthy/no-owner absence path and forbid every custody/health write.
    Other native owner behavior still uses the unchanged consumed contract.
    """
    key = graph.only("p11_owner_start_get")
    if not bank_erased_second_argument(graph, key):
        return None
    vm = BankExecution(graph)
    vm.native_get_probe = key
    for name in ("OWNER_CTL", "THREAD_OWNER", "START"):
        handle = max(vm.by_handle) + 0x100
        vm.handles[name], vm.by_handle[handle] = handle, name
    control = struct.pack("<7Q", 16448, 0, 0, 0, 0, 0, 0)
    at = vm.set("OWNER_CTL", 0, control)
    start_key = vm.set("native_probe_key", 0, struct.pack("<QII", 9, 0, 0))
    returned = vm.execute(key, [start_key, 9, 0, 0, 0], 0)
    if (returned or vm.debt or vm.fault()
            or vm.read(at, 56).to_bytes(56, "little") != control):
        raise RuntimeError("optimized native START get does not preserve quiet absence")
    lookups = [event for event in vm.trace if event[0] == "lookup" and event[3] == "START"]
    if len(lookups) != 1:
        raise RuntimeError("optimized native START get has no exact preliminary lookup")
    return lookups[0][1:3]


def bank_scenarios(graph, optional_get, optimized_aggregate):
    """Literal healthy/failure expectations over actual native bridge bodies."""
    reports, executions = {}, []

    def new_vm():
        return BankExecution(graph, optimized_optional_get=optional_get is not None,
                             optimized_aggregate=optimized_aggregate)

    def check(name, vm, rows, debt, fault=0, rv=None):
        actual_rv = {}
        for (mapped, raw_key), address in vm.cells.items():
            if mapped == "RV_COUNTS":
                slot, pad, value = struct.unpack("<IIQ", raw_key)
                if pad:
                    raise RuntimeError("bank RV key has nonzero padding")
                actual_rv[slot, value] = vm.read(address, 8)
        if (tuple(vm.row(slot) for slot in (0, 1)) != rows or vm.debt != debt
                or vm.fault() != fault or len(vm.starts) > debt or actual_rv != (rv or {})):
            raise RuntimeError(f"actual bank scenario violates custody/counts: {name}")
        reports[name] = "accepted"
        executions.append(vm)

    zeros = ((0, 0, 0), (0, 0, 0))
    vm = new_vm()
    vm.delete("COUNTER_BANK_COMMIT", 1)
    vm.run("p11_bank_enter", (0, 9))
    check("inactive_entry", vm, zeros, 0)
    vm.set("COUNTER_BANK_COMMIT", 1, struct.pack("<QQ", 1, BANK_CONFIG))
    vm.run("p11_bank_complete", (0, 9, 0x100000001, 1))
    check("precommit_return_after_commit", vm, zeros, 0)
    vm = new_vm()
    vm.start(1)
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    check("absent_return_preserves_other_start", vm, zeros, 1)
    vm = new_vm()
    vm.start(0)
    vm.starts.clear()  # physical loss does not remove the owner's debt
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    check("absent_return_preserves_lost_debt", vm, zeros, 1)
    vm = new_vm()
    vm.delete("COUNTER_BANK_COMMIT", 2)
    vm.run("p11_bank_enter", (0, 9))
    vm.set("COUNTER_BANK_COMMIT", 2, struct.pack("<QQ", 2, BANK_CONFIG))
    vm.run("p11_bank_enter", (1, 9))
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    vm.run("p11_bank_complete", (1, 9, U64_MAX, 1))
    check("old_bank_keeps_original_transaction", vm, ((1, 1, 0), (1, 1, 1)), 0,
          rv={(0, 0): 1, (1, U64_MAX): 1})
    for slot in (0, 1):
        for missing in ("COUNTER_BANK_META", "COUNTER_BANKS", f"bank{slot}", "COUNTER_BANK_COMMIT"):
            vm = new_vm()
            vm.run("p11_bank_enter", (slot, 9))
            vm.delete(missing, slot if missing in ("COUNTER_BANK_META", "COUNTER_BANKS") else
                      slot + 1 if missing == "COUNTER_BANK_COMMIT" else 0)
            vm.run("p11_bank_complete", (slot, 9, 0, 1))
            rows = ((1, 0, 0), (0, 0, 0)) if slot == 0 else ((0, 0, 0), (1, 0, 0))
            check("missing_route_retires_start", vm, rows, 0, 1)
    vm = new_vm()
    vm.start(0)
    vm.failed_retirement = True
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    check("failed_retirement_keeps_debt", vm, zeros, 1, 2)
    for transaction in (0x100000001, U64_MAX):
        vm = new_vm()
        vm.set("COUNTER_BANK_META", 0, struct.pack("<QQII", transaction, 1, 0, 1))
        vm.set("COUNTER_BANK_COMMIT", transaction, struct.pack("<QQ", 1, BANK_CONFIG))
        vm.run("p11_bank_enter", (0, 9))
        vm.run("p11_bank_complete", (0, 9, transaction, 1))
        check("full_width_transaction", vm, ((1, 1, 1), (0, 0, 0)), 0, rv={(0, transaction): 1})
    for slot in (2, 0xffffffff):
        vm = new_vm()
        vm.run("p11_bank_enter", (slot, 9))
        check("invalid_logical_slot", vm, zeros, 0, 1)
    for mask, configuration in ((2, BANK_CONFIG), (1, BANK_CONFIG + 1), (3, BANK_CONFIG)):
        vm = new_vm()
        vm.set("COUNTER_BANK_COMMIT", 1, struct.pack("<QQ", mask, configuration))
        vm.run("p11_bank_enter", (0, 9))
        check("wrong_exact_set_or_config", vm, zeros, 0, 1)
    vm = new_vm()
    for slot in (0, 1):
        vm.set("COUNTER_BANK_META", slot, struct.pack("<QQII", 3, 3, slot, 1))
    vm.set("COUNTER_BANK_COMMIT", 3, struct.pack("<QQ", 3, BANK_CONFIG))
    for slot in (0, 1):
        vm.run("p11_bank_enter", (slot, 9))
        vm.run("p11_bank_complete", (slot, 9, 0, 1))
    check("complete_two_bank_union", vm, ((1, 1, 0), (1, 1, 0)), 0, rv={(0, 0): 1, (1, 0): 1})
    vm = new_vm()
    vm.run("p11_bank_enter", (0, 9))
    vm.run("p11_bank_complete", (0, 9, 0, 0))
    check("scope_refusal_retires_without_credit", vm, ((1, 0, 0), (0, 0, 0)), 0, 8)
    vm = new_vm()
    vm.run("p11_bank_enter", (1, 9))
    pointer = vm.starts[struct.pack("<QII", 9, 1, 0)]
    # CallStart.slot_id is neither a bank ID nor authoritative for Counts.
    for index, byte in enumerate(U64_MAX.to_bytes(8, "little")):
        vm.memory[pointer + 16 + index] = byte
    vm.run("p11_bank_complete", (1, 9, 0, 1))
    check("start_payload_does_not_route", vm, ((0, 0, 0), (1, 1, 0)), 0, rv={(1, 0): 1})
    vm = new_vm()
    vm.failed_admission = True
    vm.run("p11_bank_enter", (0, 9))
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    check("admission_failure_is_sticky", vm, ((1, 0, 0), (0, 0, 0)), 0, 2)
    vm = new_vm()
    for rv in (0x100000001, 0x100000001, U64_MAX):
        vm.run("p11_bank_enter", (0, 9))
        vm.run("p11_bank_complete", (0, 9, rv, 1))
    check("rv_full_width_accumulates", vm, ((3, 3, 3), (0, 0, 0)), 0,
          rv={(0, 0x100000001): 2, (0, U64_MAX): 1})
    vm = new_vm()
    vm.run("p11_bank_enter", (0, 9))
    vm.run("p11_bank_complete", (0, 9, 0x204, 1))
    check("pending_is_returned_without_error", vm, ((1, 1, 0), (0, 0, 0)), 0,
          rv={(0, 0x204): 1})
    vm = new_vm()
    vm.run("p11_bank_enter", (0, 9))
    vm.run("p11_bank_complete", (0, 9, 0x100000204, 1))
    check("pending_high_alias_is_full_width_error", vm, ((1, 1, 1), (0, 0, 0)), 0,
          rv={(0, 0x100000204): 1})
    vm = new_vm()
    vm.failed_rv_insert = True
    vm.run("p11_bank_enter", (0, 9))
    vm.run("p11_bank_complete", (0, 9, 0, 1))
    check("rv_failure_is_sticky", vm, ((1, 1, 0), (0, 0, 0)), 0, 4)
    vm = new_vm()
    vm.bank_storage[0] = vm.set("bank0", 0, struct.pack("<QQQ", U64_MAX, 0, 0))
    vm.run("p11_bank_enter", (0, 9))
    check("entered_saturates_without_wrap", vm, ((U64_MAX, 0, 0), (0, 0, 0)), 1)
    if vm.health(0) != 1 or vm.health(1):
        raise RuntimeError("actual bank saturation has wrong health disposition")
    vm = new_vm()
    vm.contended.add("bank0")
    vm.run("p11_bank_enter", (0, 9))
    check("bounded_contention_is_unhealthy", vm, ((8, 0, 0), (0, 0, 0)), 1)
    if vm.health(1) != 1 or vm.health(0) or vm.cas_attempts.get("bank0") != 8:
        raise RuntimeError("actual bank contention loses its eight-attempt/health bound")
    return reports, executions


def validate_bank_proof(body):
    graph = CallGraph(body)
    maps, expected = bank_maps(graph)
    if any(name.startswith((".rodata", ".data", ".bss")) for name in graph.elf.sections):
        raise RuntimeError("bank proof carries global data")
    validate_counter_owner_helpers(graph.elf)
    bank_global_abi(graph)
    owner = native_owner_bound(graph, maps, expected_bound=8192)
    proof_maps = {**maps, "COUNTER_BANK_VALUE": MAPS.map_def(6, 4, 24, 1)}
    roots, frames, seed_sites = {}, dict(owner.frames), set()
    for name, section in BANK_ROOTS.items():
        root = graph.root(name, section)
        reached = graph.reachable(root)
        names = {graph.bodies[key][0] for key in reached}
        required = ({"p11_bank_enter", "p11_owner_start_aggregate"} if name.endswith("entry") else
                    {"p11_bank_complete", "p11_owner_start_get", "p11_owner_start_remove"})
        if not required <= names:
            raise RuntimeError("bank proof root loses mandatory START/bridge work")
        calls = [target for (key, _), (kind, target) in graph.calls.items()
                 if key in reached and kind == "helper"]
        if any(helper == 5 or helper not in ALLOWED_HELPERS or helper in FORBIDDEN_HELPERS
               for helper in calls):
            raise RuntimeError("Counts bank root reaches clock/semantic/event/unknown helper")
        for key in reached:
            for pc, instruction in graph.instructions[key].items():
                if (instruction[0] == 0x18
                        and graph.map_at(key, pc) in FORBIDDEN_ENDPOINT_MAPS):
                    raise RuntimeError("Counts bank root reaches semantic/event storage")
        proof = BankFootprint(graph, proof_maps, native_bound=8192)
        proof.run(root, [("external", "ctx", 0), None, None, None, None])
        if name.endswith("entry"):
            seed_sites = {touch[:2] for touch in proof.touches
                          if touch[2:6] == ("START", "write", (0, 0), 8)}
            if not seed_sites:
                raise RuntimeError("Counts bank entry omits its zero START timestamp store")
        frames.update({key: max(frames.get(key, 0), depth) for key, depth in proof.frames.items()})
        required_offsets = (0,) if name.endswith("entry") else (8, 16)
        for offset in required_offsets:
            if not any(touch[2:5] == ("COUNTER_BANK_VALUE", "write", (offset, offset))
                       for touch in proof.touches):
                raise RuntimeError("bank proof omits a complete Counts field update")
        roots[name] = {"stack_chain": frame_and_chain(graph, root, frames),
                       "clocks": 0, "semantic_or_event_work": False}
    optional_get = bank_optional_start_get(graph)
    optimized_aggregate = bank_erased_second_argument(graph, graph.only("p11_owner_start_aggregate"))
    controls, executions = bank_scenarios(graph, optional_get, optimized_aggregate)
    try:
        validate(body, "counts")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("bank proof is accepted by the ordinary fixed counter profile")
    report = {"schema": "p11scope-counter-bank-object/v1", "logical_slots": [0, 1],
              "native_owner_slot_bound": owner.native_bound,
              "maps": {name: maps[name] for name in expected},
              "inner_template": maps["COUNTER_BANKS"]["inner_template"], "roots": roots,
              "controls": controls, "ordinary_counter_profile": "refused"}
    return report, (graph, executions, optional_get, seed_sites, owner)


def bank_btf_mutant(body, graph, name, field, wanted, *, inner=False):
    btf = MAPS.Btf(graph.elf.sections[".BTF"][1])
    variables = [node for node in btf.types[1:] if node[0] == 14 and node[1] == name]
    if len(variables) != 1:
        raise RuntimeError("bank mutant has no exact BTF map variable")
    node = btf.resolve(variables[0][2])
    if inner:
        values_ref = next(node[5][i + 1] for i in range(0, len(node[5]), 3)
                          if MAPS.string_at(btf.strings, node[5][i]) == "values")
        node = btf.resolve(btf.resolve(btf.resolve(values_ref)[5][0])[2])
    base = graph.elf.sections[".BTF"][0][4]
    if field == "value_bytes":
        value_ref = next(node[5][i + 1] for i in range(0, len(node[5]), 3)
                         if MAPS.string_at(btf.strings, node[5][i]) == "value")
        target = btf.resolve(btf.resolve(value_ref)[2])
        address, replacement = base + target[6] + 8, wanted
    else:
        member = next(i for i in range(node[3])
                      if MAPS.string_at(btf.strings, node[5][i * 3]) == field)
        # Select actual pointer-to-array constants directly, without trying
        # to resolve unrelated void/qualified-void pointers in this ELF.
        arrays = {ident for ident, candidate in enumerate(btf.types[1:], 1)
                  if candidate[0] == 3 and candidate[5][2] == wanted}
        pointer_refs = [ident for ident, candidate in enumerate(btf.types[1:], 1)
                        if candidate[0] == 2 and candidate[2] in arrays]
        if not pointer_refs:
            raise RuntimeError("bank BTF mutant has no literal replacement type")
        address, replacement = base + node[6] + 12 + member * 12 + 4, pointer_refs[0]
    changed = bytearray(body)
    struct.pack_into("<I", changed, address, replacement)
    if changed == body:
        raise RuntimeError("bank BTF mutation did not change actual bytes")
    return bytes(changed)


def bank_owner_bound_mutants(body, graph, owner):
    """Damage every actual tagged guard, including its producing shift."""
    if owner.native_bound != 8192:
        raise RuntimeError("bank owner mutants require the validated private 8192 bound")
    changes = {name: {} for name in ("native_owner_slot_bound", "missing_native_owner_slot_bound",
                                     "legacy_native_owner_slot_bound")}
    for key, pc, kind, value in sorted(owner.guards):
        instruction = graph.instructions[key][pc]
        changes["missing_native_owner_slot_bound"][key, pc] = (0xbf, 0, 0, 0)
        if kind == "immediate":
            legacy = 511 if instruction[0] & 0xf0 in (0x20, 0xb0) else 512
            changes["native_owner_slot_bound"][key, pc] = instruction[:3] + (value - 1,)
            changes["legacy_native_owner_slot_bound"][key, pc] = instruction[:3] + (legacy,)
        elif kind == "shift":
            source = owner.guard_sources.get((key, pc))
            if source is None:
                raise RuntimeError("native owner guard lost its actual shift producer")
            shift = graph.instructions[source[0]][source[1]]
            if shift[0] not in (0x74, 0x77) or shift[2:] != (0, value):
                raise RuntimeError("native owner guard has no exact immediate shift producer")
            changes["native_owner_slot_bound"][source] = shift[:3] + (value - 1,)
            changes["legacy_native_owner_slot_bound"][source] = shift[:3] + (9,)
        else:
            raise RuntimeError("unclassified native owner bound guard")
    mutants = {}
    for name, sites in changes.items():
        if not sites:
            raise RuntimeError("native owner bound mutant has no actual guard")
        changed = body
        for (key, pc), instruction in sorted(sites.items()):
            changed = mutated_instruction(changed, graph, key, pc, instruction)
        mutants[name] = changed
    return mutants


def bank_causal_mutants(body):
    report, (graph, executions, optional_get, seed_sites, owner) = validate_bank_proof(body)
    mutants = {
        "inner_value_width": bank_btf_mutant(body, graph, "COUNTER_BANKS", "value_bytes", 40, inner=True),
        "inner_cell_count": bank_btf_mutant(body, graph, "COUNTER_BANKS", "max_entries", 2, inner=True),
        "outer_type": bank_btf_mutant(body, graph, "COUNTER_BANKS", "type", 2),
    }
    mutants.update(bank_owner_bound_mutants(body, graph, owner))
    symbol_index = next(index for index, symbol in enumerate(graph.elf.symbols)
                        if symbol[0] == "p11_bank_enter")
    changed = bytearray(body)
    changed[graph.elf.sections[".symtab"][0][4] + symbol_index * 24 + 4] = 2
    mutants["bank_global_linkage"] = bytes(changed)
    btf = MAPS.Btf(graph.elf.sections[".BTF"][1])
    function = next(node for node in btf.types[1:] if node[0] == 12 and node[1] == "p11_bank_enter")
    proto = btf.resolve(function[2])
    changed = bytearray(body)
    struct.pack_into("<I", changed, graph.elf.sections[".BTF"][0][4] + proto[6] + 16, proto[5][3])
    mutants["bank_global_abi"] = bytes(changed)
    events = [event for execution in executions for event in execution.trace]

    def instruction(label, site, replacement):
        mutants[label] = mutated_instruction(body, graph, site[0], site[1], replacement)

    seed = min(seed_sites)
    _, encoded, offset, _ = graph.instructions[seed[0]][seed[1]]
    instruction("aggregate_timestamp", seed, (0x7a, encoded & 15, offset, 1))

    # Every selection below comes from an actual executed call/read/branch,
    # not a source string, function size, hardcoded PC or favorable label.
    for label, helper in (("optional_start_get", "p11_owner_start_get"),
                          ("required_start_remove", "p11_owner_start_remove")):
        if label == "optional_start_get" and optional_get is not None:
            # The optimized LOCAL getter has no flag literal to mutate.
            # Damage its real preliminary absence lookup instead; forcing
            # the required path must fail the native quiet-absence probe.
            instruction(label, optional_get, (0xb7, 0, 0, 1))
            continue
        event = next(event for event in events if event[0] == "owner" and event[3] == helper)
        site = event[5][2]
        if site is None:
            raise RuntimeError("bank owner argument mutation has no actual defining instruction")
        op, encoded, offset, immediate = graph.instructions[site[0]][site[1]]
        if op not in (0xb4, 0xb7) or immediate != (0 if label == "optional_start_get" else 1):
            raise RuntimeError("bank owner argument is not the expected emitted scalar literal")
        instruction(label, site, (op, encoded, offset, 1 - immediate))
    for label, helper in (("missing_start_get", "p11_owner_start_get"),
                          ("missing_start_remove", "p11_owner_start_remove")):
        event = next(event for event in events if event[0] == "owner" and event[3] == helper)
        instruction(label, event[1:3], (0xb7, 0, 0, 0))
    read = next(event for event in events if event[0] == "read"
                and event[3] == ("COUNTER_BANK_META", 0) and event[4] == 8)
    old = graph.instructions[read[1]][read[2]]
    instruction("transaction_width", read[1:3], (0x61, old[1], old[2], old[3]))
    logical = next(event for event in events if event[0] == "branch"
                   and event[3:5] == (2, 1)
                   and graph.instructions[event[1]][event[2]][0] in (0x25, 0x26)
                   and graph.instructions[event[1]][event[2]][3] == 1)
    old = graph.instructions[logical[1]][logical[2]]
    instruction("logical_index", logical[1:3], old[:3] + (old[3] + 1,))
    inner_store = None
    for execution in executions:
        for index, event in enumerate(execution.trace):
            if event[0] != "lookup" or event[3] not in ("bank0", "bank1"):
                continue
            inner_store = next((item for item in reversed(execution.trace[:index])
                                if item[0] == "stack_write" and item[3] == event[5]
                                and item[4] in (4, 8) and item[5] == 0), None)
            if inner_store:
                break
        if inner_store:
            break
    if inner_store is None:
        raise RuntimeError("inner-index mutation has no actual zero-key initialization")
    old = graph.instructions[inner_store[1]][inner_store[2]]
    store_op = 0x62 if inner_store[4] == 4 else 0x7a
    instruction("inner_index", inner_store[1:3], (store_op, old[1] & 15, old[2], 1))
    commit_gate = None
    for execution in executions:
        for event in execution.trace:
            if event[0] != "branch" or 0 not in event[3:5]:
                continue
            other = event[3] or event[4]
            region = execution.region(other, 1)
            if region and region[2] == "COUNTER_BANK_COMMIT":
                commit_gate = event
                break
        if commit_gate:
            break
    if commit_gate is None:
        raise RuntimeError("commit-gate mutation has no actual checked commit pointer")
    instruction("commit_gate", commit_gate[1:3], (0xbf, 0, 0, 0))
    commit_set = next(event for event in events if event[0] == "branch"
                      and event[6] == ("COUNTER_BANK_COMMIT", 0)
                      and set(event[3:5]) == {1, 2})
    instruction("commit_set", commit_set[1:3], (0xbf, 0, 0, 0))
    fault = next(event for event in events if event[0] == "write"
                 and event[3] == "COUNTER_BANK_FAULT" and event[5] == 1)
    instruction("route_fault", fault[1:3], (0xbf, 0, 0, 0))
    lookup = next(event for event in events if event[0] == "lookup")
    for label, number in (("endpoint_clock", 5), ("semantic_helper", 112)):
        instruction(label, lookup[1:3], (0x85, 0, 0, number))
    owner_call = next(event for event in events if event[0] == "owner")
    old = graph.instructions[owner_call[1]][owner_call[2]]
    instruction("unknown_call", owner_call[1:3], (0x85, 0x20, 0, old[3]))
    refused = {}
    for label, changed in mutants.items():
        if changed == body:
            raise RuntimeError(f"bank causal mutation did not change actual bytes: {label}")
        try:
            validate_bank_proof(changed)
        except (RuntimeError, struct.error):
            refused[label] = "refused"
        else:
            raise RuntimeError(f"actual bank mutant accepted: {label}")
    return {"schema": report["schema"], "mutants": refused}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("object", nargs="?", type=Path)
    parser.add_argument("--mode", choices=tuple(STATS_BYTES))
    parser.add_argument("--profile", choices=("fixed", "counts-bank-proof"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-mutants", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.object is not None or args.mode is not None or args.self_test_mutants or args.profile:
            parser.error("--self-test accepts no other arguments")
    elif args.object is None or args.mode is None:
        parser.error("object and --mode are required for object checks")
    if args.profile == "counts-bank-proof" and args.mode != "counts":
        parser.error("bank proof requires counts")
    try:
        if args.self_test:
            result = {"schema": "p11scope-counter-transfer-controls/v1",
                      "transfer_controls": transfer_controls()}
        else:
            body = args.object.read_bytes()
            if args.profile == "counts-bank-proof":
                result = bank_causal_mutants(body) if args.self_test_mutants else validate_bank_proof(body)[0]
            else:
                result = causal_mutants(body, args.mode) if args.self_test_mutants else validate(body, args.mode)[0]
    except (OSError, RuntimeError, struct.error, ValueError, IndexError, KeyError) as error:
        print(f"counter object refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
