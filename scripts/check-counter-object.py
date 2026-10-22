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

    def __init__(self, graph, maps, strict=True):
        self.graph, self.maps, self.strict = graph, maps, strict
        self.touches, self.health, self.guards = set(), set(), set()
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
                if bound != 512:
                    raise RuntimeError("native owner slot bound differs from STATS512")
                self.guards.add((key, pc, "immediate", immediate))
            if isinstance(tag, tuple) and tag[0] == "key_shift" and operation in (0x10, 0x50) and immediate == 0:
                if tag[1] != 9:
                    raise RuntimeError("native owner shifted slot bound differs from STATS512")
                self.guards.add((key, pc, "shift", 9))
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
        elif operation in (0x20, 0x30, 0xa0, 0xb0):
            greater = operation in (0x20, 0x30)
            inclusive = operation in (0x30, 0xb0)
            if greater == taken:
                low = max(low, immediate + (not inclusive))
            else:
                high = min(high, immediate - inclusive)
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
                    registers[destination] = scalar_alu(left, right, operation, bits)
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
                for taken, target in ((True, pc + 1 + offset), (False, pc + 1)):
                    branch_registers = list(registers)
                    if (not can_refine or self.refine(branch_registers, destination, comparison_left,
                                                     singleton(comparison_right), operation, taken)):
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


def native_owner_bound(graph, maps):
    proof = MemoryProof(graph, maps, strict=False)
    proof.run(graph.only("p11_owner_start_aggregate"), [("key", 0), scalar(), None, None, None])
    if not proof.guards:
        raise RuntimeError("native aggregate constructor has no proven 512-slot key guard")
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

    def run(instructions, arguments=None, helpers=()):
        proof = MemoryProof(Graph(instructions + [exit_instruction], helpers), maps)
        proof.run(key, arguments or [pointer, ONE, scalar(), None, None])
        return proof

    report = {}

    def refuses(name, instructions, arguments=None, helpers=()):
        try:
            run(instructions, arguments, helpers)
        except RuntimeError:
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
    return report


def validate(body, mode):
    if mode not in STATS_BYTES:
        raise RuntimeError("unknown counter mode")
    graph = CallGraph(body)
    maps, expected = counter_maps(graph, mode)
    if any(name.startswith((".rodata", ".data", ".bss")) for name in graph.elf.sections):
        raise RuntimeError("counter artifact carries global data")
    MAPS.validate_owner_helpers(graph.elf)
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
        "native_owner_slot_bound": 512,
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
        histogram = sorted(touch for proof in proofs.values() for touch in proof.touches
                           if touch[2:4] == ("STATS", "write") and touch[4][0] >= 40)
        if not histogram:
            raise RuntimeError("histogram-removal mutant has no actual bucket update")
        changed = body
        for key, pc, *_ in histogram:
            changed = mutated_instruction(changed, graph, key, pc, (0xbf, 0, 0, 0))
        mutants["missing_histogram_write"] = changed
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object", type=Path)
    parser.add_argument("--mode", required=True, choices=tuple(STATS_BYTES))
    parser.add_argument("--self-test-mutants", action="store_true")
    args = parser.parse_args()
    try:
        body = args.object.read_bytes()
        result = causal_mutants(body, args.mode) if args.self_test_mutants else validate(body, args.mode)[0]
    except (OSError, RuntimeError, struct.error, ValueError, IndexError, KeyError) as error:
        print(f"counter object refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
