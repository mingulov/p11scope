#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect the image-bank proof object (Choice B feasibility, R0 route).

This is a compiled-object contract, not a kernel behavior claim. It pins
the 10 proof maps plus the reused production map shapes, the 6 exported
bank cores, and a per-root reachable map/helper census: dispatcher
counting presence (gate touched, accounts untouched, tail-call present),
cross-bank isolation of the slot/birth cores, and the return, reference,
exec and query cover shapes. Dynamic exactness (gate balance, ticket
numbers, route words, verifier budgets) is proven by the E3 kernel cells.
"""

import argparse
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _loader import load_sibling

MAPS = load_sibling("check-bpf-map-defs.py")
SCHEMA = "p11scope-image-bank-object/v1"

RUST_UPROBE_ROOTS = {
    "p11_bank_disp_enter": "uprobe",
    "p11_bank_disp_enter_multi": "uprobe",
    "p11_bank_entry_a": "uprobe",
    "p11_bank_entry_b": "uprobe",
    "p11_bank_ref_entry": "uprobe",
}
RUST_URETPROBE_ROOTS = {"p11_bank_return": "uretprobe"}
NATIVE_ROOTS = {
    "p11_bank_disp_birth": "tp_btf/task_newtask",
    "p11_bank_birth_a": "tp_btf/task_newtask",
    "p11_bank_birth_b": "tp_btf/task_newtask",
    "p11_bank_exec_cover": "fentry/exec_mm_release",
    "p11_bank_query_cover": "iter/task",
}
# (name, byte width per argument). Every exported bank core takes
# scalars only: the verifier refuses a context (or any unsized void *)
# pointer across a global call, so the entry dispatchers keep the probe
# context in the Rust root and tail-call through their own owner array.
BANK_CORES = {
    "p11_bank_select": (),
    "p11_bank_gate_release": (4,),
    "p11_bank_enter_a": (8, 8, 8, 8),
    "p11_bank_enter_b": (8, 8, 8, 8),
    "p11_bank_complete": (8,),
    "p11_bank_ref": (8, 8),
}
BANK_MAPS = {
    "TASK_COOKIE_B", "COOKIE_CTL_B", "IMAGE_CONTINUITY_B",
    "IMAGE_TGID_INDEX_B",
}
SHARED_MAPS = {
    "BANK_SELECT", "BANK_GATE", "BANK_PROGS_SINGLES", "BANK_PROGS_MULTI",
    "BANK_PROGS_BIRTH", "IMAGE_BANK_ACCOUNT", "START",
}
BANK_A_MAPS = {
    "TASK_COOKIE", "COOKIE_CTL", "IMAGE_CONTINUITY", "IMAGE_TGID_INDEX",
}
# Helpers 1/2/3/5/12/127/156/158 in the native cores, 14/173/174 in the
# Rust roots. No ringbuf/output, no skb, no arbitrary kernel reads.
ALLOWED_HELPERS = {1, 2, 3, 5, 12, 14, 127, 156, 158, 173, 174}
TAIL_CALL = 12


class CallGraph:
    """Function bodies, call edges and map relocations for one object."""

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
                raise RuntimeError("duplicate or unaligned bank function")
            MAPS.checked_slice(self.sections[key[0]][1], key[1], symbol[5],
                               "function")
            self.bodies[key] = symbol
        self.relocations = {}
        for row, raw in self.elf.sections.values():
            if row[1] != 9 or row[7] not in {key[0] for key in self.bodies}:
                continue
            if row[9] != 16 or len(raw) % 16 or row[6] != self.elf.indices[".symtab"]:
                raise RuntimeError("invalid bank relocation table")
            for at in range(0, len(raw), 16):
                address, info = struct.unpack_from("<QQ", raw, at)
                key = row[7], address
                if key in self.relocations or info >> 32 >= len(self.elf.symbols):
                    raise RuntimeError("duplicate or invalid bank relocation")
                self.relocations[key] = info & 0xffffffff, self.elf.symbols[info >> 32]
        self.instructions = {}
        self.calls = {}
        self.edges = {key: set() for key in self.bodies}
        for key, symbol in self.bodies.items():
            raw = MAPS.checked_slice(self.sections[key[0]][1], key[1],
                                     symbol[5], "function")
            instructions = {}
            at = 0
            while at < len(raw):
                instruction = struct.unpack_from("<BBhi", raw, at)
                instructions[at // 8] = instruction
                op, registers, offset, immediate = instruction
                if op == 0x18:
                    MAPS.checked_slice(raw, at, 16, "wide bank instruction")
                    if struct.unpack_from("<BBh", raw, at + 8) != (0, 0, 0):
                        raise RuntimeError("invalid wide instruction continuation")
                    at += 16
                    continue
                if op == 0x8d:
                    raise RuntimeError("indirect bank call")
                if op == 0x85:
                    if offset:
                        raise RuntimeError("bank call has a nonzero offset")
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
                        raise RuntimeError("unsupported bank call encoding")
                at += 8
            for pc, (op, _, offset, _) in instructions.items():
                if op & 7 in (5, 6) and op not in (0x85, 0x95):
                    delta = instructions[pc][3] if op == 0x06 else offset
                    if pc + 1 + delta not in instructions:
                        raise RuntimeError("bank branch leaves its function")
            self.instructions[key] = instructions

    def only(self, name):
        found = [key for key, symbol in self.bodies.items()
                 if symbol[0] == name]
        if len(found) != 1:
            raise RuntimeError(f"requires exactly one {name}")
        return found[0]

    def root(self, name, section, *, global_bind):
        key = self.only(name)
        symbol = self.bodies[key]
        want = 0x12 if global_bind else 0x02
        if (symbol[1] != want or symbol[2] != 0
                or key[0] != self.elf.indices.get(section)):
            raise RuntimeError(f"requires {'GLOBAL' if global_bind else 'LOCAL'}"
                               f" DEFAULT {section} {name}")
        return key

    def reachable(self, root):
        reached, pending = set(), [root]
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(self.edges[key])
        return reached

    def map_at(self, key, pc):
        relocation = self.relocations.get((key[0], key[1] + pc * 8))
        if relocation is None:
            return None
        kind, target = relocation
        if kind != 1 or target[1] & 15 not in (1, 3):
            raise RuntimeError("unsupported bank data relocation")
        if target[3] not in {self.elf.indices.get("maps"),
                             self.elf.indices.get(".maps")}:
            raise RuntimeError("bank root reaches global data")
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

    def census(self, root):
        """(helpers, maps) over a root and its reachable callees."""
        helpers, touched = set(), set()
        for key in self.reachable(root):
            for pc, (op, _, _, _) in self.instructions[key].items():
                call = self.calls.get((key, pc))
                if call is not None and call[0] == "helper":
                    helpers.add(call[1])
                if op == 0x18:
                    named = self.map_at(key, pc)
                    if named is not None:
                        touched.add(named)
        return helpers, touched


# The 10 proof maps (4 second-bank image maps + select + gate + 3 bank
# program arrays + the proof attribution counter) plus the reused
# production shapes bank A runs on. START's 288-byte value carries the R0
# route at 88/264/272/280.
EXPECTED_MAP_SHAPES = {
    "TASK_COOKIE_B": (29, 4, 8, 0, 1),
    "COOKIE_CTL_B": (2, 4, 40, 1, 0),
    "IMAGE_CONTINUITY_B": (1, 8, 24, 16384, 17),
    "IMAGE_TGID_INDEX_B": (1, 8, 8, 16384, 17),
    "BANK_SELECT": (2, 4, 32, 1, 0),
    "BANK_GATE": (2, 4, 8, 2, 0),
    "BANK_PROGS_SINGLES": (3, 4, 4, 2, 0),
    "BANK_PROGS_MULTI": (3, 4, 4, 2, 0),
    "BANK_PROGS_BIRTH": (3, 4, 4, 2, 0),
    "IMAGE_BANK_ACCOUNT": (2, 4, 104, 3, 0),
    "TASK_COOKIE": (29, 4, 8, 0, 1),
    "COOKIE_CTL": (2, 4, 40, 1, 0),
    "IMAGE_CONTINUITY": (1, 8, 24, 16384, 17),
    "IMAGE_TGID_INDEX": (1, 8, 8, 16384, 17),
    "IMAGE_QUERY_REQUESTS": (1, 8, 24, 1024, 129),
    "IMAGE_QUERY_CTL": (2, 4, 56, 1, 0),
    "START": (1, 16, 288, 16384, 0),
}


def collect_maps(graph):
    elf = graph.elf
    if "maps" not in elf.sections:
        raise RuntimeError("image bank proof has no Rust map definitions")
    section = elf.indices["maps"]
    records = [(s[4], s[5], "OBJECT", "", "", str(s[3]), s[0])
               for s in elf.symbols if s[3] == section and s[1] & 15 == 1]
    maps = MAPS.decode_map_definitions(records, section,
                                       elf.sections["maps"][1])
    native = MAPS.decode_btf_maps(elf)
    if maps.keys() & native.keys():
        raise RuntimeError("duplicate Rust/native image bank map")
    maps.update(native)
    return maps


def check_map_shapes(maps):
    fields = ("type", "key_size", "value_size", "max_entries", "flags")
    for name, wanted in EXPECTED_MAP_SHAPES.items():
        if name not in maps:
            raise RuntimeError(f"image bank proof has no {name} map")
        actual = tuple(maps[name][field] for field in fields)
        if actual != wanted:
            raise RuntimeError(
                f"{name} shape {actual} differs, expected {wanted}")


def proof_maps(graph):
    maps = collect_maps(graph)
    check_map_shapes(maps)
    return maps


def core_protos(btf):
    """name -> (return kind, return width, argument widths) for bank cores."""
    protos = {}
    for name in BANK_CORES:
        matches = [node for node in btf.types[1:]
                   if node[0] == 12 and node[1] == name]
        if len(matches) != 1 or matches[0][3] != 1:
            raise RuntimeError(f"image bank BTF function {name} differs")
        proto = btf.resolve(matches[0][2])
        if proto[0] != 13:
            raise RuntimeError(f"image bank {name} has no BTF prototype")
        returns = btf.resolve(proto[2])
        arguments = []
        for ref in proto[5][1::2]:
            arg = btf.resolve(ref)
            arguments.append("ptr" if arg[0] == 2 else
                             (arg[2], arg[5]) if arg[0] == 1 else None)
        protos[name] = (returns[0], (returns[2], returns[5]), arguments)
    return protos


def check_core_abi(cores, text_index, protos):
    if {symbol[0] for symbol in cores} != set(BANK_CORES):
        raise RuntimeError("image bank core inventory differs")
    for _, info, other, section, address, size in cores:
        if (info != 0x12 or other or section != text_index
                or not size or address % 8 or size % 8):
            raise RuntimeError(
                "image bank requires defined GLOBAL DEFAULT core functions")
    if set(protos) != set(BANK_CORES):
        raise RuntimeError("image bank BTF core inventory differs")
    for name, widths in BANK_CORES.items():
        kind, rest, arguments = protos[name]
        if len(arguments) != len(widths):
            raise RuntimeError(f"image bank {name} argument count differs")
        if kind != 1 or rest != (4, (32,)):
            raise RuntimeError(f"image bank {name} must return u32")
        for argument, width in zip(arguments, widths):
            if argument == "ptr":
                raise RuntimeError(
                    f"image bank {name} takes a pointer across the "
                    "global-call boundary: keep ctx in the root, pass scalars")
            if argument != (width, (width * 8,)):
                raise RuntimeError(
                    f"image bank {name} requires exact unsigned scalar ABI")


def proof_global_abi(graph):
    elf = graph.elf
    cores = [symbol for symbol in elf.symbols if symbol[0] in BANK_CORES]
    btf = MAPS.Btf(elf.sections[".BTF"][1])
    check_core_abi(cores, elf.indices.get(".text"), core_protos(btf))


def proof_roots(graph):
    roots = {}
    for name, section in RUST_UPROBE_ROOTS.items():
        roots[name] = graph.root(name, section, global_bind=True)
    for name, section in RUST_URETPROBE_ROOTS.items():
        roots[name] = graph.root(name, section, global_bind=True)
    for name, section in NATIVE_ROOTS.items():
        roots[name] = graph.root(name, section, global_bind=False)
    return roots


def proof_reachability(graph, roots):
    census = {name: graph.census(key) for name, key in roots.items()}
    for name, (helpers, _) in census.items():
        outside = helpers - ALLOWED_HELPERS
        if outside:
            raise RuntimeError(
                f"{name} uses helpers outside the proof allowlist: {sorted(outside)}")
    dispatchers = ("p11_bank_disp_enter", "p11_bank_disp_enter_multi",
                   "p11_bank_disp_birth")
    for name in dispatchers:
        _, touched = census[name]
        if "IMAGE_BANK_ACCOUNT" in touched:
            raise RuntimeError(f"{name} counts admissions")
        if touched - ({"BANK_SELECT", "BANK_GATE", "BANK_PROGS_SINGLES",
                       "BANK_PROGS_MULTI", "BANK_PROGS_BIRTH"}):
            raise RuntimeError(f"{name} reaches past select/gate/arrays")
        if "BANK_GATE" not in touched:
            raise RuntimeError(f"{name} takes no gate ref")
        helpers, _ = census[name]
        if TAIL_CALL not in helpers:
            raise RuntimeError(f"{name} never tail-calls its bank")
    bank_a = census["p11_bank_entry_a"][1] | census["p11_bank_birth_a"][1]
    if bank_a & BANK_MAPS:
        raise RuntimeError(
            f"bank A core touches second-bank maps: {sorted(bank_a & BANK_MAPS)}")
    if not {"BANK_SELECT", "BANK_GATE"} <= bank_a:
        raise RuntimeError("bank A core skips select or gate")
    bank_b = census["p11_bank_entry_b"][1] | census["p11_bank_birth_b"][1]
    if bank_b & BANK_A_MAPS:
        raise RuntimeError(
            f"bank B core touches first-bank maps: {sorted(bank_b & BANK_A_MAPS)}")
    if not {"BANK_SELECT", "BANK_GATE"} <= bank_b:
        raise RuntimeError("bank B core skips select or gate")
    helpers, touched = census["p11_bank_return"]
    if touched - {"START", "IMAGE_BANK_ACCOUNT"}:
        raise RuntimeError("return core reaches past route/accounts")
    if 3 not in helpers:
        raise RuntimeError("return core never retires its route")
    if 2 in helpers:
        raise RuntimeError("return core mints state")
    helpers, touched = census["p11_bank_ref_entry"]
    if touched != {"IMAGE_BANK_ACCOUNT"} or helpers - {1, 173, 174}:
        raise RuntimeError("reference core is not a pure account write")
    _, touched = census["p11_bank_exec_cover"]
    if "IMAGE_BANK_ACCOUNT" in touched:
        raise RuntimeError("exec cover counts")
    if touched - {"IMAGE_TGID_INDEX", "IMAGE_TGID_INDEX_B",
                  "IMAGE_CONTINUITY", "IMAGE_CONTINUITY_B"}:
        raise RuntimeError("exec cover reaches past both index/continuity pairs")
    _, touched = census["p11_bank_query_cover"]
    if not {"TASK_COOKIE", "TASK_COOKIE_B", "IMAGE_CONTINUITY",
            "IMAGE_CONTINUITY_B", "IMAGE_QUERY_REQUESTS",
            "IMAGE_QUERY_CTL"} <= touched:
        raise RuntimeError("query cover misses a dual-bank input")
    return census


def check_object(path):
    body = Path(path).read_bytes()
    graph = CallGraph(body)
    maps = proof_maps(graph)
    proof_global_abi(graph)
    roots = proof_roots(graph)
    census = proof_reachability(graph, roots)
    helpers = sorted({helper for helpers, _ in census.values()
                      for helper in helpers})
    return (f"{SCHEMA}: OK roots={len(roots)} maps={len(maps)} "
            f"helpers={helpers}")


def main(argv):
    parser = argparse.ArgumentParser(
        description="Check the image-bank proof object contract")
    parser.add_argument("object", help="proof object to inspect")
    arguments = parser.parse_args(argv)
    try:
        print(check_object(arguments.object))
    except (OSError, RuntimeError) as error:
        print(f"{SCHEMA}: FAIL {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
