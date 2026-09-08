#!/usr/bin/env python3
"""Partial compiled entry/return cookie, descriptor and ABI-routing contract.

This is a caller-wiring analysis, not a BPF interpreter or a native owner proof.
Instruction decoding, ELF inspection and relocation resolution belong to the
sibling checker. The final-sink extension uses finite descriptor index domains
and separate success obligations in the same transfer/worklist analysis.
The CLI exits 2 even when these bounded obligations pass, so this
module cannot silently replace the complete source guards.
"""

import argparse
from collections import Counter, deque
import importlib.util
import json
from pathlib import Path
import re
import subprocess


_spec = importlib.util.spec_from_file_location(
    "entry_discovery_primitives", Path(__file__).with_name("check-live-discovery-object.py")
)
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)
SCHEMA = "p11scope-entry-object/v1"
BASE_FIELDS = {3, 6, 7, 8, 9, 10, 11}
LOAD = re.compile(r"([rw]\d+) = \*\(u(8|16|32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\)")
STORE = re.compile(r"\*\(u(8|16|32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) = ([rw]\d+|-?0x[0-9a-f]+)")
ATOMIC_POINTER = re.compile(r"\(u(32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\)")
EXCHANGE_POINTER = re.compile(r"(?:cmpxchg|xchg)_(32|64)\(r(\d+) ([+-]) 0x([0-9a-f]+)")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def reg(name):
    return "r" + name[1:]


def value(state, operand):
    return state.get(reg(operand)) if operand[0] in "rw" else ("constant", int(operand, 16))


def narrow(fact, width):
    if not fact:
        return None
    if fact[0] == "constant":
        return ("constant", fact[1] & ((1 << width) - 1))
    if width == 64 or fact[0] == "field":
        return fact
    if width == 32:
        if fact[0] == "scalar":
            return ("scalar", fact[1], 32)
        if fact[0] == "cookie":
            return ("low", fact[1])
        if fact[0] in ("low", "high", "selected"):
            return fact
    return None


def address(state, base, sign, offset):
    fact = state.get("r" + base)
    if not fact:
        return None
    delta = int(offset, 16) * (1 if sign == "+" else -1)
    if fact[0] in ("stack", "context", "event"):
        return (fact[0], fact[1] + delta)
    if fact[0] == "descriptor":
        return ("descriptor", fact[1], delta)
    if fact[0] == "owned":
        return ("owned", fact[1], fact[2] + delta)
    if fact[0] == "function_value":
        return ("function_value", fact[1], fact[2] + delta)
    return None


def forget_stack(state, offset, size):
    for key in list(state):
        if isinstance(key, tuple) and key[0] == "stack":
            if key[1] < offset + size and offset < key[1] + key[2]:
                del state[key]


def forget_event_slot(state, offset, size):
    if offset < 0x6c and 0x68 < offset + size:
        state.pop(("event_slot",), None)


def forget_atomic_memory(state, text):
    """Read-modify-write effects precede and survive result-register handling."""
    match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
    pointer = address(state, *match.groups()[1:]) if match else None
    if pointer and pointer[0] == "stack":
        forget_stack(state, pointer[1], int(match[1]) // 8)
    elif pointer and pointer[0] == "event":
        forget_event_slot(state, pointer[1], int(match[1]) // 8)
    else:
        # Unsupported syntax/address cannot establish which tracked bytes survive.
        for key in list(state):
            if isinstance(key, tuple) and key[0] in ("stack", "event_slot"):
                del state[key]


def stack_read(state, pointer, size, offset=0):
    if pointer and pointer[0] == "stack":
        start = pointer[1] + offset
        for key, fact in state.items():
            if isinstance(key, tuple) and key[0] == "stack" and key[1] == start and key[2] >= size:
                return narrow(fact, size * 8)
    return None


def sections(disassembly):
    parts = re.split(r"(?m)^Disassembly of section ([^:]+):\s*$", disassembly)
    return dict(zip(parts[1::2], parts[2::2]))


class Consumer:
    def __init__(self, section, name, lines, calls):
        self.section, self.name = section, name
        self.lines = lines
        self.insns, self.graph = D.instruction_graph(lines)
        self.text = dict(self.insns)
        self.calls = calls
        entries = D.instruction_entries(lines)
        self.maps = {pc: target for index, kind, target in D.relocation_targets(lines)
                     if kind == "64" for line, pc, _ in entries if line == index - 1}
        self.helper = {pc for _, pc, text in entries if text.startswith("85 00 ")}
        self.proof = None

    def label(self, pc):
        return f"{self.section}:{self.name}:{pc}"

    def step(self, pc, incoming):
        state = self.transfer(pc, incoming)
        return self.proof.transfer(self, pc, incoming, state) if self.proof else state

    def transfer(self, pc, incoming):
        state = incoming.copy()
        text = self.text[pc]
        if "atomic" in text or "xchg" in text or text.startswith("lock "):
            forget_atomic_memory(state, text)
            if match := re.match(r"([rw]\d+)\s", text):
                state.pop(reg(match[1]), None)
            return state
        if pc in self.maps:
            match = re.match(r"([rw]\d+) =", text)
            require(match is not None, self.label(pc) + ": map load changed")
            state[reg(match[1])] = ("map", self.maps[pc])
        elif match := STORE.fullmatch(text):
            width, base, sign, offset, src = match.groups()
            pointer = address(state, base, sign, offset)
            if pointer and pointer[0] == "stack":
                size = int(width) // 8
                forget_stack(state, pointer[1], size)
                fact = narrow(value(state, src), int(width))
                if fact is not None:
                    state[("stack", pointer[1], size)] = fact
            elif pointer and pointer[0] == "event":
                forget_event_slot(state, pointer[1], int(width) // 8)
                if pointer[1] == 0x68 and width == "32":
                    fact = narrow(value(state, src), 32)
                    if fact is not None:
                        state[("event_slot",)] = fact
            elif pointer is None:
                # An unresolved destination cannot preserve output provenance.
                state.pop(("event_slot",), None)
        elif match := LOAD.fullmatch(text):
            dst, width, base, sign, offset = match.groups()
            pointer = address(state, base, sign, offset)
            fact = None
            if pointer:
                if pointer[0] == "stack":
                    fact = stack_read(state, pointer, int(width) // 8)
                elif pointer == ("context", 0x88) and width == "64":
                    fact = ("selector",)
                elif pointer[0] == "descriptor" and width == "8":
                    fact = ("field", pointer[2])
            state.pop(reg(dst), None)
            if fact is not None:
                state[reg(dst)] = fact
        elif text.startswith("call "):
            result = None
            if pc in self.helper:
                if text == "call 0xae" and state.get("r1") == ("context", 0):
                    result = ("cookie", (self.section, self.name))
                elif text == "call 0xe":
                    result = ("pid_tgid", (self.section, self.name))
                elif text == "call 0x5":
                    result = ("ktime_ns", (self.section, self.name))
                elif text == "call 0x1" and state.get("r1", (None,))[0] == "map":
                    result = ("descriptor", pc) if state["r1"][1] == "DESCRIPTORS" else ("result", pc)
                elif text == "call 0x83" and state.get("r1") == ("map", "EVENTS"):
                    result = ("event", 0)
                    state.pop(("event_slot",), None)
                elif text in ("call 0x70", "call 0x72"):
                    pointer, size = state.get("r1"), state.get("r2")
                    if pointer and pointer[0] == "stack":
                        forget_stack(state, pointer[1], size[1] if size and size[0] == "constant" else 512)
            # Only caller wiring is examined. Known internal output destinations
            # lose facts; keyed owner calls receive const keys and retain them.
            target = self.calls.get(pc, "")
            output = None
            if target == "memset":
                size = state.get("r3")
                output = ("r1", size[1] if size and size[0] == "constant" else 512)
            elif target.endswith("scope_auth") or target.endswith("capture_scalar"):
                output = ("r1", 16)
            elif target == "p11_link_current_identity":
                output = ("r1", 16)
            if output:
                pointer = state.get(output[0])
                if pointer and pointer[0] == "stack":
                    forget_stack(state, pointer[1], output[1])
                elif pointer and pointer[0] == "event":
                    forget_event_slot(state, pointer[1], output[1])
            elif text != "call 0x84" and any(
                state.get("r" + str(index), (None,))[0] == "event" for index in range(1, 6)
            ):
                state.pop(("event_slot",), None)
            for index in range(6):
                state.pop("r" + str(index), None)
            if result:
                state["r0"] = result
        elif match := re.fullmatch(r"([rw]\d+) (=|\+=|<<=|>>=|&=) ([rw]\d+|-?0x[0-9a-f]+)(?: ll)?", text):
            dst, op, src = match.groups()
            old, fact = state.get(reg(dst)), value(state, src)
            if op != "=":
                if old and fact and fact[0] == "constant":
                    amount = fact[1]
                    if op == "+=" and old[0] in ("stack", "context", "event", "constant"):
                        fact = (old[0], old[1] + amount)
                    elif op == "<<=" and amount == 32 and old[0] == "cookie":
                        fact = ("low_shifted", old[1])
                    elif op == ">>=" and amount == 32 and old[0] in ("cookie", "low_shifted"):
                        fact = ("high" if old[0] == "cookie" else "low", old[1])
                    elif op == "&=" and amount == 0xffffffff and old[0] == "cookie":
                        fact = ("low", old[1])
                    else:
                        fact = None
                else:
                    fact = None
            if dst.startswith("w"):
                fact = narrow(fact, 32)
            state.pop(reg(dst), None)
            if fact is not None:
                state[reg(dst)] = fact
        elif match := re.match(r"[rw](\d+)\s", text):
            state.pop("r" + match[1], None)
        elif "*(" in text or "atomic" in text or "cmpxchg" in text:
            # Unsupported memory writes cannot preserve stack facts.
            for key in list(state):
                if isinstance(key, tuple) and key[0] == "stack":
                    del state[key]
            state.pop(("event_slot",), None)
        return state

    def facts(self, initial=None, proof=None):
        start = self.insns[0][0]
        initial = initial or {"r1": ("context", 0), "r10": ("stack", 0)}
        if proof is not None:
            # Topological worklist: validate only complete predecessor joins.
            # Success/lifecycle partitions belong to ONE role, never to all
            # combinations of captured arguments or machine states.
            reachable = D.reachable(self.graph, [start])
            degree = Counter(v for u in reachable for v in self.graph[u] if v in reachable)
            pending = deque(pc for pc in reachable if not degree[pc])
            order = []
            while pending:
                pc = pending.popleft()
                order.append(pc)
                for successor in self.graph[pc]:
                    degree[successor] -= 1
                    if degree[successor] == 0:
                        pending.append(successor)
            require(len(order) == len(reachable), self.name + ": final-sink cyclic CFG")
            incoming = {start: {proof.partition(initial): initial}}
            self.proof = proof
            try:
                for pc in order:
                    for state in incoming.get(pc, {}).values():
                        after = self.step(pc, state)
                        for successor, edge in proof.edges(self, pc, state, after):
                            partition = proof.partition(edge)
                            previous = incoming.setdefault(successor, {}).get(partition)
                            incoming[successor][partition] = proof.join(previous, edge)
                proof.finish(self)
                return incoming
            finally:
                self.proof = None
        incoming = {start: initial}
        pending = deque([start])
        while pending:
            pc = pending.popleft()
            state = self.step(pc, incoming[pc])
            for successor in self.graph[pc]:
                previous = incoming.get(successor)
                merged = state.copy() if previous is None else {k: v for k, v in previous.items() if state.get(k) == v}
                if previous != merged:
                    incoming[successor] = merged
                    pending.append(successor)
        return incoming


# Semantic inventory for the admitted compiled forms. PCs locate roles; no
# expected field or destination is inferred from the observed call sequence.
# CallStart offsets and lifecycle predicates are independent source contracts.
DESTINATIONS = {6: (8, 8), 7: (0x10, 8), 10: (0x28, 8),
                11: (0x38, 4), 8: (0x20, 8), 9: (0x30, 8),
                "join": (0x58, 8), "get": (0x30, 8), 16: (0x104, 4)}
LP64_OFFSETS = (0x70, 0x68, 0x60, 0x58, 0x48, 0x40)
LP64_READS = {
    6: ([1099, 977, 1103, 1069, 1101, 1064], 1079),
    7: ([1152, 1110, 1156, 1121, 1154, 1116], 1131),
    10: ([1205, 1164, 1209, 1176, 1207, 1171], 1186),
    11: ([1265, 1221, 1269, 1236, 1267, 1227], 1246),
    8: ([1548, 1453, 1288, 1372, 1301, 1377], 1324),
    9: ([1368, 1380, 1281, 1370, 1295, 1375], 1312),
    "join": ([1530, 1427, 1536, 1466, 1533, 1443], 1478),
    "get": ([1539, 1436, 1545, 1486, 1542, 1450], 1498),
}
IA32_READS = {6: 1788, 7: 1818, 10: 1850, 11: 1962,
              8: 2051, 9: 1997, "join": 2202, "get": 2236}
LP64_DISPATCH = {6: (971,), 7: (1105,), 10: (1158,), 11: (1216,),
                 8: (1272, 1283), 9: (1275, 1276), "join": (1422,), "get": (1431,)}
IA32_DISPATCH = {6: (1773,), 7: (1803,), 10: (1835,), 11: (1947,),
                 8: (1979, 2037), 9: (1981,), "join": (2186,), "get": (2220,)}
SCALAR_CALLS = {
    "default": {978: 6, 991: 7, 1004: 10, 1020: 11, 1105: 8,
                1138: 9, 1185: 16, 1356: "join", 1370: "get"},
    "p11_entry_template": {2404: 6, 2417: 7, 2429: 10, 2446: 11,
                           2462: 9, 2553: 8, 2604: 12, 2615: 13},
    "p11_entry_template_pair": {2883: 6, 2896: 7, 2908: 10, 2925: 11,
                                2941: 9, 3032: 8, 3083: 12, 3094: 13},
    "p11_entry_template_types": {3493: 6, 3506: 7, 3518: 10, 3535: 11,
                                 3551: 9, 3642: 8, 3693: 12, 3704: 13},
    "p11_entry_template_second": {3302: 14, 3314: 15},
}
SEMANTIC_INSERT = {"default": 1163, "p11_entry": 1398, "p11_entry_ia32": 2022,
                   "p11_entry_template": 2648, "p11_entry_template_pair": 3127,
                   "p11_entry_template_types": 3741}
BYTE_DOMAIN = frozenset(range(256))
BRANCH = re.compile(r"if ([rw]\d+) (==|!=|s>|>|s>=|>=|<|<=) ([rw]\d+|-?0x[0-9a-f]+) goto [+-]0x[0-9a-f]+")


def field_number(role):
    return 17 if role in ("join", "get") else role


def compare(left, op, right, width=64):
    left, right = left & ((1 << width) - 1), right & ((1 << width) - 1)
    if op.startswith("s"):
        left = left - (1 << width) if left >= 1 << (width - 1) else left
        right = right - (1 << width) if right >= 1 << (width - 1) else right
        op = op[1:]
    return {"==": left == right, "!=": left != right, ">": left > right,
            ">=": left >= right, "<": left < right, "<=": left <= right}[op]


def zero_partition(fact, op, width):
    """Taken-edge zero status only for an exact zero/nonzero partition.

    The comparison's right operand must be zero. Other predicates retain
    uncertainty: a signed nonpositive pointer can still be nonzero, and an
    unsigned >= 0 comparison admits both zero and nonzero on the same edge.
    """
    if op in ("==", "<="):
        return True
    if op in ("!=", ">"):
        return False
    if op == "s>" and width == 64 and fact[0] == "scalar" and fact[2] == 32:
        return False  # Every nonzero zero-extended u32 is positive as s64.
    return None


class SinkProof:
    """Additional facts and obligations for one semantic role in Consumer.

    Index domains union at joins; all other facts intersect. Only this role's
    success and lifecycle/nonzero predicates partition a join. A successful
    capture must survive to its final sink; initialized bytes cannot satisfy it.
    """
    def __init__(self, role, abi, present, start, *, calls=None, reads=None,
                 helpers=None, insert=None, kind="entry", mode=0):
        self.role, self.field = role, field_number(role)
        self.abi, self.present, self.start = abi, present, start
        self.calls, self.reads, self.helpers = calls or {}, reads or {}, helpers or {}
        self.insert, self.kind, self.mode = insert, kind, mode
        self.lifecycle = {9: 1, "join": 13, "get": 12}.get(role)
        self.witnesses, self.read_witnesses = set(), set()
        self.boundaries = set()
        self.dispatches = ()
        self.decoder_required = False
        self.effect_start = None

    def partition(self, state):
        return tuple(state.get((key,)) for key in ("success", "nonnull", "life", "done", "inserted"))

    @staticmethod
    def join(previous, state):
        if previous is None:
            return state.copy()
        merged = {k: v for k, v in previous.items() if state.get(k) == v}
        for key in previous.keys() & state.keys():
            if isinstance(key, tuple) and key[0] == "domain":
                merged[key] = previous[key] | state[key]
        return merged

    def domain(self, state, field):
        return state.get(("domain", field), BYTE_DOMAIN)

    def scalar(self, field=None, width=None):
        return ("scalar", self.field if field is None else field,
                (32 if self.abi else 64) if width is None else width)

    def captured(self, state):
        state[("success",)] = True
        if self.lifecycle is not None:
            domain = self.domain(state, 3)
            if self.lifecycle not in domain:
                state[("life",)] = False
            elif domain == {self.lifecycle}:
                state[("life",)] = True

    def required(self, state):
        return (state.get(("success",)) and state.get(("life",)) is not False
                and (self.role != 8 or state.get(("nonnull",)) is not False))

    def fail(self, consumer, pc, message):
        return consumer.label(pc) + f": final-sink {self.role}: " + message

    def check_sink(self, consumer, pc, state):
        if not self.required(state):
            return
        if self.lifecycle is not None:
            require(state.get(("life",)) is True, self.fail(consumer, pc, "lifecycle predicate not proved"))
        if self.role == 8:
            require(state.get(("nonnull",)) is True, self.fail(consumer, pc, "nonzero pointer predicate not proved"))
        if self.role == "template":
            require(state.get(("done",)) is True, self.fail(consumer, pc, "successful ptr/count missed mode walker"))
        else:
            offset, size = DESTINATIONS[self.role]
            expected = ("selected", 16) if self.role == 16 else self.scalar(width=32 if size == 4 else (32 if self.abi else 64))
            actual = stack_read(state, self.start, size, offset)
            require(actual == expected, self.fail(consumer, pc, f"successful capture lost at START+{offset:#x}: {actual}"))
        self.witnesses.add(pc)

    def transfer(self, consumer, pc, before, state):
        text, target = consumer.text[pc], consumer.calls.get(pc, "")
        error = lambda message: self.fail(consumer, pc, message)
        if match := STORE.fullmatch(text):
            pointer = address(before, match[2], match[3], match[4])
            if pointer is None and before.get("r"+match[2], (None,))[0] != "result":
                require(self.effect_start is None, error("unresolved callee memory footprint"))
                # A map helper's result is disjoint from the BPF frame. An
                # otherwise unresolved destination may alias any saved sink.
                for key in list(state):
                    if isinstance(key, tuple) and key[0] == "stack":
                        del state[key]
            if self.effect_start and pointer:
                require(pointer[0] == "stack", error("unsupported callee memory destination"))
            if self.effect_start and pointer and pointer[0] == "stack" and pointer[1] < -512:
                allowed = {(self.effect_start[1]+0x100, 4)}
                if self.kind == "async":
                    allowed.add((self.effect_start[1]+0x104, 4))
                else:
                    allowed |= {(self.start[1], 8), (self.start[1]+8, 8)}
                require((pointer[1], int(match[1])//8) in allowed, error("callee START/Option write footprint"))
        if self.effect_start and ("atomic" in text or "xchg" in text or text.startswith("lock ")):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(before, *match.groups()[1:]) if match else None
            require(pointer and pointer[0] == "stack" and -512 <= pointer[1] < 0,
                    error("unsupported callee memory footprint"))
        if pc in self.dispatches:
            branch = BRANCH.fullmatch(text)
            expected = ("field", self.field) if self.present else ("constant", 255)
            require(branch and value(before, branch[1]) == expected,
                    error("scalar-read dispatch descriptor field provenance"))
        # Byte domains exist independently of register aliases and spills.
        if match := LOAD.fullmatch(text):
            dst, width, base, sign, offset = match.groups()
            pointer = address(before, base, sign, offset)
            if pointer == ("context", 0x88) and width == "64":
                state[reg(dst)] = ("constant", 0x23 if self.abi else 0x33)
            elif pointer and pointer[0] == "descriptor" and width == "8":
                state[("domain", pointer[2])] = BYTE_DOMAIN
            elif pointer == ("context", 0x98) and width == "64":
                state[reg(dst)] = ("rsp", 64, 0)
            elif pointer and pointer[0] == "owned" and before.get(("live", pointer[1])):
                state[reg(dst)] = ("retained", pointer[2], int(width))
            elif pointer and pointer[0] == "function_value" and pointer[2] == 0 and width == "32" and before.get(("live", pointer[1])):
                state[reg(dst)] = ("selected", 16)
                if self.role == 16:
                    self.captured(state)
            if pc in self.reads:
                index = self.reads[pc]
                require(self.abi == 0 and pointer == ("context", LP64_OFFSETS[index]) and width == "64"
                        and self.domain(before, self.field) == {index}, error("scalar-read LP64 field/index/context provenance"))
                state[reg(dst)] = self.scalar()
                self.captured(state)
                self.read_witnesses.add(index)
            fact = state.get(reg(dst))
            if fact and fact[0] == "candidate":
                # Payload loads are unusable until the corresponding success
                # edge promoted the helper/Option memory fact.
                state.pop(reg(dst), None)
        if pc not in consumer.maps and (match := re.fullmatch(r"([rw]\d+) (=|\+=|<<=|>>=|&=|\|=) ([rw]\d+|-?0x[0-9a-f]+)(?: ll)?", text)):
            dst, op, src = match.groups()
            old, rhs = before.get(reg(dst)), value(before, src)
            fact = None
            if op == "=" and rhs:
                fact = narrow(rhs, 32) if dst.startswith("w") else rhs
            elif op == "+=" and old == ("result", "map"):
                # Offset selection within a BPF map value cannot turn its
                # address space into the local frame's address space.
                fact = old
            elif old and rhs:
                if old[0] == rhs[0] == "constant":
                    a, b = old[1], rhs[1]
                    fact = ("constant", {"+=": lambda: a+b, "<<=": lambda: a<<b,
                            ">>=": lambda: a>>b, "&=": lambda: a&b, "|=": lambda: a|b}[op]() & ((1 << 64)-1))
                elif rhs[0] == "constant":
                    amount = rhs[1]
                    if old[0] == "field" and op == "&=" and amount == 255:
                        fact = old
                    elif old[0] == "field" and op == "<<=":
                        fact = ("stride", old[1], 1 << amount, 0, None)
                    elif old[0] == "stride" and op == "+=":
                        fact = (*old[:3], old[3] + amount, old[4])
                    elif old[0] == "stride" and op == "&=":
                        fact = (*old[:4], amount)
                    elif old == ("rsp", 64, 0) and op == "<<=" and amount == 32:
                        fact = ("rsp_shift",)
                    elif old == ("rsp_shift",) and op == ">>=" and amount == 32:
                        fact = ("rsp", 32, 0)
                    elif old[0] == "rsp" and op == "+=":
                        fact = ("rsp", old[1], old[2] + amount)
                    elif old[0] == "owned" and op == "+=":
                        fact = ("owned", old[1], old[2] + amount)
                elif old == ("rsp", 32, 0) and rhs[0] == "stride" and op == "+=":
                    fact = ("arg_address", rhs)
            if fact is not None:
                state[reg(dst)] = fact
        if pc in self.calls:
            role = self.calls[pc]
            field = field_number(role)
            require(target.endswith("capture_scalar"), error("scalar-read callee missing or changed"))
            require(before.get("r2") == ("context", 0), error("scalar-read context argument"))
            require(before.get("r4") == ("constant", self.abi), error("layout argument does not match admitted ABI"))
            require(before.get("r5") == self.start, error("scalar-read START argument"))
            index = before.get("r3")
            require(index == (("field", field) if self.present else ("constant", 255)),
                    error(f"scalar-read expected descriptor field {field}, got {index}"))
            pointer = before.get("r1")
            require(pointer and pointer[0] == "stack", error("scalar-read Option destination"))
            state[("stack", pointer[1], 8)] = ("option", pc, field)
            if self.present:
                state[("stack", pointer[1]+8, 8)] = ("candidate", pc, field, 32 if self.abi else 64)
            else:
                state[("stack", pointer[1], 8)] = ("constant", 0)
        if pc in self.helpers:
            field = self.helpers[pc]
            require(pc in consumer.helper and text == "call 0x70", error("scalar-read user helper missing"))
            source = before.get("r3")
            domain = self.domain(before, field)
            expected = ("arg_address", ("stride", field, 4, 4, 0xfc)) if self.abi else ("rsp", 64, 8)
            require(source == expected and domain <= set(range(7)) and (self.abi or domain == {6}),
                    error(f"scalar-read RSP/index/stride source {source}, domain {sorted(domain)}"))
            require(before.get(("span", source)) is True, error("scalar-read complete address span not proved"))
            size, output = before.get("r2"), before.get("r1")
            require(size == ("constant", 4 if self.abi else 8), error("scalar-read helper width"))
            require(output and output[0] == "stack", error("scalar-read output address"))
            require(-512 <= output[1] and output[1]+size[1] <= 0, error("scalar-read output outside local frame"))
            state[("stack", output[1], size[1])] = ("candidate", pc, field, size[1]*8)
            state["r0"] = ("read_result", pc, field)
        if pc in consumer.helper and text == "call 0x1":
            if before.get("r1", (None,))[0] == "map" and before["r1"][1] not in ("DESCRIPTORS", "ASYNC_FUNCTIONS"):
                # Different counter-map lookups join at shared writebacks;
                # retain their common disjointness from the local frame.
                state["r0"] = ("result", "map")
            if before.get("r1") == ("map", "DESCRIPTORS") and not self.present:
                state["r0"] = ("constant", 0)
            if before.get("r1") == ("map", "ASYNC_FUNCTIONS"):
                if self.role == 16:
                    require(before.get(("string_low",)) and before.get(("string_high",)),
                            error("async user-string success/length bounds"))
                state["r0"] = ("function_value", pc, 0)
        if target == "p11_owner_start_get":
            state["r0"] = ("owned", pc, 0)
        if target == "p11_owner_start_remove":
            for key in list(state):
                if isinstance(key, tuple) and key[0] == "live":
                    del state[key]
        if target == "p11_owner_start_insert":
            state["r0"] = ("insert_result", pc)
        if target.endswith("capture_async_target"):
            require(self.mode == 0 and before.get("r1") == ("context", 0)
                    and before.get("r2") == ("field", 16)
                    and before.get("r3") == ("constant", self.abi)
                    and before.get("r4") == self.start, error("async target field/layout/START boundary"))
            if self.role == 16:
                # Conditional-success summary of the independently checked
                # callee. Only its successful selection creates this obligation.
                state[("stack", self.start[1]+0x104, 4)] = ("selected", 16)
                self.captured(state)
        if text == "call 0x72" and self.role == 16:
            require(before.get("r3") == self.scalar(16) and before.get(("nonnull",)) is True
                    and before.get("r2") == ("constant", 29), error("async name pointer/nonzero/read bound"))
            output = before.get("r1")
            require(output and output[0] == "stack" and -512 <= output[1] and output[1]+29 <= 0,
                    error("async name output outside local frame"))
            self.boundaries.add("async_name")
            state["r0"] = ("string_result", pc)
            state.pop(("string_low",), None)
            state.pop(("string_high",), None)
        if target == "p11_decode_params":
            require(self.kind == "entry" and self.mode != "second"
                    and before.get("r3") == ("constant", 4 if self.abi else 8)
                    and before.get("r4") == ("stack", self.start[1]+0x40), error("layout/decoder word bytes or output"))
            if self.role == 8:
                require(before.get("r1") == self.scalar(8) and before.get(("nonnull",)) is True,
                        error("decoder mechanism field 8 pointer"))
                self.boundaries.add("decoder")
        if target == "p11_walk_template" or "walk_template_types" in target:
            ordinary = target == "p11_walk_template"
            require((ordinary and self.mode in (1, 3, "second")) or (not ordinary and self.mode == 2), error("mode walker callee"))
            if ordinary:
                destination = (("owned", self.start[1], 0xb0) if self.mode == "second"
                               else ("stack", self.start[1]+0x60))
                require(before.get("r3") == ("constant", 4 if self.abi else 8)
                        and before.get("r4") == destination, error("mode walker word bytes/output/owned START"))
            else:
                require(f"walk_template_typesKb{self.abi}_" in target
                        and before.get("r3") == self.start, error("mode types layout/whole START"))
            if self.role == "template":
                ptr, count = (14, 15) if self.mode == "second" else (12, 13)
                require(before.get("r1") == self.scalar(ptr) and before.get("r2") == self.scalar(count),
                        error("mode walker ptr/count fields"))
                require(before.get(("success",)), error("mode walker lacks successful capture"))
                state[("done",)] = True
                self.witnesses.add(pc)
        if text == "call 0xc" and pc in consumer.helper:
            require(self.mode == 3 and before.get(("inserted",)) is True
                    and before.get("r1") == ("context", 0)
                    and before.get("r2") == ("map", "TAIL_CALLS")
                    and before.get("r3") == ("constant", 1), error("mode pair tail needs successful insertion and slot 1"))
            self.boundaries.add("tail")
        if self.kind == "return" and pc in self.retained_sites:
            offset, lifecycle, abi = self.retained_sites[pc]
            require(text == "call 0x70" and pc in consumer.helper
                    and self.abi == abi and before.get("r2") == ("constant", 4 if abi else 8), error("retained helper/layout/width"))
            require(before.get("r3") == ("retained", offset, 64), error("retained pointer source/lifetime"))
            if lifecycle is not None:
                require(self.domain(before, 3) == {lifecycle}, error("retained lifecycle field 3"))
            self.boundaries.add(pc)
        if self.kind == "scalar" and text == "exit":
            expected = 1 if before.get(("success",)) else 0
            require(stack_read(before, self.start, 8) == ("constant", expected), error("scalar-read Option discriminator"))
            if expected:
                require(stack_read(before, self.start, 8, 8) == self.scalar(), error("scalar-read Option success payload"))
                self.witnesses.add(pc)
        elif pc == self.insert:
            self.check_sink(consumer, pc, before)
            # The final value was checked at the insertion boundary. Later
            # scratch writes cannot retroactively corrupt that copied value.
            state[("success",)] = False
        elif self.kind in ("entry", "async") and text == "exit":
            # A successful read cannot evade its store by taking an early exit
            # while other indices provide the positive insertion witness.
            self.check_sink(consumer, pc, before)
        return state

    def edges(self, consumer, pc, before, after):
        text = consumer.text[pc]
        branch = BRANCH.fullmatch(text)
        for successor in consumer.graph[pc]:
            state = after.copy()
            if branch:
                left, op, right = value(before, branch[1]), branch[2], value(before, branch[3])
                width = 32 if branch[1].startswith("w") else 64
                require(branch[3][0] not in "rw" or branch[1][0] == branch[3][0],
                        self.fail(consumer, pc, "mixed branch operand widths"))
                if width == 32:
                    # A low32 predicate cannot refine a full pointer or an
                    # address formed by adding an offset to normalized RSP.
                    # Admit only facts independently bounded to 32 bits;
                    # constants are truncated by compare, never assumed equal
                    # to their full-register value. Option is the proved 0/1
                    # discriminator, not an unconstrained helper return value.
                    for fact in (left, right):
                        require(not fact or fact[0] in ("constant", "field", "option", "low", "high", "selected")
                                or fact[0] in ("scalar", "retained") and fact[2] == 32
                                or fact == ("rsp", 32, 0),
                                self.fail(consumer, pc, f"branch width 32 cannot refine full-width fact {fact}"))
                taken = successor == D.relative_target(pc, text)
                zero_taken = zero_partition(left, op, width) if left and right == ("constant", 0) else None
                if left and right and left[0] == right[0] == "constant":
                    if compare(left[1], op, right[1], width) != taken:
                        continue
                elif left and right and left[0] == "field" and right[0] == "constant":
                    domain = frozenset(n for n in self.domain(before, left[1]) if compare(n, op, right[1], width) == taken)
                    if not domain:
                        continue
                    state[("domain", left[1])] = domain
                    if left[1] == 3 and self.lifecycle is not None:
                        if self.lifecycle not in domain:
                            state[("life",)] = False
                        elif domain == {self.lifecycle}:
                            state[("life",)] = True
                elif left and right and left[0] == "descriptor" and right == ("constant", 0):
                    if zero_taken is not None and taken == zero_taken:
                        continue
                elif left and right and left[0] in ("option", "read_result", "insert_result") and right[0] == "constant":
                    require(op in ("==", "!=") and right[1] in ((0, 1) if left[0] == "option" else (0,)),
                            self.fail(consumer, pc, "unsupported success comparison"))
                    success_value = 1 if left[0] == "option" else 0
                    success = compare(success_value, op, right[1], width) == taken
                    # Both outcomes are possible, but their memory provenance
                    # differs. Failure never promotes a helper output.
                    if success:
                        if left[0] == "option":
                            domain = self.domain(before, left[2]) & frozenset(range(7))
                            if not domain:
                                continue
                            state[("domain", left[2])] = domain
                        if left[0] == "read_result":
                            # Invocation alone is not evidence of a usable
                            # argument. In particular, indices 0..5 must not
                            # hide a deleted LP64 index-6 success branch.
                            self.read_witnesses |= self.domain(before, left[2])
                        for key, fact in list(state.items()):
                            if isinstance(fact, tuple) and fact[:2] == ("candidate", left[1]):
                                state[key] = ("scalar", fact[2], fact[3])
                        if left[0] == "insert_result":
                            if left[1] == self.insert:
                                state[("inserted",)] = True
                        elif (left[0] == "read_result" or self.role != 16 and self.calls.get(left[1]) == self.role
                              or self.role == "template" and left[2] in (13, 15)):
                            self.captured(state)
                    else:
                        for key, fact in list(state.items()):
                            if isinstance(fact, tuple) and fact[:2] == ("candidate", left[1]):
                                del state[key]
                elif left and left[0] in ("owned", "function_value") and zero_taken is not None:
                    if taken != zero_taken:
                        state[("live", left[1])] = True
                    else:
                        for key, fact in list(state.items()):
                            if fact == left:
                                state[key] = ("constant", 0)
                if self.role in (8, 16) and left == self.scalar() and zero_taken is not None:
                    state[("nonnull",)] = taken != zero_taken
                # Exact unsigned complete-span edges of the admitted forms.
                if left == ("rsp", 64, 0) and right == ("constant", -16) and op == ">" and not taken:
                    state[("span", ("rsp", 64, 8))] = True
                if left and left[0] == "arg_address" and right == ("constant", 0xfffffffc) and op == ">" and not taken:
                    state[("span", left)] = True
                if left == ("constant", 0xfffffffd) and right and right[0] == "arg_address" and op == ">" and taken:
                    state[("span", right)] = True
                if right and right[0] == "string_result" and op == "s>":
                    if left == ("constant", 1) and not taken:
                        state[("string_low",)] = True
                    if left == ("constant", 29) and taken:
                        state[("string_high",)] = True
            yield successor, state

    def finish(self, consumer):
        if self.present and self.role not in ("return", "mode"):
            require(self.witnesses, consumer.name + f": final-sink {self.role}: no positive successful sink witness")
        if self.present and (self.reads or self.helpers):
            require(self.read_witnesses == set(range(7)), consumer.name + f": scalar-read {self.role}: incomplete index coverage")
        if self.present and self.decoder_required:
            require("decoder" in self.boundaries, consumer.name + ": final-sink decoder: no positive boundary witness")
        if self.present and self.role == 16 and (self.kind == "async" or 16 in self.calls.values()):
            require("async_name" in self.boundaries, consumer.name + ": final-sink async name boundary missing")
        if self.mode == 3:
            require("tail" in self.boundaries, consumer.name + ": final-sink mode pair: tail boundary missing")


def scalar_body_contract(internal_blocks, internal_calls, variant):
    names = [name for name in internal_blocks if name.endswith("capture_scalar")]
    require(len(names) == 1, "scalar-read callee inventory")
    name = names[0]
    consumer = Consumer(".text", name, internal_blocks[name], internal_calls.get(name, {}))
    delta = 252 if variant == "unsafe" else 0
    reads = {pc+delta: index for index, pc in enumerate((938, 944, 900, 940, 906, 942))}
    for abi in (0, 1):
        proof = SinkProof(6, abi, True, ("stack", -0x1000), kind="scalar",
                          reads=reads if abi == 0 else {}, helpers={(890 if abi else 918)+delta: 6})
        proof.effect_start = ("stack", -0x2000)
        initial = {"r1": proof.start, "r2": ("context", 0), "r3": ("field", 6),
                   "r4": ("constant", abi), "r5": ("stack", -0x2000), "r10": ("stack", 0),
                   ("domain", 6): BYTE_DOMAIN}
        consumer.facts(initial, proof)
    if variant == "unsafe":
        names = [name for name in internal_blocks if name.endswith("capture_async_target")]
        require(len(names) == 1, "final-sink async callee inventory")
        name = names[0]
        consumer = Consumer(".text", name, internal_blocks[name], internal_calls.get(name, {}))
        for abi in (0, 1):
            proof = SinkProof(16, abi, True, ("stack", -0x1000), calls={1208: 16}, kind="async")
            proof.effect_start = proof.start
            initial = {"r1": ("context", 0), "r2": ("field", 16), "r3": ("constant", abi),
                       "r4": proof.start, "r10": ("stack", 0), ("domain", 16): BYTE_DOMAIN}
            consumer.facts(initial, proof)


def final_sink_contract(consumer, variant, selectors, internal_blocks, internal_calls):
    name = consumer.name
    key = "default" if variant == "default" else name
    if name == "p11_return":
        return retained_contract(consumer, variant, selectors)
    mode = {"p11_entry_template": 1, "p11_entry_template_pair": 3,
            "p11_entry_template_types": 2, "p11_entry_template_second": "second"}.get(name, 0)
    start = (("owned", 3268, 0) if mode == "second" else
             ("stack", -0x168 if variant == "default" else -0x130 if name == "p11_entry" else -0x128))
    roles = ["template"] if mode == "second" else [6, 7, 10, 11, 8, 9]
    roles += [16, "join", "get"] if mode == 0 else ([] if mode == "second" else ["template"])
    for selector in selectors:
        abi = int(selector == 0x23)
        for present in (False, True):
            for role in roles:
                reads, helpers = {}, {}
                if variant == "unsafe" and name == "p11_entry" and role in LP64_READS:
                    locations, helper = LP64_READS[role]
                    reads = {pc: index for index, pc in enumerate(locations)}
                    helpers = {helper: field_number(role)}
                elif name == "p11_entry_ia32" and role in IA32_READS:
                    helpers = {IA32_READS[role]: field_number(role)}
                proof = SinkProof(role, abi, present, start, calls=SCALAR_CALLS.get(key),
                                  reads=reads, helpers=helpers, insert=SEMANTIC_INSERT.get(key), mode=mode)
                proof.dispatches = (LP64_DISPATCH if name == "p11_entry" else IA32_DISPATCH).get(role, ()) if variant == "unsafe" and name in ("p11_entry", "p11_entry_ia32") else ()
                proof.decoder_required = variant == "unsafe" and role == 8
                consumer.facts(proof=proof)
    return {"roles": roles, "mode": mode, "scenarios": len(selectors)*2}


def retained_contract(consumer, variant, selectors):
    # Return copies these scalars while START is owned, before removal. They
    # are retained values, never permission to reuse the removed map pointer.
    delta = int(variant == "unsafe")
    sites = {1297+delta: (0x30, 1, 1), 1370+delta: (0x30, 1, 0),
             1344+delta: (0x20, None, 1), 1379+delta: (0x20, None, 0),
             1531+delta: (0x30, 12, 1), 1552+delta: (0x30, 12, 0)}
    for selector in selectors:
        abi = int(selector == 0x23)
        for present in (False, True):
            proof = SinkProof("return", abi, present, None, kind="return")
            proof.retained_sites = sites
            consumer.facts(proof=proof)
            if present:
                require(proof.boundaries == {pc for pc, (_, _, layout) in sites.items() if layout == abi},
                        consumer.name + ": retained read inventory/layout differs")
    return {"retained_offsets": [0x20, 0x30], "scenarios": len(selectors)*2}


def descriptor_contract(consumer, facts, lookup):
    """Check every materialized field at the null/non-null merge boundary."""
    pcs = [pc for pc, _ in consumer.insns]
    state = consumer.step(lookup, facts[lookup])
    index = pcs.index(lookup) + 1
    while index < len(pcs) and not consumer.text[pcs[index]].startswith(("if ", "goto ", "call ", "exit")):
        state = consumer.step(pcs[index], state)
        index += 1
    branch = pcs[index]
    match = re.fullmatch(r"if (r\d+) == 0x0 goto \+0x[0-9a-f]+", consumer.text[branch])
    require(match and state.get(match[1]) == ("descriptor", lookup), consumer.label(branch) + ": descriptor null guard")
    join = D.relative_target(branch, consumer.text[branch])
    nonnull = state.copy()
    loads = set()
    for pc in pcs[index + 1:pcs.index(join)]:
        text = consumer.text[pc]
        require(not text.startswith(("if ", "goto ", "call ", "exit")), consumer.label(pc) + ": descriptor merge is not finite")
        match = LOAD.fullmatch(text)
        if match:
            pointer = address(nonnull, match[3], match[4], match[5])
            require(pointer and pointer[:2] == ("descriptor", lookup) and match[2] == "8", consumer.label(pc) + ": descriptor field provenance")
            loads.add(pointer[2])
        nonnull = consumer.step(pc, nonnull)
    expected = ({3} if consumer.name == "p11_return" else {14, 15}
                if consumer.name == "p11_entry_template_second" else BASE_FIELDS | ({12, 13}
                if "template" in consumer.name else {16, 17}))
    require(loads == expected, consumer.label(lookup) + f": descriptor fields {loads}, expected {expected}")
    carried = set()
    for key, fact in nonnull.items():
        if fact[0] != "field":
            continue
        # Ignore a register temporary killed before its first subsequent use.
        if isinstance(key, str):
            live = False
            for following in pcs[pcs.index(join):]:
                text = consumer.text[following]
                rhs = re.sub(r"^[rw]\d+ = ", "", text)
                if re.search(rf"\b{key}\b", rhs):
                    live = True
                    break
                if text.startswith("call ") and int(key[1:]) < 6:
                    live = int(key[1:]) > 0 and text not in ("call 0x5", "call 0xe")
                    break
                if re.match(rf"{key} =", text):
                    break
                if text.startswith(("if ", "goto ", "exit")):
                    live = True
                    break
            if not live:
                continue
        carried.add(fact[1])
        fallback = 0 if fact[1] < 6 else 255
        require(state.get(key) == ("constant", fallback), consumer.label(join) + f": COUNT_ONLY field {fact[1]} at {key}")
    require(carried == expected, consumer.label(join) + ": descriptor fields lost at merge")
    return sorted(expected)


def abi_contract(consumer, facts, variant):
    selectors = [pc for pc, text in consumer.insns if (m := LOAD.fullmatch(text))
                 and address(facts.get(pc, {}), m[3], m[4], m[5]) == ("context", 0x88)]
    require(len(selectors) == 1, consumer.name + ": selector load inventory")
    start = selectors[0]
    # The scenario proof below is valid only if genuine entry cannot bypass
    # this selector load on the way to any observation or admission site.
    bypass = D.reachable(consumer.graph, [consumer.insns[0][0]], blocked={start})
    observations = set()
    for pc, text in consumer.insns:
        state = facts.get(pc, {})
        target = consumer.calls.get(pc)
        if ((pc in consumer.helper and state.get("r1", (None, None))[0] == "map"
             and state["r1"][1] in ("STATS", "RV_COUNTS", "DESCRIPTORS", "EVENTS"))
                or target in ("p11_owner_start_get", "p11_owner_start_insert")
                or (target == "p11_owner_start_remove" and state.get("r2") == ("constant", 1))):
            observations.add(pc)
        match = LOAD.fullmatch(text)
        if match:
            pointer = address(state, match[3], match[4], match[5])
            if pointer and pointer[0] == "context" and pc != start:
                observations.add(pc)
    require(observations and not (observations & bypass), consumer.name + ": entry path bypasses ABI selector before observation/admission")
    accepted = {0x23, 0x33}
    if variant == "unsafe" and consumer.name == "p11_entry":
        accepted = {0x33}
    if consumer.name == "p11_entry_ia32":
        accepted = {0x23}
    for selector in (0, 0x23, 0x33):
        state = consumer.step(start, facts[start])
        state[reg(LOAD.fullmatch(consumer.text[start])[1])] = ("selector_case", selector)
        pending = [(consumer.graph[start][0], state, False, False, frozenset())]
        visited = set()
        admitted = False
        while pending:
            pc, state, cleaned, refused, ancestors = pending.pop()
            require(pc not in ancestors, consumer.label(pc) + ": cyclic ABI prefix")
            signature = (pc, repr(sorted(state.items(), key=lambda p: repr(p[0]))), cleaned, refused)
            if signature in visited:
                continue
            visited.add(signature)
            text, target = consumer.text[pc], consumer.calls.get(pc)
            map_name = state.get("r1")
            admission = (text == "call 0x1" and map_name == ("map", "STATS")) or target in ("p11_owner_start_get", "p11_owner_start_insert")
            if admission:
                require(selector in accepted and not refused, consumer.label(pc) + ": ABI refusal reaches admission")
                admitted = True
                continue
            if target == "p11_owner_start_remove":
                require(state.get("r2") == ("constant", 0), consumer.label(pc) + ": refusal cleanup must be optional")
                cleaned = True
            elif text == "call 0x1" and map_name == ("map", "EVIDENCE"):
                require(cleaned and stack_read(state, state.get("r2"), 4) == ("constant", 8), consumer.label(pc) + ": ABI refusal evidence key/order")
                require(D.counter_writeback_contract(consumer.lines, pc), consumer.label(pc) + ": ABI refusal counter update")
                refused = True
            elif text.startswith("call "):
                require(False, consumer.label(pc) + ": unexpected helper before ABI admission")
            if m := LOAD.fullmatch(text):
                pointer = address(state, m[3], m[4], m[5])
                require(not pointer or pointer[0] != "context", consumer.label(pc) + ": argument read before ABI admission")
            if text == "exit":
                require(selector not in accepted and cleaned and refused, consumer.label(pc) + ": ABI exit lacks cleanup/refusal")
                continue
            after = consumer.step(pc, state)
            edges = consumer.graph[pc]
            branch = re.fullmatch(r"if (r\d+) (==|!=) (-?0x[0-9a-f]+) goto [+-]0x[0-9a-f]+", text)
            if branch and state.get(branch[1], (None,))[0] == "selector_case":
                immediate = int(branch[3], 16)
                require(immediate in (0x23, 0x33), consumer.label(pc) + ": unsupported selector comparison")
                taken = (selector == immediate) == (branch[2] == "==")
                edges = [D.relative_target(pc, text)] if taken else [e for e in edges if e != D.relative_target(pc, text)]
            for successor in edges:
                pending.append((successor, after.copy(), cleaned, refused, ancestors | {pc}))
        require(admitted == (selector in accepted), consumer.name + ": selector acceptance differs")
    return sorted(accepted)


def incoming_parameter_unused(lines, parameter):
    """Prove the compiled callee kills an incoming parameter before any use.

    Default START get has no required argument after optimization. This narrow
    check examines every entry path up to the first definition, never the
    native owner's transaction semantics.
    """
    insns, graph = D.instruction_graph(lines)
    texts = dict(insns)
    pending, seen = [insns[0][0]], set()
    while pending:
        pc = pending.pop()
        if pc in seen:
            continue
        seen.add(pc)
        text = texts[pc]
        rhs = re.sub(r"^[rw]\d+ = ", "", text)
        if re.search(rf"\b[rw]{parameter}\b", rhs) or text.startswith("call "):
            return False
        if re.match(rf"[rw]{parameter} =", text) or text == "exit":
            continue
        pending.extend(graph[pc])
    return True


def operation_contract(consumer, facts, variant, internal_blocks):
    """Require distinct, reachable operations and their complete caller keys."""
    identity = (consumer.section, consumer.name)
    reachable = D.reachable(consumer.graph, [consumer.insns[0][0]])
    owner, maps, keys, values, records = [], Counter(), set(), set(), []
    for pc, text in consumer.insns:
        state = facts.get(pc, {})
        target = consumer.calls.get(pc, "")
        if target.startswith("p11_owner_start_"):
            require(pc in reachable, consumer.label(pc) + ": unreachable START operation")
            key = state.get("r1")
            require(key and key[0] == "stack", consumer.label(pc) + ": START key address")
            require(stack_read(state, key, 8) == ("pid_tgid", identity), consumer.label(pc) + ": START pid_tgid provenance")
            require(stack_read(state, key, 4, 8) == ("low", identity), consumer.label(pc) + ": START slot provenance")
            require(stack_read(state, key, 4, 12) == ("constant", 0), consumer.label(pc) + ": START zero padding")
            keys.add(key)
            operation = target.removeprefix("p11_owner_start_")
            argument = state.get("r2")
            if operation == "insert":
                require(argument and argument[0] == "stack" and argument != key, consumer.label(pc) + ": START value address")
                require(stack_read(state, argument, 8) == ("ktime_ns", identity), consumer.label(pc) + ": START value timestamp provenance")
                values.add(argument)
                role = "insert"
            elif operation == "get" and variant == "default":
                require(incoming_parameter_unused(internal_blocks[target], 2), "default START get retains an unexpected required argument")
                role = "get0-specialized"
            else:
                require(argument in (("constant", 0), ("constant", 1)), consumer.label(pc) + ": START required argument")
                role = operation + str(argument[1])
            owner.append(role)
            records.append((pc, "START." + role))
        if pc in consumer.helper:
            name = state.get("r1", (None, None))
            if name[0] == "map" and name[1] in ("STATS", "RV_COUNTS", "DESCRIPTORS", "EVENTS"):
                operation = (name[1], text)
                require(pc in reachable, consumer.label(pc) + ": unreachable map operation")
                maps[operation] += 1
                records.append((pc, name[1] + "." + text))
            if text == "call 0x84":
                require(state.get("r1") == ("event", 0), consumer.label(pc) + ": submitted event address")
                require(state.get(("event_slot",)) == ("low", identity), consumer.label(pc) + ": Event.slot corrupted before submit")
                maps[("EVENTS", text)] += 1
                records.append((pc, "EVENTS.submit"))
    name = consumer.name
    if name == "p11_return":
        expected_owner = ["remove0", "remove0", "get0-specialized" if variant == "default" else "get0", "remove1"]
    elif name == "p11_entry_template_second":
        expected_owner = ["remove0", "get1"]
    else:
        expected_owner = ["remove0", "insert", "remove0", "insert"]
        if variant == "unsafe" and name in ("p11_entry", "p11_entry_ia32"):
            expected_owner.insert(1, "remove0")
    expected_maps = Counter({("DESCRIPTORS", "call 0x1"): 1})
    if name != "p11_entry_template_second":
        expected_maps[("STATS", "call 0x1")] = 1
    if name == "p11_return":
        expected_maps.update({("RV_COUNTS", "call 0x1"): 1, ("RV_COUNTS", "call 0x2"): 1,
                              ("EVENTS", "call 0x83"): 1, ("EVENTS", "call 0x84"): 1})
    require(owner == expected_owner, name + f": START operation inventory {owner}, expected {expected_owner}")
    require(maps == expected_maps, name + ": distinct map operation inventory differs")
    require(len(keys) == 1 and len(values) == (1 if "insert" in expected_owner else 0), name + ": START operation key/value wiring differs")
    return records


def contract(disassembly, variant):
    require(variant in ("default", "unsafe"), "unknown variant")
    split = sections(disassembly)
    require(".text" in split, "missing internal text section")
    internal_blocks = D.function_blocks(split[".text"])
    internal_calls = {}
    for caller, _, pc, target in D.internal_call_targets(split[".text"]):
        internal_calls.setdefault(caller, {})[pc] = target
    scalar_body_contract(internal_blocks, internal_calls, variant)
    expected = {"p11_entry", "p11_return"}
    if variant == "unsafe":
        expected |= {"p11_entry_ia32", "p11_entry_template", "p11_entry_template_pair", "p11_entry_template_second", "p11_entry_template_types"}
    report = {}
    for section in ("uprobe", "uretprobe"):
        require(section in split, "missing " + section)
        # .text comes last so equal PCs in unrelated ELF sections cannot replace
        # the relocation target table of the shared primitive.
        calls = D.internal_call_targets(split[section] + "\n" + split[".text"])
        for name, lines in D.function_blocks(split[section]).items():
            if not (name.startswith("p11_entry") or name == "p11_return"):
                continue
            consumer = Consumer(section, name, lines, {pc: target for caller, _, pc, target in calls if caller == name})
            facts = consumer.facts()
            identity = (section, name)
            sinks = []
            descriptor = []
            bounds = []
            for pc, text in consumer.insns:
                state = facts.get(pc, {})
                target = consumer.calls.get(pc, "")
                map_name = state.get("r1", (None, None))
                if match := re.fullmatch(r"if (r\d+) > 0x1ff goto [+-]0x[0-9a-f]+", text):
                    require(state.get(match[1]) == ("low", identity), consumer.label(pc) + ": slot bound uses cookie low word")
                    bounds.append(pc)
                if pc in consumer.helper and text in ("call 0x1", "call 0x2") and map_name[0] == "map":
                    if map_name[1] in ("STATS", "RV_COUNTS", "DESCRIPTORS"):
                        word = "high" if map_name[1] == "DESCRIPTORS" else "low"
                        require(stack_read(state, state.get("r2"), 4) == (word, identity), consumer.label(pc) + ": " + map_name[1] + " cookie key")
                        sinks.append((pc, map_name[1]))
                        if word == "high":
                            descriptor.append(pc)
                if target.startswith("p11_owner_start_"):
                    require(stack_read(state, state.get("r1"), 4, 8) == ("low", identity), consumer.label(pc) + ": START slot cookie")
                    sinks.append((pc, "START"))
                if match := STORE.fullmatch(text):
                    pointer = address(state, match[2], match[3], match[4])
                    if pointer == ("event", 0x68):
                        require(match[1] == "32" and narrow(value(state, match[5]), 32) == ("low", identity), consumer.label(pc) + ": Event.slot cookie")
                        sinks.append((pc, "Event.slot"))
            required = {"DESCRIPTORS", "START"}
            if name != "p11_entry_template_second":
                required.add("STATS")
            if name == "p11_return":
                required |= {"RV_COUNTS", "Event.slot"}
            require({sink for _, sink in sinks} == required, name + ": sink inventory differs")
            require(len(bounds) == 1, name + ": slot bound inventory")
            require(len(descriptor) == 1, name + ": descriptor lookup inventory")
            fields = descriptor_contract(consumer, facts, descriptor[0])
            selectors = abi_contract(consumer, facts, variant)
            operations = operation_contract(consumer, facts, variant, internal_blocks)
            final_sinks = final_sink_contract(consumer, variant, selectors, internal_blocks, internal_calls)
            report[name] = {"section": section, "sinks": sinks, "operations": operations,
                            "descriptor_fields": fields, "accepted_selectors": selectors,
                            "final_sinks": final_sinks}
    require(set(report) == expected, "consumer inventory differs")
    return {
        "schema": SCHEMA,
        "variant": variant,
        "status": "partial",
        "verified": {
            "cookie_sink_provenance": True,
            "descriptor_materialization": True,
            "abi_refusal_before_admission": True,
            "distinct_operations_and_full_start_key": True,
            "event_slot_through_submit": True,
        },
        "unproved": ["selected decoder layout after admission", "template mode specialization",
                     "descriptor field-to-final-argument wiring after the null/non-null merge"],
        "consumers": report,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=("default", "unsafe"))
    args = parser.parse_args()
    D.map_checker()["Elf"](args.object.read_bytes())
    disassembly = subprocess.run(["llvm-objdump", "-dr", "--print-imm-hex", str(args.object)], capture_output=True, text=True, check=True).stdout
    print(json.dumps(contract(disassembly, args.variant), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
