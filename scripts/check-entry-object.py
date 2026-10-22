#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
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
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_sibling


D = load_sibling("check-live-discovery-object.py")
SPAN = load_sibling("check-bpf-map-defs.py")
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
        if fact[0] in ("scalar", "retained"):
            return (fact[0], fact[1], 32)
        if fact[0] == "key_tail":
            return ("low", fact[1])
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
    if fact[0] in ("function_value", "external_key"):
        return (fact[0], fact[1], fact[2] + delta)
    return None


def join_fact(left, right):
    """Must-join of one register/stack fact. Different map-helper lookups can
    join at one shared counter writeback (as in SinkProof's ("result",
    "map")): the joined pointer is still a map value disjoint from the local
    frame; only which lookup produced it is forgotten."""
    if left == right:
        return left
    if left and right and left[0] == right[0] == "result":
        return ("result", "map")
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
    base = state.get("r" + match[2]) if match else None
    if pointer and pointer[0] == "stack":
        forget_stack(state, pointer[1], int(match[1]) // 8)
    elif pointer and pointer[0] == "event":
        forget_event_slot(state, pointer[1], int(match[1]) // 8)
    elif pointer is None and base is not None and base[0] == "result":
        # As for plain stores: a map helper's result (a counter or gate cell)
        # is disjoint from the BPF frame and the reserved event.
        return
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


def capture_read(state, pointer, size, offset=0):
    if pointer and pointer[0] == "owned":
        for key, fact in state.items():
            if (isinstance(key, tuple) and key[:3] == ("owned_word", pointer[1], pointer[2]+offset)
                    and key[3] >= size):
                return narrow(fact, size*8)
        return None
    return stack_read(state, pointer, size, offset)


def capture_pointer(pointer, offset):
    return ("owned", pointer[1], pointer[2]+offset) if pointer[0] == "owned" else ("stack", pointer[1]+offset)


def forget_owned(state, owner=None, offset=0, size=0x1000):
    for key in list(state):
        if (isinstance(key, tuple) and key[0] == "owned_word" and (owner is None or key[1] == owner)
                and key[2] < offset+size and offset < key[2]+key[3]):
            del state[key]


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
            elif target == "p11_instance_return":
                # Task 3 Stage A: fills the 40-byte private continuity tail
                # (EventRecord offset 328) through its second argument.
                output = ("r2", 40)
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
                if op == "+=" and old and old[0] == "result":
                    # As in SinkProof: offset selection within a BPF map value
                    # (a verifier-bounded histogram index, say) cannot turn its
                    # address space into the local frame's.
                    fact = ("result", "map")
                elif old and fact and fact[0] == "constant":
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
                merged = state.copy() if previous is None else {
                    k: joined for k, v in previous.items()
                    if (joined := join_fact(v, state.get(k))) is not None}
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
BYTE_DOMAIN = frozenset(range(256))
# TAIL_CALLS_NO_PRIVATE_STACK_INDEX: an index no slot of TAIL_CALLS,
# STACK_GUARD, or PAIR_CALLS has (always falls through).
NO_PRIVATE_STACK_INDEX = 0xFFFFFFFF
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
        self.argument_calls = {}
        self.success_tag = 0 if kind == "result" else 1

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
            actual = capture_read(state, self.start, size, offset)
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
                allowed = set() if self.kind == "result" else {(self.effect_start[1]+0x100, 4)}
                if self.kind == "async":
                    allowed.add((self.effect_start[1]+0x104, 4))
                else:
                    allowed |= {(self.start[1], 8), (self.start[1]+8, 8)}
                require((pointer[1], int(match[1])//8) in allowed, error("callee START/Option write footprint"))
            source = value(before, match[5])
            if pointer and pointer[0] == "stack" and source \
                    and source[0] == "read_result":
                if before.get(("read_ok", source[1])):
                    state[("stack", pointer[1], int(match[1])//8)] = self.scalar(width=32)
                    self.captured(state)
                else:
                    state[("stack", pointer[1], int(match[1])//8)] = \
                        ("candidate", source[1], source[2], 32)
        if self.effect_start and ("atomic" in text or "xchg" in text or text.startswith("lock ")):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(before, *match.groups()[1:]) if match else None
            # As for plain stores: a map helper's result is disjoint from the
            # BPF frame, so a non-fetch counter add through it (loss evidence)
            # cannot touch a saved sink. Fetch forms also write a register.
            counter = (text.startswith("lock ") and match is not None and pointer is None
                       and before.get("r" + match[2], (None,))[0] == "result")
            require(counter or (pointer and pointer[0] == "stack" and -512 <= pointer[1] < 0),
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
            elif self.kind == "return" and pointer and pointer[0] == "owned" and before.get(("live", pointer[1])):
                state[reg(dst)] = ("retained", pointer[2], int(width))
            elif pointer and pointer[0] == "function_value" and pointer[2] == 0 and width == "32" and before.get(("live", pointer[1])):
                state[reg(dst)] = ("selected", 16)
                if self.role == 16:
                    self.captured(state)
            if pc in self.reads:
                index = self.reads[pc]
                require(self.abi == 0 and pointer == ("context", LP64_OFFSETS[index])
                        and width == "64" and self.domain(before, self.field) == {index},
                        error("scalar-read LP64 field/index/context provenance"))
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
                fact = narrow(rhs, 32) if dst.startswith("w") or src.startswith("w") else rhs
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
        if pc in self.argument_calls:
            field = self.argument_calls[pc]
            require(target.endswith("arg_u64") and before.get("r2") == ("context", 0)
                    and before.get("r3") == ("field", field)
                    and before.get("r4") == ("constant", self.abi),
                    error("scalar-read Result context/index/layout boundary"))
            output = before.get("r1")
            require(output and output[0] == "stack" and -512 <= output[1] <= -16,
                    error("scalar-read Result destination outside local frame"))
            forget_stack(state, output[1], 16)
            state[("stack", output[1], 8)] = ("argument_result", pc, field)
            state[("stack", output[1]+8, 8)] = ("candidate", pc, field, 32 if self.abi else 64)
        if pc in self.helpers and target == "p11_read_ia32_arg":
            field = self.helpers[pc]
            require(self.abi == 1,
                    error("ia32 scalar boundary used outside ia32 capture"))
            require(before.get("r1") == ("rsp", 64, 0),
                    error("ia32 scalar boundary stack pointer"))
            index = before.get("r2")
            require(index == ("field", field),
                    error("ia32 scalar boundary descriptor index"))
            state["r0"] = ("read_result", pc, field)
        elif pc in self.helpers:
            field = self.helpers[pc]
            domain = self.domain(before, field)
            expected = ("arg_address", ("stride", field, 4, 4, 0xfc)) if self.abi else ("rsp", 64, 8)
            source = before.get("r3")
            require(pc in consumer.helper and text == "call 0x70", error("scalar-read user helper missing"))
            require(source == expected and domain <= set(range(7)) and (self.abi or domain == {6}),
                    error("scalar-read RSP/index/stride source"))
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
            if self.role == 16:
                require(self.mode == 0 and before.get("r1") == self.scalar(16)
                        and before.get("r2") == self.start,
                        error(f"async target descriptor pointer/START boundary: "
                              f"pointer={before.get('r1')} START={before.get('r2')}"))
                # Conditional-success summary of the independently checked
                # callee. Only its successful selection creates this obligation.
                state[("owned_word", self.start[1], self.start[2]+0x104, 4) if self.start[0] == "owned"
                      else ("stack", self.start[1]+0x104, 4)] = ("selected", 16)
                self.captured(state)
                self.boundaries.add("async_name")
        if text == "call 0x72" and self.role == 16:
            require(pc in consumer.helper, error("async string read requires genuine helper provenance"))
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
                    and before.get("r4") == capture_pointer(self.start, 0x40), error("layout/decoder word bytes or output"))
            if self.role == 8:
                require(before.get("r1") == self.scalar(8) and before.get(("nonnull",)) is True,
                        error("decoder mechanism field 8 pointer"))
                self.boundaries.add("decoder")
        if target == "p11_walk_template" or target == "p11_walk_template_types":
            ordinary = target == "p11_walk_template"
            require((ordinary and self.mode in (1, 3, "second")) or (not ordinary and self.mode == 2), error("mode walker callee"))
            destination = capture_pointer(self.start, 0xb0 if self.mode == "second" else 0x60)
            require(before.get("r3") == ("constant", 4 if self.abi else 8)
                    and before.get("r4") == destination, error("mode walker word bytes/output/owned START"))
            if self.role == "template":
                ptr, count = (14, 15) if self.mode == "second" else (12, 13)
                require(before.get("r1") == self.scalar(ptr) and before.get("r2") == self.scalar(count),
                        error("mode walker ptr/count fields"))
                require(before.get(("success",)), error("mode walker lacks successful capture"))
                state[("done",)] = True
                self.witnesses.add(pc)
        if (text == "call 0xc" and pc in consumer.helper
                and before.get("r2") in (("map", "TAIL_CALLS"), ("map", "STACK_GUARD"))
                and before.get("r3") == ("constant", NO_PRIVATE_STACK_INDEX)):
            # The kernel-stack opt-out: an index past every slot of either
            # program array (STACK_GUARD is also never populated), so the
            # kernel always falls through. It carries no mode and no data.
            # Which array each program may use is check-bpf-map-defs' rule.
            pass
        elif text == "call 0xc" and pc in consumer.helper:
            require(self.mode == 3 and (before.get(("inserted",)) is True
                    or self.start[0] == "owned" and before.get(("live", self.start[1])))
                    and before.get("r1") == ("context", 0)
                    and before.get("r2") == ("map", "PAIR_CALLS")
                    and before.get("r3") == ("constant", 0), error("mode pair tail needs live START and slot 0"))
            self.boundaries.add("tail")
        if self.kind == "return" and pc in self.retained_sites:
            offset, lifecycle, abi = self.retained_sites[pc]
            require(text == "call 0x70" and pc in consumer.helper
                    and self.abi == abi and before.get("r2") == ("constant", 4 if abi else 8), error("retained helper/layout/width"))
            require(before.get("r3") == ("retained", offset, 64), error("retained pointer source/lifetime"))
            if lifecycle is not None:
                require(self.domain(before, 3) == {lifecycle}, error("retained lifecycle field 3"))
            self.boundaries.add(pc)
        if self.kind in ("scalar", "result") and text == "exit":
            success = bool(before.get(("success",)))
            expected = self.success_tag if success else 1 - self.success_tag
            require(stack_read(before, self.start, 8) == ("constant", expected), error("scalar-read Option/Result discriminator"))
            if success:
                require(stack_read(before, self.start, 8, 8) == self.scalar(), error("scalar-read Option/Result success payload"))
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
                        require(not fact or fact[0] in ("constant", "field", "option", "argument_result", "low", "high", "selected")
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
                elif right and right[0] == "read_result" \
                        and left == ("constant", 1 << 32) and op == ">":
                    if taken:
                        domain = self.domain(before, right[2]) & frozenset(range(7))
                        if not domain:
                            continue
                        state[("domain", right[2])] = domain
                        state[("read_ok", right[1])] = True
                        self.read_witnesses |= domain
                        for key, fact in list(state.items()):
                            if fact == right:
                                state[key] = self.scalar(width=32)
                        self.captured(state)
                elif left and left[0] == "read_result" and right == ("constant", 0xffffffff) and op == ">":
                    if not taken:
                        domain = self.domain(before, left[2]) & frozenset(range(7))
                        if not domain:
                            continue
                        state[("domain", left[2])] = domain
                        state[("read_ok", left[1])] = True
                        self.read_witnesses |= domain
                        for key, fact in list(state.items()):
                            if fact == left:
                                state[key] = self.scalar(width=32)
                        self.captured(state)
                elif left and right and left[0] in ("option", "argument_result", "read_result", "insert_result") and right[0] == "constant":
                    require(op in ("==", "!=") and right[1] in ((0, 1) if left[0] in ("option", "argument_result") else (0,)),
                            self.fail(consumer, pc, "unsupported success comparison"))
                    success_value = 1 if left[0] == "option" else 0
                    success = compare(success_value, op, right[1], width) == taken
                    # Both outcomes are possible, but their memory provenance
                    # differs. Failure never promotes a helper output.
                    if success:
                        if left[0] in ("option", "argument_result"):
                            domain = self.domain(before, left[2]) & frozenset(range(7))
                            if not domain:
                                continue
                            state[("domain", left[2])] = domain
                        if left[0] == "read_result":
                            # Invocation alone is not evidence of a usable
                            # argument. In particular, indices 0..5 must not
                            # hide a deleted LP64 index-6 success branch.
                            domain = self.domain(before, left[2]) & frozenset(range(7))
                            if not domain:
                                continue
                            state[("domain", left[2])] = domain
                            self.read_witnesses |= domain
                        for key, fact in list(state.items()):
                            if isinstance(fact, tuple) and fact[:2] == ("candidate", left[1]):
                                state[key] = ("scalar", fact[2], fact[3])
                        if left[0] == "insert_result":
                            if left[1] == self.insert:
                                state[("inserted",)] = True
                        elif (left[0] in ("read_result", "argument_result") or self.role != 16 and self.calls.get(left[1]) == self.role
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
                if left == ("rsp", 64, 0) and right == ("constant", -9) and op == ">" and not taken:
                    state[("address_no_wrap", 8)] = True
                if (left == ("rsp", 64, 15) and right == ("rsp", 64, 8) and op == ">=" and taken
                        and before.get(("address_no_wrap", 8))):
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
                if left and left[0] == "string_result" and op == "s>" \
                        and right == ("constant", 28) and not taken:
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


def ia32_register_transfer(text, incoming):
    """Conservative constant facts for the disassembled span proof."""
    state = list(incoming)
    if text.startswith("call "):
        state[:6] = [None] * 6
    elif "atomic" in text or "xchg" in text or text.startswith("lock "):
        state = [None] * 11
    elif match := re.fullmatch(r"([rw])(\d+) = (-?0x[0-9a-f]+)(?: ll)?", text):
        state[int(match[2])] = int(match[3], 16) & ((1 << (32 if match[1] == "w" else 64)) - 1)
    elif match := re.fullmatch(r"([rw])(\d+) = ([rw])(\d+)", text):
        fact = incoming[int(match[4])]
        state[int(match[2])] = (fact & 0xffffffff if fact is not None
                               and "w" in (match[1], match[3]) else fact)
    elif match := re.match(r"[rw](\d+)\s", text):
        state[int(match[1])] = None
    elif not (BRANCH.fullmatch(text) or STORE.fullmatch(text)
              or text == "exit" or re.fullmatch(r"goto [+-]0x[0-9a-f]+", text)):
        state = [None] * 11
    return tuple(state)


def ia32_reader_contract(internal_blocks, internal_calls):
    # The scalar-return summary depends on normalization of the supplied RSP,
    # independently of the index normalization also present in this body.
    require("p11_read_ia32_arg" in internal_blocks, "missing ia32 scalar reader")
    reader = D.instructions(internal_blocks["p11_read_ia32_arg"])
    pointer_writes = [text for _, text in reader if re.match(r"[rw]3 ", text)]
    require(reader[0][1] == "r3 = r1"
            and pointer_writes == ["r3 = r1", "r3 <<= 0x20", "r3 >>= 0x20", "r3 += r2"],
            "ia32 scalar reader stack-pointer normalization/address provenance")
    span = [pc for pc, text in reader if re.fullmatch(r"if r3 > r1 goto .*", text)]
    user_reads = [pc for pc, text in reader if text == "call 0x70"]
    require(len(span) == len(user_reads) == 1 and span[0] < user_reads[0],
            "ia32 scalar reader requires full-width address span before read")
    reader_consumer = Consumer(".text", "p11_read_ia32_arg", internal_blocks["p11_read_ia32_arg"],
                               internal_calls.get("p11_read_ia32_arg", {}))
    require(user_reads[0] in reader_consumer.helper, "ia32 reader span requires genuine user helper")
    require(reader_consumer.facts().get(span[0], {}).get("r1") == ("constant", 0xfffffffc),
            "ia32 reader span limit must cover the complete u32")
    SPAN.validate_ia32_span_paths(reader_consumer.graph, reader[0][0], span[0],
        D.relative_target(span[0], reader_consumer.text[span[0]]), user_reads[0], {},
        {pc for pc, text in reader if text == "exit"},
        register_transfer=lambda pc, state: ia32_register_transfer(reader_consumer.text[pc], state))


def scalar_body_contract(internal_blocks, internal_calls, variant):
    ia32_reader_contract(internal_blocks, internal_calls)
    names = [name for name in internal_blocks if name.endswith("arg_u64")]
    require(len(names) == 1, "scalar-read Result callee inventory")
    name = names[0]
    consumer = Consumer(".text", name, internal_blocks[name], internal_calls.get(name, {}))
    instructions = consumer.insns
    helper_reads = [pc for pc, text in instructions if pc in consumer.helper and text == "call 0x70"]
    require(len(helper_reads) == 1, "scalar-read LP64 user-helper inventory")
    ia32_calls = [pc for pc, target in consumer.calls.items() if target == "p11_read_ia32_arg"]
    require(len(ia32_calls) == 1, "scalar-read ia32 boundary inventory")
    reads = {}
    for pc, text in instructions:
        match = LOAD.fullmatch(text)
        if match and match[2] == "64" and match[3] == "2" and match[4] == "+":
            offset = int(match[5], 16)
            if offset in LP64_OFFSETS:
                reads[pc] = LP64_OFFSETS.index(offset)
    require(set(reads.values()) == set(range(6)), "scalar-read LP64 register-read inventory")
    for abi in (0, 1):
        proof = SinkProof(6, abi, True, ("stack", -0x1000), kind="result",
                          reads=reads if abi == 0 else {},
                          helpers={(ia32_calls[0] if abi else helper_reads[0]): 6})
        proof.effect_start = ("stack", -0x2000)
        initial = {"r1": proof.start, "r2": ("context", 0), "r3": ("field", 6),
                   "r4": ("constant", abi), "r10": ("stack", 0),
                   ("domain", 6): BYTE_DOMAIN}
        consumer.facts(initial, proof)
    names = [name for name in internal_blocks if name.endswith("capture_scalar")]
    require(len(names) == 1, "scalar-read Option callee inventory")
    name = names[0]
    consumer = Consumer(".text", name, internal_blocks[name], internal_calls.get(name, {}))
    argument_calls = [pc for pc, target in consumer.calls.items() if target.endswith("arg_u64")]
    require(len(argument_calls) == 1 and not any(pc in consumer.helper and text == "call 0x70"
            for pc, text in consumer.insns), "scalar-read Result boundary inventory")
    for abi in (0, 1):
        proof = SinkProof(6, abi, True, ("stack", -0x1000), kind="scalar")
        proof.argument_calls = {argument_calls[0]: 6}
        proof.effect_start = ("stack", -0x2000)
        initial = {"r1": proof.start, "r2": ("context", 0), "r3": ("field", 6),
                   "r4": ("constant", abi), "r5": proof.effect_start, "r10": ("stack", 0),
                   ("domain", 6): BYTE_DOMAIN}
        consumer.facts(initial, proof)
    names = [name for name in internal_blocks if name.endswith("capture_async_target")]
    require(len(names) <= 1, "final-sink async callee inventory")
    if names:
        name = names[0]
        pending, reached = [name], set()
        while pending:
            caller = pending.pop()
            for _, pc, text in D.instruction_entries(internal_blocks[caller]):
                if re.search(r"\bcall ", text) and not text.startswith("85 00 "):
                    require(pc in internal_calls.get(caller, {}),
                            f"final-sink async callee unresolved internal call: {caller}:{pc}")
            for target in internal_calls.get(caller, {}).values():
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        require(not any(target.endswith("capture_scalar") or target == "p11_read_ia32_arg"
                        for target in reached),
                "final-sink async callee reaches scalar/ia32 reader")
        consumer = Consumer(".text", name, internal_blocks[name], internal_calls.get(name, {}))
        for abi in (0, 1):
            proof = SinkProof(16, abi, True, ("stack", -0x1000), kind="async")
            proof.effect_start = proof.start
            initial = {"r1": proof.scalar(16), "r2": proof.start,
                       "r10": ("stack", 0), ("domain", 16): BYTE_DOMAIN}
            consumer.facts(initial, proof)



class _SeedCaller(Consumer):
    """Caller-only summaries for the reviewed native APIs, never a native model.

    Identity writes its two-word output; a separate CFG check requires success
    and nonzero cookie before construction. Memset's exact emitted byte loop is
    checked below. Shadow marker facts join only proven zero/current-cookie
    values, so initialization cannot be inferred from an unknown merged word.
    This subclass leaves the historical checker and stop-gate Consumer unchanged.
    """
    def transfer(self, pc, incoming):
        state = super().transfer(pc, incoming)
        text, target = self.text[pc], self.calls.get(pc, "")
        identity = (self.section, self.name)
        if match := STORE.fullmatch(text):
            width, base, sign, offset, source = match.groups()
            pointer = address(incoming, base, sign, offset)
            if pointer and pointer[0] == "stack":
                size = int(width) // 8
                for key in list(state):
                    if isinstance(key, tuple) and key[0] == "seed_marker" and key[1] < pointer[1]+size and pointer[1] < key[1]+8:
                        del state[key]
                fact = value(incoming, source)
                if width == "64" and fact in (("constant", 0), ("entry_marker", identity)):
                    state[("seed_marker", pointer[1])] = True
            elif pointer is None and incoming.get("r"+base, (None,))[0] != "result":
                for key in list(state):
                    if isinstance(key, tuple) and key[0] == "seed_marker":
                        del state[key]
        if "atomic" in text or "xchg" in text or text.startswith("lock "):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(incoming, *match.groups()[1:]) if match else None
            disjoint = match and incoming.get("r"+match[2], (None,))[0] == "result"
            for key in list(state):
                if isinstance(key, tuple) and key[0] == "seed_marker" and not disjoint:
                    if pointer is None or pointer[0] != "stack" or (key[1] < pointer[1]+int(match[1])//8 and pointer[1] < key[1]+8):
                        del state[key]
        if target in ("memset", "p11_link_current_identity") or target.endswith("scope_auth"):
            pointer = incoming.get("r1")
            size = incoming.get("r3") if target == "memset" else ("constant", 16)
            width = size[1] if size and size[0] == "constant" else 512
            for key in list(state):
                if isinstance(key, tuple) and key[0] == "seed_marker":
                    if not pointer or pointer[0] != "stack" or (key[1] < pointer[1]+width and pointer[1] < key[1]+8):
                        del state[key]
        if target == "memset":
            pointer, byte, size = (incoming.get(reg) for reg in ("r1", "r2", "r3"))
            if pointer and pointer[0] == "stack" and byte == ("constant", 0) and size and size[0] == "constant" and 0 < size[1] <= 32 and size[1] % 8 == 0:
                for offset in range(0, size[1], 8):
                    state[("stack", pointer[1]+offset, 8)] = ("constant", 0)
                    state[("seed_marker", pointer[1]+offset)] = True
        elif target == "p11_link_current_identity":
            pointer = incoming.get("r1")
            if pointer and pointer[0] == "stack":
                state[("stack", pointer[1], 8)] = ("image_cookie", identity, pc)
                state[("stack", pointer[1]+8, 8)] = ("image_exec", identity, pc)
                state["r0"] = ("identity_result", pc)
        elif target.endswith("object_marker_for"):
            if incoming.get("r1") == ("cookie", identity):
                state["r0"] = ("entry_marker", identity)
        elif target == "p11_owner_start_begin":
            state["r0"] = ("owned", pc, 0)
        if match := re.fullmatch(r"([rw]\d+) (=|<<=|>>=) ([rw]\d+|-?0x[0-9a-f]+)(?: ll)?", text):
            dst, op, src = match.groups()
            fact = value(incoming, src) if op == "=" else incoming.get(reg(dst))
            if fact and fact[0] == "identity_result" and (op == "=" or src == "0x20"):
                state[reg(dst)] = fact
        return state


class _OwnedCaller(_SeedCaller):
    """Track mutable START bytes separately from every local BPF frame.

    These are caller API footprints, not claims about native transaction bodies.
    Unknown aliases and callees erase the facts they might overwrite.
    """
    def transfer(self, pc, incoming):
        state = super().transfer(pc, incoming)
        text, target = self.text[pc], self.calls.get(pc, "")
        if match := STORE.fullmatch(text):
            width, base, sign, offset, src = match.groups()
            pointer = address(incoming, base, sign, offset)
            if pointer and pointer[0] == "owned":
                size = int(width)//8
                forget_owned(state, pointer[1], pointer[2], size)
                fact = narrow(value(incoming, src), int(width))
                if fact is not None:
                    state[("owned_word", pointer[1], pointer[2], size)] = fact
                    # A later adjacent u32 shape update may overlap the high
                    # half of this initialized u64 without touching user_type.
                    if size == 8 and fact[0] == "constant":
                        for delta in (0, 4):
                            state[("owned_word", pointer[1], pointer[2]+delta, 4)] = ("constant", (fact[1] >> (delta*8)) & 0xffffffff)
            elif pointer is None and incoming.get("r"+base, (None,))[0] != "result":
                forget_owned(state)
        if match := LOAD.fullmatch(text):
            pointer = address(incoming, match[3], match[4], match[5])
            if pointer and pointer[0] == "owned":
                fact = capture_read(incoming, pointer, int(match[2])//8)
                state.pop(reg(match[1]), None)
                if fact is not None:
                    state[reg(match[1])] = fact
        if "atomic" in text or "xchg" in text or text.startswith("lock "):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(incoming, *match.groups()[1:]) if match else None
            if pointer and pointer[0] == "owned":
                forget_owned(state, pointer[1], pointer[2], int(match[1])//8)
            elif pointer is None and not (match and incoming.get("r"+match[2], (None,))[0] == "result"):
                forget_owned(state)
        if text.startswith("call "):
            if not target and pc not in self.helper:
                forget_owned(state)
            if pc in self.helper:
                if text in ("call 0x70", "call 0x72"):
                    pointer, size = incoming.get("r1"), incoming.get("r2")
                    if pointer and pointer[0] == "owned" and size and size[0] == "constant":
                        forget_owned(state, pointer[1], pointer[2], size[1])
                    elif not pointer or pointer[0] not in ("stack", "result"):
                        forget_owned(state)
                elif text not in ("call 0x1", "call 0x5", "call 0xc", "call 0xe", "call 0xae"):
                    forget_owned(state)
            if target.endswith("capture_scalar"):
                pointer = incoming.get("r5")
                if pointer and pointer[0] == "owned":
                    forget_owned(state, pointer[1], pointer[2]+0x100, 4)
            elif target.endswith("capture_async_target"):
                pointer = incoming.get("r2")
                if pointer and pointer[0] == "owned":
                    forget_owned(state, pointer[1], pointer[2]+0x100, 8)
            elif target in ("p11_decode_params", "p11_walk_template", "p11_walk_template_types"):
                pointer = incoming.get("r4")
                if pointer and pointer[0] == "owned":
                    forget_owned(state, pointer[1], pointer[2], 24 if target == "p11_decode_params" else 80)
            elif target == "p11_owner_start_get":
                state["r0"] = ("owned", pc, 0)
            elif target == "p11_owner_start_remove":
                forget_owned(state)
            elif target and not (target in ("memset", "p11_link_current_identity", "p11_instance_entry",
                    "p11_owner_start_begin", "p11_owner_start_aggregate", "p11_object_side_get", "p11_object_fault")
                    or any(target.endswith(suffix) for suffix in ("scope_auth", "scope_flags_word", "object_marker_for",
                        "object_record_entry_abi", "object_fill_entry", "object_entry_derive", "object_entry_results",
                        "object_entry_find", "object_entry_attributes"))):
                forget_owned(state)
        if match := re.fullmatch(r"(r\d+) \+= (-?0x[0-9a-f]+)", text):
            fact = incoming.get(match[1])
            if fact and fact[0] == "owned":
                state[match[1]] = ("owned", fact[1], fact[2]+int(match[2],16))
        if match := re.fullmatch(r"([rw]\d+) = (w\d+)", text):
            state.pop(reg(match[1]), None)
            fact = narrow(value(incoming, match[2]), 32)
            if fact is not None:
                state[reg(match[1])] = fact
        return state


def finite_intervals(intervals, op, constant, taken):
    """Exact unsigned scalar partition; neither examples nor truncated aliases."""
    constant &= (1 << 64)-1
    result = []
    for low, high in intervals:
        cuts = sorted({low, high+1, max(low, min(high+1, constant)),
                       max(low, min(high+1, constant+1))})
        for begin, end in zip(cuts, cuts[1:]):
            if begin < end and compare(begin, op, constant) == taken:
                result.append((begin, end-1))
    return tuple(result)


class _OwnedSinkProof(SinkProof):
    def partition(self, state):
        intervals = state.get(("finite_values",))
        finite = None
        if intervals is not None:
            finite = "mixed"
            if all(high < 3 for _, high in intervals):
                finite = "valid"
            elif all(low >= 3 for low, _ in intervals):
                finite = "invalid"
        return super().partition(state) + (state.get(("live", self.start[1])),
            state.get(("cleanup",)), state.get(("poisoned",)), state.get(("entry_pending",)),
            state.get(("entry_refusal",)), finite)

    @staticmethod
    def join(previous, state):
        merged = SinkProof.join(previous, state)
        if previous is not None and ("finite_values",) in previous and ("finite_values",) in state:
            merged[("finite_values",)] = tuple(sorted(set(previous[("finite_values",)]) | set(state[("finite_values",)])))
        return merged

    def captured(self, state):
        super().captured(state)
        if self.role == 11:
            state[("finite_values",)] = ((0, (1 << (32 if self.abi else 64))-1),)

    def check_sink(self, consumer, pc, state):
        if state.get(("cleanup",)):
            require(state.get(("poisoned",)), self.fail(consumer, pc, "removed START lacks terminal fault"))
            return
        require(not state.get(("entry_pending",)) and not state.get(("entry_refusal",)),
                self.fail(consumer, pc, "entry refusal/pending adapter bypassed terminal cleanup"))
        if not state.get(("live", self.start[1])):
            require(not self.required(state), self.fail(consumer, pc, "capture lost owned START lifetime"))
            return
        if self.role == 11:
            actual = capture_read(state, self.start, 4, 0x38)
            intervals = state.get(("finite_values",))
            if not state.get(("success",)):
                require(actual == ("constant", 0xffffffff), self.fail(consumer, pc, "None lost USER_TYPE_NONE sentinel"))
            else:
                valid = intervals and all(high < 3 for _, high in intervals)
                invalid = intervals and all(low >= 3 for low, _ in intervals)
                require((valid and actual == self.scalar(width=32)) or (invalid and actual == ("constant", 0xffffffff)),
                        self.fail(consumer, pc, "user type full-width finite classification lost"))
                self.witnesses.add(pc)
            return
        super().check_sink(consumer, pc, state)

    def transfer(self, consumer, pc, before, state):
        text, target = consumer.text[pc], consumer.calls.get(pc, "")
        memory = LOAD.fullmatch(text) or STORE.fullmatch(text)
        if memory:
            base, sign, offset = memory.groups()[2:5] if LOAD.fullmatch(text) else memory.groups()[1:4]
            pointer = address(before, base, sign, offset)
            if pointer and pointer[0] == "owned":
                require(before.get(("live", pointer[1])), self.fail(consumer, pc, "START access outside owned lifetime"))
        if target == "p11_owner_start_remove" and before.get(("live", self.start[1])):
            state[("cleanup",)] = True
        if any(target.endswith(suffix) for suffix in ("object_record_entry_abi", "object_fill_entry",
                "object_entry_derive", "object_entry_results", "object_entry_find", "object_entry_attributes")):
            require(not before.get(("entry_pending",)), self.fail(consumer, pc, "pending entry adapter result"))
            state["r0"] = ("entry_adapter", pc)
            state[("entry_pending",)] = pc
        if target == "p11_object_fault":
            require(not before.get(("live", self.start[1])), self.fail(consumer, pc, "terminal fault bypassed START removal attempt"))
            if before.get(("cleanup",)):
                state[("poisoned",)] = True
        if text == "call 0xc" and before.get("r2") == ("map", "PAIR_CALLS"):
            self.check_sink(consumer, pc, before)
        return super().transfer(consumer, pc, before, state)

    def edges(self, consumer, pc, before, after):
        branch = BRANCH.fullmatch(consumer.text[pc])
        for successor, state in super().edges(consumer, pc, before, after):
            if branch:
                left, right = value(before, branch[1]), value(before, branch[3])
                zero_taken = zero_partition(left, branch[2], 64) if left and right == ("constant", 0) else None
                if left and left[0] == "entry_adapter" and zero_taken is not None:
                    require(branch[1].startswith("r"), self.fail(consumer, pc, "entry adapter result width"))
                    state.pop(("entry_pending",), None)
                    if (successor == D.relative_target(pc, consumer.text[pc])) == zero_taken:
                        state[("entry_refusal",)] = True
            if self.role == 11 and branch and before.get(("finite_values",)):
                left, op, right = value(before, branch[1]), branch[2], value(before, branch[3])
                scalar, constant = left, right
                if left and left[0] == "constant" and right and right[0] == "scalar" and right[1] == 11:
                    scalar, constant = right, left
                    op = {">": "<", ">=": "<=", "<": ">", "<=": ">=", "==": "==", "!=": "!="}.get(op)
                if scalar and scalar[0] == "scalar" and scalar[1] == 11 and constant and constant[0] == "constant":
                    require(op is not None and not op.startswith("s") and (self.abi or scalar[2] == 64),
                            self.fail(consumer, pc, "user type predicate narrowed full-width input"))
                    width = 32 if branch[1].startswith("w") else 64
                    boundary = constant[1] & ((1 << width)-1)
                    intervals = finite_intervals(before[("finite_values",)], op, boundary,
                        successor == D.relative_target(pc, consumer.text[pc]))
                    if not intervals:
                        continue
                    state[("finite_values",)] = intervals
            yield successor, state


def scalar_scope_flags_contract(disassembly):
    """Summarize only the actual scalar wrapper's own-stack/full-word effects.

    The real authority body remains scope_auth. This finite branch-first
    wrapper supplies its own 32-byte output, returns flags64 on Some and zero
    on None, and cannot write a caller's seed or perform a target read.
    """
    split = sections(disassembly)
    blocks = D.function_blocks(split.get(".text", ""))
    names = [name for name in blocks if name.endswith("scope_flags_word")]
    require(len(names) <= 1, "scalar scope flags wrapper inventory")
    if not names:
        return None  # Earlier objects call the already-modeled authority directly.
    name = names[0]
    insns = D.instructions(blocks[name])
    require(8 <= len(insns) <= 9 and insns[0][1] == "r1 = r10"
            and insns[1][1] == "r1 += -0x20"
            and re.fullmatch(r"call -?0x[0-9a-f]+", insns[2][1]),
            "scalar scope flags own-stack/call effects")
    authority = [candidate for candidate in blocks
                 if re.fullmatch(r"_RNv[0-9A-Za-z]+_13p11scope_ebpf10scope_auth", candidate)]
    calls = [(pc, target) for caller, _, pc, target in D.internal_call_targets(split[".text"])
             if caller == name]
    require(len(authority) == 1 and len(calls) == 1 and calls[0][0] == insns[2][0]
            and calls[0][1] == authority[0],
            "scalar scope flags one actual scope_auth callee")
    roles = {"tag": [], "flags": [], "zero": [], "guard": [], "exit": [], "jump": []}
    for pc, text in insns[3:]:
        if text == "r1 = *(u64 *)(r10 - 0x20)": role = "tag"
        elif text == "r0 = *(u64 *)(r10 - 0x18)": role = "flags"
        elif text == "r0 = 0x0": role = "zero"
        elif re.fullmatch(r"if r1 (==|!=) 0x[01] goto .*", text): role = "guard"
        elif text == "exit": role = "exit"
        elif re.fullmatch(r"goto .*", text): role = "jump"
        else: raise RuntimeError("scalar scope flags unknown/full64/discriminant effect")
        roles[role].append(pc)
    require(all(len(roles[role]) == 1 for role in ("tag", "flags", "zero", "guard", "exit"))
            and len(roles["jump"]) <= 1, "scalar scope flags finite effect inventory")
    texts = dict(insns)
    _, graph = D.instruction_graph(blocks[name])
    entry, tag, flags, zero, guard, end = (insns[0][0], roles["tag"][0], roles["flags"][0],
                                        roles["zero"][0], roles["guard"][0], roles["exit"][0])
    for pc in roles["guard"] + roles["jump"]:
        target = D.relative_target(pc, texts[pc])
        require(target in texts and target > pc, "scalar scope flags finite forward branch")
    require(guard not in D.reachable(graph, [entry], blocked={tag}),
            "scalar scope flags initialized discriminant")
    target = D.relative_target(guard, texts[guard])
    other = next(edge for edge in graph[guard] if edge != target)
    condition = re.fullmatch(r"if r1 (==|!=) 0x([01]) goto .*", texts[guard])
    some_taken = (condition[2] == "1") == (condition[1] == "==")
    some, absent = (target, other) if some_taken else (other, target)
    require(flags in D.reachable(graph, [some]) and end in D.reachable(graph, [absent])
            and flags not in D.reachable(graph, [entry], blocked={guard})
            and flags not in D.reachable(graph, [absent])
            and end not in D.reachable(graph, [some], blocked={flags}),
            "scalar scope flags payload load before discriminant/refusal")
    require((guard not in D.reachable(graph, [entry], blocked={zero})
             or end not in D.reachable(graph, [absent], blocked={zero}))
            and zero not in D.reachable(graph, [flags])
            and end in D.reachable(graph, [flags]),
            "scalar scope flags zero-refusal/fullword return")
    return name


def seeded_start_contract(disassembly):
    """Actual ordinary-entry key/immutable-seed wiring, independent of old pins.

    The native transaction is exercised by the real C fixture and ELF/frame
    contracts, not summarized as a second owner algorithm here. This proves
    caller provenance and refusal edges; it is not kernel verifier acceptance.
    """
    scalar_scope = scalar_scope_flags_contract(disassembly)
    split = sections(disassembly)
    require(".text" in split and "uprobe" in split, "seeded START missing sections")
    blocks = D.function_blocks(split[".text"])
    require("memset" in blocks, "seeded START missing memset")
    memset = D.instructions(blocks["memset"])
    # llvm-objdump 18 prints the stored sub-register as `r2`; 21 prints the
    # same instruction bytes as `w2`. Accept both spellings: the loop shape
    # (8 instructions, byte store, bounds) is what the contract pins.
    patterns = (r"if r3 == 0x0 goto .*", r"r4 = 0x0", r"r5 = r1", r"r5 \+= r4",
                r"\*\(u8 \*\)\(r5 \+ 0x0\) = (?:w2|r2)", r"r4 \+= 0x1", r"if r3 > r4 goto .*", r"exit")
    require(len(memset) == len(patterns) and all(re.fullmatch(pattern, instruction) for (_, instruction), pattern in zip(memset, patterns)),
            "seeded START memset byte-loop summary changed")
    _, graph = D.instruction_graph(blocks["memset"])
    require(D.relative_target(memset[0][0], memset[0][1]) == memset[-1][0]
            and D.relative_target(memset[-2][0], memset[-2][1]) == memset[2][0],
            "seeded START memset loop edges changed")
    calls = D.internal_call_targets(split["uprobe"] + "\n" + split[".text"])
    report = {}
    for name, lines in D.function_blocks(split["uprobe"]).items():
        if not name.startswith("p11_entry") or name == "p11_entry_template_second":
            continue
        consumer = _SeedCaller("uprobe", name, lines, {pc: target for caller, _, pc, target in calls if caller == name})
        if scalar_scope is not None:
            require(sum(target == scalar_scope for target in consumer.calls.values()) == 1,
                    name + ": seeded START one scalar scope call")
        begins = [pc for pc, target in consumer.calls.items() if target == "p11_owner_start_begin"]
        require(len(begins) == 1, name + ": seeded START constructor inventory")
        begin = begins[0]
        facts = consumer.facts()
        state = facts.get(begin, {})
        identity = (consumer.section, name)
        key, seed = state.get("r1"), state.get("r2")
        require(key and seed and key[0] == seed[0] == "stack" and key != seed,
                name + ": seeded START key/seed addresses")
        require(stack_read(state, key, 8) == ("pid_tgid", identity)
                and stack_read(state, key, 4, 8) == ("low", identity)
                and stack_read(state, key, 4, 12) == ("constant", 0), name + ": seeded START full owner key/padding")
        require(stack_read(state, seed, 8) == ("ktime_ns", identity), name + ": seeded START original timestamp")
        cookie, image = stack_read(state, seed, 8, 8), stack_read(state, seed, 8, 16)
        require(cookie and cookie[:2] == ("image_cookie", identity) and image == ("image_exec", identity, cookie[2]),
                name + ": seeded START current image words")
        require(sum(target == "p11_link_current_identity" for target in consumer.calls.values()) == 1,
                name + ": seeded START current identity inventory")
        require(state.get(("seed_marker", seed[1]+24)) is True, name + ": seeded START marker uninitialized/nonzero/unproven")
        entry = consumer.insns[0][0]
        before = D.reachable(consumer.graph, [entry], blocked={begin})
        can_reach_begin = {pc for pc in before if begin in D.reachable(consumer.graph, [pc])}
        require(sum(pc in can_reach_begin and pc in consumer.helper and text == "call 0x5" for pc, text in consumer.insns) == 1,
                name + ": seeded START must use one original timestamp")
        def guarded(expected, constant, success_taken):
            matches = []
            for pc, text in consumer.insns:
                branch = BRANCH.fullmatch(text)
                if branch and value(facts.get(pc, {}), branch[1]) == expected and value(facts.get(pc, {}), branch[3]) == ("constant", constant) and branch[2] in ("==", "!="):
                    taken = D.relative_target(pc, text)
                    success = taken if (branch[2] == "==") == success_taken else next(edge for edge in consumer.graph[pc] if edge != taken)
                    failure = next(edge for edge in consumer.graph[pc] if edge != success)
                    if begin in D.reachable(consumer.graph, [success]) and begin not in D.reachable(consumer.graph, [failure]) and begin not in D.reachable(consumer.graph, [entry], blocked={pc}):
                        matches.append(pc)
            require(len(matches) == 1, name + ": seeded START identity success/nonzero guard")
            return matches[0]
        identity_guard = guarded(("identity_result", cookie[2]), 1, True)
        cookie_guard = guarded(cookie, 0, False)
        witnesses = [pc for pc, target in consumer.calls.items() if target == "p11_instance_entry"]
        require(len(witnesses) == 1, name + ": seeded START witness inventory")
        witness = witnesses[0]
        witness_state = facts.get(witness, {})
        require(witness_state.get("r1") == key and witness_state.get("r3") == cookie and witness_state.get("r4") == image
                and begin not in D.reachable(consumer.graph, [entry], blocked={witness}),
                name + ": seeded START witness key/image provenance")
        for pc in can_reach_begin:
            target = consumer.calls.get(pc, "")
            require(not target or target in ("memset", "p11_link_current_identity", "p11_instance_entry")
                    or target.endswith(("scope_auth", "object_marker_for"))
                    or (scalar_scope is not None and target == scalar_scope),
                    name + ": seeded START unknown pre-construction callee effects")
            require(pc not in consumer.helper or consumer.text[pc] in
                    ("call 0x1", "call 0x5", "call 0xc", "call 0xe", "call 0xae"),
                    name + ": seeded START private read before construction/unknown helper")
            require(not (pc in consumer.helper and consumer.text[pc] in ("call 0x70", "call 0x72"))
                    and not any(target.endswith(suffix) for suffix in ("capture_scalar", "capture_async_target", "object_fill_entry", "object_entry_attributes")),
                    name + ": seeded START private read before construction")
        captures = {pc for pc, text in consumer.insns
                    if (pc in consumer.helper and text in ("call 0x70", "call 0x72"))
                    or any(consumer.calls.get(pc, "").endswith(suffix) for suffix in
                           ("capture_scalar", "capture_async_target", "object_fill_entry", "object_entry_attributes", "p11_decode_params", "p11_walk_template", "p11_walk_template_types"))}
        require(captures, name + ": seeded START no capture boundary witness")
        null_guards = []
        for pc, text in consumer.insns:
            branch = BRANCH.fullmatch(text)
            if not branch or branch[2] not in ("==", "!=") or value(facts.get(pc, {}), branch[1]) != ("owned", begin, 0) or value(facts.get(pc, {}), branch[3]) != ("constant", 0):
                continue
            taken = D.relative_target(pc, text)
            failure = taken if branch[2] == "==" else next(edge for edge in consumer.graph[pc] if edge != taken)
            if not captures & D.reachable(consumer.graph, [failure]) and not captures & D.reachable(consumer.graph, [entry], blocked={pc}):
                null_guards.append(pc)
        require(len(null_guards) == 1, name + ": seeded START null refusal before private reads")
        aggregate_calls = [pc for pc, target in consumer.calls.items() if target == "p11_owner_start_aggregate"]
        require(len(aggregate_calls) == 1, name + ": aggregate START constructor inventory")
        aggregate = aggregate_calls[0]
        aggregate_state = facts.get(aggregate, {})
        require(aggregate_state.get("r1") == key
                and stack_read(aggregate_state, key, 8) == ("pid_tgid", identity)
                and stack_read(aggregate_state, key, 4, 8) == ("low", identity)
                and stack_read(aggregate_state, key, 4, 12) == ("constant", 0),
                name + ": aggregate START full owner key/padding")
        require(aggregate_state.get("r2") == ("ktime_ns", identity),
                name + ": aggregate START original scalar timestamp")
        report[name] = {"constructor": begin, "key": key[1], "seed": seed[1],
                        "identity_guard": identity_guard, "cookie_guard": cookie_guard, "witness": witness,
                        "null_guard": null_guards[0], "aggregate": aggregate}
    require("p11_entry" in report, "seeded START missing ordinary entry")
    return report


def final_sink_contract(consumer, variant, selectors, internal_blocks, internal_calls):
    name = consumer.name
    if name == "p11_return":
        return retained_contract(consumer, variant, selectors, internal_blocks, internal_calls)
    consumer = _OwnedCaller(consumer.section, name, consumer.lines, consumer.calls)
    mode = {"p11_entry_template": 1, "p11_entry_template_pair": 3,
            "p11_entry_template_types": 2, "p11_entry_template_second": "second"}.get(name, 0)
    expected_roles = (14, 15) if mode == "second" else (6, 7, 10, 11, 9, 8) + ((16, "join", "get") if mode == 0 else (12, 13))
    scalar_calls = sorted(pc for pc, target in consumer.calls.items() if target.endswith("capture_scalar"))
    require(len(scalar_calls) == len(expected_roles), name + ": final-sink scalar-read inventory")
    calls = dict(zip(scalar_calls, expected_roles))
    constructors = [pc for pc, target in consumer.calls.items() if target == ("p11_owner_start_get" if mode == "second" else "p11_owner_start_begin")]
    require(len(constructors) == 1, name + ": final-sink owned START constructor inventory")
    start = ("owned", constructors[0], 0)
    if mode == 0:
        lifecycle = [pc for pc, text in consumer.insns if re.fullmatch(r"if r\d+ == 0xc goto .*", text)]
        require(len(lifecycle) == 1, name + ": final-sink async lifecycle continuation inventory")
        capture = next(pc for pc, role in calls.items() if role == 16)
        exits = {pc for pc, text in consumer.insns if text == "exit"}
        require(not exits & D.reachable(consumer.graph, [capture], blocked={lifecycle[0]}),
                name + ": final-sink async scalar failure bypasses lifecycle continuation")
    roles = ["template"] if mode == "second" else [6, 7, 10, 11, 8, 9]
    roles += [16, "join", "get"] if mode == 0 else ([] if mode == "second" else ["template"])
    for selector in selectors:
        abi = int(selector == 0x23)
        for present in (False, True):
            for role in roles:
                proof = _OwnedSinkProof(role, abi, present, start, calls=calls, mode=mode)
                proof.decoder_required = variant == "unsafe" and role == 8
                consumer.facts(proof=proof)
    return {"roles": roles, "mode": mode, "scenarios": len(selectors)*2}


class _ReturnCaller(_SeedCaller):
    """An outlined frame with explicit external key and START parameters."""
    identity = ("uretprobe", "p11_return")

    def transfer(self, pc, incoming):
        state = super().transfer(pc, incoming)
        text, target = self.text[pc], self.calls.get(pc, "")
        if pc in self.helper and text == "call 0xae" and incoming.get("r1") == ("context", 0):
            state["r0"] = ("cookie", self.identity)
        elif pc in self.helper and text == "call 0xe":
            state["r0"] = ("pid_tgid", self.identity)
        if match := LOAD.fullmatch(text):
            pointer = address(incoming, match[3], match[4], match[5])
            fact = None
            if pointer and pointer[0] == "external_key":
                fact = {0: ("pid_tgid", self.identity), 8: ("key_tail", self.identity)}.get(pointer[2]) if match[2] == "64" else None
            elif pointer and pointer[0] == "owned":
                fact = ("retained", pointer[2], int(match[2]))
            if fact:
                state[reg(match[1])] = fact
        if match := STORE.fullmatch(text):
            pointer = address(incoming, match[2], match[3], match[4])
            if pointer and pointer[0] == "stack" and match[1] == "64" and value(incoming, match[5]) == ("key_tail", self.identity):
                state[("stack", pointer[1], 4)] = ("low", self.identity)
                state[("stack", pointer[1]+4, 4)] = ("constant", 0)
        if match := STORE.fullmatch(text):
            pointer = address(incoming, match[2], match[3], match[4])
            if pointer and pointer[0] == "event":
                size = int(match[1])//8
                if pointer[1] < 0x74 and 0x70 < pointer[1]+size:
                    state.pop(("event_user_type",), None)
                if pointer[1] == 0x70 and match[1] == "32":
                    fact = narrow(value(incoming, match[5]), 32)
                    if fact is not None:
                        state[("event_user_type",)] = fact
            elif pointer is None:
                state.pop(("event_user_type",), None)
        if "atomic" in text or "xchg" in text or text.startswith("lock "):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(incoming, *match.groups()[1:]) if match else None
            if pointer is None or pointer[0] == "event" and pointer[1] < 0x74 and 0x70 < pointer[1]+int(match[1])//8:
                state.pop(("event_user_type",), None)
        if pc in self.helper and text == "call 0x83":
            state.pop(("event_user_type",), None)
        if target == "memset" or pc in self.helper and text in ("call 0x70", "call 0x72"):
            pointer = incoming.get("r1")
            size = incoming.get("r3" if target == "memset" else "r2")
            if pointer and pointer[0] == "event" and (not size or size[0] != "constant"
                    or pointer[1] < 0x74 and 0x70 < pointer[1]+size[1]):
                state.pop(("event_user_type",), None)
        if target == "p11_owner_start_get":
            state["r0"] = ("owned", pc, 0)
        elif target.endswith("scope_flags_word"):
            state["r0"] = ("scope_flags", self.identity)
        if match := re.fullmatch(r"(r\d+) \+= (-?0x[0-9a-f]+)", text):
            fact = incoming.get(match[1])
            if fact and fact[0] in ("owned", "external_key"):
                state[match[1]] = (fact[0], fact[1], fact[2]+int(match[2],16))
        # A tail adapter only writes its ObjectCallWire destination. The
        # base event and local snapshot are disjoint from that narrow region.
        if any(target.endswith(suffix) for suffix in ("object_tail_fill", "object_emit_find", "object_emit_get_attributes")):
            require(incoming.get("r1") == ("event", 0x170), self.label(pc)+": return tail output boundary")
            if ("event_slot",) in incoming:
                state[("event_slot",)] = incoming[("event_slot",)]
        return state


class _ReturnRootProof(SinkProof):
    def __init__(self, abi, owner, targets):
        super().__init__("return", abi, True, ("owned", owner, 0), kind="return")
        self.retained_sites, self.targets = {}, targets

    def partition(self, state):
        return super().partition(state) + (state.get(("live", self.start[1])), state.get(("object_mode",)))

    def transfer(self, consumer, pc, before, state):
        text, target = consumer.text[pc], consumer.calls.get(pc, "")
        if text.startswith("call "):
            allowed = target in ("p11_owner_start_get", "p11_owner_start_remove", "p11_object_fault") or target.endswith("scope_flags_word") or pc in self.targets
            require(allowed if pc not in consumer.helper else text in ("call 0x1", "call 0xc", "call 0xe", "call 0xae"),
                    consumer.label(pc)+": return unknown root callee/helper")
        if target.startswith("p11_owner_start_"):
            key = before.get("r1")
            require(key and key[0] == "stack" and stack_read(before, key, 8) == ("pid_tgid", consumer.identity)
                    and stack_read(before, key, 4, 8) == ("low", consumer.identity)
                    and stack_read(before, key, 4, 12) == ("constant", 0),
                    consumer.label(pc)+": return START lookup/cleanup key provenance")
        if pc in self.targets:
            role = self.targets[pc]
            require(before.get("r1") == ("context", 0) and before.get("r3") == self.start
                    and before.get(("live", self.start[1])) and before.get("r4") == ("scope_flags", consumer.identity)
                    and before.get("r5") == ("constant", self.abi),
                    consumer.label(pc)+": return context/START/flags/layout boundary")
            key = before.get("r2")
            require(key and key[0] == "stack" and stack_read(before, key, 8) == ("pid_tgid", consumer.identity)
                    and stack_read(before, key, 4, 8) == ("low", consumer.identity)
                    and stack_read(before, key, 4, 12) == ("constant", 0),
                    consumer.label(pc)+": return full caller key boundary")
            require(before.get(("object_mode",)) == (role == "object"),
                    consumer.label(pc)+": return marker routing boundary")
            self.boundaries.add(pc)
        return super().transfer(consumer, pc, before, state)

    def edges(self, consumer, pc, before, after):
        branch = BRANCH.fullmatch(consumer.text[pc])
        for successor, state in super().edges(consumer, pc, before, after):
            if branch and value(before, branch[1]) == ("retained", 0x108, 64) and value(before, branch[3]) == ("constant", 0):
                zero_taken = zero_partition(value(before, branch[1]), branch[2], 64)
                require(zero_taken is not None and branch[1].startswith("r"), consumer.label(pc)+": return marker full-word guard")
                state[("object_mode",)] = (successor == D.relative_target(pc, consumer.text[pc])) != zero_taken
            yield successor, state

    def finish(self, consumer):
        require(self.boundaries == set(self.targets), consumer.name+": return outlined boundary inventory")


class _ReturnProof(SinkProof):
    def __init__(self, abi, present, owner, role, sites):
        super().__init__("return", abi, present, ("owned", owner, 0), kind="return")
        self.return_role, self.retained_sites = role, sites
        self.submits = set()
        self.emission_roles = ("object_fill_return", "object_tail_fill", "object_emit_find", "object_emit_get_attributes")

    def partition(self, state):
        return super().partition(state) + tuple(state.get((key,)) for key in ("retired", "settled", "fault", "emitted"))

    def transfer(self, consumer, pc, before, state):
        text, target = consumer.text[pc], consumer.calls.get(pc, "")
        error = lambda message: consumer.label(pc)+": return "+message
        if text.startswith("call "):
            allowed = target in ("memset", "p11_link_current_identity", "p11_owner_start_remove", "p11_object_fault",
                                 "p11_object_side_get", "p11_instance_return", "p11_root_current_tag") or any(target.endswith(role) for role in self.emission_roles)
            require(allowed if pc not in consumer.helper else text in ("call 0x1", "call 0x2", "call 0x5", "call 0xe",
                    "call 0x50", "call 0x70", "call 0x83", "call 0x84", "call 0x85", "call 0xae"), error("unknown callee/helper footprint"))
        if match := STORE.fullmatch(text):
            pointer = address(before, match[2], match[3], match[4])
            require(pointer and pointer[0] in ("stack", "event")
                    or before.get("r"+match[2], (None,))[0] == "result", error("unknown or immutable START/key/context write"))
        if "atomic" in text or "xchg" in text or text.startswith("lock "):
            match = ATOMIC_POINTER.search(text) or EXCHANGE_POINTER.search(text)
            pointer = address(before, *match.groups()[1:]) if match else None
            require(match and (pointer and pointer[0] in ("stack", "event")
                    or before.get("r"+match[2], (None,))[0] == "result"), error("immutable or unknown atomic footprint"))
        if match := LOAD.fullmatch(text):
            pointer = address(before, match[3], match[4], match[5])
            if pointer and pointer[0] == "owned":
                require(before.get(("live", self.start[1])), error("START read after retirement"))
        if target in ("p11_owner_start_remove", "p11_object_side_get", "p11_instance_return"):
            key = before.get("r1")
            require(key and key[0] == "stack" and stack_read(before, key, 8) == ("pid_tgid", consumer.identity)
                    and stack_read(before, key, 4, 8) == ("low", consumer.identity)
                    and stack_read(before, key, 4, 12) == ("constant", 0), error("full callee key provenance"))
        if target == "p11_owner_start_remove":
            require(before.get("r2") == ("constant", 1) and not before.get(("retired",)), error("required single retirement attempt"))
            state[("retired",)] = True
            state["r0"] = ("retire_result", pc)
        if target == "p11_object_fault":
            require(before.get(("retired",)), error("fault before retirement attempt"))
            state[("fault",)] = True
        if target == "p11_object_side_get" or any(target.endswith(suffix) for suffix in
                ("object_fill_return", "object_tail_fill", "object_emit_find", "object_emit_get_attributes")):
            require(self.return_role == "object" and before.get(("live", self.start[1])), error("side access after retirement"))
        for role in self.emission_roles:
            if target.endswith(role):
                state["r0"] = ("emission_result", role)
        if target == "p11_instance_return":
            require(before.get("r2") == ("event", 0x148), error("continuity output boundary"))
            require(before.get(("live", self.start[1])) if self.return_role == "object" else before.get(("settled",)),
                    error("continuity lifetime boundary"))
        if pc in self.retained_sites:
            require(before.get(("live", self.start[1])) if self.return_role == "object" else before.get(("settled",)),
                    error("retained read lifetime boundary"))
            output, size = before.get("r1"), before.get("r2")
            require(output and output[0] == "stack" and size and size[0] == "constant"
                    and -512 <= output[1] and output[1]+size[1] <= 0, error("retained read output outside local frame"))
        if text == "call 0x83" and pc in consumer.helper:
            require(before.get("r1") == ("map", "EVENTS")
                    and before.get("r2") == ("constant", 608 if self.return_role == "object" else 368), error("record reserve size"))
        if text == "call 0x84" and pc in consumer.helper:
            require(before.get("r1") == ("event", 0) and before.get(("settled",)), error("submit before successful retirement"))
            require(before.get(("event_slot",)) == ("low", consumer.identity), error("Event.slot corrupted before submit"))
            require(before.get(("event_user_type",)) == ("retained", 0x38, 32), error("user_type was not copied unchanged"))
            if self.return_role == "object":
                require(before.get(("emitted",)) == frozenset(self.emission_roles), error("submit bypassed successful emission"))
            self.submits.add(pc)
        if text == "exit":
            require(before.get(("retired",)) and (before.get(("settled",)) or before.get(("fault",))),
                    error("exit bypassed checked retirement/fault"))
        return super().transfer(consumer, pc, before, state)

    def edges(self, consumer, pc, before, after):
        branch = BRANCH.fullmatch(consumer.text[pc])
        for successor, state in super().edges(consumer, pc, before, after):
            if branch and (fact := value(before, branch[1])) and fact[0] == "emission_result":
                zero_taken = zero_partition(fact, branch[2], 64) if value(before, branch[3]) == ("constant", 0) else None
                require(zero_taken is not None, consumer.label(pc)+": return emission result guard")
                if (successor == D.relative_target(pc, consumer.text[pc])) != zero_taken:
                    state[("emitted",)] = before.get(("emitted",), frozenset()) | {fact[1]}
            if branch and (fact := value(before, branch[1])) and fact[0] == "retire_result":
                require(branch[1].startswith("r") and value(before, branch[3]) == ("constant", 0) and branch[2] in ("==", "!="),
                        consumer.label(pc)+": return retirement result guard")
                success = (successor == D.relative_target(pc, consumer.text[pc])) == (branch[2] == "==")
                state[("settled",)] = success
            yield successor, state

    def finish(self, consumer):
        require(self.submits, consumer.name+": return no positive submit witness")
        if self.present:
            require(self.boundaries == {pc for pc, (_, _, abi) in self.retained_sites.items() if abi == self.abi},
                    consumer.name+": retained read inventory/layout differs")


def retained_contract(consumer, variant, selectors, internal_blocks, internal_calls):
    root = _ReturnCaller(consumer.section, consumer.name, consumer.lines, consumer.calls)
    gets = [pc for pc, target in root.calls.items() if target == "p11_owner_start_get"]
    require(len(gets) == 1, "return START lookup inventory")
    targets = {}
    bodies = {}
    for role in ("ordinary", "object"):
        names = [name for name in internal_blocks if name.endswith(role+"_return")]
        require(len(names) == 1, "return outlined callee inventory: "+role)
        name = names[0]
        sites = [pc for pc, target in root.calls.items() if target == name]
        require(len(sites) == 1, "return outlined caller inventory: "+role)
        targets[sites[0]] = role
        bodies[role] = _ReturnCaller(".text", name, internal_blocks[name], internal_calls.get(name, {}))
    for selector in selectors:
        root.facts(proof=_ReturnRootProof(int(selector == 0x23), gets[0], targets))
    # Literal role inventories: OpenSession, mechanism and ASYNC_GET_ID each
    # have one actual 4-byte and one 8-byte read. Provenance is checked below.
    inventory = {
        "ordinary": ((0x30,1,1), (0x20,None,1), (0x30,1,0), (0x30,12,1), (0x20,None,0), (0x30,12,0)),
        "object": ((0x30,12,1), (0x20,None,1), (0x30,1,1), (0x20,None,0), (0x30,1,0), (0x30,12,0)),
    }
    report = {}
    for role, body in bodies.items():
        helpers = [pc for pc, text in body.insns if text == "call 0x70" and pc in body.helper]
        require(len(helpers) == 6, body.name+": retained read helper inventory")
        sites = dict(zip(helpers, inventory[role]))
        retires = [pc for pc, target in body.calls.items() if target == "p11_owner_start_remove"]
        require(len(retires) == (1 if role == "ordinary" else 7), body.name+": return retirement inventory")
        for selector in selectors:
            abi = int(selector == 0x23)
            for present in (False, True):
                initial = {"r1": ("context", 0), "r2": ("external_key", root.identity, 0),
                           "r3": ("owned", gets[0], 0), "r4": ("scope_flags", root.identity),
                           "r5": ("constant", abi), "r10": ("stack", 0), ("live", gets[0]): True}
                body.facts(initial, proof=_ReturnProof(abi, present, gets[0], role, sites))
        result = consumer_contract(body, variant, internal_blocks, initial, outlined=True)
        result.update({"function": body.name, "retained_reads": sorted(sites), "retirements": retires})
        report[role] = result
    return {"retained_offsets": [0x20, 0x30], "scenarios": len(selectors)*2, "outlined": report}


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
        previous = nonnull
        nonnull = consumer.step(pc, nonnull)
        if bit := re.fullmatch(r"([rw]\d+) &= 0x1", text):
            if previous.get(reg(bit[1])) == ("field", 5):
                nonnull[reg(bit[1])] = ("field_bit", 5, 1)
    lookups = [pc for pc, text in consumer.insns if pc in consumer.helper and text == "call 0x1"
               and facts.get(pc, {}).get("r1") == ("map", "DESCRIPTORS")]
    if consumer.section == ".text" and consumer.name.endswith(("ordinary_return", "object_return")):
        groups = [{3}]
    elif consumer.name == "p11_entry_template_second":
        groups = [{14, 15}]
    else:
        require(consumer.name.startswith("p11_entry"), consumer.name+": unexpected descriptor consumer")
        groups = [BASE_FIELDS | ({12, 13} if "template" in consumer.name else {16, 17}), {5}]
    require(len(lookups) == len(groups) and lookup in lookups, consumer.name+": descriptor lookup inventory")
    expected = groups[lookups.index(lookup)]
    require(loads == expected, consumer.label(lookup) + f": descriptor fields {loads}, expected {expected}")
    carried = set()
    for key, fact in nonnull.items():
        if not isinstance(fact, tuple) or fact[0] not in ("field", "field_bit"):
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
                or target in ("p11_owner_start_get", "p11_owner_start_begin")
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
    for selector in (0, 0x23, 0x33, 0x100000023, 0x100000033):
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
            admission = (text == "call 0x1" and map_name == ("map", "STATS")) or target in ("p11_owner_start_get", "p11_owner_start_begin")
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
            elif target == "p11_object_fault":
                require(cleaned, consumer.label(pc)+": ABI fault before cleanup")
            elif text == "call 0x1" and map_name == ("map", "STOP_GATE"):
                # The stop-gate release epilogue: admitted paths stop at
                # admission above and never reach it, so only refusal paths
                # arrive here, and only after cleanup plus refusal evidence.
                require(cleaned and refused, consumer.label(pc) + ": gate release without ABI cleanup/refusal")
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
            branch = BRANCH.fullmatch(text)
            if branch:
                left, right = value(state, branch[1]), value(state, branch[3])
                taken = None
                if left and left[0] == "selector_case" and right and right[0] == "constant":
                    require(branch[1].startswith("r") and branch[2] in ("==", "!=") and right[1] in (0x23, 0x33),
                            consumer.label(pc)+": unsupported selector comparison")
                    taken = compare(selector, branch[2], right[1])
                elif left and right and left[0] == right[0] == "constant":
                    taken = compare(left[1], branch[2], right[1], 32 if branch[1].startswith("w") else 64)
                if taken is not None:
                    target = D.relative_target(pc, text)
                    edges = [target] if taken else [edge for edge in edges if edge != target]
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
    identity = getattr(consumer, "identity", (consumer.section, consumer.name))
    reachable = D.reachable(consumer.graph, [consumer.insns[0][0]])
    owner, maps, keys, values, records = Counter(), Counter(), set(), set(), []
    for pc, text in consumer.insns:
        state, target = facts.get(pc, {}), consumer.calls.get(pc, "")
        if target.startswith("p11_owner_start_"):
            require(pc in reachable, consumer.label(pc)+": unreachable START operation")
            key = state.get("r1")
            require(key and key[0] == "stack", consumer.label(pc)+": START key address")
            require(stack_read(state, key, 8) == ("pid_tgid", identity), consumer.label(pc)+": START pid_tgid provenance")
            require(stack_read(state, key, 4, 8) == ("low", identity), consumer.label(pc)+": START slot provenance")
            require(stack_read(state, key, 4, 12) == ("constant", 0), consumer.label(pc)+": START zero padding")
            keys.add(key)
            operation, argument = target.removeprefix("p11_owner_start_"), state.get("r2")
            if operation == "begin":
                require(argument and argument[0] == "stack" and argument != key
                        and stack_read(state, argument, 8) == ("ktime_ns", identity), consumer.label(pc)+": START immutable seed address/timestamp")
                values.add(argument)
                role = "begin"
            elif operation == "aggregate":
                require(argument == ("ktime_ns", identity), consumer.label(pc)+": START aggregate scalar timestamp")
                role = "aggregate"
            elif operation == "get" and variant == "default":
                require(incoming_parameter_unused(internal_blocks[target], 2), "default START get retains an unexpected required argument")
                role = "get0-specialized"
            else:
                require(operation in ("get", "remove") and argument in (("constant", 0), ("constant", 1)),
                        consumer.label(pc)+": START required argument/operation")
                role = operation+str(argument[1])
            owner[role] += 1
            records.append((pc, "START."+role))
        if pc in consumer.helper:
            name = state.get("r1", (None, None))
            if name[0] == "map" and name[1] in ("STATS", "RV_COUNTS", "DESCRIPTORS", "EVENTS"):
                require(pc in reachable, consumer.label(pc)+": unreachable map operation")
                maps[(name[1], text)] += 1
                records.append((pc, name[1]+"."+text))
            if text in ("call 0x84", "call 0x85"):
                require(state.get("r1") == ("event", 0), consumer.label(pc)+": submitted/discarded event address")
                if text == "call 0x84":
                    require(state.get(("event_slot",)) == ("low", identity), consumer.label(pc)+": Event.slot corrupted before submit")
                maps[("EVENTS", text)] += 1
                records.append((pc, "EVENTS."+("submit" if text == "call 0x84" else "discard")))
    name = consumer.name
    outlined = consumer.section == ".text" and name.endswith(("ordinary_return", "object_return"))
    if outlined:
        expected_owner = Counter({"remove1": 7 if name.endswith("object_return") else 1})
    elif name == "p11_return":
        expected_owner = Counter({"remove0": 2, "get0-specialized" if variant == "default" else "get0": 1})
    elif name == "p11_entry_template_second":
        expected_owner = Counter({"remove0": 1, "get1": 1})
    else:
        strict = variant == "unsafe" and name in ("p11_entry", "p11_entry_ia32")
        expected_owner = Counter({"begin": 1, "aggregate": 1, "remove0": 3 if strict else 2, "remove1": 1})
    expected_maps = Counter()
    if name != "p11_return":
        expected_maps[("DESCRIPTORS", "call 0x1")] = 1 if outlined or name == "p11_entry_template_second" else 2
    if name not in ("p11_return", "p11_entry_template_second"):
        expected_maps[("STATS", "call 0x1")] = 1
    if outlined:
        expected_maps.update({("RV_COUNTS", "call 0x1"): 2, ("RV_COUNTS", "call 0x2"): 1,
                              ("EVENTS", "call 0x83"): 1, ("EVENTS", "call 0x84"): 1})
        if name.endswith("object_return"):
            expected_maps[("EVENTS", "call 0x85")] = 1
    require(owner == expected_owner, name+f": START operation inventory {owner}, expected {expected_owner}")
    require(maps == expected_maps, name+f": distinct map operation inventory differs: {maps}")
    require(len(keys) == 1 and len(values) == int("begin" in expected_owner), name+": START operation key/seed wiring differs")
    return records


def consumer_contract(consumer, variant, internal_blocks, initial=None, outlined=False):
    facts = consumer.facts(initial)
    identity = getattr(consumer, "identity", (consumer.section, consumer.name))
    sinks, descriptors, bounds = [], [], []
    for pc, text in consumer.insns:
        state, target = facts.get(pc, {}), consumer.calls.get(pc, "")
        map_name = state.get("r1", (None, None))
        if match := re.fullmatch(r"if ([rw]\d+) > 0x1ff goto [+-]0x[0-9a-f]+", text):
            require(state.get(reg(match[1])) == ("low", identity), consumer.label(pc)+": slot bound uses cookie low word")
            bounds.append(pc)
        if pc in consumer.helper and text in ("call 0x1", "call 0x2") and map_name[0] == "map":
            if map_name[1] in ("STATS", "RV_COUNTS", "DESCRIPTORS"):
                word = "high" if map_name[1] == "DESCRIPTORS" else "low"
                require(stack_read(state, state.get("r2"), 4) == (word, identity), consumer.label(pc)+": "+map_name[1]+" cookie key")
                sinks.append((pc, map_name[1]))
                if word == "high":
                    descriptors.append(pc)
        if target.startswith("p11_owner_start_"):
            require(stack_read(state, state.get("r1"), 4, 8) == ("low", identity), consumer.label(pc)+": START slot cookie")
            sinks.append((pc, "START"))
        if match := STORE.fullmatch(text):
            if address(state, match[2], match[3], match[4]) == ("event", 0x68):
                require(match[1] == "32" and narrow(value(state, match[5]), 32) == ("low", identity), consumer.label(pc)+": Event.slot cookie")
                sinks.append((pc, "Event.slot"))
    required = {"START"} if consumer.name == "p11_return" else {"DESCRIPTORS", "START"}
    if consumer.name not in ("p11_return", "p11_entry_template_second"):
        required.add("STATS")
    if outlined:
        required |= {"RV_COUNTS", "Event.slot"}
    require({sink for _, sink in sinks} == required, consumer.name+": sink inventory differs")
    require(len(bounds) == (0 if outlined else 1), consumer.name+": slot bound inventory")
    if bounds:
        bound = bounds[0]
        observation = {pc for pc, _ in sinks}
        rejected = D.relative_target(bound, consumer.text[bound])
        require(not observation & D.reachable(consumer.graph, [consumer.insns[0][0]], blocked={bound})
                and not observation & D.reachable(consumer.graph, [rejected]), consumer.name+": slot bound refusal/bypass")
    expected_descriptors = 0 if consumer.name == "p11_return" else 1 if outlined or consumer.name == "p11_entry_template_second" else 2
    require(len(descriptors) == expected_descriptors, consumer.name+": descriptor lookup inventory")
    fields = sorted({field for pc in descriptors for field in descriptor_contract(consumer, facts, pc)})
    selectors = [] if outlined else abi_contract(consumer, facts, variant)
    operations = operation_contract(consumer, facts, variant, internal_blocks)
    return {"section": consumer.section, "sinks": sinks, "operations": operations,
            "descriptor_fields": fields, "accepted_selectors": selectors}


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
    seeded_start_contract(disassembly)
    report = {}
    for section in ("uprobe", "uretprobe"):
        require(section in split, "missing "+section)
        calls = D.internal_call_targets(split[section]+"\n"+split[".text"])
        for name, lines in D.function_blocks(split[section]).items():
            if not (name.startswith("p11_entry") or name == "p11_return"):
                continue
            caller = _ReturnCaller if name == "p11_return" else _SeedCaller
            consumer = caller(section, name, lines, {pc: target for caller, _, pc, target in calls if caller == name})
            result = consumer_contract(consumer, variant, internal_blocks)
            result["final_sinks"] = final_sink_contract(consumer, variant, result["accepted_selectors"], internal_blocks, internal_calls)
            report[name] = result
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
