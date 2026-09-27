#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stop-gate object contract for the Detailed programs.

For each static entry/return program (plan 2026-09-23 Task 2) and each
discovery, lifecycle and native fork program (Task 3) the compiled
object must prove the admission discipline:

- a STOP_GATE relocation (the program looks the gate cell up);
- a compare-exchange read of the gate cell before the first capture-map
  or native-helper access (STATS, START helpers, RV_COUNTS, EVENTS,
  EVIDENCE, identity, DISCOVERY, COUNTERS, discovery helpers, owner
  cleanup, root exit/propagation, fork emission);
- a balancing decrement on every exit path of an admitted body, checked
  by walking the program's control-flow graph. The deny exit of
  ``stop_gate_enter`` carries no increment, so it must carry no
  decrement either: every exit must be balanced, and every capture
  access must be inside admission. The one exception is the leave's
  own null check (the 5.15 verifier rejects an unchecked STOP_GATE
  dereference): an admitted exit is excused only along the null edge
  of a null check on the gate-cell pointer whose sibling path still
  holds the decrement, so removing the decrement fails the proof.

The continuations (``p11_entry_template_second`` after the template
pair, ``interface_list_worker`` after ``interface_list_return`` and
after itself) carry admission across the tail call: they must reference
STOP_GATE, must decrement on every exit, and must never re-check the
gate (no CAS read, no increment). A carrying program must not decrement
on any path from entry to the tail-call site, and every such path must
be admitted; a failed tail call falls through to cleanup and then
leaves, which the balance walk proves.

Gate-cell atomics are classified by following the gate-cell pointer
from each STOP_GATE lookup to the atomic instructions through it: the
entry checker's must-facts where they survive, plus a may-provenance
union across joins (LLVM shares one release epilogue between the
enter second-read-failure path and the guarded-body release, joining
two lookup provenances). A non-fetch ``lock``
add of exactly +1/-1 and a 64-bit compare-exchange at cell offset 0
with must-fact zero operands are the only recognized forms; any other
atomic through the gate cell (in particular any fetch form) is
rejected, and the raw instruction bytes must agree (0xdb/imm 0 for
register adds, 0xf1 for compare-exchange).
"""

import argparse
from collections import deque
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_sibling


D = load_sibling("check-live-discovery-object.py")
ENTRY = load_sibling("check-entry-object.py")

SCHEMA = "p11scope-stop-gate-object/v1"
CAPTURE_MAPS = frozenset({"STATS", "RV_COUNTS", "EVENTS", "EVIDENCE", "DISCOVERY", "COUNTERS"})
NATIVE_CALL_PREFIX = "p11_"
TAIL_CALL = "call 0xc"
ENTER = "enter"
CARRY = "carry"
LEAVE_ONLY = "leave-only"
LEAVE_TAIL = "leave-tail"
TASK3_PROGRAMS = {
    "function_list_entry": ENTER,
    "function_list_return": ENTER,
    "interface_list_entry": ENTER,
    "interface_list_return": CARRY,
    "interface_list_worker": LEAVE_TAIL,
    "interface_entry": ENTER,
    "interface_return": ENTER,
    "dl_debug_state": ENTER,
    "sched_process_exec": ENTER,
    "sched_process_exit": ENTER,
    "task_newtask": ENTER,
}
PROGRAMS = {
    "default": {"p11_entry": ENTER, "p11_return": ENTER, **TASK3_PROGRAMS},
    "unsafe": {
        "p11_entry": ENTER,
        "p11_entry_ia32": ENTER,
        "p11_entry_template": ENTER,
        "p11_entry_template_pair": CARRY,
        "p11_entry_template_second": LEAVE_ONLY,
        "p11_entry_template_types": ENTER,
        "p11_return": ENTER,
        **TASK3_PROGRAMS,
    },
}
PROGRAM_SECTIONS = (
    "uprobe",
    "uretprobe",
    "raw_tp/sched_process_exec",
    "raw_tp/sched_process_exit",
    "tp_btf/task_newtask",
)
GATE_ADD = re.compile(r"lock \*\(u(32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) \+= (\S+)")
GATE_NULL_EQ = re.compile(r"if r(\d+) == 0x0 goto \+0x([0-9a-f]+)")
GATE_NULL_NE = re.compile(r"if r(\d+) != 0x0 goto \+0x([0-9a-f]+)")
GATE_CAS = re.compile(r"r(\d+) = cmpxchg_(32|64)\(r(\d+) ([+-]) 0x([0-9a-f]+), r(\d+), r(\d+)\)")
GATE_REGISTER = re.compile(r"r(\d+)")
# The raw bytes lead the entry text; the last byte is followed by a tab,
# not a space, so it needs its own group.
RAW_PREFIX = re.compile(r"((?:[0-9a-f]{2} )+[0-9a-f]{2})")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def disassemble(path):
    completed = subprocess.run(
        ["llvm-objdump", "-dr", "--print-imm-hex", str(path)],
        capture_output=True, text=True, check=True,
    )
    return completed.stdout


def signed_offset(sign, digits):
    return int(digits, 16) * (1 if sign == "+" else -1)


class GateAnalysis:
    """The classified gate operations of one static program."""

    def __init__(self, section, name, lines, calls, role):
        self.section, self.name, self.role = section, name, role
        self.consumer = ENTRY.Consumer(section, name, lines, calls)
        self.facts = self.consumer.facts()
        self.raw = {}
        for _, pc, text in D.instruction_entries(lines):
            match = RAW_PREFIX.match(text)
            self.raw[pc] = (
                bytes(int(byte, 16) for byte in match.group(1).split()) if match else b""
            )
        self.gate_lookups = {
            pc
            for pc, text in self.consumer.insns
            if pc in self.consumer.helper
            and text == "call 0x1"
            and self.facts.get(pc, {}).get("r1") == ("map", "STOP_GATE")
        }
        # May-provenance of the gate-cell pointer per register. The
        # must-facts above lose the pointer where LLVM joins paths with
        # different lookups (the shared release epilogue reuses the enter
        # lookup's pointer on the second-read-failure path and the leave
        # lookup's pointer on the normal path), so take the union across
        # predecessors. Sets hold gate-lookup PCs only; a missed
        # provenance breaks the balance proof loudly, never silently.
        self.provenance = self.compute_provenance()
        self.cas_sites, self.inc_sites, self.dec_sites = set(), set(), set()
        self.tail_sites = set()
        self.capture_sites = set()
        self.leave_guards = {}

    def label(self, pc=None):
        base = f"{self.section}:{self.name}"
        return base if pc is None else f"{base}:{pc}"

    def step_provenance(self, pc, incoming):
        state = {register: set(sites) for register, sites in incoming.items()}
        text = self.consumer.text[pc]
        if text.startswith("call "):
            for index in range(6):
                state.pop("r" + str(index), None)
            if (
                pc in self.consumer.helper
                and text == "call 0x1"
                and self.facts.get(pc, {}).get("r1") == ("map", "STOP_GATE")
            ):
                state["r0"] = {pc}
            return state
        match = re.fullmatch(
            r"([rw]\d+) (=|\+=|<<=|>>=|&=) ([rw]\d+|-?0x[0-9a-f]+)(?: ll)?", text
        )
        if match:
            dst, op, src = match.groups()
            state.pop("r" + dst[1:], None)
            if op == "=" and dst.startswith("r") and src.startswith("r"):
                sites = incoming.get("r" + src[1:])
                if sites:
                    state["r" + dst[1:]] = set(sites)
            return state
        if match := re.match(r"[rw](\d+)\s", text):
            state.pop("r" + match[1], None)
        return state

    def compute_provenance(self):
        consumer = self.consumer
        start = consumer.insns[0][0]
        incoming = {start: {}}
        pending = deque([start])
        while pending:
            pc = pending.popleft()
            after = self.step_provenance(pc, incoming[pc])
            for successor in consumer.graph[pc]:
                # Unvisited is None: an empty union must still enqueue, or
                # propagation dies at the first pointer-free state.
                previous = incoming.get(successor)
                base = previous if previous is not None else {}
                merged = {
                    register: base.get(register, set()) | after.get(register, set())
                    for register in set(base) | set(after)
                }
                merged = {register: sites for register, sites in merged.items() if sites}
                if previous is None or previous != merged:
                    incoming[successor] = merged
                    pending.append(successor)
        return incoming

    def is_gate_cell(self, pc, register):
        if self.provenance.get(pc, {}).get("r" + register):
            return True
        fact = self.facts.get(pc, {}).get("r" + register)
        return (
            fact is not None
            and fact[0] == "result"
            and fact[1] in self.gate_lookups
        )

    def check_relocation(self):
        require(
            "STOP_GATE" in self.consumer.maps.values(),
            self.label() + ": missing STOP_GATE relocation",
        )

    def check_raw(self, pc, code, immediate):
        raw = self.raw.get(pc, b"")
        require(
            len(raw) >= 8
            and raw[0] == code
            and int.from_bytes(raw[4:8], "little") == immediate,
            self.label(pc) + ": gate atomic raw encoding differs",
        )

    def classify_delta(self, pc, source, state):
        if source.startswith("r"):
            fact = state.get("r" + source[1:])
            require(
                fact is not None and fact[0] == "constant",
                self.label(pc) + ": gate delta is not a known constant",
            )
            value = fact[1] & ((1 << 64) - 1)
        else:
            try:
                value = int(source, 16) & ((1 << 64) - 1)
            except ValueError:
                value = None
            require(value is not None, self.label(pc) + ": gate delta is not a constant")
        require(
            value in (1, (1 << 64) - 1),
            self.label(pc) + ": gate delta is not +1/-1",
        )
        return 1 if value == 1 else -1

    def classify_atomics(self):
        for pc, text in self.consumer.insns:
            require(
                "atomic" not in text,
                self.label(pc) + ": fetch-form atomic is forbidden in gated programs",
            )
            if "xchg" not in text and not text.startswith("lock "):
                continue
            state = self.facts.get(pc, {})
            gate_registers = {
                register
                for register in GATE_REGISTER.findall(text)
                if self.is_gate_cell(pc, register)
            }
            if not gate_registers:
                continue
            if match := GATE_CAS.fullmatch(text):
                _, width, base, sign, offset, expected, desired = match.groups()
                require(
                    width == "64"
                    and base in gate_registers
                    and signed_offset(sign, offset) == 0,
                    self.label(pc) + ": unrecognized gate compare-exchange",
                )
                for operand in (expected, desired):
                    fact = state.get("r" + operand)
                    require(
                        fact is not None,
                        self.label(pc) + ": gate read CAS operand is not a known constant",
                    )
                    require(
                        fact == ("constant", 0),
                        self.label(pc) + ": gate read CAS operand is nonzero",
                    )
                self.check_raw(pc, 0xDB, 0xF1)
                self.cas_sites.add(pc)
            elif match := GATE_ADD.fullmatch(text):
                width, base, sign, offset, source = match.groups()
                require(
                    width == "64"
                    and base in gate_registers
                    and signed_offset(sign, offset) == 0,
                    self.label(pc) + ": unrecognized gate add",
                )
                self.check_raw(pc, 0xDB, 0x00)
                if self.classify_delta(pc, source, state) > 0:
                    self.inc_sites.add(pc)
                else:
                    self.dec_sites.add(pc)
            else:
                raise RuntimeError(self.label(pc) + ": unrecognized gate atomic")

    def classify_calls(self):
        consumer = self.consumer
        for pc, text in consumer.insns:
            state = self.facts.get(pc, {})
            if pc in consumer.helper and text in ("call 0x1", "call 0x2", "call 0x6"):
                if state.get("r1", (None,))[0] == "map" and state["r1"][1] in CAPTURE_MAPS:
                    self.capture_sites.add(pc)
            elif pc in consumer.helper and text == "call 0x83":
                if state.get("r1", (None,))[0] == "map" and state["r1"][1] in CAPTURE_MAPS:
                    self.capture_sites.add(pc)
            elif pc in consumer.helper and text in ("call 0x84", "call 0x85"):
                self.capture_sites.add(pc)
            elif text == TAIL_CALL and pc in consumer.helper:
                if state.get("r2") == ("map", "TAIL_CALLS"):
                    self.tail_sites.add(pc)
            target = consumer.calls.get(pc, "")
            if target.startswith(NATIVE_CALL_PREFIX):
                self.capture_sites.add(pc)

    def straight_dec(self, start):
        """The decrement reached from `start` by straight-line code, if any.

        Follows single-successor edges at most two steps (the delta load
        plus the atomic itself, or an immediate-form atomic at `start`).
        The skipped stretch must hold nothing but the decrement: no
        capture, increment, CAS, or tail call hides inside a null skip.
        """
        current, steps = start, 0
        while steps <= 2:
            if current in self.dec_sites:
                return current
            if (
                current in self.inc_sites
                or current in self.cas_sites
                or current in self.capture_sites
                or current in self.tail_sites
            ):
                return None
            successors = self.consumer.graph.get(current, ())
            if len(successors) != 1:
                return None
            current, steps = successors[0], steps + 1
        return None

    def classify_leave_guards(self):
        """Null checks whose sibling path holds the leave decrement.

        The 5.15 verifier rejects an unchecked STOP_GATE dereference, so
        every leave guards its lookup and the null edge skips the
        decrement. Two codegen shapes occur: `if rX == 0 goto` over the
        [delta load, decrement] pair rejoining right after it, and the
        inverted `if rX != 0 goto` forward to the decrement with the
        decrement path rejoining the fall-through. A guard excuses an
        admitted exit only along its null edge, and only while the
        decrement stays present on the sibling path: removing the
        decrement dissolves the guard and the balance proof fails.
        """
        for pc, text in self.consumer.insns:
            match = GATE_NULL_EQ.fullmatch(text)
            null_is_taken = True
            if match is None:
                match = GATE_NULL_NE.fullmatch(text)
                null_is_taken = False
            if match is None:
                continue
            register, offset = match.groups()
            if not self.is_gate_cell(pc, register):
                continue
            target = pc + 1 + int(offset, 16)
            if null_is_taken:
                null_edge, sibling = target, pc + 1
            else:
                null_edge, sibling = pc + 1, target
            dec = self.straight_dec(sibling)
            if dec is None:
                continue
            if null_is_taken:
                if null_edge != dec + 1:
                    continue
            else:
                current, rejoined = dec, False
                for _ in range(2):
                    successors = self.consumer.graph.get(current, ())
                    if len(successors) != 1:
                        break
                    current = successors[0]
                    if current == null_edge:
                        rejoined = True
                        break
                if not rejoined:
                    continue
            self.leave_guards[pc] = null_edge

    def walk(self, initial, transition, violation):
        """Walk every (instruction, flag) state; the first violation raises."""
        consumer = self.consumer
        start = consumer.insns[0][0]
        seen, pending = set(), [(start, initial)]
        while pending:
            pc, flag = pending.pop()
            if (pc, flag) in seen:
                continue
            seen.add((pc, flag))
            message = violation(pc, flag)
            if message is not None:
                raise RuntimeError(self.label(pc) + ": " + message)
            for successor in consumer.graph[pc]:
                pending.append((successor, transition(pc, flag, successor)))

    def admission(self, pc, admitted, successor):
        if pc in self.inc_sites:
            return True
        if pc in self.dec_sites:
            return False
        return admitted

    def check_tail_carry(self, initial):
        require(self.tail_sites, self.label() + ": carrying program lost its tail call")

        def leaked(pc, seen):
            if pc in self.tail_sites and seen:
                return "decrement before the tail call drops the carried admission"
            return None

        self.walk(False, lambda pc, seen, successor: seen or pc in self.dec_sites, leaked)

        def unadmitted(pc, admitted):
            if pc in self.tail_sites and not admitted:
                return "tail call without carried admission"
            return None

        self.walk(initial, self.admission, unadmitted)

    def check_cas_before_capture(self):
        if self.role in (LEAVE_ONLY, LEAVE_TAIL):
            reachable = D.reachable(self.consumer.graph, [self.consumer.insns[0][0]])
            require(
                not (self.cas_sites & reachable),
                self.label() + ": continuation re-checks the gate",
            )
            require(
                not (self.inc_sites & reachable),
                self.label() + ": continuation re-checks the gate",
            )
            return

        def early(pc, seen):
            if pc in self.capture_sites and not seen:
                return "capture-map access before the gate CAS read"
            return None

        self.walk(False, lambda pc, seen, successor: seen or pc in self.cas_sites, early)

    def check_balance(self):
        exits = {
            pc for pc, text in self.consumer.insns if text == "exit"
        }
        require(exits, self.label() + ": program has no exit")

        def transition(pc, flag, successor):
            admitted, _excused = flag
            if pc in self.inc_sites:
                return (True, False)
            if pc in self.dec_sites:
                return (False, False)
            if self.leave_guards.get(pc) == successor:
                return (admitted, True)
            return flag

        def unbalanced(pc, flag):
            admitted, excused = flag
            if pc in self.capture_sites and (not admitted or excused):
                return "capture-map access outside admission"
            if pc in exits and admitted and not excused:
                return "exit without a balancing decrement"
            return None

        initial = (self.role in (LEAVE_ONLY, LEAVE_TAIL), False)
        self.walk(initial, transition, unbalanced)

    def classify(self):
        self.check_relocation()
        self.classify_atomics()
        self.classify_calls()
        self.classify_leave_guards()
        return self

    def check(self):
        self.classify()
        require(
            self.capture_sites,
            self.label() + ": no capture-map access classified",
        )
        if self.role == CARRY:
            self.check_tail_carry(False)
        if self.role == LEAVE_TAIL:
            self.check_tail_carry(True)
        self.check_cas_before_capture()
        self.check_balance()
        return {
            "section": self.section,
            "role": self.role,
            "instructions": len(self.consumer.insns),
            "gate_lookups": sorted(self.gate_lookups),
            "cas": sorted(self.cas_sites),
            "inc": sorted(self.inc_sites),
            "dec": sorted(self.dec_sites),
            "tail_calls": sorted(self.tail_sites),
        }


# Per-CPU counter maps. From Linux 6.1 uprobe programs run migrate-disabled
# but preemptible, so two programs on one CPU can interleave inside a plain
# load/add/store of a per-CPU cell and lose an increment. Every write into one
# of these cells must be a non-fetch ``lock`` add. The one exception is
# SlotStats.max_ns (offset 0x20): a monotone best-effort maximum, never a sum.
COUNTER_MAPS = frozenset({"STATS", "EVIDENCE", "COUNTERS", "RV_COUNTS"})
RACY_MAXIMA = frozenset({("STATS", 0x20)})
CELL_STORE = re.compile(r"\*\(u(8|16|32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) = \S+")
CELL_ATOMIC = re.compile(r"lock \*\(u(32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) \+= r\d+")
CELL_POINTER = re.compile(r"(?:\*\(u\d+ \*\)|cmpxchg_\d+|xchg_\d+|atomic_\w+\(\(u\d+ \*\))\(?r(\d+) [+-]")


def counter_cell_facts(lines):
    """Must-facts: register -> ("map", name) | ("cell", name, offset|None).

    Like the live-discovery cell owners, but a cell pointer keeps its owner
    through pointer arithmetic (an unknown index clears only the offset), so a
    write into an indexed histogram bucket is still attributed to its map.
    Anything unrecognized clears the register; joins intersect.
    """
    insns, graph = D.instruction_graph(lines)
    if not insns:
        return {}
    relocs = {index: (kind, target) for index, kind, target in D.relocation_targets(lines)}
    loads = {}
    for index, pc, text in D.instruction_entries(lines):
        decoded = re.sub(r"^(?:[0-9a-f]{2}\s+){8,16}", "", text)
        match = re.fullmatch(r"r(\d+) = 0x0 ll", decoded)
        if match and relocs.get(index + 1, (None, None))[0] == "64":
            loads[pc] = (match.group(1), relocs[index + 1][1])
    texts = dict(insns)
    incoming = {insns[0][0]: {}}
    pending = [insns[0][0]]
    while pending:
        pc = pending.pop()
        state = incoming[pc].copy()
        text = texts[pc]
        if re.search(r"\bcall ", text):
            lookup = state.get("r1")
            for register in range(6):
                state.pop("r" + str(register), None)
            if text == "call 0x1" and lookup is not None and lookup[0] == "map":
                state["r0"] = ("cell", lookup[1], 0)
        elif pc in loads and re.fullmatch(r"r\d+ = 0x0 ll", text):
            register, target = loads[pc]
            state["r" + register] = ("map", target)
        elif match := re.fullmatch(r"r(\d+) = r(\d+)", text):
            value = state.get("r" + match.group(2))
            state.pop("r" + match.group(1), None)
            if value is not None:
                state["r" + match.group(1)] = value
        elif match := re.fullmatch(r"r(\d+) \+= (r\d+|-?0x[0-9a-f]+)", text):
            value = state.pop("r" + match.group(1), None)
            if value is not None and value[0] == "cell":
                delta = match.group(2)
                offset = (value[2] + int(delta, 16)
                          if value[2] is not None and not delta.startswith("r") else None)
                state["r" + match.group(1)] = ("cell", value[1], offset)
        elif match := re.match(r"[rw](\d+)\s", text):
            state.pop("r" + match.group(1), None)
        for successor in graph[pc]:
            if successor not in incoming:
                merged = state.copy()
            else:
                merged = {key: value for key, value in incoming[successor].items()
                          if state.get(key) == value}
            if incoming.get(successor) != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming


def counter_cells_contract(disassembly):
    """Every attributed write into a per-CPU counter cell is a non-fetch atomic
    add, and RV_COUNTS is only ever created with BPF_NOEXIST (an existing row
    is updated in place, so a racing creator cannot overwrite a count)."""
    split = ENTRY.sections(disassembly)
    atomic_updates = 0
    rv_creates = 0
    for section in (*PROGRAM_SECTIONS, ".text"):
        if section not in split:
            continue
        for name, lines in D.function_blocks(split[section]).items():
            facts = counter_cell_facts(lines)
            arguments = D.call_argument_facts(lines)
            insns, _ = D.instruction_graph(lines)
            for pc, text in insns:
                state = facts.get(pc, {})
                label = f"{section}:{name}:{pc}"
                if match := CELL_ATOMIC.fullmatch(text):
                    cell = state.get("r" + match.group(2))
                    if cell and cell[0] == "cell" and cell[1] in COUNTER_MAPS:
                        atomic_updates += 1
                    continue
                if match := CELL_STORE.fullmatch(text):
                    width, base, sign, digits = match.groups()
                    cell = state.get("r" + base)
                    if cell and cell[0] == "cell" and cell[1] in COUNTER_MAPS:
                        offset = (None if cell[2] is None
                                  else cell[2] + signed_offset(sign, digits))
                        require(width == "64" and (cell[1], offset) in RACY_MAXIMA,
                                f"{label}: non-atomic write to a {cell[1]} counter cell")
                    continue
                if match := CELL_POINTER.search(text):
                    cell = state.get("r" + match.group(1))
                    require(not (cell and cell[0] == "cell" and cell[1] in COUNTER_MAPS
                                 and ("atomic" in text or "xchg" in text)),
                            f"{label}: fetch-form atomic on a {cell and cell[1]} counter cell")
                if text == "call 0x2" and state.get("r1") == ("map", "RV_COUNTS"):
                    require(arguments.get(pc, {}).get("r4") == ("constant", 1),
                            f"{label}: RV_COUNTS row created without BPF_NOEXIST")
                    rv_creates += 1
    require(atomic_updates, "no atomic counter-cell update classified")
    require(rv_creates, "no RV_COUNTS row creation classified")
    return {"atomic_updates": atomic_updates, "rv_creates": rv_creates}


def analyze(disassembly, variant):
    require(variant in PROGRAMS, "unknown variant " + variant)
    split = ENTRY.sections(disassembly)
    for section in (*PROGRAM_SECTIONS, ".text"):
        require(section in split, "missing " + section)
    analyses = {}
    for name, role in PROGRAMS[variant].items():
        found = None
        for section in PROGRAM_SECTIONS:
            blocks = D.function_blocks(split[section])
            if name in blocks:
                require(found is None, "duplicate program " + name)
                found = (section, blocks[name])
        require(found is not None, "missing program " + name)
        section, lines = found
        calls = {
            pc: target
            for caller, _, pc, target in D.internal_call_targets(
                split[section] + "\n" + split[".text"]
            )
            if caller == name
        }
        analyses[name] = GateAnalysis(section, name, lines, calls, role)
    return analyses


def check_decoded(disassembly, variant):
    return {
        "schema": SCHEMA,
        "variant": variant,
        "status": "ok",
        "programs": {
            name: analysis.check() for name, analysis in analyze(disassembly, variant).items()
        },
        "counter_cells": counter_cells_contract(disassembly),
    }


def check_object(path, variant):
    data = Path(path).read_bytes()
    D.map_checker()["Elf"](data)
    return check_decoded(disassemble(path), variant)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=sorted(PROGRAMS))
    args = parser.parse_args()
    report = check_object(args.object, args.variant)
    print(json.dumps(report, sort_keys=True))
    print(
        "stop-gate {variant}: programs={programs} OK".format(
            variant=args.variant, programs=len(report["programs"])
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
