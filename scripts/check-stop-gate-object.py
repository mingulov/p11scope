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
  access must be inside admission.

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
            flag = transition(pc, flag)
            pending.extend((successor, flag) for successor in consumer.graph[pc])

    def admission(self, pc, admitted):
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

        self.walk(False, lambda pc, seen: seen or pc in self.dec_sites, leaked)

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

        self.walk(False, lambda pc, seen: seen or pc in self.cas_sites, early)

    def check_balance(self):
        exits = {
            pc for pc, text in self.consumer.insns if text == "exit"
        }
        require(exits, self.label() + ": program has no exit")

        def unbalanced(pc, admitted):
            if pc in self.capture_sites and not admitted:
                return "capture-map access outside admission"
            if pc in exits and admitted:
                return "exit without a balancing decrement"
            return None

        self.walk(self.role in (LEAVE_ONLY, LEAVE_TAIL), self.admission, unbalanced)

    def classify(self):
        self.check_relocation()
        self.classify_atomics()
        self.classify_calls()
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
