# SPDX-License-Identifier: GPL-3.0-or-later
"""Caller object ABI and bounded execution of actual ordinary-entry bytecode.

The concrete runner implements only the instruction subset reached by these
finite cells. Scope and native identity are explicit stub boundaries; this is
neither a kernel verifier nor a test of native identity allocation. Unknown
instructions, calls, memory, or more than 10,000 steps fail closed.
"""
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

checker = load_path(ROOT / "scripts/check-bpf-map-defs.py", "caller_map_checker")

# Independent manifest: never obtain expected shapes from the caller freeze.
MAPS = {name: checker.map_def(*shape) for name, shape in {
    "CONFIG": (2, 4, 8, 2, 128), "PID_FILTER": (1, 4, 8, 1024, 128),
    "CGROUP_FILTER": (8, 4, 4, 1), "TAIL_CALLS": (3, 4, 4, 2),
    "EVIDENCE": (6, 4, 8, 9), "COUNTERS": (6, 4, 8, 5),
    "DISCOVERY": (27, 0, 0, 65536), "DISCOVERY_STATE": (1, 24, 24, 64),
    "THREAD_OWNER": (29, 4, 544, 0, 1), "OWNER_CTL": (2, 4, 56, 1),
    "USAGE": (2, 4, 8, 1), "USAGE_CONFIG": (2, 4, 8, 1, 128),
    "USAGE_EVIDENCE": (6, 4, 8, 3), "ENDPOINT_OBJECT": (2, 4, 8, 1, 128),
    "CALLER_USE": (1, 24, 32, 1), "CALLER_EVIDENCE": (6, 4, 8, 4),
    "TASK_COOKIE": (29, 4, 8, 0, 1), "COOKIE_CTL": (2, 4, 40, 1),
}.items()}
PROGRAMS = {"p11_usage_entry_lp64", "p11_usage_entry_ia32", "dl_debug_state",
            "function_list_entry", "function_list_return", "interface_list_entry",
            "interface_list_return", "interface_list_worker", "interface_entry",
            "interface_return", "sched_process_exec", "sched_process_exit"}
SYMBOLS = {"p11_owner_reserve", "p11_owner_refund", "p11_read_ia32_arg",
           "p11_link_current_identity"}
MASK = (1 << 64) - 1
TAIL_CALLS_ID = 0x7F0000  # a map id outside every modelled map segment
TAG = 0x50555347


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class CallerManifestTests(unittest.TestCase):
    def test_exact_caller_manifest_and_each_field_mutation(self):
        for variant in ("inventory-callers", "inventory-callers-small-discovery"):
            maps = {name: dict(value) for name, value in MAPS.items()}
            if variant.endswith("small-discovery"):
                maps["DISCOVERY"]["max_entries"] = 4096
            checker.validate_inventory(variant, maps, PROGRAMS, SYMBOLS)
            for name in maps:
                for field in checker.MAP_FIELDS:
                    changed = {key: dict(value) for key, value in maps.items()}
                    changed[name][field] ^= 1
                    with self.subTest(variant=variant, name=name, field=field), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                        checker.validate_inventory(variant, changed, PROGRAMS, SYMBOLS)

    def test_no_detailed_roots_helpers_or_maps_and_no_missing_identity(self):
        for root in PROGRAMS:
            with self.subTest(missing=root), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory-callers", MAPS, PROGRAMS - {root}, SYMBOLS)
        for root in ("p11_entry", "p11_return", "task_newtask", "iterator"):
            with self.subTest(extra=root), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory-callers", MAPS, PROGRAMS | {root}, SYMBOLS)
        for name in ("START", "EVENTS", "ROOT_CTL", "p11_link_emit_fork", "p11_link_fork_allowed",
                     "p11_root_current_exit", "p11_owner_start_get", "p11_link_task_identity"):
            with self.subTest(symbol=name), self.assertRaises(RuntimeError):
                checker.validate_inventory("inventory-callers", MAPS, PROGRAMS, SYMBOLS | {name})
        with self.assertRaises(RuntimeError):
            checker.validate_inventory("inventory-callers", MAPS, PROGRAMS,
                                       SYMBOLS - {"p11_link_current_identity"})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
            checker.validate_inventory("inventory", MAPS, PROGRAMS, SYMBOLS)


class EntryMachine:
    """Fixed memory/map backend executing the compiled entry, not its algorithm."""
    def __init__(self, body, capacity=10, pair_capacity=4):
        self.elf = checker.Elf(body)
        self.roots = {s[0]: s for s in self.elf.symbols
                      if s[0] in {"p11_usage_entry_lp64", "p11_usage_entry_ia32"}}
        self.functions = {s[3:5]: s for s in self.elf.symbols
                          if s[1] & 15 == 2 and s[3] and s[5]}
        self.relocations = {}
        for row, raw in self.elf.sections.values():
            if row[1] == 9:
                for offset in range(0, len(raw), 16):
                    address, info = struct.unpack_from("<QQ", raw, offset)
                    self.relocations[row[7], address] = (info & 0xffffffff, self.elf.symbols[info >> 32])
        self.memory, self.next_address = {}, 0x100000
        self.context = self.allocate("context", bytes(168))
        self.stack = self.allocate("stack", bytes(512))
        self.maps, self.map_ids = {}, {}
        arrays = {"USAGE": (capacity, 8), "USAGE_CONFIG": (1, 8),
                  "ENDPOINT_OBJECT": (capacity, 8), "USAGE_EVIDENCE": (3, 8),
                  "CALLER_EVIDENCE": (4, 8), "EVIDENCE": (9, 8)}
        for name, (maximum, size) in arrays.items():
            self.maps[name] = {struct.pack("<I", key): self.allocate(name, bytes(size))
                               for key in range(maximum)}
        self.maps["CALLER_USE"] = {}
        for index, name in enumerate(self.maps):
            self.map_ids[0x800000 + index * 0x1000] = name
        self.capacity, self.pair_capacity = capacity, pair_capacity
        self.set_array("USAGE_CONFIG", 0, struct.pack("<II", 1, capacity))
        for endpoint, obj in [(7, 2), (8, 2), (9, 3)]:
            self.set_array("ENDPOINT_OBJECT", endpoint, struct.pack("<II", obj, 1))
        self.next_time = 101
        self.identity_calls = self.clock_calls = self.insert_calls = 0
        self.trace = []

    def allocate(self, name, value):
        pointer = self.next_address
        self.next_address += (len(value) + 31) & ~15
        self.memory[pointer] = (name, bytearray(value), set(range(len(value))))
        return pointer

    def segment(self, pointer, size):
        for base, (name, value, initialized) in self.memory.items():
            if base <= pointer and pointer + size <= base + len(value):
                return name, value, initialized, pointer - base
        raise RuntimeError(f"unowned entry memory {pointer:#x}+{size}")

    def read(self, pointer, size):
        name, value, initialized, offset = self.segment(pointer, size)
        require(set(range(offset, offset + size)) <= initialized, "uninitialized entry memory read")
        if name == "context":
            require(self.authorized and offset == 136 and size == 8, "pre-scope or unexpected payload read")
        return bytes(value[offset:offset + size])

    def write(self, pointer, value, *, setup=False):
        name, target, initialized, offset = self.segment(pointer, len(value))
        if not setup:
            require(name in {"stack", "USAGE", "USAGE_EVIDENCE", "CALLER_EVIDENCE", "EVIDENCE"},
                    f"entry writes immutable {name}")
            require(name == "stack" or self.authorized, "entry mutation precedes authorization")
        target[offset:offset + len(value)] = value
        initialized.update(range(offset, offset + len(value)))

    def set_array(self, name, index, value):
        self.write(self.maps[name][struct.pack("<I", index)], value, setup=True)

    def array(self, name, index):
        pointer = self.maps[name][struct.pack("<I", index)]
        return self.read(pointer, len(self.segment(pointer, 1)[1]))

    def rows(self):
        return {key: self.read(pointer, 32) for key, pointer in self.maps["CALLER_USE"].items()}

    def integer(self, index):
        require(self.regs[index] is not None, f"entry uses clobbered r{index}")
        return self.regs[index]

    def execute_memset(self, target):
        """Execute this object's eight-instruction intrinsic, with no native stub.

        The reviewed call clears exactly one 16-byte stack image before the
        identity boundary. Other sizes, destinations, intrinsic shapes, nested
        calls and more than 128 callee instructions are unsupported. Every
        callee instruction also consumes the root's 10,000-step budget.
        """
        require(target[1:4] == (0x12, 2, self.elf.indices[".text"]),
                "memset requires the actual GLOBAL HIDDEN .text body")
        raw = self.elf.sections[".text"][1][target[4]:target[4] + target[5]]
        require(len(raw) == 64, "unsupported memset body size")
        code = [struct.unpack_from("<BBhi", raw, pc) for pc in range(0, len(raw), 8)]
        require(code == [(0x15, 3, 6, 0), (0xb7, 4, 0, 0), (0xbf, 0x15, 0, 0),
                         (0x0f, 0x45, 0, 0), (0x73, 0x25, 0, 0), (0x07, 4, 0, 1),
                         (0x2d, 0x43, -5, 0), (0x95, 0, 0, 0)],
                "unsupported in-object memset instruction shape")
        r = self.integer
        require(self.authorized and self.segment(r(1), 16)[0] == "stack"
                and r(2) == 0 and r(3) == 16, "unsupported memset arguments")
        self.trace.append(("memset", self.pc))
        pc = 0
        for _ in range(128):
            self.steps += 1
            require(self.steps <= 10000, "entry step budget exceeded")
            require(0 <= pc < len(code), "memset escaped its body")
            op, registers, offset, immediate = code[pc]
            dst, src = registers & 15, registers >> 4
            next_pc = pc + 1
            if op == 0x15:
                if r(dst) == immediate:
                    next_pc += offset
            elif op == 0x2d:
                if r(dst) > r(src):
                    next_pc += offset
            elif op in (0xb7, 0xbf):
                self.regs[dst] = r(src) if op == 0xbf else immediate
            elif op in (0x07, 0x0f):
                self.regs[dst] = (r(dst) + (r(src) if op == 0x0f else immediate)) & MASK
            elif op == 0x73:
                self.write(r(dst) + offset, bytes([r(src) & 0xff]))
            elif op == 0x95:
                return r(0)  # The actual void intrinsic leaves r0 untouched.
            pc = next_pc
        raise RuntimeError("memset instruction budget exceeded")

    def external_call(self, helper, target):
        r = self.integer
        result = 0
        if not target and helper == 12:
            # Only the kernel-stack opt-out: TAIL_CALLS with an index past every
            # slot, which the kernel refuses without jumping. Any real slot
            # would leave this entry, so it is refused here.
            require(self.regs[2] == TAIL_CALLS_ID and r(3) & 0xFFFFFFFF == 0xFFFFFFFF,
                    "entry tail call must be the out-of-range kernel-stack opt-out")
            self.regs[:6] = [(-2) & MASK] + [None] * 5
            return
        if target and target[0].endswith("10scope_auth"):
            require(not self.trace, "scope must be the first external entry operation")
            self.authorized = self.scope
            self.write(r(1), struct.pack("<QQIIQ", int(self.scope), 0, self.tgid, 0, 0))
            self.trace.append(("scope", self.pc, self.scope))
        elif target and target[0] == "p11_link_current_identity":
            require(self.authorized, "native identity before authorization")
            self.identity_calls += 1
            self.trace.append(("identity", self.pc))
            self.write(r(1), struct.pack("<QQ", *(self.image or (0, 0))))
            result = 1 if self.image is not None else 2
        elif target and target[0] == "memset":
            result = self.execute_memset(target)
        elif target:
            raise RuntimeError(f"entry runner refuses unknown native call {target[0]}")
        else:
            require(self.authorized, "helper before authorization")
            if helper in (1, 2):
                name = self.map_ids.get(r(1))
                require(name is not None, "unknown entry map")
                key = self.read(r(2), 24 if name == "CALLER_USE" else 4)
                if helper == 1:
                    self.trace.append(("lookup", self.pc, name, key))
                    result = self.maps[name].get(key, 0)
                else:
                    require(name == "CALLER_USE" and r(4) == 1, "caller insertion must use exact BPF_NOEXIST")
                    value = self.read(r(3), 32)
                    self.trace.append(("insert", self.pc, key, value, self.writers[4]))
                    self.insert_calls += 1
                    if key in self.maps[name]:
                        result = -17
                    elif len(self.maps[name]) >= self.pair_capacity:
                        result = -7
                    else:
                        self.maps[name][key] = self.allocate(name, value)
            elif helper == 5:
                self.trace.append(("clock", self.pc))
                self.clock_calls += 1
                result, self.next_time = self.next_time, self.next_time + 1
            elif helper == 174:
                require(r(1) == self.context, "attach cookie must use the original context")
                self.trace.append(("cookie", self.pc))
                result = self.cookie
            else:
                raise RuntimeError(f"entry runner refuses helper {helper}")
        self.regs[:6] = [result & MASK] + [None] * 5

    def run(self, root, *, scope=True, cs=None, image=(41, 9), tgid=100, cookie=None):
        self.scope, self.image, self.tgid = scope, image, tgid
        self.cookie = (TAG << 32) | 7 if cookie is None else cookie
        self.authorized, self.trace = False, []
        cs = (0x33 if root.endswith("lp64") else 0x23) if cs is None else cs
        self.write(self.context + 136, struct.pack("<Q", cs), setup=True)
        self.memory[self.stack][2].clear()
        self.regs, self.writers = [None] * 11, [None] * 11
        self.regs[1], self.regs[10] = self.context, self.stack + 512
        symbol = self.roots[root]
        section = self.elf.sections["uprobe"][1]
        self.code = [struct.unpack_from("<BBhi", section, pc)
                     for pc in range(symbol[4], symbol[4] + symbol[5], 8)]
        self.pc = 0
        self.steps = 0
        for _ in range(10000):
            self.steps += 1
            require(self.steps <= 10000, "entry step budget exceeded")
            require(0 <= self.pc < len(self.code), "entry control escaped its root")
            op, registers, offset, immediate = self.code[self.pc]
            dst, src, cls, operation = registers & 15, registers >> 4, op & 7, op & 0xf0
            next_pc = self.pc + 1
            r = self.integer
            relocation = self.relocations.get((symbol[3], symbol[4] + self.pc * 8))
            if op == 0x18:
                require(next_pc < len(self.code) and self.code[next_pc][0] == 0, "malformed entry wide load")
                if relocation and relocation[1][0] == "TAIL_CALLS":
                    require(relocation[0] == 1, "unknown entry map relocation")
                    self.regs[dst] = TAIL_CALLS_ID
                elif relocation:
                    require(relocation[0] == 1 and relocation[1][0] in self.maps, "unknown entry map relocation")
                    self.regs[dst] = next(key for key, name in self.map_ids.items() if name == relocation[1][0])
                else:
                    self.regs[dst] = (immediate & 0xffffffff) | ((self.code[next_pc][3] & 0xffffffff) << 32)
                self.writers[dst] = self.pc
                next_pc += 1
            elif cls in (1, 2, 3) and op & 0xe0 == 0x60:
                size = {0: 4, 8: 2, 16: 1, 24: 8}[op & 0x18]
                if cls == 1:
                    pointer = r(src) + offset
                    self.regs[dst] = int.from_bytes(self.read(pointer, size), "little")
                    self.writers[dst] = self.pc
                    if self.segment(pointer, size)[0] == "USAGE":
                        self.trace.append(("usage-load", self.pc, self.regs[dst]))
                else:
                    value = r(src) if cls == 3 else immediate
                    self.write(r(dst) + offset, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
            elif op == 0xdb and immediate == 0x00:
                # Non-fetch 64-bit atomic ADD: only a per-CPU loss counter may
                # take it. The global USAGE cell changes solely through its
                # exact zero-to-one CAS; every fetch form stays refused.
                pointer = r(dst) + offset
                name = self.segment(pointer, 8)[0]
                require(name in {"EVIDENCE", "USAGE_EVIDENCE", "CALLER_EVIDENCE"},
                        "caller entry atomic add outside a per-CPU counter cell")
                old = int.from_bytes(self.read(pointer, 8), "little")
                self.write(pointer, struct.pack("<Q", (old + r(src)) & MASK))
                self.trace.append(("counter-add", self.pc, name))
            elif op == 0xdb and immediate == 0xf1:
                pointer, expected, replacement = r(dst) + offset, r(0), r(src)
                old = int.from_bytes(self.read(pointer, 8), "little")
                require(self.segment(pointer, 8)[0] == "USAGE" and expected == 0 and replacement == 1,
                        "caller entry CAS must preserve exact global zero-to-one transition")
                if old == expected:
                    self.write(pointer, struct.pack("<Q", replacement))
                self.regs[0] = old
            elif cls in (4, 7):
                width = 32 if cls == 4 else 64
                mask = (1 << width) - 1
                rhs = (r(src) if op & 8 else immediate) & mask
                lhs = r(dst) & mask if operation != 0xb0 else 0
                if operation == 0x00:
                    value = lhs + rhs
                elif operation == 0x10:
                    value = lhs - rhs
                elif operation == 0x40:
                    value = lhs | rhs
                elif operation == 0x50:
                    value = lhs & rhs
                elif operation == 0x60:
                    value = lhs << (rhs & (width - 1))
                elif operation == 0x70:
                    value = lhs >> (rhs & (width - 1))
                elif operation == 0xa0:
                    value = lhs ^ rhs
                elif operation == 0xb0:
                    value = rhs
                elif operation == 0xc0:
                    signed = lhs - (1 << width) if lhs >> (width - 1) else lhs
                    value = signed >> (rhs & (width - 1))
                else:
                    raise RuntimeError(f"entry runner refuses ALU opcode {op:#x}")
                self.regs[dst], self.writers[dst] = value & mask, self.pc
            elif op == 0x85:
                target = None
                if registers == 0x10:
                    if relocation:
                        require(relocation[0] == 10, "invalid entry call relocation")
                        destination = (relocation[1][3], relocation[1][4] + (immediate + 1) * 8)
                    else:
                        destination = (symbol[3], symbol[4] + (self.pc + immediate + 1) * 8)
                    target = self.functions.get(destination)
                    require(target is not None, "unresolved entry call")
                else:
                    require(registers == 0, "unsupported entry call class")
                self.external_call(immediate, target)
            elif op == 0x95:
                require(r(0) == 0, "ordinary entry must return zero")
                self.trace.append(("exit", self.pc))
                return
            elif cls in (5, 6):
                if operation == 0:
                    next_pc += offset
                else:
                    width = 32 if cls == 6 else 64
                    mask = (1 << width) - 1
                    lhs, rhs = r(dst) & mask, (r(src) if op & 8 else immediate) & mask
                    signed_lhs = lhs - (1 << width) if lhs >> (width - 1) else lhs
                    signed_rhs = rhs - (1 << width) if rhs >> (width - 1) else rhs
                    conditions = {0x10: lhs == rhs, 0x20: lhs > rhs, 0x30: lhs >= rhs,
                                  0x40: bool(lhs & rhs), 0x50: lhs != rhs,
                                  0x60: signed_lhs > signed_rhs, 0x70: signed_lhs >= signed_rhs,
                                  0xa0: lhs < rhs, 0xb0: lhs <= rhs,
                                  0xc0: signed_lhs < signed_rhs, 0xd0: signed_lhs <= signed_rhs}
                    require(operation in conditions, "unsupported entry branch")
                    taken = conditions[operation]
                    self.trace.append(("branch", self.pc, op, lhs, rhs, taken))
                    if taken:
                        next_pc += offset
            else:
                raise RuntimeError(f"entry runner refuses opcode {op:#x}")
            self.pc = next_pc
        raise RuntimeError("entry step budget exceeded")


def check_entry_cases(body):
    """Closed cells: actual root routing; helper implementations are out of scope."""
    for root in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
        machine = EntryMachine(body)
        for image, tgid, endpoint in [((41, 9), 100, 7), ((41, 9), 100, 7),
                                      ((42, 9), 200, 7), ((41, 10), 100, 7),
                                      ((41, 9), 100, 8), ((41, 9), 100, 9)]:
            machine.run(root, image=image, tgid=tgid, cookie=(TAG << 32) | endpoint)
        expected = {}
        for image, obj, timestamp, tgid, endpoint in [((41, 9), 2, 101, 100, 7),
                                                     ((42, 9), 2, 102, 200, 7),
                                                     ((41, 10), 2, 103, 100, 7),
                                                     ((41, 9), 3, 104, 100, 9)]:
            expected[struct.pack("<QQII", *image, obj, 0)] = struct.pack("<QQIIII", timestamp, 0, tgid, endpoint, 1, 0)
        require(machine.rows() == expected, f"{root}: missing/changed exact caller-object witnesses")
        require((machine.identity_calls, machine.clock_calls, machine.insert_calls) == (6, 4, 4),
                f"{root}: repeated caller did not preserve bounded helper work")
        for endpoint in (7, 8, 9):
            require(machine.array("USAGE", endpoint) == struct.pack("<Q", 1), "global use lost")

        cases = [("scope", {"scope": False}, None, None),
                 ("abi", {"cs": 0x23 if root.endswith("lp64") else 0x33}, "EVIDENCE", 8),
                 ("unknown-abi", {"cs": 0}, "EVIDENCE", 8),
                 ("cookie-tag", {"cookie": 7}, "USAGE_EVIDENCE", 1),
                 ("cookie-bound", {"cookie": (TAG << 32) | 10}, "USAGE_EVIDENCE", 1),
                 ("config", {}, "USAGE_EVIDENCE", 0),
                 ("empty-object", {}, "CALLER_EVIDENCE", 0),
                 ("unknown-object-class", {}, "CALLER_EVIDENCE", 0)]
        for label, arguments, evidence, index in cases:
            machine = EntryMachine(body)
            if label == "config":
                machine.set_array("USAGE_CONFIG", 0, struct.pack("<II", 2, 10))
            if label in {"empty-object", "unknown-object-class"}:
                machine.set_array("ENDPOINT_OBJECT", 7, struct.pack("<II", 2, 0 if label == "empty-object" else 3))
            machine.run(root, **arguments)
            require(not machine.rows() and machine.identity_calls == 0 and machine.insert_calls == 0,
                    f"{root}/{label}: refusal reached caller processing")
            require(machine.array("USAGE", 7) == bytes(8), f"{root}/{label}: refusal changed global use")
            for name, count in [("EVIDENCE", 9), ("USAGE_EVIDENCE", 3), ("CALLER_EVIDENCE", 4)]:
                for cell in range(count):
                    require(machine.array(name, cell) == struct.pack("<Q", int(name == evidence and cell == index)),
                            f"{root}/{label}: failure evidence differs")
        machine = EntryMachine(body, pair_capacity=2)
        for image, tgid in [((41, 9), 100), ((42, 9), 200), ((41, 10), 100), ((41, 9), 100)]:
            machine.run(root, image=image, tgid=tgid)
        require(len(machine.rows()) == 2 and machine.insert_calls == 3,
                f"{root}: pair exhaustion erased history or retried existing pair")
        require(machine.array("CALLER_EVIDENCE", 2) == struct.pack("<Q", 1), "pair exhaustion hidden")


@unittest.skipUnless(os.environ.get("P11SCOPE_INVENTORY_CALLERS_OBJECT"), "actual caller object supplied by Rust integration gate")
class ActualCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(os.environ["P11SCOPE_INVENTORY_CALLERS_OBJECT"])
        cls.body = cls.path.read_bytes()
        cls.variant = os.environ.get("P11SCOPE_INVENTORY_CALLERS_VARIANT", "inventory-callers")

    def test_actual_manifest_native_graph_and_entry_cases(self):
        checker.validate_inventory(self.variant, *checker.inspect(self.path, variant=self.variant))
        check_entry_cases(self.body)

    def test_actual_root_mutants_cannot_hide_new_callers_or_change_noexist(self):
        check_entry_cases(self.body)
        for root in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
            machine = EntryMachine(self.body)
            machine.run(root)
            first = list(machine.trace)
            machine.run(root)
            repeated = list(machine.trace)
            identity = next(event[1] for event in first if event[0] == "identity")
            flags = next(event[4] for event in first if event[0] == "insert")
            self.assertEqual(machine.code[flags], (0xb7, 4, 0, 1), "review changed NOEXIST lowering")
            positive_load = next(event[1] for event in repeated if event[0] == "usage-load")
            positive = next(event for event in repeated if event[0] == "branch" and event[1] > positive_load)
            self.assertTrue(positive[5] and positive[3:5] == (1, 1), "review changed positive-USAGE branch")
            exit_pc = next(event[1] for event in repeated if event[0] == "exit")
            self.assertEqual(machine.code[exit_pc - 1], (0xb7, 0, 0, 0), "review changed zero-return lowering")
            old = machine.code[positive[1]]
            cases = [("skip-identity", identity, (0xb7, 0, 0, 1)),
                     ("used-bit-returns", positive[1], (old[0], old[1], exit_pc - positive[1] - 2, old[3])),
                     ("insert-any", flags, (0xb7, 4, 0, 0)),
                     ("insert-exist-only", flags, (0xb7, 4, 0, 2))]
            root_symbol = machine.roots[root]
            base = machine.elf.sections["uprobe"][0][4] + root_symbol[4]
            for label, pc, instruction in cases:
                changed = bytearray(self.body)
                struct.pack_into("<BBhi", changed, base + pc * 8, *instruction)
                reason = "missing/changed exact caller-object" if label == "used-bit-returns" else ".*"
                with self.subTest(root=root, mutation=label), self.assertRaisesRegex(RuntimeError, reason):
                    check_entry_cases(bytes(changed))

    def test_actual_scope_branch_mutants_are_rejected(self):
        for root in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
            machine = EntryMachine(self.body)
            machine.run(root, scope=False)
            branch = next(event for event in machine.trace if event[0] == "branch")
            pc = branch[1]
            old = machine.code[pc]
            self.assertEqual((old[0], old[3]), (0x55, 1), "review changed Option-scope lowering")
            base = machine.elf.sections["uprobe"][0][4] + machine.roots[root][4]
            for label, instruction in [("bypass", (0x05, 0, 0, 0)),
                                       ("invert", (0x15, old[1], old[2], 1)),
                                       ("refusal-continues", (old[0], old[1], 0, 1))]:
                changed = bytearray(self.body)
                struct.pack_into("<BBhi", changed, base + pc * 8, *instruction)
                with self.subTest(root=root, mutation=label), self.assertRaises(RuntimeError):
                    check_entry_cases(bytes(changed))

    def test_actual_abi_guard_mutants_are_rejected(self):
        for root in ("p11_usage_entry_lp64", "p11_usage_entry_ia32"):
            machine = EntryMachine(self.body)
            machine.run(root, cs=0)
            branch = [event for event in machine.trace if event[0] == "branch"][1]
            pc = branch[1]
            selector = 0x33 if root.endswith("lp64") else 0x23
            self.assertEqual(machine.code[pc], (0x15, 1, 1, selector), "review changed ABI selector guard")
            base = machine.elf.sections["uprobe"][0][4] + machine.roots[root][4]
            for label, instruction in [("invert", (0x55, 1, 1, selector)),
                                       ("always-accept", (0x05, 0, 1, 0))]:
                changed = bytearray(self.body)
                struct.pack_into("<BBhi", changed, base + pc * 8, *instruction)
                with self.subTest(root=root, mutation=label), self.assertRaises(RuntimeError):
                    check_entry_cases(bytes(changed))

    def test_actual_intrinsic_body_cannot_be_replaced_by_an_unchecked_stub(self):
        elf = checker.Elf(self.body)
        intrinsic = next(symbol for symbol in elf.symbols if symbol[0] == "memset")
        base = elf.sections[".text"][0][4] + intrinsic[4]
        # The exact reviewed intrinsic is executed. A changed byte store, loop
        # branch or premature return must be rejected, even if the modeled
        # native identity boundary would overwrite those output bytes later.
        for label, pc, instruction in [("wrong-store-width", 4, (0x7b, 0x25, 0, 0)),
                                       ("unbounded-loop", 6, (0x05, 0, -5, 0)),
                                       ("empty-stub", 0, (0x95, 0, 0, 0))]:
            changed = bytearray(self.body)
            struct.pack_into("<BBhi", changed, base + pc * 8, *instruction)
            with self.subTest(mutation=label), self.assertRaisesRegex(RuntimeError, "memset instruction shape"):
                check_entry_cases(bytes(changed))

    def test_actual_new_map_dimensions_flags_and_kind_are_exact(self):
        elf = checker.Elf(self.body)
        with tempfile.TemporaryDirectory(prefix="caller-object-") as directory:
            changed_path = Path(directory) / "changed.o"
            for symbol in elf.symbols:
                if symbol[0] not in {"ENDPOINT_OBJECT", "CALLER_USE", "CALLER_EVIDENCE"}:
                    continue
                for field in range(7):
                    changed = bytearray(self.body)
                    offset = elf.sections["maps"][0][4] + symbol[4] + field * 4
                    struct.pack_into("<I", changed, offset, struct.unpack_from("<I", changed, offset)[0] ^ 1)
                    changed_path.write_bytes(changed)
                    with self.subTest(map=symbol[0], field=field), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
                        checker.validate_inventory(self.variant, *checker.inspect(changed_path, variant=self.variant))


if __name__ == "__main__":
    unittest.main()
