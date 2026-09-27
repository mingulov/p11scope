#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-bound static gate for the four production discovery BPF objects."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys


SCHEMA = "p11scope-live-discovery-object/v1"
VARIANTS = ("default", "unsafe", "small-ring", "small-discovery-ring")
INITIALIZER_BEGIN = "// DISCOVERY_INITIALIZER_BEGIN"
INITIALIZER_END = "// DISCOVERY_INITIALIZER_END"
PAUSE_BEGIN = "// PAUSE_WRITER_BEGIN"
PAUSE_END = "// PAUSE_WRITER_END"
STORE = re.compile(r"core::ptr::write_volatile\(words\.add\((\d+)\), 0u64\);")
OBJECT_STORE = re.compile(
    r"\*\(u64 \*\)\(r(?P<base>\d+) \+ 0x(?P<offset>[0-9a-f]+)\) = r(?P<zero>\d+)"
)
ANY_OBJECT_STORE = re.compile(
    r"\*\(u(?:8|16|32|64) \*\)\(r(?P<base>\d+) \+ 0x(?P<offset>[0-9a-f]+)\) ="
)
COUNTERS = {
    "0": "ring_loss",
    "1": "export_state_failures",
    "2": "export_bounded_read_failures",
    "3": "loader_hits",
    "4": "loader_state_read_failures",
}


def fail(message):
    raise RuntimeError(message)


def bounded_region(source, begin, end):
    if source.count(begin) != 1 or source.count(end) != 1:
        fail(f"expected exactly one {begin!r}/{end!r} region")
    before, tail = source.split(begin, 1)
    region, after = tail.split(end, 1)
    if source.index(begin) >= source.index(end):
        fail(f"{begin!r} must precede {end!r}")
    return before, region, after


def initializer_contract(source):
    _, region, _ = bounded_region(source, INITIALIZER_BEGIN, INITIALIZER_END)
    indices = []
    for line in region.splitlines():
        line = line.strip()
        if not line:
            continue
        match = STORE.fullmatch(line)
        if not match:
            fail(f"initializer contains non-approved text: {line!r}")
        indices.append(int(match.group(1)))
    if len(indices) != 115:
        fail(f"initializer has {len(indices)} stores, expected 115")
    if indices != list(range(115)):
        fail("initializer indices must be the ordered exact set 0..114")
    return region


def pause_contract(source):
    _, pause, _ = bounded_region(source, PAUSE_BEGIN, PAUSE_END)
    if pause.count("core::intrinsics::atomic_cxchg") != 1:
        fail("pause writer must contain exactly one atomic_cxchg source site")
    if pause.count("helpers::bpf_send_signal(19)") != 1:
        fail("pause writer must contain exactly one SIGSTOP helper source site")
    cas = pause.index("core::intrinsics::atomic_cxchg")
    signal = pause.index("helpers::bpf_send_signal(19)")
    winner_prefix = pause[cas:signal]
    timestamp = pause.find("helpers::bpf_ktime_get_ns()", cas, signal)
    if timestamp < cas:
        fail("pause winner timestamp must follow CAS and precede SIGSTOP")
    if winner_prefix.count("helpers::") != 1:
        fail("another helper separates the successful CAS and winner timestamp")
    between = pause[timestamp + len("helpers::bpf_ktime_get_ns()") : signal]
    if "helpers::" in between:
        fail("another helper separates the winner timestamp and SIGSTOP")
    if any(token in pause for token in ("while ", "loop {", "sleep", "yield_now")):
        fail("pause writer contains a busy wait, delay, sleep, or yield")
    if pause.count("entry.submit(0)") != 1:
        fail("pause writer must own exactly one terminal ring submit")
    final_result = pause.find("addr_of_mut!((*raw).send_signal_rc)", signal)
    submit = pause.index("entry.submit(0)")
    if final_result < signal or submit < final_result:
        fail("pause writer submits before its final helper-result store")
    winner_end = pause.find("} else", signal)
    if winner_end < 0:
        winner_end = submit
    if "helpers::" in pause[
        signal + len("helpers::bpf_send_signal(19)") : winner_end
    ]:
        fail("pause winner calls another helper after SIGSTOP")
    return pause


def production_source_contract(source):
    required = [
        "DISCOVERY.reserve::<DiscoveryRecord>(0)",
        "while pointer_index < 104",
        "aya_ebpf::bindings::BPF_NOEXIST",
        "fn loader_cookie_of(",
        "fn export_state_key",
        "cookie_slot(cookie_of(ctx))",
        "if token != 0",
        "DISCOVERY_COUNTER_RING_LOSS",
        "DISCOVERY_COUNTER_EXPORT_STATE_FAILURES",
        "DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES",
        "DISCOVERY_COUNTER_LOADER_HITS",
        "DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES",
        "let mut bytes = [0u8; 9];",
        'read == 8 && bytes[..8] == *b"PKCS 11\\0"',
        "if state.arg0 == 0",
        "pub fn interface_list_return(ctx: RetProbeContext) -> u32",
        "pub fn interface_list_worker(ctx: RetProbeContext) -> u32",
    ]
    for marker in required:
        if marker not in source:
            fail(f"production source contract missing {marker!r}")
    if source.count("DISCOVERY.reserve::<DiscoveryRecord>(0)") != 1:
        fail("all discovery producers must share the sole reservation path")
    if source.count("domain: STATE_DOMAIN_EXPORT") != 3:
        fail("export state-key constructors must use the export namespace")
    if source.count("domain: STATE_DOMAIN_SELECTION") != 1:
        fail("selection state-key constructor must use the selection namespace")
    if "target-cpu=v3" in source:
        fail("production source requests forbidden target-cpu=v3")
    loader = source.split("fn loader_cookie_of(", 1)[1].split("fn loader_runtime_ip", 1)[0]
    if "cookie_slot" in loader or "cookie_descriptor" in loader:
        fail("loader and static-slot cookie namespaces collide")
    return_region = source.split(
        "pub fn interface_list_return(ctx: RetProbeContext) -> u32 {", 1
    )[1].split("#[uretprobe]\npub fn interface_list_worker", 1)[0]
    worker_region = source.split(
        "pub fn interface_list_worker(ctx: RetProbeContext) -> u32 {", 1
    )[1].split("#[uprobe]\npub fn interface_entry", 1)[0]
    if return_region.count("classify_direct_interface(") != 0:
        fail("interface-list return must not call the direct classifier")
    if worker_region.count("classify_direct_interface(") != 1:
        fail("interface-list worker must call the direct classifier exactly once")
    for marker in [
        "interface_continuation_pack(count, 0, symbol_id)",
        "active_count == 0",
        "state.arg0 == 0",
        "take_export_state(&ctx, scope.is_some())",
        "StateKey {",
        "attach_cookie: 0",
        "aya_ebpf::bindings::BPF_NOEXIST as u64",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
    ]:
        if marker not in return_region:
            fail(f"interface-list return contract missing {marker!r}")
    interface_list_span_contract(return_region)
    if "export_state_key(&ctx)" in worker_region:
        fail("interface-list worker must not use the attach-cookie helper")
    for marker in [
        "StateKey {",
        "pid_tgid: helpers::bpf_get_current_pid_tgid()",
        "attach_cookie: 0",
        "interface_continuation_unpack(state.arg1)",
        "DISCOVERY_INTERFACES",
        "(u64::from(symbol_id) << 32)",
        "interface_continuation_next(state.arg1)",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
        "finish_export_state(&key)",
    ]:
        if marker not in worker_region:
            fail(f"interface-list worker contract missing {marker!r}")


def interface_list_span_contract(return_region):
    markers = [
        "checked_add((active_count - 1) * layout.interface().stride as u64)",
        "address.checked_add(layout.interface().stride as u64 - layout.word_bytes() as u64)",
        "target_word_end(address, layout)",
    ]
    for marker in markers:
        if marker not in return_region:
            fail(f"interface-list return contract missing {marker!r}")
    continuation = return_region.find("interface_continuation_pack(count, 0, symbol_id)")
    if not all(return_region.find(marker) < continuation for marker in markers):
        fail("interface-list span validation must precede continuation state")


def source_contract(source):
    region = initializer_contract(source)
    pause_contract(source)
    if "fn reserve_discovery" in source:
        production_source_contract(source)
    return region


def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def expected_manifest_values(variant):
    if variant not in VARIANTS:
        fail(f"unknown variant {variant!r}")
    maps, programs = expected_inventory(variant)
    return {
        "record_size": 920,
        "record_align": 8,
        "counter_indices": COUNTERS,
        "initializer_words": 115,
        "initializer_indices": list(range(115)),
        "inventory": {"maps": maps, "programs": sorted(programs)},
    }


def test_manifest(source_path, variant, source):
    region = source_contract(source)
    return {
        "schema": SCHEMA,
        "variant": variant,
        "source": {
            "canonical_path": str(source_path),
            "sha256": sha256(source),
            "initializer_region_sha256": sha256(region),
        },
        "expected": expected_manifest_values(variant),
    }


def manifest_contract(manifest, source_path, source, variant):
    expected = test_manifest(source_path, variant, source)
    if manifest != expected:
        fail("manifest differs from the checked-in source/contract values")


def map_checker():
    path = Path(__file__).resolve().with_name("check-bpf-map-defs.py")
    return runpy.run_path(str(path), run_name="task5_map_checker")


def expected_inventory(variant):
    checker = map_checker()
    maps = copy.deepcopy(
        checker["UNSAFE_MAPS"] if variant == "unsafe" else checker["SAFE_MAPS"]
    )
    programs = set(
        checker["UNSAFE_PROGRAMS"] if variant == "unsafe" else checker["SAFE_PROGRAMS"]
    )
    if variant == "small-ring":
        maps["EVENTS"]["max_entries"] = 4096
    if variant == "small-discovery-ring":
        maps["DISCOVERY"]["max_entries"] = 4096
    return maps, programs


def function_blocks(disassembly):
    matches = list(re.finditer(r"(?m)^\s*[0-9a-f]+ <([^>]+)>:\s*$", disassembly))
    blocks = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(disassembly)
        blocks[match.group(1)] = disassembly[match.end() : end].splitlines()
    return blocks


def line_pc(line):
    match = re.match(r"\s*(\d+):", line)
    return int(match.group(1)) if match else None


def relative_target(pc, text):
    branch = re.search(r"\bgoto (?P<sign>[+-])0x(?P<distance>[0-9a-f]+)\b", text)
    if not branch:
        return None
    distance = int(branch.group("distance"), 16)
    return pc + 1 + (distance if branch.group("sign") == "+" else -distance)


def initializer_regions(disassembly):
    regions = []
    for function, lines in function_blocks(disassembly).items():
        discovery_relocations = [
            index
            for index, line in enumerate(lines)
            if re.search(r"R_BPF_64_64\s+DISCOVERY\s*$", line)
        ]
        for relocation in discovery_relocations:
            reserve = next(
                (
                    index
                    for index in range(relocation, min(len(lines), relocation + 10))
                    if "call 0x83" in lines[index]
                ),
                None,
            )
            if reserve is None:
                fail(f"{function}: DISCOVERY relocation lacks ring reservation")
            size_window = "\n".join(lines[max(relocation - 2, 0) : reserve + 1])
            if "r2 = 0x398" not in size_window:
                fail(f"{function}: discovery reservation is not 920 bytes")

            candidate = None
            for start in range(reserve + 1, len(lines) - 114):
                first = OBJECT_STORE.search(lines[start])
                if not first or int(first.group("offset"), 16) != 0:
                    continue
                base, zero = first.group("base"), first.group("zero")
                stores = []
                for offset, line in enumerate(lines[start : start + 115]):
                    store = OBJECT_STORE.search(line)
                    if (
                        not store
                        or store.group("base") != base
                        or store.group("zero") != zero
                        or int(store.group("offset"), 16) != offset * 8
                    ):
                        break
                    stores.append(offset * 8)
                if len(stores) == 115:
                    candidate = (start, start + 115, base, zero, stores)
                    break
            if candidate is None:
                fail(f"{function}: missing exact 115-store initializer")
            start, end, base, zero, stores = candidate
            prefix = "\n".join(lines[:start])
            if not re.search(rf"r{zero} = 0x0\b", prefix):
                fail(f"{function}: initializer source register is not proven zero")
            success_branches = []
            for line in lines[reserve + 1 : start]:
                pc = line_pc(line)
                if pc is None or not re.search(rf"\bif r{base} != 0x0 goto ", line):
                    continue
                success_branches.append(relative_target(pc, line))
            if len(success_branches) != 1 or success_branches[0] is None:
                fail(
                    f"{function}: reservation must have one finite success branch"
                )
            target = success_branches[0]
            target_index = next(
                (index for index, line in enumerate(lines) if line_pc(line) == target),
                None,
            )
            if target_index is None or not (reserve < target_index <= start):
                fail(f"{function}: successful reservation does not enter the initializer")
            for line in lines[target_index:start]:
                if line_pc(line) is not None and not re.search(
                    r"\*\(u(?:8|16|32|64) \*\)\(r10 - 0x[0-9a-f]+\) =", line
                ):
                    fail(f"{function}: non-stack operation precedes initialization: {line!r}")
            before_init = "\n".join(lines[reserve + 1 : start])
            if re.search(rf"= \*\([^)]*\)\(r{base} \+", before_init):
                fail(f"{function}: record field read precedes initialization")
            if "call 0x84" in before_init:
                fail(f"{function}: record submit precedes initialization")
            trailing = "\n".join(lines[end:])
            if re.search(
                rf"\*\(u64 \*\)\(r{base} \+ 0x(?:39[89a-f]|3[a-f][0-9a-f]|[4-9a-f][0-9a-f]{{2,}})\) = r{zero}\b",
                trailing,
            ):
                fail(f"{function}: initializer writes beyond the 920-byte record")
            regions.append(
                {
                    "function": function,
                    "offsets": stores,
                }
            )
    return regions


def instructions(lines):
    parsed = []
    for line in lines:
        if "R_BPF_" in line:
            continue
        match = re.match(r"\s*(\d+):\s+(.*)", line)
        if match:
            text = re.sub(r"^(?:[0-9a-f]{2}\s+){8,16}", "", match.group(2))
            text = re.sub(r"\s+<[^>]+>$", "", text)
            parsed.append((int(match.group(1)), text))
    return parsed


def instruction_graph(lines):
    insns = instructions(lines)
    positions = {pc for pc, _ in insns}
    graph = {}
    for index, (pc, text) in enumerate(insns):
        following = insns[index + 1][0] if index + 1 < len(insns) else None
        target = relative_target(pc, text)
        edges = []
        if target is not None:
            if target not in positions:
                fail(f"branch from instruction {pc} targets missing instruction {target}")
            edges.append(target)
            if re.search(r"\bif .*\bgoto ", text) and following is not None:
                edges.append(following)
        elif not re.search(r"\bexit\s*$", text) and following is not None:
            edges.append(following)
        graph[pc] = edges
    return insns, graph


def reachable(graph, starts, blocked=frozenset()):
    seen = set()
    pending = list(starts)
    while pending:
        pc = pending.pop()
        if pc in seen or pc in blocked:
            continue
        seen.add(pc)
        pending.extend(graph.get(pc, ()))
    return seen


def nodes_on_paths(graph, start, target):
    forward = reachable(graph, [start])
    reverse = {pc: [] for pc in graph}
    for pc, edges in graph.items():
        for edge in edges:
            reverse.setdefault(edge, []).append(pc)
    return forward & reachable(reverse, [target])


def winner_finishes_without_helper(lines, signal_index):
    insns, graph = instruction_graph(lines)
    signal_pc = int(re.match(r"\s*(\d+):", lines[signal_index]).group(1))
    texts = dict(insns)
    pending = [(pc, {}) for pc in graph.get(signal_pc, ())]
    visited = set()
    submitted = False
    while pending:
        pc, stores = pending.pop()
        state = (
            pc,
            tuple((base, tuple(sorted(offsets))) for base, offsets in sorted(stores.items())),
        )
        if state in visited:
            continue
        visited.add(state)
        text = texts[pc]
        if re.search(r"\bcall 0x84\b", text):
            if not any({0, 8, 0x364, 0x378}.issubset(offsets) for offsets in stores.values()):
                return False
            submitted = True
            continue
        if re.search(r"\bcall 0x", text):
            return False
        store = ANY_OBJECT_STORE.search(text)
        if store:
            stores = {base: set(offsets) for base, offsets in stores.items()}
            stores.setdefault(store.group("base"), set()).add(
                int(store.group("offset"), 16)
            )
        edges = graph.get(pc, ())
        if not edges:
            return False
        pending.extend((edge, stores) for edge in edges)
    return submitted


def pause_emitter(name):
    return name == "dl_debug_state" or name.endswith(("emit_export", "emit_lifecycle"))


def map_cell_owners(lines):
    """Must-facts: register -> ("map"|"cell", map name) per instruction.

    Follows ld_imm64 map loads through lookups and copies; joins lose
    facts by intersection. Anything unrecognized clears the register, so
    callers fail closed on an unknown cell owner.
    """
    insns, graph = instruction_graph(lines)
    if not insns:
        return {}
    relocs = {index: (kind, target) for index, kind, target in relocation_targets(lines)}
    entries = instruction_entries(lines)
    loads = {}
    for index, pc, text in entries:
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
                state["r0"] = ("cell", lookup[1])
        elif pc in loads and re.fullmatch(r"r\d+ = 0x0 ll", text):
            register, target = loads[pc]
            state.pop("r" + register, None)
            state["r" + register] = ("map", target)
        elif match := re.fullmatch(r"r(\d+) = (r\d+|-?0x[0-9a-f]+)", text):
            register = "r" + match.group(1)
            state.pop(register, None)
            if match.group(2).startswith("r") and match.group(2) in state:
                state[register] = state[match.group(2)]
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


def cas_owners(lines):
    """Classify each cmpxchg_64 site by its cell owner map, if known."""
    facts = map_cell_owners(lines)
    owners = {}
    for _, pc, text in instruction_entries(lines):
        match = re.search(r"cmpxchg_64\(r(\d+) [+-] 0x[0-9a-f]+,", text)
        if match:
            fact = facts.get(pc, {}).get("r" + match.group(1))
            owners[pc] = fact[1] if fact is not None and fact[0] == "cell" else None
    return owners


def pause_cas_count(disassembly):
    total = 0
    for name, lines in function_blocks(disassembly).items():
        if not pause_emitter(name):
            continue
        owners = cas_owners(lines)
        total += sum(1 for _, pc, text in instruction_entries(lines)
                     if "cmpxchg_64" in text and owners.get(pc) == "PAUSE_PIDS")
    return total


def pause_object_contract(disassembly):
    signal_blocks = []
    total_cas = 0
    total_signals = 0
    for function, lines in function_blocks(disassembly).items():
        signals = [
            index for index, line in enumerate(lines) if re.search(r"call 0x6d\b", line)
        ]
        if pause_emitter(function):
            owners = cas_owners(lines)
            kinds = {}
            for index, line in enumerate(lines):
                if "cmpxchg_64" in line:
                    kinds[index] = owners.get(line_pc(line))
            if any(owner not in ("STOP_GATE", "PAUSE_PIDS") for owner in kinds.values()):
                return False
            cas = [index for index, owner in kinds.items() if owner == "PAUSE_PIDS"]
            total_cas += len(cas)
        elif signals:
            return False
        else:
            cas = []
        total_signals += len(signals)
        if signals:
            signal_blocks.append((function, lines, cas, signals))
    if total_cas != 3 or total_signals != 3 or len(signal_blocks) != 3:
        return False
    for _, lines, cas, signals in signal_blocks:
        if len(cas) != 1 or len(signals) != 1 or cas[0] >= signals[0]:
            return False
        insns, graph = instruction_graph(lines)
        pcs = [pc for pc, _ in insns]
        texts = dict(insns)
        cas_pc = line_pc(lines[cas[0]])
        signal_pc = line_pc(lines[signals[0]])
        cas_position = pcs.index(cas_pc)
        if cas_position + 1 >= len(pcs):
            return False
        start = pcs[cas_position + 1]
        winner_path = nodes_on_paths(graph, start, signal_pc)
        helper_calls = [
            pc
            for pc in winner_path
            if pc != signal_pc and re.search(r"\bcall (?:-?0x[0-9a-f]+)\b", texts[pc])
        ]
        if len(helper_calls) != 1 or not re.search(r"\bcall 0x5\b", texts[helper_calls[0]]):
            return False
        if signal_pc in reachable(graph, [start], {helper_calls[0]}):
            return False
        if not winner_finishes_without_helper(lines, signals[0]):
            return False
    return True


def table_bounds_object_contract(disassembly):
    blocks = function_blocks(disassembly)
    export = next(
        ("\n".join(lines) for name, lines in blocks.items() if name.endswith("emit_export")),
        "",
    )
    return bool(export) and all(
        re.search(rf"\br\d+ = 0x{bound:x}\b", export)
        for bound in (67, 68, 92, 104)
    ) and bool(re.search(r"\bif r\d+ > r\d+ goto -0x", export))


def instruction_entries(lines):
    return [
        (index, pc, text)
        for index, line in enumerate(lines)
        if "R_BPF_" not in line
        if (match := re.match(r"\s*(\d+):\s+(.*)", line))
        for pc, text in [(int(match.group(1)), match.group(2))]
    ]


def relocation_targets(lines):
    return [
        (index, kind, target)
        for index, line in enumerate(lines)
        if (match := re.search(r"R_BPF_64_(32|64)\s+(\S+)", line))
        for kind, target in [(match.group(1), match.group(2))]
    ]


def map_call_sites(lines, map_name, helper=None):
    sites = []
    entries = instruction_entries(lines)
    for relocation, _, target in relocation_targets(lines):
        if target != map_name:
            continue
        for line_index, pc, text in entries:
            if not relocation < line_index <= relocation + 6:
                continue
            if re.search(r"\bcall -?0x[0-9a-f]+\b", text):
                if helper is None or re.search(rf"\bcall 0x{helper:x}\b", text):
                    sites.append((line_index, pc, text))
                break
    return sites


def internal_call_targets(disassembly):
    blocks = function_blocks(disassembly)
    by_pc = {
        instruction_entries(lines)[0][1]: name
        for name, lines in blocks.items() if instruction_entries(lines)
    }
    calls = []
    for function, lines in blocks.items():
        for line_index, pc, text in instruction_entries(lines):
            match = re.search(r"\bcall (?P<sign>-?)0x(?P<value>[0-9a-f]+)\b", text)
            if not match:
                continue
            # Raw BPF helper calls (src_reg=0) are never internal calls.
            if re.match(r"85 00 ", text):
                continue
            relocation = next((target for index, kind, target in relocation_targets(lines)
                               if index == line_index + 1 and kind == "32"), None)
            value = int(match.group("value"), 16) * (-1 if match.group("sign") else 1)
            if relocation == ".text":
                target = by_pc.get(value + 1)
            elif relocation:
                target = relocation if relocation in blocks else None
            elif re.match(r"85 10 ", text) or match.group("sign"):
                target = by_pc.get(pc + 1 + value)
            else:
                target = None
            if target:
                calls.append((function, line_index, pc, target))
    return calls


def discovery_call_sites(disassembly, function, operation):
    return [(index, pc) for caller, index, pc, target in internal_call_targets(disassembly)
            if caller == function and target == "p11_owner_discovery_" + operation]


def call_argument_facts(lines):
    """Finite constants/stack addresses at discovery call sites; joins lose facts.

    This checks caller wiring only. The native transaction fixture remains the
    oracle for physical task ownership, directory updates and poison/debt.
    """
    insns, graph = instruction_graph(lines)
    if not insns:
        return {}
    texts = dict(insns)
    internal_pcs = {pc for index, pc, text in instruction_entries(lines)
                    if text.startswith("85 10 ") or any(
                        relocation == index + 1 and kind == "32"
                        for relocation, kind, _ in relocation_targets(lines))}
    incoming = {insns[0][0]: {"r10": ("stack", 0)}}
    pending = [insns[0][0]]
    while pending:
        pc = pending.pop()
        state = incoming[pc].copy()
        text = re.sub(r"^(?:[0-9a-f]{2}\s+){8,16}", "", texts[pc])
        text = re.sub(r"\s+<[^>]+>$", "", text)
        store = re.fullmatch(r"\*\(u(8|16|32|64) \*\)\(r(\d+) ([+-]) 0x([0-9a-f]+)\) = r(\d+)", text)
        if store:
            width, base, sign, offset, src = store.groups()
            address = state.get("r" + base)
            if address and address[0] == "stack":
                offset = address[1] + int(offset, 16) * (1 if sign == "+" else -1)
                for key in list(state):
                    if isinstance(key, int) and key < offset + int(width)//8 and offset < key + 8:
                        state.pop(key)
                if width == "64" and "r" + src in state:
                    state[offset] = state["r" + src]
        elif re.search(r"\bcall ", text):
            for register in range(6):
                state.pop("r" + str(register), None)
            state["r0"] = ("result", pc)
            if re.fullmatch(r"call 0xae", text) and pc not in internal_pcs:
                state["r0"] = ("cookie", pc)
        elif match := re.fullmatch(r"(r\d+) &= (0xffffff|0x100|-0x200)", text):
            register, mask = match.groups()
            previous = state.pop(register, None)
            if previous and previous[0] == "cookie":
                state[register] = ("cookie_mask", previous[1], int(mask, 16))
        elif match := re.fullmatch(r"(r\d+) s>>= 0x9", text):
            previous = state.pop(match.group(1), None)
            if previous and previous[0] == "cookie":
                state[match.group(1)] = ("loader_delta", previous[1])
        elif match := re.fullmatch(r"(r\d+) = \*\(u64 \*\)\(r10 ([+-]) 0x([0-9a-f]+)\)", text):
            register, sign, offset = match.groups()
            value = state.get(int(offset, 16) * (1 if sign == "+" else -1))
            state.pop(register, None)
            if value is not None:
                state[register] = value
        elif match := re.fullmatch(r"([rw]\d+) (=|\+=) (r\d+|-?0x[0-9a-f]+)(?: ll)?", text):
            dst, op, src = match.groups()
            register = "r" + dst[1:]
            value = state.get(src) if src.startswith("r") else ("constant", int(src, 16))
            if op == "+=":
                previous = state.get(register)
                value = ((previous[0], previous[1] + value[1])
                         if previous and previous[0] in ("constant", "stack")
                         and value and value[0] == "constant" else None)
            if dst.startswith("w") and value:
                value = ("constant", value[1] & 0xffffffff) if value[0] == "constant" else None
            state.pop(register, None)
            if value is not None:
                state[register] = value
        elif match := re.match(r"[rw](\d+)\s", text):
            state.pop("r" + match.group(1), None)
        for successor in graph[pc]:
            edge_state = state.copy()
            branch = re.fullmatch(r"if (r\d+) (==|!=) 0x0 goto [+-]0x[0-9a-f]+", text)
            if branch:
                register, comparison = branch.groups()
                value = state.get(register)
                taken = successor == relative_target(pc, text)
                if value:
                    predicate = "nonzero" if taken == (comparison == "!=") else "zero"
                    edge_state[(predicate, value)] = True
            if successor not in incoming:
                merged = edge_state
            else:
                merged = {k: v for k, v in incoming[successor].items() if edge_state.get(k) == v}
            if incoming.get(successor) != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming


def discovery_arguments(disassembly, function, operation, argument):
    lines = function_blocks(disassembly).get(function, [])
    facts = call_argument_facts(lines)
    sites = discovery_call_sites(disassembly, function, operation)
    register = "r3" if operation == "insert" else "r2"
    for _, pc in sites:
        state = facts.get(pc, {})
        key = state.get("r1")
        if state.get(register) != ("constant", argument) or not key or key[0] != "stack":
            return False
        if operation == "insert":
            value = state.get("r2")
            if not value or value[0] != "stack" or abs(value[1] - key[1]) < 24:
                return False
    return bool(sites)


def known_tail_relocations(lines):
    allowed_maps = {"COUNTERS", "EVIDENCE", "TAIL_CALLS", "STOP_GATE"}
    return all(
        (kind == "64" and target in allowed_maps)
        or (kind == "32" and target in {".text", "memset"})
        for _, kind, target in relocation_targets(lines)
    )


def has_counter_update_after(lines, start_pc, graph):
    sites = {pc for index, pc, _ in map_call_sites(lines, "COUNTERS", helper=1)
             if finite_counter_key(lines, index) == 1 and counter_writeback_contract(lines, pc)}
    exits = {pc for pc, edges in graph.items() if not edges}
    return bool(sites & reachable(graph, [start_pc])) and not (
        exits & reachable(graph, [start_pc], sites))


def tail_cleanup_contract(disassembly, function, tail_pc, graph):
    lines = function_blocks(disassembly)[function]
    facts = call_argument_facts(lines)
    cleanup = {pc for _, pc in discovery_call_sites(disassembly, function, "remove")
               if facts.get(pc, {}).get("r2") == ("constant", 1)}
    fallthrough = graph.get(tail_pc, [])
    reachable_pcs = reachable(graph, fallthrough)
    exits = {pc for pc, edges in graph.items() if not edges}
    # Every falling-through path must perform owned required removal.
    if exits & reachable(graph, fallthrough, cleanup):
        return False
    owned_paths = cleanup & reachable_pcs
    return bool(owned_paths) and all(has_counter_update_after(lines, pc, graph)
                                    for pc in owned_paths)


def interface_tail_contract(disassembly):
    blocks = function_blocks(disassembly)
    returns = [name for name in blocks if name.endswith("interface_list_return")]
    workers = [name for name in blocks if name.endswith("interface_list_worker")]
    classifiers = [name for name in blocks if name.endswith("classify_direct_interface")]
    emitters = [name for name in blocks if name.endswith("emit_export")]
    if len(returns) != 1 or len(workers) != 1 or len(classifiers) != 1 or len(emitters) != 1:
        return False
    if not all(
        known_tail_relocations(blocks[name]) for name in {*returns, *workers}
    ):
        return False
    return_name, worker_name, classifier_name, emitter_name = (
        *returns,
        *workers,
        *classifiers,
        *emitters,
    )
    return_lines, worker_lines = blocks[return_name], blocks[worker_name]
    return_insns, return_graph = instruction_graph(return_lines)
    worker_insns, worker_graph = instruction_graph(worker_lines)
    calls = internal_call_targets(disassembly)
    return_classifier_calls = [
        call for call in calls if call[0] == return_name and call[3] == classifier_name
    ]
    worker_classifier_calls = [
        call for call in calls if call[0] == worker_name and call[3] == classifier_name
    ]
    classifier_emit_calls = [
        call for call in calls if call[0] == classifier_name and call[3] == emitter_name
    ]
    if (
        return_classifier_calls
        or len(worker_classifier_calls) != 1
        or len(classifier_emit_calls) != 1
    ):
        return False
    if not discovery_arguments(disassembly, return_name, "insert", 1):
        return False
    if not discovery_arguments(disassembly, worker_name, "insert", 2):
        return False
    if not discovery_arguments(disassembly, worker_name, "get", 1):
        return False
    reads = {pc for _, pc in discovery_call_sites(disassembly, worker_name, "get")}
    classifier_state = call_argument_facts(worker_lines).get(worker_classifier_calls[0][2], {})
    if (worker_classifier_calls[0][2] in reachable(worker_graph, [worker_insns[0][0]], reads)
            or not any(classifier_state.get(("nonzero", ("result", pc))) for pc in reads)):
        return False
    for name, lines, graph in ((return_name, return_lines, return_graph),
                               (worker_name, worker_lines, worker_graph)):
        tails = map_call_sites(lines, "TAIL_CALLS", helper=0xC)
        if len(tails) != 1:
            return False
        tail_index, tail_pc, _ = tails[0]
        if call_argument_facts(lines).get(tail_pc, {}).get("r3") != ("constant", 0):
            return False
        inserts = {pc for _, pc in discovery_call_sites(disassembly, name, "insert")}
        tail_state = call_argument_facts(lines).get(tail_pc, {})
        if (tail_pc in reachable(graph, [instruction_entries(lines)[0][1]], inserts)
                or not any(tail_state.get(("zero", ("result", pc))) for pc in inserts)):
            return False
        if not tail_cleanup_contract(disassembly, name, tail_pc, graph):
            return False
    return_block = "\n".join(return_lines)
    worker_block = "\n".join(worker_lines)
    if not re.search(r"\br\d+ = \*\(u64 \*\)\(r\d+ \+ 0x8\)", return_block):
        return False
    if not re.search(r"\bif r\d+ == 0x0 goto", return_block):
        return False
    if not re.search(r"\bif r\d+ > r\d+ goto", return_block):
        return False
    if re.search(r"\bcall 0xae\b", worker_block):
        return False
    if not (
        re.search(r"\bif r\d+ > 0xffffff goto", worker_block)
        or (
            re.search(r"\br\d+ = 0xffffff\b", worker_block)
            and re.search(r"\bif r\d+ > r\d+ goto", worker_block)
        )
    ):
        return False
    if not re.search(r"\br\d+ = 0x10\b", worker_block):
        return False
    if not re.search(r"\bif r\d+ > 0xf goto", worker_block):
        return False
    if not re.search(r"\bif r\d+ >= r\d+ goto", worker_block):
        return False
    classifier_pc = worker_classifier_calls[0][2]
    tail_pc = map_call_sites(worker_lines, "TAIL_CALLS", helper=0xC)[0][1]
    if not any(
        pc > classifier_pc
        and pc < tail_pc
        and re.search(r"\br\d+ \+= 0x1\b", text)
        for pc, text in worker_insns
    ):
        return False
    return True


def cookie_object_contract(disassembly):
    blocks = function_blocks(disassembly)
    loader = blocks.get("dl_debug_state", [])
    loader_facts = call_argument_facts(loader)
    cookie_pcs = [pc for _, pc, text in instruction_entries(loader)
                  if re.search(r"\bcall 0xae\b", text)]
    if len(cookie_pcs) != 1:
        return False
    cookie_pc = cookie_pcs[0]
    # Only operations on the loader cookie count; unrelated ABI shifts do not.
    loader_values = {value for state in loader_facts.values()
                     for value in state.values() if isinstance(value, tuple)}
    if not {("cookie_mask", cookie_pc, 0x100),
            ("cookie_mask", cookie_pc, -0x200),
            ("loader_delta", cookie_pc)} <= loader_values:
        return False
    for name in ("function_list_entry", "function_list_return", "interface_list_entry",
                 "interface_list_return", "interface_list_worker", "interface_entry",
                 "interface_return"):
        lines = blocks.get(name, [])
        facts = call_argument_facts(lines)
        domain = 2 if name in ("interface_entry", "interface_return") else 1
        sites = [(pc, operation) for operation in ("get", "insert", "remove")
                 for _, pc in discovery_call_sites(disassembly, name, operation)]
        if not sites:
            return False
        if name == "interface_list_worker" and any("call 0xae" in line for line in lines):
            return False
        for pc, operation in sites:
            state = facts.get(pc, {})
            key = state.get("r1")
            if not key or key[0] != "stack" or state.get(key[1] + 16) != ("constant", domain):
                return False
            cookie = state.get(key[1] + 8)
            if cookie == ("constant", 0):
                if name == "interface_list_worker":
                    continue
                if name == "interface_list_return":
                    _, graph = instruction_graph(lines)
                    tails = [tail_pc for _, tail_pc, _ in map_call_sites(lines, "TAIL_CALLS", helper=12)]
                    if operation == "insert" or (operation == "remove" and pc in reachable(graph, tails)):
                        continue
                return False
            if not cookie or cookie[0] != "cookie":
                return False
            checked = cookie if domain == 2 else ("cookie_mask", cookie[1], 0xffffff)
            if not state.get(("nonzero", checked)):
                return False
    return True


def finite_counter_key(lines, relocation):
    key_store = re.compile(
        r"\*\(u32 \*\)\(r10 - 0x[0-9a-f]+\) = [rw](?P<register>\d+)"
    )
    stored = next(
        (
            (index, match.group("register"))
            for index in range(relocation - 1, max(-1, relocation - 12), -1)
            if (match := key_store.search(lines[index]))
        ),
        None,
    )
    if stored is None:
        return None
    store_index, register = stored
    assignment = re.compile(
        rf"\br{register} = (?P<sign>-?)0x(?P<value>[0-9a-f]+)\b"
    )
    for index in range(store_index - 1, -1, -1):
        if match := assignment.search(lines[index]):
            value = int(match.group("value"), 16)
            return -value if match.group("sign") else value
        if re.search(rf"\br{register} =", lines[index]):
            break
    return None


COUNTER_ATOMIC_ADD = re.compile(r"lock \*\(u64 \*\)\(r(\d+) \+ 0x0\) \+= r(\d+)")
COUNTER_CELL_WRITE = re.compile(r"\*\(u(?:8|16|32|64) \*\)\(r(\d+) [+-] 0x[0-9a-f]+\) = ")


def counter_writeback_contract(lines, lookup_pc):
    """Every non-null path from this lookup must atomically add one to its value.

    The only accepted update is a non-fetch ``lock *(u64 *)(cell + 0x0) += rN``
    whose addend is the known constant 1. A plain load/add/store is refused:
    from Linux 6.1 uprobe programs run preemptible (migrate-disabled only), so
    two programs on one CPU can interleave inside a per-CPU read-modify-write
    and lose an increment of the one loss counter a run may have.
    """
    insns, graph = instruction_graph(lines)
    texts = dict(insns)
    facts = call_argument_facts(lines)
    pending = [(pc, frozenset({"0"}), False) for pc in graph.get(lookup_pc, [])]
    seen = set()
    stored = False
    while pending:
        pc, cells, checked = pending.pop()
        key = (pc, cells, checked)
        if key in seen:
            return False  # An update-free cycle cannot establish loss accounting.
        seen.add(key)
        text = texts[pc]
        null = re.fullmatch(r"if r(\d+) (==|!=) 0x0 goto [+-]0x[0-9a-f]+", text)
        if null and null.group(1) in cells and not checked:
            target = relative_target(pc, text)
            if null.group(2) == "==":
                edges = [edge for edge in graph[pc] if edge != target]
            else:
                edges = [target]
            checked = True
        elif atomic := COUNTER_ATOMIC_ADD.fullmatch(text):
            base, addend = atomic.groups()
            if base not in cells:
                return False
            if not checked or facts.get(pc, {}).get("r" + addend) != ("constant", 1):
                return False
            stored = True
            continue
        else:
            if re.search(r"\bcall ", text) or "atomic" in text or "xchg" in text \
                    or text.startswith("lock "):
                return False
            write = COUNTER_CELL_WRITE.match(text)
            if write and write.group(1) in cells:
                return False  # Non-atomic writeback of the counter cell.
            copy = re.fullmatch(r"r(\d+) = r(\d+)", text)
            destination = re.match(r"[rw](\d+)\s", text)
            if copy and copy.group(2) in cells:
                cells = cells | {copy.group(1)}
            elif destination and destination.group(1) in cells:
                cells = cells - {destination.group(1)}
                if not cells:
                    return False
            edges = graph[pc]
        if not edges:
            return False
        pending.extend((edge, cells, checked) for edge in edges)
    return stored


def reservation_loss_contract(disassembly):
    reservation_functions = set()
    for function, lines in function_blocks(disassembly).items():
        for relocation in [
            index
            for index, line in enumerate(lines)
            if re.search(r"R_BPF_64_64\s+DISCOVERY\s*$", line)
        ]:
            reservation_functions.add(function)
            reserve = next(
                (
                    index
                    for index in range(relocation, min(len(lines), relocation + 10))
                    if "call 0x83" in lines[index]
                ),
                None,
            )
            if reserve is None:
                return False
            branch = next(
                (
                    index
                    for index in range(reserve + 1, min(len(lines), reserve + 8))
                    if re.search(r"\bif r(?P<base>\d+) != 0x0 goto ", lines[index])
                ),
                None,
            )
            if branch is None:
                return False
            target = relative_target(line_pc(lines[branch]), lines[branch])
            target_index = next(
                (index for index, line in enumerate(lines) if line_pc(line) == target),
                None,
            )
            if target_index is None or target_index <= branch:
                return False
            failure = lines[branch + 1 : target_index]
            counters = [
                index
                for index, line in enumerate(failure)
                if re.search(r"R_BPF_64_64\s+COUNTERS\s*$", line)
            ]
            if len(counters) != 1 or finite_counter_key(lines, branch + 1 + counters[0]) != 0:
                return False
            lookups = map_call_sites(lines, "COUNTERS", helper=1)
            lookup = next((pc for index, pc, _ in lookups
                           if branch < index < target_index), None)
            if lookup is None or not counter_writeback_contract(lines, lookup):
                return False
            _, graph = instruction_graph(lines)
            # The null reservation arm cannot bypass its COUNTERS lookup.
            failure_start = line_pc(next(line for line in lines[branch + 1:] if line_pc(line) is not None))
            unaccounted = reachable(graph, [failure_start], {lookup})
            if target in unaccounted or any(not graph[pc] for pc in unaccounted):
                return False
    return len(reservation_functions) == 3 and {
        next((name for name in reservation_functions if name.endswith("emit_export")), None),
        next((name for name in reservation_functions if name.endswith("emit_lifecycle")), None),
        "dl_debug_state",
    } == reservation_functions


def producer_object_contract(disassembly):
    blocks = function_blocks(disassembly)
    entry_names = ("function_list_entry", "interface_list_entry", "interface_entry")
    return_names = ("function_list_return", "interface_list_return", "interface_return")
    for name in entry_names:
        lines = blocks.get(name, [])
        if (not discovery_arguments(disassembly, name, "insert", 1)
                or not discovery_call_sites(disassembly, name, "remove")
                or not map_call_sites(lines, "COUNTERS", helper=1)):
            return False
    for name in return_names:
        lines = blocks.get(name, [])
        if (not discovery_arguments(disassembly, name, "get", 0)
                # Scope-refused and admitted returns each read their saved state.
                or len(discovery_call_sites(disassembly, name, "get")) != 2
                or len(discovery_call_sites(disassembly, name, "remove")) < 2
                or not map_call_sites(lines, "COUNTERS", helper=1)):
            return False

    export = "\n".join(blocks.get("interface_list_return", []))
    if "call 0x70" not in export or not re.search(
        r"R_BPF_64_64\s+COUNTERS\s*$", export, re.MULTILINE
    ):
        return False

    loader = "\n".join(blocks.get("dl_debug_state", []))
    if (
        "= -0x8000000000000000 ll" not in loader
        or len(re.findall(r"\bif r\d+ == 0x2 goto ", loader)) < 2
        or not re.search(r"R_BPF_64_64\s+PAUSE_PIDS\s*$", loader, re.MULTILINE)
    ):
        return False

    for name in ("dl_debug_state",):
        block = "\n".join(blocks.get(name, []))
        if "= 0x4" not in block:
            return False

    return reservation_loss_contract(disassembly)


def object_counter_uses(disassembly):
    uses = []
    for function, lines in function_blocks(disassembly).items():
        for relocation in [
            index
            for index, line in enumerate(lines)
            if re.search(r"R_BPF_64_64\s+COUNTERS\s*$", line)
        ]:
            key = finite_counter_key(lines, relocation)
            if key is None:
                fail(f"{function}: COUNTERS lookup has no finite u32 stack key")
            uses.append((function, key))
    return uses


def counter_ownership_contract(uses):
    allowed = {
        0: ("emit_export", "emit_lifecycle", "dl_debug_state"),
        1: (
            "function_list_entry",
            "function_list_return",
            "interface_list_entry",
            "interface_list_return",
            "interface_list_worker",
            "interface_entry",
            "interface_return",
        ),
        2: ("emit_export", "interface_list_return", "interface_entry",
            "classify_direct_interface", "classify_indirect_interface",
            "function_list_entry", "interface_list_entry"),
        3: ("dl_debug_state",),
        4: ("dl_debug_state",),
    }
    if {key for _, key in uses} != set(allowed):
        return False
    return all(
        key in allowed and any(function.endswith(owner) for owner in allowed[key])
        for function, key in uses
    )


def inspect_object(path, source, variant):
    checker = map_checker()
    allowed = checker["DIAGNOSTIC_GLOBAL_HELPERS"] if variant == "unsafe" else frozenset()
    maps, programs, _ = checker["inspect"](str(path), allowed)
    disassembly = subprocess.run(
        ["llvm-objdump", "-dr", "--print-imm-hex", str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    regions = initializer_regions(disassembly)
    counter_uses = object_counter_uses(disassembly)
    offsets = [offset for region in regions for offset in region["offsets"]]
    return {
        "maps": maps,
        "programs": programs,
        "initializer_regions": regions,
        "record_size": max(offsets, default=-8) + 8,
        "record_align": min(
            (
                right - left
                for region in regions
                for left, right in zip(region["offsets"], region["offsets"][1:])
                if right > left
            ),
            default=0,
        ),
        "counter_indices": {
            str(index): COUNTERS[str(index)] for index in {key for _, key in counter_uses}
        },
        "counter_ownership": counter_ownership_contract(counter_uses),
        "cookie_namespaces_distinct": cookie_object_contract(disassembly),
        "table_bounds": "while pointer_index < 104" in source
        and table_bounds_object_contract(disassembly),
        "interface_tail": interface_tail_contract(disassembly),
        "producer_edges": producer_object_contract(disassembly),
        "cmpxchg_count": pause_cas_count(disassembly),
        "signal_count": len(re.findall(r"call 0x6d\b", disassembly)),
        "pause_order": pause_object_contract(disassembly),
        "unrelated_memset": "<memset>:" in disassembly,
        "variant": variant,
    }


def object_contract(facts, variant):
    maps, programs = expected_inventory(variant)
    checks = [
        (facts["maps"] == maps, "map ABI/inventory differs"),
        (facts["programs"] == programs, "program inventory differs"),
        (facts["record_size"] == 920, "record size differs"),
        (facts["record_align"] == 8, "record alignment differs"),
        (facts["counter_indices"] == COUNTERS, "counter permutation differs"),
        (facts["counter_ownership"], "counter ownership differs"),
        (facts["cookie_namespaces_distinct"], "cookie namespaces collide"),
        (facts["table_bounds"], "table-bound proof differs"),
        (facts["interface_tail"], "interface tail lifecycle differs"),
        (facts["producer_edges"], "producer edge contract differs"),
        (facts["cmpxchg_count"] == 3, "cmpxchg_64 inventory differs"),
        (facts["signal_count"] == 3, "signal helper inventory differs"),
        (facts["pause_order"], "CAS/timestamp/signal/result/submit order differs"),
        (facts["unrelated_memset"], "unrelated memset positive control is absent"),
        (len(facts["initializer_regions"]) == 3, "initializer copy inventory differs"),
    ]
    for region in facts["initializer_regions"]:
        checks.extend(
            [
                (region["offsets"] == list(range(0, 920, 8)), "initializer offsets differ"),
            ]
        )
    for okay, message in checks:
        if not okay:
            fail(message)


def _initializer(stores=range(115)):
    return "\n".join(
        [INITIALIZER_BEGIN]
        + [f"core::ptr::write_volatile(words.add({index}), 0u64);" for index in stores]
        + [INITIALIZER_END]
    )


def _pause():
    return f"""{PAUSE_BEGIN}
let previous = core::intrinsics::atomic_cxchg::<u64, AcqRel, Acquire>(value, PAUSE_ARMED, PAUSE_REQUESTED);
if previous == PAUSE_ARMED {{
    let hook_ts_ns = helpers::bpf_ktime_get_ns();
    let send_signal_rc = helpers::bpf_send_signal(19) as i64;
}} else {{
    let hook_ts_ns = helpers::bpf_ktime_get_ns();
}}
core::ptr::write(core::ptr::addr_of_mut!((*raw).send_signal_rc), send_signal_rc);
entry.submit(0);
{PAUSE_END}"""


def _source(stores=range(115)):
    return "\n".join(
        [
            "fn unrelated() { core::ptr::write_bytes(dst, 0, 8); }",
            "fn loader_cookie_context(cookie: u64) {}",
            "fn slot_cookie_descriptor(cookie: u64) {}",
            _initializer(stores),
            _pause(),
        ]
    )


def _initializer_block(function, tail=""):
    lines = [
        f"0000000000000000 <{function}>:",
        "       0:\tr7 = 0x0",
        "       1:\tr1 = 0x0 ll",
        "\t\t0000000000000008:  R_BPF_64_64\tDISCOVERY",
        "       3:\tr2 = 0x398",
        "       4:\tr3 = 0x0",
        "       5:\tcall 0x83",
        "       6:\tr6 = r0",
        "       7:\tif r6 != 0x0 goto +0x7",
        "       8:\t*(u32 *)(r10 - 0x4) = r7",
        "\t\t0000000000000040:  R_BPF_64_64\tCOUNTERS",
        "       9:\tcall 0x1",
        "      10:\tif r0 == 0x0 goto +0x74",
        "      11:\tr1 = 0x1",
        "      12:\tlock *(u64 *)(r0 + 0x0) += r1",
        "      13:\tr1 = 0x0",
        "      14:\tgoto +0x70",
    ]
    lines.extend(
        f"{15 + index:8}:\t*(u64 *)(r6 + 0x{index * 8:x}) = r7"
        for index in range(115)
    )
    lines.append("     127:\tcall 0x84")
    if tail:
        lines.extend(tail.splitlines())
    return "\n".join(lines)


def _initializer_disassembly(loader_tail=""):
    return "\n".join(
        [
            _initializer_block("fixture_emit_export"),
            _initializer_block("fixture_emit_lifecycle"),
            _initializer_block("dl_debug_state", loader_tail),
        ]
    )


def _pause_disassembly():
    block = """0000000000000000 <pause{index}>:
       0:\tr1 = 0x0 ll
\t\t0000000000000000:  R_BPF_64_64\tPAUSE_PIDS
       2:\tcall 0x1
       3:\tr1 = r0
       4:\tr0 = cmpxchg_64(r1 + 0x0, r0, r3)
       5:\tif r0 == 0x1 goto +0x4
       6:\tr7 = -0x8000000000000000 ll
       7:\tif r0 == 0x2 goto +0x0
       8:\tcall 0x5
       9:\tgoto +0x7
      10:\tcall 0x5
      11:\tr1 = 0x13
      12:\tcall 0x6d
      13:\t*(u64 *)(r6 + 0x0) = r7
      14:\t*(u64 *)(r6 + 0x8) = r7
      15:\t*(u64 *)(r6 + 0x364) = r7
      16:\t*(u64 *)(r6 + 0x378) = r7
      17:\tcall 0x84
      18:\texit"""
    return "\n".join(block.format(index=name) for name in ("_emit_export", "_emit_lifecycle", "_dl_debug_state")).replace("pause_dl_debug_state", "dl_debug_state")


def _owned_disassembly():
    """Small instruction/relocation fixtures for the native caller ABI."""
    starts = {"p11_owner_discovery_get": 5000, "p11_owner_discovery_insert": 5100,
              "p11_owner_discovery_remove": 5200, "classify_direct_interface": 6000,
              "fixture_emit_export": 7000}

    def call(name):
        return [f"call 0x{starts[name] - 1:x}", "rel32:.text"]

    def assemble(name, body, start):
        labels = {}
        pc = start
        for text in body:
            if text.startswith("label:"):
                labels[text[6:]] = pc
            elif not text.startswith("rel"):
                pc += 1
        pc = start
        lines = [f"{start * 8:016x} <{name}>:"]
        for text in body:
            if text.startswith("label:"):
                continue
            if text.startswith("rel"):
                kind, target = text[3:].split(":")
                lines.append(f"                {(pc - 1) * 8:016x}:  R_BPF_64_{kind}\t{target}")
                continue
            if "@" in text:
                prefix, label = text.split("@")
                distance = labels[label] - pc - 1
                text = prefix + ("+" if distance >= 0 else "-") + f"0x{abs(distance):x}"
            lines.append(f"{pc:8}:\t{text}")
            pc += 1
        return "\n".join(lines)

    def key(domain, continuation=False):
        if continuation:
            body = ["r6 = 0x0"]
        else:
            body = ["call 0xae", "r6 = r0"]
            if domain == 1:
                body += ["r7 = r6", "r7 &= 0xffffff", "if r7 == 0x0 goto @exit"]
            else:
                body += ["if r6 == 0x0 goto @exit"]
        return body + ["call 0xe", "r1 = r10", "r1 += -0x18",
                       "*(u64 *)(r1 + 0x0) = r0", "*(u64 *)(r1 + 0x8) = r6",
                       f"r7 = 0x{domain:x}", "*(u64 *)(r1 + 0x10) = r7"]

    def operation(name, arg):
        body = ["r1 = r10", "r1 += -0x18"]
        if name == "insert":
            body += ["r2 = r10", "r2 += -0x30", f"r3 = 0x{arg:x}"]
        else:
            body += [f"r2 = 0x{arg:x}"]
        return body + call("p11_owner_discovery_" + name)

    def counter():
        return ["r7 = 0x1", "*(u32 *)(r10 - 0x4) = r7", "r2 = r10", "r2 += -0x4",
                "r1 = 0x0 ll", "rel64:COUNTERS", "call 0x1", "if r0 == 0x0 goto @exit",
                "r5 = 0x1", "lock *(u64 *)(r0 + 0x0) += r5"]

    parts = []
    names = ("function_list_entry", "interface_list_entry", "interface_entry",
             "function_list_return", "interface_list_return", "interface_return",
             "interface_list_worker")
    for index, name in enumerate(names):
        worker = name == "interface_list_worker"
        domain = 2 if name in ("interface_entry", "interface_return") else 1
        body = key(domain, worker)
        if name.endswith("entry"):
            body += operation("insert", 1) + operation("remove", 0) + counter()
        elif worker or name == "interface_list_return":
            body += operation("get", 1 if worker else 0)
            if not worker:
                body += operation("get", 0)
            else:
                body += ["if r0 == 0x0 goto @exit"]
            body += ["r8 = *(u64 *)(r0 + 0x8)", "if r8 == 0x0 goto @exit", "if r1 > r2 goto @exit"]
            if worker:
                body += ["if r8 > 0xffffff goto @exit", "r1 = 0x10", "if r1 > 0xf goto @exit",
                         "if r1 >= r2 goto @exit"] + call("classify_direct_interface") + ["r1 += 0x1"]
            else:
                body += operation("remove", 1) + operation("remove", 1) + ["call 0x70"] + key(1, True)
            body += operation("insert", 2 if worker else 1)
            body += ["if r0 != 0x0 goto @exit"]
            body += ["r2 = 0x0 ll", "rel64:TAIL_CALLS", "r3 = 0x0", "call 0xc"]
            body += operation("remove", 1) + counter()
        else:
            body += operation("get", 0) + operation("get", 0) + operation("remove", 1) + operation("remove", 1) + counter()
        body += ["label:exit", "exit"]
        parts.append(assemble(name, body, 100 + index * 100))
    for name in starts:
        if name.startswith("p11_owner_"):
            parts.append(assemble(name, ["exit"], starts[name]))
    parts.append(assemble("classify_direct_interface", call("fixture_emit_export") + ["exit"], 6000))
    for index, name in enumerate(("fixture_emit_export", "fixture_emit_lifecycle", "dl_debug_state")):
        tail = ["r1 = 0x43", "r2 = 0x44", "r3 = 0x5c", "r4 = 0x68", "if r1 > r2 goto -0x1"]
        if name == "dl_debug_state":
            tail = ["call 0xae", "r7 = r0", "r1 = r7", "r1 &= 0x100", "r2 = r7", "r2 &= -0x200",
                    "r7 s>>= 0x9", "r1 = 0x4", "r7 = -0x8000000000000000 ll",
                    "if r0 == 0x2 goto +0x0", "if r0 == 0x2 goto +0x0", "r1 = 0x0 ll", "rel64:PAUSE_PIDS"]
        # Reuse the initializer fixture, fixing its historical duplicate PC at submit.
        block = _initializer_block(name).replace("     127:\tcall 0x84", "     130:\tcall 0x84")
        body = []
        for line in block.splitlines()[1:]:
            if "R_BPF" in line:
                kind, target = re.search(r"R_BPF_64_(32|64)\s+(\S+)", line).groups()
                body.append(f"rel{kind}:{target}")
            elif (match := re.match(r"\s*\d+:\s+(.*)", line)):
                body.append(match.group(1))
        parts.append(assemble(name, body + tail + ["exit"], 7000 + index * 200))
    return "\n".join(parts)


def _counter_writeback_self_test(disassembly=None, counter_keys=(0, 1)):
    # The same maintained mutations run on the fixture and on retained decoded
    # objects, including their backwards branches to shared counter updates.
    good = _owned_disassembly() if disassembly is None else disassembly
    blocks = function_blocks(good)
    export = next(name for name in blocks if name.endswith("emit_export"))
    worker = next(name for name in blocks if name.endswith("interface_list_worker"))

    def accounting(disassembly, name, key):
        if key == 0:
            return reservation_loss_contract(disassembly)
        lines = function_blocks(disassembly)[name]
        _, graph = instruction_graph(lines)
        tail = map_call_sites(lines, "TAIL_CALLS", helper=12)[0][1]
        return tail_cleanup_contract(disassembly, name, tail, graph)

    def insert_before(name, position, inserted):
        # Shift only this function's decoded PCs and local branch targets. No
        # ELF or kernel execution is implied by these instruction mutations.
        changed = []
        for line in blocks[name]:
            if "R_BPF" in line or not (match := re.match(r"\s*(\d+):\s+(.*)", line)):
                changed.append(line)
                continue
            pc = int(match.group(1))
            text = re.sub(r"^(?:[0-9a-f]{2}\s+){8,16}", "", match.group(2))
            text = re.sub(r"\s+<[^>]+>$", "", text)
            new_pc = pc + (pc >= position)
            target = relative_target(pc, text)
            if target is not None:
                target += target >= position
                offset = target - new_pc - 1
                text = re.sub(r"goto [+-]0x[0-9a-f]+",
                              f"goto {'+' if offset >= 0 else '-'}0x{abs(offset):x}", text)
            if pc == position:
                changed.append(f"{position}: {inserted}")
            changed.append(f"{new_pc}: {text}")
        return good.replace("\n".join(blocks[name]), "\n".join(changed), 1)

    def replace_in_function(disassembly, name, before, after):
        block = "\n".join(function_blocks(disassembly)[name])
        if block.count(before) != 1:
            raise AssertionError(f"counter mutation ambiguous in {name}: {before}")
        return disassembly.replace(block, block.replace(before, after, 1), 1)

    tested = 0
    for name, key in ((export, 0), (worker, 1)):
        if key not in counter_keys:
            continue
        if not accounting(good, name, key):
            raise AssertionError(f"counter{key} positive control rejected")
        lines = blocks[name]
        insns, graph = instruction_graph(lines)
        start = insns[0][0] if key == 0 else map_call_sites(lines, "TAIL_CALLS", helper=12)[0][1]
        relocation, lookup = next((index, pc) for index, pc, _ in map_call_sites(lines, "COUNTERS", helper=1)
                                  if finite_counter_key(lines, index) == key
                                  and pc in reachable(graph, [start]))
        key_store = re.compile(
            r"\*\(u32 \*\)\(r10 - 0x(?P<offset>[0-9a-f]+)\) = (?P<width>[rw])(?P<register>\d+)"
        )
        store_index, store, store_match = next(
            (index, lines[index], match)
            for index in range(relocation - 1, max(-1, relocation - 12), -1)
            if (match := key_store.search(lines[index]))
        )
        register = store_match.group("register")
        assignment = next(
            lines[index]
            for index in range(store_index - 1, -1, -1)
            if re.search(rf"\br{register} = 0x{key:x}\b", lines[index])
        )
        alias_width = "w" if store_match.group("width") == "r" else "r"
        alias_store = (
            store[: store_match.start("width")]
            + alias_width
            + store[store_match.end("width") :]
        )
        alias_good = replace_in_function(good, name, store, alias_store)
        alias_lines = function_blocks(alias_good)[name]
        alias_relocation = next(index for index, _, _ in map_call_sites(alias_lines, "COUNTERS", helper=1)
                                if finite_counter_key(alias_lines, index) == key)
        if finite_counter_key(alias_lines, alias_relocation) != key or not accounting(alias_good, name, key):
            raise AssertionError(f"counter{key} {alias_width}{register} stack-store alias rejected")
        wrong_register = str(int(register) - 1 if register == "9" else int(register) + 1)
        for label, before, after in (
            ("wrong key", assignment,
             assignment.replace(f"r{register} = 0x{key:x}", f"r{register} = 0x{1 - key:x}")),
            ("missing key store", store,
             store[:store_match.start()] + "r0 = r0" + store[store_match.end():]),
            ("wrong key source", store,
             store[:store_match.start("register")] + wrong_register
             + store[store_match.end("register"):]),
        ):
            bad = replace_in_function(good, name, before, after)
            if accounting(bad, name, key):
                raise AssertionError(f"counter{key} {label} accepted")
        downstream = reachable(graph, [lookup])
        texts = dict(insns)
        update, register = next((pc, match.group(2)) for pc, text in insns
                                if pc in downstream
                                if (match := COUNTER_ATOMIC_ADD.fullmatch(text)))
        assignment = next(pc for pc, text in reversed(insns)
                          if pc < update and pc in downstream
                          and text == f"r{register} = 0x1")
        assert texts[update] == f"lock *(u64 *)(r0 + 0x0) += r{register}"
        for label, before, after in (
            ("plain writeback", texts[update], f"*(u64 *)(r0 + 0x0) = r{register}"),
            ("fetch writeback", texts[update],
             f"r{register} = atomic_fetch_add((u64 *)(r0 + 0x0), r{register})"),
            ("addend two", texts[assignment], f"r{register} = 0x2"),
        ):
            bad = replace_in_function(good, name, "\t" + before, "\t" + after)
            if accounting(bad, name, key):
                raise AssertionError(f"counter{key} {label} accepted")
            tested += 1
        for position in (assignment + 1, update):
            for clobber in (f"r{register} ^= 0x1", f"r{register} *= 0x0",
                            f"w{register} ^= 0x1", "r0 ^= 0x8", "w0 ^= 0x8",
                            f"r{register} += 0x1", "call 0x5",
                            f"*(u64 *)(r0 + 0x0) = r{register}"):
                bad = insert_before(name, position, clobber)
                if accounting(bad, name, key):
                    raise AssertionError(f"counter{key} mutation accepted before {position}: {clobber}")
                tested += 1
    return tested


def _owned_self_test():
    good = _owned_disassembly()
    checks = (cookie_object_contract, interface_tail_contract, producer_object_contract)
    for check in checks:
        if not check(good):
            raise AssertionError(f"valid owned fixture rejected: {check.__name__}")
    blocks = function_blocks(good)

    def mutate(function, before, after, last=False):
        block = "\n".join(blocks[function])
        if before not in block:
            raise AssertionError(f"mutation did not change {function}: {before}")
        changed = after.join(block.rsplit(before, 1)) if last else block.replace(before, after, 1)
        return good.replace(block, changed, 1)

    for name in ("interface_list_return", "interface_list_worker"):
        for label, before, after in (
            ("insert flag", "r3 = 0x" + ("1" if name.endswith("return") else "2"), "r3 = 0x0"),
            ("insert call", "call 0x13eb", "call 0x13ec"),
            ("cleanup call", "call 0x144f", "call 0x1450"),
            ("tail slot", "r3 = 0x0", "r3 = 0x1"),
            ("insert success gate", "if r0 != 0x0 goto", "if r0 == 0x0 goto"),
            ("counter increment", "r5 = 0x1", "r5 = 0x2"),
            ("counter writeback", "lock *(u64 *)(r0 + 0x0) += r5", "r2 = r5"),
            ("plain counter writeback", "lock *(u64 *)(r0 + 0x0) += r5", "*(u64 *)(r0 + 0x0) = r5"),
        ):
            if interface_tail_contract(mutate(name, before, after, last=label == "cleanup call")):
                raise AssertionError(f"mutation accepted: {name} {label}")
    for before, after in (("r2 = 0x1", "r2 = 0x0"), ("call 0x1387", "call 0x1388"),
                          ("call 0x176f", "call 0x1770"), ("r1 += 0x1", "r1 += 0x0"),
                          ("if r1 > 0xf", "if r1 > 0x10"), ("if r1 >= r2", "if r1 > r2"),
                          ("if r8 > 0xffffff", "if r8 > 0x1000000")):
        if interface_tail_contract(mutate("interface_list_worker", before, after)):
            raise AssertionError(f"worker mutation accepted: {before}")
    for name in ("function_list_entry", "interface_entry", "interface_list_worker"):
        for before, after in (("*(u64 *)(r1 + 0x10) = r7", "*(u64 *)(r1 + 0x10) = r0"),
                              ("r1 += -0x18", "r1 += -0x20")):
            if cookie_object_contract(mutate(name, before, after)):
                raise AssertionError(f"cookie domain/key mutation accepted: {name}")
    for name in ("function_list_entry", "interface_entry"):
        for before, after in (("call 0xae", "call 0x5"), ("r6 = r0", "w6 = w0"),
                              ("r6 = r0", "r6 = 0x1"), ("== 0x0 goto", "!= 0x0 goto")):
            if cookie_object_contract(mutate(name, before, after)):
                raise AssertionError(f"cookie provenance mutation accepted: {name} {before}")
    for before, after in (("r1 &= 0x100", "r1 &= 0x200"), ("r2 &= -0x200", "r2 &= -0x100"),
                          ("r7 s>>= 0x9", "r7 >>= 0x20")):
        if cookie_object_contract(mutate("dl_debug_state", before, after)):
            raise AssertionError(f"loader cookie mutation accepted: {before}")
    for before, after in (("call 0x13eb", "call 0x13ec"), ("r3 = 0x1", "r3 = 0x0"),
                          ("call 0x144f", "call 0x1450")):
        if producer_object_contract(mutate("function_list_entry", before, after)):
            raise AssertionError(f"producer mutation accepted: {before}")
    for name, before, after in (("function_list_return", "call 0x1387", "call 0x1388"),
                               ("interface_list_return", "call 0x70", "call 0x71"),
                               ("dl_debug_state", "r1 = 0x4", "r1 = 0x0"),
                               ("dl_debug_state", "r7 = -0x8000000000000000 ll", "r7 = 0x0"),
                               ("fixture_emit_export", "R_BPF_64_64\tCOUNTERS", "R_BPF_64_64\tNOT_COUNTERS"),
                               ("fixture_emit_export", "r7 = 0x0", "r7 = 0x1"),
                               ("fixture_emit_export", "\tr1 = 0x1\n", "\tr1 = 0x2\n"),
                               ("fixture_emit_export", "lock *(u64 *)(r0 + 0x0) += r1", "r2 = r1"),
                               ("fixture_emit_export", "lock *(u64 *)(r0 + 0x0) += r1",
                                "*(u64 *)(r0 + 0x0) = r1")):
        if producer_object_contract(mutate(name, before, after)):
            raise AssertionError(f"producer edge mutation accepted: {before}")
    if not table_bounds_object_contract(good):
        raise AssertionError("valid table bounds rejected")
    for bound in ("0x43", "0x44", "0x5c", "0x68"):
        if table_bounds_object_contract(mutate("fixture_emit_export", " = " + bound, " = 0x42")):
            raise AssertionError(f"table bound mutation accepted: {bound}")


def _reject(action, label):
    try:
        action()
    except (RuntimeError, ValueError):
        return
    raise AssertionError(f"mutation accepted: {label}")


def self_test():
    good = _source()
    source_contract(good)
    _reject(lambda: source_contract(_source(range(111))), "111 stores")
    _reject(lambda: source_contract(_source(range(113))), "113 stores")
    _reject(
        lambda: source_contract(_source(list(range(111)) + [110])),
        "duplicate/missing index",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "write_volatile(words.add(7), 0u64)",
                "write_volatile(words.cast::<u32>().add(14), 0u32)",
            )
        ),
        "narrow store",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "write_volatile(words.add(111), 0u64);",
                "let early = (*raw).kind;\ncore::ptr::write_volatile(words.add(111), 0u64);",
            )
        ),
        "field read before initialization",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "write_volatile(words.add(111), 0u64);",
                "entry.submit(0);\ncore::ptr::write_volatile(words.add(111), 0u64);",
            )
        ),
        "submit before final store",
    )
    _reject(
        lambda: source_contract(
            good.replace("core::intrinsics::atomic_cxchg", "plain_compare_exchange")
        ),
        "missing CAS",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "let send_signal_rc = helpers::bpf_send_signal(19) as i64;",
                "let _earlier = helpers::bpf_get_prandom_u32();\n    let send_signal_rc = helpers::bpf_send_signal(19) as i64;",
            )
        ),
        "winner timestamp not immediately before helper",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "if previous == PAUSE_ARMED {\n    let hook_ts_ns",
                "if previous == PAUSE_ARMED {\n    let _early = helpers::bpf_get_prandom_u32();\n    let hook_ts_ns",
            )
        ),
        "helper between CAS and winner timestamp",
    )
    timestamp_before_cas = good.replace(
        "let previous = core::intrinsics::atomic_cxchg::<u64, AcqRel, Acquire>(value, PAUSE_ARMED, PAUSE_REQUESTED);",
        "let hook_ts_ns = helpers::bpf_ktime_get_ns();\nlet previous = core::intrinsics::atomic_cxchg::<u64, AcqRel, Acquire>(value, PAUSE_ARMED, PAUSE_REQUESTED);",
    ).replace(
        "    let hook_ts_ns = helpers::bpf_ktime_get_ns();\n    let send_signal_rc",
        "    let send_signal_rc",
    )
    _reject(
        lambda: source_contract(timestamp_before_cas),
        "winner timestamp before CAS",
    )
    span = """
checked_add((active_count - 1) * layout.interface().stride as u64)
address.checked_add(layout.interface().stride as u64 - layout.word_bytes() as u64)
target_word_end(address, layout)
interface_continuation_pack(count, 0, symbol_id)
"""
    interface_list_span_contract(span)
    for label, mutation in [
        ("target-sized interface stride", span.replace("layout.interface().stride", "24", 1)),
        ("complete final word", span.replace("target_word_end(address, layout)", "address")),
        (
            "span check after continuation",
            "interface_continuation_pack(count, 0, symbol_id)\n" + span,
        ),
    ]:
        _reject(lambda mutation=mutation: interface_list_span_contract(mutation), label)
    _reject(
        lambda: source_contract(
            good.replace(
                "let send_signal_rc = helpers::bpf_send_signal(19) as i64;",
                "let send_signal_rc = helpers::bpf_send_signal(19) as i64;\n    let _again = helpers::bpf_send_signal(19);",
            )
        ),
        "two signal helpers",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "let send_signal_rc = helpers::bpf_send_signal(19) as i64;",
                "let send_signal_rc = helpers::bpf_send_signal(19) as i64;\n    let _after = helpers::bpf_get_prandom_u32();",
            )
        ),
        "post-signal helper",
    )
    _reject(
        lambda: source_contract(
            good.replace(
                "core::ptr::write(core::ptr::addr_of_mut!((*raw).send_signal_rc), send_signal_rc);\nentry.submit(0);",
                "entry.submit(0);\ncore::ptr::write(core::ptr::addr_of_mut!((*raw).send_signal_rc), send_signal_rc);",
            )
        ),
        "pause submit before final result stores",
    )

    initializer = _initializer_disassembly()
    if len(initializer_regions(initializer)) != 3:
        raise AssertionError("valid initializer disassembly fixture was rejected")
    if not reservation_loss_contract(initializer):
        raise AssertionError("valid reservation-loss disassembly fixture was rejected")
    initializer_mutations = [
        (
            "initializer success branch retarget",
            initializer.replace("if r6 != 0x0 goto +0x7", "if r6 != 0x0 goto +0x6", 1),
        ),
        (
            "114 object stores",
            initializer.replace("*(u64 *)(r6 + 0x378) = r7\n", "", 1),
        ),
        (
            "116 object stores",
            initializer.replace(
                "     127:\tcall 0x84",
                "     127:\t*(u64 *)(r6 + 0x398) = r7\n     128:\tcall 0x84",
                1,
            ),
        ),
        (
            "narrow object spill",
            initializer.replace(
                "*(u64 *)(r6 + 0x38) = r7",
                "*(u32 *)(r6 + 0x38) = r7",
                1,
            ),
        ),
        (
            "initializer back edge",
            initializer.replace("*(u64 *)(r6 + 0x38) = r7", "goto -0x1", 1),
        ),
        (
            "premature object read",
            initializer.replace(
                "*(u64 *)(r6 + 0x38) = r7",
                "r1 = *(u64 *)(r6 + 0x38)",
                1,
            ),
        ),
        (
            "premature object submit",
            initializer.replace("*(u64 *)(r6 + 0x38) = r7", "call 0x84", 1),
        ),
    ]
    for label, mutation in initializer_mutations:
        _reject(lambda mutation=mutation: initializer_regions(mutation), label)
    _reject(
        lambda: reservation_loss_contract(
            initializer.replace("R_BPF_64_64\tCOUNTERS", "R_BPF_64_64\tNOT_COUNTERS", 1)
        )
        or fail("ring-reservation loss path accepted without counter zero"),
        "ring-reservation loss counter",
    )

    pause = _pause_disassembly()
    if not pause_object_contract(pause):
        raise AssertionError("valid pause disassembly fixture was rejected")
    for label, mutation in [
        (
            "object helper between CAS and winner timestamp",
            pause.replace("      10:\tcall 0x5\n      11:\tr1 = 0x13", "      10:\tcall 0x7\n      11:\tcall 0x5", 1),
        ),
        ("missing object timestamp", pause.replace("      10:\tcall 0x5", "      10:\tr1 = 0x0", 1)),
        ("post-signal object helper", pause.replace("      13:\t*(u64 *)(r6 + 0x0) = r7", "      13:\tcall 0x7", 1)),
        ("post-signal object back edge", pause.replace("      14:\t*(u64 *)(r6 + 0x8) = r7", "      14:\tgoto -0x2", 1)),
    ]:
        if pause_object_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")

    _owned_self_test()
    _counter_writeback_self_test()
    classifier_counter = [("emit_export", 0), ("function_list_entry", 1),
                          ("interface_list_return", 2), ("dl_debug_state", 3),
                          ("dl_debug_state", 4), ("interface_entry", 2)]
    assert counter_ownership_contract(classifier_counter)
    classifier_counter[-1] = ("interface_entry", 3)
    assert not counter_ownership_contract(classifier_counter)
    classifier_counter[-1] = ("unrelated_function", 2)
    assert not counter_ownership_contract(classifier_counter)
    extra_cas = pause + "\n0000000000100000 <p11_owner_fixture>:\n 131072: r0 = cmpxchg_64(r1 + 0x0, r0, r3)\n 131073: exit"
    assert pause_object_contract(extra_cas)
    assert not pause_object_contract(extra_cas.replace("131073: exit", "131073: call 0x6d\n 131074: exit"))
    gate_prologue = ("\n0000000000200000 <gated_emit_export>:\n"
                     " 131076: r1 = 0x0 ll\n"
                     "\t\t0000000000000000:  R_BPF_64_64\tSTOP_GATE\n"
                     " 131078: call 0x1\n"
                     " 131079: r1 = r0\n"
                     " 131080: r0 = cmpxchg_64(r1 + 0x0, r0, r7)\n"
                     " 131081: exit")
    assert pause_object_contract(pause + gate_prologue)
    gate_block = pause.replace("0000000000000000 <pause_emit_export>:",
                               "0000000000000000 <pause_emit_export>:\n"
                               " 131082: r1 = 0x0 ll\n"
                               "\t\t0000000000000000:  R_BPF_64_64\tSTOP_GATE\n"
                               " 131084: call 0x1\n"
                               " 131085: r1 = r0\n"
                               " 131086: r0 = cmpxchg_64(r1 + 0x0, r0, r7)", 1)
    assert pause_object_contract(gate_block)
    unknown_block = pause.replace("R_BPF_64_64\tPAUSE_PIDS",
                                  "R_BPF_64_64\tEVIDENCE", 1)
    assert not pause_object_contract(unknown_block)
    second_pause = pause.replace("       4:\tr0 = cmpxchg_64(r1 + 0x0, r0, r3)",
                                 "       4:\tr0 = cmpxchg_64(r1 + 0x0, r0, r3)\n"
                                 " 131087: r0 = cmpxchg_64(r1 + 0x0, r0, r3)", 1)
    assert not pause_object_contract(second_pause)

    manifest = test_manifest(Path("/canonical/main.rs"), "default", good)
    _reject(
        lambda: manifest_contract(
            manifest,
            Path("/canonical/main.rs"),
            good.replace("fn unrelated()", "fn unrelated_changed()"),
            "default",
        ),
        "source digest mismatch",
    )
    wrong_region_digest = copy.deepcopy(manifest)
    wrong_region_digest["source"]["initializer_region_sha256"] = "0" * 64
    _reject(
        lambda: manifest_contract(
            wrong_region_digest,
            Path("/canonical/main.rs"),
            good,
            "default",
        ),
        "initializer-region digest mismatch",
    )
    wrong_inventory = copy.deepcopy(manifest)
    wrong_inventory["expected"]["inventory"]["programs"].remove("dl_debug_state")
    _reject(
        lambda: manifest_contract(
            wrong_inventory,
            Path("/canonical/main.rs"),
            good,
            "default",
        ),
        "exact inventory mismatch",
    )
    _reject(
        lambda: validate_manifest_output(
            Path("/canonical/main.rs"), Path("/canonical/main.rs")
        ),
        "manifest output overwrites canonical source",
    )
    print("live discovery source mutations rejected: OK")
    print("live discovery object mutations rejected: OK")
    print("unrelated memset positive control: OK")
    print("check-live-discovery-object self-test: OK")


def canonical_source(path):
    expected = Path(__file__).resolve().parents[1] / "crates/ebpf/src/main.rs"
    expected = expected.resolve(strict=True)
    if not path.is_absolute() or path != expected:
        fail(f"source must be canonical {expected}")
    return expected


def validate_manifest_output(source_path, output_path):
    aliases_source = output_path.resolve() == source_path.resolve()
    if output_path.exists():
        aliases_source = aliases_source or output_path.samefile(source_path)
    if aliases_source:
        fail("manifest output must not overwrite the canonical source")


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-test-manifest", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--variant", choices=VARIANTS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--object", type=Path)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        if any(
            value is not None
            for value in (args.source, args.variant, args.output, args.object, args.manifest)
        ) or args.write_test_manifest:
            fail("--self-test accepts no other arguments")
        self_test()
        return

    if args.write_test_manifest:
        if not all((args.source, args.variant, args.output)) or any(
            (args.object, args.manifest)
        ):
            fail("manifest mode requires exactly --source --variant --output")
        source_path = canonical_source(args.source)
        validate_manifest_output(source_path, args.output)
        source = source_path.read_text()
        manifest = test_manifest(source_path, args.variant, source)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"wrote {args.variant} source-bound manifest {args.output}")
        return

    if not all((args.source, args.object, args.manifest)) or any(
        (args.variant, args.output)
    ):
        fail("check mode requires exactly --source --object --manifest")
    source_path = canonical_source(args.source)
    source = source_path.read_text()
    manifest = json.loads(args.manifest.read_text())
    variant = manifest.get("variant")
    manifest_contract(manifest, source_path, source, variant)
    # Binding is complete before the object is opened or disassembled.
    facts = inspect_object(args.object, source, variant)
    object_contract(facts, variant)
    print(
        f"live discovery object: variant={variant} maps={len(facts['maps'])} "
        f"programs={len(facts['programs'])} initializer-copies=3 OK"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"check-live-discovery-object: {error}", file=sys.stderr)
        sys.exit(1)
