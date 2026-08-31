#!/usr/bin/env python3
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
INITIALIZER_BEGIN = "// TASK5_DISCOVERY_INITIALIZER_BEGIN"
INITIALIZER_END = "// TASK5_DISCOVERY_INITIALIZER_END"
PAUSE_BEGIN = "// TASK5_PAUSE_WRITER_BEGIN"
PAUSE_END = "// TASK5_PAUSE_WRITER_END"
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
    if len(indices) != 112:
        fail(f"initializer has {len(indices)} stores, expected 112")
    if indices != list(range(112)):
        fail("initializer indices must be the ordered exact set 0..111")
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
        "DISCOVERY_STATE.remove(&key)",
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
        "interface_continuation_pack(count, 0)",
        "active_count == 0",
        "state.arg0 == 0",
        "checked_add((active_count - 1) * 24)",
        "DISCOVERY_STATE\n        .insert(&key, &continuation, aya_ebpf::bindings::BPF_EXIST as u64)",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
    ]:
        if marker not in return_region:
            fail(f"interface-list return contract missing {marker!r}")
    for marker in [
        "export_state_key(&ctx)",
        "interface_continuation_unpack(state.arg1)",
        "DISCOVERY_STATE.get(&key)",
        "DISCOVERY_INTERFACES",
        "interface_continuation_next(state.arg1)",
        "DISCOVERY_STATE\n        .insert(&key, &continuation, aya_ebpf::bindings::BPF_EXIST as u64)",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
        "finish_export_state(&key)",
    ]:
        if marker not in worker_region:
            fail(f"interface-list worker contract missing {marker!r}")


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
        "record_size": 896,
        "record_align": 8,
        "counter_indices": COUNTERS,
        "initializer_words": 112,
        "initializer_indices": list(range(112)),
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
            if "r2 = 0x380" not in size_window:
                fail(f"{function}: discovery reservation is not 896 bytes")

            candidate = None
            for start in range(reserve + 1, len(lines) - 111):
                first = OBJECT_STORE.search(lines[start])
                if not first or int(first.group("offset"), 16) != 0:
                    continue
                base, zero = first.group("base"), first.group("zero")
                stores = []
                for offset, line in enumerate(lines[start : start + 112]):
                    store = OBJECT_STORE.search(line)
                    if (
                        not store
                        or store.group("base") != base
                        or store.group("zero") != zero
                        or int(store.group("offset"), 16) != offset * 8
                    ):
                        break
                    stores.append(offset * 8)
                if len(stores) == 112:
                    candidate = (start, start + 112, base, zero, stores)
                    break
            if candidate is None:
                fail(f"{function}: missing exact 112-store initializer")
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
                rf"\*\(u64 \*\)\(r{base} \+ 0x(?:38[0-9a-f]|3[9a-f][0-9a-f]|[4-9a-f][0-9a-f]{{2,}})\) = r{zero}\b",
                trailing,
            ):
                fail(f"{function}: initializer writes beyond the 896-byte record")
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
            parsed.append((int(match.group(1)), match.group(2)))
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


def pause_object_contract(disassembly):
    signal_blocks = []
    total_cas = 0
    total_signals = 0
    for function, lines in function_blocks(disassembly).items():
        cas = [index for index, line in enumerate(lines) if "cmpxchg_64" in line]
        signals = [
            index for index, line in enumerate(lines) if re.search(r"call 0x6d\b", line)
        ]
        total_cas += len(cas)
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
    starts = {
        name: instruction_entries(lines)[0][1]
        for name, lines in blocks.items()
        if instruction_entries(lines)
    }
    by_pc = {pc: name for name, pc in starts.items()}
    calls = []
    for function, lines in blocks.items():
        for line_index, pc, text in instruction_entries(lines):
            match = re.search(r"\bcall (?P<sign>-?)0x(?P<value>[0-9a-f]+)\b", text)
            if not match:
                continue
            value = int(match.group("value"), 16)
            if match.group("sign"):
                candidates = [pc + 1 - value]
            elif value >= 0x10:
                candidates = [value + 1, pc + 1 + value]
            else:
                candidates = []
            targets = {by_pc[candidate] for candidate in candidates if candidate in by_pc}
            for target in targets:
                calls.append((function, line_index, pc, target))
    return calls


def known_tail_relocations(lines):
    allowed_maps = {"COUNTERS", "DISCOVERY_STATE", "TAIL_CALLS"}
    return all(
        (kind == "64" and target in allowed_maps)
        or (kind == "32" and target in {".text", "memset"})
        for _, kind, target in relocation_targets(lines)
    )


def has_counter_update_after(lines, start_pc, graph):
    entries = instruction_entries(lines)
    for _, lookup_pc, _ in map_call_sites(lines, "COUNTERS", helper=1):
        if lookup_pc not in nodes_on_paths(graph, start_pc, lookup_pc):
            continue
        for _, load_pc, load_text in entries:
            load = re.search(
                r"\br(?P<value>\d+) = \*\(u64 \*\)\(r0 \+ 0x0\)$", load_text
            )
            if not load or load_pc not in nodes_on_paths(graph, lookup_pc, load_pc):
                continue
            value = load.group("value")
            increment_pc = next(
                (
                    pc
                    for _, pc, text in entries
                    if re.search(rf"\br{value} \+= 0x1$", text)
                    and pc in nodes_on_paths(graph, load_pc, pc)
                ),
                None,
            )
            if increment_pc is None:
                continue
            if any(
                re.search(rf"\*\(u64 \*\)\(r0 \+ 0x0\) = r{value}$", text)
                and pc in nodes_on_paths(graph, increment_pc, pc)
                for _, pc, text in entries
            ):
                return True
    return False


def tail_cleanup_contract(lines, tail_pc, graph):
    reachable_pcs = reachable(graph, [tail_pc])
    cleanup_sites = [
        pc
        for _, pc, _ in map_call_sites(lines, "DISCOVERY_STATE", helper=3)
        if pc in reachable_pcs
    ]
    return any(has_counter_update_after(lines, pc, graph) for pc in cleanup_sites)


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
    if not map_call_sites(return_lines, "DISCOVERY_STATE", helper=2):
        return False
    if not map_call_sites(worker_lines, "DISCOVERY_STATE", helper=2):
        return False
    for lines, graph in ((return_lines, return_graph), (worker_lines, worker_graph)):
        tails = map_call_sites(lines, "TAIL_CALLS", helper=0xC)
        if len(tails) != 1:
            return False
        tail_index, tail_pc, _ = tails[0]
        preceding = [
            text
            for line_index, _, text in instruction_entries(lines)
            if line_index < tail_index and tail_index - line_index <= 6
        ]
        if not any(re.search(r"\br2 = 0x0\b", text) for text in preceding):
            return False
        if not tail_cleanup_contract(lines, tail_pc, graph):
            return False
    return_block = "\n".join(return_lines)
    worker_block = "\n".join(worker_lines)
    if not re.search(r"\br\d+ = \*\(u64 \*\)\(r0 \+ 0x8\)", return_block):
        return False
    if not re.search(r"\bif r\d+ == 0x0 goto", return_block):
        return False
    if not re.search(r"\bif r\d+ > r\d+ goto", return_block):
        return False
    if not re.search(r"\br\d+ = 0x2\b", return_block):
        return False
    if not re.search(r"\bcall 0x2\b", return_block):
        return False
    if not re.search(r"\br\d+ = 0x2\b", worker_block):
        return False
    if not re.search(r"\bcall 0x2\b", worker_block):
        return False
    if not re.search(r"\bcall 0xae\b", worker_block):
        return False
    if not (
        re.search(r"\bif r\d+ > 0xffffffffff goto", worker_block)
        or (
            re.search(r"\br\d+ = 0xffffffffff\b", worker_block)
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
    loader = "\n".join(blocks.get("dl_debug_state", []))
    if len(re.findall(r"\bcall 0xae\b", loader)) != 1:
        return False
    if not all(
        marker in loader for marker in ("&= 0x100", "&= -0x200", "s>>= 0x9")
    ):
        return False
    export_programs = (
        "function_list_entry",
        "function_list_return",
        "interface_list_entry",
        "interface_list_return",
        "interface_list_worker",
        "interface_entry",
        "interface_return",
    )
    for name in export_programs:
        block = "\n".join(blocks.get(name, []))
        if (
            len(re.findall(r"\bcall 0xae\b", block)) != 2
            or "= -0x100000000 ll" not in block
            or "= -0xffffffff ll" not in block
            or (
                name != "interface_list_worker"
                and re.search(r"(?:s)?>>= 0x20\b", block)
            )
        ):
            return False
    return not re.search(r"(?:s)?>>= 0x20\b", loader)


def finite_counter_key(lines, relocation):
    key_store = re.compile(
        r"\*\(u32 \*\)\(r10 - 0x[0-9a-f]+\) = r(?P<register>\d+)"
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
            counter_instructions = (
                instructions(failure[counters[0] :]) if len(counters) == 1 else []
            )
            lookup = next(
                (
                    index
                    for index, (_, text) in enumerate(counter_instructions)
                    if re.search(r"\bcall 0x1\b", text)
                ),
                None,
            )
            update = (
                [text for _, text in counter_instructions[lookup + 1 : lookup + 5]]
                if lookup is not None
                else []
            )
            loaded = (
                re.search(r"\br(?P<value>\d+) = \*\(u64 \*\)\(r0 \+ 0x0\)\s*$", update[1])
                if len(update) == 4
                and re.search(r"\bif r0 == 0x0 goto ", update[0])
                else None
            )
            if (
                len(counters) != 1
                or finite_counter_key(lines, branch + 1 + counters[0]) != 0
                or loaded is None
                or not re.search(
                    rf"\br{loaded.group('value')} \+= 0x1\s*$", update[2]
                )
                or not re.search(
                    rf"\*\(u64 \*\)\(r0 \+ 0x0\) = r{loaded.group('value')}\s*$",
                    update[3],
                )
            ):
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
        block = "\n".join(blocks.get(name, []))
        if (
            len(re.findall(r"R_BPF_64_64\s+DISCOVERY_STATE\s*$", block, re.MULTILINE))
            < 2
            or "call 0x2" not in block
            or "call 0x3" not in block
            or not re.search(r"\br4 = 0x1\b", block)
            or not re.search(r"R_BPF_64_64\s+COUNTERS\s*$", block, re.MULTILINE)
        ):
            return False
    for name in return_names:
        block = "\n".join(blocks.get(name, []))
        if (
            len(re.findall(r"R_BPF_64_64\s+DISCOVERY_STATE\s*$", block, re.MULTILINE))
            < 3
            or "call 0x1" not in block
            or len(re.findall(r"\bcall 0x3\b", block)) < 2
            or not re.search(r"R_BPF_64_64\s+COUNTERS\s*$", block, re.MULTILINE)
        ):
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
        2: ("emit_export", "interface_list_return"),
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
    maps, programs, _ = checker["inspect"](str(path))
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
        "cmpxchg_count": disassembly.count("cmpxchg_64"),
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
        (facts["record_size"] == 896, "record size differs"),
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
                (region["offsets"] == list(range(0, 896, 8)), "initializer offsets differ"),
            ]
        )
    for okay, message in checks:
        if not okay:
            fail(message)


def _initializer(stores=range(112)):
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


def _source(stores=range(112)):
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
        "       3:\tr2 = 0x380",
        "       4:\tr3 = 0x0",
        "       5:\tcall 0x83",
        "       6:\tr6 = r0",
        "       7:\tif r6 != 0x0 goto +0x7",
        "       8:\t*(u32 *)(r10 - 0x4) = r7",
        "\t\t0000000000000040:  R_BPF_64_64\tCOUNTERS",
        "       9:\tcall 0x1",
        "      10:\tif r0 == 0x0 goto +0x74",
        "      11:\tr1 = *(u64 *)(r0 + 0x0)",
        "      12:\tr1 += 0x1",
        "      13:\t*(u64 *)(r0 + 0x0) = r1",
        "      14:\tgoto +0x70",
    ]
    lines.extend(
        f"{15 + index:8}:\t*(u64 *)(r6 + 0x{index * 8:x}) = r7"
        for index in range(112)
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
       0:\tr0 = cmpxchg_64(r1 + 0x0, r0, r3)
       1:\tif r0 == 0x1 goto +0x4
       2:\tr7 = -0x8000000000000000 ll
       3:\tif r0 == 0x2 goto +0x0
       4:\tcall 0x5
       5:\tgoto +0x7
       6:\tcall 0x5
       7:\tr1 = 0x13
       8:\tcall 0x6d
       9:\t*(u64 *)(r6 + 0x0) = r7
      10:\t*(u64 *)(r6 + 0x8) = r7
      11:\t*(u64 *)(r6 + 0x364) = r7
      12:\t*(u64 *)(r6 + 0x378) = r7
      13:\tcall 0x84
      14:\texit"""
    return "\n".join(block.format(index=index) for index in range(3))


def _cookie_disassembly():
    loader = """0000000000000000 <dl_debug_state>:
       0:\tcall 0xae
       1:\tr1 &= 0x100
       2:\tr1 &= -0x200
       3:\tr1 s>>= 0x9
       4:\texit"""
    export = """0000000000000000 <{name}>:
       0:\tcall 0xae
       1:\tr1 = -0x100000000 ll
       3:\tr1 = -0xffffffff ll
       5:\tcall 0xae
       6:\texit"""
    names = (
        "function_list_entry",
        "function_list_return",
        "interface_list_entry",
        "interface_list_return",
        "interface_entry",
        "interface_return",
    )
    worker = """0000000000001000 <interface_list_worker>:
       0:\tcall 0xae
       1:\tr1 = -0x100000000 ll
       3:\tr1 = -0xffffffff ll
       5:\tcall 0xae
       6:\texit"""
    return "\n".join([loader] + [export.format(name=name) for name in names] + [worker])


def _bounded_disassembly():
    return """0000000000000000 <fixture_emit_export>:
       0:\tr1 = 0x43
       1:\tr2 = 0x44
       2:\tr3 = 0x5c
       3:\tr4 = 0x68
       4:\tif r1 > r2 goto -0x1
       5:\texit"""


def _tail_disassembly():
    return """0000000000000000 <interface_list_return>:
       0:\tr1 = *(u64 *)(r0 + 0x8)
       1:\tif r1 == 0x0 goto +0x8
       2:\tif r2 == 0x0 goto +0x7
       3:\tif r2 > r3 goto +0x6
		0000000000000020:  R_BPF_64_64\tDISCOVERY_STATE
       4:\tr4 = 0x2
       5:\tcall 0x2
       6:\tr2 = 0x0
		0000000000000038:  R_BPF_64_64\tTAIL_CALLS
       7:\tcall 0xc
		0000000000000048:  R_BPF_64_64\tDISCOVERY_STATE
       8:\tcall 0x3
      9:\tr1 = 0x1
		0000000000000058:  R_BPF_64_64\tCOUNTERS
      10:\tcall 0x1
      11:\tif r0 == 0x0 goto +0x3
      12:\tr1 = *(u64 *)(r0 + 0x0)
      13:\tr1 += 0x1
      14:\t*(u64 *)(r0 + 0x0) = r1
      15:\texit
0000000000000060 <interface_list_worker>:
      12:\tcall 0xae
      13:\tcall 0x1
		0000000000000070:  R_BPF_64_64\tDISCOVERY_STATE
		0000000000000080:  R_BPF_64_64\tDISCOVERY_STATE
      14:\tif r0 == 0x0 goto +0xd
      15:\tif r8 > 0xffffffffff goto +0xc
      16:\tr1 = 0x10
      17:\tif r1 > 0xf goto +0xa
      18:\tif r1 >= r2 goto +0x9
       19:\tcall 0x1c
		0000000000000090:  R_BPF_64_32\t.text
      20:\tr1 += 0x1
      21:\tr4 = 0x2
		00000000000000a0:  R_BPF_64_64\tDISCOVERY_STATE
      22:\tcall 0x2
      23:\tr2 = 0x0
		00000000000000b8:  R_BPF_64_64\tTAIL_CALLS
      24:\tcall 0xc
		00000000000000c8:  R_BPF_64_64\tDISCOVERY_STATE
      25:\tcall 0x3
		00000000000000d8:  R_BPF_64_64\tCOUNTERS
      26:\tcall 0x1
      27:\tif r0 == 0x0 goto +0x3
      28:\tr5 = *(u64 *)(r0 + 0x0)
      29:\tr5 += 0x1
      30:\t*(u64 *)(r0 + 0x0) = r5
      31:\texit
00000000000000d0 <classify_direct_interface>:
      29:\tcall 0x1d
00000000000000e0 <emit_export>:
      30:\tr1 = 0x43
      31:\tr2 = 0x44
      32:\tr3 = 0x5c
      33:\tr4 = 0x68
      34:\tif r1 > r2 goto -0x1
      35:\texit"""


def _producer_disassembly():
    loader_tail = """     128:\tr1 = 0x4
     129:\tr7 = -0x8000000000000000 ll
     131:\tif r0 == 0x2 goto +0x0
     132:\tif r0 == 0x2 goto +0x0
\t\t0000000000000400:  R_BPF_64_64\tPAUSE_PIDS"""
    entry = """0000000000000000 <{name}>:
       0:\tr4 = 0x1
\t\t0000000000000000:  R_BPF_64_64\tDISCOVERY_STATE
       1:\tcall 0x2
\t\t0000000000000008:  R_BPF_64_64\tDISCOVERY_STATE
       2:\tcall 0x3
\t\t0000000000000010:  R_BPF_64_64\tCOUNTERS
       3:\texit"""
    returned = """0000000000000000 <{name}>:
\t\t0000000000000000:  R_BPF_64_64\tDISCOVERY_STATE
       0:\tcall 0x1
\t\t0000000000000008:  R_BPF_64_64\tDISCOVERY_STATE
       1:\tcall 0x3
\t\t0000000000000010:  R_BPF_64_64\tDISCOVERY_STATE
       2:\tcall 0x3
\t\t0000000000000018:  R_BPF_64_64\tCOUNTERS
       3:\tcall 0x70
       4:\texit"""
    parts = [_initializer_disassembly(loader_tail)]
    parts.extend(
        entry.format(name=name)
        for name in ("function_list_entry", "interface_list_entry", "interface_entry")
    )
    parts.extend(
        returned.format(name=name)
        for name in ("function_list_return", "interface_list_return", "interface_return")
    )
    return "\n".join(parts)


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
            "111 object stores",
            initializer.replace("*(u64 *)(r6 + 0x378) = r7\n", "", 1),
        ),
        (
            "113 object stores",
            initializer.replace(
                "     127:\tcall 0x84",
                "     127:\t*(u64 *)(r6 + 0x380) = r7\n     128:\tcall 0x84",
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
            pause.replace("       6:\tcall 0x5\n       7:\tr1 = 0x13", "       6:\tcall 0x7\n       7:\tcall 0x5", 1),
        ),
        ("missing object timestamp", pause.replace("       6:\tcall 0x5", "       6:\tr1 = 0x0", 1)),
        ("post-signal object helper", pause.replace("       9:\t*(u64 *)(r6 + 0x0) = r7", "       9:\tcall 0x7", 1)),
        ("post-signal object back edge", pause.replace("      10:\t*(u64 *)(r6 + 0x8) = r7", "      10:\tgoto -0x2", 1)),
    ]:
        if pause_object_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")

    cookie = _cookie_disassembly()
    if not cookie_object_contract(cookie):
        raise AssertionError("valid cookie disassembly fixture was rejected")
    if cookie_object_contract(cookie.replace("       0:\tcall 0xae", "       0:\tcall 0x5", 1)):
        raise AssertionError("mutation accepted: missing loader cookie")
    if cookie_object_contract(
        cookie.replace("       5:\tcall 0xae", "       5:\tr1 >>= 0x20\n       6:\tcall 0xae", 1)
    ):
        raise AssertionError("mutation accepted: export cookie slot collision")

    bounded = _bounded_disassembly()
    if not table_bounds_object_contract(bounded):
        raise AssertionError("valid table-bounds disassembly fixture was rejected")
    for label, mutation in [
        ("104-slot cap", bounded.replace("r4 = 0x68", "r4 = 0x69")),
    ]:
        if table_bounds_object_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")

    tail = _tail_disassembly()
    if not interface_tail_contract(tail):
        raise AssertionError("valid interface-list tail fixture was rejected")
    for label, mutation in [
        (
            "return counter increment skipped",
            tail.replace(
                "      11:\tif r0 == 0x0 goto +0x3\n"
                "      12:\tr1 = *(u64 *)(r0 + 0x0)\n"
                "      13:\tr1 += 0x1\n"
                "      14:\t*(u64 *)(r0 + 0x0) = r1\n"
                "      15:\texit",
                "      11:\tif r0 == 0x0 goto +0x4\n"
                "      12:\tr1 = *(u64 *)(r0 + 0x0)\n"
                "      13:\tgoto +0x1\n"
                "      14:\tr1 += 0x1\n"
                "      15:\t*(u64 *)(r0 + 0x0) = r1\n"
                "      16:\texit",
                1,
            ),
        ),
        (
            "return counter writeback removed",
            tail.replace("      14:\t*(u64 *)(r0 + 0x0) = r1", "      14:\tr2 = r1", 1),
        ),
        (
            "worker counter increment skipped",
            tail.replace(
                "      27:\tif r0 == 0x0 goto +0x3\n"
                "      28:\tr5 = *(u64 *)(r0 + 0x0)\n"
                "      29:\tr5 += 0x1\n"
                "      30:\t*(u64 *)(r0 + 0x0) = r5\n"
                "      31:\texit",
                "      27:\tif r0 == 0x0 goto +0x4\n"
                "      28:\tr5 = *(u64 *)(r0 + 0x0)\n"
                "      29:\tgoto +0x1\n"
                "      30:\tr5 += 0x1\n"
                "      31:\t*(u64 *)(r0 + 0x0) = r5\n"
                "      32:\texit",
                1,
            ),
        ),
        (
            "worker counter writeback removed",
            tail.replace("      30:\t*(u64 *)(r0 + 0x0) = r5", "      30:\tr2 = r5", 1),
        ),
    ]:
        if interface_tail_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")
    for label, mutation in [
        ("return tail slot", tail.replace("r2 = 0x0", "r2 = 0x1", 1)),
        ("worker tail slot", tail.replace("      23:\tr2 = 0x0", "      23:\tr2 = 0x1", 1)),
        ("return BPF_EXIST", tail.replace("       4:\tr4 = 0x2", "       4:\tr4 = 0x1", 1)),
        ("worker BPF_EXIST", tail.replace("      21:\tr4 = 0x2", "      21:\tr4 = 0x1", 1)),
        ("return fallthrough cleanup", tail.replace("       8:\tcall 0x3\n", "", 1)),
        ("worker fallthrough cleanup", tail.replace("      25:\tcall 0x3\n", "", 1)),
        ("worker cookie", tail.replace("      12:\tcall 0xae\n", "", 1)),
        ("worker index cap", tail.replace("if r1 > 0xf", "if r1 > 0x10", 1)),
        ("worker active-count gate", tail.replace("if r1 >= r2", "if r1 > r2", 1)),
        ("worker classifier", tail.replace("      19:\tcall 0x1c", "      19:\tcall 0x1b", 1)),
        ("duplicated classifier", tail.replace("      19:\tcall 0x1c", "      19:\tcall 0x1c\n      19:\tcall 0x1c", 1)),
        ("worker progression", tail.replace("      20:\tr1 += 0x1", "      20:\tr1 += 0x0", 1)),
        ("worker counter", tail.replace("      29:\tr5 += 0x1", "      29:\tr5 += 0x0", 1)),
    ]:
        if interface_tail_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")

    producer = _producer_disassembly()
    if not producer_object_contract(producer):
        raise AssertionError("valid producer-edge disassembly fixture was rejected")
    for label, mutation in [
        ("state insert no-overwrite", producer.replace("       0:\tr4 = 0x1", "       0:\tr4 = 0x0", 1)),
        ("state insertion cleanup", producer.replace("       2:\tcall 0x3", "       2:\tcall 0x2", 1)),
        ("state return removal", producer.replace("       1:\tcall 0x3", "       1:\tcall 0x2", 1)),
        ("bounded-read failure counter", producer.replace("call 0x70", "call 0x71")),
        ("invalid-loader marker", producer.replace("     128:\tr1 = 0x4", "     128:\tr1 = 0x0")),
        ("coalesced pause sentinel", producer.replace("r7 = -0x8000000000000000 ll", "r7 = 0x0", 1)),
        ("ring-reservation loss counter", producer.replace("R_BPF_64_64\tCOUNTERS", "R_BPF_64_64\tNOT_COUNTERS", 1)),
        ("ring-reservation loss increment", producer.replace("      12:\tr1 += 0x1", "      12:\tr1 += 0x0", 1)),
        ("ring-reservation loss store", producer.replace("      13:\t*(u64 *)(r0 + 0x0) = r1", "      13:\tr2 = r1", 1)),
    ]:
        if producer_object_contract(mutation):
            raise AssertionError(f"mutation accepted: {label}")

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
