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
    timestamp = pause.rfind("helpers::bpf_ktime_get_ns()", cas, signal)
    if timestamp < cas:
        fail("pause winner timestamp must follow CAS and precede SIGSTOP")
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
        "while interface_index < 16",
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
    return {
        "record_size": 896,
        "record_align": 8,
        "counter_indices": COUNTERS,
        "initializer_words": 112,
        "initializer_indices": list(range(112)),
        "inventory": f"p11scope-live-discovery-{variant}/v1",
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
            start, _, base, zero, stores = candidate
            prefix = "\n".join(lines[:start])
            if not re.search(rf"r{zero} = 0x0\b", prefix):
                fail(f"{function}: initializer source register is not proven zero")
            before_init = "\n".join(lines[reserve + 1 : start])
            if re.search(rf"= \*\([^)]*\)\(r{base} \+", before_init):
                fail(f"{function}: record field read precedes initialization")
            if "call 0x84" in before_init:
                fail(f"{function}: record submit precedes initialization")
            regions.append(
                {
                    "function": function,
                    "offsets": stores,
                    "narrow": False,
                    "back_edge": False,
                    "premature_read": False,
                    "premature_submit": False,
                }
            )
    return regions


def instructions(lines):
    parsed = []
    for line in lines:
        match = re.match(r"\s*(\d+):\s+(.*)", line)
        if match:
            parsed.append((int(match.group(1)), match.group(2)))
    return parsed


def winner_finishes_without_helper(lines, signal_index):
    insns = instructions(lines)
    signal_pc = int(re.match(r"\s*(\d+):", lines[signal_index]).group(1))
    positions = {pc: index for index, (pc, _) in enumerate(insns)}
    index = positions[signal_pc] + 1
    visited = set()
    stores = {}
    while index < len(insns):
        pc, text = insns[index]
        if pc in visited:
            return False
        visited.add(pc)
        if re.search(r"\bcall 0x84\b", text):
            bases = [
                base
                for base, offsets in stores.items()
                if {0, 8, 0x364, 0x378}.issubset(offsets)
            ]
            return bool(bases)
        if re.search(r"\bcall 0x", text):
            return False
        store = ANY_OBJECT_STORE.search(text)
        if store:
            stores.setdefault(store.group("base"), set()).add(
                int(store.group("offset"), 16)
            )
        if re.search(r"\bif .*\bgoto [+-]0x", text):
            return False
        branch = re.search(r"\bgoto (?P<sign>[+-])0x(?P<distance>[0-9a-f]+)\b", text)
        if branch:
            distance = int(branch.group("distance"), 16)
            target = pc + 1 + (distance if branch.group("sign") == "+" else -distance)
            if target not in positions:
                return False
            index = positions[target]
            continue
        if "goto " in text:
            return False
        index += 1
    return False


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
        between = "\n".join(lines[cas[0] : signals[0]])
        timestamp = between.rfind("call 0x5")
        if timestamp < 0 or "call 0x" in between[timestamp + len("call 0x5") :]:
            return False
        if not winner_finishes_without_helper(lines, signals[0]):
            return False
    return True


def bounded_object_contract(disassembly):
    blocks = function_blocks(disassembly)
    export = next(
        ("\n".join(lines) for name, lines in blocks.items() if name.endswith("emit_export")),
        "",
    )
    listed = "\n".join(blocks.get("interface_list_return", []))
    export_bounds = all(
        re.search(rf"\br\d+ = 0x{bound:x}\b", export)
        for bound in (67, 68, 92, 104)
    ) and bool(re.search(r"\bif r\d+ > r\d+ goto -0x", export))
    interface_bounds = bool(re.search(r"\bif r(?P<index>\d+) > 0xe goto \+0x", listed))
    if interface_bounds:
        index = re.search(r"\bif r(?P<index>\d+) > 0xe goto \+0x", listed).group(
            "index"
        )
        interface_bounds = bool(
            re.search(rf"\br{index} \+= 0x1\b", listed)
            and re.search(r"\bgoto -0x", listed)
        )
    return export_bounds and interface_bounds


def object_counter_uses(disassembly):
    uses = []
    key_store = re.compile(
        r"\*\(u32 \*\)\(r10 - 0x[0-9a-f]+\) = r(?P<register>\d+)"
    )
    for function, lines in function_blocks(disassembly).items():
        for relocation in [
            index
            for index, line in enumerate(lines)
            if re.search(r"R_BPF_64_64\s+COUNTERS\s*$", line)
        ]:
            stored = next(
                (
                    (index, match.group("register"))
                    for index in range(relocation - 1, max(-1, relocation - 12), -1)
                    if (match := key_store.search(lines[index]))
                ),
                None,
            )
            if stored is None:
                fail(f"{function}: COUNTERS lookup has no finite u32 stack key")
            store_index, register = stored
            assignment = re.compile(
                rf"\br{register} = (?P<sign>-?)0x(?P<value>[0-9a-f]+)\b"
            )
            key = None
            for index in range(store_index - 1, -1, -1):
                if match := assignment.search(lines[index]):
                    value = int(match.group("value"), 16)
                    key = -value if match.group("sign") else value
                    break
                if re.search(rf"\br{register} =", lines[index]):
                    break
            if key is None:
                fail(f"{function}: COUNTERS key register is not a direct finite constant")
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
    maps, programs, symbols = checker["inspect"](str(path))
    disassembly = subprocess.run(
        ["llvm-objdump", "-dr", str(path)],
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
        "symbols": symbols,
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
        "cookie_namespaces_distinct": "fn loader_cookie_of(" in source
        and "cookie_slot(cookie_of(ctx))" in source,
        "bounded": "while pointer_index < 104" in source
        and "while interface_index < 16" in source
        and bounded_object_contract(disassembly),
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
        (facts["bounded"], "bounded 104/16 source loops are absent"),
        (facts["cmpxchg_count"] == 3, "cmpxchg_64 inventory differs"),
        (facts["signal_count"] == 3, "signal helper inventory differs"),
        (facts["pause_order"], "CAS/timestamp/signal/result/submit order differs"),
        (len(facts["initializer_regions"]) == 3, "initializer copy inventory differs"),
    ]
    for region in facts["initializer_regions"]:
        checks.extend(
            [
                (region["offsets"] == list(range(0, 896, 8)), "initializer offsets differ"),
                (not region["narrow"], "initializer contains a narrow store"),
                (not region["back_edge"], "initializer contains a back edge"),
                (not region["premature_read"], "initializer has a premature field read"),
                (not region["premature_submit"], "initializer has a premature submit"),
            ]
        )
    for okay, message in checks:
        if not okay:
            fail(message)


def synthetic_object_facts(variant):
    maps, programs = expected_inventory(variant)
    region = {
        "function": "synthetic",
        "offsets": list(range(0, 896, 8)),
        "narrow": False,
        "back_edge": False,
        "premature_read": False,
        "premature_submit": False,
    }
    return {
        "maps": maps,
        "programs": programs,
        "symbols": {"memset"},
        "initializer_regions": [copy.deepcopy(region) for _ in range(3)],
        "record_size": 896,
        "record_align": 8,
        "counter_indices": COUNTERS,
        "counter_ownership": True,
        "cookie_namespaces_distinct": True,
        "bounded": True,
        "cmpxchg_count": 3,
        "signal_count": 3,
        "pause_order": True,
        "unrelated_memset": True,
        "variant": variant,
    }


def object_mutations(facts):
    mutations = []

    def changed(label, mutate):
        value = copy.deepcopy(facts)
        mutate(value)
        mutations.append((label, value))

    changed("111 object stores", lambda value: value["initializer_regions"][0]["offsets"].pop())
    changed("113 object stores", lambda value: value["initializer_regions"][0]["offsets"].append(896))
    changed("duplicate object offset", lambda value: value["initializer_regions"][0]["offsets"].__setitem__(111, 880))
    changed("narrow object spill", lambda value: value["initializer_regions"][0].__setitem__("narrow", True))
    changed("initializer back edge", lambda value: value["initializer_regions"][0].__setitem__("back_edge", True))
    changed("premature object read", lambda value: value["initializer_regions"][0].__setitem__("premature_read", True))
    changed("premature object submit", lambda value: value["initializer_regions"][0].__setitem__("premature_submit", True))
    changed("missing cmpxchg_64", lambda value: value.__setitem__("cmpxchg_count", 2))
    changed("missing signal helper", lambda value: value.__setitem__("signal_count", 2))
    changed("wrong helper ordering", lambda value: value.__setitem__("pause_order", False))
    changed("unbounded object loop", lambda value: value.__setitem__("bounded", False))
    changed("wrong record size", lambda value: value.__setitem__("record_size", 888))
    changed("wrong record alignment", lambda value: value.__setitem__("record_align", 4))
    changed("wrong map flags", lambda value: value["maps"]["PAUSE_PIDS"].__setitem__("flags", 128))
    changed("wrong map size", lambda value: value["maps"]["PID_FILTER"].__setitem__("value_size", 1))
    changed("wrong counter permutation", lambda value: value.__setitem__("counter_indices", {**COUNTERS, "4": "loader_hits"}))
    changed("wrong counter owner", lambda value: value.__setitem__("counter_ownership", False))
    changed("wrong program inventory", lambda value: value["programs"].remove("dl_debug_state"))
    changed("cookie collision", lambda value: value.__setitem__("cookie_namespaces_distinct", False))
    return mutations


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

    facts = synthetic_object_facts("default")
    object_contract(facts, "default")
    for label, mutation in object_mutations(facts):
        _reject(lambda mutation=mutation: object_contract(mutation, "default"), label)

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
