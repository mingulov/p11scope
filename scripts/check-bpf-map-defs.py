#!/usr/bin/env python3
"""Inspect exact map/program policy inventory in a freshly built BPF ELF."""

from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


MAP_FIELDS = ("type", "key_size", "value_size", "max_entries", "flags", "id", "pinning")
MAP_DEFINITION_SIZE = 28


def elf_records(path):
    symbols = subprocess.run(
        ["llvm-readelf", "-sW", path], capture_output=True, text=True, check=True
    ).stdout
    sections = subprocess.run(
        ["llvm-readelf", "-SW", path], capture_output=True, text=True, check=True
    ).stdout
    records = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        try:
            value, size = int(fields[1], 16), int(fields[2])
        except ValueError:
            continue
        records.append((value, size, fields[3], fields[4], fields[5], fields[6], fields[7]))
    indices = {
        match.group(2): int(match.group(1))
        for line in sections.splitlines()
        if (match := re.match(r"\s*\[\s*(\d+)\]\s+(\S+)", line))
    }
    return records, indices


def decode_map_definitions(records, section, data):
    objects = sorted(
        (offset, size, name)
        for offset, size, kind, _, _, symbol_section, name in records
        if kind == "OBJECT" and symbol_section == str(section)
    )
    maps = {}
    cursor = 0
    for offset, size, name in objects:
        if name in maps:
            raise RuntimeError(f"duplicate map symbol name {name}")
        if size != MAP_DEFINITION_SIZE:
            raise RuntimeError(f"{name} map definition size is {size}, expected 28")
        if offset % 4:
            raise RuntimeError(f"misaligned map definition for {name}: offset {offset}")
        if offset != cursor:
            raise RuntimeError(
                f"non-contiguous map definitions before {name}: offset {offset}, expected {cursor}"
            )
        if offset + size > len(data):
            raise RuntimeError(f"truncated map definition for {name}")
        maps[name] = dict(zip(MAP_FIELDS, struct.unpack_from("<7I", data, offset)))
        cursor += size
    if cursor != len(data):
        raise RuntimeError(f"maps section has {len(data) - cursor} trailing bytes")
    return maps


def inspect(path):
    records, sections = elf_records(path)
    if "maps" not in sections:
        raise RuntimeError(f"{path} has no maps section")
    with tempfile.TemporaryDirectory() as directory:
        raw = Path(directory) / "maps.bin"
        subprocess.run(["llvm-objcopy", "--dump-section", f"maps={raw}", path], check=True)
        data = raw.read_bytes()
    maps = decode_map_definitions(records, sections["maps"], data)
    program_sections = {
        index for name, index in sections.items()
        if name in {"uprobe", "uretprobe"} or name.startswith("tracepoint/")
    }
    programs = {
        name for _, _, kind, bind, visibility, section, name in records
        if kind == "FUNC" and bind == "GLOBAL" and visibility == "DEFAULT"
        and section.isdigit() and int(section) in program_sections
    }
    return maps, programs, {record[-1] for record in records}


def definitions(path):
    return inspect(path)[0]


def map_def(map_type, key, value, maximum, flags=0):
    return dict(zip(MAP_FIELDS, (map_type, key, value, maximum, flags, 0, 0)))


SAFE_MAPS = {
    name: map_def(*values)
    for name, values in {
        "ASYNC_FUNCTIONS": (1, 32, 4, 128, 128),
        "CGROUP_FILTER": (8, 4, 4, 1),
        "CONFIG": (2, 4, 8, 1, 128),
        "EVENTS": (27, 0, 0, 262_144),
        "EVIDENCE": (6, 4, 8, 8),
        "MECH_SHAPE": (1, 8, 4, 1_024, 128),
        "PID_FILTER": (1, 4, 1, 1_024, 128),
        "RV_COUNTS": (5, 16, 8, 4_096),
        "SLOT_SEMANTICS": (2, 4, 18, 512, 128),
        "START": (1, 16, 272, 16_384),
        "STATS": (6, 4, 296, 512),
    }.items()
}
UNSAFE_MAPS = SAFE_MAPS | {
    "ATTR_BOOL_BITS": map_def(1, 4, 4, 16, 128),
    "TEMPLATE_TAIL": map_def(3, 4, 4, 1),
}
SAFE_PROGRAMS = {"p11_entry", "p11_return", "sched_process_fork"}
UNSAFE_PROGRAMS = SAFE_PROGRAMS | {
    "p11_entry_template", "p11_entry_template_pair",
    "p11_entry_template_second", "p11_entry_template_types",
}


def validate_policy_inventory(safe, unsafe):
    safe_maps, safe_programs, safe_symbols = safe
    unsafe_maps, unsafe_programs, unsafe_symbols = unsafe
    checks = [
        (safe_maps == SAFE_MAPS, "default map inventory differs"),
        (unsafe_maps == UNSAFE_MAPS, "diagnostic map inventory differs"),
        (safe_programs == SAFE_PROGRAMS, "default program inventory differs"),
        (unsafe_programs == UNSAFE_PROGRAMS, "diagnostic program inventory differs"),
        (not any("decode_params" in n or "walk_template" in n for n in safe_symbols),
         "default object contains an unsafe decoder symbol"),
        (any("decode_params" in n for n in unsafe_symbols), "diagnostic object lacks decode_params"),
        (sum("walk_template" in n for n in unsafe_symbols) == 3,
         "diagnostic object must contain exactly three walk_template variants"),
    ]
    for okay, message in checks:
        if not okay:
            raise RuntimeError(message)


def self_test():
    good = (SAFE_MAPS, SAFE_PROGRAMS, {"p11_entry"})
    diagnostic = (
        UNSAFE_MAPS,
        UNSAFE_PROGRAMS,
        {"decode_params", "walk_template-0", "walk_template-1", "walk_template-2"},
    )
    validate_policy_inventory(good, diagnostic)
    try:
        validate_policy_inventory((UNSAFE_MAPS, SAFE_PROGRAMS, {"decode_params"}), diagnostic)
    except RuntimeError:
        pass
    else:
        raise AssertionError("unsafe default inventory was accepted")
    record = (0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")
    data = struct.pack("<7I", 1, 4, 8, 1, 0, 0, 0)
    assert decode_map_definitions([record], 9, data)["ONE"]["value_size"] == 8
    mutations = [
        ([(0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE"), record], data * 2),
        ([(0, 24, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], data),
        ([(2, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], b"\0\0" + data),
        ([(0, 28, "OBJECT", "GLOBAL", "DEFAULT", "9", "ONE")], data[:-1]),
        ([record], data + b"\0"),
    ]
    for records, raw in mutations:
        try:
            decode_map_definitions(records, 9, raw)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"malformed map definitions accepted: {records!r}")
    print("malformed map definitions rejected: OK")
    print("check-bpf-map-defs self-test: OK")
    print("policy inventory self-test: OK")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--policy-inventory":
        safe, unsafe = inspect(sys.argv[2]), inspect(sys.argv[3])
        validate_policy_inventory(safe, unsafe)
        print(
            f"policy inventory: default maps={len(safe[0])} programs={len(safe[1])}; "
            f"diagnostic maps={len(unsafe[0])} programs={len(unsafe[1])} OK"
        )
        return
    if len(sys.argv) < 3:
        raise SystemExit(
            f"usage: {sys.argv[0]} BPF_ELF MAP=MAX_ENTRIES [...] | "
            "--policy-inventory DEFAULT_ELF DIAGNOSTIC_ELF | --self-test"
        )
    path = sys.argv[1]
    expected = dict(item.split("=", 1) for item in sys.argv[2:])
    actual = definitions(path)
    for name, value in expected.items():
        if name not in actual:
            raise RuntimeError(f"{name} has no map definition in {path}")
        want, got = int(value, 0), actual[name]["max_entries"]
        if got != want:
            raise RuntimeError(f"{path}: {name}.max_entries={got}, expected {want}")
        print(f"{path}: {name}.max_entries={got} OK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"check-bpf-map-defs: {error}", file=sys.stderr)
        sys.exit(1)
