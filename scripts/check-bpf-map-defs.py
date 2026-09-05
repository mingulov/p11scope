#!/usr/bin/env python3
"""Inspect exact map/program policy inventory in a freshly built BPF ELF."""

from pathlib import Path
import contextlib
import io
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
    globals_in = lambda wanted: {
        (name, section)
        for _, _, kind, bind, visibility, section, name in records
        if kind == "FUNC" and bind == "GLOBAL" and visibility == "DEFAULT"
        and section.isdigit() and (int(section) in program_sections) == wanted
    }
    programs = {name for name, _ in globals_in(True)}
    # A program emitted under an attach type this whitelist does not name
    # (`raw_tp/`, `kprobe/`, `fentry/`, `lsm/`, `uprobe.s`, ...) would land in an
    # unlisted section and be silently dropped from `programs`, leaving the
    # frozen count intact while the object gained a program. Refuse instead of
    # skipping: only the compiler-emitted mem* helpers in `.text` are exempt.
    by_index = {index: name for name, index in sections.items()}
    stray = sorted(
        f"{name} in {by_index.get(int(section), section)}"
        for name, section in globals_in(False)
        if name not in {"memcpy", "memmove", "memset"}
    )
    if stray:
        raise RuntimeError(f"{path}: global functions in unclassified sections: {stray}")
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
        "CONFIG": (2, 4, 8, 2, 128),
        "COUNTERS": (6, 4, 8, 5),
        "DISCOVERY": (27, 0, 0, 65_536),
        "DISCOVERY_STATE": (1, 24, 24, 64),
        "EVENTS": (27, 0, 0, 262_144),
        "EVIDENCE": (6, 4, 8, 8),
        "MECH_SHAPE": (1, 8, 4, 1_024, 128),
        "PAUSE_PIDS": (1, 16, 8, 1),
        "PID_FILTER": (1, 4, 8, 1_024, 128),
        "RV_COUNTS": (5, 16, 8, 4_096),
        "DESCRIPTORS": (2, 4, 18, 105, 128),
        "START": (1, 16, 272, 16_384),
        "STATS": (6, 4, 296, 512),
        "TAIL_CALLS": (3, 4, 4, 2),
    }.items()
}
UNSAFE_MAPS = SAFE_MAPS | {
    "ATTR_BOOL_BITS": map_def(1, 4, 4, 16, 128),
}
SAFE_PROGRAMS = {
    "p11_entry",
    "p11_return",
    "task_newtask",
    "dl_debug_state",
    "function_list_entry",
    "function_list_return",
    "interface_list_entry",
    "interface_list_return",
    "interface_list_worker",
    "interface_entry",
    "interface_return",
    "sched_process_exec",
    "sched_process_exit",
}
UNSAFE_PROGRAMS = SAFE_PROGRAMS | {
    "p11_entry_template", "p11_entry_template_pair",
    "p11_entry_template_second", "p11_entry_template_types",
}


FROZEN_INVENTORY = {
    "default": (SAFE_MAPS, SAFE_PROGRAMS),
    "diagnostic": (UNSAFE_MAPS, UNSAFE_PROGRAMS),
}


# Per-variant decoder-symbol freeze: (decode_params present?, walk_template count).
# The default object must carry no parameter decoder at all; the diagnostic one
# carries the decoder and exactly three template walkers.
FROZEN_SYMBOLS = {"default": (False, 0), "diagnostic": (True, 3)}


def validate_inventory(variant, maps, programs, symbols):
    """Compare ONE object's maps and programs against the frozen `variant` inventory.

    A mismatch prints every differing map name and field to stderr first, so a
    stale freeze is diagnosable from the failing lane's log alone.
    """
    frozen_maps, frozen_programs = FROZEN_INVENTORY[variant]
    if maps != frozen_maps:
        for name in sorted(maps.keys() - frozen_maps.keys()):
            print(f"map added: {name}", file=sys.stderr)
        for name in sorted(frozen_maps.keys() - maps.keys()):
            print(f"map removed: {name}", file=sys.stderr)
        for name in sorted(maps.keys() & frozen_maps.keys()):
            for field in MAP_FIELDS:
                got, want = maps[name][field], frozen_maps[name][field]
                if got != want:
                    print(f"{name}.{field}: object={got} frozen={want}", file=sys.stderr)
        raise RuntimeError(f"{variant} map inventory differs")
    if programs != frozen_programs:
        for name in sorted(programs - frozen_programs):
            print(f"program added: {name}", file=sys.stderr)
        for name in sorted(frozen_programs - programs):
            print(f"program removed: {name}", file=sys.stderr)
        raise RuntimeError(f"{variant} program inventory differs")
    found = (
        any("decode_params" in name for name in symbols),
        sum("walk_template" in name for name in symbols),
    )
    if found != FROZEN_SYMBOLS[variant]:
        print(
            f"decode_params={found[0]} walk_template={found[1]} "
            f"frozen decode_params={FROZEN_SYMBOLS[variant][0]} "
            f"walk_template={FROZEN_SYMBOLS[variant][1]}",
            file=sys.stderr,
        )
        raise RuntimeError(f"{variant} decoder symbol inventory differs")


def validate_policy_inventory(safe, unsafe):
    validate_inventory("default", *safe)
    validate_inventory("diagnostic", *unsafe)


def self_test():
    assert SAFE_MAPS["DISCOVERY"] == map_def(27, 0, 0, 65_536)
    assert SAFE_MAPS["DISCOVERY_STATE"] == map_def(1, 24, 24, 64)
    assert SAFE_MAPS["COUNTERS"] == map_def(6, 4, 8, 5)
    assert SAFE_MAPS["PAUSE_PIDS"] == map_def(1, 16, 8, 1)
    assert SAFE_MAPS["PID_FILTER"] == map_def(1, 4, 8, 1_024, 128)
    assert len(SAFE_MAPS) == 16
    assert len(UNSAFE_MAPS) == 17
    assert len(SAFE_PROGRAMS) == 13
    assert len(UNSAFE_PROGRAMS) == 17
    good = (SAFE_MAPS, SAFE_PROGRAMS, {"p11_entry"})
    diagnostic = (
        UNSAFE_MAPS,
        UNSAFE_PROGRAMS,
        {"decode_params", "walk_template-0", "walk_template-1", "walk_template-2"},
    )
    validate_policy_inventory(good, diagnostic)

    def rejected(check, *arguments):
        errors = io.StringIO()
        try:
            with contextlib.redirect_stderr(errors):
                check(*arguments)
        except RuntimeError:
            return errors.getvalue().splitlines()
        raise AssertionError(f"{check.__name__} accepted {arguments!r}")

    assert rejected(
        validate_policy_inventory, (UNSAFE_MAPS, SAFE_PROGRAMS, {"decode_params"}), diagnostic
    ) == ["map added: ATTR_BOOL_BITS"]
    # Each variant is compared against ITS OWN freeze, not the other one's.
    assert rejected(validate_inventory, "diagnostic", SAFE_MAPS, SAFE_PROGRAMS, set()) == [
        "map removed: ATTR_BOOL_BITS"
    ]
    assert rejected(validate_inventory, "default", UNSAFE_MAPS, UNSAFE_PROGRAMS, set()) == [
        "map added: ATTR_BOOL_BITS"
    ]
    # A one-field drift names exactly that field, nothing else (the W3 CONFIG
    # shape: same maps, one max_entries apart).
    frozen = SAFE_MAPS["CONFIG"]["max_entries"]
    drifted = SAFE_MAPS | {"CONFIG": SAFE_MAPS["CONFIG"] | {"max_entries": frozen + 1}}
    assert rejected(validate_inventory, "default", drifted, SAFE_PROGRAMS, set()) == [
        f"CONFIG.max_entries: object={frozen + 1} frozen={frozen}"
    ]
    # A program leaving the object is named, not just counted.
    assert rejected(
        validate_inventory, "default", SAFE_MAPS, SAFE_PROGRAMS - {"p11_entry"}, {"p11_entry"}
    ) == ["program removed: p11_entry"]
    # A decoder symbol reaching the shipped object is refused even when its maps
    # and programs are untouched -- the drift class `--inventory` alone would miss.
    assert rejected(
        validate_inventory, "default", SAFE_MAPS, SAFE_PROGRAMS, {"p11_entry", "decode_params"}
    ) == [
        "decode_params=True walk_template=0 frozen decode_params=False walk_template=0"
    ]
    assert rejected(validate_inventory, "diagnostic", UNSAFE_MAPS, UNSAFE_PROGRAMS, set()) == [
        "decode_params=False walk_template=0 frozen decode_params=True walk_template=3"
    ]
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


def usage():
    return (
        f"usage: {sys.argv[0]} BPF_ELF MAP=MAX_ENTRIES [...] | "
        "--inventory default|diagnostic BPF_ELF | "
        "--policy-inventory DEFAULT_ELF DIAGNOSTIC_ELF | --self-test"
    )


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:2] == ["--inventory"]:
        if len(sys.argv) != 4:
            raise SystemExit(usage())
        variant, path = sys.argv[2], sys.argv[3]
        if variant not in FROZEN_INVENTORY:
            raise RuntimeError(f"unknown inventory variant {variant!r}")
        maps, programs, symbols = inspect(path)
        validate_inventory(variant, maps, programs, symbols)
        print(f"inventory {variant}: maps={len(maps)} programs={len(programs)} OK")
        return
    if sys.argv[1:2] == ["--policy-inventory"]:
        if len(sys.argv) != 4:
            raise SystemExit(usage())
        safe, unsafe = inspect(sys.argv[2]), inspect(sys.argv[3])
        validate_policy_inventory(safe, unsafe)
        print(
            f"policy inventory: default maps={len(safe[0])} programs={len(safe[1])}; "
            f"diagnostic maps={len(unsafe[0])} programs={len(unsafe[1])} OK"
        )
        return
    if len(sys.argv) < 3:
        raise SystemExit(usage())
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
