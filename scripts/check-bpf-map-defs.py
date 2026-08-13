#!/usr/bin/env python3
"""Read legacy Aya map definitions directly from a freshly built BPF ELF."""

import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def symbols(path):
    output = subprocess.run(
        ["llvm-readelf", "-sW", path], capture_output=True, text=True, check=True
    ).stdout
    found = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3] == "OBJECT" and fields[6].isdigit():
            found[fields[7]] = int(fields[1], 16)
    return found


def definitions(path):
    with tempfile.TemporaryDirectory() as directory:
        raw = Path(directory) / "maps.bin"
        subprocess.run(
            ["llvm-objcopy", "--dump-section", f"maps={raw}", path], check=True
        )
        data = raw.read_bytes()
    result = {}
    for name, offset in symbols(path).items():
        if offset + 28 <= len(data):
            map_type, key_size, value_size, max_entries, flags, pinning, _ = struct.unpack_from(
                "<7I", data, offset
            )
            result[name] = {
                "type": map_type,
                "key_size": key_size,
                "value_size": value_size,
                "max_entries": max_entries,
                "flags": flags,
                "pinning": pinning,
            }
    return result


def self_test():
    raw = struct.pack("<7I", 1, 16, 200, 16_384, 0, 0, 0)
    assert struct.unpack_from("<7I", raw)[3] == 16_384
    print("check-bpf-map-defs self-test: OK")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) < 3:
        raise SystemExit(f"usage: {sys.argv[0]} BPF_ELF MAP=MAX_ENTRIES [...]")
    path = sys.argv[1]
    expected = dict(item.split("=", 1) for item in sys.argv[2:])
    actual = definitions(path)
    for name, value in expected.items():
        if name not in actual:
            raise RuntimeError(f"{name} has no map definition in {path}")
        want = int(value, 0)
        got = actual[name]["max_entries"]
        if got != want:
            raise RuntimeError(f"{path}: {name}.max_entries={got}, expected {want}")
        print(f"{path}: {name}.max_entries={got} OK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"check-bpf-map-defs: {error}", file=sys.stderr)
        sys.exit(1)
