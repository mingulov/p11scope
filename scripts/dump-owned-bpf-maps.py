#!/usr/bin/env python3
"""Dump only BPF maps whose fds are owned by one observer process."""

import glob
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


MAP_ID = re.compile(r"^map_id:\s*(\d+)\s*$", re.MULTILINE)


def map_ids_from_fdinfo(texts):
    return sorted({int(match.group(1)) for text in texts for match in MAP_ID.finditer(text)})


def checked_json(args, returncode, stdout, stderr, require_list=False):
    if returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {stderr.strip()}")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"{' '.join(args)} produced invalid JSON: stderr={stderr!r}"
        ) from error
    if require_list and not isinstance(value, list):
        raise RuntimeError(f"{' '.join(args)} produced {type(value).__name__}, expected JSON list")
    return value


def run_json(args, require_list=False):
    proc = subprocess.run(args, capture_output=True, text=True)
    return checked_json(
        args, proc.returncode, proc.stdout, proc.stderr, require_list=require_list
    )


def one(value):
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError(f"expected one bpftool record, got {len(value)}")
        return value[0]
    return value


def self_test():
    assert map_ids_from_fdinfo(["pos:\t0\nmap_id:\t17\n", "map_id: 4\n", "map_id: 17\n"]) == [4, 17]
    assert one([{"id": 4}]) == {"id": 4}
    try:
        one([])
    except RuntimeError:
        pass
    else:
        raise AssertionError("empty bpftool result was accepted")
    try:
        checked_json(["bpftool"], 1, "[]", "map disappeared", require_list=True)
    except RuntimeError:
        pass
    else:
        raise AssertionError("nonzero bpftool result with valid JSON was accepted")
    print("nonzero valid JSON rejected: OK")
    try:
        checked_json(["bpftool"], 0, "{}", "", require_list=True)
    except RuntimeError:
        pass
    else:
        raise AssertionError("non-list ordinary map dump was accepted")
    print("ordinary dump list validation: OK")
    print("dump-owned-bpf-maps self-test: OK")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 6:
        raise SystemExit(
            f"usage: {sys.argv[0]} OBSERVER_PID OUT_DIR LABEL MIN_START_ENTRIES EXPECTED_START_MAX"
        )

    pid = int(sys.argv[1])
    out_dir = Path(sys.argv[2])
    label = sys.argv[3]
    min_start = int(sys.argv[4])
    expected_start_max = int(sys.argv[5])
    out_dir.mkdir(parents=True, exist_ok=True)

    texts = []
    for path in glob.glob(f"/proc/{pid}/fdinfo/*"):
        try:
            texts.append(Path(path).read_text())
        except OSError:
            continue
    ids = map_ids_from_fdinfo(texts)
    if not ids:
        raise RuntimeError(f"observer pid {pid} owns no readable BPF map fds")

    maps = []
    for map_id in ids:
        info = one(run_json(["bpftool", "-j", "map", "show", "id", str(map_id)]))
        info["id"] = map_id
        maps.append(info)
    names = [item.get("name") for item in maps]
    if len(names) != len(set(names)):
        raise RuntimeError(f"observer pid {pid} owns duplicate map names: {names}")

    starts = [item for item in maps if item.get("name") == "START"]
    if len(starts) != 1:
        raise RuntimeError(f"expected exactly one observer-owned START map, got {starts}")
    start = starts[0]
    if start.get("type") != "hash" or start.get("max_entries") != expected_start_max:
        raise RuntimeError(
            f"unexpected START definition: type={start.get('type')!r} "
            f"max_entries={start.get('max_entries')!r}, expected hash/{expected_start_max}"
        )

    if min_start:
        deadline = time.monotonic() + 8
        while True:
            entries = run_json(
                ["bpftool", "-j", "map", "dump", "id", str(start["id"])],
                require_list=True,
            )
            if len(entries) >= min_start:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"START map id {start['id']} never reached {min_start} live entries; "
                    f"last dump had {len(entries)}"
                )
            time.sleep(0.05)

    suffix = f"_{label}" if label else ""
    manifest = []
    for item in maps:
        name = item["name"]
        if name == "EVENTS":
            if item.get("type") != "ringbuf":
                raise RuntimeError(f"EVENTS is not a ringbuf: {item}")
            manifest.append(
                {
                    "id": item["id"],
                    "name": name,
                    "type": item.get("type"),
                    "key_size": item.get("bytes_key"),
                    "value_size": item.get("bytes_value"),
                    "max_entries": item.get("max_entries"),
                    "oracle": "mmap",
                }
            )
            continue
        output = out_dir / f"mapdump_{name}{suffix}.json"
        dumped = run_json(
            ["bpftool", "-j", "map", "dump", "id", str(item["id"])],
            require_list=True,
        )
        output.write_text(json.dumps(dumped, separators=(",", ":")) + "\n")
        manifest.append(
            {
                "id": item["id"],
                "name": name,
                "type": item.get("type"),
                "key_size": item.get("bytes_key"),
                "value_size": item.get("bytes_value"),
                "max_entries": item.get("max_entries"),
                "oracle": "dump",
                "file": str(output),
            }
        )

    manifest_path = out_dir / f"mapdump_manifest{suffix}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        f"observer pid {pid}: dumped {len(manifest)} owned maps; "
        f"START id={start['id']} max_entries={start['max_entries']}"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"dump-owned-bpf-maps: {error}", file=sys.stderr)
        sys.exit(1)
