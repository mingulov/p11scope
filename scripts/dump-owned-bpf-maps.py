#!/usr/bin/env python3
"""Dump only BPF maps whose fds are owned by one observer process."""

import glob
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time


MAP_ID = re.compile(r"^map_id:\s*(\d+)\s*$", re.MULTILINE)
TASK_STORAGE_MAGIC = b"P11TSV1\0"
TASK_STORAGE_HEADER = struct.Struct("<8sIIIII")
TASK_STORAGE_RECORD = 1
TASK_STORAGE_EOF = 2
TASK_STORAGE_NAMES = ("TASK_COOKIE", "THREAD_OWNER", "ROOT_AFFILIATION")
TASK_STORAGE_MAX_RECORDS = 131072
TASK_STORAGE_MAX_BYTES = 64 * 1024 * 1024
TASK_STORAGE_TIMEOUT_SECONDS = 8
DIAGNOSTIC_LIMIT = 4096


def map_ids_from_fdinfo(texts):
    return sorted({int(match.group(1)) for text in texts for match in MAP_ID.finditer(text)})


def checked_json(args, returncode, stdout, stderr, require_list=False, map_identity=None):
    identity = ""
    if map_identity is not None:
        identity = (
            f" for map id={map_identity['id']} name={map_identity['name']}"
            f" type={map_identity['type']}"
        )
    if returncode:
        raise RuntimeError(
            f"{' '.join(args)}{identity} failed: {bounded_diagnostic(stderr)}"
        )
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"{' '.join(args)}{identity} produced invalid JSON: "
            f"stderr={bounded_diagnostic(stderr)!r}"
        ) from error
    if require_list and not isinstance(value, list):
        raise RuntimeError(
            f"{' '.join(args)}{identity} produced {type(value).__name__}, expected JSON list"
        )
    return value


def bounded_diagnostic(value):
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    text = text.strip()
    if len(text) > DIAGNOSTIC_LIMIT:
        return text[:DIAGNOSTIC_LIMIT] + "...[truncated]"
    return text


def run_json(args, require_list=False, map_identity=None):
    proc = subprocess.run(args, capture_output=True, text=True)
    return checked_json(
        args, proc.returncode, proc.stdout, proc.stderr,
        require_list=require_list, map_identity=map_identity,
    )


def map_oracle(item):
    """Which oracle reads this map: `bpftool map dump`, or an mmap consumer.

    A ringbuf has no key/value iteration, so `bpftool map dump` refuses it
    (exit 244, empty stderr) whatever it is called. Task-storage maps require
    the native reader added by Task 2. Dispatch on the map type, never name.
    """
    if item.get("type") == "ringbuf":
        return "mmap"
    if item.get("type") == "task_storage":
        return "task-storage"
    if item["name"] == "EVENTS":
        raise RuntimeError(f"EVENTS is not a ringbuf: {item}")
    return "dump"


def canonical_map_name(item):
    name = item.get("name")
    if item.get("type") != "task_storage" or not isinstance(name, str):
        return name
    matches = [candidate for candidate in TASK_STORAGE_NAMES if candidate[:15] == name]
    return matches[0] if len(matches) == 1 else name


def one(value):
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError(f"expected one bpftool record, got {len(value)}")
        return value[0]
    return value


def write_receipt(path, text):
    """Write a receipt file 0600 from creation, owned by the invoking user.

    The dumper runs under sudo, but its receipts are audited and normalized by
    the unprivileged finalizer, which cannot chmod a root-owned 0644 file.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    uid, gid = (int(os.environ.get(name, "-1")) for name in ("SUDO_UID", "SUDO_GID"))
    if os.getuid() == 0 and uid >= 0 and gid >= 0:
        os.chown(path, uid, gid)


def write_binary_receipt(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
        uid, gid = (int(os.environ.get(name, "-1")) for name in ("SUDO_UID", "SUDO_GID"))
        if os.getuid() == 0 and uid >= 0 and gid >= 0:
            os.chown(path, uid, gid)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def task_storage_specs(maps):
    by_name = {item.get("name"): item for item in maps}
    if set(by_name) != set(TASK_STORAGE_NAMES) or len(maps) != len(TASK_STORAGE_NAMES):
        raise RuntimeError(
            f"expected exact task-storage maps {list(TASK_STORAGE_NAMES)}, "
            f"got {sorted(str(name) for name in by_name)}"
        )
    ordered = [by_name[name] for name in TASK_STORAGE_NAMES]
    if len({item.get("id") for item in ordered}) != len(ordered):
        raise RuntimeError("task-storage maps do not have distinct map ids")
    for item in ordered:
        actual = (
            item.get("type"), item.get("bytes_key"), item.get("bytes_value"),
            item.get("max_entries"), item.get("map_flags"),
        )
        expected = ("task_storage", 4, 544 if item["name"] == "THREAD_OWNER" else 8, 0, 1)
        if actual != expected:
            raise RuntimeError(
                f"task-storage map id={item['id']} name={item['name']} metadata mismatch: "
                f"type/key/value/max/flags={actual!r}, expected={expected!r}"
            )
    return ordered


def run_task_storage_reader(reader, obj, observer_pid, maps, *, timeout_seconds,
                            max_records, max_bytes):
    reader = Path(reader)
    obj = Path(obj)
    if not reader.is_absolute() or not obj.is_absolute():
        raise RuntimeError("task-storage reader and object paths must be absolute")
    if not reader.is_file() or not os.access(reader, os.X_OK):
        raise RuntimeError(f"task-storage reader is not an executable file: {reader}")
    if not obj.is_file():
        raise RuntimeError(f"task-storage object is not a file: {obj}")
    ordered = task_storage_specs(maps)
    arguments = [
        str(reader), str(obj), str(observer_pid), str(max_records), str(max_bytes),
        str(max(1, int(timeout_seconds * 1000))),
    ]
    for item in ordered:
        arguments.append(
            ":".join(str(value) for value in (
                item["name"], item["id"], item["type"], item["bytes_key"],
                item["bytes_value"], item["max_entries"], item["map_flags"],
            ))
        )
    output_limit = max_bytes + (max_records + 1) * TASK_STORAGE_HEADER.size
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(arguments, stdout=stdout, stderr=stderr)
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise RuntimeError(
                f"task-storage reader timed out after {timeout_seconds:g}s"
            ) from error
        stderr.seek(0)
        diagnostic = bounded_diagnostic(stderr.read(DIAGNOSTIC_LIMIT + 1))
        if returncode:
            raise RuntimeError(
                f"task-storage reader failed with status {returncode}: {diagnostic}"
            )
        size = os.fstat(stdout.fileno()).st_size
        if size > output_limit:
            raise RuntimeError(
                f"task-storage reader exceeded framed output bound: {size} > {output_limit}"
            )
        stdout.seek(0)
        return stdout.read()


def parse_task_storage_frames(data, maps, *, max_records, max_bytes):
    expected = {item["id"]: item for item in task_storage_specs(maps)}
    records = []
    identities = set()
    value_bytes = 0
    offset = 0
    while True:
        if len(data) - offset < TASK_STORAGE_HEADER.size:
            raise RuntimeError("task-storage stream ended before terminal EOF frame")
        magic, kind, map_id, pid, tid, value_len = TASK_STORAGE_HEADER.unpack_from(data, offset)
        offset += TASK_STORAGE_HEADER.size
        if magic != TASK_STORAGE_MAGIC:
            raise RuntimeError(f"task-storage frame {len(records)} has invalid magic")
        if kind == TASK_STORAGE_EOF:
            if any((map_id, pid, tid, value_len)):
                raise RuntimeError("task-storage terminal EOF frame has nonzero metadata")
            if offset != len(data):
                raise RuntimeError("task-storage stream has bytes after terminal EOF")
            return records
        if kind != TASK_STORAGE_RECORD:
            raise RuntimeError(f"task-storage frame {len(records)} has invalid kind={kind}")
        if len(records) >= max_records:
            raise RuntimeError(f"task-storage record bound exceeded: {max_records}")
        item = expected.get(map_id)
        if item is None:
            raise RuntimeError(f"task-storage frame names unexpected map id={map_id}")
        if value_len != item["bytes_value"]:
            raise RuntimeError(
                f"task-storage map id={map_id} name={item['name']} value length "
                f"{value_len} != {item['bytes_value']}"
            )
        if not pid or not tid:
            raise RuntimeError(
                f"task-storage map id={map_id} name={item['name']} has zero task identity"
            )
        end = offset + value_len
        if end > len(data):
            raise RuntimeError(
                f"task-storage map id={map_id} name={item['name']} value is truncated"
            )
        identity = (map_id, pid, tid)
        if identity in identities:
            raise RuntimeError(
                f"duplicate task-storage record for map id={map_id} pid={pid} tid={tid}"
            )
        identities.add(identity)
        value_bytes += value_len
        if value_bytes > max_bytes:
            raise RuntimeError(f"task-storage byte bound exceeded: {value_bytes} > {max_bytes}")
        records.append({
            "map_id": map_id, "pid": pid, "tid": tid, "value": data[offset:end],
        })
        offset = end


def publish_task_storage_surfaces(out_dir, label, maps, records):
    values = {item["id"]: bytearray() for item in maps}
    for record in records:
        values[record["map_id"]].extend(record["value"])
    suffix = f"_{label}" if label else ""
    paths = {}
    created = []
    try:
        for item in maps:
            path = out_dir / f"mapdump_{item['name']}{suffix}.bin"
            write_binary_receipt(path, values[item["id"]])
            created.append(path)
            paths[item["name"]] = str(path)
    except BaseException:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return paths


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
    # `bpftool map dump` cannot read a ringbuf — it exits 244 with empty stderr —
    # so every ringbuf this observer owns must route to the mmap oracle. The
    # mutation lane is the real Slice 1b-2 inventory: two ringbufs, only one of
    # them named EVENTS. Dispatching on the name dumps DISCOVERY and dies.
    inventory = [
        {"name": "EVENTS", "type": "ringbuf"},
        {"name": "DISCOVERY", "type": "ringbuf"},
        {"name": "START", "type": "hash"},
        {"name": "COUNTERS", "type": "percpu_array"},
        {"name": "TASK_COOKIE", "type": "task_storage"},
        {"name": "THREAD_OWNER", "type": "task_storage"},
        {"name": "ROOT_AFFILIATION", "type": "task_storage"},
    ]
    assert [map_oracle(item) for item in inventory] == [
        "mmap", "mmap", "dump", "dump", "task-storage", "task-storage", "task-storage"
    ], [
        map_oracle(item) for item in inventory
    ]
    print("every owned ringbuf routes to the mmap oracle: OK")
    try:
        map_oracle({"name": "EVENTS", "type": "hash"})
    except RuntimeError:
        pass
    else:
        raise AssertionError("EVENTS built as a non-ringbuf was accepted")
    print("EVENTS ringbuf build guard: OK")
    print("dump-owned-bpf-maps self-test: OK")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 8:
        raise SystemExit(
            f"usage: {sys.argv[0]} OBSERVER_PID OUT_DIR LABEL MIN_START_ENTRIES "
            "EXPECTED_START_MAX TASK_STORAGE_READER TASK_STORAGE_OBJECT"
        )

    pid = int(sys.argv[1])
    out_dir = Path(sys.argv[2])
    label = sys.argv[3]
    min_start = int(sys.argv[4])
    expected_start_max = int(sys.argv[5])
    reader = Path(sys.argv[6])
    obj = Path(sys.argv[7])
    if not reader.is_absolute() or not obj.is_absolute():
        raise RuntimeError("task-storage reader and object paths must be absolute")
    if not reader.is_file() or not os.access(reader, os.X_OK):
        raise RuntimeError(f"task-storage reader is not an executable file: {reader}")
    if not obj.is_file():
        raise RuntimeError(f"task-storage object is not a file: {obj}")
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
        info["name"] = canonical_map_name(info)
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
            f"unexpected START map id={start['id']} name=START definition: "
            f"type={start.get('type')!r} "
            f"max_entries={start.get('max_entries')!r}, expected hash/{expected_start_max}"
        )

    if min_start:
        deadline = time.monotonic() + 8
        while True:
            entries = run_json(
                ["bpftool", "-j", "map", "dump", "id", str(start["id"])],
                require_list=True,
                map_identity=start,
            )
            if len(entries) >= min_start:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"START map id={start['id']} name=START type={start.get('type')} "
                    f"never reached {min_start} live entries; "
                    f"last dump had {len(entries)}"
                )
            time.sleep(0.05)

    suffix = f"_{label}" if label else ""
    manifest = []
    task_records = []
    for item in maps:
        name = item["name"]
        record = {
            "id": item["id"],
            "name": name,
            "type": item.get("type"),
            "key_size": item.get("bytes_key"),
            "value_size": item.get("bytes_value"),
            "max_entries": item.get("max_entries"),
            "oracle": map_oracle(item),
        }
        if record["oracle"] == "task-storage":
            task_records.append((item, record))
        if record["oracle"] == "dump":
            output = out_dir / f"mapdump_{name}{suffix}.json"
            dumped = run_json(
                ["bpftool", "-j", "map", "dump", "id", str(item["id"])],
                require_list=True,
                map_identity=item,
            )
            write_receipt(output, json.dumps(dumped, separators=(",", ":")) + "\n")
            record["file"] = str(output)
        manifest.append(record)

    if task_records:
        task_maps = task_storage_specs([item for item, _record in task_records])
        framed = run_task_storage_reader(
            reader, obj, pid, task_maps,
            timeout_seconds=TASK_STORAGE_TIMEOUT_SECONDS,
            max_records=TASK_STORAGE_MAX_RECORDS,
            max_bytes=TASK_STORAGE_MAX_BYTES,
        )
        parsed = parse_task_storage_frames(
            framed, task_maps, max_records=TASK_STORAGE_MAX_RECORDS,
            max_bytes=TASK_STORAGE_MAX_BYTES,
        )
        surfaces = publish_task_storage_surfaces(out_dir, label, task_maps, parsed)
        for _item, record in task_records:
            record["file"] = surfaces[record["name"]]

    manifest_path = out_dir / f"mapdump_manifest{suffix}.json"
    write_receipt(manifest_path, json.dumps(manifest, indent=2) + "\n")
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
