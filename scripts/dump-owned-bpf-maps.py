#!/usr/bin/env python3
"""Dump only BPF maps whose fds are owned by one observer process."""

import ctypes
import glob
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import struct
import subprocess
import sys
import threading
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
STOPPED_SNAPSHOT_CONTRACT = "p11scope/stopped-task-storage/v1"
SNAPSHOT_MAP_ORACLES = {
    "hash": "dump", "array": "dump", "prog_array": "dump",
    "cgroup_array": "refused-lookup",
    "percpu_hash": "dump", "percpu_array": "dump",
    "ringbuf": "mmap", "task_storage": "task-storage",
}
# `cgroup_array_map_ops` defines no `map_fd_sys_lookup_elem`, so every
# userspace lookup of one is answered -ENOTSUPP by `bpf_fd_array_map_lookup_elem`
# whether the map is empty or populated. Record that kernel errno per key.
ENOTSUPP = 524
BPF_SYSCALL = 321
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_TYPE_CGROUP_ARRAY = 8
BPF_ATTR_BYTES = 64
BPF_ATTR_MAP_CREATE = struct.Struct("=IIIIIII16s")
BPF_ATTR_MAP_ID = struct.Struct("=III")
BPF_ATTR_MAP_ELEM = struct.Struct("=IIQQQ")
BPF_ATTR_OBJ_INFO = struct.Struct("=IIQ")
BPF_MAP_INFO = struct.Struct("=IIIIII")
DIAGNOSTIC_LIMIT = 4096
# A diagnostic keeps a bounded head AND a bounded tail, never a head-only
# prefix: the children run here (libbpf, cargo, gcc, ld, the native reader)
# log their identity and inputs first and state the actual failure LAST, so
# the tail is where the explanation of a failure lives and a head-only cut
# is guaranteed to discard it. The marker budget reserves room for the
# dropped-bytes seam so head + marker + tail stays inside DIAGNOSTIC_LIMIT
# and one elision pass never yields text that needs a second.
DIAGNOSTIC_MARKER_BUDGET = 64
DIAGNOSTIC_HEAD = (DIAGNOSTIC_LIMIT - DIAGNOSTIC_MARKER_BUDGET) // 2
DIAGNOSTIC_TAIL = DIAGNOSTIC_LIMIT - DIAGNOSTIC_MARKER_BUDGET - DIAGNOSTIC_HEAD
JSON_TIMEOUT_SECONDS = 8
JSON_OUTPUT_MAX_BYTES = TASK_STORAGE_MAX_BYTES


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
        def unique_object(pairs):
            result = {}
            for key, child in pairs:
                if key in result:
                    raise RuntimeError("bpftool JSON contains duplicate object key")
                result[key] = child
            return result

        value = json.loads(stdout, object_pairs_hook=unique_object)
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


def dropped_marker(dropped):
    """The explicit seam saying how many unread middle bytes were elided."""
    return f"\n...[{dropped} bytes dropped]...\n"


def bounded_diagnostic(value):
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    text = text.strip()
    if len(text) <= DIAGNOSTIC_LIMIT:
        return text
    # Elide the middle, not the end: the first lines identify the tool and
    # its inputs, the last lines say why it failed.
    dropped = len(text) - DIAGNOSTIC_HEAD - DIAGNOSTIC_TAIL
    return text[:DIAGNOSTIC_HEAD] + dropped_marker(dropped) + text[-DIAGNOSTIC_TAIL:]


def run_json(args, require_list=False, map_identity=None, *,
             timeout_seconds=JSON_TIMEOUT_SECONDS, max_bytes=JSON_OUTPUT_MAX_BYTES):
    """Acquire JSON under the caller preconditions of _run_bounded_bytes."""
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= JSON_TIMEOUT_SECONDS
            or not snapshot_uint(max_bytes, 63, positive=True)
            or max_bytes > JSON_OUTPUT_MAX_BYTES):
        raise RuntimeError("bpftool JSON acquisition has invalid bounds")
    returncode, output, diagnostic = _run_bounded_bytes(
        args, timeout_seconds=timeout_seconds, max_bytes=max_bytes,
        label="bpftool JSON acquisition",
    )
    return checked_json(
        args, returncode, output.decode("utf-8", "replace"),
        diagnostic.decode("utf-8", "replace"), require_list=require_list,
        map_identity=map_identity,
    )


def _run_bounded_bytes(args, *, timeout_seconds, max_bytes, label):
    """Collect bounded bytes and reap only this acquisition's direct child.

    Callers validate their own timeout and output limits before entering here.
    Run only in an isolated, single-threaded script with default SIGCHLD
    retention and no competing waiters (including signal handlers or native
    threads). Keep those conditions unchanged until this call returns. They
    preserve direct-child ownership if pidfd acquisition itself fails.
    """
    if (threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise RuntimeError(f"{label} requires one main thread and default SIGCHLD")
    output = bytearray()
    diagnostic = bytearray()
    diagnostic_dropped = 0
    streams = None
    process = None
    pidfd = None
    original_mask = None
    returncode = None
    primary_error = None
    primary_traceback = None
    try:
        # Record restoration before the mutating call: a Python handler can
        # raise after the kernel changes the mask but before that call returns.
        handled_signals = {sig for sig in signal.valid_signals()
                           if callable(signal.getsignal(sig))}
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
        # Keep handlers deferred through acquisition AND all cleanup entry/
        # transition steps. Cancellation is delivered after bounded cleanup;
        # callers testing that bound need an independent process watchdog.
        # The child must not inherit the temporary blocked mask.
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, original_mask),
        )
        pidfd = os.pidfd_open(process.pid)
        deadline = time.monotonic() + timeout_seconds
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, output)
        streams.register(process.stderr, selectors.EVENT_READ, diagnostic)
        failure = None
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"{label} timed out after {timeout_seconds:g}s"
                break
            for key, _events in streams.select(min(0.05, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                target = key.data
                if target is output:
                    target.extend(chunk[:max_bytes + 1 - len(target)])
                    if len(target) > max_bytes:
                        failure = f"{label} exceeded output bound {max_bytes}"
                        break
                else:
                    # stderr: retain a bounded head and a bounded tail, and
                    # count the middle as dropped. Stopping at the first
                    # bound instead is what kept libbpf's ELF/CO-RE chatter
                    # and threw away the verifier verdict at the end of the
                    # stream — the only bytes that explained the failure.
                    # Only the retained window grows with this code, never
                    # memory: a runaway child's stderr is trimmed on every
                    # chunk, so a hostile child cannot fill memory either.
                    target.extend(chunk)
                    excess = len(target) - DIAGNOSTIC_HEAD - DIAGNOSTIC_TAIL
                    if excess > 0:
                        diagnostic_dropped += excess
                        del target[DIAGNOSTIC_HEAD:len(target) - DIAGNOSTIC_TAIL]
            if failure is not None:
                break
        if failure is not None:
            raise RuntimeError(failure)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"{label} timed out after {timeout_seconds:g}s")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"{label} timed out after {timeout_seconds:g}s") from None
    except BaseException as error:
        primary_error = error
        primary_traceback = error.__traceback__
    finally:
        cleanup_error = None

        def cleanup(action):
            nonlocal cleanup_error
            try:
                action()
            except BaseException as error:
                if cleanup_error is not None:
                    error.__cause__ = cleanup_error
                cleanup_error = error

        def terminate_child():
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The retained identity exited, possibly already reaped.
            else:
                # No reaping wait has occurred on this path. With exclusive
                # waits and retained zombies, WNOWAIT proves the direct child
                # still owns this PID even if it exits before kill(). ECHILD
                # refuses signaling; never infer ownership from Popen state.
                try:
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    return
                os.kill(process.pid, signal.SIGKILL)

        if process is not None and returncode is None:
            cleanup(terminate_child)
        if streams is not None:
            cleanup(streams.close)
        if process is not None:
            cleanup(process.stdout.close)
            cleanup(process.stderr.close)
            cleanup(lambda: process.wait(timeout=min(timeout_seconds, 1)))
        if pidfd is not None:
            cleanup(lambda: os.close(pidfd))
        if original_mask is not None:
            cleanup(lambda: signal.pthread_sigmask(signal.SIG_SETMASK, original_mask))
    if primary_error is not None:
        if cleanup_error is not None:
            raise primary_error.with_traceback(primary_traceback) from cleanup_error
        raise primary_error.with_traceback(primary_traceback)
    if cleanup_error is not None:
        raise cleanup_error.with_traceback(cleanup_error.__traceback__)
    if diagnostic_dropped:
        # Splice the seam in here, where the head/tail boundary is known;
        # callers and bounded_diagnostic pass the result through untouched
        # because it already fits DIAGNOSTIC_LIMIT.
        diagnostic = (diagnostic[:DIAGNOSTIC_HEAD]
                      + dropped_marker(diagnostic_dropped).encode("ascii")
                      + diagnostic[DIAGNOSTIC_HEAD:])
    return returncode, bytes(output), bytes(diagnostic)


def map_oracle(item):
    """Which oracle witnesses this map, read from the one type-to-oracle table.

    A ringbuf has no key/value iteration, so `bpftool map dump` refuses it
    (exit 244, empty stderr) whatever it is called. Task-storage maps require
    the native reader added by Task 2. A cgroup_array has no userspace lookup
    at all, so the kernel's refusal is the only value evidence there is.
    Dispatch on the map type, never name, and read the same table
    `normalize_map_metadata` validates against: a dispatcher that keeps its own
    opinion is how a cgroup_array came to be routed to a dump it cannot answer.
    """
    oracle = SNAPSHOT_MAP_ORACLES.get(item.get("type"))
    if oracle is None:
        raise RuntimeError(f"unknown owned map type: {item}")
    if item["name"] == "EVENTS" and oracle != "mmap":
        raise RuntimeError(f"EVENTS is not a ringbuf: {item}")
    return oracle


def canonical_map_name(item):
    name = item.get("name")
    if item.get("type") != "task_storage" or not isinstance(name, str):
        return name
    matches = [candidate for candidate in TASK_STORAGE_NAMES if candidate[:15] == name]
    return matches[0] if len(matches) == 1 else name


def normalize_map_metadata(item, requested_id):
    """Translate one real bpftool map-show row to the strict internal shape."""
    if not isinstance(item, dict) or not snapshot_uint(requested_id, 32, positive=True):
        raise RuntimeError("map metadata: malformed result")
    if item.get("id") != requested_id:
        raise RuntimeError(f"map metadata: returned map id differs from requested id={requested_id}")
    has_flags = "flags" in item
    has_alias = "map_flags" in item
    if not has_flags and not has_alias:
        raise RuntimeError(f"map metadata: missing flags for requested id={requested_id}")
    if has_flags and has_alias and item["flags"] != item["map_flags"]:
        raise RuntimeError(f"map metadata: conflicting flags for requested id={requested_id}")
    flags = item["flags"] if has_flags else item["map_flags"]
    normalized = {
        "id": item.get("id"), "name": canonical_map_name(item), "type": item.get("type"),
        "bytes_key": item.get("bytes_key"), "bytes_value": item.get("bytes_value"),
        "max_entries": item.get("max_entries"), "map_flags": flags,
    }
    map_type = normalized["type"]
    normalized["oracle"] = SNAPSHOT_MAP_ORACLES.get(map_type)
    snapshot_map_metadata(normalized)
    if normalized["name"] == "EVENTS" and map_type != "ringbuf":
        raise RuntimeError(f"map metadata: EVENTS is not a ringbuf for requested id={requested_id}")
    return normalized


def _raw_bytes(value, expected):
    if not isinstance(value, list) or len(value) != expected:
        raise RuntimeError("raw map dump: malformed byte array")
    result = []
    for byte in value:
        if type(byte) is int and 0 <= byte <= 0xff:
            result.append(f"0x{byte:02x}")
        elif type(byte) is str and re.fullmatch(r"0x[0-9a-fA-F]{2}", byte) is not None:
            result.append(f"0x{int(byte, 16):02x}")
        else:
            raise RuntimeError("raw map dump: malformed byte array")
    return result


def possible_cpu_ids(path=Path("/sys/devices/system/cpu/possible")):
    """Return the kernel possible-CPU set, which sizes per-CPU map values."""
    with Path(path).open(encoding="ascii") as handle:
        text = handle.read(4097)
    if len(text) > 4096:
        raise RuntimeError("possible CPU set exceeds input bound")
    cpus = set()
    for part in text.strip().split(","):
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", part)
        if match is None:
            raise RuntimeError("possible CPU set is malformed")
        first = int(match.group(1))
        last = first if match.group(2) is None else int(match.group(2))
        if first > last or last >= (1 << 20):
            raise RuntimeError("possible CPU set is malformed")
        before = len(cpus)
        cpus.update(range(first, last + 1))
        if len(cpus) != before + last - first + 1:
            raise RuntimeError("possible CPU set contains duplicates")
    if not cpus:
        raise RuntimeError("possible CPU set is empty")
    return tuple(sorted(cpus))


def normalize_map_dump(entries, metadata, *, possible_cpus=None):
    """Retain complete raw bpftool cells while discarding validated BTF formatting."""
    snapshot_map_metadata(metadata)
    if metadata["oracle"] != "dump" or not isinstance(entries, list):
        raise RuntimeError("raw map dump: invalid map or result")
    if len(entries) > metadata["max_entries"]:
        raise RuntimeError("raw map dump: entry bound exceeded")
    per_cpu = metadata["type"] in ("percpu_hash", "percpu_array")
    array = metadata["type"] in ("array", "percpu_array")
    if array and metadata["bytes_key"] != 4:
        raise RuntimeError("raw map dump: malformed array key metadata")
    if per_cpu:
        possible_cpus = possible_cpu_ids() if possible_cpus is None else possible_cpus
        if (not isinstance(possible_cpus, (list, tuple)) or not possible_cpus
                or any(not snapshot_uint(cpu, 32) for cpu in possible_cpus)
                or list(possible_cpus) != sorted(set(possible_cpus))):
            raise RuntimeError("raw map dump: invalid possible CPU set")
    result = []
    keys = set()
    for entry in entries:
        expected_fields = {"key", "values" if per_cpu else "value"}
        if not isinstance(entry, dict) or set(entry) not in (expected_fields,
                                                             expected_fields | {"formatted"}):
            raise RuntimeError("raw map dump: malformed cell")
        if "formatted" in entry and not isinstance(entry["formatted"], dict):
            raise RuntimeError("raw map dump: malformed formatted metadata")
        key = _raw_bytes(entry["key"], metadata["bytes_key"])
        identity = tuple(key)
        if identity in keys:
            raise RuntimeError("raw map dump: duplicate key")
        keys.add(identity)
        if array and int.from_bytes(bytes(int(byte, 16) for byte in key), "little") >= metadata["max_entries"]:
            raise RuntimeError("raw map dump: invalid array key")
        if not per_cpu:
            result.append({"key": key,
                           "value": _raw_bytes(entry["value"], metadata["bytes_value"])})
            continue
        values = entry["values"]
        if (not isinstance(values, list) or not values
                or any(not isinstance(row, dict) or set(row) != {"cpu", "value"}
                       for row in values)):
            raise RuntimeError("raw map dump: malformed per-CPU values")
        cpus = [row["cpu"] for row in values]
        if (any(not snapshot_uint(cpu, 32) for cpu in cpus)
                or len(cpus) != len(set(cpus)) or set(cpus) != set(possible_cpus)):
            raise RuntimeError("raw map dump: incomplete or duplicate CPU values")
        rows = {row["cpu"]: row for row in values}
        result.append({"key": key, "values": [{
            "cpu": cpu, "value": _raw_bytes(rows[cpu]["value"], metadata["bytes_value"])
        } for cpu in possible_cpus]})
    if array and len(keys) != metadata["max_entries"]:
        raise RuntimeError("raw map dump: incomplete array keys")
    return result


def refused_lookup_metadata(metadata):
    """The exact shape a refusal oracle applies to, or a refusal to proceed.

    The kernel itself only builds an fd array with 4-byte keys and values
    (`fd_array_map_alloc_check`), so anything else claiming this oracle is not
    the map the refusal would be about.
    """
    snapshot_map_metadata(metadata)
    if metadata["oracle"] != "refused-lookup" or metadata["type"] != "cgroup_array":
        raise RuntimeError("stopped map refusal: invalid map or result")
    if (metadata["bytes_key"], metadata["bytes_value"]) != (4, 4):
        raise RuntimeError("stopped map refusal: malformed fd-array metadata")


def probe_refused_lookup(item, *, fd=None):
    """Ask the kernel for every key of a map whose values it will not return.

    This is the whole content oracle for a cgroup_array: `bpftool map dump`
    reports the same failure as a per-cell `{"error": "Unknown error 524"}`
    blob, which is glibc's `strerror` text for the kernel's -ENOTSUPP and not
    a kernel fact. Record the raw errno instead, one cell per key, so a future
    kernel that does answer the lookup turns the lane RED rather than passing
    a readable map off under a refusal. Callers that already retain a
    descriptor pass it; otherwise one is acquired by map id for the probe.
    """
    refused_lookup_metadata(item)
    libc = ctypes.CDLL(None, use_errno=True)
    acquired = fd is None
    if acquired:
        attr = ctypes.create_string_buffer(BPF_ATTR_MAP_ID.pack(item["id"], 0, 0))
        fd = libc.syscall(BPF_SYSCALL, BPF_MAP_GET_FD_BY_ID,
                          ctypes.byref(attr), ctypes.sizeof(attr))
        if fd < 0:
            raise OSError(ctypes.get_errno(), "retain refused-lookup map")
    cells = []
    try:
        for index in range(item["max_entries"]):
            key = ctypes.create_string_buffer(
                index.to_bytes(item["bytes_key"], "little"), item["bytes_key"])
            value = ctypes.create_string_buffer(item["bytes_value"])
            attr = ctypes.create_string_buffer(BPF_ATTR_MAP_ELEM.pack(
                fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
            ctypes.set_errno(0)
            result = libc.syscall(BPF_SYSCALL, BPF_MAP_LOOKUP_ELEM,
                                  ctypes.byref(attr), ctypes.sizeof(attr))
            cells.append({"key": list(key.raw),
                          "errno": ctypes.get_errno() if result < 0 else 0})
    finally:
        if acquired:
            os.close(fd)
    return cells


def normalize_refused_lookup(cells, metadata):
    """Retain the kernel's own per-key refusal, and never a value beside it.

    No value was read, so a value here was invented; an empty list witnesses
    nothing at all; and an errno other than ENOTSUPP says this map is not the
    map the oracle claims -- 0 that a value came back, ENOENT that the lookup
    is supported and the slot is merely empty. Each is a deliberate oracle
    change, not something to accept quietly.
    """
    refused_lookup_metadata(metadata)
    if not isinstance(cells, list) or len(cells) != metadata["max_entries"]:
        raise RuntimeError("stopped map refusal: incomplete refusal population")
    result = []
    keys = set()
    for cell in cells:
        if not isinstance(cell, dict) or set(cell) != {"key", "errno"}:
            raise RuntimeError("stopped map refusal: malformed cell")
        key = _raw_bytes(cell["key"], metadata["bytes_key"])
        index = int.from_bytes(bytes(int(byte, 16) for byte in key), "little")
        if index >= metadata["max_entries"]:
            raise RuntimeError("stopped map refusal: invalid array key")
        if index in keys:
            raise RuntimeError("stopped map refusal: duplicate key")
        keys.add(index)
        if type(cell["errno"]) is not int or cell["errno"] != ENOTSUPP:
            raise RuntimeError("stopped map refusal: value was read or refusal is unexplained")
        result.append({"key": key, "errno": ENOTSUPP})
    return result


def refusal_probe():
    """Privileged: prove on this kernel that a cgroup_array refuses lookups.

    Creating one costs nothing and reads nothing, but it is the only check
    that would notice a kernel which starts answering the lookup. On such a
    kernel the refusal is no longer the honest oracle for CGROUP_FILTER, and
    the lanes must stop here rather than accept a readable map under it.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.create_string_buffer(BPF_ATTR_MAP_CREATE.pack(
        BPF_MAP_TYPE_CGROUP_ARRAY, 4, 4, 1, 0, 0, 0, b"REFUSAL_PROBE"), BPF_ATTR_BYTES)
    ctypes.set_errno(0)
    fd = libc.syscall(BPF_SYSCALL, BPF_MAP_CREATE, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "create the cgroup_array refusal probe")
    try:
        info = ctypes.create_string_buffer(BPF_MAP_INFO.size)
        attr = ctypes.create_string_buffer(BPF_ATTR_OBJ_INFO.pack(
            fd, BPF_MAP_INFO.size, ctypes.addressof(info)), BPF_ATTR_OBJ_INFO.size)
        ctypes.set_errno(0)
        if libc.syscall(BPF_SYSCALL, BPF_OBJ_GET_INFO_BY_FD,
                        ctypes.byref(attr), ctypes.sizeof(attr)) < 0:
            raise OSError(ctypes.get_errno(), "identify the cgroup_array refusal probe")
        map_type, map_id, bytes_key, bytes_value, max_entries, map_flags = BPF_MAP_INFO.unpack(info.raw)
        if map_type != BPF_MAP_TYPE_CGROUP_ARRAY:
            raise RuntimeError(f"refusal probe is not a cgroup_array: type={map_type}")
        item = {"id": map_id, "name": "REFUSAL_PROBE", "type": "cgroup_array",
                "bytes_key": bytes_key, "bytes_value": bytes_value,
                "max_entries": max_entries, "map_flags": map_flags,
                "oracle": "refused-lookup"}
        cells = normalize_refused_lookup(probe_refused_lookup(item, fd=fd), item)
    finally:
        os.close(fd)
    if cells != [{"key": ["0x00"] * 4, "errno": ENOTSUPP}]:
        raise RuntimeError(f"unexpected cgroup_array refusal: {cells}")
    print(f"cgroup_array userspace lookup is refused ENOTSUPP={ENOTSUPP}: OK")


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
    """Acquire native frames under _run_bounded_bytes' caller preconditions."""
    if (not snapshot_uint(observer_pid, 32, positive=True)
            or not snapshot_uint(max_records, 32, positive=True)
            or max_records > TASK_STORAGE_MAX_RECORDS
            or not snapshot_uint(max_bytes, 32, positive=True)
            or max_bytes > TASK_STORAGE_MAX_BYTES
            or type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= 60 or not math.isfinite(timeout_seconds)):
        raise RuntimeError("task-storage reader has invalid bounds")
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
    returncode, output, diagnostic = _run_bounded_bytes(
        arguments, timeout_seconds=timeout_seconds, max_bytes=output_limit,
        label="task-storage reader",
    )
    if returncode:
        raise RuntimeError(
            f"task-storage reader failed with status {returncode}: {bounded_diagnostic(diagnostic)}"
        )
    return output


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


def snapshot_uint(value, bits=64, *, positive=False):
    return type(value) is int and (1 if positive else 0) <= value < (1 << bits)


def stopped_roster(rows, *, expected=False):
    """Validate bounded physical identities; generation is /proc starttime ticks.

    Only a confirmed group stop (T), not a ptrace stop (t), qualifies. The
    coordinator must prevent exec/clone/exit over both roster samples.
    """
    if not isinstance(rows, list) or not 0 < len(rows) <= TASK_STORAGE_MAX_RECORDS:
        raise RuntimeError("stopped roster: missing, empty or oversized task list")
    result = {}
    fields = {"pid", "tid", "generation"} | (
        {"cookie", "owner", "root"} if expected else {"state"})
    for row in rows:
        if (not isinstance(row, dict) or set(row) != fields
                or not snapshot_uint(row.get("pid"), 32, positive=True)
                or not snapshot_uint(row.get("tid"), 32, positive=True)
                or not snapshot_uint(row.get("generation"), positive=True)):
            raise RuntimeError("stopped roster: malformed task identity or fields")
        if row["tid"] in result:
            raise RuntimeError(f"stopped roster: duplicate or reused tid={row['tid']}")
        if expected:
            if any(type(row[key]) is not bool for key in ("cookie", "owner", "root")):
                raise RuntimeError("stopped roster: malformed population expectation")
            if row["cookie"] and row["pid"] != row["tid"]:
                raise RuntimeError("stopped roster: TASK_COOKIE requires a leader")
        elif row["state"] != "T":
            raise RuntimeError(f"stopped roster: unconfirmed group stop tid={row['tid']}")
        result[row["tid"]] = row
    if any(row["pid"] not in result or result[row["pid"]]["pid"] != row["pid"]
           for row in result.values()):
        raise RuntimeError("stopped roster: missing group leader")
    return result


def snapshot_map_metadata(item):
    if (not isinstance(item, dict)
            or not snapshot_uint(item.get("id"), 32, positive=True)
            or any(not snapshot_uint(item.get(key), 32) for key in (
                "bytes_key", "bytes_value", "max_entries", "map_flags"))):
        raise RuntimeError("stopped map: invalid numeric metadata")
    name = item.get("name")
    map_type = item.get("type")
    if type(name) is not str or re.fullmatch(r"[A-Z0-9_]{1,32}", name) is None:
        raise RuntimeError("stopped map: invalid textual metadata")
    if type(map_type) is not str or map_type not in SNAPSHOT_MAP_ORACLES:
        raise RuntimeError("stopped map: invalid textual metadata")
    if item.get("oracle") != SNAPSHOT_MAP_ORACLES[map_type]:
        raise RuntimeError("stopped map: invalid textual metadata")


def reconcile_task_storage(maps, records, *, expected, before, after, controls,
                           lane, small_state=False):
    """Pure population check after bounded framing/EOF validation.

    V1 frames contain pid/tid, not generation. Bind them to identical stopped
    before/after rosters here, and return generation-bearing identities in raw
    surface order for a later receipt. Replayed receipts must supply that same
    generation. This function neither acquires nor publishes evidence and does
    not establish pidfd custody; the Task 3C coordinator owns that obligation.
    Controls are exact map metadata plus complete raw single-cell values.
    """
    roster = stopped_roster(expected, expected=True)
    def identity(row):
        return row["pid"], row["tid"], row["generation"]

    wanted_roster = {identity(row) for row in roster.values()}
    for sample in (before, after):
        if {identity(row) for row in stopped_roster(sample).values()} != wanted_roster:
            raise RuntimeError("stopped roster: expected/before/after identity mismatch")
    if lane not in ("external", "owned-root") or type(small_state) is not bool:
        raise RuntimeError("stopped roster: invalid lane or state-map configuration")
    roots = {identity(row) for row in roster.values() if row["root"]}
    if (lane == "external" and roots) or (lane == "owned-root" and not roots):
        raise RuntimeError("stopped roster: root expectations contradict lane")
    if not isinstance(maps, list) or len(maps) != 3:
        raise RuntimeError("stopped map: invalid task-storage inventory")
    for item in maps:
        snapshot_map_metadata(item)
    ordered = task_storage_specs(maps)
    by_id = {item["id"]: item for item in ordered}
    if any(not snapshot_uint(map_id, 32, positive=True) for map_id in by_id):
        raise RuntimeError("stopped map: invalid task-storage map identity")
    if not isinstance(records, list) or len(records) > TASK_STORAGE_MAX_RECORDS:
        raise RuntimeError("stopped map: missing or oversized record population")
    seen = {item["name"]: set() for item in ordered}
    bound = {item["name"]: [] for item in ordered}
    for record in records:
        if (not isinstance(record, dict)
                or not snapshot_uint(record.get("map_id"), 32, positive=True)
                or record["map_id"] not in by_id):
            raise RuntimeError("stopped map: unexpected record map identity")
        item = by_id[record["map_id"]]
        context = f"stopped map id={item['id']} name={item['name']}"
        if (not snapshot_uint(record.get("pid"), 32, positive=True)
                or not snapshot_uint(record.get("tid"), 32, positive=True)):
            raise RuntimeError(f"{context}: invalid task identity")
        task = roster.get(record["tid"])
        if task is None or task["pid"] != record["pid"]:
            raise RuntimeError(f"{context}: foreign identity pid={record['pid']} tid={record['tid']}")
        if "generation" in record and (
                not snapshot_uint(record["generation"], positive=True)
                or record["generation"] != task["generation"]):
            raise RuntimeError(f"{context}: reused identity tid={record['tid']}")
        key = identity(task)
        if key in seen[item["name"]]:
            raise RuntimeError(f"{context}: duplicate identity tid={record['tid']}")
        seen[item["name"]].add(key)
        bound[item["name"]].append({k: task[k] for k in ("pid", "tid", "generation")})
        if type(record.get("value")) is not bytes or len(record["value"]) != item["bytes_value"]:
            raise RuntimeError(f"{context}: invalid value length")
    for name, flag in zip(TASK_STORAGE_NAMES, ("cookie", "owner", "root")):
        required = {identity(row) for row in roster.values() if row[flag]}
        if seen[name] != required:
            item = next(item for item in ordered if item["name"] == name)
            raise RuntimeError(f"stopped map id={item['id']} name={name}: population identity mismatch")

    control_sizes = {"COOKIE_CTL": 40, "OWNER_CTL": 56, "ROOT_CTL": 64}
    if not isinstance(controls, dict) or set(controls) != set(control_sizes):
        raise RuntimeError("stopped control maps: missing exact COOKIE_CTL/OWNER_CTL/ROOT_CTL")
    words = {}
    ids = set(by_id)
    for name, size in control_sizes.items():
        cell = controls[name]
        context = f"stopped control map name={name}"
        if (not isinstance(cell, dict)
                or not snapshot_uint(cell.get("id"), 32, positive=True)
                or cell["id"] in ids):
            raise RuntimeError(f"{context}: invalid map identity")
        snapshot_map_metadata(cell)
        ids.add(cell["id"])
        context += f" id={cell['id']}"
        if (tuple(cell.get(key) for key in ("type", "bytes_key", "bytes_value", "max_entries", "map_flags"))
                != ("array", 4, size, 1, 0)
                or type(cell.get("value")) is not bytes or len(cell["value"]) != size):
            raise RuntimeError(f"{context}: malformed metadata or value")
        values = struct.unpack("<" + "Q" * (size // 8), cell["value"])
        words[name] = values
        if name == "COOKIE_CTL":
            healthy = values[0] == 16384 and values[1] <= 16384 and not any(values[2:])
        elif name == "OWNER_CTL":
            limit = 65 if small_state else 16448
            healthy = values[0] == limit and values[1] == len(seen["THREAD_OWNER"]) <= limit and not any(values[2:])
        else:
            limit = 3 if small_state else 16384
            healthy = values[0] == len(roots) <= limit and not any(values[1:])
        if not healthy:
            raise RuntimeError(f"{context}: unhealthy or inconsistent control")
    tickets = set()
    for record in records:
        item = by_id[record["map_id"]]
        name = item["name"]
        raw = record["value"]
        context = f"stopped map id={item['id']} name={name} tid={record['tid']}"
        if name == "TASK_COOKIE":
            ticket, = struct.unpack("<Q", raw)
            if not 0 < ticket <= words["COOKIE_CTL"][1] or ticket in tickets:
                raise RuntimeError(f"{context}: value contradicts COOKIE_CTL allocation history")
            tickets.add(ticket)
        elif name == "ROOT_AFFILIATION":
            if struct.unpack("<Q", raw)[0] != 1:
                raise RuntimeError(f"{context}: invalid affiliation value")
        else:
            original, = struct.unpack_from("<Q", raw)
            cookies = struct.unpack_from("<64Q", raw, 8)
            occupied, domains, starts, flags = struct.unpack_from("<QQII", raw, 520)
            if original != (record["pid"] << 32) | record["tid"]:
                raise RuntimeError(f"{context}: value ownership identity mismatch")
            if (flags != 1 or starts > 512 or domains & ~occupied
                    or starts == occupied == 0):
                raise RuntimeError(f"{context}: invalid production tail value")
            directory = set()
            for index, cookie in enumerate(cookies):
                bit = 1 << index
                if not occupied & bit:
                    if cookie:
                        raise RuntimeError(f"{context}: unoccupied directory value")
                else:
                    key = (cookie, bool(domains & bit))
                    if key in directory:
                        raise RuntimeError(f"{context}: duplicate directory value")
                    directory.add(key)
    return bound


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
        {"name": "CGROUP_FILTER", "type": "cgroup_array"},
        {"name": "TASK_COOKIE", "type": "task_storage"},
        {"name": "THREAD_OWNER", "type": "task_storage"},
        {"name": "ROOT_AFFILIATION", "type": "task_storage"},
    ]
    assert [map_oracle(item) for item in inventory] == [
        "mmap", "mmap", "dump", "dump", "refused-lookup",
        "task-storage", "task-storage", "task-storage"
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

    def reject(label, thunk):
        try:
            thunk()
        except RuntimeError:
            return
        raise AssertionError(f"{label} was accepted")

    # The dispatcher and the validation table are now one table, so a row can
    # never claim an oracle its type does not have -- in either direction.
    filter_map = {"id": 7, "name": "CGROUP_FILTER", "type": "cgroup_array",
                  "bytes_key": 4, "bytes_value": 4, "max_entries": 1, "map_flags": 0,
                  "oracle": "refused-lookup"}
    snapshot_map_metadata(filter_map)
    reject("cgroup_array claiming a dump",
           lambda: snapshot_map_metadata({**filter_map, "oracle": "dump"}))
    reject("hash claiming a refused lookup",
           lambda: snapshot_map_metadata({**filter_map, "type": "hash", "oracle": "refused-lookup"}))
    # An empty list is what `bpftool map dump` on an unreadable map would have
    # to be believed as. It is not a dump of anything, so it is not one here.
    reject("cgroup_array normalized as an empty dump",
           lambda: normalize_map_dump([], filter_map))
    print("a cgroup_array is never dumpable, even empty: OK")

    # The positive control both ways: raw probe bytes canonicalize, and the
    # retained receipt replays to exactly the bytes that were retained.
    refusal = [{"key": ["0x00", "0x00", "0x00", "0x00"], "errno": ENOTSUPP}]
    assert normalize_refused_lookup([{"key": [0, 0, 0, 0], "errno": ENOTSUPP}],
                                    filter_map) == refusal
    assert normalize_refused_lookup(refusal, filter_map) == refusal
    for label, cells in (
        # Zeroes nobody read, with or without the refusal kept beside them.
        ("fabricated value cell", [{"key": [0] * 4, "value": [0] * 4}]),
        ("refusal carrying a value", [{"key": [0] * 4, "errno": ENOTSUPP, "value": [0] * 4}]),
        ("refusal carrying per-CPU values", [{"key": [0] * 4, "values": [{"cpu": 0, "value": [0] * 4}]}]),
        # A readable map is a different map: 0 returned a value, ENOENT says
        # the lookup is supported and the slot is empty.
        ("value returned instead of a refusal", [{"key": [0] * 4, "errno": 0}]),
        ("supported lookup of an empty slot", [{"key": [0] * 4, "errno": 2}]),
        ("errno as text", [{"key": [0] * 4, "errno": "524"}]),
        ("errno as a boolean", [{"key": [0] * 4, "errno": True}]),
        ("no refusal at all", []),
        ("duplicate key", [{"key": [0] * 4, "errno": ENOTSUPP}] * 2),
        ("key beyond max_entries", [{"key": [1, 0, 0, 0], "errno": ENOTSUPP}]),
        ("more cells than keys",
         [{"key": [0] * 4, "errno": ENOTSUPP}, {"key": [1, 0, 0, 0], "errno": ENOTSUPP}]),
        ("key of the wrong width", [{"key": [0] * 8, "errno": ENOTSUPP}]),
    ):
        reject(label, lambda cells=cells: normalize_refused_lookup(cells, filter_map))
    reject("refusal claiming a dumpable map",
           lambda: normalize_refused_lookup(refusal, {**filter_map, "type": "hash", "oracle": "dump"}))
    print("a refused lookup records the kernel errno and never a value: OK")
    print("dump-owned-bpf-maps self-test: OK")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.argv[1:] == ["--refusal-probe"]:
        refusal_probe()
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
        info = normalize_map_metadata(
            one(run_json(["bpftool", "-j", "map", "show", "id", str(map_id)])),
            map_id,
        )
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
            entries = normalize_map_dump(
                run_json(
                    ["bpftool", "-j", "map", "dump", "id", str(start["id"])],
                    require_list=True, map_identity=start,
                ),
                start,
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
    possible_cpus = possible_cpu_ids() if any(
        item["type"] in ("percpu_hash", "percpu_array") for item in maps) else None
    for item in maps:
        name = item["name"]
        record = {
            "id": item["id"],
            "name": name,
            "type": item.get("type"),
            "key_size": item.get("bytes_key"),
            "value_size": item.get("bytes_value"),
            "max_entries": item.get("max_entries"),
            "map_flags": item.get("map_flags"),
            "oracle": map_oracle(item),
        }
        if record["oracle"] == "task-storage":
            task_records.append((item, record))
        if record["oracle"] == "dump":
            output = out_dir / f"mapdump_{name}{suffix}.json"
            dumped = normalize_map_dump(
                run_json(
                    ["bpftool", "-j", "map", "dump", "id", str(item["id"])],
                    require_list=True, map_identity=item,
                ),
                item, possible_cpus=possible_cpus,
            )
            write_receipt(output, json.dumps(dumped, separators=(",", ":")) + "\n")
            record["file"] = str(output)
        elif record["oracle"] == "refused-lookup":
            output = out_dir / f"mapdump_{name}{suffix}.json"
            refused = normalize_refused_lookup(probe_refused_lookup(item), item)
            write_receipt(output, json.dumps(refused, separators=(",", ":")) + "\n")
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
