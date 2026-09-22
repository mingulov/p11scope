#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create fail-closed identities for the system-scope measurement harness.

The mapping command hashes the object opened through the live process's
``/proc/PID/map_files`` entry. Pathnames are labels. The receipt preserves the
mapping device domain separately from opened-file fstat/hash identity and
records the exact addressed map_files relation that joins them.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import select
import signal
import sys
import tempfile
import time
from pathlib import Path


MAPPING_SCHEMA = "p11scope/workload-mapping-receipt/v1"
MAPPING_BRIDGE_SCHEMA = "p11scope/map-files-mountinfo-bridge/v1"
WRAPPER_SETTLEMENT_SCHEMA = "p11scope/wrapper-settlement/v1"
MAX_MOUNTINFO_BYTES = 2 * 1024 * 1024
HANDSHAKE = re.compile(
    r"^pid=(?P<pid>[1-9][0-9]*) starttime=(?P<starttime>[1-9][0-9]*) "
    r"endpoint=(?P<endpoint>0x[0-9a-fA-F]+)$"
)


class ReceiptError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReceiptError(message)


def canonical_bool(value):
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("boolean must be true or false")


def bounded_diagnostic(path, limit=4096, *, opener=open):
    """Read one diagnostic with a limit-plus-one truncation proof."""
    with opener(path, "rb") as stream:
        raw = stream.read(limit + 1)
    captured = raw[:limit]
    return (captured.decode("utf-8", "replace"), len(raw) > limit,
            len(captured))


def decode_wrapper_result(path, expected_pid, expected_starttime, *, opener=open):
    """Bound and strictly validate the sole wrapper terminal-proof protocol."""
    try:
        with opener(path, "rb") as stream:
            raw = stream.read(65_537)
        require(len(raw) <= 65_536,
                "wrapper cleanup result exceeds 65536-byte bound")
        value = json.loads(raw.decode("utf-8"))
    except ReceiptError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReceiptError(
            f"wrapper cleanup result cannot be decoded: {type(error).__name__}: {error}"
        ) from error
    require(type(value) is dict, "wrapper cleanup result is not an object")
    require(value.get("schema") == WRAPPER_SETTLEMENT_SCHEMA,
            "wrapper cleanup result schema is invalid")
    require(type(value.get("pid")) is int
            and value["pid"] == expected_pid,
            "wrapper cleanup result PID identity is invalid")
    require(type(value.get("starttime")) is int
            and value["starttime"] == expected_starttime,
            "wrapper cleanup result birth identity is invalid")
    require(type(value.get("terminal")) is bool,
            "wrapper cleanup terminal field is not boolean")
    require(type(value.get("signals")) is list,
            "wrapper cleanup signals field is not a list")
    require(type(value.get("signal_failures")) is list,
            "wrapper cleanup signal_failures field is not a list")
    return value


def validate_wrapper_result(args):
    result = decode_wrapper_result(args.result, args.pid, args.starttime)
    return "terminal" if result["terminal"] is True else "nonterminal"


def atomic_replace_json(path, value):
    path = Path(path)
    original = path.stat()
    require(original.st_uid == os.geteuid(),
            "receipt is not owned by the updating caller")
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".tmp.", dir=path.parent)
    try:
        payload = (json.dumps(value, sort_keys=True) + "\n").encode()
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
        os.fchmod(fd, original.st_mode & 0o777)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def record_wrapper_cleanup(args):
    try:
        cleanup = decode_wrapper_result(
            args.result, args.pid, args.starttime)
    except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError,
            TypeError, ValueError) as error:
        cleanup = {
            "schema": WRAPPER_SETTLEMENT_SCHEMA,
            "pid": args.pid, "starttime": args.starttime,
            "terminal": False, "signals": [], "signal_failures": [],
            "protocol_error": f"{type(error).__name__}: {error}",
        }
    error, error_truncated, error_bytes = bounded_diagnostic(args.error)
    cleanup.update(
        helper_status=args.helper_status,
        reaped=args.reaped,
        wrapper_exit=args.wrapper_exit,
        helper_error=error,
        helper_error_truncated=error_truncated,
        helper_error_captured_bytes=error_bytes,
    )
    failed = (args.helper_status != 0 or cleanup.get("terminal") is not True
              or args.reaped is not True or bool(cleanup.get("signal_failures")))
    cleanup["qualification_failed"] = failed
    receipt_path = Path(args.receipt)
    record = json.loads(receipt_path.read_text(encoding="utf-8"))
    attempts = record.get("outer_wrapper_cleanup_attempts", [])
    require(isinstance(attempts, list), "wrapper cleanup attempt ledger is malformed")
    attempts.append(cleanup)
    dropped = record.get("outer_wrapper_cleanup_attempts_dropped", 0)
    require(isinstance(dropped, int) and dropped >= 0,
            "wrapper cleanup dropped-attempt count is malformed")
    if len(attempts) > 32:
        dropped += len(attempts) - 32
        attempts = attempts[-32:]
    previous = record.get("outer_wrapper_cleanup")
    previous_failed = False
    if isinstance(previous, dict):
        previous_failed = (
            previous.get("helper_status") != 0
            or previous.get("terminal") is not True
            or previous.get("reaped") is not True
            or bool(previous.get("signal_failures")))
    record["outer_wrapper_cleanup_attempts"] = attempts
    record["outer_wrapper_cleanup_attempts_dropped"] = dropped
    record["outer_wrapper_cleanup"] = cleanup
    record["outer_wrapper_cleanup_failed"] = bool(
        record.get("outer_wrapper_cleanup_failed", False)
        or previous_failed or failed
        or args.owner_failed
        or Path(str(receipt_path) + ".wrapper-owner-failed").exists())
    atomic_replace_json(receipt_path, record)
    return cleanup


def hash_fd(fd):
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def identity_from_fd(fd, path):
    info = os.fstat(fd)
    return {
        "path": str(Path(path).resolve()),
        "dev": [os.major(info.st_dev), os.minor(info.st_dev)],
        "ino": info.st_ino,
        "size": info.st_size,
        "sha256": hash_fd(fd),
    }


def file_identity(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return identity_from_fd(fd, path)
    finally:
        os.close(fd)


def physical(identity):
    return (tuple(identity["dev"]), identity["ino"], identity["sha256"])


def read_birth(proc_root, pid):
    text = (Path(proc_root) / str(pid) / "stat").read_text(encoding="utf-8").strip()
    close = text.rfind(")")
    require(close >= 0, f"PID {pid} stat has no command terminator")
    require(text[: text.find(" ")] == str(pid), f"PID {pid} stat names another PID")
    tail = text[close + 1 :].split()
    require(len(tail) > 19 and tail[19].isdigit(),
            f"PID {pid} stat has no starttime")
    return int(tail[19])


def read_mount_namespace(proc_root, pid):
    info = os.stat(Path(proc_root) / str(pid) / "ns" / "mnt")
    return {"dev": [os.major(info.st_dev), os.minor(info.st_dev)],
            "ino": info.st_ino}


def read_mountinfo(proc_root, pid):
    path = Path(proc_root) / str(pid) / "mountinfo"
    with path.open("rb") as stream:
        content = stream.read(MAX_MOUNTINFO_BYTES + 1)
    require(len(content) <= MAX_MOUNTINFO_BYTES,
            f"mountinfo exceeds {MAX_MOUNTINFO_BYTES}-byte bound")
    require(content.endswith(b"\n"), "mountinfo is partial (missing final newline)")
    return content


def fd_mount_id(fd):
    content = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="utf-8")
    values = [line.removeprefix("mnt_id:\t") for line in content.splitlines()
              if line.startswith("mnt_id:\t")]
    require(len(values) == 1 and values[0].isdigit(),
            "opened map_files fd mount identity is missing or malformed")
    return int(values[0])


def opened_mapping_identity(fd, mountinfo):
    mount_id = fd_mount_id(fd)
    try:
        text = mountinfo.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ReceiptError(f"mountinfo is not UTF-8: {error}") from error
    rows = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 3, f"malformed mountinfo row: {line!r}")
        require(fields[0].isdigit(),
                f"malformed mountinfo mount ID: {fields[0]!r}")
        if int(fields[0]) == mount_id:
            rows.append(fields)
    require(len(rows) == 1,
            f"fd mount {mount_id} resolves to {len(rows)} mountinfo rows")
    selected = rows[0]
    separators = [index for index, field in enumerate(selected)
                  if field == "-"]
    require(len(selected) >= 10
            and selected[1].isdigit()
            and selected[3].startswith("/")
            and selected[4].startswith("/")
            and len(separators) == 1
            and separators[0] >= 6
            and len(selected) - separators[0] - 1 >= 3,
            "selected mountinfo row is structurally incomplete")
    device = selected[2]
    match = re.fullmatch(r"([0-9]+):([0-9]+)", device)
    require(match is not None, f"malformed mountinfo device: {device!r}")
    info = os.fstat(fd)
    return {
        "mount_id": mount_id,
        "dev": [int(match[1]), int(match[2])],
        "ino": info.st_ino,
    }


def read_process(proc_root, pid):
    text = (Path(proc_root) / str(pid) / "stat").read_text(encoding="utf-8").strip()
    close = text.rfind(")")
    require(close >= 0, f"PID {pid} stat has no command terminator")
    require(text[: text.find(" ")] == str(pid), f"PID {pid} stat names another PID")
    tail = text[close + 1 :].split()
    require(len(tail) > 19 and tail[19].isdigit(),
            f"PID {pid} stat has no starttime")
    return {"pid": pid, "state": tail[0], "ppid": int(tail[1]),
            "pgrp": int(tail[2]), "session": int(tail[3]),
            "starttime": int(tail[19])}


def parse_maps(content):
    mappings = []
    for line in content.decode("utf-8", errors="strict").splitlines():
        fields = line.split(None, 5)
        require(len(fields) >= 5, f"malformed maps line: {line!r}")
        bounds = fields[0].split("-", 1)
        require(len(bounds) == 2, f"malformed maps range: {fields[0]!r}")
        device = fields[3].split(":", 1)
        require(len(device) == 2, f"malformed maps device: {fields[3]!r}")
        mappings.append({
            "start": int(bounds[0], 16),
            "end": int(bounds[1], 16),
            "perms": fields[1],
            "offset": int(fields[2], 16),
            "dev": [int(device[0], 16), int(device[1], 16)],
            "ino": int(fields[4]),
            "path": fields[5] if len(fields) == 6 else "",
        })
    return mappings


def read_maps(proc_root, pid):
    content = (Path(proc_root) / str(pid) / "maps").read_bytes()
    return content, parse_maps(content)


def addressed_mapping(mappings, address):
    matches = [mapping for mapping in mappings
               if mapping["start"] <= address < mapping["end"]
               and "x" in mapping["perms"]]
    require(len(matches) == 1,
            f"endpoint address 0x{address:x} resolves to {len(matches)} executable mappings")
    return matches[0]


def parse_handshake(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    match = HANDSHAKE.fullmatch(text)
    require(match is not None, "mapped handshake is malformed")
    return int(match["pid"]), int(match["starttime"]), int(match["endpoint"], 16)


def same_mapping(left, right):
    keys = ("start", "end", "perms", "offset", "dev", "ino")
    return all(left[key] == right[key] for key in keys)


def report_identity_bridge(receipt):
    mapping = receipt.get("mapping_identity", {})
    mapping_record = receipt.get("mapping", {})
    opened_mapping = receipt.get("opened_mapping_identity", {})
    opened = receipt.get("opened_file_identity", receipt.get("pinned", {}))
    before_namespace = receipt.get("mount_namespace_identity_before")
    after_namespace = receipt.get("mount_namespace_identity_after")
    require(before_namespace == after_namespace
            and isinstance(before_namespace, dict),
            "mapping bridge mount namespace identity is invalid")
    require(type(opened_mapping.get("mount_id")) is int
            and opened_mapping["mount_id"] > 0,
            "mapping bridge mount ID is invalid")
    require(mapping.get("dev") == opened_mapping.get("dev")
            and mapping.get("ino") == opened_mapping.get("ino"),
            "mapping bridge mountinfo identity disagrees with maps")
    require(mapping.get("ino") == opened.get("ino"),
            "mapping bridge opened-file inode disagrees with maps")
    bridge = {
        "schema": MAPPING_BRIDGE_SCHEMA,
        "kind": "map_files_fdinfo_target_mountinfo",
        "mapping_identity": {
            "dev": mapping["dev"], "ino": mapping["ino"]},
        "opened_mapping_identity": {
            "mount_id": opened_mapping["mount_id"],
            "dev": opened_mapping["dev"], "ino": opened_mapping["ino"]},
        "opened_file_identity": {
            "dev": opened["dev"], "ino": opened["ino"],
            "sha256": opened["sha256"]},
    }
    stored = receipt.get("mapping_bridge")
    start_text = mapping_record.get("start")
    end_text = mapping_record.get("end")
    endpoint_text = receipt.get("endpoint_address")
    try:
        require(all(isinstance(value, str)
                    and re.fullmatch(r"0x[0-9a-f]+", value)
                    for value in (start_text, end_text, endpoint_text)),
                "mapping bridge endpoint proof is not canonical")
        start = int(start_text, 16)
        end = int(end_text, 16)
        endpoint = int(endpoint_text, 16)
        require(start < end and start <= endpoint < end,
                "mapping bridge endpoint is outside its executable range")
        require(re.fullmatch(r"[r-][w-]x[ps]",
                             str(mapping_record.get("perms"))) is not None,
                "mapping bridge range is not executable")
        exact_range = f"{start:x}-{end:x}"
    except (KeyError, TypeError, ValueError) as error:
        raise ReceiptError("mapping bridge endpoint proof is malformed") from error
    require(isinstance(stored, dict)
            and stored.get("schema") == MAPPING_BRIDGE_SCHEMA
            and stored.get("kind") == bridge["kind"]
            and stored.get("range") == exact_range
            and stored.get("mount_namespace_identity") == before_namespace
            and re.fullmatch(r"[0-9a-f]{64}",
                             str(stored.get("mountinfo_sha256"))) is not None
            and stored.get("report_identity_bridge") == bridge,
            "mapping bridge receipt is missing or forged")
    return bridge


def mapping_receipt(args):
    pid, handshake_birth, endpoint = parse_handshake(args.handshake)
    before_root = Path(args.proc_root)
    after_root = Path(args.after_proc_root or args.proc_root)
    birth_before = read_birth(before_root, pid)
    require(birth_before == handshake_birth,
            "mapped handshake PID birth identity does not match /proc")
    namespace_before = read_mount_namespace(before_root, pid)
    maps_before_bytes, maps_before = read_maps(before_root, pid)
    mapping_before = addressed_mapping(maps_before, endpoint)
    pin_name = f"{mapping_before['start']:x}-{mapping_before['end']:x}"
    pin_path = before_root / str(pid) / "map_files" / pin_name
    try:
        pin_fd = os.open(pin_path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES):
            raise ReceiptError(
                f"map_files pin permission denied (errno={error.errno})"
            ) from error
        raise ReceiptError(f"cannot pin live map_files/{pin_name}: {error}") from error
    try:
        pinned = identity_from_fd(pin_fd, pin_path)
        mountinfo_bytes = read_mountinfo(before_root, pid)
        opened_mapping = opened_mapping_identity(pin_fd, mountinfo_bytes)
        require(opened_mapping["dev"] == mapping_before["dev"]
                and opened_mapping["ino"] == mapping_before["ino"],
                "map_files mountinfo identity disagrees with addressed maps entry")

        # Keep the exact VMA descriptor alive while copy provenance and the
        # after snapshots are checked. Closing it earlier would discard the
        # kernel relation before the receipt is complete.
        expected = file_identity(args.expected_file)
        require(physical(pinned) == physical(expected),
                "pinned mapping does not match expected copy identity")
        source = file_identity(args.source_file) if args.source_file else None

        birth_after = read_birth(after_root, pid)
        require(birth_after == birth_before,
                "PID birth identity changed while pinning mapping")
        namespace_after = read_mount_namespace(after_root, pid)
        require(namespace_after == namespace_before,
                "PID mount namespace changed while pinning mapping")
        maps_after_bytes, maps_after = read_maps(after_root, pid)
        mapping_after = addressed_mapping(maps_after, endpoint)
        require(same_mapping(mapping_before, mapping_after),
                "addressed executable mapping changed while pinning")
        birth_final = read_birth(after_root, pid)
        require(birth_final == birth_before,
                "PID birth identity changed during final maps snapshot")
        namespace_final = read_mount_namespace(after_root, pid)
        require(namespace_final == namespace_before,
                "PID mount namespace changed during final maps snapshot")
        namespace_after = namespace_final
    finally:
        os.close(pin_fd)
    # `maps` reports the mapping superblock device while fstat reports the
    # opened file's device. These are intentionally different domains (for
    # example btrfs subvolumes), but opening the exact addressed map_files
    # range bridges them. Preserve both and require the inode relation rather
    # than silently normalizing one device into the other.
    require(pinned["ino"] == mapping_before["ino"],
            "addressed map_files inode disagrees with /proc/PID/maps")

    mapping_out = dict(mapping_before)
    mapping_out["start"] = f"0x{mapping_before['start']:x}"
    mapping_out["end"] = f"0x{mapping_before['end']:x}"
    mapping_out["offset"] = f"0x{mapping_before['offset']:x}"
    bridge = {
        "schema": MAPPING_BRIDGE_SCHEMA,
        "kind": "map_files_fdinfo_target_mountinfo",
        "range": pin_name,
        "mount_namespace_identity": namespace_before,
        "mountinfo_sha256": hashlib.sha256(mountinfo_bytes).hexdigest(),
    }
    receipt = {
        "schema": MAPPING_SCHEMA,
        "pid": pid,
        "starttime": birth_before,
        "endpoint_address": f"0x{endpoint:x}",
        "mapping": mapping_out,
        "mapping_identity": {
            "dev": mapping_before["dev"], "ino": mapping_before["ino"]},
        "opened_mapping_identity": opened_mapping,
        "pinned": pinned,
        "opened_file_identity": pinned,
        "mount_namespace_identity_before": namespace_before,
        "mount_namespace_identity_after": namespace_after,
        "expected": expected,
        "source": source,
        "maps_before_sha256": hashlib.sha256(maps_before_bytes).hexdigest(),
        "maps_after_sha256": hashlib.sha256(maps_after_bytes).hexdigest(),
    }
    bridge["report_identity_bridge"] = {
        "schema": MAPPING_BRIDGE_SCHEMA,
        "kind": bridge["kind"],
        "mapping_identity": receipt["mapping_identity"],
        "opened_mapping_identity": opened_mapping,
        "opened_file_identity": {
            "dev": pinned["dev"], "ino": pinned["ino"],
            "sha256": pinned["sha256"]},
    }
    receipt["mapping_bridge"] = bridge
    return receipt


def metadata(args):
    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    require(receipt.get("schema") == MAPPING_SCHEMA, "mapping receipt schema is invalid")
    copy = file_identity(args.copy_file)
    source = file_identity(args.source_file)
    observer = file_identity(args.observer)
    observer_source = (file_identity(args.observer_source)
                       if args.observer_source else None)
    opened = receipt.get("opened_file_identity", receipt.get("pinned", {}))
    mapping = receipt.get("mapping_identity", {})
    require(physical(copy) == physical(opened),
            "private provider copy changed after mapping receipt")
    require(mapping.get("dev") == receipt.get("mapping", {}).get("dev")
            and mapping.get("ino") == receipt.get("mapping", {}).get("ino"),
            "mapping identity disagrees with addressed maps entry")
    bridge = report_identity_bridge(receipt)
    require(copy["sha256"] == source["sha256"] and copy["size"] == source["size"],
            "private provider copy bytes differ from source")
    require((copy["dev"], copy["ino"]) != (source["dev"], source["ino"]),
            "private provider copy is not a distinct physical file")
    if observer_source is not None:
        require(observer["sha256"] == observer_source["sha256"]
                and observer["size"] == observer_source["size"],
                "private observer bytes differ from source")
        require((observer["dev"], observer["ino"]) !=
                (observer_source["dev"], observer_source["ino"]),
                "private observer is not a distinct physical file")
    # Reports describe modules in the maps device domain, while SHA-256 comes
    # from the exact opened map_files object. This joined identity is what the
    # parser can compare to report rows; the receipt retains both raw domains.
    identity = {
        "dev": mapping["dev"], "ino": mapping["ino"],
        "sha256": opened["sha256"], "path": copy["path"],
        "report_identity_associated": True,
        "report_identity_bridge": bridge,
    }
    return {
        "workload_module_identity": [identity],
        "workload_mapping_receipt": receipt,
        "provider_copy": {"source": source, "copy": copy},
        "observer_binary_identity": observer,
        "observer_source_identity": observer_source,
    }


def verify_file(args):
    expected = json.loads(Path(args.identity).read_text(encoding="utf-8"))
    if "observer_binary_identity" in expected:
        expected = expected["observer_binary_identity"]
    actual = file_identity(args.path)
    require(physical(actual) == physical(expected),
            f"file identity changed: {args.path}")
    return actual


def process_identity(args):
    return {"pid": args.pid, "starttime": read_birth(args.proc_root, args.pid)}


def inspect_process(args):
    """Classify one expected birth without converting read errors to death."""
    try:
        record = read_process(args.proc_root, args.pid)
    except FileNotFoundError:
        return {"pid": args.pid, "starttime": args.starttime,
                "state": "terminal", "reason": "absent"}
    except (OSError, UnicodeError, ReceiptError, ValueError) as error:
        return {"pid": args.pid, "starttime": args.starttime,
                "state": "unknown",
                "reason": f"{type(error).__name__}: {error}"}
    if record["starttime"] != args.starttime:
        return {"pid": args.pid, "starttime": args.starttime,
                "state": "terminal", "reason": "birth-replaced",
                "observed_starttime": record["starttime"]}
    if record["state"] in ("Z", "X", "x"):
        return {"pid": args.pid, "starttime": args.starttime,
                "state": "terminal", "reason": f"state-{record['state']}"}
    return {"pid": args.pid, "starttime": args.starttime,
            "state": "live", "process": record}


def signal_process(args):
    require(args.proc_root == "/proc", "process signalling requires live /proc")
    require(read_birth(args.proc_root, args.pid) == args.starttime,
            "process birth identity changed before signal")
    fd = os.pidfd_open(args.pid, 0)
    try:
        require(read_birth(args.proc_root, args.pid) == args.starttime,
                "process birth identity changed during signal custody")
        signal.pidfd_send_signal(fd, getattr(signal, f"SIG{args.signal}"))
    finally:
        os.close(fd)
    return {"pid": args.pid, "starttime": args.starttime,
            "signal": args.signal}


def settle_process(args):
    """Bounded identity-safe custody for one process, without tree discovery."""
    require(args.proc_root == "/proc", "process settlement requires live /proc")
    require(0 <= args.term_timeout <= args.total_timeout <= 60,
            "settlement timeouts must satisfy 0 <= term <= total <= 60")
    deadline = time.monotonic() + args.total_timeout
    inspected = inspect_process(args)
    require(inspected["state"] != "unknown",
            "process identity is unknown before settlement: " +
            inspected.get("reason", ""))
    result = {"pid": args.pid, "starttime": args.starttime,
              "schema": WRAPPER_SETTLEMENT_SCHEMA,
              "signals": [], "signal_failures": [], "terminal": False,
              "escalated": False, "total_timeout_seconds": args.total_timeout,
              "term_timeout_seconds": args.term_timeout,
              "inspection": inspected}
    if inspected["state"] == "terminal":
        result.update(terminal=True, already_terminal=True)
        return result
    fd = os.pidfd_open(args.pid, 0)
    try:
        inspected = inspect_process(args)
        require(inspected["state"] != "unknown",
                "process identity is unknown during settlement: " +
                inspected.get("reason", ""))
        if inspected["state"] == "terminal":
            result.update(terminal=True, already_terminal=True,
                          inspection=inspected)
            return result
        result["inspection"] = inspected
        if _pidfd_terminal(fd):
            result["terminal"] = True
            return result
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            result["signals"].append("SIGTERM")
        except OSError as error:
            result["signal_failures"].append(
                {"signal": "SIGTERM", "error": f"{type(error).__name__}: {error}"})
        term_wait = min(args.term_timeout, max(0, deadline - time.monotonic()))
        if select.select([fd], [], [], term_wait)[0]:
            result["terminal"] = True
            return result
        result["escalated"] = True
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            result["signals"].append("SIGKILL")
        except OSError as error:
            result["signal_failures"].append(
                {"signal": "SIGKILL", "error": f"{type(error).__name__}: {error}"})
        kill_wait = max(0, deadline - time.monotonic())
        result["terminal"] = bool(select.select([fd], [], [], kill_wait)[0])
        return result
    finally:
        os.close(fd)


def verify_group(args):
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            record = read_process(args.proc_root, args.pid)
            require(record["starttime"] == args.starttime,
                    "owned group leader birth identity changed")
            if (record["pgrp"] == args.pid and record["session"] == args.pid
                    and record["state"] not in ("Z", "X", "x")):
                return record
        except FileNotFoundError:
            pass
        time.sleep(0.005)
    raise ReceiptError("owned launch did not establish a live private session group")


def _scan_group(proc_root, leader, deadline):
    _before_deadline(deadline)
    members = []
    for entry in Path(proc_root).iterdir():
        _before_deadline(deadline)
        if not entry.name.isdigit():
            continue
        try:
            record = read_process(proc_root, int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        if record["pgrp"] == leader and record["session"] == leader:
            members.append(record)
    return members


def settle_group(args):
    """Settle one launch-time private session before its shell wait owner reaps.

    The unreaped session leader's verified generation anchors numeric killpg
    authority even when it is already terminal. Every observed member is also
    retained by pidfd and birth/group checked around acquisition.
    """
    require(args.proc_root == "/proc", "group settlement requires live /proc")
    require(0 < args.total_timeout <= 60 and 0 <= args.term_timeout <= 60,
            "group settlement timeouts are out of range")
    deadline = time.monotonic() + args.total_timeout
    leader = read_process(args.proc_root, args.pid)
    require(leader["starttime"] == args.starttime,
            "owned group leader birth identity changed")
    require(leader["pgrp"] == args.pid and leader["session"] == args.pid,
            "owned leader is not its private session group")
    leader_fd = os.pidfd_open(args.pid, 0)
    retained = {}

    def vanished(record):
        """Accept only proven disappearance, never a recycled numeric PID."""
        try:
            current = read_process(args.proc_root, record["pid"])
        except (FileNotFoundError, ProcessLookupError):
            return True
        require(current["starttime"] == record["starttime"],
                f"group member {record['pid']} identity changed after census")
        require(current["pgrp"] == args.pid and current["session"] == args.pid,
                f"group member {record['pid']} ownership changed after census")
        return False

    def acquire_members():
        _before_deadline(deadline)
        for record in _scan_group(args.proc_root, args.pid, deadline):
            pid = record["pid"]
            existing = retained.get(pid)
            if existing is not None:
                if _pidfd_terminal(existing["pidfd"]):
                    continue
                repeated = read_process(args.proc_root, pid)
                require(repeated["starttime"] == existing["starttime"]
                        and repeated["pgrp"] == args.pid
                        and repeated["session"] == args.pid,
                        f"retained group member {pid} identity changed")
                continue
            try:
                fd = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                if vanished(record):
                    continue
                raise
            try:
                try:
                    repeated = read_process(args.proc_root, pid)
                except (FileNotFoundError, ProcessLookupError):
                    if vanished(record):
                        os.close(fd)
                        continue
                    raise
                require(repeated["starttime"] == record["starttime"]
                        and repeated["pgrp"] == args.pid
                        and repeated["session"] == args.pid,
                        f"group member {pid} identity changed during custody")
                retained[pid] = {**record, "pidfd": fd}
            except BaseException:
                os.close(fd)
                raise

    def live_members():
        return [owned for owned in retained.values()
                if not _pidfd_terminal(owned["pidfd"])]

    try:
        acquire_members()
        # A second census closes the initial spawn/churn window or consumes the
        # shared deadline. No acquisition phase owns an unbounded loop.
        previous = None
        while previous != set(retained):
            previous = set(retained)
            acquire_members()
        first = getattr(signal, f"SIG{args.first_signal}")
        try:
            os.killpg(args.pid, first)
        except ProcessLookupError:
            pass
        term_deadline = min(deadline, time.monotonic() + args.term_timeout)
        while time.monotonic() < term_deadline:
            acquire_members()
            if not live_members():
                break
            time.sleep(min(0.01, max(0, term_deadline - time.monotonic())))
        escalated = [owned["pid"] for owned in live_members()]
        if escalated:
            try:
                os.killpg(args.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            acquire_members()
            live = live_members()
            if not live:
                break
            _before_deadline(deadline)
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        return {"pid": args.pid, "starttime": args.starttime,
                "targets": sorted(retained), "escalated": escalated,
                "first_signal": args.first_signal}
    finally:
        for owned in retained.values():
            os.close(owned["pidfd"])
        os.close(leader_fd)


def direct_children(proc_root, pid):
    """Snapshot direct children across every thread of one process."""
    children = []
    task_root = Path(proc_root) / str(pid) / "task"
    for path in task_root.glob("*/children"):
        try:
            words = path.read_text(encoding="ascii").split()
        except FileNotFoundError:
            continue
        for word in words:
            require(word.isdigit() and int(word) > 0,
                    f"PID {pid} children file is malformed")
            child = int(word)
            if child not in children:
                children.append(child)
    return children


def _before_deadline(deadline):
    require(time.monotonic() < deadline, "process custody acquisition deadline expired")


def _pidfd_terminal(fd):
    return bool(select.select([fd], [], [], 0)[0])


def acquire_process_tree(proc_root, pid, starttime, *, deadline=None):
    """Open verified pidfds for a stable snapshot of the owned process tree.

    Every descendant is birth-checked before and after pidfd_open and must
    still be a direct child of the already-custodied parent. Handles remain
    open for the caller's entire TERM/INT -> KILL lifecycle.
    """
    deadline = time.monotonic() + 10 if deadline is None else deadline
    _before_deadline(deadline)
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "pidfd signalling is unavailable")
    handles = []
    seen = set()

    def acquire(child, expected_birth, parent):
        _before_deadline(deadline)
        birth_before = read_birth(proc_root, child)
        require(birth_before == expected_birth,
                f"PID {child} birth identity changed before custody")
        handle = os.pidfd_open(child, 0)
        try:
            require(read_birth(proc_root, child) == birth_before,
                    f"PID {child} birth identity changed during custody")
            if parent is not None:
                require(child in direct_children(proc_root, parent["pid"]),
                        f"PID {child} left owned parent {parent['pid']} "
                        "during custody")
            owned = {"pid": child, "starttime": birth_before,
                     "parent": None if parent is None else parent["pid"],
                     "pidfd": handle}
            handles.append(owned)
            seen.add(child)
            return owned
        except BaseException:
            os.close(handle)
            raise

    try:
        root = acquire(pid, starttime, None)

        def validate_parent(parent):
            _before_deadline(deadline)
            require(read_birth(proc_root, parent["pid"]) == parent["starttime"],
                    f"retained parent {parent['pid']} identity changed")
            require(not _pidfd_terminal(parent["pidfd"]),
                    f"retained parent {parent['pid']} became terminal")
            _before_deadline(deadline)

        # Repeat until a full pass discovers nothing, so grandchildren and
        # children created during an earlier pass are also held before signal.
        changed = True
        while changed:
            changed = False
            for parent in list(handles):
                validate_parent(parent)
                children = direct_children(proc_root, parent["pid"])
                validate_parent(parent)
                for child in children:
                    if child in seen:
                        continue
                    try:
                        birth = read_birth(proc_root, child)
                        acquire(child, birth, parent)
                    except (FileNotFoundError, ProcessLookupError):
                        # A short-lived child may vanish between membership
                        # snapshot and pidfd_open. Skip only after it is no
                        # longer a member; an extant/replaced child fails.
                        if child not in direct_children(proc_root, parent["pid"]):
                            continue
                        raise
                    changed = True
        validate_parent(root)
        return handles
    except BaseException:
        for owned in handles:
            os.close(owned["pidfd"])
        raise


def send_handle(owned, sig):
    signal.pidfd_send_signal(owned["pidfd"], sig)


def wait_handles_terminal(handles, timeout):
    """Return handles still live after a bounded independent pidfd wait."""
    remaining = {owned["pidfd"]: owned for owned in handles}
    poller = select.poll()
    for fd in remaining:
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    deadline = time.monotonic() + timeout
    while remaining:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        for fd, _ in poller.poll(max(1, int(left * 1000))):
            if fd in remaining:
                poller.unregister(fd)
                del remaining[fd]
    return list(remaining.values())


def teardown_custody(handles, first_signal, term_timeout, kill_timeout,
                     *, send=send_handle, wait=wait_handles_terminal,
                     deadline=None):
    deadline = (time.monotonic() + term_timeout + kill_timeout
                if deadline is None else deadline)
    failures = []
    for owned in handles:
        try:
            send(owned, first_signal)
        except OSError as error:
            failures.append({"pid": owned["pid"], "signal": first_signal,
                             "error": str(error)})
    remaining = wait(handles, min(term_timeout,
                                  max(0, deadline - time.monotonic())))
    escalated = [owned["pid"] for owned in remaining]
    for owned in remaining:
        try:
            send(owned, signal.SIGKILL)
        except OSError as error:
            failures.append({"pid": owned["pid"], "signal": signal.SIGKILL,
                             "error": str(error)})
    remaining = wait(remaining, min(kill_timeout,
                                    max(0, deadline - time.monotonic())))
    require(not remaining,
            "owned processes not terminal after KILL: " +
            ", ".join(str(owned["pid"]) for owned in remaining))
    return {"targets": [owned["pid"] for owned in handles],
            "escalated": escalated, "signal_failures": failures}


def teardown_process(args):
    require(args.proc_root == "/proc",
            "process signalling is supported only against live /proc")
    require(0 <= args.term_timeout <= 60 and 0 <= args.kill_timeout <= 60,
            "teardown timeouts must be between zero and 60 seconds")
    require(0 < args.total_timeout <= 60,
            "total teardown timeout must be in (0, 60]")
    deadline = time.monotonic() + args.total_timeout
    handles = acquire_process_tree(
        args.proc_root, args.pid, args.starttime, deadline=deadline)
    try:
        result = teardown_custody(
            handles, getattr(signal, f"SIG{args.first_signal}"),
            args.term_timeout, args.kill_timeout, deadline=deadline)
        result.update(pid=args.pid, starttime=args.starttime,
                      first_signal=args.first_signal)
        return result
    finally:
        for owned in handles:
            os.close(owned["pidfd"])


def parser():
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    mapping = commands.add_parser("mapping")
    mapping.add_argument("--proc-root", default="/proc")
    mapping.add_argument("--after-proc-root")
    mapping.add_argument("--handshake", required=True)
    mapping.add_argument("--expected-file", required=True)
    mapping.add_argument("--source-file")
    file_command = commands.add_parser("file")
    file_command.add_argument("--path", required=True)
    meta = commands.add_parser("metadata")
    meta.add_argument("--receipt", required=True)
    meta.add_argument("--observer", required=True)
    meta.add_argument("--observer-source")
    meta.add_argument("--source-file", required=True)
    meta.add_argument("--copy-file", required=True)
    verify = commands.add_parser("verify-file")
    verify.add_argument("--identity", required=True)
    verify.add_argument("--path", required=True)
    process = commands.add_parser("process")
    process.add_argument("--proc-root", default="/proc")
    process.add_argument("--pid", required=True, type=int)
    inspect = commands.add_parser("inspect-process")
    inspect.add_argument("--proc-root", default="/proc")
    inspect.add_argument("--pid", required=True, type=int)
    inspect.add_argument("--starttime", required=True, type=int)
    signal_one = commands.add_parser("signal-process")
    signal_one.add_argument("--proc-root", default="/proc")
    signal_one.add_argument("--pid", required=True, type=int)
    signal_one.add_argument("--starttime", required=True, type=int)
    signal_one.add_argument("--signal", required=True, choices=("INT", "TERM"))
    settle_one = commands.add_parser("settle-process")
    settle_one.add_argument("--proc-root", default="/proc")
    settle_one.add_argument("--pid", required=True, type=int)
    settle_one.add_argument("--starttime", required=True, type=int)
    settle_one.add_argument("--term-timeout", default=1.0, type=float)
    settle_one.add_argument("--total-timeout", default=4.0, type=float)
    validate_wrapper = commands.add_parser("validate-wrapper-result")
    validate_wrapper.add_argument("--result", required=True)
    validate_wrapper.add_argument("--pid", required=True, type=int)
    validate_wrapper.add_argument("--starttime", required=True, type=int)
    wrapper = commands.add_parser("record-wrapper-cleanup")
    wrapper.add_argument("--receipt", required=True)
    wrapper.add_argument("--result", required=True)
    wrapper.add_argument("--error", required=True)
    wrapper.add_argument("--helper-status", required=True, type=int)
    wrapper.add_argument("--pid", required=True, type=int)
    wrapper.add_argument("--starttime", required=True, type=int)
    wrapper.add_argument("--reaped", required=True,
                         type=canonical_bool,
                         choices=(True, False))
    wrapper.add_argument("--wrapper-exit", required=True, type=int)
    wrapper.add_argument("--owner-failed", required=True,
                         type=canonical_bool, choices=(True, False))
    group = commands.add_parser("verify-group")
    group.add_argument("--proc-root", default="/proc")
    group.add_argument("--pid", required=True, type=int)
    group.add_argument("--starttime", required=True, type=int)
    group.add_argument("--timeout", default=2.0, type=float)
    settle = commands.add_parser("settle-group")
    settle.add_argument("--proc-root", default="/proc")
    settle.add_argument("--pid", required=True, type=int)
    settle.add_argument("--starttime", required=True, type=int)
    settle.add_argument("--first-signal", default="KILL",
                        choices=("TERM", "INT", "KILL"))
    settle.add_argument("--term-timeout", default=2.0, type=float)
    settle.add_argument("--total-timeout", default=10.0, type=float)
    teardown = commands.add_parser("teardown")
    teardown.add_argument("--proc-root", default="/proc")
    teardown.add_argument("--pid", required=True, type=int)
    teardown.add_argument("--starttime", required=True, type=int)
    teardown.add_argument("--first-signal", default="TERM",
                          choices=("TERM", "INT", "KILL"))
    teardown.add_argument("--term-timeout", default=5.0, type=float)
    teardown.add_argument("--kill-timeout", default=5.0, type=float)
    teardown.add_argument("--total-timeout", default=10.0, type=float)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate-wrapper-result":
            print(validate_wrapper_result(args))
            return 0
        if args.command == "mapping":
            result = mapping_receipt(args)
        elif args.command == "file":
            result = file_identity(args.path)
        elif args.command == "metadata":
            result = metadata(args)
        elif args.command == "verify-file":
            result = verify_file(args)
        elif args.command == "process":
            result = process_identity(args)
        elif args.command == "inspect-process":
            result = inspect_process(args)
        elif args.command == "signal-process":
            result = signal_process(args)
        elif args.command == "settle-process":
            result = settle_process(args)
        elif args.command == "record-wrapper-cleanup":
            result = record_wrapper_cleanup(args)
        elif args.command == "verify-group":
            result = verify_group(args)
        elif args.command == "settle-group":
            result = settle_group(args)
        else:
            result = teardown_process(args)
        print(json.dumps(result, sort_keys=True))
    except (OSError, UnicodeError, json.JSONDecodeError, ReceiptError,
            KeyError, TypeError) as error:
        print(f"receipt unknown: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
