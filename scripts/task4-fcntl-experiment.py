#!/usr/bin/python3
"""Private, refusal-only S9 normalization experiment."""

import hashlib
import json
import os
import stat
import sys
import tempfile


class ContractError(ValueError):
    def __init__(self, code):
        if code not in {"invalid", "tainted-output"}:
            raise ValueError("invalid")
        self.code = code

    def __str__(self):
        return self.code


_RECORD_SIZE = 128
_RAW_CAP = 128 * 1024 * 1024
_MAX_GENERATIONS = 4096
_MAX_INVOCATIONS = 65536
_MAX_ROWS = 1024
_AGGREGATE_CAP = 1 << 20
_INT_MAX = (1 << 31) - 1
_U64 = 1 << 64
_MAGIC = b"P11S9R1\0"

_SYSCALL_NUMBERS = {1: 57, 2: 58, 3: 56, 4: 435}
_KNOWN_KINDS = {
    1,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1A,
    0x20,
    0x21,
}
_COMMANDS = {
    0: "dupfd",
    1: "getfd",
    2: "setfd",
    3: "getfl",
    4: "setfl",
    1030: "dupfd-cloexec",
}
_COMMANDS.update({command: "lock" for command in (5, 6, 7, 36, 37, 38, 1029)})
_COMMANDS.update({command: "owner-signal" for command in (8, 9, 10, 11, 15, 16, 17)})
_COMMANDS.update({command: "lease" for command in (1024, 1025)})
_COMMANDS[1026] = "notify"
_COMMANDS.update({command: "pipe" for command in (1031, 1032)})
_COMMANDS.update({command: "seal" for command in (1033, 1034)})
_COMMANDS.update({command: "hint" for command in range(1035, 1039)})

_COMMAND_TOKENS = {
    "dupfd",
    "dupfd-cloexec",
    "getfd",
    "setfd",
    "getfl",
    "setfl",
    "lock",
    "owner-signal",
    "lease",
    "notify",
    "pipe",
    "seal",
    "hint",
    "unknown",
}
_ARGUMENT_TOKENS = {
    "zero",
    "stdio",
    "low-3-31",
    "medium-32-1023",
    "high-1024-int-max",
    "none",
    "cloexec",
    "fd-mask-other",
    "file-status-flags",
    "pointer",
    "owner-signal",
    "lease",
    "notify",
    "pipe",
    "seal",
    "hint",
    "unknown",
}
_RESULT_TOKENS = {
    "equal-floor",
    "above-floor",
    "none",
    "cloexec",
    "fd-mask-other",
    "success-zero",
    "success",
    "failure",
    "signed-ambiguous",
}
_ERRNO_TOKENS = {
    "none",
    "bad-fd",
    "invalid",
    "process-fd-limit",
    "system-fd-limit",
    "interrupted",
    "contended",
    "deadlock",
    "no-locks",
    "bad-pointer",
    "denied",
    "unsupported",
    "other",
}


def _invalid():
    raise ContractError("invalid")


def _tainted():
    raise ContractError("tainted-output")


def _u64(value):
    if type(value) is not int or not 0 <= value < _U64:
        _invalid()
    return value


def _fd(value):
    if type(value) is not int or value < 0:
        _invalid()
    return value


def _read_u16(record, offset):
    return int.from_bytes(record[offset : offset + 2], "little")


def _read_u32(record, offset):
    return int.from_bytes(record[offset : offset + 4], "little")


def _read_u64(record, offset):
    return int.from_bytes(record[offset : offset + 8], "little")


def _stat_fields(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _check_input_stat(info, *, size_required=None):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o7777 != 0o600
        or info.st_nlink != 1
        or (size_required is not None and info.st_size != size_required)
    ):
        _invalid()


def _parse_raw(raw_fd):
    _fd(raw_fd)
    try:
        before = os.fstat(raw_fd)
        _check_input_stat(before)
        if before.st_size <= 0 or before.st_size > _RAW_CAP:
            _invalid()
        if before.st_size % _RECORD_SIZE:
            _invalid()
        raw = os.pread(raw_fd, before.st_size, 0)
        after = os.fstat(raw_fd)
    except ContractError:
        raise
    except Exception:
        _invalid()
    if len(raw) != before.st_size or _stat_fields(before) != _stat_fields(after):
        _invalid()

    count = before.st_size // _RECORD_SIZE
    records = [raw[index : index + _RECORD_SIZE] for index in range(0, len(raw), _RECORD_SIZE)]
    for index, record in enumerate(records):
        if (
            record[:8] != _MAGIC
            or _read_u16(record, 8) != 1
            or _read_u32(record, 12) != 0
            or _read_u64(record, 16) != index
        ):
            _invalid()
        kind = _read_u16(record, 10)
        if kind not in _KNOWN_KINDS:
            _invalid()

    if count < 3 or _read_u16(records[0], 10) != 1 or _read_u16(records[1], 10) != 0x10:
        _invalid()
    if _read_u32(records[0], 24) != _RECORD_SIZE or _read_u32(records[0], 28) != 0x01020304:
        _invalid()
    if any(records[0][32:]) or _read_u64(records[1], 24) != 1 or any(records[1][32:]):
        _invalid()

    allowed_end = {
        1: 32,
        0x10: 32,
        0x11: 42,
        0x12: 42,
        0x13: 44,
        0x14: 58,
        0x15: 48,
        0x16: 50,
        0x17: 36,
        0x18: 36,
        0x19: 36,
        0x1A: 40,
        0x20: 88,
        0x21: 48,
    }
    for record in records:
        if any(record[allowed_end[_read_u16(record, 10)] :]):
            _invalid()

    generations = {}
    next_generation = 2
    next_creation = 1
    next_invocation = 1
    max_group = 1
    creations = {}
    invocations = {}
    rows = {}

    def generation(number, *, live=False):
        item = generations.get(number)
        if item is None:
            _invalid()
        if live and (not item["live"] or item["wif"] is not None or item["superseded"]):
            _invalid()
        return item

    for index, record in enumerate(records):
        kind = _read_u16(record, 10)
        if index == 2:
            if kind != 0x16:
                _invalid()
            if (
                _read_u64(record, 24) != 1
                or _read_u64(record, 32) != 0
                or _read_u64(record, 40) != 1
                or _read_u16(record, 48) != 1
            ):
                _invalid()
            generations[1] = {
                "group": 1,
                "live": True,
                "exit": None,
                "wif": None,
                "superseded": False,
                "creation": None,
                "fcntl": None,
            }
            continue
        if index < 3:
            continue

        if kind == 1:
            if index != 0:
                _invalid()
            continue
        if kind == 0x10:
            _invalid()
        if kind == 0x11:
            creation = _read_u64(record, 24)
            parent_number = _read_u64(record, 32)
            syscall_kind = _read_u16(record, 40)
            if creation != next_creation:
                _invalid()
            parent = generation(parent_number, live=True)
            if syscall_kind not in _SYSCALL_NUMBERS or parent["creation"] is not None or parent["fcntl"] is not None:
                _invalid()
            parent["creation"] = creation
            creations[creation] = {
                "parent": parent_number,
                "syscall": syscall_kind,
                "event": None,
                "join": None,
                "child": None,
                "child_group": None,
                "done": None,
                "exit": None,
            }
            next_creation += 1
        elif kind == 0x12:
            creation = _read_u64(record, 24)
            parent_number = _read_u64(record, 32)
            event_kind = _read_u16(record, 40)
            state = creations.get(creation)
            if (
                state is None
                or state["parent"] != parent_number
                or state["event"] is not None
                or event_kind not in (1, 2, 3)
                or state["exit"] is not None
            ):
                _invalid()
            parent = generation(parent_number, live=True)
            if state["syscall"] in (1, 2) and state["syscall"] != event_kind:
                _invalid()
            state["event"] = (index, event_kind)
            del parent
        elif kind == 0x13:
            creation = _read_u64(record, 24)
            parent_number = _read_u64(record, 32)
            outcome = _read_u16(record, 40)
            errno = _read_u16(record, 42)
            state = creations.get(creation)
            if state is None or state["parent"] != parent_number or state["exit"] is not None:
                _invalid()
            parent = generation(parent_number)
            if parent["wif"] is not None or parent["superseded"] or parent["fcntl"] is not None:
                _invalid()
            if outcome == 0:
                if not 1 <= errno <= 4095 or any(state[key] is not None for key in ("event", "join", "done")):
                    _invalid()
            elif outcome == 1:
                if errno != 0 or state["event"] is None:
                    _invalid()
                if state["event"][1] == 2 and (state["join"] is None or state["done"] is None):
                    _invalid()
                if state["event"][1] != 2 and state["done"] is not None:
                    _invalid()
            else:
                _invalid()
            state["exit"] = (index, outcome)
            state["closed"] = True
            parent["creation"] = None
        elif kind == 0x14:
            creation = _read_u64(record, 24)
            parent_number = _read_u64(record, 32)
            child_number = _read_u64(record, 40)
            child_group = _read_u64(record, 48)
            event_kind = _read_u16(record, 56)
            state = creations.get(creation)
            if (
                state is None
                or state["parent"] != parent_number
                or state["event"] is None
                or state["join"] is not None
                or state["event"][1] != event_kind
                or child_number != next_generation
                or not 1 <= child_number <= _MAX_GENERATIONS
            ):
                _invalid()
            parent = generation(parent_number, live=True)
            if state["event"][0] >= index or parent["wif"] is not None or parent["superseded"]:
                _invalid()
            if state["event"][1] in (1, 2):
                if child_group != max_group + 1:
                    _invalid()
                max_group += 1
            elif child_group not in (parent["group"], max_group + 1):
                _invalid()
            elif child_group == max_group + 1:
                max_group += 1
            state["join"] = index
            state["child"] = child_number
            state["child_group"] = child_group
            generations[child_number] = {
                "group": child_group,
                "live": True,
                "exit": None,
                "wif": None,
                "superseded": False,
                "creation": None,
                "fcntl": None,
            }
            next_generation += 1
        elif kind == 0x15:
            creation = _read_u64(record, 24)
            parent_number = _read_u64(record, 32)
            child_number = _read_u64(record, 40)
            state = creations.get(creation)
            if (
                state is None
                or state["event"] is None
                or state["event"][1] != 2
                or state["parent"] != parent_number
                or state["join"] is None
                or state["done"] is not None
                or state["child"] != child_number
                or state["join"] >= index
            ):
                _invalid()
            generation(parent_number, live=True)
            generation(child_number, live=True)
            state["done"] = index
        elif kind == 0x16:
            execing_number = _read_u64(record, 24)
            displaced_number = _read_u64(record, 32)
            group = _read_u64(record, 40)
            klass = _read_u16(record, 48)
            execing = generation(execing_number, live=True)
            if execing["group"] != group or execing["creation"] is not None or execing["fcntl"] is not None:
                _invalid()
            if klass == 1:
                if displaced_number != 0:
                    _invalid()
            elif klass == 2:
                if displaced_number == execing_number:
                    _invalid()
                displaced = generation(displaced_number)
                if (
                    displaced["group"] != group
                    or displaced["exit"] is None
                    or displaced["wif"] is not None
                    or displaced["creation"] is not None
                    or displaced["fcntl"] is not None
                    or displaced["superseded"]
                ):
                    _invalid()
                displaced["superseded"] = True
                displaced["live"] = False
            else:
                _invalid()
        elif kind == 0x17:
            number = _read_u64(record, 24)
            status = _read_u32(record, 32)
            item = generation(number, live=True)
            if item["exit"] is not None or item["fcntl"] is not None or item["creation"] is not None:
                _invalid()
            if not _valid_wait_status(status):
                _invalid()
            item["exit"] = (index, status)
            item["live"] = False
        elif kind == 0x18:
            number = _read_u64(record, 24)
            status = _read_u32(record, 32)
            item = generation(number)
            if item["superseded"] or item["exit"] is None or item["wif"] is not None:
                _invalid()
            if item["exit"][1] != status or not _valid_wait_status(status):
                _invalid()
            item["wif"] = (index, status)
        elif kind == 0x19:
            number = _read_u64(record, 24)
            signal = _read_u32(record, 32)
            item = generation(number, live=True)
            if not 1 <= signal <= 64 or item["creation"] is not None or item["fcntl"] is not None:
                _invalid()
        elif kind == 0x1A:
            number = _read_u64(record, 24)
            syscall = _read_u64(record, 32)
            item = generation(number, live=True)
            creation = item["creation"]
            if creation is None or item["fcntl"] is not None or syscall != _SYSCALL_NUMBERS[creations[creation]["syscall"]]:
                _invalid()
            state = creations[creation]
            if any(state[key] is not None for key in ("event", "join", "done", "exit")):
                _invalid()
            state["canceled"] = True
            item["creation"] = None
        elif kind == 0x20:
            invocation = _read_u64(record, 24)
            number = _read_u64(record, 32)
            item = generation(number, live=True)
            if invocation != next_invocation or not 1 <= invocation <= _MAX_INVOCATIONS:
                _invalid()
            if item["creation"] is not None or item["fcntl"] is not None:
                _invalid()
            invocations[invocation] = {
                "generation": number,
                "command": _read_u64(record, 48),
                "argument": _read_u64(record, 56),
            }
            item["fcntl"] = invocation
            next_invocation += 1
        elif kind == 0x21:
            invocation = _read_u64(record, 24)
            number = _read_u64(record, 32)
            result = _read_u64(record, 40)
            state = invocations.get(invocation)
            item = generation(number)
            if (
                state is None
                or state["generation"] != number
                or item["fcntl"] != invocation
                or item["wif"] is not None
                or item["superseded"]
            ):
                _invalid()
            normalized = _normalize(state["command"], state["argument"], result)
            rows[normalized] = rows.get(normalized, 0) + 1
            item["fcntl"] = None
        else:
            _invalid()

    if any(item["creation"] is not None or item["fcntl"] is not None for item in generations.values()):
        _invalid()
    for state in creations.values():
        if state.get("exit") is None and not state.get("canceled"):
            _invalid()
        if state.get("canceled") and any(state[key] is not None for key in ("event", "join", "done", "exit")):
            _invalid()
        if state["exit"] is not None and state["exit"][1] == 1:
            if state["event"] is None or state["join"] is None:
                _invalid()
            if state["event"][1] == 2 and state["done"] is None:
                _invalid()
            if state["event"][1] != 2 and state["done"] is not None:
                _invalid()
    if len(generations) != next_generation - 1 or len(rows) > _MAX_ROWS:
        _invalid()
    if sum(rows.values()) > _MAX_INVOCATIONS:
        _invalid()
    for item in generations.values():
        if item["superseded"]:
            if item["wif"] is not None:
                _invalid()
        elif item["wif"] is None:
            _invalid()
    return rows


def _valid_wait_status(status):
    if status & 0xFFFF0000:
        return False
    low = status & 0xFF
    if low == 0:
        return True
    return status & 0xFF00 == 0 and 1 <= (low & 0x7F) <= 64 and (low & 0x7F) != 0


def _errno_token(number):
    return {
        9: "bad-fd",
        22: "invalid",
        24: "process-fd-limit",
        23: "system-fd-limit",
        4: "interrupted",
        13: "contended",
        11: "contended",
        35: "deadlock",
        37: "no-locks",
        14: "bad-pointer",
        1: "denied",
        38: "unsupported",
        95: "unsupported",
    }.get(number, "other")


def _normalize(command, argument, raw_result_bits):
    command = _u64(command)
    argument = _u64(argument)
    raw_result_bits = _u64(raw_result_bits)
    result = raw_result_bits if raw_result_bits < (1 << 63) else raw_result_bits - _U64
    if result in (-512, -513, -514, -516):
        _invalid()
    command_token = _COMMANDS.get(command, "unknown")
    if command_token in {"dupfd", "dupfd-cloexec"}:
        if argument > _INT_MAX:
            _invalid()
        if argument == 0:
            argument_token, floor = "zero", 0
        elif argument <= 2:
            argument_token, floor = "stdio", argument
        elif argument <= 31:
            argument_token, floor = "low-3-31", argument
        elif argument <= 1023:
            argument_token, floor = "medium-32-1023", argument
        else:
            argument_token, floor = "high-1024-int-max", argument
    elif command_token == "getfd":
        if argument != 0:
            _invalid()
        argument_token, floor = "none", None
    elif command_token == "setfd":
        argument_token = {0: "none", 1: "cloexec"}.get(argument, "fd-mask-other")
        floor = None
    elif command_token in {"getfl", "setfl"}:
        argument_token, floor = "file-status-flags", None
    elif command_token == "lock":
        argument_token, floor = "pointer", None
    elif command_token == "owner-signal":
        argument_token, floor = "owner-signal", None
    elif command_token == "lease":
        argument_token, floor = "lease", None
    elif command_token in {"notify", "pipe", "seal", "hint"}:
        argument_token, floor = command_token, None
    else:
        argument_token, floor = "unknown", None

    if result < 0:
        if command == 9:
            return command_token, argument_token, "signed-ambiguous", "none"
        if result < -4095:
            _invalid()
        return command_token, argument_token, "failure", _errno_token(-result)

    if command_token in {"dupfd", "dupfd-cloexec"}:
        if result < floor or result > _INT_MAX:
            _invalid()
        return command_token, argument_token, ("equal-floor" if result == floor else "above-floor"), "none"
    if command_token == "getfd":
        return command_token, argument_token, {0: "none", 1: "cloexec"}.get(result, "fd-mask-other"), "none"
    if command_token == "setfd":
        if result != 0:
            _invalid()
        return command_token, argument_token, "success-zero", "none"
    return command_token, argument_token, "success", "none"


def _row_allowed(row):
    command, argument, result, errno = row
    if (
        type(command) is not str
        or type(argument) is not str
        or type(result) is not str
        or type(errno) is not str
        or command not in _COMMAND_TOKENS
        or argument not in _ARGUMENT_TOKENS
        or result not in _RESULT_TOKENS
        or errno not in _ERRNO_TOKENS
    ):
        return False
    arguments = {
        "dupfd": {"zero", "stdio", "low-3-31", "medium-32-1023", "high-1024-int-max"},
        "dupfd-cloexec": {"zero", "stdio", "low-3-31", "medium-32-1023", "high-1024-int-max"},
        "getfd": {"none"},
        "setfd": {"none", "cloexec", "fd-mask-other"},
        "getfl": {"file-status-flags"},
        "setfl": {"file-status-flags"},
        "lock": {"pointer"},
        "owner-signal": {"owner-signal"},
        "lease": {"lease"},
        "notify": {"notify"},
        "pipe": {"pipe"},
        "seal": {"seal"},
        "hint": {"hint"},
        "unknown": {"unknown"},
    }
    if argument not in arguments[command]:
        return False
    if result == "failure":
        return errno != "none"
    if result == "signed-ambiguous":
        return command == "owner-signal" and errno == "none"
    if errno != "none":
        return False
    allowed_results = {
        "dupfd": {"equal-floor", "above-floor"},
        "dupfd-cloexec": {"equal-floor", "above-floor"},
        "getfd": {"none", "cloexec", "fd-mask-other"},
        "setfd": {"success-zero"},
    }
    return result in allowed_results.get(command, {"success"})


def _validate_rows(rows):
    if type(rows) is not dict or len(rows) > _MAX_ROWS:
        _invalid()
    total = 0
    for row, count in rows.items():
        if type(row) is not tuple or len(row) != 4 or not _row_allowed(row):
            _invalid()
        if type(count) is not int or count <= 0 or count > _MAX_INVOCATIONS:
            _invalid()
        total += count
        if total > _MAX_INVOCATIONS:
            _invalid()


def _encode_aggregate(rows):
    _validate_rows(rows)
    payload = {
        "authority": "non-production-experiment-only",
        "rows": [
            {
                "argument": argument,
                "command": command,
                "count": rows[(command, argument, result, errno)],
                "errno": errno,
                "result": result,
            }
            for command, argument, result, errno in sorted(rows)
        ],
        "schema": "bs2b-s9-fcntl-experiment-aggregate-v1",
        "trace_v1_input": False,
    }
    try:
        data = (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except Exception:
        _invalid()
    if len(data) > _AGGREGATE_CAP:
        _invalid()
    return data


def _reject_constant(_value):
    _invalid()


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _privacy_scan_aggregate(data):
    if type(data) is not bytes or len(data) > _AGGREGATE_CAP:
        _invalid()
    try:
        text = data.decode("utf-8", "strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except Exception:
        _invalid()
    if type(decoded) is not dict or set(decoded) != {"authority", "rows", "schema", "trace_v1_input"}:
        _invalid()
    if (
        type(decoded["authority"]) is not str
        or decoded["authority"] != "non-production-experiment-only"
        or type(decoded["schema"]) is not str
        or decoded["schema"] != "bs2b-s9-fcntl-experiment-aggregate-v1"
        or type(decoded["trace_v1_input"]) is not bool
        or decoded["trace_v1_input"] is not False
        or type(decoded["rows"]) is not list
        or len(decoded["rows"]) > _MAX_ROWS
    ):
        _invalid()
    rows = {}
    for row in decoded["rows"]:
        if type(row) is not dict or set(row) != {"argument", "command", "count", "errno", "result"}:
            _invalid()
        key = (row["command"], row["argument"], row["result"], row["errno"])
        if key in rows or type(row["count"]) is not int:
            _invalid()
        rows[key] = row["count"]
    expected = _encode_aggregate(rows)
    if expected != data:
        _invalid()


def _output_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, info.st_size)


def _check_raw(raw_fd, aggregate_fd):
    _fd(raw_fd)
    _fd(aggregate_fd)
    try:
        raw_before = os.fstat(raw_fd)
        aggregate_before = os.fstat(aggregate_fd)
        _check_input_stat(raw_before)
        _check_input_stat(aggregate_before, size_required=0)
        if (raw_before.st_dev, raw_before.st_ino) == (aggregate_before.st_dev, aggregate_before.st_ino):
            _invalid()
        rows = _parse_raw(raw_fd)
        data = _encode_aggregate(rows)
        raw_after = os.fstat(raw_fd)
        if _stat_fields(raw_before) != _stat_fields(raw_after):
            _invalid()
        digest = hashlib.sha256(data).hexdigest()
        aggregate_prewrite = os.fstat(aggregate_fd)
        if _output_identity(aggregate_prewrite) != _output_identity(aggregate_before) or aggregate_prewrite.st_size != 0:
            _invalid()
    except ContractError:
        raise
    except Exception:
        _invalid()

    try:
        written = os.pwrite(aggregate_fd, data, 0)
        if written != len(data):
            _tainted()
        os.fsync(aggregate_fd)
        aggregate_after = os.fstat(aggregate_fd)
        if (
            _output_identity(aggregate_after)[:6] != _output_identity(aggregate_before)[:6]
            or aggregate_after.st_size != len(data)
        ):
            _tainted()
        readback = os.pread(aggregate_fd, len(data), 0)
        if readback != data:
            _tainted()
        _privacy_scan_aggregate(readback)
        if hashlib.sha256(readback).hexdigest() != digest:
            _tainted()
    except ContractError as exc:
        if exc.code == "tainted-output":
            raise
        _tainted()
    except Exception:
        _tainted()
    return digest


def _self_test():
    golden = bytes.fromhex(
        "5031315339523100010001000000000000000000000000008000000004030201000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010010000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010016000000000002000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010020000000000003000000000000000100000000000000010000000000000005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010021000000000004000000000000000100000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010017000000000005000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "5031315339523100010018000000000006000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    with tempfile.NamedTemporaryFile(mode="w+b") as raw_file, tempfile.NamedTemporaryFile(mode="w+b") as aggregate_file:
        raw_fd = raw_file.fileno()
        aggregate_fd = aggregate_file.fileno()
        os.fchmod(raw_fd, 0o600)
        os.fchmod(aggregate_fd, 0o600)
        os.pwrite(raw_fd, golden, 0)
        os.ftruncate(raw_fd, len(golden))
        rows = _parse_raw(raw_fd)
        if _normalize(0, 0, 0) != ("dupfd", "zero", "equal-floor", "none"):
            _invalid()
        data = _encode_aggregate(rows)
        if os.pwrite(aggregate_fd, data, 0) != len(data):
            _invalid()
        if os.pread(aggregate_fd, len(data), 0) != data:
            _invalid()
        _privacy_scan_aggregate(data)


def main(argv):
    if type(argv) is list and argv == ["self-test"]:
        _self_test()
        print("bs2b-s9-fcntl-experiment-self-test-ok")
        return 0
    return 77


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
