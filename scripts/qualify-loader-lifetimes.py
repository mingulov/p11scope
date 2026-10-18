#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent workload and public-output oracle for loader/image lifetimes.

G16 needs one capture over 300 sequential provider-bearing lifetimes (at
most 4 live, at most 8 retained controlled contexts), every lifetime
257-300 genuinely arming and executing publication plus useful calls.
G17 needs one non-aggregate Detailed capture over 16,385 distinct
sequential leaders with exactly 2 controlled completed calls each
(32,770 total, at most 4 live, including the last participant).

This script owns only the disjoint workload plus independent oracle
portion. It runs real sequential lifetimes, writes an independent JSONL
ledger (header + one row per lifetime + done), validates that ledger, and
judges public observer output against it. It never manufactures native
admission, generation, leases, H0/H3 receipts or successful installed
results. Installed judging fails honestly (FAIL) or reports the exact
missing native seam (BLOCKED) while the product cannot satisfy the gates.

Ledger rows are application self-reports, like scripts/key-operation-ledger.py:
they prove what the owned fixture did, not what the observer saw. The
(starttime) field is self-reported /proc field 22; only (pid,starttime)
uniqueness and positivity are checked, never absolute truth. Installed
image identity must come from native task proof.

Bounds: 20,000 ledger rows, 4,096 bytes per line, 16 MiB per ledger,
64 MiB per profile report, 256 MiB per trace, at most 16,385 lifetimes
per run, sequential launch (live 1, within the required at most 4),
30 s per lifetime. No signals beyond the held child handle, no
kill-by-PID, no process leaks: every child is reaped exactly once.

Usage:
  qualify-loader-lifetimes.py run --cell g16|g17 --lifetimes N \
      --provider provider.so --driver lifetime-driver --output ledger.jsonl
  qualify-loader-lifetimes.py validate --cell g16|g17 --expected N ledger.jsonl
  qualify-loader-lifetimes.py judge --cell g16|g17 --ledger ledger.jsonl \
      (--report observed-profile.json | --trace trace.txt)
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

G16_LIFETIMES = 300
G16_FINAL_START = 257
G16_MAX_LIVE = 4
G16_MAX_RETAINED = 8
G17_LIFETIMES = 16385
G17_CALLS_PER_LEADER = 2
G17_TOTAL_CALLS = G17_LIFETIMES * G17_CALLS_PER_LEADER
G17_MAX_LIVE = 4
CALLS_PER_LIFETIME = 2
EXPECTED_FUNCTIONS = ("C_GetInfo", "C_GetSlotList")

MAX_ROWS = 20000
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_TRACE_BYTES = 256 * 1024 * 1024
MAX_LIFETIMES = 16385
PER_LIFETIME_SECONDS = 30
MAX_MAPS_BYTES = 8 * 1024 * 1024

MAPS_LINE = re.compile(
    r"([0-9a-f]+)-([0-9a-f]+)\s+([r-][w-][x-][ps])\s+"
    r"([0-9a-f]+)\s+([0-9a-f]+):([0-9a-f]+)\s+([0-9]+)(?:\s+.*)?")

JSON_STRING = r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"'
TRACE_ROW = re.compile(
    rf'\d{{2}}:\d{{2}}:\d{{2}}\.\d{{6}} (?P<label>Unknown executable|{JSON_STRING}) '
    rf'\(PID (?P<pid>[1-9]\d*), TID (?P<tid>[1-9]\d*)\)'
    rf'(?: exe=(?P<path>{JSON_STRING}))?(?: sess#[1-9]\d*)? '
    r'(?P<fn>C_[A-Za-z0-9_]+)(?: \[semantics unverified\])? '
    r'→ (?P<rv>CKR_[A-Z0-9_]+|0x[0-9a-fA-F]+) '
    r'(?P<duration>[0-9]+(?:\.[0-9]+)?(?:ns|µs|ms|s))')
TRACE_HEADERS = {
    "Trace — completed call events in arrival order",
    "Executable labels use verified observed paths; event PID/TID remain diagnostic identifiers.",
    "CAPTURE privacy=allowlisted",
}


class LedgerError(ValueError):
    """The independent ledger is incomplete or inconsistent."""


class JudgeFail(ValueError):
    """Installed evidence contradicts the required population."""


class Blocked(ValueError):
    """A missing native seam makes the installed gate undecidable."""


def _require(condition, reason):
    if not condition:
        raise LedgerError(reason)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value < 2**64


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise LedgerError("nonfinite JSON number")


def read_jsonl(stream, *, max_rows=MAX_ROWS, max_line=MAX_LINE_BYTES,
               max_bytes=MAX_LEDGER_BYTES):
    """Read bounded JSONL without retaining unrecognized payloads on error."""
    rows = []
    total = 0
    while True:
        line = stream.readline(max_line + 1)
        if not line:
            break
        if type(line) is not str:
            raise LedgerError("ledger must be text")
        try:
            size = len(line.encode("utf-8"))
        except UnicodeError as error:
            raise LedgerError("invalid ledger encoding") from error
        total += size
        if size > max_line or total > max_bytes:
            raise LedgerError("ledger byte limit")
        if len(rows) >= max_rows:
            raise LedgerError("ledger row limit")
        try:
            row = json.loads(line, object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)
        except (ValueError, RecursionError) as error:
            raise LedgerError("invalid ledger JSON") from error
        if type(row) is not dict:
            raise LedgerError("ledger row must be an object")
        rows.append(row)
    return rows


def read_bounded_text(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise JudgeFail("evidence must be a regular file")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise JudgeFail("evidence exceeds size limit")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def parse_bounded_json(text, what):
    try:
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as error:
        raise JudgeFail("invalid " + what + " JSON") from error
    if type(value) is not dict:
        raise JudgeFail(what + " must be a JSON object")
    return value


# --- Provider pin: held-FD hash plus private mapping anchor. Follows
# scripts/mapped-provider-pin.py; file and mapping devices stay separate. ---

def _file_identity(info):
    return {"dev": [os.major(info.st_dev), os.minor(info.st_dev)],
            "ino": info.st_ino, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def _maps_anchor(text, address, length, inode):
    matches = []
    for line in text.splitlines():
        row = MAPS_LINE.fullmatch(line)
        if row is None:
            raise LedgerError("malformed self maps line")
        low, high = (int(row[i], 16) for i in (1, 2))
        if high <= low:
            raise LedgerError("invalid self maps range")
        if low <= address < high:
            if (address + length > high or row[3] != "r--p"
                    or int(row[4], 16) + address - low != 0
                    or int(row[7]) != inode):
                raise LedgerError("self mapping is not the held FD offset-zero anchor")
            matches.append({"dev": [int(row[5], 16), int(row[6], 16)],
                            "ino": int(row[7]), "file_offset": 0,
                            "length": length, "permissions": row[3]})
    if len(matches) != 1:
        raise LedgerError("missing or duplicate self mapping anchor")
    return matches[0]


def _mapping_from_fd(fd, size):
    length = min(os.sysconf("SC_PAGESIZE"), size)
    if length <= 0:
        raise LedgerError("provider has no mappable bytes")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    address = libc.mmap(None, length, 1, 2, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        with open("/proc/self/maps", encoding="utf-8") as stream:
            text = stream.read(MAX_MAPS_BYTES + 1)
        if len(text) > MAX_MAPS_BYTES:
            raise LedgerError("self maps exceeds size limit")
        return _maps_anchor(text, address, length, os.fstat(fd).st_ino)
    finally:
        if libc.munmap(address, length) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def _pin_fd(fd):
    """Pin one held FD: hash its content and anchor mapping identity."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise LedgerError("provider must be a nonempty regular file")
    anchor = _mapping_from_fd(fd, before.st_size)
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(fd, 1024 * 1024, offset):
        digest.update(chunk)
        offset += len(chunk)
        if offset > before.st_size:
            raise LedgerError("provider grew during hash")
    after = os.fstat(fd)
    if offset != before.st_size or _file_identity(before) != _file_identity(after):
        raise LedgerError("provider changed or short read during pin")
    if anchor["ino"] != before.st_ino:
        raise LedgerError("provider inode changed during mapping")
    return {"dev": anchor["dev"], "ino": anchor["ino"],
            "sha256": digest.hexdigest(), "mapping": anchor,
            "file_identity": _file_identity(before)}


def pin_provider(path):
    """Hash the held provider FD and anchor its mapping identity."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return _pin_fd(fd)
    finally:
        os.close(fd)


def _retained_identity(info):
    # Unlinking a pathname updates ctime, so exclude that field while
    # retaining mtime to reject edits whose original bytes were restored.
    return ([os.major(info.st_dev), os.minor(info.st_dev)],
            info.st_ino, info.st_size, info.st_mtime_ns)


def _revalidate_fd(fd, pin):
    """Re-hash the same held FD; fail if it changed during the workload."""
    current = os.fstat(fd)
    wanted = pin["file_identity"]
    if _retained_identity(current) != (wanted["dev"], wanted["ino"],
                                       wanted["size"], wanted["mtime_ns"]):
        raise LedgerError("provider changed during workload")
    expected = wanted["size"]
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
        if offset > expected:
            raise LedgerError("provider grew during workload")
    if offset != expected:
        raise LedgerError("provider changed during workload")
    if digest.hexdigest() != pin["sha256"]:
        raise LedgerError("provider content changed during workload")
    if _retained_identity(os.fstat(fd)) != (
            wanted["dev"], wanted["ino"], wanted["size"], wanted["mtime_ns"]):
        raise LedgerError("provider changed during workload revalidation")


def _check_pin_shape(pin):
    _require(type(pin) is dict, "header provider pin must be an object")
    for key in ("dev", "ino", "sha256", "mapping", "file_identity"):
        _require(key in pin, "header provider pin is incomplete")
    _require(type(pin["dev"]) is list and len(pin["dev"]) == 2
             and all(_integer(v) for v in pin["dev"]), "invalid mapping device")
    _require(_integer(pin["ino"], 1), "invalid mapping inode")
    _require(type(pin["sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
             "invalid provider hash")
    mapping = pin["mapping"]
    _require(type(mapping) is dict and mapping.get("dev") == pin["dev"]
             and all(type(v) is int for v in pin["dev"])
             and type(mapping.get("ino")) is int and mapping.get("ino") == pin["ino"]
             and type(mapping.get("file_offset")) is int
             and mapping.get("file_offset") == 0
             and _integer(mapping.get("length"), 1)
             and mapping.get("permissions") == "r--p", "invalid mapping anchor")
    identity = pin["file_identity"]
    _require(type(identity) is dict and type(identity.get("dev")) is list
             and len(identity["dev"]) == 2
             and all(type(v) is int for v in identity["dev"])
             and type(identity.get("ino")) is int and identity.get("ino") == pin["ino"]
             and _integer(identity.get("size"), 1)
             and all(type(identity.get(k)) is int for k in ("mtime_ns", "ctime_ns")),
             "invalid file identity")


# --- Independent ledger validation. G16 checks publication surfaces plus
# useful calls; G17 checks only distinct leaders plus 2 calls each. ---

def validate_ledger(rows, cell, expected_lifetimes):
    """Validate one independent lifetime ledger; derive counts from rows."""
    if cell not in ("g16", "g17"):
        raise LedgerError("unknown lifetime cell")
    _require(type(rows) is list and 0 < len(rows) <= MAX_ROWS, "ledger row limit")
    _require(type(expected_lifetimes) is int
             and 1 <= expected_lifetimes <= MAX_LIFETIMES, "invalid expected population")
    header = rows[0]
    _require(header.get("kind") == "header", "first row must be header")
    _require(type(header.get("seq")) is int and header.get("seq") == 1,
             "header sequence must be 1")
    _require(type(header.get("version")) is int and header.get("version") == 1,
             "unsupported ledger version")
    _require(header.get("cell") == cell, "ledger cell mismatch")
    _require(type(header.get("expected_lifetimes")) is int
             and header.get("expected_lifetimes") == expected_lifetimes,
             "ledger expected population mismatch")
    _require(type(header.get("calls_per_lifetime")) is int
             and header.get("calls_per_lifetime") == CALLS_PER_LIFETIME,
             "ledger call denominator mismatch")
    _require(_integer(header.get("max_live"), 1) and header["max_live"] <= 4,
             "workload live bound exceeds 4")
    _require(set(header) == {"seq", "kind", "version", "cell", "expected_lifetimes",
                             "calls_per_lifetime", "max_live", "provider"},
             "unexpected header fields")
    _check_pin_shape(header["provider"])
    pin = header["provider"]
    file_dev = pin["file_identity"]["dev"]
    file_ino = pin["file_identity"]["ino"]

    _require(len(rows) == expected_lifetimes + 2, "ledger population is not complete")
    seen_labels = set()
    seen_births = set()
    counts = {name: 0 for name in EXPECTED_FUNCTIONS}
    for index in range(1, expected_lifetimes + 1):
        row = rows[index]
        _require(type(row.get("seq")) is int and row.get("seq") == index + 1,
                 "lifetime sequence order")
        _require(row.get("kind") == "lifetime", "lifetime row order")
        _require(set(row) == {"seq", "kind", "label", "pid", "starttime",
                              "provider_dev", "provider_ino", "surfaces", "calls"},
                 "unexpected lifetime fields")
        label = row["label"]
        _require(type(label) is int and 1 <= label <= expected_lifetimes,
                 "lifetime label out of range")
        _require(label not in seen_labels, "duplicate lifetime label")
        seen_labels.add(label)
        pid, start = row["pid"], row["starttime"]
        _require(_integer(pid, 1) and _integer(start, 1), "invalid lifetime birth")
        _require((pid, start) not in seen_births, "duplicate process birth")
        seen_births.add((pid, start))
        dev = row.get("provider_dev")
        _require(type(dev) is list and len(dev) == 2
                 and all(type(v) is int for v in dev) and dev == file_dev
                 and type(row.get("provider_ino")) is int
                 and row.get("provider_ino") == file_ino,
                 "lifetime provider differs from pinned file identity")
        surfaces = row["surfaces"]
        _require(type(surfaces) is dict, "lifetime surfaces must be an object")
        if cell == "g16":
            _require(set(surfaces) == {"function_list", "interface_list",
                                       "interface", "interface_count"},
                     "unexpected surface fields")
            for key in ("function_list", "interface_list", "interface"):
                _require(type(surfaces.get(key)) is int and surfaces.get(key) == 0,
                         "publication surface did not succeed")
            _require(type(surfaces.get("interface_count")) is int
                     and surfaces.get("interface_count") == 1,
                     "interface count mismatch")
        calls = row["calls"]
        _require(type(calls) is list and len(calls) == CALLS_PER_LIFETIME,
                 "lifetime must complete exactly 2 calls")
        for position, call in enumerate(calls):
            _require(type(call) is dict and set(call) == {"fn", "rv"},
                     "unexpected call fields")
            _require(call.get("fn") == EXPECTED_FUNCTIONS[position],
                     "unexpected call function or order")
            _require(type(call.get("rv")) is int and call.get("rv") == 0,
                     "useful call did not succeed")
            counts[call["fn"]] += 1
    _require(seen_labels == set(range(1, expected_lifetimes + 1)),
             "lifetime labels are not 1..N without gaps")
    if cell == "g16" and expected_lifetimes == G16_LIFETIMES:
        _require(all(label in seen_labels
                     for label in range(G16_FINAL_START, G16_LIFETIMES + 1)),
                 "final 44 lifetimes are missing")
    if cell == "g17" and expected_lifetimes == G17_LIFETIMES:
        _require(G17_LIFETIMES in seen_labels, "last leader is missing")

    done = rows[-1]
    _require(done.get("kind") == "done", "last row must be done")
    _require(type(done.get("seq")) is int
             and done.get("seq") == expected_lifetimes + 2, "done sequence mismatch")
    _require(set(done) == {"seq", "kind", "lifetimes", "api_calls",
                           "calls_by_function"}, "unexpected done fields")
    _require(type(done.get("lifetimes")) is int
             and done.get("lifetimes") == expected_lifetimes,
             "done lifetime mismatch")
    total = sum(counts.values())
    _require(type(done.get("api_calls")) is int and done.get("api_calls") == total,
             "done total disagrees with calls")
    summary = done.get("calls_by_function")
    _require(type(summary) is dict and set(summary) == set(counts)
             and all(_integer(summary[n]) and summary[n] == counts[n]
                     for n in counts), "done per-function summary disagrees")
    return {"cell": cell, "lifetimes": expected_lifetimes, "api_calls": total,
            "calls_by_function": dict(counts),
            "provider": {"dev": pin["dev"], "ino": pin["ino"],
                         "sha256": pin["sha256"]}}


# --- Workload harness: sequential real lifetimes with held custody. ---

def run_lifetimes(*, cell, lifetimes, provider, driver, output):
    """Run N sequential lifetimes and write a validated independent ledger.

    The provider FD stays open across the workload. Each lifetime executes
    the FD-backed path so a pathname replacement cannot swap bytes, and the
    same FD is re-hashed after the workload to fail on same-inode mutation.
    The ledger hash describes the held bytes only, never native observation.
    """
    if cell not in ("g16", "g17"):
        raise LedgerError("unknown lifetime cell")
    if type(lifetimes) is not int or not 1 <= lifetimes <= MAX_LIFETIMES:
        raise LedgerError("lifetimes must be 1..16385")
    provider_path = Path(provider)
    driver_path = Path(driver)
    output_path = Path(output)
    if not provider_path.is_file() or not driver_path.is_file():
        raise LedgerError("provider or driver is missing")
    if not os.access(driver_path, os.X_OK):
        raise LedgerError("driver is not executable")
    if not output_path.parent.is_dir():
        raise LedgerError("output directory is missing")
    provider_fd = os.open(provider_path,
                          os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        pin = _pin_fd(provider_fd)
        provider_arg = f"/dev/fd/{provider_fd}"
        header = {"seq": 1, "kind": "header", "version": 1, "cell": cell,
                  "expected_lifetimes": lifetimes,
                  "calls_per_lifetime": CALLS_PER_LIFETIME, "max_live": 1,
                  "provider": pin}
        rows = [header]
        counts = {name: 0 for name in EXPECTED_FUNCTIONS}
        for label in range(1, lifetimes + 1):
            wanted = pin["file_identity"]
            if _retained_identity(os.fstat(provider_fd)) != (
                    wanted["dev"], wanted["ino"], wanted["size"],
                    wanted["mtime_ns"]):
                raise LedgerError("provider changed during workload")
            # Held custody: the Popen handle (never a bare PID) owns signals
            # and reaping. The row pid must equal this held child's pid.
            # The FD-backed path keeps the driver's stat/dlopen on the held
            # file; pass_fds preserves the number in the child.
            child = subprocess.Popen(
                [str(driver_path), provider_arg, str(label)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(provider_fd,))
            try:
                try:
                    stdout, _stderr = child.communicate(
                        timeout=PER_LIFETIME_SECONDS)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    raise LedgerError(f"lifetime {label} exceeded its deadline")
                held_pid = child.pid
                if child.returncode != 0:
                    raise LedgerError(f"lifetime {label} exited {child.returncode}")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                else:
                    child.wait()
                for stream in (child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()
            if len(stdout.encode("utf-8")) > MAX_LINE_BYTES:
                raise LedgerError(f"lifetime {label} output exceeds line limit")
            lines = stdout.splitlines()
            if len(lines) != 1:
                raise LedgerError(f"lifetime {label} must emit exactly one row")
            try:
                body = json.loads(lines[0], object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
            except (ValueError, RecursionError) as error:
                raise LedgerError(f"lifetime {label} emitted invalid JSON") from error
            if type(body) is not dict:
                raise LedgerError(f"lifetime {label} row must be an object")
            if body.get("pid") != held_pid:
                raise LedgerError(f"lifetime {label} pid does not match held child")
            row = {"seq": label + 1, "kind": "lifetime"}
            row.update(body)
            rows.append(row)
        _revalidate_fd(provider_fd, pin)
        for row in rows[1:]:
            for call in row.get("calls", []):
                if isinstance(call, dict) and call.get("fn") in counts:
                    counts[call["fn"]] += 1
        rows.append({"seq": lifetimes + 2, "kind": "done",
                     "lifetimes": lifetimes,
                     "api_calls": sum(counts.values()),
                     "calls_by_function": dict(counts)})
        summary = validate_ledger(rows, cell, lifetimes)
        text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        if len(text.encode("utf-8")) > MAX_LEDGER_BYTES:
            raise LedgerError("ledger byte limit")
        with open(output_path, "w", encoding="utf-8") as stream:
            stream.write(text)
        return summary
    finally:
        os.close(provider_fd)


# --- Installed judging against public output. Never manufactures native
# facts; missing seams below are BLOCKED, contradictions are FAIL. ---

def _fail(reason):
    raise JudgeFail(reason)


def _blocked(reason):
    raise Blocked(reason)


def _evidence_uint(evidence, key):
    value = evidence.get(key)
    if type(value) is not int or not 0 <= value < 2**64:
        _fail("invalid evidence counter: " + key)
    return value


def _check_identity(value, what):
    if type(value) is not dict:
        _fail("missing " + what + " identity")
    dev = value.get("dev")
    if (type(dev) is not list or len(dev) != 2
            or any(type(v) is not int or v < 0 for v in dev)):
        _fail("invalid " + what + " device")
    if type(value.get("ino")) is not int or value["ino"] <= 0:
        _fail("invalid " + what + " inode")
    if (type(value.get("sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None):
        _fail("invalid " + what + " hash")
    return (tuple(dev), value["ino"], value["sha256"])


def check_profile_report(report, *, pin, expected, cell):
    """Check the public facts a profile can carry; raise FAIL on mismatch."""
    if (report.get("schema") == "p11scope/observed-profile/v3-metrics"
            or report.get("lane") == "metrics"):
        _fail("wrong mode: G16/G17 need non-aggregate Detailed, not metrics")
    if report.get("schema") != "p11scope/observed-profile/v3":
        _fail("unsupported or wrong profile schema")
    if report.get("lane") != "profile":
        _fail("wrong lane: G16/G17 need non-aggregate Detailed profile")
    capture = report.get("capture")
    if type(capture) is not dict or capture.get("mode") != "profile":
        _fail("wrong capture mode: G16/G17 need Detailed profile, not aggregate")
    if capture.get("scope") not in ("system", "cgroup"):
        _fail("wrong capture scope: one pid cannot observe sequential lifetimes")
    evidence = report.get("evidence")
    if type(evidence) is not dict:
        _fail("missing capture evidence")
    if evidence.get("completeness") != "COMPLETE":
        _fail("partial output cannot prove full lifetimes")
    if evidence.get("verdict_detail") != "clean_proven":
        _fail("verdict is not clean_proven")
    if evidence.get("drain_proven") is not True:
        _fail("terminal drain is not proven")
    stop = evidence.get("stop_quiescence")
    if (type(stop) is not dict or stop.get("state") != "proven"
            or stop.get("post_q_events") is not False
            or stop.get("post_q_discovery") is not False):
        _fail("stop quiescence is not proven")
    observation = evidence.get("gap_classes", {}).get("observation", {})
    if observation.get("status") != "exact" or observation.get("causes") != []:
        _fail("observation gap class is not exact")
    kernel = evidence.get("kernel_control", {})
    if (kernel.get("capture_halted") is not False
            or kernel.get("owner_poison") != []
            or kernel.get("root_affiliation_failures") != []):
        _fail("kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        if type(kernel.get(key)) is not int or kernel.get(key) != 0:
            _fail("kernel loss or unknown " + key)
    if cell == "g16" and kernel.get("identity_budget_exhausted") is not False:
        _fail("G16 must keep image-ticket use below 16,384")
    admitted = evidence.get("discovery")
    if type(admitted) is not list:
        _fail("missing discovery admission")
    owned = (tuple(pin["dev"]), pin["ino"], pin["sha256"])
    found = False
    for entry in admitted:
        if type(entry) is not dict or entry.get("sha256") is None:
            continue
        try:
            if _check_identity(entry, "discovery") == owned:
                found = True
        except JudgeFail:
            continue
    if not found:
        _fail("owned provider was not admitted")
    rows = report.get("functions")
    if type(rows) is not list:
        _fail("missing functions")
    if len(rows) != len(EXPECTED_FUNCTIONS):
        _fail(f"expected exactly {len(EXPECTED_FUNCTIONS)} owned rows, "
              f"found {len(rows)} (foreign, ambient or missing rows fail)")
    seen_targets = set()
    seen_counts = {}
    for row in rows:
        if type(row) is not dict:
            _fail("invalid function row")
        module = row.get("module")
        ambiguous, unresolved = row.get("module_ambiguous"), row.get("module_unresolved")
        if (type(ambiguous) is not bool or type(unresolved) is not bool
                or module is None or ambiguous or unresolved):
            _fail("owned row lacks a sole accepted module owner")
        if _check_identity(module, "module") != owned:
            _fail("row module differs from owned provider")
        target = row.get("target")
        if type(target) is not dict:
            _fail("invalid physical target")
        if target.get("object") is None:
            _fail("owned row has no physical target identity")
        key = (_check_identity(target["object"], "target"), target.get("file_offset"))
        if type(key[1]) is not int or key[1] < 0:
            _fail("invalid target file offset")
        if key in seen_targets:
            _fail("duplicate observed physical target")
        seen_targets.add(key)
        if type(row.get("calls")) is not int or row.get("calls") != expected:
            _fail("owned target count differs from independent ledger")
        for counter in ("errors", "in_flight", "pending_returns"):
            if type(row.get(counter)) is not int or row.get(counter) != 0:
                _fail("owned target has failed or unsettled returns")
        returns = row.get("rv_counts")
        if (type(returns) is not dict or set(returns) != {"0000000000000000"}
                or type(returns["0000000000000000"]) is not int
                or returns["0000000000000000"] != expected):
            _fail("owned target return distribution is not exactly CKR_OK")
        names = row.get("names")
        if (type(names) is not list or not names
                or any(type(n) is not str for n in names)):
            _fail("invalid function names")
        seen_counts[key] = row["calls"]
    if sorted(seen_counts.values()) != [expected] * len(EXPECTED_FUNCTIONS):
        _fail("per-function counts differ from independent ledger")
    for key in ("in_flight_at_end", "event_loss"):
        _evidence_uint(evidence, key)
        if evidence[key] != 0:
            _fail("evidence loss: " + key)


def parse_trace(text):
    """Strictly parse a Detailed trace; unknown lines are errors."""
    rows, counts, evidence, errors = [], [], [], []
    for line in text.splitlines():
        match = TRACE_ROW.fullmatch(line)
        if match:
            row = match.groupdict()
            row["pid"], row["tid"] = int(row["pid"]), int(row["tid"])
            if row["label"] == "Unknown executable":
                if row["path"] is not None:
                    errors.append("unknown row carries an executable path")
                row["path"], row["label"] = None, None
            else:
                try:
                    row["label"] = json.loads(row["label"])
                    row["path"] = json.loads(row["path"]) if row["path"] else None
                except ValueError:
                    errors.append("invalid trace label encoding")
                    continue
                if not row["path"]:
                    errors.append("named row lacks an executable path")
            rows.append(row)
        elif line.startswith(("COUNT_EVIDENCE ", "EVIDENCE ")):
            prefix, _, body = line.partition(" ")
            try:
                value = json.loads(body, object_pairs_hook=_unique_object,
                                   parse_constant=_invalid_constant)
                if type(value) is not dict:
                    raise ValueError("record is not an object")
                (counts if prefix == "COUNT_EVIDENCE" else evidence).append(value)
            except (ValueError, RecursionError) as error:
                errors.append(f"invalid {prefix}: {error}")
        elif not line or line in TRACE_HEADERS:
            continue
        else:
            errors.append(f"unexpected trace record: {line[:160]}")
    if len(counts) != 1 or len(evidence) != 1:
        errors.append("expected exactly one terminal count and evidence record")
    return rows, counts, evidence, errors


def check_trace_output(text, *, expected):
    """Check delivered trace rows and terminal evidence; raise FAIL."""
    rows, _counts, evidence_list, errors = parse_trace(text)
    if errors:
        _fail("; ".join(errors[:3]))
    evidence = evidence_list[0]
    if evidence.get("completeness") != "COMPLETE":
        _fail("partial trace cannot prove full lifetimes")
    if evidence.get("verdict_detail") != "clean_proven":
        _fail("trace verdict is not clean_proven")
    if evidence.get("drain_proven") is not True:
        _fail("trace terminal drain is not proven")
    if evidence.get("trace_truncated") is True:
        _fail("truncated trace cannot prove full lifetimes")
    observation = evidence.get("gap_classes", {}).get("observation", {})
    if observation.get("status") != "exact" or observation.get("causes") != []:
        _fail("trace observation gap class is not exact")
    kernel = evidence.get("kernel_control", {})
    if (kernel.get("capture_halted") is not False
            or kernel.get("owner_poison") != []
            or kernel.get("root_affiliation_failures") != []):
        _fail("kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        if type(kernel.get(key)) is not int or kernel.get(key) != 0:
            _fail("kernel loss or unknown " + key)
    per_function = {name: 0 for name in EXPECTED_FUNCTIONS}
    for row in rows:
        if row["fn"] not in per_function:
            _fail("trace carries foreign or unowned calls: " + row["fn"])
        if row["rv"] != "CKR_OK":
            _fail("trace carries a failed controlled call")
        per_function[row["fn"]] += 1
    if any(count != expected for count in per_function.values()):
        _fail("trace per-function delivery differs from independent ledger")
    if len(rows) != expected * len(EXPECTED_FUNCTIONS):
        _fail("trace total delivery differs from independent ledger")
    if expected > 1 and len({row["pid"] for row in rows}) < 2:
        _fail("trace shows a single PID, not sequential leaders")


def judge(cell, ledger_rows, *, report_text=None, trace_text=None):
    """Judge one installed capture; PASS only with all native gates proven.

    Public contradictions raise JudgeFail. Anything needing native
    generation/lease/cutoff, ticket-issuance, per-lifetime arming or
    single-capture receipts raises Blocked with the exact missing seam.
    """
    if cell == "g16":
        expected = G16_LIFETIMES
    elif cell == "g17":
        expected = G17_LIFETIMES
    else:
        _fail("unknown lifetime cell")
    if (report_text is None) == (trace_text is None):
        _fail("judge needs exactly one capture: --report or --trace")
    try:
        summary = validate_ledger(ledger_rows, cell, expected)
    except LedgerError as error:
        _fail("independent ledger does not establish the full population: "
              + str(error))
    pin = {"dev": summary["provider"]["dev"], "ino": summary["provider"]["ino"],
           "sha256": summary["provider"]["sha256"]}
    if report_text is not None:
        report = parse_bounded_json(report_text, "profile report")
        check_profile_report(report, pin=pin, expected=expected, cell=cell)
    else:
        check_trace_output(trace_text, expected=expected)
    if cell == "g16":
        _blocked("missing native seam: per-lifetime loader arming/admission "
                 "and peak retained occupancy are not observable in current "
                 "public output (needs the approved bounded aggregate loader "
                 "transition counters, L4); retained controlled contexts "
                 "(at most 8), held-return cutoff and delayed-record ack "
                 "(LoaderRetirementFence) likewise have no public proof")
    _blocked("missing native seam: successful ticket issuance across 16,384 "
             "has no public producer receipt (kernel_control shows refusals "
             "only); distinct (pid,starttime) leaders are not provable from "
             "aggregated profile or starttime-less trace rows; single-capture "
             "guarantee against hidden session restart needs an observer "
             "invocation receipt")


def _redacted_error():
    return "loader-lifetimes input refused: incomplete or inconsistent"


def command_run(args):
    try:
        summary = run_lifetimes(cell=args.cell, lifetimes=args.lifetimes,
                                provider=args.provider, driver=args.driver,
                                output=args.output)
    except (LedgerError, OSError) as error:
        print(f"{_redacted_error()}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


def command_validate(args):
    try:
        with open(args.ledger, encoding="utf-8") as stream:
            rows = read_jsonl(stream)
        summary = validate_ledger(rows, args.cell, args.expected)
    except (LedgerError, OSError, UnicodeError) as error:
        print(f"{_redacted_error()}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


def command_judge(args):
    result = {"cell": args.cell, "pass": False, "qualification": "failed",
              "detail": ""}
    try:
        with open(args.ledger, encoding="utf-8") as stream:
            ledger_rows = read_jsonl(stream)
        report_text = trace_text = None
        if args.report:
            report_text = read_bounded_text(args.report, MAX_REPORT_BYTES)
        if args.trace:
            trace_text = read_bounded_text(args.trace, MAX_TRACE_BYTES)
        detail = judge(args.cell, ledger_rows, report_text=report_text,
                       trace_text=trace_text)
        result.update({"pass": True, "qualification": "installed-positive",
                       "detail": detail or "installed positive"})
        code = 0
    except Blocked as error:
        result.update({"qualification": "blocked", "detail": str(error)})
        code = 2
    except (JudgeFail, LedgerError, OSError, ValueError, TypeError,
            KeyError, AttributeError) as error:
        result["detail"] = str(error) or _redacted_error()
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run sequential lifetimes")
    run.add_argument("--cell", required=True, choices=("g16", "g17"))
    run.add_argument("--lifetimes", required=True, type=int)
    run.add_argument("--provider", required=True)
    run.add_argument("--driver", required=True)
    run.add_argument("--output", required=True)
    validate = commands.add_parser("validate", help="validate a ledger")
    validate.add_argument("--cell", required=True, choices=("g16", "g17"))
    validate.add_argument("--expected", required=True, type=int)
    validate.add_argument("ledger")
    judge_parser = commands.add_parser("judge", help="judge installed output")
    judge_parser.add_argument("--cell", required=True, choices=("g16", "g17"))
    judge_parser.add_argument("--ledger", required=True)
    judge_parser.add_argument("--report", default=None)
    judge_parser.add_argument("--trace", default=None)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "run":
        return command_run(args)
    if args.command == "validate":
        return command_validate(args)
    return command_judge(args)


if __name__ == "__main__":
    raise SystemExit(main())
