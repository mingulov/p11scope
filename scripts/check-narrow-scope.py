#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check narrow-scope discovery evidence for the absence of a global census.

Evidence command (run against the observer)::

    strace -f -y -e trace=openat,open,getdents64 -s 128 -o <ev> p11scope ...

Allowed /proc set for PID, run and cgroup scopes: ``/proc/self/**``,
``/proc/<scoped-pid>/**`` and, for cgroup scopes, ``<cgroup>/**/cgroup.procs``
plus directory opens inside the scoped cgroup. Forbidden: opening the bare
``/proc`` directory, ``getdents64`` on a bare-``/proc`` fd, any
``/proc/<unscoped-pid>/**`` path, and root-tree enumeration (``getdents64``
on ``/``, on ``/sys/fs/cgroup``, or above the scoped cgroup; out-of-scope
``cgroup.procs`` reads). System scope is the census scope: a ``/proc`` walk
there passes. Paths outside ``/proc`` and outside the scoped cgroup are
counted but never verdicts: opening a provider file is not a census.
Relative opens resolve through dirfds opened earlier in the trace;
unresolvable ones are counted as ``relative-unresolved`` for the caller to
judge, while ``getdents64`` on an unattributable fd always fails.

The record checkers below validate canned per-cell CLI-output records
(coverage declarations, endpoint-sample residency claims, observer-numbering
rows, root/mount replacement refusals, partial-walk declarations). Twins
live in tests/python/test_narrow_scope_oracle.py and import this module.
"""

import argparse
import json
import re
import sys

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65536
MAX_EVENTS = 2000000
SAFE_PATH = re.compile(r"[A-Za-z0-9_/.,:@%+-]{1,512}\Z")
INT_RE = re.compile(r"[0-9]+\Z")

_LINE = re.compile(
    r"\A(?P<pid>[0-9]+)\s+(?P<call>openat|open|getdents64)"
    r"\((?P<args>.*)\)\s+=\s+(?P<ret>-?[0-9]+|\?)"
)
_QUOTED = re.compile(r'"(?P<body>(?:[^"\\]|\\.)*)"')
_FD = re.compile(r"\A(?P<fd>[0-9]+)(?:<(?P<fdpath>[^>]*)>)?")
_OCTAL = re.compile(r"\\([0-7]{3})")
_SIMPLE_ESCAPE = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "r": "\r"}


class EvidenceError(ValueError):
    """The evidence shows a census, or a record is inconsistent."""


def _require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def _shown_path(path):
    """Render an evidence path inside a refusal reason.

    Paths over a safe file-name alphabet print verbatim (claim narrowing
    needs the measured path); anything else prints as a fixed kind, never
    its content, so a refusal cannot echo hostile bytes.
    """
    if type(path) is str and SAFE_PATH.match(path):
        return path
    return "unprintable path"


def _unescape(body):
    """Decode strace C-style escapes in a quoted path argument."""
    out = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 >= len(body):
            out.append(char)
            index += 1
            continue
        nxt = body[index + 1]
        if nxt in _SIMPLE_ESCAPE:
            out.append(_SIMPLE_ESCAPE[nxt])
            index += 2
        elif nxt.isdigit():
            match = _OCTAL.match(body, index)
            if match is None:
                raise EvidenceError("unsupported strace escape")
            out.append(chr(int(match.group(1), 8)))
            index += 4
        else:
            raise EvidenceError("unsupported strace escape")
    return "".join(out)


def parse_strace(text):
    """Parse strace -f -y openat/open/getdents64 output into events.

    Each event is ``{"pid", "call", "path", "fd", "result"}``; ``path`` is
    the open target or the getdents64 fd's ``<path>`` annotation (resolved
    through earlier opens of the same pid when the annotation is absent).
    Unfinished/resumed pairs join, so a split call cannot dodge the check.
    """
    _require(type(text) is str, "evidence must be text")
    events = []
    pending = {}
    fds = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        _require(len(events) < MAX_EVENTS, "evidence event limit")
        line = raw.strip()
        if not line:
            continue
        pid_text, _, rest = line.partition(" ")
        if not INT_RE.match(pid_text):
            continue
        pid = int(pid_text)
        resumed = "<... " in rest and " resumed> " in rest
        if rest.rstrip().endswith(">") and "<unfinished ...>" in rest:
            pending[pid] = rest[: rest.index(" <unfinished ...>")]
            continue
        if resumed:
            head = pending.pop(pid, None)
            _require(head is not None,
                     f"resumed call without unfinished line near {lineno}")
            rest = head + rest[rest.index(" resumed> ") + len(" resumed> "):]
        match = _LINE.match(f"{pid} {rest}")
        if match is None:
            continue
        call = match.group("call")
        args = match.group("args")
        result_text = match.group("ret")
        result = None if result_text == "?" else int(result_text)
        path = None
        fd = None
        if call in ("open", "openat"):
            quoted = _QUOTED.search(args)
            _require(quoted is not None,
                     f"unparseable {call} arguments near line {lineno}")
            raw_path = _unescape(quoted.group("body"))
            path = raw_path
            if call == "openat" and not raw_path.startswith("/"):
                dirfd = args.split(",", 1)[0].strip()
                if INT_RE.match(dirfd):
                    base = fds.get((pid, int(dirfd)))
                    if base is not None:
                        path = base.rstrip("/") + "/" + raw_path
            directory_open = "O_DIRECTORY" in args.split('"', 2)[-1]
            if result is not None and result >= 0:
                fds[(pid, result)] = path
        else:
            fd_match = _FD.match(args.strip())
            _require(fd_match is not None,
                     f"unparseable getdents64 arguments near line {lineno}")
            fd = int(fd_match.group("fd"))
            annotated = fd_match.group("fdpath")
            if annotated:
                path = annotated
            else:
                path = fds.get((pid, fd))
            directory_open = True
        events.append({"pid": pid, "call": call, "path": path, "fd": fd,
                       "result": result, "directory_open": directory_open,
                       "lineno": lineno})
    _require(not pending, "unfinished call without resumed line")
    return events


def read_evidence(stream):
    """Read bounded strace evidence text."""
    chunks = []
    total = 0
    while True:
        piece = stream.read(65536)
        if not piece:
            break
        _require(type(piece) is str, "evidence must be text")
        total += len(piece.encode("utf-8", "replace"))
        _require(total <= MAX_EVIDENCE_BYTES, "evidence byte limit")
        chunks.append(piece)
    text = "".join(chunks)
    for line in text.splitlines():
        _require(len(line.encode("utf-8", "replace")) <= MAX_LINE_BYTES,
                 "evidence line limit")
    return text


def _proc_class(path):
    """Classify a /proc path: root, self, pid, other, or None (not /proc)."""
    if path == "/proc" or path == "/proc/":
        return ("root",)
    if path == "/proc/self" or path.startswith("/proc/self/"):
        return ("self",)
    if path.startswith("/proc/"):
        second = path[len("/proc/"):].split("/", 1)[0]
        if INT_RE.match(second):
            return ("pid", int(second))
        return ("other",)
    return None


def _under(path, root):
    return path == root or path.startswith(root + "/")


def _normalize(path):
    """Collapse /./ and /../ lexically so textual escapes cannot dodge."""
    if not path.startswith("/"):
        return path
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _census_pid_event(event, scoped):
    path = event["path"]
    if event["call"] == "getdents64" and path is None:
        raise EvidenceError(
            f"getdents64 on unresolved fd {event['fd']} "
            f"(pid {event['pid']} line {event['lineno']})")
    if path is None:
        return "unresolved-open"
    if not path.startswith("/"):
        return "relative-unresolved"
    path = _normalize(path)
    bare = path.rstrip("/") or "/"
    if event["call"] == "getdents64" and bare in ("/", "/sys/fs/cgroup"):
        raise EvidenceError(
            f"enumerates {_shown_path(bare)} (pid {event['pid']} "
            f"line {event['lineno']})")
    kind = _proc_class(path)
    if kind is None:
        return "outside-proc"
    if kind[0] == "root":
        if event["call"] == "getdents64":
            raise EvidenceError(
                f"bare-/proc enumeration (pid {event['pid']} "
                f"line {event['lineno']})")
        raise EvidenceError(
            f"opens the bare /proc directory (pid {event['pid']} "
            f"line {event['lineno']})")
    if kind[0] == "pid" and kind[1] not in scoped:
        raise EvidenceError(
            f"opens /proc/{kind[1]} outside the scoped pids "
            f"(pid {event['pid']} line {event['lineno']})")
    return "allowed" if kind[0] in ("self", "pid") else "other-proc"


def check_census(events, scope, scoped_pids=(), cgroup=None):
    """Verdict on parsed strace events for one scope.

    ``scope`` is pid, run (the owned ``run`` child: same rules as pid),
    cgroup (``cgroup`` names the scoped cgroup root) or system (the census
    scope: a /proc walk passes). ``scoped_pids`` holds the in-scope pids.
    Returns the verdict record; raises EvidenceError naming the census.
    """
    _require(scope in ("pid", "run", "cgroup", "system"),
             f"unknown scope {_shown_path(scope)}")
    scoped = set()
    for value in scoped_pids:
        _require(type(value) is int and value > 0, "scoped pid out of range")
        scoped.add(value)
    if scope == "cgroup":
        _require(type(cgroup) is str and cgroup.startswith("/") and
                 len(cgroup) > 1, "cgroup scope needs an absolute cgroup")
        cgroup = cgroup.rstrip("/") or "/"
    if scope == "system":
        return {"scope": scope, "verdict": "pass", "events": len(events),
                "note": "system scope is the census scope"}
    counts = {"allowed": 0, "outside-proc": 0, "other-proc": 0,
              "unresolved-open": 0, "relative-unresolved": 0, "cgroup": 0}
    for event in events:
        path = event["path"]
        if scope == "cgroup" and path is not None and \
                path.startswith("/"):
            normal = _normalize(path)
            # /proc/self reads (including fd-relative cgroup.procs opens the
            # kernel resolves) classify under the pid rules below.
            if _proc_class(normal) == ("self",):
                counts[_census_pid_event(event, scoped)] += 1
                continue
            if _under(normal, cgroup):
                base = normal.rsplit("/", 1)[-1]
                if event["call"] == "getdents64" or \
                        base == "cgroup.procs" or \
                        event["directory_open"] or normal == cgroup:
                    counts["cgroup"] += 1
                    continue
                raise EvidenceError(
                    f"reads {_shown_path(normal)} outside the "
                    f"cgroup.procs set (pid {event['pid']} "
                    f"line {event['lineno']})")
            if normal.rsplit("/", 1)[-1] == "cgroup.procs":
                raise EvidenceError(
                    f"reads out-of-scope cgroup.procs {_shown_path(normal)} "
                    f"(pid {event['pid']} line {event['lineno']})")
            if event["call"] == "getdents64":
                bare = normal.rstrip("/") or "/"
                if bare != cgroup and _under(cgroup, bare):
                    raise EvidenceError(
                        f"enumerates {_shown_path(bare)} above the scoped "
                        f"cgroup (pid {event['pid']} line {event['lineno']})")
        counts[_census_pid_event(event, scoped)] += 1
    return {"scope": scope, "verdict": "pass", "events": len(events),
            "counts": counts}


def _record_keys(record, expected, what):
    _require(type(record) is dict and set(record) == set(expected),
             f"{what} must carry exactly {','.join(sorted(expected))}")


def _gaps(record):
    gaps = record["gaps"]
    _require(type(gaps) is list, "gaps must be a list")
    for gap in gaps:
        _require(type(gap) is dict and type(gap.get("reason")) is str and
                 gap["reason"], "every gap needs a non-empty reason")
    return gaps


def check_coverage(record):
    """Verdict on one cell's coverage declaration.

    ``{"cell", "coverage", "exit", "gaps", "refusal"}``: full coverage
    carries no gaps and no refusal; partial coverage needs an explicit
    PARTIAL marker plus a boundary gap; refused coverage needs refusal
    text and a nonzero exit. Anything silently narrowed fails.
    """
    _record_keys(record, {"cell", "coverage", "exit", "gaps", "refusal"},
                 "coverage record")
    _require(type(record["cell"]) is str and record["cell"], "cell names it")
    coverage = record["coverage"]
    _require(coverage in ("full", "partial", "refused"),
             f"unknown coverage {_shown_path(coverage)}")
    _require(type(record["exit"]) is int, "exit must be an integer")
    refusal = record["refusal"]
    _require(refusal is None or type(refusal) is str, "refusal must be text")
    gaps = _gaps(record)
    if coverage == "full":
        _require(not gaps, "full coverage carries gaps")
        _require(not refusal, "full coverage carries a refusal")
    elif coverage == "partial":
        _require(gaps, "partial coverage without a boundary gap")
        marked = (refusal and "PARTIAL" in refusal) or \
            any("PARTIAL" in gap["reason"] for gap in gaps)
        _require(marked, "partial coverage without explicit PARTIAL")
    else:
        _require(refusal, "refused coverage without refusal text")
        _require(record["exit"] != 0, "refused coverage with exit 0")
    return {"cell": record["cell"], "coverage": coverage, "verdict": "pass"}


def check_residency(samples, claim):
    """Verdict on an endpoint-sample residency claim.

    ``claim`` is ``{"kind", "start", "end"}`` on CLOCK_MONOTONIC ns.
    Endpoint samples never prove continuous residency: a continuous claim
    always fails. A sampled claim passes exactly when every sample stamp
    lies inside the claimed window.
    """
    _require(type(samples) is list and samples and
             all(type(value) is int and value >= 0 for value in samples),
             "samples must be a non-empty list of stamp integers")
    _record_keys(claim, {"kind", "start", "end"}, "residency claim")
    _require(claim["kind"] in ("sampled", "continuous"),
             f"unknown residency kind {_shown_path(claim['kind'])}")
    _require(type(claim["start"]) is int and type(claim["end"]) is int and
             0 <= claim["start"] <= claim["end"],
             "residency window out of range")
    _require(claim["kind"] == "sampled",
             "endpoint samples cannot prove continuous residency")
    for value in samples:
        _require(claim["start"] <= value <= claim["end"],
                 f"sample {value} lies outside the claimed window")
    return {"verdict": "pass", "samples": len(samples)}


def check_numbering(rows):
    """Verdict on caller rows against the observer /proc numbering.

    Each row is ``{"caller_pid", "observer_pid"}``; every caller pid must
    equal the observer numbering. An empty row set proves nothing and fails.
    """
    _require(type(rows) is list and rows, "numbering needs caller rows")
    for index, row in enumerate(rows):
        _record_keys(row, {"caller_pid", "observer_pid"}, "numbering row")
        caller = row["caller_pid"]
        observer = row["observer_pid"]
        _require(type(caller) is int and type(observer) is int,
                 f"numbering row {index} pids must be integers")
        _require(caller == observer,
                 f"numbering row {index}: caller pid {caller} is not the "
                 f"observer numbering {observer}")
    return {"verdict": "pass", "rows": len(rows)}


def check_replacement(record):
    """Verdict on a root/mount replacement cell.

    ``{"event", "exit", "gaps", "refusal"}``: the replacement must be
    refused (nonzero exit or refusal text) and must record a gap.
    """
    _record_keys(record, {"event", "exit", "gaps", "refusal"},
                 "replacement record")
    _require(record["event"] in ("root-replacement", "mount-replacement"),
             f"unknown replacement {_shown_path(record['event'])}")
    _require(type(record["exit"]) is int, "exit must be an integer")
    refusal = record["refusal"]
    _require(refusal is None or type(refusal) is str, "refusal must be text")
    _require(record["exit"] != 0 or refusal,
             "replacement without a refusal")
    _require(_gaps(record), "replacement without a recorded gap")
    return {"event": record["event"], "verdict": "pass"}


def check_partial_walk(evidence, boundary, record, scoped_pids=()):
    """Verdict on a partial-walk cell: the walk stops at the boundary and
    the output declares PARTIAL. ``evidence`` is strace text or parsed
    events; ``boundary`` is the forbidden path prefix."""
    _require(type(boundary) is str and boundary.startswith("/"),
             "boundary must be an absolute path")
    events = parse_strace(evidence) if type(evidence) is str else evidence
    scoped = set()
    for value in scoped_pids:
        _require(type(value) is int and value > 0, "scoped pid out of range")
        scoped.add(value)
    for event in events:
        path = event["path"]
        if path is None or not path.startswith("/"):
            continue
        path = _normalize(path)
        kind = _proc_class(path)
        if kind is not None and kind[0] in ("self", "other"):
            continue
        if kind is not None and kind[0] == "pid" and kind[1] in scoped:
            continue
        if kind == ("root",):
            raise EvidenceError(
                f"partial walk enumerates the bare /proc directory "
                f"(pid {event['pid']} line {event['lineno']})")
        if kind is not None and kind[0] == "pid":
            raise EvidenceError(
                f"partial walk opens /proc/{kind[1]} outside the scoped "
                f"pids (pid {event['pid']} line {event['lineno']})")
        if _under(path, boundary):
            raise EvidenceError(
                f"partial walk crosses {_shown_path(boundary)} at "
                f"{_shown_path(path)} (pid {event['pid']} "
                f"line {event['lineno']})")
    outcome = check_coverage(record)
    _require(outcome["coverage"] == "partial",
             "partial walk without a partial coverage declaration")
    return {"verdict": "pass", "events": len(events)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", help="strace evidence file, or -")
    parser.add_argument("--scope", required=True,
                        choices=("pid", "run", "cgroup", "system"))
    parser.add_argument("--pid", type=int, action="append", default=[],
                        help="in-scope pid (repeatable)")
    parser.add_argument("--cgroup", default=None,
                        help="scoped cgroup root (cgroup scope)")
    args = parser.parse_args(argv)
    try:
        if args.evidence == "-":
            text = read_evidence(sys.stdin)
        else:
            with open(args.evidence, encoding="utf-8") as stream:
                text = read_evidence(stream)
        result = check_census(parse_strace(text), args.scope,
                              scoped_pids=args.pid, cgroup=args.cgroup)
    except EvidenceError as error:
        print(f"narrow scope refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("narrow scope refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
