#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the 32 transient first-use sweep cells against one observer.

Each cell is a load -> one call -> unload transient from
tests/fixtures/system-first-use.c: the driver builds the fixture once (the
caller plus the file-backed and heap-table provider builds), runs every
(mode, delay, arm) combination under ``p11scope run --trace`` as an owned
child, judges the fixture ledger plus the parsed trace through
scripts/measure-first-use.py, and writes the delay-indexed bound table
(JSON plus a short markdown table) with exact missed-call and
caller-attribution integers.

The observer invocation is identical for every cell except ``--module``:
modes whose provider file exists before capture (known-inode, late-heap)
name it; copy modes (equal-bytes-new-inode, unseen-provider) omit it, since
the file the child maps does not exist until the fixture creates it. Every
cell runs with ``--pause never`` by default so the delay knob measures the
raw transient window; ``--pause-policy auto`` reruns the same matrix as a
control with the child held at each loader hit until probes attach. The
ungated/prearmed arm is fixture-side only.

The campaign verdict fails on any oracle failure, a gated cell counting
positive, an arm mismatch, a copy mode without source identity, a timeout,
a lossy or partial trace, or a missing cell. A missed call is data, never
a failure: it lands in the table as an exact integer.
"""

import argparse
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MEASURE = ROOT / "scripts" / "measure-first-use.py"
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "system-first-use.c"

MODES = ("known-inode", "equal-bytes-new-inode", "unseen-provider",
         "late-heap")
COPY_MODES = ("equal-bytes-new-inode", "unseen-provider")
MODES_WITH_MODULE = ("known-inode", "late-heap")
DELAYS_US = (0, 10, 100, 1000)
CAMPAIGN_ARMS = ("ungated", "prearmed")
EXPECTED_CELLS = [(mode, delay_us, armed)
                  for mode in MODES for delay_us in DELAYS_US
                  for armed in CAMPAIGN_ARMS]
BODY_FUNCTION = "C_Initialize"
UNKNOWN_LABEL = "Unknown executable"
SCHEMA = "p11scope-first-use-sweep/1"
DEFAULT_CELL_TIMEOUT_S = 120
MEASURE_TIMEOUT_S = 60
BUILD_TIMEOUT_S = 120
GCC_FLAGS = ["-O0", "-g", "-Wall", "-Wextra", "-Werror"]
ZERO_LOSS_FIELDS = ("event_loss", "start_insert_failures",
                    "unmatched_returns", "rv_update_failures",
                    "process_tracking_failures", "process_tracking_evictions",
                    "malformed_records", "in_flight_at_end",
                    "pending_at_end")

JSON_STRING = r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"'
ROW = re.compile(
    rf'\d{{2}}:\d{{2}}:\d{{2}}\.\d{{6}} (?P<label>Unknown executable|{JSON_STRING}) '
    rf'\(PID (?P<pid>[1-9]\d*), TID (?P<tid>[1-9]\d*)\)'
    rf'(?: exe=(?P<path>{JSON_STRING}))?(?: sess#[1-9]\d*)? '
    r'(?P<fn>C_[A-Za-z0-9_]+)(?: \[semantics unverified\])? '
    r'→ (?P<rv>CKR_[A-Z0-9_]+|0x[0-9a-fA-F]+) '
    r'(?P<duration>[0-9]+(?:\.[0-9]+)?(?:ns|µs|ms|s))')
TRACE_HEADERS = (
    "Trace — completed call events in arrival order",
    "Executable labels use verified observed paths; "
    "event PID/TID remain diagnostic identifiers.",
)


class SweepError(Exception):
    """The sweep setup, a cell, or the campaign table is not trustworthy."""


class SweepTimeout(SweepError):
    """A bounded command exceeded its cell timeout."""


def cell_key(mode, delay_us, armed):
    return f"{mode}|{delay_us}|{armed}"


def parse_trace(text):
    """Parse owned-child trace output into rows, counts and evidence."""
    rows, counts, evidence, errors = [], [], [], []
    for line in text.splitlines():
        match = ROW.fullmatch(line)
        if match:
            row = match.groupdict()
            row["pid"], row["tid"] = int(row["pid"]), int(row["tid"])
            if row["label"] == UNKNOWN_LABEL:
                if row["path"] is not None:
                    errors.append("unknown row carries an executable path")
                row["path"], row["label"] = None, None
            else:
                row["label"] = json.loads(row["label"])
                row["path"] = json.loads(row["path"]) if row["path"] else None
                if not row["path"]:
                    errors.append("named row lacks an executable path")
            rows.append(row)
        elif line.startswith(("COUNT_EVIDENCE ", "EVIDENCE ")):
            prefix, body = line.split(" ", 1)
            try:
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise ValueError("record is not an object")
                (counts if prefix == "COUNT_EVIDENCE" else evidence).append(
                    value)
            except (ValueError, TypeError) as error:
                errors.append(f"invalid {prefix}: {error}")
        elif (not line or line in TRACE_HEADERS
                or line.startswith("CAPTURE privacy=")):
            continue
        elif line.startswith(("LOST ", "TRUNCATED ")):
            errors.append(f"trace ended with loss evidence: {line[:160]}")
        else:
            errors.append(f"unexpected trace record: {line[:160]}")
    return {"rows": rows, "counts": counts, "evidence": evidence,
            "errors": errors}


def select_body_rows(rows, pid):
    """Split trace rows into the cell body call, extras and foreign rows."""
    body, extras, foreign = [], [], []
    for row in rows:
        if row["pid"] != pid:
            foreign.append(row)
        elif row["fn"] == BODY_FUNCTION:
            body.append(row)
        else:
            extras.append(row)
    return {"body": body, "extras": extras, "foreign": foreign}


def check_body_returns(body_rows):
    """Every body row must agree with the ledgered rv 0 (CKR_OK)."""
    errors = []
    for row in body_rows:
        if row["rv"] != "CKR_OK":
            errors.append(
                f"trace row for {BODY_FUNCTION} disagrees with the "
                f"ledgered rv 0: {row['rv']}")
    return errors


def check_foreign_rows(selected, pid):
    """Refuse trace rows captured outside the cell pid."""
    if selected["foreign"]:
        return [f"trace captured {len(selected['foreign'])} rows "
                f"outside the cell pid {pid}"]
    return []


def check_counts(rows, counts):
    """The terminal count record must account every parsed row."""
    if len(counts) != 1:
        return ["expected exactly one terminal count record"]
    errors = []
    for field in ("stats_entered", "stats_returned", "raw_calls"):
        value = counts[0].get(field)
        if type(value) is not int or value != len(rows):
            errors.append(f"terminal {field} disagrees with parsed rows: "
                          f"{value!r} versus {len(rows)}")
    return errors


def check_evidence(evidence):
    """The terminal evidence must prove an exact, drained capture."""
    if len(evidence) != 1:
        return ["expected exactly one terminal evidence record"]
    record = evidence[0]
    errors = []
    if record.get("privacy_mode") != "allowlisted":
        errors.append("capture privacy policy differs from the requested "
                      f"allowlisted policy: {record.get('privacy_mode')!r}")
    if record.get("completeness") not in ("COMPLETE", "PARTIAL"):
        errors.append("terminal evidence without COMPLETE or PARTIAL "
                      "completeness: "
                      f"{record.get('completeness')!r}")
    scheduling = record.get("scheduling")
    if isinstance(scheduling, dict):
        for field in ("sink_stall_ms", "sink_timeouts",
                      "sink_dropped_bytes"):
            if field not in scheduling:
                continue
            value = scheduling[field]
            if type(value) is not int or value != 0:
                errors.append(f"capture reports {field} {value!r} in this "
                              "exact-count cell")
    for field in ZERO_LOSS_FIELDS:
        if field not in record:
            if field == "event_loss":
                errors.append("terminal evidence without event_loss")
            continue
        value = record[field]
        if type(value) is not int or value != 0:
            errors.append(f"capture reports {field} {value!r} in this "
                          "exact-count cell")
    if record.get("final_drain") is not True:
        errors.append("capture lacks its final drain proof")
    if record.get("trace_truncated") is True:
        errors.append("trace stream is truncated")
    if record.get("provider_changed") is True:
        errors.append("pinned provider object changed after attach")
    return errors


def build_observer_record(body_rows):
    """Observer record for the oracle: one caller row per body row."""
    return {"observed_calls": len(body_rows),
            "caller_rows": [{"pid": row["pid"],
                             "label": row["label"] or UNKNOWN_LABEL}
                            for row in body_rows]}


def without_sink_fields(record):
    """Evidence without the sink-timing fields that may differ by stream."""
    record = dict(record)
    scheduling = record.get("scheduling")
    if isinstance(scheduling, dict):
        scheduling = dict(scheduling)
        for field in ("sink_stall_ms", "sink_timeouts",
                      "sink_dropped_bytes"):
            scheduling.pop(field, None)
        record["scheduling"] = scheduling
    return record


def compare_streams(file_parsed, stdout_parsed):
    """Problems where the trace file and stdout streams disagree.

    Rows and terminal counts must match exactly; evidence must match once
    the per-stream sink-timing fields are stripped.
    """
    problems = []
    if file_parsed["rows"] != stdout_parsed["rows"]:
        problems.append("stdout/file trace row disagreement")
    if file_parsed["counts"] != stdout_parsed["counts"]:
        problems.append("stdout/file terminal count disagreement")
    file_evidence = [without_sink_fields(record) for record in
                     file_parsed["evidence"]]
    stdout_evidence = [without_sink_fields(record) for record in
                       stdout_parsed["evidence"]]
    if file_evidence != stdout_evidence:
        problems.append("stdout/file terminal evidence disagreement")
    return problems


def run_bounded(argv, timeout_s, cwd=None, env=None):
    """Run argv to completion inside timeout_s, killing its process group."""
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=cwd, env=env,
                                 start_new_session=True)
    except OSError as error:
        raise SweepError(f"cannot start {' '.join(argv)}: {error}") from error
    try:
        stdout, stderr = child.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        try:
            stdout, stderr = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            stdout, stderr = child.communicate()
        raise SweepTimeout(f"command exceeded {timeout_s}s timeout: "
                           f"{' '.join(argv)}") from error
    return subprocess.CompletedProcess(argv, child.returncode, stdout,
                                       stderr)


def _require_integer(record, key, where):
    value = record.get(key)
    if type(value) is not int or value < 0:
        raise SweepError(f"{where} without an exact {key} integer")


def build_campaign(records, meta):
    """Judge 32 per-cell records into the bound table, markdown and verdict.

    Every record carries mode, delay_us, intended armed and a status. An
    "ok" record carries the oracle-judged exact integers plus the evidence
    summary; any other status carries a reason and fails the campaign.
    """
    errors = []
    for key in ("source_revision", "observer", "started_unix",
                "finished_unix"):
        if key not in meta:
            raise SweepError(f"campaign meta without {key}")
    seen = set()
    by_key = {}
    for record in records:
        key = (record.get("mode"), record.get("delay_us"),
               record.get("armed"))
        label = cell_key(*key)
        if key in seen:
            errors.append(f"duplicate cell {label}")
            continue
        seen.add(key)
        by_key[key] = record
        if key not in EXPECTED_CELLS:
            errors.append(f"unknown cell {label}")
    for key in EXPECTED_CELLS:
        if key not in seen:
            errors.append(f"missing cell {cell_key(*key)}")
    for key in sorted(by_key, key=repr):
        record = by_key[key]
        label = cell_key(*key)
        if key not in EXPECTED_CELLS:
            continue
        status = record.get("status")
        if status != "ok":
            errors.append(f"cell {label} {status or 'without status'}: "
                          f"{record.get('reason', 'no reason recorded')}")
            continue
        try:
            if record.get("armed_ledger") != record.get("armed"):
                if (record.get("armed_ledger") == "gated"
                        and record.get("positive") is True):
                    raise SweepError(
                        f"cell {label} gated cell counted as positive")
                raise SweepError(
                    f"cell {label} ran {record.get('armed_ledger')} "
                    f"instead of intended {record.get('armed')}")
            if record.get("positive") is not True:
                raise SweepError(f"cell {label} is not a positive "
                                 "measurement")
            for field in ("body_calls", "observed_calls", "missed_calls",
                          "attributed_calls"):
                _require_integer(record, field, f"cell {label}")
            body = record["body_calls"]
            observed = record["observed_calls"]
            if observed > body:
                raise SweepError(f"cell {label} observed {observed} "
                                 f"above body {body}")
            if record["missed_calls"] != body - observed:
                raise SweepError(f"cell {label} missed count disagrees "
                                 "with its body count")
            if not 0 <= record["attributed_calls"] <= observed:
                raise SweepError(f"cell {label} attributed outside "
                                 "observed")
        except SweepError as error:
            errors.append(str(error))
    bounds = {str(delay): 0 for delay in DELAYS_US}
    ordered = []
    if not errors:
        for key in sorted(by_key, key=repr):
            record = by_key[key]
            delay = str(record["delay_us"])
            bounds[delay] = max(bounds[delay], record["missed_calls"])
            ordered.append(record)
    table = {"schema": SCHEMA, **meta, "cells": ordered, "bounds": bounds,
             "verdict": "pass" if not errors else "fail", "errors": errors}
    return {"table": table, "markdown": render_markdown(ordered, bounds),
            "verdict": table["verdict"], "errors": errors}


def render_markdown(cells, bounds):
    """Short markdown table: per-cell missed/attributed plus delay bounds."""
    lines = ["| mode | arm | 0 us | 10 us | 100 us | 1000 us |",
             "| --- | --- | --- | --- | --- | --- |"]
    lookup = {(cell["mode"], cell["armed"], cell["delay_us"]): cell
              for cell in cells}
    for mode in sorted(MODES):
        for armed in sorted(CAMPAIGN_ARMS):
            values = []
            for delay in DELAYS_US:
                cell = lookup.get((mode, armed, delay))
                values.append("?" if cell is None else
                              f"{cell['missed_calls']}/"
                              f"{cell['attributed_calls']}")
            lines.append(f"| {mode} | {armed} | {' | '.join(values)} |")
    bound_values = " | ".join(str(bounds[str(delay)]) for delay in DELAYS_US)
    lines.append(f"| bound (max missed) | | {bound_values} |")
    return "\n".join(lines) + "\n"


def _run_build(argv):
    """Run one fixture build command; keep the compiler diagnostic."""
    done = run_bounded(argv, BUILD_TIMEOUT_S)
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace")[-2000:]
        raise SweepError(f"build {' '.join(argv)} exited "
                         f"{done.returncode}: {detail}")
    return done


def compile_fixture(gcc, source, build_dir):
    """Build the caller plus the file-backed and heap-table providers."""
    build_dir.mkdir(parents=True, exist_ok=True)
    driver = build_dir / "first-use-driver"
    providers = {}
    runs = [(["-DT2_PROVIDER"], build_dir / "provider-file.so"),
            (["-DT2_PROVIDER", "-DT2_HEAP_TABLE"],
             build_dir / "provider-heap.so")]
    try:
        _run_build([gcc, *GCC_FLAGS, str(source), "-ldl", "-o",
                    str(driver)])
        for extra, path in runs:
            _run_build([gcc, *GCC_FLAGS, "-shared", "-fPIC", *extra,
                        str(source), "-o", str(path)])
            kind = "heap" if "-DT2_HEAP_TABLE" in extra else "file"
            providers[kind] = path
    except SweepError as error:
        raise SweepError(f"fixture build failed: {error}") from error
    for path in (driver, *providers.values()):
        if not path.is_file():
            raise SweepError(f"fixture build produced no {path.name}")
        os.chmod(path, 0o755)
    os.chmod(build_dir, 0o755)
    return {"driver": driver, "providers": providers}


def observer_argv(observer, provider, built, ledger, pub_gate, entry_gate,
                  mode, delay_us, trace_path, pause="never"):
    """The owned-child trace invocation for one sweep cell."""
    argv = [str(observer), "run", "--trace"]
    if mode in MODES_WITH_MODULE:
        argv += ["--module", str(provider)]
    argv += ["--pause", pause, "-o", str(trace_path), "--",
            str(built["driver"]), str(provider), str(ledger),
            str(pub_gate), str(entry_gate),
            "--mode", mode, "--delay-us", str(delay_us)]
    return argv


# The same ledger bounds the oracle enforces in its read_rows
# (scripts/measure-first-use.py): the driver extracts the cell pid before
# the oracle re-validates, so it must not read unbounded input first.
LEDGER_MAX_BYTES = 1024 * 1024
LEDGER_MAX_ROWS = 1024
LEDGER_LINE_CAP = 65536 + 1


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_ledger(ledger):
    """Read the fixture ledger with the oracle's byte/row/key bounds."""
    rows = []
    total = 0
    with open(ledger, encoding="utf-8") as stream:
        while True:
            line = stream.readline(LEDGER_LINE_CAP)
            if not line:
                break
            total += len(line.encode("utf-8", "replace"))
            if total > LEDGER_MAX_BYTES:
                raise ValueError("ledger exceeds its byte limit")
            if len(rows) >= LEDGER_MAX_ROWS:
                raise ValueError("ledger exceeds its row limit")
            if not line.strip():
                continue
            rows.append(json.loads(line, object_pairs_hook=_unique_object))
    cells = [row for row in rows
             if isinstance(row, dict) and row.get("phase") == "cell"]
    if len(cells) != 1:
        raise SweepError("ledger without exactly one cell row")
    return rows, cells[0]


def run_cell(observer, measure, built, cell_dir, mode, delay_us, armed,
             uid, gid, timeout_s, pause="never"):
    """Run one sweep cell; return its campaign record (never a skip)."""
    label = cell_key(mode, delay_us, armed)
    try:
        cell_dir.mkdir(parents=True, exist_ok=True)
        os.chown(cell_dir, uid, gid)
    except OSError as error:
        raise SweepError(f"cell {label} workdir not delegable: {error}")
    ledger = cell_dir / "ledger.jsonl"
    trace_path = cell_dir / "trace.out"
    stdout_path = cell_dir / "trace.stdout"
    stderr_path = cell_dir / "observer.stderr"
    provider = (built["providers"]["heap"] if mode == "late-heap"
                else built["providers"]["file"])
    started = time.monotonic()
    try:
        if armed == "prearmed":
            pub_gate = cell_dir / "publish-gate"
            entry_gate = cell_dir / "entry-gate"
            pub_gate.touch()
            entry_gate.touch()
        else:
            pub_gate = Path("-")
            entry_gate = Path("-")
        argv = observer_argv(observer, provider, built, ledger, pub_gate,
                            entry_gate, mode, delay_us, trace_path,
                            pause)
        env = dict(os.environ)
        env["SUDO_UID"], env["SUDO_GID"] = str(uid), str(gid)
        try:
            done = run_bounded(argv, timeout_s, env=env)
        except SweepTimeout as error:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "timeout", "reason": str(error)}
        duration_s = time.monotonic() - started
        stdout_path.write_bytes(done.stdout)
        stderr_path.write_bytes(done.stderr)
        if done.returncode != 0:
            tail = done.stderr.decode("utf-8", "replace")[-500:]
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error",
                    "reason": f"observer exited {done.returncode}: {tail}"}
        if not trace_path.is_file():
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error",
                    "reason": "observer produced no trace file"}
        if not ledger.is_file():
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error", "reason": "fixture left no ledger"}
        _, cell = _read_ledger(ledger)
        pid = cell.get("pid")
        if type(pid) is not int or pid <= 0:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error",
                    "reason": "ledger cell row without a caller pid"}
        file_parsed = parse_trace(
            trace_path.read_text(encoding="utf-8", errors="replace"))
        stdout_parsed = parse_trace(
            done.stdout.decode("utf-8", "replace"))
        problems = ([f"trace file: {error}"
                     for error in file_parsed["errors"]]
                    + [f"trace stdout: {error}"
                       for error in stdout_parsed["errors"]])
        if not problems:
            problems += compare_streams(file_parsed, stdout_parsed)
            problems += check_counts(file_parsed["rows"],
                                     file_parsed["counts"])
            problems += check_evidence(file_parsed["evidence"])
        if not problems:
            selected = select_body_rows(file_parsed["rows"], pid)
            problems += check_foreign_rows(selected, pid)
            problems += check_body_returns(selected["body"])
        if problems:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error", "reason": "; ".join(problems)}
        observer_record = build_observer_record(selected["body"])
        observer_path = cell_dir / "observer.json"
        observer_path.write_text(json.dumps(observer_record, sort_keys=True))
        try:
            judged = run_bounded(
                [sys.executable, "-I", str(measure), str(ledger),
                 str(observer_path)], MEASURE_TIMEOUT_S)
        except SweepTimeout as error:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "timeout", "reason": str(error)}
        if judged.returncode != 0:
            refusal = judged.stderr.decode("utf-8", "replace").strip()
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "oracle-refused",
                    "reason": refusal or "oracle refused the cell"}
        try:
            verdict = json.loads(judged.stdout.decode("utf-8"))
        except ValueError as error:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "error",
                    "reason": f"oracle verdict is not JSON: {error}"}
        (cell_dir / "verdict.json").write_text(
            json.dumps(verdict, sort_keys=True, indent=2))
        if verdict.get("positive") is not True:
            return {"mode": mode, "delay_us": delay_us, "armed": armed,
                    "status": "not-positive",
                    "reason": verdict.get("reason",
                                          "oracle verdict not positive")}
        missed = verdict["missed"]
        attributed = verdict["attribution"]
        extras = {}
        for row in selected["extras"]:
            slot = extras.setdefault(row["fn"], {"count": 0, "unknown": 0})
            slot["count"] += 1
            slot["unknown"] += row["label"] is None
        evidence = file_parsed["evidence"][0]
        return {"mode": mode, "delay_us": delay_us, "armed": armed,
                "status": "ok", "armed_ledger": verdict.get("armed"),
                "body_calls": missed["body_calls"],
                "observed_calls": missed["observed_calls"],
                "missed_calls": missed["missed_calls"],
                "attributed_calls": attributed["attributed_calls"],
                "positive": True, "duration_s": round(duration_s, 3),
                "completeness": evidence.get("completeness"),
                "final_drain": evidence.get("final_drain"),
                "event_loss": evidence.get("event_loss"),
                "pause": pause,
                "evidence": evidence,
                "extra_functions": extras,
                "observer_argv": [str(part) for part in argv]}
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {"mode": mode, "delay_us": delay_us, "armed": armed,
                "status": "error", "reason": f"cell I/O failed: {error}"}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_revision(explicit):
    if explicit is not None:
        return explicit
    try:
        done = run_bounded(["git", "-C", str(ROOT), "rev-parse", "HEAD"], 15)
    except SweepError:
        return "unknown"
    revision = done.stdout.decode("utf-8", "replace").strip()
    if done.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", revision):
        return revision
    return "unknown"


def preflight(args):
    """Refuse before the window opens when the lane cannot run."""
    if os.geteuid() != 0:
        raise SweepError("sweep requires root: the observer attaches BPF")
    if args.uid <= 0 or args.gid <= 0:
        raise SweepError("workload uid/gid must name an ordinary account")
    try:
        pwd.getpwuid(args.uid)
    except KeyError as error:
        raise SweepError(f"unknown workload uid {args.uid}") from error
    try:
        grp.getgrgid(args.gid)
    except KeyError as error:
        raise SweepError(f"unknown workload gid {args.gid}") from error
    observer = Path(args.observer)
    if not (observer.is_file() and os.access(observer, os.X_OK)):
        raise SweepError(f"observer is not executable: {observer}")
    measure = Path(args.measure)
    if not measure.is_file():
        raise SweepError(f"oracle missing: {measure}")
    source = Path(args.fixture_source)
    if not source.is_file():
        raise SweepError(f"fixture source missing: {source}")
    try:
        done = run_bounded([args.gcc, "--version"], 30)
    except SweepError as error:
        raise SweepError(f"gcc preflight failed: {error}") from error
    if done.returncode != 0:
        raise SweepError("gcc preflight failed: compiler not usable")
    if not 1 <= args.cell_timeout <= 3600:
        raise SweepError("cell timeout must stay within 1..3600s")
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise SweepError(f"refusing to reuse out dir: {out}") from error
    except OSError as error:
        raise SweepError(f"cannot create out dir {out}: {error}") from error
    return {"observer": observer, "measure": measure, "source": source,
            "out": out}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True,
                        help="observer binary to sweep against")
    parser.add_argument("--uid", type=int, required=True,
                        help="ordinary workload uid for the owned child")
    parser.add_argument("--gid", type=int, required=True,
                        help="ordinary workload gid for the owned child")
    parser.add_argument("--out", required=True,
                        help="new-only output directory for the campaign")
    parser.add_argument("--cell-timeout", type=int,
                        default=DEFAULT_CELL_TIMEOUT_S,
                        help="seconds bounding each cell "
                             f"(default {DEFAULT_CELL_TIMEOUT_S})")
    parser.add_argument("--pause-policy", choices=("never", "auto"),
                        default="never",
                        help="observer pause policy for every cell "
                             "(auto reruns the matrix as a held control)")
    parser.add_argument("--measure", default=str(DEFAULT_MEASURE),
                        help="measure-first-use.py oracle path")
    parser.add_argument("--fixture-source", default=str(DEFAULT_FIXTURE),
                        help="system-first-use.c fixture source")
    parser.add_argument("--gcc", default="gcc", help="C compiler")
    parser.add_argument("--source-revision", default=None,
                        help="exact 40-hex source commit (else git HEAD)")
    args = parser.parse_args(argv)
    if (args.source_revision is not None and not re.fullmatch(
            r"[0-9a-f]{40}", args.source_revision)):
        parser.error("source revision must be an exact 40-hex commit")
    try:
        ready = preflight(args)
        started = int(time.time())
        built = compile_fixture(args.gcc, ready["source"],
                                ready["out"] / "build")
        records = []
        for mode, delay_us, armed in EXPECTED_CELLS:
            record = run_cell(
                ready["observer"], ready["measure"], built,
                ready["out"] / f"cell-{mode}-{delay_us}us-{armed}",
                mode, delay_us, armed, args.uid, args.gid,
                args.cell_timeout, args.pause_policy)
            records.append(record)
            print(json.dumps({"cell": cell_key(mode, delay_us, armed),
                              "status": record["status"],
                              **({"missed_calls": record["missed_calls"],
                                   "attributed_calls":
                                       record["attributed_calls"]}
                                  if record["status"] == "ok" else
                                  {"reason": record["reason"]})}),
                  flush=True)
        meta = {"source_revision": _source_revision(args.source_revision),
                "observer": {"path": str(ready["observer"]),
                             "sha256": _sha256(ready["observer"])},
                "host": {"kernel": platform.release(),
                         "cpus": os.cpu_count()},
                "started_unix": started,
                "finished_unix": int(time.time())}
        result = build_campaign(records, meta)
        (ready["out"] / "table.json").write_text(
            json.dumps(result["table"], sort_keys=True, indent=2))
        (ready["out"] / "table.md").write_text(result["markdown"])
        print(json.dumps({"verdict": result["verdict"],
                          "cells": len(records),
                          "bounds": result["table"]["bounds"],
                          "table": str(ready["out"] / "table.json")}),
              flush=True)
        return 0 if result["verdict"] == "pass" else 1
    except (SweepError, OSError) as error:
        print(f"sweep refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

