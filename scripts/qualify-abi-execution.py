#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed 104-slot ABI execution qualification, LP64 and ia32 (stage-3
cell 3.8, missing piece M9).

Builds tests/fixtures/abi-execution/abi-104.c for LP64 and -m32, runs every
condition scripts/joint-abi-compare.py knows against an installed observer
(`p11scope profile --pid`, the T9 command; profile is the native capture
lane and has no --capture flag), and judges each cell with
joint-abi-compare.py. One verdict per cell plus an overall verdict; a
missing or timed-out cell fails. Every wait is bounded.

Provider choice: the emitter is stub-only (it refuses providers without
the P11ScopeSlot68 marker, pinned by
test_joint_abi_oracle.py::test_fixture_refuses_nonstub_provider, and OD-R5
sends V5-26 ia32 to the -m32 provider build), so LP64 cells use the
exported live-discovery-provider stub, ia32 cells its -m32 build, and the
rv64 cells the high-bit stub tests/fixtures/abi-execution/
abi-rv64-provider.c. SoftHSM cannot drive these cells.

Judging is at the level v0.5.0 ships: native per-function call counts plus
the plain S1 proof, not the 0.5.1 key-operation journal. Per cell, in
order: (1) the gated workload must exit as designed (0, or 1 for rv64
whose high-bit returns are unhealthy by construction) with an
oracle-valid ledger bound to the expected (cond, cell) population tag;
(2) the profile report must pass the S1 gates mirrored from
public-cli-oracle.py (schema/lane/scope, zero loss counters, a healthy
kernel account, the canonical terminal verdict, admission of the pinned
provider, well-formed function rows) with the attribution causes
restricted to the known scan-only disclosure and the observation causes
pinned to the deterministic attach-late set (PINNED_OBSERVATION_CAUSES),
plus a fully walked 104-function surface; (3) the
observer's per-ordinal counts convert to a counts document (calls count
entries, returns count returns, return values expand full-width; rows
without ordinals and rows outside the ledger population must be quiet;
active rows must bind to the pinned provider bytes); (4)
joint-abi-compare.py judges the saved ledger against the saved counts
through its CLI, so any verdict replays byte-for-byte from the artifacts.

The blocked cell instead proves in-flight accounting on a real call: the
slot-10 provider entry waits for this driver's release file, the driver
ends the capture with the call in flight only after the provider proves
the entry, checks the stopped report saw it, and only then releases, so
the S1 pin for that cell is exactly one in-flight call with its matching
observation cause.

Usage (as root; the observer refuses otherwise):
  python3 -I scripts/qualify-abi-execution.py --observer ./p11scope --out DIR
  python3 -I scripts/qualify-abi-execution.py --observer ./p11scope --out DIR \\
      --arch ia32 --cell full --cell blocked
  python3 -I scripts/qualify-abi-execution.py --observer ./p11scope --out DIR \\
      --fixtures PREBUILT --loader32 /lib/ld-linux.so.2

Exit 0 when every run cell passes, 1 otherwise. results.jsonl carries one
record per cell plus the overall record.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

DRIVER_DIR = Path(__file__).resolve().parent
ORACLE_NAME = "joint-abi-compare.py"
EVIDENCE_NAME = "check-capture-evidence.py"
PIN_NAME = "mapped-provider-pin.py"
RECEIPT_SCHEMA = "p11scope/abi-execution-receipt/v1"

READY_TIMEOUT = 60
CAPTURING_TIMEOUT = 180
FIXTURE_TIMEOUT = 180
ORACLE_TIMEOUT = 120
BUILD_TIMEOUT = 300
BLOCKED_ENTER_TIMEOUT = 60
MAX_CALLS = 200000
MAX_WORD = (1 << 64) - 1

PROFILE_SCHEMA = "p11scope/observed-profile/v3"

# Every condition the oracle knows, in run order, with the emitter argv, the
# provider family, the designed workload exit and the expected population
# tag. Threaded args and the entry index mirror the oracle twins exactly.
CELLS = {
    "full": {"mode": "full", "arg": None, "provider": "stub",
             "workload_exit": 0, "cond": "full", "cell": "full"},
    "threads": {"mode": "threads", "arg": "4,25,5", "provider": "stub",
                "workload_exit": 0, "cond": "threads", "cell": "threads"},
    "hot": {"mode": "hot", "arg": "8,50,5", "provider": "stub",
            "workload_exit": 0, "cond": "hot", "cell": "hot-keys"},
    "cellrun": {"mode": "cell:g31-575", "arg": None, "provider": "stub",
                "workload_exit": 0, "cond": "cellrun", "cell": "g31-575"},
    "rv64": {"mode": "rv64", "arg": None, "provider": "hibit",
             "workload_exit": 1, "cond": "rv64", "cell": "rv64"},
    "entry": {"mode": "entry", "arg": "103", "provider": "stub",
              "workload_exit": 0, "cond": "entry", "cell": "entry"},
    "migration": {"mode": "cond:migration", "arg": None, "provider": "stub",
                  "workload_exit": 0, "cond": "migration",
                  "cell": "cond-migration"},
    "nesting": {"mode": "cond:nesting", "arg": None, "provider": "stub",
                "workload_exit": 0, "cond": "nesting", "cell": "cond-nesting"},
    "recursion": {"mode": "cond:recursion", "arg": None, "provider": "stub",
                  "workload_exit": 0, "cond": "recursion",
                  "cell": "cond-recursion"},
    "longjmp": {"mode": "cond:longjmp", "arg": None, "provider": "stub",
                "workload_exit": 0, "cond": "longjmp", "cell": "cond-longjmp"},
    "thread-exit": {"mode": "cond:thread-exit", "arg": None,
                    "provider": "stub", "workload_exit": 0,
                    "cond": "thread-exit", "cell": "cond-thread-exit"},
    "held-detach": {"mode": "cond:held-detach", "arg": None,
                    "provider": "stub", "workload_exit": 0,
                    "cond": "held-detach", "cell": "cond-held-detach"},
    "blocked": {"mode": "blocked", "arg": None, "provider": "stub",
                "workload_exit": 0, "cond": "blocked",
                "cell": "blocked-unreturned"},
}
COND_ORDER = ["full", "threads", "hot", "cellrun", "rv64", "entry",
              "migration", "nesting", "recursion", "longjmp", "thread-exit",
              "held-detach", "blocked"]

# Same loss tuple public-cli-oracle.py gates profile-pid cells with.
LOSS_COUNTERS = ("event_loss", "in_flight_at_end", "start_insert_failures",
                 "unmatched_returns", "rv_update_failures",
                 "cgroup_scope_failures", "abi_refusals", "malformed_records",
                 "discovery_ring_loss", "discovery_state_failures",
                 "discovery_read_failures", "discovery_truncated",
                 "task_uprobe_link_losses")

# The only attribution causes a scan-only pid cell may carry: slots the
# scan found stay semantics-unverified, and an unlinked table stays
# uncorroborated. Anything else is an anomaly, never a disclosure.
SCAN_ATTRIBUTION_CAUSES = frozenset({"semantic_unverified_slots",
                                     "discovery_uncorroborated"})

# The pinned S1 observation disclosure for gated attach-late pid cells over
# a legacy-only stub (the qualify-key-operations.py --s1 pattern: pin the
# S1-level disclosure exactly instead of demanding Joint-style exactness).
# A gated attach-late capture over the frozen emitter deterministically
# reports these three, and only these three, observation causes: the
# pre-attach live window stays unprotected (the GO gate proves the
# workload window itself starts after capturing, and zero loss proves
# nothing was missed inside it), the exit-time dlclose loader hits stay
# timing-unproven (the emitter always dlcloses at exit, abi-104.c; a
# no-dlclose variant drops exactly these two causes with identical
# counts), and the legacy-only workload never selects through
# C_GetInterface (absent and attach-late uncovered in every variant,
# while the table itself walks full). Fewer causes would claim a
# whole-life exactness no attach-late capture can have; more causes are
# anomalies. Either deviation fails the cell. The verdict detail and
# causes are always recorded beside the verdict, never hidden by it.
PINNED_OBSERVATION_CAUSES = frozenset({"unprotected_live_windows",
                                       "loader_discovery",
                                       "interface_selection"})

RV_KEY_PATTERN = re.compile(r"(?:0[xX])?[0-9a-fA-F]{1,16}\Z")


class DriverRefusal(Exception):
    """A cell artifact is missing, inconsistent or outside the S1 contract."""


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_oracle(scripts_dir):
    return _load("joint_abi_compare", Path(scripts_dir) / ORACLE_NAME)


def load_evidence(scripts_dir):
    return _load("check_capture_evidence", Path(scripts_dir) / EVIDENCE_NAME)


def load_pin(scripts_dir):
    return _load("mapped_provider_pin", Path(scripts_dir) / PIN_NAME)


def gcc_fixture_cmd(cc, src, out, m32):
    """Emitter build argv, mirroring the oracle twins' LP64/-m32 pair."""
    cmd = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if m32:
        cmd.append("-m32")
    return cmd + ["-pthread", str(src), "-ldl", "-o", str(out)]


def gcc_provider_cmd(cc, src, out, m32, exports_macro=True):
    """Stub-provider build argv; the hibit provider needs no export macro."""
    cmd = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if m32:
        cmd.append("-m32")
    cmd.append("-fPIC")
    if exports_macro:
        cmd.append("-DP11SCOPE_EXPORT_TABLES=1")
    return cmd + ["-shared", "-Wl,-z,defs", "-o", str(out), str(src)]


def wait_for_match(path, pattern, timeout_s):
    """First line matching pattern in path, or None on timeout."""
    want = re.compile(pattern)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                for line in stream.read().splitlines():
                    if want.search(line):
                        return line
        except OSError:
            pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.05)


def _u64(value):
    return type(value) is int and 0 <= value <= MAX_WORD


def check_ledger_binding(rows, cond, cell):
    """Bind validated ledger rows to the expected population tag.

    Returns the (cell, entry) key set. Only call/entry rows carry the tag;
    thread/cpu rows are tagless by oracle design.
    """
    keys = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("kind") not in ("call", "entry"):
            continue
        if row.get("cond") != cond:
            raise DriverRefusal(f"ledger cond is not {cond}")
        if row.get("cell") != cell:
            raise DriverRefusal(f"ledger cell is not {cell}")
        keys.add((row.get("cell"), row.get("entry")))
    if not keys:
        raise DriverRefusal("ledger without populations")
    return keys


def parse_rv_counts(rv_counts):
    """Expand full-width hex RV counts into a return-value multiset."""
    if type(rv_counts) is not dict:
        raise DriverRefusal("rv_counts is not an object")
    total = 0
    expanded = []
    for key in sorted(rv_counts):
        count = rv_counts[key]
        if type(key) is not str or RV_KEY_PATTERN.match(key) is None:
            raise DriverRefusal("rv_counts key is not hex")
        if type(count) is not int or count < 0:
            raise DriverRefusal("rv_counts count is not a counter")
        total += count
        if total > MAX_CALLS:
            raise DriverRefusal("rv_counts carry too many returns")
        expanded.extend([int(key, 16)] * count)
    return expanded


def _identity_matches(candidate, pin):
    return (isinstance(candidate, dict)
            and candidate.get("dev") == pin["dev"]
            and candidate.get("ino") == pin["ino"])


def counts_from_profile(report, rows, pin, cond, cell):
    """Convert the observer's per-ordinal counts into a counts document.

    Entry positions come from the rows' ordinals, fn labels from the rows'
    names, entries from calls plus in-flight, returns from calls, and the
    RV multiset from the full-width rv_counts. Rows without ordinals and
    rows outside the ledger population must be quiet, and active rows must
    bind to the pinned provider bytes, so the oracle's exact join cannot
    pass beside unmapped observer activity.
    """
    keys = check_ledger_binding(rows, cond, cell)
    entries = {entry for _, entry in keys}
    functions = report.get("functions")
    if type(functions) is not list:
        raise DriverRefusal("report functions are not a list")
    by_ordinal = {}
    notes = set()
    for position, row in enumerate(functions):
        if type(row) is not dict or type(row.get("ordinals")) is not list:
            raise DriverRefusal(f"function row {position} has no ordinals")
        for item in row["ordinals"]:
            if (type(item) is not dict or type(item.get("ordinal")) is not int
                    or not 0 <= item["ordinal"] <= 103):
                raise DriverRefusal(f"function row {position} ordinal invalid")
            by_ordinal.setdefault(item["ordinal"], []).append(position)
    counts = []
    for key in sorted(keys):
        _, entry = key
        claimants = by_ordinal.get(entry, [])
        if not claimants:
            raise DriverRefusal(f"entry {entry} has no observer row")
        if len(claimants) > 1:
            raise DriverRefusal(f"ordinal {entry} claimed by rows")
        row = functions[claimants[0]]
        names = row.get("names")
        if (type(names) is not list or not names
                or any(type(name) is not str for name in names)):
            raise DriverRefusal(f"entry {entry} names invalid")
        row_entries = {item["ordinal"] for item in row["ordinals"]}
        if len(row_entries & entries) > 1:
            raise DriverRefusal(f"entry {entry} shares its target")
        calls = row.get("calls")
        in_flight = row.get("in_flight")
        if not _u64(calls) or not _u64(in_flight):
            raise DriverRefusal(f"entry {entry} counters invalid")
        if calls + in_flight > MAX_WORD:
            raise DriverRefusal(f"entry {entry} counters overflow")
        active = calls > 0 or in_flight > 0
        if active:
            target = row.get("target")
            if not isinstance(target, dict):
                raise DriverRefusal(f"entry {entry} target invalid")
            if not _identity_matches(target.get("object"), pin):
                raise DriverRefusal(f"entry {entry} target is not the provider")
            digest = target["object"].get("sha256")
            if digest is None:
                notes.add("sha256_unavailable")
            elif digest != pin["sha256"]:
                raise DriverRefusal(f"entry {entry} target is not the provider")
            module = row.get("module")
            if not _identity_matches(module, pin):
                raise DriverRefusal(f"entry {entry} module is unattributed")
            if module.get("sha256") is None:
                notes.add("sha256_unavailable")
            elif module.get("sha256") != pin["sha256"]:
                raise DriverRefusal(f"entry {entry} module is unattributed")
        try:
            rvs = parse_rv_counts(row.get("rv_counts"))
        except DriverRefusal as error:
            raise DriverRefusal(f"entry {entry} {error}") from None
        if len(names) == 1:
            fn = names[0]
        else:
            fn = "|".join(sorted(names))
            notes.add(f"aliased entry {entry}")
        counts.append({"kind": "counts", "cell": cell, "entry": entry,
                       "fn": fn, "calls": calls + in_flight,
                       "returns": calls, "rv": rvs})
    for position, row in enumerate(functions):
        calls = row.get("calls")
        in_flight = row.get("in_flight")
        if not _u64(calls) or not _u64(in_flight):
            raise DriverRefusal(f"function row {position} counters invalid")
        if calls == 0 and in_flight == 0:
            continue
        row_entries = {item["ordinal"] for item in row["ordinals"]}
        if not row_entries:
            raise DriverRefusal("activity on an ordinal-less row")
        if not row_entries & entries:
            raise DriverRefusal(f"activity without ledger rows for entry "
                                f"{min(row_entries)}")
    counts.sort(key=lambda item: (item["cell"], item["entry"]))
    return {"counts": counts,
            "diagnostics": {"notes": sorted(notes),
                            "mapped_keys": len(counts),
                            "function_rows": len(functions)}}


def _terminal(evidence, verdict):
    """Mirror public-cli-oracle.terminal for the profile lane."""
    profile_fields = verdict.PROFILE_V3_FIELDS
    if not profile_fields <= set(evidence):
        raise DriverRefusal("missing required profile verdict authority")
    selection = evidence["interface_selection"]
    try:
        verdict.exact_keys(selection, verdict.SELECTION_KEYS,
                           "interface_selection")
    except AssertionError as error:
        raise DriverRefusal(f"invalid interface_selection: {error}") from None
    if type(selection["selection_truncated"]) is not bool:
        raise DriverRefusal("invalid selection truncation authority")
    for key in ("providers", "standard_exports", "inventory_surfaces", "tuples"):
        if not isinstance(selection[key], list):
            raise DriverRefusal(f"invalid selection authority list: {key}")
    for row in selection["providers"]:
        if (not isinstance(row, dict)
                or row.get("coverage") not in verdict.SELECTION_COVERAGE):
            raise DriverRefusal("invalid selection provider coverage")
    for row in selection["standard_exports"]:
        if (not isinstance(row, dict)
                or row.get("status") not in verdict.STANDARD_EXPORT_STATUS):
            raise DriverRefusal("invalid selection export authority")
    for row in selection["tuples"]:
        if (not isinstance(row, dict)
                or not ({"rv", "authority", "inventory_matches", "result"}
                        <= set(row))
                or not _u64(row.get("rv"))
                or row.get("authority") not in verdict.SELECTION_AUTHORITIES
                or not isinstance(row.get("inventory_matches"), list)
                or not (row.get("result") is None
                        or isinstance(row["result"], dict))):
            raise DriverRefusal("invalid selection tuple verdict authority")
    for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
        try:
            verdict.uint(evidence[key], verdict.U64_MAX, key)
        except AssertionError as error:
            raise DriverRefusal(f"invalid {key}: {error}") from None
    for key in (*verdict.COUNTERS, "slots", "semantic_unverified_slots",
                "unprotected_live_windows", "module_unresolved_slots",
                "pause_partial", "vendor_interfaces"):
        if not _u64(evidence.get(key)):
            raise DriverRefusal(f"invalid or missing verdict counter: {key}")
    for key in ("drain_proven", "provider_changed", "templates_truncated"):
        if type(evidence.get(key)) is not bool:
            raise DriverRefusal(f"invalid or missing verdict authority: {key}")
    scheduling = evidence.get("scheduling", {})
    if (type(scheduling.get("terminal_drain_truncated")) is not bool
            or not _u64(scheduling.get("sink_dropped_bytes"))):
        raise DriverRefusal("invalid verdict scheduling authority")
    loader = evidence.get("loader_discovery", {})
    for group, group_keys in verdict.LOADER_DISCOVERY_GROUPS.items():
        if (not isinstance(loader.get(group), dict)
                or any(not _u64(loader[group].get(key)) for key in group_keys)):
            raise DriverRefusal(f"invalid verdict loader authority: {group}")
    for key in verdict.LOADER_DISCOVERY_COUNTERS:
        if not _u64(loader.get(key)):
            raise DriverRefusal(f"invalid verdict loader counter: {key}")
    try:
        verdict.exact_stop_quiescence(evidence)
        verdict.exact_verdict_classes(evidence)
    except (AssertionError, KeyError, TypeError) as error:
        raise DriverRefusal(f"verdict classes refused: {error}") from None
    if (evidence.get("completeness")
            != verdict.expected_terminal_completeness(evidence)):
        raise DriverRefusal("completeness conflicts with terminal evidence")


def _ownership(row):
    """Mirror public-cli-oracle.ownership's exclusive relation."""
    if not ({"module", "module_ambiguous", "module_unresolved"} <= set(row)):
        raise DriverRefusal("missing required row ownership evidence")
    ambiguous, unresolved = row["module_ambiguous"], row["module_unresolved"]
    if type(ambiguous) is not bool or type(unresolved) is not bool:
        raise DriverRefusal("invalid row ownership flag")
    if row["module"] is None:
        if ambiguous == unresolved:
            raise DriverRefusal("null module requires exactly one reason")
        return
    if ambiguous or unresolved:
        raise DriverRefusal("nonnull module contradicts ownership reason")
    module = row["module"]
    if (not isinstance(module, dict)
            or not ({"dev", "ino", "sha256"} <= set(module))):
        raise DriverRefusal("missing module ownership identity")
    dev = module["dev"]
    if (not isinstance(dev, list) or len(dev) != 2
            or not all(_u64(part) for part in dev)
            or not _u64(module["ino"]) or module["ino"] == 0):
        raise DriverRefusal("invalid module ownership identity")


def check_s1_report(report, pin, *, verdict_module=None,
                    expected_in_flight_at_end=0,
                    extra_observation_causes=frozenset()):
    """The S1 proof for a scan-only pid profile: loss-free and healthy,
    with the attach-late disclosure pinned.

    Mirrors the public-cli-oracle.py report gates (schema/lane/scope, zero
    loss, kernel account, canonical terminal verdict, provider admission,
    well-formed rows), restricts attribution causes to the known scan-only
    disclosure, pins the observation causes to the deterministic attach-late
    set, and requires a fully walked 104-function surface. The terminal
    verdict itself is recorded, never pinned.

    The blocked cell designs one genuinely unreturned provider call, so it
    pins in_flight_at_end to exactly 1 with the matching observation cause
    instead of 0; every other cell pins 0 with no extra cause. Either way
    the value is exact, never a floor.
    """
    verdict = verdict_module
    if verdict is None:
        verdict = load_evidence(DRIVER_DIR)
    if type(report) is not dict:
        raise DriverRefusal("report is not an object")
    if report.get("schema") != PROFILE_SCHEMA:
        raise DriverRefusal("unsupported or wrong profile schema")
    capture = report.get("capture", {})
    if report.get("lane") != "profile" or capture.get("mode") != "profile":
        raise DriverRefusal("report lane differs from the profile cell")
    if capture.get("scope") != "pid":
        raise DriverRefusal("report scope differs from the pid cell")
    evidence = report.get("evidence")
    if not isinstance(evidence, dict):
        raise DriverRefusal("missing capture evidence")
    for key in LOSS_COUNTERS:
        if key == "in_flight_at_end":
            continue
        if type(evidence.get(key)) is not int or evidence[key] != 0:
            raise DriverRefusal(f"loss or unknown {key}")
    if (type(evidence.get("in_flight_at_end")) is not int
            or evidence["in_flight_at_end"] != expected_in_flight_at_end):
        raise DriverRefusal("loss or unknown in_flight_at_end")
    kernel = evidence.get("kernel_control", {})
    if (kernel.get("capture_halted") is not False
            or kernel.get("owner_poison") != []
            or kernel.get("root_affiliation_failures") != []):
        raise DriverRefusal("kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        if type(kernel.get(key)) is not int or kernel[key] != 0:
            raise DriverRefusal(f"kernel loss or unknown {key}")
    try:
        verdict.exact_attach_backend(evidence.get("attach_backend"),
                                     evidence.get("attach_mechanisms"), report)
    except (AssertionError, KeyError, TypeError) as error:
        raise DriverRefusal(f"attach backend refused: {error}") from None
    _terminal(evidence, verdict)
    observation = evidence.get("gap_classes", {}).get("observation", {})
    causes = observation.get("causes", [])
    expected_causes = PINNED_OBSERVATION_CAUSES | set(extra_observation_causes)
    if (not isinstance(causes, list) or set(causes) != expected_causes):
        raise DriverRefusal("observation disclosure differs from the pinned "
                            "attach-late set")
    if observation.get("status") != "lossy":
        raise DriverRefusal("pinned observation causes without lossy status")
    surfaces = evidence.get("surfaces", [])
    if not (isinstance(surfaces, list)
            and any(isinstance(row, dict) and row.get("walk") == "full"
                    and row.get("acquisition") == "ok"
                    and row.get("functions") == 104 for row in surfaces)):
        raise DriverRefusal("no fully walked 104-function surface")
    semantics = evidence.get("gap_classes", {}).get("semantics", {})
    if semantics.get("status") not in ("complete", "not_applicable"):
        raise DriverRefusal("degraded semantics gap class")
    attribution = evidence.get("gap_classes", {}).get("attribution", {})
    attr_causes = attribution.get("causes", [])
    if (not isinstance(attr_causes, list)
            or not set(attr_causes) <= SCAN_ATTRIBUTION_CAUSES):
        raise DriverRefusal("attribution cause outside the scan-only disclosure")
    admitted = evidence.get("discovery")
    if not (isinstance(admitted, list)
            and any(isinstance(row, dict) and row.get("sha256") is not None
                    and _identity_matches(row, pin)
                    and row.get("sha256") == pin["sha256"] for row in admitted)):
        raise DriverRefusal("owned provider not admitted")
    rows = report.get("functions")
    if not isinstance(rows, list):
        raise DriverRefusal("missing functions")
    active = 0
    for row in rows:
        if type(row) is not dict:
            raise DriverRefusal("function row is not an object")
        _ownership(row)
        if not _u64(row.get("calls")):
            raise DriverRefusal("invalid function count")
        names = row.get("names")
        if (not isinstance(names, list) or not names
                or any(type(name) is not str for name in names)):
            raise DriverRefusal("invalid function names")
        for counter in ("errors", "in_flight", "pending_returns"):
            if not _u64(row.get(counter)):
                raise DriverRefusal(f"invalid function return counter: {counter}")
        target = row.get("target")
        if (not isinstance(target, dict)
                or not _u64(target.get("file_offset"))):
            raise DriverRefusal("invalid physical target")
        if row["calls"] > 0 or row["in_flight"] > 0:
            active += 1
    return {"verdict_detail": evidence.get("verdict_detail"),
            "completeness": evidence.get("completeness"),
            "observation": observation.get("status"),
            "observation_causes": sorted(set(causes)),
            "observation_exact": False,
            "attribution_causes": sorted(set(attr_causes)),
            "functions": len(rows), "active_rows": active}


def judge_with_oracle(oracle_py, ledger_path, counts_path):
    """Judge saved artifacts through the oracle CLI. Returns (code, out, err)."""
    try:
        completed = subprocess.run(
            [sys.executable, "-I", str(oracle_py), str(ledger_path),
             str(counts_path)],
            capture_output=True, text=True, timeout=ORACLE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, "", "oracle timed out"
    return completed.returncode, completed.stdout, completed.stderr


def aggregate(results):
    """Overall verdict over per-cell results."""
    failed = [f"{item['cell']}/{item['arch']}" for item in results
              if not item.get("passed")]
    return {"passed": bool(results) and not failed,
            "cells": len(results), "failed": failed}


def entry_detail(rows, counts):
    """Per-entry diagnostic context (dimensions only, never a verdict).

    Compares the ledger population against the converted counts entry by
    entry so a refusal localizes to entries and dimensions. Numbers only:
    fn values are compared internally but only the agreement flag leaves.
    """
    expected = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("kind") not in ("call", "entry"):
            continue
        slot = expected.setdefault((row["cell"], row["entry"]),
                                   {"fns": set(), "total": 0, "rvs": []})
        slot["fns"].add(row["fn"])
        slot["total"] += 1
        if row["kind"] == "call":
            slot["rvs"].append(row["rv"])
    observed = {(row["cell"], row["entry"]): row for row in counts}
    detail = []
    mismatched = []
    for key in sorted(expected):
        slot = expected[key]
        row = observed.get(key)
        if row is None:
            entry = {"entry": key[1], "calls_ok": False, "returns_ok": False,
                     "fn_ok": False, "rv_ok": False, "missing_counts": True}
        else:
            entry = {"entry": key[1],
                     "calls_ok": row["calls"] == slot["total"],
                     "returns_ok": row["returns"] == len(slot["rvs"]),
                     "fn_ok": len(slot["fns"]) == 1 and row["fn"] in slot["fns"],
                     "rv_ok": sorted(row["rv"]) == sorted(slot["rvs"])}
            if not entry["calls_ok"]:
                entry["calls"] = {"ledger": slot["total"],
                                  "observed": row["calls"]}
            if not entry["returns_ok"]:
                entry["returns"] = {"ledger": len(slot["rvs"]),
                                    "observed": row["returns"]}
            if not entry["rv_ok"]:
                entry["rv_lengths"] = {"ledger": len(slot["rvs"]),
                                       "observed": len(row["rv"])}
        if not (entry["calls_ok"] and entry["returns_ok"]
                and entry["fn_ok"] and entry["rv_ok"]):
            mismatched.append(key[1])
        detail.append(entry)
    return {"entries": detail, "mismatched_entries": mismatched}


def blocked_entry_in_flight(report):
    """Prove the capture saw the blocked slot-10 entry still in flight.

    Returns {"calls": ..., "in_flight": ...} for the ordinal-10 row, or
    raises DriverRefusal when the row is missing or nothing is in flight.
    The driver calls this after stopping the observer but before releasing
    the provider, so the release is proven to follow the observation.
    """
    if type(report) is not dict or type(report.get("functions")) is not list:
        raise DriverRefusal("report functions are not a list")
    for position, row in enumerate(report["functions"]):
        if type(row) is not dict or type(row.get("ordinals")) is not list:
            raise DriverRefusal(f"function row {position} has no ordinals")
        claimed = [item.get("ordinal") for item in row["ordinals"]
                   if type(item) is dict]
        if 10 not in claimed:
            continue
        calls, in_flight = row.get("calls"), row.get("in_flight")
        if not _u64(calls) or not _u64(in_flight):
            raise DriverRefusal("entry 10 counters invalid")
        if in_flight < 1:
            raise DriverRefusal("entry 10 has no call in flight")
        return {"calls": calls, "in_flight": in_flight}
    raise DriverRefusal("entry 10 has no observer row")


def _terminate(proc, label):
    if proc.poll() is not None:
        return proc.returncode
    try:
        proc.terminate()
    except OSError:
        return proc.poll()
    try:
        return proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except OSError:
        return proc.poll()
    try:
        return proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        return None


def run_cell(*, observer, fixture, provider, scripts_dir, cond, arch,
             cell_dir, duration, loader32=None, library_path32=None):
    """Run one installed cell; return its result record (never raises)."""
    from datetime import datetime, timezone
    spec = CELLS[cond]
    oracle = load_oracle(scripts_dir)
    pin_mod = load_pin(scripts_dir)
    started = datetime.now(timezone.utc).isoformat()
    ledger_path = cell_dir / "ledger.jsonl"
    gate_path = cell_dir / "gate"
    wl_path = cell_dir / "workload.log"
    stderr_path = cell_dir / "observer.stderr"
    profile_path = cell_dir / "profile.json"
    counts_path = cell_dir / "counts.jsonl"
    entered_path = cell_dir / "entered"
    release_path = cell_dir / "release"
    for path in (ledger_path, gate_path, wl_path, stderr_path, profile_path,
                 counts_path, entered_path, release_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    result = {"cell": cond, "arch": arch, "passed": False, "reason": "",
              "started": started, "dir": str(cell_dir)}
    fixture_argv = [str(fixture), str(provider), str(ledger_path),
                    str(gate_path), spec["mode"]]
    if spec["arg"] is not None:
        fixture_argv.append(spec["arg"])
    if loader32 is not None and arch == "ia32":
        run_argv = [str(loader32)]
        if library_path32:
            run_argv += ["--library-path", str(library_path32)]
        run_argv += fixture_argv
    else:
        run_argv = fixture_argv
    try:
        provider_before = pin_mod.pin(str(provider))
    except (OSError, ValueError) as error:
        result["reason"] = f"provider pin failed: {error}"
        return result
    workload = observer_proc = None
    workload_rc = observer_rc = 125
    workload_ready = capture_ready = gate_released = False
    workload_env = dict(os.environ)
    workload_env["P11SCOPE_FIXTURE_QUIET"] = "1"
    if cond == "blocked":
        workload_env["P11SCOPE_FIXTURE_BLOCK_ENTERED"] = str(entered_path)
        workload_env["P11SCOPE_FIXTURE_BLOCK_RELEASE"] = str(release_path)
    try:
        with open(wl_path, "w", encoding="utf-8") as wl_file:
            try:
                workload = subprocess.Popen(run_argv, stdout=wl_file,
                                            stderr=subprocess.STDOUT,
                                            env=workload_env)
            except OSError as error:
                result["reason"] = f"workload did not start: {error}"
                return result
        ready = wait_for_match(
            str(wl_path), rf"^READY pid={workload.pid}$", READY_TIMEOUT)
        if ready is None or workload.poll() is not None:
            result["reason"] = "workload never became ready"
            return result
        workload_ready = True
        observer_argv = [str(observer), "profile", "--pid", str(workload.pid),
                         "--duration", str(duration), "-o", str(profile_path)]
        with open(stderr_path, "w", encoding="utf-8") as err_file:
            try:
                observer_proc = subprocess.Popen(observer_argv, stdout=subprocess.DEVNULL,
                                                 stderr=err_file)
            except OSError as error:
                result["reason"] = f"observer did not start: {error}"
                return result
        capturing = wait_for_match(str(stderr_path), r"p11scope: capturing:",
                                   CAPTURING_TIMEOUT)
        if capturing is None or observer_proc.poll() is not None \
                or workload.poll() is not None:
            result["reason"] = "observer never started capturing"
            return result
        capture_ready = True
        try:
            with open(gate_path, "w", encoding="utf-8"):
                pass
        except OSError as error:
            result["reason"] = f"gate release failed: {error}"
            return result
        gate_released = True
        if cond == "blocked":
            # The provider blocks inside slot 10 until this driver releases
            # it: wait for the provider's proof of entry, then end the
            # capture with the call genuinely in flight, prove the stopped
            # report saw it, and only then release. The return lands after
            # the capture, so the S1 in-flight pin below is exact.
            entered_seen = False
            entered_deadline = time.monotonic() + BLOCKED_ENTER_TIMEOUT
            while time.monotonic() < entered_deadline:
                if entered_path.exists():
                    entered_seen = True
                    break
                if workload.poll() is not None:
                    break
                time.sleep(0.05)
            if not entered_seen:
                result["reason"] = "provider never entered the blocked call"
                return result
            result["entered_seen"] = True
            observer_rc = _terminate(observer_proc, "observer")
            if observer_rc is None:
                result["reason"] = "observer would not stop while blocked"
                return result
            try:
                with open(profile_path, encoding="utf-8") as stream:
                    stopped_report = json.load(stream)
            except (OSError, UnicodeError, json.JSONDecodeError):
                result["reason"] = "profile report unreadable at release time"
                return result
            try:
                result["capture_saw_entry"] = \
                    blocked_entry_in_flight(stopped_report)
            except DriverRefusal as error:
                result["reason"] = \
                    f"capture missed the blocked entry: {error}"
                return result
            try:
                with open(release_path, "w", encoding="utf-8"):
                    pass
            except OSError as error:
                result["reason"] = f"release failed: {error}"
                return result
            result["released"] = True
        try:
            workload_rc = workload.wait(timeout=FIXTURE_TIMEOUT)
        except subprocess.TimeoutExpired:
            result["reason"] = "workload timed out"
            return result
        # The ledger is complete: end the capture promptly instead of
        # rescanning a dead target until the duration backstop. SIGTERM is
        # a documented clean end; the exit-time loader hits are already in
        # the ring, and the S1 drain gate still has to prove the stop.
        # (The blocked cell already stopped its capture above, with the
        # call in flight; _terminate on the exited observer is a no-op.)
        observer_rc = _terminate(observer_proc, "observer")
        if observer_rc is None:
            result["reason"] = "observer would not stop after the workload exit"
            return result
    finally:
        if observer_proc is not None and observer_proc.poll() is None:
            killed = _terminate(observer_proc, "observer")
            if observer_rc == 125:
                observer_rc = 124 if killed is None else killed
        if workload is not None and workload.poll() is None:
            killed = _terminate(workload, "workload")
            if workload_rc == 125:
                workload_rc = 124 if killed is None else killed
    result.update({"workload_ready": workload_ready,
                   "capture_ready": capture_ready,
                   "gate_released": gate_released,
                   "workload_exit": workload_rc,
                   "observer_exit": observer_rc,
                   "launched_pid": workload.pid if workload else None})
    try:
        provider_after = pin_mod.pin(str(provider))
    except (OSError, ValueError) as error:
        result["reason"] = f"provider pin failed: {error}"
        return result
    result["provider_before"] = provider_before
    result["provider_after"] = provider_after
    for key in ("dev", "ino", "sha256"):
        if provider_before.get(key) != provider_after.get(key):
            result["reason"] = "provider identity changed during the cell"
            return result
    pin = {"dev": provider_before["dev"], "ino": provider_before["ino"],
           "sha256": provider_before["sha256"]}
    if workload_rc != spec["workload_exit"]:
        result["reason"] = (f"workload exit {workload_rc}, expected "
                            f"{spec['workload_exit']}")
        return result
    if observer_rc != 0:
        result["reason"] = f"observer exit {observer_rc}"
        return result
    try:
        with open(ledger_path, encoding="utf-8") as stream:
            ledger_rows = oracle.read_ledger(stream)
        summary = oracle.validate_ledger(ledger_rows)
    except (OSError, UnicodeError):
        result["reason"] = "ledger unreadable"
        return result
    except oracle.LedgerError as error:
        result["reason"] = f"ledger refused: {error}"
        return result
    result["ledger"] = summary
    try:
        with open(profile_path, encoding="utf-8") as stream:
            report = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        result["reason"] = "profile report unreadable"
        return result
    try:
        if cond == "blocked":
            s1 = check_s1_report(
                report, pin, expected_in_flight_at_end=1,
                extra_observation_causes={"in_flight_at_end"})
        else:
            s1 = check_s1_report(report, pin)
    except DriverRefusal as error:
        result["reason"] = f"S1 proof refused: {error}"
        return result
    result["s1"] = s1
    try:
        converted = counts_from_profile(report, ledger_rows, pin,
                                        spec["cond"], spec["cell"])
    except DriverRefusal as error:
        result["reason"] = f"counts conversion refused: {error}"
        return result
    try:
        with open(counts_path, "w", encoding="utf-8") as stream:
            for row in converted["counts"]:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError:
        result["reason"] = "counts document unwritable"
        return result
    oracle_py = Path(scripts_dir) / ORACLE_NAME
    code, out, err = judge_with_oracle(oracle_py, ledger_path, counts_path)
    try:
        with open(oracle_py, "rb") as stream:
            oracle_sha = hashlib.sha256(stream.read()).hexdigest()
    except OSError:
        oracle_sha = None
    result["oracle"] = {"argv": [str(oracle_py), str(ledger_path),
                                 str(counts_path)],
                        "exit": code, "sha256": oracle_sha}
    if code != 0:
        result["reason"] = f"oracle refused: {err.strip() or out.strip()}"
        result["detail"] = entry_detail(ledger_rows, converted["counts"])
        return result
    try:
        result["oracle_summary"] = json.loads(out)
    except json.JSONDecodeError:
        result["reason"] = "oracle printed no summary"
        return result
    result["detail"] = entry_detail(ledger_rows, converted["counts"])
    result["diagnostics"] = converted["diagnostics"]
    result["receipt"] = {"schema": RECEIPT_SCHEMA, "cell": cond, "arch": arch,
                         "cond": spec["cond"], "population": spec["cell"],
                         "mode": spec["mode"], "arg": spec["arg"],
                         "provider": spec["provider"],
                         "launched_pid": result["launched_pid"],
                         "workload_ready": workload_ready,
                         "capture_ready": capture_ready,
                         "gate_released": gate_released,
                         "ledger_complete": True,
                         "observer_exit": observer_rc,
                         "workload_exit": workload_rc}
    result["passed"] = True
    result["reason"] = "oracle accepted the installed population"
    return result


def build_all(cc, src_dir, out_dir, archs):
    """Build the emitter and both stub providers; return artifact paths."""
    src_dir = Path(src_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    emitter = src_dir / "abi-execution" / "abi-104.c"
    stub = src_dir / "live-discovery-provider.c"
    hibit = src_dir / "abi-execution" / "abi-rv64-provider.c"
    for path in (emitter, stub, hibit):
        if not path.is_file():
            raise DriverRefusal(f"fixture source missing: {path.name}")
    built = {}
    for arch in archs:
        m32 = arch == "ia32"
        suffix = "ia32" if m32 else "lp64"
        jobs = [
            ("fixture", gcc_fixture_cmd(
                cc, emitter, out_dir / f"abi-104-{suffix}", m32)),
            ("stub", gcc_provider_cmd(
                cc, stub, out_dir / f"provider-{suffix}.so", m32)),
            ("hibit", gcc_provider_cmd(
                cc, hibit, out_dir / f"hibit-{suffix}.so", m32,
                exports_macro=False)),
        ]
        paths = {}
        for name, cmd in jobs:
            try:
                completed = subprocess.run(cmd, capture_output=True, text=True,
                                           timeout=BUILD_TIMEOUT)
            except subprocess.TimeoutExpired:
                raise DriverRefusal(f"{arch} {name} build timed out") from None
            if completed.returncode != 0:
                raise DriverRefusal(
                    f"{arch} {name} build failed: {completed.stderr.strip()}")
            paths[name] = str(out_dir / cmd[cmd.index("-o") + 1])
        built[arch] = paths
    return built


def _prebuilt(fixtures_dir, archs):
    names = {"fixture": "abi-104", "stub": "provider", "hibit": "hibit"}
    found = {}
    for arch in archs:
        suffix = "ia32" if arch == "ia32" else "lp64"
        paths = {}
        for name, stem in names.items():
            ext = "" if name == "fixture" else ".so"
            candidate = Path(fixtures_dir) / f"{stem}-{suffix}{ext}"
            if not candidate.is_file():
                raise DriverRefusal(f"prebuilt fixture missing: {candidate.name}")
            paths[name] = str(candidate)
        found[arch] = paths
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True,
                        help="installed observer binary under test")
    parser.add_argument("--out", required=True,
                        help="output directory for per-cell records")
    parser.add_argument("--arch", default="both",
                        choices=("lp64", "ia32", "both"))
    parser.add_argument("--cell", action="append", default=[],
                        help="condition to run (repeatable; default: all)")
    parser.add_argument("--cc", default="gcc", help="C compiler for fixtures")
    parser.add_argument("--src", default=None,
                        help="fixture source dir (default: repo tests/fixtures)")
    parser.add_argument("--fixtures", default=None,
                        help="prebuilt fixture dir (skip the gcc build)")
    parser.add_argument("--duration", type=int, default=30,
                        help="observer --duration backstop in seconds")
    parser.add_argument("--loader32", default=None,
                        help="explicit 32-bit loader for ia32 cells")
    parser.add_argument("--library-path32", default=None,
                        help="library path for the explicit 32-bit loader")
    parser.add_argument("--list-cells", action="store_true",
                        help="print the cell table and exit")
    args = parser.parse_args(argv)
    if args.list_cells:
        for cond in COND_ORDER:
            spec = CELLS[cond]
            print(f"{cond}: mode={spec['mode']} provider={spec['provider']} "
                  f"exit={spec['workload_exit']} population={spec['cell']}")
        return 0
    conds = args.cell or COND_ORDER
    unknown = [cond for cond in conds if cond not in CELLS]
    if unknown:
        parser.error(f"unknown cell: {', '.join(unknown)}")
    archs = ["lp64", "ia32"] if args.arch == "both" else [args.arch]
    out_dir = Path(args.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        print(f"abi execution refused: out dir unwritable: {error}",
              file=sys.stderr)
        return 2
    if not out_dir.is_dir():
        print("abi execution refused: out path is not a directory",
              file=sys.stderr)
        return 2
    observer = str(args.observer)
    if not Path(observer).is_file():
        print("abi execution refused: observer binary missing", file=sys.stderr)
        return 2
    scripts_dir = DRIVER_DIR
    try:
        if args.fixtures is not None:
            built = _prebuilt(args.fixtures, archs)
        else:
            src = Path(args.src) if args.src else \
                DRIVER_DIR / ".." / "tests" / "fixtures"
            built = build_all(args.cc, src, out_dir / "fixtures", archs)
    except DriverRefusal as error:
        print(f"abi execution refused: {error}", file=sys.stderr)
        return 2
    results = []
    for arch in archs:
        for cond in conds:
            cell_dir = out_dir / arch / cond
            cell_dir.mkdir(parents=True, exist_ok=True)
            spec = CELLS[cond]
            print(f"abi execution: cell {cond}/{arch} "
                  f"(mode={spec['mode']} provider={spec['provider']}) ...",
                  flush=True)
            record = run_cell(observer=observer,
                              fixture=built[arch]["fixture"],
                              provider=built[arch][spec["provider"]],
                              scripts_dir=scripts_dir, cond=cond, arch=arch,
                              cell_dir=cell_dir, duration=args.duration,
                              loader32=args.loader32,
                              library_path32=args.library_path32)
            verdict_path = cell_dir / "verdict.json"
            try:
                with open(verdict_path, "w", encoding="utf-8") as stream:
                    json.dump(record, stream, indent=2, sort_keys=True)
                    stream.write("\n")
            except OSError:
                record = dict(record, passed=False,
                              reason="verdict unwritable")
            results.append(record)
            status = "PASS" if record["passed"] else "FAIL"
            print(f"abi execution: cell {cond}/{arch}: {status}: "
                  f"{record['reason']}", flush=True)
    overall = aggregate(results)
    line = {"overall": overall["passed"], "cells": overall["cells"],
            "failed": overall["failed"]}
    try:
        with open(out_dir / "results.jsonl", "w", encoding="utf-8") as stream:
            for record in results:
                stream.write(json.dumps({"cell": record["cell"],
                                         "arch": record["arch"],
                                         "passed": record["passed"],
                                         "reason": record["reason"]},
                                        sort_keys=True) + "\n")
            stream.write(json.dumps(line, sort_keys=True) + "\n")
    except OSError:
        print("abi execution refused: results unwritable", file=sys.stderr)
        return 2
    print(f"abi execution: overall {'PASS' if overall['passed'] else 'FAIL'}: "
          f"{overall['cells'] - len(overall['failed'])}/{overall['cells']} "
          f"cells passed", flush=True)
    return 0 if overall["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
