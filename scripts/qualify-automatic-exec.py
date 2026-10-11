#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed automatic exec/scope recovery acceptance (H6 slice 4).

Runs the required --cells against an explicitly staged observer binary plus
owned disk fixtures (never tmpfs: the Btrfs mapping-domain identity path is
part of the check), driving only public trace / profile / metrics /
inventory --capture native commands (H3 inventory --manifest only for the
S1-bearing legs), and judges every leg with an independent driver ledger
that never derives expectations from p11scope.

Cells: pid-leader, pid-reexec, pid-nonleader-cold, pid-failed-exec,
leader-exit-exec, rapid-chain, cgroup-reentry, system-mixed.

Workloads (all owned, all on disk under the case directory):
  caller.c    SoftHSM interactive caller (leader/reexec/rapid/cgroup legs)
  detailed-nonleader-exec.c  LP64 synthetic provider, exec inside the probed
              frame (cold nonleader / failed / leader-exit legs)
  inventory-ledger.c (unmodified reuse)  mech/exec-chain/map S1 workloads

Oracle reuse: trace rows and COUNT/EVIDENCE parsing reuse
scripts/cgroup-trace-oracle.py verbatim (ROW, parse_trace). The H6
evaluation below reuses that spine and N3's error taxonomy where the
rules are compatible; every H6 delta is marked H6-DELTA with a reason.
Harness reuse: owned process/cgroup/file-pin/reader primitives are
imported from scripts/qualify-cgroup-trace.py (same revision); the H6
drivers add workload-B byte-protocol and inventory-ledger gate handling.

No product source is touched by this script. A red leg is either a
harness/setup failure (fix the cell) or product behavior that must be
reported BLOCKED-with-evidence, never fixed here.

Live use requires the separately granted privileged lane: run as root
with an ordinary workload uid/gid. Only owned fixtures, processes,
cgroups and temp files are created; every owned resource is cleaned up
and cleanup receipts are recorded in summary.json.
"""

import argparse
from collections import Counter, defaultdict, deque
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import runpy
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True

N3HARNESS = runpy.run_path(str(ROOT / "scripts/qualify-cgroup-trace.py"))
N3ORACLE = runpy.run_path(str(ROOT / "scripts/cgroup-trace-oracle.py"))
ROW = N3ORACLE["ROW"]
N3_PARSE_TRACE = N3ORACLE["parse_trace"]
IMAGE_FIELDS = ("image", "pid", "start_time", "path", "dev", "ino", "mtime_ns",
                "pid_namespace", "time_namespace")

CELLS = ("pid-leader", "pid-reexec", "pid-nonleader-cold", "pid-failed-exec",
         "leader-exit-exec", "rapid-chain", "cgroup-reentry", "system-mixed")
BACKENDS = ("singles", "multi")
CANARIES = ("H6_PRIVATE_BUFFER_44c1d7", "H6_PRIVATE_ENV_9e02b4", "H6_PRIVATE_ARG_71f5aa")

# Fixture RV values to presented CKR names (workload-B uses RV 0 and 5 only).
RV_NAMES = {0: "CKR_OK", 5: "CKR_GENERAL_ERROR"}


def monotonic_ns():
    return time.monotonic_ns()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# H6 oracle: trace legs
#
# Spine reused from scripts/cgroup-trace-oracle.py (ROW/parse_trace verbatim;
# check sequence and error taxonomy mirrored). H6-DELTA marks every rule that
# differs, with the reason. Deltas: scope-kind-aware in-scope selection (pid
# cells ignore caller scope labels); measured/warmup gates (required); order
# -matched attribution per (pid,tid,fn) when lossless+exact (rapid-chain
# reused keys); explicit duplicate-return, manual-rebind, pid-purity,
# abandoned-accounting and session/VA/token-reuse checks; nonzero-RV
# ledgers (workload-B fails every other call by design); no first-proved /
# cold-proved / short / sparse / run special cases (no such H6 cells).
# ---------------------------------------------------------------------------

def _without_sink(value):
    value = dict(value)
    if "scheduling" in value:
        scheduling = dict(value["scheduling"])
        for field in ("sink_stall_ms", "sink_timeouts", "sink_dropped_bytes"):
            scheduling.pop(field, None)
        value["scheduling"] = scheduling
    return value


def _evaluate_trace_h6(trace, ledger, receipt, file_trace):
    rows, counts, evidence, errors = N3_PARSE_TRACE(trace)
    if receipt.get("expect_empty"):
        if rows:
            errors.append("stop-before-collection leg captured rows")
        if counts and any([counts[0].get("stats_entered", -1) != 0,
                           counts[0].get("stats_returned", -1) != 0,
                           counts[0].get("raw_calls", -1) != 0]):
            errors.append("stop-before-collection leg reports nonzero terminal counts")
        if evidence:
            ev = evidence[0]
            if any(ev.get(field, 0) != 0 for field in
                   ("event_loss", "start_insert_failures", "unmatched_returns",
                    "rv_update_failures", "cgroup_scope_failures",
                    "process_tracking_failures", "process_tracking_evictions")):
                errors.append("empty leg reports event/identity loss")
            if (ev.get("attach_backend") or {}).get("fallback") is not None:
                errors.append("capture installed a fallback link: no global fallback allowed")
        else:
            errors.append("missing terminal evidence record")
        if receipt.get("observer_rc") != 0:
            errors.append("observer did not exit successfully")
        if not 0 <= receipt.get("stop_latency_seconds", -1) <= receipt.get("stop_limit_seconds", 5):
            errors.append("stop exceeded the bounded cell limit")
        return {"pass": not errors, "status": "pass" if not errors else "fail",
                "cell": receipt.get("cell"), "leg": receipt.get("leg"),
                "calls": len(rows), "named": 0, "unknown": 0, "false_names": 0,
                "physical_entered": 0, "api_returned": 0, "completed_operations": 0,
                "errors": errors}
    if file_trace is not None:
        other_rows, other_counts, other_evidence, other_errors = N3_PARSE_TRACE(file_trace)
        errors.extend(other_errors)
        if (rows, counts) != (other_rows, other_counts):
            errors.append("stdout/file event or count disagreement")
        if [_without_sink(v) for v in evidence] != [_without_sink(v) for v in other_evidence]:
            errors.append("stdout/file terminal evidence disagreement")
        if any(ev.get("scheduling", {}).get(field, 0) for ev in evidence + other_evidence
               for field in ("sink_timeouts", "sink_dropped_bytes")):
            errors.append("capture lost output in this no-loss parity cell")
    # H6-DELTA: backend refusal is a recorded negative, never recovery.
    if receipt.get("backend_refused"):
        return {"pass": False, "status": "negative", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"), "calls": len(rows), "named": 0,
                "unknown": 0, "false_names": 0,
                "negative_reason": receipt["backend_refused"],
                "errors": ["backend refused: %s" % (receipt["backend_refused"],)]}
    for canary in receipt.get("privacy_canaries", []):
        if not canary or any(canary in output for output in
                             (trace, file_trace or "", receipt.get("observer_stderr", ""))):
            errors.append("private fixture canary appears in capture output")
    # H6-DELTA: group-death legs. The caller is SIGKILLed as a whole
    # group, so its reaped rc is -SIGKILL, never 0; death is proven by
    # the harness via waitpid plus /proc disappearance, never from
    # p11scope output. The exact per-key population agreement below is
    # then the no-post-death-rows proof.
    death = receipt.get("group_death")
    if death is None:
        if receipt.get("observer_rc") != 0 or receipt.get("caller_rc") != 0:
            errors.append("observer or caller did not exit successfully")
    else:
        errors.extend(_check_group_death_proof(death, receipt))
    if not 0 <= receipt.get("stop_latency_seconds", -1) <= receipt.get("stop_limit_seconds", 5):
        errors.append("normal stop exceeded the bounded cell limit")
    before, after = receipt["provider_before"], receipt["provider_after"]
    if (before != after or before["dev"] != before["mapping"]["dev"]
            or before["ino"] != before["mapping"]["ino"]):
        errors.append("held provider pin changed or lacks the independent mapped-device anchor")
    if not re.fullmatch(r"[0-9a-f]{64}", before["sha256"]):
        errors.append("invalid held provider digest")
    # H6-DELTA: manual rebind can never satisfy automatic acceptance.
    if receipt.get("manual_rebind"):
        errors.append("manual rebind cannot satisfy automatic acceptance")
    if any(row.get("kind") == "rebind" for row in ledger):
        errors.append("fixture-issued rebind present: not an automatic recovery proof")

    images = {row["image"]: row for row in ledger if row["kind"] == "image"}
    trusted_images = {row["image"]: row for row in receipt["images"]}
    if len(images) != sum(row["kind"] == "image" for row in ledger):
        errors.append("duplicate caller image generation")
    if set(images) != set(trusted_images):
        errors.append("independent image receipts do not cover every caller image")
    for image_id, image in images.items():
        trusted = trusted_images.get(image_id, {})
        if any(image.get(field) != trusted.get(field) for field in IMAGE_FIELDS):
            errors.append("caller image disagrees with independently held executable/birth receipt")
        if any(image[field] != receipt[field] for field in ("pid_namespace", "time_namespace")):
            errors.append("caller and observer clock/PID namespace disagree")
        if not image["path"].startswith("/") or any(image[field] <= 0 for field in
                ("pid", "start_time", "ino", "mtime_ns", "pid_namespace", "time_namespace")):
            errors.append("incomplete caller image identity")
    targets = {(row["image"], row["fn"]): row for row in ledger if row["kind"] == "target"}
    calls = [row for row in ledger if row["kind"] == "call"]
    # H6-DELTA: exec-transition scope is controller-declared per transition
    # (N3 hardcodes 'outside'); pid/system cells record the label only.
    transitions = {}
    for transition in receipt.get("exec_transitions", []):
        previous, successor = images[transition["from_image"]], images[transition["to_image"]]
        requests = [row for row in ledger if row["kind"] == "exec"
                    and row["image"] == previous["image"]]
        if len(requests) != 1 or requests[0] != transition["request"]:
            errors.append("exec request disagrees with independently controlled transition")
            continue
        request = requests[0]
        mode = transition["mode"]
        scope_ok = True
        if receipt.get("scope_kind") == "cgroup":
            scope_ok = request["scope"] == transition.get("scope", "outside")
        if (mode not in ("leader", "nonleader") or request["mode"] != mode
                or request["pid"] != previous["pid"] or request["start_time"] != previous["start_time"]
                or request["tid"] <= 0 or (request["tid"] == request["pid"]) != (mode == "leader")
                or not scope_ok or request["path"] != successor["path"]
                or not transition["t0"] <= request["t"] < successor["t"] <= transition["t1"]
                or previous["pid"] != successor["pid"] or previous["start_time"] != successor["start_time"]
                or (previous["path"] == successor["path"]) != transition["same_path"]
                or any(call["scope"] == "selected" and call["t0"] < successor["t"]
                       for call in calls if call["image"] == successor["image"])):
            errors.append("exec transition lacks authentic generation/leader/birth/scope evidence")
        else:
            transitions[successor["image"]] = transition
    if "phases" in receipt:
        phase_calls = [call for call in calls if call["phase"] not in ("setup", "teardown")]
        phase_keys = set()
        for phase in receipt["phases"]:
            key = phase["image"], phase["fn"], phase["phase"]
            if key in phase_keys:
                errors.append("duplicate controller phase")
            phase_keys.add(key)
            population = [call for call in phase_calls
                          if (call["image"], call["fn"], call["phase"]) == key]
            if len(population) != phase["count"] or any(
                    call["scope"] != phase["scope"] or not phase["t0"] <= call["t0"] <= call["t1"] <= phase["t1"]
                    for call in population):
                errors.append("fixture phase disagrees with independently issued command/membership interval")
            if "gap_ms" in phase:
                ordered = sorted(population, key=lambda call: call["t0"])
                gap = phase["gap_ms"] * 1_000_000
                if not 0 <= phase["gap_ms"] <= 61000 or any(
                        later["t0"] - earlier["t1"] < gap
                        for earlier, later in zip(ordered, ordered[1:])):
                    errors.append("real spaced-call gap is shorter than the independent command")
        if any((call["image"], call["fn"], call["phase"]) not in phase_keys for call in phase_calls):
            errors.append("fixture call has no independently issued workload phase")
    start, ready, stop = (receipt[field] for field in
                          ("observer_started_ns", "observer_ready_ns", "observer_stopped_ns"))
    if not receipt["scope_created_ns"] < start <= ready < stop:
        errors.append("invalid independent observer interval")
    # H6-DELTA: measured/warmup gates. The measured phase is required,
    # nonempty, and after public readiness; warm-up is explicitly bounded
    # and reported, never discarded from coverage.
    measured_calls, warmup_calls, gate_errors = _check_measured_warmup(
        calls, receipt, ready, stop, start)
    errors.extend(gate_errors)
    for call in calls:
        image = images[call["image"]]
        target = targets.get((call["image"], call["fn"]))
        if (not target or target["dev"] != before["dev"] or target["ino"] != before["ino"]
                or target["file_offset"] < 0):
            errors.append(f"call lacks a matching physical provider target: {call['fn']}")
        if call["pid"] != image["pid"] or call["t1"] < call["t0"]:
            errors.append("call identity/interval disagrees with its caller image")
        # H6-DELTA: nonzero RVs are legal when the ledger declares them;
        # the row RV must match the ledger RV exactly (checked below).
        if call["rv"] not in RV_NAMES:
            errors.append(f"ledger call carries an unmapped return value: {call['fn']} rv={call['rv']}")
    scope_kind = receipt.get("scope_kind", "pid")
    owned_pids = set(receipt.get("owned_pids", []))
    in_window, pre_ready, post_stop, out_of_scope, boundary_errors = _select_in_window(
        calls, receipt, ready, stop)
    errors.extend(boundary_errors)
    # H6-DELTA: group-death legs ledger nothing at or after the
    # independently proven death; any post-death row then fails the
    # exact population agreement below as a duplicate/foreign count.
    if death is not None and isinstance(death.get("death_ns"), int):
        if any(call["t1"] >= death["death_ns"] for call in in_window):
            errors.append("group-death leg ledgered a call at or after the proven death")
    mandatory: Counter = Counter()
    expected_images: dict = defaultdict(set)
    expected_calls: dict = defaultdict(deque)
    for call in in_window:
        key = (call["pid"], call["tid"], call["fn"])
        expected_images[key].add(images[call["image"]]["image"])
        mandatory[key] += 1
    if not mandatory:
        errors.append("no independently ledgered calls after capture readiness")
    # Calls outside the capture window or scope must never surface as rows:
    # exact per-key population agreement enforces this (below). Ledger
    # sequence (not dict equality) breaks timestamp ties: normalized
    # window-bound calls are often identical dicts.
    for _, call in sorted(enumerate(in_window), key=lambda pair: (pair[1]["t0"], pair[0])):
        expected_calls[call["pid"], call["tid"], call["fn"]].append(call)
    actual = Counter((row["pid"], row["tid"], row["fn"]) for row in rows)
    for key in sorted(actual.keys() | mandatory.keys()):
        if mandatory[key] == 0 and actual[key] > 0:
            errors.append(
                f"outside-scope or foreign count: captured {actual[key]} rows for no "
                f"ledgered in-scope call: {key}")
        elif actual[key] > mandatory[key]:
            errors.append(
                f"duplicate return: captured {actual[key]} rows for {mandatory[key]} "
                f"ledgered calls: {key}")
        elif actual[key] < mandatory[key]:
            errors.append(
                f"captured provider-call population disagrees with ledger: {key}: "
                f"ledger {mandatory[key]} captured {actual[key]}")
    # H6-DELTA: order-matched attribution. When lossless and per-key exact,
    # the k-th row of a key is the k-th ledger call: reused keys across
    # generations (rapid-chain) attribute by order. Under loss or mismatch
    # there is no attribution: reused keys are ambiguous (fail, like N3).
    lossless = bool(evidence) and all(
        evidence[0].get(field, 0) == 0
        for field in ("event_loss", "start_insert_failures", "unmatched_returns",
                      "rv_update_failures", "cgroup_scope_failures",
                      "process_tracking_failures", "process_tracking_evictions"))
    exact = all(actual[key] == mandatory[key] for key in actual.keys() | mandatory.keys())
    order_match: dict = {}
    ambiguous_keys = [key for key, ids in expected_images.items() if len(ids) != 1]
    if lossless and exact and mandatory:
        per_key_rows: dict = defaultdict(list)
        for index, row in enumerate(rows):
            per_key_rows[row["pid"], row["tid"], row["fn"]].append((index, row))
        for key, ledgered in expected_calls.items():
            for (index, _), call in zip(sorted(per_key_rows.get(key, [])), list(ledgered)):
                order_match[index] = call
    elif ambiguous_keys:
        errors.append("ambiguous image generation for a reused key under loss; "
                      "a stronger oracle is required")
    # H6-DELTA: pid/system purity (no global fallback links).
    if scope_kind == "pid":
        for row in rows:
            if row["pid"] != receipt.get("pid"):
                errors.append("pid capture published a foreign pid: no global fallback allowed")
                break
        for row in rows:
            if row["tid"] not in receipt.get("known_tids", [row["tid"]]):
                errors.append("pid capture published an unknown tid")
                break
    else:
        for row in rows:
            if row["pid"] not in owned_pids:
                errors.append("capture published a row for an unowned pid")
                break
    named = unknown = false_names = 0
    populations = {image["path"]: {"named": 0, "unknown": 0} for image in images.values()}
    generations: dict = {image_id: {"named": 0, "unknown": 0} for image_id in images}
    phase_populations: dict = defaultdict(Counter)
    first_rows: dict = {}
    for index, row in enumerate(rows):
        key = row["pid"], row["tid"], row["fn"]
        matched = order_match.get(index)
        if matched is not None:
            want_rv = RV_NAMES.get(matched["rv"])
            if want_rv is None or row["rv"] != want_rv:
                errors.append("capture disagrees with ledgered provider return value")
        if row["path"] is None:
            unknown += 1
        else:
            named += 1
            if matched is not None:
                image = images[matched["image"]]
                if row["path"] != image["path"] or row["label"] != Path(image["path"]).name:
                    false_names += 1
            else:
                ids = expected_images.get(key, set())
                if (len(ids) != 1 or row["path"] != images[next(iter(ids))]["path"]
                        or row["label"] != Path(row["path"]).name):
                    false_names += 1
        ids = {matched["image"]} if matched is not None else expected_images.get(key, set())
        if len(ids) == 1:
            image_id = next(iter(ids))
            field = "named" if row["path"] else "unknown"
            populations[images[image_id]["path"]][field] += 1
            generations[image_id][field] += 1
            first_rows.setdefault(image_id, (index, row))
            if matched is not None:
                phase_populations[matched["phase"]][field] += 1
            elif expected_calls[key]:
                phase_populations[expected_calls[key].popleft()["phase"]][field] += 1
    if false_names:
        errors.append("capture published an executable other than the independently observed image")
    if receipt.get("require_named") and not named:
        errors.append("required stable positive contains no named event")
    for image_id in receipt.get("require_named_images", []):
        if not generations[image_id]["named"]:
            errors.append("required image contains no independently correct named event")
    for image_id in receipt.get("first_unknown_images", []):
        image_calls = [call for call in in_window if call["image"] == image_id]
        if (not image_calls or image_id not in transitions
                or any(call["scope"] == "selected" and call["t0"] < ready
                       for call in calls if call["image"] == image_id)):
            errors.append("first image CALL lacks independently proved fresh scoped generation")
        else:
            first = min(image_calls, key=lambda call: call["t0"])
            entry = first_rows.get(image_id)
            if entry is None or (entry[1]["pid"], entry[1]["tid"], entry[1]["fn"]) != (
                    first["pid"], first["tid"], first["fn"]):
                errors.append("first image event disagrees with the earliest independent scoped call")
            elif entry[1]["path"] is not None:
                errors.append("fresh image first scoped CALL was named without a possible upper witness")
    # H6-DELTA: abandoned in-flight accounting. Physical entries, API
    # returns, completed operations, named calls and unknowns are distinct
    # units: entries minus returns must equal the ledgered abandoned count.
    abandoned = receipt.get("abandoned_expected", 0)
    entered = len(in_window) + abandoned
    if counts and any([counts[0].get("stats_entered") != entered,
                       counts[0].get("stats_returned") != len(in_window),
                       counts[0].get("raw_calls") != len(rows)]):
        errors.append("terminal counts disagree with independently accounted physical entries/"
                      "returns/completions")
    elif counts and (counts[0].get("stats_entered", 0) - counts[0].get("stats_returned", 0)) != abandoned:
        errors.append("terminal entry/return gap disagrees with the ledgered abandoned in-flight count")
    # H6-DELTA: reuse legs. Expected-but-unobserved reuse fails the cell;
    # observed reuse additionally requires order-attributed non-completion
    # of old operations (post-exec rows match post-exec calls only, above).
    reuse_expected = receipt.get("reuse_expected", {})
    for kind in ("session", "va", "token"):
        info = receipt.get(f"{kind}_reuse", {})
        if reuse_expected.get(kind) and not info.get("observed"):
            errors.append(f"expected {kind} reuse across exec is not demonstrated by the ledger")
    if evidence:
        ev = evidence[0]
        if ev.get("privacy_mode") != "allowlisted" or ev.get("trace_truncated") is not False:
            errors.append("capture privacy policy/truncation differs from the requested policy")
        if any(ev.get(field, 0) != 0 for field in
               ("event_loss", "start_insert_failures", "unmatched_returns", "rv_update_failures",
                "cgroup_scope_failures", "process_tracking_failures", "process_tracking_evictions")):
            errors.append("capture reports event/identity loss in this no-loss cell")
        if ev.get("final_drain") is False and ev.get("completeness") == "COMPLETE":
            errors.append("capture claims complete without its final drain proof")
        if ev.get("in_flight_at_end", 0) != abandoned:
            errors.append("terminal in-flight disagrees with the ledgered abandoned in-flight count")
        backend = ev.get("attach_backend", {})
        if backend.get("fallback") is not None:
            errors.append("capture installed a fallback link: no global fallback allowed")
        if receipt.get("requested_backend") and backend.get("selection") != receipt["requested_backend"]:
            errors.append("capture backend differs from the requested backend")
    else:
        errors.append("missing terminal evidence record")
    return {"pass": not errors, "status": "pass" if not errors else "fail",
            "cell": receipt.get("cell"), "leg": receipt.get("leg"),
            "calls": len(rows), "named": named, "unknown": unknown, "false_names": false_names,
            "named_share": named / len(rows) if rows else None,
            "unknown_share": unknown / len(rows) if rows else None,
            "physical_entered": entered, "api_returned": len(in_window),
            "completed_operations": len(rows), "abandoned": abandoned,
            "pre_ready_calls": pre_ready, "post_stop_calls": post_stop,
            "out_of_scope_calls": out_of_scope,
            "measured_calls": len(measured_calls), "warmup_calls": len(warmup_calls),
            "order_matched": len(order_match), "ambiguous_keys": len(ambiguous_keys),
            "link_losses": evidence[0].get("task_uprobe_link_losses") if evidence else None,
            "image_populations": populations, "image_generation_populations": generations,
            "phase_populations": {key: dict(value) for key, value in phase_populations.items()},
            "mandatory_calls": sum(mandatory.values()), "counts": counts,
            "evidence": evidence, "errors": errors}


def _check_group_death_proof(death, receipt):
    """Group-death-ends-capture gate (brief line 101, death half).

    All inputs are harness receipts (waitpid, /proc, monotonic clock),
    never p11scope output. Returns a list of error strings.
    """
    errors = []
    if receipt.get("observer_rc") != 0:
        errors.append("observer did not exit successfully")
    if receipt.get("caller_rc") != -signal.SIGKILL:
        errors.append("group-death caller was not reaped as whole-group SIGKILLed")
    if death.get("kill") != "SIGKILL/killpg":
        errors.append("group death was not a whole-group SIGKILL via killpg")
    if not isinstance(death.get("group_size_before"), int) or death["group_size_before"] < 1:
        errors.append("group-death leg lacks a live-group pre-kill receipt")
    if death.get("reaped") is not True or death.get("proc_gone") is not True:
        errors.append("group death is not proven by waitpid plus /proc disappearance")
    if death.get("manufactured_reuse") is not False:
        errors.append("numeric PID reuse must never be manufactured via sysctl")
    if not death.get("replacement_leg"):
        errors.append("group-death leg names no independently admitted replacement control")
    ready, stop = receipt.get("observer_ready_ns"), receipt.get("observer_stopped_ns")
    kill_ns, death_ns = death.get("kill_ns"), death.get("death_ns")
    if not (isinstance(kill_ns, int) and isinstance(death_ns, int)
            and isinstance(ready, int) and isinstance(stop, int)
            and ready < kill_ns <= death_ns < stop):
        errors.append("group-death kill/death stamps are not inside the observer interval")
    else:
        min_dwell = death.get("min_dwell_ns", 0)
        if not isinstance(min_dwell, int) or stop - death_ns < min_dwell:
            errors.append("post-death dwell is too short to prove capture ended")
    return errors


def _check_measured_warmup(calls, receipt, ready, stop, start):
    """Shared measured/warmup gate. Returns (measured_calls, warmup_calls, errors)."""
    errors = []
    measured = receipt.get("measured")
    if (not measured or not measured.get("label") or measured.get("expected_calls", 0) <= 0
            or not ready <= measured["t0"] <= measured["t1"] <= stop):
        errors.append("missing measured phase: require a fixed nonempty phase after public readiness")
        measured_calls = []
    else:
        measured_calls = [call for call in calls if call["phase"] in measured.get("phases", [])]
        if len(measured_calls) != measured["expected_calls"] or any(
                not measured["t0"] <= call["t0"] <= call["t1"] <= measured["t1"]
                for call in measured_calls):
            errors.append("measured phase disagrees with its fixed ledger population/window")
    warmup = receipt.get("warmup")
    warmup_ok = (
        warmup
        and warmup.get("label")
        and measured
        and start <= warmup["t0"] <= warmup["t1"] <= measured["t0"]
    )
    if not warmup_ok:
        errors.append("missing warm-up window: warm-up must be explicitly separated and bounded")
        warmup_calls = []
    else:
        warmup_calls = [call for call in calls if call["phase"] in warmup.get("phases", [])]
        if len(warmup_calls) != warmup.get("expected_calls", 0) or any(
                not warmup["t0"] <= call["t0"] <= call["t1"] <= warmup["t1"]
                for call in warmup_calls):
            errors.append("warm-up phase disagrees with its declared ledger population/window")
    return measured_calls, warmup_calls, errors


def _select_in_window(calls, receipt, ready, stop):
    """Shared scope-kind-aware in-window selection.

    Returns (in_window, pre_ready, post_stop, out_of_scope, boundary_errors).
    """
    scope_kind = receipt.get("scope_kind", "pid")
    owned_pids = set(receipt.get("owned_pids", []))
    intervals = receipt.get("scope_intervals", [])
    in_window = []
    pre_ready = post_stop = out_of_scope = 0
    boundary_errors = []
    for call in calls:
        in_scope = True
        if scope_kind == "pid":
            if call["pid"] != receipt.get("pid"):
                in_scope = False
        elif scope_kind == "cgroup":
            if call["scope"] != "selected":
                in_scope = False
            elif not any(iv["pid"] == call["pid"] and iv["membership"] == "selected"
                         and iv["t0"] <= call["t0"] <= call["t1"] <= iv["t1"] for iv in intervals):
                in_scope = False
        else:
            if call["pid"] not in owned_pids:
                in_scope = False
        if not in_scope:
            out_of_scope += 1
            continue
        if call["t1"] < ready:
            pre_ready += 1
            continue
        if call["t0"] >= stop:
            post_stop += 1
            continue
        if not (call["t0"] >= ready and call["t1"] < stop):
            boundary_errors.append("provider call overlaps an unresolved observer boundary")
            continue
        in_window.append(call)
    return in_window, pre_ready, post_stop, out_of_scope, boundary_errors


def evaluate_trace_h6(trace, ledger, receipt, file_trace=None):
    """Judge one H6 trace leg. Never raises on evidence input."""
    try:
        return _evaluate_trace_h6(trace, ledger, receipt, file_trace)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {"pass": False, "status": "fail", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"), "named": 0, "unknown": 0, "false_names": 0,
                "errors": [f"invalid independent evidence: {error}"]}


# ---------------------------------------------------------------------------
# H6 oracle: profile / metrics legs (aggregate JSON + stdout parity)
# ---------------------------------------------------------------------------

def _evaluate_aggregate_h6(doc, stdout_text, ledger, receipt, mode):
    errors = []
    if receipt.get("backend_refused"):
        return {"pass": False, "status": "negative", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"), "negative_reason": receipt["backend_refused"],
                "errors": ["backend refused: %s" % (receipt["backend_refused"],)]}
    want_schema = ("p11scope/observed-profile/v3-metrics" if mode == "metrics"
                   else "p11scope/observed-profile/v3")
    if doc.get("schema") != want_schema or doc.get("lane") != mode:
        errors.append("aggregate schema/lane differs from the requested mode")
    capture = doc.get("capture", {})
    if capture.get("mode") != mode or capture.get("scope") != receipt.get("scope_kind"):
        errors.append("aggregate capture mode/scope differs from the requested leg")
    want_privacy = "aggregate-only" if mode == "metrics" else "allowlisted"
    if capture.get("privacy_mode") != want_privacy:
        errors.append("aggregate privacy mode differs from the requested policy")
    if mode == "metrics" and set(doc.keys()) != {"capture", "evidence", "functions", "lane", "schema"}:
        errors.append("metrics surface carries non-aggregate sections")
    modules = capture.get("modules", [])
    pin = receipt["provider_before"]
    if (len(modules) != 1 or modules[0].get("path") != pin.get("path")
            or modules[0].get("ino") != pin.get("ino")
            or modules[0].get("sha256") != pin.get("sha256")):
        errors.append("aggregate module identity disagrees with the held provider pin")
    if receipt.get("manual_rebind"):
        errors.append("manual rebind cannot satisfy automatic acceptance")
    if any(row.get("kind") == "rebind" for row in ledger):
        errors.append("fixture-issued rebind present: not an automatic recovery proof")
    calls = [row for row in ledger if row["kind"] == "call"]
    start, ready, stop = (receipt[field] for field in
                          ("observer_started_ns", "observer_ready_ns", "observer_stopped_ns"))
    measured_calls, warmup_calls, gate_errors = _check_measured_warmup(
        calls, receipt, ready, stop, start)
    errors.extend(gate_errors)
    in_window, pre_ready, post_stop, out_of_scope, boundary_errors = _select_in_window(
        calls, receipt, ready, stop)
    errors.extend(boundary_errors)
    if not in_window:
        errors.append("no independently ledgered calls after capture readiness")
    # Ledger expectations per function: completed == returned, errors ==
    # returned-nonzero, in-flight == abandoned. Abandoned frames are not
    # ledger call records; the receipt attributes them per function.
    abandoned_by_fn: Counter = Counter(receipt.get("abandoned_by_fn", {}))
    expect_completed: Counter = Counter()
    expect_errors: Counter = Counter()
    for call in in_window:
        expect_completed[call["fn"]] += 1
        if call["rv"] != 0:
            expect_errors[call["fn"]] += 1
    got_completed: Counter = Counter()
    got_errors: Counter = Counter()
    got_in_flight: Counter = Counter()
    named_calls = unknown_calls = 0
    for function in doc.get("functions", []):
        names = function.get("names", [])
        label = names[0] if len(names) == 1 else "|".join(names)
        if label == "unknown":
            unknown_calls += function.get("calls", 0)
            if function.get("calls", 0) or function.get("errors", 0) or function.get("in_flight", 0):
                errors.append("unverified function claims completed calls")
            continue
        named_calls += function.get("calls", 0)
        got_completed[label] += function.get("calls", 0)
        got_errors[label] += function.get("errors", 0)
        got_in_flight[label] += function.get("in_flight", 0)
    for fn in sorted(set(expect_completed) | set(got_completed)):
        if got_completed[fn] > expect_completed[fn]:
            errors.append(
                f"duplicate return: function {fn}: captured {got_completed[fn]} completed "
                f"for {expect_completed[fn]} ledgered calls")
        elif got_completed[fn] < expect_completed[fn]:
            errors.append(
                f"aggregate population disagrees with ledger: function {fn}: "
                f"ledger {expect_completed[fn]} captured {got_completed[fn]}")
    for fn in sorted(set(expect_errors) | set(got_errors)):
        if got_errors[fn] != expect_errors[fn]:
            errors.append(
                f"aggregate returned-error population disagrees with ledger: function {fn}: "
                f"ledger {expect_errors[fn]} captured {got_errors[fn]}")
    for fn in sorted(set(abandoned_by_fn) | set(got_in_flight)):
        if got_in_flight[fn] != abandoned_by_fn[fn]:
            errors.append(
                f"aggregate in-flight disagrees with the ledgered abandoned count: function {fn}: "
                f"ledger {abandoned_by_fn[fn]} captured {got_in_flight[fn]}")
    total_completed = sum(got_completed.values())
    total_errors = sum(got_errors.values())
    total_in_flight = sum(got_in_flight.values())
    match = re.search(
        r"(\d+) completed calls; (\d+) returned errors; (\d+) entries without an observed return\.",
        stdout_text)
    if not match or tuple(int(v) for v in match.groups()) != (
            total_completed, total_errors, total_in_flight):
        errors.append("aggregate stdout totals disagree with the JSON document")
    abandoned = sum(abandoned_by_fn.values())
    if receipt.get("abandoned_expected", 0) != abandoned:
        errors.append("receipt abandoned count disagrees with its per-function attribution")
    ev = doc.get("evidence", {})
    if ev.get("attach_failures"):
        errors.append("aggregate capture reports attach failures")
    if (ev.get("attach_backend") or {}).get("fallback") is not None:
        errors.append("capture installed a fallback link: no global fallback allowed")
    reported = (ev.get("attach_backend") or {}).get("selection")
    if receipt.get("requested_backend") and reported is not None \
            and reported != receipt["requested_backend"]:
        errors.append("capture backend differs from the requested backend")
    if receipt.get("observer_rc") != 0 or receipt.get("caller_rc") != 0:
        errors.append("observer or caller did not exit successfully")
    return {"pass": not errors, "status": "pass" if not errors else "fail",
            "cell": receipt.get("cell"), "leg": receipt.get("leg"),
            "completed_calls": total_completed, "returned_errors": total_errors,
            "in_flight": total_in_flight, "abandoned": abandoned,
            "named_calls": named_calls, "unknown_calls": unknown_calls,
            "physical_entered": len(in_window) + abandoned,
            "api_returned": len(in_window),
            "pre_ready_calls": pre_ready, "post_stop_calls": post_stop,
            "out_of_scope_calls": out_of_scope,
            "measured_calls": len(measured_calls), "warmup_calls": len(warmup_calls),
            "per_function": {fn: {"completed": got_completed[fn], "errors": got_errors[fn],
                                  "in_flight": got_in_flight[fn]}
                             for fn in sorted(set(got_completed) | set(got_errors))},
            "errors": errors}


def evaluate_profile_h6(doc, stdout_text, ledger, receipt):
    """Judge one H6 profile leg. Never raises on evidence input."""
    try:
        return _evaluate_aggregate_h6(doc, stdout_text, ledger, receipt, "profile")
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {"pass": False, "status": "fail", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"),
                "errors": [f"invalid independent evidence: {error}"]}


def evaluate_metrics_h6(doc, stdout_text, ledger, receipt):
    """Judge one H6 metrics leg. Never raises on evidence input."""
    try:
        return _evaluate_aggregate_h6(doc, stdout_text, ledger, receipt, "metrics")
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {"pass": False, "status": "fail", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"),
                "errors": [f"invalid independent evidence: {error}"]}


# ---------------------------------------------------------------------------
# H6 oracle: inventory legs (native snapshot + event log vs ledger batches)
# ---------------------------------------------------------------------------

INV_LINE = re.compile(r"^(IDENT|MAPPED|LEDGER|HELD|RETURNED|ZOMBIE|EXEC|DONE|READY) (.+)$")
INV_KV = re.compile(r"(\S+?)=(\S+)")


def parse_inv_ledger(text):
    """Parse inventory-ledger stdout into typed batches. Never raises."""
    out = {"idents": [], "mapped": [], "batches": [], "held": [], "returned": [],
           "zombie": [], "execs": [], "dones": [], "readys": [], "unflushed": 0,
           "strange": []}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("LEDGER_UNFLUSHED"):
            out["unflushed"] += 1
            continue
        match = INV_LINE.match(line)
        if not match:
            out["strange"].append(line[:120])
            continue
        kind, rest = match.groups()
        fields = dict(INV_KV.findall(rest))
        try:
            if kind == "IDENT":
                out["idents"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                      "start": int(fields["start"]), "gen": int(fields["gen"]),
                                      "exe": fields["exe"]})
            elif kind == "MAPPED":
                out["mapped"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                      "start": int(fields["start"]), "gen": int(fields["gen"]),
                                      "exe": fields["exe"], "module": fields["module"],
                                      "ino": int(fields["ino"])})
            elif kind == "LEDGER":
                out["batches"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                       "start": int(fields["start"]), "gen": int(fields["gen"]),
                                       "exe": fields["exe"], "module": fields["module"],
                                       "fn": fields["fn"], "mech": fields["mech"],
                                       "n": int(fields["n"]), "bad": int(fields["bad"]),
                                       "phase": fields["phase"], "t0": int(fields["t0"]),
                                       "t1": int(fields["t1"])})
            elif kind == "HELD":
                out["held"].append(fields)
            elif kind == "RETURNED":
                out["returned"].append(fields)
            elif kind == "ZOMBIE":
                out["zombie"].append(fields)
            elif kind == "EXEC":
                out["execs"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                     "start": int(fields["start"]), "gen": int(fields["gen"]),
                                     "exe": fields["exe"], "how": fields["how"],
                                     "next": fields["next"]})
            elif kind == "DONE":
                out["dones"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                     "start": int(fields["start"]), "gen": int(fields["gen"]),
                                     "exe": fields["exe"], "status": fields["status"]})
            elif kind == "READY":
                out["readys"].append({"cell": fields["cell"], "pid": int(fields["pid"]),
                                      "start": int(fields["start"]), "gen": int(fields["gen"]),
                                      "exe": fields["exe"]})
        except (KeyError, ValueError):
            out["strange"].append(line[:120])
    return out


def attach_side_entered(batches, phases=None):
    """Attach-side entered totals per (pid, gen, module): table calls only.

    The dlsym C_GetFunctionList entry is not a function-table call and is
    excluded (same rule the C8 oracle applies).
    """
    totals: Counter = Counter()
    bad: Counter = Counter()
    for batch in batches:
        if phases is not None and batch["phase"] not in phases:
            continue
        if batch["fn"] == "C_GetFunctionList":
            continue
        key = (batch["pid"], batch["gen"], batch["module"])
        totals[key] += batch["n"]
        bad[key] += batch["bad"]
    return totals, bad


def normalize_inv_calls(batches):
    """Expand ledger batches to N3-schema individual call records.

    Batches carry window [t0, t1] bounds shared by their calls; phases are
    suffixed with :genN so measured/warmup gates can select generations.
    Failed calls get rv=-1 (failed, exact value unledgered by the driver).
    tid is the caller's pid (single-threaded driver; leader-exit worker
    activity is out of scope for the H6 inventory legs).
    """
    calls = []
    for batch in batches:
        if batch["fn"] == "C_GetFunctionList":
            continue
        phase = f"{batch['phase']}:gen{batch['gen']}"
        for index in range(batch["n"]):
            calls.append({"kind": "call", "image": batch["gen"], "pid": batch["pid"],
                          "tid": batch["pid"], "fn": batch["fn"],
                          "rv": -1 if index < batch["bad"] else 0, "phase": phase,
                          "scope": "selected", "sess": 0,
                          "t0": batch["t0"], "t1": batch["t1"]})
    return calls


def coverage_of(edge):
    """entries.coverage per the inventory/v1 contract (C8 reads it the same way)."""
    return (edge.get("entries") or {}).get("coverage") or {}


# S1 attribution classes from src/kinds.rs at this source revision:
# transition::INITIALIZE (Init), direct != NONE (single-call operations),
# and Finish transitions (FINISH_WITH_OUTPUT / FINISH_ALWAYS /
# FINISH_ON_SUCCESS). Init and direct calls record mechanism claims
# OK-only with no error count (record_init_mechanism); operational calls
# attribute calls+errors (attribute_op_call); bad direct calls establish
# nothing (apply_direct returns early); bad FINISH_ON_SUCCESS retains its
# machine without an end state. Bad BUFFER_TOO_SMALL finishes also retain;
# the H6 fixtures use sized single-shot buffers, so any such live row fails
# loudly for investigation instead of silently matching.
S1_INIT_FNS = frozenset({
    "C_EncryptInit", "C_DecryptInit", "C_DigestInit", "C_SignInit",
    "C_SignRecoverInit", "C_VerifyInit", "C_VerifyRecoverInit",
    "C_MessageEncryptInit", "C_MessageDecryptInit", "C_MessageSignInit",
    "C_MessageVerifyInit", "C_VerifySignatureInit"})
S1_DIRECT_FNS = frozenset({
    "C_GenerateKey", "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey",
    "C_DeriveKey", "C_EncapsulateKey", "C_DecapsulateKey",
    "C_WrapKeyAuthenticated", "C_UnwrapKeyAuthenticated"})
S1_FINISH_FNS = frozenset({
    "C_Encrypt", "C_Decrypt", "C_Digest", "C_Sign", "C_SignRecover",
    "C_VerifyRecover", "C_EncryptFinal", "C_DecryptFinal", "C_DigestFinal",
    "C_SignFinal", "C_Verify", "C_VerifyFinal", "C_VerifySignature",
    "C_VerifySignatureFinal", "C_MessageEncryptFinal", "C_MessageDecryptFinal",
    "C_MessageSignFinal", "C_MessageVerifyFinal"})
S1_RETAIN_ON_FAILURE_FNS = frozenset({
    "C_MessageEncryptFinal", "C_MessageDecryptFinal", "C_MessageSignFinal",
    "C_MessageVerifyFinal"})
S1_COUNT_ONLY_FNS = frozenset({
    "C_Initialize", "C_GetInfo", "C_GetFunctionList", "C_GetSlotList",
    "C_GetInterfaceList", "C_GetInterface", "C_GetSlotInfo", "C_GetTokenInfo",
    "C_GetMechanismList", "C_GetMechanismInfo", "C_InitToken"})


def mechanism_row_id(row):
    """Production mechanism row id: mechanism_hex when a dict, else str."""
    if isinstance(row, dict):
        if row.get("mechanism_hex"):
            return row["mechanism_hex"]
        value = row.get("mechanism")
        if isinstance(value, int):
            return f"0x{value:x}"
        return str(value)
    return str(row)


def ledger_s1_totals(batches, started_ns):
    """Per-(pid, gen, module) S1 ledger totals over in-capture phases.

    Gen0 setup precedes the observer (same guard as counted_totals).
    Returns (mech_calls, mech_errors, op_completed, op_failed, op_calls,
    entered) keyed by (pid, gen, module[, mech]); op totals assume the
    H6 workload shape (single-shot, Init-before-op, no competing Inits).
    """
    mech_calls: Counter = Counter()
    mech_errors: Counter = Counter()
    op_completed: Counter = Counter()
    op_failed: Counter = Counter()
    op_calls: Counter = Counter()
    entered: Counter = Counter()
    for batch in batches:
        if batch["fn"] == "C_GetFunctionList":
            continue
        if batch["gen"] == 0 and batch["phase"] == "setup":
            if batch["t1"] >= started_ns:
                raise SetupError("gen0 setup overlaps the observer lifetime: "
                                 "the gated start is broken")
            continue
        key = (batch["pid"], batch["gen"], batch["module"])
        fn, mech, n, bad = batch["fn"], batch["mech"], batch["n"], batch["bad"]
        entered[key] += n
        if fn not in S1_COUNT_ONLY_FNS:
            op_calls[key] += n
        if mech == "-":
            continue
        mkey = key + (mech,)
        if fn in S1_INIT_FNS or fn in S1_DIRECT_FNS:
            mech_calls[mkey] += n - bad
        else:
            mech_calls[mkey] += n
            mech_errors[mkey] += bad
        if fn in S1_DIRECT_FNS or fn in S1_FINISH_FNS:
            op_completed[key] += n - bad
        if fn in S1_FINISH_FNS and fn not in S1_RETAIN_ON_FAILURE_FNS:
            op_failed[key] += bad
    return mech_calls, mech_errors, op_completed, op_failed, op_calls, entered


def _evaluate_inventory_h6(doc, ledgers, receipt):
    errors = []
    if receipt.get("backend_refused"):
        return {"pass": False, "status": "negative", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"), "negative_reason": receipt["backend_refused"],
                "errors": ["backend refused: %s" % (receipt["backend_refused"],)]}
    if doc.get("schema") != "p11scope/inventory/v1":
        errors.append("inventory schema differs from the native snapshot contract")
    if doc.get("scope") != receipt.get("scope_label"):
        errors.append("inventory scope differs from the requested leg")
    if receipt.get("manual_rebind"):
        errors.append("manual rebind cannot satisfy automatic acceptance")
    for cell, parsed in ledgers.items():
        if parsed["unflushed"] or parsed["strange"]:
            errors.append(f"ledger {cell} has unflushed or unparsable records")
        if any(done["status"] != "ok" for done in parsed["dones"]):
            errors.append(f"ledger {cell} reports a failed generation")
    # Normalized gates over every owned batch population.
    calls = []
    for parsed in ledgers.values():
        calls.extend(normalize_inv_calls(parsed["batches"]))
    start, ready, stop = (receipt[field] for field in
                          ("observer_started_ns", "observer_ready_ns", "observer_stopped_ns"))
    measured_calls, warmup_calls, gate_errors = _check_measured_warmup(
        calls, receipt, ready, stop, start)
    errors.extend(gate_errors)
    in_window, pre_ready, post_stop, out_of_scope, boundary_errors = _select_in_window(
        calls, receipt, ready, stop)
    errors.extend(boundary_errors)
    callers = {caller["id"]: caller for caller in doc.get("callers", [])}
    module_by_path = {}
    for module in doc.get("modules", []):
        for path in module.get("paths", []):
            module_by_path.setdefault(path, module)
    owned_ids: set = set()
    per_pid: dict = {}
    for pid_text, want in receipt.get("expected_incarnations", {}).items():
        pid = int(pid_text)
        gens = {int(gen): spec for gen, spec in want["gens"].items()}
        rows = sorted((caller for caller in doc.get("callers", []) if caller.get("pid") == pid),
                      key=lambda caller: caller.get("incarnation", -1))
        per_pid[pid] = {"incarnations": len(rows), "exes": [],
                        "lifecycles": [], "edges": []}
        if [caller.get("incarnation") for caller in rows] != sorted(gens):
            errors.append(f"pid {pid}: incarnation population disagrees with the exec ledger")
        for caller in rows:
            owned_ids.add(caller["id"])
            gen = caller.get("incarnation")
            exe = ((caller.get("image") or {}).get("exe") or {}).get("path")
            per_pid[pid]["exes"].append(exe)
            per_pid[pid]["lifecycles"].append(caller.get("lifecycle"))
            want_gen = gens.get(gen, {})
            if exe != want_gen.get("exe"):
                errors.append(f"pid {pid} gen {gen}: executable disagrees with the exec ledger")
            if bool(caller.get("retired")) != bool(want_gen.get("retired", False)):
                errors.append(f"pid {pid} gen {gen}: retirement disagrees with the exec ledger")
    # Expected physical edges: counted + exact, or absent/zero for outside.
    # Edge keys are "pid:gen:module" strings (JSON-safe receipts).
    physical_entered = 0
    physical_counted = 0
    for key, want in receipt.get("expected_edges", {}).items():
        pid_text, gen_text, module_key = key.split(":")
        pid, gen = int(pid_text), int(gen_text)
        provider = receipt["providers"][module_key]
        module = module_by_path.get(provider["path"])
        if module is not None and provider.get("ino") is not None:
            identity = module.get("identity") or {}
            if identity.get("inode") != provider["ino"] or (
                    provider.get("sha256") is not None
                    and identity.get("sha256") != provider["sha256"]):
                errors.append(f"pid {pid} gen {gen} {module_key}: module identity "
                              f"disagrees with the held provider file")
        caller_id = next((caller["id"] for caller in doc.get("callers", [])
                          if caller.get("pid") == pid and caller.get("incarnation") == gen), None)
        edge = next((edge for edge in doc.get("edges", [])
                     if edge.get("caller") == caller_id
                     and module is not None and edge.get("module") == module.get("id")), None)
        per_pid.setdefault(pid, {}).setdefault("edges", []).append(
            {"gen": gen, "module": module_key,
             "count": ((edge.get("entries") or {}).get("count") if edge else None),
             "state": (coverage_of(edge).get("state") if edge else "absent")})
        if want.get("zero_ok"):
            if edge is not None and (edge.get("entries") or {}).get("count", 0) != 0:
                errors.append(f"pid {pid} gen {gen} {module_key}: mapping-only control "
                              f"reports usage")
        elif want.get("counted"):
            physical_entered += want["count"]
            if edge is None or coverage_of(edge).get("state") != "counted":
                errors.append(f"pid {pid} gen {gen} {module_key}: usage never admitted "
                              f"(expected {want['count']} counted entries)")
            else:
                got = (edge.get("entries") or {}).get("count")
                physical_counted += got or 0
                if got != want["count"]:
                    errors.append(f"pid {pid} gen {gen} {module_key}: counted entries disagree "
                                  f"with the ledger: ledger {want['count']} captured {got}")
                if coverage_of(edge).get("lossy"):
                    errors.append(f"pid {pid} gen {gen} {module_key}: counted edge is lossy")
        else:
            if edge is not None and (edge.get("entries") or {}).get("count", 0) != 0:
                errors.append(f"pid {pid} gen {gen} {module_key}: outside-scope calls entered "
                              f"the scoped totals")
    # Foreign callers (unidentifiable producer): refusal means no counted
    # usage on any of their edges; mapping-only rows may exist.
    foreign_ids = {caller["id"] for caller in doc.get("callers", [])
                   if caller.get("pid") in set(receipt.get("foreign_pids", []))}
    for edge in doc.get("edges", []):
        if edge.get("caller") in foreign_ids and (
                edge.get("entries") or {}).get("count", 0) != 0:
            errors.append("foreign producer calls entered the scoped totals")
            break
    # No unexpected edges may reference owned callers (outside never in totals).
    expected_pairs = set()
    for key in receipt.get("expected_edges", {}):
        pid_text, gen_text, module_key = key.split(":")
        pid, gen = int(pid_text), int(gen_text)
        provider = receipt["providers"][module_key]
        module = module_by_path.get(provider["path"])
        caller_id = next((caller["id"] for caller in doc.get("callers", [])
                          if caller.get("pid") == pid and caller.get("incarnation") == gen), None)
        if caller_id is not None and module is not None:
            expected_pairs.add((caller_id, module.get("id")))
    for edge in doc.get("edges", []):
        if edge.get("caller") in foreign_ids:
            continue
        if edge.get("caller") in owned_ids and (edge.get("caller"), edge.get("module")) \
                not in expected_pairs:
            errors.append("unexpected edge references an owned caller")
            break
    # Failed returns are reported separately from successes, always.
    failed_ledgered = sum(1 for call in in_window if call["rv"] != 0)
    # S1 legs: nonempty + ledger-matched when expected; honest-withheld else.
    instances = doc.get("instances", [])
    semantic_edges = doc.get("semantic_edges", [])
    s1 = {"instances": len(instances), "semantic_edges": len(semantic_edges),
          "withheld": [], "matched": [], "completed_total": 0,
          "failed_total": 0, "measured_completed": 0}
    if receipt.get("s1_expected"):
        if not instances and not semantic_edges:
            errors.append("S1 unavailable: no instance or semantic rows for the attested leg")
        all_batches = [batch for parsed in ledgers.values()
                       for batch in parsed["batches"]]
        mech_calls, mech_errors, op_completed, op_failed, op_calls, entered = \
            ledger_s1_totals(all_batches, receipt["observer_started_ns"])
        path_by_module = {module.get("id"): list(module.get("paths", []))
                          for module in doc.get("modules", [])}
        count_only_ids = set()
        for module_key in receipt.get("count_only_providers", []):
            module = module_by_path.get(receipt["providers"][module_key]["path"])
            if module is not None:
                count_only_ids.add(module.get("id"))

        def edge_group(edge):
            caller = callers.get(edge.get("caller"), {})
            paths = path_by_module.get(edge.get("module"), [])
            path = next((p for p in paths
                         if (caller.get("pid"), caller.get("incarnation"), p) in entered
                         or (caller.get("pid"), caller.get("incarnation"), p) in op_calls), None)
            if path is None and paths:
                path = paths[0]
            return caller.get("pid"), caller.get("incarnation"), path

        measured_gens = set()
        for phase in (receipt.get("measured") or {}).get("phases", []):
            if ":gen" in phase:
                try:
                    measured_gens.add(int(phase.split(":gen")[1]))
                except ValueError:
                    pass
        for edge in doc.get("edges", []):
            if edge.get("caller") not in owned_ids:
                continue
            pid, gen, module_path = edge_group(edge)
            key = (pid, gen, module_path)
            rows = edge.get("mechanisms") or []
            if not rows:
                s1["withheld"].append(edge.get("caller"))
                continue
            want_ids = {mech for (p, g, m, mech) in mech_calls if (p, g, m) == key}
            want_ids |= {mech for (p, g, m, mech) in mech_errors if (p, g, m) == key}
            got_ids = {mechanism_row_id(row) for row in rows}
            if got_ids - want_ids:
                errors.append(f"pid {pid} gen {gen}: S1 mechanism outside the "
                              f"ledgered mechanism set: {sorted(got_ids - want_ids)}")
            elif want_ids - got_ids:
                errors.append(f"pid {pid} gen {gen}: S1 unattributed ledgered "
                              f"mechanism: {sorted(want_ids - got_ids)}")
            else:
                for row in rows:
                    ident = mechanism_row_id(row)
                    if row.get("calls") != mech_calls.get(key + (ident,), 0):
                        errors.append(
                            f"pid {pid} gen {gen} {ident}: S1 mechanism call total "
                            f"disagrees with the ledger: ledger "
                            f"{mech_calls.get(key + (ident,), 0)} captured {row.get('calls')}")
                    if row.get("errors") != mech_errors.get(key + (ident,), 0):
                        errors.append(
                            f"pid {pid} gen {gen} {ident}: S1 mechanism error total "
                            f"disagrees with the ledger: ledger "
                            f"{mech_errors.get(key + (ident,), 0)} captured {row.get('errors')}")
                s1["matched"].append(edge.get("caller"))
            ops = edge.get("operations")
            counted = coverage_of(edge).get("state") == "counted"
            if counted and edge.get("module") not in count_only_ids:
                if ops is None:
                    errors.append(f"pid {pid} gen {gen}: S1 operations withheld "
                                  f"although a manifest attests the leg")
                    continue
                completed, failed = ops.get("completed"), ops.get("failed")
                if not isinstance(completed, int) or not isinstance(failed, int):
                    errors.append(f"pid {pid} gen {gen}: S1 operations lack "
                                  f"completed/failed totals")
                    continue
                if completed != op_completed.get(key, 0):
                    errors.append(
                        f"pid {pid} gen {gen}: S1 completed operations disagree "
                        f"with the ledger: ledger {op_completed.get(key, 0)} "
                        f"captured {completed}")
                if failed != op_failed.get(key, 0):
                    errors.append(
                        f"pid {pid} gen {gen}: S1 failed operations disagree "
                        f"with the ledger: ledger {op_failed.get(key, 0)} "
                        f"captured {failed}")
                if ops.get("calls") != op_calls.get(key, 0):
                    errors.append(
                        f"pid {pid} gen {gen}: S1 authorized calls disagree "
                        f"with the ledger: ledger {op_calls.get(key, 0)} "
                        f"captured {ops.get('calls')}")
                s1["completed_total"] += completed
                s1["failed_total"] += failed
                if not measured_gens or gen in measured_gens:
                    s1["measured_completed"] += completed
        if s1["withheld"] and not s1["matched"]:
            errors.append("S1 withheld for every owned edge although a manifest attests the leg")
        if s1["measured_completed"] < 10:
            errors.append(f"S1 measured image completes fewer than 10 successful "
                          f"operations: {s1['measured_completed']}")
        # Semantic rows group by (caller, module) exactly like edges: a stale
        # incarnation carrying successor counts fails its own group.
        api_by_group: Counter = Counter()
        for row in semantic_edges:
            caller = callers.get(row.get("caller"), {})
            paths = path_by_module.get(row.get("module"), [])
            module_path = paths[0] if paths else None
            group = (caller.get("pid"), caller.get("incarnation"), module_path)
            api = (row.get("api_returns") or {}).get("count")
            if not isinstance(api, int):
                errors.append("S1 semantic row lacks an api_returns count")
                continue
            api_by_group[group] += api
            if (row.get("api_returns") or {}).get("historical_only_returns"):
                errors.append("S1 semantic row carries historical-only returns "
                              "although every call post-dates admission")
            sub = row.get("operations")
            if sub is not None:
                sub_completed, sub_failed = sub.get("completed"), sub.get("failed")
                if not isinstance(sub_completed, int) or not isinstance(sub_failed, int):
                    errors.append("S1 semantic row lacks completed/failed totals")
                elif sub_completed + sub_failed > api:
                    errors.append("S1 semantic row ends more operations than it returns")
        for group, total in api_by_group.items():
            if total != entered.get(group, 0):
                errors.append(f"pid {group[0]} gen {group[1]}: S1 semantic returns "
                              f"disagree with the ledger: ledger {entered.get(group, 0)} "
                              f"captured {total}")
        for instance in instances:
            ref = instance.get("caller")
            if ref not in callers:
                errors.append("S1 instance references an unknown caller")
            elif callers[ref].get("pid") not in receipt.get("owned_pids", []):
                errors.append("S1 instance references an unowned caller")
    else:
        for edge in doc.get("edges", []):
            if edge.get("caller") not in owned_ids:
                continue
            semantics = edge.get("semantics")
            if not (semantics is None or str(semantics).startswith("unknown")):
                errors.append("non-attested leg publishes semantic rows")
                break
            if edge.get("mechanisms") is not None or edge.get("operations") is not None:
                errors.append("non-attested leg publishes mechanism/operation rows")
                break
    # Count-only providers: physical counts without semantic rows.
    for module_key in receipt.get("count_only_providers", []):
        provider = receipt["providers"][module_key]
        module = module_by_path.get(provider["path"])
        if module is None:
            continue
        for edge in doc.get("edges", []):
            if edge.get("module") != module.get("id") or edge.get("caller") not in owned_ids:
                continue
            if edge.get("mechanisms") is not None or edge.get("operations") is not None:
                errors.append(f"count-only provider {module_key} publishes semantic rows")
            semantics = edge.get("semantics")
            if semantics is not None and not str(semantics).startswith("unknown"):
                errors.append(f"count-only provider {module_key} publishes semantic rows")
    allowed_gaps = set(receipt.get("allowed_gap_subjects", []))
    allow_path_gaps = receipt.get("allow_path_gaps", False)
    gaps = [(gap.get("subject"), gap.get("detail")) for gap in doc.get("gaps", [])]
    for subject, _ in gaps:
        if subject in allowed_gaps:
            continue
        if allow_path_gaps and isinstance(subject, str) and subject.startswith("/"):
            continue
        errors.append(f"unexpected inventory gap: {subject}")
    witnesses = (doc.get("observation") or {}).get("native_witnesses", {})
    attach = (doc.get("observation") or {}).get("attach", {})
    if attach.get("fallback") is not None:
        errors.append("capture installed a fallback link: no global fallback allowed")
    if receipt.get("requested_backend") and attach.get("selection") != receipt["requested_backend"]:
        errors.append("capture backend differs from the requested backend")
    for cell, ending in receipt.get("cell_endings", {}).items():
        if ending.get("how") == "exited" and ending.get("rc") != 0:
            errors.append(f"ledger {cell} exited unsuccessfully")
    if receipt.get("observer_rc") != 0:
        errors.append("observer did not exit successfully")
    return {"pass": not errors, "status": "pass" if not errors else "fail",
            "cell": receipt.get("cell"), "leg": receipt.get("leg"),
            "physical_entered": physical_entered, "physical_counted": physical_counted,
            "completed_operations": s1["completed_total"] if receipt.get("s1_expected") else None,
            "failed_ledgered": failed_ledgered,
            "named_incarnations": sum(len(v.get("exes", [])) for v in per_pid.values()),
            "unbound_witnesses": witnesses.get("unbound"),
            "pre_ready_calls": pre_ready, "post_stop_calls": post_stop,
            "out_of_scope_calls": out_of_scope,
            "measured_calls": len(measured_calls), "warmup_calls": len(warmup_calls),
            "per_pid": per_pid, "s1": s1, "gaps": gaps,
            "errors": errors}


def evaluate_inventory_h6(doc, ledgers, receipt):
    """Judge one H6 inventory leg. Never raises on evidence input."""
    try:
        return _evaluate_inventory_h6(doc, ledgers, receipt)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {"pass": False, "status": "fail", "cell": receipt.get("cell"),
                "leg": receipt.get("leg"),
                "errors": [f"invalid independent evidence: {error}"]}


# ---------------------------------------------------------------------------
# H6 harness: independent process evidence
# ---------------------------------------------------------------------------

OwnedProcess = N3HARNESS["OwnedProcess"]
Reader = N3HARNESS["Reader"]
FilePin = N3HARNESS["FilePin"]
spawn_owned = N3HARNESS["spawn_owned"]
cleanup_processes = N3HARNESS["cleanup_processes"]
cleanup_cgroups = N3HARNESS["cleanup_cgroups"]
create_cgroup = N3HARNESS["create_cgroup"]
cgroup_of = N3HARNESS["cgroup_of"]
process_identity = N3HARNESS["process_identity"]
wait_capture_started = N3HARNESS["wait_capture_started"]
n3_command = N3HARNESS["command"]
signal_cleanup = N3HARNESS["signal_cleanup"]
cleanup_section = N3HARNESS["cleanup_section"]


def expect_line(reader, index, prefix, timeout):
    """Wait for the next line with prefix; returns (line, next_index)."""
    deadline = time.monotonic() + timeout
    while True:
        while index < len(reader.lines):
            line = reader.lines[index]
            index += 1
            if line.startswith(prefix):
                return line, index
        if reader.finished:
            raise EOFError(f"stream ended waiting for {prefix}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {prefix}")
        try:
            reader.updates.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            pass


def proc_birth_ticks(pid):
    """Process start_time ticks (field 22) from /proc, like the fixtures."""
    with open(f"/proc/{pid}/stat") as handle:
        text = handle.read()
    fields = text[text.rindex(")") + 2:].split()
    return int(fields[19])


def proc_exe(pid):
    return os.readlink(f"/proc/{pid}/exe")


def proc_task_states(pid):
    """{tid: state} for every thread of an owned process."""
    states = {}
    for tid in sorted(os.listdir(f"/proc/{pid}/task")):
        with open(f"/proc/{pid}/task/{tid}/stat") as handle:
            text = handle.read()
        states[int(tid)] = text[text.rindex(")") + 2:].split()[0]
    return states


def proc_provider_mapping(pid, provider_path):
    """Executable mapping of provider_path: (start, file_offset, dev, ino)."""
    with open(f"/proc/{pid}/maps") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 6 or fields[-1] != provider_path or "x" not in fields[1]:
                continue
            start = int(fields[0].split("-")[0], 16)
            offset = int(fields[2], 16)
            major, minor = (int(v, 16) for v in fields[3].split(":"))
            return start, offset, [major, minor], int(fields[4])
    raise LookupError(f"no executable mapping of {provider_path} in {pid}")


_libc = None


def symbol_file_offset(library_path, symbol):
    """File offset of an exported symbol via dlopen in this process.

    The offset is file-structural (identical for every mapping of the
    same bytes), so resolving it here instead of in the target loses
    nothing and avoids an ELF parser.
    """
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None)
        _libc.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _libc.dlopen.restype = ctypes.c_void_p
        _libc.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _libc.dlsym.restype = ctypes.c_void_p
    resolved = os.path.realpath(library_path)
    handle = _libc.dlopen(resolved.encode(), 1)  # RTLD_LAZY; kept open: one handle per file
    if not handle:
        raise LookupError(f"cannot dlopen {library_path}")
    address = _libc.dlsym(handle, symbol.encode())
    if not address:
        raise LookupError(f"no export {symbol} in {library_path}")
    start, offset, _, _ = proc_provider_mapping(os.getpid(), resolved)
    return address - start + offset


class BDriver:
    """One detailed-nonleader-exec fixture run (LP64 synthetic provider).

    Drives the byte protocol with bounded acks and records independent
    per-generation evidence (birth, exe, provider mapping, task states).
    """

    def __init__(self, owners, readers, leg_dir, before_pin, after_pin, provider_pin,
                 uid, gid, env, mode, measured=25, delay_ms=300):
        self.leg_dir = Path(leg_dir)
        self.before_pin, self.after_pin, self.provider_pin = before_pin, after_pin, provider_pin
        self.uid, self.gid, self.env = uid, gid, env
        self.mode, self.measured, self.delay_ms = mode, measured, delay_ms
        self.stamps: dict = {}
        self.lines: dict = {}
        self.tasks: dict = {}
        self.index = 0
        token = int.from_bytes(os.urandom(8), "little") | 1
        absent = self.leg_dir / "must-not-exist"
        argv = [str(before_pin.path), str(provider_pin.path), str(after_pin.path),
               str(absent), str(os.getpid()), str(token), mode, str(measured), str(delay_ms)]
        self.token = token
        self.owned = spawn_owned(
            owners, argv, uid, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env, user=uid, group=gid,
            extra_groups=[], start_new_session=True)
        self.stdout = Reader(self.owned.popen.stdout, self.leg_dir / "b.stdout.txt")
        self.stderr = Reader(self.owned.popen.stderr, self.leg_dir / "b.stderr.txt")
        readers.extend((self.stdout, self.stderr))
        self.pid = self.owned.pid
        self.birth = self.owned.identity["start_time"]

    def expect(self, prefix, timeout=10):
        line, self.index = expect_line(self.stdout, self.index, prefix, timeout)
        stamp = monotonic_ns()
        self.lines[prefix] = line.rstrip("\n")
        self.stamps[prefix] = stamp
        return line.rstrip("\n")

    def send(self, byte, name):
        self.owned.verify()
        self.owned.popen.stdin.write(byte)
        self.owned.popen.stdin.flush()
        self.stamps[name] = monotonic_ns()

    def snapshot_tasks(self, name):
        self.tasks[name] = proc_task_states(self.pid)
        return self.tasks[name]

    def ready(self):
        """READY: fixture published its table and waits; observer may attach."""
        line = self.expect("READY", timeout=10)
        fields = line.split()
        assert int(fields[1]) == self.pid and int(fields[5]) == self.token, line
        self.owned.verify()
        assert proc_exe(self.pid) == str(self.before_pin.path)
        self.exe0 = proc_exe(self.pid)
        self.maps0 = proc_provider_mapping(self.pid, str(self.provider_pin.path))
        self.start0 = proc_birth_ticks(self.pid)
        assert self.start0 == self.birth
        return line

    def start_worker(self):
        self.send("G", "G")
        thread = self.expect("THREAD", timeout=10)
        fields = thread.split()
        self.worker_tid = int(fields[2])
        assert self.worker_tid != self.pid
        if self.mode == "2":
            gone = self.expect("LEADER_EXIT", timeout=10)
            assert int(gone.split()[1]) == self.pid
            states = self.snapshot_tasks("leader_exit")
            assert states.get(self.pid) == "Z", states
            assert states.get(self.worker_tid) in ("R", "S"), states
        return thread

    def pre_exec(self):
        done = self.expect("WORKER_DONE", timeout=10)
        fields = done.split()
        assert [int(fields[3]), int(fields[4]), int(fields[5])] == [11, 6, 5], done
        assert int(fields[2]) == self.worker_tid, done
        self.expect("EXEC_BODY", timeout=10)
        self.snapshot_tasks("exec_frame")
        return done

    def do_exec(self):
        self.send("X", "X")
        if self.mode == "1":
            failed = self.expect("EXEC_FAILED", timeout=10)
            assert int(failed.split()[3]) == 2, failed  # ENOENT, exact old return
            return None
        line = self.expect("NEW_READY", timeout=10)
        fields = line.split()
        assert int(fields[1]) == self.pid and int(fields[5]) == self.token, line
        assert int(fields[1]) == int(fields[2]), line  # single thread, tid == pid
        self.owned.verify()
        assert proc_exe(self.pid) == str(self.after_pin.path)
        self.exe1 = proc_exe(self.pid)
        self.maps1 = proc_provider_mapping(self.pid, str(self.provider_pin.path))
        assert proc_birth_ticks(self.pid) == self.birth
        self.snapshot_tasks("post_exec")
        return line

    def post_exec(self):
        self.send("P", "P")
        self.expect("POST_BODY", timeout=10)
        self.send("R", "R")
        done = self.expect("NEW_DONE", timeout=60)
        fields = done.split()
        total, ok, err = int(fields[3]), int(fields[4]), int(fields[5])
        assert total == self.measured, done
        assert ok + err == total and int(fields[6]) == self.token, done
        return done

    def post_fail(self):
        self.send("R", "Rpost")
        done = self.expect("DONE", timeout=10)
        fields = done.split()
        assert [int(fields[3]), int(fields[4]), int(fields[5]), int(fields[6])] == [29, 15, 14, 5], done
        return done

    def finish(self):
        self.send("F", "F")
        rc = self.owned.popen.wait(timeout=10)
        assert rc == 0, rc
        return rc

    def b_setup_note(self):
        return {"token": self.token, "mode": self.mode, "measured": self.measured,
                "delay_ms": self.delay_ms, "tasks": self.tasks, "lines": self.lines,
                "stamps": self.stamps}

    def normalize(self, file_offset):
        """Translate receipts to N3LEDGER-schema records."""
        pre_rvs = [0 if i % 2 == 0 else 5 for i in range(11)]
        ledger = [
            {"kind": "image", "image": 0, "pid": self.pid, "start_time": self.birth,
             "path": self.exe0, "dev": self.before_pin.initial.st_dev,
             "ino": self.before_pin.initial.st_ino,
             "mtime_ns": self.before_pin.initial.st_mtime_ns,
             "pid_namespace": self.owned.identity["pid_namespace"],
             "time_namespace": self.owned.identity["time_namespace"],
             "t": self.stamps["READY"]},
            {"kind": "target", "image": 0, "fn": "C_Initialize",
             "dev": self.maps0[2], "ino": self.maps0[3], "file_offset": file_offset,
             "vaddr": self.maps0[0] + (file_offset - self.maps0[1])},
        ]
        for seq, rv in enumerate(pre_rvs):
            ledger.append({"kind": "call", "image": 0, "pid": self.pid, "tid": self.worker_tid,
                           "fn": "C_Initialize", "rv": rv, "phase": "pre", "scope": "selected",
                           "sess": 0, "t0": self.stamps["G"], "t1": self.stamps["WORKER_DONE"],
                           "seq": seq})
        failed = self.mode == "1"
        if failed:
            post_rvs = [5] + [0 if i % 2 == 0 else 5 for i in range(17)]
            for seq, rv in enumerate(post_rvs):
                ledger.append({"kind": "call", "image": 0, "pid": self.pid,
                               "tid": self.worker_tid, "fn": "C_Initialize", "rv": rv,
                               "phase": "post", "scope": "selected", "sess": 0,
                               "t0": self.stamps["Rpost"], "t1": self.stamps["DONE"],
                               "seq": 11 + seq})
        else:
            ledger.append({"kind": "exec", "image": 0, "pid": self.pid, "tid": self.worker_tid,
                           "start_time": self.birth, "mode": "nonleader",
                           "path": self.exe1, "scope": "selected", "t": self.stamps["EXEC_BODY"]})
            ledger.append({"kind": "image", "image": 1, "pid": self.pid, "start_time": self.birth,
                           "path": self.exe1, "dev": self.after_pin.initial.st_dev,
                           "ino": self.after_pin.initial.st_ino,
                           "mtime_ns": self.after_pin.initial.st_mtime_ns,
                           "pid_namespace": self.owned.identity["pid_namespace"],
                           "time_namespace": self.owned.identity["time_namespace"],
                           "t": self.stamps["NEW_READY"]})
            ledger.append({"kind": "target", "image": 1, "fn": "C_Initialize",
                           "dev": self.maps1[2], "ino": self.maps1[3], "file_offset": file_offset,
                           "vaddr": self.maps1[0] + (file_offset - self.maps1[1])})
            post_rvs = [0] + [5 if i % 2 == 1 else 0 for i in range(1, self.measured)]
            for seq, rv in enumerate(post_rvs):
                ledger.append({"kind": "call", "image": 1, "pid": self.pid, "tid": self.pid,
                               "fn": "C_Initialize", "rv": rv, "phase": "post",
                               "scope": "selected", "sess": 0,
                               "t0": self.stamps["R"], "t1": self.stamps["NEW_DONE"],
                               "seq": seq})
            ledger.append({"kind": "ack", "image": 0, "phase": "pre", "t": self.stamps["WORKER_DONE"]})
            ledger.append({"kind": "ack", "image": 1, "phase": "post", "t": self.stamps["NEW_DONE"]})
        return ledger


class BackendRefused(Exception):
    """The observer refused the requested backend (negative, not recovery)."""


class SetupError(Exception):
    """The harness could not establish the cell's preconditions."""


B_CFLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
            "-fno-stack-protector", "-fno-omit-frame-pointer"]
CALLER_CFLAGS = ["-O2", "-Wall", "-Wextra", "-Werror"]
LEDGER_CFLAGS = ["-O1", "-Wall", "-Wextra", "-Werror"]


def compile_case_fixtures(bin_dir):
    """Compile every H6 workload from repo fixtures into the case bin dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    sources = {"exec": ROOT / "tests/fixtures/detailed-nonleader-exec.c",
               "caller": ROOT / "tests/fixtures/cgroup-trace/caller.c",
               "ledger": ROOT / "tests/fixtures/public-cli/inventory-ledger.c"}
    for name, source in sources.items():
        assert source.is_file(), source
    jobs = [
        (["cc", *B_CFLAGS, "-fPIC", "-shared", "-DDETAILED_EXEC_PROVIDER",
          str(sources["exec"]), "-ldl", "-o", str(bin_dir / "provider.so")], "provider.so"),
        (["cc", *B_CFLAGS, str(sources["exec"]), "-ldl", "-o", str(bin_dir / "before")], "before"),
        (["cc", *B_CFLAGS, "-DDETAILED_EXEC_AFTER", str(sources["exec"]), "-ldl",
          "-o", str(bin_dir / "after")], "after"),
        (["cc", *CALLER_CFLAGS, str(sources["caller"]), "-ldl", "-lpthread",
          "-o", str(bin_dir / "caller")], "caller"),
        (["cc", *LEDGER_CFLAGS, str(sources["ledger"]), "-ldl", "-lpthread",
          "-o", str(bin_dir / "ledger")], "ledger"),
    ]
    for argv, name in jobs:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise SetupError(f"fixture build failed for {name}: {proc.stderr[-2000:]}")
    for name in ("provider.so", "before", "after", "caller", "ledger"):
        (bin_dir / name).chmod(0o755)
    return {name: FilePin(bin_dir / name)
            for name in ("provider.so", "before", "after", "caller", "ledger")}


def init_token(workload_dir, uid, gid, label):
    """Create an owned SoftHSM token dir; returns the workload env."""
    workload_dir = Path(workload_dir)
    tokens = workload_dir / "tokens"
    tokens.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(workload_dir, uid, gid)
    os.chown(tokens, uid, gid)
    config = workload_dir / "softhsm2.conf"
    config.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\n"
                      "log.level = ERROR\n")
    config.chmod(0o644)
    env = dict(os.environ, SOFTHSM2_CONF=str(config))
    proc = subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", label,
         "--so-pin", "5678", "--pin", "1234"],
        env=env, user=uid, group=gid, extra_groups=[], text=True,
        capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise SetupError(f"token init failed: {proc.stderr[-1000:]}")
    return env


def build_manifest(discover_pin, module_path, out_path, env, uid, gid):
    """Run p11scope-discover as the workload user (executes provider code)."""
    discover_pin.verify()
    out_path = Path(out_path)
    if out_path.exists():
        raise SetupError(f"manifest path already exists: {out_path}")
    proc = subprocess.run(
        [str(discover_pin.path), "--module", str(module_path), "-o", str(out_path)],
        env=env, user=uid, group=gid, extra_groups=[], text=True,
        capture_output=True, timeout=180)
    if proc.returncode != 0 or not out_path.is_file():
        raise SetupError(f"manifest build failed: {proc.stderr[-1000:]}")
    manifest = json.loads(out_path.read_text())
    if manifest.get("schema") != "p11scope-manifest/5":
        raise SetupError(f"manifest schema is not p11scope-manifest/5: "
                         f"{manifest.get('schema')!r}")
    if not manifest.get("objects"):
        raise SetupError("manifest attests no module")
    return manifest


def spawn_observer(owners, readers, leg_dir, argv, env):
    """Spawn an observer; returns (owned, capture, errors, started_ns)."""
    started = monotonic_ns()
    owned = spawn_owned(owners, argv, 0, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, env=env, start_new_session=True)
    capture = Reader(owned.popen.stdout, Path(leg_dir) / "observer.stdout.txt")
    errors = Reader(owned.popen.stderr, Path(leg_dir) / "observer.stderr.txt")
    readers.extend((capture, errors))
    return owned, capture, errors, started


REFUSAL_MARKERS = re.compile(
    r"refus|not supported|unsupported|requires .* kernel|EOPNOTSUPP|ENOSYS|"
    r"backend .* unavailable|no .* backend", re.IGNORECASE)


def observer_ready(owned, errors, backend, timeout=20):
    """Wait for capturing; raises BackendRefused or SetupError."""
    try:
        wait_capture_started(errors, seconds=timeout)
        return monotonic_ns()
    except (TimeoutError, ValueError):
        pass
    rc = owned.popen.poll()
    tail = "".join(errors.lines[-20:])
    if rc is not None and rc != 0 and REFUSAL_MARKERS.search(tail):
        raise BackendRefused(f"{backend}: {tail.strip()[-500:]}")
    raise SetupError(f"observer never reached capturing (rc={rc}): {tail[-1000:]}")


def stop_observer(owned, limit_seconds=90):
    """SIGINT stop; returns (rc, stopped_ns, latency_seconds).

    Detach runs ~15 links/s on this host (139 links after a SoftHSM
    attach), so a clean stop takes 9-15 s; the kill fallback stays as
    the finite backstop.
    """
    begin = monotonic_ns()
    owned.send(signal.SIGINT)
    try:
        rc = owned.popen.wait(timeout=limit_seconds + 5)
    except subprocess.TimeoutExpired:
        owned.popen.kill()
        rc = owned.popen.wait(timeout=5)
    stopped = monotonic_ns()
    return rc, stopped, (stopped - begin) / 1e9


def spawn_caller(owners, readers, leg_dir, caller_pin, provider_pin, uid, gid, env,
                 tag="caller", prefix=()):
    """Spawn the interactive SoftHSM caller; returns (owned, stdout, stderr)."""
    owned = spawn_owned(
        owners, [*prefix, str(caller_pin.path), str(provider_pin.path), "0", "selected",
                 "--canary", CANARIES[2]], uid,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env, user=uid, group=gid, extra_groups=[],
        start_new_session=True)
    stdout = Reader(owned.popen.stdout, Path(leg_dir) / f"{tag}.ledger.jsonl")
    stderr = Reader(owned.popen.stderr, Path(leg_dir) / f"{tag}.stderr.txt")
    readers.extend((stdout, stderr))
    return owned, stdout, stderr


def caller_exec(caller, stdout, images, method, target_pin):
    """Drive one caller exec/thread-exec; returns (request, receipt, t0, t1)."""
    if method not in ("exec", "thread-exec"):
        raise SetupError(f"unknown exec method {method}")
    caller.verify()
    t0 = monotonic_ns()
    caller.popen.stdin.write(f"{method} {target_pin.path}\n")
    caller.popen.stdin.flush()
    image_index = len(images)
    stdout.record("ready", image_index)
    record = stdout.record("image", image_index)
    receipt = target_pin.image_receipt(record, caller)
    images.append(receipt)
    # The exec record carries the FROM image; the default image=0 would
    # return the first transition's record forever on multi-exec chains.
    request = stdout.record("exec", image_index - 1)
    want_mode = "leader" if method == "exec" else "nonleader"
    if request["path"] != str(target_pin.path) or request["mode"] != want_mode:
        raise SetupError(f"exec record disagrees with the driven transition: "
                         f"{request.get('path')} {request.get('mode')}")
    return request, receipt, t0, monotonic_ns()


def stop_caller(caller, stdout, image, timeout=10):
    caller.verify()
    caller.popen.stdin.write("stop\n")
    caller.popen.stdin.flush()
    stdout.record("ack", image, "done", seconds=timeout)
    return caller.popen.wait(timeout=timeout)


def spawn_ledger(owners, readers, leg_dir, argv, env, uid, gid, tag):
    """Spawn an inventory-ledger cell; returns (owned, stdout, stderr)."""
    owned = spawn_owned(
        owners, argv, uid, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env, user=uid, group=gid,
        extra_groups=[], start_new_session=True)
    stdout = Reader(owned.popen.stdout, Path(leg_dir) / f"{tag}.out")
    stderr = Reader(owned.popen.stderr, Path(leg_dir) / f"{tag}.err")
    readers.extend((stdout, stderr))
    return owned, stdout, stderr


def wait_usage_armed(jsonl_path, wants, timeout=90):
    """Wait until every wanted (pid, exe, modules) edge reads armed/counted.

    wants: list of (pid, exe_path, module_count). Matches caller ids via
    admitted caller_event identity, then edge_observed coverage states.
    Returns the arming evidence; raises SetupError on timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = Path(jsonl_path).read_text()
        except FileNotFoundError:
            text = ""
        ids: dict = {}
        for line in text.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("kind") != "caller_event":
                continue
            event = record.get("event", {})
            if event.get("event") != "admitted":
                continue
            caller = ((event.get("identity_context") or {}).get("caller") or {})
            for pid, exe, _ in wants:
                if caller.get("pid") == pid and (
                        caller.get("executable") or {}).get("path") == exe:
                    ids.setdefault((pid, exe), set()).add(event.get("caller"))
        armed: dict = {}
        for line in text.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("kind") != "edge_observed":
                continue
            event = record.get("event", {})
            coverage = (event.get("entries") or {}).get("coverage", {}) or {}
            if coverage.get("state") not in ("watched_no_use", "counted"):
                continue
            for pid, exe, _ in wants:
                if event.get("caller") in ids.get((pid, exe), set()):
                    armed.setdefault((pid, exe), set()).add(event.get("module"))
        missing = [(pid, exe) for pid, exe, count in wants
                   if len(armed.get((pid, exe), set())) < count]
        if not missing:
            return {f"{pid} {exe}": sorted(modules) for (pid, exe), modules in armed.items()}
        if time.monotonic() >= deadline:
            raise SetupError(f"usage never armed for {missing}")
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# H6 harness: cells
# ---------------------------------------------------------------------------

PIN_FD = runpy.run_path(str(ROOT / "scripts/mapped-provider-pin.py"))["pin_fd"]


def provider_receipt(pin):
    pin.verify()
    return dict(PIN_FD(pin.fd), path=str(pin.path))


def session_reuse_from(ledger):
    by_image = {}
    for row in ledger:
        if row.get("kind") == "call" and row.get("fn") == "C_OpenSession" \
                and row.get("phase") == "setup":
            by_image[row["image"]] = row.get("sess", 0)
    gens = sorted(by_image)
    if len(gens) < 2:
        return {"observed": False, "gens": gens}
    pre, post = by_image[gens[0]], by_image[gens[-1]]
    return {"observed": bool(pre and pre == post), "pre": pre, "post": post,
            "gens": gens, "all": [by_image[gen] for gen in gens]}


def va_reuse_from(ledger):
    by_image_fn = {}
    for row in ledger:
        if row.get("kind") == "target" and "vaddr" in row:
            by_image_fn.setdefault(row["image"], {})[row["fn"]] = row["vaddr"]
    gens = sorted(by_image_fn)
    matches = []
    for index in range(1, len(gens)):
        before, after = by_image_fn[gens[index - 1]], by_image_fn[gens[index]]
        for fn in set(before) & set(after):
            if before[fn] == after[fn]:
                matches.append({"fn": fn, "from": gens[index - 1], "to": gens[index],
                                "vaddr": before[fn]})
    return {"observed": bool(matches), "matches": matches}


class Case:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out)
        self.owners: list = []
        self.readers: list = []
        self.groups: list = []
        self.results: dict = {}
        self.scope_created_ns = monotonic_ns()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")


def finish_readers(readers):
    for reader in readers:
        reader.finish()


def run_pid_caller_leg(ctx, cell, backend, observer_kind, leg_dir, same_path, prefix=()):
    """One pid-scope caller leg: warm, exec, measured, stop, judge."""
    leg_dir = Path(leg_dir)
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, f"h6-{cell}")
    image_a = leg_dir / "caller-a"
    shutil.copyfile(ctx.pins["caller"].path, image_a)
    image_a.chmod(0o755)
    pin_a = FilePin(image_a)
    if same_path:
        pin_b, image_b = pin_a, image_a
    else:
        image_b = leg_dir / "caller-b"
        shutil.copyfile(ctx.pins["caller"].path, image_b)
        image_b.chmod(0o755)
        pin_b = FilePin(image_b)
    provider = ctx.provider_pin
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pin_a, provider,
                                     ctx.args.uid, ctx.args.gid, env, prefix=prefix)
    stdout.record("ready", 0)
    images = [pin_a.image_receipt(stdout.record("image", 0), caller)]
    scope_args = ["--pid", str(caller.pid)]
    module_args = ["--module", str(provider.path)]
    backend_args = ["--attach-backend", backend]
    if observer_kind == "trace":
        argv = [str(ctx.binary.path), "trace", *scope_args, *module_args, *backend_args,
               "--duration", "120s", "-o", str(leg_dir / "trace.file.txt")]
    else:
        mode = "metrics" if observer_kind == "metrics" else "profile"
        argv = [str(ctx.binary.path), "profile", *scope_args, *module_args,
               "--mode", mode, *backend_args, "--duration", "120s",
               "-o", str(leg_dir / f"{observer_kind}.json")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": cell, "leg": f"{observer_kind}/{backend}",
                   "backend_refused": str(refused)}
        result = (evaluate_trace_h6("", [], receipt) if observer_kind == "trace"
                  else evaluate_profile_h6({}, "", [], receipt))
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 3, 100, "warm", "selected",
               0, None, phases)
    request, _, t0, t1 = caller_exec(caller, stdout, images, "exec", pin_b)
    transitions = [{"from_image": 0, "to_image": 1, "mode": "leader",
                    "same_path": bool(same_path), "t0": t0, "t1": t1, "request": request}]
    n3_command(caller, stdout, "C_GetSessionInfo", 10, 200, "measured", "selected",
               1, None, phases)
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = stop_caller(caller, stdout, 1)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = next(p for p in phases if p["phase"] == "measured")
    warmup = next(p for p in phases if p["phase"] == "warm")
    receipt = {
        "cell": cell, "leg": f"{observer_kind}/{backend}", "scope_kind": "pid",
        "pid": caller.pid, "known_tids": [caller.pid], "owned_pids": [caller.pid],
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "stable", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 10, "phases": ["measured"]},
        "warmup": {"label": "pre", "t0": warmup["t0"], "t1": warmup["t1"],
                   "expected_calls": 3, "phases": ["warm"]},
        "exec_transitions": transitions, "phases": phases,
        "require_named": True, "require_named_images": [1], "first_unknown_images": [1],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {"session": True, "va": bool(same_path)},
        "session_reuse": session_reuse_from(ledger), "va_reuse": va_reuse_from(ledger),
        "requested_backend": backend,
    }
    if observer_kind == "trace":
        trace = "".join(capture.lines)
        file_trace = (leg_dir / "trace.file.txt").read_text()
        result = evaluate_trace_h6(trace, ledger, receipt, file_trace)
    elif observer_kind == "profile":
        doc = json.loads((leg_dir / "profile.json").read_text())
        result = evaluate_profile_h6(doc, "".join(capture.lines), ledger, receipt)
    else:
        doc = json.loads((leg_dir / "metrics.json").read_text())
        result = evaluate_metrics_h6(doc, "".join(capture.lines), ledger, receipt)
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_pid_leader(ctx, cell_dir, backend):
    return [run_pid_caller_leg(ctx, "pid-leader", backend, kind,
                               Path(cell_dir) / backend / kind, same_path=False)
            for kind in ("trace", "profile", "metrics")]


def run_pid_reexec(ctx, cell_dir, backend):
    if not shutil.which("setarch"):
        raise SetupError("setarch is required for the VA-reuse reexec leg")
    return [run_pid_caller_leg(ctx, "pid-reexec", backend, kind,
                               Path(cell_dir) / backend / kind, same_path=True,
                               prefix=("setarch", "-R"))
            for kind in ("trace", "profile", "metrics")]


def run_b_leg(ctx, cell, backend, observer_kind, leg_dir, mode, measured=25, delay_ms=300):
    """One workload-B leg: cold/failed/leader-exit exec under an observer."""
    leg_dir = Path(leg_dir)
    leg_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    env = dict(os.environ)
    driver = BDriver(ctx.owners, ctx.readers, leg_dir, ctx.pins["before"],
                     ctx.pins["after"], ctx.pins["provider.so"],
                     ctx.args.uid, ctx.args.gid, env, mode, measured, delay_ms)
    driver.ready()
    provider = ctx.pins["provider.so"]
    scope_args = ["--pid", str(driver.pid)]
    module_args = ["--module", str(provider.path)]
    backend_args = ["--attach-backend", backend]
    if observer_kind == "trace":
        argv = [str(ctx.binary.path), "trace", *scope_args, *module_args, *backend_args,
               "--duration", "180s", "-o", str(leg_dir / "trace.file.txt")]
    else:
        agg = "metrics" if observer_kind == "metrics" else "profile"
        argv = [str(ctx.binary.path), "profile", *scope_args, *module_args,
               "--mode", agg, *backend_args, "--duration", "180s",
               "-o", str(leg_dir / f"{observer_kind}.json")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        driver.owned.popen.kill()
        driver.owned.popen.wait(timeout=5)
        receipt = {"cell": cell, "leg": f"{observer_kind}/{backend}",
                   "backend_refused": str(refused)}
        result = (evaluate_trace_h6("", [], receipt) if observer_kind == "trace"
                  else evaluate_profile_h6({}, "", [], receipt))
        write_json(leg_dir / "result.json", result)
        return result
    driver.start_worker()
    driver.pre_exec()
    driver.do_exec()
    failed = mode == "1"
    if failed:
        driver.post_fail()
    else:
        driver.post_exec()
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = driver.finish()
    finish_readers([driver.stdout, driver.stderr, capture, errors])
    ledger = driver.normalize(ctx.b_file_offset)
    pre_phase = {"image": 0, "fn": "C_Initialize", "phase": "pre", "scope": "selected",
                 "count": 11, "t0": driver.stamps["G"], "t1": driver.stamps["WORKER_DONE"]}
    if failed:
        post_phase = {"image": 0, "fn": "C_Initialize", "phase": "post", "scope": "selected",
                      "count": 18, "t0": driver.stamps["Rpost"], "t1": driver.stamps["DONE"]}
        images = [{"kind": "image", "image": 0, "pid": driver.pid, "start_time": driver.birth,
                   "path": driver.exe0, "dev": ctx.pins["before"].initial.st_dev,
                   "ino": ctx.pins["before"].initial.st_ino,
                   "mtime_ns": ctx.pins["before"].initial.st_mtime_ns,
                   "pid_namespace": driver.owned.identity["pid_namespace"],
                   "time_namespace": driver.owned.identity["time_namespace"]}]
        transitions = []
        require_named_images: list = []
        require_named = False
        abandoned = 0
    else:
        post_phase = {"image": 1, "fn": "C_Initialize", "phase": "post", "scope": "selected",
                      "count": measured, "t0": driver.stamps["R"], "t1": driver.stamps["NEW_DONE"]}
        images = [
            {"kind": "image", "image": 0, "pid": driver.pid, "start_time": driver.birth,
             "path": driver.exe0, "dev": ctx.pins["before"].initial.st_dev,
             "ino": ctx.pins["before"].initial.st_ino,
             "mtime_ns": ctx.pins["before"].initial.st_mtime_ns,
             "pid_namespace": driver.owned.identity["pid_namespace"],
             "time_namespace": driver.owned.identity["time_namespace"]},
            {"kind": "image", "image": 1, "pid": driver.pid, "start_time": driver.birth,
             "path": driver.exe1, "dev": ctx.pins["after"].initial.st_dev,
             "ino": ctx.pins["after"].initial.st_ino,
             "mtime_ns": ctx.pins["after"].initial.st_mtime_ns,
             "pid_namespace": driver.owned.identity["pid_namespace"],
             "time_namespace": driver.owned.identity["time_namespace"]},
        ]
        request = next(row for row in ledger if row["kind"] == "exec")
        transitions = [{"from_image": 0, "to_image": 1, "mode": "nonleader",
                        "same_path": False, "t0": driver.stamps["EXEC_BODY"],
                        "t1": driver.stamps["NEW_READY"], "request": request}]
        require_named_images = [1]
        require_named = True
        abandoned = 1
    receipt = {
        "cell": cell, "leg": f"{observer_kind}/{backend}", "scope_kind": "pid",
        "pid": driver.pid, "known_tids": [driver.pid, driver.worker_tid],
        "owned_pids": [driver.pid], "images": images,
        "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": driver.owned.identity["pid_namespace"],
        "time_namespace": driver.owned.identity["time_namespace"],
        "measured": {"label": "stable", "t0": post_phase["t0"], "t1": post_phase["t1"],
                     "expected_calls": post_phase["count"], "phases": ["post"]},
        "warmup": {"label": "pre", "t0": pre_phase["t0"], "t1": pre_phase["t1"],
                   "expected_calls": 11, "phases": ["pre"]},
        "exec_transitions": transitions, "phases": [pre_phase, post_phase],
        "require_named": require_named, "require_named_images": require_named_images,
        "first_unknown_images": [],
        "manual_rebind": False, "abandoned_expected": abandoned,
        "abandoned_by_fn": {"C_Initialize": abandoned} if abandoned else {},
        "reuse_expected": {"token": True},
        "token_reuse": {"observed": True, "token": driver.token},
        "requested_backend": backend, "b_setup": driver.b_setup_note(),
    }
    if observer_kind == "trace":
        result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                                   (leg_dir / "trace.file.txt").read_text())
    elif observer_kind == "profile":
        doc = json.loads((leg_dir / "profile.json").read_text())
        result = evaluate_profile_h6(doc, "".join(capture.lines), ledger, receipt)
    else:
        doc = json.loads((leg_dir / "metrics.json").read_text())
        result = evaluate_metrics_h6(doc, "".join(capture.lines), ledger, receipt)
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_pid_nonleader_cold(ctx, cell_dir, backend):
    return [run_b_leg(ctx, "pid-nonleader-cold", backend, kind,
                      Path(cell_dir) / backend / kind, "0")
            for kind in ("trace", "profile", "metrics")]


def run_pid_failed_exec(ctx, cell_dir, backend):
    return [run_b_leg(ctx, "pid-failed-exec", backend, "trace",
                      Path(cell_dir) / backend / "trace", "1")]


def run_leader_exit_exec(ctx, cell_dir, backend):
    leg_dir = Path(cell_dir) / backend / "trace"
    result = run_b_leg(ctx, "leader-exit-exec", backend, "trace", leg_dir, "2")
    # Explicit capability sub-result: zombie-leader/live-worker pre-exec
    # activity is demonstrated iff the pre-exec phase was captured; it is
    # never counted toward the post-exec positive.
    receipt = json.loads((leg_dir / "receipt.json").read_text())
    pre = (result.get("phase_populations", {}).get("pre", {}))
    captured = (pre.get("named", 0) + pre.get("unknown", 0)) if isinstance(pre, dict) else 0
    capability = {"cell": "leader-exit-exec", "leg": f"capability-preexec/{backend}",
                  "status": "demonstrated" if captured > 0 else "limitation",
                  "pass": None, "pre_exec_captured": captured,
                  "pre_exec_ledgered": 11,
                  "task_states": receipt.get("b_setup", {}).get("tasks", {}),
                  "note": ("zombie-leader/live-worker pre-exec activity; "
                           "never counted toward the post-exec positive")}
    write_json(leg_dir / "capability.json", capability)
    return [result, capability]


def run_rapid_chain(ctx, cell_dir, backend):
    """Bounded 3-exec leader chain (A->B->A->B) plus reuse and group-death legs."""
    leg_dir = Path(cell_dir) / backend / "trace"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-rapid")
    pins = {}
    for name in ("caller-a", "caller-b"):
        path = leg_dir / name
        shutil.copyfile(ctx.pins["caller"].path, path)
        path.chmod(0o755)
        pins[name] = FilePin(path)
    provider = ctx.provider_pin
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pins["caller-a"],
                                     provider, ctx.args.uid, ctx.args.gid, env)
    stdout.record("ready", 0)
    images = [pins["caller-a"].image_receipt(stdout.record("image", 0), caller)]
    argv = [str(ctx.binary.path), "trace", "--pid", str(caller.pid),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "180s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "rapid-chain", "leg": f"trace/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return [result]
    phases = []
    # Same function in every generation: order-matched attribution.
    n3_command(caller, stdout, "C_GenerateRandom", 2, 50, "warm", "selected",
               0, None, phases)
    order = [("caller-b", 1, "gen1"), ("caller-a", 2, "gen2"), ("caller-b", 3, "measured")]
    transitions = []
    for name, image, phase in order:
        request, _, t0, t1 = caller_exec(caller, stdout, images, "exec", pins[name])
        transitions.append({"from_image": image - 1, "to_image": image, "mode": "leader",
                            "same_path": False, "t0": t0, "t1": t1, "request": request})
        count = 10 if phase == "measured" else 2
        delay = 200 if phase == "measured" else 50
        n3_command(caller, stdout, "C_GenerateRandom", count, delay, phase, "selected",
                   image, None, phases)
    obs_rc, stopped, latency = stop_observer(owned)
    dead_pid = caller.pid
    caller_rc = stop_caller(caller, stdout, 3)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = next(p for p in phases if p["phase"] == "measured")
    warmup = next(p for p in phases if p["phase"] == "warm")
    receipt = {
        "cell": "rapid-chain", "leg": f"trace/{backend}", "scope_kind": "pid",
        "pid": dead_pid, "known_tids": [dead_pid], "owned_pids": [dead_pid],
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "stable", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 10, "phases": ["measured"]},
        "warmup": {"label": "pre", "t0": warmup["t0"], "t1": warmup["t1"],
                   "expected_calls": 2, "phases": ["warm"]},
        "exec_transitions": transitions, "phases": phases,
        "require_named": True, "require_named_images": [3],
        "first_unknown_images": [1, 2, 3],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {"session": True},
        "session_reuse": session_reuse_from(ledger),
        "requested_backend": backend,
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    control = run_reuse_control(ctx, Path(cell_dir) / backend / "reuse", backend, env,
                                dead_pid, pins["caller-a"])
    death = run_group_death_leg(ctx, Path(cell_dir) / backend / "group-death",
                                backend, env, pins["caller-a"])
    return [result, control, death]


def run_reuse_control(ctx, leg_dir, backend, env, dead_pid, image_pin):
    """Fresh same-image host under --system: independent admission, no history."""
    leg_dir = Path(leg_dir)
    leg_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    provider = ctx.provider_pin
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, image_pin,
                                     provider, ctx.args.uid, ctx.args.gid, env,
                                     tag="host")
    stdout.record("ready", 0)
    images = [image_pin.image_receipt(stdout.record("image", 0), caller)]
    assert caller.pid != dead_pid
    argv = [str(ctx.binary.path), "trace", "--system",
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "120s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "rapid-chain", "leg": f"reuse/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 5, 100, "measured", "selected",
               0, None, phases)
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = stop_caller(caller, stdout, 0)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = phases[0]
    receipt = {
        "cell": "rapid-chain", "leg": f"reuse/{backend}", "scope_kind": "system",
        "owned_pids": [caller.pid], "dead_pid": dead_pid,
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "host", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 5, "phases": ["measured"]},
        "warmup": {"label": "none", "t0": measured["t0"], "t1": measured["t0"],
                   "expected_calls": 0, "phases": []},
        "exec_transitions": [], "phases": phases,
        "require_named": True, "require_named_images": [0], "first_unknown_images": [],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {}, "requested_backend": backend,
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


GROUP_DEATH_DWELL_NS = 3_000_000_000
GROUP_DEATH_MIN_DWELL_NS = 2_000_000_000


def run_group_death_leg(ctx, leg_dir, backend, env, image_pin):
    """Whole-group death ends --pid capture: no post-death rows.

    Brief line 101, death half: drive a nonempty named pre-death phase
    under --pid, SIGKILL the entire owned process group at once, prove
    death via waitpid plus /proc disappearance, keep the observer up
    through a bounded post-death dwell, then require the capture to
    hold only pre-death rows. Numeric PID reuse is never manufactured
    (no sysctl); the real independently admitted replacement is the
    sibling reuse leg, named in the receipt.
    """
    leg_dir = Path(leg_dir)
    leg_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    provider = ctx.provider_pin
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, image_pin,
                                     provider, ctx.args.uid, ctx.args.gid, env,
                                     tag="doomed")
    stdout.record("ready", 0)
    images = [image_pin.image_receipt(stdout.record("image", 0), caller)]
    argv = [str(ctx.binary.path), "trace", "--pid", str(caller.pid),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "120s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "rapid-chain", "leg": f"group-death/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 5, 100, "measured", "selected",
               0, None, phases)
    # Whole-group kill: the caller is an owned session/group leader, so
    # killpg reaches every thread at once; nothing survives to keep the
    # PID capture alive. Liveness before and death after are proven by
    # the harness (pidfd identity, waitpid, /proc), never by p11scope.
    caller.verify()
    group_size_before = len(list((Path("/proc") / str(caller.pid) / "task").iterdir()))
    dead_pid = caller.pid
    kill_ns = monotonic_ns()
    os.killpg(caller.pid, signal.SIGKILL)
    caller_rc = caller.popen.wait(timeout=10)
    proc_gone = not (Path("/proc") / str(dead_pid)).exists()
    death_ns = monotonic_ns()
    deadline = death_ns + GROUP_DEATH_DWELL_NS
    while monotonic_ns() < deadline:
        time.sleep(0.05)
    dwell_end = monotonic_ns()
    if owned.popen.poll() is None:
        observer_self_ended = False
        obs_rc, stopped, latency = stop_observer(owned)
    else:
        # The observer ended capture by itself after the group death.
        observer_self_ended = True
        obs_rc, stopped, latency = owned.popen.poll(), dwell_end, 0.0
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = phases[0]
    receipt = {
        "cell": "rapid-chain", "leg": f"group-death/{backend}", "scope_kind": "pid",
        "pid": dead_pid, "known_tids": [dead_pid], "owned_pids": [dead_pid],
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "pre-death", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 5, "phases": ["measured"]},
        "warmup": {"label": "none", "t0": measured["t0"], "t1": measured["t0"],
                   "expected_calls": 0, "phases": []},
        "exec_transitions": [], "phases": phases,
        "require_named": True, "require_named_images": [0], "first_unknown_images": [],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {}, "requested_backend": backend,
        "group_death": {
            "kill": "SIGKILL/killpg", "group_size_before": group_size_before,
            "kill_ns": kill_ns, "death_ns": death_ns,
            "reaped": caller.popen.returncode is not None, "proc_gone": proc_gone,
            "manufactured_reuse": False, "replacement_leg": f"reuse/{backend}",
            "min_dwell_ns": GROUP_DEATH_MIN_DWELL_NS,
            "observer_self_ended": observer_self_ended,
        },
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_cgroup_r2(ctx, cell_dir, backend):
    """Observed-dir replacement: the new dir is not silently re-admitted."""
    leg_dir = Path(cell_dir) / backend / "replacement"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-r2")
    image = leg_dir / "caller-a"
    shutil.copyfile(ctx.pins["caller"].path, image)
    image.chmod(0o755)
    pin = FilePin(image)
    provider = ctx.provider_pin
    root, _ = create_tracked(ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-{uuid.uuid4().hex[:8]}")
    selected, selected_w = create_tracked(ctx, root.path / "selected")
    outside, _ = create_tracked(ctx, root.path / "outside")
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pin,
                                     provider, ctx.args.uid, ctx.args.gid, env)
    stdout.record("ready", 0)
    images = [pin.image_receipt(stdout.record("image", 0), caller)]
    moves = []
    move_and_verify(selected, caller, moves, "initial")
    argv = [str(ctx.binary.path), "trace", "--cgroup", str(selected.path),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "180s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "cgroup-reentry", "leg": f"replacement/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 3, 100, "warm", "selected",
               0, selected, phases)
    t_out = monotonic_ns()
    move_and_verify(outside, caller, moves, "exit-for-replacement")
    old_ino = selected.path.stat().st_ino
    os.rmdir(selected.path)
    os.mkdir(selected.path, 0o755)
    new_ino = selected.path.stat().st_ino
    assert new_ino != old_ino
    moves.append({"t": monotonic_ns(), "cgroup": str(selected.path),
                  "note": f"replaced old-ino={old_ino} new-ino={new_ino}"})
    # The stale wrapper tracks the removed dir; move into the new dir by
    # raw path (same string, new inode) and verify membership manually.
    caller.verify()
    with open(selected.path / "cgroup.procs", "w") as handle:
        handle.write(f"{caller.pid}\n")
    actual = cgroup_of(caller.pid)
    assert actual == "/" + str(selected.path.relative_to("/sys/fs/cgroup")), actual
    moves.append({"t": monotonic_ns(), "cgroup": actual, "note": "replacement-entry"})
    n3_command(caller, stdout, "C_GenerateRandom", 3, 100, "replaced", "selected",
               0, None, phases)
    assert cgroup_of(caller.pid) == actual
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = stop_caller(caller, stdout, 0)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    # Explicit replacement-dir cleanup (the stale wrapper cannot remove it).
    procs = (selected.path / "cgroup.procs").read_text().split()
    assert not procs, procs
    os.rmdir(selected.path)
    selected_w.group.close()
    os.close(selected_w.parent_fd)
    ctx.groups.remove(selected_w)
    moves.append({"t": monotonic_ns(), "cgroup": str(selected.path), "note": "replaced-removed"})
    warmup = next(p for p in phases if p["phase"] == "warm")
    receipt = {
        "cell": "cgroup-reentry", "leg": f"replacement/{backend}", "scope_kind": "cgroup",
        "owned_pids": [caller.pid],
        "scope_intervals": [
            {"pid": caller.pid, "membership": "selected", "t0": ready, "t1": t_out},
        ],
        "moves": moves, "replacement": {"old_ino": old_ino, "new_ino": new_ino},
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "pre-replacement stable", "t0": warmup["t0"], "t1": warmup["t1"],
                     "expected_calls": 3, "phases": ["warm"]},
        "warmup": {"label": "none", "t0": warmup["t0"], "t1": warmup["t0"],
                   "expected_calls": 0, "phases": []},
        "exec_transitions": [], "phases": phases,
        "require_named": False, "require_named_images": [], "first_unknown_images": [],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {}, "requested_backend": backend,
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


# ---------------------------------------------------------------------------
# H6 harness: exec-freeze (ptrace) until successor admission is observed
# ---------------------------------------------------------------------------
#
# Inventory rule R-C51-1 (documented product behavior): a usage row recorded
# before its caller's admission never binds, so a successor generation whose
# first call precedes the post-exec admission pass reads
# unknown/use_before_admission forever — never a positive. Exact
# ledger-matched successor counts therefore require every successor call to
# post-date the admission the observer itself publishes in its event log.
# The harness freezes the owned successor at exec (PTRACE_O_TRACEEXEC stops
# it before its first user instruction) and resumes it only after the
# public caller_event/admitted record for the new image is observed. This
# is harness-side scheduling of an owned process: it never touches
# observer links or BPF state, and the ledger's t0/t1 stay truthful.

_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
_PTRACE_SEIZE = 0x4206
_PTRACE_CONT = 7
_PTRACE_DETACH = 17
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_O_TRACEEXEC = 0x10
_PTRACE_EVENT_EXEC = 4


def _ptrace(request, pid, addr=0, data=0):
    ctypes.set_errno(0)
    result = _LIBC.ptrace(ctypes.c_ulong(request), ctypes.c_ulong(pid),
                          ctypes.c_void_p(addr), ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if result == -1:
        raise SetupError(f"ptrace {request:#x} on {pid} failed: {os.strerror(error)}")
    return result


def seize_until_exec(pid):
    """Seize an owned pid; its next exec trap-stops before user code."""
    _ptrace(_PTRACE_SEIZE, pid)
    _ptrace(_PTRACE_SETOPTIONS, pid, 0, _PTRACE_O_TRACEEXEC)


def wait_exec_stop(pid, timeout=120):
    """Wait for the TRACEEXEC trap-stop; returns the stop time (ns)."""
    deadline = time.monotonic() + timeout
    while True:
        done_pid, status = os.waitpid(pid, os.WNOHANG)
        if done_pid == pid:
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                raise SetupError(f"owned pid {pid} died while frozen for exec")
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                if (status >> 16) == _PTRACE_EVENT_EXEC:
                    return monotonic_ns()
                _ptrace(_PTRACE_CONT, pid)  # unrelated trap: resume
        if time.monotonic() >= deadline:
            raise SetupError(f"owned pid {pid} never reached its exec stop")
        time.sleep(0.01)


def ptrace_continue(pid):
    _ptrace(_PTRACE_CONT, pid)


def ptrace_detach(pid):
    _ptrace(_PTRACE_DETACH, pid)


def wait_caller_admitted(jsonl_path, pid, exe, timeout=90):
    """Wait for caller_event/admitted for (pid, exe) in an inventory event log."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = Path(jsonl_path).read_text()
        except FileNotFoundError:
            text = ""
        for line in text.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("kind") != "caller_event":
                continue
            event = record.get("event", {})
            if event.get("event") != "admitted":
                continue
            caller = ((event.get("identity_context") or {}).get("caller") or {})
            if caller.get("pid") == pid and (
                    caller.get("executable") or {}).get("path") == exe:
                return {"caller": event.get("caller"),
                        "incarnation": caller.get("incarnation"),
                        "at_ns": record.get("at_ns")}
        if time.monotonic() >= deadline:
            raise SetupError(f"caller ({pid}, {exe}) never admitted")
        time.sleep(0.2)


def wait_passes(jsonl_path, count, timeout=120):
    """Wait until the event log holds >= count pass_committed records."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = Path(jsonl_path).read_text()
        except FileNotFoundError:
            text = ""
        passes = sum(1 for line in text.splitlines()
                     if '"pass_committed"' in line)
        if passes >= count:
            return passes
        if time.monotonic() >= deadline:
            raise SetupError(f"only {passes}/{count} inventory passes committed")
        time.sleep(0.5)


def move_and_verify(cgroup, caller, moves, note):
    """Move an owned caller; record the verified membership interval edge."""
    cgroup.move(caller)
    actual = cgroup_of(caller.pid)
    moves.append({"t": monotonic_ns(), "cgroup": actual, "note": note})
    return actual


def create_tracked(ctx, path):
    """create_cgroup plus its cleanup wrapper (needed for rename fixups)."""
    before = len(ctx.groups)
    group = create_cgroup(Path(path), ctx.groups)
    return group, ctx.groups[before]


def fixup_renamed_wrappers(moves, top_wrapper, new_top, children):
    """Repoint cleanup wrappers after an owned rename; verify + record.

    Only the top dir is renamed; children move with it and are repointed
    (relative names under the new top).
    """
    os.rename(top_wrapper.path, new_top)
    top_wrapper.path = Path(new_top)
    if top_wrapper.group is not None:
        top_wrapper.group.path = Path(new_top)
        top_wrapper.group.verify()
    for wrapper, rel in children:
        wrapper.path = Path(new_top) / rel
        if wrapper.group is not None:
            wrapper.group.path = wrapper.path
            wrapper.group.verify()
    moves.append({"t": monotonic_ns(), "cgroup": str(new_top), "note": "rename-held"})


def run_cgroup_r1(ctx, cell_dir, backend):
    """Inside -> outside exec -> descendant re-entry, same-image move, rename."""
    leg_dir = Path(cell_dir) / backend / "trace"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-r1")
    pins = {}
    for name in ("caller-a", "caller-b"):
        path = leg_dir / name
        shutil.copyfile(ctx.pins["caller"].path, path)
        path.chmod(0o755)
        pins[name] = FilePin(path)
    provider = ctx.provider_pin
    root, _ = create_tracked(ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-{uuid.uuid4().hex[:8]}")
    selected, selected_w = create_tracked(ctx, root.path / "selected")
    outside, _ = create_tracked(ctx, root.path / "outside")
    sub, sub_w = create_tracked(ctx, selected.path / "sub")
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pins["caller-a"],
                                     provider, ctx.args.uid, ctx.args.gid, env)
    stdout.record("ready", 0)
    images = [pins["caller-a"].image_receipt(stdout.record("image", 0), caller)]
    moves = []
    move_and_verify(selected, caller, moves, "initial")
    argv = [str(ctx.binary.path), "trace", "--cgroup", str(selected.path),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "240s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "cgroup-reentry", "leg": f"trace/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 5, 100, "warm", "selected",
               0, selected, phases)
    t_out = monotonic_ns()
    move_and_verify(outside, caller, moves, "exit")
    n3_command(caller, stdout, "C_GetInfo", 3, 50, "aside", "outside",
               0, outside, phases)
    request, _, t0, t1 = caller_exec(caller, stdout, images, "thread-exec", pins["caller-b"])
    transitions = [{"from_image": 0, "to_image": 1, "mode": "nonleader",
                    "same_path": False, "scope": "outside",
                    "t0": t0, "t1": t1, "request": request}]
    n3_command(caller, stdout, "C_GetInfo", 3, 50, "outside-b", "outside",
               1, outside, phases)
    t_in = monotonic_ns()
    move_and_verify(sub, caller, moves, "descendant-reentry")
    n3_command(caller, stdout, "C_GetSessionInfo", 10, 200, "measured", "selected",
               1, sub, phases)
    move_and_verify(selected, caller, moves, "same-image-move")
    n3_command(caller, stdout, "C_GetSessionInfo", 3, 100, "still", "selected",
               1, selected, phases)
    renamed = root.path / "selected-renamed"
    fixup_renamed_wrappers(moves, selected_w, renamed, [(sub_w, "sub")])
    assert cgroup_of(caller.pid).endswith("selected-renamed")
    # The N3 group object still points at the old path: verify by raw path.
    begin = monotonic_ns()
    caller.popen.stdin.write("calls C_GetSessionInfo 3 100 renamed selected\n")
    caller.popen.stdin.flush()
    stdout.record("ack", 1, "renamed")
    finish = monotonic_ns()
    assert cgroup_of(caller.pid).endswith("selected-renamed")
    phases.append({"image": 1, "fn": "C_GetSessionInfo", "phase": "renamed",
                   "scope": "selected", "count": 3, "t0": begin, "t1": finish,
                   "actual_cgroup": cgroup_of(caller.pid)})
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = stop_caller(caller, stdout, 1)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = next(p for p in phases if p["phase"] == "measured")
    warmup = next(p for p in phases if p["phase"] == "warm")
    receipt = {
        "cell": "cgroup-reentry", "leg": f"trace/{backend}", "scope_kind": "cgroup",
        "owned_pids": [caller.pid],
        "scope_intervals": [
            {"pid": caller.pid, "membership": "selected", "t0": ready, "t1": t_out},
            {"pid": caller.pid, "membership": "selected", "t0": t_in, "t1": stopped},
        ],
        "moves": moves,
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "post-reentry", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 10, "phases": ["measured"]},
        "warmup": {"label": "pre", "t0": warmup["t0"], "t1": warmup["t1"],
                   "expected_calls": 5, "phases": ["warm"]},
        "exec_transitions": transitions, "phases": phases,
        "require_named": True, "require_named_images": [1], "first_unknown_images": [1],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {"session": True},
        "session_reuse": session_reuse_from(ledger),
        "requested_backend": backend,
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def provider_entry(path):
    """Independent provider identity receipt for inventory legs."""
    info = os.stat(path)
    return {"path": str(path), "ino": info.st_ino,
            "sha256": sha256_file(path)}


def phase_window(batches, phases):
    """Ledger [t0, t1] span and entered total over named phases."""
    picked = [batch for batch in batches if f"{batch['phase']}:gen{batch['gen']}"
              in phases or batch["phase"] in phases]
    total = sum(batch["n"] for batch in picked
                if batch["fn"] != "C_GetFunctionList")
    if not picked:
        return None, None, 0
    return (min(batch["t0"] for batch in picked),
            max(batch["t1"] for batch in picked), total)


def counted_totals(batches, started_ns):
    """Per-(pid, gen, module) entered totals over in-capture phases only.

    Generation 0 runs setup before READY, which strictly precedes the
    observer spawn by harness construction; the guard below proves it from
    the ledger clock, so main+teardown is the independent gen0 expectation.
    Later generations run entirely inside the capture (the exec freeze
    holds gen1 until its admission is observed), so all their phases count.
    """
    totals: Counter = Counter()
    for batch in batches:
        if batch["fn"] == "C_GetFunctionList":
            continue
        if batch["gen"] == 0 and batch["phase"] == "setup":
            if batch["t1"] >= started_ns:
                raise SetupError("gen0 setup overlaps the observer lifetime: "
                                 "the gated start is broken")
            continue
        totals[(batch["pid"], batch["gen"], batch["module"])] += batch["n"]
    return totals


def run_cgroup_inventory_r5(ctx, cell_dir, backend):
    """R5: post-reentry S1 inventory; successor frozen until admission proof."""
    leg_dir = Path(cell_dir) / backend / "inventory"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-r5")
    ledger_bin = leg_dir / "ledger"
    shutil.copyfile(ctx.pins["ledger"].path, ledger_bin)
    ledger_bin.chmod(0o755)
    ledger2 = leg_dir / "ledger2"
    shutil.copyfile(ctx.pins["ledger"].path, ledger2)
    ledger2.chmod(0o755)
    provider = ctx.provider_pin
    manifest_path = leg_dir / "manifest-A.json"
    build_manifest(ctx.discover_pin, provider.path, manifest_path, env,
                   ctx.args.uid, ctx.args.gid)
    root, _ = create_tracked(ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-{uuid.uuid4().hex[:8]}")
    selected, _ = create_tracked(ctx, root.path / "selected")
    outside, _ = create_tracked(ctx, root.path / "outside")
    sub, _ = create_tracked(ctx, selected.path / "sub")
    gate_x = leg_dir / "gate-X"
    gate_s = leg_dir / "gate-S0"
    owned_x, out_x, err_x = spawn_ledger(
        ctx.owners, ctx.readers, leg_dir,
        [str(ledger_bin), "exec-chain", "--cell", "RX", "--module", str(provider.path),
         "--iters", "2", "--gate", str(gate_x), "--delay-ms", "2000",
         "--sleep-us", "50000", "--hold", "--chain", f"leader:{ledger2}"],
        env, ctx.args.uid, ctx.args.gid, "RX")
    owned_s, out_s, err_s = spawn_ledger(
        ctx.owners, ctx.readers, leg_dir,
        [str(ledger_bin), "map", "--cell", "RS0", "--module", str(provider.path),
         "--gate", str(gate_s), "--hold"],
        env, ctx.args.uid, ctx.args.gid, "RS0")
    wait_ledger_line(out_x, "READY ", timeout=60)
    wait_ledger_line(out_s, "READY ", timeout=60)
    moves = []
    x_pid = owned_x.pid
    s_pid = owned_s.pid
    move_and_verify(selected, owned_x, moves, "X-initial")
    move_and_verify(selected, owned_s, moves, "S0-initial")
    seize_until_exec(x_pid)
    owned, capture, errors, started, doc_path, log_path = spawn_inventory(
        ctx, leg_dir, ["--cgroup", str(selected.path)], [], ["--manifest", str(manifest_path)],
        backend, 300)
    try:
        ready = wait_inventory_ready(owned, errors, log_path, backend)
    except BackendRefused as refused:
        ptrace_detach(x_pid)
        owned_x.popen.send_signal(signal.SIGINT)
        owned_s.popen.send_signal(signal.SIGINT)
        receipt = {"cell": "cgroup-reentry", "leg": f"inventory/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_inventory_h6({}, {}, receipt)
        write_json(leg_dir / "result.json", result)
        return result
    wait_passes(log_path, 2)
    gate_x.touch()
    gate_s.touch()
    out_x.wait(lambda r: any(line.startswith("DONE ") and " gen=0 " in line
                             for line in r.lines), 120)
    t_out = monotonic_ns()
    move_and_verify(outside, owned_x, moves, "X-exit-for-exec")
    exec_stop_ns = wait_exec_stop(x_pid)
    admitted = wait_caller_admitted(log_path, x_pid, str(ledger2))
    t_in = monotonic_ns()
    move_and_verify(sub, owned_x, moves, "X-descendant-reentry")
    ptrace_continue(x_pid)
    out_x.wait(lambda r: any(line.startswith("DONE ") and " gen=1 " in line
                             for line in r.lines), 180)
    out_s.wait(lambda r: any(line.startswith("DONE ") for line in r.lines), 60)
    settled = wait_passes(log_path, wait_passes(log_path, 1) + 2)
    obs_rc, stopped, latency = stop_inventory(owned)
    ptrace_detach(x_pid)
    owned_x.popen.send_signal(signal.SIGINT)
    owned_s.popen.send_signal(signal.SIGINT)
    x_rc = owned_x.popen.wait(timeout=15)
    s_rc = owned_s.popen.wait(timeout=15)
    finish_readers([out_x, err_x, out_s, err_s, capture, errors])
    ledgers = {"RX": parse_inv_ledger("".join(out_x.lines)),
               "RS0": parse_inv_ledger("".join(out_s.lines))}
    totals = counted_totals(ledgers["RX"]["batches"], started)
    m_t0, m_t1, m_n = phase_window(
        ledgers["RX"]["batches"], ["setup:gen1", "main:gen1", "teardown:gen1"])
    w_t0, w_t1, w_n = phase_window(
        ledgers["RX"]["batches"], ["main:gen0", "teardown:gen0"])
    key0 = (x_pid, 0, str(provider.path))
    key1 = (x_pid, 1, str(provider.path))
    receipt = {
        "cell": "cgroup-reentry", "leg": f"inventory/{backend}", "scope_kind": "cgroup",
        "scope_label": "cgroup", "owned_pids": [x_pid, s_pid],
        "scope_intervals": [
            {"pid": x_pid, "membership": "selected", "t0": ready, "t1": t_out},
            {"pid": x_pid, "membership": "selected", "t0": t_in, "t1": stopped},
            {"pid": s_pid, "membership": "selected", "t0": ready, "t1": stopped},
        ],
        "moves": moves,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "observer_rc": obs_rc,
        "manual_rebind": False, "s1_expected": True,
        "providers": {"A": provider_entry(provider.path)},
        "expected_incarnations": {
            str(x_pid): {"gens": {
                "0": {"exe": str(ledger_bin), "retired": True},
                "1": {"exe": str(ledger2), "retired": False}}},
            str(s_pid): {"gens": {
                "0": {"exe": str(ledger_bin), "retired": False}}}},
        "expected_edges": {
            f"{x_pid}:0:A": {"counted": True, "count": totals.get(key0, -1)},
            f"{x_pid}:1:A": {"counted": True, "count": totals.get(key1, -1)},
            f"{s_pid}:0:A": {"zero_ok": True}},
        "measured": {"label": "post-reentry successor", "t0": m_t0, "t1": m_t1,
                     "expected_calls": m_n,
                     "phases": ["setup:gen1", "main:gen1", "teardown:gen1"]},
        "warmup": {"label": "pre-exec generation", "t0": w_t0, "t1": w_t1,
                   "expected_calls": w_n, "phases": ["main:gen0", "teardown:gen0"]},
        "allowed_gap_subjects": ["exact image authority unavailable",
                                 "native capture scope custody unproven",
                                 "used by an unidentified caller image"],
        "cell_endings": {"RX": {"how": "exited" if x_rc == 0 else "signaled", "rc": x_rc},
                         "RS0": {"how": "exited" if s_rc == 0 else "signaled", "rc": s_rc}},
        "requested_backend": backend,
        "freeze": {"exec_stop_ns": exec_stop_ns, "admitted": admitted,
                   "settled_passes": settled},
    }
    doc = json.loads(doc_path.read_text())
    result = evaluate_inventory_h6(doc, ledgers, receipt)
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_system_mixed(ctx, cell_dir, backend):
    """system-mixed: execing + sibling same-file callers, attested + count-only.

    XE exec-chains on the attested provider A (frozen until the successor's
    admission is observed); XS runs continuously on A and on the unattested
    copy B (count-only: physical counts, no semantic rows); XF's provider
    file is deleted after READY, so its producer proof is foreign and the
    host must refuse it while the valid siblings stay exact.
    """
    leg_dir = Path(cell_dir) / backend / "inventory"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-mix")
    ledger_bin = leg_dir / "ledger"
    shutil.copyfile(ctx.pins["ledger"].path, ledger_bin)
    ledger_bin.chmod(0o755)
    ledger2 = leg_dir / "ledger2"
    shutil.copyfile(ctx.pins["ledger"].path, ledger2)
    ledger2.chmod(0o755)
    provider_a = ctx.provider_pin
    provider_b = leg_dir / "provider-B.so"
    shutil.copyfile(provider_a.path, provider_b)
    provider_b.chmod(0o755)
    provider_f = leg_dir / "provider-F.so"
    shutil.copyfile(provider_a.path, provider_f)
    provider_f.chmod(0o755)
    manifest_path = leg_dir / "manifest-A.json"
    build_manifest(ctx.discover_pin, provider_a.path, manifest_path, env,
                   ctx.args.uid, ctx.args.gid)
    gate_e = leg_dir / "gate-E"
    gate_s = leg_dir / "gate-S"
    gate_f = leg_dir / "gate-F"
    # XE and XS spawn from the same file: independent same-file callers.
    owned_e, out_e, err_e = spawn_ledger(
        ctx.owners, ctx.readers, leg_dir,
        [str(ledger_bin), "exec-chain", "--cell", "MX", "--module", str(provider_a.path),
         "--iters", "2", "--gate", str(gate_e), "--delay-ms", "2000",
         "--sleep-us", "50000", "--hold", "--chain", f"leader:{ledger2}"],
        env, ctx.args.uid, ctx.args.gid, "MX")
    owned_s, out_s, err_s = spawn_ledger(
        ctx.owners, ctx.readers, leg_dir,
        [str(ledger_bin), "mech", "--cell", "MS", "--module", str(provider_a.path),
         "--module", str(provider_b), "--iters", "3", "--gate", str(gate_s),
         "--sleep-us", "100000", "--hold"],
        env, ctx.args.uid, ctx.args.gid, "MS")
    owned_f, out_f, err_f = spawn_ledger(
        ctx.owners, ctx.readers, leg_dir,
        [str(ledger_bin), "mech", "--cell", "MF", "--module", str(provider_f),
         "--iters", "1", "--gate", str(gate_f), "--hold"],
        env, ctx.args.uid, ctx.args.gid, "MF")
    wait_ledger_line(out_e, "READY ", timeout=60)
    wait_ledger_line(out_s, "READY ", timeout=60)
    wait_ledger_line(out_f, "READY ", timeout=60)
    e_pid, s_pid, f_pid = owned_e.pid, owned_s.pid, owned_f.pid
    provider_f.unlink()
    seize_until_exec(e_pid)
    owned, capture, errors, started, doc_path, log_path = spawn_inventory(
        ctx, leg_dir, ["--system"], [], ["--manifest", str(manifest_path)],
        backend, 300)
    try:
        ready = wait_inventory_ready(owned, errors, log_path, backend)
    except BackendRefused as refused:
        ptrace_detach(e_pid)
        for owned_p in (owned_e, owned_s, owned_f):
            owned_p.popen.send_signal(signal.SIGINT)
        receipt = {"cell": "system-mixed", "leg": f"inventory/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_inventory_h6({}, {}, receipt)
        write_json(leg_dir / "result.json", result)
        return result
    wait_passes(log_path, 2)
    gate_e.touch()
    gate_s.touch()
    gate_f.touch()
    out_e.wait(lambda r: any(line.startswith("DONE ") and " gen=0 " in line
                             for line in r.lines), 120)
    exec_stop_ns = wait_exec_stop(e_pid)
    admitted = wait_caller_admitted(log_path, e_pid, str(ledger2))
    ptrace_continue(e_pid)
    out_e.wait(lambda r: any(line.startswith("DONE ") and " gen=1 " in line
                             for line in r.lines), 180)
    out_s.wait(lambda r: any(line.startswith("DONE ") for line in r.lines), 180)
    out_f.wait(lambda r: any(line.startswith("DONE ") for line in r.lines), 120)
    settled = wait_passes(log_path, wait_passes(log_path, 1) + 2)
    obs_rc, stopped, latency = stop_inventory(owned)
    ptrace_detach(e_pid)
    for owned_p in (owned_e, owned_s, owned_f):
        owned_p.popen.send_signal(signal.SIGINT)
    e_rc = owned_e.popen.wait(timeout=15)
    s_rc = owned_s.popen.wait(timeout=15)
    f_rc = owned_f.popen.wait(timeout=15)
    finish_readers([out_e, err_e, out_s, err_s, out_f, err_f, capture, errors])
    ledgers = {"MX": parse_inv_ledger("".join(out_e.lines)),
               "MS": parse_inv_ledger("".join(out_s.lines)),
               "MF": parse_inv_ledger("".join(out_f.lines))}
    totals_e = counted_totals(ledgers["MX"]["batches"], started)
    totals_s = counted_totals(ledgers["MS"]["batches"], started)
    m_t0, m_t1, m_n = phase_window(
        ledgers["MX"]["batches"], ["setup:gen1", "main:gen1", "teardown:gen1"])
    w_t0, w_t1, w_n = phase_window(
        ledgers["MX"]["batches"], ["main:gen0", "teardown:gen0"])
    a_path, b_path = str(provider_a.path), str(provider_b)
    receipt = {
        "cell": "system-mixed", "leg": f"inventory/{backend}", "scope_kind": "system",
        "scope_label": "system",
        "owned_pids": [e_pid, s_pid, f_pid], "foreign_pids": [f_pid],
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "observer_rc": obs_rc,
        "manual_rebind": False, "s1_expected": True,
        "providers": {"A": provider_entry(provider_a.path),
                      "B": provider_entry(provider_b)},
        "count_only_providers": ["B"],
        "expected_incarnations": {
            str(e_pid): {"gens": {
                "0": {"exe": str(ledger_bin), "retired": True},
                "1": {"exe": str(ledger2), "retired": False}}},
            str(s_pid): {"gens": {
                "0": {"exe": str(ledger_bin), "retired": False}}},
            # No incarnation row is required for the foreign caller: refusal
            # may mean no caller row at all. Its edges must still carry no
            # counted usage (foreign_pids rule above).
        },
        "expected_edges": {
            f"{e_pid}:0:A": {"counted": True,
                             "count": totals_e.get((e_pid, 0, a_path), -1)},
            f"{e_pid}:1:A": {"counted": True,
                             "count": totals_e.get((e_pid, 1, a_path), -1)},
            f"{s_pid}:0:A": {"counted": True,
                             "count": totals_s.get((s_pid, 0, a_path), -1)},
            f"{s_pid}:0:B": {"counted": True,
                             "count": totals_s.get((s_pid, 0, b_path), -1)}},
        "measured": {"label": "exec successor", "t0": m_t0, "t1": m_t1,
                     "expected_calls": m_n,
                     "phases": ["setup:gen1", "main:gen1", "teardown:gen1"]},
        "warmup": {"label": "pre-exec generation", "t0": w_t0, "t1": w_t1,
                   "expected_calls": w_n, "phases": ["main:gen0", "teardown:gen0"]},
        "allow_path_gaps": True,
        "allowed_gap_subjects": ["exact image authority unavailable",
                                 "native capture scope custody unproven",
                                 "used by an unidentified caller image"],
        "cell_endings": {"MX": {"how": "exited" if e_rc == 0 else "signaled", "rc": e_rc},
                         "MS": {"how": "exited" if s_rc == 0 else "signaled", "rc": s_rc},
                         "MF": {"how": "exited" if f_rc == 0 else "signaled", "rc": f_rc}},
        "requested_backend": backend,
        "freeze": {"exec_stop_ns": exec_stop_ns, "admitted": admitted,
                   "settled_passes": settled},
    }
    doc = json.loads(doc_path.read_text())
    result = evaluate_inventory_h6(doc, ledgers, receipt)
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_cgroup_reentry(ctx, cell_dir, backend):
    """R1 reentry + R2 replacement + R3/R4 stops + R5 S1 inventory."""
    cell_dir = Path(cell_dir)
    return [run_cgroup_r1(ctx, cell_dir, backend),
            run_cgroup_r2(ctx, cell_dir, backend),
            run_cgroup_stop_before(ctx, cell_dir, backend),
            run_cgroup_stop_during(ctx, cell_dir, backend),
            run_cgroup_inventory_r5(ctx, cell_dir, backend)]


CELL_RUNNERS = {
    "pid-leader": run_pid_leader,
    "pid-reexec": run_pid_reexec,
    "pid-nonleader-cold": run_pid_nonleader_cold,
    "pid-failed-exec": run_pid_failed_exec,
    "leader-exit-exec": run_leader_exit_exec,
    "rapid-chain": run_rapid_chain,
    "cgroup-reentry": run_cgroup_reentry,
    "system-mixed": run_system_mixed,
}


def run_cell_backend(ctx, cell, backend):
    """Run one cell x backend; SetupError becomes a recorded error result."""
    cell_dir = ctx.out / cell
    cell_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        results = CELL_RUNNERS[cell](ctx, cell_dir, backend)
    except (SetupError, TimeoutError, AssertionError, OSError,
            ValueError, subprocess.SubprocessError) as error:
        results = [{"pass": False, "status": "error", "cell": cell,
                    "leg": backend, "errors": [f"{type(error).__name__}: {error}"]}]
    for result in results:
        result.setdefault("cell", cell)
        print(json.dumps({key: result.get(key) for key in
                          ("cell", "leg", "status", "pass", "calls", "named",
                           "unknown", "physical_entered", "physical_counted",
                           "completed_operations", "negative_reason", "errors")}),
              flush=True)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Installed automatic exec/scope recovery acceptance (H6 slice 4). "
                    "Live use requires root with an ordinary workload uid/gid.")
    parser.add_argument("--binary", type=Path, required=True,
                        help="absolute path of the staged p11scope binary")
    parser.add_argument("--provider", type=Path,
                        default=Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
                        help="absolute path of the SoftHSM provider")
    parser.add_argument("--discover", type=Path, default=None,
                        help="absolute path of p11scope-discover "
                             "(default: sibling of --binary)")
    parser.add_argument("--source-revision", required=True,
                        help="exact 40-hex source commit under test")
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--cells", default=",".join(CELLS))
    parser.add_argument("--backends", default=",".join(BACKENDS))
    parser.add_argument("--out", type=Path, required=True,
                        help="absolute new-only output directory (disk, never tmpfs)")
    args = parser.parse_args(argv)
    cells = args.cells.split(",")
    backends = args.backends.split(",")
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error("live harness requires root observer and an ordinary workload uid/gid")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        parser.error("supply the exact source commit under test")
    if any(name not in CELLS for name in cells):
        parser.error(f"supported cells: {','.join(CELLS)}")
    if any(name not in BACKENDS for name in backends):
        parser.error(f"supported backends: {','.join(BACKENDS)}")
    if args.discover is None:
        args.discover = args.binary.parent / "p11scope-discover"
    if not args.out.is_absolute() or any(
            not path.is_absolute() for path in (args.binary, args.provider, args.discover)):
        parser.error("all input/output paths must be absolute")
    if "tmpfs" in str(args.out):
        parser.error("output must live on disk, never tmpfs")
    os.umask(0o022)
    args.out.mkdir(mode=0o755)  # new-only; refuse accidental reuse
    (args.out / "bin").mkdir(mode=0o755)
    ctx = Case(args)
    pins = []
    results = []
    cleanup_receipt: dict = {"processes": 0, "cgroups": 0, "pins": 0, "errors": []}
    with signal_cleanup():
        try:
            with cleanup_section():
                ctx.binary = FilePin(args.binary)
                pins.append(ctx.binary)
                ctx.provider_pin = FilePin(args.provider)
                pins.append(ctx.provider_pin)
                ctx.discover_pin = FilePin(args.discover)
                pins.append(ctx.discover_pin)
            ctx.pins = compile_case_fixtures(args.out / "bin")
            ctx.b_file_offset = symbol_file_offset(
                str(args.out / "bin" / "provider.so"), "C_Initialize")
            for cell in cells:
                for backend in backends:
                    results.extend(run_cell_backend(ctx, cell, backend))
            summary = {
                "source_revision": args.source_revision,
                "candidate": ctx.binary.metadata(),
                "provider": ctx.provider_pin.metadata(),
                "abi": "Linux x86-64 LP64", "kernel": os.uname().release,
                "cells": [cell for cell in cells for _ in backends],
                "backends": list(backends),
                "legs": results,
                "passed": sum(1 for result in results if result.get("pass")),
                "failed": sum(1 for result in results if not result.get("pass")),
                "unexecuted": [name for name in CELLS if name not in cells],
            }
            write_json(args.out / "summary.json", summary)
            print(json.dumps({"passed": summary["passed"], "failed": summary["failed"],
                              "out": str(args.out)}), flush=True)
            return 0 if summary["failed"] == 0 else 1
        finally:
            with cleanup_section():
                cleanup_receipt["processes"] = len(ctx.owners)
                cleanup_receipt["cgroups"] = len(ctx.groups)
                try:
                    cleanup_processes(ctx.owners)
                except Exception as error:  # noqa: BLE001 - receipt must record
                    cleanup_receipt["errors"].append(f"processes: {error}")
                try:
                    cleanup_cgroups(ctx.groups)
                except Exception as error:  # noqa: BLE001 - receipt must record
                    cleanup_receipt["errors"].append(f"cgroups: {error}")
                for pin in reversed(pins):
                    try:
                        pin.close()
                        cleanup_receipt["pins"] += 1
                    except Exception as error:  # noqa: BLE001 - receipt must record
                        cleanup_receipt["errors"].append(f"pin: {error}")
                try:
                    write_json(args.out / "cleanup.json", cleanup_receipt)
                except OSError as error:
                    print(f"cleanup receipt unwritable: {error}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())


def spawn_inventory(ctx, leg_dir, scope_args, module_args, manifest_args,
                    backend, duration_s, tag="inventory"):
    """Spawn an inventory observer; returns (owned, capture, errors, started, paths)."""
    leg_dir = Path(leg_dir)
    doc_path = leg_dir / f"{tag}.json"
    log_path = leg_dir / f"{tag}.jsonl"
    argv = [str(ctx.binary.path), "inventory", *scope_args, *module_args,
           *manifest_args, "--duration", str(duration_s), "-o", str(doc_path),
           "--event-log", str(log_path), "--capture", "native",
           "--attach-backend", backend]
    started = monotonic_ns()
    owned = spawn_owned(ctx.owners, argv, 0, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, env=dict(os.environ), start_new_session=True)
    capture = Reader(owned.popen.stdout, leg_dir / f"{tag}.stdout.txt")
    errors = Reader(owned.popen.stderr, leg_dir / f"{tag}.stderr.txt")
    ctx.readers.extend((capture, errors))
    return owned, capture, errors, started, doc_path, log_path


def wait_inventory_ready(owned, errors, log_path, backend, timeout=120):
    """Wait for the first committed pass; BackendRefused on explicit refusal."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = Path(log_path).read_text()
        except FileNotFoundError:
            text = ""
        if '"pass_committed"' in text:
            return monotonic_ns()
        rc = owned.popen.poll()
        if rc is not None:
            tail = "".join(errors.lines[-20:])
            if rc != 0 and REFUSAL_MARKERS.search(tail):
                raise BackendRefused(f"{backend}: {tail.strip()[-500:]}")
            raise SetupError(f"inventory observer exited rc={rc} before first pass: "
                             f"{tail[-1000:]}")
        if time.monotonic() >= deadline:
            raise SetupError("inventory observer never committed a pass")
        time.sleep(0.5)


def stop_inventory(owned, limit_seconds=30):
    """SIGINT stop; returns (rc, stopped_ns, latency_seconds)."""
    begin = monotonic_ns()
    owned.send(signal.SIGINT)
    try:
        rc = owned.popen.wait(timeout=limit_seconds + 10)
    except subprocess.TimeoutExpired:
        owned.popen.kill()
        rc = owned.popen.wait(timeout=10)
    stopped = monotonic_ns()
    return rc, stopped, (stopped - begin) / 1e9


def wait_ledger_line(reader, prefix, timeout=120):
    """Wait for an inventory-ledger stdout line with prefix; returns the line."""
    try:
        return reader.wait(lambda r: next(
            (line for line in r.lines if line.startswith(prefix)), None), timeout)
    except TimeoutError:
        raise SetupError(f"ledger never printed {prefix!r}")


def ledger_pids(reader):
    """Parse pid per gen from IDENT lines seen so far."""
    pids = {}
    for line in reader.lines:
        if line.startswith("IDENT "):
            fields = dict(INV_KV.findall(line))
            try:
                pids[int(fields["gen"])] = int(fields["pid"])
            except (KeyError, ValueError):
                continue
    return pids


def run_cgroup_stop_before(ctx, cell_dir, backend):
    """R3: stop before the first completed collection; capture stays empty."""
    leg_dir = Path(cell_dir) / backend / "stop-before"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-stop3")
    image = leg_dir / "caller-a"
    shutil.copyfile(ctx.pins["caller"].path, image)
    image.chmod(0o755)
    pin = FilePin(image)
    provider = ctx.provider_pin
    root, _ = create_tracked(ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-{uuid.uuid4().hex[:8]}")
    selected, _ = create_tracked(ctx, root.path / "selected")
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pin,
                                     provider, ctx.args.uid, ctx.args.gid, env)
    stdout.record("ready", 0)
    moves = []
    move_and_verify(selected, caller, moves, "initial")
    argv = [str(ctx.binary.path), "trace", "--cgroup", str(selected.path),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "120s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "cgroup-reentry", "leg": f"stop-before/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    # No call is ever issued: stop lands before the first completed collection.
    obs_rc, stopped, latency = stop_observer(owned)
    caller_rc = stop_caller(caller, stdout, 0)
    finish_readers([stdout, capture, errors])
    receipt = {"cell": "cgroup-reentry", "leg": f"stop-before/{backend}",
               "scope_kind": "cgroup", "owned_pids": [caller.pid], "moves": moves,
               "observer_rc": obs_rc, "caller_rc": caller_rc,
               "observer_started_ns": started, "observer_ready_ns": ready,
               "observer_stopped_ns": stopped,
               "stop_latency_seconds": latency, "stop_limit_seconds": 60,
               "expect_empty": True}
    result = evaluate_trace_h6("".join(capture.lines), [], receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result


def run_cgroup_stop_during(ctx, cell_dir, backend):
    """R4: stop during final membership work; completed phases stay intact."""
    leg_dir = Path(cell_dir) / backend / "stop-during"
    (leg_dir / "workload").mkdir(mode=0o755, parents=True, exist_ok=True)
    env = init_token(leg_dir / "workload", ctx.args.uid, ctx.args.gid, "h6-stop4")
    pins = {}
    for name in ("caller-a", "caller-b"):
        path = leg_dir / name
        shutil.copyfile(ctx.pins["caller"].path, path)
        path.chmod(0o755)
        pins[name] = FilePin(path)
    provider = ctx.provider_pin
    root, _ = create_tracked(ctx, Path("/sys/fs/cgroup") / f"p11scope-h6-{uuid.uuid4().hex[:8]}")
    selected, _ = create_tracked(ctx, root.path / "selected")
    outside, _ = create_tracked(ctx, root.path / "outside")
    sub, _ = create_tracked(ctx, selected.path / "sub")
    caller, stdout, _ = spawn_caller(ctx.owners, ctx.readers, leg_dir, pins["caller-a"],
                                     provider, ctx.args.uid, ctx.args.gid, env)
    stdout.record("ready", 0)
    images = [pins["caller-a"].image_receipt(stdout.record("image", 0), caller)]
    moves = []
    move_and_verify(selected, caller, moves, "initial")
    argv = [str(ctx.binary.path), "trace", "--cgroup", str(selected.path),
           "--module", str(provider.path), "--attach-backend", backend,
           "--duration", "240s", "-o", str(leg_dir / "trace.file.txt")]
    owned, capture, errors, started = spawn_observer(
        ctx.owners, ctx.readers, leg_dir, argv, env)
    try:
        ready = observer_ready(owned, errors, backend)
    except BackendRefused as refused:
        stop_caller(caller, stdout, 0)
        receipt = {"cell": "cgroup-reentry", "leg": f"stop-during/{backend}",
                   "backend_refused": str(refused)}
        result = evaluate_trace_h6("", [], receipt)
        write_json(leg_dir / "result.json", result)
        return result
    phases = []
    n3_command(caller, stdout, "C_GenerateRandom", 5, 100, "warm", "selected",
               0, selected, phases)
    t_out = monotonic_ns()
    move_and_verify(outside, caller, moves, "exit")
    request, _, t0, t1 = caller_exec(caller, stdout, images, "thread-exec", pins["caller-b"])
    transitions = [{"from_image": 0, "to_image": 1, "mode": "nonleader",
                    "same_path": False, "scope": "outside",
                    "t0": t0, "t1": t1, "request": request}]
    t_in = monotonic_ns()
    move_and_verify(sub, caller, moves, "descendant-reentry")
    n3_command(caller, stdout, "C_GetSessionInfo", 10, 200, "measured", "selected",
               1, sub, phases)
    # Final membership work continues around the stop: one call strictly
    # before, the observer stops, one call strictly after.
    n3_command(caller, stdout, "C_GetSessionInfo", 1, 0, "still-pre", "selected",
               1, sub, phases)
    obs_rc, stopped, latency = stop_observer(owned)
    begin = monotonic_ns()
    caller.popen.stdin.write("calls C_GetSessionInfo 1 0 still-post selected\n")
    caller.popen.stdin.flush()
    stdout.record("ack", 1, "still-post")
    finish = monotonic_ns()
    phases.append({"image": 1, "fn": "C_GetSessionInfo", "phase": "still-post",
                   "scope": "selected", "count": 1, "t0": begin, "t1": finish,
                   "actual_cgroup": cgroup_of(caller.pid)})
    caller_rc = stop_caller(caller, stdout, 1)
    finish_readers([stdout, capture, errors])
    ledger = list(stdout.records)
    measured = next(p for p in phases if p["phase"] == "measured")
    warmup = next(p for p in phases if p["phase"] == "warm")
    receipt = {
        "cell": "cgroup-reentry", "leg": f"stop-during/{backend}", "scope_kind": "cgroup",
        "owned_pids": [caller.pid],
        "scope_intervals": [
            {"pid": caller.pid, "membership": "selected", "t0": ready, "t1": t_out},
            {"pid": caller.pid, "membership": "selected", "t0": t_in, "t1": stopped},
        ],
        "moves": moves,
        "images": images, "provider_before": provider_receipt(provider),
        "provider_after": provider_receipt(provider),
        "privacy_canaries": list(CANARIES), "observer_stderr": "".join(errors.lines),
        "observer_rc": obs_rc, "caller_rc": caller_rc,
        "observer_started_ns": started, "observer_ready_ns": ready,
        "observer_stopped_ns": stopped, "scope_created_ns": ctx.scope_created_ns,
        "stop_latency_seconds": latency, "stop_limit_seconds": 60,
        "pid_namespace": caller.identity["pid_namespace"],
        "time_namespace": caller.identity["time_namespace"],
        "measured": {"label": "post-reentry", "t0": measured["t0"], "t1": measured["t1"],
                     "expected_calls": 10, "phases": ["measured"]},
        "warmup": {"label": "pre", "t0": warmup["t0"], "t1": warmup["t1"],
                   "expected_calls": 5, "phases": ["warm"]},
        "exec_transitions": transitions, "phases": phases,
        "require_named": True, "require_named_images": [1], "first_unknown_images": [1],
        "manual_rebind": False, "abandoned_expected": 0, "abandoned_by_fn": {},
        "reuse_expected": {"session": True},
        "session_reuse": session_reuse_from(ledger),
        "requested_backend": backend,
    }
    result = evaluate_trace_h6("".join(capture.lines), ledger, receipt,
                               (leg_dir / "trace.file.txt").read_text())
    write_json(leg_dir / "receipt.json", receipt)
    write_json(leg_dir / "result.json", result)
    return result
