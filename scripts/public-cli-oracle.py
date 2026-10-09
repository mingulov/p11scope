#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge public-command evidence against independent fixture targets/counts.

TARGET records bind actual mapped device/inode and function file offsets.
The receipt supplies independently hashed and mapped provider identity before/after, launch
identity, readiness, and process exits. Counts remain provider totals; this
checker never claims system-wide per-caller attribution.
"""

import argparse
import json
from pathlib import Path
import re
import runpy
import stat
import sys

NAMES = ("C_GenerateRandom", "C_DigestInit", "C_Digest",
         "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal")
COUNT_CELLS = {"profile-pid", "metrics-pid", "mt-exact", "system",
               "names-pid", "verdict-pid"}
SMOKE_CELLS = {"run-short", "run-cover", "trace-pid"}
LOSS_COUNTERS = ("event_loss", "in_flight_at_end", "start_insert_failures", "unmatched_returns",
                 "rv_update_failures", "cgroup_scope_failures", "abi_refusals", "malformed_records",
                 "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures",
                 "discovery_truncated", "task_uprobe_link_losses")
# Keep verdict policy in the existing canonical reader; it recomputes classes
# from published counters rather than trusting a report's claimed statuses.
VERDICT = runpy.run_path(str(Path(__file__).with_name("check-capture-evidence.py")))


class EvidenceError(Exception):
    pass


class Nonqualifying(Exception):
    pass


def require(condition, detail):
    if not condition:
        raise EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    require(stat.S_ISREG(path.stat().st_mode), "evidence must be a regular file")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence exceeds size limit")
    return path.read_text(encoding="utf-8")


def identity(value):
    require(isinstance(value, dict), "missing physical identity")
    dev = value.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
            "invalid device identity")
    require(integer(value.get("ino")) and value["ino"] > 0, "invalid inode identity")
    require(isinstance(value.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "missing provider hash")
    return (*dev, value["ino"], value["sha256"])


def provider_pin(value):
    physical = identity(value)
    anchor = value.get("mapping")
    require(isinstance(anchor, dict) and isinstance(anchor.get("dev"), list) and
            all(integer(x) for x in anchor["dev"]) and anchor["dev"] == list(physical[:2]) and
            type(anchor.get("ino")) is int and anchor["ino"] == physical[2] and
            type(anchor.get("file_offset")) is int and anchor["file_offset"] == 0 and
            integer(anchor.get("length")) and anchor["length"] > 0 and
            anchor.get("permissions") == "r--p", "missing or invalid independent mapping anchor")
    file = value.get("file_identity")
    require(isinstance(file, dict), "missing private FD identity")
    dev = file.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            type(file.get("ino")) is int and file["ino"] == physical[2] and
            integer(file.get("size")) and file["size"] >= anchor["length"] and
            all(type(file.get(key)) is int for key in ("mtime_ns", "ctime_ns")),
            "invalid private FD identity")
    return physical, (*dev, file["ino"], file["size"], file["mtime_ns"], file["ctime_ns"])


def ownership(row):
    """Validate the v3 exclusive ownership relation; absence has no authority."""
    require({"module", "module_ambiguous", "module_unresolved"} <= set(row),
            "missing required row ownership evidence")
    ambiguous, unresolved = row["module_ambiguous"], row["module_unresolved"]
    require(type(ambiguous) is bool and type(unresolved) is bool, "invalid row ownership flag")
    module = row["module"]
    if module is None:
        require(ambiguous != unresolved, "null module requires exactly one ownership reason")
        return None
    require(not ambiguous and not unresolved, "nonnull module contradicts ownership reason")
    require(isinstance(module, dict) and {"dev", "ino", "sha256"} <= set(module),
            "missing module ownership identity")
    dev = module["dev"]
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev) and
            integer(module["ino"]) and module["ino"] > 0, "invalid module ownership identity")
    if module["sha256"] is None:
        return None
    return identity(module)


def terminal(evidence, *, profile):
    # The schema/cell selects policy. Field omission cannot turn a profile
    # into the canonical reader's intentionally selection-blind metrics lane.
    profile_fields = VERDICT["PROFILE_V3_FIELDS"]
    if profile:
        require(profile_fields <= set(evidence), "missing required profile verdict authority")
        selection = evidence["interface_selection"]
        VERDICT["exact_keys"](selection, VERDICT["SELECTION_KEYS"], "interface_selection")
        require(type(selection["selection_truncated"]) is bool, "invalid selection truncation authority")
        for key in ("providers", "standard_exports", "inventory_surfaces", "tuples"):
            require(isinstance(selection[key], list), "invalid selection authority list: " + key)
        for row in selection["providers"]:
            require(isinstance(row, dict) and row.get("coverage") in VERDICT["SELECTION_COVERAGE"],
                    "invalid selection provider coverage")
        for row in selection["standard_exports"]:
            require(isinstance(row, dict) and row.get("status") in VERDICT["STANDARD_EXPORT_STATUS"],
                    "invalid selection export authority")
        for row in selection["tuples"]:
            require(isinstance(row, dict) and {"rv", "authority", "inventory_matches", "result"} <= set(row) and
                    integer(row.get("rv")) and
                    row.get("authority") in VERDICT["SELECTION_AUTHORITIES"] and
                    isinstance(row.get("inventory_matches"), list) and
                    (row.get("result") is None or isinstance(row["result"], dict)),
                    "invalid selection tuple verdict authority")
        for key in ("pid_descendant_gaps", "multi_rebuild_gaps"):
            VERDICT["uint"](evidence[key], VERDICT["U64_MAX"], key)
    else:
        require(profile_fields.isdisjoint(evidence), "metrics contains profile-only verdict authority")
    for key in (*VERDICT["COUNTERS"], "slots", "semantic_unverified_slots",
                "unprotected_live_windows", "module_unresolved_slots", "pause_partial", "vendor_interfaces"):
        require(integer(evidence.get(key)), "invalid or missing verdict counter: " + key)
    for key in ("drain_proven", "provider_changed", "templates_truncated"):
        require(type(evidence.get(key)) is bool, "invalid or missing verdict authority: " + key)
    scheduling = evidence.get("scheduling", {})
    require(type(scheduling.get("terminal_drain_truncated")) is bool and
            integer(scheduling.get("sink_dropped_bytes")), "invalid verdict scheduling authority")
    loader = evidence.get("loader_discovery", {})
    for group, keys in VERDICT["LOADER_DISCOVERY_GROUPS"].items():
        require(isinstance(loader.get(group), dict) and all(integer(loader[group].get(key)) for key in keys),
                "invalid verdict loader authority: " + group)
    for key in VERDICT["LOADER_DISCOVERY_COUNTERS"]:
        require(integer(loader.get(key)), "invalid verdict loader counter: " + key)
    VERDICT["exact_stop_quiescence"](evidence)
    VERDICT["exact_verdict_classes"](evidence)
    require(evidence.get("completeness") == VERDICT["expected_terminal_completeness"](evidence),
            "completeness conflicts with terminal gap and settlement evidence")


def fixture(text, receipt, cell):
    targets, ledgers, ready = [], [], []
    for line in text.splitlines():
        if line.startswith("TARGET "):
            require(not ready and not ledgers, "fixture target emitted after readiness or ledger")
            targets.append(parse(line[7:]))
        elif line.startswith("LEDGER "):
            require(len(ready) == 1, "fixture ledger emitted before workload READY")
            ledgers.append(parse(line[7:]))
        elif line.startswith("READY "):
            match = re.fullmatch(r"READY pid=([0-9]+)", line)
            require(match is not None, "invalid workload READY")
            ready.append(int(match[1]))
    pid = receipt.get("launched_pid")
    require(integer(pid) and pid > 0 and ready == [pid] and receipt.get("ready_pid") == pid,
            "workload READY does not match launched PID")
    require(len(ledgers) == 1, "missing or duplicate complete LEDGER")
    ledger = ledgers[0]
    require(ledger.get("schema") == "p11scope/public-cli-ledger/v1" and
            ledger.get("pid") == pid and ledger.get("complete") is True,
            "invalid or incomplete fixture ledger")
    names = {NAMES[0]} if cell == "mt-exact" else set(NAMES)
    functions = ledger.get("functions")
    require(isinstance(functions, list), "missing ledger functions")
    expected = {}
    for row in functions:
        name = row.get("name")
        require(name in names and name not in expected, "duplicate or unexpected ledger function")
        attempts, successes = row.get("attempts"), row.get("successful")
        require(integer(attempts) and integer(successes) and attempts > 0 and attempts == successes,
                "workload had failed calls or no successful calls")
        expected[name] = attempts
    require(set(expected) == names, "missing fixture ledger function")
    physical, seen = {}, set()
    provider = identity(receipt.get("provider_before"))
    for row in targets:
        name, offset = row.get("name"), row.get("file_offset")
        require(name in names and name not in physical and integer(offset),
                "duplicate, missing or invalid fixture target")
        require(row.get("dev") == list(provider[:2]) and row.get("ino") == provider[2],
                "mapped fixture target differs from independently hashed provider")
        key = (*provider, offset)
        require(key not in seen, "fixture functions share an ambiguous target")
        physical[name] = key
        seen.add(key)
    require(set(physical) == names, "missing fixture target")
    return expected, physical


def common(receipt, cell):
    require(receipt.get("schema") == "p11scope/public-cli-receipt/v1" and
            receipt.get("cell") == cell, "receipt schema or cell mismatch")
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, "missing " + key)
    if cell not in {"run-short", "run-cover"}:
        require(receipt.get("gate_released") is True, "gate was not safely released")
    for key in ("observer_exit", "workload_exit"):
        require(type(receipt.get(key)) is int and receipt[key] == 0, "nonzero or missing " + key)
    generation = receipt.get("generation")
    if generation is not None:
        require(integer(generation) and generation > 0 and
                type(receipt.get("ready_generation")) is int and
                receipt["ready_generation"] == generation, "workload generation changed")
    require(provider_pin(receipt.get("provider_before")) == provider_pin(receipt.get("provider_after")),
            "provider physical identity or hash changed")


def judge(report_text, ledger_text, receipt, cell):
    require(cell in COUNT_CELLS | SMOKE_CELLS, "undeclared cell")
    common(receipt, cell)
    expected, physical = fixture(ledger_text, receipt, cell)
    if cell == "trace-pid":
        require(sum(" → " in line for line in report_text.splitlines()) == sum(expected.values()),
                "trace delivery/count smoke differs from independent ledger")
        raise Nonqualifying("trace delivery/count smoke; text lacks attributable physical targets")
    report = parse(report_text)
    schema = "p11scope/observed-profile/v3-metrics" if cell == "metrics-pid" else "p11scope/observed-profile/v3"
    require(report.get("schema") == schema, "unsupported or wrong cell profile schema")
    mode = "metrics" if cell == "metrics-pid" else "profile"
    require(report.get("lane") == mode and report.get("capture", {}).get("mode") == mode,
            "report lane or capture mode differs from declared cell/schema")
    if cell in {"run-short", "run-cover"}:
        raise Nonqualifying("run report smoke; independently counted first-call completeness remains unproved")
    scope = "system" if cell == "system" else "pid"
    require(receipt.get("scope") == scope and report.get("capture", {}).get("scope") == scope,
            "receipt or report capture scope differs from declared cell")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")
    for key in LOSS_COUNTERS:
        require(type(evidence.get(key)) is int and evidence[key] == 0, "loss or unknown " + key)
    observation = evidence.get("gap_classes", {}).get("observation", {})
    require(observation.get("status") == "exact" and observation.get("causes") == [],
            "lossy or unknown observation gap class")
    kernel = evidence.get("kernel_control", {})
    require(kernel.get("capture_halted") is False and kernel.get("owner_poison") == [] and
            kernel.get("root_affiliation_failures") == [], "kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        require(type(kernel.get(key)) is int and kernel[key] == 0, "kernel loss or unknown " + key)
    terminal(evidence, profile=mode == "profile")
    provider = identity(receipt["provider_before"])
    admitted = evidence.get("discovery")
    require(isinstance(admitted, list) and any(identity(row) == provider for row in admitted
            if isinstance(row, dict) and row.get("sha256") is not None), "owned provider not admitted")
    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    observed = {}
    unknown = []
    uncertainty = []
    for row in rows:
        ownership(row)
        require(integer(row.get("calls")), "invalid function count")
        require(isinstance(row.get("names"), list) and all(isinstance(name, str) for name in row["names"]),
                "invalid function names")
        for counter in ("errors", "in_flight", "pending_returns"):
            require(integer(row.get(counter)), "invalid function return counter: " + counter)
        target = row.get("target")
        require(isinstance(target, dict) and integer(target.get("file_offset")), "invalid physical target")
        obj = target.get("object")
        if obj is None:
            unknown.append(row)
            uncertainty.append("missing physical target identity; counts are unattributable")
            continue
        key = (*identity(obj), target["file_offset"])
        require(key not in observed, "duplicate observed physical target")
        observed[key] = row
    if receipt.get("count_domain") != "owned-provider":
        uncertainty.append("shared or unknown count domain; provider totals cannot prove per-caller coverage")
    # Definite contradictions and coverage failures have priority over uncertainty.
    # A null-object row at the expected offset can only keep identity unknown; it
    # never supplies a qualifying match and never excuses a known row's deficit.
    for name, key in physical.items():
        if key not in observed:
            possible = [row for row in unknown if row["target"]["file_offset"] == key[-1]]
            require(any(row["calls"] == expected[name] and name in row["names"] and
                        all(row[counter] == 0 for counter in ("errors", "in_flight", "pending_returns"))
                        for row in possible), "missing owned physical target: " + name)
            continue
        row = observed[key]
        require(type(row.get("calls")) is int and row["calls"] == expected[name],
                "owned target count differs from independent ledger: " + name)
        for counter in ("errors", "in_flight", "pending_returns"):
            require(type(row.get(counter)) is int and row[counter] == 0,
                    "owned target has failed or unsettled returns: " + name)
        require(isinstance(row.get("names"), list) and name in row["names"],
                "physical target semantic name differs: " + name)
        owner = ownership(row)
        if owner is None:
            uncertainty.append("shared, unresolved or unpinned module count domain: " + name)
        else:
            require(owner == provider, "owned target has a different publishing module: " + name)
    if uncertainty:
        raise Nonqualifying("; ".join(dict.fromkeys(uncertainty)))
    if cell == "verdict-pid":
        require(evidence.get("completeness") in {"COMPLETE", "PARTIAL"} and
                evidence.get("verdict_detail") in {"clean_proven", "attribution_only", "clean_but_unproven"},
                "missing or inconsistent clean capture verdict")
        require((evidence["completeness"] == "COMPLETE") == (evidence["verdict_detail"] == "clean_proven"),
                "completeness conflicts with terminal verdict")
        return "verdict-consistency", "clean owned target verdict is consistent"
    if cell == "names-pid":
        return "semantic-names", "six independent physical targets carry expected semantic names"
    return "owned-provider-counts", ("owned physical-provider counts match independent successful ledger; "
                                     "per-caller attribution is not established")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("report", "ledger", "receipt", "cell"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        qualification, detail = judge(read(Path(args.report)), read(Path(args.ledger)),
                                      parse(read(Path(args.receipt))), args.cell)
        result.update({"pass": True, "qualification": qualification, "detail": detail})
        code = 0
    except Nonqualifying as error:
        result.update(qualification="nonqualifying", detail=str(error))
        code = 2
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError, AssertionError) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
