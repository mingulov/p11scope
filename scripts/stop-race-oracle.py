#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge stop-race sweep trials and newcomer-burst runs against ledgers.

A sweep trial stops one capture with SIGINT at a seeded offset and judges:
the exit is a clean stop, a report is published, owned counts never exceed
the independent workload ledger (and equal it when the ledger finished
before the signal), the stop receipt printed (cleanup completed for
profile/run, the native-stopped line for inventory), nothing panicked, and
no storage refusal appeared unless one was injected. The seed and offset
ride along in every detail string so a failing trial replays with --seed.

The burst judges one `profile --system` run whose last 300 ms started 32
short-lived processes: the long workload stays exact, each provider
newcomer is either counted or covered by the named pending counter, and
`pending > 0` never coexists with `exact`.
"""

import argparse
import json
from pathlib import Path
import re
import runpy
import sys

BASE = runpy.run_path(str(Path(__file__).with_name("public-cli-oracle.py")))
require = BASE["require"]
parse = BASE["parse"]
read = BASE["read"]
integer = BASE["integer"]
identity = BASE["identity"]
ownership = BASE["ownership"]
provider_pin = BASE["provider_pin"]
NAMES = BASE["NAMES"]
LOSS_COUNTERS = BASE["LOSS_COUNTERS"]
VERDICT = BASE["VERDICT"]

PROFILE_COMMANDS = {"profile-pid": "pid", "profile-system": "system", "run": "pid"}
SWEEP_COMMANDS = set(PROFILE_COMMANDS) | {"inventory-system"}
STORAGE_REFUSAL = "provider_storage_refused"
# Call-path loss is never a newcomer backlog: dropped or unsettled calls are
# real loss in every branch. Discovery-side counters may carry the admission
# backlog itself, so the burst tolerates them only while pending covers every
# uncounted provider newcomer.
CALL_PATH_LOSS = ("event_loss", "start_insert_failures", "unmatched_returns",
                  "rv_update_failures", "cgroup_scope_failures", "abi_refusals",
                  "malformed_records")


EvidenceError = BASE["EvidenceError"]


def workload_ledger(text):
    """Parse TARGET/READY/LEDGER lines; the LEDGER may be partial (racing)."""
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
    require(len(ready) == 1, "missing workload READY")
    require(len(ledgers) == 1, "missing or duplicate LEDGER")
    ledger = ledgers[0]
    require(ledger.get("schema") == "p11scope/public-cli-ledger/v1" and
            ledger.get("pid") == ready[0] and
            ledger.get("complete") in (True, False), "invalid fixture ledger")
    functions = ledger.get("functions")
    require(isinstance(functions, list), "missing ledger functions")
    expected = {}
    for row in functions:
        name = row.get("name")
        require(name in NAMES and name not in expected, "duplicate or unexpected ledger function")
        attempts, successes = row.get("attempts"), row.get("successful")
        require(integer(attempts) and integer(successes) and successes <= attempts,
                "invalid ledger attempts for " + name)
        expected[name] = (attempts, successes)
    require(set(expected) == set(NAMES), "missing fixture ledger function")
    physical = {}
    for row in targets:
        name, offset = row.get("name"), row.get("file_offset")
        require(name in NAMES and name not in physical and integer(offset),
                "duplicate, missing or invalid fixture target")
        physical[name] = offset
    require(set(physical) == set(NAMES), "missing fixture target")
    return expected, physical, targets, ledger["complete"], ready[0]


def pinned_provider(before_text, after_text):
    before, after = provider_pin(parse(before_text)), provider_pin(parse(after_text))
    require(before == after, "provider physical identity or hash changed")
    return before[0]


def check_targets(targets, provider):
    for row in targets:
        require(row.get("dev") == list(provider[:2]) and row.get("ino") == provider[2],
                "mapped fixture target differs from independently hashed provider")


def check_hygiene(stderr_text, report_text, exit_code, allow_storage_refusal):
    require(exit_code == 0, "observer exit is not a clean stop: %r" % exit_code)
    require("cleanup completed" in stderr_text, "missing cleanup-completed line")
    require("panicked" not in stderr_text, "observer panicked")
    if not allow_storage_refusal:
        require(STORAGE_REFUSAL not in stderr_text, "storage refusal on stderr")
        require(STORAGE_REFUSAL not in report_text, "storage refusal in report")


def check_kernel_clean(evidence):
    kernel = evidence.get("kernel_control", {})
    require(kernel.get("capture_halted") is False and kernel.get("owner_poison") == [] and
            kernel.get("root_affiliation_failures") == [], "kernel capture halted or unknown")
    for key in ("owner_admission_failures", "identity_unavailable"):
        require(type(kernel.get(key)) is int and kernel[key] == 0, "kernel loss or unknown " + key)


def join_profile_rows(report, physical, provider):
    rows = report.get("functions")
    require(isinstance(rows, list), "missing functions")
    observed, unknown = {}, []
    for row in rows:
        ownership(row)
        require(integer(row.get("calls")), "invalid function count")
        require(isinstance(row.get("names"), list) and
                all(isinstance(name, str) for name in row["names"]), "invalid function names")
        for counter in ("errors", "in_flight", "pending_returns"):
            require(integer(row.get(counter)), "invalid function return counter: " + counter)
        target = row.get("target")
        require(isinstance(target, dict) and integer(target.get("file_offset")),
                "invalid physical target")
        obj = target.get("object")
        if obj is None:
            unknown.append(row)
            continue
        key = (*identity(obj), target["file_offset"])
        require(key not in observed, "duplicate observed physical target")
        observed[key] = row
    totals = {}
    for name in NAMES:
        key = (*provider, physical[name])
        total = 0
        row = observed.get(key)
        if row is not None:
            total += row["calls"]
        for extra in unknown:
            if extra["target"]["file_offset"] == physical[name]:
                total += extra["calls"]
        totals[name] = (total, row)
    return totals


def judge_profile_counts(report, provider, expected, physical, complete):
    totals = join_profile_rows(report, physical, provider)
    for name in NAMES:
        attempts, successes = expected[name]
        total, row = totals[name]
        if complete:
            require(attempts == successes, "workload had failed calls: " + name)
            require(row is not None, "missing owned physical target: " + name)
            require(row["calls"] == successes,
                    "owned target count differs from independent ledger: " + name)
            require(total == successes, "unattributed counts at owned offset: " + name)
            for counter in ("errors", "in_flight", "pending_returns"):
                require(row[counter] == 0, "owned target has failed or unsettled returns: " + name)
            require(name in row["names"], "physical target semantic name differs: " + name)
            require(ownership(row) == provider,
                    "owned target has a different publishing module: " + name)
        else:
            require(total <= attempts, "owned target count exceeds independent ledger: " + name)
            if row is not None:
                require(ownership(row) == provider,
                        "owned target has a different publishing module: " + name)
    return totals


def check_profile_evidence(report, scope):
    # S3 judges counts plus hygiene; observation class, loss counters,
    # drain proof and kernel flags ride along in the detail (see
    # describe_capture) but never fail a trial by themselves. Live
    # evidence: system scope on a busy host reports lossy via ambient
    # descendant churn while every owned count holds, and `run --pause
    # auto` reports pause windows while the stop itself is clean.
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "unsupported or wrong profile schema")
    require(report.get("lane") == "profile" and
            report.get("capture", {}).get("mode") == "profile", "report is not a profile capture")
    require(report.get("capture", {}).get("scope") == scope, "report scope differs from command")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")
    VERDICT["exact_verdict_classes"](evidence)


def describe_capture(report):
    """Forensic capture facts for sweep details. Reported, never judged."""
    evidence = report.get("evidence", {})
    observation = evidence.get("gap_classes", {}).get("observation", {})
    status = observation.get("status", "?")
    causes = ",".join(observation.get("causes", [])) or "-"
    loss = sorted(key for key in LOSS_COUNTERS
                  if not (type(evidence.get(key)) is int and evidence[key] == 0))
    kernel = evidence.get("kernel_control", {})
    halted = kernel.get("capture_halted", "?")
    return "obs=%s[%s] loss=%s drain=%s khalt=%s" % (
        status, causes, ",".join(loss) or "-", evidence.get("drain_proven", "?"), halted)


def judge_sweep_profile(command, report_text, workload_text, stderr_text, exit_code,
                        ledger_complete, before_text, after_text, allow_storage_refusal):
    check_hygiene(stderr_text, report_text, exit_code, allow_storage_refusal)
    provider = pinned_provider(before_text, after_text)
    expected, physical, targets, _, _ = workload_ledger(workload_text)
    check_targets(targets, provider)
    report = parse(report_text)
    check_profile_evidence(report, PROFILE_COMMANDS[command])
    judge_profile_counts(report, provider, expected, physical, bool(ledger_complete))
    branch = "completeledger-equal" if ledger_complete else "racing-under-or-equal"
    return "stop-race-trial", "%s %s: owned counts hold against the ledger; %s" % (
        command, branch, describe_capture(report))


def judge_sweep_inventory(report_text, workload_text, stderr_text, exit_code,
                          ledger_complete, before_text, after_text, allow_storage_refusal):
    # Inventory drives its own native stop path, not the Detailed link
    # cleanup printer: its positive stop receipt is the native-stopped
    # line (measured on a live --system --manifest stop), plus the same
    # exit/panic/refusal hygiene as the profile commands.
    require(exit_code == 0, "observer exit is not a clean stop: %r" % exit_code)
    require("native capture stopped after " in stderr_text, "missing native-stopped line")
    require("panicked" not in stderr_text, "observer panicked")
    if not allow_storage_refusal:
        require(STORAGE_REFUSAL not in stderr_text, "storage refusal on stderr")
        require(STORAGE_REFUSAL not in report_text, "storage refusal in report")
    provider = pinned_provider(before_text, after_text)
    expected, _, targets, _, workload_pid = workload_ledger(workload_text)
    check_targets(targets, provider)
    report = parse(report_text)
    require(report.get("schema") == "p11scope/inventory/v1", "unsupported or wrong inventory schema")
    modules = {row.get("id"): row.get("identity") for row in report.get("modules", [])}
    owned_modules = {key for key, ident in modules.items()
                     if isinstance(ident, dict) and
                     ident.get("device", {}).get("major") == provider[0] and
                     ident.get("device", {}).get("minor") == provider[1] and
                     ident.get("inode") == provider[2] and
                     ident.get("sha256") == provider[3]}
    require(owned_modules, "owned provider not admitted")
    callers = {row.get("id"): row.get("pid") for row in report.get("callers", [])}
    owned_callers = {key for key, pid in callers.items() if pid == workload_pid}
    require(owned_callers, "workload caller missing from inventory")
    total, unsettled = 0, False
    for edge in report.get("edges", []):
        if edge.get("module") not in owned_modules or edge.get("caller") not in owned_callers:
            continue
        entries = edge.get("entries", {})
        require(integer(entries.get("count")), "invalid inventory edge count")
        require(entries.get("in_flight") in (True, False), "invalid inventory edge flight")
        total += entries["count"]
        unsettled = unsettled or entries["in_flight"]
    attempts = sum(pair[0] for pair in expected.values())
    if ledger_complete:
        require(all(pair[0] == pair[1] for pair in expected.values()),
                "workload had failed calls")
        require(total == attempts, "owned inventory entries differ from independent ledger")
        require(not unsettled, "owned inventory edge still in flight")
        branch = "completeledger-equal"
    else:
        require(total <= attempts, "owned inventory entries exceed independent ledger")
        branch = "racing-under-or-equal"
    return "stop-race-trial", "inventory-system %s: %d owned entries hold" % (branch, total)


def newcomer_pending(report, stderr_text):
    scheduling = report.get("evidence", {}).get("scheduling", {})
    queue = scheduling.get("newcomer_queue", {})
    require(integer(queue.get("pending")), "missing newcomer pending counter")
    match = re.search(r"pending (\d+) \(oldest ([^)]*)\)", stderr_text)
    require(match is not None, "missing newcomer queue timing line")
    require(int(match[1]) == queue["pending"], "stderr pending differs from report pending")
    return queue["pending"]


def judge_burst(report_text, workload_text, stderr_text, exit_code,
                before_text, after_text, newcomer_functions, provider_newcomers):
    require(exit_code == 0, "observer exit is not a clean stop: %r" % exit_code)
    require("cleanup completed" in stderr_text, "missing cleanup-completed line")
    require("panicked" not in stderr_text, "observer panicked")
    require(STORAGE_REFUSAL not in stderr_text, "storage refusal on stderr")
    require(STORAGE_REFUSAL not in report_text, "storage refusal in report")
    require(isinstance(newcomer_functions, list) and newcomer_functions and
            all(name in NAMES for name in newcomer_functions) and
            len(set(newcomer_functions)) == len(newcomer_functions),
            "unknown or duplicate newcomer function")
    require(integer(provider_newcomers) and provider_newcomers > 0,
            "invalid provider newcomer count")
    provider = pinned_provider(before_text, after_text)
    expected, physical, targets, complete, _ = workload_ledger(workload_text)
    require(complete, "long-workload ledger is incomplete")
    check_targets(targets, provider)
    report = parse(report_text)
    require(report.get("schema") == "p11scope/observed-profile/v3",
            "unsupported or wrong profile schema")
    require(report.get("capture", {}).get("scope") == "system", "burst report is not system scope")
    evidence = report.get("evidence")
    require(isinstance(evidence, dict), "missing capture evidence")
    VERDICT["exact_verdict_classes"](evidence)
    for key in CALL_PATH_LOSS:
        require(type(evidence.get(key)) is int and evidence[key] == 0, "call loss: " + key)
    check_kernel_clean(evidence)
    require(evidence.get("drain_proven") is True, "final drain is not proven")
    totals = join_profile_rows(report, physical, provider)
    extras = {}
    for name in NAMES:
        attempts, successes = expected[name]
        require(attempts == successes, "workload had failed calls: " + name)
        total, row = totals[name]
        if row is not None:
            require(ownership(row) == provider,
                    "owned target has a different publishing module: " + name)
            require(row["errors"] == 0, "owned target has failed calls: " + name)
        if name in newcomer_functions:
            extra = total - successes
            require(0 <= extra <= provider_newcomers,
                    "newcomer counts outside the burst population: %s=%d" % (name, extra))
            extras[name] = extra
        else:
            require(total == successes,
                    "long-workload count differs from independent ledger: " + name)
            if row is not None:
                for counter in ("in_flight", "pending_returns"):
                    require(row[counter] == 0,
                            "long-workload target has unsettled returns: " + name)
    pending = newcomer_pending(report, stderr_text)
    observation = evidence.get("gap_classes", {}).get("observation", {})
    if pending > 0:
        require(observation.get("status") != "exact", "pending coexists with exact observation")
        for name, extra in extras.items():
            require(extra + pending >= provider_newcomers,
                    "provider newcomers neither counted nor pending: %s" % name)
        branch = "pending-covered"
    else:
        require(observation.get("status") == "exact" and observation.get("causes") == [],
                "lossy observation with no pending newcomers")
        for key in LOSS_COUNTERS:
            require(type(evidence.get(key)) is int and evidence[key] == 0,
                    "loss or unknown " + key)
        for name, extra in extras.items():
            require(extra == provider_newcomers,
                    "provider newcomers missing with none pending: %s" % name)
        branch = "exact-all-counted"
    return ("newcomer-burst",
            "system burst %s: newcomer fns=%d pending=%d" % (branch, len(extras), pending))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("sweep", "burst"))
    parser.add_argument("--command", required=True,
                        choices=sorted(SWEEP_COMMANDS | {"profile-system"}))
    parser.add_argument("--report", required=True)
    parser.add_argument("--workload", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--exit", required=True, type=int)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--offset-ms", required=True)
    parser.add_argument("--ledger-complete", required=True, choices=("0", "1"))
    parser.add_argument("--provider-before", required=True)
    parser.add_argument("--provider-after", required=True)
    parser.add_argument("--newcomer-function", default="C_GenerateRandom")
    parser.add_argument("--provider-newcomers", default=16, type=int)
    parser.add_argument("--allow-storage-refusal", action="store_true")
    args = parser.parse_args(argv)
    seed = "seed=%s offset_ms=%s ledger_complete=%s" % (args.seed, args.offset_ms,
                                                        args.ledger_complete)
    result = {"cell": "", "pass": False, "detail": "", "qualification": "failed"}
    try:
        report_text = read(Path(args.report))
        workload_text = read(Path(args.workload))
        stderr_text = read(Path(args.stderr))
        before_text = read(Path(args.provider_before))
        after_text = read(Path(args.provider_after))
        if args.mode == "burst":
            require(args.command == "profile-system", "burst runs profile --system only")
            result["cell"] = "system-newcomer-burst"
            qualification, detail = judge_burst(
                report_text, workload_text, stderr_text, args.exit,
                before_text, after_text, args.newcomer_function.split(","),
                args.provider_newcomers)
        elif args.command == "inventory-system":
            result["cell"] = "stop-race-sweep.inventory-system"
            qualification, detail = judge_sweep_inventory(
                report_text, workload_text, stderr_text, args.exit,
                args.ledger_complete == "1", before_text, after_text,
                args.allow_storage_refusal)
        else:
            require(args.command in PROFILE_COMMANDS, "undeclared sweep command")
            result["cell"] = "stop-race-sweep." + args.command
            qualification, detail = judge_sweep_profile(
                args.command, report_text, workload_text, stderr_text, args.exit,
                args.ledger_complete == "1", before_text, after_text,
                args.allow_storage_refusal)
        result.update({"pass": True, "qualification": qualification,
                       "detail": "%s; %s" % (seed, detail)})
        code = 0
    except (EvidenceError, BASE["Nonqualifying"], OSError, ValueError,
            TypeError, KeyError, AttributeError, AssertionError) as error:
        result["detail"] = "%s; %s" % (seed, error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
