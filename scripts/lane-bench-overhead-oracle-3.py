#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bench-overhead coverage oracle: prove each observed sample counted the workload.

Exit 0 means the sample is VALID (exact equal coverage). Exit 10 means the
report is well-formed but its count differs from the workload truth: the
sample is INVALID and must not enter the statistics. Exit 1 means the report
is missing or malformed (harness failure, fails the run).

Subcommands (all unprivileged, all fail closed):
  profile <report.json> <expected_generaterandom>
  trace <trace.txt> <expected_total>
  hammer <hammer.log> <expected_n> <expected_w>
  --self-test
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

VALID = 0
INVALID_COVERAGE = 10
ERROR = 1

HAMMER_OK_RE = re.compile(r"^hammer OK: (\d+) C_GenerateRandom calls$")
HAMMER_WARMUP_RE = re.compile(r"^hammer warm-up: (\d+) C_GenerateRandom calls$")


def fail(message):
    print(f"bench-overhead coverage: {message}", file=sys.stderr)
    return ERROR


def check_profile(path, expected):
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except FileNotFoundError:
        return fail(f"missing profile report: {path}")
    except (OSError, ValueError) as error:
        return fail(f"unreadable profile report {path}: {error}")
    if not isinstance(report, dict):
        return fail(f"profile report is not an object: {path}")
    evidence = report.get("evidence")
    if not isinstance(evidence, dict):
        return fail(f"profile report lacks evidence: {path}")
    probes = evidence.get("attached_probes")
    if not isinstance(probes, int) or isinstance(probes, bool):
        return fail(f"profile report lacks integer attached_probes: {path}")
    if probes <= 0:
        return fail(f"profile report shows no attached probes: {path}")
    functions = report.get("functions")
    if not isinstance(functions, list):
        return fail(f"profile report lacks functions[]: {path}")
    total = 0
    for entry in functions:
        if not isinstance(entry, dict):
            return fail(f"profile functions[] entry is not an object: {path}")
        names = entry.get("names") or []
        calls = entry.get("calls")
        if "C_GenerateRandom" in names:
            if not isinstance(calls, int) or isinstance(calls, bool) or calls < 0:
                return fail(f"profile C_GenerateRandom calls is not a count: {path}")
            total += calls
    if total != expected:
        print(
            f"bench-overhead coverage: INVALID profile sample: "
            f"observer counted {total} C_GenerateRandom calls, "
            f"workload truth is {expected}",
            file=sys.stderr,
        )
        return INVALID_COVERAGE
    return VALID


def check_trace(path, expected):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = [line.rstrip("\n") for line in handle]
    except FileNotFoundError:
        return fail(f"missing trace file: {path}")
    except OSError as error:
        return fail(f"unreadable trace file {path}: {error}")
    lines = [line for line in lines if line != ""]
    if not lines or not lines[0].startswith("CAPTURE "):
        return fail(f"trace stream must open with the CAPTURE header: {path}")
    if not lines[-1].startswith("EVIDENCE "):
        return fail(f"trace stream must close with the EVIDENCE record: {path}")
    count_evidence = None
    evidence = None
    for line in lines:
        if line.startswith("TRUNCATED "):
            return fail(f"trace stream is truncated (unexpected at bench size): {path}")
        if line.startswith("COUNT_EVIDENCE "):
            if count_evidence is not None:
                return fail(f"duplicate COUNT_EVIDENCE record: {path}")
            try:
                count_evidence = json.loads(line[len("COUNT_EVIDENCE "):])
            except ValueError as error:
                return fail(f"malformed COUNT_EVIDENCE: {error}: {path}")
        elif line.startswith("EVIDENCE "):
            if evidence is not None:
                return fail(f"duplicate EVIDENCE record: {path}")
            try:
                evidence = json.loads(line[len("EVIDENCE "):])
            except ValueError as error:
                return fail(f"malformed EVIDENCE: {error}: {path}")
    if count_evidence is None:
        return fail(f"trace stream lacks the COUNT_EVIDENCE record: {path}")
    if evidence is None:
        return fail(f"trace stream lacks the EVIDENCE record: {path}")
    if not isinstance(evidence, dict):
        return fail(f"trace EVIDENCE is not an object: {path}")
    probes = evidence.get("attached_probes")
    if not isinstance(probes, int) or isinstance(probes, bool):
        return fail(f"trace EVIDENCE lacks integer attached_probes: {path}")
    if probes <= 0:
        return fail(f"trace EVIDENCE shows no attached probes: {path}")
    if evidence.get("trace_truncated") is True:
        return fail(f"trace EVIDENCE reports truncation: {path}")
    returned = count_evidence.get("stats_returned")
    if not isinstance(returned, int) or isinstance(returned, bool):
        return fail(f"COUNT_EVIDENCE lacks integer stats_returned: {path}")
    if returned != expected:
        print(
            f"bench-overhead coverage: INVALID trace sample: "
            f"observer counted {returned} total calls, workload truth is {expected}",
            file=sys.stderr,
        )
        return INVALID_COVERAGE
    return VALID


def check_hammer(path, expected_n, expected_w):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = [line.rstrip("\n") for line in handle]
    except FileNotFoundError:
        return fail(f"missing hammer log: {path}")
    except OSError as error:
        return fail(f"unreadable hammer log {path}: {error}")
    seen_n = None
    seen_w = None
    for line in lines:
        ok_match = HAMMER_OK_RE.match(line)
        if ok_match is not None:
            seen_n = int(ok_match.group(1))
        warmup_match = HAMMER_WARMUP_RE.match(line)
        if warmup_match is not None:
            seen_w = int(warmup_match.group(1))
    if seen_n is None:
        return fail(f"hammer log lacks its OK count line: {path}")
    if seen_n != expected_n:
        return fail(f"hammer ran {seen_n} main calls, want {expected_n}: {path}")
    if expected_w > 0 and seen_w != expected_w:
        return fail(f"hammer ran {seen_w} warm-up calls, want {expected_w}: {path}")
    return VALID


def self_test():
    here = Path(__file__).resolve()
    cases = []

    def profile_doc(*, calls_rows, probes=136):
        return {
            "schema": "p11scope/observed-profile/v2",
            "evidence": {"attached_probes": probes, "completeness": "PARTIAL"},
            "functions": [
                {"names": names, "calls": calls} for names, calls in calls_rows
            ],
        }

    def trace_text(*, returned, probes=136, truncated=False, with_counts=True,
                   with_capture=True, with_evidence=True):
        lines = []
        if with_capture:
            lines.append("CAPTURE privacy=allowlisted")
        lines.append("12:00:01.000000 pid 1 tid 1 C_GenerateRandom \u2192 CKR_OK 1.0\u00b5s")
        if truncated:
            lines.append("TRUNCATED at 1 events (--max-events 1)")
        if with_counts:
            lines.append(f"COUNT_EVIDENCE {json.dumps({'stats_entered': returned, 'stats_returned': returned, 'raw_calls': 1})}")
        if with_evidence:
            lines.append(f"EVIDENCE {json.dumps({'attached_probes': probes, 'completeness': 'PARTIAL', 'trace_truncated': truncated})}")
        return "\n".join(lines) + "\n"

    cases.append(("profile valid", "profile", json.dumps(profile_doc(calls_rows=[(["C_Initialize"], 1), (["C_GenerateRandom"], 1000)])), ["1000"], VALID))
    cases.append(("profile off-by-one rejected", "profile", json.dumps(profile_doc(calls_rows=[(["C_GenerateRandom"], 999)])), ["1000"], INVALID_COVERAGE))
    cases.append(("profile unobserved-as-observed rejected", "profile", json.dumps(profile_doc(calls_rows=[(["C_GenerateRandom"], 0)])), ["1000"], INVALID_COVERAGE))
    cases.append(("profile malformed fails", "profile", "{not json", ["1000"], ERROR))
    cases.append(("profile missing functions fails", "profile", json.dumps({"evidence": {"attached_probes": 2}}), ["1000"], ERROR))
    cases.append(("profile zero probes fails", "profile", json.dumps(profile_doc(calls_rows=[(["C_GenerateRandom"], 1000)], probes=0)), ["1000"], ERROR))
    cases.append(("profile missing row rejected", "profile", json.dumps(profile_doc(calls_rows=[(["C_Initialize"], 5)])), ["1000"], INVALID_COVERAGE))
    cases.append(("profile multi-row sum valid", "profile", json.dumps(profile_doc(calls_rows=[(["C_GenerateRandom"], 600), (["C_GenerateRandom"], 400)])), ["1000"], VALID))
    cases.append(("trace valid", "trace", trace_text(returned=1005), ["1005"], VALID))
    cases.append(("trace short count rejected", "trace", trace_text(returned=5), ["1005"], INVALID_COVERAGE))
    cases.append(("trace missing counts fails", "trace", trace_text(returned=1005, with_counts=False), ["1005"], ERROR))
    cases.append(("trace missing capture fails", "trace", trace_text(returned=1005, with_capture=False), ["1005"], ERROR))
    cases.append(("trace missing evidence fails", "trace", trace_text(returned=1005, with_evidence=False), ["1005"], ERROR))
    cases.append(("trace truncated fails", "trace", trace_text(returned=1005, truncated=True), ["1005"], ERROR))
    cases.append(("trace zero probes fails", "trace", trace_text(returned=1005, probes=0), ["1005"], ERROR))
    cases.append(("hammer two-phase valid", "hammer", "hammer OK: 1000 C_GenerateRandom calls\nhammer warm-up: 100 C_GenerateRandom calls\n", ["1000", "100"], VALID))
    cases.append(("hammer single-phase valid", "hammer", "hammer OK: 1000 C_GenerateRandom calls\n", ["1000", "0"], VALID))
    cases.append(("hammer wrong main fails", "hammer", "hammer OK: 999 C_GenerateRandom calls\n", ["1000", "0"], ERROR))
    cases.append(("hammer wrong warm-up fails", "hammer", "hammer OK: 1000 C_GenerateRandom calls\nhammer warm-up: 99 C_GenerateRandom calls\n", ["1000", "100"], ERROR))
    cases.append(("hammer empty fails", "hammer", "", ["1000", "0"], ERROR))

    with tempfile.TemporaryDirectory(prefix="p11scope-bench-oracle3-") as work:
        for label, kind, body, args, want in cases:
            target = Path(work) / "case.txt"
            target.write_text(body, encoding="utf-8")
            got = subprocess.run(
                [sys.executable, "-I", str(here), kind, str(target), *args],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).returncode
            if got != want:
                raise SystemExit(f"self-test case failed: {label}: exit {got}, want {want}")
        missing = Path(work) / "absent.txt"
        for label, argv, want in [
            ("profile missing report fails", ["profile", str(missing), "1000"], ERROR),
            ("trace missing report fails", ["trace", str(missing), "1005"], ERROR),
            ("hammer missing log fails", ["hammer", str(missing), "1000", "0"], ERROR),
        ]:
            got = subprocess.run(
                [sys.executable, "-I", str(here), *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).returncode
            if got != want:
                raise SystemExit(f"self-test case failed: {label}: exit {got}, want {want}")
    print("lane-bench-overhead-oracle-3 self-test: OK")


def main(argv):
    if argv[1:] in (["--help"], ["-h"]):
        argparse.ArgumentParser(description=__doc__).print_help()
        return 0
    if argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(argv) == 4 and argv[1] == "profile":
        return check_profile(argv[2], int(argv[3]))
    if len(argv) == 4 and argv[1] == "trace":
        return check_trace(argv[2], int(argv[3]))
    if len(argv) == 5 and argv[1] == "hammer":
        return check_hammer(argv[2], int(argv[3]), int(argv[4]))
    print(f"usage: {argv[0]} profile <report.json> <expected> | trace <trace.txt> <expected> | hammer <log> <n> <w> | --self-test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
