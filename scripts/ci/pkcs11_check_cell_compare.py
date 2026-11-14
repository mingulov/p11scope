#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Compare pkcs11-check legs for the CI cell (scripts/ci/pkcs11-check-cell.sh).

Three legs run the same pkcs11-check selection against fresh SoftHSM tokens:
(a) alone, (b) under `p11scope run` (default, no manifest), (c) under
`p11scope run --manifest`. This helper judges the hard checks:

- identical pkcs11-check result sets across a/b/c (summary counts, per-unit
  statuses, and per-test when=call outcomes from report.jsonl);
- observer clean (exits match the base leg, observed.json valid v3);
- leg (c) oracle subset (teardown rv-trace calls ⊆ captured counts);
- leg (b) default coverage ratio vs a pinned floor, or a named
  expected-failure when slot exhaustion blinds the default capture.

It writes results.jsonl (four cells) and summary.txt, prints details, and
exits 0 when every qualified row passes, 1 when a qualified check fails,
2 on harness errors. PINs never appear in outputs.
"""

import argparse
import json
import sys
from pathlib import Path

PINNED_VERSION = "0.2.3"
# Suffix of the known oracle-side misattribution node (docs/notes/phase4-oracle.md):
# test_v32_interface_negotiated carries test_v30's trace. Matched by suffix so
# venv and source-checkout prefixes both work.
MISATTRIBUTED_SUFFIX = (
    "test_interface.py::TestInterfaceV32::test_v32_interface_negotiated"
)
# Summary keys compared exactly; child_crash/child_timeout are recorded but
# not gated (v070 showed 3 vs 2 with identical outcome sets).
SUMMARY_KEYS = (
    "passed", "failed", "skipped", "xfailed", "xpassed", "error",
    "crashed", "timeout", "crash_limited", "total", "incomplete",
)
COUNT_KEYS = (
    "passed", "failed", "skipped", "xfailed", "xpassed", "error",
    "crashed", "timeout", "crash_limited",
)


def fail(message):
    print(f"pkcs11_check_cell_compare: {message}", file=sys.stderr)
    return 2


def load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing {what}: {path}")
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {what} {path}: {error}")


def normalize_nodeid(nodeid):
    """Strip the venv/checkout prefix, keeping from testcases/ on."""
    marker = "testcases/"
    at = nodeid.find(marker)
    if at >= 0:
        return nodeid[at:]
    return nodeid.rsplit("/", 1)[-1]


def call_outcomes(report_path):
    """{normalized nodeid: outcome} for when=call TestReports."""
    outcomes = {}
    with open(report_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("$report_type") != "TestReport":
                continue
            if record.get("when") != "call":
                continue
            nodeid = normalize_nodeid(str(record.get("nodeid", "")))
            outcomes[nodeid] = str(record.get("outcome", ""))
    return outcomes


def compare_outcomes(base, other):
    only_base = sorted(set(base) - set(other))
    only_other = sorted(set(other) - set(base))
    diff = sorted(
        node for node in set(base) & set(other) if base[node] != other[node]
    )
    return only_base, only_other, diff


def unit_map(results):
    """{basename(target): (status, counts tuple, returncode)} per unit."""
    units = {}
    for unit in results.get("units", []):
        target = str(unit.get("target", ""))
        name = target.rsplit("/", 1)[-1]
        counts = tuple(int(unit.get("counts", {}).get(key, 0)) for key in COUNT_KEYS)
        units[name] = (str(unit.get("status", "")), counts, unit.get("returncode"))
    return units


def compare_results(base_path, other_path, label):
    """Compare two results.json files; return (ok, detail, info)."""
    base = load_json(base_path, f"{label} base results")
    other = load_json(other_path, f"{label} other results")
    problems = []
    # Pinned framework version on both sides.
    for name, doc in (("base", base), ("other", other)):
        version = doc.get("provenance", {}).get("framework", {}).get("version")
        if version != PINNED_VERSION:
            problems.append(f"{name} framework version {version!r} != {PINNED_VERSION}")
    base_summary = base.get("summary", {})
    other_summary = other.get("summary", {})
    for key in SUMMARY_KEYS:
        if base_summary.get(key) != other_summary.get(key):
            problems.append(
                f"summary {key}: base {base_summary.get(key)!r} != "
                f"other {other_summary.get(key)!r}"
            )
    base_units = unit_map(base)
    other_units = unit_map(other)
    if set(base_units) != set(other_units):
        missing = sorted(set(base_units) - set(other_units))
        extra = sorted(set(other_units) - set(base_units))
        if missing:
            problems.append(f"units only in base: {', '.join(missing[:5])}")
        if extra:
            problems.append(f"units only in other: {', '.join(extra[:5])}")
    for name in sorted(set(base_units) & set(other_units)):
        base_status, base_counts, _ = base_units[name]
        other_status, other_counts, _ = other_units[name]
        if base_status != other_status or base_counts != other_counts:
            problems.append(f"unit {name}: base {(base_status, base_counts)} != other {(other_status, other_counts)}")
    info = (
        f"summary total={base_summary.get('total')} "
        f"passed={base_summary.get('passed')} failed={base_summary.get('failed')} "
        f"units={len(base_units)}; "
        f"child_crash base={base_summary.get('child_crash')} "
        f"other={other_summary.get('child_crash')} "
        f"(informational); "
        f"child_timeout base={base_summary.get('child_timeout')} "
        f"other={other_summary.get('child_timeout')} (informational)"
    )
    detail = info if not problems else info + "; " + "; ".join(problems[:5])
    return not problems, detail


def oracle_counts(report_path):
    """{(fn, rv_hex): count} from teardown rv-traces, with stats."""
    oracle = {}
    tests_with_trace = 0
    excluded = 0
    with open(report_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("when") != "teardown":
                continue
            props = dict(record.get("user_properties") or [])
            trace = props.get("pkcs11_rv_trace")
            if trace is None:
                continue
            nodeid = str(record.get("nodeid", ""))
            if nodeid.endswith(MISATTRIBUTED_SUFFIX):
                excluded += 1
                continue
            tests_with_trace += 1
            for entry in trace:
                key = (entry["fn"], f"0x{entry['rv'] & 0xffffffffffffffff:016x}")
                oracle[key] = oracle.get(key, 0) + 1
    return oracle, tests_with_trace, excluded


def capture_counts(observed_path):
    """({(fn, rv_hex): count}, {fn: calls}, observed doc) from observed.json."""
    observed = load_json(observed_path, "observed profile")
    capture = {}
    by_name = {}
    for function in observed.get("functions", []):
        for name in function.get("names", []):
            by_name[name] = by_name.get(name, 0) + int(function.get("calls", 0))
            for rv_hex, count in function.get("rv_counts", {}).items():
                key = (name, rv_hex)
                capture[key] = capture.get(key, 0) + int(count)
    return capture, by_name, observed


def subset_check(oracle, capture):
    """(mismatches, call_recall, pair_recall, oracle_calls)."""
    oracle_calls = sum(oracle.values())
    if oracle_calls == 0:
        return None, 0.0, 0.0, 0
    mismatches = []
    covered = 0
    satisfied = 0
    for key, want in sorted(oracle.items()):
        got = capture.get(key, 0)
        covered += min(got, want)
        if got >= want:
            satisfied += 1
        else:
            mismatches.append((key, want, got))
    call_recall = covered / oracle_calls
    pair_recall = satisfied / len(oracle) if oracle else 0.0
    return mismatches, call_recall, pair_recall, oracle_calls


def slot_exhaustion_evidence(observed):
    """True when the report names 512-slot refusal/retirement."""
    skipped = observed.get("modules_skipped", [])
    text = json.dumps(skipped)
    return (
        "512 attach slots" in text
        and ("retired" in text or "refusing" in text)
    )


def zero_probe_blindness(observed):
    """True when default discovery attached nothing on short-lived workers.

    Scan-only discovery without a manifest can miss every worker when they
    exit before the scan corroborates them: 0 probes, 0 functions, PARTIAL
    with named pid_descendant_gaps. The report is honest (gaps named, not
    silent zeros), but coverage is 0.
    """
    evidence = observed.get("evidence", {})
    return (
        evidence.get("attached_probes", -1) == 0
        and len(observed.get("functions", [])) == 0
        and int(evidence.get("pid_descendant_gaps", 0)) > 0
        and evidence.get("completeness") == "PARTIAL"
    )


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "full"), required=True)
    parser.add_argument("--results-a", required=True)
    parser.add_argument("--report-a", required=True)
    parser.add_argument("--exit-a", required=True, type=int)
    parser.add_argument("--wall-a", required=True, type=float)
    parser.add_argument("--results-b", required=True)
    parser.add_argument("--report-b", required=True)
    parser.add_argument("--exit-b", required=True, type=int)
    parser.add_argument("--wall-b", required=True, type=float)
    parser.add_argument("--observed-b", required=True)
    parser.add_argument("--results-c", required=True)
    parser.add_argument("--report-c", required=True)
    parser.add_argument("--exit-c", required=True, type=int)
    parser.add_argument("--wall-c", required=True, type=float)
    parser.add_argument("--observed-c", required=True)
    parser.add_argument("--floor", required=True, type=float)
    parser.add_argument("--out-results", required=True)
    parser.add_argument("--out-summary", required=True)
    args = parser.parse_args(argv)

    try:
        # Identical results across a/b/c.
        ok_ab, detail_ab = compare_results(args.results_a, args.results_b, "a-vs-b")
        ok_ac, detail_ac = compare_results(args.results_a, args.results_c, "a-vs-c")
        outcomes_a = call_outcomes(args.report_a)
        outcomes_b = call_outcomes(args.report_b)
        outcomes_c = call_outcomes(args.report_c)
        only_ab, only_ba, diff_ab = compare_outcomes(outcomes_a, outcomes_b)
        only_ac, only_ca, diff_ac = compare_outcomes(outcomes_a, outcomes_c)
        outcomes_ok = not (only_ab or only_ba or diff_ab or only_ac or only_ca or diff_ac)
        identical_ok = ok_ab and ok_ac and outcomes_ok
        identical_detail = (
            f"results a-vs-b {'match' if ok_ab else 'DIFFER'}; "
            f"a-vs-c {'match' if ok_ac else 'DIFFER'}; "
            f"when=call outcomes n={len(outcomes_a)} "
            f"only_base_b={len(only_ab)} only_b={len(only_ba)} diff_b={len(diff_ab)} "
            f"only_base_c={len(only_ac)} only_c={len(only_ca)} diff_c={len(diff_ac)}"
        )
        if not ok_ab:
            identical_detail += f"; b: {detail_ab[:200]}"
        if not ok_ac:
            identical_detail += f"; c: {detail_ac[:200]}"
        print(f"identical-results: {'PASS' if identical_ok else 'FAIL'} {identical_detail}")

        # Observer clean: exits match base, observed.json valid v3.
        capture_c, _, observed_c = capture_counts(args.observed_c)
        capture_b, _, observed_b = capture_counts(args.observed_b)
        schema_b = observed_b.get("schema", "")
        schema_c = observed_c.get("schema", "")
        schema_ok = schema_b == "p11scope/observed-profile/v3" and schema_c == schema_b
        if args.mode == "smoke":
            exits_ok = args.exit_a == 0 and args.exit_b == 0 and args.exit_c == 0
            exits_detail = f"exits a/b/c={args.exit_a}/{args.exit_b}/{args.exit_c} (smoke wants 0/0/0)"
        else:
            exits_ok = args.exit_b == args.exit_a and args.exit_c == args.exit_a
            exits_detail = (
                f"exits a/b/c={args.exit_a}/{args.exit_b}/{args.exit_c} "
                f"(full wants b==a and c==a)"
            )
        observer_ok = exits_ok and schema_ok
        observer_detail = (
            f"{exits_detail}; observed schemas b/c={schema_b}/{schema_c} "
            f"(results.json present on all legs proves no SIGKILL abort)"
        )
        print(f"observer-clean: {'PASS' if observer_ok else 'FAIL'} {observer_detail}")

        # Leg (c) oracle subset.
        oracle_c, traced_c, excluded_c = oracle_counts(args.report_c)
        mismatches_c, recall_c, pair_c, total_c = subset_check(oracle_c, capture_c)
        if mismatches_c is None:
            manifest_ok = False
            manifest_detail = "oracle logged 0 calls (vacuous)"
        else:
            manifest_ok = not mismatches_c
            manifest_detail = (
                f"oracle {total_c} calls in {len(oracle_c)} (fn,rv) pairs "
                f"({traced_c} tests, {excluded_c} misattributed excluded); "
                f"call_recall={recall_c:.4f} pair_recall={pair_c:.4f}; "
                f"mismatches={len(mismatches_c)}"
            )
            for (fn, rv), want, got in mismatches_c[:5]:
                manifest_detail += f"; {fn} {rv}: want {want} got {got}"
        print(f"manifest-exact: {'PASS' if manifest_ok else 'FAIL'} {manifest_detail}")

        # Leg (b) default coverage vs floor.
        oracle_b, traced_b, excluded_b = oracle_counts(args.report_b)
        mismatches_b, recall_b, pair_b, total_b = subset_check(oracle_b, capture_b)
        if mismatches_b is None:
            coverage_ok = False
            coverage_expected = False
            coverage_detail = "oracle logged 0 calls (vacuous)"
        else:
            exhausted = slot_exhaustion_evidence(observed_b)
            zero_probe = zero_probe_blindness(observed_b)
            coverage_detail = (
                f"default call_recall={recall_b:.4f} pair_recall={pair_b:.4f} "
                f"oracle={total_b} calls ({traced_b} tests, {excluded_b} excluded) "
                f"floor={args.floor:.2f} slot_exhaustion={exhausted} "
                f"zero_probe={zero_probe}"
            )
            if recall_b >= args.floor:
                coverage_ok = True
                coverage_expected = False
            elif recall_b < 0.05 and (exhausted or zero_probe):
                coverage_ok = False
                coverage_expected = True
                if exhausted:
                    reason = (
                        "512 slots retired then re-admission refused"
                    )
                else:
                    gaps = observed_b.get("evidence", {}).get("pid_descendant_gaps", 0)
                    reason = (
                        f"scan-only discovery attached 0 probes on short-lived "
                        f"workers (pid_descendant_gaps={gaps}, PARTIAL)"
                    )
                coverage_detail += (
                    f" (named expected-failure: default capture blind, {reason}; "
                    f"identical results + no abort still hold)"
                )
            else:
                coverage_ok = False
                coverage_expected = False
        print(
            f"default-coverage: {'PASS' if coverage_ok else 'EXPECTED-FAIL' if coverage_expected else 'FAIL'} "
            f"{coverage_detail}"
        )

        # Overhead (informational, never gated).
        overhead_b = args.wall_b - args.wall_a
        overhead_c = args.wall_c - args.wall_a
        print(
            f"wall: a={args.wall_a:.1f}s b={args.wall_b:.1f}s c={args.wall_c:.1f}s; "
            f"overhead b-a={overhead_b:+.1f}s c-a={overhead_c:+.1f}s"
        )

        rows = [
            {"cell": "pkcs11-check-identical-results", "pass": identical_ok,
             "qualification": "qualified", "detail": identical_detail[:500]},
            {"cell": "pkcs11-check-observer-clean", "pass": observer_ok,
             "qualification": "qualified", "detail": observer_detail[:500]},
            {"cell": "pkcs11-check-manifest-exact", "pass": manifest_ok,
             "qualification": "qualified", "detail": manifest_detail[:500]},
            {"cell": "pkcs11-check-default-coverage",
             "pass": coverage_ok,
             "qualification": "expected-failure" if coverage_expected else "qualified",
             "detail": coverage_detail[:500]},
        ]
        Path(args.out_results).write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
        )
        summary = (
            f"mode={args.mode} pinned pkcs11-check {PINNED_VERSION}\n"
            f"identical-results: {'PASS' if identical_ok else 'FAIL'}\n"
            f"observer-clean: {'PASS' if observer_ok else 'FAIL'}\n"
            f"manifest-exact: {'PASS' if manifest_ok else 'FAIL'}\n"
            f"default-coverage: {'PASS' if coverage_ok else 'EXPECTED-FAIL' if coverage_expected else 'FAIL'}\n"
            f"wall a/b/c={args.wall_a:.1f}/{args.wall_b:.1f}/{args.wall_c:.1f}s "
            f"overhead b-a={overhead_b:+.1f}s c-a={overhead_c:+.1f}s\n"
        )
        Path(args.out_summary).write_text(summary, encoding="utf-8")
        print(summary, end="")

        qualified_fail = (
            not identical_ok or not observer_ok or not manifest_ok
            or (not coverage_ok and not coverage_expected)
        )
        return 1 if qualified_fail else 0
    except SystemExit as error:
        return fail(str(error))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return fail(f"harness error: {error}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
