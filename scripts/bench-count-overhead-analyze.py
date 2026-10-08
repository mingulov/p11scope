#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Counting-overhead ABBA analysis (Stage 2 M2 cost gate).

Reads a scripts/bench-count-overhead.sh campaign log: MACHINE/BINARY header
lines plus one SAMPLE line per valid sample, and prints the per-cell
with/without comparison (median ns/call + min..max spread), the paired
median delta with a bootstrap 95% CI, the BPF run-time corroboration, a
drift check, and a verdict against the M2 bar.

Pairing: within a (cell, round) the i-th on sample pairs with the i-th off
sample in log order (adjacent under the ABBA/BAAB round order). The M2 bar
(binding, r1 plan section 4 M2-c7) passes a cell when the paired median
V1-BASE delta is at most 5% of the BASE observed call cost with the
bootstrap 95% CI upper bound at most 10%, with 0 count errors. The
campaign fails closed on any count mismatch already; the analysis
re-verifies every on-arm edge count from the SAMPLE fields and refuses to
pass otherwise.

Usage:
  scripts/bench-count-overhead-analyze.py LOG [--rel-pct 5.0] [--ci-pct 10.0]
  scripts/bench-count-overhead-analyze.py --self-test

Exit 0 prints the table and verdict. Exit 1 when a cell cannot be compared
(samples missing for an arm, unpaired rounds, mixed attach mechanisms, or
a count mismatch) or the log holds no samples.
"""
import random
import statistics
import sys

BOOTSTRAP_SEED = 20261008
BOOTSTRAP_REPS = 10000


def parse_log(path):
    """Split a campaign log into headers and samples.

    Returns (headers, samples, errors): headers maps MACHINE/BINARY keys
    (BINARY keyed by role), samples is a list of dicts in log order,
    errors lists malformed SAMPLE lines (never silently dropped: the
    caller fails on them).
    """
    headers = {}
    samples = []
    errors = []
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            head, _, rest = line.partition(" ")
            if head == "MACHINE":
                headers["MACHINE"] = rest.strip()
                continue
            if head == "BINARY":
                fields = dict(
                    token.split("=", 1) for token in rest.split() if "=" in token
                )
                role = fields.get("role", "?")
                headers[f"BINARY:{role}"] = rest.strip()
                continue
            if head != "SAMPLE":
                continue
            try:
                fields = dict(
                    token.split("=", 1) for token in rest.split() if "=" in token
                )
                sample = {
                    "cell": fields["cell"],
                    "arm": fields["arm"],
                    "round": int(fields["round"]),
                    "threads": int(fields["threads"]),
                    "ops": int(fields["ops"]),
                    "wall_ns": int(fields["wall_ns"]),
                    "pad": int(fields["pad"]),
                    "mode": fields["mode"],
                    "parallel": int(fields["parallel"]),
                    "lane": fields["lane"],
                    "edge_count": None if fields["edge_count"] == "none" else int(fields["edge_count"]),
                    "edge_expected": None if fields["edge_expected"] == "none" else int(fields["edge_expected"]),
                    "edge_state": fields["edge_state"],
                    "bpf_ns": None if fields["bpf_ns"] == "none" else int(fields["bpf_ns"]),
                    "bpf_cnt": None if fields["bpf_cnt"] == "none" else int(fields["bpf_cnt"]),
                    "lineno": lineno,
                }
            except (KeyError, ValueError) as error:
                errors.append(f"line {lineno}: {error}: {line[:200]}")
                continue
            if (
                sample["arm"] not in ("on", "off", "unobserved")
                or sample["mode"] not in ("call", "mmap")
                or sample["lane"] not in ("multi", "singles", "none")
                or sample["edge_state"] not in ("counted", "witnessed", "none")
                or sample["ops"] <= 0
                or sample["wall_ns"] <= 0
                or sample["parallel"] <= 0
                or sample["threads"] <= 0
                or sample["round"] <= 0
                or sample["pad"] not in (0, 1)
            ):
                errors.append(f"line {lineno}: out-of-range fields: {line[:200]}")
                continue
            if (sample["bpf_ns"] is None) != (sample["bpf_cnt"] is None):
                errors.append(f"line {lineno}: half-present bpf pair: {line[:200]}")
                continue
            if (sample["edge_count"] is None) != (sample["edge_expected"] is None):
                errors.append(f"line {lineno}: half-present edge pair: {line[:200]}")
                continue
            samples.append(sample)
    return headers, samples, errors


def unit_ns(sample):
    """Normalized cost: ns per call (call churn over threads) or ns per op."""
    if sample["mode"] == "call":
        return sample["wall_ns"] * sample["threads"] / sample["ops"]
    return sample["wall_ns"] / sample["ops"]


def unit_label(cell_samples):
    return "ns/call" if cell_samples[0]["mode"] == "call" else "ns/op"


def summarize(values):
    """Median + spread of a non-empty unit list."""
    return {
        "n": len(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def paired_deltas(cell_samples):
    """Per-round i-th-on minus i-th-off deltas in log order.

    Returns (deltas, problem): deltas is the flat pair list, problem names
    a round whose arms do not pair (fail closed).
    """
    deltas = []
    rounds = sorted({s["round"] for s in cell_samples if s["arm"] in ("on", "off")})
    for rnd in rounds:
        on = [s for s in cell_samples if s["round"] == rnd and s["arm"] == "on"]
        off = [s for s in cell_samples if s["round"] == rnd and s["arm"] == "off"]
        if len(on) != len(off) or not on:
            return [], f"round {rnd}: on={len(on)} off={len(off)} samples do not pair"
        for a, b in zip(on, off):
            deltas.append(unit_ns(a) - unit_ns(b))
    return deltas, ""


def bootstrap_median_ci(deltas, seed=BOOTSTRAP_SEED, reps=BOOTSTRAP_REPS):
    """Bootstrap 95% CI of the median delta (deterministic seed)."""
    rng = random.Random(seed)
    n = len(deltas)
    medians = []
    for _ in range(reps):
        medians.append(statistics.median(rng.choice(deltas) for _ in range(n)))
    medians.sort()
    lo = medians[int(0.025 * reps)]
    hi = medians[int(0.975 * reps) - 1]
    return lo, hi


def analyze(samples, rel_bar, ci_bar):
    """Per-cell comparison. Returns (rows, problems).

    rows holds one dict per cell with on/off/unobserved summaries, the
    paired median delta with its bootstrap CI, absolute + relative
    overhead, bpf corroboration and drift; problems lists cells that
    cannot be compared or whose gates do not re-verify.
    """
    rows = []
    problems = []
    cells = sorted({sample["cell"] for sample in samples})
    for cell in cells:
        cell_samples = [s for s in samples if s["cell"] == cell]
        modes = {s["mode"] for s in cell_samples}
        if len(modes) != 1:
            problems.append(f"cell {cell}: mixed modes {sorted(modes)}")
            continue
        on = [unit_ns(s) for s in cell_samples if s["arm"] == "on"]
        off = [unit_ns(s) for s in cell_samples if s["arm"] == "off"]
        bare = [unit_ns(s) for s in cell_samples if s["arm"] == "unobserved"]
        if not on or not off:
            problems.append(f"cell {cell}: on={len(on)} off={len(off)} samples")
            continue
        # Attach mechanism must not differ across arms: a multi/singles
        # split would confound the counting delta with trap cost.
        lanes = {s["lane"] for s in cell_samples if s["arm"] in ("on", "off")}
        if len(lanes) != 1 or lanes == {"none"}:
            problems.append(f"cell {cell}: mixed lane mechanisms {sorted(lanes)}")
            continue
        # Count-exactness re-verification: every relevant on-sample edge
        # count must equal its expectation with state counted; every
        # relevant off-sample must read witnessed.
        mode = cell_samples[0]["mode"]
        for s in cell_samples:
            if s["arm"] == "unobserved":
                continue
            if mode == "call":
                if s["arm"] == "on" and (
                    s["edge_state"] != "counted" or s["edge_count"] != s["edge_expected"]
                ):
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: count {s['edge_count']} "
                        f"!= expected {s['edge_expected']} ({s['edge_state']})"
                    )
                if s["arm"] == "off" and s["edge_state"] != "witnessed":
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: off-arm state "
                        f"{s['edge_state']}, want witnessed"
                    )
            elif s["edge_state"] != "none":
                problems.append(
                    f"cell {cell}: line {s['lineno']}: map-cell edge state "
                    f"{s['edge_state']}, want none"
                )
        if problems and problems[-1].startswith(f"cell {cell}: line"):
            continue
        deltas, pairing = paired_deltas(cell_samples)
        if pairing:
            problems.append(f"cell {cell}: {pairing}")
            continue
        if len(deltas) < 2:
            problems.append(f"cell {cell}: only {len(deltas)} pair(s), need >= 2")
            continue
        on_summary = summarize(on)
        off_summary = summarize(off)
        bare_summary = summarize(bare) if bare else None
        absolute = on_summary["median"] - off_summary["median"]
        relative = 100.0 * absolute / off_summary["median"]
        paired_median = statistics.median(deltas)
        ci_lo, ci_hi = bootstrap_median_ci(deltas)
        paired_rel = 100.0 * paired_median / off_summary["median"]
        ci_rel_hi = 100.0 * ci_hi / off_summary["median"]
        bpf = {}
        for arm in ("on", "off"):
            arm_bpf = [
                (s["bpf_ns"], s["bpf_cnt"], s["ops"])
                for s in cell_samples
                if s["arm"] == arm and s["bpf_ns"] is not None
            ]
            total_ns = sum(ns for ns, _, _ in arm_bpf)
            total_cnt = sum(cnt for _, cnt, _ in arm_bpf)
            total_ops = sum(ops for _, _, ops in arm_bpf)
            bpf[arm] = {
                "ns_per_call": total_ns / total_ops if total_ops else None,
                "ns_per_event": total_ns / total_cnt if total_cnt else None,
                "events_per_op": total_cnt / total_ops if total_ops else None,
                "samples": len(arm_bpf),
            }
        # Drift: off-arm medians of the first vs second half in log order.
        off_ordered = [
            unit_ns(s) for s in cell_samples if s["arm"] == "off"
        ]
        half = len(off_ordered) // 2
        drift = None
        if half > 0:
            first = statistics.median(off_ordered[:half])
            second = statistics.median(off_ordered[half:])
            drift = 100.0 * (second - first) / first
        material = paired_rel > rel_bar or ci_rel_hi > ci_bar
        rows.append(
            {
                "cell": cell,
                "mode": mode,
                "lane": sorted(lanes)[0],
                "on": on_summary,
                "off": off_summary,
                "bare": bare_summary,
                "absolute_ns": absolute,
                "relative_pct": relative,
                "paired_median_ns": paired_median,
                "paired_rel_pct": paired_rel,
                "ci_lo_ns": ci_lo,
                "ci_hi_ns": ci_hi,
                "ci_rel_hi_pct": ci_rel_hi,
                "pairs": len(deltas),
                "bpf": bpf,
                "drift_pct": drift,
                "material": material,
            }
        )
    return rows, problems


def report(headers, rows, rel_bar, ci_bar):
    """Render the comparison table plus the verdict; returns the verdict."""
    lines = []
    if "MACHINE" in headers:
        lines.append(f"machine: {headers['MACHINE']}")
    for key in sorted(k for k in headers if k.startswith("BINARY:")):
        lines.append(f"binary[{key.split(':', 1)[1]}]: {headers[key]}")
    lines.append(
        f"m2 bar: paired median V1-BASE <= {rel_bar:g}% of BASE observed call "
        f"cost and bootstrap 95% CI upper <= {ci_bar:g}%, 0 count errors"
    )
    exact = 0
    for row in rows:
        on, off = row["on"], row["off"]
        unit = "ns/call" if row["mode"] == "call" else "ns/op"
        lines.append(f"cell {row['cell']} (lane {row['lane']}, {row['pairs']} pairs):")
        lines.append(
            f"  off n={off['n']} median={off['median']:.1f} "
            f"min..max={off['min']:.1f}..{off['max']:.1f} {unit}"
        )
        lines.append(
            f"  on  n={on['n']} median={on['median']:.1f} "
            f"min..max={on['min']:.1f}..{on['max']:.1f} {unit}"
        )
        if row["bare"] is not None:
            bare = row["bare"]
            lines.append(
                f"  unobserved n={bare['n']} median={bare['median']:.1f} "
                f"min..max={bare['min']:.1f}..{bare['max']:.1f} {unit}"
            )
        else:
            lines.append("  unobserved: no baseline samples")
        lines.append(
            f"  overhead (medians) {row['absolute_ns']:+.1f} {unit} "
            f"({row['relative_pct']:+.2f}%)"
        )
        lines.append(
            f"  paired median {row['paired_median_ns']:+.1f} {unit} "
            f"({row['paired_rel_pct']:+.2f}%), 95% CI "
            f"[{row['ci_lo_ns']:+.1f}, {row['ci_hi_ns']:+.1f}] "
            f"(upper {row['ci_rel_hi_pct']:+.2f}%)"
        )
        for arm in ("on", "off"):
            arm_bpf = row["bpf"][arm]
            if arm_bpf["ns_per_event"] is not None:
                lines.append(
                    f"  bpf[{arm}]: {arm_bpf['ns_per_call']:.1f} {unit} program time "
                    f"over {arm_bpf['events_per_op']:.2f} events/op "
                    f"({arm_bpf['ns_per_event']:.1f} ns/event, "
                    f"{arm_bpf['samples']} samples)"
                )
            elif arm_bpf["samples"]:
                lines.append(f"  bpf[{arm}]: no entry firings (idle, as designed)")
            else:
                lines.append(f"  bpf[{arm}]: no entry run-time samples")
        if row["drift_pct"] is not None:
            lines.append(f"  off-arm drift {row['drift_pct']:+.2f}% (2nd vs 1st half)")
        lines.append(f"  verdict: {'MATERIAL' if row['material'] else 'immaterial'}")
        exact += on["n"]
    material = [row["cell"] for row in rows if row["material"]]
    if material:
        lines.append(f"OVERALL: MATERIAL ({', '.join(material)})")
    else:
        lines.append("OVERALL: immaterial on every cell")
    gate = "FAIL" if material else "PASS"
    lines.append(f"M2 gate: {gate} (0 count errors across {exact} on-arm samples)")
    return "\n".join(lines) + "\n"


def main(argv):
    args = list(argv)
    if args and args[0] == "--self-test":
        if len(args) != 1:
            print("usage: bench-count-overhead-analyze.py --self-test", file=sys.stderr)
            return 2
        self_test()
        return 0
    rel_bar, ci_bar, positional = 5.0, 10.0, []
    index = 0
    while index < len(args):
        if args[index] == "--rel-pct" and index + 1 < len(args):
            rel_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--ci-pct" and index + 1 < len(args):
            ci_bar = float(args[index + 1])
            index += 2
        elif args[index].startswith("--"):
            print(f"unknown flag {args[index]}", file=sys.stderr)
            return 2
        else:
            positional.append(args[index])
            index += 1
    if len(positional) != 1:
        print(
            "usage: bench-count-overhead-analyze.py LOG "
            "[--rel-pct PCT] [--ci-pct PCT]",
            file=sys.stderr,
        )
        return 2
    headers, samples, errors = parse_log(positional[0])
    if errors:
        for error in errors:
            print(f"malformed sample: {error}", file=sys.stderr)
        return 1
    if not samples:
        print("no samples in the log", file=sys.stderr)
        return 1
    rows, problems = analyze(samples, rel_bar, ci_bar)
    if problems:
        for problem in problems:
            print(f"cannot compare: {problem}", file=sys.stderr)
        return 1
    sys.stdout.write(report(headers, rows, rel_bar, ci_bar))
    return 0


def self_test():
    """Pinned-numbers checks over synthetic logs."""
    import os
    import tempfile

    def sample(cell, arm, rnd, threads, ops, wall, **kw):
        base = {
            "pad": 0, "mode": "call", "parallel": 1, "lane": "multi",
            "edge_count": "none", "edge_expected": "none", "edge_state": "none",
            "bpf_ns": "none", "bpf_cnt": "none",
        }
        base.update(kw)
        return (
            f"SAMPLE cell={cell} arm={arm} round={rnd} threads={threads} "
            f"ops={ops} wall_ns={wall} pad={base['pad']} mode={base['mode']} "
            f"parallel={base['parallel']} lane={base['lane']} "
            f"edge_count={base['edge_count']} edge_expected={base['edge_expected']} "
            f"edge_state={base['edge_state']} bpf_ns={base['bpf_ns']} "
            f"bpf_cnt={base['bpf_cnt']}\n"
        )

    # ABBA round (on off off on) + BAAB round, 1 thread, 1000 ns/call base.
    log = "MACHINE kernel=7.0 test-cpu nproc=12\n"
    log += "BINARY role=candidate path=/tmp/c sha256=aaa commit=c0ffee\n"
    log += "BINARY role=base path=/tmp/b sha256=bbb commit=ba5e\n"
    # Round 1 ABBA: on=1100, off=1000, off=1000, on=1100 (counted exact).
    log += sample("relevant-call-t1", "on", 1, 1, 1000, 1100000,
                  edge_count=1003, edge_expected=1003, edge_state="counted",
                  bpf_ns=200000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "off", 1, 1, 1000, 1000000,
                  edge_state="witnessed", bpf_ns=150000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "off", 1, 1, 1000, 1000000,
                  edge_state="witnessed", bpf_ns=150000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "on", 1, 1, 1000, 1100000,
                  edge_count=1003, edge_expected=1003, edge_state="counted",
                  bpf_ns=200000, bpf_cnt=1000)
    # Round 2 BAAB: off=1020, on=1120, on=1120, off=1020.
    log += sample("relevant-call-t1", "off", 2, 1, 1000, 1020000,
                  edge_state="witnessed", bpf_ns=150000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "on", 2, 1, 1000, 1120000,
                  edge_count=1003, edge_expected=1003, edge_state="counted",
                  bpf_ns=200000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "on", 2, 1, 1000, 1120000,
                  edge_count=1003, edge_expected=1003, edge_state="counted",
                  bpf_ns=200000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "off", 2, 1, 1000, 1020000,
                  edge_state="witnessed", bpf_ns=150000, bpf_cnt=1000)
    log += sample("relevant-call-t1", "unobserved", 1, 1, 1000, 900000, lane="none")
    log += sample("relevant-call-t1", "unobserved", 2, 1, 1000, 900000, lane="none")
    with tempfile.TemporaryDirectory(prefix="count-analyze-") as work:
        path = os.path.join(work, "campaign.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(log)
        headers, samples, errors = parse_log(path)
        assert not errors, errors
        assert len(samples) == 10, len(samples)
        assert headers["BINARY:candidate"].endswith("commit=c0ffee")
        rows, problems = analyze(samples, 5.0, 10.0)
        assert not problems, problems
        assert len(rows) == 1
        row = rows[0]
        # on median 1110, off median 1010 over 4 samples each.
        assert row["on"]["median"] == 1110.0, row["on"]
        assert row["off"]["median"] == 1010.0, row["off"]
        assert row["absolute_ns"] == 100.0, row["absolute_ns"]
        # Pairs: r1 (1100-1000)x2, r2 (1120-1020)x2 -> median 100.
        assert row["pairs"] == 4, row["pairs"]
        assert row["paired_median_ns"] == 100.0, row["paired_median_ns"]
        assert abs(row["paired_rel_pct"] - 100.0 * 100.0 / 1010.0) < 1e-9
        # Bootstrap CI is deterministic and contains the median.
        lo2, hi2 = bootstrap_median_ci([100.0] * 4)
        assert (row["ci_lo_ns"], row["ci_hi_ns"]) == (lo2, hi2)
        assert row["ci_lo_ns"] <= 100.0 <= row["ci_hi_ns"]
        # 9.9% paired median over the 5% bar reads MATERIAL.
        assert row["material"], "9.9% must read MATERIAL"
        assert row["lane"] == "multi"
        assert row["bpf"]["on"]["ns_per_event"] == 200.0
        assert row["bpf"]["off"]["ns_per_event"] == 150.0
        assert row["bare"]["median"] == 900.0
        text = report(headers, rows, 5.0, 10.0)
        assert "OVERALL: MATERIAL (relevant-call-t1)" in text, text
        assert "M2 gate: FAIL (0 count errors across 4 on-arm samples)" in text, text
        # A quiet log (1% delta) reads immaterial with gate PASS.
        quiet = log.replace("wall_ns=1100000", "wall_ns=1010000").replace(
            "wall_ns=1120000", "wall_ns=1030000"
        )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(quiet)
        _, quiet_samples, quiet_errors = parse_log(path)
        assert not quiet_errors
        quiet_rows, _ = analyze(quiet_samples, 5.0, 10.0)
        assert not quiet_rows[0]["material"], "1% must read immaterial"
        assert "M2 gate: PASS" in report(headers, quiet_rows, 5.0, 10.0)
        # Failure modes fail, never pass quietly.
        bad_pair = log + sample("relevant-call-t1", "on", 3, 1, 1000, 1100000,
                                edge_count=1003, edge_expected=1003,
                                edge_state="counted")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(bad_pair)
        _, bad_samples, _ = parse_log(path)
        _, problems = analyze(bad_samples, 5.0, 10.0)
        assert any("do not pair" in p for p in problems), problems
        bad_lane = log.replace("lane=multi", "lane=singles", 1)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(bad_lane)
        _, lane_samples, _ = parse_log(path)
        _, problems = analyze(lane_samples, 5.0, 10.0)
        assert any("mixed lane" in p for p in problems), problems
        bad_count = log.replace("edge_count=1003", "edge_count=1002", 1)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(bad_count)
        _, count_samples, _ = parse_log(path)
        _, problems = analyze(count_samples, 5.0, 10.0)
        assert any("!= expected" in p for p in problems), problems
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("SAMPLE cell=x arm=maybe round=1 threads=1 ops=1 wall_ns=2 pad=0 mode=call parallel=1 lane=multi edge_count=none edge_expected=none edge_state=none bpf_ns=none bpf_cnt=none\n")
        _, _, bad = parse_log(path)
        assert bad, "a bad arm must be reported"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("MACHINE nothing here\n")
        _, empty, _ = parse_log(path)
        assert not empty
    print("bench-count-overhead-analyze self-test: OK")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

