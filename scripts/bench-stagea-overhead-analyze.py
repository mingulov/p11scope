#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage A overhead ABBA analysis (Task 1d).

Reads a scripts/bench-stagea-overhead.sh campaign log: MACHINE/BINARY header
lines plus one SAMPLE line per valid sample, and prints the per-cell
with/without comparison (median ns/op + min..max spread), the absolute and
relative overhead, the BPF run-time corroboration, a drift check, and a
verdict against the materiality bar.

Usage:
  scripts/bench-stagea-overhead-analyze.py LOG [--rel-pct 5.0] [--abs-ns 1000.0]
  scripts/bench-stagea-overhead-analyze.py --self-test

Exit 0 prints the table and verdict. Exit 1 when a cell cannot be compared
(samples missing for an arm) or the log holds no samples.
"""
import statistics
import sys


def parse_log(path):
    """Split a campaign log into headers and samples.

    Returns (headers, samples, errors): headers maps MACHINE/BINARY keys,
    samples is a list of dicts in log order, errors lists malformed SAMPLE
    lines (never silently dropped: the caller fails on them).
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
            if head in ("MACHINE", "BINARY"):
                headers[head] = rest.strip()
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
                    "ops": int(fields["ops"]),
                    "wall_ns": int(fields["wall_ns"]),
                    "mode": fields["mode"],
                    "parallel": int(fields["parallel"]),
                    "bpf_ns": None if fields["bpf_ns"] == "none" else int(fields["bpf_ns"]),
                    "bpf_cnt": None if fields["bpf_cnt"] == "none" else int(fields["bpf_cnt"]),
                    "lineno": lineno,
                }
            except (KeyError, ValueError) as error:
                errors.append(f"line {lineno}: {error}: {line[:160]}")
                continue
            if (
                sample["arm"] not in ("on", "off")
                or sample["ops"] <= 0
                or sample["wall_ns"] <= 0
                or sample["parallel"] <= 0
                or sample["round"] <= 0
            ):
                errors.append(f"line {lineno}: out-of-range fields: {line[:160]}")
                continue
            if (sample["bpf_ns"] is None) != (sample["bpf_cnt"] is None):
                errors.append(f"line {lineno}: half-present bpf pair: {line[:160]}")
                continue
            samples.append(sample)
    return headers, samples, errors


def summarize(values):
    """Median + spread of a non-empty ns/op list."""
    return {
        "n": len(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def analyze(samples, rel_bar, abs_bar):
    """Per-cell comparison. Returns (rows, problems).

    rows holds one dict per cell with on/off summaries, absolute + relative
    overhead, bpf corroboration and drift; problems lists cells that cannot
    be compared (an arm with no samples).
    """
    rows = []
    problems = []
    cells = sorted({sample["cell"] for sample in samples})
    for cell in cells:
        on = [
            sample["wall_ns"] / sample["ops"]
            for sample in samples
            if sample["cell"] == cell and sample["arm"] == "on"
        ]
        off = [
            sample["wall_ns"] / sample["ops"]
            for sample in samples
            if sample["cell"] == cell and sample["arm"] == "off"
        ]
        if not on or not off:
            problems.append(f"cell {cell}: on={len(on)} off={len(off)} samples")
            continue
        on_summary = summarize(on)
        off_summary = summarize(off)
        absolute = on_summary["median"] - off_summary["median"]
        relative = 100.0 * absolute / off_summary["median"]
        bpf = [
            (sample["bpf_ns"], sample["bpf_cnt"], sample["ops"])
            for sample in samples
            if sample["cell"] == cell
            and sample["arm"] == "on"
            and sample["bpf_ns"] is not None
        ]
        bpf_ns_per_event = (
            sum(ns for ns, _, _ in bpf) / sum(cnt for _, cnt, _ in bpf)
            if bpf and sum(cnt for _, cnt, _ in bpf) > 0
            else None
        )
        bpf_events_per_op = (
            sum(cnt for _, cnt, _ in bpf) / sum(ops for _, _, ops in bpf)
            if bpf
            else None
        )
        # Drift: off-arm medians of the first vs second half in log order.
        off_ordered = [
            sample["wall_ns"] / sample["ops"]
            for sample in samples
            if sample["cell"] == cell and sample["arm"] == "off"
        ]
        half = len(off_ordered) // 2
        drift = None
        if half > 0:
            first = statistics.median(off_ordered[:half])
            second = statistics.median(off_ordered[half:])
            drift = 100.0 * (second - first) / first
        material = relative > rel_bar or absolute > abs_bar
        rows.append(
            {
                "cell": cell,
                "on": on_summary,
                "off": off_summary,
                "absolute_ns": absolute,
                "relative_pct": relative,
                "bpf_ns_per_event": bpf_ns_per_event,
                "bpf_events_per_op": bpf_events_per_op,
                "bpf_samples": len(bpf),
                "drift_pct": drift,
                "material": material,
            }
        )
    return rows, problems


def report(headers, rows, rel_bar, abs_bar):
    """Render the comparison table plus the verdict; returns the verdict."""
    lines = []
    if "MACHINE" in headers:
        lines.append(f"machine: {headers['MACHINE']}")
    if "BINARY" in headers:
        lines.append(f"binary: {headers['BINARY']}")
    lines.append(
        f"materiality bar: relative > {rel_bar:g}% or absolute > {abs_bar:g} ns/op"
    )
    for row in rows:
        on, off = row["on"], row["off"]
        lines.append(f"cell {row['cell']}:")
        lines.append(
            f"  off n={off['n']} median={off['median']:.1f} "
            f"min..max={off['min']:.1f}..{off['max']:.1f} ns/op"
        )
        lines.append(
            f"  on  n={on['n']} median={on['median']:.1f} "
            f"min..max={on['min']:.1f}..{on['max']:.1f} ns/op"
        )
        lines.append(
            f"  overhead {row['absolute_ns']:+.1f} ns/op "
            f"({row['relative_pct']:+.2f}%)"
        )
        if row["bpf_ns_per_event"] is not None:
            lines.append(
                f"  bpf: {row['bpf_ns_per_event']:.1f} ns/hook-event over "
                f"{row['bpf_events_per_op']:.2f} events/op "
                f"({row['bpf_samples']} samples)"
            )
        else:
            lines.append("  bpf: no hook run-time samples")
        if row["drift_pct"] is not None:
            lines.append(f"  off-arm drift {row['drift_pct']:+.2f}% (2nd vs 1st half)")
        lines.append(f"  verdict: {'MATERIAL' if row['material'] else 'immaterial'}")
    material = [row["cell"] for row in rows if row["material"]]
    if material:
        lines.append(f"OVERALL: MATERIAL ({', '.join(material)})")
    else:
        lines.append("OVERALL: immaterial on every cell")
    return "\n".join(lines) + "\n"


def main(argv):
    args = list(argv)
    if args and args[0] == "--self-test":
        if len(args) != 1:
            print("usage: bench-stagea-overhead-analyze.py --self-test", file=sys.stderr)
            return 2
        self_test()
        return 0
    rel_bar, abs_bar, positional = 5.0, 1000.0, []
    index = 0
    while index < len(args):
        if args[index] == "--rel-pct" and index + 1 < len(args):
            rel_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--abs-ns" and index + 1 < len(args):
            abs_bar = float(args[index + 1])
            index += 2
        elif args[index].startswith("--"):
            print(f"unknown flag {args[index]}", file=sys.stderr)
            return 2
        else:
            positional.append(args[index])
            index += 1
    if len(positional) != 1:
        print(
            "usage: bench-stagea-overhead-analyze.py LOG "
            "[--rel-pct PCT] [--abs-ns NS]",
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
    rows, problems = analyze(samples, rel_bar, abs_bar)
    if problems:
        for problem in problems:
            print(f"cannot compare: {problem}", file=sys.stderr)
        return 1
    sys.stdout.write(report(headers, rows, rel_bar, abs_bar))
    return 0


def self_test():
    """Pinned-numbers checks over synthetic logs."""
    import os
    import tempfile

    log = """MACHINE kernel=7.0 test-cpu nproc=12
BINARY path=/tmp/p sha256=abc
SAMPLE cell=relevant-mmap arm=off round=1 ops=1000 wall_ns=4000000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none
SAMPLE cell=relevant-mmap arm=on round=1 ops=1000 wall_ns=4100000 mode=mmap parallel=1 bpf_ns=160000 bpf_cnt=2000
SAMPLE cell=relevant-mmap arm=on round=2 ops=1000 wall_ns=4300000 mode=mmap parallel=1 bpf_ns=170000 bpf_cnt=2050
SAMPLE cell=relevant-mmap arm=off round=2 ops=1000 wall_ns=4200000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none
SAMPLE cell=unrelated-mmap arm=off round=1 ops=1000 wall_ns=4000000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none
SAMPLE cell=unrelated-mmap arm=on round=1 ops=1000 wall_ns=4020000 mode=mmap parallel=1 bpf_ns=140000 bpf_cnt=2010
SAMPLE cell=unrelated-mmap arm=on round=2 ops=1000 wall_ns=4040000 mode=mmap parallel=1 bpf_ns=150000 bpf_cnt=1990
SAMPLE cell=unrelated-mmap arm=off round=2 ops=1000 wall_ns=4000000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none
"""
    with tempfile.TemporaryDirectory(prefix="stagea-analyze-") as work:
        path = os.path.join(work, "campaign.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(log)
        headers, samples, errors = parse_log(path)
        assert not errors, errors
        assert len(samples) == 8, len(samples)
        assert headers["MACHINE"] == "kernel=7.0 test-cpu nproc=12"
        rows, problems = analyze(samples, 5.0, 1000.0)
        assert not problems, problems
        assert [row["cell"] for row in rows] == ["relevant-mmap", "unrelated-mmap"]
        relevant = rows[0]
        assert relevant["off"]["median"] == 4100.0, relevant["off"]
        assert relevant["on"]["median"] == 4200.0, relevant["on"]
        assert relevant["absolute_ns"] == 100.0, relevant["absolute_ns"]
        assert abs(relevant["relative_pct"] - 100.0 * 100.0 / 4100.0) < 1e-9
        assert relevant["bpf_samples"] == 2
        assert abs(relevant["bpf_ns_per_event"] - 330000.0 / 4050.0) < 1e-9
        assert abs(relevant["bpf_events_per_op"] - 4050.0 / 2000.0) < 1e-9
        assert abs(relevant["drift_pct"] - 5.0) < 1e-9, relevant["drift_pct"]
        assert not relevant["material"], "100ns/2.4% must read immaterial"
        unrelated = rows[1]
        assert unrelated["absolute_ns"] == 30.0, unrelated["absolute_ns"]
        assert not unrelated["material"]
        text = report(headers, rows, 5.0, 1000.0)
        assert "OVERALL: immaterial on every cell" in text, text
        assert "overhead +100.0 ns/op (+2.44%)" in text, text
        # A cell over the relative bar reads MATERIAL.
        hot = log.replace(
            "cell=relevant-mmap arm=on round=1 ops=1000 wall_ns=4100000",
            "cell=relevant-mmap arm=on round=1 ops=1000 wall_ns=4500000",
        ).replace(
            "cell=relevant-mmap arm=on round=2 ops=1000 wall_ns=4300000",
            "cell=relevant-mmap arm=on round=2 ops=1000 wall_ns=4500000",
        )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(hot)
        _, hot_samples, hot_errors = parse_log(path)
        assert not hot_errors
        hot_rows, _ = analyze(hot_samples, 5.0, 1000.0)
        assert hot_rows[0]["material"], "400ns/9.8% must read MATERIAL"
        assert "OVERALL: MATERIAL (relevant-mmap)" in report(headers, hot_rows, 5.0, 1000.0)
        # Missing arm, malformed lines and empty logs fail, never pass quietly.
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("SAMPLE cell=x arm=on round=1 ops=1 wall_ns=2 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n")
        _, one_arm, _ = parse_log(path)
        _, problems = analyze(one_arm, 5.0, 1000.0)
        assert problems, "a cell with one arm must not compare"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("SAMPLE cell=x arm=maybe round=1 ops=1 wall_ns=2 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n")
        _, _, bad = parse_log(path)
        assert bad, "a bad arm must be reported"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("MACHINE nothing here\n")
        _, empty, _ = parse_log(path)
        assert not empty
    print("bench-stagea-overhead-analyze self-test: OK")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
