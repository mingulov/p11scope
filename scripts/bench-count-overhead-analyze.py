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
recomputes every on-arm expectation from the workload denominator
(ops + 2*threads + 1) and refuses to pass unless both logged fields
match it.

Expected shape (A:DR-T3A-13): the log must hold exactly the five M2
cells, each under its exact workload (mode, threads, padding bound to
the cell name on every arm), each with contiguous rounds 1..R (R >= 10),
each round in strict ABBA (odd) or BAAB (even) on/off order plus exactly
one trailing unobserved baseline. Relevant on-arm counts must equal the
recomputed denominator (None == None is not exactness, and neither is
one log field agreeing with another); every observed arm carries its
independent BPF corroboration, and unobserved samples carry no observed
evidence at all. A reduced or reshaped log renders no verdict.
--cells/--rounds override the required shape for explicitly non-M2 reuse;
the report then names the custom shape instead of the M2 gate.

Denominator reuse (--traced-cost, the R-47 N5 production cost):
each round runs on/unobserved ABBA (odd) or BAAB (even) with no base
arm, and the tool prints one TRACED_COST line per cell (median and
p10/p90 spread of the per-pair observed-minus-unobserved ns per
completed call: wall_ns / total completed calls, without M2's thread
factor). Each line names the unit, thread count and both arms' total
completed calls. Every per-sample gate above still applies; the --rel-pct and
--ci-pct bars belong to the M2 report only.

Usage:
  scripts/bench-count-overhead-analyze.py LOG [--rel-pct 5.0] [--ci-pct 10.0]
      [--cells a,b] [--rounds N] [--traced-cost]
  scripts/bench-count-overhead-analyze.py --self-test

Exit 0 prints the table and verdict. Exit 1 when the shape is not the
required campaign (missing/unexpected cells, a cell off its workload,
short/noncontiguous rounds, scrambled ABBA order), a cell cannot be
compared (unpaired rounds, mixed attach mechanisms, a count mismatch,
missing BPF corroboration) or the log holds no samples.
"""
import random
import statistics
import sys

BOOTSTRAP_SEED = 20261008
BOOTSTRAP_REPS = 10000
M2_CELLS = ("relevant-call-t1", "relevant-call-t4", "relevant-call-t12",
            "relevant-call-t12-nolock", "unrelated-mmap")
M2_ROUNDS = 10
# Exact workload each M2 cell name establishes (scripts/bench-count-overhead.sh
# run_call_sample/run_map_sample): mode, worker threads and counter padding.
# ops/wall_ns stay measured per sample; everything else about the workload is
# pinned by the name on every arm.
M2_WORKLOADS = {
    "relevant-call-t1": {"mode": "call", "threads": 1, "pad": 0},
    "relevant-call-t4": {"mode": "call", "threads": 4, "pad": 0},
    "relevant-call-t12": {"mode": "call", "threads": 12, "pad": 0},
    "relevant-call-t12-nolock": {"mode": "call", "threads": 12, "pad": 1},
    "unrelated-mmap": {"mode": "mmap", "threads": 1, "pad": 0},
}


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


def traced_percentile(ordered, pct):
    """Linear-interpolation percentile of a sorted non-empty list."""
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct / 100.0
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


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


def paired_traced_deltas(cell_samples):
    """Per-round i-th-on minus i-th-unobserved deltas in log order.

    Returns (deltas, problem): deltas is the flat pair list, problem names
    a round whose arms do not pair (fail closed).
    """
    deltas = []
    rounds = sorted({s["round"] for s in cell_samples
                     if s["arm"] in ("on", "unobserved")})
    for rnd in rounds:
        on = [s for s in cell_samples if s["round"] == rnd and s["arm"] == "on"]
        bare = [s for s in cell_samples if s["round"] == rnd
                and s["arm"] == "unobserved"]
        if len(on) != len(bare) or not on:
            return [], (f"round {rnd}: on={len(on)} unobserved={len(bare)} "
                        "samples do not pair")
        for a, b in zip(on, bare):
            # N5 divides elapsed time by total completed calls, so its
            # production denominator must use that same unit. M2's
            # per-thread normalization in unit_ns remains separate.
            deltas.append(a["wall_ns"] / a["ops"] - b["wall_ns"] / b["ops"])
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


def analyze(samples, rel_bar, ci_bar, required_cells=M2_CELLS, required_rounds=M2_ROUNDS):
    """Per-cell comparison. Returns (rows, problems).

    rows holds one dict per cell with on/off/unobserved summaries, the
    paired median delta with its bootstrap CI, absolute + relative
    overhead, bpf corroboration and drift; problems lists cells that
    cannot be compared or whose gates do not re-verify. The log must
    hold exactly the required cells in the required ABBA/BAAB shape;
    anything less renders no verdict.
    """
    rows = []
    problems = []
    cells = sorted({sample["cell"] for sample in samples})
    missing = [name for name in required_cells if name not in cells]
    extra = [name for name in cells if name not in required_cells]
    if missing or extra:
        problems.append(f"expected cells {list(required_cells)}: missing {missing}, "
                        f"unexpected {extra}")
        return rows, problems
    for cell in cells:
        cell_samples = [s for s in samples if s["cell"] == cell]
        workload = M2_WORKLOADS.get(cell)
        if workload is not None:
            # A known cell name establishes its exact workload: mode,
            # thread count and padding on every arm including the
            # unobserved baseline. A relabeled or reshaped cell proves
            # nothing about the M2 population.
            reshaped = [s for s in cell_samples
                        if s["mode"] != workload["mode"]
                        or s["threads"] != workload["threads"]
                        or s["pad"] != workload["pad"]]
            if reshaped:
                first = reshaped[0]
                problems.append(
                    f"cell {cell}: line {first['lineno']}: workload "
                    f"mode={first['mode']} threads={first['threads']} "
                    f"pad={first['pad']}, want mode={workload['mode']} "
                    f"threads={workload['threads']} pad={workload['pad']}"
                )
                continue
            mode = workload["mode"]
        else:
            modes = {s["mode"] for s in cell_samples}
            if len(modes) != 1:
                problems.append(f"cell {cell}: mixed modes {sorted(modes)}")
                continue
            mode = cell_samples[0]["mode"]
        # Campaign shape: contiguous rounds 1..R with R >= required,
        # each round in strict ABBA (odd) or BAAB (even) on/off order
        # plus exactly one trailing unobserved baseline.
        present = sorted({s["round"] for s in cell_samples})
        if present != list(range(1, len(present) + 1)):
            problems.append(f"cell {cell}: rounds {present} are not contiguous from 1")
            continue
        if len(present) < required_rounds:
            problems.append(f"cell {cell}: {len(present)} rounds, need >= {required_rounds}")
            continue
        shaped = True
        for rnd in present:
            order = [s["arm"] for s in cell_samples if s["round"] == rnd]
            want = ["on", "off", "off", "on"] if rnd % 2 else ["off", "on", "on", "off"]
            if order != want + ["unobserved"]:
                problems.append(f"cell {cell}: round {rnd} order {order} is not "
                                f"ABBA/BAAB plus one unobserved baseline")
                shaped = False
        if not shaped:
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
        # Count-exactness re-verification: the on-arm expectation is
        # recomputed from the independently recorded workload
        # denominator (ops + 2*threads + 1, the campaign's exactness
        # gate); both logged fields must equal it with state counted.
        # Two agreeing log fields prove nothing by themselves, and
        # None == None proves nothing either. Every relevant
        # off-sample must read none/none witnessed; map cells and
        # unobserved baselines must carry no observed evidence.
        for s in cell_samples:
            if s["arm"] == "unobserved":
                if not (s["edge_state"] == "none" and s["edge_count"] is None
                        and s["edge_expected"] is None and s["lane"] == "none"
                        and s["bpf_ns"] is None and s["bpf_cnt"] is None):
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: unobserved sample carries "
                        "observed evidence"
                    )
                continue
            if mode == "call":
                if s["arm"] == "on":
                    want = s["ops"] + 2 * s["threads"] + 1
                    if not (s["edge_state"] == "counted"
                            and s["edge_count"] == want
                            and s["edge_expected"] == want):
                        problems.append(
                            f"cell {cell}: line {s['lineno']}: on-arm count "
                            f"{s['edge_count']} / expected {s['edge_expected']} != "
                            f"workload denominator {want} (ops={s['ops']} "
                            f"threads={s['threads']} {s['edge_state']})"
                        )
                if s["arm"] == "off" and not (
                    s["edge_state"] == "witnessed" and s["edge_count"] is None
                    and s["edge_expected"] is None
                ):
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: off-arm edge "
                        f"{s['edge_count']}/{s['edge_expected']} {s['edge_state']}, "
                        "want none/none witnessed"
                    )
            elif not (s["edge_state"] == "none" and s["edge_count"] is None
                      and s["edge_expected"] is None):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: map-cell edge "
                    f"{s['edge_count']}/{s['edge_expected']} {s['edge_state']}, want none"
                )
            # Independent BPF corroboration: every observed arm carries
            # its run-time delta; a call window with no entry firings is
            # vacuous, while the idle map anchor may read zero.
            ns, cnt = s["bpf_ns"], s["bpf_cnt"]
            if ns is None or cnt is None:
                problems.append(
                    f"cell {cell}: line {s['lineno']}: {s['arm']}-arm BPF "
                    "corroboration missing"
                )
            elif mode == "call" and not (ns > 0 and cnt > 0):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: {s['arm']}-arm BPF run-time "
                    f"vacuous (ns={ns} cnt={cnt})"
                )
            elif mode == "mmap" and not (ns >= 0 and cnt >= 0):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: {s['arm']}-arm BPF run-time "
                    f"invalid (ns={ns} cnt={cnt})"
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


def analyze_traced(samples, required_cells=M2_CELLS, required_rounds=M2_ROUNDS):
    """Per-cell production traced cost (the R-47 N5 15% denominator).

    Returns (rows, problems). Each row holds one cell's median and
    spread (p10/p90) of the per-pair observed-minus-unobserved ns per
    completed call, without a thread factor, plus the pair count and
    total-call/thread provenance. Every M2 per-sample gate is kept: the
    log must hold exactly the required cells, each under its exact
    workload, each with contiguous rounds 1..R (R >= required) in
    strict on/unobserved ABBA (odd) or BAAB (even) order, each on-arm
    sample count-exact against the recomputed workload denominator
    with independent BPF corroboration, and each unobserved baseline
    carrying no observed evidence. Anything less renders no numbers.
    """
    rows = []
    problems = []
    cells = sorted({sample["cell"] for sample in samples})
    missing = [name for name in required_cells if name not in cells]
    extra = [name for name in cells if name not in required_cells]
    if missing or extra:
        problems.append(f"expected cells {list(required_cells)}: missing {missing}, "
                        f"unexpected {extra}")
        return rows, problems
    for cell in cells:
        cell_samples = [s for s in samples if s["cell"] == cell]
        workload = M2_WORKLOADS.get(cell)
        if workload is not None:
            reshaped = [s for s in cell_samples
                        if s["mode"] != workload["mode"]
                        or s["threads"] != workload["threads"]
                        or s["pad"] != workload["pad"]]
            if reshaped:
                first = reshaped[0]
                problems.append(
                    f"cell {cell}: line {first['lineno']}: workload "
                    f"mode={first['mode']} threads={first['threads']} "
                    f"pad={first['pad']}, want mode={workload['mode']} "
                    f"threads={workload['threads']} pad={workload['pad']}"
                )
                continue
            mode = workload["mode"]
        else:
            modes = {s["mode"] for s in cell_samples}
            if len(modes) != 1:
                problems.append(f"cell {cell}: mixed modes {sorted(modes)}")
                continue
            mode = cell_samples[0]["mode"]
        thread_counts = {s["threads"] for s in cell_samples}
        if len(thread_counts) != 1:
            problems.append(f"cell {cell}: mixed thread counts {sorted(thread_counts)}")
            continue
        present = sorted({s["round"] for s in cell_samples})
        if present != list(range(1, len(present) + 1)):
            problems.append(f"cell {cell}: rounds {present} are not contiguous from 1")
            continue
        if len(present) < required_rounds:
            problems.append(f"cell {cell}: {len(present)} rounds, need >= {required_rounds}")
            continue
        shaped = True
        for rnd in present:
            order = [s["arm"] for s in cell_samples if s["round"] == rnd]
            want = (["on", "unobserved", "unobserved", "on"] if rnd % 2
                    else ["unobserved", "on", "on", "unobserved"])
            if order != want:
                problems.append(f"cell {cell}: round {rnd} order {order} is not "
                                "the on/unobserved ABBA/BAAB round order")
                shaped = False
        if not shaped:
            continue
        on = [s for s in cell_samples if s["arm"] == "on"]
        if not on:
            problems.append(f"cell {cell}: no on-arm samples")
            continue
        lanes = {s["lane"] for s in on}
        if len(lanes) != 1 or lanes == {"none"}:
            problems.append(f"cell {cell}: mixed lane mechanisms {sorted(lanes)}")
            continue
        for s in cell_samples:
            if s["arm"] == "unobserved":
                if not (s["edge_state"] == "none" and s["edge_count"] is None
                        and s["edge_expected"] is None and s["lane"] == "none"
                        and s["bpf_ns"] is None and s["bpf_cnt"] is None):
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: unobserved sample carries "
                        "observed evidence"
                    )
                continue
            if mode == "call":
                want = s["ops"] + 2 * s["threads"] + 1
                if not (s["edge_state"] == "counted"
                        and s["edge_count"] == want
                        and s["edge_expected"] == want):
                    problems.append(
                        f"cell {cell}: line {s['lineno']}: on-arm count "
                        f"{s['edge_count']} / expected {s['edge_expected']} != "
                        f"workload denominator {want} (ops={s['ops']} "
                        f"threads={s['threads']} {s['edge_state']})"
                    )
            elif not (s["edge_state"] == "none" and s["edge_count"] is None
                      and s["edge_expected"] is None):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: map-cell edge "
                    f"{s['edge_count']}/{s['edge_expected']} {s['edge_state']}, want none"
                )
            ns, cnt = s["bpf_ns"], s["bpf_cnt"]
            if ns is None or cnt is None:
                problems.append(
                    f"cell {cell}: line {s['lineno']}: on-arm BPF "
                    "corroboration missing"
                )
            elif mode == "call" and not (ns > 0 and cnt > 0):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: on-arm BPF run-time "
                    f"vacuous (ns={ns} cnt={cnt})"
                )
            elif mode == "mmap" and not (ns >= 0 and cnt >= 0):
                problems.append(
                    f"cell {cell}: line {s['lineno']}: on-arm BPF run-time "
                    f"invalid (ns={ns} cnt={cnt})"
                )
        if problems and problems[-1].startswith(f"cell {cell}: line"):
            continue
        deltas, pairing = paired_traced_deltas(cell_samples)
        if pairing:
            problems.append(f"cell {cell}: {pairing}")
            continue
        if len(deltas) < 2:
            problems.append(f"cell {cell}: only {len(deltas)} pair(s), need >= 2")
            continue
        ordered = sorted(deltas)
        rows.append(
            {
                "cell": cell,
                "median_ns": statistics.median(ordered),
                "p10_ns": traced_percentile(ordered, 10),
                "p90_ns": traced_percentile(ordered, 90),
                "samples": len(ordered),
                "unit": "ns/completed_call" if mode == "call" else "ns/op",
                "threads": next(iter(thread_counts)),
                "on_total_ops": sum(s["ops"] for s in on),
                "unobserved_total_ops": sum(s["ops"] for s in cell_samples
                                            if s["arm"] == "unobserved"),
            }
        )
    return rows, problems


def traced_cost_lines(rows):
    """One TRACED_COST line with a round-trip machine denominator.

    N5 consumes median_ns without display rounding at its 15% boundary;
    the informational spread retains the ordinary one-decimal display.
    """
    lines = []
    for row in rows:
        count_kind = "calls" if row["unit"] == "ns/completed_call" else "ops"
        lines.append(
            f"TRACED_COST cell={row['cell']} median_ns={row['median_ns']!r} "
            f"p10_ns={row['p10_ns']:.1f} p90_ns={row['p90_ns']:.1f} "
            f"samples={row['samples']} unit={row['unit']} threads={row['threads']} "
            f"on_total_{count_kind}={row['on_total_ops']} "
            f"unobserved_total_{count_kind}={row['unobserved_total_ops']}"
        )
    return lines


def report(headers, rows, rel_bar, ci_bar, required_cells=M2_CELLS,
           required_rounds=M2_ROUNDS):
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
    lines.append(f"required shape: cells={list(required_cells)} rounds>={required_rounds} "
                 "order=ABBA/BAAB plus one unobserved baseline per round")
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
        if row["mode"] == "call":
            exact += on["n"]
    material = [row["cell"] for row in rows if row["material"]]
    if material:
        lines.append(f"OVERALL: MATERIAL ({', '.join(material)})")
    else:
        lines.append("OVERALL: immaterial on every cell")
    gate = "FAIL" if material else "PASS"
    label = "M2 gate" if (tuple(required_cells) == M2_CELLS and required_rounds == M2_ROUNDS) \
        else f"shape gate (cells={len(required_cells)} rounds>={required_rounds})"
    lines.append(f"{label}: {gate} (0 count errors across {exact} counted on-arm samples)")
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
    required_cells, required_rounds = M2_CELLS, M2_ROUNDS
    traced = False
    index = 0
    while index < len(args):
        if args[index] == "--rel-pct" and index + 1 < len(args):
            rel_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--ci-pct" and index + 1 < len(args):
            ci_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--traced-cost":
            traced = True
            index += 1
        elif args[index] == "--cells" and index + 1 < len(args):
            required_cells = tuple(name for name in args[index + 1].split(",") if name)
            if not required_cells or len(set(required_cells)) != len(required_cells):
                print("usage: --cells needs a comma list of distinct cell names",
                      file=sys.stderr)
                return 2
            index += 2
        elif args[index] == "--rounds" and index + 1 < len(args):
            try:
                required_rounds = int(args[index + 1])
            except ValueError:
                required_rounds = 0
            if required_rounds < 1:
                print("usage: --rounds needs a positive integer", file=sys.stderr)
                return 2
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
            "[--rel-pct PCT] [--ci-pct PCT] [--cells a,b] [--rounds N] "
            "[--traced-cost]",
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
    if traced:
        rows, problems = analyze_traced(samples, required_cells, required_rounds)
        if problems:
            for problem in problems:
                print(f"cannot compare: {problem}", file=sys.stderr)
            return 1
        sys.stdout.write("\n".join(traced_cost_lines(rows)) + "\n")
        return 0
    rows, problems = analyze(samples, rel_bar, ci_bar, required_cells, required_rounds)
    if problems:
        for problem in problems:
            print(f"cannot compare: {problem}", file=sys.stderr)
        return 1
    sys.stdout.write(report(headers, rows, rel_bar, ci_bar, required_cells, required_rounds))
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

    def campaign(cells, rounds, hot=True):
        text = "MACHINE kernel=7.0 test-cpu nproc=12\n"
        text += "BINARY role=candidate path=/tmp/c sha256=aaa commit=c0ffee\n"
        text += "BINARY role=base path=/tmp/b sha256=bbb commit=ba5e\n"
        for cell in cells:
            workload = M2_WORKLOADS[cell]
            threads = workload["threads"]
            pad = workload["pad"]
            mmap = workload["mode"] == "mmap"
            for rnd in range(1, rounds + 1):
                arms = ("on", "off", "off", "on") if rnd % 2 else ("off", "on", "on", "off")
                for arm in arms:
                    wall = 1000000
                    if arm == "on":
                        if hot and cell == "relevant-call-t1":
                            wall = 1100000 if rnd % 2 else 1120000
                        else:
                            wall = 1010000
                    elif rnd % 2 == 0:
                        wall = 1020000 if (hot and cell == "relevant-call-t1") else 1000000
                    if not mmap:
                        exact = 1000 + 2 * threads + 1
                        edge = {"edge_count": exact, "edge_expected": exact,
                                "edge_state": "counted"} if arm == "on" else {
                                    "edge_state": "witnessed"}
                        text += sample(cell, arm, rnd, threads, 1000, wall, pad=pad,
                                       **edge,
                                       bpf_ns=200000 if arm == "on" else 150000,
                                       bpf_cnt=1000)
                    else:
                        text += sample(cell, arm, rnd, threads, 1000, wall, pad=pad,
                                       mode="mmap", bpf_ns=0, bpf_cnt=0)
                text += sample(cell, "unobserved", rnd, threads, 1000, 900000,
                               pad=pad, lane="none",
                               **({"mode": "mmap"} if mmap else {}))
        return text

    log = campaign(M2_CELLS, M2_ROUNDS)
    with tempfile.TemporaryDirectory(prefix="count-analyze-") as work:
        path = os.path.join(work, "campaign.log")

        def load(text):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            return parse_log(path)

        headers, samples, errors = load(log)
        assert not errors, errors
        assert len(samples) == 5 * 10 * 5, len(samples)
        assert headers["BINARY:candidate"].endswith("commit=c0ffee")
        rows, problems = analyze(samples, 5.0, 10.0)
        assert not problems, problems
        assert len(rows) == 5, len(rows)
        row = next(r for r in rows if r["cell"] == "relevant-call-t1")
        # Hot t1: odd rounds on=1100/off=1000, even rounds on=1120/off=1020.
        assert row["on"]["median"] == 1110.0, row["on"]
        assert row["off"]["median"] == 1010.0, row["off"]
        assert row["absolute_ns"] == 100.0, row["absolute_ns"]
        # Pairs: 10 rounds x 2, every delta 100 -> median 100.
        assert row["pairs"] == 20, row["pairs"]
        assert row["paired_median_ns"] == 100.0, row["paired_median_ns"]
        assert abs(row["paired_rel_pct"] - 100.0 * 100.0 / 1010.0) < 1e-9
        # Bootstrap CI is deterministic and contains the median.
        lo2, hi2 = bootstrap_median_ci([100.0] * 20)
        assert (row["ci_lo_ns"], row["ci_hi_ns"]) == (lo2, hi2)
        assert row["ci_lo_ns"] <= 100.0 <= row["ci_hi_ns"]
        # 9.9% paired median over the 5% bar reads MATERIAL.
        assert row["material"], "9.9% must read MATERIAL"
        assert row["lane"] == "multi"
        assert row["bpf"]["on"]["ns_per_event"] == 200.0
        assert row["bpf"]["off"]["ns_per_event"] == 150.0
        assert row["bare"]["median"] == 900.0
        assert all(not r["material"] for r in rows if r["cell"] != "relevant-call-t1")
        text = report(headers, rows, 5.0, 10.0)
        assert "OVERALL: MATERIAL (relevant-call-t1)" in text, text
        assert "M2 gate: FAIL (0 count errors across 80 counted on-arm samples)" in text, text
        # A quiet log (1% delta) reads immaterial with gate PASS.
        _, quiet_samples, quiet_errors = load(campaign(M2_CELLS, M2_ROUNDS, hot=False))
        assert not quiet_errors
        quiet_rows, quiet_problems = analyze(quiet_samples, 5.0, 10.0)
        assert not quiet_problems, quiet_problems
        assert not any(r["material"] for r in quiet_rows), "1% must read immaterial"
        assert "M2 gate: PASS" in report(headers, quiet_rows, 5.0, 10.0)
        # Failure modes fail, never pass quietly.
        bad_pair = log + sample("relevant-call-t1", "on", 11, 1, 1000, 1100000,
                                edge_count=1003, edge_expected=1003,
                                edge_state="counted", bpf_ns=200000, bpf_cnt=1000)
        _, bad_samples, _ = load(bad_pair)
        _, problems = analyze(bad_samples, 5.0, 10.0)
        assert any("ABBA" in p for p in problems), problems
        bad_lane = load(log.replace("lane=multi", "lane=singles", 1))
        _, problems = analyze(bad_lane[1], 5.0, 10.0)
        assert any("mixed lane" in p for p in problems), problems
        bad_count = load(log.replace("edge_count=1003", "edge_count=1002", 1))
        _, problems = analyze(bad_count[1], 5.0, 10.0)
        assert any("workload denominator" in p for p in problems), problems
        # A:DR-T3A-13 controls: None exactness, reduced rounds, scrambled
        # order, missing BPF, missing/extra cells, evidenced unobserved.
        none_count = load(log.replace("edge_count=1003", "edge_count=none", 1).replace(
            "edge_expected=1003", "edge_expected=none", 1))
        _, problems = analyze(none_count[1], 5.0, 10.0)
        assert any("workload denominator" in p for p in problems), problems
        reduced = load(campaign(M2_CELLS, 2))
        _, problems = analyze(reduced[1], 5.0, 10.0)
        assert any("rounds" in p for p in problems), problems
        missing_cell = load(campaign(M2_CELLS[:4], M2_ROUNDS))
        _, problems = analyze(missing_cell[1], 5.0, 10.0)
        assert any("unrelated-mmap" in p for p in problems), problems
        extra_cell = load(log + sample("rogue", "on", 1, 1, 100, 100000,
                                        edge_count=103, edge_expected=103,
                                        edge_state="counted", bpf_ns=1, bpf_cnt=1))
        _, problems = analyze(extra_cell[1], 5.0, 10.0)
        assert any("rogue" in p for p in problems), problems
        scrambled = log.replace("cell=relevant-call-t1 arm=on round=1",
                                "cell=relevant-call-t1 arm=off round=1", 1)
        _, problems = analyze(load(scrambled)[1], 5.0, 10.0)
        assert any("ABBA" in p for p in problems), problems
        no_bpf = load(log.replace("bpf_ns=200000 bpf_cnt=1000",
                                  "bpf_ns=none bpf_cnt=none", 1))
        _, problems = analyze(no_bpf[1], 5.0, 10.0)
        assert any("BPF" in p for p in problems), problems
        evidenced_bare = load(log.replace(
            "arm=unobserved round=1 threads=1 ops=1000 wall_ns=900000 pad=0 mode=call "
            "parallel=1 lane=none edge_count=none edge_expected=none edge_state=none "
            "bpf_ns=none bpf_cnt=none",
            "arm=unobserved round=1 threads=1 ops=1000 wall_ns=900000 pad=0 mode=call "
            "parallel=1 lane=multi edge_count=none edge_expected=none edge_state=none "
            "bpf_ns=none bpf_cnt=none", 1))
        _, problems = analyze(evidenced_bare[1], 5.0, 10.0)
        assert any("unobserved" in p for p in problems), problems
        # T1 fix controls: the cell name binds mode/threads/pad on every
        # arm, and both count fields must equal the recomputed workload
        # denominator (two agreeing log fields prove nothing).
        mmap_all = load(log.replace("mode=call", "mode=mmap"))
        _, problems = analyze(mmap_all[1], 5.0, 10.0)
        assert any("workload mode=" in p for p in problems), problems
        wrong_threads = load(log.replace("threads=4", "threads=1", 1))
        _, problems = analyze(wrong_threads[1], 5.0, 10.0)
        assert any("workload mode=" in p for p in problems), problems
        wrong_pad = load(log.replace("pad=1", "pad=0", 1))
        _, problems = analyze(wrong_pad[1], 5.0, 10.0)
        assert any("workload mode=" in p for p in problems), problems
        bare_threads = load(log.replace("arm=unobserved round=1 threads=1",
                                        "arm=unobserved round=1 threads=2", 1))
        _, problems = analyze(bare_threads[1], 5.0, 10.0)
        assert any("workload mode=" in p for p in problems), problems
        agreed_lie = load(log.replace("edge_count=1003 edge_expected=1003",
                                      "edge_count=1 edge_expected=1", 1))
        _, problems = analyze(agreed_lie[1], 5.0, 10.0)
        assert any("workload denominator 1003" in p for p in problems), problems
        near_lie = load(log.replace("edge_count=1003 edge_expected=1003",
                                    "edge_count=1002 edge_expected=1002", 1))
        _, problems = analyze(near_lie[1], 5.0, 10.0)
        assert any("workload denominator 1003" in p for p in problems), problems
        _, _, bad = load("SAMPLE cell=x arm=maybe round=1 threads=1 ops=1 wall_ns=2 pad=0 mode=call parallel=1 lane=multi edge_count=none edge_expected=none edge_state=none bpf_ns=none bpf_cnt=none\n")
        assert bad, "a bad arm must be reported"
        _, empty, _ = load("MACHINE nothing here\n")
        assert not empty
        # Denominator mode (the R-47 N5 production cost): on/unobserved
        # ABBA per round, traced cost per pair, TRACED_COST lines. t1
        # diffs run 100..190 over alternating bare walls (the
        # subtraction is per pair, not against a median); t4 is flat.
        den_cells = ("relevant-call-t1", "relevant-call-t4")

        def dencampaign(cells, rounds):
            text = "MACHINE kernel=7.2.9 test-cpu nproc=5\n"
            text += "BINARY role=candidate path=/tmp/c sha256=aaa commit=c0ffee\n"
            for cell in cells:
                workload = M2_WORKLOADS[cell]
                threads = workload["threads"]
                pad = workload["pad"]
                pair = 0
                for rnd in range(1, rounds + 1):
                    arms = ("on", "unobserved", "unobserved", "on") if rnd % 2 else (
                        "unobserved", "on", "on", "unobserved")
                    on_queue, bare_queue = [], []
                    for _ in range(2):
                        if cell == "relevant-call-t1":
                            bare = 1000000 + (pair % 2) * 10000
                            diff = 100 + 10 * pair
                        else:
                            bare = 1000000
                            diff = 300
                        on_queue.append(bare + diff * 1000 // threads)
                        bare_queue.append(bare)
                        pair += 1
                    for arm in arms:
                        if arm == "on":
                            exact = 1000 + 2 * threads + 1
                            text += sample(cell, arm, rnd, threads, 1000,
                                           on_queue.pop(0), pad=pad,
                                           edge_count=exact, edge_expected=exact,
                                           edge_state="counted",
                                           bpf_ns=200000, bpf_cnt=1000)
                        else:
                            text += sample(cell, arm, rnd, threads, 1000,
                                           bare_queue.pop(0), pad=pad, lane="none")
            return text

        den_log = dencampaign(den_cells, 5)
        _, den_samples, den_errors = load(den_log)
        assert not den_errors, den_errors
        assert len(den_samples) == 2 * 5 * 4, len(den_samples)
        den_rows, den_problems = analyze_traced(den_samples, den_cells, 5)
        assert not den_problems, den_problems
        assert len(den_rows) == 2, den_rows
        t1row = next(r for r in den_rows if r["cell"] == "relevant-call-t1")
        assert t1row["median_ns"] == 145.0, t1row
        # Interpolated percentiles: float-exact only to 1e-9 (0.9 is
        # not exact in binary); the printed line rounds to 1 decimal.
        assert abs(t1row["p10_ns"] - 109.0) < 1e-9, t1row
        assert abs(t1row["p90_ns"] - 181.0) < 1e-9, t1row
        assert t1row["samples"] == 10, t1row
        t4row = next(r for r in den_rows if r["cell"] == "relevant-call-t4")
        assert (t4row["median_ns"], t4row["p10_ns"], t4row["p90_ns"],
                t4row["samples"]) == (75.0, 75.0, 75.0, 10), t4row
        assert traced_cost_lines(den_rows) == [
            "TRACED_COST cell=relevant-call-t1 median_ns=145.0 "
            "p10_ns=109.0 p90_ns=181.0 samples=10 unit=ns/completed_call threads=1 "
            "on_total_calls=10000 unobserved_total_calls=10000",
            "TRACED_COST cell=relevant-call-t4 median_ns=75.0 "
            "p10_ns=75.0 p90_ns=75.0 samples=10 unit=ns/completed_call threads=4 "
            "on_total_calls=10000 unobserved_total_calls=10000",
        ], traced_cost_lines(den_rows)
        # Every denominator failure mode fails loudly.
        den_off = den_log.replace("cell=relevant-call-t1 arm=on round=1",
                                  "cell=relevant-call-t1 arm=off round=1", 1)
        _, problems = analyze_traced(load(den_off)[1], den_cells, 5)
        assert any("order" in p for p in problems), problems
        den_scrambled = den_log.replace("cell=relevant-call-t1 arm=on round=2",
                                        "cell=relevant-call-t1 arm=unobserved round=2", 1)
        _, problems = analyze_traced(load(den_scrambled)[1], den_cells, 5)
        assert any("order" in p for p in problems), problems
        den_no_bpf = load(den_log.replace("bpf_ns=200000 bpf_cnt=1000",
                                          "bpf_ns=none bpf_cnt=none", 1))
        _, problems = analyze_traced(den_no_bpf[1], den_cells, 5)
        assert any("BPF" in p for p in problems), problems
        den_evidenced = load(den_log.replace("lane=none", "lane=multi", 1))
        _, problems = analyze_traced(den_evidenced[1], den_cells, 5)
        assert any("unobserved" in p for p in problems), problems
        den_bad_count = load(den_log.replace("edge_count=1003", "edge_count=1002", 1))
        _, problems = analyze_traced(den_bad_count[1], den_cells, 5)
        assert any("denominator" in p for p in problems), problems
        _, problems = analyze_traced(load(dencampaign(den_cells[:1], 5))[1],
                                     den_cells, 5)
        assert any("relevant-call-t4" in p for p in problems), problems
        den_extra = den_log + sample("rogue", "on", 1, 1, 100, 100000,
                                     edge_count=103, edge_expected=103,
                                     edge_state="counted", bpf_ns=1, bpf_cnt=1)
        _, problems = analyze_traced(load(den_extra)[1], den_cells, 5)
        assert any("rogue" in p for p in problems), problems
        _, problems = analyze_traced(load(dencampaign(den_cells, 2))[1],
                                     den_cells, 5)
        assert any("rounds" in p for p in problems), problems
        den_lane = load(den_log.replace("lane=multi", "lane=singles", 1))
        _, problems = analyze_traced(den_lane[1], den_cells, 5)
        assert any("mixed lane" in p for p in problems), problems
        den_threads = load(den_log.replace("threads=4", "threads=1", 1))
        _, problems = analyze_traced(den_threads[1], den_cells, 5)
        assert any("workload" in p for p in problems), problems
        # The modes do not leak into each other.
        _, problems = analyze(den_samples, 5.0, 10.0, den_cells, 5)
        assert problems, "an on/unobserved log is not an M2 campaign"
        _, m2_samples, _ = load(campaign(("relevant-call-t1",), 5))
        _, problems = analyze_traced(m2_samples, ("relevant-call-t1",), 5)
        assert problems, "an on/off log is not a denominator campaign"
    print("bench-count-overhead-analyze self-test: OK")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

