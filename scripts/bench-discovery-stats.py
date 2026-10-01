# SPDX-License-Identifier: GPL-3.0-or-later
"""Statistics for scripts/bench-discovery.sh (Phase 2, D2).

Reads BENCH_DISCOVERY JSON sample lines (one per line, `cold`/`warm` runs
of the D1 cold/warm harness) and reports median + min..max wall time per
run kind plus the median per-stage wall/call numbers and the queue/tail
evidence. A sample whose harness coverage check failed never reaches this
script: the driver counts it INVALID and fails the run at the end.

Live-capture stages (drain spans, inter-drain gaps, the resource timeline)
need a privileged capture loop, so the unprivileged harness never measures
them; they are listed as UNMEASURED, never zero. `--full` (privileged
controller lanes) fails when any stage the full matrix requires is
unmeasured.

Capture evidence arrives as OPTIONAL per-sample keys (absent in
unprivileged samples; the D1 `bench_line` omits them):

- `inter_drain_gap_samples`: inter-drain gap samples observed in the run.
- `resource_samples`: resource-timeline samples observed in the run.

The privileged controller-lane harness (live capture -> report JSON ->
BENCH_DISCOVERY samples; built by the controller lanes) emits them from
the capture report: `inter_drain_gap_samples` from
`evidence.scheduling.inter_drain_gap.samples`, `resource_samples` from
`evidence.scheduling.resource.samples`, and a nonzero
`stage_invocations.drain` (the existing required key) from
`evidence.scheduling.stage_invocations.drain`. An evidence item counts as
measured when at least one sample carries its key with a value above zero;
absent (or zero) means unmeasured and fails `--full` loudly.

Run: python3 -I scripts/bench-discovery-stats.py [--self-test] [--full] [samples...]
"""

import json
import statistics
import sys

STAGES = (
    "scan",
    "pin",
    "bind",
    "plan",
    "merge",
    "projection",
    "attach",
    "drain",
    "cleanup",
)
# Stages only a live capture loop can measure (privileged controller lanes).
CAPTURE_ONLY = ("drain",)
# Evidence only a live capture loop can sample, mapped to the optional
# per-sample key that carries it. No `run_loop_pin_gate` item: the pin-gate
# sweep/skip counters are run-loop-local (never synced into the scheduling
# evidence or the stderr summary), so no sample source could satisfy such a
# gate item; the B2 counter test in-tree is that gate's proof instead.
CAPTURE_ONLY_EVIDENCE = {
    "inter_drain_gap": "inter_drain_gap_samples",
    "resource": "resource_samples",
}


def parse_samples(lines):
    """Parse BENCH_DISCOVERY JSON lines; malformed lines fail loudly."""
    samples = []
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            sample = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"sample line {lineno}: malformed JSON: {error}")
        for key in ("run", "wall_ms", "modules", "slots", "stage_ms",
                    "stage_invocations", "tail_publishes", "tail_skips",
                    "newcomer_admitted", "newcomer_admitted_unknown",
                    "newcomer_pending"):
            if key not in sample:
                raise SystemExit(f"sample line {lineno}: missing key {key!r}")
        if sample["run"] not in ("cold", "warm"):
            raise SystemExit(f"sample line {lineno}: bad run {sample['run']!r}")
        for group in ("stage_ms", "stage_invocations"):
            missing = set(STAGES) - set(sample[group])
            if missing:
                raise SystemExit(
                    f"sample line {lineno}: {group} missing {sorted(missing)}"
                )
        for key in CAPTURE_ONLY_EVIDENCE.values():
            if key in sample:
                value = sample[key]
                if type(value) is not int or value < 0:
                    raise SystemExit(
                        f"sample line {lineno}: {key!r} must be an int >= 0, "
                        f"got {value!r}"
                    )
        samples.append(sample)
    if not samples:
        raise SystemExit("no samples: all rounds invalid or missing")
    return samples


def summarize(values):
    ordered = sorted(values)
    return {
        "median": statistics.median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
        "n": len(ordered),
    }


def unmeasured_capture(samples):
    """Capture stages/evidence no sample measured, in canonical order.

    A drain stage counts as measured when at least one sample ran a drain
    span; an evidence item counts as measured when at least one sample
    carries its optional key with a value above zero. Absent (or zero)
    means unmeasured — never silently treated as measured.
    """
    unmeasured = [
        stage
        for stage in CAPTURE_ONLY
        if all(s["stage_invocations"][stage] == 0 for s in samples)
    ]
    for evidence, key in CAPTURE_ONLY_EVIDENCE.items():
        if not any(type(s.get(key)) is int and s[key] > 0 for s in samples):
            unmeasured.append(evidence)
    return unmeasured


def report(samples):
    """Aggregate per-run-kind statistics over valid samples."""
    kinds = {}
    for sample in samples:
        kinds.setdefault(sample["run"], []).append(sample)
    out = {}
    for kind in ("cold", "warm"):
        group = kinds.get(kind, [])
        if not group:
            raise SystemExit(f"no valid samples for {kind}")
        entry = {
            "wall_ms": summarize(s["wall_ms"] for s in group),
            "modules": sorted({s["modules"] for s in group}),
            "slots": sorted({s["slots"] for s in group}),
            "stage_ms": {
                stage: summarize(s["stage_ms"][stage] for s in group)
                for stage in STAGES
            },
            "stage_invocations": {
                stage: sorted({s["stage_invocations"][stage] for s in group})
                for stage in STAGES
            },
            "tail_publishes": sorted({s["tail_publishes"] for s in group}),
            "tail_skips": sorted({s["tail_skips"] for s in group}),
            "newcomer_admitted": sorted({s["newcomer_admitted"] for s in group}),
            "newcomer_pending": sorted({s["newcomer_pending"] for s in group}),
        }
        out[kind] = entry
    out["capture_evidence"] = {
        "measured": [
            name
            for name in list(CAPTURE_ONLY) + list(CAPTURE_ONLY_EVIDENCE)
            if name not in unmeasured_capture(samples)
        ],
        "unmeasured": unmeasured_capture(samples),
    }
    return out


def format_report(agg):
    lines = []
    for kind in ("cold", "warm"):
        entry = agg[kind]
        wall = entry["wall_ms"]
        lines.append(
            f"{kind}: wall_ms median={wall['median']} "
            f"min..max={wall['min']}..{wall['max']} n={wall['n']}"
        )
        lines.append(
            f"{kind}: modules={entry['modules']} slots={entry['slots']} "
            f"tail_publishes={entry['tail_publishes']} "
            f"tail_skips={entry['tail_skips']} "
            f"newcomer_admitted={entry['newcomer_admitted']} "
            f"newcomer_pending={entry['newcomer_pending']}"
        )
        for stage in STAGES:
            total = entry["stage_ms"][stage]
            calls = entry["stage_invocations"][stage]
            lines.append(
                f"{kind}: stage {stage}: ms median={total['median']} "
                f"min..max={total['min']}..{total['max']} calls={calls}"
            )
    unmeasured = agg["capture_evidence"]["unmeasured"]
    if unmeasured:
        lines.append(
            "UNMEASURED without a privileged live capture: "
            + ", ".join(unmeasured)
        )
    else:
        lines.append(
            "capture stages and evidence: all measured "
            "(privileged samples present)"
        )
    return "\n".join(lines)


def self_test():
    cold = {
        "run": "cold", "wall_ms": 24, "modules": 1, "slots": 2,
        "stage_ms": {s: 1 for s in STAGES},
        "stage_invocations": {s: 2 for s in STAGES},
        "tail_publishes": 2, "tail_skips": 1,
        "newcomer_admitted": 0, "newcomer_admitted_unknown": 0,
        "newcomer_pending": 0,
    }
    warm = dict(cold, run="warm", wall_ms=21)
    agg = report([cold, warm, dict(cold, wall_ms=26)])
    assert agg["cold"]["wall_ms"]["median"] == 25, agg
    assert agg["warm"]["wall_ms"]["median"] == 21, agg
    assert agg["cold"]["stage_invocations"]["scan"] == [2], agg
    assert "UNMEASURED" in format_report(agg)
    for bad in ('{"run": "cold"}', "not json",
                json.dumps(dict(cold, run="lukewarm"))):
        try:
            parse_samples([bad])
        except SystemExit:
            pass
        else:
            raise AssertionError(f"accepted bad sample: {bad}")
    try:
        parse_samples([])
    except SystemExit:
        pass
    else:
        raise AssertionError("accepted empty samples")
    try:
        require_capture_stages([cold, warm])
    except SystemExit as error:
        assert "drain" in str(error), error
        assert "inter_drain_gap" in str(error), error
        assert "resource" in str(error), error
        assert "run_loop_pin_gate" not in str(error), error
    else:
        raise AssertionError("full gate passed without capture stages")
    measured = dict(cold)
    measured["stage_invocations"] = dict(cold["stage_invocations"], drain=3)
    try:
        require_capture_stages([measured])
    except SystemExit as error:
        assert "inter_drain_gap" in str(error), error
    else:
        raise AssertionError("full gate passed without capture evidence")
    # Present-but-zero evidence still counts as unmeasured, never as
    # measured: a zero sample observed nothing.
    zeroed = dict(
        measured, inter_drain_gap_samples=0, resource_samples=0,
    )
    try:
        require_capture_stages([zeroed])
    except SystemExit:
        pass
    else:
        raise AssertionError("full gate passed on zero evidence")
    # The pass path: privileged samples carry the capture-evidence keys.
    privileged = dict(
        measured, inter_drain_gap_samples=5, resource_samples=2,
    )
    require_capture_stages([cold, privileged])
    privileged_warm = dict(privileged, run="warm", wall_ms=21)
    assert "all measured" in format_report(report([cold, privileged_warm]))
    # Malformed optional keys fail loudly at parse time.
    for key, bad_value in (
        ("inter_drain_gap_samples", -1),
        ("inter_drain_gap_samples", "5"),
        ("inter_drain_gap_samples", None),
        ("inter_drain_gap_samples", True),
        ("resource_samples", 1.5),
    ):
        try:
            parse_samples([json.dumps(dict(cold, **{key: bad_value}))])
        except SystemExit:
            pass
        else:
            raise AssertionError(f"accepted bad {key}: {bad_value!r}")
    print("bench-discovery-stats: self-test ok")


def require_capture_stages(samples):
    """The --full gate: every capture-only stage and evidence item must be
    measured in at least one sample, else fail loudly listing what is
    unmeasured."""
    unmeasured = unmeasured_capture(samples)
    if unmeasured:
        raise SystemExit(
            "bench-discovery --full: FAILED: unmeasured stages need a "
            f"privileged live capture: {', '.join(unmeasured)}"
        )


def main(argv):
    if argv[:1] == ["--self-test"]:
        self_test()
        return 0
    full = argv[:1] == ["--full"]
    argv = argv[1:] if full else argv
    check_only = argv[:1] == ["--check-only"]
    argv = argv[1:] if check_only else argv
    paths = argv or ["-"]
    lines = []
    for path in paths:
        if path == "-":
            lines.extend(sys.stdin.read().splitlines())
        else:
            with open(path, encoding="utf-8") as handle:
                lines.extend(handle.read().splitlines())
    samples = parse_samples(lines)
    if not check_only:
        print(format_report(report(samples)))
    if full or check_only:
        require_capture_stages(samples)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
