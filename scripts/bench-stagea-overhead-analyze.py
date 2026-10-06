#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage A overhead ABBA analysis (Task 1d; completeness-hardened, P2-4).

Reads a scripts/bench-stagea-overhead.sh campaign log: MACHINE/BINARY header
lines, one SAMPLE line per valid sample, and a DONE completion marker — and
validates it against the campaign manifest (expected cells, rounds, workload
parameters, completion marker) BEFORE any verdict math. Missing or
inconsistent evidence is rejected; nothing certifies on partial input.

Usage:
  scripts/bench-stagea-overhead-analyze.py LOG --manifest MANIFEST [--rel-pct PCT] [--abs-ns NS]
  scripts/bench-stagea-overhead-analyze.py --self-test

Exit 0 prints the table and verdict. Exit 1 when the evidence is missing or
inconsistent (no completion marker, short rounds, parameter mismatch, no
hook execution on an on-arm sample). Exit 2 on usage errors (bad flags, a
missing or malformed manifest file).
"""
import hashlib
import json
import statistics
import sys

# Grandfathered completion evidence: the explicitly reviewed pre-manifest 1d
# campaign only (commit 301dde4, task-1d report). The legacy path accepts no
# other stdout, log, or expectation set: every other campaign must carry its
# own DONE marker. Pins: the reviewed campaign-stdout bytes plus the
# corroborated expectations of task-devastrafix-1d-manifest.json.
LEGACY_CAMPAIGN_SHA256 = "07b059e0a45a97c684fe28d08df11967e8902145d563150b43304908be733147"
LEGACY_ARMS_PER_ROUND = 4
LEGACY_FIRST_ARM = "on"
LEGACY_EVENTS_PER_OP = 2
LEGACY_CELLS = {
    "relevant-mmap": {"rounds": 3, "ops": 1000000, "mode": "mmap", "parallel": 1},
    "relevant-mmap-p8": {"rounds": 2, "ops": 8000000, "mode": "mmap", "parallel": 8},
    "relevant-mremap": {"rounds": 2, "ops": 1000000, "mode": "mremap", "parallel": 1},
    "unrelated-mmap": {"rounds": 3, "ops": 1000000, "mode": "mmap", "parallel": 1},
    "unrelated-mmap-p8": {"rounds": 2, "ops": 8000000, "mode": "mmap", "parallel": 8},
    "unrelated-mremap": {"rounds": 2, "ops": 1000000, "mode": "mremap", "parallel": 1},
}


def parse_log(path):
    """Split a campaign log into headers, samples, DONE markers and errors.

    Returns (headers, samples, done_lines, errors): headers maps
    MACHINE/BINARY keys, samples is a list of dicts in log order, done_lines
    lists the line numbers of DONE completion markers, errors lists malformed
    SAMPLE lines (never silently dropped: the caller fails on them).
    """
    headers = {}
    samples = []
    done_lines = []
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
            if head == "DONE":
                done_lines.append(lineno)
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
    return headers, samples, done_lines, errors


def load_manifest(path):
    """Read a campaign manifest. Returns (manifest, error).

    The manifest pre-declares the campaign: {"cells": {name: {"rounds",
    "ops", "mode", "parallel"}}, "arms_per_round", "first_arm",
    "events_per_op", "completion": {"marker": "DONE"} or
    {"legacy_stdout", "note"}}. Only one of the two completion forms is
    valid. "first_arm" is round 1's starting arm ("on" or "off"); each
    later round starts with the flipped arm, and arms within a round run
    in ABBA mirror order (round 1 "on" reads on off off on). The legacy
    form is confined to the pinned historical artifact (see
    LEGACY_CAMPAIGN_SHA256): any other campaign needs its own DONE marker.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except OSError as error:
        return None, f"cannot read manifest {path}: {error}"
    except ValueError as error:
        return None, f"malformed manifest {path}: {error}"
    if not isinstance(manifest, dict):
        return None, f"malformed manifest {path}: top level is not an object"
    cells = manifest.get("cells")
    if not isinstance(cells, dict) or not cells:
        return None, f"malformed manifest {path}: 'cells' is empty or missing"
    for name, cell in cells.items():
        if not isinstance(cell, dict):
            return None, f"malformed manifest {path}: cell {name} is not an object"
        for key in ("rounds", "ops", "parallel"):
            value = cell.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                return (
                    None,
                    f"malformed manifest {path}: cell {name} field '{key}' "
                    f"is not a positive integer",
                )
        if cell.get("mode") not in ("mmap", "mremap"):
            return (
                None,
                f"malformed manifest {path}: cell {name} field 'mode' "
                "is not mmap or mremap",
            )
    arms = manifest.get("arms_per_round")
    if not isinstance(arms, int) or isinstance(arms, bool) or arms <= 0 or arms % 2:
        return (
            None,
            f"malformed manifest {path}: 'arms_per_round' is not a positive even integer",
        )
    if manifest.get("first_arm") not in ("on", "off"):
        return (
            None,
            f"malformed manifest {path}: 'first_arm' is not on or off",
        )
    events = manifest.get("events_per_op")
    if not isinstance(events, (int, float)) or isinstance(events, bool) or events <= 0:
        return (
            None,
            f"malformed manifest {path}: 'events_per_op' is not a positive number",
        )
    completion = manifest.get("completion")
    if not isinstance(completion, dict):
        return None, f"malformed manifest {path}: 'completion' is missing"
    if completion.get("marker") == "DONE" and "legacy_stdout" not in completion:
        pass
    elif (
        isinstance(completion.get("legacy_stdout"), str)
        and completion["legacy_stdout"]
        and isinstance(completion.get("note"), str)
        and completion["note"]
        and "marker" not in completion
    ):
        pass
    else:
        return (
            None,
            f"malformed manifest {path}: 'completion' is neither "
            "{'marker': 'DONE'} nor {'legacy_stdout', 'note'}",
        )
    return manifest, None


def expected_arms(round_no, arms, first_arm):
    """The declared arm order for one round: ABBA mirror, start alternating.

    Round 1 starts with first_arm; each later round flips the start; arms
    within the round mirror (positions 0 and 3 take the start). A 4-arm
    round 1 "on" reads on off off on; round 2 reads off on on off. The
    mirror is what protects the comparison against linear host drift, so
    totals alone never suffice.
    """
    start = first_arm if round_no % 2 == 1 else ("off" if first_arm == "on" else "on")
    other = "off" if start == "on" else "on"
    return [start if index % 4 in (0, 3) else other for index in range(arms)]


def validate(samples, done_lines, manifest, log_digest=""):
    """Check the samples against the manifest. Returns a list of problems.

    Every problem names the exact defect (want vs have); an empty list
    means the campaign is complete and workload-consistent. Runs before any
    verdict math: incomplete evidence never reaches a verdict. `log_digest`
    is the analyzed log file's sha256; the legacy path binds completion to
    the reviewed bytes through it (an empty digest never matches).
    """
    problems = []
    cells = manifest["cells"]
    arms = manifest["arms_per_round"]
    expected_events = manifest["events_per_op"]
    completion = manifest["completion"]
    if "marker" in completion:
        if not done_lines:
            problems.append(
                "missing completion marker DONE: the campaign did not finish"
            )
        elif any(sample["lineno"] > done_lines[0] for sample in samples):
            problems.append(
                f"samples past the DONE marker at line {done_lines[0]}: "
                "the marker does not complete the log"
            )
    else:
        if (
            cells != LEGACY_CELLS
            or arms != LEGACY_ARMS_PER_ROUND
            or manifest["first_arm"] != LEGACY_FIRST_ARM
            or expected_events != LEGACY_EVENTS_PER_OP
        ):
            problems.append(
                "legacy completion requires the reviewed historical "
                "expectations (six 1d cells, 4 arms/round from on, 2 "
                "events/op): this manifest declares another campaign, "
                "which needs its own DONE marker"
            )
        evidence = completion["legacy_stdout"]
        try:
            with open(evidence, "rb") as handle:
                evidence_digest = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            evidence_digest = ""
        if evidence_digest != LEGACY_CAMPAIGN_SHA256:
            problems.append(
                f"legacy completion evidence {evidence} is not the reviewed "
                f"historical artifact (sha256 {evidence_digest or 'unreadable'}, "
                f"want {LEGACY_CAMPAIGN_SHA256}): no other stdout completes "
                "a campaign"
            )
        if log_digest != LEGACY_CAMPAIGN_SHA256:
            problems.append(
                "the analyzed log is not the reviewed historical campaign "
                f"(sha256 {log_digest or 'unknown'}, want "
                f"{LEGACY_CAMPAIGN_SHA256}): legacy completion binds only "
                "to those bytes"
            )
    have_cells = sorted({sample["cell"] for sample in samples})
    for name in sorted(cells):
        if name not in have_cells:
            problems.append(
                f"cell {name}: expected by the manifest, sampled 0 times"
            )
    for name in have_cells:
        if name not in cells:
            problems.append(
                f"cell {name}: sampled but absent from the manifest"
            )
    for name in sorted(cells):
        spec = cells[name]
        rounds = sorted({sample["round"] for sample in samples if sample["cell"] == name})
        want_rounds = list(range(1, spec["rounds"] + 1))
        if rounds != want_rounds:
            problems.append(
                f"cell {name}: want rounds {want_rounds}, have {rounds}"
            )
        for round_no in want_rounds:
            bucket = sorted(
                (
                    sample
                    for sample in samples
                    if sample["cell"] == name and sample["round"] == round_no
                ),
                key=lambda sample: sample["lineno"],
            )
            on = [sample for sample in bucket if sample["arm"] == "on"]
            off = [sample for sample in bucket if sample["arm"] == "off"]
            if len(bucket) != arms or len(on) != arms // 2 or len(off) != arms // 2:
                problems.append(
                    f"cell {name} round {round_no}: want {arms} samples "
                    f"({arms // 2} on + {arms // 2} off), have {len(bucket)} "
                    f"({len(on)} on + {len(off)} off)"
                )
            elif [sample["arm"] for sample in bucket] != expected_arms(
                round_no, arms, manifest["first_arm"]
            ):
                want = " ".join(expected_arms(round_no, arms, manifest["first_arm"]))
                have = " ".join(sample["arm"] for sample in bucket)
                problems.append(
                    f"cell {name} round {round_no}: want arm order {want}, "
                    f"have {have}"
                )
    for sample in samples:
        spec = cells.get(sample["cell"])
        if spec is None:
            continue
        for key in ("ops", "mode", "parallel"):
            if sample[key] != spec[key]:
                problems.append(
                    f"line {sample['lineno']}: cell {sample['cell']} field "
                    f"'{key}' is {sample[key]}, manifest wants {spec[key]}"
                )
        if sample["arm"] == "on":
            if sample["bpf_cnt"] is None or sample["bpf_ns"] is None:
                problems.append(
                    f"line {sample['lineno']}: cell {sample['cell']} "
                    f"round {sample['round']} on-arm sample has no hook "
                    "run-time sample: the hooks never fired under the workload"
                )
            elif sample["bpf_ns"] <= 0:
                problems.append(
                    f"line {sample['lineno']}: cell {sample['cell']} "
                    f"round {sample['round']} on-arm hook run-time "
                    f"(bpf_ns={sample['bpf_ns']} over bpf_cnt={sample['bpf_cnt']}) "
                    "is not positive: the run-time counter never advanced "
                    "under the workload"
                )
            elif sample["bpf_cnt"] < sample["ops"]:
                problems.append(
                    f"line {sample['lineno']}: cell {sample['cell']} "
                    f"round {sample['round']} on-arm hook execution "
                    f"(bpf_cnt={sample['bpf_cnt']} over ops={sample['ops']}) "
                    "is below one event per op: the hooks never fired "
                    "under the workload"
                )
    for name in sorted(cells):
        on = [
            sample
            for sample in samples
            if sample["cell"] == name
            and sample["arm"] == "on"
            and sample["bpf_cnt"] is not None
        ]
        if not on:
            continue
        ratio = sum(sample["bpf_cnt"] for sample in on) / sum(
            sample["ops"] for sample in on
        )
        if not expected_events / 2 <= ratio <= expected_events * 2:
            problems.append(
                f"cell {name}: hook events per op are {ratio:.2f}, want "
                f"{expected_events:g} within 2x: the workload did not run "
                "under the hooks"
            )
    return problems


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
    be compared (an arm with no samples). Runs only after `validate`
    accepted the campaign; its problems are a backstop, not the gate.
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
    rel_bar, abs_bar, positional, manifest_path = 5.0, 1000.0, [], None
    index = 0
    while index < len(args):
        if args[index] == "--rel-pct" and index + 1 < len(args):
            rel_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--abs-ns" and index + 1 < len(args):
            abs_bar = float(args[index + 1])
            index += 2
        elif args[index] == "--manifest" and index + 1 < len(args):
            manifest_path = args[index + 1]
            index += 2
        elif args[index].startswith("--manifest="):
            manifest_path = args[index].partition("=")[2]
            index += 1
        elif args[index].startswith("--"):
            print(f"unknown flag {args[index]}", file=sys.stderr)
            return 2
        else:
            positional.append(args[index])
            index += 1
    if len(positional) != 1 or not manifest_path:
        print(
            "usage: bench-stagea-overhead-analyze.py LOG --manifest MANIFEST "
            "[--rel-pct PCT] [--abs-ns NS]",
            file=sys.stderr,
        )
        return 2
    manifest, manifest_error = load_manifest(manifest_path)
    if manifest_error is not None:
        print(manifest_error, file=sys.stderr)
        return 2
    headers, samples, done_lines, errors = parse_log(positional[0])
    if errors:
        for error in errors:
            print(f"malformed sample: {error}", file=sys.stderr)
        return 1
    if not samples:
        print("no samples in the log", file=sys.stderr)
        return 1
    with open(positional[0], "rb") as handle:
        log_digest = hashlib.sha256(handle.read()).hexdigest()
    incomplete = validate(samples, done_lines, manifest, log_digest)
    if incomplete:
        for problem in incomplete:
            print(f"incomplete campaign: {problem}", file=sys.stderr)
        return 1
    rows, problems = analyze(samples, rel_bar, abs_bar)
    if problems:
        for problem in problems:
            print(f"cannot compare: {problem}", file=sys.stderr)
        return 1
    sys.stdout.write(report(headers, rows, rel_bar, abs_bar))
    return 0


def self_test():
    """Pinned-numbers checks over synthetic logs, plus manifest-gate pins."""
    import contextlib
    import io
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
DONE samples=8
"""
    manifest = {
        "cells": {
            "relevant-mmap": {"rounds": 2, "ops": 1000, "mode": "mmap", "parallel": 1},
            "unrelated-mmap": {"rounds": 2, "ops": 1000, "mode": "mmap", "parallel": 1},
        },
        "arms_per_round": 2,
        "first_arm": "off",
        "events_per_op": 2,
        "completion": {"marker": "DONE"},
    }
    with tempfile.TemporaryDirectory(prefix="stagea-analyze-") as work:
        path = os.path.join(work, "campaign.log")
        manifest_path = os.path.join(work, "campaign.manifest.json")

        def write_log(text):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)

        def write_manifest(doc):
            with open(manifest_path, "w", encoding="utf-8") as handle:
                json.dump(doc, handle)

        def run(argv):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(argv)
            return code, stdout.getvalue(), stderr.getvalue()

        write_log(log)
        write_manifest(manifest)
        headers, samples, done_lines, errors = parse_log(path)
        assert not errors, errors
        assert len(samples) == 8, len(samples)
        assert done_lines == [11], done_lines
        assert headers["MACHINE"] == "kernel=7.0 test-cpu nproc=12"
        assert validate(samples, done_lines, manifest) == []
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
        code, out, _ = run([path, "--manifest", manifest_path])
        assert code == 0, (code, out)
        assert "OVERALL: immaterial on every cell" in out, out
        # A cell over the relative bar reads MATERIAL.
        hot = log.replace(
            "cell=relevant-mmap arm=on round=1 ops=1000 wall_ns=4100000",
            "cell=relevant-mmap arm=on round=1 ops=1000 wall_ns=4500000",
        ).replace(
            "cell=relevant-mmap arm=on round=2 ops=1000 wall_ns=4300000",
            "cell=relevant-mmap arm=on round=2 ops=1000 wall_ns=4500000",
        )
        write_log(hot)
        _, hot_samples, _, hot_errors = parse_log(path)
        assert not hot_errors
        hot_rows, _ = analyze(hot_samples, 5.0, 1000.0)
        assert hot_rows[0]["material"], "400ns/9.8% must read MATERIAL"
        assert "OVERALL: MATERIAL (relevant-mmap)" in report(headers, hot_rows, 5.0, 1000.0)
        # Missing arm, malformed lines and empty logs fail, never pass quietly.
        write_log(
            "SAMPLE cell=x arm=on round=1 ops=1 wall_ns=2 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n"
        )
        _, one_arm, _, _ = parse_log(path)
        _, problems = analyze(one_arm, 5.0, 1000.0)
        assert problems, "a cell with one arm must not compare"
        write_log(
            "SAMPLE cell=x arm=maybe round=1 ops=1 wall_ns=2 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n"
        )
        _, _, _, bad = parse_log(path)
        assert bad, "a bad arm must be reported"
        write_log("MACHINE nothing here\n")
        _, empty, _, _ = parse_log(path)
        assert not empty
        # P2-4: the astra trivial input (one equal on/off pair, one cell,
        # zero hook executions) is rejected, never certified.
        write_log(
            "MACHINE kernel=test\n"
            "BINARY path=/tmp/p sha256=abc\n"
            "SAMPLE cell=x arm=off round=1 ops=1000 wall_ns=4000000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n"
            "SAMPLE cell=x arm=on round=1 ops=1000 wall_ns=4000000 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n"
            "DONE samples=2\n"
        )
        write_manifest(
            {
                "cells": {"x": {"rounds": 1, "ops": 1000, "mode": "mmap", "parallel": 1}},
                "arms_per_round": 2,
                "first_arm": "off",
                "events_per_op": 2,
                "completion": {"marker": "DONE"},
            }
        )
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "the hooks never fired under the workload" in err, err
        assert "OVERALL" not in err
        # Every completeness defect names itself exactly.
        write_log(log.replace("DONE samples=8\n", ""))
        write_manifest(manifest)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1 and "missing completion marker DONE" in err, (code, err)
        write_log(log + "SAMPLE cell=relevant-mmap arm=off round=2 ops=1000 wall_ns=1 mode=mmap parallel=1 bpf_ns=none bpf_cnt=none\n")
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1 and "past the DONE marker" in err, (code, err)
        short = "\n".join(
            line
            for line in log.splitlines()
            if "cell=unrelated-mmap arm=on round=2" not in line
        ) + "\n"
        write_log(short)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "cell unrelated-mmap round 2: want 2 samples (1 on + 1 off)" in err, err
        # Right totals in the wrong order lose the drift mirror: rejected.
        swapped = log.splitlines()
        first = next(
            index
            for index, line in enumerate(swapped)
            if "cell=relevant-mmap arm=off round=1" in line
        )
        second = next(
            index
            for index, line in enumerate(swapped)
            if "cell=relevant-mmap arm=on round=1" in line
        )
        swapped[first], swapped[second] = swapped[second], swapped[first]
        write_log("\n".join(swapped) + "\n")
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "cell relevant-mmap round 1: want arm order off on, have on off" in err, err
        # A manifest without the declared order is a usage error, not a verdict.
        orderless = dict(manifest)
        del orderless["first_arm"]
        write_log(log)
        write_manifest(orderless)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 2 and "'first_arm' is not on or off" in err, (code, err)
        write_manifest(manifest)
        write_log(log.replace("ops=1000 wall_ns=4100000", "ops=2000 wall_ns=8200000"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "'ops' is 2000, manifest wants 1000" in err, err
        write_log(log.replace("wall_ns=4100000 mode=mmap", "wall_ns=4100000 mode=mremap"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "'mode' is mremap, manifest wants mmap" in err, err
        write_log(log.replace("wall_ns=4100000 mode=mmap parallel=1", "wall_ns=4100000 mode=mmap parallel=2"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "'parallel' is 2, manifest wants 1" in err, err
        # A whole missing round names the missing rounds exactly.
        noround2 = "\n".join(line for line in log.splitlines() if " round=2 " not in line) + "\n"
        write_log(noround2)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "cell relevant-mmap: want rounds [1, 2], have [1]" in err, err
        assert "cell unrelated-mmap: want rounds [1, 2], have [1]" in err, err
        # Present-but-zero counters/runtime fail with the exact split
        # diagnostic: a zero run-time never reports "below one event per op".
        write_log(log.replace("bpf_ns=160000 bpf_cnt=2000", "bpf_ns=100 bpf_cnt=0"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "(bpf_cnt=0 over ops=1000) is below one event per op" in err, err
        write_log(log.replace("bpf_ns=160000 bpf_cnt=2000", "bpf_ns=0 bpf_cnt=2000"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "on-arm hook run-time (bpf_ns=0 over bpf_cnt=2000) is not positive" in err, err
        assert "below one event per op" not in err, err
        # Events/op outside 2x of expected names the ratio exactly, high
        # and low alike.
        flooded = log
        for old in ("bpf_cnt=2000", "bpf_cnt=2050", "bpf_cnt=2010", "bpf_cnt=1990"):
            flooded = flooded.replace(old, "bpf_cnt=10000")
        write_log(flooded)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "hook events per op are 10.00, want 2 within 2x" in err, err
        hungry = dict(manifest)
        hungry["events_per_op"] = 10
        write_log(log)
        write_manifest(hungry)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "hook events per op are 2.02, want 10 within 2x" in err, err
        write_manifest(manifest)
        write_log(log.replace("cell=unrelated-mmap", "cell=rogue-cell"))
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "cell rogue-cell: sampled but absent from the manifest" in err, err
        assert "cell unrelated-mmap: expected by the manifest, sampled 0 times" in err, err
        # Legacy completion is confined to the reviewed historical
        # artifact: any other stdout, log, or expectation set is rejected,
        # even carrying a DONE line. (The honest 1d pair ACCEPTS; pinned
        # outside this sandbox by the re-validation run, not here.)
        legacy_manifest = dict(manifest)
        legacy_manifest["completion"] = {
            "legacy_stdout": os.path.join(work, "campaign.stdout"),
            "note": "pre-manifest campaign; completion proven by its stdout",
        }
        write_log(log.replace("DONE samples=8\n", ""))
        stdout_path = os.path.join(work, "campaign.stdout")
        with open(stdout_path, "w", encoding="utf-8") as handle:
            handle.write("=== bench-stagea-overhead: DONE (/tmp/x/campaign.log) ===\n")
        legacy_manifest["completion"] = {"legacy_stdout": stdout_path, "note": "test"}
        write_manifest(legacy_manifest)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1, (code, err)
        assert "requires the reviewed historical expectations" in err, err
        assert "is not the reviewed historical artifact" in err, err
        assert "not the reviewed historical campaign" in err, err
        with open(stdout_path, "w", encoding="utf-8") as handle:
            handle.write("interrupted\n")
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1 and "is not the reviewed historical artifact" in err, (code, err)
        legacy_manifest["completion"] = {
            "legacy_stdout": os.path.join(work, "no-such-stdout"),
            "note": "test",
        }
        write_manifest(legacy_manifest)
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 1 and "sha256 unreadable" in err, (code, err)
        # Manifest misuse is a usage error (exit 2), never a verdict.
        write_log(log)
        write_manifest(manifest)
        code, _, err = run([path])
        assert code == 2 and "--manifest" in err, (code, err)
        code, _, err = run([path, "--manifest", os.path.join(work, "no-such.json")])
        assert code == 2 and "cannot read manifest" in err, (code, err)
        with open(manifest_path, "w", encoding="utf-8") as handle:
            handle.write('{"cells": {}}')
        code, _, err = run([path, "--manifest", manifest_path])
        assert code == 2 and "malformed manifest" in err, (code, err)
    print("bench-stagea-overhead-analyze self-test: OK")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
