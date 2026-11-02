#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Birth-marker cost verdict math for scripts/bench-marker-cost.sh.

Reads a campaign log plus its pre-declared manifest, verifies the
campaign shape (cells, rounds, rotating arm order, exact ops, DONE
completion) and renders the cost table: per-cell per-arm medians and
spread, and the on-versus-off deltas for the disarmed arm (on-profile
minus off-profile) and the armed arm (on-armed minus on-profile), each
beside the 2% owner figure (CP-5) as data. The result is recorded, not
gated: this program exits nonzero only on a malformed campaign, never
on a large delta. A campaign whose call-rate workload never succeeded
is malformed: its latency medians would be error-path timings.

Usage: bench-marker-cost-analyze.py LOG --manifest MANIFEST [--out PATH]
       bench-marker-cost-analyze.py --self-test
"""
import argparse
import json
import statistics
import sys

ARMS = ("none", "off-profile", "on-profile", "on-armed")
# (label, costlier arm, baseline arm)
DELTA_PAIRS = (
    ("disarmed", "on-profile", "off-profile"),
    ("armed", "on-armed", "on-profile"),
    ("total", "on-armed", "off-profile"),
)
TWO_PCT = 0.02


class CampaignError(Exception):
    """A malformed campaign (exit 1)."""


def parse_sample(line):
    """Parse one SAMPLE line into a dict; raise CampaignError."""
    fields = {}
    for token in line.split()[1:]:
        if "=" not in token:
            raise CampaignError(f"bad SAMPLE token: {token}")
        key, value = token.split("=", 1)
        fields[key] = value
    for key in ("cell", "arm", "round", "ops", "wall_ns",
                "bpf_prog", "bpf_ns", "bpf_cnt"):
        if key not in fields:
            raise CampaignError(f"SAMPLE missing {key}: {line.strip()}")
    try:
        fields["round"] = int(fields["round"])
        fields["ops"] = int(fields["ops"])
        fields["wall_ns"] = int(fields["wall_ns"])
    except ValueError:
        raise CampaignError(f"SAMPLE has non-integer round/ops/wall: {line.strip()}")
    if fields["cell"] == "call-rate":
        for key in ("rate_per_s", "lat_med_ns", "lat_p90_ns", "unhealthy"):
            if key not in fields:
                raise CampaignError(f"call-rate SAMPLE missing {key}")
        try:
            fields["rate_per_s"] = float(fields["rate_per_s"])
            fields["lat_med_ns"] = int(fields["lat_med_ns"])
            fields["lat_p90_ns"] = int(fields["lat_p90_ns"])
            fields["unhealthy"] = int(fields["unhealthy"])
        except ValueError:
            raise CampaignError("call-rate SAMPLE has non-numeric rate/latency")
    if fields["wall_ns"] <= 0 or fields["ops"] <= 0:
        raise CampaignError(f"SAMPLE has non-positive ops/wall: {line.strip()}")
    for key in ("bpf_ns", "bpf_cnt"):
        value = fields[key]
        if value in ("absent", "none"):
            fields[key] = value
        else:
            try:
                fields[key] = int(value)
            except ValueError:
                raise CampaignError(f"SAMPLE has bad {key}: {value}")
    return fields


def expected_order(arms, rounds):
    """Arm order per round (ABBA): odd rounds forward, even reversed."""
    order = {}
    for rnd in range(1, rounds + 1):
        forward = list(arms)
        order[rnd] = forward if rnd % 2 == 1 else forward[::-1]
    return order


def verify(log_path, manifest_path):
    """Verify the campaign; return (manifest, samples). Raise CampaignError."""
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as error:
        raise CampaignError(f"cannot read manifest: {error}")
    cells = manifest.get("cells", {})
    arms = manifest.get("arms", [])
    if arms != list(ARMS):
        raise CampaignError(f"manifest arms {arms} != {list(ARMS)}")
    if not cells or any(c not in ("exec-storm", "call-rate") for c in cells):
        raise CampaignError(f"manifest cells are not a known subset: {sorted(cells)}")
    try:
        with open(log_path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as error:
        raise CampaignError(f"cannot read log: {error}")
    samples = [parse_sample(line) for line in lines if line.startswith("SAMPLE ")]
    done = [line for line in lines if line.startswith("DONE ")]
    if len(done) != 1:
        raise CampaignError(f"want exactly one DONE line, saw {len(done)}")
    claimed = None
    for token in done[0].split()[1:]:
        if token.startswith("samples="):
            try:
                claimed = int(token.split("=", 1)[1])
            except ValueError:
                claimed = None
    if claimed != len(samples):
        raise CampaignError(
            f"DONE claims {claimed} samples, log holds {len(samples)}")
    # Per-cell per-round arm order must follow the rotation exactly.
    by_cell_round = {}
    for sample in samples:
        by_cell_round.setdefault((sample["cell"], sample["round"]), []).append(sample["arm"])
    for cell, spec in cells.items():
        rounds = spec["rounds"]
        order = expected_order(arms, rounds)
        for rnd in range(1, rounds + 1):
            got = by_cell_round.get((cell, rnd), [])
            if got != order[rnd]:
                raise CampaignError(
                    f"{cell} round {rnd}: arm order {got} != rotation {order[rnd]}")
        # Exact workload shape per cell.
        for sample in samples:
            if sample["cell"] != cell:
                continue
            if cell == "exec-storm" and sample["ops"] != spec["ops"]:
                raise CampaignError(
                    f"exec-storm ops {sample['ops']} != manifest {spec['ops']}")
            if sample["arm"] != "none" and sample["bpf_prog"] not in (
                    "sched_process_exec", "p11_entry"):
                raise CampaignError(f"unknown bpf_prog {sample['bpf_prog']}")
    if {s["cell"] for s in samples} != set(cells):
        raise CampaignError("sample cells do not match the manifest")
    rated = [s for s in samples if s["cell"] == "call-rate"]
    if rated and all(s["unhealthy"] >= s["ops"] for s in rated):
        raise CampaignError(
            "no call-rate sample has a healthy call; the latency "
            "medians would be error-path timings")
    return manifest, samples


def summarize(values):
    """(median, min, max, n) over a non-empty list of numbers."""
    return (statistics.median(values), min(values), max(values), len(values))


def fmt(value):
    """Compact number formatting for the table."""
    if isinstance(value, float):
        if abs(value) >= 1000:
            return f"{value:,.0f}"
        return f"{value:.2f}"
    return f"{value:,d}"


def render(manifest, samples):
    """Render the cost table; return the text."""
    lines = []
    lines.append("birth-marker cost (recorded, not gated; 2% is the CP-5 owner figure)")
    lines.append("")
    by_cell_arm = {}
    for sample in samples:
        by_cell_arm.setdefault((sample["cell"], sample["arm"]), []).append(sample)
    for cell in manifest["cells"]:
        lines.append(f"== {cell} ==")
        medians = {}
        for arm in manifest["arms"]:
            group = by_cell_arm[(cell, arm)]
            if cell == "exec-storm":
                per_op = [s["wall_ns"] / s["ops"] for s in group]
                med, lo, hi, n = summarize(per_op)
                medians[arm] = med
                lines.append(f"  {arm:11s} ns/exec median={fmt(med)} "
                             f"spread=[{fmt(lo)},{fmt(hi)}] n={n}")
            else:
                rates = [s["rate_per_s"] for s in group]
                lats = [s["lat_med_ns"] for s in group]
                p90s = [s["lat_p90_ns"] for s in group]
                sick = [s["unhealthy"] for s in group]
                r_med, r_lo, r_hi, n = summarize(rates)
                l_med, l_lo, l_hi, _ = summarize(lats)
                p_med, p_lo, p_hi, _ = summarize(p90s)
                u_med, u_lo, u_hi, _ = summarize(sick)
                medians[arm] = l_med
                lines.append(f"  {arm:11s} rate/s median={fmt(r_med)} "
                             f"spread=[{fmt(r_lo)},{fmt(r_hi)}] n={n}")
                lines.append(f"  {arm:11s} lat_ns median={fmt(l_med)} "
                             f"spread=[{fmt(l_lo)},{fmt(l_hi)}]")
                lines.append(f"  {arm:11s} lat_p90_ns median={fmt(p_med)} "
                             f"spread=[{fmt(p_lo)},{fmt(p_hi)}]")
                lines.append(f"  {arm:11s} unhealthy median={fmt(u_med)} "
                             f"spread=[{fmt(u_lo)},{fmt(u_hi)}] "
                             f"total={fmt(sum(sick))}")
            present = [s for s in group
                       if s["bpf_ns"] not in ("absent", "none")]
            missing = len(group) - len(present)
            if present:
                per_event = [s["bpf_ns"] / s["bpf_cnt"] for s in present
                             if s["bpf_cnt"] > 0]
                if per_event:
                    b_med, b_lo, b_hi, n = summarize(per_event)
                    lines.append(f"  {arm:11s} bpf {group[0]['bpf_prog']} "
                                 f"ns/event median={fmt(b_med)} "
                                 f"spread=[{fmt(b_lo)},{fmt(b_hi)}] n={n}")
            if missing:
                lines.append(f"  {arm:11s} bpf {group[0]['bpf_prog']}: "
                             f"{missing}/{len(group)} samples absent")
        unit = "ns/exec" if cell == "exec-storm" else "lat_ns"
        for label, costlier, baseline in DELTA_PAIRS:
            delta = medians[costlier] - medians[baseline]
            base = medians[baseline]
            pct = delta / base if base else float("inf")
            flag = "exceeds 2%" if abs(pct) > TWO_PCT else "within 2%"
            lines.append(f"  delta {label:8s} ({costlier} - {baseline}): "
                         f"{fmt(delta)} {unit} ({pct:+.2%}, {flag})")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", nargs="?",
                        help="campaign log with SAMPLE/DONE lines")
    parser.add_argument("--manifest", help="pre-declared campaign manifest")
    parser.add_argument("--out", help="write the table to PATH as well")
    parser.add_argument("--self-test", action="store_true",
                        help="run the built-in checks")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.log or not args.manifest:
        parser.error("LOG and --manifest are required")
    try:
        manifest, samples = verify(args.log, args.manifest)
        table = render(manifest, samples)
    except CampaignError as error:
        print(f"bench-marker-cost-analyze: {error}", file=sys.stderr)
        return 1
    print(table, end="")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(table)
    return 0


def self_test():
    """Built-in checks: one passing campaign plus every failure mode."""
    import tempfile
    failures = []

    def check(name, cond):
        if not cond:
            failures.append(name)

    def campaign(extra_lines=(), drop=(), manifest=None, mutate=None):
        work = tempfile.mkdtemp(prefix="markercost-analyzer-")
        man = {"cells": {"exec-storm": {"rounds": 2, "ops": 100},
                         "call-rate": {"rounds": 1, "rate": "1k",
                                       "duration_s": 2}},
               "arms": list(ARMS),
               "rotation": "ABBA: odd rounds forward, even rounds reversed",
               "completion": {"marker": "DONE"}}
        if manifest is not None:
            man = manifest(man)
        man_path = f"{work}/manifest.json"
        with open(man_path, "w", encoding="utf-8") as handle:
            json.dump(man, handle)
        log = ["MACHINE kernel=test",
               "BINARY which=on path=/bin/on sha256=aa commit=bb",
               "BINARY which=off path=/bin/off sha256=cc commit=bb"]
        lat = 1000
        for cell in ("exec-storm", "call-rate"):
            rounds = man["cells"][cell]["rounds"]
            for rnd in range(1, rounds + 1):
                order = expected_order(list(ARMS), rounds)[rnd]
                for arm in order:
                    if (cell, rnd, arm) in drop:
                        continue
                    ops = 100 if cell == "exec-storm" else 2000
                    wall = 100_000 if cell == "exec-storm" else 2_000_000_000
                    if cell == "call-rate" and arm == "on-armed":
                        lat = 1100
                    elif cell == "call-rate":
                        lat = 1000
                    extra = "" if cell == "exec-storm" else (
                        f" rate_per_s=1000.0 lat_med_ns={lat} "
                        f"lat_p90_ns={lat + 100} unhealthy=0")
                    prog = ("sched_process_exec" if cell == "exec-storm"
                            else "p11_entry")
                    bpf = ("bpf_prog=" + prog + " bpf_ns=50000 bpf_cnt=100"
                           if arm != "none" else
                           "bpf_prog=" + prog + " bpf_ns=none bpf_cnt=none")
                    log.append(f"SAMPLE cell={cell} arm={arm} round={rnd} "
                               f"ops={ops} wall_ns={wall}{extra} {bpf}")
        log.extend(extra_lines)
        if mutate is not None:
            log = mutate(log)
        log_path = f"{work}/campaign.log"
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(log) + "\n")
        return work, log_path, man_path

    work, log, man = campaign(extra_lines=("DONE samples=12",))
    try:
        manifest, samples = verify(log, man)
        table = render(manifest, samples)
    except CampaignError as error:
        check(f"passing campaign verifies ({error})", False)
        table = ""
    check("passing campaign renders disarmed delta",
          "delta disarmed" in table and "on-profile - off-profile" in table)
    check("passing campaign renders armed delta", "delta armed" in table)
    check("passing campaign shows the armed call latency cost",
          "100 lat_ns (+10.00%, exceeds 2%)" in table)
    check("passing campaign shows exec deltas at zero",
          "0 ns/exec (+0.00%, within 2%)" in table)

    def must_fail(name, **kwargs):
        work2, log2, man2 = campaign(**kwargs)
        try:
            verify(log2, man2)
        except CampaignError:
            return
        check(f"{name} must fail", False)

    must_fail("missing DONE")
    must_fail("dropped sample", drop={("exec-storm", 1, "none")},
              extra_lines=("DONE samples=11",))
    must_fail("wrong arm order",
              mutate=lambda log: [
                  l.replace("arm=none", "arm=TMP").replace(
                      "arm=off-profile", "arm=none").replace(
                      "arm=TMP", "arm=off-profile")
                  if l.startswith("SAMPLE cell=exec-storm") and "round=1" in l
                  else l for l in log] + ["DONE samples=12"])
    must_fail("ops mismatch",
              mutate=lambda log: [
                  l.replace("ops=100 ", "ops=99 ", 1)
                  if l.startswith("SAMPLE cell=exec-storm") else l
                  for l in log] + ["DONE samples=12"])
    must_fail("manifest mismatch",
              manifest=lambda m: {**m, "cells": {
                  **m["cells"], "exec-storm": {"rounds": 2, "ops": 101}}},
              extra_lines=("DONE samples=12",))
    must_fail("zero wall",
              mutate=lambda log: [
                  l.replace("wall_ns=100000", "wall_ns=0", 1)
                  if l.startswith("SAMPLE cell=exec-storm") else l
                  for l in log] + ["DONE samples=12"])
    must_fail("double DONE", extra_lines=("DONE samples=12", "DONE samples=12"))
    must_fail("DONE count mismatch", extra_lines=("DONE samples=11",))
    must_fail("DONE count unparseable", extra_lines=("DONE samples=many",))
    must_fail("no healthy call-rate call",
              mutate=lambda log: [
                  l.replace("unhealthy=0", "unhealthy=2000")
                  if l.startswith("SAMPLE cell=call-rate") else l
                  for l in log] + ["DONE samples=12"])
    # One sick sample keeps the campaign: partial errors are data.
    def sicken_first(log):
        out = []
        sickened = False
        for line in log:
            if line.startswith("SAMPLE cell=call-rate") and not sickened:
                line = line.replace("unhealthy=0", "unhealthy=2000", 1)
                sickened = True
            out.append(line)
        return out

    work3, log3, man3 = campaign(
        mutate=sicken_first, extra_lines=("DONE samples=12",))
    try:
        table3 = render(*verify(log3, man3))
    except CampaignError as error:
        check(f"partial unhealthy verifies ({error})", False)
        table3 = ""
    check("partial unhealthy renders its total", "total=2,000" in table3)
    print(f"bench-marker-cost-analyze self-test: "
          f"{'OK' if not failures else 'FAIL ' + str(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
