# SPDX-License-Identifier: GPL-3.0-or-later
"""Classifiers and per-measurement analysis for the C5 campaign (M0-M7).

scripts/measure-c5-campaign.sh runs the cells; this script judges them. It
reuses scripts/bench-inventory-native-stats.py for every bench run's
validity, so a run the stats check refuses is never analysed as data.

Commands:
  m0-pid DIR         classify one `inventory --pid --capture native` run dir
                     (rc, stderr, inventory.json, target.kv) as correct,
                     lossy, refused or missing; prints CLASS=... and reasons
  m0-run RUN         classify one bench run the same way (missing = the stats
                     check refused it; lossy = a lifecycle loss was counted)
  m2 UNIT_DIR...     per-call cost from M2 rounds (target.kv per condition)
  m3 RUN             false joins and unbound shares against the churn ledger
  m4 RUN             ring loss per minute, sticky-demotion share, demotions
  m5 RUN             ticket and CALLER_USE slopes and projections (maps.tsv)
  m7 RUN             discovery_truncated against dlopen processes started
  report CAMPAIGN    write the campaign's c5-measurements.md to stdout
  --self-test        synthetic fixtures for every classifier and calculator

Every number printed comes from a valid run; invalid runs are listed with
their reasons and never enter a distribution.
"""

import importlib.util
import json
import math
import random
import re
import statistics
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("bench_stats", HERE / "bench-inventory-native-stats.py")
stats = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stats)

# Validity limits for every stats.check_run call; main() applies
# --max-load1 (the campaign's bound) before any command.
LIMITS = dict(stats.DEFAULTS)
LOSS_GAP = "lifecycle evidence lost"
LOSS_KEYS = ("ring_loss", "malformed", "failed_quanta")
TICKET_LIMIT = 16384
CLK_TCK = 100


def read_kv(path):
    return stats.read_kv(Path(path))


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def lifecycle_loss(document):
    """(lost?, reasons) from one native inventory document."""
    reasons = []
    observation = (document or {}).get("observation") or {}
    lifecycle = observation.get("lifecycle") or {}
    for key in LOSS_KEYS:
        if lifecycle.get(key):
            reasons.append(f"lifecycle.{key}={lifecycle[key]}")
    for gap in (document or {}).get("gaps") or []:
        if LOSS_GAP in str(gap.get("subject", "")):
            reasons.append(f"gap: {gap.get('subject')}")
    return bool(reasons), reasons


# ---------------------------------------------------------------- M0

def classify_pid(run):
    """M0 leg on a ledgered `--pid` run: correct only when the target's edge
    to the provider reads witnessed with no lifecycle loss."""
    run = Path(run)
    rc = (run / "rc").read_text().strip() if (run / "rc").is_file() else None
    stderr = (run / "stderr").read_text(errors="replace") if (run / "stderr").is_file() else ""
    target = read_kv(run / "target.kv") or {}
    document = load_json(run / "inventory.json")
    if rc is None:
        return "missing", ["no observer exit status"]
    if rc not in ("0", "130"):
        why = [line for line in stderr.splitlines() if line.startswith("p11scope:")][-1:]
        if why:
            return "refused", [f"rc={rc}", why[0][:300]]
        return "missing", [f"rc={rc} with no stated reason"]
    if document is None:
        return "missing", ["no inventory.json"]
    observation = document.get("observation") or {}
    if observation.get("lane") != "native":
        return "refused", [f"lane {observation.get('lane')!r}, not native"]
    lost, reasons = lifecycle_loss(document)
    if lost:
        return "lossy", reasons
    try:
        pid = int(target["pid"])
        total = int(target.get("total", "0"))
    except (KeyError, ValueError):
        return "missing", ["target.kv names no pid"]
    if total <= 0:
        return "missing", ["the ledgered workload counted no calls"]
    callers = {c["id"]: c for c in document.get("callers") or [] if c.get("pid") == pid}
    states = [
        ((edge.get("entries") or {}).get("coverage") or {})
        for edge in document.get("edges") or [] if edge.get("caller") in callers
    ]
    if any(state.get("state") == "witnessed" for state in states):
        return "correct", [f"target {pid} witnessed; workload counted {total} calls"]
    if any(state.get("reason") == "loss" for state in states):
        return "lossy", ["target edge reads unknown/loss"]
    return "unproven", [f"target edge states {[s.get('state') for s in states]}"]


def classify_run(run, limits=None):
    """M0 leg on a bench run: missing when the stats check refuses it."""
    limits = limits or LIMITS
    meta, samples, reasons = stats.check_run(Path(run), limits)
    if reasons:
        return "missing", reasons
    lost = []
    for sample in Path(run).glob("sample-*"):
        document = load_json(sample / "inventory.json")
        if document is not None:
            flag, why = lifecycle_loss(document)
            if flag:
                lost += [f"{sample.name}: {reason}" for reason in why]
    if lost:
        return "lossy", lost
    return "correct", [f"{len(samples)} valid samples, no lifecycle loss"]


# ---------------------------------------------------------------- M2

def bootstrap_ci(values, rounds=2000, seed=11):
    if len(values) < 2:
        return (None, None)
    rng = random.Random(seed)
    medians = sorted(
        statistics.median(rng.choice(values) for _ in values) for _ in range(rounds)
    )
    return medians[int(0.025 * rounds)], medians[int(0.975 * rounds) - 1]


def m2(units):
    """Per-call cost: thread-ns per call = secs*threads*1e9/TOTAL; the
    overhead is the paired difference to the same round's control."""
    rows, invalid = {}, []
    for unit in units:
        unit = Path(unit)
        conds = {}
        for target in sorted(unit.glob("*/target.kv")):
            kv = read_kv(target) or {}
            name = target.parent.name
            try:
                total, threads, secs = int(kv["total"]), int(kv["threads"]), float(kv["secs"])
                ok = kv.get("valid") == "1"
            except (KeyError, ValueError):
                total, ok = 0, False
            if not ok or total <= 0:
                invalid.append(f"{unit.name}/{name}: {kv.get('reason', 'no valid target record')}")
                continue
            conds[name] = (threads, secs * threads * 1e9 / total)
        control = conds.get("control")
        if control is None:
            invalid.append(f"{unit.name}: no valid control; round dropped")
            continue
        for name, (threads, cost) in conds.items():
            entry = rows.setdefault((name, threads), {"cost": [], "overhead": []})
            entry["cost"].append(cost)
            if name != "control":
                entry["overhead"].append(cost - control[1])
    out = []
    for (name, threads), entry in sorted(rows.items()):
        overhead = entry["overhead"]
        low, high = bootstrap_ci(overhead) if overhead else (None, None)
        out.append({
            "condition": name, "threads": threads, "n": len(entry["cost"]),
            "cost_ns_median": statistics.median(entry["cost"]),
            "overhead_ns_median": statistics.median(overhead) if overhead else None,
            "overhead_ci95": (low, high),
        })
    return out, invalid


def m2_verdict(results):
    """M2 bars: native entry cost <= v0.1.0 metrics cost (per thread
    count), and DR-02 GO when +110 ns <= 10% of the native entry cost."""
    lines = []
    by = {(r["condition"], r["threads"]): r for r in results}
    for threads in sorted({r["threads"] for r in results}):
        native = by.get(("cand-native", threads))
        base = by.get(("base-metrics", threads))
        if not native or not base or native["overhead_ns_median"] is None:
            lines.append(f"t={threads}: incomplete (need cand-native and base-metrics)")
            continue
        ok = native["overhead_ns_median"] <= base["overhead_ns_median"]
        dr02 = 110 <= 0.1 * native["overhead_ns_median"]
        lines.append(
            f"t={threads}: native {native['overhead_ns_median']:.0f} ns vs v0.1.0 metrics "
            f"{base['overhead_ns_median']:.0f} ns -> {'PASS' if ok else 'FAIL'}; "
            f"DR-02 V1 +110 ns is {110 / native['overhead_ns_median']:.1%} of native -> "
            f"{'GO' if dr02 else 'NO-GO'}"
        )
    return lines


# ---------------------------------------------------------------- ledgers

def parse_ledger(path):
    """{pid: {kind, fork_ns, reap_ns}} from an exec_churn ledger."""
    children = {}
    if not Path(path).is_file():
        return None
    for line in Path(path).read_text(errors="replace").splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("EXEC", "EXIT"):
            continue
        fields = dict(part.split("=", 1) for part in parts[1:] if "=" in part)
        pid = int(fields.get("pid", "0"))
        if parts[0] == "EXEC":
            children.setdefault(pid, []).append(
                {"kind": fields.get("kind"), "fork_ns": int(fields.get("fork_ns", "0")), "reap_ns": None}
            )
        elif children.get(pid):
            for child in reversed(children[pid]):
                if child["reap_ns"] is None:
                    child["reap_ns"] = int(fields.get("reap_ns", "0"))
                    break
    return children


def ledger_child(children, pid, start_time):
    """The ledger incarnation of pid whose fork matches start_time (clock
    ticks since boot), within one second; None when the pid is unledgered."""
    candidates = children.get(pid) or []
    if start_time is None:
        return candidates[-1] if len(candidates) == 1 else None
    started_ns = start_time * (10**9 // CLK_TCK)
    best = min(candidates, key=lambda c: abs(c["fork_ns"] - started_ns), default=None)
    if best and abs(best["fork_ns"] - started_ns) <= 10**9:
        return best
    return None


def pass_ms(sample):
    stderr = sample / "stderr"
    passes = stats.parse_passes(stderr.read_text(errors="replace")) if stderr.is_file() else {}
    steady = [sum(ops.values()) for number, ops in passes.items() if number > 1]
    return statistics.median(steady) if steady else None


# ---------------------------------------------------------------- M3

def m3_sample(sample):
    document = load_json(sample / "inventory.json")
    children = parse_ledger(sample / "churn.ledger")
    if document is None or children is None:
        return None
    callers = {c["id"]: c for c in document.get("callers") or []}
    false_joins, witnessed_provider, unledgered = [], set(), 0
    for edge in document.get("edges") or []:
        coverage = (edge.get("entries") or {}).get("coverage") or {}
        if coverage.get("state") != "witnessed":
            continue
        caller = callers.get(edge.get("caller")) or {}
        child = ledger_child(children, caller.get("pid"), caller.get("start_time"))
        if child is None:
            unledgered += 1
        elif child["kind"] == "unrelated":
            false_joins.append(f"pid {caller.get('pid')} (/bin/true child) witnessed")
        else:
            witnessed_provider.add((caller.get("pid"), child["fork_ns"]))
    cadence = pass_ms(sample)
    long_lived = [
        (pid, child["fork_ns"])
        for pid, incarnations in children.items() for child in incarnations
        if child["kind"] == "provider" and child["reap_ns"] and cadence
        and child["reap_ns"] - child["fork_ns"] >= 2 * cadence * 1e6
    ]
    unbound_long = [key for key in long_lived if key not in witnessed_provider]
    census = ((document.get("observation") or {}).get("native_witnesses") or {})
    return {
        "sample": sample.name,
        "false_joins": false_joins,
        "witnessed_provider": len(witnessed_provider),
        "witnessed_unledgered": unledgered,
        "provider_children": sum(
            1 for incarnations in children.values() for c in incarnations if c["kind"] == "provider"
        ),
        "long_lived": len(long_lived),
        "unbound_long_share": len(unbound_long) / len(long_lived) if long_lived else None,
        "rows": census.get("rows"), "unbound": census.get("unbound"),
        "unbound_reasons": census.get("unbound_reasons") or {},
        "pass_ms": cadence,
    }


# ---------------------------------------------------------------- M4

def m4_sample(sample, duration_s):
    document = load_json(sample / "inventory.json")
    if document is None:
        return None
    observation = document.get("observation") or {}
    lifecycle = observation.get("lifecycle") or {}
    minutes = max(duration_s, 1) / 60
    demoted = sum(
        1 for edge in document.get("edges") or []
        if ((edge.get("entries") or {}).get("coverage") or {}).get("reason") == "loss"
    )
    first_loss, passes = None, []
    events = sample / "events.jsonl"
    if events.is_file():
        for line in events.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("kind") == "gap_recorded" and LOSS_GAP in str((event.get("event") or {}).get("subject")):
                first_loss = event.get("at_ns") if first_loss is None else first_loss
            if event.get("kind") == "pass_committed" and not (event.get("event") or {}).get("final"):
                passes.append(event.get("at_ns"))
    sticky = (
        sum(1 for at in passes if first_loss is not None and at >= first_loss) / len(passes)
        if passes else None
    )
    return {
        "sample": sample.name,
        "ring_loss": lifecycle.get("ring_loss"),
        "ring_loss_per_min": (lifecycle.get("ring_loss") or 0) / minutes,
        "records": lifecycle.get("records"),
        "recovery_rescans": lifecycle.get("recovery_rescans"),
        "demoted_edges": demoted,
        "demotions_per_min": demoted / minutes,
        "passes": len(passes),
        "sticky_unproven_share": sticky,
    }


# ---------------------------------------------------------------- M5

def slope(points):
    if len(points) < 2:
        return None
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else None


def m5_sample(sample):
    maps = sample / "maps.tsv"
    if not maps.is_file():
        return None
    tickets, rows, capacity = [], [], None
    for line in maps.read_text(errors="replace").splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        ms, name = float(fields[0]), fields[1]
        if name == "COOKIE_CTL" and len(fields) > 4:
            match = re.search(r"next_ticket=(\d+)", fields[4])
            if match:
                tickets.append((ms / 1000, int(match.group(1))))
        elif name == "CALLER_USE" and fields[2].isdigit():
            rows.append((ms / 1000, int(fields[2])))
            capacity = int(fields[3])
    ticket_slope, row_slope = slope(tickets), slope(rows)

    def project(points, rate, limit):
        if not points or not rate or rate <= 0 or limit is None:
            return None
        return (limit - points[-1][1]) / rate

    document = load_json(sample / "inventory.json") or {}
    endpoints = ((document.get("budgets") or {}).get("inventory_endpoints") or {}).get("occupied")
    fds = [row[3] for row in stats.parse_resources(sample / "resources.tsv") if row]
    return {
        "sample": sample.name,
        "ticket_samples": len(tickets), "row_samples": len(rows),
        "next_ticket_per_s": ticket_slope,
        "s_to_ticket_limit": project(tickets, ticket_slope, TICKET_LIMIT),
        "caller_use_rows_per_s": row_slope,
        "caller_use_capacity": capacity,
        "s_to_caller_use_capacity": project(rows, row_slope, capacity),
        "endpoints": endpoints,
        "fds_per_endpoint": (max(fds) / endpoints) if fds and endpoints else None,
    }


# ---------------------------------------------------------------- M7

def m7_sample(sample):
    document = load_json(sample / "profile.json")
    children = parse_ledger(sample / "churn.ledger") or {}
    dlopens = sum(1 for inc in children.values() for c in inc if c["kind"] == "provider")
    evidence = (document or {}).get("evidence") or {}
    return {"sample": sample.name, "dlopen_processes": dlopens,
            "discovery_truncated": evidence.get("discovery_truncated")}


# ---------------------------------------------------------------- per-run drivers

def valid_samples(run):
    meta, samples, reasons = stats.check_run(Path(run), LIMITS)
    return meta, sorted(Path(run).glob("sample-*")), reasons


def per_run(kind, run):
    meta, samples, reasons = valid_samples(run)
    if reasons:
        return {"run": str(run), "invalid": reasons}
    duration = int(meta.get("duration_s", 0) or 0)
    fn = {"m3": m3_sample, "m4": lambda s: m4_sample(s, duration), "m5": m5_sample, "m7": m7_sample}[kind]
    return {"run": str(run), "samples": [fn(sample) for sample in samples]}


# ---------------------------------------------------------------- report

def fmt(value, digits=1):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def spread(values, digits=1):
    values = [v for v in values if v is not None]
    if not values:
        return "n/a"
    return (f"{statistics.median(values):.{digits}f} "
            f"[{min(values):.{digits}f}–{max(values):.{digits}f}] n={len(values)}")


def load_units(campaign):
    units = []
    for unit_file in sorted(Path(campaign).glob("units/*/unit.json")):
        unit = load_json(unit_file)
        if unit:
            unit["dir"] = unit_file.parent
            units.append(unit)
    return units


def bench_runs(unit):
    runs = []
    for attempt in sorted(unit["dir"].glob("attempt-*")):
        run = read_kv(attempt / "attempt.kv") or {}
        if run.get("run"):
            runs.append((attempt, Path(run["run"]), run))
    return runs


def report(campaign, out):
    campaign = Path(campaign)
    meta = load_json(campaign / "campaign.json") or {}
    LIMITS["max_load1"] = float(meta.get("max_load1", LIMITS["max_load1"]))
    LIMITS["max_builds"] = int(meta.get("max_builds", LIMITS["max_builds"]))
    units = load_units(campaign)
    print("# C5 measurements (M0–M7)\n", file=out)
    print(f"Campaign `{campaign}`, written by `scripts/measure-c5-analysis.py report`.\n", file=out)
    for key in ("started", "kernel", "host", "scale", "tier", "max_load1", "max_builds", "candidate", "baseline", "r4_base",
                "loss_candidate", "commit"):
        if key in meta:
            print(f"- **{key}**: `{meta[key]}`", file=out)
    print(file=out)
    statuses = {}
    for unit in units:
        statuses[unit.get("status", "pending")] = statuses.get(unit.get("status", "pending"), 0) + 1
    print("Units: " + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())) + "\n", file=out)

    by_measure = {}
    for unit in units:
        by_measure.setdefault(unit["measurement"], []).append(unit)

    # M0
    if "M0" in by_measure:
        print("## M0 harness validity\n", file=out)
        print("| Leg | Expected | Classified | Reasons |\n|---|---|---|---|", file=out)
        for unit in by_measure["M0"]:
            print(f"| {unit['cell']} | {unit.get('expect')} | {unit.get('class', 'n/a')} | "
                  f"{'; '.join(unit.get('class_reasons', []))[:300]} |", file=out)
        verdict = (campaign / "M0.verdict").read_text().strip() if (campaign / "M0.verdict").is_file() else "not run"
        print(f"\n**M0 verdict:** {verdict}\n", file=out)

    bench_measures = [m for m in ("M1", "R4", "M1-match", "M3", "M4", "M5", "M6", "M7") if m in by_measure]
    for measure in bench_measures:
        print(f"## {measure}\n", file=out)
        runs = []
        for unit in by_measure[measure]:
            for attempt, run, kv in bench_runs(unit):
                runs.append(run)
        valid = [run for run in runs if run.is_dir() and not stats.check_run(run, LIMITS)[2]]

        class Sink:
            text = ""

            def write(self, text):
                Sink.text += text
        Sink.text = ""
        if runs:
            stats.summary([run for run in runs if run.is_dir()], LIMITS, Sink())
        print("```text\n" + Sink.text.rstrip() + "\n```\n", file=out)
        kind = {"M3": "m3", "M4": "m4", "M5": "m5", "M7": "m7"}.get(measure)
        if kind:
            print("| Run | Sample | Result |\n|---|---|---|", file=out)
            for run in valid:
                result = per_run(kind, run)
                for sample in result.get("samples", []):
                    print(f"| {run.name} | {sample and sample.pop('sample')} | "
                          f"{json.dumps(sample, sort_keys=True)[:400]} |", file=out)
            print(file=out)
        verdict_file = campaign / f"{measure}.verdict"
        if verdict_file.is_file():
            print(f"**Verdict input:** {verdict_file.read_text().strip()}\n", file=out)

    if "M2" in by_measure:
        print("## M2 per-call cost\n", file=out)
        results, invalid = m2([unit["dir"] / "data" for unit in by_measure["M2"]
                               if (unit["dir"] / "data").is_dir()])
        print("| Condition | Threads | n | ns/call (median) | overhead ns (median) | 95% CI |\n"
              "|---|---|---|---|---|---|", file=out)
        for r in results:
            low, high = r["overhead_ci95"]
            print(f"| {r['condition']} | {r['threads']} | {r['n']} | {r['cost_ns_median']:.0f} | "
                  f"{fmt(r['overhead_ns_median'], 0)} | {fmt(low, 0)}–{fmt(high, 0)} |", file=out)
        print(file=out)
        for line in m2_verdict(results):
            print(f"- {line}", file=out)
        for line in invalid:
            print(f"- INVALID {line}", file=out)
        print(file=out)

    print("## Units\n", file=out)
    print("| Unit | Status | Attempts | Reason |\n|---|---|---|---|", file=out)
    for unit in units:
        print(f"| {unit['id']} | {unit.get('status', 'pending')} | {unit.get('attempts', 0)} | "
              f"{str(unit.get('reason', ''))[:200]} |", file=out)
    return 0


# ---------------------------------------------------------------- self-test

def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def pid_run(name, rc="0", lane="native", coverage="witnessed", reason=None,
                    ring_loss=0, total=1000, document=True, stderr=""):
            run = root / name
            run.mkdir()
            (run / "rc").write_text(rc + "\n")
            (run / "stderr").write_text(stderr)
            (run / "target.kv").write_text(f"pid=42\ntotal={total}\n")
            if document:
                (run / "inventory.json").write_text(json.dumps({
                    "observation": {"lane": lane, "lifecycle": {"ring_loss": ring_loss}},
                    "callers": [{"id": "c0", "pid": 42, "start_time": 5}],
                    "edges": [{"caller": "c0", "module": "m0", "entries": {
                        "coverage": {"state": coverage, "reason": reason}}}],
                    "gaps": [],
                }))
            return run

        cases = [
            (pid_run("correct"), "correct"),
            (pid_run("lossy", ring_loss=12), "lossy"),
            (pid_run("lossy-edge", coverage="unknown", reason="loss"), "lossy"),
            (pid_run("refused", rc="1", document=False,
                     stderr="p11scope: --capture native: the native usage lane cannot run: x\n"), "refused"),
            (pid_run("scan-lane", lane=None), "refused"),
            (pid_run("no-document", document=False), "missing"),
            (pid_run("no-calls", total=0), "missing"),
            (pid_run("watched", coverage="watched_no_use"), "unproven"),
        ]
        for run, want in cases:
            got, why = classify_pid(run)
            assert got == want, f"{run.name}: {got} {why}, want {want}"
            print(f"  m0-pid {run.name}: {got}")
        valid = stats.write_run(root, "bench-valid")
        assert classify_run(valid)[0] == "lossy", classify_run(valid)  # synthetic ring_loss=7
        for sample in valid.glob("sample-*"):
            document = json.loads((sample / "inventory.json").read_text())
            document["observation"]["lifecycle"]["ring_loss"] = 0
            (sample / "inventory.json").write_text(json.dumps(document))
        assert classify_run(valid)[0] == "correct", classify_run(valid)
        killed = stats.write_run(root, "bench-killed")
        (killed / "run.json").write_text((killed / "run.json").read_text().replace(
            '"duration_s": 3', '"duration_s": 60'))
        got, why = classify_run(killed)
        assert got == "missing" and any("sampler" in r for r in why), (got, why)
        print("  m0-run: correct, lossy, missing (killed sampler) ok")

        # M2: control 1000 calls/s/thread -> 1e6 ns; native 500 -> +1e6 ns.
        unit = root / "m2-round"
        for name, total in (("control", 5000), ("cand-native", 2500), ("base-metrics", 2000)):
            (unit / name).mkdir(parents=True)
            (unit / name / "target.kv").write_text(f"total={total}\nthreads=1\nsecs=5\nvalid=1\n")
        bad = root / "m2-bad"
        (bad / "cand-native").mkdir(parents=True)
        (bad / "cand-native" / "target.kv").write_text("total=10\nthreads=1\nsecs=5\nvalid=1\n")
        results, invalid = m2([unit, bad])
        by = {r["condition"]: r for r in results}
        assert by["cand-native"]["overhead_ns_median"] == 1e6, by
        assert by["base-metrics"]["overhead_ns_median"] == 1.5e6, by
        assert any("no valid control" in line for line in invalid), invalid
        assert "PASS" in m2_verdict(results)[0] and "GO" in m2_verdict(results)[0]
        print("  m2: paired overhead, verdict and dropped round ok")

        # M3: ledger join by pid + start time.
        sample = root / "m3" / "sample-1-cold"
        sample.mkdir(parents=True)
        (sample / "churn.ledger").write_text(
            "EXEC pid=100 kind=provider fork_ns=1000000000\n"
            "EXEC pid=101 kind=unrelated fork_ns=1010000000\n"
            "EXEC pid=102 kind=provider fork_ns=1020000000\n"
            "EXIT pid=100 status=0 reap_ns=9000000000\n"
            "EXIT pid=101 status=0 reap_ns=1020000000\n"
            "EXIT pid=102 status=0 reap_ns=9000000000\n"
        )
        (sample / "stderr").write_text("".join(
            f"p11scope: pass {i}: stage timings: sweep 500.000ms\n" for i in range(1, 5)))
        (sample / "inventory.json").write_text(json.dumps({
            "observation": {"native_witnesses": {"rows": 3, "unbound": 1,
                                                  "unbound_reasons": {"no_live_caller": 1}}},
            "callers": [{"id": "a", "pid": 100, "start_time": 100},
                        {"id": "b", "pid": 101, "start_time": 101},
                        {"id": "c", "pid": 555, "start_time": 7}],
            "edges": [{"caller": c, "entries": {"coverage": {"state": "witnessed"}}} for c in "abc"],
        }))
        result = m3_sample(sample)
        assert len(result["false_joins"]) == 1 and "101" in result["false_joins"][0], result
        assert result["witnessed_provider"] == 1 and result["witnessed_unledgered"] == 1, result
        assert result["long_lived"] == 2 and result["unbound_long_share"] == 0.5, result
        print("  m3: false join, unledgered caller and long-lived unbound share ok")

        # M4.
        sample = root / "m4" / "sample-1-cold"
        sample.mkdir(parents=True)
        (sample / "inventory.json").write_text(json.dumps({
            "observation": {"lifecycle": {"ring_loss": 30, "records": 900, "recovery_rescans": 1}},
            "edges": [{"entries": {"coverage": {"reason": "loss"}}},
                      {"entries": {"coverage": {"reason": None}}}],
        }))
        (sample / "events.jsonl").write_text("\n".join(json.dumps(e) for e in [
            {"kind": "pass_committed", "at_ns": 1, "event": {}},
            {"kind": "gap_recorded", "at_ns": 2, "event": {"subject": "native capture lifecycle evidence lost"}},
            {"kind": "pass_committed", "at_ns": 3, "event": {}},
            {"kind": "pass_committed", "at_ns": 4, "event": {"final": True}},
        ]) + "\n")
        result = m4_sample(sample, 60)
        assert result["ring_loss_per_min"] == 30 and result["demoted_edges"] == 1, result
        assert result["sticky_unproven_share"] == 0.5 and result["passes"] == 2, result
        print("  m4: loss rate, demotions and sticky share ok")

        # M5.
        sample = root / "m5" / "sample-1-cold"
        sample.mkdir(parents=True)
        (sample / "maps.tsv").write_text(
            "# ms map rows capacity extra\n"
            "0\tCOOKIE_CTL\t1\t1\tnext_ticket=100 limit=16384\n0\tCALLER_USE\t10\t65536\t\n"
            "10000\tCOOKIE_CTL\t1\t1\tnext_ticket=200 limit=16384\n10000\tCALLER_USE\t30\t65536\t\n"
        )
        result = m5_sample(sample)
        assert result["next_ticket_per_s"] == 10 and result["caller_use_rows_per_s"] == 2, result
        assert round(result["s_to_ticket_limit"]) == 1618, result
        print("  m5: slopes and projections ok")

        # M7.
        sample = root / "m7" / "sample-1-cold"
        sample.mkdir(parents=True)
        (sample / "profile.json").write_text(json.dumps({"evidence": {"discovery_truncated": 44}}))
        (sample / "churn.ledger").write_text("EXEC pid=1 kind=provider fork_ns=1\n" * 3)
        assert m7_sample(sample) == {"sample": "sample-1-cold", "dlopen_processes": 3,
                                     "discovery_truncated": 44}, m7_sample(sample)
        print("  m7: truncation count ok")
        assert math.isclose(slope([(0, 0), (1, 2), (2, 4)]), 2.0)
    print("measure-c5-analysis: self-test ok")
    return 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    while argv[:1] in (["--max-load1"], ["--max-builds"]) and len(argv) > 1:
        key = argv[0][2:].replace("-", "_")
        LIMITS[key] = float(argv[1]) if key == "max_load1" else int(argv[1])
        argv = argv[2:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    command, args = argv[0], argv[1:]
    if command == "m0-pid":
        got, why = classify_pid(args[0])
    elif command == "m0-run":
        got, why = classify_run(args[0])
    elif command == "m2":
        results, invalid = m2(args)
        print(json.dumps({"results": results, "invalid": invalid, "verdict": m2_verdict(results)}, indent=2))
        return 0
    elif command in ("m3", "m4", "m5", "m7"):
        print(json.dumps(per_run(command, args[0]), indent=2))
        return 0
    elif command == "report":
        return report(args[0], sys.stdout)
    else:
        print(__doc__, file=sys.stderr)
        return 64
    print(f"CLASS={got}")
    for reason in why:
        print(f"  - {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
