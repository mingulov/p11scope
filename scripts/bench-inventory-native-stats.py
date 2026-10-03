# SPDX-License-Identifier: GPL-3.0-or-later
"""Validity checks and statistics for scripts/bench-inventory-native.sh (Task 6 C5.5).

A run directory written by the bench holds:

  run.json            the cell: binary, capture mode, sizes, churn, pinning
  lock.txt            proof the run held the shared privileged lock
  load.txt            host load and build activity at run start and end
  sample-N-KIND/      one observer run (KIND cold for N=1, warm after):
    stderr            `P11SCOPE_STAGE_TIMINGS=1` lines, one per pass
    resources.tsv     observer RSS and descriptor samples (ms, rss_kb, hwm_kb, fds)
    load.txt          host load at this sample's start and end
    rc                observer exit status
    churn.ledger      exec_churn ledger, when the cell churns (or one ledger
                      for the whole run at RUN/churn.ledger)
    inventory.json    the observer's -o document (read for named counters only)

Absent or zero samples are INVALID, never fast: a run without a lock or a load
record, with load1 above the bound or a Cargo build running when it started,
with fewer stage-timed passes than required, with a pass whose stages sum to
zero, with a missing or zero resource sample, with a native capture lacking
a native span or a native lane statement, or with exec churn below 90% of its
target or with failed execs is refused with its reasons. Failed and invalid
runs stay on disk; this script only reports them.

A native capture proves itself two ways: every pass carries the full
inventory span set (completeness), and each inventory.json states
observation.lane "native" (C5.1 writes lane/settlement/retirement only in
the native lane). Census counters are read by exact path and reported
missing when absent, never silently zero.

Usage:
  python3 -I scripts/bench-inventory-native-stats.py check RUN_DIR...
  python3 -I scripts/bench-inventory-native-stats.py summary RUN_DIR...
  python3 -I scripts/bench-inventory-native-stats.py --self-test
Options (before the command): --max-load1 X (default 4), --min-passes N
(default 3), --native-spans a,b,c (default
deep_scan,assemble,confirm,absorb,reconcile,project).

`check` exits 0 when every run is valid and 1 otherwise; `summary` prints the
valid runs grouped by cell (capture, processes, callers, churn, kind) as
distributions of per-run p50/p95 (median and min..max), never a best sample,
and lists the invalid runs with their reasons.
"""

import json
import re
import statistics
import sys
import tempfile
from pathlib import Path

DEFAULTS = {
    "max_load1": 4.0,
    "min_passes": 3,
    # The inventory spans every pass emits (C5.1, first-recorded order):
    # catalog deep_scan/assemble/confirm plus coordinator
    # absorb/reconcile/project. sweep/select are conditional (over the pid
    # cap only) and never required.
    "native_spans": ("deep_scan", "assemble", "confirm", "absorb", "reconcile", "project"),
    "min_resource_samples": 3,
    "churn_floor": 0.9,
}
PASS_LINE = re.compile(r"p11scope: pass (\d+): stage timings: (.*)")
OP = re.compile(r"([A-Za-z_][\w.-]*) ([\d.]+)ms")
# Census counters (M3/M4 oracle inputs) read by exact path from the -o
# document: bare-key search would mix unrelated same-named fields
# (caller-level "rows" vs. the binder census "rows").
COUNTER_PATHS = (
    ("native_rows", ("observation", "native_witnesses", "rows")),
    ("native_bound", ("observation", "native_witnesses", "bound")),
    ("native_unbound", ("observation", "native_witnesses", "unbound")),
    ("native_pending", ("observation", "native_witnesses", "pending")),
    ("native_integrity", ("observation", "native_witnesses", "integrity")),
    ("lifecycle_loss", ("observation", "native_witnesses", "unbound_reasons", "lifecycle_loss")),
)


def read_kv(path):
    """`key=value` lines; None when the file is absent."""
    if not path.is_file():
        return None
    values = {}
    for line in path.read_text(errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def parse_passes(text):
    passes = {}
    for line in text.splitlines():
        match = PASS_LINE.search(line)
        if match:
            passes[int(match.group(1))] = {
                op: float(ms) for op, ms in OP.findall(match.group(2))
            }
    return passes


def parse_resources(path):
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        try:
            rows.append(tuple(int(field) for field in fields[:4]))
        except ValueError:
            rows.append(None)  # a malformed row is a missing sample
    return rows


def parse_churn(path):
    if not path.is_file():
        return None
    summary = None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("SUMMARY "):
            summary = dict(
                part.split("=", 1) for part in line.split()[1:] if "=" in part
            )
    return summary


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, max(0, round(q * (len(values) - 1))))]


def read_census(document):
    """Counter values by oracle name; None when the path is absent or not a
    number. A present census with no lifecycle_loss entry means zero loss
    (the binder only inserts reasons it counted)."""
    found = dict.fromkeys((name for name, _ in COUNTER_PATHS))
    if not isinstance(document, dict):
        return found
    for name, path in COUNTER_PATHS:
        node = document
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, (int, float)):
            found[name] = node
    observation = document.get("observation")
    census = observation.get("native_witnesses") if isinstance(observation, dict) else None
    if found["lifecycle_loss"] is None and isinstance(census, dict):
        found["lifecycle_loss"] = 0
    return found


def check_load(path, limits, where, reasons):
    load = read_kv(path)
    if load is None:
        reasons.append(f"{where}: no load record")
        return None
    for key in ("load1_start", "load1_end"):
        try:
            float(load.get(key, ""))
        except ValueError:
            reasons.append(f"{where}: load record lacks {key}")
            return None
    if float(load["load1_start"]) > limits["max_load1"]:
        reasons.append(
            f"{where}: load1 {load['load1_start']} above {limits['max_load1']} at start"
        )
    builds = load.get("build_processes_start", "")
    if not builds.isdigit():
        reasons.append(f"{where}: load record lacks build_processes_start")
    elif int(builds) > 0:
        reasons.append(f"{where}: {builds} cargo/rustc processes running at start")
    return load


def check_churn(summary, target, where, limits, reasons):
    if summary is None:
        reasons.append(f"{where}: churn {target}/s but no churn ledger SUMMARY")
        return
    try:
        execs = int(summary["execs"])
        achieved = float(summary["achieved_rate"])
        failed = int(summary["exec_fail"])
    except (KeyError, ValueError):
        reasons.append(f"{where}: malformed churn SUMMARY")
        return
    if execs == 0:
        reasons.append(f"{where}: churn ledger has zero execs")
    elif achieved < limits["churn_floor"] * target:
        reasons.append(f"{where}: churn {achieved:.1f}/s below 90% of {target}/s")
    if failed:
        reasons.append(f"{where}: {failed} churn execs failed")


def check_sample(sample, meta, limits, reasons):
    where = sample.name
    check_load(sample / "load.txt", limits, where, reasons)
    rc = (sample / "rc").read_text().strip() if (sample / "rc").is_file() else None
    if rc != "0":
        reasons.append(f"{where}: observer exit status {rc or 'missing'}")
    stderr = sample / "stderr"
    passes = parse_passes(stderr.read_text(errors="replace")) if stderr.is_file() else {}
    if len(passes) < limits["min_passes"]:
        reasons.append(
            f"{where}: {len(passes)} stage-timed passes, need {limits['min_passes']}"
        )
    for number, ops in sorted(passes.items()):
        if not ops or sum(ops.values()) <= 0:
            reasons.append(f"{where}: pass {number} has a zero stage sample")
    if meta.get("capture") == "native" and passes:
        for span in limits["native_spans"]:
            if not any(span in ops for ops in passes.values()):
                reasons.append(
                    f"{where}: native span {span} absent from stage timings "
                    "(the binary emits no such span)"
                )
            elif not any(ops.get(span, 0) > 0 for ops in passes.values()):
                reasons.append(f"{where}: native span {span} never sampled")
    rows = parse_resources(sample / "resources.tsv")
    if len(rows) < limits["min_resource_samples"]:
        reasons.append(f"{where}: {len(rows)} resource samples, need {limits['min_resource_samples']}")
    elif any(row is None or len(row) < 4 or 0 in row[1:4] for row in rows):
        reasons.append(f"{where}: missing or zero resource sample")
    churn = int(meta.get("churn_rate", 0) or 0)
    if churn and meta.get("churn_scope", "sample") == "sample":
        check_churn(parse_churn(sample / "churn.ledger"), churn, where, limits, reasons)
    counters = dict.fromkeys((name for name, _ in COUNTER_PATHS))
    document = sample / "inventory.json"
    parsed = None
    if document.is_file():
        try:
            parsed = json.loads(document.read_text())
        except ValueError:
            reasons.append(f"{where}: inventory.json is not JSON")
        if parsed is not None:
            counters = read_census(parsed)
    if meta.get("capture") == "native":
        if parsed is None and document.is_file():
            pass  # already refused above as not JSON
        elif parsed is None:
            reasons.append(f"{where}: native capture wrote no inventory.json (no lane proof)")
        else:
            observation = parsed.get("observation") if isinstance(parsed, dict) else None
            lane = observation.get("lane") if isinstance(observation, dict) else None
            if lane is None:
                reasons.append(f"{where}: inventory.json states no observation lane (want 'native')")
            elif lane != "native":
                reasons.append(f"{where}: observation lane is {lane!r}, want 'native'")
    steady = [sum(ops.values()) for number, ops in passes.items() if number > 1]
    good_rows = [row for row in rows if row and len(row) >= 4]
    return {
        "sample": where,
        "kind": where.rsplit("-", 1)[-1],
        "passes": len(passes),
        "pass1_ms": sum(passes[1].values()) if 1 in passes else None,
        "p50_ms": pct(steady, 0.5) if steady else None,
        "p95_ms": pct(steady, 0.95) if steady else None,
        "stages": sorted({op for ops in passes.values() for op in ops}),
        "stage_p95_ms": {
            op: pct([ops.get(op, 0.0) for number, ops in passes.items() if number > 1], 0.95)
            for op in {op for ops in passes.values() for op in ops}
        } if steady else {},
        "rss_max_kb": max((row[1] for row in good_rows), default=None),
        "hwm_max_kb": max((row[2] for row in good_rows), default=None),
        "fds_max": max((row[3] for row in good_rows), default=None),
        "counters": counters,
    }


def check_run(run, limits):
    """(meta, samples, reasons) for one run directory."""
    reasons = []
    meta_path = run / "run.json"
    try:
        meta = json.loads(meta_path.read_text())
    except (OSError, ValueError):
        return {}, [], [f"{run.name}: no readable run.json"]
    lock = read_kv(run / "lock.txt")
    if lock is None:
        reasons.append(f"{run.name}: no lock record")
    elif lock.get("verified_in_proc_locks") != "1" or not lock.get("lock"):
        reasons.append(f"{run.name}: lock record does not prove the lock was held")
    check_load(run / "load.txt", limits, run.name, reasons)
    churn = int(meta.get("churn_rate", 0) or 0)
    if churn and meta.get("churn_scope") == "run":
        check_churn(parse_churn(run / "churn.ledger"), churn, run.name, limits, reasons)
    sample_dirs = sorted(
        (path for path in run.glob("sample-*") if path.is_dir()),
        key=lambda path: int(path.name.split("-")[1]),
    )
    if not sample_dirs:
        reasons.append(f"{run.name}: no samples")
    samples = [check_sample(sample, meta, limits, reasons) for sample in sample_dirs]
    if meta.get("status", "complete") != "complete":
        reasons.append(f"{run.name}: run status {meta.get('status')}: {meta.get('reason', '')}")
    return meta, samples, reasons


def cell_key(meta, kind):
    return (
        meta.get("capture"),
        meta.get("processes"),
        meta.get("callers"),
        meta.get("churn_rate"),
        kind,
    )


def spread(values):
    values = [value for value in values if value is not None]
    if not values:
        return "n/a"
    return f"{statistics.median(values):.3f} [{min(values):.3f}..{max(values):.3f}] n={len(values)}"


def summary(runs, limits, out):
    cells, invalid = {}, []
    for run in runs:
        meta, samples, reasons = check_run(run, limits)
        if reasons:
            invalid.append((run, reasons))
            continue
        for sample in samples:
            cells.setdefault(cell_key(meta, sample["kind"]), []).append(sample)
    for key in sorted(cells, key=str):
        capture, processes, callers, churn, kind = key
        group = cells[key]
        print(
            f"cell capture={capture} processes={processes} callers={callers} "
            f"churn={churn}/s kind={kind}",
            file=out,
        )
        print(f"  pass p50 ms: {spread([s['p50_ms'] for s in group])}", file=out)
        print(f"  pass p95 ms: {spread([s['p95_ms'] for s in group])}", file=out)
        print(f"  pass1 ms:    {spread([s['pass1_ms'] for s in group])}", file=out)
        stages = sorted({op for sample in group for op in sample["stage_p95_ms"]})
        for op in stages:
            print(f"  {op:>12} p95 ms: {spread([s['stage_p95_ms'].get(op) for s in group])}", file=out)
        print(f"  rss max kb:  {spread([s['rss_max_kb'] for s in group])}", file=out)
        print(f"  fds max:     {spread([s['fds_max'] for s in group])}", file=out)
        for counter, _ in COUNTER_PATHS:
            values = [sample["counters"].get(counter) for sample in group]
            present = [value for value in values if value is not None]
            missing = len(values) - len(present)
            if not present:
                plural = "s" if len(values) != 1 else ""
                print(
                    f"  {counter}: missing in all {len(values)} sample{plural} (zero or unreported)",
                    file=out,
                )
            elif missing:
                print(
                    f"  {counter}: {spread(present)} "
                    f"(missing in {missing}/{len(values)}: zero or unreported)",
                    file=out,
                )
            else:
                print(f"  {counter}: {spread(values)}", file=out)
    for run, reasons in invalid:
        print(f"INVALID {run}:", file=out)
        for reason in reasons:
            print(f"  - {reason}", file=out)
    return 0 if not invalid else 1


def check(runs, limits, out):
    status = 0
    for run in runs:
        meta, samples, reasons = check_run(run, limits)
        for sample in samples:
            print(
                f"{run.name}/{sample['sample']}: passes={sample['passes']} "
                f"p50={sample['p50_ms']} p95={sample['p95_ms']} ms "
                f"rss_max={sample['rss_max_kb']} kB fds_max={sample['fds_max']}",
                file=out,
            )
        if reasons:
            status = 1
            print(f"INVALID {run}:", file=out)
            for reason in reasons:
                print(f"  - {reason}", file=out)
        else:
            print(f"VALID {run}", file=out)
    return status


# ---- self-test ----

def write_run(root, name, *, capture="native", churn=0, passes=4, spans=None):
    """A synthetic valid run; the self-test then breaks one thing at a time."""
    run = root / name
    run.mkdir()
    (run / "run.json").write_text(json.dumps({
        "capture": capture, "processes": 448, "callers": 300,
        "churn_rate": churn, "churn_scope": "sample", "status": "complete",
    }))
    (run / "lock.txt").write_text(
        "lock=/var/tmp/p11scope-ws-tmp/privileged.lock\nholder_pid=1\nverified_in_proc_locks=1\n"
    )
    load = "load1_start=0.50\nload1_end=0.70\nbuild_processes_start=0\nbuild_processes_end=0\n"
    (run / "load.txt").write_text(load)
    spans = DEFAULTS["native_spans"] if spans is None else spans
    for number, kind in ((1, "cold"), (2, "warm")):
        sample = run / f"sample-{number}-{kind}"
        sample.mkdir()
        (sample / "load.txt").write_text(load)
        (sample / "rc").write_text("0\n")
        lines = []
        for index in range(1, passes + 1):
            ops = ", ".join([f"sweep {10 + index}.000ms"] + [f"{span} 1.500ms" for span in spans])
            lines.append(f"p11scope: pass {index}: stage timings: {ops}")
        (sample / "stderr").write_text("\n".join(lines) + "\n")
        (sample / "resources.tsv").write_text(
            "# ms rss_kb hwm_kb fds\n0 1000 1000 12\n1000 1200 1200 14\n2000 1100 1200 14\n"
        )
        if churn:
            (sample / "churn.ledger").write_text(
                f"EXEC pid=9 kind=unrelated fork_ns=1\nSUMMARY target_rate={churn} seconds=10.0 "
                f"share_pct=10 execs={churn * 10} provider={churn} unrelated={churn * 9} "
                f"exec_fail=0 nonzero=0 signaled=0 unreaped=0 late_ticks=0 late_max_us=0 "
                f"dropped_ticks=0 achieved_rate={float(churn)}\n"
            )
        # The C5.1 document shape: the census always renders (zeros in the
        # scan lane, whose unbound_reasons omits zero counts); lane,
        # settlement and retirement only in the native lane.
        if capture == "native":
            census = {
                "rows": 4, "bound": 3, "unbound": 1, "pending": 0, "integrity": 0,
                "unbound_reasons": {"lifecycle_loss": 1},
            }
            observation = {"lane": "native", "settlement": "unsettled",
                           "retirement": "closed", "native_witnesses": census}
        else:
            census = {
                "rows": 0, "bound": 0, "unbound": 0, "pending": 0, "integrity": 0,
                "unbound_reasons": {},
            }
            observation = {"native_witnesses": census}
        (sample / "inventory.json").write_text(json.dumps({"observation": observation}))
    return run


def self_test():
    limits = dict(DEFAULTS)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def expect(run, fragment):
            _, _, reasons = check_run(run, limits)
            if fragment is None:
                assert not reasons, f"{run.name}: valid run refused: {reasons}"
            else:
                assert any(fragment in reason for reason in reasons), (
                    f"{run.name}: expected a reason containing {fragment!r}, got {reasons}"
                )
            print(f"  {run.name}: {'accepted' if fragment is None else 'rejected: ' + fragment}")

        expect(write_run(root, "valid-native"), None)
        expect(write_run(root, "valid-scan", capture="scan", spans=()), None)
        expect(write_run(root, "valid-churn", churn=100), None)

        run = write_run(root, "no-lock")
        (run / "lock.txt").unlink()
        expect(run, "no lock record")
        run = write_run(root, "unverified-lock")
        (run / "lock.txt").write_text("lock=/x\nverified_in_proc_locks=0\n")
        expect(run, "does not prove the lock")
        run = write_run(root, "no-load")
        (run / "load.txt").unlink()
        expect(run, "no load record")
        run = write_run(root, "no-sample-load")
        (run / "sample-2-warm" / "load.txt").unlink()
        expect(run, "sample-2-warm: no load record")
        run = write_run(root, "hot-host")
        (run / "load.txt").write_text(
            "load1_start=7.25\nload1_end=7.0\nbuild_processes_start=0\nbuild_processes_end=0\n"
        )
        expect(run, "above 4.0 at start")
        run = write_run(root, "building")
        (run / "load.txt").write_text(
            "load1_start=0.5\nload1_end=0.5\nbuild_processes_start=3\nbuild_processes_end=0\n"
        )
        expect(run, "cargo/rustc processes running")
        run = write_run(root, "no-passes")
        (run / "sample-1-cold" / "stderr").write_text("p11scope: something else\n")
        expect(run, "0 stage-timed passes")
        run = write_run(root, "missing-stderr")
        (run / "sample-1-cold" / "stderr").unlink()
        expect(run, "0 stage-timed passes")
        run = write_run(root, "too-few-passes", passes=2)
        expect(run, "2 stage-timed passes, need 3")
        run = write_run(root, "zero-pass")
        stderr = run / "sample-2-warm" / "stderr"
        stderr.write_text(
            stderr.read_text() + "p11scope: pass 5: stage timings: sweep 0.000ms, read 0.000ms\n"
        )
        expect(run, "pass 5 has a zero stage sample")
        run = write_run(
            root, "native-span-missing",
            spans=tuple(span for span in DEFAULTS["native_spans"] if span != "project"),
        )
        expect(run, "native span project absent from stage timings")
        run = write_run(root, "native-span-zero")
        stderr = run / "sample-1-cold" / "stderr"
        stderr.write_text(stderr.read_text().replace("confirm 1.500ms", "confirm 0.000ms"))
        stderr = run / "sample-2-warm" / "stderr"
        stderr.write_text(stderr.read_text().replace("confirm 1.500ms", "confirm 0.000ms"))
        expect(run, "native span confirm never sampled")
        run = write_run(root, "native-no-lane")
        for sample in run.glob("sample-*"):
            document = json.loads((sample / "inventory.json").read_text())
            del document["observation"]["lane"]
            (sample / "inventory.json").write_text(json.dumps(document))
        expect(run, "states no observation lane")
        run = write_run(root, "native-no-document")
        for sample in run.glob("sample-*"):
            (sample / "inventory.json").unlink()
        expect(run, "wrote no inventory.json")
        run = write_run(root, "native-wrong-lane")
        for sample in run.glob("sample-*"):
            document = json.loads((sample / "inventory.json").read_text())
            document["observation"]["lane"] = "scan"
            (sample / "inventory.json").write_text(json.dumps(document))
        expect(run, "observation lane is 'scan'")
        run = write_run(root, "no-resources")
        (run / "sample-1-cold" / "resources.tsv").unlink()
        expect(run, "0 resource samples")
        run = write_run(root, "zero-rss")
        (run / "sample-1-cold" / "resources.tsv").write_text("0 1000 1000 12\n1 0 1000 12\n2 900 1000 12\n")
        expect(run, "missing or zero resource sample")
        run = write_run(root, "zero-fds")
        (run / "sample-2-warm" / "resources.tsv").write_text("0 1000 1000 12\n1 900 1000 0\n2 900 1000 12\n")
        expect(run, "missing or zero resource sample")
        run = write_run(root, "observer-failed")
        (run / "sample-1-cold" / "rc").write_text("1\n")
        expect(run, "observer exit status 1")
        run = write_run(root, "churn-ledger-missing", churn=100)
        (run / "sample-1-cold" / "churn.ledger").unlink()
        expect(run, "no churn ledger SUMMARY")
        run = write_run(root, "churn-zero", churn=100)
        ledger = run / "sample-1-cold" / "churn.ledger"
        ledger.write_text(ledger.read_text().replace("execs=1000", "execs=0"))
        expect(run, "zero execs")
        run = write_run(root, "churn-slow", churn=100)
        ledger = run / "sample-2-warm" / "churn.ledger"
        ledger.write_text(ledger.read_text().replace("achieved_rate=100.0", "achieved_rate=80.0"))
        expect(run, "below 90% of 100/s")
        run = write_run(root, "churn-exec-fail", churn=100)
        ledger = run / "sample-2-warm" / "churn.ledger"
        ledger.write_text(ledger.read_text().replace("exec_fail=0", "exec_fail=4"))
        expect(run, "4 churn execs failed")
        run = write_run(root, "no-samples")
        for sample in run.glob("sample-*"):
            for path in sample.iterdir():
                path.unlink()
            sample.rmdir()
        expect(run, "no samples")
        run = write_run(root, "refused-run")
        meta = json.loads((run / "run.json").read_text())
        meta.update(status="invalid", reason="load1 6.1 above 4 after cooldown")
        (run / "run.json").write_text(json.dumps(meta))
        expect(run, "run status invalid")
        run = root / "no-meta"
        run.mkdir()
        expect(run, "no readable run.json")

        class Sink:
            def __init__(self):
                self.text = ""

            def write(self, text):
                self.text += text

        run = write_run(root, "no-census")
        for sample in run.glob("sample-*"):
            document = json.loads((sample / "inventory.json").read_text())
            del document["observation"]["native_witnesses"]
            (sample / "inventory.json").write_text(json.dumps(document))
        expect(run, None)
        sink = Sink()
        assert summary([root / "valid-native", root / "no-lock"], limits, sink) == 1
        assert "cell capture=native processes=448" in sink.text, sink.text
        assert "INVALID" in sink.text and "no lock record" in sink.text, sink.text
        assert "native_rows: 4.000" in sink.text, sink.text
        sink = Sink()
        assert summary([root / "no-census"], limits, sink) == 0, sink.text
        assert "native_rows: missing in all 1 sample " in sink.text, sink.text
        assert "lifecycle_loss: missing in all 1 sample " in sink.text, sink.text
        sink = Sink()
        assert summary([root / "valid-scan"], limits, sink) == 0, sink.text
        # A present census without the entry means zero loss, not missing.
        assert "lifecycle_loss: 0.000" in sink.text, sink.text
        sink = Sink()
        assert check([root / "valid-native", root / "valid-churn"], limits, sink) == 0, sink.text
    print("bench-inventory-native-stats: self-test ok")


def main(argv):
    limits = dict(DEFAULTS)
    args = list(argv)
    while args and args[0].startswith("--"):
        option = args.pop(0)
        if option == "--self-test":
            self_test()
            return 0
        if not args:
            print(f"{option} needs a value", file=sys.stderr)
            return 64
        value = args.pop(0)
        if option == "--max-load1":
            limits["max_load1"] = float(value)
        elif option == "--min-passes":
            limits["min_passes"] = int(value)
        elif option == "--native-spans":
            limits["native_spans"] = tuple(span for span in value.split(",") if span)
        else:
            print(f"unknown option {option}", file=sys.stderr)
            return 64
    if len(args) < 2 or args[0] not in ("check", "summary"):
        print(__doc__.split("Usage:")[1].split("Options")[0], file=sys.stderr)
        return 64
    runs = [Path(arg) for arg in args[1:]]
    return (check if args[0] == "check" else summary)(runs, limits, sys.stdout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
