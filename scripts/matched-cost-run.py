#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Matched v0.5.0-vs-v0.6.0 cost run: same inputs, interleaved trials.

Runs a fixed workload matrix against two observer binaries (an old
release binary and a new candidate) with identical CLI, identical
targets, ABBA/BAAB-interleaved trials and a quiet-host gate, then
prints a comparison table (startup, first-pass p50/p95, steady pass,
peak RSS). Only flags accepted by both CLI revisions are used; the
three v0.6-only flags (--prearm-module, --select-endpoint,
--track-short-lived) never appear.

Matrix (each cell: --duration D, P11SCOPE_STAGE_TIMINGS=1):

- counts-system:  inventory --system --capture native [--max-scan-pids K]
- detailed-pid:   profile --pid <fresh sleep target> (idle target:
  BPF load plus attach attempt, no provider calls)
- inventory-system: inventory --system --capture scan
  --identity-backend userspace [--max-scan-pids K] (H4a parity)

Metrics per sample: startup_ns (spawn to the cell's readiness line),
firstpass_ns (first qualifying pass total; pass cells only),
steady_ns (median of later passes' totals; pass cells only), wall_ns,
peak_rss_kb (via /usr/bin/time -v). Readiness lines:
profile `p11scope: capturing: N probe(s) attached`, inventory native
`p11scope: native usage lane active`, inventory scan first
`p11scope: pass N: stage timings:` line.

The campaign refuses mismatched inputs: missing/non-executable
binaries, old and new resolving to the same file or the same bytes, a
bad duration, an unwritable workdir, a missing /usr/bin/time, no root,
or a host that never settles below the load gates.

Usage:
  python3 -I scripts/matched-cost-run.py --old OLD --new NEW --out DIR
      [--rounds N] [--duration 20s] [--max-scan-pids K]
      [--cells counts-system,detailed-pid,inventory-system]
      [--max-load1 4] [--max-load5 4] [--settle-secs 120] [--json]
"""

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True

CELLS = ("counts-system", "detailed-pid", "inventory-system")

TIMING_LINE = re.compile(r"p11scope: pass (\d+): stage timings: (.+)")
OP_VALUE = re.compile(r"(\S+)\s+([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s)")
UNIT_NS = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}
CAPTURING_LINE = re.compile(r"p11scope: capturing: (\d+) probes? attached")
CAPTURING_WAITING = re.compile(r"p11scope: capturing: waiting for .*; stop with Ctrl-C")
LANE_ACTIVE_LINE = re.compile(r"p11scope: native usage lane active")
RSS_LINE = re.compile(r"Maximum resident set size \(kbytes\): (\d+)")
DURATION_RE = re.compile(r"(\d+)s$")

TIME_BIN = "/usr/bin/time"
MIN_DURATION_S = 5
MAX_DURATION_S = 300


class MatchedCostError(Exception):
    """A refusal: mismatched inputs, unsettled host, or a failed sample."""


def percentile(values, pct):
    """Percentile: ascending, index ceil(p*n)-1 (0-based), H4a rule."""
    ordered = sorted(values)
    if not ordered:
        raise MatchedCostError("percentile of no samples")
    return ordered[math.ceil(pct * len(ordered)) - 1]


def p50(values):
    return percentile(values, 0.50)


def p95(values):
    return percentile(values, 0.95)


def parse_stage_timings(stderr_text):
    """Every per-pass op map: [(pass, {op: ns})]."""
    passes = []
    for line in stderr_text.splitlines():
        match = TIMING_LINE.search(line)
        if not match:
            continue
        ops = {}
        for name, number, unit in OP_VALUE.findall(match.group(2)):
            ops[name] = float(number) * UNIT_NS[unit]
        passes.append((int(match.group(1)), ops))
    return passes


def first_qualifying_pass(passes):
    """First pass with sweep + select present and nonzero confirm."""
    for number, ops in passes:
        if "sweep" in ops and "select" in ops and ops.get("confirm", 0.0) > 0.0:
            return number, ops
    raise MatchedCostError("no pass with sweep + select and nonzero confirm")


def steady_pass_total(passes):
    """Median total over passes after the first qualifying one."""
    _, first = first_qualifying_pass(passes)
    later = [sum(ops.values()) for _, ops in passes[passes.index(
        next(item for item in passes if item[1] is first)) + 1:]]
    if not later:
        raise MatchedCostError("no steady pass after the first qualifying pass")
    return p50(later)


def parse_time_rss(time_text):
    """Peak RSS kilobytes from /usr/bin/time -v output."""
    match = RSS_LINE.search(time_text)
    if not match:
        raise MatchedCostError("/usr/bin/time output lacks Maximum resident set size")
    return int(match.group(1))


def parse_readiness(stderr_lines, cell):
    """(readiness line index, attached probes or None) for one cell."""
    for index, line in enumerate(stderr_lines):
        if cell == "detailed-pid":
            match = CAPTURING_LINE.search(line)
            if match:
                return index, int(match.group(1))
            if CAPTURING_WAITING.search(line):
                return index, 0
        elif cell == "counts-system":
            if LANE_ACTIVE_LINE.search(line):
                return index, None
        elif cell == "inventory-system":
            if TIMING_LINE.search(line):
                return index, None
    raise MatchedCostError(f"{cell}: no readiness line on stderr")


def round_order(round_number):
    """ABBA on odd rounds (new first), BAAB on even rounds."""
    if round_number % 2 == 1:
        return ("new", "old", "old", "new")
    return ("old", "new", "new", "old")


def paired_deltas(old_values, new_values):
    """Per-round i-th new minus i-th old in log order (ABBA pairs)."""
    if len(old_values) != len(new_values):
        raise MatchedCostError(
            f"cannot pair {len(old_values)} old with {len(new_values)} new samples"
        )
    return [new - old for old, new in zip(old_values, new_values)]


TAG_RE = re.compile(r"^(old|new)-(.+)-r(\d+)-(\d+)$")


def pair_key(tag):
    """(round, pair) interleaving key, or None for unkeyed tags.

    Campaign tags are {arm}-{cell}-r{round:02d}-{position}; two
    adjacent positions form one ABBA/BAAB half-round (position //
    2), so each key holds the temporally adjacent old/new samples.
    """
    match = TAG_RE.match(tag)
    if not match:
        return None
    return (int(match.group(3)), int(match.group(4)) // 2)


def binary_provenance(old, new, duration, max_scan_pids):
    """Campaign identity for comparison.json: who was compared, where."""
    try:
        old_digest = sha256_file(old)
        new_digest = sha256_file(new)
    except OSError as exc:
        raise MatchedCostError(f"cannot hash compared binaries ({exc})") from exc
    return {
        "old_path": old,
        "new_path": new,
        "old_sha256": old_digest,
        "new_sha256": new_digest,
        "kernel": os.uname().release,
        "duration": duration,
        "max_scan_pids": max_scan_pids,
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_args(args, euid=None):
    """Refuse mismatched inputs before any sample runs.

    `euid` overrides os.geteuid() for unit tests only; production
    callers always pass the real identity.
    """
    if (os.geteuid() if euid is None else euid) != 0:
        raise MatchedCostError("matched cost run needs root (BPF cells)")
    for label, path in (("old", args.old), ("new", args.new)):
        if not os.path.isfile(path):
            raise MatchedCostError(f"--{label}: not a file: {path}")
        if not os.access(path, os.X_OK):
            raise MatchedCostError(f"--{label}: not executable: {path}")
    if os.path.samefile(args.old, args.new):
        raise MatchedCostError("--old and --new resolve to the same file")
    if sha256_file(args.old) == sha256_file(args.new):
        raise MatchedCostError("--old and --new have identical bytes: not a comparison")
    match = DURATION_RE.match(args.duration)
    if not match:
        raise MatchedCostError(f"--duration: expected Ns, got {args.duration!r}")
    seconds = int(match.group(1))
    if not MIN_DURATION_S <= seconds <= MAX_DURATION_S:
        raise MatchedCostError(
            f"--duration: {seconds}s outside {MIN_DURATION_S}s..{MAX_DURATION_S}s"
        )
    if args.rounds < 1:
        raise MatchedCostError(f"--rounds: need >= 1, got {args.rounds}")
    if args.max_scan_pids < 1:
        raise MatchedCostError(f"--max-scan-pids: need >= 1, got {args.max_scan_pids}")
    unknown = [cell for cell in args.cells.split(",") if cell not in CELLS]
    if unknown:
        raise MatchedCostError(f"--cells: unknown cell(s): {', '.join(unknown)}")
    if not os.path.isfile(TIME_BIN) or not os.access(TIME_BIN, os.X_OK):
        raise MatchedCostError(f"{TIME_BIN} missing: peak RSS needs GNU time")
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MatchedCostError(f"--out: cannot create {out} ({exc})") from exc
    probe = out / ".writable"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise MatchedCostError(f"--out: {out} not writable ({exc})") from exc
    return seconds


def host_load():
    with open("/proc/loadavg", encoding="utf-8") as handle:
        parts = handle.read().split()
    return float(parts[0]), float(parts[1])


def builders_running():
    """True when a cargo/rustc process exists (by /proc scan, no pgrep)."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm in ("cargo", "rustc"):
            return True
    return False


def wait_for_quiet(max_load1, max_load5, settle_secs, label, allow_builders=False):
    """Wait until the host is quiet; refuse when it never settles.

    `allow_builders` is a mechanics-dry-run escape only: qualifying
    runs always wait out cargo/rustc. The flag is recorded per sample.
    """
    deadline = time.monotonic() + settle_secs
    while True:
        load1, load5 = host_load()
        busy_builders = builders_running()
        if load1 < max_load1 and load5 < max_load5 and (allow_builders or not busy_builders):
            return load1, load5
        if time.monotonic() >= deadline:
            raise MatchedCostError(
                f"{label}: host never settled below load {max_load1}/{max_load5} "
                f"(last {load1:.2f}/{load5:.2f}, builders={busy_builders})"
            )
        time.sleep(5)


def run_sample(binary, cell, prefix, duration, max_scan_pids, sleep_target):
    """One sample; returns its metrics dict. Refuses on any failure."""
    if cell == "counts-system":
        cmd = [
            binary, "inventory", "--system", "--capture", "native",
            "--max-scan-pids", str(max_scan_pids), "--duration", duration,
            "--json", "-o", str(prefix) + ".json",
        ]
    elif cell == "detailed-pid":
        cmd = [
            binary, "profile", "--pid", str(sleep_target),
            "--duration", duration, "-o", str(prefix) + ".json",
        ]
    elif cell == "inventory-system":
        cmd = [
            binary, "inventory", "--system", "--capture", "scan",
            "--identity-backend", "userspace",
            "--max-scan-pids", str(max_scan_pids), "--duration", duration,
            "--json", "-o", str(prefix) + ".json",
            "--event-log", str(prefix) + ".jsonl",
        ]
    else:  # pragma: no cover - argparse plus validate_args bound this
        raise MatchedCostError(f"unknown cell: {cell}")
    env = os.environ.copy()
    env["P11SCOPE_STAGE_TIMINGS"] = "1"
    time_path = str(prefix) + ".time"
    full_cmd = [TIME_BIN, "-v", "-o", time_path, *cmd]
    stderr_lines = []
    stderr_ns = []
    start = time.monotonic_ns()

    def drain_stdout(proc, path):
        with open(path, "wb") as handle:
            for chunk in iter(lambda: proc.stdout.read(65536), b""):
                handle.write(chunk)

    proc = subprocess.Popen(
        full_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=False, bufsize=0,
    )
    stdout_path = str(prefix) + ".stdout"
    drainer = threading.Thread(target=drain_stdout, args=(proc, stdout_path))
    drainer.start()
    stderr_file = str(prefix) + ".stderr"
    with open(stderr_file, "wb") as handle:
        for raw in iter(proc.stderr.readline, b""):
            now = time.monotonic_ns()
            handle.write(raw)
            handle.flush()
            stderr_lines.append(raw.decode("utf-8", "replace"))
            stderr_ns.append(now)
    proc.stderr.close()
    code = proc.wait()
    drainer.join()
    wall_ns = time.monotonic_ns() - start
    if code != 0:
        tail = "".join(stderr_lines[-10:])
        raise MatchedCostError(f"{prefix.name}: exit {code}: {tail[-500:]}")
    ready_index, probes = parse_readiness(stderr_lines, cell)
    startup_ns = stderr_ns[ready_index] - start
    sample = {
        "cell": cell,
        "tag": prefix.name,
        "startup_ns": float(startup_ns),
        "wall_ns": float(wall_ns),
        "attached_probes": probes,
    }
    if cell in ("counts-system", "inventory-system"):
        passes = parse_stage_timings("".join(stderr_lines))
        _, first_ops = first_qualifying_pass(passes)
        sample["firstpass_ns"] = sum(first_ops.values())
        try:
            sample["steady_ns"] = steady_pass_total(passes)
        except MatchedCostError:
            sample["steady_ns"] = None
    with open(time_path, encoding="utf-8") as handle:
        sample["peak_rss_kb"] = float(parse_time_rss(handle.read()))
    final_json = Path(str(prefix) + ".json")
    if final_json.is_file():
        try:
            final = json.loads(final_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            final = None
        if isinstance(final, dict):
            totals = final.get("totals", final)
            if isinstance(totals, dict):
                for key in ("callers", "modules", "edges"):
                    if key in totals:
                        sample[f"final_{key}"] = totals[key]
    return sample


METRICS = ("startup_ns", "firstpass_ns", "steady_ns", "wall_ns", "peak_rss_kb")


def summarize(samples):
    """Per cell per metric: old/new p50/p95 plus paired-median delta.

    Pairing is by (round, pair) tag key, so a lost metric in one arm
    drops that pair instead of aborting the campaign; a metric with
    no shared pair — or with unkeyed tags whose arm lengths differ —
    is skipped, never raised.
    """
    table = {}
    cells = sorted({sample["cell"] for sample in samples})
    for cell in cells:
        table[cell] = {}
        old = [s for s in samples if s["cell"] == cell and s["tag"].startswith("old-")]
        new = [s for s in samples if s["cell"] == cell and s["tag"].startswith("new-")]
        for metric in METRICS:
            old_values = [s[metric] for s in old if s.get(metric) is not None]
            new_values = [s[metric] for s in new if s.get(metric) is not None]
            if not old_values or not new_values:
                continue
            old_keys = [pair_key(s["tag"]) for s in old if s.get(metric) is not None]
            new_keys = [pair_key(s["tag"]) for s in new if s.get(metric) is not None]
            if all(key is not None for key in old_keys + new_keys):
                by_old = {}
                for key, value in zip(old_keys, old_values):
                    by_old.setdefault(key, value)
                by_new = {}
                for key, value in zip(new_keys, new_values):
                    by_new.setdefault(key, value)
                shared = sorted(set(by_old) & set(by_new))
                if not shared:
                    continue
                deltas = [by_new[key] - by_old[key] for key in shared]
            elif len(old_values) != len(new_values):
                continue
            else:
                deltas = paired_deltas(old_values, new_values)
            median_delta = p50(deltas)
            base = p50(old_values)
            table[cell][metric] = {
                "old_p50": p50(old_values),
                "new_p50": p50(new_values),
                "old_p95": p95(old_values),
                "new_p95": p95(new_values),
                "paired_median_delta": median_delta,
                "paired_median_delta_pct": (
                    100.0 * median_delta / base if base else None
                ),
                "old_n": len(old_values),
                "new_n": len(new_values),
                "paired_n": len(deltas),
            }
    return table


def format_ns(value):
    if value >= 1e9:
        return f"{value / 1e9:.3f}s"
    if value >= 1e6:
        return f"{value / 1e6:.1f}ms"
    return f"{value / 1e3:.0f}us"


def render_table(table, meta=None):
    lines = []
    if meta is not None:
        lines.append(f"old: {meta['old_path']} sha256:{meta['old_sha256'][:12]}")
        lines.append(f"new: {meta['new_path']} sha256:{meta['new_sha256'][:12]}")
        lines.append(
            f"kernel {meta['kernel']} duration {meta['duration']} "
            f"K {meta['max_scan_pids']}"
        )
    header = (
        f"{'cell':<16} {'metric':<12} {'old p50':>10} {'new p50':>10} "
        f"{'d%':>7} {'old p95':>10} {'new p95':>10} {'n':>5}"
    )
    lines.append(header)
    for cell in sorted(table):
        for metric in METRICS:
            row = table[cell].get(metric)
            if row is None:
                continue
            if metric == "peak_rss_kb":
                old_p50 = f"{row['old_p50'] / 1024:.0f}MiB"
                new_p50 = f"{row['new_p50'] / 1024:.0f}MiB"
                old_p95 = f"{row['old_p95'] / 1024:.0f}MiB"
                new_p95 = f"{row['new_p95'] / 1024:.0f}MiB"
            else:
                old_p50 = format_ns(row["old_p50"])
                new_p50 = format_ns(row["new_p50"])
                old_p95 = format_ns(row["old_p95"])
                new_p95 = format_ns(row["new_p95"])
            pct = row["paired_median_delta_pct"]
            pct_text = f"{pct:+.1f}" if pct is not None else "n/a"
            lines.append(
                f"{cell:<16} {metric:<12} {old_p50:>10} {new_p50:>10} "
                f"{pct_text:>7} {old_p95:>10} {new_p95:>10} "
                f"{row['old_n']}/{row['new_n']:>5}"
            )
    return "\n".join(lines)


def run_campaign(args):
    seconds = validate_args(args)
    cells = args.cells.split(",")
    out = Path(args.out)
    samples = []
    for cell in cells:
        for round_number in range(1, args.rounds + 1):
            for position, arm in enumerate(round_order(round_number)):
                binary = args.old if arm == "old" else args.new
                tag = f"{arm}-{cell}-r{round_number:02d}-{position}"
                prefix = out / tag
                load1, load5 = wait_for_quiet(
                    args.max_load1, args.max_load5, args.settle_secs, tag,
                    args.allow_builders,
                )
                target = None
                try:
                    if cell == "detailed-pid":
                        target = subprocess.Popen(["sleep", str(seconds + 60)])
                    sample = run_sample(
                        binary, cell, prefix, args.duration,
                        args.max_scan_pids,
                        target.pid if target is not None else 0,
                    )
                finally:
                    if target is not None:
                        target.terminate()
                        try:
                            target.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            target.kill()
                sample["load1"] = load1
                sample["load5"] = load5
                sample["round"] = round_number
                sample["allow_builders"] = args.allow_builders
                samples.append(sample)
                with open(out / "samples.jsonl", "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(sample) + "\n")
                print(f"{tag}: startup={format_ns(sample['startup_ns'])} "
                      f"wall={format_ns(sample['wall_ns'])} "
                      f"rss={sample['peak_rss_kb'] / 1024:.0f}MiB", flush=True)
    return samples


def main(argv):
    parser = argparse.ArgumentParser(
        description="Matched old-vs-new cost run with identical inputs."
    )
    parser.add_argument("--old", required=True, help="old release binary path")
    parser.add_argument("--new", required=True, help="new candidate binary path")
    parser.add_argument("--out", required=True, help="artifact workdir")
    parser.add_argument("--rounds", type=int, default=3,
                        help="ABBA/BAAB rounds per cell (default 3)")
    parser.add_argument("--duration", default="20s",
                        help="per-sample capture duration Ns (default 20s)")
    parser.add_argument("--max-scan-pids", type=int, default=8,
                        help="system scan cap K (default 8)")
    parser.add_argument("--cells", default=",".join(CELLS),
                        help="comma-separated subset of " + ",".join(CELLS))
    parser.add_argument("--max-load1", type=float, default=4.0)
    parser.add_argument("--max-load5", type=float, default=4.0)
    parser.add_argument("--settle-secs", type=int, default=120,
                        help="per-sample quiet-host wait bound (default 120)")
    parser.add_argument("--allow-builders", action="store_true",
                        help="mechanics dry runs only: sample despite cargo/rustc "
                        "(recorded per sample; never for qualifying runs)")
    parser.add_argument("--json", action="store_true",
                        help="print the comparison as JSON instead of a table")
    args = parser.parse_args(argv)
    try:
        samples = run_campaign(args)
        table = summarize(samples)
        meta = binary_provenance(args.old, args.new, args.duration, args.max_scan_pids)
    except MatchedCostError as exc:
        print(f"matched-cost-run: refused: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out)
    with open(out / "comparison.json", "w", encoding="utf-8") as handle:
        json.dump({"meta": meta, "samples": samples, "table": table}, handle, indent=2)
    if args.json:
        print(json.dumps(table, indent=2))
    else:
        print(render_table(table, meta))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
