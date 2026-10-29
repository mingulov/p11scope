#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""H4a matched pre/post userspace identity regression gate (RUN suite).

RUN registration runs ``--self-test`` in CI; the live gate runs via the
manual qualified runner, not DRIVEN.

Compares per-pass userspace confirmation cost of two prebuilt release
binaries on a frozen holder population past the scan cap: the R-14 pre
revision against the v0.5.0 candidate. The new confirmation work may cost
at most 5% versus the revision before it.

Workload (both arms, as root, population on Btrfs)::
    inventory --system --capture scan --max-scan-pids K --duration D \\
        --json -o OUT.json --event-log OUT.jsonl \\
        --event-rotate-bytes 1024M --event-max-files 2
Post adds ``--identity-backend userspace``; pre never takes that flag.
M holder processes (M >> K) each map the same 8 held providers
(``prov-0..7.so`` built once with ``-DINVENTORY_LEDGER_HELD_PROVIDER``
from one pinned source). One run yields one sample: its first pass with
``sweep`` + ``select`` present and nonzero ``confirm``.

Env inputs (missing input fails closed, never passes)::
    P11SCOPE_H4A_PRE_BIN    pre-arm p11scope binary (release; no
                            --identity-backend flag)
    P11SCOPE_H4A_POST_BIN   post-arm p11scope binary (release; supports
                            --identity-backend userspace)
    P11SCOPE_H4A_POP        population dir holding prov-0..7.so (Btrfs)
    P11SCOPE_H4A_K          --max-scan-pids cap (M >> K)
    P11SCOPE_H4A_M          holder process count
    P11SCOPE_H4A_DURATION   --duration per run (default "30s")
    P11SCOPE_H4A_ROUNDS     ABBA/BAAB rounds (default 10; qualifying: >= 10
                            rounds, >= 20 samples/arm, quiet host, root,
                            /var/tmp/p11scope-ws-tmp/privileged.lock held,
                            no Cargo builds while measuring)
    P11SCOPE_H4A_WORKDIR    per-run outputs (default: mkdtemp under TMPDIR)

Gates (all required for PASS): confirm-p95 regression <= 5% AND
pass-total p95 regression <= 5% (p95 = ascending, index ceil(0.95*n)-1)
AND equal coverage (every run's holder-PID caller set equals the frozen
M set, and every sampled pass agrees with the first pre run on
totals.modules/edges, so ambient provider mappings are tolerated when
stable but arm divergence fails) AND the V5-34 guards (paired median
delta <= 5%, bootstrap 95% CI upper <= 10%, 0 count errors) AND the
wall-clock guard (median post wall <= 110% of median pre wall) AND the
qualifying floor (distinct rounds >= 10, n >= 20/arm) AND matched
sampled pass indices across arms.
The spawn check (every holder maps all 8 providers) anchors the
population; the cross-run totals check needs no absolute edge count.
Verdict line::

    H4A <PASS|FAIL> confirm_pre=<ns> confirm_post=<ns> reg_pct=<f>
        total_reg_pct=<f> coverage=<ok|MISMATCH> median_pct=<f>
        ci95_upper_pct=<f> wall_guard=<ok|FAIL>

Qualified 6.16 shape: M=400 holders, K=40 cap, D=30s per run,
ROUNDS=10 (ABBA/BAAB, 20 samples/arm), POP rebuilt from the current
ledger. The K=8/M=100 example below is development shape only.

Run as a script (manual qualified runner:
scripts/run-h4a-prepost-userspace.py)::

    python3 -I tests/python/test_h4a_prepost_userspace.py --self-test
    # Development shape only (K=8/M=100):
    P11SCOPE_H4A_PRE_BIN=... P11SCOPE_H4A_POST_BIN=... P11SCOPE_H4A_POP=... \\
        P11SCOPE_H4A_K=8 P11SCOPE_H4A_M=100 \\
        python3 -I tests/python/test_h4a_prepost_userspace.py -v
"""

import importlib.util
import json
import math
import os
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_analyzer():
    spec = importlib.util.spec_from_file_location(
        "bench_count_overhead_analyze",
        str(ROOT / "scripts/bench-count-overhead-analyze.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ANALYZE = _load_analyzer()
paired_deltas = _ANALYZE.paired_deltas
bootstrap_median_ci = _ANALYZE.bootstrap_median_ci
summarize = _ANALYZE.summarize

REQUIRED_ENV = (
    "P11SCOPE_H4A_PRE_BIN",
    "P11SCOPE_H4A_POST_BIN",
    "P11SCOPE_H4A_POP",
    "P11SCOPE_H4A_K",
    "P11SCOPE_H4A_M",
)

CONFIRM_REG_BAR = 5.0
TOTAL_REG_BAR = 5.0
MEDIAN_BAR = 5.0
CI_UPPER_BAR = 10.0
WALL_BAR = 1.10
QUALIFYING_ROUNDS = 10
QUALIFYING_N_PER_ARM = 20

TIMING_LINE = re.compile(r"p11scope: pass (\d+): stage timings: (.+)")
OP_VALUE = re.compile(r"(\S+)\s+([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s)")
UNIT_NS = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}


class H4aError(Exception):
    """A gate input or signal failure: always a FAIL, never a pass."""


def p95(values):
    """95th percentile: ascending, index ceil(0.95*n)-1 (0-based)."""
    ordered = sorted(values)
    if not ordered:
        raise H4aError("p95 of no samples")
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


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
    raise H4aError("no pass with sweep + select and nonzero confirm")


def parse_event_log(path):
    """(pass_committed events in order, ended event). Rotation fails closed."""
    committed = []
    ended = None
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise H4aError(
                        f"{path}: bad JSON line ({exc})"
                    ) from exc
                if record.get("kind") == "pass_committed":
                    committed.append(record["event"])
                elif record.get("kind") == "ended":
                    ended = record["event"]
    except OSError as exc:
        raise H4aError(f"{path}: cannot read event log ({exc})") from exc
    if ended is None:
        raise H4aError(f"{path}: missing ended record (truncated stream?)")
    rotations = ended.get("stream", {}).get("rotations", 0)
    if rotations:
        raise H4aError(f"{path}: event stream rotated {rotations}x")
    for event in committed:
        for field in ("maps_matched", "scan_callers", "totals"):
            if field not in event:
                raise H4aError(f"{path}: pass_committed lacks {field}")
        for field in ("callers", "modules", "edges"):
            if field not in event["totals"]:
                raise H4aError(f"{path}: pass_committed totals lack {field}")
    return committed, ended


def parse_final_callers(path):
    """Caller pid set plus raw caller rows of the final JSON."""
    try:
        with open(path, encoding="utf-8") as handle:
            try:
                document = json.load(handle)
            except json.JSONDecodeError as exc:
                raise H4aError(
                    f"{path}: bad final JSON ({exc})"
                ) from exc
    except OSError as exc:
        raise H4aError(f"{path}: cannot read final JSON ({exc})") from exc
    callers = document.get("callers")
    if not isinstance(callers, list) or not callers:
        raise H4aError(f"{path}: final JSON has no callers")
    pids = set()
    for caller in callers:
        if "pid" not in caller:
            raise H4aError(f"{path}: caller lacks pid")
        pids.add(caller["pid"])
    return pids, callers


class H4aConfig:
    """Validated gate inputs; missing inputs fail closed."""

    def __init__(self, env):
        missing = [name for name in REQUIRED_ENV if not env.get(name)]
        if missing:
            raise H4aError(f"H4a inputs missing: {', '.join(missing)}")
        self.pre_bin = env["P11SCOPE_H4A_PRE_BIN"]
        self.post_bin = env["P11SCOPE_H4A_POST_BIN"]
        self.pop = Path(env["P11SCOPE_H4A_POP"])
        try:
            self.cap = int(env["P11SCOPE_H4A_K"])
            self.holders = int(env["P11SCOPE_H4A_M"])
            self.rounds = int(env.get("P11SCOPE_H4A_ROUNDS", "10"))
        except ValueError as exc:
            raise H4aError(f"H4a inputs missing: bad integer ({exc})") from exc
        self.duration = env.get("P11SCOPE_H4A_DURATION", "30s")
        self.workdir = Path(
            env.get("P11SCOPE_H4A_WORKDIR", tempfile.mkdtemp(prefix="h4a-"))
        )
        if self.cap <= 0 or self.holders <= 0 or self.rounds <= 0:
            raise H4aError("H4a inputs missing: K, M and rounds must be positive")
        if self.holders <= self.cap:
            raise H4aError(
                f"H4a inputs missing: M ({self.holders}) must exceed "
                f"K ({self.cap}) so the sweep runs"
            )
        for label, binary in (("pre", self.pre_bin), ("post", self.post_bin)):
            if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
                raise H4aError(f"H4a inputs missing: {label} binary not executable")
        providers = [self.pop / f"prov-{index}.so" for index in range(8)]
        absent = [str(path) for path in providers if not path.is_file()]
        if absent:
            raise H4aError(f"H4a inputs missing: providers absent: {absent[0]} ...")
        self.providers = providers
        self.workdir.mkdir(parents=True, exist_ok=True)

    def check_arm_flags(self):
        """Pre must lack --identity-backend; post must accept it."""
        for binary, want, label in (
            (self.pre_bin, False, "pre"),
            (self.post_bin, True, "post"),
        ):
            proc = subprocess.run(
                [binary, "inventory", "--help"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            has_flag = "--identity-backend" in proc.stdout
            if has_flag != want:
                state = "has" if has_flag else "lacks"
                raise H4aError(
                    f"H4a inputs missing: {label} arm {state} "
                    "--identity-backend (arms swapped?)"
                )


class HolderPopulation:
    """M sleep holders mapping all 8 providers via LD_PRELOAD."""

    def __init__(self, config):
        self.config = config
        self.pids = []
        self.procs = []

    def start(self):
        preload = ":".join(str(path) for path in self.config.providers)
        env = os.environ.copy()
        env["LD_PRELOAD"] = preload
        for _ in range(self.config.holders):
            proc = subprocess.Popen(
                ["sleep", "3600"], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.procs.append(proc)
            self.pids.append(proc.pid)
        time.sleep(2)
        alive = [proc for proc in self.procs if proc.poll() is None]
        if len(alive) != len(self.procs):
            self.stop()
            raise H4aError(
                f"only {len(alive)}/{len(self.procs)} holders alive after spawn"
            )
        for proc in self.procs:
            if self._mapped_providers(proc.pid) != 8:
                self.stop()
                raise H4aError(
                    f"holder {proc.pid} does not map all 8 providers"
                )

    @staticmethod
    def _mapped_providers(pid):
        """Distinct prov-N.so basenames mapped by pid (from /proc/PID/maps)."""
        seen = set()
        try:
            with open(f"/proc/{pid}/maps", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    path = parts[-1] if parts else ""
                    base = path.rsplit("/", 1)[-1]
                    if base.startswith("prov-") and base.endswith(".so"):
                        seen.add(base)
        except OSError:
            pass
        return len(seen)

    def check_frozen(self):
        """Every holder still alive: the population stayed frozen."""
        dead = [proc.pid for proc in self.procs if proc.poll() is not None]
        if dead:
            raise H4aError(f"population moved: {len(dead)} holders died mid-run")

    def stop(self):
        for proc in self.procs:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGKILL)
                except OSError:
                    pass
            try:
                proc.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                pass
        self.procs = []
        self.pids = []


def run_arm(config, binary, extra_flags, tag):
    """One workload run; returns its first-pass sample dict."""
    prefix = config.workdir / tag
    cmd = [
        binary, "inventory", "--system", "--capture", "scan",
        "--max-scan-pids", str(config.cap), "--duration", config.duration,
        "--json", "-o", str(prefix) + ".json",
        "--event-log", str(prefix) + ".jsonl",
        "--event-rotate-bytes", "1024M", "--event-max-files", "2",
        *extra_flags,
    ]
    env = os.environ.copy()
    env["P11SCOPE_STAGE_TIMINGS"] = "1"
    start = time.monotonic_ns()
    proc = subprocess.run(cmd, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wall_ns = time.monotonic_ns() - start
    with open(str(prefix) + ".stderr", "w", encoding="utf-8") as handle:
        handle.write(proc.stderr)
    if proc.returncode != 0:
        raise H4aError(f"{tag}: exit {proc.returncode}: {proc.stderr[-500:]}")
    passes = parse_stage_timings(proc.stderr)
    number, ops = first_qualifying_pass(passes)
    committed, _ = parse_event_log(str(prefix) + ".jsonl")
    event = next((item for item in committed if item.get("pass") == number), None)
    if event is None:
        raise H4aError(f"{tag}: no pass_committed for pass {number}")
    pids, _ = parse_final_callers(str(prefix) + ".json")
    return {
        "tag": tag,
        "confirm_ns": ops["confirm"],
        "total_ns": sum(ops.values()),
        "wall_ns": float(wall_ns),
        "pass": number,
        "event": event,
        "caller_pids": pids,
    }


def evaluate(pre_samples, post_samples, holder_pids, k=None, m=None,
             duration=None, rounds_expected=None):
    """Gate verdict over one campaign. Returns (passed, verdict, detail)."""
    count_errors = 0
    problems = []
    if not pre_samples or not post_samples:
        count_errors += 1
        problems.append("empty arm")
    n_pre = len(pre_samples)
    n_post = len(post_samples)
    rounds_observed = len(
        {s.get("round", 0) for s in [*pre_samples, *post_samples]}
    )
    qualifying = (
        rounds_observed >= QUALIFYING_ROUNDS
        and n_pre >= QUALIFYING_N_PER_ARM
        and n_post >= QUALIFYING_N_PER_ARM
    )
    if not qualifying:
        problems.append(
            f"non-qualifying shape: rounds={rounds_observed} "
            f"n_pre={n_pre} n_post={n_post} "
            f"(need >={QUALIFYING_ROUNDS} rounds, "
            f">={QUALIFYING_N_PER_ARM}/arm)"
        )
    pre_passes = sorted({s.get("pass") for s in pre_samples})
    post_passes = sorted({s.get("pass") for s in post_samples})
    pass_match = True
    if pre_samples and post_samples and set(pre_passes) != set(post_passes):
        pass_match = False
        problems.append(
            f"sampled pass indices diverge: pre={pre_passes} "
            f"post={post_passes}"
        )
    if m is None:
        m = len(holder_pids)
    holder_set = set(holder_pids)
    coverage_ok = True
    baseline = None
    if pre_samples:
        first = pre_samples[0]["event"]["totals"]
        baseline = (first["modules"], first["edges"])
    for sample in [*pre_samples, *post_samples]:
        pop = set(sample["caller_pids"]) & holder_set
        if pop != holder_set:
            coverage_ok = False
            problems.append(
                f"{sample['tag']}: {len(pop)}/{len(holder_set)} holders observed"
            )
        event = sample["event"]
        totals = (event["totals"]["modules"], event["totals"]["edges"])
        if baseline is not None and totals != baseline:
            coverage_ok = False
            problems.append(f"{sample['tag']}: totals {totals} != {baseline}")
    pre_confirm = [s["confirm_ns"] for s in pre_samples]
    post_confirm = [s["confirm_ns"] for s in post_samples]
    pre_total = [s["total_ns"] for s in pre_samples]
    post_total = [s["total_ns"] for s in post_samples]
    confirm_pre = p95(pre_confirm) if pre_confirm else 0.0
    confirm_post = p95(post_confirm) if post_confirm else 0.0
    total_pre = p95(pre_total) if pre_total else 0.0
    total_post = p95(post_total) if post_total else 0.0
    reg_pct = (confirm_post - confirm_pre) / confirm_pre * 100.0 if confirm_pre else float("inf")
    total_reg_pct = (total_post - total_pre) / total_pre * 100.0 if total_pre else float("inf")
    # V5-34 guards on pass totals via the shared analyzer, paired
    # within the true campaign rounds each sample ran in.
    campaign = []
    for sample in pre_samples:
        campaign.append({"arm": "off", "mode": "mmap", "ops": 1,
                         "wall_ns": sample["total_ns"],
                         "round": sample.get("round", 0)})
    for sample in post_samples:
        campaign.append({"arm": "on", "mode": "mmap", "ops": 1,
                         "wall_ns": sample["total_ns"],
                         "round": sample.get("round", 0)})
    deltas, problem = paired_deltas(campaign)
    if problem:
        count_errors += 1
        problems.append(problem)
        deltas = [0.0]
    pre_median = summarize(pre_total)["median"] if pre_total else 0.0
    median_delta = statistics.median(deltas)
    _ci_lo, ci_hi = bootstrap_median_ci(deltas)
    median_pct = median_delta / pre_median * 100.0 if pre_median else float("inf")
    ci95_upper_pct = ci_hi / pre_median * 100.0 if pre_median else float("inf")
    pre_wall = summarize([s["wall_ns"] for s in pre_samples])["median"] if pre_samples else 0.0
    post_wall = summarize([s["wall_ns"] for s in post_samples])["median"] if post_samples else float("inf")
    wall_ok = pre_wall > 0 and post_wall <= WALL_BAR * pre_wall
    gates = [
        ("confirm<=5%", reg_pct <= CONFIRM_REG_BAR),
        ("total<=5%", total_reg_pct <= TOTAL_REG_BAR),
        ("coverage", coverage_ok),
        ("median<=5%", median_pct <= MEDIAN_BAR),
        ("ci95<=10%", ci95_upper_pct <= CI_UPPER_BAR),
        ("count-errors==0", count_errors == 0),
        ("wall", wall_ok),
        ("qualifying-shape", qualifying),
        ("pass-match", pass_match),
    ]
    failed = [name for name, held in gates if not held]
    passed = not failed
    verdict = (
        f"H4A {'PASS' if passed else 'FAIL'} "
        f"confirm_pre={confirm_pre:.0f} confirm_post={confirm_post:.0f} "
        f"reg_pct={reg_pct:.2f} total_reg_pct={total_reg_pct:.2f} "
        f"coverage={'ok' if coverage_ok else 'MISMATCH'} "
        f"median_pct={median_pct:.2f} ci95_upper_pct={ci95_upper_pct:.2f} "
        f"wall_guard={'ok' if wall_ok else 'FAIL'}"
    )
    detail = {
        "gates": gates, "failed": failed, "problems": problems,
        "n_pre": len(pre_samples), "n_post": len(post_samples),
        "pre_passes": pre_passes, "post_passes": post_passes,
        "k": k, "m": m, "duration": duration,
        "rounds_observed": rounds_observed,
        "rounds_expected": rounds_expected,
    }
    return passed, verdict, detail


def round_order(round_number):
    """ABBA on odd rounds (A=post/on first), BAAB on even rounds."""
    if round_number % 2:
        return ("post", "pre", "pre", "post")
    return ("pre", "post", "post", "pre")


def run_campaign(config):
    """ABBA/BAAB campaign on a frozen population. Returns samples."""
    config.check_arm_flags()
    population = HolderPopulation(config)
    population.start()
    pre_samples, post_samples = [], []
    try:
        for rnd in range(1, config.rounds + 1):
            for slot, arm in enumerate(round_order(rnd)):
                tag = f"r{rnd:02d}-{slot}-{arm}"
                if arm == "pre":
                    sample = run_arm(config, config.pre_bin, [], tag)
                    sample["round"] = rnd
                    pre_samples.append(sample)
                else:
                    sample = run_arm(config, config.post_bin,
                                     ["--identity-backend", "userspace"], tag)
                    sample["round"] = rnd
                    post_samples.append(sample)
                population.check_frozen()
                print(f"h4a: {tag} pass={sample['pass']} "
                      f"confirm={sample['confirm_ns'] / 1e6:.1f}ms "
                      f"total={sample['total_ns'] / 1e6:.1f}ms", flush=True)
        frozen_pids = list(population.pids)
    finally:
        population.stop()
    return pre_samples, post_samples, frozen_pids


def make_sample(tag, confirm_ns, total_ns, wall_ns, holder_pids,
                observed_pids=None, modules=8, edges=None, rnd=1):
    """Synthetic sample for mutants and self-test."""
    if observed_pids is None:
        observed_pids = set(holder_pids)
    if edges is None:
        edges = 8 * len(holder_pids)
    return {
        "tag": tag, "confirm_ns": float(confirm_ns), "total_ns": float(total_ns),
        "wall_ns": float(wall_ns), "pass": 0, "round": rnd,
        "event": {"totals": {"callers": len(observed_pids) + 1,
                             "modules": modules, "edges": edges}},
        "caller_pids": set(observed_pids),
    }


def good_campaign(holders=10, rounds=10, confirm=1_000_000_000.0,
                  total=1_800_000_000.0, drift=0.0):
    """Two-arm synthetic campaign with equal coverage and `drift` uplift.

    Defaults to the qualifying shape: 10 rounds, 20 samples/arm.
    """
    holder_pids = list(range(1000, 1000 + holders))
    pre, post = [], []
    for rnd in range(1, rounds + 1):
        for slot in range(2):
            pre.append(make_sample(f"r{rnd}-pre{slot}", confirm, total,
                                   3e9, holder_pids, rnd=rnd))
            post.append(make_sample(
                f"r{rnd}-post{slot}", confirm * (1 + drift),
                total * (1 + drift), 3e9, holder_pids, rnd=rnd))
    return pre, post, holder_pids


class H4aGateTests(unittest.TestCase):
    """The live gate: needs root, both binaries and the Btrfs population."""

    def test_h4a_prepost_userspace_within_5_percent(self):
        try:
            config = H4aConfig(os.environ)
        except H4aError as exc:
            self.fail(str(exc))
        if os.geteuid() != 0:
            self.fail("H4a inputs missing: gate needs root (map_files proof)")
        try:
            pre, post, frozen_pids = run_campaign(config)
        except H4aError as exc:
            self.fail(f"H4A FAIL ({exc})")
        frozen = set(frozen_pids)
        if len(frozen) != config.holders:
            self.fail(f"H4A FAIL (frozen population {len(frozen)} "
                      f"!= M={config.holders})")
        passed, verdict, detail = evaluate(
            pre, post, frozen, k=config.cap, m=config.holders,
            duration=config.duration, rounds_expected=config.rounds,
        )
        print(f"h4a: rounds={config.rounds} K={config.cap} "
              f"M={config.holders} duration={config.duration} "
              f"n_pre={detail['n_pre']} n_post={detail['n_post']} "
              f"pre_passes={detail['pre_passes']} "
              f"post_passes={detail['post_passes']} {verdict}", flush=True)
        for problem in detail["problems"]:
            print(f"h4a: problem: {problem}", flush=True)
        self.assertTrue(passed, verdict)


class H4aMutantTests(unittest.TestCase):
    """Each mutant must FAIL the gate (non-vacuous by construction)."""

    def test_idle_soak_substitution_rejected(self):
        # The post arm replaced by sleep yields no stage timings: no
        # sample, so the gate fails closed instead of comparing noise.
        proc = subprocess.run(
            ["sleep", "0.2"], env={**os.environ, "P11SCOPE_STAGE_TIMINGS": "1"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(parse_stage_timings(proc.stderr), [])
        with self.assertRaises(H4aError):
            first_qualifying_pass(parse_stage_timings(proc.stderr))
        pre, _, holders = good_campaign()
        passed, verdict, _ = evaluate(pre, [], holders)
        self.assertFalse(passed, verdict)
        self.assertIn("FAIL", verdict)

    def test_unequal_coverage_rejected(self):
        # Post observes 7 providers' worth of edges and misses holders:
        # coverage MISMATCH fails the gate even with fast timings.
        pre, post, holders = good_campaign()
        short = set(holders[:-2])
        for sample in post:
            sample["caller_pids"] = set(short)
            sample["event"] = {"totals": {"callers": len(short) + 1,
                                          "modules": 7,
                                          "edges": 7 * len(holders)}}
        passed, verdict, _ = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)
        self.assertIn("MISMATCH", verdict)

    def test_hidden_loss_rejected(self):
        # A truncated post stream (timings without pass_committed/ended)
        # fails closed at collection: loss is never silently dropped.
        with tempfile.TemporaryDirectory(prefix="h4a-mutant-") as tmp:
            log = Path(tmp) / "cut.jsonl"
            log.write_text('{"kind": "edge_observed", "event": {}}\n',
                           encoding="utf-8")
            with self.assertRaisesRegex(H4aError, "missing ended"):
                parse_event_log(str(log))
        pre, post, holders = good_campaign()
        post[0]["event"] = {"totals": {"callers": len(holders) + 1,
                                       "modules": 8, "edges": 0}}
        passed, verdict, _ = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)


class H4aParserTests(unittest.TestCase):
    """Parsers accept the frozen signal shapes and reject anything else."""

    TIMINGS = (
        "p11scope: pass 0: stage timings: sweep 21.074ms, select 0.497ms, "
        "deep_scan 605.940ms, assemble 1.019ms, confirm 979.937ms\n"
    )

    def test_missing_inputs_fail_closed(self):
        env = {name: "" for name in REQUIRED_ENV}
        with self.assertRaisesRegex(H4aError, "H4a inputs missing"):
            H4aConfig(env)

    def test_p95_index_is_ceil(self):
        self.assertEqual(p95([float(n) for n in range(1, 21)]), 19.0)
        self.assertEqual(p95([5.0]), 5.0)
        with self.assertRaises(H4aError):
            p95([])

    def test_stage_timings_parse(self):
        passes = parse_stage_timings(self.TIMINGS)
        self.assertEqual(len(passes), 1)
        number, ops = first_qualifying_pass(passes)
        self.assertEqual(number, 0)
        self.assertAlmostEqual(ops["confirm"], 979937000.0, delta=1000)
        self.assertAlmostEqual(sum(ops.values()), 1608467000.0, delta=5000)

    def test_pass_without_confirm_does_not_count(self):
        text = self.TIMINGS.replace("confirm 979.937ms", "confirm 0ns")
        with self.assertRaises(H4aError):
            first_qualifying_pass(parse_stage_timings(text))
        text = "p11scope: pass 0: stage timings: deep_scan 1.0ms, confirm 2.0ms\n"
        with self.assertRaises(H4aError):
            first_qualifying_pass(parse_stage_timings(text))

    def test_round_order_is_abba_baab(self):
        self.assertEqual(round_order(1), ("post", "pre", "pre", "post"))
        self.assertEqual(round_order(2), ("pre", "post", "post", "pre"))
        self.assertEqual(round_order(11), ("post", "pre", "pre", "post"))

    def test_good_campaign_passes(self):
        pre, post, holders = good_campaign(drift=0.01)
        passed, verdict, detail = evaluate(pre, post, holders)
        self.assertTrue(passed, f"{verdict} {detail['problems']}")
        self.assertIn("H4A PASS", verdict)

    def test_single_round_campaign_fails_non_qualifying(self):
        pre, post, holders = good_campaign(rounds=1, drift=0.01)
        passed, verdict, detail = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)
        self.assertIn("FAIL", verdict)
        self.assertTrue(
            any("non-qualifying shape" in p for p in detail["problems"]),
            f"{verdict} {detail['problems']}",
        )

    def test_single_sample_per_arm_fails_non_qualifying(self):
        holders = list(range(1000, 1010))
        pre = [make_sample("pre0", 1e9, 1.8e9, 3e9, holders, rnd=1)]
        post = [make_sample("post0", 1e9, 1.8e9, 3e9, holders, rnd=1)]
        passed, verdict, detail = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)
        self.assertIn("FAIL", verdict)
        self.assertTrue(
            any("non-qualifying shape" in p for p in detail["problems"]),
            f"{verdict} {detail['problems']}",
        )

    def test_over_budget_campaign_fails(self):
        pre, post, holders = good_campaign(drift=0.20)
        passed, verdict, _ = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)

    def test_stable_ambient_totals_pass(self):
        # Ambient provider mappings (extra module/edges on every run)
        # pass when stable: coverage compares runs, not absolutes.
        pre, post, holders = good_campaign(drift=0.01)
        for sample in [*pre, *post]:
            sample["event"] = {"totals": {"callers": len(holders) + 6,
                                          "modules": 9, "edges": 850}}
        passed, verdict, detail = evaluate(pre, post, holders)
        self.assertTrue(passed, f"{verdict} {detail['problems']}")

    def test_divergent_sampled_passes_fail(self):
        pre, post, holders = good_campaign(drift=0.01)
        for sample in pre:
            sample["pass"] = 0
        for sample in post:
            sample["pass"] = 7
        passed, verdict, detail = evaluate(pre, post, holders)
        self.assertFalse(passed, verdict)
        self.assertIn("FAIL", verdict)
        self.assertTrue(
            any("pass" in p and "diverge" in p for p in detail["problems"]),
            f"{verdict} {detail['problems']}",
        )

    def test_detail_records_comparability(self):
        pre, post, holders = good_campaign(drift=0.01)
        _, _, detail = evaluate(
            pre, post, holders, k=8, m=10, duration="30s",
            rounds_expected=10,
        )
        for key in ("pre_passes", "post_passes", "k", "m",
                    "duration", "rounds_observed", "rounds_expected"):
            self.assertIn(key, detail)
        self.assertEqual(detail["k"], 8)
        self.assertEqual(detail["m"], 10)
        self.assertEqual(detail["duration"], "30s")
        self.assertEqual(detail["rounds_observed"], 10)
        self.assertEqual(detail["rounds_expected"], 10)

    def test_docstring_records_run_registration(self):
        doc = __doc__
        self.assertIn("RUN", doc)
        self.assertIn("--self-test", doc)
        self.assertIn("manual qualified runner", doc)
        self.assertNotIn("(DRIVEN suite)", doc)

    def test_qualified_runner_references_suite(self):
        runner = ROOT / "scripts/run-h4a-prepost-userspace.py"
        text = runner.read_text(encoding="utf-8")
        spec = importlib.util.spec_from_file_location(
            "run_python_suites",
            str(ROOT / "scripts/run-python-suites.py"),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state = module.driven_state(
            text, "test_h4a_prepost_userspace.py",
            "scripts/run-h4a-prepost-userspace.py",
        )
        self.assertEqual(state, "driven")

    def test_missing_event_log_raises_h4aerror(self):
        with tempfile.TemporaryDirectory(prefix="h4a-missing-") as tmp:
            missing = str(Path(tmp) / "absent.jsonl")
            with self.assertRaisesRegex(H4aError, "absent.jsonl"):
                parse_event_log(missing)

    def test_missing_final_json_raises_h4aerror(self):
        with tempfile.TemporaryDirectory(prefix="h4a-missing-") as tmp:
            missing = str(Path(tmp) / "absent.json")
            with self.assertRaisesRegex(H4aError, "absent.json"):
                parse_final_callers(missing)

    def test_empty_final_json_raises_h4aerror(self):
        with tempfile.TemporaryDirectory(prefix="h4a-empty-") as tmp:
            empty = Path(tmp) / "empty.json"
            empty.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(H4aError, "empty.json"):
                parse_final_callers(str(empty))

    def test_malformed_event_log_raises_h4aerror(self):
        with tempfile.TemporaryDirectory(prefix="h4a-bad-") as tmp:
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("not json\n", encoding="utf-8")
            with self.assertRaisesRegex(H4aError, "bad.jsonl"):
                parse_event_log(str(bad))


def self_test():
    """Unprivileged end-to-end check: parsers, analyzer, mutants, verdict."""
    checks = []
    checks.append(("analyzer fns", all(
        callable(fn) for fn in (paired_deltas, bootstrap_median_ci, summarize))))
    pre, post, holders = good_campaign(drift=0.01)
    passed, verdict, _ = evaluate(pre, post, holders)
    checks.append(("good campaign passes", passed and "H4A PASS" in verdict))
    over_pre, over_post, _ = good_campaign(drift=0.20)
    over_passed, _, _ = evaluate(over_pre, over_post, holders)
    checks.append(("over-budget fails", not over_passed))
    short = set(holders[:-1])
    for sample in post:
        sample["caller_pids"] = set(short)
    cov_passed, cov_verdict, _ = evaluate(pre, post, holders)
    checks.append(("coverage mismatch fails",
                   not cov_passed and "MISMATCH" in cov_verdict))
    empty_passed, _, _ = evaluate(pre, [], holders)
    checks.append(("idle soak fails", not empty_passed))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(H4aMutantTests))
    suite.addTests(loader.loadTestsFromTestCase(H4aParserTests))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    checks.append(("mutant+parser cases",
                   result.testsRun > 0 and result.wasSuccessful()))
    failed = [name for name, held in checks if not held]
    for name, held in checks:
        print(f"self-test: {'ok' if held else 'FAIL'}: {name}")
    if failed:
        print(f"self-test: FAIL: {failed}")
        return 1
    print(f"self-test: PASS ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(self_test())
    unittest.main()
