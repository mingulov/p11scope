#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Soak gates for the system-scope soak vehicle (soak.1800s and kin).

Evaluates one soak evidence directory produced by
scripts/system-scope-soak.sh and writes a verdict. Seven fail-closed
gates, each independently red-green proven by `--self-test` (synthetic
evidence) and, where the dry-run seam reaches, by short-horizon trials:

- duration: the receipt window covers require_duration_s.
- installed_identity: the installed observer bytes pinned before the run
  still hash identically after it (live mode only; a dry-run stub
  carries no installed authority and fails this gate by construction).
- ownership: the workload mapping receipt pins the exact workload
  generation that ran, and the private provider copy still hashes to
  the receipted bytes.
- workload_continuity: every expected epoch fired with exact call
  counts on increasing timestamps spanning the window.
- loss_accounting: pid-scope exactness (observed == workload truth)
  with a complete loss-counter universe.
- resource_accounting: the sampler trace spans the window without
  stalls, with peaks recorded.
- clean_exit: observer, sampler and workload all exited 0.

On PASS in live mode the oracle also writes the execution receipt
(schema p11scope/test-execution/v1, observed_behavior
continuous-owned-workload) that the acceptance manifest consumes; any
other outcome writes no qualifying receipt. A dry-run shape receipt
(observed_behavior dry-run-loopback) proves the writer ran without
being consumable by the verifier.

Stdlib only. Unprivileged: this module never launches the observer and
names no elevated invocation, so it stays out of the hosted UNRUN set.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

RUN_SCHEMA = "p11scope/soak-run/v1"
VERDICT_SCHEMA = "p11scope/soak-verdict/v1"
RECEIPT_SCHEMA = "p11scope/test-execution/v1"
RECORD_SCHEMA = "p11scope/system-scope-measurement/v1"
MAPPING_SCHEMA = "p11scope/workload-mapping-receipt/v1"
BEHAVIOR = "continuous-owned-workload"
DRY_BEHAVIOR = "dry-run-loopback"
GATES = ("duration", "installed_identity", "ownership",
         "workload_continuity", "loss_accounting",
         "resource_accounting", "clean_exit")


class OracleError(ValueError):
    """A gate input is missing or malformed; the gate fails, never passes."""


def require(condition, message):
    if not condition:
        raise OracleError(message)
    return condition


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise OracleError(f"cannot read {path}: {error}") from error
    except ValueError as error:
        raise OracleError(f"malformed JSON in {path}: {error}") from error


def sha256_file(path):
    try:
        with open(path, "rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise OracleError(f"cannot hash {path}: {error}") from error


def load_jsonl(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise OracleError(f"cannot read {path}: {error}") from error
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError as error:
            raise OracleError(
                f"malformed JSON on {path} line {number}: {error}") from error
    return rows


def strict_int(value, name):
    require(type(value) is int, f"{name} must be an integer")
    return value


def strict_str(value, name):
    require(isinstance(value, str) and value, f"{name} must be a nonempty string")
    return value


def hex64(value, name):
    require(isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value),
            f"{name} must be 64 lowercase hex")
    return value


def parse_epochs(workload_log_text):
    """Parse EPOCH JSON lines; malformed input raises, never skips."""
    epochs = []
    for line in workload_log_text.splitlines():
        if not line.startswith("EPOCH "):
            continue
        try:
            row = json.loads(line[len("EPOCH "):])
        except ValueError as error:
            raise OracleError(f"malformed EPOCH line: {line!r}") from error
        require(isinstance(row, dict), "EPOCH line must be a JSON object")
        epochs.append({
            "epoch": strict_int(row.get("epoch"), "epoch index"),
            "calls": strict_int(row.get("calls"), "epoch calls"),
            "t_mono_ns": strict_int(row.get("t_mono_ns"), "epoch timestamp"),
        })
    return epochs


class Evidence:
    """Typed view of one soak evidence directory; missing files fail loads."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.run = load_json(self.directory / "run.json")
        require(self.run.get("schema") == RUN_SCHEMA, "run.json schema mismatch")
        self.artifacts = self.run.get("artifacts")
        require(isinstance(self.artifacts, dict), "run.json artifacts must be an object")
        self.record = load_json(self.directory / self.artifact("record"))

    def artifact(self, name):
        relative = strict_str(self.artifacts.get(name), f"artifact {name}")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                f"artifact {name} escapes the evidence directory")
        return relative

    def path(self, name):
        return self.directory / self.artifact(name)

    def optional_path(self, name):
        relative = self.artifacts.get(name)
        if relative is None:
            return None
        return self.directory / self.artifact(name)


def gate_duration(evidence):
    run = evidence.run
    timing = run.get("timing")
    require(isinstance(timing, dict), "run.json timing must be an object")
    start = strict_int(timing.get("start_mono_ns"), "start_mono_ns")
    end = strict_int(timing.get("end_mono_ns"), "end_mono_ns")
    required = strict_int(run.get("require_duration_s"), "require_duration_s")
    require(start >= 0 and end >= 0, "window timestamps must be nonnegative")
    actual_ns = end - start
    detail = (f"window {actual_ns / 1e9:.3f}s against required {required}s")
    return actual_ns >= required * 1_000_000_000, detail


def gate_installed_identity(evidence):
    run = evidence.run
    if run.get("mode") != "live":
        return False, "dry-run stub carries no installed authority"
    installed = run.get("installed")
    require(isinstance(installed, dict), "live run needs an installed pin")
    path = strict_str(installed.get("path"), "installed path")
    require(Path(path).is_absolute(), "installed path must be absolute")
    pre = hex64(installed.get("sha256_pre"), "installed sha256_pre")
    post = hex64(installed.get("sha256_post"), "installed sha256_post")
    size = strict_int(installed.get("size"), "installed size")
    if pre != post:
        return False, "installed bytes changed between pre-run and post-run pins"
    copy_path = evidence.optional_path("installed_copy")
    require(copy_path is not None, "live run needs an installed evidence copy")
    copy_digest = sha256_file(copy_path)
    live_digest = sha256_file(path)
    if live_digest != post or copy_digest != post:
        return False, "installed bytes differ from the pinned digest"
    actual_size = copy_path.stat().st_size
    if actual_size != size:
        return False, "installed evidence copy size differs from the pin"
    return True, f"installed {path} pinned {post[:16]}... pre==post==copy"


def gate_ownership(evidence):
    run = evidence.run
    workload = run.get("workload")
    require(isinstance(workload, dict), "run.json workload must be an object")
    pid = strict_int(workload.get("pid"), "workload pid")
    starttime = strict_int(workload.get("starttime"), "workload starttime")
    receipt_path = evidence.optional_path("mapping_receipt")
    if receipt_path is None or not receipt_path.is_file():
        return False, "no workload mapping receipt in this evidence"
    receipt = load_json(receipt_path)
    if receipt.get("schema") != MAPPING_SCHEMA:
        return False, "mapping receipt schema mismatch"
    if receipt.get("pid") != pid or receipt.get("starttime") != starttime:
        return False, "mapping receipt names a different workload generation"
    metadata_path = evidence.optional_path("receipt_metadata")
    if metadata_path is None or not metadata_path.is_file():
        return False, "no receipt metadata joining the mapping to the provider copy"
    metadata = load_json(metadata_path)
    try:
        copy = metadata["provider_copy"]["copy"]
        copy_path = strict_str(copy.get("path"), "provider copy path")
        identities = metadata["workload_module_identity"]
        require(isinstance(identities, list) and identities, "no workload module identity")
        claimed = hex64(identities[0].get("sha256"), "receipted module sha256")
    except (KeyError, TypeError) as error:
        raise OracleError(f"receipt metadata shape is invalid: {error}") from error
    actual = sha256_file(copy_path)
    if actual != claimed:
        return False, "provider copy bytes differ from the receipted digest"
    return True, f"workload pid={pid} starttime={starttime} pinned to {claimed[:16]}..."


def gate_workload_continuity(evidence):
    run = evidence.run
    expected = strict_int(run.get("expected_epochs"), "expected_epochs")
    epoch_calls = strict_int(run.get("epoch_calls"), "epoch_calls")
    epoch_s = strict_int(run.get("epoch_s"), "epoch_s")
    required = strict_int(run.get("require_duration_s"), "require_duration_s")
    require(expected >= 1 and epoch_calls >= 1 and epoch_s >= 1,
            "epoch plan must be positive")
    timing = run.get("timing")
    require(isinstance(timing, dict), "run.json timing must be an object")
    go = strict_int(timing.get("t_go_mono_ns"), "t_go_mono_ns")
    try:
        text = evidence.path("workload_log").read_text(encoding="utf-8")
    except OSError as error:
        raise OracleError(f"cannot read workload log: {error}") from error
    epochs = parse_epochs(text)
    if len(epochs) != expected:
        return False, f"{len(epochs)} epoch lines against {expected} expected"
    for position, row in enumerate(epochs):
        if row["epoch"] != position:
            return False, f"epoch index {row['epoch']} out of sequence at line {position}"
        if row["calls"] != epoch_calls:
            return False, f"epoch {position} fired {row['calls']} calls, not {epoch_calls}"
        if position and row["t_mono_ns"] <= epochs[position - 1]["t_mono_ns"]:
            return False, f"epoch {position} timestamp does not increase"
    first, last = epochs[0]["t_mono_ns"], epochs[-1]["t_mono_ns"]
    if first - go > 2 * epoch_s * 1_000_000_000:
        return False, "first epoch fired more than two epoch lengths after release"
    span_ns = last - go
    floor_ns = (required - 3 * epoch_s) * 1_000_000_000
    detail = (f"{expected} epochs x {epoch_calls} calls spanning "
              f"{span_ns / 1e9:.3f}s against a {floor_ns / 1e9:.3f}s floor")
    return span_ns >= floor_ns, detail


def gate_loss_accounting(evidence):
    record = evidence.record
    require(record.get("schema") == RECORD_SCHEMA, "record.json schema mismatch")
    condition = record.get("condition")
    require(isinstance(condition, dict), "record condition must be an object")
    if condition.get("scope") != "pid":
        return False, "soak loss accounting requires pid scope exactness"
    joined = record.get("truth_vs_observed")
    require(isinstance(joined, dict), "record truth_vs_observed must be an object")
    if joined.get("counts_match") is not True:
        return False, f"workload truth does not equal observed calls: {joined.get('match_note')}"
    counters = (record.get("evidence") or {}).get("counters")
    require(isinstance(counters, dict) and counters, "record counters must be a nonempty object")
    missing = sorted(name for name, value in counters.items() if value is None)
    if missing:
        return False, f"loss counters without a value: {', '.join(missing)}"
    for name, value in counters.items():
        require(type(value) is int and value >= 0, f"counter {name} must be a nonnegative integer")
    nonzero = {name: value for name, value in counters.items() if value}
    truth = joined.get("truth")
    require(isinstance(truth, dict) and truth, "record truth must be a nonempty object")
    total = sum(strict_int(value, f"truth {name}") for name, value in truth.items())
    detail = (f"pid exact: {total} generated == observed; "
              f"{len(counters)} counters complete"
              + (f"; nonzero losses accounted: {nonzero}" if nonzero else "; zero loss"))
    return True, detail


def gate_resource_accounting(evidence):
    run = evidence.run
    required = strict_int(run.get("require_duration_s"), "require_duration_s")
    timing = run.get("timing")
    require(isinstance(timing, dict), "run.json timing must be an object")
    go = strict_int(timing.get("t_go_mono_ns"), "t_go_mono_ns")
    rows = load_jsonl(evidence.path("samples"))
    if len(rows) < 2:
        return False, "fewer than two resource samples"
    stamps = []
    for row in rows:
        require(isinstance(row, dict), "sample row must be an object")
        stamps.append(strict_int(row.get("t_mono_ns"), "sample timestamp"))
    if stamps != sorted(stamps):
        return False, "sample timestamps are not ordered"
    if stamps[0] > go:
        return False, "sampler started after the workload was released"
    span_ns = stamps[-1] - stamps[0]
    floor_ns = (required - 10) * 1_000_000_000
    if span_ns < floor_ns:
        return False, (f"sample trace spans {span_ns / 1e9:.3f}s "
                       f"against a {floor_ns / 1e9:.3f}s floor")
    worst_gap_ns = max(b - a for a, b in zip(stamps, stamps[1:]))
    if worst_gap_ns > 30_000_000_000:
        return False, f"sampler stalled for {worst_gap_ns / 1e9:.1f}s mid-window"
    observer = evidence.record.get("observer")
    require(isinstance(observer, dict), "record observer stats must be an object")
    peaks = {key: strict_int(observer.get(key), f"observer {key}")
             for key in ("rss_max_bytes", "fds_max")}
    detail = (f"{len(rows)} samples spanning {span_ns / 1e9:.3f}s, worst gap "
              f"{worst_gap_ns / 1e9:.3f}s; rss_max={peaks['rss_max_bytes']} "
              f"fds_max={peaks['fds_max']}")
    return True, detail


def gate_clean_exit(evidence):
    run = evidence.run
    problems = []
    for name in ("observer", "sampler", "workload"):
        outcome = run.get(name)
        require(isinstance(outcome, dict), f"run.json {name} must be an object")
        code = outcome.get("exit")
        require(type(code) is int, f"{name} exit must be an integer")
        signal = outcome.get("signal")
        if name == "workload":
            if code != 0:
                problems.append(f"workload exit={code}")
            continue
        if outcome.get("timed_out") is True:
            problems.append(f"{name} timed out")
        if code != 0 or signal is not None:
            problems.append(f"{name} exit={code} signal={signal}")
    if problems:
        return False, "; ".join(problems)
    return True, "observer, sampler and workload all exited 0"


GATE_FUNCTIONS = {
    "duration": gate_duration,
    "installed_identity": gate_installed_identity,
    "ownership": gate_ownership,
    "workload_continuity": gate_workload_continuity,
    "loss_accounting": gate_loss_accounting,
    "resource_accounting": gate_resource_accounting,
    "clean_exit": gate_clean_exit,
}


def evaluate(directory):
    """Run every gate; malformed evidence fails the gate that reads it."""
    try:
        evidence = Evidence(directory)
    except (OracleError, OSError) as error:
        gates = {name: {"pass": False, "detail": f"evidence load failed: {error}"}
                 for name in GATES}
        return {"schema": VERDICT_SCHEMA, "cell_id": None, "mode": None,
                "verdict": "FAIL", "require_duration_s": None,
                "window_s": None, "gates": gates,
                "evidence_dir": str(Path(directory))}
    gates = {}
    for name in GATES:
        try:
            passed, detail = GATE_FUNCTIONS[name](evidence)
            gates[name] = {"pass": bool(passed), "detail": str(detail)}
        except OracleError as error:
            gates[name] = {"pass": False, "detail": f"invalid evidence: {error}"}
    timing = evidence.run.get("timing", {})
    start, end = timing.get("start_mono_ns"), timing.get("end_mono_ns")
    window_s = (end - start) / 1e9 if type(start) is int and type(end) is int else None
    verdict = "PASS" if all(gate["pass"] for gate in gates.values()) else "FAIL"
    return {"schema": VERDICT_SCHEMA, "cell_id": evidence.run.get("cell_id"),
            "mode": evidence.run.get("mode"), "verdict": verdict,
            "require_duration_s": evidence.run.get("require_duration_s"),
            "window_s": window_s, "gates": gates,
            "evidence_dir": str(evidence.directory)}


RECEIPT_EVIDENCE = ("run", "verdict", "record", "meta", "report", "samples",
                    "stderr_ts", "stderr", "workload_log", "mapping_receipt",
                    "receipt_metadata")


def build_receipt(directory, verdict, *, dry_run=False):
    """Build the execution receipt for this verdict.

    Qualifying receipts (live mode) require a PASS verdict and carry
    observed_behavior continuous-owned-workload. A dry-run shape receipt
    keeps the exact structure with a non-qualifying observed_behavior
    and the verdict's own outcome, so it proves the writer ran while
    the verifier must still reject it for the cell. The receipt is
    written after the verdict, so the verdict itself is hashed evidence;
    the receipt file is hashed by the manifest row, not by itself.
    """
    evidence = Evidence(directory)
    run = evidence.run
    if dry_run:
        require(run.get("mode") == "dry-run", "shape receipts need dry-run evidence")
        behavior = DRY_BEHAVIOR
        outcome = verdict.get("verdict")
        require(outcome in ("PASS", "FAIL"), "verdict must be PASS or FAIL")
    else:
        require(verdict.get("verdict") == "PASS", "no receipt without a PASS verdict")
        require(run.get("mode") == "live", "qualifying receipts need live evidence")
        behavior = BEHAVIOR
        outcome = "PASS"
    cell_id = strict_str(run.get("cell_id"), "cell_id")
    test_ids = run.get("test_ids")
    require(isinstance(test_ids, list) and test_ids
            and all(isinstance(entry, str) and entry for entry in test_ids)
            and len(set(test_ids)) == len(test_ids),
            "test_ids must be nonempty and duplicate-free")
    command = run.get("harness_argv")
    require(isinstance(command, list) and command
            and all(isinstance(entry, str) and entry for entry in command),
            "harness_argv must be a nonempty argv")
    subject = run.get("subject")
    require(isinstance(subject, dict), "subject must be an object")
    for key in ("revision", "tree"):
        require(isinstance(subject.get(key), str)
                and re.fullmatch(r"[0-9a-f]{40}", subject[key]),
                f"subject {key} must be 40 lowercase hex")
    kernel_profile = strict_str(run.get("kernel_profile"), "kernel_profile")
    timing = run.get("timing")
    start = strict_int(timing.get("start_mono_ns"), "start_mono_ns")
    end = strict_int(timing.get("end_mono_ns"), "end_mono_ns")
    artifact_hashes = {}
    evidence_paths = []
    installed_copy = evidence.optional_path("installed_copy")
    if installed_copy is not None:
        digest = sha256_file(installed_copy)
        relative = evidence.artifact("installed_copy")
        artifact_hashes["installed"] = {"path": relative, "sha256": digest}
        evidence_paths.append(relative)
    for name in RECEIPT_EVIDENCE:
        if name == "verdict":
            relative = "verdict.json"
            path = evidence.directory / relative
            require(path.is_file(), "the verdict itself must be hashed evidence")
        else:
            try:
                relative = evidence.artifact(name)
            except OracleError:
                continue
            path = evidence.directory / relative
            if not path.is_file():
                continue
        artifact_hashes[name] = {"path": relative, "sha256": sha256_file(path)}
        evidence_paths.append(relative)
    require(artifact_hashes and evidence_paths, "receipt needs hashed evidence")
    installed_digest = artifact_hashes.get("installed", {}).get("sha256")
    if not dry_run:
        require(installed_digest, "a qualifying soak receipt needs the installed artifact")
    receipt = {"schema": RECEIPT_SCHEMA, "cell_id": cell_id, "subject": subject,
               "evidence_level": "soak", "entrypoint": "installed-cli",
               "kernel_profile": kernel_profile, "test_ids": list(test_ids),
               "executed_test_ids": list(test_ids), "command": list(command),
               "exit_code": 0 if outcome == "PASS" else 1, "outcome": outcome,
               "artifact_hashes": artifact_hashes,
               "evidence_paths": sorted(set(evidence_paths)),
               "observed_behavior": behavior,
               "start_mono_ns": start, "end_mono_ns": end,
               "observer_command": list(run.get("observer_argv", []))}
    if installed_digest:
        receipt["installed_artifact_sha256"] = installed_digest
    return receipt


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="run the synthetic red-green gate battery")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--out-verdict", type=Path)
    parser.add_argument("--out-receipt", type=Path, default=None,
                        help="qualifying receipt path (live PASS only)")
    parser.add_argument("--dry-run-receipt", type=Path, default=None,
                        help="shape receipt path (dry-run PASS only)")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.evidence_dir is None or args.out_verdict is None:
        parser.error("--evidence-dir and --out-verdict are required")
    if args.out_receipt is not None and args.dry_run_receipt is not None:
        parser.error("--out-receipt and --dry-run-receipt are exclusive")
    try:
        verdict = evaluate(args.evidence_dir)
        write_json(args.out_verdict, verdict)
        if args.out_receipt is not None:
            write_json(args.out_receipt,
                       build_receipt(args.evidence_dir, verdict, dry_run=False))
        if args.dry_run_receipt is not None:
            write_json(args.dry_run_receipt,
                       build_receipt(args.evidence_dir, verdict, dry_run=True))
        if verdict["verdict"] != "PASS":
            print(f"soak {verdict['cell_id']}: FAIL", flush=True)
            for name in GATES:
                gate = verdict["gates"][name]
                if not gate["pass"]:
                    print(f"  RED {name}: {gate['detail']}", flush=True)
            return 1
        print(f"soak {verdict['cell_id']}: PASS", flush=True)
        return 0
    except (OracleError, OSError, KeyError, TypeError) as error:
        print(f"soak oracle refused: {error}", file=sys.stderr)
        return 1


def load_verifier():
    """Load the acceptance verifier; the battery checks receipts against it."""
    path = Path(__file__).resolve().parent / "verify-system-test-manifest.py"
    spec = importlib.util.spec_from_file_location("soak_verify_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_synthetic_evidence(root, *, mode="live", require_duration_s=1800,
                             epochs=30, epoch_s=60, epoch_calls=570):
    """Write a fully green synthetic evidence directory; legs mutate copies."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    go = 1_000_000_000
    end = go + require_duration_s * 1_000_000_000 + epoch_s * 1_000_000_000
    installed_bytes = b"synthetic installed observer bytes"
    installed_live = root / "installed-live" / "p11scope"
    installed_live.parent.mkdir()
    installed_live.write_bytes(installed_bytes)
    installed_digest = hashlib.sha256(installed_bytes).hexdigest()
    provider_bytes = b"synthetic private provider copy"
    provider_copy = root / "provider" / "libsofthsm2-owned.so"
    provider_copy.parent.mkdir()
    provider_copy.write_bytes(provider_bytes)
    provider_digest = hashlib.sha256(provider_bytes).hexdigest()
    if mode == "live":
        copy_dir = root / "installed"
        copy_dir.mkdir()
        (copy_dir / "p11scope").write_bytes(installed_bytes)
        installed = {"path": str(installed_live), "sha256_pre": installed_digest,
                     "sha256_post": installed_digest, "size": len(installed_bytes)}
        installed_copy_rel = "installed/p11scope"
    else:
        installed = None
        installed_copy_rel = None
    total_calls = epochs * epoch_calls
    span_ns = require_duration_s * 1_000_000_000 - epoch_s * 1_000_000_000
    lines = ["workload: READY pid=4242"]
    for index in range(epochs):
        stamp = go + (span_ns * index // max(epochs - 1, 1))
        lines.append("EPOCH " + json.dumps({"epoch": index, "calls": epoch_calls,
                                            "t_mono_ns": stamp}))
    lines.append(f'TRUTH {{"C_GenerateRandom": {total_calls}}}')
    (root / "workload.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    samples = []
    step_ns = (end - go) // 100
    for index in range(101):
        samples.append({"t_mono_ns": go - 5_000_000_000 + index * step_ns,
                        "utime_ticks": 100 + index, "stime_ticks": 10,
                        "rss_bytes": 50_000_000 + index * 1000,
                        "fds": 40, "threads": 3, "clk_tck": 100})
    (root / "samples.jsonl").write_text(
        "\n".join(json.dumps(row) for row in samples) + "\n", encoding="utf-8")
    counters = {"event_loss": 0, "pending_at_end": 0, "malformed_records": 0}
    record = {"schema": RECORD_SCHEMA,
              "condition": {"scope": "pid", "mode": "metrics"},
              "truth_vs_observed": {
                  "truth": {"C_GenerateRandom": total_calls},
                  "observed": {"C_GenerateRandom": total_calls},
                  "counts_match": True, "match_note": "synthetic exact"},
              "evidence": {"counters": counters, "counters_source": "synthetic"},
              "observer": {"samples": len(samples), "rss_max_bytes": 51_000_000,
                           "fds_max": 40}}
    (root / "record.json").write_text(json.dumps(record), encoding="utf-8")
    (root / "report.json").write_text('{"schema": "synthetic"}', encoding="utf-8")
    (root / "meta.json").write_text('{"synthetic": true}', encoding="utf-8")
    (root / "stderr-ts.jsonl").write_text("", encoding="utf-8")
    (root / "stderr.txt").write_text("synthetic\n", encoding="utf-8")
    receipt = {"schema": MAPPING_SCHEMA, "pid": 4242, "starttime": 999888,
               "mapping_identity": {"dev": "7:1", "ino": 1234}}
    (root / "workload-mapping-receipt.json").write_text(json.dumps(receipt),
                                                        encoding="utf-8")
    metadata = {"provider_copy": {
        "source": {"path": "/synthetic/source.so", "sha256": provider_digest},
        "copy": {"path": str(provider_copy), "sha256": provider_digest}},
        "workload_module_identity": [{"dev": "7:1", "ino": 1234,
                                      "sha256": provider_digest}]}
    (root / "receipt-metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    run = {"schema": RUN_SCHEMA, "cell_id": "soak.1800s",
           "test_ids": ["soak.1800s::continuous-owned-workload"],
           "kernel_profile": "current/default", "mode": mode,
           "horizon_s": require_duration_s, "require_duration_s": require_duration_s,
           "epoch_s": epoch_s, "epoch_calls": epoch_calls,
           "expected_epochs": epochs, "pace_us": 100000,
           "subject": {"revision": "a" * 40, "tree": "b" * 40},
           "harness": {"name": "synthetic", "git_rev": "a" * 40, "argv": ["synthetic"]},
           "harness_argv": ["system-scope-soak.sh", "--cell", "soak.1800s"],
           "observer_argv": ["p11scope", "profile", "--pid", "4242"],
           "installed": installed,
           "stub": None if mode == "live" else {"path": "/synthetic/stub",
                                                "sha256": "c" * 64},
           "workload": {"pid": 4242, "starttime": 999888, "argv": ["workload"],
                        "exit": 0},
           "observer": {"exit": 0, "signal": None, "timed_out": False},
           "sampler": {"exit": 0, "signal": None},
           "timing": {"t_spawn_mono_ns": go - 10_000_000_000,
                      "t_go_mono_ns": go, "start_mono_ns": go, "end_mono_ns": end},
           "ownership": {"mapping_receipt": "workload-mapping-receipt.json",
                         "note": "synthetic"},
           "artifacts": {"run": "run.json", "record": "record.json", "meta": "meta.json",
                         "report": "report.json", "samples": "samples.jsonl",
                         "stderr_ts": "stderr-ts.jsonl", "stderr": "stderr.txt",
                         "workload_log": "workload.log",
                         "mapping_receipt": "workload-mapping-receipt.json",
                         "receipt_metadata": "receipt-metadata.json",
                         "installed_copy": installed_copy_rel}}
    (root / "run.json").write_text(json.dumps(run), encoding="utf-8")
    return root


def mutate_copy(base, name, mutate):
    target = base.parent / name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(base, target)
    # Repoint absolute pins at the copy so legs mutate their own bytes.
    rewrite_json(target / "run.json",
                 lambda run: run["installed"].update(
                     {"path": str(target / "installed-live" / "p11scope")})
                 if run.get("installed") else None)
    rewrite_json(target / "receipt-metadata.json",
                 lambda metadata: metadata["provider_copy"]["copy"].update(
                     {"path": str(target / "provider" / "libsofthsm2-owned.so")}))
    mutate(target)
    return target


def rewrite_json(path, transform):
    path = Path(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    transform(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def verify_soak_receipt(verifier, evidence_dir, receipt, cell_id="soak.1800s"):
    """Run the real acceptance verifier over a synthetic soak receipt."""
    manifest = verifier.new_manifest()
    manifest["subject"] = receipt["subject"]
    row = next(row for row in manifest["cells"] if row["id"] == cell_id)
    row.update({"test_ids": receipt["test_ids"], "command": receipt["command"],
                "artifact_hashes": receipt["artifact_hashes"],
                "evidence_paths": receipt["evidence_paths"],
                "outcome": "PASS", "receipt": "receipt.json"})
    receipt_path = Path(evidence_dir) / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    return verifier.verify_manifest(manifest, Path(evidence_dir), structure_only=True)


def run_self_test():
    """Synthetic red-green battery: the control passes and every gate fails."""
    failures = []
    try:
        verifier = load_verifier()
    except (OSError, ValueError) as error:
        print(f"self-test refused: cannot load the verifier: {error}", file=sys.stderr)
        return 1

    def check(name, condition, detail=""):
        print(f"  {'GREEN' if condition else 'RED-PROOF-FAILED'} {name}"
              + (f": {detail}" if detail and not condition else ""), flush=True)
        if not condition:
            failures.append(name)

    def red_leg(base, name, gate, mutate):
        target = mutate_copy(base, f"leg-{name}", mutate)
        verdict = evaluate(target)
        gate_result = verdict["gates"][gate]
        check(f"red/{name}", verdict["verdict"] == "FAIL" and not gate_result["pass"],
              gate_result["detail"])
        return target

    with tempfile.TemporaryDirectory(prefix="soak-oracle-selftest-") as tmp:
        tmp_path = Path(tmp)
        # The control: fully green live evidence passes and its receipt
        # verifies against the real acceptance oracle for soak.1800s.
        control = make_synthetic_evidence(tmp_path / "control")
        verdict = evaluate(control)
        check("green/control", verdict["verdict"] == "PASS",
              json.dumps(verdict["gates"]))
        write_json(control / "verdict.json", verdict)
        try:
            receipt = build_receipt(control, verdict, dry_run=False)
            report = verify_soak_receipt(verifier, control, receipt)
            check("green/receipt-verifies",
                  report["verdict"] == "STRUCTURE_VALID", str(report))
        except (OracleError, ValueError, OSError) as error:
            check("green/receipt-verifies", False, str(error))
        # A short window with the full 1800s requirement fails duration
        # while the same evidence passes a 10s requirement: the gate
        # measures, it does not default to green.
        short = make_synthetic_evidence(tmp_path / "short", require_duration_s=10,
                                        epochs=5, epoch_s=2, epoch_calls=5)
        check("green/short-horizon", evaluate(short)["verdict"] == "PASS",
              json.dumps(evaluate(short)["gates"]))
        red_leg(control, "duration", "duration",
                lambda target: rewrite_json(
                    target / "run.json",
                    lambda run: run["timing"].update(
                        {"end_mono_ns": run["timing"]["start_mono_ns"]
                         + 1799 * 1_000_000_000})))
        red_leg(control, "installed-changed", "installed_identity",
                lambda target: (target / "installed-live" / "p11scope").write_bytes(
                    b"different bytes"))
        red_leg(control, "installed-pin-mismatch", "installed_identity",
                lambda target: rewrite_json(
                    target / "run.json",
                    lambda run: run["installed"].update({"sha256_post": "d" * 64})))
        red_leg(control, "ownership-generation", "ownership",
                lambda target: rewrite_json(
                    target / "workload-mapping-receipt.json",
                    lambda receipt: receipt.update({"pid": 4243})))
        red_leg(control, "ownership-missing", "ownership",
                lambda target: (target / "workload-mapping-receipt.json").unlink())
        red_leg(control, "ownership-bytes", "ownership",
                lambda target: (target / "provider" / "libsofthsm2-owned.so").write_bytes(
                    b"different provider bytes"))

        def drop_epoch(target):
            path = target / "workload.log"
            kept = [line for line in path.read_text(encoding="utf-8").splitlines()
                    if '"epoch": 7' not in line]
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")

        red_leg(control, "continuity-dropped-epoch", "workload_continuity", drop_epoch)

        def stall_epochs(target):
            path = target / "workload.log"
            out = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("EPOCH "):
                    row = json.loads(line[len("EPOCH "):])
                    row["t_mono_ns"] = 1_000_000_000 + row["epoch"] * 1_000_000_000
                    line = "EPOCH " + json.dumps(row)
                out.append(line)
            path.write_text("\n".join(out) + "\n", encoding="utf-8")

        red_leg(control, "continuity-stalled-span", "workload_continuity", stall_epochs)
        red_leg(control, "loss-mismatch", "loss_accounting",
                lambda target: rewrite_json(
                    target / "record.json",
                    lambda record: record["truth_vs_observed"].update(
                        {"counts_match": False,
                         "match_note": "synthetic mismatch"})))
        red_leg(control, "loss-counter-missing", "loss_accounting",
                lambda target: rewrite_json(
                    target / "record.json",
                    lambda record: record["evidence"]["counters"].update(
                        {"event_loss": None})))

        def gap_samples(target):
            path = target / "samples.jsonl"
            rows = [json.loads(line) for line in
                    path.read_text(encoding="utf-8").splitlines()]
            rows = rows[:5] + rows[35:]
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n",
                            encoding="utf-8")

        red_leg(control, "resources-gap", "resource_accounting", gap_samples)
        red_leg(control, "resources-empty", "resource_accounting",
                lambda target: (target / "samples.jsonl").write_text("", encoding="utf-8"))
        red_leg(control, "clean-exit", "clean_exit",
                lambda target: rewrite_json(
                    target / "run.json",
                    lambda run: run["observer"].update({"exit": 3})))
        red_leg(control, "clean-timeout", "clean_exit",
                lambda target: rewrite_json(
                    target / "run.json",
                    lambda run: run["observer"].update({"timed_out": True})))
        # The honest dry-run: everything real passes, installed authority
        # fails by construction, the shape receipt builds but the real
        # verifier refuses it for the cell.
        dry = make_synthetic_evidence(tmp_path / "dry", mode="dry-run",
                                      require_duration_s=10, epochs=4,
                                      epoch_s=2, epoch_calls=5)
        dry_verdict = evaluate(dry)
        others = [name for name in GATES if name != "installed_identity"]
        check("red/dry-run-installed",
              dry_verdict["verdict"] == "FAIL"
              and not dry_verdict["gates"]["installed_identity"]["pass"]
              and all(dry_verdict["gates"][name]["pass"] for name in others),
              json.dumps(dry_verdict["gates"]))
        write_json(dry / "verdict.json", dry_verdict)
        try:
            build_receipt(dry, dry_verdict, dry_run=False)
            check("red/dry-run-no-qualifying-receipt", False, "qualifying receipt built")
        except OracleError:
            check("red/dry-run-no-qualifying-receipt", True)
        # A dry-run PASS needs installable shape: flip the one honest gate
        # by hand to prove the writer path, then prove the verifier refuses.
        passing = dict(dry_verdict)
        passing["verdict"] = "PASS"
        passing["gates"] = {name: {"pass": True, "detail": "forced green for shape proof"}
                            for name in GATES}
        write_json(dry / "verdict.json", passing)
        try:
            shape = build_receipt(dry, passing, dry_run=True)
            verify_soak_receipt(verifier, dry, shape)
            check("red/dry-run-shape-rejected", False, "verifier accepted the shape")
        except ValueError as error:
            check("red/dry-run-shape-rejected", "behavior" in str(error), str(error))
        # The shape receipt also builds on a FAIL verdict (carrying FAIL),
        # so trial wiring is proven even when the verdict is red.
        write_json(dry / "verdict.json", dry_verdict)
        try:
            shape_fail = build_receipt(dry, dry_verdict, dry_run=True)
            check("green/dry-run-shape-on-fail",
                  shape_fail["outcome"] == "FAIL" and shape_fail["exit_code"] == 1,
                  json.dumps({key: shape_fail[key] for key in ("outcome", "exit_code")}))
        except (OracleError, OSError) as error:
            check("green/dry-run-shape-on-fail", False, str(error))
        try:
            build_receipt(control, {"verdict": "FAIL"}, dry_run=False)
            check("red/no-receipt-on-fail", False, "receipt built for FAIL")
        except OracleError:
            check("red/no-receipt-on-fail", True)
        # Unreadable evidence yields an all-red verdict, never an oracle crash.
        empty = tmp_path / "empty"
        empty.mkdir()
        empty_verdict = evaluate(empty)
        check("red/evidence-load-fails-verdict",
              empty_verdict["verdict"] == "FAIL"
              and all(not gate["pass"] for gate in empty_verdict["gates"].values()),
              json.dumps(empty_verdict["gates"]))
    if failures:
        print(f"self-test: {len(failures)} failing legs: {', '.join(failures)}",
              file=sys.stderr)
        return 1
    print("self-test: all legs green", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
