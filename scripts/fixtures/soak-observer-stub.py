#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Dry-run stand-in for the installed observer in soak trials.

Speaks the observer's profile argv shape (`profile --pid PID --manifest
PATH --mode metrics --duration S -o OUT`), prints the discovery and
capturing readiness lines the attach gate waits for, sleeps the full
duration, then writes a v3-metrics-shaped report. It observes nothing:
with --loopback-log it echoes the workload's own TRUTH line back as the
observed counts (labeled dry-run-loopback in the report) so the
truth-join, record, verdict and receipt plumbing runs end to end on real
timestamps. Without it the report carries zero observed calls and the
loss gate honestly fails.

Corruption seams exist only to prove the gates fail: --loopback-corrupt
drops a loss counter or skews a count, --exit-code changes the exit
status after the report is written, --no-report skips the report so the
runner must refuse before the oracle. The soak runner passes these
through --stub-arg and records them verbatim; live mode never invokes
this stub.

Stdlib only. Unprivileged; scripts/fixtures/ is outside the hosted lane
derivations.
"""
import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path


def load_counters():
    """Import the loss-counter universe so the stub report cannot drift."""
    oracle = Path(__file__).resolve().parents[1] / "check-capture-evidence.py"
    spec = importlib.util.spec_from_file_location("check_capture_evidence", oracle)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    names = tuple(module.COUNTERS)
    if not names or not all(isinstance(name, str) for name in names):
        raise ValueError("counter universe is empty or malformed")
    return names


def read_truth(path, deadline_s=30.0):
    """Wait briefly for the workload TRUTH line; missing truth is honest zero."""
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError:
            time.sleep(0.2)
            continue
        for line in text.splitlines():
            if line.startswith("TRUTH "):
                return json.loads(line[len("TRUTH "):]), True
        time.sleep(0.2)
    return {}, False


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["profile"])
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--mode", choices=["metrics"], required=True)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--loopback-log", default=None)
    parser.add_argument("--loopback-corrupt",
                        choices=["drop-counter", "wrong-count"], default=None)
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--attach-delay", type=float, default=0.5)
    args = parser.parse_args(argv)
    if args.duration <= 0 or args.attach_delay < 0:
        print("stub: nonpositive duration or negative attach delay", file=sys.stderr)
        return 2
    try:
        with open(f"/proc/{args.pid}/stat", encoding="utf-8") as handle:
            handle.read(1)
    except OSError:
        print(f"stub: target pid {args.pid} is not alive", file=sys.stderr)
        return 2
    if not Path(args.manifest).is_file():
        print(f"stub: manifest {args.manifest} is missing", file=sys.stderr)
        return 2
    print("p11scope: discovery: 1 module(s), 2 attach slot(s), scan 1ms, "
          "conflicts 0, uncorroborated 0", file=sys.stderr, flush=True)
    time.sleep(args.attach_delay)
    print("p11scope: capturing: 2 probe(s) attached; stop with Ctrl-C",
          file=sys.stderr, flush=True)
    # Sleep the full duration in slices so a harness interrupt lands fast.
    deadline = time.monotonic() + args.duration
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 0.5))
    if args.no_report:
        return args.exit_code
    counters = load_counters()
    truth, looped = ({}, False)
    if args.loopback_log is not None:
        truth, looped = read_truth(args.loopback_log)
    if args.loopback_corrupt == "wrong-count" and truth:
        first = sorted(truth)[0]
        truth = dict(truth)
        truth[first] = truth[first] + 1
    evidence = {name: 0 for name in counters}
    if args.loopback_corrupt == "drop-counter":
        evidence.pop("event_loss", None)
    evidence.update({
        "attached_probes": 2,
        "slots": 1,
        "discovery": [],
        "surfaces": [],
        "soak_stub": {
            "mode": "dry-run-loopback" if looped else "dry-run-unobserved",
            "loopback": looped,
            "corrupt": args.loopback_corrupt,
        },
    })
    report = {"schema": "p11scope/observed-profile/v3-metrics",
              "lane": "metrics",
              "capture": {"mode": "metrics", "scope": "pid",
                          "soak_stub": evidence["soak_stub"]},
              "evidence": evidence,
              "functions": [{"names": [name], "calls": count}
                            for name, count in sorted(truth.items())]}
    Path(args.output).write_text(json.dumps(report), encoding="utf-8")
    return args.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
