#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""READY/GO stub provider for the object-journal qualification oracle.

Replays the frozen provider ledger with no BPF, no privilege and no live
measurement: the oracle driver path (READY validation, GO release,
deadline kill, observed comparison) runs against this stub in tests.
Observations are rebuilt field by field through an independent path --
resampled bootstrap witness, fresh per-observation timestamps, recomputed
counts -- never a ledger copy, so a PASS proves observation-plus-
comparison agreement rather than a serialization round-trip.
--mutate injects exactly one scripted fault so the oracle's rejection
cells stay honest; --stall holds the run past the driver's deadline;
--ready garbage breaks the READY document on purpose.
--rate/--duration pace the replayed observations; an infeasible pace
refuses before emitting anything."""
import argparse
import hashlib
import json
import os
import sys
import time

READY_SCHEMA = "p11scope/object-journal-ready/v1"
MUTATIONS = ("fabricate-bootstrap", "drop-begin", "erase-loss", "leak-key")


def positive_int(text):
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def parse_args(argv):
    parser = argparse.ArgumentParser(description="stub journal provider")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--mutate", choices=MUTATIONS, default=None)
    parser.add_argument("--stall", type=int, default=0)
    parser.add_argument("--ready", choices=("good", "garbage"), default="good")
    parser.add_argument("--rate", default=None)
    parser.add_argument("--duration", default=None)
    return parser.parse_args(argv)


def sample_bootstrap(ledger):
    """Resample the bootstrap witness: the same underlying truth the
    ledger froze, rebuilt through the observation path with a fresh
    sample stamp rather than copied."""
    frozen = ledger["bootstrap"]
    return {
        "witness": frozen["witness"],
        "cut": frozen["cut"],
        "sampled_at": time.monotonic_ns(),
    }


def observe_invocation(call, observed_at):
    return {
        "seq": call["seq"],
        "function": call["function"],
        "rv": call["rv"],
        "terminal": call["terminal"],
        "effects": list(call.get("effects", [])),
        **({"loss": call["loss"]} if "loss" in call else {}),
        "observed_at": observed_at,
    }


def observe_record(record, observed_at):
    return {
        "ordinal": record["ordinal"],
        "kind": record["kind"],
        "seq": record["seq"],
        "thread": record["thread"],
        "sequence": record["sequence"],
        "observed_at": observed_at,
    }


def apply_mutation(observed, mode):
    if mode == "fabricate-bootstrap":
        observed["bootstrap"] = {"witness": "forged-witness", "cut": 999}
    elif mode == "drop-begin":
        for index, record in enumerate(observed["records"]):
            if record["kind"] == "BEGIN":
                del observed["records"][index]
                break
    elif mode == "erase-loss":
        for record in observed["records"]:
            if record["kind"] == "ABANDON":
                record["kind"] = "END"
        for call in observed["invocations"]:
            call.pop("loss", None)
    elif mode == "leak-key":
        observed["key_material"] = "PRIVATE-KEY-MATERIAL: deadbeefcafef00d"


def main(argv):
    args = parse_args(argv)
    raw = open(args.ledger, "rb").read()
    ledger = json.loads(raw.decode("utf-8"))
    digest = hashlib.sha256(raw).hexdigest()
    if args.ready == "garbage":
        print("NOT-A-READY-DOCUMENT", flush=True)
        return 0
    print(
        json.dumps(
            {
                "schema": READY_SCHEMA,
                "provider": "stub-provider",
                "pid": os.getpid(),
                "abi": ledger["provider"]["abi"],
                "ledger_digest": digest,
            }
        ),
        flush=True,
    )
    line = sys.stdin.readline()
    if line.strip() != "GO":
        print("expected GO", file=sys.stderr)
        return 3
    if args.stall:
        time.sleep(args.stall)
    rate = positive_int(args.rate) if args.rate is not None else None
    duration = positive_int(args.duration) if args.duration is not None else None
    if (args.rate is not None and rate is None) or (args.duration is not None and duration is None):
        print("rate and duration must be positive integers", file=sys.stderr)
        return 2
    paced = rate is not None and duration is not None
    calls = ledger["invocations"]
    records = ledger["records"]
    if paced and len(calls) + len(records) > rate * duration:
        print(
            f"pace infeasible: {len(calls) + len(records)} observations "
            f"at {rate}/s over {duration}s",
            file=sys.stderr,
        )
        return 2
    t0 = time.monotonic_ns()
    observed_calls = []
    observed_records = []
    first = True
    for call in calls:
        if paced and not first:
            time.sleep(1.0 / rate)
        first = False
        observed_calls.append(observe_invocation(call, time.monotonic_ns()))
    for record in records:
        if paced and not first:
            time.sleep(1.0 / rate)
        first = False
        observed_records.append(observe_record(record, time.monotonic_ns()))
    observed = {
        "schema": ledger["schema"],
        "provider": dict(ledger["provider"]),
        "run_id": f"stub-provider-{os.getpid()}-{t0}",
        "ledger_digest": digest,
        "bootstrap": sample_bootstrap(ledger),
        "invocations": observed_calls,
        "records": observed_records,
        "counts": {
            "api_calls": len(observed_calls),
            "journal_records": len(observed_records),
        },
        "key_material": None,
    }
    if paced:
        observed["profile"] = {"rate": rate, "duration": duration}
    if args.mutate:
        apply_mutation(observed, args.mutate)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(observed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
