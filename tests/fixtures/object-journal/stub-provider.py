#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""READY/GO stub provider for the object-journal qualification oracle.

Replays the frozen provider ledger with no BPF, no privilege and no live
measurement: the oracle driver path (READY validation, GO release,
deadline kill, observed comparison) runs against this stub in tests.
--mutate injects exactly one scripted fault so the oracle's rejection
cells stay honest; --stall holds the run past the driver's deadline;
--ready garbage breaks the READY document on purpose."""
import argparse
import hashlib
import json
import os
import sys
import time

READY_SCHEMA = "p11scope/object-journal-ready/v1"
MUTATIONS = ("fabricate-bootstrap", "drop-begin", "erase-loss", "leak-key")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="stub journal provider")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--mutate", choices=MUTATIONS, default=None)
    parser.add_argument("--stall", type=int, default=0)
    parser.add_argument("--ready", choices=("good", "garbage"), default="good")
    return parser.parse_args(argv)


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
    observed = json.loads(json.dumps(ledger))
    observed["key_material"] = None
    if args.mutate:
        apply_mutation(observed, args.mutate)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(observed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
