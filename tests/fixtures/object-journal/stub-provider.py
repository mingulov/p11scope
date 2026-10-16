#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""READY/GO stub provider for the object-journal qualification oracle.

Replays the frozen provider ledger's TRACE (the raw request stream:
one birth probe, call/return pairs, journal record events) with no
BPF, no privilege and no live measurement: the oracle driver path
(READY validation, GO release, deadline kill, observed comparison)
runs against this stub in tests.

Observations are COMPUTED from the trace by this stub, never copied
from the ledger's expected semantic fields (`bootstrap`,
`invocations`, `records`): invocations pair call/return events by
seq, terminals derive from the return rv, loss derives from an
ABANDON scan, record ordinals derive from replay position, and the
bootstrap witness/cut derive from the birth probe. Mutations in the
trace are therefore detectable in the observations, while mutations
of the expected fields alone change nothing here (pinned by test).
--mutate injects exactly one scripted fault into the REPLAYED
observations so the oracle's rejection cells stay honest; --stall
holds the run past the driver's deadline; --ready garbage breaks the
READY document on purpose. --rate/--duration pace the replayed
observations; an infeasible pace refuses before emitting anything.
A paced run also streams one progress line per observation on stdout
(flushed, ACKed by the driver) so the controller measures delivery
timing itself; unpaced runs stay silent after READY.
--run-token (appended by the oracle driver) is echoed so the run
binds this output's freshness to the current invocation."""
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
    parser.add_argument("--run-token", default=None)
    return parser.parse_args(argv)


def sample_bootstrap(probe):
    """Derive the birth observation from the trace's birth probe: an
    empty-mappings probe bracketed by a strictly changed epoch proves
    an absence-appearance birth; a marker reading proves an exec-marker
    birth; anything else is unproven. The cut is the probe's raw
    prior-records counter, not the ledger's expected cut."""
    epoch = probe.get("epoch")
    if (
        isinstance(probe.get("mappings"), list)
        and probe["mappings"] == []
        and isinstance(epoch, list)
        and len(epoch) == 2
        and epoch[0] != epoch[1]
    ):
        witness = "absence-appearance"
    elif probe.get("marker") is not None:
        witness = "exec-marker"
    else:
        witness = "unproven"
    return {
        "witness": witness,
        "cut": probe.get("prior_records", 0),
        "sampled_at": time.monotonic_ns(),
    }


def observe_invocation(call, ret, loss, observed_at):
    """Pair one call/return by seq: the terminal derives from the raw
    return rv, loss from the journal ABANDON scan."""
    observed = {
        "seq": call["seq"],
        "function": call["function"],
        "rv": ret["rv"],
        "terminal": "success" if ret["rv"] == "OK" else "error",
        "effects": list(ret.get("effects", [])),
        "observed_at": observed_at,
    }
    if loss is not None:
        observed["loss"] = loss
    return observed


def observe_record(event, ordinal, observed_at):
    """One journal observation: the ordinal derives from replay
    position, never from an expected field."""
    return {
        "ordinal": ordinal,
        "kind": event["kind"],
        "seq": event["seq"],
        "thread": event["thread"],
        "sequence": event["sequence"],
        "observed_at": observed_at,
    }


def replay_trace(trace):
    """Replay the raw request stream into computed observations. Strict:
    unknown events, missing probes, duplicate call/return sequences,
    unpaired calls and misordered (return-before-call) pairs fail
    closed — identities are never collapsed."""
    if not isinstance(trace, list):
        raise ValueError("trace is not an event list")
    probes = [event for event in trace if event.get("op") == "probe"]
    if len(probes) != 1:
        raise ValueError(f"trace holds {len(probes)} birth probes, want exactly 1")
    calls = {}
    returns = {}
    call_pos = {}
    return_pos = {}
    record_events = []
    for index, event in enumerate(trace):
        op = event.get("op")
        if op == "probe":
            continue
        elif op == "call":
            if event["seq"] in calls:
                raise ValueError(f"duplicate trace call seq {event['seq']!r}")
            calls[event["seq"]] = event
            call_pos[event["seq"]] = index
        elif op == "return":
            if event["seq"] in returns:
                raise ValueError(f"duplicate trace return seq {event['seq']!r}")
            returns[event["seq"]] = event
            return_pos[event["seq"]] = index
        elif op == "record":
            record_events.append(event)
        else:
            raise ValueError(f"unknown trace op {op!r}")
    if set(calls) != set(returns):
        raise ValueError(
            f"unpaired trace calls: calls {sorted(calls)} returns {sorted(returns)}"
        )
    for seq in calls:
        if return_pos[seq] < call_pos[seq]:
            raise ValueError(f"misordered trace pair: return before call for seq {seq!r}")
    abandoned = {
        event["seq"] for event in record_events if event.get("kind") == "ABANDON"
    }
    invocations = [
        (calls[seq], returns[seq], "bounded" if seq in abandoned else None)
        for seq in sorted(calls)
    ]
    return probes[0], invocations, record_events


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
    try:
        probe, paired, record_events = replay_trace(ledger.get("trace"))
    except (ValueError, KeyError, TypeError) as error:
        print(f"trace replay refused: {error}", file=sys.stderr)
        return 2
    paced = rate is not None and duration is not None
    if paced and len(paired) + len(record_events) > rate * duration:
        print(
            f"pace infeasible: {len(paired) + len(record_events)} observations "
            f"at {rate}/s over {duration}s",
            file=sys.stderr,
        )
        return 2
    def announce(document):
        """Stream one paced observation for controller timestamping and
        wait for its ACK: delivery timing is measured by the driver, and
        an ACK-less controller (gone away) ends the run, never hangs it."""
        print(json.dumps(document), flush=True)
        if sys.stdin.readline() == "":
            print("controller went away", file=sys.stderr)
            sys.exit(3)

    t0 = time.monotonic_ns()
    observed_calls = []
    observed_records = []
    first = True
    for call, ret, loss in paired:
        if paced and not first:
            time.sleep(1.0 / rate)
        first = False
        observed_calls.append(observe_invocation(call, ret, loss, time.monotonic_ns()))
        if paced:
            announce({"progress": "call", "seq": call["seq"]})
    for ordinal, event in enumerate(record_events, start=1):
        if paced and not first:
            time.sleep(1.0 / rate)
        first = False
        observed_records.append(observe_record(event, ordinal, time.monotonic_ns()))
        if paced:
            announce({"progress": "record", "ordinal": ordinal})
    observed = {
        "schema": ledger["schema"],
        "provider": dict(ledger["provider"]),
        "run_id": f"stub-provider-{os.getpid()}-{t0}",
        "run_token": args.run_token,
        "ledger_digest": digest,
        "bootstrap": sample_bootstrap(probe),
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
