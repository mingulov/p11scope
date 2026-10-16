#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-journal proof qualification oracle (H8 slice E, unprivileged part).

Compares observer output against the READY/GO controlled provider ledger:
every API invocation and terminal, every journal record counted separately
from API calls, the bootstrap witness, loss markers and a private-key
privacy scan. Drives a provider child through READY validation, GO release
and an owned-child deadline.

Live BPF measurements stay UNRUN: this round executes only --plan-only,
--check and --run against the repository stub provider. A privileged
root lane must authorize and witness any run with a real observer.
Exit codes: 0 pass, 1 oracle rejection, 2 usage, 3 harness failure."""
import argparse
import hashlib
import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

LEDGER_SCHEMA = "p11scope/object-journal-ledger/v1"
READY_SCHEMA = "p11scope/object-journal-ready/v1"
READY_FIELDS = frozenset(("schema", "provider", "pid", "abi", "ledger_digest"))
WITNESSES = ("exec-marker", "absence-appearance")
PROFILES = {"1k": 1000, "10k": 10000, "100k": 100000}
PROFILE_SECONDS = 60
DEADLINE_SECONDS = 90
READY_SECONDS = 10
KEY_SENTINEL = "PRIVATE-KEY-MATERIAL"


def fail(message):
    print(message, file=sys.stderr)
    return 2


def load_json(path, what):
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        return None, f"cannot read {what} {path}: {error}"
    try:
        return json.loads(raw.decode("utf-8")), None
    except ValueError as error:
        return None, f"cannot parse {what} {path}: {error}"


def is_uint(value):
    return type(value) is int and value >= 0


def compare(observed, ledger, observed_raw):
    """The rejection rules. Returns a list of FAIL reason tags (empty passes)."""
    reasons = []
    if not isinstance(observed, dict) or observed.get("schema") != LEDGER_SCHEMA:
        return ["SCHEMA_MISMATCH: observed schema is not " + LEDGER_SCHEMA]
    if observed.get("bootstrap") != ledger.get("bootstrap"):
        reasons.append("BOOTSTRAP_MISMATCH: witness or cut differs from the ledger")
        witness = (observed.get("bootstrap") or {}).get("witness")
        if witness not in WITNESSES:
            reasons.append(f"BOOTSTRAP_UNPROVEN: witness {witness!r} is not genuine")
    want_calls = ledger.get("invocations", [])
    got_calls = observed.get("invocations", [])
    if len(got_calls) != len(want_calls):
        reasons.append(
            f"INVOCATION_COUNT_MISMATCH: observed {len(got_calls)} calls, "
            f"ledger holds {len(want_calls)}"
        )
    for want, got in zip(want_calls, got_calls):
        if not isinstance(got, dict):
            reasons.append(f"INVOCATION_MISMATCH seq={want.get('seq')}: not an object")
            continue
        for field in ("seq", "function", "rv", "terminal"):
            if got.get(field) != want.get(field):
                reasons.append(
                    f"INVOCATION_MISMATCH seq={want.get('seq')}: {field} "
                    f"{got.get(field)!r} != {want.get(field)!r}"
                )
        if sorted(got.get("effects", [])) != sorted(want.get("effects", [])):
            reasons.append(f"INVOCATION_MISMATCH seq={want.get('seq')}: effects differ")
        if got.get("loss") != want.get("loss"):
            reasons.append(
                f"INVOCATION_MISMATCH seq={want.get('seq')}: loss marker "
                f"{got.get('loss')!r} != {want.get('loss')!r}"
            )
    want_records = ledger.get("records", [])
    got_records = observed.get("records", [])
    if len(got_records) != len(want_records):
        reasons.append(
            f"JOURNAL_COUNT_MISMATCH: observed {len(got_records)} journal records, "
            f"ledger holds {len(want_records)} (counted separately from API calls)"
        )
    for want, got in zip(want_records, got_records):
        if not isinstance(got, dict):
            reasons.append(f"RECORD_MISMATCH ordinal={want.get('ordinal')}: not an object")
            continue
        for field in ("ordinal", "kind", "seq", "thread", "sequence"):
            if got.get(field) != want.get(field):
                reasons.append(
                    f"RECORD_MISMATCH ordinal={want.get('ordinal')}: {field} "
                    f"{got.get(field)!r} != {want.get(field)!r}"
                )
    counts = observed.get("counts", {})
    if counts.get("api_calls") != len(want_calls) or counts.get("journal_records") != len(
        want_records
    ):
        reasons.append(f"COUNT_MISMATCH: pinned counts {counts!r} disagree with the ledger")
    if observed.get("key_material") is not None:
        reasons.append("KEY_MATERIAL_LEAK: observed output carries key material")
    if KEY_SENTINEL in observed_raw:
        reasons.append("KEY_MATERIAL_LEAK: observed bytes contain the key sentinel")
    return reasons


def run_check(args):
    observed, error = load_json(args.observed, "observed output")
    if error:
        return fail(error)
    ledger, error = load_json(args.ledger, "ledger")
    if error:
        return fail(error)
    raw = Path(args.observed).read_text(encoding="utf-8", errors="replace")
    reasons = compare(observed, ledger, raw)
    if reasons:
        print("FAIL object-journal qualification")
        for reason in reasons:
            print(f"FAIL {reason}")
        return 1
    print("PASS object-journal qualification: ledger and observed output agree")
    return 0


def run_plan(args):
    _ = args
    print("object-journal qualification plan (live measurements UNRUN)")
    print(f"profiles: {', '.join(sorted(PROFILES))} at {PROFILE_SECONDS}s each after READY/GO")
    print(f"owned-child deadline: {DEADLINE_SECONDS}s; never warm away reported-phase losses")
    print("ledger: tests/fixtures/object-journal/provider-ledger.json")
    print("cells: creation, use, destruction, long-open, success/error terminals,")
    print("  fabricated-bootstrap / removed-BEGIN / erased-loss / key-leak rejections")
    return 0


def positive_int(text, name):
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def validate_ready(line, child_pid, abi, ledger_path):
    try:
        document = json.loads(line)
    except ValueError:
        return None, "READY is not JSON"
    if not isinstance(document, dict) or set(document) != set(READY_FIELDS):
        return None, f"READY fields must be exactly {sorted(READY_FIELDS)}"
    if document["schema"] != READY_SCHEMA:
        return None, "READY schema mismatch"
    if document["provider"] in (None, ""):
        return None, "READY names no provider"
    if document["pid"] != child_pid:
        return None, f"READY pid {document['pid']!r} is not the owned child {child_pid}"
    if abi is not None and document["abi"] != abi:
        return None, f"READY abi {document['abi']!r} != {abi!r}"
    try:
        digest = hashlib.sha256(Path(ledger_path).read_bytes()).hexdigest()
    except OSError as error:
        return None, f"cannot digest ledger: {error}"
    if document["ledger_digest"] != digest:
        return None, "READY ledger digest does not match the frozen ledger"
    return document, None


def run_profile(args):
    if args.profile is not None and args.profile not in PROFILES:
        return fail(f"unknown profile {args.profile!r} (want one of {sorted(PROFILES)})")
    rate = positive_int(args.rate, "rate") if args.rate is not None else PROFILES["1k"]
    duration = positive_int(args.duration, "duration") if args.duration is not None else 60
    deadline = positive_int(args.deadline_seconds, "deadline")
    if rate is None:
        return fail("rate must be a positive integer")
    if duration is None:
        return fail("duration must be a positive integer")
    if deadline is None:
        return fail("deadline must be a positive integer of seconds")
    command = [args.provider, *(args.provider_arg or [])]
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        print(f"harness: cannot spawn provider: {error}", file=sys.stderr)
        return 3
    assert child.stdout is not None and child.stdin is not None
    lines: queue.Queue = queue.Queue()

    def pump():
        try:
            lines.put(child.stdout.readline())
        except Exception:
            lines.put("")

    watcher = threading.Thread(target=pump, daemon=True)
    watcher.start()
    try:
        ready = lines.get(timeout=min(READY_SECONDS, deadline))
    except queue.Empty:
        ready = ""
    if not ready:
        child.kill()
        print("harness: READY timeout", file=sys.stderr)
        return 3
    _, error = validate_ready(ready, child.pid, args.abi, args.ledger)
    if error:
        child.kill()
        print(f"harness: invalid READY: {error}", file=sys.stderr)
        return 3
    try:
        child.stdin.write("GO\n")
        child.stdin.flush()
    except BrokenPipeError:
        print("harness: provider exited before GO", file=sys.stderr)
        return 3
    try:
        _, stderr = child.communicate(timeout=deadline)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        print(f"harness: provider deadline after {deadline}s", file=sys.stderr)
        return 3
    if child.returncode != 0:
        print(f"harness: provider exited {child.returncode}: {stderr.strip()}", file=sys.stderr)
        return 3
    print(f"profile complete: rate={rate}/s duration={duration}s provider={args.provider}")
    check_args = argparse.Namespace(observed=args.out, ledger=args.ledger)
    return run_check(check_args)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="object-journal qualification oracle")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--observed", default=None)
    parser.add_argument("--ledger", default=None)
    parser.add_argument("--provider", default=None)
    parser.add_argument("--provider-arg", action="append", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--rate", default=None)
    parser.add_argument("--duration", default=None)
    parser.add_argument("--deadline-seconds", default=str(DEADLINE_SECONDS))
    parser.add_argument("--abi", default=None)
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.plan_only:
        return run_plan(args)
    if args.check:
        if not args.observed or not args.ledger:
            return fail("--check requires --observed and --ledger")
        return run_check(args)
    if not args.provider or not args.ledger or not args.out:
        return fail("--run requires --provider, --ledger and --out")
    return run_profile(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
