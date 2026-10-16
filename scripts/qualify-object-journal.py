#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-journal proof qualification oracle (H8 slice E, unprivileged part).

Compares observer output against the READY/GO controlled provider ledger:
every API invocation and terminal, every journal record counted separately
from API calls, the bootstrap witness, loss markers and a private-key
privacy scan. Drives a provider child through READY validation, GO release
and an owned-child deadline. The ledger file is bound once per run and
every comparison checks the observed output against those exact bytes;
--run binds output freshness to the current run (a nonce the child must
echo; pre-existing or foreign output fails) and verifies execution from
controller-observed delivery timing — the child streams one progress line
per observation on stdout, timestamped here at delivery and ACKed back so
controller delay can only spread arrivals, never compress them — never
child timestamps; total child lifetime never substitutes for paced
delivery; an empty observation set always fails. A plain --run is a
fixture pacing check (mechanics only, never a profile PASS);
--run --qualify-profile additionally requires the profile's full
rate*duration workload population delivered across its full duration
window, both controller-observed.

Live BPF measurements stay UNRUN: this round executes only --plan-only,
--check and --run against the repository stub provider. A privileged
root lane must authorize and witness any run with a real observer.
Exit codes: 0 pass, 1 oracle rejection, 2 usage, 3 harness failure."""
import argparse
import hashlib
import json
import os
import secrets
import selectors
import subprocess
import sys
import time
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
PROGRESS_FLOOD_CAP = 65536


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


def well_formed_profile(profile):
    return (
        isinstance(profile, dict)
        and type(profile.get("rate")) is int
        and profile["rate"] > 0
        and type(profile.get("duration")) is int
        and profile["duration"] > 0
    )


def check_pace_measured(reasons, observed, rate, duration, measured, arrivals, qualified):
    """Verify EXECUTION from controller-observed delivery timing: every
    observation must arrive as a progress line on the child's stdout
    (timestamped here at delivery, never from child stamps), the streamed
    population must equal the file's observations exactly, and every
    consecutive inter-arrival gap must meet the paced floor (half the
    nominal gap, absorbing scheduling jitter while catching bursty
    delivery). The driver ACKs each line, so controller-side delay can
    only spread arrivals, never compress them: a sub-floor gap proves
    bursty delivery. Total child lifetime never substitutes for paced
    delivery — but the run must still fit its duration budget plus
    dump/exit slack. Child profile and stamp claims are ignored here:
    measurement decides.

    A fixture run (qualified=False) checks pacing MECHANICS only; it
    never qualifies a profile, whatever its rate/duration budget. A
    qualified run (qualified=True) additionally requires the profile's
    full workload population delivered across its full window, both
    controller-observed: exactly rate*duration progress deliveries
    (counts do not jitter) spanning at least three quarters of the
    duration (scheduling slack only compresses the edges). A short
    replay at the right rate fails here, never a profile PASS."""
    calls = observed.get("invocations", [])
    records = observed.get("records", [])
    population = len(calls) + len(records)
    if population == 0:
        # No observations at all: the empty-observation rule owns this.
        return
    progress = []
    for line, stamp_ns in arrivals:
        try:
            document = json.loads(line)
        except ValueError:
            reasons.append(
                f"STREAM_MALFORMED: progress line {len(progress) + 1} is not JSON"
            )
            return
        if not isinstance(document, dict):
            reasons.append(
                f"STREAM_MALFORMED: progress line {len(progress) + 1} is not an object"
            )
            return
        kind = document.get("progress")
        if kind == "call" and type(document.get("seq")) is int:
            progress.append(("call", document["seq"], stamp_ns))
        elif kind == "record" and type(document.get("ordinal")) is int:
            progress.append(("record", document["ordinal"], stamp_ns))
        else:
            reasons.append(
                f"STREAM_MALFORMED: progress line {len(progress) + 1} "
                "names no call/record observation"
            )
            return
    streamed_calls = sorted(
        (identity for kind, identity, _ in progress if kind == "call"), key=repr
    )
    streamed_records = sorted(
        (identity for kind, identity, _ in progress if kind == "record"), key=repr
    )
    file_calls = sorted(
        (call.get("seq") for call in calls if isinstance(call, dict)), key=repr
    )
    file_records = sorted(
        (record.get("ordinal") for record in records if isinstance(record, dict)),
        key=repr,
    )
    if streamed_calls != file_calls or streamed_records != file_records:
        reasons.append(
            f"STREAM_POPULATION_MISMATCH: streamed {len(progress)} progress "
            f"observations, file holds {population} (calls "
            f"{len(streamed_calls)}/{len(file_calls)}, records "
            f"{len(streamed_records)}/{len(file_records)})"
        )
        return
    floor = 1_000_000_000 // rate // 2
    for earlier, later in zip(progress, progress[1:]):
        gap = later[2] - earlier[2]
        if gap < floor:
            reasons.append(
                f"PACING_TOO_FAST: controller-observed inter-arrival {gap}ns "
                f"below floor {floor}ns at {rate}/s"
            )
            break
    budget = duration + max(10.0, 0.25 * duration)
    if measured > budget:
        reasons.append(
            f"PACING_SPAN_EXCEEDED: controller measured {measured:.3f}s over "
            f"{duration}s (budget {budget:.3f}s)"
        )
    if not qualified:
        return
    expected = rate * duration
    if len(progress) != expected:
        reasons.append(
            f"PROFILE_POPULATION_MISMATCH: controller observed {len(progress)} "
            f"progress deliveries, the {rate}/s {duration}s profile needs {expected}"
        )
    stamps = [stamp for _, _, stamp in progress]
    span = max(stamps) - min(stamps) if len(stamps) >= 2 else 0
    window = duration * 750_000_000
    if span < window:
        reasons.append(
            f"PROFILE_WINDOW_SHORT: controller-observed delivery window "
            f"{span / 1_000_000_000:.3f}s under {duration}s "
            f"(needs {window / 1_000_000_000:.3f}s)"
        )


def check_pace(reasons, observed):
    """Standalone (--check) stamp self-consistency: when the file carries
    a well-formed profile, every observation carries its stamp,
    consecutive stamps respect the rate floor, and the stamp span fits
    the duration. This checks the FILE's internal consistency only; it
    proves nothing about execution. --run never calls this: execution
    pace there is controller-measured (see check_pace_measured), and
    child profile/stamp claims are untrusted."""
    profile = observed.get("profile")
    if profile is None:
        return
    if not well_formed_profile(profile):
        reasons.append("PACING_INCOMPLETE: observed profile is malformed")
        return
    rate, duration = profile["rate"], profile["duration"]
    stamps = []
    for call in observed.get("invocations", []):
        stamp = call.get("observed_at") if isinstance(call, dict) else None
        if type(stamp) is not int:
            reasons.append("PACING_INCOMPLETE: an invocation lacks its stamp")
            return
        stamps.append(("call", stamp))
    for record in observed.get("records", []):
        stamp = record.get("observed_at") if isinstance(record, dict) else None
        if type(stamp) is not int:
            reasons.append("PACING_INCOMPLETE: a journal record lacks its stamp")
            return
        stamps.append(("record", stamp))
    if not stamps:
        # No observations at all: the empty-observation rule owns this.
        return
    floor = 1_000_000_000 // rate // 2
    call_stamps = [stamp for kind, stamp in stamps if kind == "call"]
    record_stamps = [stamp for kind, stamp in stamps if kind == "record"]
    for series in (call_stamps, record_stamps):
        for earlier, later in zip(series, series[1:]):
            if later - earlier < floor:
                reasons.append(
                    f"PACING_TOO_FAST: stamps {later - earlier}ns apart "
                    f"at {rate}/s (floor {floor}ns)"
                )
                break
    span = max(stamp for _, stamp in stamps) - min(stamp for _, stamp in stamps)
    if span > duration * 1_000_000_000:
        reasons.append(
            f"PACING_SPAN_EXCEEDED: observed span {span}ns over {duration}s"
        )


def compare(observed, ledger, observed_raw, ledger_raw, run=None):
    """The rejection rules. Returns a list of FAIL reason tags (empty passes).

    `ledger_raw` is the exact frozen bytes the comparison binds to: the
    observed output must carry their digest, so output produced against
    any other ledger fails here. `run` is None for a standalone
    comparison, or a (rate, duration, measured, token, arrivals,
    qualified) tuple for a driven run: the output must echo this run's
    nonce (freshness binds to the current invocation; pre-existing or
    foreign output fails), and pace is controller-measured from the
    streamed progress `arrivals` (line text plus delivery timestamp),
    never from child timestamps. `qualified` selects a qualified
    profile run (full population across the full window) over a
    fixture pacing check (mechanics only)."""
    reasons = []
    if not isinstance(observed, dict) or observed.get("schema") != LEDGER_SCHEMA:
        return ["SCHEMA_MISMATCH: observed schema is not " + LEDGER_SCHEMA]
    if run is not None and observed.get("run_token") != run[3]:
        reasons.append(
            "RUN_TOKEN_MISMATCH: observed output does not echo this run's nonce"
        )
    if observed.get("ledger_digest") != hashlib.sha256(ledger_raw).hexdigest():
        reasons.append("LEDGER_UNBOUND: observed output was not produced against this ledger")
    want_bootstrap = ledger.get("bootstrap") or {}
    got_bootstrap = observed.get("bootstrap") or {}
    if got_bootstrap.get("witness") != want_bootstrap.get("witness") or got_bootstrap.get(
        "cut"
    ) != want_bootstrap.get("cut"):
        reasons.append("BOOTSTRAP_MISMATCH: witness or cut differs from the ledger")
        witness = got_bootstrap.get("witness")
        if witness not in WITNESSES:
            reasons.append(f"BOOTSTRAP_UNPROVEN: witness {witness!r} is not genuine")
    want_calls = ledger.get("invocations", [])
    got_calls = observed.get("invocations", [])
    want_records = ledger.get("records", [])
    got_records = observed.get("records", [])
    if not got_calls or not got_records:
        reasons.append(
            "EMPTY_OBSERVATION_SET: observed output holds "
            f"{len(got_calls)} calls and {len(got_records)} journal records"
        )
    if len(got_calls) != len(want_calls):
        reasons.append(
            f"INVOCATION_COUNT_MISMATCH: observed {len(got_calls)} calls, "
            f"ledger holds {len(want_calls)}"
        )
    # Duplicate observed identities reject explicitly (equality-based:
    # unhashable hostile fields still compare, never crash the oracle).
    seen_seqs = []
    for call in got_calls:
        seq = call.get("seq") if isinstance(call, dict) else None
        if seq in seen_seqs:
            reasons.append(
                f"DUPLICATE_INVOCATION: observed invocations repeat seq {seq!r}"
            )
            break
        seen_seqs.append(seq)
    seen_ordinals = []
    for record in got_records:
        ordinal = record.get("ordinal") if isinstance(record, dict) else None
        if ordinal in seen_ordinals:
            reasons.append(
                f"DUPLICATE_RECORD: observed journal records repeat ordinal {ordinal!r}"
            )
            break
        seen_ordinals.append(ordinal)
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
    if run is None:
        check_pace(reasons, observed)
    else:
        check_pace_measured(reasons, observed, run[0], run[1], run[2], run[4], run[5])
    return reasons


def check_bound(observed_path, ledger_raw, run=None, missing_is_stale=False):
    """Compare one observed file against already-bound ledger bytes. A
    driven run passes missing_is_stale: its output file was deleted
    before the child spawned, so a missing/unreadable file after a
    clean child exit means the child produced no fresh output — a
    qualification FAIL, never an inheritance of stale bytes."""
    observed, error = load_json(observed_path, "observed output")
    if error:
        if missing_is_stale:
            print("FAIL object-journal qualification")
            print(f"FAIL STALE_OUTPUT: no fresh output from this run ({error})")
            return 1
        return fail(error)
    try:
        ledger = json.loads(ledger_raw.decode("utf-8"))
    except ValueError as error:
        return fail(f"cannot parse ledger: {error}")
    raw = Path(observed_path).read_text(encoding="utf-8", errors="replace")
    reasons = compare(
        observed, ledger, raw, ledger_raw, run,
    )
    if reasons:
        print("FAIL object-journal qualification")
        for reason in reasons:
            print(f"FAIL {reason}")
        return 1
    print("PASS object-journal qualification: ledger and observed output agree")
    return 0


def run_check(args):
    try:
        ledger_raw = Path(args.ledger).read_bytes()
    except OSError as error:
        return fail(f"cannot read ledger {args.ledger}: {error}")
    return check_bound(args.observed, ledger_raw)


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


def validate_ready(line, child_pid, abi, ledger_raw):
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
    if document["ledger_digest"] != hashlib.sha256(ledger_raw).hexdigest():
        return None, "READY ledger digest does not match the frozen ledger"
    return document, None


def run_profile(args):
    if args.profile is not None and args.profile not in PROFILES:
        return fail(f"unknown profile {args.profile!r} (want one of {sorted(PROFILES)})")
    if args.rate is not None:
        rate = positive_int(args.rate, "rate")
    elif args.profile is not None:
        rate = PROFILES[args.profile]
    else:
        rate = PROFILES["1k"]
    duration = positive_int(args.duration, "duration") if args.duration is not None else 60
    deadline = positive_int(args.deadline_seconds, "deadline")
    if rate is None:
        return fail("rate must be a positive integer")
    if duration is None:
        return fail("duration must be a positive integer")
    if deadline is None:
        return fail("deadline must be a positive integer of seconds")
    try:
        ledger_raw = Path(args.ledger).read_bytes()
    except OSError as error:
        print(f"harness: cannot bind ledger {args.ledger}: {error}", file=sys.stderr)
        return 3
    # Freshness binds to THIS invocation: a random nonce the child must
    # echo, plus deletion of any pre-existing output before the spawn,
    # so stale bytes can neither pass nor be inherited.
    run_token = secrets.token_hex(16)
    try:
        Path(args.out).unlink()
    except OSError:
        pass
    # The requested pace and nonce ride along last so smuggled
    # provider-side --rate/--duration/--run-token cannot quiet the
    # run's profile: later argparse options win, and the comparison
    # verifies the echoed nonce plus controller-measured execution.
    command = [
        args.provider,
        *(args.provider_arg or []),
        "--rate",
        str(rate),
        "--duration",
        str(duration),
        "--run-token",
        run_token,
    ]
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
    # One nonblocking line pump over the child's stdout serves READY and
    # the paced progress stream: each complete line is timestamped
    # (monotonic_ns) as its newline arrives and ACKed back on stdin, so
    # an honest child paces itself against the controller's reads —
    # controller-side delay can only spread arrivals, never compress
    # them. Bytes the child sent before GO (hostile pre-printing) stay
    # buffered and timestamp late, clustering correctly as unpaced.
    fd = child.stdout.fileno()
    os.set_blocking(fd, False)
    sel = selectors.DefaultSelector()
    sel.register(fd, selectors.EVENT_READ)
    buf = bytearray()

    def read_chunk(deadline_at):
        """One select-bounded nonblocking read. Returns b"" on EOF and
        raises TimeoutError on deadline."""
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        if not sel.select(timeout=remaining):
            raise TimeoutError
        try:
            return os.read(fd, 65536)
        except BlockingIOError:
            return None

    def next_line(deadline_at):
        """Next complete stdout line, or None on EOF. Raises TimeoutError
        on deadline."""
        nonlocal buf
        while True:
            newline = buf.find(b"\n")
            if newline >= 0:
                raw_line = bytes(buf[:newline])
                del buf[: newline + 1]
                return raw_line.decode("utf-8", errors="replace")
            chunk = read_chunk(deadline_at)
            if chunk is None:
                continue
            if chunk == b"":
                return None
            buf += chunk

    try:
        ready = next_line(time.monotonic() + min(READY_SECONDS, deadline))
    except TimeoutError:
        ready = None
    if ready is None:
        child.kill()
        print("harness: READY timeout", file=sys.stderr)
        return 3
    _, error = validate_ready(ready, child.pid, args.abi, ledger_raw)
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
    go_at = time.monotonic()
    deadline_at = go_at + deadline
    arrivals = []
    ack_dead = False
    flooded = False
    while True:
        if len(arrivals) >= PROGRESS_FLOOD_CAP:
            flooded = True
            break
        try:
            line = next_line(deadline_at)
        except TimeoutError:
            child.kill()
            child.communicate()
            print(f"harness: provider deadline after {deadline}s", file=sys.stderr)
            return 3
        if line is None:
            break
        arrivals.append((line, time.monotonic_ns()))
        if not ack_dead:
            try:
                child.stdin.write("ACK\n")
                child.stdin.flush()
            except (BrokenPipeError, OSError):
                # The child stopped reading ACKs (or exited): keep
                # draining its stdout — lines already in flight still
                # count — but stop writing.
                ack_dead = True
    if flooded:
        child.kill()
        child.communicate()
        print(
            f"harness: progress flood over {PROGRESS_FLOOD_CAP} lines", file=sys.stderr
        )
        return 3
    if buf:
        # A dangling fragment without its newline is malformed progress,
        # never a silently dropped observation.
        arrivals.append((bytes(buf).decode("utf-8", errors="replace"), time.monotonic_ns()))
    os.set_blocking(fd, True)
    try:
        _, stderr = child.communicate(timeout=max(0.0, deadline_at - time.monotonic()))
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        print(f"harness: provider deadline after {deadline}s", file=sys.stderr)
        return 3
    measured = time.monotonic() - go_at
    if child.returncode != 0:
        print(f"harness: provider exited {child.returncode}: {stderr.strip()}", file=sys.stderr)
        return 3
    qualified = bool(args.qualify_profile)
    outcome = check_bound(
        args.out, ledger_raw, (rate, duration, measured, run_token, arrivals, qualified), True
    )
    if outcome == 0:
        # The completion line reports a PASS, never a finished-but-failed
        # run: fixture passes say fixture (never profile), qualified
        # passes say profile.
        if qualified:
            print(
                f"profile complete: rate={rate}/s duration={duration}s "
                f"measured={measured:.3f}s provider={args.provider}"
            )
        else:
            print(
                f"fixture pacing check complete (not a qualified profile): rate={rate}/s "
                f"duration={duration}s measured={measured:.3f}s provider={args.provider}"
            )
    return outcome


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
    parser.add_argument(
        "--qualify-profile",
        action="store_true",
        help="qualify the profile: require the full rate*duration workload "
        "population delivered across the full duration window, both "
        "controller-observed (without it the run is a fixture pacing "
        "check only, never a profile PASS)",
    )
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
