# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Joint linked-stop cell logs: verdict records in real libtest framing.

Shared by test_joint_stop_verdict.py (the table), test_ci_stop_races.py
(S3) and test_ignored_tests.py (LONG). The cell prints one
`P11SCOPE_STOP_VERDICT=<json>` record built from its case ledger
(src/inventory/joint_stop_races_privileged_tests.rs); the healthy full
matrix record is the shared fixture
tests/fixtures/joint-stop-verdict-qualified.json, which the Rust
twin `stop_verdict_record_matches_the_shared_qualified_fixture`
serializes byte for byte. Every other record here is that fixture
edited the way the ledger would build it.

The framing is the pinned 1.99.1 libtest pretty `--nocapture` output,
threaded (S3's default) and `--test-threads=1` (LONG, where the first
output line is glued to the `test NAME ... ` prefix). A failing cell's
returned error and its backtrace follow the record, as libtest prints
them after the test function returns.
"""

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "joint-stop-verdict-qualified.json"
MARKER = "P11SCOPE_STOP_VERDICT="
CELL = ("inventory::joint_stop_races_privileged_tests::"
        "privileged_joint_stop_after_last_waiter_resolves_publishes_final_lp64")
OFFSETS_MS = (0, 1, 5, 20)
OK_SUMMARY = ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
              "12231 filtered out; finished in 148.83s")
FAILED_SUMMARY = ("test result: FAILED. 0 passed; 1 failed; 0 ignored; "
                  "0 measured; 12231 filtered out; finished in 11.68s")
S1_RECEIPT = "no joint feeds with S1 seal (producers unlinked, zero installs)"
UNATTRIBUTED_RECEIPT = ("no joint feeds without S1 seal (producers linked, "
                        "zero installs unexplained)")
STARVED_RECEIPT = ("no joint feeds from the linked session: the held "
                   "caller's birth receipt was deferred (no_receipt) or "
                   "refused (partition) and no later birth bound")
RECEIPTS = {"s1-precluded": S1_RECEIPT,
            "no-feeds-receipt-starved": STARVED_RECEIPT,
            "no-feeds-unattributed": UNATTRIBUTED_RECEIPT}
LINKED_NO_FEED = ("no-feeds-receipt-starved", "no-feeds-unattributed")
JOIN_QUANTA = 32
JOIN_PASSES = 4  # passes before join quanta 2, 10, 18 and 26
BACKTRACE = [
    "",
    "Stack backtrace:",
    "   0: <anyhow::Error>::msg::<alloc::string::String>",
    "   1: p11scope::inventory::joint_stop_races_privileged_tests::run_stop_offset",
    "             at ./nptl/pthread_create.c:454:8",
]
# Free-text diagnostics the cell prints; the validator never reads them.
PREAMBLE = [
    "JOINT_R16 r16-lane step=started live=1 gated=0 finished=0 ticks=0",
    "JOINT_R16 r16-map round=0 mapped=2/2",
]


def offset_of(k):
    return OFFSETS_MS[k % 4]


def qualified_record():
    with open(FIXTURE, encoding="utf-8") as stream:
        return json.load(stream)


_QUALIFIED = qualified_record()


def healthy_outcome(ms):
    outcome = copy.deepcopy(_QUALIFIED["cases"][0]["outcome"])
    outcome["offset_ms"] = ms
    return outcome


def no_feed_probe(branch="no-feeds-unattributed"):
    """A no-feed probe as the cell samples it."""
    starved = branch == "no-feeds-receipt-starved"
    gaps = [{"subject": "joint birth unavailable",
             "reason": "joint_birth_original_mismatch", "count": 1}]
    if starved:
        gaps = [{"subject": "semantic admission deferred",
                 "reason": "semantic_unavailable:no_receipt", "count": 1},
                {"subject": "semantic receipt refused",
                 "reason": "partition", "count": 1}]
    return {"joint_feeds": 0,
            "journal_linked": branch in LINKED_NO_FEED,
            "backstop_routed": 0, "birth_capacity": None,
            "drive": "live=1 gated=0 finished=0 ticks=3 feeds=0",
            "gaps": gaps, "no_receipt": 2 if starved else 0,
            "partition": 1 if starved else 0, "shed": 18 if starved else 0}


def join_of(branch):
    """The join the cell spends before deciding `branch`."""
    if branch is None:
        return None
    return JOIN_QUANTA if branch in LINKED_NO_FEED else 0


def case_record(k, branch="linked", outcome="healthy", completed=None,
                no_feed="sampled", join="spent"):
    if outcome == "healthy":
        outcome = healthy_outcome(offset_of(k)) if branch == "linked" else None
    if completed is None:
        completed = outcome is not None and branch == "linked"
    if no_feed == "sampled":
        no_feed = no_feed_probe(branch) if branch in RECEIPTS else None
    if join == "spent":
        join = join_of(branch)
    passes = None if join is None else (JOIN_PASSES if join == JOIN_QUANTA
                                        else 0)
    return {"name": "wp7-stop%d" % k, "index": k, "prep": k // 4,
            "offset_ms": offset_of(k), "branch": branch, "join_quanta": join,
            "join_passes": passes, "outcome": outcome, "no_feed": no_feed,
            "completed": completed}


def record(cases, terminal):
    built = copy.deepcopy(_QUALIFIED)
    built["cases"] = cases
    built["terminal"] = terminal
    return built


def completed_cases(count):
    return [case_record(k) for k in range(count)]


def no_feed_record(k=0, cause="s1-precluded"):
    kind = "precluded" if (k == 0 and cause == "s1-precluded") else "no-feed"
    return record(completed_cases(k) + [case_record(k, cause)],
                  {"kind": kind, "case": k, "cause": cause,
                   "receipt": RECEIPTS[cause]})


def precluded_record():
    return no_feed_record(0)


def wedge_outcome(k, finish="unpublished"):
    outcome = healthy_outcome(offset_of(k))
    outcome.update(finish=finish, wound="unwound", taken=False)
    return outcome


def wedge_record(k=5, finish="unpublished"):
    return record(completed_cases(k) + [case_record(k, outcome=wedge_outcome(
        k, finish), completed=False)], {"kind": "wedge", "case": k})


def case_failed_record(k=3, stage="check", check="reconcile", error=None):
    if stage == "setup":
        last = [case_record(k, branch=None, outcome=None)] if k is not None \
            else []
    elif stage == "drive":
        last = [case_record(k, outcome=None)]
    else:
        outcome = healthy_outcome(offset_of(k))
        outcome.update(reconciled=False,
                       reconcile_detail="caller deficits sum 1")
        last = [case_record(k, outcome=outcome, completed=False)]
    return record(completed_cases(k or 0) + last,
                  {"kind": "case-failed", "case": k, "stage": stage,
                   "check": check if stage == "check" else None,
                   "error": error or "offset %d: two-owner reconciliation "
                   "failed" % offset_of(k or 0)})


def record_line(rec):
    """The cell's record line (compact JSON, like serde_json)."""
    return MARKER + json.dumps(rec, separators=(",", ":"))


def human_lines(rec):
    """The free-text diagnostics a run with this record prints."""
    lines = list(PREAMBLE)
    for case in rec["cases"]:
        k = case["index"]
        lines.append("JOINT_STOP wp7-stop%d: prep=Services(1) done; "
                     "stopping in %d ms" % (k, case["offset_ms"]))
        branch = case["branch"]
        if branch is not None:
            lines.append("P11SCOPE_CELL_BRANCH=wp7-stop%d:%s" % (k, branch))
        if case["outcome"] is not None:
            lines.append("JOINT_STOP outcome: offset=%d finish=%s"
                         % (case["offset_ms"], case["outcome"]["finish"]))
    return lines


def error_lines(rec):
    """libtest's print of the returned error, after the record."""
    terminal = rec["terminal"]
    if terminal["kind"] in ("qualified", "narrowed"):
        return []
    if terminal["kind"] in ("precluded", "no-feed"):
        text = "wp7-stop%s: %s; not attempted" % (terminal["case"],
                                                  terminal["receipt"])
    elif terminal["kind"] == "wedge":
        text = ("offset %d: the finish must reach Published then WoundDown"
                % offset_of(int(terminal["case"])))
    else:
        text = str(terminal.get("error", terminal.get("kind")))
    return ["Error: " + text] + BACKTRACE


def body_for(rec, before=(), after=()):
    """Diagnostics, the record on its own line, then the error print."""
    return (human_lines(rec) + list(before) + ["", record_line(rec)]
            + list(after) + error_lines(rec))


def frame(body, ok, threaded=True, summary=None, cell=CELL, trailer=None,
          tail=()):
    """Wrap body lines in the pinned libtest framing."""
    word = "ok" if ok else "FAILED"
    if summary is None:
        summary = OK_SUMMARY if ok else FAILED_SUMMARY
    if trailer is None:
        trailer = ([""] if ok else
                   ["", "failures:", "", "failures:", "    " + cell, ""])
    lines = ["", "running 1 test"]
    if threaded:
        lines += list(body) + ["test %s ... %s" % (cell, word)]
    else:
        body = list(body)
        if body:
            lines += ["test %s ... %s" % (cell, body[0])] + body[1:] + [word]
        else:
            lines += ["test %s ... %s" % (cell, word)]
    lines += trailer + [summary, ""] + list(tail)
    return "\n".join(lines) + "\n"


def log_for(rec, ok=None, **kwargs):
    """A whole cell log carrying `rec`; ok defaults from the terminal."""
    if ok is None:
        ok = rec["terminal"]["kind"] == "qualified"
    return frame(body_for(rec), ok, **kwargs)


def passing(**kwargs):
    return log_for(qualified_record(), **kwargs)


def precluded(**kwargs):
    return log_for(precluded_record(), **kwargs)


def wedged(k=5, **kwargs):
    return log_for(wedge_record(k), **kwargs)
