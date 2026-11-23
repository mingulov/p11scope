#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Per-guard behaviour of the qualifier's inline Python checks.

Each block (second-SIGINT report check, event-stdout judge, parent-chain
oracle) is extracted from scripts/qualify-public-cli.sh and run whole
against one valid fixture and one malformed case per guard, under the
plain, -O and inherited-PYTHONOPTIMIZE interpreters. A guard that an
optimized interpreter would strip, or that is deleted, fails its row.

Run: python3 -I tests/python/test_qualifier_guard_blocks.py -v
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
QUAL = ROOT / "scripts" / "qualify-public-cli.sh"


def verdict(text):
    """Keep only the lines a check emits: a failure is matched on its
    final exception line, never on traceback frames (a frame's source
    line would show a check's message text even when another error
    raised there)."""
    return "\n".join(line for line in text.splitlines()
                     if line and not line[0].isspace()
                     and not line.startswith("Traceback (most recent call last)"))

MODES = (("plain", ["python3", "-I"], None),
         ("-O", ["python3", "-O", "-I"], None),
         ("PYTHONOPTIMIZE", ["python3"], {"PYTHONOPTIMIZE": "1"}))


RECORDS = ROOT / "scripts" / "qualify_records.py"
RUN_ID = "test-run"
SIGINT = "second-sigint"
EVENT = "event-stdout"
CHAIN = "parent-chain"
CELLS = {SIGINT: "second-sigint", EVENT: "inventory-event-stdout", CHAIN: "parent-chain"}


def judge_argv(judge, files, argv, env):
    """The judge's named arguments, as the shell passes them."""
    if judge == SIGINT:
        files.setdefault("sig2.stderr", "p11scope: cancel\np11scope: cleanup incomplete\n")
        return ["--report", argv[0], "--stderr", "sig2.stderr", "--rc", "130",
                "--custody", "1", "--cleanup", "1"]
    if judge == EVENT:
        return ["--jsonl", "event-stdout.jsonl", "--full-report", env["full_out"],
                "--epipe-report", env["epipe_out"], "--epipe-head", "event-epipe.head",
                "--rc1", env["rc1"], "--rc2", env["rc2"]]
    report, concise, verbose, wl, wl_gen, parent, parent_gen = argv
    return ["--report", report, "--concise", concise, "--verbose", verbose,
            "--workload-pid", wl, "--workload-gen", wl_gen,
            "--parent-pid", parent, "--parent-gen", parent_gen]


def run_block(judge, files, argv=(), env=None, mode=MODES[0], verdict_out=None):
    """Run one judge of the typed loader on fixture files."""
    _, interp, extra = mode
    files = dict(files)
    named = judge_argv(judge, files, list(argv), env or {})
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        cell = CELLS[judge]
        subprocess.run(["python3", "-I", str(RECORDS), "stamp", str(tmp / (cell + ".stamp")),
                        RUN_ID, cell], check=True)
        for name, text in files.items():
            (tmp / name).write_text(text)
        full = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        full.update(extra or {})
        proc = subprocess.run(interp + [str(RECORDS), judge, "--stamp", cell + ".stamp",
                                        "--run-id", RUN_ID, "--verdict", "verdict.json"] + named,
                              cwd=tmp, capture_output=True, text=True, timeout=30, env=full)
        if verdict_out is not None:
            verdict_out.update(json.loads((tmp / "verdict.json").read_text()))
        return proc.returncode, verdict(proc.stdout + proc.stderr)


class GuardCase(unittest.TestCase):
    def expect(self, *, ok, marker, **kwargs):
        for mode in MODES:
            with self.subTest(mode=mode[0]):
                rc, out = run_block(self.ANCHOR, mode=mode, **kwargs)
                if ok:
                    self.assertEqual(rc, 0, out)
                    if marker:
                        self.assertIn(marker, out)
                else:
                    self.assertNotEqual(rc, 0, out)
                    self.assertIn(marker, out)


# -- second SIGINT ------------------------------------------------------

def sigint_report():
    return {"schema": "p11scope/observed-profile/v3",
            "evidence": {"completeness": "PARTIAL",
                         "stop_quiescence": {"state": "proven",
                                             "post_q_events": False,
                                             "post_q_discovery": False},
                         "drain_proven": True,
                         "scheduling": {"inter_drain_gap": {"samples": 3}},
                         "child_still_running": False}}


def sig_set(path, value):
    def go(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        if value is DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return go


DELETE = object()


class SecondSigintReportTests(GuardCase):
    ANCHOR = SIGINT

    def check(self, report, *, ok, marker=""):
        self.expect(ok=ok, marker=marker,
                    files={"sigint2.json": json.dumps(report)},
                    argv=["sigint2.json"])

    def test_settled_partial_report_passes(self):
        self.check(sigint_report(), ok=True)

    def test_one_drain_sample_passes(self):
        report = sigint_report()
        report["evidence"]["scheduling"]["inter_drain_gap"]["samples"] = 1
        self.check(report, ok=True)

    def test_unproven_drain_matching_its_evidence_passes(self):
        for path in (["state"], ["post_q_events"], ["post_q_discovery"]):
            with self.subTest(field=path[0]):
                report = sigint_report()
                stop = report["evidence"]["stop_quiescence"]
                stop[path[0]] = "pending" if path[0] == "state" else True
                report["evidence"]["drain_proven"] = False
                self.check(report, ok=True)

    E = ["evidence"]
    ROWS = [
        ("schema", sig_set(["schema"], "p11scope/observed-profile/v2"), "schema"),
        ("complete", sig_set(E + ["completeness"], "COMPLETE"),
         "abandoned teardown cannot seal COMPLETE"),
        ("drain-claimed-unproven-state", sig_set(E + ["stop_quiescence", "state"], "pending"),
         "drain_proven must match the stop-gate evidence"),
        ("drain-claimed-post-events", sig_set(E + ["stop_quiescence", "post_q_events"], True),
         "drain_proven must match the stop-gate evidence"),
        ("drain-claimed-post-discovery", sig_set(E + ["stop_quiescence", "post_q_discovery"], None),
         "drain_proven must match the stop-gate evidence"),
        ("drain-denied", sig_set(E + ["drain_proven"], False),
         "drain_proven must match the stop-gate evidence"),
        ("samples-zero", sig_set(E + ["scheduling", "inter_drain_gap", "samples"], 0),
         "report must carry this capture live-loop drain samples"),
        ("samples-string", sig_set(E + ["scheduling", "inter_drain_gap", "samples"], "3"),
         "report must carry this capture live-loop drain samples"),
        ("samples-bool", sig_set(E + ["scheduling", "inter_drain_gap", "samples"], True),
         "report must carry this capture live-loop drain samples"),
        ("samples-missing", sig_set(E + ["scheduling"], DELETE),
         "report must carry this capture live-loop drain samples"),
        # Codex r7 F1: a still-running child with all shell custody met.
        ("child-still-running", sig_set(E + ["child_still_running"], True),
         "owned child must be settled, not still running"),
        ("child-unknown", sig_set(E + ["child_still_running"], DELETE),
         "owned child must be settled, not still running"),
    ]

    def test_each_guard_row_fails(self):
        for name, mutate, marker in self.ROWS:
            with self.subTest(row=name):
                report = sigint_report()
                mutate(report)
                self.check(report, ok=False, marker=marker)

    def test_duplicate_key_fails(self):
        # Last-wins would let a second key hide a still-running child.
        text = json.dumps(sigint_report()).replace(
            '"child_still_running": false', '"child_still_running": true, "child_still_running": false')
        self.expect(ok=False, marker="duplicate JSON key 'child_still_running'",
                    files={"sigint2.json": text}, argv=["sigint2.json"])


# -- event stdout -------------------------------------------------------

INTERVAL = 2_000_000_000


def event_stream(n_totals=2):
    """started, then per pass a pass_committed and (cadence permitting)
    a totals snapshot exactly one interval after the previous one."""
    rows = [{"kind": "started", "at_ns": 0, "event": {}}]
    for index in range(n_totals):
        totals = {"callers": index + 1, "modules": 1, "edges": index + 1}
        rows.append({"kind": "pass_committed", "at_ns": INTERVAL * index + INTERVAL // 2,
                     "event": {"pass": index, "totals": totals}})
        rows.append({"kind": "totals", "at_ns": INTERVAL * (index + 1),
                     "event": dict(totals, **{"pass": index, "passes": index + 1,
                                              "stdout_lost": {"lines": 0, "bytes": 0}})})
    rows.append({"kind": "ended", "at_ns": INTERVAL * (n_totals + 1),
                 "event": {"passes": n_totals, "stdout_lost": {"lines": 0, "bytes": 0}}})
    for seq, row in enumerate(rows):
        row["schema"] = "p11scope/inventory-events/v1"
        row["seq"] = seq
    return rows


EVENT_COMPLETE = {"status": "complete", "lines_lost": 0, "bytes_lost": 0, "reason": "none"}
EVENT_TRUNCATED = {"status": "truncated", "lines_lost": 12, "bytes_lost": 2400,
                   "reason": "broken_pipe"}


def event_case(n_totals=2):
    stream = event_stream(n_totals)
    report = {"schema": "p11scope/inventory/v1",
              "observation": {"passes": n_totals},
              "callers": [{}] * n_totals, "modules": [{}], "edges": [{}] * n_totals,
              "event_output": dict(EVENT_COMPLETE)}
    return {"stream": stream, "report": report,
            "epipe": {"schema": "p11scope/inventory/v1", "event_output": dict(EVENT_TRUNCATED)},
            # stderr is a human rendering only: it never decides loss.
            "head": "{\"schema\"", "stderr": "p11scope: event log: no rows shed\n",
            "rc1": "0", "rc2": "1", "jsonl": None}


class EventStdoutGuardTests(GuardCase):
    ANCHOR = EVENT

    def check(self, case, *, ok, marker=""):
        jsonl = case["jsonl"]
        if jsonl is None:
            jsonl = "".join(json.dumps(row) + "\n" for row in case["stream"])
        files = {"event-stdout.jsonl": jsonl,
                 "full.json": json.dumps(case["report"]),
                 "epipe.json": json.dumps(case["epipe"]),
                 "event-epipe.head": case["head"],
                 "event-epipe.stderr": case["stderr"]}
        env = {"full_out": "full.json", "epipe_out": "epipe.json",
               "rc1": case["rc1"], "rc2": case["rc2"]}
        self.expect(ok=ok, marker=marker, files=files, env=env)

    def test_valid_runs_pass(self):
        for n in (1, 2, 4):
            with self.subTest(totals=n):
                self.check(event_case(n), ok=True,
                           marker="ok lines=%d totals=%d" % (2 * n + 2, n))

    def stream_row(index, key, value):
        def go(case):
            case["stream"][index][key] = value
        return go

    def event_field(index, key, value):
        def go(case):
            case["stream"][index]["event"][key] = value
        return go

    def setter(key, value):
        def go(case):
            case[key] = value
        return go

    def output_set(document, **changes):
        def go(case):
            case[document]["event_output"].update(changes)
        return go

    def drop_totals(case):
        case["stream"] = [r for r in case["stream"] if r["kind"] != "totals"]
        for seq, row in enumerate(case["stream"]):
            row["seq"] = seq

    def blank_line(case):
        case["jsonl"] = "".join(json.dumps(r) + "\n" for r in case["stream"][:2]) + "\n"

    def short_stream(case):
        case["stream"] = [case["stream"][0], case["stream"][-1]]
        for seq, row in enumerate(case["stream"]):
            row["seq"] = seq

    def report_extra_caller(case):
        case["report"]["callers"].append({})

    def report_passes(case):
        case["report"]["observation"]["passes"] = 3

    ROWS = [
        ("blank-line", blank_line, "blank line breaks the JSONL framing"),
        ("full-rc", setter("rc1", "1"), "full run rc=1"),
        ("short-stream", short_stream, "started, a pass marker and ended"),
        ("row-schema", stream_row(1, "schema", "p11scope/inventory-events/v0"),
         "inventory-events/v0"),
        ("seq-gap", stream_row(1, "seq", 5), "seq 5 != 1"),
        ("first-not-started", stream_row(0, "kind", "bogus-first"), "bogus-first"),
        ("last-not-ended", stream_row(-1, "kind", "bogus-last"), "bogus-last"),
        ("report-schema", lambda c: c["report"].update(schema="p11scope/inventory/v0"),
         "p11scope/inventory/v0"),
        ("passes-disagree", report_passes, "passes agree"),
        ("final-totals-disagree", report_extra_caller, "('callers', 3, "),
        ("no-totals", drop_totals, "totals count 0"),
        ("totals-other-pass", event_field(2, "pass", 1), "(0, {"),
        ("totals-passes", event_field(2, "passes", 3), "'passes': 3"),
        ("totals-callers", event_field(2, "callers", 9), "('callers', {"),
        ("totals-modules", event_field(2, "modules", 9), "('modules', {"),
        ("totals-edges", event_field(2, "edges", 9), "('edges', {"),
        ("final-modules-disagree", lambda c: c["report"]["modules"].append({}), "('modules', 2, "),
        ("final-edges-disagree", lambda c: c["report"]["edges"].append({}), "('edges', 3, "),
        ("totals-early", stream_row(2, "at_ns", INTERVAL - 1), "'at_ns': 1999999999"),
        ("early-close-rc", setter("rc2", "0"), "early-close rc=0"),
        ("head-empty", setter("head", ""), "the head holds event bytes"),
        ("epipe-schema", lambda c: c["epipe"].update(schema="other"), "other"),
        # Loss proof is the typed report outcome, on both runs.
        ("full-output-missing", lambda c: c["report"].pop("event_output"),
         "full report event_output None"),
        ("full-output-truncated", output_set("report", status="truncated"),
         "full run event_output"),
        ("full-output-lines", output_set("report", lines_lost=1), "full run event_output"),
        ("full-output-bytes", output_set("report", bytes_lost=1), "full run event_output"),
        ("full-output-reason", output_set("report", reason="broken_pipe"), "full run event_output"),
        ("full-output-extra", output_set("report", extra=0), "full event_output fields"),
        ("full-output-bool", output_set("report", lines_lost=False), "full event_output lines_lost False"),
        ("ended-lost", lambda c: c["stream"][-1]["event"].update(stdout_lost={"lines": 1, "bytes": 0}),
         "full run ended stdout_lost"),
        ("ended-lost-missing", lambda c: c["stream"][-1]["event"].pop("stdout_lost"),
         "full run ended stdout_lost None"),
        ("epipe-output-missing", lambda c: c["epipe"].pop("event_output"),
         "early-close report event_output None"),
        ("epipe-complete", output_set("epipe", status="complete", lines_lost=0, bytes_lost=0, reason="none"),
         "early-close event_output"),
        ("epipe-failed", output_set("epipe", status="failed"), "early-close event_output"),
        ("epipe-slow-reader", output_set("epipe", reason="slow_reader"), "early-close event_output"),
        ("epipe-zero-lines", output_set("epipe", lines_lost=0), "early-close event_output counts"),
        ("epipe-bytes-below-lines", output_set("epipe", bytes_lost=11), "early-close event_output counts"),
        ("epipe-negative", output_set("epipe", bytes_lost=-1), "early-close event_output bytes_lost -1"),
        ("epipe-float", output_set("epipe", lines_lost=12.0), "early-close event_output lines_lost 12.0"),
        ("epipe-status-type", output_set("epipe", status=None), "early-close event_output status None"),
        ("epipe-reason-type", output_set("epipe", reason=1), "early-close event_output reason 1"),
        ("epipe-missing-field", lambda c: c["epipe"]["event_output"].pop("reason"),
         "early-close event_output fields"),
        ("epipe-not-object", lambda c: c["epipe"].update(event_output=[]),
         "early-close report event_output []"),
    ]

    def test_smallest_measured_loss_passes(self):
        # One shed line of one byte is still measured loss.
        case = event_case(2)
        case["epipe"]["event_output"].update(lines_lost=1, bytes_lost=1)
        self.check(case, ok=True, marker="ok lines=6 totals=2")

    def test_stderr_never_decides_loss(self):
        # Codex r8 F3: any stderr text, including a contradictory
        # one, leaves the typed verdict unchanged in both directions.
        for text in ("", "p11scope: event log: no rows shed\n",
                     "p11scope: inventory event log stdout shed 12 lines\n"):
            with self.subTest(stderr=text, outcome="truncated"):
                case = event_case(2)
                case["stderr"] = text
                self.check(case, ok=True, marker="ok lines=6 totals=2")
            with self.subTest(stderr=text, outcome="complete"):
                # Unrelated exit 1 with zero measured loss fails.
                case = event_case(2)
                case["stderr"] = text
                case["epipe"]["event_output"] = dict(EVENT_COMPLETE)
                self.check(case, ok=False, marker="early-close event_output")

    def test_each_guard_row_fails(self):
        for name, mutate, marker in self.ROWS:
            with self.subTest(row=name):
                case = event_case(2)
                mutate(case)
                self.check(case, ok=False, marker=marker)

    def test_repeated_totals_for_one_long_pass_pass(self):
        # A pass longer than the interval gets a second totals; its
        # marker is still the last pass_committed, not the totals row.
        case = event_case(1)
        stream = case["stream"]
        again = json.loads(json.dumps(stream[2]))
        again["at_ns"] = 2 * INTERVAL
        stream.insert(3, again)
        stream[-1]["at_ns"] = 3 * INTERVAL
        for seq, row in enumerate(stream):
            row["seq"] = seq
        self.check(case, ok=True, marker="ok lines=5 totals=2")

    def test_duplicate_keys_fail(self):
        case = event_case(2)
        rows = [json.dumps(r) for r in case["stream"]]
        rows[1] = rows[1].replace('"kind": "pass_committed"', '"kind": "totals", "kind": "pass_committed"')
        case["jsonl"] = "\n".join(rows) + "\n"
        self.check(case, ok=False, marker="duplicate JSON key 'kind'")
        for name in ("report", "epipe"):
            with self.subTest(document=name):
                case = event_case(2)
                text = json.dumps(case[name]).replace(
                    '"schema": "p11scope/inventory/v1"',
                    '"schema": "other", "schema": "p11scope/inventory/v1"')
                self.check_text(case, name, text, marker="duplicate JSON key 'schema'")

    def check_text(self, case, name, text, *, marker):
        files = {"event-stdout.jsonl": "".join(json.dumps(r) + "\n" for r in case["stream"]),
                 "full.json": text if name == "report" else json.dumps(case["report"]),
                 "epipe.json": text if name == "epipe" else json.dumps(case["epipe"]),
                 "event-epipe.head": case["head"], "event-epipe.stderr": case["stderr"]}
        env = {"full_out": "full.json", "epipe_out": "epipe.json",
               "rc1": case["rc1"], "rc2": case["rc2"]}
        self.expect(ok=False, marker=marker, files=files, env=env)

    def test_five_totals_fail(self):
        self.check(event_case(5), ok=False, marker="totals count 5")


# -- parent chain -------------------------------------------------------

WL, WL_GEN, PARENT, PARENT_GEN = 300, 9000, 299, 8999


def chain_report(ancestors=None, **caller):
    if ancestors is None:
        ancestors = [{"pid": PARENT, "exe": "chain-parent", "start_time": PARENT_GEN},
                     {"pid": 50, "exe": "bash", "start_time": 70}]
    row = {"pid": WL, "start_time": WL_GEN, "launched_by": ancestors,
           "launched_by_origin": "chain", "launched_by_unit": None,
           "launched_by_gap": None}
    row.update(caller)
    return {"callers": [{"pid": 77, "start_time": 1}, row]}


class ParentChainGuardTests(GuardCase):
    ANCHOR = CHAIN

    def check(self, report, *, ok, marker="", concise="gated (from chain-parent)\n",
              verbose="gated <- chain-parent <- bash\n"):
        self.expect(ok=ok, marker=marker,
                    files={"r.json": json.dumps(report), "c.txt": concise, "v.txt": verbose},
                    argv=["r.json", "c.txt", "v.txt", str(WL), str(WL_GEN),
                          str(PARENT), str(PARENT_GEN)])

    def test_valid_chains_pass(self):
        parent = {"pid": PARENT, "exe": "chain-parent", "start_time": PARENT_GEN}
        hop = {"pid": 50, "exe": "bash", "start_time": 70}
        for n in (1, 2, 4):
            with self.subTest(ancestors=n):
                self.check(chain_report([parent] + [dict(hop, pid=50 + k) for k in range(n - 1)]),
                           ok=True, marker="chain to chain-parent with %d ancestors" % n)

    def test_each_named_gap_reason_passes(self):
        for reason in ("launcher exited before read", "launcher hidden by /proc hidepid",
                       "parent chain truncated after 4 ancestors",
                       "parent chain not sampled in cgroup transaction"):
            with self.subTest(reason=reason):
                self.check(chain_report(launched_by_gap={"subject": "caller parent chain",
                                                         "reason": reason}), ok=True)

    PARENT_ROW = {"pid": PARENT, "exe": "chain-parent", "start_time": PARENT_GEN}
    ROWS = [
        ("two-incarnations", None, "one incarnation for the workload"),
        ("generation", dict(start_time=WL_GEN + 1), "caller generation unchanged"),
        ("not-a-list", dict(launched_by={"pid": PARENT}), "walk keeps 1..=4 ancestors"),
        ("empty-walk", dict(launched_by=[]), "walk keeps 1..=4 ancestors"),
        ("five-ancestors", dict(launched_by=[PARENT_ROW] + [
            {"pid": 60 + k, "exe": "sh", "start_time": 5} for k in range(4)]),
         "walk keeps 1..=4 ancestors"),
        ("first-pid", dict(launched_by=[dict(PARENT_ROW, pid=PARENT + 5)]), "named parent first"),
        ("first-exe", dict(launched_by=[dict(PARENT_ROW, exe="sh")]), "named parent first"),
        ("first-generation", dict(launched_by=[dict(PARENT_ROW, start_time=1)]), "named parent first"),
        ("init-shown", dict(launched_by=[PARENT_ROW, {"pid": 1, "exe": "init", "start_time": 2}]),
         "init is never shown as the launcher"),
        ("ancestor-pid", dict(launched_by=[PARENT_ROW, {"pid": 0, "exe": "x", "start_time": 2}]),
         "ancestor generation"),
        ("ancestor-generation", dict(launched_by=[PARENT_ROW, {"pid": 9, "exe": "x", "start_time": "2"}]),
         "ancestor generation"),
        ("ancestor-pid-float", dict(launched_by=[PARENT_ROW, {"pid": 9.0, "exe": "x", "start_time": 2}]),
         "ancestor generation"),
        ("ancestor-generation-bool", dict(launched_by=[PARENT_ROW, {"pid": 9, "exe": "x", "start_time": True}]),
         "ancestor generation"),
        ("origin", dict(launched_by_origin="unit"), "real chain origin"),
        ("unit-beside-chain", dict(launched_by_unit="cron.service"), "no unit beside a real chain"),
        ("gap-subject", dict(launched_by_gap={"subject": "other", "reason": "launcher exited before read"}),
         "'subject': 'other'"),
        ("gap-reason", dict(launched_by_gap={"subject": "caller parent chain", "reason": "made up"}),
         "'reason': 'made up'"),
    ]

    def test_each_guard_row_fails(self):
        for name, caller, marker in self.ROWS:
            with self.subTest(row=name):
                report = chain_report() if caller is None else chain_report(**caller)
                if caller is None:
                    report["callers"].append(copy.deepcopy(report["callers"][1]))
                self.check(report, ok=False, marker=marker)

    def test_duplicate_key_fails(self):
        text = json.dumps(chain_report()).replace(
            '"launched_by_origin": "chain"', '"launched_by_origin": "unit", "launched_by_origin": "chain"')
        self.expect(ok=False, marker="duplicate JSON key 'launched_by_origin'",
                    files={"r.json": text, "c.txt": "gated (from chain-parent)\n",
                           "v.txt": "gated <- chain-parent <- bash\n"},
                    argv=["r.json", "c.txt", "v.txt", str(WL), str(WL_GEN),
                          str(PARENT), str(PARENT_GEN)])

    def test_concise_and_verbose_text_are_checked(self):
        self.check(chain_report(), ok=False, marker="concise one-hop", concise="gated\n")
        self.check(chain_report(), ok=False, marker="verbose chain", verbose="gated\n")


if __name__ == "__main__":
    unittest.main()
