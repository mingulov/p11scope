#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Rule table and field fuzz for the qualifier's typed loader.

scripts/qualify_records.py holds every structured-evidence decision of
scripts/qualify-public-cli.sh as declared rules. This suite:

- runs a table in which every declared rule has at least one negative
  row (decided by the verdict record's exact rule id, never by message
  text) and at least one positive row that evaluates the rule and holds
  (the loader's `require` is traced in-process);
- fuzzes every field of every valid fixture (each base case and each
  positive row's case where it differs: delete, wrong JSON type,
  integral float/bool twins of ints, u64 range edges, bool flips,
  unknown keys) and decides each outcome from the verdict's `stage`:
  a wrong type must be refused by typing, a flip or an in-type value
  by a relation rule, an unknown key exactly where the record is
  closed; every pass must be a named, explained allowance;
- holds every numeric argument at its exact bounds and the loader's
  kinds at their exact ranges;
- exercises the shell side of run binding (fresh destinations in both
  output layouts, a failed report copy failing the event cell).

Run: python3 -I tests/python/test_qualify_records.py -v
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
RECORDS = ROOT / "scripts" / "qualify_records.py"
QUAL = ROOT / "scripts" / "qualify-public-cli.sh"
RUN_ID = "3f1c-test-run"


def load_module():
    spec = importlib.util.spec_from_file_location("qualify_records", RECORDS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


Q = load_module()

# -- valid fixtures (the real producer shapes) ----------------------------------

MODPATH = "/usr/lib64/pkcs11/libsofthsm2.so"
SHA = "61" * 32
FUNCTIONS = ["C_GenerateRandom", "C_DigestInit", "C_Digest",
             "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]
ITERS, OUT_ITERS = 250, 500
DRIVEN = 6 * ITERS + 7
INTERVAL = 2_000_000_000
STARTED = 1_000_000_000_000
WL, WL_GEN, PARENT, PARENT_GEN = 300, 9000, 299, 8999


def ledger(pid, attempts):
    return {"schema": "p11scope/public-cli-ledger/v1", "pid": pid, "complete": True,
            "functions": [{"name": n, "attempts": attempts, "successful": attempts} for n in FUNCTIONS]}


def entries():
    return {"count": DRIVEN, "coverage": {"state": "counted", "lossy": False},
            "observation": "observed", "saturated": False, "in_flight": False}


def cgroup_case(modfs="ext4"):
    report = {
        "schema": "p11scope/inventory/v1", "scope": "cgroup",
        "modules": [{"id": "m0", "identity": {"device": {"major": 0, "minor": 46}, "inode": 153887,
                                               "sha256": SHA},
                     "admission": {"state": "admitted"}}],
        "callers": [{"id": "c0", "pid": 100, "start_time": 5000, "start_time_unit": "clock_ticks_since_boot",
                     "retired": False, "image": {"authority": "native_exact"}},
                    {"id": "c1", "pid": 101, "start_time": 5001, "start_time_unit": "clock_ticks_since_boot",
                     "retired": False, "image": {"authority": "native_exact"}}],
        "edges": [{"caller": "c0", "module": "m0", "entries": entries()},
                  {"caller": "c1", "module": "m0", "entries": entries()}],
        "gaps": []}
    if modfs == "overlayfs":
        report["gaps"] = [{"caller": c, "pid": p, "module": None, "subject": MODPATH,
                           "reason": Q.UNPROVEN + ": scoped collection deactivates the kernel proof"}
                          for c, p in (("c0", 100), ("c1", 101))]
    return {"judge": "cgroup-inventory", "report": report,
            "inside": ["READY pid=100", "CHILD pid=101", "LEDGER " + json.dumps(ledger(100, 2 * ITERS))],
            "outside": ["READY pid=102", "LEDGER " + json.dumps(ledger(102, OUT_ITERS))],
            "pin": {"dev": [0, 46], "ino": 153887, "sha256": SHA},
            "args": {"inside-iters": str(ITERS), "outside-iters": str(OUT_ITERS), "module": MODPATH,
                     "module-fs": modfs, "inside-pid": "100", "inside-gen": "5000", "child-pid": "101",
                     "child-gen": "5001", "outside-pid": "102", "cell": "inventory-cgroup"}}


def event_rows(n_totals=2):
    rows = [{"kind": "started", "at_ns": STARTED, "event": {}}]
    for index in range(n_totals):
        at = STARTED + (index + 1) * INTERVAL
        counts = {"callers": 1, "modules": 1, "edges": 1}
        rows.append({"kind": "pass_committed", "at_ns": at, "event": {"pass": index, "totals": dict(counts)}})
        rows.append({"kind": "totals", "at_ns": at,
                     "event": dict(counts, **{"pass": index, "passes": index + 1,
                                              "stdout_lost": {"lines": 0, "bytes": 0}})})
    rows.append({"kind": "ended", "at_ns": STARTED + (n_totals + 1) * INTERVAL,
                 "event": {"passes": n_totals, "stdout_lost": {"lines": 0, "bytes": 0}}})
    for seq, row in enumerate(rows):
        row.update(schema="p11scope/inventory-events/v1", seq=seq)
    return rows


def event_case():
    return {"judge": "event-stdout", "stream": event_rows(),
            "report": {"schema": "p11scope/inventory/v1", "observation": {"passes": 2},
                       "callers": [{}], "modules": [{}], "edges": [{}],
                       "event_output": {"status": "complete", "lines_lost": 0, "bytes_lost": 0,
                                        "reason": "none"}},
            "epipe": {"schema": "p11scope/inventory/v1",
                      "event_output": {"status": "truncated", "lines_lost": 6, "bytes_lost": 5660,
                                       "reason": "broken_pipe"}},
            "head": '{"schema"', "args": {"rc1": "0", "rc2": "1"}}


def sigint_case():
    return {"judge": "second-sigint",
            "report": {"schema": "p11scope/observed-profile/v3",
                       "evidence": {"completeness": "PARTIAL",
                                    "stop_quiescence": {"state": "proven", "post_q_events": False,
                                                        "post_q_discovery": False},
                                    "drain_proven": True,
                                    "scheduling": {"inter_drain_gap": {"samples": 3}},
                                    "child_still_running": False}},
            "stderr": "p11scope: stopping\np11scope: cleanup incomplete\n",
            "args": {"rc": "130", "custody": "1", "cleanup": "1"}}


def fifo_case():
    return {"judge": "fifo-refusal", "stderr": Q.FIFO_REFUSAL + "\n", "fifo": True, "args": {"rc": "1"}}


def member_case():
    return {"judge": "cgroup-member", "procs": "77\n100\n", "args": {"pid": "100"}}


def prearm_evidence(windows, attached=50):
    return {"discovery": [{"sources": ["scan"], "unobserved_windows": [], "attached_at_ns": 7},
                          {"sources": ["prearm", "scan"], "unobserved_windows": windows,
                           "attached_at_ns": attached}]}


PRE_ATTACH = [{"start_ns": 10, "end_ns": 50, "reason": "pre_attach"}]
HANDOFF = [{"start_ns": 10, "end_ns": 50, "reason": "late_discovery"},
           {"start_ns": 10, "end_ns": 60, "reason": "mapped_unattached"}]


def prearm_ledger():
    rows = [{"pair": n, "init_ns": 10 + n, "init_returned_ns": 20 + n, "fini_returned_ns": 30 + n}
            for n in range(3)]
    return rows + [{"initializes": 3, "finalizes": 3}]


def trace_lines(counts=(3, 3, 1)):
    lines = []
    for name, count in zip(("C_Initialize", "C_Finalize", "C_GetFunctionList"), counts):
        lines += ['1.0 "w" (PID 1, TID 1) %s -> CKR_OK 1.0us' % name] * count
    return lines


def prearm_case():
    return {"judge": "run-prearm",
            "held": trace_lines(), "held_evidence": [prearm_evidence([])],
            "passive": [], "passive_evidence": [prearm_evidence(PRE_ATTACH)],
            "held_ledger": prearm_ledger(), "passive_ledger": prearm_ledger(),
            "args": {"kernel-release": "7.2.9-200.fc44.x86_64"}}


def chain_case():
    return {"judge": "parent-chain",
            "report": {"callers": [{"pid": 77, "start_time": 1},
                                   {"pid": WL, "start_time": WL_GEN,
                                    "launched_by": [{"pid": PARENT, "exe": "chain-parent",
                                                     "start_time": PARENT_GEN},
                                                    {"pid": 50, "exe": "bash", "start_time": 70}],
                                    "launched_by_origin": "chain", "launched_by_unit": None,
                                    "launched_by_gap": None}]},
            "concise": "gated (from chain-parent)\n", "verbose": "gated <- chain-parent <- bash\n",
            "args": {"workload-pid": str(WL), "workload-gen": str(WL_GEN), "parent-pid": str(PARENT),
                     "parent-gen": str(PARENT_GEN)}}


BUILDERS = {"cgroup-inventory": cgroup_case, "event-stdout": event_case, "second-sigint": sigint_case,
            "fifo-refusal": fifo_case, "cgroup-member": member_case, "run-prearm": prearm_case,
            "parent-chain": chain_case}
CELLS = {"cgroup-inventory": "inventory-cgroup", "event-stdout": "inventory-event-stdout",
         "second-sigint": "second-sigint", "fifo-refusal": "fifo-refused", "run-prearm": "run-prearm",
         "parent-chain": "parent-chain"}


# -- in-process runner ------------------------------------------------------------

def dumps(value):
    return json.dumps(value)


def write_inputs(case, tmp):
    """Serialize a case into files (after the stamp) and named arguments."""
    raw = case.get("raw", {})
    judge = case["judge"]
    files, argv = {}, []

    def put(name, text, option):
        files[name] = raw.get(name, text)
        argv.extend(["--" + option, str(tmp / name)])

    if judge == "cgroup-inventory":
        put("report.json", dumps(case["report"]), "report")
        put("inside.wl", "\n".join(case["inside"]) + "\n", "inside-wl")
        put("outside.wl", "\n".join(case["outside"]) + "\n", "outside-wl")
        argv.extend(["--pin", raw.get("pin", dumps(case["pin"]))])
    elif judge == "event-stdout":
        put("events.jsonl", "".join(dumps(r) + "\n" for r in case["stream"]), "jsonl")
        put("full.json", dumps(case["report"]), "full-report")
        put("epipe.json", dumps(case["epipe"]), "epipe-report")
        put("epipe.head", case["head"], "epipe-head")
    elif judge == "second-sigint":
        put("sigint2.json", dumps(case["report"]), "report")
        put("sig2.stderr", case["stderr"], "stderr")
    elif judge == "fifo-refusal":
        fifo = tmp / "fifo"
        if case["fifo"] == "regular":
            fifo.write_text("")
        elif case["fifo"]:
            os.mkfifo(fifo)
        put("fifo.stderr", case["stderr"].replace("{path}", str(fifo)), "stderr")
        argv.extend(["--fifo", str(fifo)])
    elif judge == "cgroup-member":
        files["cgroup.procs"] = raw.get("cgroup.procs", case["procs"])
        argv.extend(["--procs", str(tmp / "cgroup.procs")])
    elif judge == "run-prearm":
        for name in ("held", "passive"):
            lines = list(case[name]) + ["EVIDENCE " + dumps(e) for e in case[name + "_evidence"]]
            put("run-prearm-%s.txt" % name, "\n".join(lines) + "\n", "%s-report" % name)
            put("run-prearm-%s.wl" % name, "".join(dumps(r) + "\n" for r in case[name + "_ledger"]),
                "%s-ledger" % name)
    elif judge == "parent-chain":
        put("chain.json", dumps(case["report"]), "report")
        put("chain.stdout", case["concise"], "concise")
        put("chain-v.stdout", case["verbose"], "verbose")
    for option, value in case["args"].items():
        argv.extend(["--" + option, value])
    return files, argv


class Trace:
    """Records every rule `require` evaluated and whether it held."""

    def __init__(self):
        self.held = set()

    def __enter__(self):
        original = Q.require

        def traced(condition, rule_id, detail):
            original(condition, rule_id, detail)
            self.held.add(rule_id)

        self.original = original
        Q.require = traced
        return self

    def __exit__(self, *exc):
        Q.require = self.original


def run_case(case, *, stamp=True, before=None):
    """Run one judge in-process; returns (verdict record, held rules)."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        judge = case["judge"]
        argv = [judge, "--verdict", str(tmp / "verdict.json")]
        if judge != "cgroup-member":
            stamp_path = tmp / "cell.stamp"
            if case.get("stamp_dir"):
                stamp_path.mkdir()
            elif "stamp_text" in case:
                stamp_path.write_text(case["stamp_text"])
            elif stamp:
                Q.write_stamp(str(stamp_path), case.get("stamp_run_id", RUN_ID),
                              case.get("stamp_cell", CELLS[judge]))
            argv += ["--stamp", str(stamp_path), "--run-id", case.get("run_id", RUN_ID)]
        files, named = write_inputs(case, tmp)
        for name, text in files.items():
            path = tmp / name
            if isinstance(text, bytes):
                path.write_bytes(text)
            else:
                path.write_text(text)
        for name, delta in case.get("age", {}).items():
            info = os.stat(tmp / "cell.stamp")
            os.utime(tmp / name, ns=(info.st_atime_ns, info.st_mtime_ns - delta))
        for name in case.get("remove", ()):
            os.unlink(tmp / name)
        for name in case.get("symlink", ()):
            # The same bytes behind a symlink: an input is never followed.
            os.rename(tmp / name, tmp / (name + ".real"))
            os.symlink(name + ".real", tmp / name)
        for name, size in case.get("sparse", {}).items():
            os.truncate(tmp / name, size)
        if before:
            before(tmp)
        with Trace() as trace, contextlib.redirect_stdout(io.StringIO()):
            rc = Q.main(argv + named)
        record = json.loads((tmp / "verdict.json").read_text())
        assert rc == (0 if record["verdict"] == "pass" else 1)
        return record, trace.held


# -- mutation helpers ---------------------------------------------------------------

def at(path, value=None, *, delete=False):
    """Set (or delete) one nested field: path is a tuple of keys/indices."""
    def go(case):
        node = case
        for key in path[:-1]:
            node = node[key]
        if delete:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return go


def arg(option, value):
    def go(case):
        case["args"][option] = value
    return go


def raw(name, text):
    def go(case):
        case.setdefault("raw", {})[name] = text
    return go


def chain(*steps):
    def go(case):
        for step in steps:
            step(case)
    return go


def gap(**fields):
    base = {"caller": None, "pid": None, "module": None, "subject": "s", "reason": None}
    base.update(fields)
    return base


def add_gaps(*gaps):
    def go(case):
        case["report"]["gaps"].extend(copy.deepcopy(list(gaps)))
    return go


UNBOUND_REASON = (MODPATH + ": native witness rows of this module were not bound to a caller incarnation "
                  "(first: no live caller); module-level positive use only, never attributed by pid")
DEADLINE_GAP = gap(subject="cgroup scope transaction incomplete", reason=Q.DEADLINE)
RETAINED_GAP = gap(caller="c0", pid=100, subject="native owner refresh refused", reason=Q.RETAINED)
ACTIVATION_GAP = gap(caller="c0", pid=100, subject=Q.ACTIVATION, reason=Q.SETTLE_REASON)
ADMISSION_GAP = gap(caller="c0", pid=100, module="m0", subject="module admission changed",
                    reason=MODPATH + ": admission changed from unresolved to admitted")
UNBOUND_GAP = gap(module="m0", subject="used by an unidentified caller image", reason=UNBOUND_REASON)


def ledger_fn(side, index, key, value):
    def go(case):
        wl = case[side]
        line = [n for n, text in enumerate(wl) if text.startswith("LEDGER ")][0]
        record = json.loads(wl[line][len("LEDGER "):])
        if key is None:
            record.update(value)
        elif index is None:
            record[key] = value
        else:
            record["functions"][index][key] = value
        wl[line] = "LEDGER " + json.dumps(record)
    return go


def ledger_edit(side, edit):
    """Apply `edit` to one workload's decoded LEDGER record."""
    def go(case):
        wl = case[side]
        line = [n for n, text in enumerate(wl) if text.startswith("LEDGER ")][0]
        record = json.loads(wl[line][len("LEDGER "):])
        edit(record)
        wl[line] = "LEDGER " + json.dumps(record)
    return go


def all_attempts(side, attempts, successful):
    def edit(record):
        for function in record["functions"]:
            function.update(attempts=attempts, successful=successful)
    return ledger_edit(side, edit)


def drop_rows(*kinds):
    """Keep only the stream rows not of these kinds, resequenced."""
    def go(case):
        case["stream"] = [r for r in case["stream"] if r["kind"] not in kinds]
        resequence(case)
    return go


def totals_case(n_totals):
    def go(case):
        case["stream"] = event_rows(n_totals)
        case["report"]["observation"]["passes"] = n_totals
    return go


def caller(index, **fields):
    def go(case):
        case["report"]["callers"][index].update(fields)
    return go


def edge_entries(index, **fields):
    def go(case):
        case["report"]["edges"][index]["entries"].update(fields)
    return go


def stream_row(index, **fields):
    def go(case):
        case["stream"][index].update(fields)
    return go


def stream_event(index, **fields):
    def go(case):
        case["stream"][index]["event"].update(fields)
    return go


def resequence(case):
    for seq, row in enumerate(case["stream"]):
        row["seq"] = seq


def chain_caller(**fields):
    def go(case):
        case["report"]["callers"][1].update(fields)
    return go


def ancestor(index, **fields):
    def go(case):
        case["report"]["callers"][1]["launched_by"][index].update(fields)
    return go


def evidence(name, value, index=0):
    def go(case):
        case[name + "_evidence"][index] = value
    return go


def prearm_module(name, **fields):
    def go(case):
        case[name + "_evidence"][0]["discovery"][1].update(fields)
    return go


def direct(function):
    """A rule decided by a loader function outside the judges' paths."""
    return {"judge": "direct", "function": function}


# -- the rule table --------------------------------------------------------------------
# (rule id, judge, mutation). Each row must refuse with exactly that rule.

NEGATIVE = [
    # strict JSON
    ("json.decode", "parent-chain", raw("chain.json", "{")),
    ("json.duplicate-key", "parent-chain", raw("chain.json", '{"callers": [], "callers": []}')),
    ("json.constant", "event-stdout", raw("full.json", '{"schema": NaN}')),
    # run binding (codex r9 #1: a stale report never passes)
    ("fresh.run", "event-stdout", lambda c: c.update(stamp_run_id="an-older-run")),
    ("fresh.run", "parent-chain", lambda c: c.update(stamp_cell="second-sigint")),
    ("fresh.file", "event-stdout", lambda c: c.update(age={"epipe.json": 10**9})),
    ("fresh.file", "event-stdout", lambda c: c.update(remove=["epipe.json"])),
    ("fresh.file", "run-prearm", lambda c: c.update(age={"run-prearm-held.txt": 1})),
    ("fresh.file", "second-sigint", raw("sigint2.json", b"\xff\xfe")),
    ("record.stamp", "event-stdout", lambda c: c.update(raw_stamp=True)),
    ("arg.integer", "second-sigint", arg("rc", "130.0")),
    ("arg.integer", "cgroup-inventory", arg("inside-pid", "4194305")),
    # second SIGINT
    ("record.observed-profile", "second-sigint", at(("report", "schema"), "p11scope/observed-profile/v2")),
    ("record.profile-evidence", "second-sigint", at(("report", "evidence", "drain_proven"), 1)),
    ("record.stop-quiescence", "second-sigint", at(("report", "evidence", "stop_quiescence", "state"), None)),
    ("sigint.exit", "second-sigint", arg("rc", "0")),
    ("sigint.custody", "second-sigint", arg("custody", "0")),
    ("sigint.custody", "second-sigint", arg("cleanup", "0")),
    ("sigint.partial", "second-sigint", at(("report", "evidence", "completeness"), "COMPLETE")),
    ("sigint.drain-proof", "second-sigint", at(("report", "evidence", "drain_proven"), False)),
    ("sigint.drain-samples", "second-sigint",
     at(("report", "evidence", "scheduling", "inter_drain_gap", "samples"), 0)),
    ("sigint.drain-samples", "second-sigint",
     at(("report", "evidence", "scheduling", "inter_drain_gap", "samples"), 3.0)),
    ("sigint.child-settled", "second-sigint", at(("report", "evidence", "child_still_running"), None)),
    # codex r9 #5: the cleanup line is one exact full line, once
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "p11scope: cleanup incomplete\n" * 2)),
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "xp11scope: cleanup incomplete\n")),
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "p11scope: cleanup incomplete.\n")),
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "p11scope: cleanup incomplete \n")),
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "")),
    ("sigint.no-panic", "second-sigint",
     at(("stderr",), "p11scope: cleanup incomplete\nthread 'main' panicked at src/x.rs\n")),
    # FIFO refusal
    ("fifo.exit", "fifo-refusal", arg("rc", "124")),
    ("fifo.kept", "fifo-refusal", lambda c: c.update(fifo=False)),
    ("fifo.refusal-line", "fifo-refusal", lambda c: c.update(stderr=Q.FIFO_REFUSAL + "\n" + Q.FIFO_REFUSAL + "\n")),
    ("fifo.refusal-line", "fifo-refusal", lambda c: c.update(stderr="p11scope: " + Q.FIFO_REFUSAL + "\n")),
    # cgroup.procs membership (codex r9 #5)
    ("cgroup.procs-lines", "cgroup-member", lambda c: c.update(procs="(100)\n")),
    ("cgroup.procs-lines", "cgroup-member", lambda c: c.update(procs="100 \n")),
    ("cgroup.procs-lines", "cgroup-member", lambda c: c.update(procs="0100\n")),
    ("cgroup.procs-once", "cgroup-member", lambda c: c.update(procs="1000\n10\n")),
    ("cgroup.procs-once", "cgroup-member", lambda c: c.update(procs="100\n100\n")),
    ("cgroup.procs-once", "cgroup-member", lambda c: c.update(procs="")),
    # event stdout (codex r9 #3)
    ("record.event-row", "event-stdout", chain(stream_row(1, seq=True))),
    ("record.event-row", "event-stdout", stream_row(1, at_ns=2**64)),
    ("record.event-row", "event-stdout", stream_row(1, extra=1)),
    ("record.pass-committed", "event-stdout", stream_event(1, **{"pass": 0.0})),
    ("record.pass-totals", "event-stdout", lambda c: c["stream"][1]["event"]["totals"].update(callers=True)),
    ("record.totals-event", "event-stdout", stream_event(2, passes=1.0)),
    ("record.stdout-lost", "event-stdout", stream_event(2, stdout_lost={"lines": 0, "bytes": 0.0})),
    ("record.stdout-lost", "event-stdout", stream_event(2, stdout_lost={"lines": 0, "bytes": 0, "x": 0})),
    ("record.ended-event", "event-stdout", stream_event(-1, passes=False)),
    ("record.inventory-document", "event-stdout", at(("report", "edges"), {})),
    ("record.observation", "event-stdout", at(("report", "observation", "passes"), 2.0)),
    ("record.early-close-document", "event-stdout", at(("epipe", "schema"), None)),
    ("record.event-output", "event-stdout", at(("epipe", "event_output", "lines_lost"), 2**64)),
    ("record.event-output", "event-stdout", at(("epipe", "event_output", "bytes_lost"), 5660.0)),
    ("record.event-output", "event-stdout", at(("report", "event_output", "lines_lost"), False)),
    ("record.event-output", "event-stdout", at(("report", "event_output", "reason"), "elsewhere")),
    ("record.event-output", "event-stdout", lambda c: c["epipe"].pop("event_output")),
    ("event.full-exit", "event-stdout", arg("rc1", "1")),
    ("event.jsonl", "event-stdout", raw("events.jsonl", "\n")),
    ("event.jsonl", "event-stdout", raw("events.jsonl", '{"a": 1}')),
    ("event.seq", "event-stdout", stream_row(2, seq=5)),
    ("event.framing", "event-stdout", stream_row(0, kind="bogus")),
    ("event.framing", "event-stdout", lambda c: c.update(stream=[c["stream"][0], c["stream"][-1]])),
    ("event.report-passes", "event-stdout", at(("report", "observation", "passes"), 3)),
    ("event.report-totals", "event-stdout", at(("report", "callers"), [{}, {}])),
    ("event.report-totals", "event-stdout", chain(
        lambda c: c.update(stream=[r for r in c["stream"] if r["kind"] != "pass_committed"]), resequence)),
    ("event.totals-count", "event-stdout", chain(
        lambda c: c.update(stream=[r for r in c["stream"] if r["kind"] != "totals"]), resequence)),
    ("event.totals-marker", "event-stdout", stream_event(2, callers=9)),
    ("event.totals-marker", "event-stdout", stream_event(4, **{"pass": 0, "passes": 1})),
    ("event.totals-marker", "event-stdout", chain(
        lambda c: c["stream"].insert(1, copy.deepcopy(c["stream"][2])), resequence)),
    ("event.totals-cadence", "event-stdout", stream_row(2, at_ns=STARTED + INTERVAL - 1)),
    ("event.full-no-loss", "event-stdout", stream_event(2, stdout_lost={"lines": 1, "bytes": 80})),
    ("event.full-no-loss", "event-stdout", stream_event(-1, stdout_lost={"lines": 0, "bytes": 1})),
    ("event.full-no-loss", "event-stdout", stream_event(-1, stdout_lost={"lines": False, "bytes": 0.0})),
    ("event.full-no-loss", "event-stdout", lambda c: c["stream"][-1]["event"].pop("stdout_lost")),
    ("event.full-output", "event-stdout", at(("report", "event_output"),
                                             {"status": "truncated", "lines_lost": 1, "bytes_lost": 9,
                                              "reason": "slow_reader"})),
    ("event.full-output", "event-stdout", at(("report", "event_output"),
                                             {"status": "complete", "lines_lost": 0, "bytes_lost": 1,
                                              "reason": "none"})),
    ("event.early-exit", "event-stdout", arg("rc2", "0")),
    ("event.early-head", "event-stdout", lambda c: c.update(head="")),
    ("event.early-output", "event-stdout", at(("epipe", "event_output"),
                                              {"status": "complete", "lines_lost": 0, "bytes_lost": 0,
                                               "reason": "none"})),
    ("event.early-output", "event-stdout", at(("epipe", "event_output", "reason"), "slow_reader")),
    ("event.early-output", "event-stdout", at(("epipe", "event_output", "lines_lost"), 0)),
    ("event.early-output", "event-stdout", at(("epipe", "event_output", "bytes_lost"), 5)),
    ("event-output.consistent", "direct", lambda: Q.check_event_output_consistent(
        {"status": "failed", "lines_lost": 0, "bytes_lost": 0, "reason": "none"}, "x")),
    ("event-output.consistent", "direct", lambda: Q.check_event_output_consistent(
        {"status": "truncated", "lines_lost": 2, "bytes_lost": 1, "reason": "broken_pipe"}, "x")),
    ("event-output.consistent", "direct", lambda: Q.check_event_output_consistent(
        {"status": "complete", "lines_lost": 0, "bytes_lost": 0, "reason": "unknown"}, "x")),
    # cgroup inventory: records
    ("record.cgroup-report", "cgroup-inventory", at(("report", "schema"), "p11scope/inventory/v0")),
    ("record.cgroup-report", "cgroup-inventory", at(("report", "gaps"), None)),
    ("record.caller", "cgroup-inventory", caller(0, pid=100.0)),
    ("record.caller", "cgroup-inventory", caller(1, start_time=2**64)),
    ("record.caller-image", "cgroup-inventory", caller(0, image={"authority": 1})),
    ("record.module", "cgroup-inventory", at(("report", "modules", 0, "id"), 0)),
    ("record.module-identity", "cgroup-inventory", at(("report", "modules", 0, "identity", "inode"), 153887.0)),
    ("record.module-device", "cgroup-inventory",
     at(("report", "modules", 0, "identity", "device", "major"), False)),
    ("record.module-admission", "cgroup-inventory", at(("report", "modules", 0, "admission"), {})),
    ("record.edge", "cgroup-inventory", at(("report", "edges", 0, "caller"), None)),
    ("record.edge-entries", "cgroup-inventory", edge_entries(0, count=1507.0)),
    ("record.edge-coverage", "cgroup-inventory", edge_entries(0, coverage={"state": "counted"})),
    ("record.gap", "cgroup-inventory", add_gaps({"caller": None, "pid": 0, "module": None,
                                                 "subject": "s", "reason": None})),
    ("record.provider-pin", "cgroup-inventory", at(("pin", "ino"), "153887")),
    ("record.provider-pin", "cgroup-inventory", at(("pin", "dev"), [0, 46, 1])),
    ("record.inside-ledger", "cgroup-inventory", ledger_fn("inside", None, None, {"extra": 1})),
    ("record.inside-ledger-function", "cgroup-inventory", ledger_fn("inside", 0, "name", 1)),
    ("record.outside-ledger", "cgroup-inventory", ledger_fn("outside", None, "pid", 102.0)),
    ("record.outside-ledger-function", "cgroup-inventory", ledger_fn("outside", 2, "x", 1)),
    # cgroup inventory: workload protocol (codex r9 #2)
    ("workload.protocol", "cgroup-inventory", lambda c: c["inside"].insert(1, "READY pid=100")),
    ("workload.protocol", "cgroup-inventory", lambda c: c["inside"].__setitem__(1, "CHILD pid=0101")),
    ("workload.protocol", "cgroup-inventory", lambda c: c["outside"].__setitem__(0, "READY pid=4194305")),
    ("workload.ledger-line", "cgroup-inventory", lambda c: c["outside"].pop()),
    ("workload.ledger-line", "cgroup-inventory", lambda c: c["inside"].append(c["inside"][-1])),
    ("workload.distinct", "cgroup-inventory", chain(
        lambda c: c["inside"].__setitem__(1, "CHILD pid=100"), arg("child-pid", "100"))),
    ("workload.distinct", "cgroup-inventory", chain(
        lambda c: c["outside"].__setitem__(0, "READY pid=101"), arg("outside-pid", "101"))),
    ("workload.launched", "cgroup-inventory", arg("inside-pid", "99")),
    ("workload.launched", "cgroup-inventory", arg("outside-pid", "99")),
    ("workload.launched", "cgroup-inventory", arg("child-pid", "")),
    ("workload.launched", "cgroup-inventory", arg("child-pid", "102")),
    ("workload.launched", "cgroup-inventory", ledger_fn("inside", None, "pid", 101)),
    ("workload.generation", "cgroup-inventory", arg("child-gen", "")),
    ("workload.generation", "cgroup-inventory", arg("inside-gen", "5000.0")),
    # cgroup inventory: relations
    ("cgroup.scope", "cgroup-inventory", at(("report", "scope"), "pid")),
    ("cgroup.unique-ids", "cgroup-inventory", caller(1, id="c0")),
    ("cgroup.owned-module", "cgroup-inventory", at(("pin", "sha256"), "00")),
    ("cgroup.owned-admission", "cgroup-inventory", at(("report", "modules", 0, "admission", "state"), "refused")),
    ("ledger.complete", "cgroup-inventory", ledger_fn("inside", None, "complete", 1)),
    ("ledger.complete", "cgroup-inventory", ledger_fn("outside", None, "complete", False)),
    ("ledger.functions", "cgroup-inventory", ledger_fn("inside", 5, "name", "C_Logout")),
    ("ledger.functions", "cgroup-inventory", ledger_fn("outside", 0, "name", "C_Digest")),
    ("ledger.successes", "cgroup-inventory", ledger_fn("inside", 0, "successful", 499)),
    ("ledger.successes", "cgroup-inventory", ledger_fn("outside", 0, "successful", 500.0)),
    ("ledger.inside-attempts", "cgroup-inventory", ledger_fn("inside", 3, "attempts", 500.0)),
    ("ledger.inside-attempts", "cgroup-inventory", chain(
        *[ledger_fn("inside", n, "attempts", 501) for n in range(6)],
        *[ledger_fn("inside", n, "successful", 501) for n in range(6)])),
    ("ledger.inside-attempts", "cgroup-inventory", arg("inside-iters", "249")),
    ("ledger.outside-attempts", "cgroup-inventory", arg("outside-iters", "400")),
    ("ledger.outside-attempts", "cgroup-inventory", chain(
        ledger_fn("outside", 1, "attempts", -1), ledger_fn("outside", 1, "successful", -1))),
    ("cgroup.outside-excluded", "cgroup-inventory", lambda c: c["report"]["callers"].append(
        {"id": "c9", "pid": 102, "start_time": 1, "start_time_unit": "clock_ticks_since_boot",
         "retired": False, "image": {"authority": "native_exact"}})),
    ("cgroup.inside-edge", "cgroup-inventory", lambda c: c["report"].update(edges=[])),
    ("cgroup.no-extra-caller", "cgroup-inventory", lambda c: c["report"]["callers"].append(
        {"id": "c9", "pid": 555, "start_time": 1, "start_time_unit": "clock_ticks_since_boot",
         "retired": False, "image": {"authority": "native_exact"}})),
    ("cgroup.member-once", "cgroup-inventory", lambda c: c["report"]["callers"].append(
        dict(c["report"]["callers"][1], id="c9"))),
    ("cgroup.member-once", "cgroup-inventory", lambda c: c["report"]["callers"].pop()),
    ("cgroup.no-orphan-edge", "cgroup-inventory", lambda c: c["report"]["edges"].append(
        {"caller": "c7", "module": "m0", "entries": entries()})),
    ("gap.unclassified", "cgroup-inventory", add_gaps(gap(subject="made up"))),
    ("gap.unclassified", "cgroup-inventory", add_gaps(gap(module="m0", subject="made up"))),
    ("gap.activation", "cgroup-inventory", add_gaps(dict(ACTIVATION_GAP, subject="other"))),
    ("gap.activation", "cgroup-inventory", add_gaps(dict(ACTIVATION_GAP, pid=101))),
    ("gap.activation", "cgroup-inventory", add_gaps(gap(subject=Q.ACTIVATION, reason="else"))),
    ("gap.retained", "cgroup-inventory", add_gaps(RETAINED_GAP)),
    ("gap.retained", "cgroup-inventory", add_gaps(RETAINED_GAP, RETAINED_GAP, DEADLINE_GAP)),
    ("gap.retained", "cgroup-inventory", add_gaps(dict(RETAINED_GAP, caller="c9"), DEADLINE_GAP)),
    ("gap.deadline", "cgroup-inventory", add_gaps(dict(DEADLINE_GAP, pid=100))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(ADMISSION_GAP, reason=MODPATH + ": admission changed from x"))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(ADMISSION_GAP, module=None))),
    ("gap.unproven-cover", "overlay", lambda c: c["report"]["gaps"].pop()),
    ("gap.unproven-cover", "overlay", lambda c: c["report"]["gaps"].__setitem__(
        0, dict(c["report"]["gaps"][0], subject="/other.so"))),
    ("gap.unproven-cover", "overlay", lambda c: c["report"]["gaps"].__setitem__(
        0, dict(c["report"]["gaps"][0], pid=101))),
    ("gap.unproven-cover", "overlay", lambda c: c["report"]["gaps"].__setitem__(
        0, dict(c["report"]["gaps"][0], module="m0"))),
    ("cgroup.generation", "cgroup-inventory", arg("inside-gen", "5001")),
    ("cgroup.generation", "cgroup-inventory", caller(1, start_time_unit="ns")),
    ("cgroup.live", "cgroup-inventory", caller(1, retired=True)),
    ("cgroup.authority", "cgroup-inventory", caller(1, image={"authority": "scan_pinned"})),
    ("cgroup.owned-edge", "cgroup-inventory", lambda c: c["report"]["edges"].pop()),
    ("cgroup.owned-edge", "cgroup-inventory", lambda c: c["report"]["edges"].append(
        {"caller": "c0", "module": "m9", "entries": entries()})),
    ("cgroup.exact-count", "cgroup-inventory", edge_entries(1, count=DRIVEN - 1)),
    ("cgroup.exact-count", "cgroup-inventory", edge_entries(1, saturated=True)),
    ("cgroup.exact-count", "cgroup-inventory", edge_entries(1, coverage={"state": "counted", "lossy": None})),
    # run pre-arm (codex r9 #4: exactly one EVIDENCE per report)
    ("prearm.release", "run-prearm", arg("kernel-release", "linux")),
    ("prearm.evidence-once", "run-prearm", lambda c: c["held_evidence"].insert(0, prearm_evidence(PRE_ATTACH))),
    ("prearm.evidence-once", "run-prearm", lambda c: c["held_evidence"].append(prearm_evidence(PRE_ATTACH))),
    ("prearm.evidence-once", "run-prearm", lambda c: c["passive_evidence"].insert(0, prearm_evidence([]))),
    ("prearm.evidence-once", "run-prearm", lambda c: c["passive_evidence"].append(prearm_evidence([]))),
    ("prearm.evidence-once", "run-prearm", lambda c: c.update(passive_evidence=[])),
    ("record.prearm-evidence", "run-prearm", evidence("held", {"discovery": {}})),
    ("record.prearm-module", "run-prearm", prearm_module("held", attached_at_ns=50.0)),
    ("record.unobserved-window", "run-prearm", prearm_module(
        "passive", unobserved_windows=[{"start_ns": 10, "end_ns": 50, "reason": "pre_attach", "x": 1}])),
    ("record.prearm-pair", "run-prearm", lambda c: c["held_ledger"][0].update(pair=True)),
    ("record.prearm-summary", "run-prearm", lambda c: c["passive_ledger"][-1].update(initializes=3.0)),
    ("prearm.one-prearmed", "run-prearm", lambda c: c["held_evidence"][0]["discovery"][0]["sources"].append("prearm")),
    ("prearm.scan-source", "run-prearm", prearm_module("held", sources=["prearm"])),
    ("prearm.scan-source", "run-prearm", prearm_module("passive", sources=["prearm"])),
    ("prearm.attached", "run-prearm", prearm_module("held", attached_at_ns=None)),
    ("prearm.attached", "run-prearm", chain(arg("kernel-release", "6.6.0"),
                                             prearm_module("passive", attached_at_ns=None))),
    ("prearm.held-windows", "run-prearm", prearm_module("held", unobserved_windows=PRE_ATTACH)),
    ("prearm.held-windows", "run-prearm", chain(arg("kernel-release", "6.6.0"),
                                                 prearm_module("held", unobserved_windows=PRE_ATTACH))),
    ("prearm.passive-window", "run-prearm", prearm_module("passive", attached_at_ns=51)),
    ("prearm.passive-window", "run-prearm", prearm_module("passive", unobserved_windows=[])),
    ("prearm.handoff-pair", "run-prearm", chain(arg("kernel-release", "6.6.0"), prearm_module(
        "held", unobserved_windows=[dict(HANDOFF[0], end_ns=49), HANDOFF[1]]))),
    ("prearm.handoff-pair", "run-prearm", chain(arg("kernel-release", "6.6.0"), prearm_module(
        "passive", unobserved_windows=[HANDOFF[0], dict(HANDOFF[1], start_ns=11)]))),
    ("prearm.handoff-pair", "run-prearm", chain(arg("kernel-release", "6.6.0"), prearm_module(
        "passive", unobserved_windows=[HANDOFF[0], dict(HANDOFF[1], end_ns=9)]))),
    ("prearm.handoff-pair", "direct", lambda: Q.assert_handoff_pair(
        {"attached_at_ns": 50, "unobserved_windows": PRE_ATTACH})),
    ("prearm.ledger", "run-prearm", lambda c: c["held_ledger"].pop(0)),
    ("prearm.ledger", "run-prearm", lambda c: c["passive_ledger"][-1].update(finalizes=2)),
    ("prearm.ledger", "run-prearm", lambda c: c.update(held_ledger=[])),
    ("prearm.trace-counts", "run-prearm", lambda c: c.update(held=trace_lines((3, 3, 2)))),
    ("prearm.trace-counts", "run-prearm", lambda c: c.update(held=trace_lines((2, 3, 1)))),
    # parent chain (codex r9 #3)
    ("record.chain-report", "parent-chain", at(("report", "callers"), {})),
    ("record.chain-report-caller", "parent-chain", at(("report", "callers", 1, "pid"), float(WL))),
    ("record.chain-report-caller", "parent-chain", at(("report", "callers", 0, "start_time"), True)),
    ("record.chain-caller", "parent-chain", chain_caller(launched_by_origin=1)),
    ("record.chain-gap", "parent-chain", chain_caller(launched_by_gap={"subject": 1, "reason": "r"})),
    ("chain.workload-once", "parent-chain", lambda c: c["report"]["callers"].append(
        copy.deepcopy(c["report"]["callers"][1]))),
    ("chain.workload-once", "parent-chain", arg("workload-pid", "301")),
    ("chain.generation", "parent-chain", arg("workload-gen", "9001")),
    ("chain.walk", "parent-chain", chain_caller(launched_by={"pid": PARENT})),
    ("chain.walk", "parent-chain", chain_caller(launched_by=[])),
    ("chain.named-parent", "parent-chain", ancestor(0, pid=float(PARENT))),
    ("chain.named-parent", "parent-chain", ancestor(0, start_time=float(PARENT_GEN))),
    ("chain.named-parent", "parent-chain", ancestor(0, exe="sh")),
    ("chain.named-parent", "parent-chain", arg("parent-gen", "1")),
    ("chain.ancestor", "parent-chain", ancestor(1, pid=50.0)),
    ("chain.ancestor", "parent-chain", ancestor(1, start_time=True)),
    ("chain.ancestor", "parent-chain", ancestor(1, folded=-1)),
    ("chain.no-init", "parent-chain", ancestor(1, pid=1)),
    ("chain.origin", "parent-chain", chain_caller(launched_by_origin="unit")),
    ("chain.origin", "parent-chain", chain_caller(launched_by_unit="cron.service")),
    ("chain.gap", "parent-chain", chain_caller(launched_by_gap={"subject": "other",
                                                                 "reason": "launcher exited before read"})),
    ("chain.gap", "parent-chain", chain_caller(launched_by_gap={"subject": "caller parent chain",
                                                                 "reason": "made up"})),
    ("chain.text", "parent-chain", lambda c: c.update(concise="gated\n")),
    ("chain.text", "parent-chain", lambda c: c.update(verbose="gated\n")),
    # run binding: the stamp, then every input (class: a reused, linked,
    # oversized or foreign input never stands for this run's evidence)
    ("record.stamp", "event-stdout", lambda c: c.update(stamp_text=json.dumps(
        {"schema": Q.STAMP_SCHEMA, "run_id": 1, "cell": "inventory-event-stdout"}))),
    ("record.stamp", "event-stdout", lambda c: c.update(stamp_text=json.dumps(
        {"schema": Q.STAMP_SCHEMA, "run_id": RUN_ID, "cell": None}))),
    ("fresh.run", "event-stdout", lambda c: c.update(stamp_dir=True)),
    ("fresh.run", "event-stdout", lambda c: c.update(stamp_run_id="", run_id="")),
    ("fresh.file", "event-stdout", lambda c: c.update(symlink=["full.json"])),
    ("fresh.file", "event-stdout", lambda c: c.update(sparse={"full.json": Q.MAX_INPUT_BYTES + 1})),
    ("json.decode", "event-stdout", lambda c: c.update(sparse={"full.json": Q.MAX_INPUT_BYTES})),
    # second SIGINT and FIFO boundaries
    ("fifo.exit", "fifo-refusal", arg("rc", "125")),
    ("fifo.exit", "fifo-refusal", arg("rc", "0")),
    ("fifo.kept", "fifo-refusal", lambda c: c.update(fifo="regular")),
    # event stdout: framing, cadence and marker relations, one row per site
    ("event.totals-count", "event-stdout", drop_rows("totals")),
    ("event.totals-count", "event-stdout", chain(drop_rows("totals"), lambda c: c["stream"].__delitem__(2),
                                                  resequence, stream_event(-1, passes=1),
                                                  at(("report", "observation", "passes"), 1))),
    ("event.totals-count", "event-stdout", totals_case(5)),
    ("event.framing", "event-stdout", lambda c: c.update(stream=c["stream"][:2])),
    ("event.framing", "event-stdout", lambda c: c["stream"].pop()),
    ("event.totals-marker", "event-stdout", stream_event(2, passes=5)),
    ("event.totals-marker", "event-stdout", stream_event(2, modules=9)),
    ("event.totals-marker", "event-stdout", stream_event(2, edges=9)),
    ("event.report-totals", "event-stdout", at(("report", "modules"), [{}, {}])),
    ("event.report-totals", "event-stdout", at(("report", "edges"), [])),
    ("event.early-output", "event-stdout", at(("epipe", "event_output"), {
        "status": "failed", "lines_lost": 6, "bytes_lost": 5660, "reason": "broken_pipe"})),
    # cgroup inventory: one row per relation site
    ("record.provider-pin", "cgroup-inventory", at(("pin", "dev"), [0])),
    ("record.inside-ledger", "cgroup-inventory", ledger_edit("inside", lambda r: r.pop("complete"))),
    ("workload.launched", "cgroup-inventory", chain(lambda c: c["inside"].__setitem__(1, "CHILD pid=1"),
                                                    arg("child-pid", ""))),
    ("cgroup.unique-ids", "cgroup-inventory", lambda c: c["report"]["modules"].append(
        copy.deepcopy(c["report"]["modules"][0]))),
    ("cgroup.owned-admission", "cgroup-inventory",
     at(("report", "modules", 0, "admission", "state"), "unresolved")),
    ("cgroup.owned-admission", "overlay", at(("report", "modules", 0, "admission", "state"), "refused")),
    ("ledger.inside-attempts", "cgroup-inventory", ledger_edit("inside", lambda r: r["functions"].pop())),
    ("ledger.inside-attempts", "cgroup-inventory", all_attempts("inside", 500.0, 500)),
    ("ledger.inside-attempts", "cgroup-inventory", chain(all_attempts("inside", 2**64, 2**64),
                                                         arg("inside-iters", str(2**63)))),
    ("ledger.outside-attempts", "cgroup-inventory", all_attempts("outside", 500.0, 500)),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason="X" + MODPATH[1:] + ": admission changed from unresolved to admitted"))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason=ADMISSION_GAP["reason"] + " ()"))),
    ("gap.unproven-cover", "overlay", lambda c: c["report"].update(gaps=[])),
    ("gap.unproven-cover", "cgroup-inventory", add_gaps(gap(caller="c0", pid=100, subject=MODPATH,
                                                            reason=Q.UNPROVEN))),
    ("gap.activation", "cgroup-inventory", chain(add_gaps(ACTIVATION_GAP),
                                                 caller(0, image={"authority": "scan_pinned"}))),
    ("gap.retained", "cgroup-inventory", add_gaps(dict(RETAINED_GAP, subject="other"), DEADLINE_GAP)),
    ("gap.deadline", "cgroup-inventory", add_gaps(dict(DEADLINE_GAP, subject="other"))),
    ("gap.deadline", "cgroup-inventory", add_gaps(dict(DEADLINE_GAP, caller="c0"))),
    ("gap.deadline", "cgroup-inventory", add_gaps(dict(DEADLINE_GAP, module="m0"))),
    ("cgroup.owned-edge", "cgroup-inventory", lambda c: c["report"]["edges"][1].update(module="m9")),
    # run pre-arm: the kernel split and each window site
    ("prearm.release", "run-prearm", arg("kernel-release", "6")),
    ("prearm.release", "run-prearm", arg("kernel-release", "6.x")),
    ("prearm.held-windows", "run-prearm", chain(arg("kernel-release", "6.8.0"),
                                                 prearm_module("held", unobserved_windows=HANDOFF))),
    ("prearm.held-windows", "run-prearm", prearm_module("held", unobserved_windows=HANDOFF)),
    ("prearm.passive-window", "run-prearm", prearm_module("passive", unobserved_windows=HANDOFF)),
    ("prearm.passive-window", "run-prearm", prearm_module(
        "passive", unobserved_windows=[dict(PRE_ATTACH[0], reason="late_discovery")])),
    # parent chain: walk bounds and the named parent's identity
    ("chain.walk", "parent-chain", chain_caller(launched_by=[
        {"pid": PARENT, "exe": "chain-parent", "start_time": PARENT_GEN}] + [
        {"pid": 50 + n, "exe": "sh", "start_time": 70 + n} for n in range(4)])),
    ("chain.named-parent", "parent-chain", ancestor(0, pid=PARENT - 1)),
    ("record.chain-caller", "parent-chain", chain_caller(launched_by_unit=1)),
]

# Positive rows beyond each judge's valid base case: (rule, judge, mutation).
POSITIVE = [
    ("gap.activation", "cgroup-inventory", add_gaps(ACTIVATION_GAP)),
    ("gap.activation", "cgroup-inventory", add_gaps(dict(ACTIVATION_GAP, reason=Q.DEFERRED_REASON))),
    ("gap.retained", "cgroup-inventory", add_gaps(RETAINED_GAP, DEADLINE_GAP)),
    ("gap.deadline", "cgroup-inventory", add_gaps(DEADLINE_GAP)),
    ("gap.admission-note", "cgroup-inventory", add_gaps(ADMISSION_GAP)),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason=ADMISSION_GAP["reason"] + " (refresh)"))),
    ("gap.unclassified", "cgroup-inventory", add_gaps(UNBOUND_GAP)),
    ("cgroup.owned-admission", "overlay", at(("report", "modules", 0, "admission", "state"), "unresolved")),
    ("prearm.handoff-pair", "run-prearm", chain(
        arg("kernel-release", "6.6.0"), prearm_module("held", unobserved_windows=HANDOFF),
        prearm_module("passive", unobserved_windows=HANDOFF))),
] + [("chain.gap", "parent-chain", chain_caller(launched_by_gap={"subject": "caller parent chain", "reason": r}))
     for r in Q.CHAIN_GAP_REASONS] + [
    ("chain.ancestor", "parent-chain", ancestor(1, exe=None, label="bash", folded=2, exe_gap="hidden")),
    ("cgroup.procs-once", "cgroup-member", lambda c: c.update(procs="100")),
    ("sigint.cleanup-line", "second-sigint", at(("stderr",), "a\np11scope: cleanup incomplete")),
    ("event-output.consistent", "event-stdout", at(("epipe", "event_output", "lines_lost"), 1)),
    ("fresh.file", "event-stdout", lambda c: c.update(age={"events.jsonl": 0, "full.json": 0})),
    ("sigint.drain-samples", "second-sigint",
     at(("report", "evidence", "scheduling", "inter_drain_gap", "samples"), 1)),
    ("event-output.consistent", "event-stdout", at(("epipe", "event_output"), {
        "status": "truncated", "lines_lost": 1, "bytes_lost": 1, "reason": "broken_pipe"})),
    ("event.totals-count", "event-stdout", totals_case(4)),
    ("event.totals-count", "event-stdout", totals_case(1)),
    ("event.report-totals", "event-stdout", chain(
        lambda c: c["stream"][1]["event"]["totals"].update(callers=2), stream_event(2, callers=2))),
    ("workload.protocol", "cgroup-inventory", chain(
        lambda c: c.update(outside=["READY pid=4194304", "LEDGER " + json.dumps(ledger(4194304, OUT_ITERS))]),
        arg("outside-pid", "4194304"))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason=ADMISSION_GAP["reason"] + " (r)"))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason=MODPATH + ": admission changed from unresolved to refused"))),
    ("gap.admission-note", "cgroup-inventory", add_gaps(dict(
        ADMISSION_GAP, reason=MODPATH + ": admission changed from refused to admitted"))),
    ("gap.deadline", "overlay", add_gaps(DEADLINE_GAP)),
    ("prearm.held-windows", "run-prearm", arg("kernel-release", "6.6.0")),
    ("prearm.release", "run-prearm", arg("kernel-release", "6.7-rc1")),
    ("prearm.handoff-pair", "run-prearm", chain(
        arg("kernel-release", "6.6.0"),
        prearm_module("held", unobserved_windows=[HANDOFF[0], dict(HANDOFF[1], end_ns=10)]))),
    ("chain.walk", "parent-chain", chain_caller(launched_by=[
        {"pid": PARENT, "exe": "chain-parent", "start_time": PARENT_GEN}] + [
        {"pid": 50 + n, "exe": "sh", "start_time": 70 + n} for n in range(3)])),
]


def base(judge):
    case = cgroup_case("overlayfs") if judge == "overlay" else BUILDERS[judge]()
    return copy.deepcopy(case)


def build(judge, mutate):
    case = base(judge)
    mutate(case)
    return copy.deepcopy(case)


def stamp_record_case(case):
    """A stamp with an unknown key (the stamp record is closed)."""
    def before(tmp):
        path = tmp / "cell.stamp"
        text = json.loads(path.read_text())
        text["extra"] = 1
        info = os.stat(path)
        path.write_text(json.dumps(text))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    return before


class RuleTableTests(unittest.TestCase):
    def test_every_declared_rule_has_a_negative_and_a_positive(self):
        negatives = {rule for rule, _, _ in NEGATIVE}
        positives = set()
        for judge in list(BUILDERS) + ["overlay"]:
            positives |= run_case(base(judge))[1]
        for rule, judge, mutate in POSITIVE:
            positives |= run_case(build(judge, mutate))[1]
        self.assertEqual(sorted(set(Q.RULES) - negatives), [], "rules without a negative row")
        self.assertEqual(sorted(set(Q.RULES) - positives), [], "rules never evaluated and held")
        self.assertEqual(sorted(negatives - set(Q.RULES)), [], "rows for undeclared rules")

    def test_valid_cases_pass(self):
        for judge in list(BUILDERS) + ["overlay"]:
            with self.subTest(judge=judge):
                record, _ = run_case(base(judge))
                self.assertEqual(record["verdict"], "pass", record)
                self.assertIsNone(record["rule"])

    def test_positive_rows_hold_their_rule(self):
        for rule, judge, mutate in POSITIVE:
            with self.subTest(rule=rule):
                record, held = run_case(build(judge, mutate))
                self.assertEqual(record["verdict"], "pass", record)
                self.assertIn(rule, held)

    def test_negative_rows_refuse_with_their_rule(self):
        for number, (rule, judge, mutate) in enumerate(NEGATIVE):
            with self.subTest(row=number, rule=rule):
                if judge == "direct":
                    with self.assertRaises(Q.Refusal) as raised:
                        mutate()
                    self.assertEqual(raised.exception.rule, rule)
                    continue
                case = build(judge, mutate)
                before = stamp_record_case(case) if case.pop("raw_stamp", False) else None
                record, _ = run_case(case, before=before)
                self.assertEqual(record["schema"], "p11scope/qualify-verdict/v1")
                self.assertEqual((record["verdict"], record["rule"]), ("fail", rule), record["detail"])

    def test_missing_stamp_refuses(self):
        record, _ = run_case(base("parent-chain"), stamp=False)
        self.assertEqual(record["rule"], "fresh.run")


# -- field fuzz -----------------------------------------------------------------------------

def leaf_paths(value, prefix=()):
    """Every (path, value) under a JSON value, containers included."""
    out = [(prefix, value)]
    if type(value) is dict:
        for key, item in value.items():
            out += leaf_paths(item, prefix + (key,))
    elif type(value) is list:
        for index, item in enumerate(value):
            out += leaf_paths(item, prefix + (index,))
    return out


def replacements(value):
    """Wrong-type and range twins of one value (never the same JSON type
    and value)."""
    pool = [None, True, "x", [], {}, 1.5, -1, 2**64]
    out = []
    if type(value) is int:
        out += [float(value)]
        if value in (0, 1):
            out += [bool(value)]
    if type(value) is bool:
        out += [int(value)]
    for item in pool:
        if type(item) is not type(value) or (type(item) is int and item != value):
            out.append(item)
    return out


# JSON documents of each judge's valid case that the fuzz mutates.
DOCUMENTS = {
    "cgroup-inventory": [("report",), ("pin",)],
    "event-stdout": [("stream",), ("report",), ("epipe",)],
    "second-sigint": [("report",)],
    "run-prearm": [("held_evidence", 0), ("passive_evidence", 0), ("held_ledger",), ("passive_ledger",)],
    "parent-chain": [("report",)],
}

# A pattern is a path in which "*" stands for any list index.
def matches(pattern, path, prefix=False):
    if len(path) < len(pattern) or (not prefix and len(path) != len(pattern)):
        return False
    return all(p == "*" or p == q for p, q in zip(pattern, path))


# Survivors that are valid by contract, each with its reason
# (a pattern also covers every path under it).
ALLOWED = {
    # Payload fields of the started event and of counted report items are
    # not consumed (each payload is still typed as an object).
    ("event-stdout", ("stream", 0, "event", "*")): "started payload fields are not consumed",
    ("event-stdout", ("report", "callers", "*", "*")): "only the callers count is consumed",
    ("event-stdout", ("report", "modules", "*", "*")): "only the modules count is consumed",
    ("event-stdout", ("report", "edges", "*", "*")): "only the edges count is consumed",
    # Another discovery module's nullable attach stamp and free text.
    ("run-prearm", ("*", 0, "discovery", 0, "attached_at_ns")): "nullable by schema",
    ("run-prearm", ("*", 0, "discovery", 0, "sources", "*")): "free source name of another module",
    # A further ancestor's exe, its optional fields and the chain gap.
    ("parent-chain", ("report", "callers", 1, "launched_by", "*", "exe")): "a further ancestor's exe is nullable",
    ("parent-chain", ("report", "callers", 1, "launched_by", "*", "label")): "optional by schema",
    ("parent-chain", ("report", "callers", 1, "launched_by", "*", "folded")): "optional by schema",
    ("parent-chain", ("report", "callers", 1, "launched_by", "*", "exe_gap")): "optional by schema",
    ("parent-chain", ("report", "callers", 1, "launched_by_gap")): "a gap object is optional when the chain is whole",
}


def allowed(judge, path):
    return any(j == judge and matches(pattern, path, prefix=True) for j, pattern in ALLOWED)


# A replacement that stays inside the field's type (a null in a nullable
# field, another string) is decided by a relation rule, not by typing:
# (judge, path pattern, replacement).
VALUE_DECIDED = {
    ("cgroup-inventory", ("report", "modules", 0, "identity", "sha256"), None),
    ("cgroup-inventory", ("report", "edges", "*", "entries", "coverage", "lossy"), None),
    ("second-sigint", ("report", "evidence", "stop_quiescence", "post_q_events"), None),
    ("second-sigint", ("report", "evidence", "stop_quiescence", "post_q_discovery"), None),
    ("run-prearm", ("*", 0, "discovery", 1, "attached_at_ns"), None),
    ("parent-chain", ("report", "callers", 1, "launched_by", 0, "exe"), None),
    ("parent-chain", ("report", "callers", 1, "launched_by_unit"), "x"),
} | {("cgroup-inventory", ("report", "gaps", "*", key), item)
     for key in ("caller", "module", "reason") for item in (None, "x")} | {
    ("cgroup-inventory", ("report", "gaps", "*", "pid"), None)}


def value_decided(judge, path, item):
    return any(j == judge and matches(pattern, path) and type(item) is type(want) and item == want
               for j, pattern, want in VALUE_DECIDED)


# Closed records: an unknown key is a type-stage refusal there and is
# accepted (forward-compatible) everywhere else.
CLOSED = {
    ("event-stdout", ("stream", "*")),
    ("event-stdout", ("stream", "*", "event", "totals")),
    ("event-stdout", ("stream", "*", "event", "stdout_lost")),
    ("event-stdout", ("*", "event_output")),
    ("run-prearm", ("*", 0, "discovery", 1, "unobserved_windows", "*")),
    ("run-prearm", ("held_ledger", "*")),
    ("run-prearm", ("passive_ledger", "*")),
}


def closed(judge, path):
    return any(j == judge and matches(pattern, path) for j, pattern in CLOSED)


def lookup(value, path):
    for key in path:
        try:
            value = value[key]
        except (KeyError, IndexError, TypeError):
            return MISSING_PATH
    return value


MISSING_PATH = object()


def valid_fixtures():
    """Each judge's base case, then every positive row's case; a positive
    row's case is fuzzed where it differs from its base case."""
    out = [(judge, judge, base(judge), None) for judge in DOCUMENTS]
    out.append(("cgroup-inventory", "overlay", base("overlay"), base("cgroup-inventory")))
    for rule, judge, mutate in POSITIVE:
        if judge in DOCUMENTS or judge == "overlay":
            target = "cgroup-inventory" if judge == "overlay" else judge
            out.append((target, rule, build(judge, mutate), base(judge)))
    return out


class FieldFuzzTests(unittest.TestCase):
    def test_every_field_mutation_of_the_valid_fixtures_is_killed(self):
        killed = total = 0
        off = []
        for judge, name, valid, reference in valid_fixtures():
            for document in DOCUMENTS[judge]:
                for path, value in leaf_paths(lookup(valid, document)):
                    full = document + path
                    if not path or (reference is not None and lookup(reference, full) == value):
                        continue
                    mutations = [("delete", None)] if type(path[-1]) is str else []
                    mutations += [("set", item) for item in replacements(value)]
                    if type(value) is dict and value:
                        mutations.append(("extra", None))
                    if type(value) is bool:
                        mutations.append(("flip", not value))
                    for kind, item in mutations:
                        case = copy.deepcopy(valid)
                        target = lookup(case, full[:-1])
                        if kind == "delete":
                            del target[full[-1]]
                        elif kind in ("set", "flip"):
                            target[full[-1]] = copy.deepcopy(item)
                        else:
                            target[full[-1]]["unexpected_key"] = 0
                        total += 1
                        record, _ = run_case(case)
                        got = (record["verdict"], record["stage"])
                        if kind == "extra":
                            want = ("fail", "type") if closed(judge, full) else ("pass", None)
                        elif kind == "flip":
                            # Every consumed flag is decided: its flip is
                            # refused by a relation rule.
                            want = ("fail", "relation")
                        elif kind == "set" and value_decided(judge, full, item):
                            want = ("fail", "relation")
                        elif allowed(judge, full) and record["verdict"] == "pass":
                            want = got
                        else:
                            want = ("fail", "type")
                        if record["verdict"] == "fail":
                            killed += 1
                        if got != want:
                            off.append((name, full, kind, item, record["rule"], record["stage"]))
        print("\nfield fuzz: killed %d/%d (outcomes off the expected stage: %d)"
              % (killed, total, len(off)), file=sys.stderr)
        self.assertEqual(off, [])
        self.assertGreater(total, 2000)


# -- loader kernel: kinds, rules and argument bounds --------------------------------

U64_MAX = 2**64 - 1
# (judge, option, low, high): every numeric argument of every judge.
ARGUMENTS = [
    ("second-sigint", "rc", 0, 255), ("second-sigint", "custody", 0, 1), ("second-sigint", "cleanup", 0, 1),
    ("fifo-refusal", "rc", 0, 255), ("cgroup-member", "pid", 1, Q.PID_MAX),
    ("event-stdout", "rc1", 0, 255), ("event-stdout", "rc2", 0, 255),
    ("cgroup-inventory", "inside-iters", 1, U64_MAX), ("cgroup-inventory", "outside-iters", 1, U64_MAX),
    ("cgroup-inventory", "inside-pid", 1, Q.PID_MAX), ("cgroup-inventory", "outside-pid", 1, Q.PID_MAX),
    ("cgroup-inventory", "child-pid", 0, Q.PID_MAX),
    ("parent-chain", "workload-pid", 1, Q.PID_MAX), ("parent-chain", "workload-gen", 0, U64_MAX),
    ("parent-chain", "parent-pid", 1, Q.PID_MAX), ("parent-chain", "parent-gen", 0, U64_MAX),
]


def with_arg(judge, option, value):
    case = base(judge)
    case["args"][option] = str(value)
    return case


class LoaderKernelTests(unittest.TestCase):
    def test_every_numeric_argument_holds_its_exact_bounds(self):
        for judge, option, low, high in ARGUMENTS:
            for value, inside in ((low, True), (high, True), (low - 1, False), (high + 1, False)):
                with self.subTest(judge=judge, option=option, value=value):
                    record, _ = run_case(with_arg(judge, option, value))
                    self.assertEqual(record["rule"] == "arg.integer", not inside, record)

    def test_kinds_hold_their_exact_ranges(self):
        cases = [
            (Q.U64, 0, True), (Q.U64, U64_MAX, True), (Q.U64, -1, False), (Q.U64, 2**64, False),
            (Q.U64, True, False), (Q.U64, 1.0, False),
            (Q.PID, 1, True), (Q.PID, Q.PID_MAX, True), (Q.PID, 0, False), (Q.PID, Q.PID_MAX + 1, False),
            (Q.ListOf(Q.U64, 2, 2), [0, 1], True), (Q.ListOf(Q.U64, 2, 2), [0], False),
            (Q.ListOf(Q.U64, 2, 2), [0, 1, 2], False),
            (Q.Record("t", {"a": (Q.Anything(), "a")}, rule="record.stamp"), {}, False),
            (Q.Record("t", {"a": (Q.Anything(), "a")}, rule="record.stamp"), {"a": None}, True),
            (Q.OneOf("a"), "a", True), (Q.OneOf("a"), "b", False), (Q.OneOf("a"), ["a"], False),
        ]
        for kind, value, ok in cases:
            with self.subTest(kind=type(kind).__name__, value=value):
                try:
                    kind.check(value, "v", "record.stamp")
                    outcome = None
                except Q.Refusal as refusal:
                    outcome = (refusal.rule, refusal.stage)
                self.assertEqual(outcome, None if ok else ("record.stamp", "type"))

    def test_rules_are_declared_once_and_never_invented(self):
        with self.assertRaises(KeyError):
            Q.declare("fresh.run", "again")
        with self.assertRaises(KeyError):
            Q.require(True, "made.up", "x")
        with self.assertRaises(KeyError):
            Q.Refusal("made.up", "x")

    def test_event_output_consistency_per_status(self):
        ok = [("complete", 0, 0, "none"), ("failed", 0, 0, "event_log_error"),
              ("failed", 3, 90, "event_log_error")]
        ok += [("truncated", 1, 1, reason) for reason in Q.SHED_REASONS]
        bad = [("complete", 1, 1, "none"), ("complete", 0, 1, "none"), ("complete", 0, 0, "broken_pipe"),
               ("truncated", 0, 0, "broken_pipe"), ("truncated", 2, 1, "broken_pipe"),
               ("truncated", 1, 1, "none"), ("truncated", 1, 1, "event_log_error"),
               ("failed", 0, 0, "unknown"), ("failed", 0, 0, "broken_pipe")]
        for row, good in [(r, True) for r in ok] + [(r, False) for r in bad]:
            outcome = dict(zip(("status", "lines_lost", "bytes_lost", "reason"), row))
            with self.subTest(outcome=outcome):
                try:
                    Q.check_event_output_consistent(outcome, "x")
                    rule = None
                except Q.Refusal as refusal:
                    rule = refusal.rule
                self.assertEqual(rule, None if good else "event-output.consistent")


# -- shell side of run binding ----------------------------------------------------------------

def shell_function(name):
    text = QUAL.read_text()
    start = text.index("\n%s() {" % name) + 1
    first = text[start:text.index("\n", start)]
    if first.rstrip().endswith("}"):
        return first + "\n"
    end = text.index("\n}\n", start) + 3
    return text[start:end]


class ShellBindingTests(unittest.TestCase):
    """stamp_leg removes every destination and stamps; a seeded old
    report then never reaches a judge, in both output layouts."""

    def run_leg(self, local_same):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "out"
            local = out if local_same else Path(raw) / "local"
            out.mkdir()
            local.mkdir(exist_ok=True)
            for where in {out, local}:
                (where / "event-epipe.json").write_text(json.dumps(event_case()["epipe"]))
            body = ("set -u\nRECORDS=%s\nRUN_ID=%s\nOUT=%s\nLOCAL_OUTPUT=%s\n%s\n%s\n"
                    "cd \"$OUT\"\n"
                    "stamp_leg inventory-event-stdout \"$(product_output event-epipe.json)\" "
                    "\"$OUT/event-epipe.json\" || exit 9\n"
                    "ls -A \"$OUT\" \"$LOCAL_OUTPUT\"\n"
                    % (RECORDS, RUN_ID, out, local, shell_function("product_output"),
                       shell_function("stamp_leg")))
            proc = subprocess.run(["bash", "-c", body], capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse((out / "event-epipe.json").exists())
            self.assertFalse((local / "event-epipe.json").exists())
            self.assertTrue((out / "inventory-event-stdout.stamp").is_file())
            # The product wrote no report this run: the judge refuses.
            stamp = json.loads((out / "inventory-event-stdout.stamp").read_text())
            self.assertEqual((stamp["run_id"], stamp["cell"]), (RUN_ID, "inventory-event-stdout"))
            run = Q.Run(str(out / "inventory-event-stdout.stamp"), RUN_ID, "inventory-event-stdout")
            with self.assertRaises(Q.Refusal) as raised:
                run.read(str(local / "event-epipe.json"), "early-close report")
            self.assertEqual(raised.exception.rule, "fresh.file")

    def test_seeded_old_report_is_removed_in_the_shared_layout(self):
        self.run_leg(True)

    def test_seeded_old_report_is_removed_in_the_split_layout(self):
        self.run_leg(False)

    def test_stamp_refuses_to_reuse_an_existing_stamp(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "x.stamp"
            Q.write_stamp(str(path), RUN_ID, "x")
            with self.assertRaises(FileExistsError):
                Q.write_stamp(str(path), RUN_ID, "x")

    def test_failed_report_copy_fails_the_event_cell(self):
        text = QUAL.read_text()
        start = text.index("  local copied=1\n")
        end = text.index("\n", text.index("  result inventory-event-stdout ", start)) + 1
        snippet = text[start:end]
        for failing in ("event-stdout.json", "event-epipe.json"):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as raw:
                body = ("set -u\nf() {\nlocal judge_rc=1 rc1=0 rc2=1 full_out=a epipe_out=b\n"
                        "RECORDS=/nonexistent RUN_ID=x\n"
                        "publish_output() { [ \"$1\" != %s ]; }\n"
                        "result() { echo \"RESULT $1 $2\"; }\n%s}\nf\n" % (failing, snippet))
                proc = subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                                      timeout=30, cwd=raw)
                self.assertIn("RESULT inventory-event-stdout 0", proc.stdout, proc.stderr)
                self.assertIn("report copy failed", (Path(raw) / "event-stdout.judge").read_text())

    def test_cells_stamp_before_their_inputs_exist(self):
        text = QUAL.read_text()
        for cell, judge in (("second-sigint", "second-sigint"), ("fifo-refused", "fifo-refusal"),
                            ("inventory-event-stdout", "event-stdout"), ('"$cell"', "cgroup-inventory"),
                            ("run-prearm", "run-prearm"), ('"$cell"', "parent-chain")):
            with self.subTest(judge=judge):
                call = text.index('python3 -I "$RECORDS" %s ' % judge)
                stamp = text.rfind("stamp_leg %s " % cell, 0, call)
                self.assertGreater(stamp, 0, "no stamp_leg before the %s judge" % judge)
                body_start = text.rfind("\n}\n", 0, call)
                self.assertGreater(stamp, body_start, "the stamp must be in the judge's own cell")

    def test_fork_child_is_the_kernel_verified_owned_child(self):
        # Codex r9 #2: the child is registered only as the live child of
        # the inside parent; the judge then needs that exact pid.
        text = QUAL.read_text()
        body = text[text.index("cgroup_capture() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn('register_owned_child "$child" "$inside"; then', body)
        self.assertNotIn('register "$child"', body)
        self.assertIn('--child-pid "${child_owned}"', body)


# Rows whose setup is done by run_case (not by write_inputs alone).
SETUP_HOOKS = {"age", "remove", "symlink", "sparse", "stamp_dir", "stamp_text", "run_id"}


class OptimizedInterpreterTests(unittest.TestCase):
    """The judges keep every rule under -O and inherited PYTHONOPTIMIZE."""

    def test_rows_refuse_under_optimized_interpreters(self):
        rows = [row for row in NEGATIVE if row[1] not in ("direct",)][::7]
        for interp, extra in ((["python3", "-O", "-I"], None), (["python3"], {"PYTHONOPTIMIZE": "1"})):
            for rule, judge, mutate in rows:
                case = build(judge, mutate)
                if case.pop("raw_stamp", False) or set(case) & SETUP_HOOKS:
                    continue
                with self.subTest(interp=" ".join(interp), rule=rule), tempfile.TemporaryDirectory() as raw:
                    tmp = Path(raw)
                    argv = [case["judge"], "--verdict", str(tmp / "v.json")]
                    if case["judge"] != "cgroup-member":
                        Q.write_stamp(str(tmp / "cell.stamp"), case.get("stamp_run_id", RUN_ID),
                                      case.get("stamp_cell", CELLS[case["judge"]]))
                        argv += ["--stamp", str(tmp / "cell.stamp"), "--run-id", RUN_ID]
                    files, named = write_inputs(case, tmp)
                    for name, text in files.items():
                        (tmp / name).write_bytes(text if isinstance(text, bytes) else text.encode())
                    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
                    env.update(extra or {})
                    proc = subprocess.run(interp + [str(RECORDS)] + argv + named, env=env,
                                          capture_output=True, text=True, timeout=30)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertEqual(json.loads((tmp / "v.json").read_text())["rule"], rule)


if __name__ == "__main__":
    unittest.main()
