#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge inventory MT-exact evidence against the threaded fixture ledger.

Cells `inventory-mt-pid` (one N-thread process) and `inventory-mt-system`
(several processes x N threads) run the deterministic mt_mixed/mt_fork
workloads under `inventory --capture native`. This checker asserts:

- the snapshot inventories the owned provider (admitted) and every workload
  caller (READY + CHILD pids), with no gaps about the owned module;
- every workload edge to the owned module carries `counted` coverage that is
  not lossy, and the summed `entries.count` equals the ledger's grand total
  of through-table calls plus the fixture's exact SCAFFOLD record
  (session open attempts/closes/finalizes, entry-side) exactly;
- the `--event-log` stream ends cleanly (`ended`), its last `edge_observed`
  record per workload edge equals the snapshot row, and the streamed edge
  totals equal the same grand total exactly.

Counts are entry-side attach totals per (caller, module) edge; error-returning
calls count (entry, not return, is observed). Rows never sum as deltas: the
last record per edge key replaces earlier ones.
"""

import argparse
import json
from pathlib import Path
import re
import stat
import sys

MT_NAMES = ("C_GenerateRandom", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo")
CELLS = {"inventory-mt-pid": "pid", "inventory-mt-system": "system"}


class EvidenceError(Exception):
    pass


def require(condition, detail):
    if not condition:
        raise EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    require(stat.S_ISREG(path.stat().st_mode), "evidence must be a regular file")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence exceeds size limit")
    return path.read_text(encoding="utf-8")


def identity(value):
    require(isinstance(value, dict), "missing physical identity")
    dev = value.get("dev")
    require(isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
            "invalid device identity")
    require(integer(value.get("ino")) and value["ino"] > 0, "invalid inode identity")
    require(isinstance(value.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "missing provider hash")
    return (*dev, value["ino"], value["sha256"])


def check_receipt(receipt, cell):
    require(receipt.get("schema") == "p11scope/public-cli-receipt/v1" and
            receipt.get("cell") == cell, "receipt schema or cell mismatch")
    require(receipt.get("scope") == CELLS[cell], "receipt scope differs from declared cell")
    require(receipt.get("count_domain") == "owned-provider", "count domain is not owned-provider")
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, "missing " + key)
    require(receipt.get("gate_released") is True, "gate was not safely released")
    for key in ("observer_exit", "workload_exit"):
        require(type(receipt.get(key)) is int and receipt[key] == 0, "nonzero or missing " + key)
    generation = receipt.get("generation")
    if generation is not None:
        require(integer(generation) and generation > 0 and
                type(receipt.get("ready_generation")) is int and
                receipt["ready_generation"] == generation, "workload generation changed")
    before = identity(receipt.get("provider_before"))
    after = identity(receipt.get("provider_after"))
    require(before == after, "provider physical identity or hash changed")
    return before


def check_ledger(text, receipt, cell):
    targets, ledgers, ready, children, scaffolds = [], [], [], [], []
    for line in text.splitlines():
        if line.startswith("TARGET "):
            require(not ready and not ledgers, "fixture target emitted after readiness or ledger")
            targets.append(parse(line[7:]))
        elif line.startswith("LEDGER "):
            require(len(ready) == 1, "fixture ledger emitted before workload READY")
            ledgers.append(parse(line[7:]))
        elif line.startswith("SCAFFOLD "):
            require(len(ready) == 1, "fixture scaffold emitted before workload READY")
            scaffolds.append(parse(line[9:]))
        elif line.startswith("READY "):
            match = re.fullmatch(r"READY pid=([0-9]+)", line)
            require(match is not None, "invalid workload READY")
            ready.append(int(match[1]))
        elif line.startswith("CHILD "):
            match = re.fullmatch(r"CHILD pid=([0-9]+)", line)
            require(match is not None, "invalid workload CHILD")
            children.append(int(match[1]))
    pid = receipt.get("launched_pid")
    require(integer(pid) and pid > 0 and ready == [pid] and receipt.get("ready_pid") == pid,
            "workload READY does not match launched PID")
    require(len(ledgers) == 1, "missing or duplicate complete LEDGER")
    ledger = ledgers[0]
    require(ledger.get("schema") == "p11scope/public-cli-ledger/v2" and
            ledger.get("pid") == pid and ledger.get("complete") is True,
            "invalid or incomplete fixture ledger")
    if cell == "inventory-mt-system":
        require(len(children) == 4 and len(set(children)) == 4 and pid not in children,
                "multi-process workload did not report 4 distinct children")
    else:
        require(not children, "single-process workload reported children")
    functions = ledger.get("functions")
    require(isinstance(functions, list), "missing ledger functions")
    expected = {}
    for row in functions:
        name = row.get("name")
        require(name in MT_NAMES and name not in expected, "duplicate or unexpected ledger function")
        attempts, successes = row.get("attempts"), row.get("successful")
        require(integer(attempts) and integer(successes) and attempts > 0 and
                0 <= successes <= attempts, "invalid ledger attempts/successful: " + name)
        counts = row.get("rv_counts")
        require(isinstance(counts, dict) and counts and
                all(re.fullmatch(r"0x[0-9a-f]{16}", key) is not None and integer(value)
                    for key, value in counts.items()),
                "invalid ledger return map: " + name)
        require(sum(counts.values()) == attempts and
                counts.get("0x0000000000000000", 0) == successes,
                "ledger return map disagrees with attempts/successful: " + name)
        expected[name] = attempts
    require(set(expected) == set(MT_NAMES), "missing fixture ledger function")
    require(len(scaffolds) == 1, "missing or duplicate SCAFFOLD record")
    scaffold = scaffolds[0]
    for key in ("opens_attempted", "opens_ok", "closes", "finalizes"):
        require(integer(scaffold.get(key)), "invalid scaffold " + key)
    require(scaffold["opens_attempted"] >= scaffold["opens_ok"] and
            scaffold["closes"] == scaffold["opens_ok"] and scaffold["finalizes"] == 1,
            "inconsistent scaffold record: %r" % (scaffold,))
    dev_ino = set()
    for row in targets:
        name = row.get("name")
        require(name in MT_NAMES, "unexpected fixture target")
        require(row.get("dev") == list(identity(receipt["provider_before"])[:2]) and
                row.get("ino") == identity(receipt["provider_before"])[2],
                "mapped fixture target differs from independently hashed provider")
        dev_ino.add((tuple(row["dev"]), row["ino"]))
    require(len(dev_ino) == 1, "fixture targets span providers")
    return expected, [pid, *children], scaffold


def snapshot_edges(report, provider, pids):
    require(report.get("schema") == "p11scope/inventory/v1", "unsupported inventory schema")
    modules = {row["id"]: row for row in report.get("modules", [])
               if isinstance(row, dict) and "id" in row}
    owned = None
    for mid, module in modules.items():
        ident = module.get("identity", {})
        dev = ident.get("device", {})
        if ([dev.get("major"), dev.get("minor")] == list(provider[:2]) and
                ident.get("inode") == provider[2] and ident.get("sha256") == provider[3]):
            require(owned is None, "duplicate owned provider module")
            owned = mid
    require(owned is not None, "owned provider not inventoried")
    require(modules[owned].get("admission", {}).get("state") == "admitted",
            "owned provider not admitted")
    callers = {row["id"]: row for row in report.get("callers", [])
               if isinstance(row, dict) and "id" in row}
    wanted = {}
    for pid in pids:
        hits = [cid for cid, row in callers.items() if row.get("pid") == pid]
        require(len(hits) == 1, "workload pid %d is not exactly one caller: %r" % (pid, hits))
        wanted[pid] = hits[0]
    edges = [row for row in report.get("edges", [])
             if isinstance(row, dict) and row.get("module") == owned and
             row.get("caller") in set(wanted.values())]
    require(len(edges) == len(wanted),
            "workload edges to owned module are not exactly one per caller: %d vs %d" %
            (len(edges), len(wanted)))
    for row in report.get("gaps", []):
        require(not (isinstance(row, dict) and row.get("module") == owned),
                "inventory gap about owned module: %r" % (row,))
    return edges


def check_edge_totals(edges, total, where):
    counted = 0
    for row in edges:
        entries = row.get("entries", {})
        require(entries.get("observation") == "observed",
                "%s edge %r is not observed: %r" % (where, row.get("caller"), entries.get("observation")))
        count = entries.get("count")
        require(integer(count), "%s edge %r lacks an exact count" % (where, row.get("caller")))
        coverage = entries.get("coverage", {})
        require(coverage.get("state") == "counted",
                "%s edge %r is not counted: %r" % (where, row.get("caller"), coverage.get("state")))
        require(coverage.get("lossy") is False,
                "%s edge %r is lossy" % (where, row.get("caller")))
        counted += count
    require(counted == total,
            "%s edge usage %d differs from the independent ledger total %d" % (where, counted, total))
    return counted


def check_event_log(text, edges, total):
    last = {}
    ended = False
    unretained_keys = ("instances_unretained", "semantic_edges_unretained",
                       "key_operations_unretained", "edges_unretained")
    for line in text.splitlines():
        if not line.strip():
            continue
        record = parse(line)
        kind = record.get("kind")
        if kind == "edge_observed":
            row = record.get("event", record.get("row", {}))
            if isinstance(row, dict) and "caller" in row and "module" in row:
                last[(row["caller"], row["module"])] = row
        elif kind == "ended":
            ended = True
            event = record.get("event", {})
            for key in unretained_keys:
                if key in event:
                    require(event[key] == 0, "stream deleted retained rows: %s=%r" % (key, event[key]))
    require(ended, "event stream was cut short (no ended marker)")
    snap = {(row.get("caller"), row.get("module")): row for row in edges}
    require(set(snap) <= set(last), "event stream misses workload edges: %r" %
            sorted(set(snap) - set(last)))
    for key in snap:
        stream_count = last[key].get("entries", {}).get("count")
        snap_count = snap[key].get("entries", {}).get("count")
        require(integer(stream_count) and stream_count == snap_count,
                "streamed edge total differs from the snapshot row: %r" % (key,))
    streamed = sum(last[key]["entries"]["count"] for key in snap)
    require(streamed == total,
            "streamed edge usage %d differs from the independent ledger total %d" % (streamed, total))


def judge(report_text, ledger_text, receipt, event_text, cell):
    require(cell in CELLS, "undeclared cell")
    provider = check_receipt(receipt, cell)
    expected, pids, scaffold = check_ledger(ledger_text, receipt, cell)
    total = (sum(expected.values()) + scaffold["opens_attempted"] +
             scaffold["closes"] + scaffold["finalizes"])
    report = parse(report_text)
    if CELLS[cell] == "pid":
        require(report.get("scope") == "pid:%d" % pids[0],
                "report scope differs from declared workload pid")
    else:
        require(report.get("scope") == "system", "report scope differs from declared cell")
    edges = snapshot_edges(report, provider, pids)
    check_edge_totals(edges, total, "snapshot")
    check_event_log(event_text, edges, total)
    return ("owned-edge-usage-counts",
            "owned per-edge usage and streamed edge totals match the independent ledger "
            "total %d over %d workload callers; per-caller attribution is by caller pid" %
            (total, len(pids)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("report", "ledger", "receipt", "cell", "event-log"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        qualification, detail = judge(read(Path(args.report)), read(Path(args.ledger)),
                                      parse(read(Path(args.receipt))),
                                      read(Path(getattr(args, "event_log"))), args.cell)
        result.update({"pass": True, "qualification": qualification, "detail": detail})
        code = 0
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError, AssertionError) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
