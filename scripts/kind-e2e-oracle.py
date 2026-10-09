#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kubernetes (kind) e2e oracle for scripts/kind-e2e.sh: validate DaemonSet capture evidence against the workload ledgers and refuse mutations."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(
        description="Kubernetes (kind) e2e oracle for scripts/kind-e2e.sh. Subcommands: "
        "profile-exact FILE ITERS [MODULE_SUFFIX], trace-exact FILE ITERS, "
        "negative FILE ENTRY_LOG, inventory FILE --caller PID... --non-caller PID..., "
        "pid-refusal STDERR STATUS PID REPORT_PRESENT, pid-probe FILE ITERS "
        "(diagnostic), --self-test; --expect-observer initial|nested applies the "
        "PID-numbering rules"
    ).print_help()
    raise SystemExit(0)

import copy
import json
import re

# The ledgered loop of tests/fixtures/public-cli/gated.c, one call each per iteration.
LEDGER_FUNCTIONS = {
    "C_GenerateRandom",
    "C_DigestInit",
    "C_Digest",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
}
PROVIDER = "libsofthsm2.so"

# PID numbering (pidns-honesty, DR-K8S-1/2): every capture document carries
# `pid_namespace` = {observer, kernel_pids, proc_pids}. An observer outside the
# initial PID namespace is the observation cause `pid_namespace`, a /proc
# numbered by another namespace is `proc_namespace_mismatch`; both make the
# capture lossy (`concrete_gap`). kind nodes are containers, so the e2e passes
# expect_observer="nested" and requires exactly those causes there.
PIDNS_FIELDS = {"observer", "kernel_pids", "proc_pids"}


def expected_pidns_causes(pid_namespace, expect_observer):
    """The observation causes the PID numbering alone must produce."""
    assert set(pid_namespace) == PIDNS_FIELDS, pid_namespace
    assert pid_namespace["kernel_pids"] == "initial", pid_namespace
    assert pid_namespace["observer"] in {"initial", "nested", "unknown"}, pid_namespace
    assert pid_namespace["proc_pids"] in {"observer", "foreign"}, pid_namespace
    if expect_observer is not None:
        assert pid_namespace["observer"] == expect_observer, (pid_namespace, expect_observer)
    causes = set()
    if pid_namespace["observer"] != "initial":
        causes.add("pid_namespace")
    if pid_namespace["proc_pids"] != "observer":
        causes.add("proc_namespace_mismatch")
    return causes


def check_numbering(evidence, expect_observer, exact=True):
    """Observation causes must be exactly the PID-numbering ones (exact=True),
    or include them (exact=False, for a capture that may carry other gaps);
    a numbering cause makes the verdict a lossy concrete gap."""
    expected = expected_pidns_causes(evidence["pid_namespace"], expect_observer)
    observation = evidence["gap_classes"]["observation"]
    causes = set(observation["causes"])
    if exact:
        assert causes == expected, (causes, expected)
    else:
        assert expected <= causes, (causes, expected)
    if expected:
        assert observation["status"] == "lossy", observation
        assert evidence["verdict_detail"] == "concrete_gap", evidence["verdict_detail"]
    elif exact:
        assert evidence["verdict_detail"] != "concrete_gap", evidence["verdict_detail"]
    return sorted(expected)


def counted_rows(document):
    return [f for f in document["functions"] if f["calls"]]


def profile_exact(document, iters, module_suffix=PROVIDER, expect_observer=None):
    """Exactly the ledger: six named rows of `iters` calls, nothing else counted;
    the only concrete gap allowed is the one the PID numbering names."""
    evidence = document["evidence"]
    numbering = check_numbering(evidence, expect_observer)
    assert document["capture"]["scope"] == "cgroup", document["capture"]["scope"]
    paths = [m["path"] for m in document["capture"]["modules"]]
    assert len(paths) == 1 and paths[0].endswith(module_suffix), paths
    assert evidence["attached_probes"] > 0, evidence["attached_probes"]
    assert evidence["event_loss"] == 0, evidence["event_loss"]
    assert evidence["in_flight_at_end"] == 0, evidence["in_flight_at_end"]
    rows = counted_rows(document)
    assert len(rows) == len(LEDGER_FUNCTIONS), rows
    names = set()
    for row in rows:
        assert row["calls"] == iters, row
        assert row["errors"] == 0, row
        assert len(row["names"]) == 1, row
        names.add(row["names"][0])
    assert names == LEDGER_FUNCTIONS, sorted(names)
    return {
        "calls": sum(r["calls"] for r in rows),
        "module": paths[0],
        "attached_probes": evidence["attached_probes"],
        "verdict_detail": evidence["verdict_detail"],
        "pid_namespace_causes": numbering,
    }


CALL_LINE = re.compile(r"^\S+ pid (\d+) tid (\d+) (?:sess#\d+ )?(C_\w+)\b.* → (CKR_\w+)")
UNKNOWN_CALL_LINE = re.compile(
    r"^\d{2}:\d{2}:\d{2}\.\d{6} Unknown executable \(PID ([0-9]+), TID ([0-9]+)\) "
    r"(?:sess#\d+ )?(C_\w+)\b.* → (CKR_\w+)")


def trace_exact(text, iters, expect_observer=None):
    """Exactly the ledger as call lines; reports the PIDs the trace printed."""
    per_name = {}
    pids = set()
    evidence = counts = None
    for line in text.splitlines():
        if line.startswith("EVIDENCE "):
            evidence = json.loads(line[len("EVIDENCE "):])
            continue
        if line.startswith("COUNT_EVIDENCE "):
            counts = json.loads(line[len("COUNT_EVIDENCE "):])
            continue
        match = CALL_LINE.match(line) or UNKNOWN_CALL_LINE.match(line)
        if match:
            pid, _tid, name, rv = match.groups()
            assert rv == "CKR_OK", line
            per_name[name] = per_name.get(name, 0) + 1
            pids.add(int(pid))
        elif re.match(r"^\d{2}:\d{2}:\d{2}\.", line):
            raise AssertionError(f"unrecognized trace call line: {line!r}")
    assert evidence is not None, "no EVIDENCE line"
    assert counts is not None, "no COUNT_EVIDENCE line"
    assert per_name == {name: iters for name in LEDGER_FUNCTIONS}, per_name
    total = iters * len(LEDGER_FUNCTIONS)
    assert counts["stats_entered"] == total, counts
    assert counts["stats_returned"] == total, counts
    assert evidence["event_loss"] == 0, evidence["event_loss"]
    numbering = check_numbering(evidence, expect_observer)
    assert len(pids) == 1, pids
    return {"calls": total, "trace_pids": sorted(pids), "pid_namespace_causes": numbering}


ENTRY_VISIBLE = re.compile(r"\((\d+) visible process\(es\), (\d+) with readable memory\)")


def negative(document, entry_log, expect_observer=None):
    """A pod that maps no provider yields no module and no counted call, and
    its processes were provably seen: k8s-profile-entry reports at least one
    visible process, every one with readable memory. Without that, "no
    module" could mean "no process visible" (no hostPID) or "unreadable"."""
    found = ENTRY_VISIBLE.findall(entry_log)
    assert len(found) == 1, f"entry visibility line missing: {entry_log!r}"
    visible, readable = (int(n) for n in found[0])
    assert visible >= 1 and readable == visible, (visible, readable)
    assert document["capture"]["scope"] == "cgroup", document["capture"]["scope"]
    assert document["capture"]["modules"] == [], document["capture"]["modules"]
    assert counted_rows(document) == [], counted_rows(document)
    check_numbering(document["evidence"], expect_observer, exact=False)
    return {"modules": 0, "calls": 0, "visible_processes": visible}


def inventory(document, callers, non_callers, expect_observer=None):
    """Scan-lane caller map: every ledger PID has an edge to the provider; no
    negative-control PID has any edge. PIDs here are /proc PIDs; when the
    numbering disagrees with the kernel's, one scope-level `pid namespace`
    gap must say so."""
    assert document["schema"] == "p11scope/inventory/v1", document["schema"]
    if expected_pidns_causes(document["pid_namespace"], expect_observer):
        scope_gaps = [
            g for g in document["gaps"]
            if g["subject"] == "pid namespace" and g["caller"] is None
            and g["module"] is None and g["pid"] is None
        ]
        assert len(scope_gaps) == 1, document["gaps"]
    pid_of = {c["id"]: c["pid"] for c in document["callers"]}
    paths_of = {m["id"]: m["paths"] for m in document["modules"]}
    edges = {}
    for edge in document["edges"]:
        edges.setdefault(pid_of[edge["caller"]], []).append(paths_of[edge["module"]])
    for pid in callers:
        assert pid in edges, f"ledger pid {pid} has no caller edge"
        assert any(p.endswith(PROVIDER) for paths in edges[pid] for p in paths), edges[pid]
    for pid in non_callers:
        # Scanned, yet no edge: an unscanned pid would make "no edge" vacuous.
        assert pid in pid_of.values(), f"negative-control pid {pid} was never scanned"
        assert pid not in edges, f"negative-control pid {pid} appears as a caller: {edges[pid]}"
    return {
        "callers_with_edges": sorted(edges),
        "modules": sorted(p for paths in paths_of.values() for p in paths),
        "scanned_callers": len(pid_of),
        "gaps": len(document["gaps"]),
    }


REFUSAL = re.compile(r"^(?:p11scope: )?pid-namespace-mismatch: refusing --pid (\d+)")


def pid_refusal(stderr, status, pid, report_present):
    """Gating (DR-30/DR-K8S-1): on a node whose observer is not in the initial
    PID namespace, `profile --pid` must be refused by name before anything
    runs: non-zero exit, a `pid-namespace-mismatch:` error naming the pid, and
    no report written."""
    assert status != 0, status
    refused = [int(m.group(1)) for m in map(REFUSAL.match, stderr.splitlines()) if m]
    assert refused == [pid], (refused, pid, stderr)
    assert not report_present, "a refused --pid capture still wrote a report"
    return {"refused_pid": pid, "exit_status": status}


def pid_probe(document, iters):
    """Classify what a `profile --pid` report counted (kept for diagnosis)."""
    observed = sum(f["calls"] for f in counted_rows(document))
    expected = iters * len(LEDGER_FUNCTIONS)
    evidence = document["evidence"]
    if observed == expected:
        classification = "exact"
    elif observed == 0 and evidence["attached_probes"] > 0:
        classification = "silent-zero"
    else:
        classification = "other"
    return {
        "classification": classification,
        "observed_calls": observed,
        "ledger_calls": expected,
        "attached_probes": evidence["attached_probes"],
        "verdict_detail": evidence["verdict_detail"],
        "gap_classes": evidence.get("gap_classes"),
    }


# ---------------------------------------------------------------- self-test


def good_profile(iters=400, path="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"):
    return {
        "capture": {"scope": "cgroup", "modules": [{"path": path}]},
        "evidence": {
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "verdict_detail": "attribution_only",
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": [], "status": "exact"}},
        },
        "functions": [{"calls": iters, "errors": 0, "names": [n]} for n in sorted(LEDGER_FUNCTIONS)]
        + [{"calls": 0, "errors": 0, "names": ["C_Login"]}],
    }


def good_trace(iters=2):
    lines = [
        f"03:48:03.{i:06d} pid 77 tid 77 {name} [semantics unverified] → CKR_OK 3.0µs"
        for i in range(iters)
        for name in sorted(LEDGER_FUNCTIONS)
    ]
    total = iters * len(LEDGER_FUNCTIONS)
    lines.append("COUNT_EVIDENCE " + json.dumps({"stats_entered": total, "stats_returned": total, "raw_calls": total}))
    lines.append("EVIDENCE " + json.dumps({
        "event_loss": 0,
        "verdict_detail": "attribution_only",
        "pid_namespace": {"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
        "gap_classes": {"observation": {"causes": [], "status": "exact"}},
    }))
    return "\n".join(lines) + "\n"


def good_inventory():
    return {
        "schema": "p11scope/inventory/v1",
        "callers": [{"id": "c0", "pid": 10}, {"id": "c1", "pid": 11}, {"id": "c2", "pid": 12}],
        "modules": [{"id": "m0", "paths": ["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],
        "edges": [{"caller": "c0", "module": "m0"}, {"caller": "c1", "module": "m0"}],
        "gaps": [],
        "pid_namespace": {"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
    }


def nested(document):
    """The same document as a nested observer (kind) publishes it."""
    nested_doc = copy.deepcopy(document)
    evidence = nested_doc.get("evidence", nested_doc)
    evidence["pid_namespace"] = {"observer": "nested", "kernel_pids": "initial", "proc_pids": "observer"}
    if "gap_classes" in evidence:
        evidence["gap_classes"]["observation"] = {"causes": ["pid_namespace"], "status": "lossy"}
        evidence["verdict_detail"] = "concrete_gap"
    else:
        evidence["gaps"].append({"subject": "pid namespace", "caller": None, "module": None, "pid": None})
    return nested_doc


def mutate(document, path, value):
    mutated = copy.deepcopy(document)
    cursor = mutated
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return mutated


def refuses(label, check):
    try:
        check()
    except (AssertionError, KeyError, IndexError, TypeError, ValueError):
        return
    raise SystemExit(f"mutation accepted: {label}")


def self_test():
    profile_exact(good_profile(), 400)
    profile_exact(good_profile(300, "/tmp/private/libsofthsm2.so"), 300, "/tmp/private/libsofthsm2.so")
    leak = good_profile()
    leak["functions"][0]["calls"] = 650  # a neighbouring pod's 250 calls leaked in
    for label, document, iters in [
        ("other pod's calls leaked", leak, 400),
        ("wrong ledger", good_profile(), 401),
        ("no module", mutate(good_profile(), ["capture", "modules"], []), 400),
        ("two modules", mutate(good_profile(), ["capture", "modules"], [{"path": "/a/libsofthsm2.so"}] * 2), 400),
        ("wrong module", mutate(good_profile(), ["capture", "modules"], [{"path": "/usr/lib/libother.so"}]), 400),
        ("not cgroup", mutate(good_profile(), ["capture", "scope"], "system"), 400),
        ("no probes", mutate(good_profile(), ["evidence", "attached_probes"], 0), 400),
        ("event loss", mutate(good_profile(), ["evidence", "event_loss"], 3), 400),
        ("in flight", mutate(good_profile(), ["evidence", "in_flight_at_end"], 1), 400),
        ("concrete gap", mutate(good_profile(), ["evidence", "verdict_detail"], "concrete_gap"), 400),
        ("missing row", mutate(good_profile(), ["functions"], good_profile()["functions"][1:]), 400),
        ("unnamed row", mutate(good_profile(), ["functions", 0, "names"], []), 400),
        ("errors", mutate(good_profile(), ["functions", 0, "errors"], 1), 400),
    ]:
        refuses(label, lambda d=document, n=iters: profile_exact(d, n))
    refuses("private module suffix", lambda: profile_exact(good_profile(), 400, "/tmp/private/libsofthsm2.so"))

    assert trace_exact(good_trace(), 2) == {"calls": 12, "trace_pids": [77], "pid_namespace_causes": []}
    text = good_trace()
    for label, bad in [
        ("dropped call line", text.replace(" C_Digest [", " C_Nothing [", 1)),
        ("extra call line", "03:48:03.9 pid 77 tid 77 C_Digest [x] → CKR_OK 1µs\n" + text),
        ("second pid", text.replace("pid 77 tid 77 C_Digest", "pid 78 tid 78 C_Digest")),
        ("error rv", text.replace("→ CKR_OK", "→ CKR_GENERAL_ERROR", 1)),
        ("no evidence", "\n".join(l for l in text.splitlines() if not l.startswith("EVIDENCE"))),
        ("no count evidence", "\n".join(l for l in text.splitlines() if not l.startswith("COUNT_EVIDENCE"))),
        ("stats mismatch", text.replace('"stats_entered": 12', '"stats_entered": 13')),
        ("loss", text.replace('"event_loss": 0', '"event_loss": 1')),
    ]:
        refuses(label, lambda t=bad: trace_exact(t, 2))

    empty = mutate(good_profile(), ["capture", "modules"], [])
    empty["functions"] = [{"calls": 0, "errors": 0, "names": ["C_Login"]}]
    seen = "pod cgroup: /sys/fs/cgroup/x (1 visible process(es), 1 with readable memory)\n"
    negative(empty, seen)
    refuses("negative pod mapped a module", lambda: negative(mutate(empty, ["capture", "modules"], [{"path": "/x/libsofthsm2.so"}]), seen))
    refuses("negative pod counted calls", lambda: negative(mutate(empty, ["functions"], [{"calls": 1, "errors": 0, "names": ["C_Digest"]}]), seen))
    refuses("no process visible (no hostPID)", lambda: negative(empty, seen.replace("(1 visible", "(0 visible")))
    refuses("memory unreadable (no ptrace)", lambda: negative(empty, seen.replace("1 with readable", "0 with readable")))
    refuses("no entry visibility line", lambda: negative(empty, ""))

    inventory(good_inventory(), [10, 11], [12])
    refuses("negative control is a caller", lambda: inventory(good_inventory(), [10], [11]))
    refuses("negative control never scanned", lambda: inventory(good_inventory(), [10], [99]))
    refuses("ledger pid missing", lambda: inventory(good_inventory(), [10, 12], []))
    refuses("wrong module", lambda: inventory(mutate(good_inventory(), ["modules", 0, "paths"], ["/x/libother.so"]), [10], []))
    refuses("wrong schema", lambda: inventory(mutate(good_inventory(), ["schema"], "p11scope/inventory/v0"), [10], []))

    assert pid_probe(good_profile(100), 100)["classification"] == "exact"
    zero = copy.deepcopy(good_profile())
    for row in zero["functions"]:
        row["calls"] = 0
    assert pid_probe(zero, 100)["classification"] == "silent-zero"
    assert pid_probe(good_profile(7), 100)["classification"] == "other"
    # PID numbering (pidns-honesty).
    profile_exact(nested(good_profile()), 400, expect_observer="nested")
    for label, document in [
        ("nested claims initial", good_profile()),
        ("no pid_namespace", mutate(good_profile(), ["evidence", "pid_namespace"], None)),
        ("nested but exact", mutate(nested(good_profile()), ["evidence", "gap_classes", "observation"], {"causes": [], "status": "exact"})),
        ("nested cause but not lossy", mutate(nested(good_profile()), ["evidence", "gap_classes", "observation", "status"], "exact")),
        ("nested but not concrete", mutate(nested(good_profile()), ["evidence", "verdict_detail"], "attribution_only")),
        ("nested plus another cause", mutate(nested(good_profile()), ["evidence", "gap_classes", "observation", "causes"], ["pid_namespace", "ring_loss"])),
        ("kernel pids not initial", mutate(nested(good_profile()), ["evidence", "pid_namespace", "kernel_pids"], "observer")),
    ]:
        refuses(label, lambda d=document: profile_exact(d, 400, expect_observer="nested"))
    foreign = nested(good_profile())
    foreign["evidence"]["pid_namespace"]["proc_pids"] = "foreign"
    refuses("foreign /proc without its cause", lambda: profile_exact(foreign, 400, expect_observer="nested"))
    foreign["evidence"]["gap_classes"]["observation"]["causes"] = ["pid_namespace", "proc_namespace_mismatch"]
    profile_exact(foreign, 400, expect_observer="nested")
    refuses("initial observer with a pid cause", lambda: profile_exact(
        mutate(good_profile(), ["evidence", "gap_classes", "observation"], {"causes": ["pid_namespace"], "status": "lossy"}), 400))
    nested_trace = good_trace().replace(
        '"pid_namespace": {"observer": "initial"', '"pid_namespace": {"observer": "nested"').replace(
        '"observation": {"causes": [], "status": "exact"}', '"observation": {"causes": ["pid_namespace"], "status": "lossy"}').replace(
        '"verdict_detail": "attribution_only"', '"verdict_detail": "concrete_gap"')
    trace_exact(nested_trace, 2, expect_observer="nested")
    refuses("nested trace claims initial", lambda: trace_exact(good_trace(), 2, expect_observer="nested"))
    nested_empty = nested(empty)
    negative(nested_empty, seen, expect_observer="nested")
    refuses("nested negative without cause", lambda: negative(empty, seen, expect_observer="nested"))
    inventory(nested(good_inventory()), [10, 11], [12], expect_observer="nested")
    refuses("nested inventory without scope gap", lambda: inventory(
        mutate(nested(good_inventory()), ["gaps"], []), [10, 11], [12], expect_observer="nested"))
    refuses("nested inventory claims initial", lambda: inventory(good_inventory(), [10, 11], [12], expect_observer="nested"))
    # The gating --pid refusal.
    err = "p11scope: pid-namespace-mismatch: refusing --pid 4106: this observer is not in the initial PID namespace\n"
    pid_refusal(err, 1, 4106, False)
    pid_refusal(err[len("p11scope: "):], 1, 4106, False)
    for label, args in [
        ("refusal exited 0", (err, 0, 4106, False)),
        ("refusal names another pid", (err, 1, 4107, False)),
        ("no refusal line", ("p11scope: capturing: 136 probe(s) attached\n", 1, 4106, False)),
        ("refusal mid-line", ("note: p11scope: pid-namespace-mismatch: refusing --pid 4106\n", 1, 4106, False)),
        ("report written", (err, 1, 4106, True)),
    ]:
        refuses(label, lambda a=args: pid_refusal(*a))
    print("kind-e2e oracle mutations rejected: OK")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return
    expect_observer = None
    if "--expect-observer" in argv:
        at = argv.index("--expect-observer")
        expect_observer = argv[at + 1]
        assert expect_observer in {"initial", "nested"}, expect_observer
        argv = argv[:at] + argv[at + 2:]
    command, path, rest = argv[0], argv[1], argv[2:]
    if command == "pid-refusal":
        # pid-refusal STDERR_FILE STATUS PID REPORT_PRESENT(0|1)
        with open(path, encoding="utf-8") as handle:
            result = pid_refusal(handle.read(), int(rest[0]), int(rest[1]), rest[2] == "1")
        print(json.dumps({"check": command, "ok": True, **result}, sort_keys=True))
        return
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()
    if command == "trace-exact":
        result = trace_exact(raw, int(rest[0]), expect_observer)
    else:
        document = json.loads(raw)
        if command == "profile-exact":
            result = profile_exact(document, int(rest[0]), *rest[1:2], expect_observer=expect_observer)
        elif command == "negative":
            with open(rest[0], encoding="utf-8") as handle:
                result = negative(document, handle.read(), expect_observer)
        elif command == "pid-probe":
            # Record-only: never an "ok" line, never counted as a passed check.
            print(json.dumps({"check": command, "record_only": True, **pid_probe(document, int(rest[0]))}, sort_keys=True))
            return
        elif command == "inventory":
            parser = argparse.ArgumentParser(prog="kind-e2e-oracle.py inventory")
            parser.add_argument("--caller", type=int, action="append", default=[])
            parser.add_argument("--non-caller", type=int, action="append", default=[])
            options = parser.parse_args(rest)
            result = inventory(document, options.caller, options.non_caller, expect_observer)
        else:
            raise SystemExit(f"unknown subcommand {command}")
    print(json.dumps({"check": command, "ok": True, **result}, sort_keys=True))


main(sys.argv[1:])
