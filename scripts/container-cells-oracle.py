#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Container-cells oracle for scripts/docker-shared-layer-e2e.sh (D1) and scripts/late-provider-negative.sh (N4).

Subcommands: copy-up (D1 shared-layer / copy-up), late-reported (N4 never-seen
late provider), --self-test. Every check ships a mutation this oracle refuses;
see --self-test and tests/python/test_container_cells_oracle.py.

D1 expectations follow the R4 per-lane overlay outcome table
(plans/2026-10-24-v050-r4-identity.md, "Per-lane overlay outcome table"):
pre-copy-up both backends attribute both containers (parity); post-copy-up on
lane B the kernel refuses the upper mapping with a named identity loss while
userspace still joins it (D-C7-3, disclosed in docs/known-limitations.md
"Overlay xino/copy-up identity divergences (D-C7-2/D-C7-3)"), and on lane A
neither backend joins it (parity none, disclosed). The observer runs on the
host in the initial PID namespace, so no pid_namespace cause is allowed.
"""
import argparse
import copy
import json
import sys

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

# OQ4 frozen gap/loss subject allowlist for the N4 late leg, enumerated from
# the product source. Each value cites the production push site. A gap
# referencing the late PID with any other subject FAILs (vocabulary drift is
# harness, never silently accepted). PENDING the controller's first N4 run,
# which confirms the list against the built binary's actual output.
ALLOWED_LATE_SUBJECTS = {
    "module admission changed": "src/discovery/caller_registry.rs:4885",
    "maps attribution": "src/inspect_system.rs:1854",
    "discovery capped": "src/inspect_system.rs:1900",
    "capture discovery": "src/discovery/scan.rs:3007",
    "process view": "src/discovery/engine.rs:5890",
    "physical provider use preceded first observed semantic registration":
        "src/discovery/caller_registry.rs:3619",
    "entry without mapping evidence": "src/discovery/caller_registry.rs:4906",
    "native witness without a module": "src/discovery/inventory_coordinator.rs:3110",
    "caller admission failed": "src/discovery/inventory_coordinator.rs:2451",
    "native pre-admission rows past their bound":
        "src/discovery/inventory_coordinator.rs:4831",
    "module identity uncertain": "src/discovery/caller_registry.rs:4041",
    "semantic call without mapping evidence": "src/discovery/caller_registry.rs:4956",
}
# Dynamic subjects the product emits for one provider file (never frozen
# strings): the raw maps path (src/discovery/scan.rs:4101), the pinned path
# (src/inspect_system.rs:1828), /proc/<pid>/mem (src/discovery/scan.rs:4041),
# and "device M:m inode I" (src/discovery/scan.rs:4104).


def known_late_subject(subject, late_module):
    """A late-leg gap subject the frozen vocabulary admits."""
    if subject in ALLOWED_LATE_SUBJECTS or subject == late_module:
        return True
    if subject.endswith(".so"):
        return True
    if subject.startswith("/proc/") and subject.endswith("/mem"):
        return True
    return subject.startswith("device ") and " inode " in subject


def inventory_maps(document, module_suffix=PROVIDER):
    """Caller PIDs, provider edges per PID, and the caller-id table."""
    assert document["schema"] == "p11scope/inventory/v1", document.get("schema")
    pid_of = {c["id"]: c["pid"] for c in document["callers"]}
    paths_of = {m["id"]: m["paths"] for m in document["modules"]}
    edges = {}
    for edge in document["edges"]:
        assert edge["caller"] in pid_of, ("dangling edge caller", edge)
        assert edge["module"] in paths_of, ("dangling edge module", edge)
        pid = pid_of[edge["caller"]]
        if any(p.endswith(module_suffix) for p in paths_of[edge["module"]]):
            edges.setdefault(pid, []).append(edge["module"])
    return pid_of, edges


def gaps_for(document, pid_of, pid, extra_subject=None):
    """Gaps referencing one PID: direct pid, caller id, or module subject."""
    found = []
    for gap in document["gaps"]:
        if gap.get("pid") == pid:
            found.append(gap)
        elif gap.get("caller") is not None and pid_of.get(gap["caller"]) == pid:
            found.append(gap)
        elif extra_subject is not None and gap.get("subject") == extra_subject:
            found.append(gap)
    return found


def require_initial_observer(document, label):
    """D1/N4 run on the host: initial observer, no pid_namespace cause."""
    numbering = document["pid_namespace"]
    assert numbering["observer"] == "initial", (label, numbering)
    assert numbering["kernel_pids"] == "initial", (label, numbering)
    assert numbering["proc_pids"] == "observer", (label, numbering)
    for gap in document.get("gaps", []):
        assert gap.get("subject") != "pid namespace", (label, gap)


def require_profile_exact(document, iters, label, module_suffix=PROVIDER):
    """Exactly the workload ledger: six named rows of `iters`, zero loss, initial observer."""
    require_initial_observer(document["evidence"], label)
    evidence = document["evidence"]
    assert document["capture"]["scope"] == "cgroup", (label, document["capture"])
    paths = [m["path"] for m in document["capture"]["modules"]]
    assert len(paths) == 1 and paths[0].endswith(module_suffix), (label, paths)
    assert evidence["attached_probes"] > 0, (label, evidence["attached_probes"])
    assert evidence["event_loss"] == 0, (label, evidence["event_loss"])
    assert evidence["in_flight_at_end"] == 0, (label, evidence["in_flight_at_end"])
    assert evidence["gap_classes"]["observation"]["causes"] == [], (label, evidence)
    assert evidence["verdict_detail"] != "concrete_gap", (label, evidence)
    rows = [f for f in document["functions"] if f["calls"]]
    assert len(rows) == len(LEDGER_FUNCTIONS), (label, rows)
    names = set()
    for row in rows:
        assert row["calls"] == iters, (label, row)
        assert row["errors"] == 0, (label, row)
        assert len(row["names"]) == 1, (label, row)
        names.add(row["names"][0])
    assert names == LEDGER_FUNCTIONS, (label, sorted(names))


def has_identity_loss(gaps):
    """A named copy-up loss: reason carries identity_mismatch (src/discovery/identity.rs:757)."""
    return [g for g in gaps if "identity_mismatch" in g.get("reason", "")]


def copy_up(pre_kernel, pre_userspace, post_kernel, post_userspace,
            pre_profile_a, pre_profile_b, post_profile_b,
            pid_a, pid_b_pre, pid_b_post, iters_a, iters_b, lane, dc73_note,
            module_suffix=PROVIDER):
    """D1: pre parity on both backends, post per the R4 row for `lane`.

    Post runs only three captures (the plan's d1-post-*): both inventory
    backends plus the restarted B profile. A is the unchanged control: its
    ledger ran once pre-copy-up, and post it is pinned by both inventories.
    """
    assert lane in ("A", "B"), lane
    for label, document in (("pre-kernel", pre_kernel), ("pre-userspace", pre_userspace),
                            ("post-kernel", post_kernel), ("post-userspace", post_userspace)):
        require_initial_observer(document, label)
    pre_k_pid, pre_k_edges = inventory_maps(pre_kernel, module_suffix)
    pre_u_pid, pre_u_edges = inventory_maps(pre_userspace, module_suffix)
    post_k_pid, post_k_edges = inventory_maps(post_kernel, module_suffix)
    post_u_pid, post_u_edges = inventory_maps(post_userspace, module_suffix)

    # Pre: both backends show edges for A and B to the provider, with no
    # named identity loss (exact parity, non-vacuous).
    assert pid_a in pre_k_edges, ("pre-kernel", pid_a, sorted(pre_k_edges))
    assert pid_b_pre in pre_k_edges, ("pre-kernel", pid_b_pre, sorted(pre_k_edges))
    assert pid_a in pre_u_edges, ("pre-userspace", pid_a, sorted(pre_u_edges))
    assert pid_b_pre in pre_u_edges, ("pre-userspace", pid_b_pre, sorted(pre_u_edges))
    assert not has_identity_loss(gaps_for(pre_kernel, pre_k_pid, pid_b_pre)), "pre-kernel"
    assert not has_identity_loss(gaps_for(pre_userspace, pre_u_pid, pid_b_pre)), "pre-userspace"
    require_profile_exact(pre_profile_a, iters_a, "pre-profile-a", module_suffix)
    require_profile_exact(pre_profile_b, iters_b, "pre-profile-b", module_suffix)

    # Vacuity guard: the kernel backend results must differ across the
    # copy-up (pre edge, post no-edge plus named loss). Identical results
    # mean the copy-up never happened or was never observed.
    pre_fingerprint = (pid_b_pre in pre_k_edges,
                       bool(has_identity_loss(gaps_for(pre_kernel, pre_k_pid, pid_b_pre))))
    post_fingerprint = (pid_b_post in post_k_edges,
                        bool(has_identity_loss(gaps_for(post_kernel, post_k_pid, pid_b_post))))
    assert pre_fingerprint == (True, False), ("pre-kernel", pre_fingerprint)
    assert pre_fingerprint != post_fingerprint, ("vacuity: pre/post kernel results identical",
                                                 pre_fingerprint, post_fingerprint)

    # Post, both lanes: A stays exact; B's new mapping is scanned (in
    # callers) so "no edge" cannot mean "never seen".
    assert pid_a in post_k_edges, ("post-kernel", pid_a, sorted(post_k_edges))
    assert pid_a in post_u_edges, ("post-userspace", pid_a, sorted(post_u_edges))
    assert pid_b_post in post_k_pid.values(), ("post-kernel unscanned", pid_b_post)
    assert pid_b_post in post_u_pid.values(), ("post-userspace unscanned", pid_b_post)
    # Post kernel, both lanes: NO edge for B's new mapping plus a named loss.
    assert pid_b_post not in post_k_edges, ("post-kernel claims exact attribution "
                                            "across the copy-up", pid_b_post)
    assert has_identity_loss(gaps_for(post_kernel, post_k_pid, pid_b_post)), \
        ("post-kernel names no loss for B", pid_b_post)
    if lane == "B":
        # R4 lane-B row: userspace still joins the upper mapping to the stale
        # lower anchor (D-C7-3); the run log must record the disclosure.
        assert pid_b_post in post_u_edges, ("post-userspace lost the D-C7-3 edge", pid_b_post)
        assert "D-C7-3 applies" in dc73_note, "post-userspace edge without the D-C7-3 note"
    else:
        # R4 lane-A row: neither backend joins (parity none, disclosed).
        assert pid_b_post not in post_u_edges, ("post-userspace joins on lane A", pid_b_post)
        assert has_identity_loss(gaps_for(post_userspace, post_u_pid, pid_b_post)), \
            ("post-userspace names no loss for B on lane A", pid_b_post)
        assert "D-C7-3 applies" not in dc73_note, "D-C7-3 is lane-B-only"
    require_profile_exact(post_profile_b, iters_b, "post-profile-b", module_suffix)
    return {"check": "copy-up", "ok": True, "lane": lane,
            "pre": {"kernel_edges": sorted(pre_k_edges), "userspace_edges": sorted(pre_u_edges)},
            "post": {"kernel_edges": sorted(post_k_edges), "userspace_edges": sorted(post_u_edges)}}


def late_reported(document, pid_o, pid_l, late_module, module_suffix=PROVIDER):
    """N4: O exact and gap-free; L scanned and reported, never silently zero.

    The L verdict stays NON-PASS/UNSUPPORTED (G33): passing means the late
    boundary is REPORTED (edge with a named pre-attach gap, or no edge with
    a named gap), never that the late provider became exact.
    """
    require_initial_observer(document, "n4")
    pid_of, edges = inventory_maps(document, module_suffix)
    scanned = set(pid_of.values())
    assert pid_o in scanned, ("O never scanned", pid_o, sorted(scanned))
    assert pid_l in scanned, ("L never scanned: silently zero", pid_l, sorted(scanned))
    assert pid_o in edges, ("O has no provider edge", pid_o, sorted(edges))
    assert not gaps_for(document, pid_of, pid_o), ("O is not gap-free", pid_o)
    late_gaps = gaps_for(document, pid_of, pid_l, late_module)
    for gap in late_gaps:
        assert known_late_subject(gap.get("subject", ""), late_module), \
            ("unknown late gap subject", gap)
    assert late_gaps and all(g.get("reason") for g in late_gaps), \
        ("L silently zero: no named gap", pid_l)
    if pid_l in edges:
        verdict = "edge-with-gap"
    else:
        verdict = "no-edge-with-gap"
    return {"check": "late-reported", "ok": True, "late": verdict,
            "owned_edges": sorted(edges), "late_gaps": len(late_gaps)}


# ---------------------------------------------------------------- self-test


def good_inventory(edges, gaps=(), observer="initial"):
    pids = [101, 102, 103, 201, 202]
    callers = [{"id": f"c{i}", "pid": pid} for i, pid in enumerate(pids)]
    by_pid = {pid: f"c{i}" for i, pid in enumerate(pids)}
    path = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    return {
        "schema": "p11scope/inventory/v1",
        "callers": callers,
        "modules": [{"id": "m0", "paths": [path]}],
        "edges": [{"caller": by_pid[pid], "module": "m0"}
                  for pid, present in sorted(edges.items()) if present],
        "gaps": [{"subject": subject, "reason": reason, "caller": None,
                  "module": None, "pid": pid} for subject, reason, pid in gaps],
        "pid_namespace": {"observer": observer, "kernel_pids": "initial",
                          "proc_pids": "observer"},
    }


def good_profile(iters=400):
    path = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    return {
        "capture": {"scope": "cgroup", "modules": [{"path": path}]},
        "evidence": {
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "verdict_detail": "attribution_only",
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": [], "status": "exact"}},
        },
        "functions": [{"calls": iters, "errors": 0, "names": [n]} for n in sorted(LEDGER_FUNCTIONS)]
        + [{"calls": 0, "errors": 0, "names": ["C_Login"]}],
    }


def good_copy_up(lane="B"):
    gap = ("x", "identity_mismatch: mapping (0:42, 5) != opened (0:42, 6)", 103)
    if lane == "B":
        post_kernel = good_inventory({101: True, 102: False, 103: False}, [gap])
        post_userspace = good_inventory({101: True, 102: False, 103: True})
        note = "run log: D-C7-3 applies to the post-copy-up userspace edge"
    else:
        post_kernel = good_inventory({101: True, 102: False, 103: False}, [gap])
        post_userspace = good_inventory({101: True, 102: False, 103: False}, [gap])
        note = "run log: D-C7-3 does not apply on lane A"
    return {
        "pre_kernel": good_inventory({101: True, 102: True}),
        "pre_userspace": good_inventory({101: True, 102: True}),
        "post_kernel": post_kernel,
        "post_userspace": post_userspace,
        "pre_profile_a": good_profile(400),
        "pre_profile_b": good_profile(250),
        "post_profile_b": good_profile(250),
        "pid_a": 101,
        "pid_b_pre": 102,
        "pid_b_post": 103,
        "iters_a": 400,
        "iters_b": 250,
        "lane": lane,
        "dc73_note": note,
    }


def refuses(label, check):
    try:
        check()
    except (AssertionError, KeyError, IndexError, TypeError, ValueError):
        print(f"container-cells mutation rejected: {label}")
        return
    raise SystemExit(f"container-cells mutation accepted: {label}")


def self_test():
    assert copy_up(**good_copy_up("B"))["lane"] == "B"
    assert copy_up(**good_copy_up("A"))["lane"] == "A"

    def mutate_copy(label, **overrides):
        inputs = good_copy_up(overrides.pop("lane", "B"))
        inputs.update(overrides)
        refuses(label, lambda: copy_up(**inputs))

    mutate_copy("pre-kernel missing B edge",
                pre_kernel=good_inventory({101: True, 102: False}))
    mutate_copy("pre exact with identity loss",
                pre_kernel=good_inventory(
                    {101: True, 102: True}, [("x", "identity_mismatch", 102)]))
    mutate_copy("pre profile wrong count", pre_profile_b=good_profile(251))
    mutate_copy("pre profile event loss", pre_profile_a={**good_profile(400),
                "evidence": {**good_profile(400)["evidence"], "event_loss": 2}})
    nested = good_inventory({101: True, 102: True},
                            [("pid namespace", "nested", None)], observer="nested")
    mutate_copy("pre pid_namespace cause", pre_kernel=nested)
    mutate_copy("exact attribution across the copy-up",
                post_kernel=good_inventory({101: True, 103: True}))
    mutate_copy("post-kernel no edge without named loss",
                post_kernel=good_inventory({101: True, 103: False}))
    unscanned = good_inventory({101: True, 103: False},
                               [("x", "identity_mismatch", 103)])
    unscanned["callers"] = [c for c in unscanned["callers"] if c["pid"] != 103]
    mutate_copy("post-kernel B unscanned", post_kernel=unscanned)
    mutate_copy("lane-B userspace lost the D-C7-3 edge",
                post_userspace=good_inventory(
                    {101: True, 103: False}, [("x", "identity_mismatch", 103)]))
    mutate_copy("lane-B userspace edge without the D-C7-3 note", dc73_note="nothing recorded")
    mutate_copy("lane-A userspace joins", lane="A",
                post_userspace=good_inventory({101: True, 103: True}))
    mutate_copy("lane-A claims D-C7-3", lane="A", dc73_note="D-C7-3 applies here")
    identical = good_copy_up("B")
    mutate_copy("vacuous identical pre/post",
                post_kernel=copy.deepcopy(identical["pre_kernel"]))
    mutate_copy("post profile wrong count", post_profile_b=good_profile(249))
    mutate_copy("A inexact post",
                post_kernel=good_inventory({101: False, 103: False},
                                           [("x", "identity_mismatch", 103)]))
    refuses("unknown lane", lambda: copy_up(**{**good_copy_up("B"), "lane": "C"}))

    late_module = "/tmp/private/libsofthsm2.so"

    def late(edge, gaps, owned=True):
        return {"document": good_inventory({201: owned, 202: bool(edge)}, gaps),
                "pid_o": 201, "pid_l": 202, "late_module": late_module}

    assert late_reported(**late(True, [(late_module, "first seen after admission", 202)]))["late"] \
        == "edge-with-gap"
    assert late_reported(**late(False, [("maps attribution", "past the cap", 202)]))["late"] \
        == "no-edge-with-gap"

    def mutate_late(label, **inputs):
        refuses(label, lambda: late_reported(**inputs))

    mutate_late("O missing edge",
                **late(True, [(late_module, "r", 202)], owned=False))
    o_gap = good_inventory({201: True, 202: True},
                           [(late_module, "r", 202), ("x", "y", 201)])
    mutate_late("O not gap-free",
                document=o_gap, pid_o=201, pid_l=202, late_module=late_module)
    absent = good_inventory({201: True, 202: False})
    absent["callers"] = [c for c in absent["callers"] if c["pid"] != 202]
    mutate_late("L absent silently zero",
                document=absent, pid_o=201, pid_l=202, late_module=late_module)
    mutate_late("L no edge no gap",
                **late(False, []))
    mutate_late("L edge no gap",
                **late(True, []))
    mutate_late("L unknown gap subject",
                **late(False, [("frobnicate", "r", 202)]))
    stripped = good_inventory({201: True, 202: True}, [(late_module, "r", 202)])
    stripped["gaps"] = []
    mutate_late("stripped-gap control",
                document=stripped, pid_o=201, pid_l=202, late_module=late_module)
    mutate_late("nested observer",
                document=good_inventory({201: True, 202: True},
                                        [(late_module, "r", 202)], observer="nested"),
                pid_o=201, pid_l=202, late_module=late_module)
    for subject, citation in ALLOWED_LATE_SUBJECTS.items():
        assert citation.startswith("src/") and ":" in citation, subject
    assert len(ALLOWED_LATE_SUBJECTS) >= 8
    print("container-cells oracle mutations rejected: OK")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    copy_parser = sub.add_parser("copy-up")
    copy_parser.add_argument("--pre-kernel", required=True)
    copy_parser.add_argument("--pre-userspace", required=True)
    copy_parser.add_argument("--post-kernel", required=True)
    copy_parser.add_argument("--post-userspace", required=True)
    copy_parser.add_argument("--pre-profile-a", required=True)
    copy_parser.add_argument("--pre-profile-b", required=True)
    copy_parser.add_argument("--post-profile-b", required=True)
    copy_parser.add_argument("--pid-a", type=int, required=True)
    copy_parser.add_argument("--pid-b-pre", type=int, required=True)
    copy_parser.add_argument("--pid-b-post", type=int, required=True)
    copy_parser.add_argument("--iters-a", type=int, required=True)
    copy_parser.add_argument("--iters-b", type=int, required=True)
    copy_parser.add_argument("--lane", required=True)
    copy_parser.add_argument("--dc73-note")
    copy_parser.add_argument("--module-suffix", default=PROVIDER)
    late_parser = sub.add_parser("late-reported")
    late_parser.add_argument("file")
    late_parser.add_argument("--pid-o", type=int, required=True)
    late_parser.add_argument("--pid-l", type=int, required=True)
    late_parser.add_argument("--late-module", required=True)
    late_parser.add_argument("--module-suffix", default=PROVIDER)
    options = parser.parse_args(argv)
    if options.self_test:
        self_test()
        return
    if options.command == "copy-up":
        def load(path):
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)

        note = ""
        if options.dc73_note is not None:
            with open(options.dc73_note, encoding="utf-8") as handle:
                note = handle.read()
        result = copy_up(load(options.pre_kernel), load(options.pre_userspace),
                         load(options.post_kernel), load(options.post_userspace),
                         load(options.pre_profile_a), load(options.pre_profile_b),
                         load(options.post_profile_b), options.pid_a, options.pid_b_pre,
                         options.pid_b_post, options.iters_a, options.iters_b,
                         options.lane, note, options.module_suffix)
        print(json.dumps(result, sort_keys=True))
    elif options.command == "late-reported":
        with open(options.file, encoding="utf-8") as handle:
            document = json.load(handle)
        result = late_reported(document, options.pid_o, options.pid_l,
                               options.late_module, options.module_suffix)
        print(json.dumps(result, sort_keys=True))
    else:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
