#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Container-cells oracle for scripts/docker-shared-layer-e2e.sh (D1) and scripts/late-provider-negative.sh (N4).

Subcommands: copy-up (D1 shared-layer / copy-up), late-reported (N4 never-seen
late provider), --self-test. Every check ships a mutation this oracle refuses;
see --self-test and tests/python/test_container_cells_oracle.py.

D1 follows the live run-5/6 shape (Opus D1 identity investigation): pre-copy-up
both backends collapse B onto A's module (same lower file, honest); the span
shows B-pre's old edge ended plus a mapped edge to the new module with B's
overlay key, and B2 plus the round-2 twin mapped to that module new-only, on
BOTH backends with no named identity loss (B-pre's new edge is the known issue
copy-up-stale-caller: B-pre still runs the lower file, and its later calls are
not counted; the twin's post-copy-up calls are measured as missed or fully
counted, never partial). Every kernel run reports backend kernel with a
non-null fallback, recorded as "kernel proof checked no container edge", never
as qualification. The copy-up itself is proven from facts.log (a different
real inode in B's upper layer, same sha256). Fresh captures after B restarts
attribute B exactly on lane B. The observer runs on the host in the initial
PID namespace, so no pid_namespace cause is allowed.

N4 follows the run-1 ruling: O exact and gap-free; L passes when scanned and
EITHER a named gap from the frozen vocabulary references the late module OR
L's edge to the late module states an unwatched prefix (since_ns greater than
the mapping's first_seen_ns) with entries within the L ledger total. The cell
verdict for the L leg stays NON-PASS/UNSUPPORTED (G33): passing means the
boundary is REPORTED, never that the late provider became exact.
"""
import argparse
import json
import re
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
    """Caller PIDs, live provider edges per PID, and the caller-id table.

    Only edges whose mapping.state is live (mapped) count; ended edges are
    not edges.
    """
    assert document["schema"] == "p11scope/inventory/v1", document.get("schema")
    pid_of = {c["id"]: c["pid"] for c in document["callers"]}
    paths_of = {m["id"]: m["paths"] for m in document["modules"]}
    edges = {}
    for edge in document["edges"]:
        assert edge["caller"] in pid_of, ("dangling edge caller", edge)
        assert edge["module"] in paths_of, ("dangling edge module", edge)
        if edge["mapping"]["state"] != "mapped":
            continue
        pid = pid_of[edge["caller"]]
        if any(p.endswith(module_suffix) for p in paths_of[edge["module"]]):
            edges.setdefault(pid, []).append(edge["module"])
    return pid_of, edges


def edge_records(document, module_suffix=PROVIDER):
    """{(pid, module id): edge} for provider edges in any mapping state."""
    assert document["schema"] == "p11scope/inventory/v1", document.get("schema")
    pid_of = {c["id"]: c["pid"] for c in document["callers"]}
    paths_of = {m["id"]: m["paths"] for m in document["modules"]}
    records = {}
    for edge in document["edges"]:
        assert edge["caller"] in pid_of, ("dangling edge caller", edge)
        assert edge["module"] in paths_of, ("dangling edge module", edge)
        if any(p.endswith(module_suffix) for p in paths_of[edge["module"]]):
            records[(pid_of[edge["caller"]], edge["module"])] = edge
    return pid_of, records


def module_keys(document, module_suffix=PROVIDER):
    """{module id: (major, minor, inode)} for provider modules."""
    keys = {}
    for module in document["modules"]:
        if any(p.endswith(module_suffix) for p in module["paths"]):
            device = module["identity"]["device"]
            keys[module["id"]] = (device["major"], device["minor"],
                                  module["identity"]["inode"])
    return keys


COLLAPSE_RE = re.compile(
    r"mapping ObjectKey \{ device: Device \{ major: (\d+), minor: (\d+) \}, "
    r"inode: (\d+) \} was collapsed onto ObjectKey \{ device: Device \{ "
    r"major: (\d+), minor: (\d+) \}, inode: (\d+) \}")


def collapse_gaps(document, module_suffix=PROVIDER):
    """[(mapping key, target key)] for the provider's overlay-collapse gaps."""
    found = []
    for gap in document["gaps"]:
        reason = gap.get("reason") or ""
        if "was collapsed onto" not in reason:
            continue
        if module_suffix not in (gap.get("subject") or ""):
            continue
        match = COLLAPSE_RE.search(reason)
        assert match, ("unparsable collapse gap", gap)
        numbers = tuple(int(part) for part in match.groups())
        found.append(((numbers[0], numbers[1], numbers[2]),
                      (numbers[3], numbers[4], numbers[5])))
    return found


def parse_facts(text):
    """facts.log key=value tokens (whitespace-separated; bare tokens ignored)."""
    facts = {}
    for token in text.split():
        if "=" in token:
            key, value = token.split("=", 1)
            facts[key] = value
    return facts


def stat_key(dev_ino):
    """'138:29662859' (stat %d:%i) -> (major, minor, inode), glibc decoding."""
    dev_text, ino_text = dev_ino.split(":")
    dev = int(dev_text)
    major = ((dev >> 8) & 0xFFF) | ((dev >> 32) & ~0xFFF)
    minor = (dev & 0xFF) | ((dev >> 12) & ~0xFF)
    return (major, minor, int(ino_text))


def known_issue_line(pid, old_module, new_module):
    return (f"KNOWN_ISSUE cell=D1 copy-up-stale-caller pid={pid} "
            f"old_module={old_module} new_module={new_module}")


def measured_issue_line(pid, ledger, counted, module):
    return ("KNOWN_ISSUE cell=D1 copy-up-stale-caller measured: "
            f"ledger={ledger} counted={counted} pid={pid} module={module}")


def boundary_line(unwatched_ns, entries):
    return (f"BOUNDARY cell=N4 late-provider unwatched_ns={unwatched_ns} "
            f"entries={entries}")


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


def copy_up(pre_kernel, pre_userspace, span_kernel, span_userspace,
            fresh_kernel, fresh_userspace, pre_profile_a, pre_profile_b, post_profile_b,
            pid_a, pid_b_pre, pid_b_span, pid_b_post, iters_a, iters_b, lane, dc73_note,
            facts_text, b_pre_round2_calls=None, b_pre_round2_pid=None,
            module_suffix=PROVIDER):
    """D1: pre collapse, the run-5/6 span shape on both backends, fresh exactness.

    pid_b_pre is B's first process (lower mapper, alive through the span);
    pid_b_span is the second process in B that maps the upper copy inside the
    span; pid_b_post is B's main process after the restart. facts_text is
    facts.log, which proves the copy-up (a different real inode in B's upper
    layer, same sha256). b_pre_round2_calls is the measured post-copy-up
    LEDGER total of the round-2 caller b_pre_round2_pid (default pid_b_pre)
    when the driver ran that round, else None (unmeasured). The driver runs
    round 2 on a second pre-copy-up mapper (gated.c runs one round per
    process); that twin is first scanned after the collapse resolves, so its
    only provider edge is the new module. The oracle accepts exactly two
    outcomes for its post-copy-up calls: missed (counted 0, the R-41 known
    issue) or fully counted (a future fix); anything in between fails named.
    The same two outcomes apply to B-pre's own later calls when measured.
    """
    assert lane in ("A", "B"), lane
    assert isinstance(facts_text, str) and facts_text.strip(), "facts.log is empty"
    facts = parse_facts(facts_text)
    for key in ("stat-a-pre", "stat-b-pre", "sha-b-pre",
                "upper-stat-b", "upper-sha-b"):
        assert key in facts, (f"facts.log names no {key}", sorted(facts))
    key_a = stat_key(facts["stat-a-pre"])
    key_b = stat_key(facts["stat-b-pre"])
    upper_dev_ino = facts["upper-stat-b"]
    assert upper_dev_ino != facts["stat-b-pre"], \
        ("copy-up changed no inode", upper_dev_ino)
    assert facts["upper-sha-b"] == facts["sha-b-pre"], \
        "copy-up changed bytes (not same-bytes)"
    copy_up_proof = {"upper": upper_dev_ino, "lower": facts["stat-b-pre"],
                     "sha256": facts["sha-b-pre"]}

    documents = (("pre-kernel", pre_kernel, "kernel"),
                 ("pre-userspace", pre_userspace, "userspace"),
                 ("span-kernel", span_kernel, "kernel"),
                 ("span-userspace", span_userspace, "userspace"),
                 ("fresh-kernel", fresh_kernel, "kernel"),
                 ("fresh-userspace", fresh_userspace, "userspace"))
    for label, document, _want in documents:
        require_initial_observer(document, label)
    kernel_proof = {"finding": "kernel proof checked no container edge",
                    "runs": {}}
    for label, document, want in documents:
        identity = document["observation"]["identity"]
        assert identity["backend"] == want, (label, identity)
        if want == "kernel":
            assert identity["fallback"], (label, "kernel run without a fallback",
                                          identity)
        kernel_proof["runs"][label] = {"backend": identity["backend"],
                                       "fallback": identity["fallback"]}

    # Pre: A and B-pre live-edge one shared module (A's key) with deep_scan
    # evidence; exactly one collapse gap names B's key -> A's key; no named
    # identity loss anywhere.
    pre_k_pid, pre_k_edges = inventory_maps(pre_kernel, module_suffix)
    pre_u_pid, pre_u_edges = inventory_maps(pre_userspace, module_suffix)
    pre_k_keys = module_keys(pre_kernel, module_suffix)
    pre_u_keys = module_keys(pre_userspace, module_suffix)
    _pre_k_pid, pre_k_records = edge_records(pre_kernel, module_suffix)
    _pre_u_pid, pre_u_records = edge_records(pre_userspace, module_suffix)
    for label, edges, keys, records, document in (
            ("pre-kernel", pre_k_edges, pre_k_keys, pre_k_records, pre_kernel),
            ("pre-userspace", pre_u_edges, pre_u_keys, pre_u_records,
             pre_userspace)):
        assert pid_a in edges, (label, pid_a, sorted(edges))
        assert pid_b_pre in edges, (label, pid_b_pre, sorted(edges))
        assert len(set(edges[pid_a])) == 1 and set(edges[pid_a]) == set(edges[pid_b_pre]), \
            (label, "A and B-pre edge different modules", edges[pid_a],
             edges[pid_b_pre])
        shared = edges[pid_a][0]
        assert keys[shared] == key_a, (label, shared, keys[shared], key_a)
        for pid in (pid_a, pid_b_pre):
            mapping = records[(pid, shared)]["mapping"]
            assert mapping["evidence"] == "deep_scan", (label, pid, mapping)
            assert mapping["state"] == "mapped", (label, pid, mapping)
        collapses = collapse_gaps(document, module_suffix)
        assert len(collapses) == 1, (label, "collapse gap count", len(collapses))
        assert collapses[0] == (key_b, key_a), (label, collapses[0], key_b, key_a)
        assert not has_identity_loss(document["gaps"]), (label, "identity loss pre")
    # B's overlay key is new after the copy-up: no pre module carries it.
    assert key_b not in pre_k_keys.values(), ("pre-kernel already has B's key", key_b)
    assert key_b not in pre_u_keys.values(), ("pre-userspace already has B's key", key_b)
    require_profile_exact(pre_profile_a, iters_a, "pre-profile-a", module_suffix)
    require_profile_exact(pre_profile_b, iters_b, "pre-profile-b", module_suffix)

    # Span: both backends agree. A stays on its key; one new module carries
    # B's overlay key under a different id; the collapse gap repeats exactly
    # once; B2 maps the new module with no loss; B-pre's exact known-issue
    # shape is old-ended plus new-mapped.
    span_k_pid, span_k_edges = inventory_maps(span_kernel, module_suffix)
    span_u_pid, span_u_edges = inventory_maps(span_userspace, module_suffix)
    span_k_keys = module_keys(span_kernel, module_suffix)
    span_u_keys = module_keys(span_userspace, module_suffix)
    _span_k_pid, span_k_records = edge_records(span_kernel, module_suffix)
    _span_u_pid, span_u_records = edge_records(span_userspace, module_suffix)
    span_shapes = {}
    for label, pid_of, edges, keys, records, document in (
            ("span-kernel", span_k_pid, span_k_edges, span_k_keys,
             span_k_records, span_kernel),
            ("span-userspace", span_u_pid, span_u_edges, span_u_keys,
             span_u_records, span_userspace)):
        assert pid_a in edges, (label, pid_a, sorted(edges))
        assert len(set(edges[pid_a])) == 1, (label, "A edges", edges[pid_a])
        old_id = edges[pid_a][0]
        assert keys[old_id] == key_a, (label, old_id, keys[old_id], key_a)
        new_ids = [mid for mid, key in keys.items() if key == key_b]
        assert len(new_ids) == 1, (label, "no single new module with B's key",
                                   key_b, sorted(keys.items()))
        new_id = new_ids[0]
        assert new_id != old_id, (label, old_id, new_id)
        collapses = collapse_gaps(document, module_suffix)
        assert len(collapses) == 1, (label, "collapse gap count", len(collapses))
        assert collapses[0] == (key_b, key_a), (label, collapses[0], key_b, key_a)
        assert not has_identity_loss(document["gaps"]), (label, "identity loss in span")
        assert pid_b_span in pid_of.values(), (label, "upper mapper unscanned",
                                               pid_b_span)
        assert sorted(edges.get(pid_b_span, [])) == [new_id], \
            (label, "B2 edges", pid_b_span, edges.get(pid_b_span))
        b2_record = records[(pid_b_span, new_id)]
        assert b2_record["mapping"]["state"] == "mapped", (label, b2_record)
        assert b2_record["entries"]["coverage"].get("lossy") is not True, \
            (label, "B2 lossy", b2_record)
        b_pre_modules = sorted(mid for (pid, mid) in records if pid == pid_b_pre)
        assert b_pre_modules == sorted([old_id, new_id]), \
            (label, "B-pre provider edges changed", b_pre_modules, old_id, new_id)
        assert records[(pid_b_pre, old_id)]["mapping"]["state"] == "ended", \
            (label, "B-pre old edge is not ended")
        assert records[(pid_b_pre, new_id)]["mapping"]["state"] == "mapped", \
            (label, "B-pre new edge is not mapped")
        span_shapes[label] = (old_id, new_id)
    assert (span_k_keys[span_shapes["span-kernel"][0]],
            span_k_keys[span_shapes["span-kernel"][1]]) == \
           (span_u_keys[span_shapes["span-userspace"][0]],
            span_u_keys[span_shapes["span-userspace"][1]]), \
        ("span backends disagree", span_shapes)
    known_issue = {"pid": pid_b_pre, "old_module": span_shapes["span-kernel"][0],
                   "new_module": span_shapes["span-kernel"][1]}

    if b_pre_round2_calls is None:
        assert b_pre_round2_pid is None, "round-2 pid without a measured total"
        b_pre_round2 = {"measured": False}
    else:
        assert isinstance(b_pre_round2_calls, int) and b_pre_round2_calls >= 1, \
            ("bad B-pre round-2 total", b_pre_round2_calls)
        if b_pre_round2_pid is None:
            round2_pid = pid_b_pre
        else:
            assert isinstance(b_pre_round2_pid, int) and b_pre_round2_pid >= 1, \
                ("bad round-2 pid", b_pre_round2_pid)
            round2_pid = b_pre_round2_pid
        legs = {}
        for label, records in (("span_kernel", span_k_records),
                               ("span_userspace", span_u_records)):
            old_id, new_id = span_shapes[label.replace("_", "-")]
            assert (round2_pid, new_id) in records, \
                (label, "no new-module edge for the round-2 caller", round2_pid)
            m8_record = records[(round2_pid, new_id)]
            assert m8_record["mapping"]["state"] == "mapped", \
                (label, "the round-2 new edge is not mapped", round2_pid)
            if round2_pid == pid_b_pre:
                # B-pre was first scanned before the collapse resolved, so it
                # keeps its ended old edge next to the new one.
                assert (round2_pid, old_id) in records, \
                    (label, "no old-module edge for B-pre", round2_pid)
                m7_entries = records[(round2_pid, old_id)]["entries"]["count"]
            else:
                # A B process first scanned after the collapse resolves never
                # had the old module: the twin is new-only by construction.
                assert (round2_pid, old_id) not in records, \
                    (label, "round-2 twin must not have an old-module edge",
                     round2_pid)
                m7_entries = None
            m8_entries = m8_record["entries"]["count"]
            m8_status = m8_record["entries"]["coverage"]["state"]
            assert m8_entries == 0 or m8_entries == b_pre_round2_calls, \
                (label, "partial round-2 count: neither missed nor fully counted",
                 round2_pid, m8_entries, b_pre_round2_calls)
            legs[label] = {"m7_entries": m7_entries, "m8_entries": m8_entries,
                           "m8_status": m8_status}
        assert legs["span_kernel"]["m8_entries"] == legs["span_userspace"]["m8_entries"], \
            ("span backends disagree on the round-2 count", legs)
        b_pre_round2 = {"measured": True, "calls": b_pre_round2_calls,
                        "pid": round2_pid, **legs}

    assert "copy-up-stale-caller" in dc73_note, \
        "run log without the copy-up-stale-caller disclosure"

    # Fresh, after the restart: the anchor is opened from the upper copy.
    fresh_k_pid, fresh_k_edges = inventory_maps(fresh_kernel, module_suffix)
    fresh_u_pid, fresh_u_edges = inventory_maps(fresh_userspace, module_suffix)
    for label, pid_of, edges, document in (
            ("fresh-kernel", fresh_k_pid, fresh_k_edges, fresh_kernel),
            ("fresh-userspace", fresh_u_pid, fresh_u_edges, fresh_userspace)):
        assert pid_a in edges, (label, pid_a, sorted(edges))
        assert pid_b_post in pid_of.values(), (label, "restarted B unscanned", pid_b_post)
        gaps = gaps_for(document, pid_of, pid_b_post)
        if lane == "B":
            # Lane B keys maps by the overlay inode and the anchor names the
            # same upper file: exact on both backends.
            assert pid_b_post in edges, (label, "restarted B lost its edge", pid_b_post)
            assert not has_identity_loss(gaps), (label, "identity loss for restarted B")
        else:
            # Lane A has no recorded row for a fresh anchor: never silent.
            assert pid_b_post in edges or any(g.get("reason") for g in gaps), \
                (label, "restarted B silently zero", pid_b_post)
    require_profile_exact(post_profile_b, iters_b, "post-profile-b", module_suffix)
    return {"check": "copy-up", "ok": True, "lane": lane,
            "pre": {"kernel_edges": sorted(pre_k_edges), "userspace_edges": sorted(pre_u_edges)},
            "span": {"kernel_edges": sorted(span_k_edges), "userspace_edges": sorted(span_u_edges)},
            "fresh": {"kernel_edges": sorted(fresh_k_edges),
                      "userspace_edges": sorted(fresh_u_edges)},
            "copy_up_proof": copy_up_proof,
            "kernel_proof": kernel_proof,
            "known_issue": known_issue,
            "b_pre_round2": b_pre_round2}


def late_reported(document, pid_o, pid_l, late_module, iters_l,
                  module_suffix=PROVIDER):
    """N4: O exact and gap-free; L scanned and reported, never silently zero.

    L passes when scanned and EITHER (a) a named gap from the frozen
    vocabulary references the late module OR (b) L's edge to the late module
    states an unwatched prefix (since_ns greater than that mapping's
    first_seen_ns) with entries within the L ledger total and status
    watched_no_use or counted. The L verdict stays NON-PASS/UNSUPPORTED
    (G33): passing means the late boundary is REPORTED, never that the late
    provider became exact.
    """
    require_initial_observer(document, "n4")
    assert isinstance(iters_l, int) and iters_l >= 1, \
        ("bad L ledger iterations", iters_l)
    ledger_total = len(LEDGER_FUNCTIONS) * iters_l
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
    named = [gap for gap in late_gaps if gap.get("reason")]
    late_ids = [m["id"] for m in document["modules"] if late_module in m["paths"]]
    assert len(late_ids) == 1, ("no single late module", late_module, late_ids)
    late_id = late_ids[0]
    _pid_of, records = edge_records(document, module_suffix)
    late_edges = sorted(mid for (pid, mid) in records
                        if pid == pid_l and mid == late_id)
    assert len(late_edges) <= 1, ("ambiguous L late edge", pid_l, late_edges)
    if named:
        verdict = "edge-with-gap" if pid_l in edges else "no-edge-with-gap"
        if late_edges:
            record = records[(pid_l, late_id)]
            since_ns = record["entries"]["coverage"]["since_ns"]
            first_seen_ns = record["mapping"]["first_seen_ns"]
            if isinstance(since_ns, int) and isinstance(first_seen_ns, int):
                unwatched_ns = since_ns - first_seen_ns
            else:
                unwatched_ns = "unknown"
            boundary = {"late_module": late_module, "module": late_id,
                        "unwatched_ns": unwatched_ns,
                        "entries": record["entries"]["count"],
                        "since_ns": since_ns, "first_seen_ns": first_seen_ns,
                        "status": record["entries"]["coverage"]["state"],
                        "gap_subjects": sorted(g.get("subject", "") for g in named)}
        else:
            boundary = {"late_module": late_module, "module": late_id,
                        "unwatched_ns": "unknown", "entries": "none",
                        "since_ns": None, "first_seen_ns": None, "status": "none",
                        "gap_subjects": sorted(g.get("subject", "") for g in named)}
        return {"check": "late-reported", "ok": True, "late": verdict,
                "owned_edges": sorted(edges), "late_gaps": len(late_gaps),
                "boundary": boundary}
    assert len(late_edges) == 1, ("L silently zero: no late edge and no named gap",
                                  pid_l)
    record = records[(pid_l, late_id)]
    assert record["mapping"]["state"] == "mapped", ("L late edge is not mapped", record)
    since_ns = record["entries"]["coverage"]["since_ns"]
    first_seen_ns = record["mapping"]["first_seen_ns"]
    assert isinstance(since_ns, int) and isinstance(first_seen_ns, int), \
        ("L late edge states no watch window", since_ns, first_seen_ns)
    assert since_ns > first_seen_ns, \
        ("L silently zero: no named gap and no unwatched prefix", pid_l,
         since_ns, first_seen_ns)
    status = record["entries"]["coverage"]["state"]
    count = record["entries"]["count"]
    assert status in ("watched_no_use", "counted"), ("L late edge status", status)
    assert count <= ledger_total, ("L entries above its ledger", count, ledger_total)
    if status == "watched_no_use":
        assert count == 0, ("watched_no_use with entries", count)
    else:
        assert count >= 1, ("counted with zero entries", count)
    boundary = {"late_module": late_module, "module": late_id,
                "unwatched_ns": since_ns - first_seen_ns, "entries": count,
                "since_ns": since_ns, "first_seen_ns": first_seen_ns,
                "status": status, "gap_subjects": []}
    return {"check": "late-reported", "ok": True, "late": "unwatched-prefix",
            "owned_edges": sorted(edges), "late_gaps": len(late_gaps),
            "boundary": boundary}


# ---------------------------------------------------------------- self-test


ST_PIDS = [101, 102, 103, 104, 105, 201, 202]
ST_KEY_A = (0, 138, 100)
ST_KEY_B = (0, 140, 100)
ST_PROVIDER = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"


def st_edge(pid, module, evidence="deep_scan", state="mapped", count=0,
            cov="unknown", since=None, first_seen=1000, lossy=None):
    return {"pid": pid, "module": module, "evidence": evidence, "state": state,
            "count": count, "cov": cov, "since": since,
            "first_seen": first_seen, "lossy": lossy}


def st_collapse(mapping_key=ST_KEY_B, target_key=ST_KEY_A):
    (jmaj, jmnr, jino), (tmaj, tmnr, tino) = mapping_key, target_key
    return (f"{ST_PROVIDER} (ObjectKey {{ device: Device {{ major: {jmaj}, "
            f"minor: {jmnr} }}, inode: {jino} }})",
            f"mapping ObjectKey {{ device: Device {{ major: {jmaj}, minor: {jmnr} }}, "
            f"inode: {jino} }} was collapsed onto ObjectKey {{ device: Device {{ "
            f"major: {tmaj}, minor: {tmnr} }}, inode: {tino} }} by the overlayfs + "
            f"inode metadata + SHA-256 heuristic", None)


def good_inventory(edges, gaps=(), observer="initial", backend="kernel",
                   fallback="anchor_not_installed",
                   modules=(("m7", ST_KEY_A, ST_PROVIDER),)):
    callers = [{"id": f"c{i}", "pid": pid} for i, pid in enumerate(ST_PIDS)]
    by_pid = {pid: f"c{i}" for i, pid in enumerate(ST_PIDS)}
    return {
        "schema": "p11scope/inventory/v1",
        "observation": {"identity": {"backend": backend, "fallback": fallback}},
        "callers": callers,
        "modules": [{"id": mid, "paths": [path],
                     "identity": {"device": {"major": key[0], "minor": key[1]},
                                  "inode": key[2]}}
                    for mid, key, path in modules],
        "edges": [{"caller": by_pid[item["pid"]], "module": item["module"],
                   "mapping": {"evidence": item["evidence"], "state": item["state"],
                               "first_seen_ns": item["first_seen"]},
                   "entries": {"count": item["count"],
                               "coverage": {"state": item["cov"],
                                            "since_ns": item["since"],
                                            "lossy": item["lossy"]}}}
                 for item in edges],
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


ST_MODULES_PRE = (("m7", ST_KEY_A, ST_PROVIDER),)
ST_MODULES_SPAN = (("m7", ST_KEY_A, ST_PROVIDER), ("m8", ST_KEY_B, ST_PROVIDER))
ST_FACTS = ("stat-a-pre=138:100 941088 sha-a-pre=abc\n"
            "stat-b-pre=140:100 941088 sha-b-pre=abc\n"
            "upper-stat-b=51:200 941088 upper-sha-b=abc\n")
ST_NOTE = "run log: copy-up-stale-caller disclosed for B-pre"


def st_pre_edges():
    return [st_edge(101, "m7"), st_edge(102, "m7")]


def st_span_edges():
    # Live runs 5/6: B-pre keeps old-ended plus new-mapped (deep_scan, first
    # scanned before the collapse resolves); the round-2 twin (105) and B2
    # (104) are first scanned after it resolves, so new-only maps_match.
    return [st_edge(101, "m7"),
            st_edge(102, "m7", state="ended"),
            st_edge(102, "m8", cov="watched_no_use", since=3000,
                    first_seen=2000),
            st_edge(104, "m8", evidence="maps_match", cov="watched_no_use",
                    since=3000, first_seen=2000),
            st_edge(105, "m8", evidence="maps_match", cov="watched_no_use",
                    since=3000, first_seen=2000)]


def good_copy_up(lane="B"):
    gap = st_collapse()
    return {
        "pre_kernel": good_inventory(st_pre_edges(), [gap], backend="kernel",
                                     fallback="anchor_not_installed",
                                     modules=ST_MODULES_PRE),
        "pre_userspace": good_inventory(st_pre_edges(), [gap],
                                        backend="userspace", fallback=None,
                                        modules=ST_MODULES_PRE),
        "span_kernel": good_inventory(st_span_edges(), [gap], backend="kernel",
                                      fallback="anchor_not_installed",
                                      modules=ST_MODULES_SPAN),
        "span_userspace": good_inventory(st_span_edges(), [gap],
                                         backend="userspace", fallback=None,
                                         modules=ST_MODULES_SPAN),
        "fresh_kernel": good_inventory([st_edge(101, "m7"), st_edge(103, "m8")],
                                       backend="kernel",
                                       fallback="anchor_not_installed",
                                       modules=ST_MODULES_SPAN),
        "fresh_userspace": good_inventory([st_edge(101, "m7"), st_edge(103, "m8")],
                                          backend="userspace", fallback=None,
                                          modules=ST_MODULES_SPAN),
        "pre_profile_a": good_profile(400),
        "pre_profile_b": good_profile(250),
        "post_profile_b": good_profile(250),
        "pid_a": 101,
        "pid_b_pre": 102,
        "pid_b_span": 104,
        "pid_b_post": 103,
        "iters_a": 400,
        "iters_b": 250,
        "lane": lane,
        "dc73_note": ST_NOTE,
        "facts_text": ST_FACTS,
    }


def refuses(label, check):
    try:
        check()
    except (AssertionError, KeyError, IndexError, TypeError, ValueError):
        print(f"container-cells mutation rejected: {label}")
        return
    raise SystemExit(f"container-cells mutation accepted: {label}")


def refuses_with(label, text, check):
    """The check must fail with `text` in its message (a named failure)."""
    try:
        check()
    except (AssertionError, KeyError, IndexError, TypeError, ValueError) as error:
        assert text in str(error), (label, "unnamed failure", str(error))
        print(f"container-cells mutation rejected: {label}")
        return
    raise SystemExit(f"container-cells mutation accepted: {label}")


def self_test():
    healthy = copy_up(**good_copy_up("B"))
    assert healthy["lane"] == "B"
    assert healthy["known_issue"] == {"pid": 102, "old_module": "m7",
                                      "new_module": "m8"}
    assert healthy["b_pre_round2"] == {"measured": False}
    assert "checked no container edge" in healthy["kernel_proof"]["finding"]
    assert copy_up(**good_copy_up("A"))["lane"] == "A"
    assert known_issue_line(102, "m7", "m8") == \
        "KNOWN_ISSUE cell=D1 copy-up-stale-caller pid=102 old_module=m7 new_module=m8"
    assert boundary_line(1000, 0) == \
        "BOUNDARY cell=N4 late-provider unwatched_ns=1000 entries=0"

    def mutate_copy(label, **overrides):
        inputs = good_copy_up(overrides.pop("lane", "B"))
        inputs.update(overrides)
        refuses(label, lambda: copy_up(**inputs))

    mutate_copy("pre-kernel missing B edge",
                pre_kernel=good_inventory([st_edge(101, "m7")], [st_collapse()],
                                          backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre-kernel A and B-pre on different modules",
                pre_kernel=good_inventory([st_edge(101, "m7"), st_edge(102, "m8")],
                                          [st_collapse()], backend="kernel",
                                          modules=ST_MODULES_SPAN))
    mutate_copy("pre B-pre edge not deep_scan",
                pre_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre B-pre ended edge is not an edge",
                pre_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", state="ended")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre collapse gap missing",
                pre_kernel=good_inventory(st_pre_edges(), backend="kernel",
                                          modules=ST_MODULES_PRE))
    mutate_copy("pre collapse gap duplicated",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse(), st_collapse()],
                                          backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre collapse gap wrong keys",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse((0, 141, 100))],
                                          backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre exact with identity loss",
                pre_kernel=good_inventory(
                    st_pre_edges(), [st_collapse(), ("x", "identity_mismatch", 102)],
                    backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("pre-kernel without kernel identity",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse()],
                                          backend="userspace", fallback=None,
                                          modules=ST_MODULES_PRE))
    mutate_copy("pre-kernel without fallback",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse()],
                                          backend="kernel", fallback=None,
                                          modules=ST_MODULES_PRE))
    mutate_copy("B key already in pre modules",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse()],
                                          backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("pre profile wrong count", pre_profile_b=good_profile(251))
    mutate_copy("pre profile event loss", pre_profile_a={**good_profile(400),
                "evidence": {**good_profile(400)["evidence"], "event_loss": 2}})
    nested = good_inventory(st_pre_edges(), [st_collapse(),
                            ("pid namespace", "nested", None)], observer="nested",
                            backend="kernel", modules=ST_MODULES_PRE)
    mutate_copy("pre pid_namespace cause", pre_kernel=nested)
    mutate_copy("span without new module",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7"),
                     st_edge(104, "m7", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("span collapse gap duplicated",
                span_kernel=good_inventory(st_span_edges(), [st_collapse(), st_collapse()],
                                           backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span collapse gap missing",
                span_kernel=good_inventory(st_span_edges(), backend="kernel",
                                           modules=ST_MODULES_SPAN))
    mutate_copy("span B2 without edge",
                span_kernel=good_inventory(
                    [item for item in st_span_edges() if item["pid"] != 104],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B2 edge ended",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", state="ended"),
                     st_edge(102, "m8", cov="watched_no_use", since=3000,
                            first_seen=2000),
                     st_edge(104, "m8", evidence="maps_match", state="ended")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B2 with identity loss",
                span_kernel=good_inventory(
                    st_span_edges(), [st_collapse(), ("x", "identity_mismatch", 104)],
                    backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span backends disagree on the new module",
                span_userspace=good_inventory(
                    st_span_edges(), [st_collapse()], backend="userspace",
                    fallback=None,
                    modules=(("m7", ST_KEY_A, ST_PROVIDER),
                             ("m8", (0, 141, 100), ST_PROVIDER))))
    mutate_copy("span B-pre old edge still mapped",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7"),
                     st_edge(102, "m8", cov="watched_no_use", since=3000,
                            first_seen=2000),
                     st_edge(104, "m8", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B-pre new edge ended",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", state="ended"),
                     st_edge(102, "m8", state="ended"),
                     st_edge(104, "m8", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B-pre new edge missing",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", state="ended"),
                     st_edge(104, "m8", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("copy-up unproven: upper inode unchanged",
                facts_text=ST_FACTS.replace("upper-stat-b=51:200",
                                            "upper-stat-b=140:100"))
    mutate_copy("copy-up bytes drifted",
                facts_text=ST_FACTS.replace("upper-sha-b=abc", "upper-sha-b=abd"))
    mutate_copy("facts.log without the upper stat",
                facts_text="stat-a-pre=138:100 1 sha-a-pre=x\n")
    mutate_copy("run log without the disclosure", dc73_note="nothing recorded")
    mutate_copy("disproven kernel-refusal disclosure",
                dc73_note="D-C7-3 applies; the kernel refusal with "
                          "identity_mismatch is the correct leg.")
    round2 = good_copy_up("B")
    round2["b_pre_round2_calls"] = 1500
    assert copy_up(**round2)["b_pre_round2"]["calls"] == 1500
    round2_bad = good_copy_up("B")
    round2_bad["b_pre_round2_calls"] = 1500
    claimed = [st_edge(101, "m7"),
               st_edge(102, "m7", state="ended"),
               st_edge(102, "m8", cov="counted", count=9, since=3000,
                      first_seen=2000),
               st_edge(104, "m8", evidence="maps_match")]
    round2_bad["span_kernel"] = good_inventory(claimed, [st_collapse()],
                                               backend="kernel",
                                               modules=ST_MODULES_SPAN)
    refuses("round-2 calls claimed by the new edge",
            lambda: copy_up(**round2_bad))
    round2_twin = good_copy_up("B")
    round2_twin["b_pre_round2_calls"] = 1500
    round2_twin["b_pre_round2_pid"] = 105
    assert copy_up(**round2_twin)["b_pre_round2"]["pid"] == 105
    assert copy_up(**round2_twin)["b_pre_round2"]["span_kernel"]["m7_entries"] is None
    # The run-5/6 twin shape is new-only: an old-module edge for a caller
    # first scanned after the collapse resolves is forbidden.
    twin_old = [st_edge(101, "m7"),
                st_edge(102, "m7", state="ended"),
                st_edge(102, "m8", cov="watched_no_use", since=3000,
                       first_seen=2000),
                st_edge(104, "m8", evidence="maps_match"),
                st_edge(105, "m7", state="ended"),
                st_edge(105, "m8", evidence="maps_match", cov="watched_no_use",
                       since=3000, first_seen=2000)]
    round2_twin_old = good_copy_up("B")
    round2_twin_old["b_pre_round2_calls"] = 1500
    round2_twin_old["b_pre_round2_pid"] = 105
    round2_twin_old["span_kernel"] = good_inventory(twin_old, [st_collapse()],
                                                    backend="kernel",
                                                    modules=ST_MODULES_SPAN)
    refuses_with("round-2 twin must not have an old-module edge",
                 "must not have an old-module edge",
                 lambda: copy_up(**round2_twin_old))
    # A future fix that counts every post-copy-up call passes too.
    twin_counted_edges = [st_edge(101, "m7"),
                          st_edge(102, "m7", state="ended"),
                          st_edge(102, "m8", cov="watched_no_use", since=3000,
                                 first_seen=2000),
                          st_edge(104, "m8", evidence="maps_match"),
                          st_edge(105, "m8", evidence="maps_match", cov="counted",
                                 count=1500, since=3000, first_seen=2000)]
    round2_twin_counted = good_copy_up("B")
    round2_twin_counted["b_pre_round2_calls"] = 1500
    round2_twin_counted["b_pre_round2_pid"] = 105
    round2_twin_counted["span_kernel"] = good_inventory(
        twin_counted_edges, [st_collapse()], backend="kernel",
        modules=ST_MODULES_SPAN)
    round2_twin_counted["span_userspace"] = good_inventory(
        twin_counted_edges, [st_collapse()], backend="userspace",
        fallback=None, modules=ST_MODULES_SPAN)
    assert copy_up(**round2_twin_counted)["b_pre_round2"]["span_kernel"]["m8_entries"] == 1500
    # Anything between missed (0) and fully counted (ledger) fails named.
    twin_claimed = [st_edge(101, "m7"),
                    st_edge(102, "m7", state="ended"),
                    st_edge(102, "m8", cov="watched_no_use", since=3000,
                           first_seen=2000),
                    st_edge(104, "m8", evidence="maps_match"),
                    st_edge(105, "m8", evidence="maps_match", cov="counted",
                           count=9, since=3000, first_seen=2000)]
    round2_twin_bad = good_copy_up("B")
    round2_twin_bad["b_pre_round2_calls"] = 1500
    round2_twin_bad["b_pre_round2_pid"] = 105
    round2_twin_bad["span_kernel"] = good_inventory(twin_claimed, [st_collapse()],
                                                    backend="kernel",
                                                    modules=ST_MODULES_SPAN)
    refuses_with("round-2 twin partial count refused", "partial",
                 lambda: copy_up(**round2_twin_bad))
    # Same two outcomes for B-pre's own later calls when measured.
    b_pre_counted_edges = [st_edge(101, "m7"),
                           st_edge(102, "m7", state="ended"),
                           st_edge(102, "m8", cov="counted", count=1500,
                                  since=3000, first_seen=2000),
                           st_edge(104, "m8", evidence="maps_match")]
    round2_b_pre_counted = good_copy_up("B")
    round2_b_pre_counted["b_pre_round2_calls"] = 1500
    round2_b_pre_counted["span_kernel"] = good_inventory(
        b_pre_counted_edges, [st_collapse()], backend="kernel",
        modules=ST_MODULES_SPAN)
    round2_b_pre_counted["span_userspace"] = good_inventory(
        b_pre_counted_edges, [st_collapse()], backend="userspace",
        fallback=None, modules=ST_MODULES_SPAN)
    assert copy_up(**round2_b_pre_counted)["b_pre_round2"]["span_kernel"]["m8_entries"] == 1500
    refuses_with("round-2 B-pre partial count refused", "partial",
                 lambda: copy_up(**round2_bad))
    # The two backends must agree on missed vs counted.
    round2_split = good_copy_up("B")
    round2_split["b_pre_round2_calls"] = 1500
    round2_split["b_pre_round2_pid"] = 105
    round2_split["span_userspace"] = good_inventory(
        twin_counted_edges, [st_collapse()], backend="userspace",
        fallback=None, modules=ST_MODULES_SPAN)
    refuses_with("round-2 backends disagree on the count", "disagree",
                 lambda: copy_up(**round2_split))
    assert measured_issue_line(105, 1500, 0, "m8") == \
        ("KNOWN_ISSUE cell=D1 copy-up-stale-caller measured: ledger=1500 "
         "counted=0 pid=105 module=m8")
    twin_missing = good_copy_up("B")
    twin_missing["b_pre_round2_calls"] = 1500
    twin_missing["b_pre_round2_pid"] = 105
    twin_missing["span_kernel"] = good_inventory(
        [item for item in st_span_edges() if item["pid"] != 105],
        [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN)
    refuses("round-2 twin without a new edge",
            lambda: copy_up(**twin_missing))
    twin_nocalls = good_copy_up("B")
    twin_nocalls["b_pre_round2_pid"] = 105
    refuses("round-2 pid without a measured total",
            lambda: copy_up(**twin_nocalls))
    mutate_copy("post profile wrong count", post_profile_b=good_profile(249))
    mutate_copy("A inexact in the span",
                span_kernel=good_inventory(
                    [st_edge(102, "m7", state="ended"),
                     st_edge(102, "m8", cov="watched_no_use", since=3000,
                            first_seen=2000),
                     st_edge(104, "m8", evidence="maps_match")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("lane-B fresh kernel lost restarted B",
                fresh_kernel=good_inventory([st_edge(101, "m7")],
                                            backend="kernel",
                                            modules=ST_MODULES_SPAN))
    mutate_copy("lane-B fresh userspace identity loss",
                fresh_userspace=good_inventory(
                    [st_edge(101, "m7"), st_edge(103, "m8")],
                    [("x", "identity_mismatch", 103)], backend="userspace",
                    fallback=None, modules=ST_MODULES_SPAN))
    fresh_unscanned = good_inventory([st_edge(101, "m7")], backend="kernel",
                                     modules=ST_MODULES_SPAN)
    fresh_unscanned["callers"] = [c for c in fresh_unscanned["callers"]
                                  if c["pid"] != 103]
    mutate_copy("fresh restarted B unscanned", fresh_kernel=fresh_unscanned)
    mutate_copy("lane-A fresh restarted B silently zero", lane="A",
                fresh_userspace=good_inventory([st_edge(101, "m7")],
                                               backend="userspace",
                                               fallback=None,
                                               modules=ST_MODULES_SPAN))
    mutate_copy("fresh A inexact",
                fresh_userspace=good_inventory([st_edge(103, "m8")],
                                               backend="userspace",
                                               fallback=None,
                                               modules=ST_MODULES_SPAN))
    refuses("unknown lane", lambda: copy_up(**{**good_copy_up("B"), "lane": "C"}))

    late_module = "/tmp/private/libsofthsm2.so"
    late_modules = (("m7", (0, 412, 900), ST_PROVIDER),
                    ("m8", (0, 138, 901), late_module))

    def late(edge, gaps, cov="watched_no_use", count=0, since=2000,
             first_seen=1000, owned=True, iters_l=250):
        items = []
        if owned:
            items.append(st_edge(201, "m7", count=6 * 400, cov="counted",
                                 since=1500, first_seen=1000, lossy=False))
        if edge:
            items.append(st_edge(202, "m8", count=count, cov=cov, since=since,
                                 first_seen=first_seen))
        return {"document": good_inventory(items, gaps, backend="kernel",
                                           fallback="below_threshold",
                                           modules=late_modules),
                "pid_o": 201, "pid_l": 202, "late_module": late_module,
                "iters_l": iters_l}

    assert late_reported(**late(True, []))["late"] == "unwatched-prefix"
    assert late_reported(**late(True, [], cov="counted", count=9))["late"] == \
        "unwatched-prefix"
    assert late_reported(**late(True, [(late_module, "first seen after admission", 202)],
                                   since=1000))["late"] == "edge-with-gap"
    assert late_reported(**late(False, [("maps attribution", "past the cap", 202)]))["late"] \
        == "no-edge-with-gap"

    def mutate_late(label, **inputs):
        refuses(label, lambda: late_reported(**inputs))

    mutate_late("O missing edge",
                **late(True, [], owned=False))
    o_gap = good_inventory([st_edge(201, "m7"), st_edge(202, "m8")],
                           [(late_module, "r", 202), ("x", "y", 201)],
                           backend="kernel", fallback="below_threshold",
                           modules=late_modules)
    mutate_late("O not gap-free",
                document=o_gap, pid_o=201, pid_l=202, late_module=late_module,
                iters_l=250)
    absent = good_inventory([st_edge(201, "m7")], backend="kernel",
                            fallback="below_threshold", modules=late_modules)
    absent["callers"] = [c for c in absent["callers"] if c["pid"] != 202]
    mutate_late("L absent silently zero",
                document=absent, pid_o=201, pid_l=202, late_module=late_module,
                iters_l=250)
    mutate_late("L no edge no gap",
                **late(False, []))
    mutate_late("L edge no gap and no prefix",
                **late(True, [], since=1000))
    mutate_late("L since rewritten to first_seen",
                **late(True, [], since=500))
    mutate_late("L unknown gap subject",
                **late(False, [("frobnicate", "r", 202)]))
    stripped = good_inventory([st_edge(201, "m7"), st_edge(202, "m8")],
                              [(late_module, "r", 202)], backend="kernel",
                              fallback="below_threshold", modules=late_modules)
    stripped["gaps"] = []
    mutate_late("stripped-gap control",
                document=stripped, pid_o=201, pid_l=202, late_module=late_module,
                iters_l=250)
    mutate_late("nested observer",
                document=good_inventory([st_edge(201, "m7"), st_edge(202, "m8")],
                                        [(late_module, "r", 202)],
                                        observer="nested", backend="kernel",
                                        fallback="below_threshold",
                                        modules=late_modules),
                pid_o=201, pid_l=202, late_module=late_module, iters_l=250)
    mutate_late("L entries above its ledger",
                **late(True, [], cov="counted", count=6 * 250 + 1))
    mutate_late("L counted with zero entries",
                **late(True, [], cov="counted", count=0))
    mutate_late("L watched_no_use with entries",
                **late(True, [], cov="watched_no_use", count=3))
    for subject, citation in ALLOWED_LATE_SUBJECTS.items():
        assert citation.startswith("src/") and ":" in citation, subject
    assert len(ALLOWED_LATE_SUBJECTS) >= 8
    print("container-cells oracle mutations rejected: OK")


def main(argv):
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="controller reruns (dev host; the drivers run these oracle "
               "commands internally):\n"
               "  python3 -I scripts/container-cells-oracle.py copy-up --lane B \\\n"
               "      --pre-kernel $WORK/d1-pre-kernel.json "
               "--pre-userspace $WORK/d1-pre-userspace.json \\\n"
               "      --span-kernel $WORK/d1-span-kernel.json "
               "--span-userspace $WORK/d1-span-userspace.json \\\n"
               "      --fresh-kernel $WORK/d1-fresh-kernel.json "
               "--fresh-userspace $WORK/d1-fresh-userspace.json \\\n"
               "      --pre-profile-a $WORK/d1-pre-a.json "
               "--pre-profile-b $WORK/d1-pre-b.json \\\n"
               "      --post-profile-b $WORK/d1-post-b.json \\\n"
               "      --pid-a $PID_A --pid-b-pre $PID_B_PRE "
               "--pid-b-span $PID_B2 --pid-b-post $PID_B_POST \\\n"
               "      --iters-a 400 --iters-b 250 --facts-log $WORK/facts.log "
               "--dc73-note $WORK/dc73-note.txt\n"
               "  python3 -I scripts/container-cells-oracle.py late-reported "
               "$WORK/n4.json \\\n"
               "      --pid-o $PID_O --pid-l $PID_L "
               "--late-module /tmp/private/libsofthsm2.so --iters-l 250",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    copy_parser = sub.add_parser("copy-up")
    copy_parser.add_argument("--pre-kernel", required=True)
    copy_parser.add_argument("--pre-userspace", required=True)
    copy_parser.add_argument("--span-kernel", required=True)
    copy_parser.add_argument("--span-userspace", required=True)
    copy_parser.add_argument("--fresh-kernel", required=True)
    copy_parser.add_argument("--fresh-userspace", required=True)
    copy_parser.add_argument("--pre-profile-a", required=True)
    copy_parser.add_argument("--pre-profile-b", required=True)
    copy_parser.add_argument("--post-profile-b", required=True)
    copy_parser.add_argument("--pid-a", type=int, required=True)
    copy_parser.add_argument("--pid-b-pre", type=int, required=True)
    copy_parser.add_argument("--pid-b-span", type=int, required=True)
    copy_parser.add_argument("--pid-b-post", type=int, required=True)
    copy_parser.add_argument("--iters-a", type=int, required=True)
    copy_parser.add_argument("--iters-b", type=int, required=True)
    copy_parser.add_argument("--lane", required=True)
    copy_parser.add_argument("--dc73-note")
    copy_parser.add_argument("--facts-log", required=True)
    copy_parser.add_argument("--b-pre-round2-calls", type=int, default=None)
    copy_parser.add_argument("--b-pre-round2-pid", type=int, default=None)
    copy_parser.add_argument("--module-suffix", default=PROVIDER)
    late_parser = sub.add_parser("late-reported")
    late_parser.add_argument("file")
    late_parser.add_argument("--pid-o", type=int, required=True)
    late_parser.add_argument("--pid-l", type=int, required=True)
    late_parser.add_argument("--late-module", required=True)
    late_parser.add_argument("--iters-l", type=int, required=True)
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
        facts = open(options.facts_log, encoding="utf-8").read()
        result = copy_up(load(options.pre_kernel), load(options.pre_userspace),
                         load(options.span_kernel), load(options.span_userspace),
                         load(options.fresh_kernel), load(options.fresh_userspace),
                         load(options.pre_profile_a), load(options.pre_profile_b),
                         load(options.post_profile_b), options.pid_a, options.pid_b_pre,
                         options.pid_b_span, options.pid_b_post, options.iters_a,
                         options.iters_b, options.lane, note, facts,
                         options.b_pre_round2_calls, options.b_pre_round2_pid,
                         options.module_suffix)
        print(json.dumps(result, sort_keys=True))
        known = result["known_issue"]
        print(known_issue_line(known["pid"], known["old_module"],
                               known["new_module"]),
              file=sys.stderr)
        round2 = result["b_pre_round2"]
        if round2.get("measured"):
            print(measured_issue_line(round2["pid"], round2["calls"],
                                      round2["span_kernel"]["m8_entries"],
                                      known["new_module"]),
                  file=sys.stderr)
    elif options.command == "late-reported":
        with open(options.file, encoding="utf-8") as handle:
            document = json.load(handle)
        result = late_reported(document, options.pid_o, options.pid_l,
                               options.late_module, options.iters_l,
                               options.module_suffix)
        print(json.dumps(result, sort_keys=True))
        print(boundary_line(result["boundary"]["unwatched_ns"],
                            result["boundary"]["entries"]),
              file=sys.stderr)
    else:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
