#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Container-cells oracle for scripts/docker-shared-layer-e2e.sh (D1), scripts/docker-copyup-changed-e2e.sh (D1-changed) and scripts/late-provider-negative.sh (N4).

Subcommands: copy-up (D1 shared-layer / copy-up), copy-up-changed
(D1-changed different-bytes copy-up), copy-up-midcapture
(D1-changed-midcapture: the patch lands during the running profile),
late-reported (N4 never-seen late provider), --self-test. Every check
ships a mutation this oracle refuses; see --self-test and
tests/python/test_container_cells_oracle.py.

D1 follows the honest span split. Pre-copy-up the kernel leg collapses
B onto A's module (same lower file, honest) while the userspace leg
gaps both joins (no kernel witness there). The span shows B-pre's
collapsed edge ended and its stale ranges rejoined on the new module
carrying B's key (mapped, deep_scan, gap-free: the stale join); B2 and
the round-2 twin are each either gap-only (the sweep never attributed
the mapper: no edge, only the unproven gap) or admitted under the new
module but unprobed (mapped or uncertain, deep_scan evidence, zero
counted entries with the not_attached disclosure, never a gap). The two
mapper shapes are the documented sweep-attribution race, not per-host
pins: each branch carries its distinguishing evidence, and the verdict
records which shape each mapper took. All four cell pids stay gap-only
on the userspace span leg. No named identity loss is allowed on any leg:
pre, span and fresh all assert global zero (the 0-vs-2 span flip race is
a named known flake, never an allowance). A forced-kernel run either
names its first proof fallback or reports null (no proof attempted: the
sweep skipped under the 256 cap, never a proof claim). The copy-up
itself is proven from facts.log (a different real inode in B's upper
layer, same sha256: same bytes, different file identities), which also
proves B's mount stacks at least two lower layers. A span profile of B's
cgroup shows one stale row under the merge path (the twin's exact
ledger, no layer marker) with an honestly lossy verdict (concrete_gap:
the upper ranges refuse as an ambiguous all-plain collision, disclosed
in skipped, so B2's in-span round is uncounted but never silent). Fresh
captures after B restarts attribute B exactly on its own key. The
observer runs on the host in the initial PID namespace, so no
pid_namespace cause is allowed.

D1-changed patches one unmapped provider byte inside B (the holder
image's patch-unmapped tool), so the copy-up changes both the inode
and the bytes and no byte-identical collapse can preempt the witness.
The kernel leg attributes B-pre to the witness-proven lower module and
B2 to the upper module (the pair routes by proof under one maps key or
two); the userspace leg honestly gaps both joins (the negative); the
cgroup-B profile counts the stale ledger S on the pre_copy_up row and
the fresh ledger F on the upper row, both exact, with S != F so a
swapped routing fails. All legs are settled single-pass captures (no
spanning), and the loss gate is global zero on every leg.

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
# harness, never silently accepted). Vocabulary status: SYNTHETIC-ONLY. N4
# has run twice (dev run 2, fedora) with zero late gaps both times, so
# branch (a) and this list are neither confirmed nor corrected against
# live output; the first live late gap confirms or corrects the list.
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

# Finite kernel-fallback vocabulary a forced-kernel run may name (anything
# else is drift, never silently accepted). Runtime labels come from
# KernelFallbackReason::label (src/discovery/kernel_identity.rs:529-543)
# plus the fixed target-run-limit detail rendered by
# runtime_fallback_label (src/inspect_system.rs:3185-3191); selection and
# session-setup labels come from IdentityUnavailable::label
# (src/inspect_system.rs:2724-2736); the anchor-install sites note
# anchor_not_installed directly (src/inspect_system.rs:3639, 3755).
# zombie_batch is deliberately excluded: it never becomes the surfaced
# first reason (src/discovery/kernel_identity.rs:521-525).
KERNEL_FALLBACK_LABELS = frozenset({
    "below_threshold",
    "fd_headroom",
    "fd_headroom: target_run_limit",
    "anchor_not_installed",
    "scope_unavailable",
    "deadline",
    "clock_unavailable",
    "stream_invalid",
    "target_unavailable",
    "unvisited",
    "conflicting_duplicate",
    "no_btf",
    "kernel_fix_missing",
    "no_task_iter_pidfd",
    "numbering_mismatch",
    "numbering_unknown",
    "permission_denied",
    "load_failed",
    "probe_failed",
})

KERNEL_PROOF_FINDING = (
    "kernel runs recorded per capture (see runs): a fallback names the "
    "first attempted proof's fallback, null is forced selection with no "
    "proof attempted (the sweep skipped under the 256 cap)"
)


DEVICE_SUBJECT_RE = re.compile(r"^device (\d+):(\d+) inode (\d+)$")


def known_late_subject(subject, late_module, late_key, pid_l):
    """A late-leg gap subject that names the late module (or a frozen cause).

    Dynamic per-file subjects only pass when they ARE the late module: its
    maps path, its device:ino identity (src/discovery/scan.rs:4104), or
    L's own /proc/<pid>/mem read (src/discovery/scan.rs:4041). An
    unrelated .so, device or mem subject for L's pid FAILs.
    """
    if subject in ALLOWED_LATE_SUBJECTS or subject == late_module:
        return True
    if subject == f"/proc/{pid_l}/mem":
        return True
    match = DEVICE_SUBJECT_RE.match(subject)
    if match is None:
        return False
    return (int(match.group(1)), int(match.group(2)),
            int(match.group(3))) == late_key


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


def stale_caller_line(pid):
    return (f"D1 cell=D1 copy-up-stale-caller resolved: pid={pid} "
            f"edge=new-module mapped (stale ranges rejoined the proven lower "
            f"on the cell's own key; the collapsed old edge ended; no gap)")


def unproven_gaps_for(document, pid_of, pid, module_suffix=PROVIDER):
    """The honest overlay gaps for one pid: original_file_unproven on the cell path."""
    return [gap for gap in gaps_for(document, pid_of, pid)
            if (gap.get("subject") or "").endswith(module_suffix)
            and "original_file_unproven" in (gap.get("reason") or "")]


def require_userspace_gap_only(document, label, pids, cell_keys, module_suffix=PROVIDER):
    """A userspace leg never edges the overlay provider: explicit userspace
    disables the kernel witness, so the guard's every overlay join is
    honestly unproven. Every cell pid is scanned yet un-edged and carries
    the unproven gap; no collapse names a cell key; no identity loss.
    """
    pid_of, edges = inventory_maps(document, module_suffix)
    for pid in pids:
        assert pid in pid_of.values(), (label, "cell pid unscanned", pid)
        assert pid not in edges, \
            (label, "userspace leg edged the provider", pid, edges.get(pid))
        assert unproven_gaps_for(document, pid_of, pid, module_suffix), \
            (label, "cell pid without the honest gap", pid)
    for mapping_key, target_key in collapse_gaps(document, module_suffix):
        assert mapping_key not in cell_keys and target_key not in cell_keys, \
            (label, "userspace collapse names a cell key", mapping_key, target_key)
    assert not has_identity_loss(document["gaps"]), (label, "identity loss")


def round2_line(pid, ledger, shape):
    if shape == "gap-only":
        tail = "gap=original_file_unproven (uncounted: no edge)"
    else:
        tail = f"(admitted: {shape} new edge, uncounted: not_attached)"
    return ("D1 cell=D1 copy-up-round2-caller resolved: "
            f"pid={pid} ledgered={ledger} {tail}")


def boundary_line(unwatched_ns, entries):
    return (f"BOUNDARY cell=N4 late-provider unwatched_ns={unwatched_ns} "
            f"entries={entries}")


def assert_late_edge_within_ledger(record, ledger_total):
    """L's edge count/status rule, shared by the gap and prefix branches."""
    status = record["entries"]["coverage"]["state"]
    count = record["entries"]["count"]
    assert status in ("watched_no_use", "counted"), ("L late edge status", status)
    assert count <= ledger_total, ("L entries above its ledger", count,
                                   ledger_total)
    if status == "watched_no_use":
        assert count == 0, ("watched_no_use with entries", count)
    else:
        assert count >= 1, ("counted with zero entries", count)


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


def require_span_profile_stale_row(document, iters_b3, label,
                                    module_suffix=PROVIDER):
    """The cgroup-B capture spanning the copy-up: one stale row, exact totals.

    The profile keeps a single module row (no second object: the upper
    ranges refuse as an ambiguous all-plain collision — the named
    profile-spanning gap, disclosed below) and counts the stale twin's
    ledger exactly on it: six named rows of iters_b3, zero errors, no
    loss, no in-flight rows. Any fresh-side leak inflates a total and
    fails. The verdict is honestly lossy (concrete_gap) with the
    refusal published in skipped: B2's in-span round is uncounted but
    never silent.
    """
    modules = [module for module in document["capture"]["modules"]
               if module["path"].endswith(module_suffix)]
    assert len(modules) == 1, (label, "want the one stale row", modules)
    assert modules[0].get("layer") is None, (label, "no layer marker", modules)
    rows = [row for row in document["evidence"]["discovery"]
            if row["path"].endswith(module_suffix)]
    assert len(rows) == 1, (label, "want the one discovery row", rows)
    assert rows[0].get("layer") is None, (label, "no layer marker", rows)
    identity = ((rows[0]["dev"][0], rows[0]["dev"][1]), rows[0]["ino"],
                rows[0]["sha256"])
    for name in sorted(LEDGER_FUNCTIONS):
        named = [row for row in document["functions"]
                 if row.get("names") == [name] and row["calls"]]
        assert len(named) == 1, (label, name, "want the one stale row", named)
        assert named[0]["calls"] == iters_b3, (label, name, named, iters_b3)
        assert named[0]["errors"] == 0, (label, name, named)
        module = named[0]["module"]
        assert ((module["dev"][0], module["dev"][1]), module["ino"],
                module["sha256"]) == identity, (label, name, named)
        assert named[0].get("module_ambiguous") is False, (label, name, named)
    evidence = document["evidence"]
    assert document["capture"]["scope"] == "cgroup", (label, document["capture"])
    require_initial_observer(evidence, label)
    assert evidence["attached_probes"] > 0, (label, evidence)
    assert evidence["event_loss"] == 0, (label, evidence)
    assert evidence["in_flight_at_end"] == 0, (label, evidence)
    assert evidence["verdict_detail"] == "concrete_gap", (label, evidence)
    assert evidence["skipped"], (label, "the upper refusal must be disclosed",
                                 evidence)
    assert evidence["gap_classes"]["observation"]["causes"], (label, evidence)


def has_identity_loss(gaps):
    """A named copy-up loss: reason carries identity_mismatch (src/discovery/identity.rs:757)."""
    return [g for g in gaps if "identity_mismatch" in g.get("reason", "")]


def copy_up(pre_kernel, pre_userspace, span_kernel, span_userspace,
            fresh_kernel, fresh_userspace, pre_profile_a, pre_profile_b, post_profile_b,
            pid_a, pid_b_pre, pid_b_span, pid_b_post, iters_a, iters_b, lane, dc73_note,
            facts_text, b_pre_round2_pid=None,
            module_suffix=PROVIDER, span_profile=None):
    """D1: pre collapse, the honest span split, fresh exactness.

    pid_b_pre is B's first process (lower mapper, alive through the span);
    pid_b_span is the second process in B that maps the upper copy inside the
    span; pid_b_post is B's main process after the restart. facts_text is
    facts.log, which proves the copy-up (a different real inode in B's upper
    layer, same sha256). b_pre_round2_pid is the round-2 twin: a second
    pre-copy-up mapper that ledgers iters_b rounds inside the span (gated.c
    runs one round per process). The kernel legs prove; the userspace legs
    honestly gap every overlay join (explicit userspace disables the kernel
    witness, so no userspace edge, module collapse, or count is expected on
    the cell path — only the unproven gap). Pre: the kernel leg collapses B
    onto A's module. Span: the split is honest — A stays on its key, B-pre's
    collapsed edge ends and its stale ranges rejoin the proven lower on B's
    own key module (mapped, gap-free: the stale join), while B2 and the twin
    are each either admitted under the same key but unprobed (the
    byte-identical collapse suppresses probing, so their ledgered rounds
    show count 0 with the not_attached disclosure, never a gap) or
    gap-only where the sweep never attributed the mapper. Fresh: both
    backends exact on
    their own shape. span_profile is the cgroup-B capture spanning the
    copy-up (required): one stale row with the twin's exact ledger, no
    marker, honestly lossy (the upper ranges refuse as an ambiguous
    all-plain collision — the named profile-spanning gap — so B2's
    in-span round is uncounted but disclosed). A forced-kernel run names
    its first proof fallback or null (no proof attempted).
    """
    assert lane in ("A", "B"), lane
    assert isinstance(facts_text, str) and facts_text.strip(), "facts.log is empty"
    facts = parse_facts(facts_text)
    for key in ("stat-a-pre", "stat-b-pre", "sha-b-pre",
                "upper-stat-b", "upper-sha-b", "lower-stack-b"):
        assert key in facts, (f"facts.log names no {key}", sorted(facts))
    lower_stack = int(facts["lower-stack-b"])
    assert lower_stack >= 2, ("B's mount stacks a single lower layer", lower_stack)
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
    kernel_proof = {"finding": KERNEL_PROOF_FINDING, "runs": {}}
    for label, document, want in documents:
        identity = document["observation"]["identity"]
        assert identity["backend"] == want, (label, identity)
        if want == "kernel":
            # A forced-kernel capture either attempted kernel proof (the
            # sweep ran: first finite fallback recorded) or attempted
            # none (the sweep skipped under the 256 cap: null is the
            # forced-selection label, never a proof claim).
            fallback = identity["fallback"]
            assert fallback is None or fallback in KERNEL_FALLBACK_LABELS, \
                (label, "kernel run with an unknown fallback", identity)
        kernel_proof["runs"][label] = {"backend": identity["backend"],
                                       "fallback": identity["fallback"]}

    # Pre: the kernel leg live-edges A and B-pre onto one shared module
    # (A's key) with deep_scan evidence; exactly one collapse gap names
    # B's key -> A's key; no named identity loss. The userspace leg gaps
    # both honestly (no witness, no edges).
    pre_k_pid, pre_k_edges = inventory_maps(pre_kernel, module_suffix)
    pre_k_keys = module_keys(pre_kernel, module_suffix)
    _pre_k_pid, pre_k_records = edge_records(pre_kernel, module_suffix)
    label = "pre-kernel"
    assert pid_a in pre_k_edges, (label, pid_a, sorted(pre_k_edges))
    assert pid_b_pre in pre_k_edges, (label, pid_b_pre, sorted(pre_k_edges))
    assert len(set(pre_k_edges[pid_a])) == 1 \
        and set(pre_k_edges[pid_a]) == set(pre_k_edges[pid_b_pre]), \
        (label, "A and B-pre edge different modules", pre_k_edges[pid_a],
         pre_k_edges[pid_b_pre])
    shared = pre_k_edges[pid_a][0]
    assert pre_k_keys[shared] == key_a, (label, shared, pre_k_keys[shared], key_a)
    for pid in (pid_a, pid_b_pre):
        mapping = pre_k_records[(pid, shared)]["mapping"]
        assert mapping["evidence"] == "deep_scan", (label, pid, mapping)
        assert mapping["state"] == "mapped", (label, pid, mapping)
    collapses = collapse_gaps(pre_kernel, module_suffix)
    assert len(collapses) == 1, (label, "collapse gap count", len(collapses))
    assert collapses[0] == (key_b, key_a), (label, collapses[0], key_b, key_a)
    assert not has_identity_loss(pre_kernel["gaps"]), (label, "identity loss pre")
    require_userspace_gap_only(pre_userspace, "pre-userspace",
                               [pid_a, pid_b_pre], {key_a, key_b}, module_suffix)
    # B's overlay key is new after the copy-up: no pre module carries it.
    assert key_b not in pre_k_keys.values(), ("pre-kernel already has B's key", key_b)
    require_profile_exact(pre_profile_a, iters_a, "pre-profile-a", module_suffix)
    require_profile_exact(pre_profile_b, iters_b, "pre-profile-b", module_suffix)

    # Span kernel: the split is honest. A stays on its key's module; one
    # new module carries B's overlay key; B-pre's collapsed edge ended and
    # its stale ranges rejoin the proven lower on the new module (mapped,
    # deep_scan, gap-free: the stale join — never mapped to the old
    # module anymore); B2 and the round-2 twin are each either admitted
    # under the new module but unprobed (the byte-identical collapse
    # suppresses probing, so their ledgered rounds show count 0 with the
    # not_attached disclosure, never a gap) or gap-only where the sweep
    # never attributed the mapper (no edge, only the unproven gap). At
    # least one collapse names key_b (the flip records both directions
    # while A keeps the committed survivor). Exactly the two shapes
    # 23 dev-host spans showed: the stable single collapse (B's key
    # onto A's) or the flip (B's onto A's, then A's onto B's — that
    # order). Any other count, key or order refuses.
    label = "span-kernel"
    span_k_pid, span_k_edges = inventory_maps(span_kernel, module_suffix)
    span_k_keys = module_keys(span_kernel, module_suffix)
    _span_k_pid, span_k_records = edge_records(span_kernel, module_suffix)
    assert pid_a in span_k_edges, (label, pid_a, sorted(span_k_edges))
    assert len(set(span_k_edges[pid_a])) == 1, \
        (label, "A edges", span_k_edges[pid_a])
    old_id = span_k_edges[pid_a][0]
    assert span_k_keys[old_id] == key_a, \
        (label, old_id, span_k_keys[old_id], key_a)
    new_ids = [mid for mid, key in span_k_keys.items() if key == key_b]
    assert len(new_ids) == 1, (label, "no single new module with B's key",
                               key_b, sorted(span_k_keys.items()))
    new_id = new_ids[0]
    assert new_id != old_id, (label, old_id, new_id)
    assert span_k_edges.get(pid_b_pre) == [new_id], \
        (label, "B-pre stale edge", pid_b_pre, span_k_edges.get(pid_b_pre),
         new_id)
    old_record = span_k_records.get((pid_b_pre, old_id))
    assert old_record is not None \
        and old_record["mapping"]["state"] == "ended", \
        (label, "B-pre collapsed edge never ended", pid_b_pre)
    new_record = span_k_records[(pid_b_pre, new_id)]
    assert new_record["mapping"]["state"] == "mapped", (label, new_record)
    assert new_record["mapping"]["evidence"] == "deep_scan", \
        (label, new_record)
    assert new_record["entries"]["count"] == 0, (label, new_record)
    for pid in (pid_a, pid_b_pre):
        assert not unproven_gaps_for(span_kernel, span_k_pid, pid,
                                     module_suffix), \
            (label, "joined yet still carries the gap", pid)
    assert not has_identity_loss(span_kernel["gaps"]), \
        (label, "identity loss in span")
    collapses = collapse_gaps(span_kernel, module_suffix)
    assert collapses == [(key_b, key_a)] \
        or collapses == [(key_b, key_a), (key_a, key_b)], \
        (label, "span collapse is not an observed shape", collapses)
    assert b_pre_round2_pid is not None, "round-2 twin pid is required"
    round2_pid = b_pre_round2_pid
    twin_shapes = {}
    for pid, tag in ((pid_b_span, "B2"), (round2_pid, "twin")):
        assert pid in span_k_pid.values(), (label, tag, "unscanned", pid)
        record = span_k_records.get((pid, new_id))
        if record is None:
            # Tolerated where the sweep never attributed the mapper: no
            # provider edge at all, only the gap — honestly uncounted.
            twin_shapes[tag] = "gap-only"
            assert unproven_gaps_for(span_kernel, span_k_pid, pid,
                                     module_suffix), \
                (label, tag, "no edge yet no gap either", pid)
        else:
            # Admitted under the new module (mapped where the last pass
            # confirmed the member, uncertain where it did not), deep_scan
            # evidence, zero counted entries with the not_attached
            # disclosure: never refused, never counted through the collapse.
            twin_shapes[tag] = record["mapping"]["state"]
            assert record["mapping"]["state"] in ("mapped", "uncertain"), \
                (label, tag, record)
            assert record["mapping"]["evidence"] == "deep_scan", \
                (label, tag, record)
            assert record["entries"]["count"] == 0, (label, tag, record)
            assert record["entries"]["coverage"].get("reason") == "not_attached", \
                (label, tag, record)
            assert not unproven_gaps_for(span_kernel, span_k_pid, pid,
                                         module_suffix), \
                (label, tag, "admitted yet still carries the gap", pid)
        stale = span_k_records.get((pid, old_id))
        assert stale is None or stale["mapping"]["state"] != "mapped", \
            (label, tag, "mapped on the old module", pid)
    b_pre_round2 = {"pid": round2_pid, "new_module": new_id, **twin_shapes}
    # Span userspace: all four cell pids honestly gap-only.
    require_userspace_gap_only(
        span_userspace, "span-userspace",
        [pid_a, pid_b_pre, pid_b_span, round2_pid], {key_a, key_b},
        module_suffix)

    assert "copy-up-stale-caller" in dc73_note, \
        "run log without the copy-up-stale-caller disclosure"
    assert "identity_mismatch is the correct leg" not in dc73_note, \
        "run log repeats the disproven kernel-refusal sentence"
    for token in ("lower", "upper", "unprobed", "lossy"):
        assert token in dc73_note, \
            ("run log without the copy-up proof facts", token)

    # Fresh, after the restart: the split commits. A stays on its key's
    # module, B-post edges B's key module (both mapped deep_scan), no
    # collapse survives, no gaps. The userspace leg gaps both honestly.
    label = "fresh-kernel"
    fresh_k_pid, fresh_k_edges = inventory_maps(fresh_kernel, module_suffix)
    fresh_k_keys = module_keys(fresh_kernel, module_suffix)
    _fresh_k_pid, fresh_k_records = edge_records(fresh_kernel, module_suffix)
    assert pid_a in fresh_k_edges, (label, pid_a, sorted(fresh_k_edges))
    assert len(set(fresh_k_edges[pid_a])) == 1, \
        (label, "A edges", fresh_k_edges[pid_a])
    assert fresh_k_keys[fresh_k_edges[pid_a][0]] == key_a, (label, "A key")
    assert pid_b_post in fresh_k_pid.values(), \
        (label, "restarted B unscanned", pid_b_post)
    assert pid_b_post in fresh_k_edges, \
        (label, "restarted B lost its edge", pid_b_post)
    assert len(set(fresh_k_edges[pid_b_post])) == 1, \
        (label, "B-post edges", fresh_k_edges[pid_b_post])
    assert fresh_k_keys[fresh_k_edges[pid_b_post][0]] == key_b, \
        (label, "B-post key")
    for pid, mid in ((pid_a, fresh_k_edges[pid_a][0]),
                     (pid_b_post, fresh_k_edges[pid_b_post][0])):
        mapping = fresh_k_records[(pid, mid)]["mapping"]
        assert mapping["evidence"] == "deep_scan", (label, pid, mapping)
        assert mapping["state"] == "mapped", (label, pid, mapping)
    assert collapse_gaps(fresh_kernel, module_suffix) == [], \
        (label, "a collapse survives the restart")
    for pid in (pid_a, pid_b_post):
        assert not unproven_gaps_for(fresh_kernel, fresh_k_pid, pid,
                                     module_suffix), \
            (label, "joined yet still carries the gap", pid)
    assert not has_identity_loss(fresh_kernel["gaps"]), \
        (label, "identity loss fresh")
    require_userspace_gap_only(fresh_userspace, "fresh-userspace",
                               [pid_a, pid_b_post], {key_a, key_b},
                               module_suffix)
    require_profile_exact(post_profile_b, iters_b, "post-profile-b", module_suffix)
    assert span_profile is not None, "span profile of B is required"
    require_span_profile_stale_row(span_profile, iters_b, "span-profile-b",
                                   module_suffix)
    return {"check": "copy-up", "ok": True, "lane": lane,
            "pre_kernel_edges": sorted(pre_k_edges),
            "span_kernel_edges": sorted(span_k_edges),
            "fresh_kernel_edges": sorted(fresh_k_edges),
            "span_new_module": new_id,
            "copy_up_proof": copy_up_proof,
            "lower_stack_b": lower_stack,
            "kernel_proof": kernel_proof,
            "b_pre_round2": b_pre_round2,
            "stale_caller": stale_caller_line(pid_b_pre)}


def late_reported(document, pid_o, pid_l, late_module, iters_l,
                  module_suffix=PROVIDER):
    """N4: O exact and gap-free; L scanned and reported, never silently zero.

    L passes when scanned and EITHER (a) a named gap that names the late
    module (its path, its device:ino identity, or a frozen cause subject)
    OR (b) L's edge to the late module states an unwatched prefix
    (since_ns greater than that mapping's first_seen_ns) with entries
    within the L ledger total and status watched_no_use or counted. The
    ledger bound and status check apply to L's edge in BOTH branches. The
    L verdict stays NON-PASS/UNSUPPORTED (G33): passing means the late
    boundary is REPORTED, never that the late provider became exact.
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
    late_ids = [m["id"] for m in document["modules"] if late_module in m["paths"]]
    assert len(late_ids) == 1, ("no single late module", late_module, late_ids)
    late_id = late_ids[0]
    late_record = next(m for m in document["modules"] if m["id"] == late_id)
    late_device = late_record["identity"]["device"]
    late_key = (late_device["major"], late_device["minor"],
                late_record["identity"]["inode"])
    late_gaps = gaps_for(document, pid_of, pid_l, late_module)
    for gap in late_gaps:
        assert known_late_subject(gap.get("subject", ""), late_module,
                                  late_key, pid_l), \
            ("unknown late gap subject", gap)
    named = [gap for gap in late_gaps if gap.get("reason")]
    _pid_of, records = edge_records(document, module_suffix)
    late_edges = sorted(mid for (pid, mid) in records
                        if pid == pid_l and mid == late_id)
    assert len(late_edges) <= 1, ("ambiguous L late edge", pid_l, late_edges)
    if named:
        verdict = "edge-with-gap" if pid_l in edges else "no-edge-with-gap"
        if late_edges:
            record = records[(pid_l, late_id)]
            assert_late_edge_within_ledger(record, ledger_total)
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
    assert_late_edge_within_ledger(record, ledger_total)
    status = record["entries"]["coverage"]["state"]
    count = record["entries"]["count"]
    boundary = {"late_module": late_module, "module": late_id,
                "unwatched_ns": since_ns - first_seen_ns, "entries": count,
                "since_ns": since_ns, "first_seen_ns": first_seen_ns,
                "status": status, "gap_subjects": []}
    return {"check": "late-reported", "ok": True, "late": "unwatched-prefix",
            "owned_edges": sorted(edges), "late_gaps": len(late_gaps),
            "boundary": boundary}


def changed_caller_line(pid):
    return (f"D1-changed cell=D1-changed copy-up-stale-caller resolved: "
            f"pid={pid} edge=lower-module mapped (stale ranges joined the "
            f"witness-proven lower file; the upper copy is its own module; "
            f"no gap)")


def require_changed_profile_dual_rows(document, iters_s, iters_f, lower_sha,
                                      upper_sha, label,
                                      module_suffix=PROVIDER):
    """The cgroup-B profile over the different-bytes copy-up: two exact rows.

    The lower row carries the stale ledger S with the pre_copy_up marker;
    the upper row carries the fresh ledger F with no marker. Both rows
    exact (zero errors, unambiguous), zero loss, zero in-flight rows: a
    same-bytes collapse, a swapped routing, or a dropped side fails.
    """
    modules = [module for module in document["capture"]["modules"]
               if module["path"].endswith(module_suffix)]
    assert len(modules) == 2, (label, "want the lower and upper rows",
                               modules)
    by_sha = {}
    for module in modules:
        assert isinstance(module.get("sha256"), str), (label, module)
        by_sha[module["sha256"]] = module
    assert set(by_sha) == {lower_sha, upper_sha}, \
        (label, "row identities", sorted(by_sha))
    rows = [row for row in document["evidence"]["discovery"]
            if row["path"].endswith(module_suffix)]
    assert len(rows) == 2, (label, "want the lower and upper rows", rows)
    lower_rows = [row for row in rows if row.get("sha256") == lower_sha]
    upper_rows = [row for row in rows if row.get("sha256") == upper_sha]
    assert len(lower_rows) == 1 and len(upper_rows) == 1, \
        (label, "row identities", rows)
    assert lower_rows[0].get("layer") == "pre_copy_up", \
        (label, "lower row unmarked", lower_rows)
    assert upper_rows[0].get("layer") is None, \
        (label, "marker off the lower row", upper_rows)
    for name in sorted(LEDGER_FUNCTIONS):
        named = [row for row in document["functions"]
                 if row.get("names") == [name] and row["calls"]]
        assert len(named) == 2, \
            (label, name, "want the stale and fresh rows", named)
        by_module = {}
        for row in named:
            module = row.get("module")
            assert isinstance(module, dict), (label, name, row)
            assert isinstance(module.get("sha256"), str), (label, name, row)
            by_module[module["sha256"]] = row
        assert set(by_module) == {lower_sha, upper_sha}, \
            (label, name, "row identities", sorted(by_module))
        assert by_module[lower_sha]["calls"] == iters_s, \
            (label, name, "stale count", by_module[lower_sha], iters_s)
        assert by_module[upper_sha]["calls"] == iters_f, \
            (label, name, "fresh count", by_module[upper_sha], iters_f)
        for row in named:
            assert row["errors"] == 0, (label, name, row)
            assert row.get("module_ambiguous") is False, (label, name, row)
    evidence = document["evidence"]
    assert document["capture"]["scope"] == "cgroup", (label, document["capture"])
    require_initial_observer(evidence, label)
    assert evidence["attached_probes"] > 0, (label, evidence)
    assert evidence["event_loss"] == 0, (label, evidence)
    assert evidence["in_flight_at_end"] == 0, (label, evidence)
    assert evidence["verdict_detail"] != "concrete_gap", (label, evidence)
    assert evidence["gap_classes"]["observation"]["causes"] == [], (label, evidence)


def copy_up_changed(kernel, userspace, profile, pid_b_pre, pid_b2, iters_s,
                    iters_f, run_note, facts_text, module_suffix=PROVIDER):
    """D1-changed: different-bytes copy-up, both mappers ledgered, both exact.

    pid_b_pre mapped the provider before the copy-up and keeps the lower
    file; pid_b2 mapped after and runs the upper copy. facts_text is
    facts.log, which proves the copy-up changed both the inode and the
    bytes (an unmapped-byte patch: no byte-identical collapse can preempt
    the witness). The kernel leg attributes B-pre to the witness-proven
    lower module and B2 to the upper module (the pair routes by proof:
    one maps key or two, the sha split decides); the userspace leg
    honestly gaps both joins (no witness, no edges — the negative); the
    cgroup-B profile counts the stale ledger S on the pre_copy_up row
    and the fresh ledger F on the upper row, both exact. S and F differ
    so a swapped routing fails.
    """
    assert isinstance(facts_text, str) and facts_text.strip(), "facts.log is empty"
    facts = parse_facts(facts_text)
    for key in ("stat-b-pre", "sha-b-pre", "upper-stat-b", "upper-sha-b",
                "lower-stack-b"):
        assert key in facts, (f"facts.log names no {key}", sorted(facts))
    lower_stack = int(facts["lower-stack-b"])
    assert lower_stack >= 2, ("B's mount stacks a single lower layer", lower_stack)
    lower_key = stat_key(facts["stat-b-pre"])
    lower_sha = facts["sha-b-pre"]
    upper_sha = facts["upper-sha-b"]
    assert facts["upper-stat-b"] != facts["stat-b-pre"], \
        ("copy-up changed no inode", facts["upper-stat-b"])
    assert upper_sha != lower_sha, \
        "copy-up changed no bytes (not different-bytes)"
    assert iters_s != iters_f, \
        "equal ledgers cannot pin the routing direction"
    copy_up_proof = {"upper": facts["upper-stat-b"], "lower": facts["stat-b-pre"],
                     "lower_sha256": lower_sha, "upper_sha256": upper_sha}

    for label, document in (("kernel", kernel), ("userspace", userspace)):
        require_initial_observer(document, label)
    kernel_proof = {"finding": KERNEL_PROOF_FINDING, "runs": {}}
    for label, document, want in (("kernel", kernel, "kernel"),
                                  ("userspace", userspace, "userspace")):
        identity = document["observation"]["identity"]
        assert identity["backend"] == want, (label, identity)
        if want == "kernel":
            fallback = identity["fallback"]
            assert fallback is None or fallback in KERNEL_FALLBACK_LABELS, \
                (label, "kernel run with an unknown fallback", identity)
        kernel_proof["runs"][label] = {"backend": identity["backend"],
                                       "fallback": identity["fallback"]}

    # Kernel: exactly the lower and upper provider modules; B-pre edges
    # only the lower (mapped, deep_scan, gap-free), B2 only the upper
    # (mapped, deep_scan, gap-free). No collapse hides the split, no
    # identity loss anywhere: the loss gate is global zero here too.
    label = "kernel"
    provider_modules = [module for module in kernel["modules"]
                        if any(p.endswith(module_suffix)
                               for p in module["paths"])]
    assert len(provider_modules) == 2, \
        (label, "want the lower and upper modules", provider_modules)
    lower_ids = [m["id"] for m in provider_modules
                 if m.get("identity", {}).get("sha256") == lower_sha]
    upper_ids = [m["id"] for m in provider_modules
                 if m.get("identity", {}).get("sha256") == upper_sha]
    assert len(lower_ids) == 1 and len(upper_ids) == 1, \
        (label, "module identities", provider_modules)
    assert lower_ids != upper_ids, (label, "one row carries both files")
    lower_mod = next(m for m in provider_modules if m["id"] == lower_ids[0])
    upper_mod = next(m for m in provider_modules if m["id"] == upper_ids[0])
    lower_device = lower_mod["identity"]["device"]
    assert (lower_device["major"], lower_device["minor"],
            lower_mod["identity"]["inode"]) == lower_key, \
        (label, "lower module off B's pre key", lower_mod, lower_key)
    upper_device = upper_mod["identity"]["device"]
    upper_key = (upper_device["major"], upper_device["minor"],
                 upper_mod["identity"]["inode"])
    k_pid, k_edges = inventory_maps(kernel, module_suffix)
    _k_pid, k_records = edge_records(kernel, module_suffix)
    assert pid_b_pre in k_edges, (label, pid_b_pre, sorted(k_edges))
    assert pid_b2 in k_edges, (label, pid_b2, sorted(k_edges))
    assert sorted(k_edges[pid_b_pre]) == lower_ids, \
        (label, "B-pre edges", pid_b_pre, k_edges.get(pid_b_pre), lower_ids)
    assert sorted(k_edges[pid_b2]) == upper_ids, \
        (label, "B2 edges", pid_b2, k_edges.get(pid_b2), upper_ids)
    for pid, mid in ((pid_b_pre, lower_ids[0]), (pid_b2, upper_ids[0])):
        mapping = k_records[(pid, mid)]["mapping"]
        assert mapping["evidence"] == "deep_scan", (label, pid, mapping)
        assert mapping["state"] == "mapped", (label, pid, mapping)
    for pid in (pid_b_pre, pid_b2):
        assert not unproven_gaps_for(kernel, k_pid, pid, module_suffix), \
            (label, "joined yet still carries the gap", pid)
    assert collapse_gaps(kernel, module_suffix) == [], \
        (label, "a collapse hides the split")
    assert not has_identity_loss(kernel["gaps"]), (label, "identity loss")

    # Userspace: the negative — both joins honestly gapped, never edged.
    require_userspace_gap_only(userspace, "userspace", [pid_b_pre, pid_b2],
                               {lower_key, upper_key}, module_suffix)

    assert "copy-up-stale-caller" in run_note, \
        "run log without the copy-up-stale-caller disclosure"
    for token in ("lower", "upper", "pre_copy_up"):
        assert token in run_note, \
            ("run log without the copy-up proof facts", token)

    require_changed_profile_dual_rows(profile, iters_s, iters_f, lower_sha,
                                      upper_sha, "profile-b", module_suffix)
    return {"check": "copy-up-changed", "ok": True,
            "lower_module": {"id": lower_ids[0],
                             "dev": [lower_device["major"],
                                     lower_device["minor"]],
                             "ino": lower_mod["identity"]["inode"],
                             "sha256": lower_sha},
            "upper_module": {"id": upper_ids[0],
                             "dev": [upper_device["major"],
                                     upper_device["minor"]],
                             "ino": upper_mod["identity"]["inode"],
                             "sha256": upper_sha},
            "copy_up_proof": copy_up_proof,
            "lower_stack_b": lower_stack,
            "kernel_proof": kernel_proof,
            "stale_caller": changed_caller_line(pid_b_pre)}


MIDCAPTURE_STAMPS = ("t-profile-ready", "t-bpre-ledger", "t-patch",
                     "t-b2-ledger", "t-profile-end")


def copy_up_midcapture(kernel, userspace, profile, pid_b_pre, pid_b2,
                       iters_s, iters_f, run_note, facts_text,
                       module_suffix=PROVIDER):
    """D1-changed-midcapture: the patch lands DURING the running profile.

    Same evidence as D1-changed, but the cgroup-B profile starts while B
    maps the single pre-copy-up file: B-pre's stale ledger completes
    inside the window, the unmapped-byte patch copies the file up
    mid-window, and the second mapper ledgers fresh on the upper copy
    before the window ends. The driver records the five window stamps in
    facts.log; they must be strictly increasing (fixed-width %s%N, so
    string order is time order), which proves the patch is strictly
    inside the capture window. The settled legs then judge exactly as
    D1-changed: the kernel leg attributes B-pre to the witness-proven
    lower module and B2 to the upper module, the userspace leg honestly
    gaps both joins, and the profile counts the stale ledger S on the
    pre_copy_up row and the fresh ledger F on the upper row, both exact.
    """
    facts = parse_facts(facts_text)
    for key in MIDCAPTURE_STAMPS:
        assert key in facts, (f"facts.log names no {key}", sorted(facts))
    stamps = [facts[key] for key in MIDCAPTURE_STAMPS]
    assert all(stamp.isdigit() for stamp in stamps), \
        ("window stamps are not %s%N", stamps)
    assert stamps == sorted(stamps) and len(set(stamps)) == len(stamps), \
        ("the copy-up is not strictly inside the capture window", stamps)
    assert "mid-capture" in run_note, \
        "run log does not name the mid-capture mode"
    result = copy_up_changed(kernel, userspace, profile, pid_b_pre, pid_b2,
                             iters_s, iters_f, run_note, facts_text,
                             module_suffix)
    result["check"] = "copy-up-midcapture"
    result["window"] = dict(zip(MIDCAPTURE_STAMPS, stamps))
    return result


# ---------------------------------------------------------------- self-test


ST_PIDS = [101, 102, 103, 104, 105, 201, 202]
ST_KEY_A = (0, 138, 100)
ST_KEY_B = (0, 140, 100)
ST_PROVIDER = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"


def st_edge(pid, module, evidence="deep_scan", state="mapped", count=0,
            cov="unknown", since=None, first_seen=1000, lossy=None,
            reason=None):
    return {"pid": pid, "module": module, "evidence": evidence, "state": state,
            "count": count, "cov": cov, "since": since,
            "first_seen": first_seen, "lossy": lossy, "reason": reason}


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
                                            "reason": item.get("reason"),
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
            "stat-b-pre=140:100 941088 sha-b-pre=abc lower-stack-b=3\n"
            "upper-stat-b=51:200 941088 upper-sha-b=abc\n")
ST_NOTE = ("run log: copy-up-stale-caller disclosed for B-pre "
             "(proven lower on its key, upper admitted-unprobed, "
             "spanning profile honestly lossy)")


def st_pre_edges():
    return [st_edge(101, "m7"), st_edge(102, "m7")]


ST_STALE_GAP = "original_file_unproven: the kernel witness proved another file"
ST_USERSPACE_GAP = ("original_file_unproven: kernel witness unavailable: "
                    "explicit userspace disables the kernel witness")


def st_unproven_gap(pid):
    return (ST_PROVIDER, ST_USERSPACE_GAP, pid)


def st_span_edges():
    # A (101) stays on its key's module. B-pre (102): the collapsed edge
    # ended, the stale ranges rejoin the proven lower on B's own key
    # module (mapped, deep_scan, gap-free). B2 (104) and the twin (105)
    # are admitted under the same key but unprobed (uncertain, deep_scan
    # evidence, count 0, not_attached).
    return [st_edge(101, "m7"),
            st_edge(102, "m7", state="ended"),
            st_edge(102, "m8"),
            st_edge(104, "m8", state="uncertain", reason="not_attached"),
            st_edge(105, "m8", state="uncertain", reason="not_attached")]


def st_span_gaps():
    # The flip records both directions while A keeps the committed survivor.
    return [st_collapse(), st_collapse(ST_KEY_A, ST_KEY_B)]


def good_span_profile(b3_iters=250):
    identity = {"dev": [0, 140], "ino": 100, "sha256": "abc"}
    return {
        "capture": {"scope": "cgroup", "modules": [{"path": ST_PROVIDER}]},
        "evidence": {
            "discovery": [{"path": ST_PROVIDER, "dev": [0, 140], "ino": 100,
                           "sha256": "abc", "build_id": "bd"}],
            "attached_probes": 136,
            "event_loss": 0,
            "in_flight_at_end": 0,
            "verdict_detail": "concrete_gap",
            "skipped": [{"name": "discovery subject",
                         "reason": ("physical identity is ambiguous; "
                                    "the collision group was not attached")}],
            "pid_namespace": {"observer": "initial", "kernel_pids": "initial",
                              "proc_pids": "observer"},
            "gap_classes": {"observation": {"causes": ["skipped",
                                                       "pid_descendant_gaps"],
                                            "status": "lossy"}},
        },
        "functions": [{"names": [name], "calls": b3_iters, "errors": 0,
                       "module": dict(identity), "module_ambiguous": False}
                      for name in sorted(LEDGER_FUNCTIONS)]
        + [{"calls": 0, "errors": 0, "names": ["C_Login"], "module": None}],
    }


def good_gap_only(*pids):
    return good_inventory([], [st_unproven_gap(pid) for pid in pids],
                          backend="userspace", fallback=None, modules=())


def good_copy_up(lane="B"):
    gap = st_collapse()
    return {
        "pre_kernel": good_inventory(st_pre_edges(), [gap], backend="kernel",
                                     fallback="anchor_not_installed",
                                     modules=ST_MODULES_PRE),
        "pre_userspace": good_gap_only(101, 102),
        "span_kernel": good_inventory(st_span_edges(), st_span_gaps(),
                                      backend="kernel",
                                      fallback="anchor_not_installed",
                                      modules=ST_MODULES_SPAN),
        "span_userspace": good_gap_only(101, 102, 104, 105),
        "fresh_kernel": good_inventory([st_edge(101, "m7"), st_edge(103, "m8")],
                                       backend="kernel",
                                       fallback="anchor_not_installed",
                                       modules=ST_MODULES_SPAN),
        "fresh_userspace": good_gap_only(101, 103),
        "pre_profile_a": good_profile(400),
        "pre_profile_b": good_profile(250),
        "post_profile_b": good_profile(250),
        "span_profile": good_span_profile(),
        "pid_a": 101,
        "pid_b_pre": 102,
        "pid_b_span": 104,
        "pid_b_post": 103,
        "iters_a": 400,
        "iters_b": 250,
        "lane": lane,
        "dc73_note": ST_NOTE,
        "facts_text": ST_FACTS,
        "b_pre_round2_pid": 105,
    }


def st_add_ambient(document, pid=999, count=0):
    """An ambient host provider edge outside the cell (agreement ignores it)."""
    document["callers"].append({"id": "camb", "pid": pid})
    document["modules"].append(
        {"id": "m9", "paths": [ST_PROVIDER],
         "identity": {"device": {"major": 0, "minor": 35}, "inode": 356176}})
    document["edges"].append(
        {"caller": "camb", "module": "m9",
         "mapping": {"evidence": "deep_scan", "state": "mapped",
                     "first_seen_ns": 1000},
         "entries": {"count": count,
                     "coverage": {"state": "unknown", "since_ns": None,
                                  "lossy": None}}})


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


def accepts(label, check):
    """The check must pass (an accepts-case); a refusal fails the self-test."""
    check()
    print(f"container-cells mutation accepted: {label}")


def self_test():
    healthy = copy_up(**good_copy_up("B"))
    assert healthy["lane"] == "B"
    assert "known_issue" not in healthy
    assert healthy["b_pre_round2"] == {"pid": 105, "new_module": "m8",
                                       "B2": "uncertain", "twin": "uncertain"}
    assert healthy["lower_stack_b"] == 3
    assert healthy["span_new_module"] == "m8"
    assert "no proof attempted" in healthy["kernel_proof"]["finding"]
    assert "edge=new-module mapped" in healthy["stale_caller"]
    assert copy_up(**good_copy_up("A"))["lane"] == "A"
    assert stale_caller_line(102) == \
        ("D1 cell=D1 copy-up-stale-caller resolved: pid=102 "
         "edge=new-module mapped (stale ranges rejoined the proven lower "
         "on the cell's own key; the collapsed old edge ended; no gap)")
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
    # Fedora d1fed1 (under the 256 cap): the sweep never runs, so no
    # kernel proof is attempted and forced-kernel runs report null.
    fedora_none = good_copy_up("B")
    for key in ("pre_kernel", "span_kernel", "fresh_kernel"):
        fedora_none[key]["observation"]["identity"]["fallback"] = None
    assert copy_up(**fedora_none)["ok"] is True
    assert copy_up(**fedora_none)["kernel_proof"]["runs"]["span-kernel"] == \
        {"backend": "kernel", "fallback": None}
    mutate_copy("pre-kernel with an unknown fallback",
                pre_kernel=good_inventory(st_pre_edges(), [st_collapse()],
                                          backend="kernel",
                                          fallback="frobnicate",
                                          modules=ST_MODULES_PRE))
    # Ambient host PKCS#11 users keep calling across the sequential legs,
    # so an ambient-only count split (or an ambient-only module) passes:
    # every assertion is scoped to the cell's pids and keys.
    ambient_split = good_copy_up("B")
    st_add_ambient(ambient_split["pre_kernel"], count=0)
    st_add_ambient(ambient_split["pre_userspace"], count=3)
    assert copy_up(**ambient_split)["ok"] is True
    ambient_module = good_copy_up("B")
    st_add_ambient(ambient_module["pre_userspace"], count=0)
    assert copy_up(**ambient_module)["ok"] is True
    # A foreign-key collapse on a userspace leg is ambient noise, not a
    # cell failure; a collapse naming a cell key refuses.
    ambient_collapse = good_copy_up("B")
    ambient_collapse["span_userspace"]["gaps"].append(
        {"subject": ST_PROVIDER, "reason": st_collapse((0, 141, 100),
                                                       (0, 142, 100))[1],
         "caller": None, "module": None, "pid": None})
    assert copy_up(**ambient_collapse)["ok"] is True
    mutate_copy("userspace leg edges the provider",
                pre_userspace=good_inventory(
                    [st_edge(101, "m7")], [st_unproven_gap(101),
                                           st_unproven_gap(102)],
                    backend="userspace", fallback=None,
                    modules=ST_MODULES_PRE))
    mutate_copy("userspace leg without the honest gap",
                pre_userspace=good_inventory([], [st_unproven_gap(101)],
                                             backend="userspace",
                                             fallback=None, modules=()))
    mutate_copy("userspace collapse names a cell key",
                span_userspace=good_inventory(
                    [], [st_unproven_gap(101), st_unproven_gap(102),
                         st_unproven_gap(104), st_unproven_gap(105),
                         st_collapse()],
                    backend="userspace", fallback=None, modules=()))
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
                    [st_edge(101, "m7"), st_edge(102, "m7")],
                    [st_collapse()], backend="kernel", modules=ST_MODULES_PRE))
    mutate_copy("span collapse gap missing",
                span_kernel=good_inventory(st_span_edges(), backend="kernel",
                                           modules=ST_MODULES_SPAN))
    mutate_copy("span collapse names foreign keys only",
                span_kernel=good_inventory(
                    st_span_edges(),
                    [st_collapse((0, 141, 100), (0, 142, 100))],
                    backend="kernel", modules=ST_MODULES_SPAN))
    # A mapped B2/twin is the quiet-host twin of the uncertain shape.
    mapped_twin = good_copy_up("B")
    mapped_twin["span_kernel"] = good_inventory(
        [st_edge(101, "m7"), st_edge(102, "m7", state="ended"),
         st_edge(102, "m8"),
         st_edge(104, "m8", reason="not_attached"),
         st_edge(105, "m8", reason="not_attached")],
        st_span_gaps(), backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    assert copy_up(**mapped_twin)["b_pre_round2"] == \
        {"pid": 105, "new_module": "m8", "B2": "mapped", "twin": "mapped"}
    # A sweep-missed mapper is tolerated gap-only, never silent.
    gap_twin = good_copy_up("B")
    gap_twin["span_kernel"] = good_inventory(
        [item for item in st_span_edges() if item["pid"] != 105],
        st_span_gaps() + [(ST_PROVIDER, ST_STALE_GAP, 105)],
        backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    assert copy_up(**gap_twin)["b_pre_round2"]["twin"] == "gap-only"
    mutate_copy("span B2 without edge and without gap",
                span_kernel=good_inventory(
                    [item for item in st_span_edges() if item["pid"] != 104],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B2 edge ended",
                span_kernel=good_inventory(
                    [item if item["pid"] != 104
                     else st_edge(104, "m8", state="ended",
                                  reason="not_attached")
                     for item in st_span_edges()],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B2 with identity loss",
                span_kernel=good_inventory(
                    st_span_edges(),
                    st_span_gaps() + [("x", "identity_mismatch", 104)],
                    backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span pid-less mismatch aggregate",
                span_kernel=good_inventory(
                    st_span_edges(),
                    st_span_gaps() + [("maps attribution",
                                       "processes mapping pinned provider objects were "
                                       "not attributed to them: 2 identity_mismatch "
                                       "(per-process reasons in the process table)",
                                       None)],
                    backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B2 claims entries",
                span_kernel=good_inventory(
                    [item if item["pid"] != 104
                     else st_edge(104, "m8", state="uncertain", count=6,
                                  reason="not_attached")
                     for item in st_span_edges()],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B2 without the disclosure",
                span_kernel=good_inventory(
                    [item if item["pid"] != 104
                     else st_edge(104, "m8", state="uncertain")
                     for item in st_span_edges()],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B2 admitted yet still gapped",
                span_kernel=good_inventory(
                    st_span_edges(),
                    st_span_gaps() + [(ST_PROVIDER, ST_STALE_GAP, 104)],
                    backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("span B2 mapped on the old module",
                span_kernel=good_inventory(
                    st_span_edges() + [st_edge(104, "m7")],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B-pre collapsed edge missing",
                span_kernel=good_inventory(
                    [item for item in st_span_edges()
                     if (item["pid"], item["module"]) != (102, "m7")],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B-pre collapsed edge still mapped",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7"),
                     st_edge(102, "m8"),
                     st_edge(104, "m8", state="uncertain",
                              reason="not_attached"),
                     st_edge(105, "m8", state="uncertain",
                              reason="not_attached")],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    mutate_copy("span B-pre missing new edge",
                span_kernel=good_inventory(
                    [st_edge(101, "m7"), st_edge(102, "m7", state="ended"),
                     st_edge(104, "m8", state="uncertain",
                              reason="not_attached"),
                     st_edge(105, "m8", state="uncertain",
                              reason="not_attached")],
                    st_span_gaps(), backend="kernel",
                    modules=ST_MODULES_SPAN))
    b_pre_with_gap = good_copy_up("B")
    b_pre_with_gap["span_kernel"] = good_inventory(
        st_span_edges(), st_span_gaps() + [(ST_PROVIDER, ST_STALE_GAP, 102)],
        backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    refuses_with("span B-pre joined yet still gapped",
                 "joined yet still carries the gap",
                 lambda: copy_up(**b_pre_with_gap))
    mutate_copy("facts lower-stack-b missing",
                facts_text=ST_FACTS.replace(" lower-stack-b=3", ""))
    mutate_copy("facts lower-stack-b single layer",
                facts_text=ST_FACTS.replace("lower-stack-b=3", "lower-stack-b=1"))
    mutate_copy("dc73 run note without the disclosure",
                dc73_note="no copy-up here")
    mutate_copy("dc73 run note repeats the disproven kernel-refusal sentence",
                dc73_note=ST_NOTE + " identity_mismatch is the correct leg")
    mutate_copy("dc73 run note without the copy-up proof facts",
                dc73_note="D1 lane B copy-up-stale-caller resolved")
    # Round 2 twin: admitted-unprobed on the kernel leg (uncertain or
    # mapped, deep_scan, count 0, not_attached), gap-only on the
    # userspace leg, and the twin pid is required.
    mutate_copy("round-2 twin pid missing", b_pre_round2_pid=None)
    round2_twin_maps_match = good_copy_up("B")
    round2_twin_maps_match["span_kernel"] = good_inventory(
        [item if item["pid"] != 105
         else st_edge(105, "m8", evidence="maps_match", state="uncertain",
                      reason="not_attached")
         for item in st_span_edges()],
        st_span_gaps(), backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    refuses_with("round-2 twin edge maps_match", "maps_match",
                 lambda: copy_up(**round2_twin_maps_match))
    round2_twin_counted = good_copy_up("B")
    round2_twin_counted["span_kernel"] = good_inventory(
        [item if item["pid"] != 105
         else st_edge(105, "m8", state="uncertain", count=1500,
                      reason="not_attached")
         for item in st_span_edges()],
        st_span_gaps(), backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    refuses_with("round-2 twin claims entries", "count",
                 lambda: copy_up(**round2_twin_counted))
    twin_no_gap = good_copy_up("B")
    twin_no_gap["span_kernel"] = good_inventory(
        [item for item in st_span_edges() if item["pid"] != 105],
        st_span_gaps(), backend="kernel", fallback="anchor_not_installed",
        modules=ST_MODULES_SPAN)
    refuses_with("round-2 twin without edge and without gap",
                 "no edge yet no gap either",
                 lambda: copy_up(**twin_no_gap))
    assert round2_line(105, 1500, "uncertain") == \
        ("D1 cell=D1 copy-up-round2-caller resolved: pid=105 ledgered=1500 "
         "(admitted: uncertain new edge, uncounted: not_attached)")
    assert round2_line(105, 1500, "gap-only") == \
        ("D1 cell=D1 copy-up-round2-caller resolved: pid=105 ledgered=1500 "
         "gap=original_file_unproven (uncounted: no edge)")
    mutate_copy("span profile missing", span_profile=None)
    two_rows = good_span_profile()
    two_rows["evidence"]["discovery"].append(
        dict(two_rows["evidence"]["discovery"][0]))
    two_rows["capture"]["modules"].append(
        dict(two_rows["capture"]["modules"][0]))
    mutate_copy("span profile twin rows", span_profile=two_rows)
    marked = good_span_profile()
    marked["evidence"]["discovery"][0]["layer"] = "pre_copy_up"
    mutate_copy("span profile stale row marked", span_profile=marked)
    short = good_span_profile()
    short["functions"][0]["calls"] = 249
    mutate_copy("span profile stale total short", span_profile=short)
    leaked = good_span_profile()
    leaked["functions"][0]["calls"] = 251
    mutate_copy("span profile fresh calls leaked", span_profile=leaked)
    dropped = good_span_profile()
    dropped["functions"] = [row for row in dropped["functions"]
                            if row["names"] != ["C_Digest"]]
    mutate_copy("span profile stale row missing", span_profile=dropped)
    misattributed = good_span_profile()
    misattributed["functions"][0]["module"]["ino"] = 9999
    mutate_copy("span profile row misattributed", span_profile=misattributed)
    ambiguous = good_span_profile()
    ambiguous["functions"][0]["module_ambiguous"] = True
    mutate_copy("span profile module ambiguous", span_profile=ambiguous)
    exact = good_span_profile()
    exact["evidence"]["verdict_detail"] = "attribution_only"
    exact["evidence"]["skipped"] = []
    exact["evidence"]["gap_classes"]["observation"]["causes"] = []
    mutate_copy("span profile silent about the upper miss",
                span_profile=exact)
    mutate_copy("post profile wrong count", post_profile_b=good_profile(249))
    mutate_copy("A inexact in the span",
                span_kernel=good_inventory(
                    [st_edge(102, "m7", state="ended"),
                     st_edge(104, "m8", evidence="maps_match")],
                    st_span_gaps(), backend="kernel", modules=ST_MODULES_SPAN))
    mutate_copy("lane-B fresh kernel lost restarted B",
                fresh_kernel=good_inventory([st_edge(101, "m7")],
                                            backend="kernel",
                                            modules=ST_MODULES_SPAN))
    mutate_copy("lane-B fresh userspace identity loss",
                fresh_userspace=good_inventory(
                    [], [st_unproven_gap(101), st_unproven_gap(103),
                         ("x", "identity_mismatch", 103)],
                    backend="userspace", fallback=None, modules=()))
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

    ch_lower_sha = "a" * 64
    ch_upper_sha = "b" * 64
    ch_facts = ("stat-a-pre=138:100 941088 sha-a-pre=" + ch_lower_sha + "\n"
                "stat-b-pre=140:100 941088 sha-b-pre=" + ch_lower_sha +
                " lower-stack-b=3\n"
                "upper-stat-b=51:200 941088 upper-sha-b=" + ch_upper_sha + "\n")
    ch_note = ("run log: copy-up-stale-caller disclosed for B-pre "
               "(witness-proven lower on its key with layer pre_copy_up, "
               "upper copy its own module, both mappers ledgered exact)")
    ch_modules = (("m8", ST_KEY_B, ST_PROVIDER), ("m9", ST_KEY_B, ST_PROVIDER))

    def ch_inventory(edges, gaps=(), backend="kernel", modules=ch_modules):
        document = good_inventory(
            edges, gaps, backend=backend,
            fallback="anchor_not_installed" if backend == "kernel" else None,
            modules=modules)
        shas = {"m8": ch_lower_sha, "m9": ch_upper_sha}
        for module in document["modules"]:
            if module["id"] in shas:
                module["identity"]["sha256"] = shas[module["id"]]
        return document

    def good_changed_profile(iters_s=250, iters_f=100):
        lower = {"dev": [0, 140], "ino": 100, "sha256": ch_lower_sha}
        upper = {"dev": [0, 140], "ino": 100, "sha256": ch_upper_sha}
        functions = []
        for name in sorted(LEDGER_FUNCTIONS):
            functions.append({"names": [name], "calls": iters_s, "errors": 0,
                              "module": dict(lower), "module_ambiguous": False})
            functions.append({"names": [name], "calls": iters_f, "errors": 0,
                              "module": dict(upper), "module_ambiguous": False})
        functions.append({"calls": 0, "errors": 0, "names": ["C_Login"],
                          "module": None})
        return {
            "capture": {"scope": "cgroup",
                        "modules": [{"path": ST_PROVIDER, **lower},
                                    {"path": ST_PROVIDER, **upper}]},
            "evidence": {
                "discovery": [{"path": ST_PROVIDER, **lower,
                               "build_id": "bd", "layer": "pre_copy_up"},
                              {"path": ST_PROVIDER, **upper,
                               "build_id": "bd"}],
                "attached_probes": 136,
                "event_loss": 0,
                "in_flight_at_end": 0,
                "verdict_detail": "attribution_only",
                "pid_namespace": {"observer": "initial",
                                  "kernel_pids": "initial",
                                  "proc_pids": "observer"},
                "gap_classes": {"observation": {"causes": [],
                                                "status": "exact"}},
            },
            "functions": functions,
        }

    def good_changed():
        return {
            "kernel": ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")]),
            "userspace": good_gap_only(102, 104),
            "profile": good_changed_profile(),
            "pid_b_pre": 102,
            "pid_b2": 104,
            "iters_s": 250,
            "iters_f": 100,
            "run_note": ch_note,
            "facts_text": ch_facts,
        }

    def mutate_changed(label, **overrides):
        inputs = good_changed()
        inputs.update(overrides)
        refuses(label, lambda: copy_up_changed(**inputs))

    healthy_changed = copy_up_changed(**good_changed())
    assert healthy_changed["check"] == "copy-up-changed"
    assert healthy_changed["lower_module"]["sha256"] == ch_lower_sha
    assert healthy_changed["upper_module"]["sha256"] == ch_upper_sha
    assert healthy_changed["lower_stack_b"] == 3
    assert "edge=lower-module mapped" in healthy_changed["stale_caller"]
    assert changed_caller_line(102) == \
        ("D1-changed cell=D1-changed copy-up-stale-caller resolved: pid=102 "
         "edge=lower-module mapped (stale ranges joined the witness-proven "
         "lower file; the upper copy is its own module; no gap)")
    mutate_changed("changed empty facts", facts_text="  \n")
    mutate_changed("changed facts without the upper sha",
                   facts_text="stat-b-pre=140:100 sha-b-pre=abc "
                              "upper-stat-b=51:200 lower-stack-b=3\n")
    mutate_changed("changed single lower layer",
                   facts_text=ch_facts.replace("lower-stack-b=3",
                                               "lower-stack-b=1"))
    mutate_changed("changed copy-up kept the inode",
                   facts_text=ch_facts.replace("upper-stat-b=51:200",
                                               "upper-stat-b=140:100"))
    mutate_changed("changed copy-up kept the bytes",
                   facts_text=ch_facts.replace(ch_upper_sha, ch_lower_sha))
    mutate_changed("changed equal ledgers", iters_s=100)
    mutate_changed("changed kernel leg with userspace identity",
                   kernel=ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")],
                                       backend="userspace"))
    unknown_fallback = ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")])
    unknown_fallback["observation"]["identity"]["fallback"] = "bogus_label"
    mutate_changed("changed kernel run with unknown fallback",
                   kernel=unknown_fallback)
    drifted_user = good_gap_only(102, 104)
    drifted_user["pid_namespace"]["observer"] = "other"
    mutate_changed("changed userspace observer drift", userspace=drifted_user)
    mutate_changed("changed single kernel module",
                   kernel=ch_inventory([st_edge(102, "m8"),
                                        st_edge(104, "m8")],
                                       modules=(("m8", ST_KEY_B, ST_PROVIDER),)))
    both_lower = ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")])
    for module in both_lower["modules"]:
        module["identity"]["sha256"] = ch_lower_sha
    mutate_changed("changed upper identity missing", kernel=both_lower)
    off_key = ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")],
                           modules=(("m8", (0, 141, 100), ST_PROVIDER),
                                    ("m9", ST_KEY_B, ST_PROVIDER)))
    mutate_changed("changed lower module off B's pre key", kernel=off_key)
    mutate_changed("changed B2 without an edge",
                   kernel=ch_inventory([st_edge(102, "m8")]))
    mutate_changed("changed mappers swapped",
                   kernel=ch_inventory([st_edge(102, "m9"),
                                        st_edge(104, "m8")]))
    mutate_changed("changed B-pre edge not deep_scan",
                   kernel=ch_inventory([st_edge(102, "m8", evidence="maps_match"),
                                        st_edge(104, "m9")]))
    mutate_changed("changed B2 admitted yet still gapped",
                   kernel=ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")],
                                       [(ST_PROVIDER, ST_STALE_GAP, 104)]))
    mutate_changed("changed kernel collapse hides the split",
                   kernel=ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")],
                                       [st_collapse()]))
    mutate_changed("changed kernel identity loss",
                   kernel=ch_inventory([st_edge(102, "m8"), st_edge(104, "m9")],
                                       [("x", "identity_mismatch: stale",
                                         None)]))
    mutate_changed("changed userspace leg edged the provider",
                   userspace=ch_inventory([st_edge(102, "m8")],
                                          [st_unproven_gap(104)],
                                          backend="userspace",
                                          modules=(("m8", ST_KEY_B,
                                                    ST_PROVIDER),)))
    mutate_changed("changed run note without the disclosure",
                   run_note="run log: no disclosure here")
    mutate_changed("changed run note without the marker token",
                   run_note=ch_note.replace("pre_copy_up", "layer"))
    single_capture = good_changed_profile()
    single_capture["capture"]["modules"] = single_capture["capture"]["modules"][:1]
    mutate_changed("changed profile single capture row",
                   profile=single_capture)
    drifted_capture = good_changed_profile()
    drifted_capture["capture"]["modules"][1]["sha256"] = "c" * 64
    mutate_changed("changed profile capture identity drift",
                   profile=drifted_capture)
    single_discovery = good_changed_profile()
    single_discovery["evidence"]["discovery"] = \
        single_discovery["evidence"]["discovery"][:1]
    mutate_changed("changed profile single discovery row",
                   profile=single_discovery)
    unmarked = good_changed_profile()
    del unmarked["evidence"]["discovery"][0]["layer"]
    mutate_changed("changed profile lower row unmarked", profile=unmarked)
    marked_upper = good_changed_profile()
    marked_upper["evidence"]["discovery"][1]["layer"] = "pre_copy_up"
    mutate_changed("changed profile marker off the lower row",
                   profile=marked_upper)
    dropped_fresh = good_changed_profile()
    dropped_fresh["functions"] = [
        row for row in dropped_fresh["functions"]
        if row.get("module", {}) is None
        or row["module"]["sha256"] == ch_lower_sha
        or row.get("names") != ["C_GenerateRandom"]]
    mutate_changed("changed profile fresh row dropped", profile=dropped_fresh)
    swapped_counts = good_changed_profile(iters_s=100, iters_f=250)
    mutate_changed("changed profile counts swapped", profile=swapped_counts)
    errored = good_changed_profile()
    errored["functions"][0]["errors"] = 1
    mutate_changed("changed profile row errored", profile=errored)
    ambiguous = good_changed_profile()
    ambiguous["functions"][1]["module_ambiguous"] = True
    mutate_changed("changed profile module ambiguous", profile=ambiguous)
    scoped = good_changed_profile()
    scoped["capture"]["scope"] = "system"
    mutate_changed("changed profile off the cgroup scope", profile=scoped)
    drifted_profile = good_changed_profile()
    drifted_profile["evidence"]["pid_namespace"]["observer"] = "other"
    mutate_changed("changed profile observer drift", profile=drifted_profile)
    unprobed = good_changed_profile()
    unprobed["evidence"]["attached_probes"] = 0
    mutate_changed("changed profile without probes", profile=unprobed)
    lossy = good_changed_profile()
    lossy["evidence"]["event_loss"] = 1
    mutate_changed("changed profile event loss", profile=lossy)
    flying = good_changed_profile()
    flying["evidence"]["in_flight_at_end"] = 1
    mutate_changed("changed profile in-flight rows", profile=flying)
    gapped = good_changed_profile()
    gapped["evidence"]["verdict_detail"] = "concrete_gap"
    gapped["evidence"]["gap_classes"]["observation"]["causes"] = ["skipped"]
    mutate_changed("changed profile honestly lossy is not exact",
                   profile=gapped)

    mc_stamps = ("t-profile-ready=100 t-bpre-ledger=200 t-patch=300 "
                 "t-b2-ledger=400 t-profile-end=500\n")
    mc_facts = ch_facts + mc_stamps
    mc_note = ch_note + " (mid-capture: the patch landed mid-profile)"

    def good_midcapture():
        inputs = good_changed()
        inputs["facts_text"] = mc_facts
        inputs["run_note"] = mc_note
        return inputs

    def mutate_midcapture(label, **overrides):
        inputs = good_midcapture()
        inputs.update(overrides)
        refuses(label, lambda: copy_up_midcapture(**inputs))

    healthy_midcapture = copy_up_midcapture(**good_midcapture())
    assert healthy_midcapture["check"] == "copy-up-midcapture"
    assert healthy_midcapture["window"]["t-patch"] == "300"
    mutate_midcapture("midcapture facts without the patch stamp",
                      facts_text=mc_facts.replace("t-patch=300 ", ""))
    mutate_midcapture("midcapture patch before the stale ledger",
                      facts_text=mc_facts.replace("t-patch=300", "t-patch=150"))
    mutate_midcapture("midcapture patch after the window",
                      facts_text=mc_facts.replace(
                          "t-profile-end=500", "t-profile-end=250"))
    mutate_midcapture("midcapture tied stamps",
                      facts_text=mc_facts.replace(
                          "t-b2-ledger=400", "t-b2-ledger=300"))
    mutate_midcapture("midcapture settled note without the mode",
                      run_note=ch_note)
    mutate_midcapture("midcapture mappers swapped",
                      kernel=ch_inventory([st_edge(102, "m9"),
                                           st_edge(104, "m8")]))

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
    mutate_late("L gap about an unrelated .so",
                **late(False, [("/usr/lib/libevil.so", "r", 202)]))
    mutate_late("L gap about an unrelated device",
                **late(False, [("device 0:999 inode 1", "r", 202)]))
    mutate_late("L gap about another pid's /proc mem",
                **late(False, [("/proc/999/mem", "r", 202)]))
    assert late_reported(**late(
        False, [("device 0:138 inode 901",
                 "module first observed after admission", 202)]))["late"] == \
        "no-edge-with-gap"
    assert late_reported(**late(
        False, [("/proc/202/mem",
                 "module first observed after admission", 202)]))["late"] == \
        "no-edge-with-gap"
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
    mutate_late("L gap-branch edge above its ledger",
                **late(True, [(late_module, "r", 202)], cov="counted",
                       count=6 * 250 + 1))
    mutate_late("L gap-branch edge with a bogus status",
                **late(True, [(late_module, "r", 202)], cov="frobnicate",
                       count=5))
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
               "      --post-profile-b $WORK/d1-post-b.json "
               "--span-profile $WORK/d1-span-b.json \\\n"
               "      --pid-a $PID_A --pid-b-pre $PID_B_PRE "
               "--pid-b-span $PID_B2 --pid-b-post $PID_B_POST \\\n"
               "      --iters-a 400 --iters-b 250 "
               "--facts-log $WORK/facts.log "
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
    copy_parser.add_argument("--span-profile", required=True)
    copy_parser.add_argument("--pid-a", type=int, required=True)
    copy_parser.add_argument("--pid-b-pre", type=int, required=True)
    copy_parser.add_argument("--pid-b-span", type=int, required=True)
    copy_parser.add_argument("--pid-b-post", type=int, required=True)
    copy_parser.add_argument("--iters-a", type=int, required=True)
    copy_parser.add_argument("--iters-b", type=int, required=True)
    copy_parser.add_argument("--lane", required=True)
    copy_parser.add_argument("--dc73-note")
    copy_parser.add_argument("--facts-log", required=True)
    copy_parser.add_argument("--b-pre-round2-pid", type=int, required=True)
    copy_parser.add_argument("--module-suffix", default=PROVIDER)
    changed_parser = sub.add_parser("copy-up-changed")
    changed_parser.add_argument("--kernel", required=True)
    changed_parser.add_argument("--userspace", required=True)
    changed_parser.add_argument("--profile", required=True)
    changed_parser.add_argument("--pid-b-pre", type=int, required=True)
    changed_parser.add_argument("--pid-b2", type=int, required=True)
    changed_parser.add_argument("--iters-s", type=int, required=True)
    changed_parser.add_argument("--iters-f", type=int, required=True)
    changed_parser.add_argument("--run-note", required=True)
    changed_parser.add_argument("--facts-log", required=True)
    changed_parser.add_argument("--module-suffix", default=PROVIDER)
    midcapture_parser = sub.add_parser("copy-up-midcapture")
    midcapture_parser.add_argument("--kernel", required=True)
    midcapture_parser.add_argument("--userspace", required=True)
    midcapture_parser.add_argument("--profile", required=True)
    midcapture_parser.add_argument("--pid-b-pre", type=int, required=True)
    midcapture_parser.add_argument("--pid-b2", type=int, required=True)
    midcapture_parser.add_argument("--iters-s", type=int, required=True)
    midcapture_parser.add_argument("--iters-f", type=int, required=True)
    midcapture_parser.add_argument("--run-note", required=True)
    midcapture_parser.add_argument("--facts-log", required=True)
    midcapture_parser.add_argument("--module-suffix", default=PROVIDER)
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
                         options.b_pre_round2_pid,
                         options.module_suffix,
                         span_profile=load(options.span_profile))
        print(json.dumps(result, sort_keys=True))
        print(stale_caller_line(options.pid_b_pre), file=sys.stderr)
        round2 = result["b_pre_round2"]
        print(round2_line(round2["pid"], 6 * options.iters_b,
                          round2["twin"]),
              file=sys.stderr)
    elif options.command == "copy-up-changed":
        def load(path):
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)

        with open(options.run_note, encoding="utf-8") as handle:
            note = handle.read()
        facts = open(options.facts_log, encoding="utf-8").read()
        result = copy_up_changed(load(options.kernel), load(options.userspace),
                                 load(options.profile), options.pid_b_pre,
                                 options.pid_b2, options.iters_s,
                                 options.iters_f, note, facts,
                                 options.module_suffix)
        print(json.dumps(result, sort_keys=True))
        print(changed_caller_line(options.pid_b_pre), file=sys.stderr)
    elif options.command == "copy-up-midcapture":
        def load(path):
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)

        with open(options.run_note, encoding="utf-8") as handle:
            note = handle.read()
        facts = open(options.facts_log, encoding="utf-8").read()
        result = copy_up_midcapture(load(options.kernel), load(options.userspace),
                                    load(options.profile), options.pid_b_pre,
                                    options.pid_b2, options.iters_s,
                                    options.iters_f, note, facts,
                                    options.module_suffix)
        print(json.dumps(result, sort_keys=True))
        print(changed_caller_line(options.pid_b_pre), file=sys.stderr)
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
