#!/usr/bin/env python3
"""Exact evidence oracles shared by the canonical live capture lanes."""

import copy
import json
import re
import sys
from collections import Counter
from pathlib import Path


COUNTERS = (
    "event_loss",
    "start_insert_failures",
    "unmatched_returns",
    "rv_update_failures",
    "cgroup_scope_failures",
    "semantic_capture_failures",
    "unregistered_mechanisms",
    "template_tail_failures",
    "process_tracking_fallbacks",
    "process_tracking_failures",
    "process_tracking_evictions",
    "state_reconciliations",
    "session_cancel_ambiguities",
    "session_cancel_unknown_flags",
    "operation_state_imports",
    "auth_state_ambiguities",
    "async_target_failures",
    "async_orphans",
    "async_duplicates",
    "async_evictions",
    "fork_state_ambiguities",
    "semantic_state_drops",
    "pending_at_end",
    "malformed_records",
    "orphan_ops",
    "unmatched_closes",
    "shape_decode_failures",
    "shape_decode_total_failures",
    # Discovery gaps (schema v2). Every one of them forces PARTIAL. None of them
    # may be nonzero by accident: each lane below states the value it expects and
    # why, because "which sources described this provider" is now part of the
    # oracle, not a detail of how the lane was set up.
    "discovery_conflicts",
    "discovery_uncorroborated",
    "module_ambiguous",
    # Live-discovery losses (slice 1b-2, design §9.1). Each has exactly one
    # owner — the BPF counters or the one discovery-engine accumulator — and
    # each forces PARTIAL. None is derived from received record counts.
    "discovery_ring_loss",
    "discovery_state_failures",
    "discovery_read_failures",
    "discovery_truncated",
)

# `evidence.loader_discovery` (design §9.2): finite, aggregate, and closed.
# Every key is always present, every value is an unsigned 64-bit count, and
# there is no second public copy of an internal counter or identity.
LOADER_TIMING_KEYS = (
    "qualified_pre_constructor",
    "known_pre_relocation",
    "unproven",
    "none",
)
LOADER_DISCOVERY_GROUPS = {
    "strategies": ("debug_state_every_hit", "dlopen_return", "unavailable"),
    "dlopen_timing": LOADER_TIMING_KEYS,
    "initial_set_timing": LOADER_TIMING_KEYS,
    "initial_set_capture": ("eligible", "none"),
}
LOADER_DISCOVERY_COUNTERS = ("hits", "state_read_failures")
PAUSE_VALUES = ("none", "sigstop", "partial")
PAUSE_COUNTERS = ("pause_attempts", "pause_confirmed", "pause_partial")
DISCOVERY_LOSS_COUNTERS = (
    "discovery_ring_loss",
    "discovery_state_failures",
    "discovery_read_failures",
    "discovery_truncated",
)
MAX_MANIFEST_OBJECT_FALLBACKS = 512
MANIFEST_STALE_REASONS = {"open_stale", "identity_mismatch"}
ALLOWED_SOURCE_ARRAYS = (["scan"], ["manifest"], ["scan", "manifest"])
ALLOWED_TABLE_SOURCES = {"scan", "manifest"}
ALLOWED_CORROBORATION = {
    "single_source",
    "agreed",
    "conflict",
    "scan_empty",
    "uncorroborated",
    "identity_mismatch",
    "object_fallback",
}
COMPARABLE_CORROBORATION = {"agreed", "conflict"}
U64_MAX = (1 << 64) - 1

# The version-matrix provider, seen two ways. Both are measured, both are exact.
#
# MANIFEST-ONLY — the workload dlopens the provider only *after* the observer
# attaches (every induced-gap lane, and every lane whose target is released by a
# go-file). This slice scans once, at attach time, so the scan finds nothing in
# scope: the manifest is the only source, and it is `uncorroborated` because
# nothing was there to confirm it. Thirteen surfaces, 988 entries — the helper's
# own numbers, unchanged from v1.
VERSION_SURFACES = Counter(
    {
        ("full", 68): 2,
        ("full", 92): 2,
        ("full", 104): 2,
        ("known_prefix", 68): 1,
        ("known_prefix", 92): 2,
        ("known_prefix", 104): 2,
        ("refused", 0): 1,
        ("not_walked", 0): 1,
    }
)
# SCANNED — the canary workload maps the provider *before* attach, so both
# sources describe it. Only three of the provider's thirteen tables live in the
# object's file-backed data; the other ten are built at run time in .bss. The
# scan decoded a nonempty file-backed subset, so the runtime-only tables are not
# object-level scan failures. The differing source sets are recorded by one
# `discovery_conflict` and exact per-source table records.
#
# What the union does *not* change is the attach plan: 104 slots and 208 probes,
# exactly as before, because a slot is one {object, file offset} however many
# sources named it. `surfaces` keeps the per-source records, so the three scan
# tables add three surfaces (13 -> 16). `table_entries` counts exact target
# occurrences across sources, so this scan subset does not add another 228.
VERSION_SURFACES_SCANNED = VERSION_SURFACES + Counter(
    {("full", 68): 2, ("full", 92): 1}
)
VERSION_SHAPE_MANIFEST_ONLY = (988, 104, 208, VERSION_SURFACES, 1, "ok")
VERSION_SHAPE_SCANNED = (988, 104, 208, VERSION_SURFACES_SCANNED, 1, "ok")
VERSION_TABLES_MANIFEST_ONLY = Counter(
    {
        ("manifest", (0, 0), 0): 1,
        ("manifest", (2, 40), 68): 3,
        ("manifest", (3, 0), 92): 2,
        ("manifest", (3, 1), 92): 2,
        ("manifest", (3, 2), 104): 3,
        ("manifest", (3, 9), 104): 1,
        ("manifest", (4, 0), 0): 1,
    }
)
VERSION_TABLES_SCANNED = VERSION_TABLES_MANIFEST_ONLY + Counter(
    {("scan", (2, 40), 68): 2, ("scan", (3, 0), 92): 1}
)
DISCOVERY_SUBJECT = "discovery subject"
DISCOVERY_UNAVAILABLE = "discovery unavailable"
ENTRY_UNAVAILABLE = "function entry unavailable"
TABLE_UNAVAILABLE = "function table unavailable in file-backed data"
SHARED_OVERLAY_UNCERTAINTY = (
    "shared-overlay physical identity is uncertain; a distinct byte-identical "
    "instance may be unobserved"
)
DISCOVERY_REASONS = {
    DISCOVERY_UNAVAILABLE,
    TABLE_UNAVAILABLE,
    SHARED_OVERLAY_UNCERTAINTY,
}
ENTRY_REASONS = {"null pointer", ENTRY_UNAVAILABLE}
G1_SURFACES = Counter({("full", 68): 1, ("full", 92): 1, ("not_walked", 0): 1})
LEGACY_SURFACES = Counter({("full", 68): 1})
# What the p11-kit proxy lane's capacity-refused module really decodes on the
# hosted lane: libp11-kit maps 64 static CK_FUNCTION_LIST_3_0 closures, 92
# entries each. The refusal is an attach-ceiling refusal, taken after decode, so
# every one of those entries stays counted in `table_entries`.
PROXY_REFUSED_SURFACES = Counter({("full", 92): 64})
PROXY_REFUSED_ENTRIES = sum(
    entries * count for (_walk, entries), count in PROXY_REFUSED_SURFACES.items()
)

SAFE_ALLOWANCES = {
    "semantic_capture_failures": 3,
    "unregistered_mechanisms": 2,
    "async_target_failures": 2,
    "async_orphans": 1,
    "orphan_ops": 3,
}
UNSAFE_ALLOWANCES = {
    "semantic_capture_failures": 7,
    "async_target_failures": 2,
    "async_orphans": 1,
    "orphan_ops": 3,
    "shape_decode_failures": 2,
}
G3_COUNTS = {
    "C_GetFunctionList": 1,
    "C_Initialize": 1,
    "C_Finalize": 1,
    "C_GetSlotList": 1,
    "C_OpenSession": 1,
    "C_CloseSession": 1,
    "C_GenerateRandom": 200000,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest_ok(carrier):
    """A whole-file SHA-256 is present and well-formed.

    `sha256` is `null` for an object this capture never pinned — an absence, not
    an empty digest — so the null must be rejected as a stated failure rather
    than crash the length check.
    """
    digest = carrier["sha256"]
    return isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None


def u64(value, *, positive=False):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= U64_MAX
    )


def exact_identity(carrier):
    require(
        isinstance(carrier["dev"], list)
        and len(carrier["dev"]) == 2
        and all(u64(part) for part in carrier["dev"]),
        f"invalid object device: {carrier}",
    )
    require(u64(carrier["ino"], positive=True), f"invalid object inode: {carrier}")
    require(digest_ok(carrier), f"invalid object digest: {carrier}")


def exact_sources(carrier):
    require(
        carrier["sources"] in ALLOWED_SOURCE_ARRAYS,
        f"invalid discovery sources: {carrier}",
    )


def semantic_join_eligible(function, module, *, has_manifest_object_fallback):
    """Whether unchanged v2 evidence authorizes semantic consumer joins."""
    if (
        has_manifest_object_fallback
        or function["module"] is None
        or function["module_ambiguous"]
        or function["aliased"]
    ):
        return False
    sources = module["sources"]
    outcomes = set(module["corroboration"])
    if sources == ["manifest"]:
        return True
    return (
        sources == ["scan", "manifest"]
        and "agreed" in outcomes
        and not outcomes.intersection({"conflict", "identity_mismatch", "object_fallback"})
    )


def exact_discovery_semantics(evidence):
    conflicts = 0
    for module in evidence["discovery"]:
        require(
            {"sources", "corroborated", "corroboration", "tables"} <= set(module),
            f"incomplete discovery module: {module}",
        )
        exact_sources(module)
        require(isinstance(module["corroborated"], bool), module)
        outcomes = module["corroboration"]
        require(isinstance(outcomes, list) and outcomes, f"invalid corroboration: {module}")
        require(
            all(outcome in ALLOWED_CORROBORATION for outcome in outcomes),
            f"invalid corroboration: {module}",
        )
        outcome_set = set(outcomes)
        sources = module["sources"]
        if sources == ["scan"]:
            source_outcomes_ok = outcomes == ["single_source"] or outcome_set <= {
                "identity_mismatch",
                "object_fallback",
            }
        elif sources == ["manifest"]:
            source_outcomes_ok = outcome_set == {"uncorroborated"}
        else:
            source_outcomes_ok = not outcome_set.intersection(
                {"single_source", "uncorroborated"}
            ) and bool(outcome_set.intersection({"agreed", "conflict", "scan_empty"}))
        require(
            source_outcomes_ok,
            f"corroboration disagrees with exact sources: {module}",
        )
        comparable = bool(outcome_set.intersection(COMPARABLE_CORROBORATION))
        require(
            module["corroborated"] == comparable,
            f"corroborated disagrees with exact outcomes: {module}",
        )
        conflicts += outcomes.count("conflict")
        for table in module["tables"]:
            source = table["source"]
            require(source in ALLOWED_TABLE_SOURCES, f"invalid table source: {table}")
            require(source in module["sources"], f"table source absent from module: {module}")
    require(
        evidence["discovery_conflicts"] == conflicts,
        f"discovery_conflicts: want {conflicts}, got {evidence['discovery_conflicts']}",
    )
    if any(module["sources"] == ["scan"] for module in evidence["discovery"]):
        require(
            evidence["completeness"] == "PARTIAL",
            "scan-only semantic evidence cannot be COMPLETE",
        )


def exact_counters(evidence, allowances=None):
    allowances = allowances or {}
    unknown = set(allowances) - set(COUNTERS)
    require(not unknown, f"unknown evidence allowances: {sorted(unknown)}")
    for name in COUNTERS:
        wanted = allowances.get(name, 0)
        require(evidence[name] == wanted, f"{name}: want {wanted}, got {evidence[name]}")


def exact_manifest_object_fallbacks(evidence):
    """Every stale object is bound to one scan-opened identity, never a path."""
    exact_discovery_semantics(evidence)
    fallbacks = evidence["manifest_object_fallbacks"]
    require(isinstance(fallbacks, list), "manifest_object_fallbacks is not an array")
    require(
        len(fallbacks) <= MAX_MANIFEST_OBJECT_FALLBACKS,
        f"too many manifest object fallbacks: {len(fallbacks)}",
    )
    scan_identities = set()
    for module in evidence["discovery"]:
        require(
            {"sources", "objects", "corroborated", "corroboration"} <= set(module),
            f"incomplete discovery module: {module}",
        )
        exact_sources(module)
        exact_identity(module)
        if "scan" in module["sources"]:
            scan_identities.add((tuple(module["dev"]), module["ino"], module["sha256"]))
        for carrier in module["objects"]:
            exact_sources(carrier)
            exact_identity(carrier)
            if "scan" in carrier["sources"]:
                scan_identities.add(
                    (tuple(carrier["dev"]), carrier["ino"], carrier["sha256"])
                )

    seen_objects = set()
    seen_replacements = set()
    for fallback in fallbacks:
        require(
            set(fallback) == {"manifest", "object", "reason", "replacement"},
            f"unexpected manifest fallback shape: {fallback}",
        )
        manifest, object_id = fallback["manifest"], fallback["object"]
        require(
            isinstance(manifest, int)
            and not isinstance(manifest, bool)
            and 0 <= manifest <= 0xFFFFFFFF,
            f"invalid manifest fallback ordinal: {fallback}",
        )
        require(
            isinstance(object_id, int) and not isinstance(object_id, bool) and 0 <= object_id < 512,
            f"invalid manifest object id: {fallback}",
        )
        require(fallback["reason"] in MANIFEST_STALE_REASONS, fallback)
        replacement = fallback["replacement"]
        require(set(replacement) == {"dev", "ino", "sha256"}, fallback)
        exact_identity(replacement)
        identity = (
            tuple(replacement["dev"]),
            replacement["ino"],
            replacement["sha256"],
        )
        require(identity in scan_identities, f"fallback is not scan-owned: {fallback}")
        require(
            (manifest, object_id) not in seen_objects,
            f"duplicate manifest object fallback: {fallback}",
        )
        require(
            identity not in seen_replacements,
            f"one scan object cannot hide two stale objects: {fallback}",
        )
        seen_objects.add((manifest, object_id))
        seen_replacements.add(identity)

    for module in evidence["discovery"]:
        fallback_outcomes = module["corroboration"].count("object_fallback")
        if fallback_outcomes:
            identity = (tuple(module["dev"]), module["ino"], module["sha256"])
            require(
                fallback_outcomes == 1 and identity in seen_replacements,
                f"object_fallback has no exact replacement evidence: {module}",
            )

    # This relation is deliberately one-way. A fallback for a dependency has no
    # public function/module relation in v2, so requiring every fallback to
    # render an `object_fallback` outcome would invent unsafe reverse evidence.
    # Consumers instead make all semantic joins ineligible when any fallback is
    # present (see `semantic_join_eligible`).

    standalone = sum(
        "manifest" in module["sources"] and not module["corroborated"]
        for module in evidence["discovery"]
    )
    ignored_manifests = sum(
        outcome == "identity_mismatch"
        for module in evidence["discovery"]
        for outcome in module["corroboration"]
    )
    expected = standalone + ignored_manifests + len(fallbacks)
    require(
        evidence["discovery_uncorroborated"] == expected,
        f"discovery_uncorroborated: want {expected}, got {evidence['discovery_uncorroborated']}",
    )


def surface_signature(evidence):
    surfaces = evidence["surfaces"]
    require(surfaces, "evidence.surfaces is empty")
    require(
        all(surface["acquisition"] == "ok" for surface in surfaces),
        f"surface acquisition failure: {surfaces}",
    )
    return Counter((surface["walk"], surface["functions"]) for surface in surfaces)


def table_signature(evidence):
    require(len(evidence["discovery"]) == 1, evidence["discovery"])
    return Counter(
        (table["source"], tuple(table["version"]), table["entries"])
        for table in evidence["discovery"][0]["tables"]
    )


def exact_shape(evidence, table_entries, slots, probes, surfaces, vendor, interface_list):
    for name, wanted in (
        ("table_entries", table_entries),
        ("slots", slots),
        ("attached_probes", probes),
        ("vendor_interfaces", vendor),
        ("interface_list", interface_list),
    ):
        require(evidence[name] == wanted, f"{name}: want {wanted!r}, got {evidence[name]!r}")
    require(surface_signature(evidence) == surfaces, f"unexpected surfaces: {evidence['surfaces']}")


def entry_skips(evidence):
    """The table entries no probe could attach to.

    `evidence.skipped` mixes two granularities the schema documents together:
    entry-level losses, whose `name` is the PKCS#11 function that was lost, and
    object/process-level losses, whose `name` is the bounded category
    `discovery subject`.
    Only the first kind is an oracle a lane can state exactly — the second kind
    depends on what else the scan walked, which for a `--cgroup` lane is every
    process in that cgroup.
    """
    return [item for item in evidence["skipped"] if item["name"].startswith("C_")]


def discovery_skips(evidence):
    """Object/process/scope losses after capture-output subject bounding."""
    for item in evidence["skipped"]:
        entry = item["name"].startswith("C_")
        require(
            entry or item["name"] == DISCOVERY_SUBJECT,
            f"unbounded capture skip subject: {item}",
        )
        allowed = ENTRY_REASONS if entry else DISCOVERY_REASONS
        require(item["reason"] in allowed, f"unbounded capture skip reason: {item}")
    return [item for item in evidence["skipped"] if item["name"] == DISCOVERY_SUBJECT]


# The closed loader/pause namespace. PID/TID and task sets are permitted only
# in the pre-existing ordinary call-event trace fields the allowlist already
# names (docs/privacy/allowlist-v1.md), never in a capture document.
IDENTITY_PREFIXES = ("pause", "loader", "child", "attach_gap")
IDENTITY_SUFFIXES = ("_pid", "_tid", "_tids", "_tasks", "_task_set")
PUBLISHED_LOADER_PAUSE_FIELDS = {
    "attach_gap_ms",
    "pause",
    "loader_discovery",
    "child_still_running",
    *PAUSE_COUNTERS,
}


def unpublished_identity_keys(mapping, published=()):
    """Keys this object publishes from the closed loader/pause namespace."""
    return sorted(
        name
        for name in mapping
        if name not in published
        and (name.startswith(IDENTITY_PREFIXES) or name.endswith(IDENTITY_SUFFIXES))
    )


def exact_loader_discovery(evidence):
    """`evidence.loader_discovery` is closed, finite, and count-only.

    The exact key sets are the whole check: an injected identity — a raw
    PID/TID/task set, a loader/libc path, digest or build ID, an address,
    pointer, cookie, context id, delta, absent-state sentinel, signal record,
    interface-name bytes, marker, or an observer-owned map value — can only
    arrive as an extra key or a non-count value, and both are refused here
    rather than pattern-matched out of a string.

    The cardinalities are the second half: the three classification groups are
    one partition of the same exact bound-context set, not three independent
    tallies, so a count with no context behind it is refused too.
    """
    aggregate = evidence["loader_discovery"]
    require(isinstance(aggregate, dict), f"loader_discovery is not an object: {aggregate!r}")
    require(
        set(aggregate) == set(LOADER_DISCOVERY_GROUPS) | set(LOADER_DISCOVERY_COUNTERS),
        f"loader_discovery key set: {sorted(aggregate)}",
    )
    for group, keys in LOADER_DISCOVERY_GROUPS.items():
        value = aggregate[group]
        require(isinstance(value, dict), f"loader_discovery.{group} is not an object: {value!r}")
        # The key *set* is the freeze. JSON objects carry no order the
        # renderer can promise: `serde_json` is built without `preserve_order`,
        # so a real artifact's keys arrive sorted, not in declaration order.
        # Set equality still refuses both a missing key and an added one, which
        # is the whole point of the closed aggregate.
        require(
            set(value) == set(keys),
            f"loader_discovery.{group} key set: {sorted(value)}",
        )
        for key in keys:
            require(u64(value[key]), f"loader_discovery.{group}.{key}: {value[key]!r}")
    for counter in LOADER_DISCOVERY_COUNTERS:
        require(u64(aggregate[counter]), f"loader_discovery.{counter}: {aggregate[counter]!r}")
    # Every exact bound context is counted once as a strategy and once in
    # exactly one timing group, and an initial-set context additionally states
    # its capture outcome. `hits` and `state_read_failures` are BPF counters
    # over records, not contexts, and are deliberately unconstrained here.
    strategies = sum(aggregate["strategies"].values())
    dlopen = sum(aggregate["dlopen_timing"].values())
    initial_set = sum(aggregate["initial_set_timing"].values())
    captures = sum(aggregate["initial_set_capture"].values())
    require(
        strategies == dlopen + initial_set,
        f"loader_discovery counts {strategies} strategies for {dlopen + initial_set} timed contexts",
    )
    require(
        captures == initial_set,
        f"loader_discovery states {captures} initial-set captures for {initial_set} contexts",
    )
    # An owned run owns exactly one child, so it arms at most one pre-exec
    # initial-set context; no other capture arms one at all.
    require(initial_set <= 1, f"more than one initial-set context: {initial_set}")


def exact_live_discovery_evidence(evidence, *, run=False):
    """The exact fields slice 1b-2 publishes (design §5.5, §5.6, §9.1–§9.2)."""
    missing = [
        name
        for name in (
            "attach_gap_ms",
            "pause",
            *PAUSE_COUNTERS,
            *DISCOVERY_LOSS_COUNTERS,
            "loader_discovery",
        )
        if name not in evidence
    ]
    require(not missing, f"missing live discovery evidence: {missing}")
    # The loader/pause namespace is closed at the evidence level too.
    intruders = unpublished_identity_keys(evidence, PUBLISHED_LOADER_PAUSE_FIELDS)
    require(not intruders, f"unpublished loader/pause evidence: {intruders}")
    gap = evidence["attach_gap_ms"]
    require(gap is None or u64(gap), f"attach_gap_ms: {gap!r}")
    require(evidence["pause"] in PAUSE_VALUES, f"pause: {evidence['pause']!r}")
    for counter in PAUSE_COUNTERS:
        require(u64(evidence[counter]), f"{counter}: {evidence[counter]!r}")
    attempts, confirmed, partial = (evidence[name] for name in PAUSE_COUNTERS)
    require(
        confirmed + partial == attempts,
        f"pause counters do not add up: {attempts} != {confirmed} + {partial}",
    )
    # The published value is exactly the lattice, never an independent label.
    wanted = "none" if attempts == 0 else "partial" if partial else "sigstop"
    require(evidence["pause"] == wanted, f"pause: want {wanted}, got {evidence['pause']}")
    for counter in DISCOVERY_LOSS_COUNTERS:
        require(u64(evidence[counter]), f"{counter}: {evidence[counter]!r}")
    if run:
        require(
            isinstance(evidence.get("child_still_running"), bool),
            f"run evidence must state child_still_running: {evidence.get('child_still_running')!r}",
        )
    else:
        require(
            "child_still_running" not in evidence,
            "child_still_running is a run-only field",
        )
    exact_loader_discovery(evidence)


def exact_module_ownership(document):
    """`module`, `module_ambiguous`, `module_unresolved` are exclusive.

    Exactly one of nonnull/false/false, null/true/false, or null/false/true.
    `null,false,false` is a cell with no stated reason for its missing owner
    and is refused; an explicitly unowned cell is null/false/true and forces
    PARTIAL, and it is never relabelled as two-module ambiguity.

    The unowned reason is that one finite boolean and nothing else: the row
    publishes no reason string, process identity, path, cookie, or internal
    owner key beside it, in the row or in its module reference.
    """
    unresolved_seen = False
    for item in document["functions"]:
        require(
            {"module", "module_ambiguous", "module_unresolved"} <= set(item),
            f"function row states no owner relation: {item}",
        )
        intruders = unpublished_identity_keys(item)
        require(not intruders, f"unpublished owner identity on a function row: {intruders}")
        if isinstance(item["module"], dict):
            intruders = unpublished_identity_keys(item["module"])
            require(not intruders, f"unpublished owner identity on a module ref: {intruders}")
        owner, ambiguous, unresolved = (
            item["module"],
            item["module_ambiguous"],
            item["module_unresolved"],
        )
        require(isinstance(ambiguous, bool), f"module_ambiguous is not a boolean: {item}")
        require(isinstance(unresolved, bool), f"module_unresolved is not a boolean: {item}")
        require(
            (owner is not None, ambiguous, unresolved)
            in {(True, False, False), (False, True, False), (False, False, True)},
            f"module ownership relation: {item}",
        )
        unresolved_seen = unresolved_seen or unresolved
    if unresolved_seen:
        require(
            document["evidence"]["completeness"] == "PARTIAL",
            "an unresolved slot owner must force PARTIAL",
        )


def exact_active_to_empty(document):
    """A capture whose target exited the ordinary way keeps its history.

    Modules, table entries, surfaces and skips, allocated slots, successful
    endpoints, aggregate calls, and the exact function-module references are
    capture-lifetime facts. The exit itself is neither a discovery loss nor a
    state reconciliation, and every counted call still names a declared owner.
    """
    evidence = document["evidence"]
    require(evidence["discovery"], "history lost: no module survived the exit")
    require(document["capture"]["modules"], "history lost: capture.modules is empty")
    require(evidence["surfaces"], "history lost: no surface survived the exit")
    for name in ("table_entries", "slots", "attached_probes"):
        require(u64(evidence[name], positive=True), f"history lost: {name} is {evidence[name]!r}")
    for counter in DISCOVERY_LOSS_COUNTERS:
        require(evidence[counter] == 0, f"an ordinary exit is not a {counter}")
    require(
        evidence["state_reconciliations"] == 0,
        "an ordinary exit is not a state reconciliation",
    )
    exact_module_ownership(document)
    declared = {(tuple(module["dev"]), module["ino"]) for module in evidence["discovery"]}
    for item in document["functions"]:
        owner = item["module"]
        if owner is not None:
            require(
                (tuple(owner["dev"]), owner["ino"]) in declared,
                f"undeclared slot owner: {owner}",
            )


def exact_common(evidence, *, aliases, skipped, in_flight, discovery_skipped=0):
    require(evidence["attach_failures"] == [], evidence["attach_failures"])
    require(evidence["aliased"] == aliases, f"unexpected aliases: {evidence['aliased']}")
    require(
        entry_skips(evidence) == skipped,
        f"unexpected entry skips: {entry_skips(evidence)}",
    )
    require(
        len(discovery_skips(evidence)) == discovery_skipped,
        f"discovery skips: want {discovery_skipped}, got {discovery_skips(evidence)}",
    )
    require(evidence["in_flight_at_end"] == in_flight, evidence["in_flight_at_end"])
    require(evidence["templates_truncated"] is False, "templates were truncated")
    require(evidence["provider_changed"] is False, "a pinned provider object changed during capture")
    # Discovery is the claim the whole document rests on: a lane that attached
    # probes must name what it attached them into, and how it was authorized.
    require(evidence["authority"] == "hash-pinned", f"unexpected authority: {evidence['authority']}")
    exact_live_discovery_evidence(evidence)
    require(evidence["discovery"], "evidence.discovery is empty: nothing was discovered")
    exact_manifest_object_fallbacks(evidence)
    for module in evidence["discovery"]:
        exact_identity(module)
        exact_sources(module)
        for object_ in module["objects"]:
            exact_identity(object_)
            exact_sources(object_)
    require(evidence["modules_skipped"] == [], f"modules refused: {evidence['modules_skipped']}")
    require(evidence["scan_unavailable"] is None, evidence["scan_unavailable"])
    require(evidence["completeness"] == "PARTIAL", evidence["completeness"])


# The four counters the schema documents as informational, and therefore
# permits nonzero in an otherwise complete document. A lane that attaches mid
# execution legitimately reports orphan operations and unmatched closes, and a
# lane observing many short-lived processes legitimately falls back from pidfd
# identity to /proc start-time identity.
INFORMATIONAL_COUNTERS = frozenset(
    {
        "process_tracking_fallbacks",
        "orphan_ops",
        "unmatched_closes",
        "shape_decode_failures",
    }
)


def terminal_capture_is_clean(evidence, *, uncorroborated=0):
    """Normal terminal evidence for a lane with its own call oracle.

    A detached perf link does not wait for BPF callbacks already running on
    another CPU, so a terminal snapshot is PARTIAL by construction. "Clean"
    therefore means exactly what COMPLETE used to mean, minus that one
    unprovable drain: no attach failure, alias, skip, or in-flight call, and
    every *concrete* gap counter zero. The documented informational counters
    are not gaps and are not constrained here; a lane that can prove an exact
    value for them should assert it directly with exact_counters.

    `uncorroborated` is the one gap a lane may legitimately expect: a lane whose
    target does not map the provider until *after* the observer has attached
    (a forked child, a cold-start pod, a stopped process released by SIGCONT)
    gives the scan nothing to corroborate its manifest against. The value is
    still exact — a lane must say how many manifests stand alone, and one that
    expected corroboration and did not get it still fails.
    """
    exact_common(evidence, aliases=[], skipped=[], in_flight=0)
    for name in COUNTERS:
        if name in INFORMATIONAL_COUNTERS:
            continue
        wanted = uncorroborated if name == "discovery_uncorroborated" else 0
        require(evidence[name] == wanted, f"{name}: want {wanted}, got {evidence[name]}")


def exact_capture_modules(document):
    """`capture.modules[]` — v2's replacement for the singular `capture.module`.

    A lane that attached probes observed at least one module, and every entry
    must carry the identity the probes were authorized against, never just a
    pathname (which for a scanned module is the target's, not the observer's).
    """
    exact_manifest_object_fallbacks(document["evidence"])
    exact_module_ownership(document)
    modules = document["capture"]["modules"]
    require(modules, "capture.modules is empty: the document names no provider")
    for module in modules:
        require(module["path"], f"module without a path: {module}")
        # `sha256` is null for an object nothing pinned — never in a lane that
        # attached probes, and the guard keeps that a stated rejection rather
        # than a TypeError traceback.
        exact_identity(module)
    require(
        modules == [
            {key: module[key] for key in ("path", "dev", "ino", "sha256", "build_id")}
            for module in document["evidence"]["discovery"]
        ],
        "capture.modules[] and evidence.discovery[] disagree about what was observed",
    )
    # Every count is attributed to a module the document names, or to nobody at
    # all with the reason stated. An identity that matches no declared module
    # would make the attribution unverifiable, which is the point of publishing it.
    identities = [{key: module[key] for key in ("dev", "ino", "sha256")} for module in modules]
    discovery_by_identity = {
        (tuple(module["dev"]), module["ino"], module["sha256"]): module
        for module in document["evidence"]["discovery"]
    }
    ineligible = False
    for item in document["functions"]:
        names = item["names"]
        require(isinstance(names, list) and names, f"function without names: {item}")
        require(
            isinstance(item["aliased"], bool) and item["aliased"] == (len(names) > 1),
            f"function alias flag disagrees with names: {item}",
        )
        owner, ambiguous = item["module"], item["module_ambiguous"]
        if owner is None:
            # Two stated reasons exist, and `exact_module_ownership` above has
            # already refused every shape that states both or neither: two
            # modules claim the slot, or the allocated cell has no accepted
            # sole owner at all. Neither is ever guessed into an attribution.
            require(
                ambiguous is True or item["module_unresolved"] is True,
                f"unattributed function without a reason: {item}",
            )
            ineligible = True
            continue
        require(ambiguous is False, f"attributed function marked ambiguous: {item}")
        require(owner in identities, f"function attributed to an undeclared module: {item}")
        identity = (tuple(owner["dev"]), owner["ino"], owner["sha256"])
        ineligible |= not semantic_join_eligible(
            item,
            discovery_by_identity[identity],
            has_manifest_object_fallback=bool(
                document["evidence"]["manifest_object_fallbacks"]
            ),
        )
    if ineligible:
        require(
            document["evidence"]["completeness"] == "PARTIAL",
            "semantically ineligible functions cannot be COMPLETE",
        )


def validate_proxy_capacity_fallback(document):
    """The exact p11-kit-over-capacity/SoftHSM2-attached live shape."""
    require(document["schema"] == "pkcs11-scope/observed-profile/v2-metrics", document["schema"])
    require(document["capture"]["mode"] == "metrics", document["capture"])
    require(document["capture"]["privacy_mode"] == "aggregate-only", document["capture"])
    exact_capture_modules(document)

    evidence = document["evidence"]
    exact_counters(evidence)
    require(evidence["attach_failures"] == [], evidence["attach_failures"])
    require(evidence["aliased"] == [], evidence["aliased"])
    require(evidence["in_flight_at_end"] == 0, evidence["in_flight_at_end"])
    require(evidence["templates_truncated"] is False, "templates were truncated")
    require(evidence["provider_changed"] is False, "a pinned provider object changed")
    require(evidence["authority"] == "hash-pinned", evidence["authority"])
    require(evidence["scan_unavailable"] is None, evidence["scan_unavailable"])
    require(evidence["completeness"] == "PARTIAL", evidence["completeness"])

    modules = document["capture"]["modules"]
    require(len(modules) == 1, [module["path"] for module in modules])
    module = modules[0]
    require("softhsm" in module["path"].lower(), module["path"])
    require("p11-kit" not in module["path"].lower(), module["path"])
    discovery = evidence["discovery"]
    require(len(discovery) == 1, discovery)
    require(discovery[0]["sources"] == ["scan"], discovery)
    require(discovery[0]["corroborated"] is False, discovery)
    require(discovery[0]["corroboration"] == ["single_source"], discovery)
    require(discovery[0]["interfaces"] == 0, discovery)
    require(discovery[0]["skipped"] == [], discovery)
    require(
        discovery[0]["tables"] == [{"version": [2, 40], "entries": 68, "source": "scan"}],
        discovery,
    )
    objects = discovery[0]["objects"]
    require(len(objects) == 1, objects)
    target = objects[0]
    identity = {key: module[key] for key in ("dev", "ino", "sha256")}
    require(
        {key: target[key] for key in identity} == identity,
        f"attached target is not the SoftHSM2 module object: {target}",
    )
    require(target["path"] == module["path"], target)
    require("p11-kit" not in target["path"].lower(), target)

    refused = evidence["modules_skipped"]
    require(len(refused) == 1, refused)
    require("p11-kit" in refused[0]["name"].lower(), refused)
    match = re.fullmatch(
        r"module needs ([0-9]+) more of the 512 attach slots; 0 are in use "
        r"— refusing to attach a prefix",
        refused[0]["reason"],
    )
    require(match and int(match.group(1)) > 512, refused)

    # Decoded occurrences are recorded *before* slot-capacity admission, so a
    # module refused only by the attach ceiling keeps every entry it decoded;
    # capacity bounds attachment, not discovery
    # (plan 2026-08-19-slice1b2-production.md:1120-1136, schema v2 `table_entries`).
    # How much that is belongs to the p11-kit build under test — this one maps
    # 64 static 3.0 closures — so the refused contribution is derived from the
    # surfaces the capture attributed to the refused module, never frozen at the
    # attached module's own 68. Both modules must own every surface: an
    # unattributable surface is a gap, not an allowance.
    attached_surfaces = Counter()
    refused_entries = 0
    for surface in evidence["surfaces"]:
        require(surface["acquisition"] == "ok", f"surface acquisition failure: {surface}")
        if surface["source"].startswith(f"{module['path']} "):
            attached_surfaces[(surface["walk"], surface["functions"])] += 1
        elif surface["source"].startswith(f"{refused[0]['name']} "):
            refused_entries += surface["functions"]
        else:
            require(False, f"surface belongs to neither module: {surface}")
    require(
        attached_surfaces == LEGACY_SURFACES,
        f"unexpected attached-module surfaces: {dict(attached_surfaces)}",
    )
    require(
        refused_entries > 0,
        f"the capacity-refused module kept none of its decoded entries: {evidence['surfaces']}",
    )
    # `slots`/`attached_probes` stay bounded to the one attached module: the
    # refused module contributes decoded history and no public accepted module.
    for name, wanted in (
        ("table_entries", 68 + refused_entries),
        ("slots", 68),
        ("attached_probes", 136),
        ("vendor_interfaces", 0),
        ("interface_list", "absent"),
    ):
        require(evidence[name] == wanted, f"{name}: want {wanted!r}, got {evidence[name]!r}")

    require(evidence["skipped"] == [], evidence["skipped"])

    functions = document["functions"]
    require(len(functions) == 68, len(functions))
    called = 0
    for item in functions:
        require(item["module_ambiguous"] is False, item)
        require(item["module"] == identity, item)
        require(isinstance(item["calls"], int) and item["calls"] >= 0, item)
        called += item["calls"]
    require(called > 0, "the SoftHSM2 backend handled no calls")


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_canary(path, trace):
    if not trace:
        return load_json(path)
    records = [
        line.removeprefix("EVIDENCE ")
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.startswith("EVIDENCE ")
    ]
    require(len(records) == 1, f"expected one terminal EVIDENCE record, got {len(records)}")
    return json.loads(records[0])


# How discovery saw the provider in a SoftHSM2 lane. The shape is the same for
# all three — SoftHSM2 publishes one 2.40 table in the object's file-backed
# data, so the scan and the helper compute the *same* 68 offsets — but which
# sources described it, and whether anything corroborated the manifest, is part
# of the oracle and never inferred.
CLEAN_DISCOVERY = {
    # The scan alone: no manifest was passed.
    "scan": (["scan"], {}),
    # Both, and they agreed: the manifest's offsets are confirmed by the target's
    # own mapped bytes. Both source surfaces remain visible, while their exact
    # targets count only once.
    "corroborated": (["scan", "manifest"], {}),
    # The manifest alone, because the target has not mapped the provider yet when
    # the observer attaches — a stopped process released by SIGCONT, a pod that
    # scales up from zero. Nothing was there to confirm it, so it is
    # uncorroborated; that is a stated gap, not a failure.
    "manifest-only": (["manifest"], {"discovery_uncorroborated": 1}),
}


def validate_clean_metrics(
    document, expected, multiplier=1, *, discovery="scan", discovery_skipped=0
):
    """SoftHSM2 counted exactly, with discovery stated rather than assumed."""
    require(discovery in CLEAN_DISCOVERY, f"unknown clean-metrics discovery: {discovery}")
    wanted_sources, allowances = CLEAN_DISCOVERY[discovery]
    require(multiplier >= 1, f"invalid clean-metrics multiplier: {multiplier}")
    require(document["schema"] == "pkcs11-scope/observed-profile/v2-metrics", document["schema"])
    require(document["capture"]["mode"] == "metrics", document["capture"])
    require(document["capture"]["privacy_mode"] == "aggregate-only", document["capture"])
    evidence = document["evidence"]
    surfaces = (
        LEGACY_SURFACES + LEGACY_SURFACES
        if discovery == "corroborated"
        else LEGACY_SURFACES
    )
    exact_shape(evidence, 68, 68, 136, surfaces, 0, "absent")
    exact_common(
        evidence,
        aliases=[],
        skipped=[],
        in_flight=0,
        discovery_skipped=discovery_skipped,
    )
    exact_counters(evidence, allowances)
    sources = [module["sources"] for module in evidence["discovery"]]
    require(sources == [wanted_sources], f"unexpected discovery sources: {sources}")
    corroborated = [module["corroborated"] for module in evidence["discovery"]]
    require(
        corroborated == [discovery == "corroborated"],
        f"unexpected corroboration: {evidence['discovery']}",
    )
    if discovery == "corroborated":
        wanted_surface_sources = Counter(
            ("legacy_function_list", f"{evidence['discovery'][0]['path']} table 2.40")
        )
        surface_sources = Counter(surface["source"] for surface in evidence["surfaces"])
        require(
            surface_sources == wanted_surface_sources,
            f"unexpected corroborated surface sources: {evidence['surfaces']}",
        )
    exact_capture_modules(document)

    actual = Counter()
    for item in document["functions"]:
        calls = item["calls"]
        require(isinstance(calls, int) and calls >= 0, f"invalid call count: {item}")
        require(item["names"], f"function without names: {item}")
        if calls:
            actual.update({name: calls for name in item["names"]})
    wanted = {name: calls * multiplier for name, calls in expected.items()}
    require("C_GetFunctionList" not in wanted, "expected-count file must omit bootstrap")
    wanted["C_GetFunctionList"] = multiplier
    require(dict(actual) == wanted, f"positive function counts: want {wanted}, got {dict(actual)}")


def validate_shared_layer_metrics(document, expected, multiplier=1):
    """Clean metrics plus exactly one bounded shared-overlay uncertainty."""
    validate_clean_metrics(
        document,
        expected,
        multiplier,
        discovery_skipped=1,
    )
    require(
        document["evidence"]["skipped"]
        == [{"name": DISCOVERY_SUBJECT, "reason": SHARED_OVERLAY_UNCERTAINTY}],
        f"unexpected shared-overlay uncertainty: {document['evidence']['skipped']}",
    )


def validate_canary(lane, document):
    """A canary lane: the version-matrix provider, exact in shape and policy.

    The third element of each row is how discovery saw the provider. The canary
    workload maps it before attach, so both sources describe it (`scanned`); the
    freeze lane's workload is released only after attach, so the manifest stands
    alone (`manifest-only`). Nothing else about those lanes differs, and neither
    value is optional: a lane that scanned when it should not have, or failed to
    scan when it should have, fails here.
    """
    lanes = {
        "default-safe-profile": ("safe", "profile", "scanned"),
        "default-safe-trace": ("safe", "trace", "scanned"),
        "feature-safe-profile": ("safe", "profile", "scanned"),
        "feature-safe-trace": ("safe", "trace", "scanned"),
        "feature-unsafe-profile": ("unsafe", "profile", "scanned"),
        "feature-unsafe-trace": ("unsafe", "trace", "scanned"),
        "aggregate-only-metrics": ("aggregate", "metrics", "scanned"),
        "freeze-unsafe-profile": ("unsafe", "profile", "manifest-only"),
    }
    require(lane in lanes, f"unknown canary lane: {lane}")
    policy, kind, discovery = lanes[lane]
    trace = kind == "trace"
    evidence = document if trace else document["evidence"]

    scanned = discovery == "scanned"
    exact_shape(
        evidence, *(VERSION_SHAPE_SCANNED if scanned else VERSION_SHAPE_MANIFEST_ONLY)
    )
    wanted_tables = VERSION_TABLES_SCANNED if scanned else VERSION_TABLES_MANIFEST_ONLY
    require(
        table_signature(evidence) == wanted_tables,
        f"unexpected discovery tables: {evidence['discovery']}",
    )
    exact_common(
        evidence,
        aliases=[],
        skipped=[],
        in_flight=0,
    )
    allowances = dict(
        SAFE_ALLOWANCES if policy == "safe" else UNSAFE_ALLOWANCES if policy == "unsafe" else {}
    )
    allowances["discovery_conflicts" if scanned else "discovery_uncorroborated"] = 1
    exact_counters(evidence, allowances)
    sources = [module["sources"] for module in evidence["discovery"]]
    require(
        sources == ([["scan", "manifest"]] if scanned else [["manifest"]]),
        f"unexpected discovery sources: {sources}",
    )

    privacy = {
        "safe": "allowlisted",
        "unsafe": "unsafe-unvalidated-metadata",
        "aggregate": "aggregate-only",
    }[policy]
    if trace:
        require(evidence["privacy_mode"] == privacy, evidence["privacy_mode"])
        require(evidence["capture_aborted"] is None, evidence["capture_aborted"])
        require(evidence["final_drain"] is False, evidence["final_drain"])
        require(evidence["counters_available"] is True, evidence["counters_available"])
    else:
        schema = (
            "pkcs11-scope/observed-profile/v2-metrics"
            if kind == "metrics"
            else "pkcs11-scope/observed-profile/v2"
        )
        require(document["schema"] == schema, document["schema"])
        require(document["capture"]["mode"] == kind, document["capture"])
        require(document["capture"]["privacy_mode"] == privacy, document["capture"])
        exact_capture_modules(document)
    if policy == "aggregate":
        calls = sum(item["calls"] for item in document["functions"])
        require(calls == 25, f"aggregate calls: want 25, got {calls}")


# Every induced-gap lane holds its workload behind a go-file, so nothing has
# dlopened the provider when the observer attaches and the scan finds nothing in
# scope to corroborate the manifest against. One uncorroborated module each,
# exactly — the gap being induced is never the discovery one.
INDUCED_ALLOWANCES = {"discovery_uncorroborated": 1}


def validate_induced(lane, document):
    require(lane in {"G1", "G2", "G3", "G4", "G5"}, f"unknown induced lane: {lane}")
    require(document["schema"] == "pkcs11-scope/observed-profile/v2", document["schema"])
    require(document["capture"]["mode"] == "profile", document["capture"])
    require(document["capture"]["privacy_mode"] == "allowlisted", document["capture"])
    exact_capture_modules(document)
    evidence = document["evidence"]
    sources = [module["sources"] for module in evidence["discovery"]]
    require(sources == [["manifest"]], f"unexpected discovery sources: {sources}")

    if lane == "G1":
        aliases = [["C_CancelFunction", "C_WaitForSlotEvent"]]
        skipped = [{"name": "C_GetFunctionStatus", "reason": "null pointer"}]
        exact_shape(evidence, 160, 93, 186, G1_SURFACES, 1, "ok")
        exact_common(evidence, aliases=aliases, skipped=skipped, in_flight=0)
        exact_counters(evidence, INDUCED_ALLOWANCES)
    elif lane == "G2":
        groups = evidence["aliased"]
        require(len(groups) == 1, f"G2 aliases: {groups}")
        require(len(groups[0]) == len(set(groups[0])) == 67, f"G2 alias group: {groups}")
        require("C_WaitForSlotEvent" not in groups[0], f"G2 stranded name was aliased: {groups}")
        exact_shape(evidence, 68, 2, 4, LEGACY_SURFACES, 0, "absent")
        exact_common(evidence, aliases=groups, skipped=[], in_flight=1)
        exact_counters(evidence, INDUCED_ALLOWANCES)
    elif lane == "G3":
        exact_shape(evidence, 68, 68, 136, LEGACY_SURFACES, 0, "absent")
        exact_common(evidence, aliases=[], skipped=[], in_flight=0)
        require(evidence["event_loss"] > 0, f"event_loss: {evidence['event_loss']}")
        require(evidence["unmatched_closes"] in (0, 1), evidence["unmatched_closes"])
        actual = Counter()
        for item in document["functions"]:
            if item["calls"]:
                actual.update({name: item["calls"] for name in item["names"]})
        require(dict(actual) == G3_COUNTS, f"G3 function counts: {dict(actual)}")
        exact_counters(
            evidence,
            dict(
                INDUCED_ALLOWANCES,
                event_loss=evidence["event_loss"],
                unmatched_closes=evidence["unmatched_closes"],
            ),
        )
    elif lane == "G4":
        exact_shape(evidence, *VERSION_SHAPE_MANIFEST_ONLY)
        exact_common(evidence, aliases=[], skipped=[], in_flight=9)
        exact_counters(evidence, dict(INDUCED_ALLOWANCES, start_insert_failures=8))
    else:
        exact_shape(evidence, *VERSION_SHAPE_MANIFEST_ONLY)
        exact_common(evidence, aliases=[], skipped=[], in_flight=0)
        exact_counters(
            evidence,
            dict(
                INDUCED_ALLOWANCES,
                rv_update_failures=9,
                unregistered_mechanisms=6,
                async_orphans=1,
            ),
        )
        require(sum(item["calls"] for item in document["functions"]) == 11, document["functions"])


def expected_counts(path):
    counts = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        name, wanted = line.split()
        require(name not in counts, f"duplicate expected function: {name}")
        counts[name] = int(wanted)
    return counts


MODULE_FIXTURE = {
    "path": "/opt/p11.so",
    "dev": [8, 1],
    "ino": 4242,
    "sha256": "11" * 32,
    "build_id": "aabb",
}


def function_items(pairs):
    """`functions[]` items as v2 emits them: every count attributed to a module."""
    identity = {key: MODULE_FIXTURE[key] for key in ("dev", "ino", "sha256")}
    return [
        {
            "names": names,
            "calls": calls,
            "module": identity,
            "module_ambiguous": False,
            "module_unresolved": False,
            "aliased": len(names) > 1,
        }
        for names, calls in pairs
    ]


def discovery_fixture(sources=("scan",)):
    sources = list(sources)
    corroborated = sources == ["scan", "manifest"]
    outcome = (
        "agreed"
        if corroborated
        else "uncorroborated"
        if sources == ["manifest"]
        else "single_source"
    )
    return [
        dict(
            MODULE_FIXTURE,
            objects=[
                dict(
                    MODULE_FIXTURE,
                    identity_source="mountinfo",
                    note=None,
                    sources=sources.copy(),
                )
            ],
            sources=sources,
            corroborated=corroborated,
            corroboration=[outcome],
            tables=[
                {"version": [2, 40], "entries": 68, "source": source}
                for source in sources
            ],
            interfaces=0,
            skipped=[],
        )
    ]


# An object-level scan loss after capture-output subject bounding.
DISCOVERY_SKIP = {
    "name": DISCOVERY_SUBJECT,
    "reason": TABLE_UNAVAILABLE,
}


def loader_discovery_fixture(**overrides):
    """The always-present aggregate, zeroed. Overrides are `group.key=value`
    spellings written as `group__key`, so a fixture states exactly the one
    count it means to exercise."""
    aggregate = {
        group: {key: 0 for key in keys} for group, keys in LOADER_DISCOVERY_GROUPS.items()
    }
    aggregate |= {counter: 0 for counter in LOADER_DISCOVERY_COUNTERS}
    for name, value in overrides.items():
        group, _, key = name.partition("__")
        if key:
            aggregate[group][key] = value
        else:
            aggregate[group] = value
    return aggregate


def evidence_fixture(surfaces, sources=("scan",), discovery_skipped=0):
    return {
        "authority": "hash-pinned",
        "discovery": discovery_fixture(sources),
        "manifest_object_fallbacks": [],
        "modules_skipped": [],
        "scan_unavailable": None,
        "scan_ms": 3,
        "table_entries": 0,
        "slots": 0,
        "attached_probes": 0,
        "attach_failures": [],
        "aliased": [],
        "skipped": [dict(DISCOVERY_SKIP) for _ in range(discovery_skipped)],
        "in_flight_at_end": 0,
        "surfaces": [
            {"walk": walk, "functions": functions, "acquisition": "ok"}
            for (walk, functions), count in surfaces.items()
            for _ in range(count)
        ],
        "vendor_interfaces": 0,
        "interface_list": "absent",
        # Live discovery published nothing: no measured hook gap, no pause
        # authorization, and an all-zero loader aggregate that is still
        # present, because absence of the key is not absence of the fact.
        "attach_gap_ms": None,
        "pause": "none",
        **{name: 0 for name in PAUSE_COUNTERS},
        "loader_discovery": loader_discovery_fixture(),
        **{name: 0 for name in COUNTERS},
        # A fixture is self-consistent: a module only the manifest described is
        # uncorroborated, by definition of the word.
        "discovery_uncorroborated": 1 if list(sources) == ["manifest"] else 0,
        "templates_truncated": False,
        "provider_changed": False,
        "completeness": "PARTIAL",
    }


def document_fixture(evidence, *, schema="pkcs11-scope/observed-profile/v2", mode="profile", privacy="allowlisted"):
    return {
        "schema": schema,
        "capture": {
            "mode": mode,
            "privacy_mode": privacy,
            # v2: one entry per discovered module, projected from the evidence.
            "modules": [
                {key: module[key] for key in ("path", "dev", "ino", "sha256", "build_id")}
                for module in evidence["discovery"]
            ],
        },
        "evidence": evidence,
        "functions": [],
    }


def rejected(action):
    try:
        action()
    except AssertionError:
        return
    raise AssertionError("mutated fixture was accepted")


def self_test():
    clean_evidence = evidence_fixture(LEGACY_SURFACES)
    clean_evidence.update(table_entries=68, slots=68, attached_probes=136)
    clean = document_fixture(
        clean_evidence,
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    clean["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    validate_clean_metrics(clean, {"C_Initialize": 1})
    shared = copy.deepcopy(clean)
    shared["evidence"]["skipped"] = [
        {
            "name": DISCOVERY_SUBJECT,
            "reason": SHARED_OVERLAY_UNCERTAINTY,
        }
    ]
    validate_shared_layer_metrics(shared, {"C_Initialize": 1})
    for mutate in (
        lambda d: d["evidence"].update(skipped=[]),
        lambda d: d["evidence"]["skipped"].append(
            copy.deepcopy(d["evidence"]["skipped"][0])
        ),
        lambda d: d["evidence"]["skipped"][0].update(reason="discovery unavailable"),
        lambda d: d["evidence"].update(event_loss=1),
    ):
        bad = copy.deepcopy(shared)
        mutate(bad)
        rejected(lambda bad=bad: validate_shared_layer_metrics(bad, {"C_Initialize": 1}))
    print("shared-layer metrics permits exactly one bounded overlay uncertainty: OK")
    bad = copy.deepcopy(clean)
    bad["functions"] += function_items([(["C_Unexpected"], 1)])
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("unexpected positive function rejected: OK")
    bad = copy.deepcopy(clean)
    bad["functions"][0]["calls"] = 2
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("bootstrap function exact count required: OK")
    doubled = copy.deepcopy(clean)
    for item in doubled["functions"]:
        item["calls"] *= 2
    validate_clean_metrics(doubled, {"C_Initialize": 1}, 2)
    rejected(lambda: validate_clean_metrics(clean, {"C_Initialize": 1}, 2))
    print("clean metrics multiplier is exact: OK")

    # A lane whose target maps the provider only after attach: the manifest is
    # the sole source and is reported uncorroborated. The scanned expectation
    # must reject it, and the manifest-only expectation must reject a scan.
    manifest_only_evidence = evidence_fixture(LEGACY_SURFACES, sources=("manifest",))
    manifest_only_evidence.update(
        table_entries=68, slots=68, attached_probes=136, discovery_uncorroborated=1
    )
    manifest_only = document_fixture(
        manifest_only_evidence,
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    manifest_only["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    corroborated_evidence = evidence_fixture(
        LEGACY_SURFACES + LEGACY_SURFACES, sources=("scan", "manifest")
    )
    corroborated_evidence["surfaces"][0]["source"] = "/opt/p11.so table 2.40"
    corroborated_evidence["surfaces"][1]["source"] = "legacy_function_list"
    corroborated_evidence.update(table_entries=68, slots=68, attached_probes=136)
    corroborated = document_fixture(
        corroborated_evidence,
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    corroborated["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    documents = {
        "scan": clean,
        "corroborated": corroborated,
        "manifest-only": manifest_only,
    }
    require(
        semantic_join_eligible(
            manifest_only["functions"][0],
            manifest_only["evidence"]["discovery"][0],
            has_manifest_object_fallback=False,
        ),
        "explicit manifest attestation must be eligible",
    )
    require(
        semantic_join_eligible(
            corroborated["functions"][0],
            corroborated["evidence"]["discovery"][0],
            has_manifest_object_fallback=False,
        ),
        "exact agreed scan+manifest must be eligible",
    )
    rejected(
        lambda: require(
            semantic_join_eligible(
                clean["functions"][0],
                clean["evidence"]["discovery"][0],
                has_manifest_object_fallback=False,
            ),
            "scan-only function is not semantic-joinable",
        )
    )
    conflict = copy.deepcopy(corroborated)
    conflict["evidence"]["discovery"][0]["corroboration"] = ["conflict"]
    conflict["evidence"]["discovery_conflicts"] = 1
    exact_capture_modules(conflict)
    rejected(
        lambda: require(
            semantic_join_eligible(
                conflict["functions"][0],
                conflict["evidence"]["discovery"][0],
                has_manifest_object_fallback=False,
            ),
            "conflict function is not semantic-joinable",
        )
    )
    aliased = copy.deepcopy(manifest_only)
    aliased["functions"][0]["aliased"] = True
    rejected(
        lambda: require(
            semantic_join_eligible(
                aliased["functions"][0],
                aliased["evidence"]["discovery"][0],
                has_manifest_object_fallback=False,
            ),
            "aliased function is not semantic-joinable",
        )
    )
    forged_alias = copy.deepcopy(manifest_only)
    forged_alias["functions"][0]["names"].append("C_Alias")
    rejected(lambda: exact_capture_modules(forged_alias))
    unattributed = copy.deepcopy(manifest_only)
    unattributed["functions"][0].update(module=None, module_ambiguous=True)
    rejected(
        lambda: require(
            semantic_join_eligible(
                unattributed["functions"][0],
                unattributed["evidence"]["discovery"][0],
                has_manifest_object_fallback=False,
            ),
            "unattributed function is not semantic-joinable",
        )
    )
    print("semantic join eligibility is exact and conservative: OK")
    for discovery, document in documents.items():
        validate_clean_metrics(document, {"C_Initialize": 1}, discovery=discovery)
        for other in documents:
            if other == discovery:
                continue
            rejected(
                lambda d=document, o=other: validate_clean_metrics(
                    d, {"C_Initialize": 1}, discovery=o
                )
            )
    print("clean metrics discovery source is exact in all three lanes: OK")
    duplicate_manifest_surface = copy.deepcopy(corroborated)
    duplicate_manifest_surface["evidence"]["surfaces"][0]["source"] = (
        "legacy_function_list"
    )
    rejected(
        lambda: validate_clean_metrics(
            duplicate_manifest_surface,
            {"C_Initialize": 1},
            discovery="corroborated",
        )
    )
    print("corroborated clean metrics requires one surface per source: OK")

    proxy = copy.deepcopy(clean)
    soft_path = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    proxy["capture"]["modules"][0]["path"] = soft_path
    proxy["evidence"]["discovery"][0]["path"] = soft_path
    proxy["evidence"]["discovery"][0]["objects"][0]["path"] = soft_path
    proxy_refused = "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.1"
    proxy["evidence"]["modules_skipped"] = [
        {
            "name": proxy_refused,
            "reason": "module needs 5762 more of the 512 attach slots; 0 are in use "
            "— refusing to attach a prefix",
        }
    ]
    # The refused module's decode survives its attach refusal, so the capture
    # keeps its surfaces and counts their entries on top of the attached 68.
    proxy["evidence"]["surfaces"][0]["source"] = f"{soft_path} table 2.40"
    proxy["evidence"]["surfaces"] += [
        {
            "walk": walk,
            "functions": functions,
            "acquisition": "ok",
            "source": f"{proxy_refused} table 3.0",
        }
        for (walk, functions), count in PROXY_REFUSED_SURFACES.items()
        for _ in range(count)
    ]
    proxy["evidence"]["table_entries"] = 68 + PROXY_REFUSED_ENTRIES
    proxy["evidence"]["skipped"] = []
    proxy["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
        + [([f"C_Unused_{index}"], 0) for index in range(66)]
    )
    validate_proxy_capacity_fallback(proxy)
    for mutate in (
        lambda d: d["evidence"]["discovery"][0]["objects"][0].update(
            path="/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.3.1", ino=999
        ),
        lambda d: d["evidence"]["skipped"].append(dict(DISCOVERY_SKIP)),
        lambda d: d["evidence"].update(event_loss=1),
        lambda d: d["evidence"]["modules_skipped"][0].update(reason="capacity"),
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["evidence"].update(completeness="COMPLETE"),
        lambda d: d["evidence"].update(slots=67),
        lambda d: [item.update(calls=0) for item in d["functions"]],
        # The refused module's decode is dropped rather than retained — the
        # shape the frozen oracle demanded, and the one plan:1120-1136 forbids.
        lambda d: d["evidence"].update(
            table_entries=68,
            surfaces=[s for s in d["evidence"]["surfaces"] if s["functions"] == 68],
        ),
        # ... or kept as surfaces but not counted, or miscounted either way.
        lambda d: d["evidence"].update(table_entries=68),
        lambda d: d["evidence"].update(table_entries=68 + PROXY_REFUSED_ENTRIES + 1),
        lambda d: d["evidence"]["surfaces"].pop(),
        # A surface neither module owns is a gap, never an allowance.
        lambda d: d["evidence"]["surfaces"][-1].update(source="/usr/lib/other.so table 3.0"),
    ):
        bad = copy.deepcopy(proxy)
        mutate(bad)
        rejected(lambda bad=bad: validate_proxy_capacity_fallback(bad))
    print("proxy capacity fallback accepts only its exact evidence shape: OK")

    version = evidence_fixture(
        VERSION_SURFACES_SCANNED,
        sources=("scan", "manifest"),
        discovery_skipped=0,
    )
    version["discovery"][0]["tables"] = [
        {"source": source, "version": list(table_version), "entries": entries}
        for (source, table_version, entries), count in VERSION_TABLES_SCANNED.items()
        for _ in range(count)
    ]
    version.update(
        table_entries=988,
        slots=104,
        attached_probes=208,
        vendor_interfaces=1,
        interface_list="ok",
        discovery_conflicts=1,
    )
    version["discovery"][0]["corroboration"] = ["conflict"]
    safe = document_fixture(copy.deepcopy(version))
    safe["evidence"].update(SAFE_ALLOWANCES)
    validate_canary("default-safe-profile", safe)
    bounded_skips = copy.deepcopy(safe["evidence"])
    bounded_skips["skipped"] = [dict(DISCOVERY_SKIP)]
    discovery_skips(bounded_skips)
    for leaked_subject in (
        "/home/operator/private/bystander",
        "pid 4242",
        "/sys/fs/cgroup/user.slice/private.scope",
    ):
        bad = copy.deepcopy(bounded_skips)
        bad["skipped"][0]["name"] = leaked_subject
        rejected(lambda bad=bad: discovery_skips(bad))
    for leaked_reason in (
        "/home/operator/private/bystander",
        "scanning pid 4242: /proc/4242/maps",
        "/sys/fs/cgroup/user.slice/private.scope",
        "arbitrary error-chain text",
    ):
        bad = copy.deepcopy(bounded_skips)
        bad["skipped"][0]["reason"] = leaked_reason
        rejected(lambda bad=bad: discovery_skips(bad))
    print("capture skip names and reasons are bounded before JSON output: OK")
    bad = copy.deepcopy(safe)
    bad["evidence"]["attached_probes"] = 206
    rejected(lambda: validate_canary("default-safe-profile", bad))
    # The same exact target seen in both sources is one table entry. Source
    # provenance still retains all sixteen table records, so changing this to
    # their summed entry total must be rejected.
    bad = copy.deepcopy(safe)
    bad["evidence"]["table_entries"] = 1216
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary matrix 988/104/208 with 16 mixed surfaces: OK")
    # The scan's own contribution is not optional: dropping the three exact
    # source-labelled tables it decoded, or the conflict they imply, must fail.
    bad = copy.deepcopy(safe)
    bad["evidence"]["discovery_conflicts"] = 0
    rejected(lambda: validate_canary("default-safe-profile", bad))
    bad = copy.deepcopy(safe)
    bad["evidence"]["discovery"][0]["tables"] = [
        table
        for table in bad["evidence"]["discovery"][0]["tables"]
        if table["source"] != "scan"
    ]
    rejected(lambda: validate_canary("default-safe-profile", bad))
    bad = copy.deepcopy(safe)
    bad["evidence"]["discovery"][0]["sources"] = ["manifest"]
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary scan contribution is required: OK")

    # The freeze lane: same provider, same policy, manifest alone.
    freeze_evidence = evidence_fixture(VERSION_SURFACES, sources=("manifest",))
    freeze_evidence["discovery"][0]["tables"] = [
        {"source": source, "version": list(table_version), "entries": entries}
        for (source, table_version, entries), count in VERSION_TABLES_MANIFEST_ONLY.items()
        for _ in range(count)
    ]
    freeze_evidence.update(
        table_entries=988,
        slots=104,
        attached_probes=208,
        vendor_interfaces=1,
        interface_list="ok",
        discovery_uncorroborated=1,
        **UNSAFE_ALLOWANCES,
    )
    freeze = document_fixture(freeze_evidence, privacy="unsafe-unvalidated-metadata")
    validate_canary("freeze-unsafe-profile", freeze)
    rejected(lambda: validate_canary("feature-unsafe-profile", freeze))
    rejected(lambda: validate_canary("freeze-unsafe-profile", safe))
    print("canary freeze lane is manifest-only 988/104/208 with 13 surfaces: OK")
    bad = copy.deepcopy(safe)
    bad["evidence"]["unregistered_mechanisms"] = 3
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary safe exact allowances: OK")

    unsafe = document_fixture(copy.deepcopy(version), privacy="unsafe-unvalidated-metadata")
    unsafe["evidence"].update(UNSAFE_ALLOWANCES)
    validate_canary("feature-unsafe-profile", unsafe)
    bad = copy.deepcopy(unsafe)
    bad["evidence"]["shape_decode_failures"] = 1
    rejected(lambda: validate_canary("feature-unsafe-profile", bad))
    print("canary unsafe exact allowances: OK")

    aggregate = document_fixture(
        copy.deepcopy(version),
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    aggregate["functions"] = function_items([(["C_GetInterfaceList"], 25)])
    validate_canary("aggregate-only-metrics", aggregate)
    bad = copy.deepcopy(aggregate)
    bad["functions"][0]["calls"] = 24
    rejected(lambda: validate_canary("aggregate-only-metrics", bad))
    print("canary aggregate exact baseline: OK")

    induced = {}
    g1 = evidence_fixture(G1_SURFACES, sources=("manifest",))
    g1.update(
        table_entries=160,
        slots=93,
        attached_probes=186,
        vendor_interfaces=1,
        interface_list="ok",
        aliased=[["C_CancelFunction", "C_WaitForSlotEvent"]],
        skipped=[{"name": "C_GetFunctionStatus", "reason": "null pointer"}],
    )
    induced["G1"] = document_fixture(g1)
    g2 = evidence_fixture(LEGACY_SURFACES, sources=("manifest",))
    g2.update(
        table_entries=68,
        slots=2,
        attached_probes=4,
        in_flight_at_end=1,
        aliased=[[f"C_Alias_{index}" for index in range(67)]],
    )
    induced["G2"] = document_fixture(g2)
    g3 = evidence_fixture(LEGACY_SURFACES, sources=("manifest",))
    g3.update(
        table_entries=68,
        slots=68,
        attached_probes=136,
        event_loss=1,
        unmatched_closes=1,
    )
    induced["G3"] = document_fixture(g3)
    induced["G3"]["functions"] = function_items(
        [([name], calls) for name, calls in G3_COUNTS.items()]
    )
    g4 = copy.deepcopy(freeze_evidence)
    g4.update(in_flight_at_end=9, start_insert_failures=8, **{k: 0 for k in UNSAFE_ALLOWANCES})
    induced["G4"] = document_fixture(g4)
    g5 = copy.deepcopy(freeze_evidence)
    g5.update(rv_update_failures=9, unregistered_mechanisms=6, async_orphans=1,
              **{k: 0 for k in UNSAFE_ALLOWANCES if k not in ("async_orphans",)})
    induced["G5"] = document_fixture(g5)
    induced["G5"]["functions"] = function_items([(["C_Initialize"], 11)])
    for lane, document in induced.items():
        validate_induced(lane, document)
        bad = copy.deepcopy(document)
        bad["evidence"]["malformed_records"] = 1
        rejected(lambda lane=lane, bad=bad: validate_induced(lane, bad))
        print(f"induced {lane} exact allowances: OK")

    bad = copy.deepcopy(induced["G3"])
    bad["evidence"]["rv_update_failures"] = 1
    rejected(lambda: validate_induced("G3", bad))
    print("induced G3 rejects state-map contamination: OK")

    bad = copy.deepcopy(induced["G3"])
    next(item for item in bad["functions"] if item["names"] == ["C_GenerateRandom"])["calls"] -= 1
    rejected(lambda: validate_induced("G3", bad))
    print("induced G3 exact function counts required: OK")

    bad = copy.deepcopy(induced["G5"])
    bad["functions"][0]["calls"] = 12
    rejected(lambda: validate_induced("G5", bad))
    print("induced G5 exact 11 calls and 9 RV failures: OK")

    bad = copy.deepcopy(safe)
    bad["evidence"]["operation_state_imports"] = 1
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("unrelated evidence gap rejected: OK")

    terminal_capture_is_clean(copy.deepcopy(clean["evidence"]))
    for field, value in (
        ("completeness", "COMPLETE"),
        ("event_loss", 1),
        ("in_flight_at_end", 1),
        ("aliased", ["C_Sign"]),
        ("semantic_state_drops", 1),
        ("rv_update_failures", 1),
    ):
        bad = copy.deepcopy(clean["evidence"])
        bad[field] = value
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    # The documented informational counters are not gaps: a lane attaching mid
    # execution must still read as clean.
    for field in sorted(INFORMATIONAL_COUNTERS):
        tolerated = copy.deepcopy(clean["evidence"])
        tolerated[field] = 7
        terminal_capture_is_clean(tolerated)
    # An expected uncorroborated manifest is exact in both directions: the lane
    # that expects one must get one, and the lane that expects none must not.
    terminal_capture_is_clean(
        copy.deepcopy(manifest_only["evidence"]), uncorroborated=1
    )
    rejected(lambda: terminal_capture_is_clean(copy.deepcopy(manifest_only["evidence"])))
    rejected(
        lambda: terminal_capture_is_clean(
            copy.deepcopy(clean["evidence"]), uncorroborated=1
        )
    )
    print("terminal capture predicate is PARTIAL with no concrete gap: OK")

    # v2 discovery oracles. A document that discovered nothing, was authorized
    # by something else, refused a module, or names a provider its evidence does
    # not, is never a clean capture.
    for field, value in (
        ("discovery", []),
        ("authority", "manifest"),
        ("modules_skipped", [{"name": "/opt/x.so", "reason": "capacity"}]),
        ("scan_unavailable", "ptrace"),
        ("discovery_conflicts", 1),
        ("discovery_uncorroborated", 1),
        ("module_ambiguous", 1),
    ):
        bad = copy.deepcopy(clean["evidence"])
        bad[field] = value
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    for digest in ("", None):
        bad = copy.deepcopy(clean["evidence"])
        bad["discovery"][0]["sha256"] = digest
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    print("discovery evidence is required and gap-free: OK")

    fallback = copy.deepcopy(clean)
    replacement = {
        key: fallback["evidence"]["discovery"][0][key]
        for key in ("dev", "ino", "sha256")
    }
    fallback["evidence"]["manifest_object_fallbacks"] = [
        {
            "manifest": 0,
            "object": 0,
            "reason": "open_stale",
            "replacement": replacement,
        }
    ]
    fallback["evidence"]["discovery"][0]["corroboration"] = ["object_fallback"]
    fallback["evidence"]["discovery_uncorroborated"] = 1
    terminal_capture_is_clean(fallback["evidence"], uncorroborated=1)
    exact_capture_modules(fallback)

    # A stale dependency fallback has no public module/function relation. The
    # remaining module can still read as agreed, but v2 must not infer that its
    # other functions inherited manifest attestation from the dropped dependency.
    stale_dependency = copy.deepcopy(corroborated)
    stale_dependency["evidence"]["manifest_object_fallbacks"] = [
        {
            "manifest": 0,
            "object": 1,
            "reason": "open_stale",
            "replacement": replacement,
        }
    ]
    stale_dependency["evidence"]["discovery_uncorroborated"] = 1
    exact_capture_modules(stale_dependency)
    require(
        not semantic_join_eligible(
            stale_dependency["functions"][0],
            stale_dependency["evidence"]["discovery"][0],
            has_manifest_object_fallback=True,
        ),
        "any public fallback makes v2 semantic joins ineligible",
    )
    print("public fallback blocks every v2 semantic join: OK")
    for mutate in (
        lambda d: d["evidence"]["manifest_object_fallbacks"][0].update(reason="/private/path"),
        lambda d: d["evidence"]["manifest_object_fallbacks"][0]["replacement"].update(ino=999),
        lambda d: d["evidence"].update(discovery_uncorroborated=0),
        lambda d: d["evidence"]["manifest_object_fallbacks"][0].update(path="/private/p11.so"),
    ):
        bad = copy.deepcopy(fallback)
        mutate(bad)
        rejected(lambda bad=bad: exact_capture_modules(bad))

    bogus_source = copy.deepcopy(fallback)
    bogus_source["evidence"]["discovery"][0]["sources"] = ["scan", "bogus"]
    rejected(lambda: exact_capture_modules(bogus_source))

    semantic_mutations = []
    bad = copy.deepcopy(clean)
    bad["evidence"]["discovery"][0]["tables"][0]["source"] = "bogus"
    semantic_mutations.append(("unknown table source", bad))
    bad = copy.deepcopy(clean)
    bad["evidence"]["discovery"][0]["corroboration"] = ["bogus"]
    semantic_mutations.append(("unknown corroboration", bad))
    bad = copy.deepcopy(manifest_only)
    bad["evidence"]["discovery"][0]["corroboration"] = ["single_source"]
    semantic_mutations.append(("manifest-only single-source outcome", bad))
    bad = copy.deepcopy(corroborated)
    bad["evidence"]["discovery"][0].update(
        corroborated=False, corroboration=["agreed"]
    )
    bad["evidence"]["discovery_uncorroborated"] = 1
    semantic_mutations.append(("agreed marked uncorroborated", bad))
    bad = copy.deepcopy(corroborated)
    bad["evidence"]["discovery"][0].update(
        corroborated=False, corroboration=["conflict"]
    )
    bad["evidence"]["discovery_conflicts"] = 1
    bad["evidence"]["discovery_uncorroborated"] = 1
    semantic_mutations.append(("conflict marked uncorroborated", bad))
    bad = copy.deepcopy(clean)
    bad["evidence"]["discovery"][0]["corroborated"] = True
    semantic_mutations.append(("corroborated without a comparable outcome", bad))
    bad = copy.deepcopy(corroborated)
    bad["evidence"]["discovery"][0]["corroboration"] = ["conflict"]
    bad["evidence"]["discovery_conflicts"] = 0
    semantic_mutations.append(("conflict counter mismatch", bad))
    bad = copy.deepcopy(clean)
    bad["evidence"]["completeness"] = "COMPLETE"
    semantic_mutations.append(("scan-only complete", bad))
    bad = copy.deepcopy(clean)
    bad["evidence"]["discovery"][0]["objects"][0]["sources"] = ["bogus"]
    semantic_mutations.append(("unknown object source", bad))
    bad = copy.deepcopy(clean)
    bad["evidence"]["discovery"][0]["corroboration"] = ["object_fallback"]
    semantic_mutations.append(("object fallback without evidence", bad))
    for label, bad in semantic_mutations:
        rejected(lambda bad=bad: exact_capture_modules(bad))
    print("semantic source/corroboration mutations are rejected: OK")

    non_hex = copy.deepcopy(fallback)
    bad_digest = "g" * 64
    non_hex["evidence"]["discovery"][0]["sha256"] = bad_digest
    non_hex["capture"]["modules"][0]["sha256"] = bad_digest
    non_hex["evidence"]["manifest_object_fallbacks"][0]["replacement"]["sha256"] = bad_digest
    for function in non_hex["functions"]:
        function["module"]["sha256"] = bad_digest
    rejected(lambda: exact_capture_modules(non_hex))

    out_of_range = copy.deepcopy(fallback)
    bad_device = [1 << 64, 1]
    out_of_range["evidence"]["discovery"][0]["dev"] = bad_device
    out_of_range["capture"]["modules"][0]["dev"] = bad_device
    out_of_range["evidence"]["manifest_object_fallbacks"][0]["replacement"]["dev"] = bad_device
    for function in out_of_range["functions"]:
        function["module"]["dev"] = bad_device
    rejected(lambda: exact_capture_modules(out_of_range))

    inherited_object_source = copy.deepcopy(fallback)
    nested = inherited_object_source["evidence"]["discovery"][0]["objects"][0]
    nested.update(dev=[8, 2], ino=12, sha256="22" * 32, sources=["manifest"])
    inherited_object_source["evidence"]["manifest_object_fallbacks"][0]["replacement"] = {
        key: nested[key] for key in ("dev", "ino", "sha256")
    }
    rejected(lambda: exact_capture_modules(inherited_object_source))

    hidden_sole_source = copy.deepcopy(fallback)
    second = copy.deepcopy(
        hidden_sole_source["evidence"]["manifest_object_fallbacks"][0]
    )
    second["manifest"] = 1
    second["object"] = 1
    hidden_sole_source["evidence"]["manifest_object_fallbacks"].append(second)
    hidden_sole_source["evidence"]["discovery_uncorroborated"] = 2
    rejected(lambda: exact_capture_modules(hidden_sole_source))
    print("manifest fallback is per object, scan-owned, bounded, and path-free: OK")

    exact_capture_modules(clean)
    for mutate in (
        lambda d: d["capture"]["modules"].clear(),
        lambda d: d["capture"]["modules"][0].update(sha256="00"),
        lambda d: d["capture"]["modules"][0].update(ino=0),
        lambda d: d["capture"]["modules"][0].update(path="/opt/other.so"),
        lambda d: d["evidence"]["discovery"].append(copy.deepcopy(MODULE_FIXTURE)),
    ):
        bad = copy.deepcopy(clean)
        mutate(bad)
        rejected(lambda bad=bad: exact_capture_modules(bad))
    print("capture.modules[] matches the discovery record exactly: OK")

    # Per-function attribution: to a module the document declares, or to nobody
    # with the reason stated. Nothing in between.
    for mutate in (
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["functions"][0].update(module=None, module_ambiguous=False),
        lambda d: d["functions"][0].update(module_ambiguous=True),
        lambda d: d["functions"][0]["module"].update(sha256=None),
    ):
        bad = copy.deepcopy(clean)
        mutate(bad)
        rejected(lambda bad=bad: exact_capture_modules(bad))
    unattributed = copy.deepcopy(clean)
    unattributed["functions"][0].update(module=None, module_ambiguous=True)
    exact_capture_modules(unattributed)
    unowned = copy.deepcopy(clean)
    unowned["functions"][0].update(
        module=None, module_ambiguous=False, module_unresolved=True
    )
    exact_capture_modules(unowned)
    print("every count is attributed to a declared module or to nobody: OK")

    # ---- slice 1b-2 live-discovery evidence -----------------------------
    # Positive control first: the exact published shape is accepted, so every
    # rejection below is the mutation being caught and not a broken fixture.
    live = copy.deepcopy(clean)
    live["evidence"].update(
        attach_gap_ms=7,
        pause="partial",
        pause_attempts=2,
        pause_confirmed=1,
        pause_partial=1,
        # Two exact bound contexts: one ordinary `dlopen` and the owned run's
        # one pre-exec initial-set context. Each is counted once as a strategy
        # and once in its own timing group, and the initial-set one also states
        # its capture outcome — the cardinality a real aggregate always obeys.
        loader_discovery=loader_discovery_fixture(
            strategies__debug_state_every_hit=2,
            dlopen_timing__unproven=1,
            initial_set_timing__unproven=1,
            initial_set_capture__none=1,
            hits=4,
            state_read_failures=0,
        ),
    )
    exact_live_discovery_evidence(live["evidence"])
    exact_capture_modules(live)
    print("live discovery evidence positive control: OK")

    for mutate in (
        # The aggregate is closed: no key may go missing, and no key may be
        # added — an injected identity can only arrive as one of the two.
        lambda d: d["evidence"]["loader_discovery"].pop("hits"),
        lambda d: d["evidence"]["loader_discovery"].pop("state_read_failures"),
        lambda d: d["evidence"]["loader_discovery"]["strategies"].pop("unavailable"),
        lambda d: d["evidence"]["loader_discovery"]["dlopen_timing"].pop("none"),
        lambda d: d["evidence"]["loader_discovery"]["initial_set_capture"].pop("eligible"),
        lambda d: d["evidence"].pop("loader_discovery"),
        # Raw loader/pause process identity, in every new location.
        lambda d: d["evidence"]["loader_discovery"].update(pid=4242),
        lambda d: d["evidence"]["loader_discovery"].update(tid=4243),
        lambda d: d["evidence"]["loader_discovery"].update(tasks=[4242, 4243]),
        lambda d: d["evidence"]["loader_discovery"]["strategies"].update(pid=4242),
        lambda d: d["evidence"]["loader_discovery"]["dlopen_timing"].update(tid=4243),
        lambda d: d["evidence"]["loader_discovery"]["initial_set_timing"].update(
            tasks=[4242]
        ),
        lambda d: d["evidence"]["loader_discovery"]["initial_set_capture"].update(
            pid_tgid=18229209370626
        ),
        lambda d: d["evidence"].update(pause_pid=4242),
        lambda d: d["evidence"].update(pause_tasks=[4242, 4243]),
        # Loader/libc identity and proof.
        lambda d: d["evidence"]["loader_discovery"].update(
            loader="/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
        ),
        lambda d: d["evidence"]["loader_discovery"].update(libc_sha256="ab" * 32),
        lambda d: d["evidence"]["loader_discovery"].update(build_id="aabbccdd"),
        lambda d: d["evidence"]["loader_discovery"].update(proof_id=7),
        # Addresses, pointers, cookies, contexts, deltas, sentinels, markers,
        # signal records, interface bytes, and observer-owned map values.
        lambda d: d["evidence"]["loader_discovery"].update(r_debug_vaddr=0x7FFFF7FFE180),
        lambda d: d["evidence"]["loader_discovery"].update(hook_ip=0x7FFFF7FE1B00),
        lambda d: d["evidence"]["loader_discovery"].update(attach_cookie=512),
        lambda d: d["evidence"]["loader_discovery"].update(context_id=1),
        lambda d: d["evidence"]["loader_discovery"].update(delta=-4096),
        lambda d: d["evidence"]["loader_discovery"].update(absent_state_sentinel=512),
        lambda d: d["evidence"]["loader_discovery"].update(marker=0xDEADBEEF),
        lambda d: d["evidence"]["loader_discovery"].update(
            signal_record={"signal": 19, "pid": 4242}
        ),
        lambda d: d["evidence"]["loader_discovery"].update(interface_name="PKCS 11"),
        lambda d: d["evidence"]["loader_discovery"].update(
            pause_pids={"4242": 1}
        ),
        # Counts are counts: not strings, not booleans, not negative, not
        # floats, and never a second derived copy of an internal counter.
        lambda d: d["evidence"]["loader_discovery"].update(hits="4"),
        lambda d: d["evidence"]["loader_discovery"].update(hits=True),
        lambda d: d["evidence"]["loader_discovery"].update(hits=-1),
        lambda d: d["evidence"]["loader_discovery"].update(state_read_failures=1.5),
        lambda d: d["evidence"]["loader_discovery"]["strategies"].update(
            debug_state_every_hit=None
        ),
        # The pause lattice is derived, not labelled.
        lambda d: d["evidence"].update(pause="sigstop"),
        lambda d: d["evidence"].update(pause="stopped"),
        lambda d: d["evidence"].update(pause_confirmed=2),
        lambda d: d["evidence"].update(pause_attempts=0, pause="none"),
        lambda d: d["evidence"].update(pause_partial=-1),
        # A gap is a measurement or a null; never an invented zero-by-string.
        lambda d: d["evidence"].update(attach_gap_ms="7"),
        lambda d: d["evidence"].update(attach_gap_ms=-1),
        # The run-only field never appears in an ordinary capture.
        lambda d: d["evidence"].update(child_still_running=False),
        # Aggregate cardinalities: the strategy, timing, and initial-set groups
        # are one partition of the same exact bound-context set, so a count that
        # appears in one group and in no other is a fabricated context.
        lambda d: d["evidence"]["loader_discovery"]["strategies"].update(unavailable=1),
        lambda d: d["evidence"]["loader_discovery"]["dlopen_timing"].update(none=1),
        lambda d: d["evidence"]["loader_discovery"]["initial_set_capture"].update(none=2),
        # An owned run owns one child, so it has one initial-set context.
        lambda d: d["evidence"]["loader_discovery"].update(
            strategies={"debug_state_every_hit": 3, "dlopen_return": 0, "unavailable": 0},
            initial_set_timing={
                "qualified_pre_constructor": 0, "known_pre_relocation": 0,
                "unproven": 2, "none": 0,
            },
            initial_set_capture={"eligible": 0, "none": 2},
        ),
    ):
        bad = copy.deepcopy(live)
        mutate(bad)
        rejected(lambda bad=bad: exact_live_discovery_evidence(bad["evidence"]))
    print("loader/pause evidence rejects every injected identity and non-count: OK")

    run_document = copy.deepcopy(live)
    run_document["evidence"]["child_still_running"] = True
    exact_live_discovery_evidence(run_document["evidence"], run=True)
    for mutate in (
        lambda d: d["evidence"].pop("child_still_running"),
        lambda d: d["evidence"].update(child_still_running="yes"),
        lambda d: d["evidence"].update(child_still_running=4242),
    ):
        bad = copy.deepcopy(run_document)
        mutate(bad)
        rejected(
            lambda bad=bad: exact_live_discovery_evidence(bad["evidence"], run=True)
        )
    print("child_still_running is a run-only boolean: OK")

    # ---- module ownership relation --------------------------------------
    ownership = copy.deepcopy(live)
    ownership["evidence"]["completeness"] = "PARTIAL"
    ownership["functions"] = function_items([(["C_Sign"], 3)])
    exact_module_ownership(ownership)
    unresolved = copy.deepcopy(ownership)
    unresolved["functions"][0].update(module=None, module_unresolved=True)
    exact_module_ownership(unresolved)
    for mutate in (
        # No owner and no reason: the one shape the relation forbids.
        lambda d: d["functions"][0].update(
            module=None, module_ambiguous=False, module_unresolved=False
        ),
        # Unresolved is not two-module ambiguity, and never both.
        lambda d: d["functions"][0].update(
            module=None, module_ambiguous=True, module_unresolved=True
        ),
        # An owner cannot also be unowned.
        lambda d: d["functions"][0].update(module_unresolved=True),
        lambda d: d["functions"][0].update(module_ambiguous=True),
        lambda d: d["functions"][0].update(module_unresolved="yes"),
        lambda d: d["functions"][0].pop("module_unresolved"),
        # The row that publishes the owner relation publishes nothing else from
        # the loader/pause namespace: no internal owner key, process identity,
        # or loader identity beside the finite boolean.
        lambda d: d["functions"][0].update(loader_context=3),
        lambda d: d["functions"][0].update(owner_pid=4242),
        lambda d: d["functions"][0].update(pause_tasks=[4242, 4243]),
        lambda d: d["functions"][0]["module"].update(loader_path="/lib/ld.so"),
    ):
        bad = copy.deepcopy(ownership)
        mutate(bad)
        rejected(lambda bad=bad: exact_module_ownership(bad))
    complete_but_unresolved = copy.deepcopy(unresolved)
    complete_but_unresolved["evidence"]["completeness"] = "COMPLETE"
    rejected(lambda: exact_module_ownership(complete_but_unresolved))
    print("module ownership is an exact exclusive relation and unresolved is PARTIAL: OK")

    # ---- active-to-empty lifecycle --------------------------------------
    # The target exited normally: links, pins and views are gone, and every
    # capture-lifetime fact is still reported.
    exited = copy.deepcopy(live)
    exited["evidence"].update(table_entries=68, slots=68, attached_probes=136)
    exact_active_to_empty(exited)
    for mutate in (
        lambda d: d["evidence"]["discovery"].clear(),
        lambda d: d["capture"]["modules"].clear(),
        lambda d: d["evidence"]["surfaces"].clear(),
        lambda d: d["evidence"].update(table_entries=0),
        lambda d: d["evidence"].update(slots=0),
        lambda d: d["evidence"].update(attached_probes=0),
        lambda d: d["evidence"].update(discovery_truncated=1),
        lambda d: d["evidence"].update(discovery_ring_loss=1),
        lambda d: d["evidence"].update(state_reconciliations=1),
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["functions"][0].update(
            module=None, module_ambiguous=False, module_unresolved=False
        ),
    ):
        bad = copy.deepcopy(exited)
        mutate(bad)
        rejected(lambda bad=bad: exact_active_to_empty(bad))
    print("active-to-empty keeps its history and declares every owner: OK")
    print("self-test: OK")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return
    require(len(argv) >= 1, "usage: check-capture-evidence.py MODE ...")
    if argv[0] == "shared-layer-metrics" and len(argv) in (3, 4):
        multiplier = int(argv[3]) if len(argv) == 4 else 1
        validate_shared_layer_metrics(
            load_json(argv[1]),
            expected_counts(argv[2]),
            multiplier,
        )
    elif argv[0].startswith("clean-metrics") and len(argv) in (3, 4):
        discovery = argv[0][len("clean-metrics") :].lstrip("-") or "scan"
        multiplier = int(argv[3]) if len(argv) == 4 else 1
        validate_clean_metrics(
            load_json(argv[1]),
            expected_counts(argv[2]),
            multiplier,
            discovery=discovery,
        )
    elif argv[0] == "canary" and len(argv) == 3:
        trace = argv[1].endswith("-trace")
        validate_canary(argv[1], load_canary(argv[2], trace))
    elif argv[0] == "induced" and len(argv) == 3:
        validate_induced(argv[1], load_json(argv[2]))
    else:
        raise AssertionError(
            "usage: check-capture-evidence.py "
            "clean-metrics[-corroborated|-manifest-only] OUTPUT EXPECTED [MULTIPLIER] | "
            "shared-layer-metrics OUTPUT EXPECTED [MULTIPLIER] | "
            "canary LANE OUTPUT | induced G[1-5] OUTPUT | --self-test"
        )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        print(f"capture evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
