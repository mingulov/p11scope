#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact evidence oracles shared by the canonical live capture lanes."""

import copy
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path


COUNTERS = (
    "event_loss",
    "start_insert_failures",
    "unmatched_returns",
    "rv_update_failures",
    "cgroup_scope_failures",
    "abi_refusals",
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
    "semantic_history_drops",
    "pending_at_end",
    "malformed_records",
    "orphan_ops",
    "unmatched_closes",
    "shape_decode_failures",
    "shape_decode_total_failures",
    # Discovery gaps (schema v3). Every one of them forces PARTIAL. None of them
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
    "task_uprobe_link_losses",
)

# v2-metrics is retained only for historical fixtures and compatibility reads;
# it predates the task-uprobe link-loss, ABI-refusal, and semantic-history-drop
# evidence added to v3.
HISTORICAL_METRICS_SCHEMA = "p11scope/observed-profile/v2-metrics"
HISTORICAL_COUNTERS = tuple(
    counter for counter in COUNTERS
    if counter not in {"abi_refusals", "task_uprobe_link_losses", "semantic_history_drops"}
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
# Consumer-scheduling evidence (Task 3.1 repair): one nested object, closed
# keys, exact loss-split identities. The terminal drain bound is a source
# constant (events.rs TERMINAL_DRAIN_BOUND); pinning its value here forces
# the oracle and the producer to change together.
SCHEDULING_SINK_POLICY = "bounded-wait-drop"
SCHEDULING_TERMINAL_DRAIN_BOUND = 65536
SCHEDULING_U64_KEYS = (
    "drain_repolls",
    "drain_budget_exhaustions",
    "capture_event_loss",
    "detach_event_loss",
    "capture_discovery_loss",
    "detach_discovery_loss",
    "terminal_drain_bound",
    "sink_stall_ms",
    "sink_timeouts",
    "sink_dropped_bytes",
    "max_inter_drain_gap_ms",
)
SCHEDULING_KEYS = set(SCHEDULING_U64_KEYS) | {
    "terminal_drain_truncated", "sink_policy", "phase_ms",
    "phase_mono_ns",
}
SCHEDULING_PHASE_KEYS = ("discovery", "discovery_terminal", "drain",
                           "maps", "render", "detach")
# Authoritative observer phase stamps (T2, G-14): CLOCK_MONOTONIC ns or
# null when the phase was never reached, plus a closed loop-end reason.
SCHEDULING_PHASE_TS_KEYS = ("attach_mono_ns", "loop_start_mono_ns",
                            "loop_end_mono_ns", "loop_end_reason")
SCHEDULING_LOOP_END_REASONS = {"expiry", "operator_stop", "target_exit",
                               "limit_reached", "error", "unstarted"}
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
U32_MAX = (1 << 32) - 1
U16_MAX = (1 << 16) - 1
PROFILE_SCHEMA = "p11scope/observed-profile/v3"
METRICS_SCHEMA = "p11scope/observed-profile/v3-metrics"
# SYSPLAN residual F-02: the terminal verdict split. `drain_proven` is the
# settlement latch (a future COMPLETE requires it set); `verdict_detail`
# says which terminal story `completeness` tells.
VERDICT_DETAILS = {"clean_proven", "clean_but_unproven", "concrete_gap"}
# SYSPLAN residual F-01: the only override flag durable evidence may name.
URETPROBE_OVERRIDE_FLAG = "--allow-uretprobe-on-confined-target"
# SYSPLAN residual F-26: capture-visible environment switches.
P11SCOPE_ENV_VARS = {"P11SCOPE_BROAD_ADMIT", "P11SCOPE_LOADER_ENV_SANITIZED"}
# SYSPLAN residual F-12: machine-readable lane discriminators.
PROFILE_LANE = "profile"
METRICS_LANE = "metrics"
SELECTION_KEYS = {
    "providers", "standard_exports", "inventory_surfaces", "tuples",
    "selection_truncated",
}
SELECTION_NAME_CLASSES = {"null", "exact_standard", "other", "unreadable"}
SELECTION_VERSION_CLASSES = {
    "null", "unreadable", "v2_40", "v3_0", "v3_1", "v3_2", "other",
}
SELECTION_AUTHORITIES = {"inventory", "selection_count_only", "none"}
SELECTION_COVERAGE = {
    "observed", "observed_uncovered", "absent_covered", "absent_uncovered",
}
STANDARD_EXPORT_STATUS = {
    "present", "outside_module", "legacy_absent", "required_absent", "unresolved",
}
ATTACH_MECHANISMS = {"per-offset", "uprobe-multi"}
PROFILE_V3_FIELDS = {
    "interface_selection", "attach_mechanisms", "pid_descendant_gaps",
    "multi_rebuild_gaps",
}
RESIDUAL_EVIDENCE_KEYS = {
    # F-02: settlement latch + terminal verdict detail.
    "drain_proven", "verdict_detail",
    # F-01: durable uretprobe/hazard override (flag + reason), null when clean.
    "uretprobe_override",
    # F-15: handed-back orphan PID, null unless the run lane left it alive.
    "handoff_child_pid",
    # F-26: active values of every capture-visible P11SCOPE_* switch.
    "p11scope_env",
}
# Native kernel control state (OWNER_CTL / COOKIE_CTL / ROOT_CTL), read at
# every snapshot. Finite reason names and counters only; any gap forces PARTIAL.
KERNEL_CONTROL_KEYS = {
    "capture_halted", "owner_poison", "owner_admission_failures",
    "identity_unavailable", "identity_budget_exhausted",
    "root_affiliation_failures",
}
OWNER_POISON_REASONS = {
    "bad_control", "lookup_unknown", "bad_record", "delete_failed",
    "bookkeeping_failed", "refund_failed", "classifier_failed",
    "state_delete_failed", "unknown",
}
ROOT_FAILURE_REASONS = {
    "bad_control", "capacity", "reserve_contention", "create_failed",
    "existing_child", "bad_cell", "exit_classifier", "exit_delete",
    "refund_failed", "unknown",
}
# C_GetInterface result flags publish only this finite class, never the word.
SELECTION_RESULT_FLAG_CLASSES = {"zero", "fork_safe", "other"}
BASE_EVIDENCE_KEYS = set(COUNTERS) | {
    "kernel_control",
    "authority", "discovery", "manifest_object_fallbacks", "modules_skipped",
    "scan_unavailable", "scan_ms", "table_entries", "slots", "active_slots",
    "attached_probes",
    "attach_failures", "aliased", "skipped", "in_flight_at_end", "surfaces",
    "vendor_interfaces", "interface_list", "attach_gap_ms", "pause",
    *PAUSE_COUNTERS, "loader_discovery", "templates_truncated", "provider_changed",
    "scheduling",
    "completeness",
    *RESIDUAL_EVIDENCE_KEYS,
    # Informational, not a COUNTER: spilling heuristic lookalikes past the
    # per-object cap is correct admission, not a coverage gap, so it never
    # forces PARTIAL and needs no lane allowance or mutation.
    "discovery_uncorroborated_candidates",
}
TRACE_TERMINAL_KEYS = {
    "privacy_mode", "capture_aborted", "final_drain", "counters_available",
    "trace_truncated",
}

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
# sources describe it. LP64 scans three file-backed tables and reports one
# conflict; ILP32 also scans the 3.1 and 3.2 tables and agrees with the manifest.
# Tables built at run time in .bss are not object-level scan failures. Every
# scanned table remains an exact per-source record.
#
# What the union does *not* change is the attach plan: 104 slots and 208 probes,
# exactly as before, because a slot is one {object, file offset} however many
# sources named it. `surfaces` keeps the per-source records, so the scan adds
# three LP64 surfaces (13 -> 16) or five ILP32 surfaces (13 -> 18).
# `table_entries` counts exact target occurrences across sources, so neither
# scan subset changes the 988-entry union.
VERSION_SURFACES_SCANNED = VERSION_SURFACES + Counter(
    {("full", 68): 2, ("full", 92): 1}
)
VERSION_SURFACES_SCANNED_IA32 = VERSION_SURFACES_SCANNED + Counter(
    {("full", 92): 1, ("full", 104): 1}
)
VERSION_SHAPE_MANIFEST_ONLY = (988, 104, 208, VERSION_SURFACES, 1, "ok")
VERSION_SHAPE_SCANNED = (988, 104, 208, VERSION_SURFACES_SCANNED, 1, "ok")
VERSION_SHAPE_SCANNED_IA32 = (
    988,
    104,
    208,
    VERSION_SURFACES_SCANNED_IA32,
    1,
    "ok",
)
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
VERSION_TABLES_SCANNED_IA32 = VERSION_TABLES_SCANNED + Counter(
    {("scan", (3, 1), 92): 1, ("scan", (3, 2), 104): 1}
)
DISCOVERY_SUBJECT = "discovery subject"
DISCOVERY_UNAVAILABLE = "discovery unavailable"
ENTRY_UNAVAILABLE = "function entry unavailable"
TABLE_UNAVAILABLE = "function table unavailable in file-backed data"
SHARED_OVERLAY_UNCERTAINTY = (
    "shared-overlay physical identity is uncertain; a distinct byte-identical "
    "instance may be unobserved"
)
# Audit F-13: render.rs `capture_skipped_out` emits this sixth reason when
# equal mapping keys carry unequal or unavailable full opened-file
# identities. It is a discovery-scope loss (subject `discovery subject`),
# not an entry loss; the validator must accept what the producer emits.
PHYSICAL_IDENTITY_AMBIGUITY = (
    "physical identity is ambiguous; the collision group was not attached"
)
# SYSPLAN residual F-14: render.rs `capture_skipped_out` emits this seventh
# reason when the memory scan refuses a future-minor table at the
# `spans_for` gate. Fixed string, never with version numbers attached.
UNSUPPORTED_TABLE_VERSION = (
    "unsupported function-table version; the scanner does not walk this layout"
)
DISCOVERY_REASONS = {
    DISCOVERY_UNAVAILABLE,
    TABLE_UNAVAILABLE,
    SHARED_OVERLAY_UNCERTAINTY,
    PHYSICAL_IDENTITY_AMBIGUITY,
    UNSUPPORTED_TABLE_VERSION,
}
ENTRY_REASONS = {"null pointer", ENTRY_UNAVAILABLE}
# The one gated entry-like skip whose subject is not a standard function: a
# null slot in an unlinked table, renamed `unknown` by the mislabel guard
# (render.rs `capture_skipped_out` gated_null branch). Entry-granularity, so
# it joins `entry_skips` as a lane-oracle item — never `discovery_skips`.
UNKNOWN_NULL_SKIP = {"name": "unknown", "reason": "null pointer"}
# Both walks publish the provider's two tables, so every walked surface is
# doubled; the unwalked one is a single scan-side record.
G1_SURFACES = Counter({("full", 68): 2, ("full", 92): 2, ("not_walked", 0): 1})
LEGACY_SURFACES = Counter({("full", 68): 1})
# `p11scope_ebpf_common::MAX_SLOTS` (src/discovery/scan.rs, plan:83): the frozen
# attach ceiling a whole-module capacity refusal is taken against.
MAX_SLOTS = 512
# What the installed libp11-kit really maps (verified byte-level on the lane
# host, Task 1.4): 64 static CK_FUNCTION_LIST_3_2 closure templates, 104
# entries each, ordinals 65/66 shared by all 64 (64*102+2 = 6530 distinct
# targets). The K=4 per-object heuristic cap admits 4 tables (any 4 share
# exactly the 2 family targets: 4*102+2 = 410 distinct, 0 nulls); the other
# 60 spill as `discovery_uncorroborated_candidates` — evidence, never slots.
#
# Admitted p11-kit template families (audit F8): the 3.x (version, entries)
# combinations the version matrix declares — 92-entry 3.0/3.1, 104-entry
# 3.2 — each with the distinct targets K=4 admits from 4 tables sharing the
# 2 family targets (4*(entries-2)+2). The lane qualifies whichever build is
# installed instead of pinning one provider version; every table in one
# capture must still share exactly one shape.
ADMITTED_PROXY_TABLE_SHAPES = {
    (3, 0): {"entries": 92, "admitted_slots": 362},
    (3, 1): {"entries": 92, "admitted_slots": 362},
    (3, 2): {"entries": 104, "admitted_slots": 410},
}
PROXY_TABLES = 64
# The installed build's shape, which the self-test fixture pins exactly.
PROXY_TABLE_ENTRIES = ADMITTED_PROXY_TABLE_SHAPES[(3, 2)]["entries"]
PROXY_ADMITTED_TABLES = 4
PROXY_ADMITTED_SLOTS = ADMITTED_PROXY_TABLE_SHAPES[(3, 2)]["admitted_slots"]
PROXY_SPILL = PROXY_TABLES - PROXY_ADMITTED_TABLES
PROXY_DECODED_ENTRIES = PROXY_TABLES * PROXY_TABLE_ENTRIES

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


def build_id_ok(value):
    return value is None or (
        isinstance(value, str)
        and len(value) > 0
        and len(value) % 2 == 0
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


def u64(value, *, positive=False):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= U64_MAX
    )


def exact_active_slots_bound(evidence):
    """active_slots is the plan's current active set (U-14), not
    capture-lifetime history: it can legitimately be 0 (a scan-only target's
    ordinary exit) but must never exceed the allocated `slots` it is drawn
    from — every lane, every document. `slots` is type-checked first so a
    malformed `slots` fails with a stated reason here instead of a raw
    TypeError from the `<=` comparison below. One helper, called from every
    path that validates a live document (`exact_evidence_keys`,
    `exact_common`, `exact_active_to_empty`), so none of them can drift out
    of agreement or skip the check.
    """
    require(u64(evidence["slots"]), f"invalid slots: {evidence['slots']!r}")
    require(
        u64(evidence["active_slots"]),
        f"invalid active_slots: {evidence['active_slots']!r}",
    )
    require(
        evidence["active_slots"] <= evidence["slots"],
        f"active_slots ({evidence['active_slots']}) exceeds allocated "
        f"slots ({evidence['slots']})",
    )


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), f"{label} key set: {value!r}")


def uint(value, maximum, label, *, positive=False):
    require(
        isinstance(value, int) and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0) and value <= maximum,
        f"invalid {label}: {value!r}",
    )


def exact_selection_request(value, label):
    exact_keys(value, {"name", "version", "flags"}, label)
    require(value["name"] in SELECTION_NAME_CLASSES, f"invalid {label}.name: {value!r}")
    require(value["version"] in SELECTION_VERSION_CLASSES, f"invalid {label}.version: {value!r}")
    uint(value["flags"], U64_MAX, f"{label}.flags")


def exact_selection_result(value, label):
    """A result's flags word is read through caller-writable memory, so only
    its finite class is published (never the raw u64)."""
    exact_keys(value, {"name", "version", "flags"}, label)
    require(value["name"] in SELECTION_NAME_CLASSES, f"invalid {label}.name: {value!r}")
    require(value["version"] in SELECTION_VERSION_CLASSES, f"invalid {label}.version: {value!r}")
    require(
        isinstance(value["flags"], str) and value["flags"] in SELECTION_RESULT_FLAG_CLASSES,
        f"invalid {label}.flags class",
    )


def exact_kernel_control(evidence):
    """Closed native-control shape; any halt/loss must be a concrete gap."""
    control = evidence["kernel_control"]
    exact_keys(control, KERNEL_CONTROL_KEYS, "kernel_control")
    for key in ("capture_halted", "identity_budget_exhausted"):
        require(control[key] is True or control[key] is False,
                f"invalid kernel_control.{key}")
    for key in ("owner_admission_failures", "identity_unavailable"):
        uint(control[key], U64_MAX, f"kernel_control.{key}")
    for key, vocabulary in (("owner_poison", OWNER_POISON_REASONS),
                            ("root_affiliation_failures", ROOT_FAILURE_REASONS)):
        reasons = control[key]
        require(isinstance(reasons, list)
                and all(isinstance(reason, str) and reason in vocabulary for reason in reasons)
                and reasons == sorted(set(reasons)),
                f"invalid kernel_control.{key}")
    require(control["capture_halted"] == bool(control["owner_poison"]),
            "kernel_control.capture_halted disagrees with owner_poison")
    gap = (control["capture_halted"] or control["owner_admission_failures"]
           or control["identity_unavailable"] or control["root_affiliation_failures"])
    if gap:
        require(evidence["completeness"] == "PARTIAL"
                and evidence["verdict_detail"] == "concrete_gap",
                "kernel control loss must be a concrete PARTIAL gap")


def exact_profile_v3_selection(document, *, terminal=False, run=False):
    """Validate the closed, bounded profile-v3 selection/privacy extension."""
    if not terminal:
        require(document["schema"] == PROFILE_SCHEMA, document["schema"])
        require(document["lane"] == PROFILE_LANE, document.get("lane"))
        # The terminal trace carries no `capture` header, so only live
        # profile documents state their selecting scope here.
        exact_capture_scope(document)
        evidence = document["evidence"]
    else:
        evidence = document
    exact_evidence_keys(evidence, profile=True, terminal=terminal, child=run)
    exact_scheduling_evidence(evidence)
    exact_kernel_control(evidence)
    exact_task_uprobe_link_losses(evidence)
    exact_terminal_verdict(evidence)
    missing = {
        "interface_selection", "attach_mechanisms", "pid_descendant_gaps",
        "multi_rebuild_gaps",
    } - set(evidence)
    require(not missing, f"missing profile-v3 evidence: {sorted(missing)}")
    selection = evidence["interface_selection"]
    exact_keys(selection, SELECTION_KEYS, "interface_selection")
    require(isinstance(selection["selection_truncated"], bool), selection)
    modules = evidence["discovery"]

    def module_ref(value, label):
        uint(value, U32_MAX, label)
        require(value < len(modules), f"{label} refers to missing module: {value}")

    providers = selection["providers"]
    require(isinstance(providers, list) and len(providers) <= min(len(modules), 512), providers)
    for provider in providers:
        exact_keys(provider, {"module", "coverage"}, "selection provider")
        module_ref(provider["module"], "selection provider module")
        require(provider["coverage"] in SELECTION_COVERAGE, provider)
    require(providers == sorted(providers, key=lambda item: item["module"]), "unsorted providers")
    require(len({item["module"] for item in providers}) == len(providers), "duplicate providers")

    exports = selection["standard_exports"]
    require(isinstance(exports, list) and len(exports) <= min(len(modules), 512), exports)
    for export in exports:
        exact_keys(export, {"module", "status"}, "standard export")
        module_ref(export["module"], "standard export module")
        require(export["status"] in STANDARD_EXPORT_STATUS, export)
    require(exports == sorted(exports, key=lambda item: item["module"]), "unsorted exports")
    require(len({item["module"] for item in exports}) == len(exports), "duplicate exports")

    surfaces = selection["inventory_surfaces"]
    require(isinstance(surfaces, list) and len(surfaces) <= 512, surfaces)
    expected_ordinal = Counter()
    for surface in surfaces:
        exact_keys(surface, {"module", "ordinal", "kind"}, "inventory surface")
        module_ref(surface["module"], "inventory surface module")
        uint(surface["ordinal"], U16_MAX, "inventory surface ordinal")
        require(surface["ordinal"] == expected_ordinal[surface["module"]], surface)
        expected_ordinal[surface["module"]] += 1
        require(surface["kind"] in {"legacy", "interface"}, surface)
    require(
        surfaces == sorted(surfaces, key=lambda item: (item["module"], item["ordinal"])),
        "unsorted inventory surfaces",
    )

    tuples = selection["tuples"]
    require(isinstance(tuples, list) and len(tuples) <= 16, tuples)
    for tuple_ in tuples:
        exact_keys(
            tuple_,
            {"module", "request", "rv", "result", "table_match",
             "inventory_matches", "authority", "count"},
            "selection tuple",
        )
        module_ref(tuple_["module"], "selection tuple module")
        exact_selection_request(tuple_["request"], "selection request")
        uint(tuple_["rv"], U64_MAX, "selection rv")
        uint(tuple_["count"], U64_MAX, "selection count", positive=True)
        require(isinstance(tuple_["table_match"], bool), tuple_)
        require(tuple_["authority"] in SELECTION_AUTHORITIES, tuple_)
        matches = tuple_["inventory_matches"]
        require(isinstance(matches, list) and len(matches) <= 16, matches)
        previous = -1
        for match in matches:
            exact_keys(match, {"surface", "name_agrees", "version_agrees"}, "selection match")
            uint(match["surface"], U16_MAX, "selection match surface")
            require(match["surface"] < len(surfaces), f"missing selection surface: {match}")
            require(surfaces[match["surface"]]["module"] == tuple_["module"], match)
            require(match["surface"] > previous, "duplicate or unsorted selection matches")
            previous = match["surface"]
            require(isinstance(match["name_agrees"], bool), match)
            require(isinstance(match["version_agrees"], bool), match)
        require(tuple_["table_match"] == bool(matches), tuple_)
        result = tuple_["result"]
        if result is not None:
            exact_selection_result(result, "selection result")
        if tuple_["rv"] != 0 or result is None:
            require(not matches and not tuple_["table_match"] and tuple_["authority"] == "none", tuple_)
            require(tuple_["rv"] == 0 or result is None, tuple_)
        elif matches:
            readable = (
                result["name"] not in {"null", "unreadable"}
                and result["version"] not in {"null", "unreadable"}
            )
            require(
                tuple_["authority"] == ("inventory" if readable else "none"),
                tuple_,
            )
        elif tuple_["authority"] == "selection_count_only":
            require(
                tuple_["request"]["name"] == result["name"] == "exact_standard"
                and result["version"] in {"v3_0", "v3_1", "v3_2"}
                and result["flags"] in {"zero", "fork_safe"},
                tuple_,
            )
        else:
            require(tuple_["authority"] == "none", tuple_)
        for match in matches:
            surface = surfaces[match["surface"]]
            if surface["kind"] == "legacy" or result is None or result["name"] in {"null", "unreadable"}:
                require(not match["name_agrees"], f"invalid name agreement: {match}")
            if result is None or result["version"] in {"null", "unreadable"}:
                require(not match["version_agrees"], f"invalid version agreement: {match}")
    serialized_tuples = [selection_tuple_key(item) for item in tuples]
    require(serialized_tuples == sorted(serialized_tuples), "unsorted selection tuples")
    require(len(set(serialized_tuples)) == len(tuples), "duplicate selection tuples")

    mechanisms = evidence["attach_mechanisms"]
    require(
        isinstance(mechanisms, list) and mechanisms == sorted(set(mechanisms))
        and set(mechanisms) <= ATTACH_MECHANISMS,
        f"invalid attach mechanisms: {mechanisms!r}",
    )
    require(
        (not mechanisms) == (evidence["attached_probes"] == 0),
        f"attach mechanisms disagree with attached probes: {mechanisms!r}",
    )
    for field in ("pid_descendant_gaps", "multi_rebuild_gaps"):
        uint(evidence[field], U64_MAX, field)
    loss = (
        selection["selection_truncated"]
        or any(item["coverage"] not in {"observed", "absent_covered"} for item in providers)
        or any(item["status"] not in {"present", "legacy_absent"} for item in exports)
        or any(item["authority"] == "selection_count_only" for item in tuples)
        or any(item["rv"] == 0 and item["authority"] == "none" for item in tuples)
        or evidence["pid_descendant_gaps"] != 0
        or evidence["multi_rebuild_gaps"] != 0
    )
    if loss:
        require(evidence["completeness"] == "PARTIAL", "selection loss cannot be COMPLETE")


def exact_role_counts(description):
    exact_keys(description, {"observer_calls", "inspect_calls", "helper_calls"}, "role description")
    require(description == {
        "observer_calls": 0, "inspect_calls": 0, "helper_calls": 10,
    }, f"observer/helper roles are reversed or widened: {description}")


def helper_selection_call_count():
    """The helper's exact `C_GetInterface` call count, derived from the
    fixed selector×flag matrix in its source (SYSPLAN residual F-50/F5.7:
    the ten-call promise used to be a self-test against a literal, wired
    to no artifact — now the matrix bounds are read from the artifact and
    the count must still be exactly ten)."""
    text = Path("crates/discover/src/discover.rs").read_text(encoding="utf-8")
    selectors = re.search(r"for selector in 0\.\.(\d+)u8", text)
    flags = re.search(r"for flag in \[0u8, 1\]", text)
    require(selectors is not None, "helper selector loop is not the fixed 0..N matrix")
    require(flags is not None, "helper flag loop is not the fixed [0, 1] matrix")
    require(
        text.count("get_interface(name_ptr, version_ptr, &mut output, flags)") == 1,
        "helper must make its interface call at exactly one site",
    )
    return int(selectors.group(1)) * 2


def exact_evidence_keys(evidence, *, profile, terminal=False, child=False, historical=False):
    counter_keys = set(HISTORICAL_COUNTERS if historical else COUNTERS)
    wanted = (BASE_EVIDENCE_KEYS - set(COUNTERS)) | counter_keys
    if historical:
        # Retained v2-metrics documents predate scheduling evidence, like
        # the newer counters HISTORICAL_COUNTERS already excludes, and
        # predate the residual terminal/override/handoff/env evidence too.
        # They also predate active_slots (U-14, 2026-09-23).
        wanted.discard("scheduling")
        wanted.discard("active_slots")
        wanted -= RESIDUAL_EVIDENCE_KEYS
        wanted.discard("kernel_control")
    wanted |= PROFILE_V3_FIELDS if profile else set()
    if terminal:
        wanted |= TRACE_TERMINAL_KEYS
    actual = set(evidence)
    if child:
        wanted.add("child_still_running")
    require(actual == wanted, f"unexpected evidence keys: missing={sorted(wanted - actual)}, extra={sorted(actual - wanted)}")
    if not historical:
        # Historical v2-metrics documents predate active_slots (see above);
        # every current document's bound lives in one shared helper.
        exact_active_slots_bound(evidence)
    if child:
        require(isinstance(evidence["child_still_running"], bool),
                f"invalid child_still_running: {evidence['child_still_running']!r}")


def selection_tuple_key(tuple_):
    """Producer field order, rebuilt independently of input object key order."""
    request = tuple_["request"]
    result = tuple_["result"]
    canonical = {
        "module": tuple_["module"],
        "request": {"name": request["name"], "version": request["version"], "flags": request["flags"]},
        "rv": tuple_["rv"],
        "result": None if result is None else {
            "name": result["name"], "version": result["version"], "flags": result["flags"],
        },
        "table_match": tuple_["table_match"],
        "inventory_matches": [
            {"surface": item["surface"], "name_agrees": item["name_agrees"],
             "version_agrees": item["version_agrees"]}
            for item in tuple_["inventory_matches"]
        ],
        "authority": tuple_["authority"],
        "count": tuple_["count"],
    }
    return json.dumps(canonical, separators=(",", ":"))


def selection_matrix_rows(document):
    """Return every data row in the allowlist's selector matrix."""
    lines = document.splitlines()
    header = "| query order | selector | flags | request name | request version |"
    start = lines.index(header)
    require(
        lines[start + 1] == "| ---: | ---: | ---: | --- | --- |",
        "allowlist-v2 selector matrix header is malformed",
    )
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


def exact_capture_scope(document):
    """`capture.scope` names which scope selected the capture, nothing more.

    Exactly `pid`, `cgroup`, or `system` (observed-profile-v3 § capture):
    the kind, never a PID number or cgroup path. The message stays finite
    and non-echoing so an invalid value is rejected, never repeated.
    """
    capture = document.get("capture")
    require(isinstance(capture, dict), "capture must be an object")
    scope = capture.get("scope")
    require(
        isinstance(scope, str) and scope in ("pid", "cgroup", "system"),
        "capture.scope must be exactly pid, cgroup, or system",
    )


def exact_metrics_schema(document, *, run=False):
    require(document["schema"] == METRICS_SCHEMA, document["schema"])
    require(document["lane"] == METRICS_LANE, document.get("lane"))
    require(document["capture"]["mode"] == "metrics", document["capture"])
    require(document["capture"]["privacy_mode"] == "aggregate-only", document["capture"])
    exact_capture_scope(document)
    exact_evidence_keys(document["evidence"], profile=False, child=run)
    exact_scheduling_evidence(document["evidence"])
    exact_kernel_control(document["evidence"])
    exact_task_uprobe_link_losses(document["evidence"])
    exact_terminal_verdict(document["evidence"])


def exact_historical_metrics_schema(document, *, run=False):
    """Validate a retained v2-metrics document without accepting v3 fields."""
    require(document["schema"] == HISTORICAL_METRICS_SCHEMA, document["schema"])
    require(document["capture"]["mode"] == "metrics", document["capture"])
    require(document["capture"]["privacy_mode"] == "aggregate-only", document["capture"])
    exact_evidence_keys(
        document["evidence"], profile=False, child=run, historical=True
    )


def exact_scheduling_evidence(evidence):
    """Closed scheduling shape plus the loss-split identities.

    The splits are checked against the published loss counters, not just
    for shape: a capture/detach attribution that does not sum to the
    counter it claims to decompose is a misattribution, not evidence.
    """
    scheduling = evidence.get("scheduling")
    require(isinstance(scheduling, dict), "scheduling evidence must be an object")
    actual = set(scheduling)
    require(
        actual == SCHEDULING_KEYS,
        f"unexpected scheduling keys: missing={sorted(SCHEDULING_KEYS - actual)}, "
        f"extra={sorted(actual - SCHEDULING_KEYS)}",
    )
    for name in SCHEDULING_U64_KEYS:
        require(u64(scheduling[name]), f"scheduling.{name}: invalid counter {scheduling[name]!r}")
    require(
        scheduling["terminal_drain_bound"] == SCHEDULING_TERMINAL_DRAIN_BOUND,
        f"scheduling.terminal_drain_bound: want {SCHEDULING_TERMINAL_DRAIN_BOUND}, "
        f"got {scheduling['terminal_drain_bound']}",
    )
    require(
        scheduling["terminal_drain_truncated"] is False
        or scheduling["terminal_drain_truncated"] is True,
        f"scheduling.terminal_drain_truncated: invalid bool "
        f"{scheduling['terminal_drain_truncated']!r}",
    )
    require(
        scheduling["sink_policy"] == SCHEDULING_SINK_POLICY,
        f"scheduling.sink_policy: want {SCHEDULING_SINK_POLICY!r}, "
        f"got {scheduling['sink_policy']!r}",
    )
    phases = scheduling["phase_ms"]
    require(isinstance(phases, dict), "scheduling.phase_ms must be an object")
    require(
        set(phases) == set(SCHEDULING_PHASE_KEYS),
        f"unexpected phase_ms keys: {sorted(phases)}",
    )
    for name in SCHEDULING_PHASE_KEYS:
        require(u64(phases[name]), f"scheduling.phase_ms.{name}: invalid counter {phases[name]!r}")
    stamps = scheduling["phase_mono_ns"]
    require(isinstance(stamps, dict), "scheduling.phase_mono_ns must be an object")
    require(
        set(stamps) == set(SCHEDULING_PHASE_TS_KEYS),
        f"unexpected phase_mono_ns keys: {sorted(stamps)}",
    )
    for name in SCHEDULING_PHASE_TS_KEYS[:3]:
        value = stamps[name]
        require(
            value is None or u64(value),
            f"scheduling.phase_mono_ns.{name}: invalid stamp {value!r}",
        )
    require(
        stamps["loop_end_reason"] in SCHEDULING_LOOP_END_REASONS,
        f"scheduling.phase_mono_ns.loop_end_reason: invalid reason "
        f"{stamps['loop_end_reason']!r}",
    )
    # Identities: present stamps are nondecreasing (attach, then loop
    # start, then loop end), and the reason agrees with whether the loop
    # ended — an ended loop never reports "unstarted" and vice versa.
    present = [stamps[name] for name in SCHEDULING_PHASE_TS_KEYS[:3]
               if stamps[name] is not None]
    require(
        present == sorted(present),
        f"scheduling.phase_mono_ns: stamps out of order "
        f"{[stamps[name] for name in SCHEDULING_PHASE_TS_KEYS[:3]]!r}",
    )
    require(
        (stamps["loop_end_mono_ns"] is None)
        == (stamps["loop_end_reason"] == "unstarted"),
        f"scheduling.phase_mono_ns: loop_end {stamps['loop_end_mono_ns']!r} "
        f"disagrees with reason {stamps['loop_end_reason']!r}",
    )
    event_split = scheduling["capture_event_loss"] + scheduling["detach_event_loss"]
    require(
        event_split == evidence["event_loss"],
        f"scheduling event split {event_split} != event_loss {evidence['event_loss']}",
    )
    discovery_split = (
        scheduling["capture_discovery_loss"] + scheduling["detach_discovery_loss"]
    )
    require(
        discovery_split == evidence["discovery_ring_loss"],
        f"scheduling discovery split {discovery_split} != discovery_ring_loss "
        f"{evidence['discovery_ring_loss']}",
    )


def exact_task_uprobe_link_losses(evidence):
    """The live v3 schemas make task-uprobe loss a typed completeness gate."""
    value = evidence["task_uprobe_link_losses"]
    require(u64(value), f"invalid task_uprobe_link_losses: {value!r}")
    if value != 0:
        require(
            evidence["completeness"] != "COMPLETE",
            "task-uprobe link loss cannot be COMPLETE",
        )


def exact_terminal_verdict(evidence):
    """SYSPLAN residual terminal split (F-02) + durable override (F-01),
    handoff PID (F-15), and environment snapshot (F-26).

    The oracle gates any future COMPLETE on the settlement latch exactly
    like the producer's terminal seal: COMPLETE requires `drain_proven`
    and `clean_proven`; anything else is PARTIAL with the detail saying
    whether the run was clean-but-unproven or had a concrete gap.
    """
    require(
        evidence["completeness"] in {"COMPLETE", "PARTIAL"},
        f"invalid completeness: {evidence['completeness']!r}",
    )
    require(
        evidence["drain_proven"] is True or evidence["drain_proven"] is False,
        f"invalid drain_proven: {evidence['drain_proven']!r}",
    )
    detail = evidence["verdict_detail"]
    require(detail in VERDICT_DETAILS, f"invalid verdict_detail: {detail!r}")
    if evidence["completeness"] == "COMPLETE":
        require(
            evidence["drain_proven"] is True,
            "COMPLETE requires a proven terminal drain",
        )
        require(detail == "clean_proven", f"COMPLETE needs clean_proven: {detail!r}")
    elif detail == "clean_but_unproven":
        require(
            evidence["drain_proven"] is False,
            "clean_but_unproven needs an unproven drain",
        )
    override = evidence["uretprobe_override"]
    if override is not None:
        exact_keys(override, {"flag", "reason"}, "uretprobe_override")
        require(
            override["flag"] == URETPROBE_OVERRIDE_FLAG,
            f"invalid uretprobe_override.flag: {override!r}",
        )
        require(
            isinstance(override["reason"], str) and override["reason"],
            f"invalid uretprobe_override.reason: {override!r}",
        )
    pid = evidence["handoff_child_pid"]
    require(
        pid is None or (u64(pid) and 0 < pid <= U32_MAX),
        f"invalid handoff_child_pid: {pid!r}",
    )
    if "child_still_running" in evidence:
        require(
            (pid is None) == (evidence["child_still_running"] is not True),
            "handoff_child_pid disagrees with child_still_running",
        )
    else:
        require(pid is None, "handoff PID outside the run lane")
    env = evidence["p11scope_env"]
    require(isinstance(env, list), f"p11scope_env must be a list: {env!r}")
    seen = set()
    for item in env:
        exact_keys(item, {"name", "effect", "value"}, "p11scope_env item")
        require(item["name"] in P11SCOPE_ENV_VARS, f"unknown env switch: {item!r}")
        require(item["name"] not in seen, f"duplicate env switch: {item!r}")
        seen.add(item["name"])
        require(
            isinstance(item["effect"], str) and item["effect"],
            f"invalid env effect: {item!r}",
        )
        require(
            item["value"] is None or isinstance(item["value"], str),
            f"invalid env value: {item!r}",
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
    require(
        "build_id" not in carrier or build_id_ok(carrier["build_id"]),
        f"invalid object build ID: {carrier}",
    )


def exact_full_identity(carrier):
    require("build_id" in carrier, f"full identity omits build ID: {carrier}")
    exact_identity(carrier)


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
        require(u64(evidence[name]), f"{name}: invalid counter {evidence[name]!r}")
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
            {"sources", "objects", "corroborated", "corroboration", "skipped"} <= set(module),
            f"incomplete discovery module: {module}",
        )
        exact_sources(module)
        exact_full_identity(module)
        nested_skips = module["skipped"]
        require(isinstance(nested_skips, list), f"module skips are not an array: {module}")
        for skip in nested_skips:
            bounded_skip(skip)
            require(
                skip in evidence["skipped"],
                f"module skip is absent from top-level evidence: {skip}",
            )
        if "scan" in module["sources"]:
            scan_identities.add((tuple(module["dev"]), module["ino"], module["sha256"]))
        for carrier in module["objects"]:
            exact_sources(carrier)
            exact_full_identity(carrier)
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
        if isinstance(wanted, int):
            require(u64(evidence[name]), f"{name}: invalid count {evidence[name]!r}")
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
    The one exception is the gated null of an unlinked table's null slot: its
    subject is `unknown`, not a function, but the loss is still
    entry-granularity and the pair is fully specified, so a lane states it
    here exactly like any entry skip.
    """
    return [
        item
        for item in evidence["skipped"]
        if item["name"].startswith("C_") or item == UNKNOWN_NULL_SKIP
    ]


def bounded_skip(item):
    require(
        isinstance(item, dict) and set(item) == {"name", "reason"},
        f"invalid capture skip: {item!r}",
    )
    require(
        isinstance(item["name"], str) and isinstance(item["reason"], str),
        f"invalid capture skip: {item!r}",
    )
    entry = item["name"].startswith("C_")
    gated_null = item == UNKNOWN_NULL_SKIP
    require(
        entry or gated_null or item["name"] == DISCOVERY_SUBJECT,
        f"unbounded capture skip subject: {item}",
    )
    allowed = ENTRY_REASONS if (entry or gated_null) else DISCOVERY_REASONS
    require(item["reason"] in allowed, f"unbounded capture skip reason: {item}")
    return entry or gated_null


def discovery_skips(evidence):
    """Object/process/scope losses after capture-output subject bounding."""
    for item in evidence["skipped"]:
        bounded_skip(item)
    return [item for item in evidence["skipped"] if item["name"] == DISCOVERY_SUBJECT]


def exact_canary_discovery_skips(evidence, *, owned):
    """Property-based discovery-skip contract for canary lanes.

    Returns the validated skip count for exact_common to pin. Every
    discovery skip must be the one categorical public item, and the count
    must fit the lane's deterministic floor plus at most one retained
    internal loss: owned lanes carry exactly the initial-set skip,
    optionally plus one; safe lanes carry none, optionally plus one.

    Why a bound and not an exact count: the P-2 maps bracket refuses an
    acquisition whose mappings changed mid-read and records it, and the
    engine deliberately retains that record even when a later scan succeeds
    and attaches (scan_gap_this_capture_attached tombstones only not-mapped
    and file-backed-data losses). The render layer then flattens the refusal
    to the categorical item above — byte-identical to the spec-mandated
    initial-set skip — so no exact count can name which is which. The canary
    workload mmaps/munmaps while running, so the refusal fires
    intermittently in any lane.

    Why the bound is still strong: the initial-set skip is unconditional on
    owned lanes (one initial-set context per owned run, armed or not, and
    the empty timing catalog leaves it unproven by spec amendment), while
    the initial-set path never runs for profile/trace lanes. Any additional
    categorical item is a retained internal loss published through the same
    finite category — most often a bracket refusal, but whole-outcome scan
    losses and failed owned-prearm records flatten identically. That stays
    safe here: whole-outcome losses clear the scanned modules and
    Unavailable poisons scan_unavailable, so a lane carrying one cannot pass
    the exact shape, tables, sources and corroboration this validator
    demands (or the manifest-only sources that exclude scan data entirely).
    What the bound accepts alongside fully proven claims is therefore honest
    loss record — refused or unavailable data contributed nothing to the
    lane's claims. Which module refused is not a capture-document property
    by design (the public record must not name paths) and is proven by the
    workspace suite instead: the scan.rs bracket fixtures assert the
    refusing subject, and the engine.rs tests assert the refusal survives
    pinning and retention. A third skip, or any non-categorical item, is a
    new phenomenon and fails closed.
    """
    skips = discovery_skips(evidence)
    for item in skips:
        require(
            item == CANARY_DISCOVERY_SKIP,
            f"non-categorical canary discovery skip: {item}",
        )
    if owned:
        require(
            len(skips) in (1, 2),
            "owned canary discovery skips: want the categorical initial-set "
            f"skip plus at most one retained refusal, got {skips}",
        )
    else:
        require(
            len(skips) in (0, 1),
            "safe canary discovery skips: want none or one retained refusal, "
            f"got {skips}",
        )
    return len(skips)


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
    # SYSPLAN residual F-15: the run lane's own child, handed back alive.
    # The operator started this process; naming it leaks no target identity
    # they could not already see. `exact_terminal_verdict` pins it to the
    # run lane and to `child_still_running`.
    "handoff_child_pid",
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


def nested_unpublished_identity_keys(value, path="discovery"):
    found = []
    if isinstance(value, dict):
        for name, nested in value.items():
            nested_path = f"{path}.{name}"
            if name.startswith(IDENTITY_PREFIXES) or name.endswith(IDENTITY_SUFFIXES):
                found.append(nested_path)
            found.extend(nested_unpublished_identity_keys(nested, nested_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            found.extend(nested_unpublished_identity_keys(nested, f"{path}[{index}]"))
    return found


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
    # U-14: active_slots is the plan's current active set, not
    # capture-lifetime history. A scan-only target's ordinary exit retires
    # every slot its unpinned object held, so 0 is the expected value here,
    # not a loss — exact_active_slots_bound only pins that it can never
    # exceed the allocated `slots` above, checked here too (not just in
    # exact_evidence_keys) so a real renderer document that only ever
    # reaches this function still gets the bound.
    exact_active_slots_bound(evidence)
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


def exact_common(
    evidence, *, aliases, skipped, in_flight, discovery_skipped=0, run=False
):
    # U-14: active_slots is bounded here too, so every terminal_capture_is_clean
    # caller (which reaches exact_common but never exact_evidence_keys) gets it.
    exact_active_slots_bound(evidence)
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
    require(
        u64(evidence["in_flight_at_end"]),
        f"invalid in_flight_at_end: {evidence['in_flight_at_end']!r}",
    )
    require(evidence["in_flight_at_end"] == in_flight, evidence["in_flight_at_end"])
    require(evidence["templates_truncated"] is False, "templates were truncated")
    require(evidence["provider_changed"] is False, "a pinned provider object changed during capture")
    # Discovery is the claim the whole document rests on: a lane that attached
    # probes must name what it attached them into, and how it was authorized.
    require(evidence["authority"] == "hash-pinned", f"unexpected authority: {evidence['authority']}")
    exact_live_discovery_evidence(evidence, run=run)
    intruders = nested_unpublished_identity_keys(evidence["discovery"])
    require(not intruders, f"unpublished nested discovery identity: {intruders}")
    require(evidence["discovery"], "evidence.discovery is empty: nothing was discovered")
    exact_manifest_object_fallbacks(evidence)
    for module in evidence["discovery"]:
        exact_full_identity(module)
        exact_sources(module)
        for object_ in module["objects"]:
            exact_full_identity(object_)
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
    exact_capture_scope(document)
    exact_manifest_object_fallbacks(document["evidence"])
    exact_module_ownership(document)
    modules = document["capture"]["modules"]
    require(modules, "capture.modules is empty: the document names no provider")
    for module in modules:
        require(module["path"], f"module without a path: {module}")
        # `sha256` is null for an object nothing pinned — never in a lane that
        # attached probes, and the guard keeps that a stated rejection rather
        # than a TypeError traceback.
        exact_full_identity(module)
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


def validate_proxy_capacity_fallback(document, module_path=None):
    """The exact p11-kit-bounded/SoftHSM2-attached live shape.

    This is the p11-kit proxy lane's *expected* outcome, not a fallback. The
    installed libp11-kit maps 64 static 3.x closure templates into the
    scanned image — one of ADMITTED_PROXY_TABLE_SHAPES, e.g. 3.2/104-entry
    (6530 distinct targets) on the lane host. Since Task 1.2 the K=4
    per-object heuristic cap admits 4 tables (410 distinct targets at
    3.2/104) and records the other 60 as
    `discovery_uncorroborated_candidates` — spill is evidence, never slots
    — so the proxy module is NOT refused whole: both providers attach (478
    slots at 3.2/104), nothing is skipped, and every slot is scan-only
    `unknown` (1.3 mislabel guard). `module_path`, when the caller controls
    it, pins the directly-attached SoftHSM2 module by the exact path the
    lane configured rather than by a substring.
    """
    exact_metrics_schema(document)
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
    require(evidence["modules_skipped"] == [], evidence["modules_skipped"])
    require(evidence["skipped"] == [], evidence["skipped"])

    modules = document["capture"]["modules"]
    require(len(modules) == 2, [module["path"] for module in modules])
    soft = [m for m in modules if "softhsm" in m["path"].lower()]
    require(len(soft) == 1, [module["path"] for module in modules])
    soft = soft[0]
    proxy = [m for m in modules if m["path"] != soft["path"]]
    require(len(proxy) == 1, [module["path"] for module in modules])
    proxy = proxy[0]
    require("p11-kit" in proxy["path"].lower(), proxy["path"])
    require("p11-kit" not in soft["path"].lower(), soft["path"])
    require(
        module_path is None or soft["path"] == module_path,
        f"attached SoftHSM2 module is not the lane's own module: {soft['path']!r}",
    )
    soft_id = {key: soft[key] for key in ("dev", "ino", "sha256")}
    proxy_id = {key: proxy[key] for key in ("dev", "ino", "sha256")}

    discovery = evidence["discovery"]
    require(len(discovery) == 2, [module["path"] for module in discovery])
    by_path = {module["path"]: module for module in discovery}
    require(set(by_path) == {soft["path"], proxy["path"]}, by_path)
    for record in discovery:
        require(record["sources"] == ["scan"], record)
        require(record["corroborated"] is False, record)
        require(record["corroboration"] == ["single_source"], record)
        require(record["interfaces"] == 0, record)
        require(record["skipped"] == [], record)
        objects = record["objects"]
        require(len(objects) == 1, objects)
        target = objects[0]
        identity = soft_id if record["path"] == soft["path"] else proxy_id
        require(
            {key: target[key] for key in identity} == identity,
            f"attached target is not the module object: {target}",
        )
        require(target["path"] == record["path"], target)
    # Task 1.3 provenance: every decoded table carries its version-word file
    # offset and linkage kind. Zero interfaces means heuristic decode, so the
    # slots are named `unknown`, never ordinal PKCS#11 labels.
    soft_tables = by_path[soft["path"]]["tables"]
    require(len(soft_tables) == 1, soft_tables)
    require(
        {key: soft_tables[0][key] for key in ("version", "entries", "source")}
        == {"version": [2, 40], "entries": 68, "source": "scan"},
        soft_tables,
    )
    require(soft_tables[0]["linkage"] == "heuristic", soft_tables)
    require(u64(soft_tables[0]["file_offset"]), soft_tables)
    proxy_tables = by_path[proxy["path"]]["tables"]
    require(len(proxy_tables) == PROXY_TABLES, len(proxy_tables))
    offsets = set()
    shape = None
    for table in proxy_tables:
        version = table["version"]
        require(
            isinstance(version, list)
            and len(version) == 2
            and all(isinstance(value, int) for value in version),
            f"proxy table version is not a [major, minor] pair: {table}",
        )
        key = tuple(version)
        require(
            key in ADMITTED_PROXY_TABLE_SHAPES
            and table["entries"] == ADMITTED_PROXY_TABLE_SHAPES[key]["entries"]
            and table["source"] == "scan",
            table,
        )
        if shape is None:
            shape = key
        require(key == shape, f"proxy tables mix provider builds: {shape} vs {key}")
        require(table["linkage"] == "heuristic", table)
        require(u64(table["file_offset"]), table)
        offsets.add(table["file_offset"])
    require(len(offsets) == PROXY_TABLES, "proxy tables share a file offset")
    admitted = ADMITTED_PROXY_TABLE_SHAPES[shape]
    table_entries = admitted["entries"]
    admitted_slots = admitted["admitted_slots"]
    # K=4 spill: 64 decoded, 4 admitted, 60 recorded as candidates.
    require(
        evidence["discovery_uncorroborated_candidates"] == PROXY_SPILL,
        evidence["discovery_uncorroborated_candidates"],
    )

    # Decoded occurrences are recorded *before* heuristic-cap admission, so
    # the bounded module keeps every entry it decoded; the cap bounds
    # attachment, not discovery (schema v2 `table_entries`). Both modules must
    # own every surface: an unattributable surface is a gap, not an allowance.
    soft_surfaces = Counter()
    proxy_surfaces = Counter()
    for surface in evidence["surfaces"]:
        require(surface["acquisition"] == "ok", f"surface acquisition failure: {surface}")
        if surface["source"].startswith(f"{soft['path']} "):
            soft_surfaces[(surface["walk"], surface["functions"])] += 1
        elif surface["source"].startswith(f"{proxy['path']} "):
            proxy_surfaces[(surface["walk"], surface["functions"])] += 1
        else:
            require(False, f"surface belongs to neither module: {surface}")
    require(
        soft_surfaces == LEGACY_SURFACES,
        f"unexpected SoftHSM2 surfaces: {dict(soft_surfaces)}",
    )
    require(
        proxy_surfaces == Counter({("full", table_entries): PROXY_TABLES}),
        f"unexpected proxy surfaces: {dict(proxy_surfaces)}",
    )
    # One slot per {object, offset} and two probes per slot. The admitted
    # proxy slots are the distinct targets across 4 admitted tables of the
    # observed shape (410 at 3.2/104: 4*102+2, ordinals 65/66 shared,
    # byte-verified, 0 nulls); a target both providers publish is attached
    # exactly once.
    for name, wanted in (
        ("table_entries", 68 + PROXY_TABLES * table_entries),
        ("slots", 68 + admitted_slots),
        ("attached_probes", 2 * (68 + admitted_slots)),
        ("vendor_interfaces", 0),
        ("interface_list", "absent"),
    ):
        require(evidence[name] == wanted, f"{name}: want {wanted!r}, got {evidence[name]!r}")

    functions = document["functions"]
    require(len(functions) == evidence["slots"], len(functions))
    attributed = Counter()
    called_soft = 0
    called_proxy = 0
    for item in functions:
        require(item["names"] == ["unknown"], f"scan-only function must be unnamed: {item}")
        require(item["aliased"] is False, item)
        require(item["module_ambiguous"] is False, item)
        require(item["module"] in (soft_id, proxy_id), item)
        attributed["soft" if item["module"] == soft_id else "proxy"] += 1
        require(isinstance(item["calls"], int) and item["calls"] >= 0, item)
        if item["module"] == soft_id:
            called_soft += item["calls"]
        else:
            called_proxy += item["calls"]
    require(
        dict(attributed) == {"soft": 68, "proxy": admitted_slots},
        f"per-module function split: {dict(attributed)}",
    )
    # A green lane claims two-provider call coverage (audit F6): one global
    # positive count lets complete loss on either provider pass, so each
    # provider must have handled at least one call.
    require(called_soft > 0, "SoftHSM2 handled no calls: single-provider, not proxy-stack coverage")
    require(called_proxy > 0, "the proxy handled no calls: complete proxy-call loss is not two-provider coverage")


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
    document,
    expected,
    multiplier=1,
    *,
    discovery="scan",
    discovery_skipped=0,
    run=False,
):
    """SoftHSM2 counted exactly, with discovery stated rather than assumed.

    Since the 1.3 mislabel guard, scan-only tables carry no linkage and their
    slots are named `unknown` — never ordinal PKCS#11 labels — so the scan
    lane asserts exact counts on totals, while manifest-authorized lanes
    (manifest-only, corroborated) keep exact per-name counts.
    """
    require(discovery in CLEAN_DISCOVERY, f"unknown clean-metrics discovery: {discovery}")
    wanted_sources, allowances = CLEAN_DISCOVERY[discovery]
    require(multiplier >= 1, f"invalid clean-metrics multiplier: {multiplier}")
    exact_metrics_schema(document, run=run)
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
        run=run,
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
    elif discovery == "manifest-only":
        require(
            [object_["sources"] for object_ in evidence["discovery"][0]["objects"]]
            == [wanted_sources],
            f"unexpected manifest-only object sources: {evidence['discovery']}",
        )
        require(
            Counter(surface["source"] for surface in evidence["surfaces"])
            == Counter({"legacy_function_list": 1}),
            f"unexpected manifest-only surface sources: {evidence['surfaces']}",
        )
    exact_capture_modules(document)

    wanted = {name: calls * multiplier for name, calls in expected.items()}
    require("C_GetFunctionList" not in wanted, "expected-count file must omit bootstrap")
    wanted["C_GetFunctionList"] = multiplier
    if discovery == "scan":
        # Scan-only: unlinked heuristic tables are count-only under `unknown`
        # (1.3 mislabel guard) — the bootstrap loader call included — so
        # exactness is on the total, never per name.
        total = 0
        for item in document["functions"]:
            calls = item["calls"]
            require(u64(calls), f"invalid call count: {item}")
            require(
                item["names"] == ["unknown"],
                f"scan-only function must be unnamed: {item}",
            )
            require(
                item["aliased"] is False,
                f"clean metrics cannot contain aliases: {item}",
            )
            total += calls
        require(
            total == sum(wanted.values()),
            f"scan-only total calls: want {sum(wanted.values())}, got {total}",
        )
        return
    actual = Counter()
    for item in document["functions"]:
        calls = item["calls"]
        require(u64(calls), f"invalid call count: {item}")
        names = item["names"]
        require(
            isinstance(names, list)
            and names
            and all(isinstance(name, str) for name in names)
            and len(names) == len(set(names)),
            f"invalid function names: {item}",
        )
        require(item["aliased"] is False, f"clean metrics cannot contain aliases: {item}")
        if calls:
            actual.update({name: calls for name in names})
    require(dict(actual) == wanted, f"positive function counts: want {wanted}, got {dict(actual)}")


def validate_lane02_owned_run_metrics(document, expected, pause):
    """Lane 02: one owned child, one bounded discovery-unavailable projection."""
    require(pause in ("never", "auto", "always"), f"unknown Lane02 pause: {pause!r}")
    validate_clean_metrics(
        document,
        expected,
        discovery="scan",
        discovery_skipped=1,
        run=True,
    )
    evidence = document["evidence"]
    require(
        evidence["skipped"]
        == [{"name": DISCOVERY_SUBJECT, "reason": DISCOVERY_UNAVAILABLE}],
        f"unexpected Lane02 skips: {evidence['skipped']}",
    )
    require(evidence["child_still_running"] is False, evidence["child_still_running"])
    loader = evidence["loader_discovery"]
    require(loader["state_read_failures"] == 0, loader["state_read_failures"])
    require(
        loader["strategies"]
        == {"debug_state_every_hit": 2, "dlopen_return": 0, "unavailable": 0},
        f"unexpected Lane02 loader strategies: {loader['strategies']}",
    )
    timing = {
        "qualified_pre_constructor": 0,
        "known_pre_relocation": 0,
        "unproven": 1,
        "none": 0,
    }
    require(loader["dlopen_timing"] == timing, loader["dlopen_timing"])
    require(loader["initial_set_timing"] == timing, loader["initial_set_timing"])
    require(
        loader["initial_set_capture"] == {"eligible": 0, "none": 1},
        loader["initial_set_capture"],
    )
    attempts, confirmed, partial = (evidence[name] for name in PAUSE_COUNTERS)
    if pause == "never":
        require(
            (evidence["pause"], attempts, confirmed, partial) == ("none", 0, 0, 0),
            f"Lane02 never pause tuple: {(evidence['pause'], attempts, confirmed, partial)}",
        )
    else:
        require(evidence["pause"] == "sigstop", evidence["pause"])
        require(attempts == confirmed and confirmed >= 1, (attempts, confirmed))
        require(partial == 0, partial)


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
def validate_lane13_knative_metrics(document, expected):
    """Lane 13: manifest-only clean metrics plus one shared-overlay uncertainty."""
    require(
        "discovery_uncorroborated" in document["evidence"],
        "lane 13 must state discovery_uncorroborated",
    )
    validate_clean_metrics(
        document,
        expected,
        discovery="manifest-only",
        discovery_skipped=1,
    )
    require(
        document["evidence"]["skipped"]
        == [{"name": DISCOVERY_SUBJECT, "reason": SHARED_OVERLAY_UNCERTAINTY}],
        f"unexpected shared-overlay uncertainty: {document['evidence']['skipped']}",
    )
    require(
        [module["skipped"] for module in document["evidence"]["discovery"]] == [[]],
        f"lane 13 cannot contain module entry skips: {document['evidence']['discovery']}",
    )


def validate_canary(lane, document, target_bits=64):
    """A canary lane: the version-matrix provider, exact in shape and policy.

    The third element of each row is how discovery saw the provider. The canary
    workload maps it before attach, so both sources describe it (`scanned`).
    Since 1d3837b the initial provider export hooks attach before readiness, so
    a workload released only after attach is still observed live: its bootstrap
    calls trigger the scan, which compares with the manifest mid-capture. The
    live freeze lane therefore measures the scanned row exactly, and
    verify-induced-gaps.sh validates its capture as `feature-unsafe-profile`.
    The `freeze-unsafe-profile` row keeps the manifest-only expectation — still
    a real shape for a target that never calls into the provider during
    capture — under its contracted self-test marker. Neither value is optional:
    a lane that scanned when it should not have, or failed to scan when it
    should have, fails here.
    """
    lanes = {
        "default-safe-profile": ("safe", "profile", "scanned"),
        "default-safe-trace": ("safe", "trace", "scanned"),
        "feature-safe-profile": ("safe", "profile", "scanned"),
        "feature-safe-trace": ("safe", "trace", "scanned"),
        "feature-unsafe-profile": ("unsafe", "profile", "scanned"),
        "feature-unsafe-trace": ("unsafe", "trace", "scanned"),
        "aggregate-only-metrics": ("aggregate", "metrics", "scanned"),
        "owned-default-metrics": ("aggregate", "metrics", "scanned"),
        "owned-feature-metrics": ("aggregate", "metrics", "scanned"),
        "freeze-unsafe-profile": ("unsafe", "profile", "manifest-only"),
    }
    require(lane in lanes, f"unknown canary lane: {lane}")
    require(target_bits in (32, 64), f"invalid canary target width: {target_bits!r}")
    policy, kind, discovery = lanes[lane]
    owned_metrics = lane in {"owned-default-metrics", "owned-feature-metrics"}
    trace = kind == "trace"
    evidence = document if trace else document["evidence"]
    if kind == "metrics":
        require(document["schema"] == METRICS_SCHEMA, document["schema"])
        exact_metrics_schema(document, run=owned_metrics)
    else:
        exact_profile_v3_selection(document, terminal=trace)

    scanned = discovery == "scanned"
    scanned_shape = VERSION_SHAPE_SCANNED_IA32 if target_bits == 32 else VERSION_SHAPE_SCANNED
    exact_shape(evidence, *(scanned_shape if scanned else VERSION_SHAPE_MANIFEST_ONLY))
    scanned_tables = (
        VERSION_TABLES_SCANNED_IA32 if target_bits == 32 else VERSION_TABLES_SCANNED
    )
    wanted_tables = scanned_tables if scanned else VERSION_TABLES_MANIFEST_ONLY
    require(
        table_signature(evidence) == wanted_tables,
        f"unexpected discovery tables: {evidence['discovery']}",
    )
    # The discovery-skip bound lives in exact_canary_discovery_skips: the
    # deterministic floor (one initial-set skip on owned lanes, none
    # elsewhere) plus at most one retained internal loss. exact_common pins
    # the validated count against the document.
    skips = exact_canary_discovery_skips(evidence, owned=owned_metrics)
    exact_common(
        evidence,
        aliases=[],
        skipped=[],
        in_flight=0,
        discovery_skipped=skips,
        run=owned_metrics,
    )
    allowances = dict(
        SAFE_ALLOWANCES if policy == "safe" else UNSAFE_ALLOWANCES if policy == "unsafe" else {}
    )
    if scanned and target_bits == 64:
        allowances["discovery_conflicts"] = 1
    elif not scanned:
        allowances["discovery_uncorroborated"] = 1
    exact_counters(evidence, allowances)
    sources = [module["sources"] for module in evidence["discovery"]]
    require(
        sources == ([["scan", "manifest"]] if scanned else [["manifest"]]),
        f"unexpected discovery sources: {sources}",
    )
    outcomes = [module["corroboration"] for module in evidence["discovery"]]
    wanted_outcomes = (
        [["agreed"]]
        if scanned and target_bits == 32
        else [["conflict"]]
        if scanned
        else [["uncorroborated"]]
    )
    require(outcomes == wanted_outcomes, f"unexpected corroboration: {outcomes}")

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
        schema = METRICS_SCHEMA if kind == "metrics" else PROFILE_SCHEMA
        require(document["schema"] == schema, document["schema"])
        require(document["capture"]["mode"] == kind, document["capture"])
        require(document["capture"]["privacy_mode"] == privacy, document["capture"])
        exact_capture_modules(document)
    if policy == "aggregate":
        calls = sum(item["calls"] for item in document["functions"])
        wanted_calls = 30 if owned_metrics else 28
        require(calls == wanted_calls,
                f"aggregate calls: want {wanted_calls}, got {calls}")
        if owned_metrics:
            require(evidence["child_still_running"] is False,
                    f"owned child still running: {evidence['child_still_running']!r}")
            require(
                (evidence["pause"], evidence["pause_attempts"],
                 evidence["pause_confirmed"], evidence["pause_partial"])
                == ("none", 0, 0, 0),
                "owned metrics requires exact never-pause evidence",
            )


# Every induced-gap lane holds its workload behind a go-file, so nothing has
# dlopened the provider when the observer attaches. Since 1d3837b the initial
# provider export hooks attach before readiness, so the workload's bootstrap
# calls trigger a live scan that corroborates the manifest mid-capture: the
# single-table providers (G2, G3) read `agreed`, while the version-matrix
# provider (G4, G5) yields a three-table scan subset and reads `conflict`.
# The gap being induced is never the discovery one.
#
# G1 is a single-table provider too, so it reads `agreed` like G2 and G3, and
# nothing in any lane is uncorroborated any more. Its 161 table entries are 159
# deduplicated targets plus one null-entry skip record per walking source:
# `src/plan.rs` `decoded_occurrence_count` keys targets across sources but skips
# per source, because a skip is a per-walk disclosure and a target is a physical
# thing. The same per-source keying is what doubles `evidence.skipped`, and
# `corroborate` decides `agreed` on the deduplicated targets, so 161 entries and
# an agreed module are one consistent statement, not a contradiction.


def validate_induced(lane, document):
    require(lane in {"G1", "G2", "G3", "G4", "G5"}, f"unknown induced lane: {lane}")
    exact_profile_v3_selection(document)
    require(document["capture"]["mode"] == "profile", document["capture"])
    require(document["capture"]["privacy_mode"] == "allowlisted", document["capture"])
    exact_capture_modules(document)
    ring_bytes = document["capture"].get("ring_bytes")
    require(
        isinstance(ring_bytes, int) and not isinstance(ring_bytes, bool)
        and 4096 <= ring_bytes <= 67108864 and ring_bytes & (ring_bytes - 1) == 0,
        f"invalid capture.ring_bytes: {ring_bytes!r}",
    )
    drain_ms = document["capture"].get("drain_interval_ms")
    uint(drain_ms, 60000, "capture.drain_interval_ms")
    require(5 <= drain_ms, f"invalid capture.drain_interval_ms: {drain_ms!r}")
    evidence = document["evidence"]
    sources = [module["sources"] for module in evidence["discovery"]]
    require(sources == [["scan", "manifest"]], f"unexpected discovery sources: {sources}")
    outcomes = [module["corroboration"] for module in evidence["discovery"]]
    wanted_outcomes = [["conflict"]] if lane in {"G4", "G5"} else [["agreed"]]
    require(outcomes == wanted_outcomes, f"unexpected corroboration: {outcomes}")

    if lane == "G1":
        aliases = [["C_CancelFunction", "C_WaitForSlotEvent"]]
        # One null-entry disclosure per walking source: the manifest walk and
        # the live scan walk each report the provider's single NULL entry.
        skipped = [{"name": "C_GetFunctionStatus", "reason": "null pointer"}] * 2
        exact_shape(evidence, 161, 93, 186, G1_SURFACES, 1, "ok")
        exact_common(evidence, aliases=aliases, skipped=skipped, in_flight=0)
        exact_counters(evidence)
    elif lane == "G2":
        groups = evidence["aliased"]
        require(len(groups) == 1, f"G2 aliases: {groups}")
        require(len(groups[0]) == len(set(groups[0])) == 67, f"G2 alias group: {groups}")
        require("C_WaitForSlotEvent" not in groups[0], f"G2 stranded name was aliased: {groups}")
        exact_shape(evidence, 68, 2, 4, LEGACY_SURFACES + LEGACY_SURFACES, 0, "absent")
        exact_common(evidence, aliases=groups, skipped=[], in_flight=1)
        exact_counters(evidence)
    elif lane == "G3":
        exact_shape(evidence, 68, 68, 136, LEGACY_SURFACES + LEGACY_SURFACES, 0, "absent")
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
                event_loss=evidence["event_loss"],
                unmatched_closes=evidence["unmatched_closes"],
            ),
        )
    elif lane == "G4":
        exact_shape(evidence, *VERSION_SHAPE_SCANNED)
        exact_common(evidence, aliases=[], skipped=[], in_flight=9)
        exact_counters(evidence, {"discovery_conflicts": 1, "start_insert_failures": 8})
    else:
        exact_shape(evidence, *VERSION_SHAPE_SCANNED)
        exact_common(evidence, aliases=[], skipped=[], in_flight=0)
        exact_counters(
            evidence,
            {
                "discovery_conflicts": 1,
                "rv_update_failures": 9,
                "unregistered_mechanisms": 6,
                "async_orphans": 1,
            },
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

PROXY_MODULE_FIXTURE = {
    "path": "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8",
    "dev": [8, 2],
    "ino": 9999,
    "sha256": "22" * 32,
    "build_id": "ccdd",
}


def function_items(pairs, identity=None):
    """`functions[]` items as v2 emits them: every count attributed to a module."""
    if identity is None:
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
                {
                    "version": [2, 40],
                    "entries": 68,
                    "source": source,
                    "file_offset": 0x1000 if source == "scan" else None,
                    "linkage": "heuristic" if source == "scan" else "manifest",
                }
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
# The one categorical discovery-skip item a canary lane may publish. The
# render layer flattens every internal object loss to a finite public reason,
# so a retained P-2 bracket refusal publishes byte-identical to the
# spec-mandated initial-set skip.
CANARY_DISCOVERY_SKIP = {
    "name": DISCOVERY_SUBJECT,
    "reason": DISCOVERY_UNAVAILABLE,
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


def scheduling_fixture(**overrides):
    """Closed scheduling shape, idle. Overrides state the exercised counts."""
    fixture = {name: 0 for name in SCHEDULING_U64_KEYS}
    fixture["terminal_drain_bound"] = SCHEDULING_TERMINAL_DRAIN_BOUND
    fixture["terminal_drain_truncated"] = False
    fixture["sink_policy"] = SCHEDULING_SINK_POLICY
    fixture["phase_ms"] = {name: 0 for name in SCHEDULING_PHASE_KEYS}
    fixture["phase_mono_ns"] = {
        "attach_mono_ns": None,
        "loop_start_mono_ns": None,
        "loop_end_mono_ns": None,
        "loop_end_reason": "unstarted",
    }
    for name, value in overrides.items():
        require(
            name in SCHEDULING_KEYS,
            f"unknown scheduling fixture override: {name}",
        )
        fixture[name] = value
    return fixture


def kernel_control_fixture():
    return {
        "capture_halted": False,
        "owner_poison": [],
        "owner_admission_failures": 0,
        "identity_unavailable": 0,
        "identity_budget_exhausted": False,
        "root_affiliation_failures": [],
    }


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
        "active_slots": 0,
        "attached_probes": 0,
        "attach_failures": [],
        "aliased": [],
        "skipped": [dict(DISCOVERY_SKIP) for _ in range(discovery_skipped)],
        "in_flight_at_end": 0,
        "surfaces": [
            {
                "walk": walk,
                "functions": functions,
                "acquisition": "ok",
                "source": "legacy_function_list",
            }
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
        "discovery_uncorroborated_candidates": 0,
        "templates_truncated": False,
        "provider_changed": False,
        "scheduling": scheduling_fixture(),
        "kernel_control": kernel_control_fixture(),
        "completeness": "PARTIAL",
        # SYSPLAN residual: unproven drain, concrete gap, clean preflight,
        # no handoff, no env switches live.
        "drain_proven": False,
        "verdict_detail": "concrete_gap",
        "uretprobe_override": None,
        "handoff_child_pid": None,
        "p11scope_env": [],
    }


def document_fixture(evidence, *, schema=PROFILE_SCHEMA, mode="profile", privacy="allowlisted"):
    evidence = copy.deepcopy(evidence)
    if schema == PROFILE_SCHEMA:
        evidence.setdefault("interface_selection", {
            "providers": [], "standard_exports": [], "inventory_surfaces": [],
            "tuples": [], "selection_truncated": False,
        })
        evidence.setdefault("attach_mechanisms", [] if evidence["attached_probes"] == 0 else ["per-offset"])
        evidence.setdefault("pid_descendant_gaps", 0)
        evidence.setdefault("multi_rebuild_gaps", 0)
    elif schema in (METRICS_SCHEMA, HISTORICAL_METRICS_SCHEMA):
        for field in PROFILE_V3_FIELDS:
            evidence.pop(field, None)
        if schema == HISTORICAL_METRICS_SCHEMA:
            evidence.pop("task_uprobe_link_losses", None)
            evidence.pop("abi_refusals", None)
            evidence.pop("semantic_history_drops", None)
            evidence.pop("scheduling", None)
            evidence.pop("active_slots", None)
            evidence.pop("kernel_control", None)
            for field in RESIDUAL_EVIDENCE_KEYS:
                evidence.pop(field, None)
    capture = {
        "mode": mode,
        "privacy_mode": privacy,
        # Effective capture tuning, disclosed by every real capture.
        "ring_bytes": 262144,
        "drain_interval_ms": 1000,
        # v2: one entry per discovered module, projected from the evidence.
        "modules": [
            {key: module[key] for key in ("path", "dev", "ino", "sha256", "build_id")}
            for module in evidence["discovery"]
        ],
    }
    if schema != HISTORICAL_METRICS_SCHEMA:
        # Current v3 profile/metrics captures disclose which scope selected
        # them; the retained v2-metrics shape predates the field.
        capture["scope"] = "pid"
    if schema == PROFILE_SCHEMA:
        lane = PROFILE_LANE
    elif schema == METRICS_SCHEMA:
        lane = METRICS_LANE
    else:
        lane = METRICS_LANE
    return {
        "schema": schema,
        "lane": lane,
        "capture": capture,
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
    helper_calls = helper_selection_call_count()
    roles = {"observer_calls": 0, "inspect_calls": 0, "helper_calls": helper_calls}
    exact_role_counts(roles)
    reversed_roles = {"observer_calls": 10, "inspect_calls": 0, "helper_calls": 0}
    rejected(lambda: exact_role_counts(reversed_roles))
    print("observer and inspect make zero calls; only the offline helper makes ten: OK")
    clean_evidence = evidence_fixture(LEGACY_SURFACES)
    clean_evidence.update(table_entries=68, slots=68, active_slots=68, attached_probes=136)
    clean = document_fixture(
        clean_evidence,
        schema=METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    clean["functions"] = function_items([(["unknown"], 2)])
    validate_clean_metrics(clean, {"C_Initialize": 1})
    historical = document_fixture(
        clean_evidence,
        schema=HISTORICAL_METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    exact_historical_metrics_schema(historical)
    rejected(lambda: exact_metrics_schema(historical))
    print("historical v2-metrics fixture remains closed and non-emitted: OK")
    halted = copy.deepcopy(clean)
    halted["evidence"]["kernel_control"].update(
        capture_halted=True, owner_poison=["refund_failed"])
    halted["evidence"].update(completeness="PARTIAL", verdict_detail="concrete_gap")
    exact_metrics_schema(halted)
    for mutate in (
        lambda control: control.update(capture_halted=False),
        lambda control: control.update(owner_poison=["refund_failed", "refund_failed"]),
        lambda control: control.update(owner_poison=["poison 32"]),
        lambda control: control.update(owner_poison=["refund_failed"], capture_halted=1),
        lambda control: control.update(owner_admission_failures=-1),
        lambda control: control.update(root_affiliation_failures=["capacity", "bad_cell"]),
        lambda control: control.pop("identity_unavailable"),
        lambda control: control.update(raw_poison=32),
    ):
        invalid = copy.deepcopy(halted)
        mutate(invalid["evidence"]["kernel_control"])
        rejected(lambda invalid=invalid: exact_metrics_schema(invalid))
    for field, value in (("capture_halted", True), ("owner_admission_failures", 1),
                         ("identity_unavailable", 1),
                         ("root_affiliation_failures", ["capacity"])):
        unflagged = copy.deepcopy(clean)
        unflagged["evidence"]["kernel_control"][field] = value
        if field == "capture_halted":
            unflagged["evidence"]["kernel_control"]["owner_poison"] = ["classifier_failed"]
        unflagged["evidence"].update(completeness="PARTIAL", verdict_detail="clean_but_unproven")
        rejected(lambda unflagged=unflagged: exact_metrics_schema(unflagged))
    budget_only = copy.deepcopy(clean)
    budget_only["evidence"]["kernel_control"]["identity_budget_exhausted"] = True
    exact_metrics_schema(budget_only)
    print("kernel control halt/loss is closed, finite and a concrete gap: OK")
    bad_metrics = copy.deepcopy(clean)
    bad_metrics["evidence"]["secret_selection_payload"] = "CANARY"
    rejected(lambda: validate_clean_metrics(bad_metrics, {"C_Initialize": 1}))
    shared = copy.deepcopy(clean)
    shared["evidence"]["skipped"] = [
        {
            "name": DISCOVERY_SUBJECT,
            "reason": SHARED_OVERLAY_UNCERTAINTY,
        }
    ]
    validate_shared_layer_metrics(shared, {"C_Initialize": 1})
    shared_nested_overlay = copy.deepcopy(shared)
    shared_nested_overlay["evidence"]["discovery"][0]["skipped"] = [
        copy.deepcopy(shared_nested_overlay["evidence"]["skipped"][0])
    ]
    validate_shared_layer_metrics(shared_nested_overlay, {"C_Initialize": 1})
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
    bad["functions"] += function_items([(["unknown"], 1)])
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("unexpected positive function rejected: OK")
    # A scan-only slot carrying an ordinal label is a mislabel, not evidence.
    bad = copy.deepcopy(clean)
    bad["functions"] = function_items([(["unknown"], 1), (["C_Initialize"], 1)])
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("scan-only ordinal label rejected: OK")
    bad = copy.deepcopy(clean)
    bad["functions"][0]["calls"] = 3
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("scan-only total exact count required: OK")
    doubled = copy.deepcopy(clean)
    for item in doubled["functions"]:
        item["calls"] *= 2
    validate_clean_metrics(doubled, {"C_Initialize": 1}, 2)
    rejected(lambda: validate_clean_metrics(clean, {"C_Initialize": 1}, 2))
    print("clean metrics multiplier is exact: OK")

    # Lane 02 owns one child and publishes one sanitized timing-proof skip.
    for pause in ("never", "auto", "always"):
        owned = copy.deepcopy(clean)
        owned["evidence"]["skipped"] = [
            {"name": DISCOVERY_SUBJECT, "reason": DISCOVERY_UNAVAILABLE}
        ]
        owned["evidence"]["child_still_running"] = False
        owned["evidence"]["loader_discovery"] = loader_discovery_fixture(
            strategies__debug_state_every_hit=2,
            dlopen_timing__unproven=1,
            initial_set_timing__unproven=1,
            initial_set_capture__none=1,
        )
        if pause != "never":
            owned["evidence"].update(
                pause="sigstop", pause_attempts=1, pause_confirmed=1, pause_partial=0
            )
        validate_lane02_owned_run_metrics(owned, {"C_Initialize": 1}, pause)
        for mutate in (
            lambda d: d["evidence"].pop("child_still_running"),
            lambda d: d["evidence"].update(child_still_running="no"),
            lambda d: d["evidence"].update(child_still_running=True),
            lambda d: d["evidence"].update(skipped=[]),
            lambda d: d["evidence"]["skipped"].append(
                {"name": DISCOVERY_SUBJECT, "reason": DISCOVERY_UNAVAILABLE}
            ),
            lambda d: d["evidence"]["skipped"][0].update(reason=TABLE_UNAVAILABLE),
            lambda d: d["evidence"]["loader_discovery"].update(state_read_failures=1),
            lambda d: d["evidence"]["discovery"][0].update(loader_pid=7),
            lambda d: d["functions"].__setitem__(0, function_items(
                [(["C_GetFunctionList"], 2)]
            )[0]),
        ):
            bad = copy.deepcopy(owned)
            mutate(bad)
            rejected(
                lambda bad=bad, pause=pause: validate_lane02_owned_run_metrics(
                    bad, {"C_Initialize": 1}, pause
                )
            )
        bad = copy.deepcopy(owned)
        if pause == "never":
            bad["evidence"].update(pause="sigstop", pause_attempts=1, pause_confirmed=1)
        else:
            bad["evidence"].update(pause="none", pause_attempts=0, pause_confirmed=0)
        rejected(
            lambda bad=bad, pause=pause: validate_lane02_owned_run_metrics(
                bad, {"C_Initialize": 1}, pause
            )
        )
        rejected(
            lambda owned=owned, pause=pause: validate_lane02_owned_run_metrics(
                owned, {"C_Initialize": 2}, pause
            )
        )
        zero_loader = copy.deepcopy(owned)
        zero_loader["evidence"]["loader_discovery"] = loader_discovery_fixture()
        rejected(
            lambda zero_loader=zero_loader, pause=pause: validate_lane02_owned_run_metrics(
                zero_loader, {"C_Initialize": 1}, pause
            )
        )
    print("lane02 owned-run metrics self-test: OK")

    # A lane whose target maps the provider only after attach: the manifest is
    # the sole source and is reported uncorroborated. The scanned expectation
    # must reject it, and the manifest-only expectation must reject a scan.
    manifest_only_evidence = evidence_fixture(LEGACY_SURFACES, sources=("manifest",))
    manifest_only_evidence.update(
        table_entries=68, slots=68, attached_probes=136, discovery_uncorroborated=1
    )
    manifest_only = document_fixture(
        manifest_only_evidence,
        schema=METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    manifest_only["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    lane13 = copy.deepcopy(manifest_only)
    lane13["evidence"]["skipped"] = [
        {
            "name": DISCOVERY_SUBJECT,
            "reason": SHARED_OVERLAY_UNCERTAINTY,
        }
    ]
    validate_lane13_knative_metrics(lane13, {"C_Initialize": 1})
    for mutate in (
        lambda d: d["evidence"].update(skipped=[]),
        lambda d: d["evidence"]["skipped"].append(
            copy.deepcopy(d["evidence"]["skipped"][0])
        ),
        lambda d: d["evidence"]["skipped"][0].update(name="renamed discovery subject"),
        lambda d: d["evidence"]["skipped"][0].update(reason=TABLE_UNAVAILABLE),
        lambda d: d["evidence"]["skipped"][0].update(reason=DISCOVERY_UNAVAILABLE),
        lambda d: d["evidence"]["skipped"].append(
            {"name": DISCOVERY_SUBJECT, "reason": DISCOVERY_UNAVAILABLE}
        ),
        lambda d: d["evidence"]["discovery"][0].update(
            skipped=[{"name": "C_Initialize", "reason": ENTRY_UNAVAILABLE}]
        ),
        lambda d: d["evidence"]["discovery"][0].update(
            skipped=[{"name": "/private/provider/path", "reason": "raw internal error chain"}]
        ),
        lambda d: d["evidence"]["discovery"][0].update(
            skipped=[copy.deepcopy(d["evidence"]["skipped"][0])]
        ),
        lambda d: d["evidence"]["discovery"][0]["objects"][0].update(sources=["scan"]),
        lambda d: d["evidence"]["surfaces"][0].update(
            source="scan-derived arbitrary label"
        ),
        lambda d: d["evidence"].update(event_loss=1),
        lambda d: d["evidence"].update(event_loss=False),
        lambda d: d["evidence"].update(scan_unavailable="ptrace"),
        lambda d: d["evidence"].update(discovery_uncorroborated=0),
        lambda d: d["evidence"].update(discovery_uncorroborated=2),
        lambda d: d["evidence"].update(discovery_uncorroborated=True),
        lambda d: d["evidence"].pop("discovery_uncorroborated"),
        lambda d: d["evidence"].update(slots=67),
        lambda d: d["evidence"].update(vendor_interfaces=False),
        lambda d: d["evidence"].update(in_flight_at_end=False),
        lambda d: d["functions"][1].update(calls=2),
        lambda d: d["functions"][1].update(calls=True),
        lambda d: d["functions"][1].update(
            names=["C_Initialize", "C_Initialize"], aliased=True
        ),
        lambda d: d["evidence"]["discovery"][0].update(build_id=7),
        lambda d: d["capture"]["modules"][0].update(build_id=7),
        lambda d: d["evidence"]["discovery"][0]["objects"][0].update(build_id="a"),
        lambda d: d["evidence"]["discovery"][0]["objects"][0].pop("build_id"),
        lambda d: d["capture"]["modules"][0].update(build_id="AABB"),
        lambda d: d.update(schema="p11scope/observed-profile/v2"),
        lambda d: d["capture"].update(mode="profile"),
        lambda d: d["capture"].update(privacy_mode="allowlisted"),
    ):
        bad = copy.deepcopy(lane13)
        mutate(bad)
        rejected(lambda bad=bad: validate_lane13_knative_metrics(bad, {"C_Initialize": 1}))
    corroborated_evidence = evidence_fixture(
        LEGACY_SURFACES + LEGACY_SURFACES, sources=("scan", "manifest")
    )
    corroborated_evidence["surfaces"][0]["source"] = "/opt/p11.so table 2.40"
    corroborated_evidence["surfaces"][1]["source"] = "legacy_function_list"
    corroborated_evidence.update(table_entries=68, slots=68, attached_probes=136)
    corroborated = document_fixture(
        corroborated_evidence,
        schema=METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    corroborated["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    for wrong_discovery in (clean, corroborated):
        bad = copy.deepcopy(wrong_discovery)
        bad["evidence"]["skipped"] = [
            {"name": DISCOVERY_SUBJECT, "reason": SHARED_OVERLAY_UNCERTAINTY}
        ]
        rejected(lambda bad=bad: validate_lane13_knative_metrics(bad, {"C_Initialize": 1}))
    print("lane13 manifest-only shared overlay is exact: OK")
    print("lane13 rejects widened skips, discovery, modes, and concrete gaps: OK")
    print("lane13 rejects nested skips, provenance, malformed scalars, and aliases: OK")
    print("lane13 rejects nested overlays and malformed build IDs: OK")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "observed.json"
        expected = Path(directory) / "expected.txt"
        output.write_text(json.dumps(lane13), encoding="utf-8")
        expected.write_text("C_Initialize 1\n", encoding="utf-8")
        main(["lane13-knative-metrics", str(output), str(expected)])
        rejected(
            lambda: main(
                ["lane13-knative-metrics", str(output), str(expected), "2"]
            )
        )
    print("lane13 rejects a multiplier argument: OK")
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
    proxy_id = {key: PROXY_MODULE_FIXTURE[key] for key in ("dev", "ino", "sha256")}
    soft_id = {key: MODULE_FIXTURE[key] for key in ("dev", "ino", "sha256")}
    proxy["capture"]["modules"].append(dict(PROXY_MODULE_FIXTURE))
    proxy["evidence"]["discovery"].append(
        dict(
            PROXY_MODULE_FIXTURE,
            objects=[
                dict(
                    PROXY_MODULE_FIXTURE,
                    identity_source="mountinfo",
                    note=None,
                    sources=["scan"],
                )
            ],
            sources=["scan"],
            corroborated=False,
            corroboration=["single_source"],
            tables=[
                {
                    "version": [3, 2],
                    "entries": PROXY_TABLE_ENTRIES,
                    "source": "scan",
                    "file_offset": 0x2000 + index * 840,
                    "linkage": "heuristic",
                }
                for index in range(PROXY_TABLES)
            ],
            interfaces=0,
            skipped=[],
        )
    )
    # The bounded module's decode survives the K=4 cap, so the capture keeps
    # its surfaces and counts their entries on top of the attached 68.
    proxy["evidence"]["surfaces"][0]["source"] = f"{soft_path} table 2.40"
    proxy["evidence"]["surfaces"] += [
        {
            "walk": "full",
            "functions": PROXY_TABLE_ENTRIES,
            "acquisition": "ok",
            "source": f"{PROXY_MODULE_FIXTURE['path']} table 3.2",
        }
        for _ in range(PROXY_TABLES)
    ]
    proxy["evidence"].update(
        table_entries=68 + PROXY_DECODED_ENTRIES,
        slots=68 + PROXY_ADMITTED_SLOTS,
        attached_probes=2 * (68 + PROXY_ADMITTED_SLOTS),
        discovery_uncorroborated_candidates=PROXY_SPILL,
        skipped=[],
    )
    proxy["functions"] = function_items(
        [(["unknown"], 1)] + [(["unknown"], 0)] * 67
    ) + function_items(
        [(["unknown"], 1)] + [(["unknown"], 0)] * (PROXY_ADMITTED_SLOTS - 1),
        identity=proxy_id,
    )
    validate_proxy_capacity_fallback(proxy, module_path=soft_path)
    # The lane pins its own module by exact path, so a capture that attached
    # some other SoftHSM2 build is not this lane's evidence.
    rejected(
        lambda: validate_proxy_capacity_fallback(
            proxy, module_path="/opt/softhsm/libsofthsm2.so"
        )
    )
    for mutate in (
        lambda d: d["evidence"]["discovery"][1]["objects"][0].update(
            path=soft_path, ino=999
        ),
        lambda d: d["evidence"]["skipped"].append(dict(DISCOVERY_SKIP)),
        lambda d: d["evidence"].update(event_loss=1),
        lambda d: d["evidence"]["modules_skipped"].append(
            {"name": "whole refusal", "reason": "stale shape"}
        ),
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["evidence"].update(completeness="COMPLETE"),
        lambda d: d["evidence"].update(slots=68 + PROXY_ADMITTED_SLOTS - 1),
        lambda d: [item.update(calls=0) for item in d["functions"]],
        # Audit F6: complete call loss on one provider is not two-provider
        # coverage, even with the other provider's call still present.
        lambda d: [item.update(calls=0) for item in d["functions"][68:]],
        lambda d: d["functions"][0].update(calls=0),
        # The K=4 spill is exact in both directions.
        lambda d: d["evidence"].update(discovery_uncorroborated_candidates=PROXY_SPILL - 1),
        lambda d: d["evidence"].update(discovery_uncorroborated_candidates=PROXY_SPILL + 1),
        # A decoded table dropped from history, or relabeled as linked.
        lambda d: d["evidence"]["discovery"][1]["tables"].pop(),
        lambda d: d["evidence"]["discovery"][1]["tables"][0].update(linkage="manifest"),
        # The bounded module's decode is dropped rather than retained — the
        # cap bounds attachment, never discovery.
        lambda d: d["evidence"].update(
            table_entries=68,
            surfaces=[s for s in d["evidence"]["surfaces"] if s["functions"] == 68],
        ),
        # ... or kept as surfaces but not counted, or miscounted either way.
        lambda d: d["evidence"].update(table_entries=68),
        lambda d: d["evidence"].update(table_entries=68 + PROXY_DECODED_ENTRIES + 1),
        lambda d: d["evidence"]["surfaces"].pop(),
        # A surface neither module owns is a gap, never an allowance.
        lambda d: d["evidence"]["surfaces"][-1].update(source="/usr/lib/other.so table 3.2"),
        # A labeled slot in a scan-only capture is a mislabel, not evidence.
        lambda d: d["functions"][0].update(names=["C_Initialize"]),
        # A proxy slot reattributed to SoftHSM2 breaks the per-module split.
        lambda d: d["functions"][68].update(module=dict(soft_id)),
        # A target both providers publish is attached once: two probes per
        # slot, one reported function per slot.
        lambda d: d["evidence"].update(attached_probes=2 * (68 + PROXY_ADMITTED_SLOTS) + 1),
        lambda d: d["functions"].pop(),
    ):
        bad = copy.deepcopy(proxy)
        mutate(bad)
        rejected(lambda bad=bad: validate_proxy_capacity_fallback(bad))
    # Audit F8: every other admitted 3.x family is accepted when it is
    # internally consistent — same table count, one shape, K=4 spill, and
    # the slot/surface/call counts that shape implies.
    for shape in ((3, 0), (3, 1)):
        entries = ADMITTED_PROXY_TABLE_SHAPES[shape]["entries"]
        admitted = ADMITTED_PROXY_TABLE_SHAPES[shape]["admitted_slots"]
        older = copy.deepcopy(proxy)
        for table in older["evidence"]["discovery"][1]["tables"]:
            table["version"] = list(shape)
            table["entries"] = entries
        for surface in older["evidence"]["surfaces"][1:]:
            surface["functions"] = entries
            surface["source"] = surface["source"].replace("table 3.2", f"table {shape[0]}.{shape[1]}")
        older["evidence"].update(
            table_entries=68 + PROXY_TABLES * entries,
            slots=68 + admitted,
            attached_probes=2 * (68 + admitted),
        )
        older["functions"] = older["functions"][: 68 + admitted]
        validate_proxy_capacity_fallback(older)
        # ... but the pin stays exact per shape: a mixed build, a version
        # with the wrong entry count, an undeclared version, the wrong
        # admitted slots for the shape, and a malformed version all fail.
        mixed = copy.deepcopy(older)
        mixed["evidence"]["discovery"][1]["tables"][0]["version"] = [3, 2]
        mixed["evidence"]["discovery"][1]["tables"][0]["entries"] = PROXY_TABLE_ENTRIES
        rejected(lambda mixed=mixed: validate_proxy_capacity_fallback(mixed))
        for mutate in (
            lambda d: d["evidence"]["discovery"][1]["tables"][0].update(entries=PROXY_TABLE_ENTRIES),
            lambda d: [table.update(version=[3, 9]) for table in d["evidence"]["discovery"][1]["tables"]],
            lambda d: d["evidence"].update(slots=68 + PROXY_ADMITTED_SLOTS),
            lambda d: d["evidence"]["discovery"][1]["tables"][0].update(version="3.0"),
        ):
            bad = copy.deepcopy(older)
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

    safe32 = copy.deepcopy(safe)
    safe32["evidence"]["surfaces"].extend(
        [
            {
                "walk": "full",
                "functions": functions,
                "acquisition": "ok",
                "source": f"/opt/p11.so table {major}.{minor}",
            }
            for major, minor, functions in ((3, 1, 92), (3, 2, 104))
        ]
    )
    safe32["evidence"]["discovery"][0]["tables"].extend(
        [
            {"source": "scan", "version": [3, 1], "entries": 92},
            {"source": "scan", "version": [3, 2], "entries": 104},
        ]
    )
    safe32["evidence"]["discovery"][0].update(
        corroborated=True,
        corroboration=["agreed"],
    )
    safe32["evidence"]["discovery_conflicts"] = 0
    validate_canary("default-safe-profile", safe32, 32)
    rejected(lambda: validate_canary("default-safe-profile", safe32, 64))
    rejected(lambda: validate_canary("default-safe-profile", safe, 32))
    for label, mutate in (
        ("missing ia32 scan table", lambda d: d["evidence"]["discovery"][0]["tables"].pop()),
        (
            "extra ia32 scan table",
            lambda d: d["evidence"]["discovery"][0]["tables"].append(
                {"source": "scan", "version": [3, 9], "entries": 104}
            ),
        ),
        (
            "relabeled ia32 scan table",
            lambda d: d["evidence"]["discovery"][0]["tables"][-1].update(source="manifest"),
        ),
    ):
        bad = copy.deepcopy(safe32)
        mutate(bad)
        rejected(lambda bad=bad: validate_canary("default-safe-profile", bad, 32))
    print("canary ABI-specific scan shapes and cross-width refusals: OK")

    for mutate in (
        lambda d: d["evidence"].pop("interface_selection"),
        lambda d: d["evidence"].update(attach_mechanisms=["secret-canary"]),
        lambda d: d.update(schema="p11scope/observed-profile/v2"),
    ):
        bad = copy.deepcopy(safe)
        mutate(bad)
        rejected(lambda bad=bad: validate_canary("default-safe-profile", bad))
    selection_doc = copy.deepcopy(safe)
    selection_doc["evidence"]["interface_selection"] = {
        "providers": [{"module": 0, "coverage": "observed"}],
        "standard_exports": [{"module": 0, "status": "present"}],
        "inventory_surfaces": [
            {"module": 0, "ordinal": 0, "kind": "legacy"},
            {"module": 0, "ordinal": 1, "kind": "interface"},
        ],
        "tuples": [{
            "module": 0,
            "request": {"name": "exact_standard", "version": "v3_0", "flags": 0},
            "rv": 0,
            "result": {"name": "exact_standard", "version": "v3_0", "flags": "zero"},
            "table_match": True,
            "inventory_matches": [
                {"surface": 0, "name_agrees": False, "version_agrees": True},
                {"surface": 1, "name_agrees": True, "version_agrees": True},
            ],
            "authority": "inventory",
            "count": U64_MAX,
        }],
        "selection_truncated": False,
    }
    exact_profile_v3_selection(selection_doc)
    for validator, live_document in (
        (exact_metrics_schema, clean),
        (exact_profile_v3_selection, selection_doc),
    ):
        for invalid in (True, "1", -1, U64_MAX + 1):
            bad = copy.deepcopy(live_document)
            bad["evidence"]["task_uprobe_link_losses"] = invalid
            rejected(lambda bad=bad, validator=validator: validator(bad))
        bad = copy.deepcopy(live_document)
        bad["evidence"].update(task_uprobe_link_losses=1, completeness="COMPLETE")
        rejected(lambda bad=bad, validator=validator: validator(bad))
    print("live profile-v3 and metrics-v3 task-uprobe loss typing and verdict gate are exact: OK")
    for validator, live_document in (
        (exact_metrics_schema, clean),
        (exact_capture_modules, clean),
        (exact_profile_v3_selection, selection_doc),
        (exact_capture_modules, selection_doc),
    ):
        for scope in ("pid", "cgroup", "system"):
            candidate = copy.deepcopy(live_document)
            candidate["capture"]["scope"] = scope
            validator(candidate)
        for invalid in (
            None, False, 4242, ["pid"], {"scope": "pid"}, "",
            "unknown", "pid:424242991", "/sys/fs/cgroup/private.scope",
        ):
            bad = copy.deepcopy(live_document)
            bad["capture"]["scope"] = invalid
            rejected(lambda bad=bad, validator=validator: validator(bad))
        missing = copy.deepcopy(live_document)
        del missing["capture"]["scope"]
        rejected(lambda validator=validator: validator(missing))
    print("capture.scope is exactly pid, cgroup, or system on current profile and metrics: OK")
    run_profile = copy.deepcopy(selection_doc)
    run_profile["evidence"]["child_still_running"] = False
    exact_profile_v3_selection(run_profile, run=True)
    run_trace = copy.deepcopy(run_profile["evidence"])
    run_trace.update(
        privacy_mode="allowlisted", capture_aborted=None, final_drain=False,
        counters_available=True, trace_truncated=False,
    )
    exact_profile_v3_selection(run_trace, terminal=True, run=True)
    external_pid = copy.deepcopy(run_profile)
    rejected(lambda: exact_profile_v3_selection(external_pid, run=False))
    unreadable_match = copy.deepcopy(selection_doc)
    unreadable_tuple = unreadable_match["evidence"]["interface_selection"]["tuples"][0]
    unreadable_tuple["result"]["name"] = "unreadable"
    unreadable_tuple["inventory_matches"][1]["name_agrees"] = False
    unreadable_tuple["authority"] = "none"
    exact_profile_v3_selection(unreadable_match)
    null_name_match = copy.deepcopy(unreadable_match)
    null_name_match["evidence"]["interface_selection"]["tuples"][0]["result"]["name"] = "null"
    exact_profile_v3_selection(null_name_match)
    unreadable_version = copy.deepcopy(selection_doc)
    unreadable_tuple = unreadable_version["evidence"]["interface_selection"]["tuples"][0]
    unreadable_tuple["result"]["version"] = "unreadable"
    for match in unreadable_tuple["inventory_matches"]:
        match["version_agrees"] = False
    unreadable_tuple["authority"] = "none"
    exact_profile_v3_selection(unreadable_version)
    for coverage in sorted(SELECTION_COVERAGE):
        candidate = copy.deepcopy(selection_doc)
        candidate["evidence"]["interface_selection"]["providers"][0]["coverage"] = coverage
        candidate["evidence"]["completeness"] = "PARTIAL"
        exact_profile_v3_selection(candidate)
    for status in sorted(STANDARD_EXPORT_STATUS):
        candidate = copy.deepcopy(selection_doc)
        candidate["evidence"]["interface_selection"]["standard_exports"][0]["status"] = status
        candidate["evidence"]["completeness"] = "PARTIAL"
        exact_profile_v3_selection(candidate)
    for name in sorted(SELECTION_NAME_CLASSES):
        candidate = copy.deepcopy(selection_doc)
        tuple_ = candidate["evidence"]["interface_selection"]["tuples"][0]
        tuple_.update(rv=1, result=None, table_match=False, inventory_matches=[], authority="none")
        tuple_["request"]["name"] = name
        exact_profile_v3_selection(candidate)
    for version_class in sorted(SELECTION_VERSION_CLASSES):
        candidate = copy.deepcopy(selection_doc)
        tuple_ = candidate["evidence"]["interface_selection"]["tuples"][0]
        tuple_.update(rv=1, result=None, table_match=False, inventory_matches=[], authority="none")
        tuple_["request"]["version"] = version_class
        exact_profile_v3_selection(candidate)
    for field, classes in (("name", SELECTION_NAME_CLASSES),
                           ("version", SELECTION_VERSION_CLASSES)):
        for class_ in sorted(classes):
            candidate = copy.deepcopy(selection_doc)
            tuple_ = candidate["evidence"]["interface_selection"]["tuples"][0]
            tuple_.update(table_match=False, inventory_matches=[], authority="none")
            tuple_["result"][field] = class_
            candidate["evidence"]["completeness"] = "PARTIAL"
            exact_profile_v3_selection(candidate)
    for mutate in (
        lambda d: d["evidence"]["interface_selection"].update(secret="canary"),
        lambda d: d["evidence"]["interface_selection"]["providers"].append(
            {"module": 0, "coverage": "observed"}
        ),
        lambda d: d["evidence"]["interface_selection"]["providers"][0].update(module=1),
        lambda d: d["evidence"]["interface_selection"]["providers"][0].update(coverage="secret-canary"),
        lambda d: d["evidence"]["interface_selection"]["standard_exports"][0].update(status="unknown"),
        lambda d: d["evidence"]["interface_selection"]["inventory_surfaces"].reverse(),
        lambda d: d["evidence"]["interface_selection"]["inventory_surfaces"][1].update(ordinal=0),
        lambda d: d["evidence"]["interface_selection"]["tuples"].__imul__(17),
        lambda d: d["evidence"]["interface_selection"]["tuples"].append(
            copy.deepcopy(d["evidence"]["interface_selection"]["tuples"][0])
        ),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0].update(count=0),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0]["request"].update(name="secret-canary"),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0].update(result=None),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0].update(authority="none"),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0]["inventory_matches"].reverse(),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0]["inventory_matches"][0].update(surface=2),
        lambda d: d["evidence"]["interface_selection"]["tuples"][0]["inventory_matches"][0].update(name_agrees=True),
        lambda d: d["evidence"].update(pid_descendant_gaps=-1),
        lambda d: d["evidence"].update(multi_rebuild_gaps=U64_MAX + 1),
    ):
        bad = copy.deepcopy(selection_doc)
        mutate(bad)
        rejected(lambda bad=bad: exact_profile_v3_selection(bad))
    unordered = copy.deepcopy(selection_doc)
    failed = copy.deepcopy(unordered["evidence"]["interface_selection"]["tuples"][0])
    failed.update(rv=5, result=None, table_match=False, inventory_matches=[], authority="none", count=1)
    unordered["evidence"]["interface_selection"]["tuples"].append(failed)
    unordered["evidence"]["interface_selection"]["tuples"].sort(
        key=selection_tuple_key, reverse=True
    )
    rejected(lambda: exact_profile_v3_selection(unordered))
    bad_unreadable = copy.deepcopy(unreadable_match)
    bad_unreadable["evidence"]["interface_selection"]["tuples"][0]["inventory_matches"][1]["name_agrees"] = True
    rejected(lambda: exact_profile_v3_selection(bad_unreadable))
    unreadable_authority = copy.deepcopy(unreadable_match)
    unreadable_authority["evidence"]["interface_selection"]["tuples"][0]["authority"] = "inventory"
    rejected(lambda: exact_profile_v3_selection(unreadable_authority))
    authority_none = copy.deepcopy(selection_doc)
    authority_none_tuple = authority_none["evidence"]["interface_selection"]["tuples"][0]
    authority_none_tuple.update(table_match=False, inventory_matches=[], authority="none")
    authority_none["evidence"]["completeness"] = "COMPLETE"
    rejected(lambda: exact_profile_v3_selection(authority_none))
    unreadable_match["evidence"]["completeness"] = "COMPLETE"
    rejected(lambda: exact_profile_v3_selection(unreadable_match))
    semantic_duplicate = copy.deepcopy(selection_doc)
    original = semantic_duplicate["evidence"]["interface_selection"]["tuples"][0]
    reordered = {key: original[key] for key in reversed(original)}
    semantic_duplicate["evidence"]["interface_selection"]["tuples"] = [original, reordered]
    semantic_duplicate["evidence"]["interface_selection"]["tuples"].sort(
        key=selection_tuple_key
    )
    rejected(lambda: exact_profile_v3_selection(semantic_duplicate))
    extra_profile = copy.deepcopy(selection_doc)
    extra_profile["evidence"]["secret_selection_payload"] = "CANARY"
    rejected(lambda: exact_profile_v3_selection(extra_profile))
    sixteen = copy.deepcopy(selection_doc)
    sixteen["evidence"]["interface_selection"]["tuples"] = []
    for rv in range(1, 17):
        tuple_ = copy.deepcopy(selection_doc["evidence"]["interface_selection"]["tuples"][0])
        tuple_.update(rv=rv, result=None, table_match=False, inventory_matches=[], authority="none", count=U64_MAX)
        sixteen["evidence"]["interface_selection"]["tuples"].append(tuple_)
    sixteen["evidence"]["interface_selection"]["tuples"].sort(key=selection_tuple_key)
    exact_profile_v3_selection(sixteen)
    surface_bound = copy.deepcopy(selection_doc)
    surface_bound["evidence"]["interface_selection"].update(
        inventory_surfaces=[
            {"module": 0, "ordinal": ordinal, "kind": "interface"}
            for ordinal in range(512)
        ],
        tuples=[],
    )
    exact_profile_v3_selection(surface_bound)
    surface_overflow = copy.deepcopy(surface_bound)
    surface_overflow["evidence"]["interface_selection"]["inventory_surfaces"].append(
        {"module": 0, "ordinal": 512, "kind": "interface"}
    )
    rejected(lambda: exact_profile_v3_selection(surface_overflow))
    module_bound = copy.deepcopy(selection_doc)
    module_bound["evidence"]["discovery"] = [
        copy.deepcopy(selection_doc["evidence"]["discovery"][0]) for _ in range(512)
    ]
    module_bound["evidence"]["interface_selection"].update(
        providers=[{"module": module, "coverage": "observed"} for module in range(512)],
        standard_exports=[{"module": module, "status": "present"} for module in range(512)],
        inventory_surfaces=[], tuples=[],
    )
    exact_profile_v3_selection(module_bound)
    for field, record in (
        ("providers", {"module": 512, "coverage": "observed"}),
        ("standard_exports", {"module": 512, "status": "present"}),
    ):
        overflow = copy.deepcopy(module_bound)
        overflow["evidence"]["discovery"].append(
            copy.deepcopy(selection_doc["evidence"]["discovery"][0])
        )
        overflow["evidence"]["interface_selection"][field].append(record)
        rejected(lambda overflow=overflow: exact_profile_v3_selection(overflow))
    for mechanisms in ([], ["per-offset"], ["uprobe-multi"], ["per-offset", "uprobe-multi"]):
        candidate = copy.deepcopy(selection_doc)
        candidate["evidence"]["attached_probes"] = 0 if not mechanisms else 2
        candidate["evidence"]["attach_mechanisms"] = mechanisms
        exact_profile_v3_selection(candidate)
    for mechanisms in (["per-offset", "per-offset"], ["uprobe-multi", "per-offset"]):
        candidate = copy.deepcopy(selection_doc)
        candidate["evidence"]["attach_mechanisms"] = mechanisms
        rejected(lambda candidate=candidate: exact_profile_v3_selection(candidate))
    two_modules = copy.deepcopy(selection_doc)
    two_modules["evidence"]["discovery"].append(copy.deepcopy(two_modules["evidence"]["discovery"][0]))
    two_modules["evidence"]["interface_selection"]["inventory_surfaces"][1]["module"] = 1
    rejected(lambda: exact_profile_v3_selection(two_modules))
    count_only = copy.deepcopy(selection_doc)
    tuple_ = count_only["evidence"]["interface_selection"]["tuples"][0]
    tuple_.update(table_match=False, inventory_matches=[], authority="selection_count_only")
    count_only["evidence"]["completeness"] = "PARTIAL"
    exact_profile_v3_selection(count_only)
    for mutate in (
        lambda t: t["request"].update(name="other"),
        lambda t: t["result"].update(name="other"),
        lambda t: t["result"].update(version="v2_40"),
        lambda t: t["result"].update(flags="other"),
        lambda t: t["result"].update(flags=0),
    ):
        invalid = copy.deepcopy(count_only)
        mutate(invalid["evidence"]["interface_selection"]["tuples"][0])
        rejected(lambda invalid=invalid: exact_profile_v3_selection(invalid))
    no_authority = copy.deepcopy(selection_doc)
    no_authority_tuple = no_authority["evidence"]["interface_selection"]["tuples"][0]
    no_authority_tuple.update(table_match=False, inventory_matches=[], authority="none")
    no_authority["evidence"]["completeness"] = "PARTIAL"
    for authority, candidate in {
        "inventory": selection_doc,
        "selection_count_only": count_only,
        "none": no_authority,
    }.items():
        require(candidate["evidence"]["interface_selection"]["tuples"][0]["authority"] == authority,
                f"authority fixture mismatch: {authority}")
        exact_profile_v3_selection(candidate)
    overflow_count = copy.deepcopy(selection_doc)
    overflow_count["evidence"]["interface_selection"]["tuples"][0]["count"] = U64_MAX + 1
    rejected(lambda: exact_profile_v3_selection(overflow_count))
    full_width = copy.deepcopy(no_authority)
    full_width_tuple = full_width["evidence"]["interface_selection"]["tuples"][0]
    full_width_tuple["request"]["flags"] = U64_MAX
    full_width_tuple["result"]["flags"] = "other"
    exact_profile_v3_selection(full_width)
    # A raw result flags word (here a hostile "SECRET!!" sentinel) is never
    # accepted: only the finite class may be published.
    for raw in (0, 1, 0x5345_4352_4554_2121, U64_MAX):
        leaked = copy.deepcopy(full_width)
        leaked["evidence"]["interface_selection"]["tuples"][0]["result"]["flags"] = raw
        rejected(lambda leaked=leaked: exact_profile_v3_selection(leaked))
    full_width_rv = copy.deepcopy(selection_doc)
    full_width_rv_tuple = full_width_rv["evidence"]["interface_selection"]["tuples"][0]
    full_width_rv_tuple.update(
        rv=U64_MAX, result=None, table_match=False, inventory_matches=[], authority="none",
    )
    exact_profile_v3_selection(full_width_rv)
    for field, value in (
        ("request.flags", U64_MAX + 1), ("request.flags", True),
        ("result.flags", U64_MAX + 1), ("result.flags", True), ("result.flags", "fork-safe"),
        ("rv", U64_MAX + 1), ("rv", True),
    ):
        invalid = copy.deepcopy(selection_doc)
        tuple_ = invalid["evidence"]["interface_selection"]["tuples"][0]
        if field == "request.flags":
            tuple_["request"]["flags"] = value
        elif field == "result.flags":
            tuple_["result"]["flags"] = value
        else:
            tuple_["rv"] = value
        rejected(lambda invalid=invalid: exact_profile_v3_selection(invalid))
    allowlist = Path("docs/privacy/allowlist-v2.md").read_text(encoding="utf-8")
    expected_matrix = [
        f"| {selector * 2 + flags} | selector {selector} | {flags} | "
        f"`{'null' if selector == 0 else 'exact_standard'}` | "
        f"`{('null', 'null', 'v3_0', 'v3_1', 'v3_2')[selector]}` |"
        for selector in range(5) for flags in range(2)
    ]
    require(selection_matrix_rows(allowlist) == expected_matrix,
            "allowlist-v2 selector matrix is not exact")
    for extra_row in (
        "| 10 | selector 4 | 1 | `exact_standard` | `v3_2` |",
        "| malformed | selector 0 | 0 | `null` | `null` |",
    ):
        widened = allowlist.replace(expected_matrix[-1], expected_matrix[-1] + "\n" + extra_row)
        rejected(lambda widened=widened: require(
            selection_matrix_rows(widened) == expected_matrix,
            "widened allowlist-v2 selector matrix",
        ))
    normalized_allowlist = " ".join(allowlist.split())
    for statement in (
        "`selection_evidence` has exactly `acquisition`, `queries`, `tables`, and `selection_truncated`.",
        "For `export_absent` and `export_outside_module`, `queries` and `tables` are empty and `selection_truncated` is false.",
        "For `queried`, `queries` contains exactly the ten rows above and `selection_truncated` is boolean.",
        "Each row has exactly `selector`, `request`, `rv`, `result`, `inventory_matches`, `selection_table`, `authority`, and `helper_failure`.",
        "`null_output` and `unreadable_interface` require `result=null`.",
        "A successful query with `result=null` permits only `null_output`, `unreadable_interface`, or `provider_changed`.",
        "Only `unreadable_name`, `unreadable_version`, `unreadable_table`, `outside_provider`, `unresolved_function`, and `provider_changed` may coexist with a factual non-null result.",
        "With a factual non-null result, `unreadable_name` requires a `null` or `unreadable` result name; `unreadable_version` requires an `unreadable` result version; and `unreadable_table` requires a `null`, `v3_0`, `v3_1`, or `v3_2` result version.",
        "`inventory_matches` is a sorted, unique array of at most 16 exact `{surface, name_agrees, version_agrees}` records.",
        "Authority is exactly `inventory`, `selection_count_only`, or `none`.",
        "That failure class is exactly `null_output`, `unreadable_interface`, `unreadable_name`, `unreadable_version`, `unreadable_table`, `outside_provider`, `unresolved_function`, or `provider_changed`.",
        "Each table id is an integer from 0 through 9, its version is 3.0, 3.1, or 3.2, its walk is exactly `full`, and it contains at most 104 function records with `semantic_authorized=false`.",
        "A selector is an integer from 0 through 4 and request flags are exactly 0 or 1.",
    ):
        require(statement in normalized_allowlist,
                f"allowlist-v2 omits exact relation: {statement}")
    loss = copy.deepcopy(selection_doc)
    loss["evidence"]["interface_selection"]["providers"][0]["coverage"] = "observed_uncovered"
    loss["evidence"]["completeness"] = "COMPLETE"
    rejected(lambda: exact_profile_v3_selection(loss))
    print("profile-v3 selection fields, bounds, order, enums, cross-references, and loss verdict are exact: OK")
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
    gated_null = copy.deepcopy(bounded_skips)
    gated_null["skipped"] = [dict(UNKNOWN_NULL_SKIP)]
    discovery_skips(gated_null)
    require(
        entry_skips(gated_null) == [dict(UNKNOWN_NULL_SKIP)],
        f"gated null is not an entry oracle item: {entry_skips(gated_null)}",
    )
    require(
        discovery_skips(gated_null) == [],
        f"gated null leaks into discovery skips: {discovery_skips(gated_null)}",
    )
    for wrong_reason in (DISCOVERY_UNAVAILABLE, TABLE_UNAVAILABLE, ENTRY_UNAVAILABLE):
        bad = copy.deepcopy(bounded_skips)
        bad["skipped"] = [{"name": "unknown", "reason": wrong_reason}]
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
        schema=METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    aggregate["functions"] = function_items([(["C_GetInterfaceList"], 28)])
    validate_canary("aggregate-only-metrics", aggregate)
    bad = copy.deepcopy(aggregate)
    bad["functions"][0]["calls"] = 24
    rejected(lambda: validate_canary("aggregate-only-metrics", bad))
    print("canary aggregate exact baseline: OK")

    owned_aggregate = copy.deepcopy(aggregate)
    owned_aggregate["functions"] = function_items([(["C_GetInterfaceList"], 30)])
    owned_aggregate["evidence"]["child_still_running"] = False
    # The one skip an owned lane must publish: `p11scope run` attempts
    # initial-set discovery and the empty timing catalog leaves it unproven.
    owned_aggregate["evidence"]["skipped"] = [
        {"name": DISCOVERY_SUBJECT, "reason": DISCOVERY_UNAVAILABLE}
    ]
    for lane in ("owned-default-metrics", "owned-feature-metrics"):
        validate_canary(lane, owned_aggregate)
        for calls in (28, 29, 31):
            bad = copy.deepcopy(owned_aggregate)
            bad["functions"][0]["calls"] = calls
            rejected(lambda bad=bad, lane=lane: validate_canary(lane, bad))
        for mutate in (
            lambda d: d["evidence"].pop("child_still_running"),
            lambda d: d["evidence"].update(child_still_running=True),
            lambda d: d["evidence"].update(
                pause="sigstop", pause_attempts=1, pause_confirmed=1),
            # The owned skip floor is exact, not merely permitted: an owned
            # lane that published none is not a cleaner run, it is a run
            # whose initial-set attempt went unreported. (The ceiling —
            # floor plus at most one retained refusal — is covered below.)
            lambda d: d["evidence"].update(skipped=[]),
            lambda d: d["evidence"].update(skipped=[
                {"name": DISCOVERY_SUBJECT, "reason": TABLE_UNAVAILABLE}]),
        ):
            bad = copy.deepcopy(owned_aggregate)
            mutate(bad)
            rejected(lambda bad=bad, lane=lane: validate_canary(lane, bad))
    external_owned = copy.deepcopy(aggregate)
    external_owned["evidence"]["child_still_running"] = False
    rejected(lambda: validate_canary("aggregate-only-metrics", external_owned))
    print("canary owned aggregate exact30 run contract: OK")

    # A retained P-2 bracket refusal publishes byte-identical to the
    # initial-set skip: an owned lane may carry two categorical skips and a
    # safe lane one. Anything else — a third skip on owned, a second on
    # safe, or any non-categorical item — still fails.
    two_skips = copy.deepcopy(owned_aggregate)
    two_skips["evidence"]["skipped"] = [
        dict(CANARY_DISCOVERY_SKIP) for _ in range(2)
    ]
    for lane in ("owned-default-metrics", "owned-feature-metrics"):
        validate_canary(lane, two_skips)
    safe_refusal = copy.deepcopy(safe)
    safe_refusal["evidence"]["skipped"] = [dict(CANARY_DISCOVERY_SKIP)]
    validate_canary("default-safe-profile", safe_refusal)
    for lane, doc, extras in (
        ("owned-default-metrics", owned_aggregate, 3),
        ("default-safe-profile", safe, 2),
    ):
        for mutate in (
            lambda d, n=extras: d["evidence"].update(skipped=[
                dict(CANARY_DISCOVERY_SKIP) for _ in range(n)]),
            lambda d: d["evidence"].update(skipped=[
                dict(CANARY_DISCOVERY_SKIP), dict(DISCOVERY_SKIP)]),
        ):
            bad = copy.deepcopy(doc)
            mutate(bad)
            rejected(lambda bad=bad, lane=lane: validate_canary(lane, bad))
    bad = copy.deepcopy(safe)
    bad["evidence"]["skipped"] = [dict(DISCOVERY_SKIP)]
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary retained-refusal skip shapes: OK")

    induced = {}
    g1 = evidence_fixture(G1_SURFACES, sources=("scan", "manifest"))
    g1.update(
        table_entries=161,
        slots=93,
        attached_probes=186,
        vendor_interfaces=1,
        interface_list="ok",
        aliased=[["C_CancelFunction", "C_WaitForSlotEvent"]],
        skipped=[{"name": "C_GetFunctionStatus", "reason": "null pointer"}] * 2,
    )
    induced["G1"] = document_fixture(g1)
    g2 = evidence_fixture(LEGACY_SURFACES + LEGACY_SURFACES, sources=("scan", "manifest"))
    g2.update(
        table_entries=68,
        slots=2,
        attached_probes=4,
        in_flight_at_end=1,
        aliased=[[f"C_Alias_{index}" for index in range(67)]],
    )
    induced["G2"] = document_fixture(g2)
    g3 = evidence_fixture(LEGACY_SURFACES + LEGACY_SURFACES, sources=("scan", "manifest"))
    g3.update(
        table_entries=68,
        slots=68,
        attached_probes=136,
        event_loss=1,
        unmatched_closes=1,
        # The one lost event dropped while the capture loop ran, before the
        # detach window opened.
        scheduling=scheduling_fixture(capture_event_loss=1),
    )
    induced["G3"] = document_fixture(g3)
    induced["G3"]["functions"] = function_items(
        [([name], calls) for name, calls in G3_COUNTS.items()]
    )
    g4 = copy.deepcopy(version)
    g4.update(in_flight_at_end=9, start_insert_failures=8)
    induced["G4"] = document_fixture(g4)
    g5 = copy.deepcopy(version)
    g5.update(rv_update_failures=9, unregistered_mechanisms=6, async_orphans=1)
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

    bad = copy.deepcopy(induced["G3"])
    del bad["capture"]["ring_bytes"]
    rejected(lambda: validate_induced("G3", bad))
    bad = copy.deepcopy(induced["G3"])
    bad["capture"]["ring_bytes"] = 5000
    rejected(lambda: validate_induced("G3", bad))
    bad = copy.deepcopy(induced["G3"])
    bad["capture"]["ring_bytes"] = 2048
    rejected(lambda: validate_induced("G3", bad))
    bad = copy.deepcopy(induced["G3"])
    del bad["capture"]["drain_interval_ms"]
    rejected(lambda: validate_induced("G3", bad))
    bad = copy.deepcopy(induced["G3"])
    bad["capture"]["drain_interval_ms"] = 0
    rejected(lambda: validate_induced("G3", bad))
    bad = copy.deepcopy(induced["G3"])
    bad["capture"]["drain_interval_ms"] = "1000"
    rejected(lambda: validate_induced("G3", bad))
    print("induced lanes require disclosed ring_bytes/drain_interval_ms: OK")

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
        ("semantic_history_drops", 1),
        ("rv_update_failures", 1),
        ("abi_refusals", 1),
    ):
        bad = copy.deepcopy(clean["evidence"])
        bad[field] = value
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    # U-14 through exact_common: terminal_capture_is_clean reaches the shared
    # active_slots bound through exact_common, never exact_evidence_keys — an
    # active set larger than the allocation it is drawn from is rejected.
    overflowed_common = copy.deepcopy(clean["evidence"])
    overflowed_common["active_slots"] = overflowed_common["slots"] + 1
    rejected(lambda: terminal_capture_is_clean(overflowed_common))
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
    # capture-lifetime fact is still reported. active_slots is not one of
    # those facts (U-14): a real exit retires every slot a scan-only target's
    # unpinned object held, so the exit document reports active_slots == 0
    # while slots keeps the historical allocation total.
    exited = copy.deepcopy(live)
    exited["evidence"].update(
        table_entries=68, slots=68, active_slots=0, attached_probes=136
    )
    exact_active_to_empty(exited)
    exact_metrics_schema(exited)
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
        # active_slots == 0 (the baseline `exited` reading) is not a defect —
        # only exceeding the allocated `slots` it is drawn from is.
        lambda d: d["evidence"].update(active_slots=d["evidence"]["slots"] + 1),
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["functions"][0].update(
            module=None, module_ambiguous=False, module_unresolved=False
        ),
    ):
        bad = copy.deepcopy(exited)
        mutate(bad)
        rejected(lambda bad=bad: exact_active_to_empty(bad))
    print("active-to-empty keeps its history and declares every owner: OK")

    # The same bound applies to every document, not just the active-to-empty
    # lifecycle: exact_evidence_keys (reached via exact_metrics_schema here)
    # pins it once for every lane instead of every caller repeating it.
    overflowed = copy.deepcopy(exited)
    overflowed["evidence"]["active_slots"] = overflowed["evidence"]["slots"] + 1
    rejected(lambda: exact_metrics_schema(overflowed))
    negative_active_slots = copy.deepcopy(exited)
    negative_active_slots["evidence"]["active_slots"] = -1
    rejected(lambda: exact_metrics_schema(negative_active_slots))
    # A malformed `slots` must fail with a stated reason, not a raw TypeError
    # from the `<=` comparison exact_active_slots_bound also makes.
    non_integer_slots = copy.deepcopy(exited)
    non_integer_slots["evidence"]["slots"] = "68"
    rejected(lambda: exact_metrics_schema(non_integer_slots))
    print("active_slots is accepted at 0 after an exit and bounded by slots: OK")

    # ---- consumer scheduling (Task 3.1 repair) --------------------------
    # The loss splits are identities: capture + detach shares always sum to
    # the published loss counter, so a repair that misattributes fails here.
    scheduled = copy.deepcopy(clean)
    scheduled["evidence"]["event_loss"] = 10
    scheduled["evidence"]["scheduling"] = scheduling_fixture(
        capture_event_loss=6, detach_event_loss=4,
        drain_repolls=3, sink_dropped_bytes=0,
    )
    exact_scheduling_evidence(scheduled["evidence"])
    # A fully stamped run passes: ordered stamps plus a matching reason.
    stamped = copy.deepcopy(scheduled)
    stamped["evidence"]["scheduling"]["phase_mono_ns"] = {
        "attach_mono_ns": 100, "loop_start_mono_ns": 200,
        "loop_end_mono_ns": 300, "loop_end_reason": "expiry",
    }
    exact_scheduling_evidence(stamped["evidence"])
    for mutate in (
        lambda d: d["evidence"].pop("scheduling"),
        lambda d: d["evidence"]["scheduling"].pop("sink_policy"),
        lambda d: d["evidence"]["scheduling"].pop("phase_mono_ns"),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].pop(
            "loop_end_reason"),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            loop_end_reason="timeout"),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            attach_mono_ns=-1),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            attach_mono_ns=True),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            attach_mono_ns=300, loop_start_mono_ns=200,
            loop_end_mono_ns=400, loop_end_reason="expiry"),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            loop_end_mono_ns=300, loop_end_reason="unstarted"),
        lambda d: d["evidence"]["scheduling"]["phase_mono_ns"].update(
            loop_end_reason="expiry"),
        lambda d: d["evidence"]["scheduling"].update(sink_policy="drop-all"),
        lambda d: d["evidence"]["scheduling"].update(drain_repolls=-1),
        lambda d: d["evidence"]["scheduling"].update(drain_repolls=True),
        lambda d: d["evidence"]["scheduling"].update(
            terminal_drain_truncated="no"),
        lambda d: d["evidence"]["scheduling"].update(terminal_drain_bound=0),
        lambda d: d["evidence"]["scheduling"]["phase_ms"].pop("detach"),
        lambda d: d["evidence"]["scheduling"]["phase_ms"].update(
            discovery="fast"),
        lambda d: d["evidence"]["scheduling"]["phase_ms"].update(
            discovery_terminal="slow"),
        lambda d: d["evidence"]["scheduling"].update(extra_key=1),
        # Split identities: the shares must sum to the published counters.
        lambda d: d["evidence"]["scheduling"].update(detach_event_loss=5),
        lambda d: d["evidence"]["scheduling"].update(detach_discovery_loss=1),
        lambda d: d["evidence"].update(event_loss=11),
    ):
        bad = copy.deepcopy(scheduled)
        mutate(bad)
        rejected(lambda bad=bad: exact_scheduling_evidence(bad["evidence"]))
    print("scheduling evidence is exact and its loss splits are identities: OK")
    print("self-test: OK")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return
    require(len(argv) >= 1, "usage: check-capture-evidence.py MODE ...")
    if argv[0] == "lane13-knative-metrics" and len(argv) == 3:
        validate_lane13_knative_metrics(
            load_json(argv[1]),
            expected_counts(argv[2]),
        )
    elif argv[0] == "lane02-owned-run-metrics" and len(argv) == 4:
        validate_lane02_owned_run_metrics(
            load_json(argv[1]),
            expected_counts(argv[2]),
            argv[3],
        )
    elif argv[0] == "shared-layer-metrics" and len(argv) in (3, 4):
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
    elif argv[0] == "canary" and len(argv) in (3, 4):
        trace = argv[1].endswith("-trace")
        target_bits = 64 if len(argv) == 3 else int(argv[3])
        validate_canary(argv[1], load_canary(argv[2], trace), target_bits)
    elif argv[0] == "induced" and len(argv) == 3:
        validate_induced(argv[1], load_json(argv[2]))
    else:
        raise AssertionError(
            "usage: check-capture-evidence.py "
            "clean-metrics[-corroborated|-manifest-only] OUTPUT EXPECTED [MULTIPLIER] | "
            "shared-layer-metrics OUTPUT EXPECTED [MULTIPLIER] | "
            "lane13-knative-metrics OUTPUT EXPECTED | "
            "lane02-owned-run-metrics OUTPUT EXPECTED POLICY | "
            "canary LANE OUTPUT [32|64] | induced G[1-5] OUTPUT | --self-test"
        )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        print(f"capture evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
