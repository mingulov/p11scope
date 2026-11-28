#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Committed survivor dispositions for the guard-removal sweep.

Each row records a collected guard whose removal passes the committed
suite (verdict-identical on the corpus), with a cluster rationale
below. Rows are machine-checked every gate run: a row whose guard
starts failing (a kill appeared) fails as stale and must be promoted
to a kill; a row for a nonexistent guard fails as orphaned; a row on
a lane-owned guard fails (lane guards must be killed, never rowed);
a survivor without a row fails naming it. Guard IDs are content
hashes of the guard's first line: rewording a guard orphans its row
on purpose, forcing conscious review.

Row format: guard_id -> (category, cluster, note). The note carries
the gate evidence (green-under-removal plus refusal-fire counts from
the sweep corpus tracer).
"""

CLUSTERS = {
    "profile-selection": (
        "Staged profile-selection validator (70 guards over document "
        "shape): sequential field checks overlap by design, so most "
        "removals still refuse via sibling or downstream stages. Rows "
        "marked overlap fired during the corpus (another guard catches "
        "the same violations, proven by the green removal); rows marked "
        "untested never refused in the sweep corpus and may be covered "
        "by suites that call selection directly (caller_reasons, "
        "schema_json, discovery_retry, return_probe), unverified here. "
        "Per-guard message precision belongs to a profile-lane program."
    ),
    "detail-rows": (
        "Selection-detail row validators (per-row shape/lineage/count "
        "checks across many small functions). Staged overlap like "
        "profile-selection; untested rows cover rare row shapes no "
        "committed negative feeds invalidly. Same routing and ruling "
        "as profile-selection."
    ),
    "capture-modules": (
        "Capture/module agreement validators (modules vs discovery, "
        "semantics, ownership, fallbacks, identities, function "
        "targets). Removal still refuses via overlapping agreement "
        "stages; untested rows are failure modes no committed test "
        "feeds. Same routing as profile-selection."
    ),
    "scheduling": (
        "Scheduling-evidence validators (gap distribution, newcomer "
        "queue, resources, stage timing). Canary/induced documents "
        "carry valid scheduling evidence, so most failure modes are "
        "untested here; other lanes' suites exercise these validators "
        "directly (unverified row-by-row). Same routing as "
        "profile-selection."
    ),
    "counters": (
        "Counter validators (collection, banks, function timing). "
        "Overlapping count identities; untested rows are counter "
        "shapes no committed negative feeds. Same routing as "
        "profile-selection."
    ),
    "terminal-verdict": (
        "Terminal-verdict and gap-class derivation validators. "
        "Verdict consistency is redundantly checked (derivation plus "
        "comparison), so removals still refuse; untested rows cover "
        "verdict states the corpus never feeds invalidly. Same "
        "routing as profile-selection."
    ),
    "prearm": (
        "Prearm-key validators. Small staged checks with overlapping "
        "key/identity coverage; untested rows as above. Same routing "
        "as profile-selection."
    ),
    "evidence-keys": (
        "Evidence-shape key validators. Key presence is also enforced "
        "by downstream indexing (which would crash, not pass), so "
        "removals stay red-or-green-identically; untested rows as "
        "above. Same routing as profile-selection."
    ),
    "runtime-evidence": (
        "Runtime-evidence validators (rings, uprobe links, kernel "
        "control, stop quiescence, slots). Other lanes' evidence "
        "shapes carried validly by canary/induced documents; failure "
        "modes belong to owning suites. Same routing as "
        "profile-selection."
    ),
    "common": (
        "Shared common-evidence stages (history, skips, aliases). The "
        "call sites in lane validators are swept per-guard (stages "
        "cannot be dropped); internals overlap with per-stage checks. "
        "Same routing as profile-selection."
    ),
    "metrics-schema": (
        "Metrics-schema validators shared with metrics lanes. Same "
        "routing as profile-selection."
    ),
    "misc-platform": (
        "Long tail of small platform validators (caller reasons, "
        "deep scan, exit mappings, legacy collection, live/loader "
        "discovery, object capture, static hints, unmatched excludes, "
        "verdict classes, capture scope). Each row's note carries its "
        "own fire evidence; same routing as profile-selection."
    ),
    "trusted-base": (
        "Leaf predicates and skips with no invalid committed inputs "
        "in the sweep corpus. Removal is verdict-identical vacuously; "
        "latent holes would need dedicated negatives from owning "
        "suites. Same routing as profile-selection."
    ),
    "other-gate": (
        "Guards inside G1/G2/G3 lane branches of validate_induced, "
        "routed mechanically by the matrix-seam criterion. They belong "
        "to other gates' lanes; rows record verdict-identity here so "
        "nothing is silently uncovered."
    ),
}

DISPOSITIONS = {
    "bounded_skip:call:require:18415249cae1:0": ("platform-untested", "trusted-base", "r8 gate bounded_skip:4526 green-under-removal; fired 0x in corpus"),
    "bounded_skip:call:require:18415249cae1:1": ("platform-untested", "trusted-base", "r8 gate bounded_skip:4530 green-under-removal; fired 0x in corpus"),
    "exact_caller_reasons_overflow:call:exact_keys:ab312a89464b:0": ("platform-overlap", "misc-platform", "r8 gate exact_caller_reasons_overflow:2395 green-under-removal; callee fired 21x"),
    "exact_caller_reasons_overflow:call:require:058e5312decf:0": ("platform-untested", "misc-platform", "r8 gate exact_caller_reasons_overflow:2396 green-under-removal; fired 0x in corpus"),
    "exact_caller_reasons_overflow:call:require:f40df7c05564:0": ("platform-untested", "misc-platform", "r8 gate exact_caller_reasons_overflow:2398 green-under-removal; fired 0x in corpus"),
    "exact_capture_modules:call:exact_full_identity:52eee676981c:0": ("platform-overlap", "capture-modules", "r8 gate exact_capture_modules:5065 green-under-removal; callee fired 1x"),
    "exact_capture_modules:call:exact_module_ownership:1f87db89728c:0": ("platform-overlap", "capture-modules", "r8 gate exact_capture_modules:5057 green-under-removal; callee fired 14x"),
    "exact_capture_modules:call:exact_unnamed_reasons:7c5023c69a95:0": ("platform-overlap", "capture-modules", "r8 gate exact_capture_modules:5090 green-under-removal; callee fired 7x"),
    "exact_capture_modules:call:require:18415249cae1:2": ("platform-untested", "capture-modules", "r8 gate exact_capture_modules:5097 green-under-removal; fired 0x in corpus"),
    "exact_capture_modules:call:require:18415249cae1:3": ("platform-untested", "capture-modules", "r8 gate exact_capture_modules:5114 green-under-removal; fired 0x in corpus"),
    "exact_capture_modules:call:require:186944e454e2:0": ("platform-untested", "capture-modules", "r8 gate exact_capture_modules:5085 green-under-removal; fired 0x in corpus"),
    "exact_capture_modules:call:require:238f855e6fc7:0": ("platform-overlap", "capture-modules", "r8 gate exact_capture_modules:5059 green-under-removal; fired 1x in corpus"),
    "exact_capture_modules:call:require:41d79032a8bb:0": ("platform-untested", "capture-modules", "r8 gate exact_capture_modules:5103 green-under-removal; fired 0x in corpus"),
    "exact_capture_modules:call:require:df3bc7d3d5c9:0": ("platform-untested", "capture-modules", "r8 gate exact_capture_modules:5061 green-under-removal; fired 0x in corpus"),
    "exact_capture_scope:call:require:0d4f968fa211:0": ("platform-untested", "misc-platform", "r8 gate exact_capture_scope:3027 green-under-removal; fired 0x in corpus"),
    "exact_common:call:exact_full_identity:39ddcff792ff:0": ("platform-overlap", "common", "r8 gate exact_common:4926 green-under-removal; callee fired 1x"),
    "exact_common:call:exact_full_identity:52eee676981c:0": ("platform-overlap", "common", "r8 gate exact_common:4923 green-under-removal; callee fired 1x"),
    "exact_common:call:exact_live_discovery_evidence:8dc996478b70:0": ("platform-overlap", "common", "r8 gate exact_common:4917 green-under-removal; callee fired 18x"),
    "exact_common:call:exact_manifest_object_fallbacks:39794d6b539e:0": ("platform-overlap", "common", "r8 gate exact_common:4921 green-under-removal; callee fired 12x"),
    "exact_common:call:exact_sources:0dc99cacb522:0": ("platform-overlap", "common", "r8 gate exact_common:4924 green-under-removal; callee fired 2x"),
    "exact_common:call:exact_sources:47c8b61f0d13:0": ("platform-overlap", "common", "r8 gate exact_common:4927 green-under-removal; callee fired 2x"),
    "exact_common:call:require:18415249cae1:0": ("platform-untested", "common", "r8 gate exact_common:4899 green-under-removal; fired 0x in corpus"),
    "exact_common:call:require:193694b0cba4:0": ("platform-untested", "common", "r8 gate exact_common:4912 green-under-removal; fired 0x in corpus"),
    "exact_common:call:require:7f5f1d6e5a9b:0": ("platform-untested", "common", "r8 gate exact_common:4897 green-under-removal; fired 0x in corpus"),
    "exact_common:call:require:c3c49507ce93:0": ("platform-untested", "common", "r8 gate exact_common:4913 green-under-removal; fired 0x in corpus"),
    "exact_counter_bank_gaps:call:exact_keys:807a55f1e68b:0": ("platform-overlap", "counters", "r8 gate exact_counter_bank_gaps:2598 green-under-removal; callee fired 21x"),
    "exact_counter_bank_gaps:call:require:283dab64fced:0": ("platform-untested", "counters", "r8 gate exact_counter_bank_gaps:2602 green-under-removal; fired 0x in corpus"),
    "exact_counter_bank_gaps:call:require:350ec249526b:0": ("platform-untested", "counters", "r8 gate exact_counter_bank_gaps:2604 green-under-removal; fired 0x in corpus"),
    "exact_counter_bank_gaps:call:require:cbf8540f6b80:0": ("platform-untested", "counters", "r8 gate exact_counter_bank_gaps:2599 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:exact_counter_bank_gaps:12ad57f8d851:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2678 green-under-removal; callee fired 0x"),
    "exact_counter_collection:call:exact_keys:60d6dca5be12:0": ("platform-overlap", "counters", "r8 gate exact_counter_collection:2673 green-under-removal; callee fired 21x"),
    "exact_counter_collection:call:exact_keys:785eac2253dd:0": ("platform-overlap", "counters", "r8 gate exact_counter_collection:2660 green-under-removal; callee fired 21x"),
    "exact_counter_collection:call:require:153ea6888a7f:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2656 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:300f3a13d756:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2654 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:472c89b96aa4:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2680 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:4bfedd9fd188:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2666 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:58c7702c9577:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2674 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:730a3b14974d:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2684 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:730a3b14974d:1": ("platform-untested", "counters", "r8 gate exact_counter_collection:2690 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:7a80efa4937c:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2669 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:88a64dc22974:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2693 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:9419bed896a0:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2651 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:b1a23c95d0a0:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2687 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:d6b6831b81b6:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2664 green-under-removal; fired 0x in corpus"),
    "exact_counter_collection:call:require:e526ba9fd2f2:0": ("platform-untested", "counters", "r8 gate exact_counter_collection:2661 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:exact_keys:adb15b81eca4:0": ("platform-overlap", "counters", "r8 gate exact_counter_function_timing:2968 green-under-removal; callee fired 21x"),
    "exact_counter_function_timing:call:require:18415249cae1:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2952 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:2a747bf65199:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2970 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:46e4a11d8973:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2975 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:4b70cdcbc453:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2962 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:549f347c5a72:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2972 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:722c860ceae7:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2960 green-under-removal; fired 0x in corpus"),
    "exact_counter_function_timing:call:require:c56fa64259aa:0": ("platform-untested", "counters", "r8 gate exact_counter_function_timing:2966 green-under-removal; fired 0x in corpus"),
    "exact_counters:call:require:828bda418c60:0": ("platform-untested", "counters", "r8 gate exact_counters:3969 green-under-removal; fired 0x in corpus"),
    "exact_deep_scan_selection:call:exact_keys:059947588410:0": ("platform-overlap", "misc-platform", "r8 gate exact_deep_scan_selection:2551 green-under-removal; callee fired 21x"),
    "exact_deep_scan_selection:call:require:18415249cae1:0": ("platform-untested", "misc-platform", "r8 gate exact_deep_scan_selection:2558 green-under-removal; fired 0x in corpus"),
    "exact_deep_scan_selection:call:require:18415249cae1:1": ("platform-untested", "misc-platform", "r8 gate exact_deep_scan_selection:2562 green-under-removal; fired 0x in corpus"),
    "exact_deep_scan_selection:call:require:18415249cae1:2": ("platform-untested", "misc-platform", "r8 gate exact_deep_scan_selection:2566 green-under-removal; fired 0x in corpus"),
    "exact_deep_scan_selection:call:require:2a9bfbe0d29c:0": ("platform-untested", "misc-platform", "r8 gate exact_deep_scan_selection:2557 green-under-removal; fired 0x in corpus"),
    "exact_discovery_semantics:call:exact_prearm_keys:99394af3afe3:0": ("platform-overlap", "capture-modules", "r8 gate exact_discovery_semantics:3951 green-under-removal; callee fired 20x"),
    "exact_discovery_semantics:call:exact_sources:0dc99cacb522:0": ("platform-overlap", "capture-modules", "r8 gate exact_discovery_semantics:3908 green-under-removal; callee fired 2x"),
    "exact_discovery_semantics:call:require:18415249cae1:1": ("platform-overlap", "capture-modules", "r8 gate exact_discovery_semantics:3912 green-under-removal; fired 1x in corpus"),
    "exact_discovery_semantics:call:require:18415249cae1:5": ("platform-overlap", "capture-modules", "r8 gate exact_discovery_semantics:3960 green-under-removal; fired 1x in corpus"),
    "exact_discovery_semantics:call:require:325a6bbb746d:0": ("platform-untested", "capture-modules", "r8 gate exact_discovery_semantics:3950 green-under-removal; fired 0x in corpus"),
    "exact_discovery_semantics:call:require:4036876da211:0": ("platform-overlap", "capture-modules", "r8 gate exact_discovery_semantics:3949 green-under-removal; fired 1x in corpus"),
    "exact_discovery_semantics:call:require:590b34f02f79:0": ("platform-untested", "capture-modules", "r8 gate exact_discovery_semantics:3909 green-under-removal; fired 0x in corpus"),
    "exact_discovery_semantics:call:require:a28a5becf3fb:0": ("platform-untested", "capture-modules", "r8 gate exact_discovery_semantics:3911 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:exact_caller_reasons_overflow:e11320cdca31:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2269 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_counter_collection:bbd853138a6d:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2272 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_deep_scan_selection:2aafc4584a09:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2310 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_exit_mappings_split:f3b034bef83c:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2356 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_legacy_collection:c4cfc8714eb1:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2295 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_selected_detail:91ba36637703:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2275 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_static_hint_split:03ecaf944e22:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2347 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_static_hint_split:e2e0cab34dd5:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2350 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:exact_unmatched_excludes:a0123ccd3a09:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2286 green-under-removal; callee fired 0x"),
    "exact_evidence_keys:call:require:04fd5c491725:0": ("platform-overlap", "evidence-keys", "r8 gate exact_evidence_keys:2384 green-under-removal; fired 3x in corpus"),
    "exact_evidence_keys:call:require:18415249cae1:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2323 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:require:18415249cae1:1": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2334 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:require:18415249cae1:2": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2338 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:require:18415249cae1:3": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2359 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:require:514229c06101:0": ("platform-overlap", "evidence-keys", "r8 gate exact_evidence_keys:2386 green-under-removal; fired 14x in corpus"),
    "exact_evidence_keys:call:require:c92aa3e0f9a4:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2354 green-under-removal; fired 0x in corpus"),
    "exact_evidence_keys:call:require:f2a88ca97865:0": ("platform-untested", "evidence-keys", "r8 gate exact_evidence_keys:2378 green-under-removal; fired 0x in corpus"),
    "exact_excluded_modules:call:exact_keys:8c8d307c63b7:0": ("platform-overlap", "misc-platform", "r8 gate exact_excluded_modules:2407 green-under-removal; callee fired 21x"),
    "exact_excluded_modules:call:require:4d633215edb9:0": ("platform-untested", "misc-platform", "r8 gate exact_excluded_modules:2408 green-under-removal; fired 0x in corpus"),
    "exact_excluded_modules:call:require:b3429a2e32e8:0": ("platform-untested", "misc-platform", "r8 gate exact_excluded_modules:2410 green-under-removal; fired 0x in corpus"),
    "exact_excluded_modules:call:require:d331f5bd5a6b:0": ("platform-untested", "misc-platform", "r8 gate exact_excluded_modules:2405 green-under-removal; fired 0x in corpus"),
    "exact_excluded_modules:call:require:edf78bc77796:0": ("platform-untested", "misc-platform", "r8 gate exact_excluded_modules:2411 green-under-removal; fired 0x in corpus"),
    "exact_exit_mappings_split:call:exact_keys:41ad932ca0ae:0": ("platform-overlap", "misc-platform", "r8 gate exact_exit_mappings_split:2644 green-under-removal; callee fired 21x"),
    "exact_exit_mappings_split:call:require:0e658d8e0cfc:0": ("platform-untested", "misc-platform", "r8 gate exact_exit_mappings_split:2646 green-under-removal; fired 0x in corpus"),
    "exact_exit_mappings_split:call:require:74ce80cfcf66:0": ("platform-untested", "misc-platform", "r8 gate exact_exit_mappings_split:2645 green-under-removal; fired 0x in corpus"),
    "exact_function_target:call:exact_identity:c6a58d4a6f83:0": ("platform-overlap", "capture-modules", "r8 gate exact_function_target:5000 green-under-removal; callee fired 10x"),
    "exact_function_target:call:require:18415249cae1:0": ("platform-untested", "capture-modules", "r8 gate exact_function_target:5006 green-under-removal; fired 0x in corpus"),
    "exact_function_target:call:require:313e6c6a7e23:0": ("platform-untested", "capture-modules", "r8 gate exact_function_target:5002 green-under-removal; fired 0x in corpus"),
    "exact_identity:call:require:2e714aa852ac:0": ("platform-overlap", "capture-modules", "r8 gate exact_identity:3656 green-under-removal; fired 1x in corpus"),
    "exact_kernel_control:call:require:d68f52751cda:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_kernel_control:2005 green-under-removal; fired 4x in corpus"),
    "exact_legacy_collection:call:exact_keys:b2664561137f:0": ("platform-overlap", "misc-platform", "r8 gate exact_legacy_collection:2611 green-under-removal; callee fired 21x"),
    "exact_legacy_collection:call:require:27f661b24f06:0": ("platform-untested", "misc-platform", "r8 gate exact_legacy_collection:2620 green-under-removal; fired 0x in corpus"),
    "exact_legacy_collection:call:require:6de100e36350:0": ("platform-untested", "misc-platform", "r8 gate exact_legacy_collection:2622 green-under-removal; fired 0x in corpus"),
    "exact_legacy_collection:call:require:9a10ae9000bd:0": ("platform-untested", "misc-platform", "r8 gate exact_legacy_collection:2612 green-under-removal; fired 0x in corpus"),
    "exact_legacy_collection:call:require:b67bac426497:0": ("platform-untested", "misc-platform", "r8 gate exact_legacy_collection:2614 green-under-removal; fired 0x in corpus"),
    "exact_legacy_collection:call:require:fa7774439f5c:0": ("platform-untested", "misc-platform", "r8 gate exact_legacy_collection:2617 green-under-removal; fired 0x in corpus"),
    "exact_live_discovery_evidence:call:require:18415249cae1:1": ("platform-untested", "misc-platform", "r8 gate exact_live_discovery_evidence:4773 green-under-removal; fired 0x in corpus"),
    "exact_live_discovery_evidence:call:require:18415249cae1:5": ("platform-untested", "misc-platform", "r8 gate exact_live_discovery_evidence:4802 green-under-removal; fired 0x in corpus"),
    "exact_live_discovery_evidence:call:require:cf12f1308f6e:0": ("platform-untested", "misc-platform", "r8 gate exact_live_discovery_evidence:4772 green-under-removal; fired 0x in corpus"),
    "exact_live_discovery_evidence:call:require:def4495d95bb:0": ("platform-overlap", "misc-platform", "r8 gate exact_live_discovery_evidence:4763 green-under-removal; fired 1x in corpus"),
    "exact_live_discovery_evidence:call:require:def4495d95bb:1": ("platform-untested", "misc-platform", "r8 gate exact_live_discovery_evidence:4787 green-under-removal; fired 0x in corpus"),
    "exact_live_discovery_evidence:call:require:fd562561ee43:0": ("platform-overlap", "misc-platform", "r8 gate exact_live_discovery_evidence:4761 green-under-removal; fired 1x in corpus"),
    "exact_loader_discovery:call:require:18415249cae1:2": ("platform-untested", "misc-platform", "r8 gate exact_loader_discovery:4715 green-under-removal; fired 0x in corpus"),
    "exact_loader_discovery:call:require:6376eb0f43a3:0": ("platform-untested", "misc-platform", "r8 gate exact_loader_discovery:4687 green-under-removal; fired 0x in corpus"),
    "exact_loader_discovery:call:require:c0f1b9f4377b:0": ("platform-untested", "misc-platform", "r8 gate exact_loader_discovery:4698 green-under-removal; fired 0x in corpus"),
    "exact_loader_discovery:call:require:c67e74d866d8:0": ("platform-untested", "misc-platform", "r8 gate exact_loader_discovery:4739 green-under-removal; fired 0x in corpus"),
    "exact_loader_discovery:call:require:ebf255fb0aa9:1": ("platform-untested", "misc-platform", "r8 gate exact_loader_discovery:4714 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:exact_full_identity:52eee676981c:0": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3992 green-under-removal; callee fired 1x"),
    "exact_manifest_object_fallbacks:call:exact_full_identity:5f5618a65451:0": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4005 green-under-removal; callee fired 1x"),
    "exact_manifest_object_fallbacks:call:exact_identity:4666325f0bb8:0": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4032 green-under-removal; callee fired 10x"),
    "exact_manifest_object_fallbacks:call:exact_sources:0dc99cacb522:0": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3991 green-under-removal; callee fired 2x"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:0": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3981 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:1": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3987 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:2": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3997 green-under-removal; fired 2x in corpus"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:4": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4019 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:5": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4025 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:18415249cae1:6": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4039 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:3262365fabb1:0": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4031 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:49e26df17cbe:0": ("platform-overlap", "capture-modules", "r8 gate exact_manifest_object_fallbacks:4038 green-under-removal; fired 2x in corpus"),
    "exact_manifest_object_fallbacks:call:require:6b58c4ed3eaa:0": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3994 green-under-removal; fired 0x in corpus"),
    "exact_manifest_object_fallbacks:call:require:e6ced7ddc9df:0": ("platform-untested", "capture-modules", "r8 gate exact_manifest_object_fallbacks:3980 green-under-removal; fired 0x in corpus"),
    "exact_metrics_schema:call:exact_attach_backend:2c301ddad996:0": ("platform-overlap", "metrics-schema", "r8 gate exact_metrics_schema:3045 green-under-removal; callee fired 8x"),
    "exact_metrics_schema:call:exact_counter_function_timing:6ae7fc015a99:0": ("platform-untested", "metrics-schema", "r8 gate exact_metrics_schema:3042 green-under-removal; callee fired 0x"),
    "exact_metrics_schema:call:exact_object_capture:1e781d4063e5:0": ("platform-untested", "metrics-schema", "r8 gate exact_metrics_schema:3046 green-under-removal; callee fired 0x"),
    "exact_metrics_schema:call:exact_ring_accounting:8d6cb5d730c1:0": ("platform-overlap", "metrics-schema", "r8 gate exact_metrics_schema:3050 green-under-removal; callee fired 5x"),
    "exact_metrics_schema:call:exact_scheduling_evidence:1177bac98ec6:0": ("platform-overlap", "metrics-schema", "r8 gate exact_metrics_schema:3047 green-under-removal; callee fired 31x"),
    "exact_metrics_schema:call:require:53776a5dd674:0": ("platform-untested", "metrics-schema", "r8 gate exact_metrics_schema:3037 green-under-removal; fired 0x in corpus"),
    "exact_module_ownership:call:require:3dcb6d53012c:0": ("platform-untested", "capture-modules", "r8 gate exact_module_ownership:4837 green-under-removal; fired 0x in corpus"),
    "exact_module_ownership:call:require:d94fc23c2507:0": ("platform-overlap", "capture-modules", "r8 gate exact_module_ownership:4838 green-under-removal; fired 1x in corpus"),
    "exact_object_capture:call:exact_keys:ed4620b6c4a3:0": ("platform-overlap", "misc-platform", "r8 gate exact_object_capture:2038 green-under-removal; callee fired 21x"),
    "exact_object_capture:call:require:0841a1858d80:0": ("platform-untested", "misc-platform", "r8 gate exact_object_capture:2041 green-under-removal; fired 0x in corpus"),
    "exact_object_capture:call:require:21eaf8b57f23:0": ("platform-untested", "misc-platform", "r8 gate exact_object_capture:2043 green-under-removal; fired 0x in corpus"),
    "exact_object_capture:call:require:2456753f5bba:0": ("platform-untested", "misc-platform", "r8 gate exact_object_capture:2039 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:0c0033a0dc82:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3761 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3715 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:1": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3721 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:15": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3836 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:16": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3840 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:2": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3725 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:3": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3732 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:4": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3738 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:5": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3742 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:6": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3765 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:7": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3770 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:8": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3777 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:18415249cae1:9": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3783 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:20d67e57ed71:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3763 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:20d67e57ed71:1": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3775 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:3d41862d9c0d:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3759 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:54a9682c5e69:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3730 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:7a7afbfb93c0:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3757 green-under-removal; fired 0x in corpus"),
    "exact_prearm_keys:call:require:b96d85cc607b:0": ("platform-overlap", "prearm", "r8 gate exact_prearm_keys:3789 green-under-removal; fired 2x in corpus"),
    "exact_prearm_keys:call:require:f5f9d817fcba:0": ("platform-untested", "prearm", "r8 gate exact_prearm_keys:3834 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:exact_counter_function_timing:6ae7fc015a99:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2060 green-under-removal; callee fired 0x"),
    "exact_profile_v3_selection:call:exact_kernel_control:8913edb388d4:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2062 green-under-removal; callee fired 9x"),
    "exact_profile_v3_selection:call:exact_keys:14ae0931683d:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2133 green-under-removal; callee fired 21x"),
    "exact_profile_v3_selection:call:exact_keys:2bf5c31c4782:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2084 green-under-removal; callee fired 21x"),
    "exact_profile_v3_selection:call:exact_keys:3adc3ee41cb1:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2117 green-under-removal; callee fired 21x"),
    "exact_profile_v3_selection:call:exact_keys:baca9cacc138:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2103 green-under-removal; callee fired 21x"),
    "exact_profile_v3_selection:call:exact_keys:e82e7d234200:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2093 green-under-removal; callee fired 21x"),
    "exact_profile_v3_selection:call:exact_object_capture:f8ce865e65ae:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2185 green-under-removal; callee fired 0x"),
    "exact_profile_v3_selection:call:exact_ring_accounting:5a81ed9262ad:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2064 green-under-removal; callee fired 5x"),
    "exact_profile_v3_selection:call:exact_scheduling_evidence:74fae62a2498:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2061 green-under-removal; callee fired 31x"),
    "exact_profile_v3_selection:call:module_ref:9a1233fc3955:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2104 green-under-removal; callee fired 1x"),
    "exact_profile_v3_selection:call:module_ref:b2a1aa059f52:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2123 green-under-removal; callee fired 1x"),
    "exact_profile_v3_selection:call:module_ref:e3e567924d8d:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2094 green-under-removal; callee fired 1x"),
    "exact_profile_v3_selection:call:require:06e7ae2da750:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2115 green-under-removal; fired 1x in corpus"),
    "exact_profile_v3_selection:call:require:0be887de3d10:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2140 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:18415249cae1:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2109 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:18415249cae1:3": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2180 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:19a9fa6d3c35:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2096 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:2813747fbdad:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2208 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:32787d245229:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2163 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:57be33484be7:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2108 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:6016c984fffc:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2128 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:69fe7ab6dac2:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2141 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:717711e4eb5d:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2127 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:7fbef20230e1:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2147 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:a4ab74473fee:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2074 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:ac527853252c:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2139 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:c27a7eea0b09:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2169 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:c5201710f806:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2088 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:c88ce385678a:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2051 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:c98a61fafd30:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2097 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:d54855dcb4a2:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2130 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:db2a464a40e2:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2136 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:e9624b7bbe52:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2067 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:require:f511ba56d68f:0": ("platform-untested", "profile-selection", "r8 gate exact_profile_v3_selection:2087 green-under-removal; fired 0x in corpus"),
    "exact_profile_v3_selection:call:uint:1dc53d8354cc:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2071 green-under-removal; callee fired 17x"),
    "exact_profile_v3_selection:call:uint:229dc11e88b0:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2125 green-under-removal; callee fired 17x"),
    "exact_profile_v3_selection:call:uint:37ed4c43af7e:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2105 green-under-removal; callee fired 17x"),
    "exact_profile_v3_selection:call:uint:cf8c6f5c5760:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2078 green-under-removal; callee fired 17x"),
    "exact_profile_v3_selection:call:uint:f228beb2065f:0": ("platform-overlap", "profile-selection", "r8 gate exact_profile_v3_selection:2134 green-under-removal; callee fired 17x"),
    "exact_ring_accounting:call:uint:21e70c0cec96:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_ring_accounting:2479 green-under-removal; callee fired 17x"),
    "exact_scheduling_evidence:call:exact_scheduling_gap_distribution:efd37d7602a0:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3139 green-under-removal; callee fired 0x"),
    "exact_scheduling_evidence:call:exact_scheduling_newcomer_queue:12411b1f142e:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3140 green-under-removal; callee fired 0x"),
    "exact_scheduling_evidence:call:exact_scheduling_resource:7d93f0e33a51:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3141 green-under-removal; callee fired 0x"),
    "exact_scheduling_evidence:call:exact_scheduling_stage_timing:2471ea345dd6:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3138 green-under-removal; callee fired 0x"),
    "exact_scheduling_evidence:call:require:18415249cae1:7": ("platform-overlap", "scheduling", "r8 gate exact_scheduling_evidence:3117 green-under-removal; fired 1x in corpus"),
    "exact_scheduling_evidence:call:require:83f770b6950b:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3098 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_evidence:call:require:c21c8fd57187:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_evidence:3106 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:00629e31cbfc:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3219 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:0976d767b3c9:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3224 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:18415249cae1:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3220 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:18415249cae1:1": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3227 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:18415249cae1:2": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3232 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:18415249cae1:3": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3237 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_gap_distribution:call:require:18415249cae1:4": ("platform-untested", "scheduling", "r8 gate exact_scheduling_gap_distribution:3243 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_newcomer_queue:call:require:18415249cae1:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_newcomer_queue:3256 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_newcomer_queue:call:require:18415249cae1:1": ("platform-untested", "scheduling", "r8 gate exact_scheduling_newcomer_queue:3262 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_newcomer_queue:call:require:18415249cae1:2": ("platform-untested", "scheduling", "r8 gate exact_scheduling_newcomer_queue:3267 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_newcomer_queue:call:require:d6797c63d35c:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_newcomer_queue:3255 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:18415249cae1:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3280 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:18415249cae1:1": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3286 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:18415249cae1:2": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3292 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:18415249cae1:3": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3296 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:18415249cae1:4": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3301 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:4d7cd25c75c4:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3279 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_resource:call:require:67a6a621c407:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_resource:3284 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3168 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:1": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3173 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:2": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3179 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:3": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3183 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:4": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3187 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:5": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3192 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:6": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3198 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:18415249cae1:7": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3203 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:6593fe700835:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3178 green-under-removal; fired 0x in corpus"),
    "exact_scheduling_stage_timing:call:require:9826dd05f684:0": ("platform-untested", "scheduling", "r8 gate exact_scheduling_stage_timing:3167 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail:call:exact_selected_detail_bracket:353d2b2aec39:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2716 green-under-removal; callee fired 0x"),
    "exact_selected_detail:call:exact_selected_detail_bracket:df23f67309fb:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2718 green-under-removal; callee fired 0x"),
    "exact_selected_detail:call:exact_selected_detail_event:d49f0e2920c7:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2712 green-under-removal; callee fired 0x"),
    "exact_selected_detail:call:exact_selected_detail_lineage:ea27b2fe330f:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2714 green-under-removal; callee fired 0x"),
    "exact_selected_detail:call:exact_selected_detail_selection:104e8d12332e:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2708 green-under-removal; callee fired 0x"),
    "exact_selected_detail:call:require:2c3a953e4595:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2705 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail:call:require:e9f95f91a8de:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2703 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail:call:require:ee4f22e7e56d:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2702 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail:call:require:f342c2ccd6b0:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail:2710 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:exact_keys:48162e866cc0:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_bracket:2929 green-under-removal; callee fired 21x"),
    "exact_selected_detail_bracket:call:exact_selected_detail_row:b5e5216c543c:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2946 green-under-removal; callee fired 0x"),
    "exact_selected_detail_bracket:call:require:11fc8fe13822:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2933 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:2397676d92e1:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2934 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:4b4fe23396dd:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2931 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:515dfed3c780:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2941 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:c1ddc70e49e4:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2940 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:cb3cf2782453:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2944 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:d55bfdde5048:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2937 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_bracket:call:require:de053b9f5a18:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_bracket:2942 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:exact_keys:941e2a7e141d:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_drift:2838 green-under-removal; callee fired 21x"),
    "exact_selected_detail_drift:call:exact_keys:941e2a7e141d:1": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_drift:2842 green-under-removal; callee fired 21x"),
    "exact_selected_detail_drift:call:exact_keys:941e2a7e141d:2": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_drift:2857 green-under-removal; callee fired 21x"),
    "exact_selected_detail_drift:call:exact_keys:a467f7a0e601:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_drift:2849 green-under-removal; callee fired 21x"),
    "exact_selected_detail_drift:call:require:206bac1912e2:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_drift:2839 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:require:7c23e2002abb:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_drift:2852 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:require:844a6d2c586a:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_drift:2834 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:require:c263e65af65d:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_drift:2859 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:require:f42d8988c408:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_drift:2844 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_drift:call:uint:783c4fcae715:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_drift:2850 green-under-removal; callee fired 17x"),
    "exact_selected_detail_event:call:exact_keys:099398ce0ab1:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2786 green-under-removal; callee fired 21x"),
    "exact_selected_detail_event:call:exact_keys:3613f58fb461:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2795 green-under-removal; callee fired 21x"),
    "exact_selected_detail_event:call:exact_keys:39b4aaf91658:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2802 green-under-removal; callee fired 21x"),
    "exact_selected_detail_event:call:exact_keys:79c3b3355774:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2771 green-under-removal; callee fired 21x"),
    "exact_selected_detail_event:call:exact_keys:92f3df6f1516:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2779 green-under-removal; callee fired 21x"),
    "exact_selected_detail_event:call:exact_selected_detail_ids:7156f531bee0:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2772 green-under-removal; callee fired 0x"),
    "exact_selected_detail_event:call:exact_selected_detail_ids:86300b68dba6:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2787 green-under-removal; callee fired 0x"),
    "exact_selected_detail_event:call:exact_selected_detail_ids:b6e219131be5:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2780 green-under-removal; callee fired 0x"),
    "exact_selected_detail_event:call:exact_selected_detail_ids:f15a6e1cded6:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2765 green-under-removal; callee fired 0x"),
    "exact_selected_detail_event:call:require:45902d4ee4cb:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2797 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:45902d4ee4cb:1": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2804 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:5ceed86cadfc:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2781 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:5ef2ed2c83ac:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2774 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:71c6a733114b:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2791 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:9ff6ecd4689b:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2768 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:a2d05d6a4970:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2756 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:a99e8204dbe3:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2763 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:b1d9439c3f9a:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2766 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:ba2f1da009b2:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2761 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:d54acb6dfa83:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2788 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:d6032a37738c:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2776 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:e573db21d07c:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2808 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:f522dd563569:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2783 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:require:f6416b2dbaf4:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2773 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_event:call:uint:72f91515a7c0:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2800 green-under-removal; callee fired 17x"),
    "exact_selected_detail_event:call:uint:e99fbb61841b:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_event:2799 green-under-removal; callee fired 17x"),
    "exact_selected_detail_event:raise:d7516d3eae0e:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_event:2811 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_ids:call:require:a5327dfc97ea:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_ids:2750 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_ids:call:uint:b37a6b261bec:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_ids:2752 green-under-removal; callee fired 17x"),
    "exact_selected_detail_ids:call:uint:b40b0d36ea11:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_ids:2751 green-under-removal; callee fired 17x"),
    "exact_selected_detail_lineage:call:exact_keys:9d3216bda3c5:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_lineage:2864 green-under-removal; callee fired 21x"),
    "exact_selected_detail_lineage:call:exact_selected_detail_drift:ada34c590bd8:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2885 green-under-removal; callee fired 0x"),
    "exact_selected_detail_lineage:call:exact_selected_detail_mark:1d82d83d45eb:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2880 green-under-removal; callee fired 0x"),
    "exact_selected_detail_lineage:call:exact_selected_detail_mark:c5550174396d:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2881 green-under-removal; callee fired 0x"),
    "exact_selected_detail_lineage:call:require:0264aea72955:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2876 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:2641f4c49359:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2886 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:43c6e848a319:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2865 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:536fd7ba8b1e:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2869 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:5ddfdd32528a:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2872 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:81336786e641:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2882 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:89430624037f:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2868 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:d917a59d52b9:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2878 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:require:f8329334f5af:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_lineage:2874 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_lineage:call:uint:4418fbb45bc7:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_lineage:2866 green-under-removal; callee fired 17x"),
    "exact_selected_detail_lineage:call:uint:557b5cbc0423:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_lineage:2867 green-under-removal; callee fired 17x"),
    "exact_selected_detail_lineage:call:uint:8a34f137b5c2:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_lineage:2871 green-under-removal; callee fired 17x"),
    "exact_selected_detail_mark:call:exact_keys:d704e346c21e:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_mark:2815 green-under-removal; callee fired 21x"),
    "exact_selected_detail_mark:call:require:0da88233bc6c:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_mark:2829 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_mark:call:require:53467afeb8f8:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_mark:2819 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_mark:call:require:5960b07e59c1:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_mark:2817 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_mark:call:require:5fa12ea940ae:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_mark:2816 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_mark:call:require:c4428c460631:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_mark:2823 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:exact_keys:3f1c763d8328:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_row:2908 green-under-removal; callee fired 21x"),
    "exact_selected_detail_row:call:exact_selected_detail_rv_counts:b8780c6a1350:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2914 green-under-removal; callee fired 0x"),
    "exact_selected_detail_row:call:require:19e35b2ba5a4:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2919 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:require:36b491a19910:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2916 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:require:3ab6cc33580f:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2917 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:require:82c5eeb7387e:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2913 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:require:cd7a8469cfff:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_row:2911 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_row:call:uint:1bb8250d188d:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_row:2909 green-under-removal; callee fired 17x"),
    "exact_selected_detail_row:call:uint:fabcfc0bea74:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_row:2910 green-under-removal; callee fired 17x"),
    "exact_selected_detail_rv_counts:call:require:66060d5bc949:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_rv_counts:2896 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_rv_counts:call:require:f441c70385fe:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_rv_counts:2894 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:3ad789e3e494:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2728 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:3ba8f310b73e:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2730 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:509e98feea16:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2739 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:523b5340066c:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2743 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:5c7a997f5190:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2735 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:6cf4a7f14a2b:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2726 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:7e2c7e469e0a:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2723 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:require:c72eb57e0a7d:0": ("platform-untested", "detail-rows", "r8 gate exact_selected_detail_selection:2722 green-under-removal; fired 0x in corpus"),
    "exact_selected_detail_selection:call:uint:e6309b2b37e3:0": ("platform-overlap", "detail-rows", "r8 gate exact_selected_detail_selection:2733 green-under-removal; callee fired 17x"),
    "exact_selection_request:call:exact_keys:a5feb1abadb3:0": ("platform-overlap", "profile-selection", "r8 gate exact_selection_request:1953 green-under-removal; callee fired 21x"),
    "exact_selection_request:call:require:83b8883685a3:0": ("platform-untested", "profile-selection", "r8 gate exact_selection_request:1955 green-under-removal; fired 0x in corpus"),
    "exact_selection_result:call:exact_keys:a5feb1abadb3:0": ("platform-overlap", "profile-selection", "r8 gate exact_selection_result:1962 green-under-removal; callee fired 21x"),
    "exact_selection_result:call:require:83b8883685a3:0": ("platform-untested", "profile-selection", "r8 gate exact_selection_result:1964 green-under-removal; fired 0x in corpus"),
    "exact_selection_result:call:require:c082f53b2560:0": ("platform-untested", "profile-selection", "r8 gate exact_selection_result:1963 green-under-removal; fired 0x in corpus"),
    "exact_slot_sizing:call:require:18415249cae1:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2513 green-under-removal; fired 1x in corpus"),
    "exact_slot_sizing:call:require:18415249cae1:1": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2517 green-under-removal; fired 3x in corpus"),
    "exact_slot_sizing:call:uint:164ccda1957a:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2512 green-under-removal; callee fired 17x"),
    "exact_slot_sizing:call:uint:78ec18c3c305:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2507 green-under-removal; callee fired 17x"),
    "exact_slot_sizing:call:uint:7fcc248da8cd:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2511 green-under-removal; callee fired 17x"),
    "exact_slot_sizing:call:uint:9ab736d9be33:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2509 green-under-removal; callee fired 17x"),
    "exact_slot_sizing:call:uint:bc2a819dd73b:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2508 green-under-removal; callee fired 17x"),
    "exact_slot_sizing:call:uint:c2a3066ba54d:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_slot_sizing:2510 green-under-removal; callee fired 17x"),
    "exact_static_hint_split:call:exact_keys:fbd5e3795927:0": ("platform-overlap", "misc-platform", "r8 gate exact_static_hint_split:2631 green-under-removal; callee fired 21x"),
    "exact_static_hint_split:call:require:1e1b55b9b4cd:0": ("platform-untested", "misc-platform", "r8 gate exact_static_hint_split:2632 green-under-removal; fired 0x in corpus"),
    "exact_static_hint_split:call:require:bbb0adae04ae:0": ("platform-untested", "misc-platform", "r8 gate exact_static_hint_split:2637 green-under-removal; fired 0x in corpus"),
    "exact_static_hint_split:call:require:db7ae21b8fd5:0": ("platform-untested", "misc-platform", "r8 gate exact_static_hint_split:2634 green-under-removal; fired 0x in corpus"),
    "exact_stop_quiescence:call:exact_keys:7889879cd5b1:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_stop_quiescence:3548 green-under-removal; callee fired 21x"),
    "exact_stop_quiescence:call:require:18415249cae1:0": ("platform-untested", "runtime-evidence", "r8 gate exact_stop_quiescence:3552 green-under-removal; fired 0x in corpus"),
    "exact_stop_quiescence:call:require:18415249cae1:1": ("platform-untested", "runtime-evidence", "r8 gate exact_stop_quiescence:3557 green-under-removal; fired 0x in corpus"),
    "exact_stop_quiescence:call:require:2435b7a8a448:0": ("platform-untested", "runtime-evidence", "r8 gate exact_stop_quiescence:3549 green-under-removal; fired 0x in corpus"),
    "exact_stop_quiescence:call:require:3d55855131db:0": ("platform-untested", "runtime-evidence", "r8 gate exact_stop_quiescence:3551 green-under-removal; fired 0x in corpus"),
    "exact_stop_quiescence:call:require:4c7aca5ad2c8:0": ("platform-untested", "runtime-evidence", "r8 gate exact_stop_quiescence:3547 green-under-removal; fired 0x in corpus"),
    "exact_task_uprobe_link_losses:call:require:18415249cae1:0": ("platform-overlap", "runtime-evidence", "r8 gate exact_task_uprobe_link_losses:3312 green-under-removal; fired 2x in corpus"),
    "exact_terminal_verdict:call:exact_keys:91f0d74cf96e:0": ("platform-overlap", "terminal-verdict", "r8 gate exact_terminal_verdict:3635 green-under-removal; callee fired 21x"),
    "exact_terminal_verdict:call:exact_keys:b9a23adea456:0": ("platform-overlap", "terminal-verdict", "r8 gate exact_terminal_verdict:3602 green-under-removal; callee fired 21x"),
    "exact_terminal_verdict:call:exact_stop_quiescence:fb1135d153b1:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3583 green-under-removal; callee fired 0x"),
    "exact_terminal_verdict:call:require:18415249cae1:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3573 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:1": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3577 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:10": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3639 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:11": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3643 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:2": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3585 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:3": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3590 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:4": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3596 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:5": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3603 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:6": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3607 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:18415249cae1:8": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3620 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:6a3d88038130:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3632 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:6bb1a5f6f0c6:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3636 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:711fa1669045:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3630 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:ad469230e41a:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3582 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:db785ce46373:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3594 green-under-removal; fired 0x in corpus"),
    "exact_terminal_verdict:call:require:f617627c3659:0": ("platform-untested", "terminal-verdict", "r8 gate exact_terminal_verdict:3637 green-under-removal; fired 0x in corpus"),
    "exact_unmatched_excludes:call:require:ecfce91c2f6e:0": ("platform-untested", "misc-platform", "r8 gate exact_unmatched_excludes:2419 green-under-removal; fired 0x in corpus"),
    "exact_verdict_classes:call:exact_keys:613a89e7bcca:0": ("platform-overlap", "misc-platform", "r8 gate exact_verdict_classes:3502 green-under-removal; callee fired 21x"),
    "exact_verdict_classes:call:require:1fb4e6b0b0d2:0": ("platform-overlap", "misc-platform", "r8 gate exact_verdict_classes:3511 green-under-removal; fired 4x in corpus"),
    "exact_verdict_classes:call:require:5f5aa8273b92:0": ("platform-untested", "misc-platform", "r8 gate exact_verdict_classes:3501 green-under-removal; fired 0x in corpus"),
    "expected_gap_classes:call:require:b4d39b888351:0": ("platform-untested", "terminal-verdict", "r8 gate expected_gap_classes:3368 green-under-removal; fired 0x in corpus"),
    "validate_induced:call:exact_common:0a3c64e8a7c6:0": ("other-gate", "other-gate", "r8 gate validate_induced:5970 green-under-removal; callee fired 36x"),
    "validate_induced:call:exact_common:5be5e75fbe6f:0": ("other-gate", "other-gate", "r8 gate validate_induced:5982 green-under-removal; callee fired 36x"),
    "validate_induced:call:exact_common:9bd9f322be05:0": ("other-gate", "other-gate", "r8 gate validate_induced:5978 green-under-removal; callee fired 36x"),
    "validate_induced:call:exact_counters:d482984bc757:0": ("other-gate", "other-gate", "r8 gate validate_induced:5990 green-under-removal; callee fired 10x"),
    "validate_induced:call:exact_counters:df8372eba6c5:0": ("other-gate", "other-gate", "r8 gate validate_induced:5971 green-under-removal; callee fired 10x"),
    "validate_induced:call:exact_counters:df8372eba6c5:1": ("other-gate", "other-gate", "r8 gate validate_induced:5979 green-under-removal; callee fired 10x"),
    "validate_induced:call:exact_shape:8e3642ba31bd:0": ("other-gate", "other-gate", "r8 gate validate_induced:5969 green-under-removal; callee fired 29x"),
    "validate_induced:call:exact_shape:e36320c7684f:0": ("other-gate", "other-gate", "r8 gate validate_induced:5981 green-under-removal; callee fired 29x"),
    "validate_induced:call:exact_shape:fa774132cca5:0": ("other-gate", "other-gate", "r8 gate validate_induced:5977 green-under-removal; callee fired 29x"),
    "validate_induced:call:require:05ab541c90ed:0": ("other-gate", "other-gate", "r8 gate validate_induced:5984 green-under-removal; fired 0x in corpus"),
    "validate_induced:call:require:2052c7f694c8:0": ("other-gate", "other-gate", "r8 gate validate_induced:5983 green-under-removal; fired 0x in corpus"),
    "validate_induced:call:require:3e04ee5c9eaf:0": ("other-gate", "other-gate", "r8 gate validate_induced:5975 green-under-removal; fired 0x in corpus"),
    "validate_induced:call:require:3efb6fb7c59d:0": ("other-gate", "other-gate", "r8 gate validate_induced:5976 green-under-removal; fired 0x in corpus"),
    "validate_induced:call:require:b21215a79e67:0": ("other-gate", "other-gate", "r8 gate validate_induced:5974 green-under-removal; fired 0x in corpus"),
}
