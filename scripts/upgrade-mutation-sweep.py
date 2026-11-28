#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Rerunnable mutation sweep for the upgrade-cell artifact readers.

Each mutation is a small semantic deletion/weakening at one production guard
or validator site.  The harness copies only the upgrade-cell files into an
isolated temporary tree, applies exactly one textual mutation, and runs the
focused test named as that site's killer.  A mutation is killed when the test
returns non-zero; it survives when the focused test remains green.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_MODULE = ["python3", "-I", "tests/python/test_upgrade_cells.py"]
VALIDATOR_TEST = "UpgradeArtifactValidationTests"
GATE5_KILLER = "UpgradeGate5SimulationTests.test_simulated_negative_controls_fail_with_exact_typed_reasons"
GATE5_RPM_KILLER = "UpgradeGate5SimulationTests.test_simulated_rpm_uninstall_negatives_fail_with_exact_typed_reasons"
GATE6_KILLER = "UpgradeGate6ActivationTests.test_run_gate_activation_negative_controls"

GATE6_POSITIVE_KILLER = (
    "UpgradeGate6ActivationTests.test_run_gate_positive_synthetic_typed_flow_is_exact"
)
PROFILE_FLOW_KILLER = (
    "UpgradeGate6ActivationTests.test_profile_fixture_flow_requires_substantive_typed_conversion"
)
CBOM_SCHEMA_KILLER = f"{VALIDATOR_TEST}.test_cbom_inventory_validator_rejects_schema_violations"

MUTATIONS = [
    {
        "site": "b1 removed-vocab membership check",
        "file": "scripts/upgrade-gate6.py",
        "old": "        if label in new_vocab.get(prefix, ()):",
        "new": "        if True:",
        "killer": "UpgradeGate6PureTests.test_b1_removed_reason_fails",
    },
    {
        "site": "b1 unexpected-vocab membership check",
        "file": "scripts/upgrade-gate6.py",
        "old": "        if label not in new_vocab.get(prefix, ()):",
        "new": "        if False:",
        "killer": "UpgradeGate6PureTests.test_b1_unexpected_reason_fails",
    },
    {
        "site": "b1 dynamic-leaf exemption",
        "file": "scripts/upgrade-gate6.py",
        "old": "                kind = \"dynamic\"",
        "new": "                kind = None",
        "killer": "UpgradeGate6PureTests.test_b1_dynamic_mapping_leaves_are_not_compared",
    },
    {
        "site": "b1 reason-node exemption",
        "file": "scripts/upgrade-gate6.py",
        "old": "                    kind = \"node\"",
        "new": "                    kind = None",
        "killer": "UpgradeGate6PureTests.test_b1_reason_node_absence_passes",
    },
    {
        "site": "b1 vocab loader unreadable refusal",
        "file": "scripts/upgrade-gate6.py",
        "old": "        return None, f\"refused: reason vocabularies unreadable: {exc}\"",
        "new": "        return {\"v071\": {}, \"v072\": {}}, \"\"",
        "killer": "UpgradeGate6PureTests.test_b1_vocabularies_loader_refuses",
    },
    {
        "site": "b1 vocab loader non-object refusal",
        "file": "scripts/upgrade-gate6.py",
        "old": "        return None, \"refused: reason vocabularies root is not an object\"",
        "new": "        return {\"v071\": {}, \"v072\": {}}, \"\"",
        "killer": "UpgradeGate6PureTests.test_b1_vocabularies_loader_refuses",
    },
    {
        "site": "b1 vocab loader map-set refusal",
        "file": "scripts/upgrade-gate6.py",
        "old": "        if not isinstance(vocab, dict) or set(vocab) != expected:",
        "new": "        if False:",
        "killer": "UpgradeGate6PureTests.test_b1_vocabularies_loader_refuses",
    },
    {
        "site": "b1 vocab loader string-list refusal",
        "file": "scripts/upgrade-gate6.py",
        "old": """            if not isinstance(labels, list) or not all(
                isinstance(label, str) for label in labels
            ):""",
        "new": "            if False:",
        "killer": "UpgradeGate6PureTests.test_b1_vocabularies_loader_refuses",
    },
    {
        "site": "inventory schema launched_by_gap null branch",
        "file": "docs/schema/inventory-v1.schema.json",
        "old": """              {
                "type": "null"
              }
            ]
          },
          "launched_by_origin": {""",
        "new": """              {
                "type": "object",
                "required": ["zzz_no_such_key"]
              }
            ]
          },
          "launched_by_origin": {""",
        "killer": "UpgradeArtifactValidationTests.test_inventory_accepts_producer_grounded_nulls_and_conditionals",
    },
    {
        "site": "inventory schema unobserved late_discovery reason",
        "file": "docs/schema/inventory-v1.schema.json",
        "old": """                    "late_discovery",
""",
        "new": "",
        "killer": "UpgradeArtifactValidationTests.test_inventory_accepts_producer_grounded_nulls_and_conditionals",
    },
    {
        "site": "inventory schema ancestor folded key",
        "file": "docs/schema/inventory-v1.schema.json",
        "old": """                "exe_gap": {
                  "type": "string"
                },
                "folded": {
                  "type": "integer",
                  "minimum": 1
                }""",
        "new": """                "exe_gap": {
                  "type": "string"
                }""",
        "killer": "UpgradeArtifactValidationTests.test_inventory_accepts_producer_grounded_nulls_and_conditionals",
    },
    {
        "site": "jsonschema required keyword",
        "file": "scripts/json_schema.py",
        "old": "        required = schema.get(\"required\", [])",
        "new": "        required = []",
        "killer": "UpgradeJsonSchemaConformanceTests.test_conformance_matrix",
    },
    {
        "site": "jsonschema strict additional default",
        "file": "scripts/json_schema.py",
        "old": "            \"additionalProperties\", False if (self.strict and declares) else True",
        "new": "            \"additionalProperties\", True",
        "killer": "UpgradeJsonSchemaConformanceTests.test_conformance_matrix",
    },
    {
        "site": "jsonschema const comparison",
        "file": "scripts/json_schema.py",
        "old": "            if instance != value or type(instance) is not type(value):",
        "new": "            if False:",
        "killer": "UpgradeJsonSchemaConformanceTests.test_conformance_matrix",
    },
    {
        "site": "jsonschema integer bool exclusion",
        "file": "scripts/json_schema.py",
        "old": "        return isinstance(instance, int) and not isinstance(instance, bool)",
        "new": "        return isinstance(instance, int)",
        "killer": "UpgradeJsonSchemaConformanceTests.test_conformance_matrix",
    },
    {
        "site": "diff positive compared-field swapped for occurrences",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    compared = summary.get("application_groups_compared") if isinstance(summary, dict) else None""",
        "new": """    _swapped = _snapshot_evidence(document, "before") or {}
    compared = len(_swapped.get("caller_occurrences") or [])""",
        "killer": "UpgradeArtifactValidationTests.test_diff_compared_group_positive_rule",
    },
    {
        "site": "diff positive compared-count clause",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    if not is_int(compared) or compared < 1:
        errors.append("diff positive payload: fewer than one compared application group")""",
        "new": "    pass",
        "killer": "UpgradeArtifactValidationTests.test_diff_compared_group_positive_rule",
    },
    {
        "site": "diff positive backed-rows clause",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    if not backed:
        errors.append("diff positive payload: no compared group backed by rows on both sides")""",
        "new": "    pass",
        "killer": "UpgradeArtifactValidationTests.test_diff_compared_group_positive_rule",
    },
    {
        "site": "diff reference bounds check call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "        errors.extend(diff_reference_errors(document))",
        "new": "        pass",
        "killer": "UpgradeArtifactValidationTests.test_diff_references_must_resolve_inside_pools",
    },
    {
        "site": "diff ordering check call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "        errors.extend(diff_ordering_errors(document))",
        "new": "        pass",
        "killer": "UpgradeArtifactValidationTests.test_diff_ordering_must_hold",
    },
    {
        "site": "diff occurrence cardinality check",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    evidence = snapshot.get("evidence") if isinstance(snapshot.get("evidence"), dict) else {}
    for pool, kind in (("caller_occurrences", "callers"),
                       ("module_occurrences", "modules"),
                       ("edge_occurrences", "edges")):""",
        "new": "    evidence = {}\n    for pool, kind in ():",
        "killer": "UpgradeArtifactValidationTests.test_diff_occurrence_cardinality_matches_sources",
    },
    {
        "site": "inventory object-observations dispatch call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "        errors.extend(object_observations_schema_errors(document.get(\"object_observations\")))",
        "new": "        pass",
        "killer": "UpgradeArtifactValidationTests.test_inventory_strict_mode_rejects_mistyped_nested_contract_fields",
    },
    {
        "site": "inventory object-observations version guard",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    if not is_int(version) or version not in OBJECT_OBSERVATION_SCHEMA_FILES:",
        "new": "    if False:",
        "killer": "UpgradeArtifactValidationTests.test_object_observations_dispatch_refuses_unknown_version",
    },
    {
        "site": "cbom inventory format-version gate",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    format_errors = cbom_format_errors(document)
    if format_errors:
        return format_errors
    source_errors = inventory_errors(source)""",
        "new": "    source_errors = inventory_errors(source)",
        "killer": "UpgradeArtifactValidationTests.test_cbom_exact_format_and_version_refusals",
    },
    {
        "site": "cbom profile format-version gate",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    format_errors = cbom_format_errors(document)
    if format_errors:
        return format_errors
    if not isinstance(profile, dict):""",
        "new": "    if not isinstance(profile, dict):",
        "killer": "UpgradeGate6ActivationTests.test_profile_fixture_flow_requires_substantive_typed_conversion",
    },
    {
        "site": "gate6 old-binary pin call",
        "file": "scripts/upgrade-gate6.py",
        "old": '        verify_artifact_pin("v071-observer-binary", args.old_binary),',
        "new": "",
        "killer": "UpgradeGate6ActivationTests.test_inputs_present_refuses_unpinned_binary",
    },
    {
        "site": "gate6 fixture pin call",
        "file": "scripts/upgrade-gate6.py",
        "old": '        verify_artifact_pin("v071-profile-fixture", PROFILE_FIXTURE),',
        "new": "",
        "killer": "UpgradeGate6ActivationTests.test_inputs_present_refuses_tampered_fixture",
    },
    {
        "site": "gate6 pin comparison",
        "file": "scripts/upgrade-gate6.py",
        "old": "    if digest != want:",
        "new": "    if digest == want:",
        "killer": "UpgradeGate6ActivationTests.test_verify_artifact_pin_match_mismatch_missing",
    },
    {
        "site": "gate5 old-package pin call",
        "file": "scripts/upgrade-gate5.sh",
        "old": "  verify_old_package_pin",
        "new": "  :",
        "killer": "UpgradeGate5SimulationTests.test_simulated_negative_controls_fail_with_exact_typed_reasons",
    },
    {
        "site": "gate5 owned-path normalization",
        "file": "scripts/upgrade-gate5.sh",
        "old": """    case "$path" in
      */.) path="${path%/.}"; [ -n "$path" ] || path="/";;
    esac""",
        "new": "    :",
        "killer": "UpgradeGate5SimulationTests.test_simulated_negative_controls_fail_with_exact_typed_reasons",
    },
    {
        "site": "gate5 wart pin upstream entry",
        "file": "scripts/upgrade-gate5.sh",
        "old": " /usr/share/doc/p11scope/notices/licenses/upstream\"",
        "new": "\"",
        "killer": "UpgradeGate5SimulationTests.test_simulated_rpm_uninstall_negatives_fail_with_exact_typed_reasons",
    },
    {
        "site": "gate5 old capture typed validation",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  validation_detail="$(validate_inventory_report "$WORKDIR/pre-upgrade.json")" || fail "old capture report failed typed validation: $validation_detail"',
        "new": '  validation_detail="typed validation disabled"',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 new capture typed validation",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  validation_detail="$(validate_inventory_report "$WORKDIR/post-upgrade.json")" || fail "new capture report failed typed validation: $validation_detail"',
        "new": '  validation_detail="typed validation disabled"',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 leftover pin comparison",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  [ "$leftovers" = "$wanted" ] || fail "$phase uninstall leftovers differ: got [$leftovers] want [$wanted]"',
        "new": '  :',
        "killer": GATE5_RPM_KILLER,
    },
    {
        "site": "gate5 leftover stray scan",
        "file": "scripts/upgrade-gate5.sh",
        "old": '    stray="$(find "$probe" -not -type d 2>/dev/null | head -20)"',
        "new": '    stray=""',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 old uninstall observation call",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  observe_uninstall_leftovers old',
        "new": '  :',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 new uninstall observation call",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  observe_uninstall_leftovers new',
        "new": '  :',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 binary-survived uninstall check",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  [ -e "$P11SCOPE_BIN" ] && fail "installed binary survived $phase uninstall"',
        "new": '  :',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate6 inventory_reports_typed verdict",
        "file": "scripts/upgrade-gate6.py",
        "old": "        not inventory_errors,",
        "new": "        True,",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 cbom_old_typed flow validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "        cbom_errors = artifact_validation.cbom_inventory_errors(cbom, old)",
        "new": "        cbom_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 diff_old_old_zero typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            zero_errors = artifact_validation.diff_errors(same_diff, old, old)",
        "new": "            zero_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 diff_typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "        diff_errors = artifact_validation.diff_errors(diff_doc, old, new)",
        "new": "        diff_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 b2 injected cbom typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            cbom_errors = artifact_validation.cbom_inventory_errors(cbom, injected)",
        "new": "            cbom_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 b3 profile cbom typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            profile_errors = artifact_validation.cbom_profile_errors(cbom, profile_doc)",
        "new": "            profile_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 b3 old-against-tag schema check",
        "file": "scripts/upgrade-gate6.py",
        "old": '        "b3_old_schema_passes",',
        "new": '        "b3_old_schema_passes_dropped",',
        "killer": GATE6_POSITIVE_KILLER,
    },
    {
        "site": "gate6 b3 old-against-head expected-failure check",
        "file": "scripts/upgrade-gate6.py",
        "old": '        "b3_old_against_head_expected_failure",',
        "new": '        "b3_old_against_head_expected_failure_dropped",',
        "killer": GATE6_POSITIVE_KILLER,
    },
    {
        "site": "gate6 diff churn lifecycle check",
        "file": "scripts/upgrade-gate6.py",
        "old": '        "diff_churn_lifecycle",',
        "new": '        "diff_churn_lifecycle_dropped",',
        "killer": GATE6_POSITIVE_KILLER,
    },
    {
        "site": "cbom exact source flow-through comparison",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    for name, wanted in expected.items():",
        "new": "    for name, wanted in {}.items():",
        "killer": GATE6_KILLER,
    },
    {
        "site": "cbom numeric property decimal loop",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    for name in CBOM_NUMERIC_PROPERTIES:",
        "new": "    for name in ():",
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "profile providers derivation",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '        "p11scope:providers": str(len(modules)),',
        "new": '        "p11scope:providers": "0",',
        "killer": PROFILE_FLOW_KILLER,
    },
    {
        "site": "profile algorithms derivation",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '        "p11scope:algorithms": str(len(mechanism_ids)),',
        "new": '        "p11scope:algorithms": "0",',
        "killer": PROFILE_FLOW_KILLER,
    },
    {
        "site": "inventory positive caller row",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    if len(document.get("callers", [])) < 1:',
        "new": "    if False:",
        "killer": f"{VALIDATOR_TEST}.test_inventory_positive_payload_rejects_hollow_typed_rows",
    },
    {
        "site": "inventory positive provider row",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    if len(document.get("modules", [])) < 1:',
        "new": "    if False:",
        "killer": f"{VALIDATOR_TEST}.test_inventory_positive_payload_rejects_hollow_typed_rows",
    },
    {
        "site": "inventory positive caller-provider edge",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    if len(document.get("edges", [])) < 1:',
        "new": "    if False:",
        "killer": f"{VALIDATOR_TEST}.test_inventory_positive_payload_rejects_hollow_typed_rows",
    },
    {
        "site": "cbom positive applications count equality",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    for name in ("applications", "providers", "algorithms", "keys"):',
        "new": '    for name in ("providers", "algorithms", "keys"):',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive providers count equality",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    for name in ("applications", "providers", "algorithms", "keys"):',
        "new": '    for name in ("applications", "algorithms", "keys"):',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive algorithms count equality",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    for name in ("applications", "providers", "algorithms", "keys"):',
        "new": '    for name in ("applications", "providers", "keys"):',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive keys count equality",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    for name in ("applications", "providers", "algorithms", "keys"):',
        "new": '    for name in ("applications", "providers", "algorithms"):',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive inventory applications minimum",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")',
        "new": '    minimums = ("providers", "algorithms") if profile_input else ("providers", "algorithms")',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive inventory providers minimum",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")',
        "new": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "algorithms")',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive inventory algorithms minimum",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")',
        "new": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers")',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "cbom positive profile providers minimum",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")',
        "new": '    minimums = ("algorithms",) if profile_input else ("applications", "providers", "algorithms")',
        "killer": PROFILE_FLOW_KILLER,
    },
    {
        "site": "cbom positive profile algorithms minimum",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")',
        "new": '    minimums = ("providers",) if profile_input else ("applications", "providers", "algorithms")',
        "killer": PROFILE_FLOW_KILLER,
    },
    {
        "site": "diff positive before caller occurrence",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    for side in ("before", "after"):
        evidence = _snapshot_evidence(document, side)
        occurrences = evidence.get("caller_occurrences") if evidence is not None else None""",
        "new": """    for side in ("after",):
        evidence = _snapshot_evidence(document, side)
        occurrences = evidence.get("caller_occurrences") if evidence is not None else None""",
        "killer": f"{VALIDATOR_TEST}.test_diff_positive_payload_rejects_hollow_caller_projections",
    },
    {
        "site": "diff positive after caller occurrence",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": """    for side in ("before", "after"):
        evidence = _snapshot_evidence(document, side)
        occurrences = evidence.get("caller_occurrences") if evidence is not None else None""",
        "new": """    for side in ("before",):
        evidence = _snapshot_evidence(document, side)
        occurrences = evidence.get("caller_occurrences") if evidence is not None else None""",
        "killer": f"{VALIDATOR_TEST}.test_diff_positive_payload_rejects_hollow_caller_projections",
    },
    {
        "site": "inventory product-schema shape call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    errors = product_schema_errors(document, INVENTORY_SCHEMA_FILE, \"inventory\")",
        "new": "    errors = []",
        "killer": f"{VALIDATOR_TEST}.test_inventory_validator_rejects_each_required_root_field",
    },
    {
        "site": "cbom inventory product-schema shape call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "        errors.append(\"cbom property 'p11scope:gaps_suppressed' is present for a zero source count\")\n    if not errors:\n        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, \"cbom\"))",
        "new": "        errors.append(\"cbom property 'p11scope:gaps_suppressed' is present for a zero source count\")\n    if False:\n        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, \"cbom\"))",
        "killer": CBOM_SCHEMA_KILLER,
    },
    {
        "site": "cbom profile product-schema shape call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    compare_cbom_properties(document, expected, errors)\n    if not errors:\n        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, \"cbom\"))",
        "new": "    compare_cbom_properties(document, expected, errors)\n    if False:\n        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, \"cbom\"))",
        "killer": PROFILE_FLOW_KILLER,
    },
    {
        "site": "diff product-schema shape call",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    diff_source_consistency(document.get(\"after\"), after_source, \"after\", errors)\n    if not errors:\n        errors.extend(product_schema_errors(document, DIFF_SCHEMA_FILE, \"diff\"))",
        "new": "    diff_source_consistency(document.get(\"after\"), after_source, \"after\", errors)\n    if False:\n        errors.extend(product_schema_errors(document, DIFF_SCHEMA_FILE, \"diff\"))",
        "killer": f"{VALIDATOR_TEST}.test_diff_validator_requires_ten_field_typed_document_and_consistency",
    },
    {
        "site": "diff snapshot/source exact consistency",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    if source is None or not isinstance(snapshot, dict) or not isinstance(source, dict):\n        return",
        "new": "    return",
        "killer": f"{VALIDATOR_TEST}.test_diff_validator_rejects_snapshot_inconsistent_with_source",
    },
]

CONTROL_TESTS = [
    VALIDATOR_TEST,
    "UpgradeGate5SimulationTests",
    "UpgradeGate6ActivationTests",
    "UpgradeJsonSchemaConformanceTests",
]


def copy_cell_tree(destination: Path) -> None:
    for relative in (
        "scripts/upgrade-gate5.sh",
        "scripts/upgrade-gate6.py",
        "scripts/upgrade_artifact_validation.py",
        "scripts/upgrade-artifact-pins.json",
        "scripts/upgrade-reason-vocabularies.json",
        "scripts/json_schema.py",
        "scripts/upgrade-softhsm-workload.py",
        "tests/python/test_upgrade_cells.py",
        "tests/fixtures/upgrade/v071-observed-profile.json",
        "tests/fixtures/upgrade/valid-inventory.json",
        "Cargo.toml",
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    shutil.copytree(ROOT / "docs/schema", destination / "docs/schema")


def mutation_line(path: Path, needle: str) -> int:
    text = path.read_text(encoding="utf-8")
    index = text.index(needle)
    return text[:index].count("\n") + 1


def apply_mutation(tree: Path, mutation: dict) -> None:
    path = tree / mutation["file"]
    text = path.read_text(encoding="utf-8")
    if mutation["old"] not in text:
        raise RuntimeError(f"mutation text absent for {mutation['site']}")
    path.write_text(text.replace(mutation["old"], mutation["new"], 1), encoding="utf-8")


def run_tests(tree: Path, selectors: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*TEST_MODULE, *selectors],
        cwd=tree,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def sweep(mutations: list[dict], timeout: int, keep: bool) -> dict:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="upgrade-mutation-sweep-") as tmp:
        base = Path(tmp)
        control_tree = base / "control"
        control_tree.mkdir()
        copy_cell_tree(control_tree)
        control = run_tests(control_tree, CONTROL_TESTS, timeout)
        results = []
        for index, mutation in enumerate(mutations):
            tree = base / f"mutation-{index}"
            tree.mkdir()
            copy_cell_tree(tree)
            apply_mutation(tree, mutation)
            try:
                completed = run_tests(tree, [mutation["killer"]], timeout)
                output = completed.stdout[-3000:]
                returncode = completed.returncode
                error = ""
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or "")[-3000:] if isinstance(exc.stdout, str) else ""
                returncode = None
                error = f"timeout after {timeout}s"
            original = ROOT / mutation["file"]
            line = mutation_line(original, mutation["old"])
            killed = returncode not in (0, None)
            results.append(
                {
                    "site": mutation["site"],
                    "file": mutation["file"],
                    "line": line,
                    "guard": mutation["old"].strip().replace("\n", " ")[:180],
                    "killer": mutation["killer"],
                    "returncode": returncode,
                    "killed": killed,
                    "error": error,
                    "output_tail": output,
                }
            )
            if not keep:
                shutil.rmtree(tree, ignore_errors=True)
    killed_count = sum(1 for row in results if row["killed"])
    return {
        "control": {
            "selectors": CONTROL_TESTS,
            "returncode": control.returncode,
            "output_tail": control.stdout[-3000:],
        },
        "mutations": results,
        "total": len(results),
        "killed": killed_count,
        "survived": len(results) - killed_count,
        "seconds": round(time.time() - started, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="write machine-readable sweep results")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--keep", action="store_true", help="keep mutated copies inside the sweep tempdir while it exists")
    parser.add_argument("--list", action="store_true", help="validate and list mutation sites without running tests")
    args = parser.parse_args()
    if args.list:
        for mutation in MUTATIONS:
            line = mutation_line(ROOT / mutation["file"], mutation["old"])
            print(f"{mutation['file']}:{line}: {mutation['site']} -> {mutation['killer']}")
        return 0
    result = sweep(MUTATIONS, args.timeout, args.keep)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(f"mutation sweep: {result['killed']}/{result['total']} killed, control rc={result['control']['returncode']}")
    for row in result["mutations"]:
        state = "KILLED" if row["killed"] else "SURVIVED"
        print(f"{state} {row['file']}:{row['line']} {row['site']} ({row['killer']})")
    return 0 if result["control"]["returncode"] == 0 and result["survived"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
