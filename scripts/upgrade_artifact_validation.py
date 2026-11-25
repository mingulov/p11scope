#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Typed validators for the upgrade-cell artifacts.

The upgrade gates prove compatibility by reading artifacts produced by a
v0.7.1 or current binary.  A bare schema label is not evidence: these
validators require the contract fields, primitive types and internal counts
that make an inventory, inventory-diff or CycloneDX conversion substantive.
The module is deliberately standard-library only so the shell package gate
can use it inside minimal package-test containers.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import json_schema
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import json_schema

INVENTORY_SCHEMA = "p11scope/inventory/v1"
DIFF_SCHEMA = "p11scope/inventory-diff/v1"
PROFILE_SCHEMA = "p11scope/observed-profile/v3"
PROFILE_INPUT_NOTE = (
    "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
)

INVENTORY_ROOT_FIELDS = (
    "scope",
    "clock",
    "observation",
    "pid_namespace",
    "budgets",
    "callers",
    "modules",
    "edges",
    "object_observations",
    "gaps",
    "gaps_suppressed",
)

DIFF_ROOT_FIELDS = (
    "schema",
    "before",
    "after",
    "comparison",
    "summary",
    "module_contents",
    "application_changes",
    "module_path_changes",
    "unresolved",
    "limitations",
)

DIFF_SNAPSHOT_FIELDS = (
    "scope",
    "clock",
    "observation",
    "pid_namespace",
    "scope_completeness",
    "reported_gaps",
    "suppressed_gaps",
    "refusals",
    "budgets",
    "loss_evidence",
    "gaps",
    "evidence",
)

DIFF_BASELINE_LIMITATIONS = {
    "absence_is_not_removal",
    "application_groups_use_recorded_paths",
    "counts_are_independent_windows",
    "host_boot_continuity_unknown",
    "physical_continuity_unknown",
    "process_continuity_unknown",
    "scope_completeness_unknown",
    "semantic_details_not_compared",
}

CBOM_ROOT_FIELDS = ("bomFormat", "specVersion", "metadata", "components", "dependencies")
SCHEMA_ROOT = Path(__file__).resolve().parent.parent / "docs" / "schema"
INVENTORY_SCHEMA_FILE = SCHEMA_ROOT / "inventory-v1.schema.json"
DIFF_SCHEMA_FILE = SCHEMA_ROOT / "inventory-diff-v1.schema.json"
CBOM_SCHEMA_FILE = SCHEMA_ROOT / "bom-1.6.schema.json"

CBOM_NUMERIC_PROPERTIES = (
    "p11scope:established_source_query",
    "p11scope:established_source_creation_success",
    "p11scope:established_source_unrecorded",
    "p11scope:algorithms",
    "p11scope:keys",
    "p11scope:callers_unknown_exe",
    "p11scope:mechanisms_unnamed",
    "p11scope:mechanisms_unknown_primitive",
    "p11scope:keys_unknown_size",
    "p11scope:keys_unknown_type",
)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def nonnegative_int(value) -> bool:
    return is_int(value) and value >= 0


def positive_int(value) -> bool:
    return is_int(value) and value > 0


def type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    return type(value).__name__


def nonempty_string(value) -> bool:
    return isinstance(value, str) and bool(value)


def sha256_hex(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(byte in "0123456789abcdef" for byte in value)
    )


def decimal_string(value) -> bool:
    return isinstance(value, str) and value.isdigit()


def missing(errors: list[str], owner: str, field: str) -> None:
    errors.append(f"missing {owner} field '{field}'")


def wrong_type(errors: list[str], field: str, value, expected: str) -> None:
    errors.append(f"{field} is {type_name(value)}, expected {expected}")



def product_schema_errors(document, schema_file: Path, artifact: str) -> list[str]:
    """Validate one artifact against the product schema, with offline references."""
    try:
        schema = json_schema.load_schema(schema_file)
        errors = json_schema.validate(document, schema, schema_file)
    except (json_schema.SchemaError, OSError, ValueError) as exc:
        return [f"{artifact} schema validation unavailable: {exc}"]
    return [f"{artifact} schema: {error}" for error in errors]


def inventory_positive_errors(document) -> list[str]:
    """The small positive payload rule for the known SoftHSM workload."""
    errors: list[str] = []
    if len(document.get("callers", [])) < 1:
        errors.append("inventory positive payload: fewer than one typed caller row")
    if len(document.get("modules", [])) < 1:
        errors.append("inventory positive payload: fewer than one typed provider row")
    if len(document.get("edges", [])) < 1:
        errors.append("inventory positive payload: fewer than one typed caller-provider edge")
    return errors


def cbom_component_counts(document) -> dict[str, int]:
    counts = {"applications": 0, "providers": 0, "algorithms": 0, "keys": 0}
    components = document.get("components") if isinstance(document, dict) else None
    if not isinstance(components, list):
        return counts
    for component in components:
        if not isinstance(component, dict):
            continue
        reference = component.get("bom-ref")
        if component.get("type") == "application":
            counts["applications"] += 1
        if component.get("type") == "library" and isinstance(reference, str) and reference.startswith("p11scope:module:"):
            counts["providers"] += 1
        if isinstance(reference, str) and reference.startswith("p11scope:mechanism:"):
            counts["algorithms"] += 1
        if isinstance(reference, str) and reference.startswith("p11scope:key:"):
            counts["keys"] += 1
    return counts


def cbom_positive_errors(document, profile_input: bool = False) -> list[str]:
    """Check the positive metadata-count contract against typed components.

    Profile input cannot link mechanisms to a caller or key, so its
    application/key counts are legitimately zero by contract.  Inventory
    input uses the complete provider/application/mechanism rule.
    """
    errors: list[str] = []
    properties = cbom_properties(document)
    counts = cbom_component_counts(document)
    for name in ("applications", "providers", "algorithms", "keys"):
        property_name = f"p11scope:{name}"
        value = properties.get(property_name)
        if not decimal_string(value):
            errors.append(f"cbom positive payload: {property_name!r} is {value!r}, expected a decimal count")
            continue
        if int(value) != counts[name]:
            errors.append(
                f"cbom positive payload: {property_name!r} is {value}, "
                f"but {counts[name]} typed component(s) are present"
            )
    minimums = ("providers", "algorithms") if profile_input else ("applications", "providers", "algorithms")
    for name in minimums:
        if counts[name] < 1:
            errors.append(f"cbom positive payload: fewer than one typed {name} component")
    return errors


def diff_positive_errors(document) -> list[str]:
    """The diff positive rule: at least one compared caller row on each side."""
    errors: list[str] = []
    for side in ("before", "after"):
        snapshot = document.get(side) if isinstance(document, dict) else None
        evidence = snapshot.get("evidence") if isinstance(snapshot, dict) else None
        occurrences = evidence.get("caller_occurrences") if isinstance(evidence, dict) else None
        if not isinstance(occurrences, list) or not occurrences:
            errors.append(f"diff positive payload: fewer than one compared caller row on {side}")
    return errors

def validate_counter_object(value, field: str, keys, errors: list[str]) -> None:
    if not isinstance(value, dict):
        wrong_type(errors, field, value, "object")
        return
    for key in keys:
        if key not in value:
            missing(errors, field, key)
        elif not nonnegative_int(value[key]):
            wrong_type(errors, f"{field}.{key}", value[key], "a nonnegative integer")


def validate_native_witnesses(value, field: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        wrong_type(errors, field, value, "object")
        return
    for key in ("rows", "bound", "unbound", "pending", "integrity"):
        if key not in value:
            missing(errors, field, key)
        elif not nonnegative_int(value[key]):
            wrong_type(errors, f"{field}.{key}", value[key], "a nonnegative integer")
    if "unbound_reasons" not in value:
        missing(errors, field, "unbound_reasons")
    elif not isinstance(value["unbound_reasons"], dict):
        wrong_type(errors, f"{field}.unbound_reasons", value["unbound_reasons"], "object")
    placement = value.get("placement")
    if not isinstance(placement, dict):
        wrong_type(errors, f"{field}.placement", placement, "object")
        return
    for key in ("edge", "module", "ambiguous", "unresolved"):
        if key not in placement:
            missing(errors, f"{field}.placement", key)
        elif not nonnegative_int(placement[key]):
            wrong_type(
                errors,
                f"{field}.placement.{key}",
                placement[key],
                "a nonnegative integer",
            )


def validate_inventory_observation(value, errors: list[str]) -> None:
    if not isinstance(value, dict):
        wrong_type(errors, "inventory field 'observation'", value, "object")
        return
    for key in ("started_ns", "ended_ns"):
        if key not in value:
            missing(errors, "inventory observation", key)
        elif not nonnegative_int(value[key]):
            wrong_type(errors, f"inventory observation.{key}", value[key], "a nonnegative integer")
    if nonnegative_int(value.get("started_ns")) and nonnegative_int(value.get("ended_ns")):
        if value["ended_ns"] < value["started_ns"]:
            errors.append("inventory observation ended_ns is before started_ns")
    if "passes" not in value:
        missing(errors, "inventory observation", "passes")
    elif not positive_int(value["passes"]):
        wrong_type(errors, "inventory observation.passes", value["passes"], "a positive integer")
    if "usage_feed" not in value:
        missing(errors, "inventory observation", "usage_feed")
    elif not isinstance(value["usage_feed"], bool):
        wrong_type(errors, "inventory observation.usage_feed", value["usage_feed"], "bool")
    if "native_witnesses" not in value:
        missing(errors, "inventory observation", "native_witnesses")
    else:
        validate_native_witnesses(
            value["native_witnesses"], "inventory observation.native_witnesses", errors
        )


def validate_inventory_budgets(value, errors: list[str]) -> None:
    if not isinstance(value, dict):
        wrong_type(errors, "inventory field 'budgets'", value, "object")
        return
    triples = (
        "callers",
        "modules",
        "edges",
        "endpoints",
        "inventory_endpoints",
        "inventory_attach_modules",
    )
    for key in triples:
        if key not in value:
            missing(errors, "inventory budgets", key)
        else:
            validate_counter_object(
                value[key], f"inventory budgets.{key}", ("limit", "occupied", "refused"), errors
            )
    if "counters" not in value:
        missing(errors, "inventory budgets", "counters")
    else:
        validate_counter_object(
            value["counters"],
            "inventory budgets.counters",
            ("cap", "observed_edges", "saturated_edges"),
            errors,
        )
    if "semantic_state" not in value:
        missing(errors, "inventory budgets", "semantic_state")
    else:
        semantic = value["semantic_state"]
        if not isinstance(semantic, dict):
            wrong_type(errors, "inventory budgets.semantic_state", semantic, "object")
        else:
            for key in ("limit", "occupied", "unknown_edges", "refused"):
                if key not in semantic:
                    missing(errors, "inventory budgets.semantic_state", key)
                elif not nonnegative_int(semantic[key]):
                    wrong_type(
                        errors,
                        f"inventory budgets.semantic_state.{key}",
                        semantic[key],
                        "a nonnegative integer",
                    )
            if not nonempty_string(semantic.get("status")):
                wrong_type(
                    errors,
                    "inventory budgets.semantic_state.status",
                    semantic.get("status"),
                    "a nonempty string",
                )
    if "retained_history" not in value:
        missing(errors, "inventory budgets", "retained_history")
    else:
        validate_counter_object(
            value["retained_history"],
            "inventory budgets.retained_history",
            ("limit", "retained", "suppressed"),
            errors,
        )
    if "native_preadmission" not in value:
        missing(errors, "inventory budgets", "native_preadmission")
    elif value["native_preadmission"] is not None:
        validate_counter_object(
            value["native_preadmission"],
            "inventory budgets.native_preadmission",
            ("limit", "occupied", "refused", "pruned"),
            errors,
        )


def validate_inventory_caller(row, index: int, errors: list[str]) -> None:
    field = f"inventory callers[{index}]"
    if not isinstance(row, dict):
        wrong_type(errors, field, row, "object")
        return
    if not nonempty_string(row.get("id")):
        wrong_type(errors, f"{field}.id", row.get("id"), "a nonempty string")
    if not nonnegative_int(row.get("pid")):
        wrong_type(errors, f"{field}.pid", row.get("pid"), "a nonnegative integer")
    if "start_time" not in row:
        missing(errors, field, "start_time")
    elif row["start_time"] is not None and not nonnegative_int(row["start_time"]):
        wrong_type(errors, f"{field}.start_time", row["start_time"], "null or a nonnegative integer")
    if not nonempty_string(row.get("start_time_unit")):
        wrong_type(errors, f"{field}.start_time_unit", row.get("start_time_unit"), "a nonempty string")
    if not isinstance(row.get("image"), dict):
        wrong_type(errors, f"{field}.image", row.get("image"), "object")
    if not nonempty_string(row.get("lifecycle")):
        wrong_type(errors, f"{field}.lifecycle", row.get("lifecycle"), "a nonempty string")
    for key in ("first_seen_ns", "last_seen_ns"):
        if not nonnegative_int(row.get(key)):
            wrong_type(errors, f"{field}.{key}", row.get(key), "a nonnegative integer")


def validate_inventory_module(row, index: int, errors: list[str]) -> None:
    field = f"inventory modules[{index}]"
    if not isinstance(row, dict):
        wrong_type(errors, field, row, "object")
        return
    if not nonempty_string(row.get("id")):
        wrong_type(errors, f"{field}.id", row.get("id"), "a nonempty string")
    paths = row.get("paths")
    if not isinstance(paths, list) or not all(nonempty_string(path) for path in paths):
        wrong_type(errors, f"{field}.paths", paths, "an array of nonempty strings")
    identity = row.get("identity")
    if not isinstance(identity, dict):
        wrong_type(errors, f"{field}.identity", identity, "object")
    else:
        device = identity.get("device")
        if not isinstance(device, dict):
            wrong_type(errors, f"{field}.identity.device", device, "object")
        else:
            for key in ("major", "minor"):
                if not nonnegative_int(device.get(key)):
                    wrong_type(
                        errors,
                        f"{field}.identity.device.{key}",
                        device.get(key),
                        "a nonnegative integer",
                    )
        if not nonnegative_int(identity.get("inode")):
            wrong_type(errors, f"{field}.identity.inode", identity.get("inode"), "a nonnegative integer")
        digest = identity.get("sha256")
        if digest is not None and not sha256_hex(digest):
            wrong_type(errors, f"{field}.identity.sha256", digest, "null or 64 lowercase hex characters")
    admission = row.get("admission")
    if not isinstance(admission, dict):
        wrong_type(errors, f"{field}.admission", admission, "object")
    elif not nonempty_string(admission.get("state")):
        wrong_type(errors, f"{field}.admission.state", admission.get("state"), "a nonempty string")
    if not nonempty_string(row.get("lifecycle")):
        wrong_type(errors, f"{field}.lifecycle", row.get("lifecycle"), "a nonempty string")


def validate_inventory_edge(row, index: int, errors: list[str]) -> None:
    field = f"inventory edges[{index}]"
    if not isinstance(row, dict):
        wrong_type(errors, field, row, "object")
        return
    for key in ("caller", "module"):
        if not nonempty_string(row.get(key)):
            wrong_type(errors, f"{field}.{key}", row.get(key), "a nonempty string")
    mapping = row.get("mapping")
    if not isinstance(mapping, dict):
        wrong_type(errors, f"{field}.mapping", mapping, "object")
    else:
        if not nonempty_string(mapping.get("state")):
            wrong_type(errors, f"{field}.mapping.state", mapping.get("state"), "a nonempty string")
        for key in ("first_seen_ns", "last_seen_ns", "interruptions"):
            if not nonnegative_int(mapping.get(key)):
                wrong_type(errors, f"{field}.mapping.{key}", mapping.get(key), "a nonnegative integer")
    entries = row.get("entries")
    if not isinstance(entries, dict):
        wrong_type(errors, f"{field}.entries", entries, "object")
    else:
        for key in ("count", "cap"):
            if not nonnegative_int(entries.get(key)):
                wrong_type(errors, f"{field}.entries.{key}", entries.get(key), "a nonnegative integer")
        if not isinstance(entries.get("saturated"), bool):
            wrong_type(errors, f"{field}.entries.saturated", entries.get("saturated"), "bool")


def validate_inventory_gap(row, index: int, errors: list[str]) -> None:
    field = f"inventory gaps[{index}]"
    if not isinstance(row, dict):
        wrong_type(errors, field, row, "object")
        return
    for key in ("caller", "module", "pid", "budget"):
        if key not in row:
            missing(errors, field, key)
    for key in ("subject", "reason"):
        if not nonempty_string(row.get(key)):
            wrong_type(errors, f"{field}.{key}", row.get(key), "a nonempty string")
    if not positive_int(row.get("repeats")):
        wrong_type(errors, f"{field}.repeats", row.get("repeats"), "a positive integer")


def validate_object_observations(value, errors: list[str]) -> None:
    if not isinstance(value, dict):
        wrong_type(errors, "inventory field 'object_observations'", value, "object")
        return
    for key in ("version", "revision"):
        if not nonnegative_int(value.get(key)):
            wrong_type(errors, f"inventory object_observations.{key}", value.get(key), "a nonnegative integer")
    for key in ("status", "reason"):
        if not nonempty_string(value.get(key)):
            wrong_type(errors, f"inventory object_observations.{key}", value.get(key), "a nonempty string")
    for key in ("key_operations", "objects", "sessions", "unknown_key_operations"):
        if key in value and not isinstance(value[key], list):
            wrong_type(errors, f"inventory object_observations.{key}", value[key], "array")


def inventory_errors(document) -> list[str]:
    """Return deterministic typed-contract errors for an inventory report."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return [f"inventory root is {type_name(document)}, expected object"]
    if document.get("schema") != INVENTORY_SCHEMA:
        errors.append(f"schema is {document.get('schema')!r}, expected {INVENTORY_SCHEMA!r}")
    for key in INVENTORY_ROOT_FIELDS:
        if key not in document:
            missing(errors, "inventory root", key)
    if "scope" in document and not nonempty_string(document["scope"]):
        wrong_type(errors, "inventory field 'scope'", document["scope"], "a nonempty string")
    clock = document.get("clock")
    if "clock" in document:
        if not isinstance(clock, dict):
            wrong_type(errors, "inventory field 'clock'", clock, "object")
        else:
            if clock.get("basis") != "CLOCK_MONOTONIC":
                errors.append(f"inventory clock.basis is {clock.get('basis')!r}, expected 'CLOCK_MONOTONIC'")
            if clock.get("unit") != "ns":
                errors.append(f"inventory clock.unit is {clock.get('unit')!r}, expected 'ns'")
    if "observation" in document:
        validate_inventory_observation(document["observation"], errors)
    pid_namespace = document.get("pid_namespace")
    if "pid_namespace" in document and pid_namespace is not None:
        if not isinstance(pid_namespace, dict):
            wrong_type(errors, "inventory field 'pid_namespace'", pid_namespace, "null or object")
        else:
            for key in ("observer", "kernel_pids", "proc_pids"):
                if not nonempty_string(pid_namespace.get(key)):
                    wrong_type(errors, f"inventory pid_namespace.{key}", pid_namespace.get(key), "a nonempty string")
    if "budgets" in document:
        validate_inventory_budgets(document["budgets"], errors)
    for key, row_validator in (
        ("callers", validate_inventory_caller),
        ("modules", validate_inventory_module),
        ("edges", validate_inventory_edge),
        ("gaps", validate_inventory_gap),
    ):
        rows = document.get(key)
        if key in document:
            if not isinstance(rows, list):
                wrong_type(errors, f"inventory field '{key}'", rows, "array")
            else:
                for index, row in enumerate(rows):
                    row_validator(row, index, errors)
    if "object_observations" in document:
        validate_object_observations(document["object_observations"], errors)
    if "gaps_suppressed" in document and not nonnegative_int(document["gaps_suppressed"]):
        wrong_type(errors, "inventory field 'gaps_suppressed'", document["gaps_suppressed"], "a nonnegative integer")
    if not errors:
        errors.extend(product_schema_errors(document, INVENTORY_SCHEMA_FILE, "inventory"))
    errors.extend(inventory_positive_errors(document))
    return errors


def object_observation_render(document: dict) -> str:
    section = document.get("object_observations")
    if not isinstance(section, dict):
        return "absent"
    status = section.get("status") if isinstance(section.get("status"), str) else "unknown"
    reason = section.get("reason") if isinstance(section.get("reason"), str) else "unknown"
    if status == "populated":
        return "populated"
    return f"{status} ({reason})"


def inventory_application_paths(document: dict) -> set[str]:
    paths: set[str] = set()
    for caller in document.get("callers", []):
        if not isinstance(caller, dict):
            continue
        path = (
            caller.get("image", {})
            .get("exe", {})
            .get("path")
            if isinstance(caller.get("image"), dict)
            else None
        )
        if nonempty_string(path):
            paths.add(path)
    for module in document.get("modules", []):
        if not isinstance(module, dict):
            continue
        departed = module.get("departed_use")
        if not isinstance(departed, dict):
            continue
        identities = departed.get("identities")
        if not isinstance(identities, list):
            continue
        for identity in identities:
            if not isinstance(identity, dict):
                continue
            exe = identity.get("exe")
            path = exe.get("path") if isinstance(exe, dict) else None
            if nonempty_string(path):
                paths.add(path)
    return paths


def cbom_properties(document) -> dict[str, str]:
    properties: dict[str, str] = {}
    metadata = document.get("metadata") if isinstance(document, dict) else None
    rows = metadata.get("properties") if isinstance(metadata, dict) else None
    if not isinstance(rows, list):
        return properties
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        value = row.get("value")
        if isinstance(name, str) and isinstance(value, str):
            properties[name] = value
    return properties


def cbom_structure_errors(document) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return [f"cbom root is {type_name(document)}, expected object"]
    for key in CBOM_ROOT_FIELDS:
        if key not in document:
            missing(errors, "cbom root", key)
    if "bomFormat" in document and document["bomFormat"] != "CycloneDX":
        errors.append(f"cbom bomFormat is {document['bomFormat']!r}, expected 'CycloneDX'")
    if "specVersion" in document and document["specVersion"] != "1.6":
        errors.append(f"cbom specVersion is {document['specVersion']!r}, expected '1.6'")
    metadata = document.get("metadata")
    if "metadata" in document:
        if not isinstance(metadata, dict):
            wrong_type(errors, "cbom field 'metadata'", metadata, "object")
        elif not isinstance(metadata.get("properties"), list):
            wrong_type(errors, "cbom metadata.properties", metadata.get("properties"), "array")
    for key in ("components", "dependencies"):
        if key in document and not isinstance(document[key], list):
            wrong_type(errors, f"cbom field '{key}'", document[key], "array")
    rows = metadata.get("properties") if isinstance(metadata, dict) else None
    if isinstance(rows, list):
        names = set()
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                wrong_type(errors, f"cbom metadata.properties[{index}]", row, "object")
                continue
            if not nonempty_string(row.get("name")):
                wrong_type(errors, f"cbom metadata.properties[{index}].name", row.get("name"), "a nonempty string")
            elif row["name"] in names:
                errors.append(f"cbom metadata property {row['name']!r} is duplicated")
            else:
                names.add(row["name"])
            if not isinstance(row.get("value"), str):
                wrong_type(errors, f"cbom metadata.properties[{index}].value", row.get("value"), "string")
    return errors


def compare_cbom_properties(document, expected: dict[str, str], errors: list[str]) -> dict[str, str]:
    props = cbom_properties(document)
    for name, wanted in expected.items():
        actual = props.get(name)
        if actual != wanted:
            errors.append(f"cbom property {name!r} is {actual!r}, expected {wanted!r}")
    for name in CBOM_NUMERIC_PROPERTIES:
        if not decimal_string(props.get(name)):
            errors.append(f"cbom property {name!r} is {props.get(name)!r}, expected a decimal count")
    return props


def cbom_inventory_errors(document, source) -> list[str]:
    """Validate structure plus exact inventory-to-cbom flow-through."""
    errors = cbom_structure_errors(document)
    if errors:
        return errors
    source_errors = inventory_errors(source)
    if source_errors:
        return [f"inventory source: {error}" for error in source_errors]
    observation = source["observation"]
    expected = {
        "p11scope:source_schema": INVENTORY_SCHEMA,
        "p11scope:scope": source["scope"],
        "p11scope:window": f"{observation['started_ns']}..{observation['ended_ns']} (CLOCK_MONOTONIC ns)",
        "p11scope:passes": str(observation["passes"]),
        "p11scope:source_gaps": str(len(source["gaps"])),
        "p11scope:object_observations": object_observation_render(source),
        "p11scope:applications": str(len(inventory_application_paths(source))),
        "p11scope:providers": str(len(source["modules"])),
    }
    errors = []
    props = compare_cbom_properties(document, expected, errors)
    subjects = sorted(
        {
            row["subject"]
            for row in source["gaps"]
            if isinstance(row, dict) and nonempty_string(row.get("subject"))
        }
    )
    expected_subjects = ",".join(subjects)
    if subjects and props.get("p11scope:gap_subjects") != expected_subjects:
        errors.append(
            f"cbom property 'p11scope:gap_subjects' is {props.get('p11scope:gap_subjects')!r}, "
            f"expected {expected_subjects!r}"
        )
    if not subjects and "p11scope:gap_subjects" in props:
        errors.append("cbom property 'p11scope:gap_subjects' is present for a zero-subject source")
    suppressed = str(source["gaps_suppressed"])
    if source["gaps_suppressed"] and props.get("p11scope:gaps_suppressed") != suppressed:
        errors.append(
            f"cbom property 'p11scope:gaps_suppressed' is {props.get('p11scope:gaps_suppressed')!r}, "
            f"expected {suppressed!r}"
        )
    if not source["gaps_suppressed"] and "p11scope:gaps_suppressed" in props:
        errors.append("cbom property 'p11scope:gaps_suppressed' is present for a zero source count")
    if not errors:
        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, "cbom"))
    errors.extend(cbom_positive_errors(document, profile_input=False))
    return errors


def cbom_profile_errors(document, profile) -> list[str]:
    """Validate structure plus exact profile-to-cbom flow-through."""
    errors = cbom_structure_errors(document)
    if errors:
        return errors
    if not isinstance(profile, dict):
        return [f"profile source is {type_name(profile)}, expected object"]
    capture = profile.get("capture") if isinstance(profile.get("capture"), dict) else {}
    evidence = profile.get("evidence") if isinstance(profile.get("evidence"), dict) else {}
    start = capture.get("start")
    end = capture.get("end")
    window = f"{start}..{end} (capture wall clock)" if nonempty_string(start) and nonempty_string(end) else ""
    modules = capture.get("modules") if isinstance(capture.get("modules"), list) else []
    mechanisms = profile.get("mechanisms") if isinstance(profile.get("mechanisms"), list) else []
    mechanism_ids = {
        row.get("mechanism")
        for row in mechanisms
        if isinstance(row, dict) and nonnegative_int(row.get("mechanism"))
    }
    expected = {
        "p11scope:source_schema": profile.get("schema", ""),
        "p11scope:window": window,
        "p11scope:profile_note": PROFILE_INPUT_NOTE,
        "p11scope:completeness": evidence.get("completeness", ""),
        "p11scope:providers": str(len(modules)),
        "p11scope:algorithms": str(len(mechanism_ids)),
        "p11scope:applications": "0",
        "p11scope:keys": "0",
        "p11scope:object_observations": "absent",
    }
    errors = []
    compare_cbom_properties(document, expected, errors)
    if not errors:
        errors.extend(product_schema_errors(document, CBOM_SCHEMA_FILE, "cbom"))
    errors.extend(cbom_positive_errors(document, profile_input=True))
    return errors


def sorted_unique_strings(value) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(row, str) and row for row in value)
        and value == sorted(set(value))
        and len(value) == len(set(value))
    )


def sorted_nonnegative_ints(value) -> bool:
    return (
        isinstance(value, list)
        and all(nonnegative_int(row) for row in value)
        and value == sorted(value)
    )


def validate_diff_snapshot(snapshot, side: str, errors: list[str]) -> None:
    owner = f"diff {side}"
    if not isinstance(snapshot, dict):
        wrong_type(errors, f"{owner} snapshot", snapshot, "object")
        return
    for key in DIFF_SNAPSHOT_FIELDS:
        if key not in snapshot:
            missing(errors, owner, key)
    if "scope" in snapshot and not nonempty_string(snapshot["scope"]):
        wrong_type(errors, f"{owner}.scope", snapshot["scope"], "a nonempty string")
    clock = snapshot.get("clock")
    if "clock" in snapshot:
        if not isinstance(clock, dict):
            wrong_type(errors, f"{owner}.clock", clock, "object")
        else:
            if clock.get("basis") != "CLOCK_MONOTONIC":
                errors.append(f"{owner}.clock.basis is {clock.get('basis')!r}, expected 'CLOCK_MONOTONIC'")
            if clock.get("unit") != "ns":
                errors.append(f"{owner}.clock.unit is {clock.get('unit')!r}, expected 'ns'")
    observation = snapshot.get("observation")
    if "observation" in snapshot:
        if not isinstance(observation, dict):
            wrong_type(errors, f"{owner}.observation", observation, "object")
        else:
            for key in ("started_ns", "ended_ns"):
                if not nonnegative_int(observation.get(key)):
                    wrong_type(errors, f"{owner}.observation.{key}", observation.get(key), "a nonnegative integer")
            if nonnegative_int(observation.get("started_ns")) and nonnegative_int(observation.get("ended_ns")):
                if observation["ended_ns"] < observation["started_ns"]:
                    errors.append(f"{owner}.observation ended_ns is before started_ns")
            if not positive_int(observation.get("passes")):
                wrong_type(errors, f"{owner}.observation.passes", observation.get("passes"), "a positive integer")
            if not isinstance(observation.get("usage_feed"), bool):
                wrong_type(errors, f"{owner}.observation.usage_feed", observation.get("usage_feed"), "bool")
            if "native_witnesses" not in observation:
                missing(errors, f"{owner}.observation", "native_witnesses")
            else:
                validate_native_witnesses(
                    observation["native_witnesses"], f"{owner}.observation.native_witnesses", errors
                )
    if snapshot.get("scope_completeness") != "unknown":
        errors.append(f"{owner}.scope_completeness is {snapshot.get('scope_completeness')!r}, expected 'unknown'")
    for key in ("reported_gaps", "suppressed_gaps"):
        if key in snapshot and not nonnegative_int(snapshot[key]):
            wrong_type(errors, f"{owner}.{key}", snapshot[key], "a nonnegative integer")
    gaps = snapshot.get("gaps")
    if "gaps" in snapshot and not isinstance(gaps, list):
        wrong_type(errors, f"{owner}.gaps", gaps, "array")
    if isinstance(gaps, list) and nonnegative_int(snapshot.get("reported_gaps")):
        if snapshot["reported_gaps"] != len(gaps):
            errors.append(f"{owner} reported_gaps is {snapshot['reported_gaps']}, expected {len(gaps)}")
    refusals = snapshot.get("refusals")
    if "refusals" in snapshot:
        if not isinstance(refusals, dict):
            wrong_type(errors, f"{owner}.refusals", refusals, "object")
        else:
            if not nonnegative_int(refusals.get("reported_budget_gaps")):
                wrong_type(
                    errors,
                    f"{owner}.refusals.reported_budget_gaps",
                    refusals.get("reported_budget_gaps"),
                    "a nonnegative integer",
                )
            if not isinstance(refusals.get("budget_counters"), dict):
                wrong_type(errors, f"{owner}.refusals.budget_counters", refusals.get("budget_counters"), "object")
    for key in ("budgets", "loss_evidence"):
        if key in snapshot and not isinstance(snapshot[key], dict):
            wrong_type(errors, f"{owner}.{key}", snapshot[key], "object")
    evidence = snapshot.get("evidence")
    if "evidence" in snapshot:
        if not isinstance(evidence, dict):
            wrong_type(errors, f"{owner}.evidence", evidence, "object")
        else:
            for pool in (
                "callers",
                "modules",
                "edges",
                "caller_occurrences",
                "module_occurrences",
                "edge_occurrences",
            ):
                if pool not in evidence:
                    missing(errors, f"{owner}.evidence", pool)
                elif not isinstance(evidence[pool], list):
                    wrong_type(errors, f"{owner}.evidence.{pool}", evidence[pool], "array")
            for pool in ("caller_occurrences", "module_occurrences", "edge_occurrences"):
                rows = evidence.get(pool)
                if isinstance(rows, list) and not all(nonnegative_int(row) for row in rows):
                    errors.append(f"{owner}.evidence.{pool} contains a non-reference")


def validate_projection_row(row, index: int, owner: str, errors: list[str]) -> bool:
    field = f"{owner}[{index}]"
    if not isinstance(row, dict):
        wrong_type(errors, field, row, "object")
        return False
    valid = True
    for key in ("key", "presence", "changes", "before", "after"):
        if key not in row:
            missing(errors, owner, key)
            valid = False
    if not isinstance(row.get("key"), dict):
        wrong_type(errors, f"{field}.key", row.get("key"), "object")
        valid = False
    if row.get("presence") not in ("both", "before_only", "after_only"):
        errors.append(f"{field}.presence is {row.get('presence')!r}, expected a projection presence label")
        valid = False
    if not sorted_unique_strings(row.get("changes")):
        wrong_type(errors, f"{field}.changes", row.get("changes"), "a sorted duplicate-free string array")
        valid = False
    for key in ("before", "after"):
        if not sorted_nonnegative_ints(row.get(key)):
            wrong_type(errors, f"{field}.{key}", row.get(key), "a sorted nonnegative reference array")
            valid = False
    return valid


def validate_module_contents(rows, errors: list[str]) -> dict[str, int]:
    counts = {"both": 0, "before_only": 0, "after_only": 0}
    if not isinstance(rows, list):
        wrong_type(errors, "diff field 'module_contents'", rows, "array")
        return counts
    for index, row in enumerate(rows):
        if not validate_projection_row(row, index, "diff module_contents", errors):
            continue
        digest = row["key"].get("sha256")
        if not sha256_hex(digest):
            wrong_type(errors, f"diff module_contents[{index}].key.sha256", digest, "64 lowercase hex characters")
        counts[row["presence"]] += 1
    return counts


def validate_application_changes(rows, application_paths: list[str], errors: list[str]) -> set[int]:
    changed_groups: set[int] = set()
    if not isinstance(rows, list):
        wrong_type(errors, "diff field 'application_changes'", rows, "array")
        return changed_groups
    for index, row in enumerate(rows):
        if not validate_projection_row(row, index, "diff application_changes", errors):
            continue
        key = row["key"]
        path_ref = key.get("exe_path_ref")
        if not nonnegative_int(path_ref) or path_ref >= len(application_paths):
            wrong_type(
                errors,
                f"diff application_changes[{index}].key.exe_path_ref",
                path_ref,
                "a comparison.application_paths reference",
            )
        else:
            changed_groups.add(path_ref)
        if not sha256_hex(key.get("sha256")):
            wrong_type(
                errors,
                f"diff application_changes[{index}].key.sha256",
                key.get("sha256"),
                "64 lowercase hex characters",
            )
        for side in ("before", "after"):
            population = row.get(f"{side}_population")
            if not isinstance(population, dict):
                wrong_type(errors, f"diff application_changes[{index}].{side}_population", population, "object")
                continue
            for pool in ("callers", "modules"):
                refs = population.get(pool)
                if not isinstance(refs, list) or not all(nonnegative_int(ref) for ref in refs):
                    wrong_type(
                        errors,
                        f"diff application_changes[{index}].{side}_population.{pool}",
                        refs,
                        "an array of nonnegative references",
                    )
    return changed_groups


def validate_module_path_changes(rows, errors: list[str]) -> int:
    if not isinstance(rows, list):
        wrong_type(errors, "diff field 'module_path_changes'", rows, "array")
        return 0
    for index, row in enumerate(rows):
        if not validate_projection_row(row, index, "diff module_path_changes", errors):
            continue
        path = row["key"].get("path")
        if not nonempty_string(path):
            wrong_type(errors, f"diff module_path_changes[{index}].key.path", path, "a nonempty string")
    return len(rows)


def validate_unresolved(rows, errors: list[str]) -> int:
    if not isinstance(rows, list):
        wrong_type(errors, "diff field 'unresolved'", rows, "array")
        return 0
    for index, row in enumerate(rows):
        field = f"diff unresolved[{index}]"
        if not isinstance(row, dict):
            wrong_type(errors, field, row, "object")
            continue
        if row.get("side") not in ("before", "after"):
            errors.append(f"{field}.side is {row.get('side')!r}, expected 'before' or 'after'")
        if row.get("kind") not in ("caller", "module", "edge"):
            errors.append(f"{field}.kind is {row.get('kind')!r}, expected 'caller', 'module' or 'edge'")
        reasons = row.get("reasons")
        if not isinstance(reasons, list) or not all(nonempty_string(reason) for reason in reasons):
            wrong_type(errors, f"{field}.reasons", reasons, "an array of nonempty strings")
    return len(rows)


def diff_source_consistency(snapshot, source, side: str, errors: list[str]) -> None:
    if source is None or not isinstance(snapshot, dict) or not isinstance(source, dict):
        return
    if inventory_errors(source):
        errors.append(f"diff {side} source is not a typed inventory report")
        return
    if snapshot.get("scope") != source["scope"]:
        errors.append(f"diff {side}.scope is {snapshot.get('scope')!r}, expected {source['scope']!r}")
    observation = snapshot.get("observation") if isinstance(snapshot.get("observation"), dict) else {}
    source_observation = source["observation"]
    for key in ("started_ns", "ended_ns", "passes", "usage_feed"):
        if observation.get(key) != source_observation[key]:
            errors.append(
                f"diff {side}.observation.{key} is {observation.get(key)!r}, "
                f"expected {source_observation[key]!r}"
            )
    if nonnegative_int(snapshot.get("reported_gaps")) and snapshot["reported_gaps"] != len(source["gaps"]):
        errors.append(f"diff {side}.reported_gaps is {snapshot['reported_gaps']}, expected {len(source['gaps'])}")
    if nonnegative_int(snapshot.get("suppressed_gaps")) and snapshot["suppressed_gaps"] != source["gaps_suppressed"]:
        errors.append(
            f"diff {side}.suppressed_gaps is {snapshot['suppressed_gaps']}, "
            f"expected {source['gaps_suppressed']}"
        )


def diff_errors(document, before_source=None, after_source=None) -> list[str]:
    """Validate the exact ten-root-field typed inventory-diff contract."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return [f"diff root is {type_name(document)}, expected object"]
    for key in DIFF_ROOT_FIELDS:
        if key not in document:
            missing(errors, "diff root", key)
    extras = sorted(set(document) - set(DIFF_ROOT_FIELDS))
    for key in extras:
        errors.append(f"unexpected diff root field '{key}'")
    if document.get("schema") != DIFF_SCHEMA:
        errors.append(f"diff schema is {document.get('schema')!r}, expected {DIFF_SCHEMA!r}")
    if "before" in document:
        validate_diff_snapshot(document["before"], "before", errors)
    if "after" in document:
        validate_diff_snapshot(document["after"], "after", errors)

    comparison = document.get("comparison")
    application_paths: list[str] = []
    if "comparison" in document:
        if not isinstance(comparison, dict):
            wrong_type(errors, "diff field 'comparison'", comparison, "object")
            comparison = None
        else:
            for key in (
                "host_relation",
                "boot_relation",
                "process_continuity",
                "physical_continuity",
            ):
                if comparison.get(key) != "unknown":
                    errors.append(f"diff comparison.{key} is {comparison.get(key)!r}, expected 'unknown'")
            if comparison.get("counter_relation") != "independent_windows":
                errors.append(
                    f"diff comparison.counter_relation is {comparison.get('counter_relation')!r}, "
                    "expected 'independent_windows'"
                )
            if comparison.get("scope_relation") not in ("same_recorded_label", "different_recorded_labels"):
                errors.append(
                    f"diff comparison.scope_relation is {comparison.get('scope_relation')!r}, "
                    "expected a recorded-label relation"
                )
            paths = comparison.get("application_paths")
            if not sorted_unique_strings(paths):
                wrong_type(
                    errors,
                    "diff comparison.application_paths",
                    paths,
                    "a sorted duplicate-free nonempty-string array",
                )
            else:
                application_paths = paths

    module_counts = validate_module_contents(document.get("module_contents"), errors) if "module_contents" in document else {"both": 0, "before_only": 0, "after_only": 0}
    changed_groups = (
        validate_application_changes(document.get("application_changes"), application_paths, errors)
        if "application_changes" in document
        else set()
    )
    module_path_count = (
        validate_module_path_changes(document.get("module_path_changes"), errors)
        if "module_path_changes" in document
        else 0
    )
    unresolved_count = validate_unresolved(document.get("unresolved"), errors) if "unresolved" in document else 0

    summary = document.get("summary")
    if "summary" in document:
        if not isinstance(summary, dict):
            wrong_type(errors, "diff field 'summary'", summary, "object")
        else:
            summary_keys = (
                "application_groups_compared",
                "application_groups_changed",
                "content_both",
                "content_before_only",
                "content_after_only",
                "module_paths_changed",
                "unresolved_observations",
            )
            for key in summary_keys:
                if key not in summary:
                    missing(errors, "diff summary", key)
                elif not nonnegative_int(summary[key]):
                    wrong_type(errors, f"diff summary.{key}", summary[key], "a nonnegative integer")
            expected_summary = {
                "application_groups_compared": len(application_paths),
                "application_groups_changed": len(changed_groups),
                "content_both": module_counts["both"],
                "content_before_only": module_counts["before_only"],
                "content_after_only": module_counts["after_only"],
                "module_paths_changed": module_path_count,
                "unresolved_observations": unresolved_count,
            }
            for key, expected in expected_summary.items():
                if nonnegative_int(summary.get(key)) and summary[key] != expected:
                    errors.append(f"diff summary {key} is {summary[key]}, expected {expected}")

    limitations = document.get("limitations")
    if "limitations" in document:
        if not sorted_unique_strings(limitations):
            wrong_type(errors, "diff field 'limitations'", limitations, "a sorted duplicate-free string array")
        else:
            missing_limitations = sorted(DIFF_BASELINE_LIMITATIONS - set(limitations))
            if missing_limitations:
                errors.append(f"diff limitations missing baseline codes {missing_limitations!r}")

    before = document.get("before") if isinstance(document.get("before"), dict) else {}
    after = document.get("after") if isinstance(document.get("after"), dict) else {}
    if comparison is not None and before and after:
        expected_relation = (
            "same_recorded_label"
            if before.get("scope") == after.get("scope")
            else "different_recorded_labels"
        )
        if comparison.get("scope_relation") in ("same_recorded_label", "different_recorded_labels"):
            if comparison["scope_relation"] != expected_relation:
                errors.append(
                    f"diff comparison.scope_relation is {comparison['scope_relation']!r}, "
                    f"expected {expected_relation!r}"
                )
    diff_source_consistency(document.get("before"), before_source, "before", errors)
    diff_source_consistency(document.get("after"), after_source, "after", errors)
    if not errors:
        errors.extend(product_schema_errors(document, DIFF_SCHEMA_FILE, "diff"))
    errors.extend(diff_positive_errors(document))
    return errors


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse JSON artifact {path}: {exc}") from exc


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in ("inventory", "diff"):
        print("usage: upgrade_artifact_validation.py inventory|diff ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        document = load_json(Path(args[1]))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    errors = inventory_errors(document) if args[0] == "inventory" else diff_errors(document)
    if errors:
        print(errors[0], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
