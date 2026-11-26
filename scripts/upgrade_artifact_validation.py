#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Typed validators for the upgrade-cell artifacts.

The upgrade gates prove compatibility by reading artifacts produced by a
v0.7.1 or current binary.  Shape is enforced only by the product's own
shipped JSON schemas (docs/schema/*.schema.json) through a real validator:
no hand-written shape code lives here, so the gates cannot drift from the
product contract.  On top of the schema each artifact carries two thin
layers the schema cannot express: cross-artifact flow-through (a derived
document must match the source it claims to convert) and one small
positive rule per artifact for the known SoftHSM workload (metadata
counts must equal the typed rows present, each at least one; a diff
must compare at least one caller row on each side).
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
PROFILE_INPUT_NOTE = (
    "profile input: mechanisms are capture-global, without caller, usage-edge or key linkage"
)

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


def decimal_string(value) -> bool:
    return isinstance(value, str) and value.isdigit()


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

def inventory_errors(document) -> list[str]:
    """Product-schema shape plus the positive payload rule for an inventory."""
    if not isinstance(document, dict):
        return [f"inventory root is {type_name(document)}, expected object"]
    errors = product_schema_errors(document, INVENTORY_SCHEMA_FILE, "inventory")
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
    """Exact inventory-to-cbom flow-through plus schema shape and positive payload."""
    if not isinstance(document, dict):
        return [f"cbom root is {type_name(document)}, expected object"]
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
    """Exact profile-to-cbom flow-through plus schema shape and positive payload."""
    if not isinstance(document, dict):
        return [f"cbom root is {type_name(document)}, expected object"]
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
    """Source consistency plus product-schema shape and the positive payload rule."""
    if not isinstance(document, dict):
        return [f"diff root is {type_name(document)}, expected object"]
    errors: list[str] = []
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
