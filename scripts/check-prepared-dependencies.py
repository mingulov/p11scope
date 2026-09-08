#!/usr/bin/env python3
"""Verify Cargo metadata selects exact prepared dependency source trees."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys


class MetadataError(Exception):
    """A deterministic refusal caused by malformed or mismatched metadata."""


def _load_preparer(root: Path):
    path = root / "scripts" / "prepare-dependencies.py"
    spec = importlib.util.spec_from_file_location("p11scope_prepare_dependencies", path)
    if spec is None or spec.loader is None:
        raise MetadataError(f"cannot load preparation verifier {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_metadata(path: Path, workspace: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MetadataError(f"workspace {workspace}: cannot read metadata {path}: {error}") from error
    if not isinstance(value, dict):
        raise MetadataError(f"workspace {workspace}: metadata root is not an object")
    return value


def _absolute_path(value: object, workspace: str, field: str) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise MetadataError(f"workspace {workspace}: {field} must be an absolute path")
    return Path(value).resolve()


def _graph(metadata: dict, workspace: str, expected_root: Path) -> tuple[dict[str, dict], set[str], dict]:
    format_version = metadata.get("version")
    if isinstance(format_version, bool) or not isinstance(format_version, int) or format_version != 1:
        raise MetadataError(f"workspace {workspace}: Cargo metadata format version must be integer 1")
    workspace_root = _absolute_path(metadata.get("workspace_root"), workspace, "workspace_root")
    if workspace_root != expected_root.resolve():
        raise MetadataError(
            f"workspace {workspace}: workspace_root mismatch: expected {expected_root.resolve()}, got {workspace_root}"
        )
    packages_value = metadata.get("packages")
    members = metadata.get("workspace_members")
    resolve = metadata.get("resolve")
    if not isinstance(packages_value, list) or not isinstance(members, list) or not isinstance(resolve, dict):
        raise MetadataError(f"workspace {workspace}: incomplete Cargo metadata graph")
    nodes_value = resolve.get("nodes")
    if not isinstance(nodes_value, list):
        raise MetadataError(f"workspace {workspace}: incomplete Cargo resolve nodes")

    packages: dict[str, dict] = {}
    for package in packages_value:
        if not isinstance(package, dict):
            raise MetadataError(f"workspace {workspace}: malformed package entry")
        package_id = package.get("id")
        if not isinstance(package_id, str) or not package_id or package_id in packages:
            raise MetadataError(f"workspace {workspace}: duplicate or invalid package id {package_id!r}")
        for field in ("name", "version", "manifest_path"):
            if not isinstance(package.get(field), str) or not package[field]:
                raise MetadataError(f"workspace {workspace}: package {package_id}: missing {field}")
        _absolute_path(package["manifest_path"], workspace, f"package {package_id} manifest_path")
        if "source" not in package or (
            package["source"] is not None and not isinstance(package["source"], str)
        ):
            raise MetadataError(f"workspace {workspace}: package {package_id}: source has invalid type")
        if not isinstance(package.get("dependencies"), list) or not isinstance(package.get("features"), dict):
            raise MetadataError(
                f"workspace {workspace}: package {package_id}: dependencies/features have invalid types"
            )
        packages[package_id] = package

    nodes: dict[str, list[str]] = {}
    node_details: dict[str, dict] = {}
    for node in nodes_value:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise MetadataError(f"workspace {workspace}: malformed resolve node")
        node_id = node["id"]
        legacy_dependencies = node.get("dependencies")
        if (
            node_id in nodes
            or not isinstance(legacy_dependencies, list)
            or not isinstance(node.get("deps"), list)
            or not isinstance(node.get("features"), list)
        ):
            raise MetadataError(f"workspace {workspace}: package {node_id}: incomplete or duplicate resolve node")
        if any(not isinstance(feature, str) for feature in node["features"]) or len(set(node["features"])) != len(node["features"]):
            raise MetadataError(f"workspace {workspace}: package {node_id}: features contain invalid or duplicate values")
        manifest_path = packages.get(node_id, {}).get("manifest_path", "unknown path")
        if any(not isinstance(dependency_id, str) or not dependency_id for dependency_id in legacy_dependencies):
            raise MetadataError(
                f"workspace {workspace}: package {node_id} at {manifest_path}: dependencies contain an invalid id"
            )
        if len(set(legacy_dependencies)) != len(legacy_dependencies):
            raise MetadataError(
                f"workspace {workspace}: package {node_id} at {manifest_path}: duplicate dependency id"
            )
        dependencies = []
        structured_edges = set()
        for dependency in node["deps"]:
            if (
                not isinstance(dependency, dict)
                or not isinstance(dependency.get("name"), str)
                or not dependency["name"]
                or not isinstance(dependency.get("pkg"), str)
                or not dependency["pkg"]
            ):
                raise MetadataError(
                    f"workspace {workspace}: package {node_id} at {manifest_path}: malformed dependency edge"
                )
            if not isinstance(dependency.get("dep_kinds"), list):
                raise MetadataError(
                    f"workspace {workspace}: package {node_id} at {manifest_path}: malformed dep_kinds"
                )
            kinds = []
            for dependency_kind in dependency["dep_kinds"]:
                if not isinstance(dependency_kind, dict):
                    raise MetadataError(
                        f"workspace {workspace}: package {node_id} at {manifest_path}: malformed dep_kinds"
                    )
                kind = dependency_kind.get("kind")
                target = dependency_kind.get("target")
                if (kind is not None and not isinstance(kind, str)) or (
                    target is not None and not isinstance(target, str)
                ):
                    raise MetadataError(
                        f"workspace {workspace}: package {node_id} at {manifest_path}: malformed dep_kinds"
                    )
                kinds.append((kind, target))
            if len(set(kinds)) != len(kinds):
                raise MetadataError(
                    f"workspace {workspace}: package {node_id} at {manifest_path}: duplicate dep_kinds"
                )
            edge = (
                dependency["name"],
                dependency["pkg"],
                tuple(sorted(kinds, key=lambda value: ((value[0] or ""), (value[1] or "")))),
            )
            if edge in structured_edges:
                raise MetadataError(
                    f"workspace {workspace}: package {node_id} at {manifest_path}: duplicate structured dependency edge"
                )
            structured_edges.add(edge)
            dependencies.append(dependency["pkg"])
        legacy_set = set(legacy_dependencies)
        structured_set = set(dependencies)
        if legacy_set != structured_set:
            difference = sorted(legacy_set ^ structured_set)
            raise MetadataError(
                f"workspace {workspace}: package {node_id} at {manifest_path}: dependency id sets differ: {difference}"
            )
        nodes[node_id] = dependencies
        node_details[node_id] = {
            "features": sorted(node["features"]),
            "edges": [
                {
                    "name": name,
                    "pkg": package_id,
                    "dep_kinds": [
                        {"kind": kind, "target": target} for kind, target in kinds
                    ],
                }
                for name, package_id, kinds in sorted(
                    structured_edges,
                    key=lambda edge: json.dumps(edge, sort_keys=True),
                )
            ],
        }
    if set(nodes) != set(packages):
        missing = sorted(set(packages) ^ set(nodes))
        raise MetadataError(f"workspace {workspace}: incomplete resolve/package identity set: {missing}")
    if not members or any(not isinstance(member, str) or member not in packages for member in members):
        raise MetadataError(f"workspace {workspace}: invalid workspace_members")
    if len(set(members)) != len(members):
        raise MetadataError(f"workspace {workspace}: duplicate workspace member id")
    resolve_root = resolve.get("root")
    if resolve_root is not None and (not isinstance(resolve_root, str) or resolve_root not in packages):
        raise MetadataError(f"workspace {workspace}: resolve root references unknown package {resolve_root!r}")
    for node_id, dependency_ids in nodes.items():
        for dependency_id in dependency_ids:
            if dependency_id not in packages:
                raise MetadataError(
                    f"workspace {workspace}: package {node_id} at {packages.get(node_id, {}).get('manifest_path', 'unknown path')}: "
                    f"dependency id {dependency_id} is absent"
                )
    for member in members:
        member_manifest = Path(packages[member]["manifest_path"]).resolve()
        try:
            member_manifest.relative_to(expected_root.resolve())
        except ValueError as error:
            raise MetadataError(
                f"workspace {workspace}: workspace member {member} manifest is outside workspace root: {member_manifest}"
            ) from error

    reachable = set()
    pending = list(members)
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        for dependency_id in nodes[package_id]:
            if dependency_id not in packages:
                raise MetadataError(
                    f"workspace {workspace}: package {package_id}: dependency id {dependency_id} is absent"
                )
            pending.append(dependency_id)
    snapshot = {
        "workspace_members": sorted(members),
        "packages": [
            {
                "id": package_id,
                "name": packages[package_id]["name"],
                "version": packages[package_id]["version"],
                "source": packages[package_id].get("source"),
                "manifest_path": str(Path(packages[package_id]["manifest_path"]).resolve()),
                "features": node_details[package_id]["features"],
                "edges": node_details[package_id]["edges"],
            }
            for package_id in sorted(reachable)
        ],
    }
    return packages, reachable, snapshot


def _manifest_contexts(values: list[str], expected: list[str]) -> dict[str, Path]:
    contexts: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise MetadataError(f"invalid metadata context {value!r}; expected WORKSPACE=FILE")
        workspace, filename = value.split("=", 1)
        if workspace in contexts:
            raise MetadataError(f"duplicate metadata context for {workspace}")
        contexts[workspace] = Path(filename)
    expected_set = set(expected)
    actual_set = set(contexts)
    if len(expected_set) != len(expected) or actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        raise MetadataError(f"metadata context mismatch: missing={missing}, extra={extra}")
    return contexts


def verify_details(root: Path, sources: Path, metadata_values: list[str]) -> dict:
    expected_sources = (root / "third-party" / "sources.json").resolve()
    if sources.resolve() != expected_sources:
        raise MetadataError(f"--sources must name exact repository manifest {expected_sources}")
    preparer = _load_preparer(root)
    try:
        manifest = preparer.load_manifest(root)
    except preparer.PreparationError as error:
        raise MetadataError(str(error)) from error
    contexts = _manifest_contexts(metadata_values, manifest["workspace_manifests"])
    declared_workspaces = set(manifest["workspace_manifests"])
    expected_mappings = set()
    for record in manifest["packages"]:
        for workspace in record["applies_to"]:
            if workspace not in declared_workspaces:
                raise MetadataError(
                    f"package {record['name']} {record['version']}: applicability names undeclared workspace {workspace}"
                )
            mapping = (workspace, record["name"], record["version"])
            if mapping in expected_mappings:
                raise MetadataError(
                    f"ambiguous expected mapping for workspace {workspace}: {record['name']} {record['version']}"
                )
            expected_mappings.add(mapping)
    selected_records = set()
    graph_snapshots = {}
    workspace_member_manifests = set()

    for workspace in manifest["workspace_manifests"]:
        metadata = _read_metadata(contexts[workspace], workspace)
        workspace_manifest = (root / workspace).resolve()
        packages, reachable, graph_snapshot = _graph(metadata, workspace, workspace_manifest.parent)
        graph_snapshots[workspace] = graph_snapshot
        workspace_member_manifests.update(
            str(Path(packages[member]["manifest_path"]).resolve())
            for member in graph_snapshot["workspace_members"]
        )
        applicable = [record for record in manifest["packages"] if workspace in record["applies_to"]]
        expected_paths = {
            (root / "third-party" / "src" / preparer.output_name(record) / "Cargo.toml").resolve(): record
            for record in applicable
        }

        for package_id in reachable:
            package = packages[package_id]
            manifest_path = Path(package["manifest_path"]).resolve()
            try:
                manifest_path.relative_to((root / "third-party" / "src").resolve())
            except ValueError:
                pass
            else:
                if manifest_path not in expected_paths:
                    raise MetadataError(
                        f"workspace {workspace}: unknown generated package {package['name']} {package['version']} at {manifest_path}"
                    )

        for record in applicable:
            matches = [
                packages[package_id] for package_id in reachable
                if packages[package_id]["name"] == record["name"]
                and packages[package_id]["version"] == record["version"]
            ]
            expected_path = (root / "third-party/src" / preparer.output_name(record) / "Cargo.toml").resolve()
            if len(matches) != 1:
                paths = [package["manifest_path"] for package in matches]
                raise MetadataError(
                    f"workspace {workspace}: package {record['name']} {record['version']} expected once at "
                    f"{expected_path}, reached {len(matches)} copies at {paths}"
                )
            actual_path = Path(matches[0]["manifest_path"]).resolve()
            if actual_path != expected_path:
                raise MetadataError(
                    f"workspace {workspace}: package {record['name']} {record['version']} expected {expected_path}, got {actual_path}"
                )
            selected_records.add(preparer.output_name(record))

    ledger: dict[str, str] = {}
    for record in manifest["packages"]:
        if preparer.output_name(record) not in selected_records:
            continue
        tree = root / "third-party/src" / preparer.output_name(record)
        try:
            patches = preparer.read_patch_bytes(root, record)
            recipe = preparer.compute_recipe_identity(record, patches)
            inventory = preparer.verified_prepared_inventory(tree, record, recipe)
        except preparer.PreparationError as error:
            workspaces = ",".join(record["applies_to"])
            raise MetadataError(
                f"workspace {workspaces}: package {record['name']} {record['version']} at {tree}: {error}"
            ) from error
        for relative, _mode, digest in inventory:
            repository_relative = (tree / relative).relative_to(root).as_posix()
            prior = ledger.setdefault(repository_relative, digest)
            if prior != digest:
                raise MetadataError(f"ledger path collision for {repository_relative}")
    return {
        "ledger": sorted(ledger.items(), key=lambda item: item[0].encode("utf-8")),
        "graphs": graph_snapshots,
        "workspace_member_manifests": sorted(workspace_member_manifests),
        "selected_records": sorted(selected_records),
    }


def verify(root: Path, sources: Path, metadata_values: list[str]) -> list[tuple[str, str]]:
    return verify_details(root, sources, metadata_values)["ledger"]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--metadata", action="append", default=[], metavar="WORKSPACE=FILE")
    parser.add_argument("--ledger", action="store_true")
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    try:
        ledger = verify(root, options.sources, options.metadata)
    except MetadataError as error:
        print(f"check-prepared-dependencies: refusal: {error}", file=sys.stderr)
        return 1
    if options.ledger:
        for relative, digest in ledger:
            print(f"{digest}  {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
