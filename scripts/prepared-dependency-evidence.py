#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture and recheck immutable evidence for selected prepared dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from _loader import load_path


SCHEMA_VERSION = 1
WORKSPACES = (
    ("root", "Cargo.toml", "stable"),
    ("bpf", "crates/ebpf/Cargo.toml", "bpf"),
)
METADATA_ARGUMENTS = (
    "metadata", "--locked", "--offline", "--all-features",
    "--format-version", "1", "--manifest-path",
)
QUERY_KINDS = ("command.json", "context.json", "status", "stdout.json", "stderr")
MAX_CANDIDATE_SCAN_ENTRIES = 100_000
MAX_CANDIDATE_MANIFEST_BYTES = 2 * 1024 * 1024
PRUNED_DIRECTORY_NAMES = {"target", ".git", ".claude", ".superpowers", "__pycache__"}


class EvidenceError(Exception):
    """A deterministic refusal while acquiring or validating evidence."""


def _load_module(path: Path, name: str):
    return load_path(path, name)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identity(path: Path, label: str) -> dict:
    try:
        info = path.stat()
        link_info = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label}: cannot inspect {path}: {error}") from error
    if stat.S_ISLNK(link_info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EvidenceError(f"{label}: must be a non-symlink regular file: {path}")
    try:
        value = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"{label}: cannot read {path}: {error}") from error
    return {
        "path": str(path.resolve()),
        "mode": stat.S_IMODE(info.st_mode),
        "size": len(value),
        "sha256": _digest(value),
    }


def _selected_tool(path: Path, label: str) -> dict:
    if not path.is_absolute():
        raise EvidenceError(f"{label}: selected tool path must be absolute: {path}")
    identity = _identity(path, label)
    if identity["mode"] & 0o111 == 0:
        raise EvidenceError(f"{label}: selected tool is not executable: {path}")
    identity["selected_path"] = str(path)
    return identity


def _artifact(prefix: Path, phase: str, suffix: str) -> Path:
    return Path(f"{prefix}.{phase}.{suffix}")


def _phase_suffixes(phase: str) -> list[str]:
    suffixes = [f"{context}.{kind}" for context, _workspace, _tool in WORKSPACES for kind in QUERY_KINDS]
    return suffixes + ["ledger.sha256", "receipt.json"]


def _validate_prefix(prefix: Path, phase: str) -> None:
    if not prefix.is_absolute():
        raise EvidenceError(f"artifact prefix must be absolute: {prefix}")
    parent = prefix.parent
    try:
        parent_info = parent.lstat()
    except OSError as error:
        raise EvidenceError(f"artifact prefix parent cannot be inspected: {parent}: {error}") from error
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise EvidenceError(f"artifact prefix parent must be a non-symlink directory: {parent}")
    for suffix in _phase_suffixes(phase):
        path = _artifact(prefix, phase, suffix)
        if path.exists() or path.is_symlink():
            raise EvidenceError(f"artifact already exists: {path}")


def _write_new(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(value)
        path.chmod(0o600)
    except FileExistsError as error:
        raise EvidenceError(f"artifact already exists: {path}") from error
    except OSError as error:
        raise EvidenceError(f"cannot write artifact {path}: {error}") from error


def _static_paths(root: Path, preparer) -> list[tuple[str, Path]]:
    try:
        manifest = preparer.load_manifest(root)
    except preparer.PreparationError as error:
        raise EvidenceError(f"recipe: {error}") from error
    values = [
        ("helper", root / "scripts/prepared-dependency-evidence.py"),
        ("checker", root / "scripts/check-prepared-dependencies.py"),
        ("preparer", root / "scripts/prepare-dependencies.py"),
        ("recipe", root / "third-party/sources.json"),
    ]
    for workspace in manifest["workspace_manifests"]:
        manifest_path = root / workspace
        values.append((f"manifest {workspace}", manifest_path))
        values.append((f"lock {manifest_path.parent / 'Cargo.lock'}", manifest_path.parent / "Cargo.lock"))
    for record in manifest["packages"]:
        for patch in record["patches"]:
            values.append((f"recipe patch {patch}", root / patch))
    return values


def _input_snapshot(root: Path, preparer, details: dict | None = None) -> dict:
    values = _static_paths(root, preparer)
    if details is not None:
        for member in details["workspace_member_manifests"]:
            values.append((f"workspace member manifest {member}", Path(member)))
        for relative, expected_digest in details["ledger"]:
            path = root / relative
            actual = _identity(path, f"prepared tree {relative}")
            if actual["sha256"] != expected_digest:
                raise EvidenceError(f"prepared tree {relative}: ledger digest changed")
            values.append((f"prepared tree {relative}", path))
    result = {}
    for label, path in values:
        canonical = str(path.resolve())
        identity = _identity(path, label)
        prior = result.setdefault(canonical, {"labels": [], **identity})
        if prior["sha256"] != identity["sha256"] or prior["mode"] != identity["mode"]:
            raise EvidenceError(f"input identity collision for {canonical}")
        prior["labels"].append(label)
        prior["labels"].sort()
    return dict(sorted(result.items()))


def _same_file_identity(left: dict, right: dict) -> bool:
    return all(left.get(field) == right.get(field) for field in ("path", "mode", "size", "sha256"))


def _pruned_directory(relative: Path) -> bool:
    parts = relative.parts
    if relative.name in PRUNED_DIRECTORY_NAMES or parts == ("dist",):
        return True
    if len(parts) >= 2 and parts[:2] == ("third-party", "archives"):
        return True
    return (
        len(parts) == 2
        and parts[0] == "third-party"
        and parts[1].startswith(".prepare-dependencies-stage-")
    )


def _candidate_inventory(root: Path) -> dict:
    candidates = {}
    entry_count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as error:
            raise EvidenceError(f"Cargo.toml candidate scan cannot read {directory}: {error}") from error
        child_directories = []
        for entry in entries:
            entry_count += 1
            if entry_count > MAX_CANDIDATE_SCAN_ENTRIES:
                raise EvidenceError(
                    f"Cargo.toml candidate scan exceeds {MAX_CANDIDATE_SCAN_ENTRIES} entries"
                )
            path = Path(entry.path)
            relative = path.relative_to(root)
            try:
                metadata = path.lstat()
            except OSError as error:
                raise EvidenceError(f"Cargo.toml candidate scan cannot inspect {path}: {error}") from error
            if entry.name == "Cargo.toml" and not stat.S_ISREG(metadata.st_mode):
                raise EvidenceError(f"Cargo.toml candidate is not a regular file: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                if not _pruned_directory(relative):
                    child_directories.append(path)
                continue
            if entry.name != "Cargo.toml":
                continue
            if metadata.st_size > MAX_CANDIDATE_MANIFEST_BYTES:
                raise EvidenceError(
                    f"Cargo.toml candidate exceeds {MAX_CANDIDATE_MANIFEST_BYTES} bytes: {path}"
                )
            identity = _identity(path, f"Cargo.toml candidate {relative.as_posix()}")
            identity["repository_relative"] = relative.as_posix()
            candidates[identity["path"]] = identity
        pending.extend(reversed(child_directories))
    return dict(sorted(candidates.items()))


def _current_tools(tools: dict) -> dict:
    current = {}
    for name in ("stable", "bpf"):
        current[name] = {}
        for kind in ("cargo", "rustc"):
            try:
                expected = tools[name][kind]
                selected_path = expected["selected_path"]
            except (KeyError, TypeError) as error:
                raise EvidenceError(f"receipt: missing {name} {kind} tool identity") from error
            if not isinstance(selected_path, str):
                raise EvidenceError(f"receipt: malformed {name} {kind} selected tool path")
            current[name][kind] = _selected_tool(Path(selected_path), f"{name} {kind} tool")
    return current


def _admit_members(details: dict, candidates: dict) -> None:
    for member in details["workspace_member_manifests"]:
        canonical = str(Path(member).resolve())
        if canonical not in candidates:
            raise EvidenceError(f"unsupported/unadmitted workspace member: {canonical}")


def _projection(details: dict) -> dict:
    return {
        "graphs": details["graphs"],
        "selected_records": details["selected_records"],
        "workspace_member_manifests": details["workspace_member_manifests"],
        "ledger": [[relative, digest] for relative, digest in details["ledger"]],
    }


def _query(root: Path, prefix: Path, phase: str, context: str, workspace: str,
           cargo: dict, rustc: dict) -> Path:
    argv = [cargo["path"], *METADATA_ARGUMENTS, workspace]
    command = {"argv": argv, "cargo": cargo}
    query_context = {
        "context": context,
        "workspace": workspace,
        "cwd": str(root),
        "rustc": rustc,
        "environment": {"RUSTC": rustc["path"]},
    }
    _write_new(_artifact(prefix, phase, f"{context}.command.json"), _json_bytes(command))
    _write_new(_artifact(prefix, phase, f"{context}.context.json"), _json_bytes(query_context))
    environment = os.environ.copy()
    environment["RUSTC"] = rustc["path"]
    try:
        result = subprocess.run(argv, cwd=root, env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
    except OSError as error:
        _write_new(_artifact(prefix, phase, f"{context}.status"), b"126\n")
        _write_new(_artifact(prefix, phase, f"{context}.stdout.json"), b"")
        _write_new(_artifact(prefix, phase, f"{context}.stderr"), str(error).encode("utf-8"))
        raise EvidenceError(f"{context} metadata query could not execute: {error}") from error
    _write_new(_artifact(prefix, phase, f"{context}.status"), f"{result.returncode}\n".encode("ascii"))
    _write_new(_artifact(prefix, phase, f"{context}.stdout.json"), result.stdout)
    stderr_artifact = _artifact(prefix, phase, f"{context}.stderr")
    _write_new(stderr_artifact, result.stderr)
    if result.returncode != 0:
        # Name the retained stderr artifact, never inline its bytes: this
        # refusal reaches logs and receipts, and the artifact exists
        # precisely so the failure text lives somewhere bounded and
        # reviewable. A bare status once had to be reproduced by hand to
        # learn what it meant.
        raise EvidenceError(
            f"{context} metadata query returned status {result.returncode}; "
            f"stderr retained at {stderr_artifact}"
        )
    return _artifact(prefix, phase, f"{context}.stdout.json")


def _artifact_identities(prefix: Path, phase: str) -> dict:
    result = {}
    for suffix in _phase_suffixes(phase):
        if suffix == "receipt.json":
            continue
        path = _artifact(prefix, phase, suffix)
        if path.exists():
            result[suffix] = _identity(path, f"{phase} evidence {suffix}")
    return result


def _ledger_bytes(ledger: list[list[str]] | list[tuple[str, str]]) -> bytes:
    return "".join(f"{digest}  {relative}\n" for relative, digest in ledger).encode("utf-8")


def _acquire(root: Path, prefix: Path, phase: str, tools: dict, checker, preparer,
             expected: dict | None = None) -> dict:
    _validate_prefix(prefix, phase)
    before = _input_snapshot(root, preparer)
    before_candidates = _candidate_inventory(root)
    if expected is not None and before_candidates != expected["candidates"]:
        raise EvidenceError("retained Cargo.toml candidate inventory changed before acquisition")
    if _current_tools(tools) != tools:
        raise EvidenceError("selected tool identity changed before acquisition")
    metadata_values = []
    for context, workspace, tool_name in WORKSPACES:
        metadata = _query(root, prefix, phase, context, workspace,
                          tools[tool_name]["cargo"], tools[tool_name]["rustc"])
        metadata_values.append(f"{workspace}={metadata}")
    try:
        details = checker.verify_details(root, root / "third-party/sources.json", metadata_values)
    except checker.MetadataError as error:
        raise EvidenceError(f"metadata/source verification: {error}") from error
    _admit_members(details, before_candidates)
    after_candidates = _candidate_inventory(root)
    if after_candidates != before_candidates:
        raise EvidenceError("Cargo.toml candidate inventory changed during acquisition")
    after_tools = _current_tools(tools)
    if after_tools != tools:
        for name in ("stable", "bpf"):
            for kind in ("cargo", "rustc"):
                if after_tools[name][kind] != tools[name][kind]:
                    raise EvidenceError(f"{name} {kind} tool changed during acquisition")
    after = _input_snapshot(root, preparer, details)
    stable_after = _input_snapshot(root, preparer, details)
    if after != stable_after:
        raise EvidenceError("identity inputs changed during acquisition")
    for path, identity in before.items():
        if path not in after or not _same_file_identity(after[path], identity):
            label = identity["labels"][0]
            raise EvidenceError(f"{label}: identity changed during acquisition")
    if expected is not None and _projection(details) != {
        field: expected[field] for field in _projection(details)
    }:
        changed = sorted(
            workspace for workspace in details["graphs"]
            if details["graphs"].get(workspace) != expected["graphs"].get(workspace)
        )
        raise EvidenceError(f"fresh retained projection changed for workspaces {changed}")
    ledger_value = _ledger_bytes(details["ledger"])
    _write_new(_artifact(prefix, phase, "ledger.sha256"), ledger_value)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "phase": phase,
        "root": str(root),
        "prefix": str(prefix),
        "tools": tools,
        "graphs": details["graphs"],
        "selected_records": details["selected_records"],
        "workspace_member_manifests": details["workspace_member_manifests"],
        "candidates": before_candidates,
        "inputs": after,
        "ledger": [[relative, digest] for relative, digest in details["ledger"]],
        "artifacts": _artifact_identities(prefix, phase),
    }
    _write_new(_artifact(prefix, phase, "receipt.json"), _json_bytes(receipt))
    return receipt


def _read_json_artifact(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label}: cannot read valid JSON {path}: {error}") from error


def _validate_retained_queries(prefix: Path, root: Path, tools: dict) -> None:
    for context, workspace, tool_name in WORKSPACES:
        cargo = tools[tool_name]["cargo"]
        rustc = tools[tool_name]["rustc"]
        expected_command = {"argv": [cargo["path"], *METADATA_ARGUMENTS, workspace], "cargo": cargo}
        command = _read_json_artifact(
            _artifact(prefix, "initial", f"{context}.command.json"), f"retained {context} command"
        )
        if command != expected_command:
            raise EvidenceError(f"retained {context} command semantics changed")
        expected_context = {
            "context": context, "workspace": workspace, "cwd": str(root), "rustc": rustc,
            "environment": {"RUSTC": rustc["path"]},
        }
        query_context = _read_json_artifact(
            _artifact(prefix, "initial", f"{context}.context.json"), f"retained {context} context"
        )
        if query_context != expected_context:
            raise EvidenceError(f"retained {context} context/tool route changed")
        try:
            status = _artifact(prefix, "initial", f"{context}.status").read_bytes()
        except OSError as error:
            raise EvidenceError(f"retained {context} status cannot be read: {error}") from error
        if status != b"0\n":
            raise EvidenceError(f"retained {context} query status is not zero")


def _read_initial(prefix: Path, root: Path, checker, preparer) -> dict:
    receipt_path = _artifact(prefix, "initial", "receipt.json")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"receipt: cannot read valid initial receipt {receipt_path}: {error}") from error
    receipt_fields = {
        "schema_version", "phase", "root", "prefix", "tools", "graphs",
        "selected_records", "workspace_member_manifests", "candidates", "inputs", "ledger", "artifacts",
    }
    if not isinstance(receipt, dict) or set(receipt) != receipt_fields or receipt.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError("receipt: unsupported or malformed initial receipt")
    if receipt.get("phase") != "initial" or receipt.get("root") != str(root) or receipt.get("prefix") != str(prefix):
        raise EvidenceError("receipt: retained context mismatch")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        raise EvidenceError("receipt: missing retained artifact identities")
    expected_artifacts = set(_phase_suffixes("initial")) - {"receipt.json"}
    if set(artifacts) != expected_artifacts:
        missing = sorted(expected_artifacts - set(artifacts))
        extra = sorted(set(artifacts) - expected_artifacts)
        raise EvidenceError(f"receipt: incomplete retained artifacts: missing={missing}, extra={extra}")
    for suffix, expected in artifacts.items():
        actual = _identity(_artifact(prefix, "initial", suffix), f"metadata artifact {suffix}")
        if actual != expected:
            raise EvidenceError(f"metadata artifact {suffix}: retained identity changed")
    tools = receipt.get("tools")
    if not isinstance(tools, dict) or _current_tools(tools) != tools:
        raise EvidenceError("receipt: selected tool identity changed")
    _validate_retained_queries(prefix, root, tools)
    metadata_values = [
        f"{workspace}={_artifact(prefix, 'initial', f'{context}.stdout.json')}"
        for context, workspace, _tool_name in WORKSPACES
    ]
    try:
        retained_details = checker.verify_details(
            root, root / "third-party/sources.json", metadata_values
        )
    except checker.MetadataError as error:
        raise EvidenceError(f"retained metadata/source verification: {error}") from error
    retained_projection = _projection(retained_details)
    if not isinstance(receipt.get("graphs"), dict) or any(
        not isinstance(receipt.get(field), list)
        for field in ("selected_records", "workspace_member_manifests", "ledger")
    ):
        raise EvidenceError("receipt: retained projection fields are malformed")
    for field, actual in retained_projection.items():
        if receipt.get(field) != actual:
            workspace = ""
            if field == "graphs":
                changed = sorted(
                    name for name in actual if receipt.get(field, {}).get(name) != actual[name]
                )
                workspace = f" for workspaces {changed}"
            raise EvidenceError(f"retained {field[:-1] if field.endswith('s') else field} projection changed{workspace}")
    recorded_inputs = receipt.get("inputs")
    if not isinstance(recorded_inputs, dict) or not recorded_inputs:
        raise EvidenceError("receipt: missing retained input identities")
    current_inputs = _input_snapshot(root, preparer, retained_details)
    if current_inputs != recorded_inputs:
        missing = sorted(set(current_inputs) - set(recorded_inputs))
        extra = sorted(set(recorded_inputs) - set(current_inputs))
        changed = sorted(
            path for path in set(current_inputs) & set(recorded_inputs)
            if current_inputs[path] != recorded_inputs[path]
        )
        raise EvidenceError(
            f"retained input inventory changed: missing={missing}, extra={extra}, changed={changed}"
        )
    candidates = receipt.get("candidates")
    if not isinstance(candidates, dict) or _candidate_inventory(root) != candidates:
        raise EvidenceError("retained Cargo.toml candidate inventory changed")
    _admit_members(retained_details, candidates)
    ledger = receipt.get("ledger")
    if (
        not isinstance(ledger, list)
        or any(not isinstance(row, list) or len(row) != 2 or any(not isinstance(value, str) for value in row)
               for row in ledger)
        or _ledger_bytes(ledger) != _artifact(prefix, "initial", "ledger.sha256").read_bytes()
    ):
        raise EvidenceError("receipt: retained ledger is malformed or changed")
    if not isinstance(receipt.get("graphs"), dict):
        raise EvidenceError("receipt: retained graphs are malformed")
    return receipt


def capture(root: Path, prefix: Path, selected: dict, checker, preparer) -> None:
    tools = {
        name: {
            "cargo": _selected_tool(selected[f"{name}_cargo"], f"{name} cargo tool"),
            "rustc": _selected_tool(selected[f"{name}_rustc"], f"{name} rustc tool"),
        }
        for name in ("stable", "bpf")
    }
    _acquire(root, prefix, "initial", tools, checker, preparer)


def recheck(root: Path, prefix: Path, checker, preparer) -> None:
    _validate_prefix(prefix, "final")
    initial = _read_initial(prefix, root, checker, preparer)
    tools = initial.get("tools")
    _acquire(root, prefix, "final", tools, checker, preparer, expected=initial)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--prefix", type=Path, required=True)
    for name in ("stable", "bpf"):
        capture_parser.add_argument(f"--{name}-cargo", type=Path, required=True)
        capture_parser.add_argument(f"--{name}-rustc", type=Path, required=True)
    recheck_parser = subparsers.add_parser("recheck")
    recheck_parser.add_argument("--prefix", type=Path, required=True)
    options = parser.parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    checker = _load_module(root / "scripts/check-prepared-dependencies.py", "p11scope_metadata_checker")
    preparer = _load_module(root / "scripts/prepare-dependencies.py", "p11scope_dependency_preparer")
    try:
        if options.phase == "capture":
            selected = {
                "stable_cargo": options.stable_cargo,
                "stable_rustc": options.stable_rustc,
                "bpf_cargo": options.bpf_cargo,
                "bpf_rustc": options.bpf_rustc,
            }
            capture(root, options.prefix, selected, checker, preparer)
        else:
            recheck(root, options.prefix, checker, preparer)
    except EvidenceError as error:
        print(f"prepared-dependency-evidence: refusal: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
