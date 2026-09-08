#!/usr/bin/env python3
"""Behavior tests for Cargo metadata binding to prepared dependency sources."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
CHECKER = REPOSITORY / "scripts" / "check-prepared-dependencies.py"
PREPARER = REPOSITORY / "scripts" / "prepare-dependencies.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Fixture:
    def __init__(self, temporary: Path):
        self.root = temporary / "source"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy2(CHECKER, self.root / "scripts" / CHECKER.name)
        shutil.copy2(PREPARER, self.root / "scripts" / PREPARER.name)
        (self.root / "third-party/patches/demo-1.0.0").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (self.root / "crates/ebpf").mkdir(parents=True)
        (self.root / "crates/ebpf/Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        self.preparer = load_module(self.root / "scripts" / PREPARER.name, "fixture_preparer")
        self.record = {
            "name": "demo", "version": "1.0.0", "revision": 1,
            "archive_sha256": "1" * 64, "patches": [],
            "expected_tree_sha256": "0" * 64, "applies_to": ["Cargo.toml"],
        }
        self.output = self.root / "third-party/src/demo-1.0.0-p1"
        self.output.mkdir(parents=True)
        self.output.chmod(0o755)
        (self.output / "Cargo.toml").write_text(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n", encoding="utf-8"
        )
        (self.output / "src").mkdir()
        (self.output / "src").chmod(0o755)
        (self.output / "src/lib.rs").write_text("pub fn demo() {}\n", encoding="utf-8")
        for path in (self.output / "Cargo.toml", self.output / "src/lib.rs"):
            path.chmod(0o644)
        self.record["expected_tree_sha256"] = self.preparer.compute_tree_digest(self.output)
        self.refresh_receipt()
        self.write_manifest()
        self.metadata_dir = temporary / "metadata"
        self.metadata_dir.mkdir()

    def refresh_receipt(self):
        identity = self.preparer.compute_recipe_identity(self.record, [])
        receipt = {
            "schema_version": 1, "package": "demo", "version": "1.0.0", "revision": 1,
            "recipe_sha256": identity, "tree_sha256": self.record["expected_tree_sha256"],
        }
        (self.output / self.preparer.RECEIPT_NAME).write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        (self.output / self.preparer.RECEIPT_NAME).chmod(0o644)

    def write_manifest(self, packages=None, workspaces=None):
        manifest = {
            "schema_version": 1,
            "workspace_manifests": workspaces or ["Cargo.toml", "crates/ebpf/Cargo.toml"],
            "packages": packages or [self.record],
        }
        (self.root / "third-party/sources.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    def package(self, package_id, name, version, manifest_path, source=None):
        return {
            "id": package_id, "name": name, "version": version,
            "manifest_path": str(manifest_path), "source": source,
            "dependencies": [], "features": {},
        }

    def metadata(self, workspace="Cargo.toml", *, demo_path=None, demo_version="1.0.0",
                 demo_source=None, transitive=False, include_demo=True):
        manifest = self.root / workspace
        workspace_root = manifest.parent
        app_id = f"path+file://{workspace_root.as_posix()}#app@0.1.0"
        packages = [self.package(app_id, "app", "0.1.0", manifest)]
        nodes = []
        direct = []
        demo_id = None
        if include_demo:
            demo_manifest = demo_path or (self.output / "Cargo.toml")
            demo_id = f"path+file://{demo_manifest.parent.as_posix()}#demo@{demo_version}"
            packages.append(self.package(demo_id, "demo", demo_version, demo_manifest, demo_source))
            nodes.append({"id": demo_id, "dependencies": [], "deps": [], "features": ["default"]})
            direct = [{"name": "demo", "pkg": demo_id, "dep_kinds": [{"kind": None, "target": None}]}]
        if transitive and demo_id is not None:
            mid_manifest = workspace_root / "mid/Cargo.toml"
            mid_id = f"path+file://{mid_manifest.parent.as_posix()}#mid@0.2.0"
            packages.append(self.package(mid_id, "mid", "0.2.0", mid_manifest))
            nodes.append({
                "id": mid_id, "dependencies": [demo_id], "deps": direct, "features": []
            })
            direct = [{"name": "mid", "pkg": mid_id, "dep_kinds": [{"kind": None, "target": None}]}]
        nodes.append({
            "id": app_id,
            "dependencies": [dependency["pkg"] for dependency in direct],
            "deps": direct,
            "features": [],
        })
        return {
            "version": 1,
            "packages": packages,
            "workspace_members": [app_id],
            "workspace_root": str(workspace_root),
            "resolve": {"root": None, "nodes": nodes},
        }

    def write_metadata(self, name, value):
        path = self.metadata_dir / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run(self, contexts=None, *, ledger=True, sources=None):
        if contexts is None:
            contexts = {
                "Cargo.toml": self.write_metadata("root.json", self.metadata()),
                "crates/ebpf/Cargo.toml": self.write_metadata(
                    "ebpf.json", self.metadata("crates/ebpf/Cargo.toml", include_demo=False)
                ),
            }
        command = [
            sys.executable, "-I", str(self.root / "scripts" / CHECKER.name),
            "--sources", str(sources or self.root / "third-party/sources.json"),
        ]
        for workspace, path in contexts.items() if isinstance(contexts, dict) else contexts:
            command.extend(["--metadata", f"{workspace}={path}"])
        if ledger:
            command.append("--ledger")
        return subprocess.run(
            command, cwd=self.root.parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class PreparedDependencyMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def assert_refused(self, result, *needles):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_current_generation_emits_sorted_sha256sum_ledger_with_receipt(self):
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        relatives = ["third-party/src/demo-1.0.0-p1/.p11scope-prepared.json",
                     "third-party/src/demo-1.0.0-p1/Cargo.toml",
                     "third-party/src/demo-1.0.0-p1/src/lib.rs"]
        expected = "".join(
            f"{hashlib.sha256((self.fixture.root / relative).read_bytes()).hexdigest()}  {relative}\n"
            for relative in sorted(relatives, key=lambda value: value.encode("utf-8"))
        )
        self.assertEqual(result.stdout, expected)

    def test_transitive_current_generation_is_reached(self):
        root = self.fixture.write_metadata("root-transitive.json", self.fixture.metadata(transitive=True))
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_generation_and_registry_fallback_name_workspace_package_and_path(self):
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        cases = [
            ("stale", self.fixture.root / "third-party/src/demo-1.0.0-p0/Cargo.toml", None),
            ("registry", Path("/cargo/registry/demo-1.0.0/Cargo.toml"), "registry+https://github.com/rust-lang/crates.io-index"),
        ]
        for label, path, source in cases:
            with self.subTest(label=label):
                root = self.fixture.write_metadata(
                    f"root-{label}.json", self.fixture.metadata(demo_path=path, demo_source=source)
                )
                result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
                self.assert_refused(result, "Cargo.toml", "demo 1.0.0", str(path))

    def test_second_version_of_same_crate_is_allowed(self):
        metadata = self.fixture.metadata()
        other_id = "registry+https://github.com/rust-lang/crates.io-index#demo@2.0.0"
        metadata["packages"].append(self.fixture.package(
            other_id, "demo", "2.0.0", Path("/cargo/registry/demo-2.0.0/Cargo.toml"),
            "registry+https://github.com/rust-lang/crates.io-index",
        ))
        metadata["resolve"]["nodes"].append(
            {"id": other_id, "dependencies": [], "deps": [], "features": []}
        )
        metadata["resolve"]["nodes"][-2]["dependencies"].append(other_id)
        metadata["resolve"]["nodes"][-2]["deps"].append(
            {"name": "demo2", "pkg": other_id, "dep_kinds": [{"kind": None, "target": None}]}
        )
        root = self.fixture.write_metadata("two-versions.json", metadata)
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_incomplete_graph_and_wrong_workspace_root_emit_no_ledger(self):
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        incomplete = self.fixture.metadata()
        incomplete["resolve"]["nodes"] = incomplete["resolve"]["nodes"][:-1]
        wrong_root = self.fixture.metadata()
        wrong_root["workspace_root"] = str(self.fixture.root / "wrong")
        for label, metadata in (("incomplete", incomplete), ("wrong-root", wrong_root)):
            with self.subTest(label=label):
                root = self.fixture.write_metadata(f"{label}.json", metadata)
                result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
                self.assert_refused(result, "Cargo.toml", "workspace")

    def test_unknown_generated_package_in_independent_workspace_is_refused(self):
        root = self.fixture.write_metadata("root.json", self.fixture.metadata())
        unknown = self.fixture.root / "third-party/src/unknown-1.0.0-p1/Cargo.toml"
        ebpf_metadata = self.fixture.metadata("crates/ebpf/Cargo.toml", demo_path=unknown)
        ebpf_metadata["packages"][1]["name"] = "unknown"
        ebpf = self.fixture.write_metadata("ebpf-unknown.json", ebpf_metadata)
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assert_refused(result, "crates/ebpf/Cargo.toml", "unknown", str(unknown))

    def test_root_only_record_does_not_require_or_authorize_registry_copy_in_bpf(self):
        root = self.fixture.write_metadata("root.json", self.fixture.metadata())
        ebpf = self.fixture.write_metadata(
            "ebpf-registry.json",
            self.fixture.metadata(
                "crates/ebpf/Cargo.toml", demo_path=Path("/cargo/registry/demo-1.0.0/Cargo.toml"),
                demo_source="registry+https://github.com/rust-lang/crates.io-index",
            ),
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_truthful_metadata_cannot_authorize_tampered_tree(self):
        (self.fixture.output / "src/lib.rs").write_text("tampered\n", encoding="utf-8")
        result = self.fixture.run()
        self.assert_refused(result, "Cargo.toml", "demo", "tree digest mismatch")

    def test_record_shared_by_graphs_emits_each_verified_file_once(self):
        self.fixture.record["applies_to"] = ["Cargo.toml", "crates/ebpf/Cargo.toml"]
        self.fixture.refresh_receipt()
        self.fixture.write_manifest()
        root = self.fixture.write_metadata("root.json", self.fixture.metadata())
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml")
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 3)
        self.assertEqual(len(set(result.stdout.splitlines())), 3)

    def test_manifest_rejects_undeclared_applicability_and_ambiguous_mapping(self):
        cases = []
        outside = dict(self.fixture.record)
        outside["applies_to"] = ["missing/Cargo.toml"]
        cases.append(("outside", [outside], "applicability"))
        duplicate = dict(self.fixture.record)
        duplicate["revision"] = 2
        cases.append(("ambiguous", [self.fixture.record, duplicate], "ambiguous expected mapping"))
        for label, packages, needle in cases:
            with self.subTest(label=label):
                self.fixture.write_manifest(packages=packages)
                self.assert_refused(self.fixture.run(), needle)

    def test_workspace_member_manifest_must_belong_to_workspace_root(self):
        root_metadata = self.fixture.metadata()
        root_metadata["packages"][0]["manifest_path"] = str(Path(self.temporary.name) / "outside/Cargo.toml")
        root = self.fixture.write_metadata("root-outside.json", root_metadata)
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assert_refused(result, "Cargo.toml", "workspace member", "outside/Cargo.toml")

    def test_legacy_dependency_cannot_hide_generated_package_omitted_from_structured_deps(self):
        metadata = self.fixture.metadata()
        hidden_path = self.fixture.root / "third-party/src/hidden-1.0.0-p1/Cargo.toml"
        hidden_id = f"path+file://{hidden_path.parent.as_posix()}#hidden@1.0.0"
        metadata["packages"].append(self.fixture.package(hidden_id, "hidden", "1.0.0", hidden_path))
        metadata["resolve"]["nodes"].append(
            {"id": hidden_id, "dependencies": [], "deps": [], "features": []}
        )
        metadata["resolve"]["nodes"][-2]["dependencies"].append(hidden_id)
        root = self.fixture.write_metadata("hidden-legacy.json", metadata)
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assert_refused(result, "Cargo.toml", "dependency", hidden_id)

    def test_duplicate_members_and_exact_structured_edges_are_refused(self):
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        duplicate_member = self.fixture.metadata()
        duplicate_member["workspace_members"].append(duplicate_member["workspace_members"][0])
        duplicate_edge = self.fixture.metadata()
        duplicate_edge["resolve"]["nodes"][-1]["deps"].append(
            dict(duplicate_edge["resolve"]["nodes"][-1]["deps"][0])
        )
        for label, metadata, needle in (
            ("member", duplicate_member, "duplicate workspace member"),
            ("edge", duplicate_edge, "duplicate structured dependency edge"),
        ):
            with self.subTest(label=label):
                root = self.fixture.write_metadata(f"duplicate-{label}.json", metadata)
                self.assert_refused(
                    self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf}),
                    "Cargo.toml", needle,
                )

    def test_distinct_aliases_kinds_and_targets_to_same_package_are_allowed(self):
        metadata = self.fixture.metadata()
        app_node = metadata["resolve"]["nodes"][-1]
        original = app_node["deps"][0]
        app_node["deps"].extend([{
            "name": "demo_build_alias",
            "pkg": app_node["dependencies"][0],
            "dep_kinds": original["dep_kinds"],
        }, {
            "name": original["name"],
            "pkg": app_node["dependencies"][0],
            "dep_kinds": [{"kind": "build", "target": "cfg(unix)"}],
        }])
        root = self.fixture.write_metadata("aliases.json", metadata)
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        result = self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_format_version_and_dependency_fields_are_strict(self):
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        cases = []
        for value in (True, "1", 2):
            metadata = self.fixture.metadata(); metadata["version"] = value
            cases.append((f"version-{value!r}", metadata, "format version"))
        malformed_legacy = self.fixture.metadata()
        malformed_legacy["resolve"]["nodes"][-1]["dependencies"] = "not-a-list"
        cases.append(("legacy-type", malformed_legacy, "dependencies"))
        duplicate_legacy = self.fixture.metadata()
        dependency = duplicate_legacy["resolve"]["nodes"][-1]["dependencies"][0]
        duplicate_legacy["resolve"]["nodes"][-1]["dependencies"].append(dependency)
        cases.append(("legacy-duplicate", duplicate_legacy, "duplicate dependency id"))
        dangling = self.fixture.metadata()
        dangling["resolve"]["nodes"][-1]["dependencies"] = ["missing-package-id"]
        dangling["resolve"]["nodes"][-1]["deps"][0]["pkg"] = "missing-package-id"
        cases.append(("dangling", dangling, "missing-package-id"))
        malformed_kinds = self.fixture.metadata()
        malformed_kinds["resolve"]["nodes"][-1]["deps"][0]["dep_kinds"] = "normal"
        cases.append(("dep-kinds", malformed_kinds, "dep_kinds"))
        missing_source = self.fixture.metadata()
        del missing_source["packages"][0]["source"]
        cases.append(("source", missing_source, "source has invalid type"))
        malformed_features = self.fixture.metadata()
        malformed_features["resolve"]["nodes"][-1]["features"] = ["one", "one"]
        cases.append(("features", malformed_features, "features contain invalid or duplicate"))
        for label, metadata, needle in cases:
            with self.subTest(label=label):
                root = self.fixture.write_metadata(f"malformed-{label}.json", metadata)
                self.assert_refused(
                    self.fixture.run({"Cargo.toml": root, "crates/ebpf/Cargo.toml": ebpf}),
                    "Cargo.toml", needle,
                )

    def test_metadata_contexts_are_required_exactly_once(self):
        root = self.fixture.write_metadata("root.json", self.fixture.metadata())
        ebpf = self.fixture.write_metadata(
            "ebpf.json", self.fixture.metadata("crates/ebpf/Cargo.toml", include_demo=False)
        )
        cases = [
            [("Cargo.toml", root)],
            [("Cargo.toml", root), ("Cargo.toml", root), ("crates/ebpf/Cargo.toml", ebpf)],
            [("Cargo.toml", root), ("crates/ebpf/Cargo.toml", ebpf), ("extra/Cargo.toml", root)],
        ]
        for contexts in cases:
            with self.subTest(contexts=contexts):
                self.assert_refused(self.fixture.run(contexts), "metadata context")


if __name__ == "__main__":
    unittest.main(verbosity=2)
