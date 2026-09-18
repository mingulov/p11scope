#!/usr/bin/env python3
"""Native behavior tests for prepared dependency capture and recheck evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPOSITORY / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

HELPER = REPOSITORY / "scripts/prepared-dependency-evidence.py"
METADATA_TEST = REPOSITORY / "tests/python/test_prepared_dependency_metadata.py"
FIXTURES = REPOSITORY / "tests/fixtures/prepared-dependency-evidence"


def load_module(path: Path, name: str):
    return load_path(path, name)


metadata_test = load_module(METADATA_TEST, "prepared_metadata_test_fixture")


class EvidenceFixture:
    def __init__(self, temporary: Path):
        self.base = metadata_test.Fixture(temporary)
        self.root = self.base.root
        shutil.copy2(HELPER, self.root / "scripts" / HELPER.name)
        patch = self.root / "third-party/patches/demo-1.0.0/ordered.patch"
        patch.write_text("fixture ordered patch bytes\n", encoding="utf-8")
        self.base.record["patches"] = ["third-party/patches/demo-1.0.0/ordered.patch"]
        self.base.refresh_receipt()
        prepared_receipt = self.base.output / self.base.preparer.RECEIPT_NAME
        receipt = json.loads(prepared_receipt.read_text(encoding="utf-8"))
        receipt["recipe_sha256"] = self.base.preparer.compute_recipe_identity(
            self.base.record, [(self.base.record["patches"][0], patch.read_bytes())]
        )
        prepared_receipt.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        self.base.write_manifest()
        for relative in ("Cargo.lock", "crates/ebpf/Cargo.lock"):
            path = self.root / relative
            path.write_text("# fixture lock\n", encoding="utf-8")
        self.tools = temporary / "tools with spaces"
        self.tools.mkdir()
        for target, fixture in (
            ("stable cargo", "fake-cargo.py"), ("bpf cargo", "fake-cargo.py"),
            ("stable rustc", "fake-rustc.py"), ("bpf rustc", "fake-rustc.py"),
        ):
            shutil.copy2(FIXTURES / fixture, self.tools / target)
            (self.tools / target).chmod(0o755)
        self.metadata = temporary / "metadata files"
        self.metadata.mkdir()
        self.root_metadata = self.metadata / "root metadata.json"
        self.bpf_metadata = self.metadata / "bpf metadata.json"
        self.write_metadata(self.root_metadata, self.base.metadata())
        self.write_metadata(
            self.bpf_metadata,
            self.base.metadata("crates/ebpf/Cargo.toml", include_demo=False),
        )
        self.selection = temporary / "selection.json"
        self.set_selection(self.root_metadata, self.bpf_metadata)
        self.log = temporary / "fake cargo.jsonl"
        self.config_path = temporary / "fake cargo config.json"
        self.config = {
            "log": str(self.log),
            "selection_file": str(self.selection),
        }
        self.write_config()
        evidence_dir = temporary / "evidence with spaces"
        evidence_dir.mkdir()
        self.prefix = evidence_dir / "prepared source"

    def write_metadata(self, path: Path, value: dict):
        path.write_text(json.dumps(value), encoding="utf-8")

    def set_selection(self, root: Path, bpf: Path):
        self.selection.write_text(
            json.dumps({"root": str(root), "bpf": str(bpf)}), encoding="utf-8"
        )

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def run(self, phase: str, *, prefix: Path | None = None):
        command = [sys.executable, "-I", str(self.root / "scripts" / HELPER.name), phase,
                   "--prefix", str(prefix or self.prefix)]
        if phase == "capture":
            command += [
                "--stable-cargo", str(self.tools / "stable cargo"),
                "--stable-rustc", str(self.tools / "stable rustc"),
                "--bpf-cargo", str(self.tools / "bpf cargo"),
                "--bpf-rustc", str(self.tools / "bpf rustc"),
            ]
        environment = os.environ.copy()
        environment["P11SCOPE_FAKE_CARGO_CONFIG"] = str(self.config_path)
        return subprocess.run(command, cwd=self.root.parent, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def artifact(self, suffix: str) -> Path:
        return Path(str(self.prefix) + suffix)

    def invocations(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def add_root_member(self, relative: str = "member/Cargo.toml") -> Path:
        member = self.root / relative
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_text("[package]\nname='member'\nversion='0.1.0'\n", encoding="utf-8")
        metadata = json.loads(self.root_metadata.read_text(encoding="utf-8"))
        member_id = f"path+file://{member.parent.as_posix()}#member@0.1.0"
        metadata["packages"].append(self.base.package(
            member_id, "member", "0.1.0", member,
        ))
        metadata["resolve"]["nodes"].append(
            {"id": member_id, "dependencies": [], "deps": [], "features": []}
        )
        metadata["workspace_members"].append(member_id)
        self.write_metadata(self.root_metadata, metadata)
        return member


class PreparedDependencyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = EvidenceFixture(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def assert_refused(self, result, *needles):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def capture(self):
        result = self.fixture.run("capture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        return result

    def test_capture_uses_exact_fixed_commands_cwd_and_matching_tools(self):
        self.capture()
        expected_argv = ["metadata", "--locked", "--offline", "--all-features",
                         "--format-version", "1", "--manifest-path"]
        calls = self.fixture.invocations()
        self.assertEqual(len(calls), 2)
        self.assertEqual([call["context"] for call in calls], ["root", "bpf"])
        self.assertEqual(calls[0]["argv"], expected_argv + ["Cargo.toml"])
        self.assertEqual(calls[1]["argv"], expected_argv + ["crates/ebpf/Cargo.toml"])
        self.assertEqual({call["cwd"] for call in calls}, {str(self.fixture.root)})
        self.assertEqual(calls[0]["rustc"], str((self.fixture.tools / "stable rustc").resolve()))
        self.assertEqual(calls[1]["rustc"], str((self.fixture.tools / "bpf rustc").resolve()))
        ledger = self.fixture.artifact(".initial.ledger.sha256").read_text(encoding="utf-8")
        self.assertEqual(len(ledger.splitlines()), 3)
        receipt = json.loads(self.fixture.artifact(".initial.receipt.json").read_text())
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(set(receipt["graphs"]), {"Cargo.toml", "crates/ebpf/Cargo.toml"})

    def test_query_failure_keeps_diagnostics_emits_no_ledger_and_stops_before_next(self):
        for context in ("root", "bpf"):
            with self.subTest(context=context):
                temporary = Path(self.temporary.name) / context
                temporary.mkdir()
                fixture = EvidenceFixture(temporary)
                marker = temporary / "bpf marker"
                fixture.config[f"{context}_status"] = 23
                fixture.config["bpf_marker"] = str(marker)
                fixture.write_config()
                result = fixture.run("capture")
                self.assert_refused(result, context, "status 23")
                self.assertFalse(fixture.artifact(".initial.ledger.sha256").exists())
                self.assertTrue(fixture.artifact(f".initial.{context}.stderr").exists())
                if context == "root":
                    self.assertFalse(marker.exists())

    def test_query_failure_refusal_names_the_retained_stderr_artifact(self):
        # A bare `status 101` once had to be reproduced by hand to learn it
        # meant a missing crate in the offline cargo cache: the stderr was
        # retained all along, but the refusal never said where. The message
        # must name the artifact's path — and must not inline its bytes,
        # because these refusals reach logs and receipts while the artifact
        # exists precisely so the bytes stay bounded and reviewable.
        temporary = Path(self.temporary.name) / "stderr-artifact"
        temporary.mkdir()
        fixture = EvidenceFixture(temporary)
        fixture.config["root_status"] = 101
        fixture.config["root_stderr"] = (
            "error: failed to download `r-efi v0.0.0` from the offline cargo cache\n"
        )
        fixture.write_config()
        result = fixture.run("capture")
        stderr_artifact = fixture.artifact(".initial.root.stderr")
        self.assert_refused(result, "root metadata query returned status 101",
                            str(stderr_artifact))
        self.assertIn("r-efi", stderr_artifact.read_text(encoding="utf-8"))
        self.assertNotIn("r-efi", result.stderr)

    def test_recheck_preserves_initial_evidence_and_writes_separate_final_evidence(self):
        self.capture()
        initial = {path: path.read_bytes() for path in self.fixture.prefix.parent.iterdir()}
        result = self.fixture.run("recheck")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        for path, value in initial.items():
            self.assertEqual(path.read_bytes(), value)
        self.assertTrue(self.fixture.artifact(".final.receipt.json").is_file())
        self.assertEqual(
            self.fixture.artifact(".initial.ledger.sha256").read_bytes(),
            self.fixture.artifact(".final.ledger.sha256").read_bytes(),
        )

    def test_recheck_failure_preserves_initial_evidence_and_has_no_final_ledger(self):
        self.capture()
        initial = self.fixture.artifact(".initial.receipt.json").read_bytes()
        self.fixture.config["bpf_status"] = 19
        self.fixture.write_config()
        result = self.fixture.run("recheck")
        self.assert_refused(result, "bpf", "status 19")
        self.assertEqual(self.fixture.artifact(".initial.receipt.json").read_bytes(), initial)
        self.assertFalse(self.fixture.artifact(".final.ledger.sha256").exists())

    def test_retained_receipt_metadata_and_tool_tamper_are_refused_before_queries(self):
        mutations = [
            ("receipt", ".initial.receipt.json"),
            ("metadata", ".initial.root.stdout.json"),
            ("tool", None),
        ]
        for label, suffix in mutations:
            with self.subTest(label=label):
                temporary = Path(self.temporary.name) / f"retained-{label}"
                temporary.mkdir()
                fixture = EvidenceFixture(temporary)
                self.assertEqual(fixture.run("capture").returncode, 0)
                before = len(fixture.invocations())
                target = fixture.tools / "stable cargo" if suffix is None else fixture.artifact(suffix)
                target.write_bytes(target.read_bytes() + b"# tamper\n")
                result = fixture.run("recheck")
                self.assert_refused(result, label)
                self.assertEqual(len(fixture.invocations()), before)

    def test_coherently_omitted_retained_artifact_is_refused_before_queries(self):
        self.capture()
        receipt_path = self.fixture.artifact(".initial.receipt.json")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        del receipt["artifacts"]["root.stderr"]
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        before = len(self.fixture.invocations())
        result = self.fixture.run("recheck")
        self.assert_refused(result, "receipt", "incomplete retained artifacts", "root.stderr")
        self.assertEqual(len(self.fixture.invocations()), before)

    def test_helper_recipe_manifest_tree_and_generation_tamper_are_refused(self):
        mutations = [
            ("helper", lambda f: f.root / "scripts/prepared-dependency-evidence.py"),
            ("recipe", lambda f: f.root / "third-party/sources.json"),
            ("patch", lambda f: f.root / "third-party/patches/demo-1.0.0/ordered.patch"),
            ("manifest", lambda f: f.root / "Cargo.toml"),
            ("tree", lambda f: f.base.output / "src/lib.rs"),
            ("generation", lambda f: f.base.output / f.base.preparer.RECEIPT_NAME),
        ]
        for label, locate in mutations:
            with self.subTest(label=label):
                temporary = Path(self.temporary.name) / label
                temporary.mkdir()
                fixture = EvidenceFixture(temporary)
                self.assertEqual(fixture.run("capture").returncode, 0)
                target = locate(fixture)
                target.write_bytes(target.read_bytes() + b"# tamper\n")
                result = fixture.run("recheck")
                self.assert_refused(
                    result,
                    "prepared receipt" if label == "generation" else label,
                )
                self.assertFalse(fixture.artifact(".final.ledger.sha256").exists())

    def test_fresh_configuration_selection_change_is_refused(self):
        self.capture()
        changed = self.fixture.metadata / "redirected root.json"
        value = self.base_metadata_copy()
        value["packages"][1]["source"] = "registry+https://example.invalid/index"
        value["packages"][1]["manifest_path"] = "/registry/demo/Cargo.toml"
        self.fixture.write_metadata(changed, value)
        self.fixture.set_selection(changed, self.fixture.bpf_metadata)
        result = self.fixture.run("recheck")
        self.assert_refused(result, "metadata/source verification", "Cargo.toml", "/registry/demo/Cargo.toml")
        self.assertFalse(self.fixture.artifact(".final.ledger.sha256").exists())

    def base_metadata_copy(self):
        return json.loads(self.fixture.root_metadata.read_text(encoding="utf-8"))

    def test_graph_array_order_changes_are_equivalent(self):
        self.capture()
        for path in (self.fixture.root_metadata, self.fixture.bpf_metadata):
            value = json.loads(path.read_text(encoding="utf-8"))
            value["packages"].reverse()
            value["resolve"]["nodes"].reverse()
            for node in value["resolve"]["nodes"]:
                node["dependencies"].reverse()
                node["deps"].reverse()
                node["features"].reverse()
                for edge in node["deps"]:
                    edge["dep_kinds"].reverse()
            self.fixture.write_metadata(path, value)
        result = self.fixture.run("recheck")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preexisting_artifact_collision_is_preserved_before_any_query(self):
        collision = self.fixture.artifact(".initial.root.command.json")
        collision.write_text("unrelated\n", encoding="utf-8")
        result = self.fixture.run("capture")
        self.assert_refused(result, "already exists", str(collision))
        self.assertEqual(collision.read_text(encoding="utf-8"), "unrelated\n")
        self.assertEqual(self.fixture.invocations(), [])

    def test_unsafe_nonabsolute_prefix_is_refused(self):
        result = self.fixture.run("capture", prefix=Path("relative-prefix"))
        self.assert_refused(result, "absolute", "prefix")
        self.assertEqual(self.fixture.invocations(), [])

    def test_persistent_selected_tool_mutation_during_query_refuses_ledger(self):
        tool = self.fixture.tools / "stable rustc"
        self.fixture.config["root_mutations"] = [
            {"action": "append", "path": str(tool), "content": "# changed during query\n"}
        ]
        self.fixture.write_config()
        result = self.fixture.run("capture")
        self.assert_refused(result, "stable rustc tool", "changed during acquisition")
        self.assertFalse(self.fixture.artifact(".initial.ledger.sha256").exists())

    def test_existing_member_mutation_during_capture_and_recheck_is_refused(self):
        for phase in ("capture", "recheck"):
            with self.subTest(phase=phase):
                temporary = Path(self.temporary.name) / f"member-{phase}"
                temporary.mkdir()
                fixture = EvidenceFixture(temporary)
                member = fixture.add_root_member()
                if phase == "recheck":
                    self.assertEqual(fixture.run("capture").returncode, 0)
                fixture.config["root_mutations"] = [
                    {"action": "append", "path": str(member), "content": "# changed\n"}
                ]
                fixture.write_config()
                result = fixture.run(phase)
                self.assert_refused(result, "Cargo.toml candidate", "changed during acquisition")
                self.assertFalse(fixture.artifact(
                    ".initial.ledger.sha256" if phase == "capture" else ".final.ledger.sha256"
                ).exists())

    def test_new_candidate_appearing_during_query_is_refused(self):
        candidate = self.fixture.root / "new fixture/Cargo.toml"
        self.fixture.config["root_mutations"] = [
            {"action": "create", "path": str(candidate), "content": "[package]\n"}
        ]
        self.fixture.write_config()
        result = self.fixture.run("capture")
        self.assert_refused(result, "Cargo.toml candidate inventory changed")
        self.assertFalse(self.fixture.artifact(".initial.ledger.sha256").exists())

    def test_selected_member_under_excluded_namespace_is_unadmitted(self):
        member = self.fixture.add_root_member("target/member/Cargo.toml")
        result = self.fixture.run("capture")
        self.assert_refused(result, "unsupported/unadmitted workspace member", str(member.resolve()))
        self.assertFalse(self.fixture.artifact(".initial.ledger.sha256").exists())

    def test_deleted_receipt_member_input_then_changed_file_is_refused_before_query(self):
        member = self.fixture.add_root_member()
        self.capture()
        receipt_path = self.fixture.artifact(".initial.receipt.json")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        del receipt["inputs"][str(member.resolve())]
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        member.write_text("changed after deleted receipt row\n", encoding="utf-8")
        before = len(self.fixture.invocations())
        result = self.fixture.run("recheck")
        self.assert_refused(result, "retained input inventory", "missing", str(member.resolve()))
        self.assertEqual(len(self.fixture.invocations()), before)
        self.assertFalse(self.fixture.artifact(".final.ledger.sha256").exists())

    def test_edited_receipt_graph_matching_fresh_metadata_is_refused_before_query(self):
        self.capture()
        receipt_path = self.fixture.artifact(".initial.receipt.json")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["graphs"]["Cargo.toml"]["packages"][0]["features"].append("forged")
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        fresh = json.loads(self.fixture.root_metadata.read_text(encoding="utf-8"))
        package_id = receipt["graphs"]["Cargo.toml"]["packages"][0]["id"]
        next(node for node in fresh["resolve"]["nodes"] if node["id"] == package_id)["features"].append("forged")
        self.fixture.write_metadata(self.fixture.root_metadata, fresh)
        before = len(self.fixture.invocations())
        result = self.fixture.run("recheck")
        self.assert_refused(result, "retained graph projection", "Cargo.toml")
        self.assertEqual(len(self.fixture.invocations()), before)
        self.assertFalse(self.fixture.artifact(".final.ledger.sha256").exists())


if __name__ == "__main__":
    unittest.main()
