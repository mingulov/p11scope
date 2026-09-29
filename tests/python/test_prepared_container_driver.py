#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual container-driver admission and custody tests using native fake tools."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/prepared-container-driver"
EvidenceFixture = runpy.run_path(str(ROOT / "tests/python/test_prepared_dependency_evidence.py"))["EvidenceFixture"]


class DriverFixture:
    def __init__(self, base):
        self.base = base
        self.evidence = EvidenceFixture(base)
        self.root = self.evidence.root
        for name in ("verify-discover-containers.sh", "cleanup-traps.sh", "prepared-dependency-tools.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.bin = base / "bin"
        self.bin.mkdir()
        for directory in (self.bin, self.evidence.tools):
            shutil.copy2(FIXTURES / "fixture_common.py", directory / "fixture_common.py")
        for name in ("docker", "rustup", "cargo"):
            shutil.copy2(FIXTURES / f"fake-{name}.py", self.bin / name)
            (self.bin / name).chmod(0o755)
        for name in ("stable cargo", "bpf cargo"):
            shutil.copy2(FIXTURES / "fake-cargo.py", self.evidence.tools / name)
            (self.evidence.tools / name).chmod(0o755)
        self.stable_cargo = self.evidence.tools / "stable cargo"
        self.stable_rustc = self.evidence.tools / "stable rustc"
        self.bpf_cargo = self.evidence.tools / "bpf cargo"
        self.bpf_rustc = self.evidence.tools / "bpf rustc"
        alias = self.evidence.tools / "stable-cargo-link"
        alias.symlink_to(self.stable_cargo)
        self.work = base / "work"
        self.artifacts = self.work / "artifacts"
        self.artifacts.mkdir(parents=True, mode=0o700)
        self.artifacts.chmod(0o700)
        self.facts_path = self.artifacts / "discover.facts"
        self.prefix = self.artifacts / "discover.prepared"
        self.events_path = base / "events.jsonl"
        self.state_path = base / "docker-state.json"
        self.state_path.write_text(json.dumps({"count": 0, "ids": {}, "names": {}, "networks": {},
                                               "container_networks": {}, "mutated": False}))
        self.config_path = base / "driver-config.json"
        self.config = {
            "state": str(self.state_path), "events": str(self.events_path),
            "facts": str(self.facts_path), "prefix": str(self.prefix),
            "root_metadata": str(self.evidence.root_metadata),
            "bpf_metadata": str(self.evidence.bpf_metadata),
            "prepared_source": str(self.evidence.base.output / "src/lib.rs"),
            "tools": {"1.88:cargo": str(alias), "1.88:rustc": str(self.stable_rustc),
                      "nightly-2026-05-20:cargo": str(self.bpf_cargo),
                      "nightly-2026-05-20:rustc": str(self.bpf_rustc)},
        }

    def run(self, *, arguments=None, work=None, sealed=False):
        self.config_path.write_text(json.dumps(self.config))
        environment = dict(os.environ)
        tool_path = str(self.bin) + ":/usr/bin:/bin"
        if sealed:
            sealed_bin = self.base / "sealed-bin"
            sealed_bin.mkdir(mode=0o700)
            inventory = json.loads((ROOT / "tests/fixtures/release-seal/expected.json").read_text())["tool_inventory"]
            for name in inventory:
                selected = shutil.which(name, path=tool_path)
                if selected is not None:
                    (sealed_bin / name).symlink_to(Path(selected).resolve())
            tool_path = str(sealed_bin)
        environment.update(PATH=tool_path,
                           P11SCOPE_CONTAINER_FIXTURE=str(self.config_path),
                           P11SCOPE_RECEIPT_WORK=str(self.work if work is None else work))
        return subprocess.run(
            ["/bin/sh", str(self.root / "scripts/verify-discover-containers.sh"),
             *(arguments if arguments is not None else ["--lane14-facts", str(self.facts_path)])],
            cwd=self.base, env=environment, text=True, capture_output=True, timeout=30,
        )

    def events(self):
        return [json.loads(line) for line in self.events_path.read_text().splitlines()] if self.events_path.exists() else []

    def facts(self):
        return dict((parts[0], parts[1:]) for parts in (
            line.split("\t") for line in self.facts_path.read_text().splitlines()
        )) if self.facts_path.exists() else {}

    def artifact(self, suffix):
        return Path(str(self.prefix) + suffix)


class PreparedContainerDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope prepared container ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def fixture(self, name="case"):
        directory = self.base / name
        directory.mkdir()
        return DriverFixture(directory)

    def test_initial_admission_and_final_queries_bracket_resource_work(self):
        fixture = self.fixture()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = fixture.events()
        metadata = [(index, row) for index, row in enumerate(events) if row["kind"] == "metadata"]
        self.assertEqual([(row["phase"], row["context"]) for _, row in metadata],
                         [("initial", "root"), ("initial", "bpf"), ("final", "root"), ("final", "bpf")])
        resources = [(index, row) for index, row in enumerate(events) if row["kind"] in ("docker", "vendor")]
        self.assertTrue(resources)
        self.assertLess(metadata[1][0], resources[0][0])
        self.assertTrue(all(row["initial_ready"] for _, row in resources))
        absence = [index for index, row in resources if row["kind"] == "docker"
                   and row["argv"][0] == "inspect" and len(row["argv"]) == 2]
        self.assertEqual(len(absence), 3)
        self.assertLess(max(absence), metadata[2][0])
        self.assertTrue(all(not row["child_exit_present"] and not row["remaining_ids"]
                            and not row["remaining_network_ids"] for _, row in metadata[2:]))
        vendor = next(row for _, row in resources if row["kind"] == "vendor")
        self.assertEqual(vendor["executable"], str(fixture.stable_cargo.resolve()))
        self.assertEqual(vendor["rustc"], str(fixture.stable_rustc.resolve()))
        self.assertEqual(vendor["argv"], ["vendor", "--locked", "--offline",
                                                "--respect-source-config",
                                                str(fixture.work / "discover/vendor/src")])
        creates = [row["argv"] for _, row in resources if row["kind"] == "docker" and row["argv"][0] == "create"]
        self.assertEqual(len(creates), 3)
        for arguments in creates:
            self.assertIn(str(fixture.root) + ":/src:ro", arguments)
        facts = fixture.facts()
        self.assertEqual(facts["child_exit"], ["0"])
        self.assertEqual(facts["prepared_recheck_status"], ["0"])
        for phase in ("initial", "final"):
            ledger = fixture.artifact(f".{phase}.ledger.sha256")
            self.assertEqual(facts[f"prepared_{phase}_ledger"], [ledger.name, hashlib.sha256(ledger.read_bytes()).hexdigest()])
            self.assertEqual(len(ledger.read_text().splitlines()), 3)
            receipt = json.loads(fixture.artifact(f".{phase}.receipt.json").read_text())
            self.assertEqual(set(receipt["graphs"]), {"Cargo.toml", "crates/ebpf/Cargo.toml"})
            self.assertEqual(receipt["tools"]["stable"]["cargo"]["path"], str(fixture.stable_cargo.resolve()))
        text = fixture.facts_path.read_text()
        self.assertLess(text.index("prepared_final_ledger\t"), text.index("child_exit\t"))

    def test_one_owned_bridge_serves_all_containers_and_is_removed_last(self):
        fixture = self.fixture()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
        networks = [args for args in docker if args[:2] == ["network", "create"]]
        self.assertEqual(len(networks), 1, "driver did not create exactly one private bridge")
        self.assertEqual(networks[0][networks[0].index("--driver") + 1], "bridge")
        self.assertNotIn("--subnet", networks[0], "Docker must select IPAM without a hard-coded host range")
        facts = fixture.facts()
        identity = facts["network_identity"][0]
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        provenance = json.loads(facts["network_provenance"][0])
        self.assertEqual(provenance["id"], identity)
        self.assertEqual(provenance["driver"], "bridge")
        self.assertEqual(provenance["ipam"]["Config"], [{"Subnet": "172.28.0.0/16", "Gateway": "172.28.0.1"}])
        creates = [args for args in docker if args[0] == "create"]
        self.assertEqual(len(creates), 3)
        self.assertTrue(all(args[args.index("--network") + 1] == identity for args in creates))
        for event in fixture.events():
            if event["kind"] == "docker" and event["argv"][0] == "create":
                self.assertEqual(event["recorded_network_ids"], [identity])
        removal = docker.index(["network", "rm", identity])
        self.assertTrue(all(index < removal for index, args in enumerate(docker) if args[0] == "rm"))
        self.assertEqual(facts["network_cleanup_status"], ["0"])
        self.assertFalse(json.loads(fixture.state_path.read_text())["networks"])

    def test_network_lifecycle_uses_only_sealed_release_tools(self):
        fixture = self.fixture()
        result = fixture.run(sealed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixture.facts()["network_cleanup_status"], ["0"])
        self.assertIn("network_identity", fixture.facts())
        self.assertFalse(json.loads(fixture.state_path.read_text())["networks"])

    def test_network_name_collision_never_authorizes_foreign_removal(self):
        fixture = self.fixture()
        fixture.config["network_failure"] = "collision"
        result = fixture.run()
        self.assertEqual(result.returncode, 125, result.stderr)
        docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
        self.assertFalse(any(args[:2] == ["network", "rm"] for args in docker))
        self.assertFalse(any(args[0] == "create" for args in docker))
        self.assertEqual(set(json.loads(fixture.state_path.read_text())["networks"]), {"f" * 64})

    def test_lost_or_interrupted_network_create_reply_is_reconciled_by_owner_label(self):
        for failure in ("lost-reply", "interrupted"):
            with self.subTest(failure=failure):
                fixture = self.fixture(failure)
                fixture.config["network_failure"] = failure
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
                removed = [args[-1] for args in docker if args[:2] == ["network", "rm"]]
                self.assertEqual(removed, ["a" * 64])
                self.assertFalse(json.loads(fixture.state_path.read_text())["networks"])
                self.assertEqual(fixture.facts()["network_cleanup_status"], ["0"])

    def test_network_cleanup_and_ambiguous_ownership_fail_closed(self):
        for failure in ("remove", "absence", "query", "ambiguous", "wrong-owner"):
            with self.subTest(failure=failure):
                fixture = self.fixture(failure)
                fixture.config["network_failure"] = failure
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
                if failure in ("query", "ambiguous", "wrong-owner"):
                    self.assertFalse(any(args[:2] == ["network", "rm"] for args in docker))
                self.assertTrue(json.loads(fixture.state_path.read_text())["networks"])
                self.assertNotEqual(fixture.facts()["network_cleanup_status"], ["0"])

    def test_replaced_or_symlinked_facts_refuse_provenance_writes_but_clean_owned_network(self):
        for failure in ("facts-replaced", "facts-symlink"):
            with self.subTest(failure=failure):
                fixture = self.fixture(failure)
                fixture.config["network_failure"] = failure
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                state = json.loads(fixture.state_path.read_text())
                expected = "foreign receipt bytes\n" if failure == "facts-replaced" else state["facts_before_tamper"]
                self.assertEqual(fixture.facts_path.read_text(), expected)
                self.assertFalse(state["networks"], "known owned resource must still be cleaned")

    def test_foreign_name_collision_never_grants_cleanup_ownership(self):
        fixture = self.fixture()
        fixture.config["collision"] = True
        result = fixture.run()
        self.assertEqual(result.returncode, 125, result.stderr)
        docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
        self.assertFalse(any(arguments[0] == "rm" for arguments in docker))
        self.assertFalse(any(key.startswith("container_") for key in fixture.facts()))
        self.assertEqual(set(json.loads(fixture.state_path.read_text())["ids"]), {"f" * 64})
        self.assertEqual(fixture.facts()["child_exit"], ["125"])

    def test_created_ids_are_read_back_started_recorded_and_removed_exactly(self):
        fixture = self.fixture()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        docker = [row["argv"] for row in fixture.events() if row["kind"] == "docker"]
        self.assertEqual(sum(arguments[0] == "create" for arguments in docker), 3)
        self.assertFalse(any(arguments[0] == "run" for arguments in docker))
        removed = [arguments[-1] for arguments in docker if arguments[0] == "rm"]
        self.assertEqual(len(removed), 3)
        facts = fixture.facts()
        for role, identity in zip(("glibc_build", "glibc_run", "musl_build"), removed):
            self.assertRegex(identity, r"^[0-9a-f]{64}$")
            self.assertEqual(facts["container_" + role], [identity])
            self.assertLess(docker.index(["inspect", "-f", "{{.Id}}", identity]), docker.index(["start", "-a", identity]))
            self.assertLess(docker.index(["start", "-a", identity]), docker.index(["rm", "-f", identity]))
            self.assertIn(["inspect", identity], docker)
            start = next(row for row in fixture.events() if row["kind"] == "docker"
                         and row["argv"] == ["start", "-a", identity])
            self.assertIn(identity, start["recorded_ids"])
        self.assertEqual(json.loads(facts["network_provenance"][0])["name"],
                         facts["network_requested_name"][0])
        self.assertFalse(json.loads(fixture.state_path.read_text())["ids"])

    def test_bad_prepared_bytes_or_metadata_refuse_before_resources(self):
        for failure in ("tree", "root", "bpf"):
            with self.subTest(failure=failure):
                fixture = self.fixture(failure)
                if failure == "tree":
                    Path(fixture.config["prepared_source"]).write_text("tampered prepared source\n")
                else:
                    fixture.config[failure + "_status"] = 23
                result = fixture.run()
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("refusal", result.stderr)
                self.assertFalse(any(row["kind"] in ("docker", "vendor") for row in fixture.events()))
                self.assertFalse(fixture.artifact(".initial.ledger.sha256").exists())
                self.assertFalse(list(fixture.artifacts.glob("discover.prepared.final.*")))
                self.assertEqual(fixture.facts()["child_exit"], ["77"])
                self.assertNotIn("prepared_recheck_status", fixture.facts())
                if failure != "tree":
                    self.assertIn("metadata refusal", fixture.artifact(f".initial.{failure}.stderr").read_text())

    def test_non_executable_tool_selection_refuses_before_admission(self):
        fixture = self.fixture()
        fixture.config["tools"]["1.88:cargo"] = str(fixture.evidence.tools)
        result = fixture.run()
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertFalse(any(row["kind"] != "rustup" for row in fixture.events()))
        self.assertFalse(fixture.artifact(".initial.receipt.json").exists())
        self.assertFalse(list(fixture.artifacts.glob("discover.prepared.final.*")))
        self.assertEqual(fixture.facts()["child_exit"], ["77"])

    def test_persistent_tree_or_selection_mutation_fails_after_owned_cleanup(self):
        for mutation in ("tree", "metadata"):
            with self.subTest(mutation=mutation):
                fixture = self.fixture(mutation)
                fixture.config["mutation"] = mutation
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusal", result.stderr)
                self.assertEqual(sum(row["kind"] == "docker" and row["argv"][0] == "rm" for row in fixture.events()), 3)
                self.assertFalse(json.loads(fixture.state_path.read_text())["ids"])
                self.assertNotEqual(fixture.facts()["child_exit"], ["0"])
                self.assertNotEqual(fixture.facts()["prepared_recheck_status"], ["0"])
                self.assertFalse(fixture.artifact(".final.ledger.sha256").exists())

    def test_cleanup_removal_or_absence_failure_survives_successful_recheck(self):
        for failure in ("remove_failure", "absence_failure"):
            with self.subTest(failure=failure):
                fixture = self.fixture(failure)
                fixture.config["cleanup"] = failure
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sum(row["kind"] == "docker" and row["argv"][0] == "rm" for row in fixture.events()), 3)
                self.assertTrue(json.loads(fixture.state_path.read_text())["ids"])
                self.assertIn("prepared_recheck_status", fixture.facts())
                self.assertEqual(fixture.facts()["prepared_recheck_status"], ["0"])
                self.assertTrue(fixture.artifact(".final.receipt.json").is_file())
                self.assertNotEqual(fixture.facts()["child_exit"], ["0"])

    def test_argument_and_work_root_validation_remain_before_resources(self):
        fixture = self.fixture("arguments")
        self.assertEqual(fixture.run(arguments=["--unknown"]).returncode, 2)
        self.assertFalse(fixture.events())
        self.assertFalse(fixture.facts_path.exists())
        fixture = self.fixture("relative-work")
        self.assertEqual(fixture.run(work="relative-work").returncode, 2)
        self.assertFalse(fixture.events())


if __name__ == "__main__":
    unittest.main(verbosity=2)
