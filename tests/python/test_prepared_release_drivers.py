#!/usr/bin/env python3
"""Prepared source admission and finalization through the release driver callers."""

import json
import os
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "tests/fixtures/prepared-release-drivers"
SEAL = runpy.run_path(str(ROOT / "tests/fixtures/release-seal/fixture.py"))
FINALIZER = runpy.run_path(str(NATIVE / "harness.py"))["run_finalizer"]
NEW_BUILD_CONTEXT = (
    "P11SCOPE_PRODUCT_BUILD_MODE", "P11SCOPE_PREPARED_STABLE_CARGO",
    "P11SCOPE_PREPARED_STABLE_RUSTC", "P11SCOPE_PREPARED_BPF_CARGO",
    "P11SCOPE_PREPARED_BPF_RUSTC",
)


class PreparedReleaseDriverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prepared-release-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        retained = os.environ.get("P11SCOPE_PREPARED_DRIVERS_EVIDENCE")
        if retained:
            destination = Path(retained) / self._testMethodName
            destination.parent.mkdir(parents=True, exist_ok=True)
            self.addCleanup(shutil.copytree, self.base, destination, symlinks=True)

    def fixture(self, lane, name=None):
        fixture = SEAL["ReleaseSealFixture"](self.base / (name or lane))
        fixture.lane = lane
        fixture.prefix = fixture.root / "artifacts" / ("release.prepared" if lane == "release" else "lane16.prepared")
        if lane == "lane16":
            fixture.template(str(NATIVE / "sudo.sh.in"), fixture.fake_bin / "sudo", LOG=fixture.tripwire_log)
        return fixture

    def run_cli(self, fixture, mode="never"):
        if fixture.lane == "release":
            return fixture.run_to_sudo_probe().output
        environment = dict(os.environ)
        for name in SEAL["BUILD_INPUT_VARIABLES"]:
            environment.pop(name, None)
        overrides = {"PATH": str(fixture.fake_bin) + ":" + os.environ["PATH"], "HOME": str(fixture.home)}
        environment.update(overrides)
        return fixture.command(["/bin/sh", str(fixture.repo / "scripts/verify-task4-lane16.sh"), str(fixture.root), mode],
                               environment=environment, overrides=overrides, removed=SEAL["BUILD_INPUT_VARIABLES"])

    def events(self, fixture):
        path = Path(fixture.prepared.config["events"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_both_callers_admit_both_contexts_and_merge_before_sudo(self):
        for lane in ("release", "lane16"):
            with self.subTest(lane=lane):
                fixture = self.fixture(lane, lane + " paths with spaces")
                result = self.run_cli(fixture)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(fixture.tripwire_log.read_text(), "sudo\n")
                events = self.events(fixture)
                self.assertEqual(len(events), 2)
                for event, manifest in zip(events, ("Cargo.toml", "crates/ebpf/Cargo.toml")):
                    self.assertEqual(event["argv"], ["metadata", "--locked", "--offline", "--all-features", "--format-version", "1", "--manifest-path", manifest])
                    self.assertEqual(event["cargo"], str(fixture.base / "toolchain-binary"))
                    self.assertEqual(event["rustc"], str(fixture.base / "toolchain-binary"))
                    self.assertFalse(event["status"])
                ledger = (fixture.root / "artifacts/source.start.tsv").read_text()
                self.assertIn("  Cargo.toml\n", ledger)
                self.assertIn("  third-party/src/demo-1.0.0-p1/src/lib.rs\n", ledger)
                self.assertTrue(Path(str(fixture.prefix) + ".initial.receipt.json").is_file())
                self.assertFalse(Path(str(fixture.prefix) + ".final.receipt.json").exists(), "status77 skips qualifying final checks")

    def test_invalid_prepared_tree_or_metadata_refuses_before_sudo(self):
        for lane in ("release", "lane16"):
            for failure in ("tree", "root", "bpf"):
                with self.subTest(lane=lane, failure=failure):
                    fixture = self.fixture(lane, lane + "-" + failure)
                    if failure == "tree":
                        (fixture.prepared.base.output / "src/lib.rs").write_text("changed prepared bytes\n")
                    else:
                        fixture.prepared.config[failure + "_status"] = 23
                        fixture.prepared.write_config()
                    result = self.run_cli(fixture)
                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertFalse(fixture.tripwire_log.exists(), result.stderr)
                    self.assertIn("refusal", result.stderr)
                    self.assertFalse((fixture.root / "artifacts/source.start.tsv").exists())
                    self.assertFalse(Path(str(fixture.prefix) + ".final.receipt.json").exists())

    def test_duplicate_and_failed_inventory_stages_refuse_before_sudo(self):
        for lane in ("release", "lane16"):
            for failure in ("duplicate", "fail", "sort"):
                with self.subTest(lane=lane, failure=failure):
                    fixture = self.fixture(lane, lane + "-" + failure)
                    if failure == "sort":
                        fixture.template(str(NATIVE / "sort.sh.in"), fixture.fake_bin / "sort",
                                         SORT=shutil.which("sort"), LEDGER=str(fixture.prefix) + ".initial.ledger.sha256")
                    else:
                        fixture.template(str(NATIVE / "inventory.sh.in"), fixture.fake_bin / "git",
                                         GIT=shutil.which("git"), BEHAVIOR=failure)
                    result = self.run_cli(fixture)
                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertFalse(fixture.tripwire_log.exists(), failure)
                    self.assertEqual(len(self.events(fixture)), 2, "producer refusal follows actual admission")

    def test_actual_finalizers_recheck_after_cleanup_and_preserve_failures(self):
        for lane in ("release", "lane16"):
            for scenario in ("success", "tree", "metadata", "cleanup", "config", "admission", "admitted77"):
                with self.subTest(lane=lane, scenario=scenario):
                    fixture = self.fixture(lane, lane + "-" + scenario)
                    result = FINALIZER(fixture, scenario)
                    expected = 77 if scenario in ("admission", "admitted77") else 0 if scenario == "success" else 1
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual((fixture.root / "status").read_text(), str(expected) + "\n")
                    events = self.events(fixture)
                    if scenario in ("admission", "admitted77"):
                        self.assertEqual(len(events), 0 if scenario == "admission" else 2)
                        self.assertFalse(Path(str(fixture.prefix) + ".final.receipt.json").exists())
                    elif scenario in ("success", "cleanup"):
                        self.assertEqual(len(events), 4)
                        self.assertTrue(all(event["cleanup"] and not event["status"] for event in events[2:]))
                        self.assertTrue(Path(str(fixture.prefix) + ".final.receipt.json").exists())
                        self.assertEqual((fixture.root / "artifacts/source.start.tsv").read_bytes(),
                                         (fixture.root / "artifacts/source.end.tsv").read_bytes())
                    elif scenario == "config" and lane == "release":
                        self.assertEqual(len(events), 2, "strict Cargo configuration refusal precedes fresh queries")
                        self.assertIn("config", result.stderr.lower())
                    else:
                        self.assertIn("refusal", result.stderr)
                        self.assertFalse(Path(str(fixture.prefix) + ".final.receipt.json").exists())

    def test_lane16_build_uses_selected_cargo_rustc_and_offline_flags(self):
        fixture = self.fixture("lane16", "build paths with spaces")
        fixture.root.mkdir()
        source = (fixture.repo / "scripts/verify-task4-lane16.sh").read_text()
        start = 'CARGO_TARGET_DIR="$ROOT/work/target" \\\n'
        end = 'gcc -O0 -o "$ROOT/work/hammer"'
        self.assertEqual(source.count(start), 1)
        self.assertEqual(source.count(end), 1)
        command = fixture.base / "build-command.sh"
        command.write_text(source[source.index(start):source.index(end)])
        cargo = fixture.base / "selected cargo.py"
        shutil.copyfile(NATIVE / "build-probe.py", cargo)
        cargo.chmod(0o700)
        tools = []
        for name in ("selected rustc", "selected bpf cargo", "selected bpf rustc"):
            path = fixture.base / name
            fixture.inert(path)
            tools.append(path)
        harness = fixture.base / "build.sh"
        fixture.template(str(NATIVE / "build.sh.in"), harness, ROOT=fixture.root,
                         CARGO=cargo, RUSTC=tools[0], BPF_CARGO=tools[1],
                         BPF_RUSTC=tools[2], OMIT="none", COMMAND=command)
        result = fixture.command(["/bin/sh", str(harness)])
        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(cargo.with_suffix(".json").read_text())
        self.assertEqual(event, {"argv": ["build", "--locked", "--release", "--workspace", "--offline"],
                                 "cargo": str(cargo), "rustc": str(tools[0]),
                                 "bpf_cargo": str(tools[1]), "bpf_rustc": str(tools[2]),
                                 "target": str(fixture.root / "work/target")})
        for omitted in ("P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
                        "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC"):
            with self.subTest(omitted=omitted):
                harness = fixture.base / ("omit-" + omitted + ".sh")
                fixture.template(str(NATIVE / "build.sh.in"), harness, ROOT=fixture.root,
                                 CARGO=cargo, RUSTC=tools[0], BPF_CARGO=tools[1],
                                 BPF_RUSTC=tools[2], OMIT=omitted, COMMAND=command)
                cargo.with_suffix(".json").unlink(missing_ok=True)
                result = fixture.command(["/bin/sh", str(harness)])
                self.assertNotEqual(result.returncode, 0, omitted)
                self.assertFalse(cargo.with_suffix(".json").exists(), omitted)

    def test_early_release_refusals_do_not_require_new_helper_files(self):
        for scenario in (*SEAL["BUILD_INPUT_VARIABLES"], *NEW_BUILD_CONTEXT,
                         "cargo-config", "missing-home", "forged", "tab-root"):
            with self.subTest(scenario=scenario):
                fixture = self.fixture("release", "early-" + scenario)
                for path in fixture.repo.iterdir():
                    if path.name not in (".git", "scripts"):
                        shutil.rmtree(path) if path.is_dir() else path.unlink()
                for path in (fixture.repo / "scripts").iterdir():
                    # The finalizer fragment is the driver's own relocated code,
                    # not a new helper: scenarios that reach finalization execute it.
                    if path.name not in ("build-release.sh", "lib.sh", "check-capture-evidence.py",
                                         "lane-build-release-oracle-3.py"):
                        shutil.rmtree(path) if path.is_dir() else path.unlink()
                for args in (["add", "-A"], ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "minimal early-refusal fixture"]):
                    result = fixture.command(["git", "-C", str(fixture.repo), *args])
                    self.assertEqual(result.returncode, 0, result.stderr)
                extra = {}
                if scenario in (*SEAL["BUILD_INPUT_VARIABLES"], *NEW_BUILD_CONTEXT):
                    extra[scenario] = "/fixture/refused"
                    expected = "refusing inherited " + scenario
                elif scenario == "cargo-config":
                    (fixture.home / ".cargo/config.toml").write_text('[build]\nrustflags = ["-C", "target-feature=-crt-static"]\n')
                    expected = "untracked cargo config"
                elif scenario == "missing-home":
                    extra["HOME"] = ""
                    expected = "cannot evaluate the effective cargo home"
                elif scenario == "forged":
                    extra["P11SCOPE_TASK4_SEALED"] = "1"
                    expected = "unsealed or forged"
                else:
                    fixture.root = fixture.root.with_name("evidence\troot")
                    expected = "invalid Task 4 evidence root"
                result = fixture.run_to_sudo_probe(extra).output
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertFalse(fixture.tripwire_log.exists())
                self.assertEqual(self.events(fixture), [])

    def test_release_static_build_forwards_exact_stable_and_bpf_tools(self):
        fixture = self.fixture("release", "static build paths with spaces")
        source = (fixture.repo / "scripts/build-release.sh").read_text()
        start = 'CARGO_TARGET_DIR="$OFFICIAL_TARGET" \\\n'
        end = 'P11SCOPE_STATIC=$OFFICIAL_TARGET/'
        self.assertEqual(source.count(start), 1)
        command = fixture.base / "static-build-command.sh"
        command.write_text(source[source.index(start):source.index(end)])
        cargo = fixture.base / "selected stable cargo"
        shutil.copy2(NATIVE / "release-build-probe.py", cargo)
        cargo.chmod(0o700)
        tools = [cargo]
        for name in ("selected stable rustc", "selected bpf cargo", "selected bpf rustc"):
            path = fixture.base / name
            fixture.inert(path)
            tools.append(path)
        record = fixture.base / "release-build.json"
        result = fixture.command([
            "/bin/sh", str(NATIVE / "release-root-build-launcher.sh"), str(command),
            str(record), *(str(path) for path in tools),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(record.read_text()), {
            "argv": ["build", "--locked", "--offline", "--release",
                     "--no-default-features", "--target", "x86_64-unknown-linux-musl",
                     "--bin", "p11scope"],
            "cargo_target_dir": str(fixture.base / "official target with spaces"),
            "cargo": str(cargo.resolve()),
            "rustflags": "-C target-feature=+crt-static",
            "rustc": str(tools[1]), "bpf_cargo": str(tools[2]),
            "bpf_rustc": str(tools[3]),
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
