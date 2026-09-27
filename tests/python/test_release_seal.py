#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task11 release seal contracts exercised through the actual driver CLI."""

import os
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/release-seal"
NATIVE = runpy.run_path(str(FIXTURES / "fixture.py"))
ReleaseSealFixture = NATIVE["ReleaseSealFixture"]
Task11FixtureOptions = NATIVE["Task11FixtureOptions"]
EXPECTED = NATIVE["EXPECTED"]


class ReleaseSealTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope-release-seal-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        retained = os.environ.get("P11SCOPE_RELEASE_SEAL_EVIDENCE")
        if retained:
            destination = Path(retained) / self._testMethodName
            destination.parent.mkdir(parents=True, exist_ok=True)
            self.addCleanup(shutil.copytree, self.base, destination, symlinks=True)

    def run_driver(self, name="case", *, extra_env=(), **options):
        fixture = ReleaseSealFixture(self.base / name, Task11FixtureOptions(**options))
        return fixture.run_to_sudo_probe(extra_env)

    def assert_probe_refused(self, run):
        self.assertEqual(run.output.returncode, 77, run.output.stderr)

    def test_release_seal_denies_the_caller_path_to_every_reached_command(self):
        run = self.run_driver()
        self.assert_probe_refused(run)
        self.assertEqual(run.tripped(), "sudo\n", run.diagnostic())
        self.assertEqual((run.root / "status").read_text(), "77\n")
        sealed_bin = run.fact("sealed_bin")
        self.assertIsNotNone(sealed_bin, run.diagnostic())
        self.assertFalse(Path(sealed_bin).exists())
        self.assertEqual(list(run.seal_parent.iterdir()), [])
        for tool in EXPECTED["tool_inventory"]:
            with self.subTest(tool=tool):
                row = run.fact("tool_" + tool)
                self.assertIsNotNone(row, run.diagnostic())
                fields = row.split(" ")
                self.assertEqual(len(fields), 3, f"{row}\n{run.diagnostic()}")
                self.assertTrue(fields[0].startswith("/"), f"{row}\n{run.diagnostic()}")
                self.assertEqual(fields[0], fields[1], f"{row}\n{run.diagnostic()}")
                self.assertRegex(fields[2], r"^[0-9a-fA-F]{64}$", f"{row}\n{run.diagnostic()}")
        for name in ("toolchain_sysroot", "toolchain_nightly_cargo", "toolchain_nightly_rustc",
                     "toolchain_nightly_sysroot", "toolchain_nightly_rust_src", "toolchain_bpf_linker"):
            with self.subTest(closure=name):
                row = run.fact(name)
                self.assertIsNotNone(row, run.diagnostic())
                fields = row.split(" ")
                self.assertEqual(len(fields), 2, f"{row}\n{run.diagnostic()}")
                self.assertTrue(fields[0].startswith("/"), f"{row}\n{run.diagnostic()}")
                self.assertRegex(fields[1].removeprefix("tree-sha256-v1:"), r"^[0-9a-fA-F]{64}$",
                                 f"{row}\n{run.diagnostic()}")
        self.assertIn("/.cargo/bin/bpf-linker", run.fact("toolchain_bpf_linker"), run.diagnostic())
        caller_path = run.fact("caller_path")
        self.assertIsNotNone(caller_path, run.diagnostic())
        self.assertTrue(any(entry.endswith("tripwire-bin") for entry in caller_path.split(":")),
                        run.diagnostic())

    def test_release_seal_exports_exactly_the_reviewed_environment(self):
        carrier = self.base / "carrier"
        carrier.mkdir()
        shutil.copyfile(FIXTURES / "sitecustomize.py", carrier / "sitecustomize.py")
        planted = {
            "RUSTC_WORKSPACE_WRAPPER": "/task11/wrapper", "P11SCOPE_SMALL_RING": "1",
            "PYTHONPATH": str(carrier), "PYTHONHOME": "", "GIT_DIR": "/task11/git",
            "GIT_WORK_TREE": "/task11/worktree", "GIT_INDEX_FILE": "/task11/index",
            "GIT_CONFIG_GLOBAL": "/task11/gitconfig", "DOCKER_HOST": "tcp://task11.invalid:2375",
            "LANG": "en_US.UTF-8",
        }
        run = self.run_driver(extra_env=planted)
        self.assert_probe_refused(run)
        dumped = run.environment_dump.read_text()
        pairs = [line.split("=", 1) for line in dumped.splitlines() if "=" in line]
        self.assertEqual(sorted(name for name, _ in pairs), EXPECTED["sealed_environment"], dumped)
        for name in planted:
            self.assertNotIn(name + "=", dumped)
        environment = dict(pairs)
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["P11SCOPE_RECEIPT_SEALED"], "1")
        self.assertEqual(environment["PATH"], environment["P11SCOPE_RECEIPT_SEALED_BIN"])
        self.assertFalse((carrier / "sitecustomize-ran").exists())
        head = run.fixture.command(["git", "-C", str(run.repo), "rev-parse", "HEAD"])
        self.assertEqual(head.returncode, 0, head.stderr)
        self.assertEqual(run.fact("head"), head.stdout.strip(), run.diagnostic())

    def test_release_cargo_home_bin_closure_is_complete_and_refuses_shadows(self):
        safe = self.run_driver("safe")
        self.assert_probe_refused(safe)
        for name in ("cargo", "rustc", "rustup", "bpf-linker", "cargo-third-party",
                     "cargo-third-party-link", "cargo-third-party-target"):
            self.assertIsNotNone(safe.fact("cargo_home_bin_" + name),
                                 f"{name}\n{safe.diagnostic()}")
        self.assertIn("cargo-third-party-target", safe.fact("cargo_home_bin_cargo-third-party-link"),
                      safe.diagnostic())
        self.assertEqual(safe.tripped(), "sudo\n", safe.diagnostic())
        for option in ("cargo_home_inventory_shadow", "cargo_proxy_mismatch", "cargo_proxy_regular_mismatch",
                       "cargo_home_raw_target_newline", "cargo_home_canonical_target_newline"):
            with self.subTest(option=option):
                run = self.run_driver(option, **{option: True})
                self.assert_probe_refused(run)
                self.assertEqual(run.tripped(), "", f"{option}\n{run.diagnostic()}")

    def test_release_sysroot_closure_is_bound_and_missing_musl_refuses_before_body(self):
        release = (ROOT / "scripts/build-release.sh").read_text()
        self.assertIn("tree-sha256-v1:", release)
        self.assertNotIn("target add", release)
        safe = self.run_driver("internal-link", internal_rust_src_symlink=True)
        self.assert_probe_refused(safe)
        for name in ("toolchain_sysroot", "toolchain_nightly_sysroot", "toolchain_nightly_rust_src"):
            row = safe.fact(name)
            self.assertIsNotNone(row, safe.diagnostic())
            self.assertIn("tree-sha256-v1:", row, safe.diagnostic())
        self.assertEqual(safe.tripped(), "sudo\n", safe.diagnostic())
        missing = self.run_driver("missing-musl", missing_musl=True)
        self.assert_probe_refused(missing)
        self.assertEqual(missing.tripped(), "", missing.diagnostic())
        self.assertIsNone(missing.fact("toolchain_sysroot"), missing.diagnostic())

    def test_release_refuses_an_external_nightly_rust_src_symlink(self):
        run = self.run_driver(external_rust_src_symlink=True)
        self.assert_probe_refused(run)
        self.assertIsNotNone(run.fact("head"), run.diagnostic())
        for absent in ("toolchain_nightly_rust_src", "tool_awk", "tool_bpf-linker"):
            self.assertIsNone(run.fact(absent), f"{absent}\n{run.diagnostic()}")
        self.assertEqual(run.tripped(), "", run.diagnostic())
        sealed_bin = run.fact("sealed_bin")
        self.assertIsNotNone(sealed_bin, run.diagnostic())
        self.assertFalse(Path(sealed_bin).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
