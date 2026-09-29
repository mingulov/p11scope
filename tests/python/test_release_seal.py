#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task11 release seal contracts exercised through the actual driver CLI."""

import os
import hashlib
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
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

    def test_release_preserves_private_tmpdir_in_sealed_child_and_facts(self):
        fixture = ReleaseSealFixture(self.base / "temporary paths with spaces")
        fixture.seal_parent.chmod(0o700)
        run = fixture.run_to_sudo_probe()
        self.assert_probe_refused(run)
        self.assertEqual(run.tripped(), "sudo\n", run.diagnostic())
        environment = dict(line.split("=", 1) for line in
                           run.environment_dump.read_text().splitlines())
        self.assertEqual(environment.get("TMPDIR"), str(fixture.seal_parent))
        self.assertEqual(run.fact("sealed_env_TMPDIR"), str(fixture.seal_parent))
        self.assertEqual(list(fixture.seal_parent.iterdir()), [])

    def test_release_refuses_unsafe_tmpdir_before_receipt_and_privileged_probe(self):
        unsafe = self.base / "public-temp"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        linked = self.base / "linked-temp"
        linked.symlink_to(unsafe, target_is_directory=True)
        for value in ("relative-temp", str(self.base / "absent"), str(unsafe),
                      str(linked), str(self.base) + "/../", "/tmp\tbad", ""):
            with self.subTest(value=value):
                fixture = ReleaseSealFixture(self.base / ("invalid-" + str(len(list(self.base.iterdir())))))
                run = fixture.run_to_sudo_probe({"TMPDIR": value})
                self.assert_probe_refused(run)
                self.assertEqual(run.tripped(), "")
                self.assertFalse(run.root.exists())
                self.assertIn("TMPDIR", run.output.stderr)


class ReleaseArtifactLedgerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope-release-artifacts-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.dist = self.base / "dist"
        self.dist.mkdir(mode=0o700)
        self.inputs = {"p11scope": b"observer", "p11scope-discover": b"glibc",
                       "p11scope-discover-glibc": b"glibc", "p11scope-discover-musl": b"musl"}
        for name, content in self.inputs.items():
            (self.dist / name).write_bytes(content)
        self.ledger = self.base / "release-artifacts.sha256"

    def command(self, operation, digest=None):
        argv = [sys.executable, "-I", str(ROOT / "scripts/release-artifacts.py"),
                operation, "--dist", str(self.dist), "--ledger", str(self.ledger)]
        if digest is not None:
            argv.extend(["--sha256", digest])
        return subprocess.run(argv, text=True, capture_output=True, timeout=15)

    def record(self):
        result = self.command("record")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_record_and_verify_bind_exact_fixed_artifacts_and_0600_ledger(self):
        digest = self.record()
        expected = "".join(hashlib.sha256(content).hexdigest() + "  " + name + "\n"
                           for name, content in sorted(self.inputs.items())).encode()
        self.assertEqual(self.ledger.read_bytes(), expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.ledger.stat().st_mode & 0o777, 0o600)
        checked = self.command("verify", digest)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_record_preserves_existing_ledger(self):
        self.ledger.write_bytes(b"keep")
        self.assertNotEqual(self.command("record").returncode, 0)
        self.assertEqual(self.ledger.read_bytes(), b"keep")

    def test_changed_binary_and_alias_mismatch_refuse(self):
        digest = self.record()
        (self.dist / "p11scope").write_bytes(b"different")
        self.assertNotEqual(self.command("verify", digest).returncode, 0)
        self.ledger.unlink()
        (self.dist / "p11scope-discover").write_bytes(b"other helper")
        result = self.command("record")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alias", result.stderr)
        self.assertFalse(self.ledger.exists())

    def test_duplicate_missing_unknown_or_reordered_ledger_rows_refuse(self):
        self.record()
        rows = self.ledger.read_bytes().splitlines(keepends=True)
        for content in (b"".join(rows + rows[:1]), b"".join(rows[:-1]),
                        b"".join(reversed(rows)), b"".join(rows).replace(b"  p11scope\n", b"  other\n")):
            with self.subTest(content=content):
                self.ledger.write_bytes(content)
                result = self.command("verify", hashlib.sha256(content).hexdigest())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ledger", result.stderr)

    def test_ledger_digest_and_symlink_inputs_refuse(self):
        digest = self.record()
        self.assertNotEqual(self.command("verify", "0" * 64).returncode, 0)
        original = self.base / "original"
        original.write_bytes(self.inputs["p11scope"])
        (self.dist / "p11scope").unlink()
        (self.dist / "p11scope").symlink_to(original)
        self.assertNotEqual(self.command("verify", digest).returncode, 0)
        self.ledger.unlink()
        self.assertNotEqual(self.command("record").returncode, 0)
        (self.dist / "p11scope").unlink()
        (self.dist / "p11scope").write_bytes(self.inputs["p11scope"])
        digest = self.record()
        real_ledger = self.base / "ledger-real"
        self.ledger.rename(real_ledger)
        self.ledger.symlink_to(real_ledger)
        self.assertNotEqual(self.command("verify", digest).returncode, 0)

    def test_missing_binary_and_symlink_dist_refuse(self):
        (self.dist / "p11scope").unlink()
        self.assertNotEqual(self.command("record").returncode, 0)
        (self.dist / "p11scope").write_bytes(self.inputs["p11scope"])
        real_dist = self.base / "real-dist"
        self.dist.rename(real_dist)
        self.dist.symlink_to(real_dist, target_is_directory=True)
        self.assertNotEqual(self.command("record").returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
