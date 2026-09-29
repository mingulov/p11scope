# SPDX-License-Identifier: GPL-3.0-or-later
"""Release notice boundaries; no Cargo compilation or network access."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-notices.py"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPT.parent))
from _loader import load_path


class ReleaseNoticesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SCRIPT.exists():
            cls.mod = load_path(SCRIPT, "release_notices")
        else:
            cls.mod = None

    def setUp(self):
        self.assertIsNotNone(self.mod, "release notice validator is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.license = self.root / "LICENSE"
        self.license.write_text("Copyright Example authors\nPermission granted.\n")
        self.package = {"id": "registry+https://example.test#example@1.0", "name": "example",
                        "version": "1.0", "license": "MIT OR Apache-2.0", "source": "registry+https://example.test",
                        "manifest_path": str(self.root / "Cargo.toml")}
        self.metadata = {"packages": [self.package]}
        self.report = {"crates": [{"package": self.package, "license": self.package["license"]}],
                       "licenses": [{"id": "MIT", "text": self.license.read_text(),
                                     "source_path": str(self.license), "used_by": [{"crate": self.package}]}]}

    def normalize(self):
        return self.mod.normalize_report(self.report, self.metadata, self.root, self.root)

    def test_synthesized_license_is_rejected(self):
        self.report["licenses"][0]["source_path"] = None
        with self.assertRaisesRegex(self.mod.NoticeError, "synthesized"):
            self.normalize()

    def test_missing_package_is_rejected(self):
        self.report["crates"] = []
        with self.assertRaisesRegex(self.mod.NoticeError, "package coverage"):
            self.normalize()

    def test_expression_change_is_rejected(self):
        self.report["crates"][0]["license"] = "MIT"
        with self.assertRaisesRegex(self.mod.NoticeError, "expression"):
            self.normalize()

    def test_cargo_legacy_slash_spelling_is_preserved(self):
        self.package["license"] = "MIT/Apache-2.0"
        self.report["crates"][0]["license"] = "MIT OR Apache-2.0"
        self.assertEqual(self.normalize()["packages"][0]["declared_license"], "MIT/Apache-2.0")

    def test_missing_notice_owner_is_rejected(self):
        self.report["licenses"][0]["used_by"] = []
        with self.assertRaisesRegex(self.mod.NoticeError, "notice coverage"):
            self.normalize()

    def test_output_preserves_expression_and_removes_host_paths(self):
        result = self.normalize()
        self.assertEqual(result["packages"][0]["declared_license"], "MIT OR Apache-2.0")
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(result, self.normalize())

    def test_file_tampering_and_missing_file_are_rejected(self):
        digest = hashlib.sha256(self.license.read_bytes()).hexdigest()
        self.assertEqual(self.mod.checked_bytes(self.license, digest), self.license.read_bytes())
        self.license.write_text("changed")
        with self.assertRaisesRegex(self.mod.NoticeError, "hash mismatch"):
            self.mod.checked_bytes(self.license, digest)
        self.license.unlink()
        with self.assertRaises(self.mod.NoticeError):
            self.mod.checked_bytes(self.license, digest)

    def test_symlink_notice_is_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.license)
        with self.assertRaisesRegex(self.mod.NoticeError, "regular"):
            self.mod.checked_bytes(link)

    def test_workspace_ids_become_relative(self):
        self.package["id"] = "path+file://" + str(self.root) + "#example@1.0"
        result = self.normalize()
        self.assertEqual(result["packages"][0]["id"], "workspace:.#example@1.0")

    def test_cli_rejects_existing_output_without_changing_it(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--cargo-about", "/nonexistent/about",
                                 "--musl-archive", "/nonexistent/musl", "--output", str(self.root)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute, absent", result.stderr)
        self.assertEqual(self.license.read_text(), "Copyright Example authors\nPermission granted.\n")

    def test_dirty_source_is_rejected(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        with self.assertRaisesRegex(self.mod.NoticeError, "clean tracked source"):
            self.mod.source_identity(self.root)

    def test_git_environment_cannot_redirect_source_inspection(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        with mock.patch.dict(self.mod.os.environ, {"GIT_DIR": "/nonexistent/foreign.git"}):
            self.assertIn("LICENSE", self.mod.run(["git", "status", "--porcelain"], self.root))

    def test_clarification_version_drift_is_rejected(self):
        recipe = {"clarifications": {"example": {"version": "9.0", "license": self.package["license"],
                                                 "source": self.package["source"], "files": []}}}
        with self.assertRaisesRegex(self.mod.NoticeError, "identity changed"):
            self.mod.make_config(self.metadata, self.root, recipe)

    def test_recipe_input_hash_is_checked(self):
        (self.root / "third-party/licenses").mkdir(parents=True)
        notice = self.root / "third-party/licenses/upstream.txt"
        notice.write_text("the original terms")
        recipe = {"files": {"upstream.txt": {"sha256": "0" * 64}}}
        with self.assertRaisesRegex(self.mod.NoticeError, "hash mismatch"):
            self.mod.load_inputs(self.root, recipe)

    def test_symlink_ancestor_is_rejected(self):
        (self.root / "real").mkdir()
        (self.root / "real/notice").write_text("terms")
        (self.root / "linked").symlink_to(self.root / "real", target_is_directory=True)
        with self.assertRaises(self.mod.NoticeError):
            self.mod.checked_bytes(self.root / "linked/notice")

    def test_changed_input_during_read_is_rejected(self):
        original_read = self.mod.os.read
        changed = False

        def read_with_concurrent_change(fd, size):
            nonlocal changed
            data = original_read(fd, size)
            if data and not changed:
                changed = True
                self.license.write_text("a different notice")
            return data

        with mock.patch.object(self.mod.os, "read", side_effect=read_with_concurrent_change):
            with self.assertRaisesRegex(self.mod.NoticeError, "changed while reading"):
                self.mod.checked_bytes(self.license)

    def test_original_nested_and_alternate_notices_are_preserved(self):
        nested = self.root / "src/spin"
        nested.mkdir(parents=True)
        (nested / "license.MIT").write_text("Different author's notice")
        (self.root / "AUTHORS.md").write_text("The authors")
        records, payload = self.mod.collect_license_files(self.metadata, self.root)
        names = {r["package_relative_path"] for r in records}
        self.assertEqual(names, {"LICENSE", "src/spin/license.MIT", "AUTHORS.md"})
        self.assertIn(b"Different author's notice", payload.values())
        self.assertIn(b"The authors", payload.values())

    def test_workspace_ignored_notice_is_not_a_release_input(self):
        self.package["source"] = None
        self.package["id"] = "path+file://" + str(self.root) + "#example@1.0"
        scratch = self.root / ".worktrees/old"
        scratch.mkdir(parents=True)
        (scratch / "NOTICE-private.txt").write_text("private scratch")
        records, payload = self.mod.collect_license_files(self.metadata, self.root,
                                                         committed_paths={"LICENSE"})
        self.assertEqual([r["package_relative_path"] for r in records], ["LICENSE"])
        self.assertNotIn(b"private scratch", payload.values())

    def test_extra_prepared_notice_invalidates_the_recipe_tree(self):
        preparer = self.mod.load_sibling("prepare-dependencies.py")
        prepared = self.root / "third-party/src/aya-0.14.0-p2"
        prepared.mkdir(parents=True)
        prepared.chmod(0o755)
        (prepared / "LICENSE").write_text("pinned upstream notice")
        (prepared / "LICENSE").chmod(0o644)
        record = {"name": "aya", "version": "0.14.0", "revision": 2,
                  "archive_sha256": "0" * 64, "patches": [], "applies_to": ["Cargo.toml"],
                  "expected_tree_sha256": preparer.compute_tree_digest(prepared)}
        (self.root / "third-party/sources.json").write_text(json.dumps(
            {"schema_version": 1, "workspace_manifests": ["Cargo.toml"], "packages": [record]}))
        receipt = {"schema_version": 1, "package": "aya", "version": "0.14.0", "revision": 2,
                   "recipe_sha256": preparer.compute_recipe_identity(record, []),
                   "tree_sha256": record["expected_tree_sha256"]}
        (prepared / preparer.RECEIPT_NAME).write_text(json.dumps(receipt))
        (prepared / preparer.RECEIPT_NAME).chmod(0o644)
        self.assertIn(prepared / "LICENSE", self.mod.prepared_files(self.root, prepared))
        (prepared / "NOTICE-scratch").write_text("unexpected extra notice")
        (prepared / "NOTICE-scratch").chmod(0o644)
        with self.assertRaisesRegex(self.mod.NoticeError, "tree digest mismatch"):
            self.mod.prepared_files(self.root, prepared)

    def test_output_parent_must_be_private_and_outside_checkout(self):
        with self.assertRaises(self.mod.NoticeError):
            self.mod.validate_output(self.root, self.root / "out")
        private = self.root / "private"
        private.mkdir(mode=0o700)
        external_checkout = self.root / "repo"
        self.mod.validate_output(external_checkout, private / "out")
        private.chmod(0o755)
        with self.assertRaisesRegex(self.mod.NoticeError, "private"):
            self.mod.validate_output(external_checkout, private / "out")

    def test_all_required_musl_archives_are_bound_by_hash(self):
        first, second = self.root / "first", self.root / "second"
        first.write_bytes(b"archive one")
        second.write_bytes(b"archive two")
        required = [{"version": "1.2.3", "sha256": hashlib.sha256(first.read_bytes()).hexdigest()},
                    {"version": "1.2.5", "sha256": hashlib.sha256(second.read_bytes()).hexdigest()}]
        result = self.mod.musl_payload([second, first], required)
        self.assertEqual(result["licenses/musl-1.2.3-source.tar.gz"], b"archive one")
        self.assertEqual(result["licenses/musl-1.2.5-source.tar.gz"], b"archive two")
        for supplied in [[first], [first, first]]:
            with self.assertRaises(self.mod.NoticeError):
                self.mod.musl_payload(supplied, required)
        second.write_bytes(b"modified archive")
        with self.assertRaisesRegex(self.mod.NoticeError, "unrecognized"):
            self.mod.musl_payload([first, second], required)


if __name__ == "__main__":
    unittest.main()
