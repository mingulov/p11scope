#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Public packages must preserve tested bytes and exclude private evidence."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("package_release", ROOT / "scripts/package-release.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PackageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-package-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.originals = {"third-party/archives/aya-0.14.0.crate": b"pinned upstream archive"}
        self.inputs = {
            "Cargo.toml": b'[package]\nname="p11scope"\nversion="0.1.0"\n',
            "crates/discover/Cargo.toml": b'[package]\nname="p11scope-discover"\nversion="0.1.0"\n',
            "LICENSE": b"project license\n",
            "LICENSES/GPL-2.0-only.txt": b"BPF license\n",
            "LICENSES/GPL-2.0-or-later.txt": b"shared code license\n",
            "third-party/sources.json": json.dumps({"packages": [{
                "name": "aya", "version": "0.14.0",
                "archive_sha256": digest(b"pinned upstream archive"),
            }]}).encode(),
        }
        self.recipe = {
            "schema_version": 1,
            "files": {"llvm-license.txt": {"sha256": digest(b"upstream license"), "url": "https://example.test/license"}},
            "musl": [{"sha256": digest(b"musl source"), "version": "1.2.3"},
                     {"sha256": digest(b"helper musl source"), "version": "1.2.5"}],
            "native_runtime": {"revision": "fixture LLVM revision"},
            "toolchains": [{
                "name": name, "rustc_verbose_version": f"fixture {name}",
                "files": [{"payload": f"licenses/rust-{name}/COPYRIGHT-library.html", "sha256": digest(b"Rust notice")}],
            } for name in ("1.88", "nightly-2026-05-20")],
        }
        self.inputs["third-party/licenses/sources.json"] = json.dumps(self.recipe).encode()
        for name, data in self.inputs.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "fixture source")
        self.head = self.git("rev-parse", "HEAD").decode().strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        self.receipt = self.base / "receipt"
        self.dist = self.receipt / "work/dist"
        self.dist.mkdir(parents=True)
        (self.receipt / "artifacts").mkdir()
        self.ledger = self.receipt / "artifacts/release-artifacts.sha256"
        self.hashes = {}
        for name in PACKAGE.ARTIFACTS:
            data = (b"\x7fELFobserver" if name == "p11scope" else
                    b"\x7fELFmusl-helper" if name.endswith("-musl") else b"\x7fELFglibc-helper")
            (self.dist / name).write_bytes(data)
            (self.dist / name).chmod(0o600)
            self.hashes[name] = digest(data)
        self.ledger.write_text("".join(f"{self.hashes[name]}  {name}\n" for name in sorted(self.hashes)))
        (self.receipt / "status").write_text("0\n")
        self.facts = (
            f"head\t{self.head}\ntree\t{self.tree}\n"
            f"release_artifacts_sha256\t{digest(self.ledger.read_bytes())}\n"
            "checker_status\t0\nterminal_status\t0\n"
            "cwd\t/private/host/path\nsecret\tPRIVATE-CAPTURE-CANARY\n"
        )
        (self.receipt / "facts.log").write_text(self.facts)
        (self.receipt / "artifacts/capture.json").write_text("PRIVATE-CAPTURE-CANARY")
        self.notices = self.base / "notices"
        self.notices.mkdir()
        payload = {
            "NOTICES.md": b"fixture dependency notices\n",
            "licenses/dependency.txt": b"dependency license",
            "licenses/upstream/llvm-license.txt": b"upstream license",
            "licenses/musl-1.2.3-source.tar.gz": b"musl source",
            "licenses/musl-1.2.5-source.tar.gz": b"helper musl source",
            "licenses/p11scope-GPL-3.0-or-later.txt": self.inputs["LICENSE"],
        }
        for name in ("GPL-2.0-only", "GPL-2.0-or-later"):
            payload[f"licenses/p11scope-{name}.txt"] = self.inputs[f"LICENSES/{name}.txt"]
        for item in self.recipe["toolchains"]:
            payload[item["files"][0]["payload"]] = b"Rust notice"
        for name, data in payload.items():
            path = self.notices / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.notice_manifest = {
            "schema_version": 1, "head": self.head, "tree": self.tree,
            "cargo_about_version": "0.9.2",
            "files": {name: digest(data) for name, data in payload.items()},
            "recipe_sha256": digest(self.inputs["third-party/licenses/sources.json"]),
            "upstream_inputs": self.recipe["files"], "musl": self.recipe["musl"],
            "native_runtime": self.recipe["native_runtime"],
            "toolchains": [{"name": p["name"], "rustc_verbose_version": p["rustc_verbose_version"]}
                           for p in self.recipe["toolchains"]],
            "graphs": {name: {
                "packages": [{"id": name}],
                "notices": [{"file": "licenses/dependency.txt", "text_sha256": digest(b"dependency license"), "packages": [name]}],
                "original_license_files": [{"file": "licenses/dependency.txt", "sha256": digest(b"dependency license"), "package": name}],
            } for name in ("host", "bpf")},
        }
        self.write_notice_manifest()
        self.source = self.base / "source.tar.gz"
        self.write_source()
        self.output = self.base / "release"

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.DEVNULL)

    def write_notice_manifest(self):
        (self.notices / "notices.json").write_text(json.dumps(self.notice_manifest))

    def write_source(self, altered=None, extra=None):
        entries = []
        content = dict(self.inputs)
        if altered:
            content.update(altered)
        for name, data in content.items():
            entries.append({"path": name, "kind": "file", "mode": "0644",
                            "size": len(data), "sha256": digest(data)})
        archives = [{"path": name, "size": len(data), "sha256": digest(data)}
                    for name, data in self.originals.items()]
        manifest = {"schema_version": 1, "revision": self.head,
                    "source_entries": entries, "archives": archives}
        content.update(self.originals)
        content[".p11scope-source-export.json"] = json.dumps(manifest).encode()
        if extra:
            content.update(extra)
        with tarfile.open(self.source, "w:gz") as archive:
            for name, data in content.items():
                member = tarfile.TarInfo("p11scope-source/" + name)
                member.mode = 0o644
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def package(self, output=None):
        return PACKAGE.package(self.root, self.receipt, self.notices, self.source, output or self.output)

    def refused(self, text):
        with self.assertRaisesRegex((ValueError, OSError), text):
            self.package()
        self.assertFalse(self.output.exists())

    def test_packages_are_deterministic_executable_and_public_only(self):
        self.package()
        second = self.base / "release-again"
        self.package(second)
        expected = {
            "p11scope-0.1.0-x86_64-linux-musl.tar.gz",
            "p11scope-discover-0.1.0-x86_64-linux-gnu.tar.gz",
            "p11scope-discover-0.1.0-x86_64-linux-musl.tar.gz",
            "p11scope-0.1.0-source.tar.gz", "RELEASE.json", "SHA256SUMS",
        }
        self.assertEqual({p.name for p in self.output.iterdir()}, expected)
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        checksums = (self.output / "SHA256SUMS").read_text()
        for name in sorted(expected - {"SHA256SUMS"}):
            self.assertIn(f"{digest((self.output / name).read_bytes())}  {name}\n", checksums)
        for name in sorted(expected):
            if not name.endswith(".tar.gz") or name.endswith("-source.tar.gz"):
                continue
            with tarfile.open(self.output / name) as archive:
                binary_name = "p11scope-discover" if "discover" in name else "p11scope"
                binary = archive.getmember(name[:-7] + "/" + binary_name)
                self.assertEqual(binary.mode, 0o755)
                artifact = ("p11scope-discover-musl" if "discover" in name and "musl" in name else
                            "p11scope-discover-glibc" if "discover" in name else "p11scope")
                self.assertEqual(archive.extractfile(binary).read(), (self.dist / artifact).read_bytes())
                self.assertTrue(any(m.name.endswith("/LICENSE") for m in archive))
                self.assertTrue(any(m.name.endswith("/notices/NOTICES.md") for m in archive))
                for member in archive:
                    if member.isfile():
                        data = archive.extractfile(member).read()
                        self.assertNotIn(b"PRIVATE-CAPTURE-CANARY", data)
                        self.assertNotIn(b"/private/host/path", data)
        self.assertEqual((self.dist / "p11scope").stat().st_mode & 0o777, 0o600)

    def test_failed_or_unfinished_receipt_refuses(self):
        for status in ("1\n", "", "0\n0\n"):
            with self.subTest(status=status):
                (self.receipt / "status").write_text(status)
                self.refused("receipt status")

    def test_duplicate_or_wrong_receipt_identity_refuses(self):
        for value in (self.facts + f"head\t{self.head}\n",
                      self.facts.replace(self.head, "0" * 40),
                      self.facts.replace("terminal_status\t0", "terminal_status\t1")):
            with self.subTest(value=value):
                (self.receipt / "facts.log").write_text(value)
                self.refused("duplicate|revision|terminal")

    def test_tampered_artifact_refuses(self):
        (self.dist / "p11scope").write_bytes(b"different bytes")
        self.refused("digest|checksum|mismatch|does not match")

    def test_symlink_artifact_refuses(self):
        (self.dist / "p11scope").unlink()
        (self.dist / "p11scope").symlink_to(self.dist / "p11scope-discover")
        self.refused("regular|symbolic|symlink")

    def test_notice_change_or_unlisted_file_refuses(self):
        (self.notices / "NOTICES.md").write_text("changed")
        self.refused("notice.*digest")
        self.notice_manifest["files"]["NOTICES.md"] = digest(b"changed")
        self.write_notice_manifest()
        (self.notices / "unexpected.txt").write_text("unlisted private data")
        self.refused("notice.*inventory")

    def test_wrong_notice_revision_refuses(self):
        self.notice_manifest["head"] = "0" * 40
        self.write_notice_manifest()
        self.refused("notice.*revision")

    def test_incomplete_notice_bundle_refuses(self):
        self.notice_manifest.pop("graphs", None)
        self.write_notice_manifest()
        self.refused("notice.*(graph|recipe|complete)")

    def test_missing_required_runtime_notice_refuses(self):
        name = "licenses/rust-1.88/COPYRIGHT-library.html"
        del self.notice_manifest["files"][name]
        (self.notices / name).unlink()
        self.write_notice_manifest()
        self.refused("notice.*required")

    def test_wrong_notice_recipe_refuses(self):
        self.notice_manifest["recipe_sha256"] = "0" * 64
        self.write_notice_manifest()
        self.refused("notice.*recipe")

    def test_source_content_must_match_committed_git_blobs(self):
        self.write_source(altered={"LICENSE": b"forged license"})
        self.refused("source.*(blob|committed)")

    def test_source_extra_path_refuses(self):
        self.write_source(extra={"private.txt": b"unlisted"})
        self.refused("source.*inventory")

    def test_coherently_modified_upstream_archive_refuses(self):
        self.originals["third-party/archives/aya-0.14.0.crate"] = b"modified upstream"
        self.write_source()
        self.refused("source original archive checksum")

    def test_dirty_source_refuses(self):
        (self.root / "LICENSE").write_text("changed tracked source")
        self.refused("clean")

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "preserve"
        sentinel.write_text("keep")
        with self.assertRaisesRegex((ValueError, OSError), "exists"):
            self.package()
        self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
