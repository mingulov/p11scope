#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tag-only container publish at the extracted workflow seams.

container-publish.yml rebuilds the observer image from the tag bytes with
the pinned FULL musl recipe, smokes it, and publishes :<version> and
:latest only on final vX.Y.Z tags. Ordinary push CI never holds
packages:write; only this tag-triggered workflow does, scoped to its push
job. The tag classification (final publishes, prerelease skips, anything
else refuses) runs against a stub docker; no registry is touched.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/container-publish.yml"
IMAGE_ID = "sha256:" + "ab12" * 16
VERSION_DIGEST = "sha256:" + "11" * 32


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def step(name, job):
    return next(item for item in workflow()["jobs"][job]["steps"] if item.get("name") == name)


class ContainerPublishTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope-container-publish-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.env = {key: value for key, value in os.environ.items()}
        self.env["PATH"] = os.defpath

    def test_workflow_triggers_only_on_tags_and_holds_no_attestation_rights(self):
        self.assertTrue(WORKFLOW.is_file(), "the tag-only publish workflow is missing")
        document = workflow()
        trigger = document.get("on", document.get(True))
        self.assertEqual(set(trigger), {"push", "workflow_dispatch"},
                         "publish runs on tag push (plus a gated manual retry), nothing else")
        self.assertEqual(trigger["push"], {"tags": ["v*"]})
        self.assertEqual(document["permissions"], {"contents": "read"},
                         "the top level stays read-only; only the push job writes packages")
        self.assertEqual(set(document["jobs"]), {"build", "push"})
        standard = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        pins = {item["uses"] for job in standard["jobs"].values()
                for item in job.get("steps", ()) if "uses" in item}
        text = WORKFLOW.read_text()
        self.assertNotIn("id-token", text, "the publish workflow does not attest")
        self.assertNotIn("attestations", text, "the publish workflow does not attest")
        for name, job in document["jobs"].items():
            self.assertEqual(job["runs-on"], "ubuntu-26.04")
            self.assertEqual(job["steps"][0]["with"]["fetch-depth"], 0)
            for item in job["steps"]:
                if "uses" in item:
                    self.assertIn(item["uses"], pins, f"unreviewed action in {name}")
        self.assertNotIn("permissions", document["jobs"]["build"],
                         "build must inherit the read-only top-level permissions")
        self.assertEqual(document["jobs"]["push"]["permissions"],
                         {"contents": "read", "packages": "write"})
        self.assertEqual(document["jobs"]["push"]["needs"], "build")
        self.assertNotIn("needs", document["jobs"]["build"])

    def test_build_rebuilds_the_pinned_full_image_and_smokes_it(self):
        self.assertTrue(WORKFLOW.is_file(), "the tag-only publish workflow is missing")
        build = workflow()["jobs"]["build"]
        gate = build.get("if", "")
        for marker in ("github.ref_type == 'tag'", "refs/tags/v",
                       "github.repository == 'mingulov/p11scope'"):
            self.assertIn(marker, gate, f"build must gate on {marker}")
        bodies = "\n".join(item.get("run", "") for item in build["steps"])
        for marker in ("--target x86_64-unknown-linux-musl", "--bin p11scope",
                       "static-pie linked",
                       "deploy/Dockerfile.observer",
                       "docker pull",
                       "docker build --network=none"):
            self.assertIn(marker, bodies, f"build must {marker}")
        self.assertNotIn("--no-default-features", bodies,
                         "the published image holds the FULL binary, never P0 bytes")
        for marker in ('"$GITHUB_WORKSPACE/LICENSE"', '"$GITHUB_WORKSPACE/LICENSES"'):
            self.assertIn(marker, bodies, f"build staging must {marker}")
        self.assertIn("FROM", bodies)
        self.assertNotIn("docker push", bodies, "only the push job may push")
        self.assertNotIn("ghcr.io", bodies, "only the push job may name the registry")
        for marker in ("docker run", "--version", "doctor", "inventory --system",
                       "softhsm", "p11scope/inventory/v1"):
            self.assertIn(marker, bodies, f"build smoke must {marker}")
        uploads = [item for item in build["steps"] if "upload-artifact" in item.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"].get("name"), "container-publish-tarball")
        self.assertEqual(uploads[0]["with"].get("if-no-files-found"), "error")
        self.assertIn("image-id", bodies)

    def test_push_names_both_tags_only_behind_the_final_gate(self):
        self.assertTrue(WORKFLOW.is_file(), "the tag-only publish workflow is missing")
        push = workflow()["jobs"]["push"]
        gate = push.get("if", "")
        for marker in ("github.ref_type == 'tag'", "refs/tags/v",
                       "github.repository == 'mingulov/p11scope'"):
            self.assertIn(marker, gate, f"push must gate on {marker}")
        downloads = [item for item in push["steps"] if "download-artifact" in item.get("uses", "")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["with"].get("name"), "container-publish-tarball")
        bodies = "\n".join(item.get("run", "") for item in push["steps"])
        for marker in ("docker load", "docker tag", "docker login ghcr.io",
                       "ghcr.io/mingulov/p11scope", "docker push",
                       "ghcr.io/mingulov/p11scope:latest"):
            self.assertIn(marker, bodies, f"push must {marker}")
        # The published version tag is the release tag without its leading v,
        # and only a final X.Y.Z release tag publishes (no release candidates):
        # the job gate admits any v* tag, so this in-step regex is the whole
        # RC guard and is pinned verbatim, with a graceful prerelease skip
        # and a fail-closed refusal for anything that is not a version tag.
        self.assertIn("GITHUB_REF_NAME", bodies)
        self.assertIn(r'[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]', bodies)
        self.assertIn(r'[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+- ]]', bodies)
        self.assertIn("not publishing", bodies)
        self.assertIn("not a version tag", bodies)
        uploads = [item for item in push["steps"] if "upload-artifact" in item.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"].get("name"), "container-publish-receipt")
        self.assertEqual(uploads[0]["with"].get("if-no-files-found"), "error")

    def run_push(self, ref, *, version_digest=VERSION_DIGEST, latest_digest=None):
        # Both tags point at one image, so both pushes report one digest;
        # the mismatch case below overrides latest_digest to prove the
        # equality gate.
        if latest_digest is None:
            latest_digest = version_digest
        self.assertTrue(WORKFLOW.is_file(), "the tag-only publish workflow is missing")
        body = step("Push the exact built image on the release tag", "push")["run"]
        # The runner substitutes this CI expression before the shell sees it.
        body = body.replace("${{ github.actor }}", "test-actor")
        fixture = self.base / ref.replace("/", "_")
        incoming = fixture / "publish-in"
        incoming.mkdir(parents=True)
        (incoming / "observer.tar").write_bytes(b"stub-image-bytes")
        (incoming / "image-id.txt").write_text(IMAGE_ID + "\n")
        tools = fixture / "bin"
        tools.mkdir()
        (tools / "docker").write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'echo "docker $*" >>"$FAKE_CALLS"\n'
            'cmd="$1"; shift\n'
            'case "$cmd" in\n'
            "  load) exit 0 ;;\n"
            '  inspect) printf \'%s\\n\' "$FAKE_IMAGE_ID" ;;\n'
            "  tag) exit 0 ;;\n"
            "  login) cat >/dev/null ;;\n"
            "  push)\n"
            '    case "$1" in\n'
            '      *:latest) digest="$FAKE_DIGEST_LATEST" ;;\n'
            '      *) digest="$FAKE_DIGEST_VERSION" ;;\n'
            "    esac\n"
            '    echo "$1: digest: $digest size: 1234"\n'
            "    ;;\n"
            '  *) echo "unexpected docker $cmd" >&2; exit 99 ;;\n'
            "esac\n"
        )
        (tools / "docker").chmod(0o700)
        calls = fixture / "calls.log"
        summary = fixture / "summary.md"
        env = {**self.env, "PATH": f"{tools}:/usr/bin:/bin",
               "GITHUB_REF_NAME": ref, "GITHUB_SHA": "c" * 40,
               "GITHUB_TOKEN": "test-token",
               "GITHUB_STEP_SUMMARY": str(summary),
               "FAKE_CALLS": str(calls), "FAKE_IMAGE_ID": IMAGE_ID,
               "FAKE_DIGEST_VERSION": version_digest,
               "FAKE_DIGEST_LATEST": latest_digest}
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c", body],
                                cwd=fixture, env=env, text=True,
                                capture_output=True, timeout=30)
        logged = calls.read_text().splitlines() if calls.exists() else []
        receipt = incoming / "receipt.txt"
        return result, logged, receipt, summary

    def test_final_tag_publishes_the_version_and_latest_tags(self):
        result, logged, receipt, summary = self.run_push("v0.7.0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        pushes = [line for line in logged if line.startswith("docker push ")]
        self.assertEqual(pushes, ["docker push ghcr.io/mingulov/p11scope:0.7.0",
                                  "docker push ghcr.io/mingulov/p11scope:latest"])
        text = receipt.read_text()
        self.assertIn("ghcr.io/mingulov/p11scope:0.7.0", text)
        self.assertIn("ghcr.io/mingulov/p11scope:latest", text)
        self.assertIn(VERSION_DIGEST, text)
        self.assertIn("c" * 40, text)
        self.assertIn("published", summary.read_text())

    def test_prerelease_tag_validates_without_publishing(self):
        result, logged, receipt, summary = self.run_push("v0.7.0-rc1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([line for line in logged if "docker push " in line], [])
        self.assertIn("not published", receipt.read_text())
        self.assertIn("not published", summary.read_text())

    def test_non_version_tag_refuses_without_publishing(self):
        result, logged, receipt, _ = self.run_push("vfoo")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([line for line in logged if "docker push " in line], [])
        self.assertFalse(receipt.exists(), "a refused tag must leave no receipt")

    def test_mismatched_push_digests_refuse(self):
        result, logged, receipt, _ = self.run_push("v0.7.0", latest_digest="sha256:" + "33" * 32)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(receipt.exists(), "mismatched digests must leave no receipt")


if __name__ == "__main__":
    unittest.main()
