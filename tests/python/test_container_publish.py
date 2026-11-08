#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Release-asset container publish at the extracted workflow seams.

container-publish.yml downloads the published release tarball, SHA256SUMS
and RELEASE.json for the tag, verifies the checksum and the RELEASE head,
builds the reconciled observer-release Dockerfile with --network=none,
smokes it (including the permanent cell on the built bytes), and publishes
:<version> (and :latest only when the tag is the newest stable) on final
vX.Y.Z tags. Ordinary push CI never holds packages:write; only the push
job does. Tag classification runs against a stub docker; no registry is
touched.
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

    def test_workflow_triggers_on_release_published_and_holds_no_attestation_rights(self):
        self.assertTrue(WORKFLOW.is_file(), "the release publish workflow is missing")
        document = workflow()
        trigger = document.get("on", document.get(True))
        self.assertEqual(set(trigger), {"release", "workflow_dispatch"},
                         "publish runs on release publication (plus a gated tag retry), nothing else")
        self.assertEqual(trigger["release"], {"types": ["published"]})
        self.assertEqual(document["permissions"], {"contents": "read"},
                         "the top level stays read-only; only the push job writes packages")
        self.assertEqual(document.get("concurrency"),
                         {"group": "container-publish", "cancel-in-progress": False},
                         "concurrent publishes must serialize, never cancel")
        self.assertEqual(set(document["jobs"]), {"build", "push"})
        standard = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        pins = {item["uses"] for job in standard["jobs"].values()
                for item in job.get("steps", ()) if "uses" in item}
        text = WORKFLOW.read_text()
        self.assertNotIn("id-token", text, "the publish workflow does not attest")
        self.assertNotIn("attestations", text, "the publish workflow does not attest")
        for name, job in document["jobs"].items():
            self.assertEqual(job["runs-on"], "ubuntu-26.04")
            for item in job["steps"]:
                if "uses" in item:
                    self.assertIn(item["uses"], pins, f"unreviewed action in {name}")
        build_steps = document["jobs"]["build"]["steps"]
        self.assertEqual(build_steps[0]["with"]["fetch-depth"], 0)
        self.assertNotIn("permissions", document["jobs"]["build"],
                         "build must inherit the read-only top-level permissions")
        self.assertEqual(document["jobs"]["push"]["permissions"],
                         {"packages": "write"},
                         "push holds only the registry write; no checkout, no contents")
        for item in document["jobs"]["push"]["steps"]:
            self.assertNotIn("checkout", item.get("uses", ""),
                             "push must not check out: it re-identifies the build tarball")
        self.assertEqual(document["jobs"]["push"]["needs"], "build")
        self.assertNotIn("needs", document["jobs"]["build"])

    def test_build_publishes_from_the_verified_release_tarball(self):
        self.assertTrue(WORKFLOW.is_file(), "the release publish workflow is missing")
        build = workflow()["jobs"]["build"]
        gate = build.get("if", "")
        for marker in ("github.ref_type == 'tag'", "refs/tags/v",
                       "github.repository == 'mingulov/p11scope'"):
            self.assertIn(marker, gate, f"build must gate on {marker}")
        self.assertIn("github.event_name", gate, "build must distinguish release from dispatch")
        bodies = "\n".join(item.get("run", "") for item in build["steps"])
        for marker in ("gh release download", "SHA256SUMS", "RELEASE.json",
                       "sha256sum --check", "deploy/Dockerfile.observer-release",
                       "TARBALL_SHA256", "docker pull",
                       "docker build --network=none"):
            self.assertIn(marker, bodies, f"build must {marker}")
        self.assertIn("GITHUB_SHA", bodies, "build must assert RELEASE head == GITHUB_SHA")
        self.assertNotIn("cargo build", bodies,
                         "the published image holds release bytes, never a rebuild")
        self.assertNotIn("--target x86_64-unknown-linux-musl --bin p11scope", bodies,
                         "the published image holds release bytes, never a rebuild")
        self.assertIn("FROM", bodies)
        self.assertNotIn("docker push", bodies, "only the push job may push")
        self.assertNotIn("ghcr.io", bodies, "only the push job may name the registry")
        for marker in ("git rev-parse HEAD", "git status --porcelain",
                       "verify-container-image.sh --image",
                       "check-cell-results.py",
                       "--require host-exact", "--require container-exact",
                       "--require refusal-pidns", "--require refusal-cap"):
            self.assertIn(marker, bodies, f"build must {marker}")
        for marker in ("docker run", "--version", "doctor", "inventory --system",
                       "softhsm", "p11scope/inventory/v1"):
            self.assertIn(marker, bodies, f"build smoke must {marker}")
        self.assertIn("GITHUB_REF_NAME", bodies, "smoke must assert --version matches the tag")
        uploads = [item for item in build["steps"] if "upload-artifact" in item.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"].get("name"), "container-publish-tarball")
        self.assertEqual(uploads[0]["with"].get("if-no-files-found"), "error")
        self.assertIn("image-id", bodies)
        self.assertIn("is-latest", bodies, "build must record whether the tag is newest stable")

    def test_push_logs_in_from_step_env_and_names_tags_behind_the_final_gate(self):
        self.assertTrue(WORKFLOW.is_file(), "the release publish workflow is missing")
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
                       "ghcr.io/mingulov/p11scope:latest",
                       "buildx imagetools inspect", "is-latest"):
            self.assertIn(marker, bodies, f"push must {marker}")
        self.assertIn("REGISTRY_TOKEN", bodies, "login must use the step env token")
        self.assertIn("REGISTRY_USER", bodies, "login must use the step env user")
        self.assertNotIn("GITHUB_TOKEN", bodies, "login must not use the unset default variable")
        for item in push["steps"]:
            self.assertNotIn("${{", item.get("run", ""),
                             "no expression interpolation inside a run script")
        push_step = step("Push the exact built image on the release tag", "push")
        env = push_step.get("env", {})
        self.assertEqual(env.get("REGISTRY_TOKEN"), "${{ secrets.GITHUB_TOKEN }}")
        self.assertEqual(env.get("REGISTRY_USER"), "${{ github.actor }}")
        self.assertIn("GITHUB_REF_NAME", bodies)
        self.assertIn(r'[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]', bodies)
        self.assertIn(r'[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+- ]]', bodies)
        self.assertIn("not publishing", bodies)
        self.assertIn("not a version tag", bodies)
        load_at = bodies.index("docker load")
        classify_at = bodies.index(r'[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]')
        self.assertLess(load_at, classify_at,
                        "load and image-ID check must precede tag classification")
        uploads = [item for item in push["steps"] if "upload-artifact" in item.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"].get("name"), "container-publish-receipt")
        self.assertEqual(uploads[0]["with"].get("if-no-files-found"), "error")

    def run_push(self, ref, *, version_digest=VERSION_DIGEST, latest_digest=None,
                 is_latest="true", existing_digest=""):
        if latest_digest is None:
            latest_digest = version_digest
        self.assertTrue(WORKFLOW.is_file(), "the release publish workflow is missing")
        push_step = step("Push the exact built image on the release tag", "push")
        body = push_step["run"]
        # The runner substitutes the step env expressions before the shell
        # sees them; the test builds the same environment from the step's
        # own env map instead of injecting a token.
        env_map = dict(push_step.get("env", {}))
        token = env_map.get("REGISTRY_TOKEN", "").replace(
            "${{ secrets.GITHUB_TOKEN }}", "test-token")
        user = env_map.get("REGISTRY_USER", "").replace(
            "${{ github.actor }}", "test-actor")
        fixture = self.base / ref.replace("/", "_")
        incoming = fixture / "publish-in"
        incoming.mkdir(parents=True)
        (incoming / "observer.tar").write_bytes(b"stub-image-bytes")
        (incoming / "image-id.txt").write_text(IMAGE_ID + "\n")
        (incoming / "is-latest.txt").write_text(is_latest + "\n")
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
            "  login)\n"
            "    data=$(cat)\n"
            '    if [ -z "$data" ]; then echo "login: empty password" >&2; exit 1; fi\n'
            "    ;;\n"
            "  push)\n"
            '    case "$1" in\n'
            '      *:latest) digest="$FAKE_DIGEST_LATEST" ;;\n'
            '      *) digest="$FAKE_DIGEST_VERSION" ;;\n'
            "    esac\n"
            '    echo "$1: digest: $digest size: 1234"\n'
            "    ;;\n"
            "  buildx)\n"
            '    image="${@: -1}"\n'
            '    if grep -q "^docker push " "$FAKE_CALLS" 2>/dev/null; then\n'
            '      case "$image" in\n'
            '        *:latest) printf \'%s\\n\' "$FAKE_DIGEST_LATEST" ;;\n'
            '        *) printf \'%s\\n\' "$FAKE_DIGEST_VERSION" ;;\n'
            "      esac\n"
            "      exit 0\n"
            "    fi\n"
            '    if [ -n "${FAKE_EXISTING_DIGEST:-}" ]; then\n'
            '      printf \'%s\\n\' "$FAKE_EXISTING_DIGEST"\n'
            "      exit 0\n"
            "    fi\n"
            '    echo "not found" >&2; exit 1\n'
            "    ;;\n"
            '  *) echo "unexpected docker $cmd" >&2; exit 99 ;;\n'
            "esac\n"
        )
        (tools / "docker").chmod(0o700)
        calls = fixture / "calls.log"
        summary = fixture / "summary.md"
        env = {**self.env, "PATH": f"{tools}:/usr/bin:/bin",
               "GITHUB_REF_NAME": ref, "GITHUB_SHA": "c" * 40,
               "REGISTRY_TOKEN": token, "REGISTRY_USER": user,
               "GITHUB_STEP_SUMMARY": str(summary),
               "FAKE_CALLS": str(calls), "FAKE_IMAGE_ID": IMAGE_ID,
               "FAKE_DIGEST_VERSION": version_digest,
               "FAKE_DIGEST_LATEST": latest_digest,
               "FAKE_EXISTING_DIGEST": existing_digest}
        env.pop("GITHUB_TOKEN", None)
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

    def test_final_tag_skips_latest_when_a_newer_stable_exists(self):
        result, logged, receipt, summary = self.run_push("v0.7.0", is_latest="false")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        pushes = [line for line in logged if line.startswith("docker push ")]
        self.assertEqual(pushes, ["docker push ghcr.io/mingulov/p11scope:0.7.0"])
        text = receipt.read_text()
        self.assertIn("ghcr.io/mingulov/p11scope:0.7.0", text)
        self.assertNotIn(":latest", text)
        self.assertIn(VERSION_DIGEST, text)

    def test_prerelease_tag_logs_in_without_publishing(self):
        result, logged, receipt, summary = self.run_push("v0.7.0-rc1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any(line.startswith("docker load ") for line in logged),
                        "prereleases must still load the tarball")
        self.assertTrue(any(line.startswith("docker inspect ") for line in logged),
                        "prereleases must still check the image ID")
        self.assertTrue(any("docker login" in line for line in logged),
                        "prereleases must still prove the login")
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

    def test_existing_version_tag_refuses_before_pushing(self):
        result, logged, receipt, _ = self.run_push(
            "v0.7.0", existing_digest="sha256:" + "44" * 32)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([line for line in logged if "docker push " in line], [],
                         "an existing tag must be refused before any push")
        self.assertFalse(receipt.exists(), "a refused overwrite must leave no receipt")

    def test_missing_registry_env_fails_the_login(self):
        # Deleting the step env key must fail the test: with no token the
        # stub login (which refuses empty stdin) fails the push body.
        push_step = step("Push the exact built image on the release tag", "push")
        self.assertIn("REGISTRY_TOKEN", push_step.get("env", {}),
                      "the push step must carry its registry token in env")
        result, logged, _, _ = self.run_push("v0.7.0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any("docker login" in line for line in logged))
        # Re-run with the token removed: the same body must now fail at login.
        fixture = self.base / "notoken"
        incoming = fixture / "publish-in"
        incoming.mkdir(parents=True)
        (incoming / "observer.tar").write_bytes(b"stub-image-bytes")
        (incoming / "image-id.txt").write_text(IMAGE_ID + "\n")
        (incoming / "is-latest.txt").write_text("true\n")
        tools = fixture / "bin"
        tools.mkdir()
        (tools / "docker").write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\necho \"docker $*\" >>\"$FAKE_CALLS\"\n"
            'cmd="$1"; shift\ncase "$cmd" in\nload) exit 0 ;;\n'
            'inspect) printf \'%s\\n\' "$FAKE_IMAGE_ID" ;;\ntag) exit 0 ;;\n'
            'login) data=$(cat); if [ -z "$data" ]; then exit 1; fi ;;\n'
            "push) exit 0 ;;\n"
            'buildx) echo "not found" >&2; exit 1 ;;\n*) exit 99 ;;\nesac\n')
        (tools / "docker").chmod(0o700)
        calls = fixture / "calls.log"
        env = {**self.env, "PATH": f"{tools}:/usr/bin:/bin",
               "GITHUB_REF_NAME": "v0.7.0", "GITHUB_SHA": "c" * 40,
               "REGISTRY_TOKEN": "", "REGISTRY_USER": "test-actor",
               "GITHUB_STEP_SUMMARY": str(fixture / "summary.md"),
               "FAKE_CALLS": str(calls), "FAKE_IMAGE_ID": IMAGE_ID}
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c", push_step["run"]],
                                cwd=fixture, env=env, text=True,
                                capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, "empty login stdin must fail")


if __name__ == "__main__":
    unittest.main()
