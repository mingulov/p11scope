#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise Kubernetes workflow preparation, ownership and result gates offline.

Docker/kind/kubectl are subprocess stubs. No daemon, cluster, Cargo or capture
is used; the tested shell/Python bodies come from the actual workflow.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/kubernetes-runtime.yml"
NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"


def workflow():
    if not WORKFLOW.is_file():
        raise AssertionError("independent Kubernetes workflow is missing")
    return yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)


def step_body(identifier):
    steps = workflow()["jobs"]["runtime"]["steps"]
    matches = [step for step in steps if step.get("id") == identifier]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one workflow step: {identifier}")
    return matches[0]["run"]


class WorkflowShapeTests(unittest.TestCase):
    def test_manual_host_jobs_have_explicit_k1_k2_budgets(self):
        data = workflow()
        self.assertEqual(set(data["on"]), {"workflow_dispatch", "workflow_call"})
        inputs = data["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["run_k2"]["default"], "false")
        self.assertEqual(inputs["run_k2"]["type"], "boolean")
        self.assertEqual(data["permissions"], {"contents": "read", "actions": "read"})
        job = data["jobs"]["runtime"]
        self.assertEqual(job["runs-on"], "ubuntu-26.04")
        self.assertEqual(job["timeout-minutes"], "${{ matrix.timeout }}")
        matrix = job["strategy"]["matrix"]
        self.assertIn('"cell":"K1","timeout":45', matrix)
        self.assertIn('"cell":"K2","timeout":35', matrix)
        self.assertIn("inputs.run_k2", matrix)
        self.assertNotIn("container", job)
        self.assertNotIn("services", job)
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
        self.assertEqual(data["env"]["KIND_VERSION"], "0.33.0")
        self.assertEqual(data["env"]["KUBECTL_VERSION"], "v1.37.0")
        self.assertEqual(data["env"]["NODE_IMAGE"], NODE)

    def test_artifact_gate_uses_shared_exact_consumer_before_runtime(self):
        steps = workflow()["jobs"]["runtime"]["steps"]
        ids = [step.get("id") for step in steps]
        self.assertLess(ids.index("observer"), ids.index("capture"))
        self.assertLess(ids.index("capture"), ids.index("cleanup"))
        observer = next(step for step in steps if step.get("id") == "observer")
        self.assertEqual(observer["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertIn("scripts/download-runtime-observer.py", observer["run"])
        self.assertEqual(next(step for step in steps if step.get("id") == "cleanup")["if"],
                         "${{ always() && steps.workspace.outcome == 'success' }}")


class OfflineWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="p11-k8s-workflow-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.runtime = self.work / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.fake = self.work / "fake"
        self.fake.mkdir()
        self.env = os.environ.copy()
        self.env.update({
            "RUNTIME_ROOT": str(self.runtime), "CELL": "K1", "NODE_IMAGE": NODE,
            "RUNTIME_TOKEN": "123-1",
            "KIND_VERSION": "0.33.0", "KUBECTL_VERSION": "v1.37.0",
            "KIND_SHA256": "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d",
            "KUBECTL_SHA256": "6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f",
            "GITHUB_ENV": str(self.work / "github-env"),
            "GITHUB_STEP_SUMMARY": str(self.work / "step-summary"),
            "GITHUB_PATH": str(self.work / "github-path"),
            "PATH": f"{self.fake}:{os.environ['PATH']}",
        })
        for key in ("KUBECONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_DEFAULT_PLATFORM"):
            self.env.pop(key, None)
    def run_step(self, identifier, env=None, cwd=None):
        return subprocess.run(["bash", "-euo", "pipefail", "-c", step_body(identifier)],
                              cwd=cwd or ROOT, env=env or self.env,
                              text=True, capture_output=True, timeout=20)

    def test_real_checksum_gate_installs_only_verified_tools(self):
        payload = b"#!/bin/sh\nexit 0\n"
        (self.runtime / "tools").mkdir()
        sudo = self.fake / "sudo"
        sudo.write_text("#!/bin/sh\nexit 0\n")
        sudo.chmod(0o755)
        curl = self.fake / "curl"
        curl.write_text("#!/bin/sh\nwhile [ \"$1\" != --output ]; do shift; done\nprintf '#!/bin/sh\\nexit 0\\n' > \"$2\"\n")
        curl.chmod(0o755)
        self.env["KIND_SHA256"] = "0" * 64
        self.env["KUBECTL_SHA256"] = hashlib.sha256(payload).hexdigest()
        result = self.run_step("tools")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(self.env["GITHUB_PATH"]).exists())
        self.assertFalse(os.access(self.runtime / "tools/kind", os.X_OK))
        self.env["KIND_SHA256"] = hashlib.sha256(payload).hexdigest()
        result = self.run_step("tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.access(self.runtime / "tools/kind", os.X_OK))
        self.assertTrue(os.access(self.runtime / "tools/kubectl", os.X_OK))

    def test_workspace_leaves_shared_consumers_output_absent(self):
        git = self.fake / "git"
        git.write_text("#!/bin/sh\nprintf '%s\\n' " + "1" * 40 + "\n")
        git.chmod(0o755)
        self.env.update({"CANDIDATE_SHA": "1" * 40, "ARTIFACT_RUN_ID": "123",
                         "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                         "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
                         "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"})
        result = self.run_step("workspace")
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(line.split("=", 1) for line in Path(self.env["GITHUB_ENV"]).read_text().splitlines())
        created = Path(fields["RUNTIME_ROOT"])
        self.addCleanup(shutil.rmtree, created)
        self.assertEqual(created.stat().st_mode & 0o777, 0o700)
        self.assertFalse((created / "observer").exists(), "shared downloader creates its own output")

    def test_shared_downloader_failure_or_wrong_output_prevents_observer_activation(self):
        source = self.work / "source"
        (source / "scripts").mkdir(parents=True)
        self.env.update({"ARTIFACT_RUN_ID": "123", "CANDIDATE_SHA": "1" * 40,
                         "GITHUB_REPOSITORY": "owner/repo"})
        consumer = source / "scripts/download-runtime-observer.py"
        consumer.write_text("raise SystemExit('failed FULL package binding')\n")
        result = self.run_step("observer", cwd=source)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(self.env["GITHUB_ENV"]).exists())
        consumer.write_text("print('/foreign/p11scope')\n")
        result = self.run_step("observer", cwd=source)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(self.env["GITHUB_ENV"]).exists())

    def test_shared_downloader_exact_private_executable_is_activated(self):
        source = self.work / "source"
        (source / "scripts").mkdir(parents=True)
        self.env.update({"ARTIFACT_RUN_ID": "123", "CANDIDATE_SHA": "1" * 40,
                         "GITHUB_REPOSITORY": "owner/repo"})
        (source / "scripts/download-runtime-observer.py").write_text('''\
import os, pathlib, sys
args = sys.argv[1:]
assert args[:6] == ["--repository", "owner/repo", "--run-id", "123", "--sha", "1111111111111111111111111111111111111111"]
out = pathlib.Path(args[args.index("--output") + 1])
out.mkdir(mode=0o700, exist_ok=True)
binary = out / "p11scope"
binary.write_text("#!/bin/sh\\nexit 0\\n")
binary.chmod(0o700)
print(binary)
''')
        result = self.run_step("observer", cwd=source)
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = Path(self.env["GITHUB_ENV"]).read_text()
        self.assertIn(f"P11SCOPE_K8S_OBSERVER_BIN={self.runtime}/observer/p11scope\n", environment)


if __name__ == "__main__":
    unittest.main()
