#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the registered dispatcher and exact local reusable-call surface.

The dedupe body is the actual workflow shell, using an owned API transport
and real jq. No CI dispatch, artifact acquisition or runner is invoked.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
CALLS = {
    "packages": ("package-delivery", "package-preview", {
        "accepted_ci_run_id": "${{ inputs.accepted_ci_run_id }}",
        "capture_mode": "${{ inputs.capture_mode }}", "jobs": "${{ inputs.delivery_jobs }}"}),
    "docker": ("docker-delivery", "docker-runtime", {"preview_run_id": "${{ inputs.artifact_run_id }}"}),
    "kubernetes": ("kubernetes-delivery", "kubernetes-runtime", {
        "candidate_sha": "${{ github.sha }}", "artifact_run_id": "${{ inputs.artifact_run_id }}",
        "run_k2": "${{ inputs.run_k2 }}"}),
}


def workflow(name="ci"):
    return yaml.load((ROOT / ".github/workflows" / (name + ".yml")).read_text(), Loader=yaml.BaseLoader)


class DispatchTests(unittest.TestCase):
    def dedupe(self, event="workflow_dispatch", task="checks", prior="none"):
        with tempfile.TemporaryDirectory(prefix="delivery-dispatch-") as directory:
            base = Path(directory)
            tools = base / "tools"
            tools.mkdir()
            gh = tools / "gh"
            gh.write_text("#!" + sys.executable + "\n" + '''
import json, os, subprocess, sys
from pathlib import Path
args=sys.argv[1:]
base=Path(os.environ['STUB_API'])
with (base/'calls').open('a') as out: out.write(json.dumps(args)+'\\n')
assert args[0]=='api'
if os.environ['PRIOR']=='error': sys.exit(1)
endpoint=args[1]
if endpoint.endswith('/runs/42'):
    value={'workflow_id':71}
elif '/workflows/71/runs?' in endpoint:
    rows=[] if os.environ['PRIOR']=='none' else [{'id':1,'status':'completed','conclusion':'success','event':'workflow_dispatch'}]
    value={'workflow_runs':rows}
elif endpoint.endswith('/runs/1/jobs?per_page=100'):
    names=['lint','coverage-report','bpf-noninterference'] if os.environ['PRIOR']=='ordinary' else ['dedupe','package-delivery / validate','package-delivery / package-full']
    value={'jobs':[{'name':name,'conclusion':'success'} for name in names]}
else: sys.exit(91)
query=args[args.index('--jq')+1]
answer=subprocess.run(['jq','-r',query],input=json.dumps(value),text=True,capture_output=True,check=True)
sys.stdout.write(answer.stdout)
''')
            gh.chmod(0o755)
            output, summary = base / "output", base / "summary"
            env = os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "STUB_API": str(base), "PRIOR": prior, "DELIVERY_TASK": task,
                "GITHUB_EVENT_NAME": event, "GITHUB_REPOSITORY": "mingulov/p11scope",
                "GITHUB_RUN_ID": "42", "GITHUB_SHA": "a" * 40,
                "GITHUB_SERVER_URL": "https://github.com", "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary)}
            body = workflow()["jobs"]["dedupe"]["steps"][0]["run"]
            result = subprocess.run(["bash", "-c", body], env=env, cwd=ROOT,
                                    text=True, capture_output=True, timeout=10)
            values = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
            calls = [json.loads(row) for row in (base / "calls").read_text().splitlines()] if (base / "calls").exists() else []
            return result, values, summary.read_text() if summary.exists() else "", calls

    def test_dispatch_defaults_preserve_checks_and_legacy_manual_options(self):
        data = workflow()
        self.assertEqual(set(data["on"]), {"push", "pull_request", "workflow_dispatch"})
        inputs = data["on"]["workflow_dispatch"]["inputs"]
        self.assertIn("delivery_task", inputs)
        self.assertEqual(inputs["delivery_task"]["options"], ["checks", "packages", "docker", "kubernetes"])
        self.assertEqual(inputs["delivery_task"]["default"], "checks")
        self.assertEqual(inputs["release_preview"]["default"], "true")
        self.assertEqual(inputs["privileged_e2e"]["default"], "false")
        self.assertEqual(inputs["capture_mode"]["options"], ["full", "p0", "both"])
        self.assertEqual(inputs["capture_mode"]["default"], "both")
        self.assertEqual(inputs["delivery_jobs"]["default"], "2")
        self.assertEqual(inputs["run_k2"]["type"], "boolean")
        self.assertEqual(inputs["run_k2"]["default"], "false")
        for name in ("accepted_ci_run_id", "artifact_run_id"):
            self.assertEqual(inputs[name]["type"], "string")
        self.assertEqual(data["jobs"]["dedupe"]["env"]["DELIVERY_TASK"], "${{ inputs.delivery_task || 'checks' }}")

    def test_each_delivery_call_is_exact_read_only_and_independent_of_skipped_jobs(self):
        jobs = workflow()["jobs"]
        for task, (identifier, target, supplied) in CALLS.items():
            with self.subTest(task=task):
                self.assertIn(identifier, jobs)
                job = jobs[identifier]
                self.assertEqual(job["if"], "${{ github.event_name == 'workflow_dispatch' && inputs.delivery_task == '" + task + "' }}")
                self.assertEqual(job["name"], identifier)
                self.assertEqual(job["uses"], "./.github/workflows/" + target + ".yml")
                self.assertEqual(job["with"], supplied)
                self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
                self.assertFalse({"needs", "steps", "runs-on", "secrets"} & job.keys())

    def test_reusable_inputs_use_supported_types_and_preserve_direct_dispatch(self):
        expected = {"package-preview": {"accepted_ci_run_id": "string", "capture_mode": "string", "jobs": "string"},
                    "docker-runtime": {"preview_run_id": "string"},
                    "kubernetes-runtime": {"candidate_sha": "string", "artifact_run_id": "string", "run_k2": "boolean"}}
        for name, types in expected.items():
            with self.subTest(name=name):
                data = workflow(name)
                self.assertEqual(set(data["on"]), {"workflow_dispatch", "workflow_call"})
                called = data["on"]["workflow_call"]
                self.assertNotIn("secrets", called)
                self.assertEqual({key: value["type"] for key, value in called["inputs"].items()}, types)
                self.assertEqual(data["permissions"], {"contents": "read", "actions": "read"})
                for job in data["jobs"].values():
                    self.assertEqual(job["runs-on"], "ubuntu-26.04")
                if name == "package-preview":
                    for trigger in ("workflow_call", "workflow_dispatch"):
                        self.assertEqual(data["on"][trigger]["inputs"]["capture_mode"]["default"], "both")
                        self.assertEqual(data["on"][trigger]["inputs"]["jobs"]["default"], "2")

    def test_delivery_selection_skips_checks_without_querying_or_claiming_coverage(self):
        for task in CALLS:
            with self.subTest(task=task):
                result, output, summary, calls = self.dedupe(task=task)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, {"run": "false"})
                self.assertIn(task, summary)
                self.assertNotIn("passed", summary)
                self.assertEqual(calls, [])

    def test_push_pr_and_default_manual_keep_check_selection(self):
        for event, task in (("push", "checks"), ("push", "packages"),
                            ("pull_request", "docker"), ("workflow_dispatch", "checks")):
            with self.subTest(event=event, task=task):
                result, output, _, _ = self.dedupe(event=event, task=task)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, {"run": "true"})

    def test_green_delivery_run_cannot_dedupe_push_checks(self):
        result, output, summary, calls = self.dedupe(event="push", prior="delivery")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, {"run": "true"})
        self.assertNotIn("already passed", summary)
        self.assertEqual(len(calls), 3)

    def test_successful_ordinary_checks_still_dedupe_and_api_errors_run_checks(self):
        result, output, summary, _ = self.dedupe(event="push", prior="ordinary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, {"run": "false"})
        self.assertIn("already passed the full check matrix", summary)
        result, output, _, _ = self.dedupe(event="push", prior="error")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, {"run": "true"})

    def test_legacy_manual_jobs_cannot_run_alongside_delivery(self):
        jobs = workflow()["jobs"]
        for identifier, flag in (("release-preview", "release_preview"), ("privileged-e2e", "privileged_e2e")):
            with self.subTest(identifier=identifier):
                self.assertEqual(jobs[identifier]["if"], "${{ github.event_name == 'workflow_dispatch' && inputs.delivery_task == 'checks' && inputs." + flag + " }}")

    def test_invalid_manual_delivery_choice_fails_without_side_effects(self):
        result, output, _, calls = self.dedupe(task="other")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, {})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
