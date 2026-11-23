#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Accept one explicit, complete ci.yml run on the clean package checkout."""

import argparse
from datetime import datetime
import json
import os
import re
import subprocess
import sys
import tempfile


WORKFLOW = ".github/workflows/ci.yml"
# Keep this in step with ci.yml. The registered orchestration suite checks
# the ordinary jobs and both expanded matrices against this contract.
REQUIRED_JOBS = {
    "dedupe", "select", "lint", "audit", "tests", "bpf-noninterference", "scripts", "archive-log",
    *(f"contracts-{index}" for index in range(1, 9)),
    "coverage (rest)", *(f"coverage (contracts:{index}/6)" for index in range(1, 7)),
    "coverage-report", "gate",
}
PRIV_WORKFLOW = ".github/workflows/privileged-tests.yml"
PRIV_FULL_JOB = "pkcs11-check-full"
BPF_WORKFLOW = ".github/workflows/bpf-kernels.yml"
GATE_SCHEMA = "p11scope/ci-gate/v1"
# Release checks require a full-tier gate record from each workflow on the
# exact SHA; quick-tier records never qualify. The artifact name is the
# gate job's upload in each workflow.
GATE_ARTIFACT = {
    WORKFLOW: "ci-gate",
    PRIV_WORKFLOW: "privileged-tests-gate",
    BPF_WORKFLOW: "bpf-kernels-gate",
}
GATE_WORKFLOW_NAME = {
    WORKFLOW: "ci",
    PRIV_WORKFLOW: "privileged-tests",
    BPF_WORKFLOW: "bpf-kernels",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value):
    return type(value) is int and value > 0


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate API JSON key")
        result[key] = value
    return result


def api(endpoint):
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                            text=True, capture_output=True, timeout=30, check=True)
    value = json.loads(result.stdout, object_pairs_hook=unique_object,
                       parse_constant=lambda _: require(False, "invalid API JSON constant"))
    require(isinstance(value, dict), "API response is not an object")
    return value


def git(*arguments):
    return subprocess.check_output(["git", *arguments], text=True, stderr=subprocess.PIPE).strip()


def checkout(sha):
    require(git("rev-parse", "HEAD") == sha, "checkout does not match the selected SHA")
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "checkout is not clean")
    tree = git("rev-parse", "HEAD^{tree}")
    require(re.fullmatch(r"[0-9a-f]{40}", tree), "checkout tree is malformed")
    return tree


def check_run(run, repository, run_id, workflow_id, sha, tree):
    require(type(run.get("id")) is int and run["id"] == run_id, "wrong CI run")
    require(type(run.get("workflow_id")) is int and run["workflow_id"] == workflow_id
            and run.get("path") == WORKFLOW, "wrong CI workflow")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "selected CI run is not completed successfully")
    require(run.get("head_sha") == sha, "CI run is on a different SHA")
    for key in ("repository", "head_repository"):
        value = run.get(key)
        require(isinstance(value, dict) and value.get("full_name") == repository,
                "CI run is from a different repository")
    commit = run.get("head_commit")
    require(isinstance(commit, dict) and commit.get("id") == sha and commit.get("tree_id") == tree,
            "CI run does not match the checkout commit and tree")
    attempt = run.get("run_attempt")
    require(positive(attempt), "invalid CI run attempt")
    return attempt


def check_named_run(run, repository, run_id, workflow_id, expected_path, label, sha, tree):
    require(type(run.get("id")) is int and run["id"] == run_id, f"wrong {label} run")
    require(type(run.get("workflow_id")) is int and run["workflow_id"] == workflow_id
            and run.get("path") == expected_path, f"wrong {label} workflow")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            f"selected {label} run is not completed successfully")
    require(run.get("head_sha") == sha, f"{label} run is on a different SHA")
    for key in ("repository", "head_repository"):
        value = run.get(key)
        require(isinstance(value, dict) and value.get("full_name") == repository,
                f"{label} run is from a different repository")
    commit = run.get("head_commit")
    require(isinstance(commit, dict) and commit.get("id") == sha and commit.get("tree_id") == tree,
            f"{label} run does not match the checkout commit and tree")
    attempt = run.get("run_attempt")
    require(positive(attempt), f"invalid {label} run attempt")
    return attempt


def check_priv_run(run, repository, run_id, workflow_id, sha, tree):
    return check_named_run(run, repository, run_id, workflow_id, PRIV_WORKFLOW, "FULL", sha, tree)


def timestamp(value):
    require(isinstance(value, str), "required CI job has no execution timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def check_gate(job):
    require(job.get("status") == "completed" and job.get("conclusion") == "success",
            "required CI job did not complete successfully")
    require(timestamp(job.get("completed_at")) >= timestamp(job.get("started_at")),
            "invalid CI job execution interval")
    steps = job.get("steps")
    require(isinstance(steps, list) and steps, "required CI job did not execute steps")
    numbers = set()
    ran = False
    for step in steps:
        require(isinstance(step, dict), "invalid CI job step")
        number = step.get("number")
        name = step.get("name")
        require(positive(number) and number not in numbers and isinstance(name, str) and name,
                "invalid or duplicate CI step")
        numbers.add(number)
        require(step.get("status") == "completed" and step.get("conclusion") in ("success", "skipped"),
                "required CI job has an unsuccessful step")
        if step["conclusion"] == "success" and name not in ("Set up job", "Complete job") \
                and not name.startswith("Post "):
            ran = True
    require(ran, "required CI job did not run a gate step")


def check_jobs(repository, run_id, attempt, sha):
    endpoint = f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    jobs = {}
    identifiers = set()
    count = None
    page = 1
    while count is None or len(jobs) < count:
        response = api(f"{endpoint}?per_page=100&page={page}")
        total = response.get("total_count")
        require(type(total) is int and total >= 0, "invalid CI job count")
        require(count is None or total == count, "CI job count changed while paging")
        count = total
        batch = response.get("jobs")
        require(isinstance(batch, list) and len(batch) == min(100, count - len(jobs)),
                "incomplete CI jobs page")
        for job in batch:
            require(isinstance(job, dict), "invalid CI job")
            name = job.get("name")
            identifier = job.get("id")
            require(isinstance(name, str) and name and name not in jobs
                    and positive(identifier) and identifier not in identifiers, "duplicate or invalid CI job")
            require(type(job.get("run_id")) is int and job["run_id"] == run_id
                    and type(job.get("run_attempt")) is int and job["run_attempt"] == attempt
                    and job.get("head_sha") == sha, "stale CI job identity")
            jobs[name] = job
            identifiers.add(identifier)
        page += 1
    require(REQUIRED_JOBS <= jobs.keys(), "required CI jobs are missing")
    for name in sorted(REQUIRED_JOBS):
        check_gate(jobs[name])


def check_full_job(repository, run_id, attempt, sha):
    endpoint = f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    jobs = {}
    identifiers = set()
    count = None
    page = 1
    while count is None or len(jobs) < count:
        response = api(f"{endpoint}?per_page=100&page={page}")
        total = response.get("total_count")
        require(type(total) is int and total >= 0, "invalid FULL job count")
        require(count is None or total == count, "FULL job count changed while paging")
        count = total
        batch = response.get("jobs")
        require(isinstance(batch, list) and len(batch) == min(100, count - len(jobs)),
                "incomplete FULL jobs page")
        for job in batch:
            require(isinstance(job, dict), "invalid FULL job")
            name = job.get("name")
            identifier = job.get("id")
            require(isinstance(name, str) and name and name not in jobs
                    and positive(identifier) and identifier not in identifiers, "duplicate or invalid FULL job")
            require(type(job.get("run_id")) is int and job["run_id"] == run_id
                    and type(job.get("run_attempt")) is int and job["run_attempt"] == attempt
                    and job.get("head_sha") == sha, "stale FULL job identity")
            jobs[name] = job
            identifiers.add(identifier)
        page += 1
    require(PRIV_FULL_JOB in jobs, "FULL job is missing from the run")
    check_gate(jobs[PRIV_FULL_JOB])


def download_gate_record(repository, run_id, workflow_path, directory):
    artifact = GATE_ARTIFACT[workflow_path]
    result = subprocess.run(["gh", "run", "download", str(run_id),
                             "--name", artifact, "--repo", repository,
                             "--dir", directory],
                            text=True, capture_output=True, timeout=120)
    require(result.returncode == 0,
            f"gate record {artifact} is missing from run {run_id}")
    path = os.path.join(directory, artifact, "gate.json")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        raise ValueError(f"gate record {artifact} has no gate.json")
    record = json.loads(text, object_pairs_hook=unique_object,
                        parse_constant=lambda _: require(False, "invalid gate JSON constant"))
    require(isinstance(record, dict), "gate record is not an object")
    return record


def check_gate_record(record, workflow_path, sha):
    require(record.get("schema") == GATE_SCHEMA, "gate record has the wrong schema")
    require(record.get("workflow") == GATE_WORKFLOW_NAME[workflow_path],
            "gate record is for a different workflow")
    require(record.get("sha") == sha, "gate record is on a different SHA")
    require(record.get("tier") in ("full", "integration"),
            "gate record is not a full-tier record")
    require(record.get("verdict") == "pass", "gate record is not passing")
    require(record.get("unknown_jobs") == [], "gate record lists unknown jobs")
    jobs = record.get("jobs")
    require(isinstance(jobs, dict) and jobs, "gate record has no jobs")
    for name, entry in jobs.items():
        require(isinstance(entry, dict), "invalid gate record job")
        require(entry.get("status") in ("passed", "not-selected"),
                f"gate record job {name} did not pass")


def canonical(pattern, description):
    def parse(value):
        if not re.fullmatch(pattern, value):
            raise argparse.ArgumentTypeError(description)
        return value
    return parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True,
                        type=canonical(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.{1,2}$)[A-Za-z0-9_.-]+",
                                       "expected owner/repository"))
    parser.add_argument("--sha", required=True, type=canonical(r"[0-9a-f]{40}", "expected a full commit SHA"))
    parser.add_argument("--accepted-ci-run-id", required=True,
                        type=canonical(r"[1-9][0-9]*", "expected a positive decimal CI run ID"))
    parser.add_argument("--accepted-privileged-run-id", required=True,
                        type=canonical(r"[1-9][0-9]*", "expected a positive decimal privileged-tests run ID"))
    parser.add_argument("--accepted-bpf-run-id", required=True,
                        type=canonical(r"[1-9][0-9]*", "expected a positive decimal bpf-kernels run ID"))
    parser.add_argument("--accepted-pkcs11-full-run-id", default="",
                        type=canonical(r"(|[1-9][0-9]*)", "expected empty or a positive decimal FULL run ID"))
    parser.add_argument("--require-pkcs11-full", action="store_true",
                        help="refuse when no FULL run ID validates (release tags)")
    parser.add_argument("--capture-mode", choices=("full", "p0", "both"), default="both")
    parser.add_argument("--jobs", default="2", type=canonical(r"[1-9]|1[0-6]", "expected jobs 1 through 16"))
    args = parser.parse_args()
    try:
        tree = checkout(args.sha)
        workflow = api(f"repos/{args.repository}/actions/workflows/ci.yml")
        workflow_id = workflow.get("id")
        require(positive(workflow_id) and workflow.get("path") == WORKFLOW, "invalid CI workflow identity")
        run_id = int(args.accepted_ci_run_id)
        run_endpoint = f"repos/{args.repository}/actions/runs/{run_id}"
        attempt = check_run(api(run_endpoint), args.repository, run_id, workflow_id, args.sha, tree)
        check_jobs(args.repository, run_id, attempt, args.sha)
        # Refuse an attempt that was superseded by a rerun during pagination.
        require(check_run(api(run_endpoint), args.repository, run_id, workflow_id, args.sha, tree) == attempt,
                "CI run attempt changed while validating")
        full_id = args.accepted_pkcs11_full_run_id
        if args.require_pkcs11_full and not full_id:
            raise ValueError("a release tag needs a FULL pkcs11-check run ID")
        with tempfile.TemporaryDirectory(prefix="gate-records-") as tmp:
            check_gate_record(download_gate_record(args.repository, run_id, WORKFLOW, tmp),
                              WORKFLOW, args.sha)
            priv_workflow = api(f"repos/{args.repository}/actions/workflows/privileged-tests.yml")
            priv_id = priv_workflow.get("id")
            require(positive(priv_id) and priv_workflow.get("path") == PRIV_WORKFLOW,
                    "invalid privileged-tests workflow identity")
            priv_run_id = int(args.accepted_privileged_run_id)
            priv_endpoint = f"repos/{args.repository}/actions/runs/{priv_run_id}"
            priv_attempt = check_named_run(api(priv_endpoint), args.repository, priv_run_id,
                                           priv_id, PRIV_WORKFLOW, "privileged gate",
                                           args.sha, tree)
            check_gate_record(download_gate_record(args.repository, priv_run_id,
                                                   PRIV_WORKFLOW, tmp),
                              PRIV_WORKFLOW, args.sha)
            require(check_named_run(api(priv_endpoint), args.repository, priv_run_id,
                                    priv_id, PRIV_WORKFLOW, "privileged gate",
                                    args.sha, tree) == priv_attempt,
                    "privileged gate run attempt changed while validating")
            bpf_workflow = api(f"repos/{args.repository}/actions/workflows/bpf-kernels.yml")
            bpf_id = bpf_workflow.get("id")
            require(positive(bpf_id) and bpf_workflow.get("path") == BPF_WORKFLOW,
                    "invalid bpf-kernels workflow identity")
            bpf_run_id = int(args.accepted_bpf_run_id)
            bpf_endpoint = f"repos/{args.repository}/actions/runs/{bpf_run_id}"
            bpf_attempt = check_named_run(api(bpf_endpoint), args.repository, bpf_run_id,
                                          bpf_id, BPF_WORKFLOW, "BPF gate",
                                          args.sha, tree)
            check_gate_record(download_gate_record(args.repository, bpf_run_id,
                                                   BPF_WORKFLOW, tmp),
                              BPF_WORKFLOW, args.sha)
            require(check_named_run(api(bpf_endpoint), args.repository, bpf_run_id,
                                    bpf_id, BPF_WORKFLOW, "BPF gate",
                                    args.sha, tree) == bpf_attempt,
                    "BPF gate run attempt changed while validating")
        if full_id:
            full_run_id = int(full_id)
            full_endpoint = f"repos/{args.repository}/actions/runs/{full_run_id}"
            full_attempt = check_priv_run(api(full_endpoint), args.repository, full_run_id,
                                          priv_id, args.sha, tree)
            check_full_job(args.repository, full_run_id, full_attempt, args.sha)
            require(check_priv_run(api(full_endpoint), args.repository, full_run_id,
                                   priv_id, args.sha, tree) == full_attempt,
                    "FULL run attempt changed while validating")
        modes = ("full", "p0") if args.capture_mode == "both" else (args.capture_mode,)
        matrix = {"include": [
            {"mode": mode, "artifact": "release-preview-public-assets" + ("-p0" if mode == "p0" else ""),
             "public": "public-p0" if mode == "p0" else "public"}
            for mode in modes
        ]}
        print(f"sha={args.sha}\ntree={tree}\njobs={args.jobs}")
        print("matrix=" + json.dumps(matrix, separators=(",", ":")))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"package-preview: refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
