#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Accept one explicit, complete ci.yml run on the clean package checkout."""

import argparse
from datetime import datetime
import json
import re
import subprocess
import sys


WORKFLOW = ".github/workflows/ci.yml"
# Keep this in step with ci.yml. The registered orchestration suite checks
# the ordinary jobs and both expanded matrices against this contract.
REQUIRED_JOBS = {
    "dedupe", "lint", "audit", "tests", "bpf-noninterference", "scripts", "archive-log",
    *(f"contracts-{index}" for index in range(1, 9)),
    "coverage (rest)", *(f"coverage (contracts:{index}/6)" for index in range(1, 7)),
    "coverage-report",
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
