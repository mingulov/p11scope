#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge one workflow run against its tier selection; write the gate record.

The gate job of each workflow runs this script. It reads the selection
document the select job published (through env, never through
interpolation inside a run: block), lists this run's jobs through the
Actions API, and writes a p11scope/ci-gate/v1 record: the SHA, base,
tier, path classes, and per job one of passed, failed, cancelled or
not-selected with its reason. The gate fails on any failed or cancelled
job, on any required-but-not-run job, on any job the selection does not
know, and on any mismatch between selection and reality. The summary
names every skipped cell, and quick-tier passes are labelled quick-green.
"""

import argparse
import json
import os
import subprocess
import sys

GATE_SCHEMA = "p11scope/ci-gate/v1"
SELECTION_SCHEMA = "p11scope/ci-selection/v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(text, what):
    try:
        value = json.loads(text, object_pairs_hook=unique_object)
    except ValueError:
        raise ValueError(f"invalid {what} JSON")
    require(isinstance(value, dict), f"{what} is not an object")
    return value


def api(endpoint):
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                            text=True, capture_output=True, timeout=60)
    require(result.returncode == 0, f"API query failed: {endpoint}")
    return parse_json(result.stdout, "API response")


def positive(value):
    return type(value) is int and value > 0


def fetch_jobs(repository, run_id, sha):
    """This run's jobs by name, latest attempt only, identity-checked."""
    endpoint = f"repos/{repository}/actions/runs/{run_id}/jobs"
    by_id = {}
    count = None
    page = 1
    while count is None or len(by_id) < count:
        response = api(f"{endpoint}?per_page=100&page={page}")
        total = response.get("total_count")
        require(type(total) is int and total >= 0, "invalid job count")
        require(count is None or total == count,
                "job count changed while paging")
        count = total
        batch = response.get("jobs")
        require(isinstance(batch, list)
                and len(batch) == min(100, count - len(by_id)),
                "incomplete jobs page")
        for job in batch:
            require(isinstance(job, dict), "invalid job")
            identifier = job.get("id")
            require(positive(identifier) and identifier not in by_id,
                    "duplicate or invalid job id")
            require(type(job.get("run_id")) is int
                    and job["run_id"] == run_id
                    and job.get("head_sha") == sha, "stale job identity")
            by_id[identifier] = job
        page += 1
    # After a rerun one name lists twice: judge the latest attempt
    # (greatest id), never splice two attempts into one verdict.
    by_name = {}
    for identifier in sorted(by_id):
        job = by_id[identifier]
        name = job.get("name")
        require(isinstance(name, str) and name, "invalid job name")
        by_name[name] = job
    return by_name


def group_children(by_name, job_id, names, children):
    """API entries belonging to one selection job.

    Contracts names its shards explicitly; matrix jobs group by the
    "id (" prefix (never a bare prefix: public-cli must not swallow
    public-cli-ia32); plain jobs match exactly. Delivery calls group
    their "caller / callee" children by the "job / " prefix.
    """
    if names is not None:
        return {name: by_name[name] for name in names if name in by_name}
    found = {}
    for name, job in by_name.items():
        if name == job_id or name.startswith(job_id + " (") \
                or name.startswith(job_id + " / "):
            found[name] = job
    if children is None:
        # Plain jobs never grow matrix children; delivery calls group
        # their "caller / callee" children here instead.
        bad = sorted(name for name in found if name != job_id
                     and not name.startswith(job_id + " / "))
        require(not bad, f"{job_id} matched unexpected children: "
                         f"{', '.join(bad)}")
    return found


def judge_children(children):
    """Aggregate verdict over one job's API entries.

    Returns (status, detail): passed only when every child completed
    successfully; failed on any failure; cancelled when cancelled wins
    over skipped but no failure; required-but-not-run otherwise.
    """
    if not children:
        return "failed", "required but not run: no such job in this run"
    conclusions = {}
    for name, job in children.items():
        status = job.get("status")
        conclusion = job.get("conclusion")
        if status != "completed":
            conclusions[name] = status
        else:
            conclusions[name] = conclusion
    failed = sorted(name for name, verdict in conclusions.items()
                    if verdict == "failure")
    if failed:
        return "failed", f"failed: {', '.join(failed)}"
    cancelled = sorted(name for name, verdict in conclusions.items()
                       if verdict == "cancelled")
    if cancelled:
        return "cancelled", f"cancelled: {', '.join(cancelled)}"
    pending = sorted(name for name, verdict in conclusions.items()
                     if verdict != "success")
    if pending:
        described = ", ".join(f"{name} ({conclusions[name]})"
                              for name in pending)
        return "failed", f"required but not run: {described}"
    return "passed", None


def judge(selection, by_name):
    """The per-job record plus the run verdict.

    Returns (jobs, unknown, verdict): jobs maps each selection job to
    its status entry, unknown lists API names the selection does not
    know, and verdict is pass only when every selected job passed,
    every conditional job passed or stayed dormant, no deselected job
    ran, and no unknown job exists.
    """
    jobs = {}
    verdict = "pass"
    consumed = set()
    for job_id in sorted(selection["jobs"]):
        if job_id == "gate":
            # The record cannot judge its own writer: the run conclusion
            # judges the gate job, and the release check requires it.
            continue
        entry = selection["jobs"][job_id]
        state = entry["state"]
        children = group_children(by_name, job_id, entry.get("names"),
                                  entry.get("children"))
        consumed.update(children)
        expected = entry.get("children")
        expected_names = entry.get("names")
        if state == "selected" and (
                (expected is not None and len(children) != expected)
                or (expected_names is not None
                    and sorted(children) != sorted(expected_names))):
            # A verdict, not an exception: the record must still be
            # written (a needs-skipped matrix may list fewer entries).
            if expected_names is not None:
                missing = sorted(set(expected_names) - set(children))
                detail = f"required but not run: {', '.join(missing)}"
            else:
                detail = (f"ran {len(children)} children, expected "
                          f"{expected}")
            jobs[job_id] = {
                "status": "failed",
                "detail": detail,
                "children": {name: conclusions_of(job)
                             for name, job in sorted(children.items())},
            }
            verdict = "fail"
            continue
        if state == "not-selected":
            ran = {name: job for name, job in children.items()
                   if job.get("status") == "completed"
                   and job.get("conclusion") not in ("skipped", None)}
            if ran:
                jobs[job_id] = {
                    "status": "failed",
                    "detail": "ran though not selected "
                              f"({entry['reason']}): "
                              f"{', '.join(sorted(ran))}",
                    "children": {name: job.get("conclusion")
                                 for name, job in sorted(children.items())},
                }
                verdict = "fail"
            else:
                jobs[job_id] = {
                    "status": "not-selected",
                    "reason": entry["reason"],
                    "children": {},
                }
            continue
        status, detail = judge_children(children)
        if state == "conditional" and status == "failed" \
                and detail.startswith("required but not run"):
            jobs[job_id] = {
                "status": "not-selected",
                "reason": f"{entry['reason']} (did not trigger)",
                "children": {},
            }
            continue
        record = {"status": status,
                  "children": {name: conclusions_of(job)
                               for name, job in sorted(children.items())}}
        if detail is not None:
            record["detail"] = detail
        jobs[job_id] = record
        if status != "passed":
            verdict = "fail"
    unknown = sorted(name for name in by_name
                     if name not in consumed and name != "gate")
    if unknown:
        verdict = "fail"
    return jobs, unknown, verdict


def conclusions_of(job):
    if job.get("status") != "completed":
        return job.get("status")
    return job.get("conclusion")


def label_for(tier, verdict):
    if verdict != "pass":
        return "red"
    if tier == "quick":
        return "quick-green"
    if tier == "integration":
        return "integration-green"
    if tier == "schedule":
        return "schedule"
    return "full-green"


def summarize(selection, jobs, unknown, verdict, label):
    """The gate summary: tier, verdict, and every skipped cell by name."""
    lines = [f"## gate ({selection['workflow']} {selection['tier']})",
             "",
             f"verdict: {verdict} ({label})",
             f"sha: {selection['sha']}",
             f"base: {selection['base'] or 'unknown'}",
             "path classes: "
             + " ".join(selection["path_classes"] or ["unknown"]),
             ""]
    for job_id in sorted(jobs):
        entry = jobs[job_id]
        status = entry["status"]
        if status == "not-selected":
            lines.append(f"- {job_id}: not-selected ({entry['reason']})")
        elif entry.get("detail"):
            lines.append(f"- {job_id}: {status} ({entry['detail']})")
        else:
            lines.append(f"- {job_id}: {status}")
    for name in unknown:
        lines.append(f"- {name}: unknown job (not in the selection)")
    lines.append("")
    return "\n".join(lines)


def load_selection():
    raw = os.environ.get("GATE_SELECTION", "")
    require(raw, "no selection: the select job did not publish one")
    selection = parse_json(raw, "selection")
    require(selection.get("schema") == SELECTION_SCHEMA,
            "selection has the wrong schema")
    workflow = os.environ.get("P11SCOPE_CI_WORKFLOW", "")
    require(workflow, "P11SCOPE_CI_WORKFLOW is not set")
    require(selection.get("workflow") == workflow,
            "selection is for a different workflow")
    sha = os.environ.get("GITHUB_SHA", "")
    require(sha, "GITHUB_SHA is not set")
    require(selection.get("sha") == sha, "selection is for a different SHA")
    require(isinstance(selection.get("jobs"), dict), "selection has no jobs")
    return selection


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True,
                        help="path for the gate record JSON")
    arguments = parser.parse_args(argv)
    selection = load_selection()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    require(repository, "GITHUB_REPOSITORY is not set")
    try:
        run_id = int(os.environ.get("GITHUB_RUN_ID", ""))
    except ValueError:
        raise ValueError("GITHUB_RUN_ID is not an integer")
    by_name = fetch_jobs(repository, run_id, os.environ["GITHUB_SHA"])
    jobs, unknown, verdict = judge(selection, by_name)
    label = label_for(selection["tier"], verdict)
    record = {
        "schema": GATE_SCHEMA,
        "workflow": selection["workflow"],
        "sha": selection["sha"],
        "base": selection["base"],
        "tier": selection["tier"],
        "bpf_extra": selection["bpf_extra"],
        "path_classes": selection["path_classes"],
        "event": selection["event"],
        "ref": selection["ref"],
        "verdict": verdict,
        "label": label,
        "jobs": jobs,
        "unknown_jobs": unknown,
    }
    with open(arguments.record, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    require(summary, "GITHUB_STEP_SUMMARY is not set")
    with open(summary, "a", encoding="utf-8") as handle:
        handle.write(summarize(selection, jobs, unknown, verdict, label))
    print(f"gate: {verdict} ({label})")
    return 0 if verdict == "pass" else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        print(f"gate-record: {error}", file=sys.stderr)
        sys.exit(1)
