#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Choose the CI tier and per-job selection for one workflow run.

The select job of each workflow runs this script. It reads the GitHub
context from the environment (the workflow passes dispatch inputs through
env, never through interpolation inside a run: block), diffs the checkout
against the dev merge-base, and writes one `run_<job>` output per gated
job plus the shared `selection` document the gate job consumes.

Fail-closed throughout: an unknown ref class, event, path, tier or Base
setting selects the full tier; any `.github/` or `scripts/ci/` change does
too. A BPF-crate, toolchain or lockfile change on the quick tier adds the
full BPF matrix, every guest kernel and the journal/counter flavours.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NIGHTLY_REF_FILE = ROOT / ".github" / "ci-nightly-ref"

SELECTION_SCHEMA = "p11scope/ci-selection/v1"

# Every kernel matrix in every workflow, single-sourced here. The contract
# tests pin these lists (sums files, YAML references) instead of YAML
# literals, and the workflows render them through dynamic matrices.
CLI_FULL_KERNELS = {
    "public-cli": ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                  "v7.4-rc2"],
    "witness-cli": ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                    "v7.4-rc2"],
    "run-tree": ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1"],
}
CLI_QUICK_KERNELS = ["host", "v6.6.157", "v7.3.1"]
BPF_POSITIVE_KERNELS = ["v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                        "v7.4-rc2"]
BPF_REFUSAL_ROWS = [
    {"kernel": "v6.1.188", "refusal_control": True},
    {"kernel": "v5.15.221", "refusal_control": True,
     "denial_branch": "denied"},
]
LIB_CELL_KERNELS = ["v6.6.157", "v6.12.111"]

# Checked-in extra cell groups for the cells dispatch input. Each group
# adds its jobs on top of the tier selection; unknown names fail the run.
# bpf-matrix is the BPF-diff equivalent (full BPF matrix, every guest
# kernel, the journal/counter flavours); cli-guests widens only the CLI
# kernel lists; the rest add one job family each.
CELL_GROUPS = frozenset({
    "bpf-matrix",
    "cli-guests",
    "coverage",
    "counter-flavor",
    "browser",
    "pkcs11-full",
    "providers-full",
})

# The pinned guest kernel list for the kernels dispatch input: positives
# and CLI guests (the refusal controls always run with their job and are
# not selectable; host always runs and is not selectable either).
PINNED_KERNELS = frozenset([
    kernel for guests in CLI_FULL_KERNELS.values() for kernel in guests
    if kernel != "host"
] + BPF_POSITIVE_KERNELS)

# Path classes. Order matters: the first matching rule classifies the path.
# Anything unmatched is unknown and forces the full tier.
# The BPF crates plus the build scripts that emit BPF objects: a change
# to build.rs or build_support/ can change BPF emission without touching
# the crates, so it joins the BPF class rather than escaping the matrix.
_BPF_PREFIXES = ("crates/ebpf/", "crates/ebpf-common/", "build_support/")
_BPF_FILES = frozenset({"build.rs"})
_TOOLCHAIN_FILES = frozenset({
    ".release-rust-version",
    "rust-toolchain.toml",
    "crates/ebpf/rust-toolchain.toml",
})
# The lockfiles plus the tracked third-party notice inputs, which change
# exactly when the dependency set does.
_LOCK_FILES = frozenset({
    "Cargo.lock",
    "crates/ebpf/Cargo.lock",
})
_LOCK_PREFIXES = ("third-party/",)
_CI_PREFIXES = (".github/", "scripts/ci/")
# Tracked top-level entries that carry no CI, BPF, toolchain or lockfile
# meaning: a change confined to these stays tier-eligible. The selection
# contract test fails when a tracked top-level path is classified nowhere,
# so a new top-level entry forces an explicit decision here.
_KNOWN_TOP_LEVELS = frozenset({
    ".coverage-floor",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "COPYRIGHT",
    "Cargo.toml",
    "LICENSE",
    "LICENSES",
    "README.md",
    "RELEASING.md",
    "REUSE.toml",
    "SECURITY.md",
    "crates",
    "deny-ebpf.toml",
    "deny.toml",
    "deploy",
    "docs",
    "examples",
    "mise.toml",
    "ruff.toml",
    "scripts",
    "spike",
    "src",
    "tests",
})


def classify_path(path):
    """One of bpf, toolchain, lockfile, ci, known or unknown."""
    if path.startswith(_BPF_PREFIXES) or path in _BPF_FILES:
        return "bpf"
    if path in _TOOLCHAIN_FILES:
        return "toolchain"
    if path in _LOCK_FILES or path.startswith(_LOCK_PREFIXES):
        return "lockfile"
    if path.startswith(_CI_PREFIXES):
        return "ci"
    top = path.split("/", 1)[0]
    if top in _KNOWN_TOP_LEVELS:
        return "known"
    return "unknown"


def classify_paths(paths):
    """Sorted classes present in a diff, for the gate record."""
    return sorted({classify_path(path) for path in paths})


def read_base_branch():
    """The dev branch the nightly setting names, or None when unusable."""
    try:
        text = NIGHTLY_REF_FILE.read_text(encoding="utf-8")
    except OSError:
        return None
    lines = [line for line in text.splitlines()
             if line.strip() and not line.startswith("#")]
    if len(lines) != 1:
        return None
    branch = lines[0].strip()
    if not re.fullmatch(r"dev/[A-Za-z0-9][A-Za-z0-9._/-]*", branch):
        return None
    return branch


def git(*arguments):
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed: "
                           f"{result.stderr.strip()}")
    return result.stdout


def changed_paths(event, ref, sha, base_branch):
    """Changed paths for the tier decision, or None when undeterminable.

    Branch pushes and dispatches diff the merge-base with the dev branch,
    so rebases and force-pushes cannot hide branch changes. Pushes to the
    dev branch itself or main diff the pushed range exactly. Any git
    failure returns None and the caller fails closed to the full tier.
    """
    try:
        if event == "push" and base_branch is not None and ref in (
                f"refs/heads/{base_branch}", "refs/heads/main"):
            before = event_before()
            if before is not None:
                out = git("diff", "--name-only", "-z", f"{before}..{sha}")
                return [path for path in out.split("\0") if path]
        if base_branch is None:
            return None
        git("fetch", "--no-tags", "--quiet", "origin", base_branch)
        base = git("merge-base", "HEAD", "FETCH_HEAD").strip()
        out = git("diff", "--name-only", "-z", f"{base}..{sha}")
        # NUL-separated: a fixture name carries spaces, and the non-NUL
        # form would split (and quote) it into unknown fragments.
        return [path for path in out.split("\0") if path]
    except (RuntimeError, subprocess.SubprocessError, OSError,
            ValueError):
        return None


def event_before():
    """The push `before` SHA, or None when absent or unusable."""
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        return None
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    before = event.get("before", "")
    if not re.fullmatch(r"[0-9a-f]{40}", before or ""):
        return None
    if before == "0" * 40:
        return None
    try:
        git("cat-file", "-e", before)
    except (RuntimeError, subprocess.SubprocessError, OSError):
        return None
    return before


def validate_tier(value, event):
    """The dispatch tier, defaulting by event; unknown values fail."""
    if not value:
        return "full"
    if value not in ("quick", "integration", "full"):
        raise ValueError(f"unknown tier: {value!r}")
    if event != "workflow_dispatch":
        raise ValueError(f"tier {value!r} applies to dispatches only, "
                         f"not {event}")
    return value


def parse_list(value, known, kind):
    """Comma-separated validated names; empty fragments dropped."""
    names = [item.strip() for item in value.split(",")]
    names = [item for item in names if item]
    for name in names:
        if name not in known:
            raise ValueError(f"unknown {kind}: {name!r}")
    return frozenset(names)


def parse_cells(value):
    """The cells dispatch input as a group set; unknown groups fail."""
    return parse_list(value, CELL_GROUPS, "cell group")


def parse_kernels(value):
    """The kernels dispatch input as a guest set; unknown kernels fail."""
    return parse_list(value, PINNED_KERNELS, "kernel")


def narrow(job_list, kernels):
    """A kernel list narrowed to the requested guests (None keeps all)."""
    if kernels is None:
        return list(job_list)
    return [kernel for kernel in job_list if kernel in kernels]


# Job universes: every job id in each workflow. The selection contract
# test asserts these equal the YAML job sets exactly.
UNIVERSE = {
    "ci": [
        "dedupe",
        "select",
        "lint",
        "audit",
        "tests",
        "bpf-noninterference",
        "contracts",
        "scripts",
        "archive-log",
        "coverage",
        "coverage-report",
        "quarantine",
        "privileged-e2e",
        "release-preview",
        "package-delivery",
        "docker-delivery",
        "kubernetes-delivery",
        "gate",
    ],
    "privileged-tests": [
        "select",
        "privileged-build",
        "privileged-build-journal",
        "privileged-shard",
        "privileged-summary",
        "privileged-second-flavor",
        "privileged-counter-flavor",
        "privileged-btrfs",
        "privileged-overlay",
        "release-build",
        "system-scale",
        "public-cli",
        "public-cli-ia32",
        "legacy32-shape",
        "root-integration",
        "witness-cli",
        "run-tree",
        "browser-cells",
        "container-image",
        "pkcs11-check-smoke",
        "pkcs11-check-full",
        "pkcs11-check-providers",
        "pkcs11-check-providers-full",
        "gate",
    ],
    "bpf-kernels": [
        "select",
        "kvm-probe",
        "bpf-load-build",
        "bpf-load-kernels",
        "bpf-load-gate1-build",
        "bpf-load-gate1-kernels",
        "lib-cells-kernels",
        "bpf-load-host",
        "gate",
    ],
}

# Static matrix children per job, for the gate's count check. Dynamic
# kernel matrices report their emitted length instead; contracts names
# its shards explicitly in the selection document.
STATIC_CHILDREN = {
    "privileged-shard": 8,
    "coverage": 7,
    "contracts-shards": 8,
    "pkcs11-check-providers": 3,
    "pkcs11-check-providers-full": 2,
}

# Jobs whose YAML carries `needs.select.outputs.run_<job> == 'true'`.
# Mechanism jobs (select, gate), the always-first dedupe, the
# failure-driven quarantine and the delivery calls (pinned independent of
# every check job) carry no select predicate.
GATED = {
    "ci": [
        "lint",
        "audit",
        "tests",
        "bpf-noninterference",
        "contracts",
        "scripts",
        "archive-log",
        "coverage",
        "coverage-report",
        "privileged-e2e",
        "release-preview",
    ],
    "privileged-tests": [
        "privileged-build",
        "privileged-build-journal",
        "privileged-shard",
        "privileged-summary",
        "privileged-second-flavor",
        "privileged-counter-flavor",
        "privileged-btrfs",
        "privileged-overlay",
        "release-build",
        "system-scale",
        "public-cli",
        "public-cli-ia32",
        "legacy32-shape",
        "root-integration",
        "witness-cli",
        "run-tree",
        "browser-cells",
        "container-image",
        "pkcs11-check-smoke",
        "pkcs11-check-full",
        "pkcs11-check-providers",
        "pkcs11-check-providers-full",
    ],
    "bpf-kernels": [
        "kvm-probe",
        "bpf-load-build",
        "bpf-load-kernels",
        "bpf-load-gate1-build",
        "bpf-load-gate1-kernels",
        "lib-cells-kernels",
        "bpf-load-host",
    ],
}


def output_name(job):
    """The run_<job> output name for a job id."""
    return "run_" + job.replace("-", "_")


def decide_tier(event, ref, tier_input, classes):
    """(tier, bpf_extra): the tier for this run.

    tier_input is the validated dispatch tier (quick, integration or
    full). Pushes to development branches run the quick tier unless the
    diff touches CI, an unknown path, or nothing determinable; BPF,
    toolchain and lockfile classes add the BPF set. Everything else,
    including every pull request and schedule, runs the full tier.
    """
    if event == "schedule":
        return "schedule", False
    if classes is None or "ci" in classes or "unknown" in classes:
        return "full", True
    if event == "workflow_dispatch":
        return tier_input, tier_input != "quick"
    if event == "push" and (ref.startswith("refs/heads/test/")
                            or ref.startswith("refs/heads/task/")):
        extra = bool({"bpf", "toolchain", "lockfile"} & set(classes))
        return "quick", extra
    return "full", True


def _selected(jobs):
    return {job: ("selected", None) for job in jobs}


def _deselected(jobs, reason):
    return {job: ("not-selected", reason) for job in jobs}


def select_ci(tier, bpf_extra, event, delivery_task, dedupe_run,
              release_preview, privileged_e2e, cells=frozenset()):
    """Per-job (state, reason) for ci.yml."""
    ordinary = ["lint", "audit", "tests", "contracts", "scripts"]
    jobs = {"dedupe": ("selected", None), "select": ("selected", None)}
    if delivery_task != "checks":
        jobs.update(_deselected(
            ordinary + ["bpf-noninterference", "archive-log", "coverage",
                        "coverage-report", "quarantine", "privileged-e2e",
                        "release-preview"],
            f"manual delivery task '{delivery_task}' selected"))
        for task, job in (("packages", "package-delivery"),
                          ("docker", "docker-delivery"),
                          ("kubernetes", "kubernetes-delivery")):
            if task == delivery_task:
                jobs[job] = ("selected", None)
            else:
                jobs[job] = ("not-selected",
                             f"manual delivery task '{delivery_task}' selected")
        return jobs
    for task, job in (("packages", "package-delivery"),
                      ("docker", "docker-delivery"),
                      ("kubernetes", "kubernetes-delivery")):
        jobs[job] = ("not-selected", "manual delivery runs on dispatch only")
    if not dedupe_run:
        jobs.update(_deselected(
            ordinary + ["bpf-noninterference", "archive-log", "coverage",
                        "coverage-report", "quarantine"],
            "deduped by an earlier covering run"))
    else:
        jobs.update(_selected(ordinary))
        if tier == "quick" and not bpf_extra and "bpf-matrix" not in cells:
            jobs["bpf-noninterference"] = (
                "not-selected",
                "quick tier without BPF, toolchain or lockfile changes")
        else:
            jobs["bpf-noninterference"] = ("selected", None)
        jobs["archive-log"] = ("conditional", "archives selected check logs")
        if tier == "quick" and "coverage" not in cells:
            jobs["coverage"] = ("not-selected",
                                "coverage runs on the full tier only")
            jobs["coverage-report"] = ("not-selected",
                                       "coverage runs on the full tier only")
        else:
            jobs["coverage"] = ("selected", None)
            jobs["coverage-report"] = ("selected", None)
        jobs["quarantine"] = ("conditional", "quarantines failed checks only")
    if event == "workflow_dispatch" and privileged_e2e:
        jobs["privileged-e2e"] = ("selected", None)
    else:
        jobs["privileged-e2e"] = (
            "not-selected", "privileged-e2e runs on dispatch with its flag")
    if event == "workflow_dispatch" and release_preview and tier != "quick":
        jobs["release-preview"] = ("selected", None)
    else:
        jobs["release-preview"] = (
            "not-selected", "release-preview runs on full-tier dispatch")
    return jobs


def select_privileged(tier, bpf_extra, event, pkcs11_full,
                      cells=frozenset()):
    """Per-job (state, reason) for privileged-tests.yml."""
    jobs = {"select": ("selected", None)}
    if event == "schedule":
        jobs.update(_deselected(
            [job for job in UNIVERSE["privileged-tests"] if job != "select"],
            "the schedule runs release-build plus the FULL suites only"))
        jobs["release-build"] = ("selected", None)
        jobs["pkcs11-check-full"] = ("selected", None)
        jobs["pkcs11-check-providers-full"] = ("selected", None)
        return jobs
    quick_only = tier == "quick" and not bpf_extra \
        and "bpf-matrix" not in cells and "counter-flavor" not in cells
    jobs.update(_selected([
        "privileged-build",
        "privileged-shard",
        "privileged-summary",
        "privileged-btrfs",
        "privileged-overlay",
        "release-build",
        "system-scale",
        "public-cli",
        "public-cli-ia32",
        "legacy32-shape",
        "root-integration",
        "witness-cli",
        "run-tree",
        "pkcs11-check-smoke",
        "pkcs11-check-providers",
    ]))
    if quick_only:
        jobs.update(_deselected(
            ["privileged-build-journal", "privileged-second-flavor",
             "privileged-counter-flavor"],
            "quick tier without BPF, toolchain or lockfile changes"))
    else:
        jobs.update(_selected(["privileged-build-journal",
                               "privileged-second-flavor",
                               "privileged-counter-flavor"]))
    if tier == "quick" and "browser" not in cells:
        jobs["browser-cells"] = ("not-selected", "not in the quick tier")
    else:
        jobs["browser-cells"] = ("selected", None)
    if tier == "quick":
        jobs["container-image"] = ("not-selected", "not in the quick tier")
    else:
        jobs["container-image"] = ("selected", None)
    if tier == "integration" or pkcs11_full or "pkcs11-full" in cells:
        jobs["pkcs11-check-full"] = ("selected", None)
    else:
        jobs["pkcs11-check-full"] = (
            "not-selected",
            "FULL suites run on schedule, dispatch with the flag, "
            "or the integration tier")
    if tier == "integration" or pkcs11_full or "providers-full" in cells:
        jobs["pkcs11-check-providers-full"] = ("selected", None)
    else:
        jobs["pkcs11-check-providers-full"] = (
            "not-selected",
            "FULL suites run on schedule, dispatch with the flag, "
            "or the integration tier")
    return jobs


def select_bpf(tier, bpf_extra, cells=frozenset(), kernels=None):
    """Per-job (state, reason) for bpf-kernels.yml."""
    jobs = {"select": ("selected", None)}
    matrix = tier != "quick" or bpf_extra or "bpf-matrix" in cells
    jobs["bpf-load-build"] = ("selected", None)
    jobs["bpf-load-host"] = ("selected", None)
    if not matrix:
        jobs.update(_deselected(
            ["kvm-probe", "bpf-load-kernels", "bpf-load-gate1-build",
             "bpf-load-gate1-kernels", "lib-cells-kernels"],
            "quick tier without BPF, toolchain or lockfile changes"))
        return jobs
    narrowed = {
        "bpf-load-kernels": narrow(BPF_POSITIVE_KERNELS, kernels),
        "bpf-load-gate1-kernels": narrow(BPF_POSITIVE_KERNELS, kernels),
        "lib-cells-kernels": narrow(LIB_CELL_KERNELS, kernels),
    }
    picked = {job for job, guests in narrowed.items() if guests}
    for job, guests in narrowed.items():
        if guests:
            jobs[job] = ("selected", None)
        else:
            jobs[job] = ("not-selected",
                         "none of the requested kernels are in its list")
    if "bpf-load-gate1-kernels" in picked:
        jobs["bpf-load-gate1-build"] = ("selected", None)
    else:
        jobs["bpf-load-gate1-build"] = (
            "not-selected", "its gate-1 matrix selected no kernel")
    if picked:
        jobs["kvm-probe"] = ("selected", None)
    else:
        jobs["kvm-probe"] = (
            "not-selected", "no guest matrix selected a kernel")
    return jobs


def cli_kernels(tier, bpf_extra, cells=frozenset(), kernels=None):
    """Guest kernel lists per CLI job for this tier and narrowing."""
    if tier == "quick" and not bpf_extra and "bpf-matrix" not in cells \
            and "cli-guests" not in cells:
        base = {job: list(CLI_QUICK_KERNELS) for job in CLI_FULL_KERNELS}
    else:
        base = {job: list(guests)
                for job, guests in CLI_FULL_KERNELS.items()}
    # Host always runs; guests narrow to the requested set (a CLI job
    # whose guests narrow away still runs its host leg).
    return {job: ["host"] + [kernel for kernel in guests
                             if kernel != "host"
                             and (kernels is None or kernel in kernels)]
            for job, guests in base.items()}


def bpf_matrices(kernels=None):
    """The BPF matrices: narrowed positives plus the refusal controls,
    which always run with their job."""
    positives = narrow(BPF_POSITIVE_KERNELS, kernels)
    return {
        "matrix_bpf_load": {"kernel": positives,
                            "include": [dict(row) for row in BPF_REFUSAL_ROWS]},
        "matrix_bpf_gate1": {"kernel": positives},
        "matrix_lib_cells": {"kernel": narrow(LIB_CELL_KERNELS, kernels)},
    }


def build_selection(workflow, event, ref, sha, tier_input, classes,
                    base_branch, delivery_task="checks", dedupe_run=True,
                    release_preview=False, privileged_e2e=False,
                    pkcs11_full=False, cells=frozenset(), kernels=None):
    """The selection document plus flattened outputs for one run."""
    if workflow not in UNIVERSE:
        raise ValueError(f"unknown workflow: {workflow!r}")
    tier, bpf_extra = decide_tier(event, ref, tier_input, classes)
    if workflow == "ci":
        states = select_ci(tier, bpf_extra, event, delivery_task,
                           dedupe_run, release_preview, privileged_e2e,
                           cells)
    elif workflow == "privileged-tests":
        states = select_privileged(tier, bpf_extra, event, pkcs11_full,
                                   cells)
    else:
        states = select_bpf(tier, bpf_extra, cells, kernels)
    # The gate always runs (needs all, if: always); the record excludes
    # its own writer, and the run conclusion judges it instead.
    states["gate"] = ("selected", None)
    cli = cli_kernels(tier, bpf_extra, cells, kernels)
    matrices = {f"matrix_{job.replace('-', '_')}": {"kernel": cli[job]}
                for job in CLI_FULL_KERNELS}
    bpf = bpf_matrices(kernels)
    matrices.update(bpf)
    children = {}
    for job in CLI_FULL_KERNELS:
        children[job] = len(cli[job])
    children["bpf-load-kernels"] = (len(bpf["matrix_bpf_load"]["kernel"])
                                    + len(BPF_REFUSAL_ROWS))
    children["bpf-load-gate1-kernels"] = len(bpf["matrix_bpf_gate1"]["kernel"])
    children["lib-cells-kernels"] = len(bpf["matrix_lib_cells"]["kernel"])
    children.update({job: count for job, count in STATIC_CHILDREN.items()
                     if job != "contracts-shards"})
    names = {"contracts": [f"contracts-{index + 1}" for index in
                           range(STATIC_CHILDREN["contracts-shards"])]}
    jobs = {}
    for job in UNIVERSE[workflow]:
        state, reason = states[job]
        jobs[job] = {"state": state, "reason": reason,
                     "children": children.get(job),
                     "names": names.get(job)}
    return {
        "schema": SELECTION_SCHEMA,
        "workflow": workflow,
        "event": event,
        "ref": ref,
        "sha": sha,
        "base": base_branch,
        "tier": tier,
        "bpf_extra": bpf_extra,
        "path_classes": sorted(classes) if classes is not None else None,
        "cells": sorted(cells),
        "kernels": sorted(kernels) if kernels is not None else None,
        "jobs": jobs,
    }, matrices


def write_outputs(selection, matrices):
    """Append every select output to GITHUB_OUTPUT."""
    path = os.environ.get("GITHUB_OUTPUT", "")
    if not path:
        raise ValueError("GITHUB_OUTPUT is not set")
    workflow = selection["workflow"]
    lines = [
        f"tier={selection['tier']}",
        f"base={selection['base'] or ''}",
        "path_classes=" + " ".join(selection["path_classes"] or []),
    ]
    for job in GATED[workflow]:
        state = selection["jobs"][job]["state"]
        # Conditional jobs (archive-log) run under their own fuller
        # condition; the predicate only deselects them with the rest.
        lines.append(f"{output_name(job)}="
                     f"{'false' if state == 'not-selected' else 'true'}")
    for name, matrix in sorted(matrices.items()):
        lines.append(f"{name}={json.dumps(matrix, separators=(',', ':'))}")
    lines.append(f"selection={json.dumps(selection, separators=(',', ':'))}")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("".join(f"{line}\n" for line in lines))


def main():
    workflow = os.environ.get("P11SCOPE_CI_WORKFLOW", "")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    ref = os.environ.get("GITHUB_REF", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if not workflow or not event or not ref or not sha:
        raise ValueError("P11SCOPE_CI_WORKFLOW, GITHUB_EVENT_NAME, "
                         "GITHUB_REF and GITHUB_SHA must all be set")
    tier_input = validate_tier(os.environ.get("P11SCOPE_CI_TIER", ""), event)
    cells = parse_cells(os.environ.get("P11SCOPE_CI_CELLS", ""))
    kernels_value = os.environ.get("P11SCOPE_CI_KERNELS", "")
    kernels = parse_kernels(kernels_value) if kernels_value.strip(", ") else None
    if event != "workflow_dispatch" and (cells or kernels is not None):
        raise ValueError("cells and kernels apply to dispatches only, "
                         f"not {event}")
    base_branch = read_base_branch()
    raw = changed_paths(event, ref, sha, base_branch)
    classes = None if raw is None else classify_paths(raw)
    delivery_task = os.environ.get("P11SCOPE_CI_DELIVERY_TASK", "checks")
    if delivery_task not in ("checks", "packages", "docker", "kubernetes"):
        raise ValueError(f"unknown delivery task: {delivery_task!r}")
    dedupe_run = os.environ.get("P11SCOPE_CI_DEDUPE_RUN", "true") == "true"
    release_preview = os.environ.get("P11SCOPE_CI_RELEASE_PREVIEW", "") == "true"
    privileged_e2e = os.environ.get("P11SCOPE_CI_PRIVILEGED_E2E", "") == "true"
    pkcs11_full = os.environ.get("P11SCOPE_CI_PKCS11_FULL", "") == "true"
    selection, matrices = build_selection(
        workflow, event, ref, sha, tier_input, classes, base_branch,
        delivery_task=delivery_task, dedupe_run=dedupe_run,
        release_preview=release_preview, privileged_e2e=privileged_e2e,
        pkcs11_full=pkcs11_full, cells=cells, kernels=kernels)
    write_outputs(selection, matrices)
    print(f"tier={selection['tier']} bpf_extra={selection['bpf_extra']} "
          f"classes={' '.join(selection['path_classes'] or ['unknown'])}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(f"select-cells: {error}", file=sys.stderr)
        sys.exit(1)

