#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Validate and judge the tracked known-failing test list.

`tests/known-failing.json` is schema `p11scope/known-failing/v1`. A row is
one typed exception owned by one or more named known issues; it is never a
mechanism for declaring an ordinary regression expected. Required fields are
`path`, `test`, `cell`, `issues`, `target`, `runner`, `signature`, `lane`,
`mode`, `reason` and `last_green_sha`; optional fields are `hosts`, `since`,
`evidence` and `invocation`. `issues` is a nonempty unique list of KI-nn ids
(one plan row names two issues). `reason` is the plain human reason;
`last_green_sha` is the newest passing commit as a 40-hex SHA. `signature`
is a nested JSON record of enum-like typed values only, never a log line or
a textual pattern.

Known-issue authority is the typed `p11scope/known-issues/v1` block in the
`## Known limitations in 0.7.2` section of docs/known-limitations.md. Until
that section lands, only an empty list is valid; once
docs/releases/v0.7.2.md exists the typed registry must exist, and rule 2
exact equality governs (zero `test: true` issues means zero rows is valid).

Static validation checks row shape, executable test/cell discovery, suite
registration, issue/row exact equality, reverse runner declarations per
invocation stream (no undeclared workflow cells; row-to-declaration
unification is deferred to 0.7.3), and exact `cell: known-failing`
ignored-test entries. The eleven pre-existing inverted declarations are a
closed legacy baseline until their 0.7.3 migration. Host-limited rows for
hosts without a CI judge (fedora, fedora-sm1) and privileged-lib rows
(the summary job does not count XFAIL yet) are refused.

With `--results`, the checker judges schema
`p11scope/known-failing-results/v1`:

    {
      "schema": "p11scope/known-failing-results/v1",
      "runner": "python-suite",
      "host": "github",
      "complete": true,
      "selection": [
        {"path": "tests/python/test_x.py", "test": "C.test_x", "invocation": []}
      ],
      "results": [
        {"path": "tests/python/test_x.py", "test": "C.test_x", "invocation": [],
         "state": "failed", "signature": {"cell": "X", "branch": "y"}}
      ]
    }

The selection is the producer's executable inventory, recorded before or by
the runner framework itself. Selection and result keys must be nonempty,
unique and exactly one-to-one, and `complete` must be true; therefore
deleting a failing row cannot turn red into green. Empty selections fail
closed. Comparison is recursive type-sensitive JSON equality.

Usage:
  python3 -I scripts/check-known-failing.py [--root DIR] [--list PATH]
  python3 -I scripts/check-known-failing.py [--root DIR] [--list PATH] --results RESULTS.json
"""

import argparse
import ast
import json
import math
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LIST_SCHEMA = "p11scope/known-failing/v1"
ISSUE_SCHEMA = "p11scope/known-issues/v1"
RESULT_SCHEMA = "p11scope/known-failing-results/v1"
ISSUE_HEADING = "## Known limitations in 0.7.2"
ISSUE_MARKER = "<!-- p11scope-known-issues-v1"
TARGETS = {"0.7.3", "0.8.0"}
MODES = {"always", "intermittent"}
HOSTS = {"fedora", "fedora-sm1", "vng", "github"}
BASE_RUNNERS = {"privileged-lib", "python-suite"}
REQUIRED_ROW_FIELDS = {
    "path", "test", "cell", "issues", "target", "runner", "signature",
    "lane", "mode", "reason", "last_green_sha",
}
OPTIONAL_ROW_FIELDS = {"hosts", "since", "evidence", "invocation"}
RESULT_TOP_FIELDS = {"schema", "runner", "host", "complete", "selection", "results"}
RESULT_SELECTION_FIELDS = {"path", "test", "invocation"}
RESULT_ROW_FIELDS = {"path", "test", "invocation", "state", "signature"}
RESULT_STATES = {"passed", "failed", "error", "skipped", "unexpected_success", "not_run", "not_applicable"}
NEUTRAL_STATES = {"skipped", "not_applicable"}
# A row branch naming a bare producer state or scope token accepts any
# failure of that shape (every AssertionError looks like the named issue).
# Rows need a test-raised typed branch instead.
GENERIC_SIGNATURE_BRANCHES = RESULT_STATES | {"class_skip", "module_skip"}
ISSUE_RE = re.compile(r"^KI-[0-9]{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
TYPED_STRING_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:+|-]{0,127}$")
TEXTUAL_SIGNATURE_KEY_TOKENS = {
    "detail", "log", "message", "output", "pattern", "regex", "stderr",
    "stdout", "text",
}

# Closed legacy baselines. They are not typed rows in v0.7.2; a migration
# patch removes a name here and adds its typed row in the same change.
LEGACY_PRIVILEGED_LIB = frozenset({
    "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation",
    "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64",
    "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64",
})
LEGACY_CELL_EXPECTED = frozenset({
    "profile-cgroup", "trace-cgroup", "profile-pid-ia32", "run-ia32",
})
LEGACY_CELL_INTERMITTENT = frozenset({
    "privileged_run_tree_unprearmed_shortlived_descendants_reach_high_coverage",
    "privileged_run_tree_unprearmed_shortlived_never_pause_still_learns",
    "privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves",
    "privileged_run_tree_arming_exhaustion_still_stages_and_counts",
})
PUBLIC_CLI_RUNNER = "cell:scripts/qualify-public-cli.sh"
RUN_TREE_RUNNER = "cell:scripts/ci/run-run-tree.sh"
# Typed records nest at most this deep. Deeper inputs are refused as
# too deep instead of crashing recursive validation or comparison.
MAX_TYPED_DEPTH = 32


class DuplicateKeyError(ValueError):
    pass


def object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError(f"non-strict JSON constant {value}")


class _ParseFailed:
    """Unique strict-JSON parse-failure sentinel (never a valid value)."""

    __slots__ = ()

    def __repr__(self):
        return "PARSE_FAILED"


PARSE_FAILED = _ParseFailed()


def strict_json(text, label):
    """Parse typed JSON, rejecting duplicate keys and non-strict constants.

    Returns (PARSE_FAILED, [problem]) when parsing fails and (value, [])
    when it succeeds — including (None, []) for a valid JSON null, which
    must reach schema validation instead of being mistaken for failure.
    """
    try:
        return json.loads(text, object_pairs_hook=object_no_duplicates,
                          parse_constant=reject_json_constant), []
    except (json.JSONDecodeError, DuplicateKeyError, ValueError, RecursionError) as exc:
        return PARSE_FAILED, [f"{label}: invalid JSON: {exc}"]


def valid_runner(value):
    if not isinstance(value, str):
        return False
    return value in BASE_RUNNERS or (value.startswith("cell:") and len(value) > len("cell:"))


def valid_relative_path(value):
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/") or "\\" in value:
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def valid_invocation(value):
    return (isinstance(value, list)
            and all(isinstance(argument, str) and argument for argument in value))


def typed_string(value):
    return isinstance(value, str) and TYPED_STRING_RE.fullmatch(value) is not None


def textual_signature_key(key):
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    tokens = (token for token in re.split(r"[_\-.]+", camel_split.lower()) if token)
    return any(token in TEXTUAL_SIGNATURE_KEY_TOKENS for token in tokens)


def signature_problems(value, where="signature"):
    if not isinstance(value, dict) or not value:
        return [f"{where} must be a nonempty object of typed fields"]
    problems = []
    stack = [(value, where, 0)]
    while stack:
        node, path, depth = stack.pop()
        if depth > MAX_TYPED_DEPTH:
            problems.append(f"{path} exceeds the maximum typed nesting depth of {MAX_TYPED_DEPTH}")
            continue
        if isinstance(node, dict):
            if not node:
                problems.append(f"{path} must not be an empty object")
                continue
            children = []
            for key, child in node.items():
                if not isinstance(key, str) or not SIGNATURE_KEY_RE.fullmatch(key):
                    problems.append(f"{path}.{key!r} is not a typed snake-case field name")
                    continue
                if textual_signature_key(key):
                    problems.append(f"{path}.{key} is free-text/log matching; use a typed verdict branch or record field")
                children.append((child, f"{path}.{key}", depth + 1))
            stack.extend(reversed(children))
        elif isinstance(node, list):
            for index, child in reversed(list(enumerate(node))):
                stack.append((child, f"{path}[{index}]", depth + 1))
        elif isinstance(node, str):
            if not typed_string(node):
                problems.append(f"{path} must be a stable typed token, not prose, log text or raw output")
        elif isinstance(node, float):
            if not math.isfinite(node):
                problems.append(f"{path} must be a finite JSON number")
        elif node is None or isinstance(node, (int, bool)):
            continue
        else:
            problems.append(f"{path} has a non-JSON value of type {type(node).__name__}")
    return problems


def validate_row(raw, index):
    label = f"row {index}"
    if not isinstance(raw, dict):
        return [f"{label}: row must be an object"], None
    allowed = REQUIRED_ROW_FIELDS | OPTIONAL_ROW_FIELDS
    keys = set(raw)
    missing = sorted(REQUIRED_ROW_FIELDS - keys)
    problems = []
    if missing:
        return [f"{label}: missing required fields: {', '.join(missing)}"], None
    unknown = sorted(keys - allowed)
    if unknown:
        problems.append(f"{label}: unknown fields: {', '.join(unknown)}")
    if not valid_relative_path(raw["path"]):
        problems.append(f"{label}: path must be a clean repository-relative POSIX path")
    if not isinstance(raw["test"], str) or not raw["test"]:
        problems.append(f"{label}: test must be a nonempty exact test or cell id")
    if not typed_string(raw["cell"]):
        problems.append(f"{label}: cell must be a stable typed cell token")
    if isinstance(raw["runner"], str) and raw["runner"].startswith("cell:") and raw["cell"] != raw["test"]:
        problems.append(f"{label}: cell must equal the cell id in test for cell runners")
    issues = raw["issues"]
    if (not isinstance(issues, list) or not issues
            or any(not isinstance(issue, str) or not ISSUE_RE.fullmatch(issue) for issue in issues)
            or len(set(issues)) != len(issues)):
        problems.append(f"{label}: issues must be a nonempty unique list of KI-nn ids")
    if not isinstance(raw["target"], str) or raw["target"] not in TARGETS:
        problems.append(f"{label}: target must be one of {', '.join(sorted(TARGETS))}")
    if not valid_runner(raw["runner"]):
        problems.append(f"{label}: runner is not in the closed runner vocabulary")
    if raw["runner"] == "privileged-lib":
        problems.append(f"{label}: privileged-lib rows are refused until Prove full coverage counts XFAIL rows")
    problems.extend(f"{label}: {problem}" for problem in signature_problems(raw["signature"]))
    if isinstance(raw["signature"], dict) and "branch" not in raw["signature"]:
        problems.append(f"{label}: signature lacks a typed branch")
    if isinstance(raw.get("signature"), dict) and "branch" in raw["signature"] \
            and type(raw["signature"].get("branch")) is not str:
        problems.append(f"{label}: signature branch must be a typed token string")
    if isinstance(raw.get("signature"), dict) and type(raw["signature"].get("branch")) is str \
            and raw["signature"].get("branch") in GENERIC_SIGNATURE_BRANCHES:
        problems.append(f"{label}: signature branch {raw['signature']['branch']!r} is a generic producer state or scope token; "
                        "rows need a test-raised typed branch")
    if isinstance(raw["signature"], dict) and "cell" in raw["signature"] and raw["signature"]["cell"] != raw["cell"]:
        problems.append(f"{label}: signature cell must equal the row cell")
    if not isinstance(raw["lane"], str) or not raw["lane"].strip():
        problems.append(f"{label}: lane must name the lane that owns the fix")
    if not isinstance(raw["mode"], str) or raw["mode"] not in MODES:
        problems.append(f"{label}: mode must be always or intermittent")
    if not isinstance(raw["reason"], str) or not raw["reason"].strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in raw["reason"]):
        problems.append(f"{label}: reason must be nonempty printable plain text")
    if not isinstance(raw["last_green_sha"], str) or not SHA_RE.fullmatch(raw["last_green_sha"]):
        problems.append(f"{label}: last_green_sha must be a 40-hex commit SHA")
    if "hosts" in raw:
        hosts = raw["hosts"]
        if (not isinstance(hosts, list) or not hosts
                or any(not isinstance(host, str) or host not in HOSTS for host in hosts)
                or len(set(hosts)) != len(hosts)):
            problems.append(f"{label}: hosts must be a unique nonempty subset of {', '.join(sorted(HOSTS))}")
    if "hosts" in raw and isinstance(raw["hosts"], list):
        limited = [host for host in raw["hosts"] if host in ("fedora", "fedora-sm1")]
        if limited:
            problems.append(f"{label}: hosts {', '.join(limited)} have no CI judge: host-limited rows are refused until one exists")
        if raw.get("runner") == "python-suite" and "github" not in raw["hosts"]:
            problems.append(f"{label}: python-suite rows without github have no CI judge: python suites are judged only with host github")
    if isinstance(raw.get("runner"), str) and raw["runner"].startswith("cell:"):
        script = raw["runner"][len("cell:"):]
        if isinstance(raw.get("path"), str) and raw["path"] != script and not raw["path"].endswith(".rs"):
            problems.append(f"{label}: cell row path must equal the runner script or the .rs ignored-tests exception: "
                            f"{raw['path']} has no CI judge for {raw['runner']}")
    if "invocation" in raw and not valid_invocation(raw["invocation"]):
        problems.append(f"{label}: invocation must be a list of nonempty argument strings")
    for key in ("since", "evidence"):
        if key in raw and (not isinstance(raw[key], str) or not raw[key].strip()):
            problems.append(f"{label}: {key} must be a nonempty string when present")
    return problems, raw


def row_invocation(row):
    return row.get("invocation", [])


def row_key(row):
    invocation = tuple(row_invocation(row))
    return (row["path"], row["test"], invocation)


def load_list(path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], [f"{path}: missing known-failing list"]
    except (OSError, UnicodeDecodeError) as exc:
        return [], [f"{path}: cannot read known-failing list: {exc}"]
    data, problems = strict_json(text, str(path))
    if data is PARSE_FAILED:
        return [], problems
    if not isinstance(data, dict):
        return [], problems + [f"{path}: top level must be an object"]
    if set(data) != {"schema", "rows"}:
        problems.append(f"{path}: top level must have exactly schema and rows")
    if data.get("schema") != LIST_SCHEMA:
        problems.append(f"{path}: schema must be {LIST_SCHEMA}")
    raw_rows = data.get("rows")
    if not isinstance(raw_rows, list):
        return [], problems + [f"{path}: rows must be a list"]
    rows = []
    for index, raw in enumerate(raw_rows, 1):
        row_problems, row = validate_row(raw, index)
        problems.extend(row_problems)
        if row is not None and not row_problems:
            rows.append(row)
    return rows, problems


def issue_section(text):
    match = re.search(rf"(?m)^{re.escape(ISSUE_HEADING)}\s*$", text)
    if match is None:
        return None
    following = re.search(r"(?m)^## ", text[match.end():])
    end = len(text) if following is None else match.end() + following.start()
    return text[match.end():end]


def load_issue_registry(root):
    path = root / "docs/known-limitations.md"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False, {}, []
    except (OSError, UnicodeDecodeError) as exc:
        return True, {}, [f"known-issue registry: cannot read {path}: {exc}"]
    section = issue_section(text)
    if section is None:
        return False, {}, []
    count = section.count(ISSUE_MARKER)
    if count != 1:
        return True, {}, [f"known-issue registry: {ISSUE_HEADING} must contain exactly one {ISSUE_MARKER} block, found {count}"]
    start = section.index(ISSUE_MARKER) + len(ISSUE_MARKER)
    end = section.find("-->", start)
    if end < 0:
        return True, {}, ["known-issue registry: block is not closed"]
    data, problems = strict_json(section[start:end].strip(), "known-issue registry")
    if data is PARSE_FAILED:
        return True, {}, problems
    if not isinstance(data, dict) or set(data) != {"schema", "issues"}:
        problems.append("known-issue registry: top level must have exactly schema and issues")
        return True, {}, problems
    if data.get("schema") != ISSUE_SCHEMA:
        problems.append(f"known-issue registry: schema must be {ISSUE_SCHEMA}")
    raw_issues = data.get("issues")
    if not isinstance(raw_issues, list):
        problems.append("known-issue registry: issues must be a list")
        return True, {}, problems
    registry = {}
    for index, raw in enumerate(raw_issues, 1):
        if not isinstance(raw, dict) or set(raw) != {"id", "test"}:
            problems.append(f"known-issue registry: issue {index} must have exactly id and test")
            continue
        if not isinstance(raw["id"], str) or not ISSUE_RE.fullmatch(raw["id"]):
            problems.append(f"known-issue registry: issue {index} has a malformed id")
            continue
        if not isinstance(raw["test"], bool):
            problems.append(f"known-issue registry: {raw['id']} test must be a boolean")
            continue
        if raw["id"] in registry:
            problems.append(f"known-issue registry: duplicate issue {raw['id']}")
            continue
        registry[raw["id"]] = raw["test"]
    heading_ids = {
        match.group(1)
        for match in re.finditer(r"(?m)^###\s+(KI-[0-9]{2})(?=\s|:|$)", section)
    }
    missing_sections = sorted(set(registry) - heading_ids)
    unregistered_sections = sorted(heading_ids - set(registry))
    if missing_sections:
        problems.append("known-issue registry entries without a KI section: " + ", ".join(missing_sections))
    if unregistered_sections:
        problems.append("KI sections missing from the typed registry: " + ", ".join(unregistered_sections))
    return True, registry, problems


def python_tests_executable(root, row):
    probe = root / "scripts/typed-python-suite.py"
    suite = root / row["path"]
    if not probe.is_file():
        return False
    command = [sys.executable, "-I", str(probe), "--list", str(suite), *row_invocation(row)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    tests = payload.get("tests")
    return isinstance(tests, list) and row["test"] in tests


def shell_cells_executable(root, row):
    script = root / row["path"]
    if not os.access(script, os.X_OK):
        return False
    try:
        result = subprocess.run([str(script), "--list-cells"], capture_output=True,
                                text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    cells = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return row["test"] in cells


def cargo_list_probe(root, row):
    """Executable Rust test discovery through cargo and libtest --list.

    This probe runs only when a Rust row exists. Integration tests use their
    target stem; root library tests use --lib. Nonstandard crate layouts fail
    closed rather than guessing.
    """
    relative = Path(row["path"])
    if len(relative.parts) == 2 and relative.parts[0] == "tests" and relative.suffix == ".rs":
        target_args = ["--test", relative.stem]
    elif relative.parts and relative.parts[0] == "src":
        target_args = ["--lib"]
    else:
        return False
    toolchain_file = root / ".release-rust-version"
    try:
        toolchain = toolchain_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return False
    cargo_wrapper = root / "scripts/cargo.sh"
    if not os.access(cargo_wrapper, os.X_OK):
        return False
    command = [str(cargo_wrapper), f"+{toolchain}", "test", "--locked", "--offline", "--no-run",
               "--message-format=json", *target_args]
    try:
        built = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if built.returncode != 0:
        return False
    executables = []
    for line in built.stdout.splitlines():
        try:
            artifact = json.loads(line)
        except json.JSONDecodeError:
            continue
        if artifact.get("reason") == "compiler-artifact" and artifact.get("executable"):
            target = artifact.get("target", {})
            if target.get("test"):
                executables.append(artifact["executable"])
    if len(executables) != 1:
        return False
    found = set()
    for ignored in (False, True):
        command = [executables[0], "--list", "--format", "terse"]
        if ignored:
            command.append("--ignored")
        try:
            listed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if listed.returncode == 0:
            found.update(line[: -len(": test")].strip() for line in listed.stdout.splitlines() if line.endswith(": test"))
    return row["test"] in found


def test_exists(root, row):
    try:
        if row["path"].endswith(".py"):
            return python_tests_executable(root, row)
        if row["path"].endswith(".sh"):
            return shell_cells_executable(root, row)
        if row["path"].endswith(".rs"):
            return cargo_list_probe(root, row)
    except (OSError, ValueError):
        return False
    return False


def registry_run_entries(registry_path):
    """The RUN membership list parsed as data, or None when unreadable.

    The suite registry is never executed here: the production runner
    needs module globals (`__file__`) at import time, so executing it
    in a probe namespace crashes on the valid real file. The RUN
    assignment is a plain literal, and every entry is validated
    before any lookup: one malformed entry refuses the whole
    registry. Entries are (nonempty name, args) pairs with string
    arguments.
    """
    try:
        text = registry_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    run_value = None
    run_seen = False
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "RUN" for target in node.targets):
            continue
        run_seen = True
        try:
            run_value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            run_value = None
    if not run_seen or not isinstance(run_value, list):
        return None
    for item in run_value:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            return None
        entry, args = item
        if not isinstance(entry, str) or not entry:
            return None
        if not isinstance(args, (list, tuple)):
            return None
        if not all(isinstance(arg, str) for arg in args):
            return None
    return run_value


def python_suite_registered(root, row):
    if row["runner"] != "python-suite":
        return True
    prefix = "tests/python/"
    if not row["path"].startswith(prefix):
        return False
    entries = registry_run_entries(root / "scripts/run-python-suites.py")
    if entries is None:
        return False
    name = row["path"][len(prefix):]
    invocation = row_invocation(row)
    return any(entry == name and list(args) == invocation for entry, args in entries)


def shell_string_array(text, name):
    match = re.search(rf"(?ms)^{re.escape(name)}=\(\n(.*?)^\)", text)
    if match is None:
        return None
    return {line.strip() for line in match.group(1).splitlines() if line.strip() and not line.strip().startswith("#")}


def validate_privileged_runner(root, rows):
    runner_path = root / "scripts/run-privileged-lib-tests.sh"
    wanted_new = {row["test"] for row in rows if row["runner"] == "privileged-lib"}
    if not runner_path.is_file():
        if wanted_new:
            return ["privileged-lib rows exist but scripts/run-privileged-lib-tests.sh is missing"]
        return []
    try:
        text = runner_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"privileged-lib runner declaration cannot be read: {exc}"]
    legacy_actual = shell_string_array(text, "EXPECTED_FAILURE_TESTS")
    typed_actual = shell_string_array(text, "KNOWN_FAILING_TYPED_TESTS")
    if legacy_actual is None:
        return ["privileged-lib runner declaration cannot be read: no EXPECTED_FAILURE_TESTS array"]
    if typed_actual is None:
        return ["privileged-lib runner declaration cannot be read: no KNOWN_FAILING_TYPED_TESTS array"]
    problems = []
    legacy_missing = sorted(set(LEGACY_PRIVILEGED_LIB) - legacy_actual)
    legacy_extra = sorted(legacy_actual - set(LEGACY_PRIVILEGED_LIB))
    if legacy_missing:
        problems.append("privileged-lib legacy declaration is missing cells: " + ", ".join(legacy_missing))
    if legacy_extra:
        problems.append("privileged-lib legacy declaration has non-legacy cells: " + ", ".join(legacy_extra))
    missing = sorted(wanted_new - typed_actual)
    extra = sorted(typed_actual - wanted_new)
    if missing:
        problems.append("privileged-lib typed runner is missing known-failing rows: " + ", ".join(missing))
    if extra:
        problems.append("privileged-lib typed runner has undeclared known-failing rows: " + ", ".join(extra))
    overlap = sorted(legacy_actual & typed_actual)
    if overlap:
        problems.append("privileged-lib rows cannot use the legacy fixed-string xfail group: " + ", ".join(overlap))
    return problems


def cell_runner_script_present(root, row):
    if not row["runner"].startswith("cell:"):
        return True
    script = row["runner"][len("cell:"):]
    return valid_relative_path(script) and (root / script).is_file()


OPTION_ARITY = {
    "--expected-failure": 1,
    "--intermittent-failure": 1,
    "--allow-nonqualifying": 1,
    "--require": 1,
    "--require-file": 1,
    "--known-failing-runner": 1,
    "--known-failing-results": 1,
    "--known-failing-host": 1,
}
COMMAND_BOUNDARY = {
    ";", "&&", "||", "|", "then", "do", "done", "fi", "if", "else", "elif",
    "python3", "sudo", "env", "PY", "EOF",
}


def parse_invocation(tokens, start, kind):
    positionals = []
    options = {name: [] for name in OPTION_ARITY}
    option_sequence = []
    cursor = start + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if not token.strip():
            cursor += 1
            continue
        if token in COMMAND_BOUNDARY or token.startswith(">") or token.startswith("<"):
            break
        if token.startswith("scripts/"):
            break
        array_match = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\[@\]\}", token)
        if array_match is not None:
            option_sequence.append(("array-expansion", array_match.group(1)))
        elif token.startswith("--"):
            if "=" in token:
                name, value = token.split("=", 1)
                values = [value]
            else:
                name = token
                values = []
            if name not in OPTION_ARITY:
                break
            needed = OPTION_ARITY[name] - len(values)
            if needed > 0:
                if cursor + needed >= len(tokens):
                    break
                values.extend(tokens[cursor + 1:cursor + 1 + needed])
                cursor += needed
            options[name].extend(values)
            option_sequence.extend((name, value) for value in values)
        else:
            positionals.append(token)
        cursor += 1
    if kind == "check-cell-results":
        results = positionals[0] if positionals else None
    else:
        results = positionals[2] + "/results.jsonl" if len(positionals) >= 3 else None
    runner = (options["--known-failing-runner"] or [None])[-1]
    if runner is None and kind == "run-cell-script" and positionals:
        runner = f"cell:scripts/ci/{positionals[0]}.sh"
    return {
        "kind": kind,
        "runner": runner,
        "results": results,
        "expected": options["--expected-failure"],
        "intermittent": options["--intermittent-failure"],
        "required": options["--require"],
        "nonqualifying": options["--allow-nonqualifying"],
        "require_file": options["--require-file"],
        "known_results": (options["--known-failing-results"] or [None])[-1],
        "known_host": (options["--known-failing-host"] or [None])[-1],
        "explicit_runner": bool(options["--known-failing-runner"]),
        "option_sequence": option_sequence,
    }


def workflow_invocations(root):
    workflow_dir = root / ".github" / "workflows"
    invocations = []
    problems = []
    if not workflow_dir.is_dir():
        return [], [f"{workflow_dir}: missing workflow directory"]
    try:
        entries = sorted(workflow_dir.iterdir())
    except OSError as exc:
        return [], [f"{workflow_dir}: cannot list workflow directory: {exc}"]
    for path in entries:
        if path.suffix not in (".yml", ".yaml") or not path.is_file():
            problems.append(f"{path}: unknown workflow directory entry: only .yml and .yaml files are workflows")
            continue
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
            problems.append(f"{path}: cannot parse workflow: {exc}")
            continue
        jobs = document.get("jobs") if isinstance(document, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job_name, job in jobs.items():
            steps = job.get("steps") if isinstance(job, dict) else None
            if not isinstance(steps, list):
                continue
            for step_index, step in enumerate(steps, 1):
                script = step.get("run") if isinstance(step, dict) else None
                if not isinstance(script, str):
                    continue
                # Comments often explain that the wrapper "validates with
                # check-cell-results.py"; they are not invocations. YAML run
                # blocks are shell, so full-line shell comments are removed
                # before tokenization.
                executable_script = "\n".join(
                    line for line in script.splitlines() if not line.lstrip().startswith("#"))
                try:
                    tokens = shlex.split(executable_script, comments=False, posix=True)
                except ValueError:
                    if ("check-cell-results.py" in executable_script
                            or "run-cell-script.sh" in executable_script):
                        where = f"{path.relative_to(root)}:{job_name}:{step_index}"
                        problems.append(
                            f"{where}: unparsable step mentions a cell checker; "
                            "fix the quoting so the scan cannot miss a declaration")
                    continue
                for index, token in enumerate(tokens):
                    kind = None
                    if token.endswith("scripts/ci/check-cell-results.py") or token.endswith("check-cell-results.py"):
                        kind = "check-cell-results"
                    elif token.endswith("scripts/ci/run-cell-script.sh") or token.endswith("run-cell-script.sh"):
                        kind = "run-cell-script"
                    if kind is None:
                        continue
                    invocation = parse_invocation(tokens, index, kind)
                    invocation.update({
                        "workflow": str(path.relative_to(root)),
                        "job": str(job_name),
                        "step": step_index,
                    })
                    invocations.append(invocation)
    return invocations, problems


def _is_kf_host_wildcard(value):
    if not isinstance(value, str):
        return False
    stripped = value.strip().strip('"').strip("'")
    return stripped in ("$kf_host", "${kf_host}")


def _cell_invocation_judges_row(row, invocation):
    if invocation.get("runner") != row["runner"]:
        return False
    host = invocation.get("known_host")
    if _is_kf_host_wildcard(host):
        return True
    if not isinstance(host, str) or host not in HOSTS:
        return False
    if "hosts" not in row:
        return True
    return host in row["hosts"]


def validate_cell_runner_declarations(root, rows):
    problems = []
    cell_rows = [row for row in rows if row["runner"].startswith("cell:")]
    for row in cell_rows:
        if not cell_runner_script_present(root, row):
            problems.append(f"{row['test']}: cell runner script does not exist: {row['runner']}")
    invocations, scan_problems = workflow_invocations(root)
    problems.extend(scan_problems)
    if scan_problems:
        return problems

    # Real result wiring is part of the declaration contract: every checker
    # invocation has a typed runner identity and result output. A workflow
    # cannot satisfy the gate by retaining a checker that only judges text.
    for invocation in invocations:
        where = f"{invocation['workflow']}:{invocation['job']}:{invocation['step']}"
        if invocation["runner"] is None or not valid_runner(invocation["runner"]):
            problems.append(f"{where}: declaration invocation lacks a typed known-failing runner")
        if not invocation["known_results"]:
            problems.append(f"{where}: check-cell-results invocation does not emit typed known-failing results")
        if not invocation["known_host"]:
            problems.append(f"{where}: check-cell-results invocation lacks a typed host")
        if invocation["known_results"] and not (
            invocation["required"] or invocation["expected"] or invocation["intermittent"] or invocation["nonqualifying"]
            or invocation["require_file"]
        ):
            problems.append(f"{where}: typed cell result selection is empty")

    for row in cell_rows:
        if not any(_cell_invocation_judges_row(row, invocation) for invocation in invocations):
            problems.append(
                f"{row['test']}: cell runner {row['runner']} has no CI judge: "
                "no workflow invocation with the same --known-failing-runner and a compatible host")

    groups = {}
    for invocation in invocations:
        if invocation["runner"] is None or invocation["results"] is None:
            continue
        key = (invocation["runner"], invocation["workflow"], invocation["job"], invocation["results"])
        groups.setdefault(key, []).append(invocation)

    rows_by_runner = {}
    for row in cell_rows:
        rows_by_runner.setdefault(row["runner"], []).append(row)

    for (runner, workflow, job, results), sites in sorted(groups.items()):
        first = sites[0]
        for site in sites[1:]:
            if any(sorted(site[key]) != sorted(first[key])
                   for key in ("expected", "intermittent", "required", "nonqualifying", "require_file")):
                problems.append(
                    f"{workflow}:{job}:{results}: repeated declarations for one runner/results stream differ")
                break
        runner_rows = rows_by_runner.get(runner, [])
        legacy_always = set(LEGACY_CELL_EXPECTED) if runner == PUBLIC_CLI_RUNNER else set()
        legacy_intermittent = set(LEGACY_CELL_INTERMITTENT) if runner == RUN_TREE_RUNNER else set()
        allowed_always = legacy_always | {row["test"] for row in runner_rows if row["mode"] == "always"}
        allowed_intermittent = legacy_intermittent | {row["test"] for row in runner_rows if row["mode"] == "intermittent"}
        extra_always = sorted(set(first["expected"]) - allowed_always)
        # Workflow declarations name the owning lane (CELL=LANE); the
        # ledger rows name the cell. Compare cell names; the runtime
        # checker already refuses a lane-less declaration.
        declared_intermittent = {value.partition("=")[0] for value in first["intermittent"]}
        extra_intermittent = sorted(declared_intermittent - allowed_intermittent)
        if extra_always:
            problems.append(f"{runner} declarations have undeclared expected cells: " + ", ".join(extra_always))
        if extra_intermittent:
            problems.append(f"{runner} declarations have undeclared intermittent cells: " + ", ".join(extra_intermittent))

    # Row-to-workflow declaration unification (plan rule 3) is deferred
    # to 0.7.3: only the reverse direction is enforced here.
    overlap = sorted({row["test"] for row in cell_rows if row["mode"] == "always"}
                     & {row["test"] for row in cell_rows if row["mode"] == "intermittent"})
    if overlap:
        problems.append("cell rows declare the same cell both always and intermittent: " + ", ".join(overlap))
    return problems


def load_ignored_registry(path):
    """Strictly load an ignored-test registry file for test->file mapping.

    Returns (files, problems). A missing file raises FileNotFoundError
    so each caller applies its own missing-file policy visibly; every
    other read failure yields a typed problem, as does a present file
    that fails strict parsing or is not an object with a sites list.
    Every site is validated before any mapping: a site that is not a
    {file, path} string pair, or a path claimed by more than one
    file, refuses the whole registry instead of yielding partial
    evidence.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        return {}, [f"{path}: cannot read ignored-test registry: {exc}"]
    registry, load_problems = strict_json(text, str(path))
    if load_problems or type(registry) is not dict or type(registry.get("sites")) is not list:
        detail = f" ({load_problems[0]})" if load_problems else ""
        return {}, [f"{path}: ignored-test registry must be an object with a sites list{detail}"]
    files = {}
    for index, site in enumerate(registry["sites"], 1):
        if not isinstance(site, dict) or not isinstance(site.get("file"), str) or not isinstance(site.get("path"), str):
            return {}, [f"{path}: ignored-test registry site {index} must have string file and path"]
        if site["path"] in files and files[site["path"]] != site["file"]:
            return {}, [f"{path}: ignored-test registry path {site['path']!r} is claimed by more than one file"]
        files[site["path"]] = site["file"]
    return files, []


def validate_ignored_known_failing(root, rows):
    path = root / "tests/ignored-tests.json"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if any(row["path"].endswith(".rs") for row in rows):
            return [f"{path}: missing ignored-test registry for Rust known-failing rows"]
        return []
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{path}: cannot read ignored-test registry: {exc}"]
    data, problems = strict_json(text, str(path))
    if data is PARSE_FAILED:
        return problems
    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        return problems + [f"{path}: ignored-test registry must be an object with a sites list"]
    if data.get("schema") != "p11scope/ignored-tests/v1":
        problems.append(f"{path}: schema must be p11scope/ignored-tests/v1")
    actual = set()
    malformed = []
    for index, site in enumerate(data["sites"], 1):
        if not isinstance(site, dict):
            malformed.append(str(index))
            continue
        file_name = site.get("file")
        test_path = site.get("path")
        if not isinstance(file_name, str) or not isinstance(test_path, str):
            malformed.append(str(index))
            continue
        if site.get("cell") == "known-failing":
            actual.add((file_name, test_path))
    if malformed:
        problems.append(f"{path}: malformed site entries at positions: {', '.join(malformed)}")
    wanted = {(row["path"], row["test"]) for row in rows if row["path"].endswith(".rs")}
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing:
        rendered = ", ".join(f"{file_name}:{test}" for file_name, test in missing)
        problems.append("ignored-tests missing cell=known-failing rows: " + rendered)
    if extra:
        rendered = ", ".join(f"{file_name}:{test}" for file_name, test in extra)
        problems.append("ignored-tests has cell=known-failing entries without rows: " + rendered)
    return problems


def validate_static(root, list_path, discover_executables=True):
    rows, problems = load_list(list_path)
    registry_present, registry, registry_problems = load_issue_registry(root)
    problems.extend(registry_problems)
    if (root / "docs/releases/v0.7.2.md").is_file() and not registry_present:
        problems.append("the 0.7.2 release needs the typed known-issue registry")
    if rows and not registry_present:
        problems.append("no typed known-issue registry: rows cannot name a known issue before the 0.7.2 section lands")
    elif registry_present and not registry_problems:
        row_issues = {issue for row in rows for issue in row["issues"]}
        known_ids = set(registry)
        test_yes = {issue for issue, has_test in registry.items() if has_test}
        unknown_issues = sorted(row_issues - known_ids)
        if unknown_issues:
            problems.append("rows name issues that are not a named known issue: " + ", ".join(unknown_issues))
        covered_yes = {issue for row in rows for issue in row["issues"] if issue in test_yes}
        missing_issue_rows = sorted(test_yes - covered_yes)
        if missing_issue_rows:
            problems.append("test=yes issues without rows: " + ", ".join(missing_issue_rows))
        rows_not_test_yes = sorted((row_issues & known_ids) - test_yes)
        if rows_not_test_yes:
            problems.append("rows for issues not marked test=yes: " + ", ".join(rows_not_test_yes))

    seen_row_keys = set()
    for row in rows:
        key = (row["runner"], *row_key(row))
        if key in seen_row_keys:
            problems.append(f"duplicate row for {row['runner']} {row['path']} {row['test']}: split composite cells instead")
        seen_row_keys.add(key)
        if (root / "docs/releases" / f"v{row['target']}.md").is_file():
            problems.append(f"{row['test']}: target {row['target']} already released "
                            f"(docs/releases/v{row['target']}.md exists): rows expire at their target release")
        candidate = root / row["path"]
        if not candidate.is_file():
            problems.append(f"{row['path']}: path does not exist for {row['test']}")
            continue
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            problems.append(f"{row['path']}: path escapes the repository root")
            continue
        if discover_executables and not test_exists(root, row):
            problems.append(f"{row['path']}: executable discovery did not find exact test id: {row['test']}")
        if not python_suite_registered(root, row):
            problems.append(f"{row['path']}: suite invocation is not registered in scripts/run-python-suites.py")
    problems.extend(validate_privileged_runner(root, rows))
    problems.extend(validate_cell_runner_declarations(root, rows))
    problems.extend(validate_ignored_known_failing(root, rows))
    return rows, problems, registry_present


def validate_invocation_value(value, label, problems):
    if not valid_invocation(value):
        problems.append(f"{label}: invocation must be a list of nonempty argument strings")


def validate_result_document(path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [f"results: missing file {path}"]
    except (OSError, UnicodeDecodeError) as exc:
        return None, [f"results: cannot read {path}: {exc}"]
    data, problems = strict_json(text, f"results {path}")
    if data is PARSE_FAILED:
        return None, problems
    if not isinstance(data, dict) or set(data) != RESULT_TOP_FIELDS:
        problems.append("results: top level must have exactly schema/runner/host/complete/selection/results")
        return None, problems
    if data.get("schema") != RESULT_SCHEMA:
        problems.append(f"results: schema must be {RESULT_SCHEMA}")
    if not valid_runner(data.get("runner")):
        problems.append("results: runner is not in the closed runner vocabulary")
    if not isinstance(data.get("host"), str) or data["host"] not in HOSTS:
        problems.append(f"results: host must be one of {', '.join(sorted(HOSTS))}")
    if data.get("complete") is not True:
        problems.append("results: complete must be true; an incomplete or failed-to-complete run is not a result set")
    raw_selection = data.get("selection")
    raw_results = data.get("results")
    if not isinstance(raw_selection, list) or not raw_selection:
        problems.append("results: selection must be a nonempty executable inventory")
        return None, problems
    if not isinstance(raw_results, list):
        problems.append("results: results must be a list")
        return None, problems

    selection = {}
    for index, raw in enumerate(raw_selection, 1):
        label = f"selection row {index}"
        if not isinstance(raw, dict) or set(raw) != RESULT_SELECTION_FIELDS:
            problems.append(f"{label}: must have exactly path/test/invocation")
            continue
        if not valid_relative_path(raw["path"]):
            problems.append(f"{label}: path must be a clean repository-relative POSIX path")
        if not isinstance(raw["test"], str) or not raw["test"]:
            problems.append(f"{label}: test must be a nonempty exact test or cell id")
        validate_invocation_value(raw["invocation"], label, problems)
        if type(raw["path"]) is str and type(raw["test"]) is str:
            key = (raw["path"], raw["test"], tuple(raw["invocation"]) if valid_invocation(raw["invocation"]) else ())
            if key in selection:
                problems.append(f"{label}: duplicate selected test {raw['test']}")
            selection[key] = raw

    results = {}
    for index, raw in enumerate(raw_results, 1):
        label = f"results row {index}"
        if not isinstance(raw, dict) or set(raw) != RESULT_ROW_FIELDS:
            problems.append(f"{label}: must have exactly path/test/invocation/state/signature")
            continue
        if not valid_relative_path(raw["path"]):
            problems.append(f"{label}: path must be a clean repository-relative POSIX path")
        if not isinstance(raw["test"], str) or not raw["test"]:
            problems.append(f"{label}: test must be a nonempty exact test or cell id")
        validate_invocation_value(raw["invocation"], label, problems)
        if type(raw["state"]) is not str or raw["state"] not in RESULT_STATES:
            problems.append(f"{label}: state is not in the closed terminal-state vocabulary")
        if raw["state"] == "passed":
            if raw["signature"] is not None:
                problems.append(f"{label}: a passing result must carry a null signature")
        else:
            problems.extend(f"{label}: {problem}" for problem in signature_problems(raw["signature"]))
        if type(raw["path"]) is str and type(raw["test"]) is str:
            key = (raw["path"], raw["test"], tuple(raw["invocation"]) if valid_invocation(raw["invocation"]) else ())
            if key in results:
                problems.append(f"{label}: duplicate result for {raw['test']}")
            results[key] = raw

    missing_results = sorted(set(selection) - set(results))
    missing_selection = sorted(set(results) - set(selection))
    if missing_results:
        problems.append("results: selected tests without terminal results: "
                        + ", ".join(key[1] for key in missing_results))
    if missing_selection:
        problems.append("results: terminal results outside the selection: "
                        + ", ".join(key[1] for key in missing_selection))
    if problems:
        return None, problems
    data["selection_typed"] = selection
    data["results_typed"] = results
    return data, []


def json_exact_equal(left, right):
    stack = [(left, right, 0)]
    while stack:
        left, right, depth = stack.pop()
        if depth > MAX_TYPED_DEPTH:
            return False
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            if set(left) != set(right):
                return False
            stack.extend((left[key], right[key], depth + 1) for key in left)
        elif isinstance(left, list):
            if len(left) != len(right):
                return False
            stack.extend((left_item, right_item, depth + 1)
                         for left_item, right_item in zip(left, right))
        elif isinstance(left, float):
            if not (left == right and math.copysign(1.0, left) == math.copysign(1.0, right)):
                return False
        elif left != right:
            return False
    return True


def host_applies(row, host):
    return "hosts" not in row or host in row["hosts"]


def legacy_exempt(runner, test):
    if runner == "privileged-lib":
        return test in LEGACY_PRIVILEGED_LIB
    if runner == PUBLIC_CLI_RUNNER:
        return test in LEGACY_CELL_EXPECTED
    if runner == RUN_TREE_RUNNER:
        return test in LEGACY_CELL_INTERMITTENT
    return False


def evaluate_results(rows, document):
    problems = []
    runner = document["runner"]
    host = document["host"]
    applicable = [row for row in rows if row["runner"] == runner and host_applies(row, host)]
    results_by_key = document["results_typed"]
    listed_keys = {row_key(row) for row in applicable}
    expected_failures = 0
    intermittent_passes = 0
    for row in applicable:
        key = row_key(row)
        result = results_by_key.get(key)
        if result is None:
            problems.append(f"listed row has no selected terminal result: {row['test']} ({'/'.join(row['issues'])})")
            continue
        if result["state"] == "passed" and row["mode"] == "always":
            problems.append(f"stale row: {row['test']} passed but {'/'.join(row['issues'])} is still listed always-failing")
        elif result["state"] == "passed":
            intermittent_passes += 1
        elif result["state"] in NEUTRAL_STATES or result["state"] == "not_run":
            problems.append(f"listed row was not executed: {row['test']} ({result['state']})")
        elif not json_exact_equal(result["signature"], row["signature"]):
            problems.append(
                f"failure signature mismatch for {row['test']} ({'/'.join(row['issues'])}): "
                f"got {json.dumps(result['signature'], sort_keys=True)}, "
                f"want {json.dumps(row['signature'], sort_keys=True)}")
        else:
            expected_failures += 1
    for key, result in results_by_key.items():
        if key in listed_keys or result["state"] == "passed" or result["state"] in NEUTRAL_STATES:
            continue
        if legacy_exempt(runner, key[1]):
            continue
        problems.append(f"failing test not listed: {key[1]} at {key[0]} ({result['state']})")
    skipped = sum(1 for result in results_by_key.values() if result["state"] == "skipped")
    not_applicable = sum(1 for result in results_by_key.values() if result["state"] == "not_applicable")
    return problems, expected_failures, intermittent_passes, len(applicable), len(results_by_key), skipped, not_applicable


def parse_args(argv):
    parser = argparse.ArgumentParser(description="validate and judge tests/known-failing.json")
    parser.add_argument("--root", default=str(ROOT), help="repository root")
    parser.add_argument("--list", dest="list_path", help="known-failing list path (default ROOT/tests/known-failing.json)")
    parser.add_argument("--results", help="typed known-failing results JSON document")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    root = Path(args.root).resolve()
    list_path = Path(args.list_path) if args.list_path else root / "tests/known-failing.json"
    if not list_path.is_absolute():
        list_path = root / list_path
    rows, problems, registry_present = validate_static(root, list_path, discover_executables=args.results is None)
    if problems:
        for problem in problems:
            print(f"check-known-failing: {problem}", file=sys.stderr)
        return 1
    authority = "typed issue registry" if registry_present else "pre-registry empty-list window"
    print(f"check-known-failing: list ok ({len(rows)} rows, {authority})")
    if not args.results:
        return 0
    document, result_problems = validate_result_document(Path(args.results))
    if result_problems:
        for problem in result_problems:
            print(f"check-known-failing: {problem}", file=sys.stderr)
        return 1
    problems, expected, intermittent, applicable, observed, skipped, not_applicable = evaluate_results(rows, document)
    if problems:
        for problem in problems:
            print(f"check-known-failing: {problem}", file=sys.stderr)
        return 1
    print(
        f"check-known-failing: results ok ({expected} expected failures, "
        f"{intermittent} intermittent passes, {applicable} applicable rows, {observed} observations, "
        f"{skipped} skipped, {not_applicable} not_applicable)")
    return 0


def entry(argv):
    """CLI entry point: every operational failure is a typed refusal, never a traceback."""
    try:
        return main(argv)
    except (OSError, RecursionError, TypeError, ValueError, KeyError, UnicodeError) as exc:
        print(f"check-known-failing: internal refusal: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(entry(sys.argv[1:]))
