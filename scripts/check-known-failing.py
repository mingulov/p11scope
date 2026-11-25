#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Validate and judge the tracked known-failing test list.

`tests/known-failing.json` is schema `p11scope/known-failing/v1`. Each row is
one typed exception owned by a named known issue; it is not a mechanism for
declaring an ordinary regression expected. Required row fields are `path`,
`test`, `issue`, `target`, `runner`, `signature`, `lane` and `mode`; optional
fields are `hosts`, `since` and `evidence`. `signature` is a JSON object of
typed verdict/record fields (for example `{"cell": "X", "branch": "y"}`),
never text to search for in a log.

Known-issue authority is typed too. Once `docs/known-limitations.md` gains
`## Known limitations in 0.7.2`, that section must carry exactly one block of
the form:

    <!-- p11scope-known-issues-v1
    {"schema":"p11scope/known-issues/v1","issues":[{"id":"KI-01","test":true}]}
    -->

The block is the authority for named issue ids and for which issues have a
test. Every registry id must also have a prose `### KI-nn` heading in the
same section, and every such heading must be registered; this is structural
Markdown identity, not log-text matching. Until that section lands, only an
empty known-failing list is valid; this keeps the pre-docs integration window
fail-closed without inventing a second issue authority.

Static validation checks row shape, exact test existence, Python-suite
registration, the issue/row set equality, and exact equality with the runner
declarations (`EXPECTED_FAILURE_TESTS`, workflow `--expected-failure` /
`--intermittent-failure` cells, and `cell: known-failing` entries in
`tests/ignored-tests.json`). The eleven pre-existing declarations are a closed
legacy baseline until their 0.7.3 migration; any additional declaration must
be a typed row. With `--results`, the checker also judges one typed result
document of schema
`p11scope/known-failing-results/v1`:

    {
      "schema": "p11scope/known-failing-results/v1",
      "runner": "python-suite",
      "host": "fedora",
      "results": [
        {"path": "tests/python/test_x.py", "test": "C.test_x",
         "passed": false, "signature": {"cell": "X", "branch": "y"}}
      ]
    }

Every applicable row for the result runner and host must have exactly one
observation. An `always` row that passes is stale. A failing observation not
covered by a row is an ordinary failure. A covered failure whose typed
signature differs by even one field is an ordinary failure. Comparison is
JSON-value equality, never log-text matching. Until the legacy declarations
are migrated in 0.7.3, a producer keeps those cells in the old runner's input
rather than copying them into this result document; every other failure in
the selected runner output must be present so the unlisted-failure rule stays
closed.

Usage:
  python3 -I scripts/check-known-failing.py [--root DIR] [--list PATH]
  python3 -I scripts/check-known-failing.py [--root DIR] [--list PATH] --results RESULTS.json
"""

import argparse
import ast
import importlib.util
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST_SCHEMA = "p11scope/known-failing/v1"
ISSUE_SCHEMA = "p11scope/known-issues/v1"
RESULT_SCHEMA = "p11scope/known-failing-results/v1"
ISSUE_HEADING = "## Known limitations in 0.7.2"
ISSUE_MARKER = "<!-- p11scope-known-issues-v1"
TARGETS = {"0.7.3", "0.8.0"}
MODES = {"always", "intermittent"}
HOSTS = {"fedora", "fedora-sm1", "vng"}
BASE_RUNNERS = {"privileged-lib", "python-suite", "host-matrix"}
REQUIRED_ROW_FIELDS = {
    "path", "test", "issue", "target", "runner", "signature", "lane", "mode",
}
OPTIONAL_ROW_FIELDS = {"hosts", "since", "evidence"}
RESULT_TOP_FIELDS = {"schema", "runner", "host", "results"}
RESULT_ROW_FIELDS = {"path", "test", "passed", "signature"}
ISSUE_RE = re.compile(r"^KI-[0-9]{2}$")
TEST_ATTR_RE = re.compile(r"#\s*\[\s*test\s*\]")
FN_AT_RE = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b")
TEXTUAL_SIGNATURE_KEY_TOKENS = {
    "detail", "log", "message", "output", "pattern", "regex", "stderr",
    "stdout", "text",
}


def textual_signature_key(key):
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    tokens = (token for token in re.split(r"[_\-.]+", camel_split.lower()) if token)
    return any(token in TEXTUAL_SIGNATURE_KEY_TOKENS for token in tokens)

# The pre-existing inverted privileged-lib declarations. They are legacy
# machinery, explicitly not known-issue rows in v0.7.2; the exact-equality
# check below nevertheless prevents a new legacy declaration from being added
# silently. They move to typed rows only when their owner gives them issue ids.
LEGACY_PRIVILEGED_LIB = frozenset({
    "discovery::engine::tests::exit_loader_balanced_benign_transaction_needs_no_terminal_truncation",
    "inventory::privileged_tests::privileged_identity_kernel_sweep_cell_lp64",
    "inventory::privileged_tests::privileged_identity_kernel_multipass_reuse_lp64",
})

# The pre-existing check-cell-results declarations. As with the privileged
# legacy cells above, they are not known-issue rows in v0.7.2; they are a
# closed legacy baseline so rule 3 still compares exact sets rather than
# tolerating any additional untracked exception. A 0.7.3 migration patch
# moves one of these names into a typed row and removes it from the baseline
# in the same change.
LEGACY_CELL_EXPECTED = frozenset({
    "profile-cgroup",
    "trace-cgroup",
    "profile-pid-ia32",
    "run-ia32",
})
LEGACY_CELL_INTERMITTENT = frozenset({
    "privileged_run_tree_unprearmed_shortlived_descendants_reach_high_coverage",
    "privileged_run_tree_unprearmed_shortlived_never_pause_still_learns",
    "privileged_run_tree_unprearmed_shortlived_parallel_never_pause_covers_waves",
    "privileged_run_tree_arming_exhaustion_still_stages_and_counts",
})


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


def strict_json(text, label):
    try:
        return json.loads(text, object_pairs_hook=object_no_duplicates,
                          parse_constant=reject_json_constant), []
    except (json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        return None, [f"{label}: invalid JSON: {exc}"]


def valid_runner(value):
    if not isinstance(value, str):
        return False
    if value in BASE_RUNNERS:
        return True
    return value.startswith("cell:") and len(value) > len("cell:")


def valid_relative_path(value):
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/") or "\\" in value:
        return False
    parts = value.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def signature_problems(value, where="signature"):
    if not isinstance(value, dict) or not value:
        return [f"{where} must be a nonempty object of typed fields"]
    problems = []

    def walk(node, path):
        if isinstance(node, dict):
            if not node:
                problems.append(f"{path} must not be an empty object")
                return
            for key, child in node.items():
                if not isinstance(key, str) or not key:
                    problems.append(f"{path} has a non-string or empty key")
                    continue
                if textual_signature_key(key):
                    problems.append(
                        f"{path}.{key} is free-text/log matching; use a typed verdict branch or record field")
                walk(child, f"{path}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]")
        elif isinstance(node, float) and not math.isfinite(node):
            problems.append(f"{path} must be a finite JSON number")
        elif node is None or isinstance(node, (str, int, float, bool)):
            return
        else:
            problems.append(f"{path} has a non-JSON value of type {type(node).__name__}")

    walk(value, where)
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
        problems.append(f"{label}: missing required fields: {', '.join(missing)}")
        return problems, None
    unknown = sorted(keys - allowed)
    if unknown:
        problems.append(f"{label}: unknown fields: {', '.join(unknown)}")
    if not valid_relative_path(raw["path"]):
        problems.append(f"{label}: path must be a clean repository-relative POSIX path")
    if not isinstance(raw["test"], str) or not raw["test"]:
        problems.append(f"{label}: test must be a nonempty exact test or cell id")
    if not isinstance(raw["issue"], str) or not ISSUE_RE.fullmatch(raw["issue"]):
        problems.append(f"{label}: issue must be a known-issue id KI-nn")
    if not isinstance(raw["target"], str) or raw["target"] not in TARGETS:
        problems.append(f"{label}: target must be one of {', '.join(sorted(TARGETS))}")
    if not valid_runner(raw["runner"]):
        problems.append(f"{label}: runner is not in the closed runner vocabulary")
    problems.extend(f"{label}: {problem}" for problem in signature_problems(raw["signature"]))
    if not isinstance(raw["lane"], str) or not raw["lane"].strip():
        problems.append(f"{label}: lane must name the lane that owns the fix")
    if not isinstance(raw["mode"], str) or raw["mode"] not in MODES:
        problems.append(f"{label}: mode must be always or intermittent")
    if "hosts" in raw:
        hosts = raw["hosts"]
        if (not isinstance(hosts, list) or not hosts
                or any(not isinstance(host, str) or host not in HOSTS for host in hosts)
                or len(set(hosts)) != len(hosts)):
            problems.append(f"{label}: hosts must be a unique nonempty subset of {', '.join(sorted(HOSTS))}")
    for key in ("since", "evidence"):
        if key in raw and (not isinstance(raw[key], str) or not raw[key].strip()):
            problems.append(f"{label}: {key} must be a nonempty string when present")
    return problems, raw


def load_list(path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], [f"{path}: missing known-failing list"]
    except OSError as exc:
        return [], [f"{path}: cannot read known-failing list: {exc}"]
    data, problems = strict_json(text, str(path))
    if data is None:
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
    except OSError as exc:
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
    if data is None:
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


def import_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def python_tests(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    tests = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            tests.add(node.name)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test"):
                    tests.add(f"{node.name}.{child.name}")
    return tests


def rust_crate_base(root, path):
    """Module segments implied by the ordinary Rust file layout.

    Integration targets under tests/ are crate roots. Library/bin modules use
    their conventional path below src/ (with mod.rs elided). A nonstandard
    #[path] layout is deliberately not guessed: its exact id is treated as
    absent rather than risking a false positive.
    """
    relative = path.relative_to(root)
    parts = list(relative.parts)
    if len(parts) == 2 and parts[0] == "tests" and parts[1].endswith(".rs"):
        return []
    if parts and parts[0] == "src":
        module_parts = parts[1:]
    elif len(parts) >= 3 and parts[0] == "crates" and parts[2] == "src":
        module_parts = parts[3:]
    else:
        return None
    if not module_parts:
        return []
    if module_parts in (["lib.rs"], ["main.rs"]):
        return []
    if module_parts[-1] == "mod.rs":
        module_parts = module_parts[:-1]
    else:
        module_parts[-1] = module_parts[-1][:-3] if module_parts[-1].endswith(".rs") else module_parts[-1]
    return [part for part in module_parts if part]


def rust_tests(root, path):
    helper_path = root / "scripts/check-ignored-tests.py"
    helper = import_module(helper_path, "p11scope_check_ignored_for_known_failing")
    base = rust_crate_base(root, path)
    if base is None:
        return set()
    text = path.read_text(encoding="utf-8")
    stripped = helper.strip_code(text)
    found = set()
    for match in TEST_ATTR_RE.finditer(stripped):
        try:
            cursor = helper.attribute_end(stripped, match.start())
        except ValueError:
            continue
        while True:
            while cursor < len(stripped) and stripped[cursor].isspace():
                cursor += 1
            if stripped.startswith("#[", cursor):
                try:
                    cursor = helper.attribute_end(stripped, cursor)
                except ValueError:
                    break
                continue
            break
        fn_match = FN_AT_RE.match(stripped, cursor)
        if fn_match is None:
            continue
        segments = base + helper.inline_mods_at(stripped, match.start()) + [fn_match.group(1)]
        found.add("::".join(segments))
    return found


def shell_cells(path):
    cells = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.+|-]+)\s*\)", line)
        if match is None:
            continue
        cells.update(part for part in match.group(1).split("|") if part)
    return cells


def test_exists(root, row):
    path = root / row["path"]
    try:
        if row["path"].endswith(".py"):
            return row["test"] in python_tests(path)
        if row["path"].endswith(".rs"):
            return row["test"] in rust_tests(root, path)
        if row["path"].endswith(".sh"):
            return row["test"] in shell_cells(path)
    except (OSError, SyntaxError, ValueError):
        return False
    return False


def python_suite_registered(root, row):
    if row["runner"] != "python-suite":
        return True
    prefix = "tests/python/"
    if not row["path"].startswith(prefix):
        return False
    registry_path = root / "scripts/run-python-suites.py"
    try:
        registry = import_module(registry_path, "p11scope_python_suite_registry_for_known_failing")
    except (OSError, SyntaxError, ValueError):
        return False
    name = row["path"][len(prefix):]
    return any(entry == name for entry, _args in getattr(registry, "RUN", []))


def validate_privileged_runner(root, rows):
    runner_path = root / "scripts/run-privileged-lib-tests.sh"
    wanted_new = {row["test"] for row in rows if row["runner"] == "privileged-lib"}
    if not runner_path.is_file():
        if wanted_new:
            return ["privileged-lib rows exist but scripts/run-privileged-lib-tests.sh is missing"]
        return []
    try:
        helper = import_module(root / "scripts/check-ignored-tests.py",
                               "p11scope_check_ignored_for_privileged_known_failing")
        lists = helper.runner_lists(runner_path)
    except (OSError, SyntaxError, ValueError) as exc:
        return [f"privileged-lib runner declaration cannot be read: {exc}"]
    actual = set(lists.get("EXPECTED_FAILURE_TESTS", set()))
    expected = set(LEGACY_PRIVILEGED_LIB) | wanted_new
    problems = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        problems.append("privileged-lib runner is missing known-failing rows: " + ", ".join(missing))
    if extra:
        problems.append("privileged-lib runner has undeclared expected failures: " + ", ".join(extra))
    return problems


def cell_runner_script_present(root, row):
    if not row["runner"].startswith("cell:"):
        return True
    script = row["runner"][len("cell:"):]
    if not valid_relative_path(script):
        return False
    return (root / script).is_file()


def workflow_cell_declarations(root):
    """(--expected-failure cells, --intermittent-failure cells) in CI."""
    path = root / ".github/workflows/privileged-tests.yml"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None, [f"{path}: missing workflow carrying check-cell-results declarations"]
    except OSError as exc:
        return None, None, [f"{path}: cannot read workflow declarations: {exc}"]
    expected = set()
    intermittent = set()
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        expected.update(
            match.group(1).strip("'\"")
            for match in re.finditer(r"--expected-failure(?:=|\s+)([^\s\\]+)", line)
        )
        intermittent.update(
            match.group(1).strip("'\"")
            for match in re.finditer(r"--intermittent-failure(?:=|\s+)([^\s\\]+)", line)
        )
    return expected, intermittent, []


def validate_cell_runner_declarations(root, rows):
    problems = []
    cell_rows = [row for row in rows if row["runner"].startswith("cell:")]
    for row in cell_rows:
        if not cell_runner_script_present(root, row):
            problems.append(f"{row['test']}: cell runner script does not exist: {row['runner']}")
    expected_actual, intermittent_actual, read_problems = workflow_cell_declarations(root)
    problems.extend(read_problems)
    if read_problems:
        return problems

    always_rows = {row["test"] for row in cell_rows if row["mode"] == "always"}
    intermittent_rows = {row["test"] for row in cell_rows if row["mode"] == "intermittent"}
    overlap = sorted(always_rows & intermittent_rows)
    if overlap:
        problems.append("cell rows declare the same cell both always and intermittent: " + ", ".join(overlap))

    expected_wanted = set(LEGACY_CELL_EXPECTED) | always_rows
    intermittent_wanted = set(LEGACY_CELL_INTERMITTENT) | intermittent_rows
    for label, actual, wanted in (
        ("--expected-failure", expected_actual, expected_wanted),
        ("--intermittent-failure", intermittent_actual, intermittent_wanted),
    ):
        missing = sorted(wanted - actual)
        extra = sorted(actual - wanted)
        if missing:
            problems.append(f"workflow {label} declarations missing known-failing rows: " + ", ".join(missing))
        if extra:
            problems.append(f"workflow {label} has undeclared expected/intermittent cells: " + ", ".join(extra))
    return problems


def validate_ignored_known_failing(root, rows):
    path = root / "tests/ignored-tests.json"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if any(row["path"].endswith(".rs") for row in rows):
            return [f"{path}: missing ignored-test registry for Rust known-failing rows"]
        return []
    except OSError as exc:
        return [f"{path}: cannot read ignored-test registry: {exc}"]
    data, problems = strict_json(text, str(path))
    if data is None:
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


def validate_static(root, list_path):
    rows, problems = load_list(list_path)
    registry_present, registry, registry_problems = load_issue_registry(root)
    problems.extend(registry_problems)
    if rows and not registry_present:
        problems.append("no typed known-issue registry: rows cannot name a known issue before the 0.7.2 section lands")
    elif registry_present and not registry_problems:
        row_issues = {row["issue"] for row in rows}
        known_ids = set(registry)
        test_yes = {issue for issue, has_test in registry.items() if has_test}
        unknown_issues = sorted(row_issues - known_ids)
        if unknown_issues:
            problems.append("rows name issues that are not a named known issue: " + ", ".join(unknown_issues))
        missing_issue_rows = sorted(test_yes - row_issues)
        if missing_issue_rows:
            problems.append("test=yes issues without rows: " + ", ".join(missing_issue_rows))
        rows_not_test_yes = sorted((row_issues & known_ids) - test_yes)
        if rows_not_test_yes:
            problems.append("rows for issues not marked test=yes: " + ", ".join(rows_not_test_yes))

    seen_row_keys = set()
    for row in rows:
        key = (row["runner"], row["path"], row["test"])
        if key in seen_row_keys:
            problems.append(f"duplicate row for {row['runner']} {row['path']} {row['test']}: split composite cells instead")
        seen_row_keys.add(key)
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
        if not test_exists(root, row):
            problems.append(f"{row['path']}: test id not found exactly: {row['test']}")
        if not python_suite_registered(root, row):
            problems.append(f"{row['path']}: suite is not registered in scripts/run-python-suites.py")
    problems.extend(validate_privileged_runner(root, rows))
    problems.extend(validate_cell_runner_declarations(root, rows))
    problems.extend(validate_ignored_known_failing(root, rows))
    return rows, problems, registry_present


def validate_result_document(path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [f"results: missing file {path}"]
    except OSError as exc:
        return None, [f"results: cannot read {path}: {exc}"]
    data, problems = strict_json(text, f"results {path}")
    if data is None:
        return None, problems
    if not isinstance(data, dict) or set(data) != RESULT_TOP_FIELDS:
        problems.append("results: top level must have exactly schema/runner/host/results")
        return None, problems
    if data.get("schema") != RESULT_SCHEMA:
        problems.append(f"results: schema must be {RESULT_SCHEMA}")
    if not valid_runner(data.get("runner")):
        problems.append("results: runner is not in the closed runner vocabulary")
    if not isinstance(data.get("host"), str) or data["host"] not in HOSTS:
        problems.append(f"results: host must be one of {', '.join(sorted(HOSTS))}")
    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        problems.append("results: results must be a list")
        return None, problems
    rows = []
    seen = set()
    for index, raw in enumerate(raw_results, 1):
        label = f"results row {index}"
        if not isinstance(raw, dict) or set(raw) != RESULT_ROW_FIELDS:
            problems.append(f"{label}: must have exactly path/test/passed/signature")
            continue
        path_value = raw.get("path")
        test_value = raw.get("test")
        key = None
        if isinstance(path_value, str) and isinstance(test_value, str):
            key = (path_value, test_value)
            if key in seen:
                problems.append(f"{label}: duplicate result for {key[1]}")
                continue
            seen.add(key)
        if not valid_relative_path(raw["path"]):
            problems.append(f"{label}: path must be a clean repository-relative POSIX path")
        if not isinstance(raw["test"], str) or not raw["test"]:
            problems.append(f"{label}: test must be a nonempty exact test or cell id")
        if not isinstance(raw["passed"], bool):
            problems.append(f"{label}: passed must be a boolean")
        if raw["signature"] is not None:
            problems.extend(f"{label}: {problem}" for problem in signature_problems(raw["signature"]))
        if raw["passed"] and raw["signature"] is not None:
            problems.append(f"{label}: a passing result must carry a null signature")
        rows.append(raw)
    if problems:
        return None, problems
    return data, []


def json_exact_equal(left, right):
    """Type-sensitive equality for strict JSON values.

    Python's ordinary equality intentionally conflates bool/int and int/float
    (`True == 1`, `1 == 1.0`). The ledger compares typed records, so those
    are different values here. Strict JSON parsing has already rejected NaN
    and infinities; the copysign check keeps signed zero distinct as well.
    """
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (
            set(left) == set(right)
            and all(json_exact_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            json_exact_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    if isinstance(left, float):
        return left == right and math.copysign(1.0, left) == math.copysign(1.0, right)
    return left == right


def host_applies(row, host):
    return "hosts" not in row or host in row["hosts"]


def evaluate_results(rows, document):
    problems = []
    runner = document["runner"]
    host = document["host"]
    applicable = [row for row in rows if row["runner"] == runner and host_applies(row, host)]
    results_by_key = {(entry["path"], entry["test"]): entry for entry in document["results"]}
    listed_keys = {(row["path"], row["test"]) for row in applicable}
    expected_failures = 0
    intermittent_passes = 0
    for row in applicable:
        key = (row["path"], row["test"])
        if key not in results_by_key:
            problems.append(f"listed row has no result: {row['test']} ({row['issue']})")
            continue
        result = results_by_key[key]
        if result["passed"] and row["mode"] == "always":
            problems.append(f"stale row: {row['test']} passed but {row['issue']} is still listed always-failing")
        elif result["passed"]:
            intermittent_passes += 1
        elif not json_exact_equal(result["signature"], row["signature"]):
            problems.append(
                f"failure signature mismatch for {row['test']} ({row['issue']}): "
                f"got {json.dumps(result['signature'], sort_keys=True)}, "
                f"want {json.dumps(row['signature'], sort_keys=True)}")
        else:
            expected_failures += 1
    for key, result in results_by_key.items():
        if key not in listed_keys and result["passed"] is False:
            problems.append(f"failing test not listed: {key[1]} at {key[0]}")
    return problems, expected_failures, intermittent_passes, len(applicable), len(document["results"])


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
    rows, problems, registry_present = validate_static(root, list_path)
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
    problems, expected, intermittent, applicable, observed = evaluate_results(rows, document)
    if problems:
        for problem in problems:
            print(f"check-known-failing: {problem}", file=sys.stderr)
        return 1
    print(
        f"check-known-failing: results ok ({expected} expected failures, "
        f"{intermittent} intermittent passes, {applicable} applicable rows, {observed} observations)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
