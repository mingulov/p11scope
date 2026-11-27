#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Merge the privileged lib runner's structured selection/verdict records.

Input is not results.txt and not test logs: run-privileged-lib-tests.sh writes
a selection file (one exact libtest id per line) and a verdict TSV whose
verdicts are closed runner tokens. This converter proves the two sets are
nonempty, unique and exactly one-to-one, maps every id through
tests/ignored-tests.json, and emits p11scope/known-failing-results/v1.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERDICT_STATE = {
    "PASS": ("passed", None),
    "FAIL": ("failed", {"oracle": "libtest-summary", "verdict": "FAIL"}),
    "SKIP": ("skipped", {"oracle": "runner-preflight", "verdict": "SKIP"}),
    "XFAIL": ("failed", {"oracle": "runner-xfail", "verdict": "XFAIL"}),
    # XPASS means libtest itself passed in an inverted legacy cell. The typed
    # stream records the truthful terminal test state; the shell runner still
    # fails the legacy campaign separately.
    "XPASS": ("passed", None),
}


def checker_module():
    path = ROOT / "scripts/check-known-failing.py"
    spec = importlib.util.spec_from_file_location("known_failing_checker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ignored_scanner_module():
    path = ROOT / "scripts/check-ignored-tests.py"
    spec = importlib.util.spec_from_file_location("ignored_test_scanner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rust_token_index():
    """Map Rust identifier tokens to source files, ignoring comments/strings.

    Returns (index, problems): every *.rs file outside the excluded
    segments is either indexed or reported. An unreadable source
    refuses the conversion instead of silently shrinking the token
    set, which could turn an ambiguous token unique.
    """
    scanner = ignored_scanner_module()
    index = {}
    problems = []
    for base_name in ("src", "tests", "crates"):
        base = ROOT / base_name
        if not base.is_dir():
            continue
        files, scan_problems = scanner.scan_tree_files(
            base, lambda name: name.endswith(".rs"), scanner.EXCLUDED_SEGMENTS)
        problems.extend(scan_problems)
        for path in files:
            try:
                stripped = scanner.strip_code(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError) as exc:
                problems.append(f"cannot read Rust source {path.relative_to(ROOT).as_posix()}: {exc}")
                continue
            relative = path.relative_to(ROOT).as_posix()
            for token in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped)):
                index.setdefault(token, set()).add(relative)
    return index, problems


def typed_sidecar_signature(path_text):
    path = Path(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, "typed signature sidecar is missing or invalid JSON"
    checker = checker_module()
    value, _load_problems = checker.strict_json(text, str(path))
    if value is checker.PARSE_FAILED:
        return None, "typed signature sidecar is missing or invalid JSON"
    problems = checker.signature_problems(value)
    if problems:
        return None, "typed signature sidecar is not a typed signature: " + "; ".join(problems)
    return value, None


def main(argv):
    if len(argv) != 4:
        print("usage: privileged-lib-results.py SELECTION VERDICTS OUTPUT HOST", file=sys.stderr)
        return 2
    selection_path = Path(argv[0])
    verdicts_path = Path(argv[1])
    output_path = Path(argv[2])
    host = argv[3]
    if host not in {"fedora", "fedora-sm1", "vng", "github"}:
        print("privileged-lib-results: unknown host", file=sys.stderr)
        return 1
    try:
        selected = [line.strip() for line in selection_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        verdict_rows = []
        for number, line in enumerate(verdicts_path.read_text(encoding="utf-8").splitlines(), 1):
            parts = line.split("\t")
            if len(parts) not in (2, 3):
                print(f"privileged-lib-results: malformed verdict line {number}", file=sys.stderr)
                return 1
            verdict_rows.append(tuple(parts))
    except (OSError, UnicodeDecodeError) as error:
        print(f"privileged-lib-results: cannot read structured records: {error}", file=sys.stderr)
        return 1
    if not selected or len(selected) != len(set(selected)):
        print("privileged-lib-results: selection is empty or duplicated", file=sys.stderr)
        return 1
    verdict_names = [parts[0] for parts in verdict_rows]
    if len(verdict_names) != len(set(verdict_names)) or set(verdict_names) != set(selected):
        print("privileged-lib-results: verdict rows are not exactly one-to-one with the selection", file=sys.stderr)
        return 1
    try:
        files, registry_problems = checker_module().load_ignored_registry(ROOT / "tests/ignored-tests.json")
    except FileNotFoundError as error:
        print(f"privileged-lib-results: cannot read ignored-test registry: {error}", file=sys.stderr)
        return 1
    if registry_problems:
        print(f"privileged-lib-results: cannot read ignored-test registry: {'; '.join(registry_problems)}", file=sys.stderr)
        return 1
    index, index_problems = rust_token_index()
    if index_problems:
        print(f"privileged-lib-results: {'; '.join(index_problems)}", file=sys.stderr)
        return 1
    missing = [name for _path, name in
               ((files.get(name), name) for name in verdict_names) if _path is None]
    if missing:
        for name in missing:
            leaf = name.rsplit("::", 1)[-1]
            candidates = index.get(leaf, set())
            if len(candidates) == 1:
                files[name] = next(iter(candidates))
    selection = []
    results = []
    for parts in verdict_rows:
        name, verdict = parts[0], parts[1]
        if verdict not in VERDICT_STATE:
            print(f"privileged-lib-results: verdict outside the closed vocabulary for {name}", file=sys.stderr)
            return 1
        path = files.get(name)
        if path is None:
            print(f"privileged-lib-results: no unambiguous Rust source path for {name}", file=sys.stderr)
            return 1
        state, signature = VERDICT_STATE[verdict]
        if len(parts) == 3:
            if state == "passed":
                print(f"privileged-lib-results: passing verdict carries a typed failure sidecar for {name}", file=sys.stderr)
                return 1
            signature, error = typed_sidecar_signature(parts[2])
            if error is not None:
                print(f"privileged-lib-results: {error} for {name}", file=sys.stderr)
                return 1
        identity = {"path": path, "test": name, "invocation": []}
        selection.append(identity)
        results.append({**identity, "state": state, "signature": signature})
    document = {
        "schema": "p11scope/known-failing-results/v1",
        "runner": "privileged-lib",
        "host": host,
        "complete": True,
        "selection": selection,
        "results": results,
    }
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output_path)
    except OSError as error:
        print(f"privileged-lib-results: cannot write output: {error}", file=sys.stderr)
        return 1
    print(f"privileged-lib-results: typed {len(results)} selected terminal rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
