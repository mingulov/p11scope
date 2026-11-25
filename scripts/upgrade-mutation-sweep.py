#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Rerunnable mutation sweep for the upgrade-cell artifact readers.

Each mutation is a small semantic deletion/weakening at one production guard
or validator site.  The harness copies only the upgrade-cell files into an
isolated temporary tree, applies exactly one textual mutation, and runs the
focused test named as that site's killer.  A mutation is killed when the test
returns non-zero; it survives when the focused test remains green.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_MODULE = ["python3", "-I", "tests/python/test_upgrade_cells.py"]
VALIDATOR_TEST = "UpgradeArtifactValidationTests"
GATE5_KILLER = "UpgradeGate5SimulationTests.test_simulated_negative_controls_fail_with_exact_typed_reasons"
GATE6_KILLER = "UpgradeGate6ActivationTests.test_run_gate_activation_negative_controls"

MUTATIONS = [
    {
        "site": "gate5 old capture typed validation",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  validation_detail="$(validate_inventory_report "$WORKDIR/pre-upgrade.json")" || fail "old capture report failed typed validation: $validation_detail"',
        "new": '  validation_detail="typed validation disabled"',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate5 new capture typed validation",
        "file": "scripts/upgrade-gate5.sh",
        "old": '  validation_detail="$(validate_inventory_report "$WORKDIR/post-upgrade.json")" || fail "new capture report failed typed validation: $validation_detail"',
        "new": '  validation_detail="typed validation disabled"',
        "killer": GATE5_KILLER,
    },
    {
        "site": "gate6 inventory_reports_typed verdict",
        "file": "scripts/upgrade-gate6.py",
        "old": "        not inventory_errors,",
        "new": "        True,",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 cbom_old_typed flow validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "        cbom_errors = artifact_validation.cbom_inventory_errors(cbom, old)",
        "new": "        cbom_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 diff_old_old_zero typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            zero_errors = artifact_validation.diff_errors(same_diff, old, old)",
        "new": "            zero_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 diff_typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "        diff_errors = artifact_validation.diff_errors(diff_doc, old, new)",
        "new": "        diff_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 b2 injected cbom typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            cbom_errors = artifact_validation.cbom_inventory_errors(cbom, injected)",
        "new": "            cbom_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "gate6 b3 profile cbom typed validation",
        "file": "scripts/upgrade-gate6.py",
        "old": "            profile_errors = artifact_validation.cbom_profile_errors(cbom, profile_doc)",
        "new": "            profile_errors = []",
        "killer": GATE6_KILLER,
    },
    {
        "site": "inventory root positive-content contract",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    "scope",\n',
        "new": "",
        "killer": f"{VALIDATOR_TEST}.test_inventory_validator_rejects_each_required_root_field",
    },
    {
        "site": "inventory nested observation typing",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '        validate_inventory_observation(document["observation"], errors)',
        "new": "        pass",
        "killer": f"{VALIDATOR_TEST}.test_inventory_validator_rejects_wrong_nested_types",
    },
    {
        "site": "inventory row typing",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "                for index, row in enumerate(rows):\n                    row_validator(row, index, errors)",
        "new": "                pass",
        "killer": f"{VALIDATOR_TEST}.test_inventory_validator_rejects_wrong_nested_types",
    },
    {
        "site": "cbom exact source flow-through comparison",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    for name, wanted in expected.items():",
        "new": "    for name, wanted in {}.items():",
        "killer": GATE6_KILLER,
    },
    {
        "site": "cbom structural root contract",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": 'CBOM_ROOT_FIELDS = ("bomFormat", "specVersion", "metadata", "components", "dependencies")',
        "new": 'CBOM_ROOT_FIELDS = ("bomFormat", "metadata", "components", "dependencies")',
        "killer": f"{VALIDATOR_TEST}.test_cbom_inventory_validator_requires_source_flow_through",
    },
    {
        "site": "diff ten-root-field contract",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": '    "before",\n',
        "new": "",
        "killer": f"{VALIDATOR_TEST}.test_diff_validator_requires_ten_field_typed_document_and_consistency",
    },
    {
        "site": "diff summary exact-count consistency",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "            for key, expected in expected_summary.items():",
        "new": "            for key, expected in {}.items():",
        "killer": f"{VALIDATOR_TEST}.test_diff_validator_requires_ten_field_typed_document_and_consistency",
    },
    {
        "site": "diff snapshot/source exact consistency",
        "file": "scripts/upgrade_artifact_validation.py",
        "old": "    if source is None or not isinstance(snapshot, dict) or not isinstance(source, dict):\n        return",
        "new": "    return",
        "killer": f"{VALIDATOR_TEST}.test_diff_validator_rejects_snapshot_inconsistent_with_source",
    },
]

CONTROL_TESTS = [
    VALIDATOR_TEST,
    "UpgradeGate5SimulationTests",
    "UpgradeGate6ActivationTests",
]


def copy_cell_tree(destination: Path) -> None:
    for relative in (
        "scripts/upgrade-gate5.sh",
        "scripts/upgrade-gate6.py",
        "scripts/upgrade_artifact_validation.py",
        "tests/python/test_upgrade_cells.py",
        "tests/fixtures/upgrade/v071-observed-profile.json",
        "Cargo.toml",
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def mutation_line(path: Path, needle: str) -> int:
    text = path.read_text(encoding="utf-8")
    index = text.index(needle)
    return text[:index].count("\n") + 1


def apply_mutation(tree: Path, mutation: dict) -> None:
    path = tree / mutation["file"]
    text = path.read_text(encoding="utf-8")
    if mutation["old"] not in text:
        raise RuntimeError(f"mutation text absent for {mutation['site']}")
    path.write_text(text.replace(mutation["old"], mutation["new"], 1), encoding="utf-8")


def run_tests(tree: Path, selectors: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*TEST_MODULE, *selectors],
        cwd=tree,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def sweep(mutations: list[dict], timeout: int, keep: bool) -> dict:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="upgrade-mutation-sweep-") as tmp:
        base = Path(tmp)
        control_tree = base / "control"
        control_tree.mkdir()
        copy_cell_tree(control_tree)
        control = run_tests(control_tree, CONTROL_TESTS, timeout)
        results = []
        for index, mutation in enumerate(mutations):
            tree = base / f"mutation-{index}"
            tree.mkdir()
            copy_cell_tree(tree)
            apply_mutation(tree, mutation)
            try:
                completed = run_tests(tree, [mutation["killer"]], timeout)
                output = completed.stdout[-3000:]
                returncode = completed.returncode
                error = ""
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or "")[-3000:] if isinstance(exc.stdout, str) else ""
                returncode = None
                error = f"timeout after {timeout}s"
            original = ROOT / mutation["file"]
            line = mutation_line(original, mutation["old"])
            killed = returncode not in (0, None)
            results.append(
                {
                    "site": mutation["site"],
                    "file": mutation["file"],
                    "line": line,
                    "guard": mutation["old"].strip().replace("\n", " ")[:180],
                    "killer": mutation["killer"],
                    "returncode": returncode,
                    "killed": killed,
                    "error": error,
                    "output_tail": output,
                }
            )
            if not keep:
                shutil.rmtree(tree, ignore_errors=True)
    killed_count = sum(1 for row in results if row["killed"])
    return {
        "control": {
            "selectors": CONTROL_TESTS,
            "returncode": control.returncode,
            "output_tail": control.stdout[-3000:],
        },
        "mutations": results,
        "total": len(results),
        "killed": killed_count,
        "survived": len(results) - killed_count,
        "seconds": round(time.time() - started, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="write machine-readable sweep results")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--keep", action="store_true", help="keep mutated copies inside the sweep tempdir while it exists")
    parser.add_argument("--list", action="store_true", help="validate and list mutation sites without running tests")
    args = parser.parse_args()
    if args.list:
        for mutation in MUTATIONS:
            line = mutation_line(ROOT / mutation["file"], mutation["old"])
            print(f"{mutation['file']}:{line}: {mutation['site']} -> {mutation['killer']}")
        return 0
    result = sweep(MUTATIONS, args.timeout, args.keep)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(f"mutation sweep: {result['killed']}/{result['total']} killed, control rc={result['control']['returncode']}")
    for row in result["mutations"]:
        state = "KILLED" if row["killed"] else "SURVIVED"
        print(f"{state} {row['file']}:{row['line']} {row['site']} ({row['killer']})")
    return 0 if result["control"]["returncode"] == 0 and result["survived"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
