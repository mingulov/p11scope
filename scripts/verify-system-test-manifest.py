#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify acceptance records without executing their declared commands.

The checked-in ledger and mandatory gate catalog are acceptance authority;
a submitted manifest cannot remove a required cell or promote its level.
Receipts attest owned executions. This verifier checks their consistency
and file integrity; it cannot establish the truth of an invented receipt.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "tests/fixtures/system-qualification/closure-ledger.json"
DEFERRED = ROOT / "tests/fixtures/system-qualification/system-deferred-gates.json"
SCHEMA = "p11scope/system-test-manifest/v1"
OUTCOMES = {"PASS", "FAIL", "INVALID", "NOT_RUN", "UNSUPPORTED", "BLOCKED"}
ENTRYPOINTS = {"model": "unit-test", "artifact": "artifact-check",
               "live-mechanism": "private-live-test", "public-command": "public-cli",
               "installed": "installed-cli", "soak": "installed-cli"}
REQUIREMENTS = {f"R{number:02}" for number in range(1, 11)}
CLAIMS = {"system-product", "t7-static"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def catalog():
    policies = {}
    ledger = json.loads(LEDGER.read_text())
    require(isinstance(ledger, dict) and ledger.get("schema") == "p11scope/system-closure-ledger/v1",
            "wrong closure ledger schema")
    findings = ledger.get("findings")
    require(isinstance(findings, list), "closure findings must be a list")
    fields = {"id", "title", "disposition", "owner_task", "check"}
    dispositions = {"source-fixed", "required-open", "accepted-boundary", "refuted", "optional"}
    for finding in findings:
        require(isinstance(finding, dict) and set(finding) == fields
                and all(isinstance(value, str) and value for value in finding.values()),
                "invalid closure finding")
        identifier, title, disposition, owner, check = (
            finding[key] for key in ("id", "title", "disposition", "owner_task", "check"))
        require(disposition in dispositions, f"unknown disposition: {identifier}")
        require("finding:" + identifier not in policies, f"duplicate finding: {identifier}")
        require(owner != "NEEDS-OWNER", f"missing owner: {identifier}")
        level = "live-mechanism" if disposition == "required-open" and owner != "T13" else "artifact"
        policies["finding:" + identifier] = {
            "owner_task": owner, "requirement_ids": ["R10"], "evidence_level": level,
            "kernel_profile": "final-supported-matrix" if level == "live-mechanism" else "ordinary",
            "required_for_claims": [] if disposition == "optional" else ["system-product"],
            "expected_behavior": "regression",
            "limitation": f"{disposition}: {title}. Existing check: {check}. Final execution not recorded."}
    require(len(policies) == 147, "closure ledger inventory changed; review the acceptance catalog")
    deferred = json.loads(DEFERRED.read_text())
    require(deferred.get("schema") == "p11scope/system-deferred-gates/v1", "wrong deferred gate schema")
    groups = deferred["gates"]
    expected = {f"U-{number:02}" for number in range(1, 25)} | {f"G-{number:02}" for number in range(1, 20)}
    require(len(groups) == 43 and {group["id"] for group in groups} == expected,
            "deferred gate inventory changed; all 43 groups are required in the register")
    for group in groups:
        require(group["evidence_level"] in ENTRYPOINTS and group["owner_task"], "invalid deferred gate policy")
        require(group["required"] is (group["id"] not in {"U-23", "G-09"}), "deferred requirement was downgraded")
        policies["followup:" + group["id"]] = {
            "owner_task": group["owner_task"], "requirement_ids": ["R10"], "evidence_level": group["evidence_level"],
            "kernel_profile": "ordinary" if group["evidence_level"] == "artifact" else "final-supported-matrix",
            "required_for_claims": ["system-product"] if group["required"] else [],
            "expected_behavior": "deferred-gate",
            "limitation": f"Review input: {group['review_disposition']} Required check: {group['gate']} No execution claimed."}
    for number, owner in enumerate(["T3/T10", "T2/T10", "T3/T4", "T5/T12", "T4/T6",
                                    "T7", "T8/T9", "T10/T12", "T10", "T11/T12/T13"], 1):
        identifier = f"R{number:02}"
        policies[identifier + ".public"] = {
            "owner_task": owner, "requirement_ids": [identifier], "evidence_level": "public-command",
            "kernel_profile": "final-supported-matrix", "required_for_claims": ["system-product"],
            "expected_behavior": "public-contract",
            "limitation": "Requires public command and independent oracle; concrete tests remain to be registered."}
    for profile, slug in [("default", f"inventory_n{n}_lp64") for n in [576, 1024, 4097, 6530]] + [
            ("default", "inventory_n8192_boundary_lp64"), ("default", "detailed_hot_slot_third_rv_lp64"),
            ("wide", "detailed_hot_slot_third_rv_lp64")]:
        policies[f"T7.{profile}.{slug}"] = {
            "owner_task": "T7", "requirement_ids": ["R06", "R10"], "evidence_level": "live-mechanism",
            "kernel_profile": "current/" + profile, "required_for_claims": ["system-product", "t7-static"],
            "expected_behavior": "expected-refusal" if "n8192" in slug else "capture",
            "limitation": "Private static mechanism only; no public, growth or performance claim."}
    for profile in ["linux-5.15/default", "linux-5.15/wide", "current/default", "current/wide"]:
        policies["installed." + profile.replace("/", ".")] = {
            "owner_task": "T12/T13", "requirement_ids": sorted(REQUIREMENTS), "evidence_level": "installed",
            "kernel_profile": profile, "required_for_claims": ["system-product"],
            "expected_behavior": "installed-contract",
            "limitation": "Install and run final packaging artifact; source-tree binaries are insufficient."}
    for duration in [1800, 14400, 86400]:
        policies[f"soak.{duration}s"] = {
            "owner_task": "T12", "requirement_ids": ["R05", "R06", "R08", "R10"], "evidence_level": "soak",
            "kernel_profile": "current/default", "required_for_claims": ["system-product"],
            "expected_behavior": "continuous-owned-workload", "minimum_duration_s": duration,
            "limitation": "Actual wall time with independent workload/loss and resource accounting required."}
    return policies


def new_manifest():
    cells = []
    for identifier, policy in catalog().items():
        cells.append({"id": identifier, **policy, "test_ids": [], "command": [], "artifact_hashes": {},
                      "evidence_paths": [], "outcome": "NOT_RUN", "receipt": None, "receipt_sha256": None})
    return {"schema": SCHEMA, "ledger_sha256": digest(LEDGER), "deferred_sha256": digest(DEFERRED),
            "subject": None, "cells": cells}


def evidence_path(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            "evidence path must be relative; absolute paths escape custody")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), "evidence path escapes root")
    require(path.is_file(), f"missing evidence artifact: {relative}")
    return path


def verify_pass(row, subject, root):
    label = row["id"]
    require(row["kernel_profile"] != "final-supported-matrix",
            f"{label}: placeholder matrix must be replaced by concrete kernel/profile cells in the catalog")
    require(isinstance(subject, dict) and all(re.fullmatch(r"[0-9a-f]{40}", subject.get(key, ""))
            for key in ["revision", "tree"]), "PASS requires exact source subject")
    require(row["test_ids"] and len(row["test_ids"]) == len(set(row["test_ids"])), f"{label}: empty test/duplicate test IDs")
    require(row["command"] and row["artifact_hashes"] and row["evidence_paths"], f"{label}: empty execution artifacts")
    receipt_path = evidence_path(root, row["receipt"])
    require(digest(receipt_path) == row["receipt_sha256"], f"{label}: receipt hash mismatch")
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get("schema") == "p11scope/test-execution/v1" and receipt.get("cell_id") == label,
            f"{label}: wrong execution receipt")
    require(receipt.get("subject") == subject, f"{label}: receipt subject differs from final build")
    for key in ["evidence_level", "kernel_profile", "test_ids", "command", "artifact_hashes", "evidence_paths"]:
        require(receipt.get(key) == row[key], f"{label}: receipt {key} mismatch")
    require(receipt.get("entrypoint") == ENTRYPOINTS[row["evidence_level"]], f"{label}: false level/entrypoint promotion")
    require(receipt.get("executed_test_ids") == row["test_ids"], f"{label}: missing/wrong executed test IDs")
    require(type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0 and receipt.get("outcome") == "PASS",
            f"{label}: failed exit or receipt outcome")
    require(receipt.get("observed_behavior") == row["expected_behavior"], f"{label}: expected behavior mismatch")
    if row["evidence_level"] in {"installed", "soak"}:
        require(receipt.get("installed_artifact_sha256") == row["artifact_hashes"].get("installed", {}).get("sha256")
                and "installed" in row["artifact_hashes"], f"{label}: missing installed artifact authority")
    if row["evidence_level"] == "soak":
        start, end = receipt.get("start_mono_ns"), receipt.get("end_mono_ns")
        require(type(start) is int and type(end) is int and start >= 0
                and end - start >= row["minimum_duration_s"] * 1_000_000_000, f"{label}: insufficient actual soak duration")
    hashed_paths = set()
    for record in row["artifact_hashes"].values():
        require(isinstance(record, dict) and re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")),
                f"{label}: invalid artifact hash")
        path = evidence_path(root, record["path"])
        require(digest(path) == record["sha256"], f"{label}: artifact hash mismatch: {record['path']}")
        hashed_paths.add(record["path"])
    require(set(row["evidence_paths"]) <= hashed_paths, f"{label}: evidence has no artifact hash")


def verify_manifest(manifest, root, claim="system-product", structure_only=False):
    require(manifest.get("schema") == SCHEMA, "wrong manifest schema")
    require(manifest.get("ledger_sha256") == digest(LEDGER), "closure ledger hash mismatch")
    require(manifest.get("deferred_sha256") == digest(DEFERRED), "deferred gate hash mismatch")
    require(claim in CLAIMS, "unknown acceptance claim")
    policies = catalog()
    rows = manifest.get("cells")
    require(isinstance(rows, list), "cells must be a list")
    identifiers = [row["id"] for row in rows]
    require(len(identifiers) == len(set(identifiers)), "duplicate cell IDs")
    require(set(policies) <= set(identifiers), "missing mandatory acceptance rows")
    require(set(identifiers) <= set(policies), "unregistered acceptance rows; update authority first")
    for row in rows:
        policy = policies[row["id"]]
        require(row["required_for_claims"] == policy["required_for_claims"], "required claim membership changed")
        for key in ["evidence_level", "requirement_ids", "owner_task", "kernel_profile", "expected_behavior"]:
            require(row.get(key) == policy[key], f"{row['id']}: authority {key} mismatch")
        require(row.get("minimum_duration_s") == policy.get("minimum_duration_s"), "soak requirement changed")
        require(row.get("outcome") in OUTCOMES, "unknown cell outcome")
        require(isinstance(row.get("limitation"), str) and row["limitation"], "missing evidence limitation")
        for field in ["test_ids", "command", "evidence_paths"]:
            require(isinstance(row.get(field), list) and all(isinstance(value, str) and value for value in row[field]),
                    f"invalid {field}")
        require(isinstance(row.get("artifact_hashes"), dict), "invalid artifact_hashes")
    selected = [row for row in rows if claim in row["required_for_claims"]]
    if not structure_only:
        for row in selected:
            require(row["outcome"] == "PASS", f"required cell {row['id']}: {row['outcome']}")
    for row in rows:
        if row["outcome"] == "PASS":
            verify_pass(row, manifest.get("subject"), root)
    return {"verdict": "STRUCTURE_VALID" if structure_only else "PASS", "claim": None if structure_only else claim,
            "cells": len(rows), "passed": sum(row["outcome"] == "PASS" for row in selected),
            "required": len(selected), "qualification": not structure_only}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--claim", choices=sorted(CLAIMS), default="system-product")
    parser.add_argument("--check-structure", action="store_true", help="validate an open register; does not qualify a claim")
    args = parser.parse_args()
    try:
        result = verify_manifest(json.loads(args.manifest.read_text()), args.evidence_root,
                                 claim=args.claim, structure_only=args.check_structure)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
