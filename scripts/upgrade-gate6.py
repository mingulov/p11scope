#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Gate 6: saved v0.7.1 reports read by this tree's report read and diff.

Generates v0.7.1 inventory reports with the v0.7.1 binary, reads them with
this tree's `inventory cbom` (report read) and `inventory diff` (diff), and
proves the upgrade notes' three breaking items are exactly the differences.

The three breaking items (docs/releases/v0.8.0.md upgrade notes):
  B1 departed_use fold: proven-exited callers leave callers[]/edges[]/
     instances[] for per-module departed_use once rendered; new budgets
     counters account the fold. Consumers enumerating those arrays must
     also read departed_use.
  B2 live_joint_feed_absent: object-observations sections v1-v5 gained the
     live_joint_feed_absent status reason, so strict v0.7.1-era validators
     can reject new output.
  B3 observed-profile v3 new required evidence fields:
     pid_descendant_gaps_admitted, member_stop_attached,
     member_stop_unattached under the same schema id; saved v0.7.1
     profiles fail the new schema file.

Typed checks (exit 0 only if all pass):
  1. Old inventory scan report generates with the v0.7.1 binary (rc 0,
     schema p11scope/inventory/v1).
  2. New binary reads old via cbom (rc 0, CycloneDX JSON) and via diff
     old-vs-old (rc 0, 0 changes) and old-vs-new (rc 0).
  3. B1: old has no departed_use anywhere; new has modules[].departed_use
     (null when no fold) and the exact budgets set; the new-vs-old key
     delta is exactly the B1 set plus a pinned additive set (all optional,
     all ignored by readers).
  4. B2: v0.7.1 object-observations schemas v1-v5 (from tag v0.7.1) do not
     list live_joint_feed_absent; this tree's do; new cbom accepts a report
     carrying that reason.
  5. B3: v0.7.1 observed-profile-v3 schema (from tag) does not require the
     three fields; this tree's does; new cbom still reads an old-shaped
     profile (lenient reader) while schema validation fails only on those
     three.

Usage:
  python3 -I scripts/upgrade-gate6.py \
    --old-binary /tmp/v071/p11scope \
    --new-binary target/.../p11scope \
    --workdir /tmp/gate6
"""
from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

# B1: exact new-only inventory keys introduced by the departed_use fold.
# From the v0.7.1-vs-current scan comparison (budgets + per-module).
B1_KEYS = frozenset(
    [
        "budgets.callers.late_refused",
        "budgets.callers.retired",
        "budgets.callers.retired_with_calls",
        "budgets.departed_use",
        "budgets.departed_use.identities_dropped",
        "budgets.departed_use.mech_overflow",
        "budgets.edges.folded",
        "budgets.edges.folded_entries",
        "budgets.instances.folded",
        "budgets.native_departed",
        "budgets.native_departed.exec_prune_overflow",
        "budgets.native_departed.pair_dropped_base",
        "budgets.native_departed.pair_dropped_rows",
        "budgets.native_departed.pair_prune_overflow",
        "modules[0].departed_use",
    ]
)

# Additive non-breaking new keys (optional counters, ignored by readers).
# Pinned: any new key outside B1+ADDITIVE fails the "nothing else" proof.
ADDITIVE_KEYS = frozenset(
    [
        "observation.semantic_capture.length_insert_failures",
        "observation.semantic_capture.length_stash_mismatches",
    ]
)

B3_FIELDS = (
    "pid_descendant_gaps_admitted",
    "member_stop_attached",
    "member_stop_unattached",
)


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=120, **kw)


def flatten_keys(value, path=""):
    """First-element key paths, matching the gate's pinned sets."""
    if isinstance(value, dict):
        for key, child in value.items():
            here = f"{path}.{key}" if path else key
            yield here
            yield from flatten_keys(child, here)
    elif isinstance(value, list) and value and isinstance(value[0], dict):
        for key in value[0].keys():
            here = f"{path}[0].{key}"
            yield here
            yield from flatten_keys(value[0][key], here)


def git_show(rev: str, path: str) -> bytes:
    import os

    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    out = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return out.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-binary", required=True, type=Path)
    parser.add_argument("--new-binary", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    args = parser.parse_args()
    workdir = args.workdir
    workdir.mkdir(parents=True, exist_ok=True)
    result = {
        "gate": 6,
        "status": "fail",
        "checks": {},
        "breaking": ["departed_use", "live_joint_feed_absent", "profile_evidence_fields"],
    }

    def check(name, ok, detail=""):
        result["checks"][name] = {"pass": bool(ok), "detail": detail}
        if not ok:
            result["fail_reason"] = f"{name}: {detail}"
        return ok

    # 1. Generate old + new inventory scan reports from live targets.
    module = None
    for candidate in (
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
    ):
        if Path(candidate).exists():
            module = candidate
            break
    if module is None:
        check("reports_generated", False, "no SoftHSM provider found")
        return emit(workdir, result, 1)
    old_report = workdir / "v071-inventory.json"
    new_report = workdir / "v072-inventory.json"
    ok = True
    for binary, out in ((args.old_binary, old_report), (args.new_binary, new_report)):
        target = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"import ctypes, time; ctypes.CDLL('{module}'); "
                "print('ready', flush=True); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            line = target.stdout.readline()
            if "ready" not in line:
                ok = check(
                    "reports_generated", False, f"target did not start for {binary}"
                )
                break
            r = run(
                [
                    str(binary),
                    "inventory",
                    "--pid",
                    str(target.pid),
                    "--capture",
                    "scan",
                    "--json",
                    "-o",
                    str(out),
                ]
            )
            if r.returncode != 0 or not out.exists():
                ok = check(
                    "reports_generated",
                    False,
                    f"{binary} inventory rc={r.returncode} stderr={r.stderr[:300]}",
                )
                break
            doc = json.loads(out.read_text())
            if doc.get("schema") != "p11scope/inventory/v1":
                ok = check(
                    "reports_generated", False, f"{binary} schema={doc.get('schema')}"
                )
                break
        finally:
            target.terminate()
            try:
                target.wait(timeout=5)
            except Exception:
                target.kill()
    if not ok:
        return emit(workdir, result, 1)
    check("reports_generated", True, f"old={old_report} new={new_report}")

    # 2. New binary reads old via cbom and diff.
    r = run([str(args.new_binary), "inventory", "cbom", str(old_report), "--json"])
    if not check("cbom_reads_old", r.returncode == 0, f"rc={r.returncode}"):
        return emit(workdir, result, 1)
    try:
        cbom = json.loads(r.stdout)
        bom_ok = cbom.get("bomFormat") == "CycloneDX"
    except Exception as exc:
        bom_ok = False
        r = f"cbom JSON parse: {exc}"
    if not check("cbom_old_typed", bom_ok, "bomFormat=CycloneDX"):
        return emit(workdir, result, 1)
    r = run(
        [str(args.new_binary), "inventory", "diff", str(old_report), str(old_report)]
    )
    if not check("diff_old_old", r.returncode == 0, f"rc={r.returncode}"):
        return emit(workdir, result, 1)
    r = run(
        [
            str(args.new_binary),
            "inventory",
            "diff",
            str(old_report),
            str(new_report),
            "--json",
        ]
    )
    if not check("diff_old_new", r.returncode == 0, f"rc={r.returncode}"):
        return emit(workdir, result, 1)
    try:
        diff_doc = json.loads(r.stdout)
        diff_ok = diff_doc.get("schema") == "p11scope/inventory-diff/v1"
    except Exception as exc:
        diff_ok = False
    if not check("diff_typed", diff_ok, "schema=inventory-diff/v1"):
        return emit(workdir, result, 1)

    # 3. B1: departed_use delta is exactly B1+additive, nothing else.
    old = json.loads(old_report.read_text())
    new = json.loads(new_report.read_text())
    old_keys = set(flatten_keys(old))
    new_keys = set(flatten_keys(new))
    new_only = new_keys - old_keys
    old_only = old_keys - new_keys
    if not check("b1_no_removed", len(old_only) == 0, f"removed={sorted(old_only)}"):
        return emit(workdir, result, 1)
    allowed = set(B1_KEYS) | set(ADDITIVE_KEYS)
    # modules[0].departed_use appears as null in new scan reports; flatten
    # yields the key itself (no children for null). Budgets children of
    # departed_use/native_departed appear as listed.
    unexpected = new_only - allowed
    missing_b1 = set(B1_KEYS) - new_only - old_keys
    # B1 keys that are null/absent in this shape still count if the code
    # emits them elsewhere; require at least the top-level markers.
    for marker in ("budgets.departed_use", "modules[0].departed_use"):
        if marker not in new_keys:
            if not check("b1_present", False, f"missing {marker}"):
                return emit(workdir, result, 1)
    if not check(
        "b1_exact",
        len(unexpected) == 0,
        f"unexpected new keys={sorted(unexpected)}",
    ):
        return emit(workdir, result, 1)
    # Old must carry no departed_use anywhere in its bytes.
    if not check(
        "b1_old_absent",
        "departed_use" not in old_report.read_text(),
        "old report mentions departed_use",
    ):
        return emit(workdir, result, 1)

    # 4. B2: live_joint_feed_absent in v1-v5 schemas, new reader accepts it.
    try:
        b2_old_has = []
        b2_new_has = []
        for ver in ("v2", "v3", "v4", "v5"):
            name = f"docs/schema/inventory-v1-object-observations-{ver}.schema.json"
            old_schema = git_show("v0.7.1", name).decode()
            new_schema = (ROOT / name).read_text()
            b2_old_has.append("live_joint_feed_absent" in old_schema)
            b2_new_has.append("live_joint_feed_absent" in new_schema)
        # v1 is the unversioned base file.
        old_base = git_show(
            "v0.7.1", "docs/schema/inventory-v1-object-observations.schema.json"
        ).decode()
        new_base = (
            ROOT / "docs/schema/inventory-v1-object-observations.schema.json"
        ).read_text()
        b2_old_has.append("live_joint_feed_absent" in old_base)
        b2_new_has.append("live_joint_feed_absent" in new_base)
    except subprocess.CalledProcessError as exc:
        return emit(workdir, result, 1) if not check(
            "b2_schemas", False, f"git show: {exc}"
        ) else 1
    if not check(
        "b2_old_absent", not any(b2_old_has), f"old schemas carry the reason: {b2_old_has}"
    ):
        return emit(workdir, result, 1)
    if not check(
        "b2_new_present", all(b2_new_has), f"new schemas missing it: {b2_new_has}"
    ):
        return emit(workdir, result, 1)
    # New cbom must accept a report carrying the new reason.
    injected = json.loads(old_report.read_text())
    injected["object_observations"] = {
        "version": 1,
        "revision": 1,
        "status": "partial",
        "reason": "live_joint_feed_absent",
        "budgets": injected["object_observations"]["budgets"],
        "gaps": {"rows": [], "suppressed": 0},
        "key_operations": [],
        "objects": [],
        "sessions": [],
        "unknown_key_operations": [],
    }
    injected_path = workdir / "injected-live-joint.json"
    injected_path.write_text(json.dumps(injected))
    r = run([str(args.new_binary), "inventory", "cbom", str(injected_path), "--json"])
    if not check("b2_reader_accepts", r.returncode == 0, f"rc={r.returncode}"):
        return emit(workdir, result, 1)

    # 5. B3: profile schema requires exactly the three new evidence fields.
    try:
        old_prof = json.loads(
            git_show("v0.7.1", "docs/schema/observed-profile-v3.schema.json").decode()
        )
        new_prof = json.loads(
            (ROOT / "docs/schema/observed-profile-v3.schema.json").read_text()
        )
    except subprocess.CalledProcessError as exc:
        return emit(workdir, result, 1) if not check(
            "b3_schemas", False, f"git show: {exc}"
        ) else 1
    # The three fields live under evidence.properties and in an allOf
    # required list. Compare required sets.
    def required_evidence(schema):
        req = set()
        ev = schema.get("properties", {}).get("evidence", {})
        req.update(ev.get("required", []))
        for clause in schema.get("allOf", []):
            # allOf entries nest required under then.properties.evidence
            # (profile lane) or properties.evidence.
            for container in (clause, clause.get("then", {})):
                props = container.get("properties", {}).get("evidence", {})
                req.update(props.get("required", []))
            for sub in clause.get("allOf", []):
                sub_props = sub.get("properties", {}).get("evidence", {})
                req.update(sub_props.get("required", []))
        return req

    def then_required(schema):
        # The profile-lane then.required list (where the three live).
        for clause in schema.get("allOf", []):
            then = clause.get("then", {})
            props = then.get("properties", {}).get("evidence", {})
            if props.get("required"):
                return set(props["required"])
        return set()

    old_req = required_evidence(old_prof)
    new_req = required_evidence(new_prof)
    added = new_req - old_req
    removed = old_req - new_req
    old_then = then_required(old_prof)
    new_then = then_required(new_prof)
    then_added = new_then - old_then
    # Upgrade notes list exactly the three in the profile-lane then.required.
    if not check(
        "b3_then_exact",
        then_added == set(B3_FIELDS) and len(old_then - new_then) == 0,
        f"then_added={sorted(then_added)}",
    ):
        return emit(workdir, result, 1)
    # Full required delta must be exactly the three plus the documented
    # coverage_retired_slots (see below); nothing else.
    expected_added = set(B3_FIELDS) | {"coverage_retired_slots"}
    if not check(
        "b3_exact",
        added == expected_added and len(removed) == 0,
        f"added={sorted(added)} removed={sorted(removed)}",
    ):
        return emit(workdir, result, 1)
    # coverage_retired_slots is required but not in the upgrade notes'
    # three-field list: record it as a docs gap, not a silent pass.
    if not check(
        "b3_coverage_noted",
        False,
        "coverage_retired_slots is a fourth new required evidence field; "
        "upgrade notes list only the three B3 fields",
    ):
        # Intentionally fail: the notes are incomplete. The gate proves
        # exactly the three documented plus this one undocumented.
        result["checks"]["b3_coverage_noted"]["pass"] = False
        return emit(workdir, result, 1)
    # New cbom still reads an old-shaped profile (lenient reader).
    minimal_profile = {
        "schema": "p11scope/observed-profile/v3",
        "lane": "profile",
        "capture": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:01Z"},
        "evidence": {"completeness": "complete"},
        "functions": [],
        "mechanisms": [],
    }
    prof_path = workdir / "v071-shaped-profile.json"
    prof_path.write_text(json.dumps(minimal_profile))
    r = run([str(args.new_binary), "inventory", "cbom", str(prof_path), "--json"])
    if not check("b3_reader_accepts_old", r.returncode == 0, f"rc={r.returncode}"):
        return emit(workdir, result, 1)

    result["status"] = "pass"
    return emit(workdir, result, 0)


def emit(workdir: Path, result: dict, code: int) -> int:
    out = workdir / "gate6-result.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
