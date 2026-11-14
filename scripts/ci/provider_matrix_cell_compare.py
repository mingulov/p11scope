#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge one provider-matrix cell (scripts/ci/provider-matrix-cell.sh).

The cell runs the pinned pkcs11-check suite (or a pkcs11-tool probe for
reader-less providers) against one provider in three legs ((a) alone,
(b) under `p11scope run`, (c) under `p11scope run --manifest`), plus a
`p11scope-discover` manifest assertion and a paced ctypes workload under
`p11scope inventory --pid`. This helper judges six rows:

- <provider>-identical-results: suite result sets identical across a/b/c
  (summary counts, per-unit statuses/codes, when=call outcomes);
- <provider>-observer-clean: exits match the base leg, observed.json
  valid v3 on both observer legs;
- <provider>-run-observed: calls attributed to the provider module in
  the manifest leg are > 0, else FAIL as not observed (with the oracle
  call_recall as the coverage figure when an rv-trace oracle exists);
- <provider>-default-run-coverage: nonqualifying record of the default
  (no-manifest) leg's attribution and recall, which short-lived suite
  workers routinely blind;
- <provider>-inventory-pid: the workload pid is a caller AND the provider
  module carries edge calls, else FAIL as not observed;
- the discover row (<provider>-discover, or kryoptic-multi-table for
  kryoptic): discover exit 0 plus the exact pinned surface shape.

Result-set and oracle helpers are reused from
scripts/ci/pkcs11_check_cell_compare.py, not duplicated.

It writes results.jsonl (six rows) and summary.txt, prints details, and
exits 0 when every qualified row passes, 1 when a qualified check fails,
2 on harness errors. PINs never appear in outputs.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_BASE_SPEC = importlib.util.spec_from_file_location(
    "pkcs11_check_cell_compare",
    Path(__file__).resolve().parent / "pkcs11_check_cell_compare.py")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

# Pinned discover shapes: (interface_list.status, ordered surface tuples
# of (source kind, major, minor, function count, walk status)), measured
# with p11scope-discover at dev 2c87d8f10 against the pinned artifacts in
# scripts/provider-matrix/pins.sh. A provider/version pair missing here
# records a nonqualifying row (surfaces printed for the pin commit), so a
# fetch-pin bump without updated expectations cannot silently pass.
EXPECTED_SURFACES = {
    ("kryoptic", "1.5.2"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 3, 0, 92, "full"),
         ("interface", 2, 40, 68, "full")),
    ),
    ("haskoki", "0.5.0.0"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 3, 1, 92, "full"),
         ("interface", 3, 0, 92, "full")),
    ),
    ("softhsm2-2.7", "2.7"): (
        "absent",
        (("legacy_function_list", 3, 2, 68, "full"),),
    ),
    ("softhsm2-2.6", "2.6.1"): (
        "absent",
        (("legacy_function_list", 2, 40, 68, "full"),),
    ),
    ("bouncyhsm", "2.3.2"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 2, 40, 68, "full"),
         ("interface", 3, 1, 92, "full"),
         ("interface", 3, 2, 104, "full")),
    ),
    ("freehsm", "main"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 3, 0, 92, "full")),
    ),
    ("nss-softokn", "system"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 3, 0, 92, "full"),
         ("interface", 2, 40, 68, "full")),
    ),
    ("opensc", "system"): (
        "ok",
        (("legacy_function_list", 2, 20, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 3, 0, 92, "full"),
         ("interface", 2, 20, 68, "known_prefix")),
    ),
    ("p11kit-proxy", "system"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 2, 40, 68, "full")),
    ),
    # The aggregating proxy surface does not depend on the module
    # config: managed and unmanaged rows pin the p11kit-proxy shape.
    ("p11kit-managed", "system"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 2, 40, 68, "full")),
    ),
    ("p11kit-unmanaged", "system"): (
        "ok",
        (("legacy_function_list", 2, 40, 68, "full"),
         ("interface", 3, 2, 104, "full"),
         ("interface", 2, 40, 68, "full")),
    ),
}

# Static-progs Opus review I2: real 3.x providers ship several tables
# (kryoptic FNLIST_240/300/320), so a file-scan discover finds two
# allowlisted candidates and refuses as ambiguous. Fix: emit one legacy
# surface when the candidates agree on every shared function number.
I2_POINTER = ("static-progs Opus review I2 (kryoptic FNLIST_240/300/320: "
              "emit one legacy surface when allowlisted candidates agree)")


def fail(message):
    print(f"provider_matrix_cell_compare: {message}", file=sys.stderr)
    return 2


def load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing {what}: {path}")
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {what} {path}: {error}")


def file_identity(module_path):
    """(sha256 hex, (dev_major, dev_minor), ino) of the provider file."""
    data = Path(module_path).read_bytes()
    stat = Path(module_path).stat()
    return (hashlib.sha256(data).hexdigest(),
            (os.major(stat.st_dev), os.minor(stat.st_dev)), stat.st_ino)


def function_owner_matches(function, sha256, dev, ino):
    """How a functions[] row joins to the provider file, or None.

    sha256 join first; dev/ino only when the row carries no digest
    (unpinned object). module null never joins: the owner is not
    knowable and is never guessed.
    """
    owner = function.get("module")
    if not isinstance(owner, dict):
        return None
    if owner.get("sha256") == sha256:
        return "sha256"
    if owner.get("sha256") is not None:
        return None
    row_dev = owner.get("dev")
    if (isinstance(row_dev, list) and len(row_dev) == 2
            and row_dev[0] == dev[0] and row_dev[1] == dev[1]
            and owner.get("ino") == ino):
        return "dev-ino"
    return None


def judge_run_observed(observed, module_path, oracle=None, capture=None):
    """(pass, detail, recall-or-None) for the run-leg observed row."""
    sha256, dev, ino = file_identity(module_path)
    calls = 0
    rows = 0
    joins = set()
    null_rows = 0
    total_rows = 0
    for function in observed.get("functions", []):
        total_rows += 1
        if not isinstance(function.get("module"), dict):
            null_rows += 1
            continue
        how = function_owner_matches(function, sha256, dev, ino)
        if how is None:
            continue
        calls += int(function.get("calls", 0))
        rows += 1
        joins.add(how)
    join_text = "+".join(sorted(joins)) if joins else "none"
    detail = (f"{calls} calls on {rows} rows via {join_text} join "
              f"({total_rows} rows total, {null_rows} null-module)")
    recall = None
    if oracle is not None and capture is not None:
        mismatches, call_recall, pair_recall, total = _BASE.subset_check(
            oracle, capture)
        if mismatches is None:
            detail += "; oracle logged 0 calls (no recall denominator)"
        else:
            recall = call_recall
            detail += (f"; oracle call_recall={call_recall:.4f} "
                       f"pair_recall={pair_recall:.4f} over {total} calls")
    if calls > 0:
        return True, detail, recall
    return False, f"not observed: {detail}", recall


def inventory_module_ids(inventory, module_path):
    """(ids, how): module ids joining to the provider file.

    sha256 join first. When no digest joins, a row carrying no sha256
    (unpinned object) still joins on an exact path or a recorded
    device/inode identity (same-file proofs, never a basename
    substring): a same-basename module with different bytes does not
    join, and a recorded different digest refuses. Empty ids means the
    module is absent.
    """
    sha256, dev, ino = file_identity(module_path)
    by_sha = {m.get("id") for m in inventory.get("modules", [])
              if isinstance(m.get("identity"), dict)
              and m["identity"].get("sha256") == sha256}
    if by_sha:
        return by_sha, "sha256"
    for module in inventory.get("modules", []):
        if not isinstance(module, dict):
            continue
        identity = module.get("identity")
        digest = (identity.get("sha256")
                  if isinstance(identity, dict) else None)
        if digest is not None:
            continue
        paths = [str(p) for p in module.get("paths", [])]
        if str(module_path) in paths:
            return {module.get("id")}, "path"
        device = identity.get("device") if isinstance(identity, dict) else None
        if (isinstance(device, dict)
                and device.get("major") == dev[0]
                and device.get("minor") == dev[1]
                and identity.get("inode") == ino):
            return {module.get("id")}, "dev-ino"
    return set(), "absent"


def judge_inventory_pid(inventory, module_path, pid):
    """(pass, detail): pid a caller AND provider edges carry calls."""
    ids, how = inventory_module_ids(inventory, module_path)
    calls = 0
    for edge in inventory.get("edges", []):
        if edge.get("module") in ids:
            calls += int((edge.get("entries") or {}).get("count", 0) or 0)
    pid_seen = any(c.get("pid") == pid
                   for c in inventory.get("callers", []))
    pid_gaps = [g.get("reason", "?") for g in inventory.get("gaps", [])
                if g.get("pid") == pid and g.get("reason")]
    detail = (f"module join {how} ({len(ids)} ids), {calls} edge calls, "
              f"workload pid {pid} "
              f"{'seen as caller' if pid_seen else 'not a caller'}")
    if pid_gaps:
        detail += f"; pid gaps: {'; '.join(pid_gaps[:3])}"
    if calls > 0 and pid_seen:
        return True, detail
    return False, f"not observed: {detail}"


def surface_tuples(manifest):
    """Ordered surface tuples, or None when the manifest is malformed."""
    try:
        return tuple(
            (s["source"]["kind"], s["version"]["major"],
             s["version"]["minor"], len(s["functions"]),
             s["walk"]["status"])
            for s in manifest["surfaces"])
    except (KeyError, TypeError):
        return None


def judge_discover(provider, version, rc, manifest, stderr_text):
    """(pass, qualification, detail) for the discover row."""
    expected = EXPECTED_SURFACES.get((provider, version))
    if expected is None:
        if rc != 0:
            return (False, "nonqualifying",
                    f"discover rc={rc}: {stderr_text.strip()[:200]} "
                    f"(surfaces not yet pinned for {provider} {version})")
        tuples = surface_tuples(manifest or {})
        return (True, "nonqualifying",
                f"surfaces recorded, not yet pinned for {provider} "
                f"{version}: status="
                f"{(manifest or {}).get('interface_list', {}).get('status')} "
                f"tuples={tuples}")
    want_status, want_tuples = expected
    if rc != 0 and "ambiguous" in stderr_text.lower() \
            and provider == "kryoptic":
        return (False, "expected-failure",
                f"expected-failure kryoptic-multi-table: discover refused "
                f"the multi-table library as ambiguous ({I2_POINTER}); "
                f"surfaces unasserted")
    if rc != 0:
        return (False, "qualified",
                f"discover rc={rc}: {stderr_text.strip()[:200]}")
    got_status = (manifest or {}).get("interface_list", {}).get("status")
    if got_status != want_status:
        return (False, "qualified",
                f"interface_list.status: want {want_status!r}, "
                f"got {got_status!r}")
    got_tuples = surface_tuples(manifest or {})
    if got_tuples is None:
        return (False, "qualified", "manifest surfaces malformed")
    if got_tuples != want_tuples:
        if len(got_tuples) != len(want_tuples):
            return (False, "qualified",
                    f"surfaces.length: want {len(want_tuples)}, "
                    f"got {len(got_tuples)}")
        index = next(i for i, (want, got)
                     in enumerate(zip(want_tuples, got_tuples))
                     if want != got)
        return (False, "qualified",
                f"surfaces[{index}]: want {want_tuples[index]!r}, "
                f"got {got_tuples[index]!r}")
    return (True, "qualified",
            f"interface_list {got_status}, {len(got_tuples)} surfaces "
            f"as pinned")


def discover_row_name(provider):
    if provider == "kryoptic":
        return "kryoptic-multi-table"
    return f"{provider}-discover"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--provider-version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--discover-rc", required=True, type=int)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--discover-stderr", required=True)
    parser.add_argument("--suite", choices=("yes", "no"), required=True)
    parser.add_argument("--results-a", default=None)
    parser.add_argument("--report-a", default=None)
    parser.add_argument("--exit-a", required=True, type=int)
    parser.add_argument("--wall-a", required=True, type=float)
    parser.add_argument("--results-b", default=None)
    parser.add_argument("--report-b", default=None)
    parser.add_argument("--exit-b", required=True, type=int)
    parser.add_argument("--wall-b", required=True, type=float)
    parser.add_argument("--results-c", default=None)
    parser.add_argument("--report-c", default=None)
    parser.add_argument("--exit-c", required=True, type=int)
    parser.add_argument("--wall-c", required=True, type=float)
    parser.add_argument("--observed-b", required=True)
    parser.add_argument("--observed-c", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--workload-pid", required=True, type=int)
    parser.add_argument("--out-results", required=True)
    parser.add_argument("--out-summary", required=True)
    args = parser.parse_args(argv)
    provider = args.provider

    try:
        if args.suite == "yes":
            for name in ("results_a", "report_a", "results_b", "report_b",
                         "results_c", "report_c"):
                if getattr(args, name) is None:
                    raise SystemExit(f"--{name.replace('_', '-')} "
                                     f"is required with --suite yes")
            ok_ab, detail_ab = _BASE.compare_results(
                args.results_a, args.results_b, "a-vs-b")
            ok_ac, detail_ac = _BASE.compare_results(
                args.results_a, args.results_c, "a-vs-c")
            outcomes_a = _BASE.call_outcomes(args.report_a)
            outcomes_b = _BASE.call_outcomes(args.report_b)
            outcomes_c = _BASE.call_outcomes(args.report_c)
            only_ab, only_ba, diff_ab = _BASE.compare_outcomes(
                outcomes_a, outcomes_b)
            only_ac, only_ca, diff_ac = _BASE.compare_outcomes(
                outcomes_a, outcomes_c)
            outcomes_ok = not (only_ab or only_ba or diff_ab
                               or only_ac or only_ca or diff_ac)
            identical_ok = ok_ab and ok_ac and outcomes_ok
            identical_qual = "qualified"
            identical_detail = (
                f"result sets a-vs-b {'match' if ok_ab else 'DIFFER'}; "
                f"a-vs-c {'match' if ok_ac else 'DIFFER'}; "
                f"when=call outcomes n={len(outcomes_a)} "
                f"only_a_b={len(only_ab)} only_b={len(only_ba)} "
                f"diff_b={len(diff_ab)} only_a_c={len(only_ac)} "
                f"only_c={len(only_ca)} diff_c={len(diff_ac)}")
            if not ok_ab:
                identical_detail += f"; b: {detail_ab[:150]}"
            if not ok_ac:
                identical_detail += f"; c: {detail_ac[:150]}"
        else:
            identical_ok = True
            identical_qual = "nonqualifying"
            identical_detail = ("reader-less provider: no suite; leg exits "
                                "compared by observer-clean")
        print(f"identical-results: {'PASS' if identical_ok else 'FAIL'} "
              f"{identical_detail}")

        capture_b, _, observed_b = _BASE.capture_counts(args.observed_b)
        capture_c, _, observed_c = _BASE.capture_counts(args.observed_c)
        schema_b = observed_b.get("schema", "")
        schema_c = observed_c.get("schema", "")
        schema_ok = schema_b == "p11scope/observed-profile/v3" \
            and schema_c == schema_b
        exits_ok = args.exit_b == args.exit_a and args.exit_c == args.exit_a
        observer_ok = exits_ok and schema_ok
        observer_detail = (
            f"exits a/b/c={args.exit_a}/{args.exit_b}/{args.exit_c} "
            f"(wants b==a and c==a); observed schemas b/c={schema_b}/{schema_c}")
        print(f"observer-clean: {'PASS' if observer_ok else 'FAIL'} "
              f"{observer_detail}")

        # The manifest leg carries the observed gate; the default leg is
        # recorded alongside (short-lived suite workers routinely blind it).
        if args.suite == "yes":
            oracle_b, _, _ = _BASE.oracle_counts(args.report_b)
            oracle_c, _, _ = _BASE.oracle_counts(args.report_c)
        else:
            oracle_b, oracle_c, capture_b, capture_c = None, None, None, None
        run_ok, run_detail, recall = judge_run_observed(
            observed_c, args.module, oracle_c, capture_c)
        _, cov_detail, cov_recall = judge_run_observed(
            observed_b, args.module, oracle_b, capture_b)
        if args.suite == "no":
            run_detail += "; no oracle (tool probe)"
            cov_detail += "; no oracle (tool probe)"
        print(f"run-observed: {'PASS' if run_ok else 'FAIL'} {run_detail}")
        cov_row_detail = f"informational default leg: {cov_detail}"
        print(f"default-run-coverage: {cov_row_detail}")

        inventory = load_json(args.inventory, "inventory")
        pid_ok, pid_detail = judge_inventory_pid(
            inventory, args.module, args.workload_pid)
        print(f"inventory-pid: {'PASS' if pid_ok else 'FAIL'} {pid_detail}")

        try:
            manifest = load_json(args.manifest, "manifest") \
                if args.discover_rc == 0 else None
        except SystemExit:
            manifest = None
        stderr_text = Path(args.discover_stderr).read_text(
            encoding="utf-8", errors="replace")
        disc_ok, disc_qual, disc_detail = judge_discover(
            provider, args.provider_version, args.discover_rc,
            manifest, stderr_text)
        disc_name = discover_row_name(provider)
        print(f"{disc_name}: "
              f"{'PASS' if disc_ok else 'EXPECTED-FAIL' if disc_qual == 'expected-failure' else 'FAIL'} "
              f"{disc_detail}")

        overhead_b = args.wall_b - args.wall_a
        overhead_c = args.wall_c - args.wall_a
        print(f"wall: a={args.wall_a:.1f}s b={args.wall_b:.1f}s "
              f"c={args.wall_c:.1f}s; "
              f"overhead b-a={overhead_b:+.1f}s c-a={overhead_c:+.1f}s")

        rows = [
            {"cell": f"{provider}-identical-results", "pass": identical_ok,
             "qualification": identical_qual,
             "detail": identical_detail[:500]},
            {"cell": f"{provider}-observer-clean", "pass": observer_ok,
             "qualification": "qualified", "detail": observer_detail[:500]},
            {"cell": f"{provider}-run-observed", "pass": run_ok,
             "qualification": "qualified", "detail": run_detail[:500]},
            {"cell": f"{provider}-default-run-coverage", "pass": True,
             "qualification": "nonqualifying",
             "detail": cov_row_detail[:500]},
            {"cell": f"{provider}-inventory-pid", "pass": pid_ok,
             "qualification": "qualified", "detail": pid_detail[:500]},
            {"cell": disc_name, "pass": disc_ok,
             "qualification": disc_qual, "detail": disc_detail[:500]},
        ]
        Path(args.out_results).write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n",
            encoding="utf-8")

        def recall_text(value):
            if value is not None:
                return f"{value:.4f}"
            if args.suite == "no":
                return "n/a (no oracle)"
            return "n/a (oracle empty)"

        summary = (
            f"provider={provider} version={args.provider_version} "
            f"suite={args.suite}\n"
            f"identical-results: {'PASS' if identical_ok else 'FAIL'}\n"
            f"observer-clean: {'PASS' if observer_ok else 'FAIL'}\n"
            f"run-observed: {'PASS' if run_ok else 'FAIL'}\n"
            f"default-run-coverage: {recall_text(cov_recall)} "
            f"(nonqualifying)\n"
            f"inventory-pid: {'PASS' if pid_ok else 'FAIL'}\n"
            f"{disc_name}: "
            f"{'PASS' if disc_ok else 'EXPECTED-FAIL' if disc_qual == 'expected-failure' else 'FAIL'}\n"
            f"run coverage call_recall={recall_text(recall)}\n"
            f"wall a/b/c={args.wall_a:.1f}/{args.wall_b:.1f}/{args.wall_c:.1f}s "
            f"overhead b-a={overhead_b:+.1f}s c-a={overhead_c:+.1f}s\n"
        )
        Path(args.out_summary).write_text(summary, encoding="utf-8")
        print(summary, end="")

        qualified_fail = (
            (not identical_ok and identical_qual == "qualified")
            or not observer_ok or not run_ok or not pid_ok
            or (not disc_ok and disc_qual == "qualified"))
        return 1 if qualified_fail else 0
    except SystemExit as error:
        return fail(str(error))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return fail(f"harness error: {error}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
