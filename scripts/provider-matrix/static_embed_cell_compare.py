#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge one kryoptic static-embed cell (scripts/provider-matrix/static-embed-cell.sh).

The cell drives a program with kryoptic statically linked (no dlopenable
module): the program self-tests through its embedded table (printing
CALLS=n, the observation oracle), runs once more under `p11scope run`
with default discovery, and faces `p11scope-discover`. This helper judges
these rows:

- kryoptic-static-embed-program-runs: the self-test exits 0 with CALLS>0;
- kryoptic-static-embed-run-observed: calls attributed to the binary in
  the run leg are > 0, else FAIL as not observed (the rv-trace oracle
  does not exist here; the program's own CALLS count is the denominator);
- kryoptic-static-embed-discover: a manifest with at least one surface
  passes; the dlopen refusal fails with the named static gap;
- kryoptic-static-embed-getter-manifest (when the cell passes the
  getter leg): `scripts/getter-manifest.py` writes a getter-only
  manifest from the binary's own symbol table and `p11scope run
  --manifest` with it must count the program's table calls, named and
  owned by the binary. Table calls must equal the program's CALLS
  oracle; fewer passes only when the report itself names an observation
  gap (a missed call is never hidden), more always fails (a call counted
  twice).

The run/discover joins reuse provider_matrix_cell_compare (same sha256
then dev/ino file-join semantics against the binary path). No manifest
pin exists yet: when a file scan lands, the surfaced shape gets pinned
like the other providers.

It writes results.jsonl (three rows, four with the getter leg) and
summary.txt, prints details, and exits 0 when every qualified row
passes, 1 when a qualified check fails, 2 on harness errors. PINs never appear in outputs.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_BASE_SPEC = importlib.util.spec_from_file_location(
    "provider_matrix_cell_compare",
    Path(__file__).resolve().parent.parent / "ci"
    / "provider_matrix_cell_compare.py")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

# The product gap behind the run/discover FAILs on this tip: static
# executables embed their tables in the image, and only the unlanded
# static-progs file scan can witness them (table-shapes requirement,
# file-scan path). The rows flip green when that lands; until then they
# fail red with this exact name, never skip.
STATIC_GAP = "static-executable-unobserved"
GAP_POINTER = ("static file-scan unlanded: static-progs lane "
               "(ET_EXEC/PIE executable table witness)")


# Getter rows are not table calls: CALLS counts table calls only.
GETTERS = ("C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList")
UNKNOWN_NAME = "unknown"


def judge_getter_manifest(rc, observed, binary_path, oracle_calls):
    """(pass, detail) for the getter-only manifest run leg."""
    if rc != 0:
        return False, f"getter-manifest.py exit={rc} (wants 0)"
    if observed is None:
        return False, "no observed report from the getter-manifest run"
    if oracle_calls is None:
        return (False, "no CALLS oracle under the getter-manifest run "
                       "(the program failed under observation?)")
    sha256, dev, ino = _BASE.file_identity(binary_path)
    table_calls = 0
    unnamed = 0
    for function in observed.get("functions", []):
        if _BASE.function_owner_matches(function, sha256, dev, ino) is None:
            continue
        names = function.get("names") or []
        calls = int(function.get("calls", 0))
        if any(name in GETTERS for name in names):
            continue
        if not names or UNKNOWN_NAME in names:
            unnamed += calls
            continue
        table_calls += calls
    observation = (((observed.get("evidence") or {}).get("gap_classes") or {})
                   .get("observation") or {}).get("status")
    detail = (f"oracle CALLS={oracle_calls}; {table_calls} named table calls "
              f"on the binary, {unnamed} unnamed; observation={observation}")
    if unnamed:
        return False, f"{detail}; table calls counted without names"
    if table_calls == 0:
        return False, f"not observed: {detail}"
    if table_calls > oracle_calls:
        return False, f"{detail}; more calls than the program made"
    if table_calls < oracle_calls and observation == "exact":
        return False, f"{detail}; calls missed with no observation gap named"
    return True, detail


def fail(message):
    print(f"static_embed_cell_compare: {message}", file=sys.stderr)
    return 2


def load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing {what}: {path}")
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {what} {path}: {error}")


def parse_calls_log(text):
    """The last CALLS=n count in the log, or None when absent/malformed."""
    calls = None
    for line in text.splitlines():
        if line.startswith("CALLS="):
            try:
                calls = int(line[len("CALLS="):])
            except ValueError:
                return None
    return calls


def judge_program_runs(rc, log_text):
    """(pass, detail, calls-or-None) for the direct self-test leg."""
    calls = parse_calls_log(log_text)
    if rc != 0:
        return False, f"self-test exit={rc} (wants 0)", calls
    if calls is None:
        return False, "self-test exit=0 with no CALLS oracle", None
    if calls <= 0:
        return False, f"self-test exit=0 with CALLS={calls} (wants > 0)", calls
    return True, f"self-test exit=0, CALLS={calls}", calls


def judge_static_run_observed(observed, binary_path, oracle_calls):
    """(pass, detail) for the run-leg observed row."""
    if oracle_calls is None:
        return (False,
                "no CALLS oracle under run "
                "(the program failed under observation?)")
    ok, detail, _ = _BASE.judge_run_observed(observed, binary_path)
    detail = f"oracle CALLS={oracle_calls}; {detail}"
    if ok:
        return True, detail
    return False, f"{detail}; gap: {STATIC_GAP} ({GAP_POINTER})"


def judge_static_discover(rc, manifest, stderr_text):
    """(pass, detail) for the discover row."""
    if rc == 0:
        surfaces = (manifest or {}).get("surfaces")
        if isinstance(surfaces, list) and surfaces:
            return (True,
                    f"manifest with {len(surfaces)} surfaces "
                    f"(shape not yet pinned: "
                    f"{_BASE.surface_tuples(manifest or {})})")
        return False, "discover rc=0 but the manifest has no surfaces"
    if "cannot dlopen" in stderr_text:
        return (False,
                f"discover rc={rc}: cannot dlopen a static binary "
                f"({stderr_text.strip()[:160]}); gap: {STATIC_GAP} "
                f"({GAP_POINTER})")
    return False, f"discover rc={rc}: {stderr_text.strip()[:200]}"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--selftest-rc", required=True, type=int)
    parser.add_argument("--selftest-log", required=True)
    parser.add_argument("--observer-out", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--discover-rc", required=True, type=int)
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--discover-stderr", required=True)
    parser.add_argument("--getter-rc", type=int, default=None)
    parser.add_argument("--getter-observed", default=None)
    parser.add_argument("--getter-observer-out", default=None)
    parser.add_argument("--out-results", required=True)
    parser.add_argument("--out-summary", required=True)
    args = parser.parse_args(argv)

    try:
        selftest_text = Path(args.selftest_log).read_text(
            encoding="utf-8", errors="replace")
        prog_ok, prog_detail, _ = judge_program_runs(
            args.selftest_rc, selftest_text)
        print(f"program-runs: {'PASS' if prog_ok else 'FAIL'} {prog_detail}")

        run_text = Path(args.observer_out).read_text(
            encoding="utf-8", errors="replace")
        oracle = parse_calls_log(run_text)
        observed = load_json(args.observed, "observed")
        run_ok, run_detail = judge_static_run_observed(
            observed, args.binary, oracle)
        print(f"run-observed: {'PASS' if run_ok else 'FAIL'} {run_detail}")

        manifest = None
        if args.manifest is not None:
            try:
                manifest = load_json(args.manifest, "manifest")
            except SystemExit:
                manifest = None
        stderr_text = Path(args.discover_stderr).read_text(
            encoding="utf-8", errors="replace")
        disc_ok, disc_detail = judge_static_discover(
            args.discover_rc, manifest, stderr_text)
        print(f"discover: {'PASS' if disc_ok else 'FAIL'} {disc_detail}")

        rows = [
            {"cell": "kryoptic-static-embed-program-runs", "pass": prog_ok,
             "qualification": "qualified", "detail": prog_detail[:500]},
            {"cell": "kryoptic-static-embed-run-observed", "pass": run_ok,
             "qualification": "qualified", "detail": run_detail[:500]},
            {"cell": "kryoptic-static-embed-discover", "pass": disc_ok,
             "qualification": "qualified", "detail": disc_detail[:500]},
        ]
        getter_ok = True
        if args.getter_rc is not None:
            getter_observed = None
            if args.getter_observed is not None:
                try:
                    getter_observed = load_json(args.getter_observed,
                                                "getter observed")
                except SystemExit:
                    getter_observed = None
            getter_oracle = None
            if args.getter_observer_out is not None:
                getter_oracle = parse_calls_log(
                    Path(args.getter_observer_out).read_text(
                        encoding="utf-8", errors="replace"))
            getter_ok, getter_detail = judge_getter_manifest(
                args.getter_rc, getter_observed, args.binary, getter_oracle)
            print(f"getter-manifest: {'PASS' if getter_ok else 'FAIL'} "
                  f"{getter_detail}")
            rows.append({"cell": "kryoptic-static-embed-getter-manifest",
                         "pass": getter_ok, "qualification": "qualified",
                         "detail": getter_detail[:500]})
        Path(args.out_results).write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n",
            encoding="utf-8")
        summary = (
            "provider=kryoptic-static-embed\n"
            f"program-runs: {'PASS' if prog_ok else 'FAIL'}\n"
            f"run-observed: {'PASS' if run_ok else 'FAIL'}\n"
            f"discover: {'PASS' if disc_ok else 'FAIL'}\n"
        )
        if args.getter_rc is not None:
            summary += f"getter-manifest: {'PASS' if getter_ok else 'FAIL'}\n"
        Path(args.out_summary).write_text(summary, encoding="utf-8")
        print(summary, end="")
        return 0 if (prog_ok and run_ok and disc_ok and getter_ok) else 1
    except SystemExit as error:
        return fail(str(error))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return fail(f"harness error: {error}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
