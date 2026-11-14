#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge one kryoptic static-embed cell (scripts/provider-matrix/static-embed-cell.sh).

The cell drives a program with kryoptic statically linked (no dlopenable
module): the program self-tests through its embedded table (printing
CALLS=n, the observation oracle), runs once more under `p11scope run`
with default discovery, and faces `p11scope-discover`. This helper judges
three rows:

- kryoptic-static-embed-program-runs: the self-test exits 0 with CALLS>0;
- kryoptic-static-embed-run-observed: calls attributed to the binary in
  the run leg are > 0, else FAIL as not observed (the rv-trace oracle
  does not exist here; the program's own CALLS count is the denominator);
- kryoptic-static-embed-discover: a manifest with at least one surface
  passes; the dlopen refusal fails with the named static gap.

The run/discover joins reuse provider_matrix_cell_compare (same sha256
then dev/ino file-join semantics against the binary path). No manifest
pin exists yet: when a file scan lands, the surfaced shape gets pinned
like the other providers.

It writes results.jsonl (three rows) and summary.txt, prints details, and
exits 0 when every qualified row passes, 1 when a qualified check fails,
2 on harness errors. PINs never appear in outputs.
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
        Path(args.out_results).write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n",
            encoding="utf-8")
        summary = (
            "provider=kryoptic-static-embed\n"
            f"program-runs: {'PASS' if prog_ok else 'FAIL'}\n"
            f"run-observed: {'PASS' if run_ok else 'FAIL'}\n"
            f"discover: {'PASS' if disc_ok else 'FAIL'}\n"
        )
        Path(args.out_summary).write_text(summary, encoding="utf-8")
        print(summary, end="")
        return 0 if (prog_ok and run_ok and disc_ok) else 1
    except SystemExit as error:
        return fail(str(error))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return fail(f"harness error: {error}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
