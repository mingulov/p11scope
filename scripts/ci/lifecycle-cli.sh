#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# lifecycle-cli.sh P11SCOPE OUTDIR — lifecycle cells entry (S9/S10).
#
# Runs scripts/qualify-lifecycle-cli.sh and validates its results.jsonl:
# every row has cell/pass/qualification/detail, all 9 cells are present
# exactly once, and no qualified cell failed. Exit 0 when every qualified
# cell passes (expected-failures allowed), 1 when a cell fails, 2 on
# harness error, 77 when a prerequisite is missing.
#
# Apt prerequisites (ubuntu-26.04 runner, as root): gcc python3 softhsm2
# procps. Needs passwordless sudo when run as non-root and BTF.
# Expected time: about 3 minutes on the CI host plus guest 6.6.
set -eu
cd "$(dirname "$0")/../.."
P=${1:?usage: lifecycle-cli.sh P11SCOPE OUTDIR}
OUT=${2:?usage: lifecycle-cli.sh P11SCOPE OUTDIR}
case $P in /*) ;; *) P=$PWD/$P ;; esac
test -x "$P" || { echo "no observer binary at $P" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
command -v gcc >/dev/null || { echo "gcc required" >&2; exit 77; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 77; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required" >&2; exit 77; }
if [ "$(id -u)" -ne 0 ]; then
    sudo -n true || { echo "passwordless sudo required" >&2; exit 77; }
fi
if scripts/qualify-lifecycle-cli.sh "$P" "$OUT" > "$OUT/lifecycle.log" 2>&1; then
    RC=0
else
    RC=$?
fi
python3 - "$OUT/results.jsonl" <<'PY'
import json, sys
expected = {"profile-pid-reload", "run-exec-chain", "profile-system-exec-churn",
            "profile-pid-reuse", "prearm-late-dlopen", "prearm-late-dlopen-noflag",
            "track-short-lived-cgroup", "track-short-lived-refused",
            "track-short-lived-pid"}
rows = [json.loads(line) for line in open(sys.argv[1])]
ids = [row["cell"] for row in rows]
assert len(ids) == len(set(ids)) == 9, f"need 9 distinct cells, got {ids}"
assert set(ids) == expected, f"cell set mismatch: {set(ids) ^ expected}"
for row in rows:
    assert isinstance(row["pass"], bool), f"bad pass: {row}"
    assert row["qualification"] in ("qualified", "nonqualifying",
                                    "expected-failure", "failed"), row
    assert isinstance(row["detail"], str) and row["detail"], row
failed = [r["cell"] for r in rows if not r["pass"] and
          r["qualification"] not in ("nonqualifying", "expected-failure")]
if failed:
    print(f"FAILED CELLS: {failed}")
    sys.exit(1)
print(f"lifecycle cells ok: {len(rows)} rows, "
      f"{sum(r['pass'] for r in rows)} passed")
PY
PYRC=$?
cat "$OUT/results.jsonl"
if [ "$PYRC" -ne 0 ]; then exit 1; fi
exit "$RC"
