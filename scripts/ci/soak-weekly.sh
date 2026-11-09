#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# soak-weekly.sh P11SCOPE OUTDIR — weekly 1800 s soak entries (S14).
#
# Runs the two long soaks sequentially:
#   system-scope-soak.sh --cell soak.1800s
#   system-manifest-soak.sh --cell soak-manifest.1800s
# and records one results.jsonl row per cell. Exit 0 when both pass,
# 1 when a cell fails, 2 on harness error, 77 when a prerequisite
# is missing.
#
# Proof mode: SOAK_HORIZON=120 SOAK_REQUIRE=120 runs short 120 s
# versions instead (the oracle records the short window; a short PASS
# proves wiring only and never qualifies for the 1800 s cell). Do not
# run the 1800 s version as a proof; it belongs on weekly dispatch.
#
# Weekly dispatch only: the manifest soak fails today on resource
# bounds (120 s proofs: RSS 258 MiB vs the 256 MiB bound, then FD
# growth; product lane, not a harness gap) and must not run per-push
# until that lane lands.
#
# Apt prerequisites (ubuntu-26.04 runner, as root): gcc python3 softhsm2
# procps. Needs passwordless sudo when run as non-root, BTF, and the
# privileged lock for live mode as non-root. Expected time: about
# 70 runner-minutes a week (two 1800 s captures plus slack).
set -eu
cd "$(dirname "$0")/../.."
P=${1:?usage: soak-weekly.sh P11SCOPE OUTDIR}
OUT=${2:?usage: soak-weekly.sh P11SCOPE OUTDIR}
case $P in /*) ;; *) P=$PWD/$P ;; esac
test -x "$P" || { echo "no observer binary at $P" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
HORIZON=${SOAK_HORIZON:-1800}
REQUIRE=${SOAK_REQUIRE:-1800}
command -v gcc >/dev/null || { echo "gcc required" >&2; exit 77; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 77; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required" >&2; exit 77; }
if [ "$(id -u)" -ne 0 ]; then
    sudo -n true || { echo "passwordless sudo required" >&2; exit 77; }
fi
: > "$OUT/results.jsonl"
run_one() {
    cell=$1; script=$2; work=$3
    log="$OUT/$cell.log"
    start=$(date +%s)
    if scripts/"$script" --cell "$cell" --installed "$P" \
        --work "$OUT/$work" --horizon "$HORIZON" \
        --require-duration "$REQUIRE" > "$log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    end=$(date +%s)
    dur=$((end - start))
    if [ "$rc" -eq 0 ]; then
        pass=true; qual=qualified
        detail="$cell passed in ${dur}s (horizon ${HORIZON}s)"
    else
        pass=false; qual=failed
        detail="$cell failed rc=$rc after ${dur}s; see $cell.log"
    fi
    python3 - "$cell" "$pass" "$qual" "$detail" >> "$OUT/results.jsonl" <<'PY'
import json, sys
print(json.dumps({"cell": sys.argv[1], "pass": sys.argv[2] == "true",
                  "qualification": sys.argv[3], "detail": sys.argv[4]}))
PY
    return "$rc"
}
FAIL=0
run_one soak.1800s system-scope-soak.sh soak-scope || FAIL=1
run_one soak-manifest.1800s system-manifest-soak.sh soak-manifest || FAIL=1
cat "$OUT/results.jsonl"
exit "$FAIL"
