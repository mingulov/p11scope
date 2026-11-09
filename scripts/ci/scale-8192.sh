#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# scale-8192.sh P11SCOPE OUTDIR — weekly 8192-endpoint system-scale entry (S7).
#
# Runs scripts/qualify-inventory-native.sh --capacity boundary
# --max-endpoints 8192 once and records the verdict plus wall time in
# OUTDIR/results.jsonl. Exit 0 when the cell passes, 1 when it fails,
# 2 on harness error, 77 when a prerequisite is missing.
#
# Weekly dispatch only: the capacity boundary fails today (verdict
# FAILED fail=230 pass=539 in 548 s; product lane, not a harness gap)
# and must not run per-push until that lane lands.
#
# Apt prerequisites (ubuntu-26.04 runner, as root): gcc python3
# (boundary uses synthetic providers; no SoftHSM needed). Needs
# passwordless sudo when run as non-root, BTF, and a root-owned --base.
# Expected time: about 9 minutes (548 s measured).
set -eu
cd "$(dirname "$0")/../.."
P=${1:?usage: scale-8192.sh P11SCOPE OUTDIR}
OUT=${2:?usage: scale-8192.sh P11SCOPE OUTDIR}
case $P in /*) ;; *) P=$PWD/$P ;; esac
test -x "$P" || { echo "no observer binary at $P" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
command -v gcc >/dev/null || { echo "gcc required" >&2; exit 77; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 77; }
if [ "$(id -u)" -ne 0 ]; then
    sudo -n true || { echo "passwordless sudo required" >&2; exit 77; }
fi
START=$(date +%s)
if [ "$(id -u)" -eq 0 ]; then
    if scripts/qualify-inventory-native.sh "$P" --capacity boundary \
        --max-endpoints 8192 > "$OUT/scale-8192.log" 2>&1; then
        RC=0
    else
        RC=$?
    fi
else
    if sudo -n scripts/qualify-inventory-native.sh "$P" --capacity boundary \
        --max-endpoints 8192 > "$OUT/scale-8192.log" 2>&1; then
        RC=0
    else
        RC=$?
    fi
fi
END=$(date +%s)
DUR=$((END - START))
if [ "$RC" -eq 0 ]; then
    PASS=true
    QUAL=qualified
    DETAIL="capacity boundary 8192 passed in ${DUR}s"
else
    PASS=false
    QUAL=failed
    DETAIL="capacity boundary 8192 failed rc=$RC after ${DUR}s; see scale-8192.log"
fi
python3 - "$PASS" "$QUAL" "$DETAIL" > "$OUT/results.jsonl" <<'PY'
import json, sys
print(json.dumps({"cell": "capacity-boundary-8192",
                  "pass": sys.argv[1] == "true",
                  "qualification": sys.argv[2], "detail": sys.argv[3]}))
PY
cat "$OUT/results.jsonl"
if [ "$RC" -eq 0 ]; then exit 0; else exit 1; fi
