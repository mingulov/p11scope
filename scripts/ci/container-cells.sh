#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# scripts/ci/container-cells.sh P11SCOPE OUTDIR — S8 container cells on hosted runners.
#
# Apt prerequisites (ubuntu-26.04): docker.io gcc python3 softhsm2 libsofthsm2
# libcap2-bin gnu-coreutils. Plus: cargo (Rust toolchain, for the harness cargo
# presence check), systemd, util-linux and coreutils (preinstalled), passwordless
# sudo, BTF (/sys/kernel/btf/vmlinux) and cgroup v2. Docker and cargo are
# preinstalled on the GitHub runner; the workflow apt-installs the rest.
#
# Cells (each one row in OUTDIR/results.jsonl):
#   docker            scripts/matrix/verify-docker.sh with P11SCOPE_BIN
#   shared-layer      scripts/matrix/verify-shared-layer.sh with P11SCOPE_BIN
#   pidns             scripts/matrix/verify-pidns.sh via sudo (9 subcells)
#   fork-scope        scripts/matrix/verify-fork-scope.sh with P11SCOPE_BIN
#   d1                scripts/docker-shared-layer-e2e.sh --host dev (copy-up)
# All run under their existing oracles. kind (verify-kind-pod.sh) is weekly
# only and is NOT run here; its command is:
#   P11SCOPE_BIN=/abs/p11scope scripts/matrix/verify-kind-pod.sh
#
# The copy-up misattribution (R-41, OD24) ships as a disclosed known issue:
# this entry point asserts the disclosure (KNOWN_ISSUE copy-up-stale-caller in
# the D1 facts log), not its absence. A D1 run without the disclosure fails.
#
# Exit codes: 0 every qualified cell passed; 1 a cell failed; 2 harness error;
# 77 a prerequisite is missing. Rows are JSON lines:
# {"cell": str, "pass": bool, "qualification": "qualified"|"nonqualifying"|"failed", "detail": str}
# "nonqualifying" marks a cell that could not run (missing prerequisite);
# there are no expected-failure cells here.
#
# Wiring: run as a non-root user with passwordless sudo. This entry point
# cannot run through scripts/ci/run-cell-script.sh as written: that template
# requires root and runs the cell as root, while this script and its subcells
# (verify-docker, verify-shared-layer, d1; fork-scope has no caller check but
# runs under this entry point) require a non-root caller. Wire it direct in
# the workflow (non-root caller, then validate OUTDIR/results.jsonl with
# scripts/ci/check-cell-results.py, which needs WP-1's fixed checker with
# --require), or add a non-root mode to the template on port.
set -u
cd "$(dirname "$0")/../.." || exit 2

P11SCOPE=${1-}
OUTDIR=${2-}
[ -n "$P11SCOPE" ] && [ -n "$OUTDIR" ] && [ "$#" -eq 2 ] || {
    echo "usage: $0 P11SCOPE OUTDIR" >&2
    exit 2
}
case $P11SCOPE in
    /*) ;;
    *) echo "P11SCOPE must be absolute: $P11SCOPE" >&2; exit 2 ;;
esac
[ -f "$P11SCOPE" ] && [ -x "$P11SCOPE" ] || {
    echo "P11SCOPE is not an executable file: $P11SCOPE" >&2
    exit 2
}
mkdir -p "$OUTDIR" 2>/dev/null || { echo "cannot create OUTDIR: $OUTDIR" >&2; exit 2; }
OUTDIR=$(cd "$OUTDIR" && pwd -P) || { echo "cannot resolve OUTDIR: $OUTDIR" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || {
    echo "run as a non-root user with passwordless sudo (pidns runs via sudo)" >&2
    exit 2
}

# Preflight: missing prerequisites exit 77 before any cell runs.
for tool in bash docker gcc python3 softhsm2-util systemd-run capsh setpriv unshare nsenter sudo; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 77; }
done
if command -v gnutimeout >/dev/null 2>&1; then
    :
elif timeout --version 2>/dev/null | head -n 1 | grep -q "GNU coreutils"; then
    :
else
    echo "GNU coreutils timeout required (gnutimeout or GNU timeout)" >&2
    exit 77
fi
sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 77; }
# P11SCOPE_CONTAINER_CELLS_MODULE/BTF/CGROUP are test hooks for the Python
# suite (a stub path that must still exist); production leaves them unset.
if [ -n "${P11SCOPE_CONTAINER_CELLS_MODULE-}" ]; then
    MODULE_PROBED=$P11SCOPE_CONTAINER_CELLS_MODULE
    [ -f "$MODULE_PROBED" ] || { echo "SoftHSM2 not installed (probed Debian/Fedora paths)" >&2; exit 77; }
elif command -v python3 >/dev/null 2>&1 && MODULE_PROBED=$(python3 -I scripts/release-matrix-contract.py --select-module 2>/dev/null); then
    :
else
    MODULE_PROBED=
    for candidate in /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so /usr/lib64/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so; do
        if [ -f "$candidate" ]; then MODULE_PROBED=$candidate; break; fi
    done
    unset candidate
fi
[ -n "$MODULE_PROBED" ] || { echo "SoftHSM2 not installed (probed Debian/Fedora paths)" >&2; exit 77; }
unset MODULE_PROBED
docker info >/dev/null 2>&1 || { echo "docker daemon unavailable (docker info failed)" >&2; exit 77; }
BTF_PATH=${P11SCOPE_CONTAINER_CELLS_BTF:-/sys/kernel/btf/vmlinux}
CGROUP_PATH=${P11SCOPE_CONTAINER_CELLS_CGROUP:-/sys/fs/cgroup/cgroup.controllers}
test -s "$BTF_PATH" || { echo "BTF unavailable ($BTF_PATH)" >&2; exit 77; }
test -f "$CGROUP_PATH" || { echo "cgroup v2 unavailable" >&2; exit 77; }
unset BTF_PATH CGROUP_PATH
DISCOVER=${P11SCOPE_DISCOVER_BIN:-${P11SCOPE%/*}/p11scope-discover}
[ -f "$DISCOVER" ] && [ -x "$DISCOVER" ] || {
    echo "p11scope-discover missing beside P11SCOPE (or set P11SCOPE_DISCOVER_BIN): $DISCOVER" >&2
    exit 77
}

: >"$OUTDIR/results.jsonl"
FAILED=0
MISSING=0

record() {
    python3 - "$OUTDIR/results.jsonl" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
path, cell, passed, qualification, detail = sys.argv[1:6]
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"cell": cell, "pass": passed == "1",
                             "qualification": qualification, "detail": detail}) + "\n")
PY
}

echo "=== cell: docker ==="
if P11SCOPE_BIN="$P11SCOPE" sh scripts/matrix/verify-docker.sh >"$OUTDIR/docker.log" 2>&1; then
    record docker 1 qualified "exact counts, provider pinned via /proc/pid/root"
else
    rc=$?
    if [ "$rc" -eq 77 ]; then
        record docker 0 nonqualifying "prerequisite missing (see docker.log)"
        MISSING=1
    elif [ "$rc" -eq 2 ]; then
        record docker 0 failed "harness error (see docker.log)"
        echo "harness error in docker cell" >&2
        exit 2
    else
        record docker 0 failed "exit $rc (see docker.log)"
        FAILED=1
    fi
    unset rc
fi

echo "=== cell: shared-layer ==="
if P11SCOPE_BIN="$P11SCOPE" P11SCOPE_DISCOVER_BIN="$DISCOVER" sh scripts/matrix/verify-shared-layer.sh >"$OUTDIR/shared-layer.log" 2>&1; then
    record shared-layer 1 qualified "broad 2x plus leaf exactness, collapse uncertainties disclosed"
else
    rc=$?
    if [ "$rc" -eq 77 ]; then
        record shared-layer 0 nonqualifying "prerequisite missing (see shared-layer.log)"
        MISSING=1
    elif [ "$rc" -eq 2 ]; then
        record shared-layer 0 failed "harness error (see shared-layer.log)"
        echo "harness error in shared-layer cell" >&2
        exit 2
    else
        record shared-layer 0 failed "exit $rc (see shared-layer.log)"
        FAILED=1
    fi
    unset rc
fi

echo "=== cell: pidns ==="
# verify-pidns.sh is bash (arrays); invoke via bash, not sh. The redirect stays
# outside sudo deliberately: the caller owns OUTDIR/pidns.log.
# shellcheck disable=SC2024
if sudo -n bash scripts/matrix/verify-pidns.sh "$P11SCOPE" "$OUTDIR/pidns" >"$OUTDIR/pidns.log" 2>&1; then
    if python3 -c 'import json,sys; rows=[json.loads(l) for l in open(sys.argv[1])]; sys.exit(0 if len(rows)==9 and all(r["pass"] for r in rows) else 1)' "$OUTDIR/pidns/results.jsonl" 2>/dev/null; then
        record pidns 1 qualified "9/9 subcells passed (refusals named, cgroup lossy, trace initial PIDs)"
    else
        record pidns 0 failed "subcell failure despite exit 0 (see pidns/results.jsonl)"
        FAILED=1
    fi
else
    rc=$?
    if [ "$rc" -eq 77 ]; then
        record pidns 0 nonqualifying "prerequisite missing (see pidns.log)"
        MISSING=1
    elif [ "$rc" -eq 64 ]; then
        record pidns 0 failed "harness error: root/sudo unavailable (see pidns.log)"
        echo "harness error in pidns cell" >&2
        exit 2
    else
        failed_cells=$(python3 -c 'import json; print(",".join(r["cell"] for r in (json.loads(l) for l in open("'"$OUTDIR"'/pidns/results.jsonl")) if not r["pass"]))' 2>/dev/null) || failed_cells="unknown"
        [ -n "$failed_cells" ] || failed_cells="exit $rc before any subcell"
        record pidns 0 failed "exit $rc, failed: $failed_cells"
        FAILED=1
        unset failed_cells
    fi
    unset rc
fi

echo "=== cell: fork-scope ==="
if P11SCOPE_BIN="$P11SCOPE" P11SCOPE_DISCOVER_BIN="$DISCOVER" sh scripts/matrix/verify-fork-scope.sh >"$OUTDIR/fork-scope.log" 2>&1; then
    record fork-scope 1 qualified "exact counts across prefork children, privileges measured"
else
    rc=$?
    if [ "$rc" -eq 77 ]; then
        record fork-scope 0 nonqualifying "prerequisite missing (see fork-scope.log)"
        MISSING=1
    elif [ "$rc" -eq 2 ]; then
        record fork-scope 0 failed "harness error (see fork-scope.log)"
        echo "harness error in fork-scope cell" >&2
        exit 2
    else
        record fork-scope 0 failed "exit $rc (see fork-scope.log)"
        FAILED=1
    fi
    unset rc
fi

echo "=== cell: d1 ==="
rm -rf "$OUTDIR/d1"
if sh scripts/docker-shared-layer-e2e.sh --host dev --observer "$P11SCOPE" --work "$OUTDIR/d1" --iters-a 400 --iters-b 250 --duration 30 --span 60 >"$OUTDIR/d1.log" 2>&1; then
    if grep -q "KNOWN_ISSUE cell=D1 copy-up-stale-caller" "$OUTDIR/d1/facts.log" 2>/dev/null; then
        record d1 1 qualified "copy-up disclosed (KNOWN_ISSUE copy-up-stale-caller, R-41)"
    else
        record d1 0 failed "disclosure missing: R-41 KNOWN_ISSUE not in d1/facts.log"
        FAILED=1
    fi
else
    rc=$?
    if [ "$rc" -eq 3 ]; then
        reason=$(grep "^SUMMARY" "$OUTDIR/d1.log" 2>/dev/null | tail -n 1) || reason="UNRUN"
        [ -n "$reason" ] || reason="UNRUN (see d1.log)"
        record d1 0 nonqualifying "$reason"
        MISSING=1
        unset reason
    elif [ "$rc" -eq 2 ]; then
        record d1 0 failed "harness error (see d1.log)"
        echo "harness error in d1 cell" >&2
        exit 2
    else
        record d1 0 failed "exit $rc (see d1.log)"
        FAILED=1
    fi
    unset rc
fi

python3 -c 'import json; r=[json.loads(l) for l in open("'"$OUTDIR"'/results.jsonl")]; print("SUMMARY pass=%d fail=%d nonqualifying=%d failed=%s" % (sum(x["pass"] for x in r), sum(not x["pass"] and x["qualification"]=="failed" for x in r), sum(x["qualification"]=="nonqualifying" for x in r), [x["cell"] for x in r if not x["pass"]]))'
if [ "$FAILED" -ne 0 ]; then exit 1; fi
if [ "$MISSING" -ne 0 ]; then exit 77; fi
exit 0
