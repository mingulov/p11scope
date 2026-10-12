#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Gate G1: p11scope attaches at discovered offsets and counts a
# deterministic workload exactly. Oracle: spike/expected.txt, the ground
# truth for spike/harness.c.
#
# Two lanes, same oracle:
#   1. manifest-free — the memory scan is the only source of offsets;
#   2. manifest      — the same manifest the helper produces, corroborated
#                      against the scan (sources ["scan","manifest"], agreed).
set -eu
cd "$(dirname "$0")/.."

# The lane oracle, in one place. `--self-test` runs it over synthetic evidence
# and requires every claimed field to refuse a mutation, unprivileged.
assert_lane_evidence() {
    python3 -I scripts/lane-attach-e2e-oracle.py "$@"
}

diagnose_skips=0
case "$#:${1-}" in
    0:) ;;
    1:--self-test)
        assert_lane_evidence --self-test
        echo "verify-attach-e2e self-test: OK"
        exit 0
        ;;
    1:--diagnose-skips) diagnose_skips=1 ;;
    *) echo "usage: $0 [--self-test | --diagnose-skips]" >&2; exit 2 ;;
esac

P11SCOPE_PRODUCT_BUILD_MODE=${P11SCOPE_PRODUCT_BUILD_MODE:-ordinary}
. scripts/product-build.sh

MODULE=${P11SCOPE_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
WORK=${P11SCOPE_RECEIPT_WORK-target/e2e}
if [ "${P11SCOPE_RECEIPT_WORK+set}" = set ]; then
    case $WORK in /*) ;; *) echo "P11SCOPE_RECEIPT_WORK must be absolute" >&2; exit 2 ;; esac
fi
WPID=
SPID=
. scripts/lib.sh
require_non_root_caller
# See verify-canaries.sh: the observer refuses an output directory with a
# group/world-writable non-sticky ancestor, which this checkout has.
[ "${P11SCOPE_RECEIPT_WORK+set}" = set ] || {
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-verify-XXXXXX")/$WORK
    echo "work root: $WORK"
}
(umask 077; mkdir -p "$WORK")

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    [ -z "$WPID" ] || kill "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
rm -rf "$WORK/build"
set -- --release --workspace --target-dir "$WORK/build"
if [ "$diagnose_skips" -eq 1 ]; then
    set -- "$@" --features skip-attribution
fi
p11scope_product_build "$P11SCOPE_PRODUCT_BUILD_MODE" "$@"
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== softhsm token ==="
# harness.c calls C_GetSlotList(tokenPresent=1, ...) and requires at least
# one initialized token. The system-wide /etc/softhsm/softhsm2.conf and
# /var/lib/softhsm/tokens are root:softhsm-only on this host, so point
# SOFTHSM2_CONF at a private, disposable token store instead of requiring
# host-level SoftHSM setup.
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label e2e --so-pin 1234 --pin 1234 >/dev/null

# One capture, one lane. $1 is the output basename, the rest are the extra
# p11scope arguments this lane adds. The workload dlopens the provider, then
# blocks on the go-file: the scan needs the provider mapped before it runs,
# and the oracle needs every PKCS#11 call to happen after the probes are on.
run_lane() {
    lane=$1
    mode=$2
    shift 2
    rm -f "$WORK/$lane-go"
    "$WORK/harness" "$MODULE" "$WORK/$lane-go" > "$WORK/$lane-workload.log" 2>&1 &
    WPID=$!
    wait_for_mapped_provider "$WPID" libsofthsm2.so
    sudo --preserve-env=SOFTHSM2_CONF "$WORK/build/release/p11scope" profile \
        "$@" --pid "$WPID" \
        --mode metrics --duration 20 -o "$WORK/$lane.json" \
        > "$WORK/$lane.log" 2>&1 &
    SPID=$!
    wait_for_capture_ready "$WORK/$lane.log" aggregate-only metrics
    touch "$WORK/$lane-go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "workload failed: $status"; cat "$WORK/$lane-workload.log"; exit "$status"; fi
    if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "profiler failed: $status"; tail -n 20 "$WORK/$lane.log" || true; exit "$status"; fi
    if [ "$diagnose_skips" -eq 1 ]; then
        # Attribution belongs only in the bounded checker-failure dump below.
        tail -n 3 "$WORK/$lane.log" | sed '/^p11scope: skip-attribution: /d'
    else
        tail -n 3 "$WORK/$lane.log"
    fi
    reclaim_root_output "$WORK/$lane.json"
    if python3 -I scripts/check-capture-evidence.py "$mode" \
        "$WORK/$lane.json" spike/expected.txt; then
        :
    else
        checker_status=$?
        if [ "$diagnose_skips" -eq 1 ]; then
            # Existing internal stderr only, bounded independently of the log.
            # Diagnostic I/O must never replace the checker failure.
            LC_ALL=C awk '
                index($0, "p11scope: skip-attribution: ") == 1 {
                    if (++records > 64) {
                        print "p11scope: skip-attribution: [additional lines clipped]"
                        exit
                    }
                    marker = " [line clipped]"
                    if (length($0) > 2048)
                        print substr($0, 1, 2048 - length(marker)) marker
                    else
                        print
                }
            ' "$WORK/$lane.log" >&2 2>/dev/null || :
        fi
        exit "$checker_status"
    fi
}

echo "=== observe (manifest-free: memory scan only) ==="
run_lane observed-scan clean-metrics
assert_lane_evidence scan "$WORK/observed-scan.json"

echo "=== discover (the helper still produces a manifest, for the corroboration lane) ==="
"$WORK/build/release/p11scope-discover" --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe (manifest corroborated against the scan) ==="
run_lane observed clean-metrics-corroborated --manifest "$WORK/manifest.json"
assert_lane_evidence manifest "$WORK/observed.json"

echo "=== e2e: ALL OK ==="
