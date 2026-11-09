#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Test-only entry for the p11scope-holder image (deploy/Dockerfile.holder).
#
#   holder-entry ledger ITERS   init a private SoftHSM2 token, then exec the
#                               ledgered `gated` client
#                               (tests/fixtures/public-cli/gated.c): it maps the
#                               provider, sets up a session, prints READY, waits
#                               for /tmp/gate, runs ITERS x {GenerateRandom,
#                               DigestInit, Digest, FindObjectsInit, FindObjects,
#                               FindObjectsFinal}, prints LEDGER and then holds
#                               until SIGTERM (Logout/CloseSession/Finalize only
#                               after that, so they fall outside a capture).
#   holder-entry ledger-private ITERS
#                               the same, but the provider is first copied into
#                               a 0700 directory owned by the (non-root) pod user,
#                               like a vendor library only its application can
#                               read: the observer then needs CAP_DAC_READ_SEARCH
#                               to open it through /proc/<pid>/root.
#   holder-entry copy-up S_ITERS F_ITERS SETTLE_SECS
#                               the kind copy-up negative: stage the provider
#                               into the container's own writable layer, map it
#                               (side S), and hold at /tmp/gate. After release
#                               S ledgers, one unmapped byte is rewritten in
#                               place (same inode: a genuine change, not a
#                               copy-up), the settle delay lets the observer's
#                               ticks see it, then side F maps the changed file
#                               and ledgers. Each side's READY/LEDGER block is
#                               printed once its ledger completes, so the pod
#                               log carries exactly two of each.
#   holder-entry idle           sleep forever without mapping any provider (the
#                               negative control: SoftHSM2 is on disk, unused).
#   holder-entry --self-test    argument checks only.
set -eu

MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
GATED=${HOLDER_GATED:-/usr/local/bin/p11scope-ledger-gated}
PATCHER=${HOLDER_PATCH_UNMAPPED:-/usr/local/bin/p11scope-patch-unmapped}

usage() {
    echo "usage: holder-entry ledger|ledger-private ITERS | holder-entry copy-up S F SECS | holder-entry idle | holder-entry --self-test" >&2
    exit 2
}

valid_iters() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
        *) [ "${#1}" -le 7 ] ;;
    esac
}

valid_secs() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
        *) [ "$1" -ge 1 ] && [ "$1" -le 120 ] ;;
    esac
}

if [ "${1-}" = --self-test ]; then
    for bad in "" "ledger" "ledger 0" "ledger -1" "ledger 01" "ledger x" \
               "ledger 12345678" "ledger 5 extra" "idle extra" "bogus" \
               "ledger-private" "ledger-private 0" "ledger-private 5 extra" \
               "copy-up" "copy-up 1" "copy-up 1 2" "copy-up 0 2 3" \
               "copy-up 1 0 3" "copy-up 1 2 0" "copy-up 01 2 3" \
               "copy-up 1 2 121" "copy-up 1 2 x" "copy-up 1 2 3 extra"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || { echo "holder-entry exited $status (want 2) for: [$bad]" >&2; exit 1; }
    done
    echo "holder-entry self-test: OK"
    exit 0
fi

case ${1-} in
    idle)
        [ "$#" -eq 1 ] || usage
        exec sleep infinity
        ;;
    ledger|ledger-private)
        [ "$#" -eq 2 ] || usage
        valid_iters "$2" || usage
        ITERS=$2
        ;;
    copy-up)
        [ "$#" -eq 4 ] || usage
        valid_iters "$2" || usage
        valid_iters "$3" || usage
        valid_secs "$4" || usage
        S_ITERS=$2
        F_ITERS=$3
        SETTLE=$4
        ;;
    *) usage ;;
esac

# The token lives in the container's own writable /tmp; nothing is shared with
# other pods. The gate file is created by the e2e from the node.
export SOFTHSM2_CONF=/tmp/softhsm2.conf
rm -rf /tmp/tokens /tmp/gate
mkdir -p /tmp/tokens
printf 'directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
    > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label k8s-e2e --so-pin 5678 --pin 1234 >/dev/null
if [ "$1" = ledger-private ]; then
    [ "$(id -u)" -ne 0 ] || { echo "ledger-private must run as a non-root user" >&2; exit 1; }
    rm -rf /tmp/private
    mkdir -m 0700 /tmp/private
    cp "$MODULE" /tmp/private/libsofthsm2.so
    chmod 0500 /tmp/private/libsofthsm2.so
    MODULE=/tmp/private/libsofthsm2.so
fi
if [ "$1" = copy-up ]; then
    # A fresh upper file (not a copy-up of the lower): the later rewrite
    # lands in place on this same inode.
    rm -rf /tmp/copyup
    mkdir /tmp/copyup
    cp "$MODULE" /tmp/copyup/libsofthsm2.so
    MODULE=/tmp/copyup/libsofthsm2.so
    run_side() {
        # Tee: the driver's READY/LEDGER waits read the pod log live
        # while the entry polls the file. gated flushes every line, so
        # no block buffering hides one; if gated dies the tee exits and
        # the liveness check below fails the side loudly.
        rm -f "$1"
        "$GATED" "$MODULE" "$2" 200 /tmp/gate 2>&1 | tee "$1" &
        side_pid=$!
        # No timeout: the driver releases this pod's gate just before
        # the copy-up-neg cell, after the earlier cells and lock waits
        # (an hour or more on a busy host). Hold like the plain ledger
        # mode; the liveness check below still fails a dead side fast,
        # and the driver's ledger checker fails a hung one at the cell.
        while ! grep -q '^LEDGER ' "$1" 2>/dev/null; do
            kill -0 "$side_pid" 2>/dev/null || {
                echo "gated side died before its ledger" >&2
                cat "$1" >&2
                exit 1
            }
            sleep 0.5
        done
    }
    run_side /tmp/s.log "$S_ITERS"
    "$PATCHER" "$MODULE" || exit 1
    sleep "$SETTLE"
    run_side /tmp/f.log "$F_ITERS"
    echo "COPYUP sides complete"
    exec sleep infinity
fi
exec "$GATED" "$MODULE" "$ITERS" 200 /tmp/gate
