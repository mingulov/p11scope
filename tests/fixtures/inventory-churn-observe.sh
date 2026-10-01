#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned churn observation helper (inventory breadth matrix).
#
# Spawns one anchor driver (killed INV_ANCHOR_KILL_SECS seconds after the
# observer starts) plus a background churn loop spawning INV_CHURNERS
# short-lived drivers, then EXECS `p11scope inventory` so the observer
# is every fixture's ancestor (under ptrace_scope=1 only a descendant's
# memory is readable). Background jobs outlive the exec as the
# observer's children; their stdio is detached so a caller piping this
# script never blocks on them.
#
# Environment (all required):
#   INV_DRIVER            catalog-driver binary
#   INV_PROV              provider.so every driver maps
#   INV_CHURNERS          short-lived drivers to spawn, one per second
#   INV_ANCHOR_KILL_SECS  seconds after observer start to kill the anchor
#   INV_READY             directory for READY files (created)
#   INV_OUT               observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN          p11scope binary under test
# Arguments: passed verbatim to `p11scope inventory` (e.g. --system
#   --json --duration 14s --max-scan-pids 4096). Observer stderr
#   (progress) inherits this shell's.
set -eu

: "${INV_DRIVER:?}" "${INV_PROV:?}" "${INV_CHURNERS:?}"
: "${INV_ANCHOR_KILL_SECS:?}" "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$INV_READY"

"$INV_DRIVER" --ready "$INV_READY/anchor.ready" --call --sleep 300 "$INV_PROV" \
    </dev/null >"$INV_READY/anchor.log" 2>&1 &
i=0
while [ ! -f "$INV_READY/anchor.ready" ]; do
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "inventory-churn-observe: anchor never became ready" >&2
        exit 3
    fi
    sleep 0.1
done
anchor_pid=$(sed -n 's/^READY //p' "$INV_READY/anchor.ready" | head -1)

# Churn loop: one 4-second driver per second, each detached.
(
    i=1
    while [ "$i" -le "$INV_CHURNERS" ]; do
        "$INV_DRIVER" --ready "$INV_READY/churn-$i.ready" --sleep 4 "$INV_PROV" \
            </dev/null >"$INV_READY/churn-$i.log" 2>&1 &
        sleep 1
        i=$((i + 1))
    done
) </dev/null >/dev/null 2>&1 &
( sleep "$INV_ANCHOR_KILL_SECS"; kill "$anchor_pid" ) </dev/null >/dev/null 2>&1 &

exec "$P11SCOPE_BIN" inventory "$@" > "$INV_OUT"
