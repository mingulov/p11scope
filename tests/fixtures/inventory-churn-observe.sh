#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Owned churn observation helper (inventory breadth matrix).
#
# Spawns one anchor driver plus two long-lived churn drivers, waits for
# every readiness marker, then EXECS `p11scope inventory` so the observer
# is every fixture's ancestor (under ptrace_scope=1 only a descendant's
# memory is readable). The test kills fixtures from event-log admission
# conditions mid-run; nothing here sleeps on a fixed deadline, so slow
# passes cannot strand a kill past the last pass.
#
# Environment (all required):
#   INV_DRIVER            catalog-driver binary
#   INV_PROV              provider.so every driver maps
#   INV_READY             directory for READY files (created)
#   INV_OUT               observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN          p11scope binary under test
# Arguments: passed verbatim to `p11scope inventory` (e.g. --system
#   --json --duration 14s --max-scan-pids 4096). Observer stderr
#   (progress) inherits this shell's.
set -eu

: "${INV_DRIVER:?}" "${INV_PROV:?}"
: "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

mkdir -p "$INV_READY"

"$INV_DRIVER" --ready "$INV_READY/anchor.ready" --call --sleep 300 "$INV_PROV" \
    </dev/null >"$INV_READY/anchor.log" 2>&1 &
"$INV_DRIVER" --ready "$INV_READY/churn-a.ready" --sleep 300 "$INV_PROV" \
    </dev/null >"$INV_READY/churn-a.log" 2>&1 &
"$INV_DRIVER" --ready "$INV_READY/churn-b.ready" --sleep 300 "$INV_PROV" \
    </dev/null >"$INV_READY/churn-b.log" 2>&1 &
for name in anchor churn-a churn-b; do
    i=0
    while [ ! -f "$INV_READY/$name.ready" ]; do
        i=$((i + 1))
        if [ "$i" -gt 300 ]; then
            echo "inventory-churn-observe: $name never became ready" >&2
            exit 3
        fi
        sleep 0.1
    done
done

exec "$P11SCOPE_BIN" inventory "$@" > "$INV_OUT"
