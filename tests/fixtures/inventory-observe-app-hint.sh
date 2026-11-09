#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Owned single-target inventory observation helper for app-hint cells.
#
# Like inventory-observe-pid.sh, but the driver is an interpreter script
# (console-script shape) taking a `--pin` value after the provider, so the
# cell proves the pin value is never captured. Spawns the driver, waits for
# its readiness marker, then EXECS `p11scope inventory --pid <its-pid>` so
# the observer is the fixture's parent (under ptrace_scope=1 only a
# descendant's memory is readable). After the exec the helper IS the
# observer; observer stdout goes to INV_OUT.
#
# Environment (all required):
#   INV_DRIVER   fixture driver script (executable, direct shebang)
#   INV_PROV     provider.so the driver maps
#   INV_READY    readiness file the driver writes "READY <pid>" to
#   INV_OUT      observer stdout destination (the JSON/text document)
#   INV_PIN      pin-style value passed after the provider (never captured)
#   P11SCOPE_BIN p11scope binary under test
# Arguments: observer arguments after --pid <pid> (e.g. --capture scan,
#   -o <file>). Observer stderr (progress) inherits this shell's.
set -eu

: "${INV_DRIVER:?}" "${INV_PROV:?}"
: "${INV_READY:?}" "${INV_OUT:?}" "${INV_PIN:?}" "${P11SCOPE_BIN:?}"

rm -f "$INV_READY"
log="$INV_READY.log"
"$INV_DRIVER" --ready "$INV_READY" --call --sleep 30 "$INV_PROV" --pin "$INV_PIN" \
    </dev/null >"$log" 2>&1 &

i=0
while :; do
    if [ -f "$INV_READY" ] && grep -q '^READY [0-9][0-9]*$' "$INV_READY" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "inventory-observe-app-hint: driver never became ready (log: $log)" >&2
        [ -f "$log" ] && tail -5 "$log" >&2
        exit 3
    fi
    sleep 0.1
done
pid=$(sed -n 's/^READY //p' "$INV_READY" | head -1)

# shellcheck disable=SC2086
exec "$P11SCOPE_BIN" inventory --pid "$pid" "$@" > "$INV_OUT"
