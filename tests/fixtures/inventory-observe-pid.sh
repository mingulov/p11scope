#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Owned single-target inventory observation helper.
#
# Spawns one fixture driver, waits for its readiness marker, then EXECS
# `p11scope inventory --pid <its-pid>` so the observer is the fixture's
# parent (under ptrace_scope=1 only a descendant's memory is readable).
# After the exec the helper IS the observer; lifecycle timing (exec,
# unload/reload, self-SIGKILL) is driven by the fixture itself, so
# multi-pass observations need no test-side orchestration mid-run.
#
# Environment (all required):
#   INV_DRIVER   fixture driver binary for INV_MODE
#   INV_MODE     exec | reload | suicide | plain
#   INV_PROV     provider.so the driver maps
#   INV_READY    readiness file the driver appends "READY <pid>" to
#   INV_OUT      observer stdout destination (the JSON/text document)
#   P11SCOPE_BIN p11scope binary under test
# Arguments: observer arguments after --pid <pid> (e.g. --json,
#   --duration 10s, -o <file>). Observer stderr (progress) inherits
#   this shell's.
set -eu

: "${INV_DRIVER:?}" "${INV_MODE:?}" "${INV_PROV:?}"
: "${INV_READY:?}" "${INV_OUT:?}" "${P11SCOPE_BIN:?}"

rm -f "$INV_READY"
log="$INV_READY.log"
case "$INV_MODE" in
    exec)
        "$INV_DRIVER" --ready "$INV_READY" "$INV_PROV" /bin/sleep 300 \
            </dev/null >"$log" 2>&1 &
        ;;
    reload | suicide)
        "$INV_DRIVER" --ready "$INV_READY" "$INV_PROV" \
            </dev/null >"$log" 2>&1 &
        ;;
    plain)
        "$INV_DRIVER" --ready "$INV_READY" --call --sleep 30 "$INV_PROV" \
            </dev/null >"$log" 2>&1 &
        ;;
    *)
        echo "inventory-observe-pid: unknown INV_MODE $INV_MODE" >&2
        exit 2
        ;;
esac

i=0
while :; do
    if [ -f "$INV_READY" ] && grep -q '^READY [0-9][0-9]*$' "$INV_READY" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "inventory-observe-pid: driver never became ready (log: $log)" >&2
        [ -f "$log" ] && tail -5 "$log" >&2
        exit 3
    fi
    sleep 0.1
done
pid=$(sed -n 's/^READY //p' "$INV_READY" | head -1)

# shellcheck disable=SC2086
exec "$P11SCOPE_BIN" inventory --pid "$pid" "$@" > "$INV_OUT"
