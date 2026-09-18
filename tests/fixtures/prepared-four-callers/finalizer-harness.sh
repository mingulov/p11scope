#!/bin/sh
set -u
. scripts/prepared-dependency-snapshot.sh
receipt_digest() { sha256sum "$1" | awk '{print $1}'; }
receipt_fact() { printf '%s\t%s\n' "$1" "$2" >> "$RECEIPT_FACTS"; }

if [ "${P11SCOPE_FINALIZER_ORACLE-0}" -eq 1 ]; then
    P11SCOPE_ORACLE_SOURCE_ONLY=1
    export P11SCOPE_ORACLE_SOURCE_ONLY
    . "$P11SCOPE_FINALIZER_SOURCE"
    oracle_cleanup() {
        : > "$P11SCOPE_FINALIZER_CLEANUP_MARKER"
        return "$P11SCOPE_FINALIZER_CLEANUP_STATUS"
    }
    receipt_terminal_checks() { return 0; }
else
    . "$P11SCOPE_FINALIZER_FUNCTIONS"
    : > "$P11SCOPE_FINALIZER_CLEANUP_MARKER"
fi

set +e
if [ "$P11SCOPE_FINALIZER_INITIAL_STATUS" -eq 0 ]; then
    true
else
    (exit "$P11SCOPE_FINALIZER_INITIAL_STATUS")
fi
receipt_finalize
