#!/bin/sh
set -u
umask 077
functions=$1
ROOT=$2
P11SCOPE_PREPARED_PYTHON=$3
PREPARED_PREFIX=$4
PREPARED_ADMITTED=1
ROOT_ID=$(stat -Lc %d:%i "$ROOT")
FACTS=$ROOT/facts.log
SPID=
LAUNCHING=0
OWNED_RUN_STARTED=1
BODY_COMPLETE=1
FINALIZED=0

. scripts/prepared-dependency-snapshot.sh
. "$functions"

fact() { printf '%s\t%s\n' "$1" "$2" >> "$FACTS"; }
durable() { :; }
validate_root() { [ "$(stat -Lc %d:%i "$ROOT")" = "$ROOT_ID" ]; }
stop_observer() { return 0; }
terminate_owned_harness() {
    printf '%s\n' cleanup >> "$P11SCOPE_LANE02_FINALIZER_EVENTS"
    [ "${P11SCOPE_LANE02_CLEANUP_FAIL-0}" -eq 0 ]
}

cleanup
