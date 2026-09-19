#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Task 4 Lane 16: one fixed owned-run structural row (never or auto).
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
PATH_FIXED=/usr/sbin:/usr/bin:/sbin:/bin

usage() {
    echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT never|auto" >&2
    exit 2
}

self_test() {
    [ "$#" -eq 0 ] || usage
    report=${P11SCOPE_RECEIPT_SELF_TEST_REPORT-}
    if [ -z "$report" ]; then self_tmp=$(mktemp -d); trap 'rm -rf "$self_tmp"' EXIT INT TERM; report=$self_tmp/report.tsv; fi
    umask 077
    python3 -I scripts/lane-receipt-lane16-oracle-1.py "$report" lane16
    echo "verify-receipt-lane16 Task 4 receipt self-test: OK"
}

prepare_root() {
    candidate=$1
    case $candidate in /*) ;; *) return 1 ;; esac
    case $candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    parent=${candidate%/*}; leaf=${candidate##*/}
    [ -n "$parent" ] && [ -n "$leaf" ] && [ -d "$parent" ] || return 1
    ancestor=$parent
    while [ "$ancestor" != / ]; do
        [ ! -L "$ancestor" ] || return 1
        ancestor=${ancestor%/*}; [ -n "$ancestor" ] || ancestor=/
    done
    parent=$(cd "$parent" && pwd -P) || return 1
    [ "$candidate" = "$parent/$leaf" ] || return 1
    here=$(pwd -P)
    case $candidate in "$here"|"$here"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || return 1
    umask 077
    mkdir -m 700 "$candidate" || return 1
    ROOT=$candidate; CAMPAIGN=$parent
    ROOT_ID=$(stat -Lc %d:%i "$ROOT") || return 1
}

digest() { sha256sum "$1" | awk '{print $1}'; }
source_snapshot() {
    case $1 in initial|final) ;; *) return 1 ;; esac
    snapshot=$ROOT/artifacts/source.$1
    git ls-files -z > "$snapshot.unsorted0" || return 1
    sort -z < "$snapshot.unsorted0" > "$snapshot.sorted0" || return 1
    xargs -0 -r sha256sum < "$snapshot.sorted0" > "$snapshot.tracked.sha256" || return 1
    "$P11SCOPE_PREPARED_PYTHON" -I scripts/merge-checksum-ledgers.py \
        "$snapshot.tracked.sha256" "$PREPARED_PREFIX.$1.ledger.sha256"
}
fact() { printf '%s\t%s\n' "$1" "$2" >> "$FACTS"; }

finalize() {
    result=$?
    trap - EXIT INT TERM HUP
    set +e
    [ "$(stat -Lc %d:%i "$ROOT" 2>/dev/null)" = "$ROOT_ID" ] || result=1
    [ "$(stat -Lc %d:%i "$ROOT/artifacts" 2>/dev/null)" = "$ARTIFACTS_ID" ] || result=1
    [ "$(stat -Lc %d:%i "$ROOT/work" 2>/dev/null)" = "$WORK_ID" ] || result=1
    if [ "$result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$HEAD_ID" ] || result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TREE_ID" ] || result=1
        git diff --quiet && git diff --cached --quiet || result=1
        [ "$(digest scripts/verify-receipt-lane16.sh 2>/dev/null)" = "$DRIVER_HASH" ] || result=1
        [ "$(digest scripts/fixtures/hammer.c 2>/dev/null)" = "$HAMMER_SOURCE_HASH" ] || result=1
        [ "$(digest scripts/check-capture-evidence.py 2>/dev/null)" = "$CHECKER_SOURCE_HASH" ] || result=1
        if [ "$PREPARED_ADMITTED" -eq 1 ]; then
            if "$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py recheck \
                --prefix "$PREPARED_PREFIX"; then
                ledger_hash=$(digest "$PREPARED_PREFIX.final.ledger.sha256") \
                    && fact prepared_final_ledger "lane16.prepared.final.ledger.sha256 $ledger_hash" || result=1
                source_snapshot final > "$ROOT/artifacts/source.end.tsv" || result=1
                cmp -s "$ROOT/artifacts/source.start.tsv" "$ROOT/artifacts/source.end.tsv" || result=1
            else
                result=1
            fi
        else
            result=1
        fi
        [ -s "$ROOT/artifacts/observed.json" ] || result=1
        [ -s "$ROOT/artifacts/checker.log" ] || result=1
    fi
    find "$ROOT" -type d -exec chmod 700 {} + 2>/dev/null || result=1
    find "$ROOT" -type f -exec chmod 600 {} + 2>/dev/null || result=1
    python3 -I scripts/lane-receipt-lane16-oracle-2.py "$ROOT" || result=1
    fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || result=1
    fact terminal_status "$result" || result=1
    sync -f "$FACTS" "$ROOT/stdout.log" "$ROOT/stderr.log" 2>/dev/null || result=1
    if [ ! -e "$ROOT/status" ] && [ ! -L "$ROOT/status" ]; then
        printf '%s\n' "$result" > "$ROOT/status" || result=1
        chmod 600 "$ROOT/status" || result=1
        sync -f "$ROOT/status" 2>/dev/null || result=1
    else
        result=1
    fi
    exit "$result"
}

[ "$#" -ge 1 ] || usage
if [ "$1" = --self-test ]; then
    shift
    self_test "$@"
    exit 0
fi
[ "$#" -eq 2 ] || usage
MODE=$2
case $MODE in never|auto) ;; *) usage ;; esac
prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }

FACTS=$ROOT/facts.log
: > "$FACTS"; : > "$ROOT/stdout.log"; : > "$ROOT/stderr.log"
chmod 600 "$FACTS" "$ROOT/stdout.log" "$ROOT/stderr.log"
mkdir -m 700 "$ROOT/artifacts" "$ROOT/work"
ARTIFACTS_ID=$(stat -Lc %d:%i "$ROOT/artifacts")
WORK_ID=$(stat -Lc %d:%i "$ROOT/work")
HEAD_ID= TREE_ID= DRIVER_HASH= HAMMER_SOURCE_HASH= CHECKER_SOURCE_HASH=
PREPARED_ADMITTED=0
PREPARED_PREFIX=$ROOT/artifacts/lane16.prepared
trap finalize EXIT INT TERM HUP

LOCK=$CAMPAIGN/.receipt.lock
[ ! -L "$LOCK" ] || exit 77
exec 9>>"$LOCK"
chmod 600 "$LOCK"
[ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$LOCK")" ] || exit 77
[ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
flock -n 9 || exit 77
LOCK_ID=$(stat -Lc %d:%i "$LOCK")
HEAD_ID=$(git rev-parse HEAD) || exit 77
TREE_ID=$(git rev-parse 'HEAD^{tree}') || exit 77
git diff --quiet && git diff --cached --quiet || exit 77
DRIVER_HASH=$(digest scripts/verify-receipt-lane16.sh)
HAMMER_SOURCE_HASH=$(digest scripts/fixtures/hammer.c)
CHECKER_SOURCE_HASH=$(digest scripts/check-capture-evidence.py)
fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fact argv "$0 $1 $MODE"
fact cwd "$(pwd -P)"
fact uid_gid "$(id -u):$(id -g)"
fact kernel "$(uname -srmo)"
fact head "$HEAD_ID"
fact tree "$TREE_ID"
fact root_identity "$ROOT_ID"
fact artifacts_identity "$ARTIFACTS_ID"
fact work_identity "$WORK_ID"
fact lock_identity "$LOCK_ID"
fact lock_holder "$$:$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, a, " "); print a[20] }' /proc/$$/stat)"
fact driver_sha256 "$DRIVER_HASH"
fact hammer_source_sha256 "$HAMMER_SOURCE_HASH"
fact checker_source_sha256 "$CHECKER_SOURCE_HASH"

for variable in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET \
    CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS; do
    eval "value=\${$variable-}"
    [ -z "$value" ] || { echo "refusing inherited $variable" >&2; exit 77; }
done
for tool in cargo rustc rustup gcc python3 softhsm2-util sudo sha256sum; do
    command -v "$tool" >/dev/null || exit 77
done
[ -r scripts/prepared-dependency-tools.sh ] || exit 77
. scripts/prepared-dependency-tools.sh
p11scope_prepared_tools_select "$(command -v python3)" "$(command -v rustup)" || exit 77
"$P11SCOPE_PREPARED_STABLE_CARGO" --version >/dev/null || exit 77
"$P11SCOPE_PREPARED_STABLE_RUSTC" --version >/dev/null || exit 77
"$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py capture \
    --prefix "$PREPARED_PREFIX" \
    --stable-cargo "$P11SCOPE_PREPARED_STABLE_CARGO" --stable-rustc "$P11SCOPE_PREPARED_STABLE_RUSTC" \
    --bpf-cargo "$P11SCOPE_PREPARED_BPF_CARGO" --bpf-rustc "$P11SCOPE_PREPARED_BPF_RUSTC" || exit 77
PREPARED_ADMITTED=1
ledger_hash=$(digest "$PREPARED_PREFIX.initial.ledger.sha256") || exit 77
fact prepared_initial_ledger "lane16.prepared.initial.ledger.sha256 $ledger_hash"
source_snapshot initial > "$ROOT/artifacts/source.start.tsv" || exit 77
SOURCE_LEDGER_HASH=$(digest "$ROOT/artifacts/source.start.tsv") || exit 77
fact source_input_ledger_sha256 "$SOURCE_LEDGER_HASH"
sudo -n true >/dev/null 2>&1 || exit 77
[ -f "$MODULE" ] && [ ! -L "$MODULE" ] || exit 77

mkdir -m 700 "$ROOT/work/tokens"
cat > "$ROOT/work/softhsm2.conf" <<EOF
directories.tokendir = $ROOT/work/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
chmod 600 "$ROOT/work/softhsm2.conf"
SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" softhsm2-util --init-token --free \
    --label receipt-lane16 --so-pin 1234 --pin 1234 >/dev/null
CARGO_TARGET_DIR="$ROOT/work/target" \
    RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
    P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
    "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --release --workspace --offline \
    > "$ROOT/stdout.log" 2> "$ROOT/stderr.log"
gcc -O0 -o "$ROOT/work/hammer" scripts/fixtures/hammer.c -ldl \
    >> "$ROOT/stdout.log" 2>> "$ROOT/stderr.log"
OBSERVER=$ROOT/work/target/release/p11scope
chmod 700 "$OBSERVER" "$ROOT/work/hammer"
fact cargo_argv "$P11SCOPE_PREPARED_STABLE_CARGO build --locked --release --workspace --offline"
fact cargo_target_dir "$ROOT/work/target"
fact observer_identity "$(stat -Lc %d:%i:%s "$OBSERVER"):$(digest "$OBSERVER")"
fact cargo_identity "$("$P11SCOPE_PREPARED_STABLE_CARGO" --version)|$("$P11SCOPE_PREPARED_STABLE_RUSTC" --version)"

set +e
/usr/bin/env -i PATH="$PATH_FIXED" SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" \
    SUDO_UID="${SUDO_UID-}" SUDO_GID="${SUDO_GID-}" \
    "$OBSERVER" run --module "$MODULE" --mode metrics --duration 30 \
    --kill-on-timeout --pause "$MODE" -o "$ROOT/artifacts/observed.json" -- \
    "$ROOT/work/hammer" "$MODULE" 200000 \
    >> "$ROOT/stdout.log" 2>> "$ROOT/stderr.log"
body_status=$?
set -e
[ "$body_status" -eq 0 ] || exit "$body_status"
python3 -I scripts/lane-receipt-lane16-oracle-3.py "$ROOT/artifacts/observed.json" "$MODE" \
    > "$ROOT/artifacts/checker.log" 2>&1
chmod 600 "$ROOT/artifacts/observed.json" "$ROOT/artifacts/checker.log"
exit 0
