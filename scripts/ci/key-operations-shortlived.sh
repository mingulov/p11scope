#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# key-operations-shortlived.sh — short-lived callers counted, never silent.
#
# Runs `inventory --system --key-operations --module` for DURATION
# seconds beside N_CALLERS sequential SoftHSM signers (each init,
# login, one early sign, sleep, exit), then judges the two terminal
# miss gaps against a recomputation from the published records
# (scripts/ci/key_operations_shortlived_checks.py). The signers sleep
# SLEEP_MS (default 6000): their single call happens pre-admission
# and sheds, which is the miss the gaps count. True one-shot
# processes (tens of milliseconds) exit before any scan examines
# them and land in the aggregate never-scanned gap instead; see the
# known limitations. A gated seed maps the provider before the
# observer starts: with --module, zero resident mappers means zero
# attach endpoints and the semantic lane never seals. The seed idles
# (no calls) and stays live through the stop, so the oracle ignores
# it. Rows:
#   shortlived-shaped  vacuity and shape: fixture callers
#                  discovered, all retired, the miss path hit
#   shortlived-counted gap conservation: each published gap
#                  count within [fixture, fixture+ambient]
#
# Usage: flock "$LOCK" scripts/ci/key-operations-shortlived.sh P11SCOPE OUTDIR
# OUTDIR receives results.jsonl plus per-run evidence. Exit codes: 0
# every qualified row passed; 1 a row failed; 2 a harness error; 77 a
# prerequisite is missing.
#
# Environment: MODULE (default: release-matrix-contract --select-module),
# LOCK, DURATION (default 90), SETTLE_S (default 2), N_CALLERS
# (default 6), SLEEP_MS (default 6000), PIN (default 1234), TMPDIR.
#
# Apt prerequisites on an ubuntu-26.04 runner: gcc, softhsm2,
# libp11-kit-dev (a real pkcs11.h), python3, sudo, flock (util-linux).
#
# Self-test-only knobs (production runs leave them unset):
# KEYOPS_SL_SELFTEST_NO_PRIV=1 (drop root, sudo and lock checks),
# KEYOPS_SL_SELFTEST_SIGNER_BIN, KEYOPS_SL_SELFTEST_KEYGEN_BIN,
# KEYOPS_SL_SELFTEST_GATED_BIN (fake fixture binaries),
# KEYOPS_SL_SELFTEST_SCENARIO (the fake observer's canned doc).
# Suite: tests/python/test_key_operations_shortlived.py.
set -eu
cd "$(dirname "$0")/../.."
REPO=$PWD
. scripts/lib.sh

LOCK=${LOCK:-/var/tmp/p11scope-ws-tmp/privileged.lock}
DURATION=${DURATION:-90}
SETTLE_S=${SETTLE_S:-2}
N_CALLERS=${N_CALLERS:-6}
SLEEP_MS=${SLEEP_MS:-6000}
PIN=${PIN:-1234}
SEAL_LINE="p11scope: semantic lane ready"
SELFTEST=${KEYOPS_SL_SELFTEST_NO_PRIV:-0}

is_positive_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

is_non_negative_int() {
    case $1 in ''|*[!0-9]*) return 1 ;; esac
    return 0
}

say() { echo "key-operations-shortlived: $*"; }
die() { echo "key-operations-shortlived: harness error: $*" >&2; exit 2; }
missing() { echo "key-operations-shortlived: missing prerequisite: $*" >&2; exit 77; }

[ "$#" -eq 2 ] || { echo "usage: $0 P11SCOPE OUTDIR" >&2; exit 2; }
P11SCOPE=$1 OUTDIR=$2
[ -x "$P11SCOPE" ] || { echo "usage: P11SCOPE is not executable: $P11SCOPE" >&2; exit 2; }
is_positive_int "$DURATION" || { echo "usage: DURATION is a positive integer" >&2; exit 2; }
is_non_negative_int "$SETTLE_S" || { echo "usage: SETTLE_S is a non-negative integer" >&2; exit 2; }
is_positive_int "$N_CALLERS" || { echo "usage: N_CALLERS is a positive integer" >&2; exit 2; }
is_non_negative_int "$SLEEP_MS" || { echo "usage: SLEEP_MS is a non-negative integer" >&2; exit 2; }
case $P11SCOPE in /*) : ;; *) P11SCOPE=$REPO/$P11SCOPE ;; esac
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

CHECKS=$REPO/scripts/ci/key_operations_shortlived_checks.py
SIGNER_SRC=$REPO/tests/fixtures/shortlived-sign/shortlived-sign.c
KEYGEN_SRC=$REPO/tests/fixtures/shortlived-sign/shortlived-keygen.c
GATED_SRC=$REPO/tests/fixtures/public-cli/gated.c

WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-keyops-shortlived-XXXXXX")
chmod 0700 "$WORK"
BIN=$WORK/bin
mkdir -p "$BIN"

OBSERVER_PID=
SEED_PID=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$SEED_PID" ] || kill -TERM "$SEED_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || kill -TERM "$OBSERVER_PID" 2>/dev/null || true
    [ -z "$SEED_PID" ] || wait "$SEED_PID" 2>/dev/null || true
    [ -z "$OBSERVER_PID" ] || wait "$OBSERVER_PID" 2>/dev/null || true
    exit "$status"
}
. scripts/cleanup-traps.sh

row() {
    python3 -I - "$OUTDIR/results.jsonl" "$1" "$2" "$3" "$4" <<'EOF' || die "results write failed"
import json, sys
path, cell, passed, qual, detail = sys.argv[1:6]
row = {"cell": cell, "pass": passed == "1",
       "qualification": qual, "detail": detail}
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(row) + "\n")
print(json.dumps(row))
EOF
}

if [ "$SELFTEST" != 1 ]; then
    command -v gcc >/dev/null || missing "gcc"
    command -v softhsm2-util >/dev/null || missing "softhsm2-util"
    command -v flock >/dev/null || missing "flock"
    command -v sudo >/dev/null || missing "sudo"
    sudo -n true 2>/dev/null || missing "passwordless sudo"
    python3 -I - "$LOCK" "$$" <<'EOF' || die "run under flock $LOCK: no ancestor holds the privileged lock"
import os, sys
path, me = sys.argv[1], int(sys.argv[2])
try:
    inode = str(os.stat(path).st_ino)
except OSError:
    sys.exit(1)
holders = []
for line in open("/proc/locks"):
    fields = line.split()
    if "->" in fields:
        continue
    if (len(fields) >= 6 and fields[1] == "FLOCK" and fields[3] == "WRITE"
            and fields[5].rsplit(":", 1)[-1] == inode):
        holders.append(int(fields[4]))
chain, pid = {me}, me
while pid > 1:
    try:
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        break
    pid = int(next(l.split()[1] for l in status.splitlines() if l.startswith("PPid:")))
    chain.add(pid)
sys.exit(0 if any(h in chain for h in holders) else 1)
EOF
fi

if [ -n "${MODULE-}" ]; then
    PROVIDER=$MODULE
else
    PROVIDER=$(python3 -I scripts/release-matrix-contract.py --select-module 2>/dev/null) \
        || missing "no SoftHSM provider (release-matrix-contract --select-module failed)"
fi
[ -f "$PROVIDER" ] || missing "SoftHSM provider not a file: $PROVIDER"

find_header_dir() {
    if [ -n "${PKCS11_HEADER_DIR-}" ]; then
        [ -f "$PKCS11_HEADER_DIR/pkcs11.h" ] && { echo "$PKCS11_HEADER_DIR"; return 0; }
        return 1
    fi
    for dir in /usr/include /usr/include/softhsm /usr/include/p11-kit-1/p11-kit; do
        [ -f "$dir/pkcs11.h" ] && { echo "$dir"; return 0; }
    done
    for header in "$HOME"/.cargo/registry/src/*/cryptoki-sys-*/vendor/pkcs11.h; do
        [ -f "$header" ] && { dirname "$header"; return 0; }
    done
    return 1
}

if [ -n "${KEYOPS_SL_SELFTEST_SIGNER_BIN-}" ]; then
    SIGNER=$KEYOPS_SL_SELFTEST_SIGNER_BIN
else
    gcc -O2 -Wall -Wextra -Werror -o "$BIN/shortlived-sign" \
        "$SIGNER_SRC" -ldl || die "shortlived-sign does not compile"
    SIGNER=$BIN/shortlived-sign
fi
if [ -n "${KEYOPS_SL_SELFTEST_KEYGEN_BIN-}" ]; then
    KEYGEN=$KEYOPS_SL_SELFTEST_KEYGEN_BIN
else
    HEADER_DIR=$(find_header_dir) || missing "no pkcs11.h (tried system dirs and cryptoki-sys vendor)"
    gcc -O2 -Wall -Wextra -Werror -I "$HEADER_DIR" -o "$BIN/shortlived-keygen" \
        "$KEYGEN_SRC" -ldl || die "shortlived-keygen does not compile"
    KEYGEN=$BIN/shortlived-keygen
fi
if [ -n "${KEYOPS_SL_SELFTEST_GATED_BIN-}" ]; then
    GATED=$KEYOPS_SL_SELFTEST_GATED_BIN
else
    command -v gcc >/dev/null || missing "gcc"
    gcc -O1 -Wall -Wextra -Werror -o "$BIN/gated" "$GATED_SRC" -ldl \
        || die "gated anchor does not compile"
    GATED=$BIN/gated
fi

say "provider: $PROVIDER"
say "duration: ${DURATION}s callers: $N_CALLERS sleep: ${SLEEP_MS}ms"

if [ "$SELFTEST" != 1 ]; then
    export SOFTHSM2_CONF=$WORK/softhsm2.conf
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
    softhsm2-util --init-token --free --label keyops-shortlived --so-pin "$PIN" --pin "$PIN" \
        >/dev/null || die "token init failed"
    "$KEYGEN" "$PROVIDER" "$PIN" || die "keygen failed"
fi

# The root observer must see the disposable token: stock sudoers
# scrubs SOFTHSM2_CONF, so preserve it like the bench script does.
SUDO="sudo -n --preserve-env=SOFTHSM2_CONF"
[ "$SELFTEST" = 1 ] && SUDO=""

wait_for_line() {
    end=$(( $(date +%s) + $3 ))
    while ! grep -Fq "$2" "$1" 2>/dev/null; do
        if [ -n "$OBSERVER_PID" ] && ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
            echo "observer died before [$2]" >&2
            return 1
        fi
        [ "$(date +%s)" -lt "$end" ] || { echo "never saw [$2] within $3s" >&2; return 1; }
        sleep 0.2
    done
    return 0
}

start_seed() {
    SOFTHSM2_CONF=${SOFTHSM2_CONF:-} "$GATED" "$PROVIDER" 0 0 "$1/gate-never" \
        > "$1/seed.log" 2>&1 &
    SEED_PID=$!
    end=$(( $(date +%s) + 60 ))
    while ! grep -q "^READY" "$1/seed.log" 2>/dev/null; do
        kill -0 "$SEED_PID" 2>/dev/null || { echo "seed died" >&2; return 1; }
        [ "$(date +%s)" -lt "$end" ] || { echo "seed never READY" >&2; return 1; }
        sleep 0.05
    done
    return 0
}

stop_seed() {
    [ -z "$SEED_PID" ] || kill -TERM "$SEED_PID" 2>/dev/null || true
    [ -z "$SEED_PID" ] || wait "$SEED_PID" 2>/dev/null || true
    SEED_PID=
}

dir=$WORK/run
mkdir -p "$dir" && chmod 0700 "$dir" || die "cell dir $dir"
start_seed "$dir" || die "seed anchor failed"
# shellcheck disable=SC2086
$SUDO "$P11SCOPE" inventory --system --key-operations --module "$PROVIDER" \
    --max-gaps 65536 --duration "${DURATION}s" \
    -o "$dir/out.json" > "$dir/observer.log" 2> "$dir/observer.stderr" &
OBSERVER_PID=$!
wait_for_line "$dir/observer.stderr" "$SEAL_LINE" 120 || {
    reclaim_root_output "$dir/observer.stderr" 2>/dev/null || true
    cp "$dir/observer.stderr" "$OUTDIR/observer.stderr" 2>/dev/null || true
    die "observer never sealed"
}
sleep "$SETTLE_S"
sign_fail=0
spawned=0
i=1
while [ "$i" -le "$N_CALLERS" ]; do
    if SOFTHSM2_CONF=${SOFTHSM2_CONF:-} "$SIGNER" "$PROVIDER" "$PIN" "$SLEEP_MS" \
        >> "$dir/signers.log" 2>&1; then
        spawned=$((spawned + 1))
    else
        sign_fail=$((sign_fail + 1))
    fi
    i=$((i + 1))
done
OBS_EXIT=0
wait "$OBSERVER_PID" || OBS_EXIT=$?
OBSERVER_PID=
stop_seed
say "spawned=$spawned sign_fail=$sign_fail observer_exit=$OBS_EXIT"
if [ "$SELFTEST" != 1 ]; then
    reclaim_root_output "$dir/out.json" || die "cannot reclaim out.json"
    reclaim_root_output "$dir/observer.stderr" || die "cannot reclaim observer.stderr"
fi
cp "$dir/out.json" "$OUTDIR/out.json" || die "cannot copy out.json"
cp "$dir/observer.stderr" "$OUTDIR/observer.stderr" || die "cannot copy observer.stderr"
cp "$dir/signers.log" "$OUTDIR/signers.log" || die "cannot copy signers.log"

judge=$(python3 -I "$CHECKS" --judge "$dir/out.json" "$SIGNER" "$PROVIDER" \
    "$spawned" "$sign_fail" "$OBS_EXIT" 2> "$dir/judge.stderr") || {
    say "judge failed:"
    cat "$dir/judge.stderr" >&2
    die "judge crashed"
}
shaped_pass=$(printf '%s' "$judge" | sed -n '1p')
shaped_detail=$(printf '%s' "$judge" | sed -n '2p')
counted_pass=$(printf '%s' "$judge" | sed -n '3p')
counted_detail=$(printf '%s' "$judge" | sed -n '4p')
rc=0
if [ "$shaped_pass" = 1 ]; then
    row shortlived-shaped 1 qualified "$shaped_detail"
else
    row shortlived-shaped 0 failed "$shaped_detail"
    rc=1
fi
if [ "$counted_pass" = 1 ]; then
    row shortlived-counted 1 qualified "$counted_detail"
else
    row shortlived-counted 0 failed "$counted_detail"
    rc=1
fi
exit "$rc"
