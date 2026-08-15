#!/bin/sh
# v0.1.0 release build.
#
# Produces the two artifact shapes the design calls for:
#   - p11scope            fully static musl build (the observer never
#                          dlopens the target provider, so static is safe
#                          and gives a single dependency-free binary)
#   - p11scope-discover   dynamic glibc AND dynamic musl builds (a static
#                          helper cannot dlopen a provider .so sanely, so
#                          discover is intentionally never static)
#
# The dynamic host attach gate and container discover builds stay isolated
# from the dedicated safe-only target directory used for the official observer.
#   - scripts/verify-attach-e2e.sh        proves dynamic attach+capture
#     correctness end to end against spike/expected.txt.
#   - scripts/verify-discover-containers.sh  builds p11scope-discover for
#     glibc (rust:1-bookworm -> run in ubuntu:24.04) and dynamic musl
#     (rust:1-alpine), and smoke-runs each against SoftHSM2 inside its
#     own container.
#
# NOTE: musl static-PIE binaries report as "static-pie linked" under
# `file`, not "statically linked" -- both mean static (no dynamic
# interpreter); `ldd` printing "statically linked"/"not a dynamic
# executable" is the second, independent confirmation.
set -eu
cd "$(dirname "$0")/.."

command -v file >/dev/null || { echo "file(1) required"; exit 1; }
command -v jq >/dev/null || { echo "jq required"; exit 1; }
command -v setpriv >/dev/null || { echo "setpriv required"; exit 1; }

MODULE=/usr/lib/softhsm/libsofthsm2.so
DIST=dist
WORK=target/e2e
OFFICIAL_TARGET=target/release-official
WPID=
TARGET_STARTTIME=
LPID=
SPID=
. scripts/lib.sh
require_non_root_caller
rm -rf "$DIST"
mkdir -p "$DIST"

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$WPID" ] && [ -n "$TARGET_STARTTIME" ]; then
        signal_verified_process KILL "$WPID" "$TARGET_STARTTIME" 2>/dev/null || true
    fi
    [ -z "$LPID" ] || kill "$LPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || true
    [ -z "$LPID" ] || wait "$LPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== release privacy gate ==="
sh scripts/verify-canaries.sh

echo "=== p11scope: dynamic-build attach correctness ==="
sh scripts/verify-attach-e2e.sh

echo "=== p11scope: isolated safe-only official static build ==="
rustup target add --toolchain 1.88 x86_64-unknown-linux-musl
rm -rf "$OFFICIAL_TARGET"
CARGO_TARGET_DIR="$OFFICIAL_TARGET" \
RUSTFLAGS="-C target-feature=+crt-static" \
    cargo +1.88 build --locked --release --no-default-features \
        --target x86_64-unknown-linux-musl --bin p11scope
P11SCOPE_STATIC=$OFFICIAL_TARGET/x86_64-unknown-linux-musl/release/p11scope

set -- "$OFFICIAL_TARGET"/x86_64-unknown-linux-musl/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "official BPF object is not unique"; exit 1; }
OFFICIAL_BPF=$1
set -- target/canaries/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "diagnostic BPF object is not unique"; exit 1; }
DIAGNOSTIC_BPF=$1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$OFFICIAL_BPF" "$DIAGNOSTIC_BPF"

if "$P11SCOPE_STATIC" profile --unsafe-unvalidated-metadata \
    --manifest /nonexistent/manifest.json --pid 1 \
    > "$OFFICIAL_TARGET/unsafe-cli.log" 2>&1; then
    echo "safe-only official observer accepted --unsafe-unvalidated-metadata"
    exit 1
fi
grep -Fq -- "--unsafe-unvalidated-metadata requires a build with" \
    "$OFFICIAL_TARGET/unsafe-cli.log" || {
        echo "safe-only observer returned the wrong unsafe-feature diagnostic"
        cat "$OFFICIAL_TARGET/unsafe-cli.log"
        exit 1
    }

echo "--- file: p11scope (static musl) ---"
file "$P11SCOPE_STATIC"
file "$P11SCOPE_STATIC" | grep -qE "statically linked|static-pie linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "--- ldd: p11scope (static musl) ---"
ldd "$P11SCOPE_STATIC" || true   # diagnostic only; file(1) above is the enforced static-link check
cp "$P11SCOPE_STATIC" "$DIST/p11scope"

echo "=== p11scope-discover: dynamic glibc + dynamic musl builds ==="
sh scripts/verify-discover-containers.sh
GLIBC_DISCOVER=target/glibc-build/release/p11scope-discover
MUSL_DISCOVER=target/musl-build/release/p11scope-discover

echo "--- file: p11scope-discover (glibc) ---"
file "$GLIBC_DISCOVER"
echo "--- ldd: p11scope-discover (glibc) ---"
ldd "$GLIBC_DISCOVER"
echo "--- smoke run: p11scope-discover (glibc), on host ---"
"$GLIBC_DISCOVER" --module /usr/lib/softhsm/libsofthsm2.so -o "$DIST/.smoke-manifest-glibc.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-glibc.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
echo "glibc discover host smoke run: $n/68 function records OK"
rm -f "$DIST/.smoke-manifest-glibc.json"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover-glibc"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover"

echo "--- file: p11scope-discover (musl) ---"
file "$MUSL_DISCOVER"
echo "musl-dynamic file/ldd/smoke run already verified inside the alpine" \
     "container by verify-discover-containers.sh above -- this (glibc)" \
     "host has no musl dynamic linker to exec it directly."
cp "$MUSL_DISCOVER" "$DIST/p11scope-discover-musl"

echo "=== packaged discovery helper smoke ==="
"$DIST/p11scope-discover" --module /usr/lib/softhsm/libsofthsm2.so \
    -o "$DIST/.smoke-manifest-helper.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-helper.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
rm -f "$DIST/.smoke-manifest-helper.json"

echo "=== p11scope: smoke run of the packaged STATIC artifact itself ==="
"$DIST/p11scope" --help >/dev/null
echo "--help OK"

echo "=== official static hostile-target smoke ==="
wait_for_hardened_target() {
    wht_pid=$1
    wht_starttime=$2
    wht_attempt=0
    while [ "$wht_attempt" -lt 160 ]; do
        process_matches_starttime "$wht_pid" "$wht_starttime" || {
            echo "Hardened target $wht_pid exited or changed identity" >&2
            return 1
        }
        if awk '
            $1 == "State:" { stopped_ok = ($2 == "T" || $2 == "t") }
            $1 == "Uid:" {
                uid_ok = ($2 != 0 && $3 != 0 && $4 != 0 && $5 != 0)
            }
            $1 == "CapInh:" || $1 == "CapPrm:" || $1 == "CapEff:" || $1 == "CapAmb:" {
                caps_ok += ($2 == "0000000000000000")
            }
            $1 == "NoNewPrivs:" { nnp_ok = ($2 == 1) }
            END { exit !(stopped_ok && uid_ok && caps_ok == 4 && nnp_ok) }
        ' "/proc/$wht_pid/status" 2>/dev/null; then
            return 0
        fi
        kill -0 "$wht_pid" 2>/dev/null || {
            echo "Hardened target $wht_pid exited before its status was verified" >&2
            return 1
        }
        wht_attempt=$((wht_attempt + 1))
        sleep 0.05
    done
    echo "Hardened target $wht_pid did not stop with non-root UIDs, zero active capabilities, and NoNewPrivs" >&2
    cat "/proc/$wht_pid/status" >&2 || true
    return 1
}

export SOFTHSM2_CONF="$PWD/$WORK/softhsm2.conf"
"$DIST/p11scope-discover" --module "$MODULE" -o "$WORK/release-manifest.json"

TARGET_UID=$(id -u)
TARGET_GID=$(id -g)
rm -f "$WORK/observed-static-smoke.json" "$WORK/hardened-target.pid"
sudo --preserve-env=SOFTHSM2_CONF sh -c 'umask 077; exec 3>"$1"; shift; exec "$@"' \
    sh "$WORK/hardened-target.pid" \
    setpriv --no-new-privs --reuid "$TARGET_UID" --regid "$TARGET_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- \
    sh -c '
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' \
            "/proc/$$/stat") || exit 1
        case $starttime in ""|*[!0-9]*) exit 1 ;; esac
        printf "%s %s\n" "$$" "$starttime" >&3
        exec 3>&-
        kill -STOP "$$"
        exec "$1" "$2"
    ' sh "$PWD/$WORK/harness" "$MODULE" &
LPID=$!
target_attempt=0
while ! sudo test -s "$WORK/hardened-target.pid" && [ "$target_attempt" -lt 160 ]; do
    kill -0 "$LPID" 2>/dev/null || { echo "Hardened target launcher exited before publishing its pid"; exit 1; }
    target_attempt=$((target_attempt + 1))
    sleep 0.05
done
sudo test -s "$WORK/hardened-target.pid" || { echo "Hardened target pid missing"; exit 1; }
set -- $(sudo cat "$WORK/hardened-target.pid")
[ "$#" -eq 2 ] || { echo "invalid Hardened target identity record"; exit 1; }
WPID=$1
TARGET_STARTTIME=$2
case $WPID:$TARGET_STARTTIME in *[!0-9:]*) echo "invalid Hardened target identity"; exit 1 ;; esac
wait_for_hardened_target "$WPID" "$TARGET_STARTTIME"

sudo --preserve-env=SOFTHSM2_CONF "$DIST/p11scope" profile \
    --manifest "$WORK/release-manifest.json" \
    --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed-static-smoke.json" \
    > "$WORK/profile-static-smoke.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile-static-smoke.log" aggregate-only metrics
signal_verified_process CONT "$WPID" "$TARGET_STARTTIME"
if wait "$LPID"; then LPID=; WPID=; TARGET_STARTTIME=; else status=$?; LPID=; WPID=; TARGET_STARTTIME=; echo "static smoke workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "static smoke profiler failed: $status"; cat "$WORK/profile-static-smoke.log" || true; exit "$status"; fi
# The observer ran under sudo, so its published report is root-owned 0600.
sudo chown "$(id -u):$(id -g)" "$WORK/observed-static-smoke.json"

python3 scripts/check-capture-evidence.py clean-metrics \
    "$WORK/observed-static-smoke.json" spike/expected.txt
echo "static p11scope smoke attach OK: $(jq -c .evidence "$WORK/observed-static-smoke.json")"

echo "=== dist/ ==="
ls -la "$DIST"

echo "=== build-release: ALL OK ==="
