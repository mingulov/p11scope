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
# This script does not re-implement either build: it calls the two
# existing verification scripts that already build and prove these
# artifacts correct, then copies what they produced into dist/.
#   - scripts/verify-attach-e2e.sh        builds the dynamic host binary,
#     proves real attach+capture correctness end to end against
#     spike/expected.txt, THEN builds the static musl target and checks
#     `file` reports it static.
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

DIST=dist
rm -rf "$DIST"
mkdir -p "$DIST"

echo "=== p11scope: dynamic-build attach correctness + static musl build ==="
sh scripts/verify-attach-e2e.sh
P11SCOPE_STATIC=target/x86_64-unknown-linux-musl/release/p11scope

echo "--- file: p11scope (static musl) ---"
file "$P11SCOPE_STATIC"
file "$P11SCOPE_STATIC" | grep -qE "statically linked|static-pie linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "--- ldd: p11scope (static musl) ---"
ldd "$P11SCOPE_STATIC" || true   # expect "not a dynamic executable" / "statically linked"; ldd's own exit status varies by libc, text is what we check
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

echo "--- file: p11scope-discover (musl) ---"
file "$MUSL_DISCOVER"
echo "musl-dynamic file/ldd/smoke run already verified inside the alpine" \
     "container by verify-discover-containers.sh above -- this (glibc)" \
     "host has no musl dynamic linker to exec it directly."
cp "$MUSL_DISCOVER" "$DIST/p11scope-discover-musl"

echo "=== p11scope: smoke run of the packaged STATIC artifact itself ==="
"$DIST/p11scope" --help >/dev/null
echo "--help OK"

# Functional smoke run: attach the actual dist/p11scope binary (not the
# dynamic host build verify-attach-e2e.sh already proved correct above)
# to a real workload, to prove the static musl build's eBPF attach path
# also works, not just that `file`/`ldd` call it static. Reuses the
# harness, private SoftHSM2 token and manifest verify-attach-e2e.sh just
# built under target/e2e -- no need to rebuild any of that.
WORK=target/e2e
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -f "$WORK/go-static"
( while [ ! -f "$WORK/go-static" ]; do sleep 0.05; done
  exec "$WORK/harness" /usr/lib/softhsm/libsofthsm2.so ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF "$DIST/p11scope" profile \
    --manifest "$WORK/manifest.json" --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed-static-smoke.json" \
    > "$WORK/profile-static-smoke.log" 2>&1 &
SPID=$!
sleep 3            # let attach complete before releasing the workload
touch "$WORK/go-static"
wait "$WPID"
wait "$SPID"
jq -e '.evidence.attached_probes > 0 and .evidence.completeness == "COMPLETE"' \
    "$WORK/observed-static-smoke.json" >/dev/null \
    || { echo "static p11scope smoke attach FAILED"; cat "$WORK/profile-static-smoke.log"; exit 1; }
echo "static p11scope smoke attach OK: $(jq -c .evidence "$WORK/observed-static-smoke.json")"

echo "=== dist/ ==="
ls -la "$DIST"

echo "=== build-release: ALL OK ==="
