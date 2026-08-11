#!/bin/sh -eu
# Gate G1: p11scope-discover runs against SoftHSM2 in ubuntu (glibc) and
# alpine (musl), and both builds are DYNAMIC (a static helper cannot
# dlopen providers sanely). The glibc binary is built in rust:1-bookworm
# (glibc 2.36) so it runs on ubuntu 24.04 (2.39) — the host glibc may be
# newer than the container's, so a host build is not portable.
#
# Both --target-dir paths below are under $PWD/target (bind-mounted into
# the container as /src), not the container's own /tmp, so the built
# artifacts survive the container's --rm and are reused as-is by
# scripts/build-release.sh instead of building them a second time.
set -eu
cd "$(dirname "$0")/.."

docker pull -q ubuntu:24.04
docker pull -q rust:1-bookworm
docker pull -q rust:1-alpine

# Vendored so container builds need no network (sandbox git quirks).
# The vendor config is rewritten with absolute /src paths because it is
# copied into $CARGO_HOME inside the containers.
mkdir -p target/vendor
cargo vendor target/vendor/src > target/vendor/config.toml
sed 's|directory = "|directory = "/src/|' target/vendor/config.toml > target/vendor/config.container.toml

echo "=== glibc: build in rust:1-bookworm, run in ubuntu:24.04 ==="
docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm sh -ec '
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp target/vendor/config.container.toml /tmp/cargo/config.toml
  cargo build --release -p p11scope-discover --offline --target-dir /src/target/glibc-build'
docker run --rm -v "$PWD/target/glibc-build/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    ubuntu:24.04 sh -ec '
  apt-get update -q >/dev/null && apt-get install -qy softhsm2 >/dev/null
  p11scope-discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  echo "ubuntu glibc: 68/68 OK"'

echo "=== musl-dynamic: build + run in rust:1-alpine ==="
docker run --rm -v "$PWD:/src" -w /src rust:1-alpine sh -ec '
  apk add -q musl-dev gcc softhsm file
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp target/vendor/config.container.toml /tmp/cargo/config.toml
  export RUSTFLAGS="-C target-feature=-crt-static"
  cargo build --release -p p11scope-discover --offline --target-dir /src/target/musl-build
  file /src/target/musl-build/release/p11scope-discover | grep -q "dynamically linked" \
      || { echo "helper is NOT dynamic"; exit 1; }
  ldd /src/target/musl-build/release/p11scope-discover
  /src/target/musl-build/release/p11scope-discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  echo "alpine musl-dynamic: 68/68 OK"'

echo "=== container verification: ALL OK ==="
