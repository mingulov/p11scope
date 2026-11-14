#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# build.sh OUTDIR: build the kryoptic static-embed fixture binary
# (scripts/provider-matrix/static-embed/kryoptic-embed/), prove kryoptic
# is statically linked into it, and stage the binary plus BUILD.json
# into OUTDIR for run-matrix.sh --extra-deliver (deliver the dir as
# kryoptic-static-embed/).
#
# Build needs a Rust toolchain, a C compiler, OpenSSL headers (bindgen)
# and crates.io access; sqlite is statically bundled. The build is
# --locked: direct deps are =-pinned and Cargo.lock is committed, so a
# rebuild resolves identical bytes. To bump kryoptic, update Cargo.toml,
# regenerate the lock, rebuild, and commit all three.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
CRATE=$HERE/kryoptic-embed
if [ $# -ne 1 ]; then echo "usage: build.sh OUTDIR" >&2; exit 2; fi
OUT=$1
command -v cargo >/dev/null 2>&1 || { echo "build: missing prerequisite: cargo" >&2; exit 2; }
[ -f "$CRATE/Cargo.lock" ] || { echo "build: Cargo.lock missing; generate it with a plain build and commit it first" >&2; exit 2; }
cargo build --release --locked --manifest-path "$CRATE/Cargo.toml"
BIN=$CRATE/target/release/kryoptic-static-embed
[ -x "$BIN" ] || { echo "build: binary missing after build: $BIN" >&2; exit 1; }
# Static-embed proofs: the entry export lives in the image, and no
# kryoptic object is dynamically linked. (No grep -q under pipefail: an
# early-quitting grep SIGPIPEs the producer and fails the pipeline.)
[ -n "$(nm "$BIN" | grep " T C_GetFunctionList$" || true)" ] \
  || { echo "build: C_GetFunctionList not a text symbol in $BIN" >&2; exit 1; }
if [ -n "$(ldd "$BIN" | grep -i "kryoptic" || true)" ]; then
  echo "build: kryoptic dynamically linked into $BIN (wants static)" >&2
  ldd "$BIN" >&2
  exit 1
fi
mkdir -p "$OUT" || exit 2
cp -p "$BIN" "$OUT/" || exit 2
SHA=$(sha256sum "$OUT/kryoptic-static-embed" | cut -d' ' -f1)
RUSTC=$(rustc --version 2>/dev/null || echo unknown)
{
  echo "{"
  echo '  "fixture": "kryoptic-static-embed",'
  echo '  "kryoptic": "1.5.2",'
  echo '  "source": "crates.io",'
  echo '  "sqlite": "bundled",'
  echo "  \"rustc\": \"$RUSTC\","
  echo "  \"sha256\": \"$SHA\""
  echo "}"
} >"$OUT/BUILD.json"
echo "build: staged $OUT/kryoptic-static-embed ($SHA)"
