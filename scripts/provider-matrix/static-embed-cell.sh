#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# static-embed-cell.sh P11SCOPE OUTDIR: one kryoptic static-embed cell.
# Drives a program with kryoptic statically linked (no dlopenable
# module): the program self-tests through its embedded table (printing
# CALLS=n, the observation oracle), runs once more under `p11scope run`
# with default discovery (no manifest can exist for a static binary),
# and faces `p11scope-discover`. Judged by
# static_embed_cell_compare.py: program-runs, run-observed and discover
# (FAIL with the static-executable-unobserved gap while the static
# file-scan is unlanded). Fresh token db per cell; PINs via
# P11TEST_PIN/P11TEST_SO_PIN env (never echoed). The binary arrives via
# run-matrix.sh --extra-deliver (kryoptic-static-embed/ dir holding the
# binary plus BUILD.json); a missing binary is a harness error, never a
# skip. Test-host only: everything runs direct and the observer goes
# through $OBS_SUDO (default `sudo -n`) with the provider env. Exit 0
# means every row passed, 1 means a row failed, 2 means a harness error.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
if [ $# -ne 2 ]; then echo "usage: static-embed-cell.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "static-embed-cell: no executable observer: $P" >&2; exit 2; }
case ${TASK_DIR:-} in '' ) echo "static-embed-cell: TASK_DIR must be set" >&2; exit 2 ;; esac
[ -d "$TASK_DIR" ] || { echo "static-embed-cell: TASK_DIR not a directory: $TASK_DIR" >&2; exit 2; }
OBS_SUDO=${OBS_SUDO:-sudo -n}
ENV_FILE=$HERE/providers/kryoptic-static-embed.env
[ -f "$ENV_FILE" ] || { echo "static-embed-cell: no such provider env: $ENV_FILE" >&2; exit 2; }
# shellcheck disable=SC1090
. "$ENV_FILE"
: "${PROVIDER_NAME:?env must set PROVIDER_NAME}"
: "${PROVIDER_VERSION:?env must set PROVIDER_VERSION}"
: "${PROVIDER_CANDIDATES:?env must set PROVIDER_CANDIDATES}"
: "${PROVIDER_SETUP:?env must set PROVIDER_SETUP}"
PROVIDER_ENV_VARS=${PROVIDER_ENV_VARS:-}
STATIC_BIN=
# shellcheck disable=SC2086
for cand in $PROVIDER_CANDIDATES; do
  expanded=$(eval echo "$cand")
  if [ -f "$expanded" ]; then STATIC_BIN=$expanded; break; fi
done
[ -n "$STATIC_BIN" ] || { echo "static-embed-cell: no static binary delivered (tried: $PROVIDER_CANDIDATES; deliver kryoptic-static-embed/ via --extra-deliver)" >&2; exit 2; }
export TASK_DIR STATIC_BIN PROVIDER_MATRIX_DIR=$HERE
DISCOVER=${P11SCOPE_DISCOVER_BIN:-$(dirname "$P")/p11scope-discover}
command -v python3 >/dev/null 2>&1 || { echo "static-embed-cell: missing prerequisite: python3" >&2; exit 2; }
[ -x "$DISCOVER" ] || { echo "static-embed-cell: no executable discover helper: $DISCOVER" >&2; exit 2; }
P11TEST_PIN=${PROVIDER_PIN:-${P11TEST_PIN:-}}
P11TEST_SO_PIN=${PROVIDER_SO_PIN:-${P11TEST_SO_PIN:-}}
[ -z "${P11TEST_PIN:-}" ] && { echo "static-embed-cell: P11TEST_PIN env must be set (throwaway token PIN, never echoed)" >&2; exit 2; }
[ -z "${P11TEST_SO_PIN:-}" ] && { echo "static-embed-cell: P11TEST_SO_PIN env must be set (throwaway SO PIN, never echoed)" >&2; exit 2; }
STATIC_EMBED_PIN=$P11TEST_PIN
STATIC_EMBED_SO_PIN=$P11TEST_SO_PIN
export STATIC_EMBED_PIN STATIC_EMBED_SO_PIN
# shellcheck disable=SC2086
for kv in $PROVIDER_ENV_VARS; do
  name=${kv%%=*}; value=${kv#*=}
  value=$(eval echo "$value")
  export "$name=$value"
done
RUN_ENV=()
# shellcheck disable=SC2086
for kv in $PROVIDER_ENV_VARS; do
  name=${kv%%=*}; value=${kv#*=}
  value=$(eval echo "$value")
  RUN_ENV+=("$name=$value")
done
RUN_ENV+=("STATIC_EMBED_PIN=$STATIC_EMBED_PIN" "STATIC_EMBED_SO_PIN=$STATIC_EMBED_SO_PIN")
obs() {
  # shellcheck disable=SC2086
  $OBS_SUDO env "${RUN_ENV[@]}" "$@"
}
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
COMPARE=$HERE/static_embed_cell_compare.py
[ -f "$COMPARE" ] || { echo "static-embed-cell: missing helper: $COMPARE" >&2; exit 2; }
echo "static-embed-cell: binary=$STATIC_BIN"
{
  echo "provider_name=$PROVIDER_NAME"
  echo "provider_version=$PROVIDER_VERSION"
  echo "static_binary=$STATIC_BIN"
  echo "task_dir=$TASK_DIR"
  echo "p11scope=$P"
  [ -x "$P" ] && "$P" --version 2>/dev/null || echo "p11scope_version=UNKNOWN"
  echo "discover=$DISCOVER"
  "$DISCOVER" --version 2>/dev/null || echo "discover_version=UNKNOWN"
  echo "uname=$(uname -a)"
  sha256sum "$STATIC_BIN"
} >"$OUT/cell.env" 2>&1
if [ -f "$TASK_DIR/kryoptic-static-embed/BUILD.json" ]; then
  cp -p "$TASK_DIR/kryoptic-static-embed/BUILD.json" "$OUT/BUILD.json" || exit 2
fi
set +e
(
  set -euo pipefail
  "$PROVIDER_SETUP" "$TASK_DIR"
) >"$OUT/setup.log" 2>&1
rc=$?
echo "$rc" >"$OUT/setup.exit"
set -e
echo "static-embed-cell: setup exit=$rc"
[ "$rc" = 0 ] || { echo "static-embed-cell: provider setup failed (see setup.log)" >&2; exit 2; }
# Direct self-test: the program drives its embedded table and prints
# CALLS=n. rc is judged by the compare, never aborts here.
set +e
"$STATIC_BIN" --iterations 5 --interval 1 </dev/null >"$OUT/selftest.log" 2>"$OUT/selftest.stderr.log"
rc=$?
echo "$rc" >"$OUT/selftest.exit"
set -e
echo "static-embed-cell: self-test exit=$rc"
# Observed leg: the same drive under `p11scope run` with default
# discovery (no manifest can exist for a static binary). The child's
# stdout (CALLS=n) lands in observer.out, the oracle for the judge.
set +e
obs "$P" run -o "$OUT/observed.json" -- "$STATIC_BIN" --iterations 5 --interval 1 \
  </dev/null >"$OUT/observer.out" 2>"$OUT/observer.err"
rc=$?
echo "$rc" >"$OUT/run.exit"
set -e
echo "static-embed-cell: run exit=$rc"
[ -s "$OUT/observed.json" ] || { echo "static-embed-cell: missing observed.json (observer abort)" >&2; exit 1; }
# Discover the binary now. rc is judged by the compare, never aborts.
set +e
"$DISCOVER" --module "$STATIC_BIN" -o "$OUT/manifest.json" \
  >"$OUT/discover.stdout.log" 2>"$OUT/discover.stderr.log"
rc=$?
echo "$rc" >"$OUT/discover.exit"
set -e
echo "static-embed-cell: discover exit=$rc"
MANIFEST_ARGS=()
if [ -s "$OUT/manifest.json" ]; then MANIFEST_ARGS=(--manifest "$OUT/manifest.json"); fi
python3 -I "$COMPARE" --binary "$STATIC_BIN" \
  --selftest-rc "$(cat "$OUT/selftest.exit")" --selftest-log "$OUT/selftest.log" \
  --observer-out "$OUT/observer.out" \
  --observed "$OUT/observed.json" \
  --discover-rc "$(cat "$OUT/discover.exit")" \
  "${MANIFEST_ARGS[@]}" \
  --discover-stderr "$OUT/discover.stderr.log" \
  --out-results "$OUT/results.jsonl" --out-summary "$OUT/summary.txt"
rc=$?
echo "static-embed-cell: compare rc=$rc"
[ -s "$OUT/results.jsonl" ] || { echo "static-embed-cell: missing results.jsonl" >&2; exit 2; }
exit "$rc"
