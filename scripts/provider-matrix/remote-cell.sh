#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# remote-cell.sh PROVIDER: run one provider-matrix cell on a test host.
# Invoked on the host under lane-run.sh by scripts/provider-matrix/
# run-matrix.sh. Environment: TASK_DIR (task folder), REPO (delivered
# scripts subtree mirroring repo/scripts/), OUT (this cell's output dir),
# P11SCOPE, DISCOVER, P11CHECK, MODE (smoke|full), OBS_SUDO, PINS
# (600 file exporting P11TEST_PIN/P11TEST_SO_PIN, sourced, never shown).
# Fetches pinned artifacts first (haskoki/kryoptic/softhsm2-2.6), then
# runs the same cell CI runs (the custom static-embed cell for
# kryoptic-static-embed). Exit codes match the cell (0 pass, 1 cell
# failed, 2 harness/fetch error, 77 provider absent -> host UNRUN).
set -u
[ $# -eq 1 ] || { echo "usage: remote-cell.sh PROVIDER" >&2; exit 2; }
PROVIDER=$1
case $PROVIDER in ''|*/*|*..*|" "* ) echo "remote-cell: bad provider name" >&2; exit 2 ;; esac
: "${TASK_DIR:?}" "${REPO:?}" "${OUT:?}" "${P11SCOPE:?}" "${DISCOVER:?}" "${P11CHECK:?}" "${PINS:?}"
MODE=${MODE:-smoke}
OBS_SUDO=${OBS_SUDO:-sudo -n}
mkdir -p "$OUT" || exit 2
case $PROVIDER in
  haskoki|kryoptic) FETCH=$PROVIDER ;;
  softhsm2-2.6) FETCH=softhsm26 ;;
  *) FETCH= ;;
esac
case $PROVIDER in
  kryoptic-static-embed) CELL_SCRIPT="$REPO/scripts/provider-matrix/static-embed-cell.sh" ;;
  *) CELL_SCRIPT="$REPO/scripts/ci/provider-matrix-cell.sh" ;;
esac
if [ -n "$FETCH" ]; then
  "$REPO/scripts/ci/fetch-provider.sh" "$FETCH" "$TASK_DIR" >"$OUT/fetch.log" 2>&1 || {
    rc=$?
    echo "remote-cell: fetch failed for $PROVIDER (see fetch.log)" >&2
    echo "$rc" >"$OUT/cell.exit"
    exit 2
  }
fi
# shellcheck disable=SC1090
. "$PINS"
export P11TEST_PIN P11TEST_SO_PIN
rc=0
PROVIDER="$PROVIDER" TASK_DIR="$TASK_DIR" P11CHECK_MODE="$MODE" \
  P11CHECK_BIN="$P11CHECK" P11SCOPE_DISCOVER_BIN="$DISCOVER" OBS_SUDO="$OBS_SUDO" \
  "$CELL_SCRIPT" "$P11SCOPE" "$OUT/cells" || rc=$?
echo "$rc" >"$OUT/cell.exit"
echo "remote-cell: provider=$PROVIDER rc=$rc"
exit "$rc"
