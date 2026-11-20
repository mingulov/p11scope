#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# pqc-cell.sh P11SCOPE OUTDIR: the post-quantum key-visibility cell.
# Runs the PQC workload (ML-DSA-44/65/87 + ML-KEM-512/768/1024, each
# generated once and used once) against the pinned kryoptic 1.5.2
# artifact under `inventory --pid --key-operations`, once with
# --key-sizes and once without, and judges both legs with
# pqc_cell_compare.py: every key row must show family + parameter set
# in verbose text and --json, with known exact counts. No skip counts
# as a pass: a missing file, row or spotlight line fails its leg.
# The workflow fetches kryoptic first (scripts/ci/fetch-provider.sh
# kryoptic into TASK_DIR); the token lives under
# $TASK_DIR/kryoptic/. PINs via P11TEST_PIN/P11TEST_SO_PIN env (never
# echoed). Two modes like provider-matrix-cell.sh: as root (CI) the
# setup/workload drop to RUNUID/RUNGID via setpriv and the observer
# runs direct; as a user (test hosts) everything runs direct and the
# observer goes through $OBS_SUDO (default `sudo -n`). Exit 0 means
# every row passed, 1 means the cell failed, 2 means a harness error,
# 77 means a prerequisite is missing (run-cell-script.sh fails that in
# CI, never a pass).
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
MATRIX_DIR=$REPO/scripts/provider-matrix
if [ $# -ne 2 ]; then echo "usage: pqc-cell.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "pqc-cell: no executable observer: $P" >&2; exit 2; }
case ${TASK_DIR:-} in '' ) echo "pqc-cell: TASK_DIR must be set" >&2; exit 2 ;; esac
[ -d "$TASK_DIR" ] || { echo "pqc-cell: TASK_DIR not a directory: $TASK_DIR" >&2; exit 2; }
if [ "$(id -u)" = 0 ]; then
  ROOTMODE=yes
  RUNUID=${RUNUID:-${SUDO_UID:-}}
  RUNGID=${RUNGID:-${SUDO_GID:-}}
  case $RUNUID in ''|*[!0-9]*) echo "pqc-cell: RUNUID must be a uid, got '${RUNUID:-}'" >&2; exit 2 ;; esac
  case $RUNGID in ''|*[!0-9]*) echo "pqc-cell: RUNGID must be a gid, got '${RUNGID:-}'" >&2; exit 2 ;; esac
  if [ "$RUNUID" = 0 ]; then echo "pqc-cell: refusing to run the workload as root (RUNUID=0)" >&2; exit 2; fi
  [ -z "${OBS_SUDO:-}" ] || { echo "pqc-cell: OBS_SUDO must be empty as root" >&2; exit 2; }
  command -v setpriv >/dev/null 2>&1 || { echo "pqc-cell: missing prerequisite: setpriv" >&2; exit 77; }
else
  ROOTMODE=no
  OBS_SUDO=${OBS_SUDO:-sudo -n}
fi
command -v gcc >/dev/null 2>&1 || { echo "pqc-cell: missing prerequisite: gcc" >&2; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "pqc-cell: missing prerequisite: python3" >&2; exit 77; }
PKCS11_TOOL=${PKCS11_TOOL:-pkcs11-tool}
command -v "$PKCS11_TOOL" >/dev/null 2>&1 || { echo "pqc-cell: missing prerequisite: $PKCS11_TOOL" >&2; exit 77; }
P11TEST_PIN=${P11TEST_PIN:-}
P11TEST_SO_PIN=${P11TEST_SO_PIN:-}
[ -z "$P11TEST_PIN" ] && { echo "pqc-cell: P11TEST_PIN env must be set (throwaway token PIN, never echoed)" >&2; exit 2; }
[ -z "$P11TEST_SO_PIN" ] && { echo "pqc-cell: P11TEST_SO_PIN env must be set (throwaway SO PIN, never echoed)" >&2; exit 2; }
export P11TEST_PIN P11TEST_SO_PIN
PKCS11_MODULE=$TASK_DIR/kryoptic-rpm/usr/lib64/pkcs11/libkryoptic_pkcs11.so
[ -f "$PKCS11_MODULE" ] || { echo "pqc-cell: no pinned kryoptic module (fetch-provider.sh kryoptic first): $PKCS11_MODULE" >&2; exit 2; }
COMPARE=$HERE/pqc_cell_compare.py
[ -f "$COMPARE" ] || { echo "pqc-cell: missing helper: $COMPARE" >&2; exit 2; }
WORKLOAD_SRC=$HERE/pqc-workload.c
[ -f "$WORKLOAD_SRC" ] || { echo "pqc-cell: missing helper: $WORKLOAD_SRC" >&2; exit 2; }
ENV_FILE=$MATRIX_DIR/providers/kryoptic.env
[ -f "$ENV_FILE" ] || { echo "pqc-cell: missing helper: $ENV_FILE" >&2; exit 2; }
export TASK_DIR PKCS11_MODULE PKCS11_TOOL PROVIDER_MATRIX_DIR=$MATRIX_DIR
export KRYOPTIC_CONF=$TASK_DIR/kryoptic/token.conf
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
if [ "$ROOTMODE" = yes ]; then chown "$RUNUID:$RUNGID" "$OUT" || exit 2; fi
{
  echo "provider_name=kryoptic"
  echo "provider_version=1.5.2"
  echo "p11scope=$P"
  [ -x "$P" ] && "$P" --version 2>/dev/null || echo "p11scope_version=UNKNOWN"
  echo "uname=$(uname -a)"
  sha256sum "$PKCS11_MODULE"
} >"$OUT/cell.env" 2>&1
# Token setup as the workload user (the sqlite db must stay writable
# by it): re-sourced under setpriv in root mode, direct in user mode.
if [ "$ROOTMODE" = yes ]; then
  set +e
  (export TASK_DIR PKCS11_MODULE PKCS11_TOOL PROVIDER_MATRIX_DIR KRYOPTIC_CONF
   # shellcheck disable=SC1090
   setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
     bash -c '. "$0"; kryoptic_setup "$1"' "$ENV_FILE" "$TASK_DIR" \
  ) >"$OUT/setup.log" 2>&1
  rc=$?
  echo "$rc" >"$OUT/setup.exit"
  set -e
else
  set +e
  (
    set -euo pipefail
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    kryoptic_setup "$TASK_DIR"
  ) >"$OUT/setup.log" 2>&1
  rc=$?
  echo "$rc" >"$OUT/setup.exit"
  set -e
fi
echo "pqc-cell: setup exit=$(cat "$OUT/setup.exit")"
[ "$(cat "$OUT/setup.exit")" = 0 ] || { echo "pqc-cell: kryoptic token setup failed (see setup.log)" >&2; exit 2; }
# Compile the workload (warnings fail the build).
set +e
gcc -O1 -Wall -Werror -o "$OUT/pqc-workload" "$WORKLOAD_SRC" -ldl >"$OUT/build.log" 2>&1
rc=$?
echo "$rc" >"$OUT/build.exit"
set -e
[ "$rc" = 0 ] || { echo "pqc-cell: workload build failed (see build.log)" >&2; exit 2; }
chmod a+rx "$OUT/pqc-workload" || exit 2
# One leg: workload waits for GO with no provider loaded; the observer
# starts with the kryoptic file prearmed; a sleeper releases GO after
# the attach wait; the workload settles 10 s past login, runs the six
# sets, and exits before the observer's duration ends.
run_leg() {
  leg=$1; shift
  READY=$OUT/$leg.ready
  GO=$OUT/$leg.go
  rm -f "$READY" "$GO"
  WL_ARGV=("$OUT/pqc-workload" --module "$PKCS11_MODULE" --ready "$READY" --go "$GO" --pin "$P11TEST_PIN" --pace 1 --settle 10 --post-sleep 5)
  set +e
  if [ "$ROOTMODE" = yes ]; then
    setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
      "${WL_ARGV[@]}" </dev/null >"$OUT/$leg.workload.log" 2>&1 8>&- &
  else
    "${WL_ARGV[@]}" </dev/null >"$OUT/$leg.workload.log" 2>&1 8>&- &
  fi
  WPID=$!
  set -e
  echo "$WPID" >"$OUT/$leg.workload.pid"
  for _ in $(seq 1 60); do
    [ -f "$READY" ] && break
    kill -0 "$WPID" 2>/dev/null || break
    sleep 1
  done
  if [ ! -f "$READY" ]; then
    kill -KILL "$WPID" 2>/dev/null || true
    echo "pqc-cell: $leg workload never became ready (see $leg.workload.log)" >&2
    return 2
  fi
  echo "pqc-cell: $leg workload pid=$WPID ready"
  ( sleep 30; touch "$GO" ) 8>&- &
  SLEEPER=$!
  set +e
  if [ "$ROOTMODE" = yes ]; then
    "$P" inventory --pid "$WPID" --duration 90 --key-operations "$@" --prearm-module "$PKCS11_MODULE" -v -o "$OUT/$leg.json" \
      >"$OUT/$leg.verbose.txt" 2>"$OUT/$leg.stderr.log"
  else
    # shellcheck disable=SC2086
    $OBS_SUDO "$P" inventory --pid "$WPID" --duration 90 --key-operations "$@" --prearm-module "$PKCS11_MODULE" -v -o "$OUT/$leg.json" \
      >"$OUT/$leg.verbose.txt" 2>"$OUT/$leg.stderr.log"
  fi
  rc=$?
  echo "$rc" >"$OUT/$leg.inventory.exit"
  set -e
  echo "pqc-cell: $leg inventory exit=$rc"
  wait "$SLEEPER" 2>/dev/null || true
  set +e
  for _ in $(seq 1 30); do
    kill -0 "$WPID" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$WPID" 2>/dev/null || true
  wait "$WPID"
  rc=$?
  echo "$rc" >"$OUT/$leg.workload.exit"
  set -e
  echo "pqc-cell: $leg workload exit=$rc"
  case $(cat "$OUT/$leg.workload.exit") in
    0) ;;
    *) echo "pqc-cell: $leg workload failed (see $leg.workload.log)" >&2; return 1 ;;
  esac
  [ "$(cat "$OUT/$leg.inventory.exit")" = 0 ] || { echo "pqc-cell: $leg inventory failed (see $leg.stderr.log)" >&2; return 1; }
  [ -s "$OUT/$leg.json" ] || { echo "pqc-cell: $leg missing $leg.json (observer produced nothing)" >&2; return 2; }
  return 0
}
run_leg sizes --key-sizes || exit $?
run_leg nosizes || exit $?
set +e
python3 -I "$COMPARE" --sizes-log "$OUT/sizes.workload.log" --sizes-exit "$(cat "$OUT/sizes.workload.exit")" \
  --sizes-inventory "$OUT/sizes.json" --sizes-inventory-exit "$(cat "$OUT/sizes.inventory.exit")" --sizes-text "$OUT/sizes.verbose.txt" \
  --nosizes-log "$OUT/nosizes.workload.log" --nosizes-exit "$(cat "$OUT/nosizes.workload.exit")" \
  --nosizes-inventory "$OUT/nosizes.json" --nosizes-inventory-exit "$(cat "$OUT/nosizes.inventory.exit")" --nosizes-text "$OUT/nosizes.verbose.txt" \
  --out-results "$OUT/results.jsonl" --out-summary "$OUT/summary.txt"
rc=$?
set -e
echo "pqc-cell: compare rc=$rc"
[ -s "$OUT/results.jsonl" ] || { echo "pqc-cell: missing results.jsonl" >&2; exit 2; }
exit "$rc"
