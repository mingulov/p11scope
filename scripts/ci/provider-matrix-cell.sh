#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# provider-matrix-cell.sh P11SCOPE OUTDIR: one provider-matrix cell.
# Runs the pinned pkcs11-check suite (or a pkcs11-tool probe for
# reader-less providers) against one provider in two legs ((a) alone,
# (b) under `p11scope run`), plus a `p11scope-discover` manifest assertion
# and a paced ctypes workload under `p11scope inventory --pid`. Judged by
# provider_matrix_cell_compare.py: identical results, observer-clean,
# run-observed (FAIL when the provider is not observed), inventory-pid
# (FAIL when the provider is not observed) and the discover row
# (kryoptic-multi-table for kryoptic). Fresh token per cell; PINs via
# P11TEST_PIN/P11TEST_SO_PIN env, never echoed; --rv-trace -o json oracle
# for the coverage figure. DEFAULT crash isolation always (never
# --isolation). Mode via P11CHECK_MODE=smoke (default, --marker smoke)
# or full (no marker).
# Provider comes from PROVIDER (scripts/provider-matrix/providers/*.env)
# with TASK_DIR holding fetched artifacts and cell state; module paths
# are probed from PROVIDER_CANDIDATES, never assumed.
# Two modes: as root (CI) the suite/setup/workload/discover drop to
# RUNUID/RUNGID via setpriv and the observer runs direct; as a user (test
# hosts) everything runs direct and the observer goes through
# $OBS_SUDO (default `sudo -n`) with the provider env. Exit 0 means every
# qualified row passed, 1 means a cell failed, 2 means a harness error,
# 77 means the provider is absent (system-only candidates, host UNRUN).
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
MATRIX_DIR=$REPO/scripts/provider-matrix
if [ $# -ne 2 ]; then echo "usage: provider-matrix-cell.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "provider-matrix-cell: no executable observer: $P" >&2; exit 2; }
case ${PROVIDER:-} in ''|*/*|*..*|" "* ) echo "provider-matrix-cell: PROVIDER must be a bare provider name, got '${PROVIDER:-}'" >&2; exit 2 ;; esac
case ${TASK_DIR:-} in '' ) echo "provider-matrix-cell: TASK_DIR must be set" >&2; exit 2 ;; esac
[ -d "$TASK_DIR" ] || { echo "provider-matrix-cell: TASK_DIR not a directory: $TASK_DIR" >&2; exit 2; }
MODE=${P11CHECK_MODE:-smoke}
case $MODE in
  smoke|full) ;;
  *) echo "provider-matrix-cell: P11CHECK_MODE must be smoke or full, got '$MODE'" >&2; exit 2 ;;
esac
if [ "$(id -u)" = 0 ]; then
  ROOTMODE=yes
  RUNUID=${RUNUID:-${SUDO_UID:-}}
  RUNGID=${RUNGID:-${SUDO_GID:-}}
  case $RUNUID in ''|*[!0-9]*) echo "provider-matrix-cell: RUNUID must be a uid, got '${RUNUID:-}'" >&2; exit 2 ;; esac
  case $RUNGID in ''|*[!0-9]*) echo "provider-matrix-cell: RUNGID must be a gid, got '${RUNGID:-}'" >&2; exit 2 ;; esac
  if [ "$RUNUID" = 0 ]; then echo "provider-matrix-cell: refusing to run the suite as root (RUNUID=0)" >&2; exit 2; fi
  [ -z "${OBS_SUDO:-}" ] || { echo "provider-matrix-cell: OBS_SUDO must be empty as root" >&2; exit 2; }
  command -v setpriv >/dev/null 2>&1 || { echo "provider-matrix-cell: missing prerequisite: setpriv" >&2; exit 77; }
else
  ROOTMODE=no
  OBS_SUDO=${OBS_SUDO:-sudo -n}
fi
ENV_FILE=$MATRIX_DIR/providers/$PROVIDER.env
[ -f "$ENV_FILE" ] || { echo "provider-matrix-cell: no such provider env: $ENV_FILE" >&2; exit 2; }
# shellcheck disable=SC1090
. "$ENV_FILE"
: "${PROVIDER_NAME:?env must set PROVIDER_NAME}"
: "${PROVIDER_VERSION:?env must set PROVIDER_VERSION}"
: "${PROVIDER_CANDIDATES:?env must set PROVIDER_CANDIDATES}"
: "${PROVIDER_SETUP:?env must set PROVIDER_SETUP}"
PROVIDER_ENV_VARS=${PROVIDER_ENV_VARS:-}
PROVIDER_TEARDOWN=${PROVIDER_TEARDOWN:-}
PROVIDER_PREFLIGHT=${PROVIDER_PREFLIGHT:-}
PROVIDER_SUITE=${PROVIDER_SUITE:-yes}
case $PROVIDER_SUITE in yes|no) ;; *) echo "provider-matrix-cell: PROVIDER_SUITE must be yes or no" >&2; exit 2 ;; esac
# Probe the module candidates in order ($TASK_DIR references expanded;
# env files are ours). A pinned task-dir copy wins over system paths.
PKCS11_MODULE=
# shellcheck disable=SC2086
for cand in $PROVIDER_CANDIDATES; do
  expanded=$(eval echo "$cand")
  if [ -f "$expanded" ]; then PKCS11_MODULE=$expanded; break; fi
done
if [ -z "$PKCS11_MODULE" ]; then
  case $PROVIDER_CANDIDATES in
    *TASK_DIR*) echo "provider-matrix-cell: no probed module (fetch/delivery missing? tried: $PROVIDER_CANDIDATES)" >&2; exit 2 ;;
    *) echo "provider-matrix-cell: provider absent (tried: $PROVIDER_CANDIDATES)" >&2; exit 77 ;;
  esac
fi
export TASK_DIR PKCS11_MODULE PROVIDER_MATRIX_DIR=$MATRIX_DIR
PKCS11_TOOL=${PKCS11_TOOL:-pkcs11-tool}
export PKCS11_TOOL
P11CHECK_BIN=${P11CHECK_BIN:-pkcs11-check}
DISCOVER=${P11SCOPE_DISCOVER_BIN:-$(dirname "$P")/p11scope-discover}
command -v python3 >/dev/null 2>&1 || { echo "provider-matrix-cell: missing prerequisite: python3" >&2; exit 77; }
[ -x "$DISCOVER" ] || { echo "provider-matrix-cell: no executable discover helper: $DISCOVER" >&2; exit 77; }
if [ "$PROVIDER_SUITE" = yes ]; then
  command -v "$P11CHECK_BIN" >/dev/null 2>&1 || { echo "provider-matrix-cell: missing prerequisite: $P11CHECK_BIN (pip install --require-hashes -r scripts/ci/pkcs11-check-requirements.txt)" >&2; exit 77; }
  [ -z "${P11TEST_PIN:-}" ] && { echo "provider-matrix-cell: P11TEST_PIN env must be set (throwaway token PIN, never echoed)" >&2; exit 2; }
  [ -z "${P11TEST_SO_PIN:-}" ] && { echo "provider-matrix-cell: P11TEST_SO_PIN env must be set (throwaway SO PIN, never echoed)" >&2; exit 2; }
  HAVE_VER=$("$P11CHECK_BIN" version 2>/dev/null) || { echo "provider-matrix-cell: cannot run $P11CHECK_BIN version" >&2; exit 77; }
  [ "$HAVE_VER" = "pkcs11-check 0.2.3" ] || { echo "provider-matrix-cell: want pkcs11-check 0.2.3, have '$HAVE_VER'" >&2; exit 1; }
else
  command -v "$PKCS11_TOOL" >/dev/null 2>&1 || { echo "provider-matrix-cell: missing prerequisite: $PKCS11_TOOL" >&2; exit 77; }
fi
# Provider env for the suite legs (exported, never echoed) and, in user
# mode, across $OBS_SUDO for the observer (sudo -n env K=V ...).
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
if [ "$PROVIDER_SUITE" = yes ]; then
  RUN_ENV+=("P11TEST_PIN=$P11TEST_PIN" "P11TEST_SO_PIN=$P11TEST_SO_PIN")
fi
as_user() {
  if [ "$ROOTMODE" = yes ]; then
    setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups "$@"
  else
    "$@"
  fi
}
obs() {
  if [ "$ROOTMODE" = yes ]; then
    "$@"
  else
    # shellcheck disable=SC2086
    $OBS_SUDO env "${RUN_ENV[@]}" "$@"
  fi
}
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
COMPARE=$HERE/provider_matrix_cell_compare.py
[ -f "$COMPARE" ] || { echo "provider-matrix-cell: missing helper: $COMPARE" >&2; exit 2; }
WORKLOAD=$MATRIX_DIR/workload-pace.py
[ -f "$WORKLOAD" ] || { echo "provider-matrix-cell: missing helper: $WORKLOAD" >&2; exit 2; }
echo "provider-matrix-cell: provider=$PROVIDER_NAME version=$PROVIDER_VERSION mode=$MODE suite=$PROVIDER_SUITE module=$PKCS11_MODULE"
{
  echo "provider_name=$PROVIDER_NAME"
  echo "provider_version=$PROVIDER_VERSION"
  echo "mode=$MODE"
  echo "suite=$PROVIDER_SUITE"
  echo "pkcs11_module=$PKCS11_MODULE"
  echo "task_dir=$TASK_DIR"
  echo "p11check=${P11CHECK_BIN:-n/a}"
  if [ "$PROVIDER_SUITE" = yes ]; then echo "p11check_version=$HAVE_VER"; fi
  echo "p11scope=$P"
  [ -x "$P" ] && "$P" --version 2>/dev/null || echo "p11scope_version=UNKNOWN"
  echo "discover=$DISCOVER"
  "$DISCOVER" --version 2>/dev/null || echo "discover_version=UNKNOWN"
  echo "uname=$(uname -a)"
  sha256sum "$PKCS11_MODULE"
} >"$OUT/cell.env" 2>&1
# Provider setup (token in the task folder) as the suite user: direct in
# user mode, or re-sourced under setpriv in root mode (setup functions
# cannot cross setpriv as shell functions). A stale extra-env file from an
# earlier cell in this task dir must not leak into this one.
rm -f "$TASK_DIR/.provider-extra-env"
if [ "$ROOTMODE" = yes ]; then
  set +e
  (export TASK_DIR PKCS11_MODULE PKCS11_TOOL PROVIDER_MATRIX_DIR
   # shellcheck disable=SC1090
   setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
     bash -c '. "$0"; "$1" "$2"' "$ENV_FILE" "$PROVIDER_SETUP" "$TASK_DIR" \
  ) >"$OUT/setup.log" 2>&1
  rc=$?
  echo "$rc" >"$OUT/setup.exit"
  set -e
else
  set +e
  (
    set -euo pipefail
    "$PROVIDER_SETUP" "$TASK_DIR"
  ) >"$OUT/setup.log" 2>&1
  rc=$?
  echo "$rc" >"$OUT/setup.exit"
  set -e
fi
echo "setup exit=$(cat "$OUT/setup.exit")"
if [ "$(cat "$OUT/setup.exit")" != 0 ]; then
  # A failing optional preflight means the provider is unusable here
  # (e.g. OpenSC with no reader-less mode): host UNRUN, not a failure.
  if [ -n "$PROVIDER_PREFLIGHT" ]; then
    set +e
    (
      set -euo pipefail
      "$PROVIDER_PREFLIGHT" "$TASK_DIR"
    ) >"$OUT/preflight.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" != 0 ]; then
      echo "provider-matrix-cell: preflight refused; provider UNRUN (see preflight.log)" >&2
      exit 77
    fi
  fi
  echo "provider-matrix-cell: provider setup failed (see setup.log)" >&2
  exit 2
fi
# Dynamic setup outputs (e.g. the p11-kit server address): KEY=VALUE lines
# this cell's own setup wrote to $TASK_DIR/.provider-extra-env (stale
# files went before setup ran, so nothing leaks across cells).
EXTRA_ENV=$TASK_DIR/.provider-extra-env
if [ -f "$EXTRA_ENV" ]; then
  while IFS='=' read -r name value; do
    case $name in ''|\#*) continue ;; esac
    case $name in *[!A-Za-z0-9_]*)
      echo "provider-matrix-cell: bad extra-env name: '$name'" >&2; exit 2 ;;
    esac
    export "$name=$value"
    RUN_ENV+=("$name=$value")
  done <"$EXTRA_ENV"
  echo "provider-matrix-cell: extra-env: $(cut -d= -f1 "$EXTRA_ENV" | tr '\n' ' ')"
fi
# Discover the module now (unprivileged helper, runs provider code in its
# own process). rc is judged by the compare, never aborts here.
set +e
as_user "$DISCOVER" --module "$PKCS11_MODULE" -o "$OUT/manifest.json" \
  >"$OUT/discover.stdout.log" 2>"$OUT/discover.stderr.log"
rc=$?
echo "$rc" >"$OUT/discover.exit"
set -e
echo "discover exit=$rc"
leg_prep() {
  dir=$1
  rm -f "$dir/results.json" "$dir/report.jsonl" "$dir/observed.json" \
    "$dir/observer.out" "$dir/observer.err" \
    "$dir/.pkcs11-check-isolation-state.json" "$dir/.pkcs11-check-isolation-state-policy.json"
}
# Never pass --isolation: DEFAULT (auto) crash isolation always.
wall_start() { date +%s.%N; }
wall_elapsed() {
  python3 -I - "$1" "$2" <<'PY'
import sys
print(f"{float(sys.argv[2]) - float(sys.argv[1]):.1f}")
PY
}
make_leg() {
  dir=$OUT/leg-$1
  mkdir -p "$dir" || return 1
  if [ "$ROOTMODE" = yes ]; then chown "$RUNUID:$RUNGID" "$dir" || return 1; fi
  leg_prep "$dir"
}
run_leg_a() {
  dir=$OUT/leg-a
  if [ "$PROVIDER_SUITE" = yes ]; then
    # shellcheck disable=SC2086
    set -- $1
    echo "provider-matrix-cell: leg (a) alone: $P11CHECK_BIN $*"
    start=$(wall_start)
    rc=0
    (cd "$dir" && as_user "$P11CHECK_BIN" "$@" >"$dir/stdout.log" 2>"$dir/stderr.log") || rc=$?
  else
    echo "provider-matrix-cell: leg (a) alone: $PKCS11_TOOL -L"
    start=$(wall_start)
    rc=0
    (cd "$dir" && as_user "$PKCS11_TOOL" --module "$PKCS11_MODULE" -L >"$dir/stdout.log" 2>"$dir/stderr.log") || rc=$?
  fi
  end=$(wall_start)
  echo "$rc" >"$dir/exit.txt"
  wall_elapsed "$start" "$end" >"$dir/wall.txt"
  echo "provider-matrix-cell: leg (a) exit=$rc wall=$(cat "$dir/wall.txt")s"
}
run_leg_b() {
  dir=$OUT/leg-b
  if [ "$PROVIDER_SUITE" = yes ]; then
    # shellcheck disable=SC2086
    set -- $1
    echo "provider-matrix-cell: leg (b) under run"
  else
    echo "provider-matrix-cell: leg (b) under run: $PKCS11_TOOL -L"
  fi
  start=$(wall_start)
  rc=0
  if [ "$PROVIDER_SUITE" = yes ]; then
    (cd "$dir" && obs "$P" run -o "$dir/observed.json" -- "$P11CHECK_BIN" "$@" \
      >"$dir/observer.out" 2>"$dir/observer.err") || rc=$?
  else
    (cd "$dir" && obs "$P" run -o "$dir/observed.json" -- "$PKCS11_TOOL" --module "$PKCS11_MODULE" -L \
      >"$dir/observer.out" 2>"$dir/observer.err") || rc=$?
  fi
  end=$(wall_start)
  echo "$rc" >"$dir/exit.txt"
  wall_elapsed "$start" "$end" >"$dir/wall.txt"
  echo "provider-matrix-cell: leg (b) exit=$rc wall=$(cat "$dir/wall.txt")s"
}
make_leg a || { echo "provider-matrix-cell: cannot prepare leg a" >&2; exit 2; }
make_leg b || { echo "provider-matrix-cell: cannot prepare leg b" >&2; exit 2; }
if [ "$PROVIDER_SUITE" = yes ]; then
  if [ "$MODE" = smoke ]; then
    ARGS_A="test --module $PKCS11_MODULE --marker smoke --rv-trace -o json --output-file $OUT/leg-a/results.json"
    ARGS_B="test --module $PKCS11_MODULE --marker smoke --rv-trace -o json --output-file $OUT/leg-b/results.json"
  else
    ARGS_A="test --module $PKCS11_MODULE --rv-trace -o json --output-file $OUT/leg-a/results.json"
    ARGS_B="test --module $PKCS11_MODULE --rv-trace -o json --output-file $OUT/leg-b/results.json"
  fi
  run_leg_a "$ARGS_A"
  run_leg_b "$ARGS_B"
  for leg in a b; do
    dir=$OUT/leg-$leg
    [ -s "$dir/results.json" ] || { echo "provider-matrix-cell: leg $leg missing results.json (suite did not finish)" >&2; exit 1; }
    [ -s "$dir/report.jsonl" ] || { echo "provider-matrix-cell: leg $leg missing report.jsonl" >&2; exit 1; }
  done
else
  run_leg_a ""
  run_leg_b ""
fi
[ -s "$OUT/leg-b/observed.json" ] || { echo "provider-matrix-cell: leg b missing observed.json (observer abort)" >&2; exit 1; }
# Inventory leg: paced workload under inventory --pid. The workload runs
# as the suite user without lane fds; the observer perms match leg (b).
WORK_ITER=100
READY=$OUT/workload.ready
rm -f "$READY"
set +e
as_user python3 -I "$WORKLOAD" --module "$PKCS11_MODULE" --ready "$READY" \
  --iterations $WORK_ITER --interval 1 \
  </dev/null >"$OUT/workload.log" 2>&1 8>&- &
WPID=$!
set -e
echo "$WPID" >"$OUT/workload.pid"
for _ in $(seq 1 60); do
  [ -f "$READY" ] && break
  kill -0 "$WPID" 2>/dev/null || break
  sleep 1
done
if [ ! -f "$READY" ]; then
  kill -KILL "$WPID" 2>/dev/null || true
  echo "provider-matrix-cell: workload never became ready (see workload.log)" >&2
  exit 2
fi
echo "provider-matrix-cell: workload pid=$WPID ready"
set +e
obs "$P" inventory --pid "$WPID" --duration 90 --json -o "$OUT/inventory.json" \
  >"$OUT/inventory.stdout.log" 2>"$OUT/inventory.stderr.log"
rc=$?
echo "$rc" >"$OUT/inventory.exit"
set -e
echo "provider-matrix-cell: inventory exit=$rc"
set +e
kill -TERM "$WPID" 2>/dev/null || true
for _ in $(seq 1 10); do
  kill -0 "$WPID" 2>/dev/null || break
  sleep 1
done
kill -KILL "$WPID" 2>/dev/null || true
wait "$WPID"
rc=$?
echo "$rc" >"$OUT/workload.exit"
set -e
echo "provider-matrix-cell: workload exit=$rc"
case $(cat "$OUT/workload.exit") in
  0|143|137) ;;
  *) echo "provider-matrix-cell: workload crashed (see workload.log)" >&2; exit 2 ;;
esac
[ -s "$OUT/inventory.json" ] || { echo "provider-matrix-cell: missing inventory.json (observer produced nothing)" >&2; exit 2; }
# Optional provider teardown (e.g. stop a forwarding server). A failing
# teardown warns but never rewrites the judged verdict.
if [ -n "$PROVIDER_TEARDOWN" ]; then
  if [ "$ROOTMODE" = yes ]; then
    set +e
    (export TASK_DIR PKCS11_MODULE PKCS11_TOOL PROVIDER_MATRIX_DIR
     # shellcheck disable=SC1090
     setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
       bash -c '. "$0"; "$1" "$2"' "$ENV_FILE" "$PROVIDER_TEARDOWN" "$TASK_DIR" \
    ) >"$OUT/teardown.log" 2>&1
    rc=$?
    echo "$rc" >"$OUT/teardown.exit"
    set -e
  else
    set +e
    (
      set -euo pipefail
      "$PROVIDER_TEARDOWN" "$TASK_DIR"
    ) >"$OUT/teardown.log" 2>&1
    rc=$?
    echo "$rc" >"$OUT/teardown.exit"
    set -e
  fi
  echo "provider-matrix-cell: teardown exit=$rc"
  [ "$rc" = 0 ] || echo "provider-matrix-cell: WARNING: teardown failed; a server may linger" >&2
fi
if [ "$PROVIDER_SUITE" = yes ]; then
  python3 -I "$COMPARE" --provider "$PROVIDER_NAME" --provider-version "$PROVIDER_VERSION" \
    --module "$PKCS11_MODULE" \
    --discover-rc "$(cat "$OUT/discover.exit")" --manifest "$OUT/manifest.json" \
    --discover-stderr "$OUT/discover.stderr.log" \
    --suite yes \
    --results-a "$OUT/leg-a/results.json" --report-a "$OUT/leg-a/report.jsonl" \
    --exit-a "$(cat "$OUT/leg-a/exit.txt")" --wall-a "$(cat "$OUT/leg-a/wall.txt")" \
    --results-b "$OUT/leg-b/results.json" --report-b "$OUT/leg-b/report.jsonl" \
    --exit-b "$(cat "$OUT/leg-b/exit.txt")" --wall-b "$(cat "$OUT/leg-b/wall.txt")" \
    --observed-b "$OUT/leg-b/observed.json" \
    --inventory "$OUT/inventory.json" --workload-pid "$WPID" \
    --out-results "$OUT/results.jsonl" --out-summary "$OUT/summary.txt"
else
  python3 -I "$COMPARE" --provider "$PROVIDER_NAME" --provider-version "$PROVIDER_VERSION" \
    --module "$PKCS11_MODULE" \
    --discover-rc "$(cat "$OUT/discover.exit")" --manifest "$OUT/manifest.json" \
    --discover-stderr "$OUT/discover.stderr.log" \
    --suite no \
    --exit-a "$(cat "$OUT/leg-a/exit.txt")" --wall-a "$(cat "$OUT/leg-a/wall.txt")" \
    --exit-b "$(cat "$OUT/leg-b/exit.txt")" --wall-b "$(cat "$OUT/leg-b/wall.txt")" \
    --observed-b "$OUT/leg-b/observed.json" \
    --inventory "$OUT/inventory.json" --workload-pid "$WPID" \
    --out-results "$OUT/results.jsonl" --out-summary "$OUT/summary.txt"
fi
rc=$?
echo "provider-matrix-cell: compare rc=$rc"
[ -s "$OUT/results.jsonl" ] || { echo "provider-matrix-cell: missing results.jsonl" >&2; exit 2; }
exit "$rc"
