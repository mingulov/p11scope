#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# pkcs11-check-cell.sh P11SCOPE OUTDIR: pkcs11-check suite under p11scope.
# Runs the owner's public pkcs11-check suite (PyPI, pinned 0.2.3, DEFAULT
# crash isolation) against SoftHSM (probed path) in three legs: (a) alone,
# (b) under `p11scope run` (default, no manifest), (c) under `p11scope run
# --manifest` (manifest from p11scope-discover, the verify-oracle shape).
# Fresh SoftHSM token per leg; PINs via P11TEST_PIN/P11TEST_SO_PIN env,
# never echoed; --rv-trace -o json oracle. Hard checks (in
# pkcs11_check_cell_compare.py): identical result sets across a/b/c,
# observer exit matches base with valid v3 reports (no abort), leg (c)
# oracle calls subset-of captured counts, leg (b) coverage vs a pinned
# floor (or a named expected-failure when slot exhaustion blinds it).
# Overhead (wall) printed. Mode via P11CHECK_MODE=smoke (default,
# --marker smoke, few minutes) or full (no marker, ~45 min).
# Must run as root; the template wrapper calls this directly. Exit 0 means
# every qualified row passed, 1 means a cell failed, 2 means a harness
# error, 77 means a prerequisite is missing.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
if [ $# -ne 2 ]; then echo "usage: pkcs11-check-cell.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "pkcs11-check-cell: no executable observer: $P" >&2; exit 2; }
if [ "$(id -u)" != 0 ]; then echo "pkcs11-check-cell: must run as root" >&2; exit 2; fi
MODE=${P11CHECK_MODE:-smoke}
case $MODE in
  smoke|full) ;;
  *) echo "pkcs11-check-cell: P11CHECK_MODE must be smoke or full, got '$MODE'" >&2; exit 2 ;;
esac
P11CHECK_BIN=${P11CHECK_BIN:-pkcs11-check}
DISCOVER=${P11SCOPE_DISCOVER_BIN:-$(dirname "$P")/p11scope-discover}
for tool in softhsm2-util python3 setpriv; do
  command -v "$tool" >/dev/null 2>&1 || { echo "pkcs11-check-cell: missing prerequisite: $tool" >&2; exit 77; }
done
command -v "$P11CHECK_BIN" >/dev/null 2>&1 || { echo "pkcs11-check-cell: missing prerequisite: $P11CHECK_BIN (pip install --require-hashes -r scripts/ci/pkcs11-check-requirements.txt)" >&2; exit 77; }
[ -x "$DISCOVER" ] || { echo "pkcs11-check-cell: no executable discover helper: $DISCOVER" >&2; exit 77; }
[ -z "${P11TEST_PIN:-}" ] && { echo "pkcs11-check-cell: P11TEST_PIN env must be set (throwaway token PIN, never echoed)" >&2; exit 2; }
[ -z "${P11TEST_SO_PIN:-}" ] && { echo "pkcs11-check-cell: P11TEST_SO_PIN env must be set (throwaway SO PIN, never echoed)" >&2; exit 2; }
# The observer drops `run` children to the sudo invoker; leg (a) uses the
# same account via setpriv so all three legs run as one user.
RUNUID=${RUNUID:-${SUDO_UID:-}}
RUNGID=${RUNGID:-${SUDO_GID:-}}
case $RUNUID in ''|*[!0-9]*) echo "pkcs11-check-cell: RUNUID must be a uid, got '${RUNUID:-}'" >&2; exit 2 ;; esac
case $RUNGID in ''|*[!0-9]*) echo "pkcs11-check-cell: RUNGID must be a gid, got '${RUNGID:-}'" >&2; exit 2 ;; esac
if [ "$RUNUID" = 0 ]; then echo "pkcs11-check-cell: refusing to run the suite as root (RUNUID=0)" >&2; exit 2; fi
probe_module() {
  for cand in "/usr/lib/softhsm/libsofthsm2.so" \
      "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" \
      "/usr/lib64/pkcs11/libsofthsm2.so" \
      "/usr/lib64/softhsm/libsofthsm2.so"; do
    if [ -f "$cand" ]; then echo "$cand"; return 0; fi
  done
  return 1
}
MODULE=${MODULE:-$(probe_module || true)}
[ -n "$MODULE" ] || { echo "pkcs11-check-cell: no SoftHSM library found (Debian/Fedora layouts probed)" >&2; exit 77; }
[ -f "$MODULE" ] || { echo "pkcs11-check-cell: MODULE not found: $MODULE" >&2; exit 77; }
# Pinned suite version: the binary must report exactly it.
HAVE_VER=$("$P11CHECK_BIN" version 2>/dev/null) || { echo "pkcs11-check-cell: cannot run $P11CHECK_BIN version" >&2; exit 77; }
[ "$HAVE_VER" = "pkcs11-check 0.2.3" ] || { echo "pkcs11-check-cell: want pkcs11-check 0.2.3, have '$HAVE_VER'" >&2; exit 1; }
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
COMPARE=$HERE/pkcs11_check_cell_compare.py
[ -f "$COMPARE" ] || { echo "pkcs11-check-cell: missing helper: $COMPARE" >&2; exit 2; }
# Default-coverage floor, set from the smoke measurement (see the lane
# report): leg (b) without a manifest must reach it, else it records the
# named slot-exhaustion expected-failure when the report proves it.
FLOOR=0.50
echo "pkcs11-check-cell: mode=$MODE module=$MODULE floor=$FLOOR"
echo "pkcs11-check-cell: suite=$HAVE_VER observer=$P discover=$DISCOVER run as $RUNUID:$RUNGID"
make_token() {
  leg=$1
  dir=$OUT/leg-$leg
  mkdir -p "$dir/tokens" || return 1
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$dir" >"$dir/softhsm2.conf" || return 1
  chown -R "$RUNUID:$RUNGID" "$dir" || return 1
  chmod 700 "$dir" "$dir/tokens" || return 1
  chmod 600 "$dir/softhsm2.conf" || return 1
  # PINs travel in args to softhsm2-util only; this script never prints them.
  (export SOFTHSM2_CONF=$dir/softhsm2.conf
   setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
    softhsm2-util --init-token --free --label lane \
    --so-pin "$P11TEST_SO_PIN" --pin "$P11TEST_PIN" >/dev/null 2>&1) || return 1
}
for leg in a b c; do
  make_token "$leg" || { echo "pkcs11-check-cell: token init failed for leg $leg" >&2; exit 2; }
done
chown "$RUNUID:$RUNGID" "$OUT" 2>/dev/null || true
# The verify-oracle manifest shape: discover the SoftHSM module now.
"$DISCOVER" --module "$MODULE" -o "$OUT/manifest.json" || { echo "pkcs11-check-cell: discover failed" >&2; exit 2; }
[ -s "$OUT/manifest.json" ] || { echo "pkcs11-check-cell: empty manifest" >&2; exit 2; }
suite_args() {
  leg=$1
  dir=$OUT/leg-$leg
  # Drop stale verdict files first: a re-run into a reused OUT must not judge
  # the previous run's outputs when a leg aborts before overwriting them.
  rm -f "$dir/results.json" "$dir/report.jsonl" "$dir/observed.json" \
    "$dir/observer.out" "$dir/observer.err" \
    "$dir/.pkcs11-check-isolation-state.json" "$dir/.pkcs11-check-isolation-state-policy.json"
  if [ "$MODE" = smoke ]; then
    echo "test --module $MODULE --marker smoke --rv-trace -o json --output-file $dir/results.json"
  else
    echo "test --module $MODULE --rv-trace -o json --output-file $dir/results.json"
  fi
}
# Never pass --isolation: DEFAULT (auto) crash isolation always.
wall_start() { date +%s.%N; }
wall_elapsed() {
  python3 -I - "$1" "$2" <<'PY'
import sys
print(f"{float(sys.argv[2]) - float(sys.argv[1]):.1f}")
PY
}
run_leg_a() {
  dir=$OUT/leg-a
  # shellcheck disable=SC2086
  set -- $1
  echo "pkcs11-check-cell: leg (a) alone: $P11CHECK_BIN $*"
  start=$(wall_start)
  rc=0
  # PINs stay in the inherited environment (from the workflow's sudo env);
  # only SOFTHSM2_CONF varies per leg. Nothing secret is printed or arg-passed.
  (cd "$dir" && export SOFTHSM2_CONF=$dir/softhsm2.conf
   setpriv --reuid="$RUNUID" --regid="$RUNGID" --clear-groups \
    "$P11CHECK_BIN" "$@" >"$dir/stdout.log" 2>"$dir/stderr.log") || rc=$?
  end=$(wall_start)
  echo "$rc" >"$dir/exit.txt"
  wall_elapsed "$start" "$end" >"$dir/wall.txt"
  echo "pkcs11-check-cell: leg (a) exit=$rc wall=$(cat "$dir/wall.txt")s"
}
run_leg_obs() {
  leg=$1; manifest=$2; suite=$3
  dir=$OUT/leg-$leg
  # shellcheck disable=SC2086
  set -- $suite
  if [ -n "$manifest" ]; then
    echo "pkcs11-check-cell: leg ($leg) under run --manifest"
  else
    echo "pkcs11-check-cell: leg ($leg) under run (default)"
  fi
  start=$(wall_start)
  rc=0
  # The run child inherits the observer's environment (per-leg conf plus the
  # workflow-supplied PINs), so no /usr/bin/env wrapper is needed.
  if [ -n "$manifest" ]; then
    (cd "$dir" && export SOFTHSM2_CONF=$dir/softhsm2.conf
     "$P" run --manifest "$manifest" -o "$dir/observed.json" -- "$P11CHECK_BIN" "$@" \
      >"$dir/observer.out" 2>"$dir/observer.err") || rc=$?
  else
    (cd "$dir" && export SOFTHSM2_CONF=$dir/softhsm2.conf
     "$P" run -o "$dir/observed.json" -- "$P11CHECK_BIN" "$@" \
      >"$dir/observer.out" 2>"$dir/observer.err") || rc=$?
  fi
  end=$(wall_start)
  echo "$rc" >"$dir/exit.txt"
  wall_elapsed "$start" "$end" >"$dir/wall.txt"
  echo "pkcs11-check-cell: leg ($leg) exit=$rc wall=$(cat "$dir/wall.txt")s"
}
ARGS_A=$(suite_args a); ARGS_B=$(suite_args b); ARGS_C=$(suite_args c)
run_leg_a "$ARGS_A"
run_leg_obs b "" "$ARGS_B"
run_leg_obs c "$OUT/manifest.json" "$ARGS_C"
# report.jsonl lands next to results.json (phase4-oracle.md).
for leg in a b c; do
  dir=$OUT/leg-$leg
  [ -s "$dir/results.json" ] || { echo "pkcs11-check-cell: leg $leg missing results.json (suite did not finish)" >&2; exit 1; }
  [ -s "$dir/report.jsonl" ] || { echo "pkcs11-check-cell: leg $leg missing report.jsonl" >&2; exit 1; }
done
for leg in b c; do
  [ -s "$OUT/leg-$leg/observed.json" ] || { echo "pkcs11-check-cell: leg $leg missing observed.json (observer abort)" >&2; exit 1; }
done
chown -R root:root "$OUT/leg-a" "$OUT/leg-b" "$OUT/leg-c" 2>/dev/null || true
python3 -I "$COMPARE" --mode "$MODE" \
  --results-a "$OUT/leg-a/results.json" --report-a "$OUT/leg-a/report.jsonl" \
  --exit-a "$(cat "$OUT/leg-a/exit.txt")" --wall-a "$(cat "$OUT/leg-a/wall.txt")" \
  --results-b "$OUT/leg-b/results.json" --report-b "$OUT/leg-b/report.jsonl" \
  --exit-b "$(cat "$OUT/leg-b/exit.txt")" --wall-b "$(cat "$OUT/leg-b/wall.txt")" \
  --observed-b "$OUT/leg-b/observed.json" \
  --results-c "$OUT/leg-c/results.json" --report-c "$OUT/leg-c/report.jsonl" \
  --exit-c "$(cat "$OUT/leg-c/exit.txt")" --wall-c "$(cat "$OUT/leg-c/wall.txt")" \
  --observed-c "$OUT/leg-c/observed.json" \
  --floor "$FLOOR" --out-results "$OUT/results.jsonl" --out-summary "$OUT/summary.txt"
rc=$?
echo "pkcs11-check-cell: compare rc=$rc"
[ -s "$OUT/results.jsonl" ] || { echo "pkcs11-check-cell: missing results.jsonl" >&2; exit 2; }
exit "$rc"
