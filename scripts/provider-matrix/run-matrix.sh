#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# run-matrix.sh: run the provider matrix on a Fedora test host.
# Delivers a dev-tip observer + discover helper, the cell scripts and the
# pinned provider artifacts to ~/p11scope-live/<task>/ on the host, runs
# one cell per provider through lane-run.sh (shared bpf, one lane hold
# per cell), collects out/ back, prints the per-provider table, and
# deletes the task folder unless --keep.
#
# Usage: run-matrix.sh --host HOST --task NAME --p11scope BIN --discover BIN
#   [--mode smoke|full] [--providers a,b,c] [--lane bpf|test]
#   [--collect DIR] [--extra-deliver PATH...] [--keep] [--print-plan]
#
# Default providers: softhsm2-2.7,softhsm2-2.6,kryoptic,haskoki,bouncyhsm,
# freehsm,opensc,p11kit-proxy,nss-softokn,p11kit-managed,p11kit-unmanaged,
# kryoptic-static-embed. Pinned artifacts (haskoki tarball, kryoptic
# and softhsm2.6 rpms) are fetched on the host with pinned sha256
# (scripts/ci/fetch-provider.sh); bouncyhsm/freehsm trees ride --extra-deliver
# (dirs named bouncyhsm/ freehsm/, see the matrix README). Smoke is
# minutes per cell; full is the whole pkcs11-check suite per provider.
# Exit 0 when no cell failed (UNRUN providers are shown in the table, not
# hidden), 1 when a cell failed, 2 on harness/collect/cleanup errors.
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 2
REPO=$(cd "$HERE/../.." && pwd) || exit 2
HOST=; TASK=; P11SCOPE=; DISCOVER=
MODE=smoke
PROVIDERS=softhsm2-2.7,softhsm2-2.6,kryoptic,haskoki,bouncyhsm,freehsm,opensc,p11kit-proxy,nss-softokn,p11kit-managed,p11kit-unmanaged,kryoptic-static-embed
LANE=bpf
COLLECT=./provider-matrix-out
KEEP=no
EXTRA=()
while [ $# -gt 0 ]; do
  case $1 in
    --host) HOST=$2; shift 2 ;;
    --task) TASK=$2; shift 2 ;;
    --p11scope) P11SCOPE=$2; shift 2 ;;
    --discover) DISCOVER=$2; shift 2 ;;
    --mode) MODE=$2; shift 2 ;;
    --providers) PROVIDERS=$2; shift 2 ;;
    --lane) LANE=$2; shift 2 ;;
    --collect) COLLECT=$2; shift 2 ;;
    --extra-deliver) EXTRA+=("$2"); shift 2 ;;
    --keep) KEEP=yes; shift ;;
    --print-plan) PRINT_PLAN=yes; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "run-matrix: unknown option: $1" >&2; exit 2 ;;
  esac
done
PRINT_PLAN=${PRINT_PLAN:-no}
[ -n "$HOST" ] || { echo "run-matrix: --host is required" >&2; exit 2; }
[ -n "$TASK" ] || { echo "run-matrix: --task is required" >&2; exit 2; }
case $TASK in *[/.]*|"") echo "run-matrix: --task must be a bare name" >&2; exit 2 ;; esac
case $MODE in smoke|full) ;; *) echo "run-matrix: --mode must be smoke or full" >&2; exit 2 ;; esac
case $LANE in bpf|test) ;; *) echo "run-matrix: --lane must be bpf or test" >&2; exit 2 ;; esac
OLDIFS=$IFS; IFS=,
# shellcheck disable=SC2206
PROVIDER_LIST=($PROVIDERS)
IFS=$OLDIFS
[ "${#PROVIDER_LIST[@]}" -gt 0 ] || { echo "run-matrix: empty --providers" >&2; exit 2; }
for p in "${PROVIDER_LIST[@]}"; do
  case $p in ''|*/*|*..*|*" "*) echo "run-matrix: bad provider name: '$p'" >&2; exit 2 ;; esac
  [ -f "$HERE/providers/$p.env" ] || { echo "run-matrix: unknown provider: $p" >&2; exit 2; }
done
if [ "$PRINT_PLAN" = yes ]; then
  echo "host=$HOST task=$TASK mode=$MODE lane=$LANE"
  for p in "${PROVIDER_LIST[@]}"; do
    # shellcheck disable=SC1090
    ( . "$HERE/providers/$p.env"
      echo "provider=$PROVIDER_NAME version=$PROVIDER_VERSION suite=${PROVIDER_SUITE:-yes}" )
  done
  exit 0
fi
[ -n "$P11SCOPE" ] || { echo "run-matrix: --p11scope is required" >&2; exit 2; }
[ -n "$DISCOVER" ] || { echo "run-matrix: --discover is required" >&2; exit 2; }
[ -x "$P11SCOPE" ] || { echo "run-matrix: no executable observer: $P11SCOPE" >&2; exit 2; }
[ -x "$DISCOVER" ] || { echo "run-matrix: no executable discover helper: $DISCOVER" >&2; exit 2; }
for x in "${EXTRA[@]}"; do
  [ -e "$x" ] || { echo "run-matrix: --extra-deliver missing: $x" >&2; exit 2; }
done
command -v ssh >/dev/null 2>&1 || { echo "run-matrix: missing prerequisite: ssh" >&2; exit 2; }
command -v rsync >/dev/null 2>&1 || { echo "run-matrix: missing prerequisite: rsync" >&2; exit 2; }
SSH="ssh -o BatchMode=yes -l user $HOST"
TASKDIR=/home/user/p11scope-live/$TASK
echo "run-matrix: host=$HOST task=$TASK mode=$MODE providers=$PROVIDERS lane=$LANE"
$SSH "install -d -m 700 '$TASKDIR' && test -x ~/p11scope-live/lane-run.sh" || { echo "run-matrix: host setup failed (task dir or lane-run.sh)" >&2; exit 2; }
FREE_KB=$($SSH "df -k ~ | awk 'NR==2 {print \$4}'") || { echo "run-matrix: df check failed" >&2; exit 2; }
case $FREE_KB in ''|*[!0-9]*) echo "run-matrix: cannot parse host free space" >&2; exit 2 ;; esac
if [ "$FREE_KB" -lt 5242880 ]; then echo "run-matrix: host has under 5 GB free; refusing" >&2; exit 2; fi
echo "run-matrix: host free: $((FREE_KB / 1024)) MB"
# Deliver: binaries, the scripts subtree (mirroring repo/scripts/ so the
# cell resolves its helpers), the pinned requirements, extras.
STAGE=$(mktemp -d "${TMPDIR:-/var/tmp}/p11matrix-stage.XXXXXX") || exit 2
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/repo/scripts/ci" "$STAGE/repo/scripts/provider-matrix/providers"
cp -p "$P11SCOPE" "$DISCOVER" "$STAGE/bin/" || exit 2
cp -p "$REPO/scripts/ci/provider-matrix-cell.sh" "$REPO/scripts/ci/provider_matrix_cell_compare.py" \
  "$REPO/scripts/ci/pkcs11_check_cell_compare.py" "$REPO/scripts/ci/fetch-provider.sh" \
  "$REPO/scripts/ci/pkcs11-check-requirements.txt" "$STAGE/repo/scripts/ci/" || exit 2
cp -p "$HERE/workload-pace.py" "$HERE/remote-cell.sh" "$HERE/pins.sh" \
  "$HERE/static-embed-cell.sh" "$HERE/static_embed_cell_compare.py" \
  "$STAGE/repo/scripts/provider-matrix/" || exit 2
cp -p "$HERE"/providers/*.env "$HERE"/providers/_p11kit_proxy_config.sh \
  "$HERE"/providers/_token_dir.sh \
  "$STAGE/repo/scripts/provider-matrix/providers/" || exit 2
rsync -a "$STAGE/bin/" "user@$HOST:$TASKDIR/bin/" || exit 2
rsync -a "$STAGE/repo/" "user@$HOST:$TASKDIR/repo/" || exit 2
for x in "${EXTRA[@]}"; do
  rsync -a "$x" "user@$HOST:$TASKDIR/" || exit 2
done
rm -rf "$STAGE"
trap - EXIT
SHA_LOCAL=$(mktemp "${TMPDIR:-/var/tmp}/p11matrix-sha.XXXXXX") || exit 2
{
  echo "$(sha256sum "$P11SCOPE" | cut -d' ' -f1)  $TASKDIR/bin/$(basename "$P11SCOPE")"
  echo "$(sha256sum "$DISCOVER" | cut -d' ' -f1)  $TASKDIR/bin/$(basename "$DISCOVER")"
} >"$SHA_LOCAL"
$SSH "sha256sum -c --quiet" <"$SHA_LOCAL" || { echo "run-matrix: binary sha mismatch on arrival" >&2; rm -f "$SHA_LOCAL"; exit 2; }
rm -f "$SHA_LOCAL"
echo "run-matrix: delivered, binary sha ok"
# Throwaway PINs (600 file, sourced on the host, never shown).
$SSH "umask 077 && printf 'P11TEST_PIN=1234\nP11TEST_SO_PIN=5678\n' >'$TASKDIR/pins.env' && chmod 600 '$TASKDIR/pins.env'" || exit 2
# Pinned pkcs11-check venv on the host.
$SSH "python3 -m venv '$TASKDIR/venv' && '$TASKDIR/venv/bin/pip' install --quiet --require-hashes -r '$TASKDIR/repo/scripts/ci/pkcs11-check-requirements.txt' && test \"\$('$TASKDIR/venv/bin/pkcs11-check' version)\" = 'pkcs11-check 0.2.3'" \
  || { echo "run-matrix: host venv setup failed" >&2; exit 2; }
echo "run-matrix: host venv ready (pkcs11-check 0.2.3)"
# One lane hold per cell; a failing cell never aborts the matrix.
mkdir -p "$COLLECT" || exit 2
OVERALL=0
UNRUN=
for p in "${PROVIDER_LIST[@]}"; do
  echo "run-matrix: === cell $p ==="
  rc=0
  # shellcheck disable=SC2029
  $SSH "TASKDIR='$TASKDIR' ~/p11scope-live/lane-run.sh shared '$LANE' env TASK_DIR='$TASKDIR' REPO='$TASKDIR/repo' OUT='$TASKDIR/out/$p' P11SCOPE='$TASKDIR/bin/$(basename "$P11SCOPE")' DISCOVER='$TASKDIR/bin/$(basename "$DISCOVER")' P11CHECK='$TASKDIR/venv/bin/pkcs11-check' PINS='$TASKDIR/pins.env' MODE='$MODE' OBS_SUDO='sudo -n' bash '$TASKDIR/repo/scripts/provider-matrix/remote-cell.sh' '$p'" || rc=$?
  echo "run-matrix: cell $p rc=$rc"
  echo "$rc" >"$COLLECT/$p.ssh-exit"
  case $rc in
    0) ;;
    77) UNRUN="$UNRUN $p" ;;
    1) [ "$OVERALL" = 0 ] && OVERALL=1 ;;
    *) OVERALL=2 ;;
  esac
done
[ -n "$UNRUN" ] && echo "run-matrix: UNRUN providers:$UNRUN"
rsync -a "user@$HOST:$TASKDIR/out/" "$COLLECT/out/" || { echo "run-matrix: collect failed" >&2; exit 2; }
echo "run-matrix: collected to $COLLECT/out"
python3 -I - "$COLLECT" "${PROVIDER_LIST[@]}" <<'PY'
import json
import sys
from pathlib import Path
collect = Path(sys.argv[1])
print("provider | cell rc | rows")
print("---|---|---")
for name in sys.argv[2:]:
    rc = (collect / f"{name}.ssh-exit").read_text().strip()
    results = collect / "out" / name / "cells" / "results.jsonl"
    if results.is_file():
        cells = []
        for line in results.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            mark = "PASS" if row["pass"] and row["qualification"] == "qualified" else row["qualification"]
            if not row["pass"] and row["qualification"] == "qualified":
                mark = "FAIL"
            cells.append(f"{row['cell']}={mark}")
        print(f"{name} | {rc} | {' '.join(cells)}")
    else:
        print(f"{name} | {rc} | no results.jsonl")
PY
if [ "$KEEP" = no ]; then
  $SSH "rm -rf '$TASKDIR'" || { echo "run-matrix: WARNING: task dir cleanup failed: $TASKDIR" >&2; exit 2; }
  echo "run-matrix: task dir deleted"
else
  echo "run-matrix: --keep: task dir left at $TASKDIR"
fi
exit "$OVERALL"
