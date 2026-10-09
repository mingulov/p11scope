#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-release-matrix.sh — exact selected release-matrix assertions.
# Full Stage5 remains owner-manual; valid smoke exits 2, never full coverage PASS.
#
#   qualify-release-matrix.sh --rev REV [--kernels "K1 K2..."] [options]
#   qualify-release-matrix.sh --bin-dir DIR --rev REV [--kernels ...]
#   qualify-release-matrix.sh --dry-run [--rev REV] [--kernels ...]
#   qualify-release-matrix.sh --self-test   (hermetic: no vng, kernels or privilege; runs in hosted CI)
#   qualify-release-matrix.sh --preflight   (this host: vng, kernel caches, stage and lock dirs)
#
# Runs, per kernel, with release binaries (cargo build --release --locked, Rust 1.98.1):
#   1. public CLI: qualify-public-cli.sh + qualify-inventory-native.sh (scan+native)
#      + --version, against the SoftHSM2 fixtures those scripts use (p11-kit is
#      covered by the priv-lib broad_p11kit cell);
#   2. exact default lib cells plus three explicitly selected native breadth gates;
#   3. doctor capability-tier line;
#   4. independently proven PID/system capability-dependent backend outcomes.
# --judge-stage STAGE --contract STAGE/contract.json is nonexecuting.
# --write-inner-stage STAGE --contract STAGE/contract.json only writes execution argv.
#
# Guest I/O staging: vng shares the host rootfs read-only and hides host /tmp
# and /var/tmp, so per-kernel stage dirs live under /home (STAGE_BASE) and are
# passed as vng --rwdir; results are copied to OUT_BASE (under /var/tmp) with
# summary.md at OUT_BASE/<rev>/summary.md and raw logs alongside.
# Privileged work is serialized under flock(LOCK); one guest runs at a time;
# every guest is bounded by timeout; quiet-window file pauses before each guest.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd -P)
RUST=1.98.1
LOCK=/var/tmp/p11scope-ws-tmp/privileged.lock
QUIET=/var/tmp/p11scope-ws-tmp/QUIET-WINDOW
OUT_BASE=/var/tmp/p11scope-ws-tmp/rc-qualify
STAGE_BASE=/home/user/.cache/p11scope-vng/rc-qualify
TIMEOUT=5400
DRY_RUN=0
SELF_TEST=0
PREFLIGHT=0
REV=""
BIN_DIR=""
CANDIDATE_RECEIPT=""
KERNELS_ARG=""
KERNELS_SUPPLIED=0
JUDGE_STAGE=""
WRITE_STAGE=""
CONTRACT=""
CHECKER=$REPO/scripts/release-matrix-contract.py

usage() {
  sed -n '2,30p' "$0" >&2
}

# Source-registered kernels and the separately owned host lane.
default_kernels() {
  printf '%s\n' \
    "v5.15.221" \
    "v6.1.188" \
    "v6.6.157" \
    "/home/user/.cache/virtme-ng/ubuntu-6.8.0-142/amd64/boot/vmlinuz-6.8.0-142-generic" \
    "v6.12.111" \
    "v7.2.6" \
    "host"
}

resolve_kernel() {
  case "$1" in
    5.15|5.15.221|v5.15.221) echo "v5.15.221" ;;
    6.1|6.1.188|v6.1.188) echo "v6.1.188" ;;
    6.6|6.6.157|v6.6.157) echo "v6.6.157" ;;
    host) echo host ;;
    6.8|6.8.0-142|6.8.0-142-generic|ubuntu-6.8*) echo "/home/user/.cache/virtme-ng/ubuntu-6.8.0-142/amd64/boot/vmlinuz-6.8.0-142-generic" ;;
    6.12|6.12.111|v6.12.111) echo "v6.12.111" ;;
    7.2|7.2.6|v7.2.6) echo "v7.2.6" ;;
    *) echo "$1" ;;
  esac
}

tag_for_kernel() {
  basename "$1" | sed 's/vmlinuz-//'
}

# Hosted CI (GitHub sets CI=true) runs --self-test only: no vng, no kernel
# fetch and no /home/user writes may be required there. In CI mode preflight
# downgrades the guest-gated checks to SKIP and stages under $TMPDIR, so a
# --preflight probe stays informative where only --self-test runs. Real-run
# behavior outside CI is unchanged: missing requirements still FAIL.
ci_mode() { [ "${CI:-false}" = "true" ]; }

# Parse args.
POS_KERNELS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --judge-stage) JUDGE_STAGE=$2; shift 2 ;;
    --write-inner-stage) WRITE_STAGE=$2; shift 2 ;;
    --contract) CONTRACT=$2; shift 2 ;;
    --plan) DRY_RUN=1; shift ;;
    --rev) REV=$2; shift 2 ;;
    --bin-dir) BIN_DIR=$2; shift 2 ;;
    --candidate-receipt) CANDIDATE_RECEIPT=$2; shift 2 ;;
    --kernels) KERNELS_ARG=$2; KERNELS_SUPPLIED=1; shift 2 ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    --out-base) OUT_BASE=$2; shift 2 ;;
    --stage-base) STAGE_BASE=$2; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --self-test) SELF_TEST=1; shift ;;
    --preflight) PREFLIGHT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "unknown option $1" >&2; usage; exit 2 ;;
    *) POS_KERNELS+=("$1"); shift ;;
  esac
done

if [ -n "$JUDGE_STAGE" ]; then
  [ -n "$CONTRACT" ] || { echo '--contract required' >&2; exit 1; }
  exec python3 -I "$CHECKER" --judge "$JUDGE_STAGE" --contract "$CONTRACT"
fi

# Kernel list: --kernels splits on whitespace/commas, plus positional kernels.
KERNELS=()
if [ "$KERNELS_SUPPLIED" -eq 1 ]; then
  read -r -a KERNELS <<< "${KERNELS_ARG//,/ }"
  [ "${#KERNELS[@]}" -gt 0 ] || { echo 'empty kernel selection' >&2; exit 1; }
fi
if [ "${#POS_KERNELS[@]}" -gt 0 ]; then
  for k in "${POS_KERNELS[@]}"; do
    [[ "$k" =~ [^[:space:],] ]] || { echo 'empty kernel positional lane' >&2; exit 1; }
  done
  KERNELS+=("${POS_KERNELS[@]}")
fi
if [ "${#KERNELS[@]}" -eq 0 ] && [ "$SELF_TEST" -eq 0 ] && [ "$PREFLIGHT" -eq 0 ]; then
  mapfile -t KERNELS < <(default_kernels)
fi
RESOLVED=()
for k in "${KERNELS[@]:-}"; do
  [ -n "$k" ] || continue
  RESOLVED+=("$(resolve_kernel "$k")")
done
KERNELS=()
if [ "${#RESOLVED[@]}" -gt 0 ]; then
  KERNELS=("${RESOLVED[@]}")
fi
if [ "$SELF_TEST" -eq 0 ] && [ "$PREFLIGHT" -eq 0 ] && [ -z "$WRITE_STAGE" ]; then
  [ "${#KERNELS[@]}" -gt 0 ] || { echo 'empty kernel resolved lane set' >&2; exit 1; }
fi

if [ -z "$REV" ] && [ -z "$BIN_DIR" ] && [ "$DRY_RUN" -eq 0 ] && [ "$SELF_TEST" -eq 0 ] && [ "$PREFLIGHT" -eq 0 ] && [ -z "$WRITE_STAGE" ]; then
  echo "need --rev REV or --bin-dir DIR" >&2; usage; exit 2
fi
if [ -n "$BIN_DIR" ]; then
  BIN_DIR=$(realpath -e "$BIN_DIR") || { echo "bin-dir not found: $BIN_DIR" >&2; exit 2; }
  case "$BIN_DIR" in /tmp/*|/var/tmp/*) echo "bin-dir must be under /home (vng hides /tmp and /var/tmp)" >&2; exit 2 ;; esac
  [ -z "$REV" ] && REV="bins-$(basename "$BIN_DIR")"
fi
# Short rev for dir names.
REV_SHORT=${REV//[^A-Za-z0-9._-]/_}
[ -n "$REV_SHORT" ] || REV_SHORT="norun"

print_plan() {
  echo "rev=$REV (dir $REV_SHORT)"
  echo "repo=$REPO rust=+$RUST jobs=${CARGO_BUILD_JOBS:-4} tmpdir=${TMPDIR:-/var/tmp/p11scope-ws-tmp}"
  echo "out_base=$OUT_BASE stage_base=$STAGE_BASE lock=$LOCK quiet=$QUIET timeout=${TIMEOUT}s"
  echo "kernels (${#KERNELS[@]}):"
  for k in "${KERNELS[@]}"; do
    echo "  $k tag=$(tag_for_kernel "$k") PID=proof-dependent system=independent-functional-link-proof"
    lane=$(tag_for_kernel "$k"); lane=${lane#v}
    python3 -I "$CHECKER" --plan --lane "$lane" || return 1
  done
  echo "public contention: THREADS=12; libtest threads=1"
  echo "binaries: $([ -n "$BIN_DIR" ] && echo "bin-dir $BIN_DIR" || echo "build --rev $REV from $REPO")"
}

if [ "$DRY_RUN" -eq 1 ]; then
  print_plan || exit 1
  echo "dry-run: no build, no guests started"
  exit 0
fi

# Host readiness for a real run: tools, kernel caches and writable dirs.
preflight() {
  fail=0
  say() { echo "$1"; }
  check() { if eval "$2"; then say "OK $1"; else say "FAIL $1"; fail=1; fi; }
  guest_check() { if eval "$2"; then say "OK $1"; elif ci_mode; then say "SKIP $1 (absent; hosted CI starts no guests and fetches no kernels)"; else say "FAIL $1"; fail=1; fi; }
  check "repo $REPO" "[ -d '$REPO/scripts' ]"
  check "qualify-public-cli.sh" "[ -x '$REPO/scripts/qualify-public-cli.sh' ]"
  check "qualify-inventory-native.sh" "[ -x '$REPO/scripts/qualify-inventory-native.sh' ]"
  check "run-privileged-lib-tests.sh" "[ -x '$REPO/scripts/run-privileged-lib-tests.sh' ]"
  check "rust $RUST" "rustup toolchain list 2>/dev/null | grep -q '$RUST'"
  guest_check "vng on PATH" "command -v vng >/dev/null"
  check "flock on PATH" "command -v flock >/dev/null"
  check "timeout on PATH" "command -v timeout >/dev/null"
  lock_test="[ -d '$(dirname "$LOCK")' ]"
  if ci_mode; then lock_test="$lock_test || mkdir -p '$(dirname "$LOCK")'"; fi
  check "lock parent $(dirname "$LOCK")" "$lock_test"
  check "out base parent $(dirname "$OUT_BASE")" "[ -d '$(dirname "$OUT_BASE")' ] || mkdir -p '$OUT_BASE'"
  if ci_mode; then
    stage_probe=${TMPDIR:-/tmp}/qrm-preflight-stage
    check "stage base writable ($stage_probe)" "mkdir -p '$stage_probe' && [ -w '$stage_probe' ]"
  else
    check "stage base writable" "mkdir -p '$STAGE_BASE' && [ -w '$STAGE_BASE' ]"
  fi
  for k in $(default_kernels); do
    case "$k" in
      host) check "host lane sudo" "command -v sudo >/dev/null" ;;
      /*) guest_check "kernel file $k" "[ -f '$k' ]" ;;
      *) guest_check "kernel cache $k" "[ -d \"/home/user/.cache/virtme-ng/$k\" ]" ;;
    esac
  done
  if [ -e "$QUIET" ]; then say "WARN quiet window present: $QUIET"; fi
  if [ $fail -eq 0 ]; then say "preflight: OK"; else say "preflight: FAIL"; fi
  return $fail
}

# Hermetic checks of this script's own logic: no vng, kernel cache, privilege
# or host path is needed, so hosted CI runs it.
self_test() {
  # The real shell plan and judge are exercised through bounded controlled files.
  python3 -I "$REPO/tests/python/test_release_matrix_contract.py" -v
}

if [ "$SELF_TEST" -eq 1 ]; then
  self_test
  exit $?
fi
if [ "$PREFLIGHT" -eq 1 ]; then
  print_plan
  preflight
  exit $?
fi

# The same tested module judges hermetic controls and exported production runs.
judge_kernel() {
  python3 -I "$CHECKER" --judge "$1" --contract "$1/contract.json"
}

# Only writes a concrete Bash script; no command in it runs during preparation.
write_inner() {
  local stage=$1 lib_command names
  python3 -I "$CHECKER" --verify-launch-policy || return 1
  python3 -I "$CHECKER" --verify-inputs "$stage" --contract "$stage/contract.json" || return 1
  local -a selectors
  names=$(python3 - "$stage/contract.json" <<'PYARGS'
import json,sys
print("\n".join(json.load(open(sys.argv[1]))["lib_tests"]))
PYARGS
) || return 1
  mapfile -t selectors <<< "$names"
  printf -v lib_command '%q ' "$REPO/scripts/run-privileged-lib-tests.sh" \
    "$stage/artifacts/p11scope-lib" "$stage/work/priv/run" --include-long "${selectors[@]}"
  {
    echo '#!/bin/bash'
    echo 'set -uo pipefail'
    printf 'STAGE=%q\nR=%q\n' "$stage" "$REPO"
    printf 'LIB_COMMAND=%q\n' "$lib_command"
    cat <<'INNER'
P=$STAGE/artifacts/p11scope
BM=$STAGE/artifacts/p11scope-bpfmulti
WORK=$STAGE/work
python3 -I "$R/scripts/release-matrix-contract.py" --verify-launch-policy || exit 1
python3 -I "$R/scripts/release-matrix-contract.py" --verify-inputs "$STAGE" --contract "$STAGE/contract.json" || exit 1
RUN_ID=$(python3 - "$STAGE/contract.json" <<'PYRUN'
import json,sys
print(json.load(open(sys.argv[1]))['run_id'])
PYRUN
) || exit 1
record_exit() { printf '%s_exit=%s\nmatrix_run=%s\n' "$2" "$3" "$RUN_ID" >> "$1"; }
export SUDO_UID=${SUDO_UID:-1000} SUDO_GID=${SUDO_GID:-1000} SUDO_USER=${SUDO_USER:-user}
mkdir -p "$WORK/qual" "$WORK/priv" "$WORK/backend" "$WORK/c8-native" "$WORK/c8-scan" || exit 1
chmod 0711 "$WORK" "$WORK/c8-native" "$WORK/c8-scan" || exit 1
mkdir -p "$WORK/tmp"; chmod 0700 "$WORK/tmp" || exit 1
export TMPDIR=$WORK/tmp
umask 022
uname -r > "$STAGE/uname.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$STAGE/guest-start.txt"
ulimit -n 65536 || exit 1
"$P" --version > "$STAGE/version.log" 2>&1
record_exit "$STAGE/version.log" version "$?"
"$P" doctor > "$STAGE/doctor.log" 2>&1
record_exit "$STAGE/doctor.log" doctor "$?"
THREADS=12 "$R/scripts/qualify-public-cli.sh" "$P" "$WORK/qual/cells" > "$STAGE/qual.log" 2>&1
record_exit "$STAGE/qual.log" qual "$?"
[ ! -d "$WORK/qual/cells" ] || cp -r "$WORK/qual/cells" "$STAGE/cells"
"$R/scripts/qualify-inventory-native.sh" "$P" --lane native --base "$WORK/c8-native" > "$STAGE/inv-native.log" 2>&1
record_exit "$STAGE/inv-native.log" inv_native "$?"
cp -r "$WORK/c8-native" "$STAGE/c8-native" 2>/dev/null || true
"$R/scripts/qualify-inventory-native.sh" "$P" --lane scan --base "$WORK/c8-scan" > "$STAGE/inv-scan.log" 2>&1
record_exit "$STAGE/inv-scan.log" inv_scan "$?"
cp -r "$WORK/c8-scan" "$STAGE/c8-scan" 2>/dev/null || true
(cd "$R" && eval "$LIB_COMMAND") > "$STAGE/priv.log" 2>&1
record_exit "$STAGE/priv.log" priv "$?"
[ ! -d "$WORK/priv/run" ] || cp -r "$WORK/priv/run" "$STAGE/run"
"$BM" --exact tests::the_pid_filter_probe_reaches_the_kernel --test-threads=1 --nocapture > "$STAGE/pidflt.log" 2>&1
record_exit "$STAGE/pidflt.log" pidflt "$?"
# Auto PID and system routes are decided independently by functional probes.
# These observations corroborate backend selection; counted coverage is supplied
# by the separately ledgered public/native assertions above.
MODULE=${MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}
[ -f "$MODULE" ] || MODULE=/usr/lib/softhsm/libsofthsm2.so
backend_probe() {
  local scope=$1 gate=$WORK/backend/gate-$1 wl observer rc
  setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --clear-groups \
    env SOFTHSM2_CONF="$WORK/qual/cells/softhsm2.conf" \
    "$WORK/qual/cells/fix/gated" "$MODULE" 500 200 "$gate" > "$WORK/backend/wl-$scope.log" 2>&1 &
  wl=$!
  local ready=0
  for _ in $(seq 300); do
    if grep -qx "READY pid=$wl" "$WORK/backend/wl-$scope.log"; then ready=1; break; fi
    kill -0 "$wl" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$ready" -ne 1 ]; then
    kill -TERM "$wl" 2>/dev/null || true; wait "$wl" 2>/dev/null || true
    return 1
  fi
  local -a scope_args
  if [ "$scope" = pid ]; then scope_args=(--pid "$wl"); else scope_args=(--system); fi
  "$P" inventory "${scope_args[@]}" --capture native --duration 10 \
    -o "$WORK/backend/inv-$scope.json" > "$WORK/backend/inv-$scope.stdout" 2> "$WORK/backend/inv-$scope.stderr" &
  observer=$!
  local capture=0
  for _ in $(seq 300); do
    if grep -q 'p11scope: native usage lane active' "$WORK/backend/inv-$scope.stderr"; then capture=1; break; fi
    kill -0 "$observer" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$capture" -eq 1 ] && kill -0 "$observer" 2>/dev/null; then
    touch "$gate"
    wait "$observer"; rc=$?
  else
    kill -TERM "$observer" 2>/dev/null || true; wait "$observer" 2>/dev/null || true; rc=1
  fi
  record_exit "$WORK/backend/inv-$scope.stderr" "inv_$scope" "$rc"
  kill -TERM "$wl" 2>/dev/null || true; wait "$wl" 2>/dev/null || true
  return "$rc"
}
mkdir -p "$STAGE/backend"
if [ -x "$WORK/qual/cells/fix/gated" ] && [ -f "$MODULE" ]; then
  backend_probe pid || true
  backend_probe sys || true
  cp -r "$WORK/backend/." "$STAGE/backend/" || exit 1
fi
date -u +%Y-%m-%dT%H:%M:%SZ > "$STAGE/guest-end.txt"
python3 -I "$R/scripts/release-matrix-contract.py" --seal "$STAGE" --contract "$STAGE/contract.json" --guest-exit 0 || exit 1
python3 -I "$R/scripts/release-matrix-contract.py" --judge "$STAGE" --contract "$STAGE/contract.json" > "$STAGE/guest-verdict.json"
rc=$?
# A valid nonqualifying verdict is a completed guest, with final matrix exit2.
[ "$rc" -ne 2 ] || rc=0
exit "$rc"
INNER
  } > "$stage/inner.sh"
  chmod 0755 "$stage/inner.sh"
}

if [ -n "$WRITE_STAGE" ]; then
  [ -n "$CONTRACT" ] && [ "$CONTRACT" = "$WRITE_STAGE/contract.json" ] || exit 1
  write_inner "$WRITE_STAGE"
  exit "$?"
fi

# --- real run ---------------------------------------------------------------
python3 -I "$CHECKER" --verify-launch-policy || exit 1
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
export TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp}
umask 022

# Verify rev checkout when building from source.
if [ -z "$BIN_DIR" ]; then
  git -C "$REPO" rev-parse --verify "$REV" >/dev/null 2>&1 || { echo "rev not found: $REV" >&2; exit 2; }
  head=$(git -C "$REPO" rev-parse --short HEAD)
  want=$(git -C "$REPO" rev-parse --short "$REV")
  [ "$head" = "$want" ] || { echo "checkout is $head, want $want; checkout $REV first (or pass --bin-dir)" >&2; exit 2; }
fi

OUT_REV=$OUT_BASE/$REV_SHORT
STAGE_REV=$STAGE_BASE/$REV_SHORT
BIN_OUT=$STAGE_REV/bins
[ ! -e "$OUT_REV" ] && [ ! -e "$STAGE_REV" ] || {
  echo "refusing existing campaign output/stage: $OUT_REV / $STAGE_REV" >&2
  exit 1
}
if [ -n "$BIN_DIR" ]; then
  [ -n "$CANDIDATE_RECEIPT" ] && [ -f "$CANDIDATE_RECEIPT" ] || {
    echo 'prebuilt candidate requires --candidate-receipt from its actual build producer' >&2
    exit 1
  }
  CANDIDATE_RECEIPT=$(realpath -e "$CANDIDATE_RECEIPT") || exit 1
fi
mkdir -p "$OUT_REV" "$STAGE_REV" "$BIN_OUT" || exit 1
chmod 755 "$OUT_REV" "$STAGE_REV" "$BIN_OUT"

# Kill only OUR vng/qemu strays: vng cmdlines containing our stage rev dir,
# plus qemu processes descended from this script.
cleanup_ours() {
  pids=$(pgrep -f "vng --run.*$STAGE_REV" 2>/dev/null || true)
  for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 2 2>/dev/null || true
  pids=$(pgrep -f "vng --run.*$STAGE_REV" 2>/dev/null || true)
  for p in $pids; do kill -KILL "$p" 2>/dev/null || true; done
  # qemu descended from us: walk ancestors to $$.
  for q in $(pgrep -x qemu-system-x86_64 2>/dev/null || true); do
    a=$(ps -o ppid= -p "$q" 2>/dev/null | tr -d ' ')
    while [ -n "$a" ] && [ "$a" != 1 ]; do
      if [ "$a" = "$$" ]; then kill -KILL "$q" 2>/dev/null || true; break; fi
      a=$(ps -o ppid= -p "$a" 2>/dev/null | tr -d ' ')
    done
  done
}
trap cleanup_ours EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_quiet() {
  while [ -e "$QUIET" ]; do
    echo "quiet window present ($QUIET); waiting 15s before next guest" >&2
    sleep 15
  done
}

build_bins() {
  local build_head build_tree libbuild_log libbuild_stderr
  git -C "$REPO" diff --quiet HEAD -- || { echo 'candidate build requires clean tracked source' >&2; return 1; }
  build_head=$(git -C "$REPO" rev-parse HEAD) || return 1
  build_tree=$(git -C "$REPO" rev-parse 'HEAD^{tree}') || return 1
  echo "== build $REV (rust +$RUST, jobs $CARGO_BUILD_JOBS) $(date -u +%T)" >&2
  ( cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" build --manifest-path "$REPO/Cargo.toml" --release --locked --bin p11scope ) || return 1
  libbuild_log=$STAGE_REV/lib-build.jsonl
  libbuild_stderr=$STAGE_REV/lib-build.stderr
  (cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" test --manifest-path "$REPO/Cargo.toml" --release --locked --lib --no-run --message-format=json) > "$libbuild_log" 2> "$libbuild_stderr" || return 1
  libjson=$(python3 - "$libbuild_log" <<'PYEXE'
import json,sys
exes=[json.loads(line).get('executable') for line in open(sys.argv[1]) if line.strip().startswith('{')]
exes=[exe for exe in exes if exe]
print(exes[-1] if exes else '')
PYEXE
) || return 1
  [ -n "$libjson" ] && [ -x "$libjson" ] || return 1
  bmjson=$(cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" test --manifest-path "$REPO/Cargo.toml" --release --locked -p p11scope-bpf-multi --lib --no-run --message-format=json 2>/dev/null | python3 -c 'import json,sys; exes=[json.loads(l).get("executable") for l in sys.stdin if l.strip().startswith("{")]; exes=[e for e in exes if e]; print(exes[-1] if exes else "")') || return 1
  [ -n "$bmjson" ] && [ -x "$bmjson" ] || return 1
  cp -f "$REPO/target/release/p11scope" "$BIN_OUT/p11scope"
  cp -f "$libjson" "$BIN_OUT/p11scope-lib"
  cp -f "$bmjson" "$BIN_OUT/p11scope-bpfmulti"
  chmod 755 "$BIN_OUT/p11scope" "$BIN_OUT/p11scope-lib" "$BIN_OUT/p11scope-bpfmulti"
  git -C "$REPO" diff --quiet HEAD -- && [ "$(git -C "$REPO" rev-parse HEAD)" = "$build_head" ] || {
    echo 'source changed during candidate build; no build receipt' >&2; return 1;
  }
  CANDIDATE_RECEIPT=$STAGE_REV/candidate-build.json
  python3 - "$REPO" "$BIN_OUT/p11scope-lib" "$build_head" "$build_tree" "$CANDIDATE_RECEIPT" "$RUST" "$libbuild_log" "$libbuild_stderr" <<'PYBUILD' || return 1
import hashlib,json,sys
from pathlib import Path
root,lib,revision,tree,out,rust,stdout,stderr=sys.argv[1:]
sha=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
receipt={'schema':'p11scope/release-matrix-build/v1','producer':'cargo-build',
         'lib_sha256':sha(lib),'source_root':root,'source_revision':revision,
         'source_tree':tree,'source_clean':True,
         'build':{'argv':['mise','exec','--','./scripts/cargo.sh','+'+rust,'test','--manifest-path',str(Path(root)/'Cargo.toml'),'--release','--locked','--lib','--no-run','--message-format=json'],
                  'cwd':root,'exit':0,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)},
         'runtime_sources':{name:sha(Path(root)/name) for name in
                            ('tests/fixtures/public-cli/inventory-ledger.c','scripts/fixtures/exec_churn.c')}}
Path(out).write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
PYBUILD
  echo "bins: $(ls -la "$BIN_OUT")" >&2
}

if [ -n "$BIN_DIR" ]; then
  for b in p11scope p11scope-lib p11scope-bpfmulti; do
    [ -x "$BIN_DIR/$b" ] || { echo "bin-dir missing executable $b" >&2; exit 2; }
  done
  cp -f "$BIN_DIR/p11scope" "$BIN_DIR/p11scope-lib" "$BIN_DIR/p11scope-bpfmulti" "$BIN_OUT/"
  chmod 755 "$BIN_OUT/"*
else
  build_bins || { echo "build failed for $REV" >&2; exit 1; }
fi
LIBBIN=$BIN_OUT/p11scope-lib
BPFMULTI=$BIN_OUT/p11scope-bpfmulti

# Fresh candidate receipts: these list operations execute no ignored body.
"$LIBBIN" --list --ignored > "$STAGE_REV/candidate-ignored.txt" || exit 1
"$REPO/scripts/run-privileged-lib-tests.sh" --list "$LIBBIN" > "$STAGE_REV/curation.txt" || exit 1
"$BPFMULTI" --list > "$STAGE_REV/bpfmulti-list.txt" || exit 1

SUMMARY=$OUT_REV/summary.md
{
  echo "# Selected release matrix $REV"
  echo
  echo "Exact selected coverage is distinct from valid nonqualifying plumbing. Full Stage5 remains pending."
  echo
  echo '| lane | classification | contract SHA-256 | detail |'
  echo '|---|---|---|---|'
} > "$SUMMARY"

run_one() {
  local k=$1 tag lane stage out start end wall vng_exit judge_exit
  tag=$(tag_for_kernel "$k"); lane=${tag#v}
  stage=$STAGE_REV/$tag; out=$OUT_REV/$tag
  [ ! -e "$stage" ] && [ ! -e "$out" ] || { echo "refusing existing stage/output: $tag" >&2; return 1; }
  mkdir -p "$stage" "$out" || return 1
  chmod 0755 "$stage" "$out"
  python3 -I "$CHECKER" --prepare "$stage" --lane "$lane" --bin-dir "$BIN_OUT" \
    --candidate-receipt "$CANDIDATE_RECEIPT" \
    --binary-list "$STAGE_REV/candidate-ignored.txt" --curation "$STAGE_REV/curation.txt" \
    --bpfmulti-list "$STAGE_REV/bpfmulti-list.txt" > "$stage/preparation.json" || return 1
  write_inner "$stage" || return 1
  wait_quiet
  start=$(date +%s)
  if [ "$k" = host ]; then
    # Explicit host obligation: same contract and harness, same owned lock.
    flock "$LOCK" timeout -k 60 "$TIMEOUT" sudo -n env \
      SUDO_UID="$(id -u)" SUDO_GID="$(id -g)" SUDO_USER="$(id -un)" \
      bash "$stage/inner.sh" > "$stage/vng-console.log" 2>&1
  else
    flock "$LOCK" timeout -k 60 "$TIMEOUT" vng --run "$k" --user root --cpus 4 \
      --memory 6G --rwdir "$stage" --exec "bash '$stage/inner.sh'" > "$stage/vng-console.log" 2>&1
  fi
  vng_exit=$?
  end=$(date +%s); wall=$((end-start))
  echo "vng_exit=$vng_exit wall=${wall}s" >> "$stage/vng-console.log"
  sudo -n chown -R "$(id -u):$(id -g)" "$stage" 2>/dev/null || return 1
  python3 -I "$CHECKER" --seal "$stage" --contract "$stage/contract.json" --guest-exit "$vng_exit" || return 1
  cp -r "$stage/." "$out/" || return 1
  judge_kernel "$out" > "$out/verdict.json"
  judge_exit=$?
  python3 - "$out/verdict.json" "$SUMMARY" "$tag" <<'PYSUM'
import json,sys
result=json.load(open(sys.argv[1]))
def clean(value): return str(value).replace('|','/').replace('\n',' ')
with open(sys.argv[2],'a') as stream:
    stream.write('| %s | %s | %s | %s |\n' % tuple(map(clean,(sys.argv[3],result['qualification'],result.get('contract_sha256','unbound'),result['detail']))))
PYSUM
  echo "$tag wall=${wall}s process_exit=$vng_exit judgment_exit=$judge_exit" >&2
  cleanup_ours
  return "$judge_exit"
}

overall=0
for k in "${KERNELS[@]}"; do
  run_one "$k"; rc=$?
  if [ "$rc" -eq 1 ] || [ "$rc" -gt 2 ]; then overall=1
  elif [ "$rc" -eq 2 ] && [ "$overall" -eq 0 ]; then overall=2
  fi
done
{
  echo
  echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ); exit=$overall"
  echo "logs: $OUT_REV/<lane>/; full Stage5 NOT_RUN by this selected contract"
} >> "$SUMMARY"
cat "$SUMMARY"
exit "$overall"
