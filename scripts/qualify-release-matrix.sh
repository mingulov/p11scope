#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-release-matrix.sh — v0.2.0 RC qualification across the vng kernel tiers.
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
#   2. curated privileged lib cells (run-privileged-lib-tests.sh default set);
#   3. doctor capability-tier line;
#   4. disclosed backend: 5.15 per-offset with probe reason, 6.8+ uprobe-multi
#      with pid filter proven (inventory scope_filter + bpf-multi probe log).
#
# Guest I/O staging: vng shares the host rootfs read-only and hides host /tmp
# and /var/tmp, so per-kernel stage dirs live under /home (STAGE_BASE) and are
# passed as vng --rwdir; results are copied to OUT_BASE (under /var/tmp) with
# summary.md at OUT_BASE/<rev>/summary.md and raw logs alongside.
# Privileged work is serialized under flock(LOCK); one guest runs at a time;
# every guest is bounded by timeout; quiet-window file pauses before each guest.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
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
KERNELS_ARG=""

usage() {
  sed -n '2,30p' "$0" >&2
}

# Default vng kernel specs for the four tiers.
default_kernels() {
  printf '%s\n' \
    "v5.15.221" \
    "/home/user/.cache/virtme-ng/ubuntu-6.8.0-142/amd64/boot/vmlinuz-6.8.0-142-generic" \
    "v6.12.111" \
    "v7.2.6"
}

resolve_kernel() {
  case "$1" in
    5.15|5.15.221|v5.15.221) echo "v5.15.221" ;;
    6.8|6.8.0-142|6.8.0-142-generic|ubuntu-6.8*) echo "/home/user/.cache/virtme-ng/ubuntu-6.8.0-142/amd64/boot/vmlinuz-6.8.0-142-generic" ;;
    6.12|6.12.111|v6.12.111) echo "v6.12.111" ;;
    7.2|7.2.6|v7.2.6) echo "v7.2.6" ;;
    *) echo "$1" ;;
  esac
}

tag_for_kernel() {
  basename "$1" | sed 's/vmlinuz-//'
}

expected_backend() {
  case "$1" in *5.15*) echo "per-offset" ;; *) echo "uprobe-multi" ;; esac
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
    --rev) REV=$2; shift 2 ;;
    --bin-dir) BIN_DIR=$2; shift 2 ;;
    --kernels) KERNELS_ARG=$2; shift 2 ;;
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

# Kernel list: --kernels splits on whitespace/commas, plus positional kernels.
KERNELS=()
if [ -n "$KERNELS_ARG" ]; then
  # shellcheck disable=SC2206
  KERNELS+=($(echo "$KERNELS_ARG" | tr ',' ' '))
fi
if [ "${#POS_KERNELS[@]}" -gt 0 ]; then
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

if [ -z "$REV" ] && [ -z "$BIN_DIR" ] && [ "$DRY_RUN" -eq 0 ] && [ "$SELF_TEST" -eq 0 ] && [ "$PREFLIGHT" -eq 0 ]; then
  echo "need --rev REV or --bin-dir DIR" >&2; usage; exit 2
fi
if [ -n "$BIN_DIR" ]; then
  BIN_DIR=$(realpath -e "$BIN_DIR") || { echo "bin-dir not found: $BIN_DIR" >&2; exit 2; }
  case "$BIN_DIR" in /tmp/*|/var/tmp/*) echo "bin-dir must be under /home (vng hides /tmp and /var/tmp)" >&2; exit 2 ;; esac
  [ -z "$REV" ] && REV="bins-$(basename "$BIN_DIR")"
fi
# Short rev for dir names.
REV_SHORT=$(echo "$REV" | sed 's/[^A-Za-z0-9._-]/_/g')
[ -n "$REV_SHORT" ] || REV_SHORT="norun"

print_plan() {
  echo "rev=$REV (dir $REV_SHORT)"
  echo "repo=$REPO rust=+$RUST jobs=${CARGO_BUILD_JOBS:-4} tmpdir=${TMPDIR:-/var/tmp/p11scope-ws-tmp}"
  echo "out_base=$OUT_BASE stage_base=$STAGE_BASE lock=$LOCK quiet=$QUIET timeout=${TIMEOUT}s"
  echo "kernels (${#KERNELS[@]}):"
  for k in "${KERNELS[@]}"; do
    echo "  $k tag=$(tag_for_kernel "$k") expect=$(expected_backend "$(tag_for_kernel "$k")")"
  done
  echo "checks per kernel: version doctor-tier public-cli inv-scan inv-native priv-lib backend pid-filter"
  echo "binaries: $([ -n "$BIN_DIR" ] && echo "bin-dir $BIN_DIR" || echo "build --rev $REV from $REPO")"
}

if [ "$DRY_RUN" -eq 1 ]; then
  print_plan
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
  fail=0
  expect() { if [ "$2" = "$3" ]; then echo "OK $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
  for s in qualify-public-cli.sh qualify-inventory-native.sh run-privileged-lib-tests.sh; do
    expect "$s executable" "$([ -x "$REPO/scripts/$s" ] && echo yes)" yes
  done
  expect "default kernels" "$(default_kernels | wc -l | tr -d ' ')" 4
  expect "resolve 5.15" "$(resolve_kernel 5.15)" v5.15.221
  expect "resolve 6.8" "$(resolve_kernel 6.8)" "/home/user/.cache/virtme-ng/ubuntu-6.8.0-142/amd64/boot/vmlinuz-6.8.0-142-generic"
  expect "resolve 6.12" "$(resolve_kernel 6.12)" v6.12.111
  expect "resolve 7.2" "$(resolve_kernel v7.2.6)" v7.2.6
  expect "resolve passthrough" "$(resolve_kernel v9.9.9)" v9.9.9
  expect "tag 6.8" "$(tag_for_kernel "$(resolve_kernel 6.8)")" 6.8.0-142-generic
  expect "backend 5.15" "$(expected_backend 5.15.221)" per-offset
  for k in 6.8.0-142-generic v6.12.111 v7.2.6; do
    expect "backend $k" "$(expected_backend "$k")" uprobe-multi
  done
  "$0" --no-such-option >/dev/null 2>&1; expect "unknown option refused" $? 2
  "$0" --kernels 5.15 >/dev/null 2>&1; expect "missing --rev refused" $? 2
  d=$(mktemp -d "${TMPDIR:-/tmp}/qrm-selftest-XXXXXX")
  "$0" --bin-dir "$d" --rev x >/dev/null 2>&1; expect "bin-dir under a hidden tmp refused" $? 2
  rmdir "$d"
  plan=$("$0" --dry-run --rev abc --kernels 5.15,7.2 2>&1)
  expect "dry-run kernels" "$(echo "$plan" | grep -c 'tag=')" 2
  expect "dry-run 5.15 backend" "$(echo "$plan" | grep -c 'v5.15.221 tag=v5.15.221 expect=per-offset')" 1
  expect "dry-run starts nothing" "$(echo "$plan" | tail -1)" "dry-run: no build, no guests started"
  # CI hermeticity: hosted CI runs --self-test only and must need no vng, no
  # kernel fetch and no /home/user writes. --preflight in CI mode (CI=true)
  # downgrades the guest-gated checks to SKIP and stages under $TMPDIR.
  d2=$(mktemp -d "${TMPDIR:-/tmp}/qrm-selftest-XXXXXX")
  ci_pf=$(CI=true "$0" --out-base "$d2/out" --preflight 2>&1 || true)
  expect "CI preflight never fails vng" "$(printf '%s\n' "$ci_pf" | grep -c -F 'FAIL vng on PATH')" 0
  expect "CI preflight never fails kernels" "$(printf '%s\n' "$ci_pf" | grep -c -F 'FAIL kernel')" 0
  expect "CI preflight stages under TMPDIR" "$(printf '%s\n' "$ci_pf" | grep -c -F "stage base writable (${TMPDIR:-/tmp}/qrm-preflight-stage)")" 1
  if command -v vng >/dev/null 2>&1; then
    echo "OK CI preflight vng SKIP branch (not exercised: vng present)"
  else
    expect "CI preflight skips absent vng" "$(printf '%s\n' "$ci_pf" | grep -c -F 'SKIP vng on PATH')" 1
  fi
  CI=true "$0" --out-base "$d2/out" --stage-base "$d2/stage" --preflight >/dev/null 2>&1 || true
  expect "CI preflight leaves STAGE_BASE untouched" "$([ -e "$d2/stage" ] && echo created || echo untouched)" untouched
  rm -rf "$d2"
  if [ $fail -eq 0 ]; then echo "self-test: OK"; else echo "self-test: FAIL"; fi
  return $fail
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

# --- real run ---------------------------------------------------------------
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
export TMPDIR=/var/tmp/p11scope-ws-tmp
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
mkdir -p "$OUT_REV" "$STAGE_REV" "$BIN_OUT"
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
trap cleanup_ours EXIT INT TERM

wait_quiet() {
  while [ -e "$QUIET" ]; do
    echo "quiet window present ($QUIET); waiting 15s before next guest" >&2
    sleep 15
  done
}

build_bins() {
  echo "== build $REV (rust +$RUST, jobs $CARGO_BUILD_JOBS) $(date -u +%T)" >&2
  ( cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" build --release --locked --bin p11scope ) || return 1
  libjson=$(cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" test --release --locked --lib --no-run --message-format=json 2>/dev/null | python3 -c 'import json,sys; exes=[json.loads(l).get("executable") for l in sys.stdin if l.strip().startswith("{")]; exes=[e for e in exes if e]; print(exes[-1] if exes else "")')
  [ -n "$libjson" ] && [ -x "$libjson" ] || return 1
  bmjson=$(cd "$REPO" && mise exec -- ./scripts/cargo.sh "+$RUST" test --release --locked -p p11scope-bpf-multi --lib --no-run --message-format=json 2>/dev/null | python3 -c 'import json,sys; exes=[json.loads(l).get("executable") for l in sys.stdin if l.strip().startswith("{")]; exes=[e for e in exes if e]; print(exes[-1] if exes else "")')
  [ -n "$bmjson" ] && [ -x "$bmjson" ] || return 1
  cp -f "$REPO/target/release/p11scope" "$BIN_OUT/p11scope"
  cp -f "$libjson" "$BIN_OUT/p11scope-lib"
  cp -f "$bmjson" "$BIN_OUT/p11scope-bpfmulti"
  chmod 755 "$BIN_OUT/p11scope" "$BIN_OUT/p11scope-lib" "$BIN_OUT/p11scope-bpfmulti"
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
P11SCOPE=$BIN_OUT/p11scope
LIBBIN=$BIN_OUT/p11scope-lib
BPFMULTI=$BIN_OUT/p11scope-bpfmulti

# Write the guest inner script for one kernel stage dir.
write_inner() {
  local stage=$1
  cat > "$stage/inner.sh" <<INNER
#!/bin/sh
set -u
STAGE=$stage
P=$P11SCOPE
LIB=$LIBBIN
BM=$BPFMULTI
R=$REPO
MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
[ -f "\$MODULE" ] || MODULE=/usr/lib/softhsm/libsofthsm2.so
uname -r > \$STAGE/uname.txt 2>&1
date -u +%Y-%m-%dT%H:%M:%SZ > \$STAGE/guest-start.txt
export SUDO_UID=1000 SUDO_GID=1000 SUDO_USER=user
mkdir -p /tmp/qual /tmp/priv /tmp/backend /tmp/c8-native /tmp/c8-scan
chmod 755 /tmp/qual /tmp/priv /tmp/backend
chmod 0711 /tmp/c8-native /tmp/c8-scan
# Per-offset (Singles) captures need thousands of fds; the vng guest default
# RLIMIT_NOFILE 4096 refuses them. Raise like run-privileged-lib-tests.sh does.
ulimit -n 65536 || echo "warning: cannot raise RLIMIT_NOFILE" >&2
{ ulimit -Sn; ulimit -Hn; } > \$STAGE/ulimit.txt 2>&1
# --version
\$P --version > \$STAGE/version.log 2>&1; echo "version_exit=\$?" >> \$STAGE/version.log
# doctor
\$P doctor > \$STAGE/doctor.log 2>&1; echo "doctor_exit=\$?" >> \$STAGE/doctor.log
# public CLI cells (guest-local work, copied out)
THREADS=4 \$R/scripts/qualify-public-cli.sh \$P /tmp/qual/cells > \$STAGE/qual.log 2>&1
echo "qual_exit=\$?" >> \$STAGE/qual.log
[ -d /tmp/qual/cells ] && cp -r /tmp/qual/cells \$STAGE/cells
# inventory native + scan lanes
\$R/scripts/qualify-inventory-native.sh \$P --lane native --base /tmp/c8-native > \$STAGE/inv-native.log 2>&1
echo "inv_native_exit=\$?" >> \$STAGE/inv-native.log
cp -r /tmp/c8-native \$STAGE/c8-native 2>/dev/null || true
\$R/scripts/qualify-inventory-native.sh \$P --lane scan --base /tmp/c8-scan > \$STAGE/inv-scan.log 2>&1
echo "inv_scan_exit=\$?" >> \$STAGE/inv-scan.log
cp -r /tmp/c8-scan \$STAGE/c8-scan 2>/dev/null || true
# curated privileged lib cells (default set)
cd \$R && scripts/run-privileged-lib-tests.sh \$LIB /tmp/priv/run > \$STAGE/priv.log 2>&1
echo "priv_exit=\$?" >> \$STAGE/priv.log
[ -d /tmp/priv/run ] && cp -r /tmp/priv/run \$STAGE/run
# bpf-multi pid-filter probe evidence (all crate tests, unprivileged-safe asserts)
\$BM --test-threads=1 --nocapture > \$STAGE/pidflt.log 2>&1
echo "pidflt_exit=\$?" >> \$STAGE/pidflt.log
# minimal backend probe: native inventory --pid and --system over the gated fixture
if [ -x /tmp/qual/cells/fix/gated ] && [ -f "\$MODULE" ]; then
  export SOFTHSM2_CONF=/tmp/backend/softhsm2.conf
  rm -rf /tmp/backend/tokens; mkdir -p /tmp/backend/tokens
  printf 'directories.tokendir = /tmp/backend/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > \$SOFTHSM2_CONF
  softhsm2-util --init-token --free --label be --so-pin 5678 --pin 1234 >/dev/null 2>&1 || true
  chown -R 1000:1000 /tmp/backend/tokens 2>/dev/null || true
  rm -f /tmp/backend/gate
  setpriv --reuid=1000 --regid=1000 --clear-groups env SOFTHSM2_CONF=\$SOFTHSM2_CONF /tmp/qual/cells/fix/gated \$MODULE 500 200 /tmp/backend/gate > /tmp/backend/wl.log 2>&1 &
  WL=\$!
  for _ in \$(seq 300); do grep -qa READY /tmp/backend/wl.log 2>/dev/null && break; sleep 0.1; done
  \$P inventory --pid \$WL --capture native --duration 10 -o /tmp/backend/inv-pid.json > /tmp/backend/inv-pid.stdout 2> /tmp/backend/inv-pid.stderr &
  PP=\$!
  sleep 2; touch /tmp/backend/gate 2>/dev/null || true
  wait \$PP; echo "inv_pid_exit=\$?" >> /tmp/backend/inv-pid.stderr
  kill -TERM \$WL 2>/dev/null || true; wait \$WL 2>/dev/null || true
  rm -f /tmp/backend/gate2
  setpriv --reuid=1000 --regid=1000 --clear-groups env SOFTHSM2_CONF=\$SOFTHSM2_CONF /tmp/qual/cells/fix/gated \$MODULE 500 200 /tmp/backend/gate2 > /tmp/backend/wl2.log 2>&1 &
  WL2=\$!
  for _ in \$(seq 300); do grep -qa READY /tmp/backend/wl2.log 2>/dev/null && break; sleep 0.1; done
  \$P inventory --system --capture native --duration 10 -o /tmp/backend/inv-sys.json > /tmp/backend/inv-sys.stdout 2> /tmp/backend/inv-sys.stderr &
  PP2=\$!
  sleep 2; touch /tmp/backend/gate2 2>/dev/null || true
  wait \$PP2; echo "inv_sys_exit=\$?" >> /tmp/backend/inv-sys.stderr
  kill -TERM \$WL2 2>/dev/null || true; wait \$WL2 2>/dev/null || true
  cp -r /tmp/backend \$STAGE/backend 2>/dev/null || true
else
  echo "backend probe skipped: gated fixture or SoftHSM2 missing" > \$STAGE/backend/skip.txt 2>/dev/null || { mkdir -p \$STAGE/backend; echo "backend probe skipped: gated fixture or SoftHSM2 missing" > \$STAGE/backend/skip.txt; }
fi
date -u +%Y-%m-%dT%H:%M:%SZ > \$STAGE/guest-end.txt
INNER
  chmod 755 "$stage/inner.sh"
}

# Parse one kernel stage dir into CHECK=RESULT lines. Prints shell assignments.
judge_kernel() {
  local stage=$1 tag=$2 expect=$3
  python3 - "$stage" "$tag" "$expect" <<'PY'
import json, re, sys
from pathlib import Path
stage, tag, expect = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def read(p):
    try: return (stage/p).read_text(errors="replace")
    except: return ""
def verdict(passed, detail=""):
    return ("PASS" if passed else "FAIL") + (f"({detail})" if detail and not passed else "")
out = {}
# version
v = read("version.log")
out["version"] = "PASS" if ("version_exit=0" in v and "p11scope" in v.lower()) else verdict(False, (v.strip().splitlines() or ["missing"])[:1][0][:80] if v else "missing")
# doctor-tier
d = read("doctor.log")
m = re.search(r"capability tier:\s*(T[0-4][^\n]*)", d)
out["doctor-tier"] = "PASS" if m else verdict(False, "no capability tier")
if m: out["doctor-tier-detail"] = m.group(0).strip()
# public-cli
q = read("cells/summary.txt") or read("qual.log")
mm = re.search(r"pass=(\d+)\s+fail=(\d+)", q)
if mm and int(mm.group(2)) == 0 and int(mm.group(1)) > 0:
    out["public-cli"] = "PASS"
elif mm:
    failcells = re.search(r"failed=\[([^\]]*)\]", q)
    out["public-cli"] = verdict(False, f"pass={mm.group(1)} fail={mm.group(2)} {failcells.group(0) if failcells else ''}".strip()[:120])
else:
    out["public-cli"] = verdict(False, "no summary")
# inv-native: oracle exit 0 qualifies
n = read("inv-native.log")
mn = re.search(r"inv_native_exit=(\d+)", n)
if mn and mn.group(1) == "0": out["inv-native"] = "PASS"
elif mn: out["inv-native"] = verdict(False, f"exit={mn.group(1)}")
else: out["inv-native"] = verdict(False, "missing")
# inv-scan: oracle exit 2 is the plumbing pass (non-qualifying by design)
s = read("inv-scan.log")
ms = re.search(r"inv_scan_exit=(\d+)", s)
if ms and ms.group(1) == "2": out["inv-scan"] = "PASS"
elif ms and ms.group(1) == "0": out["inv-scan"] = verdict(False, "exit=0 unexpected for scan")
elif ms: out["inv-scan"] = verdict(False, f"exit={ms.group(1)}")
else: out["inv-scan"] = verdict(False, "missing")
# priv-lib
p = read("priv.log")
mp = re.search(r"SUMMARY pass=(\d+) fail=(\d+) skipped=(\d+)", p)
if mp and int(mp.group(2)) == 0 and int(mp.group(1)) > 0:
    out["priv-lib"] = "PASS"
elif mp:
    out["priv-lib"] = verdict(False, f"pass={mp.group(1)} fail={mp.group(2)} skipped={mp.group(3)}")
else:
    out["priv-lib"] = verdict(False, "no SUMMARY")
# backend + pid-filter from backend JSONs and pidflt log
def loadj(name):
    try: return json.loads((stage/"backend"/name).read_text())
    except: return None
pidj, sysj = loadj("inv-pid.json"), loadj("inv-sys.json")
def attach(j):
    try: return j["observation"]["attach"]
    except: return {}
ap, asy = attach(pidj), attach(sysj)
mech_ok = (ap.get("mechanism") == expect and asy.get("mechanism") == expect)
if pidj is None or sysj is None:
    skip = read("backend/skip.txt").strip()
    out["backend"] = f"SKIP({skip[:100] if skip else 'missing backend JSON'})"
    out["pid-filter"] = out["backend"]
else:
    if expect == "per-offset":
        fb = (ap.get("fallback") or "") + " " + (asy.get("fallback") or "")
        ok = mech_ok and ("functional probe failed" in fb)
        out["backend"] = "PASS" if ok else verdict(False, f"pid={ap.get('mechanism')}/{ap.get('fallback')} sys={asy.get('mechanism')}/{asy.get('fallback')}"[:160])
        # 5.15: pid filter unproven; --pid must be perf-task+bpf, no proves=true
        pf = read("pidflt.log")
        scope_ok = ap.get("scope_filter") == "perf-task+bpf"
        proves = "proves=true" in pf.lower().replace(" ", "")
        ok2 = scope_ok and not proves
        out["pid-filter"] = "PASS" if ok2 else verdict(False, f"scope_filter={ap.get('scope_filter')} proves_true={proves}"[:120])
    else:
        ok = mech_ok and not ap.get("fallback") and not asy.get("fallback")
        out["backend"] = "PASS" if ok else verdict(False, f"pid={ap.get('mechanism')}/{ap.get('fallback')} sys={asy.get('mechanism')}/{asy.get('fallback')}"[:160])
        pf = read("pidflt.log")
        scope_ok = ap.get("scope_filter") == "kernel-pid+bpf"
        proves = "proves=true" in pf.lower().replace(" ", "")
        ok2 = scope_ok and proves
        out["pid-filter"] = "PASS" if ok2 else verdict(False, f"scope_filter={ap.get('scope_filter')} proves_true={proves}"[:120])
for k in ["version","doctor-tier","public-cli","inv-scan","inv-native","priv-lib","backend","pid-filter"]:
    print(f"{k}={out.get(k,'FAIL(missing)')}")
if "doctor-tier-detail" in out:
    print(f"doctor_tier_detail={out['doctor-tier-detail']}")
PY
}

SUMMARY=$OUT_REV/summary.md
{
  echo "# rc-qualify $REV"
  echo ""
  echo "rev: $REV  repo: $REPO  rust: +$RUST  timeout: ${TIMEOUT}s  started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "| kernel | tag | version | doctor-tier | public-cli | inv-scan | inv-native | priv-lib | backend | pid-filter | runtime |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
} > "$SUMMARY"

run_one() {
  local k=$1
  local tag expect stage out start end wall vng_exit
  tag=$(tag_for_kernel "$k"); expect=$(expected_backend "$tag")
  stage=$STAGE_REV/$tag; out=$OUT_REV/$tag
  rm -rf "$stage" "$out"; mkdir -p "$stage" "$out"; chmod 755 "$stage" "$out"
  write_inner "$stage"
  wait_quiet
  echo "== $tag ($k) expect $expect $(date +%T)" >&2
  start=$(date +%s)
  # Serialized privileged guest, bounded by timeout, one at a time.
  flock "$LOCK" timeout -k 60 "$TIMEOUT" vng --run "$k" --user root --cpus 4 --memory 6G --rwdir "$stage" --exec "sh $stage/inner.sh" > "$stage/vng-console.log" 2>&1
  vng_exit=$?
  end=$(date +%s); wall=$((end-start))
  echo "vng_exit=$vng_exit wall=${wall}s" >> "$stage/vng-console.log"
  # Export to /var/tmp and chown root-created files back to the user.
  cp -r "$stage/." "$out/" 2>/dev/null || true
  sudo chown -R "$(id -u):$(id -g)" "$stage" "$out" 2>/dev/null || chown -R "$(id -u):$(id -g)" "$stage" "$out" 2>/dev/null || true
  # Judge from the exported copy (single parse).
  judge_out=$(judge_kernel "$out" "$tag" "$expect")
  R_version=$(echo "$judge_out" | grep ^version= | cut -d= -f2-)
  R_doctor_tier=$(echo "$judge_out" | grep ^doctor-tier= | cut -d= -f2-)
  R_public_cli=$(echo "$judge_out" | grep ^public-cli= | cut -d= -f2-)
  R_inv_scan=$(echo "$judge_out" | grep ^inv-scan= | cut -d= -f2-)
  R_inv_native=$(echo "$judge_out" | grep ^inv-native= | cut -d= -f2-)
  R_priv_lib=$(echo "$judge_out" | grep ^priv-lib= | cut -d= -f2-)
  R_backend=$(echo "$judge_out" | grep ^backend= | cut -d= -f2-)
  R_pid_filter=$(echo "$judge_out" | grep ^pid-filter= | cut -d= -f2-)
  kr=$(cat "$out/uname.txt" 2>/dev/null || echo "?")
  echo "| $kr | $tag | $R_version | $R_doctor_tier | $R_public_cli | $R_inv_scan | $R_inv_native | $R_priv_lib | $R_backend | $R_pid_filter | ${wall}s |" >> "$SUMMARY"
  echo "$tag wall=${wall}s vng_exit=$vng_exit public-cli=$R_public_cli inv-native=$R_inv_native priv-lib=$R_priv_lib backend=$R_backend pid-filter=$R_pid_filter" >&2
  cleanup_ours
}

for k in "${KERNELS[@]}"; do run_one "$k"; done

{
  echo ""
  echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "logs: $OUT_REV/<tag>/ (stage mirror: $STAGE_REV/<tag>/) bins: $BIN_OUT"
} >> "$SUMMARY"
cat "$SUMMARY"
