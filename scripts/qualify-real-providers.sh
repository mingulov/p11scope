#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# qualify-real-providers.sh P11SCOPE OUTDIR: real distro tools under `run`.
#
# Each cell runs a real PKCS#11 tool under `p11scope run --pause auto` with
# the tool's calls routed through OpenSC pkcs11-spy.so, which appends one
# entry per forwarded call to an independent spy log. scripts/real-provider-
# oracle.py then judges the report against that ledger: exact per-function
# counts at the spied module's identity, a confirmed pause, and an
# observation-cause set equal to the pinned list in
# tests/fixtures/real-providers/expected-causes.json. A fixed cause and a
# new cause both fail until the pin is updated: the pin is the ratchet.
#
# Cells (each with a --mode metrics twin):
#   real-pkcs11tool-softhsm   pkcs11-tool --module spy -L -M -O, spy -> SoftHSM
#   real-pkcs11tool-opensc    same, spy -> opensc-pkcs11.so (needs a reader)
#   real-p11kit-trust         trust list --filter=ca-anchors, spy -> p11-kit-trust
#   real-nss-certutil         certutil -L -h all -d sql:DB, spy -> SoftHSM
#                             (modutil -list verifies the registration in setup)
#   real-gnutls-p11tool       p11tool --provider spy --list-tokens, spy -> SoftHSM
#   real-opencryptoki         pkcs11-tool --module spy -L, spy -> libopencryptoki
# The p11-kit-proxy transparency cells (real-p11kit-spy, owned SoftHSM
# through p11-kit) belong to WP-3b and are not duplicated here.
#
# Ledger routing per tool (all verified on Ubuntu 26.04 + Fedora 44):
# - pkcs11-tool: --module <spy> (documented in pkcs11-tool --help).
# - p11tool: --provider <spy> (documented in p11tool --help).
# - NSS: the spy is registered into an owned DB with modutil -add (falling
#   back to modutil -rawadd where -add verification fails); the observed
#   command is certutil -L -h all alone, with an owned empty p11-kit user
#   config blinding NSS's second SoftHSM path (both distros ship it).
# - trust: an owned p11-kit user config (XDG_CONFIG_HOME/pkcs11/{pkcs11.conf
#   with "user-config: only", modules/spy.module naming the spy with
#   trust-policy/priority/x-trust-lookup copied from p11-kit-trust.module}),
#   per pkcs11.conf(5); the config paths come from libp11-kit itself.
# Every cell passes its environment through /usr/bin/env after `--`: a
# sudo-run child only inherits PATH/LC/TERM/TZ/SOFTHSM2_CONF, so PKCS11SPY,
# PKCS11SPY_OUTPUT and XDG_CONFIG_HOME must ride the command line.
#
# Owned state: OUTDIR/work holds the SoftHSM config+tokens, the NSS DB and
# the p11-kit user configs (trust spy module, NSS blinding). Nothing is written outside
# OUTDIR (the opencryptoki soft token is used as the system provides it and
# is never initialized here). The spy log appends across runs, so every
# cell removes its spy log before running.
#
# Apt prerequisites on Ubuntu (CI installs these; Fedora names in brackets):
#   opensc (opensc), p11-kit (p11-kit), softhsm2 (softhsm),
#   libnss3-tools (nss-tools), gnutls-bin (gnutls-utils),
#   opencryptoki (opencryptoki), binutils (binutils), python3 (python3).
# Plus root (passwordless sudo), BTF and the release observer binary.
#
# Results: OUTDIR/results.jsonl, one row per cell:
#   {"cell","pass","qualification","detail"} with qualification qualified |
#   expected-failure | failed | nonqualifying. A cell whose prerequisites
#   are missing is recorded nonqualifying with detail "SKIP (77): ..." and
#   never passes. Exit: 0 every cell qualified or pinned; 1 a cell failed;
#   2 harness error; 77 a cell skipped and none failed.
#
# Every observer invocation runs under the workspace privileged lock
# (/var/tmp/p11scope-ws-tmp/privileged.lock), so concurrent BPF captures
# from other lanes cannot interfere. Callers must not hold that lock
# around this script (flock self-deadlocks).
set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 64
ORACLE=$HERE/real-provider-oracle.py
EXPECTS=$HERE/../tests/fixtures/real-providers/expected-causes.json
TIMEOUT=${REAL_PROVIDERS_TIMEOUT:-180}
[ $# = 2 ] || { echo 'usage: qualify-real-providers.sh P11SCOPE OUTDIR' >&2; exit 64; }
P=$(realpath -e -- "$1") || { echo 'observer not found' >&2; exit 2; }
OUT=$2
[ "$(id -u)" = 0 ] || [ -n "${SUDO_UID:-}" ] || sudo -n true || {
  echo 'passwordless sudo required' >&2; exit 77; }
mkdir -p "$OUT" && OUT=$(realpath -e -- "$OUT") || { echo 'cannot create OUTDIR' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 missing' >&2; exit 77; }
mkdir -p /var/tmp/p11scope-ws-tmp || { echo 'cannot create lock dir' >&2; exit 2; }
WORK=$OUT/work; mkdir -p "$WORK"
: > "$OUT/results.jsonl"
FAILED=0; SKIPPED=0; HARNESS=0
NM_MISSING=0
command -v nm >/dev/null 2>&1 || NM_MISSING=1

result() {
  python3 -I - "$1" "$2" "$3" "$4" <<'PY' | tee -a "$OUT/results.jsonl"
import json,sys
print(json.dumps({'cell':sys.argv[1],'pass':sys.argv[2]=='1','detail':sys.argv[3],
 'qualification':sys.argv[4]}))
PY
}
skip() { SKIPPED=1; result "$1" 0 "SKIP (77): $2" nonqualifying; }

OS_ID=$(python3 -I -c 'import re;print(re.search(r"^ID=(.*)$",open("/etc/os-release").read(),re.M).group(1).strip().strip("\""))' 2>/dev/null || echo unknown)
[ -n "$OS_ID" ] || OS_ID=unknown

pkg_version() {
  local deb=$1 rpm=$2 out
  if command -v dpkg-query >/dev/null 2>&1; then
    out=$(dpkg-query -W -f='${Version}' "$deb" 2>/dev/null) && [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
  fi
  if command -v rpm >/dev/null 2>&1; then
    out=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$rpm" 2>/dev/null) && [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
  fi
  return 1
}

probe_module() {
  # Canonicalized: the oracle compares the spy's Loaded path byte-wise,
  # and distro module paths are sometimes symlinks (libopencryptoki.so).
  local candidate resolved
  for candidate in "$@"; do
    if [ -f "$candidate" ]; then
      resolved=$(realpath -e -- "$candidate") && { printf '%s\n' "$resolved"; return 0; }
    fi
  done
  return 1
}

SOFTHSM_CANDIDATES=(/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so)
OPENSC_CANDIDATES=(/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so /usr/lib64/opensc-pkcs11.so /usr/lib64/pkcs11/opensc-pkcs11.so)
SPY_CANDIDATES=(/usr/lib/x86_64-linux-gnu/pkcs11-spy.so /usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so /usr/lib64/pkcs11-spy.so /usr/lib64/pkcs11/pkcs11-spy.so)
TRUST_CANDIDATES=(/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib64/pkcs11/p11-kit-trust.so)
OCK_CANDIDATES=(/usr/lib/x86_64-linux-gnu/pkcs11/libopencryptoki.so /usr/lib64/pkcs11/libopencryptoki.so)

pin() { python3 -I "$HERE/mapped-provider-pin.py" "$1"; }

spied_exports() {
  nm -D --defined-only -- "$1" 2>/dev/null | python3 -I -c '
import json,sys
defined = {line.split()[-1].split("@")[0] for line in sys.stdin if line.split()}
print(json.dumps({name: (name in defined)
 for name in ("C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList")}))'
}

softhsm_setup() {
  # Owned SoftHSM state; idempotent for reruns in one OUTDIR.
  export SOFTHSM_CONF=$WORK/softhsm2.conf
  if [ ! -f "$SOFTHSM_CONF" ]; then
    mkdir -p "$OUT/tokens"
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
      "$OUT" > "$SOFTHSM_CONF"
  fi
  if [ -z "$(ls -A "$OUT/tokens" 2>/dev/null)" ]; then
    SOFTHSM2_CONF=$SOFTHSM_CONF softhsm2-util --init-token --free \
      --label qual --so-pin 5678 --pin 1234 >/dev/null || return 1
  fi
  return 0
}

run_and_judge() {
  # CELL MODE TOOL TOOL_VERSION SPIED ENV_ARGS CMD_ARGS must be set.
  local i
  if [ "$NM_MISSING" = 1 ]; then skip "$CELL" 'nm (binutils) missing'; return 0; fi
  rm -f -- "$OUT/$CELL.json" "$OUT/$CELL.spy.log" "$OUT/$CELL.receipt.json" \
    "$OUT/$CELL.tool.out" "$OUT/$CELL.run.stderr"
  local before after exports
  before=$(pin "$SPIED") || { HARNESS=1; result "$CELL" 0 'harness: spied pin failed' failed; return 1; }
  local args=(run --pause auto)
  [ "$MODE" = metrics ] && args+=(--mode metrics)
  args+=(-o "$OUT/$CELL.json" -- /usr/bin/env)
  for i in "${ENV_ARGS[@]}"; do args+=("$i"); done
  for i in "${CMD_ARGS[@]}"; do args+=("$i"); done
  local rc
  flock /var/tmp/p11scope-ws-tmp/privileged.lock \
    timeout "$TIMEOUT" sudo -n "$P" "${args[@]}" >"$OUT/$CELL.tool.out" 2>"$OUT/$CELL.run.stderr"; rc=$?
  if [ "$rc" = 124 ]; then FAILED=1; result "$CELL" 0 "observer timed out after ${TIMEOUT}s" failed; return 1; fi
  sudo -n chown "$(id -u):$(id -g)" "$OUT/$CELL.json" 2>/dev/null || true
  after=$(pin "$SPIED") || { HARNESS=1; result "$CELL" 0 'harness: spied re-pin failed' failed; return 1; }
  exports=$(spied_exports "$SPIED") || { HARNESS=1; result "$CELL" 0 'harness: nm exports failed' failed; return 1; }
  P11KIT_VERSION=${P11KIT_VERSION:-unknown}
  python3 -I - "$OUT/$CELL.receipt.json" "$CELL" "$MODE" "$TOOL" "$TOOL_VERSION" "$OS_ID" \
    "$SPIED" "$before" "$after" "$rc" "$P11KIT_VERSION" "$exports" <<'PY'
import json,sys
path, cell, mode, tool, version, os_id, spied, before, after, rc, p11kit, exports = sys.argv[1:]
json.dump({"schema": "p11scope/real-provider-receipt/v1", "cell": cell, "mode": mode,
 "tool": tool, "tool_version": version, "os_id": os_id, "spied_module": spied,
 "provider_before": json.loads(before), "provider_after": json.loads(after),
 "run_exit": int(rc), "p11kit_version": p11kit, "spied_exports": json.loads(exports)},
 open(path, "w"), sort_keys=True)
PY
  if [ "$?" != 0 ]; then HARNESS=1; result "$CELL" 0 'harness: receipt publication failed' failed; return 1; fi
  local row oracle_rc
  row=$(python3 -I "$ORACLE" --report "$OUT/$CELL.json" --spy "$OUT/$CELL.spy.log" \
    --receipt "$OUT/$CELL.receipt.json" --expect "$EXPECTS" --cell "$CELL"); oracle_rc=$?
  if [ -z "$row" ]; then HARNESS=1; result "$CELL" 0 'harness: oracle produced no row' failed; return 1; fi
  printf '%s\n' "$row" | tee -a "$OUT/results.jsonl" >/dev/null
  case $oracle_rc in
    0|3) return 0 ;;
    2) HARNESS=1; return 1 ;;
    *) FAILED=1; return 1 ;;
  esac
}

pkcs11tool_cell() {
  # $1 cell base, $2 spied candidates name, $3 spied label; defines profile+metrics.
  local base=$1 candname=$2 label=$3
  local spied toolbin version
  toolbin=$(command -v pkcs11-tool) || { skip "$base" 'pkcs11-tool missing'; skip "$base-metrics" 'pkcs11-tool missing'; return 0; }
  SPY=$(probe_module "${SPY_CANDIDATES[@]}") || { skip "$base" 'pkcs11-spy.so missing'; skip "$base-metrics" 'pkcs11-spy.so missing'; return 0; }
  case $candname in
    SOFTHSM) spied=$(probe_module "${SOFTHSM_CANDIDATES[@]}") ;;
    OPENSC) spied=$(probe_module "${OPENSC_CANDIDATES[@]}") ;;
    OCK) spied=$(probe_module "${OCK_CANDIDATES[@]}") ;;
  esac
  [ -n "${spied:-}" ] || { skip "$base" "$label missing"; skip "$base-metrics" "$label missing"; return 0; }
  version=$(pkg_version opensc opensc) || { skip "$base" 'opensc version unknown'; skip "$base-metrics" 'opensc version unknown'; return 0; }
  P11KIT_VERSION=$(pkg_version p11-kit p11-kit || echo unknown)
  softhsm_setup || { skip "$base" 'owned SoftHSM setup failed'; skip "$base-metrics" 'owned SoftHSM setup failed'; return 0; }
  if [ "$candname" = OPENSC ]; then
    if ! "$toolbin" --module "$spied" -L >/dev/null 2>&1; then
      skip "$base" 'no smart-card reader: pkcs11-tool exits nonzero with opensc';
      skip "$base-metrics" 'no smart-card reader: pkcs11-tool exits nonzero with opensc'; return 0;
    fi
  fi
  if [ "$candname" = OCK ]; then
    if ! pgrep -x pkcsslotd >/dev/null 2>&1; then
      sudo -n systemctl start pkcsslotd >/dev/null 2>&1 || true
      sleep 2
    fi
    if ! pgrep -x pkcsslotd >/dev/null 2>&1; then
      skip "$base" 'pkcsslotd cannot start'; skip "$base-metrics" 'pkcsslotd cannot start'; return 0;
    fi
    local ruid rgid
    ruid=$(id -u); rgid=$(id -g)
    rm -f -- "$WORK/ock-probe.spy.log"
    if ! sudo -n setpriv --reuid="$ruid" --regid="$rgid" --clear-groups \
      /usr/bin/env PKCS11SPY="$spied" PKCS11SPY_OUTPUT="$WORK/ock-probe.spy.log" \
      "$toolbin" --module "$SPY" -L >/dev/null 2>&1; then
      rm -f -- "$WORK/ock-probe.spy.log"
      skip "$base" 'opencryptoki token not usable as the run-child identity (pkcs11 group; sudo-run clears groups)';
      skip "$base-metrics" 'opencryptoki token not usable as the run-child identity (pkcs11 group; sudo-run clears groups)'; return 0;
    fi
    rm -f -- "$WORK/ock-probe.spy.log"
  fi
  local mode
  for mode in profile metrics; do
    CELL=$base; MODE=$mode; TOOL=pkcs11-tool; TOOL_VERSION=$version; SPIED=$spied
    [ "$mode" = metrics ] && CELL=$base-metrics
    ENV_ARGS=("SOFTHSM2_CONF=$SOFTHSM_CONF" "PKCS11SPY=$spied" "PKCS11SPY_OUTPUT=$OUT/$CELL.spy.log")
    if [ "$candname" = OCK ]; then
      CMD_ARGS=("$toolbin" --module "$SPY" -L)
    else
      CMD_ARGS=("$toolbin" --module "$SPY" -L -M -O)
    fi
    run_and_judge || true
  done
}

trust_cell() {
  local base=real-p11kit-trust
  local spied trustbin version
  trustbin=$(command -v trust) || { skip "$base" 'trust missing'; skip "$base-metrics" 'trust missing'; return 0; }
  SPY=$(probe_module "${SPY_CANDIDATES[@]}") || { skip "$base" 'pkcs11-spy.so missing'; skip "$base-metrics" 'pkcs11-spy.so missing'; return 0; }
  spied=$(probe_module "${TRUST_CANDIDATES[@]}") || { skip "$base" 'p11-kit-trust.so missing'; skip "$base-metrics" 'p11-kit-trust.so missing'; return 0; }
  version=$(pkg_version p11-kit p11-kit) || { skip "$base" 'p11-kit version unknown'; skip "$base-metrics" 'p11-kit version unknown'; return 0; }
  P11KIT_VERSION=$version
  softhsm_setup || { skip "$base" 'owned SoftHSM setup failed'; skip "$base-metrics" 'owned SoftHSM setup failed'; return 0; }
  local mode
  for mode in profile metrics; do
    CELL=$base; MODE=$mode; TOOL=trust; TOOL_VERSION=$version; SPIED=$spied
    [ "$mode" = metrics ] && CELL=$base-metrics
    local xdg=$WORK/xdg-$CELL
    rm -rf -- "$xdg"; mkdir -p "$xdg/pkcs11/modules"
    printf 'user-config: only\n' > "$xdg/pkcs11/pkcs11.conf"
    cat > "$xdg/pkcs11/modules/spy.module" <<EOF
module: $SPY
priority: 1
trust-policy: yes
x-trust-lookup: pkcs11:library-description=PKCS%2311%20Kit%20Trust%20Module
EOF
    ENV_ARGS=("SOFTHSM2_CONF=$SOFTHSM_CONF" "XDG_CONFIG_HOME=$xdg" "PKCS11SPY=$spied" "PKCS11SPY_OUTPUT=$OUT/$CELL.spy.log")
    CMD_ARGS=("$trustbin" list --filter=ca-anchors)
    run_and_judge || true
  done
}

nss_cell() {
  local base=real-nss-certutil
  local spied certbin modbin version
  certbin=$(command -v certutil) || { skip "$base" 'certutil missing'; skip "$base-metrics" 'certutil missing'; return 0; }
  modbin=$(command -v modutil) || { skip "$base" 'modutil missing'; skip "$base-metrics" 'modutil missing'; return 0; }
  SPY=$(probe_module "${SPY_CANDIDATES[@]}") || { skip "$base" 'pkcs11-spy.so missing'; skip "$base-metrics" 'pkcs11-spy.so missing'; return 0; }
  spied=$(probe_module "${SOFTHSM_CANDIDATES[@]}") || { skip "$base" 'libsofthsm2.so missing'; skip "$base-metrics" 'libsofthsm2.so missing'; return 0; }
  version=$(pkg_version libnss3-tools nss-tools) || { skip "$base" 'nss tools version unknown'; skip "$base-metrics" 'nss tools version unknown'; return 0; }
  P11KIT_VERSION=$(pkg_version p11-kit p11-kit || echo unknown)
  softhsm_setup || { skip "$base" 'owned SoftHSM setup failed'; skip "$base-metrics" 'owned SoftHSM setup failed'; return 0; }
  local nssdb=$WORK/nssdb
  mkdir -p "$nssdb"
  if [ ! -f "$nssdb/cert9.db" ]; then
    "$certbin" -N --empty-password -d "sql:$nssdb" >/dev/null 2>&1 || {
      skip "$base" 'owned NSS DB setup failed'; skip "$base-metrics" 'owned NSS DB setup failed'; return 0; }
  fi
  if ! "$modbin" -list -dbdir "sql:$nssdb" 2>/dev/null | grep -q '\. spy$'; then
    # modutil exits 0 even when -add fails, so registration is verified by
    # listing, never by exit code. Fedora NSS 3.130 rejects -add verification
    # (plain SoftHSM fails identically: "Unknown PKCS #11 error"), while the
    # same module loads fine at use time; -rawadd writes the same spec
    # without that verification step.
    rm -f -- "$WORK/nss-add.spy.log"
    SOFTHSM2_CONF=$SOFTHSM_CONF PKCS11SPY=$spied PKCS11SPY_OUTPUT=$WORK/nss-add.spy.log \
      "$modbin" -add spy -libfile "$SPY" -dbdir "sql:$nssdb" -force </dev/null >/dev/null 2>&1 || true
    if ! "$modbin" -list -dbdir "sql:$nssdb" 2>/dev/null | grep -q '\. spy$'; then
      "$modbin" -rawadd "library=$SPY name=spy" -dbdir "sql:$nssdb" -force </dev/null >/dev/null 2>&1 || true
    fi
    rm -f -- "$WORK/nss-add.spy.log"
    if ! "$modbin" -list -dbdir "sql:$nssdb" 2>/dev/null | grep -q '\. spy$'; then
      skip "$base" 'NSS spy registration failed (-add and -rawadd)';
      skip "$base-metrics" 'NSS spy registration failed (-add and -rawadd)'; return 0;
    fi
  fi
  # The observed tool is certutil alone: `run` does not track descendants
  # (pid_descendant_gaps is cgroup-only), so a shell wrapper running two
  # tools would hide both. modutil -list still exercises the same
  # registration unobserved in setup verification above.
  # NSS also loads every p11-kit-registered module (both distros ship
  # softhsm2.module), which would execute SoftHSM calls behind the spy's
  # back and double the ledger; an owned empty p11-kit user config blinds
  # that path (verified: only p11-kit-proxy.so opens, exit 0).
  local xdg=$WORK/xdg-nss
  rm -rf -- "$xdg"; mkdir -p "$xdg/pkcs11/modules"
  printf 'user-config: only\n' > "$xdg/pkcs11/pkcs11.conf"
  local mode
  for mode in profile metrics; do
    CELL=$base; MODE=$mode; TOOL=certutil; TOOL_VERSION=$version; SPIED=$spied
    [ "$mode" = metrics ] && CELL=$base-metrics
    ENV_ARGS=("SOFTHSM2_CONF=$SOFTHSM_CONF" "XDG_CONFIG_HOME=$xdg" "PKCS11SPY=$spied" "PKCS11SPY_OUTPUT=$OUT/$CELL.spy.log")
    CMD_ARGS=("$certbin" -L -h all -d "sql:$nssdb")
    run_and_judge || true
  done
}

p11tool_cell() {
  local base=real-gnutls-p11tool
  local spied toolbin version
  toolbin=$(command -v p11tool) || { skip "$base" 'p11tool missing'; skip "$base-metrics" 'p11tool missing'; return 0; }
  SPY=$(probe_module "${SPY_CANDIDATES[@]}") || { skip "$base" 'pkcs11-spy.so missing'; skip "$base-metrics" 'pkcs11-spy.so missing'; return 0; }
  spied=$(probe_module "${SOFTHSM_CANDIDATES[@]}") || { skip "$base" 'libsofthsm2.so missing'; skip "$base-metrics" 'libsofthsm2.so missing'; return 0; }
  version=$(pkg_version gnutls-bin gnutls-utils) || { skip "$base" 'gnutls version unknown'; skip "$base-metrics" 'gnutls version unknown'; return 0; }
  P11KIT_VERSION=$(pkg_version p11-kit p11-kit || echo unknown)
  softhsm_setup || { skip "$base" 'owned SoftHSM setup failed'; skip "$base-metrics" 'owned SoftHSM setup failed'; return 0; }
  local mode
  for mode in profile metrics; do
    CELL=$base; MODE=$mode; TOOL=p11tool; TOOL_VERSION=$version; SPIED=$spied
    [ "$mode" = metrics ] && CELL=$base-metrics
    ENV_ARGS=("SOFTHSM2_CONF=$SOFTHSM_CONF" "PKCS11SPY=$spied" "PKCS11SPY_OUTPUT=$OUT/$CELL.spy.log")
    CMD_ARGS=("$toolbin" --provider "$SPY" --list-tokens)
    run_and_judge || true
  done
}

pkcs11tool_cell real-pkcs11tool-softhsm SOFTHSM libsofthsm2.so
pkcs11tool_cell real-pkcs11tool-opensc OPENSC opensc-pkcs11.so
trust_cell
nss_cell
p11tool_cell
pkcs11tool_cell real-opencryptoki OCK libopencryptoki.so

python3 -I - "$OUT/results.jsonl" <<'PY' | tee "$OUT/summary.txt"
import json,sys
rows = [json.loads(line) for line in open(sys.argv[1])]
expected = ["real-pkcs11tool-softhsm", "real-pkcs11tool-softhsm-metrics",
 "real-pkcs11tool-opensc", "real-pkcs11tool-opensc-metrics",
 "real-p11kit-trust", "real-p11kit-trust-metrics",
 "real-nss-certutil", "real-nss-certutil-metrics",
 "real-gnutls-p11tool", "real-gnutls-p11tool-metrics",
 "real-opencryptoki", "real-opencryptoki-metrics"]
ids = [row["cell"] for row in rows]
valid = len(ids) == len(set(ids)) and set(ids) == set(expected)
failed = [r["cell"] for r in rows if not r["pass"] and r["qualification"] == "failed"]
skipped = [r["cell"] for r in rows if not r["pass"] and r["qualification"] == "nonqualifying"]
harness = [r["cell"] for r in rows if r["detail"].startswith("harness:")]
print("SUMMARY pass=%d fail=%d skipped=%d harness=%d failed=%s terminal_rows_valid=%s"
 % (sum(r["pass"] for r in rows), len(failed), len(skipped), len(harness), failed, valid))
PY
[ "$HARNESS" != 0 ] && exit 2
[ "$FAILED" != 0 ] && exit 1
[ "$SKIPPED" != 0 ] && exit 77
exit 0
