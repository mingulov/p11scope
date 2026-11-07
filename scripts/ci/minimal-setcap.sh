#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# minimal-setcap.sh P11SCOPE OUTDIR: the v0.7.0 least-privilege cell.
# Runs the observer as the unprivileged `nobody` user with exactly the
# minimal file-capability set (no sudo, no CAP_SYS_ADMIN) at the current
# kernel.perf_event_paranoid and at 3/4, and proves: doctor/profile-pid
# work, inventory --system and run work, the post-setup drop sheds
# CAP_SYS_ADMIN, a run child inherits nothing, and each missing
# capability gives its named line. Leaves OUTDIR/results.jsonl for
# check-cell-results.py.
# Apt prerequisites: binutils gcc libcap2-bin procps python3 softhsm2
# util-linux.
# Must run as root (setcap, sysctl, runuser); restores paranoid on exit.
# Exit 0 means every row passed, 1 means a cell failed, 2 means a
# harness error, 77 means a prerequisite is missing.
set -u
if [ $# -ne 2 ]; then echo "usage: minimal-setcap.sh P11SCOPE OUTDIR" >&2; exit 2; fi
P=$1; OUT=$2
[ -x "$P" ] || { echo "minimal-setcap: no executable observer: $P" >&2; exit 2; }
if [ "$(id -u)" != 0 ]; then echo "minimal-setcap: must run as root" >&2; exit 2; fi
for tool in gcc getcap runuser setcap strip sysctl timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "minimal-setcap: missing prerequisite: $tool" >&2; exit 77; }
done
id nobody >/dev/null 2>&1 || { echo "minimal-setcap: missing prerequisite: nobody user" >&2; exit 77; }
SOFTHSM=""
for candidate in /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so; do
  if [ -r "$candidate" ]; then SOFTHSM=$candidate; break; fi
done
[ -n "$SOFTHSM" ] || { echo "minimal-setcap: missing prerequisite: SoftHSM2 provider" >&2; exit 77; }
test -r /sys/kernel/btf/vmlinux || { echo "minimal-setcap: missing prerequisite: kernel BTF" >&2; exit 77; }
umask 022
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd) || exit 2
CELLTMP=$OUT/tmp
rm -rf "$CELLTMP"
mkdir -p "$CELLTMP/bin" "$CELLTMP/nobody" "$CELLTMP/out" || exit 2
chmod 700 "$CELLTMP/nobody" "$CELLTMP/out"
chown nobody:nogroup "$CELLTMP/nobody" "$CELLTMP/out" 2>/dev/null \
  || chown nobody:nobody "$CELLTMP/nobody" "$CELLTMP/out" || exit 2
RESULTS=$OUT/results.jsonl
: >"$RESULTS"
FAILED=0
# -o outputs for the nobody runs: the trust check walks ancestors, so
# they must live outside the runner-owned tree. A nobody-owned 0700
# directory under root-owned /tmp passes; files move into OUT after.
NOBODYOUT=$(mktemp -d /tmp/nobody-out.XXXXXX) || exit 2
chmod 700 "$NOBODYOUT"
chown nobody:nogroup "$NOBODYOUT" 2>/dev/null || chown nobody:nobody "$NOBODYOUT" || exit 2
row() { # CELL PASS QUALIFICATION DETAIL
  pass=$2; qual=$3
  python3 -I -c 'import json,sys; print(json.dumps({"cell":sys.argv[1],"pass":sys.argv[2]=="1","qualification":sys.argv[3],"detail":sys.argv[4][:400]}))' "$1" "$pass" "$qual" "$4" >>"$RESULTS"
  [ "$pass" = 1 ] || FAILED=$((FAILED + 1))
}
SAVED_PARANOID=$(sysctl -n kernel.perf_event_paranoid)
restore_paranoid() { sysctl -w kernel.perf_event_paranoid="$SAVED_PARANOID" >/dev/null 2>&1 || true; }
cleanup() { restore_paranoid; [ -n "${NOBODYOUT:-}" ] && rm -rf "$NOBODYOUT"; }
trap cleanup EXIT
cat >"$CELLTMP/workload.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned long CK_RV;
typedef struct CK_VERSION { unsigned char major, minor; } CK_VERSION;
typedef void *CK_VOID_PTR;
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
} CK_FUNCTION_LIST;
typedef CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST **);
int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 200;
    const char *paths[] = {
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        NULL,
    };
    void *h = NULL;
    for (int i = 0; paths[i] && !h; i++)
        h = dlopen(paths[i], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed\n"); return 1; }
    C_GetFunctionList get_list = (C_GetFunctionList)dlsym(h, "C_GetFunctionList");
    printf("ready pid=%d\n", (int)getpid());
    fflush(stdout);
    for (int i = 0; i < iters; i++) {
        CK_FUNCTION_LIST *f = NULL;
        if (get_list && get_list(&f) == 0 && f) {
            f->C_Initialize(NULL);
            f->C_Finalize(NULL);
        }
        usleep(200000);
    }
    return 0;
}
EOF
gcc -O1 -o "$CELLTMP/workload" "$CELLTMP/workload.c" -ldl || exit 2
# Hermetic sleeper for the run-child cell: the owned child execs
# fd-pinned (/proc/self/fd/N, so comm is the fd number, never the
# program name), and a host uutils /bin/sleep can exit 1 under such an
# exec — match the run.rs build_sleeper precedent instead of /bin/sleep.
cat >"$CELLTMP/sleeper.c" <<'EOF'
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    unsigned secs = argc > 1 ? (unsigned)atoi(argv[1]) : 8;
    sleep(secs);
    return 0;
}
EOF
gcc -O1 -o "$CELLTMP/sleeper" "$CELLTMP/sleeper.c" || exit 2
FULL_CAPS="cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace"
mkobserver() { # NAME CAPSPEC — copy staged under CELLTMP/bin with CAPSPEC=ep
  # A failed copy must abort: setcap would happily label the truncation.
  cp -p "$P" "$CELLTMP/bin/$1" || return 1
  # Strip the copies (never the original): six debug binaries exhaust a
  # small guest tmpfs; the stripped copies execute identically.
  strip "$CELLTMP/bin/$1" || return 1
  setcap "$2=ep" "$CELLTMP/bin/$1" || return 1
  getcap "$CELLTMP/bin/$1" | grep -q . || return 1
}
mkobserver full "$FULL_CAPS" || exit 2
mkobserver miss-cap_bpf "cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace" || exit 2
mkobserver miss-cap_perfmon "cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_sys_ptrace" || exit 2
mkobserver miss-cap_checkpoint_restore "cap_bpf,cap_dac_read_search,cap_perfmon,cap_sys_ptrace" || exit 2
mkobserver miss-cap_dac_read_search "cap_bpf,cap_checkpoint_restore,cap_perfmon,cap_sys_ptrace" || exit 2
mkobserver miss-cap_sys_ptrace "cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon" || exit 2
as_nobody() { # runs "$@" as nobody with a private TMPDIR; caller redirects
  runuser -u nobody -- env TMPDIR="$CELLTMP/nobody" "$@"
}
start_workload() { # ITERS LOG — prints the workload pid
  "$CELLTMP/workload" "$1" >"$2" 2>&1 &
  local pid=$!
  for _ in $(seq 1 50); do
    grep -q "^ready pid=" "$2" 2>/dev/null && break
    sleep 0.2
  done
  grep -q "^ready pid=" "$2" || { echo "workload never became ready" >&2; return 1; }
  echo "$pid"
}
stop_workload() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
paranoid_values() { # current, 3, 4 deduplicated
  printf "%s\n%s\n%s\n" "$SAVED_PARANOID" 3 4 | awk '!seen[$0]++'
}
run_doctor() { # PARANOID — doctor-minimal cell as nobody with the full set
  paranoid=$1
  sysctl -w kernel.perf_event_paranoid="$paranoid" >/dev/null || return 1
  as_nobody "$CELLTMP/bin/full" doctor -v >"$CELLTMP/out/doctor-p$paranoid.out" 2>&1
  rc=$?
  out=$CELLTMP/out/doctor-p$paranoid.out
  detail="exit=$rc paranoid=$paranoid"
  pass=1
  [ "$rc" -eq 0 ] || pass=0
  grep -q "verdict: capture available" "$out" || pass=0
  grep -qE "^effective capabilities \.+ ok" "$out" || pass=0
  grep -qE "^minimal setcap \.+ ok" "$out" || pass=0
  grep -qE "^uprobe attach \(self\) \.+ ok" "$out" || pass=0
  if [ "$paranoid" -ge 3 ]; then
    grep -q -- "--attach-backend singles" "$out" || pass=0
  else
    grep -q "suffice" "$out" || pass=0
  fi
  detail="$detail $(grep -E '^(effective capabilities|minimal setcap|uprobe attach \(self\))' "$out" | tr '\n' ';' | head -c 200)"
  row "doctor-minimal-p$paranoid" "$pass" qualified "$detail"
}
run_profile() { # PARANOID — profile-pid cell as nobody with the full set
  paranoid=$1
  sysctl -w kernel.perf_event_paranoid="$paranoid" >/dev/null || return 1
  wlog=$CELLTMP/out/workload-p$paranoid.log
  wpid=$(start_workload 120 "$wlog") \
    || { row "profile-pid-p$paranoid" 0 qualified "workload never became ready"; return 0; }
  json=$NOBODYOUT/profile-p$paranoid.json
  as_nobody timeout 120 "$CELLTMP/bin/full" profile --pid "$wpid" --duration 8s -o "$json" \
    >"$CELLTMP/out/profile-p$paranoid.out" 2>"$CELLTMP/out/profile-p$paranoid.err"
  rc=$?
  stop_workload "$wpid"
  mv -f "$json" "$CELLTMP/out/" 2>/dev/null || true
  json=$CELLTMP/out/profile-p$paranoid.json
  out=$CELLTMP/out/profile-p$paranoid.out
  detail="exit=$rc paranoid=$paranoid"
  pass=1
  [ "$rc" -eq 0 ] || pass=0
  grep -q "counts complete" "$out" || pass=0
  if python3 -I - "$json" <<'PY'; then
import json, sys
evidence = json.load(open(sys.argv[1]))["evidence"]
assert evidence["attach_mechanisms"] == ["uprobe-multi"], evidence["attach_mechanisms"]
assert evidence.get("attach_failures", []) == [], evidence.get("attach_failures")
PY
    detail="$detail mechanisms=[uprobe-multi]"
  else
    pass=0
  fi
  detail="$detail $(grep -E 'completed calls' "$out" | head -c 120)"
  row "profile-pid-p$paranoid" "$pass" qualified "$detail"
}
run_missing() { # PARANOID CAPNAME — one missing-capability line cell
  paranoid=$1; cap=$2
  sysctl -w kernel.perf_event_paranoid="$paranoid" >/dev/null || return 1
  lower=$(printf "%s" "$cap" | tr 'A-Z' 'a-z')
  wlog=$CELLTMP/out/workload-miss-$lower-p$paranoid.log
  wpid=$(start_workload 120 "$wlog") \
    || { row "missing-cap-$lower-p$paranoid" 0 qualified "workload never became ready"; return 0; }
  as_nobody timeout 120 "$CELLTMP/bin/miss-$lower" profile --pid "$wpid" --duration 6s \
    >"$CELLTMP/out/miss-$lower-p$paranoid.out" 2>"$CELLTMP/out/miss-$lower-p$paranoid.err"
  rc=$?
  stop_workload "$wpid"
  err=$CELLTMP/out/miss-$lower-p$paranoid.err
  detail="paranoid=$paranoid exit=$rc"
  pass=1
  grep -q "needs $cap" "$err" || pass=0
  case $cap in
    CAP_BPF|CAP_PERFMON)
      grep -q "Grant the minimal set: sudo setcap" "$err" || pass=0
      [ "$rc" -ne 0 ] || pass=0
      ;;
    *)
      [ "$rc" -eq 0 ] || pass=0
      ;;
  esac
  detail="$detail $(grep -o "needs ${cap}[^;]*" "$err" | head -1 | head -c 200)"
  row "missing-cap-$lower-p$paranoid" "$pass" qualified "$detail"
}
for paranoid in $(paranoid_values); do
  run_doctor "$paranoid" || FAILED=1
  run_profile "$paranoid" || FAILED=1
  for cap in CAP_BPF CAP_PERFMON CAP_CHECKPOINT_RESTORE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE; do
    run_missing "$paranoid" "$cap" || FAILED=1
  done
done
sysctl -w kernel.perf_event_paranoid="$SAVED_PARANOID" >/dev/null || exit 2
# inventory --system as nobody with the full set (current paranoid only).
json=$NOBODYOUT/inventory-system.json
as_nobody timeout 300 "$CELLTMP/bin/full" inventory --system --duration 10s -o "$json" \
  >"$CELLTMP/out/inventory-system.out" 2>"$CELLTMP/out/inventory-system.err"
rc=$?
mv -f "$json" "$CELLTMP/out/" 2>/dev/null || true
json=$CELLTMP/out/inventory-system.json
pass=1
[ "$rc" -eq 0 ] || pass=0
python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$json" || pass=0
row inventory-system "$pass" qualified "exit=$rc"
# run as nobody with the full set (current paranoid only).
as_nobody timeout 120 "$CELLTMP/bin/full" run --duration 10s -- "$CELLTMP/workload" 40 \
  >"$CELLTMP/out/run.out" 2>"$CELLTMP/out/run.err"
rc=$?
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -qE "[1-9][0-9]* completed calls" "$CELLTMP/out/run.out" || pass=0
detail="exit=$rc $(grep -E 'completed calls' "$CELLTMP/out/run.out" | head -c 160)"
row run-minimal "$pass" qualified "$detail"
# A run child inherits no capabilities (current paranoid only).
# $opid is a subshell above runuser (a backgrounded function does not
# exec-optimize, so the sleeper sits three forks down): find it by
# executable identity across the whole tree, then confirm it descends
# from this run. -ef compares by device+inode without forking, so the
# scan is one stat per process; match by identity, not by name, because
# the fd-pinned exec leaves comm as the fd number. The 30 s duration
# against a 25 s sleeper leaves a wide window past a slow attach; the
# capability snapshot is taken at find time because the observer reaps
# the child before the run ends.
as_nobody "$CELLTMP/bin/full" run --duration 30s -- "$CELLTMP/sleeper" 25 \
  >"$CELLTMP/out/run-child.out" 2>"$CELLTMP/out/run-child.err" &
opid=$!
is_descendant() {
  _p=$1
  while [ "$_p" != 1 ] && [ "$_p" != 0 ]; do
    [ "$_p" = "$2" ] && return 0
    _p=$(awk '/^PPid:/{print $2}' /proc/"$_p"/status 2>/dev/null) || return 1
    [ -n "$_p" ] || return 1
  done
  return 1
}
child=""; eff=""; amb=""
for _ in $(seq 1 300); do
  for task in /proc/[0-9]*/exe; do
    [ "$task" -ef "$CELLTMP/sleeper" ] 2>/dev/null || continue
    cand=${task#/proc/}; cand=${cand%/exe}
    if is_descendant "$cand" "$opid"; then
      eff=$(awk '/^CapEff:/{print $2}' /proc/"$cand"/status 2>/dev/null)
      amb=$(awk '/^CapAmb:/{print $2}' /proc/"$cand"/status 2>/dev/null)
      if [ -n "$eff" ] && [ -n "$amb" ]; then
        child=$cand
        break 2
      fi
    fi
  done
  # Stop polling once the run itself exits: a slow attach must not
  # burn the whole window before the child spawns. kill -0 alone is
  # not enough (it succeeds on an unreaped zombie), so also stop on
  # zombie state; the state parse anchors on the last ")" because the
  # comm field may contain spaces.
  ostate=$(sed 's/.*) \([A-Z]\).*/\1/' /proc/"$opid"/stat 2>/dev/null) || ostate=""
  { [ -z "$ostate" ] || [ "$ostate" = "Z" ]; } && break
  sleep 0.1
done
wait "$opid"; runrc=$?
pass=1
detail=""
if [ -z "$child" ]; then
  pass=0
  detail="no sleeper child of observer $opid appeared runexit=$runrc"
  detail="$detail err=$(tail -c 160 "$CELLTMP/out/run-child.err" 2>/dev/null | tr '\n' ';')"
else
  detail="child=$child CapEff=$eff CapAmb=$amb runexit=$runrc"
  { [ "$eff" = "0000000000000000" ] && [ "$amb" = "0000000000000000" ]; } || pass=0
fi
[ "$runrc" -eq 0 ] || pass=0
row run-child-drops-caps "$pass" qualified "$detail"
# Post-setup shed: a root observer holds exactly the minimal live set
# mid-capture (current paranoid only).
wlog=$CELLTMP/out/workload-postsetup.log
wpid=$(start_workload 200 "$wlog") || exit 2
"$CELLTMP/bin/full" profile --pid "$wpid" --duration 12s \
  >"$CELLTMP/out/postsetup.out" 2>"$CELLTMP/out/postsetup.err" &
opid=$!
pass=1
detail=""
for _ in $(seq 1 60); do
  grep -q "capturing:" "$CELLTMP/out/postsetup.err" 2>/dev/null && break
  sleep 0.5
done
if grep -q "capturing:" "$CELLTMP/out/postsetup.err" 2>/dev/null; then
  eff_hex=$(awk '/^CapEff:/{print $2}' /proc/"$opid"/status)
  if python3 -I - "$eff_hex" <<'PY'; then
import sys
eff = int(sys.argv[1], 16)
live = {39, 40, 2, 38, 19}
assert all((eff >> bit) & 1 for bit in live), hex(eff)
assert not (eff >> 21) & 1, hex(eff)
PY
    detail="CapEff=$eff_hex minimal-set-only"
  else
    pass=0
    detail="unexpected mid-run CapEff=$eff_hex"
  fi
else
  pass=0
  detail="observer never reached capturing state"
fi
wait "$opid" || pass=0
stop_workload "$wpid"
row postsetup-drops-sysadmin "$pass" qualified "$detail"
trap - EXIT
cleanup
if [ "$FAILED" -ne 0 ]; then
  echo "minimal-setcap: $FAILED row(s) failed (see $RESULTS)" >&2
  exit 1
fi
echo "minimal-setcap: all rows passed"
exit 0