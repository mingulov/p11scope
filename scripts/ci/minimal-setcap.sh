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
# The cell binaries run as `nobody`, so they must live outside the
# runner-owned tree: /home/runner is not traversable by nobody (exit
# 126 there). A 755 mktemp under /var/tmp traverses everywhere.
CELLTMP=$(mktemp -d /var/tmp/minimal-setcap.XXXXXX) || exit 2
chmod 755 "$CELLTMP" || exit 2
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
cleanup() {
  restore_paranoid
  [ -n "${NOBODYOUT:-}" ] && rm -rf "$NOBODYOUT"
  # Keep the detailed row logs beside the results for failed-run
  # debugging (CELLTMP itself lives under /var/tmp and is removed).
  if [ -n "${CELLTMP:-}" ] && [ -d "$CELLTMP/out" ]; then
    rm -rf "$OUT/logs"
    cp -r "$CELLTMP/out" "$OUT/logs" 2>/dev/null || true
    rm -rf "$CELLTMP"
  fi
}
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
# Capability-drop helper for the DaemonSet rows: root with exactly the
# shipped grant (SYS_ADMIN, SYS_PTRACE, DAC_READ_SEARCH), via bounding
# drops plus capset, then exec. capsh cannot restrict root across exec
# (a bare uid-0 exec re-grants full), so this tiny helper does it.
cat >"$CELLTMP/dropcaps.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/prctl.h>
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: dropcaps MASK CMD...\n"); return 2; }
    unsigned long long keep = strtoull(argv[1], 0, 0);
    for (int cap = 0; cap <= 40; cap++) {
        if (!(keep & (1ULL << cap))) {
            if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL)
                { perror("PR_CAPBSET_DROP"); return 1; }
        }
    }
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &hdr, data)) { perror("capget"); return 1; }
    data[0].effective &= (unsigned)(keep & 0xffffffffULL);
    data[0].permitted &= (unsigned)(keep & 0xffffffffULL);
    data[0].inheritable &= (unsigned)(keep & 0xffffffffULL);
    data[1].effective &= (unsigned)((keep >> 32) & 0xffffffffULL);
    data[1].permitted &= (unsigned)((keep >> 32) & 0xffffffffULL);
    data[1].inheritable &= (unsigned)((keep >> 32) & 0xffffffffULL);
    if (syscall(SYS_capset, &hdr, data)) { perror("capset"); return 1; }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) { perror("ambient"); return 1; }
    execvp(argv[2], argv + 2);
    perror("exec");
    return 127;
}
EOF
gcc -O1 -o "$CELLTMP/dropcaps" "$CELLTMP/dropcaps.c" || exit 2
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
# Harness proof before the first nobody row: the staged observer must be
# traversable and executable by nobody, else every row would fail 126.
runuser -u nobody -- test -x "$CELLTMP/bin/full" || {
  echo "minimal-setcap: harness error: nobody cannot execute $CELLTMP/bin/full" >&2
  exit 2
}
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
  out=$CELLTMP/out/miss-$lower-p$paranoid.out
  detail="paranoid=$paranoid exit=$rc"
  pass=1
  grep -q "needs $cap" "$err" || pass=0
  case $cap in
    CAP_BPF|CAP_PERFMON)
      grep -q "Grant the minimal set: sudo setcap" "$err" || pass=0
      [ "$rc" -ne 0 ] || pass=0
      ;;
    CAP_CHECKPOINT_RESTORE)
      # Degraded proof only: counts stay complete for an in-scan-cap
      # target, and the coverage line must say so (no silent success).
      [ "$rc" -eq 0 ] || pass=0
      grep -q "counts complete" "$out" || pass=0
      ;;
    CAP_DAC_READ_SEARCH)
      # No target read: the coverage line must disclose the partial
      # scan, not just the stderr needs-line.
      [ "$rc" -eq 0 ] || pass=0
      grep -q "memory scan unavailable" "$out" || pass=0
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
# inventory --system as nobody with the full set (current paranoid only),
# with a calling SoftHSM workload so the report must name its module
# and at least one caller edge (guards the 0-endpoint silent pass).
wlog=$CELLTMP/out/workload-inventory.log
wpid=$(start_workload 200 "$wlog") || exit 2
json=$NOBODYOUT/inventory-system.json
as_nobody timeout 300 "$CELLTMP/bin/full" inventory --system --duration 10s -o "$json" \
  >"$CELLTMP/out/inventory-system.out" 2>"$CELLTMP/out/inventory-system.err"
rc=$?
stop_workload "$wpid"
mv -f "$json" "$CELLTMP/out/" 2>/dev/null || true
json=$CELLTMP/out/inventory-system.json
pass=1
[ "$rc" -eq 0 ] || pass=0
if python3 -I - "$json" <<'PY'; then
import json, sys
doc = json.load(open(sys.argv[1]))
modules = [m.get("path", "") for m in doc.get("modules", [])]
assert any("libsofthsm2" in p for p in modules), modules
assert len(doc.get("edges", [])) > 0, "no caller edges"
PY
  detail="exit=$rc module+edge present"
else
  pass=0
  detail="exit=$rc module or edge missing"
fi
row inventory-system "$pass" qualified "$detail"
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
  # The shed is per-thread: every task must hold the minimal set only,
  # not just the leader (the cleanup worker and its helpers predate it).
  tasks_detail=""
  tasks_bad=""
  for task in /proc/"$opid"/task/*; do
    tid=${task#/proc/"$opid"/task/}
    eff_hex=$(awk '/^CapEff:/{print $2}' "$task/status" 2>/dev/null) || continue
    tasks_detail="$tasks_detail $tid=$eff_hex"
    if ! python3 -I - "$eff_hex" <<'PY'; then
import sys
eff = int(sys.argv[1], 16)
live = {39, 40, 2, 38, 19}
assert all((eff >> bit) & 1 for bit in live), hex(eff)
assert not (eff >> 21) & 1, hex(eff)
PY
      tasks_bad="$tasks_bad $tid=$eff_hex"
    fi
  done
  if [ -z "$tasks_bad" ] && [ -n "$tasks_detail" ]; then
    detail="CapEff minimal-set-only on all tasks:$tasks_detail"
  else
    pass=0
    detail="unexpected mid-run CapEff on tasks:$tasks_bad (all:$tasks_detail)"
  fi
else
  pass=0
  detail="observer never reached capturing state"
fi
wait "$opid" || pass=0
stop_workload "$wpid"
row postsetup-drops-sysadmin "$pass" qualified "$detail"
# Root `run` rows: the sudo drop re-owns the child without `--user`
# (SETUID/SETGID) and the parent signals across uids (KILL). Without
# those keeps the child dies EPERM and the run reports "original
# process exited before proc acquisition".
SUDO_IDS="SUDO_UID=$(id -u nobody) SUDO_GID=$(id -g nogroup 2>/dev/null || id -g nobody)"
env $SUDO_IDS timeout 120 "$CELLTMP/bin/full" run --duration 8s -- "$CELLTMP/workload" 40 \
  >"$CELLTMP/out/run-sudo.out" 2>"$CELLTMP/out/run-sudo.err"
rc=$?
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -qE "[1-9][0-9]* completed calls" "$CELLTMP/out/run-sudo.out" || pass=0
row run-sudo "$pass" qualified "exit=$rc $(grep -E 'completed calls' "$CELLTMP/out/run-sudo.out" | head -c 120)"
timeout 120 "$CELLTMP/bin/full" run --user nobody --duration 8s -- "$CELLTMP/workload" 40 \
  >"$CELLTMP/out/run-user.out" 2>"$CELLTMP/out/run-user.err"
rc=$?
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -qE "[1-9][0-9]* completed calls" "$CELLTMP/out/run-user.out" || pass=0
row run-user-nobody "$pass" qualified "exit=$rc $(grep -E 'completed calls' "$CELLTMP/out/run-user.out" | head -c 120)"
# --kill-on-timeout across uids: the observer must signal (KILL) the
# re-owned sleeper at duration end instead of leaving it running.
env $SUDO_IDS timeout 120 "$CELLTMP/bin/full" run --kill-on-timeout --duration 5s -- "$CELLTMP/sleeper" 60 \
  >"$CELLTMP/out/run-kill.out" 2>"$CELLTMP/out/run-kill.err"
rc=$?
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -q "child still running" "$CELLTMP/out/run-kill.err" && pass=0
row run-kill-on-timeout "$pass" qualified "exit=$rc"
# Sudo `trace -o` into an invoker-owned directory: the preflight hands
# the stream over (CHOWN), then the first write chmods it private
# (FOWNER) — without FOWNER the handover breaks with EPERM.
SUDODIR=$(mktemp -d /tmp/trace-sudo-out.XXXXXX)
chmod 700 "$SUDODIR"
chown nobody:nogroup "$SUDODIR" 2>/dev/null || chown nobody:nobody "$SUDODIR"
wlog=$CELLTMP/out/workload-tracesudo.log
wpid=$(start_workload 120 "$wlog") || exit 2
env $SUDO_IDS timeout 120 "$CELLTMP/bin/full" trace --pid "$wpid" --duration 6s -o "$SUDODIR/trace.txt" \
  >"$CELLTMP/out/trace-sudo.out" 2>"$CELLTMP/out/trace-sudo.err"
rc=$?
stop_workload "$wpid"
pass=1
[ "$rc" -eq 0 ] || pass=0
[ -s "$SUDODIR/trace.txt" ] || pass=0
[ "$(stat -c %U "$SUDODIR/trace.txt")" = "nobody" ] || pass=0
[ "$(stat -c %a "$SUDODIR/trace.txt")" = "600" ] || pass=0
row trace-sudo-out "$pass" qualified "exit=$rc owner=$(stat -c %U:%a "$SUDODIR/trace.txt" 2>/dev/null)"
rm -rf "$SUDODIR"
# DaemonSet rows: root with exactly the shipped grant (SYS_ADMIN,
# SYS_PTRACE, DAC_READ_SEARCH). The observer must retain SYS_ADMIN as
# the only BPF/map_files grant instead of dropping to an unusable set.
DAEMONSET=0x280004
"$CELLTMP/dropcaps" "$DAEMONSET" "$CELLTMP/bin/full" doctor \
  >"$CELLTMP/out/daemonset-doctor.out" 2>"$CELLTMP/out/daemonset-doctor.err"
rc=$?
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -q "capture available" "$CELLTMP/out/daemonset-doctor.out" || pass=0
row daemonset-doctor "$pass" qualified "exit=$rc"
wlog=$CELLTMP/out/workload-daemonset.log
wpid=$(start_workload 120 "$wlog") || exit 2
"$CELLTMP/dropcaps" "$DAEMONSET" "$CELLTMP/bin/full" profile --pid "$wpid" --duration 6s \
  >"$CELLTMP/out/daemonset-profile.out" 2>"$CELLTMP/out/daemonset-profile.err"
rc=$?
stop_workload "$wpid"
pass=1
[ "$rc" -eq 0 ] || pass=0
grep -q "counts complete" "$CELLTMP/out/daemonset-profile.out" || pass=0
row daemonset-profile "$pass" qualified "exit=$rc"
wlog=$CELLTMP/out/workload-daemonset-inv.log
wpid=$(start_workload 200 "$wlog") || exit 2
"$CELLTMP/dropcaps" "$DAEMONSET" "$CELLTMP/bin/full" inventory --system --duration 8s -o "$CELLTMP/out/daemonset-inventory.json" \
  >"$CELLTMP/out/daemonset-inventory.out" 2>"$CELLTMP/out/daemonset-inventory.err"
rc=$?
stop_workload "$wpid"
pass=1
[ "$rc" -eq 0 ] || pass=0
python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$CELLTMP/out/daemonset-inventory.json" || pass=0
row daemonset-inventory "$pass" qualified "exit=$rc"
trap - EXIT
cleanup
if [ "$FAILED" -ne 0 ]; then
  echo "minimal-setcap: $FAILED row(s) failed (see $RESULTS)" >&2
  exit 1
fi
echo "minimal-setcap: all rows passed"
exit 0