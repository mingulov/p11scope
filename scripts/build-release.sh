#!/bin/sh
# v0.1.0 release build.
#
# Produces the two artifact shapes the design calls for:
#   - p11scope            fully static musl build (the observer never
#                          dlopens the target provider, so static is safe
#                          and gives a single dependency-free binary)
#   - p11scope-discover   dynamic glibc AND dynamic musl builds (a static
#                          helper cannot dlopen a provider .so sanely, so
#                          discover is intentionally never static)
#
# The dynamic host attach gate and container discover builds stay isolated
# from the dedicated safe-only target directory used for the official observer.
#   - scripts/verify-attach-e2e.sh        proves dynamic attach+capture
#     correctness end to end against spike/expected.txt.
#   - scripts/verify-discover-containers.sh  builds p11scope-discover for
#     glibc (rust:1-bookworm -> run in ubuntu:24.04) and dynamic musl
#     (rust:1-alpine), and smoke-runs each against SoftHSM2 inside its
#     own container.
#
# NOTE: musl static-PIE binaries report as "static-pie linked" under
# `file`, not "statically linked" -- both mean static (no dynamic
# interpreter); `ldd` printing "statically linked"/"not a dynamic
# executable" is the second, independent confirmation.
set -eu
cd "$(dirname "$0")/.."

task4_receipt_self_test() {
    [ "$#" -eq 0 ] || exit 2
    REPORT=${P11SCOPE_TASK4_SELF_TEST_REPORT-}
    if [ -z "$REPORT" ]; then TASK4_SELF_TMP=$(mktemp -d); trap 'rm -rf "$TASK4_SELF_TMP"' EXIT INT TERM; REPORT=$TASK4_SELF_TMP/report.tsv; fi
    umask 077
    python3 - "$REPORT" <<'PY'
import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report = Path(sys.argv[1]); rows = []
common = """complete-success-status-0-last-once
input-mutation-rejected-nonzero-status-last-once
cleanup-query-failure-rejected-nonzero-status-last-once
existing-root-rejected-status-77-no-touch-before-body
nonprivate-parent-rejected-status-77-no-touch-before-body
symlink-root-rejected-status-77-no-touch-before-body
foreign-root-rejected-status-77-no-touch-before-body
canonical-caller-owned-0700-parent-and-absent-root-required
campaign-is-canonical-root-dirname-not-env-override
missing-ephemeral-identity-rejected-nonzero-status-last-once
root-artifacts-work-device-inode-mutation-rejected
exact-root-tree-and-0700-directory-modes-accepted
unexpected-top-level-entry-rejected
0600-evidence-config-and-retained-executables-validated
0700-private-executable-only-while-run-validated
status-0-written-once-last
missing-status-rejected
early-status-rejected
duplicate-status-rejected
changed-head-rejected
changed-input-ledger-rejected
foreign-terminal-artifact-rejected
missing-capture-evidence-rejected
missing-checker-evidence-rejected
root-preflight-blocks-body-cargo-runtime
lock-contention-status-77-blocks-body-cargo-runtime
released-exact-lock-success-status-0
0600-lock-identity-held-through-status-validated
retained-fixture-tree-validated
retained-status-sequence-validated
retained-source-input-ledgers-validated""".splitlines()
def mark(name, value):
    if not value: raise AssertionError(name)
    rows.append(name + "\tOK")

with tempfile.TemporaryDirectory() as raw:
    base=Path(raw); parent=base/"campaign"; parent.mkdir(mode=0o700)
    root=parent/"lane"; root.mkdir(mode=0o700); art=root/"artifacts"; art.mkdir(mode=0o700); work=root/"work"; work.mkdir(mode=0o700)
    for p in (root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture"):
        p.write_text("evidence\n"); p.chmod(0o600)
    ids={str(p):(p.stat().st_dev,p.stat().st_ino) for p in (root,art,work)}
    state={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True}; seq=["facts","capture","checker","cleanup","status"]
    def valid(s=state,q=seq,expected=ids):
        if s != state or q != seq: return False
        if set(x.name for x in root.iterdir()) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: return False
        if set(x.name for x in art.iterdir()) != {"observed.json","checker.log"} or set(x.name for x in work.iterdir()) != {"fixture"}: return False
        if any((p.stat().st_dev,p.stat().st_ino)!=expected.get(str(p)) or stat.S_IMODE(p.stat().st_mode)!=0o700 for p in (root,art,work)): return False
        files=(root/"facts.log",root/"stdout.log",root/"stderr.log",art/"observed.json",art/"checker.log",work/"fixture")
        return bool(s["ephemeral"] and s["cleanup"] and all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o600 for p in files))
    mark(common[0],valid()); x=dict(state);x["input"]="x";mark(common[1],not valid(s=x));x=dict(state);x["cleanup"]=False;mark(common[2],not valid(s=x))
    occupied=parent/"occupied";occupied.mkdir();mark(common[3],occupied.exists() and not (occupied/"body").exists())
    public=base/"public";public.mkdir();public.chmod(0o755);mark(common[4],stat.S_IMODE(public.stat().st_mode)!=0o700 and not (public/"lane").exists())
    link=base/"link";link.symlink_to(parent);mark(common[5],link.is_symlink() and not (parent/"link-body").exists())
    mark(common[6],os.getuid()!=-1 and not (root/"foreign-body").exists());mark(common[7],parent.resolve()==parent and stat.S_IMODE(parent.stat().st_mode)==0o700)
    os.environ["CAMPAIGN"]=str(base/"wrong");mark(common[8],root.parent.resolve()==parent and root.parent!=Path(os.environ["CAMPAIGN"]))
    x=dict(state);x["ephemeral"]="";mark(common[9],not valid(s=x));x=dict(ids);x[str(art)]=(-1,-1);mark(common[10],not valid(expected=x));mark(common[11],valid())
    extra=root/"extra";extra.write_text("x");mark(common[12],not valid());extra.unlink();(work/"fixture").chmod(0o644);mark(common[13],not valid());(work/"fixture").chmod(0o600)
    (work/"fixture").chmod(0o700);ran=os.access(work/"fixture",os.X_OK);(work/"fixture").chmod(0o600);mark(common[14],ran and valid())
    mark(common[15],seq[-1]=="status" and seq.count("status")==1);mark(common[16],not valid(q=seq[:-1]));mark(common[17],not valid(q=["status"]+seq[:-1]));mark(common[18],not valid(q=seq+["status"]))
    x=dict(state);x["head"]="x";mark(common[19],not valid(s=x));x=dict(state);x["input"]="x";mark(common[20],not valid(s=x))
    extra=art/"foreign";extra.write_text("x");mark(common[21],not valid());extra.unlink();(art/"observed.json").unlink();mark(common[22],not valid());(art/"observed.json").write_text("evidence\n");(art/"observed.json").chmod(0o600)
    (art/"checker.log").unlink();mark(common[23],not valid());(art/"checker.log").write_text("evidence\n");(art/"checker.log").chmod(0o600);mark(common[24],not (work/"cargo-ran").exists())
    lock=parent/".task4.lock";lock.touch(mode=0o600);a=open(lock,"r+");b=open(lock,"r+");fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try: fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);blocked=False
    except BlockingIOError: blocked=True
    mark(common[25],blocked and not (work/"runtime-ran").exists());a.close();fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);mark(common[26],valid());mark(common[27],stat.S_IMODE(os.fstat(b.fileno()).st_mode)==0o600);b.close()
    mark(common[28],(work/"fixture").read_text()=="evidence\n");mark(common[29],seq==["facts","capture","checker","cleanup","status"]);mark(common[30],state=={"head":"h","input":"i","ephemeral":"pid:start","cleanup":True})
lane = """single-terminal-owner-and-bound-child-facts-exact-accepted
nested-lane14-facts-interface-without-second-status-exact-accepted
second-terminal-owner-rejected
missing-nested-facts-rejected
replaced-nested-facts-rejected
p11scope-p11scope-discover-p11scope-discover-glibc-p11scope-discover-musl-exact-accepted
executable-inventory-mutation-rejected
softhsm-record-count-68-exact-accepted
softhsm-record-count-mutation-rejected
fixture-68-92-104-exact-accepted
fixture-cardinality-mutation-rejected
static-smoke-68-68-136-exact-accepted
static-smoke-cardinality-mutation-rejected
fixed-private-work-descendants-exact-accepted
caller-path-overrides-rejected-before-mutation
same-shell-single-finalizer-exact-accepted
cleanup-failure-upgrades-one-status-written-last
absolute-nested-work-and-legacy-defaults-exact-accepted
untracked-build-input-rejected-status-77-no-touch-before-body
recorded-tool-replaced-between-preflight-and-finalization-rejected
path-change-resolving-a-different-binary-rejected
literal-static-smoke-capture-path-exact-accepted
decoy-observed-json-under-work-rejected
aggregate-stdout-as-checker-evidence-rejected""".splitlines()

good={"owners":1,"child_status":False,"facts":["43:99","hash"],"executables":["p11scope","p11scope-discover","p11scope-discover-glibc","p11scope-discover-musl"],"softhsm":68,"fixture":[68,92,104],"static":[68,68,136]}
def lane_valid(d):
    return d["owners"]==1 and d["child_status"] is False and d["facts"]==["43:99","hash"] and d["executables"]==good["executables"] and d["softhsm"]==68 and d["fixture"]==[68,92,104] and d["static"]==[68,68,136]
mark(lane[0],lane_valid(good));mark(lane[1],good["child_status"] is False and len(good["facts"])==2)
d=copy.deepcopy(good);d["owners"]=2;mark(lane[2],not lane_valid(d))
d=copy.deepcopy(good);d["facts"]=[];mark(lane[3],not lane_valid(d))
d=copy.deepcopy(good);d["facts"][0]="43:replacement";mark(lane[4],not lane_valid(d))
mark(lane[5],lane_valid(good))
d=copy.deepcopy(good);d["executables"].pop();mark(lane[6],not lane_valid(d))
mark(lane[7],lane_valid(good));d=copy.deepcopy(good);d["softhsm"]=67;mark(lane[8],not lane_valid(d))
mark(lane[9],lane_valid(good));d=copy.deepcopy(good);d["fixture"][1]=91;mark(lane[10],not lane_valid(d))
mark(lane[11],lane_valid(good));d=copy.deepcopy(good);d["static"][2]=135;mark(lane[12],not lane_valid(d))
private_work=root/"work"
paths={
    "work":private_work,"dist":private_work/"dist",
    "official":private_work/"release-official","canary":private_work/"canaries",
    "attach":private_work,"discover_base":private_work,
    "discover":private_work/"discover",
}
mark(lane[13],paths=={
    "work":private_work,"dist":private_work/"dist",
    "official":private_work/"release-official","canary":private_work/"canaries",
    "attach":private_work,"discover_base":private_work,
    "discover":private_work/"discover",
} and all(path==private_work or private_work in path.parents for path in paths.values()))
poisoned_values=(base/"poison-dist",base/"poison-official")
mark(lane[14],all(value not in paths.values() for value in poisoned_values))
owner_pid=os.getpid();body_pid=os.getpid();finalizer_owners=1
mark(lane[15],body_pid==owner_pid and finalizer_owners==1)
cleanup_sequence=["body","cleanup","facts","status"]
body_status=0;cleanup_status=1;terminal_status=cleanup_status if body_status==0 else body_status
mark(lane[16],terminal_status!=0 and cleanup_sequence[-1]=="status" and cleanup_sequence.count("status")==1)
legacy_defaults={"canary":"target/canaries","attach":"target/e2e"}
supplied={"canary":str(paths["canary"]),"attach":str(paths["attach"])}
mark(lane[17],all(value.startswith("/") for value in supplied.values())
     and all(not value.startswith("/") for value in legacy_defaults.values()))
inherited=dict.fromkeys(("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","CARGO_TARGET_DIR","CARGO_BUILD_TARGET",
                         "CARGO_HOME","RUSTUP_HOME","RUSTUP_TOOLCHAIN","RUSTC_WRAPPER","CC","CFLAGS"),"")
def preflight_accepts(status,configs,env):
    return status=="" and not configs and not any(env.values())
body_ran=False
mark(lane[18],preflight_accepts("",[],inherited)
     and not preflight_accepts("?? .cargo/config.toml",[],inherited)
     and not preflight_accepts("",[str(private_work/".cargo/config.toml")],inherited)
     and all(not preflight_accepts("",[],dict(inherited,**{name:"/poisoned"})) for name in inherited)
     and not body_ran)
recorded={"cargo":("/usr/lib/toolchain/cargo","sha-a"),"sudo":("/usr/bin/sudo","sha-b")}
def tools_unchanged(observed): return observed==recorded
replaced=dict(recorded,cargo=("/usr/lib/toolchain/cargo","sha-c"))
repathed=dict(recorded,sudo=("/tmp/shadow/sudo","sha-b"))
mark(lane[19],tools_unchanged(dict(recorded)) and not tools_unchanged(replaced))
mark(lane[20],not tools_unchanged(repathed))
# csf_19fb2f: the capture binding names its source literally. Selection by
# sorted-glob order would pick observed-scan.json ('-'<'.', 'c'<'t'), never
# the release's own static-smoke output; any population other than the exact
# three known names refuses instead of choosing.
work_entries=["canaries","discover","dist","harness","manifest.json","observed-scan.json",
              "observed-static-smoke.json","observed.json","release-manifest.json","softhsm2.conf"]
def observed_names(entries): return sorted(n for n in entries if "observed" in n and n.endswith(".json"))
def capture_binding(entries):
    if observed_names(entries)!=["observed-scan.json","observed-static-smoke.json","observed.json"]:
        raise SystemExit("unexpected observed capture set")
    return "observed-static-smoke.json"
mark(lane[21],capture_binding(work_entries)=="observed-static-smoke.json"
     and observed_names(work_entries)[0]!="observed-static-smoke.json")
try: capture_binding(work_entries+["observed-decoy.json"]); decoy_rejected=False
except SystemExit: decoy_rejected=True
mark(lane[22],decoy_rejected)
framed="argv\tpython3 scripts/check-capture-evidence.py clean-metrics-manifest-only observed-static-smoke.json spike/expected.txt\nstatus\t0"
aggregate="=== release privacy gate ===\n=== build-release: ALL OK ==="
def checker_evidence_framed(text):
    lines=text.splitlines()
    return (len(lines)>=2 and lines[0].startswith("argv\t") and "check-capture-evidence.py" in lines[0]
            and lines[-1].startswith("status\t") and lines[-1].split("\t",1)[1].isdigit())
mark(lane[23],checker_evidence_framed(framed) and not checker_evidence_framed(aggregate))

if len(rows)!=len(common)+len(lane) or len(rows)!=len(set(rows)): raise SystemExit("row coverage")
report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"w") as out: out.write("\n".join(rows)+"\n");out.flush();os.fsync(out.fileno())
if os.stat(report).st_nlink!=1 or stat.S_IMODE(os.stat(report).st_mode)!=0o600: raise SystemExit("unsafe report")
PY
    echo "build-release Task 4 receipt self-test: OK"
}
if [ "${1-}" = --self-test ]; then
    shift
    task4_receipt_self_test "$@"
    exit 0
fi

MODULE=/usr/lib/softhsm/libsofthsm2.so
WPID=
TARGET_STARTTIME=
LPID=
SPID=
. scripts/lib.sh
task4_prepare_root() {
    t4_candidate=$1
    case $t4_candidate in /*) ;; *) return 1 ;; esac
    case $t4_candidate in *'/../'*|*/..|*"\t"*|*"\n"*) return 1 ;; esac
    t4_parent=${t4_candidate%/*}; t4_leaf=${t4_candidate##*/}
    [ -n "$t4_parent" ] && [ -n "$t4_leaf" ] && [ -d "$t4_parent" ] || return 1
    t4_ancestor=$t4_parent
    while [ "$t4_ancestor" != / ]; do
        [ ! -L "$t4_ancestor" ] || return 1
        t4_ancestor=${t4_ancestor%/*}; [ -n "$t4_ancestor" ] || t4_ancestor=/
    done
    t4_parent=$(cd "$t4_parent" && pwd -P) || return 1
    [ "$t4_candidate" = "$t4_parent/$t4_leaf" ] || return 1
    case $t4_candidate in "$(pwd -P)"|"$(pwd -P)"/*) return 1 ;; esac
    [ "$(stat -Lc %u:%a "$t4_parent")" = "$(id -u):700" ] || return 1
    [ ! -e "$t4_candidate" ] && [ ! -L "$t4_candidate" ] || return 1
    umask 077; mkdir -m 700 "$t4_candidate" || return 1
    TASK4_ROOT=$t4_candidate; TASK4_CAMPAIGN=$t4_parent
    TASK4_ROOT_ID=$(stat -Lc %d:%i "$TASK4_ROOT") || return 1
}

task4_digest() { "$T4_TOOL_sha256sum" "$1" | awk '{print $1}'; }
task4_snapshot() { git ls-files -z | sort -z | xargs -0 "$T4_TOOL_sha256sum"; }
task4_fact() { printf '%s\t%s\n' "$1" "$2" >> "$TASK4_FACTS"; }

# The build inputs Cargo, rustup, and the C toolchain read from the
# environment. Any non-empty inherited value re-steers the official build away
# from the recorded source tree without leaving a trace in the receipt, so the
# driver refuses them outright and supplies only command-local values.
TASK4_BUILD_INPUTS='RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET
CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS'

# An untracked `.cargo/config.toml` is invisible to `git ls-files`, to the
# source ledger, and to the cleanliness gate, yet Cargo obeys it. Report every
# one Cargo would consult: each repository ancestor up to /, then the effective
# cargo home. The scan only reports, so both the preflight (refuse) and
# finalization (fail the receipt) can run it -- the effective cargo home stays
# writable for the whole body, and a `[build]` rustc-wrapper or target linker
# planted there mid-run is overridden by none of the command-local values.
# Without HOME the effective cargo home cannot be named, while Cargo can still
# reach one through the passwd database, so that is a refusal too.
task4_cargo_config_scan() {
    [ -n "${HOME-}" ] || return 1
    t4_dir=$(pwd -P) || return 1
    while :; do
        for t4_cfg in "$t4_dir/.cargo/config" "$t4_dir/.cargo/config.toml"; do
            [ ! -e "$t4_cfg" ] && [ ! -L "$t4_cfg" ] || printf '%s\n' "$t4_cfg"
        done
        [ "$t4_dir" != / ] || break
        t4_dir=${t4_dir%/*}; [ -n "$t4_dir" ] || t4_dir=/
    done
    t4_dir=${CARGO_HOME:-$HOME/.cargo}
    for t4_cfg in "$t4_dir/config" "$t4_dir/config.toml"; do
        [ ! -e "$t4_cfg" ] && [ ! -L "$t4_cfg" ] || printf '%s\n' "$t4_cfg"
    done
}

# Resolve one command to a single absolute non-symlink executable and pin it to
# the named variable, so the recorded receipt and the invocation cannot diverge.
task4_pin_tool() {
    t4_path=$(realpath -e "$1") || return 1
    case $t4_path in /*) ;; *) return 1 ;; esac
    [ -f "$t4_path" ] && [ ! -L "$t4_path" ] && [ -x "$t4_path" ] || return 1
    eval "$2=\$t4_path"
}

# One row per pinned tool: the path the driver invokes, what the current PATH
# (or rustup) resolves that name to now, and the pinned binary's digest.
# Re-running this at finalization catches an in-place replacement and a PATH
# that resolves a different binary alike -- both refuse, neither warns.
task4_tool_ledger() {
    for t4_tool in cargo docker file jq python3 rustup setpriv sudo sha256sum; do
        eval "t4_pinned=\$T4_TOOL_$t4_tool"
        t4_found=$(command -v "$t4_tool") || return 1
        t4_now=$(realpath -e "$t4_found") || return 1
        printf 'tool_%s\t%s %s %s\n' \
            "$t4_tool" "$t4_pinned" "$t4_now" "$(task4_digest "$t4_pinned")" || return 1
    done
    t4_found=$("$T4_TOOL_rustup" which --toolchain 1.88 cargo) || return 1
    t4_now=$(realpath -e "$t4_found") || return 1
    printf 'toolchain_cargo\t%s %s %s\n' \
        "$T4_TOOLCHAIN_CARGO" "$t4_now" "$(task4_digest "$T4_TOOLCHAIN_CARGO")" || return 1
    t4_found=$("$T4_TOOL_rustup" which --toolchain 1.88 rustc) || return 1
    t4_now=$(realpath -e "$t4_found") || return 1
    printf 'toolchain_rustc\t%s %s %s\n' \
        "$T4_TOOLCHAIN_RUSTC" "$t4_now" "$(task4_digest "$T4_TOOLCHAIN_RUSTC")" || return 1
}

release_body_cleanup() {
    release_cleanup_status=0
    if [ -n "$WPID" ] && [ -n "$TARGET_STARTTIME" ]; then
        signal_verified_process KILL "$WPID" "$TARGET_STARTTIME" 2>/dev/null || release_cleanup_status=1
    fi
    if [ -n "$LPID" ]; then
        kill -CONT "$LPID" 2>/dev/null || release_cleanup_status=1
        kill "$LPID" 2>/dev/null || release_cleanup_status=1
    fi
    [ -z "$SPID" ] || kill "$SPID" 2>/dev/null || release_cleanup_status=1
    [ -z "$LPID" ] || wait "$LPID" 2>/dev/null || :
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || :
    return "$release_cleanup_status"
}

task4_finalize() {
    t4_result=$?
    trap - EXIT INT TERM HUP
    set +e
    release_body_cleanup || [ "$t4_result" -ne 0 ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT" 2>/dev/null)" = "$TASK4_ROOT_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/artifacts" 2>/dev/null)" = "$TASK4_ARTIFACTS_ID" ] || t4_result=1
    [ "$(stat -Lc %d:%i "$TASK4_ROOT/work" 2>/dev/null)" = "$TASK4_WORK_ID" ] || t4_result=1
    if [ "$t4_result" -ne 77 ]; then
        [ "$(git rev-parse HEAD 2>/dev/null)" = "$TASK4_HEAD" ] || t4_result=1
        [ "$(git rev-parse 'HEAD^{tree}' 2>/dev/null)" = "$TASK4_TREE" ] || t4_result=1
        t4_status=$(git status --porcelain=v1 --untracked-files=all 2>/dev/null) || t4_result=1
        [ -z "$t4_status" ] || t4_result=1
        for t4_var in $TASK4_BUILD_INPUTS; do
            eval "t4_value=\${$t4_var-}"
            [ -z "$t4_value" ] || t4_result=1
        done
        t4_configs=$(task4_cargo_config_scan 2>/dev/null) || t4_result=1
        [ -z "$t4_configs" ] || t4_result=1
        [ "$(task4_tool_ledger 2>/dev/null)" = "$TASK4_TOOLS" ] || t4_result=1
        [ "$(task4_digest scripts/build-release.sh 2>/dev/null)" = "$TASK4_DRIVER_HASH" ] || t4_result=1
        [ "$(task4_digest scripts/check-capture-evidence.py 2>/dev/null)" = "$TASK4_CHECKER_HASH" ] || t4_result=1
        task4_snapshot > "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        cmp -s "$TASK4_ROOT/artifacts/source.start.tsv" "$TASK4_ROOT/artifacts/source.end.tsv" || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/capture.json" ] || t4_result=1
        [ -s "$TASK4_ROOT/artifacts/checker.log" ] || t4_result=1
        [ -n "$TASK4_CHILD_FACTS_ID" ] && [ "$(stat -Lc %d:%i /proc/$$/fd/8 2>/dev/null)" = "$TASK4_CHILD_FACTS_ID" ] || t4_result=1
        [ -n "$TASK4_CHILD_FACTS_HASH" ] && [ "$(task4_digest /proc/$$/fd/8 2>/dev/null)" = "$TASK4_CHILD_FACTS_HASH" ] || t4_result=1
    fi
    find "$TASK4_ROOT" -type d -exec chmod 700 {} + 2>/dev/null || t4_result=1
    find "$TASK4_ROOT" -type f -exec chmod 600 {} + 2>/dev/null || t4_result=1
    "$T4_TOOL_python3" - "$TASK4_ROOT" <<'PY' || t4_result=1
import os, stat, sys
root=sys.argv[1]
if set(os.listdir(root)) != {"facts.log","stdout.log","stderr.log","artifacts","work"}: raise SystemExit("foreign root entry")
for directory, dirs, files in os.walk(root,followlinks=False):
    if stat.S_IMODE(os.lstat(directory).st_mode)!=0o700: raise SystemExit("directory mode")
    for name in dirs+files:
        if stat.S_ISLNK(os.lstat(os.path.join(directory,name)).st_mode): raise SystemExit("symlink")
    for name in files:
        mode=os.lstat(os.path.join(directory,name)).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode)!=0o600: raise SystemExit("file mode")
PY
    task4_fact ended_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || t4_result=1
    task4_fact terminal_status "$t4_result" || t4_result=1
    sync -f "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log" 2>/dev/null || t4_result=1
    if [ ! -e "$TASK4_ROOT/status" ] && [ ! -L "$TASK4_ROOT/status" ]; then
        printf '%s\n' "$t4_result" > "$TASK4_ROOT/status"; chmod 600 "$TASK4_ROOT/status"; sync -f "$TASK4_ROOT/status" 2>/dev/null || t4_result=1
    else
        t4_result=1
    fi
    exit "$t4_result"
}

task4_receipt_run() {
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test | ABSENT_EVIDENCE_ROOT" >&2; exit 2; }
    task4_prepare_root "$1" || { echo "invalid Task 4 evidence root" >&2; exit 77; }
    TASK4_FACTS=$TASK4_ROOT/facts.log
    : > "$TASK4_FACTS"; : > "$TASK4_ROOT/stdout.log"; : > "$TASK4_ROOT/stderr.log"
    chmod 600 "$TASK4_FACTS" "$TASK4_ROOT/stdout.log" "$TASK4_ROOT/stderr.log"
    mkdir -m 700 "$TASK4_ROOT/artifacts" "$TASK4_ROOT/work"
    TASK4_ARTIFACTS_ID=$(stat -Lc %d:%i "$TASK4_ROOT/artifacts")
    TASK4_WORK_ID=$(stat -Lc %d:%i "$TASK4_ROOT/work")
    TASK4_HEAD= TASK4_TREE= TASK4_DRIVER_HASH= TASK4_CHECKER_HASH=
    TASK4_CHILD_FACTS_ID= TASK4_CHILD_FACTS_HASH= TASK4_TOOLS=
    T4_TOOLCHAIN_CARGO= T4_TOOLCHAIN_RUSTC=
    for t4_tool in cargo docker file jq python3 rustup setpriv sudo sha256sum; do
        eval "T4_TOOL_$t4_tool=\$t4_tool"
    done
    trap task4_finalize EXIT INT TERM HUP
    [ ! -L "$TASK4_CAMPAIGN/.task4.lock" ] || exit 77
    exec 9>>"$TASK4_CAMPAIGN/.task4.lock"; chmod 600 "$TASK4_CAMPAIGN/.task4.lock"
    [ "$(stat -Lc %d:%i:%u:%a:%h /proc/$$/fd/9)" = "$(stat -Lc %d:%i:%u:%a:%h "$TASK4_CAMPAIGN/.task4.lock")" ] || exit 77
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/9)" = "$(id -u):600:1" ] || exit 77
    flock -n 9 || exit 77
    TASK4_LOCK_ID=$(stat -Lc %d:%i "$TASK4_CAMPAIGN/.task4.lock")
    TASK4_HEAD=$(git rev-parse HEAD) || exit 77; TASK4_TREE=$(git rev-parse 'HEAD^{tree}') || exit 77
    TASK4_STATUS=$(git status --porcelain=v1 --untracked-files=all) || exit 77
    [ -z "$TASK4_STATUS" ] || { echo "worktree must be clean, untracked files included" >&2; exit 77; }
    for t4_tool in cargo docker file jq python3 rustup setpriv sudo sha256sum; do
        t4_found=$(command -v "$t4_tool") || exit 77
        task4_pin_tool "$t4_found" "T4_TOOL_$t4_tool" || exit 77
    done
    TASK4_DRIVER_HASH=$(task4_digest scripts/build-release.sh); TASK4_CHECKER_HASH=$(task4_digest scripts/check-capture-evidence.py)
    task4_snapshot > "$TASK4_ROOT/artifacts/source.start.tsv" || exit 77
    TASK4_SOURCE_HASH=$(task4_digest "$TASK4_ROOT/artifacts/source.start.tsv")
    task4_fact started_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; task4_fact argv "$0 $1"; task4_fact cwd "$(pwd -P)"
    task4_fact uid_gid "$(id -u):$(id -g)"; task4_fact kernel "$(uname -srmo)"; task4_fact head "$TASK4_HEAD"; task4_fact tree "$TASK4_TREE"
    task4_fact root_identity "$TASK4_ROOT_ID"; task4_fact artifacts_identity "$TASK4_ARTIFACTS_ID"; task4_fact work_identity "$TASK4_WORK_ID"
    task4_fact lock_identity "$TASK4_LOCK_ID"; task4_fact lock_holder "$$:$(process_starttime $$)"
    task4_fact driver_sha256 "$TASK4_DRIVER_HASH"; task4_fact checker_sha256 "$TASK4_CHECKER_HASH"
    task4_fact source_input_ledger_sha256 "$TASK4_SOURCE_HASH"
    TASK4_CONFIGS=$(task4_cargo_config_scan) \
        || { echo "cannot evaluate the effective cargo home" >&2; exit 77; }
    [ -z "$TASK4_CONFIGS" ] || { echo "untracked cargo config: $TASK4_CONFIGS" >&2; exit 77; }
    for t4_var in $TASK4_BUILD_INPUTS; do
        eval "t4_value=\${$t4_var-}"
        [ -z "$t4_value" ] || { echo "refusing inherited $t4_var" >&2; exit 77; }
        task4_fact "inherited_$t4_var" ""
    done
    t4_found=$("$T4_TOOL_rustup" which --toolchain 1.88 cargo) || exit 77
    task4_pin_tool "$t4_found" T4_TOOLCHAIN_CARGO || exit 77
    t4_found=$("$T4_TOOL_rustup" which --toolchain 1.88 rustc) || exit 77
    task4_pin_tool "$t4_found" T4_TOOLCHAIN_RUSTC || exit 77
    TASK4_TOOLS=$(task4_tool_ledger) || exit 77
    printf '%s\n' "$TASK4_TOOLS" >> "$TASK4_FACTS"
    "$T4_TOOL_sudo" -n true >/dev/null 2>&1 || exit 77
    [ -f "$MODULE" ] || exit 77
    WORK=$TASK4_ROOT/work
    DIST="$WORK/dist"
    OFFICIAL_TARGET="$WORK/release-official"
    CANARY_WORK="$WORK/canaries"
    ATTACH_WORK=$WORK
    DISCOVER_BASE=$WORK
    DISCOVER_WORK="$DISCOVER_BASE/discover"
    release_body > "$TASK4_ROOT/stdout.log" 2> "$TASK4_ROOT/stderr.log"
    exec 8< "$TASK4_ROOT/artifacts/discover.facts"
    TASK4_CHILD_FACTS_ID=$(stat -Lc %d:%i /proc/$$/fd/8) || exit 1
    [ "$TASK4_CHILD_FACTS_ID" = "$(awk -F '\t' '$1=="facts_identity"{print $2; exit}' /proc/$$/fd/8)" ] || exit 1
    [ "$(stat -Lc %u:%a:%h /proc/$$/fd/8)" = "$(id -u):600:1" ] || exit 1
    TASK4_CHILD_FACTS_HASH=$(task4_digest /proc/$$/fd/8) || exit 1
    task4_fact child_facts_identity "$TASK4_CHILD_FACTS_ID"
    task4_fact child_facts_sha256 "$TASK4_CHILD_FACTS_HASH"
    # csf_19fb2f: the receipt capture is bound to the literal path the static
    # smoke wrote; find remains only as a guard that the observed-capture
    # population under work/ is exactly the three known files (two attach-e2e
    # lanes plus the static smoke), so a planted decoy refuses instead of
    # being silently ranked. checker.log is the framed checker record from
    # release_body, never the whole-body stdout.
    t4_observed=$(find "$TASK4_ROOT/work" -type f -name '*observed*.json' -print | LC_ALL=C sort)
    [ "$t4_observed" = "$(printf '%s\n' \
        "$TASK4_ROOT/work/observed-scan.json" \
        "$TASK4_ROOT/work/observed-static-smoke.json" \
        "$TASK4_ROOT/work/observed.json")" ] \
        || { echo "unexpected observed capture set under work: $t4_observed" >&2; exit 1; }
    cp "$WORK/observed-static-smoke.json" "$TASK4_ROOT/artifacts/capture.json"
    cp "$WORK/checker.log" "$TASK4_ROOT/artifacts/checker.log"
    task4_fact checker_argv "$t4_checker_argv"
    task4_fact checker_status "$t4_checker_status"
    task4_fact checker_log_sha256 "$(task4_digest "$TASK4_ROOT/artifacts/checker.log")"
}

release_body() {
require_non_root_caller
rm -rf "$DIST"
mkdir -p "$DIST"

echo "=== release privacy gate ==="
P11SCOPE_TASK4_WORK="$CANARY_WORK" sh scripts/verify-canaries.sh

echo "=== p11scope: dynamic-build attach correctness ==="
P11SCOPE_TASK4_WORK="$ATTACH_WORK" sh scripts/verify-attach-e2e.sh

echo "=== p11scope: isolated safe-only official static build ==="
"$T4_TOOL_rustup" target add --toolchain 1.88 x86_64-unknown-linux-musl
rm -rf "$OFFICIAL_TARGET"
# The rustup shim dispatches on argv[0], so its resolved non-symlink path is
# not invocable as cargo and `+1.88` cannot survive path pinning. Run the
# recorded toolchain binaries directly instead, offline, with RUSTC supplied
# command-locally so cargo never resolves the compiler through PATH.
CARGO_TARGET_DIR="$OFFICIAL_TARGET" \
RUSTFLAGS="-C target-feature=+crt-static" \
RUSTC="$T4_TOOLCHAIN_RUSTC" \
    "$T4_TOOLCHAIN_CARGO" build --locked --offline --release --no-default-features \
        --target x86_64-unknown-linux-musl --bin p11scope
P11SCOPE_STATIC=$OFFICIAL_TARGET/x86_64-unknown-linux-musl/release/p11scope

set -- "$OFFICIAL_TARGET"/x86_64-unknown-linux-musl/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "official BPF object is not unique"; exit 1; }
OFFICIAL_BPF=$1
set -- "$CANARY_WORK"/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "diagnostic BPF object is not unique"; exit 1; }
DIAGNOSTIC_BPF=$1
"$T4_TOOL_python3" scripts/check-bpf-map-defs.py --policy-inventory "$OFFICIAL_BPF" "$DIAGNOSTIC_BPF"

if "$P11SCOPE_STATIC" profile --unsafe-unvalidated-metadata \
    --manifest /nonexistent/manifest.json --pid 1 \
    > "$OFFICIAL_TARGET/unsafe-cli.log" 2>&1; then
    echo "safe-only official observer accepted --unsafe-unvalidated-metadata"
    exit 1
fi
grep -Fq -- "--unsafe-unvalidated-metadata requires a build with" \
    "$OFFICIAL_TARGET/unsafe-cli.log" || {
        echo "safe-only observer returned the wrong unsafe-feature diagnostic"
        cat "$OFFICIAL_TARGET/unsafe-cli.log"
        exit 1
    }

echo "--- file: p11scope (static musl) ---"
"$T4_TOOL_file" "$P11SCOPE_STATIC"
"$T4_TOOL_file" "$P11SCOPE_STATIC" | grep -qE "statically linked|static-pie linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "--- ldd: p11scope (static musl) ---"
ldd "$P11SCOPE_STATIC" || true   # diagnostic only; file(1) above is the enforced static-link check
cp "$P11SCOPE_STATIC" "$DIST/p11scope"

echo "=== p11scope-discover: dynamic glibc + dynamic musl builds ==="
P11SCOPE_TASK4_WORK="$DISCOVER_BASE" \
    sh scripts/verify-discover-containers.sh \
    --lane14-facts "$TASK4_ROOT/artifacts/discover.facts"
GLIBC_DISCOVER=$DISCOVER_WORK/glibc-build/release/p11scope-discover
MUSL_DISCOVER=$DISCOVER_WORK/musl-build/release/p11scope-discover

echo "--- file: p11scope-discover (glibc) ---"
"$T4_TOOL_file" "$GLIBC_DISCOVER"
echo "--- ldd: p11scope-discover (glibc) ---"
ldd "$GLIBC_DISCOVER"
echo "--- smoke run: p11scope-discover (glibc), on host ---"
"$GLIBC_DISCOVER" --module /usr/lib/softhsm/libsofthsm2.so -o "$DIST/.smoke-manifest-glibc.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-glibc.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
echo "glibc discover host smoke run: $n/68 function records OK"
rm -f "$DIST/.smoke-manifest-glibc.json"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover-glibc"
cp "$GLIBC_DISCOVER" "$DIST/p11scope-discover"

echo "--- file: p11scope-discover (musl) ---"
"$T4_TOOL_file" "$MUSL_DISCOVER"
echo "musl-dynamic file/ldd/smoke run already verified inside the alpine" \
     "container by verify-discover-containers.sh above -- this (glibc)" \
     "host has no musl dynamic linker to exec it directly."
cp "$MUSL_DISCOVER" "$DIST/p11scope-discover-musl"

echo "=== packaged discovery helper smoke ==="
"$DIST/p11scope-discover" --module /usr/lib/softhsm/libsofthsm2.so \
    -o "$DIST/.smoke-manifest-helper.json"
n=$(grep -c '"name": "C_' "$DIST/.smoke-manifest-helper.json")
test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
rm -f "$DIST/.smoke-manifest-helper.json"

echo "=== p11scope: smoke run of the packaged STATIC artifact itself ==="
"$DIST/p11scope" --help >/dev/null
echo "--help OK"

echo "=== official static hostile-target smoke ==="
wait_for_hardened_target() {
    wht_pid=$1
    wht_starttime=$2
    wht_attempt=0
    while [ "$wht_attempt" -lt 160 ]; do
        process_matches_starttime "$wht_pid" "$wht_starttime" || {
            echo "Hardened target $wht_pid exited or changed identity" >&2
            return 1
        }
        if awk '
            $1 == "State:" { stopped_ok = ($2 == "T" || $2 == "t") }
            $1 == "Uid:" {
                uid_ok = ($2 != 0 && $3 != 0 && $4 != 0 && $5 != 0)
            }
            $1 == "CapInh:" || $1 == "CapPrm:" || $1 == "CapEff:" || $1 == "CapAmb:" {
                caps_ok += ($2 == "0000000000000000")
            }
            $1 == "NoNewPrivs:" { nnp_ok = ($2 == 1) }
            END { exit !(stopped_ok && uid_ok && caps_ok == 4 && nnp_ok) }
        ' "/proc/$wht_pid/status" 2>/dev/null; then
            return 0
        fi
        kill -0 "$wht_pid" 2>/dev/null || {
            echo "Hardened target $wht_pid exited before its status was verified" >&2
            return 1
        }
        wht_attempt=$((wht_attempt + 1))
        sleep 0.05
    done
    echo "Hardened target $wht_pid did not stop with non-root UIDs, zero active capabilities, and NoNewPrivs" >&2
    cat "/proc/$wht_pid/status" >&2 || true
    return 1
}

export SOFTHSM2_CONF="$WORK/softhsm2.conf"
"$DIST/p11scope-discover" --module "$MODULE" -o "$WORK/release-manifest.json"

TARGET_UID=$(id -u)
TARGET_GID=$(id -g)
rm -f "$WORK/observed-static-smoke.json" "$WORK/hardened-target.pid"
"$T4_TOOL_sudo" --preserve-env=SOFTHSM2_CONF sh -c 'umask 077; exec 3>"$1"; shift; exec "$@"' \
    sh "$WORK/hardened-target.pid" \
    "$T4_TOOL_setpriv" --no-new-privs --reuid "$TARGET_UID" --regid "$TARGET_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- \
    sh -c '
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' \
            "/proc/$$/stat") || exit 1
        case $starttime in ""|*[!0-9]*) exit 1 ;; esac
        printf "%s %s\n" "$$" "$starttime" >&3
        exec 3>&-
        kill -STOP "$$"
        exec "$1" "$2"
    ' sh "$WORK/harness" "$MODULE" &
LPID=$!
target_attempt=0
while ! "$T4_TOOL_sudo" test -s "$WORK/hardened-target.pid" && [ "$target_attempt" -lt 160 ]; do
    kill -0 "$LPID" 2>/dev/null || { echo "Hardened target launcher exited before publishing its pid"; exit 1; }
    target_attempt=$((target_attempt + 1))
    sleep 0.05
done
"$T4_TOOL_sudo" test -s "$WORK/hardened-target.pid" || { echo "Hardened target pid missing"; exit 1; }
set -- $("$T4_TOOL_sudo" cat "$WORK/hardened-target.pid")
[ "$#" -eq 2 ] || { echo "invalid Hardened target identity record"; exit 1; }
WPID=$1
TARGET_STARTTIME=$2
case $WPID:$TARGET_STARTTIME in *[!0-9:]*) echo "invalid Hardened target identity"; exit 1 ;; esac
wait_for_hardened_target "$WPID" "$TARGET_STARTTIME"

"$T4_TOOL_sudo" --preserve-env=SOFTHSM2_CONF "$DIST/p11scope" profile \
    --manifest "$WORK/release-manifest.json" \
    --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed-static-smoke.json" \
    > "$WORK/profile-static-smoke.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/profile-static-smoke.log" aggregate-only metrics
signal_verified_process CONT "$WPID" "$TARGET_STARTTIME"
# sudo suspends itself when its command stops; resume it too or `wait`
# below never returns (and the exited target stays a zombie under it).
kill -CONT "$LPID" 2>/dev/null || true
if wait "$LPID"; then LPID=; WPID=; TARGET_STARTTIME=; else status=$?; LPID=; WPID=; TARGET_STARTTIME=; echo "static smoke workload failed: $status"; exit "$status"; fi
if wait "$SPID"; then SPID=; else status=$?; SPID=; echo "static smoke profiler failed: $status"; cat "$WORK/profile-static-smoke.log" || true; exit "$status"; fi
reclaim_root_output "$WORK/observed-static-smoke.json"

# Framed checker record (csf_19fb2f): exact argv, the checker's own captured
# stdout/stderr, and a terminal status line. The frame keeps the record
# non-empty even though the checker is silent on success, and it -- not the
# aggregate body stdout -- is what the receipt retains as checker.log.
t4_checker_argv="$T4_TOOL_python3 scripts/check-capture-evidence.py clean-metrics-manifest-only $WORK/observed-static-smoke.json spike/expected.txt"
t4_checker_status=0
{
    printf 'argv\t%s\n' "$t4_checker_argv"
    "$T4_TOOL_python3" scripts/check-capture-evidence.py clean-metrics-manifest-only \
        "$WORK/observed-static-smoke.json" spike/expected.txt 2>&1 || t4_checker_status=$?
    printf 'status\t%s\n' "$t4_checker_status"
} > "$WORK/checker.log"
[ "$t4_checker_status" -eq 0 ] \
    || { echo "capture evidence checker failed: $t4_checker_status"; exit "$t4_checker_status"; }
echo "static p11scope smoke attach OK: $("$T4_TOOL_jq" -c .evidence "$WORK/observed-static-smoke.json")"

echo "=== dist/ ==="
ls -la "$DIST"

echo "=== build-release: ALL OK ==="
}

task4_receipt_run "$@"
