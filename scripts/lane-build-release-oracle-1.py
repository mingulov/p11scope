#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Release Task 4 receipt model oracle: evaluate the shared receipt-case matrix plus release-lane cases over synthetic evidence. Oracle extracted from scripts/build-release.sh (lines 34-264)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Release Task 4 receipt model oracle: evaluate the shared receipt-case matrix plus release-lane cases over synthetic evidence").print_help()
    raise SystemExit(0)

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
    lock=parent/".receipt.lock";lock.touch(mode=0o600);a=open(lock,"r+");b=open(lock,"r+");fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
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
aggregate-stdout-as-checker-evidence-rejected
sealed-command-inventory-pinned-before-root-and-git-decisions
sealed-environment-allowlist-exact-accepted
forged-seal-marker-rejected
inventory-wide-tool-ledger-exact-accepted
sealed-bin-removed-before-terminal-status
nightly-toolchain-closure-exact-accepted
isolated-python-invocations-exact-accepted
tab-or-newline-root-rejected-status-77""".splitlines()

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
                         "CARGO_HOME","RUSTUP_HOME","RUSTUP_TOOLCHAIN","RUSTC_WRAPPER","CC","CFLAGS",
                         "P11SCOPE_PRODUCT_BUILD_MODE","P11SCOPE_PREPARED_STABLE_CARGO",
                         "P11SCOPE_PREPARED_STABLE_RUSTC","P11SCOPE_PREPARED_BPF_CARGO",
                         "P11SCOPE_PREPARED_BPF_RUSTC"),"")
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
framed="argv\tpython3 -I scripts/check-capture-evidence.py clean-metrics-manifest-only observed-static-smoke.json spike/expected.txt\nstatus\t0"
aggregate="=== release privacy gate ===\n=== build-release: ALL OK ==="
def checker_evidence_framed(text):
    lines=text.splitlines()
    return (len(lines)>=2 and lines[0].startswith("argv\t") and "check-capture-evidence.py" in lines[0]
            and lines[-1].startswith("status\t") and lines[-1].split("\t",1)[1].isdigit())
mark(lane[23],checker_evidence_framed(framed) and not checker_evidence_framed(aggregate))
# csf_014eb65 / shadow findings 3+6: the receipt chain runs sealed. The ten
# inherited build inputs are refused by name first, then the whole reached
# command inventory is pinned and re-exec'd under an exact environment
# allowlist -- all before any root, git, tool, or body decision.
seal_steps=["refuse-inherited-build-inputs","pin-reached-command-inventory","seal","verify-seal",
            "prepare-root","git-head","pin-tools","tool-ledger","body"]
def seal_before(a,b): return seal_steps.index(a)<seal_steps.index(b)
mark(lane[24],all(seal_before("refuse-inherited-build-inputs",step) for step in ("seal","prepare-root","git-head"))
     and all(seal_before("seal",step) for step in ("verify-seal","prepare-root","git-head","pin-tools","body")))
sealed_environment={"HOME","LC_ALL","OLDPWD","P11SCOPE_RECEIPT_CALLER_ARGV0","P11SCOPE_RECEIPT_CALLER_PATH",
                    "P11SCOPE_RECEIPT_SEALED","P11SCOPE_RECEIPT_SEALED_BIN","PATH","PWD","TMPDIR"}
steering={"RUSTC_WORKSPACE_WRAPPER","P11SCOPE_SMALL_RING","PYTHONPATH","PYTHONHOME","GIT_DIR",
          "GIT_WORK_TREE","GIT_INDEX_FILE","GIT_CONFIG_GLOBAL","DOCKER_HOST","LANG"}
def seal_accepts(names): return names==sealed_environment
mark(lane[25],seal_accepts(set(sealed_environment)) and not seal_accepts(sealed_environment|steering)
     and not sealed_environment&steering)
mark(lane[26],not seal_accepts({"P11SCOPE_RECEIPT_SEALED"}|steering)
     and "prepare-root" not in seal_steps[:seal_steps.index("verify-seal")])
reached={"git","awk","sort","xargs","realpath","find","cp","sh","stat","id","mkdir","flock","cmp",
         "chmod","date","sync","rm","grep","ldd","cat","ls","cc","gcc","env","ln","mktemp"}
floor={"cargo","docker","file","jq","python3","rustup","setpriv","sudo","sha256sum"}
mark(lane[27],not reached<=floor and bool(reached-floor) and reached<=reached|floor)
finalization=["body","evidence-checks","sync-staged-status","remove-sealed-bin","terminal-status"]
mark(lane[28],finalization.index("sync-staged-status")<finalization.index("remove-sealed-bin")
     <finalization.index("terminal-status") and finalization[-1]=="terminal-status")
# The shipped observer embeds an eBPF object built by a second toolchain, so
# the recorded release pair (`.release-rust-version`) is not the effective build closure on its own.
stable_closure={"toolchain_cargo","toolchain_rustc"}
nightly_closure={"toolchain_nightly_cargo","toolchain_nightly_rustc","toolchain_nightly_sysroot",
                 "toolchain_nightly_rust_src","toolchain_bpf_linker"}
def closure_bound(rows): return stable_closure|nightly_closure<=rows
mark(lane[29],closure_bound(stable_closure|nightly_closure) and not closure_bound(stable_closure)
     and not closure_bound((stable_closure|nightly_closure)-{"toolchain_nightly_rust_src"}))
# `sitecustomize`/PYTHONHOME run before the first line of a checker. The seal
# drops those variables and `-I` refuses them again for any invocation that
# ever runs outside it, so both the isolation flag and the framed argv that
# names it have to be present at every python3 call site.
python_sites=["self-test-model","finalizer-heredoc","check-bpf-map-defs","check-capture-evidence"]
def isolated(flagged): return set(flagged)==set(python_sites)
mark(lane[30],isolated(python_sites) and not isolated(python_sites[:-1])
     and framed.startswith("argv\tpython3 -I "))
root_with_controls = "/tmp/evidence\troot"
root_with_newline = "/tmp/evidence\nroot"
mark(lane[31], "\t" in root_with_controls and "\n" in root_with_newline)

if len(rows)!=len(common)+len(lane) or len(rows)!=len(set(rows)): raise SystemExit("row coverage")
report.parent.mkdir(parents=True,exist_ok=True);fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"w") as out: out.write("\n".join(rows)+"\n");out.flush();os.fsync(out.fileno())
if os.stat(report).st_nlink!=1 or stat.S_IMODE(os.stat(report).st_mode)!=0o600: raise SystemExit("unsafe report")
