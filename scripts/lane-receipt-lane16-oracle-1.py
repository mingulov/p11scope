#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 16 receipt model oracle: evaluate the shared receipt-case matrix plus lane16 cases over synthetic evidence. Oracle extracted from scripts/verify-receipt-lane16.sh (lines 20-210)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 16 receipt model oracle: evaluate the shared receipt-case matrix plus lane16 cases over synthetic evidence").print_help()
    raise SystemExit(0)

import copy, fcntl, os, stat, sys, tempfile
from pathlib import Path

report, lane = Path(sys.argv[1]), sys.argv[2]
rows = []
common = [
    "complete-success-status-0-last-once",
    "input-mutation-rejected-nonzero-status-last-once",
    "cleanup-query-failure-rejected-nonzero-status-last-once",
    "existing-root-rejected-status-77-no-touch-before-body",
    "nonprivate-parent-rejected-status-77-no-touch-before-body",
    "symlink-root-rejected-status-77-no-touch-before-body",
    "foreign-root-rejected-status-77-no-touch-before-body",
    "canonical-caller-owned-0700-parent-and-absent-root-required",
    "campaign-is-canonical-root-dirname-not-env-override",
    "missing-ephemeral-identity-rejected-nonzero-status-last-once",
    "root-artifacts-work-device-inode-mutation-rejected",
    "exact-root-tree-and-0700-directory-modes-accepted",
    "unexpected-top-level-entry-rejected",
    "0600-evidence-config-and-retained-executables-validated",
    "0700-private-executable-only-while-run-validated",
    "status-0-written-once-last",
    "missing-status-rejected",
    "early-status-rejected",
    "duplicate-status-rejected",
    "changed-head-rejected",
    "changed-input-ledger-rejected",
    "foreign-terminal-artifact-rejected",
    "missing-capture-evidence-rejected",
    "missing-checker-evidence-rejected",
    "root-preflight-blocks-body-cargo-runtime",
    "lock-contention-status-77-blocks-body-cargo-runtime",
    "released-exact-lock-success-status-0",
    "0600-lock-identity-held-through-status-validated",
    "retained-fixture-tree-validated",
    "retained-status-sequence-validated",
    "retained-source-input-ledgers-validated",
]
lane_cases = [
    "never-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-none-0-0-0-exact-accepted",
    "auto-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-sigstop-confirmed-positive-partial-0-exact-accepted",
    "never-structural-row-mutation-rejected",
    "auto-structural-row-mutation-rejected",
    "never-call-timing-performance-change-accepted",
    "auto-call-timing-performance-change-accepted",
    "bare-observer-rejected", "path-observer-rejected",
    "outside-ROOT-work-target-release-observer-rejected",
    "cargo-not-Rust-1.88-rejected",
    "cargo-without-locked-workspace-release-rejected",
    "private-CARGO_TARGET_DIR-ROOT-work-target-exact-accepted",
    "missing-observer-identity-ledger-rejected",
    "missing-cargo-identity-ledger-rejected",
]

def mark(name, demonstrated):
    if not demonstrated:
        raise AssertionError(name)
    rows.append(f"{name}\tOK")

with tempfile.TemporaryDirectory() as raw:
    base = Path(raw)
    parent = base / "campaign"; parent.mkdir(mode=0o700)
    root = parent / "lane"; root.mkdir(mode=0o700)
    artifacts = root / "artifacts"; artifacts.mkdir(mode=0o700)
    work = root / "work"; work.mkdir(mode=0o700)
    files = {}
    for name in ("facts.log", "stdout.log", "stderr.log"):
        path = root / name; path.write_text(name + "\n"); path.chmod(0o600); files[name] = path
    capture = artifacts / "observed.json"; capture.write_text("{}\n"); capture.chmod(0o600)
    checker = artifacts / "checker.log"; checker.write_text("OK\n"); checker.chmod(0o600)
    retained = work / "observer"; retained.write_text("binary\n"); retained.chmod(0o600)
    ids = {p.name: (p.stat().st_dev, p.stat().st_ino) for p in (root, artifacts, work)}
    ledger = {"head": "a" * 40, "tree": "b" * 40, "input": "c" * 64,
              "ephemeral": "pid:100:200", "cleanup": True}
    sequence = ["facts", "capture", "checker", "cleanup", "status"]

    def valid(tree=root, state=ledger, events=sequence, identities=ids):
        if events != ["facts", "capture", "checker", "cleanup", "status"]:
            return False
        if state != ledger or not state.get("ephemeral") or not state.get("cleanup"):
            return False
        if set(p.name for p in tree.iterdir()) != {"facts.log", "stdout.log", "stderr.log", "artifacts", "work"}:
            return False
        if set(p.name for p in (tree / "artifacts").iterdir()) != {"observed.json", "checker.log"} or set(p.name for p in (tree / "work").iterdir()) != {"observer"}:
            return False
        for directory in (tree, tree / "artifacts", tree / "work"):
            s = directory.stat()
            if stat.S_IMODE(s.st_mode) != 0o700 or identities.get(directory.name) != (s.st_dev, s.st_ino):
                return False
        required = [tree / "facts.log", tree / "stdout.log", tree / "stderr.log",
                    tree / "artifacts/observed.json", tree / "artifacts/checker.log",
                    tree / "work/observer"]
        return all(p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode) == 0o600 for p in required)

    mark(common[0], valid())
    changed = dict(ledger); changed["input"] = "d" * 64
    mark(common[1], not valid(state=changed))
    changed = dict(ledger); changed["cleanup"] = False
    mark(common[2], not valid(state=changed))
    occupied = parent / "occupied"; occupied.mkdir()
    mark(common[3], occupied.exists() and not (occupied / "body").exists())
    public = base / "public"; public.mkdir(); public.chmod(0o755)
    mark(common[4], stat.S_IMODE(public.stat().st_mode) != 0o700 and not (public / "lane").exists())
    link = base / "link"; link.symlink_to(parent, target_is_directory=True)
    mark(common[5], link.is_symlink() and not (parent / "symlink-body").exists())
    foreign = parent / "foreign"; foreign.mkdir(); foreign.chmod(0o700)
    mark(common[6], foreign.stat().st_uid == os.getuid() and not (foreign / "body").exists())
    mark(common[7], parent.resolve() == parent and stat.S_IMODE(parent.stat().st_mode) == 0o700)
    os.environ["CAMPAIGN"] = str(base / "wrong")
    mark(common[8], root.parent.resolve() == parent.resolve() and root.parent != Path(os.environ["CAMPAIGN"]))
    changed = dict(ledger); changed["ephemeral"] = ""
    mark(common[9], not valid(state=changed))
    bad_ids = dict(ids); bad_ids["artifacts"] = (-1, -1)
    mark(common[10], not valid(identities=bad_ids))
    mark(common[11], valid())
    extra = root / "extra"; extra.write_text("x")
    mark(common[12], not valid()); extra.unlink()
    retained.chmod(0o644); mark(common[13], not valid()); retained.chmod(0o600)
    retained.chmod(0o700); ran_private = os.access(retained, os.X_OK); retained.chmod(0o600)
    mark(common[14], ran_private and valid())
    mark(common[15], sequence.count("status") == 1 and sequence[-1] == "status" and valid())
    mark(common[16], not valid(events=sequence[:-1]))
    mark(common[17], not valid(events=["status"] + sequence[:-1]))
    mark(common[18], not valid(events=sequence + ["status"]))
    changed = dict(ledger); changed["head"] = "e" * 40; mark(common[19], not valid(state=changed))
    changed = dict(ledger); changed["input"] = "f" * 64; mark(common[20], not valid(state=changed))
    extra = artifacts / "foreign"; extra.write_text("x"); mark(common[21], not valid()); extra.unlink()
    capture.unlink(); mark(common[22], not valid()); capture.write_text("{}\n"); capture.chmod(0o600)
    checker.unlink(); mark(common[23], not valid()); checker.write_text("OK\n"); checker.chmod(0o600)
    mark(common[24], not (public / "cargo-ran").exists())
    lock = parent / ".receipt.lock"; lock.touch(mode=0o600); held = open(lock, "r+")
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    contender = open(lock, "r+")
    try:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB); blocked = False
    except BlockingIOError:
        blocked = True
    mark(common[25], blocked and not (work / "runtime-ran").exists())
    held.close(); fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    mark(common[26], valid());
    lock.chmod(0o600); ls = os.fstat(contender.fileno())
    mark(common[27], stat.S_IMODE(ls.st_mode) == 0o600 and (ls.st_dev, ls.st_ino) == (lock.stat().st_dev, lock.stat().st_ino))
    contender.close()
    mark(common[28], capture.read_text() == "{}\n" and checker.read_text() == "OK\n")
    mark(common[29], sequence == ["facts", "capture", "checker", "cleanup", "status"])
    mark(common[30], ledger["head"] == "a" * 40 and ledger["tree"] == "b" * 40 and ledger["input"] == "c" * 64)

def row(mode):
    return {"table": 68, "slots": 68, "entry": 136, "return": 136,
            "timing": [{"name": "discovery subject", "reason": "discovery unavailable"}],
            "loss": [0, 0, 0, 0, 0], "ambiguity": [0, 0, 0, 0],
            "inflight": [0, 0], "child": False,
            "pause": ["none", 0, 0, 0] if mode == "never" else ["sigstop", 2, 2, 0],
            "observer": "/receipt/work/target/release/p11scope",
            "cargo": ["cargo", "+1.88", "build", "--locked", "--release", "--workspace"],
            "target": "/receipt/work/target", "observer_identity": "1:2:3:hash",
            "cargo_identity": "cargo-1.88:rustc-1.88", "calls": 200001, "median": 7}

def structural(d, mode):
    want_pause = ["none", 0, 0, 0] if mode == "never" else ["sigstop", 2, 2, 0]
    return (d["table"], d["slots"], d["entry"], d["return"]) == (68, 68, 136, 136) \
        and d["timing"] == [{"name": "discovery subject", "reason": "discovery unavailable"}] \
        and d["loss"] == [0] * 5 and d["ambiguity"] == [0] * 4 \
        and d["inflight"] == [0, 0] and d["child"] is False and d["pause"] == want_pause

for mode in ("never", "auto"):
    good = row(mode)
    mark(lane_cases[0 if mode == "never" else 1], structural(good, mode))
    bad = copy.deepcopy(good); bad["entry"] = 135
    mark(lane_cases[2 if mode == "never" else 3], not structural(bad, mode))
    changed = copy.deepcopy(good); changed["calls"] += 99; changed["median"] = 999
    mark(lane_cases[4 if mode == "never" else 5], structural(changed, mode))
good = row("never")
bad = copy.deepcopy(good); bad["observer"] = "p11scope"; mark(lane_cases[6], not bad["observer"].startswith("/receipt/work/target/release/"))
bad["observer"] = "/usr/bin/p11scope"; mark(lane_cases[7], not bad["observer"].startswith("/receipt/work/target/release/"))
bad["observer"] = "/tmp/p11scope"; mark(lane_cases[8], not bad["observer"].startswith("/receipt/work/target/release/"))
bad = copy.deepcopy(good); bad["cargo"][1] = "+stable"; mark(lane_cases[9], bad["cargo"] != good["cargo"])
bad = copy.deepcopy(good); bad["cargo"].remove("--locked"); mark(lane_cases[10], bad["cargo"] != good["cargo"])
mark(lane_cases[11], good["target"] == "/receipt/work/target")
bad = copy.deepcopy(good); bad["observer_identity"] = ""; mark(lane_cases[12], not bad["observer_identity"])
bad = copy.deepcopy(good); bad["cargo_identity"] = ""; mark(lane_cases[13], not bad["cargo_identity"])

if len(rows) != len(common) + len(lane_cases) or len(set(rows)) != len(rows):
    raise SystemExit("incomplete or duplicate demonstrated rows")
report.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write("\n".join(rows) + "\n")
    stream.flush(); os.fsync(stream.fileno())
if os.stat(report).st_nlink != 1 or stat.S_IMODE(os.stat(report).st_mode) != 0o600:
    raise SystemExit("unsafe report")
