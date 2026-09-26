#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the seven owned T7 static cells from immutable, prebuilt host pins.

This is a private mechanism campaign, not public-product qualification.
No builds, retries, host-object deletion, or implicit privilege escalation
approval are performed. Authorization for owned live work must already exist.
"""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

PREFIX = "attach::inventory::activation::privileged_tests::"
CELLS = [
    ("default", "inventory_n576_lp64", 576),
    ("default", "inventory_n1024_lp64", 1024),
    ("default", "inventory_n4097_lp64", 4097),
    ("default", "inventory_n6530_lp64", 6530),
    ("default", "inventory_n8192_boundary_lp64", 8192),
    ("default", "detailed_hot_slot_third_rv_lp64", None),
    ("wide", "detailed_hot_slot_third_rv_lp64", None),
]
# These cooperative leases are shared with the current workspace owners.
# Holding the Cargo lease also prevents a cooperating heavy build during BPF.
LOCKS = [
    "/var/tmp/p11scope-ws-tmp/cargo-heavy.lock",
    "/tmp/p11scope-slice1b2-spike-vm.lock",
    "/var/tmp/p11scope-ws-tmp/full-system-live.lock",
    "/home/user/src/m/kryprobe-ws/.artifacts/locks/bpf-lane.lock",
    "/home/user/src/m/kryprobe-ws/.artifacts/locks/k5-bpf-lane.lock",
    "/tmp/kryprobe-bpf-lane.lock",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def parse_census(kind, payload):
    require(kind in {"map", "prog", "link"}, "unknown BPF object kind")
    records = json.loads(payload)
    require(isinstance(records, list), "enumeration was not an array")
    result = []
    for row in records:
        require(isinstance(row, dict), "enumeration row was not an object")
        identifier = row.get("id")
        require(type(identifier) is int and identifier > 0, "invalid BPF object id")
        result.append((kind, identifier))
    require(len(result) == len(set(result)), "duplicate BPF object id")
    return sorted(result)


def take_census(directory, tag, run=subprocess.run):
    objects = []
    for kind in ("map", "prog", "link"):
        result = run(["sudo", "-n", "bpftool", "-j", kind, "show"],
                     capture_output=True, text=True, timeout=30, check=False)
        (directory / f"{tag}-{kind}.stdout").write_text(result.stdout)
        (directory / f"{tag}-{kind}.stderr").write_text(result.stderr)
        require(result.returncode == 0, f"{kind} enumeration failed: {result.returncode}")
        objects.extend(parse_census(kind, result.stdout))
    objects.sort()
    write_json(directory / f"{tag}.json", objects)
    return objects


def validate_selector(selector, output):
    bodies = [line for line in output.splitlines() if line.endswith(": test")]
    require(bodies == [selector + ": test"], "selector must name exactly one test body")
    require("1 test, 0 benchmarks" in output.splitlines(), "selector inventory is incomplete")


def validate_test_exit(exit_code, log):
    require(exit_code == 0, f"test exit {exit_code}")
    require(re.findall(r"^running (\d+) tests?$", log, re.M) == ["1"],
            "exactly one executed test is required")
    results = re.findall(r"^test result: (.+)$", log, re.M)
    require(len(results) == 1 and results[0].startswith(
        "ok. 1 passed; 0 failed; 0 ignored; 0 measured; "), "test body did not pass")


def validate_inventory_phases(rows, n):
    snapshots = [row for row in rows if row.get("kind") == "usage_phase"]
    require([row.get("phase") for row in snapshots] ==
            ["pre_go", "after_go", "after_repeat", "terminal"], "missing/duplicate Inventory phase")
    for row in snapshots:
        phase = row["phase"]
        require(row.get("cells_read") == n and row.get("positive_count") ==
                (0 if phase == "pre_go" else n), "Inventory denominator mismatch")
        require(row.get("newly_positive") == (list(range(n)) if phase == "after_go" else []),
                "Inventory physical ID set mismatch")
        require(row.get("usage_integrity_failures") == row.get("usage_read_failures") == 0,
                "Inventory map-read failure")
    terminal = [row for row in rows if row.get("kind") == "terminal"]
    require(len(terminal) == 1 and terminal[0].get("phase") == "terminal"
            and terminal[0].get("usage_positive") == n, "missing/duplicate Inventory terminal")


def verify_pins(pins, root):
    require(pins.get("schema") == "p11scope/t7-static-pins/v1", "wrong pins schema")
    require(re.fullmatch(r"[0-9a-f]{40}", pins.get("source_revision", "")), "missing source revision")
    require(re.fullmatch(r"[0-9a-f]{40}", pins.get("source_tree", "")), "missing source tree")
    required = {"driver", "oracle", "cargo_lock", "default.binary", "wide.binary",
                "default.inventory", "default.detailed", "wide.inventory", "wide.detailed"}
    require(required <= pins["artifacts"].keys(), "incomplete artifact pins")
    paths = {}
    for name, record in pins["artifacts"].items():
        path = (root / record["path"]).resolve()
        require(path.is_relative_to(root.resolve()), "artifact escaped pin directory")
        require(sha256(path) == record["sha256"], f"artifact hash mismatch: {name}")
        paths[name] = path
    for profile in ["default", "wide"]:
        executable = paths[f"{profile}.binary"].read_bytes()
        for kind in ["inventory", "detailed"]:
            require(paths[f"{profile}.{kind}"].read_bytes() in executable,
                    f"{profile} binary does not embed its pinned {kind} object")
    require(sha256(Path(__file__)) == pins["artifacts"]["driver"]["sha256"], "running driver differs")
    require(os.uname().release == pins["kernel_release"], "kernel changed after pinning")
    require(sha256(Path("/sys/kernel/btf/vmlinux")) == pins["kernel_btf_sha256"], "kernel BTF changed")
    return paths


def verify_cell_evidence(directory, index, profile, n, log, pins):
    if n == 8192:
        require("T7_ENVELOPE_REFUSAL cell=inventory-t7-n8192-boundary n=8192 phase=preflight" in log
                and "RLIMIT_NOFILE soft=8192" in log, "boundary did not prove expected FD refusal")
        require("TASK4_RAW_SUMMARY" not in log, "refusal mislabeled as capture")
        return "expected-refusal"
    profile_name = "default" if profile == "default" else "wide-detailed-2112"
    require(f"TASK4_PROFILE name={profile_name} " in log, "executed profile differs from pin")
    require("OWNED_RELEASED OwnedIds" in log, "owned kernel IDs lack a release receipt")
    if n is None:
        require("T7_HOT_RV hot_slot=0 rvs=0,5,7 old_cells=1..8 exact=true" in log,
                "hot-RV evidence missing")
        return "capture"
    manifest = json.loads((directory / f"case-{index:02}-evidence.json").read_text())
    require(manifest.get("case") == "inventory" and manifest.get("case_index") == index
            and manifest.get("outcome") == "complete" and manifest["replay"]["ok"] is True,
            "Inventory replay did not complete")
    require(manifest["object_sha256"] == pins["artifacts"][f"{profile}.inventory"]["sha256"],
            "loaded Inventory object differs from pin")
    for role, expected in (("fixture", manifest["fixture_sha256"]),
                           ("offsets", manifest["offsets_sha256"])):
        suffix = "elf" if role == "fixture" else "json"
        require(sha256(directory / f"{role}-{index:02}.{suffix}") == expected, f"{role} hash mismatch")
    for record in manifest["files"].values():
        path = (directory / record["name"]).resolve()
        require(path.parent == directory.resolve(), "evidence path escaped its cell")
        require(sha256(path) == record["sha256"] and path.stat().st_size == record["bytes"],
                "evidence hash/length mismatch")
        if path.suffix == ".jsonl":
            payload = path.read_bytes()
            require(payload.endswith(b"\n") and len(payload.splitlines()) == record["rows"],
                    "incomplete evidence rows")
    raw = [json.loads(line) for line in (directory / f"case-{index:02}-raw.jsonl").read_text().splitlines()]
    require(len(raw) == 5 * n + 5, "raw phase schedule is incomplete")
    validate_inventory_phases(raw, n)
    require("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true" in log,
            "Inventory final cleanup marker missing")
    return "capture"


def run_campaign(pins_path, output):
    pins = json.loads(pins_path.read_text())
    paths = verify_pins(pins, pins_path.parent)
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": "p11scope/t7-static-campaign/v1", "pins_sha256": sha256(pins_path),
                "source_revision": pins["source_revision"], "evidence_level": "live-mechanism",
                "limitation": "private static mechanism; no public/growth/performance claim",
                "cells": [{"id": f"T7.{profile}.{slug}", "outcome": "NOT_RUN"}
                          for profile, slug, _ in CELLS]}
    manifest_path = output / "manifest.json"
    write_json(manifest_path, manifest)
    with ExitStack() as stack:
        for lock in LOCKS:
            stream = stack.enter_context(open(lock, "a"))
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_json(output / "ownership.json", {"controller_pid": os.getpid(), "uid": os.getuid(),
                   "locks": LOCKS, "acquired_unix_ns": time.time_ns()})
        try:
            for index, (profile, slug, n) in enumerate(CELLS):
                paths = verify_pins(pins, pins_path.parent)
                cell = manifest["cells"][index]
                selector = PREFIX + "privileged_t7_" + slug
                directory = output / f"{index:02}-{profile}-{slug}"
                directory.mkdir()
                evidence = directory / "evidence"
                evidence.mkdir()
                binary = str(paths[f"{profile}.binary"])
                listed = subprocess.run([binary, "--list", "--exact", selector, "--ignored"],
                                        capture_output=True, text=True, check=True, timeout=30)
                (directory / "tests.list").write_text(listed.stdout)
                validate_selector(selector, listed.stdout)
                before = take_census(directory, "before")
                command = ["/usr/bin/time", "-v", "sudo", "-n", "timeout", "--signal=TERM",
                           "--kill-after=10s", "1800s", "env", "TMPDIR=/var/tmp/p11scope-ws-tmp",
                           f"P11SCOPE_TASK4_EVIDENCE_DIR={evidence}", f"P11SCOPE_TASK4_CASE_INDEX={index}",
                           "bash", "-c", 'set -e\nulimit -n 8192\nexec "$@"', "t7-owned-cell",
                           binary, "--exact", selector, "--ignored", "--test-threads=1", "--nocapture"]
                cell.update({"selector": selector, "command": command, "outcome": "NOT_RUN",
                             "started_unix_ns": time.time_ns(), "profile": profile})
                write_json(directory / "command.json", cell)
                write_json(manifest_path, manifest)
                print(f"START {cell['id']}", flush=True)
                start = time.monotonic()
                with (directory / "test.log").open("x") as log_stream:
                    result = subprocess.run(command, stdout=log_stream, stderr=subprocess.STDOUT,
                                            check=False, timeout=1830)
                cell.update({"exit_code": result.returncode, "elapsed_s": time.monotonic() - start})
                after = take_census(directory, "after")
                cell["new_objects"] = sorted(set(after) - set(before))
                cell["missing_baseline_objects"] = sorted(set(before) - set(after))
                require(not cell["new_objects"] and not cell["missing_baseline_objects"],
                        "kernel census changed; preserve lane evidence and investigate ownership")
                require(result.returncode not in {124, 137, -9, -15},
                        "cell exceeded its deadline or was killed; reconcile owned processes before continuing")
                verify_pins(pins, pins_path.parent)
                try:
                    log = (directory / "test.log").read_text()
                    validate_test_exit(result.returncode, log)
                    cell["behavior"] = verify_cell_evidence(evidence, index, profile, n, log, pins)
                    cell["outcome"] = "PASS"
                except (ValueError, OSError, KeyError) as error:
                    cell.update({"outcome": "FAIL", "error": str(error)})
                cell["artifact_hashes"] = {
                    str(path.relative_to(output)): sha256(path)
                    for path in sorted(directory.rglob("*")) if path.is_file()}
                write_json(directory / "result.json", cell)
                write_json(manifest_path, manifest)
                print(f"END {cell['id']} {cell['outcome']} {cell['elapsed_s']:.2f}s", flush=True)
        except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
            manifest["error"] = str(error)
            cell = next((row for row in manifest["cells"] if row["outcome"] == "NOT_RUN"), None)
            if cell is not None:
                cell.update({"outcome": "INVALID", "error": str(error)})
            write_json(manifest_path, manifest)
            raise
    return 0 if all(cell["outcome"] == "PASS" for cell in manifest["cells"]) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        return run_campaign(arguments.pins.resolve(), arguments.output.resolve())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"T7 campaign refused/failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
