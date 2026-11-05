#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare native-owner proof evidence against snapshot rows.

Owners input: a directory with one file per owner child, each carrying
the pressure-live driver protocol lines (TARGET <json>, READY pid=N,
LEDGER <json> with schema p11scope/pressure-live-ledger/v1), plus an
optional newcomer.json ({admit_ns, first_settled_ns, bound_ns}) for the
separate newcomer cell. Snapshot input: one JSON document with callers[]
({id, pid}), instances[] ({id, caller, module, state, reason,
first_seen_ns, last_seen_ns}), modules[] ({id, key {device [major,
minor], inode, sha256}, lifecycle}), key_rows[] ({instance, started,
completed, failed, unknown}) and gaps[] ({subject, reason}), plus
optional budgets ({instances {limit, occupied, refused}}).

Verdicts, in order: every owner file parses (TARGET/READY/LEDGER join by
pid, every burst complete, at least one successful call); the population
counts exactly --owners (default 257) with distinct pids, both modes,
and targets spanning old and new providers; the newcomer settles within
its declared bound; every owner pid joins one caller, one retained
instance and the module its TARGET names (inode plus digest; each device
is compared only inside its own domain, since the TARGET device is
maps-domain and the module device is fstat-domain); every owner instance
carries a key row that never over-claims
its ledger and never ends more operations than it started; instances
outside the owner set carry no positive (the run excludes ambient
provider use); the association bound holds over observed rows.
Counter-only rows without a TARGET, path-keyed modules,
repeated owner pids and pid-mismatched joins are refused, never scored.
Refusal exits 1 with a numbers-only reason. Twins live in
tests/python/test_joint_owner_proof_oracle.py.
"""

import argparse
import json
import os
import re
import sys

MAX_OWNERS = 1024
MAX_OWNER_BYTES = 64 * 1024
MAX_LINE_BYTES = 4096
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
MAX_PID = (1 << 22) - 1
MAX_INSTANCES = 4096
EXPECTED_OWNERS = 257
LEDGER_SCHEMA = "p11scope/pressure-live-ledger/v1"
SURFACES = ("C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface")
READY_PATTERN = re.compile(r"READY pid=([0-9]{1,10})\Z")
REF_PATTERN = re.compile(r"[icm][0-9]{1,10}\Z")
SHA_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class LedgerError(ValueError):
    """The owners, snapshot or comparison is incomplete or inconsistent."""


def _require(condition, reason):
    if not condition:
        raise LedgerError(reason)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_WORD


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise LedgerError("nonfinite JSON number")


def _shown(value):
    """Render an untrusted value inside a refusal reason.

    Integers print verbatim (claim narrowing needs the measured numbers);
    anything else prints as its fixed JSON kind, never its content, so a
    refusal carries numbers only and never echoes owner payload.
    """
    if type(value) is int:
        return str(value)
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is float:
        return "non-integer number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    return "object"


def _parse_json(text, what):
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except json.JSONDecodeError as error:
        raise LedgerError(f"invalid {what} row") from error


def _read_owner_lines(path):
    try:
        size = os.path.getsize(path)
    except OSError as error:
        raise LedgerError("unreadable owner file") from error
    _require(size <= MAX_OWNER_BYTES, "owner file byte limit")
    try:
        with open(path, encoding="utf-8") as stream:
            lines = stream.readlines()
    except (OSError, UnicodeError) as error:
        raise LedgerError("unreadable owner file") from error
    for line in lines:
        _require(len(line.encode("utf-8")) <= MAX_LINE_BYTES,
                 "owner line byte limit")
    return lines


def _check_target(row):
    _require(type(row) is dict, "target row must be an object")
    _require(set(row) == {"name", "dev", "ino", "file_offset"} or
             set(row) == {"name", "dev", "ino", "file_offset", "sha256"},
             "target without identity fields")
    _require(type(row["name"]) is str and 1 <= len(row["name"]) <= 128,
             "target name invalid")
    _require(type(row["dev"]) is list and len(row["dev"]) == 2 and
             all(_integer(part) for part in row["dev"]),
             "target device invalid")
    _require(_integer(row["ino"], minimum=1), "target inode invalid")
    _require(_integer(row["file_offset"]), "target file offset invalid")
    digest = row.get("sha256")
    if digest is not None:
        _require(type(digest) is str and SHA_PATTERN.match(digest),
                 "target sha256 invalid")
    return (tuple(row["dev"]), row["ino"], digest)


def _check_ledger(row):
    _require(type(row) is dict, "ledger row must be an object")
    _require(set(row) == {"schema", "pid", "mode", "burst", "complete",
                          "functions"},
             "ledger without count fields")
    _require(row["schema"] == LEDGER_SCHEMA,
             f"ledger schema {_shown(row['schema'])} mismatch")
    _require(_integer(row["pid"], minimum=1) and row["pid"] <= MAX_PID,
             "ledger pid out of range")
    _require(row["mode"] in ("retain", "late"), "ledger mode invalid")
    _require(_integer(row["burst"], minimum=1), "ledger burst out of range")
    _require(type(row["complete"]) is bool, "ledger complete invalid")
    functions = row["functions"]
    _require(type(functions) is list and 1 <= len(functions) <= 3,
             "ledger functions invalid")
    seen = set()
    for entry in functions:
        _require(type(entry) is dict, "ledger function must be an object")
        _require(set(entry) == {"name", "attempts", "successful"},
                 "ledger function without counts")
        _require(entry["name"] in SURFACES, "ledger function name invalid")
        _require(entry["name"] not in seen, "duplicate ledger function")
        seen.add(entry["name"])
        _require(_integer(entry["attempts"]), "ledger attempts out of range")
        _require(_integer(entry["successful"]) and
                 entry["successful"] <= entry["attempts"],
                 "ledger successful out of range")
    return row


def read_owner(path):
    """Parse one owner child stdout file into its proof summary."""
    targets = []
    pids = []
    ledgers = []
    for line in _read_owner_lines(path):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("TARGET "):
            targets.append(_check_target(_parse_json(stripped[7:], "target")))
        elif stripped.startswith("LEDGER "):
            ledgers.append(_check_ledger(_parse_json(stripped[7:], "ledger")))
        elif stripped.startswith("READY "):
            match = READY_PATTERN.match(stripped)
            _require(match is not None, "owner READY line invalid")
            pid = int(match.group(1))
            _require(1 <= pid <= MAX_PID, "owner READY pid out of range")
            pids.append(pid)
        else:
            raise LedgerError("unexpected owner line")
    _require(targets, "owner without a physical target")
    _require(len(set(targets)) == 1, "owner targets disagree")
    _require(pids, "owner without READY")
    _require(len(set(pids)) == 1, "owner READY pids disagree")
    _require(ledgers, "owner without a ledger row")
    pid = pids[0]
    for row in ledgers:
        _require(row["pid"] == pid, "owner pid join refused")
        _require(row["complete"], "owner without a complete burst")
    modes = {row["mode"] for row in ledgers}
    _require(len(modes) == 1, "mixed owner modes")
    attempts = sum(entry["attempts"] for row in ledgers
                   for entry in row["functions"])
    successful = sum(entry["successful"] for row in ledgers
                     for entry in row["functions"])
    _require(successful >= 1, "owner without a completed call")
    dev, ino, digest = targets[0]
    return {"pid": pid, "mode": next(iter(modes)), "target": (dev, ino),
            "target_sha": digest, "attempts": attempts,
            "successful": successful}


def read_owners(directory):
    """Parse every owner file in a directory; return owners + newcomer."""
    try:
        entries = sorted(os.listdir(directory))
    except OSError as error:
        raise LedgerError("unreadable owners directory") from error
    owners = []
    newcomer = None
    for name in entries:
        if name.startswith("."):
            continue
        path = os.path.join(directory, name)
        _require(not os.path.islink(path),
                 "owner entry must be a regular file")
        _require(os.path.isfile(path), "owner entry must be a regular file")
        if name == "newcomer.json":
            newcomer = _read_newcomer(path)
            continue
        owners.append(read_owner(path))
    _require(len(owners) <= MAX_OWNERS, "owner count limit")
    return {"owners": owners, "newcomer": newcomer}


def _read_newcomer(path):
    try:
        with open(path, encoding="utf-8") as stream:
            text = stream.read(MAX_LINE_BYTES + 1)
    except (OSError, UnicodeError) as error:
        raise LedgerError("unreadable newcomer file") from error
    _require(len(text.encode("utf-8")) <= MAX_LINE_BYTES,
             "newcomer file byte limit")
    row = _parse_json(text, "newcomer")
    _require(type(row) is dict, "newcomer row must be an object")
    _require(set(row) == {"admit_ns", "first_settled_ns", "bound_ns"},
             "newcomer without bound fields")
    for key in ("admit_ns", "first_settled_ns", "bound_ns"):
        _require(_integer(row[key]), f"newcomer {key} out of range")
    _require(row["bound_ns"] >= 1, "newcomer bound out of range")
    _require(row["admit_ns"] <= row["first_settled_ns"],
             "newcomer admission follows its first settlement")
    _require(row["first_settled_ns"] - row["admit_ns"] <= row["bound_ns"],
             f"newcomer settles {_shown(row['first_settled_ns'] - row['admit_ns'])} "
             f"past its bound {_shown(row['bound_ns'])}")
    return row


def read_snapshot(stream):
    """Read and shape-check one snapshot JSON document."""
    try:
        text = stream.read(MAX_SNAPSHOT_BYTES + 1)
    except UnicodeError as error:
        raise LedgerError("invalid snapshot encoding") from error
    _require(type(text) is str, "snapshot must be text")
    _require(len(text.encode("utf-8")) <= MAX_SNAPSHOT_BYTES,
             "snapshot byte limit")
    try:
        snapshot = json.loads(text, object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
    except json.JSONDecodeError as error:
        raise LedgerError("invalid snapshot row") from error
    _require(type(snapshot) is dict, "snapshot must be an object")
    for key in ("callers", "instances", "modules", "key_rows", "gaps"):
        _require(key in snapshot, f"snapshot without {key}")
        _require(type(snapshot[key]) is list, f"snapshot {key} must be a list")
    for row in snapshot["callers"]:
        _require(type(row) is dict, "caller row must be an object")
        for key in ("id", "pid"):
            _require(key in row, f"caller without {key}")
        _require(type(row["id"]) is str and REF_PATTERN.match(row["id"]),
                 "caller id invalid")
        _require(_integer(row["pid"], minimum=1) and row["pid"] <= MAX_PID,
                 "caller pid out of range")
    identifiers = [row["id"] for row in snapshot["callers"]]
    _require(len(set(identifiers)) == len(identifiers), "duplicate caller id")
    pids = [row["pid"] for row in snapshot["callers"]]
    _require(len(set(pids)) == len(pids), "duplicate caller pid")
    for row in snapshot["instances"]:
        _require(type(row) is dict, "instance row must be an object")
        for key in ("id", "caller", "module", "state", "reason",
                    "first_seen_ns", "last_seen_ns"):
            _require(key in row, f"instance without {key}")
        _require(type(row["id"]) is str and REF_PATTERN.match(row["id"]),
                 "instance id invalid")
        _require(type(row["caller"]) is str and REF_PATTERN.match(row["caller"]),
                 "instance caller invalid")
        _require(type(row["module"]) is str and REF_PATTERN.match(row["module"]),
                 "instance module invalid")
        _require(row["state"] in ("observed", "uncertain", "retired"),
                 "instance state invalid")
        _require(row["reason"] is None or (
            type(row["reason"]) is str and TOKEN_PATTERN.match(row["reason"])),
            "instance reason invalid")
        _require(_integer(row["first_seen_ns"]), "instance first_seen invalid")
        _require(_integer(row["last_seen_ns"]), "instance last_seen invalid")
        _require(row["first_seen_ns"] <= row["last_seen_ns"],
                 "instance last_seen precedes first_seen")
    identifiers = [row["id"] for row in snapshot["instances"]]
    _require(len(set(identifiers)) == len(identifiers), "duplicate instance id")
    for row in snapshot["modules"]:
        _require(type(row) is dict, "module row must be an object")
        for key in ("id", "key", "lifecycle"):
            _require(key in row, f"module without {key}")
        _require(type(row["id"]) is str and REF_PATTERN.match(row["id"]),
                 "module id invalid")
        key = row["key"]
        _require(type(key) is dict, "module without identity key")
        for name in ("device", "inode", "sha256"):
            _require(name in key, f"module key without {name}")
        _require(type(key["device"]) is list and len(key["device"]) == 2 and
                 all(_integer(part) for part in key["device"]),
                 "module device invalid")
        _require(_integer(key["inode"], minimum=1), "module inode invalid")
        _require(type(key["sha256"]) is str and SHA_PATTERN.match(key["sha256"]),
                 "module sha256 invalid")
        _require(row["lifecycle"] in ("mapped", "unloaded", "unknown"),
                 "module lifecycle invalid")
    identifiers = [row["id"] for row in snapshot["modules"]]
    _require(len(set(identifiers)) == len(identifiers), "duplicate module id")
    seen_keys = set()
    for row in snapshot["modules"]:
        key = row["key"]
        digest = (tuple(key["device"]), key["inode"], key["sha256"])
        _require(digest not in seen_keys, "duplicate module key")
        seen_keys.add(digest)
    for row in snapshot["key_rows"]:
        _require(type(row) is dict, "key row must be an object")
        for key in ("instance", "started", "completed", "failed", "unknown"):
            _require(key in row, f"key row without {key}")
        _require(type(row["instance"]) is str and
                 REF_PATTERN.match(row["instance"]), "key row instance invalid")
        for key in ("started", "completed", "failed", "unknown"):
            _require(_integer(row[key]), f"key row {key} out of range")
    identifiers = [row["instance"] for row in snapshot["key_rows"]]
    _require(len(set(identifiers)) == len(identifiers),
             "duplicate key row instance")
    for row in snapshot["gaps"]:
        _require(type(row) is dict, "gap row must be an object")
        for key in ("subject", "reason"):
            _require(key in row, f"gap without {key}")
            _require(type(row[key]) is str and 1 <= len(row[key]) <= 256,
                     f"gap {key} invalid")
    budgets = snapshot.get("budgets")
    if budgets is not None:
        _require(type(budgets) is dict, "snapshot budgets must be an object")
        held = budgets.get("instances")
        _require(type(held) is dict, "budgets without instances")
        for key in ("limit", "occupied", "refused"):
            _require(key in held, f"instance budget without {key}")
            _require(_integer(held[key]), f"instance budget {key} invalid")
        _require(held["limit"] >= 1, "instance budget limit invalid")
    return snapshot


def check_associations(snapshot):
    """Enforce the retained-instance bound over observed rows."""
    instances = snapshot["instances"]
    observed = [row for row in instances if row["state"] == "observed"]
    ordered = sorted(observed,
                     key=lambda row: (row["first_seen_ns"], row["id"]))
    _require(len(ordered) <= MAX_INSTANCES,
             f"association bound exceeded: {len(ordered)} observed past "
             f"{MAX_INSTANCES}")
    pairs = set()
    for row in ordered:
        pair = (row["caller"], row["module"])
        _require(pair not in pairs,
                 f"duplicate observed association {pair[0]} {pair[1]}")
        pairs.add(pair)
    budgets = snapshot.get("budgets")
    if budgets is not None:
        held = budgets["instances"]
        _require(held["occupied"] == min(len(instances), held["limit"]),
                 f"budget occupied {held['occupied']} disagrees with "
                 f"{len(instances)} instance rows")
        if len(instances) > held["limit"]:
            _require(held["refused"] >= len(instances) - held["limit"],
                     "budget refused undercounts overflow rows")
        else:
            _require(held["refused"] == 0,
                     f"budget refused {held['refused']} without overflow")
    return {"associations": len(ordered), "rows": len(instances)}


def compare(population, snapshot, expect=EXPECTED_OWNERS):
    """Compare owner proofs against snapshot rows; return the verdict.

    The population must come from read_owners and the snapshot from
    read_snapshot; pids print verbatim because the readers already bound
    their range.
    """
    owners = population["owners"]
    _require(len(owners) == expect,
             f"expected {expect} owners, found {len(owners)}")
    pids = [owner["pid"] for owner in owners]
    seen = set()
    repeated = None
    for pid in pids:
        if pid in seen:
            repeated = pid
            break
        seen.add(pid)
    _require(repeated is None, f"repeated owner pid {repeated}")
    modes = {owner["mode"] for owner in owners}
    _require("retain" in modes, "population without a retain owner")
    _require("late" in modes, "population without a late owner")
    targets = {owner["target"] for owner in owners}
    _require(len(targets) >= 2,
             "old and new providers not both retained")
    associations = check_associations(snapshot)
    callers = {row["id"]: row for row in snapshot["callers"]}
    caller_of_pid = {row["pid"]: row["id"] for row in snapshot["callers"]}
    instances = {row["id"]: row for row in snapshot["instances"]}
    modules = {row["id"]: row for row in snapshot["modules"]}
    key_rows = {row["instance"]: row for row in snapshot["key_rows"]}
    for row in snapshot["instances"]:
        _require(row["caller"] in callers,
                 f"instance {row['id']} names missing caller "
                 f"{_shown(row['caller'])}")
        _require(row["module"] in modules,
                 f"instance {row['id']} names missing module "
                 f"{_shown(row['module'])}")
    for row in snapshot["key_rows"]:
        _require(row["instance"] in instances,
                 f"key row names missing instance {_shown(row['instance'])}")
    referenced = {row["module"] for row in snapshot["instances"]}
    for module_id in modules:
        _require(module_id in referenced,
                 f"module {module_id} without an instance row")
    owner_callers = set()
    for owner in owners:
        _require(owner["pid"] in caller_of_pid,
                 f"owner pid {owner['pid']} without a caller row")
        caller = caller_of_pid[owner["pid"]]
        owner_callers.add(caller)
        rows = [row for row in snapshot["instances"]
                if row["caller"] == caller]
        _require(len(rows) == 1,
                 f"caller {caller} without exactly one instance")
        instance = rows[0]
        _require(instance["state"] == "observed",
                 f"owner pid {owner['pid']} not retained")
        module = modules[instance["module"]]
        key = module["key"]
        # The TARGET device lives in the /proc-maps domain while the module
        # device lives in the fstat domain (they differ on btrfs), so the
        # join compares the inode plus the digest and never the devices.
        _require(key["inode"] == owner["target"][1],
                 f"owner pid {owner['pid']} target disagrees with its module")
        if owner["target_sha"] is not None:
            _require(owner["target_sha"] == key["sha256"],
                     f"owner pid {owner['pid']} target digest disagrees "
                     "with its module")
        key_row = key_rows.get(instance["id"])
        _require(key_row is not None,
                 f"observed instance {instance['id']} without a key row")
        _require(key_row["completed"] <= key_row["started"],
                 f"owner pid {owner['pid']} completes without starting")
        _require(key_row["failed"] <= key_row["started"],
                 f"owner pid {owner['pid']} fails without starting")
        _require(key_row["started"] <= owner["attempts"],
                 f"owner pid {owner['pid']} over-claims started calls")
        _require(key_row["completed"] <= owner["successful"],
                 f"owner pid {owner['pid']} over-claims completed calls")
        _require(key_row["failed"] <= owner["attempts"] - owner["successful"],
                 f"owner pid {owner['pid']} over-claims failed calls")
    for row in snapshot["instances"]:
        if row["caller"] in owner_callers:
            continue
        key_row = key_rows.get(row["id"])
        if key_row is None:
            continue
        _require(key_row["started"] == 0 and key_row["completed"] == 0 and
                 key_row["failed"] == 0 and key_row["unknown"] == 0,
                 f"ambient instance {row['id']} claims a positive")
    return {"owners": len(owners), "modes": sorted(modes),
            "modules": len(modules),
            "newcomer": population["newcomer"] is not None,
            "associations": associations["associations"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("owners_dir", help="directory with one file per owner")
    parser.add_argument("snapshot", help="snapshot JSON document file")
    parser.add_argument("--owners", dest="expect", type=int,
                        default=EXPECTED_OWNERS,
                        help="expected owner file count (default 257)")
    args = parser.parse_args(argv)
    try:
        _require(_integer(args.expect, minimum=1), "expected owners invalid")
        population = read_owners(args.owners_dir)
        with open(args.snapshot, encoding="utf-8") as stream:
            snapshot = read_snapshot(stream)
        result = compare(population, snapshot, expect=args.expect)
    except LedgerError as error:
        print(f"comparison refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("comparison refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
