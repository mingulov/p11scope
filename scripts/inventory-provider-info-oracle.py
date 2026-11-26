#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge provider-info inventory evidence against the fixture ledger.

Cell `inventory-provider-info-pid` runs one single-process workload
(`tests/fixtures/public-cli/provider_info.c`) under `inventory --pid
--capture native --provider-info`. The workload primes binder
association with counted C_GetSlotList calls until the second gate,
then makes exactly one observed call per info query (C_GetInfo, one
C_GetSlotList, per slot one C_GetTokenInfo plus, on token slots, one
C_GetMechanismList and one C_GetMechanismInfo per listed mechanism)
and ledgers the returned facts. This checker asserts:

- the snapshot inventories the owned provider (admitted) and the one
  workload caller, with no gaps about the owned module;
- the owned module's `provider_info` record equals the fixture's
  C_GetInfo exactly (manufacturer, description, versions, flags);
- the `provider_observations` token rows are exactly the ledger's
  token slots (same slots, same manufacturer/model/versions/flags/PIN
  lengths, completions 1, changes 0) and the mechanism rows are
  exactly the ledger's (slot, mechanism) facts (same keys, same
  sizes/flags, completions 1, changes 0), with no observation gaps;
- the workload edge carries `counted` non-lossy coverage whose count
  equals the priming plus sweep call total exactly, and the
  `--event-log` stream ends cleanly with the same total;
- no `serial` or `label` key appears anywhere in the report.

Counts are entry-side attach totals; error-returning calls count.
"""

import argparse
import json
from pathlib import Path
import re
import stat
import sys

INFO_NAMES = (
    "C_GetInfo",
    "C_GetSlotList",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
)
CELL = "inventory-provider-info-pid"
LEDGER_SCHEMA = "p11scope/provider-info-ledger/v1"
FORBIDDEN_KEY_SUBSTRINGS = ("serial", "label")

# Exact row key sets from the frozen consumer contract
# (docs/schema/inventory-v1-object-observations-v8.schema.json,
# additionalProperties false) and docs/schema/inventory-v1.md. Any
# key outside base + approved-optionals is refused before value
# comparisons, so privacy-excluded bytes (serial, label, session
# counts, memory sizes, clock readings, PINs, values, argv, env)
# and any unrelated extra key fail here even when no value check
# names them. The report-wide serial/label scan stays as a second
# layer, never as the schema check.
PROVIDER_INFO_KEYS = frozenset(
    (
        "cryptoki_major",
        "cryptoki_minor",
        "manufacturer",
        "description",
        "flags",
        "library_major",
        "library_minor",
    )
)
PROVIDER_INFO_OPTIONAL = frozenset(("manufacturer_reason", "description_reason"))
TOKEN_ROW_KEYS = frozenset(
    (
        "module",
        "caller",
        "slot",
        "manufacturer",
        "model",
        "hardware_major",
        "hardware_minor",
        "firmware_major",
        "firmware_minor",
        "flags",
        "pin_min_len",
        "pin_max_len",
        "completions",
        "changes",
    )
)
TOKEN_ROW_OPTIONAL = frozenset(("instance", "manufacturer_reason", "model_reason"))
MECHANISM_ROW_KEYS = frozenset(
    (
        "module",
        "caller",
        "slot",
        "mechanism",
        "min_key_size",
        "max_key_size",
        "flags",
        "completions",
        "changes",
    )
)
MECHANISM_ROW_OPTIONAL = frozenset(("instance",))


def check_row_keys(kind, row, required, optional):
    unknown = sorted(set(row) - required - optional)
    require(not unknown, "%s carries unknown keys: %r" % (kind, unknown))
    missing = sorted(required - set(row))
    require(not missing, "%s misses required keys: %r" % (kind, missing))


class EvidenceError(Exception):
    pass


def require(condition, detail):
    if not condition:
        raise EvidenceError(detail)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    require(stat.S_ISREG(path.stat().st_mode), "evidence must be a regular file")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence exceeds size limit")
    return path.read_text(encoding="utf-8")


def identity(value):
    require(isinstance(value, dict), "missing physical identity")
    dev = value.get("dev")
    require(
        isinstance(dev, list) and len(dev) == 2 and all(integer(x) for x in dev),
        "invalid device identity",
    )
    require(integer(value.get("ino")) and value["ino"] > 0, "invalid inode identity")
    require(
        isinstance(value.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
        "missing provider hash",
    )
    return (*dev, value["ino"], value["sha256"])


def check_receipt(receipt, cell):
    require(
        receipt.get("schema") == "p11scope/public-cli-receipt/v1"
        and receipt.get("cell") == cell,
        "receipt schema or cell mismatch",
    )
    require(receipt.get("scope") == "pid", "receipt scope differs from declared cell")
    require(
        receipt.get("count_domain") == "owned-provider",
        "count domain is not owned-provider",
    )
    for key in ("workload_ready", "capture_ready", "ledger_complete"):
        require(receipt.get(key) is True, "missing " + key)
    require(receipt.get("gate_released") is True, "gate was not safely released")
    for key in ("observer_exit", "workload_exit"):
        require(
            type(receipt.get(key)) is int and receipt[key] == 0,
            "nonzero or missing " + key,
        )
    generation = receipt.get("generation")
    if generation is not None:
        require(
            integer(generation)
            and generation > 0
            and type(receipt.get("ready_generation")) is int
            and receipt["ready_generation"] == generation,
            "workload generation changed",
        )
    before = identity(receipt.get("provider_before"))
    after = identity(receipt.get("provider_after"))
    require(before == after, "provider physical identity or hash changed")
    return before


def check_info_record(info):
    require(isinstance(info, dict), "missing ledger C_GetInfo record")
    for key in ("cryptoki_major", "cryptoki_minor", "library_major", "library_minor"):
        value = info.get(key)
        require(type(value) is int and 0 <= value <= 255, "invalid ledger " + key)
    for key in ("manufacturer", "description"):
        value = info.get(key)
        require(
            isinstance(value, str) and value and len(value) <= 32,
            "invalid ledger " + key,
        )
    require(integer(info.get("flags")), "invalid ledger info flags")
    return info


def check_slots(slots):
    require(isinstance(slots, list) and slots, "ledger carries no slots")
    seen = set()
    token_slots = {}
    mech_facts = {}
    for entry in slots:
        require(isinstance(entry, dict), "ledger slot is not an object")
        slot = entry.get("slot")
        require(integer(slot), "invalid ledger slot id")
        require(slot not in seen, "duplicate ledger slot %r" % (slot,))
        seen.add(slot)
        token = entry.get("token")
        require(token is True or token is False, "invalid ledger token presence")
        mechanisms = entry.get("mechanisms")
        require(isinstance(mechanisms, list), "missing ledger mechanism list")
        if token:
            for key in ("manufacturer", "model"):
                value = entry.get(key)
                require(
                    isinstance(value, str) and value and len(value) <= 32,
                    "invalid ledger token " + key,
                )
            for key in (
                "hardware_major",
                "hardware_minor",
                "firmware_major",
                "firmware_minor",
            ):
                value = entry.get(key)
                require(
                    type(value) is int and 0 <= value <= 255,
                    "invalid ledger token " + key,
                )
            require(integer(entry.get("flags")), "invalid ledger token flags")
            require(integer(entry.get("pin_min_len")), "invalid ledger pin_min_len")
            require(integer(entry.get("pin_max_len")), "invalid ledger pin_max_len")
            token_slots[slot] = entry
        else:
            require(mechanisms == [], "tokenless ledger slot carries mechanisms")
        seen_mechs = set()
        for mech in mechanisms:
            require(isinstance(mech, dict), "ledger mechanism is not an object")
            mid = mech.get("id")
            require(integer(mid), "invalid ledger mechanism id")
            require(mid not in seen_mechs, "duplicate ledger mechanism %r" % (mid,))
            seen_mechs.add(mid)
            for key in ("min_key_size", "max_key_size", "flags"):
                require(integer(mech.get(key)), "invalid ledger mechanism " + key)
            mech_facts[(slot, mid)] = mech
    require(token_slots, "ledger carries no token rows: vacuous")
    require(mech_facts, "ledger carries no mechanism rows: vacuous")
    return token_slots, mech_facts


def check_ledger(text, receipt, cell):
    targets, ledgers, ready, children, primes = [], [], [], [], []
    for line in text.splitlines():
        if line.startswith("TARGET "):
            require(
                not ready and not ledgers,
                "fixture target emitted after readiness or ledger",
            )
            targets.append(parse(line[7:]))
        elif line.startswith("LEDGER "):
            require(len(ready) == 1, "fixture ledger emitted before workload READY")
            ledgers.append(parse(line[7:]))
        elif line.startswith("PRIME "):
            match = re.fullmatch(r"PRIME calls=([0-9]+)", line)
            require(match is not None, "invalid workload PRIME line")
            require(
                len(ready) == 1 and not ledgers,
                "fixture PRIME outside the priming window",
            )
            primes.append(int(match[1]))
        elif line.startswith("READY "):
            match = re.fullmatch(r"READY pid=([0-9]+)", line)
            require(match is not None, "invalid workload READY")
            ready.append(int(match[1]))
        elif line.startswith("CHILD "):
            match = re.fullmatch(r"CHILD pid=([0-9]+)", line)
            require(match is not None, "invalid workload CHILD")
            children.append(int(match[1]))
    pid = receipt.get("launched_pid")
    require(
        integer(pid) and pid > 0 and ready == [pid] and receipt.get("ready_pid") == pid,
        "workload READY does not match launched PID",
    )
    require(len(ledgers) == 1, "missing or duplicate complete LEDGER")
    ledger = ledgers[0]
    require(
        ledger.get("schema") == LEDGER_SCHEMA
        and ledger.get("pid") == pid
        and ledger.get("complete") is True,
        "invalid or incomplete fixture ledger",
    )
    require(not children, "single-process workload reported children")
    require(len(primes) == 1, "missing or duplicate PRIME line")
    prime = primes[0]
    info = check_info_record(ledger.get("info"))
    token_slots, mech_facts = check_slots(ledger.get("slots"))
    dev_ino = set()
    for row in targets:
        name = row.get("name")
        require(name in INFO_NAMES, "unexpected fixture target")
        require(
            row.get("dev") == list(identity(receipt["provider_before"])[:2])
            and row.get("ino") == identity(receipt["provider_before"])[2],
            "mapped fixture target differs from independently hashed provider",
        )
        dev_ino.add((tuple(row["dev"]), row["ino"]))
    require(len(dev_ino) == 1, "fixture targets span providers")
    require(
        sorted(row.get("name") for row in targets) == sorted(INFO_NAMES),
        "fixture targets are not exactly the info functions",
    )
    # Post-gate through-table calls: the PRIME priming calls plus the
    # sweep (C_GetInfo + C_GetSlotList, per slot C_GetTokenInfo, per
    # token slot C_GetMechanismList, per mechanism C_GetMechanismInfo).
    # C_Initialize runs pre-gate (unobserved) and the workload holds
    # instead of finalizing.
    slots = ledger.get("slots")
    total = prime + 2 + len(slots)
    for entry in slots:
        if entry.get("token") is True:
            total += 1 + len(entry.get("mechanisms"))
    return info, token_slots, mech_facts, pid, total, len(slots)


def snapshot_owned(report, provider, pid):
    require(
        report.get("schema") == "p11scope/inventory/v1", "unsupported inventory schema"
    )
    require(
        report.get("scope") == "pid:%d" % pid,
        "report scope differs from declared workload pid",
    )
    modules = {
        row["id"]: row
        for row in report.get("modules", [])
        if isinstance(row, dict) and "id" in row
    }
    owned = None
    for mid, module in modules.items():
        ident = module.get("identity", {})
        dev = ident.get("device", {})
        if (
            [dev.get("major"), dev.get("minor")] == list(provider[:2])
            and ident.get("inode") == provider[2]
            and ident.get("sha256") == provider[3]
        ):
            require(owned is None, "duplicate owned provider module")
            owned = mid
    require(owned is not None, "owned provider not inventoried")
    require(
        modules[owned].get("admission", {}).get("state") == "admitted",
        "owned provider not admitted",
    )
    callers = {
        row["id"]: row
        for row in report.get("callers", [])
        if isinstance(row, dict) and "id" in row
    }
    hits = [cid for cid, row in callers.items() if row.get("pid") == pid]
    require(
        len(hits) == 1, "workload pid %d is not exactly one caller: %r" % (pid, hits)
    )
    for row in report.get("gaps", []):
        require(
            not (isinstance(row, dict) and row.get("module") == owned),
            "inventory gap about owned module: %r" % (row,),
        )
    return modules[owned], owned, hits[0]


def check_provider_info(module, info):
    record = module.get("provider_info")
    require(isinstance(record, dict), "owned module carries no provider_info")
    check_row_keys("provider_info", record, PROVIDER_INFO_KEYS, PROVIDER_INFO_OPTIONAL)
    for key in ("cryptoki_major", "cryptoki_minor", "library_major", "library_minor"):
        require(
            record.get(key) == info[key],
            "provider_info %s %r differs from the fixture C_GetInfo %r"
            % (key, record.get(key), info[key]),
        )
    for key in ("manufacturer", "description"):
        require(
            record.get(key) == info[key],
            "provider_info %s %r differs from the fixture C_GetInfo %r"
            % (key, record.get(key), info[key]),
        )
        require(
            key + "_reason" not in record,
            "provider_info %s refused although the fixture read clean bytes" % key,
        )
    require(
        record.get("flags") == info["flags"],
        "provider_info flags %r differs from the fixture C_GetInfo %r"
        % (record.get("flags"), info["flags"]),
    )


def check_observations(report, owned, caller, token_slots, mech_facts):
    observations = report.get("provider_observations")
    require(isinstance(observations, dict), "report carries no provider_observations")
    require(
        observations.get("version") == 8,
        "provider_observations is not section version 8",
    )
    tokens = observations.get("tokens")
    require(isinstance(tokens, list), "provider_observations carries no token rows")
    seen_tokens = {}
    for row in tokens:
        require(isinstance(row, dict), "token row is not an object")
        check_row_keys("token row", row, TOKEN_ROW_KEYS, TOKEN_ROW_OPTIONAL)
        require(row.get("module") == owned, "token row on another module: %r" % (row,))
        require(row.get("caller") == caller, "token row on another caller: %r" % (row,))
        slot = row.get("slot")
        require(integer(slot), "invalid token row slot")
        require(slot not in seen_tokens, "duplicate token row for slot %r" % (slot,))
        seen_tokens[slot] = row
    require(
        set(seen_tokens) == set(token_slots),
        "token row slots %r differ from the ledger token slots %r"
        % (sorted(seen_tokens), sorted(token_slots)),
    )
    for slot, want in token_slots.items():
        row = seen_tokens[slot]
        for key in ("manufacturer", "model"):
            require(
                row.get(key) == want[key],
                "token row slot %r %s %r differs from the ledger %r"
                % (slot, key, row.get(key), want[key]),
            )
            require(
                key + "_reason" not in row,
                "token row slot %r %s refused although the fixture read clean bytes"
                % (slot, key),
            )
        for key in (
            "hardware_major",
            "hardware_minor",
            "firmware_major",
            "firmware_minor",
            "flags",
            "pin_min_len",
            "pin_max_len",
        ):
            require(
                row.get(key) == want[key],
                "token row slot %r %s %r differs from the ledger %r"
                % (slot, key, row.get(key), want[key]),
            )
        require(
            row.get("completions") == 1,
            "token row slot %r completions %r, want exactly 1"
            % (slot, row.get("completions")),
        )
        require(
            row.get("changes") == 0,
            "token row slot %r changes %r, want 0" % (slot, row.get("changes")),
        )
    mechanisms = observations.get("mechanisms")
    require(
        isinstance(mechanisms, list), "provider_observations carries no mechanism rows"
    )
    seen_mechs = {}
    for row in mechanisms:
        require(isinstance(row, dict), "mechanism row is not an object")
        check_row_keys("mechanism row", row, MECHANISM_ROW_KEYS, MECHANISM_ROW_OPTIONAL)
        require(
            row.get("module") == owned, "mechanism row on another module: %r" % (row,)
        )
        require(
            row.get("caller") == caller, "mechanism row on another caller: %r" % (row,)
        )
        slot, mid = row.get("slot"), row.get("mechanism")
        require(integer(slot) and integer(mid), "invalid mechanism row key")
        require(
            (slot, mid) not in seen_mechs,
            "duplicate mechanism row for %r" % ((slot, mid),),
        )
        seen_mechs[(slot, mid)] = row
    require(
        set(seen_mechs) == set(mech_facts),
        "mechanism row keys differ from the ledger: extra %r missing %r"
        % (
            sorted(set(seen_mechs) - set(mech_facts)),
            sorted(set(mech_facts) - set(seen_mechs)),
        ),
    )
    for key, want in mech_facts.items():
        row = seen_mechs[key]
        for field in ("min_key_size", "max_key_size", "flags"):
            require(
                row.get(field) == want[field],
                "mechanism row %r %s %r differs from the ledger %r"
                % (key, field, row.get(field), want[field]),
            )
        require(
            row.get("completions") == 1,
            "mechanism row %r completions %r, want exactly 1"
            % (key, row.get("completions")),
        )
        require(
            row.get("changes") == 0,
            "mechanism row %r changes %r, want 0" % (key, row.get("changes")),
        )
    gaps = observations.get("gaps")
    require(gaps == [], "provider_observations carries gaps: %r" % (gaps,))


def check_no_excluded_keys(node, path="$"):
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = key.lower()
            for forbidden in FORBIDDEN_KEY_SUBSTRINGS:
                require(forbidden not in lowered, "excluded key %r at %s" % (key, path))
            check_no_excluded_keys(value, path + "." + key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            check_no_excluded_keys(value, "%s[%d]" % (path, index))


def check_edge_and_stream(report, event_text, owned, caller, total):
    edges = [
        row
        for row in report.get("edges", [])
        if isinstance(row, dict)
        and row.get("module") == owned
        and row.get("caller") == caller
    ]
    require(
        len(edges) == 1,
        "workload edge to owned module is not exactly one: %d" % len(edges),
    )
    entries = edges[0].get("entries", {})
    require(
        entries.get("observation") == "observed",
        "workload edge is not observed: %r" % (entries.get("observation"),),
    )
    count = entries.get("count")
    require(integer(count), "workload edge lacks an exact count")
    coverage = entries.get("coverage", {})
    require(
        coverage.get("state") == "counted",
        "workload edge is not counted: %r" % (coverage.get("state"),),
    )
    require(coverage.get("lossy") is False, "workload edge is lossy")
    require(
        count == total,
        "edge usage %d differs from the independent ledger total %d" % (count, total),
    )
    last = None
    ended = False
    unretained_keys = (
        "instances_unretained",
        "semantic_edges_unretained",
        "key_operations_unretained",
        "edges_unretained",
    )
    for line in event_text.splitlines():
        if not line.strip():
            continue
        record = parse(line)
        kind = record.get("kind")
        if kind == "edge_observed":
            row = record.get("event", record.get("row", {}))
            if (
                isinstance(row, dict)
                and row.get("caller") == caller
                and row.get("module") == owned
            ):
                last = row
        elif kind == "ended":
            ended = True
            event = record.get("event", {})
            for key in unretained_keys:
                if key in event:
                    require(
                        event[key] == 0,
                        "stream deleted retained rows: %s=%r" % (key, event[key]),
                    )
    require(ended, "event stream was cut short (no ended marker)")
    require(last is not None, "event stream misses the workload edge")
    stream_count = last.get("entries", {}).get("count")
    require(
        integer(stream_count) and stream_count == count,
        "streamed edge total differs from the snapshot row",
    )


def judge(report_text, ledger_text, receipt, event_text, cell):
    require(cell == CELL, "undeclared cell")
    provider = check_receipt(receipt, cell)
    info, token_slots, mech_facts, pid, total, nslots = check_ledger(
        ledger_text, receipt, cell
    )
    report = parse(report_text)
    module, owned, caller = snapshot_owned(report, provider, pid)
    check_provider_info(module, info)
    check_observations(report, owned, caller, token_slots, mech_facts)
    check_no_excluded_keys(report)
    check_edge_and_stream(report, event_text, owned, caller, total)
    # The typed proof record is what the workflow checker decides
    # over; the detail sentence carries the same numbers for human
    # readers only and is never parsed.
    proof = {
        "manufacturer": info["manufacturer"],
        "library_major": info["library_major"],
        "library_minor": info["library_minor"],
        "token_rows": len(token_slots),
        "mechanism_rows": len(mech_facts),
        "slots": nslots,
    }
    return (
        "provider-info-exact",
        "provider %s library %d.%d: %d token rows and %d mechanism rows "
        "match the ledger over %d slots; serial/label absent"
        % (
            info["manufacturer"],
            info["library_major"],
            info["library_minor"],
            len(token_slots),
            len(mech_facts),
            nslots,
        ),
        proof,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("report", "ledger", "receipt", "cell", "event-log"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args(argv)
    result = {"cell": args.cell, "pass": False, "detail": "", "qualification": "failed"}
    try:
        qualification, detail, proof = judge(
            read(Path(args.report)),
            read(Path(args.ledger)),
            parse(read(Path(args.receipt))),
            read(Path(getattr(args, "event_log"))),
            args.cell,
        )
        result.update(
            {"pass": True, "qualification": qualification, "detail": detail, "proof": proof}
        )
        code = 0
    except (
        EvidenceError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        AssertionError,
    ) as error:
        result["detail"] = str(error)
        code = 1
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
