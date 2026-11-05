#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure offline controls for retained System sibling admission and exact deltas."""

import copy
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = runpy.run_path(str(ROOT / "tests/python/test_automatic_exec_oracle.py"))
H6 = BASE["H6"]
START, STOP = BASE["START"], BASE["STOP"]


def sibling_inputs(no_calls=True):
    doc, _, receipt = BASE["inventory_inputs"]()
    provider = {**BASE["PIN"], "path": "/w/libA.so", "mapping": {"dev": [8, 1], "ino": 111}}
    image = {"image": 0, "pid": 2000, "start_time": 8888, "path": "/w/ledger",
             "dev": 37, "ino": 301, "mtime_ns": 22, "pid_namespace": 1, "time_namespace": 2}
    context = {"id": "c2", "pid": 2000, "start_time": 8888, "incarnation": 0,
               "authority": "scan_pinned", "lifecycle": "mapped", "status": "observed",
               "executable": {"path": "/w/ledger", "dev": 37, "ino": 301,
                              "mtime_secs": 0, "mtime_nanos": 22}}
    ident = {"cell": "MS", "pid": 2000, "start": 8888, "gen": 0, "exe": "/w/ledger"}
    ledger = H6["parse_inv_ledger"]("")
    ledger["idents"] = [ident]
    ledger["mapped"] = [{**ident, "module": provider["path"], "ino": 111}]
    prefix = [{**ident, "module": provider["path"], "fn": fn, "mech": mech,
               "n": 1, "bad": 0, "phase": "h6-setup", "t0": START + 201 + i,
               "t1": START + 201 + i} for i, (fn, mech) in enumerate((
        ("C_GetFunctionList", "-"), ("C_Initialize", "-"), ("C_GetSlotList", "-"),
        ("C_OpenSession", "-"), ("C_Login", "-"), ("C_GenerateKey", "0x350"),
        ("C_SignInit", "0x251"), ("C_Sign", "0x251")))]
    prefix += [{**ident, "module": provider["path"], "fn": fn, "mech": "0x250", "n": 5,
                "bad": 0, "phase": "h6-warm1", "t0": START + 211, "t1": START + 212}
               for fn in ("C_DigestInit", "C_Digest")]
    ack = {**ident, "command": "W", "seq": 1, "attempt": 1, "t0": START + 200,
           "t1": START + 220, "deadline": STOP, "rv": 0, "idle": 1}
    marker = {"ack": ack, "batches": prefix, "dispatch_ns": START + 199}
    ledger["acks"] = [ack]
    ledger["batches"] = list(prefix)
    for number in (2, 3, 4):
        at = START + number * 1000
        ledger["batches"] += [{**ident, "module": provider["path"], "fn": fn, "mech": "0x250",
            "n": 5, "bad": 0, "phase": f"h6-warm{number}", "t0": at + 1, "t1": at + 2}
            for fn in ("C_DigestInit", "C_Digest")]
        ledger["acks"].append({**ack, "seq": number, "attempt": number,
                               "t0": at, "t1": at + 3})
    records = []
    def emit(kind, event, at):
        record = {"schema": "p11scope/inventory-events/v1", "kind": kind,
                  "seq": len(records), "at_ns": START + at, "event": event}
        records.append(record)
        return record
    def committed(number, at, edges=0, instances=0, semantics=0, final=False):
        return emit("pass_committed", {"pass": number, "final": final,
            "edge_events": edges, "instance_events": instances, "semantic_edge_events": semantics,
            "edge_events_deferred": 0, "instance_events_deferred": 0,
            "semantic_edge_events_deferred": 0, "gaps_suppressed": 0}, at)
    emit("started", {"scope": "system", "started_ns": START}, 0)
    admitted = emit("caller_event", {"event": "admitted", "caller": "c2",
                                    "identity_context": {"version": 1, "caller": context}}, 10)
    first_pass = committed(0, 20)
    gap = {"caller": "c2", "module": "m0", "pid": None, "budget": None,
           "subject": "physical provider use preceded first observed semantic registration",
           "reason": "before_semantic_boundary"}
    emit("gap_recorded", {**gap, "index": 0}, 250)
    edge = {"caller": "c2", "module": "m0", "mapping": {"state": "mapped"},
            "entries": {"count": 18, "saturated": False, "last_seen_ns": START + 212,
                        "coverage": {"state": "counted", "lossy": False}},
            "semantics": "unknown (semantic capture withheld)", "mechanisms": None,
            "operations": None, "identity_context": {"version": 1, "caller": context, "module": {
                "id": "m0", "status": "observed", "path": provider["path"],
                "device_major": 8, "device_minor": 1, "inode": 111}}}
    physical = emit("edge_observed", edge, 251)
    instance = emit("instance_observed", {"id": "i2", "caller": "c2", "module": "m0",
        "state": "observed", "reason": None, "first_seen_ns": START + 225, "last_seen_ns": START + 225}, 252)
    quiet = {"caller": "c2", "module": "m0", "instance": "i2",
        "entries": {"unit": "api_entries", "count": None, "observation": "unavailable"},
        "api_returns": {"unit": "api_returns", "count": None, "saturated": False, "historical_only_returns": 0},
        "semantics": "unknown (no calls observed)", "mechanisms": None, "operations": None,
        "coverage": {"lossy": False, "reasons": ["no_calls"]}}
    semantic = emit("semantic_edge_observed", quiet, 253)
    baseline_pass = committed(1, 260, 1, 1, 1)
    admission = {"caller": "c2", "incarnation": 0, "seq": admitted["seq"],
                 "completed_pass": H6["r5_pass_receipt"](first_pass)}
    baseline = {"image": image, "provider": provider, "admission": admission, "marker": marker,
        "physical": physical, "instance": instance, "semantic": semantic, "pass": baseline_pass,
        "tuple": [8888, "c2", 0, "m0", "i2"], "observed_ns": START + 261}
    final = {**quiet, "semantics": "observed",
        "api_returns": {"count": 30, "saturated": False, "historical_only_returns": 0},
        "mechanisms": [{"mechanism_hex": "0x250", "calls": 30, "errors": 0}],
        "operations": {"calls": 30, "completed": 15, "failed": 0, "unknown": 0, "orphans": 0,
                       "dropped": 0, "cancelled": 0, "active": [], "last_seen_ns": START + 4002},
        "coverage": {"lossy": False, "reasons": []}}
    emit("semantic_edge_observed", final, 4500)
    committed(2, 4600, semantics=1)
    stopped_instance = {**instance["event"], "state": "uncertain", "reason": "semantic_loss"}
    stopped = {**final, "coverage": {"lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}}
    emit("instance_observed", stopped_instance, 4700)
    emit("semantic_edge_observed", stopped, 4701)
    committed(2, 4710, instances=1, semantics=1, final=True)
    emit("ended", {"edge_events": 0, "instance_events": 0, "semantic_edge_events": 0,
        "edges_unretained": 0, "instances_unretained": 0, "semantic_edges_unretained": 0}, 4720)
    doc.update(scope="system", callers=[{"id": "c2", "pid": 2000, "start_time": 8888,
        "incarnation": 0, "retired": False, "lifecycle": "mapped",
        "image": {"authority": "scan_pinned", "exe": context["executable"]}}],
        modules=[{"id": "m0", "paths": [provider["path"]], "identity": {
            "inode": 111, "sha256": provider["sha256"], "device": {"major": 8, "minor": 1}}}],
        edges=[{**edge, "entries": {**edge["entries"], "count": 48}}], instances=[stopped_instance],
        semantic_edges=[stopped], gaps=[{**gap, "repeats": 1}], gaps_suppressed=0)
    receipt.update(scope_label="system", providers={"A": provider}, owned_pids=[2000],
                   observer_ready_ns=START + 20, observer_started_ns=START,
                   observer_stopped_ns=STOP, physical_hooks={provider["path"]: {
                       "provider": provider, "getter_export_offset": 0, "functions": {fn: i for i, fn in enumerate(["C_GetFunctionList", "C_Initialize",
                           "C_GetSlotList", "C_OpenSession", "C_Login", "C_GenerateKey",
                           "C_SignInit", "C_Sign", "C_DigestInit", "C_Digest"])}}},
                   inventory_control={"sibling": "MS", "sibling_providers": ["A"],
                       "sibling_baseline": baseline, "final_records": records,
                       "stages": [{"label": label, "t0": START + n * 1000,
                                   "t1": START + n * 1000 + 4} for n, label in
                                  ((2, "exec"), (3, "recovery"), (4, "measurement"))]})
    if not no_calls:
        expected = {"0x350": [1, 0], "0x251": [2, 0], "0x250": [10, 0]}
        quiet.update(semantics="observed", coverage={"lossy": False, "reasons": []},
            mechanisms=[{"mechanism_hex": key, "calls": values[0], "errors": values[1]}
                        for key, values in expected.items()],
            operations={"calls": 15, "completed": 7, "failed": 0, "unknown": 0,
                        "orphans": 0, "dropped": 0, "cancelled": 0, "active": []})
        quiet["api_returns"]["count"] = 17
        combined = [{"mechanism_hex": key, "calls": values[0] + (30 if key == "0x250" else 0),
                     "errors": values[1]} for key, values in expected.items()]
        for row in records:
            if row["kind"] == "semantic_edge_observed" and row["seq"] > semantic["seq"]:
                row["event"]["api_returns"]["count"] = 47
                row["event"]["operations"].update(calls=45, completed=22)
                row["event"]["mechanisms"] = copy.deepcopy(combined)
        doc["semantic_edges"][0]["mechanisms"] = copy.deepcopy(combined)
    return doc, ledger, receipt, records


def controlled_inputs(*, missing_target=True, target_gap=None):
    """Replay the existing observer seam with literal ledgers, without children."""
    pins = {name: {**BASE["PIN"], "path": f"/w/lib{name}.so", "ino": 111 + i,
                  "mapping": {"dev": [8, 1], "ino": 111 + i}} for i, name in enumerate(("A", "B"))}
    images = {0: {"image": 0, "pid": 1000, "start_time": 7777, "path": "/w/ledger",
                  "dev": 37, "ino": 301, "mtime_ns": 22},
              1: {"image": 1, "pid": 1000, "start_time": 7777, "path": "/w/ledger2",
                  "dev": 37, "ino": 302, "mtime_ns": 33}}
    observer = object.__new__(BASE["ControlledInventoryObserver"])
    owners = [SimpleNamespace(pid=pid, identity={"start_time": start},
                h6_test_reader=SimpleNamespace(lines=[])) for pid, start in ((1000, 7777), (2000, 8888))]
    observer.ctx = SimpleNamespace(owners=owners)
    observer.provider, observer.providers, observer.membership, observer.fault = pins["A"], pins, None, None
    observer.started, observer.passed = START, -1
    observer.records, observer.callers, observer.last, observer.instances, observer.semantic = [], {}, {}, {}, {}
    observer.last_acks, observer.quiet_publications, observer.gaps = {}, {}, []
    observer.release_original_admission = observer.release_teardown = True
    observer.teardown_published = False
    observer.module_ids = {pins[name]["path"]: f"m{i}" for i, name in enumerate(("A", "B"))}
    clock = [START]
    markers = {"MX": [], "MS": []}
    def identity(name, gen=0):
        return {"cell": name, "pid": 1000 if name == "MX" else 2000,
            "start": 7777 if name == "MX" else 8888, "gen": gen, "exe": images[gen]["path"]}
    def line(kind, row):
        return kind + " " + " ".join(f"{key}={value}" for key, value in row.items()) + "\n"
    for name, owner in zip(("MX", "MS"), owners):
        ident = identity(name)
        owner.h6_test_reader.lines.append(line("IDENT", ident))
        for module in (("A",) if name == "MX" else ("A", "B")):
            owner.h6_test_reader.lines.append(line("MAPPED", {**ident,
                "module": pins[module]["path"], "ino": pins[module]["ino"]}))
    def context(owner, ident, caller):
        image = images[ident["gen"]]
        return {"id": caller, "pid": owner.pid, "start_time": ident["start"], "incarnation": ident["gen"],
            "authority": "scan_pinned", "lifecycle": "mapped", "status": "observed",
            "executable": {"path": ident["exe"], "dev": image["dev"], "ino": image["ino"],
                           "mtime_secs": 0, "mtime_nanos": image["mtime_ns"]}}
    observer.context = context
    def emit(kind, event):
        event = copy.deepcopy(event)
        if kind == "pass_committed":
            event["gaps_suppressed"] = 0
        if kind == "edge_observed" and not event["entries"]["count"]:
            event["entries"].update(in_flight=False, first_seen_ns=None, last_seen_ns=None,
                coverage={"state": "watched_no_use", "lossy": None, "reason": None})
        if kind == "semantic_edge_observed":
            event["api_returns"]["unit"] = "api_returns"
            name = "MS" if event["caller"] == "c1" else "MX"
            old = name == "MX" and event["caller"] == "c0"
            if name == "MS" and len(markers["MS"]) == 1:
                event.update(semantics="unknown (no calls observed)", mechanisms=None, operations=None,
                             coverage={"lossy": False, "reasons": ["no_calls"]})
                event["api_returns"]["count"] = None
            elif name == "MS" or old and missing_target:
                api, calls, completed = (17, 15, 7) if name == "MS" else (87, 85, 42)
                event["api_returns"]["count"] -= api
                for key, deficit in (("calls", calls), ("completed", completed)):
                    event["operations"][key] -= deficit
                missed = {"0x250": 10 if name == "MS" else 80, "0x350": 1, "0x251": 2}
                for row in event["mechanisms"]:
                    row["calls"] -= missed.get(row["mechanism_hex"], 0)
                event["mechanisms"] = [row for row in event["mechanisms"] if row["calls"]]
        record = {"schema": "p11scope/inventory-events/v1", "seq": len(observer.records),
                  "at_ns": clock[0], "kind": kind, "event": event}
        observer.records.append(record)
        return record
    observer.emit = emit
    emit("started", {"scope": "system", "started_ns": START})
    clock[0] += 10
    observer.sweep()
    admissions = {}
    first_pass = observer.records[-1]
    for name, caller in (("MX", "c0"), ("MS", "c1")):
        row = next(row for row in observer.records if row["kind"] == "caller_event"
                   and row["event"].get("caller") == caller)
        admissions[name] = {"caller": caller, "incarnation": 0, "seq": row["seq"],
                            "completed_pass": H6["r5_pass_receipt"](first_pass)}
        gap = {"caller": caller, "module": None, "pid": None, "budget": None,
               "subject": "semantic admission refused", "reason": "semantic_unavailable"}
        observer.gaps.append({**gap, "repeats": 1})
        emit("gap_recorded", {**gap, "index": len(observer.gaps) - 1})
    clock[0] += 10
    observer.sweep()
    def command(name, number, command="W", gen=0):
        clock[0] += 100
        ident = identity(name, gen)
        modules = ("A",) if name == "MX" else ("A", "B")
        entries = []
        setup = (("C_GetFunctionList", "-", 1, 0, "h6-setup"), ("C_Initialize", "-", 1, 0, "h6-setup"),
            ("C_GetSlotList", "-", 1, 0, "h6-setup"), ("C_OpenSession", "-", 1, 0, "h6-setup"),
            ("C_Login", "-", 1, 0, "h6-setup"), ("C_GenerateKey", "0x350", 1, 0, "h6-setup"),
            ("C_SignInit", "0x251", 1, 0, "h6-setup"), ("C_Sign", "0x251", 1, 0, "h6-setup"))
        if command == "W":
            spec = (setup if number == 1 else ()) + tuple((fn, "0x250", 5, 0, f"h6-warm{number}")
                for fn in ("C_DigestInit", "C_Digest"))
        elif command == "M":
            spec = tuple((fn, mech, n, bad, phase) for fn, mech, n, bad, phase in (
                ("C_DigestInit", "0x250", 2, 0, "h6-measured"), ("C_Digest", "0x250", 2, 0, "h6-measured"),
                ("C_GenerateKey", "0x1080", 2, 0, "h6-measured"), ("C_EncryptInit", "0x1087", 2, 0, "h6-measured"),
                ("C_Encrypt", "0x1087", 2, 0, "h6-measured"), ("C_GenerateKey", "0x350", 2, 0, "h6-measured"),
                ("C_SignInit", "0x251", 2, 0, "h6-measured"), ("C_Sign", "0x251", 2, 0, "h6-measured"),
                ("C_DestroyObject", "-", 4, 0, "h6-measured"), ("C_VerifyInit", "0x251", 1, 0, "h6-failed"),
                ("C_Verify", "0x251", 1, 1, "h6-failed")))
        elif command == "T":
            spec = tuple((fn, "-", 1, 0, "h6-teardown") for fn in
                         ("C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize"))
        else:
            spec = ()
        for module in modules:
            for fn, mech, n, bad, phase in spec:
                entries.append({**ident, "module": pins[module]["path"], "fn": fn, "mech": mech,
                                "n": n, "bad": bad, "phase": phase, "t0": clock[0] + 1, "t1": clock[0] + 2})
        ack = {**ident, "command": command, "seq": number, "attempt": number if command == "W" else 0,
               "t0": clock[0], "t1": clock[0] + 3, "deadline": STOP, "idle": 1,
               "rv": 0xc0 if command == "M" else 0}
        owner = owners[0 if name == "MX" else 1]
        owner.h6_test_reader.lines.extend(line("LEDGER", row) for row in entries)
        owner.h6_test_reader.lines.append(line("ACK", ack))
        marker = {"ack": ack, "batches": entries, "dispatch_ns": clock[0] - 1}
        if command == "W":
            markers[name].append(marker)
        clock[0] += 10
        return marker
    first_sibling = command("MS", 1)
    for number in range(1, 10):
        command("MX", number)
    for caller in ("c0", "c1"):
        gap = {"caller": caller, "module": "m0", "pid": None, "budget": None,
               "subject": "physical provider use preceded first observed semantic registration",
               "reason": "before_semantic_boundary"}
        if caller == "c0" and target_gap:
            gap.update(target_gap)
        observer.gaps.append({**gap, "repeats": 1})
        emit("gap_recorded", {**gap, "index": len(observer.gaps) - 1})
    observer.sweep()
    def parsed(name):
        return H6["parse_inv_ledger"]("".join(owners[0 if name == "MX" else 1].h6_test_reader.lines))
    functions = {name: i for i, name in enumerate(("C_GetFunctionList", "C_Initialize", "C_GetSlotList",
        "C_OpenSession", "C_Login", "C_GenerateKey", "C_SignInit", "C_Sign", "C_DigestInit", "C_Digest",
        "C_EncryptInit", "C_Encrypt", "C_DestroyObject", "C_VerifyInit", "C_Verify", "C_Logout", "C_CloseSession", "C_Finalize"))}
    hooks = {pin["path"]: {"provider": pin, "functions": functions, "getter_export_offset": 0}
             for pin in pins.values()}
    owner = owners[0]
    def boundary(gen, admission, marker, floor, prior=None):
        return H6["inventory_boundary"](observer.records, owner, images[gen], pins["A"], admission,
            floor, marker, [row for row in parsed("MX")["batches"] if row["gen"] == gen],
            prior=prior, physical_hooks=hooks, started_ns=START)
    baseline0 = boundary(0, admissions["MX"], markers["MX"][-1], admissions["MX"]["completed_pass"]["seq"])
    proof0 = {"caller": "c0", "incarnation": 0, "module": "m0", "instance": "i0", "image": images[0],
        "provider": pins["A"], "admission": admissions["MX"], "cursor": {"seq": admissions["MX"]["seq"]},
        "physical_hooks": hooks, "observer_started_ns": START, "started_ns": markers["MX"][0]["ack"]["t0"],
        "observed_ns": clock[0] + 1, "deadline_ns": STOP, "attempts": 9, "max_attempts": 20,
        "markers": markers["MX"][:], "baseline": baseline0}
    fixed0 = command("MX", 10, "M")
    observer.sweep()
    end0 = boundary(0, admissions["MX"], fixed0, baseline0["pass"]["seq"], baseline0)
    teardown = command("MX", 11, "T")
    observer.sweep()
    tail = boundary(0, admissions["MX"], teardown, end0["pass"]["seq"], end0)
    sibling_image = {**images[0], "pid": 2000, "start_time": 8888}
    before = observer.records[:]
    by_kind = {kind: next(row for row in reversed(before) if row["kind"] == kind
        and row["event"].get("caller") == "c1") for kind in
        ("edge_observed", "instance_observed", "semantic_edge_observed")}
    # A is selected by physical identity rather than the sibling's last B row.
    by_kind["edge_observed"] = next(row for row in reversed(before) if row["kind"] == "edge_observed"
        and (row["event"]["caller"], row["event"]["module"]) == ("c1", "m0"))
    sibling_baseline = {"image": sibling_image, "provider": pins["A"], "admission": admissions["MS"],
        "marker": first_sibling, "physical": by_kind["edge_observed"], "instance": by_kind["instance_observed"],
        "semantic": by_kind["semantic_edge_observed"], "pass": before[-1], "tuple": [8888, "c1", 0, "m0", "i1"],
        "observed_ns": clock[0] + 1}
    checkpoint = {"seq": before[-1]["seq"], "at_ns": before[-1]["at_ns"]}
    x = command("MX", 12, "X")
    exec_start = x["dispatch_ns"]
    for kind in ("IDENT", "MAPPED"):
        row = identity("MX", 1)
        if kind == "MAPPED":
            row.update(module=pins["A"]["path"], ino=111)
        owners[0].h6_test_reader.lines.append(line(kind, row))
    command("MS", 2)
    observer.sweep()
    successor_record = next(row for row in observer.records if row["kind"] == "caller_event"
                            and row["event"].get("new") == "c2")
    admission1 = {"caller": "c2", "incarnation": 1, "seq": successor_record["seq"],
                  "completed_pass": H6["r5_pass_receipt"](observer.records[-1])}
    resumed = clock[0]
    command("MS", 3)
    successor_warm = command("MX", 1, gen=1)
    observer.sweep()
    baseline1 = boundary(1, admission1, successor_warm, admission1["completed_pass"]["seq"])
    proof1 = {**proof0, "caller": "c2", "incarnation": 1, "instance": "i2", "image": images[1],
        "admission": admission1, "cursor": checkpoint, "started_ns": successor_warm["ack"]["t0"],
        "observed_ns": clock[0] + 1, "attempts": 1, "markers": [successor_warm], "baseline": baseline1}
    measurement_start = clock[0]
    command("MS", 4)
    fixed1 = command("MX", 2, "M", gen=1)
    observer.sweep()
    end1 = boundary(1, admission1, fixed1, baseline1["pass"]["seq"], baseline1)
    clock[0] += 10
    observer.sweep(final=True)
    emit("ended", {"edge_events": 0, "instance_events": 0, "semantic_edge_events": 0,
                   "edges_unretained": 0, "instances_unretained": 0, "semantic_edges_unretained": 0})
    doc = observer.snapshot()
    # The seam's emit override supplies the observer's raw semantic output.
    # Its snapshot must retain those same cumulative rows, not the seam's
    # unmodified complete-ledger model used to generate them.
    latest_semantics = {}
    for row in observer.records:
        if row["kind"] == "semantic_edge_observed":
            latest_semantics[row["event"]["instance"]] = row["event"]
    doc["semantic_edges"] = list(latest_semantics.values())
    for row in doc["callers"]:
        context = next(value for value in observer.callers.values() if value["id"] == row["id"])
        row["image"].update(authority="scan_pinned", exe=context["executable"])
    doc.update(gaps=observer.gaps, gaps_suppressed=0)
    doc["observation"].update(lane="native", passes=observer.passed + 1)
    doc["observation"]["attach"]["scope_filter"] = None
    ledgers = {"MX": parsed("MX"), "MS": parsed("MS"), "MF": H6["parse_inv_ledger"]("")}
    ledgers["MF"]["idents"] = [{"cell": "MF", "pid": 3000, "start": 9999, "gen": 0, "exe": "/w/ledger"}]
    receipt = {"cell": "system-mixed", "leg": "inventory/singles", "scope_kind": "system", "scope_label": "system",
        "system_scan_limit": 256, "owned_pids": [1000, 2000, 3000], "foreign_pids": [3000],
        "observer_started_ns": START, "observer_ready_ns": START + 20, "observer_stopped_ns": STOP,
        "observer_rc": 0, "manual_rebind": False, "s1_expected": True, "providers": pins,
        "physical_hooks": hooks, "count_only_providers": ["B"], "allowed_gap_subjects": [],
        "expected_incarnations": {"1000": {"gens": {"0": {"exe": "/w/ledger", "retired": True},
            "1": {"exe": "/w/ledger2", "retired": False}}}, "2000": {"gens": {"0": {"exe": "/w/ledger", "retired": False}}}},
        "expected_edges": {"1000:0:A": {"counted": True, "count": 124}, "1000:1:A": {"counted": True, "count": 40},
            "2000:0:A": {"counted": True, "count": 48}, "2000:0:B": {"counted": True, "count": 48}},
        "measured": {"label": "successor", "t0": fixed1["ack"]["t0"], "t1": fixed1["ack"]["t1"],
            "expected_calls": 22, "phases": ["MX:h6-measured:gen1", "MX:h6-failed:gen1"]},
        "warmup": {"label": "original", "t0": markers["MX"][0]["ack"]["t0"], "t1": teardown["ack"]["t1"],
            "expected_calls": 123, "phases": sorted({H6["inventory_phase_name"](row) for row in ledgers["MX"]["batches"]
                if row["gen"] == 0 and row["fn"] != "C_GetFunctionList"})},
        "freeze": {"checkpoint": checkpoint}, "cell_endings": {}, "requested_backend": "singles",
        "inventory_control": {"proofs": [proof0, proof1], "measurements": [{"proof": proof0, "marker": fixed0, "end": end0},
            {"proof": proof1, "marker": fixed1, "end": end1}], "sibling": "MS", "sibling_providers": ["A", "B"],
            "sibling_baseline": sibling_baseline, "teardown": {"marker": teardown, "end": tail}, "final_records": observer.records,
            "stages": [{"label": "exec", "t0": exec_start, "t1": resumed},
                {"label": "recovery", "t0": resumed, "t1": proof1["observed_ns"]},
                {"label": "measurement", "t0": measurement_start, "t1": clock[0]}]}}
    # The final full read is a separate decode from the retained baseline.
    # Copies keep corruption controls from mutating both pieces together.
    control = receipt["inventory_control"]
    receipt["inventory_control"] = {key: copy.deepcopy(value) for key, value in control.items()}
    return copy.deepcopy(doc), copy.deepcopy(ledgers), receipt


class SystemSiblingTest(unittest.TestCase):
    def test_exact_postbaseline_sibling_delta_retains_seventeen_unobserved_early_api_calls(self):
        doc, ledger, receipt, records = sibling_inputs()
        errors, summaries = H6["inventory_sibling_s1_errors"](doc, ledger, receipt, records)
        self.assertEqual(errors, [])
        early = summaries[0]["early"]
        self.assertEqual(early["expected"]["api"], 17)
        self.assertEqual(early["observed"]["api"], 0)
        self.assertEqual(early["unobserved"]["api"], 17)
        self.assertEqual(early["expected"]["completed"], 7)
        self.assertEqual(early["observed"]["completed"], 0)
        self.assertEqual(early["unobserved"]["completed"], 7)
        self.assertEqual(early["mechanisms_expected"], {"0x350": [1, 0], "0x251": [2, 0], "0x250": [10, 0]})
        self.assertEqual(early["mechanisms_observed"], {})
        self.assertEqual((summaries[0]["api_returns"], summaries[0]["ledger_api_returns"]), (30, 47))
        self.assertEqual(summaries[0]["operations_observed"]["completed"], 15)
        self.assertEqual(summaries[0]["operations"]["completed"], 22)
        self.assertEqual(summaries[0]["delta"]["observed"], summaries[0]["delta"]["expected"])
        self.assertEqual(summaries[0]["delta"]["observed"]["api"], 30)
        self.assertEqual(summaries[0]["delta"]["observed"]["completed"], 15)

    def test_native_no_calls_baseline_requires_both_public_units(self):
        original = sibling_inputs()
        for part in ("api_returns", "entries"):
            with self.subTest(part=part):
                doc, ledger, receipt, records = copy.deepcopy(original)
                receipt["inventory_control"]["sibling_baseline"]["semantic"]["event"][part].pop("unit")
                errors, _ = H6["inventory_sibling_s1_errors"](doc, ledger, receipt, records)
                self.assertTrue(errors)

    def test_full_controlled_oracle_retains_missing_87_and_17_with_exact_later_work(self):
        doc, ledgers, receipt = controlled_inputs()
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        self.assertEqual(result["completed_operations"], 20)
        self.assertEqual(result["s1"]["stable_instances"][0]["early"]["api_missed"], 87)
        self.assertEqual(result["s1"]["sibling_instances"][0]["early"]["unobserved"]["api"], 17)
        self.assertEqual(len(result["expected_disclosures"]), 4)
        self.assertEqual(len(result["gaps"]), 4)

    def test_full_count_target_cannot_license_unrelated_boundary_subject_or_reason(self):
        for gap in ({"subject": "future gap", "reason": "before_admission"},
                    {"reason": "before_admission"}):
            with self.subTest(gap=gap):
                data = controlled_inputs(missing_target=False, target_gap=gap)
                result = H6["evaluate_inventory_h6"](*data)
                self.assertFalse(result["pass"], result)

    def test_full_count_target_retains_conservative_boundary_gap_without_claiming_loss(self):
        doc, ledgers, receipt = controlled_inputs(missing_target=False)
        result = H6["evaluate_inventory_h6"](doc, ledgers, receipt)
        self.assertTrue(result["pass"], result["errors"])
        early = result["s1"]["stable_instances"][0]["early"]
        self.assertEqual(early["api_missed"], 0)
        self.assertEqual(len(early["gaps"]), 1)
        self.assertEqual(len(result["expected_disclosures"]), 4)
        self.assertEqual(len(result["gaps"]), 4)

    def test_owned_preuse_requires_armed_provider_progression_and_complete_prefix(self):
        original = controlled_inputs()
        def accepted(data):
            doc, ledgers, receipt = data
            records = receipt["inventory_control"]["final_records"]
            publication = next(row for row in records if row["kind"] == "gap_recorded"
                               and row["event"]["index"] == 1)
            return H6["inventory_system_preuse_disclosure"](doc, ledgers, receipt, doc["gaps"][1], publication)
        self.assertTrue(accepted(original))
        for fault in ("not-armed", "regression", "uncommitted-prefix"):
            with self.subTest(fault=fault):
                data = copy.deepcopy(original)
                records = data[2]["inventory_control"]["final_records"]
                dispatch = data[2]["inventory_control"]["sibling_baseline"]["marker"]["dispatch_ns"]
                edges = [row for row in records if row["kind"] == "edge_observed"
                         and row["event"]["caller"] == "c1" and row["at_ns"] < dispatch]
                if fault == "not-armed":
                    edges[-1]["event"]["entries"]["coverage"] = {
                        "state": "unknown", "reason": "not_attached", "lossy": None}
                else:
                    pending = copy.deepcopy(edges[-1])
                    if fault == "regression":
                        pending["event"]["entries"]["coverage"] = {
                            "state": "unknown", "reason": "not_attached", "lossy": None}
                        where = max(i for i, row in enumerate(records) if row["kind"] == "pass_committed"
                                    and row["at_ns"] < dispatch)
                        records[where:where] = [pending, copy.deepcopy(edges[-1])]
                    else:
                        pending["at_ns"] = dispatch - 1
                        where = next(i for i, row in enumerate(records) if row["at_ns"] >= dispatch)
                        records.insert(where, pending)
                    for seq, row in enumerate(records):
                        row["seq"] = seq
                self.assertFalse(accepted(data), fault)

    def test_composed_baseline_and_early_disclosures_reject_authority_or_later_loss_mutations(self):
        original = controlled_inputs()
        def baseline(data):
            return data[2]["inventory_control"]["sibling_baseline"]
        def change_gap(data, index, key, value):
            data[0]["gaps"][index][key] = value
            for row in data[2]["inventory_control"]["final_records"]:
                if row["kind"] == "gap_recorded" and row["event"]["index"] == index:
                    row["event"][key] = value
        def late_repeat(data):
            data[0]["gaps"][1]["repeats"] = 2
            records = data[2]["inventory_control"]["final_records"]
            records.insert(-1, {"schema": "p11scope/inventory-events/v1", "kind": "gap_repeated",
                "at_ns": records[-1]["at_ns"], "event": {"index": 1, "repeats": 2}})
            for seq, row in enumerate(records):
                row["seq"] = seq
        def missing_later(data):
            row = next(row for row in data[0]["semantic_edges"] if row["caller"] == "c1")
            row["api_returns"]["count"] -= 1
        def hidden_loss(data):
            records = data[2]["inventory_control"]["final_records"]
            for row in records:
                if row["kind"] == "semantic_edge_observed" and row["event"]["caller"] == "c1" \
                        and row["seq"] > baseline(data)["pass"]["seq"]:
                    row["event"]["coverage"]["lossy"] = True
                    row["event"]["coverage"]["reasons"] = ["semantic_loss"]
                    break
        cases = {
            "missing-baseline": lambda d: d[2]["inventory_control"].pop("sibling_baseline"),
            "borrowed-stream": lambda d: baseline(d)["semantic"].update(at_ns=START + 5),
            "borrowed-caller": lambda d: baseline(d)["image"].update(pid=1000),
            "borrowed-module": lambda d: baseline(d)["provider"].update(ino=112),
            "borrowed-instance": lambda d: baseline(d)["tuple"].__setitem__(4, "i9"),
            "wrong-birth": lambda d: baseline(d)["image"].update(start_time=7777),
            "active-baseline": lambda d: baseline(d)["semantic"]["event"].update(operations={"active": [{"count": 1}]}),
            "late-baseline": lambda d: baseline(d).update(observed_ns=d[2]["inventory_control"]["stages"][0]["t1"]),
            "prebaseline-W2": lambda d: next(row for row in d[1]["MS"]["batches"]
                if row["phase"] == "h6-warm2").update(t0=baseline(d)["pass"]["at_ns"] - 1),
            "missing-boundary-gap": lambda d: change_gap(d, 3, "reason", "provider_mapping_unproven"),
            "unrelated-boundary-gap": lambda d: change_gap(d, 3, "caller", "c0"),
            "unknown-boundary-subject": lambda d: change_gap(d, 3, "subject", "future gap"),
            "late-preuse-repeat": late_repeat,
            "missing-later-call": missing_later,
            "hidden-later-loss": hidden_loss,
            "count-only-positive": lambda d: next(row for row in d[0]["edges"]
                if (row["caller"], row["module"]) == ("c1", "m1")).update(operations={"completed": 1}),
            "baseline-wrong-admission-kind": lambda d: next(row for row in
                d[2]["inventory_control"]["final_records"]
                if row["seq"] == baseline(d)["admission"]["completed_pass"]["seq"]).update(kind="gap_repeated"),
            "baseline-missing-written": lambda d: baseline(d)["pass"]["event"].pop("semantic_edge_events"),
            "baseline-deferred": lambda d: baseline(d)["pass"]["event"].update(semantic_edge_events_deferred=1),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                data = copy.deepcopy(original)
                mutate(data)
                result = H6["evaluate_inventory_h6"](*data)
                self.assertFalse(result["pass"], result)

    def test_early_current_mechanism_overcount_or_unreported_deficit_is_rejected(self):
        original = sibling_inputs(no_calls=False)
        errors, _ = H6["inventory_sibling_s1_errors"](*original)
        self.assertEqual(errors, [])
        for fault in ("mechanism-overcount", "mechanism-deficit-without-gap", "cancelled-later", "active-later"):
            with self.subTest(fault=fault):
                doc, ledger, receipt, records = copy.deepcopy(original)
                baseline = receipt["inventory_control"]["sibling_baseline"]
                row = baseline["semantic"]["event"]
                expected = {"0x350": [1, 0], "0x251": [2, 0], "0x250": [10, 0]}
                row.update(semantics="observed", coverage={"lossy": False, "reasons": []},
                    mechanisms=[{"mechanism_hex": key, "calls": values[0], "errors": values[1]}
                                for key, values in expected.items()],
                    operations={"calls": 15, "completed": 7, "failed": 0, "unknown": 0,
                                "orphans": 0, "dropped": 0, "cancelled": 0, "active": []})
                row["api_returns"]["count"] = 17
                final = doc["semantic_edges"][0]
                final["api_returns"]["count"] = 47
                final["operations"].update(calls=45, completed=22)
                final["mechanisms"] = [{"mechanism_hex": key, "calls": values[0] + (30 if key == "0x250" else 0),
                                        "errors": values[1]} for key, values in expected.items()]
                if fault == "mechanism-overcount":
                    row["mechanisms"][0]["calls"] = 2
                elif fault == "mechanism-deficit-without-gap":
                    row["mechanisms"][0]["calls"] = 0
                    final["mechanisms"][0]["calls"] = 0
                    for record in records:
                        if record["kind"] == "semantic_edge_observed" and record["seq"] > baseline["pass"]["seq"]:
                            record["event"]["mechanisms"][0]["calls"] = 0
                    records[3]["event"]["reason"] = "different"
                elif fault == "cancelled-later":
                    final["operations"]["cancelled"] = 1
                else:
                    final["operations"]["active"] = [{"count": 1}]
                errors, _ = H6["inventory_sibling_s1_errors"](doc, ledger, receipt, records)
                self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
