#!/usr/bin/env python3
"""Exact evidence oracles shared by the canonical live capture lanes."""

import copy
import json
import sys
from collections import Counter
from pathlib import Path


COUNTERS = (
    "event_loss",
    "start_insert_failures",
    "unmatched_returns",
    "rv_update_failures",
    "cgroup_scope_failures",
    "semantic_capture_failures",
    "unregistered_mechanisms",
    "template_tail_failures",
    "process_tracking_fallbacks",
    "process_tracking_failures",
    "process_tracking_evictions",
    "state_reconciliations",
    "session_cancel_ambiguities",
    "session_cancel_unknown_flags",
    "operation_state_imports",
    "auth_state_ambiguities",
    "async_target_failures",
    "async_orphans",
    "async_duplicates",
    "async_evictions",
    "fork_state_ambiguities",
    "semantic_state_drops",
    "pending_at_end",
    "malformed_records",
    "orphan_ops",
    "unmatched_closes",
    "shape_decode_failures",
    "shape_decode_total_failures",
    # Discovery gaps (schema v2). Every one of them forces PARTIAL, so a lane
    # with a real provider must report all three as zero.
    "discovery_conflicts",
    "discovery_uncorroborated",
    "module_ambiguous",
)

VERSION_SURFACES = Counter(
    {
        ("full", 68): 2,
        ("full", 92): 2,
        ("full", 104): 2,
        ("known_prefix", 68): 1,
        ("known_prefix", 92): 2,
        ("known_prefix", 104): 2,
        ("refused", 0): 1,
        ("not_walked", 0): 1,
    }
)
G1_SURFACES = Counter({("full", 68): 1, ("full", 92): 1, ("not_walked", 0): 1})
LEGACY_SURFACES = Counter({("full", 68): 1})

SAFE_ALLOWANCES = {
    "semantic_capture_failures": 3,
    "unregistered_mechanisms": 2,
    "async_target_failures": 2,
    "async_orphans": 1,
    "orphan_ops": 3,
}
UNSAFE_ALLOWANCES = {
    "semantic_capture_failures": 7,
    "async_target_failures": 2,
    "async_orphans": 1,
    "orphan_ops": 3,
    "shape_decode_failures": 2,
}
G3_COUNTS = {
    "C_GetFunctionList": 1,
    "C_Initialize": 1,
    "C_Finalize": 1,
    "C_GetSlotList": 1,
    "C_OpenSession": 1,
    "C_CloseSession": 1,
    "C_GenerateRandom": 200000,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest_ok(carrier):
    """A whole-file SHA-256 is present and well-formed.

    `sha256` is `null` for an object this capture never pinned — an absence, not
    an empty digest — so the null must be rejected as a stated failure rather
    than crash the length check.
    """
    digest = carrier["sha256"]
    return isinstance(digest, str) and len(digest) == 64


def exact_counters(evidence, allowances=None):
    allowances = allowances or {}
    unknown = set(allowances) - set(COUNTERS)
    require(not unknown, f"unknown evidence allowances: {sorted(unknown)}")
    for name in COUNTERS:
        wanted = allowances.get(name, 0)
        require(evidence[name] == wanted, f"{name}: want {wanted}, got {evidence[name]}")


def surface_signature(evidence):
    surfaces = evidence["surfaces"]
    require(surfaces, "evidence.surfaces is empty")
    require(
        all(surface["acquisition"] == "ok" for surface in surfaces),
        f"surface acquisition failure: {surfaces}",
    )
    return Counter((surface["walk"], surface["functions"]) for surface in surfaces)


def exact_shape(evidence, table_entries, slots, probes, surfaces, vendor, interface_list):
    for name, wanted in (
        ("table_entries", table_entries),
        ("slots", slots),
        ("attached_probes", probes),
        ("vendor_interfaces", vendor),
        ("interface_list", interface_list),
    ):
        require(evidence[name] == wanted, f"{name}: want {wanted!r}, got {evidence[name]!r}")
    require(surface_signature(evidence) == surfaces, f"unexpected surfaces: {evidence['surfaces']}")


def exact_common(evidence, *, aliases, skipped, in_flight):
    require(evidence["attach_failures"] == [], evidence["attach_failures"])
    require(evidence["aliased"] == aliases, f"unexpected aliases: {evidence['aliased']}")
    require(evidence["skipped"] == skipped, f"unexpected skips: {evidence['skipped']}")
    require(evidence["in_flight_at_end"] == in_flight, evidence["in_flight_at_end"])
    require(evidence["templates_truncated"] is False, "templates were truncated")
    require(evidence["provider_changed"] is False, "a pinned provider object changed during capture")
    # Discovery is the claim the whole document rests on: a lane that attached
    # probes must name what it attached them into, and how it was authorized.
    require(evidence["authority"] == "hash-pinned", f"unexpected authority: {evidence['authority']}")
    require(evidence["discovery"], "evidence.discovery is empty: nothing was discovered")
    for module in evidence["discovery"]:
        require(digest_ok(module), f"module without a whole-file digest: {module}")
        require(module["sources"], f"module with no discovery source: {module}")
    require(evidence["modules_skipped"] == [], f"modules refused: {evidence['modules_skipped']}")
    require(evidence["scan_unavailable"] is None, evidence["scan_unavailable"])
    require(evidence["completeness"] == "PARTIAL", evidence["completeness"])


# The four counters the schema documents as informational, and therefore
# permits nonzero in an otherwise complete document. A lane that attaches mid
# execution legitimately reports orphan operations and unmatched closes, and a
# lane observing many short-lived processes legitimately falls back from pidfd
# identity to /proc start-time identity.
INFORMATIONAL_COUNTERS = frozenset(
    {
        "process_tracking_fallbacks",
        "orphan_ops",
        "unmatched_closes",
        "shape_decode_failures",
    }
)


def terminal_capture_is_clean(evidence):
    """Normal terminal evidence for a lane with its own call oracle.

    A detached perf link does not wait for BPF callbacks already running on
    another CPU, so a terminal snapshot is PARTIAL by construction. "Clean"
    therefore means exactly what COMPLETE used to mean, minus that one
    unprovable drain: no attach failure, alias, skip, or in-flight call, and
    every *concrete* gap counter zero. The documented informational counters
    are not gaps and are not constrained here; a lane that can prove an exact
    value for them should assert it directly with exact_counters.
    """
    exact_common(evidence, aliases=[], skipped=[], in_flight=0)
    for name in COUNTERS:
        if name in INFORMATIONAL_COUNTERS:
            continue
        require(evidence[name] == 0, f"{name}: want 0, got {evidence[name]}")


def exact_capture_modules(document):
    """`capture.modules[]` — v2's replacement for the singular `capture.module`.

    A lane that attached probes observed at least one module, and every entry
    must carry the identity the probes were authorized against, never just a
    pathname (which for a scanned module is the target's, not the observer's).
    """
    modules = document["capture"]["modules"]
    require(modules, "capture.modules is empty: the document names no provider")
    for module in modules:
        require(module["path"], f"module without a path: {module}")
        # `sha256` is null for an object nothing pinned — never in a lane that
        # attached probes, and the guard keeps that a stated rejection rather
        # than a TypeError traceback.
        require(digest_ok(module), f"module without a whole-file digest: {module}")
        require(isinstance(module["ino"], int) and module["ino"] > 0, f"module inode: {module}")
        require(len(module["dev"]) == 2, f"module device: {module}")
    require(
        modules == [
            {key: module[key] for key in ("path", "dev", "ino", "sha256", "build_id")}
            for module in document["evidence"]["discovery"]
        ],
        "capture.modules[] and evidence.discovery[] disagree about what was observed",
    )
    # Every count is attributed to a module the document names, or to nobody at
    # all with the reason stated. An identity that matches no declared module
    # would make the attribution unverifiable, which is the point of publishing it.
    identities = [{key: module[key] for key in ("dev", "ino", "sha256")} for module in modules]
    for item in document["functions"]:
        owner, ambiguous = item["module"], item["module_ambiguous"]
        if owner is None:
            require(ambiguous is True, f"unattributed function without a reason: {item}")
            continue
        require(ambiguous is False, f"attributed function marked ambiguous: {item}")
        require(owner in identities, f"function attributed to an undeclared module: {item}")


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_canary(path, trace):
    if not trace:
        return load_json(path)
    records = [
        line.removeprefix("EVIDENCE ")
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.startswith("EVIDENCE ")
    ]
    require(len(records) == 1, f"expected one terminal EVIDENCE record, got {len(records)}")
    return json.loads(records[0])


def validate_clean_metrics(document, expected, multiplier=1):
    require(multiplier >= 1, f"invalid clean-metrics multiplier: {multiplier}")
    require(document["schema"] == "pkcs11-scope/observed-profile/v2-metrics", document["schema"])
    require(document["capture"]["mode"] == "metrics", document["capture"])
    require(document["capture"]["privacy_mode"] == "aggregate-only", document["capture"])
    evidence = document["evidence"]
    exact_shape(evidence, 68, 68, 136, LEGACY_SURFACES, 0, "absent")
    exact_common(evidence, aliases=[], skipped=[], in_flight=0)
    exact_counters(evidence)
    exact_capture_modules(document)

    actual = Counter()
    for item in document["functions"]:
        calls = item["calls"]
        require(isinstance(calls, int) and calls >= 0, f"invalid call count: {item}")
        require(item["names"], f"function without names: {item}")
        if calls:
            actual.update({name: calls for name in item["names"]})
    wanted = {name: calls * multiplier for name, calls in expected.items()}
    require("C_GetFunctionList" not in wanted, "expected-count file must omit bootstrap")
    wanted["C_GetFunctionList"] = multiplier
    require(dict(actual) == wanted, f"positive function counts: want {wanted}, got {dict(actual)}")


def validate_canary(lane, document):
    lanes = {
        "default-safe-profile": ("safe", "profile"),
        "default-safe-trace": ("safe", "trace"),
        "feature-safe-profile": ("safe", "profile"),
        "feature-safe-trace": ("safe", "trace"),
        "feature-unsafe-profile": ("unsafe", "profile"),
        "feature-unsafe-trace": ("unsafe", "trace"),
        "aggregate-only-metrics": ("aggregate", "metrics"),
    }
    require(lane in lanes, f"unknown canary lane: {lane}")
    policy, kind = lanes[lane]
    trace = kind == "trace"
    evidence = document if trace else document["evidence"]

    exact_shape(evidence, 988, 104, 208, VERSION_SURFACES, 1, "ok")
    exact_common(evidence, aliases=[], skipped=[], in_flight=0)
    exact_counters(
        evidence,
        SAFE_ALLOWANCES if policy == "safe" else UNSAFE_ALLOWANCES if policy == "unsafe" else {},
    )

    privacy = {
        "safe": "allowlisted",
        "unsafe": "unsafe-unvalidated-metadata",
        "aggregate": "aggregate-only",
    }[policy]
    if trace:
        require(evidence["privacy_mode"] == privacy, evidence["privacy_mode"])
        require(evidence["capture_aborted"] is None, evidence["capture_aborted"])
        require(evidence["final_drain"] is False, evidence["final_drain"])
        require(evidence["counters_available"] is True, evidence["counters_available"])
    else:
        schema = (
            "pkcs11-scope/observed-profile/v2-metrics"
            if kind == "metrics"
            else "pkcs11-scope/observed-profile/v2"
        )
        require(document["schema"] == schema, document["schema"])
        require(document["capture"]["mode"] == kind, document["capture"])
        require(document["capture"]["privacy_mode"] == privacy, document["capture"])
        exact_capture_modules(document)
    if policy == "aggregate":
        calls = sum(item["calls"] for item in document["functions"])
        require(calls == 25, f"aggregate calls: want 25, got {calls}")


def validate_induced(lane, document):
    require(lane in {"G1", "G2", "G3", "G4", "G5"}, f"unknown induced lane: {lane}")
    require(document["schema"] == "pkcs11-scope/observed-profile/v2", document["schema"])
    require(document["capture"]["mode"] == "profile", document["capture"])
    require(document["capture"]["privacy_mode"] == "allowlisted", document["capture"])
    exact_capture_modules(document)
    evidence = document["evidence"]

    if lane == "G1":
        aliases = [["C_CancelFunction", "C_WaitForSlotEvent"]]
        skipped = [{"name": "C_GetFunctionStatus", "reason": "null pointer"}]
        exact_shape(evidence, 160, 93, 186, G1_SURFACES, 1, "ok")
        exact_common(evidence, aliases=aliases, skipped=skipped, in_flight=0)
        exact_counters(evidence)
    elif lane == "G2":
        groups = evidence["aliased"]
        require(len(groups) == 1, f"G2 aliases: {groups}")
        require(len(groups[0]) == len(set(groups[0])) == 67, f"G2 alias group: {groups}")
        require("C_WaitForSlotEvent" not in groups[0], f"G2 stranded name was aliased: {groups}")
        exact_shape(evidence, 68, 2, 4, LEGACY_SURFACES, 0, "absent")
        exact_common(evidence, aliases=groups, skipped=[], in_flight=1)
        exact_counters(evidence)
    elif lane == "G3":
        exact_shape(evidence, 68, 68, 136, LEGACY_SURFACES, 0, "absent")
        exact_common(evidence, aliases=[], skipped=[], in_flight=0)
        require(evidence["event_loss"] > 0, f"event_loss: {evidence['event_loss']}")
        require(evidence["unmatched_closes"] in (0, 1), evidence["unmatched_closes"])
        actual = Counter()
        for item in document["functions"]:
            if item["calls"]:
                actual.update({name: item["calls"] for name in item["names"]})
        require(dict(actual) == G3_COUNTS, f"G3 function counts: {dict(actual)}")
        exact_counters(
            evidence,
            {
                "event_loss": evidence["event_loss"],
                "unmatched_closes": evidence["unmatched_closes"],
            },
        )
    elif lane == "G4":
        exact_shape(evidence, 988, 104, 208, VERSION_SURFACES, 1, "ok")
        exact_common(evidence, aliases=[], skipped=[], in_flight=9)
        exact_counters(evidence, {"start_insert_failures": 8})
    else:
        exact_shape(evidence, 988, 104, 208, VERSION_SURFACES, 1, "ok")
        exact_common(evidence, aliases=[], skipped=[], in_flight=0)
        exact_counters(
            evidence,
            {"rv_update_failures": 9, "unregistered_mechanisms": 6, "async_orphans": 1},
        )
        require(sum(item["calls"] for item in document["functions"]) == 11, document["functions"])


def expected_counts(path):
    counts = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        name, wanted = line.split()
        require(name not in counts, f"duplicate expected function: {name}")
        counts[name] = int(wanted)
    return counts


MODULE_FIXTURE = {
    "path": "/opt/p11.so",
    "dev": [8, 1],
    "ino": 4242,
    "sha256": "11" * 32,
    "build_id": "aabb",
}


def function_items(pairs):
    """`functions[]` items as v2 emits them: every count attributed to a module."""
    identity = {key: MODULE_FIXTURE[key] for key in ("dev", "ino", "sha256")}
    return [
        {"names": names, "calls": calls, "module": identity, "module_ambiguous": False}
        for names, calls in pairs
    ]


def discovery_fixture():
    return [
        dict(
            MODULE_FIXTURE,
            objects=[dict(MODULE_FIXTURE, identity_source="mountinfo", note=None)],
            sources=["scan"],
            corroborated=False,
            corroboration=["single_source"],
            tables=[{"version": [2, 40], "entries": 68, "source": "scan"}],
            interfaces=0,
            skipped=[],
        )
    ]


def evidence_fixture(surfaces):
    return {
        "authority": "hash-pinned",
        "discovery": discovery_fixture(),
        "modules_skipped": [],
        "scan_unavailable": None,
        "scan_ms": 3,
        "table_entries": 0,
        "slots": 0,
        "attached_probes": 0,
        "attach_failures": [],
        "aliased": [],
        "skipped": [],
        "in_flight_at_end": 0,
        "surfaces": [
            {"walk": walk, "functions": functions, "acquisition": "ok"}
            for (walk, functions), count in surfaces.items()
            for _ in range(count)
        ],
        "vendor_interfaces": 0,
        "interface_list": "absent",
        **{name: 0 for name in COUNTERS},
        "templates_truncated": False,
        "provider_changed": False,
        "completeness": "PARTIAL",
    }


def document_fixture(evidence, *, schema="pkcs11-scope/observed-profile/v2", mode="profile", privacy="allowlisted"):
    return {
        "schema": schema,
        "capture": {
            "mode": mode,
            "privacy_mode": privacy,
            # v2: one entry per discovered module, projected from the evidence.
            "modules": [
                {key: module[key] for key in ("path", "dev", "ino", "sha256", "build_id")}
                for module in evidence["discovery"]
            ],
        },
        "evidence": evidence,
        "functions": [],
    }


def rejected(action):
    try:
        action()
    except AssertionError:
        return
    raise AssertionError("mutated fixture was accepted")


def self_test():
    clean_evidence = evidence_fixture(LEGACY_SURFACES)
    clean_evidence.update(table_entries=68, slots=68, attached_probes=136)
    clean = document_fixture(
        clean_evidence,
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    clean["functions"] = function_items(
        [(["C_GetFunctionList"], 1), (["C_Initialize"], 1)]
    )
    validate_clean_metrics(clean, {"C_Initialize": 1})
    bad = copy.deepcopy(clean)
    bad["functions"] += function_items([(["C_Unexpected"], 1)])
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("unexpected positive function rejected: OK")
    bad = copy.deepcopy(clean)
    bad["functions"][0]["calls"] = 2
    rejected(lambda: validate_clean_metrics(bad, {"C_Initialize": 1}))
    print("bootstrap function exact count required: OK")
    doubled = copy.deepcopy(clean)
    for item in doubled["functions"]:
        item["calls"] *= 2
    validate_clean_metrics(doubled, {"C_Initialize": 1}, 2)
    rejected(lambda: validate_clean_metrics(clean, {"C_Initialize": 1}, 2))
    print("clean metrics multiplier is exact: OK")

    version = evidence_fixture(VERSION_SURFACES)
    version.update(table_entries=988, slots=104, attached_probes=208, vendor_interfaces=1, interface_list="ok")
    safe = document_fixture(copy.deepcopy(version))
    safe["evidence"].update(SAFE_ALLOWANCES)
    validate_canary("default-safe-profile", safe)
    bad = copy.deepcopy(safe)
    bad["evidence"]["attached_probes"] = 206
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary matrix 988/104/208 with 13 mixed surfaces: OK")
    bad = copy.deepcopy(safe)
    bad["evidence"]["unregistered_mechanisms"] = 3
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("canary safe exact allowances: OK")

    unsafe = document_fixture(copy.deepcopy(version), privacy="unsafe-unvalidated-metadata")
    unsafe["evidence"].update(UNSAFE_ALLOWANCES)
    validate_canary("feature-unsafe-profile", unsafe)
    bad = copy.deepcopy(unsafe)
    bad["evidence"]["shape_decode_failures"] = 1
    rejected(lambda: validate_canary("feature-unsafe-profile", bad))
    print("canary unsafe exact allowances: OK")

    aggregate = document_fixture(
        copy.deepcopy(version),
        schema="pkcs11-scope/observed-profile/v2-metrics",
        mode="metrics",
        privacy="aggregate-only",
    )
    aggregate["functions"] = function_items([(["C_GetInterfaceList"], 25)])
    validate_canary("aggregate-only-metrics", aggregate)
    bad = copy.deepcopy(aggregate)
    bad["functions"][0]["calls"] = 24
    rejected(lambda: validate_canary("aggregate-only-metrics", bad))
    print("canary aggregate exact baseline: OK")

    induced = {}
    g1 = evidence_fixture(G1_SURFACES)
    g1.update(
        table_entries=160,
        slots=93,
        attached_probes=186,
        vendor_interfaces=1,
        interface_list="ok",
        aliased=[["C_CancelFunction", "C_WaitForSlotEvent"]],
        skipped=[{"name": "C_GetFunctionStatus", "reason": "null pointer"}],
    )
    induced["G1"] = document_fixture(g1)
    g2 = evidence_fixture(LEGACY_SURFACES)
    g2.update(
        table_entries=68,
        slots=2,
        attached_probes=4,
        in_flight_at_end=1,
        aliased=[[f"C_Alias_{index}" for index in range(67)]],
    )
    induced["G2"] = document_fixture(g2)
    g3 = evidence_fixture(LEGACY_SURFACES)
    g3.update(
        table_entries=68,
        slots=68,
        attached_probes=136,
        event_loss=1,
        unmatched_closes=1,
    )
    induced["G3"] = document_fixture(g3)
    induced["G3"]["functions"] = function_items(
        [([name], calls) for name, calls in G3_COUNTS.items()]
    )
    g4 = copy.deepcopy(version)
    g4.update(in_flight_at_end=9, start_insert_failures=8)
    induced["G4"] = document_fixture(g4)
    g5 = copy.deepcopy(version)
    g5.update(rv_update_failures=9, unregistered_mechanisms=6, async_orphans=1)
    induced["G5"] = document_fixture(g5)
    induced["G5"]["functions"] = function_items([(["C_Initialize"], 11)])
    for lane, document in induced.items():
        validate_induced(lane, document)
        bad = copy.deepcopy(document)
        bad["evidence"]["malformed_records"] = 1
        rejected(lambda lane=lane, bad=bad: validate_induced(lane, bad))
        print(f"induced {lane} exact allowances: OK")

    bad = copy.deepcopy(induced["G3"])
    bad["evidence"]["rv_update_failures"] = 1
    rejected(lambda: validate_induced("G3", bad))
    print("induced G3 rejects state-map contamination: OK")

    bad = copy.deepcopy(induced["G3"])
    next(item for item in bad["functions"] if item["names"] == ["C_GenerateRandom"])["calls"] -= 1
    rejected(lambda: validate_induced("G3", bad))
    print("induced G3 exact function counts required: OK")

    bad = copy.deepcopy(induced["G5"])
    bad["functions"][0]["calls"] = 12
    rejected(lambda: validate_induced("G5", bad))
    print("induced G5 exact 11 calls and 9 RV failures: OK")

    bad = copy.deepcopy(safe)
    bad["evidence"]["operation_state_imports"] = 1
    rejected(lambda: validate_canary("default-safe-profile", bad))
    print("unrelated evidence gap rejected: OK")

    terminal_capture_is_clean(copy.deepcopy(clean["evidence"]))
    for field, value in (
        ("completeness", "COMPLETE"),
        ("event_loss", 1),
        ("in_flight_at_end", 1),
        ("aliased", ["C_Sign"]),
        ("semantic_state_drops", 1),
        ("rv_update_failures", 1),
    ):
        bad = copy.deepcopy(clean["evidence"])
        bad[field] = value
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    # The documented informational counters are not gaps: a lane attaching mid
    # execution must still read as clean.
    for field in sorted(INFORMATIONAL_COUNTERS):
        tolerated = copy.deepcopy(clean["evidence"])
        tolerated[field] = 7
        terminal_capture_is_clean(tolerated)
    print("terminal capture predicate is PARTIAL with no concrete gap: OK")

    # v2 discovery oracles. A document that discovered nothing, was authorized
    # by something else, refused a module, or names a provider its evidence does
    # not, is never a clean capture.
    for field, value in (
        ("discovery", []),
        ("authority", "manifest"),
        ("modules_skipped", [{"name": "/opt/x.so", "reason": "capacity"}]),
        ("scan_unavailable", "ptrace"),
        ("discovery_conflicts", 1),
        ("discovery_uncorroborated", 1),
        ("module_ambiguous", 1),
    ):
        bad = copy.deepcopy(clean["evidence"])
        bad[field] = value
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    for digest in ("", None):
        bad = copy.deepcopy(clean["evidence"])
        bad["discovery"][0]["sha256"] = digest
        rejected(lambda bad=bad: terminal_capture_is_clean(bad))
    print("discovery evidence is required and gap-free: OK")

    exact_capture_modules(clean)
    for mutate in (
        lambda d: d["capture"]["modules"].clear(),
        lambda d: d["capture"]["modules"][0].update(sha256="00"),
        lambda d: d["capture"]["modules"][0].update(ino=0),
        lambda d: d["capture"]["modules"][0].update(path="/opt/other.so"),
        lambda d: d["evidence"]["discovery"].append(copy.deepcopy(MODULE_FIXTURE)),
    ):
        bad = copy.deepcopy(clean)
        mutate(bad)
        rejected(lambda bad=bad: exact_capture_modules(bad))
    print("capture.modules[] matches the discovery record exactly: OK")

    # Per-function attribution: to a module the document declares, or to nobody
    # with the reason stated. Nothing in between.
    for mutate in (
        lambda d: d["functions"][0]["module"].update(ino=999),
        lambda d: d["functions"][0].update(module=None, module_ambiguous=False),
        lambda d: d["functions"][0].update(module_ambiguous=True),
        lambda d: d["functions"][0]["module"].update(sha256=None),
    ):
        bad = copy.deepcopy(clean)
        mutate(bad)
        rejected(lambda bad=bad: exact_capture_modules(bad))
    unattributed = copy.deepcopy(clean)
    unattributed["functions"][0].update(module=None, module_ambiguous=True)
    exact_capture_modules(unattributed)
    print("every count is attributed to a declared module or to nobody: OK")
    print("self-test: OK")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return
    require(len(argv) >= 1, "usage: check-capture-evidence.py MODE ...")
    if argv[0] == "clean-metrics" and len(argv) in (3, 4):
        multiplier = int(argv[3]) if len(argv) == 4 else 1
        validate_clean_metrics(load_json(argv[1]), expected_counts(argv[2]), multiplier)
    elif argv[0] == "canary" and len(argv) == 3:
        trace = argv[1].endswith("-trace")
        validate_canary(argv[1], load_canary(argv[2], trace))
    elif argv[0] == "induced" and len(argv) == 3:
        validate_induced(argv[1], load_json(argv[2]))
    else:
        raise AssertionError("usage: check-capture-evidence.py clean-metrics OUTPUT EXPECTED [MULTIPLIER] | canary LANE OUTPUT | induced G[1-5] OUTPUT | --self-test")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        print(f"capture evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
