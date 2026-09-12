#!/usr/bin/env python3
"""Validate canary capture evidence without import-time side effects."""

import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import re
import runpy
import struct
import subprocess
import sys
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent

REGISTERED = 0x250
ALIASES_BY_BITS = {
    32: {
        "mechanism": 0xF0010101,
        "pss_hash": 0xF0020201,
        "pss_mgf": 0xF0030301,
        "pss_salt": 0xF0040401,
        "gcm220_iv": 0xF0050501,
        "gcm220_aad": 0xF0060601,
        "gcm220_tag": 0xF0070701,
        "gcm240_iv": 0xF0080801,
        "gcm240_aad": 0xF0090901,
        "gcm240_tag": 0xF00A0A01,
        "template_type": 0xF00B0B01,
    },
    64: {
        "mechanism": 0xF001000000000101,
        "pss_hash": 0xF002000000000201,
        "pss_mgf": 0xF003000000000301,
        "pss_salt": 0xF004000000000401,
        "gcm220_iv": 0xF005000000000501,
        "gcm220_aad": 0xF006000000000601,
        "gcm220_tag": 0xF007000000000701,
        "gcm240_iv": 0xF008000000000801,
        "gcm240_aad": 0xF009000000000901,
        "gcm240_tag": 0xF00A000000000A01,
        "template_type": 0xF00B000000000B01,
    },
}


def target_oracle(bits):
    return dict(ALIASES_BY_BITS[bits]), (1 << bits) - 1


ALIASES = None
MAXIMUM = None
UNKNOWN = None
POLICY_BOOLEANS = {
    "CKA_TOKEN", "CKA_PRIVATE", "CKA_SENSITIVE", "CKA_ENCRYPT",
    "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP", "CKA_SIGN", "CKA_VERIFY",
    "CKA_DERIVE", "CKA_EXTRACTABLE",
}
POLICY_BOOLEAN_TYPES = (
    0x01, 0x02, 0x103, 0x104, 0x105, 0x106,
    0x107, 0x108, 0x10A, 0x10C, 0x162,
)
# The owned-map inventory is read from the one checked-in BPF list rather than
# frozen again here: a second copy went stale across Slice 1b-2 (11 names
# against the observer's 15) and every map missing from it was a map this
# matrix never scanned.
BPF_MAP_DEFS = None
SAFE_MAPS = None
FEATURE_MAPS = None
EXPECTED_SENTINEL_FAMILIES = {
    "PIN", "KEY", "LABEL", "ID", "PLAINTEXT", "IV", "AAD", "BOOLLONG",
    "USERNAME", "CIPHERTEXT", "SIGNATURE", "WRAPPED", "RANDOM", "OUTPUT",
    "ARG7", "ARG8", "ARG9", "ASYNC", "INTERFACE", "UNTERMINATED",
    "INTERFACEALIAS",
}
EXPECTED_SOURCE_FAMILIES = {
    "canary_workload.c": EXPECTED_SENTINEL_FAMILIES - {"ASYNC"},
    "privacy-stack-workload.c": {
        "PIN", "USERNAME", "KEY", "LABEL", "SIGNATURE", "ASYNC", "OUTPUT",
        "ARG7", "ARG8", "ARG9",
    },
}


def fixture_sentinels():
    by_family = {}
    for source in (SCRIPT_DIR / "fixtures/canary_workload.c",
                   SCRIPT_DIR / "fixtures/privacy-stack-workload.c"):
        found = re.findall(rb'"(CANARY_[A-Za-z0-9_]+)"', source.read_bytes())
        assert len(found) == len(set(found)), f"duplicate canary literal in {source}"
        families = {value.split(b"_", 2)[1].decode() for value in found}
        assert families == EXPECTED_SOURCE_FAMILIES[source.name], (
            source, families, EXPECTED_SOURCE_FAMILIES[source.name]
        )
        for value in found:
            family = value.split(b"_", 2)[1].decode()
            prior = by_family.setdefault(family, value)
            assert prior == value, f"conflicting {family} canaries: {prior!r}, {value!r}"
    assert set(by_family) == EXPECTED_SENTINEL_FAMILIES, (
        set(by_family), EXPECTED_SENTINEL_FAMILIES
    )
    return by_family


SENTINELS = None


def initialize(bits):
    """Initialize width-dependent policy and checked-in source inputs."""
    global ALIASES, MAXIMUM, UNKNOWN, BPF_MAP_DEFS, SAFE_MAPS, FEATURE_MAPS, SENTINELS
    if bits not in (32, 64):
        raise ValueError("target bits must be 32 or 64")
    ALIASES, MAXIMUM = target_oracle(bits)
    UNKNOWN = ALIASES["mechanism"]
    BPF_MAP_DEFS = runpy.run_path(
        str(SCRIPT_DIR / "check-bpf-map-defs.py"), run_name="canary_map_inventory"
    )
    SAFE_MAPS = set(BPF_MAP_DEFS["SAFE_MAPS"])
    FEATURE_MAPS = set(BPF_MAP_DEFS["UNSAFE_MAPS"])
    SENTINELS = fixture_sentinels() | {
        "ASYNC_ALIAS": b"AliasAsync_7a91c45d", "LEGACY_NAME": b"C_Encrypu",
    }
HEX_TOKEN = re.compile(rb"0x([0-9a-fA-F]{2})(?![0-9a-fA-F])")
MECH_NONE = (1 << 64) - 1
FUNCTION_NONE = (1 << 32) - 1
ARG_READ_FAILURE = 1 << 4
CALL_START_SIZE = 288
EVENT_SIZE = 328
DISCOVERY_RECORD_SIZE = 920
# Every owned ringbuf, with the exact record length its mmap oracle accepts.
# Keyed by name only because a record layout is per-map; which maps are
# ringbufs is decided by `type`, from the one checked-in BPF inventory.
RING_RECORD_SIZES = {"EVENTS": EVENT_SIZE, "DISCOVERY": DISCOVERY_RECORD_SIZE}
START_SNAPSHOT_LANES = {
    "default-safe-start", "feature-safe-start", "feature-unsafe-fault",
}
OWNED_METRICS_LANES = {"owned-default-metrics", "owned-feature-metrics"}


# Loader and pause identities the observer holds privately. None of them may
# reach profile/metrics JSON, trace output, an observer or workload log,
# private temporary output, or an observer-owned map value (design §9.3, §9.4).
LOADER_PAUSE_IDENTITIES = {
    "attach_cookie": 0x5C00_11E5_0000_0200,
    "context_id": 0xFA,
    "delta": -4096,
    "absent_state_sentinel": 512,
    "process_generation": 0x0000_0007_C0FF_EE01,
    "child_pid": 4242424,
    "child_tid": 4242425,
    "r_debug_vaddr": 0x7FFF_F7FF_E180,
    "hook_ip": 0x7FFF_F7FE_1B00,
    "marker": 0xDEAD_BEEF_CAFE_F00D,
    "loader_path": "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "loader_sha256": "ab" * 32,
    "loader_build_id": "aabbccddeeff0011",
    "interface_name_bytes": "PKCS 11",
}
# A narrow value's raw 64-bit word is the same byte run any zero-padded small
# integer produces — `512` little-endian is indistinguishable from the padding
# around a `2` in an adjacent map slot — so scanning for it would fire on every
# clean dump and mask the leaks that matter. Narrow values are therefore
# searched in the spellings a leak actually takes in text (JSON, trace, logs),
# while wide distinctive values are searched raw as well; the checker's exact
# key sets are what close the structural case.
DISTINCTIVE_FLOOR = 1 << 20


def identity_patterns(values):
    patterns = []
    for value in values:
        if isinstance(value, str):
            patterns.append(value.encode())
            continue
        word = value & ((1 << 64) - 1)
        patterns.append(f"0x{word:x}".encode())
        patterns.append(f"0x{word:016x}".encode())
        if abs(value) >= DISTINCTIVE_FLOOR:
            patterns.append(str(value).encode())
            patterns.append(struct.pack("<Q", word))
            patterns.append(struct.pack(">Q", word))
    return patterns


def assert_no_loader_pause_identity(label, data, values=None):
    values = list(LOADER_PAUSE_IDENTITIES.values()) if values is None else values
    if isinstance(data, str):
        data = data.encode()
    for pattern in identity_patterns(values):
        assert pattern not in data, f"{label} published loader/pause identity {pattern!r}"


# The published loader/pause field names, mirroring
# `scripts/check-capture-evidence.py`. Anything else in that namespace is an
# identity the capture document may not carry, wherever it appears.
PUBLISHED_LOADER_PAUSE_FIELDS = {
    "attach_gap_ms", "pause", "pause_attempts", "pause_confirmed",
    "pause_partial", "loader_discovery", "child_still_running",
}
IDENTITY_PREFIXES = ("pause", "loader", "child", "attach_gap")
IDENTITY_SUFFIXES = ("_pid", "_tid", "_tids", "_tasks", "_task_set")
STRING_IDENTITIES = [value for value in LOADER_PAUSE_IDENTITIES.values()
                     if isinstance(value, str)]
# A workload's own stderr legitimately names the interface it went looking for
# ("no exact PKCS 11 v3.2 table"). The prohibition binds what the *observer*
# publishes, so the target's own log is scanned for every identity except that
# one; every observer surface is scanned for all of them.
WORKLOAD_IDENTITIES = [value for name, value in LOADER_PAUSE_IDENTITIES.items()
                       if name != "interface_name_bytes"]
# `HH:MM:SS.ffffff pid P tid T [sess#N] FUNCTION[ MECHANISM] → CKR_x DURATION`
# (src/trace.rs). The two identity positions are captured so they can be
# removed structurally rather than by exempting the whole surface.
TRACE_EVENT = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{6} pid \d+ tid \d+ (?P<rest>.*)$")


def assert_json_identity_structure(label, value, path="$"):
    """Structural field check for a capture document.

    Keys are checked against the closed loader/pause namespace and strings
    against the loader path/digest/build-id/interface-name spellings. Numbers
    are deliberately not byte-scanned here: `rv_counts` keys, mechanism ids and
    latency totals are allowlisted arbitrary values whose spellings collide
    with a narrow private constant in a clean document, which is the false
    trigger the plan forbids. The checker's exact key sets and u64 ranges close
    the numeric case structurally instead.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            published = (
                key in PUBLISHED_LOADER_PAUSE_FIELDS
                or not (key.startswith(IDENTITY_PREFIXES)
                        or key.endswith(IDENTITY_SUFFIXES))
            )
            assert published, f"{label} publishes loader/pause identity {path}.{key}"
            assert_json_identity_structure(label, item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_json_identity_structure(label, item, f"{path}[{index}]")
    elif isinstance(value, str):
        assert_no_loader_pause_identity(f"{label} {path}", value, STRING_IDENTITIES)


def trace_scannable(label, text):
    """A trace with only its allowlisted call-event identity positions removed.

    `pid`/`tid` are published output for an ordinary call event, and only
    there. Scanning the whole surface would fire on a legitimate field;
    exempting the whole surface would mask a leak elsewhere in the same file.
    Every line must match one of the frozen shapes, so an unfrozen line cannot
    smuggle an identity past either.
    """
    kept = []
    for line in text.splitlines():
        if not line or line.startswith((
            "CAPTURE ", "COUNT_EVIDENCE ", "EVIDENCE ", "LOST "
        )):
            kept.append(line)
            continue
        event = TRACE_EVENT.match(line)
        assert event, f"{label} rendered an unfrozen trace line: {line!r}"
        kept.append(event.group("rest"))
    return "\n".join(kept)


def selection_terminal(ev):
    # This is a shallow privacy/shape guard. check-capture-evidence.py performs
    # the exact schema validation for every produced profile and terminal record.
    assert {
        "interface_selection", "attach_mechanisms", "pid_descendant_gaps",
        "multi_rebuild_gaps",
    } <= set(ev), ev
    selection = ev["interface_selection"]
    assert set(selection) == {
        "providers", "standard_exports", "inventory_surfaces", "tuples",
        "selection_truncated",
    }, selection
    assert all(isinstance(selection[name], list) for name in (
        "providers", "standard_exports", "inventory_surfaces", "tuples",
    )), selection
    assert isinstance(selection["selection_truncated"], bool), selection
    mechanisms = ev["attach_mechanisms"]
    assert mechanisms == sorted(set(mechanisms)), mechanisms
    assert set(mechanisms) <= {"per-offset", "uprobe-multi"}, mechanisms
    for name in ("pid_descendant_gaps", "multi_rebuild_gaps"):
        assert isinstance(ev[name], int) and not isinstance(ev[name], bool)
        assert 0 <= ev[name] <= (1 << 64) - 1, ev[name]


def exact_role_counts(description):
    assert description == {
        "observer_calls": 0, "inspect_calls": 0, "helper_calls": 10,
    }, description


def profile_terminal(doc, schema="pkcs11-scope/observed-profile/v3"):
    assert doc["schema"] == schema, doc["schema"]
    ev = doc["evidence"]
    assert "secret_selection_payload" not in ev, ev
    assert ev["completeness"] == "PARTIAL", ev
    assert isinstance(ev["task_uprobe_link_losses"], int) and not isinstance(
        ev["task_uprobe_link_losses"], bool
    ) and 0 <= ev["task_uprobe_link_losses"] <= (1 << 64) - 1, ev
    if schema == "pkcs11-scope/observed-profile/v3":
        selection_terminal(ev)


def trace_terminal(text, privacy):
    lines = text.splitlines()
    evidence = [index for index, line in enumerate(lines)
                if line.startswith("EVIDENCE ")]
    counts = [index for index, line in enumerate(lines)
              if line.startswith("COUNT_EVIDENCE ")]
    assert len(evidence) == 1, f"expected one terminal EVIDENCE record, got {len(evidence)}"
    assert len(counts) == 1, f"expected one COUNT_EVIDENCE record, got {len(counts)}"
    assert counts[0] + 1 == evidence[0], "COUNT_EVIDENCE must immediately precede EVIDENCE"
    count = json.loads(lines[counts[0]].removeprefix("COUNT_EVIDENCE "))
    assert set(count) == {"stats_entered", "stats_returned", "raw_calls"}, count
    assert all(isinstance(value, int) and not isinstance(value, bool)
               and 0 <= value <= (1 << 64) - 1 for value in count.values()), count
    ev = json.loads(lines[evidence[0]].removeprefix("EVIDENCE "))
    assert ev["privacy_mode"] == privacy, ev
    assert ev["completeness"] == "PARTIAL", ev
    assert ev["capture_aborted"] is None, ev
    assert ev["final_drain"] is False, ev
    assert ev["counters_available"] is True, ev
    selection_terminal(ev)
    return ev


def trace_abort_terminal(text, privacy):
    counts = [line for line in text.splitlines()
              if line.startswith("COUNT_EVIDENCE ")]
    assert not counts, f"expected no abort COUNT_EVIDENCE record, got {len(counts)}"
    records = [line.removeprefix("EVIDENCE ") for line in text.splitlines()
               if line.startswith("EVIDENCE ")]
    assert len(records) == 1, f"expected one terminal abort EVIDENCE record, got {len(records)}"
    ev = json.loads(records[0])
    assert ev == {
        "completeness": "PARTIAL",
        "privacy_mode": privacy,
        "capture_aborted": "object_lease_break",
        "final_drain": False,
        "counters_available": False,
        "event_loss": None,
    }, ev
    return ev


def mechanism_map(doc):
    return {item["mechanism"]: item for item in doc["mechanisms"]}


def assert_safe_profile(doc):
    assert doc["capture"]["mode"] == "profile", doc["capture"]
    assert doc["capture"]["privacy_mode"] == "allowlisted", doc["capture"]
    profile_terminal(doc)
    mechanisms = mechanism_map(doc)
    assert REGISTERED in mechanisms, "registered standard mechanism was not useful"
    assert UNKNOWN not in mechanisms and MAXIMUM not in mechanisms, mechanisms.keys()
    assert all(item["params"] is None for item in mechanisms.values()), mechanisms
    assert doc["templates"]["operations"] == [], doc["templates"]
    ev = doc["evidence"]
    assert ev["unregistered_mechanisms"] == 2, ev
    assert ev["semantic_capture_failures"] == 3, ev
    assert ev["async_target_failures"] == 2, ev


def assert_safe_trace(text):
    assert text.startswith("CAPTURE privacy=allowlisted\n"), text[:200]
    ev = trace_terminal(text, "allowlisted")
    events = [line for line in text.splitlines()
              if line and not line.startswith((
                  "CAPTURE ", "COUNT_EVIDENCE ", "EVIDENCE ", "LOST "
              ))]
    assert events, "safe trace has no rendered call"
    assert "C_DigestInit 0x250" in text, "registered mechanism missing from trace"
    for value in set(ALIASES.values()) | {MAXIMUM}:
        assert str(value) not in text and f"0x{value:x}" not in text, value
    assert ev["unregistered_mechanisms"] == 2, ev
    assert ev["semantic_capture_failures"] == 3, ev
    assert ev["async_target_failures"] == 2, ev


def assert_unsafe_profile(doc):
    assert doc["capture"]["mode"] == "profile", doc["capture"]
    assert doc["capture"]["privacy_mode"] == "unsafe-unvalidated-metadata"
    profile_terminal(doc)
    mechanisms = mechanism_map(doc)
    for mechanism in (REGISTERED, UNKNOWN, MAXIMUM, 0xD, 0x1087):
        assert mechanism in mechanisms, f"diagnostic profile missed {mechanism:#x}"
    assert doc["evidence"]["unregistered_mechanisms"] == 0

    pss = mechanisms[0xD]["params"]
    assert pss == [{
        "shape": "rsa_pkcs_pss", "hash_alg": ALIASES["pss_hash"],
        "hash_alg_hex": f"0x{ALIASES['pss_hash']:x}", "mgf": ALIASES["pss_mgf"],
        "salt_len": ALIASES["pss_salt"], "count": 1,
    }], pss
    gcm = {(item["layout"], item["iv_len"], item["aad_len"], item["tag_bits"])
           for item in mechanisms[0x1087]["params"]}
    assert gcm == {
        ("v2.20", ALIASES["gcm220_iv"], ALIASES["gcm220_aad"], ALIASES["gcm220_tag"]),
        ("v2.40", ALIASES["gcm240_iv"], ALIASES["gcm240_aad"], ALIASES["gcm240_tag"]),
    }, gcm

    operations = [item for item in doc["templates"]["operations"]
                  if "C_CreateObject" in item["names"]]
    assert len(operations) == 1, operations
    operation = operations[0]
    assert operation["requested"] is True
    attr_types = {item["attr_type"] for item in operation["attr_types"]}
    assert ALIASES["template_type"] in attr_types, attr_types
    assert set(operation["policy_booleans"]["observed_true"]) == POLICY_BOOLEANS
    assert operation["policy_booleans"]["observed_false"] == []
    faults = {item["names"][0]: item for item in doc["templates"]["operations"]
              if item["names"] in (["C_CopyObject"], ["C_SetAttributeValue"])}
    assert set(faults) == {"C_CopyObject", "C_SetAttributeValue"}, faults
    for name, attr_type in (("C_CopyObject", 2), ("C_SetAttributeValue", 1)):
        fault = faults[name]
        assert [item["attr_type"] for item in fault["attr_types"]] == [attr_type], fault
        assert fault["policy_booleans"] == {
            "observed_true": [], "observed_false": []
        }, fault
    ev = doc["evidence"]
    assert ev["semantic_capture_failures"] == 7, ev
    assert ev["async_target_failures"] == 2, ev
    assert ev["templates_truncated"] is False, ev


def assert_unsafe_trace(text):
    assert text.startswith("CAPTURE privacy=unsafe-unvalidated-metadata\n"), text[:200]
    ev = trace_terminal(text, "unsafe-unvalidated-metadata")
    for value in [UNKNOWN, MAXIMUM, *[ALIASES[name] for name in (
        "pss_hash", "pss_mgf", "pss_salt", "gcm220_iv", "gcm220_aad",
        "gcm220_tag", "gcm240_iv", "gcm240_aad", "gcm240_tag")]]:
        assert str(value) in text or f"0x{value:x}" in text, f"trace missed {value:#x}"
    assert ev["semantic_capture_failures"] == 7, ev
    assert ev["async_target_failures"] == 2, ev


def _assert_aggregate_metrics(doc, expected_calls):
    assert set(doc) == {"schema", "capture", "evidence", "functions"}, doc
    assert doc["schema"] == "pkcs11-scope/observed-profile/v3-metrics"
    assert doc["capture"]["mode"] == "metrics"
    assert doc["capture"]["privacy_mode"] == "aggregate-only"
    assert "secret_selection_payload" not in doc["evidence"], doc["evidence"]
    profile_terminal(doc, "pkcs11-scope/observed-profile/v3-metrics")
    assert sum(item["calls"] for item in doc["functions"]) == expected_calls, doc["functions"]


def assert_aggregate_metrics(doc):
    _assert_aggregate_metrics(doc, 28)


def assert_owned_aggregate_metrics(doc):
    _assert_aggregate_metrics(doc, 30)


def assert_scan_only_hostile_output(doc, text, hostile):
    """The scan-only COUNT_ONLY rendering contract, independent of live BPF."""
    assert doc["capture"]["mode"] == "profile", doc["capture"]
    assert doc["capture"]["privacy_mode"] == "allowlisted", doc["capture"]
    profile_terminal(doc)
    evidence = doc["evidence"]
    assert evidence["table_entries"] == evidence["slots"] == 1, evidence
    assert evidence["attached_probes"] == 2, evidence
    assert evidence["surfaces"] == [{
        "source": "/opt/p11.so table 2.40", "walk": "full", "acquisition": "ok", "functions": 1,
    }], evidence
    assert len(evidence["discovery"]) == 1, evidence
    discovered = evidence["discovery"][0]
    module = {"dev": [8, 1], "ino": 42, "sha256": "11" * 32}
    assert {field: discovered[field] for field in module} == module, discovered
    assert discovered["sources"] == ["scan"], discovered
    assert discovered["tables"] == [
        {"version": [2, 40], "entries": 1, "source": "scan"},
    ], discovered
    assert doc["capture"]["modules"] == [{
        **module, "path": "/opt/p11.so", "build_id": "aabb",
    }], doc["capture"]
    assert doc["functions"] == [{
        "names": ["C_OpenSession"], "aliased": False, "module": module,
        # The owner relation is exclusive: an owned cell states both reasons
        # false, so a leaked owner key cannot hide behind a missing field.
        "module_ambiguous": False, "module_unresolved": False,
        "calls": 25, "errors": 3,
        "pending_returns": 5, "in_flight": 0,
        "latency_ns": {
            "approximate": True, "p50": 64, "p95": 64, "p99": 64,
            "total": 2500, "max": 100,
        },
        "rv_counts": {
            "0x0000000000000000": 17,
            "0x0000000000000005": 3,
            "0x0000000000000204": 5,
        },
    }], doc["functions"]
    assert doc["mechanisms"] == [], doc["mechanisms"]
    assert doc["sessions"] == {
        "opened": 0, "inherited": 0, "closed": 0, "async_opened": 0,
        "peak_concurrent": 0, "balance": 0,
    }, doc["sessions"]
    assert doc["logins"] == {}, doc["logins"]
    assert doc["templates"]["operations"] == [], doc["templates"]
    assert doc["cgroups"] == [{
        "cgroup_id": 7, "label": None, "calls": 25, "errors": 3,
        "mechanisms": [],
    }], doc["cgroups"]
    rendered = json.dumps(doc, sort_keys=True) + "\n" + text
    for sentinel in hostile:
        assert sentinel not in rendered, f"scan-only output leaked {sentinel}"
    assert text.startswith("CAPTURE privacy=allowlisted\n"), text[:200]
    terminal = trace_terminal(text, "allowlisted")
    assert terminal["table_entries"] == terminal["slots"] == 1, terminal
    assert terminal["attached_probes"] == 2, terminal
    assert terminal["semantic_capture_failures"] == 0, terminal
    events = [line for line in text.splitlines()
              if line and not line.startswith((
                  "CAPTURE ", "COUNT_EVIDENCE ", "EVIDENCE ", "LOST "
              ))]
    assert events == [
        "00:00:00.000000 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_OK 100ns",
        "00:00:00.000001 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_GENERAL_ERROR 100ns",
        "00:00:00.000024 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_PENDING 100ns",
    ], events


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def bpftool_bytes(value, expected):
    assert isinstance(value, list) and all(
        isinstance(item, str) and re.fullmatch(r"0x[0-9a-fA-F]{2}", item)
        for item in value
    ), value
    raw = bytes(int(item, 16) for item in value)
    assert len(raw) == expected, f"bpftool blob is {len(raw)} bytes, expected {expected}"
    return raw


def u64(raw, offset):
    return struct.unpack_from("<Q", raw, offset)[0]


def u32(raw, offset):
    return struct.unpack_from("<I", raw, offset)[0]


def decode_start(raw):
    assert len(raw) == CALL_START_SIZE
    assert u64(raw, 264) == 0, "CallStart padding must be zero"
    return {
        "raw": raw, "session": u64(raw, 8), "slot_id": u64(raw, 16),
        "mechanism": u64(raw, 24), "mechanism_ptr": u64(raw, 32),
        "flags": u64(raw, 40), "out_ptr": u64(raw, 48),
        "user_type": u32(raw, 56), "shape": u32(raw, 60),
        "p0": u64(raw, 64), "p1": u64(raw, 72), "p2": u64(raw, 80),
        "async_value": u64(raw, 88),
        "attrs": struct.unpack_from("<8Q", raw, 96), "attr_count": u32(raw, 160),
        "attr_total": u32(raw, 164), "attr_bools": u32(raw, 168),
        "attr_seen": u32(raw, 172), "attrs1": struct.unpack_from("<8Q", raw, 176),
        "attr_count1": u32(raw, 240), "attr_total1": u32(raw, 244),
        "attr_bools1": u32(raw, 248), "attr_seen1": u32(raw, 252),
        "capture": u32(raw, 256), "target": u32(raw, 260),
    }


def decode_event(raw):
    assert len(raw) == EVENT_SIZE
    root_affiliation = u64(raw, 320)
    assert root_affiliation in (0, 1), f"invalid root affiliation {root_affiliation}"
    return {
        "raw": raw, "pid_tgid": u64(raw, 16), "session": u64(raw, 32),
        "mechanism": u64(raw, 48), "p0": u64(raw, 72), "p1": u64(raw, 80),
        "p2": u64(raw, 88), "slot": u32(raw, 104), "target": u32(raw, 108),
        "shape": u32(raw, 116), "attrs": struct.unpack_from("<8Q", raw, 120),
        "attr_count": u32(raw, 184), "attr_total": u32(raw, 188),
        "attr_bools": u32(raw, 192), "attr_seen": u32(raw, 196),
        "attrs1": struct.unpack_from("<8Q", raw, 200),
        "attr_count1": u32(raw, 264), "attr_total1": u32(raw, 268),
        "attr_bools1": u32(raw, 272), "attr_seen1": u32(raw, 276),
        "capture": u32(raw, 280), "event_type": u32(raw, 284),
        "root_affiliation": root_affiliation,
    }


def zero_metadata(record):
    return (record["shape"], record["p0"], record["p1"], record["p2"],
            *record["attrs"], record["attr_count"], record["attr_total"],
            record["attr_bools"], record["attr_seen"], *record["attrs1"],
            record["attr_count1"], record["attr_total1"],
            record["attr_bools1"], record["attr_seen1"]) == (0,) * 28


def manifest_map(path, name):
    matches = [item for item in read_json(path) if item["name"] == name]
    assert len(matches) == 1, f"expected one {name} in {path}, got {matches}"
    return matches[0]


def assert_async_targets(records):
    rows = [record for record in records
            if record["session"] in {0x11d, 0x11e, 0x11f, 0x302, 0x303, 0x304}]
    by_session = {record["session"]: record for record in rows}
    assert len(rows) == len(by_session), "duplicate async identity records"
    expected = {0x11d: 30, 0x11e: FUNCTION_NONE, 0x11f: FUNCTION_NONE}
    if 0x302 in by_session:
        expected = {0x302: 30, 0x303: FUNCTION_NONE, 0x304: FUNCTION_NONE}
    assert set(by_session) == set(expected), (set(by_session), set(expected))
    assert {session: by_session[session]["target"] for session in expected} == expected


def assert_hostile_records(starts, pointers):
    assert len(starts) == 4, f"hostile START has {len(starts)} entries"
    by_session = {start["session"]: start for start in starts}
    assert set(by_session) == {0x301, 0x302, 0x303, 0x304}, set(by_session)
    for start in starts:
        assert start["mechanism"] == MECH_NONE and zero_metadata(start), start
        assert (start["slot_id"], start["flags"], start["out_ptr"],
                start["user_type"], start["async_value"]) == (
                    0, 0, 0, (1 << 32) - 1, 0
                ), start
        assert struct.pack("<Q", UNKNOWN) not in start["raw"]
    assert_async_targets(starts)
    assert {session: by_session[session]["mechanism_ptr"] for session in by_session} == {
        0x301: pointers["unknown_mechanism"], 0x302: 0, 0x303: 0, 0x304: 0,
    }
    assert {session: by_session[session]["capture"] for session in by_session} == {
        0x301: 0, 0x302: 0, 0x303: ARG_READ_FAILURE, 0x304: ARG_READ_FAILURE,
    }
    assert all(isinstance(pointer, int) and pointer > 0 for pointer in pointers.values())
    assert len(set(pointers.values())) == 4, pointers
    meaningful = b"".join(start["raw"][:268] for start in starts)
    for name, pointer in pointers.items():
        encoded = struct.pack("<Q", pointer)
        expected = 1 if name == "unknown_mechanism" else 0
        assert meaningful.count(encoded) == expected, (name, pointer, expected)
    encoded_unknown = struct.pack("<Q", pointers["unknown_mechanism"])
    assert by_session[0x301]["raw"][:268].find(encoded_unknown) == 32


def assert_hostile_starts(manifest, workload_log, workload_pid):
    item = manifest_map(manifest, "START")
    assert item["oracle"] == "dump" and item["type"] == "hash", item
    entries = read_json(item["file"])
    starts = []
    for entry in entries:
        key = bpftool_bytes(entry["key"], 16)
        assert u64(key, 0) >> 32 == workload_pid, (u64(key, 0), workload_pid)
        starts.append(decode_start(bpftool_bytes(entry["value"], CALL_START_SIZE)))
    log_lines = [line.removeprefix("P11SCOPE_POINTERS ")
                 for line in Path(workload_log).read_text().splitlines()
                 if line.startswith("P11SCOPE_POINTERS ")]
    assert len(log_lines) == 1, log_lines
    assert_hostile_records(starts, json.loads(log_lines[0]))


def value_total(value):
    if isinstance(value, dict):
        encoded = value.get("value")
        if isinstance(encoded, list) and encoded and all(isinstance(item, str) for item in encoded):
            raw = bytes(int(item, 16) for item in encoded)
            assert len(raw) % 8 == 0, len(raw)
            return sum(struct.unpack(f"<{len(raw) // 8}Q", raw))
        return sum(value_total(child) for child in value.values())
    if isinstance(value, list):
        return sum(value_total(child) for child in value)
    return 0


def assert_fault_records(starts, evidence_total):
    assert len(starts) == 2, f"fault START has {len(starts)} entries"
    by_session = {start["session"]: start for start in starts}
    assert set(by_session) == {0x401, 0x402}, set(by_session)
    for session, attr_type in ((0x401, 2), (0x402, 1)):
        start = by_session[session]
        assert start["attrs"] == (attr_type, 0, 0, 0, 0, 0, 0, 0), start
        assert (start["attr_count"], start["attr_total"]) == (1, 1), start
        assert (start["attr_bools"], start["attr_seen"]) == (0, 0), start
        assert start["capture"] & ARG_READ_FAILURE, start
    assert evidence_total == 2, evidence_total


def assert_fault_starts(manifest, workload_pid):
    start_item = manifest_map(manifest, "START")
    entries = read_json(start_item["file"])
    starts = []
    for entry in entries:
        key = bpftool_bytes(entry["key"], 16)
        assert u64(key, 0) >> 32 == workload_pid
        starts.append(decode_start(bpftool_bytes(entry["value"], CALL_START_SIZE)))
    evidence = read_json(manifest_map(manifest, "EVIDENCE")["file"])
    cells = [entry for entry in evidence if u32(bpftool_bytes(entry["key"], 4), 0) == 5]
    assert len(cells) == 1, cells
    assert_fault_records(starts, value_total(cells[0].get("values", [])))


def ring_raw_path(prefix, name):
    """Where a ringbuf's mmap-oracled records land for the privacy scan."""
    return Path(f"{prefix}.{name}.raw")


def parse_ring_records(data, capacity, consumer_pos, producer_pos,
                       record_length=EVENT_SIZE):
    assert capacity >= mmap.PAGESIZE and capacity & (capacity - 1) == 0
    assert capacity % mmap.PAGESIZE == 0 and len(data) == 2 * capacity
    assert producer_pos >= consumer_pos, "ring position wrap cannot be proved"
    assert producer_pos - consumer_pos <= capacity, "ring data was overwritten"
    records = []
    position = consumer_pos
    while position < producer_pos:
        offset = position & (capacity - 1)
        header = u32(data, offset)
        assert not header & (1 << 31), "BUSY ring record"
        assert not header & (1 << 30), "discarded ring record"
        length = header & ((1 << 30) - 1)
        assert length == record_length, f"ring record size {length}, expected {record_length}"
        record_size = (8 + length + 7) & ~7
        assert position + record_size <= producer_pos
        records.append(bytes(data[offset + 8:offset + 8 + length]))
        position += record_size
    assert position == producer_pos
    return records


class RetainedRingReader:
    """Own one ring map FD and both read-only mappings across an acquisition."""

    def __init__(self, item):
        assert platform.machine() == "x86_64", "raw ring oracle requires Linux x86-64"
        assert isinstance(item, dict) and item.get("oracle") == "mmap" and "file" not in item, item
        assert (item.get("type"), item.get("key_size"), item.get("value_size")) == (
            "ringbuf", 0, 0), item
        assert (type(item.get("id")) is int and item["id"] > 0
                and item.get("name") in RING_RECORD_SIZES), item
        capacity = item.get("max_entries")
        assert (type(capacity) is int and capacity >= mmap.PAGESIZE
                and capacity & (capacity - 1) == 0
                and capacity % mmap.PAGESIZE == 0), item
        self.item = item
        self.fd = None
        self.consumer = None
        self.producer = None
        map_id = item["id"]
        attr = ctypes.create_string_buffer(struct.pack("=III", map_id, 0, 0))
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.syscall(321, 14, ctypes.byref(attr), ctypes.sizeof(attr))
        if self.fd < 0:
            self.fd = None
            error = ctypes.get_errno()
            raise OSError(error, f"BPF_MAP_GET_FD_BY_ID for {item['name']} id {map_id}")
        page = mmap.PAGESIZE
        try:
            self.consumer = mmap.mmap(self.fd, page, flags=mmap.MAP_SHARED,
                                      prot=mmap.PROT_READ, offset=0)
            self.producer = mmap.mmap(
                self.fd, page + 2 * capacity, flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ, offset=page)
        except BaseException:
            self._close(preserve_error=True)
            raise

    def positions(self):
        if self.consumer is None or self.producer is None:
            raise RuntimeError("retained ring reader is closed")
        return u64(self.consumer, 0), u64(self.producer, 0)

    def read_records(self, positions=None):
        if self.producer is None:
            raise RuntimeError("retained ring reader is closed")
        positions = self.positions() if positions is None else positions
        if (not isinstance(positions, tuple) or len(positions) != 2
                or any(type(position) is not int or position < 0 for position in positions)):
            raise RuntimeError("invalid retained ring positions")
        page = mmap.PAGESIZE
        return parse_ring_records(
            self.producer[page:], self.item["max_entries"], *positions,
            RING_RECORD_SIZES[self.item["name"]])

    def _close(self, *, preserve_error=False):
        cleanup_error = None
        resources = (self.producer, self.consumer, self.fd)
        self.producer = self.consumer = self.fd = None
        for resource in resources:
            if resource is None:
                continue
            try:
                resource.close() if hasattr(resource, "close") else os.close(resource)
            except Exception as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and not preserve_error:
            raise cleanup_error

    def close(self):
        self._close()

    def __enter__(self):
        return self

    def __exit__(self, error_type, _error, _traceback):
        self._close(preserve_error=error_type is not None)
        return False


def ring_records(manifest, name="EVENTS"):
    item = dict(manifest_map(manifest, name))
    item.setdefault("name", name)
    with RetainedRingReader(item) as reader:
        before = reader.positions()
        records = reader.read_records(before)
        after = reader.positions()
        assert after == before, f"ring moved during snapshot: {before} -> {after}"
        return records


def assert_event_records(raw_records, lane, workload_pid):
    expected = 0 if lane == "aggregate-only-metrics" or lane in OWNED_METRICS_LANES else 28
    assert len(raw_records) == expected, f"{lane}: {len(raw_records)} records, expected {expected}"
    if not raw_records:
        return
    events = [decode_event(raw) for raw in raw_records]
    assert all(event["pid_tgid"] >> 32 == workload_pid for event in events)
    assert all(event["event_type"] == 0 for event in events)
    assert_async_targets(events)
    if "unsafe" not in lane:
        assert all(zero_metadata(event) for event in events), lane
        mechanisms = {event["mechanism"] for event in events}
        assert mechanisms <= {MECH_NONE, REGISTERED, 0xD, 0x1087}, mechanisms
        assert {REGISTERED, 0xD, 0x1087} <= mechanisms
        return
    mechanisms = {event["mechanism"] for event in events}
    assert {REGISTERED, UNKNOWN, MAXIMUM, 0xD, 0x1087} <= mechanisms, mechanisms
    pss = [(event["shape"], event["p0"], event["p1"], event["p2"])
           for event in events
           if event["mechanism"] == 0xD and event["shape"] != 0]
    assert pss == [(1, ALIASES["pss_hash"], ALIASES["pss_mgf"], ALIASES["pss_salt"])], pss
    gcm = {(event["shape"], event["p0"], event["p1"], event["p2"])
           for event in events
           if event["mechanism"] == 0x1087 and event["shape"] != 0}
    assert gcm == {
        (3, ALIASES["gcm220_iv"], ALIASES["gcm220_aad"], ALIASES["gcm220_tag"]),
        (4, ALIASES["gcm240_iv"], ALIASES["gcm240_aad"], ALIASES["gcm240_tag"]),
    }, gcm
    templates = [event for event in events
                 if event["attrs"][0] == ALIASES["template_type"]]
    assert [(event["attrs"], event["attr_count"], event["attr_total"],
             event["attr_bools"], event["attr_seen"]) for event in templates] == [
        ((ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[:6], 0), 7, 7, 0x3F, 0x3F),
        ((ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[6:], 0, 0), 6, 6, 0x7C0, 0x7C0),
    ], templates
    faults = [event for event in events
              if event["attrs"][0] in {1, 2}
              and event["capture"] & ARG_READ_FAILURE]
    assert sorted(event["attrs"][0] for event in faults) == [1, 2], faults
    for event in faults:
        assert (event["attr_count"], event["attr_total"], event["attr_bools"],
                event["attr_seen"]) == (1, 1, 0, 0), event


def assert_start_event_records(raw_records, lane):
    assert lane in START_SNAPSHOT_LANES, lane
    assert not raw_records, (
        f"{lane}: blocked START snapshot contains {len(raw_records)} completed EVENTS"
    )


def assert_retained_ring_records(retained, lane, workload_pid):
    """Validate already-retained ring bytes without opening or mapping BPF maps."""
    assert isinstance(retained, dict) and set(retained) == set(RING_RECORD_SIZES), retained
    for name, expected_size in RING_RECORD_SIZES.items():
        records = retained[name]
        assert isinstance(records, list), (name, type(records).__name__)
        assert all(type(record) is bytes and len(record) == expected_size for record in records), name
    if lane in START_SNAPSHOT_LANES:
        assert_start_event_records(retained["EVENTS"], lane)
    else:
        assert_event_records(retained["EVENTS"], lane, workload_pid)
    if lane in OWNED_METRICS_LANES:
        assert retained["DISCOVERY"], f"{lane}: retained DISCOVERY is empty"


def assert_raw_records(manifest, lane, workload_pid, prefix):
    """Reads every owned ringbuf through the mmap oracle and keeps its bytes.

    `EVENTS` additionally gets its frozen per-call policy oracle; the rest are
    kept for the matrix scan, which is what makes a ringbuf a scanned privacy
    surface rather than a map the dump loop silently walked past.
    """
    retained = {}
    for item in read_json(manifest):
        if item["type"] != "ringbuf":
            continue
        records = ring_records(manifest, item["name"])
        retained[item["name"]] = records
        ring_raw_path(prefix, item["name"]).write_bytes(b"".join(records))
    assert_retained_ring_records(retained, lane, workload_pid)


def assert_stopped_snapshot(manifest, prefix):
    """Replay an opt-in V1 receipt against every surface actually scanned.

    Legacy Task 1/2 manifests remain usable while Task 3C is staged. Any row
    claiming snapshot evidence requires the complete contract on every row.
    Digests bind retained bytes, not the truth of process custody: only the
    retained-pidfd coordinator may issue a live qualification receipt.
    """
    api = runpy.run_path(str(SCRIPT_DIR / "dump-owned-bpf-maps.py"))
    uint = api["snapshot_uint"]
    maximum = api["TASK_STORAGE_MAX_BYTES"]
    context = "stopped snapshot"

    def require(condition, message):
        if not condition:
            raise RuntimeError(f"{context}: {message}")

    def read_bounded(path, bound):
        with Path(path).open("rb") as handle:
            raw = handle.read(bound + 1)
        require(len(raw) <= bound, "surface or receipt exceeds byte bound")
        return raw

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    def read_json_bytes(raw):
        return json.loads(raw, object_pairs_hook=unique_object)

    def byte_array(value, size):
        require(isinstance(value, list) and len(value) == size, "malformed control value")
        result = bytearray()
        for byte in value:
            if type(byte) is str and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{2}", byte):
                byte = int(byte, 16)
            require(uint(byte, 8), "malformed control value")
            result.append(byte)
        return bytes(result)

    try:
        require(isinstance(manifest, list) and 0 < len(manifest) <= 128,
                "invalid manifest bound")
        claim = manifest[0].get("snapshot")
        require(isinstance(claim, dict) and set(claim) == {
            "contract", "acquisition_id", "phase", "receipt"}, "incomplete claim")
        require(claim["contract"] == api["STOPPED_SNAPSHOT_CONTRACT"], "unknown contract")
        acquisition = claim["acquisition_id"]
        require(type(acquisition) is str and re.fullmatch(r"[0-9a-f]{32}", acquisition),
                "invalid acquisition identity")
        require(claim["phase"] == "stopped", "invalid receipt phase")
        require(type(claim["receipt"]) is str and len(claim["receipt"]) <= 4096
                and Path(claim["receipt"]).is_absolute(), "invalid receipt path")
        require(all(item.get("snapshot") == claim for item in manifest), "partial or mixed claim")
        receipt = read_json_bytes(read_bounded(claim["receipt"], 16 * 1024 * 1024))
        require(isinstance(receipt, dict) and set(receipt) == {
            "contract", "acquisition_id", "phase", "lane", "small_state",
            "expected", "before", "after", "surfaces"}, "incomplete roster receipt")
        require(all(receipt[key] == claim[key] for key in ("contract", "acquisition_id", "phase")),
                "receipt acquisition or phase mismatch")
        rows = receipt["surfaces"]
        require(isinstance(rows, list) and len(rows) == len(manifest), "incomplete surface set")
        require(all(isinstance(row, dict) and uint(row.get("id"), 32, positive=True)
                    for row in rows), "invalid surface identity")
        surfaces = {row["id"]: row for row in rows}
        require(len(surfaces) == len(rows), "duplicate surface identity")
        require(all(uint(item.get("id"), 32, positive=True) for item in manifest),
                "invalid map identity")
        require(set(surfaces) == {item["id"] for item in manifest}, "surface map identity mismatch")
        metadata_rows = [{"id": item.get("id"), "name": item.get("name"),
                          "type": item.get("type"), "oracle": item.get("oracle"),
                          "bytes_key": item.get("key_size"),
                          "bytes_value": item.get("value_size"),
                          "max_entries": item.get("max_entries"),
                          "map_flags": item.get("map_flags")}
                         for item in manifest]
        for metadata in metadata_rows:
            api["snapshot_map_metadata"](metadata)
        names = [metadata["name"] for metadata in metadata_rows]
        require(len(set(names)) == len(names), "duplicate map names")
        require(set(api["TASK_STORAGE_NAMES"]) | {
            "COOKIE_CTL", "OWNER_CTL", "ROOT_CTL", "START", "EVENTS", "DISCOVERY"
        } <= set(names), "missing required acquisition map")
        records, maps, controls = [], [], {}
        total = 0
        for item, metadata in zip(manifest, metadata_rows):
            name = metadata["name"]
            context = f"stopped map id={item['id']} name={name}"
            surface = surfaces[item["id"]]
            task_storage = metadata["type"] == "task_storage"
            fields = {"id", "acquisition_id", "phase", "size", "sha256"}
            require(set(surface) == fields | ({"records"} if task_storage else set()),
                    "malformed surface metadata")
            require(surface["acquisition_id"] == acquisition and surface["phase"] == "stopped",
                    "surface acquisition or phase mismatch")
            require(uint(surface["size"]) and surface["size"] <= maximum - total,
                    "surface exceeds aggregate byte bound")
            if metadata["type"] == "ringbuf":
                path = ring_raw_path(prefix, name)
            else:
                require(type(item.get("file")) is str and len(item["file"]) <= 4096,
                        "missing surface path")
                path = Path(item["file"])
            raw = read_bounded(path, surface["size"])
            require(len(raw) == surface["size"] and hashlib.sha256(raw).hexdigest() == surface["sha256"],
                    "surface size or digest mismatch")
            total += len(raw)
            if name == "START":
                require((item["type"], item["key_size"], item["value_size"],
                         item["max_entries"], item["map_flags"]) == (
                             "hash", 16, 288, 1 if receipt["small_state"] else 16384, 0),
                        "START metadata contradicts state-map configuration")
            elif name in ("EVENTS", "DISCOVERY"):
                require(item["type"] == "ringbuf" and item["oracle"] == "mmap"
                        and item["key_size"] == item["value_size"] == 0 and "file" not in item,
                        "invalid ring surface metadata")
            if task_storage:
                maps.append(metadata)
                identities = surface["records"]
                require(isinstance(identities, list)
                        and len(identities) <= api["TASK_STORAGE_MAX_RECORDS"] - len(records),
                        "invalid record population bound")
                size = item["value_size"]
                require(uint(size, 32, positive=True) and len(raw) == len(identities) * size,
                        "record population byte count mismatch")
                for index, identity in enumerate(identities):
                    require(isinstance(identity, dict) and set(identity) == {"pid", "tid", "generation"},
                            "malformed record identity")
                    records.append({**identity, "map_id": item["id"],
                                    "value": raw[index * size:(index + 1) * size]})
            elif name in ("COOKIE_CTL", "OWNER_CTL", "ROOT_CTL"):
                cells = read_json_bytes(raw)
                require(isinstance(cells, list) and len(cells) == 1
                        and isinstance(cells[0], dict) and set(cells[0]) == {"key", "value"},
                        "malformed control cell")
                require(byte_array(cells[0]["key"], 4) == bytes(4), "invalid control key")
                controls[name] = {**metadata, "value": byte_array(cells[0]["value"], item["value_size"])}
        api["reconcile_task_storage"](
            maps, records, expected=receipt["expected"], before=receipt["before"],
            after=receipt["after"], controls=controls, lane=receipt["lane"],
            small_state=receipt["small_state"])
    except RuntimeError as error:
        raise AssertionError(str(error)) from None
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        # Native/JSON exceptions may quote input or raw values. Never forward them.
        raise AssertionError("stopped snapshot: malformed or unavailable evidence") from None


def owned_map_surfaces(label, manifest, expected, prefix):
    """Every owned map paired with the file the privacy scan reads it from.

    Dispatch is by map *type*, never by name: a ringbuf has no key/value
    iteration, so `bpftool map dump` cannot read it at all and it is read
    through the mmap oracle instead, landing as its raw records; every other
    map is read as its `bpftool` dump. A map with no surface on disk is a
    failure, never a skip — an unscanned owned map is exactly the privacy hole
    this gate exists to close.
    """
    if any("snapshot" in item for item in manifest):
        assert_stopped_snapshot(manifest, prefix)
    names = {item["name"] for item in manifest}
    assert names == expected, f"{label}: map inventory {names} != {expected}"
    ids = [item['id'] for item in manifest]
    assert all(isinstance(map_id, int) and map_id > 0 for map_id in ids), ids
    assert len(ids) == len(set(ids)), f"{label}: duplicate observer-owned map ids {ids}"
    surfaces = []
    for item in manifest:
        if item["type"] == "ringbuf":
            assert item["oracle"] == "mmap" and "file" not in item, item
            assert item["key_size"] == item["value_size"] == 0, item
            path = ring_raw_path(prefix, item["name"])
        elif item["type"] == "task_storage":
            assert item["oracle"] == "task-storage", item
            path = Path(item.get("file", ""))
        else:
            assert item["oracle"] == "dump", item
            path = Path(item.get("file", ""))
        assert path.is_file(), f"{label}: {item['name']} has no scanned surface {path}"
        surfaces.append(path)
    return surfaces


def assert_exact_owned_map_inventory(work, lane, expected):
    return owned_map_surfaces(
        lane,
        read_json(f"{work}/mapdump_manifest_{lane}.json"),
        expected,
        f"{work}/{lane}",
    )


def alias_hits(content, reconstructed=b""):
    lower = content.lower()
    return {name for name, value in ALIASES.items()
            if str(value).encode() in lower or f"0x{value:x}".encode() in lower
            or struct.pack("<Q", value) in content
            or struct.pack("<Q", value) in reconstructed}


def sentinel_hits(content, reconstructed=b""):
    lower = content.lower()
    return {name for name, value in SENTINELS.items()
            if value in content or value.hex().encode() in lower or value in reconstructed}


def reconstruct(content):
    return bytes(int(value, 16) for value in HEX_TOKEN.findall(content))


def positive_control_content(value=None):
    value = SENTINELS["PIN"] if value is None else value
    return b'{"value":[' + b",".join(
        f'"0x{byte:02x}"'.encode() for byte in value) + b"]}\n"


def assert_final_artifact_privacy(artifacts):
    artifacts = list(dict.fromkeys(map(Path, artifacts)))
    for path in artifacts:
        content = path.read_bytes()
        if path.suffix == ".output":
            rendered = content.decode("utf-8", "surrogateescape")
            if rendered.lstrip().startswith("{"):
                assert_json_identity_structure(str(path), json.loads(rendered))
            else:
                assert_no_loader_pause_identity(
                    str(path), trace_scannable(str(path), rendered)
                )
        elif path.suffix == ".json":
            assert_no_loader_pause_identity(str(path), reconstruct(content))
        elif path.name.endswith(".workload.log"):
            assert_no_loader_pause_identity(str(path), content, WORKLOAD_IDENTITIES)
        else:
            assert_no_loader_pause_identity(str(path), content)

    leaks = {}
    for path in artifacts:
        content = path.read_bytes()
        found = sentinel_hits(content, reconstruct(content) if path.suffix == ".json" else b"")
        if found:
            leaks[str(path)] = sorted(found)
    assert not leaks, f"ordinary pointer canaries leaked: {leaks}"


def assert_safe_lane_alias_privacy(lane, paths):
    for path in map(Path, paths):
        content = path.read_bytes()
        reconstructed = reconstruct(content) if path.suffix == ".json" else b""
        found = alias_hits(content, reconstructed)
        assert not found, f"{lane}: scalar aliases {found} in {path}"


def final_lane_artifacts(work, lane, surfaces, *, combined_log=False):
    work = Path(work)
    paths = [work / f"{lane}.output", work / f"{lane}.observer.log"]
    if not combined_log:
        paths.append(work / f"{lane}.workload.log")
    paths.extend(map(Path, surfaces))
    manifest_path = work / f"mapdump_manifest_{lane}.json"
    paths.append(manifest_path)
    manifest = read_json(manifest_path)
    assert isinstance(manifest, list) and manifest, f"{lane}: empty lane map manifest"
    claim = manifest[0].get("snapshot") if isinstance(manifest[0], dict) else None
    # Required in EVERY lane, on the owned lanes' own fail-closed terms. A
    # manifest claiming no snapshot would otherwise lose both the semantic
    # replay -- `owned_map_surfaces` runs it only for a claiming manifest --
    # and the receipt scan below, while the lane still reported OK: a privacy
    # scan passing over bytes nobody read, which is the exact failure G3 exists
    # to prevent and worse here than a crash. Every producer of a lane manifest
    # stamps the claim (`capture-stopped-canary.py` `manifest()`), so this is a
    # no-op on a real run and a loud failure if that ever stops being true.
    assert isinstance(claim, dict), f"{lane}: missing stopped snapshot claim"
    # A stopped receipt is a scanned privacy surface in EVERY lane, not just the
    # two owned rows. Replaying a receipt semantically and scanning the lane's
    # surface set says nothing about the receipt's own bytes, so a sentinel
    # landing in one of the 10 external receipts used to escape the final scan
    # outright. The path is taken from the manifest claim: the receipt is
    # reached by being NAMED, never by walking the lane directory, which is what
    # keeps this scanner tree-walk-free and the nested seed out-dir outside the
    # scan surface (see verify-canaries.sh).
    receipt = Path(claim.get("receipt", ""))
    assert receipt.is_absolute(), f"{lane}: invalid stopped receipt path"
    paths.append(receipt)
    return paths


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv:
        print("usage: check-canary-evidence.py MODE ... BITS", file=sys.stderr)
        return 2
    if argv == ["--self-test"]:
        argv.append("64")
    try:
        target_bits = int(argv[-1])
        initialize(target_bits)
    except (ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        return 2
    work = argv[0]
    if work == "--raw-events":
        assert_raw_records(argv[1], argv[2], int(argv[3]), argv[4])
        return 0
    if work == "--hostile-starts":
        assert_hostile_starts(argv[1], argv[2], int(argv[3]))
        return 0
    if work == "--fault-starts":
        assert_fault_starts(argv[1], int(argv[2]))
        return 0


    if work == "--self-test":
        def reject(label, action):
            try:
                action()
            except AssertionError:
                return
            raise AssertionError(f"{label} mutation was accepted")

        macro_names = {
            "mechanism": "ALIAS_MECHANISM_ID",
            "pss_hash": "ALIAS_PSS_HASH",
            "pss_mgf": "ALIAS_PSS_MGF",
            "pss_salt": "ALIAS_PSS_SALT",
            "gcm220_iv": "ALIAS_GCM_V220_IV_LEN",
            "gcm220_aad": "ALIAS_GCM_V220_AAD_LEN",
            "gcm220_tag": "ALIAS_GCM_V220_TAG_BITS",
            "gcm240_iv": "ALIAS_GCM_V240_IV_LEN",
            "gcm240_aad": "ALIAS_GCM_V240_AAD_LEN",
            "gcm240_tag": "ALIAS_GCM_V240_TAG_BITS",
            "template_type": "ALIAS_TEMPLATE_TYPE",
        }

        def assert_target_oracle(bits, aliases, maximum):
            definitions = dict(re.findall(
                r"^#define\s+(\S+)\s+(\S+)$",
                subprocess.check_output(
                    ["gcc", f"-m{bits}", "-dM", "-E",
                     str(SCRIPT_DIR / "fixtures/canary_workload.c")],
                    text=True,
                ),
                re.MULTILINE,
            ))
            actual = {
                name: int(definitions[macro].removesuffix("UL"), 0)
                for name, macro in macro_names.items()
            }
            actual_maximum = (1 << (8 * int(definitions["__SIZEOF_LONG__"]))) - 1
            assert aliases == actual and maximum == actual_maximum, (
                bits, aliases, maximum, actual, actual_maximum
            )

        for bits in (32, 64):
            assert_target_oracle(bits, *target_oracle(bits))
        reject(
            "target-width scalar oracle mismatch",
            lambda: assert_target_oracle(32, *target_oracle(64)),
        )
        print("target-width scalar oracles: OK")

        full_fixture = {
            "attached_probes": 136, "table_entries": 68,
            "surfaces": [{"walk": "full", "acquisition": "ok"}],
            "shape_decode_failures": 0,
            "task_uprobe_link_losses": 0,
        }
        selection_fixture = {
            "interface_selection": {
                "providers": [], "standard_exports": [],
                "inventory_surfaces": [], "tuples": [],
                "selection_truncated": False,
            },
            "attach_mechanisms": ["per-offset"],
            "pid_descendant_gaps": 0, "multi_rebuild_gaps": 0,
        }
        exact_role_counts({"observer_calls": 0, "inspect_calls": 0, "helper_calls": 10})
        reject("reversed observer/helper roles", lambda: exact_role_counts({
            "observer_calls": 10, "inspect_calls": 0, "helper_calls": 0,
        }))

        def terminal(privacy, semantic, unregistered=0):
            return {
                **full_fixture,
                "privacy_mode": privacy, "completeness": "PARTIAL",
                "capture_aborted": None,
                "final_drain": False, "counters_available": True,
                "semantic_capture_failures": semantic,
                "unregistered_mechanisms": unregistered, "async_target_failures": 2,
                **selection_fixture,
            }

        def count_line():
            return "COUNT_EVIDENCE " + json.dumps({
                "stats_entered": 7, "stats_returned": 5, "raw_calls": 3,
            }) + "\n"

        safe = {
            "schema": "pkcs11-scope/observed-profile/v3",
            "capture": {"mode": "profile", "privacy_mode": "allowlisted"},
            "evidence": {**full_fixture, **selection_fixture,
                         "completeness": "PARTIAL", "unregistered_mechanisms": 2,
                         "semantic_capture_failures": 3, "async_target_failures": 2},
            "mechanisms": [{"mechanism": REGISTERED, "params": None}],
            "templates": {"operations": []},
        }
        assert_safe_profile(safe)
        v3 = json.loads(json.dumps(safe))
        v3["evidence"].update(
            interface_selection={
                "providers": [], "standard_exports": [],
                "inventory_surfaces": [], "tuples": [],
                "selection_truncated": False,
            },
            attach_mechanisms=[], pid_descendant_gaps=0, multi_rebuild_gaps=0,
        )
        assert_safe_profile(v3)
        reject("v3 missing interface selection", lambda: assert_safe_profile({
            **v3, "evidence": {
                key: value for key, value in v3["evidence"].items()
                if key != "interface_selection"
            },
        }))
        extra_v3 = json.loads(json.dumps(v3))
        extra_v3["evidence"]["interface_selection"]["secret"] = "canary"
        reject("v3 extra selection field", lambda: assert_safe_profile(extra_v3))
        secret_v3 = json.loads(json.dumps(v3))
        secret_v3["evidence"]["attach_mechanisms"] = ["secret-canary"]
        reject("v3 secret canary", lambda: assert_safe_profile(secret_v3))
        stale_v2 = json.loads(json.dumps(v3))
        stale_v2["schema"] = "pkcs11-scope/observed-profile/v2"
        reject("stale live profile v2", lambda: assert_safe_profile(stale_v2))
        extra_evidence = json.loads(json.dumps(v3))
        extra_evidence["evidence"]["secret_selection_payload"] = "CANARY"
        reject("v3 extra evidence field", lambda: assert_safe_profile(extra_evidence))
        reject("safe profile unknown-id", lambda: assert_safe_profile({
            **safe, "mechanisms": safe["mechanisms"] + [{"mechanism": UNKNOWN, "params": None}]
        }))
        bad_safe = json.loads(json.dumps(safe))
        bad_safe["evidence"]["semantic_capture_failures"] = 4
        reject("safe profile failure total", lambda: assert_safe_profile(bad_safe))

        safe_trace = "CAPTURE privacy=allowlisted\nC_DigestInit 0x250\n" + count_line() + \
            "EVIDENCE " + json.dumps(
            terminal("allowlisted", 3, 2)
        )
        assert_safe_trace(safe_trace)
        reject("safe trace alias", lambda: assert_safe_trace(
            safe_trace.replace("C_DigestInit 0x250", f"C_DigestInit 0x250 0x{UNKNOWN:x}")
        ))
        reject("safe trace needs rendered call", lambda: assert_safe_trace(
            "CAPTURE privacy=allowlisted\n" + count_line() +
            "EVIDENCE " + json.dumps(terminal("allowlisted", 3, 2))
        ))
        reject("safe trace missing count evidence", lambda: assert_safe_trace(
            safe_trace.replace(count_line(), "")
        ))
        reject("safe trace count evidence ordering", lambda: assert_safe_trace(
            safe_trace.replace(count_line(), "").replace(
                "C_DigestInit 0x250\n", count_line() + "C_DigestInit 0x250\n"
            )
        ))
        reject("safe trace count evidence shape", lambda: assert_safe_trace(
            safe_trace.replace('"raw_calls": 3', '"raw_calls_extra": 3')
        ))

        pss = [{
            "shape": "rsa_pkcs_pss", "hash_alg": ALIASES["pss_hash"],
            "hash_alg_hex": f"0x{ALIASES['pss_hash']:x}", "mgf": ALIASES["pss_mgf"],
            "salt_len": ALIASES["pss_salt"], "count": 1,
        }]
        gcm = [
            {"layout": "v2.20", "iv_len": ALIASES["gcm220_iv"],
             "aad_len": ALIASES["gcm220_aad"], "tag_bits": ALIASES["gcm220_tag"]},
            {"layout": "v2.40", "iv_len": ALIASES["gcm240_iv"],
             "aad_len": ALIASES["gcm240_aad"], "tag_bits": ALIASES["gcm240_tag"]},
        ]
        unsafe = {
            "schema": "pkcs11-scope/observed-profile/v3",
            "capture": {"mode": "profile", "privacy_mode": "unsafe-unvalidated-metadata"},
            "evidence": {**terminal("unsafe-unvalidated-metadata", 7),
                         "templates_truncated": False},
            "mechanisms": [
                {"mechanism": REGISTERED, "params": None},
                {"mechanism": UNKNOWN, "params": None},
                {"mechanism": MAXIMUM, "params": None},
                {"mechanism": 0xD, "params": pss},
                {"mechanism": 0x1087, "params": gcm},
            ],
            "templates": {"operations": [
                {"names": ["C_CreateObject"], "requested": True,
                 "attr_types": [{"attr_type": ALIASES["template_type"]}],
                 "policy_booleans": {"observed_true": sorted(POLICY_BOOLEANS),
                                     "observed_false": []}},
                {"names": ["C_CopyObject"], "requested": True,
                 "attr_types": [{"attr_type": 2}],
                 "policy_booleans": {"observed_true": [], "observed_false": []}},
                {"names": ["C_SetAttributeValue"], "requested": True,
                 "attr_types": [{"attr_type": 1}],
                 "policy_booleans": {"observed_true": [], "observed_false": []}},
            ]},
        }
        assert_unsafe_profile(unsafe)
        bad_unsafe = json.loads(json.dumps(unsafe))
        bad_unsafe["templates"]["operations"][0]["policy_booleans"]["observed_true"].pop()
        reject("unsafe profile policy boolean", lambda: assert_unsafe_profile(bad_unsafe))
        bad_unsafe = json.loads(json.dumps(unsafe))
        bad_unsafe["evidence"]["semantic_capture_failures"] = 6
        reject("unsafe profile failure total", lambda: assert_unsafe_profile(bad_unsafe))

        unsafe_values = [UNKNOWN, MAXIMUM, *[ALIASES[name] for name in (
            "pss_hash", "pss_mgf", "pss_salt", "gcm220_iv", "gcm220_aad",
            "gcm220_tag", "gcm240_iv", "gcm240_aad", "gcm240_tag")]]
        unsafe_trace = "CAPTURE privacy=unsafe-unvalidated-metadata\n" + \
            " ".join(f"0x{value:x}" for value in unsafe_values) + "\n" + count_line() + \
            "EVIDENCE " + \
            json.dumps(terminal("unsafe-unvalidated-metadata", 7))
        assert_unsafe_trace(unsafe_trace)
        missing = f"0x{ALIASES['pss_hash']:x}"
        reject("unsafe trace PSS alias", lambda: assert_unsafe_trace(
            unsafe_trace.replace(missing, "removed", 1)
        ))

        aborted = "CAPTURE privacy=allowlisted\nEVIDENCE " + json.dumps({
            "completeness": "PARTIAL", "privacy_mode": "allowlisted",
            "capture_aborted": "object_lease_break", "final_drain": False,
            "counters_available": False, "event_loss": None,
        })
        trace_abort_terminal(aborted, "allowlisted")
        reject("trace abort extra count", lambda:
               trace_abort_terminal(aborted + "\n" + count_line(), "allowlisted"))
        reject("trace abort duplicate count", lambda:
               trace_abort_terminal(count_line() + count_line() + aborted, "allowlisted"))
        reject("trace abort misplaced count", lambda:
               trace_abort_terminal(aborted.replace("EVIDENCE ", count_line() + "EVIDENCE "),
                                    "allowlisted"))
        for field, value in (("capture_aborted", None), ("final_drain", True),
                             ("counters_available", True), ("event_loss", 0)):
            mutated = json.loads(aborted.split("EVIDENCE ", 1)[1])
            mutated[field] = value
            reject(f"trace abort {field}", lambda mutated=mutated:
                   trace_abort_terminal("EVIDENCE " + json.dumps(mutated), "allowlisted"))
        mutated = json.loads(aborted.split("EVIDENCE ", 1)[1])
        mutated["unmatched_returns"] = 0
        reject("trace abort fabricated counter", lambda:
               trace_abort_terminal("EVIDENCE " + json.dumps(mutated), "allowlisted"))

        aggregate = {
            "schema": "pkcs11-scope/observed-profile/v3-metrics",
            "capture": {"mode": "metrics", "privacy_mode": "aggregate-only"},
            "evidence": {
                **full_fixture,
                "completeness": "PARTIAL", "templates_truncated": False,
                "attach_failures": [], "skipped": [], "aliased": [],
                "in_flight_at_end": 0,
                "surfaces": [{"walk": "full", "acquisition": "ok"}],
                "vendor_interfaces": 0, "interface_list": "ok",
            },
            "functions": [{"calls": 28}],
        }
        assert_aggregate_metrics(aggregate)
        owned_aggregate = json.loads(json.dumps(aggregate))
        owned_aggregate["functions"][0]["calls"] = 30
        assert_owned_aggregate_metrics(owned_aggregate)
        for calls in (28, 29, 31):
            bad_owned = json.loads(json.dumps(owned_aggregate))
            bad_owned["functions"][0]["calls"] = calls
            reject(f"owned metrics call count {calls}",
                   lambda bad_owned=bad_owned: assert_owned_aggregate_metrics(bad_owned))
        extra_metrics = json.loads(json.dumps(aggregate))
        extra_metrics["evidence"]["secret_selection_payload"] = "CANARY"
        reject("metrics extra evidence field", lambda: assert_aggregate_metrics(extra_metrics))

        # This preserves the artifact-side output/privacy contract. The
        # producer-shaped Rust test proves the State/Tracer path; this oracle keeps
        # its exact scan-only rendered shape and hostile-output refusal in canaries.
        hostile = [
            "CANARY_SCAN_ONLY_SESSION_PAYLOAD",
            "CANARY_SCAN_ONLY_MECHANISM_PAYLOAD",
            "CANARY_SCAN_ONLY_ARGUMENT_PAYLOAD",
        ]
        scan_module = {"dev": [8, 1], "ino": 42, "sha256": "11" * 32}
        scan_only = {
            "schema": "pkcs11-scope/observed-profile/v3",
            "capture": {
                "start": "t0", "end": "t1", "mode": "profile",
                "privacy_mode": "allowlisted", "kernel": "6.8.0",
                "modules": [{
                    **scan_module, "path": "/opt/p11.so", "build_id": "aabb",
                }],
            },
            "evidence": {
                **selection_fixture,
                "completeness": "PARTIAL", "table_entries": 1, "slots": 1,
                "attached_probes": 2,
                "task_uprobe_link_losses": 0,
                "surfaces": [{
                    "source": "/opt/p11.so table 2.40", "walk": "full", "acquisition": "ok",
                    "functions": 1,
                }],
                "discovery": [{
                    **scan_module, "path": "/opt/p11.so", "build_id": "aabb",
                    "sources": ["scan"],
                    "tables": [{"version": [2, 40], "entries": 1, "source": "scan"}],
                }],
            },
            "functions": [{
                "names": ["C_OpenSession"], "aliased": False, "module": scan_module,
                "module_ambiguous": False, "module_unresolved": False,
                "calls": 25, "errors": 3,
                "pending_returns": 5, "in_flight": 0,
                "latency_ns": {
                    "approximate": True, "p50": 64, "p95": 64, "p99": 64,
                    "total": 2500, "max": 100,
                },
                "rv_counts": {
                    "0x0000000000000000": 17,
                    "0x0000000000000005": 3,
                    "0x0000000000000204": 5,
                },
            }],
            "mechanisms": [],
            "sessions": {
                "opened": 0, "inherited": 0, "closed": 0, "async_opened": 0,
                "peak_concurrent": 0, "balance": 0,
            },
            "logins": {}, "templates": {"operations": []},
            "cgroups": [{
                "cgroup_id": 7, "label": None, "calls": 25, "errors": 3,
                "mechanisms": [],
            }],
        }
        scan_terminal = {
            **selection_fixture,
            "completeness": "PARTIAL", "privacy_mode": "allowlisted",
            "capture_aborted": None, "final_drain": False, "counters_available": True,
            "table_entries": 1, "slots": 1, "attached_probes": 2,
            "task_uprobe_link_losses": 0,
            "semantic_capture_failures": 0,
        }
        scan_trace = "CAPTURE privacy=allowlisted\n" + "\n".join([
            "00:00:00.000000 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_OK 100ns",
            "00:00:00.000001 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_GENERAL_ERROR 100ns",
            "00:00:00.000024 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_PENDING 100ns",
        ]) + "\n" + count_line() + "EVIDENCE " + json.dumps(scan_terminal)
        assert_scan_only_hostile_output(scan_only, scan_trace, hostile)
        reject("scan-only hostile trace payload", lambda: assert_scan_only_hostile_output(
            scan_only,
            scan_trace.replace("CKR_PENDING", "CKR_PENDING " + hostile[0]),
            hostile,
        ))
        reject("scan-only hostile count payload", lambda: assert_scan_only_hostile_output(
            scan_only,
            scan_trace.replace('"raw_calls": 3', f'"raw_calls": "{hostile[0]}"'),
            hostile,
        ))
        # The owner relation is part of that exact shape: an owned cell may not be
        # relabelled unowned or ambiguous, and it may not drop the boolean either.
        for label, mutate in (
            ("scan-only owned cell relabelled unowned",
             lambda d: d["functions"][0].update(module=None, module_unresolved=True)),
            ("scan-only owned cell relabelled ambiguous",
             lambda d: d["functions"][0].update(module=None, module_ambiguous=True)),
            ("scan-only owner relation dropped",
             lambda d: d["functions"][0].pop("module_unresolved")),
        ):
            mutated = json.loads(json.dumps(scan_only))
            mutate(mutated)
            reject(label, lambda m=mutated: assert_scan_only_hostile_output(
                m, scan_trace, hostile
            ))
        print("scan-only hostile output contract: OK")

        for family, sentinel in sorted(fixture_sentinels().items()):
            control = positive_control_content(sentinel)
            assert sentinel_hits(control) == set()
            assert sentinel_hits(control, reconstruct(control)) == {family}
            print(f"scanner sentinel OK: {sentinel.decode()}")
        alias = ALIASES["pss_hash"]
        assert alias_hits(str(alias).encode()) == {"pss_hash"}
        assert alias_hits(struct.pack("<Q", alias)) == {"pss_hash"}
        assert alias_hits(b"", struct.pack("<Q", alias)) == {"pss_hash"}
        print("raw binary alias scanner self-test: OK")

        def start_bytes(session, target=FUNCTION_NONE, mechanism=MECH_NONE,
                        mechanism_ptr=0, attr_type=0, capture=0):
            raw = bytearray(CALL_START_SIZE)
            struct.pack_into("<Q", raw, 8, session)
            struct.pack_into("<Q", raw, 24, mechanism)
            struct.pack_into("<Q", raw, 32, mechanism_ptr)
            struct.pack_into("<I", raw, 56, (1 << 32) - 1)
            if attr_type:
                struct.pack_into("<Q", raw, 96, attr_type)
                struct.pack_into("<II", raw, 160, 1, 1)
            struct.pack_into("<I", raw, 256, capture)
            struct.pack_into("<I", raw, 260, target)
            return bytes(raw)

        pointers = {
            "unknown_mechanism": 0x123456789ABCDEF0,
            "exact_async": 0x223456789ABCDEF0,
            "legacy_name": 0x323456789ABCDEF0,
            "alias_name": 0x423456789ABCDEF0,
        }
        starts = [decode_start(start_bytes(
                      0x301, mechanism_ptr=pointers["unknown_mechanism"]
                  )),
                  decode_start(start_bytes(0x302, target=30)),
                  decode_start(start_bytes(0x303, capture=ARG_READ_FAILURE)),
                  decode_start(start_bytes(0x304, capture=ARG_READ_FAILURE))]
        assert_hostile_records(starts, pointers)
        nonzero_pad = bytearray(start_bytes(0x301))
        struct.pack_into("<I", nonzero_pad, 268, 1)
        reject("CallStart padding", lambda: decode_start(bytes(nonzero_pad)))
        for session in (0x301, 0x302, 0x303, 0x304):
            mutated = [dict(record) for record in starts]
            record = next(record for record in mutated if record["session"] == session)
            if session == 0x301:
                record["mechanism"] = UNKNOWN
            else:
                record["target"] ^= 1
            reject(f"hostile START {session:#x}", lambda mutated=mutated:
                   assert_hostile_records(mutated, pointers))
        for field, value in (("shape", 1), ("p0", 1), ("attrs", (1,) + (0,) * 7),
                             ("attr_count", 1), ("slot_id", 1), ("flags", 1),
                             ("out_ptr", 1), ("user_type", 0), ("async_value", 1)):
            mutated = [dict(record) for record in starts]
            mutated[0][field] = value
            reject(f"safe raw {field}", lambda mutated=mutated:
                   assert_hostile_records(mutated, pointers))
        for name in ("exact_async", "legacy_name", "alias_name"):
            mutated_pointers = dict(pointers)
            mutated_pointers[name] = pointers["unknown_mechanism"]
            reject(f"pointer identity {name}", lambda mutated_pointers=mutated_pointers:
                   assert_hostile_records(starts, mutated_pointers))
        print("full CallStart safe defaults self-test: OK")

        faults = [decode_start(start_bytes(0x401, attr_type=2, capture=ARG_READ_FAILURE)),
                  decode_start(start_bytes(0x402, attr_type=1, capture=ARG_READ_FAILURE))]
        assert_fault_records(faults, 2)
        for label, session, field, value in (
            ("metadata type", 0x401, "attrs", (0,) * 8),
            ("value boolean", 0x402, "attr_seen", 1),
            ("fault capture", 0x401, "capture", 0),
        ):
            mutated = [dict(record) for record in faults]
            next(record for record in mutated if record["session"] == session)[field] = value
            reject(label, lambda mutated=mutated: assert_fault_records(mutated, 2))
        for total in (1, 3):
            reject(f"fault evidence {total}", lambda total=total: assert_fault_records(faults, total))

        raw = bytearray(2 * mmap.PAGESIZE)
        event = bytes(EVENT_SIZE)
        struct.pack_into("<I", raw, 0, EVENT_SIZE)
        raw[8:8 + EVENT_SIZE] = event
        assert parse_ring_records(raw, mmap.PAGESIZE, 0, 336) == [event]
        for label, header, producer in (
            ("ring busy", EVENT_SIZE | (1 << 31), 336),
            ("ring discard", EVENT_SIZE | (1 << 30), 336),
            ("ring short", EVENT_SIZE - 1, 336),
            ("ring long", EVENT_SIZE + 1, 344),
        ):
            mutated = bytearray(raw)
            struct.pack_into("<I", mutated, 0, header)
            reject(label, lambda mutated=mutated, producer=producer:
                   parse_ring_records(mutated, mmap.PAGESIZE, 0, producer))
        reject("ring producer wrap", lambda: parse_ring_records(raw, mmap.PAGESIZE, 336, 0))

        def event_bytes(index, mechanism=None, slot=0, shape=0, p0=0, p1=0, p2=0,
                        attrs=(), attr_count=0, attr_total=0, attr_bools=0,
                        attr_seen=0, capture=0, root_affiliation=0):
            raw_event = bytearray(EVENT_SIZE)
            struct.pack_into("<Q", raw_event, 16, 0x555 << 32 | index)
            if 22 <= index < 25:
                session, target = ((0x11d, 30), (0x11e, FUNCTION_NONE),
                                   (0x11f, FUNCTION_NONE))[index - 22]
            else:
                session, target = 0x101, FUNCTION_NONE
            struct.pack_into("<Q", raw_event, 32, session)
            if mechanism is None:
                mechanism = (REGISTERED, 0xD, 0x1087)[index] if index < 3 else MECH_NONE
            struct.pack_into("<Q", raw_event, 48, mechanism)
            struct.pack_into("<QQQ", raw_event, 72, p0, p1, p2)
            struct.pack_into("<I", raw_event, 104, slot)
            struct.pack_into("<I", raw_event, 108, target)
            struct.pack_into("<I", raw_event, 116, shape)
            if attrs:
                struct.pack_into("<8Q", raw_event, 120, *(tuple(attrs) + (0,) * (8 - len(attrs))))
            struct.pack_into("<IIII", raw_event, 184, attr_count, attr_total,
                             attr_bools, attr_seen)
            struct.pack_into("<I", raw_event, 280, capture)
            struct.pack_into("<Q", raw_event, 320, root_affiliation)
            return bytes(raw_event)

        safe_events = [event_bytes(index) for index in range(28)]
        safe_events[0] = event_bytes(0, root_affiliation=1)
        assert_event_records(safe_events, "default-safe-profile", 0x555)
        assert_event_records([], "aggregate-only-metrics", 0x555)
        discovery_record = bytes(DISCOVERY_RECORD_SIZE)
        for lane in OWNED_METRICS_LANES:
            assert_retained_ring_records(
                {"EVENTS": [], "DISCOVERY": [discovery_record]}, lane, 0x555)
            reject(f"{lane} ordinary event", lambda lane=lane: assert_retained_ring_records(
                {"EVENTS": [safe_events[0]], "DISCOVERY": [discovery_record]}, lane, 0x555))
            reject(f"{lane} empty discovery", lambda lane=lane: assert_retained_ring_records(
                {"EVENTS": [], "DISCOVERY": []}, lane, 0x555))
        reject("raw event count", lambda: assert_event_records(
            safe_events[:-1], "default-safe-profile", 0x555
        ))
        for label, offset, encoded in (
            ("raw event pid", 16, struct.pack("<Q", 0x556 << 32)),
            ("raw event type", 284, struct.pack("<I", 1)),
            ("raw event metadata", 116, struct.pack("<I", 1)),
            ("raw alias target", 108, struct.pack("<I", 30)),
        ):
            mutated = list(safe_events)
            index = 23 if label == "raw alias target" else 0
            record = bytearray(mutated[index])
            record[offset:offset + len(encoded)] = encoded
            mutated[index] = bytes(record)
            reject(label, lambda mutated=mutated: assert_event_records(
                mutated, "default-safe-profile", 0x555
            ))
        for root_affiliation in (2, (1 << 64) - 1):
            mutated = list(safe_events)
            record = bytearray(mutated[0])
            struct.pack_into("<Q", record, 320, root_affiliation)
            mutated[0] = bytes(record)
            reject(f"raw root affiliation {root_affiliation}", lambda mutated=mutated:
                   assert_event_records(mutated, "default-safe-profile", 0x555))
        print("raw policy oracle self-test: OK")

        unsafe_events = list(safe_events)
        unsafe_events[9] = event_bytes(9, mechanism=REGISTERED)
        unsafe_events[10] = event_bytes(10, mechanism=UNKNOWN)
        unsafe_events[11] = event_bytes(11, mechanism=MAXIMUM)
        unsafe_events[12] = event_bytes(
            12, mechanism=0xD, slot=401, shape=1, p0=ALIASES["pss_hash"],
            p1=ALIASES["pss_mgf"], p2=ALIASES["pss_salt"]
        )
        unsafe_events[13] = event_bytes(
            13, mechanism=0x1087, slot=402, shape=3, p0=ALIASES["gcm220_iv"],
            p1=ALIASES["gcm220_aad"], p2=ALIASES["gcm220_tag"]
        )
        unsafe_events[14] = event_bytes(
            14, mechanism=0x1087, slot=402, shape=4, p0=ALIASES["gcm240_iv"],
            p1=ALIASES["gcm240_aad"], p2=ALIASES["gcm240_tag"]
        )
        unsafe_events[15] = event_bytes(
            15, slot=403, attrs=(ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[:6]),
            attr_count=7, attr_total=7, attr_bools=0x3F, attr_seen=0x3F
        )
        unsafe_events[16] = event_bytes(
            16, slot=403, attrs=(ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[6:]),
            attr_count=6, attr_total=6, attr_bools=0x7C0, attr_seen=0x7C0
        )
        unsafe_events[17] = event_bytes(
            17, slot=404, attrs=(2,), attr_count=1, attr_total=1,
            capture=ARG_READ_FAILURE
        )
        unsafe_events[18] = event_bytes(
            18, slot=405, attrs=(1,), attr_count=1, attr_total=1,
            capture=ARG_READ_FAILURE
        )
        assert_event_records(unsafe_events, "feature-unsafe-profile", 0x555)
        for label, index, offset, encoded in (
            ("unsafe template A alias", 15, 120, struct.pack("<Q", 0)),
            ("unsafe template A count", 15, 184, struct.pack("<I", 6)),
            ("unsafe template B booleans", 16, 192, struct.pack("<I", 0x3C0)),
            ("unsafe template B seen", 16, 196, struct.pack("<I", 0x3C0)),
        ):
            mutated = list(unsafe_events)
            record = bytearray(mutated[index])
            record[offset:offset + len(encoded)] = encoded
            mutated[index] = bytes(record)
            reject(label, lambda mutated=mutated: assert_event_records(
                mutated, "feature-unsafe-profile", 0x555
            ))
        print("unsafe raw template oracle self-test: OK")

        # Loader/pause identity scan. The positive control comes first: every
        # spelling of every private value is found when it is deliberately placed
        # in each scanned surface, so the clean result below is a real absence and
        # not a scanner that matches nothing.
        surfaces = ("profile json", "trace output", "observer log",
                    "private temp output", "owned map value")
        for name, value in LOADER_PAUSE_IDENTITIES.items():
            for pattern in identity_patterns([value]):
                for surface in surfaces:
                    reject(
                        f"{surface} {name}",
                        lambda s=surface, p=pattern: assert_no_loader_pause_identity(
                            s, b"leading" + p + b"trailing"
                        ),
                    )
        clean_document = {
            "capture": {"modules": [{"path": "/opt/p11.so", "dev": [8, 1], "ino": 42,
                                     "sha256": "11" * 32, "build_id": "aabb"}]},
            "evidence": {
                "attach_gap_ms": 7, "pause": "partial", "pause_attempts": 2,
                "pause_confirmed": 1, "pause_partial": 1,
                "discovery_ring_loss": 0, "discovery_state_failures": 0,
                "discovery_read_failures": 0, "discovery_truncated": 0,
                "task_uprobe_link_losses": 0,
                "loader_discovery": {
                    # Two exact bound contexts: one ordinary `dlopen`, and the
                    # owned run's one pre-exec initial-set context.
                    "strategies": {"debug_state_every_hit": 2, "dlopen_return": 0,
                                   "unavailable": 0},
                    "dlopen_timing": {"qualified_pre_constructor": 0,
                                      "known_pre_relocation": 0, "unproven": 1,
                                      "none": 0},
                    "initial_set_timing": {"qualified_pre_constructor": 0,
                                           "known_pre_relocation": 0, "unproven": 1,
                                           "none": 0},
                    "initial_set_capture": {"eligible": 0, "none": 1},
                    "hits": 4, "state_read_failures": 0,
                },
            },
            "functions": [{
                "names": ["C_Sign"], "aliased": False,
                "module": {"dev": [8, 1], "ino": 42, "sha256": "11" * 32},
                "module_ambiguous": False, "module_unresolved": False,
                "rv_counts": {"0x0000000000000200": 3, "0x00000000000000fa": 1},
            }],
        }
        clean_aggregate = json.dumps(clean_document["evidence"])
        assert_no_loader_pause_identity("profile evidence", clean_aggregate)
        assert_no_loader_pause_identity(
            "trace output",
            "CAPTURE privacy=allowlisted\nC_Sign 0x0 sess#1 1.2ms\nEVIDENCE "
            + clean_aggregate,
        )
        assert_no_loader_pause_identity(
            "owned map value", struct.pack("<QQ", 1, 0) + struct.pack("<QQ", 2, 0)
        )
        print("loader/pause identity scanner self-test: OK")

        # Structural field checks. A published capture document carries the finite
        # loader/pause fields and nothing else from that namespace, at any depth —
        # and a legitimate allowlisted value whose spelling looks like a narrow
        # private constant (an `rv_counts` key of `0x…0200` or `0x…00fa`) must not
        # be mistaken for one.
        assert_json_identity_structure("clean profile json", clean_document)
        for label, mutate in (
            # The document as a whole is checked structurally, never byte-scanned:
            # this clean one carries `rv_counts` keys spelling `0x…0200` and
            # `0x…00fa`, which are allowlisted full-width return codes and also the
            # text spelling of two narrow private constants.
            ("evidence loader path", lambda d: d["evidence"].update(
                loader="/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")),
            ("evidence child pid", lambda d: d["evidence"].update(child_pid=4242424)),
            ("nested pause identity", lambda d: d["evidence"]["loader_discovery"].update(
                pause_tasks=[4242424, 4242425])),
            ("function row owner key", lambda d: d["functions"][0].update(loader_context=3)),
            ("module ref process identity", lambda d: d["functions"][0]["module"].update(
                owner_tid=4242425)),
            ("capture module interface bytes", lambda d: d["capture"]["modules"][0].update(
                path="PKCS 11")),
            ("discovered loader digest", lambda d: d["evidence"].update(
                discovery=[{"path": "/opt/p11.so", "sha256": "ab" * 32}])),
        ):
            mutated = json.loads(json.dumps(clean_document))
            mutate(mutated)
            reject(label, lambda m=mutated: assert_json_identity_structure("profile json", m))

        # The trace's two allowlisted identity positions are removed by shape, so a
        # real PID that collides with a private constant cannot fire, while an
        # identity anywhere else on the same line — or on an unfrozen line — still
        # does.
        allowlisted_trace = (
            "CAPTURE privacy=allowlisted\n"
            f"00:00:00.000000 pid {LOADER_PAUSE_IDENTITIES['child_pid']} "
            f"tid {LOADER_PAUSE_IDENTITIES['child_tid']} C_Sign → CKR_OK 100ns\n"
            "LOST 2 events\nEVIDENCE " + clean_aggregate
        )
        assert_no_loader_pause_identity(
            "trace output", trace_scannable("trace output", allowlisted_trace)
        )
        for label, line in (
            ("trace session identity", "00:00:00.000000 pid 100 tid 1 C_Sign "
                                       f"sess#{LOADER_PAUSE_IDENTITIES['marker']} → CKR_OK 100ns"),
            ("unfrozen trace line", "loader /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
        ):
            reject(label, lambda line=line: assert_no_loader_pause_identity(
                "trace output",
                trace_scannable("trace output", f"CAPTURE privacy=allowlisted\n{line}"),
            ))

        # The workload-log exemption is exactly one value wide: the target's own
        # stderr may name the interface it looked for, and nothing else.
        assert_no_loader_pause_identity(
            "workload log", b"no exact PKCS 11 v3.2 table\n", WORKLOAD_IDENTITIES
        )
        reject("observer log interface bytes", lambda: assert_no_loader_pause_identity(
            "observer log", b"no exact PKCS 11 v3.2 table\n"
        ))
        for label, leaked in (
            ("workload log loader path", LOADER_PAUSE_IDENTITIES["loader_path"]),
            ("workload log child pid", str(LOADER_PAUSE_IDENTITIES["child_pid"])),
        ):
            reject(label, lambda leaked=leaked: assert_no_loader_pause_identity(
                "workload log", f"leading{leaked}trailing".encode(), WORKLOAD_IDENTITIES
            ))
        print("loader/pause structural field checks: OK")

        # ------------------------------------------------------------------
        # Owned-map inventory and scan surfaces. The inventory comes from the one
        # checked-in BPF list, the dispatch from each map's `type`, and every owned
        # map must end up with a file the matrix scan actually reads.
        # ------------------------------------------------------------------
        RINGBUF = 27
        assert set(RING_RECORD_SIZES) == {
            name for name, definition in BPF_MAP_DEFS["UNSAFE_MAPS"].items()
            if definition["type"] == RINGBUF
        }, "a new owned ringbuf needs its exact record length here"
        assert SAFE_MAPS and FEATURE_MAPS == SAFE_MAPS | {"ATTR_BOOL_BITS"}
        assert {
            "COUNTERS", "DISCOVERY", "DISCOVERY_STATE", "PAUSE_PIDS",
            "TASK_COOKIE", "COOKIE_CTL", "THREAD_OWNER", "OWNER_CTL",
            "ROOT_AFFILIATION", "ROOT_CTL",
        } <= SAFE_MAPS
        assert FEATURE_MAPS - SAFE_MAPS == {"ATTR_BOOL_BITS"}

        with tempfile.TemporaryDirectory() as scan_dir:
            prefix = f"{scan_dir}/default-safe-profile"

            def owned_manifest():
                manifest = []
                for map_id, (name, definition) in enumerate(
                    sorted(BPF_MAP_DEFS["SAFE_MAPS"].items()), start=1
                ):
                    ring = definition["type"] == RINGBUF
                    task_storage = definition["type"] == 29
                    item = {
                        "name": name, "id": map_id, "max_entries": definition["max_entries"],
                        "key_size": definition["key_size"] if not ring else 0,
                        "value_size": definition["value_size"] if not ring else 0,
                        "type": "ringbuf" if ring else "task_storage" if task_storage else "hash",
                        "oracle": "mmap" if ring else "task-storage" if task_storage else "dump",
                    }
                    if not ring:
                        item["file"] = f"{scan_dir}/mapdump_{name}_lane.json"
                    manifest.append(item)
                return manifest

            def write_surfaces(manifest, planted=None):
                for item in manifest:
                    if item["type"] == "ringbuf":
                        payload = planted if planted and item["name"] == planted[0] else (b"", b"")
                        ring_raw_path(prefix, item["name"]).write_bytes(bytes(64) + payload[1])
                    else:
                        content = (positive_control_content(planted[1])
                                   if planted and item["name"] == planted[0]
                                   else b"[]\n")
                        Path(item["file"]).write_bytes(content)

            manifest = owned_manifest()
            write_surfaces(manifest)
            surfaces = owned_map_surfaces("lane", manifest, SAFE_MAPS, prefix)
            assert len(surfaces) == len(SAFE_MAPS)
            assert all(path.is_file() for path in surfaces), surfaces
            assert {path.name for path in surfaces} >= {
                f"default-safe-profile.{name}.raw" for name in RING_RECORD_SIZES
            }, surfaces
            print("owned map inventory routes every map by type: OK")

            for label, mutate in (
                # The frozen name-keyed dispatch: every ringbuf that is not EVENTS
                # was required to be a `bpftool map dump`, which cannot read one.
                ("ringbuf dumped", lambda m: m[[i["name"] for i in m].index("DISCOVERY")].update(
                    oracle="dump", type="hash", file=f"{scan_dir}/mapdump_DISCOVERY_lane.json")),
                ("non-ringbuf mmapped", lambda m: [
                    i.update(oracle="mmap") or i.pop("file") for i in m
                    if i["name"] == "DISCOVERY_STATE"]),
                ("stale inventory", lambda m: m.pop([i["name"] for i in m].index("PAUSE_PIDS"))),
                ("duplicate map ids", lambda m: m[1].update(id=m[0]["id"])),
                # A surface that is not on disk is an unscanned owned map.
                ("dump surface missing", lambda m: [
                    i.update(file=f"{scan_dir}/absent.json") for i in m
                    if i["name"] == "COUNTERS"]),
                ("ring surface missing",
                 lambda m: ring_raw_path(prefix, "DISCOVERY").unlink()),
            ):
                mutated = json.loads(json.dumps(manifest))
                mutate(mutated)
                reject(label, lambda mutated=mutated:
                       owned_map_surfaces("lane", mutated, SAFE_MAPS, prefix))
            print("owned map surface mutations are all rejected: OK")

            # Each owned map is a scan surface in its own right: a canary
            # planted in it must be found by the same reader the matrix uses.
            write_surfaces(manifest)
            for name in sorted(SAFE_MAPS):
                planted = json.loads(json.dumps(manifest))
                write_surfaces(planted, (name, SENTINELS["PIN"]))
                found = {}
                for path in owned_map_surfaces("lane", planted, SAFE_MAPS, prefix):
                    content = path.read_bytes()
                    hits = sentinel_hits(
                        content, reconstruct(content) if path.suffix == ".json" else b""
                    )
                    if hits:
                        found[path.name] = sorted(hits)
                assert list(found.values()) == [["PIN"]], (name, found)
                assert name in next(iter(found)), (name, found)
                write_surfaces(manifest)
            print("every owned map is a scanned canary surface: OK")

        print("canary lane assertion self-test: OK")
        return 0

    profiles = {
        lane: read_json(f"{work}/{lane}.output")
        for lane in ["default-safe-profile", "feature-safe-profile",
                     "feature-unsafe-profile", "aggregate-only-metrics",
                     "owned-default-metrics", "owned-feature-metrics"]
    }
    traces = {
        lane: Path(f"{work}/{lane}.output").read_text(encoding="utf-8")
        for lane in ["default-safe-trace", "feature-safe-trace", "feature-unsafe-trace"]
    }
    assert_safe_profile(profiles["default-safe-profile"])
    assert_safe_profile(profiles["feature-safe-profile"])
    assert_safe_trace(traces["default-safe-trace"])
    assert_safe_trace(traces["feature-safe-trace"])
    assert_unsafe_profile(profiles["feature-unsafe-profile"])
    assert_unsafe_trace(traces["feature-unsafe-trace"])
    assert_aggregate_metrics(profiles["aggregate-only-metrics"])
    assert_owned_aggregate_metrics(profiles["owned-default-metrics"])
    assert_owned_aggregate_metrics(profiles["owned-feature-metrics"])

    lanes = {
        "default-safe-profile": SAFE_MAPS, "default-safe-trace": SAFE_MAPS,
        "feature-safe-profile": FEATURE_MAPS, "feature-safe-trace": FEATURE_MAPS,
        "feature-unsafe-profile": FEATURE_MAPS, "feature-unsafe-trace": FEATURE_MAPS,
        "aggregate-only-metrics": SAFE_MAPS,
        "owned-default-metrics": SAFE_MAPS,
        "owned-feature-metrics": FEATURE_MAPS,
    }
    lane_surfaces = {
        lane: assert_exact_owned_map_inventory(work, lane, expected)
        for lane, expected in lanes.items()
    }
    additional_lanes = {
        "default-safe-start": SAFE_MAPS,
        "feature-safe-start": FEATURE_MAPS,
        "feature-unsafe-fault": FEATURE_MAPS,
    }
    lane_surfaces.update({
        lane: assert_exact_owned_map_inventory(work, lane, expected)
        for lane, expected in additional_lanes.items()
    })
    for lane in ["default-safe-profile", "default-safe-trace",
                 "feature-safe-profile", "feature-safe-trace",
                 "aggregate-only-metrics", "owned-default-metrics",
                 "owned-feature-metrics"]:
        assert len(read_json(f"{work}/mapdump_TAIL_CALLS_{lane}.json")) == 1
    for lane in ["feature-safe-profile", "feature-safe-trace", "owned-feature-metrics"]:
        assert read_json(f"{work}/mapdump_ATTR_BOOL_BITS_{lane}.json") == []
    for lane in ["feature-unsafe-profile", "feature-unsafe-trace"]:
        assert len(read_json(f"{work}/mapdump_ATTR_BOOL_BITS_{lane}.json")) == 11
        assert len(read_json(f"{work}/mapdump_TAIL_CALLS_{lane}.json")) == 2

    for lane in ["feature-unsafe-profile", "feature-unsafe-trace"]:
        log = Path(f"{work}/{lane}.observer.log").read_text(encoding="utf-8")
        assert "WARNING: unsafe-unvalidated-metadata" in log, f"{lane}: warning missing"
    for lane in lanes.keys() - {"feature-unsafe-profile", "feature-unsafe-trace"}:
        log = Path(f"{work}/{lane}.observer.log").read_text(encoding="utf-8")
        assert "WARNING: unsafe-unvalidated-metadata" not in log, f"{lane}: false warning"

    control = Path(work) / "positive_control.json"
    control.write_bytes(positive_control_content())
    content = control.read_bytes()
    assert sentinel_hits(content) == set()
    assert sentinel_hits(content, reconstruct(content)) == {"PIN"}
    print(f"positive control OK: scanner found PIN in {control}")

    all_lanes = (*lanes, *additional_lanes)
    artifacts = []
    for lane in all_lanes:
        artifacts.extend(final_lane_artifacts(
            work, lane, lane_surfaces[lane], combined_log=lane in OWNED_METRICS_LANES
        ))
    artifacts.append(Path(work) / "mapdump_START_live.json")
    # Loader and pause identities, over every artifact surface: the capture
    # documents, the trace streams, the observer/workload logs, the raw event dumps,
    # every map owned by the exact observer map ids (including the published copy of
    # the private temporary START dump), and every lane's stopped receipt bytes --
    # all 12 of them, not just the two owned rows, because a semantic receipt replay
    # never reads the receipt's own bytes. Each surface is scanned the way a leak
    # into it would actually look: a capture document structurally, because its
    # allowlisted `rv_counts`/mechanism values legitimately spell narrow private
    # constants; a trace with its two allowlisted call-event identity positions
    # removed by shape, so a real PID cannot fire the scan and an identity anywhere
    # else on the line still does; a map dump as the bytes it encodes, never as its
    # `0x..` token text, whose two-hex-digit runs would match a narrow spelling in
    # every clean dump.
    assert_final_artifact_privacy(artifacts)

    safe_lanes = (set(lanes) - {"feature-unsafe-profile", "feature-unsafe-trace"}) | {
        "default-safe-start", "feature-safe-start",
    }
    for lane in safe_lanes:
        paths = final_lane_artifacts(
            work, lane, lane_surfaces[lane], combined_log=lane in OWNED_METRICS_LANES
        )
        assert_safe_lane_alias_privacy(lane, paths)

    print(f"canary matrix OK: {len(all_lanes)} lanes; no ordinary or safe-policy alias leak")


if __name__ == "__main__":
    raise SystemExit(main())
