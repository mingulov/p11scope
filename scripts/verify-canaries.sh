#!/bin/sh
# Gate G3: hostile pointer aliases across the complete capture-policy matrix.
# Live BPF work is approval-gated; this file is kept syntactically and
# statically testable even when the gate remains UNRUN.
set -eu
cd "$(dirname "$0")/.."

WORK=target/canaries
TRUST_ROOT=
TRUST_DIR=
TRUST_UNSAFE_DIR=
RUN_DIR=

assert_lanes() {
    case ${1-} in
        --raw-events|--hostile-starts|--fault-starts) oracle_runner="sudo python3" ;;
        *) oracle_runner=python3 ;;
    esac
    $oracle_runner - "$@" <<'PY'
import ctypes
import json
import mmap
import os
from pathlib import Path
import platform
import re
import struct
import sys

work = sys.argv[1]
REGISTERED = 0x250
UNKNOWN = 0xF001000000000101
MAXIMUM = (1 << 64) - 1
ALIASES = {
    "mechanism": UNKNOWN,
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
}
POLICY_BOOLEANS = {
    "CKA_TOKEN", "CKA_PRIVATE", "CKA_SENSITIVE", "CKA_ENCRYPT",
    "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP", "CKA_SIGN", "CKA_VERIFY",
    "CKA_DERIVE", "CKA_EXTRACTABLE",
}
POLICY_BOOLEAN_TYPES = (
    0x01, 0x02, 0x103, 0x104, 0x105, 0x106,
    0x107, 0x108, 0x10A, 0x10C, 0x162,
)
SAFE_MAPS = {
    "ASYNC_FUNCTIONS", "CGROUP_FILTER", "CONFIG", "EVENTS", "EVIDENCE",
    "MECH_SHAPE", "PID_FILTER", "RV_COUNTS", "SLOT_SEMANTICS", "START",
    "STATS",
}
FEATURE_MAPS = SAFE_MAPS | {"ATTR_BOOL_BITS", "TEMPLATE_TAIL"}
EXPECTED_SENTINEL_FAMILIES = {
    "PIN", "KEY", "LABEL", "ID", "PLAINTEXT", "IV", "AAD", "BOOLLONG",
    "USERNAME", "CIPHERTEXT", "SIGNATURE", "WRAPPED", "RANDOM", "OUTPUT",
    "ARG7", "ARG8", "ARG9", "ASYNC",
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
    for source in (Path("scripts/fixtures/canary_workload.c"),
                   Path("scripts/fixtures/privacy-stack-workload.c")):
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


SENTINELS = fixture_sentinels() | {
    "ASYNC_ALIAS": b"AliasAsync_7a91c45d", "LEGACY_NAME": b"C_Encrypu",
}
HEX_TOKEN = re.compile(rb"0x([0-9a-fA-F]{2})(?![0-9a-fA-F])")
MECH_NONE = (1 << 64) - 1
FUNCTION_NONE = (1 << 32) - 1
ARG_READ_FAILURE = 1 << 4
CALL_START_SIZE = 272
EVENT_SIZE = 288


def profile_terminal(doc, schema="pkcs11-scope/observed-profile/v1.4"):
    assert doc["schema"] == schema, doc["schema"]
    ev = doc["evidence"]
    assert ev["completeness"] == "PARTIAL", ev


def trace_terminal(text, privacy):
    records = [line.removeprefix("EVIDENCE ") for line in text.splitlines()
               if line.startswith("EVIDENCE ")]
    assert len(records) == 1, f"expected one terminal EVIDENCE record, got {len(records)}"
    ev = json.loads(records[0])
    assert ev["privacy_mode"] == privacy, ev
    assert ev["completeness"] == "PARTIAL", ev
    assert ev["capture_aborted"] is None, ev
    assert ev["final_drain"] is False, ev
    assert ev["counters_available"] is True, ev
    return ev


def trace_abort_terminal(text, privacy):
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


def assert_aggregate_metrics(doc):
    assert doc["schema"] == "pkcs11-scope/observed-profile/v1.1-metrics"
    assert doc["capture"]["mode"] == "metrics"
    assert doc["capture"]["privacy_mode"] == "aggregate-only"
    profile_terminal(doc, "pkcs11-scope/observed-profile/v1.1-metrics")
    assert sum(item["calls"] for item in doc["functions"]) == 25, doc["functions"]


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


def parse_ring_records(data, capacity, consumer_pos, producer_pos):
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
        assert length == EVENT_SIZE, f"ring record size {length}, expected {EVENT_SIZE}"
        record_size = (8 + length + 7) & ~7
        assert record_size == 296 and position + record_size <= producer_pos
        records.append(bytes(data[offset + 8:offset + 8 + length]))
        position += record_size
    assert position == producer_pos
    return records


def ring_records(manifest):
    assert platform.machine() == "x86_64", "raw ring oracle requires Linux x86-64"
    item = manifest_map(manifest, "EVENTS")
    assert item["oracle"] == "mmap" and "file" not in item, item
    assert item["type"] == "ringbuf" and item["key_size"] == item["value_size"] == 0, item
    map_id, capacity = item["id"], item["max_entries"]
    attr = ctypes.create_string_buffer(struct.pack("=III", map_id, 0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(321, 14, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, f"BPF_MAP_GET_FD_BY_ID for EVENTS id {map_id}")
    page = mmap.PAGESIZE
    consumer = mmap.mmap(fd, page, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ, offset=0)
    producer = mmap.mmap(fd, page + 2 * capacity, flags=mmap.MAP_SHARED,
                         prot=mmap.PROT_READ, offset=page)
    before = (u64(consumer, 0), u64(producer, 0))
    records = parse_ring_records(producer[page:], capacity, *before)
    after = (u64(consumer, 0), u64(producer, 0))
    producer.close()
    consumer.close()
    os.close(fd)
    assert after == before, f"ring moved during snapshot: {before} -> {after}"
    return records


def assert_event_records(raw_records, lane, workload_pid):
    expected = 0 if lane == "aggregate-only-metrics" else 25
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
           for event in events if event["slot"] == 42]
    assert pss == [(1, ALIASES["pss_hash"], ALIASES["pss_mgf"], ALIASES["pss_salt"])], pss
    gcm = {(event["shape"], event["p0"], event["p1"], event["p2"])
           for event in events if event["slot"] == 29 and event["shape"] != 0}
    assert gcm == {
        (3, ALIASES["gcm220_iv"], ALIASES["gcm220_aad"], ALIASES["gcm220_tag"]),
        (4, ALIASES["gcm240_iv"], ALIASES["gcm240_aad"], ALIASES["gcm240_tag"]),
    }, gcm
    templates = [event for event in events
                 if event["slot"] == 20 and event["attrs"][0] == ALIASES["template_type"]]
    assert [(event["attrs"], event["attr_count"], event["attr_total"],
             event["attr_bools"], event["attr_seen"]) for event in templates] == [
        ((ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[:6], 0), 7, 7, 0x3F, 0x3F),
        ((ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[6:], 0, 0), 6, 6, 0x7C0, 0x7C0),
    ], templates
    fault_types = {event["slot"]: event["attrs"][0] for event in events
                   if event["slot"] in {21, 25}}
    assert fault_types == {21: 2, 25: 1}, fault_types
    for event in events:
        if event["slot"] in {21, 25}:
            assert (event["attr_count"], event["attr_total"], event["attr_bools"],
                    event["attr_seen"]) == (1, 1, 0, 0), event
            assert event["capture"] & ARG_READ_FAILURE


def assert_raw_events(manifest, lane, workload_pid, output):
    raw_records = ring_records(manifest)
    assert_event_records(raw_records, lane, workload_pid)
    Path(output).write_bytes(b"".join(raw_records))


def assert_exact_owned_map_inventory(lane, expected):
    manifest = read_json(f"{work}/mapdump_manifest_{lane}.json")
    names = {item["name"] for item in manifest}
    assert names == expected, f"{lane}: map inventory {names} != {expected}"
    ids = [item['id'] for item in manifest]
    assert all(isinstance(map_id, int) and map_id > 0 for map_id in ids), ids
    assert len(ids) == len(set(ids)), f"{lane}: duplicate observer-owned map ids {ids}"
    for item in manifest:
        if item["name"] == "EVENTS":
            assert item["oracle"] == "mmap" and "file" not in item, item
        else:
            assert item["oracle"] == "dump" and Path(item["file"]).is_file(), item


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


if work == "--raw-events":
    assert_raw_events(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    raise SystemExit
if work == "--hostile-starts":
    assert_hostile_starts(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    raise SystemExit
if work == "--fault-starts":
    assert_fault_starts(sys.argv[2], int(sys.argv[3]))
    raise SystemExit


if work == "--self-test":
    def reject(label, action):
        try:
            action()
        except AssertionError:
            return
        raise AssertionError(f"{label} mutation was accepted")

    full_fixture = {
        "attached_probes": 136, "table_entries": 68,
        "surfaces": [{"walk": "full", "acquisition": "ok"}],
        "shape_decode_failures": 0,
    }

    def terminal(privacy, semantic, unregistered=0):
        return {
            **full_fixture,
            "privacy_mode": privacy, "completeness": "PARTIAL",
            "capture_aborted": None,
            "final_drain": False, "counters_available": True,
            "semantic_capture_failures": semantic,
            "unregistered_mechanisms": unregistered, "async_target_failures": 2,
        }

    safe = {
        "schema": "pkcs11-scope/observed-profile/v1.4",
        "capture": {"mode": "profile", "privacy_mode": "allowlisted"},
        "evidence": {**full_fixture, "completeness": "PARTIAL", "unregistered_mechanisms": 2,
                     "semantic_capture_failures": 3, "async_target_failures": 2},
        "mechanisms": [{"mechanism": REGISTERED, "params": None}],
        "templates": {"operations": []},
    }
    assert_safe_profile(safe)
    reject("safe profile unknown-id", lambda: assert_safe_profile({
        **safe, "mechanisms": safe["mechanisms"] + [{"mechanism": UNKNOWN, "params": None}]
    }))
    bad_safe = json.loads(json.dumps(safe))
    bad_safe["evidence"]["semantic_capture_failures"] = 4
    reject("safe profile failure total", lambda: assert_safe_profile(bad_safe))

    safe_trace = "CAPTURE privacy=allowlisted\nC_DigestInit 0x250\nEVIDENCE " + json.dumps(
        terminal("allowlisted", 3, 2)
    )
    assert_safe_trace(safe_trace)
    reject("safe trace alias", lambda: assert_safe_trace(
        safe_trace.replace("C_DigestInit 0x250", f"C_DigestInit 0x250 0x{UNKNOWN:x}")
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
        "schema": "pkcs11-scope/observed-profile/v1.4",
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
        " ".join(f"0x{value:x}" for value in unsafe_values) + "\nEVIDENCE " + \
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
        "schema": "pkcs11-scope/observed-profile/v1.1-metrics",
        "capture": {"mode": "metrics", "privacy_mode": "aggregate-only"},
        "evidence": {
            **full_fixture,
            "completeness": "PARTIAL", "templates_truncated": False,
            "attach_failures": [], "skipped": [], "aliased": [],
            "in_flight_at_end": 0,
            "surfaces": [{"walk": "full", "acquisition": "ok"}],
            "vendor_interfaces": 0, "interface_list": "ok",
        },
        "functions": [{"calls": 25}],
    }
    assert_aggregate_metrics(aggregate)

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
    assert parse_ring_records(raw, mmap.PAGESIZE, 0, 296) == [event]
    for label, header, producer in (
        ("ring busy", EVENT_SIZE | (1 << 31), 296),
        ("ring discard", EVENT_SIZE | (1 << 30), 296),
        ("ring short", EVENT_SIZE - 1, 296),
        ("ring long", EVENT_SIZE + 1, 304),
    ):
        mutated = bytearray(raw)
        struct.pack_into("<I", mutated, 0, header)
        reject(label, lambda mutated=mutated, producer=producer:
               parse_ring_records(mutated, mmap.PAGESIZE, 0, producer))
    reject("ring producer wrap", lambda: parse_ring_records(raw, mmap.PAGESIZE, 296, 0))

    def event_bytes(index, mechanism=None, slot=0, shape=0, p0=0, p1=0, p2=0,
                    attrs=(), attr_count=0, attr_total=0, attr_bools=0,
                    attr_seen=0, capture=0):
        raw_event = bytearray(EVENT_SIZE)
        struct.pack_into("<Q", raw_event, 16, 0x555 << 32 | index)
        if index >= 22:
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
        return bytes(raw_event)

    safe_events = [event_bytes(index) for index in range(25)]
    assert_event_records(safe_events, "default-safe-profile", 0x555)
    assert_event_records([], "aggregate-only-metrics", 0x555)
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
    print("raw policy oracle self-test: OK")

    unsafe_events = list(safe_events)
    unsafe_events[9] = event_bytes(9, mechanism=REGISTERED)
    unsafe_events[10] = event_bytes(10, mechanism=UNKNOWN)
    unsafe_events[11] = event_bytes(11, mechanism=MAXIMUM)
    unsafe_events[12] = event_bytes(
        12, mechanism=0xD, slot=42, shape=1, p0=ALIASES["pss_hash"],
        p1=ALIASES["pss_mgf"], p2=ALIASES["pss_salt"]
    )
    unsafe_events[13] = event_bytes(
        13, mechanism=0x1087, slot=29, shape=3, p0=ALIASES["gcm220_iv"],
        p1=ALIASES["gcm220_aad"], p2=ALIASES["gcm220_tag"]
    )
    unsafe_events[14] = event_bytes(
        14, mechanism=0x1087, slot=29, shape=4, p0=ALIASES["gcm240_iv"],
        p1=ALIASES["gcm240_aad"], p2=ALIASES["gcm240_tag"]
    )
    unsafe_events[15] = event_bytes(
        15, slot=20, attrs=(ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[:6]),
        attr_count=7, attr_total=7, attr_bools=0x3F, attr_seen=0x3F
    )
    unsafe_events[16] = event_bytes(
        16, slot=20, attrs=(ALIASES["template_type"], *POLICY_BOOLEAN_TYPES[6:]),
        attr_count=6, attr_total=6, attr_bools=0x7C0, attr_seen=0x7C0
    )
    unsafe_events[17] = event_bytes(
        17, slot=21, attrs=(2,), attr_count=1, attr_total=1,
        capture=ARG_READ_FAILURE
    )
    unsafe_events[18] = event_bytes(
        18, slot=25, attrs=(1,), attr_count=1, attr_total=1,
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
    print("canary lane assertion self-test: OK")
    raise SystemExit

profiles = {
    lane: read_json(f"{work}/{lane}.output")
    for lane in ["default-safe-profile", "feature-safe-profile",
                 "feature-unsafe-profile", "aggregate-only-metrics"]
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

lanes = {
    "default-safe-profile": SAFE_MAPS, "default-safe-trace": SAFE_MAPS,
    "feature-safe-profile": FEATURE_MAPS, "feature-safe-trace": FEATURE_MAPS,
    "feature-unsafe-profile": FEATURE_MAPS, "feature-unsafe-trace": FEATURE_MAPS,
    "aggregate-only-metrics": SAFE_MAPS,
}
for lane, expected in lanes.items():
    assert_exact_owned_map_inventory(lane, expected)
for lane in ["feature-safe-profile", "feature-safe-trace"]:
    assert read_json(f"{work}/mapdump_ATTR_BOOL_BITS_{lane}.json") == []
    assert read_json(f"{work}/mapdump_TEMPLATE_TAIL_{lane}.json") == []
for lane in ["feature-unsafe-profile", "feature-unsafe-trace"]:
    assert len(read_json(f"{work}/mapdump_ATTR_BOOL_BITS_{lane}.json")) == 11
    assert len(read_json(f"{work}/mapdump_TEMPLATE_TAIL_{lane}.json")) == 1

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

artifacts = []
for lane in lanes:
    artifacts.extend(Path(work) / f"{lane}.{suffix}" for suffix in
                     ("output", "observer.log", "workload.log", "events.raw"))
artifacts.extend(Path(work).glob("mapdump_*.json"))
for lane in ("default-safe-start", "feature-safe-start", "feature-unsafe-fault"):
    artifacts.extend(Path(work) / f"{lane}.{suffix}" for suffix in
                     ("output", "observer.log", "workload.log"))
leaks = {}
for path in artifacts:
    content = path.read_bytes()
    found = sentinel_hits(content, reconstruct(content) if path.suffix == ".json" else b"")
    if found:
        leaks[str(path)] = sorted(found)
assert not leaks, f"ordinary pointer canaries leaked: {leaks}"

safe_lanes = (set(lanes) - {"feature-unsafe-profile", "feature-unsafe-trace"}) | {
    "default-safe-start", "feature-safe-start",
}
for lane in safe_lanes:
    paths = [Path(work) / f"{lane}.{suffix}" for suffix in
             ("output", "observer.log", "workload.log")]
    raw = Path(work) / f"{lane}.events.raw"
    if raw.exists():
        paths.append(raw)
    paths.extend(Path(work).glob(f"mapdump_*_{lane}.json"))
    for path in paths:
        content = path.read_bytes()
        reconstructed = reconstruct(content) if path.suffix == ".json" else b""
        found = alias_hits(content, reconstructed)
        assert not found, f"{lane}: scalar aliases {found} in {path}"

print(f"canary matrix OK: {len(lanes)} lanes; no ordinary or safe-policy alias leak")
PY
}

if [ "${1-}" = "--self-test" ]; then
    python3 scripts/check-capture-evidence.py --self-test
    assert_lanes --self-test
    exit 0
fi

. scripts/trusted-p11scope.sh
require_non_root_caller
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }

WPID=
SPID=
OBSERVER_PID=
OBSERVER_STARTTIME=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
WORKER_STOPPED=
PUBLISH_TMP=
cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    if [ -n "$OBSERVER_PID" ] && [ -n "$WORKER_STOPPED" ]; then
        signal_verified_root_process CONT "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
            "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" 2>/dev/null || true
        WORKER_STOPPED=
    fi
    OBSERVER_PID=
    OBSERVER_STARTTIME=
    if [ -n "$SUPERVISOR_PID" ] && [ -n "$SUPERVISOR_STARTTIME" ]; then
        signal_verified_root_process TERM "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME" \
            2>/dev/null || true
    elif [ -n "$SPID" ]; then
        kill -TERM "$SPID" 2>/dev/null || true
    fi
    [ -z "$WPID" ] || kill -TERM "$WPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    cleanup_step restore_suid_dumpable
    [ -z "$PUBLISH_TMP" ] || cleanup_step rm -f -- "$PUBLISH_TMP"
    cleanup_step remove_trusted_p11scope "$TRUST_DIR"
    cleanup_step remove_trusted_p11scope "$TRUST_UNSAFE_DIR"
    [ -z "$TRUST_ROOT" ] || cleanup_step sudo rm -f "$TRUST_ROOT/dump-owned-bpf-maps.py"
    cleanup_step remove_trusted_exec_root "$TRUST_ROOT"
    cleanup_step remove_protected_output_dir "$RUN_DIR"
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
rm -rf "$WORK/default-build" "$WORK/feature-build"
cargo +1.88 build --locked --release --workspace --target-dir "$WORK/default-build"
cargo +1.88 build --locked --release --workspace --features unsafe-unvalidated-metadata \
    --target-dir "$WORK/feature-build"
TRUST_ROOT=$(create_trusted_exec_dir)
TRUST_DIR=$TRUST_ROOT/default
TRUST_UNSAFE_DIR=$TRUST_ROOT/unsafe
RUN_DIR=$(create_protected_output_dir)
sudo install -o root -g root -m 0555 scripts/dump-owned-bpf-maps.py \
    "$TRUST_ROOT/dump-owned-bpf-maps.py"
stage_trusted_p11scope "$WORK/default-build/release/p11scope" \
    "$WORK/default-build/release/p11scope-discover" "$TRUST_DIR"
stage_trusted_p11scope "$WORK/feature-build/release/p11scope" \
    "$WORK/feature-build/release/p11scope-discover" "$TRUST_UNSAFE_DIR"
gcc -std=c11 -O0 -Wall -Wextra -o "$WORK/canary_workload" \
    scripts/fixtures/canary_workload.c -ldl -pthread
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/matrix-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/privacy-provider.so" crates/discover/tests/fixture/version_matrix.c
python3 scripts/dump-owned-bpf-maps.py --self-test

set -- "$WORK"/default-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "default BPF object is not unique"; exit 1; }
DEFAULT_BPF=$1
set -- "$WORK"/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "feature BPF object is not unique"; exit 1; }
FEATURE_BPF=$1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FEATURE_BPF"

observer_worker_pid() {
    ow_supervisor=$1
    ow_supervisor_starttime=$2
    ow_attempt=0
    while [ "$ow_attempt" -lt 160 ]; do
        root_process_matches_starttime "$ow_supervisor" "$ow_supervisor_starttime" || {
            echo "supervisor $ow_supervisor exited or changed identity" >&2
            return 1
        }
        ow_children=$(sudo cat "/proc/$ow_supervisor/task/$ow_supervisor/children" 2>/dev/null || true)
        set -- $ow_children
        if [ "$#" -eq 1 ]; then
            ow_worker=$1
            ow_worker_starttime=$(root_process_starttime "$ow_worker") || return 1
            ow_parent=$(sudo awk '$1 == "PPid:" { print $2; exit }' \
                "/proc/$ow_worker/status" 2>/dev/null) || return 1
            ow_recheck=$(sudo cat "/proc/$ow_supervisor/task/$ow_supervisor/children" \
                2>/dev/null || true)
            if [ "$ow_parent" = "$ow_supervisor" ] \
                && [ "$ow_recheck" = "$ow_children" ] \
                && root_process_matches_starttime "$ow_supervisor" "$ow_supervisor_starttime"; then
                printf '%s %s\n' "$ow_worker" "$ow_worker_starttime"
                return 0
            fi
        fi
        ow_attempt=$((ow_attempt + 1))
        sleep 0.05
    done
    echo "supervisor $ow_supervisor did not expose exactly one capture worker" >&2
    return 1
}

wait_for_stopped() {
    wfs_pid=$1
    wfs_starttime=$2
    wfs_attempt=0
    while [ "$wfs_attempt" -lt 160 ]; do
        root_process_matches_starttime "$wfs_pid" "$wfs_starttime" || {
            echo "capture worker $wfs_pid exited or changed identity" >&2
            return 1
        }
        wfs_state=$(sudo awk '$1 == "State:" { print $2; exit }' \
            "/proc/$wfs_pid/status" 2>/dev/null || true)
        [ "$wfs_state" = T ] && return 0
        wfs_attempt=$((wfs_attempt + 1))
        sleep 0.05
    done
    echo "capture worker $wfs_pid did not reach State: T after SIGSTOP" >&2
    return 1
}

run_lane() {
    lane=$1
    build=$2
    kind=$3
    case $build in
        default) lane_trust=$TRUST_DIR; lane_unsafe= ;;
        feature) lane_trust=$TRUST_UNSAFE_DIR; lane_unsafe= ;;
        feature-unsafe) lane_trust=$TRUST_UNSAFE_DIR; lane_unsafe=1 ;;
        *) echo "unknown lane build: $build" >&2; exit 1 ;;
    esac
    case $kind in
        profile) lane_command=profile; lane_mode=profile ;;
        trace) lane_command=trace; lane_mode= ;;
        metrics) lane_command=profile; lane_mode=metrics ;;
        *) echo "unknown lane kind: $kind" >&2; exit 1 ;;
    esac

    echo "=== $lane ($build $kind) ==="
    rm -f "$WORK/$lane.ready" "$WORK/$lane.go" "$WORK/$lane.output" \
        "$WORK/$lane.observer.log" "$WORK/$lane.workload.log" \
        "$WORK/$lane.events.raw" \
        "$WORK"/mapdump_*_"$lane".json "$WORK/mapdump_manifest_$lane.json"
    "$WORK/canary_workload" "$PWD/$WORK/matrix-provider.so" matrix \
        "$PWD/$WORK/$lane.ready" "$PWD/$WORK/$lane.go" \
        > "$WORK/$lane.workload.log" 2>&1 &
    WPID=$!
    lane_workload_pid=$WPID
    lane_ready_attempt=0
    while [ ! -f "$WORK/$lane.ready" ] && [ "$lane_ready_attempt" -lt 160 ]; do
        kill -0 "$WPID" 2>/dev/null || { echo "$lane workload exited before ready"; exit 1; }
        lane_ready_attempt=$((lane_ready_attempt + 1))
        sleep 0.05
    done
    test -f "$WORK/$lane.ready" || { echo "$lane workload never became ready"; exit 1; }

    set -- "$lane_trust/p11scope" "$lane_command" \
        --manifest "$RUN_DIR/matrix-manifest.json" \
        --provenance-module "$PWD/$WORK/matrix-provider.so" --pid "$WPID" \
        --trusted-workload
    [ -z "$lane_mode" ] || set -- "$@" --mode "$lane_mode"
    [ -z "$lane_unsafe" ] || set -- "$@" --unsafe-unvalidated-metadata
    set -- "$@" --duration 6 -o "$RUN_DIR/$lane.output"
    sudo sh -c '
        umask 077
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' "/proc/$$/stat") || exit 1
        printf "%s %s\n" "$$" "$starttime" > "$1"
        shift
        exec "$@"
    ' sh \
        "$RUN_DIR/$lane.observer.pid" "$@" \
        > "$WORK/$lane.observer.log" 2>&1 &
    SPID=$!
    case $build in
        feature-unsafe) lane_privacy=unsafe-unvalidated-metadata ;;
        *) [ "$kind" = metrics ] && lane_privacy=aggregate-only || lane_privacy=allowlisted ;;
    esac
    wait_for_capture_ready "$WORK/$lane.observer.log" "$lane_privacy" "$kind"
    sudo test -s "$RUN_DIR/$lane.observer.pid" || { echo "$lane supervisor pid missing"; exit 1; }
    set -- $(sudo cat "$RUN_DIR/$lane.observer.pid")
    [ "$#" -eq 2 ] || { echo "$lane supervisor identity invalid"; exit 1; }
    SUPERVISOR_PID=$1
    SUPERVISOR_STARTTIME=$2
    case $SUPERVISOR_PID:$SUPERVISOR_STARTTIME in
        *[!0-9:]*) echo "$lane supervisor identity invalid"; exit 1 ;;
    esac
    set -- $(observer_worker_pid "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME")
    [ "$#" -eq 2 ] || { echo "$lane worker identity invalid"; exit 1; }
    OBSERVER_PID=$1
    OBSERVER_STARTTIME=$2
    case $OBSERVER_PID:$OBSERVER_STARTTIME in
        *[!0-9:]*) echo "$lane worker identity invalid"; exit 1 ;;
    esac
    signal_verified_root_process STOP "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
        "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
    WORKER_STOPPED=1
    wait_for_stopped "$OBSERVER_PID" "$OBSERVER_STARTTIME"
    touch "$WORK/$lane.go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$lane workload failed: $status"; exit "$status"; fi
    sudo python3 "$TRUST_ROOT/dump-owned-bpf-maps.py" \
        "$OBSERVER_PID" "$RUN_DIR" "$lane" 0 16384
    assert_lanes --raw-events "$RUN_DIR/mapdump_manifest_$lane.json" "$lane" \
        "$lane_workload_pid" "$RUN_DIR/$lane.events.raw"
    signal_verified_root_process CONT "$OBSERVER_PID" "$OBSERVER_STARTTIME" \
        "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME"
    WORKER_STOPPED=
    OBSERVER_PID=
    OBSERVER_STARTTIME=
    if wait "$SPID"; then SPID=; SUPERVISOR_PID=; SUPERVISOR_STARTTIME=; else status=$?; SPID=; SUPERVISOR_PID=; SUPERVISOR_STARTTIME=; echo "$lane observer failed: $status"; exit "$status"; fi
    publish_protected_file "$RUN_DIR" "$lane.output" "$WORK" "$lane.output"
    python3 scripts/check-capture-evidence.py canary "$lane" "$WORK/$lane.output"
    publish_protected_file "$RUN_DIR" "$lane.events.raw" "$WORK" "$lane.events.raw"
    publish_protected_mapdump_lane "$RUN_DIR" "$WORK" "$lane"
}

echo "=== discover deterministic matrix providers ==="
"$WORK/default-build/release/p11scope-discover" \
    --module "$PWD/$WORK/matrix-provider.so" -o "$WORK/.matrix-manifest.candidate"
"$WORK/default-build/release/p11scope-discover" \
    --module "$PWD/$WORK/privacy-provider.so" -o "$WORK/.privacy-manifest.candidate"
sudo install -o root -g root -m 0600 "$WORK/.matrix-manifest.candidate" \
    "$RUN_DIR/matrix-manifest.json"
sudo install -o root -g root -m 0600 "$WORK/.privacy-manifest.candidate" \
    "$RUN_DIR/privacy-manifest.json"
rm -f "$WORK/.matrix-manifest.candidate" "$WORK/.privacy-manifest.candidate"
rm -f "$WORK"/mapdump_*.json "$WORK"/mapdump_manifest_*.json
set_suid_dumpable_zero

while read -r lane build kind; do
    run_lane "$lane" "$build" "$kind"
done <<'LANES'
default-safe-profile default profile
default-safe-trace default trace
feature-safe-profile feature profile
feature-safe-trace feature trace
feature-unsafe-profile feature-unsafe profile
feature-unsafe-trace feature-unsafe trace
aggregate-only-metrics default metrics
LANES

run_start_lane() {
    start_lane=$1
    start_build=$2
    start_mode=$3
    start_entries=$4
    start_oracle=$5
    case $start_build in
        default) start_trust=$TRUST_DIR; start_privacy=allowlisted; start_unsafe= ;;
        feature) start_trust=$TRUST_UNSAFE_DIR; start_privacy=allowlisted; start_unsafe= ;;
        feature-unsafe) start_trust=$TRUST_UNSAFE_DIR; start_privacy=unsafe-unvalidated-metadata; start_unsafe=1 ;;
        *) echo "unknown START build: $start_build" >&2; exit 1 ;;
    esac
    rm -f "$WORK/$start_lane.go" \
        "$WORK/$start_lane.output" "$WORK/$start_lane.observer.log" \
        "$WORK/$start_lane.workload.log" "$WORK"/mapdump_*_"$start_lane".json \
        "$WORK/mapdump_manifest_$start_lane.json"
    ( while [ ! -f "$WORK/$start_lane.go" ]; do sleep 0.05; done
      exec "$WORK/canary_workload" "$PWD/$WORK/privacy-provider.so" "$start_mode" ) \
        > "$WORK/$start_lane.workload.log" 2>&1 &
    WPID=$!
    start_workload_pid=$WPID
    set -- "$start_trust/p11scope" profile --manifest "$RUN_DIR/privacy-manifest.json" \
        --provenance-module "$PWD/$WORK/privacy-provider.so" --pid "$WPID" \
        --trusted-workload --mode profile --duration 8 -o "$RUN_DIR/$start_lane.output"
    [ -z "$start_unsafe" ] || set -- "$@" --unsafe-unvalidated-metadata
    sudo sh -c '
        umask 077
        starttime=$(awk '\''{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }'\'' "/proc/$$/stat") || exit 1
        printf "%s %s\n" "$$" "$starttime" > "$1"
        shift
        exec "$@"
    ' sh \
        "$RUN_DIR/$start_lane.observer.pid" "$@" > "$WORK/$start_lane.observer.log" 2>&1 &
    SPID=$!
    wait_for_capture_ready "$WORK/$start_lane.observer.log" "$start_privacy" profile
    set -- $(sudo cat "$RUN_DIR/$start_lane.observer.pid")
    [ "$#" -eq 2 ] || { echo "$start_lane supervisor identity invalid"; exit 1; }
    SUPERVISOR_PID=$1
    SUPERVISOR_STARTTIME=$2
    case $SUPERVISOR_PID:$SUPERVISOR_STARTTIME in
        *[!0-9:]*) echo "$start_lane supervisor identity invalid"; exit 1 ;;
    esac
    set -- $(observer_worker_pid "$SUPERVISOR_PID" "$SUPERVISOR_STARTTIME")
    [ "$#" -eq 2 ] || { echo "$start_lane worker identity invalid"; exit 1; }
    OBSERVER_PID=$1
    OBSERVER_STARTTIME=$2
    case $OBSERVER_PID:$OBSERVER_STARTTIME in
        *[!0-9:]*) echo "$start_lane worker identity invalid"; exit 1 ;;
    esac
    touch "$WORK/$start_lane.go"
    sudo python3 "$TRUST_ROOT/dump-owned-bpf-maps.py" "$OBSERVER_PID" "$RUN_DIR" \
        "$start_lane" "$start_entries" 16384
    if [ "$start_oracle" = --fault-starts ]; then
        assert_lanes "$start_oracle" "$RUN_DIR/mapdump_manifest_$start_lane.json" \
            "$start_workload_pid"
    else
        assert_lanes "$start_oracle" "$RUN_DIR/mapdump_manifest_$start_lane.json" \
            "$WORK/$start_lane.workload.log" "$start_workload_pid"
    fi
    kill -0 "$WPID" || { echo "$start_lane workload exited before START oracle completed"; exit 1; }
    kill -TERM "$WPID" || { echo "$start_lane workload could not be terminated"; exit 1; }
    if wait "$WPID"; then
        start_status=0
        WPID=
    else
        start_status=$?
        WPID=
    fi
    [ "$start_status" -eq 143 ] || {
        echo "$start_lane workload exit status $start_status, expected SIGTERM status 143"
        exit 1
    }
    OBSERVER_PID=
    OBSERVER_STARTTIME=
    if wait "$SPID"; then SPID=; SUPERVISOR_PID=; SUPERVISOR_STARTTIME=; else status=$?; SPID=; SUPERVISOR_PID=; SUPERVISOR_STARTTIME=; echo "$start_lane observer failed: $status"; exit "$status"; fi
    publish_protected_file "$RUN_DIR" "$start_lane.output" "$WORK" "$start_lane.output"
    publish_protected_mapdump_lane "$RUN_DIR" "$WORK" "$start_lane"
    if [ "$start_lane" = default-safe-start ]; then
        PUBLISH_TMP=$(mktemp "$WORK/.mapdump_START_live.XXXXXXXX")
        cp "$WORK/mapdump_START_$start_lane.json" "$PUBLISH_TMP"
        mv -f "$PUBLISH_TMP" "$WORK/mapdump_START_live.json"
        PUBLISH_TMP=
    fi
}

echo "=== live safe START policy: hostile exact-name and mechanism controls ==="
while read -r lane build; do
    run_start_lane "$lane" "$build" blocked 4 --hostile-starts
done <<'BLOCKED_LANES'
default-safe-start default
feature-safe-start feature
BLOCKED_LANES

echo "=== live diagnostic START policy: distinct template faults ==="
run_start_lane feature-unsafe-fault feature-unsafe faults 2 --fault-starts

restore_suid_dumpable

publish_protected_file "$RUN_DIR" matrix-manifest.json "$WORK" matrix-manifest.json
publish_protected_file "$RUN_DIR" privacy-manifest.json "$WORK" privacy-manifest.json

echo "=== assert capture-policy matrix ==="
assert_lanes "$WORK"
echo "=== canary matrix: ALL OK ==="
