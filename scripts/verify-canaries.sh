#!/bin/sh
# Gate G3: hostile pointer aliases across the complete capture-policy matrix.
# Live BPF work is approval-gated; this file is kept syntactically and
# statically testable even when the gate remains UNRUN.
set -eu
cd "$(dirname "$0")/.."

WORK=target/canaries
TRUST_DIR="$PWD/$WORK/trusted"
TRUST_UNSAFE_DIR="$PWD/$WORK/trusted-unsafe"
RUN_DIR=/run/p11scope-canaries-$$

assert_lanes() {
    python3 - "$1" <<'PY'
import json
from pathlib import Path
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
SAFE_MAPS = {
    "ASYNC_FUNCTIONS", "CGROUP_FILTER", "CONFIG", "EVENTS", "EVIDENCE",
    "MECH_SHAPE", "PID_FILTER", "RV_COUNTS", "SLOT_SEMANTICS", "START",
    "STATS",
}
FEATURE_MAPS = SAFE_MAPS | {"ATTR_BOOL_BITS", "TEMPLATE_TAIL"}
ZERO_AGGREGATE_EVIDENCE = (
    "event_loss", "start_insert_failures", "unmatched_returns",
    "rv_update_failures", "cgroup_scope_failures", "semantic_capture_failures",
    "unregistered_mechanisms", "template_tail_failures", "state_reconciliations",
    "session_cancel_ambiguities", "session_cancel_unknown_flags",
    "operation_state_imports", "auth_state_ambiguities", "async_target_failures",
    "async_orphans", "async_duplicates", "async_evictions", "fork_state_ambiguities",
    "semantic_state_drops", "pending_at_end", "malformed_records",
    "shape_decode_failures", "shape_decode_total_failures",
)
SENTINELS = {
    "PIN": b"CANARY_PIN_e68d21cf481bb1efcc17dab7c0183bdd",
    "KEY": b"CANARY_KEY_58fa8b6832cfa111313260aa3314ad0f",
    "LABEL": b"CANARY_LABEL_5527f89ff269f233a661f5d3a11d082e",
    "ID": b"CANARY_ID_d4875f5041bd7364aee7c2d625bb57f7",
    "PLAINTEXT": b"CANARY_PLAINTEXT_64193ef05a68b3de185c0f430c8190ba",
    "IV": b"CANARY_IV_d81e4ec085489f1adfcf4729eadd745d",
    "AAD": b"CANARY_AAD_5b1502ea971ec81f4b974fe84d62a22f",
    "BOOLLONG": b"CANARY_BOOLLONG_7cd9f6ab17348ba2e65a43d173f9ea1d",
    "USERNAME": b"CANARY_USERNAME_e2df5c11270a7b893619aa831b78fc18",
    "CIPHERTEXT": b"CANARY_CIPHERTEXT_c01ee2e83e86bb323d3c44ffb2f04296",
    "SIGNATURE": b"CANARY_SIGNATURE_a578d332cab775078a719c4c520bfd8c",
    "WRAPPED": b"CANARY_WRAPPED_a7048bd887266e35062ac8d42d0197cc",
    "RANDOM": b"CANARY_RANDOM_0f433fc130b6af2d4f5128d91a652d31",
    "OUTPUT": b"CANARY_OUTPUT_5391960450406458bc83e37c2b43b80b",
    "ARG7": b"CANARY_ARG7_b2747079a35f10aba729f83ff3285ddc",
    "ARG8": b"CANARY_ARG8_1752403b4bb53924b6881d095e3e9198",
    "ARG9": b"CANARY_ARG9_8f119353c9e69ce4f2f3b9a4d2aa2fab",
    "ASYNC_ALIAS": b"AliasAsync_7a91c45d",
    "LEGACY_NAME": b"C_Encrypu",
}
HEX_TOKEN = re.compile(rb"0x([0-9a-fA-F]{2})(?![0-9a-fA-F])")


def profile_terminal(doc):
    assert doc["evidence"]["completeness"] == "PARTIAL", doc["evidence"]


def trace_terminal(text, privacy):
    records = [line.removeprefix("EVIDENCE ") for line in text.splitlines()
               if line.startswith("EVIDENCE ")]
    assert len(records) == 1, f"expected one terminal EVIDENCE record, got {len(records)}"
    ev = json.loads(records[0])
    assert ev["privacy_mode"] == privacy, ev
    assert ev["completeness"] == "PARTIAL", ev
    assert ev["final_drain"] is False, ev
    assert ev["counters_available"] is True, ev
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
    assert ev["unregistered_mechanisms"] >= 2, ev
    assert ev["semantic_capture_failures"] >= 3, ev
    assert ev["async_target_failures"] == 2, ev


def assert_safe_trace(text):
    assert text.startswith("CAPTURE privacy=allowlisted\n"), text[:200]
    ev = trace_terminal(text, "allowlisted")
    assert "C_DigestInit 0x250" in text, "registered mechanism missing from trace"
    for value in set(ALIASES.values()) | {MAXIMUM}:
        assert str(value) not in text and f"0x{value:x}" not in text, value
    assert ev["unregistered_mechanisms"] >= 2, ev
    assert ev["semantic_capture_failures"] >= 3, ev
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
    ev = doc["evidence"]
    assert ev["semantic_capture_failures"] >= 6, ev
    assert ev["async_target_failures"] == 2, ev
    assert ev["templates_truncated"] is False, ev


def assert_unsafe_trace(text):
    assert text.startswith("CAPTURE privacy=unsafe-unvalidated-metadata\n"), text[:200]
    ev = trace_terminal(text, "unsafe-unvalidated-metadata")
    for value in [UNKNOWN, MAXIMUM, *[ALIASES[name] for name in (
        "pss_hash", "pss_mgf", "pss_salt", "gcm220_iv", "gcm220_aad",
        "gcm220_tag", "gcm240_iv", "gcm240_aad", "gcm240_tag")]]:
        assert str(value) in text or f"0x{value:x}" in text, f"trace missed {value:#x}"
    assert ev["semantic_capture_failures"] >= 6, ev
    assert ev["async_target_failures"] == 2, ev


def assert_aggregate_metrics(doc):
    assert doc["schema"] == "pkcs11-scope/observed-profile/v1.1-metrics"
    assert doc["capture"]["mode"] == "metrics"
    assert doc["capture"]["privacy_mode"] == "aggregate-only"
    profile_terminal(doc)
    assert sum(item["calls"] for item in doc["functions"]) >= 24, doc["functions"]
    ev = doc["evidence"]
    assert {name: ev[name] for name in ZERO_AGGREGATE_EVIDENCE} == {
        name: 0 for name in ZERO_AGGREGATE_EVIDENCE
    }, ev
    assert ev["templates_truncated"] is False, ev


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def assert_exact_owned_map_inventory(lane, expected):
    manifest = read_json(f"{work}/mapdump_manifest_{lane}.json")
    names = {item["name"] for item in manifest}
    assert names == expected, f"{lane}: map inventory {names} != {expected}"
    ids = [item['id'] for item in manifest]
    assert all(isinstance(map_id, int) and map_id > 0 for map_id in ids), ids
    assert len(ids) == len(set(ids)), f"{lane}: duplicate observer-owned map ids {ids}"
    for item in manifest:
        assert Path(item["file"]).is_file(), item


def assert_nonempty_start():
    start = read_json(f"{work}/mapdump_START_live.json")
    assert len(start) >= 9, f"live START map has only {len(start)} entries"


def alias_hits(content, reconstructed=b""):
    lower = content.lower()
    return {name for name, value in ALIASES.items()
            if str(value).encode() in lower or f"0x{value:x}".encode() in lower
            or struct.pack("<Q", value) in reconstructed}


def sentinel_hits(content, reconstructed=b""):
    lower = content.lower()
    return {name for name, value in SENTINELS.items()
            if value in content or value.hex().encode() in lower or value in reconstructed}


def reconstruct(content):
    return bytes(int(value, 16) for value in HEX_TOKEN.findall(content))


def positive_control_content():
    return b'{"value":[' + b",".join(
        f'"0x{byte:02x}"'.encode() for byte in SENTINELS["PIN"]) + b"]}\n"


if work == "--self-test":
    def reject(label, action):
        try:
            action()
        except AssertionError:
            return
        raise AssertionError(f"{label} mutation was accepted")

    def terminal(privacy, semantic, unregistered=0):
        return {
            "privacy_mode": privacy, "completeness": "PARTIAL",
            "final_drain": False, "counters_available": True,
            "semantic_capture_failures": semantic,
            "unregistered_mechanisms": unregistered, "async_target_failures": 2,
        }

    safe = {
        "capture": {"mode": "profile", "privacy_mode": "allowlisted"},
        "evidence": {"completeness": "PARTIAL", "unregistered_mechanisms": 2,
                     "semantic_capture_failures": 3, "async_target_failures": 2},
        "mechanisms": [{"mechanism": REGISTERED, "params": None}],
        "templates": {"operations": []},
    }
    assert_safe_profile(safe)
    reject("safe profile unknown-id", lambda: assert_safe_profile({
        **safe, "mechanisms": safe["mechanisms"] + [{"mechanism": UNKNOWN, "params": None}]
    }))

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
        "capture": {"mode": "profile", "privacy_mode": "unsafe-unvalidated-metadata"},
        "evidence": {**terminal("unsafe-unvalidated-metadata", 6),
                     "templates_truncated": False},
        "mechanisms": [
            {"mechanism": REGISTERED, "params": None},
            {"mechanism": UNKNOWN, "params": None},
            {"mechanism": MAXIMUM, "params": None},
            {"mechanism": 0xD, "params": pss},
            {"mechanism": 0x1087, "params": gcm},
        ],
        "templates": {"operations": [{
            "names": ["C_CreateObject"], "requested": True,
            "attr_types": [{"attr_type": ALIASES["template_type"]}],
            "policy_booleans": {"observed_true": sorted(POLICY_BOOLEANS),
                                "observed_false": []},
        }]},
    }
    assert_unsafe_profile(unsafe)
    bad_unsafe = json.loads(json.dumps(unsafe))
    bad_unsafe["templates"]["operations"][0]["policy_booleans"]["observed_true"].pop()
    reject("unsafe profile policy boolean", lambda: assert_unsafe_profile(bad_unsafe))

    unsafe_values = [UNKNOWN, MAXIMUM, *[ALIASES[name] for name in (
        "pss_hash", "pss_mgf", "pss_salt", "gcm220_iv", "gcm220_aad",
        "gcm220_tag", "gcm240_iv", "gcm240_aad", "gcm240_tag")]]
    unsafe_trace = "CAPTURE privacy=unsafe-unvalidated-metadata\n" + \
        " ".join(f"0x{value:x}" for value in unsafe_values) + "\nEVIDENCE " + \
        json.dumps(terminal("unsafe-unvalidated-metadata", 6))
    assert_unsafe_trace(unsafe_trace)
    missing = f"0x{ALIASES['pss_hash']:x}"
    reject("unsafe trace PSS alias", lambda: assert_unsafe_trace(
        unsafe_trace.replace(missing, "removed", 1)
    ))

    aggregate = {
        "schema": "pkcs11-scope/observed-profile/v1.1-metrics",
        "capture": {"mode": "metrics", "privacy_mode": "aggregate-only"},
        "evidence": {"completeness": "PARTIAL", "templates_truncated": False,
                     **{name: 0 for name in ZERO_AGGREGATE_EVIDENCE}},
        "functions": [{"calls": 24}],
    }
    assert_aggregate_metrics(aggregate)
    bad_aggregate = json.loads(json.dumps(aggregate))
    bad_aggregate["evidence"]["semantic_capture_failures"] = 1
    reject("aggregate semantic evidence", lambda: assert_aggregate_metrics(bad_aggregate))

    control = positive_control_content()
    assert sentinel_hits(control) == set()
    assert sentinel_hits(control, reconstruct(control)) == {"PIN"}
    alias = ALIASES["pss_hash"]
    assert alias_hits(str(alias).encode()) == {"pss_hash"}
    assert alias_hits(b"", struct.pack("<Q", alias)) == {"pss_hash"}
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
assert_nonempty_start()

ring = Path(f"{work}/aggregate-only-metrics.ring-empty").read_text(encoding="utf-8")
assert ring.endswith("available=0\n"), ring
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
                     ("output", "observer.log", "workload.log"))
artifacts.extend(Path(work).glob("mapdump_*.json"))
artifacts.extend(Path(work) / name for name in
                 ("privacy-observed.json", "privacy-profile.log", "privacy-workload.log"))
leaks = {}
for path in artifacts:
    content = path.read_bytes()
    found = sentinel_hits(content, reconstruct(content) if path.suffix == ".json" else b"")
    if found:
        leaks[str(path)] = sorted(found)
assert not leaks, f"ordinary pointer canaries leaked: {leaks}"

safe_lanes = set(lanes) - {"feature-unsafe-profile", "feature-unsafe-trace"}
for lane in safe_lanes:
    paths = [Path(work) / f"{lane}.{suffix}" for suffix in
             ("output", "observer.log", "workload.log")]
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
    assert_lanes --self-test
    exit 0
fi

mkdir -p "$WORK"
. scripts/trusted-p11scope.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }

WPID=
SPID=
OBSERVER_PID=
PUBLISH_TMP=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$OBSERVER_PID" ] || sudo kill -TERM "$OBSERVER_PID" 2>/dev/null || true
    [ -z "$WPID" ] || kill -TERM "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill -TERM "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    [ -z "$PUBLISH_TMP" ] || rm -f -- "$PUBLISH_TMP"
    remove_trusted_p11scope "$TRUST_DIR"
    remove_trusted_p11scope "$TRUST_UNSAFE_DIR"
    if sudo test -d "$RUN_DIR"; then
        sudo find "$RUN_DIR" -mindepth 1 -maxdepth 1 -type f -delete
        sudo rmdir "$RUN_DIR"
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
rm -rf "$WORK/default-build" "$WORK/feature-build"
cargo build --locked --release --workspace --target-dir "$WORK/default-build"
cargo build --locked --release --workspace --features unsafe-unvalidated-metadata \
    --target-dir "$WORK/feature-build"
stage_trusted_p11scope "$WORK/default-build/release/p11scope" \
    "$WORK/default-build/release/p11scope-discover" "$TRUST_DIR"
stage_trusted_p11scope "$WORK/feature-build/release/p11scope" \
    "$WORK/feature-build/release/p11scope-discover" "$TRUST_UNSAFE_DIR"
gcc -std=c11 -O0 -Wall -Wextra -o "$WORK/canary_workload" \
    scripts/fixtures/canary_workload.c -ldl
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 \
    -o "$WORK/matrix-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/privacy-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -O0 -Wall -Wextra -pthread -o "$WORK/privacy-stack-workload" \
    scripts/fixtures/privacy-stack-workload.c -ldl
python3 scripts/dump-owned-bpf-maps.py --self-test
sudo install -d -o root -g root -m 0700 "$RUN_DIR"

set -- "$WORK"/default-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "default BPF object is not unique"; exit 1; }
DEFAULT_BPF=$1
set -- "$WORK"/feature-build/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "feature BPF object is not unique"; exit 1; }
FEATURE_BPF=$1
python3 scripts/check-bpf-map-defs.py --policy-inventory "$DEFAULT_BPF" "$FEATURE_BPF"

observer_worker_pid() {
    ow_supervisor=$1
    ow_attempt=0
    while [ "$ow_attempt" -lt 160 ]; do
        ow_children=$(sudo cat "/proc/$ow_supervisor/task/$ow_supervisor/children" 2>/dev/null || true)
        set -- $ow_children
        if [ "$#" -eq 1 ]; then
            printf '%s\n' "$1"
            return 0
        fi
        ow_attempt=$((ow_attempt + 1))
        sleep 0.05
    done
    echo "supervisor $ow_supervisor did not expose exactly one capture worker" >&2
    return 1
}

wait_for_capture_ready() {
    wcr_log=$1
    wcr_privacy=$2
    wcr_kind=$3
    wcr_attempt=0
    while [ "$wcr_attempt" -lt 160 ]; do
        case $wcr_kind in
            trace) grep -Fqx "CAPTURE privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
            profile|metrics) grep -Fq " — privacy=$wcr_privacy" "$wcr_log" 2>/dev/null && return 0 ;;
            *) echo "unknown readiness kind: $wcr_kind" >&2; return 1 ;;
        esac
        [ -z "$SPID" ] || kill -0 "$SPID" 2>/dev/null || {
            echo "observer exited before capture readiness: $wcr_log" >&2
            return 1
        }
        wcr_attempt=$((wcr_attempt + 1))
        sleep 0.05
    done
    echo "observer never reported capture readiness: $wcr_log" >&2
    return 1
}

assert_ring_empty() {
    sudo python3 - "$1" <<'PY'
import ctypes
import json
import mmap
import platform
import struct
import sys

assert platform.machine() == "x86_64", "ring mmap oracle currently requires Linux x86-64"
events = [item for item in json.load(open(sys.argv[1])) if item["name"] == "EVENTS"]
assert len(events) == 1, f"expected one exact observer-owned EVENTS id, got {events}"
info = events[0]
map_id = info["id"]
assert info["type"] == "ringbuf", info

# BPF_MAP_GET_FD_BY_ID (14) through the x86-64 bpf syscall (321). A
# successful fd plus successful ring mmap is required; an unsupported or
# invalid operation cannot be mistaken for an empty ring.
attr = ctypes.create_string_buffer(struct.pack("=III", map_id, 0, 0))
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.syscall(321, 14, ctypes.byref(attr), ctypes.sizeof(attr))
if fd < 0:
    error = ctypes.get_errno()
    raise OSError(error, f"BPF_MAP_GET_FD_BY_ID for EVENTS id {map_id}")
page = mmap.PAGESIZE
consumer = mmap.mmap(fd, page, flags=mmap.MAP_SHARED,
                     prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
producer = mmap.mmap(fd, page + 2 * info["max_entries"], flags=mmap.MAP_SHARED,
                     prot=mmap.PROT_READ, offset=page)
consumer_pos = struct.unpack_from("=Q", consumer)[0]
producer_pos = struct.unpack_from("=Q", producer)[0]
producer.close()
consumer.close()
libc.close(fd)
assert producer_pos == consumer_pos, (
    f"aggregate-only EVENTS id {map_id} is not empty: "
    f"producer={producer_pos} consumer={consumer_pos}"
)
print(f"EVENTS id={map_id} producer={producer_pos} consumer={consumer_pos} available=0")
PY
}

publish_protected() {
    pp_source=$1
    pp_dest=$2
    PUBLISH_TMP="$WORK/.$pp_dest.$$"
    sudo cat "$RUN_DIR/$pp_source" > "$PUBLISH_TMP"
    mv -f "$PUBLISH_TMP" "$WORK/$pp_dest"
    PUBLISH_TMP=
    test -s "$WORK/$pp_dest" || { echo "$pp_dest was not published"; exit 1; }
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
    rm -f "$WORK/$lane.go" "$WORK/$lane.observer.pid" "$WORK/$lane.output" \
        "$WORK/$lane.observer.log" "$WORK/$lane.workload.log" \
        "$WORK"/mapdump_*_"$lane".json "$WORK/mapdump_manifest_$lane.json"
    ( while [ ! -f "$WORK/$lane.go" ]; do sleep 0.05; done
      exec "$WORK/canary_workload" "$PWD/$WORK/matrix-provider.so" matrix ) \
        > "$WORK/$lane.workload.log" 2>&1 &
    WPID=$!

    set -- "$lane_trust/p11scope" "$lane_command" \
        --manifest "$WORK/matrix-manifest.json" \
        --provenance-module "$PWD/$WORK/matrix-provider.so" --pid "$WPID"
    [ -z "$lane_mode" ] || set -- "$@" --mode "$lane_mode"
    [ -z "$lane_unsafe" ] || set -- "$@" --unsafe-unvalidated-metadata
    set -- "$@" --duration 6 -o "$RUN_DIR/$lane.output"
    sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/$lane.observer.pid" "$@" \
        > "$WORK/$lane.observer.log" 2>&1 &
    SPID=$!
    case $build in
        feature-unsafe) lane_privacy=unsafe-unvalidated-metadata ;;
        *) [ "$kind" = metrics ] && lane_privacy=aggregate-only || lane_privacy=allowlisted ;;
    esac
    wait_for_capture_ready "$WORK/$lane.observer.log" "$lane_privacy" "$kind"
    test -s "$WORK/$lane.observer.pid" || { echo "$lane supervisor pid missing"; exit 1; }
    lane_supervisor=$(cat "$WORK/$lane.observer.pid")
    OBSERVER_PID=$(observer_worker_pid "$lane_supervisor")
    sudo kill -0 "$OBSERVER_PID"
    touch "$WORK/$lane.go"
    if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "$lane workload failed: $status"; exit "$status"; fi
    sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" "$lane" 0 16384
    if [ "$kind" = metrics ]; then
        assert_ring_empty "$WORK/mapdump_manifest_$lane.json" > "$WORK/$lane.ring-empty"
    fi
    if wait "$SPID"; then SPID=; OBSERVER_PID=; else status=$?; SPID=; OBSERVER_PID=; echo "$lane observer failed: $status"; exit "$status"; fi
    publish_protected "$lane.output" "$lane.output"
}

echo "=== discover deterministic matrix providers ==="
"$WORK/default-build/release/p11scope-discover" \
    --module "$PWD/$WORK/matrix-provider.so" -o "$WORK/matrix-manifest.json"
"$WORK/default-build/release/p11scope-discover" \
    --module "$PWD/$WORK/privacy-provider.so" -o "$WORK/privacy-manifest.json"
rm -f "$WORK"/mapdump_*.json "$WORK"/mapdump_manifest_*.json

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

echo "=== live START map: nine blocked 2.40/3.0/3.2 calls ==="
rm -f "$WORK/privacy-go" "$WORK/privacy-observer.pid" "$WORK/privacy-observed.json" \
    "$WORK/privacy-profile.log" "$WORK/privacy-workload.log"
( while [ ! -f "$WORK/privacy-go" ]; do sleep 0.05; done
  exec "$WORK/privacy-stack-workload" "$PWD/$WORK/privacy-provider.so" ) \
    > "$WORK/privacy-workload.log" 2>&1 &
WPID=$!
sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/privacy-observer.pid" \
    "$TRUST_DIR/p11scope" profile --manifest "$WORK/privacy-manifest.json" \
    --provenance-module "$PWD/$WORK/privacy-provider.so" --pid "$WPID" \
    --mode profile --duration 8 -o "$RUN_DIR/privacy-observed.json" \
    > "$WORK/privacy-profile.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/privacy-profile.log" allowlisted profile
test -s "$WORK/privacy-observer.pid" || { echo "privacy supervisor pid missing"; exit 1; }
privacy_supervisor=$(cat "$WORK/privacy-observer.pid")
OBSERVER_PID=$(observer_worker_pid "$privacy_supervisor")
sudo kill -0 "$OBSERVER_PID"
touch "$WORK/privacy-go"
sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" live 9 16384
kill -TERM "$WPID" 2>/dev/null || true
if wait "$WPID"; then WPID=; else WPID=; fi
if wait "$SPID"; then SPID=; OBSERVER_PID=; else status=$?; SPID=; OBSERVER_PID=; echo "privacy profiler failed: $status"; exit "$status"; fi
publish_protected privacy-observed.json privacy-observed.json
test -s "$WORK/privacy-observed.json" || { echo "privacy profiler produced no output"; exit 1; }

echo "=== assert capture-policy matrix ==="
assert_lanes "$WORK"
echo "=== canary matrix: ALL OK ==="
