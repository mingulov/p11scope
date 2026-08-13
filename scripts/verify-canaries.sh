#!/bin/sh
# Gate G3: the secret-canary suite. This is the release gate that decides
# whether the Phase 3 privacy allowlist can be trusted.
#
# scripts/fixtures/canary_workload.c plants a distinct, high-entropy
# sentinel in every place a secret can live against a real SoftHSM2
# module: the C_Login PIN, CKA_VALUE/CKA_LABEL/CKA_ID on C_CreateObject
# (including a deliberately-malformed CKA_TOKEN boolean, ulValueLen > 1,
# to probe the `ulValueLen == 1` gate specifically), C_Digest plaintext,
# and CK_GCM_PARAMS.pIv/.pAAD — precisely the pointers the allowlist
# forbids dereferencing.
#
# This script then searches for every sentinel, as raw bytes and as hex,
# in every artifact the capture produces: the output profile JSON, the
# profiler's stdout/stderr log, and a BPF map dump for every map
# p11_entry/p11_return own (this is the artifact that matters most: it
# catches a sentinel that reached kernel memory even if userspace never
# printed it).
#
# A scanner that silently matches nothing would pass vacuously, so this
# script also writes one sentinel into a scratch file and asserts the
# scanner finds it there before trusting a clean result anywhere else.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/canaries
TRUST_DIR="$PWD/$WORK/trusted"

mkdir -p "$WORK"
. scripts/trusted-p11scope.sh

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
sudo -n true 2>/dev/null || { echo "passwordless sudo required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

WPID=
SPID=
OBSERVER_PID=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    [ -z "$OBSERVER_PID" ] || sudo kill -TERM "$OBSERVER_PID" 2>/dev/null || true
    [ -z "$WPID" ] || kill -TERM "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || kill -TERM "$SPID" 2>/dev/null || true
    [ -z "$WPID" ] || wait "$WPID" 2>/dev/null || true
    [ -z "$SPID" ] || wait "$SPID" 2>/dev/null || true
    remove_trusted_p11scope "$TRUST_DIR"
    exit "$status"
}
. scripts/cleanup-traps.sh

echo "=== build ==="
cargo build --release --workspace
stage_trusted_p11scope target/release/p11scope \
    target/release/p11scope-discover "$TRUST_DIR"
gcc -O0 -Wall -o "$WORK/canary_workload" scripts/fixtures/canary_workload.c -ldl
gcc -shared -fPIC -Wall -Wextra -DPRIVACY_FIXTURE=1 -DPRIVACY_BLOCKS=1 \
    -o "$WORK/privacy-provider.so" crates/discover/tests/fixture/version_matrix.c
gcc -O0 -Wall -Wextra -pthread -o "$WORK/privacy-stack-workload" \
    scripts/fixtures/privacy-stack-workload.c -ldl
python3 scripts/dump-owned-bpf-maps.py --self-test

echo "=== softhsm token ==="
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $PWD/$WORK/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
softhsm2-util --init-token --free --label canary --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe (canary workload under attach) ==="
rm -f "$WORK/go" "$WORK/observer.pid" "$WORK/observed.json" "$WORK/profile.log" \
    "$WORK"/mapdump_*.json "$WORK"/mapdump_manifest_*.json
( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/canary_workload" "$MODULE" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF sh -c \
    'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/observer.pid" \
    "$TRUST_DIR/p11scope" profile --manifest "$WORK/manifest.json" \
    --provenance-module "$MODULE" --pid "$WPID" \
    --mode profile --duration 8 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 3             # let attach complete before the workload runs
test -s "$WORK/observer.pid" || { echo "observer pid was not recorded"; exit 1; }
OBSERVER_PID=$(cat "$WORK/observer.pid")
sudo kill -0 "$OBSERVER_PID"
touch "$WORK/go"
if wait "$WPID"; then WPID=; else status=$?; WPID=; echo "canary workload failed: $status"; exit "$status"; fi
echo "workload done; profiler still attached — dumping BPF maps now"
sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" base 0 16384
if wait "$SPID"; then SPID=; OBSERVER_PID=; else status=$?; SPID=; OBSERVER_PID=; echo "profiler failed: $status"; exit "$status"; fi
test -s "$WORK/observed.json" || { echo "profiler produced no fresh observed.json"; exit 1; }
tail -n 20 "$WORK/profile.log"

echo "=== live START map: nine blocked 2.40/3.0/3.2 calls ==="
./target/release/p11scope-discover --module "$PWD/$WORK/privacy-provider.so" \
    -o "$WORK/privacy-manifest.json"
rm -f "$WORK/privacy-go" "$WORK/privacy-observer.pid" "$WORK/privacy-observed.json" \
    "$WORK/privacy-profile.log" "$WORK/privacy-workload.log"
( while [ ! -f "$WORK/privacy-go" ]; do sleep 0.05; done
  exec "$WORK/privacy-stack-workload" "$PWD/$WORK/privacy-provider.so" ) \
    > "$WORK/privacy-workload.log" 2>&1 &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF sh -c \
    'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/privacy-observer.pid" \
    "$TRUST_DIR/p11scope" profile --manifest "$WORK/privacy-manifest.json" \
    --provenance-module "$PWD/$WORK/privacy-provider.so" --pid "$WPID" \
    --mode profile --duration 8 -o "$WORK/privacy-observed.json" \
    > "$WORK/privacy-profile.log" 2>&1 &
SPID=$!
sleep 3
test -s "$WORK/privacy-observer.pid" || { echo "privacy observer pid was not recorded"; exit 1; }
OBSERVER_PID=$(cat "$WORK/privacy-observer.pid")
sudo kill -0 "$OBSERVER_PID"
touch "$WORK/privacy-go"
sudo python3 scripts/dump-owned-bpf-maps.py "$OBSERVER_PID" "$WORK" live 9 16384
kill -TERM "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true
WPID=
if wait "$SPID"; then SPID=; OBSERVER_PID=; else status=$?; SPID=; OBSERVER_PID=; echo "privacy profiler failed: $status"; exit "$status"; fi
test -s "$WORK/privacy-observed.json" || { echo "privacy profiler produced no fresh report"; exit 1; }
tail -n 10 "$WORK/privacy-profile.log"

echo "=== scan every artifact for every sentinel ==="
python3 - "$WORK" <<'PY'
import json, pathlib, re, sys

work = sys.argv[1]

# Must match scripts/fixtures/canary_workload.c exactly.
SENTINELS = {
    "PIN":       b"CANARY_PIN_e68d21cf481bb1efcc17dab7c0183bdd",
    "KEY":       b"CANARY_KEY_58fa8b6832cfa111313260aa3314ad0f",
    "LABEL":     b"CANARY_LABEL_5527f89ff269f233a661f5d3a11d082e",
    "ID":        b"CANARY_ID_d4875f5041bd7364aee7c2d625bb57f7",
    "PLAINTEXT": b"CANARY_PLAINTEXT_64193ef05a68b3de185c0f430c8190ba",
    "IV":        b"CANARY_IV_d81e4ec085489f1adfcf4729eadd745d",
    "AAD":       b"CANARY_AAD_5b1502ea971ec81f4b974fe84d62a22f",
    "BOOLLONG":  b"CANARY_BOOLLONG_7cd9f6ab17348ba2e65a43d173f9ea1d",
    "USERNAME":  b"CANARY_USERNAME_e2df5c11270a7b893619aa831b78fc18",
    "SIGNATURE": b"CANARY_SIGNATURE_a578d332cab775078a719c4c520bfd8c",
    "ASYNC":     b"CANARY_ASYNC_ef239b70be4c0e1d5cb234a225fe1ff7",
    "OUTPUT":    b"CANARY_OUTPUT_5391960450406458bc83e37c2b43b80b",
    "ARG7":      b"CANARY_ARG7_b2747079a35f10aba729f83ff3285ddc",
    "ARG8":      b"CANARY_ARG8_1752403b4bb53924b6881d095e3e9198",
    "ARG9":      b"CANARY_ARG9_8f119353c9e69ce4f2f3b9a4d2aa2fab",
}
assert all(len(v) >= 16 for v in SENTINELS.values()), "every sentinel must be >= 16 bytes"

HEX_TOKEN = re.compile(rb"0x([0-9a-fA-F]{2})")


def hits(content: bytes, hex_reconstruction: bytes | None = None) -> set[str]:
    """Sentinel names found in `content` — as raw bytes, as ASCII hex text
    (upper or lower), or (for bpftool's {"key":["0x..",...]} map dumps)
    reassembled from the JSON's individual hex byte tokens back into the
    raw bytes bpftool encoded."""
    found = set()
    lower = content.lower()
    for name, sentinel in SENTINELS.items():
        if sentinel in content:
            found.add(name)
            continue
        hexed = sentinel.hex().encode()
        if hexed in lower:
            found.add(name)
            continue
        if hex_reconstruction is not None and sentinel in hex_reconstruction:
            found.add(name)
    return found


def reconstruct_from_hex_tokens(content: bytes) -> bytes:
    """bpftool `map dump -j` encodes every byte as an individual "0xHH"
    JSON string. Reassemble those tokens, in file order, back into the raw
    bytes they represent — this is what actually proves a sentinel never
    reached a map's key/value bytes, independent of the JSON's exact
    array/object punctuation."""
    return bytes(int(b, 16) for b in HEX_TOKEN.findall(content))


# --- Mandatory positive control: prove the scanner can detect a leak. ---
control_path = f"{work}/positive_control.json"
with open(control_path, "wb") as f:
    tokens = b",".join(f'"0x{byte:02x}"'.encode() for byte in SENTINELS["PIN"])
    f.write(b'{"value":[' + tokens + b']}\n')
control_content = open(control_path, "rb").read()
assert hits(control_content) == set(), "positive control accidentally contains raw/contiguous hex"
control_hits = hits(control_content, reconstruct_from_hex_tokens(control_content))
assert control_hits == {"PIN"}, (
    f"positive control FAILED: expected to find exactly {{'PIN'}} in "
    f"{control_path}, found {control_hits!r} — the scanner cannot be "
    f"trusted to detect a real leak"
)
print(f"positive control OK: scanner found {control_hits} in {control_path}")

# --- Real artifacts: the output JSON and the profiler's log. ---
text_artifacts = [
    ("observed.json", f"{work}/observed.json"),
    ("profile.log", f"{work}/profile.log"),
    ("privacy-observed.json", f"{work}/privacy-observed.json"),
    ("privacy-profile.log", f"{work}/privacy-profile.log"),
    ("privacy-workload.log", f"{work}/privacy-workload.log"),
]

# --- Real artifacts: every BPF map the program owns. ---
mapdump_artifacts = []
for manifest_path in sorted(pathlib.Path(work).glob("mapdump_manifest_*.json")):
    for item in json.load(open(manifest_path)):
        mapdump_artifacts.append((f"mapdump:{item['name']}:{item['id']}", item["file"]))
assert mapdump_artifacts, "no observer-owned BPF maps were dumped — nothing to scan"
live_start = json.load(open(f"{work}/mapdump_START_live.json"))
assert len(live_start) >= 9, f"live START positive control is empty/short: {len(live_start)}"

leaks = {}
for label, path in text_artifacts + mapdump_artifacts:
    content = open(path, "rb").read()
    recon = reconstruct_from_hex_tokens(content) if label.startswith("mapdump:") else None
    found = hits(content, recon)
    if found:
        leaks[label] = found

print(f"scanned {len(text_artifacts)} text artifacts and "
      f"{len(mapdump_artifacts)} observer-owned BPF map dumps "
      f"for {len(SENTINELS)} sentinels")

if leaks:
    print("=== canaries: LEAK DETECTED ===", file=sys.stderr)
    for label, found in leaks.items():
        print(f"  {label}: {sorted(found)}", file=sys.stderr)
    sys.exit(1)

print("=== canaries: NONE LEAKED ===")
PY

echo "=== verify GCM/PSS parameter decode correctness ==="
# Beyond "no sentinel leaked" above: this checks the *decoded scalar
# fields themselves* are correct, not just absent of secrets. This is the
# regression test for a defect the sentinel scan above cannot see: a
# stale ulParameterLen >= 40 guard let a modern 48-byte CK_GCM_PARAMS
# through and misread its pAAD *pointer* into the field labeled aad_len —
# a small, plausible-looking-but-wrong integer, not a sentinel byte
# string, so nothing above would have caught it. Verified instead by
# checking the emitted value against the length actually planted, and
# generically by rejecting any numeric field that looks like a pointer.
python3 - "$WORK/observed.json" <<'PY'
import json, sys

path = sys.argv[1]
doc = json.load(open(path))
mechs = {m["mechanism_hex"]: m for m in doc["mechanisms"]}

# Must match scripts/fixtures/canary_workload.c exactly.
AAD_LEN = len("CANARY_AAD_5b1502ea971ec81f4b974fe84d62a22f")
IV_LEN = len("CANARY_IV_d81e4ec085489f1adfcf4729eadd745d")


def combos_for(mech_hex):
    m = mechs.get(mech_hex)
    assert m is not None, f"mechanism {mech_hex} not observed in {path}"
    params = m["params"]
    assert params is not None, f"mechanism {mech_hex} has null params: note={m['note']!r}"
    return params


# No emitted numeric field, on any mechanism, may look like a pointer.
# General sweep, not just the GCM combo the defect happened to hit: a
# pointer disclosure could show up in any shape-specific field.
PTR_LOOKS_LIKE = 2**32
for m in doc["mechanisms"]:
    for combo in m["params"] or []:
        for k, v in combo.items():
            if k in ("shape", "layout", "count") or k.endswith("_hex"):
                continue
            assert isinstance(v, int) and v < PTR_LOOKS_LIKE, (
                f"mechanism {m['mechanism_hex']} combo {combo!r} field "
                f"{k!r}={v!r} looks like a pointer, not a length/count"
            )
print("no emitted parameter field looks like a pointer (all < 2^32)")

# CKM_AES_GCM (0x1087): must show exactly the two real combos — legacy
# v2.20 and modern v2.40 — never a third, fabricated one from the
# malformed ulParameterLen=24 call (which matches neither known layout).
gcm_combos = combos_for("0x1087")
by_layout = {c["layout"]: c for c in gcm_combos if c.get("shape") == "gcm"}
assert set(by_layout) == {"v2.20", "v2.40"}, (
    f"expected exactly the v2.20 and v2.40 GCM combos, got {sorted(by_layout)} "
    "— an extra combo would mean the malformed-length call decoded "
    "something instead of being rejected"
)

v220, v240 = by_layout["v2.20"], by_layout["v2.40"]
assert v220["aad_len"] == AAD_LEN, f"v2.20 aad_len should be {AAD_LEN}, got {v220['aad_len']}"
assert v220["iv_len"] == IV_LEN and v220["tag_bits"] == 128, v220
# This is the exact defect this fix closes: against the pre-fix code, a
# 48-byte struct read offset 24 (pAAD, a pointer) into this field instead
# of offset 32 (ulAADLen) — aad_len would be a huge, pointer-looking
# value instead of the planted AAD length.
assert v240["aad_len"] == AAD_LEN, (
    f"v2.40 aad_len should be the planted AAD length ({AAD_LEN}), not a "
    f"pointer-looking value — got {v240['aad_len']}"
)
assert v240["iv_len"] == IV_LEN and v240["tag_bits"] == 128, v240
print(f"GCM v2.20 combo verified: {v220}")
print(f"GCM v2.40 combo verified: {v240} (aad_len is the planted length, not the pAAD pointer)")

# The malformed call must be visible evidence, not silently absorbed into
# a clean-looking record: it must count as a shape decode failure. (It
# does not flip evidence.completeness to PARTIAL here — that requires
# EVERY observed call for a mechanism id to fail to decode
# (shape_decode_total_failures, see semantics::State::total_shape_decode_failures
# and its dedicated Rust unit tests), and this mechanism id also decoded
# successfully twice above in the same capture, which is correctly the
# weaker "inconsistent decode" signal, not a total regression.)
shape_decode_failures = doc["evidence"]["shape_decode_failures"]
assert shape_decode_failures >= 1, (
    "the malformed-length GCM call should count as a shape decode failure "
    f"(evidence.shape_decode_failures), got evidence={doc['evidence']}"
)
print(f"evidence.shape_decode_failures = {shape_decode_failures} "
      "(malformed-length call counted as a failure, not silently dropped)")

# CKM_RSA_PKCS_PSS (0xd): the PSS offset path, exercised here for the
# first time by this suite.
pss_combos = combos_for("0xd")
assert len(pss_combos) == 1, f"expected exactly one PSS combo, got {pss_combos}"
pss = pss_combos[0]
assert pss["shape"] == "rsa_pkcs_pss"
assert pss["hash_alg"] == 0x250, pss    # CKM_SHA256
assert pss["mgf"] == 2, pss             # CKG_MGF1_SHA256
assert pss["salt_len"] == 32, pss
print(f"PSS combo verified: {pss}")

print("=== GCM/PSS parameter decode: OK ===")
PY
