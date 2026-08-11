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

mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
cargo build --release --workspace
gcc -O0 -Wall -o "$WORK/canary_workload" scripts/fixtures/canary_workload.c -ldl

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
rm -f "$WORK/go"
# Snapshot loaded programs *before* this run's attach. This sandbox's
# kernel has been observed to retain stray p11_entry/p11_return copies
# from earlier, unrelated captures (their prog fds end up held open by
# PID 1 well after the owning p11scope process exits — an environment
# quirk, not something this script causes or can fix). Matching on name
# alone would risk dumping — and attributing a "leak" to — a foreign,
# unrelated program's maps. Diffing against this snapshot isolates the
# programs *this* run's attach actually created.
sudo bpftool prog show --json > "$WORK/progs_before.json"

( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/canary_workload" "$MODULE" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF ./target/release/p11scope profile \
    --manifest "$WORK/manifest.json" --pid "$WPID" \
    --mode profile --duration 25 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 3             # let attach complete before the workload runs
sudo bpftool prog show --json > "$WORK/progs_after.json"
touch "$WORK/go"
wait "$WPID"
echo "workload done; profiler still attached — dumping BPF maps now"

echo "=== bpf map dump (every map p11_entry/p11_return own) ==="
rm -f "$WORK"/mapdump_*.json
python3 - "$WORK/progs_before.json" "$WORK/progs_after.json" "$WORK" <<'PY'
import json, subprocess, sys

before_path, after_path, work = sys.argv[1], sys.argv[2], sys.argv[3]
before_ids = {p["id"] for p in json.load(open(before_path))}
after = json.load(open(after_path))

our_progs = [p for p in after
             if p.get("name") in ("p11_entry", "p11_return") and p["id"] not in before_ids]
if not our_progs:
    print("no newly-attached p11_entry/p11_return program found — attach failed, or this "
          "run's programs are indistinguishable from a pre-existing stray one",
          file=sys.stderr)
    sys.exit(1)

map_ids = set()
for p in our_progs:
    map_ids.update(p.get("map_ids") or [])
print(f"this run's programs: {[(p['id'], p['name']) for p in our_progs]}")

dumped = []
for mid in sorted(map_ids):
    show = subprocess.run(["sudo", "bpftool", "map", "show", "id", str(mid)],
                           capture_output=True, text=True, check=True).stdout
    # "<id>: <type>  name <NAME>  flags ..."
    name = show.split("name", 1)[1].split()[0]
    # check=False: bpftool exits non-zero on BPF_MAP_TYPE_RINGBUF (EVENTS)
    # even though it prints valid ("[]") JSON — ring buffers aren't a
    # lookup map the kernel can iterate for dump, a structural quirk, not
    # a failure to capture. Every map still gets dumped; still fail loudly
    # if a map produces no parseable output at all.
    proc = subprocess.run(["sudo", "bpftool", "map", "dump", "id", str(mid), "-j"],
                           capture_output=True, text=True, check=False)
    dump = proc.stdout
    try:
        json.loads(dump)
    except json.JSONDecodeError:
        print(f"bpftool map dump id {mid} ({name}) produced unparseable output: "
              f"rc={proc.returncode} stderr={proc.stderr!r}", file=sys.stderr)
        sys.exit(1)
    open(f"{work}/mapdump_{name}.json", "w").write(dump)
    dumped.append(name)

open(f"{work}/mapdump_manifest.txt", "w").write("\n".join(sorted(dumped)) + "\n")
print(f"dumped {len(dumped)} maps: {', '.join(sorted(dumped))}")
PY

wait "$SPID"
tail -n 20 "$WORK/profile.log"

echo "=== scan every artifact for every sentinel ==="
python3 - "$WORK" <<'PY'
import re, sys

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
control_path = f"{work}/positive_control.txt"
with open(control_path, "wb") as f:
    f.write(b"scanner self-test scratch file: " + SENTINELS["PIN"] + b"\n")
control_hits = hits(open(control_path, "rb").read())
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
]

# --- Real artifacts: every BPF map the program owns. ---
map_names = open(f"{work}/mapdump_manifest.txt").read().split()
assert map_names, "no BPF maps were dumped — nothing to scan"
mapdump_artifacts = [(f"mapdump:{n}", f"{work}/mapdump_{n}.json") for n in map_names]

leaks = {}
for label, path in text_artifacts + mapdump_artifacts:
    content = open(path, "rb").read()
    recon = reconstruct_from_hex_tokens(content) if label.startswith("mapdump:") else None
    found = hits(content, recon)
    if found:
        leaks[label] = found

print(f"scanned {len(text_artifacts)} text artifacts and "
      f"{len(mapdump_artifacts)} BPF map dumps ({', '.join(map_names)}) "
      f"for {len(SENTINELS)} sentinels")

if leaks:
    print("=== canaries: LEAK DETECTED ===", file=sys.stderr)
    for label, found in leaks.items():
        print(f"  {label}: {sorted(found)}", file=sys.stderr)
    sys.exit(1)

print("=== canaries: NONE LEAKED ===")
PY
