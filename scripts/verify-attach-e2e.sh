#!/bin/sh
# Gate G1: p11scope attaches at discovered offsets and counts a
# deterministic workload exactly. Oracle: spike/expected.txt, the ground
# truth for spike/harness.c.
set -eu
cd "$(dirname "$0")/.."

MODULE=/usr/lib/softhsm/libsofthsm2.so
WORK=target/e2e
mkdir -p "$WORK"

command -v gcc >/dev/null || { echo "gcc required"; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util required"; exit 1; }
test -f "$MODULE" || { echo "SoftHSM2 not installed at $MODULE"; exit 1; }

echo "=== build ==="
# NOTE (deviation from the literal brief): the root Cargo.toml is a
# combined package+workspace manifest. A plain `cargo build --release`
# run from the root only builds the root package (p11scope) since Cargo
# 1.71 — it does NOT build the other workspace members. p11scope-discover
# silently goes missing and the "discover" step below fails with ENOENT.
# --workspace makes both binaries build, matching what this script needs.
cargo build --release --workspace
gcc -O0 -o "$WORK/harness" spike/harness.c -ldl

echo "=== softhsm token ==="
# harness.c calls C_GetSlotList(tokenPresent=1, ...) and requires at least
# one initialized token. The system-wide /etc/softhsm/softhsm2.conf and
# /var/lib/softhsm/tokens are root:softhsm-only on this host, so point
# SOFTHSM2_CONF at a private, disposable token store instead of requiring
# host-level SoftHSM setup.
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
softhsm2-util --init-token --free --label e2e --so-pin 1234 --pin 1234 >/dev/null

echo "=== discover ==="
./target/release/p11scope-discover --module "$MODULE" -o "$WORK/manifest.json"

echo "=== observe ==="
# The workload waits for a go-file so probes are attached before it runs
# a single call — attach-before-run is the whole point. The `exec` inside
# the subshell replaces the subshell's process image with the harness, so
# $! (captured before exec runs) stays valid as the harness's real pid.
rm -f "$WORK/go"
( while [ ! -f "$WORK/go" ]; do sleep 0.05; done; exec "$WORK/harness" "$MODULE" ) &
WPID=$!
sudo --preserve-env=SOFTHSM2_CONF ./target/release/p11scope profile \
    --manifest "$WORK/manifest.json" --pid "$WPID" \
    --mode metrics --duration 20 -o "$WORK/observed.json" \
    > "$WORK/profile.log" 2>&1 &
SPID=$!
sleep 3            # let attach complete
touch "$WORK/go"
wait "$WPID"
wait "$SPID"
tail -n 20 "$WORK/profile.log"

echo "=== verify against spike/expected.txt ==="
python3 - "$WORK/observed.json" spike/expected.txt <<'PY'
import json, sys
obs = json.load(open(sys.argv[1]))
counts = {}
for f in obs["functions"]:
    for n in f["names"]:
        counts[n] = counts.get(n, 0) + f["calls"]
fail = 0
for line in open(sys.argv[2]):
    name, want = line.split()
    got = counts.get(name, 0)
    if got != int(want):
        print(f"MISMATCH {name}: want {want}, got {got}")
        fail = 1
    else:
        print(f"ok {name}: {got}")
ev = obs["evidence"]
print("evidence:", ev["attached_probes"], "probes,", ev["completeness"])
if ev["attached_probes"] == 0:
    print("no probes attached")
    fail = 1
if ev["completeness"] != "COMPLETE":
    print(f"completeness: want COMPLETE, got {ev['completeness']!r}")
    fail = 1
sys.exit(fail)
PY

echo "=== static musl build ==="
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl --bin p11scope
# NOTE (deviation from the literal brief): on this toolchain (rustc
# 1.94 / file 5.45), `file` reports a static+PIE musl binary as
# "static-pie linked", not "statically linked" — grep-ing only the
# latter string false-negatives a genuinely static binary. Accept
# either; `ldd` on the same binary independently confirms
# "statically linked" (no dynamic interpreter).
file target/x86_64-unknown-linux-musl/release/p11scope \
    | grep -qE "statically linked|static-pie linked" \
    || { echo "p11scope is NOT static"; exit 1; }
echo "p11scope: statically linked OK"

echo "=== e2e: ALL OK ==="
