#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# verify-spy-forwarding.sh: privileged cell for an interposing PKCS#11
# module (OpenSC pkcs11-spy) in front of SoftHSM2.
#
# The application loads pkcs11-spy.so, which loads the real provider and
# forwards every call. Oracle: exit 0 everywhere; the direct run against
# SoftHSM sets the baseline; the spy run with --prearm-module (full
# attach) plus --forwarding-module counts each application call ONCE
# (logical == baseline, forwarding layer named with its own counts);
# the same run WITHOUT the declaration keeps honest per-layer counts
# (no silent split, no drop) instead of silently doubling; a spy whose
# backend fails to load names the failed call and never crashes the
# observer. Provider paths are probed (Debian and Fedora layouts).
# (`-L` never earns the `Possible forwarding` hint: its bootstrap pair
# is genuinely per-layer — C_GetInterface at the spy, C_GetFunctionList
# at the backend — so the vectors contain each other in neither
# direction. The hint itself is pinned by unit tests and fires live for
# coincident holder workloads.)
#
# Needs root for the observer (sudo -n), plus pkcs11-tool, softhsm2 and
# the opensc pkcs11-spy module (the workflow job installs `opensc` for
# the spy module and pkcs11-tool).
set -eu
cd "$(dirname "$0")/.."

MODE=""
BINARY=""
WORK=""
KEEP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --self-test) MODE=self; shift ;;
        --binary) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2; }
            BINARY=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2; }
            WORK=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2 ;;
    esac
done

# The oracle, shared by --self-test (canned documents) and the live run.
ORACLE='
import json, sys
doc = json.load(open(sys.argv[1]))
want = sys.argv[2]
lt = doc.get("layer_totals", {})
logical = lt.get("logical", {}).get("calls", -1)
forwarding = lt.get("forwarding", {}).get("calls", -1)
rows = doc.get("functions", [])
if want == "split":
    base = int(sys.argv[3])
    assert logical == base, f"logical {logical} != baseline {base}"
    assert forwarding == base, f"forwarding {forwarding} != baseline {base}"
    assert any(r.get("forwarding_layer") for r in rows), "no forwarding_layer row"
    fwd = sum(r.get("calls", 0) for r in rows if r.get("forwarding_layer"))
    assert fwd == forwarding, f"forwarding rows sum {fwd} != total {forwarding}"
elif want == "baseline":
    assert logical > 0 and forwarding == 0, f"direct run must be all logical: {lt}"
else:
    raise AssertionError("unknown oracle want: " + want)
print(f"oracle {want} ok: logical={logical} forwarding={forwarding}")
'

if [ "$MODE" = self ]; then
    [ -z "$BINARY$WORK" ] && [ "$KEEP" -eq 0 ] || {
        echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2
    }
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    cat >"$tmp/split.json" <<'JSON'
{"schema": "p11scope/observed-profile/v3",
 "layer_totals": {"logical": {"calls": 9}, "forwarding": {"calls": 9}},
 "functions": [{"names": ["C_Sign"], "calls": 8, "forwarding_layer": true},
               {"names": ["C_Verify"], "calls": 1, "forwarding_layer": true},
               {"names": ["C_GetInfo"], "calls": 0, "forwarding_layer": true},
               {"names": ["C_Sign"], "calls": 9, "forwarding_layer": false}]}
JSON
    cat >"$tmp/plain.json" <<'JSON'
{"schema": "p11scope/observed-profile/v3",
 "layer_totals": {"logical": {"calls": 9}, "forwarding": {"calls": 0}},
 "functions": [{"names": ["C_Sign"], "calls": 9, "forwarding_layer": false}]}
JSON
    python3 -I -c "$ORACLE" "$tmp/split.json" split 9
    python3 -I -c "$ORACLE" "$tmp/plain.json" baseline
    if python3 -I -c "$ORACLE" "$tmp/plain.json" split 9 2>/dev/null; then
        echo "self-test: oracle accepted an unsplit document" >&2; exit 1
    fi
    echo "self-test ok"
    exit 0
fi

[ -n "$BINARY" ] && [ -n "$WORK" ] || {
    echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2
}
[ -x "$BINARY" ] || { echo "observer is not executable: $BINARY" >&2; exit 2; }
umask 077
rm -rf "$WORK"
mkdir -p "$WORK/tokens" "$WORK/logs"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

probe() { for p in "$@"; do [ -e "$p" ] && { echo "$p"; return 0; }; done; return 1; }
SOFTHSM=$(probe /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so) || {
    echo "no SoftHSM2 library found" >&2; exit 1; }
SPY=$(probe /usr/lib/x86_64-linux-gnu/pkcs11-spy.so /usr/lib64/pkcs11-spy.so) || {
    echo "no pkcs11-spy module found" >&2; exit 1; }
command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool missing" >&2; exit 1; }
command -v softhsm2-util >/dev/null || { echo "softhsm2-util missing" >&2; exit 1; }

export SOFTHSM2_CONF="$WORK/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" >"$WORK/softhsm2.conf"
softhsm2-util --init-token --slot 0 --label "spy-cell" --pin 1234 --so-pin 12345678 >/dev/null

cell() { # name OBS_ARGS... -- ENV... -- TOOL_ARGS...
    name=$1; shift
    obs=""; while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do obs="$obs $1"; shift; done; shift
    penv=""; while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do penv="$penv $1"; shift; done; shift
    rm -f "$WORK/$name.json" "$WORK/$name.stdout" "$WORK/$name.stderr"
    status=0
    # shellcheck disable=SC2086 # $penv is VAR=value words by construction
    # shellcheck disable=SC2024 # redirects stay owned by the invoking user; only the observer runs privileged
    sudo -n env TMPDIR="$WORK" SOFTHSM2_CONF="$WORK/softhsm2.conf" $penv \
        "$BINARY" run --pause auto $obs -o "$WORK/$name.json" -- \
        pkcs11-tool --module "$MOD" "$@" >"$WORK/$name.stdout" 2>"$WORK/$name.stderr" || status=$?
    echo "cell $name exit=$status: $(grep -m1 'completed calls' "$WORK/$name.stdout" || tail -n 1 "$WORK/$name.stdout")"
    return "$status"
}

MOD=$SOFTHSM
cell direct -- -- -L
python3 -I -c "$ORACLE" "$WORK/direct.json" baseline
BASELINE=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["layer_totals"]["logical"]["calls"])' "$WORK/direct.json")

MOD=$SPY
cell spy_declared --prearm-module "$SPY" --forwarding-module "$SPY" -- PKCS11SPY="$SOFTHSM" PKCS11SPY_OUTPUT="$WORK/logs/spy.log" -- -L
python3 -I -c "$ORACLE" "$WORK/spy_declared.json" split "$BASELINE"

cell spy_undeclared --prearm-module "$SPY" -- PKCS11SPY="$SOFTHSM" PKCS11SPY_OUTPUT="$WORK/logs/spy2.log" -- -L
python3 -I - "$WORK/spy_undeclared.json" "$BASELINE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
base = int(sys.argv[2])
lt = doc["layer_totals"]
assert lt["logical"]["calls"] == 2 * base, lt
assert lt["forwarding"]["calls"] == 0, lt
print(f"undeclared per-layer ok: logical={2 * base} forwarding=0")
PY

cell spy_bad_backend -- -- PKCS11SPY=/nonexistent/libfoo.so PKCS11SPY_OUTPUT="$WORK/logs/spy-bad.log" -- -L || true
python3 -I - "$WORK/spy_bad_backend.json" <<'PY'
import json, sys
# A dead backend fails fast, so attach may or may not catch the single
# failed call; both outcomes are honest. Parsed JSON already proves no
# crash: either error rows name the failure, or zero captured calls come
# with PARTIAL coverage, never a silent clean report.
doc = json.load(open(sys.argv[1]))
rows = doc.get("functions", [])
calls = sum(r.get("calls", 0) for r in rows)
errors = sum(r.get("errors", 0) for r in rows)
complete = doc.get("evidence", {}).get("completeness")
if calls == 0:
    assert complete == "PARTIAL", f"a call-less run must report PARTIAL, got {complete}"
    print("bad-backend ok: no calls captured, PARTIAL coverage named")
else:
    assert errors >= 1, "captured calls must include the backend failure as errors"
    print(f"bad-backend ok: {calls} call(s), {errors} error(s) name the failure")
PY
echo "spy forwarding cell ok: baseline=$BASELINE"
