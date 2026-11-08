#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# r/PKI demo: which program called my token? Make a SoftHSM token, run three
# callers (pkcs11-tool sign, a python3 sign script, openssl via
# pkcs11-provider), then show `inventory --system` naming each program and
# `profile --pid` counts for the python caller.
#
#   scripts/demo.sh [--observer BIN] [--duration SECS] [--keep] [--help]
#
# Flow: probe the SoftHSM and pkcs11-provider paths (Debian and Fedora
# layouts, never one hard-coded path), init a throwaway token with one RSA
# key, start the three callers, run a system inventory capture, print its
# concise text, run a profile capture on the python caller, print that, and
# check the inventory text names openssl, pkcs11-tool and python3. Removes
# its token and callers afterwards unless --keep. Exit 2 before any capture
# when a tool or module is missing, exit 1 when a capture or a name check
# fails.
set -eu

OBSERVER=p11scope
DURATION=30
PROFILE_SECS=15
KEEP=0

usage() {
    echo "usage: $0 [--observer BIN] [--duration SECS] [--keep] [--help]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --observer) [ "$#" -ge 2 ] || usage; OBSERVER=$2; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || usage; DURATION=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --help) usage ;;
        *) usage ;;
    esac
done
case $DURATION in
    ''|*[!0-9]*|0*) echo "demo: --duration wants seconds, got '$DURATION'" >&2; exit 2 ;;
esac
[ "$DURATION" -le 600 ] || { echo "demo: --duration above 600s refused" >&2; exit 2; }

# Missing-tool checks first: one line each, before anything is built or run.
command -v softhsm2-util >/dev/null 2>&1 \
    || { echo "demo: softhsm2-util not found; install SoftHSM (softhsm2 / softhsm), then rerun this script" >&2; exit 2; }
command -v pkcs11-tool >/dev/null 2>&1 \
    || { echo "demo: pkcs11-tool not found; install OpenSC (opensc), then rerun this script" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 \
    || { echo "demo: python3 not found; install Python 3, then rerun this script" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 \
    || { echo "demo: openssl not found; install OpenSSL, then rerun this script" >&2; exit 2; }
probe() { for p in "$@"; do [ -e "$p" ] && { echo "$p"; return 0; }; done; return 1; }
SOFTHSM=$(probe /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so) \
    || { echo "demo: no SoftHSM library found; install SoftHSM (softhsm2 / softhsm), then rerun this script" >&2; exit 2; }
PKCS11SO=$(probe /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so /usr/lib64/ossl-modules/pkcs11.so) \
    || { echo "demo: no pkcs11-provider module found; install it (pkcs11-provider), then rerun this script" >&2; exit 2; }
case $OBSERVER in
    */*) [ -x "$OBSERVER" ] \
        || { echo "demo: p11scope not found; pass --observer PATH to the p11scope binary, then rerun this script" >&2; exit 2; } ;;
    *) command -v "$OBSERVER" >/dev/null 2>&1 \
        || { echo "demo: p11scope not found; pass --observer PATH to the p11scope binary, then rerun this script" >&2; exit 2; }
        # Resolve a bare name now: sudo does not share our PATH, so the
        # later sudo invocation must use the absolute path we verified.
        OBSERVER=$(command -v "$OBSERVER") ;;
esac
sudo -n true >/dev/null 2>&1 \
    || { echo "demo: this demo needs passwordless sudo for the captures" >&2; exit 2; }
sudo -n "$OBSERVER" --version >/dev/null 2>&1 \
    || { echo "demo: cannot run $OBSERVER via passwordless sudo; pass --observer PATH to a sudo-runnable p11scope binary" >&2; exit 2; }

OUT=
PYPID=
TOOLLOOP=
SSLLOOP=
# Plain ifs: an && chain that ends false would trip set -e inside the trap
# and flip a PASS to exit 1.
cleanup() {
    if [ -n "$TOOLLOOP" ]; then kill -TERM "$TOOLLOOP" 2>/dev/null || true; fi
    if [ -n "$SSLLOOP" ]; then kill -TERM "$SSLLOOP" 2>/dev/null || true; fi
    if [ -n "$PYPID" ]; then kill -TERM "$PYPID" 2>/dev/null || true; fi
    sleep 1
    if [ -n "$TOOLLOOP" ]; then kill -KILL "$TOOLLOOP" 2>/dev/null || true; fi
    if [ -n "$SSLLOOP" ]; then kill -KILL "$SSLLOOP" 2>/dev/null || true; fi
    if [ -n "$PYPID" ]; then kill -KILL "$PYPID" 2>/dev/null || true; fi
    if [ -n "$TOOLLOOP" ]; then wait "$TOOLLOOP" 2>/dev/null || true; fi
    if [ -n "$SSLLOOP" ]; then wait "$SSLLOOP" 2>/dev/null || true; fi
    if [ -n "$PYPID" ]; then wait "$PYPID" 2>/dev/null || true; fi
    if [ "$KEEP" -eq 0 ]; then
        if [ -n "$OUT" ]; then rm -rf "$OUT" || true; fi
    fi
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

OUT=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-demo-XXXXXX")
[ "$KEEP" -eq 1 ] && echo "demo: output kept in $OUT" >&2
mkdir -p "$OUT/tokens"
export SOFTHSM2_CONF="$OUT/softhsm2.conf"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$OUT" \
    > "$SOFTHSM2_CONF"

echo "demo: making a SoftHSM token ..." >&2
softhsm2-util --init-token --free --label demo --so-pin 5678 --pin 1234 >/dev/null \
    || { echo "demo: token init failed" >&2; exit 1; }
pkcs11-tool --module "$SOFTHSM" --login --pin 1234 --keypairgen --key-type rsa:2048 \
    --id 01 --label demo-sign >/dev/null \
    || { echo "demo: keypairgen failed" >&2; exit 1; }
printf 'hello-demo' > "$OUT/data"

# openssl.cnf expands the two probed paths, so this heredoc is unquoted.
cat > "$OUT/openssl.cnf" <<EOF
HOME = .
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $PKCS11SO
pkcs11-module-path = $SOFTHSM
pkcs11-module-token-pin = 1234
activate = 1
EOF

cat > "$OUT/signloop.py" <<'PYEOF'
"""SoftHSM RSA sign loop for the p11scope demo (ctypes, stdlib only)."""
import ctypes
import os
import sys
import time

CKU_USER = 1
CKF_SERIAL_SESSION = 4
CKF_RW_SESSION = 2
CKO_PRIVATE_KEY = 3
CKA_CLASS = 0x0
CKA_ID = 0x102
CKM_RSA_PKCS = 0x1


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", ctypes.c_ulong),
    ]


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", ctypes.c_ulong),
        ("pParameter", ctypes.c_void_p),
        ("ulParameterLen", ctypes.c_ulong),
    ]


def main():
    module, secs = sys.argv[1], int(sys.argv[2])
    lib = ctypes.CDLL(module)
    for name, args in [
        ("C_Initialize", [ctypes.c_void_p]),
        ("C_Finalize", [ctypes.c_void_p]),
        ("C_GetSlotList", [ctypes.c_ubyte, ctypes.c_void_p, ctypes.c_void_p]),
        ("C_OpenSession", [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]),
        ("C_CloseSession", [ctypes.c_ulong]),
        ("C_Login", [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong]),
        ("C_Logout", [ctypes.c_ulong]),
        ("C_FindObjectsInit", [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]),
        ("C_FindObjects", [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]),
        ("C_FindObjectsFinal", [ctypes.c_ulong]),
        ("C_SignInit", [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]),
        ("C_Sign", [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_void_p]),
    ]:
        fn = getattr(lib, name)
        fn.argtypes = args
        fn.restype = ctypes.c_ulong
    if lib.C_Initialize(None):
        print("signloop: C_Initialize failed", file=sys.stderr)
        return 1
    nslots = ctypes.c_ulong(16)
    slots = (ctypes.c_ulong * 16)()
    if lib.C_GetSlotList(1, slots, ctypes.byref(nslots)) or not nslots.value:
        print("signloop: no token slot", file=sys.stderr)
        return 1
    session = ctypes.c_ulong(0)
    if lib.C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session)):
        print("signloop: C_OpenSession failed", file=sys.stderr)
        return 1
    if lib.C_Login(session.value, CKU_USER, b"1234", 4):
        print("signloop: C_Login failed", file=sys.stderr)
        return 1
    klass = ctypes.c_ulong(CKO_PRIVATE_KEY)
    keyid = ctypes.c_ubyte(0x01)
    findt = (CK_ATTRIBUTE * 2)(
        CK_ATTRIBUTE(CKA_CLASS, ctypes.addressof(klass), ctypes.sizeof(klass)),
        CK_ATTRIBUTE(CKA_ID, ctypes.addressof(keyid), ctypes.sizeof(keyid)),
    )
    privkey = ctypes.c_ulong(0)
    nfound = ctypes.c_ulong(0)
    if (
        lib.C_FindObjectsInit(session.value, findt, 2)
        or lib.C_FindObjects(session.value, ctypes.byref(privkey), 1, ctypes.byref(nfound))
        or lib.C_FindObjectsFinal(session.value)
        or not nfound.value
    ):
        print("signloop: RSA key id 01 not found", file=sys.stderr)
        return 1
    print(f"READY pid={os.getpid()}", flush=True)
    prefix = bytes([0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20])
    data = prefix + bytes([0xA5]) * 32
    mech = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
    sig = ctypes.create_string_buffer(512)
    siglen = ctypes.c_ulong(0)
    signs = errors = 0
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        siglen.value = 512
        rv = lib.C_SignInit(session.value, ctypes.byref(mech), privkey.value)
        if not rv:
            rv = lib.C_Sign(session.value, data, len(data), sig, ctypes.byref(siglen))
        if rv:
            errors += 1
        else:
            signs += 1
        time.sleep(0.1)
    print(f"SIGNLOOP {{\"pid\":{os.getpid()},\"signs\":{signs},\"errors\":{errors}}}", flush=True)
    lib.C_Logout(session.value)
    lib.C_CloseSession(session.value)
    lib.C_Finalize(None)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF

echo "demo: starting the three callers ..." >&2
LOOP_SECS=$((DURATION + PROFILE_SECS + 60))
python3 -I "$OUT/signloop.py" "$SOFTHSM" "$LOOP_SECS" >"$OUT/py.log" 2>&1 &
PYPID=$!
# set +e in each loop: one failed sign must not stop the demo load; the
# per-iteration output stays in the loop log for diagnosis.
( set +e
  while :; do
    pkcs11-tool --module "$SOFTHSM" --login --pin 1234 --sign \
        --mechanism SHA256-RSA-PKCS --id 01 \
        --input-file "$OUT/data" --output-file "$OUT/sig-tool" >>"$OUT/tool.log" 2>&1
done ) &
TOOLLOOP=$!
( set +e
  while :; do
    OPENSSL_CONF="$OUT/openssl.cnf" openssl pkeyutl -sign \
        -inkey 'pkcs11:token=demo;object=demo-sign;type=private' \
        -in "$OUT/data" -out "$OUT/sig-ssl" >>"$OUT/ssl.log" 2>&1
done ) &
SSLLOOP=$!

# The python signer must be past setup (token + key + READY) before capture.
i=0
while [ "$i" -lt 30 ]; do
    if grep -q READY "$OUT/py.log" 2>/dev/null; then break; fi
    if ! kill -0 "$PYPID" 2>/dev/null; then
        echo "demo: the python signer died; its log follows" >&2
        cat "$OUT/py.log" >&2 || true
        exit 1
    fi
    sleep 2
    i=$((i + 1))
done
if ! grep -q READY "$OUT/py.log" 2>/dev/null; then
    echo "demo: the python signer never reported READY; its log follows" >&2
    cat "$OUT/py.log" >&2 || true
    exit 1
fi
sleep 2
if ! kill -0 "$PYPID" 2>/dev/null; then
    echo "demo: the python signer died; its log follows" >&2
    cat "$OUT/py.log" >&2 || true
    exit 1
fi

echo "demo: capturing $DURATION s of system inventory ..." >&2
status=0
sudo -n "$OBSERVER" inventory --system \
    --duration "${DURATION}s" -o "$OUT/inventory.json" >"$OUT/inventory.txt" 2>"$OUT/inventory.err" \
    || status=$?
cat "$OUT/inventory.txt"
if [ "$status" -ne 0 ]; then
    echo "demo: system inventory failed (exit $status); its stderr follows" >&2
    cat "$OUT/inventory.err" >&2 || true
    exit 1
fi

echo "demo: profiling the python caller (pid $PYPID) for $PROFILE_SECS s ..." >&2
status=0
sudo -n "$OBSERVER" profile --pid "$PYPID" \
    --duration "${PROFILE_SECS}s" -o "$OUT/profile.json" >"$OUT/profile.txt" 2>"$OUT/profile.err" \
    || status=$?
cat "$OUT/profile.txt"
if [ "$status" -ne 0 ]; then
    echo "demo: profile failed (exit $status); its stderr follows" >&2
    cat "$OUT/profile.err" >&2 || true
    exit 1
fi

# The concise inventory names each caller program on the SoftHSM line.
fail=0
for name in openssl pkcs11-tool python3; do
    if grep -Fq "$name" "$OUT/inventory.txt"; then
        echo "demo: inventory names $name" >&2
    else
        echo "demo: inventory never names $name (full output above)" >&2
        fail=1
    fi
done
if [ "$fail" -ne 0 ]; then
    echo "demo: the SoftHSM line reads:" >&2
    grep -F "libsofthsm2" "$OUT/inventory.txt" >&2 || true
    echo "demo: $OUT holds inventory.json and the caller logs" >&2
    exit 1
fi
echo "demo: PASS: inventory names openssl, pkcs11-tool and python3" >&2
