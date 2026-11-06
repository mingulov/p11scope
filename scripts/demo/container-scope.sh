#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Container-scope demo (v0.7.0 F10; Task 9 reuses this script): two SoftHSM
# signing containers run on this host while the host inventory names each
# container in concise text.
#
#   scripts/demo/container-scope.sh [--observer BIN] [--duration SECS] [--keep]
#
# Flow: build the demo image (pinned Ubuntu base + SoftHSM + opensc + the
# embedded sign-loop client below), start two containers, wait for both to
# report READY, run `inventory --system --key-operations --caller-metadata
# cgroup` on the host, print the concise output, and check that it carries
# one caller line per demo container with its own `container <12hex>
# (docker)` label and a positive call count. Respects DOCKER_HOST, so a
# private daemon works. Removes its containers afterwards unless --keep;
# the image is kept for fast reruns. Exit 2 before any capture when a tool
# is missing, exit 1 when the capture or the label check fails.
set -eu

IMAGE=p11scope-demo-sign:1
CTR_A=p11scope-demo-a
CTR_B=p11scope-demo-b
# Pinned base reused from deploy/Dockerfile.holder (same digest, same window).
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
OBSERVER=p11scope
DURATION=60
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
command -v docker >/dev/null 2>&1 \
    || { echo "demo: docker not found; install Docker, then rerun this script" >&2; exit 2; }
case $OBSERVER in
    */*) [ -x "$OBSERVER" ] \
        || { echo "demo: p11scope not found; pass --observer PATH to the p11scope binary, then rerun this script" >&2; exit 2; } ;;
    *) command -v "$OBSERVER" >/dev/null 2>&1 \
        || { echo "demo: p11scope not found; pass --observer PATH to the p11scope binary, then rerun this script" >&2; exit 2; } ;;
esac
sudo -n true >/dev/null 2>&1 \
    || { echo "demo: this demo needs passwordless sudo for the host capture" >&2; exit 2; }
docker info >/dev/null 2>&1 \
    || { echo "demo: cannot reach the docker daemon; start Docker or set DOCKER_HOST, then rerun this script" >&2; exit 2; }

STARTED_A=0
STARTED_B=0
STAGE=
OUT=
# Plain ifs: an && chain that ends false would trip set -e inside the trap
# and flip a PASS to exit 1.
cleanup() {
    if [ "$KEEP" -eq 0 ]; then
        if [ "$STARTED_A" -eq 1 ]; then docker rm -f "$CTR_A" >/dev/null 2>&1 || true; fi
        if [ "$STARTED_B" -eq 1 ]; then docker rm -f "$CTR_B" >/dev/null 2>&1 || true; fi
        if [ -n "$OUT" ]; then rm -rf "$OUT" || true; fi
    fi
    if [ -n "$STAGE" ]; then rm -rf "$STAGE" || true; fi
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Never touch a container we did not start.
names=$(docker ps -a --format '{{.Names}}' 2>/dev/null) \
    || { echo "demo: docker ps failed" >&2; exit 2; }
for want in "$CTR_A" "$CTR_B"; do
    if printf '%s\n' "$names" | grep -Fxq "$want"; then
        echo "demo: container $want already exists; remove it, then rerun this script" >&2
        exit 2
    fi
done

# Reuse our own image when it carries our label; otherwise (re)build it.
need_build=1
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    have=$(docker image inspect --format '{{index .Config.Labels "p11scope.demo.signloop"}}' "$IMAGE" 2>/dev/null) || have=
    [ "$have" = 1 ] && need_build=0
fi
if [ "$need_build" -eq 1 ]; then
    STAGE=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-demo-XXXXXX")
    cat > "$STAGE/Dockerfile" <<EOF
FROM $HOLDER_BASE AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \\
    && rm -rf /var/lib/apt/lists/*
COPY signloop.c /src/signloop.c
RUN gcc -O1 -Wall -o /src/signloop /src/signloop.c -ldl
FROM $HOLDER_BASE
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc \\
    && rm -rf /var/lib/apt/lists/* \\
    && test -f /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \\
    && command -v pkcs11-tool
COPY --from=build /src/signloop /usr/local/bin/signloop
COPY demo-entry.sh /usr/local/bin/demo-entry
RUN chmod 0755 /usr/local/bin/demo-entry
LABEL p11scope.demo.signloop=1
ENTRYPOINT ["/usr/local/bin/demo-entry"]
EOF
    cat > "$STAGE/demo-entry.sh" <<'EOF'
#!/bin/sh
# Demo entry: token setup runs before the capture starts, so its one-shot
# processes never appear in it; then exactly one long-lived signer runs.
set -eu
MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
SECS=${1:-120}
export SOFTHSM2_CONF=/tmp/softhsm2.conf
rm -rf /tmp/tokens
mkdir -p /tmp/tokens
printf 'directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
    > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label demo-sign --so-pin 5678 --pin 1234 >/dev/null
pkcs11-tool --module "$MODULE" --login --pin 1234 --keypairgen --key-type rsa:2048 \
    --id 1 --label demo-sign >/dev/null
exec /usr/local/bin/signloop "$MODULE" "$SECS"
EOF
    cat > "$STAGE/signloop.c" <<'EOF'
/* signloop: long-lived SoftHSM signing load for the container-scope demo.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * usage: signloop MODULE SECONDS
 * Opens the first token slot, logs in (PIN 1234), finds the RSA private key
 * with CKA_ID 0x01 (created at entry by pkcs11-tool --keypairgen), then
 * C_Sign-loops until SECONDS elapse or SIGTERM/SIGINT arrives.
 * Prints one SIGNLOOP JSON line with exact success/error counts. */
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;
typedef struct {
    unsigned long type;
    void *value;
    unsigned long len;
} CK_ATTRIBUTE;
typedef struct {
    unsigned long mechanism;
    void *p;
    unsigned long len;
} CK_MECHANISM;
static volatile sig_atomic_t stop;
static void on(int s) {
    (void)s;
    stop = 1;
}
#define NEED(handle, name, ret, ...)                               \
    ret(*name)(__VA_ARGS__) = (ret(*)(__VA_ARGS__))dlsym(handle, #name); \
    if (!name) {                                                     \
        fprintf(stderr, "signloop: no %s\n", #name);                 \
        return 1;                                                    \
    }
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: signloop MODULE SECONDS\n");
        return 2;
    }
    long secs = atol(argv[2]);
    if (secs <= 0 || secs > 3600) {
        fprintf(stderr, "signloop: bad SECONDS\n");
        return 2;
    }
    signal(SIGTERM, on);
    signal(SIGINT, on);
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "signloop: dlopen: %s\n", dlerror());
        return 1;
    }
    NEED(h, C_Initialize, CK_RV, void *);
    NEED(h, C_Finalize, CK_RV, void *);
    NEED(h, C_GetSlotList, CK_RV, unsigned char, CK_SLOT_ID *, CK_ULONG *);
    NEED(h, C_OpenSession, CK_RV, CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
    NEED(h, C_CloseSession, CK_RV, CK_SESSION_HANDLE);
    NEED(h, C_Login, CK_RV, CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG);
    NEED(h, C_Logout, CK_RV, CK_SESSION_HANDLE);
    NEED(h, C_FindObjectsInit, CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    NEED(h, C_FindObjects, CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG,
         CK_ULONG *);
    NEED(h, C_FindObjectsFinal, CK_RV, CK_SESSION_HANDLE);
    NEED(h, C_SignInit, CK_RV, CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    NEED(h, C_Sign, CK_RV, CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *,
         CK_ULONG *);
    if (C_Initialize(NULL)) {
        fprintf(stderr, "signloop: C_Initialize failed\n");
        return 1;
    }
    CK_SLOT_ID slots[16];
    CK_ULONG nslots = 16;
    if (C_GetSlotList(1, slots, &nslots) || !nslots) {
        fprintf(stderr, "signloop: no token slot\n");
        return 1;
    }
    CK_SESSION_HANDLE s;
    if (C_OpenSession(slots[0], 6, NULL, NULL, &s)) {
        fprintf(stderr, "signloop: C_OpenSession failed\n");
        return 1;
    }
    if (C_Login(s, 1, (unsigned char *)"1234", 4)) {
        fprintf(stderr, "signloop: C_Login failed\n");
        return 1;
    }
    CK_ULONG class_priv = 3;
    static unsigned char keyid[] = {0x01};
    CK_ATTRIBUTE findt[] = {
        {0x00000000, &class_priv, sizeof class_priv},
        {0x00000102, keyid, sizeof keyid},
    };
    CK_OBJECT_HANDLE privkey = 0;
    CK_ULONG nfound = 0;
    if (C_FindObjectsInit(s, findt, 2) || C_FindObjects(s, &privkey, 1, &nfound)
        || C_FindObjectsFinal(s) || !nfound) {
        fprintf(stderr, "signloop: RSA key id 01 not found\n");
        return 1;
    }
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    static const unsigned char sha256_prefix[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    };
    unsigned char data[64], sig[512];
    memcpy(data, sha256_prefix, sizeof sha256_prefix);
    memset(data + sizeof sha256_prefix, 0xA5, 32);
    CK_ULONG datalen = sizeof(sha256_prefix) + 32;
    CK_MECHANISM sign_mech = {0x00000001, NULL, 0};
    unsigned long signs = 0, errors = 0, firstrv = 0;
    for (long i = 0; i < secs * 10 && !stop; i++) {
        CK_ULONG siglen = sizeof sig;
        CK_RV rv = C_SignInit(s, &sign_mech, privkey);
        if (!rv)
            rv = C_Sign(s, data, datalen, sig, &siglen);
        if (rv) {
            errors++;
            if (errors == 1)
                firstrv = rv;
        } else {
            signs++;
        }
        usleep(100000);
    }
    if (errors)
        fprintf(stderr, "signloop: first sign rv=0x%lx\n", firstrv);
    printf("SIGNLOOP {\"pid\":%d,\"signs\":%lu,\"errors\":%lu}\n", getpid(), signs, errors);
    fflush(stdout);
    C_Logout(s);
    C_CloseSession(s);
    C_Finalize(NULL);
    return errors ? 1 : 0;
}
EOF
    echo "demo: building $IMAGE ..." >&2
    # Host networking for the build steps only, so the image also builds
    # against a bridgeless private daemon; the signers themselves need no
    # network and run isolated.
    docker build -q --network=host -f "$STAGE/Dockerfile" -t "$IMAGE" "$STAGE" >&2 \
        || { echo "demo: image build failed" >&2; exit 2; }
fi

LOOP_SECS=$((DURATION + 60))
echo "demo: starting $CTR_A and $CTR_B ..." >&2
docker run -d --name "$CTR_A" "$IMAGE" "$LOOP_SECS" >/dev/null \
    || { echo "demo: cannot start $CTR_A" >&2; exit 1; }
STARTED_A=1
docker run -d --name "$CTR_B" "$IMAGE" "$LOOP_SECS" >/dev/null \
    || { echo "demo: cannot start $CTR_B" >&2; exit 1; }
STARTED_B=1

# Both signers must be past setup (token + key + READY) before the capture.
i=0
while [ "$i" -lt 30 ]; do
    ra=$(docker logs "$CTR_A" 2>&1 | grep -c READY) || ra=0
    rb=$(docker logs "$CTR_B" 2>&1 | grep -c READY) || rb=0
    [ "${ra:-0}" -ge 1 ] && [ "${rb:-0}" -ge 1 ] && break
    sleep 2
    i=$((i + 1))
done
if [ "${ra:-0}" -lt 1 ] || [ "${rb:-0}" -lt 1 ]; then
    echo "demo: a signer never reported READY; its log follows" >&2
    docker logs "$CTR_A" >&2 || true
    docker logs "$CTR_B" >&2 || true
    exit 1
fi

OUT=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-demo-out-XXXXXX")
[ "$KEEP" -eq 1 ] && echo "demo: output kept in $OUT" >&2
echo "demo: capturing $DURATION s of host inventory ..." >&2
status=0
sudo -n "$OBSERVER" inventory --system --key-operations --caller-metadata cgroup \
    --duration "${DURATION}s" -o "$OUT/capture.json" >"$OUT/capture.txt" 2>"$OUT/capture.err" \
    || status=$?
cat "$OUT/capture.txt"
if [ "$status" -ne 0 ]; then
    echo "demo: host capture failed (exit $status); its stderr follows" >&2
    cat "$OUT/capture.err" >&2 || true
    exit 1
fi

# One caller line per demo container, with its own 12-hex label and calls > 0.
fail=0
for ctr in "$CTR_A" "$CTR_B"; do
    id=$(docker inspect --format '{{.Id}}' "$ctr" 2>/dev/null) \
        || { echo "demo: cannot inspect $ctr" >&2; exit 1; }
    prefix=$(printf '%s' "$id" | cut -c1-12)
    line=$(grep -F "container $prefix (docker)" "$OUT/capture.txt" | head -1) || line=
    if [ -z "$line" ]; then
        echo "demo: no caller line for $ctr (container $prefix)" >&2
        fail=1
        continue
    fi
    count=$(printf '%s' "$line" | sed -n 's/^caller .* pid [0-9][0-9]*: \([0-9][0-9]*\) entr.*/\1/p')
    case $count in
        ''|0) echo "demo: $ctr caller line has no calls: $line" >&2; fail=1 ;;
        *) echo "demo: $ctr: $line" >&2 ;;
    esac
done
if [ "$fail" -ne 0 ]; then
    echo "demo: container labels missing or call-free (full output above)" >&2
    exit 1
fi
echo "demo: PASS: both demo containers are named with their own container IDs" >&2
