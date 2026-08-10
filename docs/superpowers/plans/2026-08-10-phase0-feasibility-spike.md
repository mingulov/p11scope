# Phase 0 — Feasibility Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the decisive experiment from the design spec: an isolated helper obtains a (stripped) provider's function table, maps the pointers to stable file offsets, probes attach *before* the workload runs, and every controlled-harness call is captured with no module substitution — on the host and across a Docker mount-namespace boundary, including the shared-image-layer (inode) property.

**Architecture:** Three throwaway spike-grade artifacts in `spike/`: a C discovery helper (dlopen + `C_GetFunctionList` + `/proc/self/maps` → offset manifest), a deterministic C workload harness with exact known call counts, and shell glue that turns the manifest into a generated **bpftrace** program. No Go/cilium-ebpf yet — bpftrace is already installed and is the laziest way to test the *attachment semantics*, which is the actual risk. The product toolchain comes in Phase 1.

**Tech Stack:** C (clang), bpftrace ≥ 0.20, SoftHSM2 2.6, Docker (ubuntu:24.04 image), `strip`/`nm`/`readelf`.

## Global Constraints

- Everything in this plan lives under `spike/` (plus one findings doc in `docs/notes/`); it is evidence, not product code — committed, but never imported by product code.
- Working/scratch artifacts (binaries, tokens, manifests, outputs) go to `spike/work/`, which is gitignored.
- x86-64 Linux only. `sudo` is required for bpftrace steps — never work around missing privileges.
- The harness and discovery helper must only ever be pointed at SoftHSM2 (system copy or stripped copy of it). No vendor/production modules in the spike.
- Spike code needs no tests beyond its built-in acceptance check (`spike/check.sh` count comparison) — that check IS the deliverable.

## Spike acceptance criteria (from the design spec)

1. Manifest resolves all 68 PKCS#11 v2.40 function-table entries of a **fully stripped** SoftHSM2 copy to file offsets.
2. bpftrace attached **by offset only, before the harness starts**, captures call counts exactly matching the harness's known ground truth, plus `CK_RV` return values via uretprobes.
3. Same result with the workload inside a Docker container, probes attached from the host.
4. A second container from the same image is observed **without re-attaching** (shared image-layer inode → the Knative scale-from-zero claim).

---

### Task 1: Discovery helper (`spike/discover.c`)

**Files:**
- Create: `spike/discover.c`
- Modify: `.gitignore` (add `spike/work/`)

**Interfaces:**
- Produces: `discover <module.so>` → stdout, one line per function-table entry:
  `"<name> <mapped-path> <file-offset-hex> <vaddr-hex>"`, or `"<name> UNRESOLVED 0 0"`.
  Tasks 3–4 consume this format positionally (fields 1–4, space-separated).

- [ ] **Step 1: Write the helper**

```c
/* spike/discover.c — dlopen a PKCS#11 module, resolve its CK_FUNCTION_LIST
 * pointers to file offsets via /proc/self/maps. Spike quality: x86-64,
 * PKCS#11 v2.x table only, no 3.x interfaces, no ELF parsing.
 * Output per entry: <name> <path> <file_offset_hex> <vaddr_hex>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* CK_FUNCTION_LIST order, PKCS#11 v2.40, 68 entries. */
static const char *names[] = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
    "C_GetOperationState", "C_SetOperationState", "C_Login", "C_Logout",
    "C_CreateObject", "C_CopyObject", "C_DestroyObject", "C_GetObjectSize",
    "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
    "C_FindObjects", "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt",
    "C_EncryptUpdate", "C_EncryptFinal", "C_DecryptInit", "C_Decrypt",
    "C_DecryptUpdate", "C_DecryptFinal", "C_DigestInit", "C_Digest",
    "C_DigestUpdate", "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign",
    "C_SignUpdate", "C_SignFinal", "C_SignRecoverInit", "C_SignRecover",
    "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal",
    "C_VerifyRecoverInit", "C_VerifyRecover", "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate", "C_SignEncryptUpdate", "C_DecryptVerifyUpdate",
    "C_GenerateKey", "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey",
    "C_DeriveKey", "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus",
    "C_CancelFunction", "C_WaitForSlotEvent",
};
#define NFUNCS (sizeof names / sizeof names[0])

struct map { unsigned long lo, hi, off; char path[512]; };

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/module.so\n", argv[0]); return 2; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    if (!gfl) { fprintf(stderr, "no C_GetFunctionList export\n"); return 1; }

    void *list = NULL;
    unsigned long rv = gfl(&list);
    if (rv != 0 || !list) { fprintf(stderr, "C_GetFunctionList rv=0x%lx\n", rv); return 1; }

    /* CK_FUNCTION_LIST = CK_VERSION {2 x CK_BYTE}, padded to pointer
     * alignment, then 68 function pointers. On LP64 the pointers start at
     * offset 8 (Linux pkcs11.h uses no struct packing). */
    void **fns = (void **)((char *)list + 8);

    struct map maps[4096];
    int nmaps = 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("maps"); return 1; }
    char line[1024];
    while (nmaps < 4096 && fgets(line, sizeof line, f)) {
        struct map *m = &maps[nmaps];
        m->path[0] = 0;
        if (sscanf(line, "%lx-%lx %*4s %lx %*s %*s %511s",
                   &m->lo, &m->hi, &m->off, m->path) >= 3)
            nmaps++;
    }
    fclose(f);

    for (unsigned i = 0; i < NFUNCS; i++) {
        unsigned long p = (unsigned long)fns[i];
        struct map *hit = NULL, *base = NULL;
        for (int j = 0; j < nmaps; j++)
            if (p >= maps[j].lo && p < maps[j].hi) { hit = &maps[j]; break; }
        if (!hit || !hit->path[0]) {           /* non-file-backed: report, don't guess */
            printf("%s UNRESOLVED 0 0\n", names[i]);
            continue;
        }
        for (int j = 0; j < nmaps; j++)        /* first mapping of same file = load base */
            if (!strcmp(maps[j].path, hit->path)) { base = &maps[j]; break; }
        printf("%s %s 0x%lx 0x%lx\n", names[i], hit->path,
               p - hit->lo + hit->off,          /* file offset (uprobe currency) */
               p - base->lo);                   /* link-time vaddr: DSO first LOAD at 0 */
    }
    return 0;
}
```

- [ ] **Step 2: Add `spike/work/` to `.gitignore`** (append the line `spike/work/`)

- [ ] **Step 3: Build and run against the system SoftHSM2**

```bash
mkdir -p spike/work
clang -O1 -Wall -o spike/work/discover spike/discover.c -ldl
spike/work/discover /usr/lib/softhsm/libsofthsm2.so | tee spike/work/manifest-system.txt
wc -l spike/work/manifest-system.txt          # expect: 68
grep -c UNRESOLVED spike/work/manifest-system.txt   # expect: 0 (SoftHSM implements all)
```

- [ ] **Step 4: Cross-validate offsets against the (unstripped) symbol table**

SoftHSM exports every `C_*` symbol, so `nm -D` is an independent oracle for the
vaddr column — this is the correctness check for the maps arithmetic:

```bash
for fn in C_Initialize C_Digest C_Sign C_GenerateRandom; do
  want=$(nm -D /usr/lib/softhsm/libsofthsm2.so | awk -v f=$fn '$3==f {print "0x" $1}')
  got=$(awk -v f=$fn '$1==f {print $4}' spike/work/manifest-system.txt)
  echo "$fn nm=$want helper=$got"
done
```

Expected: `nm=` and `helper=` values identical for all four (leading zeros may
differ; compare numerically if needed: `$(( want == got ))`).

- [ ] **Step 5: Commit**

```bash
git add spike/discover.c .gitignore
git commit -m "spike: function-table discovery helper (dlopen -> file offsets)"
```

---

### Task 2: Deterministic workload harness (`spike/harness.c`)

**Files:**
- Create: `spike/harness.c`
- Create: `spike/expected.txt`

**Interfaces:**
- Consumes: nothing from other tasks (calls the module via its own function table).
- Produces: `harness <module.so>` → exit 0 and prints `harness OK`; issues exactly the call counts in `spike/expected.txt`. Tasks 3–4 treat `expected.txt` (`"<name> <count>"` lines, sorted) as ground truth.

- [ ] **Step 1: Write the harness**

```c
/* spike/harness.c — deterministic PKCS#11 workload with exact call counts.
 * Calls go through the module's own CK_FUNCTION_LIST (indirect calls), like a
 * real application. Digest + random only: no token objects, no login, no PIN.
 * Ground truth lives in spike/expected.txt.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKF_SERIAL_SESSION 4UL
#define CKM_SHA256 0x250UL

/* CK_FUNCTION_LIST indices (v2.40 order, see spike/discover.c) */
enum { I_Initialize = 0, I_Finalize = 1, I_GetInfo = 2, I_GetSlotList = 4,
       I_OpenSession = 12, I_CloseSession = 13, I_DigestInit = 37,
       I_Digest = 38, I_GenerateRandom = 64 };

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_diginit)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG,
                           unsigned char *, CK_ULONG *);
typedef CK_RV (*fn_rand)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);

static void **fns;

#define CHECK(what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "%s failed: 0x%lx\n", what, _rv); exit(1); } } while (0)

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/module.so\n", argv[0]); return 2; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    unsigned char info[256];
    for (int i = 0; i < 3; i++)
        CHECK("C_GetInfo", ((fn_gen)fns[I_GetInfo])(info));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "no token present — init a token first\n"); return 1; }

    CK_SESSION_HANDLE sess[10];
    for (int i = 0; i < 10; i++)
        CHECK("C_OpenSession",
              ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &sess[i]));

    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    unsigned char data[] = "pkcs11-scope spike", out[64];
    for (int i = 0; i < 50; i++) {
        CK_ULONG outlen = sizeof out;
        CHECK("C_DigestInit", ((fn_diginit)fns[I_DigestInit])(sess[0], &sha256));
        CHECK("C_Digest",
              ((fn_digest)fns[I_Digest])(sess[0], data, sizeof data - 1, out, &outlen));
    }

    unsigned char rnd[16];
    for (int i = 0; i < 100; i++)
        CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess[0], rnd, sizeof rnd));

    for (int i = 0; i < 10; i++)
        CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess[i]));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("harness OK\n");
    return 0;
}
```

- [ ] **Step 2: Write the ground truth** (`spike/expected.txt`, sorted, exactly this content)

```
C_CloseSession 10
C_Digest 50
C_DigestInit 50
C_Finalize 1
C_GenerateRandom 100
C_GetInfo 3
C_GetSlotList 1
C_Initialize 1
C_OpenSession 10
```

(`C_GetFunctionList` is deliberately not asserted: dlsym vs table-entry
attribution is ambiguous for it — that ambiguity is a *v1 reporting* concern,
not a spike blocker.)

- [ ] **Step 3: Build, set up a scratch token, run**

```bash
clang -O1 -Wall -o spike/work/harness spike/harness.c -ldl
mkdir -p spike/work/tokens
printf 'directories.tokendir = %s/spike/work/tokens\nobjectstore.backend = file\n' "$PWD" \
    > spike/work/softhsm2.conf
export SOFTHSM2_CONF=$PWD/spike/work/softhsm2.conf
softhsm2-util --init-token --free --label spike --pin 1234 --so-pin 12345678
spike/work/harness /usr/lib/softhsm/libsofthsm2.so
```

Expected: `harness OK`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add spike/harness.c spike/expected.txt
git commit -m "spike: deterministic PKCS#11 workload harness with known call counts"
```

---

### Task 3: Offset-attached capture on a stripped copy (host)

**Files:**
- Create: `spike/gen-bt.sh` (manifest → bpftrace program)
- Create: `spike/check.sh` (bpftrace output vs expected.txt)

**Interfaces:**
- Consumes: manifest format from Task 1; `spike/expected.txt` and harness from Task 2.
- Produces: `gen-bt.sh <manifest> [path-prefix]` → bpftrace program on stdout; `check.sh <expected.txt> <bpftrace-output>` → exit 0 + `ALL COUNTS MATCH`, or exit 1 with per-function mismatches. Task 4 reuses both unchanged.

- [ ] **Step 1: Write the generator**

```bash
#!/bin/sh
# gen-bt.sh <manifest> [path-prefix]  — emit a bpftrace program on stdout.
# Uses the vaddr column ($4): bpftrace's numeric-address probe form expects a
# virtual address within the object, not a raw file offset (see fallback note
# in the plan if counts come back zero). path-prefix is for /proc/<pid>/root.
awk -v prefix="${2:-}" '$2 != "UNRESOLVED" {
    path = prefix $2
    printf "uprobe:%s:%s { @call[\"%s\"] = count(); }\n",    path, $4, $1
    printf "uretprobe:%s:%s { @rv[\"%s\", retval] = count(); }\n", path, $4, $1
}' "$1"
```

- [ ] **Step 2: Write the checker**

```bash
#!/bin/sh
# check.sh <expected.txt> <bpftrace-output> — assert exact call counts.
fail=0
while read -r name count; do
    if ! grep -q "@call\[$name\]: $count\$" "$2"; then
        echo "MISMATCH $name: want $count, got: $(grep "@call\[$name\]" "$2" || echo none)"
        fail=1
    fi
done < "$1"
[ "$fail" = 0 ] && echo "ALL COUNTS MATCH"
exit "$fail"
```

- [ ] **Step 3: Make a fully stripped provider copy and discover it**

```bash
chmod +x spike/gen-bt.sh spike/check.sh
cp /usr/lib/softhsm/libsofthsm2.so spike/work/libsofthsm2-stripped.so
strip --strip-all spike/work/libsofthsm2-stripped.so
nm spike/work/libsofthsm2-stripped.so 2>&1 | head -1   # expect: "no symbols"
spike/work/discover "$PWD/spike/work/libsofthsm2-stripped.so" \
    | tee spike/work/manifest-stripped.txt
grep -c UNRESOLVED spike/work/manifest-stripped.txt     # expect: 0
```

(Dynamic exports remain in `.dynsym` — unavoidable and irrelevant: nothing
below consults any symbol table; only the manifest's numeric offsets are used.)

- [ ] **Step 4: Attach first, then run the harness, then check**

```bash
spike/gen-bt.sh spike/work/manifest-stripped.txt > spike/work/spike.bt
sudo timeout -s INT 60 bpftrace spike/work/spike.bt > spike/work/host-capture.txt &
sleep 5   # let all ~136 probes attach
export SOFTHSM2_CONF=$PWD/spike/work/softhsm2.conf
spike/work/harness "$PWD/spike/work/libsofthsm2-stripped.so"
sleep 1; sudo pkill -INT -f 'bpftrace .*spike.bt'; sleep 2   # flush + print maps
spike/check.sh spike/expected.txt spike/work/host-capture.txt
grep '@rv\[C_Digest, 0\]' spike/work/host-capture.txt   # expect: count 50 (CKR_OK)
```

Expected: `ALL COUNTS MATCH`, and the `@rv` line proves CK_RV capture via
uretprobe.

**Known ambiguity + fallback:** if every count is zero, bpftrace interpreted
the address as a file offset rather than a vaddr (or vice versa). Convert and
retry once — for each function, file offset ↔ vaddr via the containing LOAD
segment: `readelf -lW <lib>` , `vaddr = p_vaddr + (fileoff - p_offset)`.
Whichever interpretation works, **record it in the findings doc** — Phase 1's
cilium/ebpf attach code needs the same decision made explicitly.

- [ ] **Step 5: Commit**

```bash
git add spike/gen-bt.sh spike/check.sh
git commit -m "spike: offset-attached bpftrace capture matches harness ground truth"
```

---

### Task 4: Docker cross-namespace + shared-inode capture

**Files:**
- Create: `spike/Dockerfile`

**Interfaces:**
- Consumes: all Task 1–3 artifacts unchanged.
- Produces: evidence only (capture files under `spike/work/`), consumed by Task 5.

- [ ] **Step 1: Write the image** (same distro as host so host-built binaries run inside)

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/spike/softhsm2.conf
RUN mkdir -p /spike/tokens \
    && printf 'directories.tokendir = /spike/tokens\nobjectstore.backend = file\n' \
       > /spike/softhsm2.conf \
    && softhsm2-util --init-token --free --label spike --pin 1234 --so-pin 12345678
COPY work/discover work/harness /spike/
CMD ["sleep", "infinity"]
```

- [ ] **Step 2: Start container, discover inside it, attach from host**

```bash
docker build -t p11scope-spike -f spike/Dockerfile spike/
docker run -d --rm --name spike1 p11scope-spike
PID=$(docker inspect -f '{{.State.Pid}}' spike1)
docker exec spike1 /spike/discover /usr/lib/softhsm/libsofthsm2.so \
    > spike/work/manifest-container.txt
grep -c UNRESOLVED spike/work/manifest-container.txt    # expect: 0
spike/gen-bt.sh spike/work/manifest-container.txt "/proc/$PID/root" \
    > spike/work/spike-container.bt
sudo timeout -s INT 120 bpftrace spike/work/spike-container.bt \
    > spike/work/container-capture.txt &
sleep 5
```

- [ ] **Step 3: Run harness in the container — probes were attached from the host, before it ran**

```bash
docker exec spike1 /spike/harness /usr/lib/softhsm/libsofthsm2.so
```

- [ ] **Step 4: Second container, same image — NO new attachment (the Knative claim)**

```bash
docker run -d --rm --name spike2 p11scope-spike
docker exec spike2 /spike/harness /usr/lib/softhsm/libsofthsm2.so
sleep 1; sudo pkill -INT -f 'bpftrace .*spike-container.bt'; sleep 2
docker rm -f spike1 spike2
```

- [ ] **Step 5: Check — counts must be exactly DOUBLE the ground truth**

```bash
awk '{print $1, $2 * 2}' spike/expected.txt > spike/work/expected-double.txt
spike/check.sh spike/work/expected-double.txt spike/work/container-capture.txt
```

Expected: `ALL COUNTS MATCH`. spike2's calls landed in probes attached while
only spike1 existed → overlayfs image-layer inode is shared and future
containers are observed for free. If this FAILS at exactly 1× the counts,
the inode-sharing claim is wrong for this storage driver — record it; the
design's Knative story then needs per-container attach (a design revision,
not a spike failure).

- [ ] **Step 6: Commit**

```bash
git add spike/Dockerfile
git commit -m "spike: cross-mount-namespace and shared-image-layer capture verified"
```

---

### Task 5: Findings and go/no-go

**Files:**
- Create: `docs/notes/spike-findings.md`

- [ ] **Step 1: Write up results** — actual numbers, not adjectives. Required content:

```markdown
# Phase 0 spike findings — YYYY-MM-DD

| Check | Result |
| --- | --- |
| 68/68 entries resolved on stripped SoftHSM2 | PASS/FAIL |
| Helper vaddrs == nm -D oracle (4 sampled) | PASS/FAIL |
| Host capture == ground truth (stripped, attach-first) | PASS/FAIL |
| CK_RV via uretprobe (C_Digest → CKR_OK ×50) | PASS/FAIL |
| Container capture from host, attach-before-run | PASS/FAIL |
| Second container observed w/o re-attach (2× counts) | PASS/FAIL |

- bpftrace address interpretation: vaddr / file-offset (which one worked)
- Surprises / deviations:
- Decision: proceed to Phase 1: YES/NO (+ any design-spec amendments needed)
```

- [ ] **Step 2: Amend the design spec if any result contradicts it** (e.g. inode sharing), commit both:

```bash
git add docs/notes/spike-findings.md docs/superpowers/specs/2026-08-10-pkcs11-scope-design.md
git commit -m "spike: record Phase 0 findings and go/no-go decision"
```

---

## Self-review notes

- Spec coverage: this plan covers only the spike section of the spec by design; all other spec sections map to ROADMAP phases 1–5 (see `ROADMAP.md`), each of which gets its own detailed plan after the spike's go decision.
- The kind/Knative environments are deliberately NOT in the spike: the kernel mechanism they rely on (inode-attached uprobes crossing mount namespaces) is exactly what Task 4 proves with plain Docker; kind/Knative add orchestration, not new kernel behavior. They are validated in Phase 4.
- PKCS#11 3.x interface discovery (`C_GetInterfaceList`) is Phase 1 scope; SoftHSM2 2.6 is a 2.40 module, so the spike cannot exercise it anyway.
