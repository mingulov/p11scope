/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* provider_info: single-process SoftHSM info-call workload for the
 * `inventory-provider-info-pid` public cell (`inventory --pid --capture
 * native --provider-info -o`).
 *
 * usage: provider_info MODULE GATE
 *   GATE: path to wait for, or "-" for no wait (self-tests only)
 *
 * After the gate opens the workload makes exactly one observed call per
 * info query: C_GetInfo, one C_GetSlotList over every slot, and per slot
 * one C_GetTokenInfo plus, on slots holding a token, one
 * C_GetMechanismList and one C_GetMechanismInfo per listed mechanism.
 * The LEDGER (schema p11scope/provider-info-ledger/v1) carries the
 * returned C_GetInfo record, the per-slot token presence and token
 * facts, and the per-slot mechanism facts, so the oracle asserts the
 * report's provider_info, token rows and mechanism rows exactly.
 *
 * Gate discipline (as mt_mixed): only dlopen/C_GetFunctionList/
 * C_Initialize run before READY; every info call happens after the
 * gate opens, i.e. after the observer attaches. Any unexpected return
 * (a should-succeed call failing, a should-fail call succeeding, a
 * truncated list) exits nonzero with no LEDGER, so a sample that did
 * not run exactly as scripted can never count. The ledger refuses
 * vacuity: zero slots, zero token rows or zero mechanism rows die
 * instead of emitting an empty expectation.
 *
 * The ledger prints only allowlisted info fact fields (versions,
 * manufacturer, model, flags, PIN lengths, key sizes); token labels,
 * serials, session counts, memory sizes and clock readings are never
 * printed, mirroring the product's own exclusion (spec section 17.2).
 *
 * After LEDGER the workload holds for SIGTERM/SIGINT instead of
 * exiting (inventory capture windows; like MT_MIXED_HOLD=1): the
 * harness stops the observer first, then terminates the workload.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_FLAGS, CK_MECHANISM_TYPE;
typedef unsigned char CK_BBOOL;

typedef struct { unsigned char major, minor; } CK_VERSION;
typedef struct {
    CK_VERSION cryptokiVersion;
    unsigned char manufacturerID[32];
    CK_FLAGS flags;
    unsigned char libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef struct {
    unsigned char label[32];
    unsigned char manufacturerID[32];
    unsigned char model[16];
    unsigned char serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG maxSessionCount, sessionCount, maxRwSessionCount, rwSessionCount;
    CK_ULONG maxPinLen, minPinLen;
    CK_ULONG totalPublicMemory, freePublicMemory, totalPrivateMemory, freePrivateMemory;
    CK_VERSION hardwareVersion, firmwareVersion;
    unsigned char utcTime[16];
} CK_TOKEN_INFO;
typedef struct {
    CK_ULONG minKeySize, maxKeySize, flags;
} CK_MECHANISM_INFO;

#define CKR_OK 0UL
#define CKR_TOKEN_NOT_PRESENT 0xE0UL
#define CKR_BUFFER_TOO_SMALL 0x150UL

/* Index into the v2.40 CK_FUNCTION_LIST for each info function. */
enum { I_GetInfo = 2, I_GetSlotList = 4, I_GetTokenInfo = 6,
       I_GetMechanismList = 7, I_GetMechanismInfo = 8 };
static const int INFO_INDEX[5] = {I_GetInfo, I_GetSlotList, I_GetTokenInfo,
                                  I_GetMechanismList, I_GetMechanismInfo};
static const char *INFO_NAME[5] = {"C_GetInfo", "C_GetSlotList", "C_GetTokenInfo",
                                   "C_GetMechanismList", "C_GetMechanismInfo"};

#define MAX_SLOTS 64
#define MAX_MECHS 256

#define F(fns, i, t) ((t)(fns)[i])

static void info_die(const char *what, CK_RV rv)
{
    fprintf(stderr, "provider_info: %s: rv=0x%lx\n", what, rv);
    exit(1);
}

static void info_target(const char *name, void *address)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[4096], perms[5];
    unsigned long lo, hi, off, ino;
    unsigned int major, minor;
    uintptr_t ptr;
    if (!maps)
        info_die("maps", 0);
    ptr = (uintptr_t)address;
    while (fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &lo, &hi, perms, &off, &major, &minor,
                   &ino) == 7 &&
            ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
            printf("TARGET {\"name\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,\"file_offset\":%lu}\n",
                   name, major, minor, ino, (unsigned long)(ptr - lo) + off);
            fclose(maps);
            return;
        }
    }
    fclose(maps);
    info_die("target not mapped", 0);
}

/* Trim one space-padded fixed-width field exactly like the observer's
 * trim_padded (provider_info.rs): truncate at the first NUL, trim
 * trailing spaces. Non-UTF8 bytes fail the workload: the ledger must
 * stay comparable with the report's refused-string shape. */
static void trim_padded(const unsigned char *field, size_t len, char *out, size_t out_len)
{
    size_t end = len;
    for (size_t i = 0; i < len; i++) {
        if (field[i] == 0) {
            end = i;
            break;
        }
    }
    while (end > 0 && field[end - 1] == ' ')
        end--;
    if (end + 1 > out_len) {
        fprintf(stderr, "provider_info: trimmed field overruns\n");
        exit(1);
    }
    for (size_t i = 0; i < end; i++) {
        if (field[i] < 0x20 || field[i] > 0x7E) {
            fprintf(stderr, "provider_info: non-ASCII info byte 0x%02x\n", field[i]);
            exit(1);
        }
        out[i] = (char)field[i];
    }
    out[end] = 0;
}

/* One JSON string literal on a single line; the trimmed info alphabet
 * above keeps this total (quote and backslash still escaped). */
static void json_string(const char *text)
{
    putchar('"');
    for (const char *p = text; *p; p++) {
        if (*p == '"' || *p == '\\')
            putchar('\\');
        putchar(*p);
    }
    putchar('"');
}

struct mech_fact {
    CK_MECHANISM_TYPE id;
    CK_ULONG min_key, max_key, flags;
};

struct slot_fact {
    CK_SLOT_ID id;
    int token;
    char manufacturer[33];
    char model[17];
    CK_FLAGS flags;
    CK_ULONG pin_min, pin_max;
    unsigned char hardware_major, hardware_minor, firmware_major, firmware_minor;
    struct mech_fact mechs[MAX_MECHS];
    size_t nmechs;
};

static void wait_gate(const char *gate)
{
    if (!gate || !*gate || (gate[0] == '-' && !gate[1]))
        return;
    while (access(gate, F_OK) != 0)
        usleep(10000);
}

static volatile sig_atomic_t stop_seen;
static void on_stop(int sig)
{
    (void)sig;
    stop_seen = 1;
}

int main(int argc, char **argv)
{
    void *handle, *list = NULL, **fns;
    CK_RV (*gfl)(void **);
    CK_RV rv;
    CK_INFO info;
    CK_SLOT_ID slots[MAX_SLOTS];
    CK_ULONG nslots;
    struct slot_fact facts[MAX_SLOTS];
    size_t ntokens = 0, nmechinfo = 0, ncalls;
    char manufacturer[33], description[33];
    typedef struct { void *c, *d, *l, *u; CK_FLAGS flags; void *r; } INITARGS;
    INITARGS args;

    if (argc != 3) {
        fprintf(stderr, "usage: %s MODULE GATE\n", argv[0]);
        return 2;
    }
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "provider_info: dlopen: %s\n", dlerror());
        return 1;
    }
    gfl = (CK_RV(*)(void **))dlsym(handle, "C_GetFunctionList");
    if (!gfl || gfl(&list) || !list)
        info_die("C_GetFunctionList", 0);
    fns = (void **)((char *)list + 8);
    memset(&args, 0, sizeof args);
    args.flags = 2; /* CKF_OS_LOCKING_OK */
    rv = F(fns, 0, CK_RV (*)(void *))(&args);
    if (rv != CKR_OK)
        info_die("C_Initialize", rv);
    for (int i = 0; i < 5; i++)
        info_target(INFO_NAME[i], fns[INFO_INDEX[i]]);
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    wait_gate(argv[2]);

    memset(&info, 0, sizeof info);
    rv = F(fns, I_GetInfo, CK_RV (*)(CK_INFO *))(&info);
    if (rv != CKR_OK)
        info_die("C_GetInfo", rv);
    trim_padded(info.manufacturerID, sizeof info.manufacturerID, manufacturer, sizeof manufacturer);
    trim_padded(info.libraryDescription, sizeof info.libraryDescription, description,
                sizeof description);

    nslots = MAX_SLOTS;
    rv = F(fns, I_GetSlotList, CK_RV (*)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *))(0, slots, &nslots);
    if (rv != CKR_OK)
        info_die("C_GetSlotList", rv);
    if (nslots == 0 || nslots > MAX_SLOTS) {
        fprintf(stderr, "provider_info: slot count %lu proves nothing\n", nslots);
        return 1;
    }
    for (CK_ULONG s = 0; s < nslots; s++) {
        struct slot_fact *fact = &facts[s];
        CK_TOKEN_INFO token;
        CK_MECHANISM_TYPE mechs[MAX_MECHS];
        CK_ULONG nmechs;
        memset(fact, 0, sizeof *fact);
        fact->id = slots[s];
        memset(&token, 0, sizeof token);
        rv = F(fns, I_GetTokenInfo, CK_RV (*)(CK_SLOT_ID, CK_TOKEN_INFO *))(slots[s], &token);
        if (rv == CKR_OK) {
            fact->token = 1;
            ntokens++;
            trim_padded(token.manufacturerID, sizeof token.manufacturerID, fact->manufacturer,
                        sizeof fact->manufacturer);
            trim_padded(token.model, sizeof token.model, fact->model, sizeof fact->model);
            fact->flags = token.flags;
            fact->pin_min = token.minPinLen;
            fact->pin_max = token.maxPinLen;
            fact->hardware_major = token.hardwareVersion.major;
            fact->hardware_minor = token.hardwareVersion.minor;
            fact->firmware_major = token.firmwareVersion.major;
            fact->firmware_minor = token.firmwareVersion.minor;
        } else if (rv != CKR_TOKEN_NOT_PRESENT) {
            info_die("C_GetTokenInfo", rv);
        }
        if (!fact->token)
            continue;
        nmechs = MAX_MECHS;
        rv = F(fns, I_GetMechanismList,
               CK_RV (*)(CK_SLOT_ID, CK_MECHANISM_TYPE *, CK_ULONG *))(slots[s], mechs, &nmechs);
        if (rv != CKR_OK)
            info_die("C_GetMechanismList", rv);
        if (nmechs > MAX_MECHS) {
            fprintf(stderr, "provider_info: mechanism count %lu overruns\n", nmechs);
            return 1;
        }
        for (CK_ULONG m = 0; m < nmechs; m++) {
            CK_MECHANISM_INFO minfo;
            memset(&minfo, 0, sizeof minfo);
            rv = F(fns, I_GetMechanismInfo,
                   CK_RV (*)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO *))(slots[s],
                                                                                 mechs[m], &minfo);
            if (rv != CKR_OK)
                info_die("C_GetMechanismInfo", rv);
            fact->mechs[m].id = mechs[m];
            fact->mechs[m].min_key = minfo.minKeySize;
            fact->mechs[m].max_key = minfo.maxKeySize;
            fact->mechs[m].flags = minfo.flags;
            nmechinfo++;
        }
        fact->nmechs = nmechs;
    }
    if (ntokens == 0 || nmechinfo == 0) {
        fprintf(stderr, "provider_info: %lu token rows and %lu mechanism infos prove nothing\n",
                (unsigned long)ntokens, (unsigned long)nmechinfo);
        return 1;
    }

    printf("LEDGER {\"schema\":\"p11scope/provider-info-ledger/v1\",\"pid\":%d,\"complete\":true,",
           (int)getpid());
    printf("\"info\":{\"cryptoki_major\":%u,\"cryptoki_minor\":%u,\"manufacturer\":",
           info.cryptokiVersion.major, info.cryptokiVersion.minor);
    json_string(manufacturer);
    printf(",\"description\":");
    json_string(description);
    printf(",\"flags\":%lu,\"library_major\":%u,\"library_minor\":%u},\"slots\":[",
           (unsigned long)info.flags, info.libraryVersion.major, info.libraryVersion.minor);
    for (CK_ULONG s = 0; s < nslots; s++) {
        struct slot_fact *fact = &facts[s];
        printf("%s{\"slot\":%lu,\"token\":%s", s ? "," : "", (unsigned long)fact->id,
               fact->token ? "true" : "false");
        if (fact->token) {
            printf(",\"manufacturer\":");
            json_string(fact->manufacturer);
            printf(",\"model\":");
            json_string(fact->model);
            printf(",\"flags\":%lu,\"pin_min_len\":%lu,\"pin_max_len\":%lu,"
                   "\"hardware_major\":%u,\"hardware_minor\":%u,\"firmware_major\":%u,"
                   "\"firmware_minor\":%u",
                   (unsigned long)fact->flags, (unsigned long)fact->pin_min,
                   (unsigned long)fact->pin_max, fact->hardware_major, fact->hardware_minor,
                   fact->firmware_major, fact->firmware_minor);
        }
        printf(",\"mechanisms\":[");
        for (size_t m = 0; m < fact->nmechs; m++) {
            printf("%s{\"id\":%lu,\"min_key_size\":%lu,\"max_key_size\":%lu,\"flags\":%lu}",
                   m ? "," : "", (unsigned long)fact->mechs[m].id,
                   (unsigned long)fact->mechs[m].min_key,
                   (unsigned long)fact->mechs[m].max_key, (unsigned long)fact->mechs[m].flags);
        }
        printf("]}");
    }
    printf("]}\n");
    fflush(stdout);
    ncalls = 2 + nslots + ntokens;
    for (CK_ULONG s = 0; s < nslots; s++)
        ncalls += facts[s].nmechs;
    fprintf(stderr, "provider_info: %lu post-gate table calls over %lu slots\n",
            (unsigned long)ncalls, (unsigned long)nslots);

    /* Hold for the harness stop (inventory windows only): SIGTERM/SIGINT. */
    {
        struct sigaction stop = {0};
        stop.sa_handler = on_stop;
        sigemptyset(&stop.sa_mask);
        if (sigaction(SIGTERM, &stop, NULL) || sigaction(SIGINT, &stop, NULL)) {
            fprintf(stderr, "provider_info: sigaction failed\n");
            return 1;
        }
        while (!stop_seen)
            pause();
    }
    return 0;
}
