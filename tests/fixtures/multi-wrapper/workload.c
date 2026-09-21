/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned deterministic workload + oracle writer (system-scale plan Tasks
 * 1.4/1.5/1.6). Drives the multi-wrapper provider through one scenario,
 * records every call the provider must emit, and writes the exact oracle.
 *
 * Usage: workload <provider.so> <scenario> <seed> <logpath> <oraclepath>
 *
 * Scenarios: five | holes | reuse | pair_a | pair_b | forward | fail | legacy | stage
 *   five    alloc 5 wrappers (indices 0..4, so index 4 > 3 is active)
 *   holes   alloc 18, free 0..16, call only via 17 (0..3 free at call time)
 *   reuse   holes setup, then one more alloc must reuse index 0
 *   pair_a  alloc 2 -> indices {0,1} (two-process lane, same inode)
 *   pair_b  alloc 7, free 0..4 -> indices {5,6} (two-process lane)
 *   forward one wrapper with ordinals 5,43 forwarded straight to backend.so
 *   fail    one wrapper whose ordinal 43 fails wrapper-only (no backend)
 *   legacy  publish only: C_GetFunctionList + interface list, zero calls
 *   stage   stdin REPL driving alloc/free/call/publish for capture tests;
 *           the log path feeds P11SCOPE_MW_LOG (C-command calls are
 *           recorded there); the oracle path is unused (no oracle is
 *           written). Commands (one per line, stdout flushed per reply):
 *             A <fwd> <fail>  alloc; replies ALLOC idx=<i> table=0x...
 *             F <idx>         free; replies FREED idx=<i>
 *             C <idx> <ord> <n>
 *                             call entry <ord> on wrapper <idx> <n> times
 *                             (mid-capture activation for Task 1.6 lanes);
 *                             replies CALLED idx=<i> ord=<o> n=<n> rv=<rv>;
 *                             every call is recorded via mw_log exactly
 *                             like scenario calls (P11SCOPE_MW_LOG comes
 *                             from argv[4] as usual)
 *             P               publish via the real standard factories and
 *                             print every published table with all entries
 *             T               print the template pool (or TEMPLATE unknown
 *                             when the pool symbol is hidden)
 *             B               print the six backend entry addresses
 *             G <name|-> [major minor]
 *                             drive C_GetInterface ("-" is a NULL name) and
 *                             print the result; an explicit version is
 *                             passed by pointer, else NULL. Replies
 *                             IFACE rv=<rv> name=<name|(none)> table=<ptr>
 *                             flags=<flags> (table=(nil) when no interface
 *                             is returned).
 *             V <idx> <major> <minor>
 *                             rewrite wrapper <idx>'s version word in
 *                             place; replies VERSION idx=<i> major=<ma>
 *                             minor=<mi>
 *             M <idx> <ord> <mode>
 *                             rewrite wrapper <idx>'s entry <ord> in place
 *                             (0 NULL hole, 1 unmapped, 2 provider .bss,
 *                             3 heap data); replies POKED idx=<i> ord=<o>
 *                             mode=<m>
 *             X               exit 0
 *
 * The log path is exported as P11SCOPE_MW_LOG for the provider/backend
 * stubs. The oracle JSON carries the exact expected log lines (this process
 * knows its own pid/tid), per-key counts, occupancy at call time, and the
 * layout_known flag derived from a real dlsym of "p11scope_fixed".
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -o workload workload.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;
typedef CK_RV (*EntryFn)(CK_ULONG p0, CK_ULONG p1);
typedef struct {
    CK_VERSION version;
    void *funcs[104];
} Table;

#define CKR_OK 0UL
#define CKR_DEVICE_ERROR 0x30UL
#define NEX 6

static const int EX[NEX] = { 0, 5, 13, 18, 43, 44 };
static const char *EX_NAMES[NEX] = {
    "C_Initialize", "C_GetSlotList", "C_OpenSession", "C_Login", "C_Sign", "C_SignUpdate"
};

#define EXIT_USAGE 2
#define EXIT_LOAD 3
#define EXIT_SCENARIO 4
#define EXIT_IO 5

static void *need_sym(void *handle, const char *name)
{
    dlerror();
    void *sym = dlsym(handle, name);
    const char *err = dlerror();
    if (err != NULL || sym == NULL) {
        fprintf(stderr, "workload: missing symbol %s\n", name);
        exit(EXIT_LOAD);
    }
    return sym;
}

static uint64_t rng_state;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

typedef struct {
    char **lines;
    size_t len;
    size_t cap;
} Expect;

static void expect_init(Expect *e)
{
    e->lines = NULL;
    e->len = 0;
    e->cap = 0;
}

static void expect_push(Expect *e, const char *line)
{
    if (e->len == e->cap) {
        size_t grown = e->cap == 0 ? 64 : e->cap * 2;
        char **next = realloc(e->lines, grown * sizeof *next);
        if (next == NULL) {
            fprintf(stderr, "workload: out of memory\n");
            exit(EXIT_IO);
        }
        e->lines = next;
        e->cap = grown;
    }
    e->lines[e->len] = strdup(line);
    if (e->lines[e->len] == NULL) {
        fprintf(stderr, "workload: out of memory\n");
        exit(EXIT_IO);
    }
    e->len++;
}

/* Must stay byte-identical to mw_log's format in backend.c. */
static void expect_record(Expect *e, int pid, int tid, const char *layer, const char *func,
    CK_ULONG idx, const char *via, CK_RV rv)
{
    char line[256];
    snprintf(line, sizeof line, "%d %d %s %s %lu %s %lu\n", pid, tid, layer, func, idx, via, rv);
    expect_push(e, line);
}

static void do_call(Expect *e, int pid, int tid, Table *t, int idx, int ex, int fwd_mask, int fail_ord)
{
    int ord = EX[ex];
    if ((fwd_mask & (1 << ex)) != 0) {
        expect_record(e, pid, tid, "backend", EX_NAMES[ex], (CK_ULONG)idx, "direct", CKR_OK);
    } else if (fail_ord == ord) {
        expect_record(
            e, pid, tid, "wrapper", EX_NAMES[ex], (CK_ULONG)idx, "direct", CKR_DEVICE_ERROR);
    } else {
        expect_record(e, pid, tid, "wrapper", EX_NAMES[ex], (CK_ULONG)idx, "direct", CKR_OK);
        expect_record(e, pid, tid, "backend", EX_NAMES[ex], (CK_ULONG)idx, "nested", CKR_OK);
    }
    EntryFn fn = t->funcs[ord];
    CK_RV rv = fn((CK_ULONG)idx, 0);
    CK_RV want = (fail_ord == ord && (fwd_mask & (1 << ex)) == 0) ? CKR_DEVICE_ERROR : CKR_OK;
    if (rv != want) {
        fprintf(stderr, "workload: ordinal %d returned %lu, want %lu\n", ord, rv, want);
        exit(EXIT_SCENARIO);
    }
}

static void call_plan(Expect *e, int pid, int tid, Table *t, int idx, int fwd_mask, int fail_ord)
{
    for (int ex = 0; ex < NEX; ex++) {
        unsigned n = 1 + (unsigned)(rng_next() % 3);
        for (unsigned k = 0; k < n; k++) {
            do_call(e, pid, tid, t, idx, ex, fwd_mask, fail_ord);
        }
    }
}

typedef void *(*alloc_fn)(int fwd_mask, int fail_ord);
typedef void (*free_fn)(void *handle);
typedef int (*index_fn)(void *handle);
typedef void *(*table_fn)(void *handle);
typedef void (*set_version_fn)(void *handle, int major, int minor);
typedef void (*poke_fn)(void *handle, int ord, int mode);
typedef int (*occupied_fn)(int idx);
typedef CK_RV (*gfl_fn)(void **list);
typedef CK_RV (*gil_fn)(CK_INTERFACE *list, CK_ULONG *count);
typedef CK_RV (*gi_fn)(void *name, void *version, void **out, CK_FLAGS flags);

typedef struct {
    int index;
    int fwd;
    int fail;
} WrapperInfo;

static void write_oracle(const char *path, const char *scenario, unsigned long seed,
    const char *variant, int layout_known, int pid, const WrapperInfo *wrappers, size_t nw,
    const int *free_list, size_t nfree, const int *occ_list, size_t nocc, int legacy_pub,
    int legacy_major, int legacy_minor, long reused, const Expect *e)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        fprintf(stderr, "workload: cannot write %s\n", path);
        exit(EXIT_IO);
    }
    fprintf(f, "{\n  \"scenario\": \"%s\",\n  \"seed\": %lu,\n", scenario, seed);
    fprintf(f, "  \"build_variant\": \"%s\",\n  \"layout_known\": %s,\n  \"pid\": %d,\n",
        variant, layout_known ? "true" : "false", pid);
    fprintf(f, "  \"wrappers\": [");
    for (size_t k = 0; k < nw; k++) {
        fprintf(f, "%s{\"index\": %d, \"fwd\": %d, \"fail\": %d}", k == 0 ? "" : ", ",
            wrappers[k].index, wrappers[k].fwd, wrappers[k].fail);
    }
    fprintf(f, "],\n  \"free_at_call\": [");
    for (size_t k = 0; k < nfree; k++) {
        fprintf(f, "%s%d", k == 0 ? "" : ", ", free_list[k]);
    }
    fprintf(f, "],\n  \"occupied_at_call\": [");
    for (size_t k = 0; k < nocc; k++) {
        fprintf(f, "%s%d", k == 0 ? "" : ", ", occ_list[k]);
    }
    fprintf(f, "],\n");
    fprintf(f,
        "  \"legacy\": {\"published\": %s, \"major\": %d, \"minor\": %d},\n  \"reused\": %ld,\n",
        legacy_pub ? "true" : "false", legacy_major, legacy_minor, reused);
    fprintf(f, "  \"expected\": [");
    for (size_t k = 0; k < e->len; k++) {
        size_t len = strlen(e->lines[k]);
        if (len > 0 && e->lines[k][len - 1] == '\n') {
            e->lines[k][len - 1] = '\0';
        }
        /* Lines never contain '"' or '\\'; no escaping needed. */
        fprintf(f, "%s\"%s\"", k == 0 ? "\n" : ",\n", e->lines[k]);
    }
    fprintf(f, "%s],\n", e->len == 0 ? "" : "\n");
    /* Counts keyed "layer func idx via rv" (the log line minus pid/tid). */
    fprintf(f, "  \"counts\": {");
    size_t distinct = 0;
    for (size_t k = 0; k < e->len; k++) {
        const char *key = e->lines[k];
        int skip = 0;
        for (int s = 0; s < 2; s++) {
            const char *sp = strchr(key, ' ');
            if (sp == NULL) {
                skip = 1;
                break;
            }
            key = sp + 1;
        }
        if (skip) {
            continue;
        }
        size_t n = 0;
        for (size_t j = 0; j < e->len; j++) {
            const char *other = e->lines[j];
            for (int s = 0; s < 2; s++) {
                other = strchr(other, ' ') + 1;
            }
            if (strcmp(other, key) == 0) {
                n++;
            }
        }
        int seen = 0;
        for (size_t j = 0; j < k; j++) {
            const char *other = e->lines[j];
            for (int s = 0; s < 2; s++) {
                other = strchr(other, ' ') + 1;
            }
            if (strcmp(other, key) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            fprintf(f, "%s\"%s\": %zu", distinct == 0 ? "\n" : ",\n", key, n);
            distinct++;
        }
    }
    fprintf(f, "%s},\n", distinct == 0 ? "" : "\n");
    fprintf(f, "  \"total\": %zu\n}\n", e->len);
    if (fclose(f) != 0) {
        fprintf(stderr, "workload: failed to close %s\n", path);
        exit(EXIT_IO);
    }
}

static void snapshot_occupancy(occupied_fn occ, int *free_list, size_t *nfree, int *occ_list,
    size_t *nocc, int lo, int hi)
{
    *nfree = 0;
    *nocc = 0;
    for (int idx = lo; idx <= hi; idx++) {
        if (occ(idx)) {
            occ_list[(*nocc)++] = idx;
        } else {
            free_list[(*nfree)++] = idx;
        }
    }
}

#define STAGE_NWRAP 64
#define STAGE_NENTRY 104
#define STAGE_LEGACY_NENTRY 68

typedef struct {
    alloc_fn do_alloc;
    free_fn do_free;
    index_fn do_index;
    table_fn do_table;
    set_version_fn do_set_version;
    poke_fn do_poke;
    gfl_fn gfl;
    gil_fn gil;
    gi_fn gi;
    void *handles[STAGE_NWRAP];
} Stage;

static const char *stage_sym(void *addr)
{
    Dl_info info;
    if (addr == NULL || dladdr(addr, &info) == 0 || info.dli_sname == NULL) {
        return "-";
    }
    return info.dli_sname;
}

/* Print one table exactly as the observer's probe would capture it: the
 * version word plus every entry pointer. Index -1 marks the legacy table. */
static void stage_print_table(int idx, const void *table, int nentry)
{
    const unsigned char *bytes = table;
    printf("TABLE index=%d addr=%p major=%u minor=%u nentry=%d\n", idx, table, bytes[0],
        bytes[1], nentry);
    const void *const *funcs = (const void *const *)((const char *)table + 8);
    for (int o = 0; o < nentry; o++) {
        printf("E ord=%d addr=%p sym=%s\n", o, funcs[o], stage_sym((void *)funcs[o]));
    }
}

static int stage_publish(Stage *s)
{
    void *legacy = NULL;
    if (s->gfl(&legacy) != CKR_OK || legacy == NULL) {
        printf("ERROR C_GetFunctionList failed\n");
        return -1;
    }
    CK_ULONG count = 0;
    if (s->gil(NULL, &count) != CKR_OK || count < 1 || count > STAGE_NWRAP + 1) {
        printf("ERROR C_GetInterfaceList count failed\n");
        return -1;
    }
    CK_INTERFACE *list = calloc(count, sizeof *list);
    if (list == NULL) {
        printf("ERROR out of memory\n");
        return -1;
    }
    CK_ULONG want = count;
    CK_RV rv = s->gil(list, &want);
    if (rv != CKR_OK || want != count) {
        printf("ERROR C_GetInterfaceList failed\n");
        free(list);
        return -1;
    }
    printf("PUBLISH begin count=%lu\n", count);
    stage_print_table(-1, legacy, STAGE_LEGACY_NENTRY);
    for (CK_ULONG k = 0; k < count; k++) {
        int idx = -1;
        if (sscanf(list[k].pInterfaceName, "P11Scope-MW-%d", &idx) != 1) {
            idx = -1;
        }
        /* Every list element is independently re-published through
         * C_GetInterface: the two factories must agree exactly. */
        void *found = NULL;
        if (s->gi(list[k].pInterfaceName, NULL, &found, 0) != CKR_OK || found == NULL
            || ((const CK_INTERFACE *)found)->pFunctionList != list[k].pFunctionList) {
            printf("ERROR C_GetInterface disagrees on %s\n", list[k].pInterfaceName);
            free(list);
            return -1;
        }
        stage_print_table(idx, list[k].pFunctionList,
            idx < 0 ? STAGE_LEGACY_NENTRY : STAGE_NENTRY);
    }
    printf("PUBLISH end\n");
    free(list);
    return 0;
}

static int stage_templates(void *handle)
{
    dlerror();
    Table *pool = dlsym(handle, "p11scope_fixed");
    if (dlerror() != NULL || pool == NULL) {
        printf("TEMPLATE unknown\n");
        fflush(stdout);
        return 0;
    }
    for (int idx = 0; idx < STAGE_NWRAP; idx++) {
        stage_print_table(idx, &pool[idx], STAGE_NENTRY);
    }
    printf("TEMPLATE end\n");
    return 0;
}

static int run_stage(void *handle)
{
    Stage s;
    memset(&s, 0, sizeof s);
    s.do_alloc = need_sym(handle, "mw_alloc");
    s.do_free = need_sym(handle, "mw_free");
    s.do_index = need_sym(handle, "mw_index");
    s.do_table = need_sym(handle, "mw_table");
    s.do_set_version = need_sym(handle, "mw_set_version");
    s.do_poke = need_sym(handle, "mw_poke");
    s.gfl = need_sym(handle, "C_GetFunctionList");
    s.gil = need_sym(handle, "C_GetInterfaceList");
    s.gi = need_sym(handle, "C_GetInterface");
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("STAGE pid=%d\n", (int)getpid());
    char *line = NULL;
    size_t cap = 0;
    for (;;) {
        fflush(stdout);
        ssize_t len = getline(&line, &cap, stdin);
        if (len < 0) {
            break;
        }
        if (line[0] == 'X') {
            printf("BYE\n");
            free(line);
            return 0;
        }
        if (line[0] == 'P') {
            if (stage_publish(&s) != 0) {
                free(line);
                return EXIT_SCENARIO;
            }
            continue;
        }
        if (line[0] == 'T') {
            if (stage_templates(handle) != 0) {
                free(line);
                return EXIT_SCENARIO;
            }
            continue;
        }
        if (line[0] == 'B') {
            static const int back_ords[NEX] = { 0, 5, 13, 18, 43, 44 };
            for (int k = 0; k < NEX; k++) {
                char name[32];
                snprintf(name, sizeof name, "mw_backend_%d", back_ords[k]);
                dlerror();
                void *sym = dlsym(handle, name);
                if (dlerror() != NULL || sym == NULL) {
                    printf("ERROR backend %s missing\n", name);
                    free(line);
                    return EXIT_SCENARIO;
                }
                printf("BACKEND ord=%d addr=%p\n", back_ords[k], sym);
            }
            printf("BACKEND end\n");
            continue;
        }
        if (line[0] == 'A') {
            int fwd = 0;
            int fail = -1;
            if (sscanf(line + 1, "%d %d", &fwd, &fail) != 2) {
                printf("ERROR bad alloc\n");
                free(line);
                return EXIT_SCENARIO;
            }
            void *w = s.do_alloc(fwd, fail);
            if (w == NULL) {
                printf("ERROR alloc failed\n");
                free(line);
                return EXIT_SCENARIO;
            }
            int idx = s.do_index(w);
            s.handles[idx] = w;
            printf("ALLOC idx=%d table=%p\n", idx, s.do_table(w));
            continue;
        }
        if (line[0] == 'F') {
            int idx = -1;
            if (sscanf(line + 1, "%d", &idx) != 1 || idx < 0 || idx >= STAGE_NWRAP
                || s.handles[idx] == NULL) {
                printf("ERROR bad free\n");
                free(line);
                return EXIT_SCENARIO;
            }
            s.do_free(s.handles[idx]);
            s.handles[idx] = NULL;
            printf("FREED idx=%d\n", idx);
            continue;
        }
        if (line[0] == 'G') {
            char name[64];
            int major = -1;
            int minor = -1;
            int fields = sscanf(line + 1, "%63s %d %d", name, &major, &minor);
            if (fields != 1 && fields != 3) {
                printf("ERROR bad get-interface\n");
                free(line);
                return EXIT_SCENARIO;
            }
            if (fields == 3 && (major < 0 || major > 255 || minor < 0 || minor > 255)) {
                printf("ERROR bad get-interface version\n");
                free(line);
                return EXIT_SCENARIO;
            }
            CK_VERSION version;
            void *version_ptr = NULL;
            if (fields == 3) {
                version.major = (CK_BYTE)major;
                version.minor = (CK_BYTE)minor;
                version_ptr = &version;
            }
            void *want = strcmp(name, "-") == 0 ? NULL : name;
            void *found = NULL;
            CK_RV rv = s.gi(want, version_ptr, &found, 0);
            if (rv != CKR_OK || found == NULL) {
                printf("IFACE rv=%lu name=(none) table=(nil) flags=0\n", rv);
            } else {
                const CK_INTERFACE *iface = found;
                printf("IFACE rv=%lu name=%s table=%p flags=%lu\n", rv,
                    iface->pInterfaceName != NULL ? iface->pInterfaceName : "(null)",
                    iface->pFunctionList, iface->flags);
            }
            continue;
        }
        if (line[0] == 'V') {
            int idx = -1;
            int major = -1;
            int minor = -1;
            if (sscanf(line + 1, "%d %d %d", &idx, &major, &minor) != 3 || idx < 0
                || idx >= STAGE_NWRAP || s.handles[idx] == NULL || major < 0 || major > 255
                || minor < 0 || minor > 255) {
                printf("ERROR bad set-version\n");
                free(line);
                return EXIT_SCENARIO;
            }
            s.do_set_version(s.handles[idx], major, minor);
            printf("VERSION idx=%d major=%d minor=%d\n", idx, major, minor);
            continue;
        }
        if (line[0] == 'M') {
            int idx = -1;
            int ord = -1;
            int mode = -1;
            if (sscanf(line + 1, "%d %d %d", &idx, &ord, &mode) != 3 || idx < 0
                || idx >= STAGE_NWRAP || s.handles[idx] == NULL || ord < 0
                || ord >= STAGE_NENTRY || mode < 0 || mode > 3) {
                printf("ERROR bad poke\n");
                free(line);
                return EXIT_SCENARIO;
            }
            s.do_poke(s.handles[idx], ord, mode);
            printf("POKED idx=%d ord=%d mode=%d\n", idx, ord, mode);
            continue;
        }
        if (line[0] == 'C') {
            int idx = -1;
            int ord = -1;
            int n = -1;
            if (sscanf(line + 1, "%d %d %d", &idx, &ord, &n) != 3 || idx < 0
                || idx >= STAGE_NWRAP || s.handles[idx] == NULL || ord < 0
                || ord >= STAGE_NENTRY || n < 0) {
                printf("ERROR bad call\n");
                free(line);
                return EXIT_SCENARIO;
            }
            /* The driver calls through the published heap table (never the
             * templates), like every scenario: mw_table gives &bound. */
            Table *t = s.do_table(s.handles[idx]);
            EntryFn fn = t->funcs[ord];
            CK_RV rv = CKR_OK;
            for (int k = 0; k < n; k++) {
                rv = fn((CK_ULONG)idx, 0);
            }
            printf("CALLED idx=%d ord=%d n=%d rv=%lu\n", idx, ord, n, rv);
            continue;
        }
        printf("ERROR unknown command\n");
        free(line);
        return EXIT_SCENARIO;
    }
    free(line);
    return EXIT_SCENARIO;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: workload <provider.so> <scenario> <seed> <log> <oracle>\n");
        return EXIT_USAGE;
    }
    const char *provider_path = argv[1];
    const char *scenario = argv[2];
    unsigned long seed = strtoul(argv[3], NULL, 10);
    const char *log_path = argv[4];
    const char *oracle_path = argv[5];

    if (setenv("P11SCOPE_MW_LOG", log_path, 1) != 0) {
        fprintf(stderr, "workload: setenv failed\n");
        return EXIT_IO;
    }
    rng_state = seed ^ 0x9E3779B97F4A7C15ULL;
    if (rng_state == 0) {
        rng_state = 1;
    }

    void *handle = dlopen(provider_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "workload: dlopen failed: %s\n", dlerror());
        return EXIT_LOAD;
    }
    if (strcmp(scenario, "stage") == 0) {
        int rc = run_stage(handle);
        dlclose(handle);
        return rc;
    }
    alloc_fn do_alloc = need_sym(handle, "mw_alloc");
    free_fn do_free = need_sym(handle, "mw_free");
    index_fn do_index = need_sym(handle, "mw_index");
    table_fn do_table = need_sym(handle, "mw_table");
    occupied_fn do_occupied = need_sym(handle, "mw_occupied");
    int layout_known = dlsym(handle, "p11scope_fixed") != NULL;
    const char *variant = layout_known ? "normal" : "stripped";

    int pid = (int)getpid();
    int tid = (int)gettid();
    Expect e;
    expect_init(&e);
    WrapperInfo wrappers[64];
    size_t nw = 0;
    void *handles[64];
    size_t nh = 0;
    int free_list[64];
    int occ_list[64];
    size_t nfree = 0;
    size_t nocc = 0;
    int legacy_pub = 0;
    int legacy_major = 0;
    int legacy_minor = 0;
    long reused = -1;

    if (strcmp(scenario, "five") == 0) {
        for (int k = 0; k < 5; k++) {
            void *w = do_alloc(0, -1);
            if (w == NULL || do_index(w) != k) {
                fprintf(stderr, "workload: five: alloc %d failed\n", k);
                return EXIT_SCENARIO;
            }
            handles[nh++] = w;
            wrappers[nw++] = (WrapperInfo){ k, 0, -1 };
        }
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 4);
        for (size_t k = 0; k < nh; k++) {
            call_plan(&e, pid, tid, do_table(handles[k]), (int)k, 0, -1);
        }
    } else if (strcmp(scenario, "holes") == 0) {
        for (int k = 0; k < 18; k++) {
            void *w = do_alloc(0, -1);
            if (w == NULL || do_index(w) != k) {
                fprintf(stderr, "workload: holes: alloc %d failed\n", k);
                return EXIT_SCENARIO;
            }
            handles[nh++] = w;
        }
        for (int k = 0; k < 17; k++) {
            do_free(handles[k]);
        }
        wrappers[nw++] = (WrapperInfo){ 17, 0, -1 };
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 17);
        call_plan(&e, pid, tid, do_table(handles[17]), 17, 0, -1);
        do_free(handles[17]);
        nh = 0;
    } else if (strcmp(scenario, "reuse") == 0) {
        for (int k = 0; k < 18; k++) {
            void *w = do_alloc(0, -1);
            if (w == NULL || do_index(w) != k) {
                fprintf(stderr, "workload: reuse: alloc %d failed\n", k);
                return EXIT_SCENARIO;
            }
            handles[nh++] = w;
        }
        for (int k = 0; k < 17; k++) {
            do_free(handles[k]);
        }
        void *w = do_alloc(0, -1);
        if (w == NULL || do_index(w) != 0) {
            fprintf(stderr, "workload: reuse: expected index 0, got %d\n",
                w == NULL ? -2 : do_index(w));
            return EXIT_SCENARIO;
        }
        reused = 0;
        wrappers[nw++] = (WrapperInfo){ 17, 0, -1 };
        wrappers[nw++] = (WrapperInfo){ 0, 0, -1 };
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 17);
        call_plan(&e, pid, tid, do_table(handles[17]), 17, 0, -1);
        do_call(&e, pid, tid, do_table(w), 0, 0, 0, -1);
        do_free(w);
        do_free(handles[17]);
        nh = 0;
    } else if (strcmp(scenario, "pair_a") == 0) {
        for (int k = 0; k < 2; k++) {
            void *h = do_alloc(0, -1);
            if (h == NULL || do_index(h) != k) {
                fprintf(stderr, "workload: pair_a: alloc %d failed\n", k);
                return EXIT_SCENARIO;
            }
            handles[nh++] = h;
            wrappers[nw++] = (WrapperInfo){ k, 0, -1 };
        }
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 1);
        for (size_t k = 0; k < nh; k++) {
            call_plan(&e, pid, tid, do_table(handles[k]), (int)k, 0, -1);
        }
    } else if (strcmp(scenario, "pair_b") == 0) {
        for (int k = 0; k < 7; k++) {
            void *h = do_alloc(0, -1);
            if (h == NULL || do_index(h) != k) {
                fprintf(stderr, "workload: pair_b: alloc %d failed\n", k);
                return EXIT_SCENARIO;
            }
            handles[nh++] = h;
        }
        for (int k = 0; k < 5; k++) {
            do_free(handles[k]);
        }
        wrappers[nw++] = (WrapperInfo){ 5, 0, -1 };
        wrappers[nw++] = (WrapperInfo){ 6, 0, -1 };
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 6);
        call_plan(&e, pid, tid, do_table(handles[5]), 5, 0, -1);
        call_plan(&e, pid, tid, do_table(handles[6]), 6, 0, -1);
        do_free(handles[5]);
        do_free(handles[6]);
        nh = 0;
    } else if (strcmp(scenario, "forward") == 0) {
        const int mask = (1 << 1) | (1 << 4); /* ordinals 5 and 43 */
        void *h = do_alloc(mask, -1);
        if (h == NULL || do_index(h) != 0) {
            fprintf(stderr, "workload: forward: alloc failed\n");
            return EXIT_SCENARIO;
        }
        handles[nh++] = h;
        wrappers[nw++] = (WrapperInfo){ 0, mask, -1 };
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 0);
        call_plan(&e, pid, tid, do_table(h), 0, mask, -1);
    } else if (strcmp(scenario, "fail") == 0) {
        void *h = do_alloc(0, 43);
        if (h == NULL || do_index(h) != 0) {
            fprintf(stderr, "workload: fail: alloc failed\n");
            return EXIT_SCENARIO;
        }
        handles[nh++] = h;
        wrappers[nw++] = (WrapperInfo){ 0, 0, 43 };
        snapshot_occupancy(do_occupied, free_list, &nfree, occ_list, &nocc, 0, 0);
        call_plan(&e, pid, tid, do_table(h), 0, 0, 43);
    } else if (strcmp(scenario, "legacy") == 0) {
        gfl_fn gfl = need_sym(handle, "C_GetFunctionList");
        gil_fn gil = need_sym(handle, "C_GetInterfaceList");
        void *list = NULL;
        CK_ULONG count = 0;
        if (gfl(&list) != CKR_OK || list == NULL) {
            fprintf(stderr, "workload: legacy: C_GetFunctionList failed\n");
            return EXIT_SCENARIO;
        }
        if (gil(NULL, &count) != CKR_OK || count < 1) {
            fprintf(stderr, "workload: legacy: interface list failed\n");
            return EXIT_SCENARIO;
        }
        legacy_pub = 1;
        legacy_major = ((const Table *)list)->version.major;
        legacy_minor = ((const Table *)list)->version.minor;
    } else {
        fprintf(stderr, "workload: unknown scenario %s\n", scenario);
        return EXIT_USAGE;
    }

    for (size_t k = 0; k < nh; k++) {
        do_free(handles[k]);
    }
    write_oracle(oracle_path, scenario, seed, variant, layout_known, pid, wrappers, nw,
        free_list, nfree, occ_list, nocc, legacy_pub, legacy_major, legacy_minor, reused, &e);
    return 0;
}
