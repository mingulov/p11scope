/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Late-provider-B fixture with a physical cut: two distinct provider files,
 * real PKCS#11 v2.40 calls, one feed-labeled ledger.
 *
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror late-b.c -ldl -o late-b
 *   late-b PROVIDER_A PROVIDER_B COUNT LEDGER [GO_FILE]
 *     COUNT  1..10000 burst iterations per phase
 *
 * PROVIDER_A and PROVIDER_B are distinct files (see mk-providers.sh beside
 * this file, which copies the system SoftHSM module twice and initializes
 * the P11SCOPE-A and P11SCOPE-B tokens in one store). SOFTHSM2_CONF selects
 * the store. The driver loads A with dlopen (distinct files need no new
 * namespaces), initializes, locates the P11SCOPE-A token, prints
 * "READY pid=<pid>", then, when GO_FILE is given, waits for that path
 * before emitting the ledger; SIGTERM/SIGINT interrupts the wait. After
 * the gate it runs the A burst, late-loads B, runs the B burst, cuts B
 * (finalize, dlclose, then a trailing-bytes change of the B file so the
 * object identity changes), records the cut marker, reloads B, runs the
 * post-cut B burst, and writes the ack row.
 *
 * Each burst iteration ledgers six real calls: two C_GetSlotList steps,
 * C_GetTokenInfo, C_OpenSession (public read-only), C_GetSessionInfo and
 * C_CloseSession. Setup calls (Initialize, token discovery, Finalize) are
 * not ledgered. The ledger carries feed labels ("A"/"B"), a global
 * contiguous seq, two ready rows (B stamped at its late load), and one cut
 * row naming the last pre-cut B seq. Exit 0 when every ledgered call
 * returned CKR_OK, 1 when the ledger is complete but some call did not, 2
 * on usage/setup/refusal failure. Providers whose function-list major
 * version is not 2 are refused: this driver calls the v2.40 prefix with
 * exact signatures, and a foreign table layout would be undefined
 * behaviour. Info outputs land in oversized buffers (the label sits at
 * offset 0), so no cryptoki struct packing is assumed.
 *
 * When GO-gated, the driver holds both mappings until SIGTERM/SIGINT
 * after the ledger is complete, so repeated observer rescans observe
 * identical state; no second burst runs. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_COUNT 10000
#define TOKEN_INFO_BYTES 512
#define SESSION_INFO_BYTES 128
#define LABEL_BYTES 32
#define CUT_TRAILER_BYTES 4096
#define SERIAL_SESSION 0x4UL
#define ALREADY_INITIALIZED 0x191UL

#define TOKEN_A "P11SCOPE-A"
#define TOKEN_B "P11SCOPE-B"

typedef unsigned long ck_rv;
typedef unsigned long ck_ulong;
typedef unsigned char ck_bool;

typedef ck_rv (*fn_initialize)(void *);
typedef ck_rv (*fn_finalize)(void *);
typedef ck_rv (*fn_get_slot_list)(ck_bool, ck_ulong *, ck_ulong *);
typedef ck_rv (*fn_get_token_info)(ck_ulong, void *);
typedef ck_rv (*fn_open_session)(ck_ulong, ck_ulong, void *, void *, ck_ulong *);
typedef ck_rv (*fn_get_session_info)(ck_ulong, void *);
typedef ck_rv (*fn_close_session)(ck_ulong);
typedef ck_rv (*fn_get_function_list)(void **);

/* The canonical v2.40 prefix through C_GetSessionInfo; entries this driver
 * never calls are order-keeping placeholders. */
typedef struct {
    unsigned char major, minor;
    fn_initialize initialize;
    fn_finalize finalize;
    void *get_info;
    void *get_function_list;
    fn_get_slot_list get_slot_list;
    void *get_slot_info;
    fn_get_token_info get_token_info;
    void *get_mechanism_list;
    void *get_mechanism_info;
    void *init_token;
    void *init_pin;
    void *set_pin;
    fn_open_session open_session;
    fn_close_session close_session;
    void *close_all_sessions;
    fn_get_session_info get_session_info;
} FunctionList;

_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long) == 8, "LP64 only");
_Static_assert(offsetof(FunctionList, initialize) == 8, "v2.40 order");
_Static_assert(offsetof(FunctionList, get_slot_list) == 40, "v2.40 order");
_Static_assert(offsetof(FunctionList, get_token_info) == 56, "v2.40 order");
_Static_assert(offsetof(FunctionList, open_session) == 104, "v2.40 order");
_Static_assert(offsetof(FunctionList, get_session_info) == 128, "v2.40 order");

static volatile sig_atomic_t stop;

static void on_signal(int number) {
    (void)number;
    stop = 1;
}

static int clock_ns(uint64_t *out) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *out = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 0;
}

static int wait_for_go(const char *path) {
    while (access(path, F_OK) != 0 && !stop) {
        if (errno != ENOENT) {
            return -1;
        }
        usleep(10000);
    }
    return stop ? 1 : 0;
}

static int parse_count(const char *text, unsigned long *out) {
    if (text[0] == '\0') {
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value == 0 || value > MAX_COUNT) {
        return -1;
    }
    *out = value;
    return 0;
}

struct provider {
    const char *feed;
    void *handle;
    FunctionList *list;
    int initialized;
    ck_ulong slot;
};

static int match_label(const unsigned char *info, const char *want) {
    size_t length = strlen(want);
    if (length == 0 || length > LABEL_BYTES) {
        return 0;
    }
    if (memcmp(info, want, length) != 0) {
        return 0;
    }
    for (size_t i = length; i < LABEL_BYTES; i++) {
        if (info[i] != ' ') {
            return 0;
        }
    }
    return 1;
}

static int find_token_slot(FunctionList *list, const char *label, ck_ulong *slot) {
    ck_ulong count = 0;
    if (list->get_slot_list(0, NULL, &count) != 0 || count == 0) {
        return -1;
    }
    ck_ulong *slots = malloc(count * sizeof *slots);
    if (slots == NULL) {
        return -1;
    }
    int found = -1;
    if (list->get_slot_list(0, slots, &count) == 0) {
        unsigned char info[TOKEN_INFO_BYTES];
        for (ck_ulong i = 0; i < count; i++) {
            memset(info, 0, sizeof info);
            if (list->get_token_info(slots[i], info) == 0 &&
                match_label(info, label)) {
                *slot = slots[i];
                found = 0;
                break;
            }
        }
    }
    free(slots);
    return found;
}

static int load_provider(const char *path, const char *feed, const char *label,
                         struct provider *out) {
    out->feed = feed;
    out->handle = NULL;
    out->list = NULL;
    out->initialized = 0;
    out->slot = 0;
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "late-b: cannot open %s: %s\n", feed, dlerror());
        return -1;
    }
    fn_get_function_list get_list =
        (fn_get_function_list)dlsym(handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "late-b: C_GetFunctionList failed for %s\n", feed);
        dlclose(handle);
        return -1;
    }
    FunctionList *list = raw;
    if (list->major != 2) {
        fprintf(stderr, "late-b: refuses %s: function-list major %u is not v2\n",
                feed, list->major);
        dlclose(handle);
        return -1;
    }
    if (list->initialize == NULL || list->finalize == NULL ||
        list->get_slot_list == NULL || list->get_token_info == NULL ||
        list->open_session == NULL || list->close_session == NULL ||
        list->get_session_info == NULL) {
        fprintf(stderr, "late-b: %s lacks a required v2.40 entry\n", feed);
        dlclose(handle);
        return -1;
    }
    ck_rv init = list->initialize(NULL);
    if (init != 0 && init != ALREADY_INITIALIZED) {
        fprintf(stderr, "late-b: C_Initialize failed for %s: rv %lu\n",
                feed, init);
        dlclose(handle);
        return -1;
    }
    if (find_token_slot(list, label, &out->slot) != 0) {
        fprintf(stderr, "late-b: token %s not found for %s\n", label, feed);
        if (init == 0) {
            list->finalize(NULL);
        }
        dlclose(handle);
        return -1;
    }
    out->handle = handle;
    out->list = list;
    out->initialized = init == 0;
    return 0;
}

static void unload_provider(struct provider *provider) {
    if (provider->handle == NULL) {
        return;
    }
    if (provider->initialized) {
        provider->list->finalize(NULL);
        provider->initialized = 0;
    }
    dlclose(provider->handle);
    provider->handle = NULL;
    provider->list = NULL;
}

struct ledger {
    FILE *file;
    int pid;
    int tid;
    unsigned long seq;
    unsigned long unhealthy;
    int failed;
};

static void ledger_call(struct ledger *ledger, const char *feed, const char *fn,
                        ck_rv rv, uint64_t t0, uint64_t t1) {
    if (ledger->failed) {
        return;
    }
    if (rv != 0) {
        ledger->unhealthy++;
    }
    ledger->seq++;
    if (fprintf(ledger->file,
                "{\"kind\":\"call\",\"seq\":%lu,\"feed\":\"%s\",\"fn\":\"%s\","
                "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                ",\"t1\":%" PRIu64 "}\n",
                ledger->seq, feed, fn, rv, ledger->pid, ledger->tid,
                t0, t1) < 0) {
        ledger->failed = 1;
    }
}

/* One burst iteration: six real ledgered calls. A failed OpenSession ends
 * the iteration early (no handle exists for the session calls); only calls
 * actually made are ledgered. */
static void burst_iteration(struct provider *provider, struct ledger *ledger) {
    FunctionList *list = provider->list;
    uint64_t t0 = 0, t1 = 0;
    ck_ulong count = 0;
    if (clock_ns(&t0) != 0) {
        ledger->failed = 1;
        return;
    }
    ck_rv rv = list->get_slot_list(0, NULL, &count);
    if (clock_ns(&t1) != 0) {
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_GetSlotList", rv, t0, t1);
    if (rv != 0 || ledger->failed) {
        return;
    }
    ck_ulong *slots = malloc(count > 0 ? count * sizeof *slots : 1);
    if (slots == NULL) {
        ledger->failed = 1;
        return;
    }
    ck_ulong fill = count;
    if (clock_ns(&t0) != 0) {
        free(slots);
        ledger->failed = 1;
        return;
    }
    rv = list->get_slot_list(0, slots, &fill);
    if (clock_ns(&t1) != 0) {
        free(slots);
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_GetSlotList", rv, t0, t1);
    free(slots);
    if (rv != 0 || ledger->failed) {
        return;
    }
    unsigned char token[TOKEN_INFO_BYTES];
    memset(token, 0, sizeof token);
    if (clock_ns(&t0) != 0) {
        ledger->failed = 1;
        return;
    }
    rv = list->get_token_info(provider->slot, token);
    if (clock_ns(&t1) != 0) {
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_GetTokenInfo", rv, t0, t1);
    if (rv != 0 || ledger->failed) {
        return;
    }
    ck_ulong session = 0;
    if (clock_ns(&t0) != 0) {
        ledger->failed = 1;
        return;
    }
    rv = list->open_session(provider->slot, SERIAL_SESSION, NULL, NULL, &session);
    if (clock_ns(&t1) != 0) {
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_OpenSession", rv, t0, t1);
    if (rv != 0 || ledger->failed) {
        return;
    }
    unsigned char info[SESSION_INFO_BYTES];
    memset(info, 0, sizeof info);
    if (clock_ns(&t0) != 0) {
        ledger->failed = 1;
        return;
    }
    rv = list->get_session_info(session, info);
    if (clock_ns(&t1) != 0) {
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_GetSessionInfo", rv, t0, t1);
    if (rv != 0 || ledger->failed) {
        list->close_session(session);
        return;
    }
    if (clock_ns(&t0) != 0) {
        ledger->failed = 1;
        list->close_session(session);
        return;
    }
    rv = list->close_session(session);
    if (clock_ns(&t1) != 0) {
        ledger->failed = 1;
        return;
    }
    ledger_call(ledger, provider->feed, "C_CloseSession", rv, t0, t1);
}

static void run_burst(struct provider *provider, struct ledger *ledger,
                      unsigned long count) {
    for (unsigned long i = 0; i < count && !ledger->failed; i++) {
        burst_iteration(provider, ledger);
    }
}

static int emit_ready(struct ledger *ledger, const char *feed, uint64_t *stamp) {
    if (clock_ns(stamp) != 0) {
        ledger->failed = 1;
        return -1;
    }
    if (fprintf(ledger->file,
                "{\"kind\":\"ready\",\"feed\":\"%s\",\"pid\":%d,\"tid\":%d,"
                "\"t\":%" PRIu64 ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                feed, ledger->pid, ledger->tid, *stamp) < 0) {
        ledger->failed = 1;
        return -1;
    }
    return 0;
}

static int cut_provider_file(const char *path) {
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        fprintf(stderr, "late-b: cannot open %s for the cut: %s\n",
                path, strerror(errno));
        return -1;
    }
    static const unsigned char trailer[CUT_TRAILER_BYTES] = {0};
    size_t written = 0;
    while (written < sizeof trailer) {
        ssize_t chunk =
            write(fd, trailer + written, sizeof trailer - written);
        if (chunk <= 0) {
            fprintf(stderr, "late-b: cut write failed: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        written += (size_t)chunk;
    }
    if (close(fd) != 0) {
        fprintf(stderr, "late-b: cut close failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s PROVIDER_A PROVIDER_B COUNT LEDGER [GO_FILE]\n",
                argc > 0 ? argv[0] : "late-b");
        return 2;
    }
    unsigned long count = 0;
    if (parse_count(argv[3], &count) != 0) {
        fprintf(stderr, "late-b: COUNT must be 1..%d\n", MAX_COUNT);
        return 2;
    }
    if (access(argv[1], R_OK) != 0 || access(argv[2], R_OK) != 0) {
        fprintf(stderr, "late-b: provider file unreadable\n");
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    struct provider prov_a = {0}, prov_b = {0};
    if (load_provider(argv[1], "A", TOKEN_A, &prov_a) != 0) {
        return 2;
    }
    if (printf("READY pid=%d\n", (int)getpid()) < 0 || fflush(stdout)) {
        unload_provider(&prov_a);
        return 2;
    }
    if (argc == 6 && wait_for_go(argv[5]) != 0) {
        if (stop) {
            fprintf(stderr, "late-b: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "late-b: cannot wait for gate\n");
        }
        unload_provider(&prov_a);
        return 2;
    }
    FILE *file = fopen(argv[4], "w");
    if (file == NULL) {
        fprintf(stderr, "late-b: cannot open ledger: %s\n", strerror(errno));
        unload_provider(&prov_a);
        return 2;
    }
    struct ledger ledger = {
        .file = file, .pid = (int)getpid(), .tid = (int)gettid(),
        .seq = 0, .unhealthy = 0, .failed = 0,
    };
    uint64_t ready_a = 0, ready_b = 0;
    if (emit_ready(&ledger, "A", &ready_a) != 0) {
        fclose(file);
        unload_provider(&prov_a);
        return 2;
    }
    run_burst(&prov_a, &ledger, count);
    if (!ledger.failed && load_provider(argv[2], "B", TOKEN_B, &prov_b) != 0) {
        ledger.failed = 1;
    }
    if (!ledger.failed && emit_ready(&ledger, "B", &ready_b) != 0) {
        ledger.failed = 1;
    }
    run_burst(&prov_b, &ledger, count);
    unsigned long pre_cut_seq = ledger.seq;
    uint64_t cut_t = 0;
    if (!ledger.failed) {
        unload_provider(&prov_b);
        if (cut_provider_file(argv[2]) != 0 || clock_ns(&cut_t) != 0) {
            ledger.failed = 1;
        }
    }
    if (!ledger.failed && fprintf(file,
                                  "{\"kind\":\"cut\",\"feed\":\"B\","
                                  "\"at_seq\":%lu,\"t\":%" PRIu64 "}\n",
                                  pre_cut_seq, cut_t) < 0) {
        ledger.failed = 1;
    }
    if (!ledger.failed && load_provider(argv[2], "B", TOKEN_B, &prov_b) != 0) {
        ledger.failed = 1;
    }
    run_burst(&prov_b, &ledger, count);
    uint64_t done = 0;
    if (!ledger.failed && clock_ns(&done) != 0) {
        ledger.failed = 1;
    }
    if (!ledger.failed && fprintf(file, "{\"kind\":\"ack\",\"issued\":%lu,\"t\":%" PRIu64 "}\n",
                                  ledger.seq, done) < 0) {
        ledger.failed = 1;
    }
    if (fclose(file) != 0) {
        ledger.failed = 1;
    }
    int gated = argc == 6;
    if (gated && !ledger.failed) {
        while (!stop) {
            pause();
        }
    }
    unload_provider(&prov_b);
    unload_provider(&prov_a);
    if (ledger.failed) {
        fprintf(stderr, "late-b: ledger emission failed\n");
        return 2;
    }
    return ledger.unhealthy == 0 ? 0 : 1;
}
