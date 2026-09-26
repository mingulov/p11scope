/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private T2 workload. Observer transition times are deliberately absent. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct function_table {
    unsigned char major, minor;
    void *functions[68];
};
struct body_observation { uint64_t count, mono_ns; };
_Static_assert(sizeof(void *) == 8, "the initial T2 fixture is LP64");
_Static_assert(offsetof(struct function_table, functions) == 8, "table ABI");

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) {
        perror("clock_gettime");
        exit(90);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

#ifdef T2_PROVIDER

static struct body_observation body;
unsigned long C_Initialize(void *unused) {
    (void)unused;
    body.count++;
    body.mono_ns = now_ns();
    return 0;
}
unsigned long C_GetFunctionList(void **out);

/* Distinct endpoints: the fixture must not accidentally test API aliasing. */
#define ENDPOINTS(X) \
    X(1) X(2) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) \
    X(14) X(15) X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24) \
    X(25) X(26) X(27) X(28) X(29) X(30) X(31) X(32) X(33) X(34) X(35) \
    X(36) X(37) X(38) X(39) X(40) X(41) X(42) X(43) X(44) X(45) X(46) \
    X(47) X(48) X(49) X(50) X(51) X(52) X(53) X(54) X(55) X(56) X(57) \
    X(58) X(59) X(60) X(61) X(62) X(63) X(64) X(65) X(66) X(67)
#define DECLARE(n) static unsigned long endpoint_##n(void *unused) { \
    (void)unused; return 0x54UL; /* CKR_FUNCTION_NOT_SUPPORTED */ }
ENDPOINTS(DECLARE)
#undef DECLARE

#ifdef T2_HEAP_TABLE
static struct function_table *table;
int t2_table_present(void) { return table != NULL; }
__attribute__((destructor)) static void release_table(void) { free(table); }
#else
#define ENTRY(n) [n] = (void *)endpoint_##n,
static struct function_table stored = {2, 40, {
    [0] = (void *)C_Initialize, [3] = (void *)C_GetFunctionList,
    ENDPOINTS(ENTRY)
}};
#undef ENTRY
static struct function_table *table = &stored;
int t2_table_present(void) { return 1; }
#endif

unsigned long C_GetFunctionList(void **out) {
    if (!out) return 7;
#ifdef T2_HEAP_TABLE
    if (!table) {
        table = calloc(1, sizeof(*table));
        if (!table) return 2;
        table->major = 2;
        table->minor = 40;
        /* Individual assignments avoid a file-backed complete template. */
        table->functions[0] = (void *)C_Initialize;
        table->functions[3] = (void *)C_GetFunctionList;
#define ASSIGN(n) table->functions[n] = (void *)endpoint_##n;
        ENDPOINTS(ASSIGN)
#undef ASSIGN
    }
#endif
#ifdef T2_BAD_TABLE
    table->functions[67] = NULL;
#endif
    *out = table;
    return 0;
}

const struct body_observation *t2_body_observation(void) { return &body; }

#else

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static FILE *ledger;
static struct stat module_identity, namespace_identity;
static uint64_t birth;

static uint64_t process_birth(void) {
    FILE *stream = fopen("/proc/self/stat", "r");
    if (!stream) return 0;
    char line[4096];
    if (!fgets(line, sizeof line, stream)) { fclose(stream); return 0; }
    fclose(stream);
    char *tail = strrchr(line, ')');
    if (!tail) return 0;
    char *save = NULL;
    char *field = strtok_r(tail + 1, " ", &save);
    for (int index = 3; field && index < 22; index++)
        field = strtok_r(NULL, " ", &save);
    return field ? strtoull(field, NULL, 10) : 0;
}

static int emit(const char *phase, uint64_t when, const char *extra) {
    if (fprintf(ledger, "{\"phase\":\"%s\",\"mono_ns\":%" PRIu64
                ",\"pid\":%ld,\"birth\":%" PRIu64
                ",\"module_dev\":%ju,\"module_ino\":%ju,\"mount_ns_ino\":%ju%s}\n",
                phase, when, (long)getpid(), birth,
                (uintmax_t)module_identity.st_dev, (uintmax_t)module_identity.st_ino,
                (uintmax_t)namespace_identity.st_ino, extra) < 0 || fflush(ledger)) {
        perror("ledger write");
        return 1;
    }
    return 0;
}

static int wait_gate(const char *path) {
    if (!strcmp(path, "-")) return 0;
    uint64_t deadline = now_ns() + UINT64_C(120000000000);
    while (access(path, F_OK)) {
        if (errno != ENOENT || now_ns() >= deadline) {
            fprintf(stderr, "first-use gate unavailable or timed out\n");
            return 1;
        }
        struct timespec delay = {0, 1000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s provider.so ledger.jsonl publication-gate|- entry-gate|-\n", argv[0]);
        return 2;
    }
    birth = process_birth();
    if (!birth || stat(argv[1], &module_identity) ||
        stat("/proc/self/ns/mnt", &namespace_identity)) return 3;
    ledger = fopen(argv[2], "wx");
    if (!ledger) { perror("ledger open"); return 4; }
    int status = 1;
    void *handle = NULL;
    if (emit("object_stat", now_ns(), "")) goto done;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); goto done; }
    unsigned long (*publish)(void **) = dlsym(handle, "C_GetFunctionList");
    int (*present)(void) = dlsym(handle, "t2_table_present");
    const struct body_observation *(*observation)(void) =
        dlsym(handle, "t2_body_observation");
    if (!publish || !present || !observation) goto done;
    if (emit("mapped", now_ns(), present() ? ",\"table_present\":true" :
                                           ",\"table_present\":false")) goto done;
    if (wait_gate(argv[3])) goto done;
    void *pointer = NULL;
    unsigned long publication_rv = publish(&pointer);
    if (emit("publication_returned", now_ns(), "")) goto done;
    struct function_table *table = pointer;
    if (publication_rv || !table || table->major != 2 || table->minor != 40)
        goto invalid_table;
    for (size_t i = 0; i < 68; i++) {
        if (!table->functions[i]) goto invalid_table;
        for (size_t j = 0; j < i; j++)
            if (table->functions[i] == table->functions[j]) goto invalid_table;
    }
    Dl_info location;
    const char *storage = dladdr(table, &location) ? "file" : "heap";
    char extra[256];
    int size = snprintf(extra, sizeof extra,
        ",\"entries\":68,\"table_storage\":\"%s\",\"entry_address\":%" PRIuPTR,
        storage, (uintptr_t)table->functions[0]);
    if (size < 0 || (size_t)size >= sizeof extra ||
        emit("table_verified", now_ns(), extra) || wait_gate(argv[4])) goto done;
    unsigned long (*initialize)(void *) = (void *)table->functions[0];
    unsigned long rv = initialize(NULL);
    uint64_t returned = now_ns();
    struct body_observation body = *observation();
    if (rv || body.count != 1 || !body.mono_ns || body.mono_ns > returned) goto done;
    if (emit("entry_executed", body.mono_ns, ",\"body_count\":1") ||
        emit("entry_returned", returned, ",\"rv\":0")) goto done;
    if (dlclose(handle)) { handle = NULL; goto done; }
    handle = NULL;
    if (emit("unloaded", now_ns(), "")) goto done;
    status = 0;
    goto done;
invalid_table:
    fprintf(stderr, "invalid table: require version 2.40 and 68 distinct entries\n");
done:
    if (handle) dlclose(handle);
    if (fclose(ledger)) status = 1;
    return status;
}
#endif
