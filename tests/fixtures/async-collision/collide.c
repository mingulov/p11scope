/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Async-collision two-process ledger emitter (E17 pattern).
 *
 * Usage: collide PROVIDER MODE OPS LEDGER_A LEDGER_B [GO_FILE]
 *
 * MODE is one of:
 *   poll_msg   A owns each async id through the poll mechanism
 *              (begin, pending polls, terminal; op 1 also takes a
 *              non-consuming status query) while B challenges the same
 *              ids through the message mechanism (begin, too-small
 *              wait, terminal wait).
 *   cancel     A polls to completion while B cancels: op 1 fails its
 *              begin (no operation), ops 2..OPS begin, observe one
 *              pending poll, then cancel; then B calls the finalize
 *              entry (a fence row follows) and drives one post-fence
 *              op that the observer must gap, never complete.
 *   persisted  A owns through the persisted mechanism (begin, pending
 *              polls interleaved with status queries, terminal, then
 *              a post-terminal status query proving the result stays
 *              observable without completing twice) while B challenges
 *              through the message mechanism with unestablished
 *              metadata (null).
 *
 * The parent validates the provider, prints "READY pid=<pid>", waits
 * for GO_FILE when given, then forks the two children. Each child
 * opens the provider itself (same file, independent instance, so both
 * observe async ids 1, 2, ... for ops 1, 2, ...), prints one TARGET
 * line resolving the begin entry through its own /proc/self/maps
 * (independent physical-target evidence in the pressure-live shape),
 * and writes its own ledger: ready, one scenario row (process, role,
 * mechanism, slot, target, metadata, session, instance, object), then
 * sequenced call/fence rows, then ack. SIGTERM/SIGINT interrupts the
 * GO wait and the parent's reap loop (remaining children are asked to
 * stop); exit is 2 on usage/setup/refusal/interruption, else 1 when a
 * child completed its ledger with an unexpected return value, else 0.
 * The provider must export P11ScopeSlot68 (stub family) and
 * P11ScopeAsyncCaps (async capability); anything else is refused
 * before READY with no ledger. Builds LP64 and ILP32.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TABLE_SLOTS 104
#define MAX_OPS 64

#define CKR_OK 0ul
#define CKR_ARGUMENTS_BAD 7ul
#define CKR_BUFFER_TOO_SMALL 0x150ul
#define CKR_PENDING 0x204ul

/* Keep in sync with collide-provider.c. */
typedef struct {
    uint64_t async_id;
    uint64_t size;
} AsyncArg;

/* Keep in sync with collide-provider.c. */
typedef struct {
    uint32_t begin;
    uint32_t poll;
    uint32_t status;
    uint32_t wait;
    uint32_t cancel;
    uint32_t begin_fail;
    uint32_t finalize_op;
    uint32_t polls_to_complete;
    uint32_t wait_min_size;
} AsyncCaps;

typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} ProviderTable;

typedef unsigned long (*AsyncEntry)(void *);
typedef unsigned long (*GetFunctionList)(void **);

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

static int parse_number(const char *text, unsigned long bound, unsigned long *out) {
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
    if (errno != 0 || *end != '\0' || value > bound) {
        return -1;
    }
    *out = value;
    return 0;
}

static int emit_target(const char *name, void *address) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return 1;
    }
    char line[4096];
    char perms[5];
    unsigned long low, high, offset, inode;
    unsigned int major, minor;
    uintptr_t want = (uintptr_t)address;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &low, &high, perms, &offset,
                   &major, &minor, &inode) == 7 &&
            want >= low && want < high && perms[2] == 'x' && inode) {
            printf("TARGET {\"name\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,"
                   "\"file_offset\":%lu}\n",
                   name, major, minor, inode, (unsigned long)(want - low) + offset);
            fflush(stdout);
            fclose(maps);
            return 0;
        }
    }
    fclose(maps);
    return 1;
}

typedef struct {
    AsyncEntry begin;
    AsyncEntry poll;
    AsyncEntry status;
    AsyncEntry wait;
    AsyncEntry cancel;
    AsyncEntry begin_fail;
    AsyncEntry finalize_op;
} BoundEntries;

static int bind_entries(void *handle, BoundEntries *out, void **begin_address) {
    GetFunctionList get_list = (GetFunctionList)dlsym(handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "collide: C_GetFunctionList failed\n");
        return -1;
    }
    if (dlsym(handle, "P11ScopeSlot68") == NULL) {
        fprintf(stderr, "collide: refuses non-stub provider (stub-only fixture)\n");
        return -1;
    }
    AsyncCaps *caps = dlsym(handle, "P11ScopeAsyncCaps");
    if (caps == NULL) {
        fprintf(stderr, "collide: refuses provider without async capability\n");
        return -1;
    }
    uint32_t wanted[7] = {caps->begin,   caps->poll,        caps->status, caps->wait,
                          caps->cancel, caps->begin_fail, caps->finalize_op};
    ProviderTable *table = raw;
    for (int i = 0; i < 7; i++) {
        if (wanted[i] >= TABLE_SLOTS || table->functions[wanted[i]] == NULL) {
            fprintf(stderr, "collide: async entry %u is missing\n", wanted[i]);
            return -1;
        }
    }
    out->begin = (AsyncEntry)table->functions[caps->begin];
    out->poll = (AsyncEntry)table->functions[caps->poll];
    out->status = (AsyncEntry)table->functions[caps->status];
    out->wait = (AsyncEntry)table->functions[caps->wait];
    out->cancel = (AsyncEntry)table->functions[caps->cancel];
    out->begin_fail = (AsyncEntry)table->functions[caps->begin_fail];
    out->finalize_op = (AsyncEntry)table->functions[caps->finalize_op];
    if (begin_address != NULL) {
        *begin_address = table->functions[caps->begin];
    }
    return 0;
}

typedef struct {
    FILE *ledger;
    const char *process;
    int pid;
    int tid;
    unsigned long seq;
    unsigned long calls;
    unsigned long unhealthy;
    int failed;
} ChildOut;

static void emit_call(ChildOut *out, AsyncEntry entry, const char *fn, const char *phase,
                      unsigned long op, AsyncArg *arg, unsigned long expected) {
    if (out->failed) {
        return;
    }
    uint64_t t0 = 0, t1 = 0;
    if (clock_ns(&t0) != 0) {
        out->failed = 1;
        return;
    }
    unsigned long rv = entry(arg);
    if (clock_ns(&t1) != 0) {
        out->failed = 1;
        return;
    }
    if (rv != expected) {
        out->unhealthy++;
    }
    out->seq++;
    out->calls++;
    if (fprintf(out->ledger,
                "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"%s\",\"rv\":%lu,"
                "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64
                ",\"process\":\"%s\",\"op\":%lu,\"phase\":\"%s\",\"async_id\":%" PRIu64
                "}\n",
                out->seq, fn, rv, out->pid, out->tid, t0, t1, out->process, op, phase,
                arg->async_id) < 0) {
        out->failed = 1;
    }
}

static void emit_fence(ChildOut *out, const char *fence) {
    if (out->failed) {
        return;
    }
    uint64_t now = 0;
    if (clock_ns(&now) != 0) {
        out->failed = 1;
        return;
    }
    out->seq++;
    if (fprintf(out->ledger, "{\"kind\":\"fence\",\"seq\":%lu,\"fence\":\"%s\",\"t\":%" PRIu64 "}\n",
                out->seq, fence, now) < 0) {
        out->failed = 1;
    }
}

static void script_poll_owner(ChildOut *out, BoundEntries *entries, unsigned long ops) {
    for (unsigned long op = 1; op <= ops; op++) {
        AsyncArg arg = {0, 0};
        emit_call(out, entries->begin, "async_begin", "begin", op, &arg, CKR_OK);
        emit_call(out, entries->poll, "async_poll", "pending", op, &arg, CKR_PENDING);
        if (op == 1) {
            emit_call(out, entries->status, "async_status", "query", op, &arg, CKR_PENDING);
        }
        emit_call(out, entries->poll, "async_poll", "pending", op, &arg, CKR_PENDING);
        emit_call(out, entries->poll, "async_poll", "terminal", op, &arg, CKR_OK);
    }
}

static void script_message_challenger(ChildOut *out, BoundEntries *entries, unsigned long ops) {
    for (unsigned long op = 1; op <= ops; op++) {
        AsyncArg arg = {0, 0};
        emit_call(out, entries->begin, "async_begin", "begin", op, &arg, CKR_OK);
        arg.size = 0;
        emit_call(out, entries->wait, "async_wait", "too_small", op, &arg,
                  CKR_BUFFER_TOO_SMALL);
        arg.size = 128;
        emit_call(out, entries->wait, "async_wait", "terminal", op, &arg, CKR_OK);
    }
}

static void script_cancel_challenger(ChildOut *out, BoundEntries *entries, unsigned long ops) {
    AsyncArg probe = {0, 0};
    emit_call(out, entries->begin_fail, "async_begin_fail", "begin", 1, &probe,
              CKR_ARGUMENTS_BAD);
    for (unsigned long op = 2; op <= ops; op++) {
        AsyncArg arg = {0, 0};
        emit_call(out, entries->begin, "async_begin", "begin", op, &arg, CKR_OK);
        emit_call(out, entries->poll, "async_poll", "pending", op, &arg, CKR_PENDING);
        emit_call(out, entries->cancel, "async_cancel", "cancel", op, &arg, CKR_OK);
    }
    AsyncArg teardown = {0, 0};
    emit_call(out, entries->finalize_op, "async_finalize", "teardown", 0, &teardown, CKR_OK);
    emit_fence(out, "finalize");
    AsyncArg late = {0, 0};
    emit_call(out, entries->begin, "async_begin", "begin", ops + 1, &late, CKR_OK);
    emit_call(out, entries->poll, "async_poll", "pending", ops + 1, &late, CKR_PENDING);
    emit_call(out, entries->poll, "async_poll", "pending", ops + 1, &late, CKR_PENDING);
    emit_call(out, entries->poll, "async_poll", "terminal", ops + 1, &late, CKR_OK);
}

static void script_persisted_owner(ChildOut *out, BoundEntries *entries, unsigned long ops) {
    for (unsigned long op = 1; op <= ops; op++) {
        AsyncArg arg = {0, 0};
        emit_call(out, entries->begin, "async_begin", "begin", op, &arg, CKR_OK);
        emit_call(out, entries->poll, "async_poll", "pending", op, &arg, CKR_PENDING);
        emit_call(out, entries->status, "async_status", "query", op, &arg, CKR_PENDING);
        emit_call(out, entries->poll, "async_poll", "pending", op, &arg, CKR_PENDING);
        emit_call(out, entries->poll, "async_poll", "terminal", op, &arg, CKR_OK);
        emit_call(out, entries->status, "async_status", "query", op, &arg, CKR_OK);
    }
}

static int child_main(const char *provider, const char *mode, unsigned long ops,
                      const char *ledger_path, const char *process) {
    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "collide: child cannot open provider: %s\n", dlerror());
        return 2;
    }
    BoundEntries entries;
    void *begin_address = NULL;
    if (bind_entries(handle, &entries, &begin_address) != 0) {
        dlclose(handle);
        return 2;
    }
    if (emit_target("async_begin", begin_address) != 0) {
        fprintf(stderr, "collide: child cannot resolve its begin entry\n");
        dlclose(handle);
        return 2;
    }
    FILE *ledger = fopen(ledger_path, "w");
    if (ledger == NULL) {
        fprintf(stderr, "collide: child cannot open ledger: %s\n", strerror(errno));
        dlclose(handle);
        return 2;
    }
    int is_a = process[0] == 'A';
    const char *role = is_a ? "owner" : "challenger";
    const char *mechanism = "poll";
    const char *metadata = "\"rsa_2048\"";
    if (is_a) {
        mechanism = strcmp(mode, "persisted") == 0 ? "persisted" : "poll";
    } else if (strcmp(mode, "cancel") == 0) {
        mechanism = "cancel";
    } else {
        mechanism = "message";
        if (strcmp(mode, "persisted") == 0) {
            metadata = "null";
        }
    }
    ChildOut out = {.ledger = ledger,
                    .process = process,
                    .pid = (int)getpid(),
                    .tid = (int)gettid()};
    uint64_t ready = 0;
    if (clock_ns(&ready) != 0) {
        fprintf(stderr, "collide: child clock read failed\n");
        fclose(ledger);
        dlclose(handle);
        return 2;
    }
    if (fprintf(ledger,
                "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                out.pid, out.tid, ready) < 0) {
        out.failed = 1;
    }
    if (!out.failed &&
        fprintf(ledger,
                "{\"kind\":\"scenario\",\"process\":\"%s\",\"role\":\"%s\","
                "\"mechanism\":\"%s\",\"slot\":0,\"target\":\"async_begin\","
                "\"metadata\":%s,\"session\":%d,\"instance\":\"%s\",\"object\":%d}\n",
                process, role, mechanism, metadata, is_a ? 1 : 2, is_a ? "i3" : "i4",
                is_a ? 11 : 12) < 0) {
        out.failed = 1;
    }
    if (!out.failed) {
        if (is_a && strcmp(mode, "persisted") == 0) {
            script_persisted_owner(&out, &entries, ops);
        } else if (is_a) {
            script_poll_owner(&out, &entries, ops);
        } else if (strcmp(mode, "cancel") == 0) {
            script_cancel_challenger(&out, &entries, ops);
        } else {
            script_message_challenger(&out, &entries, ops);
        }
    }
    uint64_t done = 0;
    if (!out.failed && clock_ns(&done) != 0) {
        out.failed = 1;
    }
    if (!out.failed &&
        fprintf(ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"sequenced\":%lu,\"t\":%" PRIu64 "}\n",
                out.calls, out.seq, done) < 0) {
        out.failed = 1;
    }
    if (fclose(ledger) != 0) {
        out.failed = 1;
    }
    dlclose(handle);
    if (out.failed) {
        fprintf(stderr, "collide: child ledger emission failed\n");
        return 2;
    }
    return out.unhealthy == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "usage: %s PROVIDER MODE OPS LEDGER_A LEDGER_B [GO_FILE]\n",
                argc > 0 ? argv[0] : "collide");
        return 2;
    }
    if (strcmp(argv[2], "poll_msg") != 0 && strcmp(argv[2], "cancel") != 0 &&
        strcmp(argv[2], "persisted") != 0) {
        fprintf(stderr, "collide: MODE must be poll_msg, cancel or persisted\n");
        return 2;
    }
    unsigned long ops = 0;
    if (parse_number(argv[3], MAX_OPS, &ops) != 0 || ops == 0) {
        fprintf(stderr, "collide: OPS must be 1..%d\n", MAX_OPS);
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    void *probe = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (probe == NULL) {
        fprintf(stderr, "collide: cannot open provider: %s\n", dlerror());
        return 2;
    }
    BoundEntries ignored;
    if (bind_entries(probe, &ignored, NULL) != 0) {
        dlclose(probe);
        return 2;
    }
    dlclose(probe);

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argc == 7 && wait_for_go(argv[6]) != 0) {
        if (stop) {
            fprintf(stderr, "collide: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "collide: cannot wait for gate\n");
        }
        return 2;
    }

    pid_t kids[2] = {-1, -1};
    const char *names[2] = {"A", "B"};
    for (int i = 0; i < 2; i++) {
        pid_t child = fork();
        if (child < 0) {
            fprintf(stderr, "collide: fork failed: %s\n", strerror(errno));
            for (int k = 0; k < i; k++) {
                kill(kids[k], SIGTERM);
            }
            for (int k = 0; k < i; k++) {
                waitpid(kids[k], NULL, 0);
            }
            return 2;
        }
        if (child == 0) {
            int code = child_main(argv[1], argv[2], ops, argv[4 + i], names[i]);
            fflush(stdout);
            fflush(stderr);
            _exit(code);
        }
        kids[i] = child;
    }
    int status[2] = {0, 0};
    int reaped[2] = {0, 0};
    int remaining = 2;
    while (remaining > 0) {
        if (stop) {
            for (int i = 0; i < 2; i++) {
                if (!reaped[i]) {
                    kill(kids[i], SIGTERM);
                }
            }
        }
        for (int i = 0; i < 2; i++) {
            if (reaped[i]) {
                continue;
            }
            pid_t done = waitpid(kids[i], &status[i], WNOHANG);
            if (done < 0) {
                if (errno != EINTR) {
                    for (int k = 0; k < 2; k++) {
                        if (!reaped[k]) {
                            kill(kids[k], SIGTERM);
                        }
                    }
                    return 2;
                }
            } else if (done == kids[i]) {
                reaped[i] = 1;
                remaining--;
            }
        }
        if (remaining > 0) {
            usleep(10000);
        }
    }
    if (stop) {
        fprintf(stderr, "collide: interrupted while reaping children\n");
        return 2;
    }
    int worst = 0;
    for (int i = 0; i < 2; i++) {
        int code = 2;
        if (WIFEXITED(status[i])) {
            code = WEXITSTATUS(status[i]);
        }
        if (code > worst) {
            worst = code;
        }
    }
    return worst;
}
