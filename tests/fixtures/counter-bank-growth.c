/* SPDX-License-Identifier: GPL-3.0-or-later */
/* LP64-only owned fixture, built twice: -DCOUNTER_BANK_GROWTH_PROVIDER gives
 * the provider; otherwise build the dlopen/pthread driver with -ldl -pthread.
 * Symbols counter_bank_growth_e0000..e1fff are 8192 separate function bodies.
 * The host must also verify their distinct executable ELF file offsets.
 *
 * Driver: PROGRAM PROVIDER, or PROGRAM --self-test PROVIDER.
 * Line protocol (decimal indices; RV kind 0=0, 1=0x204, 2=0x100000204):
 *   READY 1 8192
 *   START             -> HELD 0             (old endpoint 0, RV kind 1)
 *   STEP 511|512|8191  -> STEP index rv_hex  (RV kind index % 3)
 *   CALL index kind   -> CALLED index rv_hex
 *   RUN first end     -> RAN first end      (one call/index in [first,end))
 *   HOT_RV index first_hex count -> HOT_RV index first_hex count
 *                     (one full64 consecutive range, count 1..65537)
 *   RELEASE           -> RELEASED 0 0000000000000204
 *   LEDGER            -> LEDGER_BEGIN 8192; 8192 ROW lines; LEDGER_END totals
 *   QUIT              -> DONE exercised    (requires no held call)
 * STEP/CALL/RUN/HOT_RV require START first. ROW is index, entered, returned, errors,
 * then the three RV counts in kind order and an other-RV count. One optional
 * HOT_RV_LEDGER index first_hex count completed describes the exact hot range;
 * these calls are already included in ROW, not extra calls to add to it.
 * LEDGER_END is entered/returned/errors. At most one old call is held, so this
 * fixture does not establish START exhaustion. 65537 is a fixture bound,
 * not a product cap.
 * HELD acknowledges the provider body, not a kernel START observation; only
 * the host can verify actual START, attachment, health and collected counts.
 * EOF, malformed input or ABORT cancels the held pipe/join and exits nonzero.
 * There are no sleeps, timed releases, subprocesses or PKCS#11 payloads. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { CBG_ENDPOINTS = 8192, CBG_KINDS = 3, CBG_HOT_RVS = 65537, CBG_LINE = 80 };

struct cbg_call {
    uint64_t rv;
    uint32_t observed_index;
    int entered_fd;
    int release_fd;
    int failed;
};

_Static_assert(sizeof(unsigned long) == 8 && sizeof(void *) == 8, "LP64 fixture");
_Static_assert(sizeof(struct cbg_call) == 24, "provider/driver private call ABI");

static int exact_byte(int fd, unsigned char expected, int write_byte)
{
    unsigned char byte = expected;
    ssize_t done;
    do {
        done = write_byte ? write(fd, &byte, 1) : read(fd, &byte, 1);
    } while (done < 0 && errno == EINTR);
    return done == 1 && byte == expected ? 0 : -1;
}

#ifdef COUNTER_BANK_GROWTH_PROVIDER

__attribute__((noinline))
static unsigned long endpoint_body(unsigned int index, struct cbg_call *call)
{
    call->observed_index = index;
    if (call->entered_fd >= 0 &&
        (exact_byte(call->entered_fd, 'E', 1) || exact_byte(call->release_fd, 'R', 0))) {
        call->failed = 1;
        return 5;
    }
    return call->rv;
}

/* The literal index in each body also prevents identical-code folding. The
 * post-call compiler barrier prevents turning these into tail-call aliases. */
#define CBG_NAME_(a, b, c, d) counter_bank_growth_e##a##b##c##d
#define CBG_NAME(a, b, c, d) CBG_NAME_(a, b, c, d)
#define CBG_INDEX_(a, b, c, d) 0x##a##b##c##d##U
#define CBG_INDEX(a, b, c, d) CBG_INDEX_(a, b, c, d)
#define CBG_DEFINE(a, b, c, d)                                                   \
    __attribute__((noinline, used, visibility("default")))                       \
    unsigned long CBG_NAME(a, b, c, d)(struct cbg_call *call)                     \
    {                                                                           \
        unsigned long result = endpoint_body(CBG_INDEX(a, b, c, d), call);       \
        __asm__ volatile("" : "+r"(result) : : "memory");                         \
        return result;                                                          \
    }
#define CBG_NIBBLE(M, hi3, hi2, hi1)                                            \
    M(hi3, hi2, hi1, 0) M(hi3, hi2, hi1, 1) M(hi3, hi2, hi1, 2)              \
    M(hi3, hi2, hi1, 3) M(hi3, hi2, hi1, 4) M(hi3, hi2, hi1, 5)              \
    M(hi3, hi2, hi1, 6) M(hi3, hi2, hi1, 7) M(hi3, hi2, hi1, 8)              \
    M(hi3, hi2, hi1, 9) M(hi3, hi2, hi1, a) M(hi3, hi2, hi1, b)              \
    M(hi3, hi2, hi1, c) M(hi3, hi2, hi1, d) M(hi3, hi2, hi1, e)              \
    M(hi3, hi2, hi1, f)
#define CBG_BYTE(M, hi3, hi2)                                                    \
    CBG_NIBBLE(M, hi3, hi2, 0) CBG_NIBBLE(M, hi3, hi2, 1)                      \
    CBG_NIBBLE(M, hi3, hi2, 2) CBG_NIBBLE(M, hi3, hi2, 3)                      \
    CBG_NIBBLE(M, hi3, hi2, 4) CBG_NIBBLE(M, hi3, hi2, 5)                      \
    CBG_NIBBLE(M, hi3, hi2, 6) CBG_NIBBLE(M, hi3, hi2, 7)                      \
    CBG_NIBBLE(M, hi3, hi2, 8) CBG_NIBBLE(M, hi3, hi2, 9)                      \
    CBG_NIBBLE(M, hi3, hi2, a) CBG_NIBBLE(M, hi3, hi2, b)                      \
    CBG_NIBBLE(M, hi3, hi2, c) CBG_NIBBLE(M, hi3, hi2, d)                      \
    CBG_NIBBLE(M, hi3, hi2, e) CBG_NIBBLE(M, hi3, hi2, f)
#define CBG_PAGE(M, hi3)                                                         \
    CBG_BYTE(M, hi3, 0) CBG_BYTE(M, hi3, 1) CBG_BYTE(M, hi3, 2)                \
    CBG_BYTE(M, hi3, 3) CBG_BYTE(M, hi3, 4) CBG_BYTE(M, hi3, 5)                \
    CBG_BYTE(M, hi3, 6) CBG_BYTE(M, hi3, 7) CBG_BYTE(M, hi3, 8)                \
    CBG_BYTE(M, hi3, 9) CBG_BYTE(M, hi3, a) CBG_BYTE(M, hi3, b)                \
    CBG_BYTE(M, hi3, c) CBG_BYTE(M, hi3, d) CBG_BYTE(M, hi3, e)                \
    CBG_BYTE(M, hi3, f)
CBG_PAGE(CBG_DEFINE, 0)
CBG_PAGE(CBG_DEFINE, 1)

#else
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef unsigned long (*endpoint_fn)(struct cbg_call *);

struct row {
    uint64_t entered, returned, errors, rv[CBG_KINDS], other_rv;
};

struct state {
    endpoint_fn *functions;
    struct row *rows;
    bool started, active;
    int entered[2], release[2];
    pthread_t thread;
    struct cbg_call old;
    unsigned long old_result;
    atomic_bool old_finished;
    bool hot_started;
    unsigned int hot_index, hot_count, hot_completed;
    uint64_t hot_first;
};

enum operation { START, STEP, CALL, RUN, HOT_RV, RELEASE, LEDGER, QUIT, ABORT };
struct command {
    enum operation operation;
    unsigned int first, second;
    uint64_t rv;
};

static const uint64_t return_values[CBG_KINDS] = {0, 0x204, 0x100000204};
static int parse_command(const char *, struct command *);
static struct state *new_state(endpoint_fn *);
static void free_state(struct state *);
static int start_old(struct state *);
static int release_old(struct state *);
static int cancel_old(struct state *);
static int call_one(struct state *, unsigned int, unsigned int);
static int run_range(struct state *, unsigned int, unsigned int);
static int hot_range(struct state *, unsigned int, uint64_t, unsigned int);

/* These literal controls precede the driver implementation. They catch a
 * missing endpoint, index alias, truncated RV, early/duplicate old completion,
 * malformed command acceptance and cancellation being credited as success. */
static int self_test(endpoint_fn *functions)
{
    struct state *state = new_state(functions), *cancelled = NULL;
    struct command command;
    int result = 1;
#define REQUIRE(test) do {                                                       \
    if (!(test)) {                                                              \
        fprintf(stderr, "SELFTEST_FAIL line %u\n", (unsigned int)__LINE__);      \
        goto out;                                                              \
    }                                                                          \
} while (0)
    REQUIRE(state);
    REQUIRE(parse_command("RUN 0 8192", &command) == 0 &&
            command.operation == RUN && command.first == 0 && command.second == 8192);
    REQUIRE(parse_command("CALL 8191 2", &command) == 0 && command.first == 8191 &&
            command.second == 2);
    REQUIRE(parse_command("HOT_RV 512 0000000100000000 65537", &command) == 0 &&
            command.operation == HOT_RV && command.first == 512 &&
            command.rv == 0x100000000 && command.second == 65537);
    const char *invalid[] = {"", " START", "START ", "STEP 0", "STEP 8192",
        "CALL 8192 0", "CALL -1 0", "CALL 0 3", "CALL 0 1 junk", "CALL 0 01",
        "RUN 1 1", "RUN 2 1", "RUN 0 8193", "RUN 0 42949672960", "QUIT junk",
        "HOT_RV 0 -1 1", "HOT_RV 0 10000000000000000 1", "HOT_RV 0 0 0",
        "HOT_RV 0 0 65538", "HOT_RV 0 ffffffffffffffff 2"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        REQUIRE(parse_command(invalid[i], &command) != 0);
    REQUIRE(call_one(state, 0, 0) != 0); /* no calls before START */
    REQUIRE(start_old(state) == 0);
    REQUIRE(!atomic_load_explicit(&state->old_finished, memory_order_acquire));
    REQUIRE(state->rows[0].entered == 1 && state->rows[0].returned == 0);
    REQUIRE(start_old(state) != 0); /* duplicate START cannot create an entry */
    REQUIRE(call_one(state, 8192, 0) != 0 && call_one(state, 0, 3) != 0);
    REQUIRE(call_one(state, 511, 1) == 0 && call_one(state, 512, 2) == 0 &&
            call_one(state, 8191, 1) == 0);
    REQUIRE(run_range(state, 0, 8192) == 0);
    REQUIRE(state->rows[0].entered == 2 && state->rows[0].returned == 1);
    REQUIRE(release_old(state) == 0 && release_old(state) != 0);
    REQUIRE(atomic_load_explicit(&state->old_finished, memory_order_acquire));
    REQUIRE(state->rows[0].entered == 2 && state->rows[0].returned == 2 &&
            state->rows[0].errors == 0 && state->rows[0].rv[0] == 1 &&
            state->rows[0].rv[1] == 1 && state->rows[0].rv[2] == 0);
    REQUIRE(state->rows[511].rv[1] == 2 && state->rows[511].errors == 0);
    REQUIRE(state->rows[512].rv[2] == 2 && state->rows[512].errors == 2);
    REQUIRE(state->rows[8191].rv[1] == 2 && state->rows[8191].errors == 0);
    uint64_t entered = 0, returned = 0, errors = 0, kinds[3] = {0};
    for (unsigned int i = 0; i < CBG_ENDPOINTS; ++i) {
        REQUIRE(state->rows[i].entered >= 1 && state->rows[i].returned >= 1);
        entered += state->rows[i].entered;
        returned += state->rows[i].returned;
        errors += state->rows[i].errors;
        for (unsigned int kind = 0; kind < CBG_KINDS; ++kind)
            kinds[kind] += state->rows[i].rv[kind];
    }
    REQUIRE(entered == 8196 && returned == 8196 && errors == 2731);
    REQUIRE(kinds[0] == 2731 && kinds[1] == 2734 && kinds[2] == 2731);
    REQUIRE(hot_range(state, 512, 0, 65538) != 0 &&
            hot_range(state, 512, UINT64_MAX, 2) != 0);
    REQUIRE(hot_range(state, 512, 0x100000000, 65537) == 0);
    REQUIRE(state->hot_completed == 65537 && state->hot_first == 0x100000000 &&
            state->hot_count == 65537 && state->hot_index == 512);
    REQUIRE(state->rows[512].returned == 65539 && state->rows[512].errors == 65539 &&
            state->rows[512].rv[2] == 3 && state->rows[512].other_rv == 65536);
    REQUIRE(hot_range(state, 512, 0, 1) != 0); /* no unbounded range history */
    cancelled = new_state(functions);
    REQUIRE(cancelled && start_old(cancelled) == 0 && cancel_old(cancelled) == 0);
    REQUIRE(cancelled->old.failed == 1 && cancelled->old_result == 5 &&
            cancelled->rows[0].entered == 1 && cancelled->rows[0].returned == 0);
    puts("SELFTEST 8192 8196 2731 65537");
    result = 0;
out:
    free_state(cancelled);
    free_state(state);
#undef REQUIRE
    return result;
}

static void close_pipe(int descriptors[2])
{
    for (unsigned int i = 0; i < 2; ++i) {
        if (descriptors[i] >= 0)
            close(descriptors[i]);
        descriptors[i] = -1;
    }
}

static struct state *new_state(endpoint_fn *functions)
{
    struct state *state = calloc(1, sizeof(*state));
    if (!state)
        return NULL;
    state->rows = calloc(CBG_ENDPOINTS, sizeof(*state->rows));
    if (!state->rows) {
        free(state);
        return NULL;
    }
    state->functions = functions;
    state->entered[0] = state->entered[1] = -1;
    state->release[0] = state->release[1] = -1;
    atomic_init(&state->old_finished, false);
    return state;
}

static void *old_thread(void *opaque)
{
    struct state *state = opaque;
    state->old_result = state->functions[0](&state->old);
    atomic_store_explicit(&state->old_finished, true, memory_order_release);
    return NULL;
}

static int start_old(struct state *state)
{
    if (state->started || state->rows[0].entered == UINT64_MAX)
        return -1;
    if (pipe2(state->entered, O_CLOEXEC) || pipe2(state->release, O_CLOEXEC)) {
        close_pipe(state->entered);
        close_pipe(state->release);
        return -1;
    }
    state->old = (struct cbg_call){.rv = 0x204, .observed_index = UINT32_MAX,
        .entered_fd = state->entered[1], .release_fd = state->release[0]};
    if (pthread_create(&state->thread, NULL, old_thread, state)) {
        close_pipe(state->entered);
        close_pipe(state->release);
        return -1;
    }
    state->started = state->active = true;
    if (exact_byte(state->entered[0], 'E', 0))
        return -1;
    state->rows[0].entered++;
    return 0;
}

static int release_old(struct state *state)
{
    if (!state->active || state->rows[0].returned == UINT64_MAX ||
        state->rows[0].rv[1] == UINT64_MAX || exact_byte(state->release[1], 'R', 1))
        return -1;
    if (pthread_join(state->thread, NULL))
        return -1;
    state->active = false;
    close_pipe(state->entered);
    close_pipe(state->release);
    if (state->old.failed || state->old.observed_index != 0 || state->old_result != 0x204)
        return -1;
    state->rows[0].returned++;
    state->rows[0].rv[1]++;
    return 0;
}

static int cancel_old(struct state *state)
{
    if (!state->active)
        return 0;
    /* EOF is refusal, never a successful release in the fixture ledger. */
    close(state->release[1]);
    state->release[1] = -1;
    if (pthread_join(state->thread, NULL))
        return -1;
    state->active = false;
    close_pipe(state->entered);
    close_pipe(state->release);
    return state->old.failed == 1 && state->old_result == 5 ? 0 : -1;
}

static void free_state(struct state *state)
{
    if (state) {
        if (cancel_old(state))
            abort(); /* cannot free storage still owned by a live thread */
        close_pipe(state->entered);
        close_pipe(state->release);
        free(state->rows);
        free(state);
    }
}

static int call_value(struct state *state, unsigned int index, uint64_t rv)
{
    if (!state->started || index >= CBG_ENDPOINTS)
        return -1;
    struct row *row = &state->rows[index];
    unsigned int kind = 0;
    while (kind < CBG_KINDS && return_values[kind] != rv)
        kind++;
    uint64_t *bucket = kind == CBG_KINDS ? &row->other_rv : &row->rv[kind];
    if (row->entered == UINT64_MAX || row->returned == UINT64_MAX ||
        *bucket == UINT64_MAX || (rv != 0 && rv != 0x204 && row->errors == UINT64_MAX))
        return -1;
    struct cbg_call call = {.rv = rv, .observed_index = UINT32_MAX,
        .entered_fd = -1, .release_fd = -1};
    unsigned long result = state->functions[index](&call);
    if (call.failed || call.observed_index != index || result != rv)
        return -1;
    row->entered++;
    row->returned++;
    (*bucket)++;
    if (result != 0 && result != 0x204)
        row->errors++;
    return 0;
}

static int call_one(struct state *state, unsigned int index, unsigned int kind)
{
    return kind < CBG_KINDS ? call_value(state, index, return_values[kind]) : -1;
}

static int run_range(struct state *state, unsigned int first, unsigned int end)
{
    if (first >= end || end > CBG_ENDPOINTS)
        return -1;
    for (unsigned int index = first; index < end; ++index)
        if (call_one(state, index, index % CBG_KINDS))
            return -1;
    return 0;
}

static int hot_range(struct state *state, unsigned int index, uint64_t first,
                     unsigned int count)
{
    if (!state->started || state->hot_started || index >= CBG_ENDPOINTS ||
        count == 0 || count > CBG_HOT_RVS || first > UINT64_MAX - (count - 1))
        return -1;
    const struct row *row = &state->rows[index];
    if (row->entered > UINT64_MAX - count || row->returned > UINT64_MAX - count ||
        row->errors > UINT64_MAX - count || row->other_rv > UINT64_MAX - count)
        return -1;
    for (unsigned int kind = 0; kind < CBG_KINDS; ++kind)
        if (row->rv[kind] > UINT64_MAX - count)
            return -1;
    state->hot_started = true;
    state->hot_index = index;
    state->hot_first = first;
    state->hot_count = count;
    for (unsigned int offset = 0; offset < count; ++offset) {
        if (call_value(state, index, first + offset))
            return -1;
        state->hot_completed++;
    }
    return 0;
}

static int decimal(const char *text, unsigned int *number)
{
    unsigned int result = 0;
    if (!*text)
        return -1;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || result > (UINT_MAX - (*text - '0')) / 10)
            return -1;
        result = result * 10 + (unsigned int)(*text - '0');
    }
    *number = result;
    return 0;
}

static int hexadecimal(const char *text, uint64_t *number)
{
    size_t length = strlen(text);
    if (length == 0 || length > 16)
        return -1;
    uint64_t result = 0;
    for (; *text; ++text) {
        unsigned int digit;
        if (*text >= '0' && *text <= '9') digit = (unsigned int)(*text - '0');
        else if (*text >= 'a' && *text <= 'f') digit = (unsigned int)(*text - 'a') + 10;
        else return -1;
        result = (result << 4) | digit;
    }
    *number = result;
    return 0;
}

static int parse_command(const char *line, struct command *command)
{
    const struct { const char *text; enum operation operation; } simple[] = {
        {"START", START}, {"RELEASE", RELEASE}, {"LEDGER", LEDGER},
        {"QUIT", QUIT}, {"ABORT", ABORT}};
    for (size_t i = 0; i < sizeof(simple) / sizeof(simple[0]); ++i)
        if (!strcmp(line, simple[i].text)) {
            *command = (struct command){.operation = simple[i].operation};
            return 0;
        }
    char copy[CBG_LINE];
    if (strlen(line) >= sizeof(copy))
        return -1;
    strcpy(copy, line);
    char *first = strchr(copy, ' ');
    if (!first)
        return -1;
    *first++ = '\0';
    char *second = strchr(first, ' ');
    if (second)
        *second++ = '\0';
    if (decimal(first, &command->first))
        return -1;
    if (!strcmp(copy, "STEP") && !second &&
        (command->first == 511 || command->first == 512 || command->first == 8191)) {
        command->operation = STEP;
        return 0;
    }
    if (!strcmp(copy, "HOT_RV") && second && command->first < CBG_ENDPOINTS) {
        char *count = strchr(second, ' ');
        if (!count)
            return -1;
        *count++ = '\0';
        if (hexadecimal(second, &command->rv) || decimal(count, &command->second) ||
            command->second == 0 || command->second > CBG_HOT_RVS ||
            command->rv > UINT64_MAX - (command->second - 1))
            return -1;
        command->operation = HOT_RV;
        return 0;
    }
    if (!second || decimal(second, &command->second))
        return -1;
    if (!strcmp(copy, "CALL") && command->first < CBG_ENDPOINTS &&
        second[0] >= '0' && second[0] <= '2' && !second[1]) {
        command->operation = CALL;
        return 0;
    }
    if (!strcmp(copy, "RUN") && command->first < command->second &&
        command->second <= CBG_ENDPOINTS) {
        command->operation = RUN;
        return 0;
    }
    return -1;
}

static int read_line(char line[CBG_LINE])
{
    size_t length = 0;
    for (;;) {
        unsigned char byte;
        ssize_t done = read(STDIN_FILENO, &byte, 1);
        if (done < 0 && errno == EINTR)
            continue;
        if (done == 0)
            return length ? -1 : 0;
        if (done != 1 || byte == 0 || byte == '\r')
            return -1;
        if (byte == '\n') {
            line[length] = '\0';
            return 1;
        }
        if (length == CBG_LINE - 1)
            return -1;
        line[length++] = (char)byte;
    }
}

static int ledger(const struct state *state)
{
    uint64_t entered = 0, returned = 0, errors = 0;
    puts("LEDGER_BEGIN 8192");
    for (unsigned int index = 0; index < CBG_ENDPOINTS; ++index) {
        const struct row *row = &state->rows[index];
        if (entered > UINT64_MAX - row->entered || returned > UINT64_MAX - row->returned ||
            errors > UINT64_MAX - row->errors)
            return -1;
        entered += row->entered;
        returned += row->returned;
        errors += row->errors;
        printf("ROW %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
               " %" PRIu64 " %" PRIu64 "\n", index, row->entered, row->returned, row->errors,
               row->rv[0], row->rv[1], row->rv[2], row->other_rv);
    }
    if (state->hot_started)
        printf("HOT_RV_LEDGER %u %016" PRIx64 " %u %u\n", state->hot_index,
               state->hot_first, state->hot_count, state->hot_completed);
    printf("LEDGER_END %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", entered, returned, errors);
    return ferror(stdout) ? -1 : 0;
}

static int drive(endpoint_fn *functions)
{
    struct state *state = new_state(functions);
    int result = 1;
    if (!state)
        return result;
    puts("READY 1 8192");
    if (fflush(stdout))
        goto out;
    char line[CBG_LINE];
    while (read_line(line) == 1) {
        struct command command;
        if (parse_command(line, &command))
            goto out;
        switch (command.operation) {
        case START:
            if (start_old(state)) goto out;
            puts("HELD 0");
            break;
        case STEP:
        case CALL: {
            unsigned int kind = command.operation == STEP ? command.first % 3 : command.second;
            if (call_one(state, command.first, kind)) goto out;
            printf("%s %u %016" PRIx64 "\n", command.operation == STEP ? "STEP" : "CALLED",
                   command.first, return_values[kind]);
            break;
        }
        case RUN:
            if (run_range(state, command.first, command.second)) goto out;
            printf("RAN %u %u\n", command.first, command.second);
            break;
        case HOT_RV:
            if (hot_range(state, command.first, command.rv, command.second)) goto out;
            printf("HOT_RV %u %016" PRIx64 " %u\n", command.first, command.rv, command.second);
            break;
        case RELEASE:
            if (release_old(state)) goto out;
            puts("RELEASED 0 0000000000000204");
            break;
        case LEDGER:
            if (ledger(state)) goto out;
            break;
        case QUIT: {
            if (state->active || !state->started) goto out;
            unsigned int exercised = 0;
            for (unsigned int i = 0; i < CBG_ENDPOINTS; ++i)
                exercised += state->rows[i].returned != 0;
            printf("DONE %u\n", exercised);
            result = fflush(stdout) ? 1 : 0;
            goto out;
        }
        case ABORT:
            goto out;
        }
        if (fflush(stdout))
            goto out;
    }
out:
    free_state(state);
    return result;
}

static int compare_address(const void *left, const void *right)
{
    uintptr_t a = *(const uintptr_t *)left, b = *(const uintptr_t *)right;
    return (a > b) - (a < b);
}

static endpoint_fn *load_endpoints(void *provider)
{
    endpoint_fn *functions = calloc(CBG_ENDPOINTS, sizeof(*functions));
    uintptr_t *addresses = calloc(CBG_ENDPOINTS, sizeof(*addresses));
    struct link_map *mapping = NULL;
    if (!functions || !addresses || dlinfo(provider, RTLD_DI_LINKMAP, &mapping) || !mapping)
        goto fail;
    for (unsigned int index = 0; index < CBG_ENDPOINTS; ++index) {
        char name[40];
        snprintf(name, sizeof(name), "counter_bank_growth_e%04x", index);
        void *symbol = dlsym(provider, name);
        Dl_info info;
        if (!symbol || !dladdr(symbol, &info) || info.dli_fbase != (void *)mapping->l_addr ||
            info.dli_saddr != symbol || !info.dli_sname || strcmp(info.dli_sname, name))
            goto fail;
        _Static_assert(sizeof(functions[index]) == sizeof(symbol), "LP64 dlsym ABI");
        memcpy(&functions[index], &symbol, sizeof(symbol));
        addresses[index] = (uintptr_t)symbol;
    }
    qsort(addresses, CBG_ENDPOINTS, sizeof(*addresses), compare_address);
    for (unsigned int index = 1; index < CBG_ENDPOINTS; ++index)
        if (addresses[index] == addresses[index - 1])
            goto fail;
    free(addresses);
    return functions;
fail:
    free(addresses);
    free(functions);
    return NULL;
}

int main(int argc, char **argv)
{
    bool test = argc == 3 && !strcmp(argv[1], "--self-test");
    if ((!test && argc != 2) || signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 2;
    void *provider = dlopen(argv[test ? 2 : 1], RTLD_NOW | RTLD_LOCAL);
    if (!provider)
        return 3;
    endpoint_fn *functions = load_endpoints(provider);
    int result = functions ? (test ? self_test(functions) : drive(functions)) : 4;
    free(functions);
    dlclose(provider);
    return result;
}
#endif
