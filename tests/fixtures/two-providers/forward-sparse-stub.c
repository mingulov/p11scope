/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Forwarding/sparse two-provider ledger stub: a provider-free emitter.
 *
 * Usage: forward-sparse-stub LEDGER COUNT [--sparse N] [--forward SPEC]
 *   LEDGER       output ledger path, created fresh (never appended)
 *   COUNT        1..100000 rounds; dense mode emits 2*COUNT call rows
 *   --sparse N   2..COUNT: feed B emits only rounds divisible by N, so
 *                B's per-feed seqs carry holes; other rounds emit A only
 *   --forward SPEC
 *                comma-separated FEED:COUNT batches (A:7,B:3); each batch
 *                becomes one forward marker row after the calls. At most
 *                64 batches, each COUNT 1..1000000.
 *
 * The stub drives no provider: it emits one feed-labeled two-provider
 * ledger directly (two ready rows, interleaved A/B call rows with a
 * global contiguous seq, fn table[4], rv 0, CLOCK_MONOTONIC t0/t1
 * stamps, optional forward markers, one ack row). No handle rows are
 * emitted: forwarding and sparsity need no collision evidence. Every
 * emitted ledger validates with scripts/joint-two-provider-compare.py
 * unchanged; a batch sum merged into completed/failed is refused by
 * the oracle's exact per-feed match, never absorbed.
 *
 * Exit 0 when the ledger is complete, 2 on usage or emission failure.
 * LP64 only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_COUNT 100000ul
#define MAX_SPARSE MAX_COUNT
#define MAX_FORWARD_BATCHES 64ul
#define MAX_FORWARD_COUNT 1000000ul

static int clock_ns(uint64_t *out) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *out = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 0;
}

static int parse_ulong(const char *text, unsigned long low,
                       unsigned long high, unsigned long *out) {
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
    if (errno != 0 || *end != '\0' || value < low || value > high) {
        return -1;
    }
    *out = value;
    return 0;
}

struct forward_batch {
    char feed;
    unsigned long count;
};

static int parse_forward_spec(const char *text, struct forward_batch *batches,
                              size_t *count) {
    *count = 0;
    if (text[0] == '\0') {
        return -1;
    }
    const char *cursor = text;
    while (*cursor != '\0') {
        if (*count >= MAX_FORWARD_BATCHES) {
            return -1;
        }
        if ((cursor[0] != 'A' && cursor[0] != 'B') || cursor[1] != ':') {
            return -1;
        }
        const char *digits = cursor + 2;
        const char *end = digits;
        while (*end >= '0' && *end <= '9') {
            end++;
        }
        if (end == digits || (*end != '\0' && *end != ',')) {
            return -1;
        }
        char number[32];
        size_t width = (size_t)(end - digits);
        if (width >= sizeof number) {
            return -1;
        }
        memcpy(number, digits, width);
        number[width] = '\0';
        unsigned long value = 0;
        if (parse_ulong(number, 1, MAX_FORWARD_COUNT, &value) != 0) {
            return -1;
        }
        batches[*count].feed = cursor[0];
        batches[*count].count = value;
        (*count)++;
        cursor = (*end == ',') ? end + 1 : end;
        if (*cursor == '\0' && *(end) == ',') {
            return -1;
        }
    }
    return *count > 0 ? 0 : -1;
}

static void usage(const char *name) {
    fprintf(stderr,
            "usage: %s LEDGER COUNT [--sparse N] [--forward SPEC]\n",
            name);
}

int main(int argc, char **argv) {
    const char *name = argc > 0 ? argv[0] : "forward-sparse-stub";
    if (argc < 3 || argc > 6) {
        usage(name);
        return 2;
    }
    unsigned long count = 0;
    if (parse_ulong(argv[2], 1, MAX_COUNT, &count) != 0) {
        fprintf(stderr, "%s: COUNT must be 1..%lu\n", name, MAX_COUNT);
        return 2;
    }
    unsigned long sparse = 0;
    struct forward_batch batches[MAX_FORWARD_BATCHES];
    size_t batch_count = 0;
    int saw_sparse = 0;
    int saw_forward = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--sparse") == 0) {
            if (saw_sparse || i + 1 >= argc ||
                parse_ulong(argv[i + 1], 2, count, &sparse) != 0) {
                fprintf(stderr, "%s: --sparse N must be 2..COUNT\n", name);
                return 2;
            }
            saw_sparse = 1;
            i++;
        } else if (strcmp(argv[i], "--forward") == 0) {
            if (saw_forward || i + 1 >= argc ||
                parse_forward_spec(argv[i + 1], batches, &batch_count) != 0) {
                fprintf(stderr, "%s: --forward SPEC must be FEED:COUNT[,...]\n",
                        name);
                return 2;
            }
            saw_forward = 1;
            i++;
        } else {
            usage(name);
            return 2;
        }
    }
    FILE *ledger = fopen(argv[1], "w");
    if (ledger == NULL) {
        fprintf(stderr, "%s: cannot open ledger: %s\n", name, strerror(errno));
        return 2;
    }
    int failed = 0;
    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t stamp = 0;
    if (clock_ns(&stamp) != 0) {
        fprintf(stderr, "%s: clock read failed\n", name);
        fclose(ledger);
        return 2;
    }
    if (fprintf(ledger,
                "{\"kind\":\"ready\",\"feed\":\"A\",\"pid\":%d,\"tid\":%d,"
                "\"t\":%" PRIu64 ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                pid, tid, stamp) < 0) {
        failed = 1;
    }
    uint64_t ready_b = 0;
    if (!failed && clock_ns(&ready_b) != 0) {
        failed = 1;
    }
    if (!failed && fprintf(ledger,
                           "{\"kind\":\"ready\",\"feed\":\"B\",\"pid\":%d,\"tid\":%d,"
                           "\"t\":%" PRIu64
                           ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                           pid, tid, ready_b) < 0) {
        failed = 1;
    }
    unsigned long seq = 0;
    for (unsigned long round = 1; round <= count && !failed; round++) {
        int emit_b = sparse == 0 || round % sparse == 0;
        int lanes = emit_b ? 2 : 1;
        for (int lane = 0; lane < lanes && !failed; lane++) {
            const char *feed = lane == 0 ? "A" : "B";
            uint64_t t0 = 0, t1 = 0;
            if (clock_ns(&t0) != 0 || clock_ns(&t1) != 0) {
                failed = 1;
                break;
            }
            seq++;
            if (fprintf(ledger,
                        "{\"kind\":\"call\",\"seq\":%lu,\"feed\":\"%s\","
                        "\"fn\":\"table[4]\",\"rv\":0,\"pid\":%d,\"tid\":%d,"
                        "\"t0\":%" PRIu64 ",\"t1\":%" PRIu64 "}\n",
                        seq, feed, pid, tid, t0, t1) < 0) {
                failed = 1;
            }
        }
    }
    for (size_t i = 0; i < batch_count && !failed; i++) {
        if (clock_ns(&stamp) != 0) {
            failed = 1;
            break;
        }
        if (fprintf(ledger,
                    "{\"kind\":\"forward\",\"feed\":\"%c\",\"count\":%lu,"
                    "\"t\":%" PRIu64 "}\n",
                    batches[i].feed, batches[i].count, stamp) < 0) {
            failed = 1;
        }
    }
    if (!failed && clock_ns(&stamp) != 0) {
        failed = 1;
    }
    if (!failed && fprintf(ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"t\":%" PRIu64 "}\n",
                           seq, stamp) < 0) {
        failed = 1;
    }
    if (fclose(ledger) != 0) {
        failed = 1;
    }
    if (failed) {
        fprintf(stderr, "%s: ledger emission failed\n", name);
        return 2;
    }
    return 0;
}
