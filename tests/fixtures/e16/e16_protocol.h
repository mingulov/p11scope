/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The one E16 fixture hold protocol, shared by every E16 driver.
 *
 * Every protocol record is one whole stderr line written by e16_write_all,
 * which retries partial writes and EINTR; any other write failure exits 90.
 * In order:
 *
 *   P11SCOPE_E16 ready pid=<pid> starttime=<ticks> endpoint=0x<hex> image=0x<hex> calls=<n>
 *   [hold] read one byte from stdin: 'G' continues; any other byte, EOF or a
 *          read error exits 92
 *   P11SCOPE_E16 call <label> <index> rv=<rv>     (index 0 .. n-1, in order)
 *   P11SCOPE_E16 done calls=<n>
 *   [hold] read one byte from stdin: 'X' continues; any other byte, EOF or a
 *          read error exits 93
 *
 * The hold is on exactly when P11SCOPE_E16_HOLD=1; otherwise the driver never
 * reads stdin and runs straight through. There is no other gate.
 *
 * `endpoint` is the exact address the call loop invokes. For a file-backed
 * shape it lies in the provider's (or, statically linked, the driver's)
 * executable mapping; for the anonymous JIT shape it lies in an anonymous
 * executable mapping. `image` is an address inside the driver executable, so a
 * receipt can pin the image that runs the loop separately from the endpoint.
 * `starttime` is field 22 of /proc/self/stat, so a reader can bind the line to
 * one process birth. A call whose rv is nonzero exits 6 right after its call
 * line. Exit 0 therefore means: every call line and the done line were
 * written and, under the hold, both gate bytes were received.
 *
 * Provider fixtures may interleave their own `P11SCOPE_E16 provider ...`
 * witness lines (suppressed by P11SCOPE_E16_QUIET=1); they are written whole
 * through the same e16_write_all and never carry protocol meaning.
 */
#ifndef P11SCOPE_E16_PROTOCOL_H
#define P11SCOPE_E16_PROTOCOL_H

/* Include this header before any system header: it selects the POSIX and
 * BSD interfaces (O_CLOEXEC, MAP_ANONYMOUS) that strict -std=c11 hides. */
#if !defined(_GNU_SOURCE) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define E16_EXIT_USAGE 2
#define E16_EXIT_CALL_FAILED 6
#define E16_EXIT_WRITE 90
#define E16_EXIT_FORMAT 91
#define E16_EXIT_GO_GATE 92
#define E16_EXIT_RELEASE_GATE 93
#define E16_EXIT_STARTTIME 94
#define E16_MAX_CALLS 1000000L

static inline void e16_write_all(const char *text, size_t length) {
    while (length > 0) {
        ssize_t written = write(STDERR_FILENO, text, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            _exit(E16_EXIT_WRITE);
        }
        text += written;
        length -= (size_t)written;
    }
}

__attribute__((format(printf, 1, 2))) static inline void e16_emitf(const char *format, ...) {
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0 || (size_t)length >= sizeof(line) || line[length - 1] != '\n') {
        _exit(E16_EXIT_FORMAT);
    }
    e16_write_all(line, (size_t)length);
}

static inline int e16_quiet(void) {
    const char *value = getenv("P11SCOPE_E16_QUIET");
    return value != NULL && strcmp(value, "1") == 0;
}

static inline int e16_hold_enabled(void) {
    const char *value = getenv("P11SCOPE_E16_HOLD");
    return value != NULL && strcmp(value, "1") == 0;
}

/* One byte, EINTR retried; a different byte, EOF or an error is fatal. */
static inline void e16_gate(unsigned char wanted, int failure) {
    if (!e16_hold_enabled()) {
        return;
    }
    unsigned char byte = 0;
    for (;;) {
        ssize_t got = read(STDIN_FILENO, &byte, 1);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got != 1 || byte != wanted) {
            _exit(failure);
        }
        return;
    }
}

static inline long e16_parse_count(const char *text) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 0 || value > E16_MAX_CALLS) {
        _exit(E16_EXIT_USAGE);
    }
    return value;
}

/* Field 22 of /proc/self/stat, parsed after the last ')' of the command. */
static inline unsigned long long e16_starttime(void) {
    char buffer[2048];
    size_t used = 0;
    int fd;
    do {
        fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        _exit(E16_EXIT_STARTTIME);
    }
    for (;;) {
        ssize_t got = read(fd, buffer + used, sizeof(buffer) - 1 - used);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got < 0) {
            _exit(E16_EXIT_STARTTIME);
        }
        if (got == 0) {
            break;
        }
        used += (size_t)got;
        if (used == sizeof(buffer) - 1) {
            _exit(E16_EXIT_STARTTIME);
        }
    }
    close(fd);
    buffer[used] = '\0';
    char *close_paren = strrchr(buffer, ')');
    if (close_paren == NULL) {
        _exit(E16_EXIT_STARTTIME);
    }
    /* After ')' come fields 3 (state) .. 22 (starttime): skip 19 fields. */
    char *cursor = close_paren + 1;
    for (int field = 3; field < 22; field++) {
        while (*cursor == ' ') {
            cursor++;
        }
        while (*cursor != ' ' && *cursor != '\0') {
            cursor++;
        }
        if (*cursor == '\0') {
            _exit(E16_EXIT_STARTTIME);
        }
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || value == 0 || (*end != ' ' && *end != '\n')) {
        _exit(E16_EXIT_STARTTIME);
    }
    return value;
}

static inline void e16_ready(uintptr_t endpoint, uintptr_t image, long calls) {
    e16_emitf("P11SCOPE_E16 ready pid=%ld starttime=%llu endpoint=0x%lx image=0x%lx calls=%ld\n",
              (long)getpid(), e16_starttime(), (unsigned long)endpoint, (unsigned long)image,
              calls);
}

static inline void e16_call(const char *label, long index, unsigned long rv) {
    e16_emitf("P11SCOPE_E16 call %s %ld rv=%lu\n", label, index, rv);
    if (rv != 0) {
        _exit(E16_EXIT_CALL_FAILED);
    }
}

static inline void e16_done(long calls) {
    e16_emitf("P11SCOPE_E16 done calls=%ld\n", calls);
}

/* A provider witness line, whole or not at all. */
static inline void e16_provider_witness(const char *kind, const char *name) {
    if (!e16_quiet()) {
        e16_emitf("P11SCOPE_E16 provider %s %s\n", kind, name);
    }
}

#endif
