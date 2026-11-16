/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* In-place downgrade (A′) tight-loop fixture. Build once as a DSO and once
 * as its owned driver. The driver runs scripted C_Initialize bursts; one
 * call per burst gates inside the provider so the test can downgrade the
 * slot while a call is provably in flight (entered but not returned).
 * Line protocol over stdin/stdout (unbuffered reads; no stdio buffering):
 *   driver emits: READY <pid> <dev> <ino>
 *   parent sends: GO <count>
 *   driver calls C_Initialize <count> times (exactly one call per
 *   burst gates: the call at index <count>/2);
 *   the gated call emits HELD, waits for one continue byte, then returns;
 *   driver emits: DONE <count>
 *   parent sends: F
 *   driver exits 0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

struct request {
    unsigned long rv;
    unsigned long gate;
};

#ifdef DOWNGRADE_TIGHT_LOOP_PROVIDER

static void write_all(int fd, const char *buffer, size_t count) {
    size_t done = 0;
    while (done < count) {
        ssize_t wrote = write(fd, buffer + done, count - done);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            _exit(20);
        }
        if (wrote == 0) _exit(21);
        done += (size_t)wrote;
    }
}

unsigned long C_Initialize(void *argument) {
    struct request *request = argument;
    if (request && request->gate) {
        static const char held[] = "HELD\n";
        write_all(STDOUT_FILENO, held, sizeof(held) - 1);
        char line[16];
        size_t done = 0;
        for (;;) {
            if (done >= sizeof(line)) _exit(22);
            char byte = 0;
            ssize_t got = read(STDIN_FILENO, &byte, 1);
            if (got < 0) {
                if (errno == EINTR) continue;
                _exit(23);
            }
            if (got == 0) _exit(24);
            if (byte == '\n') break;
            line[done++] = byte;
        }
        if (done != 1 || line[0] != 'C') _exit(25);
    }
    return request ? request->rv : 0;
}

#else

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef unsigned long (*call_fn)(void *);

static void fail(int code) {
    _exit(code);
}

static void write_all(int fd, const char *buffer, size_t count) {
    size_t done = 0;
    while (done < count) {
        ssize_t wrote = write(fd, buffer + done, count - done);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            fail(30);
        }
        if (wrote == 0) fail(31);
        done += (size_t)wrote;
    }
}

/* One unbuffered line (no stdio: the provider shares stdin while gated). */
static size_t read_line(char *buffer, size_t capacity) {
    size_t done = 0;
    for (;;) {
        if (done + 1 >= capacity) fail(32);
        char byte = 0;
        ssize_t got = read(STDIN_FILENO, &byte, 1);
        if (got < 0) {
            if (errno == EINTR) continue;
            fail(33);
        }
        if (got == 0) fail(34);
        if (byte == '\n') break;
        buffer[done++] = byte;
    }
    buffer[done] = '\0';
    return done;
}

static void emit3(const char *tag, unsigned long a, unsigned long b, unsigned long c) {
    char line[128];
    int length = snprintf(line, sizeof(line), "%s %lu %lu %lu\n", tag, a, b, c);
    if (length < 0 || (size_t)length >= sizeof(line)) fail(35);
    write_all(STDOUT_FILENO, line, (size_t)length);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *provider = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!provider) return 3;
    call_fn call = (call_fn)dlsym(provider, "C_Initialize");
    struct stat physical;
    if (!call || stat(argv[1], &physical)) return 4;
    emit3("READY", (unsigned long)getpid(), (unsigned long)physical.st_dev,
          (unsigned long)physical.st_ino);
    char line[128];
    for (;;) {
        read_line(line, sizeof(line));
        if (line[0] == 'F' && line[1] == '\0') break;
        if (line[0] != 'G' || line[1] != 'O' || line[2] != ' ') fail(36);
        char *end = NULL;
        errno = 0;
        unsigned long count = strtoul(line + 3, &end, 10);
        if (errno || !end || *end || count == 0 || count > 1000000) fail(37);
        unsigned long gate_at = count / 2;
        for (unsigned long i = 0; i < count; ++i) {
            struct request request = { .rv = (i & 1) ? 5 : 0, .gate = (i == gate_at) };
            unsigned long rv = call(&request);
            if (rv != request.rv) fail(38);
        }
        char done[64];
        int length = snprintf(done, sizeof(done), "DONE %lu\n", count);
        if (length < 0 || (size_t)length >= sizeof(done)) fail(39);
        write_all(STDOUT_FILENO, done, (size_t)length);
    }
    if (dlclose(provider)) return 5;
    return 0;
}

#endif
