/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Negative-only fixture. Gate facts are location/delivery witnesses, never ACKs. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static char line[256];
static size_t used;
static int overlong, consumed;

static uint64_t now_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static int owned_fd(const char *name) {
    const char *text = getenv(name);
    if (!text || !*text) return -1;
    unsigned value = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || value > 100000) return -1;
        value = value * 10 + (unsigned)(*text - '0');
    }
    struct stat info;
    int flags = fcntl((int)value, F_GETFL);
    if (value <= 2 || flags < 0 || !(flags & O_NONBLOCK) ||
        fstat((int)value, &info) || (!S_ISFIFO(info.st_mode) && !S_ISSOCK(info.st_mode))) return -1;
    return (int)value;
}

__attribute__((constructor)) static void close_gate_on_later_exec(void) {
    static const char *names[] = {"P11SCOPE_TEST_GATE_CONTROL_FD", "P11SCOPE_TEST_GATE_FACT_FD"};
    int saved = errno;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        int fd = owned_fd(names[i]);
        if (fd >= 0) (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    errno = saved;
}

static int fact(int fd, const char *kind) {
    char output[192];
    uint64_t stamp = now_ns();
    if (!stamp) return -1;
    int length = snprintf(output, sizeof(output),
        "{\"kind\":\"%s\",\"pid\":%ld,\"tid\":%ld,\"clock\":\"CLOCK_MONOTONIC\",\"t_ns\":%" PRIu64 "}\n",
        kind, (long)getpid(), syscall(SYS_gettid), stamp);
    if (length <= 0 || (size_t)length >= sizeof(output)) return -1;
    return syscall(SYS_write, fd, output, length) == length ? 0 : -1;
}

static void gate(void) {
    int control = owned_fd("P11SCOPE_TEST_GATE_CONTROL_FD");
    int facts = owned_fd("P11SCOPE_TEST_GATE_FACT_FD");
    if (control < 0 || facts < 0 || control == facts) return;
    sigset_t blocked, original;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    if (sigprocmask(SIG_BLOCK, &blocked, &original)) return;
    /* The gate's temporary mask is restored atomically for ppoll and on every
     * exit. No handler or process-wide signal disposition is replaced. */
    if (sigismember(&original, SIGINT) || fact(facts, "entered")) goto restore;
    uint64_t start = now_ns();
    if (!start) goto restore;
    int interrupted = 0;
    for (;;) {
        uint64_t now = now_ns();
        if (!now || now < start || now - start >= 15000000000ULL) break;
        uint64_t remaining = 15000000000ULL - (now - start);
        struct timespec timeout = {(time_t)(remaining / 1000000000), (long)(remaining % 1000000000)};
        struct pollfd wait = {control, POLLIN, 0};
        int result = ppoll(&wait, 1, &timeout, &original);
        if (result < 0 && errno == EINTR) {
            if (interrupted++ || fact(facts, "interrupted")) break;
            continue;
        }
        if (result <= 0 || wait.revents != POLLIN) break;
        char command[2];
        ssize_t length = syscall(SYS_read, control, command, sizeof(command));
        if (length == 1 && command[0] == 'R') {
            (void)fact(facts, "released");
            goto restore;
        }
        break;
    }
    (void)fact(facts, "error");
restore:
    (void)sigprocmask(SIG_SETMASK, &original, NULL);
}

static int readiness(void) {
    static const char prefix[] = "p11scope: capturing: ";
    static const char suffix[] = " probe(s) attached; stop with Ctrl-C\n";
    size_t at = sizeof(prefix) - 1;
    if (used <= at || memcmp(line, prefix, at) || line[at] < '1' || line[at] > '9') return 0;
    uint64_t count = 0;
    while (at < used && line[at] >= '0' && line[at] <= '9') {
        unsigned digit = (unsigned)(line[at++] - '0');
        if (count > (UINT64_MAX - digit) / 10) return 0;
        count = count * 10 + digit;
    }
    return count && used - at == sizeof(suffix) - 1 && !memcmp(line + at, suffix, sizeof(suffix) - 1);
}

static void forwarded(int fd, const void *data, size_t length) {
    /* Check thread ownership before touching any main-only parser state. */
    if (fd != STDERR_FILENO || syscall(SYS_gettid) != getpid()) return;
    if (consumed) return;
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; ++i) {
        if (used < sizeof(line)) line[used++] = (char)bytes[i];
        else overlong = 1;
        if (bytes[i] == '\n') {
            int matched = !overlong && readiness();
            used = 0;
            overlong = 0;
            if (matched) { consumed = 1; gate(); return; }
        }
    }
}

ssize_t write(int fd, const void *data, size_t length) {
    ssize_t result = syscall(SYS_write, fd, data, length);
    int saved = errno;
    if (result > 0) forwarded(fd, data, (size_t)result);
    errno = saved;
    return result;
}

ssize_t writev(int fd, const struct iovec *vectors, int count) {
    ssize_t result = syscall(SYS_writev, fd, vectors, count);
    int saved = errno;
    if (result > 0) {
        size_t remaining = (size_t)result;
        for (int i = 0; i < count && remaining; ++i) {
            size_t length = vectors[i].iov_len < remaining ? vectors[i].iov_len : remaining;
            forwarded(fd, vectors[i].iov_base, length);
            remaining -= length;
        }
    }
    errno = saved;
    return result;
}
