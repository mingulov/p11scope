/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Unprivileged interposer controls only, never product/cancellation evidence. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static const char line[] = "p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C\n";
static volatile sig_atomic_t handled;
static void on_signal(int signal) { if (signal == SIGINT) ++handled; }
static void *worker(void *unused) {
    (void)unused;
    return (void *)(long)(write(2, line, sizeof(line) - 1) != sizeof(line) - 1);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct sigaction action = {0};
    action.sa_handler = on_signal;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL)) return 3;
    ssize_t first = 0;
    errno = EDOM;
    if (!strcmp(argv[1], "split")) {
        if (write(2, line, 12) != 12 || write(2, line + 12, sizeof(line) - 13) != sizeof(line) - 13) return 4;
    } else if (!strcmp(argv[1], "writev")) {
        struct iovec parts[] = {{(void *)line, 12}, {(void *)(line + 12), 9},
                               {(void *)(line + 21), sizeof(line) - 22}};
        if (writev(2, parts, 3) != sizeof(line) - 1) return 5;
    } else if (!strcmp(argv[1], "partial")) {
        char prefix[4090];
        memset(prefix, '\n', sizeof(prefix));
        struct iovec parts[] = {{prefix, sizeof(prefix)}, {(void *)line, sizeof(line) - 1}};
        first = writev(2, parts, 2);
        if (first != 4096) return 6;
        size_t offset = (size_t)first - sizeof(prefix);
        while (offset < sizeof(line) - 1) {
            errno = EDOM;
            ssize_t sent = write(2, line + offset, sizeof(line) - 1 - offset);
            if (sent < 0 && errno == EAGAIN) continue;
            if (sent <= 0) return 7;
            offset += (size_t)sent;
        }
    } else if (!strcmp(argv[1], "wrongfd")) {
        if (write(1, line, sizeof(line) - 1) != sizeof(line) - 1) return 8;
    } else if (!strcmp(argv[1], "wrongtid")) {
        pthread_t thread;
        void *result;
        if (pthread_create(&thread, NULL, worker, NULL) || pthread_join(thread, &result) || result) return 9;
        errno = EDOM;
    } else if (!strcmp(argv[1], "prefix")) {
        if (write(2, line, 20) != 20) return 10;
    } else if (!strcmp(argv[1], "zero")) {
        const char invalid[] = "p11scope: capturing: 0 probe(s) attached; stop with Ctrl-C\n";
        if (write(2, invalid, sizeof(invalid) - 1) != sizeof(invalid) - 1) return 11;
    } else if (!strcmp(argv[1], "whole")) {
        if (write(2, line, sizeof(line) - 1) != sizeof(line) - 1) return 12;
    } else return 13;
    int saved = errno;
    const char *control = getenv("P11SCOPE_TEST_GATE_CONTROL_FD");
    const char *facts = getenv("P11SCOPE_TEST_GATE_FACT_FD");
    int control_flags = control ? fcntl(atoi(control), F_GETFD) : -1;
    int fact_flags = facts ? fcntl(atoi(facts), F_GETFD) : -1;
    int cloexec = control_flags >= 0 && fact_flags >= 0 &&
                  (control_flags & FD_CLOEXEC) && (fact_flags & FD_CLOEXEC);
    sigset_t mask;
    if (sigprocmask(SIG_SETMASK, NULL, &mask)) return 14;
    printf("{\"returned\":true,\"handled\":%d,\"errno\":%d,\"sigint_blocked\":%d,\"first_write\":%zd,\"gate_cloexec\":%d}\n",
           handled, saved, sigismember(&mask, SIGINT), first, cloexec);
    return 0;
}
