/* SPDX-License-Identifier: GPL-3.0-or-later */
/* chain-parent: named launcher for launcher-chain tests.
 * Usage: chain-parent CLIENT_BIN MODULE READY GATE
 * Forks and execs the client, waits for it, and exits with its status,
 * so the client has a stable, distinct parent exe name ("chain-parent"). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s CLIENT_BIN MODULE READY GATE\n", argv[0]);
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 3;
    }
    if (child == 0) {
        execl(argv[1], argv[1], argv[2], argv[3], argv[4], (char *)NULL);
        perror("exec client");
        _exit(127);
    }
    int status = 0;
    pid_t got;
    do {
        got = waitpid(child, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got < 0) {
        perror("waitpid");
        return 3;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 3;
}
