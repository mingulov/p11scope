/* SPDX-License-Identifier: GPL-3.0-or-later */
/* static-head: provider-free genuine fresh-EXEC head for the T8/G18 live256
 * pressure workload preparation (lane D). Preparation only; see README.md.
 *
 * usage: static-head GATEFILE
 *   GATEFILE  gate path ("-" = no gate: ledger immediately, then hold)
 *
 * The head's only job is to be a genuine fresh process whose real kernel
 * sched_process_exec record the observer must queue as the 256th request key
 * behind the retained prefix, preserving FIFO. It deliberately maps and calls
 * NO provider: no dlopen, no PKCS#11 surface, no function list. Provider-free
 * views stay unarmed in multi-process scopes, so servicing this head's queued
 * request consumes no loader ticket (see the ticket-257 analysis in
 * README.md). Build static when the toolchain allows it; the unprivileged
 * self-check (check.sh) verifies the running head maps no provider either
 * way by reading its own /proc/PID/maps.
 *
 * Protocol (stdout):
 *   READY pid=N
 *   LEDGER {"schema":"p11scope/pressure-live-head/v1","pid":N,
 *     "provider_free":true}
 * then hold until SIGTERM/SIGINT and exit 0. The LEDGER line is emitted
 * before the hold so the orchestrator can join liveness without waiting for
 * the episode to end; provider-freedom is proved from /proc, never from
 * this self-report alone.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void on_signal(int number) {
    (void)number;
    stop = 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: static-head GATEFILE\n");
        return 2;
    }
    const char *gate = argv[1];
    int gated = strcmp(gate, "-") != 0;

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (gated) {
        while (access(gate, F_OK) != 0 && !stop) {
            usleep(10000);
        }
        if (stop) {
            return 1;
        }
    }
    printf("LEDGER {\"schema\":\"p11scope/pressure-live-head/v1\",\"pid\":%d,"
           "\"provider_free\":true}\n",
           (int)getpid());
    fflush(stdout);
    while (!stop) {
        pause();
    }
    return 0;
}
