/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Isolated orphan reaper for the fixture orphan-policy twins.
 *
 *   orphan-reaper <pidfile> <reaped-file> -- <observer argv...>
 *
 * Registers as a child subreaper, spawns the choreographed observer,
 * waits for it, then reaps the orphaned driver whose pid the observer
 * recorded. The twins previously depended on whatever ancestor (PID 1
 * or an unrelated subreaper) adopted the orphan; a slow adopter left
 * a correctly-killed driver in Z past the assertion window. The
 * reaped file proves THIS helper did the reaping.
 *
 * Exit codes: 0 reaped (writes the REAPED line), 2 usage, 6 setup or
 * task failure, 7 observer failed, 8 driver pid unknown, 9 driver
 * adopted elsewhere, 10 driver not reaped within the deadline (the
 * driver is SIGKILLed first, best effort, so a failed twin leaks no
 * sleeper).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("orphan-reaper: clock_gettime");
        exit(6);
    }
    return (unsigned long long)now.tv_sec * 1000ULL +
        (unsigned long long)now.tv_nsec / 1000000ULL;
}

static void sleep_ms(unsigned ms)
{
    struct timespec span = {
        .tv_sec = (time_t)(ms / 1000),
        .tv_nsec = (long)(ms % 1000) * 1000000L,
    };
    while (nanosleep(&span, &span) != 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv)
{
    if (argc < 5 || strcmp(argv[3], "--") != 0) {
        fprintf(stderr, "usage: %s <pidfile> <reaped-file> -- <observer argv...>\n",
                argv[0]);
        return 2;
    }
    const char *pidfile = argv[1];
    const char *reaped_path = argv[2];
    char **observer = &argv[4];

    /* Adopt whatever the observer orphans: this helper is the nearest
     * subreaper above the driver, so adoption is deterministic
     * regardless of the outer ancestry. */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        perror("orphan-reaper: PR_SET_CHILD_SUBREAPER");
        return 6;
    }
    pid_t shell = fork();
    if (shell == 0) {
        execvp(observer[0], observer);
        perror("orphan-reaper: exec observer");
        _exit(127);
    }
    if (shell < 0) {
        perror("orphan-reaper: fork");
        return 6;
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(shell, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != shell) {
        perror("orphan-reaper: waitpid observer");
        return 6;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "orphan-reaper: observer exited %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 7;
    }
    /* The observer records the driver pid before staging sync, and the
     * twin releases the observer only after sync — so the pid file
     * exists once the observer is gone. Poll briefly anyway. */
    pid_t driver = -1;
    unsigned long long deadline = now_ms() + 5000ULL;
    while (now_ms() < deadline) {
        FILE *file = fopen(pidfile, "r");
        if (file != NULL) {
            long pid = -1;
            if (fscanf(file, "%ld", &pid) == 1 && pid > 0 && pid <= 4194304)
                driver = (pid_t)pid;
            fclose(file);
            if (driver > 0)
                break;
        }
        sleep_ms(10);
    }
    if (driver <= 0) {
        fprintf(stderr, "orphan-reaper: no driver pid in %s\n", pidfile);
        return 8;
    }
    /* Reap the orphan with a bounded wait: a surviving driver (a real
     * twin failure) must fail the helper, not hang the suite. */
    deadline = now_ms() + 30000ULL;
    for (;;) {
        int driver_status = 0;
        pid_t reaped = waitpid(driver, &driver_status, WNOHANG);
        if (reaped == driver) {
            FILE *out = fopen(reaped_path, "w");
            if (out == NULL) {
                perror("orphan-reaper: write reaped file");
                return 6;
            }
            if (WIFEXITED(driver_status))
                fprintf(out, "REAPED %d exit=%d\n", (int)driver,
                        WEXITSTATUS(driver_status));
            else if (WIFSIGNALED(driver_status))
                fprintf(out, "REAPED %d signal=%d\n", (int)driver,
                        WTERMSIG(driver_status));
            else
                fprintf(out, "REAPED %d status=%d\n", (int)driver, driver_status);
            if (fclose(out) != 0) {
                perror("orphan-reaper: write reaped file");
                return 6;
            }
            return 0;
        }
        if (reaped < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD) {
                /* Not our child: adopted elsewhere (or never
                 * spawned). Distinguish a live stranger from a
                 * vanished pid so the twin reports the real state. */
                char proc[64];
                snprintf(proc, sizeof proc, "/proc/%d/status", (int)driver);
                if (access(proc, F_OK) == 0) {
                    fprintf(stderr, "orphan-reaper: driver %d adopted elsewhere\n",
                            (int)driver);
                    return 9;
                }
                fprintf(stderr, "orphan-reaper: driver %d already gone\n",
                        (int)driver);
                return 9;
            }
            perror("orphan-reaper: waitpid driver");
            return 6;
        }
        if (now_ms() >= deadline) {
            kill(driver, SIGKILL);
            /* One last bounded reap so the failure path still cleans up. */
            unsigned long long grace = now_ms() + 5000ULL;
            while (now_ms() < grace) {
                int tired = 0;
                pid_t last = waitpid(driver, &tired, WNOHANG);
                if (last == driver || (last < 0 && errno != EINTR))
                    break;
                sleep_ms(10);
            }
            fprintf(stderr, "orphan-reaper: driver %d not reaped within 30s\n",
                    (int)driver);
            return 10;
        }
        sleep_ms(10);
    }
}
