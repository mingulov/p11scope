/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned LP64 barrier fixture: an old call returns only after explicit release.
 * Build the provider with -DCOUNTER_BANK_PROVIDER; build its small dlopen driver
 * without that define. No timeout, timing-based release or PKCS#11 payload. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int exact_byte(int fd, unsigned char expected, int write_byte)
{
    unsigned char byte = expected;
    ssize_t done;
    do {
        done = write_byte ? write(fd, &byte, 1) : read(fd, &byte, 1);
    } while (done < 0 && errno == EINTR);
    return done == 1 && byte == expected ? 0 : -1;
}

#ifdef COUNTER_BANK_PROVIDER
__attribute__((noinline, visibility("default")))
unsigned long counter_bank_old(int entered_fd, int release_fd)
{
    if (exact_byte(entered_fd, 'E', 1) || exact_byte(release_fd, 'R', 0))
        return 5;
    return 0x204;
}

__attribute__((noinline, visibility("default")))
unsigned long counter_bank_hot(void)
{
    return 0x100000204UL;
}
#else
#include <dlfcn.h>
#include <pthread.h>

struct old_call {
    unsigned long (*function)(int, int);
    int entered_fd;
    int release_fd;
    unsigned long result;
};

static void *old_thread(void *opaque)
{
    struct old_call *call = opaque;
    call->result = call->function(call->entered_fd, call->release_fd);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2 || sizeof(unsigned long) != 8)
        return 2;
    void *provider = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!provider)
        return 3;
    unsigned long (*old)(int, int) = dlsym(provider, "counter_bank_old");
    unsigned long (*hot)(void) = dlsym(provider, "counter_bank_hot");
    int entered[2], release[2];
    if (!old || !hot || pipe(entered) || pipe(release))
        return 4;
    puts("READY");
    fflush(stdout);
    if (exact_byte(STDIN_FILENO, 'S', 0))
        return 5;
    struct old_call call = {old, entered[1], release[0], 0};
    pthread_t thread;
    if (pthread_create(&thread, NULL, old_thread, &call))
        return 5;
    if (exact_byte(entered[0], 'E', 0))
        return 6;
    puts("HELD");
    fflush(stdout);
    if (exact_byte(STDIN_FILENO, 'H', 0) || hot() != 0x100000204UL)
        return 7;
    puts("HOT");
    fflush(stdout);
    if (exact_byte(STDIN_FILENO, 'R', 0) || exact_byte(release[1], 'R', 1))
        return 8;
    if (pthread_join(thread, NULL) || call.result != 0x204)
        return 9;
    close(entered[0]);
    close(entered[1]);
    close(release[0]);
    close(release[1]);
    dlclose(provider);
    puts("DONE");
    return 0;
}
#endif
