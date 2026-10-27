/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned ready;
static unsigned released;
static unsigned tids[2];

typedef unsigned long (*callback)(void *);
struct table { unsigned char version[2]; callback functions[68]; };

__attribute__((visibility("default"), noinline))
unsigned long C_Initialize(void *unused) {
    (void)unused;
    return 0;
}

static struct table sparse = {{3, 2}, {[0] = C_Initialize}};

__attribute__((visibility("default"), noinline))
unsigned long C_GetFunctionList(struct table **out) {
    if (!out) return 7;
    *out = &sparse;
    return 0;
}

static void *worker(void *argument) {
    unsigned index = *(unsigned *)argument;
    if (pthread_mutex_lock(&gate)) _exit(10);
    tids[index] = (unsigned)syscall(SYS_gettid);
    ready++;
    if (pthread_cond_broadcast(&changed)) _exit(11);
    while (!released)
        if (pthread_cond_wait(&changed, &gate)) _exit(12);
    if (pthread_mutex_unlock(&gate)) _exit(13);
    for (;;) {
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1) _exit(14);
        if (command == 'c') {
            struct table *table = NULL;
            if (C_GetFunctionList(&table) || !table || table->version[0] != 3 ||
                table->version[1] != 2 || !table->functions[0]) _exit(15);
            for (unsigned slot = 1; slot < 68; slot++)
                if (table->functions[slot]) _exit(16);
            for (unsigned call = 0; call < 3; call++)
                if (table->functions[0](NULL)) _exit(17);
            printf("CALLS tid=%u total=3\n", tids[index]);
            if (fflush(stdout)) _exit(18);
        } else if (command == 'x') {
            execl("/bin/sleep", "sleep", "30", (char *)NULL);
            _exit(25);
        } else if (command == 'e') {
            printf("EXIT tid=%u\n", tids[index]);
            if (fflush(stdout)) _exit(23);
            (void)syscall(SYS_exit, 0);
            _exit(24);
        } else {
            _exit(19);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned count = (unsigned)strtoul(argv[1], NULL, 10);
    if (count > 2) return 3;
    pthread_t threads[2];
    unsigned indices[2] = {0, 1};
    for (unsigned index = 0; index < count; index++)
        if (pthread_create(&threads[index], NULL, worker, &indices[index])) return 4;
    if (pthread_mutex_lock(&gate)) return 5;
    while (ready != count)
        if (pthread_cond_wait(&changed, &gate)) return 6;
    printf("READY tgid=%u count=%u tid0=%u tid1=%u table=%p callback=%p\n",
           (unsigned)getpid(), count, tids[0], tids[1], (void *)&sparse, (void *)C_Initialize);
    if (fflush(stdout)) return 7;
    if (pthread_mutex_unlock(&gate)) return 8;
    char command;
    if (read(STDIN_FILENO, &command, 1) != 1 || command != 'l') return 9;
    if (pthread_mutex_lock(&gate)) return 20;
    released = 1;
    if (pthread_cond_broadcast(&changed)) return 21;
    if (pthread_mutex_unlock(&gate)) return 22;
    if (count) pthread_exit(NULL);
    return 0;
}
