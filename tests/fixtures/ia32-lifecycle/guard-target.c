#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *record = getenv("IA32_GUARD_TEST_RECORD");
    int signal_number = 0;
    FILE *stream;
    char path[4096];
    int byte;
    unsigned int lifetime;
    struct stat metadata;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};

    if (record == NULL || argc != 6) return 90;
    lifetime = (unsigned int)strtoul(getenv("IA32_GUARD_TEST_SECONDS") != NULL
                                        ? getenv("IA32_GUARD_TEST_SECONDS")
                                        : "12",
                                    NULL, 10);
    if (lifetime == 0 || lifetime > 60) return 89;
    alarm(lifetime);
    if (prctl(PR_GET_PDEATHSIG, &signal_number) != 0) return 91;
    if (snprintf(path, sizeof(path), "%s.result", record) >= (int)sizeof(path)) return 92;
    stream = fopen(path, "wx");
    if (stream == NULL) return 93;
    fprintf(stream, "pid=%ld\npdeath=%d\n", (long)getpid(), signal_number);
    for (int i = 0; i < argc; i++) fprintf(stream, "argv%d=%s\n", i, argv[i]);
    while ((byte = getchar()) != EOF) fputc(byte, stream);
    if (fclose(stream) != 0) return 94;
    if (snprintf(path, sizeof(path), "%s.ready", record) >= (int)sizeof(path)) return 95;
    stream = fopen(path, "wx");
    if (stream == NULL || fclose(stream) != 0) return 96;
    if (snprintf(path, sizeof(path), "%s.acquired", record) >= (int)sizeof(path)) return 97;
    while (stat(path, &metadata) != 0) {
        if (errno != ENOENT) return 98;
        if (nanosleep(&delay, NULL) != 0 && errno != EINTR) return 99;
    }
    for (;;) pause();
}
