/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Owned identity-dataonly fixture: map a provider file data-only, then sleep.
 *
 *   identity-dataonly --ready <file> [--sleep <secs>] <provider.so>
 *
 * mmaps the provider PROT_READ|MAP_PRIVATE (never PROT_EXEC), appends
 * "READY <pid>" to the ready file, then sleeps so the observer can scan
 * this process. A data-only mapping must never produce a caller edge:
 * the no-exec negative for D3d sweep proof.
 *
 * Exit codes: 0 ready (after sleeping), 2 usage, 3 map failure,
 * 5 the ready file could not be written.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *ready = NULL;
    const char *path = NULL;
    unsigned sleep_secs = 120;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--ready") && i + 1 < argc) {
            ready = argv[++i];
        } else if (!strcmp(argv[i], "--sleep") && i + 1 < argc) {
            sleep_secs = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--help")) {
            printf("usage: identity-dataonly --ready <file> [--sleep <secs>] <provider.so>\n");
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "identity-dataonly: unknown flag %s\n", argv[i]);
            return 2;
        } else if (!path) {
            path = argv[i];
        } else {
            fprintf(stderr, "identity-dataonly: unexpected %s\n", argv[i]);
            return 2;
        }
    }
    if (!ready || !path) {
        fprintf(stderr, "usage: identity-dataonly --ready <file> <provider.so>\n");
        return 2;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("identity-dataonly: open");
        return 3;
    }
    struct stat meta;
    if (fstat(fd, &meta) || meta.st_size <= 0) {
        perror("identity-dataonly: fstat");
        close(fd);
        return 3;
    }
    void *map = mmap(NULL, (size_t)meta.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("identity-dataonly: mmap");
        close(fd);
        return 3;
    }
    FILE *out = fopen(ready, "a");
    if (!out) {
        perror("identity-dataonly: ready");
        munmap(map, (size_t)meta.st_size);
        close(fd);
        return 5;
    }
    fprintf(out, "READY %ld\n", (long)getpid());
    fclose(out);
    /* Prove the mapping stays data-only: re-read our own maps. */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[4096];
        while (fgets(line, sizeof line, maps)) {
            if (strstr(line, path) && line[3] == 'x') {
                fprintf(stderr, "identity-dataonly: provider has an exec mapping\n");
                fclose(maps);
                munmap(map, (size_t)meta.st_size);
                close(fd);
                return 3;
            }
        }
        fclose(maps);
    }
    sleep(sleep_secs);
    munmap(map, (size_t)meta.st_size);
    close(fd);
    return 0;
}
