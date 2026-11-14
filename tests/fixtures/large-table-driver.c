/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Owned large-table fixture driver: map big-table objects, optionally load a
 * provider, then sleep for the observer.
 *
 *   large-table-driver <ready> --map <file> [--map <file> ...]
 *                    [--provider <provider.so>]
 *
 * Every --map file is mapped whole (read+execute, private) so the observer's
 * scan sees it as a candidate object. --provider is dlopened (RTLD_NOW) so a
 * real PKCS#11 provider joins the scan after the mapped objects. "READY" goes
 * to the ready file, then the process sleeps so the caller can SIGSTOP it.
 * The target maps its own inputs; it never reads observer output.
 *
 * Exit codes: 0 not reached (sleeps), 2 usage, 3 map failure, 4 dlopen
 * failure, 5 the ready file could not be written.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void map_whole(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) exit(3);
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size <= 0) exit(3);
    void *mapped = mmap(NULL, (size_t)info.st_size, PROT_READ | PROT_EXEC,
                        MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) exit(3);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *ready = argv[1];
    for (int index = 2; index < argc; index += 2) {
        if (index + 1 >= argc) return 2;
        if (!strcmp(argv[index], "--map")) {
            map_whole(argv[index + 1]);
        } else if (!strcmp(argv[index], "--provider")) {
            if (!dlopen(argv[index + 1], RTLD_NOW | RTLD_LOCAL)) return 4;
        } else {
            return 2;
        }
    }
    FILE *file = fopen(ready, "w");
    if (!file) return 5;
    fputs("ready\n", file);
    fclose(file);
    for (;;) pause();
}
