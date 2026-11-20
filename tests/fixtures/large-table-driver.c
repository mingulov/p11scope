/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Owned large-table fixture driver: map big-table objects, optionally load a
 * provider, then sleep for the observer.
 *
 *   large-table-driver <ready> --map <file> [--map <file> ...]
 *                    [--provider <provider.so>]
 *                    [--reload-cmd <file> --reload-ready <file>]
 *
 * Every --map file is mapped whole (read+execute, private) so the observer's
 * scan sees it as a candidate object. --provider is dlopened (RTLD_NOW) so a
 * real PKCS#11 provider joins the scan after the mapped objects. "READY" goes
 * to the ready file, then the process sleeps so the caller can SIGSTOP it.
 * With --reload-cmd/--reload-ready, READY1 is followed by a reload
 * handshake instead of sleep: the driver waits for one command byte,
 * closes and reopens every provider (same files, fresh addresses: pins
 * held from an earlier pass survive while decode cursors miss), writes
 * READY2, then sleeps for SIGSTOP. The target maps its own inputs; it
 * never reads observer output.
 *
 * Exit codes: 0 not reached (sleeps), 2 usage, 3 map failure, 4 dlopen
 * failure, 5 a ready file could not be written, 6 the reload command
 * never arrived, 7 a reload reopen failed, 8 a reload spacer failed.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
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

#define MAX_PROVIDERS 64

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *ready = argv[1];
    const char *provider_paths[MAX_PROVIDERS];
    void *provider_handles[MAX_PROVIDERS];
    int provider_count = 0;
    const char *reload_cmd = NULL;
    const char *reload_ready = NULL;
    for (int index = 2; index < argc; index += 2) {
        if (index + 1 >= argc) return 2;
        if (!strcmp(argv[index], "--map")) {
            map_whole(argv[index + 1]);
        } else if (!strcmp(argv[index], "--provider")) {
            if (provider_count >= MAX_PROVIDERS) return 2;
            provider_handles[provider_count] =
                dlopen(argv[index + 1], RTLD_NOW | RTLD_LOCAL);
            if (!provider_handles[provider_count]) return 4;
            provider_paths[provider_count] = argv[index + 1];
            provider_count++;
        } else if (!strcmp(argv[index], "--reload-cmd")) {
            reload_cmd = argv[index + 1];
        } else if (!strcmp(argv[index], "--reload-ready")) {
            reload_ready = argv[index + 1];
        } else {
            return 2;
        }
    }
    FILE *file = fopen(ready, "w");
    if (!file) return 5;
    fputs("ready\n", file);
    fclose(file);
    if (reload_cmd && reload_ready) {
        for (int waited = 0;; waited++) {
            FILE *cmd = fopen(reload_cmd, "r");
            int byte = cmd ? fgetc(cmd) : EOF;
            if (cmd) fclose(cmd);
            if (byte != EOF) break;
            if (waited >= 120000) return 6;
            usleep(1000);
        }
        /* Record every base, close everything (each fixture was opened
         * once, so the count drops to zero and unloads), then pin the
         * freed holes with fixed spacers: a bare close+reopen would
         * reuse the same addresses, but the test needs fresh ones (pins
         * hold by file while decode cursors miss by layout). The one-page
         * spacers stay mapped; they are anonymous and unmapped-adjacent,
         * never scanned. */
        uintptr_t bases[MAX_PROVIDERS];
        for (int index = 0; index < provider_count; index++) {
            struct link_map *map = NULL;
            if (dlinfo(provider_handles[index], RTLD_DI_LINKMAP, &map) != 0) return 8;
            bases[index] = (uintptr_t)map->l_addr;
        }
        for (int index = provider_count - 1; index >= 0; index--) {
            dlclose(provider_handles[index]);
        }
        for (int index = 0; index < provider_count; index++) {
            void *spacer = mmap((void *)bases[index], 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (spacer == MAP_FAILED) return 8;
            (void)spacer;
        }
        for (int index = 0; index < provider_count; index++) {
            provider_handles[index] =
                dlopen(provider_paths[index], RTLD_NOW | RTLD_LOCAL);
            if (!provider_handles[index]) return 7;
        }
        FILE *done = fopen(reload_ready, "w");
        if (!done) return 5;
        fputs("ready\n", done);
        fclose(done);
    }
    for (;;) pause();
}
