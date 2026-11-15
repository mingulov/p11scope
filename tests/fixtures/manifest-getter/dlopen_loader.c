/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Loads a shared object that embeds a PKCS#11 provider without exporting
 * any PKCS#11 symbol, after the capture started, then runs it.
 *
 * Usage: dlopen_loader LIBRARY N list|interface|both
 *
 * Protocol (stdin gate bytes, stdout lines):
 *   LOADER pid=<pid>          then waits for 'L'
 *   (dlopen LIBRARY, then its getter_app_main(N, mode) runs the
 *    static_getter_app.c protocol: READY, 'G', PUBLISHED, 'C', DONE, 'X')
 *
 * The library is static_getter_app.c built with
 *   cc -std=c11 -O2 -fPIC -shared -Dmain=getter_app_main \
 *      -Wl,--version-script=embedded.map
 * so only getter_app_main is exported.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: dlopen_loader LIBRARY N list|interface|both\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("LOADER pid=%ld\n", (long)getpid());
    char byte = 0;
    for (;;) {
        ssize_t got = read(STDIN_FILENO, &byte, 1);
        if (got == 1 && byte == 'L') {
            break;
        }
        if (got <= 0) {
            return 3;
        }
    }
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 6;
    }
    int (*entry)(int, char **) = NULL;
    *(void **)&entry = dlsym(library, "getter_app_main");
    if (entry == NULL) {
        return 7;
    }
    char *args[] = {argv[0], argv[2], argv[3], NULL};
    return entry(3, args);
}
