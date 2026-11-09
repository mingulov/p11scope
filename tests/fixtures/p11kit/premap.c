/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* premap: constructor-only helper that maps provider files RTLD_LOCAL.
 *
 * Used via LD_PRELOAD where a --system capture needs a provider mapped
 * before attach (the observer arms no loader hooks): it maps the same
 * files the proxy later dlopens (refcount only) without exporting any
 * PKCS#11 symbol itself and without promoting the provider into the
 * global scope. Global promotion must be avoided: with OpenSC 0.27.1's
 * spy, a globally visible provider makes the spy's C_GetInterface return
 * direct provider pointers, so every later call bypasses the spy and the
 * ground-truth log holds one block (observed on Fedora; Ubuntu's
 * 0.27.0~rc1 wraps regardless). RTLD_LOCAL keeps the spy in the path.
 *
 * $P11KIT_PREMAPPED holds colon-separated absolute paths (at most 8).
 * A mapping failure is fatal (_exit 127): a silently unmapped provider
 * would fail the "not mapped in the target" check downstream.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PREMAPPED 8

static void *held[MAX_PREMAPPED];
static int held_count;

__attribute__((constructor)) static void premap(void) {
    const char *list = getenv("P11KIT_PREMAPPED");
    if (list == NULL || *list == '\0')
        return;
    char *copy = strdup(list);
    if (copy == NULL) {
        (void)fprintf(stderr, "premap: out of memory\n");
        _exit(127);
    }
    char *save = NULL;
    for (char *path = strtok_r(copy, ":", &save); path != NULL;
         path = strtok_r(NULL, ":", &save)) {
        if (held_count >= MAX_PREMAPPED) {
            (void)fprintf(stderr, "premap: too many paths (max %d)\n", MAX_PREMAPPED);
            _exit(127);
        }
        (void)dlerror();
        void *handle = dlopen(path, RTLD_LOCAL | RTLD_LAZY);
        if (handle == NULL) {
            (void)fprintf(stderr, "premap: cannot map %s: %s\n", path, dlerror());
            _exit(127);
        }
        held[held_count++] = handle;
    }
    free(copy);
}
