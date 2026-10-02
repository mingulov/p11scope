/* SPDX-License-Identifier: GPL-3.0-or-later */
/* S1/F7b owned double-load fixture: one provider object, loaded twice.
 * Built twice from this file: `-DS1_DLMOPEN_PROVIDER -shared -fPIC`
 * yields the provider; without it, the driver, which takes the
 * provider path, `dlmopen`s it in two new namespaces, acks, and
 * sleeps until the test kills it. The observer never executes
 * provider code; only this owned driver maps it. No PKCS#11 call is
 * made. */

#ifdef S1_DLMOPEN_PROVIDER

__attribute__((visibility("default"))) int s1_double_load_marker(void) { return 0x51; }

#else

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *first = dlmopen(LM_ID_NEWLM, argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!first) {
        fprintf(stderr, "first dlmopen failed: %s\n", dlerror());
        return 3;
    }
    void *second = dlmopen(LM_ID_NEWLM, argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!second) {
        fprintf(stderr, "second dlmopen failed: %s\n", dlerror());
        return 4;
    }
    if (first == second) {
        fprintf(stderr, "the two namespaces returned one handle\n");
        return 5;
    }
    if (printf("READY %ld %p %p\n", (long)getpid(), first, second) < 0 ||
        fflush(stdout)) {
        return 6;
    }
    for (;;) pause();
    return 0;
}

#endif
