/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private discovery test: a file-backed 2.40 table and an acknowledged loader.
 * The observer never executes provider code; only this owned test driver and
 * the test's offline manifest helper do. No ordinary PKCS#11 call is made. */
#include <stddef.h>

struct function_table {
    unsigned char major, minor;
    void *functions[68];
};

#ifdef DISCOVERY_LIFECYCLE_PROVIDER

unsigned long C_GetFunctionList(void **out);
static unsigned long ok(void) { return 0; }
#define P ((void *)ok)
#define P8 P, P, P, P, P, P, P, P
/* Static initialization deliberately places the complete table in file-backed
 * data. This test does not ask the scanner to discover arbitrary heap tables. */
static struct function_table table = {
    2, 40, {P, P, P, (void *)C_GetFunctionList,
            P8, P8, P8, P8, P8, P8, P8, P8}
};

unsigned long C_GetFunctionList(void **out) {
    if (!out) return 7;
    *out = &table;
    return 0;
}

#else

#include <dlfcn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (printf("READY %ld\n", (long)getpid()) < 0 || fflush(stdout)) return 3;
    if (getchar() != 'L') return 4;

    struct stat identity;
    if (stat(argv[1], &identity)) return 5;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 6;
    unsigned long (*acquire)(void **) = dlsym(handle, "C_GetFunctionList");
    void *raw_table = NULL;
    if (!acquire || acquire(&raw_table) || !raw_table) return 7;
    const struct function_table *loaded = raw_table;
    if (loaded->major != 2 || loaded->minor != 40) return 8;
    for (size_t i = 0; i < 68; ++i) if (!loaded->functions[i]) return 9;
    if (printf("LOADED %ld %llu %llu 68\n", (long)getpid(),
               (unsigned long long)identity.st_dev,
               (unsigned long long)identity.st_ino) < 0 || fflush(stdout)) return 10;

    if (getchar() != 'X') return 11;
    if (dlclose(handle)) return 12;
    return 0;
}

#endif
