/* SPDX-License-Identifier: GPL-3.0-or-later */
/* shape-probe: read a provider's published table shape without judging it.
 * usage: shape-probe PROVIDER.so
 * Prints fact lines; the cell script judges them against expectations:
 *   VERSION <major> <minor>     table version word
 *   NONNULL68 <n>                non-NULL slots among ordinals 0..67
 *   DISTINCT68 <0|1>             first 68 slots all non-NULL and pairwise distinct
 *   SLOT68 <hex>                 word at ordinal 68 (tail guard, or ambient bytes)
 *   GATED6 <0|1>                 gated.c ordinals 64,37,38,26,27,28 non-NULL+distinct
 *   GETTER_SLOT <0|1>            slot 3 equals the exported C_GetFunctionList
 *   INTERFACES <0|1>             1 when C_GetInterface/List resolves (must be 0)
 * Exit 0 on a complete read, 1 when the provider cannot be read this way.
 * x86-64 LP64 only, like its fixture. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    void *handle, *list = 0, *getter;
    unsigned long (*gfl)(void **);
    unsigned char *base;
    unsigned long *slots;
    int i, j, distinct = 1, gated = 1, getter_ok = 0;
    long nonnull = 0;
    static const int gated_ordinals[] = {64, 37, 38, 26, 27, 28};

    if (argc != 2) {
        fprintf(stderr, "usage: shape-probe PROVIDER.so\n");
        return 1;
    }
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    gfl = (unsigned long (*)(void **))dlsym(handle, "C_GetFunctionList");
    if (!gfl || gfl(&list) || !list) {
        fprintf(stderr, "C_GetFunctionList unavailable\n");
        return 1;
    }
    base = (unsigned char *)list;
    slots = (unsigned long *)(base + 8);
    printf("VERSION %u %u\n", base[0], base[1]);
    for (i = 0; i < 68; i++)
        nonnull += slots[i] != 0;
    printf("NONNULL68 %ld\n", nonnull);
    for (i = 0; i < 68 && distinct; i++) {
        if (!slots[i])
            distinct = 0;
        for (j = i + 1; j < 68; j++) {
            if (slots[i] == slots[j])
                distinct = 0;
        }
    }
    printf("DISTINCT68 %d\n", distinct);
    printf("SLOT68 0x%lx\n", slots[68]);
    for (i = 0; i < 6 && gated; i++) {
        if (!slots[gated_ordinals[i]])
            gated = 0;
        for (j = i + 1; j < 6; j++) {
            if (slots[gated_ordinals[i]] == slots[gated_ordinals[j]])
                gated = 0;
        }
    }
    printf("GATED6 %d\n", gated);
    getter = dlsym(handle, "C_GetFunctionList");
    getter_ok = getter != 0 && slots[3] == (unsigned long)getter;
    printf("GETTER_SLOT %d\n", getter_ok);
    printf("INTERFACES %d\n", dlsym(handle, "C_GetInterface") != 0 ||
                   dlsym(handle, "C_GetInterfaceList") != 0);
    return 0;
}
