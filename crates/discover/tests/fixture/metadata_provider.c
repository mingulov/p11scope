/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Metadata faults must not erase readable function words. */
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef META_MAJOR
#define META_MAJOR 2
#endif
#ifndef META_MINOR
#define META_MINOR 0
#endif
#ifndef META_HEADER_UNREADABLE
#define META_HEADER_UNREADABLE 0
#endif
#ifndef META_WORDS
#define META_WORDS 68
#endif
#ifndef META_INTERFACE
#define META_INTERFACE 0
#endif

typedef struct { unsigned char major, minor; } Version;
typedef struct { Version version; void *functions[68]; } Table;
static unsigned long initialize(void) { return 0; }
static unsigned long sign(void) { return 0; }
static Table table;
static void *published;

#if META_INTERFACE
__attribute__((visibility("hidden")))
#endif
unsigned long C_GetFunctionList(void **out) {
    if (!published) {
        table.version = (Version){META_MAJOR, META_MINOR};
        table.functions[0] = initialize;
        table.functions[43] = sign;
        if (META_HEADER_UNREADABLE) {
            size_t page = (size_t)sysconf(_SC_PAGESIZE);
            unsigned char *region = mmap(0, page * 2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (region == MAP_FAILED) __builtin_trap();
            memcpy(region + page, table.functions, sizeof(table.functions));
            published = region + page - offsetof(Table, functions);
            if (munmap(region, page) != 0) __builtin_trap();
            if (META_HEADER_UNREADABLE == 2 && munmap(region + page, page) != 0)
                __builtin_trap();
        } else if (META_WORDS < 68) {
            size_t page = (size_t)sysconf(_SC_PAGESIZE);
            size_t available = offsetof(Table, functions) + META_WORDS * sizeof(void *);
            unsigned char *region = mmap(0, page * 2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (region == MAP_FAILED) __builtin_trap();
            published = region + page - available;
            memcpy(published, &table, available);
            if (munmap(region + page, page) != 0) __builtin_trap();
        } else {
            published = &table;
        }
    }
    if (!out) return 7;
    *out = published;
    return 0;
}

#if META_INTERFACE
typedef struct { const char *name; void *table; unsigned long flags; } Interface;
unsigned long C_GetInterfaceList(Interface *out, unsigned long *count) {
    if (!count) return 7;
    if (!out) { *count = 1; return 0; }
    if (*count < 1) { *count = 1; return 0x150; }
    void *table;
    C_GetFunctionList(&table);
    out[0] = (Interface){"PKCS 11", table, 0};
    *count = 1;
    return 0;
}
#endif
