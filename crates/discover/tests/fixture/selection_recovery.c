/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Only the fixed selection getter publishes these tables. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef SELECT_MAJOR
#define SELECT_MAJOR 3
#endif
#ifndef SELECT_MINOR
#define SELECT_MINOR 0
#endif
#ifndef SELECT_WORDS
#define SELECT_WORDS -1
#endif
#ifndef SELECT_NAME
#define SELECT_NAME 0
#endif
#ifndef SELECT_PARTIAL_WORD
#define SELECT_PARTIAL_WORD 0
#endif
#ifndef SELECT_HEADER_UNREADABLE
#define SELECT_HEADER_UNREADABLE 0
#endif
#ifndef SELECT_FLAGS
#define SELECT_FLAGS 0
#endif
#ifndef SELECT_BAD
#define SELECT_BAD 0
#endif
#ifndef SELECT_SPARSE
#define SELECT_SPARSE -2
#endif
#ifndef SELECT_HEAP
#define SELECT_HEAP 0
#endif
#ifndef SELECT_DEFAULT_ONLY
#define SELECT_DEFAULT_ONLY 0
#endif
#ifndef SELECT_CONFLICT
#define SELECT_CONFLICT 0
#endif
#ifndef SELECT_LEGACY
#define SELECT_LEGACY 0
#endif
#ifndef SELECT_LIST
#define SELECT_LIST 0
#endif
#ifndef SELECT_NULL_OUTPUT
#define SELECT_NULL_OUTPUT 0
#endif
#ifndef SELECT_ERROR
#define SELECT_ERROR 0
#endif

typedef struct { unsigned char major, minor; } Version;
typedef struct { Version version; void *functions[104]; } Table;
typedef struct { const char *name; void *table; unsigned long flags; } Interface;
static Table table, other;
static Interface selected;
static void *published;
static unsigned int calls;
static unsigned long initialize(void) { return 0; }
static unsigned long sign(void) { return 1; }
static unsigned long late(void) { return 2; }
static unsigned long extension(void) { return 3; }
static unsigned long newest(void) { return 4; }
static unsigned long alternate(void) { return 5; }
#if SELECT_BAD == 3
extern unsigned long selection_backend(void);
#endif

static void fill(void) {
    if (published) return;
    table.version = (Version){SELECT_MAJOR, SELECT_MINOR};
    memset((unsigned char *)&table + sizeof(Version), 0xa5,
           offsetof(Table, functions) - sizeof(Version));
    table.functions[0] = initialize;
    table.functions[43] = sign;
    table.functions[67] = late;
    table.functions[91] = extension;
    table.functions[103] = newest;
#if SELECT_SPARSE >= -1
    memset(table.functions, 0, sizeof(table.functions));
#if SELECT_SPARSE >= 0
    table.functions[SELECT_SPARSE] = late;
#endif
#endif
#if SELECT_BAD == 1
    table.functions[20] = (void *)1;
#elif SELECT_BAD == 2
    table.functions[20] = &table;
#elif SELECT_BAD == 3
    table.functions[20] = selection_backend;
#elif SELECT_BAD == 4
    table.functions[20] = write; /* Ambient libc is not a provider dependency. */
#endif
    other = table;
    other.functions[67] = alternate;
#if SELECT_HEADER_UNREADABLE
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *region = mmap(0, page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) __builtin_trap();
    memcpy(region + page, table.functions, sizeof(table.functions));
    published = region + page - offsetof(Table, functions);
    if (munmap(region, page) != 0) __builtin_trap();
#elif SELECT_WORDS >= 0
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t available = offsetof(Table, functions) + SELECT_WORDS * sizeof(void *);
    if (SELECT_PARTIAL_WORD) available += sizeof(void *) - 1;
    unsigned char *region = mmap(0, page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) __builtin_trap();
    published = region + page - available;
    memcpy(published, &table, available);
    if (munmap(region + page, page) != 0) __builtin_trap();
#elif SELECT_HEAP
    published = malloc(sizeof(table));
    if (!published) __builtin_trap();
    memcpy(published, &table, sizeof(table));
#else
    published = &table;
#endif
}

#if SELECT_LEGACY
unsigned long C_GetFunctionList(void **out) { (void)out; return 5; }
#endif
#if SELECT_LIST
unsigned long C_GetInterfaceList(Interface *out, unsigned long *count) {
    (void)out;
#if SELECT_LIST == 1
    if (!count) return 7;
    *count = 0;
    return 0;
#else
    (void)count;
    return 0x54;
#endif
}
#endif

unsigned long C_GetInterface(void *name, void *version, void **out, unsigned long flags) {
    if (!out) return 7;
#if SELECT_ERROR
    (void)name; (void)version; (void)flags;
    return 0x54;
#endif
#if SELECT_DEFAULT_ONLY
    if (name || version || flags) return 7;
#else
    (void)name; (void)version; (void)flags;
#endif
    fill();
#if SELECT_NULL_OUTPUT
    *out = 0;
    return 0;
#endif
    const char *returned_name = "PKCS 11";
#if SELECT_NAME == 1
    returned_name = "Vendor interface";
#elif SELECT_NAME == 2
    returned_name = 0;
#elif SELECT_NAME == 3
    returned_name = (const char *)1;
#endif
    void *returned = published;
#if SELECT_CONFLICT
    if (calls >= 5) returned = &other;
#endif
    ++calls;
    selected = (Interface){returned_name, returned, SELECT_FLAGS};
    *out = &selected;
    return 0;
}
