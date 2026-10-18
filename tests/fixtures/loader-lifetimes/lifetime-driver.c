/* SPDX-License-Identifier: GPL-3.0-or-later */
/* One provider-bearing lifetime for G16/G17 qualification.
 *
 *   lifetime-driver PROVIDER LABEL
 *
 * LABEL is 1..16385. The driver stats the provider, dlopens it, exercises
 * the three publication surfaces (C_GetFunctionList, C_GetInterfaceList,
 * C_GetInterface) with exact expected returns, then makes exactly two
 * useful table calls (C_GetInfo, C_GetSlotList) with exact expected
 * returns. It prints one JSON object to stdout and exits 0. Any failure
 * prints a short diagnostic to stderr (no paths beyond the given provider
 * argument, no handles or payload) and exits nonzero without stdout.
 *
 * The stdout row carries the independent ledger facts for this lifetime:
 * label, pid, starttime (field 22 of /proc/self/stat), provider file
 * identity (stat dev/ino, file domain), publication results and the two
 * call results. Starttime parsing follows tests/fixtures/e16/e16_protocol.h
 * (after the last ')', skip fields 3..21, read field 22). The harness
 * binds pid to its held child handle and checks (pid,starttime) uniqueness;
 * starttime itself is self-reported (see README.md).
 *
 * No stdin gates, no signals, no sleeps, no Initialize/Finalize: the exact
 * denominator is 2 table calls. Output is one line under 4 KiB.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_SLOT_ID;

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct {
    CK_VERSION cryptokiVersion;
    char manufacturerID[32];
    CK_FLAGS flags;
    char libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;
typedef CK_INTERFACE *CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR *CK_INTERFACE_PTR_PTR;

typedef struct {
    CK_VERSION version;
    CK_BYTE reserved[6];
    void *functions[104];
} P11ScopeTable;

typedef CK_RV (*get_function_list_fn)(void **);
typedef CK_RV (*get_interface_list_fn)(CK_INTERFACE *, CK_ULONG *);
typedef CK_RV (*get_interface_fn)(void *, void *, CK_INTERFACE_PTR_PTR, CK_FLAGS);
typedef CK_RV (*get_info_fn)(CK_INFO *);
typedef CK_RV (*get_slot_list_fn)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);

#define EXIT_USAGE 2
#define EXIT_PROVIDER 3
#define EXIT_SURFACE 4
#define EXIT_OUTPUT 5
#define EXIT_STARTTIME 6

static unsigned long long self_starttime(void) {
    char buffer[2048];
    size_t used = 0;
    int fd;
    do {
        fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return 0;
    }
    for (;;) {
        ssize_t got = read(fd, buffer + used, sizeof(buffer) - 1 - used);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            break;
        }
        used += (size_t)got;
        if (used == sizeof(buffer) - 1) {
            break;
        }
    }
    close(fd);
    buffer[used] = '\0';
    char *close_paren = strrchr(buffer, ')');
    if (close_paren == NULL) {
        return 0;
    }
    char *cursor = close_paren + 1;
    for (int field = 3; field < 22; field++) {
        while (*cursor == ' ') {
            cursor++;
        }
        while (*cursor != ' ' && *cursor != '\0') {
            cursor++;
        }
        if (*cursor == '\0') {
            return 0;
        }
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || value == 0 || (*end != ' ' && *end != '\n' && *end != '\0')) {
        return 0;
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: lifetime-driver PROVIDER LABEL\n");
        return EXIT_USAGE;
    }
    char *end = NULL;
    errno = 0;
    long label = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || label < 1 || label > 16385) {
        fprintf(stderr, "lifetime-driver: LABEL must be 1..16385\n");
        return EXIT_USAGE;
    }
    struct stat identity;
    if (stat(argv[1], &identity) != 0 || !S_ISREG(identity.st_mode)) {
        fprintf(stderr, "lifetime-driver: provider stat failed\n");
        return EXIT_PROVIDER;
    }
    unsigned long long starttime = self_starttime();
    if (starttime == 0) {
        fprintf(stderr, "lifetime-driver: starttime unavailable\n");
        return EXIT_STARTTIME;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "lifetime-driver: dlopen failed\n");
        return EXIT_PROVIDER;
    }
    get_function_list_fn get_function_list = (get_function_list_fn)dlsym(handle, "C_GetFunctionList");
    get_interface_list_fn get_interface_list =
        (get_interface_list_fn)dlsym(handle, "C_GetInterfaceList");
    get_interface_fn get_interface = (get_interface_fn)dlsym(handle, "C_GetInterface");
    if (get_function_list == NULL || get_interface_list == NULL || get_interface == NULL) {
        fprintf(stderr, "lifetime-driver: provider lacks a publication export\n");
        dlclose(handle);
        return EXIT_PROVIDER;
    }
    void *table_ptr = NULL;
    CK_RV function_list_rv = get_function_list(&table_ptr);
    if (function_list_rv != 0 || table_ptr == NULL) {
        fprintf(stderr, "lifetime-driver: C_GetFunctionList failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    P11ScopeTable *table = table_ptr;
    if (table->version.major != 3 || table->version.minor != 2) {
        fprintf(stderr, "lifetime-driver: unexpected table version\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    CK_ULONG count = 0;
    CK_RV interface_list_rv = get_interface_list(NULL, &count);
    if (interface_list_rv != 0 || count != 1) {
        fprintf(stderr, "lifetime-driver: C_GetInterfaceList count failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    CK_INTERFACE entry;
    count = 1;
    interface_list_rv = get_interface_list(&entry, &count);
    if (interface_list_rv != 0 || count != 1 || entry.pInterfaceName == NULL ||
        strcmp(entry.pInterfaceName, "PKCS 11") != 0 || entry.pFunctionList == NULL ||
        entry.flags != 0) {
        fprintf(stderr, "lifetime-driver: C_GetInterfaceList entry failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    CK_INTERFACE_PTR selected = NULL;
    CK_RV interface_rv = get_interface(NULL, NULL, &selected, 0);
    if (interface_rv != 0 || selected == NULL || selected->pInterfaceName == NULL ||
        strcmp(selected->pInterfaceName, "PKCS 11") != 0 || selected->pFunctionList == NULL ||
        selected->flags != 0) {
        fprintf(stderr, "lifetime-driver: C_GetInterface failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    get_info_fn get_info = (get_info_fn)table->functions[2];
    get_slot_list_fn get_slot_list = (get_slot_list_fn)table->functions[4];
    if (get_info == NULL || get_slot_list == NULL) {
        fprintf(stderr, "lifetime-driver: table slots 2/4 are null\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    CK_INFO info;
    memset(&info, 0, sizeof info);
    CK_RV info_rv = get_info(&info);
    if (info_rv != 0) {
        fprintf(stderr, "lifetime-driver: C_GetInfo failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    CK_SLOT_ID slots[1];
    CK_ULONG slot_count = 1;
    CK_RV slot_rv = get_slot_list(0, slots, &slot_count);
    if (slot_rv != 0 || slot_count != 1 || slots[0] != 1) {
        fprintf(stderr, "lifetime-driver: C_GetSlotList failed\n");
        dlclose(handle);
        return EXIT_SURFACE;
    }
    int written = printf("{\"label\":%ld,\"pid\":%ld,\"starttime\":%llu,"
                         "\"provider_dev\":[%u,%u],\"provider_ino\":%llu,"
                         "\"surfaces\":{\"function_list\":%lu,\"interface_list\":%lu,"
                         "\"interface\":%lu,\"interface_count\":1},"
                         "\"calls\":[{\"fn\":\"C_GetInfo\",\"rv\":%lu},"
                         "{\"fn\":\"C_GetSlotList\",\"rv\":%lu}]}\n",
                         label, (long)getpid(), starttime,
                         major(identity.st_dev), minor(identity.st_dev),
                         (unsigned long long)identity.st_ino,
                         function_list_rv, interface_list_rv, interface_rv,
                         info_rv, slot_rv);
    if (written <= 0 || ferror(stdout) || fflush(stdout) != 0) {
        fprintf(stderr, "lifetime-driver: stdout failed\n");
        dlclose(handle);
        return EXIT_OUTPUT;
    }
    dlclose(handle);
    return 0;
}
