/* SPDX-License-Identifier: GPL-3.0-or-later */
/* pressure-live driver: ledgered provider-bearing child for the T8/G18 live256
 * pressure workload preparation (lane D). This file is preparation only: it
 * builds and runs unprivileged without any capture, and no runner consumes it
 * until the controller wires the live cell. See README.md beside it.
 *
 * usage: driver PROVIDER MODE REPEAT GATEFILE
 *   PROVIDER  absolute path of the provider .so to dlopen and drive
 *   MODE      retain (sustained prefix) or late (eligible late owner);
 *             behavior is identical; the mode is recorded in LEDGER so the
 *             oracle can join each child to its population role
 *   REPEAT    burst size: each present publication surface is called REPEAT
 *             times after the gate releases
 *   GATEFILE  gate path ("-" = no gate: burst immediately, ledger, exit)
 *
 * Protocol (stdout; same TARGET/READY/LEDGER shape as
 * tests/fixtures/public-cli/gated.c so the same join logic applies):
 *   TARGET {"name":...,"dev":[major,minor],"ino":N,"file_offset":M}
 *     one line per present publication surface, joined from this process's
 *     own executable VMA (independent physical-target evidence)
 *   READY pid=N
 *   LEDGER {"schema":"p11scope/pressure-live-ledger/v1","pid":N,
 *     "mode":"retain"|"late","complete":bool,
 *     "functions":[{"name":...,"attempts":A,"successful":S}...]}
 *
 * Gated children hold their mapping until SIGTERM/SIGINT, then dlclose and
 * exit 0 only when every attempt succeeded. C_GetFunctionList is required;
 * C_GetInterfaceList/C_GetInterface are optional (attempted and ledgered
 * honestly when present, absent from TARGET/LEDGER when not). Nothing here
 * fabricates activity: attempts and successes are counted from real calls.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_FLAGS;

typedef struct {
    char *pInterfaceName;
    void *pFunctionList;
    CK_FLAGS flags;
} CK_INTERFACE;

typedef CK_RV (*fn_function_list)(void **);
typedef CK_RV (*fn_interface_list)(CK_INTERFACE *, CK_ULONG *);
typedef CK_RV (*fn_interface)(void *, void *, void **, CK_FLAGS);

static volatile sig_atomic_t stop;

static void on_signal(int number) {
    (void)number;
    stop = 1;
}

/* One independent physical-target line for a surface address, resolved
 * through this process's own maps exactly like gated.c target(). */
static int emit_target(const char *name, void *address) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return 1;
    }
    char line[4096];
    char perms[5];
    unsigned long low, high, offset, inode;
    unsigned int major, minor;
    uintptr_t want = (uintptr_t)address;
    while (fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &low, &high, perms, &offset,
                   &major, &minor, &inode) == 7 &&
            want >= low && want < high && perms[2] == 'x' && inode) {
            printf("TARGET {\"name\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,"
                   "\"file_offset\":%lu}\n",
                   name, major, minor, inode, (unsigned long)(want - low) + offset);
            fclose(maps);
            return 0;
        }
    }
    fclose(maps);
    return 1;
}

static int wait_for_gate(const char *gate) {
    while (access(gate, F_OK) != 0 && !stop) {
        usleep(10000);
    }
    return stop ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: driver PROVIDER MODE REPEAT GATEFILE\n");
        return 2;
    }
    const char *provider = argv[1];
    const char *mode = argv[2];
    if (strcmp(mode, "retain") != 0 && strcmp(mode, "late") != 0) {
        fprintf(stderr, "driver: MODE must be retain or late\n");
        return 2;
    }
    char *end = NULL;
    long repeat = strtol(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0' || repeat < 0 || repeat > 1000000) {
        fprintf(stderr, "driver: REPEAT must be 0..1000000\n");
        return 2;
    }
    const char *gate = argv[4];
    int gated = strcmp(gate, "-") != 0;

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    void *handle = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "driver: dlopen %s\n", dlerror());
        return 1;
    }
    fn_function_list get_function_list =
        (fn_function_list)dlsym(handle, "C_GetFunctionList");
    if (!get_function_list) {
        fprintf(stderr, "driver: provider exports no C_GetFunctionList\n");
        return 1;
    }
    fn_interface_list get_interface_list =
        (fn_interface_list)dlsym(handle, "C_GetInterfaceList");
    fn_interface get_interface = (fn_interface)dlsym(handle, "C_GetInterface");

    if (emit_target("C_GetFunctionList", (void *)get_function_list)) {
        return 1;
    }
    if (get_interface_list && emit_target("C_GetInterfaceList", (void *)get_interface_list)) {
        return 1;
    }
    if (get_interface && emit_target("C_GetInterface", (void *)get_interface)) {
        return 1;
    }

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (gated && wait_for_gate(gate)) {
        return 1;
    }

    unsigned long done_function_list = 0, ok_function_list = 0;
    unsigned long done_interface_list = 0, ok_interface_list = 0;
    unsigned long done_interface = 0, ok_interface = 0;
    long done = 0;
    for (long i = 0; i < repeat && !stop; i++, done++) {
        void *table = NULL;
        done_function_list++;
        ok_function_list += get_function_list(&table) == 0 && table != NULL;
        if (get_interface_list) {
            CK_INTERFACE ifaces[17];
            CK_ULONG count = 17;
            done_interface_list++;
            ok_interface_list += get_interface_list(ifaces, &count) == 0;
        }
        if (get_interface) {
            void *iface = NULL;
            done_interface++;
            ok_interface += get_interface(NULL, NULL, &iface, 0) == 0 && iface != NULL;
        }
    }
    int complete = !stop && done == repeat;

    printf("LEDGER {\"schema\":\"p11scope/pressure-live-ledger/v1\",\"pid\":%d,"
           "\"mode\":\"%s\",\"complete\":%s,\"functions\":[",
           (int)getpid(), mode, complete ? "true" : "false");
    printf("{\"name\":\"C_GetFunctionList\",\"attempts\":%lu,\"successful\":%lu}",
           done_function_list, ok_function_list);
    if (get_interface_list) {
        printf(",{\"name\":\"C_GetInterfaceList\",\"attempts\":%lu,\"successful\":%lu}",
               done_interface_list, ok_interface_list);
    }
    if (get_interface) {
        printf(",{\"name\":\"C_GetInterface\",\"attempts\":%lu,\"successful\":%lu}",
               done_interface, ok_interface);
    }
    printf("]}\n");
    fflush(stdout);

    unsigned long bad = (done_function_list - ok_function_list) +
        (done_interface_list - ok_interface_list) + (done_interface - ok_interface);
    if (gated) {
        while (!stop) {
            pause();
        }
    }
    dlclose(handle);
    return (bad || !complete) ? 1 : 0;
}
