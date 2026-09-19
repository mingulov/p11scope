/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Two real provider objects nest both export acquisition ABIs on one thread.
 * Build twice as a DSO with PROVIDER_ID=1/2, and once with NESTING_DRIVER.
 * All values are fixture constants; table layout follows the compiler's ABI.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef unsigned long rv_t;
typedef struct { char *name; void *table; unsigned long flags; } interface_t;
typedef rv_t (*function_list_fn)(void **);
typedef rv_t (*interface_list_fn)(interface_t *, unsigned long *);
typedef void (*peer_fn)(function_list_fn, interface_list_fn);
typedef void (*counts_fn)(unsigned long *, unsigned long *);

#ifndef NESTING_DRIVER
#ifndef PROVIDER_ID
#error "Define PROVIDER_ID for a provider or NESTING_DRIVER for the driver"
#endif
static function_list_fn peer_function_list;
static interface_list_fn peer_interface_list;
static unsigned long function_calls, interface_calls;
static rv_t spare(void) { return PROVIDER_ID; }
rv_t C_GetFunctionList(void **out);
static struct {
    unsigned char major, minor;
    void *functions[68];
} table = {2, 40, {spare, spare, spare, C_GetFunctionList, [4 ... 67] = spare}};

void set_peer(function_list_fn function_list, interface_list_fn interface_list) {
    peer_function_list = function_list;
    peer_interface_list = interface_list;
}

void get_counts(unsigned long *function_list, unsigned long *interface_list) {
    *function_list = function_calls;
    *interface_list = interface_calls;
}

__attribute__((noinline)) rv_t C_GetFunctionList(void **out) {
    function_calls++;
    if (peer_function_list) {
        void *inner = NULL;
        assert(peer_function_list(&inner) == 0 && inner != NULL);
    }
    assert(out != NULL);
    *out = &table;
    return 0;
}

__attribute__((noinline)) rv_t C_GetInterfaceList(interface_t *out, unsigned long *count) {
    interface_calls++;
    if (peer_interface_list) {
        interface_t inner;
        unsigned long inner_count = 1;
        assert(peer_interface_list(&inner, &inner_count) == 0 && inner_count == 1);
    }
    assert(out != NULL && count != NULL && *count >= 1);
    *out = (interface_t){"PKCS 11", &table, 0};
    *count = 1;
    return 0;
}
#else
static void wait_file(const char *path) {
    while (access(path, F_OK) != 0) usleep(10000);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) return 2;
    alarm(60);
    void *inner = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *outer = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    assert(inner != NULL && outer != NULL);
    function_list_fn inner_fl = (function_list_fn)dlsym(inner, "C_GetFunctionList");
    interface_list_fn inner_il = (interface_list_fn)dlsym(inner, "C_GetInterfaceList");
    function_list_fn outer_fl = (function_list_fn)dlsym(outer, "C_GetFunctionList");
    interface_list_fn outer_il = (interface_list_fn)dlsym(outer, "C_GetInterfaceList");
    peer_fn set_outer = (peer_fn)dlsym(outer, "set_peer");
    counts_fn count_inner = (counts_fn)dlsym(inner, "get_counts");
    counts_fn count_outer = (counts_fn)dlsym(outer, "get_counts");
    assert(inner_fl && inner_il && outer_fl && outer_il && set_outer && count_inner && count_outer);
    set_outer(inner_fl, inner_il);
    puts("NESTED_EXPORTS_READY");
    fflush(stdout);
    if (argc >= 4) wait_file(argv[3]);
    void *result = NULL;
    interface_t interface;
    unsigned long count = 1, fl, il;
    assert(outer_fl(&result) == 0 && result != NULL);
    assert(outer_il(&interface, &count) == 0 && count == 1);
    count_inner(&fl, &il);
    assert(fl == 1 && il == 1);
    count_outer(&fl, &il);
    assert(fl == 1 && il == 1);
    puts("NESTED_EXPORTS_DONE function_lists=2 interface_lists=2");
    fflush(stdout);
    if (argc == 5) wait_file(argv[4]);
    assert(dlclose(outer) == 0 && dlclose(inner) == 0);
    return 0;
}
#endif
