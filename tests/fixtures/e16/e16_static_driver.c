/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 static-surface driver: the provider object is linked into this
 * executable, so there is no provider .so and no dlopen.
 *
 * Usage: e16_static_driver N
 *
 * Before the ready line it calls the linked-in (not dynamically exported)
 * C_GetFunctionList once and resolves functions[0] of the returned table;
 * after GO it calls only that endpoint, N times, under the label `table[0]`
 * (a position, never a guessed name). Protocol and exit codes:
 * e16_protocol.h.
 *
 * Build (the driver is PIE, so the provider object is -fPIC):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -c e16_static_provider.c
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -o e16_static_driver \
 *       e16_static_driver.c e16_static_provider.o
 * No -rdynamic: the missing dynamic factory export is the surface under test.
 */
#include "e16_protocol.h"

typedef unsigned long CK_RV;

extern CK_RV C_GetFunctionList(void **out);

int main(int argc, char **argv) {
    if (argc != 2) {
        return E16_EXIT_USAGE;
    }
    long times = e16_parse_count(argv[1]);
    void *table = NULL;
    if (C_GetFunctionList(&table) != 0 || table == NULL) {
        return 7;
    }
    /* CK_FUNCTION_LIST: version (2 bytes) + padding, then pointers. */
    CK_RV (*endpoint)(void *) = (CK_RV(*)(void *))((void **)((char *)table + 8))[0];
    if (endpoint == NULL) {
        return 7;
    }
    e16_ready((uintptr_t)endpoint, (uintptr_t)&main, times);
    e16_gate('G', E16_EXIT_GO_GATE);
    for (long index = 0; index < times; index++) {
        e16_call("table[0]", index, endpoint(NULL));
    }
    e16_done(times);
    e16_gate('X', E16_EXIT_RELEASE_GATE);
    return 0;
}
