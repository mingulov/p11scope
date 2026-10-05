/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 dlopen driver: loads one provider and calls one resolved endpoint.
 *
 * Usage (protocol and exit codes: e16_protocol.h):
 *   e16_driver call    MODULE SYMBOL N        call dlsym(SYMBOL)(NULL) N times
 *   e16_driver callptr MODULE FACTORY N       call FACTORY(&out) N times
 *   e16_driver table   MODULE FACTORY SLOT N  call FACTORY once before ready,
 *                                             then functions[SLOT](NULL) N times
 *
 * Everything that resolves the endpoint (dlopen, dlsym, the one factory call
 * of `table`) happens before the ready line, so after GO the only provider
 * code that runs is the endpoint itself. `table` reports its calls under the
 * label `table[SLOT]`: a position, never a guessed PKCS#11 name.
 */
#include "e16_protocol.h"

#include <dlfcn.h>

typedef unsigned long CK_RV;
typedef CK_RV (*direct_fn)(void *);
typedef CK_RV (*factory_fn)(void **);

static long slot_number(const char *text) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 || value >= 104) {
        _exit(E16_EXIT_USAGE);
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return E16_EXIT_USAGE;
    }
    const char *mode = argv[1];
    int is_call = strcmp(mode, "call") == 0;
    int is_callptr = strcmp(mode, "callptr") == 0;
    int is_table = strcmp(mode, "table") == 0;
    if ((!is_call && !is_callptr && !is_table) || argc != (is_table ? 6 : 5)) {
        return E16_EXIT_USAGE;
    }
    const char *module = argv[2];
    const char *symbol = argv[3];
    long slot = is_table ? slot_number(argv[4]) : -1;
    long times = e16_parse_count(argv[is_table ? 5 : 4]);

    void *handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        return 4;
    }
    void *raw = dlsym(handle, symbol);
    if (raw == NULL) {
        return 5;
    }
    direct_fn endpoint = (direct_fn)raw;
    char label[32];
    if (is_table) {
        void *table = NULL;
        if (((factory_fn)raw)(&table) != 0 || table == NULL) {
            return 7;
        }
        /* CK_FUNCTION_LIST: version (2 bytes) + padding, then pointers. */
        void **functions = (void **)((char *)table + 8);
        endpoint = (direct_fn)functions[slot];
        if (endpoint == NULL) {
            return 7;
        }
        int length = snprintf(label, sizeof(label), "table[%ld]", slot);
        if (length <= 0 || (size_t)length >= sizeof(label)) {
            return E16_EXIT_FORMAT;
        }
    } else {
        size_t length = strlen(symbol);
        if (length == 0 || length >= sizeof(label)) {
            return E16_EXIT_USAGE;
        }
        memcpy(label, symbol, length + 1);
    }

    e16_ready((uintptr_t)endpoint, (uintptr_t)&main, times);
    e16_gate('G', E16_EXIT_GO_GATE);
    for (long index = 0; index < times; index++) {
        CK_RV rv;
        if (is_callptr) {
            void *out = NULL;
            rv = ((factory_fn)endpoint)(&out);
            if (rv == 0 && out == NULL) {
                rv = E16_EXIT_CALL_FAILED;
            }
        } else {
            rv = endpoint(NULL);
        }
        e16_call(label, index, rv);
    }
    e16_done(times);
    e16_gate('X', E16_EXIT_RELEASE_GATE);
    return dlclose(handle) == 0 ? 0 : 8;
}
