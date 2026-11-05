/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>

uintptr_t C_Initialize(void) { return 0; }
uintptr_t C_WaitForSlotEvent(void) { return 0; }

static uintptr_t data_word;
static struct {
    uint64_t header;
    void *slots[68];
} table = {
#ifdef COMPAT_EMPTY_FACTORY
    .header = UINT64_C(0x2802),
#else
    .header = UINT64_C(0xa5a500000000e707),
    .slots = {
        [0] = C_Initialize,
        [5] = &data_word,
        [67] = C_WaitForSlotEvent,
    },
#endif
};

static void *published_table = &table;

void compatibility_set_table(void *value) { published_table = value; }

uintptr_t C_GetFunctionList(void **out) {
    *out = published_table;
    return 0;
}
