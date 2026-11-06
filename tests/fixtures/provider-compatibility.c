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

#ifdef COMPAT_FAT_DATA
/* 1 MiB of file-backed data after the table, so the object's readable data
 * dwarfs its ELF headers: a per-object cap between the two skips the
 * module whole. Fully nonzero (the compiler demotes a mostly-zero array
 * back to BSS, which the sweep does not group). Every word is
 * version-major 1, which the decoder reads as data, never a table. */
static uint64_t compat_fat[131072] = { [0 ... 131071] = 1 };
static void *compat_fat_anchor = &compat_fat[131071];
#endif

void compatibility_set_table(void *value) { published_table = value; }

uintptr_t C_GetFunctionList(void **out) {
    *out = published_table;
    return 0;
}
