/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static uintptr_t callback(void) { return 0; }
static struct {
    uint32_t header;
    void *slots[68];
} table = { .header = 0x2802, .slots = { [67] = callback } };

uintptr_t C_GetFunctionList(void **out) { *out = &table; return 0; }

int main(void) {
    void *observed = 0;
    if (C_GetFunctionList(&observed)) return 1;
    printf("%p %p\n", observed, table.slots[67]);
    fflush(stdout);
    char byte;
    (void)read(STDIN_FILENO, &byte, 1);
    return 0;
}
