/* SPDX-License-Identifier: GPL-3.0-or-later */
/* E16 surface: PKCS#11-shaped calls into anonymous executable memory.
 *
 * Usage: e16_jit_driver N
 *
 * An anonymous private page receives one `mov eax, 0; ret` trampoline (a
 * CKR_OK return), is made read+execute, and is called N times through a
 * function pointer under the label `jit_trampoline`. No file is behind the
 * called code: no provider object, factory or table exists anywhere. The
 * ready line's `endpoint` is the anonymous trampoline and `image` is this
 * executable, so the anonymous code and the driver image stay distinct facts.
 * Protocol and exit codes: e16_protocol.h.
 *
 * Build: gcc -std=c11 -O2 -Wall -Wextra -Werror -o e16_jit_driver e16_jit_driver.c
 */
#if !defined(__x86_64__)
#error "the E16 JIT trampoline emits x86-64 machine code"
#endif

#include "e16_protocol.h"

#include <sys/mman.h>

typedef unsigned long CK_RV;

int main(int argc, char **argv) {
    if (argc != 2) {
        return E16_EXIT_USAGE;
    }
    long times = e16_parse_count(argv[1]);
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        return 7;
    }
    unsigned char *code = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return 7;
    }
    /* mov eax, 0; ret */
    static const unsigned char body[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    memcpy(code, body, sizeof(body));
    if (mprotect(code, (size_t)page, PROT_READ | PROT_EXEC) != 0) {
        return 7;
    }
    CK_RV (*trampoline)(void) = (CK_RV(*)(void))(void *)code;
    e16_ready((uintptr_t)code, (uintptr_t)&main, times);
    e16_gate('G', E16_EXIT_GO_GATE);
    for (long index = 0; index < times; index++) {
        e16_call("jit_trampoline", index, trampoline());
    }
    e16_done(times);
    e16_gate('X', E16_EXIT_RELEASE_GATE);
    return munmap(code, (size_t)page) == 0 ? 0 : 8;
}
