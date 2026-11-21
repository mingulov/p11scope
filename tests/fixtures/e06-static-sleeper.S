/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* E06 statically linked sleeper: a libc-free _start looping the nanosleep
 * syscall, so the child parks (wchan hrtimer_nanosleep) with no `.so`
 * maps at all. Built with the same host gcc the other C fixtures require:
 *
 *   gcc -nostdlib -static -o e06-static-sleeper e06-static-sleeper.S
 *
 * No static libc is needed (nothing is linked); argv is ignored.
 */
    .text
    .global _start
_start:
    sub $16, %rsp
    movq $3600, (%rsp)
    movq $0, 8(%rsp)
.Lpark:
    mov %rsp, %rdi      /* const struct timespec *req */
    xor %esi, %esi      /* struct timespec *rem = NULL */
    mov $35, %eax       /* __NR_nanosleep */
    syscall
    jmp .Lpark
