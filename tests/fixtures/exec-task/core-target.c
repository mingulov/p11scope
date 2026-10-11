/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Independent target BTF. Padding makes an unrelocated fixed offset fail. */
#ifndef EXEC_SHAPE
#error EXEC_SHAPE must select a target representation
#endif
struct mm_struct {
    unsigned long pad[3];
#if EXEC_SHAPE == 1 || EXEC_SHAPE == 6 || EXEC_SHAPE == 7
    unsigned long flags;
#elif EXEC_SHAPE == 2
    struct { unsigned long __mm_flags[1]; } flags;
#elif EXEC_SHAPE == 3
    unsigned long other;
#elif EXEC_SHAPE == 4
    unsigned int flags;
#elif EXEC_SHAPE == 5
    void *flags;
#elif EXEC_SHAPE == 8
    long flags;
#elif EXEC_SHAPE == 9
    struct { unsigned int __mm_flags[2]; } flags;
#elif EXEC_SHAPE == 10
    struct { unsigned long unknown[1]; } flags;
#elif EXEC_SHAPE == 11
    struct { unsigned long __mm_flags[0]; } flags;
#elif EXEC_SHAPE == 12
    struct { unsigned long __mm_flags; } flags;
#elif EXEC_SHAPE == 13
    struct { void *__mm_flags[1]; } flags;
#else
#error unknown EXEC_SHAPE
#endif
};
struct task_struct {
    unsigned long pad[2];
#if EXEC_SHAPE == 7
    struct mm_struct *other;
#else
    struct mm_struct *mm;
#endif
#if EXEC_SHAPE == 6
    void *exec_state;
#endif
};
/* Retain both independent shapes in BTF without a program/map declaration. */
struct task_struct target_task;
struct mm_struct target_mm;
