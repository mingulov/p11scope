/* SPDX-License-Identifier: GPL-2.0-only */
#include "exec_task.h"

#ifndef P11SCOPE_EXEC_HOST_TEST
#define EXEC_BTF __attribute__((preserve_access_index))
#define EXEC_EXISTS(field) __builtin_preserve_field_info(field, 2)
#define EXEC_SIZE(field) __builtin_preserve_field_info(field, 1)
#define EXEC_SIGNED(field) __builtin_preserve_field_info(field, 3)
#define EXEC_LSHIFT(field) __builtin_preserve_field_info(field, 4)
#define EXEC_RSHIFT(field) __builtin_preserve_field_info(field, 5)
#define EXEC_READ(dst, field) \
    exec_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(field)))
#else
#define EXEC_BTF
#define EXEC_READ(dst, field) exec_read_kernel(&(dst), sizeof(dst), &(field))
#endif

/* Flavors prevent the linked partial kernel shapes from being conflated.
 * Pointer contents are transient and never retained or published. */
struct task_struct___p11exec {
    void *mm;
    void *exec_state;
} EXEC_BTF;
struct mm_struct___p11exec_scalar {
    unsigned long flags;
} EXEC_BTF;
struct mm_flags___p11exec {
    unsigned long __mm_flags[1];
} EXEC_BTF;
struct mm_struct___p11exec_bitmap {
    struct mm_flags___p11exec flags;
} EXEC_BTF;

static void *(*exec_current_task)(void) = (void *)158;
static long (*exec_read_kernel)(void *, unsigned int, const void *) = (void *)113;

/* No maps, new hooks or user-memory reads. Missing CO-RE accesses can be
 * poisoned by Aya, so existence guards must precede size/offset/read paths.
 * Upstream exec_state stores dumpability elsewhere: refuse without reading it.
 * Older scalar and 7.0 nested bitmap flags keep dumpability in the low 2 bits. */
__attribute__((noinline)) unsigned int p11_exec_dumpability(void)
{
    struct task_struct___p11exec *task = exec_current_task();
    void *mm = (void *)0;
    unsigned long flags = 0;

    if (!task || EXEC_EXISTS(task->exec_state))
        return 0;
    if (!EXEC_EXISTS(task->mm))
        return 0;
    if (EXEC_SIZE(task->mm) != sizeof(mm))
        return 0;
    if (EXEC_READ(mm, task->mm) || !mm)
        return 0;

    struct mm_struct___p11exec_scalar *scalar = mm;
    if (EXEC_EXISTS(scalar->flags)) {
        /* Bitfield size describes its backing storage. Zero shifts require
         * full-width word semantics, including an equivalent 64-bit field. */
        if (EXEC_SIZE(scalar->flags) != sizeof(flags) || EXEC_SIGNED(scalar->flags) ||
            EXEC_LSHIFT(scalar->flags) || EXEC_RSHIFT(scalar->flags))
            return 0;
        if (EXEC_READ(flags, scalar->flags))
            return 0;
    } else {
        struct mm_struct___p11exec_bitmap *bitmap = mm;
        if (!EXEC_EXISTS(bitmap->flags.__mm_flags))
            return 0;
        if (EXEC_SIZE(bitmap->flags) != sizeof(flags) ||
            EXEC_SIZE(bitmap->flags.__mm_flags) != sizeof(flags) ||
            EXEC_SIZE(bitmap->flags.__mm_flags[0]) != sizeof(flags))
            return 0;
        if (EXEC_READ(flags, bitmap->flags.__mm_flags[0]))
            return 0;
    }
    return (flags & 3UL) == 1UL;
}
