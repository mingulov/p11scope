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

/* 6.14 Option B: the exe-identity chain. Flavored partial shapes, one
 * field family each, following the dumpability guard discipline:
 * existence, then size, then a checked read, then null checks. The
 * caller writes nothing unless every read succeeds. No value gates:
 * a zero ino or dev word passes through and fails closed in
 * userspace verification. */
struct mm_struct___p11exe_file {
    void *exe_file;
};
struct file___p11exe {
    void *f_inode;
};
struct inode___p11exe {
    unsigned long i_ino;
    void *i_sb;
};
struct super_block___p11exe {
    unsigned int s_dev;
};

__attribute__((noinline)) unsigned int p11_exe_identity(unsigned long *dev, unsigned long *ino)
{
    struct task_struct___p11exec *task = exec_current_task();
    void *mm = (void *)0, *exe = (void *)0, *inode = (void *)0, *sb = (void *)0;
    unsigned long ino_value = 0;
    unsigned int dev_value = 0;
    if (!dev || !ino || !task)
        return 0;
    if (!EXEC_EXISTS(task->mm))
        return 0;
    if (EXEC_SIZE(task->mm) != sizeof(mm))
        return 0;
    if (EXEC_READ(mm, task->mm) || !mm)
        return 0;
    struct mm_struct___p11exe_file *emm = mm;
    if (!EXEC_EXISTS(emm->exe_file))
        return 0;
    if (EXEC_SIZE(emm->exe_file) != sizeof(exe))
        return 0;
    if (EXEC_READ(exe, emm->exe_file) || !exe)
        return 0;
    struct file___p11exe *efile = exe;
    if (!EXEC_EXISTS(efile->f_inode))
        return 0;
    if (EXEC_SIZE(efile->f_inode) != sizeof(inode))
        return 0;
    if (EXEC_READ(inode, efile->f_inode) || !inode)
        return 0;
    struct inode___p11exe *eino = inode;
    if (!EXEC_EXISTS(eino->i_ino))
        return 0;
    if (EXEC_SIZE(eino->i_ino) != sizeof(ino_value))
        return 0;
    if (EXEC_READ(ino_value, eino->i_ino))
        return 0;
    if (!EXEC_EXISTS(eino->i_sb))
        return 0;
    if (EXEC_SIZE(eino->i_sb) != sizeof(sb))
        return 0;
    if (EXEC_READ(sb, eino->i_sb) || !sb)
        return 0;
    struct super_block___p11exe *esb = sb;
    if (!EXEC_EXISTS(esb->s_dev))
        return 0;
    if (EXEC_SIZE(esb->s_dev) != sizeof(dev_value))
        return 0;
    if (EXEC_READ(dev_value, esb->s_dev))
        return 0;
    *dev = (unsigned long)dev_value;
    *ino = ino_value;
    return 1;
}
