/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <string.h>

/* Model only CO-RE metadata and the two kernel helper boundaries. The
 * predicate body and all refusal branches are the actual production unit. */
static int layout, has_exec_state, has_mm, word_bytes, ptr_bytes, signed_word;
static int scalar_lshift, scalar_rshift;
static int null_task, failed_read, reads;
static int has_exe_file, has_f_inode, has_i_ino, has_i_sb, has_s_dev;
static int exe_ptr_bytes, ino_bytes, dev_bytes;
static int exists(const char *field)
{
    if (!strcmp(field, "task->exec_state")) return has_exec_state;
    if (!strcmp(field, "task->mm")) return has_mm;
    if (!strcmp(field, "scalar->flags")) return layout == 1;
    if (!strcmp(field, "bitmap->flags.__mm_flags")) return layout == 2;
    if (!strcmp(field, "emm->exe_file")) return has_exe_file;
    if (!strcmp(field, "efile->f_inode")) return has_f_inode;
    if (!strcmp(field, "eino->i_ino")) return has_i_ino;
    if (!strcmp(field, "eino->i_sb")) return has_i_sb;
    if (!strcmp(field, "esb->s_dev")) return has_s_dev;
    assert(!"unexpected field existence query");
    return 0;
}
static int field_size(const char *field)
{
    if (!strcmp(field, "task->mm")) return ptr_bytes;
    if (!strcmp(field, "scalar->flags") || !strcmp(field, "bitmap->flags") ||
        !strcmp(field, "bitmap->flags.__mm_flags") ||
        !strcmp(field, "bitmap->flags.__mm_flags[0]")) return word_bytes;
    if (!strcmp(field, "emm->exe_file") || !strcmp(field, "efile->f_inode") ||
        !strcmp(field, "eino->i_sb")) return exe_ptr_bytes;
    if (!strcmp(field, "eino->i_ino")) return ino_bytes;
    if (!strcmp(field, "esb->s_dev")) return dev_bytes;
    assert(!"unexpected field size query");
    return 0;
}
#define P11SCOPE_EXEC_HOST_TEST
#define EXEC_EXISTS(field) exists(#field)
#define EXEC_SIZE(field) field_size(#field)
#define EXEC_SIGNED(field) signed_word
#define EXEC_LSHIFT(field) scalar_lshift
#define EXEC_RSHIFT(field) scalar_rshift
#include "exec_task.c"

static struct task_struct___p11exec current;
static unsigned long mm_flags;
/* Packet 6.14 phase 2 (Option B RED): host mirrors of the exe-identity
 * chain. Layouts are harness-local; only CO-RE metadata is modeled. */
struct exe_mm { void *exe_file; };
struct exe_file { void *f_inode; };
struct exe_inode { unsigned long i_ino; void *i_sb; };
struct exe_sb { unsigned int s_dev; };
static struct exe_mm fake_mm;
static struct exe_file fake_file;
static struct exe_inode fake_inode;
static struct exe_sb fake_sb;
static void *current_task(void) { return null_task ? 0 : &current; }
static long read_kernel(void *out, unsigned int size, const void *address)
{
    reads++;
    if (address == (const void *)&fake_sb.s_dev) {
        assert(size == 4);
    } else {
        assert(size == 8);
        assert(address == (const void *)&current.mm || address == (const void *)&mm_flags ||
               address == (const void *)&fake_mm.exe_file ||
               address == (const void *)&fake_file.f_inode ||
               address == (const void *)&fake_inode.i_ino ||
               address == (const void *)&fake_inode.i_sb);
    }
    if (failed_read == reads) return -1;
    memcpy(out, address, size);
    return 0;
}
static void reset(int shape)
{
    layout = shape;
    has_exec_state = 0; has_mm = 1;
    word_bytes = ptr_bytes = 8; signed_word = 0;
    scalar_lshift = scalar_rshift = 0;
    null_task = failed_read = reads = 0;
    current.mm = &mm_flags;
    mm_flags = 1;
}
static void reset_exe(void)
{
    reset(1);
    has_exe_file = has_f_inode = has_i_ino = has_i_sb = has_s_dev = 1;
    exe_ptr_bytes = ino_bytes = 8; dev_bytes = 4;
    current.mm = &fake_mm;
    fake_mm.exe_file = &fake_file;
    fake_file.f_inode = &fake_inode;
    fake_inode.i_ino = 802;
    fake_inode.i_sb = &fake_sb;
    fake_sb.s_dev = 0x801;
}
/* Packet 6.14 phase 2 (Option B GREEN): the real helper rides the
 * exec_task.c include above; these cases exercise it. */
static void check_exe_identity(void)
{
    unsigned long dev, ino;
    reset_exe();
    dev = ino = 0xa5a5a5a5;
    assert(p11_exe_identity(&dev, &ino) == 1);
    assert(dev == 0x801 && ino == 802 && reads == 6);
    reset_exe(); null_task = 1;
    assert(!p11_exe_identity(&dev, &ino) && reads == 0);
    reset_exe(); current.mm = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 1);
    reset_exe(); has_mm = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 0);
    reset_exe(); has_exe_file = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 1);
    reset_exe(); has_f_inode = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 2);
    reset_exe(); has_i_ino = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 3);
    reset_exe(); has_i_sb = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 4);
    reset_exe(); has_s_dev = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 5);
    reset_exe(); ptr_bytes = 4;
    assert(!p11_exe_identity(&dev, &ino) && reads == 0);
    reset_exe(); exe_ptr_bytes = 4;
    assert(!p11_exe_identity(&dev, &ino) && reads == 1);
    reset_exe(); ino_bytes = 4;
    assert(!p11_exe_identity(&dev, &ino) && reads == 3);
    reset_exe(); dev_bytes = 8;
    assert(!p11_exe_identity(&dev, &ino) && reads == 5);
    for (int failed = 1; failed <= 6; failed++) {
        reset_exe(); failed_read = failed;
        assert(!p11_exe_identity(&dev, &ino) && reads == failed);
    }
    reset_exe(); fake_mm.exe_file = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 2);
    reset_exe(); fake_file.f_inode = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 3);
    reset_exe(); fake_inode.i_sb = 0;
    assert(!p11_exe_identity(&dev, &ino) && reads == 5);
    reset_exe();
    assert(!p11_exe_identity(0, &ino) && reads == 0);
    assert(!p11_exe_identity(&dev, 0) && reads == 0);
}
int main(void)
{
    exec_current_task = current_task;
    exec_read_kernel = read_kernel;
    for (int shape = 1; shape <= 2; shape++) {
        for (unsigned long value = 0; value <= 3; value++) {
            reset(shape); mm_flags = (1UL << 63) | value;
            assert(p11_exec_dumpability() == (value == 1));
            assert(reads == 2);
        }
        reset(shape); null_task = 1;
        assert(!p11_exec_dumpability() && reads == 0);
        reset(shape); current.mm = 0;
        assert(!p11_exec_dumpability() && reads == 1);
        reset(shape); has_mm = 0;
        assert(!p11_exec_dumpability() && reads == 0);
        reset(shape); has_exec_state = 1;
        assert(!p11_exec_dumpability() && reads == 0);
        reset(shape); ptr_bytes = 4;
        assert(!p11_exec_dumpability() && reads == 0);
        reset(shape); word_bytes = 4;
        assert(!p11_exec_dumpability() && reads == 1);
        for (int failed = 1; failed <= 2; failed++) {
            reset(shape); failed_read = failed;
            assert(!p11_exec_dumpability() && reads == failed);
        }
    }
    reset(1); signed_word = 1;
    assert(!p11_exec_dumpability() && reads == 1);
    reset(1); scalar_rshift = 1;
    assert(!p11_exec_dumpability() && reads == 1);
    reset(1); scalar_lshift = scalar_rshift = 63;
    assert(!p11_exec_dumpability() && reads == 1);
    reset(0);
    assert(!p11_exec_dumpability() && reads == 1);
    check_exe_identity();
    return 0;
}
