/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <string.h>

/* Model only CO-RE metadata and the two kernel helper boundaries. The
 * predicate body and all refusal branches are the actual production unit. */
static int layout, has_exec_state, has_mm, word_bytes, ptr_bytes, signed_word;
static int null_task, failed_read, reads;
static int exists(const char *field)
{
    if (!strcmp(field, "task->exec_state")) return has_exec_state;
    if (!strcmp(field, "task->mm")) return has_mm;
    if (!strcmp(field, "scalar->flags")) return layout == 1;
    if (!strcmp(field, "bitmap->flags.__mm_flags")) return layout == 2;
    assert(!"unexpected field existence query");
    return 0;
}
static int field_size(const char *field)
{
    if (!strcmp(field, "task->mm")) return ptr_bytes;
    if (!strcmp(field, "scalar->flags") || !strcmp(field, "bitmap->flags") ||
        !strcmp(field, "bitmap->flags.__mm_flags") ||
        !strcmp(field, "bitmap->flags.__mm_flags[0]")) return word_bytes;
    assert(!"unexpected field size query");
    return 0;
}
#define P11SCOPE_EXEC_HOST_TEST
#define EXEC_EXISTS(field) exists(#field)
#define EXEC_SIZE(field) field_size(#field)
#define EXEC_SIGNED(field) signed_word
#include "exec_task.c"

static struct task_struct___p11exec current;
static unsigned long mm_flags;
static void *current_task(void) { return null_task ? 0 : &current; }
static long read_kernel(void *out, unsigned int size, const void *address)
{
    reads++;
    assert(size == 8);
    assert(address == (const void *)&current.mm || address == (const void *)&mm_flags);
    if (failed_read == reads) return -1;
    memcpy(out, address, size);
    return 0;
}
static void reset(int shape)
{
    layout = shape;
    has_exec_state = 0; has_mm = 1;
    word_bytes = ptr_bytes = 8; signed_word = 0;
    null_task = failed_read = reads = 0;
    current.mm = &mm_flags;
    mm_flags = 1;
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
    reset(0);
    assert(!p11_exec_dumpability() && reads == 1);
    return 0;
}
