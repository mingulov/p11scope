/* SPDX-License-Identifier: GPL-2.0-only */
/* H8-D atomic birth marker leaves. Inactive: no live root wires these
 * (pinned by test). BPF-compatible: at most 3 arguments per leaf, no
 * static initializers, CAS-only mutation. */
#include "journal_marker.h"

#ifndef P11SCOPE_JOURNAL_MARKER_NO_MAPS
struct {
    INST_UINT(type, 2); /* ARRAY */
    INST_TYPE(key, u32);
    INST_TYPE(value, struct journal_admission_control);
    INST_UINT(max_entries, 1);
} JOURNAL_MARKER_CTL INST_SEC(".maps");
#endif

static int marker_usable(u64 word)
{
    u64 state = word & P11_JOURNAL_MARKER_STATE_MASK;

    if (word == P11_JOURNAL_MARKER_UNPUBLISHED)
        return 1;
    if (word == P11_JOURNAL_MARKER_DIRTY)
        return 0;
    if (state == P11_JOURNAL_MARKER_READY_STATE)
        return 1;
    return 0;
}

int p11_journal_marker_publish(struct instance_record *rec, u64 exec)
{
    u64 observed, ready;
    int tries;

    if (!rec)
        return 0;
    ready = (exec << 2) | P11_JOURNAL_MARKER_READY_STATE;
    for (tries = 0; tries < 4; tries++) {
        observed = rec->journal_bootstrap;
        if (observed == ready)
            return 1;
        if (!marker_usable(observed))
            return 0;
        if (__sync_val_compare_and_swap(&rec->journal_bootstrap, observed, ready) == observed)
            return 1;
    }
    return 0;
}

void p11_journal_marker_dirty(struct instance_record *rec)
{
    if (!rec)
        return;
    /* Unconditional atomic store: a scope gap marks exactly once and
     * never fails to mark. BPF lowers this to atomic exchange. */
    __sync_lock_test_and_set(&rec->journal_bootstrap, P11_JOURNAL_MARKER_DIRTY);
}

int p11_journal_marker_read(const struct instance_record *rec, u64 *exec_out)
{
    u64 word, state;

    if (!rec)
        return P11_JOURNAL_MARKER_INVALID;
    word = rec->journal_bootstrap;
    if (word == P11_JOURNAL_MARKER_UNPUBLISHED)
        return P11_JOURNAL_MARKER_UNPUBLISHED_READ;
    if (word == P11_JOURNAL_MARKER_DIRTY)
        return P11_JOURNAL_MARKER_DIRTY_READ;
    state = word & P11_JOURNAL_MARKER_STATE_MASK;
    if (state != P11_JOURNAL_MARKER_READY_STATE)
        return P11_JOURNAL_MARKER_INVALID;
    if (exec_out)
        *exec_out = word >> 2;
    return P11_JOURNAL_MARKER_READY;
}

int p11_journal_marker_admit(struct journal_admission_control *ctl, u64 marker, u64 exec)
{
    u64 ready;

    if (!ctl)
        return 0;
    if (ctl->failed != 0)
        return 0;
    ready = (exec << 2) | P11_JOURNAL_MARKER_READY_STATE;
    if (marker != ready) {
        ctl->failed = 1;
        return 0;
    }
    if (ctl->spent >= P11_JOURNAL_MARKER_ADMIT_CAP) {
        ctl->failed = 1;
        return 0;
    }
    ctl->spent++;
    return 1;
}
