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
    u64 ready, observed;
    int tries;

    if (!ctl)
        return 0;
    if (__sync_fetch_and_add(&ctl->failed, 0) != 0)
        return 0;
    ready = (exec << 2) | P11_JOURNAL_MARKER_READY_STATE;
    if (marker != ready) {
        __sync_lock_test_and_set(&ctl->failed, 1);
        return 0;
    }
    /* Bounded ATOMIC reservation with the failure-latch protocol:
     * the permit is spent by compare-exchange, so two CPUs observing
     * the last permit cannot both win. Genuine bound-exceed trips the
     * latch and refuses loudly; concurrent admission beyond the bound
     * never over-admits silently. CAS contention retries boundedly;
     * EXHAUSTED retries latch `failed` permanently and refuse (the
     * binding H8 failure protocol: N+1, counter corruption/exhaustion
     * and failed admission CAS all latch — the mint precedent's
     * unlatched contention refusal does not apply here). The caller
     * raises the checked fault; later admissions refuse on the latch
     * without spending. The NULL-control path cannot latch (no row
     * exists to latch); it allocates nothing, satisfying that half. */
    for (tries = 0; tries < 32; tries++) {
        observed = __sync_fetch_and_add(&ctl->spent, 0);
        if (observed >= P11_JOURNAL_MARKER_ADMIT_CAP) {
            __sync_lock_test_and_set(&ctl->failed, 1);
            return 0;
        }
        if (__sync_val_compare_and_swap(&ctl->spent, observed, observed + 1) == observed)
            return 1;
    }
    __sync_lock_test_and_set(&ctl->failed, 1);
    return 0;
}
