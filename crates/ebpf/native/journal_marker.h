/* SPDX-License-Identifier: GPL-2.0-only */
/* H8-D atomic birth marker: one READY/DIRTY word appended to PROC_EPOCH
 * (152 B total) plus a Detailed-only 16 B admission control row
 * {spent, failed}. Live since slice D: the exec-birth and scope-gap
 * roots call publish, dirty, admit and reserve. The transaction leaves
 * (JOURNAL_START, journal threads) stay inactive (pinned by test).
 *
 * Word encoding (low 2 bits = state, high 62 = exec generation):
 *   0                  unpublished (fresh storage)
 *   1                  DIRTY (scope gap: unusable, sticks)
 *   (exec << 2) | 2    READY naming exec
 * Anything else (low bits 3, low bits 0 with high bits set, or
 * low bits 01 with high bits set) is invalid and fails closed.
 *
 * Publication races only the scope-gap dirtier (exec is per-task
 * serial): a single CAS from the observed usable word fails closed on
 * conflict. DIRTY sticks across execs by design — a gap poisons the
 * marker path for the task's life; births then use the absence path
 * or fail. The admission latch likewise sticks: spent counts permits
 * up to ADMIT_CAP, and any admission failure trips failed.
 */
#ifndef P11_JOURNAL_MARKER_H
#define P11_JOURNAL_MARKER_H

#include "instance_epoch.h"

#define P11_JOURNAL_MARKER_UNPUBLISHED 0ULL
#define P11_JOURNAL_MARKER_DIRTY 1ULL
#define P11_JOURNAL_MARKER_STATE_MASK 3ULL
#define P11_JOURNAL_MARKER_READY_STATE 2ULL
#define P11_JOURNAL_MARKER_ADMIT_CAP 16777216ULL

#define P11_JOURNAL_MARKER_UNPUBLISHED_READ 0
#define P11_JOURNAL_MARKER_READY 1
#define P11_JOURNAL_MARKER_DIRTY_READ 2
#define P11_JOURNAL_MARKER_INVALID -1

/* Detailed-only admission control row: spent permits plus the failed
 * latch. Initialized once (zero) before links; userspace never writes
 * it. */
struct journal_admission_control {
    u64 spent;
    u64 failed;
};

/* ATOMIC publication: observed-usable word -> READY(exec). Idempotent
 * for the same exec (a lost CAS retries into the winner's READY);
 * DIRTY, garbage, or exhausting the bounded retries fails closed.
 * Returns 1 on published-or-already, 0 on conflict. */
int p11_journal_marker_publish(struct instance_record *rec, u64 exec);

/* ATOMIC dirty: any word -> DIRTY (sticks; idempotent). */
void p11_journal_marker_dirty(struct instance_record *rec);

/* Readback + validation: UNPUBLISHED_READ, READY (*exec_out set),
 * DIRTY_READ, or INVALID. */
int p11_journal_marker_read(const struct instance_record *rec, u64 *exec_out);

/* Admission attempt: requires marker == READY(exec) and spent below
 * the cap. Success spends one permit; any failure trips the failed
 * latch and refuses. Returns 1 admitted, 0 refused. */
int p11_journal_marker_admit(struct journal_admission_control *ctl, u64 marker, u64 exec);

/* Bare reservation: spends one permit below the cap without checking
 * any marker word. The birth roots charge before they allocate; any
 * failure trips the failed latch and refuses. Returns 1 reserved,
 * 0 refused. */
int p11_journal_marker_reserve(struct journal_admission_control *ctl);

#endif
