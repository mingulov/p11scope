/* SPDX-License-Identifier: GPL-2.0-only */
/* Detailed stop-gate admission for native BPF programs. Shared by the BPF
 * build and the host unit-test builds; the map symbol below is the real
 * Rust-exported STOP_GATE cell and only its address enters map helpers. */
#ifndef P11SCOPE_STOP_GATE_H
#define P11SCOPE_STOP_GATE_H

typedef unsigned int u32;
typedef unsigned long long u64;
#define P11_ALWAYS_INLINE inline __attribute__((always_inline))
/* Bit 63 is the stop request; the low 63 bits count admitted bodies. Tracks
 * p11scope_ebpf_common STOP_GATE_STOP; change both together. */
#define P11_STOP_GATE_STOP (1ULL << 63)

/* Existing real Rust map symbol; only its address enters map helpers. */
extern unsigned char STOP_GATE;

static void *(*stop_gate_map_lookup)(void *, const void *) = (void *)1;

/* Stop-gate admission. Reads the shared word with a compare-exchange against
 * (0, 0) and counts with a non-fetch atomic add whose result is never
 * consumed; the object checker proves the fetch-free lowering in the built
 * object. Returns nonzero when the caller is admitted and must call
 * p11_stop_gate_leave exactly once when its guarded body has finished all
 * capture accesses. Mirrors stop_gate_admit_with in ebpf-common. */
static P11_ALWAYS_INLINE int p11_stop_gate_enter(void)
{
    u32 key = 0;
    u64 *cell = (u64 *)stop_gate_map_lookup(&STOP_GATE, &key);
    u64 observed;

    if (!cell)
        return 0;
    observed = __sync_val_compare_and_swap(cell, 0, 0);
    if (observed & P11_STOP_GATE_STOP)
        return 0;
    /* Discarded result: this must lower to a non-fetch BPF ATOMIC ADD,
     * verified in the object per program. Never consume a fetch-add result
     * and never pass -C target-cpu=v3 (Global Constraints: BPF atomics). */
    __sync_fetch_and_add(cell, 1);
    observed = __sync_val_compare_and_swap(cell, 0, 0);
    if (observed & P11_STOP_GATE_STOP) {
        __sync_fetch_and_add(cell, (u64)-1);
        return 0;
    }
    return 1;
}

/* Release one p11_stop_gate_enter admission. The lookup cannot fail:
 * STOP_GATE is a one-entry Array<u64>, so key 0 is always in bounds and the
 * kernel returns the cell; hence no null check, mirroring the Rust leave.
 * Balancing is exact -- the object checker proves a decrement on every exit
 * path -- so a skipped decrement would leak an in-flight count past the stop. */
static P11_ALWAYS_INLINE void p11_stop_gate_leave(void)
{
    u32 key = 0;
    u64 *cell = (u64 *)stop_gate_map_lookup(&STOP_GATE, &key);

    __sync_fetch_and_add(cell, (u64)-1);
}
#endif
