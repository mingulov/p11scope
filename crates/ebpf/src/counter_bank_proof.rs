//! SPDX-License-Identifier: GPL-2.0-only
//! Unselected format2 Counts roots. Current Session preparation refuses them.

use super::*;

#[map]
pub(super) static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(65_536, 0);

unsafe extern "C" {
    fn p11_bank_enter(slot: u32, pid_tgid: u64) -> u32;
    fn p11_bank_complete(slot: u32, pid_tgid: u64, rv: u64, account: u32) -> u32;
}

#[uprobe]
pub fn p11_counter_bank_entry(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let slot = slot_of(&ctx);
    if slot < 8192 && scope_flags().is_some() {
        if probe_layout(&ctx).is_some() {
            // All publication checks precede native START/STATS mutation.
            unsafe { p11_bank_enter(slot, helpers::bpf_get_current_pid_tgid()) };
        } else {
            bump_evidence(EVIDENCE_ABI_REFUSALS);
        }
    }
    stop_gate_leave();
    0
}

#[uretprobe]
pub fn p11_counter_bank_return(ctx: RetProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let slot = slot_of(&ctx);
    if slot < 8192 {
        let scoped = scope_flags().is_some();
        let layout = ret_probe_layout(&ctx);
        if layout.is_none() {
            bump_evidence(EVIDENCE_ABI_REFUSALS);
        }
        let rv = layout
            .map(|layout| normalize_target_word(ctx.ret::<u64>(), layout))
            .unwrap_or(0);
        // The native return first performs optional START lookup, before
        // publication/route checks. Refusal still retires a present START.
        unsafe {
            p11_bank_complete(
                slot,
                helpers::bpf_get_current_pid_tgid(),
                rv,
                u32::from(scoped && layout.is_some()),
            )
        };
    }
    stop_gate_leave();
    0
}
