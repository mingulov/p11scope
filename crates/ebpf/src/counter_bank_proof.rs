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
#[cfg(feature = "counts-bank-proof")] pub fn p11_counter_bank_entry(ctx: ProbeContext) -> u32 { // Keep on this line (byte control).
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
#[cfg(feature = "counts-bank-proof")] pub fn p11_counter_bank_return(ctx: RetProbeContext) -> u32 { // Keep on this line (byte control).
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

// Timing bank roots, appended so the counts lines above never move. The
// counts roots are gated on their signature lines: the #[uprobe] lines must
// stay byte-identical (the macro embeds them into BTF strings) and no lines
// may be added (line info records every line). Timing builds share the counts
// Rust shape; the native bank unit selected by -DP11SCOPE_BANK_MODE_* owns
// the per-mode maps, config word and bucket accounting. The clock (helper 5)
// is read only here, once per root, immediately before the timed bridge, so
// the fresh value flows straight into ts/now.
#[cfg(any(feature = "timestamps-bank-proof", feature = "latency-bank-proof"))]
unsafe extern "C" {
    fn p11_bank_enter_timed(slot: u32, pid_tgid: u64, ts: u64) -> u32;
    fn p11_bank_complete_timed(slot: u32, pid_tgid: u64, rv: u64, account: u32, now: u64) -> u32;
}

#[cfg(any(feature = "timestamps-bank-proof", feature = "latency-bank-proof"))]
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
            // The clock is read last so it reaches the bridge unspilled.
            let pid_tgid = helpers::bpf_get_current_pid_tgid();
            let ts = unsafe { helpers::bpf_ktime_get_ns() };
            unsafe { p11_bank_enter_timed(slot, pid_tgid, ts) };
        } else {
            bump_evidence(EVIDENCE_ABI_REFUSALS);
        }
    }
    stop_gate_leave();
    0
}

#[cfg(any(feature = "timestamps-bank-proof", feature = "latency-bank-proof"))]
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
        // The clock is read last so it reaches the bridge unspilled.
        let pid_tgid = helpers::bpf_get_current_pid_tgid();
        let now = unsafe { helpers::bpf_ktime_get_ns() };
        unsafe {
            p11_bank_complete_timed(
                slot,
                pid_tgid,
                rv,
                u32::from(scoped && layout.is_some()),
                now,
            )
        };
    }
    stop_gate_leave();
    0
}
