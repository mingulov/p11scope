//! SPDX-License-Identifier: GPL-2.0-only
//! Image-bank proof roots (Choice B feasibility): thin dispatcher, slot,
//! return and reference uprobe roots over the native bank cores in
//! `native/image_bank_proof.c`. Feature `image-bank-proof` only; the
//! default object never contains these roots. Birth, exec and query roots
//! stay native SEC roots (as in `image_identity_fork.c` and
//! `image_identity_query.c`) because aya-ebpf 0.2.1 has no program type
//! for them.
//!
//! The entry dispatchers keep the probe context in the root: the native
//! select/release cores take scalars only, and the tail call into the
//! owner array runs here. Passing the context pointer into a native
//! global function is refused by the verifier (the `void *` prototype
//! has no sized pointee), so the entry-owner program arrays are defined
//! here, not in the native core.

use super::*;

#[map]
static BANK_PROGS_SINGLES: ProgramArray = ProgramArray::with_max_entries(2, 0);
#[map]
static BANK_PROGS_MULTI: ProgramArray = ProgramArray::with_max_entries(2, 0);

unsafe extern "C" {
    fn p11_bank_select() -> u32;
    fn p11_bank_gate_release(slot: u32) -> u32;
    fn p11_bank_enter_a(pid_tgid: u64, bank: u64, observed: u64, ip: u64) -> u32;
    fn p11_bank_enter_b(pid_tgid: u64, bank: u64, observed: u64, ip: u64) -> u32;
    fn p11_bank_complete(pid_tgid: u64) -> u32;
    fn p11_bank_ref(cookie: u64, ip: u64) -> u32;
}

#[inline(always)]
fn bank_observed(ctx: &ProbeContext) -> (u64, u64) {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let helper_ip = unsafe { helpers::bpf_get_func_ip(ctx.as_ptr()) };
    let ip = if helper_ip != 0 {
        helper_ip
    } else {
        // Linux x86-64 uprobe pt_regs contains the adjusted runtime IP.
        unsafe { (*ctx.regs).rip as u64 }
    };
    (cookie, ip)
}

#[inline(always)]
fn bank_dispatch(ctx: &ProbeContext, owner: &ProgramArray) -> u32 {
    let slot = unsafe { p11_bank_select() };
    if slot > 1 {
        return 0;
    }
    unsafe { owner.tail_call(ctx, slot) };
    unsafe { p11_bank_gate_release(slot) };
    0
}

#[uprobe]
pub fn p11_bank_disp_enter(ctx: ProbeContext) -> u32 {
    bank_dispatch(&ctx, &BANK_PROGS_SINGLES)
}

#[uprobe]
pub fn p11_bank_disp_enter_multi(ctx: ProbeContext) -> u32 {
    bank_dispatch(&ctx, &BANK_PROGS_MULTI)
}

// Slot roots opt out of the per-CPU private stack: they are KPROBE-type
// uprobe programs with ~370-byte frames (N3) and no tail call of their
// own, so on 6.13+ a same-CPU preemption would clobber their keys and
// rows. STACK_GUARD (not TAIL_CALLS): each driver loads them once
// with its backend's type (template_second: one type per instance).
// Dispatchers already tail-call; return/ref stay under 64 (N3 32/12).
#[uprobe]
pub fn p11_bank_entry_a(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    let (cookie, ip) = bank_observed(&ctx);
    unsafe { p11_bank_enter_a(helpers::bpf_get_current_pid_tgid(), 0, cookie, ip) }
}

#[uprobe]
pub fn p11_bank_entry_b(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    let (cookie, ip) = bank_observed(&ctx);
    unsafe { p11_bank_enter_b(helpers::bpf_get_current_pid_tgid(), 1, cookie, ip) }
}

#[uretprobe]
pub fn p11_bank_return(ctx: RetProbeContext) -> u32 {
    unsafe { p11_bank_complete(helpers::bpf_get_current_pid_tgid()) }
}

#[uprobe]
pub fn p11_bank_ref_entry(ctx: ProbeContext) -> u32 {
    let (cookie, ip) = bank_observed(&ctx);
    unsafe { p11_bank_ref(cookie, ip) }
}
