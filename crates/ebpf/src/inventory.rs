//! SPDX-License-Identifier: GPL-2.0-only
//! Ordinary endpoint-use entries. The optional caller flavor additionally
//! records exact image/object witnesses. No ordinary arguments or returns.
use super::*;
use p11scope_ebpf_common::{
    inventory_cookie_endpoint, inventory_mark_used_with, InventoryUsageConfig,
    USAGE_EVIDENCE_CELLS, USAGE_EVIDENCE_INVALID_CONFIG, USAGE_EVIDENCE_INVALID_COOKIE,
    USAGE_EVIDENCE_INVALID_STATE,
};

/// Placeholder only: the loader must set the approved nonzero N before load.
#[map]
static USAGE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static USAGE_CONFIG: Array<InventoryUsageConfig> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);
#[map]
static USAGE_EVIDENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(USAGE_EVIDENCE_CELLS, 0);

fn bump_usage_evidence(index: u32) {
    if let Some(value) = USAGE_EVIDENCE.get_ptr_mut(index) {
        unsafe { *value = (*value).saturating_add(1) };
    }
}

#[uprobe]
pub fn p11_usage_entry_lp64(ctx: ProbeContext) -> u32 {
    keep_kernel_stack(&ctx);
    usage_entry(ctx, LinuxLayout::Lp64)
}

#[uprobe]
pub fn p11_usage_entry_ia32(ctx: ProbeContext) -> u32 {
    keep_kernel_stack(&ctx);
    usage_entry(ctx, LinuxLayout::Ilp32)
}

#[inline(always)]
fn usage_entry(ctx: ProbeContext, declared_layout: LinuxLayout) -> u32 {
    // Even malformed config/cookie evidence must not become an unscoped signal.
    #[cfg(not(feature = "inventory-callers"))]
    if scope_auth().is_none() {
        return 0;
    }
    #[cfg(feature = "inventory-callers")]
    let Some(scope) = scope_auth() else {
        return 0;
    };
    if probe_layout(&ctx) != Some(declared_layout) {
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    }
    let Some(config) = USAGE_CONFIG
        .get(0)
        .copied()
        .filter(|config| config.is_valid())
    else {
        bump_usage_evidence(USAGE_EVIDENCE_INVALID_CONFIG);
        return 0;
    };
    let Some(endpoint) = inventory_cookie_endpoint(cookie_of(&ctx), config.endpoint_capacity)
    else {
        bump_usage_evidence(USAGE_EVIDENCE_INVALID_COOKIE);
        return 0;
    };
    #[cfg(not(feature = "inventory-callers"))]
    if !mark_usage(endpoint) {
        bump_usage_evidence(USAGE_EVIDENCE_INVALID_STATE);
    }
    #[cfg(feature = "inventory-callers")]
    if let Err(error) = inventory_callers::record(endpoint, config.endpoint_capacity, scope.tgid) {
        use p11scope_ebpf_common::inventory_callers::entry::CallerEntryFailure;
        match error {
            CallerEntryFailure::GlobalStateInvalid => {
                bump_usage_evidence(USAGE_EVIDENCE_INVALID_STATE);
            }
            CallerEntryFailure::Caller(kind) => inventory_callers::bump_evidence(kind),
        }
    }
    0
}

#[inline(always)]
pub(super) fn mark_usage(endpoint: u32) -> bool {
    let Some(cell) = USAGE.get_ptr_mut(endpoint) else {
        return false;
    };
    // This aligned map cell is never reset or recycled in a retained session.
    // The pinned generic BPF backend cannot lower Rust AtomicLoad. As in the
    // native owner helpers, an aligned volatile u64 read emits one BPF LDXDW;
    // the shared kernel map is not Rust-owned memory. CAS performs the only
    // transition, using the same intrinsic as the existing pause writer.
    inventory_mark_used_with(
        || unsafe { core::ptr::read_volatile(cell) },
        || unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::Relaxed },
                { core::intrinsics::AtomicOrdering::Relaxed },
            >(cell, 0, 1)
            .0
        },
    )
}
