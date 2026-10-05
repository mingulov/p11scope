//! SPDX-License-Identifier: GPL-2.0-only
//! Positive exact image/physical-object witnesses for the caller flavor,
//! each with a saturating entry count. Rows and endpoint bindings are
//! retained for the entire owned map domain.

use super::*;
use p11scope_ebpf_common::inventory_callers::{
    entry::{record_caller_use_with, CallerEntryFailure, CallerEntryIo, PairInsertError},
    CallerEvidence, CallerObjectKey, CallerObjectUse, EndpointObject, CALLER_EVIDENCE_CELLS,
};

/// Placeholders: preparation must select explicit endpoint N and pair P limits
/// before loading. No insertion evicts or replaces a historical positive row.
#[map]
static ENDPOINT_OBJECT: Array<EndpointObject> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);
#[map]
static CALLER_USE: HashMap<CallerObjectKey, CallerObjectUse> = HashMap::with_max_entries(1, 0);
#[map]
static CALLER_EVIDENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(CALLER_EVIDENCE_CELLS, 0);

#[inline(always)]
pub(super) fn bump_evidence(kind: CallerEvidence) {
    if let Some(value) = CALLER_EVIDENCE.get_ptr_mut(kind.counter_index()) {
        unsafe { *value = (*value).saturating_add(1) };
    }
}

struct BpfCallerEntryIo;

impl CallerEntryIo for BpfCallerEntryIo {
    type Row = *mut CallerObjectUse;

    #[inline(always)]
    fn endpoint_object(&mut self, endpoint: u32) -> Option<EndpointObject> {
        ENDPOINT_OBJECT.get(endpoint).copied()
    }

    #[inline(always)]
    fn mark_usage(&mut self, endpoint: u32) -> bool {
        inventory::mark_usage(endpoint)
    }

    #[inline(always)]
    fn current_identity(&mut self) -> Option<ImageIdentity> {
        let mut image = ImageIdentity::default();
        // This is the same native allocator and TASK_COOKIE domain used by
        // Detailed capture, with the unchanged finite lifetime ticket policy.
        (unsafe { p11_link_current_identity(&mut image) } == 1 && image.task_cookie != 0)
            .then_some(image)
    }

    #[inline(always)]
    fn lookup(&mut self, key: &CallerObjectKey) -> Option<(Self::Row, CallerObjectUse)> {
        let row = CALLER_USE.get_ptr_mut(key)?;
        // SAFETY: this owned map has no deletion or replacement operation.
        // The loader must freeze userspace writes before any producer exists;
        // BPF publishes rows with BPF_NOEXIST, and afterwards only advances
        // `entry_count` with a non-fetch atomic add. Every validated field is
        // insert-immutable, so this copy validates exactly like the row.
        Some((row, unsafe { *row }))
    }

    #[inline(always)]
    fn insert_noexist(
        &mut self,
        key: &CallerObjectKey,
        value: &CallerObjectUse,
    ) -> Result<(), PairInsertError> {
        match CALLER_USE.insert(key, value, aya_ebpf::bindings::BPF_NOEXIST as u64) {
            Ok(()) => Ok(()),
            Err(-17) => Err(PairInsertError::Exists), // Linux EEXIST.
            Err(_) => Err(PairInsertError::Failed),
        }
    }

    #[inline(always)]
    fn now_ns(&mut self) -> u64 {
        unsafe { helpers::bpf_ktime_get_ns() }
    }

    #[inline(always)]
    fn count_entry(&mut self, row: Self::Row) {
        // SAFETY: `row` is the live CALLER_USE value this entry just looked
        // up; hash elements are never deleted. The deliberately unused result
        // selects the non-fetch BPF ATOMIC ADD (classic XADD), exact under
        // any concurrency, as in `counter_add`; a consumed fetch-add does not
        // lower on this toolchain (DR-57).
        let _ = unsafe {
            core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::AcqRel }>(
                core::ptr::addr_of_mut!((*row).entry_count),
                1,
            )
        };
    }
}

#[inline(always)]
pub(super) fn record(
    endpoint: u32,
    endpoint_capacity: u32,
    host_tgid: u32,
) -> Result<(), CallerEntryFailure> {
    record_caller_use_with(
        &mut BpfCallerEntryIo,
        endpoint,
        endpoint_capacity,
        host_tgid,
    )
}
