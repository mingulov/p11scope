//! SPDX-License-Identifier: GPL-2.0-only
//! Positive exact image/physical-object witnesses for the caller flavor.
//! Rows and endpoint bindings are retained for the entire owned map domain.

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
    fn lookup(&mut self, key: &CallerObjectKey) -> Option<CallerObjectUse> {
        // SAFETY: this owned map has no deletion or replacement operation.
        // The loader must freeze userspace writes before any producer exists;
        // BPF only publishes immutable values with BPF_NOEXIST.
        unsafe { CALLER_USE.get(key).copied() }
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
